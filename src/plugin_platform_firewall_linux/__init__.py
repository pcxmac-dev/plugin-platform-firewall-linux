"""Linux firewalls for Liminal (the user, 2026-11-07: "i also need a windows and linux firewall plugin for the
platform"): ufw (Ubuntu), firewalld (Fedora) or nftables (Gentoo, minimal systems), whichever the machine
has, on a Linux machine or in a WSL distribution on this Windows PC, through the library's
machines.linux.Shell (root through `sudo -n` here, never a password asked; `wsl -u root` in WSL), the target
by FIREWALL_LINUX_TARGET: local, wsl or wsl:<distribution> (local on Linux, the default WSL distribution on
Windows). On; no rule letting another machine reach the framework's pages; the ports the framework's services
need opened as Liminal's own rules, the only rules it changes: a ufw rule commented liminal:<name>, a
firewalld service named liminal-<name>, an nftables rule commented liminal:<name>:<protocol>:<ports>:<remote>.
Before ufw is turned on, an SSH server listening keeps its port open (a VPS stays reachable). The library's
Firewall base holds the rules, the status and the setup; this module drives Linux's.

    python -m plugin_platform_firewall_linux status | setup [STEP ...] | rules | exposure
                                             | allow NAME PORT[,PORT ...] [tcp|udp] | remove NAME | run -- COMMAND
"""
from __future__ import annotations

import json
import os
import re

from liminal_libs.machines.firewall import NAME, PREFIX, Firewall, FirewallError, FirewallNotNeeded, Rule
from liminal_libs.machines.linux import Shell
from liminal_libs.machines.plugin import CommandError

__version__ = "0.1.0"
TARGET_VAR = "FIREWALL_LINUX_TARGET"
DETECT = ("if command -v ufw >/dev/null 2>&1; then echo ufw; "
          "elif command -v firewall-cmd >/dev/null 2>&1; then echo firewalld; "
          "elif command -v nft >/dev/null 2>&1; then echo nft; else echo none; fi")
LOOPBACK = ("127.0.0.1", "::1", "127.0.0.0/8", "::1/128", "localhost", "lo")
SSH_LISTENING = "ss -ltnH 'sport = :22' 2>/dev/null | head -1"
UFW_ROW = re.compile(r"^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT|FWD))?\s+(.+?)(?:\s+#\s*(.*))?$")


def read_rule(name, ports=(), protocol="any", direction="in", action="allow", remote="any", owned=False, detail="") -> Rule:
    """A rule read from a firewall: Liminal's only under a name of its own; ports only with a protocol."""
    protocol = protocol if protocol in ("tcp", "udp") else "any"
    if owned and not NAME.match(name):
        owned = False
    ports = tuple(p for p in ports if isinstance(p, int) and 0 < p < 65536)
    if owned and protocol == "any":
        ports = ()
    return Rule(name, ports=ports, protocol=protocol, direction=direction, action=action, remote=remote or "any", owned=owned, detail=detail)


def spans(text: str):
    """The ports a ufw "To" field or a firewalld port list covers: [(low, high), ...]; None for every port; []
    for an application profile's name (its ports not known here)."""
    t = (text or "").strip()
    if not t or t.startswith("Anywhere"):
        return None
    t = t.split()[0]
    ports = t.partition("/")[0]
    out = []
    for part in ports.split(","):
        part = part.strip()
        if ":" in part or "-" in part:
            lo, _, hi = part.replace("-", ":").partition(":")
            if lo.isdecimal() and hi.isdecimal():
                out.append((int(lo), int(hi)))
        elif part.isdecimal():
            out.append((int(part), int(part)))
    return out


def covers(found, port: int) -> bool:
    return found is None or any(lo <= port <= hi for lo, hi in found)


def numbers(text: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.split(r"[,\s]+", text or "") if p.isdecimal())


# -- ufw ------------------------------------------------------------------------------------------------
class Ufw:
    name = "ufw"

    def __init__(self, sh: Shell):
        self.sh = sh

    def state(self) -> dict:
        active = "status: active" in self.sh.run("ufw", "status").lower()
        return {"enabled": active, "profiles": {"ufw": active}}

    def can_enable(self) -> bool:
        return True

    def added(self) -> list[dict]:
        """The rules as `ufw show added` lists them (on or off): {"spec": "allow proto tcp ... port 25", "comment"}."""
        out = []
        for line in self.sh.run("ufw", "show", "added").splitlines():
            line = line.strip()
            if not line.startswith("ufw "):
                continue
            m = re.search(r"\s+comment\s+'([^']*)'\s*$", line)
            out.append({"spec": (line[4:m.start()] if m else line[4:]).strip(), "comment": m.group(1) if m else ""})
        return out

    @staticmethod
    def rule_of(spec: str, comment: str) -> Rule:
        words = spec.split()
        owned = comment.startswith(PREFIX + ":")
        name = comment[len(PREFIX) + 1:] if owned else spec
        action = "block" if words and words[0] in ("deny", "reject") else "allow"
        direction = "out" if len(words) > 1 and words[1] == "out" else "in"
        protocol = words[words.index("proto") + 1] if "proto" in words else ""
        remote = words[words.index("from") + 1] if "from" in words else "any"
        if "port" in words:
            port_text = words[len(words) - 1 - words[::-1].index("port") + 1] if words[-1] != "port" else ""
        else:
            simple = next((w for w in words[1:] if re.match(r"^\d", w)), "")
            port_text, _, proto = simple.partition("/")
            protocol = protocol or proto
        return read_rule(name, numbers(port_text), protocol or "any", direction, action, remote, owned, detail=f"ufw {spec}")

    def list_rules(self, owned_only: bool = True) -> list[Rule]:
        rules = [self.rule_of(a["spec"], a["comment"]) for a in self.added()]
        return [r for r in rules if r.owned] if owned_only else rules

    def add_rule(self, rule: Rule) -> None:
        args = ["ufw", "allow" if rule.action == "allow" else "deny"]
        if rule.direction == "out":
            args.append("out")
        source = "any" if rule.remote == "any" else rule.remote
        if rule.ports:
            args += ["proto", rule.protocol, "from", source, "to", "any", "port", ",".join(map(str, rule.ports))]
        else:
            args += ["from", source]
        self.sh.run(*args, "comment", f"{PREFIX}:{rule.name}")

    def delete_rule(self, name: str) -> bool:
        mine = [a for a in self.added() if a["comment"] == f"{PREFIX}:{name}"]
        for a in mine:
            self.sh.run("ufw", "--force", "delete", *a["spec"].split())
        return bool(mine)

    def enable(self) -> None:
        if self.sh.sh(SSH_LISTENING, check=False).strip() and not any(a["comment"] == f"{PREFIX}:ssh" for a in self.added()):
            self.add_rule(Rule("ssh", ports=(22,), detail="kept open before the firewall went up: an SSH server listens"))
        self.sh.run("ufw", "--force", "enable")

    def rows(self) -> list[dict]:
        out = []
        for line in self.sh.run("ufw", "status", "numbered").splitlines():
            m = UFW_ROW.match(line.strip())
            if m:
                out.append({"number": int(m.group(1)), "to": m.group(2).strip(), "action": m.group(3), "direction": m.group(4) or "IN",
                            "from": m.group(5).strip(), "comment": (m.group(6) or "").strip()})
        return out

    def exposing(self, ports) -> list[tuple[int, str]]:
        hits = []
        for r in self.rows():
            if r["action"] not in ("ALLOW", "LIMIT") or r["direction"] != "IN" or r["from"].split()[0] in LOOPBACK:
                continue
            found = spans(r["to"])
            label = f"ufw rule [{r['number']}] {r['to']} from {r['from']}" + (f" ({r['comment']})" if r["comment"] else "")
            hits += [(p, label) for p in ports if covers(found, p)]
        return list(dict.fromkeys(hits))


# -- firewalld ------------------------------------------------------------------------------------------
class Firewalld:
    name = "firewalld"

    def __init__(self, sh: Shell):
        self.sh = sh

    def running(self) -> bool:
        return self.sh.run("firewall-cmd", "--state", check=False).strip() == "running"

    def fc(self, *args: str, check: bool = True) -> str:
        """firewall-cmd, or firewall-offline-cmd when the daemon does not run (the same options)."""
        return self.sh.run("firewall-cmd" if self.running() else "firewall-offline-cmd", *args, check=check)

    def zone(self) -> str:
        return self.fc("--get-default-zone").strip() or "public"

    def state(self) -> dict:
        running = self.running()
        return {"enabled": running, "profiles": {(self.zone() if running else "firewalld"): running}}

    def can_enable(self) -> bool:
        return True

    def list_rules(self, owned_only: bool = True) -> list[Rule]:
        zone = self.zone()
        out = []
        for s in self.fc("--permanent", f"--zone={zone}", "--list-services").split():
            if s.startswith(PREFIX + "-"):
                text = self.fc("--permanent", f"--service={s}", "--get-ports")
                protocol = "udp" if text.strip() and all(p.endswith("/udp") for p in text.split()) else "tcp"
                out.append(read_rule(s[len(PREFIX) + 1:], numbers(" ".join(p.split("/")[0] for p in text.split())), protocol,
                                     owned=True, detail=f"the firewalld service {s} in the zone {zone}"))
            elif not owned_only:
                out.append(read_rule(s, detail=f"the firewalld service {s} in the zone {zone}"))
        for rich in self.fc("--permanent", f"--zone={zone}", "--list-rich-rules").splitlines():
            m = re.search(r'source address="([^"]+)".*service name="' + PREFIX + r'-([a-z0-9-]+)"', rich)
            if m:
                out.append(read_rule(m.group(2), (), "tcp", remote=m.group(1), owned=True, detail=rich.strip()))
        if not owned_only:
            for p in self.fc("--permanent", f"--zone={zone}", "--list-ports").split():
                port, _, proto = p.partition("/")
                out.append(read_rule(p, numbers(port), proto, detail=f"the port {p} in the zone {zone}"))
        return out

    def add_rule(self, rule: Rule) -> None:
        if rule.direction == "out":
            raise FirewallError("firewalld filters what comes in here: a rule for what goes out is not made")
        svc = f"{PREFIX}-{rule.name}"
        zone = self.zone()
        if svc not in self.fc("--permanent", "--get-services").split():
            self.fc("--permanent", f"--new-service={svc}")
        self.fc("--permanent", f"--service={svc}", f"--set-description={rule.detail or 'made by the Liminal platform'}")
        for p in rule.ports:
            self.fc("--permanent", f"--service={svc}", f"--add-port={p}/{rule.protocol}")
        if rule.remote == "any" and rule.action == "allow":
            self.fc("--permanent", f"--zone={zone}", f"--add-service={svc}")
        else:
            source = f' source address="{rule.remote}"' if rule.remote != "any" else ""
            self.fc("--permanent", f"--zone={zone}",
                    f'--add-rich-rule=rule family="ipv4"{source} service name="{svc}" {"accept" if rule.action == "allow" else "drop"}')
        if self.running():
            self.sh.run("firewall-cmd", "--reload")

    def delete_rule(self, name: str) -> bool:
        svc = f"{PREFIX}-{name}"
        zone = self.zone()
        found = False
        if svc in self.fc("--permanent", f"--zone={zone}", "--list-services").split():
            self.fc("--permanent", f"--zone={zone}", f"--remove-service={svc}")
            found = True
        for rich in self.fc("--permanent", f"--zone={zone}", "--list-rich-rules").splitlines():
            if f'service name="{svc}"' in rich:
                self.fc("--permanent", f"--zone={zone}", f"--remove-rich-rule={rich.strip()}")
                found = True
        if svc in self.fc("--permanent", "--get-services").split():
            self.fc("--permanent", f"--delete-service={svc}")
            found = True
        if found and self.running():
            self.sh.run("firewall-cmd", "--reload")
        return found

    def enable(self) -> None:
        self.sh.run("systemctl", "enable", "--now", "firewalld")

    def exposing(self, ports) -> list[tuple[int, str]]:
        if not self.running():
            return []
        zone = self.zone()
        target = self.sh.run("firewall-cmd", "--permanent", f"--zone={zone}", "--get-target", check=False).strip()
        if target == "ACCEPT":
            return [(p, f"the zone {zone} accepts everything") for p in ports]
        hits = []
        for s in self.sh.run("firewall-cmd", f"--zone={zone}", "--list-services").split():
            info = self.sh.run("firewall-cmd", f"--info-service={s}", check=False)
            line = next((ln for ln in info.splitlines() if ln.strip().startswith("ports:")), "")
            found = [span for p in line.split(":", 1)[-1].split() for span in (spans(p) or [])]
            hits += [(p, f"the firewalld service {s} in the zone {zone}") for p in ports if covers(found, p)]
        for p_text in self.sh.run("firewall-cmd", f"--zone={zone}", "--list-ports").split():
            hits += [(p, f"the port {p_text} in the zone {zone}") for p in ports if covers(spans(p_text) or [], p)]
        for rich in self.sh.run("firewall-cmd", f"--zone={zone}", "--list-rich-rules").splitlines():
            m = re.search(r'port port="([0-9-]+)"', rich)
            source = re.search(r'source address="([^"]+)"', rich)
            if m and "accept" in rich and not (source and source.group(1) in LOOPBACK):
                hits += [(p, f"the rich rule {rich.strip()}") for p in ports if covers(spans(m.group(1)) or [], p)]
        return list(dict.fromkeys(hits))


# -- nftables -------------------------------------------------------------------------------------------
def nft_view(expr: list) -> tuple[bool, bool, object]:
    """A rule's expressions read: (it accepts, it is only for this machine or for connections already made, the
    ports it covers: [(lo, hi)] or None for every port)."""
    accepts = any(isinstance(e, dict) and "accept" in e for e in expr)
    local = False
    found = None
    for e in expr:
        m = e.get("match") if isinstance(e, dict) else None
        if not m:
            continue
        left, right = m.get("left") or {}, m.get("right")
        if "ct" in left and (left["ct"] or {}).get("key") == "state":
            local = True  # established, related: no new connection from outside
        elif "meta" in left and (left["meta"] or {}).get("key") in ("iif", "iifname") and right == "lo":
            local = True
        elif "payload" in left and (left["payload"] or {}).get("field") == "saddr":
            address = right.get("prefix", {}).get("addr") if isinstance(right, dict) else right
            if address in LOOPBACK or str(address).startswith("127."):
                local = True
        elif "payload" in left and (left["payload"] or {}).get("field") == "dport":
            values = right.get("set") if isinstance(right, dict) and "set" in right else [right]
            found = []
            for v in values:
                if isinstance(v, int):
                    found.append((v, v))
                elif isinstance(v, dict) and "range" in v:
                    found.append((int(v["range"][0]), int(v["range"][1])))
    return accepts, local, found


class Nft:
    name = "nftables"

    def __init__(self, sh: Shell):
        self.sh = sh

    def items(self) -> list:
        return json.loads(self.sh.run("nft", "-j", "list", "ruleset") or "{}").get("nftables", [])

    @staticmethod
    def input_chains(items) -> list[dict]:
        return [i["chain"] for i in items if "chain" in i and i["chain"].get("hook") == "input"]

    def filtering(self, items) -> dict | None:
        """The first input chain dropping by default: where Liminal's rules go."""
        return next((c for c in self.input_chains(items) if c.get("policy") == "drop"), None)

    def state(self) -> dict:
        chains = self.input_chains(self.items())
        profiles = {f"{c['family']} {c['table']} {c['name']}": c.get("policy") == "drop" for c in chains}
        return {"enabled": any(profiles.values()), "profiles": profiles or {"nftables": False}}

    def can_enable(self) -> bool:
        return False

    def enable(self) -> None:
        raise FirewallError("nftables has no switch: its rules filter or not")

    def rules_in(self, items, chain: dict) -> list[dict]:
        return [i["rule"] for i in items if "rule" in i and i["rule"].get("family") == chain["family"]
                and i["rule"].get("table") == chain["table"] and i["rule"].get("chain") == chain["name"]]

    def list_rules(self, owned_only: bool = True) -> list[Rule]:
        items = self.items()
        out = []
        for chain in self.input_chains(items):
            for r in self.rules_in(items, chain):
                comment = str(r.get("comment") or "")
                if comment.startswith(PREFIX + ":"):
                    _, name, protocol, port_text, remote = (comment.split(":", 4) + ["", "", "", ""])[:5]
                    out.append(read_rule(name, numbers(port_text), protocol, remote=remote or "any", owned=True,
                                         detail=f"nftables {chain['family']} {chain['table']} {chain['name']} handle {r.get('handle')}"))
                elif not owned_only:
                    out.append(read_rule(f"{chain['family']} {chain['table']} {chain['name']} handle {r.get('handle')}", detail=comment))
        return out

    def add_rule(self, rule: Rule) -> None:
        chain = self.filtering(self.items())
        if chain is None:
            raise FirewallNotNeeded("nothing filters what comes in here (no nftables input chain dropping by default): "
                                    "no rule is needed until a firewall does")
        if rule.direction == "out":
            raise FirewallError("only what comes in is opened here")
        words = ["nft", "insert", "rule", chain["family"], chain["table"], chain["name"]]
        if rule.remote != "any":
            words += ["ip", "saddr", rule.remote]
        if rule.ports:
            ports = [str(p) for p in rule.ports]
            words += [rule.protocol, "dport"] + (["{", *[p + "," for p in ports[:-1]], ports[-1], "}"] if len(ports) > 1 else ports)
        words += ["accept" if rule.action == "allow" else "drop", "comment",
                  f'"{PREFIX}:{rule.name}:{rule.protocol}:{",".join(map(str, rule.ports))}:{rule.remote}"']
        self.sh.run(*words)

    def delete_rule(self, name: str) -> bool:
        items = self.items()
        found = False
        for chain in self.input_chains(items):
            for r in self.rules_in(items, chain):
                if str(r.get("comment") or "").startswith(f"{PREFIX}:{name}:"):
                    self.sh.run("nft", "delete", "rule", chain["family"], chain["table"], chain["name"], "handle", str(r["handle"]))
                    found = True
        return found

    def exposing(self, ports) -> list[tuple[int, str]]:
        items = self.items()
        hits = []
        for chain in self.input_chains(items):
            if chain.get("policy") != "drop":
                continue
            for r in self.rules_in(items, chain):
                accepts, local, found = nft_view(r.get("expr") or [])
                if not accepts or local:
                    continue
                label = f"nftables {chain['family']} {chain['table']} {chain['name']} handle {r.get('handle')}" + (f" ({r['comment']})" if r.get("comment") else "")
                hits += [(p, label) for p in ports if covers(found, p)]
        return list(dict.fromkeys(hits))


class NoFirewall:
    name = "no firewall"

    def __init__(self, sh: Shell):
        self.sh = sh

    def state(self) -> dict:
        return {"enabled": False, "profiles": {}}

    def can_enable(self) -> bool:
        return False

    def enable(self) -> None:
        raise FirewallError("no firewall software here (ufw, firewalld, nftables)")

    def list_rules(self, owned_only: bool = True) -> list[Rule]:
        return []

    def add_rule(self, rule: Rule) -> None:
        raise FirewallNotNeeded("no firewall software here (ufw, firewalld, nftables): nothing filters, no rule is needed")

    def delete_rule(self, name: str) -> bool:
        return False

    def exposing(self, ports) -> list[tuple[int, str]]:
        return []


DRIVERS = {"ufw": Ufw, "firewalld": Firewalld, "nft": Nft}


class LinuxFirewallPlugin(Firewall):
    name = "firewall-linux"
    title = "Linux firewall"
    about = ("ufw, firewalld or nftables on a Linux machine or in a WSL distribution: on, the framework's pages kept to this "
             "machine, the ports its services need opened as Liminal's own rules")
    api = "2.1"
    order = 711

    def __init__(self, shell: Shell | None = None, runner=None):
        self._shell = shell
        self._runner = runner
        self._drivers: dict[str, object] = {}

    @property
    def options(self) -> tuple[str, ...]:
        return (TARGET_VAR,)

    @property
    def shell(self) -> Shell:
        """The target as FIREWALL_LINUX_TARGET says now (or the shell given)."""
        return self._shell if self._shell is not None else Shell(os.environ.get(TARGET_VAR), runner=self._runner)

    def driver(self):
        sh = self.shell
        if sh.target not in self._drivers:
            found = (sh.sh(DETECT, timeout=60).strip().splitlines() or ["none"])[-1].strip()
            self._drivers[sh.target] = DRIVERS.get(found, NoFirewall)(sh)
        return self._drivers[sh.target]

    def present(self) -> bool:
        try:
            sh = self.shell
            return sh.here and not isinstance(self.driver(), NoFirewall)
        except CommandError:
            return False

    def backend(self) -> str:
        return f"{self.driver().name} on {self.shell.where}"

    def state(self) -> dict:
        return self.driver().state()

    def list_rules(self, owned_only: bool = True) -> list[Rule]:
        return self.driver().list_rules(owned_only)

    def add_rule(self, rule: Rule) -> None:
        if not rule.owned:
            raise FirewallError("only Liminal's own rules are made here")
        self.driver().add_rule(rule)

    def delete_rule(self, name: str) -> bool:
        return self.driver().delete_rule(name)

    def enable(self) -> None:
        self.driver().enable()

    def can_enable(self) -> bool:
        return self.driver().can_enable()

    def exposing(self, ports) -> list[tuple[int, str]]:
        return self.driver().exposing(ports)

    def run(self, *command: str, **options) -> str:
        """A command on the target, as root, its output."""
        return self.shell.run(*command)


MACHINE = LinuxFirewallPlugin()
