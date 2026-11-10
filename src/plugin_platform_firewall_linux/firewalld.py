"""firewalld read from `firewall-cmd --list-all-zones` (each zone: active or not, the default, its target, interfaces,
sources, services, ports, forwarding, masquerade, forward ports, ICMP blocks, rich rules), `--list-all-policies` (its
policies between zones, since 0.9) and `--info-service` for the services the zones use (their ports); through
`firewall-offline-cmd` while the daemon is stopped. Every service, port, source, forward port and rich rule of a zone
is an `Entry` (firewalld's, removable; Liminal's: a service liminal-<name>); firewalld's own nftables table is its
machinery, read through the zones instead. A zone bound to nothing, the default zone while every interface in use is
bound to another zone, a policy turned off, and everything while firewalld is stopped, are listed too, turned off (0.6.0).
The commands are built here, never run: each change made in the running firewall and in its permanent configuration
alike."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from liminal_libs.machines.firewall import PREFIX

from .model import Entry, digest, ports_text, spans_of

HEAD = re.compile(r"^(\S+)(?:\s+\(([^)]*)\))?\s*$")
LIST_KEYS = ("interfaces", "sources", "services", "ports", "protocols", "source-ports", "icmp-blocks", "forward-ports",
             "ingress-zones", "egress-zones")
TARGETS = ("default", "ACCEPT", "DROP", "%%REJECT%%", "REJECT", "CONTINUE")


@dataclass
class Zone:
    name: str
    policy: bool = False  # a policy (between zones), not a zone
    active: bool = False
    default: bool = False
    disabled: bool = False  # a policy turned off (firewalld 2.4+: the gateway-* policies ship so)
    target: str = "default"
    fields: dict = field(default_factory=dict)  # a key -> its words (lists) or its word
    rich: list = field(default_factory=list)

    def words(self, key: str) -> list[str]:
        v = self.fields.get(key, [])
        return v if isinstance(v, list) else [v] if v else []

    def word(self, key: str) -> str:
        v = self.fields.get(key, "")
        return " ".join(v) if isinstance(v, list) else str(v)


@dataclass
class FirewalldState:
    installed: bool = False
    running: bool = False
    version: str = ""
    default_zone: str = ""
    backend: str = ""  # nftables | iptables (FirewallBackend)
    zones: list = field(default_factory=list)
    policies: list = field(default_factory=list)
    services: dict = field(default_factory=dict)  # a service -> its ports ("22/tcp")

    def zone(self, name: str) -> Zone | None:
        return next((z for z in self.zones if z.name == name), None)


def parse_blocks(text: str, policy: bool = False) -> list[Zone]:
    """`--list-all-zones` / `--list-all-policies`: a block per zone, its name (with "(default, active)") then its keys."""
    out: list[Zone] = []
    cur: Zone | None = None
    last = ""  # the key whose entries follow on lines of their own, each after a TAB (forward ports, rich rules)
    for raw in (text or "").splitlines():
        if not raw.strip():
            continue  # blocks are told apart by their unindented name line (from 2.5.1 no empty line between them)
        if not raw[0].isspace():
            m = HEAD.match(raw.strip())
            if not m:
                continue
            marks = [w.strip() for w in (m.group(2) or "").split(",")]
            cur = Zone(m.group(1), policy=policy, active="active" in marks, default="default" in marks,
                       disabled="disabled" in marks)
            out.append(cur)
            last = ""
            continue
        if cur is None:
            continue
        line = raw.strip()
        if raw.startswith("\t") or (last == "rich rules" and line.startswith("rule")):
            if last == "rich rules":
                cur.rich.append(line)
            elif last == "forward-ports":
                cur.fields.setdefault("forward-ports", []).append(line)
            continue
        key, sep, value = line.partition(":")
        if sep and key == "rich rules":
            last = key
            if value.strip():
                cur.rich.append(value.strip())
            continue
        if sep and re.fullmatch(r"[a-z0-9-]+", key):
            last = key
            value = value.strip()
            if key == "target":
                cur.target = value or "default"
            elif key == "disable":
                cur.disabled = value == "yes"
            elif key in LIST_KEYS:
                cur.fields[key] = value.split()
            else:
                cur.fields[key] = value
    return out


def parse_services(text: str) -> dict:
    """`firewall-cmd --info-service=NAME` for several, one after another: {name: ["22/tcp", ...]}."""
    out: dict = {}
    name = ""
    for raw in (text or "").splitlines():
        if not raw.strip():
            continue
        if not raw[0].isspace():
            name = raw.strip()
            out.setdefault(name, [])
        elif name and raw.strip().startswith("ports:"):
            out[name] = raw.split(":", 1)[1].split()
    return out


RICH_FAMILY = re.compile(r'family="(ipv4|ipv6)"')
RICH_SOURCE = re.compile(r'source\s+(not\s+)?(?:address|ipset|mac)="([^"]+)"')
RICH_DEST = re.compile(r'destination\s+(not\s+)?address="([^"]+)"')
RICH_PORT = re.compile(r'(?<!source-)(?<!forward-)port\s+port="([^"]+)"\s+protocol="(\w+)"')
RICH_SERVICE = re.compile(r'service\s+name="([^"]+)"')
RICH_ACTION = re.compile(r"\b(accept|drop|reject|mark)\b(?:\s+type=\"[^\"]*\")?\s*(?:limit\s+value=\"[^\"]*\")?\s*$")


def rich_view(rule: str) -> dict:
    """A rich rule's fields: its family, source, destination, service or port, and what it does."""
    out = {"family": "", "source": "", "destination": "", "service": "", "protocol": "", "spans": (), "action": "continue"}
    m = RICH_FAMILY.search(rule)
    out["family"] = m.group(1) if m else ""
    m = RICH_SOURCE.search(rule)
    if m:
        out["source"] = ("not " if m.group(1) else "") + m.group(2)
    m = RICH_DEST.search(rule)
    if m:
        out["destination"] = ("not " if m.group(1) else "") + m.group(2)
    m = RICH_SERVICE.search(rule)
    if m:
        out["service"] = m.group(1)
    m = RICH_PORT.search(rule)
    if m:
        out["spans"], out["protocol"] = spans_of(m.group(1)), m.group(2)
    for word in ("accept", "drop", "reject"):
        if re.search(rf"\b{word}\b", rule):
            out["action"] = word
    if "masquerade" in rule or "forward-port" in rule:
        out["action"] = "nat"
    if re.search(r"\blimit value=", rule) and out["action"] == "accept":
        out["action"] = "limit"
    if re.search(r"\bicmp-(?:type|block)\b", rule) and not out["protocol"]:
        out["protocol"] = "ipv6-icmp" if out["family"] == "ipv6" else "icmp"
    m = re.search(r'\bprotocol value="([^"]+)"', rule)
    if m and not out["protocol"]:
        out["protocol"] = m.group(1)
    return out


OFF_STOPPED = "firewalld is stopped"  # why every rule of its filters nothing (0.6.0)
NOT_ACTIVE = " (not active)"  # a zone's Where while its rules filter nothing (left out of a rule's key: its moves kept)
IDLE = ("down", "lowerlayerdown", "notpresent")  # an interface's states in which nothing comes in on it


def unbound(st: FirewalldState, interfaces) -> list[str] | None:
    """The interfaces in use that no zone is bound to (0.6.0), which the default zone takes: firewalld uses it for
    everything not bound to another zone. In use: every interface read but loopback (firewalld lets it in itself), one
    down, a bridge's or a bond's port (what it carries comes in through that one), and a container's or a VM's end of
    its link (veth, vnet: the same, through its bridge). None when the interfaces could not be read."""
    if not interfaces:
        return None
    bound = {i for z in st.zones if not z.policy for i in z.words("interfaces")}
    return [i.name for i in interfaces if i.name != "lo" and (i.state or "").lower() not in IDLE and not i.master
            and not i.name.startswith(("veth", "vnet")) and i.name not in bound]


def applies(z: Zone, takes=None) -> bool:
    """Whether a zone's or a policy's rules filter while firewalld runs (0.6.0): an active zone's (an interface or a
    source bound to it); the default zone's while it takes an interface in use bound to no other zone (`takes`: those,
    from `unbound`; none known when the interfaces could not be read); a policy's active and not turned off. The rest
    are listed apart, turned off (`entries(resting=True)`)."""
    if z.policy:
        return z.active and not z.disabled
    return z.active or (z.default and bool(takes))


def off_of(z: Zone, running: bool, takes=None) -> str:
    """Why a zone's or a policy's rules filter nothing now, in words ("" when they are in force)."""
    if not running:
        return OFF_STOPPED
    if z.policy:
        return "the policy is turned off" if z.disabled else "" if z.active else "its zones are not in use"
    if applies(z, takes):
        return ""
    if z.default:
        return ("every interface in use is bound to another zone" if takes is not None
                else "no interface is bound to it, and the interfaces could not be read")
    return "the zone is bound to nothing"


def entries(st: FirewalldState, resting: bool = False, takes=None) -> list[Entry]:
    """The zones' services, ports, sources, forward ports and rich rules, the policies' too, of the zones and policies
    that filter while firewalld runs (`applies`): active zones first, and the default zone while it takes an interface
    in use bound to no other zone (`takes`: those, from `unbound`). `resting` (0.6.0; the user: "also rules that are
    turned off should be shown as well"): those of every other zone and policy instead (a zone bound to nothing, the
    default zone while every interface in use is bound to another, a policy turned off or between zones not in use). A
    rule says why it filters nothing in `off`, as every rule does while firewalld is stopped."""
    out: list[Entry] = []

    def add(z: Zone, what: str, value: str, **kw):
        where = f"{'policy' if z.policy else 'zone'} {z.name}"
        out.append(Entry(ref=f"fwd|{'policy' if z.policy else 'zone'}|{z.name}|{what}|{value}|{digest(z.name, what, value)}",
                         kind="firewalld", where=where + ("" if z.policy or applies(z, takes) else NOT_ACTIVE),
                         text=kw.pop("text", f"{what} {value}"), off=off_of(z, st.running, takes), **kw))

    zones = sorted(st.zones, key=lambda z: (not z.active, not z.default, z.name)) + st.policies
    for z in zones:
        if applies(z, takes) == resting:  # the rules that filter while it runs, or those listed apart (turned off)
            continue
        direction = "in"
        if z.policy:
            ing, eg = z.words("ingress-zones"), z.words("egress-zones")
            direction = "in" if eg == ["HOST"] else "out" if ing == ["HOST"] else "fwd"
        for s in z.words("services"):
            ports = st.services.get(s)
            known = ports is not None
            ports = ports or []
            spans = tuple(sp for p in ports for sp in spans_of(p.split("/")[0]))
            protos = sorted({p.split("/")[1] for p in ports if "/" in p})
            owner = "liminal" if s.startswith(PREFIX + "-") else "firewalld"
            add(z, "service", s, direction=direction, action="accept", protocol="/".join(protos),
                ports=ports_text(spans) if known else "its own (not read)", spans=spans,
                comment=s if owner == "liminal" else "", owner=owner, text=f"service {s}" + (f" ({' '.join(ports)})" if ports else ""))
        for p in z.words("ports"):
            port, _, proto = p.partition("/")
            spans = spans_of(port)
            add(z, "port", p, direction=direction, action="accept", protocol=proto, ports=ports_text(spans), spans=spans,
                owner="firewalld", text=f"port {p}")
        for p in z.words("protocols"):
            add(z, "protocol", p, direction=direction, action="accept", protocol=p, owner="firewalld", text=f"protocol {p}")
        for src in z.words("sources"):
            add(z, "source", src, direction=direction, action="zone", source=src, owner="firewalld",
                text=f"source {src}: its traffic is the zone {z.name}'s")
        for fp in z.words("forward-ports"):
            kv = dict(part.split("=", 1) for part in fp.split(":") if "=" in part)
            spans = spans_of(kv.get("port", ""))
            add(z, "forward-port", fp, direction="nat", action="nat", protocol=kv.get("proto", ""), ports=ports_text(spans),
                spans=spans, target=f"{kv.get('toaddr', '')}:{kv.get('toport', '') or kv.get('port', '')}".strip(":"),
                owner="firewalld", text=f"forward-port {fp}")
        if z.word("masquerade") == "yes":
            add(z, "masquerade", "yes", direction="nat", action="nat", owner="firewalld", text="masquerade: what leaves through it is NATed")
        for b in z.words("icmp-blocks"):
            add(z, "icmp-block", b, direction=direction, action="reject", protocol="icmp", owner="firewalld", text=f"icmp-block {b}")
        for rich in z.rich:
            v = rich_view(rich)
            owner = "liminal" if v["service"].startswith(PREFIX + "-") else "firewalld"
            service_ports = st.services.get(v["service"], []) if v["service"] else []
            spans = v["spans"] or tuple(sp for p in service_ports for sp in spans_of(p.split("/")[0]))
            add(z, "rich", rich, direction="nat" if v["action"] == "nat" else direction, action=v["action"],
                protocol=v["protocol"] or "/".join(sorted({p.split("/")[1] for p in service_ports if "/" in p})),
                ports=ports_text(spans), spans=spans, source=v["source"], destination=v["destination"],
                comment=v["service"] if owner == "liminal" else "", owner=owner, family=v["family"], text=rich)
    return out


# -- the commands that change it ------------------------------------------------------------------------------------
def both(running: bool, *args: str) -> list[list[str]]:
    """A change made in the running firewall and in its permanent configuration (only the latter, offline, when stopped)."""
    if not running:
        return [["firewall-offline-cmd", *args]]
    return [["firewall-cmd", *args], ["firewall-cmd", "--permanent", *args]]


def remove_commands(running: bool, scope: str, name: str, what: str, value: str) -> list[list[str]]:
    flag = {"service": "--remove-service", "port": "--remove-port", "protocol": "--remove-protocol", "source": "--remove-source",
            "forward-port": "--remove-forward-port", "masquerade": "--remove-masquerade", "icmp-block": "--remove-icmp-block",
            "rich": "--remove-rich-rule"}[what]
    arg = flag if what == "masquerade" else f"{flag}={value}"
    return both(running, f"--{scope}={name}", arg)


def rich_rule(action: str, family: str, source: str, protocol: str, spans, service: str = "") -> str:
    """A rich rule letting in (or dropping, refusing) a port or a service, from an address or a network."""
    words = ["rule"]
    if family or source:
        words.append(f'family="{family or ("ipv6" if ":" in source else "ipv4")}"')
    if source:
        words.append(f'source address="{source}"')
    if service:
        words.append(f'service name="{service}"')
    elif spans:
        a, b = spans[0]
        words.append(f'port port="{a if a == b else f"{a}-{b}"}" protocol="{protocol}"')
    words.append({"allow": "accept", "block": "drop", "reject": "reject"}[action])
    return " ".join(words)
