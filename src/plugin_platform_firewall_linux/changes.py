"""The changes the page asks for, planned over one read (`Config`) before anything runs: a rule made, a rule removed, a
default policy set, a front end or a firewall service turned on or off, the rules made at run time saved where the
distribution loads them at boot. Each plan is the commands in order (run as root), what it does in words, and, for a
change that can cut this machine off or open it to everyone, the risk in words: such a change is refused until it is
accepted (`Risky`, whose `accept` names the hook's argument that accepts it: the platform's page asks it as a second,
explicit confirmation). Nothing here runs a command."""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

from liminal_libs.machines.firewall import NAME, PREFIX

from . import firewalld as fwd_mod
from . import nftables as nft_mod
from . import ufw as ufw_mod
from . import xtables as xt_mod
from .model import ALLOWS, BLOCKS, OWNER_WORDS, Entry, address_family, parse_address, parse_interface, parse_ports, ports_text
from .read import Config
from .system import service_command

ACCEPT = "accept_risk"  # the hooks' argument accepting a risky change (Risky's accept)
LIMINAL_TABLE = ("inet", "liminal")  # nftables' table of Liminal's own, made when a block rule has no chain to go in
DIRECTION_HOOK = {"in": "input", "out": "output", "fwd": "forward"}
DIRECTION_CHAIN = {"in": "INPUT", "out": "OUTPUT", "fwd": "FORWARD"}
SAFE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


class Risky(ValueError):
    """A change refused until it is accepted (the hook asked again with accept_risk true): it may cut this machine off
    or open it to everyone. The platform's page offers it as a second, explicit confirmation."""

    def __init__(self, message: str):
        super().__init__(message)
        self.accept = ACCEPT


class NotNeeded(ValueError):
    """Nothing filters there, so the rule would change nothing."""


@dataclass
class Step:
    args: list
    stdin: str | None = None
    check: bool = True

    @property
    def words(self) -> str:
        return " ".join(shlex.quote(a) for a in self.args) if self.args[:2] != ["sh", "-c"] else "a script: " + self.args[2].splitlines()[0]


@dataclass
class Plan:
    steps: list
    said: str
    risk: str = ""
    lines: list = field(default_factory=list)


@dataclass(frozen=True)
class Spec:
    """A rule asked for (Liminal's: its name is kept with it)."""

    name: str
    direction: str  # in | out | fwd
    action: str  # allow | block | reject
    protocol: str  # tcp | udp | any
    spans: tuple  # local ports, () for every port
    source: str  # an address or a network ("" for anywhere): the remote side
    interface: str

    @property
    def words(self) -> str:
        what = {"allow": "let", "block": "drop", "reject": "refuse"}[self.action]
        way = {"in": "coming in", "out": "going out", "fwd": "passing through"}[self.direction]
        ports = f"{self.protocol} port {ports_text(self.spans)}" if self.spans else ("every port" if self.protocol == "any" else f"every {self.protocol} port")
        where = f" from {self.source}" if self.source and self.direction != "out" else f" to {self.source}" if self.source else ""
        on = f" on {self.interface}" if self.interface else ""
        return f"{what} {ports} {way}{where}{on}"


def spec_of(name, direction, action, protocol, ports, remote, interface) -> Spec:
    """A form's fields as a Spec; ValueError in words for anything not right."""
    name = str(name or "").strip().lower()
    if not NAME.match(name):
        raise ValueError("a name is lowercase letters, digits and dashes (48 at most): web, office-ssh")
    direction = str(direction or "in")
    if direction not in DIRECTION_HOOK:
        raise ValueError("the direction is in, out or fwd")
    action = str(action or "allow")
    if action not in ("allow", "block", "reject"):
        raise ValueError("a rule allows, blocks or rejects")
    protocol = str(protocol or "tcp")
    if protocol not in ("tcp", "udp", "any"):
        raise ValueError("the protocol is tcp, udp or any")
    spans = parse_ports(ports)
    if spans and protocol == "any":
        raise ValueError("ports need a protocol: tcp or udp")
    return Spec(name, direction, action, protocol, spans, parse_address(remote), parse_interface(interface))


# -- risks --------------------------------------------------------------------------------------------------------------
def _ssh_note(cfg: Config) -> str:
    n = cfg.system.ssh_sessions
    return f"; {n} SSH session{'s are' if n != 1 else ' is'} connected now" if n else ""


def ssh_allowed(cfg: Config, entries, port: int, leaving: Entry | None = None) -> bool:
    """Whether a rule (but `leaving`) still lets SSH in on `port` from everywhere."""
    return any(e is not leaving and e.direction == "in" and e.action in ALLOWS and e.covers(port) and not e.local and e.from_anywhere
               for e in entries)


def ssh_only_from(entries, port: int, leaving: Entry | None = None) -> list[str]:
    """The networks a rule (but `leaving`) lets SSH in from on `port`, where none lets it in from everywhere."""
    return sorted({e.source for e in entries if e is not leaving and e.direction == "in" and e.action in ALLOWS and e.covers(port)
                   and not e.local and not e.from_anywhere})


def risk_of_make(cfg: Config, spec: Spec, framework_ports) -> str:
    ssh = sorted(cfg.system.ssh_ports)
    if spec.direction == "in" and spec.action == "allow":
        if not spec.spans and not spec.source:
            return ("It lets every machine reach every port of this machine: whatever listens here, a database or an admin "
                    "page, can be reached from outside.")
        hit = [p for p in framework_ports if any(a <= p <= b for a, b in spec.spans) or not spec.spans]
        if hit and not (spec.source.startswith("127.") or spec.source in ("::1", "::1/128")):
            return (f"It opens the framework's own pages ({', '.join(map(str, hit))}): they answer this machine only, and the "
                    "exposure check counts a rule letting other machines reach them as a finding.")
    if spec.direction == "in" and spec.action in ("block", "reject") and ssh:
        cut = [p for p in ssh if not spec.spans or any(a <= p <= b for a, b in spec.spans)]
        if cut and spec.protocol in ("tcp", "any"):
            whom = f"from {spec.source}" if spec.source else "from everywhere"
            return (f"It drops SSH {whom} (sshd listens on {', '.join(map(str, cut))}{_ssh_note(cfg)}): whoever reaches this "
                    "machine over SSH may be cut off, perhaps you.")
    if spec.direction == "out" and spec.action in ("block", "reject") and not spec.spans and not spec.source:
        return "It stops everything this machine sends: name lookups, updates, the integrator's data, replies to SSH."
    return ""


def risk_of_remove(cfg: Config, e: Entry) -> str:
    entries = cfg.entries()
    if e.direction == "in" and e.action in ALLOWS:
        if e.local and e.state:
            return ("It lets the replies to this machine's own connections back in: without it, where nothing else does, every "
                    "connection this machine makes (name lookups, updates, SSH's replies) may stop.")
        if e.local:
            return "It lets this machine reach itself (loopback): the framework's pages at 127.0.0.1 may stop answering."
        cut = [p for p in sorted(cfg.system.ssh_ports) if e.covers(p) and not ssh_allowed(cfg, entries, p, leaving=e)]
        if cut:
            only = sorted({s for p in cut for s in ssh_only_from(entries, p, leaving=e)})
            return (f"It is what lets SSH in (sshd listens on {', '.join(map(str, cut))}"
                    + (f"; another rule lets it in only from {', '.join(only)}" if only else "") + f"{_ssh_note(cfg)}): without it, "
                    "whoever reaches this machine over SSH may be cut off, perhaps you.")
        if re.search(r"ipv6-icmp|icmpv6|neighbou?r-|router-advertisement|nd-", f"{e.protocol} {e.text}"):
            return ("It lets IPv6's own messages in (neighbour discovery, router advertisements): without them this machine "
                    "may lose its IPv6 neighbours and routes, and IPv6 may stop working.")
    return ""


# -- making a rule ------------------------------------------------------------------------------------------------------
def _liminal_named(cfg: Config, name: str) -> list[Entry]:
    return [e for e in cfg.entries() if e.owner == "liminal" and e.liminal_name == name]


def plan_make(cfg: Config, spec: Spec, framework_ports=(), framework: bool = False) -> Plan:
    """Liminal's rule `spec` made through what is in charge here (ufw, firewalld, nftables, iptables)."""
    if _liminal_named(cfg, spec.name):
        raise ValueError(f"a Liminal rule named {spec.name} is there already: remove it first")
    manager = cfg.manager
    risk = "" if framework else risk_of_make(cfg, spec, framework_ports)
    if manager == "ufw":
        return _make_ufw(cfg, spec, risk)
    if manager == "firewalld":
        return _make_firewalld(cfg, spec, risk)
    if manager == "nftables":
        return _make_nft(cfg, spec, risk)
    if manager == "iptables":
        return _make_iptables(cfg, spec, risk)
    raise NotNeeded("no firewall software here (nftables, iptables, ufw, firewalld): nothing filters, no rule is needed")


def _make_ufw(cfg: Config, spec: Spec, risk: str) -> Plan:
    cmd = ufw_mod.rule_command(spec.action, spec.direction, spec.protocol, spec.spans, spec.source, spec.interface,
                               f"{PREFIX}:{spec.name}")
    later = "" if cfg.ufw.active else "; ufw is off: it holds the rule for when it is on"
    return Plan([Step(cmd)], f"made through ufw: {spec.words}, as Liminal's {spec.name}{later}", risk)


def _make_firewalld(cfg: Config, spec: Spec, risk: str) -> Plan:
    f = cfg.firewalld
    if spec.direction != "in":
        raise ValueError("firewalld filters what comes in to a zone here: a rule for what goes out or passes through is a "
                         "policy's, made with firewall-cmd --policy")
    if spec.interface:
        raise ValueError("firewalld filters by zone: bind the interface to a zone (firewall-cmd --zone=... --change-interface) "
                         "instead of naming it in a rule")
    if not spec.spans:
        raise ValueError("a named rule in firewalld is a service with its ports: name the ports (to let a network in on "
                         "every port, add it to the trusted zone)")
    zone = f.default_zone or "public"
    svc = f"{PREFIX}-{spec.name}"
    tool = "firewall-cmd" if f.running else "firewall-offline-cmd"
    perm = ["--permanent"] if f.running else []
    steps = [Step([tool, *perm, f"--new-service={svc}"]),
             Step([tool, *perm, f"--service={svc}", f"--set-description=made by the Liminal platform: {spec.words}"])]
    protocols = ("tcp", "udp") if spec.protocol == "any" else (spec.protocol,)
    for a, b in spec.spans:
        for proto in protocols:
            steps.append(Step([tool, *perm, f"--service={svc}", f"--add-port={a if a == b else f'{a}-{b}'}/{proto}"]))
    if not spec.source and spec.action == "allow":
        steps.append(Step([tool, *perm, f"--zone={zone}", f"--add-service={svc}"]))
    else:
        rich = fwd_mod.rich_rule(spec.action, address_family(spec.source), spec.source, "", (), service=svc)
        steps.append(Step([tool, *perm, f"--zone={zone}", f"--add-rich-rule={rich}"]))
    if f.running:
        steps.append(Step(["firewall-cmd", "--reload"]))
    return Plan(steps, f"made in firewalld's zone {zone}: {spec.words}, as the service {svc}"
                + ("" if f.running else "; firewalld is stopped: it holds the rule for when it runs"), risk)


def _nft_place(cfg: Config, chain: nft_mod.Chain, spec: Spec) -> list:
    """Where in the chain: a block at its head; an allow before the rule that drops everything left, else at its end."""
    rules = cfg.nft.rules_of(chain) if cfg.nft else []
    if spec.action != "allow":
        return ["insert"]
    last = next((r for r in rules if nft_mod.catch_all(r)), None)
    return ["insert", last.handle] if last else ["add"]


def _make_nft(cfg: Config, spec: Spec, risk: str) -> Plan:
    hook = DIRECTION_HOOK[spec.direction]
    chains = cfg.own_filter_chains(hook)
    family = address_family(spec.source)
    words = nft_mod.match_words(spec.protocol, spec.spans, spec.source, spec.interface, spec.direction, family)
    verdict = {"allow": "accept", "block": "drop", "reject": "reject"}[spec.action]
    comment = nft_mod.comment_of(spec.name, spec.protocol if spec.protocol != "any" else "any", spec.spans, spec.source)
    if spec.action == "allow":
        dropping = [c for c in chains if c.policy == "drop" or any(nft_mod.catch_all(r) for r in cfg.nft.rules_of(c))]
        if not dropping:
            raise NotNeeded(f"nothing in this machine's nftables drops what {'comes in' if spec.direction == 'in' else 'goes out' if spec.direction == 'out' else 'passes through'} "
                            "(no chain of its own on that hook drops by default): an allow changes nothing until one does")
        chain = dropping[0]
        place = _nft_place(cfg, chain, spec)
        cmd = (nft_mod.insert_rule(chain, words, verdict, comment, before=place[1] if len(place) > 1 else None) if place[0] == "insert"
               else nft_mod.add_rule(chain, words, verdict, comment))
        return Plan([Step(cmd)], f"made in nftables' {chain.key}: {spec.words}, as Liminal's {spec.name}; it lasts until the next "
                    "restart unless saved", risk)
    if chains:
        chain = chains[0]
        return Plan([Step(nft_mod.insert_rule(chain, words, verdict, comment))],
                    f"made at the head of nftables' {chain.key}: {spec.words}, as Liminal's {spec.name}; it lasts until the next "
                    "restart unless saved", risk)
    fam, table = LIMINAL_TABLE
    steps = []
    if cfg.nft is None or cfg.nft.table(fam, table) is None:
        steps.append(Step(["nft", "add", "table", fam, table]))
    steps.append(Step(["nft", "add", "chain", fam, table, hook, "{", "type", "filter", "hook", hook, "priority", "0;", "policy", "accept;", "}"]))
    chain = nft_mod.Chain(fam, table, hook, type="filter", hook=hook, prio=0, policy="accept")
    steps.append(Step(nft_mod.insert_rule(chain, words, verdict, comment)))
    return Plan(steps, f"made in a table of Liminal's own ({fam} {table} {hook}): {spec.words}, as Liminal's {spec.name}; it lasts "
                "until the next restart unless saved", risk)


def xt_catch_all(args) -> bool:
    """An iptables rule dropping or refusing everything left: -j DROP, -j REJECT [--reject-with ...]."""
    a = list(args)
    return a in (["-j", "DROP"], ["-j", "REJECT"]) or (len(a) == 4 and a[:2] == ["-j", "REJECT"] and a[2] == "--reject-with")


def _make_iptables(cfg: Config, spec: Spec, risk: str) -> Plan:
    chain = DIRECTION_CHAIN[spec.direction]
    fam = address_family(spec.source)
    tools = [t for t in ("iptables", "ip6tables") if t in cfg.saved and (not fam or (fam == "ipv6") == (t == "ip6tables"))]
    if not tools:
        raise ValueError(f"no {'ip6tables' if fam == 'ipv6' else 'iptables'} here for that address")
    target = xt_mod.target_of(spec.action)
    steps = []
    for tool in tools:
        saved = cfg.saved[tool]
        words = xt_mod.rule_words(spec.protocol, spec.spans, spec.source, spec.interface, spec.direction, f"{PREFIX}:{spec.name}")
        rules = [r for r in saved.rules if r.table == "filter" and r.chain == chain]
        policy = next((c.policy for c in saved.chains if c.table == "filter" and c.name == chain), "ACCEPT")
        catch = next((r for r in rules if xt_catch_all(r.args)), None)
        if spec.action == "allow":
            if policy != "DROP" and catch is None:
                if len(tools) == 1:
                    raise NotNeeded(f"nothing in {tool}' {chain} drops by default: an allow changes nothing until something does")
                continue
            steps.append(Step([tool, "-t", "filter", "-I", chain, str(catch.number), *words, "-j", target] if catch
                              else [tool, "-t", "filter", "-A", chain, *words, "-j", target]))
        else:
            steps.append(Step([tool, "-t", "filter", "-I", chain, "1", *words, "-j", target]))
    if not steps:
        raise NotNeeded(f"nothing in iptables' {chain} drops by default: an allow changes nothing until something does")
    return Plan(steps, f"made in {' and '.join(tools)}' {chain}: {spec.words}, as Liminal's {spec.name}; it lasts until the next "
                "restart unless saved", risk)


# -- removing a rule ----------------------------------------------------------------------------------------------------
def plan_remove(cfg: Config, e: Entry, check_risk: bool = True) -> Plan:
    if not e.removable:
        who = OWNER_WORDS.get(e.owner, e.owner)
        raise ValueError(f"it is {who}'s own: {who} makes it again, so it is changed through {who}, not here")
    risk = risk_of_remove(cfg, e) if check_risk else ""
    parts = e.ref.split("|")
    if e.kind == "nftables":
        _, family, table, chain, handle, _ = parts
        return Plan([Step(nft_mod.delete_rule(family, table, chain, int(handle)))],
                    f"removed from nftables' {family} {table} {chain}: {e.text}; it stays removed until the next restart unless saved", risk)
    if e.kind in ("iptables", "ip6tables"):
        _, binary, table, chain, _, _ = parts
        args = shlex.split(e.text)
        return Plan([Step([binary, "-t", table, "-D", chain, *args])],
                    f"removed from {binary}' {table} {chain}: {e.text}; it stays removed until the next restart unless saved", risk)
    if e.kind == "ufw":
        if parts[0] == "ufw":
            return Plan([Step(["ufw", "--force", "delete", str(e.number)])], f"removed from ufw: {e.text}", risk)
        spec = re.sub(r"\s+comment\s+'[^']*'\s*$", "", e.text[4:] if e.text.startswith("ufw ") else e.text)
        return Plan([Step(["ufw", "--force", "delete", *spec.split()])], f"removed from ufw: {e.text}", risk)
    if e.kind == "firewalld":
        scope, name, what, value = parts[1], parts[2], parts[3], "|".join(parts[4:-1])  # a rich rule's words may hold a |
        running = cfg.firewalld.running
        steps = [Step(a) for a in fwd_mod.remove_commands(running, scope, name, what, value)]
        if e.owner == "liminal" and what == "service":
            svc = value
            for z in cfg.firewalld.zones:
                for rich in z.rich:
                    if f'service name="{svc}"' in rich:
                        steps += [Step(a) for a in fwd_mod.remove_commands(running, "zone", z.name, "rich", rich)]
            steps.append(Step(["firewall-cmd" if running else "firewall-offline-cmd", *(["--permanent"] if running else []),
                               f"--delete-service={svc}"]))
        return Plan(steps, f"removed from firewalld's {scope} {name}: {e.text}", risk)
    raise ValueError(f"{e.kind}'s rules are not removed here")


def liminal_entries(cfg: Config, name: str) -> list[Entry]:
    """The rules of Liminal's named `name` to remove, the framework's own call (a firewalld service stands for the rich
    rules naming it, which its removal takes too)."""
    found = _liminal_named(cfg, name)
    if any(e.kind == "firewalld" for e in found):
        found = [e for e in found if e.kind != "firewalld" or "|service|" in e.ref] or found
    return found


# -- default policies ---------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Policy:
    where: str  # what the page shows and sends back: "ufw incoming", "inet filter input", "iptables filter INPUT", "zone public"
    kind: str  # ufw | nftables | iptables | ip6tables | firewalld
    current: str
    choices: tuple
    inbound: bool
    note: str = ""


def policies(cfg: Config) -> list[Policy]:
    """The default policies the page may set: ufw's three, this machine's own nftables base chains of the filter type,
    iptables' built-in chains when iptables is what is in charge, firewalld's active zones' targets."""
    out = []
    if cfg.ufw.installed:
        for d in ("incoming", "outgoing", "routed"):
            out.append(Policy(f"ufw {d}", "ufw", cfg.ufw.defaults.get(d, ""), ("allow", "deny", "reject"), d == "incoming"))
    if cfg.nft is not None and cfg.manager in ("nftables", ""):
        for hook in ("input", "forward", "output"):
            for c in cfg.own_filter_chains(hook):
                out.append(Policy(c.key, "nftables", c.policy or "accept", ("accept", "drop"), hook == "input"))
    if cfg.manager == "iptables":
        for tool, saved in cfg.saved.items():
            for c in saved.chains:
                if c.table == "filter" and c.name in ("INPUT", "FORWARD", "OUTPUT"):
                    out.append(Policy(f"{tool} filter {c.name}", tool, c.policy, ("ACCEPT", "DROP"), c.name == "INPUT"))
    if cfg.firewalld.installed:
        for z in cfg.firewalld.zones:
            if z.active or z.default:
                out.append(Policy(f"zone {z.name}", "firewalld", z.target, ("default", "ACCEPT", "DROP", "%%REJECT%%"), True,
                                  "default: what the zone does not let in is refused"))
    return out


def plan_policy(cfg: Config, where: str, policy: str) -> Plan:
    p = next((x for x in policies(cfg) if x.where == where), None)
    if p is None:
        raise ValueError(f"no default policy {where!r} is set here: Refresh, then choose one listed")
    if policy not in p.choices:
        raise ValueError(f"{where}'s policy is one of {', '.join(p.choices)}")
    opens = policy.lower() in ("accept", "allow")
    risk = ""
    if p.inbound and opens:
        risk = (f"{where} lets in by default what no rule drops: every port of this machine is reached from outside "
                "unless a rule stops it.")
    elif p.inbound and not opens and cfg.system.ssh_ports:
        entries = cfg.entries()
        cut = [port for port in sorted(cfg.system.ssh_ports) if not ssh_allowed(cfg, entries, port)]
        if cut:
            only = sorted({s for port in cut for s in ssh_only_from(entries, port)})
            risk = (f"No rule lets SSH in from everywhere (sshd listens on {', '.join(map(str, cut))}"
                    + (f"; only from {', '.join(only)}" if only else "") + f"{_ssh_note(cfg)}): with {where} dropping by default, "
                    "whoever reaches this machine over SSH may be cut off, perhaps you.")
    if p.kind == "ufw":
        steps = [Step(ufw_mod.default_command(where.split()[1], policy))]
    elif p.kind == "nftables":
        family, table, chain = where.split()
        c = cfg.nft.chain(family, table, chain)
        steps = [Step(nft_mod.set_policy(c, policy))]
    elif p.kind in ("iptables", "ip6tables"):
        tool, table, chain = where.split()
        steps = [Step([tool, "-t", table, "-P", chain, policy])]
    else:
        zone = where.split(None, 1)[1]
        f = cfg.firewalld
        if f.running:
            steps = [Step(["firewall-cmd", "--permanent", f"--zone={zone}", f"--set-target={policy}"]), Step(["firewall-cmd", "--reload"])]
        else:
            steps = [Step(["firewall-offline-cmd", f"--zone={zone}", f"--set-target={policy}"])]
    lasting = "; it lasts until the next restart unless saved" if p.kind in ("nftables", "iptables", "ip6tables") else ""
    return Plan(steps, f"{where}: {p.current or 'unset'} -> {policy}{lasting}", risk)


# -- on and off ---------------------------------------------------------------------------------------------------------
def switches(cfg: Config) -> list[tuple[str, bool]]:
    """What can be turned on or off here, and whether it is on: ufw, firewalld, and the services loading nftables' or
    iptables' saved rules at boot."""
    out = []
    if cfg.ufw.installed:
        out.append(("ufw", cfg.ufw.active))
    if cfg.firewalld.installed:
        out.append(("firewalld", cfg.firewalld.running))
    for name in ("nftables", "iptables", "netfilter-persistent"):
        s = cfg.system.service(name)
        if s.present and cfg.manager not in ("ufw", "firewalld"):
            out.append((name, bool(s.running)))
    return out


def plan_switch(cfg: Config, part: str, on: bool) -> Plan:
    known = dict(switches(cfg))
    if part not in known:
        raise ValueError(f"{part} is not turned on or off here")
    init = cfg.system.init
    if on and part == "ufw" and cfg.firewalld.running:
        raise ValueError("firewalld is on: two front ends would fight over the rules; turn firewalld off first")
    if on and part == "firewalld" and cfg.ufw.active:
        raise ValueError("ufw is on: two front ends would fight over the rules; turn ufw off first")
    others = sorted({OWNER_WORDS.get(e.owner, e.owner) for e in cfg.entries()
                     if e.owner not in ("own", "liminal", "ufw", "firewalld") and e.kind in ("nftables", "iptables", "ip6tables")})
    if not on:
        risk = {
            "ufw": "ufw stops filtering: everything its rules drop, every port, can be reached from outside.",
            "firewalld": "firewalld stops filtering: everything its zones refuse can be reached from outside.",
        }.get(part, f"Stopping {part} flushes the rules on most distributions (the nftables service flushes the whole ruleset)"
                    + (f", {', '.join(others)}'s with them until they make them again" if others else "")
                    + ": what they drop gets through.")
        if part == "ufw":
            steps = [Step(["ufw", "disable"])]
        else:
            steps = [Step(a, check=a[:2] != ["rc-update", "del"]) for a in service_command(init, part, "stop")]
        return Plan(steps, f"{part} turned off" + ("" if part == "ufw" else " and kept off at boot"), risk)
    if part == "ufw":
        steps, lines = [], []
        rules = cfg.entries()
        for port in sorted(cfg.system.ssh_ports):
            if not any(e.kind == "ufw" and e.direction == "in" and e.action in ALLOWS and e.covers(port) for e in rules):
                steps.append(Step(ufw_mod.rule_command("allow", "in", "tcp", ((port, port),), "", "", f"{PREFIX}:ssh")))
                lines.append(f"SSH kept open first (sshd listens on {port}), as Liminal's ssh")
        steps.append(Step(["ufw", "--force", "enable"]))
        svc = cfg.system.service("ufw")
        if init == "openrc" and svc.present and not svc.at_boot:  # ufw enable sets ENABLED; OpenRC starts it at boot once added
            steps.append(Step(["rc-update", "add", "ufw", "default"]))
        return Plan(steps, "ufw turned on, and on at boot", "", lines)
    risk = ""
    if part in ("nftables", "iptables", "netfilter-persistent") and others:
        risk = (f"Starting {part} loads the saved rules, and most distributions flush the ruleset first: {', '.join(others)}'s "
                "rules go until they make them again (Docker's when it restarts).")
    steps = [Step(a) for a in service_command(init, part, "start")]
    return Plan(steps, f"{part} turned on, and on at boot", risk)


# -- saving -------------------------------------------------------------------------------------------------------------
def saveable(cfg: Config) -> list[str]:
    """What has rules made at run time that a restart would lose: nftables' or iptables' own, when in charge."""
    out = []
    if cfg.manager == "nftables" and cfg.nft is not None:
        out.append("nftables")
    if cfg.manager == "iptables" and cfg.saved:
        out.append("iptables")
    return out


def own_tables(cfg: Config) -> list[nft_mod.Table]:
    skip = cfg.skipped_tables()
    return [t for t in (cfg.nft.tables if cfg.nft else []) if (t.family, t.name) not in skip
            and nft_mod.table_owner(t, cfg.nft.chains) in ("own", "liminal")]


def plan_save(cfg: Config, kind: str) -> Plan:
    if kind not in saveable(cfg):
        if cfg.manager in ("ufw", "firewalld"):
            raise ValueError(f"{cfg.manager} keeps its rules itself: nothing to save")
        raise ValueError(f"{kind} is not what holds the rules here")
    keep = cfg.system.keeping(kind)
    if keep.how == "none":
        raise ValueError(f"not saved: {keep.note}")
    boot = cfg.system.service(keep.service) if keep.service else None
    later = ([f"the {keep.service} service is not on at boot: turn it on (the Firewall table) for the saved rules to load"]
             if boot is not None and boot.present and boot.at_boot is False else [])
    if keep.how == "command":
        steps = [Step(list(keep.command))]
        if kind == "iptables" and "ip6tables" in cfg.saved:  # IPv6's own save beside it
            if keep.command[:2] == ("rc-service", "iptables"):
                steps.append(Step(["rc-service", "ip6tables", "save"]))
            elif keep.command == ("systemctl", "start", "iptables-store.service"):
                steps.append(Step(["systemctl", "start", "ip6tables-store.service"]))
        return Plan(steps, f"saved by {' '.join(keep.command)} to {keep.path}: {keep.note}", "", later)
    if kind == "nftables":
        tables = own_tables(cfg)
        if not tables:
            raise ValueError("this machine has no nftables table of its own to save")
        for t in tables:
            if t.family not in nft_mod.IPTABLES_FAMILIES and t.family not in ("inet", "netdev") or not SAFE_NAME.match(t.name):
                raise ValueError(f"the table {t.key} is not saved by name here")
        listing = "; ".join(f"nft -s list table {t.family} {t.name}" for t in tables)
        script = ("set -e; f=" + shlex.quote(keep.path) + '; new="$f.liminal-new"; '
                  "{ printf '#!/usr/sbin/nft -f\\n# saved by the Liminal platform: the tables of this machine\\n\\nflush ruleset\\n\\n'; "
                  + listing + '; } > "$new"; nft -c -f "$new"; '
                  'if [ -e "$f" ]; then cp -p "$f" "$f.liminal-$(date +%Y%m%d-%H%M%S)"; fi; mv "$new" "$f"')
        names = ", ".join(t.key for t in tables)
        return Plan([Step(["sh", "-c", script])], f"saved to {keep.path} ({names}): {keep.note}; the file before is kept beside it",
                    "", [f"checked with nft -c before it replaced {keep.path}", *later])
    # iptables to a file: iptables-save and ip6tables-save, each to its own
    pairs = {"/etc/sysconfig/iptables": "/etc/sysconfig/ip6tables", "/etc/iptables/iptables.rules": "/etc/iptables/ip6tables.rules",
             "/var/lib/iptables/rules-save": "/var/lib/ip6tables/rules-save"}
    steps = []
    for tool, path in (("iptables", keep.path), ("ip6tables", pairs.get(keep.path, ""))):
        if tool not in cfg.saved or not path:
            continue
        script = ("set -e; f=" + shlex.quote(path) + '; new="$f.liminal-new"; ' + f'{tool}-save > "$new"; '
                  'if [ -e "$f" ]; then cp -p "$f" "$f.liminal-$(date +%Y%m%d-%H%M%S)"; fi; mv "$new" "$f"')
        steps.append(Step(["sh", "-c", script]))
    return Plan(steps, f"saved to {keep.path}{' and its ip6tables file' if len(steps) > 1 else ''}: {keep.note}; the file before is kept beside it",
                "", later)
