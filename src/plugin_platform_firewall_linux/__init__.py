"""Linux firewalls for Liminal (the user, 2026-11-07: "i also need a windows and linux firewall plugin for the platform";
2026-11-08, on the Windows one: "i need it to be able to read the configuration, and make changes", "basically the
firewall plugin is an interface for windows networking / defender / firewall, and will let me make queries and alter
the firewall configurations"; then "lets mirror that for linux firewall, except research the current linux kernel, and
make sure its compatable with systemd/openrc it has access nftables, iptables, all the firewall technologies and
libraries for the most modern kernels, make sure its compatible with major distributions and gentoo linxu").

An interface to the firewall of the native Linux machine the platform runs on, and nowhere else (the user, 2026-11-08:
"the scope of linux administration is only on native linux O/S"; "Yes, firewall too"; on Windows, macOS and inside a
WSL distribution it runs no command at all: the library's machines.linux.why_not_native). It reads the whole
configuration in one read (read.SCRIPT, as root through the library's machines.linux.Shell: `sudo -n`, never a password
asked), kept READ_S and read again after each change: nftables' ruleset, iptables and ip6tables (the nf_tables variant
and legacy x_tables), ebtables, arptables, ipset, firewalld's zones and policies, ufw, the connections tracked, the
interfaces, eBPF and XDP programs (read only), the firewall services under systemd, OpenRC or SysV scripts, and where
the distribution keeps its rules across a restart. The platform's page shows it as tables (status.tables): the firewall's
parts, the interfaces, firewalld's zones, the default policies, every rule (its presets and Find), the sets. Every
change is a confirmed form: a rule made (Liminal's, named), a rule removed (this machine's own, ufw's, firewalld's,
Liminal's; never a program's that makes its own, Docker's), a default policy set, a front end or firewall service
turned on or off, the rules made at run time saved where the distribution loads them at boot. A change that can cut
this machine off over SSH or open it to everyone needs a second confirmation (changes.Risky, accept_risk).

The library's Firewall base still holds the framework's own part (its setup: on, the framework's pages kept to this
machine, the ports its services need as Liminal's rules), over the same read.

    python -m plugin_platform_firewall_linux status | tables | rules [PRESET] [WORDS] | setup [STEP ...] | exposure
                                             | allow NAME PORT[,PORT ...] [tcp|udp] | remove NAME | run -- COMMAND
"""
from __future__ import annotations

import threading
import time

from liminal_libs.machines.firewall import Firewall, FirewallError, FirewallNotNeeded, Rule, app_ports
from liminal_libs.machines.linux import Shell, why_not_native
from liminal_libs.machines.plugin import CommandError

from . import changes as ch
from . import nftables as nft_mod
from . import read as read_mod
from .changes import ACCEPT, NotNeeded, Risky
from .model import DIRECTIONS, MAX_ROWS, OWNER_WORDS, PRESET_NAMES, PRESETS
from .read import SCRIPT, Config

__version__ = "0.4.1"
READ_S = 60.0  # the configuration read is kept this long; a change, a Refresh read it again
READ_TIMEOUT_S = 90.0
FRONTS = ("ufw", "firewalld")
POLICY_ORDER = ("default", "allow", "accept", "ACCEPT", "deny", "drop", "DROP", "reject", "%%REJECT%%")
POLICY_NOTES = {"allow": "let in", "accept": "let in", "ACCEPT": "let in", "deny": "dropped", "drop": "dropped", "DROP": "dropped",
                "reject": "refused", "%%REJECT%%": "refused (firewalld's)", "default": "firewalld's default: refused"}


class LinuxFirewallPlugin(Firewall):
    name = "firewall-linux"
    title = "Linux firewall"
    about = ("the native Linux machine's firewall, read whole and changed from the platform's page: nftables, iptables "
             "(nf_tables and legacy), ebtables, arptables, ipset, firewalld, ufw, conntrack, eBPF and XDP (read only), "
             "under systemd, OpenRC or SysV scripts; never a WSL distribution")
    api = "2.1"
    order = 711
    ICON = "wallfire"  # a brick wall with a flame before it (liminal-libs 1.34.0; the user's picture: "use this icon for linux firewall")
    HOOKS = (*Firewall.HOOKS, "refresh", "show_rules", "find_rules", "make_rule", "remove_rule", "set_policy", "switch",
             "save_rules")

    def __init__(self, shell: Shell | None = None, runner=None, native: str | None = None, clock=time.monotonic):
        self._shell = shell
        self._runner = runner
        self._native = native  # a test's word for why_not_native(): "" on a native Linux machine, else why not
        self._clock = clock
        self._lock = threading.RLock()
        self._read: tuple[float, Config] | None = None
        self._preset = "in-allow"
        self._find = ""

    # -- where it works -------------------------------------------------------------------------------------------------
    def not_for_here(self) -> str:
        """Why the machine the platform runs on is not a native Linux one, in words ("" when it is): the library's
        status and setup honor it (applies False, nothing changed)."""
        return why_not_native("The Linux firewall") if self._native is None else self._native

    @property
    def shell(self) -> Shell:
        """This native Linux machine's commands (root through sudo -n); refused anywhere else, and for a WSL target."""
        note = self.not_for_here()
        if note:
            raise FirewallError(note)
        sh = self._shell if self._shell is not None else Shell("local", runner=self._runner)
        if sh.target != "local":
            raise FirewallError(f"The Linux firewall is for this native Linux machine, never {sh.where}")
        return sh

    # -- the one read ---------------------------------------------------------------------------------------------------
    def config(self, fresh: bool = False) -> Config:
        """The whole configuration, read at most every READ_S (now when `fresh`); CommandError when it cannot be read."""
        sh = self.shell
        with self._lock:
            now = self._clock()
            if not fresh and self._read is not None and now - self._read[0] < READ_S:
                return self._read[1]
            text = sh.sh(SCRIPT, timeout=READ_TIMEOUT_S)
            try:
                cfg = read_mod.parse(text)
            except ValueError as e:
                raise CommandError(f"the firewall's read gave no answer of its own: {e}") from None
            self._read = (now, cfg)
            return cfg

    def forget(self) -> None:
        with self._lock:
            self._read = None

    def present(self) -> bool:
        """Firewall tools this plugin reads on a native Linux machine: never on Windows, macOS or in WSL."""
        if self.not_for_here():
            return False
        try:
            return self.shell.here and bool(self.config().manager)
        except CommandError:
            return False

    # -- the library's backend, over the read --------------------------------------------------------------------------
    def backend(self) -> str:
        cfg = self.config()
        return f"{_named(cfg.manager, cfg)} on {self.shell.where}" if cfg.manager else f"no firewall software on {self.shell.where}"

    def state(self) -> dict:
        return self.config().state()

    def list_rules(self, owned_only: bool = True) -> list[Rule]:
        cfg = self.config()
        if owned_only:
            return cfg.liminal_rules()
        out = cfg.liminal_rules()
        for e in cfg.entries():
            if e.owner == "liminal" or e.direction not in ("in", "out") or e.action not in ("accept", "limit", "drop", "reject"):
                continue
            protocol = e.protocol if e.protocol in ("tcp", "udp") else "any"
            ports = tuple(sorted({p for a, b in e.spans for p in range(a, min(b, a + 1023) + 1)})) if protocol != "any" else ()
            try:
                out.append(Rule(f"{e.kind} {e.where}: {e.text}", ports=ports, protocol=protocol, direction=e.direction,
                                action="allow" if e.action in ("accept", "limit") else "block", remote=e.source or "any",
                                owned=False, detail=e.text))
            except ValueError:
                continue
        return out

    def add_rule(self, rule: Rule) -> None:
        if not rule.owned:
            raise FirewallError("only Liminal's own rules are made here")
        spec = ch.Spec(rule.name, rule.direction, "allow" if rule.action == "allow" else "block", rule.protocol,
                       tuple((p, p) for p in rule.ports), "" if rule.remote == "any" else rule.remote, "")
        try:
            plan = ch.plan_make(self.config(fresh=True), spec, framework=True)
        except NotNeeded as e:
            raise FirewallNotNeeded(str(e)) from None
        except ValueError as e:
            raise FirewallError(str(e)) from None
        self._run(plan)

    def delete_rule(self, name: str) -> bool:
        """Every rule of Liminal's named `name` removed, one at a time over a fresh read each (ufw's numbers move)."""
        tried: set = set()
        for _ in range(32):
            cfg = self.config(fresh=True)
            left = [e for e in ch.liminal_entries(cfg, name) if e.ref not in tried]
            if not left:
                break
            tried.add(left[0].ref)  # one that stays after its removal is not asked again
            self._run(ch.plan_remove(cfg, left[0], check_risk=False))
        return bool(tried)

    def enable(self) -> None:
        cfg = self.config(fresh=True)
        if cfg.manager not in FRONTS:
            raise FirewallError(f"{_named(cfg.manager, cfg) or 'nothing here'} has no switch: its rules filter or not")
        self._run(ch.plan_switch(cfg, cfg.manager, True))

    def can_enable(self) -> bool:
        return self.config().manager in FRONTS

    def exposing(self, ports) -> list[tuple[int, str]]:
        return self.config().exposing(ports)

    def run(self, *command: str, **options) -> str:
        """A command on this machine, as root, its output."""
        return self.shell.run(*command)

    def _run(self, plan: ch.Plan) -> list[str]:
        """A plan's commands one after another as root; the read forgotten after, whatever happened."""
        sh = self.shell
        ran: list[str] = []
        try:
            for step in plan.steps:
                sh.run(*step.args, stdin=step.stdin, check=step.check)
                ran.append(step.words)
        except CommandError as e:
            done = f" (done before it: {'; '.join(ran)})" if ran else ""
            raise CommandError(f"{e}{done}", denied=getattr(e, "denied", False)) from None
        finally:
            self.forget()
        return ran

    # -- the hooks the page asks ---------------------------------------------------------------------------------------
    def refresh(self) -> dict:
        cfg = self.config(fresh=True)
        return {"said": f"read again: {_summary(cfg)}"}

    def show_rules(self, preset: str) -> dict:
        if preset not in PRESET_NAMES:
            raise ValueError(f"the rules shown are one of {', '.join(PRESET_NAMES)}")
        with self._lock:
            self._preset = preset
        return {"said": f"showing {dict((p[0], p[1]) for p in PRESETS)[preset].lower()}"}

    def find_rules(self, words: str | None = None) -> dict:
        words = " ".join(str(words or "").split())[:80]
        with self._lock:
            self._find = words
        return {"said": f"finding {words!r}" if words else "every rule of the choice shown"}

    def make_rule(self, name, direction="in", action="allow", protocol="tcp", ports=None, remote=None, interface=None,
                  accept_risk=False) -> dict:
        spec = ch.spec_of(name, direction, action, protocol, ports, remote, interface)
        cfg = self.config(fresh=True)
        plan = ch.plan_make(cfg, spec, framework_ports=sorted(set(app_ports().values())))
        return self._apply(plan, accept_risk)

    def remove_rule(self, where, rule, accept_risk=False) -> dict:
        cfg = self.config(fresh=True)
        e = cfg.entry(str(where or ""), str(rule or ""))
        if e is None:
            raise LookupError("that rule is no longer there as it was read: Refresh, then choose it again")
        return self._apply(ch.plan_remove(cfg, e), accept_risk)

    def set_policy(self, where, policy, accept_risk=False) -> dict:
        cfg = self.config(fresh=True)
        return self._apply(ch.plan_policy(cfg, str(where or ""), str(policy or "")), accept_risk)

    def switch(self, part, state, accept_risk=False) -> dict:
        if state not in ("on", "off"):
            raise ValueError("turned on or off")
        cfg = self.config(fresh=True)
        return self._apply(ch.plan_switch(cfg, str(part or ""), state == "on"), accept_risk)

    def save_rules(self, kind) -> dict:
        cfg = self.config(fresh=True)
        return self._apply(ch.plan_save(cfg, str(kind or "")), True)

    def _apply(self, plan: ch.Plan, accept_risk) -> dict:
        if plan.risk and accept_risk is not True:
            raise Risky(plan.risk)
        ran = self._run(plan)
        return {"said": plan.said, "lines": [*plan.lines, *(f"ran: {w}" for w in ran)]}

    # -- the status ---------------------------------------------------------------------------------------------------
    def status(self) -> dict:
        """Valid whenever the firewall can be read (the Windows firewall plugin's rule): the base's "no Liminal rules"
        and "off" are said in the summary and the tables, not as invalid."""
        here = self.not_for_here()
        if here:  # not for this machine at all (on Windows, macOS or in WSL): asked nothing, no setup offered
            return self.not_here_status(here, backend="", enabled=False, profiles={}, rules=[])
        try:
            cfg = self.config()
        except CommandError as e:
            return {"present": True, "backend": "", "enabled": False, "profiles": {}, "problem": str(e),
                    "summary": f"cannot be read: {e}", "valid": False, "why": f"cannot be read: {e}"}
        if not cfg.manager:
            return {"present": False, "backend": "", "enabled": False, "profiles": {}, "summary": "no firewall software here",
                    "valid": False, "why": "no firewall software here: nftables, iptables, ufw or firewalld"}
        with self._lock:
            preset, find = self._preset, self._find
        out = {"present": True, "backend": _named(cfg.manager, cfg), **cfg.state(), "summary": _summary(cfg), "valid": True,
               "why": "", "distribution": cfg.system.name, "kernel": cfg.system.kernel, "init": cfg.system.init_words,
               "readAt": time.strftime("%H:%M:%S", time.localtime(cfg.at))}
        if cfg.problems:
            out["problems"] = list(cfg.problems)
        out["tables"] = tables(cfg, preset, find)
        out["forms"] = forms(cfg)
        out["actions"] = [{"hook": "refresh", "args": [], "title": "Refresh", "note": "reads the whole configuration again now"}]
        return out


def _named(manager: str, cfg: Config) -> str:
    if manager == "ufw":
        return f"ufw {cfg.ufw.version}".strip()
    if manager == "firewalld":
        return f"firewalld {cfg.firewalld.version}".strip()
    if manager == "nftables":
        return f"nftables {cfg.nft_version}".strip()
    if manager == "iptables":
        return f"iptables {cfg.iptables_version} ({cfg.iptables_variant or 'legacy'})"
    return manager


def _summary(cfg: Config) -> str:
    m = cfg.manager
    on = "on" if cfg.state().get("enabled") else "off"
    over = f" over nftables {cfg.nft_version}" if cfg.nft is not None and m != "nftables" else ""
    return (f"{_named(m, cfg)}{over}: {on}; {len(cfg.entries())} rule(s) read, {len(cfg.liminal_rules())} of them Liminal's; "
            f"{cfg.system.name}, {cfg.system.init_words}")


# -- the tables (liminal-platform 0.7.0: a table's own options and actions; cell buttons opening forms) ----------------------
def _cell(text, sub=None):
    return {"text": text, "sub": sub} if sub else text


def _when(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else ""


def parts_table(cfg: Config) -> dict:
    """The firewall's parts: what is there, its state and version, what it holds, how its rules last, its switch."""
    s = cfg.system
    rows = []
    switch = dict(ch.switches(cfg))
    saving = set(ch.saveable(cfg))

    def toggle(part):
        if part not in switch:
            return ""
        on = switch[part]
        return {"form": "switch", "title": "Turn off…" if on else "Turn on…", "values": {"part": part, "state": "off" if on else "on"},
                "label": f"Turn {part} {'off' if on else 'on'}"}

    def save(kind):
        if kind not in saving:
            return ""
        return {"form": "save", "title": "Save…", "values": {"kind": kind}, "label": f"Save {kind}' rules for the next restart"}

    def boot(name):
        sv = s.service(name)
        if not sv.present:
            return ""
        return f"{name} service: {'running' if sv.running else 'stopped' if sv.running is False else 'state not known'}" + (
            ", at boot" if sv.at_boot else ", not at boot" if sv.at_boot is False else "")

    def kept(kind):
        k = s.keeping(kind)
        if k.how == "none":
            return k.note
        when = _when(s.files.get(k.path, 0))
        return f"kept in {k.path}" + (f" (changed {when})" if when else " (not there yet)") + f": {k.note}"

    if cfg.nft is not None or "nft" in cfg.tools:
        rs = cfg.nft
        holds = f"{len(rs.tables)} tables, {len(rs.chains)} chains, {len(rs.rules)} rules, {len(rs.sets)} sets" if rs else "its ruleset could not be read"
        sub = "; ".join(x for x in (boot("nftables"), kept("nftables") if cfg.manager == "nftables" else "") if x)
        rows.append(["nftables", "in charge" if cfg.manager == "nftables" else "the kernel's filter", cfg.nft_version,
                     _cell(holds, sub or None), toggle("nftables"), save("nftables")])
    if cfg.saved or "iptables" in cfg.tools:
        variant = cfg.iptables_variant or "legacy"
        n = sum(len(x.rules) for x in cfg.saved.values())
        legacy = sum(len(x.rules) for x in cfg.legacy.values())
        holds = f"{n} rules (iptables and ip6tables)" + (f"; {legacy} more in the legacy x_tables, beside nftables" if legacy else "")
        if variant == "nf_tables":
            holds += "; its tables are nftables'"
        sub = "; ".join(x for x in (boot("iptables") or boot("netfilter-persistent"), kept("iptables") if cfg.manager == "iptables" else "") if x)
        rows.append(["iptables", "in charge" if cfg.manager == "iptables" else variant, f"{cfg.iptables_version} ({variant})",
                     _cell(holds, sub or None), toggle("iptables") or toggle("netfilter-persistent"), save("iptables")])
    for tool, (version, variant) in (("ebtables", cfg.ebtables), ("arptables", cfg.arptables)):
        if version or tool in cfg.tools:
            rows.append([tool, variant or "there", f"{version} ({variant})" if variant else version,
                         "bridge filtering" if tool == "ebtables" else "ARP filtering", "", ""])
    if cfg.ipsets or "ipset" in cfg.tools:
        n = sum(x.entries for x in cfg.ipsets)
        names = ", ".join(x.name for x in cfg.ipsets[:6])
        rows.append(["ipset", f"{len(cfg.ipsets)} sets", cfg.ipset_version, f"{n} entries" + (f": {names}" if names else ""), "", ""])
    f = cfg.firewalld
    if f.installed:
        sub = "; ".join(x for x in (f"on {f.backend}" if f.backend else "", boot("firewalld"), "keeps its own rules") if x)
        rows.append(["firewalld", "running" if f.running else "stopped", f.version,
                     _cell(f"default zone {f.default_zone or '?'}; {sum(1 for z in f.zones if z.active)} active zones", sub), toggle("firewalld"), ""])
    u = cfg.ufw
    if u.installed:
        d = u.defaults
        rows.append(["ufw", "on" if u.active else "off", u.version,
                     _cell(f"{len(u.rows) if u.active else len(u.added)} rules; by default {d.get('incoming', '?')} in, "
                           f"{d.get('outgoing', '?')} out, {d.get('routed', '?')} routed", f"logging {u.logging or '?'}; keeps its own rules"),
                     toggle("ufw"), ""])
    count, top = s.conntrack
    if count is not None:
        rows.append(["conntrack", "tracking", "", f"{count} of {top} connections tracked" if top else f"{count} connections tracked", "", ""])
    xdp = [f"{i.name}: {i.xdp}" for i in s.interfaces if i.xdp]
    if xdp or s.bpf:
        rows.append(["eBPF and XDP", "read only", "", "; ".join(xdp + [b for b in s.bpf if not b.startswith("xdp")]) or "none attached", "", ""])
    note = f"{s.name} (kernel {s.kernel}), {s.init_words}" + (f"; read {time.strftime('%H:%M:%S', time.localtime(cfg.at))}" if cfg.at else "")
    if cfg.problems:
        note += "; not read: " + "; ".join(cfg.problems)
    return {"title": "Firewall", "note": note, "columns": [{"title": "Part"}, {"title": "State"}, {"title": "Version"},
            {"title": "What it holds"}, {"title": ""}, {"title": ""}], "rows": rows, "empty": "No firewall software here."}


def interfaces_table(cfg: Config) -> dict:
    zone_of = {}
    for z in cfg.firewalld.zones:
        for i in z.words("interfaces"):
            zone_of[i] = z.name
    default = f"{cfg.firewalld.default_zone} (default)" if cfg.firewalld.running and cfg.firewalld.default_zone else ""
    rows = [[i.name, i.state or "?", _cell(", ".join(i.addresses[:3]) or "no address", ", ".join(i.addresses[3:]) or None),
             zone_of.get(i.name, default if i.name != "lo" else ""), i.xdp] for i in cfg.system.interfaces]
    return {"title": "Interfaces", "columns": [{"title": "Interface"}, {"title": "State"}, {"title": "Addresses"},
            {"title": "Zone"}, {"title": "XDP"}], "rows": rows, "empty": "None read (no ip command)."}


def zones_table(cfg: Config) -> dict | None:
    f = cfg.firewalld
    if not f.installed or not f.zones:
        return None
    rows = []
    for z in sorted(f.zones, key=lambda z: (not z.active, not z.default, z.name)):
        if not (z.active or z.default):
            continue
        rows.append([_cell(z.name, "default" if z.default else None), " ".join(z.words("interfaces") + z.words("sources")) or "–",
                     z.target, " ".join(z.words("services")) or "–", " ".join(z.words("ports")) or "–", len(z.rich),
                     {"form": "policy", "title": "Target…", "values": {"where": f"zone {z.name}", "policy": z.target},
                      "label": f"Set the zone {z.name}'s target"}])
    others = [z.name for z in f.zones if not (z.active or z.default)]
    return {"title": "Zones", "note": "firewalld's zones in force" + (f"; bound to nothing: {', '.join(others)}" if others else ""),
            "columns": [{"title": "Zone"}, {"title": "Interfaces and sources"}, {"title": "Target"}, {"title": "Services"},
                        {"title": "Ports"}, {"title": "Rich rules", "num": True}, {"title": ""}], "rows": rows}


def policies_table(cfg: Config) -> dict:
    rows = []
    for p in ch.policies(cfg):
        if p.kind == "firewalld":
            continue  # in the Zones table
        rows.append([p.where, OWNER_WORDS.get("own") if p.kind in ("nftables", "iptables", "ip6tables") else p.kind, p.current or "unset",
                     "what comes in" if p.inbound else "", {"form": "policy", "title": "Set…", "values": {"where": p.where, "policy": p.current},
                                                            "label": f"Set {p.where}'s default"}])
    settable = {p.where for p in ch.policies(cfg)}
    if cfg.nft is not None:  # the other base chains, read only: another program's, or a front end's machinery
        skip = cfg.skipped_tables()
        for c in cfg.nft.chains:
            if c.base and (c.family, c.table) not in skip and c.key not in settable:
                t = cfg.nft.table(c.family, c.table)
                owner = nft_mod.table_owner(t, cfg.nft.chains) if t else "own"
                rows.append([c.key, OWNER_WORDS.get(owner, owner), c.policy or "accept", f"{c.type} {c.hook}, priority {c.prio}", ""])
    for tool, saved in cfg.saved.items():  # iptables' built-in chains, read only unless iptables is in charge
        for c in saved.chains:
            where = f"{tool} {c.table} {c.name}"
            if c.policy != "-" and c.table == "filter" and where not in settable:
                whose = "ufw" if cfg.ufw.installed and c.name in ("INPUT", "FORWARD", "OUTPUT") else f"iptables ({cfg.iptables_variant or 'legacy'})"
                rows.append([where, whose, c.policy, "what comes in" if c.name == "INPUT" else "", ""])
    hidden = ", ".join(f"{OWNER_WORDS.get(k, k)}'s {n}" for k, n in cfg.hidden.items())
    return {"title": "Default policies", "note": ("What each does with what no rule decides; other programs' chains are read only"
            + (f". A front end's own machinery is shown through it ({hidden} rules)" if hidden else "")),
            "columns": [{"title": "Where"}, {"title": "Whose"}, {"title": "Default"}, {"title": "For"}, {"title": ""}],
            "rows": rows, "empty": "No default policy here."}


def rules_table(cfg: Config, preset: str, find: str) -> dict:
    entries = cfg.entries()
    shown = [e for e in entries if e.shown(preset) and e.found(find)]
    rows = []
    for e in shown[:MAX_ROWS]:
        does = e.action + (f" {e.target}" if e.target and e.action in ("jump", "goto", "nat") else "")
        port = f"{e.protocol} {e.ports}".strip() if e.ports or e.protocol else "every"
        frm = e.source or ("anywhere" if e.direction in ("in", "fwd") else "")
        button = ({"form": "remove", "title": "Remove…", "values": {"where": e.where, "rule": e.text}, "label": f"Remove {e.text}"}
                  if e.removable else "")
        rows.append([_cell(e.where, e.kind), DIRECTIONS.get(e.direction, e.direction), does, port,
                     _cell(frm, f"on {e.interface}" if e.interface else None) if frm or e.interface else "", e.destination,
                     _cell(e.text, e.comment if e.comment and e.comment not in e.text else None), OWNER_WORDS.get(e.owner, e.owner), button])
    more = len(shown) - len(rows)
    note = (f"{len(shown)} of {len(entries)} rules" + (f", the first {len(rows)} shown: Find narrows it" if more > 0 else "")
            + (f"; finding {find!r}" if find else "") + ". A program's own rules (Docker's...) are read only: it makes them again.")
    actions = [{"form": "make", "title": "Add a rule…"}, {"form": "find", "title": "Find…", "values": {"words": find}},
               {"hook": "refresh", "args": [], "title": "Refresh", "note": "reads the whole configuration again now"}]
    if find:
        actions.insert(2, {"hook": "find_rules", "args": [""], "title": "Show all", "note": "the Find's words cleared"})
    return {"title": "Rules", "note": note,
            "options": [{"title": "Rules shown", "hook": "show_rules", "value": preset,
                         "choices": [{"value": v, "title": t, "note": n} for v, t, n in PRESETS]}],
            "columns": [{"title": "Where"}, {"title": "Way"}, {"title": "Does"}, {"title": "Port"}, {"title": "From"},
                        {"title": "To"}, {"title": "Rule"}, {"title": "Whose"}, {"title": ""}],
            "rows": rows, "empty": "No rule of the choice shown" + (" with those words." if find else "."), "actions": actions}


def sets_table(cfg: Config) -> dict | None:
    rows = [[f"{s.family} {s.table} {s.name}", f"nftables {s.kind}", s.type, s.elements] for s in (cfg.nft.sets if cfg.nft else [])]
    rows += [[x.name, "ipset", x.type, x.entries] for x in cfg.ipsets]
    if not rows:
        return None
    return {"title": "Sets", "columns": [{"title": "Set"}, {"title": "Kind"}, {"title": "Type"}, {"title": "Elements", "num": True}],
            "rows": rows}


def tables(cfg: Config, preset: str = "in-allow", find: str = "") -> list[dict]:
    out = [parts_table(cfg), interfaces_table(cfg)]
    z = zones_table(cfg)
    if z:
        out.append(z)
    pol = policies_table(cfg)
    if pol["rows"] or not z:
        out.append(pol)
    out.append(rules_table(cfg, preset, find))
    s = sets_table(cfg)
    if s:
        out.append(s)
    return out


# -- the forms (liminal-platform 0.6.0: a hook asked with what is filled in, once the change is confirmed) ------------------
ACCEPT_FIELD = {"name": ACCEPT, "type": "accept", "title": "Go on anyway?", "yes": "Go on anyway",
                "words": "Accepting it makes the change as confirmed, knowing what is said above."}


def _choices(rows) -> list[dict]:
    return [{"value": v, "title": t, **({"note": n} if n else {})} for v, t, n in rows]


def forms(cfg: Config) -> list[dict]:
    manager = _named(cfg.manager, cfg)
    lasting = (" It lasts until the next restart unless saved (the Firewall table's Save)." if cfg.manager in ("nftables", "iptables")
               else f" {cfg.manager} keeps it itself." if cfg.manager in FRONTS else "")
    out = [
        {"id": "make", "hook": "make_rule", "title": "Add a rule",
         "note": f"Made through {manager}, as one of Liminal's rules under the name given.{lasting}",
         "fields": [
             {"name": "name", "label": "Name", "type": "text", "required": True, "placeholder": "web, office-ssh",
              "note": "lowercase letters, digits and dashes"},
             {"name": "direction", "label": "Way", "type": "choice", "value": "in",
              "choices": _choices([("in", "Coming in", "to this machine"), ("out", "Going out", "from this machine"),
                                   ("fwd", "Passing through", "forwarded: containers, VMs, routing")])},
             {"name": "action", "label": "Does", "type": "choice", "value": "allow",
              "choices": _choices([("allow", "Allow", ""), ("block", "Block", "dropped without a word"),
                                   ("reject", "Reject", "refused: the sender is told")])},
             {"name": "protocol", "label": "Protocol", "type": "choice", "value": "tcp",
              "choices": _choices([("tcp", "TCP", ""), ("udp", "UDP", ""), ("any", "Any", "every protocol, no ports")])},
             {"name": "ports", "label": "Ports", "type": "text", "placeholder": "22, 80, 443, 8000-8100",
              "note": "on this machine; none for every port", "empty": "every port"},
             {"name": "remote", "label": "The other side", "type": "text", "placeholder": "10.0.0.0/8, 192.168.1.20, 2001:db8::/32",
              "note": "an address or a network; none for anywhere", "empty": "anywhere"},
             {"name": "interface", "label": "Interface", "type": "text", "placeholder": "eth0, wg0", "empty": "every interface"},
             ACCEPT_FIELD],
         "submit": "Review the rule",
         "confirm": {"title": "Make the rule {name}?",
                     "words": f"{{action}}, {{protocol}} {{ports}}, {{direction}}, the other side {{remote}}, on {{interface}}: made through {manager}.{lasting}",
                     "yes": "Make the rule"}},
        {"id": "remove", "hook": "remove_rule", "title": "Remove a rule",
         "fields": [{"name": "where", "label": "Where", "type": "fixed"}, {"name": "rule", "label": "Rule", "type": "fixed"}, ACCEPT_FIELD],
         "confirm": {"title": "Remove this rule?", "words": "{rule} is removed from {where}." + lasting, "yes": "Remove the rule",
                     "danger": True}},
        {"id": "find", "hook": "find_rules", "title": "Find rules", "confirm": False,
         "note": "Every word must be in the rule (any case); a number finds the rules for that port too.",
         "fields": [{"name": "words", "label": "Words", "type": "text", "placeholder": "22, docker, 10.0.0.0/8, drop",
                     "note": "none shows every rule of the choice"}],
         "submit": "Find"},
    ]
    pol = ch.policies(cfg)
    if pol:
        found = {c for p in pol for c in p.choices}
        out.append({"id": "policy", "hook": "set_policy", "title": "Set a default policy",
                    "note": "What it does with what no rule decides: allow, deny or reject for ufw; accept or drop for nftables; "
                            "ACCEPT or DROP for iptables; a target for a firewalld zone.",
                    "fields": [{"name": "where", "label": "Where", "type": "fixed"},
                               {"name": "policy", "label": "Default", "type": "choice",
                                "choices": [{"value": c, "title": c, "note": POLICY_NOTES.get(c, "")} for c in POLICY_ORDER if c in found]},
                               ACCEPT_FIELD],
                    "submit": "Review",
                    "confirm": {"title": "Set {where}'s default to {policy}?", "words": "{where} does {policy} with what no rule decides.",
                                "yes": "Set it"}})
    if ch.switches(cfg):
        out.append({"id": "switch", "hook": "switch", "title": "Turn it on or off",
                    "fields": [{"name": "part", "label": "Part", "type": "fixed"}, {"name": "state", "label": "Turned", "type": "fixed"},
                               ACCEPT_FIELD],
                    "confirm": {"title": "Turn {part} {state}?", "words": "{part} is turned {state}, now and at boot.", "yes": "Yes, turn it"}})
    if ch.saveable(cfg):
        keep = {k: cfg.system.keeping(k) for k in ch.saveable(cfg)}
        words = " ".join(f"{k}: {v.note}" + (f" ({v.path}; the file before is kept beside it)." if v.how == "file"
                                             else f" ({' '.join(v.command)})." if v.how == "command" else ".") for k, v in keep.items())
        out.append({"id": "save", "hook": "save_rules", "title": "Save the rules",
                    "fields": [{"name": "kind", "label": "Rules", "type": "fixed"}],
                    "confirm": {"title": "Save {kind}' rules for the next restart?", "words": words, "yes": "Save them"}})
    return out


MACHINE = LinuxFirewallPlugin()
