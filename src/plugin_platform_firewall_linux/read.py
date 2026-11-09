"""The whole firewall configuration in one read (the Windows firewall plugin's way, for Linux): one POSIX shell script
run as root (`SCRIPT`, BusyBox's sh too) that prints every part in its own section: the distribution and kernel, the
init system, the tools there, nftables' ruleset as JSON, iptables and ip6tables as iptables-save writes them (the
nf_tables variant's, and the legacy x_tables only when the kernel has them loaded: reading them would load them),
ebtables' and arptables' variants, ipset's sets, firewalld's zones, policies and their services' ports, ufw's status
and rules, the connections tracked, the interfaces with their addresses and XDP programs, eBPF programs on the network
hooks (read only), the firewall services under the init system and at boot, the files each distribution keeps its rules
in, and the SSH server's ports. `parse` reads it into a `Config`; nothing in it is a guess when a part is missing: that
part is said as missing."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from . import firewalld as fwd_mod
from . import nftables as nft_mod
from . import system as sys_mod
from . import ufw as ufw_mod
from . import xtables as xt_mod
from .model import Entry, owner_by_interface, owner_by_name

MARK = "== liminal-firewall 1"
SECTION = re.compile(r"^@@ (\S+) (-?\d+)$")
SCRIPT = r"""echo '== liminal-firewall 1'
t=$(mktemp -d 2>/dev/null) || t=/tmp/liminal-firewall.$$
mkdir -p "$t" 2>/dev/null
have() { command -v "$1" >/dev/null 2>&1; }
sec() { n=$1; shift; "$@" >"$t/o" 2>"$t/e"; rc=$?; printf '\n@@ %s %s\n' "$n" "$rc"; cat "$t/o"
  if [ -s "$t/e" ]; then printf '\n@@ %s.err 0\n' "$n"; cat "$t/e"; fi; }
sec os sh -c 'cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release'
sec kernel uname -r
p1=$(cat /proc/1/comm 2>/dev/null || echo unknown)
if [ -d /run/systemd/system ] && have systemctl; then init=systemd
elif have rc-service && { [ -d /run/openrc ] || [ "$p1" = openrc-init ]; }; then init=openrc
elif have service || [ -d /etc/init.d ]; then init=sysvinit
else init=none; fi
printf '\n@@ init 0\n%s %s\n' "$init" "$p1"
printf '\n@@ tools 0\n'
for x in nft iptables ip6tables iptables-legacy-save ip6tables-legacy-save ebtables arptables ipset firewall-cmd \
  firewall-offline-cmd ufw conntrack bpftool ip ss netstat netfilter-persistent; do have "$x" && echo "$x $(command -v "$x")"; done
if have nft; then sec nft.version nft --version; sec nft nft -j list ruleset; fi
# a legacy iptables lists only tables its modules hold already (listing them otherwise would load ip_tables)
if have iptables; then sec iptables.version iptables -V
  case "$(iptables -V 2>/dev/null)" in *nf_tables*) sec iptables.save iptables-save ;;
  *) if [ -s /proc/net/ip_tables_names ]; then sec iptables.save iptables-save; fi ;; esac; fi
if have ip6tables; then
  case "$(ip6tables -V 2>/dev/null)" in *nf_tables*) sec ip6tables.save ip6tables-save ;;
  *) if [ -s /proc/net/ip6_tables_names ]; then sec ip6tables.save ip6tables-save; fi ;; esac; fi
if [ -s /proc/net/ip_tables_names ] && have iptables-legacy-save; then sec iptables.legacy iptables-legacy-save; fi
if [ -s /proc/net/ip6_tables_names ] && have ip6tables-legacy-save; then sec ip6tables.legacy ip6tables-legacy-save; fi
if have ebtables; then sec ebtables.version ebtables -V; fi
if have arptables; then sec arptables.version arptables -V; fi
if have ipset; then sec ipset.version ipset -v; if [ -d /sys/module/ip_set ]; then sec ipset ipset list -t; fi; fi
if have firewall-cmd || have firewall-offline-cmd; then
  case $init in  # firewall-cmd waits 10 s for D-Bus when the daemon is stopped (firewalld 2.4.3+): its service asked first
  systemd) systemctl is-active --quiet firewalld.service 2>/dev/null; up=$? ;;
  openrc) rc-service firewalld status >/dev/null 2>&1; up=$? ;;
  *) up=0 ;;
  esac
  if [ "$up" = 0 ] && have firewall-cmd; then st=$(firewall-cmd --state 2>&1); rc=$?; else st="not running"; rc=252; fi
  printf '\n@@ firewalld.state %s\n%s\n' "$rc" "$st"
  if [ "$st" = running ]; then fc=firewall-cmd; else fc=firewall-offline-cmd; fi
  if have "$fc"; then sec firewalld.version $fc --version; fi
  if have "$fc"; then
    sec firewalld.default $fc --get-default-zone
    sec firewalld.zones $fc --list-all-zones
    svcs=$(sed -n 's/^ *services: *//p' "$t/o" | tr ' ' '\n' | sort -u)
    sec firewalld.policies $fc --list-all-policies
    printf '\n@@ firewalld.services 0\n'
    for s in $svcs; do $fc --info-service="$s" 2>/dev/null; done
  fi
  if [ -r /etc/firewalld/firewalld.conf ]; then sec firewalld.conf grep -E '^(FirewallBackend|DefaultZone)=' /etc/firewalld/firewalld.conf; fi
fi
if have ufw; then sec ufw.version ufw version; sec ufw.verbose ufw status verbose; sec ufw.numbered ufw status numbered
  sec ufw.added ufw show added; fi
printf '\n@@ conntrack 0\n'
cat /proc/sys/net/netfilter/nf_conntrack_count /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null
if have ip; then sec addr ip -j addr show; if [ "$rc" != 0 ]; then sec addr.text ip addr show; fi; fi
if have bpftool; then sec bpf bpftool -j net show; fi
if have ss; then sec listen ss -ltnpH; sec listen.udp ss -lunpH; sec established ss -tnH state established
elif have netstat; then sec listen.netstat netstat -ltnp; sec listen.udp.netstat netstat -lunp; fi
printf '\n@@ services 0\n'
for s in nftables iptables ip6tables ipset firewalld ufw netfilter-persistent ebtables nftables-restore iptables-restore \
  ip6tables-restore nftables-load nftables-store iptables-store ip6tables-store; do
  case $init in
  systemd)
    if systemctl cat "$s.service" >/dev/null 2>&1; then
      echo "$s yes $(systemctl is-active "$s.service" 2>/dev/null) $(systemctl is-enabled "$s.service" 2>/dev/null)"
    else echo "$s no"; fi ;;
  openrc)
    if [ -x "/etc/init.d/$s" ]; then
      st=$(rc-service "$s" status 2>/dev/null | sed -n 's/.*status: *//p' | head -1)
      boot=$(for r in sysinit boot default; do if [ -e "/etc/runlevels/$r/$s" ]; then echo "$r"; fi; done | head -1)
      echo "$s yes ${st:-stopped} ${boot:--}"
    else echo "$s no"; fi ;;
  *) if [ -x "/etc/init.d/$s" ]; then echo "$s yes unknown"; else echo "$s no"; fi ;;
  esac
done
printf '\n@@ files 0\n'
for f in /etc/nftables.conf /etc/sysconfig/nftables.conf /etc/nftables.nft /etc/nftables.d /etc/nftables \
  /var/lib/nftables/rules-save /etc/iptables/rules.v4 /etc/iptables/rules.v6 /etc/sysconfig/iptables \
  /etc/sysconfig/ip6tables /etc/iptables/iptables.rules /etc/iptables/ip6tables.rules /var/lib/iptables/rules-save \
  /var/lib/ip6tables/rules-save /etc/iptables/rules-save /etc/iptables/rules6-save /etc/ufw/ufw.conf \
  /etc/firewalld/firewalld.conf; do
  if [ -e "$f" ]; then echo "$f $(stat -c %Y "$f" 2>/dev/null || echo 0)"; fi
done
printf '\n@@ conf 0\n'
for f in /etc/conf.d/nftables /etc/conf.d/iptables /etc/conf.d/ip6tables; do
  if [ -r "$f" ]; then sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)=\(.*\)$/\1=\2/p' "$f"; fi
done
printf '\n@@ end 0\n'
rm -rf "$t"
"""


def sections(text: str) -> dict:
    """SCRIPT's answer by section: {name: (exit code, output)}; ValueError when it is not the script's."""
    if MARK not in (text or ""):
        raise ValueError("not the firewall read's answer")
    out: dict = {}
    name, rc, buf = None, 0, []
    for line in text.split("\n"):
        m = SECTION.match(line.rstrip("\r"))
        if m:
            if name is not None:
                out[name] = (rc, "\n".join(buf).strip("\n"))
            name, rc, buf = m.group(1), int(m.group(2)), []
        elif name is not None:
            buf.append(line.rstrip("\r"))
    if name is not None:
        out[name] = (rc, "\n".join(buf).strip("\n"))
    return out


def _text_addresses(text: str) -> list:
    """`ip addr show` in words (BusyBox's ip has no JSON): each interface, its state and addresses."""
    out, cur = [], None
    for line in (text or "").splitlines():
        m = re.match(r"^\d+:\s+([^:@\s]+)[^:]*:\s+<[^>]*>.*?(?:state\s+(\S+))?", line)
        if m:
            cur = {"ifname": m.group(1), "operstate": (m.group(2) or "").lower(), "addr_info": []}
            out.append(cur)
            continue
        a = re.match(r"^\s+inet6?\s+([0-9a-fA-F.:]+)/(\d+)", line)
        if a and cur is not None:
            cur["addr_info"].append({"local": a.group(1), "prefixlen": int(a.group(2))})
    return out


@dataclass
class Config:
    """What one read found. `problems`: what could not be read, in words."""

    at: float = 0.0
    system: sys_mod.System = field(default_factory=sys_mod.System)
    tools: dict = field(default_factory=dict)
    nft: nft_mod.Ruleset | None = None
    nft_version: str = ""
    iptables_version: str = ""
    iptables_variant: str = ""  # nf_tables | legacy
    saved: dict = field(default_factory=dict)  # "iptables" | "ip6tables" -> xtables.Saved (the default variant's)
    legacy: dict = field(default_factory=dict)  # beside an nf_tables iptables: the legacy x_tables loaded
    ebtables: tuple = ("", "")
    arptables: tuple = ("", "")
    ipset_version: str = ""
    ipsets: list = field(default_factory=list)
    firewalld: fwd_mod.FirewalldState = field(default_factory=fwd_mod.FirewalldState)
    ufw: ufw_mod.UfwState = field(default_factory=ufw_mod.UfwState)
    problems: list = field(default_factory=list)
    _entries: list | None = None
    _hidden: dict = field(default_factory=dict)

    @property
    def hidden(self) -> dict:
        """A front end's own machinery left out of the rules (ufw's chains, firewalld's table): owner -> how many."""
        self.entries()
        return self._hidden

    # -- what is in charge ----------------------------------------------------------------------------------------
    @property
    def readable(self) -> bool:
        return self.nft is not None or bool(self.saved) or self.ufw.installed or self.firewalld.installed

    def own_filter_chains(self, hook: str = "input") -> list:
        """nftables' base chains of the filter type on `hook` in this machine's own tables (or Liminal's)."""
        if self.nft is None:
            return []
        skip = self.skipped_tables()
        owners = {(t.family, t.name): nft_mod.table_owner(t, self.nft.chains) for t in self.nft.tables}
        return [c for c in self.nft.chains if c.base and c.hook == hook and c.type == "filter" and (c.family, c.table) not in skip
                and owners.get((c.family, c.table), "own") in ("own", "liminal")]

    def iptables_own(self) -> bool:
        """Whether iptables holds rules of this machine's own (not a front end's or a program's): an input rule of its own,
        or INPUT dropping by default where no front end (ufw, firewalld) is there to have set it."""
        fronts = self.ufw.installed or self.firewalld.installed
        for saved in self.saved.values():
            if not fronts and any(c.table == "filter" and c.name == "INPUT" and c.policy == "DROP" for c in saved.chains):
                return True
            if any(e.owner in ("own", "liminal") and e.direction == "in" for e in xt_mod.entries(saved)):
                return True
        return False

    @property
    def manager(self) -> str:
        """What makes the rules here: ufw or firewalld when on; else nftables or iptables holding this machine's own;
        else a front end there but off; else whichever tool there is ("" for none)."""
        if self.ufw.installed and self.ufw.active:
            return "ufw"
        if self.firewalld.installed and self.firewalld.running:
            return "firewalld"
        if self.own_filter_chains():
            return "nftables"
        if self.iptables_own():
            return "iptables"
        if self.ufw.installed:
            return "ufw"
        if self.firewalld.installed:
            return "firewalld"
        if self.nft is not None:
            return "nftables"
        if self.saved:
            return "iptables"
        return ""

    # -- the rules ------------------------------------------------------------------------------------------------
    def skipped_tables(self) -> set:
        """nftables' tables read another way: iptables-nft's (through iptables-save), firewalld's (through its zones)."""
        if self.nft is None:
            return set()
        skip = set()
        if self.iptables_variant == "nf_tables":
            by_family: dict = {}
            for tool, fam in (("iptables", "ip"), ("ip6tables", "ip6")):
                s = self.saved.get(tool)
                if s is not None:
                    by_family[fam] = set(s.tables) - set(s.incompatible)
            skip |= nft_mod.iptables_tables(self.nft, by_family)
        if self.firewalld.installed:
            skip |= {(t.family, t.name) for t in self.nft.tables if owner_by_name(t.name) == "firewalld"}
        return skip

    def entries(self) -> list[Entry]:
        """Every rule read, a front end's machinery left out where its own rules stand for it (ufw's chains, firewalld's
        table), counted in `hidden`."""
        if self._entries is not None:
            return self._entries
        out: list[Entry] = []
        if self.nft is not None:  # firewalld's own table kept here: counted below as its machinery
            fw = {(t.family, t.name) for t in self.nft.tables if owner_by_name(t.name) == "firewalld"}
            out += nft_mod.entries(self.nft, self.skipped_tables() - fw)
        for s in self.saved.values():
            out += xt_mod.entries(s)
        for tool, s in self.legacy.items():
            out += xt_mod.entries(s, binary=f"{tool}-legacy")
        hidden: dict = {}
        fronts = []
        if self.ufw.installed:
            fronts.append("ufw")
            out += ufw_mod.entries(self.ufw)
        if self.firewalld.installed:
            fronts.append("firewalld")
            out += fwd_mod.entries(self.firewalld)
        kept = []
        for e in out:
            if e.owner in fronts and e.kind in ("nftables", "iptables", "ip6tables"):
                hidden[e.owner] = hidden.get(e.owner, 0) + 1
                continue
            kept.append(e)
        self._hidden = hidden
        self._entries = kept
        return kept

    def entry(self, where: str, text: str) -> Entry | None:
        return next((e for e in self.entries() if e.where == where and e.text == text), None)

    # -- what the library's Firewall base asks ---------------------------------------------------------------------------
    def input_chains(self) -> list:
        """nftables' input base chains of the filter type, but those read another way (iptables-nft's, firewalld's)."""
        if self.nft is None:
            return []
        skip = self.skipped_tables()
        return [c for c in self.nft.chains if c.base and c.hook == "input" and c.type in ("filter", "") and (c.family, c.table) not in skip]

    def dropping(self, chain) -> bool:
        return chain.policy == "drop" or any(nft_mod.catch_all(r) for r in self.nft.rules_of(chain))

    def xt_dropping(self, tool: str) -> bool:
        s = self.saved.get(tool)
        if s is None:
            return False
        if any(c.table == "filter" and c.name == "INPUT" and c.policy == "DROP" for c in s.chains):
            return True
        return any(r.table == "filter" and r.chain == "INPUT" and list(r.args)[:2] in (["-j", "DROP"], ["-j", "REJECT"]) and len(r.args) <= 4
                   for r in s.rules)

    def state(self) -> dict:
        """{"enabled": on everywhere, "profiles": {a front end, zone or chain: on}} for what is in charge."""
        m = self.manager
        if m == "ufw":
            return {"enabled": self.ufw.active, "profiles": {"ufw": self.ufw.active}}
        if m == "firewalld":
            f = self.firewalld
            return {"enabled": f.running, "profiles": {(f.default_zone if f.running and f.default_zone else "firewalld"): f.running}}
        if m == "nftables":
            profiles = {c.key: self.dropping(c) for c in self.input_chains()}
            return {"enabled": any(profiles.values()), "profiles": profiles or {"nftables": False}}
        if m == "iptables":
            profiles = {f"{tool} filter INPUT": self.xt_dropping(tool) for tool in self.saved}
            return {"enabled": any(profiles.values()), "profiles": profiles}
        return {"enabled": False, "profiles": {}}

    def exposing(self, ports) -> list[tuple[int, str]]:
        """The rules letting another machine reach any of `ports` inbound where something filters: (the port, the rule)."""
        m = self.manager
        hits: list = []

        def take(e: Entry, label: str):
            if e.direction != "in" or e.action not in ("accept", "limit") or e.local:
                return
            hits.extend((p, label) for p in ports if e.covers(p))

        entries = self.entries()
        if m == "ufw" and self.ufw.active:
            for e in entries:
                if e.kind == "ufw":
                    take(e, f"ufw rule [{e.number}] {e.text.split('  ')[0]} from {e.source or 'Anywhere'}" + (f" ({e.comment})" if e.comment else ""))
        elif m == "firewalld" and self.firewalld.running:
            for z in self.firewalld.zones:  # a zone accepting everything, but one bound only to a program's bridge (Docker's)
                bound = [i for i in z.words("interfaces") if not owner_by_interface(i)] + z.words("sources")
                if z.active and z.target == "ACCEPT" and bound:
                    hits.extend((p, f"the zone {z.name} accepts everything ({' '.join(bound)})") for p in ports)
            for e in entries:
                if e.kind == "firewalld":
                    take(e, f"firewalld's {e.where}: {e.text}")
        elif m == "nftables" and self.nft is not None:
            inside: set = set()
            for c in self.input_chains():
                if c.policy == "drop":
                    inside |= nft_mod.reachable_from(self.nft, c)
            for e in entries:
                if e.kind == "nftables" and e.where in inside:
                    take(e, f"nftables {e.where} handle {e.number}" + (f" ({e.comment})" if e.comment else ""))
        elif m == "iptables":
            for e in entries:
                if e.kind in ("iptables", "ip6tables") and self.xt_dropping(e.kind):
                    take(e, f"{e.kind} {e.where} rule {e.number}" + (f" ({e.comment})" if e.comment else ""))
        return list(dict.fromkeys(hits))

    def liminal_rules(self) -> list:
        """Liminal's rules as the library's Rule (one per name, its ports gathered from every rule of that name)."""
        from liminal_libs.machines.firewall import Rule

        by: dict = {}
        for e in self.entries():
            name = e.liminal_name
            if not name:
                continue
            by.setdefault(name, []).append(e)
        out = []
        for name, es in by.items():
            ports = sorted({p for e in es for a, b in e.spans for p in range(a, min(b, a + 1023) + 1)})
            first = es[0]
            protocol = first.protocol if first.protocol in ("tcp", "udp") else "tcp" if ports else "any"
            try:
                out.append(Rule(name, ports=tuple(ports), protocol=protocol if ports else "any",
                                direction="out" if first.direction == "out" else "in",
                                action="allow" if first.action in ("accept", "limit") else "block",
                                remote=first.source or "any", owned=True, detail=f"{first.kind} {first.where}: {first.text}"))
            except ValueError:
                continue
        return out


def parse(text: str, at: float | None = None) -> Config:
    """SCRIPT's answer as a Config."""
    secs = sections(text)
    cfg = Config(at=time.time() if at is None else at)
    get = lambda name: secs.get(name, (None, ""))  # noqa: E731
    sysm = cfg.system
    sysm.os = sys_mod.parse_os_release(get("os")[1])
    sysm.family = sys_mod.family_of(sysm.os)
    sysm.kernel = get("kernel")[1].strip()
    init = get("init")[1].split()
    sysm.init, sysm.pid1 = (init + ["", ""])[:2] if init else ("", "")
    if sysm.init == "none" and sysm.pid1 not in ("", "unknown"):
        sysm.init = sysm.pid1  # runit, s6, dinit...: said by name
    for line in get("tools")[1].splitlines():
        name, _, path = line.partition(" ")
        if name:
            cfg.tools[name] = path.strip()
    # nftables
    rc, out = get("nft")
    if rc is not None:
        if rc == 0:
            try:
                cfg.nft = nft_mod.parse(out)
            except ValueError as e:
                cfg.problems.append(f"nftables' ruleset could not be read: {e}")
        else:
            cfg.problems.append("nftables' ruleset could not be read: " + (get("nft.err")[1].strip().splitlines() or [f"nft failed ({rc})"])[-1])
    m = re.search(r"v?(\d+(?:\.\d+)+)", get("nft.version")[1])
    cfg.nft_version = m.group(1) if m else (cfg.nft.version if cfg.nft else "")
    # iptables
    cfg.iptables_version, cfg.iptables_variant = xt_mod.version_of(get("iptables.version")[1])
    for tool in ("iptables", "ip6tables"):
        rc, out = get(f"{tool}.save")
        if rc == 0:
            saved = xt_mod.parse_save(out, tool, cfg.iptables_variant)
            if not cfg.iptables_variant and saved.variant:
                cfg.iptables_variant = saved.variant
            cfg.saved[tool] = saved
        elif rc is not None:
            cfg.problems.append(f"{tool}' rules could not be read: " + (get(f"{tool}.save.err")[1].strip().splitlines() or [f"failed ({rc})"])[-1])
        rc, out = get(f"{tool}.legacy")
        if rc == 0 and out.strip() and cfg.iptables_variant == "nf_tables":
            legacy = xt_mod.parse_save(out, tool, "legacy")
            if legacy.rules or any(c.policy not in ("-", "ACCEPT") for c in legacy.chains):
                cfg.legacy[tool] = legacy
    cfg.ebtables = xt_mod.version_of(get("ebtables.version")[1])
    cfg.arptables = xt_mod.version_of(get("arptables.version")[1])
    m = re.search(r"v(\d+(?:\.\d+)+)", get("ipset.version")[1])
    cfg.ipset_version = m.group(1) if m else ""
    if get("ipset")[0] == 0:
        cfg.ipsets = xt_mod.parse_ipsets(get("ipset")[1])
    # firewalld
    rc, out = get("firewalld.state")
    if rc is not None:
        f = cfg.firewalld
        f.installed = True
        f.running = rc == 0 and out.strip() == "running"
        m = re.search(r"(\d+(?:\.\d+)+)", get("firewalld.version")[1])
        f.version = m.group(1) if m else ""
        f.default_zone = get("firewalld.default")[1].strip()
        f.zones = fwd_mod.parse_blocks(get("firewalld.zones")[1])
        if get("firewalld.policies")[0] == 0:
            f.policies = fwd_mod.parse_blocks(get("firewalld.policies")[1], policy=True)
        f.services = fwd_mod.parse_services(get("firewalld.services")[1])
        for line in get("firewalld.conf")[1].splitlines():
            k, _, v = line.partition("=")
            if k == "FirewallBackend":
                f.backend = v.strip()
            elif k == "DefaultZone" and not f.default_zone:
                f.default_zone = v.strip()
        for z in f.zones:
            z.default = z.default or z.name == f.default_zone
        if get("firewalld.zones")[0] not in (None, 0):
            cfg.problems.append("firewalld's zones could not be read: " + (get("firewalld.zones.err")[1].strip().splitlines() or ["failed"])[-1])
    # ufw
    if get("ufw.verbose")[0] is not None:
        if get("ufw.verbose")[0] == 0:
            cfg.ufw = ufw_mod.parse_status(get("ufw.verbose")[1], get("ufw.numbered")[1], get("ufw.added")[1], get("ufw.version")[1])
        else:
            cfg.ufw = ufw_mod.UfwState(installed=True)
            cfg.problems.append("ufw could not be read: " + (get("ufw.verbose.err")[1].strip().splitlines() or ["failed"])[-1])
    # the machine around it
    lines = [x.strip() for x in get("conntrack")[1].splitlines() if x.strip().isdecimal()]
    sysm.conntrack = (int(lines[0]), int(lines[1])) if len(lines) >= 2 else (None, None)
    if get("addr")[0] == 0:
        sysm.interfaces = sys_mod.parse_addresses(get("addr")[1])
    elif get("addr.text")[0] == 0:
        import json as _json

        sysm.interfaces = sys_mod.parse_addresses(_json.dumps(_text_addresses(get("addr.text")[1])))
    sysm.bpf = sys_mod.parse_bpf_net(get("bpf")[1]) if get("bpf")[0] == 0 else []
    if get("listen")[0] == 0:
        sysm.listening = sys_mod.parse_sockets(get("listen")[1])
    elif get("listen.netstat")[0] == 0:
        for line in get("listen.netstat")[1].splitlines():
            parts = line.split()
            if len(parts) >= 7 and parts[0].startswith("tcp") and parts[5] == "LISTEN":
                port = parts[3].rsplit(":", 1)[-1]
                prog = parts[6].split("/", 1)[-1]
                if port.isdecimal():
                    sysm.listening.setdefault(prog, set()).add(int(port))
    if get("listen.udp")[0] == 0:  # the programs listening for UDP too (0.5.0: what a rule's group is found by)
        sysm.listening_udp = sys_mod.parse_sockets(get("listen.udp")[1])
    elif get("listen.udp.netstat")[0] == 0:
        for line in get("listen.udp.netstat")[1].splitlines():
            parts = line.split()
            if len(parts) >= 6 and parts[0].startswith("udp") and "/" in parts[-1]:
                port = parts[3].rsplit(":", 1)[-1]
                if port.isdecimal():
                    sysm.listening_udp.setdefault(parts[-1].split("/", 1)[-1], set()).add(int(port))
    ssh = sysm.ssh_ports
    if ssh and get("established")[0] == 0:
        n = 0
        for line in get("established")[1].splitlines():
            parts = line.split()
            local = next((p for p in parts if ":" in p), "")
            port = local.rsplit(":", 1)[-1]
            if port.isdecimal() and int(port) in ssh:
                n += 1
        sysm.ssh_sessions = n
    sysm.services = sys_mod.parse_services(sysm.init, get("services")[1])
    for line in get("files")[1].splitlines():
        path, _, when = line.rpartition(" ")
        if path:
            sysm.files[path] = int(when) if when.isdecimal() else 0
    for line in get("conf")[1].splitlines():
        k, _, v = line.partition("=")
        if k:
            sysm.conf[k.strip()] = v.strip().strip("\"'")
    return cfg
