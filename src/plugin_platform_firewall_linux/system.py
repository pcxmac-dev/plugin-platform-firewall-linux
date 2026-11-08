"""The machine around the firewall: which distribution (/etc/os-release: ID, ID_LIKE), which init system (systemd,
OpenRC, SysV scripts; others named), the firewall services' states under it and at boot, where each distribution keeps
its rules across a restart and how it saves them, the interfaces with their addresses and any XDP program attached
(`ip -j addr`), eBPF programs on the network hooks (`bpftool -j net`, read only), the connections tracked, and the
SSH server's ports (what a change must not cut off)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

FAMILIES = {  # ID or ID_LIKE -> the family whose ways a distribution follows
    "debian": "debian", "ubuntu": "debian", "raspbian": "debian", "linuxmint": "debian", "pop": "debian", "kali": "debian",
    "devuan": "debian", "elementary": "debian", "zorin": "debian",
    "fedora": "fedora", "rhel": "fedora", "centos": "fedora", "rocky": "fedora", "almalinux": "fedora", "ol": "fedora",
    "amzn": "fedora", "nobara": "fedora",
    "arch": "arch", "manjaro": "arch", "endeavouros": "arch", "artix": "arch", "cachyos": "arch", "garuda": "arch",
    "opensuse": "suse", "opensuse-tumbleweed": "suse", "opensuse-leap": "suse", "opensuse-slowroll": "suse", "sles": "suse",
    "suse": "suse", "sle-micro": "suse",
    "alpine": "alpine", "postmarketos": "alpine",
    "gentoo": "gentoo", "funtoo": "gentoo", "calculate": "gentoo", "chromeos": "gentoo",
    "nixos": "nixos", "void": "void", "slackware": "slackware",
}
SERVICES = ("nftables", "iptables", "ip6tables", "ipset", "firewalld", "ufw", "netfilter-persistent", "ebtables",
            "nftables-restore", "iptables-restore", "ip6tables-restore", "nftables-load", "nftables-store", "iptables-store",
            "ip6tables-store")
LOADERS = ("nftables-load", "nftables-store", "nftables-restore", "iptables-restore", "ip6tables-restore", "iptables-store",
           "ip6tables-store")  # Gentoo's one-shot units: inactive once they have run, so only their place at boot says


def parse_os_release(text: str) -> dict:
    out = {}
    for line in (text or "").splitlines():
        k, sep, v = line.partition("=")
        if sep and re.fullmatch(r"[A-Z_][A-Z0-9_]*", k.strip()):
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out[k.strip()] = v
    return out


def family_of(osr: dict) -> str:
    """The distribution family: debian | fedora | arch | suse | alpine | gentoo | nixos | void | slackware | "" (unknown)."""
    for word in [osr.get("ID", "")] + osr.get("ID_LIKE", "").split():
        if word.lower() in FAMILIES:
            return FAMILIES[word.lower()]
    return ""


@dataclass(frozen=True)
class ServiceState:
    name: str
    present: bool = False
    running: bool | None = None  # None: not known
    at_boot: bool | None = None
    words: str = ""  # the init system's own words: active, enabled; started, default


def parse_services(init: str, text: str) -> dict:
    """The firewall services under the init system, from the script's lines `<name> <present> <state> <boot>`."""
    out = {}
    for line in (text or "").splitlines():
        parts = line.split(None, 3)
        if len(parts) < 2 or parts[0] not in SERVICES:
            continue
        name, present = parts[0], parts[1] == "yes"
        state = parts[2] if len(parts) > 2 else ""
        boot = parts[3].strip() if len(parts) > 3 else ""
        if not present:
            out[name] = ServiceState(name)
            continue
        if init == "systemd":
            running = None if name in LOADERS else state in ("active", "reloading", "activating")
            at_boot = boot.split()[0] in ("enabled", "enabled-runtime", "static", "alias", "generated") if boot else None
            if boot.startswith("static") or boot.startswith("generated"):
                at_boot = None
        elif init == "openrc":
            running = state in ("started", "starting")
            at_boot = bool(boot) and boot != "-"  # its runlevel (sysinit, boot, default), from /etc/runlevels
        else:
            running = None if state in ("", "unknown") else state in ("running", "started", "active")
            at_boot = None
        out[name] = ServiceState(name, True, running, at_boot, " ".join(w for w in (state, boot) if w and w != "-"))
    return out


@dataclass(frozen=True)
class Interface:
    name: str
    state: str
    addresses: tuple = ()
    xdp: str = ""  # "xdp generic: program 42"


def parse_addresses(text: str) -> list[Interface]:
    """`ip -j addr show`: each interface, its state, addresses and an XDP program attached."""
    try:
        data = json.loads(text or "[]")
    except ValueError:
        return []
    out = []
    for i in data if isinstance(data, list) else []:
        if not isinstance(i, dict) or not i.get("ifname"):
            continue
        addrs = tuple(f"{a.get('local')}/{a.get('prefixlen')}" for a in i.get("addr_info") or [] if isinstance(a, dict) and a.get("local"))
        xdp = ""
        x = i.get("xdp")
        if isinstance(x, dict):
            mode = {0: "none", 1: "driver", 2: "generic", 3: "offload", 4: "multiple"}.get(x.get("mode"), str(x.get("mode", "")))
            prog = x.get("prog") or {}
            pid = prog.get("id") if isinstance(prog, dict) else None
            if pid is None and isinstance(x.get("attached"), list):  # several modes at once: no program at the top
                names = {1: "driver", 2: "generic", 3: "offload"}
                ids = [f"{(a.get('prog') or {}).get('id')} ({names.get(a.get('mode'), a.get('mode'))})" for a in x["attached"] if isinstance(a, dict)]
                xdp = f"XDP {mode}: programs {', '.join(ids)}"
            else:
                xdp = f"XDP {mode}" + (f": program {pid}" if pid is not None else "")
        out.append(Interface(i["ifname"], str(i.get("operstate") or "").lower(), addrs, xdp))
    return out


PF = {1: "inet", 2: "ip", 3: "arp", 5: "netdev", 7: "bridge", 10: "ip6"}
HOOKS = {0: "prerouting", 1: "input", 2: "forward", 3: "output", 4: "postrouting"}


def parse_bpf_net(text: str) -> list[str]:
    """`bpftool -j net show`: the eBPF programs on the network's hooks, in words: XDP (driver, generic, offload; several
    at once), tc (classic cls_bpf by `id`, tcx and netkit links by `prog_id`), the flow dissector, and netfilter links (BPF
    programs on netfilter's hooks since Linux 6.4, never in nft's ruleset). bpftool writes a flow dissector's id as
    `["id":N]`, which is not JSON: mended before it is read."""
    raw = re.sub(r'"flow_dissector":\[\s*("id"\s*:\s*\d+)\s*\]', r'"flow_dissector":[{\1}]', text or "[]")
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    out = []
    for block in data if isinstance(data, list) else [data]:
        if not isinstance(block, dict):
            continue
        for p in block.get("xdp") or []:
            if not isinstance(p, dict):
                continue
            multi = p.get("multi_attachments")
            if isinstance(multi, list):
                out += [f"xdp {p.get('devname', '')} {m.get('mode', '')} id {m.get('id', '')}" for m in multi if isinstance(m, dict)]
            else:
                out.append(f"xdp {p.get('devname', '')} {p.get('mode', '')} id {p.get('id', '')}")
        for p in block.get("tc") or []:
            if isinstance(p, dict):
                pid = p.get("prog_id", p.get("id", ""))
                out.append(" ".join(str(w) for w in ("tc", p.get("devname", ""), p.get("kind", ""), p.get("name", ""), f"id {pid}") if w != ""))
        for p in block.get("flow_dissector") or []:
            if isinstance(p, dict) and p.get("id") is not None:
                out.append(f"flow dissector id {p['id']}")
        for p in block.get("netfilter") or []:
            if isinstance(p, dict):
                out.append(f"netfilter {PF.get(p.get('pf'), p.get('pf'))} {HOOKS.get(p.get('hook'), p.get('hook'))} "
                           f"prio {p.get('prio')} id {p.get('id')}")
    return out


def parse_sockets(listening: str) -> dict:
    """`ss -ltnpH`: the TCP ports listening by program ({"sshd": {22}, ...})."""
    out: dict = {}
    for line in (listening or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        port = local.rsplit(":", 1)[-1]
        if not port.isdecimal():
            continue
        names = re.findall(r'\(\("([^"]+)"', line) or re.findall(r'"([^"]+)",pid=', line)
        for n in names or ["?"]:
            out.setdefault(n, set()).add(int(port))
    return out


@dataclass(frozen=True)
class Keeping:
    """How rules made at run time are kept across a restart, for one kind of rules (nftables, iptables)."""

    kind: str  # nftables | iptables
    how: str  # file | command | none
    path: str = ""  # the file the boot loads
    command: tuple = ()  # the distribution's own save
    service: str = ""  # what loads it at boot
    note: str = ""


def keeping(kind: str, family: str, init: str, files: dict, services: dict, conf: dict) -> Keeping:
    """Where `kind`'s rules are kept on this distribution and init system, as its packages ship them (`files`: the
    paths present; `services`: the firewall services; `conf`: Gentoo's and Alpine's /etc/conf.d settings)."""
    present = lambda p: p in files  # noqa: E731
    if kind == "nftables":
        if family == "gentoo":
            path = conf.get("NFTABLES_SAVE") or "/var/lib/nftables/rules-save"
            if init == "openrc":
                return Keeping(kind, "command", path, ("rc-service", "nftables", "save"), "nftables",
                               "Gentoo's nftables service saves the whole ruleset there and loads it at boot")
            if services.get("nftables-store", ServiceState("")).present or not services.get("nftables-restore", ServiceState("")).present:
                return Keeping(kind, "command", "/var/lib/nftables/rules-save", ("systemctl", "start", "nftables-store.service"),
                               "nftables-load", "Gentoo's nftables-store saves the whole ruleset there; nftables-load loads it at boot")
            return Keeping(kind, "file", "/var/lib/nftables/rules-save", (), "nftables-restore",
                           "Gentoo's nftables-restore loads it at boot")
        if family == "alpine":  # its `rc-service nftables save` keeps counters and quotas, not the rules
            path = conf.get("rules_file") or "/etc/nftables.nft"
            return Keeping(kind, "file", path, (), "nftables", "Alpine's nftables service loads it at boot (the saved file holds "
                           "the whole ruleset of this machine's own, its includes of /etc/nftables.d and /var/lib/nftables no more)")
        if family == "fedora" or present("/etc/sysconfig/nftables.conf"):
            return Keeping(kind, "file", "/etc/sysconfig/nftables.conf", (), "nftables",
                           "the nftables service loads it at boot")
        if family == "suse":
            return Keeping(kind, "file", "/etc/nftables/rules/main.nft", (), "nftables",
                           "openSUSE's nftables service loads it at boot")
        if family in ("debian", "arch", "void", "slackware") or present("/etc/nftables.conf"):
            return Keeping(kind, "file", "/etc/nftables.conf", (), "nftables", "the nftables service loads it at boot")
        if family == "nixos":
            return Keeping(kind, "none", note="NixOS builds its firewall from its configuration (networking.firewall, "
                                                "networking.nftables): a rule made here lasts until the next rebuild")
        return Keeping(kind, "none", note="no file this distribution loads at boot is known here")
    # iptables
    if family == "debian":
        if services.get("netfilter-persistent", ServiceState("")).present:
            return Keeping(kind, "command", "/etc/iptables/rules.v4", ("netfilter-persistent", "save"), "netfilter-persistent",
                           "netfilter-persistent saves /etc/iptables/rules.v4 and rules.v6 and loads them at boot (it says "
                           "nothing when it fails: the Firewall table shows when rules.v4 last changed)")
        return Keeping(kind, "none", note="nothing loads iptables' rules at boot: the iptables-persistent package does")
    if family == "fedora":
        if services.get("iptables", ServiceState("")).present:
            return Keeping(kind, "file", "/etc/sysconfig/iptables", (), "iptables",
                           "iptables-services loads /etc/sysconfig/iptables and ip6tables at boot")
        return Keeping(kind, "none", note="nothing loads iptables' rules at boot: the iptables-services package does")
    if family == "arch":
        return Keeping(kind, "file", "/etc/iptables/iptables.rules", (), "iptables",
                       "the iptables and ip6tables services load /etc/iptables/iptables.rules and ip6tables.rules")
    if family == "gentoo":
        if init == "openrc":
            return Keeping(kind, "command", conf.get("IPTABLES_SAVE") or "/var/lib/iptables/rules-save",
                           ("rc-service", "iptables", "save"), "iptables", "Gentoo's iptables and ip6tables services save and load them")
        return Keeping(kind, "command", "/var/lib/iptables/rules-save", ("systemctl", "start", "iptables-store.service"),
                       "iptables-restore", "Gentoo's iptables-store saves it; iptables-restore loads it at boot")
    if family == "alpine":
        return Keeping(kind, "command", "/etc/iptables/rules-save", ("rc-service", "iptables", "save"), "iptables",
                       "Alpine's iptables and ip6tables services save and load them")
    return Keeping(kind, "none", note="no file this distribution loads at boot is known here")


@dataclass
class System:
    os: dict = field(default_factory=dict)
    family: str = ""
    kernel: str = ""
    init: str = ""  # systemd | openrc | sysvinit | none | another init's name
    pid1: str = ""
    services: dict = field(default_factory=dict)
    files: dict = field(default_factory=dict)  # path -> its modification time (seconds) or 0
    conf: dict = field(default_factory=dict)
    interfaces: list = field(default_factory=list)
    bpf: list = field(default_factory=list)
    conntrack: tuple = (None, None)  # (count, max)
    listening: dict = field(default_factory=dict)  # program -> its TCP ports
    ssh_sessions: int = 0

    @property
    def name(self) -> str:
        return self.os.get("PRETTY_NAME") or self.os.get("NAME") or "Linux"

    @property
    def init_words(self) -> str:
        return {"systemd": "systemd", "openrc": "OpenRC", "sysvinit": "SysV scripts", "none": "no init system found"}.get(self.init, self.init or "unknown")

    @property
    def ssh_ports(self) -> set:
        out = set()
        for prog, ports in self.listening.items():
            if prog in ("sshd", "sshd-session", "dropbear", "sshd.pam") or prog.startswith("sshd"):
                out |= set(ports)
        return out

    def service(self, name: str) -> ServiceState:
        return self.services.get(name) or ServiceState(name)

    def keeping(self, kind: str) -> Keeping:
        return keeping(kind, self.family, self.init, self.files, self.services, self.conf)


def service_command(init: str, name: str, action: str) -> list[list[str]]:
    """The init system's commands to start (and keep at boot) or stop (and not at boot) a service."""
    if init == "systemd":
        return [["systemctl", "enable" if action == "start" else "disable", "--now", name]]
    if init == "openrc":
        if action == "start":
            return [["rc-update", "add", name, "default"], ["rc-service", name, "start"]]
        return [["rc-service", name, "stop"], ["rc-update", "del", name, "default"]]
    return [["service", name, action]]
