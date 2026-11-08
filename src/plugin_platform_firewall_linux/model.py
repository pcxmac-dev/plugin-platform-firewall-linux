"""One shape for every rule the plugin reads, whatever wrote it (nftables, iptables, ip6tables, ufw, firewalld): an
`Entry` says where it is, which way it filters, what it does to what, in its own syntax too, and whose it is: Liminal's
own (a comment liminal:<name>, a firewalld service liminal-<name>), this machine's own (its administrator's), a front
end's (ufw's rules, firewalld's zones), or another program's (Docker, Podman, libvirt, Kubernetes, Fail2ban...), which
makes its rules again and is never changed here. The Rules table's presets and its Find read these."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass

from liminal_libs.machines.firewall import PREFIX

ALLOWS = ("accept", "limit")  # what lets a packet through
BLOCKS = ("drop", "reject")
DIRECTIONS = {"in": "in", "out": "out", "fwd": "forwarded", "nat": "NAT", "other": "other"}
REMOVABLE_OWNERS = ("liminal", "own", "ufw", "firewalld")  # the rest belong to a program that makes them again
OWNER_WORDS = {
    "liminal": "Liminal's", "own": "this machine's", "ufw": "ufw", "firewalld": "firewalld", "docker": "Docker",
    "podman": "Podman", "libvirt": "libvirt", "incus": "Incus", "lxd": "LXD", "kubernetes": "Kubernetes",
    "calico": "Calico", "cilium": "Cilium", "flannel": "flannel", "weave": "Weave", "fail2ban": "Fail2ban",
    "crowdsec": "CrowdSec", "sshguard": "SSHGuard", "tailscale": "Tailscale", "networkmanager": "NetworkManager",
    "systemd": "systemd", "nixos": "NixOS", "waydroid": "Waydroid", "wireguard": "WireGuard",
}
# Programs making their own rules, by a table's or a chain's name (its start; the first match wins)
NAMED_OWNERS = (
    ("liminal", "liminal"), ("firewalld", "firewalld"), ("ufw6-", "ufw"), ("ufw-", "ufw"), ("docker", "docker"),
    ("DOCKER", "docker"), ("netavark", "podman"), ("NETAVARK", "podman"), ("CNI-", "podman"), ("libvirt", "libvirt"),
    ("LIBVIRT", "libvirt"), ("incus", "incus"), ("INCUS", "incus"), ("lxd", "lxd"), ("LXD", "lxd"), ("kube", "kubernetes"),
    ("KUBE-", "kubernetes"), ("k3s", "kubernetes"), ("cali", "calico"), ("cali-", "calico"), ("cilium", "cilium"),
    ("CILIUM", "cilium"), ("FLANNEL", "flannel"), ("flannel", "flannel"), ("WEAVE", "weave"), ("f2b-", "fail2ban"),
    ("fail2ban", "fail2ban"), ("crowdsec", "crowdsec"), ("CROWDSEC", "crowdsec"), ("sshguard", "sshguard"),
    ("ts-", "tailscale"), ("tailscale", "tailscale"), ("nm-shared-", "networkmanager"), ("io.systemd", "systemd"),
    ("nixos-", "nixos"), ("waydroid", "waydroid"),
)
# Interfaces a program makes, for rules in the built-in chains that name them (Docker's MASQUERADE in POSTROUTING)
INTERFACE_OWNERS = (("docker", "docker"), ("br-", "docker"), ("virbr", "libvirt"), ("podman", "podman"), ("cni-podman", "podman"),
                    ("tailscale", "tailscale"), ("lxdbr", "lxd"), ("incusbr", "incus"), ("flannel", "flannel"), ("cni0", "kubernetes"),
                    ("cali", "calico"), ("cilium", "cilium"), ("waydroid", "waydroid"))
PRESETS = (  # the Rules table's choices: (value, title, note)
    ("in-allow", "Inbound allowed", "what may come in"),
    ("in-block", "Inbound blocked", "what is dropped or refused coming in"),
    ("out", "Outbound", "what this machine sends"),
    ("fwd", "Forwarded and NAT", "what passes through: containers, VMs, a router's traffic"),
    ("liminal", "Liminal's", "the rules Liminal made"),
    ("all", "All", "every rule read"),
)
PRESET_NAMES = tuple(p[0] for p in PRESETS)
MAX_ROWS = 200  # the Rules table's rows at most; Find narrows it


def owner_by_name(name: str) -> str:
    """The program a table's or chain's name says made it ("" when none: this machine's own)."""
    for start, owner in NAMED_OWNERS:
        if name.startswith(start):
            return owner
    return ""


def owner_by_interface(name: str) -> str:
    n = (name or "").lstrip("!").strip()
    n = (n[4:] if n.startswith("not ") else n).strip().strip('"')
    for start, owner in INTERFACE_OWNERS:
        if n.startswith(start):
            return owner
    return ""


def digest(*parts) -> str:
    """A short fingerprint of a rule as read: a change names it, and is refused when the rule is no longer the same."""
    return hashlib.sha1("\x1f".join(str(p) for p in parts).encode("utf-8", "replace")).hexdigest()[:10]


def spans_of(text: str) -> tuple:
    """The ports a list names: "22", "80,443", "8000-8100" or "8000:8100" -> ((lo, hi), ...); () when it names none."""
    out = []
    for part in re.split(r"[,\s]+", (text or "").strip()):
        part = part.strip().strip("{}")
        if not part:
            continue
        lo, sep, hi = part.replace(":", "-").partition("-")
        if lo.isdecimal() and (not sep or hi.isdecimal()):
            a, b = int(lo), int(hi) if sep else int(lo)
            if 0 < a <= b < 65536:
                out.append((a, b))
    return tuple(out)


def ports_text(spans) -> str:
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in spans)


def parse_ports(text) -> tuple:
    """Ports typed in a form ("22, 80 443, 8000-8100"): their spans; ValueError in words for anything else."""
    raw = str(text or "").strip()
    if not raw:
        return ()
    out = []
    for part in [p for p in re.split(r"[,\s]+", raw) if p]:
        lo, sep, hi = part.replace(":", "-").partition("-")
        if not (lo.isdecimal() and (not sep or hi.isdecimal())):
            raise ValueError(f"{part!r} is not a port or a range of ports (22, 8000-8100)")
        a, b = int(lo), int(hi) if sep else int(lo)
        if not 0 < a <= b < 65536:
            raise ValueError(f"{part} is not within 1 to 65535, low to high")
        out.append((a, b))
    if len(out) > 15:
        raise ValueError("at most 15 ports or ranges in one rule")
    return tuple(dict.fromkeys(out))


def parse_address(text) -> str:
    """An address or a network typed in a form, as written canonically ("" for anywhere); ValueError otherwise."""
    raw = str(text or "").strip()
    if raw.lower() in ("", "any", "anywhere", "*"):
        return ""
    try:
        if "/" in raw:
            return str(ipaddress.ip_network(raw, strict=False))
        return str(ipaddress.ip_address(raw))
    except ValueError:
        raise ValueError(f"{raw!r} is not an address or a network (10.0.0.0/8, 2001:db8::/32)") from None


def address_family(address: str) -> str:
    """ipv4 | ipv6 for an address or network; "" for anywhere."""
    if not address:
        return ""
    return "ipv6" if ":" in address else "ipv4"


IFNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:+-]{0,14}$")


def parse_interface(text) -> str:
    raw = str(text or "").strip()
    if not raw or raw.lower() in ("any", "every"):
        return ""
    if not IFNAME.match(raw):
        raise ValueError(f"{raw!r} is not an interface's name (eth0, enp3s0, wg0)")
    return raw


@dataclass(frozen=True)
class Entry:
    """A rule as the plugin shows it. `ref` is what a change names (its place and fingerprint); `text` the rule in its
    own syntax; `spans` the local ports it is for, () for every port (or ports it names through a set)."""

    ref: str
    kind: str  # nftables | iptables | ip6tables | ufw | firewalld
    where: str  # "inet filter input", "filter INPUT", "ufw", "zone public"
    direction: str  # in | out | fwd | nat | other
    action: str  # accept | limit | drop | reject | jump | goto | return | nat | vmap | log | continue | queue
    text: str
    target: str = ""  # a jump's or goto's chain, a NAT's address
    protocol: str = ""
    ports: str = ""
    spans: tuple = ()
    source: str = ""
    destination: str = ""
    interface: str = ""
    state: str = ""  # the connection states it is for (established, related), when it says
    comment: str = ""
    owner: str = "own"
    family: str = ""  # ipv4 | ipv6 | "" (both)
    number: int = 0  # its place in its chain (iptables), its number (ufw)
    counted: str = ""  # packets and bytes counted, when it counts

    @property
    def removable(self) -> bool:
        return self.owner in REMOVABLE_OWNERS

    @property
    def liminal_name(self) -> str:
        """The name of one of Liminal's rules ("" for any other)."""
        c = self.comment
        if self.owner != "liminal":
            return ""
        if c.startswith(PREFIX + ":"):
            return c[len(PREFIX) + 1:].split(":", 1)[0]
        if c.startswith(PREFIX + "-"):
            return c[len(PREFIX) + 1:]
        return ""

    @property
    def local(self) -> bool:
        """Only for this machine's own traffic or replies: loopback, a 127/8 or ::1 source, established/related."""
        i = self.interface.strip('"')
        if i in ("lo", "on lo"):
            return True
        s = self.source.split()[0] if self.source else ""
        if s.startswith("127.") or s in ("::1", "::1/128"):
            return True
        st = self.state.replace(",", " ").split()
        return bool(st) and "new" not in st and all(w in ("established", "related", "untracked") for w in st)

    def covers(self, port: int, protocol: str = "tcp") -> bool:
        """Whether it is for this local port of `protocol`: every port when it names none and no other protocol (ICMP has
        no ports); never when its ports are not known here (a named set, a negation, a service not read)."""
        p = self.protocol.lower()
        if p:
            named = set(re.split(r"[\s,/{}]+", p)) - {""}
            if p.startswith("not ") or protocol not in named:
                return False
        if self.ports and not self.spans:
            return False
        return not self.spans or any(a <= port <= b for a, b in self.spans)

    @property
    def from_anywhere(self) -> bool:
        s = (self.source or "").lower()
        return s in ("", "anywhere", "anywhere (v6)", "any", "0.0.0.0/0", "::/0")

    def shown(self, preset: str) -> bool:
        if preset == "in-allow":
            return self.direction == "in" and self.action in ALLOWS
        if preset == "in-block":
            return self.direction == "in" and self.action in BLOCKS
        if preset == "out":
            return self.direction == "out"
        if preset == "fwd":
            return self.direction in ("fwd", "nat")
        if preset == "liminal":
            return self.owner == "liminal"
        return True

    def found(self, words: str) -> bool:
        """Whether a Find's words are in it (every word, any case); a number also finds the rules for that port."""
        hay = " ".join((self.kind, self.where, self.direction, DIRECTIONS.get(self.direction, ""), self.action, self.target,
                        self.protocol, self.ports, self.source, self.destination, self.interface, self.state, self.comment,
                        self.owner, OWNER_WORDS.get(self.owner, ""), self.text)).lower()
        for w in str(words or "").lower().split():
            if w.isdecimal() and self.spans and any(a <= int(w) <= b for a, b in self.spans):
                continue
            if w not in hay:
                return False
        return True

    def describe(self) -> dict:
        return {"ref": self.ref, "kind": self.kind, "where": self.where, "direction": self.direction, "action": self.action,
                "target": self.target, "protocol": self.protocol, "ports": self.ports, "source": self.source,
                "destination": self.destination, "interface": self.interface, "state": self.state, "comment": self.comment,
                "owner": self.owner, "removable": self.removable, "family": self.family, "text": self.text,
                "counted": self.counted}
