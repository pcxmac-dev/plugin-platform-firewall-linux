"""Each rule's own group (0.5.0; the user: "for both firewalls, i need to have groups, like system or application and
then unassociated rules not tied to a specific application or system process can be in an other, i can create labels,
like system or application, as well and move the rules in to that").

A Linux rule names no program the way a Windows rule does, so what it is tied to is found from what is known of it:
whose rule it is (a program making its own: Docker's, libvirt's, Fail2ban's...), what it is for (this machine's own
traffic: loopback and the replies to its connections; ICMP; packets the connection tracking finds invalid), the
firewalld service or ufw application profile it names, the program listening on a port it names (`ss -ltnp`, `ss
-lunp`), or a port the system's own services use (SSH, DNS, DHCP, NTP...). System: the operating system's (its
services, its networking); Application: a program's (one installed, or one that makes rules of its own; Liminal's);
Other: tied to none of these (a port or an address alone). The user's labels and moves are the library's (rulegroups),
kept through the platform's login."""
from __future__ import annotations

import re

from liminal_libs.machines.rulegroups import Sorted, key_of

from .model import OWNER_WORDS, Entry, owner_by_name

APP_OWNERS = {"liminal", "docker", "podman", "libvirt", "incus", "lxd", "kubernetes", "calico", "cilium", "flannel", "weave",
              "tailscale", "waydroid", "wireguard", "owned"}
SYSTEM_OWNERS = {"systemd", "networkmanager", "nixos", "fail2ban", "crowdsec", "sshguard"}
# the system's own services, by the program listening (as ss and netstat name it)
SYSTEM_PROGRAMS = {
    "sshd", "sshd-session", "dropbear", "systemd", "systemd-resolve", "systemd-resolved", "systemd-network", "systemd-networkd",
    "systemd-timesyncd", "systemd-timesyn", "chronyd", "ntpd", "ntpd-rs", "openntpd", "avahi-daemon", "cupsd", "cups-browsed",
    "dhclient", "dhcpcd", "dhcpd", "udhcpc", "udhcpd", "dnsmasq", "NetworkManager", "connmand", "iwd", "wpa_supplicant",
    "rpcbind", "rpc.statd", "rpc.mountd", "nfsd", "smbd", "nmbd", "winbindd", "samba", "wsdd", "wsdd2", "exim", "exim4",
    "master", "sendmail", "dbus-daemon", "cockpit-ws", "cockpit-tls", "rsyslogd", "syslog-ng", "named", "unbound", "krb5kdc",
    "kadmind", "sssd", "slapd", "snmpd", "lldpd", "xinetd", "inetd", "init", "bluetoothd",
}
SYSTEM_PORTS = {22: "SSH", 53: "DNS", 67: "DHCP", 68: "DHCP", 111: "rpcbind", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS",
                139: "file sharing (Samba)", 445: "file sharing (Samba)", 546: "DHCPv6", 547: "DHCPv6", 631: "printing (CUPS)",
                2049: "NFS", 5353: "mDNS", 5355: "LLMNR", 9090: "Cockpit"}
SYSTEM_SERVICES = {  # firewalld's services for the system's own
    "ssh", "dhcp", "dhcpv6", "dhcpv6-client", "dns", "dns-over-tls", "mdns", "llmnr", "llmnr-client", "samba", "samba-client",
    "samba-dc", "nfs", "nfs3", "rpc-bind", "mountd", "ntp", "ipp", "ipp-client", "cockpit", "kerberos", "kpasswd", "kadmin",
    "ldap", "ldaps", "freeipa-ldap", "freeipa-ldaps", "freeipa-replication", "snmp", "snmptrap", "syslog", "syslog-tls",
    "wsdd", "ws-discovery", "ws-discovery-client", "netbios-ns", "ssdp", "upnp-client", "bluetooth",
}
SYSTEM_PROFILE = re.compile(r"ssh|cups|samba|bonjour|dhcp|dns|bind9|ntp|avahi|nfs|cockpit", re.I)  # ufw's profiles
ICMP = re.compile(r"\bicmp(v6)?\b|\bipv6-icmp\b|\bicmp6\b", re.I)


def key(e: Entry) -> str:
    """A rule's key: where it is and its words (its place in a chain, ufw's number, its counters left out)."""
    return key_of(e.kind, e.where, e.text)


def _owned(owner: str) -> Sorted | None:
    if owner == "liminal":
        return Sorted("application", "Liminal's: made on the platform")
    if owner in APP_OWNERS:
        return Sorted("application", f"{OWNER_WORDS.get(owner, owner)}'s: it makes its rules itself")
    if owner in SYSTEM_OWNERS:
        return Sorted("system", f"{OWNER_WORDS.get(owner, owner)}'s")
    return None


def _listening(e: Entry, tcp: dict, udp: dict) -> tuple[str, int] | None:
    """The program listening on a port this rule names (its protocol's), a system service's first."""
    if not e.spans:
        return None
    proto = e.protocol.lower()
    found = []
    for table, name in ((tcp, "tcp"), (udp, "udp")):
        if proto and name not in proto:
            continue
        for prog, ports in table.items():
            for p in sorted(ports):
                if any(a <= p <= b for a, b in e.spans):
                    found.append((prog, p))
    if not found:
        return None
    return next((f for f in found if f[0] in SYSTEM_PROGRAMS), found[0])


def sort_entry(e: Entry, listening: dict | None = None, listening_udp: dict | None = None) -> Sorted:
    """A rule's own group, and why: whose it is; this machine's own traffic, ICMP or invalid packets (the system's
    networking); the firewalld service or ufw profile it names; the program listening on a port it names; a port of the
    system's own services; else other."""
    own = _owned(e.owner)
    if own is not None:
        return own
    if e.action in ("jump", "goto") and e.target:
        own = _owned(owner_by_name(e.target))
        if own is not None:
            return own
    if e.local:
        return Sorted("system", "this machine's own traffic: loopback, and the replies to its connections")
    if ICMP.search(e.protocol) or ICMP.search(e.text):
        return Sorted("system", "ICMP: the network's own messages (ping, errors, IPv6's neighbours)")
    if "invalid" in e.state.lower():
        return Sorted("system", "packets the connection tracking finds invalid")
    if e.kind == "firewalld" and e.text.startswith("service "):
        name = e.text.split()[1]
        if name in SYSTEM_SERVICES:
            return Sorted("system", f"firewalld's service {name}")
        return Sorted("application", f"firewalld's service {name}")
    if e.kind == "ufw" and e.ports and not e.ports[:1].isdecimal():  # an application profile (OpenSSH, Nginx Full)
        return Sorted("system" if SYSTEM_PROFILE.search(e.ports) else "application", f"ufw's application profile {e.ports}")
    hit = _listening(e, listening or {}, listening_udp or {})
    if hit:
        prog, port = hit
        return Sorted("system" if prog in SYSTEM_PROGRAMS else "application", f"{prog} listens on port {port}")
    for a, b in e.spans:
        for p, what in SYSTEM_PORTS.items():
            if a <= p <= b and (b - a) < 1024:  # a port named, or a short range: not every port
                return Sorted("system", f"port {p}: {what}")
    return Sorted("other", "no program or service: a port or an address alone")
