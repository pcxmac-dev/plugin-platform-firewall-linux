"""Each rule's own group and its name there (0.5.0; the user: "for both firewalls, i need to have groups, like system or
application and then unassociated rules not tied to a specific application or system process can be in an other, i can
create labels, like system or application, as well and move the rules in to that"; 0.6.0: "for the windows and linux
firewall, lets have the same system and application and other, but lets group by application under apps or system, try
best to organize under system and applications", "try to group the system by 'services'").

A Linux rule names no program the way a Windows rule does, so what it is tied to is found from what is known of it:
whose rule it is (a program making its own: Docker's, libvirt's, Fail2ban's...), what it is for (this machine's own
traffic: loopback and the replies to its connections; ICMP; packets the connection tracking finds invalid), the
firewalld service or ufw application profile it names, the program listening on a port it names (`ss -ltnp`, `ss
-lunp`), or a port the system's own services use (SSH, DNS, DHCP, NTP...). System: the operating system's (its
services, its networking); Application: a program's (one installed, or one that makes rules of its own; Liminal's);
Other: tied to none of these (a port or an address alone). The user's labels and moves are the library's (rulegroups),
kept through the platform's login.

Within System and Application every rule is named too (`Sorted.name`, 0.6.0): the heading it is listed under, and each
name is in one group only, whichever way its rule was recognised. A System rule by its service (`VOCABULARY`):
firewalld's service ssh, ufw's profile OpenSSH, sshd listening on port 22 and port 22 alone all name SSH; else by what
it is (This machine's own traffic, ICMP, Invalid packets) or by the system's program making it (Fail2ban,
NetworkManager). An Application rule by its application, one name however it is found (`application`): the program
making its own rules (Docker, Liminal), what a firewalld service is for (`APP_SERVICES`: http, https and http3 are the
Web server (HTTP, HTTPS); smtp, imap and pop3 the Mail server; a service not known there by its own name), a ufw
profile's application (its name without the words saying which of its ports: Nginx Full and Nginx HTTPS are Nginx,
Apache Full is Apache), the program listening on its port (Apache for apache2, Mosh for mosh-server, Plex for Plex Media
Server; a part of a program making its own rules by that program's: docker-proxy is Docker; on one of Liminal's own
ports, Liminal). A socket no program is shown for (the kernel's: nfsd, WireGuard) names nothing: its port does. An
Other rule has no name."""
from __future__ import annotations

import re

from liminal_libs.machines.rulegroups import Sorted, key_of

from .firewalld import NOT_ACTIVE
from .model import OWNER_WORDS, Entry, owner_by_name

APP_OWNERS = {"liminal", "docker", "podman", "libvirt", "incus", "lxd", "kubernetes", "calico", "cilium", "flannel", "weave",
              "tailscale", "waydroid", "wireguard", "owned"}
SYSTEM_OWNERS = {"systemd", "networkmanager", "nixos", "fail2ban", "crowdsec", "sshguard"}

# -- the system's services, one name each whichever way a rule is recognised (0.6.0) -------------------------------------
LOCAL = "This machine's own traffic"
ICMP_NAME = "ICMP"
INVALID = "Invalid packets"
VOCABULARY = (  # every name a System rule takes from the tables below (a system program making rules: its OWNER_WORDS)
    "SSH", "DNS", "DHCP", "DHCPv6", "NTP", "mDNS", "LLMNR", "NetBIOS", "Samba", "NFS", "rpcbind", "Printing (CUPS)", "Cockpit",
    "Kerberos", "LDAP", "SNMP", "Syslog", "WSD", "SSDP (UPnP)", "TFTP", "D-Bus", "LLDP", "SSSD", "Bluetooth", "Wi-Fi",
    "ConnMan", "NetworkManager", "systemd", "init", "inetd", "xinetd", LOCAL, ICMP_NAME, INVALID,
)
SERVICE_PORTS = {  # a port's service: a program serving several is named by the port it listens on, a port alone by it
    22: "SSH", 53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 88: "Kerberos", 111: "rpcbind", 123: "NTP", 137: "NetBIOS",
    138: "NetBIOS", 139: "Samba", 161: "SNMP", 162: "SNMP", 389: "LDAP", 445: "Samba", 464: "Kerberos", 514: "Syslog",
    515: "Printing (CUPS)", 546: "DHCPv6", 547: "DHCPv6", 631: "Printing (CUPS)", 636: "LDAP", 749: "Kerberos", 853: "DNS",
    1900: "SSDP (UPnP)", 2049: "NFS", 3702: "WSD", 5353: "mDNS", 5355: "LLMNR", 5357: "WSD", 6514: "Syslog", 9090: "Cockpit",
}
SYSTEM_PORTS = {22: "SSH", 53: "DNS", 67: "DHCP", 68: "DHCP", 111: "rpcbind", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS",
                139: "file sharing (Samba)", 445: "file sharing (Samba)", 546: "DHCPv6", 547: "DHCPv6", 631: "printing (CUPS)",
                2049: "NFS", 5353: "mDNS", 5355: "LLMNR", 9090: "Cockpit"}  # a port alone that is the system's: why, in words
SYSTEM_PROGRAMS = {  # the system's own services by the program listening (as ss and netstat name it): the service
    "sshd": "SSH", "sshd-session": "SSH", "dropbear": "SSH", "chronyd": "NTP", "ntpd": "NTP", "ntpd-rs": "NTP",
    "openntpd": "NTP", "systemd-timesyncd": "NTP", "systemd-timesyn": "NTP", "avahi-daemon": "mDNS", "cupsd": "Printing (CUPS)",
    "cups-browsed": "Printing (CUPS)", "wpa_supplicant": "Wi-Fi", "rpcbind": "rpcbind", "rpc.statd": "NFS", "rpc.mountd": "NFS",
    "nfsd": "NFS", "smbd": "Samba", "samba": "Samba", "winbindd": "Samba", "nmbd": "NetBIOS", "wsdd": "WSD", "wsdd2": "WSD",
    "in.tftpd": "TFTP", "tftpd": "TFTP", "atftpd": "TFTP", "dbus-daemon": "D-Bus", "cockpit-ws": "Cockpit", "cockpit-tls": "Cockpit",
    "rsyslogd": "Syslog", "syslog-ng": "Syslog", "named": "DNS", "unbound": "DNS", "krb5kdc": "Kerberos", "kadmind": "Kerberos",
    "sssd": "SSSD", "slapd": "LDAP", "snmpd": "SNMP", "lldpd": "LLDP", "bluetoothd": "Bluetooth",
    # serving several: named by the port first (BY_PORT), else so
    "systemd": "systemd", "init": "init", "inetd": "inetd", "xinetd": "xinetd", "systemd-resolve": "DNS",
    "systemd-resolved": "DNS", "systemd-network": "DHCP", "systemd-networkd": "DHCP", "dhclient": "DHCP", "dhcpcd": "DHCP",
    "udhcpc": "DHCP", "dhcpd": "DHCP", "udhcpd": "DHCP", "dnsmasq": "DNS", "NetworkManager": "NetworkManager",
    "connmand": "ConnMan", "iwd": "Wi-Fi",
}
BY_PORT = frozenset({"systemd", "init", "inetd", "xinetd", "systemd-resolve", "systemd-resolved", "systemd-network",
                     "systemd-networkd", "dhclient", "dhcpcd", "udhcpc", "dhcpd", "udhcpd", "dnsmasq", "NetworkManager",
                     "connmand", "iwd"})  # systemd's sockets, the super-servers, DNS and DHCP's clients and servers
SYSTEM_SERVICES = {  # firewalld's services for the system's own: the service
    "ssh": "SSH", "dhcp": "DHCP", "dhcpv6": "DHCPv6", "dhcpv6-client": "DHCPv6", "dns": "DNS", "dns-over-tls": "DNS",
    "mdns": "mDNS", "llmnr": "LLMNR", "llmnr-client": "LLMNR", "llmnr-tcp": "LLMNR", "llmnr-udp": "LLMNR", "samba": "Samba",
    "samba-client": "Samba", "samba-dc": "Samba", "nfs": "NFS", "nfs3": "NFS", "mountd": "NFS", "rpc-bind": "rpcbind",
    "ntp": "NTP", "ipp": "Printing (CUPS)", "ipp-client": "Printing (CUPS)", "cockpit": "Cockpit", "kerberos": "Kerberos",
    "kpasswd": "Kerberos", "kadmin": "Kerberos", "ldap": "LDAP", "ldaps": "LDAP", "freeipa-ldap": "LDAP",
    "freeipa-ldaps": "LDAP", "freeipa-replication": "LDAP", "snmp": "SNMP", "snmptrap": "SNMP", "snmptls": "SNMP",
    "snmptls-trap": "SNMP", "syslog": "Syslog", "syslog-tls": "Syslog", "wsdd": "WSD", "ws-discovery": "WSD",
    "ws-discovery-client": "WSD", "ws-discovery-host": "WSD", "ws-discovery-tcp": "WSD", "ws-discovery-udp": "WSD",
    "netbios-ns": "NetBIOS", "ssdp": "SSDP (UPnP)", "upnp-client": "SSDP (UPnP)", "bluetooth": "Bluetooth", "tftp": "TFTP",
    "tftp-client": "TFTP",
}
PROFILE_WORDS = {  # ufw's application profiles for the system's own: a whole word of the profile's name (any case), the service
    "ssh": "SSH", "openssh": "SSH", "sshd": "SSH", "dropbear": "SSH", "dhcp": "DHCP", "dhcpd": "DHCP", "dhcpv6": "DHCPv6",
    "dns": "DNS", "bind": "DNS", "bind9": "DNS", "ntp": "NTP", "ntpd": "NTP", "chrony": "NTP", "mdns": "mDNS", "avahi": "mDNS",
    "bonjour": "mDNS", "llmnr": "LLMNR", "netbios": "NetBIOS", "samba": "Samba", "cifs": "Samba", "smb": "Samba", "nfs": "NFS",
    "mountd": "NFS", "rpcbind": "rpcbind", "portmap": "rpcbind", "cups": "Printing (CUPS)", "ipp": "Printing (CUPS)",
    "ipps": "Printing (CUPS)", "lpd": "Printing (CUPS)", "cockpit": "Cockpit", "kerberos": "Kerberos", "kdc": "Kerberos",
    "kpasswd": "Kerberos", "kadmin": "Kerberos", "ldap": "LDAP", "ldaps": "LDAP", "openldap": "LDAP", "snmp": "SNMP",
    "syslog": "Syslog", "rsyslog": "Syslog", "wsd": "WSD", "wsdd": "WSD", "ssdp": "SSDP (UPnP)", "upnp": "SSDP (UPnP)",
    "tftp": "TFTP",
}
PROFILE_PHRASES = ((("ws", "discovery"), "WSD"),)  # several whole words in a row (WS-Discovery)
PROFILE_PARTS = (  # distinctive names found inside a word too (OpenSSH-Server is a word of its own; Samba4): the first wins
    ("openssh", "SSH"), ("openldap", "LDAP"), ("bind9", "DNS"), ("wsdd", "WSD"), ("samba", "Samba"), ("netbios", "NetBIOS"),
    ("dhcpv6", "DHCPv6"), ("dhcp", "DHCP"), ("avahi", "mDNS"), ("bonjour", "mDNS"), ("rpcbind", "rpcbind"),
    ("cockpit", "Cockpit"), ("kerberos", "Kerberos"), ("syslog", "Syslog"),
)
WORD = re.compile(r"[0-9a-z]+")

# -- the applications, one name each however they are found (0.6.0) --------------------------------------------------------
WEB = "Web server (HTTP, HTTPS)"
MAIL = "Mail server"
APP_SERVICES = {service: name for name, services in (  # firewalld's services for an application: what it is for, readably
    (WEB, ("http", "https", "http3")), (MAIL, ("smtp", "smtps", "smtp-submission", "imap", "imaps", "pop3", "pop3s", "managesieve")),
    ("FTP server", ("ftp",)), ("MySQL", ("mysql",)), ("PostgreSQL", ("postgresql",)), ("MongoDB", ("mongodb",)),
    ("Redis", ("redis", "redis-sentinel")), ("Memcached", ("memcache",)), ("Elasticsearch", ("elasticsearch",)),
    ("CouchDB", ("couchdb",)), ("OpenVPN", ("openvpn",)), ("WireGuard", ("wireguard",)), ("IPsec", ("ipsec",)),
    ("VNC", ("vnc-server",)), ("Remote Desktop (RDP)", ("rdp",)), ("Git", ("git",)), ("Subversion", ("svn",)),
    ("Plex", ("plex",)), ("Jellyfin", ("jellyfin",)), ("MiniDLNA", ("minidlna",)),
    ("Syncthing", ("syncthing", "syncthing-gui", "syncthing-relay")), ("KDE Connect", ("kdeconnect",)),
    ("Steam", ("steam-streaming", "steam-lan-transfer")), ("Minecraft", ("minecraft",)),
    ("Prometheus", ("prometheus", "prometheus-node-exporter")), ("Grafana", ("grafana",)),
    ("Zabbix", ("zabbix-agent", "zabbix-server")), ("Nagios (NRPE)", ("nrpe",)), ("Docker", ("docker-registry", "docker-swarm")),
    ("Kubernetes", ("kube-api", "kube-apiserver", "kube-control-plane", "kube-control-plane-secure", "kube-controller-manager",
                    "kube-controller-manager-secure", "kube-nodeport-services", "kube-scheduler", "kube-scheduler-secure",
                    "kube-worker", "kubelet", "kubelet-readonly", "kubelet-worker")),
    ("etcd", ("etcd-client", "etcd-server")), ("libvirt", ("libvirt", "libvirt-tls")),
    ("Ceph", ("ceph", "ceph-mon", "ceph-exporter")), ("Salt", ("salt-master",)), ("Puppet", ("puppetmaster",)),
    ("XMPP", ("xmpp-client", "xmpp-server", "xmpp-bosh", "xmpp-local")), ("IRC", ("irc", "ircs")), ("MQTT", ("mqtt", "mqtt-tls")),
    ("AMQP", ("amqp", "amqps")), ("Transmission", ("transmission-client",)), ("Squid", ("squid",)), ("Tor", ("tor-socks",)),
    ("Telnet", ("telnet",)), ("rsync", ("rsyncd",)), ("Spotify", ("spotify-sync",)), ("PulseAudio", ("pulseaudio",)),
    ("Mumble", ("murmur",)), ("TeamSpeak", ("ts3",)), ("Jenkins", ("jenkins",)), ("iSCSI", ("iscsi-target",)),
) for service in services}
PROGRAM_APPS = {program: OWNER_WORDS[owner] for program, owner in (  # a listening part of a program making its own rules
    ("docker-proxy", "docker"), ("dockerd", "docker"), ("rootlessport", "podman"), ("conmon", "podman"), ("aardvark-dns", "podman"),
    ("libvirtd", "libvirt"), ("incusd", "incus"), ("lxd", "lxd"), ("kubelet", "kubernetes"), ("kube-proxy", "kubernetes"),
    ("kube-apiserver", "kubernetes"), ("k3s", "kubernetes"), ("k3s-server", "kubernetes"), ("tailscaled", "tailscale"),
    ("calico-node", "calico"), ("cilium-agent", "cilium"), ("flanneld", "flannel"), ("waydroid", "waydroid"),
)}
APP_NAMES = {alias: name for name, aliases in (  # one name for an application: a program as ss names it (its first 15
    # letters), a ufw profile's application, any case
    (WEB, ("www", "www cache", "http", "https", "httpd")),  # ufw's own WWW profiles; httpd: Fedora's Apache, or BusyBox's
    (MAIL, ("smtp", "smtps", "mail", "submission", "imap", "imaps", "pop3", "pop3s", "postfix", "master", "exim", "exim4",
            "sendmail", "sendmail-mta", "smtpd", "opensmtpd", "dovecot", "courier", "cyrus")),  # ufw's own SMTP... profiles too
    ("Apache", ("apache", "apache2")), ("Nginx", ("nginx",)), ("Caddy", ("caddy",)), ("lighttpd", ("lighttpd",)),
    ("Mosh", ("mosh", "mosh-server")),
    ("Plex", ("plex", "plexmediaserver", "plex media serv", "plex media server", "plex dlna serve", "plex dlna server")),
    ("Jellyfin", ("jellyfin",)), ("Syncthing", ("syncthing",)), ("KDE Connect", ("kdeconnect", "kdeconnectd", "kde connect")),
    ("Transmission", ("transmission", "transmission-daemon", "transmission-da")), ("Deluge", ("deluge", "deluged")),
    ("qBittorrent", ("qbittorrent", "qbittorrent-nox")), ("BitTorrent", ("bittorrent",)), ("MiniDLNA", ("minidlna", "minidlnad")),
    ("FTP server", ("ftp", "vsftpd", "proftpd", "pure-ftpd")), ("MySQL", ("mysql", "mysqld")), ("MariaDB", ("mariadb", "mariadbd")),
    ("PostgreSQL", ("postgres", "postgresql", "postmaster")), ("MongoDB", ("mongod", "mongodb")), ("Redis", ("redis", "redis-server")),
    ("Memcached", ("memcached",)), ("OpenVPN", ("openvpn",)), ("PowerDNS", ("powerdns", "pdns_server", "pdns-server")),
    ("Squid", ("squid",)), ("Remote Desktop (RDP)", ("xrdp", "rdp")), ("VNC", ("vnc", "xvnc", "x0vncserver", "vncserver")),
    ("XMPP", ("xmpp", "jabber", "prosody", "ejabberd")), ("IRC", ("irc", "ircs", "ircd", "inspircd", "ngircd")),
    ("Telnet", ("telnet", "telnetd", "in.telnetd")), ("rsync", ("rsync", "rsyncd")), ("Mumble", ("murmur", "murmurd", "mumble-server")),
    ("TeamSpeak", ("ts3server", "teamspeak")), ("MQTT", ("mqtt", "mosquitto")), ("Prometheus", ("prometheus", "node_exporter")),
    ("Grafana", ("grafana", "grafana-server")), ("Steam", ("steam",)), ("Git", ("git", "git-daemon")),
) for alias in aliases}
PROFILE_QUALIFIERS = frozenset({  # the words of a ufw profile's name that only say which of its application's ports
    "full", "http", "https", "quic", "secure", "ssl", "tls", "smtps", "submission", "imap", "imaps", "pop3", "pop3s", "tcp", "udp",
    "dlna", "all", "gui", "web",
})
SEPARATOR = re.compile(r"[\s_-]+")
ICMP = re.compile(r"\bicmp(v6)?\b|\bipv6-icmp\b|\bicmp6\b", re.I)
UNKNOWN = frozenset({"?", "-", ""})  # a socket shown with no program (the kernel's own: nfsd, WireGuard): it names nothing
SYSTEM_NAMES = {n.casefold(): n for n in (*VOCABULARY, *(OWNER_WORDS[o] for o in SYSTEM_OWNERS))}  # a name: System's alone


def key(e: Entry) -> str:
    """A rule's key: where it is and its words (its place in a chain, ufw's number, its counters left out; and a firewalld
    zone's mark while it filters nothing, so a rule moved stays where it was put when its zone comes into use)."""
    where = e.where.removesuffix(NOT_ACTIVE) if e.kind == "firewalld" else e.where
    return key_of(e.kind, where, e.text)


def service_of_program(program: str, port: int) -> str:
    """The service a system program listening on `port` is for: a program serving several (systemd's sockets, dnsmasq,
    a DHCP client, systemd-resolved) by the port first."""
    if program in BY_PORT and port in SERVICE_PORTS:
        return SERVICE_PORTS[port]
    return SYSTEM_PROGRAMS.get(program, program)


def service_of_profile(profile: str) -> str:
    """The system's service a ufw application profile is for ("" when it is an application's): by a whole word of its
    name (OpenSSH, CUPS, Kerberos KDC), several words in a row (WS-Discovery), or a distinctive name inside a word
    (Samba4); a short word inside another word names nothing (Zipper is no printer's, PowerDNS not the system's DNS)."""
    words = WORD.findall(profile.casefold())
    hit = next((PROFILE_WORDS[w] for w in words if w in PROFILE_WORDS), "")
    if hit:
        return hit
    for phrase, name in PROFILE_PHRASES:
        if any(tuple(words[i:i + len(phrase)]) == phrase for i in range(len(words))):
            return name
    low = profile.casefold()
    return next((name for part, name in PROFILE_PARTS if part in low), "")


def application(found: str) -> str:
    """An application's one name, whichever way it was found (`APP_NAMES`, any case; a part of a program making its own
    rules by that program's): Apache for apache2 and ufw's Apache, Mosh for mosh-server; else as found."""
    return PROGRAM_APPS.get(found) or APP_NAMES.get(" ".join(found.split()).casefold(), found)


def application_of_profile(profile: str) -> str:
    """The application a ufw profile is for: the profile's name as a whole when known (`APP_NAMES`: WWW Cache), else its
    name without the words at its end saying which of its ports (Nginx Full and Nginx HTTPS: Nginx; Dovecot Secure IMAP:
    Dovecot, the Mail server; plexmediaserver-dlna: Plex), never none of it."""
    whole = " ".join(profile.split()).casefold()
    if whole in APP_NAMES:
        return APP_NAMES[whole]
    parts = re.findall(r"[^\s_-]+|[\s_-]+", profile.strip())
    while len(parts) > 1 and (SEPARATOR.fullmatch(parts[-1]) or parts[-1].lower() in PROFILE_QUALIFIERS):
        parts.pop()
    return application("".join(parts) or profile)


def _app(why: str, name: str) -> Sorted:
    """An application's rule under its name; but a name that is one of the system's (a ufw profile called Bluetooth, a
    firewalld service called lldp) is System's, so that no name is a heading in both groups."""
    system = SYSTEM_NAMES.get(name.casefold())
    return Sorted("system", why, system) if system else Sorted("application", why, name)


def _table_of(e: Entry) -> str:
    """An nftables rule's table ("inet daemon input": daemon), what an owned table's program is known by."""
    words = e.where.split()
    return words[1] if e.kind == "nftables" and len(words) >= 2 else ""


def _owned(owner: str, e: Entry) -> Sorted | None:
    words = OWNER_WORDS.get(owner, owner)
    if owner == "liminal":
        return Sorted("application", "Liminal's: made on the platform", "Liminal")
    if owner == "owned":
        return _app(f"{words}'s: it makes its rules itself", _table_of(e))
    if owner in APP_OWNERS:
        return Sorted("application", f"{words}'s: it makes its rules itself", words)
    if owner in SYSTEM_OWNERS:
        return Sorted("system", f"{words}'s", words)
    return None


def _listening(e: Entry, tcp: dict, udp: dict) -> tuple[str, int] | None:
    """The program listening on a port this rule names (its protocol's), a system service's first; a socket shown with
    no program is none (`UNKNOWN`)."""
    if not e.spans:
        return None
    proto = e.protocol.lower()
    found = []
    for table, name in ((tcp, "tcp"), (udp, "udp")):
        if proto and name not in proto:
            continue
        for prog, ports in table.items():
            if prog in UNKNOWN:
                continue
            for p in sorted(ports):
                if any(a <= p <= b for a, b in e.spans):
                    found.append((prog, p))
    if not found:
        return None
    return next((f for f in found if f[0] in SYSTEM_PROGRAMS), found[0])


def sort_entry(e: Entry, listening: dict | None = None, listening_udp: dict | None = None, liminal_ports=()) -> Sorted:
    """A rule's own group, why, and its name there: whose it is; this machine's own traffic, ICMP or invalid packets (the
    system's networking); the firewalld service or ufw profile it names; the program listening on a port it names (on
    one of `liminal_ports`, the framework's own pages, Liminal); a port of the system's own services; else other, with
    no name."""
    own = _owned(e.owner, e)
    if own is not None:
        return own
    if e.action in ("jump", "goto") and e.target:
        own = _owned(owner_by_name(e.target), e)
        if own is not None:
            return own
    if e.local:
        return Sorted("system", "this machine's own traffic: loopback, and the replies to its connections", LOCAL)
    if ICMP.search(e.protocol) or ICMP.search(e.text):
        return Sorted("system", "ICMP: the network's own messages (ping, errors, IPv6's neighbours)", ICMP_NAME)
    if "invalid" in e.state.lower():
        return Sorted("system", "packets the connection tracking finds invalid", INVALID)
    if e.kind == "firewalld" and e.text.startswith("service "):
        name = e.text.split()[1]
        if name in SYSTEM_SERVICES:
            return Sorted("system", f"firewalld's service {name}", SYSTEM_SERVICES[name])
        return _app(f"firewalld's service {name}", APP_SERVICES.get(name) or application(name))
    if e.kind == "ufw" and e.ports and not e.ports[:1].isdecimal():  # an application profile (OpenSSH, Nginx Full)
        service = service_of_profile(e.ports)
        if service:
            return Sorted("system", f"ufw's application profile {e.ports}", service)
        return _app(f"ufw's application profile {e.ports}", application_of_profile(e.ports))
    hit = _listening(e, listening or {}, listening_udp or {})
    if hit:
        prog, port = hit
        if prog in SYSTEM_PROGRAMS:
            return Sorted("system", f"{prog} listens on port {port}", service_of_program(prog, port))
        return _app(f"{prog} listens on port {port}", "Liminal" if port in liminal_ports else application(prog))
    for a, b in e.spans:
        for p, what in SYSTEM_PORTS.items():
            if a <= p <= b and (b - a) < 1024:  # a port named, or a short range: not every port
                return Sorted("system", f"port {p}: {what}", SERVICE_PORTS[p])
    return Sorted("other", "no program or service: a port or an address alone")
