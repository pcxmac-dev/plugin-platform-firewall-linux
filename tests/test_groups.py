"""The rules in groups (0.5.0; the user: "for both firewalls, i need to have groups, like system or application and then
unassociated rules not tied to a specific application or system process can be in an other, i can create labels, like
system or application, as well and move the rules in to that"), over the recorded machines: each rule sorted by whose it
is, what it is for, the service or profile it names and the program listening on its port; the user's labels and moves
kept through the platform's login (a stand-in's variables here), never in the firewall: no command runs for a move.

And named within System and Application (0.6.0; the user: "lets group by application under apps or system, try best to
organize under system and applications", "try to group the system by 'services'"): the headings each recorded machine's
rules fall under, every way a rule is named, one name for a service and for an application whichever way it was
recognised, no name a heading in both groups, and Find finding a rule by its heading's name."""
from __future__ import annotations

import json

import pytest

from liminal_libs.apps.authorization import EnvironmentLogin
from liminal_libs.machines.firewall import APP_PORTS
from liminal_libs.machines import linux as linux_mod
from liminal_libs.machines.linux import Shell

from plugin_platform_firewall_linux import LinuxFirewallPlugin
from plugin_platform_firewall_linux import groups as groups_mod
from plugin_platform_firewall_linux.groups import key, sort_entry
from plugin_platform_firewall_linux.model import OWNER_WORDS, Entry
from plugin_platform_firewall_linux.read import parse
from plugin_platform_firewall_linux.system import parse_sockets

from machines import FakeLinux, answer


@pytest.fixture(autouse=True)
def root(monkeypatch):
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 0, raising=False)


def sorted_of(machine: str, **changed) -> dict:
    """Each rule's words -> (its group, why), as read on a recorded machine."""
    cfg = parse(answer(FakeLinux(machine, **changed).sections))
    return {e.text: (s.group, s.why) for e in cfg.entries()
            for s in [sort_entry(e, cfg.system.listening, cfg.system.listening_udp)]}


def test_each_rule_is_sorted_by_what_it_is_tied_to_on_every_recorded_machine():
    debian = sorted_of("debian-13-nftables")
    assert debian['tcp dport 22 counter accept comment "ssh"'] == ("system", "sshd listens on port 22")
    assert debian["ct state established,related accept"][0] == "system" and debian['iifname "lo" accept'][0] == "system"
    assert debian["meta l4proto { icmp, ipv6-icmp } accept"][0] == "system" and debian["ct state invalid drop"][0] == "system"
    assert debian["tcp dport { 80, 443 } accept"] == ("other", "no program or service: a port or an address alone")
    assert {g for t, (g, _) in debian.items() if "docker" in t.lower()} == {"application"}
    assert debian["-j DOCKER-USER"] == ("application", "Docker's: it makes its rules itself")
    ufw = sorted_of("ubuntu-24.04-ufw")
    assert ufw["25,587/tcp  ALLOW IN  Anywhere  # liminal:mail-example-test"] == ("application", "Liminal's: made on the platform")
    assert ufw["53/udp  ALLOW OUT  Anywhere (out)"] == ("system", "port 53: DNS") and ufw["Anywhere  ALLOW IN  10.0.0.0/8"][0] == "other"
    fedora = sorted_of("fedora-43-firewalld")
    assert fedora["service ssh (22/tcp)"] == ("system", "firewalld's service ssh")
    assert fedora["service cockpit (9090/tcp)"][0] == "system" and fedora["port 8443/tcp"][0] == "other"
    gentoo = sorted_of("gentoo-openrc-nftables")
    assert gentoo['udp dport 60000-61000 accept comment "mosh"'][0] == "other"
    # a program listening for UDP (ss -lunp): an application's port
    mosh = sorted_of("gentoo-openrc-nftables", listen_udp='UNCONN 0 0 0.0.0.0:60001 0.0.0.0:* users:(("mosh-server",pid=9,fd=4))')
    assert mosh['udp dport 60000-61000 accept comment "mosh"'] == ("application", "mosh-server listens on port 60001")


def test_what_a_rule_names_decides_without_a_listener():
    def one(**kw):
        s = sort_entry(Entry(ref="x", kind=kw.pop("kind", "nftables"), where="w", direction="in", action=kw.pop("action", "accept"),
                             text=kw.pop("text", "x"), **kw))
        return s.group, s.why

    assert one(kind="ufw", ports="OpenSSH", spans=((22, 22),)) == ("system", "ufw's application profile OpenSSH")
    assert one(kind="ufw", ports="Nginx Full") == ("application", "ufw's application profile Nginx Full")
    assert one(kind="firewalld", text="service plex (32400/tcp)") == ("application", "firewalld's service plex")
    assert one(owner="fail2ban") == ("system", "Fail2ban's") and one(owner="libvirt")[0] == "application"
    assert one(action="jump", target="f2b-sshd") == ("system", "Fail2ban's")
    assert one(protocol="udp", spans=((123, 123),)) == ("system", "port 123: NTP")
    assert one(protocol="tcp", spans=((1, 65535),))[0] == "other"  # every port: no service named by it
    assert parse_sockets('UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:(("dhclient",pid=1,fd=6))') == {"dhclient": {68}}


def test_the_read_lists_udp_listeners_and_netstat_alike():
    from plugin_platform_firewall_linux.read import SCRIPT

    assert "sec listen.udp ss -lunpH" in SCRIPT and "sec listen.udp.netstat netstat -lunp" in SCRIPT
    cfg = parse(answer(FakeLinux("alpine-3.22-iptables", listen_udp_netstat=(
        "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\n"
        "udp        0      0 0.0.0.0:68              0.0.0.0:*                           1501/udhcpc\n")).sections))
    assert cfg.system.listening_udp == {"udhcpc": {68}}


def test_rules_move_between_groups_and_labels_kept_through_the_login_alone():
    fake = FakeLinux("debian-13-nftables")
    fw = LinuxFirewallPlugin(shell=Shell("local", runner=fake), native="")
    fw.show_rules("all")
    login = EnvironmentLogin(env={})
    fw.login = login
    st = fw.status()
    rules = next(t for t in st["tables"] if t["title"] == "Rules")
    assert [(g["id"], g["count"]) for g in rules["groups"]] == [("system", 5), ("application", 14), ("other", 3)]
    web = next(r for r in rules["rows"] if r["cells"][6] == "tcp dport { 80, 443 } accept")
    calls = len(fake.calls)
    fw.new_label("Web")
    assert fw.move_rules([web["key"]], "label:Web")["said"] == "1 rule moved to Web"
    assert json.loads(login.env["FIREWALL_LINUX_GROUPS"]) == {"v": 1, "labels": ["Web"], "moved": {"Web": [web["key"]]}}
    rules = next(t for t in fw.status()["tables"] if t["title"] == "Rules")
    assert {g["id"]: g["count"] for g in rules["groups"]}["label:Web"] == 1
    assert next(r for r in rules["rows"] if r["key"] == web["key"])["group"] == "label:Web"
    assert len(fake.calls) == calls  # no command run for a label or a move
    assert fw.rename_label("Web", "Websites")["ok"] and fw.move_rules([web["key"]], "own")["said"] == "1 rule moved to their own groups"
    assert json.loads(login.env["FIREWALL_LINUX_GROUPS"]) == {"v": 1, "labels": ["Websites"], "moved": {}}
    assert web["key"] in fw.sorted_rules() and len(web["key"]) == 10 and key(next(e for e in fw.config().entries())) in fw.sorted_rules()


# -- the names within System and Application (0.6.0) ----------------------------------------------------------------------
RECORDED = ("debian-13-nftables", "ubuntu-24.04-ufw", "fedora-43-firewalld", "gentoo-openrc-nftables", "alpine-3.22-iptables")


def plugin(fake) -> LinuxFirewallPlugin:
    return LinuxFirewallPlugin(shell=Shell("local", runner=fake), native="")


def rules_of(fw: LinuxFirewallPlugin, find: str = "") -> dict:
    fw.show_rules("all")
    fw.find_rules(find)
    return next(t for t in fw.status()["tables"] if t["title"] == "Rules")


def headings(machine: str, fake=None, **changed) -> tuple:
    """A recorded machine's Rules table with every rule shown: System's headings and Application's, each with its count,
    and Other's count (a single list: no headings)."""
    rules = rules_of(plugin(fake or FakeLinux(machine, **changed)))
    by = {g["id"]: g for g in rules["groups"]}
    assert all("sub" in r for r in rules["rows"] if r["group"] in ("system", "application"))  # every one of theirs is named
    assert "children" not in by["other"] and all("sub" not in r for r in rules["rows"] if r["group"] == "other")
    assert all(c["listed"] == c["count"] for g in ("system", "application") for c in by[g]["children"])  # every rule listed
    return ([(c["title"], c["count"]) for c in by["system"]["children"]],
            [(c["title"], c["count"]) for c in by["application"]["children"]], by["other"]["count"])


def test_the_headings_each_recorded_machines_rules_fall_under():
    assert headings("debian-13-nftables") == (
        [("ICMP", 1), ("Invalid packets", 1), ("SSH", 1), ("This machine's own traffic", 2)], [("Docker", 14)], 3)
    assert headings("ubuntu-24.04-ufw") == ([("DNS", 1), ("SSH", 2)], [("Liminal", 1)], 2)
    assert headings("fedora-43-firewalld") == (  # the public zone's three among them: bound to nothing, turned off
        [("Cockpit", 1), ("DHCPv6", 2), ("ICMP", 2), ("mDNS", 1), ("SSH", 2)], [], 3)
    assert headings("gentoo-openrc-nftables") == ([("SSH", 1), ("This machine's own traffic", 2)], [("Liminal", 1)], 2)
    assert headings("alpine-3.22-iptables") == ([("ICMP", 1), ("SSH", 2), ("This machine's own traffic", 4)], [], 0)
    # ufw off: its rules as added, under the headings they have while it is on
    assert headings("ubuntu-24.04-ufw", ufw_verbose="Status: inactive", ufw_numbered="Status: inactive") == (
        [("DNS", 1), ("SSH", 1)], [("Liminal", 1)], 2)
    # a program listening for UDP names its rule (ss -lunp), by its application's one name: mosh-server is Mosh
    mosh = 'UNCONN 0 0 0.0.0.0:60001 0.0.0.0:* users:(("mosh-server",pid=9,fd=4))'
    assert headings("gentoo-openrc-nftables", listen_udp=mosh)[1:] == ([("Liminal", 1), ("Mosh", 1)], 1)


def one(**kw) -> tuple:
    """A rule made of `kw` (an nftables input rule's unless said), sorted: (its group, why, its name there)."""
    listening, udp, ports = kw.pop("listening", {}), kw.pop("udp", {}), kw.pop("liminal_ports", ())
    s = sort_entry(Entry(ref="x", kind=kw.pop("kind", "nftables"), where=kw.pop("where", "inet filter input"),
                         direction=kw.pop("direction", "in"), action=kw.pop("action", "accept"), text=kw.pop("text", "x"), **kw),
                   listening, udp, ports)
    return s.group, s.why, s.name


def test_every_way_a_rule_is_named():
    # the programs making their own rules by their names, and Liminal's own
    assert one(owner="docker") == ("application", "Docker's: it makes its rules itself", "Docker")
    assert [one(owner=o)[2] for o in ("podman", "libvirt", "incus", "lxd", "kubernetes", "calico", "cilium", "flannel", "weave",
                                     "tailscale", "waydroid", "wireguard")] == [
        "Podman", "libvirt", "Incus", "LXD", "Kubernetes", "Calico", "Cilium", "flannel", "Weave", "Tailscale", "Waydroid", "WireGuard"]
    assert one(owner="liminal") == ("application", "Liminal's: made on the platform", "Liminal")
    assert one(owner="owned", where="inet daemon input") == ("application", "its owning program's: it makes its rules itself", "daemon")
    assert one(action="jump", target="DOCKER-USER")[0::2] == ("application", "Docker")  # the chain it jumps to says whose
    # the system's own rule makers
    assert one(owner="fail2ban") == ("system", "Fail2ban's", "Fail2ban") and one(action="jump", target="f2b-sshd")[2] == "Fail2ban"
    assert [one(owner=o)[2] for o in ("systemd", "networkmanager", "nixos", "crowdsec", "sshguard")] == [
        "systemd", "NetworkManager", "NixOS", "CrowdSec", "SSHGuard"]
    # the system's networking
    assert one(interface="lo") == ("system", "this machine's own traffic: loopback, and the replies to its connections",
                                   "This machine's own traffic")
    assert one(state="established,related")[2] == one(source="127.0.0.1")[2] == "This machine's own traffic"
    assert one(protocol="icmp")[0::2] == one(protocol="ipv6-icmp")[0::2] == ("system", "ICMP")
    assert one(state="invalid", action="drop") == ("system", "packets the connection tracking finds invalid", "Invalid packets")
    # firewalld's services: the system's by their service; an application's by what it is for, one not known by its name
    assert one(kind="firewalld", text="service mdns (5353/udp)") == ("system", "firewalld's service mdns", "mDNS")
    assert one(kind="firewalld", text="service http (80/tcp)") == ("application", "firewalld's service http", "Web server (HTTP, HTTPS)")
    assert {one(kind="firewalld", text=f"service {s}")[2] for s in ("http", "https", "http3")} == {"Web server (HTTP, HTTPS)"}
    assert {one(kind="firewalld", text=f"service {s}")[2] for s in ("smtp", "smtp-submission", "imaps", "pop3")} == {"Mail server"}
    assert one(kind="firewalld", text="service plex (32400/tcp)")[0::2] == ("application", "Plex")
    assert one(kind="firewalld", text="service kubelet (10250/tcp)")[2] == "Kubernetes"  # with Kubernetes' own rules
    assert one(kind="firewalld", text="service some-tool (4000/tcp)") == ("application", "firewalld's service some-tool", "some-tool")
    # ufw's profiles: the system's by their service; an application's by the application, whichever of its ports
    assert one(kind="ufw", ports="OpenSSH", spans=((22, 22),)) == ("system", "ufw's application profile OpenSSH", "SSH")
    assert [one(kind="ufw", ports=p)[0::2] for p in ("Nginx Full", "Nginx HTTPS", "Apache Full", "Dovecot Secure IMAP", "KDE Connect")] == [
        ("application", "Nginx"), ("application", "Nginx"), ("application", "Apache"), ("application", "Mail server"),
        ("application", "KDE Connect")]
    # the program listening: the system's by its service (one serving several by the port), another by its application
    assert one(protocol="tcp", spans=((22, 22),), listening={"sshd": {22}}) == ("system", "sshd listens on port 22", "SSH")
    assert one(protocol="udp", spans=((5355, 5355),), udp={"systemd-resolve": {53, 5355}})[0::2] == ("system", "LLMNR")
    assert one(protocol="udp", spans=((53, 53),), udp={"systemd-resolve": {53, 5355}})[2] == "DNS"
    assert one(protocol="tcp", spans=((8080, 8080),), listening={"node": {8080}}) == ("application", "node listens on port 8080", "node")
    assert one(protocol="tcp", spans=((5432, 5432),), listening={"docker-proxy": {5432}})[0::2] == ("application", "Docker")
    assert one(protocol="tcp", spans=((443, 443),), listening={"apache2": {443}}) == ("application", "apache2 listens on port 443", "Apache")
    assert one(protocol="tcp", spans=((32400, 32400),), listening={"Plex Media Serv": {32400}})[0::2] == ("application", "Plex")
    # on one of Liminal's own pages' ports: Liminal (its pages run as python3)
    page = {"protocol": "tcp", "spans": ((8775, 8775),), "listening": {"python3": {8775}}}
    assert one(**page, liminal_ports={8765, 8775}) == ("application", "python3 listens on port 8775", "Liminal")
    assert one(**page)[2] == "python3"
    # a port of the system's own services alone
    assert one(protocol="udp", spans=((123, 123),)) == ("system", "port 123: NTP", "NTP")
    assert one(protocol="tcp", spans=((445, 445),)) == ("system", "port 445: file sharing (Samba)", "Samba")
    # tied to nothing: Other, with no name
    assert one(protocol="tcp", spans=((8443, 8443),)) == ("other", "no program or service: a port or an address alone", "")


def test_a_port_of_liminals_own_pages_is_liminals(monkeypatch):
    for _, var, _ in APP_PORTS:  # the pages at their own ports, whatever this environment moves
        if var:
            monkeypatch.delenv(var, raising=False)
    fake = FakeLinux("debian-13-nftables")  # python3 listens on 8775 there: the platform's page
    data = json.loads(fake.sections["nft"][1])
    data["nftables"].append({"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 502, "expr": [
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8775}}, {"accept": None}]}})
    fake.nft(data)
    assert headings("debian-13-nftables", fake=fake)[1] == [("Docker", 14), ("Liminal", 1)]
    row = next(r for r in rules_of(plugin(fake), "8775")["rows"])
    assert (row["group"], row["sub"], row["why"]) == ("application", "application:liminal", "python3 listens on port 8775")


def test_a_socket_with_no_program_names_nothing_its_port_does():
    """The kernel's own servers (nfsd, WireGuard) listen with no program shown: their port names the rule, never "?"."""
    assert parse_sockets("LISTEN 0 64 0.0.0.0:2049 0.0.0.0:*") == {"?": {2049}}  # ss: no users field
    assert one(protocol="tcp", spans=((2049, 2049),), listening={"?": {2049}}) == ("system", "port 2049: NFS", "NFS")
    assert one(protocol="udp", spans=((51820, 51820),), udp={"?": {51820}})[0::2] == ("other", "")
    assert one(protocol="tcp", spans=((8080, 8080),), listening={"-": {8080}})[0::2] == ("other", "")  # netstat's "-"
    fake = FakeLinux("debian-13-nftables")
    fake.set("listen", fake.sections["listen"][1].rstrip("\n") + "\nLISTEN 0      64           0.0.0.0:2049           0.0.0.0:*\n")
    fake.set("listen.udp", "UNCONN 0      0            0.0.0.0:51820          0.0.0.0:*\n")
    data = json.loads(fake.sections["nft"][1])
    for port, proto, handle in ((2049, "tcp", 500), (51820, "udp", 501)):
        data["nftables"].append({"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": handle, "expr": [
            {"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "dport"}}, "right": port}}, {"accept": None}]}})
    fake.nft(data)
    system, applications, other = headings("debian-13-nftables", fake=fake)
    assert ("NFS", 1) in system and "?" not in {t for t, _ in system + applications} and other == 4


def test_ufws_profiles_are_the_systems_by_a_whole_word_of_their_name():
    assert {p: groups_mod.service_of_profile(p) for p in (
        "OpenSSH", "Kerberos KDC", "WS-Discovery", "IPP Everywhere", "LPD", "OpenLDAP LDAPS", "Samba4", "nfs-ganesha", "Bonjour")} == {
        "OpenSSH": "SSH", "Kerberos KDC": "Kerberos", "WS-Discovery": "WSD", "IPP Everywhere": "Printing (CUPS)",
        "LPD": "Printing (CUPS)", "OpenLDAP LDAPS": "LDAP", "Samba4": "Samba", "nfs-ganesha": "NFS", "Bonjour": "mDNS"}
    # a short word inside another word names no service: these are applications', by their own names
    for p in ("Zipper", "Mountpoint", "mountdock", "Bitwsd", "Crosshair", "PowerDNS"):
        assert one(kind="ufw", ports=p)[0::2] == ("application", p), p
    # PowerDNS one name either way: its profile and its program listening
    assert one(protocol="udp", spans=((53, 53),), udp={"pdns_server": {53}})[0::2] == ("application", "PowerDNS")


def test_one_heading_for_an_application_whichever_way_it_is_found():
    def listener(prog, port, proto="tcp"):
        return one(protocol=proto, spans=((port, port),), **{"listening" if proto == "tcp" else "udp": {prog: {port}}})

    fwd, ufw = (lambda s: one(kind="firewalld", text=f"service {s}")), (lambda p: one(kind="ufw", ports=p))
    ways = {
        "Apache": [ufw("Apache"), ufw("Apache Full"), listener("apache2", 80)],
        "Nginx": [ufw("Nginx Full"), ufw("Nginx QUIC"), listener("nginx", 443)],
        "Web server (HTTP, HTTPS)": [fwd("http"), fwd("https"), ufw("WWW"), ufw("WWW Full"), ufw("WWW Secure"), ufw("WWW Cache"),
                                     listener("httpd", 80)],
        "Mail server": [fwd("smtp"), fwd("smtps"), fwd("imap"), fwd("pop3s"), ufw("SMTP"), ufw("Mail submission"), ufw("IMAPS"),
                        ufw("POP3"), ufw("Postfix"), ufw("Postfix Submission"), ufw("Dovecot IMAP"), ufw("Dovecot Secure POP3"),
                        listener("master", 25), listener("exim4", 25), listener("sendmail", 587), listener("dovecot", 993)],
        "Mosh": [ufw("mosh"), fwd("mosh"), listener("mosh-server", 60001, "udp")],
        "Plex": [fwd("plex"), ufw("plexmediaserver"), ufw("plexmediaserver-dlna"), ufw("Plex Media Server"),
                 listener("Plex Media Serv", 32400)],
        "Syncthing": [fwd("syncthing-gui"), ufw("syncthing-gui"), listener("syncthing", 22000)],
        "Docker": [one(owner="docker"), fwd("docker-registry"), listener("docker-proxy", 5000)],
        "Kubernetes": [one(owner="kubernetes"), fwd("kubelet"), listener("kubelet", 10250)],
    }
    for name, got in ways.items():
        assert {(group, n) for group, _, n in got} == {("application", name)}, name


def test_no_name_is_a_heading_in_both_groups():
    system = {n.casefold() for n in (*groups_mod.VOCABULARY, *(OWNER_WORDS[o] for o in groups_mod.SYSTEM_OWNERS))}
    applications = {*groups_mod.APP_SERVICES.values(), *groups_mod.APP_NAMES.values(), *groups_mod.PROGRAM_APPS.values(),
                    *(OWNER_WORDS[o] for o in groups_mod.APP_OWNERS - {"owned"}), "Liminal"}
    assert not {n.casefold() for n in applications} & system
    # TFTP is the system's every way (network booting, with DHCP); mail is an application's every way
    tftp = [one(kind="firewalld", text="service tftp (69/udp)"), one(kind="ufw", ports="TFTP"),
            one(protocol="udp", spans=((69, 69),), udp={"dnsmasq": {53, 67, 69}}), one(protocol="udp", spans=((69, 69),), udp={"in.tftpd": {69}})]
    assert {(g, n) for g, _, n in tftp} == {("system", "TFTP")}
    mail = [one(kind="firewalld", text="service smtp (25/tcp)"), one(kind="ufw", ports="Postfix"),
            one(protocol="tcp", spans=((587, 587),), listening={"master": {25, 587}})]
    assert {(g, n) for g, _, n in mail} == {("application", "Mail server")}
    # a name found for an application that is one of the system's is System's
    assert one(kind="ufw", ports="Bluetooth")[0::2] == ("system", "Bluetooth")
    assert one(kind="firewalld", text="service lldp")[0::2] == ("system", "LLDP")


def test_one_name_for_a_service_whichever_way_it_is_recognised():
    """firewalld's service, ufw's profile, the program listening on its port, the port alone: SSH is SSH every way."""
    ways = {  # a service: firewalld's service for it, ufw's profile, (the program listening, its port, protocol), a port alone
        "SSH": ("ssh", "OpenSSH", ("sshd", 22, "tcp"), 22),
        "DNS": ("dns", "Bind9", ("systemd-resolve", 53, "udp"), 53),
        "DHCP": ("dhcp", "DHCP", ("dhclient", 68, "udp"), 67),
        "DHCPv6": ("dhcpv6-client", "DHCPv6", ("dhclient", 546, "udp"), 546),
        "NTP": ("ntp", "NTP", ("chronyd", 123, "udp"), 123),
        "mDNS": ("mdns", "Bonjour", ("avahi-daemon", 5353, "udp"), 5353),
        "LLMNR": ("llmnr", "LLMNR", ("systemd-resolve", 5355, "udp"), 5355),
        "NetBIOS": ("netbios-ns", "NetBIOS", ("nmbd", 137, "udp"), 137),
        "Samba": ("samba", "Samba", ("smbd", 445, "tcp"), 445),
        "NFS": ("nfs", "NFS", ("rpc.mountd", 20048, "tcp"), 2049),
        "rpcbind": ("rpc-bind", "rpcbind", ("rpcbind", 111, "tcp"), 111),
        "Printing (CUPS)": ("ipp", "CUPS", ("cupsd", 631, "tcp"), 631),
        "Cockpit": ("cockpit", "Cockpit", ("systemd", 9090, "tcp"), 9090),  # systemd's socket: by the port
        "Kerberos": ("kerberos", "Kerberos KDC", ("krb5kdc", 88, "udp"), None),
        "LDAP": ("ldap", "LDAP", ("slapd", 389, "tcp"), None),
        "SNMP": ("snmp", "SNMP", ("snmpd", 161, "udp"), None),
        "Syslog": ("syslog", "Syslog", ("rsyslogd", 514, "udp"), None),
        "WSD": ("ws-discovery", "WSDD", ("wsdd", 3702, "udp"), None),
        "SSDP (UPnP)": ("ssdp", "SSDP", None, None),
        "TFTP": ("tftp", "TFTP", ("in.tftpd", 69, "udp"), None),
    }
    for name, (service, profile, listener, port) in ways.items():
        got = {"firewalld": one(kind="firewalld", text=f"service {service}"), "ufw": one(kind="ufw", ports=profile)}
        if listener:
            prog, p, proto = listener
            got["listening"] = one(protocol=proto, spans=((p, p),), **{"listening" if proto == "tcp" else "udp": {prog: {p}}})
        if port:
            got["port"] = one(spans=((port, port),))
        assert {way: (group, n) for way, (group, _, n) in got.items()} == {way: ("system", name) for way in got}, name
    # every name the tables give is the vocabulary's, and every port alone of the system's has one
    vocabulary = set(groups_mod.VOCABULARY)
    for names in (groups_mod.SYSTEM_SERVICES.values(), groups_mod.PROFILE_WORDS.values(), [n for _, n in groups_mod.PROFILE_PARTS],
                  [n for _, n in groups_mod.PROFILE_PHRASES], groups_mod.SYSTEM_PROGRAMS.values(), groups_mod.SERVICE_PORTS.values()):
        assert set(names) <= vocabulary
    assert set(groups_mod.SYSTEM_PORTS) <= set(groups_mod.SERVICE_PORTS) and groups_mod.BY_PORT <= set(groups_mod.SYSTEM_PROGRAMS)
    # on the recorded machines: SSH let in through firewalld's service (Fedora), or where sshd listens (the rest)
    for machine in RECORDED:
        cfg = parse(answer(FakeLinux(machine).sections))
        names = {sort_entry(e, cfg.system.listening, cfg.system.listening_udp).name for e in cfg.listed()
                 if e.direction == "in" and e.spans == ((22, 22),) and not e.source}
        assert names == {"SSH"}, machine


def test_find_finds_a_rule_by_its_headings_name_and_every_rule_of_one_is_listed():
    fw = plugin(FakeLinux("debian-13-nftables"))
    assert [r["cells"][6] for r in rules_of(fw, "own traffic")["rows"]] == ["ct state established,related accept", 'iifname "lo" accept']
    assert len(rules_of(fw, "invalid packets")["rows"]) == 1 and len(rules_of(fw, "this machine's")["rows"]) == 8
    # a program with hundreds of rules: every one of them listed under its heading
    fake = FakeLinux("debian-13-nftables")
    data = json.loads(fake.sections["nft"][1])
    data["nftables"] += [{"table": {"family": "ip", "name": "docker-extra", "handle": 50}},
                         {"chain": {"family": "ip", "table": "docker-extra", "name": "forward", "handle": 1, "type": "filter",
                                    "hook": "forward", "prio": 0, "policy": "accept"}}]
    data["nftables"] += [{"rule": {"family": "ip", "table": "docker-extra", "chain": "forward", "handle": 100 + i, "expr": [
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 20000 + i}}, {"accept": None}]}}
        for i in range(400)]
    fake.nft(data)
    docker = next(c for g in rules_of(plugin(fake))["groups"] if g["id"] == "application" for c in g["children"])
    assert (docker["title"], docker["count"], docker["listed"], "note" in docker) == ("Docker", 414, 414, False)
