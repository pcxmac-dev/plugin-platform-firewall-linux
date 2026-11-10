"""Rules there but turned off, shown as well (0.6.0; the user: "also rules that are turned off should be shown as well"),
over the recorded machines: ufw's rules while ufw is off, firewalld's while it is stopped, in a zone bound to nothing,
in the default zone while every interface in use is bound to another, or in a policy not in force, a dormant nftables
table's, one in a chain nothing jumps to. Each is listed under the group and name it has when on, passed to the page
marked off (shown dimmed), says why under its Where, is found and moved and removed like any other, and never stands for
a rule in force: a change's second confirmation, the exposure and the state are decided by the rules in force (a front
end's own, while it is off, for a change to that front end). Nothing runs here."""
from __future__ import annotations

import json

import pytest

from liminal_libs.apps.authorization import EnvironmentLogin
from liminal_libs.machines import linux as linux_mod
from liminal_libs.machines.linux import Shell

from plugin_platform_firewall_linux import LinuxFirewallPlugin
from plugin_platform_firewall_linux import firewalld as fwd
from plugin_platform_firewall_linux import nftables as nft
from plugin_platform_firewall_linux.changes import Risky
from plugin_platform_firewall_linux.groups import sort_entry
from plugin_platform_firewall_linux.read import _text_addresses as text_addresses
from plugin_platform_firewall_linux.system import Interface, parse_addresses

from machines import FakeLinux

UFW_OFF = {"ufw_verbose": "Status: inactive", "ufw_numbered": "Status: inactive"}
ZONE_OFF = {"text": "zone public (not active)", "sub": "firewalld, turned off: the zone is bound to nothing"}
ADDED = "Added user rules (see 'ufw status' for running firewall):\n"


@pytest.fixture(autouse=True)
def root(monkeypatch):
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 0, raising=False)


def plugin(fake) -> LinuxFirewallPlugin:
    return LinuxFirewallPlugin(shell=Shell("local", runner=fake), native="")


def rules(fw: LinuxFirewallPlugin, preset: str = "all") -> dict:
    fw.show_rules(preset)
    return next(t for t in fw.status()["tables"] if t["title"] == "Rules")


def text(row: dict) -> str:
    c = row["cells"][6]
    return c["text"] if isinstance(c, dict) else c


def accept(port: int, proto: str = "tcp") -> list:
    """An nftables rule's words letting `port` in: tcp dport PORT accept."""
    return [{"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "dport"}}, "right": port}}, {"accept": None}]


def with_nft(machine: str, *items, change=None) -> FakeLinux:
    """A recorded machine with nftables objects added to its ruleset (`change`: a function changing the ruleset first)."""
    fake = FakeLinux(machine)
    data = json.loads(fake.sections["nft"][1])
    if change:
        change(data)
    data["nftables"] += list(items)
    fake.nft(data)
    return fake


DORMANT = ({"table": {"family": "inet", "name": "staging", "handle": 9, "flags": ["dormant"]}},
           {"chain": {"family": "inet", "table": "staging", "name": "input", "handle": 1, "type": "filter", "hook": "input",
                      "prio": 10, "policy": "drop"}},
           {"rule": {"family": "inet", "table": "staging", "chain": "input", "handle": 2, "expr": accept(22)}})
SSH_IN_FORCE = ("inet filter input", 'tcp dport 22 counter accept comment "ssh"')  # Debian's, as recorded


def moved_to_public(ssh: bool = True) -> str:
    """Fedora's zones with enp1s0 bound to public, so the default zone FedoraServer takes no interface in use."""
    zones = FakeLinux("fedora-43-firewalld").sections["firewalld.zones"][1]
    zones = zones.replace("FedoraServer (default, active)", "FedoraServer (default)").replace("  interfaces: enp1s0\n", "  interfaces: \n", 1)
    return zones.replace("public\n  target: default", "public (active)\n  target: default").replace(
        "  interfaces: \n  sources: \n  services: dhcpv6-client mdns ssh",
        "  interfaces: enp1s0\n  sources: \n  services: dhcpv6-client mdns" + (" ssh" if ssh else ""))


def test_ufws_rules_while_it_is_off_are_listed_turned_off_in_every_preset():
    fw = plugin(FakeLinux("ubuntu-24.04-ufw", **UFW_OFF))
    every = rules(fw)
    assert len(every["rows"]) == 5 and all(r["off"] for r in every["rows"])
    assert every["rows"][0]["cells"][0] == {"text": "ufw (off)", "sub": "ufw, turned off: ufw is off"}
    assert every["note"].startswith("5 of 5 rules, 5 of them turned off (they filter nothing now)")
    assert [text(r) for r in rules(fw, "in-allow")["rows"]] == [
        "ufw allow 22/tcp", "ufw allow 80,443/tcp comment 'web'",
        "ufw allow proto tcp from any to any port 25,587 comment 'liminal:mail-example-test'", "ufw allow from 10.0.0.0/8"]
    assert [text(r) for r in rules(fw, "out")["rows"]] == ["ufw allow out 53/udp"]
    assert [text(r) for r in rules(fw, "liminal")["rows"]] == [
        "ufw allow proto tcp from any to any port 25,587 comment 'liminal:mail-example-test'"]
    assert "5 rule(s) read, 5 of them turned off, 1 of them Liminal's" in fw.status()["summary"]
    fw.show_rules("all")
    fw.find_rules("turned off")  # Find finds them by it
    assert len(next(t for t in fw.status()["tables"] if t["title"] == "Rules")["rows"]) == 5
    # on, none is turned off
    on = rules(plugin(FakeLinux("ubuntu-24.04-ufw")))
    assert len(on["rows"]) == 6 and not any(r.get("off") for r in on["rows"]) and "turned off" not in on["note"]


def test_a_zone_bound_to_nothing_is_listed_turned_off_and_never_stands_for_one_in_force():
    fake = FakeLinux("fedora-43-firewalld")
    fw = plugin(fake)
    off = [r for r in rules(fw)["rows"] if r.get("off")]
    assert [(r["cells"][0], text(r), r["group"], r["sub"]) for r in off] == [
        (ZONE_OFF, "service dhcpv6-client (546/udp)", "system", "system:dhcpv6"),
        (ZONE_OFF, "service mdns (5353/udp)", "system", "system:mdns"),
        (ZONE_OFF, "service ssh (22/tcp)", "system", "system:ssh")]
    assert [text(r) for r in rules(fw, "in-allow")["rows"] if r.get("off")] == [text(r) for r in off]  # in the presets too
    assert "11 rule(s) read, 3 of them turned off" in fw.status()["summary"]
    cfg = fw.config()
    assert (len(cfg.entries()), len(cfg.turned_off()), len(cfg.listed())) == (8, 3, 11)
    assert cfg.exposing([22]) == [(22, "firewalld's zone FedoraServer: service ssh (22/tcp)")]  # the zone in force alone
    # the zone in force's ssh is still what lets SSH in: the public zone's, turned off, does not stand for it
    with pytest.raises(Risky, match="what lets SSH in"):
        fw.remove_rule("zone FedoraServer", "service ssh (22/tcp)")
    assert fake.changes == []
    # removed from its zone as any of firewalld's rules (turned off, it cuts nothing: no second confirmation)
    out = fw.remove_rule("zone public (not active)", "service ssh (22/tcp)")
    assert fake.changes == [["firewall-cmd", "--zone=public", "--remove-service=ssh"],
                            ["firewall-cmd", "--permanent", "--zone=public", "--remove-service=ssh"]]
    assert out["said"] == "removed from firewalld's zone public: service ssh (22/tcp)"
    # moved as any other: kept through the login, its own group and name kept, still turned off
    login = EnvironmentLogin(env={})
    fw.login = login
    mdns = next(r for r in rules(fw)["rows"] if text(r) == "service mdns (5353/udp)")
    changed = len(fake.changes)
    assert fw.move_rules([mdns["key"]], "other")["said"] == "1 rule moved to Other"
    moved = next(r for r in rules(fw)["rows"] if r["key"] == mdns["key"])
    assert (moved["group"], moved["own"], moved.get("moved"), moved.get("off")) == ("other", "system", True, True)
    assert json.loads(login.env["FIREWALL_LINUX_GROUPS"])["moved"] == {"other": [mdns["key"]]}
    assert len(fake.changes) == changed  # nothing ran for the move


def test_a_move_is_kept_when_its_zone_comes_into_use():
    """A rule's key leaves out its zone's "(not active)": bound to an interface (a laptop's Wi-Fi connecting), the zone's
    rules keep the moves made while it was bound to nothing."""
    fake = FakeLinux("fedora-43-firewalld")
    fw = plugin(fake)
    login = EnvironmentLogin(env={})
    fw.login = login
    fw.new_label("Home")
    mdns = next(r for r in rules(fw)["rows"] if text(r) == "service mdns (5353/udp)")
    assert mdns["off"] and fw.move_rules([mdns["key"]], "Home")["said"] == "1 rule moved to Home"
    zones = fake.sections["firewalld.zones"][1].replace("public\n  target: default", "public (active)\n  target: default")
    fake.set("firewalld.zones", zones.replace("  interfaces: \n  sources: \n  services: dhcpv6-client mdns ssh",
                                              "  interfaces: wlan0\n  sources: \n  services: dhcpv6-client mdns ssh"))
    fw.forget()
    now = next(r for r in rules(fw)["rows"] if text(r) == "service mdns (5353/udp)")
    assert (now["key"], now["group"], now.get("off")) == (mdns["key"], "label:Home", None)
    assert now["cells"][0] == {"text": "zone public", "sub": "firewalld"}


def test_everything_of_firewalld_is_turned_off_while_it_is_stopped():
    fake = FakeLinux("fedora-43-firewalld", firewalld_state=(252, "not running"))
    fw = plugin(fake)
    every = rules(fw)
    assert len(every["rows"]) == 11 and all(r["off"] for r in every["rows"])
    assert {r["cells"][0]["sub"] for r in every["rows"]} == {"firewalld, turned off: firewalld is stopped"}
    assert fw.config().exposing([22]) == [] and fw.status()["summary"].startswith("firewalld 2.3.2 over nftables 1.1.3: off")
    # a change to firewalld while it is stopped is judged by its own rules, which filter again once it runs
    with pytest.raises(Risky, match="what lets SSH in once firewalld runs again"):
        fw.remove_rule("zone FedoraServer", "service ssh (22/tcp)")
    assert fw.set_policy("zone FedoraServer", "DROP")["said"] == "zone FedoraServer: default -> DROP"  # its ssh lets SSH in
    # the public zone's, bound to nothing, filters nothing once it runs either: removed with no second confirmation
    fw.remove_rule("zone public (not active)", "service ssh (22/tcp)")
    assert fake.changes == [["firewall-offline-cmd", "--zone=FedoraServer", "--set-target=DROP"],
                            ["firewall-offline-cmd", "--zone=public", "--remove-service=ssh"]]


def test_firewalld_zones_and_policies_in_force_or_listed_apart():
    pols = fwd.parse_blocks(
        "allow-host-ipv6 (active)\n  disable: no\n  target: CONTINUE\n  ingress-zones: ANY\n  egress-zones: HOST\n  rich rules: \n"
        "\trule family=\"ipv6\" icmp-type name=\"redirect\" accept\n"
        "gateway-lan-to-world (disabled)\n  disable: yes\n  target: ACCEPT\n  ingress-zones: internal home\n"
        "  egress-zones: external public\n  services: ftp tftp\n  rich rules: \n"
        "lan-to-host\n  disable: no\n  target: CONTINUE\n  ingress-zones: internal\n  egress-zones: HOST\n  services: ssh\n", policy=True)
    zones = fwd.parse_blocks("public (default)\n  target: default\n  services: ssh\nhome\n  target: default\n  services: mdns\n")
    services = {"ftp": ["21/tcp"], "tftp": ["69/udp"], "ssh": ["22/tcp"], "mdns": ["5353/udp"]}
    st = fwd.FirewalldState(installed=True, running=True, default_zone="public", zones=zones, policies=pols, services=services)
    # the default zone takes eth0, bound to no zone: in force, with the policy active and on
    takes = fwd.unbound(st, [Interface("lo", "unknown"), Interface("eth0", "up")])
    assert takes == ["eth0"]
    assert [(e.where, e.text, e.off) for e in fwd.entries(st, takes=takes)] == [
        ("zone public", "service ssh (22/tcp)", ""), ("policy allow-host-ipv6", 'rule family="ipv6" icmp-type name="redirect" accept', "")]
    resting = fwd.entries(st, resting=True, takes=takes)
    assert [(e.where, e.text, e.direction, e.off) for e in resting] == [
        ("zone home (not active)", "service mdns (5353/udp)", "in", "the zone is bound to nothing"),
        ("policy gateway-lan-to-world", "service ftp (21/tcp)", "fwd", "the policy is turned off"),
        ("policy gateway-lan-to-world", "service tftp (69/udp)", "fwd", "the policy is turned off"),
        ("policy lan-to-host", "service ssh (22/tcp)", "in", "its zones are not in use")]
    assert [(s.group, s.name) for s in map(sort_entry, resting)] == [
        ("system", "mDNS"), ("application", "FTP server"), ("system", "TFTP"), ("system", "SSH")]
    # every interface in use bound to another zone (one down, a container's end of its link, loopback aside): the
    # default zone takes none, and its rules are listed apart, turned off
    st.zones = fwd.parse_blocks("public (default)\n  target: default\n  services: ssh\n"
                                "home (active)\n  target: default\n  interfaces: eth0\n  services: mdns\n")
    takes = fwd.unbound(st, [Interface("lo", "unknown"), Interface("eth0", "up"), Interface("eth1", "down"),
                             Interface("veth1a2b", "up"), Interface("vnet0", "up")])
    assert takes == []
    # a bridge's or a bond's port carries what comes in through that one: the bridge counts, its port does not
    assert fwd.unbound(st, [Interface("br0", "up"), Interface("enp3s0", "up", master="br0")]) == ["br0"]
    assert parse_addresses('[{"ifname": "enp3s0", "operstate": "UP", "master": "br0", "addr_info": []}]')[0].master == "br0"
    assert text_addresses("3: enp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel master br0 state UP qlen 1000\n"
                          )[0]["master"] == "br0"
    assert [(e.where, e.text) for e in fwd.entries(st, takes=takes) if e.where.startswith("zone")] == [("zone home", "service mdns (5353/udp)")]
    assert [(e.where, e.off) for e in fwd.entries(st, resting=True, takes=takes) if e.where.startswith("zone")] == [
        ("zone public (not active)", "every interface in use is bound to another zone")]
    # the interfaces not read: the default zone takes none known, and says so
    assert fwd.unbound(st, []) is None
    assert fwd.off_of(st.zones[0], True, None) == "no interface is bound to it, and the interfaces could not be read"
    # stopped: nothing in force; what filters once it runs is listed first, turned off, the rest apart
    st.running = False
    assert [(e.where, e.off) for e in fwd.entries(st, takes=takes)] == [
        ("zone home", "firewalld is stopped"), ("policy allow-host-ipv6", "firewalld is stopped")]
    assert {e.off for e in fwd.entries(st, resting=True, takes=takes)} == {"firewalld is stopped"}


def test_the_default_zone_taking_no_interface_is_turned_off_and_stands_for_nothing():
    """firewalld uses the default zone only for what no other zone is bound to: with every interface in use bound to
    another zone, its rules filter nothing, so they never stand for a rule in force."""
    fake = FakeLinux("fedora-43-firewalld", firewalld_zones=moved_to_public())
    fw = plugin(fake)
    every = rules(fw)
    off = {"text": "zone FedoraServer (not active)", "sub": "firewalld, turned off: every interface in use is bound to another zone"}
    assert [text(r) for r in every["rows"] if r.get("off")] == [
        "service cockpit (9090/tcp)", "service dhcpv6-client (546/udp)", "service ssh (22/tcp)", "port 8443/tcp",
        "forward-port port=80:proto=tcp:toport=8080:toaddr=", 'rule family="ipv4" source address="10.0.0.0/8" port port="9100" protocol="tcp" accept']
    assert {json.dumps(r["cells"][0]) for r in every["rows"] if r.get("off")} == {json.dumps(off)}
    zones = next(t for t in fw.status()["tables"] if t["title"] == "Zones")
    assert next(r for r in zones["rows"] if isinstance(r[0], dict))[0] == {
        "text": "FedoraServer", "sub": "default; turned off: every interface in use is bound to another zone"}
    cfg = fw.config()
    assert cfg.exposing([22, 9090]) == [(22, "firewalld's zone public: service ssh (22/tcp)")]  # FedoraServer's: not in force
    with pytest.raises(Risky, match="what lets SSH in"):  # public's ssh is the one that lets SSH in
        fw.remove_rule("zone public", "service ssh (22/tcp)")
    fw.remove_rule("zone FedoraServer (not active)", "service ssh (22/tcp)")  # FedoraServer's cuts nothing
    # public without ssh: no rule in force lets SSH in, so its target set to DROP asks the second confirmation
    fw = plugin(FakeLinux("fedora-43-firewalld", firewalld_zones=moved_to_public(ssh=False)))
    with pytest.raises(Risky, match="No rule lets SSH in"):
        fw.set_policy("zone public", "DROP")
    # an interface in use bound to no zone (a VPN's): the default zone takes it, and its rules are in force again
    fake = FakeLinux("fedora-43-firewalld", firewalld_zones=moved_to_public(ssh=False))
    addr = json.loads(fake.sections["addr"][1]) + [{"ifname": "wg0", "operstate": "UNKNOWN", "addr_info": []}]
    fake.set("addr", json.dumps(addr))
    fw = plugin(fake)
    assert not any(r.get("off") for r in rules(fw)["rows"] if r["cells"][0]["text"].startswith("zone FedoraServer"))
    assert fw.set_policy("zone public", "DROP")["said"] == "zone public: default -> DROP"  # FedoraServer's ssh lets SSH in
    # the default zone accepting everything: an exposure through what it takes, and none while it takes nothing
    accepting = moved_to_public(ssh=False).replace("FedoraServer (default)\n  target: default", "FedoraServer (default)\n  target: ACCEPT")
    fake.set("firewalld.zones", accepting)
    assert (9090, "the zone FedoraServer accepts everything (wg0)") in plugin(fake).config().exposing([9090])
    assert plugin(FakeLinux("fedora-43-firewalld", firewalld_zones=accepting)).config().exposing([9090]) == []


def test_rules_turned_off_never_stand_for_ssh_let_in():
    # ufw installed but off, holding allow 22/tcp, beside nftables of this machine's own in charge
    fake = FakeLinux("debian-13-nftables", ufw_version="ufw 0.36.2", ufw_added=ADDED + "ufw allow 22/tcp\n", **UFW_OFF)
    fw = plugin(fake)
    assert fw.config().manager == "nftables" and [e.off for e in fw.config().listed() if e.kind == "ufw"] == ["ufw is off"]
    with pytest.raises(Risky, match="what lets SSH in"):
        fw.remove_rule(*SSH_IN_FORCE)
    assert fw.config().exposing([22]) == [(22, 'nftables inet filter input handle 10 (ssh)')]
    # ufw's own while it is off cuts nothing when removed (turning ufw on keeps SSH open first)
    fw.remove_rule("ufw (off)", "ufw allow 22/tcp")
    assert fake.changes == [["ufw", "--force", "delete", "allow", "22/tcp"]]
    # ufw's default set while it is off: its own rules count, as they filter once it is on
    off = FakeLinux("ubuntu-24.04-ufw", **UFW_OFF)
    assert plugin(off).set_policy("ufw incoming", "deny")["said"] == "ufw incoming: unset -> deny"
    off.set("ufw.added", ADDED + "ufw allow 80/tcp\n")
    with pytest.raises(Risky, match="No rule lets SSH in"):
        plugin(off).set_policy("ufw incoming", "deny")


def test_a_dormant_nftables_tables_rules_are_turned_off_and_filter_nothing():
    fake = with_nft("debian-13-nftables", *DORMANT)
    fw = plugin(fake)
    every = rules(fw)
    (row,) = [r for r in every["rows"] if r.get("off")]
    assert (text(row), row["cells"][0], row["group"], row["sub"]) == (
        "tcp dport 22 accept", {"text": "inet staging input", "sub": "nftables, turned off: its table is dormant"}, "system", "system:ssh")
    assert every["note"].startswith("23 of 23 rules, 1 of them turned off")
    cfg = fw.config()
    assert [c.key for c in cfg.input_chains()] == [c.key for c in cfg.own_filter_chains()] == ["inet filter input"]
    assert cfg.state() == {"enabled": True, "profiles": {"inet filter input": True}}
    assert cfg.exposing([22]) == [(22, "nftables inet filter input handle 10 (ssh)")]
    pol = next(t for t in fw.status()["tables"] if t["title"] == "Default policies")
    assert ["inet staging input", "this machine's", "drop", "filter input, priority 10; turned off: its table is dormant", ""] in pol["rows"]
    # the rule in force is still what lets SSH in; the dormant table's, removed, cuts nothing
    with pytest.raises(Risky, match="what lets SSH in"):
        fw.remove_rule(*SSH_IN_FORCE)
    fw.remove_rule("inet staging input", "tcp dport 22 accept")
    assert fake.changes == [["nft", "delete", "rule", "inet", "staging", "input", "handle", "2"]]
    assert nft.entries(nft.parse(fake.sections["nft"][1]))[0].off == ""  # the tables not dormant: in force

    # a default set to drop where only the dormant table's rule would let SSH in: the second confirmation
    def accepting(data):
        for o in data["nftables"]:
            if "chain" in o and (o["chain"]["family"], o["chain"]["table"], o["chain"]["name"]) == ("inet", "filter", "input"):
                o["chain"]["policy"] = "accept"
        data["nftables"] = [o for o in data["nftables"] if not ("rule" in o and o["rule"]["table"] == "filter" and o["rule"]["handle"] == 10)]

    with pytest.raises(Risky, match="No rule lets SSH in"):
        plugin(with_nft("debian-13-nftables", *DORMANT, change=accepting)).set_policy("inet filter input", "drop")


def test_a_rule_in_a_chain_nothing_jumps_to_is_turned_off():
    spare = ({"chain": {"family": "inet", "table": "filter", "name": "spare", "handle": 90}},
             {"rule": {"family": "inet", "table": "filter", "chain": "spare", "handle": 91, "expr": accept(2222)}})
    fw = plugin(with_nft("gentoo-openrc-nftables", *spare))
    (row,) = [r for r in rules(fw)["rows"] if r.get("off")]
    assert (text(row), row["cells"][0], row["cells"][1]) == (
        "tcp dport 2222 accept", {"text": "inet filter spare", "sub": "nftables, turned off: nothing jumps to its chain"}, "other")
    # jumped to from a chain in force, it is in force
    jump = {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 92, "expr": [{"jump": {"target": "spare"}}]}}
    assert not any(r.get("off") for r in rules(plugin(with_nft("gentoo-openrc-nftables", *spare, jump)))["rows"])
    # a table deciding through a verdict map declared apart: its chains may be reached through it, so none is said not to be
    by_map = {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 93, "expr": [
        {"vmap": {"key": {"payload": {"protocol": "ip", "field": "saddr"}}, "data": "@routes"}}]}}
    assert not any(r.get("off") for r in rules(plugin(with_nft("gentoo-openrc-nftables", *spare, by_map)))["rows"])
    # iptables: a chain of its own nothing jumps to
    fake = FakeLinux("alpine-3.22-iptables")
    fake.set("iptables.save", fake.sections["iptables.save"][1].replace(
        ":OUTPUT ACCEPT [0:0]\n", ":OUTPUT ACCEPT [0:0]\n:spare - [0:0]\n").replace("COMMIT", "-A spare -p tcp -m tcp --dport 2222 -j ACCEPT\nCOMMIT"))
    fw = plugin(fake)
    (row,) = [r for r in rules(fw)["rows"] if r.get("off")]
    assert (text(row), row["cells"][0]) == (
        "-p tcp -m tcp --dport 2222 -j ACCEPT", {"text": "filter spare", "sub": "iptables, turned off: nothing jumps to its chain"})
    assert fw.config().exposing([2222]) == []


def test_a_ufw_profile_as_added_keeps_its_name_while_ufw_is_off():
    fake = FakeLinux("ubuntu-24.04-ufw", **UFW_OFF)
    fake.set("ufw.added", ADDED + "ufw allow 'Nginx Full'\n")
    fw = plugin(fake)
    (nginx,) = fw.config().entries()
    assert (nginx.ports, nginx.spans, nginx.off, nginx.covers(22)) == ("Nginx Full", (), "ufw is off", False)
    (row,) = rules(fw)["rows"]
    assert (row["group"], row["sub"], row["off"]) == ("application", "application:nginx", True)
    # turned on: none of ufw's rules lets SSH in (a profile's ports not read are not every port), so SSH is kept open first
    fw.switch("ufw", "on")
    assert fake.changes == [["ufw", "allow", "in", "proto", "tcp", "from", "any", "to", "any", "port", "22", "comment", "liminal:ssh"],
                            ["ufw", "--force", "enable"]]
    # removed by its own words, the profile's name one word
    fw.remove_rule("ufw (off)", "ufw allow 'Nginx Full'")
    assert fake.changes[-1] == ["ufw", "--force", "delete", "allow", "Nginx Full"]
    # the full form names its profile after `app`
    fake.set("ufw.added", ADDED + "ufw allow from 10.0.0.0/8 to any app OpenSSH\n")
    fw.forget()
    (ssh,) = fw.config().entries()
    assert (ssh.ports, ssh.spans, ssh.source) == ("OpenSSH", ((22, 22),), "10.0.0.0/8")
    assert (sort_entry(ssh).group, sort_entry(ssh).name) == ("system", "SSH")
