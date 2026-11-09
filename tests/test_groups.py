"""The rules in groups (0.5.0; the user: "for both firewalls, i need to have groups, like system or application and then
unassociated rules not tied to a specific application or system process can be in an other, i can create labels, like
system or application, as well and move the rules in to that"), over the recorded machines: each rule sorted by whose it
is, what it is for, the service or profile it names and the program listening on its port; the user's labels and moves
kept through the platform's login (a stand-in's variables here), never in the firewall: no command runs for a move."""
from __future__ import annotations

import json

import pytest

from liminal_libs.apps.authorization import EnvironmentLogin
from liminal_libs.machines import linux as linux_mod
from liminal_libs.machines.linux import Shell

from plugin_platform_firewall_linux import LinuxFirewallPlugin
from plugin_platform_firewall_linux.groups import key, sort_entry
from plugin_platform_firewall_linux.model import Entry
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
