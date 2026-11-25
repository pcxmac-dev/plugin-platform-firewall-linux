"""The Linux firewall plugin over recorded machines (tests/machines.py: a stand-in for this machine's commands, nothing
runs): its status and tables, its one read kept a minute and read again after each change, every change the page asks
(a rule made, a rule removed, a default policy, on and off, saved), the second confirmation for a change that can cut
SSH or open everything, the framework's own setup over the same read, and that it works only on the Linux the platform
runs on (a WSL distribution it runs inside too, its page saying what WSL changes): on Windows or macOS nothing runs at
all, nor for a distribution reached from Windows."""
from __future__ import annotations

import re
import sys

import pytest

from liminal_libs.machines import linux as linux_mod
from liminal_libs.machines.firewall import FirewallError, Rule
from liminal_libs.machines.linux import Shell, why_not_native
from liminal_libs.machines.plugin import CommandError

from plugin_platform_firewall_linux import MACHINE, READ_S, LinuxFirewallPlugin, rights
from plugin_platform_firewall_linux import netstat as netstat_mod
from plugin_platform_firewall_linux.changes import ACCEPT, Risky, Spec
from plugin_platform_firewall_linux.read import SCRIPT

from machines import SUDO, FakeLinux, answer

WANTED = [Rule("mail-example-test", ports=(25, 587), detail="the mail server container")]
APP = [8765, 8775, 8785, 8795]


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture(autouse=True)
def root(monkeypatch):
    """The platform runs as root here (no sudo in the commands); a test that wants otherwise says so."""
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 0, raising=False)


def plugin(fake, clock=None) -> LinuxFirewallPlugin:
    """The plugin on a native Linux machine (the test's word), its commands through the stand-in."""
    p = LinuxFirewallPlugin(shell=Shell("local", runner=fake), native="", clock=clock or Clock())
    p.wanted = lambda: list(WANTED)
    return p


def table(st: dict, title: str) -> dict:
    return next(t for t in st["tables"] if t["title"] == title)


def cells(t: dict) -> list:
    """A grouped table's rows as their cells (0.5.0: each row {cells, key, group, own, why})."""
    return [r["cells"] for r in t["rows"]]


def texts(rows) -> list:
    return [[c.get("text", c.get("title", "")) if isinstance(c, dict) else c for c in r] for r in rows]


def test_the_status_is_the_whole_configuration_as_tables_and_valid_whenever_read():
    fw = plugin(FakeLinux("debian-13-nftables"))
    st = fw.status()
    assert st["valid"] and st["why"] == "" and st["present"] and st.get("applies") is not False
    assert st["summary"] == "nftables 1.1.3: on; 22 rule(s) read, 0 of them Liminal's; Debian GNU/Linux 13 (trixie), systemd"
    assert [t["title"] for t in st["tables"]] == ["Firewall", "Interfaces", "Default policies", "Rules", "Sets"]
    assert [f["id"] for f in st["forms"]] == ["make", "remove", "find", "policy", "switch", "save", "label-new", "label-rename", "label-remove"]
    assert st["actions"] == [{"hook": "refresh", "args": [], "title": "Refresh", "note": "reads the whole configuration again now"}]
    assert "rules" not in st  # every rule is in the Rules table, Liminal's among them (its preset)
    parts = texts(table(st, "Firewall")["rows"])
    assert [r[0] for r in parts] == ["nftables", "iptables", "conntrack", "eBPF and XDP"] and parts[0][4:] == ["Turn off…", "Save…"]
    rules = table(st, "Rules")
    assert rules["options"][0]["hook"] == "show_rules" and rules["options"][0]["value"] == "in-allow"
    assert [a.get("form") or a.get("hook") for a in rules["actions"]] == ["make", "find", "refresh", "label-new"]
    assert len(rules["rows"]) == 6 and rules["note"].startswith("6 of 22 rules")
    ssh = next(r for r in cells(rules) if "tcp dport 22" in str(r[6]))
    assert ssh[8] == {"form": "remove", "title": "Remove…", "values": {"where": "inet filter input", "rule": 'tcp dport 22 counter accept comment "ssh"'},
                      "label": 'Remove tcp dport 22 counter accept comment "ssh"'}
    assert MACHINE.ICON == "wallfire"  # a brick wall with a flame before it, the user's picture (liminal-libs 1.34.0)
    assert set(MACHINE.HOOKS) >= {"refresh", "show_rules", "find_rules", "make_rule", "remove_rule", "set_policy", "switch", "save_rules"}
    hooks = fw.interface()["hooks"]
    assert all(f["hook"] in hooks for f in st["forms"])  # every form asks a hook the platform may ask
    # off is said, not invalid (the Windows firewall plugin's rule: valid whenever it can be read)
    off = plugin(FakeLinux("ubuntu-24.04-ufw", ufw_verbose="Status: inactive", ufw_numbered="Status: inactive")).status()
    assert off["valid"] and off["summary"].startswith("ufw 0.36.2 over nftables 1.0.9: off")


def test_one_read_kept_a_minute_refreshed_and_read_again_after_a_change(monkeypatch):
    fake, clock = FakeLinux("gentoo-openrc-nftables"), Clock()
    fw = plugin(fake, clock)
    fw.status(), fw.status(), fw.present()
    assert fake.reads == 1
    clock.now += READ_S + 1
    fw.status()
    assert fake.reads == 2
    assert fw.refresh()["said"].startswith("read again: nftables 1.1.5: on") and fake.reads == 3
    fw.make_rule("web", "in", "allow", "tcp", "8443")
    assert fake.reads == 4  # read fresh before the change
    fw.status()
    assert fake.reads == 5  # and again after it
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 1000, raising=False)  # not root: sudo -n, never a password asked
    fake2 = FakeLinux("gentoo-openrc-nftables")
    plugin(fake2).status()
    assert fake2.calls == [[*SUDO, "sh", "-c", SCRIPT]]


def test_presets_and_find():
    fw = plugin(FakeLinux("debian-13-nftables"))
    assert fw.show_rules("all") == {"said": "showing all"}
    assert len(cells(table(fw.status(), "Rules"))) == 22
    fw.show_rules("fwd")
    assert {r[1] for r in cells(table(fw.status(), "Rules"))} == {"forwarded", "NAT"}
    fw.show_rules("in-block")
    assert [r[6] for r in cells(table(fw.status(), "Rules"))] == ["ct state invalid drop", "ip saddr @blocked counter drop"]
    fw.show_rules("all")
    fw.find_rules("docker dnat")
    rows = cells(table(fw.status(), "Rules"))
    assert len(rows) == 1 and rows[0][7] == "Docker" and rows[0][8] == ""  # a program's own rule: no Remove
    fw.find_rules("9100")
    st = fw.status()
    assert [r[6]["text"] if isinstance(r[6], dict) else r[6] for r in cells(table(st, "Rules"))] == [
        'ip saddr 192.168.1.0/24 tcp dport 9100 accept comment "node exporter from the LAN"']
    assert any(a.get("hook") == "find_rules" and a["args"] == [""] for a in table(st, "Rules")["actions"])
    with pytest.raises(ValueError):
        fw.show_rules("everything")


def test_a_rule_made_through_each_front_end():
    # nftables: an allow before the chain's last word (a catch-all reject), a block at its head
    fake = FakeLinux("gentoo-openrc-nftables")
    fw = plugin(fake)
    out = fw.make_rule("web", "in", "allow", "tcp", "8443, 8444", "10.0.0.0/8")
    assert fake.changes == [["nft", "insert", "rule", "inet", "filter", "input", "handle", "9", "ip", "saddr", "10.0.0.0/8", "tcp", "dport",
                             "{", "8443, 8444", "}", "accept", "comment", '"liminal:web:tcp:8443,8444:10.0.0.0/8"']]
    assert out["said"].startswith("made in nftables' inet filter input: let tcp port 8443,8444 coming in from 10.0.0.0/8, as Liminal's web")
    fw.make_rule("spam", "in", "block", "tcp", "25", "203.0.113.0/24")
    assert fake.changes[-1] == ["nft", "insert", "rule", "inet", "filter", "input", "ip", "saddr", "203.0.113.0/24", "tcp", "dport", "25", "drop",
                                "comment", '"liminal:spam:tcp:25:203.0.113.0/24"']
    with pytest.raises(ValueError, match="there already"):
        fw.make_rule("mail-example-test", "in", "allow", "tcp", "2525")
    for bad in (("web site", "in", "allow", "tcp", "1"), ("web2", "in", "allow", "any", "22"), ("web3", "in", "allow", "tcp", "x"),
                ("web4", "in", "allow", "tcp", "22", "example.com"), ("web5", "up", "allow", "tcp", "22")):
        with pytest.raises(ValueError):
            fw.make_rule(*bad)
    # ufw
    fake = FakeLinux("ubuntu-24.04-ufw")
    plugin(fake).make_rule("office", "in", "allow", "tcp", "8443", "192.168.1.0/24", "eth0")
    assert fake.changes == [["ufw", "allow", "in", "on", "eth0", "proto", "tcp", "from", "192.168.1.0/24", "to", "any", "port", "8443",
                             "comment", "liminal:office"]]
    # firewalld: a service of Liminal's in the default zone, a rich rule for a network
    fake = FakeLinux("fedora-43-firewalld")
    plugin(fake).make_rule("office", "in", "allow", "tcp", "8443-8444", "10.1.0.0/16")
    assert fake.changes[0][:2] == ["sh", "-c"] and "--delete-service=liminal-office" in fake.changes[0][2]  # one left in no zone
    assert fake.changes[1:] == [["firewall-cmd", "--permanent", "--new-service=liminal-office"],
                            ["firewall-cmd", "--permanent", "--service=liminal-office",
                             "--set-description=made by the Liminal platform: let tcp port 8443-8444 coming in from 10.1.0.0/16"],
                            ["firewall-cmd", "--permanent", "--service=liminal-office", "--add-port=8443-8444/tcp"],
                            ["firewall-cmd", "--permanent", "--zone=FedoraServer",
                             '--add-rich-rule=rule family="ipv4" source address="10.1.0.0/16" service name="liminal-office" accept'],
                            ["firewall-cmd", "--reload"]]
    with pytest.raises(ValueError, match="what comes in to a zone"):
        plugin(FakeLinux("fedora-43-firewalld")).make_rule("dns", "out", "allow", "udp", "53")
    # iptables (legacy, Alpine): before nothing (INPUT drops by default: at its end), in iptables and ip6tables
    fake = FakeLinux("alpine-3.22-iptables")
    plugin(fake).make_rule("web", "in", "allow", "tcp", "80,443")
    assert fake.changes == [["iptables", "-t", "filter", "-A", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-m", "comment",
                             "--comment", "liminal:web", "-j", "ACCEPT"],
                            ["ip6tables", "-t", "filter", "-A", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-m", "comment",
                             "--comment", "liminal:web", "-j", "ACCEPT"]]
    fake = FakeLinux("alpine-3.22-iptables")
    plugin(fake).make_rule("one", "in", "reject", "udp", "161", "10.0.0.9")
    assert fake.changes == [["iptables", "-t", "filter", "-I", "INPUT", "1", "-s", "10.0.0.9", "-p", "udp", "--dport", "161", "-m", "comment",
                             "--comment", "liminal:one", "-j", "REJECT"]]


class Firewalld(FakeLinux):
    """A recorded firewalld machine whose saved services are kept: --new-service refuses a name there already
    (NAME_CONFLICT, as firewalld does), --delete-service removes one, the step clearing one left in no zone removes it
    when no zone uses it; `fail` answers the first command starting so with an error, once."""

    def __init__(self, fail=(), services=()):
        super().__init__("fedora-43-firewalld")
        self.saved, self.used, self.fail = set(services), set(), tuple(fail)

    def __call__(self, args, timeout):
        self.calls.append(list(args))
        cmd = args[len(SUDO):] if args[:len(SUDO)] == SUDO else list(args)
        if cmd[:2] == ["sh", "-c"] and cmd[2] == SCRIPT:
            self.reads += 1
            return 0, answer(self.sections), ""
        if self.fail and " ".join(cmd).startswith(" ".join(self.fail)):
            self.fail = ()
            return 1, "", "Error: INVALID_PORT"
        word = cmd[-1] if cmd else ""
        if cmd[:2] == ["sh", "-c"]:  # the leftover's clearing: what its script does, on this stand-in's state
            svc = re.search(r"--delete-service='?([a-z0-9-]+)", cmd[2]).group(1)
            if svc in self.saved and svc not in self.used:
                self.saved.discard(svc)
            return 0, "", ""
        if word.startswith("--new-service="):
            svc = word.split("=", 1)[1]
            if svc in self.saved:
                return 26, "", f"Error: NAME_CONFLICT: new_service(): '{svc}'"
            self.saved.add(svc)
        elif word.startswith("--delete-service="):
            self.saved.discard(word.split("=", 1)[1])
        elif word.startswith(("--add-service=", "--add-rich-rule=")):
            self.used.add(re.search(r"liminal-[a-z0-9-]+", word).group(0))
        elif word.startswith(("--remove-service=", "--remove-rich-rule=")):
            self.used.discard(re.search(r"liminal-[a-z0-9-]+", word).group(0))
        return 0, "", ""


def test_a_firewalld_rule_failing_part_way_is_taken_back_and_made_again():
    # the review of 2026-11-21, item 26: the service made first was left in no zone, unseen, its name refused for good
    fake = Firewalld(fail=("firewall-cmd", "--permanent", "--service=liminal-office", "--set-description"))
    fw = plugin(fake)
    with pytest.raises(CommandError, match=r"INVALID_PORT .*taken back as it failed part way: firewall-cmd --permanent "
                                           r"--delete-service=liminal-office"):
        fw.make_rule("office", "in", "allow", "tcp", "8443")
    assert fake.saved == set() and ["firewall-cmd", "--permanent", "--delete-service=liminal-office"] in fake.changes
    assert fw.make_rule("office", "in", "allow", "tcp", "8443")["said"].startswith("made in firewalld's zone FedoraServer")
    assert fake.saved == {"liminal-office"} and fake.used == {"liminal-office"}
    # one the zone's step had used, the reload failing: the zone's use taken back too, then the service
    fake = Firewalld(fail=("firewall-cmd", "--reload"))
    with pytest.raises(CommandError, match="INVALID_PORT"):
        plugin(fake).make_rule("office", "in", "allow", "tcp", "8443", "10.1.0.0/16")
    assert fake.saved == set() and fake.used == set()


def test_a_firewalld_service_of_liminals_left_in_no_zone_is_replaced_by_a_make_of_its_name():
    # one left by a make that failed before 0.9.2: the read cannot see it (no zone uses it), the make clears it first
    fake = Firewalld(services={"liminal-office"})
    plugin(fake).make_rule("office", "in", "allow", "tcp", "8443")
    assert fake.saved == {"liminal-office"} and fake.used == {"liminal-office"}
    script = fake.changes[0][2]
    assert "--info-service=liminal-office" in script and "--list-all-zones" in script and "--list-all-policies" in script
    assert "exit 1" in script.split("--delete-service")[0]  # never while firewalld's saved zones or policies name it
    # one in a zone not in force now is a rule of that name there already: refused before anything runs
    fake = Firewalld()
    zones = fake.sections["firewalld.zones"]
    fake.set("firewalld.zones", zones[1] + "\nidle\n  target: default\n  services: liminal-office\n")
    with pytest.raises(ValueError, match="there already"):
        plugin(fake).make_rule("office", "in", "allow", "tcp", "8443")
    assert fake.changes == []


def test_a_block_with_nowhere_to_go_makes_a_table_of_liminals_own_and_an_allow_with_nothing_dropping_is_not_needed():
    fake = FakeLinux("fedora-43-firewalld", firewalld_state=(252, "not running"))
    fake.sections = {k: v for k, v in fake.sections.items() if not k.startswith("firewalld")}
    fake.nft({"nftables": [{"metainfo": {"version": "1.1.3", "json_schema_version": 1}}]})
    fw = plugin(fake)
    with pytest.raises(ValueError, match="an allow changes nothing"):
        fw.make_rule("web", "in", "allow", "tcp", "443")
    fw.make_rule("telnet", "in", "block", "tcp", "23")
    assert fake.changes == [["nft", "add", "table", "inet", "liminal"],
                            ["nft", "add", "chain", "inet", "liminal", "input", "{", "type", "filter", "hook", "input", "priority", "0;", "policy",
                             "accept;", "}"],
                            ["nft", "insert", "rule", "inet", "liminal", "input", "tcp", "dport", "23", "drop", "comment", '"liminal:telnet:tcp:23:any"']]


def test_a_change_that_can_cut_ssh_or_open_everything_needs_a_second_confirmation():
    fake = FakeLinux("debian-13-nftables")
    fw = plugin(fake)
    with pytest.raises(Risky, match=r"drops SSH from everywhere \(sshd listens on 22; 1 SSH session is connected now\)") as e:
        fw.make_rule("no-ssh", "in", "block", "tcp", "22")
    assert e.value.accept == ACCEPT and isinstance(e.value, ValueError) and fake.changes == []
    fw.make_rule("no-ssh", "in", "block", "tcp", "22", accept_risk=True)
    assert fake.changes[-1][-3:] == ["drop", "comment", '"liminal:no-ssh:tcp:22:any"']
    with pytest.raises(Risky, match="every port of this machine"):
        fw.make_rule("all", "in", "allow", "any")
    with pytest.raises(Risky, match=r"framework's own pages \(8775\)"):
        fw.make_rule("platform", "in", "allow", "tcp", "8775")
    with pytest.raises(Risky, match="stops everything this machine sends"):
        fw.make_rule("silence", "out", "block", "any")
    # removing what lets SSH in, the replies in, loopback
    with pytest.raises(Risky, match="what lets SSH in"):
        fw.remove_rule("inet filter input", 'tcp dport 22 counter accept comment "ssh"')
    with pytest.raises(Risky, match="replies to this machine's own connections"):
        fw.remove_rule("inet filter input", "ct state established,related accept")
    with pytest.raises(Risky, match="loopback"):
        fw.remove_rule("inet filter input", 'iifname "lo" accept')
    fw.remove_rule("inet filter input", 'tcp dport 22 counter accept comment "ssh"', accept_risk=True)
    assert fake.changes[-1] == ["nft", "delete", "rule", "inet", "filter", "input", "handle", "10"]
    # a default letting everything in; dropping by default with nothing letting SSH in
    with pytest.raises(Risky, match="lets in by default"):
        fw.set_policy("inet filter input", "accept")
    gentoo_fake = FakeLinux("gentoo-openrc-nftables")
    plugin(gentoo_fake).set_policy("inet filter output", "drop")  # not inbound: no second confirmation
    assert gentoo_fake.changes == [["nft", "add", "chain", "inet", "filter", "output", "{", "policy", "drop;", "}"]]
    alpine = FakeLinux("alpine-3.22-iptables")
    alpine.set("iptables.save", "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -s 10.0.0.0/8 -m comment --comment own -j ACCEPT\nCOMMIT\n")
    alpine.set("ip6tables.save", "")
    with pytest.raises(Risky, match=r"No rule lets SSH in from everywhere \(sshd listens on 22; only from 10\.0\.0\.0/8\)"):
        plugin(alpine).set_policy("iptables filter INPUT", "DROP")


def test_a_rule_removed_where_it_is_and_never_a_programs():
    fake = FakeLinux("debian-13-nftables")
    fw = plugin(fake)
    out = fw.remove_rule("inet filter input", "tcp dport { 80, 443 } accept")
    assert fake.changes == [["nft", "delete", "rule", "inet", "filter", "input", "handle", "11"]] and "until the next restart unless saved" in out["said"]
    with pytest.raises(ValueError, match="Docker's own: Docker makes it again"):
        fw.remove_rule("nat POSTROUTING", "-s 172.17.0.0/16 ! -o docker0 -j MASQUERADE")
    with pytest.raises(LookupError, match="no longer there"):
        fw.remove_rule("inet filter input", "tcp dport 9999 accept")
    # ufw by its number now, firewalld from the zone at once and for good, iptables by the rule's own words
    fake = FakeLinux("ubuntu-24.04-ufw")
    plugin(fake).remove_rule("ufw", "80,443/tcp  ALLOW IN  Anywhere  # web")
    assert fake.changes == [["ufw", "--force", "delete", "2"]]
    fake = FakeLinux("fedora-43-firewalld")
    plugin(fake).remove_rule("zone FedoraServer", "port 8443/tcp")
    assert fake.changes == [["firewall-cmd", "--zone=FedoraServer", "--remove-port=8443/tcp"],
                            ["firewall-cmd", "--permanent", "--zone=FedoraServer", "--remove-port=8443/tcp"]]
    fake = FakeLinux("fedora-43-firewalld")
    rich = 'rule family="ipv4" source address="10.0.0.0/8" port port="9100" protocol="tcp" accept'
    plugin(fake).remove_rule("zone FedoraServer", rich)
    assert fake.changes[0] == ["firewall-cmd", "--zone=FedoraServer", f"--remove-rich-rule={rich}"]
    fake = FakeLinux("alpine-3.22-iptables")
    plugin(fake).remove_rule("filter INPUT", "-p icmp -j ACCEPT")
    assert fake.changes == [["iptables", "-t", "filter", "-D", "INPUT", "-p", "icmp", "-j", "ACCEPT"]]


def test_default_policies_on_and_off_and_saving_per_distribution():
    fake = FakeLinux("ubuntu-24.04-ufw")
    fw = plugin(fake)
    with pytest.raises(Risky):
        fw.set_policy("ufw incoming", "allow")
    fw.set_policy("ufw routed", "deny")
    assert fake.changes == [["ufw", "default", "deny", "routed"]]
    with pytest.raises(Risky, match="ufw stops filtering"):
        fw.switch("ufw", "off")
    fw.switch("ufw", "off", accept_risk=True)
    assert fake.changes[-1] == ["ufw", "disable"]
    with pytest.raises(ValueError, match="no default policy"):
        fw.set_policy("inet filter input", "drop")
    # firewalld: a zone's target for good, then reloaded; turned on and off through the init system
    fake = FakeLinux("fedora-43-firewalld")
    plugin(fake).set_policy("zone FedoraServer", "DROP")
    assert fake.changes == [["firewall-cmd", "--permanent", "--zone=FedoraServer", "--set-target=DROP"], ["firewall-cmd", "--reload"]]
    fake = FakeLinux("fedora-43-firewalld", firewalld_state=(252, "not running"))
    plugin(fake).switch("firewalld", "on")
    assert fake.changes == [["systemctl", "enable", "--now", "firewalld"]]
    # nftables saved by Gentoo's OpenRC service; Alpine's iptables and ip6tables by theirs; Debian's file, checked first
    fake = FakeLinux("gentoo-openrc-nftables")
    out = plugin(fake).save_rules("nftables")
    assert fake.changes == [["rc-service", "nftables", "save"]] and "/var/lib/nftables/rules-save" in out["said"]
    fake = FakeLinux("alpine-3.22-iptables")
    plugin(fake).save_rules("iptables")
    assert fake.changes == [["rc-service", "iptables", "save"], ["rc-service", "ip6tables", "save"]]
    fake = FakeLinux("debian-13-nftables")
    out = plugin(fake).save_rules("nftables")
    (script,) = fake.changes
    assert script[:2] == ["sh", "-c"] and "f=/etc/nftables.conf" in script[2] and "nft -s list table inet filter" in script[2]
    assert "ip nat" not in script[2] and 'nft -c -f "$new"' in script[2] and script[2].index("nft -c") < script[2].index('mv "$new"')
    assert "flush ruleset" in script[2] and out["said"].startswith("saved to /etc/nftables.conf (inet filter)")
    with pytest.raises(ValueError, match="keeps its rules itself"):
        plugin(FakeLinux("ubuntu-24.04-ufw")).save_rules("nftables")
    # an OpenRC service started and kept at boot
    fake = FakeLinux("gentoo-openrc-nftables")
    with pytest.raises(Risky, match="the nftables service flushes the whole ruleset"):
        plugin(fake).switch("nftables", "off")
    plugin(fake).switch("nftables", "off", accept_risk=True)
    assert fake.changes == [["rc-service", "nftables", "stop"], ["rc-update", "del", "nftables", "default"]]
    # ufw under OpenRC: on, and in the default runlevel so it starts at boot (Gentoo, Alpine)
    fake = FakeLinux("ubuntu-24.04-ufw", init="openrc init", ufw_verbose="Status: inactive", ufw_numbered="Status: inactive",
                     services="ufw yes stopped -")
    plugin(fake).switch("ufw", "on")
    assert fake.changes[-2:] == [["ufw", "--force", "enable"], ["rc-update", "add", "ufw", "default"]]


def test_a_failure_is_said_with_what_was_done_before_it(monkeypatch):
    fake = FakeLinux("fedora-43-firewalld")
    fake.replies[("firewall-cmd", "--permanent", "--zone=FedoraServer", "--remove-port=8443/tcp")] = (1, "", "Error: NOT_ENABLED: 8443:tcp")
    with pytest.raises(CommandError, match=r"NOT_ENABLED: 8443:tcp \(done before it: firewall-cmd --zone=FedoraServer --remove-port=8443/tcp\)"):
        plugin(fake).remove_rule("zone FedoraServer", "port 8443/tcp")
    fw = LinuxFirewallPlugin(shell=Shell("local", runner=lambda a, t: (1, "", "sudo: a password is required")), native="")
    st = fw.status()
    # 0.9.0: a read that fails leaves the plugin valid, with the read's words as its problem, where the Netstat tab is
    # served (B-revisions S2); not valid where it is not (no socket table to read, or a library from before the tab)
    if netstat_mod.library():
        assert st["valid"] and st["why"] == "" and "a password is required" in st["problem"]
    monkeypatch.setattr(netstat_mod, "tables_here", lambda: False)
    fw.forget()
    st = fw.status()
    assert not st["valid"] and st["why"].startswith("cannot be read:") and "a password is required" in st["why"]


def test_what_the_firewall_needs_is_said_when_it_cannot_be_read_or_there_is_none(monkeypatch):
    """0.8.1 (the user: "still need linux firewall"; found inside WSL's Ubuntu: sudo asks for a password there, and no
    firewall tool is installed). When the read is refused for want of root, or there is no firewall software, the page's
    tables say what the firewall needs here (root for the read, a firewall tool), each with what to do, and inside WSL
    what WSL changes after it. The tools are looked for by their files, without root: nothing runs but the read, through
    sudo -n, which never asks for a password.

    As 0.8.1 has it with a library from before the grant (liminal-libs 1.62.0), which is how 0.9.0 works there, its root
    row saying what the switch needs; with the grant, the plugin is valid there instead, and offers Root access and
    nftables' install (tests/test_rights.py)."""
    import types

    for name in rights.NAMES:
        monkeypatch.delattr(linux_mod, name, raising=False)
    monkeypatch.setattr(netstat_mod, "library", lambda: False)  # nor the Netstat tab (liminal-libs 1.65.0), later still
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 1000, raising=False)  # the platform is no root: sudo -n asks
    ran: list = []

    def refused(args, timeout):
        ran.append(args)
        return 1, b"", b"sudo: a password is required"
    looked: list = []
    fw = LinuxFirewallPlugin(shell=Shell("local", runner=refused), native="", which=lambda tool: looked.append(tool))
    st = fw.status()
    assert not st["valid"] and st["why"].startswith("cannot be read: sh needs root on this machine")
    needs = st["tables"][0]
    assert needs["title"] == "What the firewall needs here"
    assert [r[0] for r in needs["rows"]] == ["Root for the read", "A firewall tool", "Netstat and the hosts database"]
    assert needs["rows"][2][1] == "not in this library"  # 0.9.0 on a library from before its Netstat tab: said
    assert needs["rows"][0][1] == "sudo asks for a password" and "sudo -n, which never asks" in needs["rows"][0][2]
    assert needs["rows"][0][2].endswith(rights.old_words())
    assert f"needs liminal-libs {rights.NEEDS_LIBS}" in needs["rows"][0][2]  # the number set at landing, one place
    assert needs["rows"][1][1].startswith("none installed") and "apt install nftables (Debian, Ubuntu)" in needs["rows"][1][2]
    assert [c["title"] for c in needs["columns"]] == ["What", "Here", "What to do"] and len(st["tables"]) == 1
    assert looked == ["nft", "iptables", "ufw", "firewall-cmd"] and ran and all(a[:len(SUDO)] == SUDO for a in ran)
    nft = LinuxFirewallPlugin(shell=Shell("local", runner=refused), native="", which=lambda t: "/usr/sbin/nft" if t == "nft" else None)
    assert nft.status()["tables"][0]["rows"][1][1:] == ["nftables installed", "none needed"]
    under = {"title": "Under WSL", "note": "What running inside a WSL distribution changes for this plugin.",
             "columns": [{"title": "What"}, {"title": "Here"}, {"title": "What it means"}],
             "rows": [["Packet filter", "the kernel's own", "nftables and iptables work here once their tools are installed"]]}
    monkeypatch.setattr(linux_mod, "wsl_table", lambda kind, *a, **k: under if kind == "firewall" else None, raising=False)
    assert [t["title"] for t in fw.status()["tables"]] == ["What the firewall needs here", "Under WSL"]  # inside WSL
    # a read that failed otherwise: its own words, and the tool as found
    odd = LinuxFirewallPlugin(shell=Shell("local", runner=lambda a, t: (2, b"", b"sh: 1: Syntax error")), native="",
                              which=lambda t: None)
    assert odd.status()["tables"][0]["rows"][0][:2] == ["The read", "failed: sh: 1: Syntax error"]
    # no firewall software at all (the read ran, as root, and found none): the tool, what to do, and WSL's table
    monkeypatch.setattr(LinuxFirewallPlugin, "config", lambda self, fresh=False: types.SimpleNamespace(manager=""))
    bare = LinuxFirewallPlugin(shell=Shell("local", runner=refused), native="", which=lambda t: 1 / 0)  # not looked for
    st = bare.status()
    assert (st["present"], st["valid"], st["summary"]) == (False, False, "no firewall software here")
    assert [r[:2] for r in st["tables"][0]["rows"]] == [
        ["A firewall tool", "none installed: no nft, iptables, ufw or firewall-cmd here"],
        ["Netstat and the hosts database", "not in this library"]]
    assert [t["title"] for t in st["tables"]] == ["What the firewall needs here", "Under WSL"]


class Numbered(FakeLinux):
    """ufw's numbered rules as ufw keeps them: a rule deleted by its number, the ones after it numbered again."""

    def __init__(self, rows):
        super().__init__("ubuntu-24.04-ufw")
        self.rows = list(rows)
        self.show()

    def show(self):
        head = "Status: active\n\n     To                         Action      From\n     --                         ------      ----\n"
        self.set("ufw.numbered", head + "".join(f"[{i:2}] {r}\n" for i, r in enumerate(self.rows, 1)))

    def __call__(self, args, timeout):
        out = super().__call__(args, timeout)
        cmd = args[len(SUDO):] if args[:len(SUDO)] == SUDO else list(args)
        if cmd[:3] == ["ufw", "--force", "delete"] and cmd[3].isdecimal():
            del self.rows[int(cmd[3]) - 1]
            self.show()
        return out


def test_liminals_rule_removed_by_name_wherever_ufw_numbers_it_now():
    fake = Numbered(["22/tcp                     ALLOW IN    Anywhere",
                     "25,587/tcp                 ALLOW IN    Anywhere                   # liminal:mail-example-test",
                     "80/tcp                     ALLOW IN    Anywhere",
                     "22/tcp (v6)                ALLOW IN    Anywhere (v6)",
                     "25,587/tcp (v6)            ALLOW IN    Anywhere (v6)              # liminal:mail-example-test"])
    assert plugin(fake).remove("mail-example-test")
    assert fake.changes == [["ufw", "--force", "delete", "2"], ["ufw", "--force", "delete", "4"]]  # the v6 one was [5] before
    assert [r.split()[0] for r in fake.rows] == ["22/tcp", "80/tcp", "22/tcp"]


def test_the_frameworks_setup_over_the_same_read():
    # ufw off, sshd listening: SSH kept open first, then on; exposure found; the services' rules made
    fake = FakeLinux("ubuntu-24.04-ufw", ufw_verbose="Status: inactive", ufw_numbered="Status: inactive")
    fake.set("ufw.added", "Added user rules (see 'ufw status' for running firewall):\nufw allow from 10.0.0.0/8\n")
    fw = plugin(fake)
    done = fw.setup(log=lambda m: None)
    assert [(d["step"], d["ok"]) for d in done] == [("enable", True), ("exposure", None), ("rules", True)]
    assert fake.changes[:2] == [["ufw", "allow", "in", "proto", "tcp", "from", "any", "to", "any", "port", "22", "comment", "liminal:ssh"],
                                ["ufw", "--force", "enable"]]
    assert fake.changes[2] == ["ufw", "allow", "in", "proto", "tcp", "from", "any", "to", "any", "port", "25,587", "comment",
                               "liminal:mail-example-test"]
    # nftables: on already; the framework's pages exposed by a rule; the services' rule there already (Liminal's)
    fw = plugin(FakeLinux("gentoo-openrc-nftables"))
    done = fw.setup(log=lambda m: None)
    assert [(d["step"], d["ok"]) for d in done] == [("enable", None), ("exposure", True), ("rules", None)]
    assert done[0]["detail"] == "on: inet filter input" and "there already: Liminal: mail-example-test" in done[2]["detail"]
    assert fw.list_rules()[0].name == "mail-example-test" and fw.list_rules()[0].ports == (25, 587)
    assert fw.exposing(APP) == []
    # allow and remove: Liminal's own by name
    fake = FakeLinux("gentoo-openrc-nftables")
    fw = plugin(fake)
    assert fw.remove("mail-example-test") and fake.changes == [["nft", "delete", "rule", "inet", "filter", "input", "handle", "7"]]
    assert not fw.remove("nothing-of-that-name")
    with pytest.raises(FirewallError, match="there already"):
        fw.allow("mail-example-test", (25,))
    # nothing dropping: the rule is not needed, said as skipped
    fake = FakeLinux("fedora-43-firewalld")
    fake.sections = {k: v for k, v in fake.sections.items() if not k.startswith("firewalld")}
    fake.nft({"nftables": [{"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input",
                                      "prio": 0, "policy": "accept"}}, {"table": {"family": "inet", "name": "filter", "handle": 1}}]})
    out = plugin(fake).setup(log=lambda m: None)
    assert [(d["step"], d["ok"]) for d in out] == [("enable", None), ("exposure", None), ("rules", None)]
    assert "an allow changes nothing" in out[2]["detail"] and "no switch" in out[0]["detail"]


# What nft would have read as commands of their own (the review of PLT-H1's fix, 2026-11-24): it joins its words and
# parses them as one script, a ';' between commands, all run as one transaction
INJECTED = ("1.2.3.4 accept;flush ruleset;add table ip x;add chain ip x c;add rule ip x c", "fe80::1%a;b",
            "fe80::1%x accept;delete table inet filter", "10.0.0.0/8 accept", '10.0.0.1" accept', "example.com")


def test_the_frameworks_allow_reads_its_remote_as_the_forms_other_side_is_read():
    """0.10.0: the base's allow made its rule from its remote as it was given (add_rule), with no second confirmation,
    and nft read a ';' in it as the start of a command of its own, run as root. Now the remote is read as the Add a
    rule form's other side is (parse_address: "any" for anywhere, else written canonically) and anything else is a
    FirewallError before anything runs; a zone (its %) too, which ipaddress keeps as typed, in the form as well."""
    fake = FakeLinux("gentoo-openrc-nftables")
    fw = plugin(fake)
    for remote in INJECTED:
        with pytest.raises(FirewallError):
            fw.allow("web", (8443,), "tcp", remote)
    with pytest.raises(FirewallError, match="names a zone"):
        fw.allow("web", (8443,), "tcp", "fe80::1%eth0")
    for remote in INJECTED[1:3]:
        with pytest.raises(ValueError, match="names a zone"):
            fw.make_rule("web", "in", "allow", "tcp", "8443", remote)
    assert fake.changes == []  # nothing ran but the reads
    fw.allow("web", (8443,), "tcp", "10.1.2.3/8")  # written canonically, in the rule and its comment
    fw.allow("everyone", (8444,), "tcp", "any")
    assert fake.changes == [["nft", "insert", "rule", "inet", "filter", "input", "handle", "9", "ip", "saddr", "10.0.0.0/8",
                             "tcp", "dport", "8443", "accept", "comment", '"liminal:web:tcp:8443:10.0.0.0/8"'],
                            ["nft", "insert", "rule", "inet", "filter", "input", "handle", "9", "tcp", "dport", "8444",
                             "accept", "comment", '"liminal:everyone:tcp:8444:any"']]


def test_a_rules_words_are_checked_however_it_is_asked_for():
    """0.10.0: a Spec, what every plan to make a rule is made from, holds its name, its other side and its interface as
    the form's fields are read (NAME, parse_address, parse_interface), however it is made: a word that reaches a
    command unread is refused where it is made, before any plan."""
    good = {"name": "web", "direction": "in", "action": "allow", "protocol": "tcp", "spans": ((8443, 8443),),
            "source": "10.0.0.0/8", "interface": "eth0"}
    assert Spec(**good).words == "let tcp port 8443 coming in from 10.0.0.0/8 on eth0"
    assert Spec(**{**good, "source": "", "interface": ""}).words == "let tcp port 8443 coming in"
    for field, bad in [*(("source", r) for r in INJECTED), ("source", "any"), ("source", "10.1.2.3/8"),
                       ("source", None), ("interface", "eth0;x"), ("interface", "any"), ("name", "web;x"),
                       ("name", "Web")]:
        with pytest.raises(ValueError):
            Spec(**{**good, field: bad})


def test_only_the_linux_the_platform_runs_on_has_its_firewall_driven():
    """The user, 2026-11-08: "the scope of linux administration is only on native linux O/S"; "Yes, firewall too"; and
    2026-11-15: "wsl and firewall linux should always work under linux". On Windows or macOS no command runs at all, the
    status says why with applies False (the platform shows "Not for this machine", no setup), the setup and every command
    are refused (liminal-libs 1.27.0). A WSL distribution the platform runs inside is Linux like any other (the library's
    check decides, test_inside_wsl_its_page_says_what_wsl_changes_after_its_own_tables), and one reached from Windows is
    never driven."""
    windows = why_not_native("The Linux firewall", "win32", "10", {})
    macos = why_not_native("The Linux firewall", "darwin", "24.1.0", {})
    assert windows.startswith("The Linux firewall is for ") and "and this one runs Windows" in windows
    assert macos.startswith("The Linux firewall is for ") and macos.endswith("and this one runs macOS")
    if sys.platform == "win32":
        assert MACHINE.not_for_here() == windows and not MACHINE.present()  # this PC: asked nothing
    for note in (windows, macos):
        ran: list = []
        p = LinuxFirewallPlugin(shell=Shell("local", runner=lambda args, timeout: ran.append(args) or (0, b"", b"")), native=note)
        st = p.status()
        assert (st["present"], st["valid"], st["applies"], st["summary"], st["why"]) == (False, False, False, "not for this machine", note)
        assert "tables" not in st and "forms" not in st
        assert not p.present() and p.setup(log=lambda m: None) == [{"step": "enable", "ok": False, "detail": note}]
        for ask in (lambda: p.run("true"), lambda: p.allow("web", (8443,)), lambda: p.remove("web"), p.list_rules,
                    lambda: p.exposing([8765]), p.backend, p.state, p.refresh, lambda: p.make_rule("web", "in", "allow", "tcp", "1"),
                    lambda: p.remove_rule("x", "y"), lambda: p.set_policy("x", "y"), lambda: p.switch("ufw", "on"),
                    lambda: p.save_rules("nftables")):
            with pytest.raises(FirewallError, match="and this one runs"):
                ask()
        assert ran == []  # nothing ran anywhere
    from_windows = LinuxFirewallPlugin(shell=Shell("wsl:Liminal-Ubuntu", runner=lambda args, timeout: (0, b"", b"")), native="")
    with pytest.raises(FirewallError, match="is for the Linux the platform runs on, never WSL's Liminal-Ubuntu"):
        from_windows.run("true")


def test_inside_wsl_its_page_says_what_wsl_changes_after_its_own_tables(monkeypatch):
    """The user, 2026-11-15: "wsl and firewall linux should always work under linux, if wsl prevents or misses some
    capability this should reflect in the plugin". Inside a WSL distribution (the library's linux.wsl_table gives a
    table for a firewall: the packet filter WSL's kernel gives, WSL's network behind Windows) the status's tables end with
    it; none on a machine of its own, nor with a library from before it, nor when the check cannot say."""
    under = {"title": "Under WSL", "note": "What running inside a WSL distribution changes for this plugin.",
             "columns": [{"title": "What"}, {"title": "Here"}, {"title": "What it means"}],
             "rows": [["Network", "WSL's own, behind Windows", "Windows' firewall first"]]}
    asked: list = []
    monkeypatch.setattr(linux_mod, "wsl_table", lambda kind, *a, **k: asked.append(kind) or under, raising=False)
    p = plugin(FakeLinux("ubuntu-24.04-ufw"))
    st = p.status()
    assert st["valid"] and st["tables"][-1] is under and asked == ["firewall"]
    assert [t["title"] for t in st["tables"]].count("Under WSL") == 1
    monkeypatch.setattr(linux_mod, "wsl_table", lambda kind, *a, **k: None, raising=False)  # a machine of its own
    assert "Under WSL" not in [t["title"] for t in p.status()["tables"]]
    monkeypatch.setattr(linux_mod, "wsl_table", lambda kind, *a, **k: 1 / 0, raising=False)  # a check that cannot say
    assert "Under WSL" not in [t["title"] for t in p.status()["tables"]]
    monkeypatch.delattr(linux_mod, "wsl_table", raising=False)  # a library from before
    assert "Under WSL" not in [t["title"] for t in p.status()["tables"]]


def test_ipv6s_own_messages_kept_unless_accepted():
    fake = FakeLinux("fedora-43-firewalld")
    with pytest.raises(Risky, match="IPv6's own messages"):
        plugin(fake).remove_rule("policy allow-host-ipv6", 'rule family="ipv6" icmp-type name="neighbour-solicitation" accept')
    assert fake.changes == []
