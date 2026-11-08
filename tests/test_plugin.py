"""The Linux firewall plugin over recorded machines (tests/machines.py: a stand-in for this machine's commands, nothing
runs): its status and tables, its one read kept a minute and read again after each change, every change the page asks
(a rule made, a rule removed, a default policy, on and off, saved), the second confirmation for a change that can cut
SSH or open everything, the framework's own setup over the same read, and that it works only on a native Linux
machine: on Windows, macOS or in a WSL distribution nothing runs at all."""
from __future__ import annotations

import sys

import pytest

from liminal_libs.machines import linux as linux_mod
from liminal_libs.machines.firewall import FirewallError, Rule
from liminal_libs.machines.linux import Shell, why_not_native
from liminal_libs.machines.plugin import CommandError

from plugin_platform_firewall_linux import MACHINE, READ_S, LinuxFirewallPlugin
from plugin_platform_firewall_linux.changes import ACCEPT, Risky
from plugin_platform_firewall_linux.read import SCRIPT

from machines import FakeLinux

WANTED = [Rule("mail-example-test", ports=(25, 587), detail="the mail server container")]
APP = [8765, 8775, 8785, 8795, 8796]


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


def texts(rows) -> list:
    return [[c.get("text", c.get("title", "")) if isinstance(c, dict) else c for c in r] for r in rows]


def test_the_status_is_the_whole_configuration_as_tables_and_valid_whenever_read():
    fw = plugin(FakeLinux("debian-13-nftables"))
    st = fw.status()
    assert st["valid"] and st["why"] == "" and st["present"] and st.get("applies") is not False
    assert st["summary"] == "nftables 1.1.3: on; 22 rule(s) read, 0 of them Liminal's; Debian GNU/Linux 13 (trixie), systemd"
    assert [t["title"] for t in st["tables"]] == ["Firewall", "Interfaces", "Default policies", "Rules", "Sets"]
    assert [f["id"] for f in st["forms"]] == ["make", "remove", "find", "policy", "switch", "save"]
    assert st["actions"] == [{"hook": "refresh", "args": [], "title": "Refresh", "note": "reads the whole configuration again now"}]
    assert "rules" not in st  # every rule is in the Rules table, Liminal's among them (its preset)
    parts = texts(table(st, "Firewall")["rows"])
    assert [r[0] for r in parts] == ["nftables", "iptables", "conntrack", "eBPF and XDP"] and parts[0][4:] == ["Turn off…", "Save…"]
    rules = table(st, "Rules")
    assert rules["options"][0]["hook"] == "show_rules" and rules["options"][0]["value"] == "in-allow"
    assert [a.get("form") or a.get("hook") for a in rules["actions"]] == ["make", "find", "refresh"]
    assert len(rules["rows"]) == 6 and rules["note"].startswith("6 of 22 rules")
    ssh = next(r for r in rules["rows"] if "tcp dport 22" in str(r[6]))
    assert ssh[8] == {"form": "remove", "title": "Remove…", "values": {"where": "inet filter input", "rule": 'tcp dport 22 counter accept comment "ssh"'},
                      "label": 'Remove tcp dport 22 counter accept comment "ssh"'}
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
    assert fake2.calls == [["sudo", "-n", "sh", "-c", SCRIPT]]


def test_presets_and_find():
    fw = plugin(FakeLinux("debian-13-nftables"))
    assert fw.show_rules("all") == {"said": "showing all"}
    assert len(table(fw.status(), "Rules")["rows"]) == 22
    fw.show_rules("fwd")
    assert {r[1] for r in table(fw.status(), "Rules")["rows"]} == {"forwarded", "NAT"}
    fw.show_rules("in-block")
    assert [r[6] for r in table(fw.status(), "Rules")["rows"]] == ["ct state invalid drop", "ip saddr @blocked counter drop"]
    fw.show_rules("all")
    fw.find_rules("docker dnat")
    rows = table(fw.status(), "Rules")["rows"]
    assert len(rows) == 1 and rows[0][7] == "Docker" and rows[0][8] == ""  # a program's own rule: no Remove
    fw.find_rules("9100")
    st = fw.status()
    assert [r[6]["text"] if isinstance(r[6], dict) else r[6] for r in table(st, "Rules")["rows"]] == [
        'ip saddr 192.168.1.0/24 tcp dport 9100 accept comment "node exporter from the LAN"']
    assert any(a.get("hook") == "find_rules" and a["args"] == [""] for a in table(st, "Rules")["actions"])
    with pytest.raises(ValueError):
        fw.show_rules("everything")


def test_a_rule_made_through_each_front_end():
    # nftables: an allow before the chain's last word (a catch-all reject), a block at its head
    fake = FakeLinux("gentoo-openrc-nftables")
    fw = plugin(fake)
    out = fw.make_rule("web", "in", "allow", "tcp", "8443, 8444", "10.0.0.0/8")
    assert fake.changes == [["nft", "insert", "rule", "inet", "filter", "input", "position", "9", "ip", "saddr", "10.0.0.0/8", "tcp", "dport",
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
    assert fake.changes == [["firewall-cmd", "--permanent", "--new-service=liminal-office"],
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
    gentoo = plugin(FakeLinux("gentoo-openrc-nftables"))
    gentoo.set_policy("inet filter output", "drop")  # not inbound, SSH's replies are its own state: no second confirmation
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


def test_a_failure_is_said_with_what_was_done_before_it():
    fake = FakeLinux("fedora-43-firewalld")
    fake.replies[("firewall-cmd", "--permanent", "--zone=FedoraServer", "--remove-port=8443/tcp")] = (1, "", "Error: NOT_ENABLED: 8443:tcp")
    with pytest.raises(CommandError, match=r"NOT_ENABLED: 8443:tcp \(done before it: firewall-cmd --zone=FedoraServer --remove-port=8443/tcp\)"):
        plugin(fake).remove_rule("zone FedoraServer", "port 8443/tcp")
    fw = LinuxFirewallPlugin(shell=Shell("local", runner=lambda a, t: (1, "", "sudo: a password is required")), native="")
    st = fw.status()
    assert not st["valid"] and st["why"].startswith("cannot be read:") and "a password is required" in st["why"]


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
        cmd = args[2:] if args[:2] == ["sudo", "-n"] else list(args)
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


def test_only_a_native_linux_machine_has_its_firewall_driven():
    """The user, 2026-11-08: "the scope of linux administration is only on native linux O/S"; "it's not for
    administrating WSL instances"; "Yes, firewall too": on Windows, macOS or in a WSL distribution no command runs at
    all, the status says why with applies False (the platform shows "Not for this machine", no setup), the setup and
    every command are refused (liminal-libs 1.27.0)."""
    windows = why_not_native("The Linux firewall", "win32", "10", {})
    wsl = why_not_native("The Linux firewall", "linux", "6.18.54.1-microsoft-standard-WSL2", {"WSL_DISTRO_NAME": "Liminal-Ubuntu"})
    assert windows.startswith("The Linux firewall is for a native Linux machine, and this one runs Windows")
    assert wsl.endswith("this is WSL's Liminal-Ubuntu on Windows")
    if sys.platform == "win32":
        assert MACHINE.not_for_here() == windows and not MACHINE.present()  # this PC: asked nothing
    for note in (windows, wsl):
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
            with pytest.raises(FirewallError, match="native Linux machine"):
                ask()
        assert ran == []  # nothing ran anywhere
    in_wsl = LinuxFirewallPlugin(shell=Shell("wsl:Liminal-Ubuntu", runner=lambda args, timeout: (0, b"", b"")), native="")
    with pytest.raises(FirewallError, match="never WSL's Liminal-Ubuntu"):
        in_wsl.run("true")


def test_ipv6s_own_messages_kept_unless_accepted():
    fake = FakeLinux("fedora-43-firewalld")
    with pytest.raises(Risky, match="IPv6's own messages"):
        plugin(fake).remove_rule("policy allow-host-ipv6", 'rule family="ipv6" icmp-type name="neighbour-solicitation" accept')
    assert fake.changes == []
