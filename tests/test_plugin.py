"""The Linux firewall plugin over ufw, firewalld and nftables: which one it finds, its status, its setup (on with
SSH kept open, exposure, the services' rules), Liminal's rules made and removed and no other touched, all
through a stand-in for the commands in a WSL distribution (nothing runs here)."""
from __future__ import annotations

import json

import pytest

from liminal_libs.machines.firewall import Rule
from liminal_libs.machines.linux import Shell

import plugin_platform_firewall_linux as fl
from plugin_platform_firewall_linux import MACHINE, DETECT, SSH_LISTENING, LinuxFirewallPlugin, NoFirewall, Nft, Ufw, Firewalld, nft_view, spans

WANTED = [Rule("mail-example-test", ports=(25, 587), detail="the mail server container")]
APP = [8765, 8775, 8785, 8795, 8796]


class FakeLinux:
    """Answers the commands a WSL distribution would, for one firewall: ufw, firewalld, nft or none."""

    def __init__(self, backend="ufw", active=False, ssh=False):
        self.backend = backend
        self.calls: list[list[str]] = []
        self.ssh = ssh
        # ufw
        self.active = active
        self.added = [{"spec": "allow 22/tcp", "comment": ""}]
        self.numbered = ""
        # firewalld
        self.running = active
        self.services = {"ssh": ["22/tcp"], "cockpit": ["9090/tcp"], "dhcpv6-client": ["546/udp"]}
        self.zone_services = {"ssh", "dhcpv6-client"}
        self.rich: list[str] = []
        self.ports: list[str] = []
        self.target = "default"
        self.reloads = 0
        # nft
        self.items = []
        self.handle = 10

    def __call__(self, args, timeout):
        self.calls.append(list(args))
        cmd = args[args.index("--") + 1:] if "--" in args else args
        if cmd == ["sh", "-c", DETECT]:
            return 0, {"ufw": "ufw", "firewalld": "firewalld", "nft": "nft"}.get(self.backend, "none") + "\n", ""
        if cmd == ["sh", "-c", SSH_LISTENING]:
            return 0, ("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n" if self.ssh else ""), ""
        if cmd[0] == "ufw":
            return self.ufw(cmd)
        if cmd[0] in ("firewall-cmd", "firewall-offline-cmd"):
            return self.firewalld(cmd)
        if cmd[:3] == ["systemctl", "enable", "--now"]:
            self.running = True
            return 0, "", ""
        if cmd[0] == "nft":
            return self.nft(cmd)
        return 0, "ran\n", ""

    def ufw(self, cmd):
        if cmd == ["ufw", "status"]:
            return 0, f"Status: {'active' if self.active else 'inactive'}\n", ""
        if cmd == ["ufw", "show", "added"]:
            lines = ["Added user rules (see 'ufw status' for running firewall):"]
            lines += [f"ufw {a['spec']}" + (f" comment '{a['comment']}'" if a["comment"] else "") for a in self.added]
            return 0, "\n".join(lines) + "\n", ""
        if cmd == ["ufw", "status", "numbered"]:
            return 0, self.numbered, ""
        if cmd == ["ufw", "--force", "enable"]:
            self.active = True
            return 0, "Firewall is active and enabled on system startup\n", ""
        if cmd[:3] == ["ufw", "--force", "delete"]:
            spec = " ".join(cmd[3:])
            self.added = [a for a in self.added if a["spec"] != spec]
            return 0, "Rule deleted\n", ""
        if cmd[1] in ("allow", "deny") and cmd[-2] == "comment":
            self.added.append({"spec": " ".join(cmd[1:-2]), "comment": cmd[-1]})
            return 0, "Rules updated\n", ""
        return 1, "", f"ufw: unknown {cmd}\n"

    def firewalld(self, cmd):
        if cmd[0] == "firewall-cmd" and cmd[1:] == ["--state"]:
            return (0, "running\n", "") if self.running else (252, "not running\n", "")
        if cmd[0] == "firewall-cmd" and not self.running and cmd[1:] != ["--reload"]:
            return 252, "", "FirewallD is not running\n"
        a = cmd[1:]
        if a == ["--get-default-zone"]:
            return 0, "public\n", ""
        if a == ["--reload"]:
            self.reloads += 1
            return 0, "success\n", ""
        if a[-1] == "--list-services":
            return 0, " ".join(sorted(self.zone_services)) + "\n", ""
        if a == ["--permanent", "--get-services"]:
            return 0, " ".join(sorted(self.services)) + "\n", ""
        if a[-1] == "--list-rich-rules":
            return 0, "\n".join(self.rich) + ("\n" if self.rich else ""), ""
        if a[-1] == "--list-ports":
            return 0, " ".join(self.ports) + "\n", ""
        if a[-1] == "--get-target":
            return 0, self.target + "\n", ""
        if a[0].startswith("--info-service="):
            name = a[0].split("=", 1)[1]
            return 0, f"{name}\n  ports: {' '.join(self.services.get(name, []))}\n", ""
        if len(a) >= 2 and a[1].startswith("--new-service="):
            self.services[a[1].split("=", 1)[1]] = []
            return 0, "success\n", ""
        if len(a) >= 3 and a[1].startswith("--service="):
            name = a[1].split("=", 1)[1]
            if a[2].startswith("--add-port="):
                self.services[name].append(a[2].split("=", 1)[1])
            if a[2] == "--get-ports":
                return 0, " ".join(self.services.get(name, [])) + "\n", ""
            return 0, "success\n", ""
        if len(a) >= 3 and a[2].startswith("--add-service="):
            self.zone_services.add(a[2].split("=", 1)[1])
            return 0, "success\n", ""
        if len(a) >= 3 and a[2].startswith("--remove-service="):
            self.zone_services.discard(a[2].split("=", 1)[1])
            return 0, "success\n", ""
        if len(a) >= 3 and a[2].startswith("--add-rich-rule="):
            self.rich.append(a[2].split("=", 1)[1])
            return 0, "success\n", ""
        if len(a) >= 3 and a[2].startswith("--remove-rich-rule="):
            self.rich.remove(a[2].split("=", 1)[1])
            return 0, "success\n", ""
        if len(a) >= 2 and a[1].startswith("--delete-service="):
            self.services.pop(a[1].split("=", 1)[1], None)
            return 0, "success\n", ""
        return 1, "", f"firewall-cmd: unknown {cmd}\n"

    def nft(self, cmd):
        if cmd == ["nft", "-j", "list", "ruleset"]:
            return 0, json.dumps({"nftables": [{"metainfo": {"version": "1.0.9"}}, *self.items]}), ""
        if cmd[:3] == ["nft", "insert", "rule"]:
            family, table, chain = cmd[3:6]
            rest = cmd[6:]
            comment = rest[rest.index("comment") + 1].strip('"')
            ports = [int(w.strip("{},")) for w in rest[rest.index("dport") + 1:rest.index("accept")] if w.strip("{},").isdecimal()]
            self.handle += 1
            self.items.append({"rule": {"family": family, "table": table, "chain": chain, "handle": self.handle, "comment": comment,
                                        "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": rest[rest.index("dport") - 1], "field": "dport"}},
                                                            "right": {"set": ports} if len(ports) > 1 else ports[0]}}, {"accept": None}]}})
            return 0, "", ""
        if cmd[:3] == ["nft", "delete", "rule"]:
            handle = int(cmd[-1])
            self.items = [i for i in self.items if not ("rule" in i and i["rule"]["handle"] == handle)]
            return 0, "", ""
        return 1, "", f"nft: unknown {cmd}\n"


def plugin(fake) -> LinuxFirewallPlugin:
    p = LinuxFirewallPlugin(shell=Shell("wsl:Ubuntu", runner=fake))
    p.wanted = lambda: list(WANTED)
    return p


def test_the_plugin_its_target_and_the_firewall_it_finds(monkeypatch):
    assert MACHINE.name == "firewall-linux" and MACHINE.KIND == "machine" and MACHINE.options == ("FIREWALL_LINUX_TARGET",)
    monkeypatch.setenv("FIREWALL_LINUX_TARGET", "wsl:Ubuntu")
    assert LinuxFirewallPlugin().shell.target == "wsl:Ubuntu" and LinuxFirewallPlugin().shell.where == "WSL's Ubuntu"
    for backend, kind in (("ufw", Ufw), ("firewalld", Firewalld), ("nft", Nft), ("none", NoFirewall)):
        assert isinstance(plugin(FakeLinux(backend)).driver(), kind)
    none = plugin(FakeLinux("none"))
    assert not none.present() and none.status()["summary"] == "not present"
    assert spans("Anywhere") is None and spans("25,587/tcp") == [(25, 25), (587, 587)] and spans("8000:8100/tcp (v6)") == [(8000, 8100)]
    assert spans("OpenSSH") == []


def test_ufw_turned_on_with_ssh_kept_open_exposure_found_and_the_services_rules_added():
    fake = FakeLinux("ufw", active=False, ssh=True)
    fake.numbered = ("Status: active\n\n     To                         Action      From\n     --                         ------      ----\n"
                     "[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
                     "[ 2] 8765/tcp                   ALLOW IN    Anywhere                   # someone\n"
                     "[ 3] Anywhere                   ALLOW IN    10.0.0.0/8\n"
                     "[ 4] 8775/tcp                   ALLOW IN    127.0.0.1\n"
                     "[ 5] 8780:8790/tcp              ALLOW IN    Anywhere\n")
    fw = plugin(fake)
    assert fw.status()["summary"] == "ufw on WSL's Ubuntu: off (ufw off); 0 Liminal rule(s)"
    done = fw.setup(log=lambda m: None)
    assert [(d["step"], d["ok"]) for d in done] == [("enable", True), ("exposure", False), ("rules", True)]
    cmds = [c[c.index("--") + 1:] for c in fake.calls]
    ssh_rule = cmds.index(["ufw", "allow", "proto", "tcp", "from", "any", "to", "any", "port", "22", "comment", "liminal:ssh"])
    assert ssh_rule < cmds.index(["ufw", "--force", "enable"])  # SSH kept open before the firewall goes up
    assert ["ufw", "allow", "proto", "tcp", "from", "any", "to", "any", "port", "25,587", "comment", "liminal:mail-example-test"] in cmds
    assert all(c[:5] == ["wsl", "-d", "Ubuntu", "-u", "root"] for c in fake.calls)
    hits = fw.exposing(APP)
    assert {p for p, _ in hits} == set(APP) and any("[3] Anywhere from 10.0.0.0/8" in label for _, label in hits)
    assert not any("[4]" in label for _, label in hits) and (8785, "ufw rule [5] 8780:8790/tcp from Anywhere") in hits
    assert {r.name for r in fw.list_rules()} == {"ssh", "mail-example-test"}
    mail = next(r for r in fw.list_rules() if r.name == "mail-example-test")
    assert mail.ports == (25, 587) and mail.protocol == "tcp" and mail.owned
    assert fw.remove("mail-example-test") and not fw.remove("mail-example-test")
    assert {"spec": "allow 22/tcp", "comment": ""} in fake.added  # another's rule left alone
    theirs = Ufw.rule_of("allow 22/tcp", "")
    assert (theirs.owned, theirs.ports, theirs.protocol) == (False, (22,), "tcp")


def test_firewalld_services_rich_rules_reload_and_exposure():
    fake = FakeLinux("firewalld", active=True)
    fw = plugin(fake)
    done = fw.setup(log=lambda m: None, steps=("enable", "rules"))
    assert [(d["step"], d["ok"]) for d in done] == [("enable", None), ("rules", True)]
    assert fake.services["liminal-mail-example-test"] == ["25/tcp", "587/tcp"] and "liminal-mail-example-test" in fake.zone_services and fake.reloads == 1
    (mine,) = fw.list_rules()
    assert (mine.name, mine.ports, mine.protocol) == ("mail-example-test", (25, 587), "tcp")
    fw.allow("office", (8443,), remote="10.1.0.0/16")
    assert any('source address="10.1.0.0/16" service name="liminal-office" accept' in r for r in fake.rich)
    assert {r.name for r in fw.list_rules()} == {"mail-example-test", "office"}
    assert fw.remove("office") and fake.rich == [] and "liminal-office" not in fake.services
    assert fw.remove("mail-example-test") and "liminal-mail-example-test" not in fake.zone_services and "ssh" in fake.zone_services
    fake.zone_services.add("cockpit")
    fake.ports = ["8765/tcp"]
    fake.rich = ['rule family="ipv4" source address="127.0.0.1" port port="8775" protocol="tcp" accept',
                 'rule family="ipv4" source address="10.1.1.1" port port="8785" protocol="tcp" accept']
    hits = fw.exposing(APP)
    assert (8765, "the port 8765/tcp in the zone public") in hits and any(p == 8785 for p, _ in hits) and not any(p == 8775 for p, _ in hits)
    fake.target = "ACCEPT"
    assert {p for p, _ in fw.exposing(APP)} == set(APP)
    off = FakeLinux("firewalld", active=False)
    fw_off = plugin(off)
    assert fw_off.status()["enabled"] is False and fw_off.list_rules() == []  # read through firewall-offline-cmd
    assert any(c[c.index("--") + 1] == "firewall-offline-cmd" for c in off.calls)
    assert fw_off.setup(log=lambda m: None, steps=("enable",))[0]["ok"] is True and off.running


def test_nftables_rules_by_comment_no_switch_and_what_filters():
    fake = FakeLinux("nft")
    chain = {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}}
    rule = lambda h, expr, comment=None: {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": h, "expr": expr,  # noqa: E731
                                                   **({"comment": comment} if comment else {})}}
    dport = lambda right: {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": right}}  # noqa: E731
    fake.items = [chain,
                  rule(2, [{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"accept": None}]),
                  rule(3, [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}}, {"accept": None}]),
                  rule(4, [dport(22), {"accept": None}]),
                  rule(5, [dport({"set": [8765, {"range": [8770, 8780]}]}), {"accept": None}], "someone"),
                  rule(6, [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "127.0.0.1"}},
                           dport(8785), {"accept": None}])]
    fw = plugin(fake)
    st = fw.status()
    assert st["enabled"] and st["profiles"] == {"inet filter input": True} and st["summary"].startswith("nftables on WSL's Ubuntu: on")
    done = fw.setup(log=lambda m: None)
    assert [(d["step"], d["ok"]) for d in done] == [("enable", None), ("exposure", False), ("rules", True)]
    assert done[0]["detail"] == "on: inet filter input" and "charts (8765)" in done[1]["detail"] and "platform (8775)" in done[1]["detail"] and "8785" not in done[1]["detail"]
    insert = next(c[c.index("--") + 1:] for c in fake.calls if "insert" in c)
    assert insert == ["nft", "insert", "rule", "inet", "filter", "input", "tcp", "dport", "{", "25,", "587", "}", "accept", "comment",
                      '"liminal:mail-example-test:tcp:25,587:any"']
    (mine,) = fw.list_rules()
    assert (mine.name, mine.ports, mine.protocol, mine.remote) == ("mail-example-test", (25, 587), "tcp", "any")
    assert fw.remove("mail-example-test") and fw.list_rules() == [] and len(fake.items) == 6
    assert nft_view([dport(22), {"accept": None}]) == (True, False, [(22, 22)]) and nft_view([{"accept": None}]) == (True, False, None)
    # nothing filtering: no rule needed, said as skipped
    bare = FakeLinux("nft")
    bare.items = [{"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "hook": "input", "policy": "accept"}}]
    out = plugin(bare).setup(log=lambda m: None)
    assert [(d["step"], d["ok"]) for d in out] == [("enable", None), ("exposure", None), ("rules", None)] and "no rule is needed" in out[2]["detail"]
    assert "no switch" in out[0]["detail"]
