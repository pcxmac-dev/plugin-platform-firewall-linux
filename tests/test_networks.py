"""Services' networks through this firewall (0.11.0; liminal-libs 1.96.0's NetworkHost; service-containers-networking
§5.4 to §5.7, decision 20 b, N9 and N10, SERVICE-INTERFACE.md §9's "wsl"): the plugin over a recorded Ubuntu (its `ip`
answers recorded too), attached to the library's App beside the library's stand-in container plugin and a stand-in
service plugin; inside WSL (it owns the stack "wsl") and on a machine of its own (the limit). Nothing runs on this
machine: every command is the stand-in's, and the root script it would have run is kept."""
from __future__ import annotations

import pytest

from liminal_libs.apps import App, asking
from liminal_libs.instances import Refusal
from liminal_libs.machines import segments as S
from liminal_libs.machines import standins
from liminal_libs.machines.linux import Shell

from machines import SUDO, FakeLinux
from plugin_platform_firewall_linux import LinuxFirewallPlugin
from plugin_platform_firewall_linux import network as N

DIG = "sha256:" + "a" * 64
ADDR = ("1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 192.168.1.20/24 brd 192.168.1.255 scope global eth0\n"
        "3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\n")
ROUTES = ("default via 192.168.1.1 dev eth0 proto dhcp\n192.168.1.0/24 dev eth0 proto kernel scope link\n"
          "172.17.0.0/16 dev docker0 proto kernel scope link\n")
LINKS = "1: lo: <LOOPBACK,UP>\n2: eth0: <UP>\n3: docker0: <UP>\n"


class Fake(FakeLinux):
    """The recorded Ubuntu, its ip answers, and the scripts given to sh -s on standard input (root's)."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.replies.update({("ip", "-4", "-o", "addr"): (0, ADDR, ""), ("ip", "-4", "route"): (0, ROUTES, ""),
                             ("ip", "-o", "link"): (0, LINKS, "")})
        self.root_scripts: list[str] = []

    def __call__(self, args, timeout, stdin=None):
        cmd = args[len(SUDO):] if args[:len(SUDO)] == SUDO else list(args)
        if cmd[:2] == ["sh", "-s"]:
            self.calls.append(list(args))
            self.root_scripts.append(stdin or "")
            return 0, "", ""
        return super().__call__(args, timeout)


class Frame(App):
    NAME = "frame"

    def __init__(self, login):
        super().__init__(log=lambda m: None, login=login)

    def disabled(self):
        return set()


def spec():
    return {"owner": "jenkins", "name": "ci", "title": "Jenkins", "system": "linux", "parts": [{
        "name": "controller",
        "image": {"ref": "docker.io/jenkins/jenkins:2.528.2-lts-jdk21", "digest": DIG, "system": "linux",
                  "platforms": ["linux/amd64"], "size": 300_000_000, "licence": "MIT", "tar": True},
        "ports": [{"name": "web", "container": 8080, "host": 8080, "lan": True, "about": "its pages"}],
        "volumes": [{"name": "home", "path": "/var/jenkins_home", "holds": "its jobs", "owner": 1000}],
        "memory": 2 << 30, "health": {"port": "web", "path": "/login", "ready_s": 30}}]}


class World:
    def __init__(self, tmp_path, wsl="Ubuntu", domain="home.arpa", own_engine=True):
        self.fake = Fake("ubuntu-24.04-ufw")
        self.app = Frame(standins.login({S.DOMAIN_VAR: domain} if domain else {}))
        self.fw = LinuxFirewallPlugin(shell=Shell("local", runner=self.fake), native="", book=S.MemoryBook(),
                                      platform="linux::TEST", wsl=wsl)
        self.fw._change_wants_password = lambda: False  # Root access on: sudo -n runs it
        self.fw.__dict__["_own_engine"] = own_engine
        out = standins.Outside(sleep=lambda s: None, health=lambda h, p, path: True, platform="linux::TEST",
                               folder=tmp_path)
        stack = "wsl" if wsl else "linux"
        t = standins.target("ubuntu", stack=stack, firewall="linux", wsl="", wsl_plugin="")
        self.host = standins.StandInHost({"ubuntu": (t, standins.FakeDocker())}, outside=out)
        self.jenkins = standins.ServiceOwner("jenkins")
        for p in (self.fw, self.host, self.jenkins):
            self.app.attach(p)

    def page(self, plugin, hook, *args):
        with asking.asking(asking.PAGE):
            return self.app.ask(plugin, hook, *args)

    def grant(self):
        self.page("standin-host", "grant_service", "jenkins", "ubuntu")
        self.page("firewall-linux", "grant_network", "standin-host")

    def wait(self, work):
        w = self.host._svc.works.get(work)
        w.thread.join(20)
        assert not w.thread.is_alive()
        return self.jenkins.call("service_work", work, 0)


def test_inside_wsl_it_owns_wsls_stack_from_the_linux_half_and_writes_no_limit(tmp_path):
    w = World(tmp_path)
    got = w.fw.network_host()
    assert got["own"] == "wsl" and got["routes_to"] == [] and got["half"] == S.HALVES["linux"]
    w.grant()
    done = standins.conformance(w.jenkins, w.page, spec(), "ubuntu", w.wait)
    assert done[-1] == "conformance"
    assert all("iptables" not in s and "nft " not in s for s in w.fake.root_scripts)  # N9: nothing written for it
    assert w.fw.resolve_name("controller.jenkins-ci.linux.home.arpa")["addresses"] == []  # delete_data forgot it


def test_on_a_machine_of_its_own_the_limit_keeps_published_ports_to_your_subnets(tmp_path):
    w = World(tmp_path, wsl="")
    assert w.fw.network_host()["own"] == "linux"
    w.grant()
    plan = w.jenkins.call("service_plan", "install", "jenkins/ci", spec(), "ubuntu", {})
    for a in plan["approve"]:
        words = w.page(a["plugin"], "plan_words", a["plan"])
        names = {x["name"] for x in words["accepts"]}
        w.page(a["plugin"], "approve_plan", a["plan"], *[k in names for k in words["approve_args"]])
    assert w.wait(w.jenkins.call("apply_plan", plan["plan"])["work"])["ok"]
    (script,) = w.fake.root_scripts
    mark = "'liminal:svc-jenkins-ci-8080 platform=linux::TEST'"
    lines = [x.strip() for x in script.splitlines()]
    assert lines[0] == "set -e" and "if iptables -nL DOCKER-USER >/dev/null 2>&1; then" in lines
    assert (f"iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL -m comment --comment "
            f"{mark} -j DROP") in lines
    assert (f"iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 8080 --ctdir ORIGINAL --ctorigsrc "
            f"192.168.1.0/24 -m comment --comment {mark} -j RETURN") in lines
    assert lines.index(next(x for x in lines if "ESTABLISHED,RELATED" in x)) > lines.index(
        next(x for x in lines if "-j DROP" in x))  # inserted last: the first rule DOCKER-USER holds
    assert any("nft add chain inet liminal svc-forward '{ type filter hook forward priority -1; policy accept; }'" in x
               for x in lines)
    assert not any("172.17." in x for x in lines)  # never an engine's bridge as one of your subnets
    end = w.jenkins.call("service_plan", "remove", "jenkins/ci", None, "", {})
    for a in end["approve"]:
        w.page(a["plugin"], "approve_plan", a["plan"])
    w.wait(w.jenkins.call("apply_plan", end["plan"])["work"])
    assert "grep -F -- " + mark in w.fake.root_scripts[-1] and "-j DROP" not in w.fake.root_scripts[-1]


def test_inside_wsl_beside_another_distributions_engine_a_change_is_asked_twice(tmp_path):
    w = World(tmp_path, own_engine=False)
    w.grant()
    plan = w.jenkins.call("service_plan", "install", "jenkins/ci", spec(), "ubuntu", {})
    fw_plan = next(a["plan"] for a in plan["approve"] if a["plugin"] == "firewall-linux")
    words = w.page("firewall-linux", "plan_words", fw_plan)
    assert "accept_shared" in {x["name"] for x in words["accepts"]} and "docker0" in words["words"] + str(words["accepts"])
    with pytest.raises(Refusal, match="WSL's network is shared"):
        w.page("firewall-linux", "approve_plan", fw_plan, True, False, False)
    assert w.page("firewall-linux", "approve_plan", fw_plan, True, True, False)["ok"]


def test_a_nested_segment_is_routed_through_the_instance_it_sits_behind(tmp_path):
    w = World(tmp_path)
    w.grant()
    want = {"stack": "wsl", "target": "ubuntu", "network": "liminal-jenkins-ci", "parts": ["controller"],
            "behind": "10.77.128.5"}
    plan = w.host.ask_plugin("firewall-linux", "network_plan", "install", "jenkins/ci", want)
    assert plan["routes"][0]["next_hop"] == "10.77.128.5"
    script = N.steps_script([S.Step("route", "", plan["routes"][0])])
    assert f"ip route replace {plan['subnet']} via 10.77.128.5" in script


def test_with_no_domain_set_no_service_is_placed(tmp_path):
    w = World(tmp_path, domain="")
    w.grant()
    with pytest.raises(Refusal, match="Networks tab"):
        w.jenkins.call("service_plan", "install", "jenkins/ci", spec(), "ubuntu", {})
    assert w.fake.root_scripts == []


def test_a_change_needing_your_password_is_refused_before_anything_runs(tmp_path):
    w = World(tmp_path, wsl="")
    w.fw._change_wants_password = lambda: True
    with pytest.raises(Refusal, match="Root access"):
        w.fw.run_steps([S.Step("route", "", {"prefix": "10.77.129.0/24", "next_hop": "10.77.128.5"})],
                       lambda line: None, lambda: False)
    assert w.fake.root_scripts == []


def test_the_templates_take_only_what_they_parse():
    for kind, d in (("route", {"prefix": "0.0.0.0/0", "next_hop": "10.77.128.5"}),
                    ("route", {"prefix": "10.77.129.0/24", "next_hop": "8.8.8.8"}),
                    ("unroute", {"prefix": "192.168.1.0/24"}),
                    ("proxy", {"limit": True, "host": 8080, "rule": "svc-a-8080", "subnets": ["0.0.0.0/0"]}),
                    ("proxy", {"limit": True, "host": 8080, "rule": "x'; reboot", "subnets": ["192.168.1.0/24"]}),
                    ("proxy", {"limit": True, "host": 8080, "rule": "svc-a-8080", "subnets": []})):
        with pytest.raises((Refusal, ValueError)):
            N.step_script(S.Step(kind, "", d))


def test_a_script_holding_what_liminal_never_writes_is_refused(monkeypatch):
    for word in N.NEVER:
        monkeypatch.setattr(N, "step_script", lambda s, w=word: f"{w} x")
        with pytest.raises(Refusal, match="never writes"):
            N.steps_script([S.Step("route", "", {})])


def test_reads_change_nothing(tmp_path):
    w = World(tmp_path, wsl="")
    w.grant()
    for hook in ("network_host", "leases", "name_records", "container_networks", "leftovers"):
        w.jenkins.call(hook, plugin="firewall-linux")
    assert w.fake.root_scripts == [] and not any(c[:len(SUDO)] == SUDO and "ip" in c for c in w.fake.calls)


def test_on_windows_it_runs_nothing(tmp_path):
    fake = Fake("ubuntu-24.04-ufw")
    fw = LinuxFirewallPlugin(shell=Shell("local", runner=fake), native="not Linux", book=S.MemoryBook())
    with pytest.raises(Refusal, match="not for this machine"):
        fw.networks_here()
    assert fake.calls == []
