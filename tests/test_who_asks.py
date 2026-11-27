"""Who may ask the plugin's changes (0.10.0, the review of PLT-H1's fix, 2026-11-24). Its changes as root are asked only
from its page (PAGE_ONLY_HOOKS, as liminal-libs 1.66.0's apps/asking.py and liminal-platform 0.34.0 read them): a rule
made or removed, a default policy, on and off, saving, Root access, nftables' install, and the base's allow and remove.
Another plugin's ask is refused, and so is an ask that names no one; over HTTP the platform also asks its login whether
you are at the page. Before, any program on this machine asked them with two headers, a second confirmation being only
an argument. The rules read again and the Rules table's two choices (refresh, show_rules, find_rules) are the page's
alone too (0.14.1; the user, 2026-11-26: "Yes, closed by default"); its other reads are asked by anyone, as before.
Asked through the library's own App (its ask, which names who asks as the platform's does), over a recorded machine
and a stand-in shell: nothing runs, no server is started."""
from __future__ import annotations

import pytest

from liminal_libs import internal
from liminal_libs.apps import App, asking
from liminal_libs.apps.authorization import EnvironmentLogin
from liminal_libs.machines import linux as linux_mod
from liminal_libs.machines.linux import Shell
from liminal_libs.machines.plugin import MachinePlugin

from plugin_platform_firewall_linux import LinuxFirewallPlugin

from machines import FakeLinux

CHANGES = ("allow", "remove", "make_rule", "remove_rule", "set_policy", "switch", "save_rules", "root_access",
           "install_nftables")
PAGE_READS = ("refresh", "show_rules", "find_rules")  # read again as root, the Rules table's choices: 0.14.1
PAGE_ASKS = {"refresh": (), "show_rules": ("all",), "find_rules": ("ssh",)}
READS = ("present", "status", "wanted", "netstat", "capture_unseen")
# 0.11.0: the base's other changes, and NetworkHost's (liminal-libs 1.96.0)
NETWORK_CHANGES = ("move_rules", "new_label", "rename_label", "remove_label", "hosts_recording", "hosts_forget",
                   "approve_plan", "grant_network", "revoke_network", "set_domain", "withdraw", "repoint",
                   "remove_leftover", "forget_records")
# 0.14.0 (liminal-libs 1.105.0): the World Wide Web tab's hooks (its GeoIP sources, data sets and the sgp4 package among
# them) are plugin-platform-worldwideweb's, none of them this plugin's: test_netstat.py


class Neighbour(MachinePlugin):
    """Another plugin of the platform, asking the firewall through its app as any plugin may (a container plugin, or
    the MCP plugin for a local agent)."""

    name, title = "neighbour", "Neighbour"

    def wants(self, hook, *args):
        """Not a hook: one of the firewall's asked through the app."""
        return self.app.ask("firewall-linux", hook, *args)


class Platform(App):
    """The library's App asking as the platform does: from its page's route, the page named in so many words, or from
    its own code, no one named."""

    NAME, TITLE, ICON = "platform", "Platform", "chip"

    def from_page(self, hook, *args):
        """As the page's route asks a hook."""
        with asking.asking(asking.PAGE):
            return self.ask("firewall-linux", hook, *args)

    def on_its_own(self, hook, *args):
        """As the app's own code asks a hook."""
        return self.ask("firewall-linux", hook, *args)


@pytest.fixture
def attached(monkeypatch):
    """The firewall on a recorded Ubuntu with ufw on, the platform root (nothing in front of a command, no password),
    attached with another plugin to an app; let go after."""
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 0, raising=False)
    fake = FakeLinux("ubuntu-24.04-ufw")
    fw, neighbour = LinuxFirewallPlugin(shell=Shell("local", runner=fake), native=""), Neighbour()
    app = Platform(log=lambda m: None, login=EnvironmentLogin(env={}))
    app.attach(fw)
    app.attach(neighbour)
    yield app, fw, neighbour, fake
    app.detach(neighbour.name)
    app.detach(fw.name)


def test_its_changes_and_the_rules_tables_choices_are_said_to_be_asked_only_from_its_page():
    fw = LinuxFirewallPlugin(shell=Shell("local", runner=FakeLinux("ubuntu-24.04-ufw")), native="")
    assert set(internal.page_only(fw)) == set(CHANGES) | set(NETWORK_CHANGES) | set(PAGE_READS)  # 0.11.0, 0.14.1
    assert set(PAGE_ASKS) == set(PAGE_READS)
    # what the platform reads; 0.14.0, liminal-libs 1.105.0: the base's three changes only the World Wide Web plugin asks
    kept = {"hosts_keep_route", "hosts_keep_places", "hosts_clear_places"}
    assert set(internal.plugin_only(fw)) == {"network_plan", "apply_network", "network_work", *kept}
    assert [p for p in internal.problems(fw) if "ONLY_HOOKS" in p] == []  # each a hook of its own, someone may ask it
    for hook in (*CHANGES, *PAGE_READS):
        assert asking.refusal(fw, hook, asking.PAGE) == ""
        assert asking.refusal(fw, hook, "neighbour") == (f"firewall-linux's {hook} is asked only from its page, "
                                                         "never by another plugin: neighbour asked it.")
        assert asking.refusal(fw, hook, None).endswith("This ask names no asker: neither the page nor a plugin.")
    for hook in READS:
        assert {asking.refusal(fw, hook, who) for who in (asking.PAGE, "neighbour", None)} == {""}


def test_another_plugin_or_no_one_asking_a_change_runs_nothing_and_its_page_does(attached):
    app, fw, neighbour, fake = attached
    for ask in (lambda: neighbour.wants("switch", "ufw", "off", True),  # ufw turned off, its second confirmation said
                lambda: app.on_its_own("switch", "ufw", "off", True),
                lambda: neighbour.wants("allow", "x", [5432], "tcp", "any"),  # a port open to everyone, never confirmed
                lambda: neighbour.wants("make_rule", "x", "in", "allow", "any", None, None, None, True),
                lambda: neighbour.wants("root_access", "off")):
        with pytest.raises(asking.AskRefused, match="is asked only from its page"):
            ask()
    for hook, args in PAGE_ASKS.items():  # Read again and the Rules table's choices: the page's alone
        for ask in (lambda: neighbour.wants(hook, *args), lambda: app.on_its_own(hook, *args)):
            with pytest.raises(asking.AskRefused, match=f"firewall-linux's {hook} is asked only from its page") as no:
                ask()
            assert no.value.status == 403 and no.value.hook == hook
    assert fake.calls == []  # not even read
    assert neighbour.wants("present") is True  # a read: answered as before
    assert app.from_page("show_rules", "all")["said"] == "showing all"
    assert app.from_page("find_rules", "ssh")["said"] == "finding 'ssh'"
    assert app.from_page("refresh")["said"].startswith("read again: ") and fake.calls and fake.changes == []
    assert app.from_page("switch", "ufw", "off", True)["said"] == "ufw turned off"
    assert fake.changes == [["ufw", "disable"]]


def test_no_hook_is_left_undeclared():
    """0.14.1, closed by default (liminal-libs 1.107.0): every hook it answers says who may ask it, so none is left to
    the default and the library's conformance has no warning. Its own are read from its words, so that part holds on
    an older library, whose bases may say less."""
    from liminal_libs.machines.firewall import Firewall
    from liminal_libs.machines.segments import NetworkHost
    from liminal_libs.sources import conformance

    fw = LinuxFirewallPlugin(shell=Shell("local", runner=FakeLinux("ubuntu-24.04-ufw")), native="")
    said = {h for word in ("READ_HOOKS", "SERVICE_HOOKS", "PLUGIN_ONLY_HOOKS", "PAGE_ONLY_HOOKS")
            for h in internal.declared(fw, word)} | {t.as_dict()["hook"] for t in fw.TABS}
    own = [h for h in fw.HOOKS if h not in (*Firewall.HOOKS, *NetworkHost.HOOKS)]
    assert set(own) >= {*PAGE_READS, "make_rule", "switch"} and [h for h in own if h not in said] == []
    assert not set(PAGE_READS) & set(internal.declared(fw, "READ_HOOKS"))  # none is opened again as a read
    warnings = getattr(conformance, "warnings", None)  # liminal-libs 1.107.0
    assert warnings is None or warnings(fw) == []
