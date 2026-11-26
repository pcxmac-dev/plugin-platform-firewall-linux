"""Who may ask the plugin's changes (0.10.0, the review of PLT-H1's fix, 2026-11-24). Its changes as root are asked only
from its page (PAGE_ONLY_HOOKS, as liminal-libs 1.66.0's apps/asking.py and liminal-platform 0.34.0 read them): a rule
made or removed, a default policy, on and off, saving, Root access, nftables' install, and the base's allow and remove.
Another plugin's ask is refused, and so is an ask that names no one; over HTTP the platform also asks its login whether
you are at the page. Before, any program on this machine asked them with two headers, a second confirmation being only
an argument. Its reads are asked by anyone, as before. Asked through the library's own App (its ask, which names who
asks as the platform's does), over a recorded machine and a stand-in shell: nothing runs, no server is started."""
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
READS = ("present", "status", "refresh", "show_rules", "find_rules", "wanted", "world", "netstat")
# 0.11.0: the base's other changes, and NetworkHost's (liminal-libs 1.96.0)
NETWORK_CHANGES = ("move_rules", "new_label", "rename_label", "remove_label", "hosts_recording", "hosts_forget",
                   "world_watching", "world_geoip", "world_asn", "world_layer_get", "world_layer_remove",
                   "approve_plan", "grant_network", "revoke_network", "set_domain", "withdraw", "repoint",
                   "remove_leftover", "forget_records",
                   # 0.12.0: the base's GeoIP sources, their file's download, use and removal (liminal-libs 1.101.0)
                   "world_geoip_get", "world_geoip_use", "world_geoip_remove")


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


def test_its_changes_are_said_to_be_asked_only_from_its_page_and_its_reads_by_anyone():
    fw = LinuxFirewallPlugin(shell=Shell("local", runner=FakeLinux("ubuntu-24.04-ufw")), native="")
    assert set(internal.page_only(fw)) == set(CHANGES) | set(NETWORK_CHANGES)  # 0.11.0
    assert set(internal.plugin_only(fw)) == {"network_plan", "apply_network", "network_work"}  # what the platform reads
    assert [p for p in internal.problems(fw) if "ONLY_HOOKS" in p] == []  # each a hook of its own, someone may ask it
    for hook in CHANGES:
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
    assert fake.calls == []  # not even read
    assert neighbour.wants("present") is True  # a read: answered as before
    assert app.from_page("switch", "ufw", "off", True)["said"] == "ufw turned off"
    assert fake.changes == [["ufw", "disable"]]
