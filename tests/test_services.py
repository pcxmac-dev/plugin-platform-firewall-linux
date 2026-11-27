"""What the plugin answers plugin-platform-worldwideweb (0.14.0, liminal-libs 1.105.0): the World Wide Web tab left
the Firewall base for that plugin, which asks a firewall through the platform what only a firewall knows. Beside the
base's services (the socket table's reading, the hosts recorded, the routes kept, the rules covering a port), this
plugin tells it what an XDP program at the adapter its capture watches drops before libpcap sees it (capture_unseen),
in the words its own tab said until 0.13.0, from the read kept and running no command. On Windows and macOS each
refuses in words. 0.14.0: the plugin needs liminal-libs 1.105.0, so they are always there."""
from __future__ import annotations

import pytest

from liminal_libs import internal
from liminal_libs.machines.linux import Shell

from plugin_platform_firewall_linux import LinuxFirewallPlugin

from machines import FakeLinux

SERVICES = ("netstat_seen", "hosts_found", "hosts_routes", "rules_covering", "hosts_keep_route", "hosts_keep_places",
            "hosts_clear_places", "capture_unseen")
WINDOWS = "The Linux firewall is for Linux: this machine runs Windows"


def plugin(native: str = "") -> LinuxFirewallPlugin:
    return LinuxFirewallPlugin(shell=Shell("local", runner=FakeLinux("debian-13-nftables")), native=native)


def test_the_services_are_its_hooks_and_its_own_a_read():
    fw = plugin()
    assert set(SERVICES) <= set(fw.HOOKS) and set(SERVICES) <= set(internal.declared(fw, "SERVICE_HOOKS"))
    assert "capture_unseen" in internal.declared(fw, "READ_HOOKS")
    assert {"hosts_keep_route", "hosts_keep_places", "hosts_clear_places"} <= set(internal.plugin_only(fw))
    assert [p for p in internal.problems(fw) if "capture_unseen" in p or "ONLY_HOOKS" in p] == []


def test_what_an_xdp_program_drops_is_said_from_the_read_kept():
    fw = plugin()
    assert fw.capture_unseen("192.168.1.10") == ""  # no read kept: nothing said, and no read made
    fw.config()  # the firewall's read, as its Main tab makes it (the stand-in's)
    calls = len(fw._shell.runner.calls) if hasattr(fw._shell, "runner") else None
    said = fw.capture_unseen("192.168.1.10")  # Debian's enp3s0, where its read found an XDP program (generic, 42)
    assert said.endswith("The firewall's last read found XDP at the adapter watched (enp3s0: XDP generic: program 42): "
                         "what XDP drops never reaches libpcap, so it is neither counted nor drawn here; what nftables "
                         "and iptables drop is, as unanswered.")
    if calls is not None:
        assert len(fw._shell.runner.calls) == calls  # the read kept: no command run
    for address in ("172.17.0.1", "192.168.1.20", "", None, 7):  # docker0 (none), an address no adapter holds, none
        assert fw.capture_unseen(address) == ""
    fw.detach()


def test_on_windows_every_service_refuses_in_words():
    fw = plugin(native=WINDOWS)
    for hook, args in (("capture_unseen", ("192.168.1.10",)), ("netstat_seen", ()), ("hosts_found", ("describe",)),
                       ("rules_covering", (443,))):
        with pytest.raises(ValueError, match="not for this machine"):
            getattr(fw, hook)(*args)
    assert fw.netstat_view(make=False) is None
