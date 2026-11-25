"""The plugin's run(): a command on this machine, as the platform's own user, and as root only when its caller says
`elevated` (0.10.0, the review's PLT-H1, 2026-11-23). It ran every command as root (the library's Shell.run defaults to
root: `sudo -n`, or nothing in front when the platform is root), and the platform's POST /api/machines/{name}/run let
any local program hand it any words; that route is gone, and the command lines ask run() in their own process. sudo's
words are the library's, read from its Shell (machines.shell_sudo(): `sudo -n --` since liminal-libs 1.80.0, the
package's floor since 0.10.0). A command refused for want of root, run as you, names `run --elevated`. Over a stand-in
shell: nothing runs."""
from __future__ import annotations

import pathlib
import re

import pytest

from liminal_libs.machines import linux
from liminal_libs.machines.linux import Shell
from liminal_libs.machines.plugin import CommandError

from plugin_platform_firewall_linux import LinuxFirewallPlugin
from plugin_platform_firewall_linux import __main__ as command_line

from machines import shell_sudo

SUDO = shell_sudo()  # the library's sudo without a password, as its Shell puts it before a command run as root
PYPROJECT = pathlib.Path(__file__).parent.parent / "pyproject.toml"
NOT_ROOT = b"Error: Operation not permitted (you must be root)\n"  # nft's words, run by a user who is not root


def _plugin(monkeypatch, root: bool = False, answer=(0, b"ran\n", b"")):
    """The plugin on this Linux (as the platform's user, or as root), over a stand-in shell noting each argv and giving
    each command `answer`."""
    ran: list[list[str]] = []
    monkeypatch.setattr(linux.os, "geteuid", lambda: 0 if root else 1000, raising=False)
    shell = Shell("local", runner=lambda args, timeout: ran.append(list(args)) or answer)
    return LinuxFirewallPlugin(shell=shell, native=""), ran


def test_an_elevated_command_comes_after_sudos_own_double_dash_from_the_library_it_needs():
    """run --elevated promises that no word of the command is read as sudo's: it needs liminal-libs 1.80.0, whose Shell
    puts `sudo -n --` before a command run as root (before, `sudo -n`, and `-u nobody id` ran id as nobody). The
    package says so (its floor), and the library the tests run on must hold it, or SUDO below would pass on its
    `sudo -n` alone."""
    assert SUDO[:1] == ["sudo"] and SUDO[-1:] == ["--"]
    floor = re.search(r'"liminal-libs\[geo\]>=(\d+)\.(\d+)\.(\d+)"', PYPROJECT.read_text(encoding="utf-8"))
    assert floor and tuple(int(n) for n in floor.groups()) >= (1, 80, 0)


def test_a_command_runs_as_the_platforms_user_and_as_root_only_when_elevated_is_said(monkeypatch):
    fw, ran = _plugin(monkeypatch)
    assert fw.run("nft", "list", "ruleset") == "ran\n" and ran == [["nft", "list", "ruleset"]]  # nothing in front
    assert fw.run("-u", "root", "id") == "ran\n" and ran[-1] == ["-u", "root", "id"]  # no sudo to read its -u
    assert fw.run("id", root=True) and ran[-1] == ["id"]  # an option, but only `elevated` makes it root
    assert fw.run("nft", "list", "ruleset", elevated=True) and ran[-1] == [*SUDO, "nft", "list", "ruleset"]
    assert fw.run("-u", "nobody", "id", elevated=True) and ran[-1] == [*SUDO, "-u", "nobody", "id"]  # after sudo's own
    # a platform that is root runs it as itself, elevated or not: there is no one else to run it as
    fw, ran = _plugin(monkeypatch, root=True)
    assert fw.run("id") and fw.run("id", elevated=True) and ran == [["id"], ["id"]]


def test_its_command_line_runs_as_you_unless_elevated_comes_before_the_command(monkeypatch, capsys):
    fw, ran = _plugin(monkeypatch)
    monkeypatch.setattr(command_line, "MACHINE", fw)
    assert command_line.main(["run", "--", "ip", "-br", "addr"]) == 0 and ran[-1] == ["ip", "-br", "addr"]
    assert command_line.main(["run", "--elevated", "--", "nft", "list", "ruleset"]) == 0
    assert ran[-1] == [*SUDO, "nft", "list", "ruleset"]
    # after the command's `--` every word is the command's own, --elevated too: run as you, with that word
    assert command_line.main(["run", "--", "x", "--elevated"]) == 0 and ran[-1] == ["x", "--elevated"]
    assert command_line.main(["run", "--", "--elevated"]) == 0 and ran[-1] == ["--elevated"]
    assert capsys.readouterr().out == "ran\n" * 4
    for words in (["run"], ["run", "--"], ["run", "--elevated"], ["run", "--elevated", "--"]):
        assert command_line.main(words) == 2 and len(ran) == 4  # no command: the usage, nothing run
        assert "run [--elevated] -- COMMAND" in capsys.readouterr().err


def test_a_command_refused_for_want_of_root_as_you_names_run_elevated(monkeypatch, capsys):
    """The library words a command refused for want of root alike, however it ran: run the platform as root, or let
    sudo run it without a password. As you, a sudo rule alone changes nothing (the same command fails again), so the
    words say that it ran as you and that such a rule counts only for `run --elevated`, which the platform's command
    line has not. Elevated, or with a platform that is root, the library's words as they are."""
    fw, ran = _plugin(monkeypatch, answer=(1, b"", NOT_ROOT))
    with pytest.raises(CommandError) as e:
        fw.run("nft", "list", "ruleset")
    words = str(e.value)
    assert e.value.denied and ran == [["nft", "list", "ruleset"]]  # as you: nothing in front
    assert words.startswith("nft needs root on this machine: run the platform as root, or let sudo run it without a "
                            "password (Error: Operation not permitted (you must be root))")
    assert words.endswith(". It ran as you, not through sudo: a rule letting sudo run it counts only for `python -m "
                          "plugin_platform_firewall_linux run --elevated -- nft ...`; the platform's command line has "
                          "no --elevated and runs every command as you")
    with pytest.raises(CommandError) as e:  # elevated: through sudo -n --, which a rule of yours lets run it
        fw.run("nft", "list", "ruleset", elevated=True)
    assert e.value.denied and ran[-1] == [*SUDO, "nft", "list", "ruleset"] and "--elevated" not in str(e.value)
    monkeypatch.setattr(command_line, "MACHINE", fw)  # its command line prints the words and ends with 1
    assert command_line.main(["run", "--", "nft", "list", "ruleset"]) == 1
    err = capsys.readouterr().err
    assert "counts only for `python -m plugin_platform_firewall_linux run --elevated -- nft ...`" in err
    # a platform that is root: the command's own words, --elevated changing nothing there
    fw, ran = _plugin(monkeypatch, root=True, answer=(1, b"", NOT_ROOT))
    with pytest.raises(CommandError) as e:
        fw.run("nft", "list", "ruleset")
    assert e.value.denied and str(e.value) == "Error: Operation not permitted (you must be root)"
    # a failure that is not for want of root: its own words, as before
    fw, ran = _plugin(monkeypatch, answer=(1, b"", b"Error: No such file or directory; did you mean table 'filter'?\n"))
    with pytest.raises(CommandError) as e:
        fw.run("nft", "list", "table", "inet", "nope")
    assert not e.value.denied and "--elevated" not in str(e.value)
