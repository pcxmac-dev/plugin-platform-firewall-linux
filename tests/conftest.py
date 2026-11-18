"""What every test here shares: the machine the tests run on never shows through. Not inside WSL (the library's
linux.wsl_table for the status, world.under_wsl for the World Wide Web tab), and no init known (world._init, so both ways
to the right to capture are told), so the suite reads alike inside a WSL distribution, on a Linux of any init and on
Windows. A test that wants one of them says so itself.

Root access as this machine has it never shows through either (0.9.0, rights.py): every firewall tool and apt are
found (find_tool), no grant's rule is (the plugin looks for its file without a command), the platform's user is
"sysop", in no group liminal, and sudo's policy is not asked (the library's needs_password answers that no password is
needed, as a rule of one's own would). A test that wants otherwise says so (tests/sudo.py).

And no test reaches the outside (`_no_outside`, the library's shared guard, 1.62.0): a process started, a connection
opened or a name resolved for real raises `Reached`, a BaseException no `except Exception` can swallow, and fails the
test at its end even if something caught it. The one test that reaches the makers' pages on purpose is marked
`outside` (and runs only when LIMINAL_VENDOR_PAGES=1)."""
from __future__ import annotations

import os
import socket
import subprocess

import pytest

import plugin_platform_firewall_linux as plugin_module
from liminal_libs.machines import linux, world
from plugin_platform_firewall_linux import rights


def pytest_configure(config):
    config.addinivalue_line("markers", "outside: the test reaches the outside on purpose (no guard)")


@pytest.fixture(autouse=True)
def _not_this_machine(monkeypatch):
    if hasattr(linux, "wsl_table"):  # a library whose check no longer refuses a WSL kernel
        monkeypatch.setattr(linux, "wsl_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(world, "under_wsl", lambda *args, **kwargs: None)
    monkeypatch.setattr(world, "_init", lambda: "")


@pytest.fixture(autouse=True)
def _no_grant_here(monkeypatch):
    monkeypatch.setattr(plugin_module, "find_tool", lambda tool: f"/usr/sbin/{tool}")  # every tool there, unless said
    monkeypatch.setattr(rights, "exists", lambda path: False)
    monkeypatch.setattr(rights, "user", lambda: "sysop")
    monkeypatch.setattr(rights, "group_of", lambda name=rights.GROUP: None)
    monkeypatch.setattr(rights, "primary_gid", lambda who: None)
    monkeypatch.setattr(rights, "has_group", lambda gid: False)
    if hasattr(linux, "needs_password"):
        monkeypatch.setattr(linux, "needs_password", lambda shell, *command: False)


class Reached(BaseException):
    """A test reached for real what it must stand in for."""


@pytest.fixture(autouse=True)
def _no_outside(request, monkeypatch):
    if request.node.get_closest_marker("outside"):
        yield []
        return
    reached: list[str] = []

    def refuse(what):
        def stand_in(*args, **kwargs):
            reached.append(f"{what} {args[:2]!r}"[:300])
            raise Reached(f"the test reached {what} for real: give the code a stand-in")
        return stand_in

    for name in ("Popen", "run", "call", "check_call", "check_output", "getoutput", "getstatusoutput"):
        monkeypatch.setattr(subprocess, name, refuse(f"subprocess.{name}"))
    for name in ("system", "startfile", "posix_spawn", "posix_spawnp", "spawnv", "spawnve", "spawnvp", "spawnvpe"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, refuse(f"os.{name}"))
    for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, refuse(f"socket.{name}"))
    for name in ("connect", "connect_ex", "sendto"):
        monkeypatch.setattr(socket.socket, name, refuse(f"socket.socket.{name}"))
    yield reached
    assert not reached, f"the test reached the outside for real: {reached}"
