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
`outside` (and runs only when LIMINAL_VENDOR_PAGES=1).

The Netstat tab and the hosts database (0.9.0, liminal-libs 1.65.0) never reach this machine either (`_no_real_hosts`,
B-critique B1, as the library's own suite has it): a firewall a test attaches reads its recording setting through its
login, and a login with no variables of its own reads this user's, so once the user chose "always" such a test would
start a thread reading this machine's socket table into this machine's own hosts database. So every test runs with
LIMINAL_HOSTS_RECORDING set to "shown" in its process (which wins over a saved one), the socket reader refused (a
`Reached`, noted and failed at its end: sockets.read, looked up when the code reads), and the hosts database and the
infrastructure layers' folder in the test's own folder (its tmp_path where it has one, else one made when first
asked); each book made there is let go after it. The kernel's socket tables are taken as a Linux machine has them,
readable (netstat.tables_here), the library's Under WSL table for the Netstat tab (sockets.under_wsl) is none, as not
inside WSL, and this machine's hosts file names no address (sockets.known_names: a view made without names of its own
reads /etc/hosts, or Windows' own hosts file, for the rows' names). A test that reads a socket table gives the code a
reader of its own. With a library from before the Netstat tab the guard has nothing to guard."""
from __future__ import annotations

import os
import socket
import subprocess
import threading

import pytest

import plugin_platform_firewall_linux as plugin_module
from liminal_libs.machines import linux, world
from plugin_platform_firewall_linux import netstat as netstat_mod
from plugin_platform_firewall_linux import rights

try:  # the Netstat tab's and the hosts database's modules (liminal-libs 1.65.0)
    from liminal_libs import hostbook, sockets
    from liminal_libs.machines import infrastructure
except ImportError:  # a library from before them: no socket table is read, no host is kept
    hostbook = sockets = infrastructure = None


def pytest_configure(config):
    config.addinivalue_line("markers", "outside: the test reaches the outside on purpose (no guard)")


@pytest.fixture(autouse=True)
def _not_this_machine(monkeypatch):
    if hasattr(linux, "wsl_table"):  # a library whose check no longer refuses a WSL kernel
        monkeypatch.setattr(linux, "wsl_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(world, "under_wsl", lambda *args, **kwargs: None)
    monkeypatch.setattr(world, "_init", lambda: "")
    if sockets is not None:  # the Netstat tab's (liminal-libs 1.65.0)
        monkeypatch.setattr(sockets, "under_wsl", lambda *args, **kwargs: None)
        monkeypatch.setattr(sockets, "known_names", lambda *args, **kwargs: {})  # this machine's hosts file: no names
    monkeypatch.setattr(netstat_mod, "tables_here", lambda: True)  # as on any Linux: /proc/net's tables are readable


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


@pytest.fixture(autouse=True)
def _no_real_hosts(monkeypatch, request, tmp_path_factory):
    """Every test: no recording all the time by the user's own setting, no socket table read for real, and the hosts
    database and the infrastructure layers kept in the test's own folder (the module's docstring). Yields the reads
    refused, so the guard's own test can clear the one it made on purpose."""
    if hostbook is None:  # a library from before the Netstat tab
        yield []
        return
    folder = request.getfixturevalue("tmp_path") if "tmp_path" in request.fixturenames else None
    lock = threading.Lock()

    def own():  # the test's own folder: made when first asked, from whichever thread asks
        nonlocal folder
        with lock:
            if folder is None:
                folder = tmp_path_factory.mktemp("no-real-hosts")
            return folder

    refused: list[str] = []

    def read(*args, **kwargs):
        refused.append(f"sockets.read {args[:1]!r}"[:300])
        raise Reached("the test read this machine's socket table for real: give the code a reader of its own")

    monkeypatch.setenv(hostbook.VARIABLE, "shown")
    monkeypatch.setattr(sockets, "read", read)
    monkeypatch.setattr(hostbook, "path", lambda: own() / "liminal-data" / hostbook.FOLDER / hostbook.FILE)
    monkeypatch.setattr(hostbook, "_BOOKS", {})
    monkeypatch.setattr(infrastructure, "folder", lambda: own() / "liminal-data" / infrastructure.FOLDER)
    yield refused
    for book in list(hostbook._BOOKS.values()):  # the books handed out in the test: written and let go
        try:
            book.close()
        except Exception:  # noqa: BLE001 - a test's own book that it broke on purpose
            pass
    assert not refused, f"the test read this machine's socket table for real: {refused}"
