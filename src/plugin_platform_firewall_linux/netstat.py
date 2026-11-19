"""The Linux firewall's part of the Netstat tab, the hosts database and the globe's filters (0.9.0; the user,
2026-11-16: "the firewall app should have a 'netstat' like interface for looking at active ports and what apps they
are attached to, and the hosts that they connect to across the lan or wan. the firewall app should also have a globe
that can be zoomed and rotated and geoip'd hosts are databased for the apps they talk to, the time they are connected
to *this *computer"; "the globe-firewall should allow filtering, so i can view apps connected to hosts all across the
globe, or ports talking to all hosts").

The tab, the database, the globe's filters and its layers are the library's Firewall base's (liminal-libs
NETSTAT_LIBS: sockets.py, hostbook.py, machines/netstat.py, machines/infrastructure.py). What is this plugin's:

- `listeners(cfg)`: the listening sockets the firewall's own read names by program, {(proto, port): program}. The read
  runs as root, so ss names every listener's program; the socket table names only the platform's user's own, so the
  tab's Listening ports takes the rest from here. From a read made already: no command is run for it.
- `serves()`: whether the tab can be served here at all (a library that has it, and one of the kernel's socket tables
  this account may read). None of it needs root, so it keeps the plugin valid where the firewall's own read is refused
  (B-revisions S2: "valid wherever it can read the socket table").
- `needs_row()`: what the tab and the database need, as a row of the table of what the firewall needs here.
- `cards(apis, netstat_cards)`: the plugin's cards with the library it runs with: the Netstat tab's left out with an
  older library, where the plugin reaches none of them (as the Windows firewall plugin has it).
- `WSL_ROWS` (`wsl_rows`, `with_wsl_rows`): what WSL changes for the tab beyond the library's own Under WSL table
  (sockets.under_wsl), only what was seen in the user's Ubuntu (WSL 2, 2026-11-18, read only): a TCP port listening at
  127.0.0.1 inside it is reached from Windows' own 127.0.0.1 too, and a UDP one is not. How such a connection looks
  from inside was not seen (none was open, and none was opened to see it), nor another distribution's sockets (none
  ran), nor WSL's mirrored networking: no row says any of them.

Nothing here runs a command, opens a socket or writes a file: `tables_here` asks whether /proc/net's files may be read,
without reading them."""
from __future__ import annotations

import os

from liminal_libs.machines import linux as linux_mod
from liminal_libs.machines.firewall import Firewall

from . import rights as rights_mod
from .groups import UNKNOWN

NETSTAT_LIBS = "1.65.0"  # the library that has the Netstat tab and the hosts database (its number, set at landing)
HOOK = "netstat"  # the base's Netstat tab's hook, among Firewall.HOOKS from NETSTAT_LIBS on
PROC_NET = ("/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6")  # the kernel's socket tables
# the read's words for a listener it names no program for, as the rules' groups take them (groups.UNKNOWN): ss's "?"
# (system.parse_sockets), and net-tools' "-" where there is no ss (netstat -ltnp's PID/Program column for a socket no
# process holds, such as the kernel's nfsd), and nothing at all
UNNAMED = UNKNOWN
WHAT = "Netstat and the hosts database"
# What WSL changes for the tab, seen in the user's Ubuntu (WSL 2, NAT networking, 2026-11-18, twice): the four Linux
# apps and Ollama listened for TCP at 127.0.0.1 there, and Windows' own table listed wslrelay.exe at 127.0.0.1 on
# exactly those five TCP ports, and on no UDP port at all: chronyd's 127.0.0.1:323/udp inside was not on Windows;
# systemd-resolved's 127.0.0.53 and 127.0.0.54 and WSL's name server at 10.255.255.254 were not among them either.
# Microsoft's page on WSL's networking says the same of localhost (apis.WSL_NETWORKING). Mirrored networking was not
# seen.
WSL_ROWS = (
    ["Reached from Windows", "TCP listening at 127.0.0.1",
     "Windows' own programs reach a TCP port listening here at 127.0.0.1 at Windows' 127.0.0.1 too: under WSL's NAT "
     "networking (its default) WSL forwards it, and Windows' own table lists it as wslrelay.exe's. So for TCP, Reached "
     "from \"this machine only\" takes in Windows' programs. UDP is not forwarded (chronyd's 323/udp was not), nor a "
     "port at another address here, such as 127.0.0.53. Mirrored networking was not seen"],
)


def library() -> bool:
    """Whether the library's Firewall base has the Netstat tab (liminal-libs NETSTAT_LIBS)."""
    return HOOK in tuple(getattr(Firewall, "HOOKS", ()) or ())


def cards(apis: tuple, netstat_cards: tuple) -> tuple:
    """The cards of what the plugin attaches to, with the library it runs with: every one of `apis` where the Firewall
    base has the Netstat tab (library), else `netstat_cards` (the kernel's socket tables and the data sets' sources)
    left out, since the plugin reaches none of them there (as the Windows firewall plugin has it)."""
    return tuple(apis) if library() else tuple(a for a in apis if a not in netstat_cards)


def tables_here() -> bool:
    """Whether this account may read one of the kernel's socket tables (/proc/net/tcp, tcp6, udp, udp6), asked of
    the files' modes and nothing read (a test stands it in, so the machine the tests run on never shows through)."""
    return any(os.access(path, os.R_OK) for path in PROC_NET)


def serves() -> bool:
    """Whether the Netstat tab, the hosts database and the globe's filters can be served here: a library that has
    them, and a socket table to read. They need no rights."""
    return library() and tables_here()


def listeners(cfg) -> dict[tuple[str, int], str]:
    """The listening sockets of the firewall's read `cfg` (its Config, or None for none), by protocol and port:
    {("tcp", 22): "sshd"}. The read runs as root, so ss names every listener's program (ss -ltnpH, ss -lunpH; netstat
    -ltnp where there is no ss, TCP alone); one it named no program for (ss's "?", net-tools' "-": UNNAMED) is left
    out, and a port several programs hold names them all, one after another."""
    system = getattr(cfg, "system", None)
    held: dict[tuple[str, int], set[str]] = {}
    tables = (("tcp", getattr(system, "listening", None)), ("udp", getattr(system, "listening_udp", None)))
    for proto, programs in tables:
        for program, ports in dict(programs or {}).items():
            name = str(program or "").strip()
            if name in UNNAMED:
                continue
            for port in ports or ():
                try:
                    held.setdefault((proto, int(port)), set()).add(name)
                except (TypeError, ValueError):
                    continue
    return {key: ", ".join(sorted(names)) for key, names in sorted(held.items())}


def needs_row(root: bool = False) -> list[str]:
    """What the Netstat tab and the hosts database need here, as a row of the table of what the firewall needs (What,
    Here, What to do): no rights; a library that has them; a socket table to read. `root`: whether the platform runs
    as root (its rights' kind "root"), so that every socket's program is read, not only its user's own."""
    if not library():
        have = rights_mod.libs_version()
        return [WHAT, "not in this library",
                f"they need liminal-libs {NETSTAT_LIBS}" + (f" (this one is {have})" if have else "")
                + ": the platform's library has no Netstat tab yet"]
    if not tables_here():
        return [WHAT, "no socket table here",
                "/proc/net/tcp, tcp6, udp and udp6 cannot be read here, so there is nothing for them to list"]
    named = ("naming every program (the platform runs as root)" if root else
             "naming your own programs (another user's: only root reads which program holds it)")
    return [WHAT, "need no rights",
            f"the Netstat tab lists every socket here as the kernel's tables give them to you, {named}; it, the hosts "
            "database and the globe's filters work while the firewall's rules are not read"]


def wsl_rows() -> list[list[str]]:
    """The rows this plugin adds to the Netstat tab's Under WSL table: under WSL 2, and where the kernel's release does
    not tell (the library's wsl_generation answers 0, which it takes as WSL 2: every distribution installed today is);
    none under WSL 1 (it shares Windows' own network, so nothing is forwarded there, and it was not seen), nor where
    the library has no such check or the check fails."""
    generation = getattr(linux_mod, "wsl_generation", None)
    try:
        if not callable(generation) or generation() == 1:
            return []
    except Exception:  # noqa: BLE001 - a check that cannot say: nothing said
        return []
    return [list(row) for row in WSL_ROWS]


def with_wsl_rows(page: dict) -> dict:
    """The Netstat tab's page with WSL_ROWS at the end of its Under WSL table, where it has one (inside a WSL
    distribution); the page as it is otherwise."""
    tables = page.get("tables") if isinstance(page, dict) else None
    if not isinstance(tables, list):
        return page
    for i, table in enumerate(tables):
        if isinstance(table, dict) and table.get("title") == "Under WSL" and isinstance(table.get("rows"), list):
            rows = wsl_rows()
            if rows:
                tables[i] = {**table, "rows": [*table["rows"], *rows]}
            break
    return page
