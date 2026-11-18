"""Installing nftables where no firewall tool is (0.9.0; DECISIONS addendum 9, after the user's Ubuntu in WSL was found
with none: "A missing tool (no nftables in the user's Ubuntu) is installed from the page the same way: Ubuntu's own
package, its size said, installing it filters nothing").

Offered only where none of nftables, iptables, ufw and firewalld is installed, and only where the distribution's own
apt is there (Debian, Ubuntu and their kin): the distribution's nftables package and what it needs that is not
installed yet, as apt installs them. What that takes is read first, without root and changing nothing (`read_facts`:
`apt-get -s install nftables`, apt's own simulation, says which packages it would install; `apt-cache show` says each
one's Size and Installed-Size and whose package it is), kept FACTS_S, and said on the form before anything is done.
The install is a job, its lines in the plugin's panel: `apt-get install -y nftables` with DEBIAN_FRONTEND set to
noninteractive (`COMMAND`), as root through sudo with the password typed on the form (handed to sudo on its standard
input for that one command, never kept), or with none where the platform is root or sudo asks none. Installing it
filters nothing. An apt lock another program holds, and a package that could not be fetched, are said in words
(`apt_words`). Nothing here runs a command but through the shell it is given."""
from __future__ import annotations

import re
from dataclasses import dataclass

PACKAGE = "nftables"
FORM = "install-nftables"  # its form's id on the plugin's page
# apt in English (LC_ALL=C), so its lock and its failed fetches are told apart in words; never a question asked
COMMAND = ("env", "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C", "apt-get", "install", "-y", PACKAGE)  # as root
SIMULATE = ("env", "LC_ALL=C", "apt-get", "-s", "install", PACKAGE)  # apt's simulation: changes nothing, needs no root
SHOW = ("env", "LC_ALL=C", "apt-cache", "show", "--no-all-versions")  # the candidates' paragraphs, read without root
TOOLS = ("apt-get", "apt-cache")  # apt's own, looked for by their files (no command run)
FACTS_S = 600.0  # what installing it takes, kept this long (read again after an install)
READ_TIMEOUT_S = 60.0
TIMEOUT_S = 900.0  # the install itself: the download and dpkg
SHOWN_LINES = 12  # apt's last lines given to the job's panel
LOCKED = ("could not get lock", "unable to acquire the dpkg", "unable to lock", "is another process using it")
UNFETCHED = ("failed to fetch", "unable to fetch", "temporary failure resolving", "could not resolve",
             "connection failed", "unable to connect")


@dataclass(frozen=True)
class Package:
    """One package apt would install: its version, the bytes downloaded (Size) and the KiB it takes installed
    (Installed-Size), and whose it is (Origin: Ubuntu, Debian)."""

    name: str
    version: str = ""
    size: int = 0
    installed: int = 0
    origin: str = ""


@dataclass(frozen=True)
class Facts:
    """What installing nftables takes here, read without root: the packages apt would install, nftables first; or
    why that is not known (`problem`)."""

    packages: tuple = ()
    problem: str = ""

    @property
    def main(self) -> Package | None:
        return next((p for p in self.packages if p.name == PACKAGE), None)

    @property
    def size(self) -> int:
        return sum(p.size for p in self.packages)

    @property
    def installed(self) -> int:
        return sum(p.installed for p in self.packages) * 1024

    @property
    def origin(self) -> str:
        main = self.main
        return main.origin if main is not None else ""

    @property
    def words(self) -> str:
        """The package and what it needs, whose they are and their size, in words."""
        main = self.main
        if main is None:
            return f"the distribution's {PACKAGE} package ({self.problem or 'its size could not be read'})"
        whose = f"{main.origin}'s own {PACKAGE} package" if main.origin else f"the distribution's {PACKAGE} package"
        others = [p.name for p in self.packages if p.name != PACKAGE]
        needs = (f", with the {len(others)} package{'s' if len(others) != 1 else ''} it needs that "
                 f"{'are' if len(others) != 1 else 'is'} not installed yet ({', '.join(others)})" if others else "")
        return (f"{whose} {main.version}".rstrip() + needs
                + f": {si(self.size)} to download, {si(self.installed)} once installed")


def si(n: int) -> str:
    """A size as apt says it: kB and MB of 1000."""
    if n < 1_000_000:
        return f"{max(n, 0) / 1000:,.0f} kB"
    return f"{n / 1_000_000:,.1f} MB"


def simulated(text: str) -> list[str]:
    """The packages `apt-get -s install` would install, in its order (its "Inst <package> (...)" lines)."""
    return list(dict.fromkeys(m.group(1) for m in re.finditer(r"^Inst (\S+)", text or "", re.M)))


def _number(text) -> int:
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return 0


def paragraphs(text: str) -> list[Package]:
    """`apt-cache show`'s paragraphs as packages (a field's continuation lines left out)."""
    out = []
    for block in re.split(r"\n[ \t]*\n", (text or "").replace("\r\n", "\n").strip()):
        fields: dict = {}
        for line in block.splitlines():
            if line[:1] in (" ", "\t"):
                continue
            key, sep, value = line.partition(":")
            if sep:
                fields.setdefault(key.strip(), value.strip())
        if fields.get("Package"):
            out.append(Package(fields["Package"], fields.get("Version", ""), _number(fields.get("Size")),
                               _number(fields.get("Installed-Size")), fields.get("Origin", "")))
    return out


def read_facts(sh) -> Facts:
    """What installing nftables takes here, read as the platform's own user (no root, nothing changed): apt's
    simulation for the packages it would install, then apt-cache for each one's size. Facts with a `problem` when
    apt cannot say (nftables is then the one package named)."""
    from liminal_libs.machines.plugin import CommandError

    try:
        names = simulated(sh.run(*SIMULATE, root=False, timeout=READ_TIMEOUT_S))
    except CommandError as e:
        names, problem = [], f"apt could not say what it would install: {e}"
    else:
        problem = "" if names else "apt would install nothing: is it installed already?"
    wanted = names or [PACKAGE]
    try:
        shown = {p.name: p for p in paragraphs(sh.run(*SHOW, *wanted, root=False, timeout=READ_TIMEOUT_S))}
    except CommandError as e:
        return Facts((), f"apt-cache could not show {PACKAGE}: {e}")
    packages = tuple(shown[n] for n in wanted if n in shown)
    if not any(p.name == PACKAGE for p in packages):
        return Facts(packages, problem or f"apt-cache knows no {PACKAGE} package here")
    return Facts(packages, problem)


def apt_words(error) -> str:
    """apt's failure in words: its lock held by another program, a package that could not be fetched, or apt's own
    last line."""
    words = str(error).strip()
    low = words.lower()
    if any(w in low for w in LOCKED):
        return ("apt is busy: another program holds its lock (an update or an install under way, unattended upgrades "
                f"after a start); nothing was installed. Try again once it has finished ({words})")
    if any(w in low for w in UNFETCHED):
        return ("a package could not be downloaded: this machine may not reach the distribution's archive, or apt's "
                "package lists are out of date (sudo apt-get update brings them up to date); nothing was installed "
                f"({words})")
    return f"apt could not install {PACKAGE}: {words}"
