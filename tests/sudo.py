"""A stand-in for sudo over a recorded machine (machines.FakeLinux), so the plugin's Root access is tested in every
state with nothing run, through the library's own rights (liminal-libs 1.62.0: machines.linux's Shell.run with a
`password`, grant, revoke, granted and needs_password), never a copy of them. With a library from before them a test
that makes one is skipped: the plugin then works as 0.8.1, which tests of their own show by taking those names away.

`Sudo(machine)` is the machine's policy and its grant as a test sets them: `root` (the platform runs as root), `own` (a
rule of the user's own lets every command run without a password), `state` (the grant: "" none, "on", "pending" (its
rule there, the user in the group liminal in the system's database but not this process), "stale" (its installed read
is not this plugin's)), whether the group liminal is there and the user in it, and the one password sudo takes
(PASSWORD, a test's). It answers what the library runs as sudo 1.9 would: `sudo -n -l` with its listing (a rule of the
user's own, and the grant's while this process has the group), `cat -- <file>` with what is installed there while this
process may read it, `sudo -S -k -p "" -- <command>` only with the password alone on its standard input, and the
grant's script and the take-back's as root. `install(monkeypatch)` gives the plugin to test, its shell the library's
`Shell` answered by this machine: everything run is kept (`calls`: the arguments; `fed`: the standard input each was
given)."""
from __future__ import annotations

import pytest

from liminal_libs.machines import linux as linux_mod
from liminal_libs.machines.linux import Shell
from plugin_platform_firewall_linux import LinuxFirewallPlugin, rights
from plugin_platform_firewall_linux.read import SCRIPT

from machines import RECORDED, SUDO_S, FakeLinux, answer

PASSWORD = "Sesame-7f3e9a1c-liminal-test"  # the one password this sudo takes: a test's, never anyone's
LIB = rights.library()  # the library's rights; None for a library from before them
NEEDS_PASSWORD = getattr(linux_mod, "needs_password", None)  # the library's own: the suite's guard stands it in
LISTING = list(getattr(linux_mod, "SUDO_LIST", ()))  # sudo's listing, as the library asks for it
HEAD = "User sysop may run the following commands on liminal-test:\n"
WRONG = "Sorry, try again.\nsudo: no password was provided\nsudo: 1 incorrect password attempt"
NEEDED = "sudo: a password is required"
GID = 991  # the group liminal's id, when it is there


def installed_read() -> str:
    """The plugin's read as the library's grant installs it."""
    return linux_mod.helper_text(rights.NAME, rights.read_text())


class Sudo(FakeLinux):
    """The machine (a recorded one), its sudo and the grant on it, as the test sets them."""

    paths = rights.Paths.here()
    installed_nft = False

    def __init__(self, machine: str = "debian-13-nftables", *, root=False, own=False, state="", group=None,
                 member=None, active=None, **changed):
        if LIB is None:  # what is tested over it are the library's rights, which this library does not have
            pytest.skip(f"a library from before the grant (liminal-libs {rights.NEEDS_LIBS})")
        super().__init__(machine, **changed)
        self.root, self.own, self.state = root, own, state
        on = state in ("on", "pending", "stale")
        self.group = on if group is None else group  # the group liminal is there
        self.member = on if member is None else member  # the user in it, in the system's database
        self.active = state in ("on", "stale") if active is None else active  # this process has it
        self.fed: list = []  # each command's standard input, as it was given
        self.installed_text = "#!/bin/sh\necho an older plugin's read\n" if state == "stale" else installed_read()
        self.apt_fails = ""  # apt-get install's errors, when the test makes it fail

    @property
    def readable(self) -> bool:
        """Whether the grant's files are there and this process may read and run them: it has the group."""
        return self.state in ("on", "pending", "stale") and self.active

    # -- the commands ----------------------------------------------------------------------------------------------
    def __call__(self, args, timeout, stdin=None):
        args = list(args)
        self.calls.append(args)
        self.fed.append(stdin)
        if args[:len(SUDO_S)] == SUDO_S:
            if (stdin or "").split("\n", 1)[0] != PASSWORD:
                return 1, "", WRONG
            return self.as_root(args[len(SUDO_S):], (stdin or "").split("\n", 1)[1])
        if args == LISTING:
            return self.listing()
        if args[:2] == ["sudo", "-n"]:
            cmd = args[2:]
            if cmd == [self.paths.read]:
                if self.state in ("on", "pending") and self.active:
                    self.reads += 1
                    return 0, answer(self.sections), ""
                return 1, "", NEEDED
            if cmd == [self.paths.helper]:
                if self.readable:
                    self.state = ""
                    return 0, "", ""
                return 1, "", NEEDED
            if not self.own:
                return 1, "", NEEDED
            return self.as_root(cmd, stdin)
        if self.root:
            return self.as_root(args, stdin)
        return self.as_user(args)

    def listing(self):
        """sudo's answer to its listing (`sudo -n -l`): a rule of the user's own, and the grant's while this process
        has the group, as sudo prints them; with neither, sudo will not list without a password."""
        rules = ["(ALL) NOPASSWD: ALL"] if self.own else []
        if self.readable:
            rules.append(f'(root) NOSETENV: EXEC: NOPASSWD: {self.paths.read} "", {self.paths.helper} ""')
        return (0, HEAD + "".join(f"    {r}\n" for r in rules), "") if rules else (1, "", NEEDED)

    def as_root(self, cmd, stdin):
        """A command run as root: the read, the group's making, the grant's script, apt, or a change (kept)."""
        if cmd[:2] == ["sh", "-c"] and cmd[2:3] == [SCRIPT]:
            self.reads += 1
            return 0, answer(self.sections), ""
        if cmd[:1] == ["groupadd"] or cmd[:2] == ["addgroup", "-S"]:
            self.group = True
            return 0, "", ""
        if cmd[:1] == ["usermod"] or (cmd[:1] == ["addgroup"] and len(cmd) == 3):
            self.member = True
            return 0, "", ""
        script = cmd[2] if cmd[:2] == ["sh", "-c"] and len(cmd) == 3 else ""  # a script as the library hands it
        if "liminal-granted" in script:
            self.state = "on" if self.active else "pending"
            self.installed_text = installed_read()
            return 0, "liminal-granted\n", ""
        if "rm -rf" in script:  # the cleanup, where the take-back helper cannot run
            self.state = ""
            return 0, "", ""
        if "apt-get" in cmd and "install" in cmd and "-s" not in cmd:
            if self.apt_fails:
                return 100, "", self.apt_fails
            self.installed_nft = True
            return 0, "Setting up libnftnl11 (1.2.6-2build1) ...\nSetting up nftables (1.0.9-1ubuntu0.1) ...\n", ""
        for first, reply in self.replies.items():
            if tuple(cmd[:len(first)]) == tuple(first):
                return reply
        return 0, "", ""

    def as_user(self, cmd):
        """A command run as the platform's own user: a file read (cat), apt's simulation and its cache."""
        if cmd[:2] == ["cat", "--"]:
            text = {self.paths.read: self.installed_text, self.paths.helper: "#!/bin/sh\n"}.get(cmd[2])
            if self.readable and text is not None:
                return 0, text, ""
            return 1, "", f"cat: {cmd[2]}: Permission denied"
        if "apt-get" in cmd and "-s" in cmd:
            return 0, RECORDED_APT["simulate"], ""
        if "apt-cache" in cmd:
            return 0, RECORDED_APT["show"], ""
        return 0, "", ""

    # -- the grant's rule file, and the system's database of users and groups ------------------------------------------
    def exists(self, path):
        return path == self.paths.rule and self.state in ("on", "pending", "stale")

    def group_of(self, name=rights.GROUP):
        return (GID, ("sysop",) if self.member else ()) if self.group and name == rights.GROUP else None

    def has_group(self, gid):
        return gid == GID and self.active

    def which(self, tool):
        """The tools' files: the recorded machine's, apt and the group's tools; nft once installed here."""
        if tool == "nft" and self.installed_nft:
            return "/usr/sbin/nft"
        known = {line.split()[0]: line.split()[-1] for line in self.sections.get("tools", (0, ""))[1].splitlines()
                 if line.split()}
        if tool in known:
            return known[tool]
        return f"/usr/sbin/{tool}" if tool in ("apt-get", "apt-cache", "groupadd", "usermod") else None

    def install(self, monkeypatch, **options) -> LinuxFirewallPlugin:
        """The plugin over this machine (a native Linux, by the test's word), its shell the library's own answered by
        this machine, the grant's rule file and the system's database as this machine has them."""
        monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 0 if self.root else 1000, raising=False)
        monkeypatch.setattr(linux_mod, "needs_password", NEEDS_PASSWORD)  # sudo's listing read, as the library reads it
        monkeypatch.setattr(rights, "exists", self.exists)
        monkeypatch.setattr(rights, "group_of", self.group_of)
        monkeypatch.setattr(rights, "has_group", self.has_group)
        options.setdefault("which", self.which)
        return LinuxFirewallPlugin(shell=Shell("local", runner=self), native="", clock=lambda: 1000.0, **options)

    @property
    def run_as_root(self) -> list[list[str]]:
        """The commands run as root but the read, without sudo's own words."""
        out = []
        for c in self.calls:
            cmd = c[len(SUDO_S):] if c[:len(SUDO_S)] == SUDO_S else c[2:] if c[:2] == ["sudo", "-n"] else c
            read = (cmd[:2] == ["sh", "-c"] and cmd[2:3] == [SCRIPT]) or cmd == [self.paths.read]
            if read or c == LISTING or c[:3] == ["sudo", "-n", "-l"] or c[:1] == ["cat"]:
                continue
            if c[:len(SUDO_S)] == SUDO_S or c[:2] == ["sudo", "-n"] or self.root:
                out.append(cmd)
        return out


def _recorded_apt() -> dict:
    """apt's simulation of installing nftables and apt-cache's paragraphs of the three packages it would install, as
    the user's Ubuntu 24.04 (WSL) answered them without root on 2026-11-17: Ubuntu's package metadata alone."""
    folder = RECORDED / "apt-ubuntu-24.04"
    return {"simulate": (folder / "simulate").read_text(encoding="utf-8"),
            "show": (folder / "show").read_text(encoding="utf-8")}


RECORDED_APT = _recorded_apt()
