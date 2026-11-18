"""Root access for the Linux firewall (0.9.0). The user, 2026-11-17, after the firewall could not be read inside their
WSL Ubuntu, where sudo asks for a password: "the plugin needs to be able to handle permissions if required"; asked how
the password is typed: "A field on its page"; then "(enable / disable)", "but only if required" (DECISIONS addenda 9
and 10).

How the plugin has the root its read and its changes need (`Rights`, one of KINDS), found with each read and kept
with it:
- `root`: the platform runs as root: everything runs as root, without sudo;
- `own`: sudo runs the read without a password by a rule of the user's own (`sudo -n sh -c <the read>`);
- `on`: Root access is on: the library's narrow grant (machines.linux.grant, liminal-libs NEEDS_LIBS) lets the
  plugin's read, installed as a root-owned file, run as root through `sudo -n`, and nothing else; the installed file
  is compared with the plugin's own read before each run (machines.linux.granted);
- `pending`: turned on, but this platform was started before: the rule names the group liminal (addendum 10), which
  programs started after the grant are given; it takes effect once the platform is started again;
- `stale`: the read installed is not this plugin's (an older plugin's), or the grant is not whole: nothing installed
  is run, and Turn on... again puts it right;
- `off`: none of them: the firewall's rules are not read;
- `old`: a library from before the grant: the plugin works as 0.8.1 did, and its page says the switch needs
  NEEDS_LIBS.

The switch (Root access, enable / disable) is shown only if required: never where the platform is root, nor where
the user's own rule runs the read (a fact then says how it has its rights). Turning it on asks for the password once,
on the page (PASSWORD_FIELD), handed to sudo on its standard input for that one action (the library's
Shell.run(password=...): `sudo -S`): the group liminal made where there is none, the platform's user put in it, then
the grant (`turn_on`). Turning it off runs the grant's take-back helper, which the grant lets run without a password,
so it asks none unless that helper cannot run yet (`turn_off`). A change's form gets the password field only if
required (`changes_need`). The password is never kept, logged, written, shown, put in a command line or an
environment, nor left in an error's words: it is a hook's last argument, handed to the shell, gone when the hook
returns.

The library's names are found when they are used (`library`), so a library from before them is told apart at once.
What the system's own database says of users and groups is read without a command (`user`, `group_of`, `has_group`),
and a test stands each in."""
from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass, field

from liminal_libs.machines import linux as linux_mod
from liminal_libs.machines.plugin import CommandError

from .read import SCRIPT

NAME = "firewall-linux"  # the grant's name: its sudoers rule and its helpers' folder are named after it
WHY = "the Linux firewall's read of its rules"  # what the grant is for, in its rule's comment (the library's `why`)
READ = "read"  # the plugin's read, installed under the grant's folder by this name
NEEDS_LIBS = "1.62.0"  # the library that has the grant and Shell.run's password
GROUP = "liminal"  # the group the grant's rule names (DECISIONS addendum 10)
PASSWORD = "password"  # every change's last argument: the password typed on its form, or None
NAMES = ("grant", "revoke", "granted", "needs_password", "PasswordRefused")  # 1.62.0's, with Shell.run's password
# The grant's places as the page names them with a library from before grant_paths, which says them otherwise
LIBEXEC, SUDOERS_D, TAKE_BACK = "/usr/local/libexec/liminal", "/etc/sudoers.d", "take-back"

KINDS = ("root", "own", "on", "pending", "stale", "off", "old")
OFF = "off: the firewall's rules are not read"
ON = "on: a rule lets its read run as root, nothing else"
PENDING = "on from the platform's next start: the firewall's rules are not read until then"
STALE = "on, but its read installed is an older plugin's: it is not run"
ROOT = "the platform runs as root: the firewall is read and changed as root, without sudo"
OWN = "sudo runs its read without a password, by a rule of your own: Root access is not needed"
WRONG = "sudo did not accept the password: nothing was changed; type it again"

PASSWORD_FIELD = {"name": PASSWORD, "label": "Your password for sudo", "type": "password", "required": True,
                  "note": "used for this once, never kept"}


def read_text() -> str:
    """The plugin's read as the body of the file the grant installs: the script it runs today (read.SCRIPT) as a POSIX
    sh script. The library's grant installs it as its helper_text (which says what that head adds), and its granted
    compares the installed file with that text."""
    return "#!/bin/sh\n" + SCRIPT


FILES = {READ: read_text()}  # what the grant installs, by name


def library():
    """The library's rights (liminal-libs NEEDS_LIBS: machines.linux's grant, revoke, granted, needs_password and
    PasswordRefused, which came with Shell.run's `password`), or None for a library from before them."""
    return linux_mod if all(hasattr(linux_mod, n) for n in NAMES) else None


def libs_version() -> str:
    try:
        import liminal_libs

        return str(getattr(liminal_libs, "__version__", "") or "")
    except Exception:  # noqa: BLE001 - not said
        return ""


def old_words() -> str:
    """What an older library lacks, in words."""
    have = libs_version()
    return (f"its Root access switch, which asks for your password once, needs liminal-libs {NEEDS_LIBS}"
            + (f" (this one is {have})" if have else ""))


@dataclass(frozen=True)
class Paths:
    """Where the grant puts things: the library's grant_paths (its folder, take-back helper and rule), and the read in
    the folder; for a library from before it, the same places, so the page can name them."""

    folder: str
    read: str
    helper: str
    rule: str

    @classmethod
    def here(cls) -> "Paths":
        paths = getattr(linux_mod, "grant_paths", None)
        folder, helper, rule = (paths(NAME) if paths is not None else
                                (f"{LIBEXEC}/{NAME}", f"{LIBEXEC}/{NAME}/{TAKE_BACK}", f"{SUDOERS_D}/liminal-{NAME}"))
        return cls(folder, f"{folder}/{READ}", helper, rule)


# -- what the system's database says of users and groups, read without a command (a test stands each in) ------------
def user() -> str:
    """The user the platform runs as, by name ("" when it cannot be told)."""
    try:
        import pwd

        return pwd.getpwuid(os.geteuid()).pw_name
    except Exception:  # noqa: BLE001 - not on Linux, or no name for the uid
        return os.environ.get("USER") or os.environ.get("LOGNAME") or ""


def group_of(name: str = GROUP) -> tuple[int, tuple[str, ...]] | None:
    """The group's id and its members as the system's database lists them, or None when there is no such group."""
    try:
        import grp

        g = grp.getgrnam(name)
        return g.gr_gid, tuple(g.gr_mem)
    except Exception:  # noqa: BLE001 - no such group, or not on Linux
        return None


def primary_gid(who: str) -> int | None:
    try:
        import pwd

        return pwd.getpwnam(who).pw_gid
    except Exception:  # noqa: BLE001 - not on Linux, or no such user
        return None


def has_group(gid: int) -> bool:
    """Whether this process has the group now (a membership given after it started is not among its groups)."""
    try:
        return gid == os.getegid() or gid in os.getgroups()
    except Exception:  # noqa: BLE001 - not on Linux
        return False


def membership(who: str, name: str = GROUP) -> tuple[bool, bool, bool]:
    """(the group is there, `who` is in it in the system's database, this process has it now)."""
    g = group_of(name)
    if g is None:
        return False, False, False
    gid, members = g
    member = bool(who) and (who in members or primary_gid(who) == gid)
    return True, member, has_group(gid)


# -- how the plugin has its rights -------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Grant:
    """What of the grant is on this machine: whether its rule is there, whether the read installed is the plugin's
    own (None: not readable from here), whether sudo runs it without a password, whether the take-back helper runs
    without one, what is missing in words, and the group's state for the platform's user."""

    rule: bool = False
    current: bool | None = None
    usable: bool = False
    helper: bool = False
    missing: tuple = ()
    group: bool = False
    member: bool = False
    active: bool = False

    @property
    def kind(self) -> str:
        if not self.rule:
            return "off"
        if self.current is True and self.usable:
            return "on"
        if self.current is None and self.member and not self.active:
            return "pending"
        return "stale"


def exists(path: str) -> bool:
    """Whether a file is there, looked for without root (a test stands it in)."""
    return os.path.exists(path)


def grant_state(lib, sh) -> Grant:
    """The grant as this machine has it: its rule's file looked for (`exists`: no command, /etc/sudoers.d is open to
    look in, the rule itself is root's), then, when it is there, the library's granted() (the read installed compared
    with this plugin's; sudo's listing, read once, for the rule that decides each file) and the group's state from the
    system's database."""
    rule = bool(exists(Paths.here().rule))
    there, member, active = membership(user())
    if not rule:
        return Grant(group=there, member=member, active=active)
    try:
        said = lib.granted(sh, NAME, FILES)
    except CommandError as e:
        return Grant(rule=True, missing=(str(e),), group=there, member=member, active=active)
    said = said if isinstance(said, dict) else {}
    read = ((said.get("files") or {}).get(READ)) or {}
    helper = said.get("take_back") or {}
    current = read.get("matches") if read.get("installed") else None
    return Grant(rule=True, current=current if current in (True, False) else None, usable=bool(read.get("nopasswd")),
                 helper=bool(helper.get("installed")) and bool(helper.get("nopasswd")),
                 missing=tuple(str(m) for m in (said.get("missing") or ())), group=there, member=member,
                 active=active)


@dataclass(frozen=True)
class Rights:
    """How the plugin has its root (`kind`, one of KINDS), with the grant as found."""

    kind: str
    grant: Grant = field(default_factory=Grant)

    @property
    def shown(self) -> bool:
        """Whether the Root access switch is shown: only if required."""
        return self.kind in ("on", "pending", "stale", "off")

    @property
    def granted(self) -> bool:
        return self.kind in ("on", "pending", "stale")

    @property
    def state(self) -> str:
        """The switch's state in words (its row's)."""
        if self.kind == "stale" and self.grant.current is not False:
            why = "; ".join(self.grant.missing) or "the grant is not whole"
            return f"on, but {why}: nothing installed is run"
        return {"on": ON, "pending": PENDING, "stale": STALE, "off": OFF}.get(self.kind, "")

    @property
    def fact(self) -> str:
        """How it has its rights, in words (the status's rootAccess)."""
        if self.kind == "old":
            return f"through sudo -n alone, which never asks for a password; {old_words()}"
        return {"root": ROOT, "own": OWN}.get(self.kind, "") or self.state

    @property
    def off_password(self) -> bool:
        """Whether turning it off needs the password: its take-back helper cannot run without one yet."""
        return self.granted and (self.kind == "pending" or not self.grant.helper)


class WrongPassword(ValueError):
    """sudo did not take the password typed: a refusal, so the page's form can be filled again."""


def refused(e: Exception) -> bool:
    """Whether a failure is sudo refusing the password typed (the library's PasswordRefused)."""
    return isinstance(e, getattr(linux_mod, "PasswordRefused", ()))


@contextmanager
def refusals(done: list | tuple = ()):
    """Around steps run with the password typed: sudo refusing it is a WrongPassword (the form is filled again) while
    no step is done; once steps are done (`done`: their words, which the steps add as they go), a failure says them, a
    refused password included: CommandError("<its words> (done before it: <the steps>)")."""
    try:
        yield
    except (CommandError, WrongPassword) as e:
        wrong = isinstance(e, WrongPassword) or refused(e)
        if done:
            raise CommandError(f"{WRONG if wrong else e} (done before it: {'; '.join(done)})",
                               denied=not wrong and e.denied) from None
        if wrong and not isinstance(e, WrongPassword):
            raise WrongPassword(WRONG) from None
        raise


def run(sh, *command, password=None, **options) -> str:
    """A command through the shell as root, the password handed to sudo on its standard input when one is given (and
    the library takes one, and the platform is not root); sudo -n otherwise, which never asks. A refused password is a
    WrongPassword."""
    if password and not sh.root() and library() is not None:
        with refusals():
            return sh.run(*command, password=password, **options)
    return sh.run(*command, **options)


def changes_need(sh, rights: Rights, *command) -> bool:
    """Whether a change running `command` needs the password typed on its form: never as root, nor with a library
    from before the field (sudo -n alone, as 0.8.1); always where the switch is required, since the grant lets the
    read alone run without one, and sudo asks for the read itself where Root access is not on yet; where the user's
    own rule runs the read, as the library's needs_password says (sudo's listing, read for the rule that decides the
    command: an exit code of `sudo -n -l <command>` says only that it is allowed, a password asked or not)."""
    if rights.kind in ("root", "old"):
        return False
    if rights.shown:
        return True
    return needs(sh, *command)


def needs(sh, *command) -> bool:
    """Whether sudo cannot run `command` without a password, by the library's needs_password (sudo's listing, the rule
    that decides the command): never as root, nor with a library from before it; in doubt, yes. Asked only where the
    user's own rule runs the read."""
    if sh.root():
        return False
    lib = library()
    if lib is None:
        return False
    try:
        return bool(lib.needs_password(sh, *command))
    except Exception:  # noqa: BLE001 - a check that cannot say: the field is shown, sudo takes it or says why
        return True


def turn_on(sh, password: str, which) -> list[str]:
    """Root access turned on with the password typed (each step as root through sudo -S, the password on its standard
    input): the group liminal made where there is none (groupadd, or BusyBox's addgroup), the platform's user put in
    it (usermod -a -G, or addgroup), then the library's grant for that group. What was done, in words; WrongPassword
    when sudo refuses the password (nothing done), CommandError in the step's words with what was done before it."""
    lib = library()
    if lib is None:
        raise ValueError(f"not from here: {old_words()}")
    lines: list[str] = []
    with refusals(lines):
        who = user()
        if not who:
            raise CommandError("the user the platform runs as could not be told")
        there, member, _ = membership(who)
        if not there:
            make = (("groupadd", "--system", GROUP) if which("groupadd") else
                    ("addgroup", "-S", GROUP) if which("addgroup") else None)
            if make is None:
                raise CommandError(f"neither groupadd nor addgroup is here to make the group {GROUP}")
            run(sh, *make, password=password)
            lines.append(f"the group {GROUP} made ({' '.join(make)})")
        if not member:
            put = (("usermod", "-a", "-G", GROUP, who) if which("usermod") else
                   ("addgroup", who, GROUP) if which("addgroup") else None)
            if put is None:
                raise CommandError(f"neither usermod nor addgroup is here to put {who} in the group {GROUP}")
            run(sh, *put, password=password)
            lines.append(f"{who} put in the group {GROUP} ({' '.join(put)})")
        installed = lib.grant(sh, NAME, FILES, password=password, group=GROUP, why=WHY)
    lines += [f"installed as root: {p}" for p in installed]
    lines.append(f"{Paths.here().rule}: checked with visudo -cf, then put in place")
    return lines + installed.notes  # and how the rule was made, where the grant said it


def turn_off(sh, password=None) -> list[str]:
    """Root access turned off: the grant's take-back helper run (sudo -n: the grant lets it run without a password),
    or, where it cannot run yet, the same removal as root with the password typed. What was done, in words."""
    lib = library()
    if lib is None:
        raise ValueError(f"not from here: {old_words()}")
    paths = Paths.here()
    with refusals():
        lib.revoke(sh, NAME, password=password or None)
    return [f"removed: {paths.rule} and {paths.folder}",
            f"the group {GROUP} and its members stay: the Linux administration plugin manages them"]
