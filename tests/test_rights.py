"""Root access (0.9.0; the user, 2026-11-17: "the plugin needs to be able to handle permissions if required"; "A field
on its page"; "(enable / disable)", "but only if required"), over recorded machines and a stand-in sudo (tests/sudo.py:
nothing runs). Every state of the switch: not required as root, not required by the user's own rule, off, turned on (in
force from the platform's next start), on, an installed read that is not this plugin's; nftables' install offered only
without a firewall tool, its size said first; the password field only where it is required; the password handed to sudo
on its standard input alone, never in an argument, an environment, a log, an answer or an error's words, nor kept; the
hooks taking their forms' fields in the platform's order, a second confirmation included; what WSL lacks; and a library
from before the grant, where the plugin works as 0.8.1 did."""
from __future__ import annotations

import base64
import inspect
import json
import os
import re

import pytest

from liminal_libs.machines import linux as linux_mod
from liminal_libs.machines.firewall import Rule
from liminal_libs.machines.linux import Shell
from liminal_libs.machines.plugin import CommandError
from plugin_platform_firewall_linux import (CHANGE_FORMS, INSTALL, REFRESH, ROOT_FOR_READ, WSL_ROOT_ROW,
                                            LinuxFirewallPlugin)
from plugin_platform_firewall_linux import netstat as netstat_mod
from plugin_platform_firewall_linux import rights
from plugin_platform_firewall_linux.changes import ACCEPT, Risky
from plugin_platform_firewall_linux.read import SCRIPT
from plugin_platform_firewall_linux.rights import PASSWORD_FIELD, WrongPassword

from machines import SUDO_S, FakeLinux, answer
from sudo import LISTING, NEEDS_PASSWORD, PASSWORD, WRONG, Sudo, installed_read

NEEDS = "What the firewall needs here"
# what the table says of the Netstat tab (0.9.0): no rights needed, with a library that has it
SERVED = "need no rights" if netstat_mod.library() else "not in this library"
BARE_TOOLS = "ip /usr/sbin/ip\nss /usr/bin/ss"  # the user's Ubuntu in WSL: no nft, iptables, ufw or firewall-cmd
FIXED = {"name": "state", "label": "Root access", "type": "fixed"}


def table(st: dict, title: str) -> dict:
    return next(t for t in st["tables"] if t["title"] == title)


def form(st: dict, fid: str) -> dict:
    return next(f for f in st["forms"] if f["id"] == fid)


def ids(st: dict) -> list[str]:
    return [f["id"] for f in st.get("forms", [])]


def first_cells(t: dict) -> list:
    return [(r["cells"] if isinstance(r, dict) else r)[0] for r in t["rows"]]


def everywhere(*things) -> str:
    """Everything given as one text: statuses, answers, lines, the plugin's own attributes (whatever it keeps)."""
    return json.dumps(things, default=lambda o: getattr(o, "__dict__", repr(o)) if not callable(o) else repr(o))


# -- not required: as root, or by a rule of the user's own -------------------------------------------------------------
def test_not_shown_where_the_platform_is_root(monkeypatch):
    sudo = Sudo("debian-13-nftables", root=True)
    fw = sudo.install(monkeypatch)
    st = fw.status()
    assert st["valid"] and st["rootAccess"] == rights.ROOT == ("the platform runs as root: the firewall is read and "
                                                              "changed as root, without sudo")
    assert "Root access" not in first_cells(table(st, "Firewall")) and NEEDS not in [t["title"] for t in st["tables"]]
    assert not {"root-on", "root-off", "install-nftables"} & set(ids(st))
    assert all(PASSWORD_FIELD not in f["fields"] for f in st["forms"])  # no change asks for a password
    assert sudo.calls == [["sh", "-c", SCRIPT]]  # as root: no sudo at all, its policy not asked
    with pytest.raises(ValueError, match="not needed here: the platform runs as root"):
        fw.root_access("on", PASSWORD)
    fw.make_rule("web", "in", "allow", "tcp", "8443")
    assert sudo.calls[-1][:2] == ["nft", "add"] and PASSWORD not in everywhere(sudo.calls, sudo.fed)


def test_not_shown_where_a_rule_of_the_users_own_runs_the_read(monkeypatch):
    sudo = Sudo("debian-13-nftables", own=True)
    fw = sudo.install(monkeypatch)
    asked: list = []  # what the library's needs_password was asked of, before it read sudo's listing
    monkeypatch.setattr(linux_mod, "needs_password", lambda shell, *c: asked.append(c) or NEEDS_PASSWORD(shell, *c))
    st = fw.status()
    assert st["valid"] and st["rootAccess"] == rights.OWN == ("sudo runs its read without a password, by a rule of "
                                                             "your own: Root access is not needed")
    assert sudo.calls[0] == ["sudo", "-n", "sh", "-c", SCRIPT]  # 0.8.1's read, which the rule allows
    assert "Root access" not in first_cells(table(st, "Firewall")) and not {"root-on", "root-off"} & set(ids(st))
    assert all(PASSWORD_FIELD not in f["fields"] for f in st["forms"])  # sudo's policy says none is needed
    fw.status()
    assert asked == [("nft",)] and sudo.calls.count(LISTING) == 1  # for the tool in charge, once per read
    with pytest.raises(ValueError, match="not needed here: sudo runs its read without a password"):
        fw.root_access("on", PASSWORD)


# -- off: valid without root, offering only what it can do ------------------------------------------------------------
def test_off_the_rules_are_not_read_and_turn_on_is_offered_with_its_words(monkeypatch):
    sudo = Sudo("debian-13-nftables")
    fw = sudo.install(monkeypatch)
    st = fw.status()
    assert (st["valid"], st["why"], st["summary"]) == (True, "", "not read: Root access is off")
    assert st["problem"] == ("The firewall's rules are not read: sudo asks for a password, and Root access is off "
                             "(Turn on… below gives the read alone root, with your password once).")
    assert st["rootAccess"] == rights.OFF == "off: the firewall's rules are not read"
    needs = table(st, NEEDS)
    assert [c["title"] for c in needs["columns"]] == ["What", "Here", "What to do", ""]
    root, tool, netstat = needs["rows"]
    assert root[:2] == ["Root access", "off: the firewall's rules are not read"]
    assert root[2].startswith("Turn on… gives")
    assert root[3] == {"form": "root-on", "title": "Turn on…", "values": {"state": "on"},
                       "label": "Turn Root access on"}
    assert tool == ["A firewall tool", "nftables, iptables installed", "none needed", ""]
    # 0.9.0: the Netstat tab and the hosts database need no rights, and are served meanwhile (B-revisions S2)
    assert netstat[:2] == ["Netstat and the hosts database", SERVED] and netstat[3] == ""
    assert ids(st) == ["root-on"] and st["actions"] == [REFRESH]  # no change it cannot make
    on = form(st, "root-on")
    assert on["hook"] == "root_access" and on["fields"] == [FIXED, PASSWORD_FIELD]
    assert PASSWORD_FIELD == {"name": "password", "label": "Your password for sudo", "type": "password",
                              "required": True, "note": "used for this once, never kept"}
    p = rights.Paths.here()
    assert (p.read, p.helper, p.rule) == ("/usr/local/libexec/liminal/firewall-linux/read",
                                         "/usr/local/libexec/liminal/firewall-linux/take-back",
                                         "/etc/sudoers.d/liminal-firewall-linux")
    for said in (p.read, p.helper, p.rule, "visudo", "open to the group liminal alone", "with no arguments",
                 "never every command", "you (sysop) put in it", "handed to sudo for this once and never kept"):
        assert said in on["note"], said
    assert on["confirm"]["words"].startswith("Anything running as you (sysop), or as another member of the group "
                                             "liminal, can then run that one read as root.")
    assert "takes effect once the platform is started again" in on["confirm"]["words"]
    hooks = fw.interface()["hooks"]
    assert all(f["hook"] in hooks for f in st["forms"]) and "world" in hooks  # valid: its tabs are asked too
    fw.status(), fw.present()
    assert sudo.calls.count(["sudo", "-n", "sh", "-c", SCRIPT]) == 1  # a refusal kept as long as a read
    fw.refresh  # noqa: B018 - Refresh reads again (and is refused again)
    with pytest.raises(Exception, match="needs root"):
        fw.refresh()
    assert sudo.calls.count(["sudo", "-n", "sh", "-c", SCRIPT]) == 2


def test_turned_on_it_makes_the_group_and_the_grant_with_the_password_once_in_force_from_the_next_start(monkeypatch):
    sudo = Sudo("debian-13-nftables")
    fw = sudo.install(monkeypatch)
    fw.status()
    with pytest.raises(ValueError, match="your password for sudo is needed"):
        fw.root_access("on")
    out = fw.root_access("on", PASSWORD)
    ran = sudo.run_as_root
    assert ran[:2] == [["groupadd", "--system", "liminal"], ["usermod", "-a", "-G", "liminal", "sysop"]]
    assert [c[:2] for c in ran[2:]] == [["sh", "-c"]] and "liminal-granted" in ran[2][2]  # the grant: an argument
    texts = blobs(ran[2][2])  # the library's grant script: the plugin's read as installed, the group's rule, its why
    assert installed_read() in texts
    assert any(t.startswith(f"# Installed by the Liminal platform for firewall-linux: {rights.WHY}. ")
               and "\n%liminal ALL=(root) " in t for t in texts)
    given = [f for c, f in zip(sudo.calls, sudo.fed) if c[:len(SUDO_S)] == SUDO_S]
    assert len(given) == 3 and all(f == f"{PASSWORD}\n" for f in given)  # alone on standard input, each time
    assert out["lines"][:2] == ["the group liminal made (groupadd --system liminal)",
                                "sysop put in the group liminal (usermod -a -G liminal sysop)"]
    assert out["said"].startswith("Root access is on from the platform's next start")
    st = fw.status()
    assert st["valid"] and st["summary"] == "not read: Root access is on from the platform's next start"
    assert st["problem"].startswith("Root access is on from the platform's next start: the firewall's rules are read")
    root = table(st, NEEDS)["rows"][0]
    assert root[1] == rights.PENDING and "a terminal opened after it was turned on" in root[2]
    assert root[3]["form"] == "root-off" and ids(st) == ["root-off"]
    assert form(st, "root-off")["fields"] == [FIXED, PASSWORD_FIELD]  # its helper cannot run yet: the password asked
    assert ["sudo", "-n", sudo.paths.read] not in sudo.calls  # nothing installed is run before it is in force
    with pytest.raises(ValueError, match="your password for sudo is needed: the take-back helper cannot run"):
        fw.root_access("off")
    out = fw.root_access("off", PASSWORD)
    assert ["sudo", "-n", sudo.paths.helper] in sudo.calls  # then sudo -S, the cleanup an argument of sh -c
    assert sudo.run_as_root[-1][:2] == ["sh", "-c"] and "rm -rf" in sudo.run_as_root[-1][2]
    assert out["said"].startswith("Root access is off") and fw.status()["rootAccess"] == rights.OFF


def test_on_the_read_runs_the_installed_file_through_sudo_n_and_every_change_asks_the_password(monkeypatch):
    sudo = Sudo("debian-13-nftables", state="on")
    fw = sudo.install(monkeypatch)
    st = fw.status()
    assert st["valid"] and st["rootAccess"] == rights.ON == "on: a rule lets its read run as root, nothing else"
    assert ["sudo", "-n", sudo.paths.read] in sudo.calls and ["sudo", "-n", "sh", "-c", SCRIPT] not in sudo.calls
    first = sudo.calls.index  # compared with the plugin's own read first (the library's granted), then run
    assert first(["cat", "--", sudo.paths.read]) < first(["sudo", "-n", sudo.paths.read])
    parts = table(st, "Firewall")
    [root] = [r for r in parts["rows"] if r[0] == "Root access"]
    assert root[1] == rights.ON and root[3]["text"] == sudo.paths.read and sudo.paths.rule in root[3]["sub"]
    assert root[4] == {"form": "root-off", "title": "Turn off…", "values": {"state": "off"},
                       "label": "Turn Root access off"}
    changing = [f for f in st["forms"] if f["id"] in CHANGE_FORMS]
    assert {f["id"] for f in changing} == set(CHANGE_FORMS) and all(f["fields"][-1] == PASSWORD_FIELD for f in changing)
    assert all(PASSWORD_FIELD not in f["fields"] for f in st["forms"] if f["id"] not in CHANGE_FORMS)
    assert form(st, "root-off")["fields"] == [FIXED]  # the take-back helper runs without one
    assert NEEDS not in [t["title"] for t in st["tables"]]
    fw.make_rule("web", "in", "allow", "tcp", "8443", None, None, False, PASSWORD)
    i = max(i for i, c in enumerate(sudo.calls) if c[:len(SUDO_S)] == SUDO_S)
    assert sudo.calls[i][len(SUDO_S):len(SUDO_S) + 2] == ["nft", "add"] and sudo.fed[i] == f"{PASSWORD}\n"
    # asked without the password it needs (the framework's setup, the command line): refused in words, sudo not asked
    before = len(sudo.calls)
    with pytest.raises(CommandError, match="needs your password for sudo, and nothing here asks for it"):
        fw.allow("mail", (2525,))
    assert not [c for c in sudo.calls[before:] if c[:len(SUDO_S)] == SUDO_S or c[:3] == ["sudo", "-n", "nft"]]
    fw.wanted = lambda: [Rule("mail-example-test", ports=(25, 587))]  # the framework's setup: a rule to make
    done = {d["step"]: d for d in fw.setup(log=lambda line: None)}
    assert done["rules"]["ok"] is False and "needs your password for sudo" in done["rules"]["detail"]
    before = len(sudo.calls)
    out = fw.root_access("off")
    assert ["sudo", "-n", sudo.paths.helper] in sudo.calls[before:] and out["said"].startswith("Root access is off")
    assert not [f for f in sudo.fed[before:] if f]  # no password handed for it
    assert fw.status()["rootAccess"] == rights.OFF


def test_an_installed_read_that_is_not_the_plugins_own_is_not_run_and_turn_on_again_replaces_it(monkeypatch):
    sudo = Sudo("debian-13-nftables", state="stale")
    fw = sudo.install(monkeypatch)
    st = fw.status()
    assert st["valid"] and st["rootAccess"] == rights.STALE and ["sudo", "-n", sudo.paths.read] not in sudo.calls
    root = table(st, NEEDS)["rows"][0]
    assert root[:2] == ["Root access", "on, but its read installed is an older plugin's: it is not run"]
    assert root[3]["form"] == "root-on" and ids(st) == ["root-on", "root-off"]
    assert form(st, "root-off")["fields"] == [FIXED]
    out = fw.root_access("on", PASSWORD)
    assert [c[:2] for c in sudo.run_as_root] == [["sh", "-c"]]  # group and membership there already: the grant alone
    assert out["said"].startswith("Root access is on: the firewall's read runs as root")
    st = fw.status()
    assert st["rootAccess"] == rights.ON and sudo.reads == 1 and ["sudo", "-n", sudo.paths.read] in sudo.calls


def test_a_password_sudo_refuses_is_a_refusal_and_nothing_is_changed(monkeypatch):
    sudo = Sudo("debian-13-nftables")
    fw = sudo.install(monkeypatch)
    with pytest.raises(WrongPassword, match="sudo did not accept the password: nothing was changed") as e:
        fw.root_access("on", "not-the-password")
    assert isinstance(e.value, ValueError)  # the platform's 400: the form is filled again
    assert (sudo.state, sudo.group, sudo.member) == ("", False, False)
    on = Sudo("debian-13-nftables", state="on")
    fw = on.install(monkeypatch)
    with pytest.raises(WrongPassword) as again:
        fw.make_rule("web", "in", "allow", "tcp", "8443", None, None, False, "not-the-password")
    tried = [c[len(SUDO_S):] for c in on.calls if c[:len(SUDO_S)] == SUDO_S]
    assert [c[:1] for c in tried] == [["nft"]]  # tried once, refused by sudo before nft ran
    assert "not-the-password" not in everywhere(on.calls, str(e.value), str(again.value))


def test_a_failure_is_said_as_it_is_before_any_step_and_with_the_steps_done_after_one():
    """rights.refusals, around a change's steps, Turn on…'s and Turn off…: a refused password is a WrongPassword (the
    form is filled again) only while nothing is done; after a step, it and any other failure say what was done."""
    done: list = []
    with pytest.raises(WrongPassword):
        with rights.refusals(done):
            raise WrongPassword(rights.WRONG)
    with pytest.raises(CommandError, match="^nft: no$") as e:
        with rights.refusals(done):
            raise CommandError("nft: no", denied=True)
    assert e.value.denied
    done.append("the group liminal made")
    for raised, words, denied in ((WrongPassword(rights.WRONG), rights.WRONG, False),
                                  (CommandError("nft: no", denied=True), "nft: no", True)):
        with pytest.raises(CommandError) as e:
            with rights.refusals(done):
                raise raised
        assert (str(e.value), e.value.denied) == (f"{words} (done before it: the group liminal made)", denied)


# -- nftables installed where no tool is -------------------------------------------------------------------------------
def test_install_nftables_is_offered_only_without_a_firewall_tool_its_size_said_first(monkeypatch):
    bare = Sudo("ubuntu-24.04-ufw", tools=BARE_TOOLS)
    fw = bare.install(monkeypatch)
    st = fw.status()
    assert st["valid"]
    assert st["problem"].endswith("No firewall tool is installed here (nftables, iptables, ufw, firewalld).")
    root, tool, netstat = table(st, NEEDS)["rows"]
    assert netstat[:2] == ["Netstat and the hosts database", SERVED]  # 0.9.0: served without a tool
    words = ("Ubuntu's own nftables package 1.0.9-1ubuntu0.1, with the 2 packages it needs that are not installed yet "
             "(libnftnl11, libnftables1): 494 kB to download, 1.5 MB once installed")
    assert tool == ["A firewall tool", "none installed: no nft, iptables, ufw or firewall-cmd here",
                    f"Install nftables… installs {words}; installing it filters nothing",
                    {"form": "install-nftables", "title": "Install nftables…", "values": {},
                     "label": "Install nftables"}]
    assert ids(st) == ["root-on", "install-nftables"]
    f = form(st, "install-nftables")
    assert f["job"] is True and f["hook"] == "install_nftables" and f["fields"] == [PASSWORD_FIELD]
    assert "install_nftables" in fw.JOB_HOOKS and f["note"].startswith(words[:1].upper() + words[1:])
    assert f["confirm"]["words"].startswith("Installing it filters nothing")
    read = [c for c in bare.calls if "apt-get" in c or "apt-cache" in c]  # read without root, changing nothing
    assert read == [["env", "LC_ALL=C", "apt-get", "-s", "install", "nftables"],
                    ["env", "LC_ALL=C", "apt-cache", "show", "--no-all-versions", "libnftnl11", "libnftables1",
                     "nftables"]]
    fw.status()
    assert len([c for c in bare.calls if "apt-cache" in c]) == 1  # kept install.FACTS_S
    lines: list = []
    out = fw.install_nftables(PASSWORD, log=lines.append)
    assert bare.run_as_root == [["env", "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C", "apt-get", "install", "-y",
                                 "nftables"]]
    i = next(i for i, c in enumerate(bare.calls) if c[:len(SUDO_S)] == SUDO_S)
    assert bare.fed[i] == f"{PASSWORD}\n"
    assert lines[0] == f"Installing {words}." and "filters nothing" in lines[1]
    assert lines[-1] == "Setting up nftables (1.0.9-1ubuntu0.1) ..." and out["said"].startswith("nftables installed:")
    st = fw.status()  # nft there now: no install offered
    assert "install-nftables" not in ids(st) and table(st, NEEDS)["rows"][1][1] == "nftables installed"
    with pytest.raises(ValueError, match="nftables is installed here already"):
        fw.install_nftables(PASSWORD)


def test_install_says_an_apt_lock_and_a_failed_fetch_in_words(monkeypatch):
    bare = Sudo("ubuntu-24.04-ufw", tools=BARE_TOOLS)
    fw = bare.install(monkeypatch)
    bare.apt_fails = ("E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4242 "
                      "(unattended-upgr)\n"
                      "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process "
                      "using it?")
    with pytest.raises(Exception, match=r"apt is busy: another program holds its lock .* nothing was installed"):
        fw.install_nftables(PASSWORD)
    bare.apt_fails = ("E: Failed to fetch nftables_1.0.9-1ubuntu0.1_amd64.deb  404  Not Found\n"
                      "E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?")
    with pytest.raises(Exception, match=r"a package could not be downloaded: .*sudo apt-get update"):
        fw.install_nftables(PASSWORD)
    with pytest.raises(WrongPassword):
        fw.install_nftables("not-the-password")


def test_install_is_not_offered_without_apt_nor_where_a_tool_is(monkeypatch):
    bare = Sudo("ubuntu-24.04-ufw", tools=BARE_TOOLS)
    fw = bare.install(monkeypatch, which=lambda tool: None)  # no apt here either (Fedora, Arch, Alpine, Gentoo...)
    st = fw.status()
    assert st["valid"] and "install-nftables" not in ids(st)
    assert table(st, NEEDS)["rows"][1] == ["A firewall tool",
                                           "none installed: no nft, iptables, ufw or firewall-cmd here", INSTALL, ""]
    assert not [c for c in bare.calls if "apt-get" in c or "apt-cache" in c]  # nothing asked of apt
    with pytest.raises(ValueError, match="there is no apt here"):
        fw.install_nftables(PASSWORD)
    with_tool = Sudo("ubuntu-24.04-ufw")
    assert "install-nftables" not in ids(with_tool.install(monkeypatch).status())
    # as root with no tool: valid, the install offered with no password field (nothing to hand to sudo)
    root = Sudo("ubuntu-24.04-ufw", root=True, tools=BARE_TOOLS)
    root.sections = {k: v for k, v in root.sections.items() if not k.startswith(("ufw", "nft", "ip"))}
    st = root.install(monkeypatch).status()
    assert (st["valid"], st["summary"]) == (True, "no firewall software here") and "rootAccess" in st
    assert form(st, "install-nftables")["fields"] == [] and "root-on" not in ids(st)


# -- the password: on sudo's standard input alone, nowhere else --------------------------------------------------------
def test_the_password_never_reaches_an_argument_an_environment_a_log_an_answer_or_an_error(monkeypatch):
    seen: list = []  # every status, answer, log line and error's words
    bare = Sudo("ubuntu-24.04-ufw", tools=BARE_TOOLS)
    fw = bare.install(monkeypatch)
    seen.append(fw.status())
    seen.append(fw.install_nftables(PASSWORD, log=seen.append))
    seen.append(fw.root_access("on", PASSWORD))
    seen.append(fw.status())
    bare.active = True  # the platform started again: the group is its own now
    fw.forget()
    seen.append(fw.status())
    for bad in ("x", PASSWORD[:-1]):
        try:
            fw.make_rule("web", "in", "allow", "tcp", "8443", None, None, False, bad)
        except Exception as e:  # noqa: BLE001 - its words kept
            seen.append(str(e))
    seen.append(fw.root_access("off"))
    seen.append(fw.api_facts())
    echo = Sudo("ubuntu-24.04-ufw", tools=BARE_TOOLS)  # a tool echoing it back in its errors: never in the words said
    echo.apt_fails = f"E: something went wrong near {PASSWORD}"
    try:
        echo.install(monkeypatch).install_nftables(PASSWORD, log=seen.append)
    except Exception as e:  # noqa: BLE001 - its words kept
        seen.append(str(e))
    bare.calls += echo.calls
    bare.fed += echo.fed
    assert bare.calls and PASSWORD not in everywhere(bare.calls)  # never in an argument
    assert PASSWORD not in everywhere(seen)
    assert PASSWORD not in everywhere(vars(fw))  # nor kept by the plugin
    assert PASSWORD not in json.dumps(dict(os.environ))  # nor put in an environment
    handed = [f for c, f in zip(bare.calls, bare.fed) if f and PASSWORD in f]
    assert handed and all(f == f"{PASSWORD}\n" for f in handed)  # alone: nothing after it to be read as more
    assert all(c[:len(SUDO_S)] == SUDO_S for c, f in zip(bare.calls, bare.fed) if f and PASSWORD in f)


# -- the hooks: their forms' fields in the platform's order ------------------------------------------------------------
def platform_args(f: dict, values: dict, accepted=()) -> list:
    """A hook's arguments as the platform's page sends them (platform.js argsOf): each field's value in the form's
    order, an accept field true only through its own second confirmation, a field left empty as null."""
    out = []
    for x in f["fields"]:
        if x["type"] == "accept":
            out.append(x["name"] in accepted)
            continue
        v = values.get(x["name"], x.get("value"))
        out.append(None if v in (None, "") else v)
    return out


def test_every_hook_takes_its_forms_fields_in_the_platforms_order_a_second_confirmation_included(monkeypatch):
    statuses = []
    for state in ("on", "stale", ""):
        statuses.append(Sudo("debian-13-nftables", state=state).install(monkeypatch).status())
    statuses.append(Sudo("ubuntu-24.04-ufw", tools=BARE_TOOLS).install(monkeypatch).status())
    fw = LinuxFirewallPlugin()
    checked = set()
    for st in statuses:
        for f in st["forms"]:
            params = [n for n in inspect.signature(getattr(fw, f["hook"])).parameters if n != "log"]
            names = [x["name"] for x in f["fields"]]
            assert names == params[:len(names)], (f["id"], names, params)
            if PASSWORD_FIELD in f["fields"]:
                assert names[-1] == params[-1] == "password", f["id"]
            checked.add(f["id"])
    assert set(CHANGE_FORMS) | {"root-on", "root-off", "install-nftables"} <= checked
    # what a risky change's form sends, then its second confirmation: the password both times, run once accepted
    sudo = Sudo("debian-13-nftables", state="on")
    fw = sudo.install(monkeypatch)
    remove = form(fw.status(), "remove")
    values = {"where": "inet filter input", "rule": 'tcp dport 22 counter accept comment "ssh"', "password": PASSWORD}
    before = len(sudo.calls)
    with pytest.raises(Risky, match="what lets SSH in") as e:
        fw.ask("remove_rule", *platform_args(remove, values))
    assert e.value.accept == ACCEPT and not [c for c in sudo.calls[before:] if c[:len(SUDO_S)] == SUDO_S]
    fw.ask("remove_rule", *platform_args(remove, values, accepted=[e.value.accept]))
    i = max(i for i, c in enumerate(sudo.calls) if c[:len(SUDO_S)] == SUDO_S)
    assert sudo.calls[i][len(SUDO_S):] == ["nft", "delete", "rule", "inet", "filter", "input", "handle", "10"]
    assert sudo.fed[i] == f"{PASSWORD}\n"
    # Root access's own forms, as the page sends them
    off = form(fw.status(), "root-off")
    assert fw.ask("root_access", *platform_args(off, {"state": "off"}))["said"].startswith("Root access is off")
    on = form(fw.status(), "root-on")
    assert platform_args(on, {"state": "on", "password": PASSWORD}) == ["on", PASSWORD]
    fw.ask("root_access", *platform_args(on, {"state": "on", "password": PASSWORD}))
    assert fw.status()["rootAccess"] == rights.ON


# -- under WSL ---------------------------------------------------------------------------------------------------------
def test_under_wsl_it_says_what_wsl_lacks_and_what_the_switch_does_there(monkeypatch):
    under = {"title": "Under WSL", "note": "What running inside a WSL distribution changes for this plugin.",
             "columns": [{"title": "What"}, {"title": "Here"}, {"title": "What it means"}],
             "rows": [["Packet filter", "the kernel's own",
                       "nftables and iptables work here once their tools are installed"]]}
    monkeypatch.setattr(linux_mod, "wsl_table", lambda kind, *a, **k: under if kind == "firewall" else None,
                        raising=False)
    st = Sudo("debian-13-nftables").install(monkeypatch).status()
    wsl = st["tables"][-1]
    assert wsl["title"] == "Under WSL" and wsl["rows"] == [*under["rows"], WSL_ROOT_ROW] and len(under["rows"]) == 1
    assert WSL_ROOT_ROW[:2] == ["Root access", "sudo inside this distribution, as on any Linux"]
    for said in ("wsl -u root", "the platform never does, nor reaches in from Windows", "whose password is yours",
                 "this distribution's alone", "started again from a terminal opened after"):
        assert said in WSL_ROOT_ROW[2], said
    assert Sudo("debian-13-nftables", root=True).install(monkeypatch).status()["tables"][-1] is under  # not required


def test_a_distribution_reached_from_windows_is_refused_as_before_and_its_status_says_so(monkeypatch):
    ran: list = []

    def runner(args, timeout):
        ran.append(args)
        return 0, "", ""
    p = LinuxFirewallPlugin(shell=Shell("wsl:Liminal-Ubuntu", runner=runner), native="")
    st = p.status()
    assert st["valid"] is False and "never WSL's Liminal-Ubuntu" in st["why"] and ran == []
    with pytest.raises(Exception, match="never WSL's Liminal-Ubuntu"):
        p.root_access("on", PASSWORD)
    assert ran == []


# -- a library from before the grant: as 0.8.1 -------------------------------------------------------------------------
def test_with_a_library_from_before_the_grant_it_works_as_0_8_1_and_says_the_switch_needs_1_62_0(monkeypatch):
    for name in rights.NAMES:
        monkeypatch.delattr(linux_mod, name, raising=False)
    monkeypatch.setattr(netstat_mod, "library", lambda: False)  # nor the Netstat tab (liminal-libs 1.65.0), later still
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 1000, raising=False)
    ran: list = []

    def refused(args, timeout):
        ran.append(list(args))
        return 1, b"", b"sudo: a password is required"
    fw = LinuxFirewallPlugin(shell=Shell("local", runner=refused), native="", which=lambda tool: None)
    st = fw.status()
    assert (st["valid"], st["why"].startswith("cannot be read: sh needs root")) == (False, True)
    assert "rootAccess" not in st and "forms" not in st and "actions" not in st
    needs = table(st, NEEDS)
    assert [c["title"] for c in needs["columns"]] == ["What", "Here", "What to do"]
    assert needs["rows"][0][:2] == ["Root for the read", "sudo asks for a password"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", rights.NEEDS_LIBS)  # the library with the grant: its number, set at landing
    assert needs["rows"][0][2].startswith(ROOT_FOR_READ + "; its Root access switch, which asks for your password "
                                          f"once, needs liminal-libs {rights.NEEDS_LIBS} (this one is ")
    assert needs["rows"][1] == ["A firewall tool", "none installed: no nft, iptables, ufw or firewall-cmd here",
                                INSTALL]
    assert needs["rows"][2][:2] == ["Netstat and the hosts database", "not in this library"]  # what 0.9.0 would add
    assert needs["rows"][2][2].startswith(f"they need liminal-libs {netstat_mod.NETSTAT_LIBS} (this one is ")
    assert ran == [["sudo", "-n", "sh", "-c", SCRIPT]]  # 0.8.1's one read, sudo -n
    for ask in (lambda: fw.root_access("on", PASSWORD), lambda: fw.install_nftables(PASSWORD)):
        with pytest.raises(ValueError, match=re.escape(f"needs liminal-libs {rights.NEEDS_LIBS}")):
            ask()
    fake = FakeLinux("debian-13-nftables")  # and a read sudo allows: 0.8.1's page, no password field anywhere
    fw = LinuxFirewallPlugin(shell=Shell("local", runner=fake), native="")
    st = fw.status()
    assert st["valid"] and "rootAccess" not in st and all(PASSWORD_FIELD not in f["fields"] for f in st["forms"])
    assert "Root access" not in first_cells(table(st, "Firewall"))
    fw.make_rule("web", "in", "allow", "tcp", "8443", None, None, False, PASSWORD)  # a password given anyway: unused
    assert fake.calls[-1][:2] == ["sudo", "-n"] and PASSWORD not in everywhere(fake.calls)


# -- with the library's own sudo (liminal-libs 1.62.0, when it is installed) -------------------------------------------
HAS_LIBRARY = rights.library() is not None


def blobs(script: str) -> list[str]:
    """The texts a script carries as base64 (the library's grant carries the files and the rule so)."""
    out = []
    for token in re.findall(r"'([A-Za-z0-9+/=]{24,})'", script):
        try:
            out.append(base64.b64decode(token).decode("utf-8"))
        except ValueError:
            continue
    return out


@pytest.mark.skipif(not HAS_LIBRARY, reason="a library from before the grant (liminal-libs 1.62.0)")
def test_with_the_librarys_own_sudo_the_password_is_on_standard_input_alone_and_the_rule_is_narrow(monkeypatch):
    calls: list = []
    fed: list = []

    def runner(args, timeout, stdin):
        calls.append(list(args))
        fed.append(stdin)
        if args[:len(SUDO_S)] == SUDO_S and (stdin or "").split("\n", 1)[0] != PASSWORD:
            return 1, "", WRONG
        return (0, "liminal-granted\n", "") if args[len(SUDO_S):][:2] == ["sh", "-c"] else (0, "", "")
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 1000, raising=False)
    sh = Shell("local", runner=runner)
    with pytest.raises(WrongPassword):
        rights.turn_on(sh, "not-the-password", lambda tool: f"/usr/sbin/{tool}")
    calls.clear(), fed.clear()
    lines = rights.turn_on(sh, PASSWORD, lambda tool: f"/usr/sbin/{tool}")
    ran = [c[len(SUDO_S):] for c in calls]
    assert ran[:2] == [["groupadd", "--system", "liminal"], ["usermod", "-a", "-G", "liminal", "sysop"]]
    assert len(ran) == 3 and ran[2][:2] == ["sh", "-c"] and len(ran[2]) == 3  # the grant's script: an argument
    # the password alone on standard input, each time: nothing after it to be read as another try, or as a command
    assert all(c[:len(SUDO_S)] == SUDO_S for c in calls) and fed == [f"{PASSWORD}\n"] * 3
    assert PASSWORD not in everywhere(calls, lines)
    script = ran[2][2]
    assert script.splitlines()[0] == "exec </dev/null"  # none of it reads a password sudo did not take
    texts = blobs(script)
    # the read as the plugin runs it, installed as the library's helper: its own PATH, LC_ALL=C, no arguments
    installed = linux_mod.helper_text(rights.NAME, rights.read_text())
    assert installed in texts and installed.endswith(SCRIPT) and "visudo -cf" in script
    assert re.search(r"^PATH=/usr/local/sbin:\S*; export PATH$", installed, re.M)
    rules = [t for t in texts if "NOPASSWD" in t]
    paths = rights.Paths.here()
    assert len(rules) == 2 and all("NOPASSWD: ALL" not in r for r in rules)  # the rule, and its plain fallback
    assert f'%liminal ALL=(root) NOPASSWD:NOSETENV:EXEC: {paths.read} "", {paths.helper} ""' in rules[0]
    assert rules[0].startswith(f"# Installed by the Liminal platform for firewall-linux: {rights.WHY}. ")
    # where this system's visudo refuses NOSETENV and EXEC, the rule is made with NOPASSWD alone, and that is said
    said = ("liminal: this system's visudo refused NOSETENV and EXEC in the rule: the rule was made with NOPASSWD "
            "alone")
    monkeypatch.setattr(rights, "membership", lambda who, name=rights.GROUP: (True, True, False))
    sh = Shell("local", runner=lambda args, timeout, stdin: (0, f"{said}\nliminal-granted\n", ""))
    assert rights.turn_on(sh, PASSWORD, lambda tool: None)[-1] == said.removeprefix("liminal: ")


@pytest.mark.skipif(not HAS_LIBRARY, reason="a library from before the grant (liminal-libs 1.62.0)")
def test_with_the_librarys_own_granted_the_installed_read_is_compared_then_run(monkeypatch):
    fake = FakeLinux("debian-13-nftables")
    paths = rights.Paths.here()
    installed = {"text": linux_mod.helper_text(rights.NAME, rights.read_text())}  # as the library's grant installs it

    # sudo's listing as the library reads it (1.62.0: the rule that decides each file, never an exit code), the
    # grant's rule after the user's own, as Ubuntu's include folder puts it, its tags as sudo prints them
    listing = ("User sysop may run the following commands on liminal-test:\n    (ALL : ALL) ALL\n"
               f'    (root) NOSETENV: EXEC: NOPASSWD: {paths.read} "", {paths.helper} ""\n')

    def runner(args, timeout, stdin):
        fake.calls.append(list(args))
        if args[-2:-1] == ["--"] and args[0] == "cat":
            text = installed["text"] if args[-1] == paths.read else "#!/bin/sh\n" if args[-1] == paths.helper else None
            return (0, text, "") if text is not None else (1, "", "cat: No such file or directory")
        if args == list(linux_mod.SUDO_LIST):
            return 0, listing, ""
        if args == ["sudo", "-n", paths.read]:
            fake.reads += 1
            return 0, answer(fake.sections), ""
        return 1, "", "sudo: a password is required"
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(rights, "exists", lambda path: path == paths.rule)
    fw = LinuxFirewallPlugin(shell=Shell("local", runner=runner), native="", clock=lambda: 1000.0)
    st = fw.status()
    assert st["valid"] and st["rootAccess"] == rights.ON and fake.reads == 1
    assert ["cat", "--", paths.read] in fake.calls and ["sudo", "-n", "sh", "-c", SCRIPT] not in fake.calls
    installed["text"] = "#!/bin/sh\necho an older plugin's read\n"
    fw.forget()
    st = fw.status()
    assert st["rootAccess"] == rights.STALE and fake.reads == 1  # not run
    # this plugin's read as it was installed before helper_text, finding its tools in whatever PATH sudo hands it: not
    # run either, and Turn on... installs it again (the release review, 2026-11-18)
    installed["text"] = rights.read_text()
    fw.forget()
    assert fw.status()["rootAccess"] == rights.STALE and fake.reads == 1
