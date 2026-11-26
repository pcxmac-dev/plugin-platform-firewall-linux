"""The World Wide Web tab as this plugin has it (the library's Firewall base, liminal-libs 1.55.0; the user, 2026-11-14: "so
for the firewall's both are going to get a 'world wide web view' that shows the globe and the routes incoming all
traffic, as well as monitoring port traffic stats"). The tab, its hooks and its setting are the base's. Its GeoIP file is
DB-IP's Lite City, downloaded from DB-IP's own address (this month's, last month's while this month's is not out) only
once its licence is accepted, through a refusal the platform asks as a second confirmation, and DB-IP is credited
wherever places are. Home is the place the user set through the login, else the public address this plugin's name
servers (hw-stats's own) give. Watching starts with an ask and stops by itself after the viewing timeout, and on detach;
a capture that cannot run says why, never asking for a password, and advises the right to capture only when libpcap
says it is missing and the platform is not root: CAP_NET_RAW alone, for the platform alone, never the system's Python,
never CAP_NET_ADMIN. What an XDP program at the adapter drops is said unseen, from the firewall's read kept. What the
tab learned is on its cards, asking nothing, through the base's world_view(make=False). Inside a WSL distribution the
page ends with what WSL changes for it (the library's world.under_wsl); on Windows and macOS nothing is made at all.

Since 0.12.0, with liminal-libs 1.101.0, the install buttons are the GeoIP sources table: DB-IP's two files offered,
downloaded only for a person signed in at the platform's page (a stand-in store, Store), their acceptance kept there and
never in the licences file; IPinfo Lite named and not offered.

Nothing is captured, downloaded or asked of a name server: the capture, the download and the lookup are stand-ins, the
GeoIP files tiny ones written here (mmdb_file.py), and libpcap, the route, nslookup and urllib fail the test if reached.
The machine's commands are a stand-in that keeps every one: the tab runs none."""
from __future__ import annotations

import contextlib
import gzip
import hashlib
import inspect
import json
import io
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import pytest

from liminal_libs import capture, dns, geo, netpath
from liminal_libs.apps import Login, Unauthorized, as_user
from liminal_libs.apps.asking import PAGE, asking
from liminal_libs.apps.authorization import LICENCE, EnvironmentLogin
from liminal_libs.apps.tabs import Tab
from liminal_libs.capture import ACK, PSH, SYN, CaptureError, Packet
from liminal_libs.machines import geosources, world
from liminal_libs.machines.firewall import Firewall
from liminal_libs.machines.linux import Shell, why_not_native
from liminal_libs.machines.world import LicenceRefused, WorldView, servers_of
from liminal_libs.sources.conformance import problems
from liminal_libs.traffic import TrafficBook

from plugin_platform_firewall_linux import MACHINE, LinuxFirewallPlugin, xdp_words
from plugin_platform_firewall_linux import apis as cards
from plugin_platform_firewall_linux import netstat as netstat_mod
from plugin_platform_firewall_linux.read import Config
from plugin_platform_firewall_linux.system import Interface, System

from machines import FakeLinux
from mmdb_file import NOVEMBER, OCTOBER, city, mmdb

try:  # the Netstat tab's view (liminal-libs 1.65.0), which the tab's every ask now reads for the hosts database
    from liminal_libs.machines.netstat import NetstatView
except ImportError:  # a library from before it: the tab reads no socket table
    NetstatView = None

# CI installs maxminddb (the library's geo extra): there these run, and fail rather than skip without it
needs_reader = pytest.mark.skipif(not geo.available()[0] and not os.environ.get("CI"),
                                  reason="maxminddb is not installed here")

LAN, ROUTER = "192.168.1.20", "192.168.1.1"
OWN = capture.own_addresses([LAN])
LONDON, CHANGCHUN = "81.2.69.142", "175.16.199.5"
PUBLIC = "8.8.8.8"  # this network's public address, as the stand-in name server says it
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc).timestamp()
NOVEMBER_FILE = "https://download.db-ip.com/free/dbip-city-lite-2026-11.mmdb.gz"  # as DB-IP's page gives it (2026-11-15)
OCTOBER_FILE = "https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz"
MARK = {"text": "IP Geolocation by DB-IP", "url": "https://db-ip.com"}
PLACES = [("81.2.69.0/24", city("GB", "United Kingdom", "London", 51.5142, -0.0931)),
          ("175.16.199.0/24", city("CN", "China", "Changchun", 43.88, 125.3228)),
          ("8.8.8.0/24", city("US", "United States", "Mountain View", 37.386, -122.0838))]
WINDOWS = why_not_native("The Linux firewall", "win32", "10", {})
# 0.12.0: the GeoIP sources' digest (sha256 of apis.GEOIP_SOURCES as canonical JSON: sorted keys, no spaces, UTF-8), the
# same the Windows firewall plugin's tests pin: the two plugins name the same sources in the same words, and a source
# changed changes both
GEOIP_SOURCES_SHA256 = "d51938accb2b636d7f4f261f1c5aeb8307cdf547060090aacacfbd069fa2ba95"
CC_BY = "https://creativecommons.org/licenses/by/4.0/"


class Store(Login):
    """A person's own login store, as the login app's session is (liminal-libs 1.101.0's tests have one): their pairs,
    settings kept. No key in it is a real one."""

    keeps_settings = True

    def __init__(self, name="alice", pairs=None):
        self.name, self.pairs, self.asked = name, dict(pairs or {}), []

    def user(self):
        return {"name": self.name}

    def vector(self, name):
        self.asked.append(name)
        if name not in self.pairs:
            raise Unauthorized("no such pair", 404)
        return self.pairs[name][1]

    def names(self):
        return set(self.pairs)

    def setting(self, name):
        kept = self.pairs.get(name)
        return json.loads(kept[1]) if kept else None

    def keep_setting(self, name, value, kind="preference", label=""):
        self.pairs[name] = (kind, json.dumps(value))
        return {"name": name, "kind": kind}


@pytest.fixture
def licences(tmp_path, monkeypatch):
    """The licences file the library keeps for programs (apps.accept_licence): never written by a GeoIP download."""
    path = tmp_path / "licences.json"
    monkeypatch.setenv("LIMINAL_LICENCES_FILE", str(path))
    return path


def cells(row) -> list:
    """A table row's cells as words: a cell's text, a button's title, "" for none."""
    return [c.get("text", c.get("title", "")) if isinstance(c, dict) else c for c in row]


def titles(page: dict) -> dict:
    """The page's tables by their titles."""
    return {t["title"]: t for t in page.get("tables") or ()}
MACOS = why_not_native("The Linux firewall", "darwin", "24.1.0", {})


def pk(at, src, sport, dst, dport, flags=0, proto="tcp", length=60) -> Packet:
    """A packet as a capture hands it, its direction judged against this machine's addresses."""
    return Packet(at, src, sport, dst, dport, flags, 0, proto, length, capture.judge(src, dst, OWN))


class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


class Feed:
    """A capture as a stand-in, pulled as a Watcher pulls one: opened, its packets handed, then nothing yet; closed."""

    def __init__(self, packets=(), address=LAN, fail_open=None):
        self.packets, self.address, self.fail_open = deque(packets), address, fail_open
        self.opened = self.closed = 0

    def open(self):
        if self.fail_open:
            raise CaptureError(self.fail_open)
        self.opened += 1

    def next(self):
        return self.packets.popleft() if self.packets else None

    def close(self):
        self.closed += 1


class Downloads:
    """The GeoIP downloads as a stand-in: each address asked for, and what it gives (bytes, or a 404)."""

    def __init__(self, answers):
        self.answers, self.asked = dict(answers), []

    def __call__(self, url, timeout):
        self.asked.append((url, timeout))
        got = self.answers.get(url, urllib.error.HTTPError(url, 404, "Not Found", {}, None))
        if isinstance(got, BaseException):
            raise got
        return io.BytesIO(got)


def socket_table(*rows, at: float = NOW) -> dict:
    """The kernel's socket tables as the library's sockets.read answers them on Linux, of the rows given (none by
    default): a stand-in, so the tab's every ask, which also reads them for the hosts database (liminal-libs 1.65.0),
    reads nothing real."""
    return {"system": "linux", "at": at, "awake": 100.0, "took": 0.004, "root": False, "starts": False,
            "read": ("tcp4", "tcp6", "udp4", "udp6"), "cut": False, "rows": list(rows), "notes": []}


class Watched(LinuxFirewallPlugin):
    """The plugin on a native Linux machine (or on one it is not for: `native` says why), its commands kept by a
    stand-in, its World Wide Web tab watching through the test's stand-ins (make_world_view, as the library's tests do),
    and (0.9.0) its Netstat view reading a stand-in socket table, with none of the plugin's data sets
    (make_netstat_view: the suite's guard refuses the real table, and keeps the hosts database in the test's own
    folder)."""

    def __init__(self, native: str = "", **view):
        self.commands = FakeLinux("debian-13-nftables")
        super().__init__(shell=Shell("local", runner=self.commands), native=native)
        view.setdefault("resolve", lambda version, servers: (None, "no name server answers in a test"))
        self.view_args, self.views, self.readings = view, 0, 0

    def make_world_view(self) -> WorldView:
        self.views += 1
        # 0.12.0: the plugin's GeoIP sources, as the base's make_world_view gives them (liminal-libs 1.101.0)
        return WorldView(self.name, timeout=self.WORLD_TIMEOUT, **{"sources": self.world_sources(), **self.view_args})

    def make_netstat_view(self):
        def reader() -> dict:
            self.readings += 1
            return socket_table()
        return NetstatView(self.name, reader=reader, names={}, login_of=lambda: getattr(self, "login", None),
                           listeners=self.netstat_listeners, clock=self.view_args.get("clock", time.monotonic),
                           wall=self.view_args.get("wall", time.time))


def wait_for(condition, seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.005)
    return condition()


def watching() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == "traffic-watcher"]


@pytest.fixture(autouse=True)
def _nothing_real(monkeypatch, tmp_path):
    """Nothing real is reached: no libpcap loaded, no route asked, no name server, no download, not this machine's data
    folder (each reach is noted, so one inside a thread is seen too). Each WorldView a test makes is stopped after it,
    and no thread is left."""
    reached: list[str] = []

    def refusing(name):
        def refuse(*args, **kwargs):
            reached.append(name)
            raise AssertionError(f"a test reached the real {name}")
        return refuse
    for module, name in ((capture, "load_pcap"), (netpath, "lan_address"), (world, "route_address"), (dns, "query"),
                         (world, "fetch_url"), (urllib.request, "urlopen")):
        monkeypatch.setattr(module, name, refusing(name))
    monkeypatch.setattr(geo, "data_folder", lambda: tmp_path / "data" / "geoip")
    made: list[WorldView] = []
    init = WorldView.__init__

    def tracked(self, *args, **kwargs):
        init(self, *args, **kwargs)
        made.append(self)
    monkeypatch.setattr(WorldView, "__init__", tracked)
    yield
    for view in made:
        view.stop()
    assert wait_for(lambda: watching() == []), "a watching thread was left"
    assert wait_for(lambda: not [t for t in threading.enumerate() if t.name.endswith("-public-address")])
    assert reached == []


def traffic_of(book: TrafficBook) -> None:
    """A little of a machine's traffic: a connection from London to this machine's 8765, answered; two attempts from
    Changchun at 3389, never answered; a question to the router and its answer (the local network's)."""
    for p in (pk(10.0, LONDON, 51000, LAN, 8765, SYN, length=74), pk(10.1, LAN, 8765, LONDON, 51000, SYN | ACK, length=74),
              pk(10.2, LONDON, 51000, LAN, 8765, PSH | ACK, length=566),
              pk(11.0, CHANGCHUN, 40001, LAN, 3389, SYN), pk(11.5, CHANGCHUN, 40002, LAN, 3389, SYN),
              pk(15.0, LAN, 53000, ROUTER, 53, proto="udp", length=80), pk(15.05, ROUTER, 53, LAN, 53000, proto="udp", length=120)):
        book.add(p)


# -- the tab: the base's, this plugin naming its download, its licence, its credit and its name servers ---------------------
def test_the_tab_its_hooks_and_its_setting_are_the_firewall_bases():
    # after Main and API, every 2 s (0.9.0, liminal-libs 1.65.0: the Netstat tab after it, the base's too)
    assert MACHINE.TABS[:len(Firewall.TABS)] == Firewall.TABS and MACHINE.TABS[0] == Tab("world", "World Wide Web", "world", 2.0)
    assert MACHINE.HOOKS[:len(Firewall.HOOKS)] == Firewall.HOOKS and {"world", "world_geoip"} <= set(Firewall.HOOKS)
    hooks = MACHINE.interface()["hooks"]
    # asked by name (Plugin.ask): the tab's page with no arguments, the install with the one its form sets and the log
    # the platform hands a job (liminal-libs 1.55.0)
    assert hooks["world"].startswith("() ") and hooks["world_geoip"].startswith("(accept_licence=False, log=None) ")
    # the install runs as a job, its progress followed in the plugin's panel: the base's JOB_HOOKS, kept as they are
    # (0.9.0: and nftables' install after them)
    assert MACHINE.JOB_HOOKS == (*Firewall.JOB_HOOKS, "install_nftables") and "world_geoip" in MACHINE.JOB_HOOKS
    assert {"make_rule", "remove_rule", "set_policy", "switch", "save_rules"} <= set(hooks)  # its own, as before
    home, *more = MACHINE.keys  # the home on the globe: a setting on its page, kept through the platform's login
    assert (home.name, home.secret) == ("LIMINAL_HOME_PLACE", False) and home.hint.startswith("optional")
    assert MACHINE.keys == Firewall.keys  # 0.9.0: and when the hosts are recorded (the base's, liminal-libs 1.65.0)
    assert problems(MACHINE) == []
    assert "World Wide Web tab" in MACHINE.about
    # 0.9.0: the Netstat tab's words only with a library that has the tab (liminal-libs 1.65.0), and none before it
    # (this test runs on both)
    assert ("Netstat tab" in MACHINE.about) == netstat_mod.library()
    assert ("hosts database" in MACHINE.about) == netstat_mod.library()


def test_its_geoip_file_is_db_ips_lite_city_and_its_places_are_credited_to_db_ip():
    assert MACHINE.GEOIP_URL == "https://download.db-ip.com/free/dbip-city-lite-{year}-{month}.mmdb.gz" == cards.GEOIP_URL
    assert world.month_url(MACHINE.GEOIP_URL, 2026, 11) == NOVEMBER_FILE  # the address DB-IP's page gives this month
    assert world.file_stem(NOVEMBER_FILE, 2026, 11) == "dbip-city-lite-2026-11"  # installed under its own name
    assert MACHINE.ATTRIBUTION == MARK  # DB-IP's own words and link for its credit
    words = MACHINE.GEOIP_LICENCE
    for said in ("Creative Commons Attribution 4.0 International License", "(CC BY 4.0)", "credit DB-IP.com for the data",
                 "link back to db-ip.com", '"IP Geolocation by DB-IP"', "about 60 MB", "121 MB unpacked"):
        assert said in words, said
    assert "password" not in words.lower()


def test_the_name_servers_asked_for_the_public_address_are_hw_stats_own():
    # asked by their absolute names, a trailing dot added (liminal-libs 1.55.0): no search domain of this machine's goes
    # with them
    assert servers_of(MACHINE.PUBLIC_DNS, 4) == (("myip.opendns.com.", "a", "208.67.222.222", "OpenDNS"),
                                                 ("o-o.myaddr.l.google.com.", "txt", "216.239.32.10", "Google"))
    assert servers_of(MACHINE.PUBLIC_DNS, 6) == (("myip.opendns.com.", "aaaa", "2620:119:35::35", "OpenDNS"),
                                                 ("o-o.myaddr.l.google.com.", "txt", "2001:4860:4802:32::a", "Google"))
    # each is asked for the asker's own address by its own name: no question names another machine
    assert {name for name, _, _, _ in MACHINE.PUBLIC_DNS} == {"myip.opendns.com", "o-o.myaddr.l.google.com"}


# -- nothing on a machine it is not for ---------------------------------------------------------------------------------
@pytest.mark.parametrize("note", [WINDOWS, MACOS], ids=["windows", "macos"])
def test_on_windows_or_macos_the_tab_watches_and_downloads_nothing(note):
    made = []
    fw = Watched(native=note, capture_factory=lambda: made.append(1) or Feed(), fetch=Downloads({}))
    assert fw.ask("world") == {"title": "World Wide Web", "note": f"Not for this machine: {note}. Nothing is watched here."}
    with pytest.raises(ValueError, match="not for this machine"):
        fw.ask("world_geoip", True)
    assert made == [] and fw.views == 0 and fw.world_view(make=False) is None and watching() == []
    assert fw.commands.calls == [] and fw.view_args["fetch"].asked == [] and fw.api_facts() == {}
    fw.detach()  # nothing to stop


def test_inside_wsl_the_tab_ends_with_what_wsl_changes_for_it(monkeypatch, tmp_path):
    """The user, 2026-11-15: "wsl and firewall linux should always work under linux, if wsl prevents or misses some
    capability this should reflect in the plugin". Inside a WSL distribution the tab's page, through this plugin's world
    (the base's, with the XDP words), ends with the library's Under WSL table for it (world.under_wsl: the
    distribution's own adapter, nothing from the internet but through Windows, nothing at all under WSL 1)."""
    under = {"title": "Under WSL", "note": "What running inside a WSL distribution changes for this tab.",
             "columns": [{"title": "What"}, {"title": "Here"}, {"title": "What it means"}],
             "rows": [["From the internet", "through Windows only", "under WSL's NAT networking, only what Windows forwards"]]}
    monkeypatch.setattr(world, "under_wsl", lambda *args, **kwargs: under)
    fw = Watched(capture_factory=Feed, geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW))
    titles = [t["title"] for t in fw.ask("world")["tables"]]
    assert titles[-1] == "Under WSL" and titles.count("Under WSL") == 1 and fw.commands.calls == []  # no command run
    fw.detach()


@pytest.mark.skipif(sys.platform != "win32", reason="this PC's own answer")
def test_on_this_pc_the_plugin_as_the_platform_loads_it_watches_nothing():
    assert MACHINE.world() == {"title": "World Wide Web", "note": f"Not for this machine: {WINDOWS}. Nothing is watched here."}
    with pytest.raises(ValueError, match="not for this machine"):
        MACHINE.world_geoip(True)
    assert MACHINE.world_view(make=False) is None and MACHINE.api_facts() == {}


# -- watching: while the tab is asked, and no longer --------------------------------------------------------------------
def test_an_ask_watches_through_the_capture_which_stops_by_itself_and_on_detach(tmp_path):
    clock, feeds = Clock(), []

    def factory():  # the first capture sees a connection from London; the next, nothing yet
        first = not feeds
        feeds.append(Feed([pk(1.0, LONDON, 51000, LAN, 8765, SYN), pk(1.1, LAN, 8765, LONDON, 51000, SYN | ACK)] if first else ()))
        return feeds[-1]
    fw = Watched(capture_factory=factory, geo_folder=tmp_path / "geoip", clock=clock, wall=Clock(NOW))
    fw.attach(object(), EnvironmentLogin(env={}))
    assert feeds == [] and watching() == [] and fw.views == 0  # nothing runs before the tab is asked
    page = fw.ask("world")  # as the platform asks it, every two seconds while the tab is shown
    view = fw.world_view()
    assert view.running and feeds[0].opened == 1 and len(watching()) == 1 and fw.views == 1
    assert page["title"] == "World Wide Web" and page["note"].startswith(
        f"Watching every packet at this machine's network adapter ({LAN}) while this tab is shown, and for 20 s after")
    assert page["watching"]["running"] is True and page["watching"]["timeout"] == 20.0
    assert wait_for(lambda: view.watcher.status()["packets"] == 2)
    clock.t += 15
    fw.world()  # asked again: kept going, on the same capture and the same view
    assert view.running and len(feeds) == 1 and fw.world_view() is view and fw.views == 1
    clock.t += 21  # nobody looked for longer than the viewing timeout
    assert wait_for(lambda: not view.running) and wait_for(lambda: watching() == []) and feeds[0].closed == 1
    page = fw.world()  # looked at again: a capture of its own; what was counted stays
    assert view.running and len(feeds) == 2 and feeds[1].opened == 1
    assert [o["id"] for o in page["globe"]["origins"]] == ["81.2.69.0/24"] and page["globe"]["origins"][0]["kind"] == "allowed"
    fw.detach()  # the plugin detached: watching ended for good, the view let go
    assert not view.running and feeds[1].closed == 1 and watching() == [] and fw.world_view(make=False) is None
    assert view.closed and view.touch() is False and fw.login is None
    assert fw.commands.calls == []  # the tab runs no command on the machine


def test_a_capture_that_cannot_run_says_why_and_how_and_never_asks_for_a_password(tmp_path):
    words = "libpcap is not installed (libpcap0.8 or libpcap): packets cannot be watched"
    fw = Watched(capture_factory=lambda: Feed(fail_open=words), geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW))
    page = fw.world()
    assert page["note"].startswith(f"Traffic cannot be watched here: {words}. {world.capture_help(words)}")
    assert page["watching"]["error"] == words and not fw.world_view().running and watching() == []
    assert fw.api_facts()[cards.CAPTURE.name]["Watching"] == f"no: {words}"
    # what a native Linux machine's page says, for libpcap missing and for the right to capture (to a platform that is
    # not root: CAP_NET_RAW alone, for the platform alone)
    assert "Install libpcap (libpcap0.8 on Debian and Ubuntu" in world.capture_help(words, windows=False)
    denied = "the adapter could not be opened: socket: Operation not permitted" + world.LIBRARY_HINT
    told = world.capture_help(denied, windows=False, root=False)
    assert "AmbientCapabilities=CAP_NET_RAW" in told and "setcap cap_net_raw=ep" in told
    for said in (page["note"], world.capture_help(words, windows=False), told):
        assert "password" not in said.lower() and "sudo" not in said
    fw.detach()


# -- the right to capture (the review's F1, its blocker, and F2) ------------------------------------------------------------
HERE = Path(__file__).resolve().parents[1]  # the plugin's checkout: its README and CHANGELOG
# libpcap's own words for a capture it may not open, and the library's hint after every libpcap open that failed
PERMISSION = ("the adapter could not be opened: eth0: You don't have permission to capture on that device (socket: "
              "Operation not permitted)" + world.LIBRARY_HINT)


def granting_net_admin(text: str) -> list[str]:
    """Each place `text` would give CAP_NET_ADMIN, the right to rewrite the firewall (a setcap list naming it, a unit's
    setting): any mention of it that is not a "never"."""
    return [text[max(0, m.start() - 40):m.end() + 20] for m in re.finditer("cap_net_admin", text, re.IGNORECASE)
            if "never " not in text[max(0, m.start() - 16):m.start()].lower()]


def note_of(tmp_path, error: str) -> str:
    """The tab's note when its capture cannot open, `error` the capture's words."""
    fw = Watched(capture_factory=lambda: Feed(fail_open=error), geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW))
    try:
        return fw.world()["note"]
    finally:
        fw.detach()


@pytest.fixture
def on_linux(monkeypatch):
    """The page's words as a native Linux machine's page gives them, wherever the tests run: world.capture_help told it
    is not Windows (this PC is), the rest of it as it is (whether the platform is root: os.geteuid, stood in for)."""
    told = world.capture_help
    monkeypatch.setattr(world, "capture_help", lambda error, windows=None, root=None: told(error, False, root))


@pytest.mark.usefixtures("on_linux")
def test_the_right_to_capture_is_cap_net_raw_alone_for_the_platform_alone(tmp_path, monkeypatch):
    """(Review F1, the blocker) The tab, the libpcap card and the README told an administrator to give CAP_NET_RAW and
    CAP_NET_ADMIN, "for good", to the realpath of the platform's Python: the system's interpreter (a venv's python links
    to it), which every account and every script runs, so any of them could have flushed the firewall this plugin keeps,
    and sniffed every adapter. Now CAP_NET_RAW alone, for the platform alone: AmbientCapabilities= in its system unit, or
    setcap on a copy of Python that is its own; never the system's Python, never CAP_NET_ADMIN. The card and the README
    say the same, and the card names each way the tab gives."""
    monkeypatch.setattr(world.os, "geteuid", lambda: 1000, raising=False)  # the platform runs as a user
    for python, own in (("/usr/bin/python3.13", False), ("/opt/liminal/.venv/bin/python3", True)):  # a venv's link; a copy
        monkeypatch.setattr(world, "_python", lambda python=python, own=own: (python, own))
        note = note_of(tmp_path, PERMISSION)
        assert note.startswith(f"Traffic cannot be watched here: {PERMISSION}. Packets are watched with CAP_NET_RAW")
        assert "AmbientCapabilities=CAP_NET_RAW under [Service]" in note and "liminal-platform-boot.service" in note
        if own:  # the platform's own copy: that file, kept its user's alone
            assert f"setcap cap_net_raw=ep {python}" in note and "chmod 0750" in note
        else:  # the system's, which a venv's python links to: never given the right
            assert f"setcap cap_net_raw=ep {python}" not in note and f"Never give it to the system's Python ({python})" in note
        assert granting_net_admin(note) == [] and "password" not in note.lower() and "sudo" not in note
    # the card: CAP_NET_RAW alone, for the platform alone, each way an administrator's, and for as long as it lasts
    card = " ".join([cards.CAPTURE.about, cards.CAPTURE.auth, *(f"{a.about} {a.covered}" for a in cards.CAPTURE.areas),
                     *(f"{c.name} {c.about} {c.used}" for c in cards.CAPTURE.calls)])
    assert granting_net_admin(card) == [] and "for good" not in card
    ways = {c.name: c for c in cards.CAPTURE.calls if c.area == "The right to capture"}
    assert set(ways) == {"AmbientCapabilities=CAP_NET_RAW", "setcap cap_net_raw=ep <the platform's own python>"}
    assert all(c.writes and not c.used for c in ways.values())  # an administrator's to make, never made from here
    assert "never to the system's Python" in cards.CAPTURE.auth and "never CAP_NET_ADMIN" in cards.CAPTURE.auth
    for name in ("README.md", "CHANGELOG.md"):  # and what people read says the same
        text = (HERE / name).read_text(encoding="utf-8")
        assert granting_net_admin(text) == [], name
        assert "AmbientCapabilities=CAP_NET_RAW" in text and "setcap cap_net_raw=ep" in text, name


@pytest.mark.usefixtures("on_linux")
def test_the_right_to_capture_is_advised_only_when_libpcap_says_it_is_missing_and_never_to_root(tmp_path, monkeypatch):
    """(Review F2) Every libpcap open that failed got the setcap words, as root too: the library's hint follows each
    failure, and it was taken for libpcap's word that the right is missing. Now the right is advised only when libpcap
    says it is missing and only to a platform that is not root; as root, what else may forbid packet sockets; and any
    other failure is said in libpcap's own words, without the hint."""
    monkeypatch.setattr(world, "_python", lambda: ("/usr/bin/python3.13", False))
    monkeypatch.setattr(world.os, "geteuid", lambda: 0, raising=False)  # the platform runs as root (the README's own way)
    note = note_of(tmp_path, PERMISSION)
    assert "The platform runs as root, and still the adapter could not be opened" in note and "AppArmor" in note
    assert "setcap" not in note and "Ambient" not in note
    for euid in (0, 1000):
        monkeypatch.setattr(world.os, "geteuid", lambda euid=euid: euid, raising=False)
        for why in ("wg0: No such device exists (SIOCGIFINDEX: No such device)", "wlan0: That device is not up",
                    "eth0: Packet capture is not supported on that device"):  # an adapter gone, one not up, one of another kind
            error = f"the adapter could not be opened: {why}"
            note = note_of(tmp_path, error + world.LIBRARY_HINT)
            assert note.startswith(f"Traffic cannot be watched here: {error}. Show this tab again once that is put right.")
            assert "setcap" not in note and "Ambient" not in note and "CAP_NET_RAW" not in note


# -- what the capture cannot see: an XDP program's drops (the review, minor) ----------------------------------------------
def test_what_an_xdp_program_at_the_adapter_watched_drops_is_said_unseen_from_the_read_kept(tmp_path):
    """Packets are seen before nftables and iptables decide, so what they drop shows as unanswered; an XDP program runs
    before the kernel's packet sockets, so what it drops is never seen. The tab says so when the firewall's last read
    found one at the adapter watched, or at a port of its bridge or bond; from the read kept, running no command."""
    def plugin(address):
        return Watched(capture_factory=lambda: Feed(address=address), geo_folder=tmp_path / "geoip", clock=Clock(),
                       wall=Clock(NOW))
    fw = plugin("192.168.1.10")  # Debian's enp3s0, where its read found an XDP program (generic, program 42)
    assert "XDP" not in fw.world()["note"] and fw.commands.calls == []  # no read kept: nothing said, and no read made
    fw.config()  # the firewall's read, as its Main tab makes it (the stand-in's)
    read = len(fw.commands.calls)
    note = fw.world()["note"]
    assert note.endswith("The firewall's last read found XDP at the adapter watched (enp3s0: XDP generic: program 42): "
                         "what XDP drops never reaches libpcap, so it is neither counted nor drawn here; what nftables and "
                         "iptables drop is, as unanswered.")
    assert len(fw.commands.calls) == read  # the read kept: the tab ran no command
    fw.detach()
    for address in ("172.17.0.1", LAN):  # docker0, with no XDP program; an address no adapter of the read holds
        fw = plugin(address)
        fw.config()
        assert "XDP" not in fw.world()["note"] and fw.xdp_unseen() == ""
        fw.detach()
    bridged = Config(system=System(interfaces=[
        Interface("br0", "up", ("10.0.0.2/24", "fe80::5054:ff:fe12:3456/64")),
        Interface("eth1", "up", (), "XDP driver: program 7", "br0"),  # a port of br0: what comes in to br0 comes through it
        Interface("eth2", "up", ("10.9.0.2/24",), "XDP generic: program 8")]))  # elsewhere
    assert "(eth1: XDP driver: program 7)" in xdp_words(bridged, "10.0.0.2")
    assert "(eth1: XDP driver: program 7)" in xdp_words(bridged, "fe80:0:0:0:5054:ff:fe12:3456%br0")  # IPv6, a zone
    assert xdp_words(bridged, "10.0.0.9") == xdp_words(bridged, "no address") == ""


# -- the GeoIP file: DB-IP's, on the user's word --------------------------------------------------------------------------
@needs_reader
def test_db_ips_file_is_downloaded_from_its_own_address_only_once_its_licence_is_accepted(tmp_path, licences):
    """0.12.0 (liminal-libs 1.101.0): the GeoIP sources table in place of the install buttons, DB-IP's two files
    offered and IPinfo Lite named, not offered; a download asked by a person signed in at the platform's page, its
    acceptance kept in their own login store (licence-dbip-lite), never in the licences file; any other ask refused
    before anything is read."""
    folder = tmp_path / "geoip"
    downloads = Downloads({NOVEMBER_FILE: gzip.compress(mmdb(PLACES, built=NOVEMBER))})
    book = TrafficBook(clock=lambda: 50.0)
    fw = Watched(capture_factory=Feed, geo_folder=folder, clock=Clock(), wall=Clock(NOW), fetch=downloads, book=book)
    traffic_of(book)
    page = fw.world()
    assert all(o["lat"] is None for o in page["globe"]["origins"]) and page["globe"]["attribution"] is None  # none placed yet
    form, networks = page["forms"]
    assert (form["id"], form["hook"], form["title"]) == (
        "world-geoip-get-dbip-places", "world_geoip_get", "Download DB-IP IP to City Lite")
    assert (networks["id"], networks["title"]) == ("world-geoip-get-dbip-networks", "Download DB-IP IP to ASN Lite")
    # run as a job by the platform, its progress in the panel, its Cancel the page's
    assert form["job"] is True and form["hook"] in fw.JOB_HOOKS and form["hook"] in fw.CANCEL_HOOKS
    licence = cards.DBIP_CITY_WORDS
    assert form["fields"] == [{"name": "source", "type": "fixed", "value": "dbip"},
                              {"name": "role", "type": "fixed", "value": "places"},
                              {"name": "accept_licence", "type": "accept", "title": "Accept its licence (CC BY 4.0)?",
                               "words": licence, "yes": "Accept it and download"}]
    assert licence.endswith(geosources.pointer(CC_BY))  # a summary: the full licence's page applies
    words = form["confirm"]["words"]
    assert f"is downloaded from download.db-ip.com, and kept in {folder}," in words
    assert "Its progress shows in the panel below; it stops by itself after 30 minutes" in words
    assert words.index(licence) < words.index("You are asked to accept it next")  # the licence first
    assert [cells(r) for r in titles(page)["GeoIP sources"]["rows"]] == [
        ["DB-IP IP to City Lite", "places", "CC BY 4.0", "none needed", "not downloaded", "", "Download…", ""],
        ["DB-IP IP to ASN Lite", "networks", "CC BY 4.0", "none needed", "not downloaded", "", "Download…", ""],
        ["IPinfo Lite", "networks", "CC BY-SA 4.0", "not asked", "not offered: waiting for your word", "", "", ""]]
    assert not page.get("actions")
    assert form["hook"] in fw.interface()["hooks"]  # a hook the platform may ask
    # the platform asks it with the form's fields, the accept field false until its own, second confirmation: refused,
    # nothing downloaded
    fixed = ["dbip", "places"]
    alice = Store()
    with asking(PAGE), as_user(alice):
        with pytest.raises(LicenceRefused) as refused:
            fw.ask(form["hook"], *fixed, False)
        assert refused.value.accept == "accept_licence" == form["fields"][-1]["name"]
        for almost in (None, 1, "true", "yes"):
            with pytest.raises(LicenceRefused):
                fw.world_geoip_get(*fixed, almost)
    # anyone but a person signed in at the page is refused by the hook itself: no asker, another plugin, the platform's
    # own login (it keeps no settings)
    for who, login in ((None, None), ("another-plugin", Store("bob")), (PAGE, EnvironmentLogin(env={}))):
        with contextlib.ExitStack() as stack:
            if who:
                stack.enter_context(asking(who))
            if login is not None:
                stack.enter_context(as_user(login))
            with pytest.raises(geosources.NotAsked, match="sign in"):
                fw.world_geoip_get(*fixed, True)
    assert downloads.asked == [] and not folder.exists() and alice.pairs == {}
    with asking(PAGE), as_user(alice):
        out = fw.ask(form["hook"], *fixed, True)  # accepted, in so many words
    assert downloads.asked == [(NOVEMBER_FILE, world.READ_S)]  # DB-IP's own address, this month's file, nothing else
    assert out["ok"] is True and out["said"].startswith("installed dbip-city-lite-2026-11.mmdb (built 2026-11-01")
    assert out["lines"][0] == "downloaded from download.db-ip.com"
    assert out["lines"][-1] == "your acceptance of its licence is kept in your own login store"
    assert [p.name for p in folder.iterdir()] == ["dbip-city-lite-2026-11.mmdb"]
    kind, raw = alice.pairs["licence-dbip-lite"]  # her own store: the file and its month, the licence's version and page
    record = json.loads(raw)
    assert kind == LICENCE and record["title"] == "DB-IP IP to City Lite, 2026-11" and record["version"] == "CC BY 4.0"
    assert record["url"] == CC_BY and record["acceptedBy"] == "alice"
    assert set(alice.pairs) == {"licence-dbip-lite"} and not licences.exists()
    # placed from now on, on this machine, DB-IP credited wherever places are; its Remove…, and the ASN file's Download…
    page = fw.world()
    by = {o["id"]: o for o in page["globe"]["origins"]}
    assert (by["81.2.69.0/24"]["city"], by["81.2.69.0/24"]["lat"], by["81.2.69.0/24"]["kind"]) == ("London", 51.5142, "allowed")
    assert (by["175.16.199.0/24"]["city"], by["175.16.199.0/24"]["kind"], by["175.16.199.0/24"]["count"]) == (
        "Changchun", "unanswered", 2)
    assert page["globe"]["local"]["places"] == 1  # the router: the local network's, never placed
    assert page["globe"]["attribution"] == MARK
    places = next(t for t in page["tables"] if t["title"] == "Places")  # (0.9.0: the globe's choice is the first)
    assert "Places: IP Geolocation by DB-IP, https://db-ip.com." in places["note"]
    assert [f["id"] for f in page.get("forms", [])] == ["world-geoip-remove-dbip-places", "world-geoip-get-dbip-networks"]
    assert not page.get("actions")
    facts = fw.api_facts()[cards.DBIP_LITE.name]
    assert facts["File"] == "dbip-city-lite-2026-11.mmdb, built 2026-11-01" and facts["Read"].startswith("memory-mapped")
    # the old install (0.8.0's hook), asked by no person at the page: DB-IP's file as before, nothing recorded
    assert fw.world_geoip(True)["said"].startswith("dbip-city-lite-2026-11.mmdb is installed already")
    assert len(downloads.asked) == 1 and not licences.exists()  # this month's is there: not downloaded again
    fw.world()  # opened again at the tab's ask
    fw.world_view().stop()  # nobody watches: the file is let go, and the cards say so, asking nothing
    assert fw.world_view(make=False).describe()["geoip"]["open"] is False
    facts = fw.api_facts()[cards.DBIP_LITE.name]
    assert facts["File"] == "dbip-city-lite-2026-11.mmdb, built 2026-11-01"
    assert facts["Read"].startswith("not now: let go while the tab is not watched, memory-mapped")
    fw.detach()


@needs_reader
def test_last_months_file_while_this_months_is_not_out_and_nothing_written_when_neither_is(tmp_path):
    folder = tmp_path / "geoip"
    downloads = Downloads({OCTOBER_FILE: gzip.compress(mmdb(PLACES, built=OCTOBER))})  # November's: a 404
    fw = Watched(capture_factory=Feed, geo_folder=folder, clock=Clock(), wall=Clock(NOW), fetch=downloads)
    out = fw.world_geoip(True)
    assert [u for u, _ in downloads.asked] == [NOVEMBER_FILE, OCTOBER_FILE]
    assert out["said"].startswith("installed dbip-city-lite-2026-10.mmdb (built 2026-10-01")
    assert out["lines"][0] == "downloaded from download.db-ip.com: this month's file is not out yet, so last month's"
    page = fw.world()  # older than this month: its update offered
    forms = {f["id"]: f for f in page["forms"]}
    assert forms["world-geoip-get-dbip-places"]["title"] == "Update DB-IP IP to City Lite"
    assert cells(titles(page)["GeoIP sources"]["rows"][0])[4:] == [
        "built 2026-10-01; used for places", "", "Update…", "Remove…"]
    fw.detach()
    empty = tmp_path / "empty"
    none = Watched(capture_factory=Feed, geo_folder=empty, wall=Clock(NOW), fetch=Downloads({}))
    with pytest.raises(geo.GeoError, match="neither this month's nor last month's: " + re.escape(f"{NOVEMBER_FILE}, {OCTOBER_FILE}")):
        none.world_geoip(True)
    assert not empty.exists()  # nothing written


# -- home ---------------------------------------------------------------------------------------------------------------
@needs_reader
def test_home_is_the_place_set_through_the_login_else_where_its_name_servers_put_this_network(tmp_path):
    folder = tmp_path / "geoip"
    folder.mkdir()
    (folder / "dbip-city-lite-2026-11.mmdb").write_bytes(mmdb(PLACES, built=NOVEMBER))
    asked = []

    def resolve(version, servers):
        asked.append((version, servers))
        return PUBLIC, servers[0][3]
    fw = Watched(capture_factory=Feed, geo_folder=folder, clock=Clock(), wall=Clock(NOW), resolve=resolve)
    login = EnvironmentLogin(env={"LIMINAL_HOME_PLACE": "48.86,2.35,Paris"})
    fw.attach(object(), login)
    g = fw.world()["globe"]
    assert g["home"] == {"lat": 48.86, "lon": 2.35, "label": "Paris"} and "Home is the place you set." in g["note"]
    assert asked == []  # the user's place: no name server asked
    del login.env["LIMINAL_HOME_PLACE"]
    fw.settings_changed()  # kept on its page: read anew at the next ask
    g = fw.world()["globe"]
    assert g["home"] is None and "being asked for" in g["note"]  # asked on a thread of its own
    assert wait_for(lambda: fw.world()["globe"]["home"] is not None)
    g = fw.world()["globe"]
    assert g["home"] == {"lat": 37.386, "lon": -122.0838, "label": "Mountain View, United States"}
    assert "where the GeoIP file puts this network's public address" in g["note"]
    assert asked == [(4, servers_of(MACHINE.PUBLIC_DNS, 4))]  # this plugin's name servers, IPv4's; once
    fw.detach()


# -- what the tab's cards learned ------------------------------------------------------------------------------------------
def test_the_tabs_facts_are_what_it_watched_and_asking_them_makes_and_starts_nothing(tmp_path, monkeypatch):
    asked = []  # how the cards reach the tab: through the base's accessor, never making a view
    reach = LinuxFirewallPlugin.world_view
    monkeypatch.setattr(Watched, "world_view", lambda self, make=True: asked.append(make) or reach(self, make))
    fw = Watched(capture_factory=Feed, geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW))
    assert fw.api_facts() == {} and fw.views == 0 and watching() == []  # before the tab was shown: nothing said, or made
    assert asked == [False]
    fw.world()
    asked.clear()
    facts = fw.api_facts()
    assert asked == [False]
    assert facts[cards.CAPTURE.name] == {"Watching": f"yes, at the adapter holding {LAN}", "Packets read": "0"}
    assert facts[cards.DBIP_LITE.name]["File"].startswith("none open")
    fw.world_view().stop()
    assert fw.api_facts()[cards.CAPTURE.name]["Watching"] == ("not now: only while the World Wide Web tab is shown, and for "
                                                              "20 s after")
    assert fw.views == 1 and watching() == []  # asking them made no view and started nothing
    fw.detach()
    assert fw.api_facts() == {}
    # the base's view is reached through its accessor alone (world_view, liminal-libs 1.55.0), never its private attribute
    source = inspect.getsource(cards)
    assert "_world" not in source and "vars(" not in source and "__dict__" not in source


def test_its_asn_file_is_db_ips_ip_to_asn_lite_under_the_same_licence():
    """liminal-libs 1.75.0: DB-IP's IP to ASN Lite beside the city file, each network's AS number and operator (its
    download page read 2026-11-22: 9.2 MB, 485,292 ranges, CC BY 4.0, the same credit)."""
    assert MACHINE.GEOIP_ASN_URL == "https://download.db-ip.com/free/dbip-asn-lite-{year}-{month}.mmdb.gz" == cards.GEOIP_ASN_URL
    assert world.month_url(MACHINE.GEOIP_ASN_URL, 2026, 11) == "https://download.db-ip.com/free/dbip-asn-lite-2026-11.mmdb.gz"
    for said in ("Creative Commons Attribution 4.0 International License", "(CC BY 4.0)", "credit DB-IP.com for the data",
                 "link back to db-ip.com", "\"IP Geolocation by DB-IP\"", "about 5 MB", "9.2 MB unpacked", "485,292"):
        assert said in MACHINE.GEOIP_ASN_LICENCE, said
    assert next(a for a in cards.DBIP_LITE.areas if a.name == "IP to ASN Lite").covered
    assert any(c.area == "IP to ASN Lite" and c.used and "dbip-asn-lite" in c.name for c in cards.DBIP_LITE.calls)


# -- 0.12.0: the GeoIP sources (liminal-libs 1.101.0, Monday list item 20) ------------------------------------------------
def test_the_sources_are_db_ips_two_files_first_and_ipinfo_lite_named_not_offered():
    """The user, 2026-11-19: "add a way to download different GEOIP sources"; 2026-11-25: each source offered only after
    their yes. DB-IP's two files the default for places and networks, at the addresses and in the words as before;
    IPinfo Lite for networks named and not offered: no card, no key, nothing asked of anyone."""
    said = json.dumps(cards.GEOIP_SOURCES, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    assert hashlib.sha256(said.encode("utf-8")).hexdigest() == GEOIP_SOURCES_SHA256  # the Windows plugin's pin too
    assert MACHINE.GEOIP_SOURCES is cards.GEOIP_SOURCES
    read, refused = geosources.read(MACHINE.GEOIP_SOURCES, [k.name for k in MACHINE.keys])
    assert refused == [] and [s.id for s in read] == ["dbip", "ipinfo"]
    dbip, ipinfo = read
    assert dbip.offered and not dbip.keys and dbip.hosts == ("download.db-ip.com",) and dbip.roles == ("places", "networks")
    assert (dbip.file("places").url, dbip.file("networks").url) == (MACHINE.GEOIP_URL, MACHINE.GEOIP_ASN_URL)
    assert [f.licence.pair for f in dbip.files] == ["dbip-lite", "dbip-asn-lite"]
    assert all(f.licence.url == CC_BY and f.licence.version == "CC BY 4.0" for f in dbip.files)
    assert all(dict(f.credit) == MACHINE.ATTRIBUTION for f in dbip.files)  # "IP Geolocation by DB-IP", linked
    assert not ipinfo.offered and ipinfo.roles == ("networks",) and ipinfo.hosts == ("ipinfo.io",)
    lite = ipinfo.file("networks")
    assert (lite.shape, lite.packing, lite.checksum, lite.every_days) == ("ipinfo-lite", "mmdb", "ipinfo-checksums", 7)
    assert lite.sent_on == ("dl.assets.ipinfo.io", "dl.ipinfo.io") and lite.licence.name == "CC BY-SA 4.0"
    assert dict(lite.credit) == {"text": "IP address data powered by IPinfo", "url": "https://ipinfo.io"}
    assert dict(ipinfo.keys) == {"IPINFO_TOKEN": "token"} and ipinfo.sends == "query"
    # not offered: no key declared or asked, no card, and its licence's pair not among what the plugin keeps
    assert "IPINFO_TOKEN" not in {k.name for k in MACHINE.keys}
    assert not any("IPinfo" in (a.name + a.maker) for a in MACHINE.apis)
    kept = dict(MACHINE.KEEPS)
    assert {geosources.VAR, "licence-dbip-lite", "licence-dbip-asn-lite"} <= set(kept)
    assert "licence-ipinfo-lite" not in kept
    # every word of a source is the plugin's: the library names no host of DB-IP's or IPinfo's
    source = inspect.getsource(geosources) + inspect.getsource(world)
    assert "db-ip.com" not in source and "ipinfo.io" not in source


def test_ipinfo_lite_is_refused_before_any_key_is_read_or_anything_downloaded(tmp_path, licences):
    downloads = Downloads({})
    fw = Watched(capture_factory=Feed, geo_folder=tmp_path / "geoip", clock=Clock(), wall=Clock(NOW), fetch=downloads)
    alice = Store(pairs={"ipinfo-token": ("key", "Canary_Token-0123456789abcdef")})  # a stand-in: never a real token
    with asking(PAGE), as_user(alice):
        with pytest.raises(ValueError, match="not offered: waiting for your word"):
            fw.world_geoip_get("ipinfo", "networks", True)
        with pytest.raises(ValueError, match="not offered"):
            fw.world_geoip_use("ipinfo", "networks")
        with pytest.raises(ValueError, match="names no"):
            fw.world_geoip_get("ipinfo", "places", True)
    assert alice.asked == [] and downloads.asked == [] and not licences.exists()
    fw.detach()
