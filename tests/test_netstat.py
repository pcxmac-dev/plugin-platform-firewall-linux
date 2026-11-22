"""The Netstat tab, the hosts database and the globe's filters and layers as this plugin has them (0.9.0; the library's
Firewall base, liminal-libs 1.65.0; the user, 2026-11-16: "the firewall app should have a 'netstat' like interface for
looking at active ports and what apps they are attached to, and the hosts that they connect to across the lan or wan";
"the globe-firewall should allow filtering, so i can view apps connected to hosts all across the globe, or ports
talking to all hosts"; "have all the backbones,ibones, major internet infrastructure, (as many as possible) datacenter
locations").

The tab, its hooks, its job and its setting are the base's. This plugin names the data sets the globe's layers come
from (OpenStreetMap's through the Overpass API, Wikidata's, EMODnet's, the Internet Topology Zoo's maps of backbone
networks: the user, 2026-11-19, "major network 'bones' need to be displayed on the map"): each one the library reads,
asked at its card's address in the one request its card names, with its licence, its credit and its wait, the same as
the Windows firewall plugin's (their digest pinned in both). Its card of the kernel's socket
tables names every file the library's reader reads. A listener another user holds is named from the firewall's read
kept, running no command. The plugin is valid and present wherever the socket table can be read, its table of what
the firewall needs saying what the tab needs; inside WSL 2 the tab's Under WSL table ends with what was seen in the
user's Ubuntu; on Windows and macOS nothing is read; a firewall attached under a login that says always records
nothing real; the cards' facts ask nothing.

Nothing real: the socket table is a stand-in reading (the suite's guard refuses the real one), the hosts database and
the layers' folder are in tmp_path (the same guard), the GeoIP folder is tmp_path's, no download is made and no name
server asked (refused here), and the machine's commands are a stand-in that keeps every one."""
from __future__ import annotations

import gzip
import hashlib
import inspect
import io
import json
import os
import re
import tarfile
import threading
import time
import types
import urllib.request
from pathlib import Path

import pytest

netstat = pytest.importorskip("liminal_libs.machines.netstat", reason="a library from before the Netstat tab")

from liminal_libs import capture, dns, geo, hostbook, netpath, sockets  # noqa: E402
from liminal_libs.apps.authorization import EnvironmentLogin  # noqa: E402
from liminal_libs.machines import infrastructure, world  # noqa: E402
from liminal_libs.machines import linux as linux_mod  # noqa: E402
from liminal_libs.machines.firewall import Firewall  # noqa: E402
from liminal_libs.machines.infrastructure import DataSet, Index  # noqa: E402
from liminal_libs.machines.linux import Shell, why_not_native  # noqa: E402
from liminal_libs.machines.netstat import NetstatView  # noqa: E402
from liminal_libs.sources.apis import problems  # noqa: E402
from liminal_libs.sources.conformance import problems as conformance  # noqa: E402

from plugin_platform_firewall_linux import MACHINE, LinuxFirewallPlugin  # noqa: E402
from plugin_platform_firewall_linux import apis as cards  # noqa: E402
from plugin_platform_firewall_linux import netstat as netstat_mod  # noqa: E402
from plugin_platform_firewall_linux.groups import UNKNOWN  # noqa: E402

from conftest import Reached  # noqa: E402
from machines import FakeLinux  # noqa: E402
from test_apis import pattern  # noqa: E402

TABLES_HERE = netstat_mod.tables_here  # the real one, taken before any test (the suite's conftest stands it in)
NOW = time.time()
LAN, PRINTER, WEB = "192.168.1.20", "192.168.1.50", "81.2.69.142"
WINDOWS = why_not_native("The Linux firewall", "win32", "10", {})
MACOS = why_not_native("The Linux firewall", "darwin", "24.1.0", {})
ANOTHER = "another user's (root): only root reads which program holds it"
NAMED_BY_READ = "named by the firewall's own root read; its pid is not read"
UNDER = {"title": "Under WSL", "note": "What running inside a WSL distribution changes for this tab.",
         "columns": [{"title": "What"}, {"title": "Here"}, {"title": "What it means"}],
         "rows": [["This Linux", "WSL 2: Ubuntu", "a WSL distribution on Windows: the sockets listed are its own"]]}
# the data sets' digest (sha256 of apis.INFRASTRUCTURE as canonical JSON: sorted keys, no spaces, UTF-8): the Windows
# firewall plugin names the same data sets, and its tests pin the same digest: a data set changed changes both
INFRASTRUCTURE_SHA256 = "8e31ca180948d874e461d61aeb336d456f39224193f4786af35e800afeaa2549"
# a map of the Topology Zoo's as its toolset wrote them (a network's values, its points with their places, its links),
# in its archive's shape (gml.tar.gz: gzipped tar of GML files); none of it recorded
NORDU = ('graph [\n  Network "NORDUnet"\n  DateYear "2010"\n  node [\n    id 0\n    label "Stockholm"\n'
         '    Longitude 18.0649\n    Internal 1\n    Latitude 59.33258\n  ]\n  node [\n    id 1\n    label "Oslo"\n'
         '    Longitude 10.74609\n    Internal 1\n    Latitude 59.91273\n  ]\n  node [\n    id 2\n    label "GEANT"\n'
         '    Internal 0\n    Longitude 4.9\n    Latitude 52.4\n  ]\n  edge [\n    source 0\n    target 1\n  ]\n'
         '  edge [\n    source 0\n    target 2\n  ]\n]\n')


def zoo_archive(maps: dict) -> bytes:
    """Maps in a gzipped tar, as the Topology Zoo's gml.tar.gz holds them."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        for name, text in maps.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(out.getvalue(), mtime=0)


def sock(proto="tcp", local=LAN, local_port=41000, remote="", remote_port=0, *, state="established", pid=2000,
         program="curl", path="/usr/bin/curl", user="sysop", inode=7001, unread=None) -> dict:
    """One socket as the library's Linux reader gives it (sockets' shape)."""
    return {"proto": proto, "family": 6 if ":" in local else 4, "state": state, "local": local,
            "local_port": local_port, "remote": remote, "remote_port": remote_port, "pid": pid,
            "pids": [pid] if pid else [], "program": program, "path": path, "service": "", "service_title": "",
            "user": user, "started": None, "process_started": None, "count": 1, "inode": inode, "seen": NOW - 60,
            "unread": dict(unread or {})}


def linux_rows() -> list[dict]:
    """A Debian machine's sockets read as its platform's user (sysop): root's sshd and cupsd listening, unnamed; the
    platform's page, its own; a connection out to the internet and one from the local network into sshd."""
    return [
        sock(local="0.0.0.0", local_port=22, state="listening", pid=0, program="", path="", user="root", inode=4001,
             unread={"program": ANOTHER}),
        sock(local="127.0.0.1", local_port=631, state="listening", pid=0, program="", path="", user="root",
             inode=4002, unread={"program": ANOTHER}),
        sock(local="127.0.0.1", local_port=8775, state="listening", pid=3301, program="python3",
             path="/usr/bin/python3.12", inode=5001),
        sock(remote=WEB, remote_port=443),
        sock(local=LAN, local_port=22, remote=PRINTER, remote_port=50500, pid=0, program="", path="", user="root",
             inode=4003, unread={"program": ANOTHER}),
    ]


def reading(rows=None, *, at: float = NOW) -> dict:
    """The kernel's socket tables as the library's sockets.read answers them on Linux, read as sysop."""
    return {"system": "linux", "at": at, "awake": 1000.0, "took": 0.004, "root": False, "starts": False,
            "read": sockets.TABLES, "cut": False, "rows": linux_rows() if rows is None else rows,
            "notes": ["Read as sysop: the kernel lists every socket here and names the program of your own alone.",
                      sockets.NO_START_NOTE]}


@pytest.fixture(autouse=True)
def _nothing_real(monkeypatch, tmp_path):
    """Nothing real is reached: no libpcap loaded, no route asked, no name server, no download, not this machine's
    GeoIP folder (each reach is noted, so one inside a thread is seen too); the socket table, the hosts database and
    the layers' folder are the suite's own guard's (conftest's _no_real_hosts). As root, so the stand-in read needs no
    sudo, unless a test says otherwise."""
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
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 0, raising=False)
    yield
    assert reached == []
    assert not [t for t in threading.enumerate() if t.name.endswith("-hosts") or t.name == "traffic-watcher"]


def plugin(fake=None, native: str = "") -> LinuxFirewallPlugin:
    """The plugin on a native Linux machine (or one it is not for: `native` says why), its commands kept by `fake`."""
    return LinuxFirewallPlugin(shell=Shell("local", runner=fake or FakeLinux("debian-13-nftables")), native=native)


class Tabbed(LinuxFirewallPlugin):
    """The plugin with its Netstat view over a stand-in socket table (the rows given), counting its readings, and its
    own data sets."""

    def __init__(self, rows=None, fake=None):
        super().__init__(shell=Shell("local", runner=fake or FakeLinux("debian-13-nftables")), native="")
        self.rows, self.readings = rows, 0

    def make_netstat_view(self) -> NetstatView:
        def reader() -> dict:
            self.readings += 1
            return reading(self.rows, at=time.time())
        return NetstatView(self.name, reader=reader, names={}, login_of=lambda: getattr(self, "login", None),
                           listeners=self.netstat_listeners,
                           index=Index(datasets=[DataSet.of(d) for d in self.INFRASTRUCTURE]))


class Bare(LinuxFirewallPlugin):
    """The plugin on a Linux with no firewall software: its read answers, and finds none."""

    def config(self, fresh: bool = False):
        return types.SimpleNamespace(manager="")


def table(page: dict, title: str) -> dict:
    return next(t for t in page["tables"] if t["title"] == title)


def texts(cells) -> list:
    return [c.get("text", "") if isinstance(c, dict) else c for c in cells]


# -- the tab, its hooks, its job and its setting: the base's -----------------------------------------------------------
def test_the_tab_its_hooks_its_job_and_its_setting_are_the_firewall_bases():
    assert MACHINE.TABS == Firewall.TABS and [t.id for t in MACHINE.TABS] == ["world", "netstat"]
    tab = MACHINE.TABS[1]
    assert (tab.title, tab.hook, tab.every) == ("Netstat", "netstat", netstat.EVERY) and netstat.EVERY == 3.0
    assert set(netstat.HOOKS) <= set(MACHINE.HOOKS) and MACHINE.HOOKS[:len(Firewall.HOOKS)] == Firewall.HOOKS
    hooks = MACHINE.interface()["hooks"]
    assert hooks["netstat"].startswith("()")  # asked with no arguments, as every tab's hook
    assert LinuxFirewallPlugin.netstat.__doc__.splitlines()[0] == (  # the line the Internal API tab draws
        "The Netstat tab's page: the listening ports and the open connections with the program behind each.")
    assert hooks["world_layer_get"].startswith("(dataset, accept_licence=False, log=None) ")
    # a data set's download runs as a job the page may cancel, beside the GeoIP file's and nftables' install
    assert MACHINE.JOB_HOOKS == (*Firewall.JOB_HOOKS, "install_nftables") and "world_layer_get" in MACHINE.JOB_HOOKS
    assert MACHINE.CANCEL_HOOKS == Firewall.CANCEL_HOOKS == ("world_layer_get",)
    assert "world_layer" in MACHINE.READ_HOOKS  # a layer's geometry is a read, which writes no log line
    recording = next(k for k in MACHINE.keys if k.name == hostbook.VARIABLE)
    assert recording.name == "LIMINAL_HOSTS_RECORDING" and not recording.secret
    assert recording.hint.startswith("optional")
    assert conformance(MACHINE) == [] and "Netstat tab" in MACHINE.about and "hosts database" in MACHINE.about


# -- the data sets: the library's, at their cards' addresses -----------------------------------------------------------
def test_every_data_set_is_one_the_library_reads_asked_in_the_one_request_its_card_names():
    assert MACHINE.INFRASTRUCTURE is cards.INFRASTRUCTURE
    sets = [DataSet.of(d) for d in MACHINE.INFRASTRUCTURE]  # each reads, as the base's make_netstat_view reads it
    assert [d.id for d in sets] == ["osm-datacentres", "osm-cables", "osm-lines", "wikidata", "emodnet-cables",
                                    "topology-zoo", "ourairports", "geonames-cities"]
    card_of = {"overpass": cards.OVERPASS_API, "sparql": cards.WIKIDATA, "geojson": cards.EMODNET,
               "gml": cards.TOPOLOGY_ZOO,
                "ourairports": cards.OURAIRPORTS_API, "geonames": cards.GEONAMES_API}
    assert [d.format for d in sets] == ["overpass", "overpass", "overpass", "sparql", "geojson", "gml",
                                         "ourairports", "geonames"]
    for d, said in zip(sets, MACHINE.INFRASTRUCTURE):
        card = card_of[d.format]
        address = d.address()
        assert d.url == card.base and d.host == card.base.split("/")[2]
        assert address.startswith(card.base + "?") if d.query else address == card.base  # a file: its address alone
        [get] = [c for c in card.used if c.name.startswith("GET ")]  # the one request each download makes
        assert pattern(get.name).search(address), (d.id, get.name)
        assert d.wait <= infrastructure.INSTALL_S
        assert d.about == said["about"] and d.title == said["title"]  # said whole: none cut to fit
    assert {d.host for d in sets} == {"overpass-api.de", "query.wikidata.org", "ows.emodnet-humanactivities.eu",
                                      "raw.githubusercontent.com",
                                      "davidmegginson.github.io", "download.geonames.org"}
    # (critique M7) Overpass prints tags and a point or a line alone, never every way's nodes; each data set waits on
    # its socket as long as its query may run, and a margin
    for d in sets[:3]:
        assert re.findall(r"out ([a-z ]+?) qt;", d.query) and all(
            o.startswith("tags ") for o in re.findall(r"out ([a-z ]+?) qt;", d.query)), d.query
        limit = int(re.match(r"\[out:json\]\[timeout:(\d+)\];", d.query).group(1))
        assert limit < d.wait <= infrastructure.INSTALL_S, d.id
    assert 60 < sets[3].wait <= infrastructure.INSTALL_S  # the query service's own deadline is 60 s (its user manual)
    # EMODnet's six telecom cable layers, as GeoJSON, longitude first (the library refuses a WFS asked otherwise)
    emodnet = sets[4]
    assert "srsName=EPSG:4326" in emodnet.query and "outputFormat=application/json" in emodnet.query
    assert re.search(r"typeName=([^&]+)", emodnet.query).group(1).split(",") == list(cards.EMODNET_LAYERS)
    assert "pcables" not in emodnet.query and len(cards.EMODNET_LAYERS) == 6  # the power cables are not asked for
    # the licences, shown first and accepted in so many words, and the credits beside every feature drawn
    for d in sets[:3]:
        assert d.licence == cards.ODBL and d.credit == cards.OSM_CREDIT and d.licence_name == "ODbL 1.0"
    assert "Open Database License 1.0" in cards.ODBL and "© OpenStreetMap contributors" in cards.ODBL
    assert cards.OSM_CREDIT == {"text": "© OpenStreetMap contributors",
                                "url": "https://www.openstreetmap.org/copyright"}
    assert sets[3].licence == cards.CC0 and "Creative Commons Zero" in cards.CC0 and sets[3].licence_name == "CC0"
    assert sets[4].licence == cards.EMODNET_LICENCE and sets[4].licence_name == "CC BY 4.0"
    assert "This data was downloaded from the EMODnet Portal" in cards.EMODNET_LICENCE
    assert cards.EMODNET_CREDIT["text"] == "EMODnet Human Activities; data originator Cogea Srl"
    # the Topology Zoo's maps: its archive alone (348,613 bytes as GitHub gave it), CC BY 4.0, credited as asked, and
    # said for what they are: logical links of about 2010 and 2011, not today's networks nor their fibre
    zoo = sets[5]
    assert (zoo.url, zoo.query, zoo.size, zoo.licence_name) == (cards.ZOO_GML, "", 348_613, "CC BY 4.0")
    assert zoo.licence == cards.ZOO_LICENCE and zoo.credit == cards.ZOO_CREDIT and zoo.credit["text"] in zoo.licence
    assert zoo.credit["text"].startswith("Internet Topology Zoo (Knight, Nguyen, Falkner, Bowden, Roughan, IEEE JSAC")
    for words in ("Creative Commons Attribution 4.0", "logical links", "not the networks of today", "newest map"):
        assert words in cards.ZOO_LICENCE, words
    # the lines on land most like backbones: none on power poles; Wikidata's data centres of every kind
    assert '["submarine"!="yes"][!"power"];' in sets[2].query and "none on power poles" in sets[2].about
    assert "{ VALUES ?kind { wd:Q671224 } ?item wdt:P31/wdt:P279* ?kind . }" in sets[3].query
    assert all(f"wd:{k}" in sets[3].query for k in infrastructure.KINDS)
    licences = {x.url for c in cards.NETSTAT for x in c.links if x.kind == "terms"}
    assert {"https://opendatacommons.org/licenses/odbl/1-0/", "https://www.openstreetmap.org/copyright",
            "https://www.wikidata.org/wiki/Wikidata:Licensing", "https://creativecommons.org/licenses/by/4.0/",
            cards.ZOO_RAW + "LICENSE"} <= licences
    # nothing names PeeringDB, root-server sites or a cloud's regions: not free-licensed, or no licence stated
    said = json.dumps(cards.INFRASTRUCTURE).lower()
    assert "peeringdb" not in said and "root-servers" not in said


def test_the_submarine_cables_are_asked_of_every_telecom_category_the_map_uses():
    """The user, 2026-11-16: "have all the backbones,ibones, major internet infrastructure, (as many as possible)". A
    submarine cable's use is its seamark:cable_submarine:category: the OSM wiki names a fibre optic cable "optical",
    and the map spells it, and telephone's, other ways too (taginfo, 2026-11-18: telephone 749, fibre_optic 366,
    fiber_optic 64, optical 5, telefon 2, telegraph, communication and telephone/fibre_optic 1 each). Every one of them
    is asked for, as a whole value, and no power, mooring or ferry cable."""
    cables = next(d for d in cards.INFRASTRUCTURE if d["id"] == "osm-cables")
    [categories] = re.findall(r'\["seamark:cable_submarine:category"~"([^"]+)"\]', cables["query"])
    for value in ("optical", "fibre_optic", "fiber_optic", "telephone", "telefon", "telegraph", "communication",
                  "telephone/fibre_optic"):
        assert re.search(categories, value), value
    for value in ("power", "mooring", "ferry", "sensor", "disused", "optical_x", "non_optical"):  # whole values alone
        assert not re.search(categories, value), value
    assert cables["about"] == "about 1,200 cable ways and 60 landing stations"
    queries = {a.name: a for a in cards.OVERPASS_API.areas}["Queries"].covered
    assert "optical, fibre_optic and fiber_optic, telephone, telegraph" in queries  # the card says which


def test_the_data_sets_are_pinned_as_the_windows_firewall_plugin_names_them():
    """The Windows firewall plugin names the same data sets, in the same order (apis.INFRASTRUCTURE there, compared key
    by key on 2026-11-19), and its tests pin the same digest. Kept alike by hand, the two drifted once unseen (the
    review's finding 12: there osm-cables asked two of the eight telecom categories), so a change to them is a change
    made on purpose, to both plugins and to both pins."""
    said = json.dumps(cards.INFRASTRUCTURE, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    assert hashlib.sha256(said.encode("utf-8")).hexdigest() == INFRASTRUCTURE_SHA256


def test_the_topology_zoos_maps_are_read_into_backbones_and_their_points_of_presence():
    """A map in the shape the Topology Zoo's archive holds it, read by the library as the plugin names it: its own
    points with a place, the link between two of them, the point of another network's and the link to it left out."""
    zoo = next(d for d in cards.INFRASTRUCTURE if d["id"] == "topology-zoo")
    found = infrastructure.parse(zoo, zoo_archive({"gml/Nordu2010.gml": NORDU}))
    assert found["layers"]["pops"]["points"] == [(18.0649, 59.33258, "Stockholm (NORDUnet)", "NORDUnet, 2010"),
                                                 (10.74609, 59.91273, "Oslo (NORDUnet)", "NORDUnet, 2010")]
    assert found["layers"]["backbones"]["lines"] == [([(10.74609, 59.91273), (18.0649, 59.33258)],
                                                      "NORDUnet, 2010: Oslo to Stockholm")]
    assert found["dropped"] == {"outside its network": 1, "between points not drawn": 1}
    layers = {x[0]: x for x in infrastructure.LAYERS}
    assert layers["backbones"][1:] == ("Backbones, about 2010-2011", "lines", "line", 7, True, 4.0)
    assert layers["pops"][1:3] == ("Backbones' points of presence, about 2010-2011", "points")


def test_the_plugins_view_offers_each_data_set_as_a_job_its_licence_first(tmp_path):
    fw = plugin()
    view = fw.netstat_view()  # the base's own, over this plugin's data sets (none refused)
    try:
        assert view.refused == () and [d.id for d in view.index.datasets] == [d["id"] for d in cards.INFRASTRUCTURE]
        # the plugin's name and its version, nothing of yours (no version where its distribution says none)
        assert view.agent == netstat.agent_of(fw.name, fw.version) and view.agent.startswith("firewall-linux")
        forms = {f["id"]: f for f in view.index.forms(can=True)}
        assert sorted(forms) == sorted(f"world-layer-{d['id']}" for d in cards.INFRASTRUCTURE)
        for d in cards.INFRASTRUCTURE:
            f = forms[f"world-layer-{d['id']}"]
            assert f["hook"] == "world_layer_get" and f["job"] is True and f["hook"] in fw.JOB_HOOKS
            [accept] = [x for x in f["fields"] if x["type"] == "accept"]
            assert accept["name"] == "accept_licence" and accept["words"] == d["licence"]
            assert DataSet.of(d).host in f["confirm"]["words"]
        assert not infrastructure.folder().exists()  # nothing downloaded, nothing made
    finally:
        fw.detach()


# -- the cards ---------------------------------------------------------------------------------------------------------
def test_the_socket_tables_card_names_every_file_the_librarys_reader_reads():
    assert problems(cards.NETSTAT) == [] and cards.APIS[-7:] == cards.NETSTAT
    files = {re.search(r"/proc/(\S+)", c.name).group(1) for c in cards.PROCFS.used}
    assert {f.replace("/<fd>", "") for f in files} == set(sockets.LINUX_FILES)  # those, and no other
    assert all(c.name.split()[0] in ("read", "readlink") for c in cards.PROCFS.used)  # files alone: no command
    assert not any(c.used for c in cards.PROCFS.calls if c.area == "Socket diagnostics (sock_diag)")
    assert cards.PROCFS.kind == "kernel" and cards.PROCFS.auth.startswith("none")
    assert "no command, no capture and no root" in cards.PROCFS.about
    # the listeners another user holds are named from the firewall's read, through ss: its card says so
    ss = {c.name: c for c in cards.IPROUTE2.calls}
    assert all("the Netstat tab's listeners" in ss[n].used for n in ("ss -ltnpH", "ss -lunpH"))
    # what Under WSL's row rests on is linked: Microsoft's page on WSL's networking
    assert cards.WSL_NETWORKING in {x.url for x in cards.PROCFS.links}


# -- the listeners another user holds: from the firewall's read kept ---------------------------------------------------
def test_the_listeners_another_user_holds_are_named_from_the_read_kept_and_naming_them_runs_nothing():
    fake = FakeLinux("debian-13-nftables")
    fw = plugin(fake)
    assert fw.netstat_listeners() == {} and fake.calls == []  # no read yet: none named, and none made for it
    fw.config()  # the firewall's read, as its Main tab makes it
    ran = len(fake.calls)
    assert fw.netstat_listeners() == {("tcp", 22): "sshd", ("tcp", 5432): "docker-proxy", ("tcp", 8775): "python3"}
    assert len(fake.calls) == ran  # the read kept: nothing run
    # UDP's too; a port two programs hold names both; one ss named no program for is left out
    udp = FakeLinux("debian-13-nftables", listen_udp=(
        'UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("avahi-daemon",pid=700,fd=12))\n'
        'UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=600,fd=13))\n'
        'UNCONN 0 0 192.168.122.1:53 0.0.0.0:* users:(("dnsmasq",pid=900,fd=5))\n'
        'UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\n'))
    fw = plugin(udp)
    fw.config()
    named = fw.netstat_listeners()
    assert named[("udp", 5353)] == "avahi-daemon" and named[("udp", 53)] == "dnsmasq, systemd-resolve"
    assert ("udp", 51820) not in named and named[("tcp", 22)] == "sshd"
    assert netstat_mod.listeners(None) == {} and netstat_mod.listeners(types.SimpleNamespace(system=None)) == {}
    # on a machine it is not for: nothing, whatever was kept
    fw._native = WINDOWS
    assert fw.netstat_listeners() == {}
    # it reads the read kept without its lock, so a read under way (as root, up to 90 s) never holds the tab
    assert "_lock" not in inspect.getsource(LinuxFirewallPlugin.netstat_listeners)


def test_a_listener_net_tools_names_no_program_for_is_named_by_nothing_as_one_ss_names_none_for(monkeypatch):
    """A Linux without ss (Alpine's BusyBox, minimal images): the read falls back to net-tools' netstat -ltnp, whose
    PID/Program column is "-" for a socket no process holds (the kernel's nfsd on 2049). Like ss's "?" that names no
    program (the rules' groups take both so: groups.UNKNOWN), so the Netstat tab says the socket's own words there."""
    fake = FakeLinux("alpine-3.22-iptables")
    assert "listen" not in fake.sections  # no ss here: its listeners are net-tools'
    rc, text = fake.sections["listen.netstat"]
    nfs = "tcp        0      0 0.0.0.0:2049            0.0.0.0:*               LISTEN      -\n"  # net-tools' line
    fake.sections["listen.netstat"] = (rc, text.rstrip("\n") + "\n" + nfs)
    fw = plugin(fake)
    nfsd = sock(local="0.0.0.0", local_port=2049, state="listening", pid=0, program="", path="", user="root",
                inode=4009, unread={"program": ANOTHER})
    monkeypatch.setattr(sockets, "read", lambda *args, **kwargs: reading([linux_rows()[0], nfsd]))
    try:
        fw.config()
        assert "-" in fw._read[1].system.listening  # the read keeps net-tools' word, as the rules' groups read it
        assert fw.netstat_listeners() == {("tcp", 22): "sshd"}
        listening = {texts(r)[0]: r for r in table(fw.ask("netstat"), "Listening ports")["rows"]}
        assert listening["22"][3] == {"text": "sshd", "sub": NAMED_BY_READ}
        assert listening["2049"][3] == ANOTHER  # not a program named "-"
    finally:
        fw.detach()
    assert set(netstat_mod.UNNAMED) == set(UNKNOWN) == {"?", "-", ""}


def test_the_netstat_tab_names_a_listener_another_user_holds_from_the_read_kept(monkeypatch):
    fake = FakeLinux("debian-13-nftables")
    fw = plugin(fake)
    monkeypatch.setattr(sockets, "read", lambda *args, **kwargs: reading())  # the base's reader, stood in
    try:
        fw.config()
        ran = len(fake.calls)
        page = fw.ask("netstat")  # as the platform asks it, every 3 s while the tab is shown
        assert len(fake.calls) == ran  # the tab runs no command
        assert page["title"] == "Netstat" and json.dumps(page, allow_nan=False)
        listening = {texts(r)[0]: r for r in table(page, "Listening ports")["rows"]}
        assert listening["22"][3] == {"text": "sshd", "sub": NAMED_BY_READ}  # root's, named by the root read
        assert listening["631"][3] == ANOTHER  # root's, and the read named none on that port: its own words
        assert texts(listening["8775"])[3] == "python3 (pid 3301)"  # the platform's user's own: from /proc
        rows = {r["remote"]: r for r in page["flows"]["rows"]}
        assert rows[f"{WEB}:443"]["labels"] == [{"kind": "internet"}] and rows[f"{WEB}:443"]["dir"] == "out"
        inward = rows[f"{PRINTER}:50500"]  # the local network's, into sshd: root's, its program the read's words
        assert inward["labels"] == [{"kind": "local network"}] and inward["dir"] == "in"
        assert "Under WSL" not in [t["title"] for t in page["tables"]]  # a machine of its own
    finally:
        fw.detach()


def test_the_hosts_file_of_the_machine_the_tests_run_on_never_names_a_row(monkeypatch):
    """The base's view, made with no names of its own (as the plugin's is), names the rows' hosts from this system's
    hosts file (sockets.known_names: /etc/hosts, or Windows' own). The suite's guard stands it in, so the machine the
    tests run on never shows through: its file is never read."""
    read: list = []
    monkeypatch.setattr(sockets, "_hosts_text", lambda *args, **kwargs: read.append(args) or f"{WEB} named.example\n")
    monkeypatch.setattr(sockets, "read", lambda *args, **kwargs: reading())  # the base's reader, stood in
    fw = plugin()
    try:
        page = fw.ask("netstat")
        assert fw.netstat_view(make=False).names() == {}
        assert "named.example" not in json.dumps(page)
    finally:
        fw.detach()
    assert read == []


# -- valid and present wherever the socket table can be read (B-revisions S2) ------------------------------------------
def test_valid_and_present_wherever_the_socket_table_can_be_read_and_what_it_needs_is_said(monkeypatch):
    odd = lambda args, timeout: (2, b"", b"sh: 1: Syntax error")  # noqa: E731 - a read failing for its own reasons
    fw = LinuxFirewallPlugin(shell=Shell("local", runner=odd), native="")
    st = fw.status()
    assert (st["valid"], st["why"], st["summary"]) == (True, "", "not read: its read failed")
    assert st["problem"] == "The firewall cannot be read here: sh: 1: Syntax error."
    needs = table(st, "What the firewall needs here")
    assert needs["rows"][-1][:2] == ["Netstat and the hosts database", "need no rights"]
    assert "work while the firewall's rules are not read" in needs["rows"][-1][2]
    assert fw.present() and "netstat" in fw.interface()["hooks"]  # in the tray, and its tabs asked
    assert st["forms"] == [] and st["actions"][0]["hook"] == "refresh"  # no change it cannot make
    logged: list = []
    nothing = [{"step": "enable", "ok": False, "detail": "no firewall here this plugin drives"}]
    assert fw.setup(log=logged.append) == nothing
    assert logged == ["firewall-linux: enable: FAILED: no firewall here this plugin drives"]
    # no firewall software at all: present for its Netstat tab, its status saying so as present() does (the platform's
    # command line prints the status' word), and the setup changes nothing there either
    bare = Bare(shell=Shell("local", runner=odd), native="")
    st = bare.status()
    assert st["valid"] and st["present"] and bare.present() and not bare.firewall_here()
    assert bare.setup(log=lambda line: None)[0]["detail"] == "no firewall here this plugin drives"
    # no socket table this account may read: as 0.8.2, not valid where the read failed for its own reasons
    monkeypatch.setattr(netstat_mod, "tables_here", lambda: False)
    fw = LinuxFirewallPlugin(shell=Shell("local", runner=odd), native="")
    st = fw.status()
    assert not st["valid"] and st["why"] == "cannot be read: sh: 1: Syntax error" and not fw.present()
    assert table(st, "What the firewall needs here")["rows"][-1][:2] == ["Netstat and the hosts database",
                                                                       "no socket table here"]
    bare = Bare(shell=Shell("local", runner=odd), native="")
    assert not bare.status()["present"] and not bare.present()  # nothing served here: not present, as 0.8.2
    # a library from before the Netstat tab: as 0.8.2, the row saying what the tab would need
    monkeypatch.setattr(netstat_mod, "tables_here", lambda: True)
    monkeypatch.setattr(netstat_mod, "library", lambda: False)
    fw = LinuxFirewallPlugin(shell=Shell("local", runner=odd), native="")
    st = fw.status()
    assert not st["valid"] and not fw.present()
    row = table(st, "What the firewall needs here")["rows"][-1]
    assert row[:2] == ["Netstat and the hosts database", "not in this library"]
    assert f"liminal-libs {netstat_mod.NETSTAT_LIBS}" in row[2]
    assert re.fullmatch(r"\d+\.\d+\.\d+", netstat_mod.NETSTAT_LIBS)  # its number, set at landing, one place


def test_present_runs_no_read_of_the_firewall_where_the_netstat_tab_is_served(monkeypatch):
    """The platform's tray asks present() every minute while a page is open. Where the Netstat tab is served that
    answers alone: no read as root is run for it (each a sudo -n that sudo notes in its log, a refusal too). Where it
    is not served, the firewall's own read answers, as before 0.9.0."""
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 1000, raising=False)  # as sysop: the read is sudo -n's
    fake = FakeLinux("debian-13-nftables")
    fw = plugin(fake)
    assert fw.present() and fw.present() and fake.calls == []
    monkeypatch.setattr(netstat_mod, "tables_here", lambda: False)  # no socket table here: the firewall's read
    assert fw.present() and fake.reads == 1 and fake.calls[-1][:2] == ["sudo", "-n"]


def test_the_needs_row_names_every_program_where_the_platform_runs_as_root(monkeypatch):
    """As root the socket table gives every socket's program, so the row of what the Netstat tab needs says so; as
    another user it names that user's own alone, and says why."""
    odd = lambda args, timeout: (2, b"", b"sh: 1: Syntax error")  # noqa: E731 - a read failing for its own reasons
    st = LinuxFirewallPlugin(shell=Shell("local", runner=odd), native="").status()  # as root (_nothing_real)
    assert st["rootAccess"].startswith("the platform runs as root")
    row = table(st, "What the firewall needs here")["rows"][-1]
    assert row[:2] == ["Netstat and the hosts database", "need no rights"]
    assert "naming every program (the platform runs as root)" in row[2] and "your own programs" not in row[2]
    assert "work while the firewall's rules are not read" in row[2]
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 1000, raising=False)  # as sysop: sudo asks for a password
    refused = lambda args, timeout: (1, b"", b"sudo: a password is required")  # noqa: E731
    st = LinuxFirewallPlugin(shell=Shell("local", runner=refused), native="").status()
    assert not st["rootAccess"].startswith("the platform runs as root")
    row = table(st, "What the firewall needs here")["rows"][-1]
    assert row[:2] == ["Netstat and the hosts database", "need no rights"]
    assert "naming your own programs (another user's: only root reads which program holds it)" in row[2]
    assert "the platform runs as root" not in row[2]


def test_the_tables_are_looked_at_and_never_read_to_say_whether_they_can_be(monkeypatch):
    looked: list = []

    def access(path, mode):  # os.access as the module asks it: whether the file may be read, nothing read
        looked.append((path, mode))
        return path.endswith("udp6")
    monkeypatch.setattr(netstat_mod, "os", types.SimpleNamespace(access=access, R_OK=os.R_OK))
    assert TABLES_HERE() and looked == [(p, os.R_OK) for p in netstat_mod.PROC_NET]
    looked.clear()
    refused = types.SimpleNamespace(access=lambda path, mode: looked.append(path) and False, R_OK=os.R_OK)
    monkeypatch.setattr(netstat_mod, "os", refused)
    assert not TABLES_HERE() and looked == list(netstat_mod.PROC_NET)
    assert netstat_mod.PROC_NET == tuple(f"/proc/{f}" for f in sockets.LINUX_FILES[:4])  # the reader's four tables


# -- inside WSL: what was seen in the user's Ubuntu --------------------------------------------------------------------
def test_inside_wsl_2_the_netstat_tab_ends_with_what_was_seen_in_the_users_ubuntu(monkeypatch):
    """The user, 2026-11-15: "wsl and firewall linux should always work under linux, if wsl prevents or misses some
    capability this should reflect in the plugin". Seen in the user's Ubuntu (WSL 2, NAT networking, 2026-11-18, read
    only): the TCP ports listening at 127.0.0.1 there were exactly those Windows' own table listed as wslrelay.exe's at
    Windows' 127.0.0.1, and 127.0.0.53's and 10.255.255.254's were not; nor was any UDP port: chronyd listened at
    127.0.0.1:323/udp inside, and wslrelay.exe held no UDP endpoint, nor did anything on Windows hold 323/udp. The
    library's Under WSL table comes first, unchanged."""
    asked: list = []
    monkeypatch.setattr(sockets, "under_wsl", lambda *args, **kwargs: asked.append(1) or UNDER)
    monkeypatch.setattr(linux_mod, "wsl_generation", lambda release=None: 2)
    fw = Tabbed()
    try:
        under = table(fw.ask("netstat"), "Under WSL")
        assert under["rows"] == [*UNDER["rows"], *map(list, netstat_mod.WSL_ROWS)] and asked == [1]
        assert len(UNDER["rows"]) == 1  # the library's table itself is left as it was
        [row] = netstat_mod.WSL_ROWS
        assert row[0] == "Reached from Windows" and row[1] == "TCP listening at 127.0.0.1"
        for said in ("WSL forwards it", "wslrelay.exe", "127.0.0.53", "is not forwarded", "NAT networking"):
            assert said in row[2], said
        # a TCP port's alone: a UDP one at 127.0.0.1 inside is not reached from Windows (chronyd's 323/udp was not)
        assert "reach a TCP port listening here at 127.0.0.1" in row[2]
        assert "So for TCP, Reached from \"this machine only\" takes in Windows' programs" in row[2]
        assert "UDP is not forwarded (chronyd's 323/udp was not)" in row[2]
        assert row[2].count("this machine only") == 1
        monkeypatch.setattr(linux_mod, "wsl_generation", lambda release=None: 0)  # a release that does not tell:
        assert table(fw.ask("netstat"), "Under WSL")["rows"] == under["rows"]  # WSL 2, as the library takes it
        monkeypatch.setattr(linux_mod, "wsl_generation", lambda release=None: 1)  # WSL 1: nothing forwarded
        assert table(fw.ask("netstat"), "Under WSL")["rows"] == UNDER["rows"]
        monkeypatch.setattr(linux_mod, "wsl_generation", lambda release=None: 1 / 0)  # a check that cannot say
        assert table(fw.ask("netstat"), "Under WSL")["rows"] == UNDER["rows"]
        monkeypatch.setattr(sockets, "under_wsl", lambda *args, **kwargs: None)  # a machine of its own: no table
        assert "Under WSL" not in [t["title"] for t in fw.ask("netstat")["tables"]]
    finally:
        fw.detach()
    assert netstat_mod.with_wsl_rows({"title": "Netstat"}) == {"title": "Netstat"}  # a page without tables: as it is


# -- on Windows and macOS: nothing -------------------------------------------------------------------------------------
@pytest.mark.parametrize("note", [WINDOWS, MACOS], ids=["windows", "macos"])
def test_on_windows_or_macos_the_netstat_tab_reads_nothing(note):
    fake = FakeLinux("debian-13-nftables")
    fw = plugin(fake, native=note)
    assert fw.ask("netstat") == {"title": "Netstat", "note": f"Not for this machine: {note}. Nothing is read here."}
    with pytest.raises(ValueError, match="not for this machine"):
        fw.ask("world_layer_get", "osm-datacentres", True)
    assert fw.netstat_view(make=False) is None and fw.netstat_listeners() == {} and not fw.present()
    assert fake.calls == [] and fw.api_facts() == {} and not infrastructure.folder().exists()
    fw.attach(object(), EnvironmentLogin(env={hostbook.VARIABLE: "always"}))
    assert fw.netstat_view(make=False) is None  # attached: nothing made, nothing recording
    fw.detach()


# -- B-critique B1: the guard's own test ------------------------------------------------------------------------------
def test_attached_under_a_login_that_says_always_it_records_nothing_real(_no_real_hosts, tmp_path):
    """The platform's suite builds its app with no login given, so with this user's own variables, and attaches its
    plugins. Here this user's saved variables say LIMINAL_HOSTS_RECORDING=always (what the Recording form keeps): the
    guard's "shown" in the test's process wins (the process's own variable over a saved one), so nothing records; the
    socket table the view would read is the guard's refusal; the database and the layers are in the test's folder."""
    saved = {"LIMINAL_HOSTS_RECORDING": "always"}
    fw = plugin()
    fw.attach(object(), EnvironmentLogin(saved=lambda: dict(saved)))  # the platform's own login, as it reads it
    try:
        view = fw.netstat_view(make=False)
        assert view is not None and view.mode() == "shown" and not view.recording()
        assert not [t for t in threading.enumerate() if t.name.endswith("-hosts")]
        assert os.environ[hostbook.VARIABLE] == "shown"
        assert Path(hostbook.path()).is_relative_to(tmp_path) and Path(infrastructure.folder()).is_relative_to(tmp_path)
        with pytest.raises(Reached, match="socket table for real"):
            view.touch()  # the reader the plugin's view is made with: the guard's
        assert _no_real_hosts == ["sockets.read ()"]
        _no_real_hosts.clear()  # (read on purpose: the guard's own check at the end stays quiet)
        assert not Path(hostbook.path()).exists()  # nothing was kept
    finally:
        fw.detach()


# -- what the cards learned: asking nothing --------------------------------------------------------------------------
def test_the_netstat_facts_are_what_the_tab_read_and_asking_them_reads_nothing(monkeypatch):
    fw = Tabbed(rows=[sock(remote=WEB, remote_port=443), sock(local=LAN, local_port=41002, remote=PRINTER,
                                                              remote_port=631, inode=7003)])
    assert cards.PROCFS.name not in fw.api_facts()  # before the tab was asked: nothing said, and no view made
    assert fw.netstat_view(make=False) is None and fw.readings == 0
    fw.ask("netstat")
    readings = fw.readings
    facts = fw.api_facts()[cards.PROCFS.name]
    assert fw.readings == readings  # asking them read nothing
    assert re.fullmatch(r"2 sockets in 4 ms, \d+ s ago", facts["Last reading"]), facts
    assert facts["Recording"] == "only while this plugin's Netstat or World Wide Web tab is shown"
    assert re.fullmatch(r"\d+ rows? \(\d+ hosts?, \d+ programs?\), .+, in .+hosts\.db(, recorded since .+)?",
                        facts["Hosts database"]), facts
    for d in cards.INFRASTRUCTURE:  # each data set under its source's card, none downloaded
        card = {"overpass": cards.OVERPASS_API, "sparql": cards.WIKIDATA, "geojson": cards.EMODNET,
                "gml": cards.TOPOLOGY_ZOO,
                "ourairports": cards.OURAIRPORTS_API, "geonames": cards.GEONAMES_API}[d["format"]]
        assert fw.api_facts()[card.name][d["title"]].startswith("not downloaded: the World Wide Web tab's")
    fw.detach()
    assert cards.PROCFS.name not in fw.api_facts()  # detached: the view let go, nothing said
    # each data set under its source's card: one installed, one being downloaded, one not downloaded
    view = types.SimpleNamespace(describe=lambda: {
        "reading": None, "book": None, "mode": "always", "recording": False, "error": "",
        "sets": [{"id": "osm-datacentres", "title": "Data centres", "format": "overpass", "installed": True,
                  "features": 5073, "fetched": "2026-11-18T20:00:00+00:00", "bytes": 1_234_567,
                  "downloading": False},
                 {"id": "wikidata", "title": "Exchange points, ground stations and teleports", "format": "sparql",
                  "installed": False, "features": 0, "fetched": None, "downloading": True},
                 {"id": "emodnet-cables", "title": "Telecom cable routes in European waters", "format": "geojson",
                  "installed": False, "features": 0, "fetched": None, "downloading": False}]})
    made: list = []
    said = cards.netstat_facts(types.SimpleNamespace(netstat_view=lambda make=True: made.append(make) or view))
    assert made == [False] and said[cards.PROCFS.name] == {
        "Last reading": "none yet: the socket tables are read while the Netstat or World Wide Web tab is shown",
        "Recording": "all the time the platform runs, but not recording now",
        "Hosts database": ("not opened yet: it is read and written while one of the two tabs is shown, or as "
                           "recording says")}
    size = world.size_words(1_234_567)
    assert said[cards.OVERPASS_API.name] == {"Data centres": f"5,073 features, fetched 2026-11-18 ({size})"}
    assert said[cards.WIKIDATA.name] == {"Exchange points, ground stations and teleports":
                                         "being downloaded now (its progress is in the plugin's panel)"}
    assert said[cards.EMODNET.name]["Telecom cable routes in European waters"].startswith("not downloaded")
    assert cards.netstat_facts(object()) == {}  # a library from before the Netstat tab: nothing
    broken = types.SimpleNamespace(netstat_view=lambda make=True: types.SimpleNamespace(describe=lambda: 1 / 0))
    assert cards.netstat_facts(broken) == {}  # what the tab read is extra: the cards are drawn without it
    # the base's view is reached through its accessor alone (netstat_view, liminal-libs 1.65.0)
    source = inspect.getsource(cards.netstat_facts)
    assert "_netstat" not in source.replace("netstat_facts", "") and "__dict__" not in source


def test_with_a_library_from_before_the_netstat_tab_its_cards_and_its_words_are_left_out(monkeypatch):
    assert netstat_mod.cards(cards.APIS, cards.NETSTAT) == cards.APIS == MACHINE.apis  # this library has it
    assert "Netstat tab" in MACHINE.about  # (its words follow the library the plugin was loaded with)
    monkeypatch.setattr(netstat_mod, "library", lambda: False)
    assert netstat_mod.cards(cards.APIS, cards.NETSTAT) == cards.FIREWALL + cards.WORLD  # it reaches none of them there


# -- the plugin's own lines --------------------------------------------------------------------------------------------
def test_the_lines_written_for_the_netstat_tab_are_120_characters_at_most():
    here = Path(__file__).resolve()
    for path in (here, Path(netstat_mod.__file__)):
        long = [i for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1) if len(line) > 120]
        assert long == [], (path.name, long)
