"""What the Linux firewall attaches to (plugin API 2.2): its cards are sound; they name every command of the read script
and every change the plugin runs (driven over the recorded machines: Debian's nftables, Gentoo's under OpenRC, Ubuntu's
ufw, Fedora's firewalld, Alpine's iptables), and the commands its plans give each init and distribution; the World Wide
Web tab's cards (0.8.0) name every libpcap call the library's capture makes, the download the tab asks for and the
reader's calls the library makes, and each question the tab asks of a name server; its facts are what the last read
found, asked without a command; and the cards' pages answer (LIMINAL_VENDOR_PAGES=1 only, the one test that reaches the
network). 0.9.0: sudo's card names its password on standard input, Root access's files and visudo, the users and groups'
card the group liminal's making, and APT's card nftables' install, each driven through a stand-in sudo
(tests/sudo.py)."""
from __future__ import annotations

import inspect
import os
import re
import shlex
import subprocess
from datetime import datetime, timezone

import pytest

from liminal_libs import capture, dns, geo
from liminal_libs.machines import linux as linux_mod
from liminal_libs.machines import world
from liminal_libs.machines.linux import Shell
from liminal_libs.sources.apis import dead_links, problems
from plugin_platform_firewall_linux import MACHINE, LinuxFirewallPlugin
from plugin_platform_firewall_linux import apis as cards
from plugin_platform_firewall_linux import netstat as netstat_mod
from plugin_platform_firewall_linux import nftables as nft_mod
from plugin_platform_firewall_linux import system as sys_mod
from plugin_platform_firewall_linux import ufw as ufw_mod
from plugin_platform_firewall_linux.read import SCRIPT

from machines import SUDO, FakeLinux
from sudo import LIB, PASSWORD, Sudo


def plugin(fake) -> LinuxFirewallPlugin:
    return LinuxFirewallPlugin(shell=Shell("local", runner=fake), native="", clock=lambda: 1000.0)


def drive(monkeypatch):
    """The changes the plugin makes, over the recorded machines, as root: rules made and removed through each front
    end, a table of Liminal's own, the defaults set, the front ends and services turned on and off, the rules saved; then
    a read as an ordinary user (through sudo -n). Every command run but the read, and the read's."""
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 0, raising=False)
    ran: list[list[str]] = []
    gentoo = FakeLinux("gentoo-openrc-nftables")
    fw = plugin(gentoo)
    fw.make_rule("web", "in", "allow", "tcp", "8443", "10.0.0.0/8")
    fw.make_rule("spam", "in", "block", "tcp", "25", "203.0.113.0/24")
    fw.set_policy("inet filter output", "drop")
    fw.save_rules("nftables")
    fw.switch("nftables", "off", accept_risk=True)
    ran += gentoo.changes
    debian = FakeLinux("debian-13-nftables")
    fw = plugin(debian)
    fw.remove_rule("inet filter input", "tcp dport { 80, 443 } accept")
    fw.save_rules("nftables")
    ran += debian.changes
    bare = FakeLinux("fedora-43-firewalld", firewalld_state=(252, "not running"))
    bare.sections = {k: v for k, v in bare.sections.items() if not k.startswith("firewalld")}
    bare.nft({"nftables": [{"metainfo": {"version": "1.1.3", "json_schema_version": 1}}]})
    plugin(bare).make_rule("telnet", "in", "block", "tcp", "23")
    ran += bare.changes
    ubuntu = FakeLinux("ubuntu-24.04-ufw")
    fw = plugin(ubuntu)
    fw.make_rule("office", "in", "allow", "tcp", "8443", "192.168.1.0/24", "eth0")
    fw.remove_rule("ufw", "80,443/tcp  ALLOW IN  Anywhere  # web")
    fw.set_policy("ufw routed", "deny")
    fw.switch("ufw", "off", accept_risk=True)
    ran += ubuntu.changes
    off = FakeLinux("ubuntu-24.04-ufw", init="openrc init", ufw_verbose="Status: inactive", ufw_numbered="Status: inactive",
                    services="ufw yes stopped -")
    plugin(off).switch("ufw", "on")
    ran += off.changes
    fedora = FakeLinux("fedora-43-firewalld")
    zones, services = fedora.sections["firewalld.zones"][1], fedora.sections["firewalld.services"][1]
    fedora.set("firewalld.zones", zones.replace("services: cockpit dhcpv6-client ssh", "services: cockpit dhcpv6-client ssh liminal-mail", 1))
    fedora.set("firewalld.services", services + "liminal-mail\n  ports: 2525/tcp\n")
    fw = plugin(fedora)
    assert fw.remove("mail")  # Liminal's, made as a firewalld service: taken out of the zone and deleted
    fw.make_rule("office", "in", "allow", "tcp", "8443-8444", "10.1.0.0/16")
    fw.make_rule("web", "in", "allow", "tcp", "8080")
    fw.remove_rule("zone FedoraServer", "port 8443/tcp")
    fw.set_policy("zone FedoraServer", "DROP")
    ran += fedora.changes
    stopped = FakeLinux("fedora-43-firewalld", firewalld_state=(252, "not running"))
    plugin(stopped).switch("firewalld", "on")
    plugin(stopped).make_rule("mail", "in", "allow", "tcp", "2525")
    ran += stopped.changes
    alpine = FakeLinux("alpine-3.22-iptables")
    fw = plugin(alpine)
    fw.make_rule("web", "in", "allow", "tcp", "80,443")
    fw.make_rule("one", "in", "reject", "udp", "161", "10.0.0.9")
    fw.remove_rule("filter INPUT", "-p icmp -j ACCEPT")
    fw.set_policy("iptables filter FORWARD", "ACCEPT")
    fw.save_rules("iptables")
    ran += alpine.changes
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 1000, raising=False)
    user = FakeLinux("debian-13-nftables")
    plugin(user).status()
    read_calls, fed = list(user.calls), []
    if LIB is None:  # a library from before the grant: no Root access to drive (the test leaves its cards out)
        return ran, read_calls, fed
    # 0.9.0, through a stand-in sudo (tests/sudo.py): Root access turned on (the group made and the user put in it, the
    # grant), then on (its read, a change with the password, turned off by its helper); turned off where the helper
    # cannot run yet; nftables installed where there is no tool; and BusyBox's addgroup where there is no groupadd
    off, on, pending = Sudo("debian-13-nftables"), Sudo("debian-13-nftables", state="on"), Sudo(state="pending")
    bare, busybox = Sudo("ubuntu-24.04-ufw", tools="ip /usr/sbin/ip"), Sudo("debian-13-nftables")
    off.install(monkeypatch).root_access("on", PASSWORD)
    fw = on.install(monkeypatch)
    fw.status()
    fw.make_rule("web", "in", "allow", "tcp", "8443", None, None, False, PASSWORD)
    fw.root_access("off")
    pending.install(monkeypatch).root_access("off", PASSWORD)
    bare.install(monkeypatch).install_nftables(PASSWORD)
    busybox.install(monkeypatch, which=lambda tool: None if tool in ("groupadd", "usermod") else
                    busybox.which(tool) or (f"/bin/{tool}" if tool == "addgroup" else None)).root_access("on", PASSWORD)
    for machine in (off, on, pending, bare, busybox):
        ran += machine.run_as_root
        read_calls += machine.calls
        fed += [f for f in machine.fed if f]
    return ran, read_calls, fed


def planned() -> list[str]:
    """The commands the plugin's plans give each init and each distribution, as its own code writes them."""
    out = [" ".join(c) for init in ("systemd", "openrc", "sysvinit") for action in ("start", "stop")
           for c in sys_mod.service_command(init, "<service>", action)]
    services = {n: sys_mod.ServiceState(n, present=True) for n in ("netfilter-persistent", "iptables", "nftables-store")}
    for kind in ("nftables", "iptables"):
        for family in ("debian", "fedora", "arch", "gentoo", "alpine", "suse"):
            for init in ("systemd", "openrc"):
                keep = sys_mod.keeping(kind, family, init, {}, services, {})
                if keep.command:
                    out.append(" ".join(keep.command))
    dropping = nft_mod.Chain("inet", "filter", "input", type="filter", hook="input", prio=0, policy="drop")
    out.append(" ".join(nft_mod.add_rule(dropping, ["tcp", "dport", "443"], "accept", "liminal:web")))  # an allow at the end
    out.append(" ".join(["ufw", "--force", "delete", *ufw_mod.spec_words("allow 8443/tcp")]))  # by its words, while off
    return out


def literal(text: str) -> str:
    """Words as a pattern: any space between them, a|b either."""
    out = ""
    for part in re.split(r"(\s+)", text):
        if not part:
            continue
        if part.isspace():
            out += r"\s*"
        elif "|" in part:
            out += "(?:" + "|".join(re.escape(a) for a in part.split("|")) + ")"
        else:
            out += re.escape(part)
    return out


def pattern(name: str):
    """A call's name as a pattern of what is run: a <placeholder> some words, an [optional part] any or none."""
    text, out, at = name.removeprefix("GET "), [], 0
    for m in re.finditer(r"\[[^\]]*\]|<[^>]+>", text):
        out += [literal(text[at:m.start()]), r"(?:.*?)" if m.group().startswith("[") else r".+?"]
        at = m.end()
    out.append(literal(text[at:]))
    return re.compile("".join(out), re.S)


def carded(cmd: list[str]) -> list[str]:
    """A command as the cards write it: Shell's sudo named sudo -n, the -- it ends with (liminal-libs 1.80.0) no word of
    theirs."""
    return [*(w for w in SUDO if w != "--"), *cmd[len(SUDO):]] if cmd[:len(SUDO)] == SUDO else cmd


def canonical(cmd: list[str]) -> str | None:
    """A change as the cards name it (None for a script: its commands are matched by pattern; `env` and the variables it
    sets before a command left out); its own words when no card names it."""
    if cmd[:2] == ["sh", "-c"]:
        return None
    if cmd[:1] == ["env"]:
        cmd = list(cmd[1:])
        while cmd and "=" in cmd[0]:
            cmd = cmd[1:]
    line = " ".join(cmd)
    return next((c.name for api in MACHINE.apis for c in api.used
                 if cmd[0] in c.name.split()[0].split("|") and pattern(c.name).fullmatch(line)), line)


def test_the_cards_are_sound_and_each_says_where_its_documentation_is():
    assert problems(cards.APIS) == [] and cards.APIS == cards.FIREWALL + cards.WORLD + cards.NETSTAT
    # 0.9.0: the Netstat tab's cards with a library that has it, else left out (the plugin reaches none of them there)
    assert MACHINE.apis == (cards.APIS if netstat_mod.library() else cards.FIREWALL + cards.WORLD)
    assert [a.name for a in cards.APIS] == [
        "nftables (nft)", "iptables and ip6tables", "ebtables and arptables", "ipset", "firewalld", "ufw",
        "Connection tracking (conntrack)", "eBPF on the network (bpftool)", "iproute2 (ip and ss)",
        "The firewall's services (systemd, OpenRC, SysV)", "sudo",
        # Root access's and nftables' install's (0.9.0)
        "Users and groups (groupadd, usermod, addgroup)", "APT (apt-get, apt-cache)",
        # the World Wide Web tab's (0.8.0)
        "libpcap (packet capture)", "DB-IP Lite City (GeoIP)", "OpenDNS (myip.opendns.com)",
        "Google's name servers (o-o.myaddr.l.google.com)",
        # the Netstat tab's and the globe's internet infrastructure (0.9.0; the Topology Zoo's, 0.9.1)
        "The kernel's socket tables (procfs)", "Overpass API", "Wikidata Query Service",
        "EMODnet Human Activities (WFS)", "Internet Topology Zoo",
        "OurAirports", "GeoNames",  # liminal-libs 1.73.0: what routers' names are read with
        # 0.13.0 (liminal-libs 1.104.0): the fibre, its stand-ins, backbones, RIPE Atlas, the satellites
        "Natural Earth (1:10m roads and railways)", "AfTerFibre (NSRC)", "TopoHub (GitHub)", "RIPE Atlas",
        "CelesTrak (GP orbits)", "sgp4 (PyPI)"]
    rights_cards = (cards.SUDO, cards.GROUPS, cards.APT)  # their addresses read again, or for the first time, in 0.9.0
    assert all(a.verified == "2026-11-11" for a in cards.FIREWALL if a not in rights_cards)
    assert all(a.verified == "2026-11-17" for a in rights_cards)
    assert all(a.verified == "2026-11-15" for a in cards.WORLD)
    assert all(a.verified == cards.NETSTAT_VERIFIED == "2026-11-18" for a in cards.NETSTAT[:-9])
    assert cards.NETSTAT[-9] is cards.TOPOLOGY_ZOO  # the Topology Zoo's pages, read on 2026-11-19
    assert cards.NETSTAT[-8:-6] == (cards.OURAIRPORTS_API, cards.GEONAMES_API)  # liminal-libs 1.73.0
    assert all(a.verified == cards.ROUTERS_VERIFIED == "2026-11-22" for a in cards.NETSTAT[-8:-6])
    assert cards.NETSTAT[-6:] == cards.GLOBE2  # 0.13.0: their pages read on 2026-11-26
    assert all(a.verified == cards.VERIFIED_GLOBE2 == "2026-11-26" for a in cards.GLOBE2)
    assert cards.TOPOLOGY_ZOO.verified == cards.GLOBE_VERIFIED == "2026-11-19"
    assert all(a.docs and a.used and a.covered for a in cards.APIS)
    assert all(len(a.areas) > len(a.covered) for a in cards.APIS)  # more of each API than the plugin uses
    assert cards.NFTABLES.link("spec").endswith("libnftables-json.5.en.html")
    assert not any(c.costs for a in MACHINE.apis for c in a.calls)  # nothing here costs money


def test_the_cards_name_every_command_of_the_read_and_every_change(monkeypatch):
    ran, read_calls, fed = drive(monkeypatch)
    pool = [SCRIPT.replace("$fc", "firewall-cmd"), *(" ".join(carded(c)) for c in (*ran, *read_calls)), *planned(),
            *(shlex.join(c) for c in read_calls), *fed]  # 0.9.0: sudo -S -k -p '' as a shell writes it; the scripts fed
    driven = [a for a in cards.FIREWALL if LIB is not None or a not in (cards.SUDO, cards.GROUPS, cards.APT)]
    never = [f"{api.name}: {call.name}" for api in driven for call in api.used
             if not any(pattern(call.name).search(t) for t in pool)]
    assert never == []
    changes = {canonical(c) for c in ran} - {None}
    used = {c.name for api in MACHINE.apis for c in api.used}
    assert changes <= used, sorted(changes - used)
    assert read_calls[0][:len(SUDO) + 2] == [*SUDO, "sh", "-c"] and read_calls[0][len(SUDO) + 2] == SCRIPT  # the one read, as root through sudo


def test_its_facts_are_what_the_last_read_found_and_asking_them_runs_nothing(monkeypatch):
    monkeypatch.setattr(linux_mod.os, "geteuid", lambda: 0, raising=False)
    fake = FakeLinux("fedora-43-firewalld")
    fw = plugin(fake)
    assert fw.api_facts() == {} and fake.calls == []
    fw.status()
    before = len(fake.calls)
    facts = fw.api_facts()
    assert len(fake.calls) == before  # nothing run
    assert facts["firewalld"]["firewalld"].endswith(", running") and facts["firewalld"]["Default zone"] == "FedoraServer"
    assert facts["nftables (nft)"]["nft"] and "Tables" in facts["nftables (nft)"]
    assert facts["The firewall's services (systemd, OpenRC, SysV)"]["Read"].startswith("Fedora")
    ufw = plugin(FakeLinux("ubuntu-24.04-ufw"))
    ufw.status()
    assert ufw.api_facts()["ufw"]["ufw"].split(",")[1].strip() in ("on", "off")
    assert not set(facts) & {a.name for a in cards.WORLD}  # the World Wide Web tab never shown: nothing said of it


# -- the World Wide Web tab's cards (0.8.0) ------------------------------------------------------------------------------
def test_the_capture_card_names_every_libpcap_call_the_librarys_capture_makes(monkeypatch):
    declared = set(re.findall(r"lib\.(pcap_\w+)", inspect.getsource(capture._declared)))
    assert {c.name for c in cards.CAPTURE.used} == declared  # each call the capture makes said used, and no other
    assert {"pcap_open_live", "pcap_next_ex", "pcap_setnonblock", "pcap_get_selectable_fd"} <= declared
    # the capture the tab makes: every TCP and UDP packet, the headers alone (world.default_capture)
    assert next(c for c in cards.CAPTURE.calls if c.name == "pcap_compile").used == capture.bpf((), None, True) == "(tcp or udp)"
    assert "128 bytes" in next(c for c in cards.CAPTURE.calls if c.name == "pcap_open_live").used and capture.SNAPLEN == 128
    # the right to capture, as the tab says it on a Linux machine to a platform that is not root (no init known: both
    # ways, tests/conftest.py): each way it gives an administrator is a call on the card (CAP_NET_RAW alone, for the
    # platform alone), never made from here
    denied = "the adapter could not be opened: socket: Operation not permitted" + world.LIBRARY_HINT
    ways = [c for c in cards.CAPTURE.calls if c.area == "The right to capture"]
    for python in (("/usr/bin/python3.13", False), ("/opt/liminal/.venv/bin/python3", True)):  # the system's; its own copy
        monkeypatch.setattr(world, "_python", lambda python=python: python)
        told = world.capture_help(denied, windows=False, root=False)
        assert [c.name for c in ways if pattern(c.name).search(told)] == [c.name for c in ways], told
    assert all(c.writes and not c.used for c in ways)  # an administrator's
    assert "CAP_NET_RAW alone" in cards.CAPTURE.auth and "never a password" in cards.CAPTURE.auth
    assert cards.AMBIENT in {x.url for x in cards.CAPTURE.links} and cards.VENV in {x.url for x in cards.CAPTURE.links}
    assert "On the Linux the platform runs on only" in cards.CAPTURE.about and "inside a WSL distribution its own adapter" in cards.CAPTURE.about
    assert "none at all under WSL 1" in cards.CAPTURE.about and "on Windows and macOS nothing is opened" in cards.CAPTURE.about
    # what the capture cannot see: before nftables and iptables, after XDP
    assert "before nftables and iptables decide" in cards.CAPTURE.about and "What an XDP program drops" in cards.CAPTURE.about


def test_the_db_ip_card_names_the_download_the_tab_makes_and_the_readers_calls_the_library_makes():
    [download] = [c for c in cards.DBIP_LITE.used if c.name.startswith("GET ") and "city-lite" in c.name]
    now = datetime(2026, 11, 15, tzinfo=timezone.utc).timestamp()
    for year, month in world.months(now):  # this month's file and last month's: the two the tab asks for (a GET of each)
        assert pattern(download.name).fullmatch(world.month_url(MACHINE.GEOIP_URL, year, month))
    # liminal-libs 1.75.0: and the ASN file's, beside it
    [asn] = [c for c in cards.DBIP_LITE.used if c.name.startswith("GET ") and "asn-lite" in c.name]
    for year, month in world.months(now):
        assert pattern(asn.name).fullmatch(world.month_url(MACHINE.GEOIP_ASN_URL, year, month))
    assert cards.DBIP_LITE.base.startswith(MACHINE.GEOIP_URL.replace("{year}", "<year>").replace("{month}", "<month>"))
    assert cards.DBIP_LITE.link("terms") == "https://db-ip.com/db/lite.php"  # its licence and the credit it asks for
    assert "https://creativecommons.org/licenses/by/4.0/" in {x.url for x in cards.DBIP_LITE.links}
    assert MACHINE.ATTRIBUTION["url"] + "/" == cards.DBIP  # the credit links DB-IP's own site
    # the reader's calls, as the library's geo.py makes them; the whole file never read into memory
    source = inspect.getsource(geo)
    made = {"maxminddb.open_database(<file>, MODE_MMAP_EXT)": r"open_database\(.*MODE_MMAP_EXT\)",
            "Reader.get(<address>)": r"_reader\.get\(address\)",
            "Reader.get_with_prefix_len(<address>)": r"\.get_with_prefix_len\(",
            "Reader.metadata()": r"\.metadata\(\)"}
    assert {c.name for c in cards.DBIP_LITE.used} == {download.name, asn.name, *made}  # 1.75.0: the ASN file's too
    for call, said in made.items():
        assert re.search(said, source), call
    [memory] = [c for c in cards.DBIP_LITE.calls if "MODE_MEMORY" in c.name]
    assert not memory.used and "maxminddb.MODE_MEMORY" not in source
    assert "no address is sent anywhere" in cards.DBIP_LITE.about


def test_the_name_servers_cards_name_each_question_the_tab_asks(monkeypatch):
    # each question exactly as the library asks it (dns.public_address over this plugin's servers, by IP version, the
    # names made absolute: world.servers_of), its nslookup a stand-in that keeps what it was given: nothing runs
    ran: list[list[str]] = []

    def nslookup(args, **_):
        ran.append(list(args))
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
    monkeypatch.setattr(dns.subprocess, "run", nslookup)
    for version in (4, 6):
        assert dns.public_address(version, world.servers_of(MACHINE.PUBLIC_DNS, version))[0] is None
    asked = [" ".join(a) for a in ran]
    assert len(asked) == len(MACHINE.PUBLIC_DNS) and all(a.split()[-2].endswith(".") for a in asked)  # a trailing dot
    for name, rtype, server, whose in MACHINE.PUBLIC_DNS:
        card = cards.OPENDNS if whose == "OpenDNS" else cards.GOOGLE
        [question] = [a for a in asked if a.split()[-1] == server and f"-type={rtype}" in a.split()]
        assert question in {c.name for c in card.used}, (whose, server)
    assert sorted(c.name for c in (*cards.OPENDNS.used, *cards.GOOGLE.used)) == sorted(asked)  # those, and no other
    assert all(cards.NSLOOKUP in {x.url for x in card.links} for card in (cards.OPENDNS, cards.GOOGLE))


@pytest.mark.outside
@pytest.mark.skipif(os.environ.get("LIMINAL_VENDOR_PAGES") != "1", reason="reaches the makers' pages: LIMINAL_VENDOR_PAGES=1")
def test_the_cards_pages_answer():
    assert dead_links(MACHINE.apis) == []
