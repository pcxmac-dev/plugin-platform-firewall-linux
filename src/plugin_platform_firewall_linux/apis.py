"""What the Linux firewall attaches to (plugin API 2.2, liminal_libs.sources.apis; the user, 2026-11-11: "each plugin
should reflect the the API its attached to, and present links that provide documentation ... it should also expose more
of what the API is about"): nftables, iptables and ip6tables, ebtables and arptables, ipset, firewalld, ufw, conntrack,
eBPF through bpftool, iproute2's ip and ss, the init's firewall services, and sudo (how root's rights are had), each as
its makers' pages describe it. Every address was read on 2026-11-11 (`VERIFIED`). `facts` says what the last read
found of them (the tools' versions, what each holds), asking nothing. With Root access and nftables' install (0.9.0):
sudo's card again (its password on standard input, its policy and visudo), the users and groups' tools that make
the group liminal, and APT, which installs nftables; their addresses read on 2026-11-17 (`RIGHTS_VERIFIED`).

And the World Wide Web tab's (0.8.0; the user, 2026-11-14: "so for the firewall's both are going to get a 'world wide
web view' that shows the globe and the routes incoming all traffic, as well as monitoring port traffic stats"): libpcap,
which watches the packets; DB-IP's Lite City, the GeoIP file that places them, read with maxminddb; and OpenDNS's and
Google's name servers, asked for this network's public address. Their addresses were read on 2026-11-15
(`WORLD_VERIFIED`). The tab itself is the library's Firewall base's. What it downloads and asks is named here, since the
library names no outside host: GEOIP_URL (this month's GeoIP file), GEOIP_LICENCE (its licence in words, shown before
the download), ATTRIBUTION (DB-IP's credit, beside the places) and PUBLIC_DNS (the name servers). `facts` says what the
tab watched and which GeoIP file it has open (or last had open, once it was let go), asking nothing either: it reads
the tab through the base's world_view(make=False), which never makes one. The GeoIP sources (0.12.0, liminal-libs
1.101.0) are named here too (GEOIP_SOURCES): DB-IP's two files, at GEOIP_URL and GEOIP_ASN_URL, and IPinfo Lite for
networks, named and not offered, so it has no card yet; the Windows firewall plugin names the same sources in the same
words, and both plugins' tests pin their digest.

And the Netstat tab's and the globe's internet infrastructure (0.9.0; the user, 2026-11-16: "the firewall app should
have a 'netstat' like interface for looking at active ports and what apps they are attached to, and the hosts that
they connect to across the lan or wan"; "The globe should have the same kind of geography associated with the
exchanges globe, but the firewall globe should instead of exchanges, have all the backbones,ibones, major internet
infrastructure, (as many as possible) datacenter locations"): the kernel's socket tables in /proc/net, which the tab
reads as files with no command and no root; and where the globe's layers come from, each asked once, on the user's
click, after its licence is accepted: OpenStreetMap's data centres, exchange points, submarine cables, landing
stations and lines on land through the Overpass API (ODbL), Wikidata's exchange points, data centres, ground stations
and teleports through its query service (CC0), EMODnet's telecom cable routes in European waters through its WFS (CC
BY 4.0), and the Internet Topology Zoo's maps of backbone networks, one archive in its repository on GitHub (CC BY 4.0;
the user, 2026-11-19: "major network 'bones' need to be displayed on the map"). They are named here as INFRASTRUCTURE,
plain dicts the library's Firewall base reads (liminal-libs 1.65.0; the Topology Zoo's since 0.9.1, read by 1.65.1's gml
format), and their addresses were read on 2026-11-18 (`NETSTAT_VERIFIED`), the Topology Zoo's on 2026-11-19
(`GLOBE_VERIFIED`). The Windows firewall plugin names the same data sets, and both plugins' tests pin their digest.
`netstat_facts` says what the tab last read, what the hosts database holds and which data sets are installed, asking
nothing (the base's netstat_view(make=False)). PeeringDB, root-server sites and cloud regions are not among them: not
free-licensed, or no licence stated.

The globe's newer sources (0.13.0, liminal-libs 1.104.0), their pages read on 2026-11-26 (`VERIFIED_GLOBE2`): Natural
Earth, AfTerFibre, TopoHub, RIPE Atlas, CelesTrak and the sgp4 package on PyPI, each a card (GLOBE2) and their data sets
GLOBE2_SETS, at the end of INFRASTRUCTURE; the same in both firewall plugins but the sgp4 wheel each pins
(SGP4_PACKAGE).

The right to capture is CAP_NET_RAW alone, for the platform alone (the card's auth and its calls, as the library's
world.capture_help words it since 1.55.0): AmbientCapabilities=CAP_NET_RAW in the platform's system unit, or setcap
cap_net_raw=ep on a copy of Python that is the platform's own. Never on the system's Python, which every program and
every user runs, and never CAP_NET_ADMIN, which is the right to rewrite the firewall this plugin keeps."""
from __future__ import annotations

import time

from liminal_libs import geo
from liminal_libs.machines import geosources
from liminal_libs.sources.apis import Api, Area, Call, Link

from .rights import Paths

VERIFIED = "2026-11-11"
WORLD_VERIFIED = "2026-11-15"  # the World Wide Web tab's cards (0.8.0): every address on them read on this day
NFT_WIKI = "https://wiki.nftables.org/wiki-nftables/index.php/"
NFT_MAN = "https://www.netfilter.org/projects/nftables/manpage.html"
NFT_JSON = "https://manpages.debian.org/unstable/libnftables1/libnftables-json.5.en.html"
MAN7 = "https://man7.org/linux/man-pages/"
DEBIAN = "https://manpages.debian.org/unstable/"
FIREWALLD = "https://firewalld.org/documentation/"
UFW_MAN = "https://manpages.ubuntu.com/manpages/resolute/man8/ufw.8.html"
SYSTEMD = "https://www.freedesktop.org/software/systemd/man/latest/"
OPENRC = "https://github.com/OpenRC/openrc/blob/master/"
PCAP = "https://www.tcpdump.org/manpages/"
DBIP = "https://db-ip.com/"
READER = "https://github.com/maxmind/MaxMind-DB-Reader-python"
READER_DOCS = "https://maxminddb.readthedocs.io/"
NSLOOKUP = DEBIAN + "bind9-dnsutils/nslookup.1.en.html"
AMBIENT = SYSTEMD + "systemd.exec.html#AmbientCapabilities="  # a unit's ambient capabilities (systemd.exec(5))
VENV = "https://docs.python.org/3/library/venv.html"  # python3 -m venv --copies: a copy of Python of the platform's own

# -- what the World Wide Web tab downloads and asks (0.8.0): the library's Firewall base reads these off the plugin ------
# this month's GeoIP file, DB-IP's IP to City Lite in MaxMind DB form: {year} and {month} filled in by the library
# (dbip-city-lite-2026-11.mmdb.gz), last month's tried when this month's is not out yet; downloaded only on the user's word
GEOIP_URL = "https://download.db-ip.com/free/dbip-city-lite-{year}-{month}.mmdb.gz"
GEOIP_LICENCE = (  # DB-IP's own terms (db-ip.com/db/lite.php), in plain words, shown before the download and accepted
    "DB-IP's IP to City Lite database is licensed under the Creative Commons Attribution 4.0 International License "
    "(CC BY 4.0). You may use, share and adapt it for any purpose, even commercially, provided you credit DB-IP.com for "
    "the data, with a link back to db-ip.com on every page that shows or uses its results: this tab shows \"IP "
    "Geolocation by DB-IP\", linked, wherever its places are. It is DB-IP's free subset of its paid data, updated "
    "monthly, with reduced accuracy. The download is about 60 MB (about 121 MB unpacked), and one copy is kept on this "
    "machine.")
# liminal-libs 1.75.0: the ASN file beside it, DB-IP's IP to ASN Lite in MaxMind DB form ({year} and {month} filled in
# by the library), downloaded only on the user's word: each network's AS number and organisation
GEOIP_ASN_URL = "https://download.db-ip.com/free/dbip-asn-lite-{year}-{month}.mmdb.gz"
GEOIP_ASN_LICENCE = (  # DB-IP's own terms for it (db-ip.com/db/download/ip-to-asn-lite, read 2026-11-22), in plain words
    "DB-IP's IP to ASN Lite database is licensed under the Creative Commons Attribution 4.0 International License "
    "(CC BY 4.0). You may use, share and adapt it for any purpose, even commercially, provided you credit DB-IP.com for "
    "the data, with a link back to db-ip.com on every page that shows or uses its results: this tab shows \"IP "
    "Geolocation by DB-IP\", linked, wherever its networks are. It is updated monthly. The download is about 5 MB "
    "(9.2 MB unpacked, 485,292 ranges), and one copy is kept on this machine, beside the GeoIP file.")
ATTRIBUTION = {"text": "IP Geolocation by DB-IP", "url": "https://db-ip.com"}  # DB-IP's own link, as its terms give it
# 0.12.0 (liminal-libs 1.101.0, Monday list item 20; the user, 2026-11-19: "add a way to download different GEOIP
# sources"): the GeoIP sources the World Wide Web tab offers, places and networks chosen apart, the first the default
# (machines/geosources.py reads each dict; every host, licence and credit is named here, never in the library). DB-IP's
# two files are GEOIP_URL and GEOIP_ASN_URL above, in the same folders; each acceptance is kept in your own login store
# (licence-dbip-lite and licence-dbip-asn-lite) when you ask from the platform's page. IPinfo Lite, for networks, is
# named and not offered (the user, 2026-11-25: each source offered only after their yes): its row says it waits for your
# word, no button, no key asked, nothing downloaded. The Windows firewall plugin names the same dicts in the same words
# (its CITY_LITE_LICENCE and ASN_LITE_LICENCE, each with the line pointing to the full licence), and both plugins' tests
# pin their digest.
CC_BY_URL = "https://creativecommons.org/licenses/by/4.0/"
CC_BY_SA_URL = "https://creativecommons.org/licenses/by-sa/4.0/"
DBIP_CITY_WORDS = (
    "DB-IP's IP to City Lite is free under the Creative Commons Attribution 4.0 International licence (CC BY 4.0, "
    "creativecommons.org/licenses/by/4.0): it may be used, shared and changed for any purpose, as long as DB-IP is "
    "credited. So wherever its places are shown, this page says \"IP Geolocation by DB-IP\" with a link to db-ip.com. "
    "It comes as it is, with no warranty, and its places are approximate. The download is about 60 MB (about 121 MB "
    "unpacked); DB-IP puts out a new one each month. "
    + geosources.pointer(CC_BY_URL)
)
DBIP_ASN_WORDS = (
    "DB-IP's IP to ASN Lite is free under the Creative Commons Attribution 4.0 International licence (CC BY 4.0, "
    "creativecommons.org/licenses/by/4.0): it may be used, shared and changed for any purpose, as long as DB-IP is "
    "credited. So wherever its networks are shown, this page says \"IP Geolocation by DB-IP\" with a link to "
    "db-ip.com. It comes as it is, with no warranty. The download is about 5 MB (9.2 MB unpacked, 485,292 ranges); "
    "DB-IP puts out a new one each month. "
    + geosources.pointer(CC_BY_URL)
)
IPINFO_LITE = "https://ipinfo.io/data/ipinfo_lite.mmdb"  # the token goes in its query, the only way IPinfo's pages show
IPINFO_LITE_LICENCE = (
    "IPinfo Lite is free under the Creative Commons Attribution-ShareAlike 4.0 International licence (CC BY-SA 4.0), "
    "for commercial use too: it may be used, shared and changed for any purpose, as long as IPinfo is credited and what "
    "is shared of it, changed or not, is shared under the same licence. So wherever its networks are shown, this page "
    "says \"IP address data powered by IPinfo\" with a link to ipinfo.io. It comes as it is, with no warranty. It needs "
    "a free IPinfo account: its token is read from your own login store during the download and sent to ipinfo.io in "
    "the download's address alone. The file is about 24 MB, not packed; IPinfo puts out a new one every day, ten "
    "downloads a day per address, and an update is offered here a week after the file installed was built. "
    + geosources.pointer(CC_BY_SA_URL)
)
GEOIP_SOURCES = (
    {"id": "dbip", "title": "DB-IP Lite", "maker": "DB-IP", "hosts": ["download.db-ip.com"], "files": [
        {"role": "places", "title": "DB-IP IP to City Lite", "url": GEOIP_URL, "packing": "mmdb.gz",
         "size": "about 60 MB (about 121 MB unpacked)",
         "licence": {"words": DBIP_CITY_WORDS, "name": "CC BY 4.0", "pair": "dbip-lite", "version": "CC BY 4.0",
                     "url": CC_BY_URL},
         "credit": ATTRIBUTION},
        {"role": "networks", "title": "DB-IP IP to ASN Lite", "url": GEOIP_ASN_URL, "packing": "mmdb.gz",
         "size": "about 5 MB (9.2 MB unpacked)",
         "licence": {"words": DBIP_ASN_WORDS, "name": "CC BY 4.0", "pair": "dbip-asn-lite", "version": "CC BY 4.0",
                     "url": CC_BY_URL},
         "credit": ATTRIBUTION}]},
    {"id": "ipinfo", "title": "IPinfo Lite", "maker": "IPinfo", "hosts": ["ipinfo.io"],
     "keys": {"IPINFO_TOKEN": "token"}, "sends": "query", "query": "token", "offered": False, "files": [
         {"role": "networks", "title": "IPinfo Lite", "url": IPINFO_LITE, "packing": "mmdb", "shape": "ipinfo-lite",
          "stem": "ipinfo-lite", "size": "about 24 MB", "sent_on": ["dl.assets.ipinfo.io", "dl.ipinfo.io"],
          "checksum": "ipinfo-checksums", "checksum_url": IPINFO_LITE + "/checksums", "every_days": 7,
          "licence": {"words": IPINFO_LITE_LICENCE, "name": "CC BY-SA 4.0", "pair": "ipinfo-lite",
                      "version": "CC BY-SA 4.0", "url": CC_BY_SA_URL},
          "credit": {"text": "IP address data powered by IPinfo", "url": "https://ipinfo.io"}}]},
)
# the name servers asked for this network's public address, which the GeoIP file places as home when the user set no
# place of their own: each answers with the asker's own address, and the question names no other machine. (the name, its
# type, the server asked directly, whose), split by the server's IP version: an IPv6 address is asked over IPv6. The
# hw-stats plugin asks the same ones (its network.PUBLIC_SERVERS). The library asks each by its absolute name, a trailing
# dot added (world.servers_of, liminal-libs 1.55.0: myip.opendns.com.), so no search domain of this machine's goes with it.
PUBLIC_DNS = (
    ("myip.opendns.com", "a", "208.67.222.222", "OpenDNS"),  # resolver1.opendns.com: an A record of the asker's address
    ("o-o.myaddr.l.google.com", "txt", "216.239.32.10", "Google"),  # ns1.google.com: its text record holds it
    ("myip.opendns.com", "aaaa", "2620:119:35::35", "OpenDNS"),
    ("o-o.myaddr.l.google.com", "txt", "2001:4860:4802:32::a", "Google"),
)

NFTABLES = Api(
    name="nftables (nft)",
    maker="the netfilter project",
    about=("nftables is the Linux kernel's packet classification framework (nf_tables) and nft its command line: tables "
           "of chains hooked into the network stack, rules matching packets, sets and maps, the whole ruleset listed as "
           "JSON. The plugin reads the ruleset in one listing, makes and removes Liminal's rules and this machine's own, "
           "sets a base chain's policy, and saves the machine's own tables where the distribution loads them at boot."),
    kind="command",
    base="nft, as root (through sudo -n)",
    version="nftables 1.1.7 (its JSON's flags as words on 1.1.3 and older, as lists on 1.1.7: both read)",
    auth="root (CAP_NET_ADMIN), had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("The nftables wiki", NFT_WIKI + "Main_Page", "docs"),
        Link("nft(8)", NFT_MAN, "reference"),
        Link("libnftables-json(5)", NFT_JSON, "spec"),
        Link("Quick reference: nftables in 10 minutes", NFT_WIKI + "Quick_reference-nftables_in_10_minutes", "guide"),
        Link("Moving from iptables to nftables", NFT_WIKI + "Moving_from_iptables_to_nftables", "guide"),
        Link("The nftables project", "https://www.netfilter.org/projects/nftables/", "tool"),
        Link("netfilter's news", "https://www.netfilter.org/news.html", "changelog"),
        Link("nftables' source", "https://git.netfilter.org/nftables/", "source"),
    ),
    areas=(
        Area("The ruleset", "every table, chain, rule, set and map, listed whole (as JSON with -j)", NFT_WIKI + "Operations_at_ruleset_level",
             covered="read in one listing (nft -j list ruleset); each rule written again in nft's own words"),
        Area("Tables", "a family's tables (ip, ip6, inet, arp, bridge, netdev) and their flags (dormant, owner, persist)",
             NFT_WIKI + "Configuring_tables",
             covered="each table's owner found (this machine, Liminal, a program); a dormant one shown turned off; an owned one read only"),
        Area("Chains", "base chains on a hook with a priority and a policy, and regular chains", NFT_WIKI + "Configuring_chains",
             covered="the input, forward and output base chains and their policies; a policy set; a table of Liminal's own made when needed"),
        Area("Rules", "rules added, inserted at a place, deleted by their handle", NFT_WIKI + "Simple_rule_management",
             covered="Liminal's rules and this machine's made and removed (never a program's that makes its own)"),
        Area("Netfilter hooks", "where in the stack a chain sees packets", NFT_WIKI + "Netfilter_hooks",
             covered="what comes in, goes out or passes through, by the chains' hooks"),
        Area("Sets and maps", "named groups of addresses, ports and verdicts", NFT_WIKI + "Sets", covered="counted"),
        Area("Saving and restoring", "a ruleset written to a file and loaded with nft -f, checked with -c", NFT_WIKI + "Scripting",
             covered="the machine's own tables saved (nft -s list table), checked (nft -c -f) before they replace the file"),
        Area("Connection tracking in rules", "ct state, ct helpers and stateful objects", NFT_WIKI + "Matching_connection_tracking_stateful_metainformation"),
        Area("Flowtables", "a fast path for established flows", NFT_WIKI + "Flowtables", covered="counted"),
        Area("Atomic replacement", "a whole ruleset replaced at once", NFT_WIKI + "Atomic_rule_replacement"),
        Area("iptables' tables in nftables", "the xtables tools writing into nf_tables (iptables-nft)", NFT_WIKI + "Legacy_xtables_tools",
             covered="iptables-nft's tables read through iptables-save rather than as nftables JSON"),
    ),
    calls=(
        Call("nft --version", "nft's version", "The ruleset", used="the Firewall table's version", docs=NFT_MAN),
        Call("nft -j list ruleset", "the whole ruleset as JSON", "The ruleset", used="the read", docs=NFT_JSON),
        Call("nft insert rule <family> <table> <chain> [position <handle>] <rule> comment <words>",
             "a rule put at a chain's head, or before a rule", "Rules", used="Make… (a block at the head; an allow before the drop)",
             docs=NFT_WIKI + "Simple_rule_management", writes=True),
        Call("nft add rule <family> <table> <chain> <rule> comment <words>", "a rule put at a chain's end", "Rules",
             used="Make… (an allow where nothing drops after it)", docs=NFT_WIKI + "Simple_rule_management", writes=True),
        Call("nft delete rule <family> <table> <chain> handle <n>", "a rule removed by its handle", "Rules", used="Remove…",
             docs=NFT_WIKI + "Simple_rule_management", writes=True),
        Call("nft add table inet liminal", "a table of Liminal's own", "Tables",
             used="Make… a block where this machine has no chain of its own", docs=NFT_WIKI + "Configuring_tables", writes=True),
        Call("nft add chain <family> <table> <chain> { type filter hook <hook> priority 0; policy accept; }",
             "a base chain on a hook", "Chains", used="the same: Liminal's own chain", docs=NFT_WIKI + "Configuring_chains",
             writes=True),
        Call("nft add chain <family> <table> <chain> { policy <policy>; }", "a base chain's policy set", "Chains",
             used="Set… (a default policy; dropping by default asked twice when SSH would be cut)",
             docs=NFT_WIKI + "Configuring_chains", writes=True),
        Call("nft -s list table <family> <table>", "a table listed without its counters", "Saving and restoring",
             used="Save: the machine's own tables written to the file the boot loads", docs=NFT_MAN),
        Call("nft -c -f <file>", "a ruleset file checked, not applied", "Saving and restoring",
             used="Save: the new file checked before it replaces the old", docs=NFT_MAN),
        Call("nft -f <file>", "a ruleset file loaded", "Saving and restoring", docs=NFT_WIKI + "Scripting", writes=True),
        Call("nft flush ruleset", "every table removed", "The ruleset", docs=NFT_WIKI + "Operations_at_ruleset_level", writes=True),
        Call("nft monitor", "the ruleset's changes as they happen", "The ruleset", docs=NFT_MAN),
        Call("nft add set <family> <table> <set> { type <type>; }", "a named set", "Sets and maps", docs=NFT_WIKI + "Sets",
             writes=True),
    ),
    verified=VERIFIED,
)

IPTABLES = Api(
    name="iptables and ip6tables",
    maker="the netfilter project",
    about=("iptables and ip6tables, the older rule tools: tables of built-in and user chains of rules, written out whole "
           "by iptables-save. Since 1.8 each comes in two variants: nf_tables (iptables-nft, writing into nftables' "
           "tables, the default on most distributions now) and legacy (the kernel's x_tables). The plugin reads both, "
           "makes and removes rules where iptables is in charge, sets a built-in chain's policy, and saves the rules "
           "where the distribution loads them at boot."),
    kind="command",
    base="iptables, ip6tables and their -save, as root (through sudo -n)",
    version=("iptables 1.8.13; the legacy x_tables read only when the kernel has them loaded (optional since Linux 6.17: "
             "reading them otherwise would load them)"),
    auth="root (CAP_NET_ADMIN), had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("The iptables project", "https://www.netfilter.org/projects/iptables/", "docs"),
        Link("iptables(8) and ip6tables(8)", MAN7 + "man8/iptables.8.html", "reference"),
        Link("iptables-save(8)", MAN7 + "man8/iptables-save.8.html", "reference"),
        Link("iptables-extensions(8)", MAN7 + "man8/iptables-extensions.8.html", "reference"),
        Link("xtables-nft(8): the nf_tables variant", DEBIAN + "iptables/xtables-nft.8.en.html", "guide"),
        Link("xtables-legacy(8)", DEBIAN + "iptables/xtables-legacy.8.en.html", "guide"),
        Link("netfilter-persistent(8)", DEBIAN + "netfilter-persistent/netfilter-persistent.8.en.html", "tool"),
        Link("netfilter's news", "https://www.netfilter.org/news.html", "changelog"),
        Link("iptables' source", "https://git.netfilter.org/iptables/", "source"),
    ),
    areas=(
        Area("Rules in chains", "rules appended, inserted at a number, deleted by their words", MAN7 + "man8/iptables.8.html",
             covered="Liminal's rules and this machine's made and removed where iptables is in charge"),
        Area("Policies", "a built-in chain's default (ACCEPT, DROP)", MAN7 + "man8/iptables.8.html",
             covered="INPUT, FORWARD and OUTPUT's policies set (dropping by default asked twice when SSH would be cut)"),
        Area("Saving", "the whole of a variant's tables written out", MAN7 + "man8/iptables-save.8.html",
             covered="read with iptables-save; saved where the distribution loads them at boot"),
        Area("Restoring", "a saved set of tables loaded back, at once", MAN7 + "man8/iptables-restore.8.html"),
        Area("User chains", "chains of one's own, jumped to from others", MAN7 + "man8/iptables.8.html"),
        Area("The two variants", "nf_tables (iptables-nft) and legacy (x_tables)", DEBIAN + "iptables/xtables-nft.8.en.html",
             covered="the variant read from iptables -V; the legacy tables beside an nf_tables iptables, when loaded"),
        Area("Matches and targets", "the extensions a rule uses: comment, conntrack, multiport...", MAN7 + "man8/iptables-extensions.8.html",
             covered="Liminal's rules carry a comment liminal:<name>"),
        Area("Keeping rules across a restart", "the distributions' own services and files (netfilter-persistent, iptables-services...)",
             DEBIAN + "netfilter-persistent/netfilter-persistent.8.en.html",
             covered="netfilter-persistent save, rc-service iptables save, iptables-store, or the file written"),
    ),
    calls=(
        Call("iptables -V", "iptables' version and variant", "The two variants", used="the read", docs=MAN7 + "man8/iptables.8.html"),
        Call("iptables-save", "IPv4's rules, whole", "Saving", used="the read; Save to a file",
             docs=MAN7 + "man8/iptables-save.8.html"),
        Call("ip6tables-save", "IPv6's rules, whole", "Saving", used="the read; Save to a file",
             docs=MAN7 + "man8/iptables-save.8.html"),
        Call("iptables-legacy-save", "the legacy x_tables' IPv4 rules", "The two variants",
             used="the read, when the kernel has them loaded", docs=DEBIAN + "iptables/xtables-legacy.8.en.html"),
        Call("ip6tables-legacy-save", "the legacy x_tables' IPv6 rules", "The two variants",
             used="the read, when the kernel has them loaded", docs=DEBIAN + "iptables/xtables-legacy.8.en.html"),
        Call("iptables|ip6tables -t filter -I <chain> <n> <rule> -j <target>", "a rule inserted at a number", "Rules in chains",
             used="Make… (a block first; an allow before the drop)", docs=MAN7 + "man8/iptables.8.html",
             writes=True),
        Call("iptables|ip6tables -t filter -A <chain> <rule> -j <target>", "a rule appended", "Rules in chains",
             used="Make… (an allow where nothing drops after it)", docs=MAN7 + "man8/iptables.8.html", writes=True),
        Call("iptables|ip6tables -t <table> -D <chain> <rule>", "a rule deleted by its words", "Rules in chains", used="Remove…",
             docs=MAN7 + "man8/iptables.8.html", writes=True),
        Call("iptables|ip6tables -t filter -P <chain> <policy>", "a built-in chain's policy", "Policies", used="Set…",
             docs=MAN7 + "man8/iptables.8.html", writes=True),
        Call("netfilter-persistent save", "the rules saved where Debian's boot loads them", "Keeping rules across a restart",
             used="Save on Debian and Ubuntu (it says nothing when it fails)",
             docs=DEBIAN + "netfilter-persistent/netfilter-persistent.8.en.html", writes=True),
        Call("iptables-restore", "a saved table loaded back", "Restoring", docs=MAN7 + "man8/iptables-restore.8.html",
             writes=True),
        Call("iptables -N <chain>", "a user chain made", "User chains", docs=MAN7 + "man8/iptables.8.html", writes=True),
    ),
    verified=VERIFIED,
)

EBTABLES = Api(
    name="ebtables and arptables",
    maker="the netfilter project",
    about=("ebtables filters Ethernet frames crossing a Linux bridge and arptables filters ARP, each in an nf_tables "
           "variant (beside iptables-nft) and a legacy one. The plugin reads only which variant and version each is, for "
           "the Firewall table; it neither lists nor changes their rules."),
    kind="command",
    base="ebtables -V and arptables -V, as root (through sudo -n)",
    version="the nf_tables variants (ebtables-nft, arptables-nft) and the legacy tools alike",
    auth="root, had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("ebtables", "https://ebtables.netfilter.org/", "docs"),
        Link("ebtables-nft(8)", MAN7 + "man8/ebtables-nft.8.html", "reference"),
        Link("arptables-nft(8)", MAN7 + "man8/arptables-nft.8.html", "reference"),
        Link("ebtables-legacy(8)", DEBIAN + "ebtables/ebtables-legacy.8.en.html", "reference"),
        Link("arptables-legacy(8)", DEBIAN + "arptables/arptables-legacy.8.en.html", "reference"),
    ),
    areas=(
        Area("Their variants and versions", "nf_tables or legacy, and each tool's version", MAN7 + "man8/ebtables-nft.8.html",
             covered="read for the Firewall table"),
        Area("Bridge filtering", "frames crossing a bridge filtered by MAC, protocol, VLAN", MAN7 + "man8/ebtables-nft.8.html"),
        Area("The broute table", "frames routed instead of bridged", DEBIAN + "ebtables/ebtables-legacy.8.en.html"),
        Area("ARP filtering", "ARP packets filtered, mangled", MAN7 + "man8/arptables-nft.8.html"),
    ),
    calls=(
        Call("ebtables -V", "ebtables' version and variant", "Their variants and versions", used="the read",
             docs=MAN7 + "man8/ebtables-nft.8.html"),
        Call("arptables -V", "arptables' version and variant", "Their variants and versions", used="the read",
             docs=MAN7 + "man8/arptables-nft.8.html"),
        Call("ebtables -L", "the bridge's rules", "Bridge filtering", docs=MAN7 + "man8/ebtables-nft.8.html"),
        Call("arptables -L", "the ARP rules", "ARP filtering", docs=MAN7 + "man8/arptables-nft.8.html"),
    ),
    verified=VERIFIED,
)

IPSET = Api(
    name="ipset",
    maker="the netfilter project",
    about=("ipset keeps sets of addresses, networks, ports and their pairs in the kernel, which iptables rules match "
           "against in one step. The plugin lists the sets (their names, types and sizes, never their members) for the "
           "Sets table, and only when the kernel has ip_set loaded: listing them otherwise would load it."),
    kind="command",
    base="ipset, as root (through sudo -n)",
    version="ipset as current distributions ship it (list -t: the headers alone)",
    auth="root, had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("ipset", "https://ipset.netfilter.org/", "docs"),
        Link("ipset(8)", "https://ipset.netfilter.org/ipset.man.html", "reference"),
        Link("The ipset project", "https://www.netfilter.org/projects/ipset/", "tool"),
    ),
    areas=(
        Area("Listing sets", "each set's header and, without -t, its members", "https://ipset.netfilter.org/ipset.man.html",
             covered="every set's name, type and size, members left out (-t)"),
        Area("Making and removing sets", "sets created, destroyed, renamed, swapped", "https://ipset.netfilter.org/ipset.man.html"),
        Area("Members", "entries added, deleted, tested", "https://ipset.netfilter.org/ipset.man.html"),
        Area("Saving and restoring", "every set written out and read back", "https://ipset.netfilter.org/ipset.man.html"),
    ),
    calls=(
        Call("ipset -v", "ipset's version", "Listing sets", used="the read", docs="https://ipset.netfilter.org/ipset.man.html"),
        Call("ipset list -t", "every set's header, no members", "Listing sets", used="the read, when ip_set is loaded",
             docs="https://ipset.netfilter.org/ipset.man.html"),
        Call("ipset create <set> <type>", "a set made", "Making and removing sets", docs="https://ipset.netfilter.org/ipset.man.html",
             writes=True),
        Call("ipset add <set> <entry>", "an entry added", "Members", docs="https://ipset.netfilter.org/ipset.man.html", writes=True),
        Call("ipset save", "every set written out", "Saving and restoring", docs="https://ipset.netfilter.org/ipset.man.html"),
    ),
    verified=VERIFIED,
)

FIREWALLD_API = Api(
    name="firewalld",
    maker="the firewalld project",
    about=("firewalld, the default firewall manager of RHEL, Fedora, SUSE and openSUSE: interfaces and sources bound to "
           "zones, each zone "
           "letting in services, ports and rich rules, policies between zones, and a runtime beside the permanent "
           "configuration, with nftables (or iptables) beneath it. The plugin reads every zone and policy, makes Liminal's "
           "rules as firewalld services, removes rules, sets a zone's target, and turns firewalld on or off."),
    kind="command",
    base="firewall-cmd while the daemon runs, firewall-offline-cmd while it is stopped; as root (through sudo -n)",
    version="firewalld 2 (from 2.4.3 firewall-cmd waits for D-Bus when the daemon is stopped: the offline tool is used then)",
    auth="root, had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("firewalld's documentation", FIREWALLD, "docs"),
        Link("firewall-cmd(1)", FIREWALLD + "man-pages/firewall-cmd.html", "reference"),
        Link("firewall-offline-cmd(1)", FIREWALLD + "man-pages/firewall-offline-cmd.html", "reference"),
        Link("firewalld.zones(5)", FIREWALLD + "man-pages/firewalld.zones.html", "reference"),
        Link("firewalld.policies(5)", FIREWALLD + "man-pages/firewalld.policies.html", "reference"),
        Link("firewalld.richlanguage(5)", FIREWALLD + "man-pages/firewalld.richlanguage.html", "reference"),
        Link("Concepts", FIREWALLD + "concepts.html", "guide"),
        Link("firewalld's releases", "https://github.com/firewalld/firewalld/releases", "changelog"),
        Link("firewalld's source", "https://github.com/firewalld/firewalld", "source"),
    ),
    areas=(
        Area("Its state", "whether the daemon runs, its version, its backend", FIREWALLD + "man-pages/firewall-cmd.html",
             covered="asked of the service first (a stopped daemon is read offline)"),
        Area("Zones", "interfaces and sources bound to zones, each with its target, services, ports and rich rules",
             FIREWALLD + "man-pages/firewalld.zones.html",
             covered="every zone read; the default zone takes the interfaces bound to none; a zone's target set"),
        Area("Policies", "rules for traffic between zones, out and forwarded", FIREWALLD + "man-pages/firewalld.policies.html",
             covered="every policy read; one not in force shown turned off"),
        Area("Services", "named sets of ports and protocols", FIREWALLD + "service/",
             covered="the zones' services' ports read; Liminal's rules made as services liminal-<name>"),
        Area("Rich rules", "rules by source, port, service, with log and limits", FIREWALLD + "man-pages/firewalld.richlanguage.html",
             covered="a rule from one address or network, or a block, made as a rich rule"),
        Area("Runtime and permanent", "the running configuration and the one kept across a reload", FIREWALLD + "concepts.html",
             covered="each change made permanent, then reloaded (offline: the permanent one alone)"),
        Area("Its configuration", "firewalld.conf: the default zone, the backend", FIREWALLD + "man-pages/firewalld.conf.html",
             covered="FirewallBackend and DefaultZone read"),
        Area("Direct rules and lockdown", "passthrough rules and who may change the firewall", FIREWALLD + "man-pages/firewall-cmd.html"),
    ),
    calls=(
        Call("firewall-cmd --state", "whether the daemon runs", "Its state", used="the read",
             docs=FIREWALLD + "man-pages/firewall-cmd.html"),
        Call("firewall-cmd --version", "its version", "Its state", used="the read (firewall-offline-cmd when stopped)",
             docs=FIREWALLD + "man-pages/firewall-cmd.html"),
        Call("firewall-cmd --get-default-zone", "the default zone", "Zones", used="the read",
             docs=FIREWALLD + "man-pages/firewall-cmd.html"),
        Call("firewall-cmd --list-all-zones", "every zone and all it holds", "Zones", used="the read",
             docs=FIREWALLD + "man-pages/firewall-cmd.html"),
        Call("firewall-cmd --list-all-policies", "every policy and all it holds", "Policies", used="the read",
             docs=FIREWALLD + "man-pages/firewall-cmd.html"),
        Call("firewall-cmd --info-service=<service>", "a service's ports and protocols", "Services",
             used="the read: the ports of each service the zones use", docs=FIREWALLD + "man-pages/firewall-cmd.html"),
        Call("firewall-cmd --permanent --new-service=<service>", "a service made", "Services", used="Make… (liminal-<name>)",
             docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-cmd --permanent --service=<service> --set-description=<words>", "what a service is for", "Services",
             used="Make… (the rule in words)", docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-cmd --permanent --service=<service> --add-port=<port>/<protocol>", "a port added to a service", "Services",
             used="Make…", docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-cmd --permanent --zone=<zone> --add-service=<service>", "a service let into a zone", "Zones",
             used="Make… (an allow from everywhere)", docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-cmd --permanent --zone=<zone> --add-rich-rule=<rule>", "a rich rule added to a zone", "Rich rules",
             used="Make… (from an address, or a block)", docs=FIREWALLD + "man-pages/firewalld.richlanguage.html", writes=True),
        Call("firewall-cmd [--permanent] --zone=<zone> --remove-<what>=<value>", "a service, port, source or rich rule taken out",
             "Zones",
             used="Remove… (in the runtime and the permanent configuration)", docs=FIREWALLD + "man-pages/firewall-cmd.html",
             writes=True),
        Call("firewall-cmd --permanent --delete-service=<service>", "a service deleted", "Services",
             used="Remove… of Liminal's", docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-cmd --permanent --zone=<zone> --set-target=<target>", "a zone's target set", "Zones", used="Set…",
             docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-cmd --reload", "the permanent configuration made the running one", "Runtime and permanent",
             used="after each change while it runs", docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-offline-cmd <options>", "the same, on the permanent configuration, while the daemon is stopped",
             "Runtime and permanent", used="the read and every change while it is stopped",
             docs=FIREWALLD + "man-pages/firewall-offline-cmd.html", writes=True),
        Call("firewall-cmd --zone=<zone> --change-interface=<interface>", "an interface bound to a zone", "Zones",
             docs=FIREWALLD + "man-pages/firewall-cmd.html", writes=True),
        Call("firewall-cmd --panic-on", "every packet dropped", "Its state", docs=FIREWALLD + "man-pages/firewall-cmd.html",
             writes=True),
    ),
    verified=VERIFIED,
)

UFW = Api(
    name="ufw",
    maker="Canonical (the Uncomplicated Firewall)",
    about=("ufw, Ubuntu's front end to iptables (and, through iptables-nft, nftables): rules in plain words (allow, "
           "deny, reject, limit a port or a service from somewhere), defaults for what comes in, goes out and is routed, "
           "and application profiles. The plugin reads its state and every rule (also while it is off), makes Liminal's "
           "rules with a comment, removes rules, sets its defaults and turns it on (SSH kept open first) or off."),
    kind="command",
    base="ufw, as root (through sudo -n)",
    version="ufw 0.36.2, Ubuntu's",
    auth="root, had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("ufw(8)", UFW_MAN, "reference"),
        Link("Firewalls (Ubuntu Server)", "https://ubuntu.com/server/docs/how-to/security/firewalls/", "docs"),
        Link("UFW (Ubuntu's wiki)", "https://wiki.ubuntu.com/UncomplicatedFirewall", "guide"),
        Link("ufw-framework(8)", "https://manpages.ubuntu.com/manpages/resolute/man8/ufw-framework.8.html", "reference"),
        Link("ufw on Launchpad", "https://launchpad.net/ufw", "source"),
    ),
    areas=(
        Area("Its state", "on or off, its logging, its defaults", UFW_MAN, covered="read with every rule"),
        Area("Rules", "allow, deny, reject or limit, in or out, on an interface, from and to, a port or an app", UFW_MAN,
             covered="every rule read, numbered (also while off); Liminal's made with a comment liminal:<name>"),
        Area("Routed rules", "rules for traffic passing through (ufw route)", UFW_MAN, covered="made for forwarded traffic"),
        Area("Deleting", "a rule removed by its number or its words", UFW_MAN, covered="Remove…"),
        Area("Defaults", "what comes in, goes out or is routed when no rule says", UFW_MAN, covered="Set…"),
        Area("On and off", "ufw enabled (at boot too) or disabled", UFW_MAN, covered="turned on (SSH kept open first) or off"),
        Area("Application profiles", "named ports apps declare (ufw app list)", UFW_MAN),
        Area("Logging", "what it logs, and how much", UFW_MAN),
        Area("Its framework", "its own rule files and chains beneath it", "https://manpages.ubuntu.com/manpages/resolute/man8/ufw-framework.8.html",
             covered="its chains in iptables are its machinery: read through ufw, not twice"),
    ),
    calls=(
        Call("ufw version", "its version", "Its state", used="the read", docs=UFW_MAN),
        Call("ufw status verbose", "on or off, logging, defaults, rules", "Its state", used="the read", docs=UFW_MAN),
        Call("ufw status numbered", "the rules, numbered", "Rules", used="the read", docs=UFW_MAN),
        Call("ufw show added", "the rules added, also while it is off", "Rules", used="the read", docs=UFW_MAN),
        Call("ufw allow|deny|reject [route] [in|out] [on <interface>] [proto <p>] from <source> to any [port <ports>] comment <words>",
             "a rule made", "Rules", used="Make…; SSH kept open before ufw is turned on", docs=UFW_MAN, writes=True),
        Call("ufw --force delete <number>", "a rule removed by its number", "Deleting", used="Remove…", docs=UFW_MAN, writes=True),
        Call("ufw --force delete <rule>", "a rule removed by its words (while off)", "Deleting", used="Remove…", docs=UFW_MAN,
             writes=True),
        Call("ufw default <policy> <direction>", "a default set", "Defaults", used="Set…", docs=UFW_MAN, writes=True),
        Call("ufw --force enable", "ufw turned on, and at boot", "On and off", used="Turn on…", docs=UFW_MAN, writes=True),
        Call("ufw disable", "ufw turned off", "On and off", used="Turn off… (asked twice)", docs=UFW_MAN, writes=True),
        Call("ufw limit <port>", "a port let in, too many connections from one address refused", "Rules", docs=UFW_MAN,
             writes=True),
        Call("ufw app list", "the application profiles", "Application profiles", docs=UFW_MAN),
        Call("ufw logging <level>", "how much it logs", "Logging", docs=UFW_MAN, writes=True),
    ),
    verified=VERIFIED,
)

CONNTRACK = Api(
    name="Connection tracking (conntrack)",
    maker="the Linux kernel (netfilter), and the conntrack-tools project",
    about=("The kernel tracks every connection the firewall sees, so a rule can let in the answers to what went out; "
           "its table has a limit, and when it is full new connections are dropped. The plugin reads how many are tracked "
           "and the limit from /proc/sys/net/netfilter, never through netlink (which would load a module); "
           "conntrack-tools' conntrack command lists, watches and deletes the entries."),
    kind="kernel",
    base="/proc/sys/net/netfilter/nf_conntrack_count and nf_conntrack_max",
    version="the nf_conntrack sysctls of current kernels",
    auth="read as root, with the rest of the read; nothing is changed",
    limits="",
    costs="",
    links=(
        Link("Netfilter conntrack sysfs variables", "https://docs.kernel.org/networking/nf_conntrack-sysctl.html", "reference"),
        Link("conntrack-tools", "https://conntrack-tools.netfilter.org/", "docs"),
        Link("The conntrack-tools user manual", "https://conntrack-tools.netfilter.org/manual.html", "guide"),
        Link("conntrack(8)", DEBIAN + "conntrack/conntrack.8.en.html", "reference"),
    ),
    areas=(
        Area("The table's size", "the connections tracked now and the most there may be",
             "https://docs.kernel.org/networking/nf_conntrack-sysctl.html", covered="both read, for the Firewall table"),
        Area("Its settings", "timeouts, helpers, accounting, the hash table", "https://docs.kernel.org/networking/nf_conntrack-sysctl.html"),
        Area("The entries", "each tracked connection listed, watched as it changes, deleted", DEBIAN + "conntrack/conntrack.8.en.html"),
        Area("Keeping state between machines", "conntrackd: the table copied to a standby firewall",
             "https://conntrack-tools.netfilter.org/manual.html"),
    ),
    calls=(
        Call("/proc/sys/net/netfilter/nf_conntrack_count", "the connections tracked now", "The table's size", used="the read",
             docs="https://docs.kernel.org/networking/nf_conntrack-sysctl.html"),
        Call("/proc/sys/net/netfilter/nf_conntrack_max", "the most that may be tracked", "The table's size", used="the read",
             docs="https://docs.kernel.org/networking/nf_conntrack-sysctl.html"),
        Call("conntrack -L", "every tracked connection", "The entries", docs=DEBIAN + "conntrack/conntrack.8.en.html"),
        Call("conntrack -E", "the table's changes as they happen", "The entries", docs=DEBIAN + "conntrack/conntrack.8.en.html"),
        Call("conntrack -D", "tracked connections deleted", "The entries", docs=DEBIAN + "conntrack/conntrack.8.en.html",
             writes=True),
    ),
    verified=VERIFIED,
)

BPF = Api(
    name="eBPF on the network (bpftool)",
    maker="the Linux kernel's BPF maintainers (bpftool)",
    about=("eBPF programs can filter packets without being in any firewall's ruleset: XDP at the network driver, tc at "
           "the traffic control layer, the flow dissector, and netfilter's own BPF links since Linux 6.4. bpftool shows "
           "and manages them. The plugin lists those on the network's hooks (from bpftool and ip), read only, so a "
           "filter outside nftables is never missed."),
    kind="command",
    base="bpftool -j net show, as root (through sudo -n)",
    version="bpftool 7 (7.8.1 the newest), its JSON's flow dissector mended where it is not JSON",
    auth="root (CAP_BPF and CAP_NET_ADMIN), had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("BPF documentation", "https://docs.kernel.org/bpf/", "docs"),
        Link("bpftool-net(8)", DEBIAN + "bpftool/bpftool-net.8.en.html", "reference"),
        Link("bpftool(8)", DEBIAN + "bpftool/bpftool.8.en.html", "reference"),
        Link("bpftool's releases", "https://github.com/libbpf/bpftool/releases", "changelog"),
        Link("bpftool's source", "https://github.com/libbpf/bpftool", "source"),
        Link("AF_XDP", "https://docs.kernel.org/networking/af_xdp.html", "guide"),
    ),
    areas=(
        Area("Programs on the network's hooks", "XDP, tc (cls_bpf, tcx, netkit), the flow dissector, netfilter links",
             DEBIAN + "bpftool/bpftool-net.8.en.html", covered="listed, read only, beside the interfaces"),
        Area("Programs and maps", "every BPF program and map loaded", DEBIAN + "bpftool/bpftool.8.en.html"),
        Area("Attaching and detaching", "a program attached to an interface's hook, or detached", DEBIAN + "bpftool/bpftool-net.8.en.html"),
        Area("XDP sockets", "packets handed to user space at the driver", "https://docs.kernel.org/networking/af_xdp.html"),
    ),
    calls=(
        Call("bpftool -j net show", "the programs on the network's hooks, as JSON", "Programs on the network's hooks",
             used="the read", docs=DEBIAN + "bpftool/bpftool-net.8.en.html"),
        Call("bpftool prog show", "every program loaded", "Programs and maps", docs=DEBIAN + "bpftool/bpftool.8.en.html"),
        Call("bpftool map show", "every map", "Programs and maps", docs=DEBIAN + "bpftool/bpftool.8.en.html"),
        Call("bpftool net detach <type> dev <interface>", "a program detached", "Attaching and detaching",
             docs=DEBIAN + "bpftool/bpftool-net.8.en.html", writes=True),
    ),
    verified=VERIFIED,
)

IPROUTE2 = Api(
    name="iproute2 (ip and ss)",
    maker="the Linux kernel's networking maintainers (iproute2)",
    about=("iproute2's ip shows and changes the network's interfaces, addresses and routes, and ss the sockets: what "
           "listens on which port, and the connections. The plugin reads the interfaces and their addresses (with any "
           "XDP program on them) and what listens, so it knows a rule's interface, which program a port is for, and "
           "whether a change would cut off SSH (net-tools' netstat where ss is not there)."),
    kind="command",
    base="ip -j addr show and ss, as root (through sudo -n)",
    version="iproute2's ip and ss (BusyBox's ip without JSON on Alpine, read in words)",
    auth="root, so ss can name every socket's program",
    limits="",
    costs="",
    links=(
        Link("ip(8)", MAN7 + "man8/ip.8.html", "docs"),
        Link("ip-address(8)", MAN7 + "man8/ip-address.8.html", "reference"),
        Link("ss(8)", MAN7 + "man8/ss.8.html", "reference"),
        Link("netstat(8)", MAN7 + "man8/netstat.8.html", "reference"),
        Link("iproute2's source", "https://git.kernel.org/pub/scm/network/iproute2/iproute2.git", "source"),
    ),
    areas=(
        Area("Interfaces and addresses", "each interface, its state, its addresses, its bridge or bond, its XDP program",
             MAN7 + "man8/ip-address.8.html", covered="read for the Interfaces table and firewalld's zones"),
        Area("Sockets", "what listens on which port, and the connections", MAN7 + "man8/ss.8.html",
             covered=("the TCP and UDP listeners (a rule's program; 0.9.0: the Netstat tab's listeners another user "
                      "holds), SSH's port and sessions (what a change must not cut)")),
        Area("Routes", "the routing tables and rules", MAN7 + "man8/ip.8.html"),
        Area("Links", "interfaces made, changed, brought up and down", MAN7 + "man8/ip.8.html"),
    ),
    calls=(
        Call("ip -j addr show", "every interface and its addresses, as JSON", "Interfaces and addresses", used="the read",
             docs=MAN7 + "man8/ip-address.8.html"),
        Call("ip addr show", "the same, in words", "Interfaces and addresses", used="the read, where ip has no JSON (BusyBox)",
             docs=MAN7 + "man8/ip-address.8.html"),
        Call("ss -ltnpH", "the TCP listeners and their programs", "Sockets",
             used="the read: a rule's program, and the Netstat tab's listeners another user holds (0.9.0)",
             docs=MAN7 + "man8/ss.8.html"),
        Call("ss -lunpH", "the UDP listeners and their programs", "Sockets",
             used="the read: a rule's program, and the Netstat tab's listeners another user holds (0.9.0)",
             docs=MAN7 + "man8/ss.8.html"),
        Call("ss -tnH state established", "the established TCP connections", "Sockets", used="the read: SSH's sessions",
             docs=MAN7 + "man8/ss.8.html"),
        Call("netstat -ltnp", "the TCP listeners (net-tools)", "Sockets", used="the read, where ss is not there",
             docs=MAN7 + "man8/netstat.8.html"),
        Call("netstat -lunp", "the UDP listeners (net-tools)", "Sockets", used="the read, where ss is not there",
             docs=MAN7 + "man8/netstat.8.html"),
        Call("ip route show", "the routes", "Routes", docs=MAN7 + "man8/ip.8.html"),
        Call("ip link set <interface> up|down", "an interface brought up or down", "Links", docs=MAN7 + "man8/ip.8.html", writes=True),
    ),
    verified=VERIFIED,
)

SERVICES = Api(
    name="The firewall's services (systemd, OpenRC, SysV)",
    maker="the systemd and OpenRC projects, and the distributions' SysV scripts",
    about=("The init system starts the firewall at boot: the nftables service loading its file, iptables' and ip6tables' "
           "(or Debian's netfilter-persistent), ipset's, firewalld, ufw, and Gentoo's nftables-store and -restore. The "
           "plugin reads which of them are there, running and on at boot, under systemd, OpenRC or SysV scripts, turns "
           "one on or off (and at boot), and runs the distribution's own save where it has one."),
    kind="command",
    base="systemctl, rc-service and rc-update, or service, as root (through sudo -n)",
    version="systemd, OpenRC or SysV scripts, as the machine runs",
    auth="root, had through sudo without a password",
    limits="",
    costs="",
    links=(
        Link("systemctl(1)", SYSTEMD + "systemctl.html", "reference"),
        Link("rc-service(8)", OPENRC + "man/rc-service.8", "reference"),
        Link("rc-update(8)", OPENRC + "man/rc-update.8", "reference"),
        Link("service(8)", "https://manpages.ubuntu.com/manpages/resolute/man8/service.8.html", "reference"),
        Link("systemd's manual pages", SYSTEMD, "docs"),
        Link("OpenRC's user guide", OPENRC + "user-guide.md", "guide"),
        Link("nftables on Gentoo", "https://wiki.gentoo.org/wiki/Nftables", "guide"),
    ),
    areas=(
        Area("Which services are there", "each firewall service known to the init, running or not, on at boot or not",
             SYSTEMD + "systemctl.html", covered="read for the Firewall table, under systemd, OpenRC or SysV scripts"),
        Area("On and off", "a service started and enabled at boot, or stopped and disabled", SYSTEMD + "systemctl.html",
             covered="Turn on… and Turn off… (a stop that flushes others' rules asked twice)"),
        Area("The distribution's own save", "a service's save action (Gentoo's, Alpine's) or its store unit",
             "https://wiki.gentoo.org/wiki/Nftables", covered="Save, where the distribution has one"),
        Area("Runlevels", "OpenRC's boot and default runlevels", OPENRC + "man/rc-update.8",
             covered="whether a service starts at boot (/etc/runlevels)"),
        Area("Masking", "a unit nothing can start, not even by hand", SYSTEMD + "systemctl.html"),
        Area("SysV scripts at boot", "a script's links in the runlevels (update-rc.d)",
             DEBIAN + "init-system-helpers/update-rc.d.8.en.html"),
    ),
    calls=(
        Call("systemctl cat <service>.service", "whether systemd knows the service", "Which services are there", used="the read",
             docs=SYSTEMD + "systemctl.html"),
        Call("systemctl is-active <service>.service", "whether it runs", "Which services are there", used="the read",
             docs=SYSTEMD + "systemctl.html"),
        Call("systemctl is-enabled <service>.service", "whether it starts at boot", "Which services are there", used="the read",
             docs=SYSTEMD + "systemctl.html"),
        Call("systemctl enable --now <service>", "a service started and on at boot", "On and off", used="Turn on…",
             docs=SYSTEMD + "systemctl.html", writes=True),
        Call("systemctl disable --now <service>", "a service stopped and off at boot", "On and off", used="Turn off…",
             docs=SYSTEMD + "systemctl.html", writes=True),
        Call("systemctl start <service>-store.service", "Gentoo's store unit run: the rules saved", "The distribution's own save",
             used="Save on Gentoo with systemd", docs=SYSTEMD + "systemctl.html", writes=True),
        Call("rc-service <service> status", "whether an OpenRC service runs", "Which services are there", used="the read",
             docs=OPENRC + "man/rc-service.8"),
        Call("rc-service <service> start", "an OpenRC service started", "On and off", used="Turn on…",
             docs=OPENRC + "man/rc-service.8", writes=True),
        Call("rc-service <service> stop", "an OpenRC service stopped", "On and off", used="Turn off…",
             docs=OPENRC + "man/rc-service.8", writes=True),
        Call("rc-service <service> save", "the rules saved by the service", "The distribution's own save",
             used="Save on Gentoo and Alpine with OpenRC", docs=OPENRC + "man/rc-service.8", writes=True),
        Call("rc-update add <service> default", "a service on at boot", "Runlevels", used="Turn on…",
             docs=OPENRC + "man/rc-update.8", writes=True),
        Call("rc-update del <service> default", "a service off at boot", "Runlevels", used="Turn off…",
             docs=OPENRC + "man/rc-update.8", writes=True),
        Call("service <service> start|stop", "a SysV service started or stopped", "On and off",
             used="Turn on… and Turn off…, without systemd or OpenRC",
             docs="https://manpages.ubuntu.com/manpages/resolute/man8/service.8.html", writes=True),
        Call("systemctl mask <service>", "a service nothing can start", "Masking", docs=SYSTEMD + "systemctl.html",
             writes=True),
        Call("update-rc.d <service> defaults", "a SysV script started at boot", "SysV scripts at boot",
             docs=DEBIAN + "init-system-helpers/update-rc.d.8.en.html", writes=True),
    ),
    verified=VERIFIED,
)

RIGHTS_VERIFIED = "2026-11-17"  # Root access's and nftables' install's cards (0.9.0): every address on them read then
SUDO_MAN = "https://www.sudo.ws/docs/man/sudo.man/"
SUDOERS_MAN = "https://www.sudo.ws/docs/man/sudoers.man/"
VISUDO_MAN = "https://www.sudo.ws/docs/man/visudo.man/"
ROOT_READ, ROOT_TAKE_BACK = Paths.here().read, Paths.here().helper  # Root access's installed read and take-back
APT_GET, APT_CACHE = DEBIAN + "apt/apt-get.8.en.html", DEBIAN + "apt/apt-cache.8.en.html"
DEBCONF = DEBIAN + "debconf-doc/debconf.7.en.html"
GROUPADD, USERMOD = DEBIAN + "passwd/groupadd.8.en.html", DEBIAN + "passwd/usermod.8.en.html"
GROUPDEL = DEBIAN + "passwd/groupdel.8.en.html"
BUSYBOX = "https://busybox.net/downloads/BusyBox.html"

SUDO = Api(
    name="sudo",
    maker="the sudo project",
    about=("sudo runs a command as root, as the sudoers policy allows. The firewall is read and changed as root. Where "
           "the platform is not root, the plugin runs its read through sudo -n, which never asks for a password: a "
           "rule of the user's own may allow it, or Root access's (0.9.0), the plugin's read installed root-owned and "
           "a rule letting the group liminal run exactly it, and its take-back helper, with no arguments and no "
           "password, checked with visudo before it is put in place (the library's grant). Where sudo needs a "
           "password for a change, its form on the page asks for it, and it is handed to sudo -S on its standard "
           "input for that one command: never kept, logged, shown, nor put in an argument or the environment; -k so "
           "no credential cached before stands in for it, -p '' so sudo prints no prompt of its own."),
    kind="command",
    base="sudo -n <command>; sudo -S -k -p '' -- <command>, the password on its standard input",
    version="sudo 1.9 (its -n, -S, -k, -p and -l; visudo -c and -f)",
    auth=("the platform's user, as /etc/sudoers allows: without a password where a rule allows it (Root access's for "
          "the read alone), else the password typed on the change's form, for that one command"),
    limits="",
    costs="",
    links=(
        Link("sudo(8)", SUDO_MAN, "reference"),
        Link("sudoers(5)", SUDOERS_MAN, "reference"),
        Link("visudo(8)", VISUDO_MAN, "reference"),
        Link("sudo", "https://www.sudo.ws/", "docs"),
        Link("sudo's changes", "https://www.sudo.ws/releases/changelog/", "changelog"),
    ),
    areas=(
        Area("Running as root", "a command run as root, refused at once where a password would be asked", SUDO_MAN,
             covered="the read (by a rule of yours, or Root access's installed read) and each change sudo allows "
                     "without a password, through sudo -n"),
        Area("Running as root with a password", "the password read from standard input (-S), no prompt (-p ''), "
             "credentials cached before ignored (-k)", SUDO_MAN,
             covered="each change where sudo needs a password, Root access turned on, nftables installed"),
        Area("The policy", "who may run what as whom", SUDOERS_MAN,
             covered="Root access's rule: the group liminal may run exactly the plugin's read and its take-back "
                     "helper, as root, with no arguments and no password"),
        Area("Checking a policy", "a sudoers file checked before it is used (visudo -c -f)", VISUDO_MAN,
             covered="Root access's rule, checked before it is put in place"),
        Area("Asking what is allowed", "the commands the user may run (sudo -l), running nothing", SUDO_MAN,
             covered="whether Root access's files run without a password, and, where a rule of yours runs the read, "
                     "whether a change does"),
        Area("Cached credentials", "a password given once, kept for a while (the timestamp)", SUDOERS_MAN),
    ),
    calls=(
        Call("sudo -n sh -c <script>", "a shell script as root, never asking a password", "Running as root",
             used="the read (one script), where a rule of yours allows it; a saved file written whole", docs=SUDO_MAN),
        Call("sudo -n <command>", "a command as root, never asking a password", "Running as root",
             used="each change sudo allows without a password", docs=SUDO_MAN, writes=True),
        Call(ROOT_READ, "the plugin's read, installed root-owned by Root access, run as root through sudo -n",
             "Running as root", used="the read, where Root access is on, once it is checked to be the plugin's own",
             docs=SUDO_MAN),
        Call(ROOT_TAKE_BACK, "Root access's take-back helper, run as root through sudo -n: its rule and files removed",
             "Running as root", used="Turn off…", docs=SUDO_MAN, writes=True),
        Call("sudo -S -k -p '' -- <command>", "a command as root, the password read from standard input",
             "Running as root with a password",
             used="each change where sudo needs a password; Root access turned on; nftables installed",
             docs=SUDO_MAN, writes=True),
        Call("sh -c <script>", "a script as root, given as an argument (the password alone on sudo's standard input)",
             "Running as root with a password",
             used="Root access's grant (the library's), and its removal where the take-back helper cannot run yet",
             docs=SUDO_MAN, writes=True),
        Call("visudo -cf <file>", "a sudoers file checked, nothing changed", "Checking a policy",
             used="Root access's rule, before it is put in place (inside the grant's script)", docs=VISUDO_MAN),
        Call("sudo -n -l", "what the user may run here, listed without a password once a rule without one applies "
             "(sudoers' listpw), running nothing", "Asking what is allowed",
             used="whether Root access's files run without a password (the library's granted), and a change's "
                  "(its needs_password, where a rule of yours runs the read): the rule that decides each, read from "
                  "the listing", docs=SUDO_MAN),
        Call("sudo -n -l -- <command>", "whether the user may run a command at all, a password asked or not, running "
             "nothing", "Asking what is allowed", docs=SUDO_MAN),
        Call("sudo -v", "the cached credentials renewed", "Cached credentials", docs=SUDO_MAN),
    ),
    verified=RIGHTS_VERIFIED,
)

GROUPS = Api(
    name="Users and groups (groupadd, usermod, addgroup)",
    maker="the shadow project (groupadd, usermod), BusyBox (addgroup)",
    about=("The group liminal holds Liminal's rights on a Linux machine (DECISIONS addendum 10): Root access's rule "
           "names it, never a person. Turning Root access on makes it where there is none, as a system group, and puts "
           "the platform's user in it, as root with the password typed on the form; a membership counts for programs "
           "started after it, so it takes effect once the platform is started again. What the system's database says "
           "of the group is read without a command. The group and its members stay when Root access is turned off: "
           "the Linux administration plugin manages them."),
    kind="command",
    base="groupadd and usermod (shadow), or BusyBox's addgroup",
    version="shadow 4 (Debian, Ubuntu, Fedora, Arch, Gentoo); BusyBox (Alpine)",
    auth="root (sudo with the password typed on the form)",
    limits="",
    costs="",
    links=(
        Link("groupadd(8)", GROUPADD, "reference"),
        Link("usermod(8)", USERMOD, "reference"),
        Link("BusyBox's commands", BUSYBOX, "reference"),
    ),
    areas=(
        Area("A group made", "a system group added to the system's database", GROUPADD,
             covered="the group liminal, where there is none"),
        Area("A member added", "a user put in a supplementary group", USERMOD,
             covered="the platform's user put in the group liminal"),
        Area("A group removed", "a group taken out of the system's database", GROUPDEL),
    ),
    calls=(
        Call("groupadd --system liminal", "the group liminal made, as a system group", "A group made",
             used="Root access turned on, where the group is not there", docs=GROUPADD, writes=True),
        Call("usermod -a -G liminal <user>", "the user put in the group, its other groups kept", "A member added",
             used="Root access turned on, where the platform's user is not in it", docs=USERMOD, writes=True),
        Call("addgroup -S liminal", "BusyBox: the group made, as a system group", "A group made",
             used="Root access turned on, where there is no groupadd", docs=BUSYBOX, writes=True),
        Call("addgroup <user> liminal", "BusyBox: the user put in the group", "A member added",
             used="Root access turned on, where there is no usermod", docs=BUSYBOX, writes=True),
        Call("groupdel liminal", "the group removed", "A group removed", docs=GROUPDEL, writes=True),
    ),
    verified=RIGHTS_VERIFIED,
)

APT = Api(
    name="APT (apt-get, apt-cache)",
    maker="the Debian project (APT); the distribution's archive (Ubuntu's, Debian's)",
    about=("APT installs a distribution's own packages from its archive, with what they need. Where no firewall tool "
           "is installed and APT is there (Debian, Ubuntu and their kin), the plugin offers to install nftables, the "
           "distribution's own package (0.9.0): what that takes is read first without root and changing nothing "
           "(apt-get -s, APT's simulation, says which packages it would install; apt-cache show, each one's Size, "
           "Installed-Size and whose it is), said on the form, then installed as root with debconf asking nothing "
           "(DEBIAN_FRONTEND=noninteractive), as a job. APT is asked in English (LC_ALL=C), so that its lock held by "
           "another program and a package not fetched are said in words. Installing it filters nothing."),
    kind="command",
    base="apt-get and apt-cache",
    version="APT 2 and 3 (Debian 12 and 13, Ubuntu 24.04)",
    auth="none to read; root to install (sudo with the password typed on the form, or the platform's root)",
    limits="",
    costs="",
    links=(
        Link("apt-get(8)", APT_GET, "reference"),
        Link("apt-cache(8)", APT_CACHE, "reference"),
        Link("debconf(7)", DEBCONF, "reference"),
        Link("nftables on Debian", "https://wiki.debian.org/nftables", "guide"),
    ),
    areas=(
        Area("Simulating", "what an install would do, changing nothing, run without root", APT_GET,
             covered="which packages installing nftables takes, said first"),
        Area("A package's facts", "its version, size, installed size and origin", APT_CACHE,
             covered="each package's Size and Installed-Size, and whose it is"),
        Area("Installing a package", "a package and what it needs, from the distribution's archive", APT_GET,
             covered="Install nftables…"),
        Area("Asking nothing", "debconf's noninteractive front end: its questions take their defaults", DEBCONF,
             covered="the install asks nothing"),
        Area("The package lists", "brought up to date from the archive (apt-get update)", APT_GET),
        Area("Removing a package", "a package removed, or purged with its configuration", APT_GET),
    ),
    calls=(
        Call("apt-get -s install nftables", "what installing nftables would do, changing nothing", "Simulating",
             used="what installing nftables takes, read without root", docs=APT_GET),
        Call("apt-cache show --no-all-versions <package>", "the candidate version's fields", "A package's facts",
             used="each package's size, read without root", docs=APT_CACHE),
        Call("apt-get install -y nftables", "nftables installed with what it needs, nothing asked",
             "Installing a package", used="Install nftables…, with DEBIAN_FRONTEND=noninteractive", docs=APT_GET,
             writes=True),
        Call("apt-get update", "the package lists brought up to date", "The package lists", docs=APT_GET, writes=True),
        Call("apt-get remove <package>", "a package removed", "Removing a package", docs=APT_GET, writes=True),
    ),
    verified=RIGHTS_VERIFIED,
)

# -- the World Wide Web tab's (0.8.0) ------------------------------------------------------------------------------------
CAPTURE = Api(
    name="libpcap (packet capture)",
    maker="the Tcpdump Group",
    about=("libpcap, the packet capture library tcpdump and Wireshark are built on: an adapter opened, a filter compiled "
           "and set, each packet read as it arrives, before nftables and iptables decide (a connection they drop still "
           "shows as its first packet arriving). On Linux it reads through the kernel's packet sockets. What an XDP "
           "program drops never reaches it: XDP runs before those sockets, so its drops are not seen at all. The "
           "library's capture.py calls the system's libpcap by ctypes, with no package between. The World "
           "Wide Web tab watches every TCP and UDP packet, IPv4 and IPv6, at the adapter of this machine's way out, the "
           "headers alone, only while the tab is shown and for 20 s after; only counts are kept, in memory. On the Linux "
           "the platform runs on only: inside a WSL distribution its own adapter (none at all under WSL 1, which gives "
           "libpcap no adapter to open); on Windows and macOS nothing is opened."),
    kind="sdk",
    base=("the system's libpcap (libpcap0.8 on Debian and Ubuntu; libpcap on Fedora, Arch and Alpine), through ctypes "
          "(the library's capture.py)"),
    version="libpcap 1.10 (1.10.7, of 2026-09-05, the newest stable; 1.11.0 in testing); every call used is in all of 1.x",
    auth=("root, or CAP_NET_RAW alone (all a capture that is not promiscuous needs), given by an administrator to the "
          "platform alone: AmbientCapabilities=CAP_NET_RAW in its system unit, or setcap cap_net_raw=ep on a copy of "
          "Python that is its own (python3 -m venv --copies, chmod 0750); never to the system's Python, which every "
          "program and every user runs, never CAP_NET_ADMIN, the right to rewrite the firewall, and never a password "
          "asked here"),
    limits="",
    costs="",
    links=(
        Link("tcpdump and libpcap", "https://www.tcpdump.org/", "docs"),
        Link("pcap(3PCAP)", PCAP + "pcap.3pcap.html", "reference"),
        Link("pcap-filter(7)", PCAP + "pcap-filter.7.html", "reference"),
        Link("pcap-linktype(7)", PCAP + "pcap-linktype.7.html", "reference"),
        Link("packet(7): Linux's packet sockets", MAN7 + "man7/packet.7.html", "reference"),
        Link("capabilities(7): CAP_NET_RAW", MAN7 + "man7/capabilities.7.html", "auth"),
        Link("systemd.exec(5): AmbientCapabilities=", AMBIENT, "auth"),
        Link("setcap(8)", MAN7 + "man8/setcap.8.html", "tool"),
        Link("venv: a copy of Python of its own (--copies)", VENV, "tool"),
        Link("libpcap's changes", "https://github.com/the-tcpdump-group/libpcap/blob/master/CHANGES", "changelog"),
        Link("libpcap's source", "https://github.com/the-tcpdump-group/libpcap", "source"),
    ),
    areas=(
        Area("Adapters", "the devices packets can be read from, and their addresses", PCAP + "pcap_findalldevs.3pcap.html",
             covered=("the adapter holding this machine's way-out address; every adapter's addresses (this machine's own) "
                      "to tell what came in from what went out, read again every 30 s while watching")),
        Area("Opening a capture", "an adapter opened, how much of each packet kept, promiscuous or not",
             PCAP + "pcap_open_live.3pcap.html",
             covered="the headers alone (128 bytes of each packet), not in promiscuous mode: this machine's own traffic"),
        Area("Filters", "BPF filters compiled from words and set in the kernel", PCAP + "pcap-filter.7.html",
             covered="(tcp or udp): every TCP and UDP packet, to and from any of this machine's addresses"),
        Area("Reading packets", "each packet as it arrives, with its time and its length", PCAP + "pcap_next_ex.3pcap.html",
             covered=("each packet's addresses, ports, TCP flags, IP version and size; read without blocking, its socket "
                      "waited on 150 ms at most, so watching stops soon after the tab is left")),
        Area("Link-layer headers", "what an adapter's packets begin with (Ethernet, Linux's cooked header, raw IP)",
             PCAP + "pcap-linktype.7.html", covered="where each packet's IP header starts"),
        Area("The right to capture", "root, or a program given CAP_NET_RAW (a capture that is not promiscuous needs no more)",
             MAN7 + "man7/capabilities.7.html",
             covered=("said only when libpcap says the right is missing and the platform is not root: how an "
                      "administrator gives CAP_NET_RAW alone to the platform alone (its system unit's AmbientCapabilities=, "
                      "or setcap on a copy of Python that is its own), never to the system's Python; as root, what else "
                      "may forbid packet sockets (a container, AppArmor, SELinux); no password asked")),
        Area("Packet sockets", "AF_PACKET, which libpcap reads through on Linux (TPACKET_V3 rings)",
             MAN7 + "man7/packet.7.html"),
        Area("Statistics", "the packets received, and those the kernel dropped for want of room", PCAP + "pcap_stats.3pcap.html"),
        Area("Writing a capture", "packets saved to a file Wireshark reads", PCAP + "pcap_dump_open.3pcap.html"),
        Area("The newer way to open", "pcap_create, then options (buffer size, immediate mode, time stamps), then pcap_activate",
             PCAP + "pcap_create.3pcap.html"),
    ),
    calls=(
        Call("pcap_findalldevs", "every capture device and its addresses", "Adapters",
             used="the adapter holding this machine's way-out address, and this machine's own addresses",
             docs=PCAP + "pcap_findalldevs.3pcap.html"),
        Call("pcap_freealldevs", "the device list freed", "Adapters", used="once the adapter is found",
             docs=PCAP + "pcap_findalldevs.3pcap.html"),
        Call("pcap_open_live", "a device opened for capture", "Opening a capture",
             used="the tab's capture: 128 bytes of each packet, not promiscuous", docs=PCAP + "pcap_open_live.3pcap.html"),
        Call("pcap_compile", "a filter compiled", "Filters", used="(tcp or udp)", docs=PCAP + "pcap_compile.3pcap.html"),
        Call("pcap_setfilter", "the filter set", "Filters", used="the same", docs=PCAP + "pcap_setfilter.3pcap.html"),
        Call("pcap_freecode", "the compiled filter freed", "Filters", used="once it is set", docs=PCAP + "pcap_freecode.3pcap.html"),
        Call("pcap_datalink", "the link-layer header type", "Link-layer headers", used="where each packet's IP header starts",
             docs=PCAP + "pcap_datalink.3pcap.html"),
        Call("pcap_setnonblock", "a capture read without blocking", "Reading packets",
             used="so a read waits on its socket no longer than its timeout", docs=PCAP + "pcap_setnonblock.3pcap.html"),
        Call("pcap_get_selectable_fd", "the capture's socket, to wait on with poll", "Reading packets",
             used="waited on for 150 ms at most before each read", docs=PCAP + "pcap_get_selectable_fd.3pcap.html"),
        Call("pcap_next_ex", "the next packet", "Reading packets", used="each packet while the tab is watched",
             docs=PCAP + "pcap_next_ex.3pcap.html"),
        Call("pcap_geterr", "the last error in words", "Reading packets", used="why packets could not be watched, said on the tab",
             docs=PCAP + "pcap_geterr.3pcap.html"),
        Call("pcap_close", "the capture closed", "Opening a capture",
             used="20 s after the tab was last shown, and when the plugin is detached", docs=PCAP + "pcap_close.3pcap.html"),
        Call("pcap_loop", "packets handed to a callback", "Reading packets", docs=PCAP + "pcap_loop.3pcap.html"),
        Call("pcap_stats", "the packets received and dropped", "Statistics", docs=PCAP + "pcap_stats.3pcap.html"),
        Call("pcap_dump_open", "a capture file opened for writing", "Writing a capture", docs=PCAP + "pcap_dump_open.3pcap.html"),
        Call("pcap_create", "a capture handle made, not yet active", "The newer way to open", docs=PCAP + "pcap_create.3pcap.html"),
        Call("pcap_activate", "a handle made by pcap_create activated", "The newer way to open",
             docs=PCAP + "pcap_activate.3pcap.html"),
        # the two ways the tab gives an administrator (world.capture_help), never made from here
        Call("AmbientCapabilities=CAP_NET_RAW",
             ("CAP_NET_RAW given to what a systemd unit starts: under [Service] of the platform's system unit "
              "(liminal-platform-boot.service, the Linux administration plugin's boot service), the platform and the "
              "programs it runs have it, and no one else"),
             "The right to capture", docs=AMBIENT, writes=True),
        Call("setcap cap_net_raw=ep <the platform's own python>",
             ("CAP_NET_RAW given to whoever runs that file: a copy of Python that is the platform's own (python3 -m venv "
              "--copies, chmod 0750, its group the platform's), never the system's; it lasts until the file is written "
              "again (python3 -m venv --upgrade copies it anew, without the right, and the tab then says so again)"),
             "The right to capture", docs=MAN7 + "man8/setcap.8.html", writes=True),
    ),
    verified=WORLD_VERIFIED,
)

DBIP_LITE = Api(
    name="DB-IP Lite City (GeoIP)",
    maker="DB-IP",
    about=("DB-IP's free IP to City Lite database: every IPv4 and IPv6 range with its continent, country, region, city and "
           "an approximate latitude and longitude, a subset of DB-IP's paid data with reduced accuracy, updated monthly, "
           "under the Creative Commons Attribution 4.0 International License. The World Wide Web tab downloads this "
           "month's file in MaxMind DB form (about 60 MB, 121 MB unpacked) only when you accept its licence on the tab, "
           "keeps one copy in the data folder, and looks each network up in it on this machine with the maxminddb "
           "package: no address is sent anywhere. \"IP Geolocation by DB-IP\", linked to db-ip.com, is shown wherever "
           "places are."),
    kind="feed",
    base=("https://download.db-ip.com/free/dbip-city-lite-<year>-<month>.mmdb.gz, kept in the data folder's geoip/ and "
          "read there"),
    version="the November 2026 file (7,777,816 ranges; MaxMind DB format 2.0), read with maxminddb 3.2.0",
    auth="none: no account and no key; its licence is accepted on the tab before the download",
    limits=("one file a month; downloaded only when you ask, one download at a time, and not again while that month's file "
            "is installed"),
    costs="",
    links=(
        Link("IP to City Lite", DBIP + "db/download/ip-to-city-lite", "docs"),
        Link("The City Lite file's MMDB fields", DBIP + "db/format/ip-to-city-lite/mmdb.html", "reference"),
        Link("DB-IP's databases", DBIP + "db/", "docs"),
        Link("The Lite databases: licence and attribution", DBIP + "db/lite.php", "terms"),
        Link("Creative Commons Attribution 4.0 International", "https://creativecommons.org/licenses/by/4.0/", "terms"),
        Link("The MaxMind DB format", "https://maxmind.github.io/MaxMind-DB/", "spec"),
        Link("maxminddb, the reader", READER_DOCS, "sdk"),
        Link("maxminddb's source", READER, "source"),
        Link("maxminddb's changes", READER + "/blob/main/HISTORY.rst", "changelog"),
        Link("maxminddb on PyPI", "https://pypi.org/project/maxminddb/", "tool"),
    ),
    areas=(
        Area("IP to City Lite", "each range's continent, country, region, city and approximate latitude and longitude",
             DBIP + "db/download/ip-to-city-lite",
             covered="each public network's place: drawn on the globe, and its country and city in the Places table"),
        Area("The monthly download", "this month's file, gzipped, updated monthly; no account", DBIP + "db/download/ip-to-city-lite",
             covered=("downloaded on your word once its licence is accepted (last month's when this month's is not out "
                      "yet), as a job whose progress shows in the plugin's panel and which stops by itself after 30 "
                      "minutes; over https from download.db-ip.com alone, a redirect anywhere else refused; unpacked into "
                      "the data folder in place of the older copy; Update… offered once the file installed is older than "
                      "this month")),
        Area("The licence and attribution", "CC BY 4.0: free to use, crediting DB-IP with a link back wherever its results are shown",
             DBIP + "db/lite.php",
             covered=("shown before the download and accepted in so many words, the acceptance kept in your own login "
                      "store when you ask from the platform's page (licence-dbip-lite, licence-dbip-asn-lite; 0.12.0); "
                      "\"IP Geolocation by DB-IP\" linked beside the places")),
        Area("The MMDB file", ("a MaxMind DB 2.0 search tree of networks; each record's city.names, location, "
                               "country.iso_code, continent and subdivisions"), DBIP + "db/format/ip-to-city-lite/mmdb.html",
             covered=("read with maxminddb, memory-mapped, never read whole into memory, and mapped only while the tab is "
                      "watched (let go once watching stops, mapped again at its next ask); the last 4096 answers kept, "
                      "each cut short; the local network's addresses never looked up")),
        Area("IP to Country Lite", "each range's country alone (732,796 ranges)", DBIP + "db/download/ip-to-country-lite"),
        Area("IP to ASN Lite", "each range's AS number and organisation (485,292 ranges)", DBIP + "db/download/ip-to-asn-lite",
             covered="each network's AS number and operator, in the hop table and with the places: read on this PC from the data folder's geoip/asn/, beside the GeoIP file, memory-mapped as it is"),
        Area("The CSV files", "the same data as CSV (City Lite's is 660 MB unpacked)", DBIP + "db/download/ip-to-city-lite"),
        Area("The lookup API", "an address's place asked of DB-IP's servers; never asked here, for it would send the address away",
             DBIP + "api/doc.php"),
        Area("The paid databases", "DB-IP's full data: location, ISP and more, more accurate", DBIP + "db/"),
    ),
    calls=(
        Call("GET https://download.db-ip.com/free/dbip-city-lite-<year>-<month>.mmdb.gz", "a month's City Lite file, gzipped",
             "The monthly download",
             used=("Download… and Update… in the GeoIP sources table (0.12.0; Install the GeoIP file… before), on your "
                   "word, as a job: this month's, then last month's on a 404; https on every hop, from download.db-ip.com alone"),
             docs=DBIP + "db/download/ip-to-city-lite"),
        Call("GET https://download.db-ip.com/free/dbip-city-lite-<year>-<month>.csv.gz", "the same as CSV", "The CSV files",
             docs=DBIP + "db/download/ip-to-city-lite"),
        Call("GET https://download.db-ip.com/free/dbip-country-lite-<year>-<month>.mmdb.gz", "a month's Country Lite file",
             "IP to Country Lite", docs=DBIP + "db/download/ip-to-country-lite"),
        Call("GET https://download.db-ip.com/free/dbip-asn-lite-<year>-<month>.mmdb.gz", "a month's ASN Lite file",
             "IP to ASN Lite", used="Download… and Update… in the GeoIP sources table (0.12.0; Install the ASN file… before), once you accept its licence, run by the platform as a job: this month's, else last month's; https on every hop, from download.db-ip.com alone", docs=DBIP + "db/download/ip-to-asn-lite"),
        Call("maxminddb.open_database(<file>, MODE_MMAP_EXT)", "the file opened, memory-mapped by the C extension",
             "The MMDB file", used="the file opened for lookups (MODE_MMAP, pure Python, without the extension); a download checked",
             docs=READER_DOCS),
        Call("Reader.get(<address>)", "an address's record", "The MMDB file", used="each public network's place", docs=READER),
        Call("Reader.get_with_prefix_len(<address>)", "a record and its network's prefix length", "The MMDB file",
             used="a download checked: its search tree leads to a record", docs=READER),
        Call("Reader.metadata()", "the file's build time, IP version, record size and node count", "The MMDB file",
             used="the file's date (Update… once it is older than this month), and a download checked", docs=READER_DOCS),
        Call("maxminddb.open_database(<file>, MODE_MEMORY)", "the whole file read into memory", "The MMDB file",
             docs=READER_DOCS),
        Call("GET api.db-ip.com/v2/<key>/<address>", "an address's place, asked of DB-IP", "The lookup API",
             docs=DBIP + "api/doc.php"),
    ),
    verified=WORLD_VERIFIED,
)

OPENDNS = Api(
    name="OpenDNS (myip.opendns.com)",
    maker="Cisco (OpenDNS)",
    about=("OpenDNS's resolvers answer the name myip.opendns.com, asked of them directly, with the asker's own public "
           "address: an A record over IPv4, an AAAA record over IPv6. The World Wide Web tab asks resolver1 "
           "(208.67.222.222, and 2620:119:35::35 over IPv6) for this network's public address, which the GeoIP file "
           "places as this machine's home on the globe when you set no place of your own: only once a GeoIP file is "
           "installed, once while the plugin is attached, and again 15 minutes after none was given. The name is asked "
           "as an absolute one (myip.opendns.com., a trailing dot), so none of this machine's search domains is added to "
           "it. The question names no other machine: no peer's address is sent. OpenDNS documents its resolvers, not "
           "this name."),
    kind="dns",
    base=("nslookup -type=a -timeout=3 -retry=1 myip.opendns.com. 208.67.222.222; -type=aaaa at 2620:119:35::35 (BIND's "
          "nslookup: dnsutils on Debian and Ubuntu, bind-utils on Fedora, bind-tools on Arch and Alpine; without it the "
          "tab says so and asks nothing)"),
    version="OpenDNS's public resolvers (208.67.222.222, 208.67.220.220)",
    auth="none: a public DNS question",
    limits=("none published; the tab asks at most once an IP version while the plugin is attached, and again 15 minutes "
            "after none was given"),
    costs="",
    links=(
        Link("OpenDNS's setup guide (its resolvers' addresses)", "https://www.opendns.com/setupguide/", "guide"),
        Link("OpenDNS", "https://www.opendns.com/", "docs"),
        Link("OpenDNS's support", "https://www.opendns.com/support/", "guide"),
        Link("Cisco Umbrella's status", "https://status.umbrella.cisco.com/", "status"),
        Link("OpenDNS's terms", "https://www.opendns.com/consumer-terms/", "terms"),
        Link("OpenDNS's privacy policy", "https://www.opendns.com/privacy-policy/", "terms"),
        Link("nslookup(1)", NSLOOKUP, "tool"),
    ),
    areas=(
        Area("The asker's own address", "myip.opendns.com, answered with the address the question came from",
             "https://www.opendns.com/setupguide/", covered="this network's public IPv4 and IPv6 address: home on the globe"),
        Area("Its resolvers", "public resolvers anyone may use, with filtering for accounts", "https://www.opendns.com/setupguide/"),
        Area("FamilyShield", "resolvers that block adult content (208.67.222.123, 208.67.220.123)", "https://www.opendns.com/setupguide/"),
        Area("Accounts and filtering", "a network's own filtering, set up on its dashboard", "https://www.opendns.com/support/"),
    ),
    calls=(
        # as the library asks them (dns.public_address: each answer waited for 3 s, once more if none; the name absolute)
        Call("nslookup -type=a -timeout=3 -retry=1 myip.opendns.com. 208.67.222.222", "the asker's IPv4 address",
             "The asker's own address", used="this network's public IPv4 address (asked first)",
             docs="https://www.opendns.com/setupguide/"),
        Call("nslookup -type=aaaa -timeout=3 -retry=1 myip.opendns.com. 2620:119:35::35",
             "the asker's IPv6 address, asked over IPv6", "The asker's own address",
             used="this network's public IPv6 address, when no IPv4 one was given"),
        Call("nslookup <name> 208.67.222.222", "any name resolved by OpenDNS", "Its resolvers",
             docs="https://www.opendns.com/setupguide/"),
    ),
    verified=WORLD_VERIFIED,
)

GOOGLE = Api(
    name="Google's name servers (o-o.myaddr.l.google.com)",
    maker="Google",
    about=("Google's own name servers (ns1.google.com) answer the text record of o-o.myaddr.l.google.com with the address "
           "the question came from. The World Wide Web tab asks them for this network's public address when OpenDNS gives "
           "none, as the home of this machine on the globe; the name is asked as an absolute one (a trailing dot), and "
           "the question names no other machine. Google documents no page for this name; its Public DNS pages, linked "
           "here, cover its DNS service and its terms."),
    kind="dns",
    base=("nslookup -type=txt -timeout=3 -retry=1 o-o.myaddr.l.google.com. 216.239.32.10 (ns1.google.com; "
          "2001:4860:4802:32::a over IPv6; BIND's nslookup)"),
    version="Google's authoritative servers for google.com",
    auth="none: a public DNS question",
    limits="none published; asked only when OpenDNS gives no public address",
    costs="",
    links=(
        Link("Google Public DNS", "https://developers.google.com/speed/public-dns", "docs"),
        Link("Google Public DNS: frequently asked questions", "https://developers.google.com/speed/public-dns/faq", "guide"),
        Link("Google Public DNS: DNS over HTTPS (JSON)", "https://developers.google.com/speed/public-dns/docs/doh/json", "reference"),
        Link("Google Public DNS's terms", "https://developers.google.com/speed/public-dns/terms", "terms"),
        Link("Google Public DNS's privacy", "https://developers.google.com/speed/public-dns/privacy", "terms"),
        Link("nslookup(1)", NSLOOKUP, "tool"),
    ),
    areas=(
        Area("The asker's own address", "o-o.myaddr.l.google.com's text record, asked of ns1.google.com directly",
             covered="this network's public IPv4 and IPv6 address, when OpenDNS gives none: home on the globe"),
        Area("Google Public DNS", "the public resolvers (8.8.8.8, 8.8.4.4)", "https://developers.google.com/speed/public-dns/docs/using"),
        Area("DNS over HTTPS", "names resolved over HTTPS, as JSON too", "https://developers.google.com/speed/public-dns/docs/doh"),
    ),
    calls=(
        # as the library asks them (dns.public_address), as OpenDNS's are
        Call("nslookup -type=txt -timeout=3 -retry=1 o-o.myaddr.l.google.com. 216.239.32.10",
             "the asker's address, in a text record", "The asker's own address",
             used="this network's public IPv4 address, when OpenDNS gives none"),
        Call("nslookup -type=txt -timeout=3 -retry=1 o-o.myaddr.l.google.com. 2001:4860:4802:32::a",
             "the same, asked over IPv6", "The asker's own address",
             used="this network's public IPv6 address, when no IPv4 one was given and OpenDNS gives none"),
        Call("GET https://dns.google/resolve?name=<name>&type=<type>", "a name resolved over HTTPS, as JSON",
             "DNS over HTTPS", docs="https://developers.google.com/speed/public-dns/docs/doh"),  # where its address is given
    ),
    verified=WORLD_VERIFIED,
)

# -- the Netstat tab, the hosts database and the globe's internet infrastructure (0.9.0) -------------------------------
# The tab, the database and the globe's filters and layers are the library's Firewall base's (liminal-libs 1.65.0:
# sockets.py, hostbook.py, machines/netstat.py, machines/infrastructure.py). The tab reads the kernel's socket tables
# (PROCFS); what the globe's layers are downloaded from is this plugin's to name, since the library names no outside
# host: the data sets of INFRASTRUCTURE, each a plain dict of the library's infrastructure.DataSet keys (read by the
# base as Firewall.INFRASTRUCTURE: so an older library, which reads none, still loads this module), downloaded only on
# your click once its licence is accepted, as a job; and the cards of where they come from. Every address on the first
# four of these cards was read on NETSTAT_VERIFIED, the Topology Zoo's on GLOBE_VERIFIED (its repository, its licence
# and its records: progress/globe-research.md, nothing downloaded).
NETSTAT_VERIFIED = "2026-11-18"
GLOBE_VERIFIED = "2026-11-19"
KERNEL_DOCS = "https://docs.kernel.org/networking/proc_net_tcp.html"  # the kernel's own words on /proc/net/tcp
WSL_NETWORKING = "https://learn.microsoft.com/en-us/windows/wsl/networking"  # WSL's localhost, NAT and mirrored modes
OVERPASS = "https://overpass-api.de/api/interpreter"  # OpenStreetMap's data, through the public Overpass server
WDQS = "https://query.wikidata.org/sparql"  # Wikidata's query service
EMODNET_WFS = "https://ows.emodnet-humanactivities.eu/geoserver/emodnet/wfs"  # EMODnet Human Activities' WFS
OSM_WIKI = "https://wiki.openstreetmap.org/wiki/"
OVERPASS_DOC = "https://dev.overpass-api.de/overpass-doc/en/"  # the Overpass API's own manual, by its author
GEOSERVER_WFS = "https://docs.geoserver.org/latest/en/user/services/wfs/"  # the WFS EMODnet runs is GeoServer's
WDQS_MANUAL = "https://www.mediawiki.org/wiki/Wikidata_Query_Service/User_Manual"  # the query service's own
EMODNET_RECORD = "https://emodnet.ec.europa.eu/geonetwork/srv/api/records/39ebe289-410b-4a5d-88a4-51bfcde538de"
ZOO_REPO = "https://github.com/mroughan/InternetTopologyZoo"  # the Internet Topology Zoo's repository (CC BY 4.0)
ZOO_RAW = "https://raw.githubusercontent.com/mroughan/InternetTopologyZoo/main/"  # its files, as they are
ZOO_GML = ZOO_RAW + "gml.tar.gz"  # every network's map in GML, one gzipped tar: 348,613 bytes (2026-11-19)
ZOO_RECORD = "https://researchdata.edu.au/internet-topology-zoo-data-set/4045587"  # Adelaide University's record
ZOO_DOI = "https://doi.org/10.25909/30153949.v1"  # the data set's DOI (figshare)
NETZSCHLEUDER = "https://networks.skewed.de/net/internet_top_pop"  # its points of presence, as Netzschleuder keeps them
OSM_CREDIT = {"text": "© OpenStreetMap contributors", "url": "https://www.openstreetmap.org/copyright"}
WIKIDATA_CREDIT = {"text": "Wikidata", "url": "https://www.wikidata.org/wiki/Wikidata:Licensing"}
EMODNET_CREDIT = {"text": "EMODnet Human Activities; data originator Cogea Srl",
                  "url": "https://emodnet.ec.europa.eu/en/"}
ZOO_CREDIT = {"text": "Internet Topology Zoo (Knight, Nguyen, Falkner, Bowden, Roughan, IEEE JSAC 2011), Adelaide "
                      "University, CC BY 4.0", "url": ZOO_REPO}
ODBL = ("OpenStreetMap's data is free under the Open Database License 1.0 (opendatacommons.org/licenses/odbl/1-0): it "
        "may be copied, used and adapted as long as OpenStreetMap and its contributors are credited, and a "
        "changed copy passed on to others stays under the same licence. So wherever these features are drawn the "
        "page says \"© OpenStreetMap contributors\", linked to openstreetmap.org/copyright. It is what volunteers "
        "have mapped: incomplete in places, and it comes as it is.")
CC0 = ("Wikidata's structured data is in the public domain (Creative Commons Zero, "
       "creativecommons.org/publicdomain/zero/1.0): it may be used for anything and no credit is required; the page "
       "names Wikidata all the same. A place with no coordinates of its own is put where its seat or its town is, and "
       "it comes as it is.")
EMODNET_LICENCE = (
    "EMODnet's telecom cable routes are free under the Creative Commons Attribution 4.0 International licence "
    "(creativecommons.org/licenses/by/4.0): they may be copied, shared and adapted for any purpose, commercial uses "
    "included, as long as they are credited, the licence is linked and changes are said. Their record asks for these "
    "words: \"This data was downloaded from the EMODnet Portal (https://emodnet.ec.europa.eu/en/). The data originator "
    "is Cogea Srl.\" So wherever these routes are drawn the page says \"EMODnet Human Activities; data originator "
    "Cogea Srl\", linked to emodnet.ec.europa.eu, and the globe draws them thinned (no two vertices nearer than 0.02 "
    "degrees). They are the actual routes as six national sources gave them (Germany's BSH, Spain's CICA, France's "
    "SHOM and SIGCables, Malta's IOI-MOC, the United Kingdom's OGA); Dutch cables are withheld by their source for "
    "security, and the data comes as it is.")
ZOO_LICENCE = (
    "The Internet Topology Zoo's maps are free under the Creative Commons Attribution 4.0 International licence "
    "(creativecommons.org/licenses/by/4.0), as its repository's LICENSE and Adelaide University's record of it say: "
    "they may be copied, shared and adapted for any purpose, commercial uses included, as long as they are credited, "
    "the licence is linked and changes are said. So wherever its networks are drawn the page says \"Internet Topology "
    "Zoo (Knight, Nguyen, Falkner, Bowden, Roughan, IEEE JSAC 2011), Adelaide University, CC BY 4.0\", linked to its "
    "repository, and each network is named with the year of its map. What is changed: of each network only its newest "
    "map is drawn, from 2000 on, and of it only its own points of presence that have a place and the links between "
    "them, each drawn as the great circle between its two ends. These are logical links as the operators' public maps "
    "showed them about 2010 and 2011, placed at their cities: not the networks of today, nor the routes their fibre "
    "takes. The data comes as it is.")
OSM = {"format": "overpass", "url": OVERPASS, "source": "OpenStreetMap, through the Overpass API",
       "licence_name": "ODbL 1.0", "licence": ODBL, "credit": OSM_CREDIT}
# EMODnet's six telecom cable layers (its WFS's capabilities, read 2026-11-17: the power cables' three left out)
EMODNET_LAYERS = ("emodnet:bshcontiscables", "emodnet:cicacables", "emodnet:shomcables", "emodnet:sigcables",
                  "emodnet:maltacables", "emodnet:ukfibrecables")
# Each data set as the library reads it: its address and query, its download's size (an estimate, said as one), its
# licence's words (shown before the download and accepted in so many words) and its credit (beside every feature
# drawn), and `wait`, the seconds each socket operation of its download waits at most: the query's own time limit and a
# margin, for a server may be silent while a query runs (Overpass' [timeout:180] and [timeout:300]; the Wikidata Query
# Service's deadline of 60 s). The data sets are the same as the Windows firewall plugin's, in the same order (their
# digest pinned in both plugins' tests). The Overpass queries ask for tags alone (out tags), a point for each feature
# that is no line (center) and a line's geometry (geom): nothing about this machine or its traffic. A line on land on
# power poles (power=minor_line, local distribution: 6,394 of communication=line's 15,775, taginfo 2026-11-18) is left
# out, which leaves the lines most like backbones. Wikidata's data centres are asked with their kinds (P279*: colocation
# centres among them, 211 items against 168, a count of 2026-11-19). The Topology Zoo's archive is the file alone, its
# size as GitHub gave it (2026-11-19).
# liminal-libs 1.72.1: IANA's RDAP bootstrap files, IPv4 and IPv6: which registry holds an address, its routers'
# networks then looked up of that registry (the library's machines/lookups.py, within the registries' limits); named
# here, as every outside host is, never in the library
RDAP_BOOTSTRAP = ("https://data.iana.org/rdap/ipv4.json", "https://data.iana.org/rdap/ipv6.json")
# liminal-libs 1.73.0: what routers' names are read with (machines/names.py), drawn as layers too, each downloaded on
# the user's click with its size and its licence first
OURAIRPORTS_CSV = "https://davidmegginson.github.io/ourairports-data/airports.csv"  # 12.2 MB (2026-11-22)
OURAIRPORTS_LICENCE = ("OurAirports releases all of its data to the public domain: it may be used for any purpose, "
                       "with no permission needed, and comes with no guarantee of accuracy or fitness for use.")
OURAIRPORTS_CREDIT = {"text": "OurAirports", "url": "https://ourairports.com/data/"}
GEONAMES_CITIES = "https://download.geonames.org/export/dump/cities15000.zip"  # 3.2 MB (2026-11-22)
GEONAMES_LICENCE = ("GeoNames' data is free under the Creative Commons Attribution 4.0 licence: it may be used, "
                    "shared and adapted for any purpose, GeoNames credited as its source.")
GEONAMES_CREDIT = {"text": "GeoNames", "url": "https://www.geonames.org/"}

# liminal-libs 1.104.0 (the Monday list's items 24, 28, 29 and 32): more of the globe's data sets, each downloaded on
# your click with its size and its licence first, kept in the plugin's own database (infrastructure.db) as the eight
# above are. Their makers' pages were read on 2026-11-26 (`VERIFIED_GLOBE2`), nothing downloaded: Natural Earth's roads
# and railways pages (their links send the file on to naciscdn.org, Natural Earth's own CDN), AfTerFibre's map (its
# fibre is served only as its map's vector tiles now), TopoHub's repository, RIPE Atlas's probes archive, its built-in
# measurements and its terms, CelesTrak's GP data formats (CATNR names one satellite a request) and usage policy, and
# the sgp4 package's files on PyPI (their sizes and sha256 read from its own file list).
VERIFIED_GLOBE2 = "2026-11-26"
NATURAL_EARTH_SITE = "https://www.naturalearthdata.com/"
NATURAL_EARTH_DOWNLOAD = NATURAL_EARTH_SITE + "http//www.naturalearthdata.com/download/10m/cultural/"  # its own links
NATURAL_EARTH_ROADS = NATURAL_EARTH_DOWNLOAD + "ne_10m_roads.zip"  # 8.66 MB, version 5.0.0 (2026-11-26)
NATURAL_EARTH_RAILWAYS = NATURAL_EARTH_DOWNLOAD + "ne_10m_railroads.zip"  # 14.42 MB, version 4.0.0 (2026-11-26)
NATURAL_EARTH_CDN = "naciscdn.org"  # where its download links send the file on to
AFTERFIBRE_SITE = "https://afterfibre.opentelecomdata.org/"  # afterfibre.nsrc.org sends you here (2026-11-26)
AFTERFIBRE_TILES = "https://d316kar6yg8hyq.cloudfront.net/africa-fiber/{z}/{x}/{y}.mvt"  # its map's tiles, layer fiber
AFTERFIBRE_BOUNDS = [-17.42, -34.50, 55.74, 36.87]  # its TileJSON's bounds: west, south, east, north
TOPOHUB_REPO = "https://github.com/piotrjurkiewicz/topohub"
TOPOHUB_WORLD = "https://raw.githubusercontent.com/piotrjurkiewicz/topohub/master/data/backbone/world.json"  # 1.04 MB
ATLAS_PROBES = "https://ftp.ripe.net/ripe/atlas/probes/archive/meta-latest"  # every probe and anchor, bzip2, 2 MB
ATLAS_LATEST = "https://atlas.ripe.net/api/v2/measurements/5151/latest/"  # the built-in IPv4 traceroute's newest
ATLAS_TERMS = "https://www.ripe.net/manage-ips-and-asns/db/support/documentation/ripe-atlas-terms-and-conditions/"
CELESTRAK_GP = "https://celestrak.org/NORAD/elements/gp.php"  # CelesTrak's GP elements, its CSV (the OMM fields)
# HughesNet's three geostationary satellites by their catalogue numbers, and the countries their beams reach (the
# globe's countries by their ISO 3166-1 numeric ids): Jupiter 1 the United States and Canada, Jupiter 2 and 3 the
# United States, Canada and the Latin American countries HughesNet is sold in
HUGHESNET = {"38551": "EchoStar XVII (Jupiter 1)", "41893": "EchoStar XIX (Jupiter 2)",
             "57479": "EchoStar XXIV (Jupiter 3)"}
AMERICAS = ["840", "124", "630", "484", "320", "340", "222", "558", "188", "591", "170", "218", "604", "076", "152",
            "032"]
HUGHESNET_BEAMS = {"38551": ["840", "124", "630"], "41893": AMERICAS, "57479": AMERICAS}

NATURAL_EARTH_CREDIT = {"text": "Made with Natural Earth", "url": NATURAL_EARTH_SITE}
AFTERFIBRE_CREDIT = {"text": "AfTerFibre, NSRC", "url": AFTERFIBRE_SITE}
TOPOHUB_CREDIT = {"text": "TopoHub (P. Jurkiewicz, SoftwareX 24, 2023)", "url": TOPOHUB_REPO}
ATLAS_CREDIT = {"text": "RIPE Atlas (RIPE NCC)", "url": "https://atlas.ripe.net/"}
CELESTRAK_CREDIT = {"text": "CelesTrak (T.S. Kelso)", "url": "https://celestrak.org/"}
NATURAL_EARTH_LICENCE = (
    "Natural Earth's data is in the public domain: its terms say every version of its map data on its website is, so "
    "it may be used in any way, changed or not, commercial uses included, with no permission asked. No credit is "
    "required; the page says \"Made with Natural Earth\", as Natural Earth suggests. These are the roads and railways "
    "at 1:10m, ferries left out: where traffic goes, not where fibre is. They are drawn as a stand-in for fibre where "
    "none is mapped, since long-haul fibre most often runs beside them, and routes found along them alone say so. The "
    "data comes as it is.")
AFTERFIBRE_LICENCE = (
    "AfTerFibre's map of Africa's fibre on land is free under the Creative Commons Attribution 4.0 International "
    "licence (creativecommons.org/licenses/by/4.0), as its records say; its site today states no licence of its own. "
    "It may be copied, shared and adapted for any purpose, commercial uses included, as long as it is credited, the "
    "licence is linked and changes are said. So wherever its fibre is drawn the page says \"AfTerFibre, NSRC\", linked "
    "to its site. What is changed: its map's tiles are read at one zoom (5), so a route is drawn thinned, and of each "
    "route only who runs it, whose it is, whether it is lit and its country are kept; its contributors' names and "
    "e-mail addresses are never kept. Its undersea layer is another maker's and is not asked for. It comes as it is.")
TOPOHUB_LICENCE = (
    "TopoHub's repository on GitHub is under the MIT licence, which lets its contents be used, copied, changed and "
    "passed on for any purpose, as long as its copyright notice goes with them. No licence is stated for its data or "
    "for the sources its model is built from, so this is the repository's licence and no more. The page credits it as "
    "\"TopoHub (P. Jurkiewicz, SoftwareX 24, 2023)\", linked to its repository. Its backbones are a model: cities and "
    "the land and submarine links between them as TopoHub builds them, not any operator's map, and the data comes as "
    "it is.")
ATLAS_LICENCE = (
    "RIPE Atlas's data is the RIPE NCC's, under its RIPE Atlas Service Terms and Conditions (version 3.5, in force "
    "since 4 November 2025). Their article 4.5 says any commercial use of it needs the RIPE NCC's permission first, and "
    "article 10.2 that its databases are passed on to others only with its written authorisation. So it is downloaded "
    "for non-commercial use on this PC alone and never passed on; commercial use needs the RIPE NCC's permission. The "
    "page credits it as \"RIPE Atlas (RIPE NCC)\", linked to atlas.ripe.net. The data comes as it is.")
CELESTRAK_LICENCE = (
    "CelesTrak states no licence for the orbits it publishes: they are the US Space Force's general perturbations "
    "elements (from its 18th Space Defense Squadron), passed on free of charge by CelesTrak (T.S. Kelso). Its usage "
    "policy asks that they are fetched no more than once an update (every 2 hours), asked compressed, used only from "
    "an answer that is OK, and that any other answer stops the download and is shown to a person. So they are asked "
    "only on your click, compressed, never again by themselves, Update… not offered before 2 hours, and a refusal "
    "stops it in words. The page credits it as \"CelesTrak (T.S. Kelso)\", linked to celestrak.org. The orbits come as "
    "they are: a satellite's place from them is good to a few kilometres for some days.")
NATURAL_EARTH = {"format": "shapefile", "source": "Natural Earth", "licence_name": "Public domain",
                 "licence": NATURAL_EARTH_LICENCE, "credit": NATURAL_EARTH_CREDIT, "hosts": [NATURAL_EARTH_CDN],
                 "stand_in": True, "step": 0.05, "wait": 120}
ATLAS = {"source": "RIPE Atlas (RIPE NCC)", "licence_name": "RIPE Atlas terms 3.5 (non-commercial)",
         "licence": ATLAS_LICENCE, "credit": ATLAS_CREDIT}
CELESTRAK = {"format": "omm-csv", "url": CELESTRAK_GP, "source": "CelesTrak", "licence_name": "none stated by CelesTrak",
             "licence": CELESTRAK_LICENCE, "credit": CELESTRAK_CREDIT, "retry": False, "every": 7200, "gzip": True,
             "wait": 120}
GLOBE2_SETS = (
    # item 24: Africa's fibre on land, as its map's tiles at zoom 5 (56 of them, asked one after another on the one
    # click); the roads and railways, a stand-in for fibre where none is mapped
    {"id": "afterfibre", "title": "Africa's terrestrial fibre", "format": "mvt", "layer": "fibre", "member": "fiber",
     "url": AFTERFIBRE_TILES, "tiles": {"zoom": 5, "bounds": AFTERFIBRE_BOUNDS}, "size": 3_000_000,
     "source": "AfTerFibre (NSRC), its map's tiles", "licence_name": "CC BY 4.0", "licence": AFTERFIBRE_LICENCE,
     "credit": AFTERFIBRE_CREDIT, "wait": 60,
     "about": ("Africa's fibre on land as NSRC's AfTerFibre maps it, live and planned; its contributors' names and "
               "addresses are never kept")},
    {**NATURAL_EARTH, "id": "ne-roads", "title": "Major roads (a stand-in for fibre)", "layer": "roads",
     "url": NATURAL_EARTH_ROADS, "member": "ne_10m_roads", "size": 8_660_000, "drop": {"featurecla": ["Ferry"]},
     "about": ("the world's major roads at 1:10m, ferries left out: where no fibre is mapped, long-haul fibre most "
               "often runs beside them")},
    {**NATURAL_EARTH, "id": "ne-railways", "title": "Railways (a stand-in for fibre)", "layer": "railways",
     "url": NATURAL_EARTH_RAILWAYS, "member": "ne_10m_railroads", "size": 14_420_000,
     "drop": {"featurecla": ["Railroad ferry"]},
     "about": "the world's railways at 1:10m, train ferries left out: a stand-in for fibre, as the roads"},
    # items 28 and 29: sources of the composite database, each behind its download
    {"id": "topohub-world", "title": "The world's backbones, a model (TopoHub)", "format": "topohub",
     "url": TOPOHUB_WORLD, "size": 1_040_000, "source": "TopoHub, through GitHub",
     "licence_name": "MIT, the repository's; its data's own not stated", "licence": TOPOHUB_LICENCE,
     "credit": TOPOHUB_CREDIT, "wait": 60,
     "about": ("cities and the land and submarine links between them, as TopoHub models them: a model, not an "
               "operator's map")},
    {**ATLAS, "id": "atlas-probes", "title": "RIPE Atlas probes and anchors", "format": "atlas-probes",
     "url": ATLAS_PROBES, "size": 2_000_000, "wait": 60,
     "about": "every probe's and anchor's place, country and network: where RIPE Atlas measures from"},
    {**ATLAS, "id": "atlas-traceroutes", "title": "RIPE Atlas traceroutes from its anchors", "format": "atlas-latest",
     "url": ATLAS_LATEST, "query": "format=json", "needs": "atlas-probes", "size": 5_000_000, "wait": 120,
     "about": ("the newest traceroute of each anchor: routers near an anchor placed, and the links between "
               "routers")},
    # item 32: the satellites' orbits, one constellation a data set, in this order (its colour: --sky-1, -2, -3)
    {**CELESTRAK, "id": "celestrak-starlink", "title": "Starlink's orbits", "constellation": "starlink",
     "query": "GROUP=starlink&FORMAT=csv", "size": 2_000_000,
     "about": "every Starlink satellite's orbit, as CelesTrak publishes it: no more often than every 2 hours"},
    {**CELESTRAK, "id": "celestrak-oneweb", "title": "Eutelsat OneWeb's orbits", "constellation": "oneweb",
     "query": "GROUP=oneweb&FORMAT=csv", "size": 120_000, "about": "every OneWeb satellite's orbit"},
    {**CELESTRAK, "id": "celestrak-hughesnet", "title": "HughesNet's satellites", "constellation": "hughesnet",
     "queries": [f"CATNR={n}&FORMAT=csv" for n in HUGHESNET], "beams": HUGHESNET_BEAMS, "size": 3_000,
     "about": "EchoStar XVII (Jupiter 1), XIX (Jupiter 2) and XXIV (Jupiter 3), geostationary"},
)
SGP4_LICENCE = (
    "The sgp4 package (Brandon Rhodes) is free under the MIT licence: anyone may use, copy, change, merge, publish and "
    "pass it on, free of charge, as long as its copyright notice and the licence go with it. It comes with no "
    "warranty of any kind.")
SGP4_PYPI = "https://pypi.org/project/sgp4/"
# the sgp4 package the satellites are placed with (the library's Firewall base's SKY_PACKAGE): its pure Python
# wheel, for any Linux and any Python 3; its size and sha256 as PyPI's file list gave them (2026-11-26)
SGP4_PACKAGE = {"version": "2.27", "name": "sgp4-2.27-py3-none-any.whl",
                "url": ("https://files.pythonhosted.org/packages/78/cd/"
                        "06dc91b31f2b919e788396c2cb5ad313d5ce0754321165343fd585c4be53/"
                        "sgp4-2.27-py3-none-any.whl"),
                "size": 123_299, "sha256": "5f3f5716649988b638fbe7fcda592830e0956f548ca273b93cfa5f75917b9087",
                "licence": SGP4_LICENCE, "licence_name": "MIT"}

INFRASTRUCTURE = (
    {**OSM, "id": "osm-datacentres", "title": "Data centres", "size": 2_000_000, "wait": 210,
     "about": "about 5,000 sites, and its few exchange points",
     "query": '[out:json][timeout:180];(nwr["telecom"="data_center"];nwr["building"="data_center"];'
              'nwr["telecom"="internet_exchange"];);out tags center qt;'},
    # a submarine cable's telecom categories: the OSM wiki's own word for fibre (optical), the spellings mapped beside
    # it (taginfo, 2026-11-18: telephone 749, fibre_optic 366, fiber_optic 64, optical 5, telefon 2, telegraph,
    # communication and telephone/fibre_optic 1 each), telephone's and telegraph's; power, mooring, ferry, sensor and
    # the like are left out
    {**OSM, "id": "osm-cables", "title": "Submarine cables and landing stations", "size": 3_000_000, "wait": 210,
     "about": "about 1,200 cable ways and 60 landing stations",
     "query": '[out:json][timeout:180];(way["seamark:type"="cable_submarine"]'
              '["seamark:cable_submarine:category"~"^(fibre_optic|fiber_optic|optical|telephone|telegraph|telefon|'
              'communication|telephone/fibre_optic)$"];'
              'way["communication"="line"]["location"="underwater"];way["communication"="line"]["submarine"="yes"];);'
              'out tags geom qt;nwr["telecom"="cable_landing_station"];out tags center qt;'},
    {**OSM, "id": "osm-lines", "title": "Telecom lines on land (partial)", "size": 15_000_000, "wait": 330,
     "about": "about 13,000 ways, none on power poles; no country is complete",
     "query": '[out:json][timeout:300];(way["communication"="line"]["location"!="underwater"]["submarine"!="yes"]'
              '[!"power"];way["telecom"="line"];way["telecom"="cable"];);out tags geom qt;'},
    {"id": "wikidata", "title": "Exchange points, ground stations and teleports", "format": "sparql", "url": WDQS,
     "source": "Wikidata", "licence_name": "CC0", "licence": CC0, "credit": WIKIDATA_CREDIT, "size": 200_000,
     "wait": 90, "about": "about 340 places, some data centres among them",
     "query": 'SELECT DISTINCT ?item ?itemLabel ?kind ?coord ?operatorLabel WHERE { { VALUES ?kind { wd:Q1433061 '
              'wd:Q1349167 wd:Q10379228 } ?item wdt:P31 ?kind . } UNION { VALUES ?kind { wd:Q671224 } ?item '
              'wdt:P31/wdt:P279* ?kind . } OPTIONAL { ?item wdt:P625 ?own } OPTIONAL { ?item wdt:P159/wdt:P625 ?seat '
              '} OPTIONAL { ?item wdt:P131/wdt:P625 ?place } BIND(COALESCE(?own, ?seat, ?place) AS ?coord) '
              'FILTER(BOUND(?coord)) OPTIONAL { ?item wdt:P137 ?operator } SERVICE wikibase:label { '
              'bd:serviceParam wikibase:language "en" } }'},
    {"id": "emodnet-cables", "title": "Telecom cable routes in European waters", "format": "geojson",
     "url": EMODNET_WFS, "source": "EMODnet Human Activities, through its WFS", "licence_name": "CC BY 4.0",
     "licence": EMODNET_LICENCE, "credit": EMODNET_CREDIT, "size": 4_000_000, "wait": 120,
     "about": "actual routes in European waters, and French cables beyond, from six national sources",
     "query": "service=WFS&version=1.1.0&request=GetFeature&typeName=" + ",".join(EMODNET_LAYERS)
              + "&outputFormat=application/json&srsName=EPSG:4326"},
    {"id": "topology-zoo", "title": "Backbone networks, about 2010-2011", "format": "gml", "url": ZOO_GML,
     "source": "the Internet Topology Zoo (Adelaide University), through GitHub", "licence_name": "CC BY 4.0",
     "licence": ZOO_LICENCE, "credit": ZOO_CREDIT, "size": 348_613, "wait": 60,
     "about": ("261 maps of backbone networks (GÉANT, Internet2, ESnet, Sprint, NTT, Cogent and more), each network's "
               "newest drawn: logical links, not fibre")},
    # liminal-libs 1.73.0: the airports' codes and the cities routers' names are read with, drawn as layers too
    {"id": "ourairports", "title": "Airports and their codes", "format": "ourairports", "url": OURAIRPORTS_CSV,
     "source": "OurAirports, through its data's mirror on GitHub", "licence_name": "Public domain",
     "licence": OURAIRPORTS_LICENCE, "credit": OURAIRPORTS_CREDIT, "size": 12_800_000, "wait": 180,
     "about": "the world's large and medium airports with a three-letter code: routers' names are read with them"},
    {"id": "geonames-cities", "title": "Cities of the world", "format": "geonames", "url": GEONAMES_CITIES,
     "source": "GeoNames", "licence_name": "CC BY 4.0", "licence": GEONAMES_LICENCE, "credit": GEONAMES_CREDIT,
     "size": 3_400_000, "wait": 120,
     "about": "the cities of 15,000 people or more: named on the globe, and routers' names read with them"},
    *GLOBE2_SETS,  # liminal-libs 1.104.0: fibre, roads and railways, backbones, RIPE Atlas, the satellites
)

PROCFS = Api(
    name="The kernel's socket tables (procfs)",
    maker="the Linux kernel",
    about=("Linux lists every socket of this machine's network in four files of /proc/net (tcp, tcp6, udp, udp6), "
           "which every account may read: each socket's two ends, its state, its user and its inode. The program "
           "behind a socket is found through /proc/<pid>/fd, which an account may read for its own processes alone "
           "(root, for all): there a socket's descriptor reads socket:[<inode>]; then the program's name, where it "
           "is on disk, the service it runs in and when it started are read from /proc/<pid>/comm, exe, cgroup and "
           "stat. The Netstat "
           "tab reads them as files, as the platform's user, with no command, no capture and no root (the library's "
           "sockets.py), every 3 s while it is shown; the hosts database is fed from the same readings. Another user's "
           "socket is listed without its program, unless the firewall's own read (as root, through ss) named the "
           "program listening on its port. Linux does not say when a socket began: Since is when a reading first "
           "listed it. Inside a WSL distribution the tables are its own network's; on Windows and macOS nothing is "
           "read."),
    kind="kernel",
    base=("/proc/net/tcp, tcp6, udp and udp6; /proc/<pid>/fd, comm, exe, cgroup and stat; /proc/stat, read as files "
          "(the library's sockets.py)"),
    version=("the same columns in all four tables on every Linux since 2.6 (WSL 2's kernel alike); a UDP socket "
             "connected to a peer says it (its st 01)"),
    auth=("none: the four tables are every account's to read; another user's /proc/<pid>/fd is root's alone, and "
          "root is never asked for the tab: their sockets are listed without their program"),
    limits=("20,000 sockets a reading at most (the rest left out, and said); the processes walked once a reading, and "
            "only for a socket not seen before or whose holder has ended"),
    costs="",
    links=(
        Link("proc_net_tcp: /proc/net/tcp and tcp6", KERNEL_DOCS, "reference"),
        Link("proc(5)", MAN7 + "man5/proc.5.html", "docs"),
        Link("proc_pid_net(5): /proc/net", MAN7 + "man5/proc_pid_net.5.html", "reference"),
        Link("proc_pid_fd(5)", MAN7 + "man5/proc_pid_fd.5.html", "reference"),
        Link("proc_pid_comm(5)", MAN7 + "man5/proc_pid_comm.5.html", "reference"),
        Link("proc_pid_exe(5)", MAN7 + "man5/proc_pid_exe.5.html", "reference"),
        Link("proc_pid_cgroup(5)", MAN7 + "man5/proc_pid_cgroup.5.html", "reference"),
        Link("proc_pid_stat(5)", MAN7 + "man5/proc_pid_stat.5.html", "reference"),
        Link("proc_stat(5)", MAN7 + "man5/proc_stat.5.html", "reference"),
        Link("tcp(7)", MAN7 + "man7/tcp.7.html", "reference"),
        Link("udp(7)", MAN7 + "man7/udp.7.html", "reference"),
        Link("sock_diag(7)", MAN7 + "man7/sock_diag.7.html", "reference"),
        Link("ss(8)", MAN7 + "man8/ss.8.html", "tool"),
        Link("WSL's networking: localhost, NAT and mirrored", WSL_NETWORKING, "guide"),
    ),
    areas=(
        Area("The TCP tables", "/proc/net/tcp and tcp6: every TCP socket, its two ends, its state, its timer, its user "
             "and its inode", KERNEL_DOCS,
             covered=("every TCP socket, listening, connected or closing: the Netstat tab's connections and listening "
                      "ports, and the hosts database's connections")),
        Area("The UDP tables", "/proc/net/udp and udp6: every UDP socket, bound, or connected with its peer",
             MAN7 + "man5/proc_pid_net.5.html",
             covered="every UDP socket: bound ones as listening ports, connected ones with their peers as connections"),
        Area("A process's descriptors", "/proc/<pid>/fd: each descriptor a link, socket:[<inode>] for a socket",
             MAN7 + "man5/proc_pid_fd.5.html",
             covered="the platform's user's own processes walked for the sockets of their own, once a reading"),
        Area("A process's facts", "/proc/<pid>/comm, exe, cgroup and stat: its name, its file, its service, its start",
             MAN7 + "man5/proc_pid_stat.5.html",
             covered="the program behind each socket of one's own, where it is on disk, its systemd unit, its start"),
        Area("The system's start", "/proc/stat's btime: when this Linux started", MAN7 + "man5/proc_stat.5.html",
             covered="a process's start in seconds since 1970 (stat's field 22 is in ticks after it)"),
        Area("Socket diagnostics (sock_diag)", ("the netlink interface ss speaks: every socket with its uid, inode, "
             "bytes each way and, from about Linux 5.8, its cgroup"), MAN7 + "man7/sock_diag.7.html"),
        Area("Connection tracking's times", "conntrack's timestamps: when a connection began (root, and a sysctl)",
             MAN7 + "man5/proc_pid_net.5.html"),
        Area("Other socket tables", "/proc/net's raw, unix, packet and netlink tables",
             MAN7 + "man5/proc_pid_net.5.html"),
    ),
    calls=(
        Call("read /proc/net/tcp", "every IPv4 TCP socket", "The TCP tables", used="each reading", docs=KERNEL_DOCS),
        Call("read /proc/net/tcp6", "every IPv6 TCP socket (an IPv4 peer of a dual-stack socket among them)",
             "The TCP tables", used="each reading", docs=KERNEL_DOCS),
        Call("read /proc/net/udp", "every IPv4 UDP socket", "The UDP tables", used="each reading",
             docs=MAN7 + "man5/proc_pid_net.5.html"),
        Call("read /proc/net/udp6", "every IPv6 UDP socket", "The UDP tables", used="each reading",
             docs=MAN7 + "man5/proc_pid_net.5.html"),
        Call("readlink /proc/<pid>/fd/<fd>", "what a descriptor is: socket:[<inode>] for a socket",
             "A process's descriptors", used="one walk a reading, only while a socket of one's own is not known yet",
             docs=MAN7 + "man5/proc_pid_fd.5.html"),
        Call("read /proc/<pid>/comm", "a process's program name", "A process's facts", used="each holder found, once",
             docs=MAN7 + "man5/proc_pid_comm.5.html"),
        Call("readlink /proc/<pid>/exe", "where a process's program is on disk", "A process's facts",
             used="each holder found, once", docs=MAN7 + "man5/proc_pid_exe.5.html"),
        Call("read /proc/<pid>/cgroup", "the control group a process runs in (its systemd unit)", "A process's facts",
             used="each holder found, once: the service behind a socket", docs=MAN7 + "man5/proc_pid_cgroup.5.html"),
        Call("read /proc/<pid>/stat", "a process's state; field 22 its start", "A process's facts",
             used="each holder found, once: when its program started", docs=MAN7 + "man5/proc_pid_stat.5.html"),
        Call("read /proc/stat", "the system's counters; btime its start", "The system's start",
             used="once a walk that found a holder", docs=MAN7 + "man5/proc_stat.5.html"),
        Call("socket(AF_NETLINK, SOCK_DGRAM, NETLINK_SOCK_DIAG)", "the socket diagnostics' netlink socket",
             "Socket diagnostics (sock_diag)", docs=MAN7 + "man7/sock_diag.7.html"),
        Call("ss -tunap", "every TCP and UDP socket with its programs, through sock_diag",
             "Socket diagnostics (sock_diag)", docs=MAN7 + "man8/ss.8.html"),
    ),
    verified=NETSTAT_VERIFIED,
)

OVERPASS_API = Api(
    name="Overpass API",
    maker="the Overpass API's makers (Roland Olbricht), its public server run for OpenStreetMap's community",
    about=("Overpass answers queries of OpenStreetMap's data: every feature with the tags asked, with its point or its "
           "line. The globe's internet infrastructure asks it once a data set, on your click, after you accept "
           "OpenStreetMap's licence (ODbL 1.0): its data centres and exchange points, its submarine cables and their "
           "landing stations, its telecom lines on land (those on power poles left out). Each query asks for tags and "
           "places alone and says nothing "
           "about this machine or its traffic; the request carries the plugin's name and version as its User-Agent, "
           "nothing of yours. The answer is read on this machine, its points and lines kept in the data folder's "
           "infrastructure/ in place of an older copy, and the download itself is not kept. Its public servers are "
           "volunteers', busy at times (a 429 or a 504 is asked once more a minute later, then said), and their rules "
           "frown on apps leaning on them: nothing is asked by itself, and a data set is asked again only on your "
           "click. What volunteers mapped is incomplete in places."),
    kind="query",
    base=OVERPASS,
    version="Overpass API 0.7, its query language Overpass QL, answering in JSON",
    auth="none: no account and no key",
    limits=("about 10,000 requests and 1 GB of downloads a day for one user, by the public server's own rules; each "
            "query's own time limit ([timeout:180], [timeout:300]); busy at times"),
    costs="",
    links=(
        Link("Overpass API", OSM_WIKI + "Overpass_API", "docs"),
        Link("Overpass QL", OSM_WIKI + "Overpass_API/Overpass_QL", "reference"),
        Link("The Overpass API's manual", OVERPASS_DOC, "guide"),
        Link("Commons: the public servers' rules", OVERPASS_DOC + "preface/commons.html", "limits"),
        Link("The public server's own page", "https://overpass-api.de/", "docs"),
        Link("Tag: telecom=data_center", OSM_WIKI + "Tag:telecom%3Ddata_center", "reference"),
        Link("Tag: seamark:type=cable_submarine", OSM_WIKI + "Tag:seamark:type%3Dcable_submarine", "reference"),
        Link("Tag: telecom=cable_landing_station", OSM_WIKI + "Tag:telecom%3Dcable_landing_station", "reference"),
        Link("Key: communication", OSM_WIKI + "Key:communication", "reference"),
        Link("Telecoms", OSM_WIKI + "Telecoms", "guide"),
        Link("OpenStreetMap's copyright and licence", "https://www.openstreetmap.org/copyright", "terms"),
        Link("The Open Database License 1.0", "https://opendatacommons.org/licenses/odbl/1-0/", "terms"),
        Link("Attribution guidelines", "https://osmfoundation.org/wiki/Licence/Attribution_Guidelines", "terms"),
    ),
    areas=(
        Area("Queries", "the interpreter: Overpass QL's queries of OpenStreetMap's features by their tags",
             OSM_WIKI + "Overpass_API/Overpass_QL",
             covered=("three queries of tags, one a data set, asked on your click: data centres (telecom=data_center, "
                      "building=data_center) and exchange points (telecom=internet_exchange); submarine cables "
                      "(seamark:type=cable_submarine of the telecom categories: optical, fibre_optic and fiber_optic, "
                      "telephone, telegraph and their kin; communication=line under water) and landing stations "
                      "(telecom=cable_landing_station); telecom lines on land, those on power poles (power=*) left "
                      "out")),
        Area("JSON output", "[out:json]: each element with its tags, a centre point or a line's geometry",
             OSM_WIKI + "Overpass_API/Overpass_QL",
             covered="read on this machine: the points and lines kept, thinned and bounded, in the data folder"),
        Area("The server's status", "/api/status: the slots a client has now and when the next one frees",
             OVERPASS_DOC + "preface/commons.html"),
        Area("Other outputs", "XML, CSV and the counts of what a query finds", OSM_WIKI + "Overpass_API/Overpass_QL"),
        Area("Changes over time", "a query of the data as it was at a date, or of what changed between two",
             OSM_WIKI + "Overpass_API/Overpass_QL"),
    ),
    calls=(
        Call("GET /api/interpreter?data=<query>", "the features a query asks for", "Queries",
             used=("Download… on the World Wide Web tab's Internet infrastructure table, once a data set, on your "
                   "word once its licence is accepted, as a job the page may cancel; https on every hop, to this host "
                   "alone"),
             docs=OSM_WIKI + "Overpass_API"),
        Call("POST /api/interpreter", "the same query in the request's body", "Queries",
             docs=OSM_WIKI + "Overpass_API"),
        Call("GET /api/status", "this client's slots now", "The server's status",
             docs=OVERPASS_DOC + "preface/commons.html"),
    ),
    verified=NETSTAT_VERIFIED,
)

WIKIDATA = Api(
    name="Wikidata Query Service",
    maker="the Wikimedia Foundation",
    about=("Wikidata's SPARQL endpoint answers queries of its structured data. The globe asks it once, on your click: "
           "the internet exchange points, data centres (of every kind: colocation centres among them), ground stations "
           "and teleports Wikidata places (by their own coordinates, else their seat's or their place's), with their "
           "names and operators in English. Its data is "
           "in the public domain (CC0): no credit is required, and the globe names Wikidata all the same. The query "
           "says nothing about this machine; the request's User-Agent is the plugin's name and version alone, and a "
           "refusal for want of a contact in it is said in words (none is sent from here)."),
    kind="query",
    base=WDQS,
    version="SPARQL 1.1, its results as JSON (format=json)",
    auth="none: no account and no key",
    limits=("a hard deadline of 60 s a query; one client (its User-Agent and address) 60 s of processing time a "
            "minute and 30 queries in error a minute; a client without a good User-Agent may be blocked"),
    costs="",
    links=(
        Link("Wikidata Query Service: the user manual", WDQS_MANUAL, "docs"),
        Link("Wikidata's SPARQL query service", "https://www.wikidata.org/wiki/Wikidata:SPARQL_query_service", "guide"),
        Link("Query limits", "https://www.wikidata.org/wiki/Wikidata:SPARQL_query_service/query_limits", "limits"),
        Link("Wikidata's licensing", "https://www.wikidata.org/wiki/Wikidata:Licensing", "terms"),
        Link("The User-Agent policy",
             "https://foundation.wikimedia.org/wiki/Policy:Wikimedia_Foundation_User-Agent_Policy", "terms"),
        Link("SPARQL 1.1 Query Language", "https://www.w3.org/TR/sparql11-query/", "spec"),
        Link("The query service", "https://query.wikidata.org/", "console"),
        Link("Creative Commons Zero", "https://creativecommons.org/publicdomain/zero/1.0/", "terms"),
    ),
    areas=(
        Area("SPARQL queries", "Wikidata's items and statements asked with SPARQL, answered as JSON",
             "https://www.mediawiki.org/wiki/Wikidata_Query_Service/User_Manual",
             covered=("one query, on your click: items that are internet exchange points (Q1433061), data centres "
                      "(Q671224, and its subclasses through P279*), ground stations (Q1349167) or teleports "
                      "(Q10379228), each with its coordinates, its label and its operator's")),
        Area("Labels", "the label service: an item's name in the languages asked",
             "https://www.mediawiki.org/wiki/Wikidata_Query_Service/User_Manual", covered="names in English"),
        Area("The entity data", "an item's whole record as JSON, by its id",
             "https://www.mediawiki.org/wiki/Wikidata_Query_Service/User_Manual"),
        Area("Federated queries", "SERVICE clauses asking other SPARQL endpoints",
             "https://www.mediawiki.org/wiki/Wikidata_Query_Service/User_Manual"),
    ),
    calls=(
        Call("GET /sparql?format=json&query=<query>", "a query's results as JSON", "SPARQL queries",
             used=("Download… on the World Wide Web tab's Internet infrastructure table, once, on your word once its "
                   "licence is accepted, as a job the page may cancel; https on every hop, to this host alone"),
             docs="https://www.mediawiki.org/wiki/Wikidata_Query_Service/User_Manual"),
        Call("POST /sparql", "the same query in the request's body", "SPARQL queries",
             docs="https://www.mediawiki.org/wiki/Wikidata_Query_Service/User_Manual"),
        Call("GET https://www.wikidata.org/wiki/Special:EntityData/<id>.json", "one item's whole record",
             "The entity data", docs="https://www.mediawiki.org/wiki/Wikidata_Query_Service/User_Manual"),
    ),
    verified=NETSTAT_VERIFIED,
)

EMODNET = Api(
    name="EMODnet Human Activities (WFS)",
    maker="EMODnet, the European Commission's marine data network (its data originator Cogea Srl)",
    about=("EMODnet Human Activities serves its layers through a GeoServer WFS. The globe asks it once, on your click, "
           "after you accept its licence (CC BY 4.0): the telecom cables' actual routes in European waters, and "
           "French cables beyond, from six national sources (Germany's BSH, Spain's CICA, France's SHOM and SIGCables, "
           "Malta's IOI-MOC, the United Kingdom's OGA), as GeoJSON, longitude first. The request names its six "
           "layers and nothing about this machine; the answer is read here, its lines kept thinned in the data "
           "folder's infrastructure/, and credited as its record asks wherever they are drawn. Its power cables are "
           "not asked for."),
    kind="query",
    base=EMODNET_WFS,
    version="WFS 1.1.0 (its server offers 1.0.0 to 2.0.0), GetFeature answered as GeoJSON (application/json)",
    auth="none: no account and no key",
    limits="none named (its capabilities: Fees NONE, AccessConstraints NONE); served through Cloudflare",
    costs="",
    links=(
        Link("The cables' record (Cables, Telecommunication, Actual Routes)", EMODNET_RECORD, "docs"),
        Link("The WFS's capabilities", EMODNET_WFS + "?service=WFS&request=GetCapabilities", "reference"),
        Link("EMODnet Human Activities", "https://emodnet.ec.europa.eu/en/human-activities", "guide"),
        Link("The EMODnet portal", "https://emodnet.ec.europa.eu/en/", "docs"),
        Link("GeoServer's WFS", GEOSERVER_WFS, "reference"),
        Link("GeoServer's WFS: axis order", GEOSERVER_WFS + "axis_order/", "reference"),
        Link("GeoServer's WFS: output formats", GEOSERVER_WFS + "outputformats/", "reference"),
        Link("GeoServer's WFS reference", GEOSERVER_WFS + "reference/", "reference"),
        Link("Creative Commons Attribution 4.0 International", "https://creativecommons.org/licenses/by/4.0/", "terms"),
    ),
    areas=(
        Area("Features (GetFeature)", "a layer's features, in the output format and the axis order asked",
             GEOSERVER_WFS + "reference/",
             covered=("the six telecom cable layers in one request, as GeoJSON with srsName=EPSG:4326 (longitude "
                      "first), on your click: their LineString and MultiLineString parts drawn as cables")),
        Area("Capabilities", "what the service offers: its layers, their coordinates, its output formats",
             EMODNET_WFS + "?service=WFS&request=GetCapabilities"),
        Area("A layer's schema (DescribeFeatureType)", "a layer's properties and their types",
             GEOSERVER_WFS + "reference/"),
        Area("The maps (WMS)", "the same layers drawn as images", "https://emodnet.ec.europa.eu/en/human-activities"),
        Area("The record's files", "the routes as a shapefile and a geodatabase in one zip", EMODNET_RECORD),
        Area("The power cables", "the three power cable layers beside the telecom ones", EMODNET_RECORD),
    ),
    calls=(
        Call("GET /geoserver/emodnet/wfs?service=WFS&version=1.1.0&request=GetFeature&typeName=<layers>"
             "&outputFormat=application/json&srsName=EPSG:4326", "the layers' features as GeoJSON, longitude first",
             "Features (GetFeature)",
             used=("Download… on the World Wide Web tab's Internet infrastructure table, once, on your word once its "
                   "licence is accepted, as a job the page may cancel; https on every hop, to this host alone"),
             docs=GEOSERVER_WFS + "reference/"),
        Call("GET /geoserver/emodnet/wfs?service=WFS&request=GetCapabilities", "the service's capabilities",
             "Capabilities", docs=GEOSERVER_WFS + "reference/"),
        Call("GET /geoserver/emodnet/wfs?service=WFS&request=DescribeFeatureType&typeName=<layer>",
             "a layer's schema", "A layer's schema (DescribeFeatureType)", docs=GEOSERVER_WFS + "reference/"),
    ),
    verified=NETSTAT_VERIFIED,
)

TOPOLOGY_ZOO = Api(
    name="Internet Topology Zoo",
    maker="Adelaide University (S. Knight, H. Nguyen, N. Falkner, R. Bowden, M. Roughan), its repository on GitHub",
    about=("261 maps of networks' backbones (some networks mapped in several years), transcribed from the operators' "
           "own public maps of about 2010 and 2011: "
           "research and education networks (GÉANT, Internet2, ESnet, RENATER, NORDUnet and more) and carriers "
           "(Sprint, UUNET, Cogent, NTT, Hurricane Electric and more), each with its points of presence, their places "
           "(at their cities) and the links between them, kept as a long-term store and not updated. The globe asks "
           "for its archive of GML maps once, on your click, after you accept its licence (CC BY 4.0), unpacks it in "
           "memory alone (nothing of it is written out but what is drawn), and draws each network's newest map as "
           "backbones and their points of presence: logical links between cities, not the routes of fibre, and not "
           "today's networks. The request names the file alone and nothing about this machine."),
    kind="feed",
    base=ZOO_GML,
    version=("its repository's main branch as read on 2026-11-19: gml.tar.gz, 348,613 bytes, one GML file a map "
             "(the maps' own dates about 2010 and 2011, older ones of some networks beside them)"),
    auth="none: no account and no key",
    limits="none named for one file; asked once on your click, waited for 60 s",
    costs="",
    links=(
        Link("The Internet Topology Zoo's repository", ZOO_REPO, "docs"),
        Link("Its licence: CC BY 4.0", ZOO_RAW + "LICENSE", "terms"),
        Link("Adelaide University's record (Research Data Australia)", ZOO_RECORD, "reference"),
        Link("The data set's DOI", ZOO_DOI, "reference"),
        Link("Its points of presence, as Netzschleuder keeps them", NETZSCHLEUDER, "reference"),
        Link("Creative Commons Attribution 4.0 International", "https://creativecommons.org/licenses/by/4.0/", "terms"),
    ),
    areas=(
        Area("The maps in GML", "every network's map in GML, one gzipped tar archive", ZOO_REPO,
             covered=("the archive, asked once on your click and unpacked in memory alone: of each network its newest "
                      "map, from 2000 on, its own points of presence with a place and the links between them")),
        Area("The maps in GraphML", "the same maps in GraphML (XML), in an archive of their own", ZOO_REPO),
        Area("One network's file", "a network's map alone, by its name, in GML or GraphML", ZOO_REPO),
        Area("The records", "the data set's record at Research Data Australia and its DOI at figshare", ZOO_RECORD),
    ),
    calls=(
        Call(f"GET {ZOO_GML}", "every network's map in GML, one gzipped tar archive", "The maps in GML",
             used=("Download… on the World Wide Web tab's Internet infrastructure table, once, on your word once its "
                   "licence is accepted, as a job the page may cancel; https on every hop, to this host alone"),
             docs=ZOO_REPO),
        Call(f"GET {ZOO_RAW}graphml.tar.gz", "every network's map in GraphML, one gzipped tar archive",
             "The maps in GraphML", docs=ZOO_REPO),
        Call(f"GET {ZOO_RAW}graphml/<network>.graphml", "one network's map in GraphML", "One network's file",
             docs=ZOO_REPO),
    ),
    verified=GLOBE_VERIFIED,
)

# liminal-libs 1.73.0: the sources of what routers' names are read with (the library's machines/names.py)
ROUTERS_VERIFIED = "2026-11-22"  # the two cards' pages, read on 2026-11-22
OURAIRPORTS_API = Api(
    name="OurAirports",
    maker="OurAirports (David Megginson and its contributors), its data mirrored on GitHub",
    about=("OurAirports keeps the world's airports, each with its codes, its place, its town and its country, and "
           "releases all of it to the public domain. The globe asks for its airports file once, on your click: each "
           "large or medium airport with a three-letter code is kept as a point of the airports layer, and routers' "
           "names are read with the codes (sea, fra) to place each router at its airport's town where the trace's "
           "time allows it. The request names the file alone and nothing about this machine."),
    kind="feed",
    base=OURAIRPORTS_CSV,
    version="airports.csv as its mirror served it on 2026-11-22: 12.2 MB, one row an airport, its codes among them",
    auth="none: no account and no key",
    limits="none named for one file; asked once on your click, waited for 180 s",
    costs="",
    links=(
        Link("OurAirports' data", "https://ourairports.com/data/", "docs"),
        Link("Its data's mirror on GitHub", "https://github.com/davidmegginson/ourairports-data", "reference"),
    ),
    areas=(
        Area("The airports", "every airport, heliport and seaplane base it knows, one CSV file",
             "https://ourairports.com/data/",
             covered="the file, asked once on your click: the large and medium airports with a three-letter code"),
        Area("The rest", "runways, frequencies, navigation aids, countries and regions, a file each",
             "https://ourairports.com/data/"),
    ),
    calls=(
        Call(f"GET {OURAIRPORTS_CSV}", "every airport it knows, one CSV file", "The airports",
             used=("Download… on the World Wide Web tab's Internet infrastructure table, once, on your word, as a job "
                   "the page may cancel; https on every hop, to this host alone"),
             docs="https://ourairports.com/data/"),
    ),
    verified=ROUTERS_VERIFIED,
)

GEONAMES_API = Api(
    name="GeoNames",
    maker="GeoNames (geonames.org)",
    about=("GeoNames keeps the world's places, free under CC BY 4.0, and offers them as files by kind and size. The "
           "globe asks for its file of the cities of 15,000 people or more once, on your click: each is kept as a "
           "point of the cities layer, the most people first (20,000 of them), named on the globe as it comes nearer, "
           "and routers' names are read with them (a city's name, or a city and its state as sttlwa). The request "
           "names the file alone and nothing about this machine."),
    kind="feed",
    base=GEONAMES_CITIES,
    version="cities15000.zip as served on 2026-11-22: 3.2 MB, one text file, one tab-separated row a city",
    auth="none: no account and no key (its web services need one; its files do not)",
    limits="none named for its files; asked once on your click, waited for 120 s",
    costs="",
    links=(
        Link("GeoNames' files", "https://download.geonames.org/export/dump/", "docs"),
        Link("Its licence: CC BY 4.0", "https://creativecommons.org/licenses/by/4.0/", "terms"),
    ),
    areas=(
        Area("The cities", "the cities of 15,000 people or more, one zipped text file",
             "https://download.geonames.org/export/dump/",
             covered="the file, asked once on your click: every city in it, the most people first"),
        Area("Its other files", "all its places, by country, and the smaller towns' files",
             "https://download.geonames.org/export/dump/"),
        Area("Its web services", "searches and lookups, with an account", "https://www.geonames.org/export/"),
    ),
    calls=(
        Call(f"GET {GEONAMES_CITIES}", "the cities of 15,000 people or more", "The cities",
             used=("Download… on the World Wide Web tab's Internet infrastructure table, once, on your word, as a job "
                   "the page may cancel; https on every hop, to this host alone"),
             docs="https://download.geonames.org/export/dump/"),
    ),
    verified=ROUTERS_VERIFIED,
)

# liminal-libs 1.104.0: the cards of the globe's newer sources (GLOBE2_SETS above), their pages read on 2026-11-26
NATURAL_EARTH_API = Api(
    name="Natural Earth (1:10m roads and railways)",
    maker="Natural Earth (NACIS and its volunteers)",
    about=("A public domain map of the world at three scales. The globe asks for two of its 1:10m files once each, on "
           "your click: the major roads and the railways, each a zipped ESRI shapefile read in memory by the library "
           "(its shapefile reader: longitude and latitude in WGS 84 alone), ferries left out, a vertex kept every 0.05 "
           "degrees. They are drawn dashed, as a stand-in for fibre where none is mapped: a route found along them "
           "alone says so, and one along real fibre, cables or backbones is preferred wherever one is near enough."),
    kind="feed",
    base=NATURAL_EARTH_DOWNLOAD,
    version=("ne_10m_roads.zip 5.0.0 (8.66 MB) and ne_10m_railroads.zip 4.0.0 (14.42 MB), as their pages said on "
             "2026-11-26; each link sends the file on to naciscdn.org, Natural Earth's own CDN"),
    auth="none: no account and no key",
    limits="none named; asked once a file on your click, the one redirect to naciscdn.org followed and no other",
    costs="",
    links=(
        Link("Natural Earth's 1:10m cultural vectors", NATURAL_EARTH_SITE + "downloads/10m-cultural-vectors/", "docs"),
        Link("Roads", NATURAL_EARTH_SITE + "downloads/10m-cultural-vectors/roads/", "reference"),
        Link("Railroads", NATURAL_EARTH_SITE + "downloads/10m-cultural-vectors/railroads/", "reference"),
        Link("Its terms of use (public domain)", NATURAL_EARTH_SITE + "about/terms-of-use/", "terms"),
    ),
    areas=(
        Area("Roads", "the world's major roads at 1:10m, with their kind, class and number", NATURAL_EARTH_SITE
             + "downloads/10m-cultural-vectors/roads/",
             covered="every road but the ferries (featurecla Ferry), as the roads layer"),
        Area("Railroads", "the world's railways at 1:10m", NATURAL_EARTH_SITE
             + "downloads/10m-cultural-vectors/railroads/",
             covered="every railway but the train ferries, as the railways layer"),
        Area("North America's roads", "a denser file of North America's roads (45.6 MB)", NATURAL_EARTH_SITE
             + "downloads/10m-cultural-vectors/roads/"),
        Area("The rest of its map", "countries, places, rivers, relief and more, at 1:10m, 1:50m and 1:110m",
             NATURAL_EARTH_SITE + "downloads/"),
    ),
    calls=(
        Call("GET " + NATURAL_EARTH_DOWNLOAD + "<file>.zip", "a zipped shapefile, sent on to naciscdn.org", "Roads",
             used=("Download… and Update… on the World Wide Web tab's Internet infrastructure table, run by the "
                   "platform as a job: one GET a file, https on every hop, its one redirect to naciscdn.org alone"),
             docs=NATURAL_EARTH_SITE + "downloads/10m-cultural-vectors/roads/"),
    ),
    verified=VERIFIED_GLOBE2,
)

AFTERFIBRE_API = Api(
    name="AfTerFibre (NSRC)",
    maker="the Network Startup Resource Center (NSRC), its map now at opentelecomdata.org",
    about=("AfTerFibre maps Africa's terrestrial fibre, live and planned, from its operators' and contributors' "
           "reports. Its site no longer offers a file: its fibre is served only as its map's vector tiles (Mapbox "
           "Vector Tiles), so the globe asks for the 56 tiles that cover Africa at zoom 5, one after another on your "
           "one click, and reads them in memory (the library's tile reader). Of each route only who runs it, whose it "
           "is, whether it is lit and its country are kept: its contributors' names and e-mail addresses, in every "
           "tile, are never decoded or kept. Its undersea layer is TeleGeography's and is never asked for."),
    kind="feed",
    base=AFTERFIBRE_TILES,
    version="its map's tiles (layer fiber, zooms 2 to 14) as its TileJSON gave them on 2026-11-26",
    auth="none: no account and no key; CC BY 4.0 accepted on the page before a download",
    limits="none named; 56 tiles asked one after another on your click, 2 MB a tile and 128 tiles at most",
    costs="",
    links=(
        Link("AfTerFibre's map", AFTERFIBRE_SITE, "docs"),
        Link("Its tiles' description (TileJSON)", "https://d316kar6yg8hyq.cloudfront.net/africa-fiber.json",
             "reference"),
        Link("The Mapbox Vector Tile specification", "https://github.com/mapbox/vector-tile-spec", "spec"),
        Link("CC BY 4.0", "https://creativecommons.org/licenses/by/4.0/", "terms"),
    ),
    areas=(
        Area("Fibre on land", "Africa's terrestrial fibre routes, live and planned, by operator and country",
             AFTERFIBRE_SITE, covered="the fiber layer at zoom 5: who runs a route, whose it is, lit or not, country"),
        Area("Its finer zooms", "the same routes drawn closer, at zooms 6 to 14", AFTERFIBRE_SITE),
        Area("Its undersea layer", "submarine cables, another maker's (TeleGeography): not asked for", AFTERFIBRE_SITE),
    ),
    calls=(
        Call("GET https://d316kar6yg8hyq.cloudfront.net/africa-fiber/5/<x>/<y>.mvt", "one map tile of the fibre",
             "Fibre on land",
             used=("Download… and Update… on the World Wide Web tab's Internet infrastructure table, run by the "
                   "platform as a job: the 56 tiles one after another, https, from d316kar6yg8hyq.cloudfront.net "
                   "alone; a missing tile is an empty one, any other failure stops it with nothing kept"),
             docs="https://github.com/mapbox/vector-tile-spec"),
    ),
    verified=VERIFIED_GLOBE2,
)

TOPOHUB_API = Api(
    name="TopoHub (GitHub)",
    maker="Piotr Jurkiewicz (AGH University of Krakow); its repository on GitHub",
    about=("A collection of network topologies, among them a model of the world's backbones: its cities, the land "
           "links between them and the submarine cables' landing points and links, each link with its length. The "
           "globe asks for its world file once, on your click (1.04 MB), draws its links as the backbone model layer "
           "and gives its cities and links to the composite database as evidence of a model, the weakest kind: a "
           "model, not an operator's map."),
    kind="feed",
    base=TOPOHUB_WORLD,
    version="its master branch as read on 2026-11-26: data/backbone/world.json, networkx node-link JSON",
    auth="none: no account and no key",
    limits="none named for one file; asked once on your click, waited for 60 s",
    costs="",
    links=(
        Link("TopoHub's repository", TOPOHUB_REPO, "docs"),
        Link("Its backbone models", TOPOHUB_REPO + "/tree/master/data/backbone", "reference"),
        Link("Its licence (MIT)", TOPOHUB_REPO + "/blob/master/LICENSE", "terms"),
    ),
    areas=(
        Area("The world's backbone model", "cities, landing points and the links between them, with their lengths",
             TOPOHUB_REPO + "/tree/master/data/backbone",
             covered="world.json: each node with a place, each link between two of them, seacable or land"),
        Area("Its regions", "the same model by region, each also without its submarine cables",
             TOPOHUB_REPO + "/tree/master/data/backbone"),
        Area("Its other topologies", "networks of CAIDA, SNDlib, the Topology Zoo and Gabriel graphs", TOPOHUB_REPO),
    ),
    calls=(
        Call("GET " + TOPOHUB_WORLD, "the world's backbone model", "The world's backbone model",
             used=("Download… and Update… on the World Wide Web tab's Internet infrastructure table, run by the "
                   "platform as a job: one GET, https on every hop, from raw.githubusercontent.com alone"),
             docs=TOPOHUB_REPO),
    ),
    verified=VERIFIED_GLOBE2,
)

RIPE_ATLAS = Api(
    name="RIPE Atlas",
    maker="the RIPE NCC",
    about=("The RIPE NCC's network of probes and anchors that measure the internet. The globe asks for two things, "
           "each on your click: the archive of every probe and anchor (its place, country and networks), drawn as the "
           "probes layer; then, with it, the newest result of the built-in IPv4 traceroute (measurement 5151) of each "
           "anchor, 300 anchors a request: a router answering within a millisecond of its anchor is placed at the "
           "anchor, and each two answering hops in a row are a link, both given to the composite database. Private "
           "addresses and this machine's own are never kept."),
    kind="rest",
    base="https://atlas.ripe.net/api/v2/",
    version="its REST API v2 and its probes archive's meta-latest, as read on 2026-11-26",
    auth="none for public measurements' results and the probes archive: no account and no key",
    limits=("its terms (3.5): commercial use needs the RIPE NCC's permission (art. 4.5), its databases passed on only "
            "with its written authorisation (art. 10.2); its latest results are cached for 5 minutes. Asked once on "
            "your click: the archive in one request, the anchors' results about 3 requests"),
    costs="",
    links=(
        Link("RIPE Atlas's documentation", "https://atlas.ripe.net/docs/", "docs"),
        Link("Its probes archive", "https://ftp.ripe.net/ripe/atlas/probes/archive/", "reference"),
        Link("The built-in traceroute, IPv4 (5151)", "https://atlas.ripe.net/measurements/5151/", "reference"),
        Link("The built-in traceroute, IPv6 (6152)", "https://atlas.ripe.net/measurements/6152/", "reference"),
        Link("Its terms and conditions", "https://atlas.ripe.net/legal/", "terms"),
    ),
    areas=(
        Area("Probes and anchors", "every probe's and anchor's place, country, networks and status, daily",
             "https://ftp.ripe.net/ripe/atlas/probes/archive/",
             covered="meta-latest: each one's id, place, country, networks, whether an anchor, its status"),
        Area("Latest results", "a measurement's newest result from each probe asked",
             "https://atlas.ripe.net/docs/",
             covered="measurement 5151's, the anchors' alone, 300 a request"),
        Area("The daily dumps", "every public result of a day, about 72 GB: not asked for",
             "https://atlas.ripe.net/docs/"),
        Area("Measurements of one's own", "traceroutes and pings asked of probes, with an account and credits",
             "https://atlas.ripe.net/docs/"),
    ),
    calls=(
        Call("GET " + ATLAS_PROBES, "every probe and anchor, bzip2 JSON", "Probes and anchors",
             used=("Download… on the World Wide Web tab's Internet infrastructure table, run by the platform as a "
                   "job: one GET, https, from ftp.ripe.net alone"),
             docs="https://ftp.ripe.net/ripe/atlas/probes/archive/"),
        Call("GET " + ATLAS_LATEST + "?format=json&probe_ids=<300 anchors>", "the anchors' newest traceroutes",
             "Latest results",
             used=("Download… on the World Wide Web tab once the probes are in, run by the platform as a job: about "
                   "3 GETs one after another, https, from atlas.ripe.net alone"),
             docs="https://atlas.ripe.net/docs/"),
    ),
    verified=VERIFIED_GLOBE2,
)

CELESTRAK_API = Api(
    name="CelesTrak (GP orbits)",
    maker="CelesTrak (T.S. Kelso); orbits from the US Space Force's 18th Space Defense Squadron",
    about=("CelesTrak publishes every tracked satellite's general perturbations elements, by group or by catalogue "
           "number. The globe asks for three constellations' orbits, each on your click: Starlink's and OneWeb's "
           "groups, and HughesNet's three geostationary satellites by their numbers (one request each), as CSV, "
           "compressed. They are kept in the plugin's own database and placed with the sgp4 package, each satellite's "
           "footprint the ground that sees it 25 degrees above the horizon or more, all of a constellation's drawn as "
           "one area in its own colour."),
    kind="feed",
    base=CELESTRAK_GP,
    version="its GP data (CSV, the OMM fields) as its formats page gave it on 2026-11-26",
    auth="none: no account and no key",
    limits=("its usage policy: once an update at most (every 2 hours), compressed, only an OK answer used, any other "
            "stops the download and is said to you, nothing after a 500 or 503 for 15 minutes, and more than 50 "
            "errors in 2 hours blocks the address. Asked only on your click, never again by itself, Update… not "
            "offered before 2 hours"),
    costs="",
    links=(
        Link("GP data formats", "https://celestrak.org/NORAD/documentation/gp-data-formats.php", "docs"),
        Link("Current GP element sets", "https://celestrak.org/NORAD/elements/", "reference"),
        Link("Its usage policy", "https://celestrak.org/usage-policy.php", "limits"),
    ),
    areas=(
        Area("Groups", "every satellite of a group (starlink, oneweb, ...)",
             "https://celestrak.org/NORAD/documentation/gp-data-formats.php",
             covered="GROUP=starlink and GROUP=oneweb, as CSV"),
        Area("Catalogue numbers", "one satellite by its number (CATNR)",
             "https://celestrak.org/NORAD/documentation/gp-data-formats.php",
             covered="CATNR=38551, 41893 and 57479: EchoStar XVII, XIX and XXIV, HughesNet's"),
        Area("Other formats", "TLE, XML, KVN and JSON", "https://celestrak.org/NORAD/documentation/gp-data-formats.php"),
        Area("The satellite catalogue", "every object's launch, owner and status (SATCAT)",
             "https://celestrak.org/satcat/"),
    ),
    calls=(
        Call("GET " + CELESTRAK_GP + "?GROUP=<group>&FORMAT=csv", "a group's orbits as CSV", "Groups",
             used=("Download… and Update… on the World Wide Web tab's Internet infrastructure table, run by the "
                   "platform as a job: one GET a constellation, gzip asked, https, from celestrak.org alone"),
             docs="https://celestrak.org/NORAD/documentation/gp-data-formats.php"),
        Call("GET " + CELESTRAK_GP + "?CATNR=<number>&FORMAT=csv", "one satellite's orbit as CSV",
             "Catalogue numbers",
             used="HughesNet's three, on the World Wide Web tab, one after another on the one click",
             docs="https://celestrak.org/NORAD/documentation/gp-data-formats.php"),
    ),
    verified=VERIFIED_GLOBE2,
)

SGP4_API = Api(
    name="sgp4 (PyPI)",
    maker="Brandon Rhodes, on PyPI",
    about=("The SGP4 orbit propagator for Python: from a satellite's published elements, where it is at a given "
           "moment. The globe places the satellites with it, and with nothing else: it is offered on the World Wide "
           "Web tab beside the data sets, its size, sha256 and licence said first, downloaded on your click, every file "
           "checked against the wheel's RECORD, unpacked into the data folder's packages/ and imported from there "
           "alone. Nothing is installed into Python itself. Until it is downloaded the satellites' layer says it needs "
           "it and draws nothing."),
    kind="sdk",
    base=SGP4_PYPI,
    version=f"sgp4 {SGP4_PACKAGE['version']}, {SGP4_PACKAGE['name']}, as PyPI's file list gave it on 2026-11-26",
    auth="none: no account and no key; its MIT licence accepted on the page before the download",
    limits="one file asked once on your click, its size and sha256 checked",
    costs="",
    links=(
        Link("sgp4 on PyPI", SGP4_PYPI, "docs"),
        Link("Its source", "https://github.com/brandon-rhodes/python-sgp4", "source"),
    ),
    areas=(
        Area("Propagation", "a satellite's position and velocity at a moment, from its elements (TEME)", SGP4_PYPI,
             covered="every satellite of the downloaded constellations, now and a minute later"),
        Area("OMM elements", "a satellite set up from its OMM fields, as CelesTrak's CSV gives them", SGP4_PYPI,
             covered="each kept orbit"),
        Area("Arrays", "many satellites at many moments in one call (SatrecArray)", SGP4_PYPI,
             covered="a constellation at once"),
        Area("Two-line elements", "a satellite set up from its two TLE lines, and its elements written back",
             SGP4_PYPI),
    ),
    calls=(
        Call("GET " + SGP4_PACKAGE["url"], "the package's wheel", "Propagation",
             used=("Download the sgp4 package on the World Wide Web tab, run by the platform as a job: one GET, https, "
                   "from files.pythonhosted.org alone"),
             docs=SGP4_PYPI),
    ),
    verified=VERIFIED_GLOBE2,
)

GLOBE2 = (NATURAL_EARTH_API, AFTERFIBRE_API, TOPOHUB_API, RIPE_ATLAS, CELESTRAK_API, SGP4_API)

FIREWALL = (NFTABLES, IPTABLES, EBTABLES, IPSET, FIREWALLD_API, UFW, CONNTRACK, BPF, IPROUTE2, SERVICES,  # its read
            SUDO, GROUPS, APT)  # and its changes; Root access's and nftables' install's (0.9.0)
WORLD = (CAPTURE, DBIP_LITE, OPENDNS, GOOGLE)  # the World Wide Web tab's (0.8.0)
# the Netstat tab's and the globe's infrastructure (0.9.0; the Topology Zoo's, 0.9.1)
NETSTAT = (PROCFS, OVERPASS_API, WIKIDATA, EMODNET, TOPOLOGY_ZOO,
           OURAIRPORTS_API, GEONAMES_API, *GLOBE2)  # liminal-libs 1.73.0: what routers' names are read with
APIS = FIREWALL + WORLD + NETSTAT


def ago(when: float) -> str:
    s = max(0.0, time.time() - when)
    return f"{s:.0f} s ago" if s < 90 else f"{s / 60:.0f} min ago" if s < 5400 else f"{s / 3600:.0f} h ago"


def facts(plugin) -> dict[str, dict[str, str]]:
    """What the last read found of its APIs, asking nothing (a read under way is not waited for): each tool's version
    and what it holds, the connections tracked, the programs on the network's hooks, the machine read and when; and what
    the World Wide Web tab watched and placed (world_facts)."""
    kept = getattr(plugin, "_read", None)  # (when, Config): the last read, kept READ_S
    if not kept:
        return {**rights_facts(plugin), **world_facts(plugin), **netstat_facts(plugin)}
    cfg = kept[1]
    out: dict[str, dict[str, str]] = {}
    tools = cfg.tools or {}
    sysm = cfg.system
    if cfg.nft is not None or "nft" in tools:
        tables = cfg.nft.tables if cfg.nft is not None else []
        dormant = len(cfg.dormant_tables()) if cfg.nft is not None else 0
        out[NFTABLES.name] = {"nft": cfg.nft_version or "version not read",
                              "Tables": f"{len(tables)}" + (f" ({dormant} turned off)" if dormant else "")}
    if cfg.iptables_version or cfg.saved:
        out[IPTABLES.name] = {"iptables": f"{cfg.iptables_version or '?'} ({cfg.iptables_variant or 'variant not said'})",
                              "Legacy tables loaded": ", ".join(sorted(cfg.legacy)) or "none"}
    eb, arp = cfg.ebtables, cfg.arptables
    if eb[0] or arp[0]:
        out[EBTABLES.name] = {k: f"{v} ({variant})" if variant else v for k, (v, variant) in
                              (("ebtables", eb), ("arptables", arp)) if v}
    if cfg.ipset_version or "ipset" in tools:
        out[IPSET.name] = {"ipset": cfg.ipset_version or "version not read", "Sets": str(len(cfg.ipsets))}
    f = cfg.firewalld
    if f.installed:
        out[FIREWALLD_API.name] = {"firewalld": (f.version or "version not read") + (", running" if f.running else ", stopped"),
                                   "Backend": f.backend or "not said", "Default zone": f.default_zone or "not said"}
    u = cfg.ufw
    if u.installed:
        out[UFW.name] = {"ufw": (u.version or "version not read") + (", on" if u.active else ", off")}
    count, most = sysm.conntrack
    if count is not None:
        out[CONNTRACK.name] = {"Tracked": f"{count:,} of {most:,}"}
    if "bpftool" in tools:
        out[BPF.name] = {"Programs on the network's hooks": str(len(sysm.bpf))}
    out[SERVICES.name] = {"Read": f"{sysm.name}, kernel {sysm.kernel or '?'}, {sysm.init_words}, {ago(cfg.at)}"}
    if cfg.problems:
        out[SERVICES.name]["Not read"] = "; ".join(cfg.problems)
    out.update(rights_facts(plugin))
    out.update(world_facts(plugin))
    out.update(netstat_facts(plugin))
    return out


def rights_facts(plugin) -> dict[str, dict[str, str]]:
    """How the last read had its rights (0.9.0: Root access) and what installing nftables takes, as they were kept,
    asking nothing."""
    out: dict[str, dict[str, str]] = {}
    kept = getattr(plugin, "_rights", None)  # (when, rights.Rights), with the read
    fact = getattr(kept[1], "fact", "") if kept else ""
    if fact:
        out[SUDO.name] = {"Root access": fact}
    facts = getattr(plugin, "_install_facts", None)  # (when, install.Facts), where the install is offered (0.11.0: renamed)
    words = getattr(facts[1], "words", "") if facts else ""
    if words:
        out[APT.name] = {"Installing nftables": words}
    return out


def world_facts(plugin) -> dict[str, dict[str, str]]:
    """What the World Wide Web tab watched and which GeoIP file it has open, asking nothing: nothing is started, opened
    or made to say it (WorldView.describe). Nothing is said before the tab was first shown, nor on a machine the plugin
    is not for: the tab's WorldView is the Firewall base's, made at its first ask and let go when the plugin is
    detached, and it is read here through the base's world_view(make=False) (liminal-libs 1.55.0), which never makes
    one. The GeoIP file is the one open, or the one last open once it was let go (watching stopped: "open" false)."""
    world_view = getattr(plugin, "world_view", None)
    try:
        view = world_view(make=False) if callable(world_view) else None
        d = view.describe() if view is not None else None
    except Exception:  # noqa: BLE001 - what the tab watched is extra: the cards are drawn without it
        return {}
    if not isinstance(d, dict):
        return {}
    w = d.get("watching") or {}
    if w.get("running"):
        watching = "yes" + (f", at the adapter holding {d['address']}" if d.get("address") else "")
    elif d.get("error") or w.get("error"):
        watching = f"no: {d.get('error') or w.get('error')}"
    else:
        watching = f"not now: only while the World Wide Web tab is shown, and for {float(w.get('timeout') or 0):g} s after"
    out = {CAPTURE.name: {"Watching": watching, "Packets read": f"{int(w.get('packets') or 0):,}"}}
    g = d.get("geoip")
    if g:
        file = ", ".join(x for x in (g.get("file") or "", f"built {g['date']}" if g.get("date") else "") if x)
        modes = {"mmap-ext": "memory-mapped (maxminddb's C extension)", "mmap": "memory-mapped (pure Python)"}
        mode = modes.get(g.get("mode"), "memory-mapped")
        if g.get("open", True):
            out[DBIP_LITE.name] = {"File": file or "open", "Read": mode}
        else:  # let go while nobody watches: nothing stays mapped, and the tab's next ask maps it again
            out[DBIP_LITE.name] = {"File": file or "let go",
                                   "Read": f"not now: let go while the tab is not watched, {mode} again at its next ask"}
    else:
        readable, why = geo.available()
        out[DBIP_LITE.name] = {"File": "none open" + ("" if readable else f": {why}")}
    return out


def netstat_facts(plugin) -> dict[str, dict[str, str]]:
    """What the Netstat tab, the hosts database and the globe's layers know of what they reach (0.9.0), asking nothing
    and starting nothing (NetstatView.describe: no socket table read, no login asked, nothing sent): under the socket
    tables' card the last reading (how many sockets, how long it took, when), how the hosts are recorded and what the
    hosts database holds; each data set of the globe, downloaded or not, under its source's card. The tab's view is the
    Firewall base's (liminal-libs 1.65.0), made at the plugin's attach on a machine it is for, or at the first ask of
    one of the two tabs, and let go at its detach; it is read here through the base's netstat_view(make=False), which
    never makes one: nothing is said before, on a machine the plugin is not for, nor with a library from before it.
    The Windows firewall plugin's cards say the same of its own."""
    netstat_view = getattr(plugin, "netstat_view", None)
    try:
        view = netstat_view(make=False) if callable(netstat_view) else None
        d = view.describe() if view is not None else None
    except Exception:  # noqa: BLE001 - what the tab read is extra: the cards are drawn without it
        return {}
    if not isinstance(d, dict):
        return {}
    from liminal_libs import hostbook  # there wherever there is a view (liminal-libs 1.65.0)
    from liminal_libs.machines import netstat
    from liminal_libs.machines.world import size_words

    reading = d.get("reading") or None
    if reading:
        took = max(0.0, float(reading.get("took") or 0.0)) * 1000
        last = f"{int(reading.get('rows') or 0):,} sockets in {took:,.0f} ms, {ago(float(reading.get('at') or 0))}"
    else:
        last = "none yet: the socket tables are read while the Netstat or World Wide Web tab is shown"
    mode = d.get("mode") if d.get("mode") in netstat.MODE_WORDS else "shown"
    recording = netstat.MODE_WORDS[mode]
    if mode == "always":
        recording += (f": recording now, a reading every {hostbook.ALWAYS_S:g} s" if d.get("recording")
                      else ", but not recording now")
    book = d.get("book")
    if not isinstance(book, dict):
        kept = "not opened yet: it is read and written while one of the two tabs is shown, or as recording says"
    elif book.get("elsewhere"):
        kept = f"not kept from here: {book['elsewhere']}"
    else:
        kept = (f"{int(book.get('rows') or 0):,} rows ({plural(int(book.get('hosts') or 0), 'host')}, "
                f"{plural(int(book.get('programs') or 0), 'program')}), {size_words(int(book.get('bytes') or 0))}, "
                f"in {book.get('path') or 'the data folder'}"
                + (f", recorded since {time.strftime('%Y-%m-%d %H:%M', time.localtime(book['since']))}"
                   if book.get("since") else ""))
        if book.get("problem"):
            kept += f"; {book['problem']}"
    tables = {"Last reading": last, "Recording": recording, "Hosts database": kept}
    if d.get("error"):
        tables["Problem"] = str(d["error"])
    out: dict[str, dict[str, str]] = {PROCFS.name: tables}
    sources = {"overpass": OVERPASS_API, "sparql": WIKIDATA, "geojson": EMODNET, "gml": TOPOLOGY_ZOO,
               "ourairports": OURAIRPORTS_API, "geonames": GEONAMES_API,
               # liminal-libs 1.104.0: the fibre, roads and railways, backbones, RIPE Atlas and the orbits
               "shapefile": NATURAL_EARTH_API, "mvt": AFTERFIBRE_API, "topohub": TOPOHUB_API,
               "atlas-probes": RIPE_ATLAS, "atlas-latest": RIPE_ATLAS, "omm-csv": CELESTRAK_API}
    for s in d.get("sets") or ():
        card = sources.get(str(s.get("format") or "")) if isinstance(s, dict) else None
        if card is not None:
            out.setdefault(card.name, {})[str(s.get("title") or s.get("id") or "a data set")] = data_set_words(s)
    return out


def data_set_words(s: dict) -> str:
    """A data set of the globe as its card's fact says it (Index.sets' entry): being downloaded, its file that does not
    read, what is installed of it, or that it is not downloaded yet."""
    if s.get("downloading"):
        return "being downloaded now (its progress is in the plugin's panel)"
    if s.get("problem"):
        return str(s["problem"])
    if s.get("installed"):
        from liminal_libs.machines.world import size_words

        dropped = int(s.get("dropped") or 0)
        return (f"{plural(int(s.get('features') or 0), 'feature')}, fetched {str(s.get('fetched') or '')[:10]} "
                f"({size_words(int(s.get('bytes') or 0))})" + (f"; {dropped:,} left out" if dropped else ""))
    return ("not downloaded: the World Wide Web tab's Internet infrastructure table offers it, its size and licence "
            "said first")


def plural(n: int, word: str) -> str:
    """A count and its word: 1 host, 2 hosts."""
    return f"{n:,} {word}" + ("" if n == 1 else "s")
