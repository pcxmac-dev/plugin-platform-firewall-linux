"""Linux firewalls for Liminal (the user, 2026-11-07: "i also need a windows and linux firewall plugin for the platform";
2026-11-08, on the Windows one: "i need it to be able to read the configuration, and make changes", "basically the
firewall plugin is an interface for windows networking / defender / firewall, and will let me make queries and alter
the firewall configurations"; then "lets mirror that for linux firewall, except research the current linux kernel, and
make sure its compatable with systemd/openrc it has access nftables, iptables, all the firewall technologies and
libraries for the most modern kernels, make sure its compatible with major distributions and gentoo linxu").

An interface to the firewall of the Linux the platform runs on, and nowhere else: a machine of its own, or a WSL
distribution the platform runs inside (the user, 2026-11-08: "the scope of linux administration is only on native linux
O/S"; "Yes, firewall too"; and 2026-11-15: "wsl and firewall linux should always work under linux, if wsl prevents or
misses some capability this should reflect in the plugin": inside WSL its page ends with what WSL changes, the library's
machines.linux.wsl_table). On Windows and macOS it runs no command at all (the library's machines.linux.why_not_native),
and a platform on Windows never reaches into a WSL distribution from outside. It reads the whole
configuration in one read (read.SCRIPT, as root through the library's machines.linux.Shell: the platform's own root,
`sudo -n` by a rule of the user's own, or Root access's installed read, below), kept READ_S and read again after each
change: nftables' ruleset, iptables and ip6tables (the nf_tables variant
and legacy x_tables), ebtables, arptables, ipset, firewalld's zones and policies, ufw, the connections tracked, the
interfaces, eBPF and XDP programs (read only), the firewall services under systemd, OpenRC or SysV scripts, and where
the distribution keeps its rules across a restart. The platform's page shows it as tables (status.tables): the firewall's
parts, the interfaces, firewalld's zones, the default policies, every rule (its presets and Find), the sets. Every
change is a confirmed form: a rule made (Liminal's, named), a rule removed (this machine's own, ufw's, firewalld's,
Liminal's; never a program's that makes its own, Docker's), a default policy set, a front end or firewall service
turned on or off, the rules made at run time saved where the distribution loads them at boot. A change that can cut
this machine off over SSH or open it to everyone needs a second confirmation (changes.Risky, accept_risk).

The library's Firewall base still holds the framework's own part (its setup: on, the framework's pages kept to this
machine, the ports its services need as Liminal's rules), over the same read.

The rules in groups (0.5.0; the user: "for both firewalls, i need to have groups, like system or application and then
unassociated rules not tied to a specific application or system process can be in an other, i can create labels, like
system or application, as well and move the rules in to that"): every rule sorted (groups.sort_entry) into System,
Application or Other by whose it is, what it is for, the service or profile it names and the program listening on its
port; the user's labels and moves are the library's (rulegroups), kept through the platform's login, never in the
firewall.

System and Application grouped again (0.6.0; the user: "for the windows and linux firewall, lets have the same system and
application and other, but lets group by application under apps or system, try best to organize under system and
applications", "try to group the system by 'services'"): each System rule named by its service, one name whichever way
it was recognised (SSH, DNS, DHCP, mDNS, Samba...; this machine's own traffic, ICMP, invalid packets), each Application
rule by its program (Docker, libvirt, Tailscale, Liminal; Web server (HTTP, HTTPS) for firewalld's http and https; a ufw
profile's application; the program listening), a heading of its own under its group (liminal-libs 1.41.0). And the
rules turned off are shown too ("also rules that are turned off should be shown as well"), dimmed: ufw's while ufw is
off, firewalld's while it is stopped, in a zone bound to nothing or in a policy turned off, a dormant nftables table's,
one in a chain nothing jumps to. A rule turned off never stands for one in force (the second confirmation, the
exposure).

What it attaches to (0.7.0, plugin API 2.2; the user, 2026-11-11: "each plugin should reflect the the API its attached
to, and present links that provide documentation"): nftables, iptables and ip6tables, ebtables and arptables, ipset,
firewalld, ufw, conntrack, eBPF (bpftool), iproute2, the init's firewall services and sudo, each with its makers' pages,
its parts and its calls (apis.py), drawn on the plugin's page; `api_facts` says what the last read found of them (each
tool's version and what it holds), asking nothing.

The World Wide Web tab (0.8.0; the user, 2026-11-14: "so for the firewall's both are going to get a 'world wide web view'
that shows the globe and the routes incoming all traffic, as well as monitoring port traffic stats"): the library's
Firewall base's (liminal-libs 1.55.0, machines/world.py), after Main and API. While it is shown, and for 20 s after, libpcap
watches every TCP and UDP packet at the adapter of this machine's way out (as root, or with CAP_NET_RAW alone given to
the platform alone: its system unit's AmbientCapabilities=, or setcap on a copy of Python that is its own; never the
system's Python, never CAP_NET_ADMIN); the page draws each place traffic came from and went to on the globe with its
route to this machine, the busiest ports' bytes in and out, and tables of the ports and the places. Only counts are
kept, in memory. Packets are seen before nftables and iptables decide, so what they drop shows as unanswered; what an
XDP program drops is never seen, and the page says so when the last read found one at the adapter watched
(xdp_unseen). Places come from DB-IP's Lite City file on this machine, downloaded only when the user accepts its
licence on the tab; no address is sent anywhere. Home is the place the user sets (LIMINAL_HOME_PLACE, through the
login), else where the file puts this network's public address, asked of OpenDNS's and Google's name servers. This
plugin names the download, its licence and attribution and the name servers (apis.py: GEOIP_URL, GEOIP_LICENCE,
ATTRIBUTION, PUBLIC_DNS) and their cards. Inside a WSL distribution the tab ends with what WSL changes for it (the
library's world.under_wsl: the distribution's own adapter, nothing from the internet but through Windows, nothing at
all under WSL 1). On Windows and macOS the tab says it is not for this machine, and nothing is watched or downloaded.

Root access (0.9.0; the user, 2026-11-17, after the firewall could not be read inside their WSL Ubuntu, where sudo asks
for a password: "the plugin needs to be able to handle permissions if required"; asked how the password is typed: "A
field on its page"; then "(enable / disable)", "but only if required"). Where root is needed it says what for and offers
it as a confirmed action on its own page, as the Windows plugins ask through UAC (rights.py). A switch, Root access, on
Main, shown only if required: not where the platform is root, nor where sudo runs the read without a password by a rule
of the user's own (a fact then says how it has its rights). Turning it on asks for the user's password for sudo once, in
a password field of its form, handed to sudo on its standard input for that one action and never kept (the library's
Shell.run(password=...), liminal-libs 1.62.0): the group liminal made where there is none and the platform's user put in
it, the plugin's read installed root-owned and a sudoers rule letting the group run exactly it, and a take-back helper,
with no arguments and nothing else (the library's grant, checked with visudo first; never NOPASSWD: ALL). The read then
runs that installed file through sudo -n once it is checked to be the plugin's own read; one that differs (an older
plugin's) is not run, and Turn on... again replaces it. Turning it off runs the take-back helper, with no password. A
change's form gets the password field (its last) only where sudo cannot run it without one, and its hook a last argument
`password`. Where the firewall cannot be read (no tool, or root not given) the plugin is valid with a `problem`: its
page says what the firewall needs, offering only what it can do, and its tabs are asked. Where no firewall tool is
installed and the distribution's apt is there, Install nftables... installs the distribution's own package (install.py),
its size read without root and said first; installing it filters nothing. On a library from before the grant it works
as 0.8.1.

The Netstat tab, the hosts database and the globe's filters and layers (0.9.0; the user, 2026-11-16: "the firewall app
should have a 'netstat' like interface for looking at active ports and what apps they are attached to, and the hosts
that they connect to across the lan or wan. the firewall app should also have a globe that can be zoomed and rotated
and geoip'd hosts are databased for the apps they talk to, the time they are connected to *this *computer"; "the
globe-firewall should allow filtering, so i can view apps connected to hosts all across the globe, or ports talking to
all hosts"): the library's Firewall base's (liminal-libs 1.65.0), the Netstat tab after the World Wide Web tab. It reads
the kernel's socket tables in /proc/net as files, as the platform's user: no command, no capture, no root, no window.
Each socket has its program where it is the platform's user's own (another user's is listed without it: only root may
read which program holds a socket), its remote host, whether that host is this machine's, the local network's or the
internet's, and its GeoIP place; a listener another user holds is named from the firewall's own root read where there
is one (netstat_listeners: from the read kept, no command). The hosts database keeps each program's remote hosts, their
ports, when they were seen and how long they were connected, recorded only while the Netstat or the World Wide Web tab
is shown unless the user chooses always. The globe shows the traffic watched or the hosts recorded, filtered by program,
port, direction and when they were last seen, and draws the internet's infrastructure from the data sets this plugin
names (apis.INFRASTRUCTURE: OpenStreetMap's data centres, exchange points, submarine cables and lines on land through
the Overpass API, Wikidata's exchange points, data centres, ground stations and teleports, EMODnet's cable routes in
European waters, the Internet Topology Zoo's backbone networks; the user, 2026-11-19: "major network 'bones' need to be
displayed on the map", "also underwater lines"), each downloaded only on the user's click once its licence is
accepted. None of it needs root, so the plugin is valid wherever the socket table can be read, the firewall's own
read refused or failed (B-revisions S2), and present
there too; what the firewall needs then says what Netstat needs (netstat.needs_row). Inside WSL the tab ends with what
WSL changes for it (the library's table, and the row seen in the user's Ubuntu: netstat.WSL_ROWS). On a library from
before it the plugin works as 0.8.2 did, its table of what the firewall needs saying what the tab would need.

Its run() as the platform's own user (0.10.0; the independent review's finding PLT-H1, checked 2026-11-23): a command
asked of run() runs as the platform's user, and as root only when its caller says `elevated` (the command line's
`run --elevated`), then through the library's `sudo -n --`, never asking a password. It ran every command as root, and
liminal-platform's POST /api/machines/{name}/run handed it any words a program on this machine sent: that route is
gone (the user, 2026-11-23: "Remove it"; liminal-platform 0.34.1), and only a command line asks run(), in its own
process. And, from the review of that change: its changes are asked only from its page (PAGE_ONLY_HOOKS: a rule made
or removed, a default policy, on and off, saving, Root access, nftables' install, and the base's allow and remove),
so another plugin's ask is refused and the platform asks its login whether you are at the page; and the framework's
allow reads its remote as the form's other side is read, so no word of it reaches nft unread.

GeoIP sources (0.12.0; liminal-libs 1.101.0's machines/geosources.py, Monday list item 20; the user, 2026-11-19: "add a
way to download different GEOIP sources"): the World Wide Web tab's GeoIP sources table, in place of its install
buttons, places and networks chosen apart, DB-IP's two files the default for both (the same addresses and folders; the
same words as the Windows firewall plugin's, each with the line pointing to the full licence). Their download, use and
removal are the base's three page-only hooks, each refusing any ask but a person's signed in at the platform's page;
each acceptance of a licence is kept in that person's own login store, never in a file. IPinfo Lite, for networks, is
named and not offered (the user, 2026-11-25: each source offered only after their yes): its row waits for your word,
with no button, no card and no key asked (apis.GEOIP_SOURCES).

The globe's newer data sets (0.13.0, liminal-libs 1.104.0; the Monday list's items 24, 27, 28, 29 and 32, with the
user's answers of 2026-11-26): AfTerFibre's fibre on land in Africa (its map's tiles; its licence unconfirmed), Natural
Earth's 1:10m roads, North America's roads and railways as stand-ins for fibre where none is mapped (public domain),
TopoHub's backbone model and its cities (no licence stated for its data), RIPE Atlas's probes and every connected
probe's newest traceroutes, IPv4 and IPv6 (non-commercial), and CelesTrak's orbits of Starlink, OneWeb and HughesNet
(refreshed by themselves every 2 hours at the soonest while the World Wide Web tab is open), placed with the sgp4
package pinned here for this machine (SGP4_PACKAGE), each footprint at 25 degrees of elevation, HughesNet's each its
full cap. Each is downloaded first only on your click, its size and licence said first, and kept in the plugin's own
infrastructure.db (GLOBE2_SETS, their cards GLOBE2).

The World Wide Web tab leaves (0.14.0, liminal-libs 1.105.0, Monday list item 33; the user, 2026-11-26: "Delete now"):
the tab, its GeoIP sources and files, its capture, its globe's filters, layers, data sets and sky, and their cards are
plugin-platform-worldwideweb's, which asks this plugin through the platform for what only a firewall knows (the socket
table's reading, the hosts recorded, the routes kept, the rules covering a port, and capture_unseen: what an XDP
program at the adapter its capture watches drops before libpcap sees it, from the read kept). This plugin keeps its
rules, Root access, the Netstat tab, the hosts' recording and database and the Networks tab; what the paragraphs above
say of the World Wide Web tab, its GeoIP sources and the globe is what it had until 0.13.0. It needs liminal-libs
1.105.0.

    python -m plugin_platform_firewall_linux status | tables | rules [PRESET] [WORDS] | setup [STEP ...] | exposure
                                             | allow NAME PORT[,PORT ...] [tcp|udp] | remove NAME
                                             | run [--elevated] -- COMMAND
"""
from __future__ import annotations

import ipaddress
import shutil
import threading
import time

from liminal_libs.machines import linux as linux_mod
from liminal_libs.machines.firewall import Firewall, FirewallError, FirewallNotNeeded, Rule, app_ports
from liminal_libs.machines.linux import Shell, why_not_native
from liminal_libs.machines.plugin import CommandError
from liminal_libs.machines.rulegroups import RuleGroups, Sorted

from . import changes as ch
from . import firewalld as fwd_mod
from . import install as install_mod
from . import netstat as netstat_mod
from . import nftables as nft_mod
from . import read as read_mod
from . import rights as rights_mod
from .apis import APIS
from .apis import facts as api_facts_of
from .changes import ACCEPT, NotNeeded, Risky
from .groups import key as rule_key
from .groups import sort_entry
from .model import DIRECTIONS, MAX_ROWS, OWNER_WORDS, PRESET_NAMES, PRESETS, parse_address
from .read import SCRIPT, Config
from .rights import PASSWORD_FIELD, Rights
from .network import LinuxNetwork
from liminal_libs.machines.segments import NetworkHost

__version__ = "0.14.1"


# 0.14.0: what plugin-platform-worldwideweb asks of this plugin beside the base's services (liminal-libs 1.105.0): the
# XDP programs at the adapter its capture watches, which drop packets before libpcap is handed them
UNSEEN_HOOK = "capture_unseen"
OWN_SERVICES = (UNSEEN_HOOK,)
READ_S = 60.0  # the configuration read is kept this long; a change, a Refresh read it again
READ_TIMEOUT_S = 90.0
FRONTS = ("ufw", "firewalld")
POLICY_ORDER = ("default", "allow", "accept", "ACCEPT", "deny", "drop", "DROP", "reject", "%%REJECT%%")
POLICY_NOTES = {"allow": "let in", "accept": "let in", "ACCEPT": "let in", "deny": "dropped", "drop": "dropped", "DROP": "dropped",
                "reject": "refused", "%%REJECT%%": "refused (firewalld's)", "default": "firewalld's default: refused"}
# What the firewall needs here, said when it cannot be read or there is none (0.8.1; the user: "still need linux
# firewall"): the tools looked for without root, by their files (no command run), in the folders root's PATH holds
TOOLS = (("nftables", "nft"), ("iptables", "iptables"), ("ufw", "ufw"), ("firewalld", "firewall-cmd"))
TOOL_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
NEEDS_TITLE = "What the firewall needs here"
INSTALL = ("install nftables, the kernel's own: apt install nftables (Debian, Ubuntu), dnf install nftables (Fedora), "
           "pacman -S nftables (Arch), apk add nftables (Alpine), emerge net-firewall/nftables (Gentoo); as root, so it is "
           "an administrator's to do")
ROOT_FOR_READ = ("run the platform as root, or let sudo run sh and the firewall's tools without a password for the user "
                 "the platform runs as (a sudoers rule): every read and change here runs through sudo -n, which never asks "
                 "for one, so a password typed here is never what it waits for")  # a library before the grant (0.8.1)
ROOT_HOOK, INSTALL_HOOK = "root_access", "install_nftables"
NEEDS_PASSWORD = ("this change needs your password for sudo, and nothing here asks for it: make it from its form on "
                  "the plugin's page, which asks for it at its click (Root access lets the firewall's read alone run "
                  "without one)")  # a change asked without the password it needs (the setup's, a command line's)
REFRESH = {"hook": "refresh", "args": [], "title": "Refresh", "note": "reads the whole configuration again now"}
UNREAD = {"off": "Root access is off", "pending": "Root access is on from the platform's next start",
          "stale": "Root access is to be turned on again"}  # the summary's words where root is not given (0.9.0)
PROBLEM = {  # the problem's words where root is not given (0.9.0)
    "off": ("The firewall's rules are not read: sudo asks for a password, and Root access is off (Turn on… below gives "
            "the read alone root, with your password once)."),
    "pending": ("Root access is on from the platform's next start: the firewall's rules are read once the platform is "
                "started again, from a terminal opened after it was turned on.")}


def find_tool(tool: str):
    """A tool's file in the folders root's PATH holds (TOOL_PATH), found without running anything; None when it is not
    there (a test stands it in, so the machine the tests run on never shows through)."""
    return shutil.which(tool, path=TOOL_PATH)


class LinuxFirewallPlugin(Firewall, LinuxNetwork):
    name = "firewall-linux"
    title = "Linux firewall"
    about = ("the firewall of the Linux the platform runs on (a WSL distribution it runs inside too, what WSL changes said), "
             "read whole and changed from the platform's page: nftables, iptables (nf_tables and legacy), ebtables, "
             "arptables, ipset, firewalld, ufw, conntrack, eBPF and XDP (read only), under systemd, OpenRC or SysV "
             "scripts; never reached from Windows or macOS. Its Netstat tab lists the listening ports and the open "
             "connections with the program behind each, and the hosts database keeps each program's remote hosts and "
             "how long they were connected")
    api = "2.2"
    # what it attaches to: nftables, iptables, ebtables, ipset, firewalld, ufw, conntrack, eBPF... and the kernel's
    # socket tables (0.9.0) (apis.py). 0.14.0: the World Wide Web tab's cards (libpcap, DB-IP, the name servers, the
    # data sets' sources) are plugin-platform-worldwideweb's, its apis.py holding them moved word for word
    apis = APIS
    order = 711
    ICON = "wallfire"  # a brick wall with a flame before it (liminal-libs 1.34.0; the user's picture: "use this icon for linux firewall")
    SECTION = "os"  # drawn under the platform's OS plugins (liminal-platform 0.26.0)
    HOOKS = (*Firewall.HOOKS, "refresh", "show_rules", "find_rules", "make_rule", "remove_rule", "set_policy", "switch",
             "save_rules",  # the base's: the rules, the Netstat tab, the hosts' recording, the services
             ROOT_HOOK, INSTALL_HOOK,  # 0.9.0: Root access turned on or off; nftables installed (a job)
             *(h for h in NetworkHost.HOOKS if h not in Firewall.HOOKS),  # 0.11.0: services' networks (network.py)
             *OWN_SERVICES)  # 0.14.0: what the World Wide Web plugin asks of it beside the base's services
    TABS = (*Firewall.TABS, *NetworkHost.TABS)  # 0.11.0: the Networks tab after the Netstat tab
    ASKS = (*getattr(Firewall, "ASKS", ()), *NetworkHost.ASKS)
    READ_HOOKS = tuple(dict.fromkeys((*Firewall.READ_HOOKS, *NetworkHost.READ_HOOKS, *OWN_SERVICES)))
    SERVICE_HOOKS = (*NetworkHost.SERVICE_HOOKS, *OWN_SERVICES)
    JOB_HOOKS = (*Firewall.JOB_HOOKS, INSTALL_HOOK)  # run by the platform as jobs, their lines in the plugin's panel
    # Its changes as root, asked only from its page (0.10.0, the review's PLT-H1 follow-up; liminal-libs 1.66.0's
    # apps/asking.py): another plugin's ask is refused (403), and liminal-platform 0.34.0 refuses one over HTTP (401)
    # unless its login shows that you are at the page. Before, any program on this machine could ask them with two
    # headers, a second confirmation being only an argument. The base's allow and remove among them: the framework's
    # setup and the command line call their code in their own process, not through an ask.
    PAGE_ONLY_HOOKS = (*NetworkHost.PAGE_ONLY_HOOKS,  # 0.11.0: approve_plan, the grants, the domain, Re-point…
                       "allow", "remove", "make_rule", "remove_rule", "set_policy", "switch", "save_rules", ROOT_HOOK,
                       INSTALL_HOOK,
                       # 0.11.0 (service-containers-networking §8.1): the base's other changes too
                       "move_rules", "new_label", "rename_label", "remove_label", "hosts_recording", "hosts_forget",
                       # 0.14.1 (the user, 2026-11-26: "Yes, closed by default", and of the reads made with a key or
                       # with rights: "Page-only"): the rules read again, as root, and the Rules table's two choices.
                       # With them every hook says who may ask it (liminal-libs 1.107.0's conformance.warnings is
                       # empty)
                       "refresh", "show_rules", "find_rules")
    # 0.14.0: the World Wide Web tab's (the watching, the GeoIP files, the data sets, the sgp4 package) are
    # plugin-platform-worldwideweb's

    def __init__(self, shell: Shell | None = None, runner=None, native: str | None = None, clock=time.monotonic,
                 which=None, book=None, platform: str = "", wsl: str | None = None):
        # 0.11.0: services' networks: the network database in the data folder (liminal-libs 1.96.0's netbook), opened
        # per call; a test's own book, platform and word for WSL ("" a machine of its own, else the distribution)
        from liminal_libs.netbook import NetBook

        NetworkHost.__init__(self, book=book if book is not None else NetBook(), platform=platform)
        self._wsl_word = wsl
        self._shell = shell
        self._runner = runner
        self._native = native  # a test's word for why_not_native(): "" on Linux, else why not
        self._clock = clock
        self._which = which  # a test's stand-in for finding a tool's file without root (tools_here)
        self._lock = threading.RLock()
        self._read: tuple[float, Config] | None = None
        self._refused: tuple[float, str, bool] | None = None  # (when, words, denied): a read refused, kept as long
        self._rights: tuple[float, Rights] | None = None  # how the last read had its rights (0.9.0)
        self._needs: dict = {}  # whether a change, and the install, need the password: asked once per read
        self._install_facts: tuple[float, install_mod.Facts] | None = None  # what installing nftables takes, kept FACTS_S
        self._preset = "in-allow"
        self._find = ""

    def app_stopping(self) -> None:
        """The platform stops: the base's, then its network works cancelled and joined, its plans forgotten."""
        Firewall.app_stopping(self)
        self.network_stopping()

    def api_facts(self) -> dict:
        """What the last read found of its APIs, asking nothing (a read under way is not waited for): each tool's version
        and what it holds, the connections tracked, the programs on the network's hooks, the machine and when."""
        return api_facts_of(self)

    # -- where it works -------------------------------------------------------------------------------------------------
    def not_for_here(self) -> str:
        """Why the machine the platform runs on is not one this plugin is for, in words ("" when it is): Windows and
        macOS (the library's why_not_native; inside a WSL distribution it is Linux like any other, with a library that
        no longer refuses a WSL kernel). The library's status and setup honor it (applies False, nothing changed)."""
        return why_not_native("The Linux firewall") if self._native is None else self._native

    @property
    def shell(self) -> Shell:
        """The commands of the Linux the platform runs on (root through sudo -n); refused anywhere else, and for a WSL
        distribution reached from Windows (a target of `wsl -d`)."""
        note = self.not_for_here()
        if note:
            raise FirewallError(note)
        sh = self._shell if self._shell is not None else Shell("local", runner=self._runner)
        if sh.target != "local":
            raise FirewallError(f"The Linux firewall is for the Linux the platform runs on, never {sh.where}")
        return sh

    # -- the one read ---------------------------------------------------------------------------------------------------
    def config(self, fresh: bool = False) -> Config:
        """The whole configuration, read at most every READ_S (now when `fresh`); CommandError when it cannot be read.
        A refused read is kept as long (0.9.0): sudo notes each refusal, so it is not asked again at every status."""
        sh = self.shell
        with self._lock:
            now = self._clock()
            if not fresh and self._read is not None and now - self._read[0] < READ_S:
                return self._read[1]
            if not fresh and self._refused is not None and now - self._refused[0] < READ_S:
                raise CommandError(self._refused[1], denied=self._refused[2])
            self._needs = {}
            try:
                text = self._read_text(sh, now)
                try:
                    cfg = read_mod.parse(text)
                except ValueError as e:
                    raise CommandError(f"the firewall's read gave no answer of its own: {e}") from None
            except CommandError as e:
                self._read, self._refused = None, (now, str(e), bool(getattr(e, "denied", False)))
                raise
            self._read, self._refused = (now, cfg), None
            return cfg

    def _read_text(self, sh: Shell, now: float) -> str:
        """The read's answer, run with the rights there are, which are kept with it (0.9.0, rights.py): as root without
        sudo; Root access's installed read through sudo -n, once the library's granted() says it is this plugin's own;
        else sh -c through sudo -n, which a rule of the user's own may allow. Root access turned on but not in force yet
        (pending) or not this plugin's (stale) runs nothing: CommandError (denied) in its words."""
        def kept(rights: Rights) -> None:
            self._rights = (now, rights)

        if sh.root():
            kept(Rights("root"))
            return sh.sh(SCRIPT, timeout=READ_TIMEOUT_S)
        lib = rights_mod.library()
        if lib is None:  # a library from before the grant: 0.8.1's read, through sudo -n alone
            kept(Rights("old"))
            return sh.sh(SCRIPT, timeout=READ_TIMEOUT_S)
        grant = rights_mod.grant_state(lib, sh)
        if grant.kind == "on":
            kept(Rights("on", grant))
            try:
                return sh.run(rights_mod.Paths.here().read, timeout=READ_TIMEOUT_S)
            except CommandError as e:
                if getattr(e, "denied", False):  # its rule changed since: said, and Turn on... offered again
                    kept(Rights("stale", rights_mod.Grant(rule=True, missing=(f"sudo refused to run it ({e})",))))
                raise
        if grant.kind in ("pending", "stale"):
            r = Rights(grant.kind, grant)
            kept(r)
            raise CommandError(f"Root access is {r.state}", denied=True)
        try:
            text = sh.sh(SCRIPT, timeout=READ_TIMEOUT_S)
        except CommandError as e:
            kept(Rights("off" if getattr(e, "denied", False) else "own", grant))
            raise
        kept(Rights("own", grant))
        return text

    def rights(self) -> Rights:
        """How the plugin has its rights (rights.Rights), as the last read found them: read again when that is older
        than READ_S, a refusal included."""
        with self._lock:
            kept = self._rights
            current = kept is not None and self._clock() - kept[0] < READ_S
        if not current:
            try:
                self.config()
            except CommandError:
                pass
            with self._lock:
                kept = self._rights
        return kept[1] if kept is not None else Rights("off")

    def password_needed(self, what: str, *command: str) -> bool:
        """Whether `what` ("changes", "install") needs the password typed on its form, `command` the one it runs: asked
        at most once per read (rights.changes_need: never as root nor with a library from before the field, always
        where Root access is required, else as sudo's policy says)."""
        with self._lock:
            if what in self._needs:
                return self._needs[what]
        need = rights_mod.changes_need(self.shell, self.rights(), *command)
        with self._lock:
            self._needs[what] = need
        return need

    def _change_wants_password(self) -> bool:
        """Whether a change needs the password typed (password_needed), by what is in charge in the read kept."""
        with self._lock:
            kept = self._read
        return self.password_needed("changes", dict(TOOLS).get(kept[1].manager if kept else "", "nft"))

    def forget(self) -> None:
        with self._lock:
            self._read = self._refused = self._rights = None
            self._needs = {}

    def present(self) -> bool:
        """What this plugin serves on the Linux the platform runs on: firewall tools it reads, or (0.9.0) the Netstat
        tab, the hosts database and the globe's filters, wherever the kernel's socket tables can be read with a library
        that has them, the firewall's own read refused or not (B-revisions S2); never on Windows or macOS.

        Where the Netstat tab is served that answers alone, before the firewall's own read is asked: the tray asks this
        every minute while a page is open, and each read as root is a sudo -n that sudo notes, a refusal too."""
        if self.not_for_here():
            return False
        if self._lib() is not None and netstat_mod.serves():
            return True
        return self.firewall_here()

    def firewall_here(self) -> bool:
        """Firewall tools this plugin reads on the Linux the platform runs on, its read answering (what present said
        before 0.9.0, and what the framework's setup needs)."""
        if self.not_for_here():
            return False
        try:
            return self.shell.here and bool(self.config().manager)
        except CommandError:
            return False

    def setup(self, log=print, steps=None) -> list[dict]:
        """The library's setup of the framework's own part (its steps: enable, exposure, rules) over the firewall's
        read. Where the plugin is present for its Netstat tab alone (0.9.0: no firewall tool here, or the firewall
        cannot be read), nothing is changed and its first step says why, as it did before."""
        if self.not_for_here() or self.scope_note() or self.firewall_here():
            return super().setup(log, steps)
        wanted = tuple(steps) if steps else self.STEPS
        what = wanted[0] if wanted else "setup"
        detail = "no firewall here this plugin drives"
        log(f"{self.name}: {what}: FAILED: {detail}")
        return [{"step": what, "ok": False, "detail": detail}]

    # -- the library's backend, over the read --------------------------------------------------------------------------
    def backend(self) -> str:
        cfg = self.config()
        return f"{_named(cfg.manager, cfg)} on {self.shell.where}" if cfg.manager else f"no firewall software on {self.shell.where}"

    def state(self) -> dict:
        return self.config().state()

    def list_rules(self, owned_only: bool = True) -> list[Rule]:
        cfg = self.config()
        if owned_only:
            return cfg.liminal_rules()
        out = cfg.liminal_rules()
        for e in cfg.entries():
            if e.owner == "liminal" or e.direction not in ("in", "out") or e.action not in ("accept", "limit", "drop", "reject"):
                continue
            protocol = e.protocol if e.protocol in ("tcp", "udp") else "any"
            ports = tuple(sorted({p for a, b in e.spans for p in range(a, min(b, a + 1023) + 1)})) if protocol != "any" else ()
            try:
                out.append(Rule(f"{e.kind} {e.where}: {e.text}", ports=ports, protocol=protocol, direction=e.direction,
                                action="allow" if e.action in ("accept", "limit") else "block", remote=e.source or "any",
                                owned=False, detail=e.text))
            except ValueError:
                continue
        return out

    def add_rule(self, rule: Rule) -> None:
        """One of Liminal's own rules made, the framework's (the base's allow, its setup's rules), with no second
        confirmation. Its remote is read as the form's other side is (model.parse_address: "any" for anywhere, else
        an address or a network, written canonically), and anything else is a FirewallError before anything runs
        (0.10.0): it went to the commands as it was given, and nft read a ';' in it as the start of a command of its
        own, run as root (the review's PLT-H1 follow-up)."""
        if not rule.owned:
            raise FirewallError("only Liminal's own rules are made here")
        try:
            spec = ch.Spec(rule.name, rule.direction, "allow" if rule.action == "allow" else "block", rule.protocol,
                           tuple((p, p) for p in rule.ports), parse_address(rule.remote), "")
            plan = ch.plan_make(self.config(fresh=True), spec, framework=True)
        except NotNeeded as e:
            raise FirewallNotNeeded(str(e)) from None
        except ValueError as e:
            raise FirewallError(str(e)) from None
        self._run(plan)

    def delete_rule(self, name: str) -> bool:
        """Every rule of Liminal's named `name` removed, one at a time over a fresh read each (ufw's numbers move)."""
        tried: set = set()
        for _ in range(32):
            cfg = self.config(fresh=True)
            left = [e for e in ch.liminal_entries(cfg, name) if e.ref not in tried]
            if not left:
                break
            tried.add(left[0].ref)  # one that stays after its removal is not asked again
            self._run(ch.plan_remove(cfg, left[0], check_risk=False))
        return bool(tried)

    def enable(self) -> None:
        cfg = self.config(fresh=True)
        if cfg.manager not in FRONTS:
            raise FirewallError(f"{_named(cfg.manager, cfg) or 'nothing here'} has no switch: its rules filter or not")
        self._run(ch.plan_switch(cfg, cfg.manager, True))

    def can_enable(self) -> bool:
        return self.config().manager in FRONTS

    def exposing(self, ports) -> list[tuple[int, str]]:
        return self.config().exposing(ports)

    def run(self, *command: str, elevated: bool = False, **options) -> str:
        """A command on this machine, its output, run as the platform's own user (0.10.0; the review's PLT-H1): as
        root only when `elevated` is said (the command line's `run --elevated`), and then through the library's
        `sudo -n --`, never a password: a command sudo wants a password for fails in words (CommandError, denied). A
        platform that is root runs it as root all the same: that is its own user. Its other options change nothing,
        `root=True` among them. Before 0.10.0 it ran every command as root, whatever asked it: liminal-platform's
        POST /api/machines/{name}/run among them, a route gone since its 0.34.1.

        A command refused for want of root, run as you, says so, and that a rule of yours letting sudo run it counts
        only with `run --elevated`: the library's words alone told you to add such a rule, and the same command run
        so fails again. Elevated, or with a platform that is root, the library's own words."""
        try:
            return self.shell.run(*command, root=elevated)
        except CommandError as e:
            if elevated or not getattr(e, "denied", False) or self.shell.root():
                raise  # through sudo, or as root: the library's words fit
            what = command[0] if command else "COMMAND"
            raise CommandError(f"{e}. It ran as you, not through sudo: a rule letting sudo run it counts only for "
                               f"`python -m plugin_platform_firewall_linux run --elevated -- {what} ...`; the "
                               "platform's command line has no --elevated and runs every command as you",
                               denied=True) from None

    def _run(self, plan: ch.Plan, password=None) -> list[str]:
        """A plan's commands one after another as root, with the password typed on its form handed to sudo for each
        (0.9.0: on its standard input, never kept; none, sudo -n); the read forgotten after, whatever happened. A
        password sudo refuses is a WrongPassword before anything ran: the form is filled again. Asked without the
        password a change needs (the setup's steps, the command line), it is refused in words before sudo is asked."""
        sh = self.shell
        if not password and plan.steps and self._change_wants_password():
            self.forget()
            raise CommandError(NEEDS_PASSWORD, denied=True)
        ran: list[str] = []
        try:
            with rights_mod.refusals(ran):  # a failure says the steps done before it
                try:
                    for step in plan.steps:
                        rights_mod.run(sh, *step.args, password=password, stdin=step.stdin, check=step.check)
                        ran.append(step.words)
                except Exception:
                    # A plan failing part way takes back what it made (Plan.undo), said with the steps done: a
                    # firewalld service left in no zone was unseen and its name refused for good (the review of
                    # 2026-11-21, item 26).
                    if plan.undo and len(ran) >= plan.undo_after:
                        for step in plan.undo:
                            try:
                                rights_mod.run(sh, *step.args, password=password, stdin=step.stdin, check=step.check)
                                ran.append(f"taken back as it failed part way: {step.words}")
                            except Exception:
                                ran.append(f"not taken back: {step.words}")
                    raise
        finally:
            self.forget()
        return ran

    def sorted_rules(self) -> dict[str, Sorted]:
        """Every rule listed (the turned-off ones too), by its key, with its own group and name (groups.sort_entry): what
        a move checks."""
        cfg = self.config()
        ports = liminal_ports()
        return {rule_key(e): sort_entry(e, cfg.system.listening, cfg.system.listening_udp, ports) for e in cfg.listed()}

    # -- the hooks the page asks ---------------------------------------------------------------------------------------
    def refresh(self) -> dict:
        cfg = self.config(fresh=True)
        return {"said": f"read again: {_summary(cfg)}"}

    def show_rules(self, preset: str) -> dict:
        if preset not in PRESET_NAMES:
            raise ValueError(f"the rules shown are one of {', '.join(PRESET_NAMES)}")
        with self._lock:
            self._preset = preset
        return {"said": f"showing {dict((p[0], p[1]) for p in PRESETS)[preset].lower()}"}

    def find_rules(self, words: str | None = None) -> dict:
        words = " ".join(str(words or "").split())[:80]
        with self._lock:
            self._find = words
        return {"said": f"finding {words!r}" if words else "every rule of the choice shown"}

    # Each change's last argument is the password typed on its form (0.9.0), there only where sudo cannot run the
    # change without one (password_needed); the platform sends a form's fields in order, so it comes after accept_risk,
    # and a second confirmation sends it again with accept_risk true. Risky is said before anything runs with it.
    def make_rule(self, name, direction="in", action="allow", protocol="tcp", ports=None, remote=None, interface=None,
                  accept_risk=False, password=None) -> dict:
        spec = ch.spec_of(name, direction, action, protocol, ports, remote, interface)
        cfg = self.config(fresh=True)
        plan = ch.plan_make(cfg, spec, framework_ports=sorted(set(app_ports().values())))
        return self._apply(plan, accept_risk, password)

    def remove_rule(self, where, rule, accept_risk=False, password=None) -> dict:
        cfg = self.config(fresh=True)
        e = cfg.entry(str(where or ""), str(rule or ""))
        if e is None:
            raise LookupError("that rule is no longer there as it was read: Refresh, then choose it again")
        return self._apply(ch.plan_remove(cfg, e), accept_risk, password)

    def set_policy(self, where, policy, accept_risk=False, password=None) -> dict:
        cfg = self.config(fresh=True)
        return self._apply(ch.plan_policy(cfg, str(where or ""), str(policy or "")), accept_risk, password)

    def switch(self, part, state, accept_risk=False, password=None) -> dict:
        if state not in ("on", "off"):
            raise ValueError("turned on or off")
        cfg = self.config(fresh=True)
        return self._apply(ch.plan_switch(cfg, str(part or ""), state == "on"), accept_risk, password)

    def save_rules(self, kind, password=None) -> dict:
        cfg = self.config(fresh=True)
        return self._apply(ch.plan_save(cfg, str(kind or "")), True, password)

    def _apply(self, plan: ch.Plan, accept_risk, password=None) -> dict:
        if plan.risk and accept_risk is not True:
            raise Risky(plan.risk)
        ran = self._run(plan, password)
        return {"said": plan.said, "lines": [*plan.lines, *(f"ran: {w}" for w in ran)]}

    # -- Root access and nftables' install (0.9.0) ---------------------------------------------------------------------
    def root_access(self, state, password=None) -> dict:
        """Root access turned on or off (the user, 2026-11-17: "(enable / disable)", "but only if required"), from its
        forms on Main. On, with the password typed, used for this once (rights.turn_on: the group liminal made where
        there is none and the platform's user put in it, the plugin's read installed root-owned, its sudoers rule
        checked with visudo first); off, by the grant's take-back helper, with no password unless it cannot run yet
        (rights.turn_off). Refused where it is not required (the platform is root, or a rule of the user's own runs
        the read) and with a library from before it."""
        if state not in ("on", "off"):
            raise ValueError("Root access is turned on or off")
        sh = self.shell
        if rights_mod.library() is None:
            raise ValueError(f"not here: {rights_mod.old_words()}")
        try:
            self.config(fresh=True)  # the rights as they are now, not as the page last showed them
        except CommandError:
            pass
        r = self.rights()
        if state == "on":
            if r.kind in ("root", "own"):
                raise ValueError(f"Root access is not needed here: {r.fact}")
            if r.kind in ("on", "pending"):
                raise ValueError(f"Root access is {r.state}")
            if not password:
                raise ValueError("your password for sudo is needed to turn Root access on")
            try:
                lines = rights_mod.turn_on(sh, password, self._tool)
            finally:
                self.forget()
            now = self.rights()
            said = ("Root access is on: the firewall's read runs as root through its own installed file, nothing else"
                    if now.kind == "on" else f"Root access is {now.state}: {root_todo(now)}"
                    if now.kind == "pending" else f"Root access: {now.state or now.fact}")
            return {"said": said, "lines": lines}
        if not r.granted:
            raise ValueError("Root access is off already: there is nothing to take back")
        if r.off_password and not password:
            raise ValueError("your password for sudo is needed: the take-back helper cannot run without one yet")
        try:
            lines = rights_mod.turn_off(sh, password if r.off_password else None)
        finally:
            self.forget()
        return {"said": "Root access is off: the firewall's rules are not read until it is turned on again",
                "lines": lines}

    def _tool(self, tool: str):
        """A tool's file found without root (tools_here's way), or None."""
        try:
            return (self._which or find_tool)(tool)
        except (OSError, ValueError):
            return None

    def apt_here(self) -> bool:
        """Whether the distribution's own apt is here (Debian, Ubuntu and their kin): what installs nftables."""
        return all(self._tool(t) for t in install_mod.TOOLS)

    def install_offered(self, tools) -> bool:
        """Whether Install nftables... is offered: no firewall tool here, apt here, and a library with the password."""
        return not tools and self._lib() is not None and self.apt_here()

    def _lib(self):
        """The library's rights (rights.library), None for a library from before them, and where the shell itself is
        refused (a WSL distribution reached from Windows)."""
        try:
            self.shell  # noqa: B018 - refused anywhere but the Linux the platform runs on
        except CommandError:
            return None
        return rights_mod.library()

    def install_facts(self, fresh: bool = False) -> install_mod.Facts:
        """What installing nftables takes here (install.read_facts: read without root), kept install.FACTS_S."""
        with self._lock:
            kept = self._install_facts
            if not fresh and kept is not None and self._clock() - kept[0] < install_mod.FACTS_S:
                return kept[1]
        facts = install_mod.read_facts(self.shell)
        with self._lock:
            self._install_facts = (self._clock(), facts)
        return facts

    def install_nftables(self, password=None, log=None) -> dict:
        """nftables installed where no firewall tool is (0.9.0; DECISIONS addendum 9): the distribution's own package,
        with what it needs, by apt as root (install.COMMAND; the password typed on its form handed to sudo for this
        one command, never kept), asked from its form alone and run by the platform as a job (JOB_HOOKS: `log` is its
        panel). Installing it filters nothing. Refused where a firewall tool is installed already, or there is no apt;
        apt's lock and a package not fetched are said in words."""
        say = _sayer(log)
        sh = self.shell
        if rights_mod.library() is None and not sh.root():
            raise ValueError(f"not from here: {rights_mod.old_words()}")
        tools = self.tools_here()
        if tools:
            raise ValueError(f"{', '.join(tools)} is installed here already: nftables is not installed beside it")
        if not self.apt_here():
            raise ValueError(f"there is no apt here to install it with: {INSTALL}")
        facts = self.install_facts(fresh=True)
        if facts.main is None:
            raise ValueError(f"nftables cannot be installed from here: {facts.problem}")
        say(f"Installing {facts.words}.")
        say("Installing it filters nothing: no rule is made, and what there is stays as it is.")
        try:
            out = rights_mod.run(sh, *install_mod.COMMAND, password=password, timeout=install_mod.TIMEOUT_S)
        except CommandError as e:  # a refused password is a WrongPassword, no CommandError: it passes as it is
            raise CommandError(install_mod.apt_words(e), denied=e.denied) from None
        finally:
            self.forget()
            with self._lock:
                self._install_facts = None
        shown = [x for x in out.splitlines() if x.strip()][-install_mod.SHOWN_LINES:]
        for line in shown:
            say(line)
        there = self.tools_here()
        said = (f"nftables installed: {facts.words}. It filters nothing until rules are made"
                if "nftables" in there else f"apt ended, but no nft is found here yet ({', '.join(there) or 'none'})")
        return {"said": said, "lines": shown}

    # -- the status ---------------------------------------------------------------------------------------------------
    def status(self) -> dict:
        """Valid whenever the firewall can be read (the Windows firewall plugin's rule): the base's "no Liminal rules"
        and "off" are said in the summary and the tables, not as invalid. When it cannot be read, or there is no
        firewall software, its tables say what the firewall needs here (needs_table: root for the read, a firewall
        tool) and, inside WSL, what WSL changes (0.8.1; the user: "still need linux firewall").

        0.9.0: valid too where the firewall cannot be read for want of a firewall tool or of root (B-revisions S2:
        "valid wherever it can serve anything"), with a `problem` and what it needs, offering only what it can do (the
        Root access switch, nftables' install) and its tabs asked; with a library from before the grant, as 0.8.1. How
        it has its rights is a fact (`rootAccess`); the switch is a row of its tables only if required, and a change's
        form has the password field only if required."""
        here = self.not_for_here()
        if here:  # not for this machine at all (on Windows or macOS): asked nothing, no setup offered
            return self.not_here_status(here, backend="", enabled=False, profiles={}, rules=[])
        try:
            cfg = self.config()
        except CommandError as e:
            return self.unread_status(e)
        if not cfg.manager:
            return self.bare_status()
        r = self.rights()
        with self._lock:
            preset, find = self._preset, self._find
        out = {"present": True, "backend": _named(cfg.manager, cfg), **cfg.state(), "summary": _summary(cfg), "valid": True,
               "why": "", "distribution": cfg.system.name, "kernel": cfg.system.kernel, "init": cfg.system.init_words,
               "readAt": time.strftime("%H:%M:%S", time.localtime(cfg.at))}
        if r.kind != "old":
            out["rootAccess"] = r.fact
        if cfg.problems:
            out["problems"] = list(cfg.problems)
        out["tables"] = [*tables(cfg, preset, find, self.groups, root=parts_root_row(r)), *under_wsl(r)]
        password = self.password_needed("changes", dict(TOOLS).get(cfg.manager, "nft"))
        out["forms"] = forms(cfg, password=password) + root_forms(r)
        out["actions"] = [dict(REFRESH)]
        return out

    def unread_status(self, error: CommandError) -> dict:
        """The status when the firewall cannot be read (0.9.0): valid with a `problem` where what is missing is root
        (Root access off, on from the platform's next start, or not this plugin's) or a firewall tool, and the library
        has the grant; and valid with a `problem` too whatever else kept the read from answering, wherever the Netstat
        tab is served (a library that has it, and the kernel's socket tables to read: netstat.serves), since none of
        it needs root (B-revisions S2: "valid wherever it can read the socket table"). Else not valid, as 0.8.1: a
        library from before the grant, or a read failing for its own reasons where the Netstat tab is not served."""
        r = self.rights()
        tools = self.tools_here()
        if self._lib() is None or not (r.shown or not tools or netstat_mod.serves()):
            return self._not_read(r, error, tools, present=True, summary=f"cannot be read: {error}",
                                  problem=str(error), why=f"cannot be read: {error}")
        wants_root = r.kind in ("off", "pending", "stale")
        problem = (PROBLEM[r.kind] if r.kind in PROBLEM
                   else f"The firewall's rules are not read: Root access is {r.state}." if wants_root
                   else f"The firewall's read failed: {error}." if r.kind == "on"
                   else f"The firewall cannot be read here: {error}.")
        if not tools:
            problem += " No firewall tool is installed here (nftables, iptables, ufw, firewalld)."
        summary = (f"not read: {UNREAD[r.kind]}" if wants_root else "not read: its read failed" if tools
                   else "not read: no firewall tool here")
        return self._not_read(r, error, tools, present=True, summary=summary, problem=problem)

    def bare_status(self) -> dict:
        """The status when the read ran and found no firewall software (0.9.0: valid with a `problem` and nftables'
        install where it can be offered, and present wherever the Netstat tab is served, as present() says; with a
        library from before the grant, not valid and not present, as 0.8.1)."""
        r = self.rights()
        if self._lib() is None:
            return self._not_read(r, None, [], present=False, summary="no firewall software here",
                                  why="no firewall software here: nftables, iptables, ufw or firewalld")
        return self._not_read(r, None, [], present=netstat_mod.serves(), summary="no firewall software here",
                              problem="No firewall tool is installed here (nftables, iptables, ufw, firewalld): "
                                      "nothing filters.")

    def _not_read(self, r: Rights, error: CommandError | None, tools: list[str], *, present: bool, summary: str,
                  problem: str | None = None, why: str | None = None) -> dict:
        """A status where the firewall's rules are not read, its tables saying what the firewall needs here and,
        inside WSL, what WSL changes: given `why`, not valid, as 0.8.1; else valid (B-revisions S2), with its
        `problem`, how it has its rights, and only what it can do (the Root access switch, nftables' install,
        Refresh). Whether the install is offered is asked once, for its row and its form."""
        offered = why is None and self.install_offered(tools)
        out = {"present": present, "backend": "", "enabled": False, "profiles": {},
               **({"problem": problem} if problem is not None else {}), "summary": summary, "valid": why is None,
               "why": why or "", "tables": [self.needs_table(error, tools, r, offered), *under_wsl(r)]}
        if why is None:
            out.update(rootAccess=r.fact, forms=root_forms(r) + self.install_forms(offered), actions=[dict(REFRESH)])
        return out

    def install_forms(self, offered: bool) -> list[dict]:
        """Install nftables's form where it is `offered` (install_offered), its words saying what it installs and its
        size first, and the password field where sudo cannot run apt without one."""
        if not offered:
            return []
        return [install_form(self.install_facts(), self.password_needed("install", *install_mod.COMMAND))]

    # -- what the firewall needs here (0.8.1): said when it cannot be read, or there is none ---------------------------
    def tools_here(self) -> list[str]:
        """The firewall tools installed on this machine, found without root by their files (no command run, nothing
        asked of sudo), in the folders root's PATH holds (TOOL_PATH): nftables, iptables, ufw, firewalld."""
        return [name for name, tool in TOOLS if self._tool(tool)]

    def needs_table(self, error: CommandError | None, tools: list[str], r: Rights, offered: bool) -> dict:
        """What the firewall needs here, as a table for the page: root for its read when the read was refused for want
        of it (`error`, denied: sudo -n asked for a password), or the read's own words when it failed otherwise; and a
        firewall tool, as installed (`tools`, tools_here's), with what to do for each.

        0.9.0, with the library's grant: the Root access row in place of root for the read (its state and its one
        action, Turn on... or Turn off..., in a fourth column), and the tool's row offering Install nftables... where it
        is `offered` (install_offered). With a library from before it, as 0.8.1, and the switch's library said. Last,
        what the Netstat tab and the hosts database need (netstat.needs_row): no rights, so they work meanwhile; or
        the library or the socket table they lack."""
        new = r.kind != "old" and self._lib() is not None
        rows = []
        if new and r.shown:
            rows.append(["Root access", r.state, root_todo(r), root_button(r)])
        elif error is not None and error.denied and not new:
            rows.append(["Root for the read", "sudo asks for a password", f"{ROOT_FOR_READ}; {rights_mod.old_words()}"])
        if error is not None and (not error.denied or (new and not r.shown)):
            rows.append(["The read", f"failed: {error}", "the read is put right where it failed; Refresh reads again"])
        here = (f"{', '.join(tools)} installed" if tools
                else "none installed: no nft, iptables, ufw or firewall-cmd here")
        if tools:
            rows.append(["A firewall tool", here, "none needed"])
        elif new and offered:
            facts = self.install_facts()
            rows.append(["A firewall tool", here,
                         f"Install nftables… installs {facts.words}; installing it filters nothing",
                         {"form": install_mod.FORM, "title": "Install nftables…", "values": {},
                          "label": "Install nftables"}])
        else:
            rows.append(["A firewall tool", here, INSTALL])
        # 0.9.0: what the Netstat tab and the hosts database need (no rights), in words that follow whether the platform
        # runs as root (then every socket's program is read)
        rows.append(netstat_mod.needs_row(root=r.kind == "root"))
        columns = [{"title": "What"}, {"title": "Here"}, {"title": "What to do"}]
        if new:
            columns.append({"title": ""})
            rows = [row + [""] * (4 - len(row)) for row in rows]
        return {"title": NEEDS_TITLE, "note": "What this plugin needs before it can read and change the firewall here.",
                "columns": columns, "rows": rows}

    # -- what the World Wide Web plugin's capture cannot see (0.14.0): from the firewall's last read ----------------------
    def capture_unseen(self, address) -> str:
        """What an XDP program at the adapter of `address` drops before the capture sees it (another plugin's read).

        0.14.0, for plugin-platform-worldwideweb (liminal-libs 1.105.0), whose capture watches that adapter: the words
        the World Wide Web tab of this plugin said until 0.13.0 (xdp_words), from the read kept, never a new one; "" for
        none, before a read, and for an address no adapter of the read holds. ValueError on a machine the plugin is not
        for."""
        here = self.not_for_here()
        if here:
            raise ValueError(f"not for this machine: {here}")
        kept = self._read
        return xdp_words(kept[1], address) if kept and isinstance(address, str) and address else ""

    # -- the Netstat tab (0.9.0): the base's, and what the firewall's own read knows that the socket table cannot ------
    def netstat_listeners(self) -> dict[tuple[str, int], str]:
        """The listening sockets the firewall's own read names by program ({(proto, port): program}: ss -ltnp and ss
        -lunp, as root, see every listener's program), which the base's Netstat tab uses for a listener whose program
        the socket table cannot say (another user's: only root reads which program holds it). From the read kept,
        never a new one, and without waiting on a read under way (the tab runs no command): {} before a read, and on a
        machine the plugin is not for."""
        if self.not_for_here():
            return {}
        kept = self._read
        return netstat_mod.listeners(kept[1]) if kept else {}

    def netstat(self) -> dict:
        """The Netstat tab's page: the listening ports and the open connections with the program behind each.

        The base's (liminal-libs 1.65.0), read from the kernel's socket tables with no command, no capture and no
        root, a listener another user holds named from the firewall's read kept (netstat_listeners); inside a WSL
        distribution its Under WSL table ends with what was seen in the user's Ubuntu (netstat.WSL_ROWS: a port
        listening here at 127.0.0.1 is reached from Windows too). LookupError with a library from before it."""
        base = getattr(super(), "netstat", None)
        if not callable(base):
            raise LookupError(f"the Netstat tab needs liminal-libs {netstat_mod.NETSTAT_LIBS}")
        return netstat_mod.with_wsl_rows(base())


def under_wsl(rights: Rights | None = None) -> list[dict]:
    """Inside a WSL distribution: what WSL changes for a firewall, as the last of the page's tables (the user, 2026-11-15:
    "if wsl prevents or misses some capability this should reflect in the plugin"; the library's linux.wsl_table: the
    packet filter WSL's kernel gives, WSL's network behind Windows' firewall). Nothing on a machine of its own, nor with a
    library from before the Linux plugins worked inside WSL (it refuses a WSL kernel, so the page says that instead).
    Where Root access is shown (0.9.0), a row more: what WSL lacks for it and what the switch does there."""
    table = getattr(linux_mod, "wsl_table", None)
    try:
        under = table("firewall") if callable(table) else None
    except Exception:  # noqa: BLE001 - a check that cannot say: nothing said
        return []
    if not under:
        return []
    if rights is not None and rights.shown and isinstance(under.get("rows"), list):
        under = {**under, "rows": [*under["rows"], WSL_ROOT_ROW]}
    return [under]


WSL_ROOT_ROW = ["Root access", "sudo inside this distribution, as on any Linux",
                "WSL lets Windows enter a distribution as root with no password (wsl -u root): the platform never "
                "does, nor reaches in from Windows, so root here is asked of this distribution's sudo, whose password "
                "is yours. Root access's rule and files are this distribution's alone, on its own disk, and stay "
                f"across its restarts; the group {rights_mod.GROUP} they name is given to programs started after "
                "it, so the platform has it once started again from a terminal opened after, or after Windows has "
                "stopped the distribution and started it again"]


def _sayer(log):
    """Each line said to `log` (the platform's job panel): nothing when there is none; a log that fails is let be."""
    if not callable(log):
        return lambda line: None

    def say(line: str) -> None:
        try:
            log(line)
        except Exception:  # noqa: BLE001 - the job goes on without its panel
            pass
    return say


# -- Root access on the page (0.9.0): its row, its button, its forms --------------------------------------------------
def root_todo(r: Rights) -> str:
    """What to do about Root access, in words (its row's)."""
    p = rights_mod.Paths.here()
    if r.kind == "off":
        return ("Turn on… gives root to the firewall's read alone, asking for your password once: the read installed "
                f"root-owned ({p.read}) and a sudoers rule ({p.rule}) letting it run without a password")
    if r.kind == "pending":
        return (f"start the platform again, from a terminal opened after it was turned on: a program started before, "
                f"the shell the platform was started from too, is not in the group {rights_mod.GROUP} yet "
                f"(newgrp {rights_mod.GROUP} in that shell gives it one); Turn off… takes it back")
    if r.kind == "stale":
        return "Turn on… again puts this plugin's read in its place; Turn off… takes it all back"
    return "nothing: Turn off… takes it back, with no password"


def root_button(r: Rights) -> dict | str:
    """Root access's one action as a button: Turn on... where it is off or not this plugin's, else Turn off..."""
    if r.kind in ("off", "stale"):
        return {"form": ROOT_ON, "title": "Turn on…", "values": {"state": "on"}, "label": "Turn Root access on"}
    if r.kind in ("on", "pending"):
        return {"form": ROOT_OFF, "title": "Turn off…", "values": {"state": "off"}, "label": "Turn Root access off"}
    return ""


def parts_root_row(r: Rights) -> list | None:
    """Root access as a row of the Firewall table where the firewall is read through it (on): its state, what it
    installed, and Turn off..."""
    if r.kind != "on":
        return None
    p = rights_mod.Paths.here()
    return ["Root access", r.state, "", _cell(p.read, f"run as root by {p.rule}, for the group {rights_mod.GROUP}"),
            root_button(r), ""]


ROOT_ON, ROOT_OFF = "root-on", "root-off"


def user_words() -> str:
    """The platform's user, for the words of Root access's forms ("you" when it cannot be told)."""
    who = rights_mod.user()
    return f"you ({who})" if who else "you"


def root_forms(r: Rights) -> list[dict]:
    """Root access's forms, where the switch is shown (only if required): Turn on... (where it is off, or its read is
    not this plugin's), its words saying exactly what is installed and where and that anything running as the
    platform's user (user_words, read for this form alone) can then run that one read as root, and the password field;
    Turn off... (where it is on), its password field only where the take-back helper cannot run without one yet."""
    if not r.shown:
        return []
    p = rights_mod.Paths.here()
    g = rights_mod.GROUP
    state = {"name": "state", "label": "Root access", "type": "fixed"}
    out = []
    if r.kind in ("off", "stale"):
        who = user_words()
        out.append({
            "id": ROOT_ON, "hook": ROOT_HOOK, "title": "Turn Root access on",
            "note": (f"Your password is handed to sudo for this once and never kept. Installed as root, by one "
                     f"script checked before anything is put in place: {p.read}, this plugin's read of the firewall as "
                     f"it runs it, which reads the whole configuration and changes nothing; {p.helper}, which takes "
                     f"all of this back; both root's, in {p.folder}, open to the group {g} alone; and {p.rule}, "
                     f"checked with visudo before it is put in place, letting the group {g} run exactly those two "
                     f"files as root without a password, with no arguments, and nothing else (never every command). "
                     f"The group {g} is made where there is none, and {who} put in it."),
            "fields": [state, PASSWORD_FIELD], "submit": "Review",
            "confirm": {"title": "Turn Root access on?", "yes": "Turn it on",
                        "words": (f"Anything running as {who}, or as another member of the group {g}, can then run "
                                  "that one read as root. Every change still asks for your password at its own click. "
                                  + ("It takes effect at once: the platform has the group already. " if r.grant.active
                                     else "It takes effect once the platform is started again from a terminal opened "
                                     "after this (the group is given to programs started after it). ")
                                  + "Turn off… takes it back with no password.")}})
    if r.kind in ("on", "pending", "stale"):
        out.append({
            "id": ROOT_OFF, "hook": ROOT_HOOK, "title": "Turn Root access off",
            "note": "" if not r.off_password else ("The take-back helper cannot run without a password until the "
                                                   "platform is started again: your password is handed to sudo for "
                                                   "this once and never kept."),
            "fields": [state, *([PASSWORD_FIELD] if r.off_password else [])], "submit": "Review",
            "confirm": {"title": "Turn Root access off?", "yes": "Turn it off",
                        "words": (f"{p.helper} removes {p.rule} and {p.folder}, and nothing else"
                                  + ("" if r.off_password else ", run through sudo with no password, as the grant "
                                     "allows") + f". The group {g} and its members stay (the Linux administration "
                                  "plugin manages them). The firewall's rules are then not read until it is turned "
                                  "on again.")}})
    return out


def install_form(facts: install_mod.Facts, password: bool) -> dict:
    """Install nftables's form (a job): its words give the package, what it needs and their size first, read without
    root; the password field only where sudo cannot run apt without one."""
    return {"id": install_mod.FORM, "hook": INSTALL_HOOK, "title": "Install nftables", "job": True,
            "note": (f"{facts.words[:1].upper()}{facts.words[1:]}, installed by apt (apt-get install -y nftables) as "
                     "root." + (" Your password is handed to sudo for this once and never kept." if password else "")),
            "fields": [PASSWORD_FIELD] if password else [], "submit": "Review",
            "confirm": {"title": "Install nftables?", "yes": "Install it",
                        "words": ("Installing it filters nothing: it adds the nft tool, the kernel's own firewall's, "
                                  "and no rule is made; what this page makes later is asked at its own click. Its "
                                  "progress shows in the panel below.")}}


def xdp_words(cfg: Config, address: str) -> str:
    """The XDP programs at the adapter holding `address` (and at the ports of its bridge or bond, which carry what comes in
    to it) as the read found them, in words; "" for none, or for an address no adapter of the read holds."""
    try:
        watched = ipaddress.ip_address(str(address).split("%")[0])
    except ValueError:
        return ""

    def holds(interface) -> bool:
        for a in interface.addresses:
            try:
                if ipaddress.ip_address(str(a).split("/")[0].split("%")[0]) == watched:
                    return True
            except ValueError:
                continue
        return False
    interfaces = list(cfg.system.interfaces or ())
    adapter = next((i for i in interfaces if holds(i)), None)
    if adapter is None:
        return ""
    at = [i for i in interfaces if i.xdp and adapter.name in (i.name, i.master)]
    if not at:
        return ""
    where = "; ".join(f"{i.name}: {i.xdp}" for i in at)
    return (f"The firewall's last read found XDP at the adapter watched ({where}): what XDP drops never reaches libpcap, "
            "so it is neither counted nor drawn here; what nftables and iptables drop is, as unanswered.")


def liminal_ports() -> frozenset:
    """The framework's own pages' ports (the library's app_ports): a program listening on one is Liminal's."""
    return frozenset(app_ports().values())


def _named(manager: str, cfg: Config) -> str:
    if manager == "ufw":
        return f"ufw {cfg.ufw.version}".strip()
    if manager == "firewalld":
        return f"firewalld {cfg.firewalld.version}".strip()
    if manager == "nftables":
        return f"nftables {cfg.nft_version}".strip()
    if manager == "iptables":
        return f"iptables {cfg.iptables_version} ({cfg.iptables_variant or 'legacy'})"
    return manager


def _summary(cfg: Config) -> str:
    m = cfg.manager
    on = "on" if cfg.state().get("enabled") else "off"
    over = f" over nftables {cfg.nft_version}" if cfg.nft is not None and m != "nftables" else ""
    listed = cfg.listed()
    off = sum(1 for e in listed if e.off)
    return (f"{_named(m, cfg)}{over}: {on}; {len(listed)} rule(s) read" + (f", {off} of them turned off" if off else "")
            + f", {len(cfg.liminal_rules())} of them Liminal's; {cfg.system.name}, {cfg.system.init_words}")


# -- the tables (liminal-platform 0.7.0: a table's own options and actions; cell buttons opening forms) ----------------------
def _cell(text, sub=None):
    return {"text": text, "sub": sub} if sub else text


def _when(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else ""


def parts_table(cfg: Config, root: list | None = None) -> dict:
    """The firewall's parts: what is there, its state and version, what it holds, how its rules last, its switch."""
    s = cfg.system
    rows = []
    switch = dict(ch.switches(cfg))
    saving = set(ch.saveable(cfg))

    def toggle(part):
        if part not in switch:
            return ""
        on = switch[part]
        return {"form": "switch", "title": "Turn off…" if on else "Turn on…", "values": {"part": part, "state": "off" if on else "on"},
                "label": f"Turn {part} {'off' if on else 'on'}"}

    def save(kind):
        if kind not in saving:
            return ""
        return {"form": "save", "title": "Save…", "values": {"kind": kind}, "label": f"Save {kind}' rules for the next restart"}

    def boot(name):
        sv = s.service(name)
        if not sv.present:
            return ""
        return f"{name} service: {'running' if sv.running else 'stopped' if sv.running is False else 'state not known'}" + (
            ", at boot" if sv.at_boot else ", not at boot" if sv.at_boot is False else "")

    def kept(kind):
        k = s.keeping(kind)
        if k.how == "none":
            return k.note
        when = _when(s.files.get(k.path, 0))
        return f"kept in {k.path}" + (f" (changed {when})" if when else " (not there yet)") + f": {k.note}"

    if cfg.nft is not None or "nft" in cfg.tools:
        rs = cfg.nft
        holds = f"{len(rs.tables)} tables, {len(rs.chains)} chains, {len(rs.rules)} rules, {len(rs.sets)} sets" if rs else "its ruleset could not be read"
        sub = "; ".join(x for x in (boot("nftables"), kept("nftables") if cfg.manager == "nftables" else "") if x)
        rows.append(["nftables", "in charge" if cfg.manager == "nftables" else "the kernel's filter", cfg.nft_version,
                     _cell(holds, sub or None), toggle("nftables"), save("nftables")])
    if cfg.saved or "iptables" in cfg.tools:
        variant = cfg.iptables_variant or "legacy"
        n = sum(len(x.rules) for x in cfg.saved.values())
        legacy = sum(len(x.rules) for x in cfg.legacy.values())
        holds = f"{n} rules (iptables and ip6tables)" + (f"; {legacy} more in the legacy x_tables, beside nftables" if legacy else "")
        if variant == "nf_tables":
            holds += "; its tables are nftables'"
        sub = "; ".join(x for x in (boot("iptables") or boot("netfilter-persistent"), kept("iptables") if cfg.manager == "iptables" else "") if x)
        rows.append(["iptables", "in charge" if cfg.manager == "iptables" else variant, f"{cfg.iptables_version} ({variant})",
                     _cell(holds, sub or None), toggle("iptables") or toggle("netfilter-persistent"), save("iptables")])
    for tool, (version, variant) in (("ebtables", cfg.ebtables), ("arptables", cfg.arptables)):
        if version or tool in cfg.tools:
            rows.append([tool, variant or "there", f"{version} ({variant})" if variant else version,
                         "bridge filtering" if tool == "ebtables" else "ARP filtering", "", ""])
    if cfg.ipsets or "ipset" in cfg.tools:
        n = sum(x.entries for x in cfg.ipsets)
        names = ", ".join(x.name for x in cfg.ipsets[:6])
        rows.append(["ipset", f"{len(cfg.ipsets)} sets", cfg.ipset_version, f"{n} entries" + (f": {names}" if names else ""), "", ""])
    f = cfg.firewalld
    if f.installed:
        sub = "; ".join(x for x in (f"on {f.backend}" if f.backend else "", boot("firewalld"), "keeps its own rules") if x)
        rows.append(["firewalld", "running" if f.running else "stopped", f.version,
                     _cell(f"default zone {f.default_zone or '?'}; {sum(1 for z in f.zones if z.active)} active zones", sub), toggle("firewalld"), ""])
    u = cfg.ufw
    if u.installed:
        d = u.defaults
        rows.append(["ufw", "on" if u.active else "off", u.version,
                     _cell(f"{len(u.rows) if u.active else len(u.added)} rules; by default {d.get('incoming', '?')} in, "
                           f"{d.get('outgoing', '?')} out, {d.get('routed', '?')} routed", f"logging {u.logging or '?'}; keeps its own rules"),
                     toggle("ufw"), ""])
    count, top = s.conntrack
    if count is not None:
        rows.append(["conntrack", "tracking", "", f"{count} of {top} connections tracked" if top else f"{count} connections tracked", "", ""])
    xdp = [f"{i.name}: {i.xdp}" for i in s.interfaces if i.xdp]
    if xdp or s.bpf:
        rows.append(["eBPF and XDP", "read only", "", "; ".join(xdp + [b for b in s.bpf if not b.startswith("xdp")]) or "none attached", "", ""])
    if root:  # 0.9.0: Root access, where the firewall is read through it
        rows.append(list(root))
    note = f"{s.name} (kernel {s.kernel}), {s.init_words}" + (f"; read {time.strftime('%H:%M:%S', time.localtime(cfg.at))}" if cfg.at else "")
    if cfg.problems:
        note += "; not read: " + "; ".join(cfg.problems)
    return {"title": "Firewall", "note": note, "columns": [{"title": "Part"}, {"title": "State"}, {"title": "Version"},
            {"title": "What it holds"}, {"title": ""}, {"title": ""}], "rows": rows, "empty": "No firewall software here."}


def interfaces_table(cfg: Config) -> dict:
    zone_of = {}
    for z in cfg.firewalld.zones:
        for i in z.words("interfaces"):
            zone_of[i] = z.name
    default = f"{cfg.firewalld.default_zone} (default)" if cfg.firewalld.running and cfg.firewalld.default_zone else ""
    rows = [[i.name, i.state or "?", _cell(", ".join(i.addresses[:3]) or "no address", ", ".join(i.addresses[3:]) or None),
             zone_of.get(i.name, default if i.name != "lo" else ""), i.xdp] for i in cfg.system.interfaces]
    return {"title": "Interfaces", "columns": [{"title": "Interface"}, {"title": "State"}, {"title": "Addresses"},
            {"title": "Zone"}, {"title": "XDP"}], "rows": rows, "empty": "None read (no ip command)."}


def zones_table(cfg: Config) -> dict | None:
    f = cfg.firewalld
    if not f.installed or not f.zones:
        return None
    rows = []
    takes = cfg.unbound_interfaces()
    for z in sorted(f.zones, key=lambda z: (not z.active, not z.default, z.name)):
        if not (z.active or z.default):
            continue
        off = fwd_mod.off_of(z, True, takes) if z.default else ""  # the default zone taking no interface in use (0.6.0)
        rows.append([_cell(z.name, ("default" + (f"; turned off: {off}" if off else "")) if z.default else None),
                     " ".join(z.words("interfaces") + z.words("sources")) or "–",
                     z.target, " ".join(z.words("services")) or "–", " ".join(z.words("ports")) or "–", len(z.rich),
                     {"form": "policy", "title": "Target…", "values": {"where": f"zone {z.name}", "policy": z.target},
                      "label": f"Set the zone {z.name}'s target"}])
    others = [z.name for z in f.zones if not (z.active or z.default)]
    return {"title": "Zones", "note": "firewalld's zones in force" + (f"; bound to nothing: {', '.join(others)}" if others else ""),
            "columns": [{"title": "Zone"}, {"title": "Interfaces and sources"}, {"title": "Target"}, {"title": "Services"},
                        {"title": "Ports"}, {"title": "Rich rules", "num": True}, {"title": ""}], "rows": rows}


def policies_table(cfg: Config) -> dict:
    rows = []
    for p in ch.policies(cfg):
        if p.kind == "firewalld":
            continue  # in the Zones table
        rows.append([p.where, OWNER_WORDS.get("own") if p.kind in ("nftables", "iptables", "ip6tables") else p.kind, p.current or "unset",
                     "what comes in" if p.inbound else "", {"form": "policy", "title": "Set…", "values": {"where": p.where, "policy": p.current},
                                                            "label": f"Set {p.where}'s default"}])
    settable = {p.where for p in ch.policies(cfg)}
    if cfg.nft is not None:  # the other base chains, read only: another program's, or a front end's machinery
        skip, dormant = cfg.skipped_tables(), cfg.dormant_tables()
        for c in cfg.nft.chains:
            if c.base and (c.family, c.table) not in skip and c.key not in settable:
                t = cfg.nft.table(c.family, c.table)
                owner = nft_mod.table_owner(t, cfg.nft.chains) if t else "own"
                rows.append([c.key, OWNER_WORDS.get(owner, owner), c.policy or "accept", f"{c.type} {c.hook}, priority {c.prio}"
                             + (f"; turned off: {nft_mod.DORMANT}" if (c.family, c.table) in dormant else ""), ""])
    for tool, saved in cfg.saved.items():  # iptables' built-in chains, read only unless iptables is in charge
        for c in saved.chains:
            where = f"{tool} {c.table} {c.name}"
            if c.policy != "-" and c.table == "filter" and where not in settable:
                whose = "ufw" if cfg.ufw.installed and c.name in ("INPUT", "FORWARD", "OUTPUT") else f"iptables ({cfg.iptables_variant or 'legacy'})"
                rows.append([where, whose, c.policy, "what comes in" if c.name == "INPUT" else "", ""])
    hidden = ", ".join(f"{OWNER_WORDS.get(k, k)}'s {n}" for k, n in cfg.hidden.items())
    return {"title": "Default policies", "note": ("What each does with what no rule decides; other programs' chains are read only"
            + (f". A front end's own machinery is shown through it ({hidden} rules)" if hidden else "")),
            "columns": [{"title": "Where"}, {"title": "Whose"}, {"title": "Default"}, {"title": "For"}, {"title": ""}],
            "rows": rows, "empty": "No default policy here."}


GROUP_NOTES = {
    "system": "the system's own, by service (SSH, DNS, DHCP, NTP...), with its own traffic, ICMP and invalid packets",
    "application": "a program's, by program: one making its own rules (Docker's, Liminal's...), or one listening on the port",
    "other": "tied to no program or service: a port or an address alone",
}


def rules_table(cfg: Config, preset: str, find: str, groups: RuleGroups | None = None) -> dict:
    """The rules shown, in their groups (0.5.0): System, Application, Other and the user's labels; System's by service and
    Application's by program (0.6.0), each service, program and Other listing its first MAX_ROWS (Find finds a rule by
    its heading's name too); a rule's group and name found by groups.sort_entry, or its group where the user moved it. A
    rule turned off is listed too, dimmed (0.6.0)."""
    listed = cfg.listed()
    ports = liminal_ports()
    sorts = [(e, sort_entry(e, cfg.system.listening, cfg.system.listening_udp, ports)) for e in listed]
    picked = [(e, s) for e, s in sorts if e.shown(preset) and e.found(find, s.name)]
    shown = [e for e, _ in picked]
    rows = []
    for e, s in picked:
        does = e.action + (f" {e.target}" if e.target and e.action in ("jump", "goto", "nat") else "")
        port = f"{e.protocol} {e.ports}".strip() if e.ports or e.protocol else "every"
        frm = e.source or ("anywhere" if e.direction in ("in", "fwd") else "")
        button = ({"form": "remove", "title": "Remove…", "values": {"where": e.where, "rule": e.text}, "label": f"Remove {e.text}"}
                  if e.removable else "")
        row = (rule_key(e), s, [
            _cell(e.where, f"{e.kind}, turned off: {e.off}" if e.off else e.kind), DIRECTIONS.get(e.direction, e.direction), does,
            port, _cell(frm, f"on {e.interface}" if e.interface else None) if frm or e.interface else "", e.destination,
            _cell(e.text, e.comment if e.comment and e.comment not in e.text else None), OWNER_WORDS.get(e.owner, e.owner), button])
        rows.append((*row, {"off": True}) if e.off else row)
    off = sum(1 for e in shown if e.off)
    note = (f"{len(shown)} of {len(listed)} rules" + (f", {off} of them turned off (they filter nothing now)" if off else "")
            + (f"; finding {find!r}" if find else "")
            + ". A program's own rules (Docker's...) are read only: it makes them again. Moving a rule to another group changes"
            " nothing in the firewall.")
    actions = [{"form": "make", "title": "Add a rule…"}, {"form": "find", "title": "Find…", "values": {"words": find}},
               {"hook": "refresh", "args": [], "title": "Refresh", "note": "reads the whole configuration again now"}]
    if find:
        actions.insert(2, {"hook": "find_rules", "args": [""], "title": "Show all", "note": "the Find's words cleared"})
    base = {"title": "Rules", "note": note,
            "options": [{"title": "Rules shown", "hook": "show_rules", "value": preset,
                         "choices": [{"value": v, "title": t, "note": n} for v, t, n in PRESETS]}],
            "columns": [{"title": "Where"}, {"title": "Way"}, {"title": "Does"}, {"title": "Port"}, {"title": "From"},
                        {"title": "To"}, {"title": "Rule"}, {"title": "Whose"}, {"title": ""}],
            "empty": "No rule of the choice shown" + (" with those words." if find else "."), "actions": actions}
    return (groups or RuleGroups("", lambda: None)).table(base, rows, per_group=MAX_ROWS, notes=GROUP_NOTES)


def sets_table(cfg: Config) -> dict | None:
    rows = [[f"{s.family} {s.table} {s.name}", f"nftables {s.kind}", s.type, s.elements] for s in (cfg.nft.sets if cfg.nft else [])]
    rows += [[x.name, "ipset", x.type, x.entries] for x in cfg.ipsets]
    if not rows:
        return None
    return {"title": "Sets", "columns": [{"title": "Set"}, {"title": "Kind"}, {"title": "Type"}, {"title": "Elements", "num": True}],
            "rows": rows}


def tables(cfg: Config, preset: str = "in-allow", find: str = "", groups: RuleGroups | None = None,
           root: list | None = None) -> list[dict]:
    out = [parts_table(cfg, root), interfaces_table(cfg)]
    z = zones_table(cfg)
    if z:
        out.append(z)
    pol = policies_table(cfg)
    if pol["rows"] or not z:
        out.append(pol)
    out.append(rules_table(cfg, preset, find, groups))
    s = sets_table(cfg)
    if s:
        out.append(s)
    return out


# -- the forms (liminal-platform 0.6.0: a hook asked with what is filled in, once the change is confirmed) ------------------
ACCEPT_FIELD = {"name": ACCEPT, "type": "accept", "title": "Go on anyway?", "yes": "Go on anyway",
                "words": "Accepting it makes the change as confirmed, knowing what is said above."}


def _choices(rows) -> list[dict]:
    return [{"value": v, "title": t, **({"note": n} if n else {})} for v, t, n in rows]


CHANGE_FORMS = ("make", "remove", "policy", "switch", "save")  # the forms that change the firewall, as root


def forms(cfg: Config, password: bool = False) -> list[dict]:
    """The page's forms. With `password` (0.9.0: sudo cannot run a change without one), each form that changes the
    firewall ends with the password field, and its hook takes it as its last argument."""
    out = _forms(cfg)
    if password:
        out = [{**f, "fields": [*f["fields"], PASSWORD_FIELD]} if f["id"] in CHANGE_FORMS else f for f in out]
    return out + RuleGroups.forms()  # a label made, renamed or removed (0.5.0)


def _forms(cfg: Config) -> list[dict]:
    manager = _named(cfg.manager, cfg)
    lasting = (" It lasts until the next restart unless saved (the Firewall table's Save)." if cfg.manager in ("nftables", "iptables")
               else f" {cfg.manager} keeps it itself." if cfg.manager in FRONTS else "")
    out = [
        {"id": "make", "hook": "make_rule", "title": "Add a rule",
         "note": f"Made through {manager}, as one of Liminal's rules under the name given.{lasting}",
         "fields": [
             {"name": "name", "label": "Name", "type": "text", "required": True, "placeholder": "web, office-ssh",
              "note": "lowercase letters, digits and dashes"},
             {"name": "direction", "label": "Way", "type": "choice", "value": "in",
              "choices": _choices([("in", "Coming in", "to this machine"), ("out", "Going out", "from this machine"),
                                   ("fwd", "Passing through", "forwarded: containers, VMs, routing")])},
             {"name": "action", "label": "Does", "type": "choice", "value": "allow",
              "choices": _choices([("allow", "Allow", ""), ("block", "Block", "dropped without a word"),
                                   ("reject", "Reject", "refused: the sender is told")])},
             {"name": "protocol", "label": "Protocol", "type": "choice", "value": "tcp",
              "choices": _choices([("tcp", "TCP", ""), ("udp", "UDP", ""), ("any", "Any", "every protocol, no ports")])},
             {"name": "ports", "label": "Ports", "type": "text", "placeholder": "22, 80, 443, 8000-8100",
              "note": "on this machine; none for every port", "empty": "every port"},
             {"name": "remote", "label": "The other side", "type": "text", "placeholder": "10.0.0.0/8, 192.168.1.20, 2001:db8::/32",
              "note": "an address or a network; none for anywhere", "empty": "anywhere"},
             {"name": "interface", "label": "Interface", "type": "text", "placeholder": "eth0, wg0", "empty": "every interface"},
             ACCEPT_FIELD],
         "submit": "Review the rule",
         "confirm": {"title": "Make the rule {name}?",
                     "words": f"{{action}}, {{protocol}} {{ports}}, {{direction}}, the other side {{remote}}, on {{interface}}: made through {manager}.{lasting}",
                     "yes": "Make the rule"}},
        {"id": "remove", "hook": "remove_rule", "title": "Remove a rule",
         "fields": [{"name": "where", "label": "Where", "type": "fixed"}, {"name": "rule", "label": "Rule", "type": "fixed"}, ACCEPT_FIELD],
         "confirm": {"title": "Remove this rule?", "words": "{rule} is removed from {where}." + lasting, "yes": "Remove the rule",
                     "danger": True}},
        {"id": "find", "hook": "find_rules", "title": "Find rules", "confirm": False,
         "note": ("Every word must be in the rule, or in the name of the service or program it is listed under (any case); "
                  "a number finds the rules for that port too."),
         "fields": [{"name": "words", "label": "Words", "type": "text", "placeholder": "22, docker, 10.0.0.0/8, drop",
                     "note": "none shows every rule of the choice"}],
         "submit": "Find"},
    ]
    pol = ch.policies(cfg)
    if pol:
        found = {c for p in pol for c in p.choices}
        out.append({"id": "policy", "hook": "set_policy", "title": "Set a default policy",
                    "note": "What it does with what no rule decides: allow, deny or reject for ufw; accept or drop for nftables; "
                            "ACCEPT or DROP for iptables; a target for a firewalld zone.",
                    "fields": [{"name": "where", "label": "Where", "type": "fixed"},
                               {"name": "policy", "label": "Default", "type": "choice",
                                "choices": [{"value": c, "title": c, "note": POLICY_NOTES.get(c, "")} for c in POLICY_ORDER if c in found]},
                               ACCEPT_FIELD],
                    "submit": "Review",
                    "confirm": {"title": "Set {where}'s default to {policy}?", "words": "{where} does {policy} with what no rule decides.",
                                "yes": "Set it"}})
    if ch.switches(cfg):
        out.append({"id": "switch", "hook": "switch", "title": "Turn it on or off",
                    "fields": [{"name": "part", "label": "Part", "type": "fixed"}, {"name": "state", "label": "Turned", "type": "fixed"},
                               ACCEPT_FIELD],
                    "confirm": {"title": "Turn {part} {state}?", "words": "{part} is turned {state}, now and at boot.", "yes": "Yes, turn it"}})
    if ch.saveable(cfg):
        keep = {k: cfg.system.keeping(k) for k in ch.saveable(cfg)}
        words = " ".join(f"{k}: {v.note}" + (f" ({v.path}; the file before is kept beside it)." if v.how == "file"
                                             else f" ({' '.join(v.command)})." if v.how == "command" else ".") for k, v in keep.items())
        out.append({"id": "save", "hook": "save_rules", "title": "Save the rules",
                    "fields": [{"name": "kind", "label": "Rules", "type": "fixed"}],
                    "confirm": {"title": "Save {kind}' rules for the next restart?", "words": words, "yes": "Save them"}})
    return out


MACHINE = LinuxFirewallPlugin()
