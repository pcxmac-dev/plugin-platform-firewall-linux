# Changelog

## 0.11.0 (2026-11-25)

Services' networks through this firewall, on liminal-libs 1.96.0's NetworkHost (service-containers-networking-2026-11-23.md
§5.4 to §5.7; decision 20 as changed to (b), N9, N10; SERVICE-INTERFACE.md §9: "wsl"). Floor: liminal-libs 1.96.0. On
0.10.0 (the review's PLT-H1, not landed).
- **Its stack:** inside a WSL distribution it owns "wsl" (every Linux inside WSL 2 shares one VM's network: N9, the
  Linux platform's firewall-linux is its one writer), on a machine of its own "linux"; it hands out from the Linux half
  of Liminal's pool (10.77.128.0/17) and names under linux.<domain>. A bridge on this host is a connected route: none
  is made; a nested segment (LXD's Docker inside liminal-oci) gets `ip route replace <its /24> via <liminal-oci>`.
- **The limit (decision 20 b):** on a machine of its own, a service's published ports opened to your network keep new
  connections to your subnets (the interfaces carrying a default route, never an engine's bridge): DOCKER-USER rules
  where Docker's iptables backend has that chain (established traffic first, the original destination port matched
  through conntrack), else a forward chain at priority -1 in Liminal's own `inet liminal` table; never Docker's own
  tables, never a flush. Taken away by its mark alone. Inside WSL nothing is written for it (WSL's NAT: Windows'
  firewall opens the port).
- **Marks with the platform:** `liminal:svc-<owner>-<name>-<port> platform=<the platform that made it>`.
- **`accept_shared`:** inside WSL, while another distribution's engine is seen in its one network (its bridges here,
  no engine of this distribution's own), every plan that makes or opens asks a second time.
- **Root without a password:** a plan's script runs as root through sudo -n (Root access, or a rule of yours), one
  `sh -s` per plan; a change that needs your password is refused in words before anything runs (a service's work has
  no form to type it into).
- **Names, DHCP records, the Networks tab, no default domain:** the library's (you set the domain; no service is placed
  until you do). Page-only: the base's other changes too (labels, moves, recording, watching, downloads).
- The plugin's own `_facts` (what installing nftables takes) is `_install_facts` now: NetworkHost's `_facts` is a
  method of the same name.
- Tests: tests/test_networks.py (10), the library's conformance sequence among them inside WSL; each of its 12 gates
  taken out once made a test fail.

## 0.10.0 (2026-11-24)

run() runs a command as the platform's own user, and as root only when asked (the independent review's finding
PLT-H1, rated high, checked 2026-11-23). The user, 2026-11-23, of liminal-platform's route that handed run() any
words: "Remove it" (gone since liminal-platform 0.34.1). And from the review of that change, 2026-11-24, each finding
checked a second time: the framework's allow reads its remote as the form does, the changes are asked only from the
page, a command refused for want of root says what helps, and the library it needs is 1.80.0.

- **As you unless elevated** (`run(*command, elevated=False)`). It asked the library's `Shell.run` for root, its
  default (`sudo -n`, or nothing in front when the platform is root), for every command. With the platform's
  `POST /api/machines/<name>/run`, which passed it any list of words, any program on this machine could run what it
  liked as root wherever the platform could: a platform that is root, or sudo without a password. The route's only
  checks were its bind to 127.0.0.1, a Host header the client chooses and a constant header anyone can send. Now a
  command runs as the platform's own user, and as root only when its caller says `elevated`, through the library's
  `sudo -n --` (liminal-libs 1.80.0: no word of the command is read as sudo's), never asking a password: a command
  sudo wants a password for fails in words. A platform that is root runs it as root, as itself. Its other options
  change nothing (`root=True` among them). admin-linux's run() was so already.
- **The command line: `run [--elevated] -- COMMAND`.** `--elevated` counts only as run's first word, before the
  command's `--`; every word after `--` is the command's own (`run -- x --elevated` runs x with that word, as you).
  No command: the usage, and nothing is run. The platform's command line has no `--elevated`: its
  `liminal-platform machine firewall-linux run -- COMMAND` runs the command as you.
- **The framework's allow reads its remote as the form does** (`add_rule`; the review's first finding, rated high,
  there since 0.4.0). The base's `allow` made one of Liminal's rules from its remote as it was given, with no second
  confirmation. nft joins its words and reads them as one script, a `;` between commands, so a remote of
  `1.2.3.4 accept;flush ruleset;...` flushed the whole ruleset as root, Docker's and ufw's tables with it, wherever
  the platform runs nft as root. Now the remote is read as the Add a rule form's other side (`model.parse_address`:
  "any" for anywhere, else an address or a network, written canonically), and anything else is a FirewallError
  before anything runs. A zone (`fe80::1%eth0`) is refused in the form too: Python's ipaddress keeps whatever follows
  the `%` as it was typed, a space and a `;` among it. And a `Spec`, what every plan to make a rule is made from,
  checks its name, its other side and its interface however it is made, so no word reaches a command unread.
- **The changes are asked only from the page** (`PAGE_ONLY_HOOKS`, liminal-libs 1.66.0's word; the review's second
  finding, rated medium): a rule made or removed, a default policy, on and off, saving, Root access, nftables'
  install, and the base's allow and remove. Another plugin's ask of one is refused (403), and liminal-platform 0.34.0
  refuses one over HTTP (401) unless its login shows that you are at the page. Before, any program on this machine
  asked them with the two headers PLT-H1 named, a second confirmation being only an argument (`accept_risk`): ufw
  turned off, a rule letting everyone reach every port, Root access taken back. A platform that holds no login asks
  them as before. The setup and the command line call the plugin's code in their own process, not through an ask, so
  they work as before; so do its reads.
- **A command refused for want of root says what helps** (run's words). The library words every such refusal alike:
  run the platform as root, or let sudo run it without a password. Run as you, such a rule changes nothing: the same
  command fails again. So the words go on: it ran as you, not through sudo, and a rule letting sudo run it counts
  only for `python -m plugin_platform_firewall_linux run --elevated -- COMMAND`; the platform's command line has no
  `--elevated`. Elevated, or with a platform that is root, the library's words stay as they are.
- `pyproject.toml`: liminal-libs[geo]>=1.80.0, the release whose Shell puts `sudo -n --` before a command run as root.
  run --elevated relies on it: with an older one `run --elevated -- -u nobody id` runs id as nobody, sudo reading `-u`
  as its own, and the tests passed there, sudo's words read from that library.
- Tests: `tests/test_run.py`, over a stand-in shell: a command as you, as root only when elevated (sudo's words read
  from the library's Shell, `machines.shell_sudo()`), its words given as they are, a dash first too, a platform that
  is root, and the command line's cases; sudo's words ending with `--` and the package's floor at 1.80.0; a command
  refused for want of root, as you, elevated and as root. `tests/test_plugin.py`: the framework's allow refusing the
  review's remotes and running nothing, a network written canonically; a Spec refusing what reaches a command
  unread. `tests/test_read.py`: a zone refused. `tests/test_who_asks.py`: the changes refused to another plugin and to
  no one through the library's own App, nothing run, the page's ask run, its reads asked by anyone.

## 0.9.2 (2026-11-24)

A firewalld rule that fails part way is taken back (the review of 2026-11-21, item 26, finding 16).

- **What a make saved before failing is taken back** (`changes.py` `Plan.undo`, `_run`). Under firewalld a rule is a
  service made first (`--new-service=liminal-<name>`), then its description, its ports, the zone's use of it and the
  reload. A step failing after the service was made left it in no zone: the page's rules come only from the services a
  zone uses, so it was not seen, and every later make of the name failed on NAME_CONFLICT. Now a plan names what takes
  it back: for firewalld, the zone's use of the service, then the service (`--delete-service`), each unchecked. The
  failure says them after the steps done before it ("taken back as it failed part way: ...").
- **A service of Liminal's left in no zone is replaced by a make of its name.** One left so by an earlier version is
  removed first, unless firewalld's saved configuration still names it in a zone or a policy (then the make stops in
  words: remove it there, or reload firewalld). One used in a zone or a policy not in force now is a rule of that name
  there already: refused before anything runs, as one in force is.
- Tests: `test_a_firewalld_rule_failing_part_way_is_taken_back_and_made_again`,
  `test_a_firewalld_service_of_liminals_left_in_no_zone_is_replaced_by_a_make_of_its_name`, over the recorded Fedora
  43 machine with a stand-in that keeps firewalld's saved services.

## 0.9.1 (2026-11-19)

Backbone networks on the globe, and a globe that zooms to 96x. The user, 2026-11-19: "i need to zoom in a few more
times maybe 96x"; "also on the firewall theres no real ibone or major hub s drawn on the map, data centers in the world
(dataset) and major network 'bones' need to be displayed on the map"; "also underwater lines". And, 2026-11-16: "the
firewall globe should instead of exchanges, have all the backbones,ibones, major internet infrastructure, (as many as
possible) datacenter locations." The globe is liminal-libs 1.65.1's: it now zooms to 96x (was 12x), with Natural
Earth's 1:10m map past 12x and GSHHG's coasts and borders past 24x (LGPL-3.0, credited while drawn). This plugin names
what the globe draws.

- **A sixth data set: backbone networks, about 2010-2011** (`apis.py`, `topology-zoo`). The Internet Topology Zoo's
  261 maps of networks (GÉANT, Internet2, ESnet, Sprint, NTT, Cogent and more): one archive of GML files on GitHub,
  348,613 bytes, under CC BY 4.0. Of each network, its newest map is drawn: its points of presence, and the links
  between them as great circles. They are logical links of about 2010-2011, placed at their cities, not today's fibre
  routes. Its licence's words are shown whole before the download. Its credit is drawn wherever its networks are:
  "Internet Topology Zoo (Knight, Nguyen, Falkner, Bowden, Roughan, IEEE JSAC 2011), Adelaide University, CC BY 4.0".
- **Submarine cables** (`osm-cables`, ODbL 1.0, about 3 MB) are asked of all eight telecom categories, as before. The
  Windows plugin now asks the same, so the two name the same six data sets in the same order, and both tests pin one
  digest.
- **Telecom lines on land, those on power poles left out** (`osm-lines`, ODbL 1.0): about 13,000 ways, about 15 MB
  (was 20 MB; both estimates). Lines on power poles are local distribution, not backbones.
- **Wikidata's data centres of every kind** (`wikidata`, CC0, about 0.2 MB): asked with their subclasses, so
  colocation centres come too (211 items, not 168), about 340 places in all.
- **A fifth card for the globe**, the Internet Topology Zoo, its pages read on 2026-11-19 (`GLOBE_VERIFIED`). Its
  facts list the data set.
- `pyproject.toml`: liminal-libs[geo]>=1.65.1, the release that reads the Topology Zoo's maps. On 1.65.0 that one
  data set is left out, in words, and the others work.
- Not here yet: Wikipedia's list of exchange points (CC BY-SA 4.0, placed only at their cities) and NOAA's cables in
  US waters (CC0). Each needs more than one request, and a data set here is one.

Tests: test_netstat.py (the six data sets with the gml card; the digest, the Windows plugin's; a stand-in NORDUnet map
read into backbones and their points of presence); test_apis.py (the cards' order and the dates they were read).

## 0.9.0 (2026-11-18)

The Netstat tab, the hosts database, and the globe's filters and internet infrastructure. The user, 2026-11-16: "the
firewall app should have a 'netstat' like interface for looking at active ports and what apps they are attached to,
and the hosts that they connect to across the lan or wan. the firewall app should also have a globe that can be
zoomed and rotated and geoip'd hosts are databased for the apps they talk to, the time they are connected to *this
*computer"; "the globe-firewall should allow filtering, so i can view apps connected to hosts all across the globe, or
ports talking to all hosts. The globe should have the same kind of geography associated with the exchanges globe, but
the firewall globe should instead of exchanges, have all the backbones,ibones, major internet infrastructure, (as many
as possible) datacenter locations." The tab, the database, the filters and the layers are liminal-libs 1.65.0's
Firewall base's; the plugin names what they reach (`apis.py`) and what is Linux's own (`netstat.py`).
liminal-platform 0.33.0 draws the layers.

- **Netstat**, a tab after World Wide Web, asked every 3 s while it is shown: the kernel's socket tables
  (`/proc/net/tcp`, `tcp6`, `udp`, `udp6`) read as files, as the platform's user: no command, no capture, no root, no
  window, no name looked up. Each socket with its program, pid and systemd unit where it is the platform's user's own
  (only root may read which program holds another user's, so such a socket is listed without it, in words), the
  remote host and port, whether that host is this machine's, the local network's or the internet's, its name in
  `/etc/hosts` or its GeoIP place, its state, and since when a reading first listed it (Linux does not say when a
  socket began). A listening port another user holds is named from the firewall's own read as root where there is one
  (`netstat_listeners`: from the read kept, no command run for it). A UDP socket connected to a peer shows that peer.
- **Valid wherever the socket table can be read.** None of it needs root, so with no firewall tool, with sudo asking
  for a password and Root access off, or with a read that failed for its own reasons, the plugin stays valid and in
  the tray, its Main page saying what is missing and offering only what it can do; its table of what the firewall
  needs ends with a row for the Netstat tab and the hosts database. Where the tab is served, whether the plugin is
  present is answered before the firewall's read is asked, so the tray's ask every minute runs no sudo.
- **The hosts database**, this machine's own (the data folder's `hosts/hosts.db`, made 0600 in a folder made 0700, at
  most 50,000 rows): each program's remote hosts, their ports, when they were first and last seen, how long they were
  connected, how many connections, and their places. Linux gives no start for a connection, so its time connected is
  what was seen: a gap of more than 30 s between two readings adds nothing. It records only while the Netstat or the
  World Wide Web tab is shown, unless you choose all the time the platform runs (Recording..., the setting
  `LIMINAL_HOSTS_RECORDING`, kept through the login: off Windows only until the platform restarts today, and the page
  says so); Forget... removes every row, asked twice.
- **The globe** shows the traffic watched or the hosts recorded, filtered by program, by port, by direction and by
  when they were last seen, the eight programs and the eight ports with the most hosts right under it. It draws the
  internet's infrastructure from five free-licensed data sets (`INFRASTRUCTURE`), each downloaded only on your click,
  as a job (its size and its licence said first and accepted in so many words; Cancel stops it), kept on this
  machine and credited where it is drawn: data centres, submarine cables of every telecom category and their landing
  stations, and telecom lines on land (OpenStreetMap, through the public Overpass API, ODbL 1.0); exchange points,
  ground stations and teleports (Wikidata, CC0); telecom cable routes in European waters (EMODnet Human Activities'
  WFS, CC BY 4.0, asked longitude first). PeeringDB, root-server sites and cloud regions are left out: not
  free-licensed, or no licence stated.
- **Under WSL** the tab ends with what WSL changes for it (the library's table), and the row seen in the user's Ubuntu
  (WSL 2, NAT networking, 2026-11-18): a TCP port listening there at 127.0.0.1 is reached from Windows' own 127.0.0.1
  too (wslrelay.exe's in Windows' table); UDP is not forwarded. What was not seen is not said.
- **Four more cards** (plugin API 2.2), their pages read on 2026-11-18: the kernel's socket tables (procfs: every file
  the library's reading opens, `sockets.LINUX_FILES`), the Overpass API, the Wikidata Query Service and EMODnet Human
  Activities (WFS). Their facts say the socket tables' last reading, how the hosts are recorded, what the database
  holds and each data set's state, asking nothing. iproute2's card says the Netstat listeners come from ss's programs.
- Its floor is liminal-libs[geo]>=1.65.0. Given an older library all the same, it works as 0.8.2 did, its table of
  what the firewall needs saying what the tab would need, and none of the four cards.

Tests: test_netstat.py (skipped on an older library: the tab is the base's; the data sets, the cables asked of every
telecom category, pinned by their digest; the listeners named from the read kept; valid and present wherever the
socket table can be read, and the needs row; the WSL row; nothing read on Windows or macOS; a login that says always
starts nothing real); test_world.py, test_apis.py, test_plugin.py, test_read.py and test_rights.py follow the
library; tests/conftest.py's `_no_real_hosts` guard, as the library's, with the socket tables' readability and WSL
stood in: no test reads this machine's socket table or writes its hosts database.

## 0.8.2 (2026-11-18)

Root access, asked for on the plugin's own page, and only if required. The user, 2026-11-17, of the firewall that
could not be read inside WSL's Ubuntu: "the plugin needs to be able to handle permissions if required"; "A field on its
page"; "(enable / disable)"; "but only if required"; and of Liminal's own user and group: "lets have a liminal user and
group for the liminal-linux-administration that enables linux potholes" (the privileges the plugins need).

- **Root access, a switch** (Turn on... / Turn off...) on Main, shown only where the platform is not root and sudo
  cannot already run the plugin's read without a password. Turning it on asks for the sudo password once, in a field
  of its form: it makes the group `liminal` if there is none, adds the platform's user to it, and installs the
  plugin's read as a root-owned helper with one sudoers rule letting only that file run, for the group, with no
  arguments. It takes effect once the platform is started again (a new group membership reaches new programs only).
  Turning it off needs no password. A helper installed by an older plugin is not run: the page says so and offers
  Turn on... again.
- **Install nftables...** where no firewall tool is installed and APT is there: a job asking the password, saying
  first what it downloads (nftables and the libraries that come with it) and that installing it filters nothing.
- **Valid with a problem**: where the firewall cannot be read for want of root or of a tool, the plugin stays valid,
  says why, and offers only what it can do, so the switch and the install can be reached.
- **A change** gets a password field only if it needs one; a change asked without the password it needs is refused
  in words before sudo is asked.
- Needs liminal-libs 1.62.0 for all of it (`Shell.run(password=)`, the grant); on an older library it works as 0.8.1.

## 0.8.1 (2026-11-16)

What the firewall needs here, said where it cannot be read. The user: "still need linux firewall". Inside WSL's Ubuntu
the plugin said only "cannot be read: sh needs root on this machine ... (sudo: a password is required)", and Ubuntu there
had no firewall tool either.

- **What the firewall needs here.** When the read is refused for want of root, or finds no firewall software, the
  status's tables begin with this table:
  - **Root for the read.** Run the platform as root, or add a sudoers rule letting sudo run `sh` and the firewall's tools
    without a password. Every read and change goes through `sudo -n`, which never asks for one.
  - **A firewall tool.** Which of nftables, iptables, ufw and firewalld is installed, found by their files without root
    and running nothing (`tools_here`). With none, how to install nftables on each distribution.

  A read that failed for another reason is said in its own words.
- **Under WSL.** The "Under WSL" table now follows it in these states too. Before, it was drawn only once the firewall
  could be read.
- **Where it shows.** liminal-platform 0.29.0 draws a plugin's tables while the plugin is not valid. An older platform
  shows only the reason, as before.

The plugin installs and changes nothing for this: what is missing is an administrator's to put right.

Tests: the read refused (sudo asking for a password), a tool found and none, a read that failed otherwise, no firewall
software at all, and inside WSL.

## 0.8.0 (2026-11-16)

The World Wide Web tab. The user, 2026-11-14: "so for the firewall's both are going to get a 'world wide web view' that
shows the globe and the routes incoming all traffic, as well as monitoring port traffic stats". The tab is the library's
Firewall base's (liminal-libs 1.55.0, `machines/world.py`). liminal-platform 0.27.0 draws it after Main and API.

- **What it shows.** The globe, with each place traffic came from or went to and its route to this machine: allowed in,
  unanswered in (dashed) and out. The four busiest ports here, their bytes in and out over the last ten minutes. Tables
  of the busiest ports here, the places and the ports elsewhere. The local network's peers are summed apart and never
  placed.
- **Watching only while you look.** Each ask of the tab (every 2 s while it is shown) keeps a libpcap capture going at
  the adapter of this machine's way out: every TCP and UDP packet, IPv4 and IPv6, the headers alone. It stops by itself
  20 s after the last ask, and when the plugin is detached. Only counts are kept, in memory.
- **What it sees.** Packets are seen before nftables and iptables decide, so an attempt they drop shows as unanswered.
  What an XDP program drops never reaches libpcap. When the firewall's last read found an XDP program at the adapter
  watched (or at a port of its bridge or bond), the tab says so, from the read it has and running no command
  (`xdp_unseen`).
- **The right to capture: CAP_NET_RAW alone, for the platform alone.** The capture runs as root, or with CAP_NET_RAW.
  When libpcap says the right is missing and the platform is not root, the tab gives an administrator two ways, and it
  never asks for a password:
  - under systemd, `AmbientCapabilities=CAP_NET_RAW` under `[Service]` in the platform's system unit
    (`liminal-platform-boot.service`, the Linux administration plugin's boot service);
  - or `setcap cap_net_raw=ep` on a copy of Python that is the platform's own (`python3 -m venv --copies`,
    `chmod 0750`): under OpenRC or another init, this way alone. It lasts until that file is written again, and the tab
    then says so again. A file with a second name (a hard link to the system's interpreter) is never taken for the
    platform's own.

  Never the system's Python, which a venv's `python` links to, and never CAP_NET_ADMIN, the right to rewrite the
  firewall. As root, the tab says what else may forbid packet sockets (a container, AppArmor, SELinux). Any other
  failure is said in libpcap's own words. These are liminal-libs 1.55.0's words (`world.capture_help`), and the libpcap
  card and this README say the same.
- **Places stay on this machine.** They come from DB-IP's IP to City Lite file, looked up here with maxminddb. The file
  is mapped only while the tab is watched. No address is sent anywhere, and none is looked up by name.
- **The GeoIP file is downloaded on your word.** While none is installed, the tab offers Install the GeoIP file….
  - Its first confirmation says what is downloaded, from download.db-ip.com, and to where, and shows the licence.
  - The second asks you to accept the licence (CC BY 4.0) in so many words (liminal-platform 0.28.0 or newer, which
    carries the licence's refusal back to the page; 0.27.0 shows it in the job's panel instead).
  - Then this month's file is downloaded (`https://download.db-ip.com/free/dbip-city-lite-{year}-{month}.mmdb.gz`,
    about 60 MB), or last month's while this month's is not out yet. The platform runs it as a job (the base's
    `JOB_HOOKS`): its progress shows in the plugin's panel, and it stops by itself after 30 minutes. Every hop is https,
    from download.db-ip.com alone. One copy is kept in the data folder.
  - Update… is offered once the file is older than this month.
  - "IP Geolocation by DB-IP", linked to db-ip.com, is shown wherever places are, as DB-IP's licence asks.
- **Home.** The place you set: Home on the globe in the plugin's Settings (`LIMINAL_HOME_PLACE`, `lat,lon[,label]`), kept
  through the platform's login. Else, where the GeoIP file puts this network's public address. That address is asked of
  OpenDNS's resolver1 and Google's ns1 (the name servers hw-stats asks), and only once a GeoIP file is installed. Each
  name is asked as an absolute one, with a trailing dot, and the question names no other machine. Without nslookup, the
  tab says which package to install.
- **The Linux the platform runs on, WSL included.** The user, 2026-11-15: "wsl and firewall linux should always work
  under linux, if wsl prevents or misses some capability this should reflect in the plugin". Inside a WSL distribution
  the plugin is Linux like any other once the library's check no longer refuses a WSL kernel (that library change
  follows 1.55.0). Its page then ends with an "Under WSL" table (`linux.wsl_table`): the packet filter WSL's kernel
  gives, and WSL's network behind Windows' firewall. The World Wide Web tab's page ends with its own (`world.under_wsl`):
  the distribution's own adapter is watched, Windows' own traffic is the Windows firewall's tab's, nothing comes in
  from the internet but through Windows, and under WSL 1 nothing can be watched. With a library that still refuses a
  WSL kernel, the plugin says so there and runs nothing, as before. On Windows and macOS the tab says "Not for this
  machine", and nothing is watched or downloaded; a platform on Windows never reaches into a distribution from outside.
- **The GeoIP file installed as root stays readable.** liminal-libs 1.55.0 installs it with the mode every file the
  platform makes has (0644 less the umask, not 0600), so the account that runs the platform later reads it. An install
  refused for want of the right says whose the folder is.

The plugin names what is its own in `apis.py`: `GEOIP_URL`, `GEOIP_LICENCE`, `ATTRIBUTION` and `PUBLIC_DNS`, set on the
plugin. The library names no outside host. Its hooks gain the base's `world` and `world_geoip`, and its keys the base's
`LIMINAL_HOME_PLACE`.

**Four more cards** (plugin API 2.2), every address on them read on 2026-11-15:

- **libpcap (packet capture)**: tcpdump.org's pages, packet(7), capabilities(7), systemd.exec(5)'s
  AmbientCapabilities=, setcap(8) and venv's --copies. Every libpcap call the library's capture makes is marked used,
  with the rest of the API beside them. The right to capture's two ways are an administrator's calls, never made here.
- **DB-IP Lite City (GeoIP)**: IP to City Lite, its MMDB fields, the Lite databases' licence and attribution, CC BY 4.0,
  the MaxMind DB format, and maxminddb (its documentation, source, changes and PyPI page).
- **OpenDNS** and **Google's name servers**: the questions asked for this network's public address, each exactly as the
  library asks it (`nslookup -type=a -timeout=3 -retry=1 myip.opendns.com. 208.67.222.222`), with nslookup(1).

`api_facts` also says what the tab watched (where, and the packets read, or why it cannot) and which GeoIP file it has
open, or last had open once watching stopped. It asks nothing, and says nothing of the tab before the tab is first
shown: it reads the tab through the base's `world_view(make=False)`, which never makes one.

Needs liminal-libs>=1.55.0 with its geo extra (maxminddb 3.2). Tests: the tab through the plugin with stand-ins for the
capture, the download, the name servers and the clocks, over a tiny GeoIP file the tests write (`tests/test_world.py`,
`tests/mmdb_file.py`). libpcap, the route, nslookup and urllib fail a test that reaches them, and no command runs. What
the tab says about the right to capture is tested as a Linux machine's page says it, as root and not. The machine the
tests run on never shows through (`tests/conftest.py`: not inside WSL, no init known), so the suite reads alike inside
a WSL distribution, on a Linux of any init and on Windows. The
cards are tied to the calls the library makes: libpcap's in `capture.py`, maxminddb's in `geo.py`, nslookup's in
`dns.py` (each question as `dns.public_address` asks it, through a stand-in that runs nothing).

## 0.7.2 (2026-11-15)

Drawn under the platform's OS plugins section, in the list on the left (the user: "then OS plugins" (the WSL distributions, the admin and the firewall plugins, as chosen)): `SECTION = "os"`, liminal-libs 1.51.0's machine-plugin attribute. liminal-platform 0.26.0 draws it; an older platform keeps the plugin under Machine plugins. Nothing else changes.

## 0.7.1 (2026-11-14)

Liminal's own ports are the four apps' alone (liminal-libs 1.52.0; the user, 2026-11-14: "i only want ports for liminal-login ; liminal-platform ; liminal-charts ; liminal-integrator"; "never provide ports for anything else"): the integrator's login at 8796 is gone, a login an app inherits being an object in that app, at its port.

## 0.7.0 (2026-11-11)

Its API on its page, plugin API 2.2 (the user: "each plugin should reflect the the API its attached to, and present
links that provide documentation, the plugin interface should more or less contain what it already has, BUT, it should
also expose more of what the API is about"). Eleven cards (`apis.py`), each with the makers' pages, every part of the
API said covered or not, and every call the plugin makes beside the API's other notable ones: nftables (the wiki,
nft(8), libnftables-json(5)), iptables and ip6tables (both variants, saving and the distributions' own saves),
ebtables and arptables, ipset, firewalld (zones, policies, services, rich rules, the offline tool), ufw, connection
tracking, eBPF through bpftool, iproute2's ip and ss, the init's firewall services, and sudo.

`api_facts()` says what the last read found, asking nothing: the tools' versions and variants, what each holds,
firewalld's and ufw's state, the connections tracked, the programs on the network's hooks, the machine and when. Tests:
the cards name every command of the read script and every change the plugin runs over the recorded machines, and the
commands its plans give each init and distribution; a link check runs with LIMINAL_VENDOR_PAGES=1. Needs
liminal-libs>=1.49.0.

## 0.6.0 (2026-11-09)

System and Application grouped again, each rule under the service or the program it is for (the user: "for the windows
and linux firewall, lets have the same system and application and other, but lets group by application under apps or
system, try best to organize under system and applications. Like system has 'core networking' or WSD or UPnP or RA
Server or Remote Assistance or network discovery or ... applications has like starcraft or edge"; then "try to group
the system by 'services'"); and the rules turned off shown too ("also rules that are turned off should be shown as
well").

**System, by service.** A service has one name whichever way its rule is recognised: firewalld's service ssh, ufw's
profile OpenSSH, sshd listening on port 22 and port 22 alone are all SSH. The services are SSH, DNS, DHCP, DHCPv6, NTP,
mDNS, LLMNR, NetBIOS, Samba, NFS, rpcbind, Printing (CUPS), Cockpit, Kerberos, LDAP, SNMP, Syslog, WSD, SSDP (UPnP) and
TFTP, with a few more the system's programs serve (D-Bus, LLDP, SSSD, Bluetooth, Wi-Fi). A program serving several is
named by the port it listens on: systemd's socket on 9090 is Cockpit, systemd-resolved on 5355 is LLMNR, a DHCP client
on 546 is DHCPv6, dnsmasq on 69 is TFTP. Beside them: This machine's own traffic (loopback and the replies to its
connections), ICMP, Invalid packets, and the system's programs making their own rules by their names (systemd,
NetworkManager, NixOS, Fail2ban, CrowdSec, SSHGuard).

**Application, by program.** An application has one name however its rule is found.

- A program making its own rules is under its name: Docker, Podman, libvirt, Incus, LXD, Kubernetes, Calico, Cilium,
  flannel, Weave, Tailscale, Waydroid, WireGuard. Liminal's own rules are under Liminal, and so is a rule for a port one
  of Liminal's own pages listens on. A table only its owning program may change is under the table's name.
- A firewalld service is under what it is for. http, https and http3 are "Web server (HTTP, HTTPS)"; smtp, smtps,
  smtp-submission, imap, imaps, pop3 and pop3s are all "Mail server"; mysql is MySQL, plex Plex, the kube services
  Kubernetes. A service not known here keeps its own name.
- A ufw profile is under its application: its name without the words at its end saying which of its ports. "Nginx
  Full" and "Nginx HTTPS" are both Nginx, "Apache Full" is Apache. ufw's own profiles have the names firewalld's
  services get: WWW, WWW Full, WWW Secure and WWW Cache are the Web server; SMTP, SMTPS, Mail submission, IMAP, IMAPS,
  POP3 and POP3S are the Mail server, and so are Postfix's and Dovecot's.
- A program listening on the rule's port is under its application's name: apache2 is Apache, httpd the Web server,
  nginx Nginx, mosh-server Mosh, Plex Media Server Plex, Postfix's master, exim4, sendmail and dovecot the Mail server.
  A part of a program making its own rules is under that program (docker-proxy is Docker, tailscaled is Tailscale), so
  all of it is one heading. A program not known here keeps its own name.

As the rules are sorted, no name is a heading in both groups: an application's name that is one of the system's
services (a ufw profile called Bluetooth) is under System. A rule moved into the other group by hand keeps its name
there, as before.

**What changed in the sorting.** The groups are found as before, with the same words for why, but:

- A mail server is an application's every way. Postfix's, Exim's and Sendmail's programs were the system's in 0.5.0.
- TFTP is the system's every way, with DHCP for network booting. firewalld's tftp service was an application's in 0.5.0.
- ufw's profiles for the system's services are known by the same words as firewalld's services: IPP and LPD are
  Printing (CUPS), CIFS is Samba, and LDAP, Kerberos, SNMP, Syslog, WSD, SSDP, NetBIOS, LLMNR and rpcbind are theirs.
  They are System now, not Application.
- A profile is the system's by a whole word of its name. A short word inside another word no longer counts, so
  PowerDNS is an application's (in 0.5.0, the "dns" inside its name made it the system's).
- firewalld's llmnr-tcp, llmnr-udp, snmptls, snmptls-trap and the other ws-discovery services are System, with the rest
  of their service.
- A port served by the kernel itself, with no program shown (nfsd on 2049, WireGuard), is named by its port: 2049 is
  NFS. Before, it was under Application, and no name was found for it.

Other and the user's labels stay single lists. Each service, each program and Other list their first 1000 rules (200
in 0.5.0, for a whole group), so a program with hundreds of rules, as Docker or Kubernetes may have, is listed whole.
Find finds a rule by the name of the service or program it is listed under too: "own traffic", "Mail server".

**Rules turned off are shown.** They are listed under the group and name they have when on, and passed to the page to be
shown dimmed. The Where of each says why it filters nothing now:

- ufw's rules while ufw is off: "ufw is off";
- all of firewalld's while it is stopped: "firewalld is stopped";
- a firewalld zone's that is bound to nothing ("zone home (not active)"): "the zone is bound to nothing";
- the default zone's while every interface in use is bound to another zone: "every interface in use is bound to another
  zone". The Zones table says so beside the default zone too;
- a firewalld policy's that is turned off ("the policy is turned off") or between zones not in use;
- a dormant nftables table's: "its table is dormant";
- a rule in a chain that no hook reaches, nftables' or iptables': "nothing jumps to its chain". A table that decides
  through a verdict map declared apart is left as it is, since its chains may be reached through that map.

They are in every preset they fit, Find's "turned off" finds them, and they can be moved and removed like any other.
The summary and the Rules table's note say how many there are. The command line lists them too, saying so. A rule moved
while its zone was bound to nothing stays where it was put when the zone comes into use.

**A rule turned off never stands for a rule in force.**

- Removing the rule that lets SSH in asks the second confirmation when only a rule turned off would let it in: ufw's
  while ufw is off beside nftables in charge, a dormant table's, the default zone's while it takes no interface.
- A default set to drop asks it too when only such a rule lets SSH in.
- The exposure check never counts them, and a dormant table's chains are not on in the firewall's state.
- No rule is made in a dormant table, and its chains' defaults are shown read only, saying the table is dormant.
- Removing a rule turned off asks nothing more: it cuts nothing. ufw's while it is off cut nothing either, since turning
  ufw on keeps SSH open first.
- A change to a front end that is off is judged by its own rules, as they filter again once it is on. ufw's default set
  while ufw is off counts ufw's rules, and a firewalld zone's target set while firewalld is stopped counts firewalld's.
  Removing firewalld's SSH rule while it is stopped asks the second confirmation when no other rule of its would let
  SSH in once it runs again.

**The default zone.** firewalld uses its default zone for every interface bound to no other zone. Its rules are read as
in force while it takes an interface in use. In use means every interface but loopback, one that is down, a bridge's
or a bond's port, and a container's or a virtual machine's end of its link (veth, vnet): what those carry comes in
through their bridge or bond. With every interface in use bound to another zone, the default zone's rules are listed
turned off. 0.5.0 left them out whenever no interface was named in the zone. When the interfaces could not be read,
the default zone takes none known.

**ufw's profiles while ufw is off.**

- A rule as added that names a profile keeps the profile's name: "allow 'Nginx Full'", or "to any app OpenSSH" in the
  full form. So it is sorted and named as it is while ufw is on.
- A profile whose ports are not read no longer counts as every port. When the only rule is such a profile's, turning ufw
  on keeps SSH open first.
- Removing such a rule gives ufw the profile's name as one word.

**Fixed.** A rule deciding through a verdict map declared apart, by its name, stopped the whole read. It is read now.

**Not listed, because not read:** firewalld's permanent configuration while it runs (the read asks the running one),
and the rules a distribution keeps in a file but has not loaded.

Needs liminal-libs>=1.41.0, and liminal-platform 0.16.0 to draw the headings and dim the rules turned off.

## 0.5.0 (2026-11-08)

The rules in groups (the user: "for both firewalls, i need to have groups, like system or application and then
unassociated rules not tied to a specific application or system process can be in an other, i can create labels, like
system or application, as well and move the rules in to that"; "just use basic expansion like a (+) to open and close
labels"). Every rule is sorted (groups.sort_entry) into System (a system service's or program's: Fail2ban's,
NetworkManager's, systemd's; this machine's own traffic, ICMP, invalid packets; firewalld's services and ufw's profiles
for the system's own services; a port sshd, chronyd, avahi... listens on; a port of SSH, DNS, DHCP, NTP...), Application
(a program's: Docker's, libvirt's, Kubernetes', Liminal's; another program listening on the port; another firewalld
service or ufw profile) or Other (a port or an address alone), each saying why. The read lists the programs listening for
UDP too (ss -lunp, netstat -lunp). The user's labels (New label…, Rename…, Remove…) and the rules moved into them or into
another group are the library's (liminal-libs 1.35.0 rulegroups), kept through the platform's login as
FIREWALL_LINUX_GROUPS, never in the firewall: moving a rule changes nothing in it. The Rules table lists each group's
first 200 rules. Needs liminal-libs>=1.35.0 and liminal-platform 0.11.0 to draw the groups.

## 0.4.1 (2026-11-08)

Its icon is the one the user picked ("use this icon for linux firewall"): a brick wall with a flame before it, drawn in
the library's line (liminal-libs 1.34.0's `wallfire`). Needs liminal-libs>=1.34.0.

## 0.4.0 (2026-11-08)

The firewall read whole and changed from the platform's page, as the Windows firewall plugin is.

The user's words: "lets mirror that for linux firewall, except research the current linux kernel, and make sure its
compatable with systemd/openrc it has access nftables, iptables, all the firewall technologies and libraries for the
most modern kernels, make sure its compatible with major distributions and gentoo linxu".

**The read.** One read, run as root and kept a minute (`read.SCRIPT`), covers:

- nftables' JSON ruleset;
- iptables and ip6tables in their variant, with the legacy x_tables only when loaded;
- ebtables, arptables, ipset;
- firewalld's zones, policies and their services' ports;
- ufw;
- conntrack, the interfaces with XDP, and eBPF programs (read only);
- the firewall services under systemd, OpenRC or SysV scripts;
- where the distribution keeps its rules;
- the SSH server's ports.

Every rule is one `Entry`, and whose it is is known: Liminal's, this machine's own, a front end's, or a program's
(Docker, Podman, libvirt, Kubernetes, Fail2ban...).

**The page.** Tables (liminal-platform 0.6.0-0.8.0): Firewall, Interfaces, Zones, Default policies, Rules (presets,
Find, Refresh, Remove per rule), Sets.

**The changes.** These are confirmed forms:

- a rule made through what is in charge (ufw, firewalld, nftables, iptables);
- a rule removed (never a program's own);
- a default policy;
- on and off through the init system;
- the rules saved where the distribution loads them at boot (checked with `nft -c` first, the file before kept).

A change that can cut SSH or open everything needs a second confirmation (`accept_risk`, liminal-platform 0.6.0's
`accept`).

**What changed in behaviour.**

- Valid whenever the firewall can be read: off, or without Liminal's rules, is no longer invalid.
- The library's Firewall base (setup, `allow`, `remove`, exposure) works over the same read.
- The old per-front-end drivers and `DETECT` are gone.
- Distributions: Debian and Ubuntu, Fedora and RHEL, Arch, openSUSE, Alpine and Gentoo (OpenRC and systemd), with
  NixOS said as not kept.

**Tests.** They run over recorded machines.

**What the research found** (the kernel's and the tools' sources, 2026-11-08; the README's "The kernel and its
firewall today"):

- Reading loads no kernel module: the legacy x_tables only when loaded, ipset only when `ip_set` is, conntrack from
  /proc.
- firewalld is asked only when its service runs.
- Owned tables (flags owner, persist) are read only.
- `nft insert ... handle N`.
- nft's flags as a word or a list.
- firewalld's TAB lines and disabled policies.
- Alpine's rules file (its own save keeps counters only).
- Gentoo's nftables-store and iptables-store.
- openSUSE's /etc/nftables/rules/main.nft.
- ufw kept at boot under OpenRC.
- bpftool's JSON, mended where it is not JSON.
- IPv6's neighbour discovery kept behind a second confirmation.

**Its icon.** Tux as a wall of bricks (`ICON = "tuxbricks"`, liminal-libs 1.33.0; the user: "for the firewalls, lets use
an icon of TUX penguin or Windows and then convert it to a patchwork of bricks"). It now needs liminal-libs>=1.33.0.

## 0.3.0 (2026-11-08)

Native Linux only, as Linux administration (the user: "the scope of linux administration is only on native linux
O/S"; "it's not for administrating WSL instances"; "Yes, firewall too"): the plugin drives the firewall of the Linux
machine the platform runs on and nothing else. On Windows (where 0.2.0 took Liminal's WSL distribution, and showed
WSL's raw error there when nftables was missing), on macOS and inside a WSL distribution it runs no command: not
present, not valid, `applies` False with the reason (liminal-libs 1.27.0: `why_not_native`, `not_for_here`), the setup
and every command refused. `FIREWALL_LINUX_TARGET` is gone.

## 0.2.0 (2026-11-07)

On liminal-libs 1.25.0: without a target named, Liminal's own WSL distribution on Windows (Liminal-Ubuntu, then
Liminal-Fedora, Liminal-Gentoo), this machine on Linux; on a target that is not Liminal's (WSL's default distribution,
the user's own) the plugin runs no command: its status says why and its setup changes nothing. Valid only with the
rights on Liminal's (`valid`, `why`).

## 0.1.0 (2026-11-07)

The first release: Linux firewall for the platform, on the library's Firewall base
(liminal-libs 1.20.1).
