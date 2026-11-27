# plugin-platform-firewall-linux

Linux firewall for Liminal: the whole firewall of the Linux the platform runs on (a machine of its own, or a WSL
distribution the platform runs inside), read and changed from the platform's page. nftables, iptables (nf_tables and
legacy), ebtables, arptables, ipset, firewalld, ufw, conntrack, and eBPF/XDP (read only), under systemd, OpenRC or SysV
scripts, on the major distributions and Gentoo. Its Netstat tab lists the listening ports and the open connections with
the program behind each, and the hosts database keeps each program's remote hosts and how long they were connected;
its Networks tab routes and names the container plugins' segments.

**0.14.0:** the World Wide Web tab (the globe, the traffic captured, the GeoIP files, the internet's infrastructure and
the satellites) is a plugin of its own, plugin-platform-worldwideweb (Monday list item 33), and nothing of it is left
here: its cards, data sets, hooks and tests went with it (the user, 2026-11-26: "Delete now"). That plugin asks this
one through the platform for what only a firewall knows (below). Floor: liminal-libs 1.105.0.

The user's words. 2026-11-07: "the platform is the interface for the software/hardware which facilitates the liminal
framework"; "i also need a windows and linux firewall plugin for the platform". 2026-11-08, on the Windows one: "i need
it to be able to read the configuration, and make changes"; "basically the firewall plugin is an interface for windows
networking / defender / firewall, and will let me make queries and alter the firewall configurations". Then: "lets
mirror that for linux firewall, except research the current linux kernel, and make sure its compatable with
systemd/openrc it has access nftables, iptables, all the firewall technologies and libraries for the most modern
kernels, make sure its compatible with major distributions and gentoo linxu".

## What it reads

One read of the whole configuration (`read.SCRIPT`), run as root through the library's `machines.linux.Shell`: as the
platform's own root, or through `sudo -n` when the platform is not root, by a rule of yours or by Root access's
installed copy of the read (below, Rights); the read itself never asks for a password. The read is a POSIX shell script
that BusyBox's sh runs too. It is kept for a minute (a refused read too: sudo notes each refusal), and read again after
each change and on Refresh. It reads:

- **nftables**: `nft -j list ruleset` (libnftables' JSON). Tables, base chains with their hook, priority and policy,
  every rule written out again in nft's own syntax (counters left out of the words, kept apart), sets and maps.
- **iptables and ip6tables**: `iptables-save` in the variant the machine uses. With nf_tables, iptables-nft's tables
  are read in iptables' own syntax rather than as nftables JSON. The legacy x_tables are read beside them only when the
  kernel has them loaded (`/proc/net/ip_tables_names`); reading them otherwise would load them.
- **ebtables, arptables**: their variant and version. **ipset**: `ipset list -t` (the sets, not their members).
- **firewalld**: its state and version, the default zone, every zone (`--list-all-zones`), its policies
  (`--list-all-policies`), the ports of the services the zones use, its backend. `firewall-offline-cmd` is used while
  the daemon is stopped.
- **ufw**: `ufw status verbose` (on or off, logging, the defaults), `ufw status numbered` and `ufw show added` (its
  rules, also while it is off).
- **conntrack**: the connections tracked and their limit.
- **Interfaces**: `ip -j addr` (BusyBox's `ip addr` without JSON on Alpine), with any XDP program attached.
- **eBPF**: `bpftool -j net show` (XDP, tc, flow dissector, netfilter programs), read only.
- **The init system and its firewall services**: systemd, OpenRC, or SysV scripts. Each service's state and whether it
  starts at boot: nftables, iptables, ip6tables, ipset, firewalld, ufw, netfilter-persistent, and Gentoo's
  nftables-restore and iptables-restore.
- **Where the distribution keeps its rules** across a restart (below), and the SSH server's ports and sessions (what a
  change must not cut off).

Whose each rule is:

- **Liminal's**: a comment `liminal:<name>`, or a firewalld service `liminal-<name>`.
- **This machine's own**: its administrator's.
- **A front end's**: ufw's rules, firewalld's zones.
- **Another program's**, known by its table, chain or interface name: Docker, Podman (netavark), libvirt, Incus, LXD,
  Kubernetes (kube-proxy, Calico, Cilium, flannel), Fail2ban, CrowdSec, SSHGuard, Tailscale, NetworkManager, systemd.

A front end's own machinery (ufw's chains, firewalld's nftables table) is shown through the front end, not twice.

## What the page shows

The plugin's status holds tables for the platform's page (liminal-platform 0.6.0-0.8.0):

- **Firewall**: each part, its state, version, what it holds, how its rules last. Each part has its switch and its
  Save.
- **Interfaces**: addresses, firewalld zone, XDP.
- **Zones**: firewalld only: interfaces and sources, target, services, ports, rich rules. Each zone has a Target… button.
- **Default policies**: ufw's three defaults, this machine's own nftables base chains, iptables' built-in chains,
  each with a Set… button. Other programs' chains are listed read only.
- **Rules**: every rule, the turned-off ones too, in groups (below).
  - Presets: inbound allowed, inbound blocked, outbound, forwarded and NAT, Liminal's, all.
  - Find: every word must be in the rule, or in the name of the service or program it is under; a number also finds
    the rules for that port; "turned off" finds those.
  - Buttons under it: Add a rule…, Find…, Refresh, New label….
  - Each removable rule has its own Remove….
- **Sets**: nftables' sets and ipset's.

Valid whenever the firewall can be read, as the Windows firewall plugin is: off, or without Liminal's rules, is said in
the summary and the tables, not as invalid. Since 0.9.0 it is valid too wherever the kernel's socket tables can be read
and the firewall cannot (the Netstat tab, below, needs no rights), its Main page saying what the firewall needs.

After Main and the API tabs come the Netstat tab (0.9.0), below, and the Networks tab (0.11.0).

## The rules in groups

The user's words. 2026-11-08: "for both firewalls, i need to have groups, like system or application and then
unassociated rules not tied to a specific application or system process can be in an other, i can create labels, like
system or application, as well and move the rules in to that"; "just use basic expansion like a (+) to open and close
labels". 2026-11-09: "for the windows and linux firewall, lets have the same system and application and other, but lets
group by application under apps or system, try best to organize under system and applications. Like system has 'core
networking' or WSD or UPnP or RA Server or Remote Assistance or network discovery or ... applications has like
starcraft or edge"; "try to group the system by 'services'"; "also rules that are turned off should be shown as well".

Each rule is in one of three groups, and System and Application are grouped again by name. Each group and each name is
a heading, opened with (+) and closed with (−). As the rules are sorted, no name is a heading in both groups; a rule
moved into the other one by hand keeps its name there.

- **System**: the operating system's own, under its service. A service has one name whichever way its rule is
  recognised: firewalld's service ssh, ufw's profile OpenSSH, sshd listening on port 22 and port 22 alone are all SSH.
  The services are SSH, DNS, DHCP, DHCPv6, NTP, mDNS, LLMNR, NetBIOS, Samba, NFS, rpcbind, Printing (CUPS), Cockpit,
  Kerberos, LDAP, SNMP, Syslog, WSD, SSDP (UPnP), TFTP, and a few more the system's programs serve. A program serving
  several is named by its port: systemd's socket on 9090 is Cockpit, and systemd-resolved on 5355 is LLMNR. A ufw
  profile is the system's by a whole word of its name (OpenSSH, CUPS, Kerberos KDC), never by a short word inside
  another (PowerDNS is an application's). Beside them: This machine's own traffic (loopback and the replies to its
  connections), ICMP, Invalid packets, and the system's programs making their own rules (systemd, NetworkManager,
  Fail2ban, CrowdSec, SSHGuard).
- **Application**: a program's, under the program, one name however its rule is found.
  - A program making its own rules is under its own name: Docker, Podman, libvirt, Incus, LXD, Kubernetes, Calico,
    Cilium, flannel, Weave, Tailscale, Waydroid, WireGuard. Liminal's own rules are under Liminal, and so is a rule for
    a port one of Liminal's own pages listens on.
  - A firewalld service is under what it is for. http, https and http3 are Web server (HTTP, HTTPS); smtp, imap, pop3
    and their secure forms are the Mail server; the kube services are Kubernetes. A service not known here keeps its
    own name.
  - A ufw profile is under its application: its name without the words saying which of its ports. Nginx Full and Nginx
    HTTPS are both Nginx. ufw's own profiles take firewalld's names: WWW Full is the Web server, SMTP and IMAPS the Mail
    server.
  - A program listening on the rule's port is under its application's name: apache2 is Apache, mosh-server Mosh,
    Postfix's master the Mail server. A part of a program making its own rules is under that program, so docker-proxy
    is Docker. A program not known here keeps its own name (python3, node).
- **Other**: tied to no program or service, a port or an address alone. It is one list.

How a rule's group is found, in order:

1. Whose it is: a program making its own rules, or Liminal's.
2. What it is for: this machine's own traffic, ICMP, invalid packets.
3. The firewalld service or ufw profile it names.
4. The program listening on a port it names. A port the kernel serves itself, with no program shown (nfsd, WireGuard),
   names nothing here.
5. A port of the system's own services.

Each rule says why on hover. The user's labels are single lists too. A rule moved into System or Application keeps its
name there. Each service, each program and Other list their first 1000 rules. Find narrows them, and finds a rule by
the name it is listed under too. Moving a rule changes nothing in the firewall: the labels and moves are kept through
the platform's login.

**Rules turned off** are listed too, under the group and name they have when on, and the page shows them dimmed. The
Where of each says why it filters nothing now:

- ufw's rules while ufw is off: ufw is off;
- all of firewalld's while it is stopped: firewalld is stopped;
- a firewalld zone's that is bound to nothing ("zone home (not active)"): the zone is bound to nothing;
- the default zone's while every interface in use is bound to another zone. firewalld uses the default zone for every
  interface bound to no other zone, so its rules are in force while it takes an interface in use: any but loopback, one
  that is down, a bridge's or a bond's port, and a container's or a virtual machine's end of its link (veth, vnet);
- a firewalld policy's that is turned off, or between zones not in use;
- a dormant nftables table's: its table is dormant;
- a rule in a chain no hook reaches, nftables' or iptables': nothing jumps to its chain.

They can be found, moved and removed like any other rule. A rule moved while its zone was bound to nothing stays where
it was put when the zone comes into use.

A rule turned off never stands for a rule in force. The second confirmation, the exposure check and the firewall's
state go by the rules in force, and no rule is made in a dormant table. Removing a rule turned off asks nothing more:
it cuts nothing. A change to a front end that is off is judged by its own rules, which filter again once it is on:
ufw's default set while ufw is off, and a firewalld zone's target set or one of its rules removed while firewalld is
stopped.

firewalld's permanent configuration while it runs, and the rules a distribution keeps in a file but has not loaded, are
not read, so they are not listed.

## What it changes

Every change is a form the user confirms on the page. The rule is first found again in a fresh read, then the commands
run as root. Afterwards the firewall is read again.

- **Add a rule**: made as one of Liminal's rules, under its name. It can let in, drop or refuse; coming in, going out
  or passing through; tcp, udp or any; with ports, the other side's address or network, and an interface. It is made
  through whatever is in charge:
  - **ufw**: a rule commented `liminal:<name>`.
  - **firewalld**: a service `liminal-<name>` in the default zone, or a rich rule naming it.
  - **nftables**: in this machine's own chain on that hook. An allow goes into a chain that drops by default, before
    its last catch-all. A block goes at the chain's head, or into a table of Liminal's own (`inet liminal`) when there
    is no chain. The rule is commented `liminal:<name>:<protocol>:<ports>:<remote>`.
  - **iptables**: into INPUT, OUTPUT or FORWARD, in iptables and ip6tables, commented `liminal:<name>`.
- **Remove a rule**: this machine's own, ufw's, firewalld's or Liminal's. Never another program's: it would make the
  rule again. It is found by its place and its words:
  - nftables: by its handle.
  - iptables: by its exact rule.
  - ufw: by its number at that moment.
  - firewalld: in the running firewall and its permanent configuration alike.
- **Set a default policy**: ufw's `default`, an nftables base chain's policy, iptables' `-P`, or a firewalld zone's
  target.
- **Turn on or off**: ufw (`ufw enable` and `disable`; turning it on keeps an SSH server's port open first), firewalld
  and the nftables, iptables or netfilter-persistent services. These go through the init system, now and at boot:
  `systemctl enable|disable --now`, or `rc-update add|del` with `rc-service start|stop`.
- **Save the rules**: nftables' or iptables' rules made at run time, where the distribution loads them at boot (below).
  For a file, it is checked first (`nft -c -f`) and the file before is kept beside it. ufw and firewalld keep their own
  rules.

A change that can cut this machine off over SSH, or open it to everyone, is refused until it is accepted. The page asks
that as a second, explicit confirmation (`accept_risk`), in the plugin's own words:

- dropping SSH;
- removing what lets SSH in, the replies in, or loopback;
- a default dropping when no rule lets SSH in from everywhere;
- a default letting everything in;
- letting every port in to everyone;
- opening the framework's own pages;
- stopping a firewall;
- starting a service that flushes other programs' rules.

**Asked only from the page** (0.10.0, `PAGE_ONLY_HOOKS`): every change above, Root access and nftables' install, and
the library base's `allow` and `remove`. Another plugin's ask of one is refused, and liminal-platform 0.34.0 asks its
login whether you are at the page before it asks one over HTTP (401 if not; a platform that holds no login asks it as
before). The second confirmation is the page's: to the hook it is an argument, so until 0.10.0 any program on this
machine that sent the platform's two headers could make any of these changes (the review of PLT-H1's fix,
2026-11-24). The framework's setup and the command line call the plugin's code in their own process, not through an
ask. Since 0.14.1 the rules read again, as root, and the Rules table's two choices (`refresh`, `show_rules`,
`find_rules`) are the page's as well (the user, 2026-11-26: "Yes, closed by default"); the other reads are asked by
anyone, as before.

**The framework's own rules** (its setup's, the base's `allow`) are made with no second confirmation. Their remote is
read as the form's other side is (0.10.0): "any" for anywhere, else an address or a network, written canonically, and
anything else refused before anything runs. Until then it went to the commands as it was given, and nft, which reads
its words as one script, ran whatever followed a `;` in it as root. An address with a zone (`fe80::1%eth0`) is
refused in the form too, and every plan to make a rule checks its name, its other side and its interface however it
was asked for (`changes.Spec`).

## The kernel and its firewall today

Researched on 2026-11-08 for this release (the user: "research the current linux kernel").

**Kernel lines.**

- Mainline is 7.4-rc1, and stable is 7.3.3.
- The long-term lines are 6.18, 6.12, 6.6, 6.1, 5.15 and 5.10.
- The plugin works the same on all of them.

**nftables.**

- nf_tables is the kernel's packet filter, and nftables 1.1.7 is its current tool.
- Its JSON listing (`nft -j list ruleset`) is what the plugin reads.
- A `flags` value is a word on nft 1.1.3 and older (a list when several flags are set), and a list on 1.1.7. The plugin
  takes both.

**iptables.**

- iptables 1.8.13 is current. Its nf_tables variant (`iptables-nft`, the default on Debian and Ubuntu, Fedora and RHEL,
  Arch since April 2026, and Alpine) writes its rules into nftables' tables.
- It marks those tables with nothing, so the plugin knows them by what `iptables-save` lists. It reads them in iptables'
  own syntax, because their `-m comment` and other extensions are opaque `xt` objects in nftables' JSON.

**The legacy x_tables.**

- They are optional since Linux 6.17 (`CONFIG_NETFILTER_XTABLES_LEGACY`, off by default), and gone from some kernels
  (Raspberry Pi OS's 6.18).
- Debian plans to drop them after forky.
- The plugin reads them only when the kernel has them loaded (`/proc/net/ip_tables_names`), because listing them
  otherwise would load `ip_tables`.

**Reading loads nothing.** As root, a listing can load kernel modules. So:

- conntrack is read from `/proc/sys/net/netfilter`, never through netlink;
- ipset is asked only when `ip_set` is loaded;
- the legacy tables are asked only when they are loaded.

**Owned tables.**

- firewalld's `inet firewalld` table carries the kernel's `owner` and `persist` flags (Linux 5.12 and 6.9), so only
  firewalld may change it.
- Any table with those flags is read only here.

**eBPF.**

- XDP programs (driver, generic, offload, several at once), tc programs (classic `cls_bpf`, and tcx or netkit links since
  6.6) and netfilter BPF links (since 6.4) filter without being in nftables' ruleset.
- The plugin lists them from `ip -j addr` and `bpftool -j net show`, read only.
- bpftool writes an attached flow dissector as `["id":N]`, which is not JSON, so the plugin mends it before reading.

## Distributions and init systems

The distribution is read from `/etc/os-release` (`ID`, `ID_LIKE`); its init system from what runs.

| Family | Init | nftables kept in | iptables kept in |
| --- | --- | --- | --- |
| Debian, Ubuntu, Mint | systemd | `/etc/nftables.conf` (nftables.service) | `netfilter-persistent save` (`/etc/iptables/rules.v4`, `rules.v6`; it exits 0 even when it fails) |
| Fedora, RHEL, Rocky, Alma | systemd | `/etc/sysconfig/nftables.conf` (nftables.service) | `/etc/sysconfig/iptables`, `ip6tables` (iptables-services) |
| Arch, Manjaro, Artix | systemd, OpenRC | `/etc/nftables.conf` | `/etc/iptables/iptables.rules`, `ip6tables.rules` |
| openSUSE, SLES | systemd | `/etc/nftables/rules/main.nft` (nftables.service; firewalld is its default) | - |
| Alpine | OpenRC | its `rules_file`, `/etc/nftables.nft` (its `rc-service nftables save` keeps counters and quotas only) | `rc-service iptables save`, `ip6tables save` (`/etc/iptables/rules-save`, `rules6-save`) |
| Gentoo | OpenRC | `rc-service nftables save` (`/var/lib/nftables/rules-save`, `NFTABLES_SAVE`) | `rc-service iptables save`, `ip6tables save` |
| Gentoo | systemd | `systemctl start nftables-store.service` (`/var/lib/nftables/rules-save`, loaded by nftables-load) | `systemctl start iptables-store.service`, `ip6tables-store` (loaded by iptables-restore) |
| NixOS | systemd | not kept: its configuration builds the firewall | not kept |

A distribution not listed is read the same way. Where no file loading the rules at boot is known, Save says so instead
of guessing. A file is written whole, from this machine's own tables (`flush ruleset` first, as the distributions'
own files begin), checked with `nft -c -f` before it replaces the file, and the file before is kept beside it.

firewalld is asked only when its service runs: from 2.4.3, `firewall-cmd` waits about 10 s for D-Bus when the daemon
is stopped, so the read uses `firewall-offline-cmd` then. ufw's service reads "active" on Ubuntu even when ufw is off,
so ufw's own `status` says whether it is on. Gentoo's one-shot units (nftables-load, iptables-restore) read inactive
once they have run, so only their place at boot is said. OpenRC's runlevels are read from `/etc/runlevels`.

## The Linux the platform runs on, WSL included

The user's words. 2026-11-08: "the scope of linux administration is only on native linux O/S"; "it's not for
administrating WSL instances"; and, asked whether the firewall follows, "Yes, firewall too". 2026-11-15: "wsl and
firewall linux should always work under linux, if wsl prevents or misses some capability this should reflect in the
plugin".

The plugin works on the Linux the platform runs on, and only there: a machine of its own, or a WSL distribution the
platform runs inside. Inside WSL it reads and changes that distribution's firewall like any other's. Its page then ends
with an "Under WSL" table (the library's `machines.linux.wsl_table`): the packet filter WSL's kernel gives (none under
WSL 1), and WSL's network behind Windows, whose own firewall decides first what reaches the distribution from outside
the PC. The Netstat tab says what WSL changes for it too (below).

On Windows and on macOS it runs no command at all, and a platform on Windows never reaches into a WSL distribution from
outside (the WSL plugins are for those). There its status says why and that it does not apply (`applies` False). The
platform shows it disabled with no setup offered, and its setup and every command are refused. A Windows PC's own
firewall is the Windows firewall plugin's.

The library's check (`machines.linux.why_not_native`) decides. A library from before the Linux plugins worked inside WSL
still refuses a WSL kernel; with it, the plugin says so inside WSL and runs nothing there.

## Rights

The user's words, 2026-11-17, after the firewall could not be read inside their WSL Ubuntu, where sudo asks for a
password: "the plugin needs to be able to handle permissions if required"; asked how the password is typed: "A field on
its page"; then "(enable / disable)", "but only if required" (DECISIONS addenda 9 and 10).

Reading and changing the firewall need root. Where root is needed, the plugin says what for and offers it as a confirmed
action on its own page, as the Windows plugins ask through UAC (`rights.py`, over liminal-libs 1.62.0's
`machines.linux`: `Shell.run(password=...)`, `grant`, `revoke`, `granted`, `needs_password`, `PasswordRefused`).

**How it has its rights** is a fact on its page (`rootAccess`), found with each read:

- the platform runs as root: everything runs as root, without sudo;
- sudo runs the read without a password, by a rule of yours (`sudo -n sh -c <the read>` allowed);
- Root access is on: the read runs as `sudo -n /usr/local/libexec/liminal/firewall-linux/read`, once the library has
  checked that the file installed is this plugin's own read as the library installs it, word for word; one that
  differs (an older plugin's, or one installed before its helpers set their own PATH) is not run, and the page says so;
- Root access is off: the firewall's rules are not read.

**Root access** (enable / disable) is a row on Main, shown only if required: never where the platform is root, nor where
a rule of yours runs the read. Its row says its state ("off: the firewall's rules are not read", "on: a rule lets its
read run as root, nothing else", on from the platform's next start, or an older plugin's read) and has one action:

- **Turn on…** asks for your password for sudo once, in a password field of its form ("used for this once, never
  kept"). Its words say exactly what is installed and where: the group `liminal` made where there is none
  (`groupadd --system liminal`, or BusyBox's `addgroup -S liminal`) and you put in it (`usermod -a -G liminal`, or
  `addgroup`), then, by one script checked before anything is put in place, the plugin's read as it runs it today at
  `/usr/local/libexec/liminal/firewall-linux/read` and a take-back helper beside it (root's, in a folder open to the
  group `liminal` alone, root:liminal 0750), and `/etc/sudoers.d/liminal-firewall-linux`, checked with `visudo -cf`
  before it is put in place, letting the group `liminal` run exactly those two files as root without a password, with
  no arguments, and nothing else. Never `NOPASSWD: ALL`. Anything running as you (or as another member of the group)
  can then run that one read as root; it reads and changes nothing. Each helper sets its own PATH, `LC_ALL=C`,
  `umask 077` and `cd /` and refuses any argument (the library's `helper_text`), since sudo hands a program the
  caller's PATH where sudoers sets no secure_path; the rule is tagged `NOPASSWD:NOSETENV:EXEC:`, so a site's
  `Defaults setenv` passes none of the caller's variables to them (NOPASSWD alone, and said, where the system's visudo
  refuses the other two); and the script refuses a folder on the way that is not root's, a symlink, or one writable by
  others or by a group other than root's (Debian's opt-in staff group, said in words).
- A membership counts for programs started after it (sudo reads the groups a program was started with), so Root
  access takes effect once the platform is started again, from a terminal opened after it was turned on (a shell
  opened before does not have the group; `newgrp liminal` in it gives it one). Until then its row says so, and Turn
  off… asks for the password too, since the take-back helper cannot run yet.
- **Turn off…** runs the take-back helper through `sudo -n`, with no password: the rule and the folder are removed,
  nothing else. The group `liminal` and its members stay: the Linux administration plugin manages them.

**Every change** still asks for your password at its own click unless the platform is root or a rule of yours lets sudo
run it: its form then ends with the password field, and its hook takes a last argument `password` (`make_rule`,
`remove_rule`, `set_policy`, `switch`, `save_rules`, after `accept_risk`, so a second confirmation sends it again). The
password is handed to `sudo -S -k -p '' --` on its standard input for that one command (the library's `Shell.run`),
alone: nothing follows it, so a mistyped one is one try, and the grant's script is an argument of `sh -c` whose first
line points its own standard input at /dev/null, so none of it reads a password sudo did not take. It is never kept,
logged, written, shown, put in a command line or an environment, nor left in an error's words. A
password sudo refuses is a refusal ("sudo did not accept the password: nothing was changed; type it again"), so the form
is filled again. A change asked without the password it needs (the framework's setup, the command line) is refused in
words before sudo is asked.

**A command of `run`** (0.10.0), asked only from a command line, runs as you. With `--elevated` it runs as root
through `sudo -n --`, never asking a password: so only where the platform is root or a rule of yours lets sudo run it
(below, From the command line). One refused for want of root, run as you, says so, and that such a rule counts only
with `--elevated`.

**Installing nftables.** Where none of nftables, iptables, ufw and firewalld is installed and the distribution's APT is
there (Debian, Ubuntu and their kin), the tool's row offers **Install nftables…**, a job: the distribution's own package
and what it needs that is not installed yet, as APT installs them. What that takes is read first without root and
changing nothing (`apt-get -s install nftables`, APT's simulation; `apt-cache show --no-all-versions` for each
package's Size, Installed-Size and Origin) and said on the form, for the user's Ubuntu 24.04: "Ubuntu's own nftables
package 1.0.9-1ubuntu0.1, with the 2 packages it needs that are not installed yet (libnftnl11, libnftables1): 494 kB to
download, 1.5 MB once installed". Then `apt-get install -y nftables` runs as root with `DEBIAN_FRONTEND=noninteractive`
(and `LC_ALL=C`, so APT's lock held by another program and a package not fetched are said in words), its last lines in
the plugin's panel. Installing it filters nothing. Elsewhere the row says how to install nftables on each distribution.

**Valid without root** (B-revisions S2). Where the firewall cannot be read for want of root, or there is no firewall
tool, the plugin is valid with a `problem`: its page has **What the firewall needs here**, its Root access row and the
tool's row, offering only what it can do (Turn on…, Install nftables…), no change it cannot make, and the platform asks
its tabs. A read failing for its own reasons, with root given, is not valid, as before.

**On a library from before 1.62.0** the plugin works as 0.8.1 did: everything through `sudo -n`, never a password; not
valid where it cannot be read, and its root row says that its Root access switch needs liminal-libs 1.62.0.

Inside WSL the "Under WSL" table follows, with a row for Root access where it is shown: Windows can enter a distribution
as root with no password (`wsl -u root`), which the platform never does, nor reaches in from Windows, so root is asked
of the distribution's own sudo, whose password is yours; Root access's rule and files are that distribution's alone, on
its own disk, and stay across its restarts; the group is the platform's once it is started again from a terminal opened
after, or after Windows has stopped the distribution and started it again. liminal-platform 0.29.0 draws a plugin's
tables while it is not valid yet; an older platform shows the reason alone.

## What the World Wide Web plugin asks of it

plugin-platform-worldwideweb draws the globe; this plugin answers it through the platform, with the library's Firewall
base's services (liminal-libs 1.105.0), only another plugin asking the changes, and one of its own:

- `netstat_seen`: the socket tables' last reading, the Netstat tab's own (one reading serves both).
- `hosts_found` and `hosts_routes`: the hosts recorded in the hosts database, and the routes traced to them that it
  keeps; `hosts_keep_route` keeps a route traced, `hosts_keep_places` and `hosts_clear_places` the places looked up in
  that plugin's GeoIP file (the Netstat tab's place column; with that plugin not attached the note says why).
- `rules_covering`: the rules of the last read covering a port.
- `capture_unseen(address)`: what an XDP program at the adapter holding the address that plugin's capture watches
  drops before libpcap sees it, in the words this plugin's own tab said until 0.13.0, from the read kept, running no
  command ("" for none).

On Windows and macOS each refuses in words, running nothing.

## The Netstat tab

The user's words (2026-11-16): "the firewall app should have a 'netstat' like interface for looking at active ports
and what apps they are attached to, and the hosts that they connect to across the lan or wan. the firewall app should
also have a globe that can be zoomed and rotated and geoip'd hosts are databased for the apps they talk to, the time
they are connected to *this *computer". The tab is the library's Firewall base's (liminal-libs 1.65.0:
`sockets.py`, `machines/netstat.py`), asked every 3 s while it is shown.

**What it shows.**

- The open connections, each with the program that holds it (its name and pid, and the systemd unit it runs in), the
  remote host and port, whether that host is this machine, the local network or the internet, its place when it is on
  the internet (from the World Wide Web plugin's GeoIP file), its name where `/etc/hosts` gives one, its state, and
  since when it was first seen here. Linux does not say when a connection began, so "Since" is when a reading first
  listed it. The page filters them by direction, by where the host is and by words, without asking again.
- The listening ports: each protocol, port and program, reached from every address or this machine only, with the
  four Liminal apps' pages named.
- The hosts database and its two forms, Recording and Forget (below).

**No rights needed.** The kernel's socket tables (`/proc/net/tcp`, `tcp6`, `udp`, `udp6`) list every socket of this
machine's network to any account, so the tab reads them as files, as the platform's user: no command, no capture, no
root, no window, and no name looked up. Only root may read which program holds another user's socket
(`/proc/<pid>/fd`), so such a socket is listed without its program, in words. A listening port another user holds is
named all the same where the firewall's own read (as root: `ss -ltnp`, `ss -lunp`) named its program: from the read
kept, with no command run for it (`netstat_listeners`). A UDP socket connected to a peer shows that peer, which
Windows cannot show. A connection shorter than the gap between two readings can be missed.

**Valid wherever the socket table can be read.** None of this needs root, so the plugin is valid, and in the tray,
wherever the kernel's socket tables can be read, whether or not the firewall itself can be: no firewall tool, sudo
asking for a password with Root access off, or a read that fails for its own reasons. Its Main page then says what is
missing and offers only what it can do, and its table of what the firewall needs ends with a row for the Netstat tab
and the hosts database: they need no rights. Where no socket table can be read, or with a library from before 1.65.0,
the plugin is as 0.8.2 was, and the row says why.

**Under WSL.** Inside a WSL distribution the tab ends with what WSL changes for it (the library's
`sockets.under_wsl`): the sockets listed are the distribution's own; what Windows' own programs listen on and connect
to is the Windows firewall plugin's Netstat to list; a platform that is not root reads as you. This plugin adds the
one thing more that was seen in the user's own Ubuntu (WSL 2, NAT networking, 2026-11-18): Windows' own programs reach
a TCP port listening there at 127.0.0.1 at Windows' 127.0.0.1 too. Windows' table listed `wslrelay.exe` at 127.0.0.1 on
exactly the TCP ports Linux programs listened on at 127.0.0.1, on none listening at another address (127.0.0.53,
10.255.255.254), and on no UDP port at all: chronyd's 127.0.0.1:323/udp there was not forwarded. So for TCP, "this
machine only" takes in Windows' programs there; for UDP it does not. How a connection from Windows looks from inside
(its peer, its owner), another distribution's sockets and WSL's mirrored networking were not seen: no connection was
open, none was opened to see one, no other distribution ran, and the networking was WSL's default NAT. The tab says
none of them.

## The hosts database

One small SQLite file on this machine's own disk (the data folder's `hosts/hosts.db`, made 0600 in a folder made
0700), the library's `hostbook.py`. For each program and remote host it keeps the ports, the first and the last time
seen, the total time connected to this machine, how many connections, and the host's GeoIP place (an internet host's
only: the local network's are never placed). It is fed from the same readings as the tab, rows capped at 50,000 (about
13 MB with ordinary values), the hosts longest unseen pruned first.

- **Recording** (a setting kept through the platform's login, `LIMINAL_HOSTS_RECORDING`): only while this plugin's
  Netstat tab or the World Wide Web plugin's tab is shown (the default), or all the time the platform runs, a reading
  every 5 s on a thread of its own. Off Windows today the login keeps a setting only until the platform restarts, and
  the page says so.
- **Forget...** removes every row, asked twice.
- Linux gives no start for a connection, so its time connected is what was seen: a gap of more than 30 s between two
  readings adds nothing.

## Its API

The user's words (2026-11-11): "each plugin should reflect the the API its attached to, and present links that provide
documentation, the plugin interface should more or less contain what it already has, BUT, it should also expose more of
what the API is about". Since 0.7.0 (plugin API 2.2) the plugin declares what it attaches to (`apis.py`), and the
platform's page draws each card: what the API is, its links, every part of it (those the plugin uses first, the rest
under "more of the API") and every call it makes, with the API's other notable calls beside them.

- **nftables**: [the nftables wiki](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page),
  [nft(8)](https://www.netfilter.org/projects/nftables/manpage.html),
  [libnftables-json(5)](https://manpages.debian.org/unstable/libnftables1/libnftables-json.5.en.html).
- **iptables and ip6tables**: [the project](https://www.netfilter.org/projects/iptables/),
  [iptables(8)](https://man7.org/linux/man-pages/man8/iptables.8.html),
  [iptables-save(8)](https://man7.org/linux/man-pages/man8/iptables-save.8.html),
  [xtables-nft(8)](https://manpages.debian.org/unstable/iptables/xtables-nft.8.en.html).
- **ebtables and arptables**: [ebtables](https://ebtables.netfilter.org/),
  [ebtables-nft(8)](https://man7.org/linux/man-pages/man8/ebtables-nft.8.html),
  [arptables-nft(8)](https://man7.org/linux/man-pages/man8/arptables-nft.8.html) (their versions only).
- **ipset**: [ipset](https://ipset.netfilter.org/), [ipset(8)](https://ipset.netfilter.org/ipset.man.html).
- **firewalld**: [its documentation](https://firewalld.org/documentation/),
  [firewall-cmd(1)](https://firewalld.org/documentation/man-pages/firewall-cmd.html),
  [firewalld.zones(5)](https://firewalld.org/documentation/man-pages/firewalld.zones.html).
- **ufw**: [ufw(8)](https://manpages.ubuntu.com/manpages/resolute/man8/ufw.8.html),
  [Firewalls (Ubuntu Server)](https://ubuntu.com/server/docs/how-to/security/firewalls/).
- **conntrack**: [the kernel's conntrack sysctls](https://docs.kernel.org/networking/nf_conntrack-sysctl.html),
  [conntrack-tools](https://conntrack-tools.netfilter.org/).
- **eBPF (bpftool)**: [the kernel's BPF documentation](https://docs.kernel.org/bpf/),
  [bpftool-net(8)](https://manpages.debian.org/unstable/bpftool/bpftool-net.8.en.html) (read only).
- **iproute2**: [ip-address(8)](https://man7.org/linux/man-pages/man8/ip-address.8.html),
  [ss(8)](https://man7.org/linux/man-pages/man8/ss.8.html).
- **The firewall's services** under systemd, OpenRC or SysV scripts.
- **sudo** (0.9.0): `sudo -n`, `sudo -S -k -p '' --` with the password on its standard input, Root access's files,
  `visudo -cf` and `sudo -n -l`: [sudo(8)](https://www.sudo.ws/docs/man/sudo.man/),
  [sudoers(5)](https://www.sudo.ws/docs/man/sudoers.man/), [visudo(8)](https://www.sudo.ws/docs/man/visudo.man/).
- **Users and groups** (0.9.0): the group liminal made and the platform's user put in it:
  [groupadd(8)](https://manpages.debian.org/unstable/passwd/groupadd.8.en.html),
  [usermod(8)](https://manpages.debian.org/unstable/passwd/usermod.8.en.html),
  [BusyBox's addgroup](https://busybox.net/downloads/BusyBox.html).
- **APT** (0.9.0): nftables installed where no tool is:
  [apt-get(8)](https://manpages.debian.org/unstable/apt/apt-get.8.en.html),
  [apt-cache(8)](https://manpages.debian.org/unstable/apt/apt-cache.8.en.html),
  [debconf(7)](https://manpages.debian.org/unstable/debconf-doc/debconf.7.en.html),
  [nftables on Debian](https://wiki.debian.org/nftables).

The Netstat tab's (0.9.0):

- **The kernel's socket tables (procfs)**: [proc_net_tcp](https://docs.kernel.org/networking/proc_net_tcp.html),
  [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html),
  [proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html),
  [WSL's networking](https://learn.microsoft.com/en-us/windows/wsl/networking). Read as files; sock_diag and `ss` are
  on its card, not used by the tab.
0.14.0: the World Wide Web tab's cards (libpcap and the right to capture, DB-IP, OpenDNS, Google's name servers and the
globe's data sets' sources) are plugin-platform-worldwideweb's, word for word as they were here.

`api_facts()` says what the last read found, asking nothing: each tool's version and variant, the tables, the sets,
firewalld's state, backend and default zone, ufw on or off, the connections tracked, the programs on the network's
hooks, the machine (its distribution, kernel and init) and when it was read. Once the Netstat tab has been asked
(0.9.0), it also says the socket tables' last reading, how the hosts are recorded and what the hosts database holds,
through `Firewall.netstat_view(make=False)`, which never makes one. Every address on the firewall's cards was read on
2026-11-11, on the socket tables' on 2026-11-18. The test `test_the_cards_pages_answer` asks each of them again when
`LIMINAL_VENDOR_PAGES=1` is set (it is skipped otherwise).

## From the command line

```
python -m plugin_platform_firewall_linux status
python -m plugin_platform_firewall_linux tables
python -m plugin_platform_firewall_linux rules in-allow 22
python -m plugin_platform_firewall_linux setup            # everything; or one step: setup exposure
python -m plugin_platform_firewall_linux exposure
python -m plugin_platform_firewall_linux allow web 8443
python -m plugin_platform_firewall_linux remove web
python -m plugin_platform_firewall_linux run -- ip -br addr                   # as you
python -m plugin_platform_firewall_linux run --elevated -- nft list ruleset   # as root, through sudo -n --
```

The platform app drives the same hooks from its page, all but `run`, which only a command line asks, in its own
process: this one, or the platform's `liminal-platform machine firewall-linux run -- COMMAND`. `run` runs the command
as you, the platform's own user (0.10.0). `--elevated`, counted only as run's first word, before the command's `--`,
runs it as root through the library's `sudo -n --`, never asking a password: so only where the platform is root or a
rule of yours lets sudo run that command without one; elsewhere it fails in words. The `--` after sudo's own words
is liminal-libs 1.80.0's, the release this plugin needs since 0.10.0: no word of the command is read as sudo's. Every
word after `--` is the command's own: `run -- x --elevated` runs `x` with that word, as you. Without a command the
usage is printed and nothing runs. The platform's command line has no `--elevated`: what it runs, it runs as you. A
command that needs root, run as you, fails in words that say it ran as you, not through sudo, and that a rule letting
sudo run it counts only for `run --elevated`. Until 0.10.0 `run` ran every command as root, and liminal-platform's
`POST /api/machines/<name>/run`, gone since its 0.34.1, handed it any words a program on this machine sent (the
independent review's finding PLT-H1, 2026-11-23).

## Tests

The tests run over recorded machines (`tests/recorded/<machine>/<section>`: what each part of the read printed there),
with a stand-in for the machine's commands (`tests/machines.py`); nothing runs. The machines are:

- Debian 13 with nftables of its own and Docker on iptables-nft.
- Ubuntu 24.04 with ufw.
- Fedora 43 Server with firewalld on nftables.
- Gentoo under OpenRC with nftables.
- Alpine 3.22 under OpenRC with BusyBox and legacy iptables.

The machine the tests run on never shows through (`tests/conftest.py`: not inside WSL, no init known), so the suite
reads alike inside a WSL distribution, on a Linux of any init and on Windows; what WSL changes is tested with the
library's tables stood in for.

Root access and nftables' install (0.9.0) are tested over the recorded machines and a stand-in sudo (`tests/sudo.py`:
it answers what liminal-libs 1.62.0's own `Shell.run`, `grant`, `revoke`, `granted` and `needs_password` run, as sudo
would: its listing, `cat` of the installed files, `sudo -S` with the password; so these tests are skipped on a library
from before them), in every state: not required as root or by a rule of yours, off, turned on (in force from the
platform's next start), on, an installed read that is not this plugin's; the install offered only without a tool and
with APT, its size from APT's own answers recorded on the user's Ubuntu (`tests/recorded/apt-ubuntu-24.04`: Ubuntu's
package metadata alone); the password field only where it is required; the password handed to sudo on its standard
input alone, never in an argument, an environment, a log, an answer, an error's words or the plugin's own attributes;
each hook taking its form's fields in the platform's order, a second confirmation included; and a library from before
the grant, by tests of their own that take its names away. No test starts
a process, opens a connection or resolves a name: `tests/conftest.py`'s guard fails one that does (the one test that
reaches the makers' pages on purpose, `LIMINAL_VENDOR_PAGES=1`, is marked `outside`). The machine's own grant, group
and tools never show through either.

The Netstat tab and the hosts database (0.9.0) are tested through the plugin (`tests/test_netstat.py`) over a stand-in
socket table and the recorded machines' reads: the socket tables' card naming every file the library's reader reads; the
listeners another user holds named from the read kept, running no command, and one net-tools names no program for ("-")
named by nothing; valid and present wherever the socket table can be read, its status saying so, present() running no
read of the firewall there, and what the firewall needs saying what the tab needs, as root or not; the Under WSL row
inside WSL 2 alone, TCP's alone; nothing on Windows or macOS; the cards' facts asking nothing. The suite's guard
(`tests/conftest.py`, `_no_real_hosts`, as the library's own suite has it) runs every test with
`LIMINAL_HOSTS_RECORDING=shown`, the real socket reader refused and the hosts database in the test's own folder, so a
plugin a test attaches never reads this machine's sockets into this machine's database; and one test of its own attaches
one under a login that says always. This machine's hosts file names no address in a test either. What the World Wide Web
plugin asks of it (0.14.0) is tested in `tests/test_services.py`; the globe's own tests are that plugin's.

run() (0.10.0) is tested over a stand-in shell (`tests/test_run.py`): a command runs as you, and as root only when
elevated, after sudo's words as the library's Shell puts them (`machines.shell_sudo()`), which must end with `--`, the
package's floor being the library that puts it there; its words, one beginning with a dash too, are handed on as they
are; a platform that is root runs it as itself; the command line counts `--elevated` only before the command's `--`,
and runs nothing without a command; and a command refused for want of root names `run --elevated` only where it ran
as you. Who may ask the changes (0.10.0) is tested through the library's own App, over a recorded machine
(`tests/test_who_asks.py`): another plugin's ask and one that names no asker are refused and run nothing, not even a
read, while the page's runs. And the framework's allow is given the remotes the review sent nft
(`tests/test_plugin.py`), each refused with nothing run.
