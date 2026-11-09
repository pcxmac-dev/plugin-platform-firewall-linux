# Changelog

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
