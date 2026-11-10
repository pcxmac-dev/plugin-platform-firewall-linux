# Changelog

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
