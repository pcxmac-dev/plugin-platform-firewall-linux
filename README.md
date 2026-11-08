# plugin-platform-firewall-linux

Linux firewall for Liminal: the whole firewall of the native Linux machine the platform runs on, read and changed from
the platform's page. nftables, iptables (nf_tables and legacy), ebtables, arptables, ipset, firewalld, ufw, conntrack,
and eBPF/XDP (read only), under systemd, OpenRC or SysV scripts, on the major distributions and Gentoo.

The user's words. 2026-11-07: "the platform is the interface for the software/hardware which facilitates the liminal
framework"; "i also need a windows and linux firewall plugin for the platform". 2026-11-08, on the Windows one: "i need
it to be able to read the configuration, and make changes"; "basically the firewall plugin is an interface for windows
networking / defender / firewall, and will let me make queries and alter the firewall configurations". Then: "lets
mirror that for linux firewall, except research the current linux kernel, and make sure its compatable with
systemd/openrc it has access nftables, iptables, all the firewall technologies and libraries for the most modern
kernels, make sure its compatible with major distributions and gentoo linxu".

## What it reads

One read of the whole configuration (`read.SCRIPT`), run as root through the library's `machines.linux.Shell`
(`sudo -n` when the platform is not root; a password is never asked). The read is a POSIX shell script that BusyBox's
sh runs too. It is kept for a minute, and read again after each change and on Refresh. It reads:

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
- **Rules**: every rule.
  - Presets: inbound allowed, inbound blocked, outbound, forwarded and NAT, Liminal's, all.
  - Find: every word must be in the rule; a number also finds the rules for that port.
  - Buttons under it: Add a rule…, Find…, Refresh.
  - Each removable rule has its own Remove….
- **Sets**: nftables' sets and ipset's.

Valid whenever the firewall can be read, as the Windows firewall plugin is: off, or without Liminal's rules, is said in
the summary and the tables, not as invalid.

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

## Native Linux only

The user's words (2026-11-08): "the scope of linux administration is only on native linux O/S"; "it's not for
administrating WSL instances"; and, asked whether the firewall follows, "Yes, firewall too".

The plugin works only on the Linux machine the platform runs on. On Windows, on macOS and inside a WSL distribution it
runs no command at all. A WSL distribution is known by its kernel's release naming Microsoft or WSL, or by WSL's
variables being set (the library's `machines.linux.why_not_native`).

There its status says why and that it does not apply (`applies` False). The platform shows it disabled with no setup
offered, and its setup and every command are refused. A Windows PC's own firewall is the Windows firewall plugin's.

## Rights

Reading and changing the firewall need root. The plugin runs its commands through `sudo -n` when the platform is not
root, and never asks for a password. Without the rights, its status says "cannot be read" with sudo's words: run the
platform as root, or let sudo run `sh` and the firewall's tools without a password.

## From the command line

```
python -m plugin_platform_firewall_linux status
python -m plugin_platform_firewall_linux tables
python -m plugin_platform_firewall_linux rules in-allow 22
python -m plugin_platform_firewall_linux setup            # everything; or one step: setup exposure
python -m plugin_platform_firewall_linux exposure
python -m plugin_platform_firewall_linux allow web 8443
python -m plugin_platform_firewall_linux remove web
```

The platform app drives the same hooks from its page.

## Tests

The tests run over recorded machines (`tests/recorded/<machine>/<section>`: what each part of the read printed there),
with a stand-in for the machine's commands (`tests/machines.py`); nothing runs. The machines are:

- Debian 13 with nftables of its own and Docker on iptables-nft.
- Ubuntu 24.04 with ufw.
- Fedora 43 Server with firewalld on nftables.
- Gentoo under OpenRC with nftables.
- Alpine 3.22 under OpenRC with BusyBox and legacy iptables.
