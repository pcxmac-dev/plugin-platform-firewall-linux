# plugin-platform-firewall-linux

Linux firewall for Liminal: ufw, firewalld or nftables on a Linux machine or in a WSL distribution, on, the framework's pages kept to the machine, the ports its services need opened as Liminal's own rules.

The user's words (2026-11-07): "the platform is the interface for the software/hardware which facilitates the
liminal framework"; "i also need a windows and linux firewall plugin for the platform"; "and a windows and
linux admin plugin for platform".

## What it does

A machine plugin of the platform (`liminal_libs.machines.firewall.Firewall`, plugin API 2.1) driving whichever
firewall the machine has, through the library's `machines.linux.Shell` (root through `sudo -n` here, never a
password asked; `wsl -u root` in a WSL distribution):

- ufw (Ubuntu): Liminal's rules commented `liminal:<name>`, read with `ufw show added` (on or off); before ufw is
  turned on, an SSH server listening keeps port 22 open as `liminal:ssh`, so a VPS stays reachable.
- firewalld (Fedora): each Liminal rule a service `liminal-<name>` in the default zone (a rich rule when it is for
  one network), `firewall-offline-cmd` when the daemon does not run, `systemctl enable --now firewalld` to turn
  it on.
- nftables (Gentoo, minimal systems): Liminal's rules inserted in the first input chain dropping by default,
  commented `liminal:<name>:<protocol>:<ports>:<remote>`; nftables has no switch, and where nothing filters no
  rule is needed.

The setup's steps: `enable`, `exposure` (a finding, never a change), `rules` (the ports the framework's services
need, a domain login's mail server container). `allow(name, ports)`, `remove(name)`: Liminal's own rules only.

Variables: `FIREWALL_LINUX_TARGET`: `local`, `wsl` or `wsl:<distribution>` (unset: this machine on Linux, Liminal's own
WSL distribution on Windows, Liminal-Ubuntu first). On a target that is not Liminal's (the user's own distribution)
the plugin runs no command at all.

## From the command line

```
python -m plugin_platform_firewall_linux status
python -m plugin_platform_firewall_linux setup            # everything; or one step: setup exposure
python -m plugin_platform_firewall_linux rules
python -m plugin_platform_firewall_linux exposure
python -m plugin_platform_firewall_linux allow web 8443
python -m plugin_platform_firewall_linux remove web
```

The platform app drives the same hooks from its page.
