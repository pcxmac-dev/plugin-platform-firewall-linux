# Changelog

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
