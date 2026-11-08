"""`python -m plugin_platform_firewall_linux status | setup [STEP ...] | rules | exposure | allow NAME PORT[,PORT ...] [tcp|udp]
| remove NAME | run -- COMMAND`: the plugin from the command line (the platform app drives the same hooks)."""
from __future__ import annotations

import json
import sys

from liminal_libs.machines.firewall import app_ports
from liminal_libs.machines.plugin import CommandError

from . import MACHINE

USAGE = "python -m plugin_platform_firewall_linux status | setup [STEP ...] | rules | exposure | allow NAME PORT[,PORT ...] [tcp|udp] | remove NAME | run -- COMMAND"


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    what, rest = (argv[0], argv[1:]) if argv else ("status", [])
    try:
        if what == "status":
            print(json.dumps(MACHINE.status(), indent=1))
            return 0 if MACHINE.present() else 1
        if what == "setup":
            done = MACHINE.setup(log=print, steps=rest or None)
            return 0 if all(d["ok"] is not False for d in done) else 1
        if what == "rules":
            print(json.dumps([r.describe() for r in MACHINE.list_rules()], indent=1))
            return 0
        if what == "exposure":
            ports = app_ports()
            hits = MACHINE.exposing(sorted(set(ports.values())))
            print("\n".join(f"{p}: {label}" for p, label in hits) or "no rule lets another machine reach the framework's pages")
            return 1 if hits else 0
        if what == "allow" and len(rest) >= 2:
            rule = MACHINE.allow(rest[0], [int(p) for p in rest[1].split(",")], protocol=rest[2] if len(rest) > 2 else "tcp",
                                 detail="made from the command line")
            print(f"made: {rule.label}")
            return 0
        if what == "remove" and rest:
            print("removed" if MACHINE.remove(rest[0]) else f"no Liminal rule named {rest[0]}")
            return 0
        if what == "run":
            command = rest[1:] if rest[:1] == ["--"] else rest
            if command:
                print(MACHINE.run(*command), end="")
                return 0
    except (CommandError, ValueError) as e:
        print(str(e), file=sys.stderr)
        return 1
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
