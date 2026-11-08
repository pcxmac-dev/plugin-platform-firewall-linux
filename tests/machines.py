"""A stand-in for a native Linux machine's commands, over recorded outputs (tests/recorded/<machine>/<section>: what each
part of the firewall's read printed there; `rc` lists the parts that failed with their exit codes). The read script is
answered with the sections in its own form; every other command is kept in `changes` and answered as the test says.
Nothing runs here."""
from __future__ import annotations

import json
import pathlib

from plugin_platform_firewall_linux.read import MARK, SCRIPT

RECORDED = pathlib.Path(__file__).parent / "recorded"
ORDER = ("os", "kernel", "init", "tools", "nft.version", "nft", "nft.err", "iptables.version", "iptables.save", "ip6tables.save",
         "iptables.legacy", "ip6tables.legacy", "ebtables.version", "arptables.version", "ipset.version", "ipset",
         "firewalld.state", "firewalld.version", "firewalld.default", "firewalld.zones", "firewalld.policies",
         "firewalld.services", "firewalld.conf", "ufw.version", "ufw.verbose", "ufw.numbered", "ufw.added", "conntrack", "addr",
         "addr.text", "bpf", "listen", "listen.netstat", "established", "services", "files", "conf")


def recorded(machine: str) -> dict:
    """A machine's recorded sections: {name: (exit code, output)}."""
    folder = RECORDED / machine
    codes = {}
    if (folder / "rc").exists():
        for line in (folder / "rc").read_text(encoding="utf-8").splitlines():
            name, _, code = line.partition(" ")
            if name:
                codes[name] = int(code)
    out = {}
    for f in folder.iterdir():
        if f.name == "rc" or f.is_dir():
            continue
        out[f.name] = (codes.get(f.name, 0), f.read_text(encoding="utf-8"))
    return out


def answer(sections: dict) -> str:
    """The read script's answer for these sections, as the script prints it."""
    parts = [MARK]
    names = [n for n in ORDER if n in sections] + sorted(n for n in sections if n not in ORDER)
    for n in names:
        rc, text = sections[n]
        parts.append(f"\n@@ {n} {rc}\n{text.rstrip(chr(10))}")
    parts.append("\n@@ end 0\n")
    return "\n".join(parts)


class FakeLinux:
    """Answers the firewall's read from a recorded machine (sections changed by the test), and keeps every other command.
    `replies`: a command's first words -> (exit code, output, errors), for the commands a test answers itself."""

    def __init__(self, machine: str, **changed):
        self.sections = recorded(machine)
        for k, v in changed.items():
            self.sections[k.replace("_", ".")] = v if isinstance(v, tuple) else (0, v)
        self.calls: list[list[str]] = []
        self.reads = 0
        self.replies: dict = {}
        self.stdin: list = []

    def set(self, name: str, text: str, rc: int = 0) -> None:
        self.sections[name] = (rc, text)

    def nft(self, data: dict) -> None:
        self.sections["nft"] = (0, json.dumps(data))

    def __call__(self, args, timeout):
        self.calls.append(list(args))
        cmd = args[2:] if args[:2] == ["sudo", "-n"] else list(args)
        if cmd[:2] == ["sh", "-c"] and cmd[2] == SCRIPT:
            self.reads += 1
            return 0, answer(self.sections), ""
        for first, reply in self.replies.items():
            if tuple(cmd[:len(first)]) == tuple(first):
                return reply
        return 0, "", ""

    @property
    def changes(self) -> list[list[str]]:
        """The commands run but the read, without sudo."""
        out = []
        for c in self.calls:
            cmd = c[2:] if c[:2] == ["sudo", "-n"] else c
            if cmd[:2] == ["sh", "-c"] and cmd[2] == SCRIPT:
                continue
            out.append(cmd)
        return out
