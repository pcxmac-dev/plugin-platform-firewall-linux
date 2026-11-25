"""The plugin's network part (0.11.0; liminal-libs 1.96.0's NetworkHost; service-containers-networking-2026-11-23.md
§5.4 to §5.7 and §14: decisions 20 (b), N9 and N10; SERVICE-INTERFACE.md §9's stack). The user, 2026-11-23: "all
services/containers will use the firewall app to create routing for the IP ranges of the containers"; "all this is
mediated between the firewall API and the containers (plugin to plugin)".

- Its stack: "wsl" inside a WSL distribution (every Linux inside WSL 2 shares one VM's network: the Linux platform's
  firewall-linux owns it, N9), "linux" on a machine of its own (containers.stack_of). It hands out from the Linux half
  of Liminal's pool (10.77.128.0/17) and routes to no other stack: a bridge on this host is a connected route.
- A nested segment (LXD's Docker inside liminal-oci, Want.behind) gets `ip route replace <its /24> via <liminal-oci's
  address>`, as root, inside its plan; Linux drops it at a reboot, and the next Start makes it again.
- The limit (decision 20, changed to b): on a machine of its own, before a service's published ports meet your network,
  new connections to them are kept to your subnets: in DOCKER-USER where Docker's iptables backend has that chain
  (established traffic first, the original destination matched through conntrack, Docker's own pattern), else in
  Liminal's own `inet liminal` table, a forward chain at a priority before Docker's; never inside Docker's own tables.
  Inside WSL nothing is written for it (N9: in NAT mode nothing but Windows reaches the VM; Windows' firewall opens it).
- Inside WSL every change to its one network is asked a second time (`accept_shared`) while another distribution's
  engine is seen there (its bridges here, and no engine of this distribution's own).
- Its rules are marked `liminal:<rule> platform=<the platform that made them>`, so two writers never take each other's.
- Root: sudo -n (Root access, or a rule of yours), never a password: a plan is carried out by a container plugin's work,
  where no form is typed into. A change that needs your password is refused in words before anything runs."""
from __future__ import annotations

import ipaddress
import re
import shlex

from liminal_libs.instances import Refusal
from liminal_libs.machines import linux as linux_mod
from liminal_libs.machines.containers import rule_name, stack_of
from liminal_libs.machines.plans import Accept, Cancelled
from liminal_libs.machines.segments import ACCEPT_SHARED, POOL, NetworkHost, Step

ENGINE_LINKS = ("docker0", "br-", "lxdbr0", "incusbr0", "cni0", "flannel")
OWN_ENGINES = ("/var/run/docker.sock", "/run/docker.sock", "/var/lib/incus/unix.socket", "/var/snap/lxd/common/lxd/unix.socket")
TABLE, CHAIN = "inet liminal", "svc-forward"
NEVER = ("iptables -F", "iptables -X", "nft flush ruleset", "-t nat", "DOCKER ", "ip-forward-no-drop")


def _pool_prefix(value) -> str:
    net = ipaddress.ip_network(str(value), strict=True)
    if net.version != 4 or not net.subnet_of(ipaddress.ip_network(POOL)) or net.prefixlen < 16:
        raise Refusal(f"{value} is not a segment of Liminal's pool ({POOL})")
    return str(net)


def _private(value, what: str) -> str:
    ip = ipaddress.ip_address(str(value))
    if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local:
        raise Refusal(f"{what} {value} is not a private IPv4 address")
    return str(ip)


def _subnet(value) -> str:
    net = ipaddress.ip_network(str(value), strict=False)
    if net.version != 4 or not net.is_private or net.prefixlen < 8:
        raise Refusal(f"{value} is not one of your private subnets")
    return str(net)


def _mark(rule: str, platform: str) -> str:
    if not re.fullmatch(r"svc-[a-z0-9-]{1,44}", str(rule)):
        raise Refusal(f"{str(rule)[:60]!r} is not a service's rule name")
    if not re.fullmatch(r"[A-Za-z0-9:._-]{0,80}", str(platform)):
        raise Refusal("the platform's name does not fit a rule's mark")
    return f"liminal:{rule} platform={platform}"


def limit_script(d: dict, make: bool) -> str:
    """The limit for one published port: DOCKER-USER where that chain is (iptables), else Liminal's own forward chain
    (nftables). Taking it away removes exactly the rules carrying its mark."""
    port = int(d["host"])
    if not 0 < port < 65536:
        raise Refusal(f"{port} is not a port")
    proto = "udp" if str(d.get("protocol")) == "udp" else "tcp"
    subnets = [_subnet(s) for s in d.get("subnets") or []]
    if make and not subnets:
        raise Refusal("no subnet of yours is known here: the limit would let nothing in")
    mark = _mark(d["rule"], str(d.get("platform") or ""))
    q = shlex.quote(mark)
    base = f"-p {proto} -m conntrack --ctorigdstport {port} --ctdir ORIGINAL"
    if make:
        xt = [f"iptables -I DOCKER-USER {base} -m comment --comment {q} -j DROP",
              *(f"iptables -I DOCKER-USER {base} --ctorigsrc {s} -m comment --comment {q} -j RETURN" for s in subnets),
              f"iptables -I DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment {q} -j RETURN"]
        allowed = ", ".join(subnets)
        nft = [f"nft add table {TABLE}",
               f"nft add chain {TABLE} {CHAIN} '{{ type filter hook forward priority -1; policy accept; }}'",
               f"nft add rule {TABLE} {CHAIN} meta l4proto {proto} ct original proto-dst {port} ct state new "
               f"ip saddr != {{ {allowed} }} drop comment {q}"]
    else:
        xt = [f"iptables -S DOCKER-USER | grep -F -- {q} | sed 's/^-A /-D /' | while read -r r; do eval \"iptables $r\"; "
              "done"]
        nft = [f"for h in $(nft -a list chain {TABLE} {CHAIN} 2>/dev/null | grep -F -- {q} | sed -n 's/.*# handle "
               f"\\([0-9]*\\)$/\\1/p'); do nft delete rule {TABLE} {CHAIN} handle $h; done"]
    return ("if iptables -nL DOCKER-USER >/dev/null 2>&1; then\n  " + "\n  ".join(xt) + "\nelse\n  "
            + "\n  ".join(nft) + "\nfi")


def step_script(s: Step) -> str:
    d = dict(s.detail)
    if s.kind == "route":
        return f"ip route replace {_pool_prefix(d.get('prefix'))} via {_private(d.get('next_hop'), 'the next hop')}"
    if s.kind == "unroute":
        return f"ip route del {_pool_prefix(d.get('prefix'))} 2>/dev/null || true"
    if s.kind in ("proxy", "unproxy"):
        if not d.get("limit"):
            return ": nothing written here (inside WSL, Windows' firewall opens it)"
        return limit_script(d, s.kind == "proxy")
    raise Refusal(f"no template for a {s.kind!r} step")


def steps_script(steps) -> str:
    body = "\n".join(step_script(s) for s in steps)
    if any(word in body for word in NEVER):
        raise Refusal("a step would write what Liminal never writes (Docker's own tables, a flush)")
    return "set -e\n" + body + "\n"


class LinuxNetwork(NetworkHost):
    """The Linux firewall's network part: what NetworkHost asks of a subclass, on the Linux the platform runs on."""

    DOMAIN_DEFAULT = None  # the user sets the domain: Liminal picks none

    def in_wsl(self) -> str:
        """The WSL distribution this Linux is ("" on a machine of its own); a test's word first."""
        said = self.__dict__.get("_wsl_word")
        return linux_mod.wsl() if said is None else said

    def stacks(self) -> dict:
        return {"own": stack_of(True, bool(self.in_wsl())), "routes_to": ()}

    def _ip(self, *args: str) -> str:
        if self.not_for_here():
            raise Refusal(f"not for this machine: {self.not_for_here()}")
        return self.shell.run("ip", *args, root=False, timeout=30)

    def networks_here(self) -> list[str]:
        out = []
        for line in self._ip("-4", "-o", "addr", "show").splitlines():
            m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
            if m:
                out.append(str(ipaddress.ip_interface(m.group(1)).network))
        for line in self._ip("-4", "route", "show").splitlines():
            first = line.split(" ", 1)[0]
            if first and first != "default":
                try:
                    out.append(str(ipaddress.ip_network(first if "/" in first else first + "/32", strict=False)))
                except ValueError:
                    continue
        return sorted(set(out))

    def your_subnets(self) -> list[str]:
        """Your network's subnets: those of the interfaces carrying a default route, never an engine's bridge."""
        dev = {m.group(1) for m in re.finditer(r"^default .*?\bdev (\S+)", self._ip("-4", "route", "show"), re.M)}
        out = []
        for line in self._ip("-4", "-o", "addr", "show").splitlines():
            m = re.match(r"\s*\d+:\s*(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
            if m and m.group(1) in dev and not m.group(1).startswith(ENGINE_LINKS):
                out.append(str(ipaddress.ip_interface(m.group(2)).network))
        return sorted(set(out))

    def engine_elsewhere(self) -> str:
        """Inside WSL: words naming another distribution's engine in its one network (its bridges seen here while no
        engine of this distribution's own is), or ""."""
        if not self.in_wsl():
            return ""
        links = [m.group(1) for m in re.finditer(r"^\s*\d+:\s*([^:@\s]+)", self._ip("-o", "link", "show"), re.M)
                 if m.group(1).startswith(ENGINE_LINKS)]
        if not links:
            return ""
        own = self.__dict__.get("_own_engine")
        if own is None:
            import os

            own = any(os.path.exists(p) for p in OWN_ENGINES)
        return "" if own else f"another WSL distribution's engine ({', '.join(links[:4])} seen in WSL's one network)"

    def more_net_accepts(self, act, sid, w, steps) -> list[Accept]:
        other = self.engine_elsewhere()
        if not other:
            return []
        return [Accept(ACCEPT_SHARED, "Change WSL's one network?",
                       f"WSL's network is shared by every distribution, your own among them, and {other} runs there: "
                       "this change reaches it too", "Change it")]

    def lan_state(self, port: int, protocol: str) -> dict:
        if self.in_wsl():
            return {"state": "closed", "words": "inside WSL's NAT nothing but Windows reaches this machine"}
        try:
            hits = self.exposing([int(port)])
        except Exception:  # noqa: BLE001 - the firewall not read: not known
            return {"state": "unknown", "words": "the firewall is not read"}
        if hits:
            return {"state": "wider", "words": f"{hits[0][1]} lets it in"}
        return {"state": "past", "words": "Docker's published ports pass ufw and firewalld: the limit keeps them to "
                                          "your subnets"}

    def lan_detail(self, sid: str, port, address: str) -> dict:
        host = int(port.get("host"))
        rule = f"{rule_name(sid)}-{host}"
        if self.in_wsl():
            return {"limit": False, "rule": rule, "words": "inside WSL nothing is written here (WSL's NAT: Windows' "
                    "firewall opens it to your network)"}
        subnets = self.your_subnets()
        if not subnets:
            raise Refusal("this machine has no subnet of yours with a default route: nothing would be let in")
        return {"limit": True, "rule": rule, "subnets": subnets, "platform": self._platform(),
                "words": f"new connections to it kept to {', '.join(subnets)} (DOCKER-USER, or Liminal's own inet "
                         "liminal table: never Docker's own)"}

    def run_steps(self, steps, line, cancelled) -> None:
        """Every step of a plan in one root sh script from the fixed templates, through sudo -n alone."""
        script = steps_script(steps)
        if cancelled():
            raise Cancelled("cancelled before anything ran")
        sh = self.shell
        if not sh.root() and self._change_wants_password():
            raise Refusal("this change needs your password for sudo, which a service's work cannot type: turn Root "
                          "access on on this plugin's page (or a sudoers rule), then plan it again")
        for s in steps:
            line(s.words)
        try:
            sh.run("sh", "-s", root=True, stdin=script, timeout=120)
        finally:
            self.forget()
        line(f"done: {len(steps)} step(s) made")


__all__ = ["LinuxNetwork", "limit_script", "step_script", "steps_script", "NEVER"]
