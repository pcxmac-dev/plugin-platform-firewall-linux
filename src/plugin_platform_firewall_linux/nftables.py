"""nftables read from `nft -j list ruleset` (libnftables-json: {"nftables": [{"metainfo"}, {"table"}, {"chain"},
{"rule"}, {"set"}, {"map"}, ...]}): its tables, base chains with their hook and policy, every rule as an `Entry` with
the rule written out again in nft's own syntax, its sets, and whose each table is (firewalld's, Docker's, iptables-nft's,
this machine's own...). The commands that change it are built here too, never run."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from liminal_libs.machines.firewall import PREFIX

from .model import UNREACHED, Entry, digest, owner_by_interface, owner_by_name, ports_text

VERDICTS = ("accept", "drop", "reject", "jump", "goto", "return", "continue", "queue")
NAT = ("masquerade", "snat", "dnat", "redirect")
PLAIN_META = ("iif", "oif", "iifname", "oifname", "iiftype", "oiftype")
STRING_KEYS = ("iifname", "oifname", "ibrname", "obrname", "ibriport", "obriport")
L4 = ("tcp", "udp", "sctp", "dccp", "udplite", "icmp", "icmpv6", "ah", "esp", "comp", "igmp")
HOOK_DIRECTION = {"input": "in", "output": "out", "forward": "fwd"}
IPTABLES_TABLES = ("filter", "nat", "mangle", "raw", "security")
IPTABLES_FAMILIES = {"ip": "iptables", "ip6": "ip6tables", "arp": "arptables", "bridge": "ebtables"}
DORMANT = "its table is dormant"  # why a dormant table's rules filter nothing (0.6.0)


@dataclass(frozen=True)
class Table:
    family: str
    name: str
    handle: int = 0
    flags: tuple = ()
    comment: str = ""

    @property
    def key(self) -> str:
        return f"{self.family} {self.name}"


@dataclass(frozen=True)
class Chain:
    family: str
    table: str
    name: str
    handle: int = 0
    type: str = ""
    hook: str = ""
    prio: object = None
    policy: str = ""
    dev: str = ""
    comment: str = ""

    @property
    def key(self) -> str:
        return f"{self.family} {self.table} {self.name}"

    @property
    def base(self) -> bool:
        return bool(self.hook)


@dataclass(frozen=True)
class Rule:
    family: str
    table: str
    chain: str
    handle: int
    expr: tuple
    comment: str = ""

    @property
    def chain_key(self) -> str:
        return f"{self.family} {self.table} {self.chain}"


@dataclass(frozen=True)
class NSet:
    family: str
    table: str
    name: str
    kind: str  # set | map
    type: str
    flags: tuple = ()
    elements: int = 0
    comment: str = ""


@dataclass
class Ruleset:
    version: str = ""
    schema: int = 0
    tables: list = field(default_factory=list)
    chains: list = field(default_factory=list)
    rules: list = field(default_factory=list)
    sets: list = field(default_factory=list)
    others: dict = field(default_factory=dict)  # flowtables, counters, quotas, ct helpers...: how many of each

    def chain(self, family: str, table: str, name: str) -> Chain | None:
        return next((c for c in self.chains if (c.family, c.table, c.name) == (family, table, name)), None)

    def rules_of(self, chain: Chain) -> list[Rule]:
        return [r for r in self.rules if (r.family, r.table, r.chain) == (chain.family, chain.table, chain.name)]

    def table(self, family: str, name: str) -> Table | None:
        return next((t for t in self.tables if (t.family, t.name) == (family, name)), None)


def parse(text: str) -> Ruleset:
    """`nft -j list ruleset`'s answer; ValueError when it is not one."""
    raw = (text or "").strip()
    if not raw:
        return Ruleset()
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
        raise ValueError("not nftables' JSON: no nftables list")
    rs = Ruleset()
    for item in data["nftables"]:
        if not isinstance(item, dict) or len(item) != 1:
            continue
        (kind, o), = item.items()
        if not isinstance(o, dict):
            continue
        if kind == "metainfo":
            rs.version = str(o.get("version") or "")
            rs.schema = int(o.get("json_schema_version") or 0)
        elif kind == "table":
            flags = o.get("flags") or ()
            rs.tables.append(Table(o.get("family", ""), o.get("name", ""), int(o.get("handle") or 0),
                                   tuple([flags] if isinstance(flags, str) else flags), str(o.get("comment") or "")))
        elif kind == "chain":
            dev = o.get("dev") or ""  # one device's name, or a list of them
            rs.chains.append(Chain(o.get("family", ""), o.get("table", ""), o.get("name", ""), int(o.get("handle") or 0),
                                   str(o.get("type") or ""), str(o.get("hook") or ""), o.get("prio"), str(o.get("policy") or ""),
                                   ", ".join(map(str, dev)) if isinstance(dev, list) else str(dev), str(o.get("comment") or "")))
        elif kind == "rule":
            rs.rules.append(Rule(o.get("family", ""), o.get("table", ""), o.get("chain", ""), int(o.get("handle") or 0),
                                 tuple(o.get("expr") or ()), str(o.get("comment") or "")))
        elif kind in ("set", "map"):
            elem = o.get("elem")
            flags = o.get("flags") or ()
            typ = o.get("type")
            if isinstance(typ, dict) and "typeof" in typ:  # declared by an expression: typeof ip saddr
                typ = "typeof " + left_text(typ["typeof"])
            rs.sets.append(NSet(o.get("family", ""), o.get("table", ""), o.get("name", ""), kind,
                                " . ".join(map(str, typ)) if isinstance(typ, list) else str(typ or ""),
                                tuple([flags] if isinstance(flags, str) else flags), len(elem) if isinstance(elem, list) else 0,
                                str(o.get("comment") or "")))
        else:
            rs.others[kind] = rs.others.get(kind, 0) + 1
    return rs


# -- writing a rule out again in nft's own syntax ---------------------------------------------------------------------
def _quote(s) -> str:
    return '"' + str(s).replace('"', '\\"') + '"'


def left_text(e) -> str:
    if not isinstance(e, dict):
        return value_text(e)
    if "payload" in e:
        p = e["payload"] or {}
        if "protocol" in p:
            return f"{p['protocol']} {p.get('field', '')}".strip()
        return f"@{p.get('base', '')},{p.get('offset', 0)},{p.get('len', 0)}"
    if "meta" in e:
        key = (e["meta"] or {}).get("key", "")
        return key if key in PLAIN_META else f"meta {key}"
    if "ct" in e:
        c = e["ct"] or {}
        return " ".join(w for w in ("ct", c.get("dir", ""), c.get("family", ""), c.get("key", "")) if w)
    if "fib" in e:
        f = e["fib"] or {}
        flags = f.get("flags") or []
        return "fib " + " . ".join([flags] if isinstance(flags, str) else flags) + f" {f.get('result', '')}"
    if "exthdr" in e:
        x = e["exthdr"] or {}
        return f"{x.get('name', '')} {x.get('field', '')}".strip()
    if "tcp option" in e:
        x = e["tcp option"] or {}
        return f"tcp option {x.get('name', '')} {x.get('field', '')}".strip()
    if "socket" in e:
        return f"socket {(e['socket'] or {}).get('key', '')}"
    if "rt" in e:
        return f"rt {(e['rt'] or {}).get('key', '')}"
    if "osf" in e:
        return "osf name"
    if "concat" in e:
        return " . ".join(left_text(x) for x in e["concat"])
    for op in ("&", "|", "^", "<<", ">>"):
        if op in e and isinstance(e[op], list) and len(e[op]) == 2:
            return f"{left_text(e[op][0])} {op} {value_text(e[op][1])}"
    return json.dumps(e, separators=(",", ":"))


def value_text(v, key: str = "") -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        return _quote(v) if key in STRING_KEYS else v
    if isinstance(v, list):  # flags: ct state established,related
        return ",".join(value_text(x, key) for x in v)
    if isinstance(v, dict):
        if "set" in v:
            items = v["set"] if isinstance(v["set"], list) else [v["set"]]
            return "{ " + ", ".join(value_text(x, key) for x in items) + " }"
        if "prefix" in v:
            p = v["prefix"] or {}
            return f"{value_text(p.get('addr'))}/{p.get('len')}"
        if "range" in v and isinstance(v["range"], list) and len(v["range"]) == 2:
            return f"{value_text(v['range'][0], key)}-{value_text(v['range'][1], key)}"
        if "elem" in v:
            return value_text((v["elem"] or {}).get("val"), key)
        if "concat" in v:
            return " . ".join(value_text(x, key) for x in v["concat"])
        return left_text(v)
    return str(v)


def verdict_text(s: dict) -> str | None:
    for k in ("accept", "drop", "continue", "return"):
        if k in s:
            return k
    if "jump" in s:
        return f"jump {(s['jump'] or {}).get('target', '')}"
    if "goto" in s:
        return f"goto {(s['goto'] or {}).get('target', '')}"
    if "reject" in s:
        r = s["reject"] or {}
        if not r:
            return "reject"
        typ, why = r.get("type", ""), r.get("expr", "")
        return "reject with " + (typ if typ in ("tcp reset",) else f"{typ} {why}".strip())
    if "queue" in s:
        return "queue"
    return None


def statement_text(s) -> str:
    if not isinstance(s, dict) or not s:
        return str(s)
    v = verdict_text(s)
    if v:
        return v
    (k, o), = list(s.items())[:1]
    if k == "match":
        op = o.get("op", "==")
        left = o.get("left")
        key = (left or {}).get("meta", {}).get("key", "") if isinstance(left, dict) and "meta" in left else ""
        right = value_text(o.get("right"), key)
        return f"{left_text(left)} {'' if op in ('==', 'in') else op + ' '}{right}"
    if k == "counter":  # its numbers left out: they move, and a change finds a rule by its words
        return f"counter name {_quote(o)}" if isinstance(o, str) else "counter"
    if k == "quota":
        if isinstance(o, str):
            return f"quota name {_quote(o)}"
        o = o or {}
        return f"quota {'over ' if o.get('inv') else ''}{o.get('val', 0)} {o.get('val_unit', 'bytes')}"
    if k == "log":
        o = o or {}
        words = ["log"] + ([f"prefix {_quote(o['prefix'])}"] if o.get("prefix") else []) + ([f"level {o['level']}"] if o.get("level") else [])
        if o.get("group") is not None:
            words.append(f"group {o['group']}")
        return " ".join(words)
    if k == "limit":
        o = o or {}
        unit = o.get("rate_unit", "packets")
        rate = f"{o.get('rate', 0)}{'' if unit == 'packets' else ' ' + unit}/{o.get('per', 'second')}"
        burst = f" burst {o['burst']} {o.get('burst_unit', unit)}" if o.get("burst") else ""
        return f"limit rate {'over ' if o.get('inv') else ''}{rate}{burst}"
    if k == "masquerade":
        return "masquerade" + (f" to :{value_text((o or {}).get('port'))}" if (o or {}).get("port") is not None else "")
    if k in ("snat", "dnat"):
        o = o or {}
        to = value_text(o.get("addr")) if o.get("addr") is not None else ""
        if o.get("port") is not None:
            to += f":{value_text(o.get('port'))}"
        fam = f"{o['family']} " if o.get("family") else ""
        return f"{k} {fam}to {to}".strip()
    if k == "redirect":
        return "redirect" + (f" to :{value_text((o or {}).get('port'))}" if (o or {}).get("port") is not None else "")
    if k == "notrack":
        return "notrack"
    if k == "mangle":
        return f"{left_text((o or {}).get('key'))} set {value_text((o or {}).get('value'))}"
    if k == "xt":
        o = o or {}
        return f"xt {o.get('type', '')} {_quote(o.get('name', ''))}"
    if k == "vmap":
        o = o or {}
        data = (o.get("data") or {})
        pairs = data.get("set") if isinstance(data, dict) else None
        if isinstance(pairs, list):
            inner = ", ".join(f"{value_text(p[0])} : {statement_text(p[1])}" for p in pairs if isinstance(p, list) and len(p) == 2)
            return f"{left_text(o.get('key'))} vmap {{ {inner} }}"
        return f"{left_text(o.get('key'))} vmap {value_text(data)}"
    if k == "flow":
        return f"flow {(o or {}).get('op', 'add')} {(o or {}).get('flowtable', '')}".strip()
    if k == "set":
        o = o or {}
        return f"{o.get('op', 'add')} {o.get('set', '')} {{ {value_text(o.get('elem'))} }}"
    if k == "ct helper":
        return f"ct helper set {_quote(o)}"
    return json.dumps(s, separators=(",", ":"))


def rule_text(rule: Rule) -> str:
    text = " ".join(statement_text(s) for s in rule.expr)
    return f"{text} comment {_quote(rule.comment)}" if rule.comment else text


# -- what a rule is for ---------------------------------------------------------------------------------------------
def vmap_pairs(s: dict) -> list:
    """A vmap statement's pairs written in the rule ([key, verdict], ...); none for a map declared apart (`vmap @name`,
    its data a name: 0.6.0, before which such a rule stopped the read)."""
    o = s.get("vmap") if isinstance(s, dict) else None
    data = o.get("data") if isinstance(o, dict) else None
    pairs = data.get("set") if isinstance(data, dict) else None
    return [p for p in pairs if isinstance(p, list) and len(p) == 2] if isinstance(pairs, list) else []


def _right_values(right) -> list:
    if isinstance(right, dict) and "set" in right:
        return right["set"] if isinstance(right["set"], list) else [right["set"]]
    if isinstance(right, list):
        return right
    return [right]


def view(rule: Rule) -> dict:
    """The fields of a rule (its verdict, protocol, ports, addresses, interface, states)."""
    out = {"action": "continue", "target": "", "protocol": "", "ports": "", "spans": (), "source": "", "destination": "",
           "interface": "", "state": "", "family": "", "counted": ""}
    for s in rule.expr:
        if not isinstance(s, dict):
            continue
        v = verdict_text(s)
        if v:
            out["action"], _, out["target"] = v.partition(" ")
            if out["action"] == "reject":
                out["target"] = ""
            continue
        if "vmap" in s:
            out["action"] = "vmap"
            key = (s["vmap"] or {}).get("key")
            if isinstance(key, dict) and "ct" in key and (key["ct"] or {}).get("key") == "state":
                accepted = [p[0] for p in vmap_pairs(s) if isinstance(p[1], dict) and "accept" in p[1]]
                out["state"] = ",".join(str(a) for a in accepted)
            continue
        for k in NAT:
            if k in s:
                out["action"] = "nat"
                out["target"] = statement_text(s)
        if "counter" in s and isinstance(s["counter"], dict):
            out["counted"] = f"{s['counter'].get('packets', 0)} packets, {s['counter'].get('bytes', 0)} bytes"
        if "limit" in s and out["action"] == "continue":
            out["limited"] = True
        m = s.get("match")
        if not isinstance(m, dict):
            continue
        left, right, op = m.get("left"), m.get("right"), m.get("op", "==")
        neg = "not " if op == "!=" else ""
        if not isinstance(left, dict):
            continue
        if "payload" in left:
            p = left["payload"] or {}
            proto, fld = p.get("protocol", ""), p.get("field", "")
            if proto in L4 and fld in ("dport", "sport", "type"):
                out["protocol"] = proto
            if fld == "dport":
                vals = _right_values(right)
                spans = []
                for x in vals:
                    if isinstance(x, int):
                        spans.append((x, x))
                    elif isinstance(x, dict) and "range" in x and all(isinstance(y, int) for y in x["range"]):
                        spans.append((x["range"][0], x["range"][1]))
                out["ports"] = neg + (ports_text(spans) if spans and len(spans) == len(vals) else value_text(right))
                out["spans"] = tuple(spans) if not neg and spans and len(spans) == len(vals) else ()
            elif fld == "saddr":
                out["source"] = neg + value_text(right)
            elif fld == "daddr":
                out["destination"] = neg + value_text(right)
            elif proto in ("ip", "ip6") and fld in ("protocol", "nexthdr"):
                out["protocol"] = value_text(right)
        elif "meta" in left:
            key = (left["meta"] or {}).get("key", "")
            if key in ("iifname", "iif", "oifname", "oif"):
                out["interface"] = neg + (right if isinstance(right, str) else value_text(right, key))
            elif key == "l4proto":
                out["protocol"] = neg + value_text(right)
            elif key == "nfproto":
                out["family"] = {"ipv4": "ipv4", "ipv6": "ipv6"}.get(str(right), "")
        elif "ct" in left and (left["ct"] or {}).get("key") == "state":
            out["state"] = neg + value_text(right)
    if out["action"] == "continue" and out.pop("limited", False):
        out["action"] = "limit"
    out.pop("limited", None)
    return out


# -- whose a table is, which hooks reach a chain --------------------------------------------------------------------
def iptables_tables(rs: Ruleset, saved: dict) -> set:
    """The tables iptables-nft made (iptables-nft-save lists them in its own syntax): {(family, name)}. `saved`: the
    tables iptables-save, ip6tables-save, arptables-save and ebtables-save of the nf_tables variant listed, by family."""
    out = set()
    for t in rs.tables:
        if t.name in saved.get(t.family, ()):
            out.add((t.family, t.name))
    return out


def table_owner(t: Table, chains: list) -> str:
    """The program that made a table ("own" when nothing says): its name, the interfaces its chains are bound to, or the
    kernel's owner flag (a table only its owning program may change: firewalld's is owner and persist)."""
    owner = owner_by_name(t.name)
    if owner:
        return owner
    if "owner" in t.flags or "persist" in t.flags:
        return "owned"
    if t.comment.lower().startswith(PREFIX):
        return "liminal"
    for c in chains:
        if c.family == t.family and c.table == t.name and c.dev and owner_by_interface(c.dev):
            return owner_by_interface(c.dev)
    return "own"


def reached(rs: Ruleset) -> dict:
    """The hooks each chain is reached from (its own when a base chain; through jumps and gotos otherwise)."""
    targets: dict = {}
    for r in rs.rules:
        for s in r.expr:
            if not isinstance(s, dict):
                continue
            for k in ("jump", "goto"):
                if k in s and isinstance(s[k], dict):
                    targets.setdefault(r.chain_key, set()).add(f"{r.family} {r.table} {s[k].get('target', '')}")
            if "vmap" in s:
                for p in vmap_pairs(s):
                    if isinstance(p[1], dict):
                        for k in ("jump", "goto"):
                            if k in p[1] and isinstance(p[1][k], dict):
                                targets.setdefault(r.chain_key, set()).add(f"{r.family} {r.table} {p[1][k].get('target', '')}")
    hooks: dict = {}
    for c in rs.chains:
        if not c.base:
            continue
        todo, seen = [c.key], set()
        while todo:
            k = todo.pop()
            if k in seen:
                continue
            seen.add(k)
            hooks.setdefault(k, set()).add((c.hook, c.type))
            todo.extend(targets.get(k, ()))
    return hooks


def reachable_from(rs: Ruleset, chain: Chain) -> set:
    """The chains a base chain reaches (itself, and those it jumps or goes to, on and on), by their keys."""
    targets: dict = {}
    for r in rs.rules:
        for s in r.expr:
            if isinstance(s, dict):
                for k in ("jump", "goto"):
                    if k in s and isinstance(s[k], dict):
                        targets.setdefault(r.chain_key, set()).add(f"{r.family} {r.table} {s[k].get('target', '')}")
    todo, seen = [chain.key], set()
    while todo:
        k = todo.pop()
        if k not in seen:
            seen.add(k)
            todo.extend(targets.get(k, ()))
    return seen


def vmap_by_name(rule: Rule) -> bool:
    """Whether a rule decides through a verdict map declared apart (`vmap @name`): the chains it jumps to are not read
    here, so none of its table's chains is said to be reached by nothing."""
    for s in rule.expr:
        if isinstance(s, dict) and isinstance(s.get("vmap"), dict):
            data = s["vmap"].get("data")
            if not (isinstance(data, dict) and isinstance(data.get("set"), list)):
                return True
    return False


def direction_of(hooks) -> str:
    names = {h for h, _ in hooks}
    for hook in ("input", "output", "forward"):
        if hook in names:
            return HOOK_DIRECTION[hook]
    if any(t == "nat" for _, t in hooks):
        return "nat"
    return "other"


def entries(rs: Ruleset, skip: set = frozenset()) -> list[Entry]:
    """Every rule as an Entry, those of the tables in `skip` ({(family, name)}: iptables-nft's, read in its own syntax)
    left out; turned off (0.6.0), a dormant table's (its base chains are off their hooks, so none of it is evaluated) and
    one in a chain no base chain jumps or goes to."""
    hooks = reached(rs)
    owners = {(t.family, t.name): table_owner(t, rs.chains) for t in rs.tables}
    dormant = {(t.family, t.name) for t in rs.tables if "dormant" in t.flags}
    by_map = {(r.family, r.table) for r in rs.rules if vmap_by_name(r)}  # its chains may be reached through such a map
    chain_by = {c.key: c for c in rs.chains}
    out = []
    for r in rs.rules:
        if (r.family, r.table) in skip:
            continue
        v = view(r)
        c = chain_by.get(r.chain_key)
        hk = hooks.get(r.chain_key, set())
        direction = direction_of(hk) if hk else "other"
        if c is not None and c.base and c.type == "nat":
            direction = "nat"
        owner = owners.get((r.family, r.table), "own")
        if owner == "own":
            if r.comment.startswith(PREFIX + ":"):
                owner = "liminal"
            elif owner_by_name(r.chain) and owner_by_name(r.chain) != "liminal":
                owner = owner_by_name(r.chain)
            elif v["target"] and owner_by_name(v["target"]) not in ("", "liminal"):
                owner = owner_by_name(v["target"])
        family = {"ip": "ipv4", "ip6": "ipv6"}.get(r.family, v["family"])
        text = rule_text(r)
        out.append(Entry(ref=f"nft|{r.family}|{r.table}|{r.chain}|{r.handle}|{digest(json.dumps(r.expr, sort_keys=True), r.comment)}",
                         kind="nftables", where=f"{r.family} {r.table} {r.chain}", direction=direction, action=v["action"],
                         text=text, target=v["target"], protocol=v["protocol"], ports=v["ports"], spans=v["spans"],
                         source=v["source"], destination=v["destination"], interface=v["interface"], state=v["state"],
                         comment=r.comment, owner=owner, family=family, number=r.handle, counted=v["counted"],
                         off=DORMANT if (r.family, r.table) in dormant
                         else UNREACHED if c is not None and not c.base and not hk and (r.family, r.table) not in by_map
                         else ""))
    return out


# -- the commands that change it ------------------------------------------------------------------------------------
def match_words(protocol: str, spans, source: str, interface: str, direction: str, family: str) -> list[str]:
    """nft's words for what a rule is for, as `nft` takes them one argument each."""
    words: list[str] = []
    if interface:
        words += ["oifname" if direction == "out" else "iifname", _quote(interface)]
    if source:
        words += ["ip6" if ":" in source else "ip", "daddr" if direction == "out" else "saddr", source]
    elif family in ("ipv4", "ipv6"):
        words += ["meta", "nfproto", family]
    if spans:
        listed = [str(a) if a == b else f"{a}-{b}" for a, b in spans]
        words += [protocol, "dport"] + (["{", ", ".join(listed), "}"] if len(listed) > 1 else listed)
    elif protocol in ("tcp", "udp"):
        words += ["meta", "l4proto", protocol]
    return words


def comment_of(name: str, protocol: str, spans, source: str) -> str:
    """Liminal's comment on an nftables rule: liminal:<name>:<protocol>:<ports>:<remote> (the framework's own read)."""
    ports = ",".join(str(a) if a == b else f"{a}-{b}" for a, b in spans)
    return f"{PREFIX}:{name}:{protocol or 'any'}:{ports}:{source or 'any'}"


def insert_rule(chain: Chain, words: list[str], verdict: str, comment: str, before: int | None = None) -> list[str]:
    """`nft insert rule` at the head of the chain, or before the rule with the handle `before` (`handle N`: the older
    `position N` is no longer documented)."""
    where = ["handle", str(before)] if before else []
    return ["nft", "insert", "rule", chain.family, chain.table, chain.name, *where, *words, verdict, "comment", _quote(comment)]


def add_rule(chain: Chain, words: list[str], verdict: str, comment: str) -> list[str]:
    return ["nft", "add", "rule", chain.family, chain.table, chain.name, *words, verdict, "comment", _quote(comment)]


def delete_rule(family: str, table: str, chain: str, handle: int) -> list[str]:
    return ["nft", "delete", "rule", family, table, chain, "handle", str(handle)]


def set_policy(chain: Chain, policy: str) -> list[str]:
    """`nft add chain FAMILY TABLE NAME { policy X; }`: an existing base chain's policy changed alone."""
    return ["nft", "add", "chain", chain.family, chain.table, chain.name, "{", "policy", f"{policy};", "}"]


def catch_all(rule: Rule) -> bool:
    """A rule dropping or refusing everything left (a chain's last word): an allow goes before it."""
    kinds = [next(iter(s)) for s in rule.expr if isinstance(s, dict) and s]
    rest = [k for k in kinds if k not in ("counter", "log", "limit")]
    return rest in (["drop"], ["reject"])
