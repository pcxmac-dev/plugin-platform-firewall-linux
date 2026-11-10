"""ufw read from `ufw status verbose` (on or off, logging, the defaults for incoming, outgoing and routed), `ufw status
numbered` (its rules as it numbers them, while it is on) and `ufw show added` (its rules as they were added, on or
off): every rule an `Entry` (ufw's own rules: the user's, removable; Liminal's by their comment liminal:<name>), turned
off while ufw is off (0.6.0). ufw keeps its rules itself (/etc/ufw/user.rules), so nothing here needs saving. The
commands are built here, never run."""
from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field

from liminal_libs.machines.firewall import PREFIX

from .model import Entry, digest, ports_text, spans_of

ROW = re.compile(r"^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT|FWD))?\s+(.+?)\s*$")
ACTIONS = {"ALLOW": "accept", "DENY": "drop", "REJECT": "reject", "LIMIT": "limit"}
SPEC_ACTIONS = {"allow": "accept", "deny": "drop", "reject": "reject", "limit": "limit"}
DIRECTIONS = {"IN": "in", "OUT": "out", "FWD": "fwd"}
APPS = {"openssh": (22, 22)}  # an application profile's port, where the lockout check needs it
DEFAULTS = re.compile(r"(\w+)\s+\((incoming|outgoing|routed)\)")
KEYWORDS = ("on", "proto", "from", "to", "port", "app")  # the words of a rule's full form, as added
OFF = "ufw is off"  # why its rules as added filter nothing (0.6.0)


@dataclass
class UfwState:
    installed: bool = False
    version: str = ""
    active: bool = False
    logging: str = ""
    defaults: dict = field(default_factory=dict)  # incoming | outgoing | routed -> allow | deny | reject | disabled
    rows: list = field(default_factory=list)  # numbered rows: (number, to, action, direction, from, comment, v6)
    added: list = field(default_factory=list)  # (spec, comment)


def parse_status(verbose: str, numbered: str = "", added: str = "", version: str = "") -> UfwState:
    st = UfwState(installed=True)
    m = re.search(r"ufw\s+(\d+(?:\.\d+)+)", version or "")
    st.version = m.group(1) if m else ""
    for line in (verbose or "").splitlines():
        s = line.strip()
        if s.lower().startswith("status:"):
            st.active = s.split(":", 1)[1].strip().lower() == "active"
        elif s.lower().startswith("logging:"):
            st.logging = s.split(":", 1)[1].strip()
        elif s.lower().startswith("default:"):
            st.defaults = {where: what for what, where in DEFAULTS.findall(s)}
    for line in (numbered or "").splitlines():
        m = ROW.match(line.strip())
        if not m:
            continue
        frm, comment = m.group(5), ""
        if " # " in f" {frm} " or frm.startswith("# "):
            frm, _, comment = frm.partition("#")
            frm, comment = frm.strip(), comment.strip()
        to = m.group(2).strip()
        v6 = "(v6)" in to or "(v6)" in frm
        st.rows.append((int(m.group(1)), to, m.group(3), m.group(4) or "IN", frm, comment, v6))
    for line in (added or "").splitlines():
        s = line.strip()
        if not s.startswith("ufw "):
            continue
        m = re.search(r"\s+comment\s+'([^']*)'\s*$", s)
        st.added.append(((s[4:m.start()] if m else s[4:]).strip(), m.group(1) if m else ""))
    return st


def _address(word: str) -> bool:
    try:
        ipaddress.ip_network(word, strict=False)
        return True
    except ValueError:
        return False


def _to_fields(to: str) -> tuple[str, str, tuple, str, str]:
    """A ufw "To" column: (destination, protocol, spans, ports as written, interface)."""
    t = to.replace("(v6)", "").strip()
    interface = ""
    if " on " in f" {t} ":
        t, _, interface = t.partition(" on ")
        t, interface = t.strip(), interface.strip()
    if t.startswith("Anywhere"):
        return "", "", (), "", interface
    words = t.split()
    dest = ""
    if words and _address(words[0]):  # an address or a network first (10.0.0.0/8, 10.0.0.5 22/tcp)
        dest, words = words[0], words[1:]
    spec = " ".join(words)
    if not spec:
        return dest, "", (), "", interface
    ports, _, proto = spec.partition("/")
    spans = spans_of(ports)
    if not spans and spec.lower() in APPS:
        return dest, "tcp", (APPS[spec.lower()],), spec, interface
    if not spans:  # an application profile (Nginx Full): its ports are its own
        return dest, "", (), spec, interface
    return dest, proto.split()[0].lower() if proto else "", spans, ports_text(spans), interface


def row_entry(row, active: bool) -> Entry:
    number, to, action, direction, frm, comment, v6 = row
    dest, proto, spans, ports, interface = _to_fields(to)
    src = frm.replace("(v6)", "").replace("(out)", "").strip()
    if " on " in f" {src} ":
        src, _, iface = src.partition(" on ")
        src, interface = src.strip(), interface or iface.strip()
    owner = "liminal" if comment.startswith(PREFIX + ":") else "ufw"
    text = f"{' '.join(to.split())}  {action} {direction}  {' '.join(frm.split())}" + (f"  # {comment}" if comment else "")
    return Entry(ref=f"ufw|{number}|{digest(to, action, direction, frm, comment)}", kind="ufw", where="ufw",
                 direction=DIRECTIONS.get(direction, "in"), action=ACTIONS.get(action, action.lower()), text=text,
                 protocol=proto, ports=ports, spans=spans, source="" if src.startswith("Anywhere") else src, destination=dest,
                 interface=interface, comment=comment, owner=owner, family="ipv6" if v6 else "ipv4", number=number)


def spec_words(spec: str) -> list[str]:
    """A rule as added, in its words: a quoted profile's name one word ('Nginx Full')."""
    try:
        return shlex.split(spec)
    except ValueError:
        return spec.split()


def _app_of(words: list[str]) -> str:
    """The application profile a rule as added names (0.6.0): after `app` (allow from 10.0.0.0/8 to any app OpenSSH), or
    alone after its action and direction (allow OpenSSH, allow 'Nginx Full'); "" when it names a port or nothing."""
    if "app" in words:
        rest = words[words.index("app") + 1:]
        return " ".join(rest[:next((i for i, w in enumerate(rest) if w in KEYWORDS), len(rest))])
    rest = [w for w in words[1:] if w not in ("in", "out", "log", "log-all")]
    if rest and not any(w in KEYWORDS for w in rest) and not re.match(r"^\d", rest[0]):
        return " ".join(rest)
    return ""


def spec_entry(spec: str, comment: str, off: str = "") -> Entry:
    """One of `ufw show added`'s rules (ufw off): `allow 22/tcp`, `allow in on eth0 from 10.0.0.0/8 to any port 22 proto tcp`,
    `allow 'Nginx Full'` (an application profile: its name kept as its ports, as `ufw status` shows it). `off`: why it
    filters nothing now (ufw is off)."""
    words = spec_words(spec)
    route = bool(words) and words[0] == "route"
    if route:
        words = words[1:]
    action = SPEC_ACTIONS.get(words[0] if words else "", "accept")
    direction = "fwd" if route else "out" if len(words) > 1 and words[1] == "out" else "in"
    proto = words[words.index("proto") + 1] if "proto" in words and words.index("proto") + 1 < len(words) else ""
    src = words[words.index("from") + 1] if "from" in words and words.index("from") + 1 < len(words) else ""
    interface = words[words.index("on") + 1] if "on" in words and words.index("on") + 1 < len(words) else ""
    if "port" in words and words.index("port") + 1 < len(words):
        port_text = words[words.index("port") + 1]
    else:
        simple = next((w for w in words[1:] if re.match(r"^\d", w)), "")
        port_text, _, p = simple.partition("/")
        proto = proto or p
    spans = spans_of(port_text)
    app = "" if spans else _app_of(words)
    if app.lower() in APPS:  # a profile's ports, where the lockout check needs them
        spans, proto = (APPS[app.lower()],), proto or "tcp"
    owner = "liminal" if comment.startswith(PREFIX + ":") else "ufw"
    return Entry(ref=f"ufw-spec|{digest(spec, comment)}", kind="ufw", where="ufw (off)", direction=direction, action=action,
                 text=f"ufw {spec}" + (f" comment '{comment}'" if comment else ""), protocol=proto,
                 ports=app or (ports_text(spans) if spans else ""), spans=spans, source="" if src in ("", "any") else src,
                 interface=interface, comment=comment, owner=owner, off=off)


def entries(st: UfwState) -> list[Entry]:
    """Its rules: as numbered while it is on, as added while it is off (0.6.0: turned off then, filtering nothing)."""
    if st.active and st.rows:
        return [row_entry(r, True) for r in st.rows]
    return [spec_entry(s, c, off="" if st.active else OFF) for s, c in st.added]


# -- the commands that change it ------------------------------------------------------------------------------------
def rule_command(action: str, direction: str, protocol: str, spans, source: str, interface: str, comment: str) -> list[str]:
    """`ufw allow|deny|reject [route] [in|out] [on IF] [proto P] from SRC to any [port P] comment C`."""
    verb = {"allow": "allow", "block": "deny", "reject": "reject"}[action]
    words = ["ufw", "route", verb] if direction == "fwd" else ["ufw", verb]
    if direction in ("in", "out"):
        words.append(direction)
    if interface:  # a routed rule names the interface it comes in on
        words += (["in"] if direction == "fwd" else []) + ["on", interface]
    if protocol in ("tcp", "udp"):
        words += ["proto", protocol]
    words += ["from", source or "any", "to", "any"]
    if spans:
        words += ["port", ",".join(str(a) if a == b else f"{a}:{b}" for a, b in spans)]
    return [*words, "comment", comment]


def default_command(where: str, policy: str) -> list[str]:
    return ["ufw", "default", policy, where]
