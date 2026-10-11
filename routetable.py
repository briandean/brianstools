"""Parse routing-table output and summarise it. Standard library only.

Understands:
  Cisco IOS / IOS-XE   show ip route / show ipv6 route
  Cisco IOS-XR         show route [ipv4|ipv6] [vrf X]
  Cisco NX-OS          show ip route [vrf X] / show ipv6 route
  Juniper Junos        show route [table X]
  Arista EOS           show ip route [vrf X] / show ipv6 route
"""
from __future__ import annotations

from texttable import format_table
import ipaddress
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

RECENT_SECONDS = 300          # "less than 5 minutes old"


# --------------------------------------------------------------------------- data


@dataclass
class NextHop:
    ip: str = ""              # next-hop address ("" for directly connected / interface-only)
    interface: str = ""

    @property
    def key(self) -> Tuple[str, str]:
        return (self.ip, self.interface)


@dataclass
class Route:
    prefix: str
    protocol: str             # normalised: Connected, Local, Static, OSPF, IS-IS, BGP, EIGRP, RIP, ...
    subtype: str = ""         # IA, E2, L2, iBGP, eBGP, EX, ...
    code: str = ""            # as printed (O E2, i L2, B, *[OSPF/10] ...)
    distance: Optional[int] = None
    metric: Optional[int] = None
    age: Optional[int] = None  # seconds
    age_text: str = ""
    next_hops: List[NextHop] = field(default_factory=list)
    table: str = ""           # VRF / routing table, when the output says
    line: int = 0             # 1-based line in the input where the route starts
    flag: str = ""            # why the metric looks unusual ("" = fine)

    @property
    def proto_label(self) -> str:
        return f"{self.protocol} {self.subtype}".strip()


@dataclass
class Parsed:
    routes: List[Route] = field(default_factory=list)
    platform: str = ""
    inactive: int = 0         # Junos: non-active alternatives that were skipped
    tables: List[str] = field(default_factory=list)
    has_ages: bool = False
    warnings: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- helpers

_V4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_V6 = r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}"
_PREFIX = re.compile(rf"(?<![\w.:])({_V4}(?:/\d{{1,2}})?|{_V6}/\d{{1,3}})(?![\w.:/])")
_IFACE = re.compile(r"^(?:[A-Za-z][A-Za-z\-]*\d[\w/.:\-]*|Null0|Loopback\d+|lo\d*|Vlan\d+|Tunnel[\w.]+|"
                    r"[a-z]{2,4}-\d+/\d+/\d+(?:[.:]\d+)*|(?:ae|irb|lo0|em|fxp|reth|st0|gr|ip|lt|ms|vlan)[\d.\-]*\S*)$")
_AGE_HMS = re.compile(r"^(?:(\d+)d\s*)?(\d{1,3}):(\d{2}):(\d{2})$")
_AGE_UNITS = re.compile(r"^(?:(\d+)y)?(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")


def parse_age(text: str) -> Optional[int]:
    """'00:01:23', '1d02h', '2w3d', '3y4w', '1d 02:11:33', '3w2d 04:11:20', '5m3s' -> seconds."""
    t = text.strip().lower()
    if not t or t in ("never", "-"):
        return None
    # Junos style: "3w2d 04:11:20" / "1d 02:11:33"
    m = re.fullmatch(r"((?:\d+[ywd])+)\s+(\d{1,3}):(\d{2}):(\d{2})", t)
    if m:
        head = parse_age(m.group(1)) or 0
        return head + int(m.group(2)) * 3600 + int(m.group(3)) * 60 + int(m.group(4))
    m = _AGE_HMS.fullmatch(t)
    if m:
        return int(m.group(1) or 0) * 86400 + int(m.group(2)) * 3600 + int(m.group(3)) * 60 + int(m.group(4))
    m = _AGE_UNITS.fullmatch(t)
    if m and any(m.groups()):
        y, w, d, h, mi, s = (int(x or 0) for x in m.groups())
        return y * 31536000 + w * 604800 + d * 86400 + h * 3600 + mi * 60 + s
    return None


def format_age(seconds: Optional[int]) -> str:
    if seconds is None:
        return ""
    if seconds < 86400:
        return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"
    d, rem = divmod(seconds, 86400)
    if d >= 7:
        return f"{d // 7}w{d % 7}d"
    return f"{d}d{rem // 3600:02d}h"


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.split("%")[0])
        return True
    except ValueError:
        return False


def _is_iface(text: str) -> bool:
    t = text.strip()
    return bool(t) and not _is_ip(t) and parse_age(t) is None and bool(_IFACE.match(t))


def _norm_prefix(p: str, default_len: Optional[int] = None) -> str:
    p = p.strip()
    if "/" not in p:
        if default_len is not None:
            p = f"{p}/{default_len}"
        else:
            try:                                  # classful guess for old IOS output
                first = int(p.split(".")[0])
                p = f"{p}/{8 if first < 128 else 16 if first < 192 else 24}"
            except ValueError:
                return p
    try:
        return str(ipaddress.ip_network(p, strict=False))
    except ValueError:
        return p


# --------------------------------------------------------------------------- protocol codes

# Cisco IOS / IOS-XE / IOS-XR / Arista EOS route codes (first token, then optional sub-code)
CISCO_CODES = {
    "C": "Connected", "L": "Local", "S": "Static", "R": "RIP", "B": "BGP", "D": "EIGRP", "EX": "EIGRP",
    "O": "OSPF", "i": "IS-IS", "I": "IS-IS", "M": "Mobile", "U": "Static", "o": "ODR", "P": "Static",
    "H": "NHRP", "l": "LISP", "a": "Application", "A": "Access", "K": "Kernel", "V": "VXLAN", "m": "OMP",
    "DH": "DHCP", "NG": "Nexthop-group", "G": "gRIBI", "+": "Replicated", "%": "Override", "t": "Traffic-eng",
    "dl": "LDP", "e": "EGP", "E": "EGP", "*": "Default",
}
SUBCODES = {"IA", "E1", "E2", "N1", "N2", "L1", "L2", "ia", "su", "EX", "I", "E", "*", "(!)", "(a)", "%", "+",
            "DH", "NG", "-", ">", "(>)", "&", "T", "p", "c"}


# IOS IPv6 / combined codes
COMBINED_CODES = {
    "OI": ("OSPF", "IA"), "OE1": ("OSPF", "E1"), "OE2": ("OSPF", "E2"), "ON1": ("OSPF", "N1"),
    "ON2": ("OSPF", "N2"), "I1": ("IS-IS", "L1"), "I2": ("IS-IS", "L2"), "IA": ("IS-IS", "IA"),
    "IS": ("IS-IS", "summary"), "ND": ("ND", ""), "NDp": ("ND", "prefix"), "NDr": ("ND", "redirect"),
    "LC": ("Local", ""), "Rl": ("RPL", ""), "ls": ("LISP", ""),
}


def _known_code(tok: str) -> bool:
    t = tok.replace("*", "")
    return bool(t) and (t in CISCO_CODES or t.upper() in CISCO_CODES or t in COMBINED_CODES)


def _cisco_protocol(code: str) -> Tuple[str, str]:
    """'O E2' -> ('OSPF', 'E2'); 'B I' -> ('BGP', 'iBGP'); 'S*' -> ('Static', ''); 'D EX' -> ('EIGRP', 'EX')."""
    toks = code.replace("*", " ").split()
    toks = [t for t in toks if t not in ("(!)", "(a)", "(>)", ">", "+", "%", "&")] or ["?"]
    head = toks[0]
    if head in COMBINED_CODES:
        return COMBINED_CODES[head]
    if head == "A" and len(toks) > 1 and toks[1] in ("B", "O"):      # EOS: A B / A O aggregates
        return "Aggregate", "BGP" if toks[1] == "B" else "OSPF"
    proto = CISCO_CODES.get(head) or CISCO_CODES.get(head.upper()) or f"Code {head}"
    sub = " ".join(toks[1:])
    if head == "EX":
        sub = "EX"
    if proto == "BGP" and sub in ("I", "E"):
        sub = "iBGP" if sub == "I" else "eBGP"
    if proto == "IS-IS" and sub == "ia":
        sub = "IA"
    return proto, sub


JUNOS_PROTOCOLS = {
    "direct": "Connected", "local": "Local", "static": "Static", "ospf": "OSPF", "ospf3": "OSPF",
    "is-is": "IS-IS", "bgp": "BGP", "rip": "RIP", "ripng": "RIP", "aggregate": "Aggregate", "generate": "Aggregate",
    "ldp": "LDP", "rsvp": "RSVP", "access": "Access", "access-internal": "Access", "kernel": "Kernel",
    "pim": "PIM", "mld": "MLD", "igmp": "IGMP", "evpn": "EVPN", "l2vpn": "L2VPN", "arp": "ARP", "frr": "FRR",
}

NXOS_PROTOCOLS = {
    "direct": "Connected", "local": "Local", "static": "Static", "ospf": "OSPF", "ospfv3": "OSPF", "bgp": "BGP",
    "eigrp": "EIGRP", "isis": "IS-IS", "rip": "RIP", "hsrp": "HSRP", "vrrp": "VRRP", "am": "Adjacency",
    "hmm": "Host mobility", "lisp": "LISP", "discard": "Discard", "broadcast": "Broadcast",
}


# --------------------------------------------------------------------------- platform detection


def detect_platform(text: str) -> str:
    head = text[:20000]
    if "ubest/mbest" in head:
        return "Cisco NX-OS"
    if re.search(r"(?m)^\S+\.(?:inet6?|mpls)\.\d+:\s+\d+ destinations|^inet6?\.\d+:\s+\d+ destinations", head) or \
            re.search(r"\*\[(?:OSPF|Static|Direct|Local|BGP|IS-IS|Aggregate)/\d+\]", head):
        return "Juniper Junos"
    if re.search(r"(?m)^VRF:\s+\S+", head) or "K - kernel" in head or re.search(r"(?m)^\s*B [IE]\s+\d", head):
        return "Arista EOS"
    if re.search(r"\(>\) - Diversion path|Bundle-Ether|\d+/\d+/\d+/\d+|TenGigE|HundredGigE|FortyGigE", head):
        return "Cisco IOS-XR"
    if "Codes:" in head or "Gateway of last resort" in head or re.search(r"(?m)^[A-Za-z*]{1,3}\s+\d", head):
        return "Cisco IOS / IOS-XE"
    return "Unknown"


# --------------------------------------------------------------------------- Cisco-style (IOS, XE, XR, EOS)

_CODE_PREFIX = re.compile(
    rf"^\s*(?P<code>(?:[A-Za-z+%*][A-Za-z0-9+%*]{{0,3}})(?:\s+(?:[A-Za-z]{{1,2}}\d?|\*|\(!\)|\(a\)|\(>\)|\+|%|>))*?)\s+"
    rf"(?P<prefix>{_V4}(?:/\d{{1,2}})?|{_V6}/\d{{1,3}})(?:\s+(?P<rest>.*))?$")
_SUBNETTED = re.compile(rf"^\s*({_V4})(?:/(\d{{1,2}}))?\s+is\s+(?:variably\s+)?subnetted")
_VIA_LINE = re.compile(r"^\s+(?:\[(\d+)/(\d+)\]\s+)?via\s+(.*)$")


def _cisco_tail(route: Route, rest: str, default_ad=None):
    """Read '[110/2] via 10.0.0.5, 00:01:23, Gi0/1' / 'is directly connected, 3w2d, Gi0/0' into route."""
    rest = rest.strip()
    m = re.match(r"\[(\d+)/(\d+)\]\s*", rest)
    if m:
        route.distance = route.distance if route.distance is not None else int(m.group(1))
        route.metric = route.metric if route.metric is not None else int(m.group(2))
        rest = rest[m.end():]
    hop = NextHop()
    if rest.startswith("via "):
        body = rest[4:]
        fields = [f.strip() for f in body.split(",")]
        target = re.sub(r"\s*\(nexthop in vrf [^)]*\)", "", fields[0]).split()[0] if fields and fields[0] else ""
        if _is_ip(target):
            hop.ip = target.split("%")[0]
        elif target:
            hop.interface = target
        others = fields[1:]
    elif "directly connected" in rest:
        others = [f.strip() for f in rest.split(",")[1:]]
    elif rest:
        others = [f.strip() for f in rest.split(",")]
    else:
        return                                  # nothing yet (prefix wrapped onto its own line)
    for f in others:
        a = parse_age(f)
        if a is not None and route.age is None:
            route.age, route.age_text = a, f
        elif not hop.interface and _is_iface(f.split()[0] if f else ""):
            hop.interface = f.split()[0]
    if hop.ip or hop.interface:
        if hop.key not in [h.key for h in route.next_hops]:
            route.next_hops.append(hop)
    elif "directly connected" in rest:
        route.next_hops.append(hop)


def parse_cisco(text: str, out: Parsed):
    table = ""
    default_len: Optional[int] = None
    last: Optional[Route] = None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip():
            continue
        s = line.strip()
        m = re.match(r"(?i)^(?:VRF:|Routing Table:|IP Route Table for VRF)\s*\"?([^\"\s,]+)", s)
        if m:
            table = m.group(1)
            if table not in out.tables:
                out.tables.append(table)
            continue
        if s.startswith(("Codes:", "Gateway of last resort", "%", "+ -", "o -", "a -")) or re.match(
                r"^[A-Za-z0-9*+%()>\-]{1,4}\s+-\s+\w", s) or " - " in s and "via" not in s and not _PREFIX.search(s):
            continue
        sub = _SUBNETTED.match(line)
        if sub:
            default_len = int(sub.group(2)) if sub.group(2) else None
            continue
        via = _VIA_LINE.match(line)
        if via and last is not None:             # ECMP / wrapped next hop for the last route
            if via.group(1) and last.distance is None:
                last.distance, last.metric = int(via.group(1)), int(via.group(2))
            _cisco_tail(last, "via " + via.group(3))
            continue
        wrapped = re.match(r"^\s+\[(\d+)/(\d+)\]\s+via\s+(.*)$", line)
        if wrapped and last is not None:
            _cisco_tail(last, f"[{wrapped.group(1)}/{wrapped.group(2)}] via {wrapped.group(3)}")
            continue
        m = _CODE_PREFIX.match(line)
        if not m:
            if last is not None and re.match(r"^\s+(?:is directly connected|\[\d+/\d+\])", line):
                _cisco_tail(last, s)
            continue
        code = m.group("code").strip()
        first = code.split()[0]
        if not _known_code(first) and not _known_code(first.split("*")[0]):
            continue
        proto, subtype = _cisco_protocol(code)
        prefix = _norm_prefix(m.group("prefix"), default_len if "/" not in m.group("prefix") else None)
        rest = m.group("rest") or ""
        if "subnetted" in rest:
            continue
        route = Route(prefix=prefix, protocol=proto, subtype=subtype, code=code, table=table, line=n)
        _cisco_tail(route, rest)
        # EOS prints the default route under "Gateway of last resort:" too; skip exact repeats
        dup = next((r for r in out.routes[-3:] if r.prefix == prefix and r.table == table and r.code == code), None)
        if dup is not None and [h.key for h in dup.next_hops] == [h.key for h in route.next_hops]:
            last = dup
            continue
        out.routes.append(route)
        last = route


# --------------------------------------------------------------------------- NX-OS

_NX_PREFIX = re.compile(rf"^({_V4}/\d{{1,2}}|{_V6}/\d{{1,3}}),\s+ubest/mbest:\s*(\d+)/(\d+)")
_NX_VIA = re.compile(r"^\s+(\*{0,2})via\s+(.*)$")


def parse_nxos(text: str, out: Parsed):
    table = ""
    cur: Optional[Route] = None
    pending: List[Tuple[str, str]] = []

    def finish():
        nonlocal cur, pending
        if cur is None:
            return
        best = [p for p in pending if p[0].startswith("*")] or pending
        for star, body in best:
            _nx_hop(cur, body)
        if cur.protocol:
            out.routes.append(cur)
        cur, pending = None, []

    for n, raw in enumerate(text.splitlines(), 1):
        m = re.match(r'^IP(?:v6)? Route Table for VRF "([^"]+)"', raw.strip())
        if m:
            finish()
            table = m.group(1)
            if table not in out.tables:
                out.tables.append(table)
            continue
        m = _NX_PREFIX.match(raw)
        if m:
            finish()
            cur = Route(prefix=_norm_prefix(m.group(1)), protocol="", table=table, line=n)
            continue
        v = _NX_VIA.match(raw)
        if v and cur is not None:
            pending.append((v.group(1), v.group(2)))
    finish()


def _nx_hop(route: Route, body: str):
    fields = [f.strip() for f in body.split(",")]
    hop = NextHop()
    target = fields[0].split("%")[0] if fields else ""
    if _is_ip(target):
        hop.ip = target
    elif target:
        hop.interface = target
    proto_seen = False
    extras = []
    for f in fields[1:]:
        m = re.fullmatch(r"\[(\d+)/(\d+)\]", f)
        if m:
            if route.distance is None:
                route.distance, route.metric = int(m.group(1)), int(m.group(2))
            continue
        a = parse_age(f)
        if a is not None and route.age is None:
            route.age, route.age_text = a, f
            continue
        if not proto_seen and parse_age(f) is None and not f.startswith("[") and (route.age is not None or
                                                                               f.split("-")[0].lower() in NXOS_PROTOCOLS):
            if not hop.interface and _is_iface(f) and f.split("-")[0].lower() not in NXOS_PROTOCOLS:
                hop.interface = f
                continue
            base = f.split("-")[0].lower()
            if not route.protocol:
                route.protocol = NXOS_PROTOCOLS.get(base, f.split("-")[0])
                route.code = f
            proto_seen = True
            continue
        if not hop.interface and _is_iface(f):
            hop.interface = f
            continue
        extras.append(f.lower())
    if route.protocol == "BGP" and not route.subtype:
        route.subtype = "iBGP" if "internal" in extras else "eBGP" if "external" in extras else ""
    if route.protocol == "OSPF" and not route.subtype:
        for e in extras:
            if e in ("intra", "inter", "type-1", "type-2", "nssa type-1", "nssa type-2"):
                route.subtype = {"intra": "", "inter": "IA", "type-1": "E1", "type-2": "E2",
                                 "nssa type-1": "N1", "nssa type-2": "N2"}[e]
    if route.protocol == "EIGRP" and "external" in extras:
        route.subtype = "EX"
    if route.protocol == "IS-IS":
        for e in extras:
            if e in ("l1", "l2"):
                route.subtype = e.upper()
    if hop.key not in [h.key for h in route.next_hops]:
        route.next_hops.append(hop)


# --------------------------------------------------------------------------- Junos

_JUN_TABLE = re.compile(r"^(\S+):\s+\d+ destinations,")
_JUN_ROUTE = re.compile(rf"^(?P<prefix>{_V4}/\d{{1,2}}|{_V6}/\d{{1,3}})?\s+(?P<flags>[*+\- ]*)"
                        r"\[(?P<proto>[A-Za-z0-9\-]+)/(?P<pref>\d+)\]\s*(?P<rest>.*)$")
_JUN_HOP = re.compile(r"^\s+(?P<sel>>)?\s*(?:to\s+(?P<ip>\S+)\s+)?via\s+(?P<intf>[^\s,]+)")
_JUN_SPECIAL = re.compile(r"^\s+(?P<sel>>)?\s*(?P<kind>Local|Discard|Reject|Receive|MultiRecv|Multicast)\b"
                          r"(?:\s+via\s+(?P<intf>\S+))?")


def parse_junos(text: str, out: Parsed):
    table = ""
    prefix = ""
    cur: Optional[Route] = None
    hops: List[Tuple[bool, NextHop]] = []

    def finish():
        nonlocal cur, hops
        if cur is not None:
            chosen = [h for sel, h in hops if sel] or [h for _, h in hops]
            for h in chosen:
                if h.key not in [x.key for x in cur.next_hops]:
                    cur.next_hops.append(h)
            out.routes.append(cur)
        cur, hops = None, []

    for n, raw in enumerate(text.splitlines(), 1):
        m = _JUN_TABLE.match(raw)
        if m:
            finish()
            table = m.group(1)
            if table not in out.tables:
                out.tables.append(table)
            continue
        m = _JUN_ROUTE.match(raw)
        if m:
            if cur is not None:
                finish()
            if m.group("prefix"):
                prefix = _norm_prefix(m.group("prefix"))
            if "*" not in m.group("flags"):
                out.inactive += 1                  # an alternative that isn't the active route
                cur = None
                hops = []
                continue
            pname = m.group("proto")
            proto = JUNOS_PROTOCOLS.get(pname.lower(), pname)
            rest = m.group("rest")
            age_m = re.match(r"((?:\d+[ywd])*\s*\d{1,3}:\d{2}:\d{2}|(?:\d+[ywd])+(?:\s+\d{1,3}:\d{2}:\d{2})?)", rest)
            route = Route(prefix=prefix, protocol=proto, code=f"[{pname}/{m.group('pref')}]", table=table, line=n,
                          distance=int(m.group("pref")))
            if age_m:
                route.age_text = age_m.group(1).strip()
                route.age = parse_age(route.age_text)
            mm = re.search(r"\bmetric (\d+)", rest)
            med = re.search(r"\bMED (\d+)", rest)
            if mm:
                route.metric = int(mm.group(1))
            elif med:
                route.metric = int(med.group(1))
            cur = route
            continue
        if cur is None:
            continue
        if re.match(r"^\s+AS path:", raw):
            continue                               # (Junos doesn't say iBGP vs eBGP in plain 'show route')
        h = _JUN_HOP.match(raw)
        if h:
            ip = h.group("ip") or ""
            hops.append((bool(h.group("sel")), NextHop(ip if _is_ip(ip) else "", h.group("intf"))))
            continue
        sp = _JUN_SPECIAL.match(raw)
        if sp:
            hops.append((bool(sp.group("sel")), NextHop("", sp.group("intf") or sp.group("kind"))))
    finish()
    if out.inactive:
        out.warnings.append(f"{out.inactive} inactive alternative route(s) (no '*') were left out of the counts.")


# --------------------------------------------------------------------------- unusual metrics

# Values that mean "maximum / unreachable / deliberately made unattractive" for each protocol.
MAX_METRICS = {
    "OSPF": (65535, "OSPF max-metric (65535+): a router on the path is advertising itself as last resort"),
    "IS-IS": (16777214, "IS-IS max-metric (16777214+): overload / max-metric set on the path"),
    "EIGRP": (4294967295, "EIGRP infinite metric"),
    "RIP": (15, "RIP metric 15–16: at or past the hop limit"),
    "BGP": (4294967295, "BGP max-MED (4294967295)"),
}


def flag_unusual(routes: List[Route]):
    """Mark routes whose metric is unusually high for their protocol (and sub-type) in this table."""
    groups: Dict[Tuple[str, str], List[Route]] = defaultdict(list)
    for r in routes:
        if r.metric is not None and r.protocol not in ("Connected", "Local"):
            groups[(r.protocol, r.subtype if r.protocol in ("OSPF", "IS-IS") else "")].append(r)
    for (proto, sub), rs in groups.items():
        limit = MAX_METRICS.get(proto)
        metrics = sorted(r.metric for r in rs)
        stats = None
        if len(metrics) >= 6:
            q = statistics.quantiles(metrics, n=4, method="inclusive")
            q1, med, q3 = q[0], q[1], q[2]
            iqr = q3 - q1
            cut = q3 + 3 * max(iqr, q3 * 0.5, 1)
            stats = (med, cut, metrics[0], int(q3))
        for r in rs:
            if limit and r.metric >= limit[0]:
                r.flag = limit[1]
            elif stats and r.metric > stats[1] and (stats[0] == 0 or r.metric >= 4 * stats[0]):
                label = f"{proto} {sub}".strip()
                r.flag = (f"Much higher than other {label} routes here (typical {stats[2]:,}–{stats[3]:,}, "
                          f"median {stats[0]:,.0f})")


# --------------------------------------------------------------------------- entry point


def parse(text: str) -> Parsed:
    out = Parsed()
    out.platform = detect_platform(text)
    if out.platform == "Cisco NX-OS":
        parse_nxos(text, out)
    elif out.platform == "Juniper Junos":
        parse_junos(text, out)
    else:
        parse_cisco(text, out)
    out.has_ages = any(r.age is not None for r in out.routes)
    flag_unusual(out.routes)
    if not out.routes and text.strip():
        out.warnings.append("No routes recognised. Paste the output of 'show ip route' / 'show route'.")
    return out


@dataclass
class Summary:
    total: int = 0
    by_protocol: List[Tuple[str, int, str]] = field(default_factory=list)   # (protocol, count, subtype breakdown)
    next_hops: List[Tuple[str, str, int, str]] = field(default_factory=list)  # (ip, intf, routes, protocols)
    interfaces: List[Tuple[str, int, int]] = field(default_factory=list)      # (intf, routes, next hops)
    recent: List[Route] = field(default_factory=list)
    unusual: List[Route] = field(default_factory=list)
    ecmp: int = 0


def summarise(parsed: Parsed, recent_seconds: int = RECENT_SECONDS) -> Summary:
    s = Summary(total=len(parsed.routes))
    proto = Counter(r.protocol for r in parsed.routes)
    subs: Dict[str, Counter] = defaultdict(Counter)
    for r in parsed.routes:
        if r.subtype:
            subs[r.protocol][r.subtype] += 1
    for p, c in proto.most_common():
        detail = ", ".join(f"{k} {v:,}" for k, v in subs[p].most_common())
        s.by_protocol.append((p, c, detail))
    nh_routes: Counter = Counter()
    nh_protos: Dict[Tuple[str, str], Counter] = defaultdict(Counter)
    if_routes: Counter = Counter()
    if_hops: Dict[str, set] = defaultdict(set)
    # a recursive next hop (BGP) with no interface: borrow the interface from a route that knows it
    via_if = {}
    for r in parsed.routes:
        for h in r.next_hops:
            if h.ip and h.interface:
                via_if.setdefault(h.ip, h.interface)
    for r in parsed.routes:
        seen_if = set()
        for h in r.next_hops:
            key = (h.ip, h.interface)
            nh_routes[key] += 1
            nh_protos[key][r.proto_label] += 1
            intf = h.interface or via_if.get(h.ip, "")
            if intf and intf not in seen_if:
                if_routes[intf] += 1
                seen_if.add(intf)
            if intf:
                if_hops[intf].add(h.ip)
        if len(r.next_hops) > 1:
            s.ecmp += 1
    for (ip, intf), c in nh_routes.most_common():
        protos = ", ".join(f"{k} {v:,}" if len(nh_protos[(ip, intf)]) > 1 else k
                           for k, v in nh_protos[(ip, intf)].most_common())
        s.next_hops.append((ip, intf, c, protos))
    for intf, c in if_routes.most_common():
        s.interfaces.append((intf, c, len([x for x in if_hops[intf] if x])))
    s.recent = sorted((r for r in parsed.routes if r.age is not None and r.age < recent_seconds), key=lambda r: r.age)
    s.unusual = [r for r in parsed.routes if r.flag]
    return s


def report(parsed: Parsed, s: Summary) -> str:
    """Plain-text summary for copying into a ticket."""
    out = [f"Route table summary ({parsed.platform})", f"Total routes: {s.total:,}"]
    if parsed.tables and len(parsed.tables) > 1:
        out.append("Tables / VRFs: " + ", ".join(parsed.tables))
    out.append("")
    out.append("Routes by protocol:")
    out.append(format_table(("Protocol", "Routes", "Detail"),
                            [(p, f"{c:,}", d) for p, c, d in s.by_protocol], indent="  "))
    out.append("")
    out.append("Next hops:")
    out.append(format_table(("Next hop", "Interface", "Routes", "Protocols"),
                            [(ip or "(directly connected)", intf or "(recursive)", f"{c:,}", protos)
                             for ip, intf, c, protos in s.next_hops], indent="  "))
    out.append("")
    if parsed.has_ages:
        out.append(f"Routes less than 5 minutes old: {len(s.recent):,}")
        if s.recent:
            out.append(format_table(("Prefix", "Protocol", "Age"),
                                    [(r.prefix, r.proto_label, r.age_text) for r in s.recent], indent="  "))
    else:
        out.append("Routes less than 5 minutes old: n/a (this output doesn't show route ages)")
    out.append("")
    out.append(f"Unusually high metrics: {len(s.unusual):,}")
    if s.unusual:
        out.append(format_table(("Prefix", "Protocol", "AD/Metric", "Why"),
                                [(r.prefix, r.proto_label, f"[{r.distance}/{r.metric}]", r.flag) for r in s.unusual],
                                indent="  "))
    return "\n".join(out)
