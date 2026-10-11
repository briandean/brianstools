"""Helpers for "Send to": pick the useful part of a selection for each tool. Standard library only."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional, Tuple

_V4 = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
_V6 = r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"     # loose; candidates are checked with ipaddress
_MASK = r"255\.(?:\d{1,3}\.){2}\d{1,3}"
_EDGE = r"(?<![\w.:])"
_END = r"(?![\w.])"
SUBNET = re.compile(
    rf"{_EDGE}(?P<cidr>{_V4}/\d{{1,2}}){_END}"
    rf"|{_EDGE}(?P<mask>{_V4}\s+{_MASK}){_END}"
    rf"|{_EDGE}(?P<v6net>(?:{_V6})/\d{{1,3}})(?![\w:])")
IPV4 = re.compile(rf"{_EDGE}{_V4}{_END}")
IPV6 = re.compile(rf"(?<![\w:.])(?:{_V6})(?![\w:])")
HOST = re.compile(r"(?<![\w.@-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,62})\.?(?![\w-])")
TOKEN_CHARS = re.compile(r"[\w.:/%@\-]")

_PREFIX = {"": 0, "k": 1, "m": 2, "g": 3, "t": 4, "p": 5}
_WORDS = {"kilo": "k", "mega": "m", "giga": "g", "tera": "t", "peta": "p"}
_AMOUNT = re.compile(
    r"(?P<num>\d[\d,_]*(?:\.\d+)?(?:[eE][+-]?\d+)?)\s*"
    r"(?P<unit>(?:kilo|mega|giga|tera|peta)?(?:bits?|bytes?)|[kKmMgGtTpP]?i?(?:bps|Bps|bit|bits|byte|bytes|b|B))?"
    r"(?![A-Za-z])")


def preview(text: str, width: int = 32) -> str:
    """Short label for a menu: first line, trimmed, plus how many more lines."""
    lines = [l for l in text.strip().splitlines() if l.strip()]
    if not lines:
        return ""
    first = " ".join(lines[0].split())
    if len(first) > width:
        first = first[:width - 1] + "…"
    return first + (f"  (+{len(lines) - 1} lines)" if len(lines) > 1 else "")


def token_at(line: str, col: int) -> str:
    """The IP / MAC / host / word around column `col` of a line (for right-click without a selection)."""
    if not line:
        return ""
    col = max(0, min(col, len(line) - 1))
    if not TOKEN_CHARS.match(line[col]):
        if col > 0 and TOKEN_CHARS.match(line[col - 1]):
            col -= 1
        else:
            return ""
    a = b = col
    while a > 0 and TOKEN_CHARS.match(line[a - 1]):
        a -= 1
    while b < len(line) and TOKEN_CHARS.match(line[b]):
        b += 1
    tok = line[a:b].strip(".,:;-")
    # "10.0.0.1 255.255.255.0": include the mask that follows an address
    m = re.match(rf"\s+{_MASK}{_END}", line[b:])
    if m and IPV4.fullmatch(tok):
        tok += " " + m.group(0).strip()
    return tok


def first_subnet(text: str) -> str:
    """For IP Calc: a CIDR, 'ip mask', an IPv6 prefix, or a single address; else the first line."""
    import ipaddress
    for m in SUBNET.finditer(text):
        try:
            if m.group("mask"):
                ipaddress.IPv4Network("/".join(m.group("mask").split()), strict=False)
            else:
                ipaddress.ip_network(m.group(0), strict=False)
        except ValueError:
            continue
        return " ".join(m.group(0).split())
    m = IPV4.search(text)
    if m:
        return m.group(0)
    v6 = _first_v6(text)
    return v6.group(0) if v6 else first_line(text)


def _first_v6(text: str):
    import ipaddress
    for m in IPV6.finditer(text):
        try:
            ipaddress.IPv6Address(m.group(0))
            return m
        except ValueError:
            continue
    return None


def first_target(text: str) -> str:
    """For single-target tools (Digr, Traceroute): the first IP address or host name."""
    best = None
    for rx in (IPV4, HOST):
        m = rx.search(text)
        if m and (best is None or m.start() < best.start()):
            best = m
    v6 = _first_v6(text)
    if v6 is not None and (best is None or v6.start() < best.start()):
        best = v6
    if best is not None:
        return best.group(1) if best.re is HOST else best.group(0)
    return first_line(text).split()[0] if first_line(text) else ""


def first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


def data_amount(text: str) -> Tuple[Optional[str], Optional[str]]:
    """'10 Gbps' -> ('10', 'gigabits'); '1.5GB' -> ('1.5', 'gigabytes'); '1500' -> ('1500', None)."""
    for m in _AMOUNT.finditer(text):
        num = m.group("num").replace(",", "").replace("_", "")
        unit = m.group("unit")
        if not unit:
            return num, None
        low = unit.lower()
        prefix = ""
        for word, letter in _WORDS.items():
            if low.startswith(word):
                prefix, unit = letter, unit[len(word):]
                break
        else:
            if unit[0].lower() in "kmgtp" and len(unit) > 1:
                prefix, unit = unit[0].lower(), unit[1:]
            if unit.startswith("i"):
                unit = unit[1:]
        is_bytes = unit in ("B", "Bps") or unit.lower().startswith("byte")
        size = ["", "kilo", "mega", "giga", "tera", "peta"][_PREFIX[prefix]]
        name = f"{size}{'bytes' if is_bytes else 'bits'}"
        return num, name
    return None, None


def first_datetime(text: str) -> Optional[datetime]:
    """The first date/time in the text (wall clock, no zone): plain forms, then any log format."""
    import subnetcalc_core as core
    import logtime
    line = first_line(text)
    dt = core.parse_datetime(line)
    if dt is not None:
        return dt
    try:
        res = logtime.convert_text(text, logtime.Options(epoch=True))
    except Exception:
        return None
    for st in res.stamps:
        if st.source is not None:
            return st.source.replace(tzinfo=None)
    return None


def all_targets(line: str) -> list:
    """Every IPv4 address, IPv6 address and dotted host name in a line, in order."""
    import ipaddress
    found = []
    for rx in (IPV4, IPV6, HOST):
        for m in rx.finditer(line):
            value = m.group(1) if rx is HOST else m.group(0)
            if rx is IPV6:
                try:
                    ipaddress.IPv6Address(value)
                except ValueError:
                    continue
            if not any(a <= m.start() < b for a, b, _ in found):
                found.append((m.start(), m.end(), value))
    return [v for _, _, v in sorted(found)]


def ping_list(text: str, accepts) -> str:
    """Turn a selection into Ping tool input (one target per line, then an optional note).
    Lines that already start with a target (192.0.2.1 Core router, 10.0.0.1-4 Lab) keep their note;
    other lines (log lines, tables) contribute every IP / host name they contain."""
    stripped = text.strip()
    if stripped and not any(c.isspace() for c in stripped) and "," not in stripped:
        return stripped + "\n"
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = re.split(r"[\s,;]+", line, maxsplit=1)
        first, rest = parts[0], (parts[1] if len(parts) > 1 else "")
        if re.search(r"[.:]", first) and accepts(first) and not all_targets(rest):
            out.append(line)
        else:
            out += [t for t in all_targets(line) if t not in out]
    return "\n".join(out) + "\n" if out else ""
