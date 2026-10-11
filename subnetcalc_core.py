"""IP, time, and MAC logic for Brian's Tools (no GUI). Standard library only (Python 3.8+)."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

IPv4Interface = ipaddress.IPv4Interface
IPv6Interface = ipaddress.IPv6Interface
Interface = Union[IPv4Interface, IPv6Interface]
Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# --------------------------------------------------------------------------- parsing


def _v4_prefix_from_mask(mask: str) -> Optional[int]:
    """Prefix length for a dotted netmask, or for a wildcard mask (ACL style)."""
    try:
        value = int(ipaddress.IPv4Address(mask))
    except ValueError:
        return None
    for candidate in (value, value ^ 0xFFFFFFFF):          # netmask, then wildcard
        prefix = bin(candidate).count("1")
        if candidate == (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF:
            return prefix
    return None


def parse(text: str) -> Optional[Interface]:
    """Parse user input into an interface (address + prefix).

    IPv4: 10.1.2.3/24, 10.1.2.3 255.255.255.0, 10.1.2.3/255.255.255.0,
          10.1.2.3 0.0.0.255 (wildcard), 10.1.2.3 (= /32)
    IPv6: 2001:db8::1/64, [2001:db8::1]/64, fe80::1%en0, 2001:db8::1 (= /128)
    """
    t = text.strip()
    if not t:
        return None
    try:
        if ":" in t:
            addr, _, prefix = t.partition("/")
            addr = addr.strip().strip("[]").split("%")[0]
            prefix = prefix.strip()
            if prefix and not prefix.isdigit():
                return None
            return ipaddress.IPv6Interface(f"{addr}/{prefix or 128}")

        parts = t.replace("/", " ").split()
        if len(parts) == 1:
            return ipaddress.IPv4Interface(f"{parts[0]}/32")
        if len(parts) != 2:
            return None
        addr, second = parts
        if second.isdigit():
            prefix = int(second)
        else:
            prefix = _v4_prefix_from_mask(second)
            if prefix is None:
                return None
        if not 0 <= prefix <= 32:
            return None
        return ipaddress.IPv4Interface(f"{addr}/{prefix}")
    except ValueError:
        return None


# --------------------------------------------------------------------------- classification

_V4_TYPES = [
    ("0.0.0.0/8", '"This" network (RFC 1122)'),
    ("10.0.0.0/8", "Private (RFC 1918)"),
    ("172.16.0.0/12", "Private (RFC 1918)"),
    ("192.168.0.0/16", "Private (RFC 1918)"),
    ("100.64.0.0/10", "Shared / CGNAT (RFC 6598)"),
    ("127.0.0.0/8", "Loopback"),
    ("169.254.0.0/16", "Link-local (APIPA)"),
    ("192.0.0.0/24", "IETF protocol assignments"),
    ("192.0.2.0/24", "Documentation (RFC 5737)"),
    ("198.51.100.0/24", "Documentation (RFC 5737)"),
    ("203.0.113.0/24", "Documentation (RFC 5737)"),
    ("198.18.0.0/15", "Benchmarking (RFC 2544)"),
    ("224.0.0.0/4", "Multicast"),
    ("255.255.255.255/32", "Limited broadcast"),
    ("240.0.0.0/4", "Reserved (Class E)"),
]

_V6_TYPES = [
    ("::/128", "Unspecified"),
    ("::1/128", "Loopback"),
    ("::ffff:0:0/96", "IPv4-mapped"),
    ("64:ff9b::/96", "NAT64 (RFC 6052)"),
    ("64:ff9b:1::/48", "NAT64 local-use (RFC 8215)"),
    ("2001:db8::/32", "Documentation"),
    ("3fff::/20", "Documentation"),
    ("2001::/32", "Teredo"),
    ("2002::/16", "6to4"),
    ("fe80::/10", "Link-local"),
    ("fc00::/7", "Unique local (ULA)"),
    ("ff00::/8", "Multicast"),
    ("2000::/3", "Global unicast"),
]
_V4_NETS = [(ipaddress.ip_network(n), label) for n, label in _V4_TYPES]
_V6_NETS = [(ipaddress.ip_network(n), label) for n, label in _V6_TYPES]


def address_type(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> str:
    table = _V4_NETS if ip.version == 4 else _V6_NETS
    for net, label in table:
        if ip in net:
            return label
    return "Public" if ip.version == 4 else "Reserved"


def ipv4_class(ip: ipaddress.IPv4Address) -> str:
    first = int(ip) >> 24
    if first < 128:
        return "A"
    if first < 192:
        return "B"
    if first < 224:
        return "C"
    if first < 240:
        return "D (multicast)"
    return "E (reserved)"


# --------------------------------------------------------------------------- formatting


def grouped(n: int) -> str:
    return f"{n:,}"


def count_text(bits: int) -> str:
    """2**bits, exact when reasonably small, otherwise as a power of two."""
    return grouped(2 ** bits) if bits < 64 else f"2^{bits}"


def binary_v4(ip: ipaddress.IPv4Address) -> str:
    return ".".join(f"{o:08b}" for o in ip.packed)


def reverse_zone(net: Network) -> str:
    """in-addr.arpa / ip6.arpa zone enclosing the network (octet / nibble boundary)."""
    if net.version == 4:
        octets = str(net.network_address).split(".")[: net.prefixlen // 8]
        return ".".join(list(reversed(octets)) + ["in-addr.arpa"])
    nibbles = net.network_address.exploded.replace(":", "")[: net.prefixlen // 4]
    return ".".join(list(reversed(nibbles)) + ["ip6.arpa"])


def usable_hosts_text(net: ipaddress.IPv4Network) -> str:
    if net.prefixlen == 32:
        return "1 (host route)"
    if net.prefixlen == 31:
        return "2 (point-to-point, RFC 3021)"
    return grouped(net.num_addresses - 2)


def host_range(net: Network) -> Tuple[str, str]:
    if net.version == 4 and net.prefixlen < 31:
        return str(net.network_address + 1), str(net.broadcast_address - 1)
    return str(net.network_address), str(net.broadcast_address)


# --------------------------------------------------------------------------- details


def details(iface: Interface, compact: bool = False) -> List[Tuple[str, str]]:
    """Label/value rows describing the subnet."""
    net = iface.network
    ip = iface.ip
    rows: List[Tuple[str, str]] = []
    if ip != net.network_address:
        rows.append(("Address", str(ip)))
    if ip.is_multicast:
        name = multicast_name(ip)
        if name:
            rows.append(("Multicast group", name))
        rows.append(("Multicast scope", multicast_scope(ip)))
        rows.append(("Multicast MAC", format_mac(multicast_mac(ip), "dotted") + "  ·  " +
                     format_mac(multicast_mac(ip), "colon")))
    if net.version == 4:
        first, last = host_range(net)
        rows += [
            ("Network", str(net.network_address)),
            ("Netmask", f"{net.netmask}  (/{net.prefixlen})"),
            ("Wildcard", str(net.hostmask)),
        ]
        if net.prefixlen < 31:
            rows.append(("Broadcast", str(net.broadcast_address)))
        rows += [
            ("Host range", f"{first} – {last}"),
            ("Usable hosts", usable_hosts_text(net)),
        ]
        if not compact:
            rows += [
                ("Total addresses", grouped(net.num_addresses)),
                ("Class", ipv4_class(ip)),
                ("Reverse zone", reverse_zone(net)),
                ("Binary address", binary_v4(ip)),
                ("Binary mask", binary_v4(net.netmask)),
                ("Hex", f"0x{int(ip):08X}"),
            ]
    else:
        rows += [
            ("Network", str(net)),
            ("First", str(net.network_address)),
            ("Last", str(net.broadcast_address)),
            ("Addresses", count_text(128 - net.prefixlen)),
        ]
        if net.prefixlen <= 64:
            rows.append(("/64 networks", count_text(64 - net.prefixlen)))
        if not compact:
            rows += [
                ("Expanded", ip.exploded),
                ("Expanded network", net.network_address.exploded),
                ("Reverse zone", reverse_zone(net)),
            ]
    return rows


def customer_details(iface: Interface) -> str:
    """Plain-text block for a customer handoff. The first usable address is taken as the gateway,
    and the usable range is what's left for the customer."""
    net = iface.network
    total = net.num_addresses
    rows: List[Tuple[str, str]] = [("Network", str(net))]

    def count(n: int) -> str:
        return f"  ({grouped(n)} address{'es' if n != 1 else ''})"

    if net.version == 4:
        if net.prefixlen == 32:
            rows += [("Gateway", "n/a (single address)"),
                     ("Usable range", f"{net.network_address}{count(1)}")]
        elif net.prefixlen == 31:                      # RFC 3021 point-to-point
            rows += [("Gateway", str(net.network_address)),
                     ("Usable range", f"{net.broadcast_address}{count(1)}")]
        else:
            gw = net.network_address + 1
            first, last = net.network_address + 2, net.broadcast_address - 1
            usable = total - 3
            rows += [("Gateway", str(gw)),
                     ("Usable range", (f"{first} - {last}" if usable > 1 else str(first)) + count(usable))]
        rows.append(("Subnet mask", str(net.netmask)))
        rows.append(("Broadcast", str(net.broadcast_address) if net.prefixlen < 31 else "n/a"))
    else:
        if net.prefixlen == 128:
            rows += [("Gateway", "n/a (single address)"),
                     ("Usable range", f"{net.network_address}{count(1)}")]
        elif net.prefixlen == 127:                     # RFC 6164 point-to-point
            rows += [("Gateway", str(net.network_address)),
                     ("Usable range", f"{net.broadcast_address}{count(1)}")]
        else:
            gw = net.network_address + 1
            first, last = net.network_address + 2, net.broadcast_address
            usable = int(last) - int(first) + 1
            rows += [("Gateway", str(gw)),
                     ("Usable range", (f"{first} - {last}" if usable > 1 else str(first))
                      + (count(usable) if usable < 2 ** 20 else f"  (about {count_text(128 - net.prefixlen)} addresses)"))]
        rows.append(("Prefix length", f"/{net.prefixlen}"))
        rows.append(("Broadcast", "n/a (IPv6 has no broadcast)"))
    width = max(len(k) for k, _ in rows) + 2
    return "\n".join(f"{k + ':':<{width}}{v}" for k, v in rows)


def copy_formats(iface: Interface) -> List[Tuple[str, str]]:
    """Ready-to-paste config snippets."""
    net = iface.network
    if net.version == 6:
        return [
            ("CIDR", str(net)),
            ("Address/len", f"{iface.ip}/{net.prefixlen}"),
            ("IOS / IOS-XR", f"ipv6 address {iface.ip}/{net.prefixlen}"),
            ("Range", f"{net.network_address} - {net.broadcast_address}"),
        ]
    return [
        ("CIDR", str(net)),
        ("Address/len", f"{iface.ip}/{net.prefixlen}"),
        ("IOS", f"ip address {iface.ip} {net.netmask}"),
        ("ACL", f"{net.network_address} {net.hostmask}"),
        ("OSPF", f"network {net.network_address} {net.hostmask} area 0"),
        ("Range", f"{net.network_address} - {net.broadcast_address}"),
    ]


# --------------------------------------------------------------------------- split


def split(net: Network, new_prefix: int, limit: int = 4096) -> List[Network]:
    """First `limit` subnets of length `new_prefix` (empty if new_prefix is shorter)."""
    if not net.prefixlen <= new_prefix <= net.max_prefixlen:
        return []
    out = []
    for sub in net.subnets(new_prefix=new_prefix):
        out.append(sub)
        if len(out) >= limit:
            break
    return out


def subnet_count(net: Network, new_prefix: int) -> int:
    if not net.prefixlen <= new_prefix <= net.max_prefixlen:
        return 0
    return 2 ** (new_prefix - net.prefixlen)


# --------------------------------------------------------------------------- summarize


@dataclass
class SummaryResult:
    blocks: List[ipaddress.IPv4Network] = field(default_factory=list)
    invalid: List[str] = field(default_factory=list)
    aggregated: List[ipaddress.IPv4Network] = field(default_factory=list)
    supernet: Optional[ipaddress.IPv4Network] = None
    total_addresses: int = 0


def summarize(text: str) -> SummaryResult:
    """One entry per line (commas/semicolons also separate). '#' starts a comment.

    Entries: CIDR, 'ip mask', bare IP, or a range 'a - b'.
    """
    r = SummaryResult()
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        for entry in line.replace(";", ",").split(","):
            entry = entry.strip()
            if not entry:
                continue
            if "-" in entry:
                ends = [e.strip() for e in entry.split("-")]
                try:
                    a, b = (ipaddress.IPv4Address(e) for e in ends)
                    if a > b:
                        raise ValueError
                    r.blocks += list(ipaddress.summarize_address_range(a, b))
                except ValueError:
                    r.invalid.append(entry)
                continue
            iface = parse(entry)
            if iface is None or iface.version != 4:
                r.invalid.append(entry)
            else:
                r.blocks.append(iface.network)
    r.aggregated = list(ipaddress.collapse_addresses(r.blocks))
    r.total_addresses = sum(n.num_addresses for n in r.aggregated)
    if r.blocks:
        lo = min(int(n.network_address) for n in r.blocks)
        hi = max(int(n.broadcast_address) for n in r.blocks)
        prefix = 32 - (lo ^ hi).bit_length()
        r.supernet = ipaddress.IPv4Network((lo, prefix), strict=False)
    return r


# --------------------------------------------------------------------------- bit / byte conversion

from decimal import Decimal, InvalidOperation, localcontext

# (name, is_byte, power of "kilo")
DATA_UNITS = [
    ("bits", False, 0), ("bytes", True, 0),
    ("kilobits", False, 1), ("kilobytes", True, 1),
    ("megabits", False, 2), ("megabytes", True, 2),
    ("gigabits", False, 3), ("gigabytes", True, 3),
    ("terabits", False, 4), ("terabytes", True, 4),
    ("petabits", False, 5), ("petabytes", True, 5),
]
UNIT_NAMES = [u[0] for u in DATA_UNITS]
NOTATIONS = {
    '"kilo" is 1024': 1024,
    '"kilo" is 1000': 1000,
}


def parse_amount(text: str) -> Optional[Decimal]:
    """Accepts 1234, 1,234, 1_234, 1.5, 1e9. Rejects negatives and junk."""
    cleaned = text.strip().replace(",", "").replace("_", "").replace(" ", "")
    if not cleaned:
        return None
    try:
        value = Decimal(cleaned)
    except InvalidOperation:
        return None
    if not value.is_finite() or value < 0:
        return None
    return value


def convert_data(amount: Decimal, unit: str, base: int = 1024) -> List[Tuple[str, Decimal]]:
    """Convert `amount` of `unit` into every unit in DATA_UNITS."""
    lookup = {name: (is_byte, power) for name, is_byte, power in DATA_UNITS}
    is_byte, power = lookup[unit]
    with localcontext() as ctx:
        ctx.prec = 60
        bits = amount * (8 if is_byte else 1) * (Decimal(base) ** power)
        return [(name, bits / ((8 if b else 1) * (Decimal(base) ** p))) for name, b, p in DATA_UNITS]


def format_amount(value: Decimal, sig_digits: int = 17) -> str:
    """Plain decimal (never scientific), rounded to `sig_digits` significant digits."""
    if value == 0:
        return "0"
    with localcontext() as ctx:
        ctx.prec = sig_digits
        value = +value          # round to context precision
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def notation_note(unit: str, base: int) -> str:
    word = "kilobyte" if unit.endswith("bytes") else "kilobit"
    plain = "byte" if unit.endswith("bytes") else "bit"
    kind = "informal notation" if base == 1024 else "SI notation"
    return f"({kind}: {word} = {base} {plain}s)"


# --------------------------------------------------------------------------- time zones

import os as _os
import time as _time
from datetime import datetime, timedelta, timezone

try:
    import zoneinfo as _zoneinfo          # Python 3.9+
except ImportError:                       # pragma: no cover
    _zoneinfo = None

DEFAULT_TARGET_ZONES = [
    "UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
    "Europe/London", "Europe/Berlin", "Asia/Kolkata", "Asia/Tokyo", "Australia/Sydney",
]

# Windows reports names like "Eastern Standard Time"; map the common ones to IANA.
_WINDOWS_TZ = {
    "Eastern Standard Time": "America/New_York", "Eastern Daylight Time": "America/New_York",
    "Central Standard Time": "America/Chicago", "Central Daylight Time": "America/Chicago",
    "Mountain Standard Time": "America/Denver", "Mountain Daylight Time": "America/Denver",
    "US Mountain Standard Time": "America/Phoenix",
    "Pacific Standard Time": "America/Los_Angeles", "Pacific Daylight Time": "America/Los_Angeles",
    "Alaskan Standard Time": "America/Anchorage", "Hawaiian Standard Time": "Pacific/Honolulu",
    "Atlantic Standard Time": "America/Halifax", "GMT Standard Time": "Europe/London",
    "W. Europe Standard Time": "Europe/Berlin", "Romance Standard Time": "Europe/Paris",
    "Central Europe Standard Time": "Europe/Budapest", "India Standard Time": "Asia/Kolkata",
    "China Standard Time": "Asia/Shanghai", "Tokyo Standard Time": "Asia/Tokyo",
    "AUS Eastern Standard Time": "Australia/Sydney", "UTC": "UTC", "Coordinated Universal Time": "UTC",
}


def timezone_support() -> Optional[str]:
    """None if time zones work, otherwise a message explaining how to fix it."""
    if _zoneinfo is None:
        return "Time zones need Python 3.9 or newer."
    if not _zoneinfo.available_timezones():
        return "No time zone database found. Install it with:  pip install tzdata"
    return None


def all_timezones() -> List[str]:
    """Every IANA zone, minus legacy aliases that just clutter the list."""
    if _zoneinfo is None:
        return []
    skip_prefixes = ("posix/", "right/", "SystemV/", "Etc/GMT")
    names = {
        z for z in _zoneinfo.available_timezones()
        if not z.startswith(skip_prefixes) and z not in ("localtime", "Factory", "posixrules")
        and ("/" in z or z == "UTC")
    }
    return sorted(names)


def get_zone(name: str):
    return _zoneinfo.ZoneInfo(name)


def local_timezone_name() -> str:
    """Best-effort IANA name for this computer's time zone (falls back to UTC)."""
    zones = set(all_timezones())
    tz_env = _os.environ.get("TZ", "").lstrip(":")
    if tz_env in zones:
        return tz_env
    try:
        target = _os.path.realpath("/etc/localtime")
        if "zoneinfo/" in target:
            name = target.split("zoneinfo/", 1)[1]
            if name in zones or name == "UTC":
                return name
            if name.startswith("Etc/") and name[4:] in ("UTC", "UCT", "Zulu", "Universal"):
                return "UTC"
    except OSError:
        pass
    try:
        with open("/etc/timezone", encoding="utf-8") as fh:
            name = fh.read().strip()
            if name in zones:
                return name
    except OSError:
        pass
    for name in _time.tzname:
        if name in _WINDOWS_TZ:
            return _WINDOWS_TZ[name]
    return "UTC"


_DT_FORMATS = [
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %I:%M:%S %p", "%Y-%m-%d %I:%M %p", "%Y-%m-%d %I %p",
    "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M %p", "%m/%d/%Y %I %p",
    "%m/%d/%y %H:%M", "%m/%d/%y %I:%M %p",
    "%Y-%m-%d", "%m/%d/%Y",
]


def parse_datetime(text: str) -> Optional[datetime]:
    """Parse a wall-clock date/time (no zone). Examples:
    2026-10-10 14:30, 2026-10-10T14:30:00, 10/10/2026 2:30 PM, 2026-10-10 (midnight)."""
    t = " ".join(text.strip().split()).upper().replace("A.M.", "AM").replace("P.M.", "PM")
    t = t.replace("AM", " AM").replace("PM", " PM").replace("  ", " ")
    for fmt in _DT_FORMATS:
        try:
            return datetime.strptime(t, fmt)
        except ValueError:
            continue
    return None


def format_offset(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    sign = "+" if minutes >= 0 else "−"
    minutes = abs(minutes)
    return f"UTC{sign}{minutes // 60:02d}:{minutes % 60:02d}"


@dataclass
class ZoneTime:
    zone: str
    local: datetime          # aware datetime in `zone`
    offset: timedelta
    abbrev: str
    day_shift: int           # calendar days relative to the source wall clock


def localize(naive: datetime, zone_name: str) -> Tuple[datetime, Optional[str]]:
    """Attach a zone to a wall-clock time, flagging DST gaps and overlaps."""
    tz = get_zone(zone_name)
    first = naive.replace(tzinfo=tz, fold=0)
    second = naive.replace(tzinfo=tz, fold=1)
    roundtrip = first.astimezone(timezone.utc).astimezone(tz).replace(tzinfo=None)
    if roundtrip != naive:
        return first, (f"{naive:%H:%M} doesn't exist in {zone_name} that day (clocks spring forward); "
                       f"treated as {roundtrip:%H:%M}.")
    if first.utcoffset() != second.utcoffset():
        return first, (f"{naive:%H:%M} happens twice in {zone_name} that day (clocks fall back); "
                       f"using the first one ({first.tzname()}).")
    return first, None


def convert_time(naive: datetime, source: str, targets: List[str]) -> Tuple[datetime, Optional[str], List[ZoneTime]]:
    """Convert a wall-clock time in `source` to each target zone, sorted by UTC offset."""
    src, note = localize(naive, source)
    rows = []
    for name in targets:
        local = src.astimezone(get_zone(name))
        rows.append(ZoneTime(
            zone=name, local=local, offset=local.utcoffset() or timedelta(0),
            abbrev=local.tzname() or "",
            day_shift=(local.date() - src.date()).days,
        ))
    rows.sort(key=lambda r: (r.offset, r.zone))
    return src, note, rows


def describe(dt: datetime) -> str:
    """'Sat 2026-10-10 14:30 EDT (UTC−04:00)'"""
    return f"{dt:%a %Y-%m-%d %H:%M} {dt.tzname()} ({format_offset(dt.utcoffset() or timedelta(0))})"


# --------------------------------------------------------------------------- date math (add / subtract)

import calendar as _calendar

WEEKDAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
ALL_WEEKDAYS = frozenset(range(7))


def add_months(dt: datetime, months: int) -> Tuple[datetime, bool]:
    """Calendar-month arithmetic. Returns (result, clamped) where clamped means the
    day didn't exist in the target month (e.g. Jan 31 + 1 month -> Feb 28)."""
    total = dt.year * 12 + (dt.month - 1) + months
    year, month = divmod(total, 12)
    month += 1
    if not 1 <= year <= 9999:
        raise OverflowError("date out of range")
    last = _calendar.monthrange(year, month)[1]
    day = min(dt.day, last)
    return dt.replace(year=year, month=month, day=day), day != dt.day


def add_days_on_weekdays(dt: datetime, days: int, allowed=ALL_WEEKDAYS) -> datetime:
    """Move `days` days forward (or back if negative), counting only `allowed`
    weekdays (0=Mon … 6=Sun). With all weekdays allowed this is plain day math."""
    allowed = frozenset(allowed)
    if not allowed:
        raise ValueError("pick at least one weekday")
    if allowed == ALL_WEEKDAYS or days == 0:
        return dt + timedelta(days=days)
    step = 1 if days > 0 else -1
    remaining = abs(days)
    per_week = len(allowed)
    # Whole weeks first: any 7 consecutive days contain each weekday exactly once.
    weeks = (remaining - 1) // per_week
    dt += timedelta(days=7 * weeks * step)
    remaining -= weeks * per_week
    while remaining:
        dt += timedelta(days=step)
        if dt.weekday() in allowed:
            remaining -= 1
    return dt


@dataclass
class DateMathResult:
    result: datetime
    notes: List[str] = field(default_factory=list)


def date_math(start: datetime, sign: int = 1, years: int = 0, months: int = 0, weeks: int = 0,
              days: int = 0, hours: int = 0, minutes: int = 0, seconds: int = 0,
              weekdays=ALL_WEEKDAYS) -> DateMathResult:
    """Add (sign=+1) or subtract (sign=-1). Order: years/months, then weeks/days
    (optionally counting only certain weekdays), then hours/minutes/seconds.
    Wall-clock arithmetic: no time zone or DST shifts are applied."""
    notes = []
    dt = start
    month_total = sign * (years * 12 + months)
    if month_total:
        dt, clamped = add_months(dt, month_total)
        if clamped:
            notes.append(f"Day {start.day} doesn't exist in {dt:%B %Y}, so the last day of that month was used.")
    day_total = sign * (weeks * 7 + days)
    if day_total:
        if frozenset(weekdays) != ALL_WEEKDAYS:
            names = ", ".join(WEEKDAY_NAMES[d] for d in sorted(weekdays))
            notes.append(f"Weeks and days counted only on: {names}.")
        dt = add_days_on_weekdays(dt, day_total, weekdays)
    dt += sign * timedelta(hours=hours, minutes=minutes, seconds=seconds)
    return DateMathResult(dt, notes)


def describe_span(start: datetime, end: datetime) -> str:
    """'12 days, 3 hours, 0 minutes, 0 seconds later' style summary."""
    delta = end - start
    later = delta >= timedelta(0)
    delta = abs(delta)
    d, rem = delta.days, delta.seconds
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = [f"{d:,} day{'s' if d != 1 else ''}"]
    if h or m or s:
        parts.append(f"{h} hour{'s' if h != 1 else ''}")
        parts.append(f"{m} minute{'s' if m != 1 else ''}")
        if s:
            parts.append(f"{s} second{'s' if s != 1 else ''}")
    return ", ".join(parts) + (" later" if later else " earlier")


# --------------------------------------------------------------------------- epoch


def epoch_seconds(naive: datetime, zone_name: Optional[str] = None) -> int:
    """Unix epoch seconds for a wall-clock time in `zone_name` (None = UTC)."""
    if zone_name is None or zone_name == "UTC":
        return int(naive.replace(tzinfo=timezone.utc).timestamp())
    try:
        aware, _ = localize(naive, zone_name)
    except Exception:            # no tz database: fall back to the OS's idea of local time
        return int(naive.timestamp())
    return int(aware.timestamp())


# --------------------------------------------------------------------------- MAC addresses

import re as _re
from collections import Counter as _Counter

_HEX = "[0-9A-Fa-f]"
MAC_REGEX = _re.compile(
    rf"(?<![0-9A-Fa-f.:-])(?:"
    rf"{_HEX}{{4}}\.{_HEX}{{4}}\.{_HEX}{{4}}"            # aabb.ccdd.eeff  (Cisco)
    rf"|(?:{_HEX}{{1,2}}[:-]){{5}}{_HEX}{{1,2}}"          # aa:bb:cc:dd:ee:ff / aa-bb-…  (1-digit groups ok)
    rf"|{_HEX}{{12}}"                                    # aabbccddeeff
    rf")(?![0-9A-Fa-f]|[.:-][0-9A-Fa-f])"
)

MAC_STYLES = {
    "dotted": "3-dot  (aabb.ccdd.eeff)",
    "dash": "Dash  (aa-bb-cc-dd-ee-ff)",
    "colon": "Colon  (aa:bb:cc:dd:ee:ff)",
}


def normalize_mac(text: str) -> str:
    """Any accepted MAC spelling -> 12 lowercase hex digits."""
    if "." in text:
        return text.replace(".", "").lower()
    if ":" in text or "-" in text:
        return "".join(part.zfill(2) for part in _re.split("[:-]", text)).lower()
    return text.lower()


def format_mac(hex12: str, style: str = "colon", upper: bool = False) -> str:
    h = hex12.upper() if upper else hex12.lower()
    if style == "dotted":
        return f"{h[0:4]}.{h[4:8]}.{h[8:12]}"
    sep = "-" if style == "dash" else ":"
    return sep.join(h[i:i + 2] for i in range(0, 12, 2))


@dataclass
class MacResult:
    output_lines: List[str] = field(default_factory=list)
    macs: List[str] = field(default_factory=list)            # normalized, in order found
    line_count: int = 0                                        # non-empty input lines
    lines_without_mac: List[Tuple[int, str]] = field(default_factory=list)
    duplicates: List[Tuple[str, int]] = field(default_factory=list)   # (normalized, count)

    @property
    def unique_count(self) -> int:
        return len(set(self.macs))


def convert_macs(text: str, style: str = "colon", upper: bool = False,
                 in_place: bool = False, dedupe: bool = False) -> MacResult:
    """Find every MAC in `text` (any surrounding text is ignored) and reformat it.

    in_place=False: output is one MAC per line.
    in_place=True:  each line is kept and its MACs are rewritten where they sit.
    dedupe:         drop repeats (MAC-only mode) — first occurrence wins.
    """
    r = MacResult()
    seen = set()
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            if in_place:
                r.output_lines.append(line)
            continue
        r.line_count += 1
        found = list(MAC_REGEX.finditer(line))
        if not found:
            r.lines_without_mac.append((n, line.strip()))
            if in_place:
                r.output_lines.append(line)
            continue
        for m in found:
            r.macs.append(normalize_mac(m.group(0)))
        if in_place:
            r.output_lines.append(MAC_REGEX.sub(
                lambda m: format_mac(normalize_mac(m.group(0)), style, upper), line))
        else:
            for m in found:
                norm = normalize_mac(m.group(0))
                if dedupe and norm in seen:
                    continue
                seen.add(norm)
                r.output_lines.append(format_mac(norm, style, upper))
    counts = _Counter(r.macs)
    r.duplicates = [(mac, c) for mac, c in counts.items() if c > 1]
    return r


# --------------------------------------------------------------------------- MAC vendor lookup (OUI)

OUI_DOWNLOAD_URL = "https://standards-oui.ieee.org/oui/oui.txt"
_OUI_HEX_LINE = _re.compile(r"^\s*([0-9A-Fa-f]{2})[-:]([0-9A-Fa-f]{2})[-:]([0-9A-Fa-f]{2})\s+\(hex\)\s*(.*)$")
_OUI_B16_LINE = _re.compile(r"^\s*([0-9A-Fa-f]{6})(?:-([0-9A-Fa-f]{6}))?\s+\(base 16\)\s*(.*)$")
_MANUF_LINE = _re.compile(r"^([0-9A-Fa-f]{2}(?:[:.-][0-9A-Fa-f]{2}){2,5})(?:/(\d+))?\s+(\S.*)$")


@dataclass
class OuiEntry:
    org: str
    address: List[str] = field(default_factory=list)
    bits: int = 24                 # 24 = MA-L, 28 = MA-M, 36 = MA-S / IAB

    @property
    def country(self) -> str:
        last = self.address[-1].strip() if self.address else ""
        return last if len(last) == 2 and last.isalpha() and last.isupper() else ""

    @property
    def is_registry_block(self) -> bool:
        """True for IEEE RA parent blocks that are subdivided in mam.txt / oui36.txt."""
        return self.org.lower().startswith("ieee registration authority")

    @property
    def block(self) -> str:
        return {24: "MA-L", 28: "MA-M", 36: "MA-S"}.get(self.bits, f"/{self.bits}")


class OuiDatabase:
    """Vendor lookup from IEEE registry text files (oui.txt, mam.txt, oui36.txt, iab.txt)
    or a Wireshark 'manuf' file. Longest-prefix match: /36 beats /28 beats /24."""

    def __init__(self):
        self.tables: dict = {}          # bits -> {prefix_int: OuiEntry}
        self.files: List[str] = []

    def __len__(self):
        return sum(len(t) for t in self.tables.values())

    def _add(self, bits: int, prefix: int, entry: OuiEntry):
        entry.bits = bits
        self.tables.setdefault(bits, {})[prefix] = entry

    def load_file(self, path) -> int:
        """Load one file; returns the number of entries added."""
        with open(path, encoding="utf-8", errors="replace") as fh:
            added = self.load_text(fh.read())
        self.files.append(str(path))
        return added

    def load_text(self, text: str) -> int:
        before = len(self)
        lines = text.splitlines()
        i, n = 0, len(lines)
        ieee = any("(hex)" in ln for ln in lines[:200])
        while i < n:
            line = lines[i]
            if ieee:
                m = _OUI_HEX_LINE.match(line)
                if not m:
                    i += 1
                    continue
                oui24 = int("".join(m.group(1, 2, 3)), 16)
                org = m.group(4).strip()
                bits, prefix = 24, oui24
                address = []
                j = i + 1
                if j < n:
                    b = _OUI_B16_LINE.match(lines[j])
                    if b:
                        org = b.group(3).strip() or org
                        if b.group(2):                     # range = smaller block (MA-M / MA-S / IAB)
                            lo, hi = int(b.group(1), 16), int(b.group(2), 16)
                            size = hi - lo + 1
                            host_bits = size.bit_length() - 1
                            bits = 48 - host_bits
                            prefix = ((oui24 << 24) | lo) >> host_bits
                        j += 1
                while j < n and lines[j].strip() and "(hex)" not in lines[j]:
                    address.append(" ".join(lines[j].split()))
                    j += 1
                self._add(bits, prefix, OuiEntry(org, address))
                i = j
            else:
                m = _MANUF_LINE.match(line.strip())
                if m and not line.lstrip().startswith("#"):
                    digits = _re.sub(r"[:.-]", "", m.group(1))
                    bits = int(m.group(2)) if m.group(2) else len(digits) * 4
                    value = int(digits, 16) << (48 - len(digits) * 4)
                    fields = m.group(3).split("\t")
                    org = (fields[1] if len(fields) > 1 else fields[0]).strip()
                    self._add(bits, value >> (48 - bits), OuiEntry(org))
                i += 1
        return len(self) - before

    def lookup(self, hex12: str) -> Optional[OuiEntry]:
        value = int(hex12, 16)
        for bits in sorted(self.tables, reverse=True):
            entry = self.tables[bits].get(value >> (48 - bits))
            if entry:
                return entry
        return None


def find_oui_files(oui_path) -> list:
    """oui.txt plus any sibling IEEE files for smaller blocks (mam.txt, oui36.txt, iab.txt)."""
    from pathlib import Path as _P
    p = _P(oui_path)
    extra = [p.with_name(name) for name in ("mam.txt", "oui36.txt", "iab.txt")]
    return [p] + [e for e in extra if e.exists() and e != p]


# --------------------------------------------------------------------------- special MAC addresses

# Well-known multicast groups (IANA registries + common vendor protocols).
IPV4_MCAST_NAMES = {
    # 224.0.0.0/24 – Local Network Control Block (link-local, TTL 1, never routed)
    "224.0.0.1": "All systems on this subnet (IGMP general queries)",
    "224.0.0.2": "All routers on this subnet (HSRPv1, LDP hello, IGMPv2 leave)",
    "224.0.0.4": "DVMRP routers",
    "224.0.0.5": "OSPF all SPF routers (AllSPFRouters)",
    "224.0.0.6": "OSPF designated routers (AllDRouters – DR/BDR)",
    "224.0.0.9": "RIPv2 routers",
    "224.0.0.10": "EIGRP routers",
    "224.0.0.12": "DHCP server / relay agent",
    "224.0.0.13": "PIMv2 all PIM routers",
    "224.0.0.14": "RSVP encapsulation",
    "224.0.0.15": "All CBT routers",
    "224.0.0.16": "Designated SBM",
    "224.0.0.17": "All SBMs",
    "224.0.0.18": "VRRP",
    "224.0.0.19": "IS-IS over IP",
    "224.0.0.20": "IS-IS over IP",
    "224.0.0.21": "IS-IS over IP",
    "224.0.0.22": "IGMPv3 membership reports",
    "224.0.0.102": "HSRPv2 / GLBP",
    "224.0.0.106": "All snoopers (Multicast Router Discovery)",
    "224.0.0.107": "PTP peer delay (IEEE 1588)",
    "224.0.0.251": "mDNS (multicast DNS / Bonjour)",
    "224.0.0.252": "LLMNR",
    "224.0.0.253": "Teredo",
    # 224.0.1.0/24 – Internetwork Control Block (routable)
    "224.0.1.1": "NTP",
    "224.0.1.39": "Cisco Auto-RP announce (RP-Announce)",
    "224.0.1.40": "Cisco Auto-RP discovery (RP-Discovery)",
    "224.0.1.41": "H.323 gatekeeper discovery",
    "224.0.1.129": "PTP primary (IEEE 1588)",
    "224.0.1.130": "PTP alternate 1", "224.0.1.131": "PTP alternate 2", "224.0.1.132": "PTP alternate 3",
    # administratively scoped / site-local
    "239.255.255.250": "SSDP / UPnP",
    "239.255.255.253": "SLP (Service Location Protocol)",
}
IPV6_MCAST_NAMES = {
    "ff01::1": "All nodes (interface-local)", "ff01::2": "All routers (interface-local)",
    "ff02::1": "All nodes (link-local)",
    "ff02::2": "All routers (link-local) – RA/RS, LDP",
    "ff02::4": "DVMRP routers",
    "ff02::5": "OSPFv3 all SPF routers (AllSPFRouters)",
    "ff02::6": "OSPFv3 designated routers (AllDRouters – DR/BDR)",
    "ff02::9": "RIPng routers",
    "ff02::a": "EIGRP routers",
    "ff02::c": "SSDP / UPnP",
    "ff02::d": "PIM all routers",
    "ff02::e": "RSVP encapsulation",
    "ff02::12": "VRRP",
    "ff02::16": "MLDv2 reports",
    "ff02::1a": "All RPL nodes",
    "ff02::66": "HSRP for IPv6",
    "ff02::6a": "All snoopers (MRD)",
    "ff02::6b": "PTP peer delay (IEEE 1588)",
    "ff02::6d": "All link-local routers (LL-MANET)",
    "ff02::fb": "mDNS (multicast DNS / Bonjour)",
    "ff02::101": "NTP",
    "ff02::1:2": "All DHCPv6 relay agents and servers",
    "ff02::1:3": "LLMNR",
    "ff05::2": "All routers (site-local)",
    "ff05::1:3": "All DHCPv6 servers (site-local)",
    "ff05::101": "NTP (site-local)",
    "ff0e::101": "NTP (global)",
    "ff05::c": "SSDP / UPnP (site-local)",
}
WELL_KNOWN_L2 = {
    "ffffffffffff": ("Broadcast", "Ethernet broadcast"),
    "0180c2000000": ("Multicast", "STP / RSTP / MSTP BPDUs (802.1D bridge group)"),
    "0180c2000001": ("Multicast", "Ethernet flow control PAUSE (802.3x)"),
    "0180c2000002": ("Multicast", "Slow protocols: LACP, Marker, Ethernet OAM (802.3ah)"),
    "0180c2000003": ("Multicast", "802.1X port authentication (EAPOL)"),
    "0180c2000008": ("Multicast", "Provider bridge group (802.1ad STP)"),
    "0180c200000e": ("Multicast", "LLDP (nearest bridge) / PTP peer delay"),
    "0180c2000014": ("Multicast", "IS-IS all Level 1 intermediate systems (AllL1ISs)"),
    "0180c2000015": ("Multicast", "IS-IS all Level 2 intermediate systems (AllL2ISs)"),
    "0180c2000016": ("Multicast", "All CONS end systems (ISO 8208)"),
    "0180c2000017": ("Multicast", "All CONS SNARES"),
    "0180c200000d": ("Multicast", "Provider bridge MVRP"),
    "01000ccdcdce": ("Multicast", "Cisco VLAN bridge"),
    "09002b000004": ("Multicast", "IS-IS / ES-IS all end systems (AllESs)"),
    "09002b000005": ("Multicast", "IS-IS / ES-IS all intermediate systems (AllISs)"),
    "030000000001": ("Multicast", "NetBIOS (Token Ring functional)"),
    "0180c2000020": ("Multicast", "MMRP (802.1ak)"),
    "0180c2000021": ("Multicast", "MVRP / GVRP (802.1ak)"),
    "01000ccccccc": ("Multicast", "Cisco CDP / VTP / DTP / PAgP / UDLD"),
    "01000ccccccd": ("Multicast", "Cisco PVST+ / Rapid-PVST+ BPDUs (SSTP)"),
    "01000ccdcdcd": ("Multicast", "Cisco STP UplinkFast"),
    "01000cdddddd": ("Multicast", "Cisco CGMP"),
    "01000c000000": ("Multicast", "Cisco ISL"),
    "011b19000000": ("Multicast", "PTP (IEEE 1588) over Ethernet"),
    "0180c200000f": ("Multicast", "Reserved bridge group address"),
}


@dataclass
class MacClass:
    category: str          # Unicast / Multicast / Broadcast / FHRP virtual
    scope: str             # Universal (OUI) / Locally administered
    detail: str = ""
    group: Optional[int] = None


def classify_mac(hex12: str) -> MacClass:
    """Identify broadcast, multicast (with the protocol or IP group it maps to),
    and HSRP / VRRP / GLBP virtual MACs (with their group numbers)."""
    h = hex12.lower()
    b = bytes.fromhex(h)
    multicast = bool(b[0] & 0x01)
    scope = "Locally administered" if b[0] & 0x02 else "Universal (OUI)"

    if h in WELL_KNOWN_L2:
        cat, detail = WELL_KNOWN_L2[h]
        return MacClass(cat, scope, detail)
    if multicast:
        if h.startswith("01005e") and not b[3] & 0x80:           # IPv4 multicast
            low23 = int(h[6:], 16) & 0x7FFFFF
            alt = [str(ipaddress.IPv4Address(0xE0000000 | (k << 23) | low23)) for k in range(32)]
            named = [a for a in alt if a in IPV4_MCAST_NAMES]
            ip = named[0] if named else alt[0]
            name = IPV4_MCAST_NAMES.get(ip)
            detail = (f"{name} – IPv4 {ip}" if name else f"IPv4 multicast {ip}") + \
                "  (1 of 32 IPv4 groups that map to this MAC)"
            return MacClass("Multicast", scope, detail)
        if h.startswith("3333"):                                    # IPv6 multicast
            low32 = int(h[4:], 16)
            if h.startswith("3333ff"):
                ip = ipaddress.IPv6Address((0xFF02 << 112) | (0x1FF << 24) | (low32 & 0xFFFFFF))
                return MacClass("Multicast", scope, f"IPv6 solicited-node multicast {ip.compressed} "
                                                    f"(neighbor discovery for IPv6 addresses ending …{h[6:8]}:{h[8:12]})")
            ip = ipaddress.IPv6Address((0xFF02 << 112) | low32)
            name = IPV6_MCAST_NAMES.get(ip.compressed)
            group = f"ffXX{ipaddress.IPv6Address(low32).compressed}"
            if name:
                return MacClass("Multicast", scope, f"{name} – IPv6 {group} (likely {ip.compressed})")
            return MacClass("Multicast", scope, f"IPv6 multicast {group}")
        if h.startswith("0180c20000"):
            last = b[5]
            if 0x30 <= last <= 0x3F:
                level = last & 0x07
                kind = "CCM" if last < 0x38 else "LTM"
                return MacClass("Multicast", scope, f"Ethernet CFM / Y.1731 (802.1ag) {kind}, MD level {level}")
            if last <= 0x0F:
                return MacClass("Multicast", scope, "Reserved IEEE 802.1 bridge group address")
        if h.startswith("01000c"):
            return MacClass("Multicast", scope, "Cisco multicast (proprietary protocol)")
        return MacClass("Multicast", scope, "Multicast (group address)")

    # FHRP virtual MACs (unicast)
    if h.startswith("00000c07ac"):
        g = b[5]
        return MacClass("FHRP virtual", scope, f"HSRPv1 virtual MAC – group {g}", g)
    if h.startswith("00000c9ff"):
        g = int(h[9:], 16)
        return MacClass("FHRP virtual", scope, f"HSRPv2 (IPv4) virtual MAC – group {g}", g)
    if h.startswith("000573a00"):
        g = int(h[9:], 16)
        return MacClass("FHRP virtual", scope, f"HSRP for IPv6 virtual MAC – group {g}", g)
    if h.startswith("00005e0001"):
        return MacClass("FHRP virtual", scope, f"VRRP (IPv4) virtual MAC – VRID {b[5]}", b[5])
    if h.startswith("00005e0002"):
        return MacClass("FHRP virtual", scope, f"VRRP (IPv6) virtual MAC – VRID {b[5]}", b[5])
    if h.startswith("0007b4"):
        group = ((b[3] << 8) | b[4]) & 0x3FF
        fwd = b[5]
        if (b[3] >> 2) == 0 and 1 <= fwd <= 4:
            return MacClass("FHRP virtual", scope, f"GLBP virtual MAC – group {group}, forwarder {fwd}", group)
    if b[0] & 0x02:
        return MacClass("Unicast", scope, "Locally administered (virtual, VM, or randomized/private MAC)")
    return MacClass("Unicast", scope)



def multicast_name(ip) -> str:
    """Well-known name for a multicast IP, '' if none.  ip = ipaddress object or string."""
    ip = ipaddress.ip_address(str(ip))
    if ip.version == 4:
        return IPV4_MCAST_NAMES.get(str(ip), "")
    return IPV6_MCAST_NAMES.get(ip.compressed, "")


def multicast_scope(ip) -> str:
    ip = ipaddress.ip_address(str(ip))
    if ip.version == 4:
        if ip in ipaddress.ip_network("224.0.0.0/24"):
            return "Local network control (link-local, TTL 1, not forwarded)"
        if ip in ipaddress.ip_network("224.0.1.0/24"):
            return "Internetwork control (routable)"
        if ip in ipaddress.ip_network("232.0.0.0/8"):
            return "Source-specific multicast (SSM)"
        if ip in ipaddress.ip_network("233.0.0.0/8"):
            return "GLOP (AS-based)"
        if ip in ipaddress.ip_network("239.0.0.0/8"):
            return "Administratively scoped (private)"
        return "Global scope"
    scopes = {1: "Interface-local", 2: "Link-local", 3: "Realm-local", 4: "Admin-local",
              5: "Site-local", 8: "Organization-local", 0xE: "Global"}
    return scopes.get(int(ip) >> 112 & 0xF, "Reserved scope")


def multicast_mac(ip) -> str:
    """Ethernet MAC an IP multicast group maps to (12 hex digits)."""
    ip = ipaddress.ip_address(str(ip))
    if ip.version == 4:
        return format(0x01005E000000 | (int(ip) & 0x7FFFFF), "012x")
    return format(0x333300000000 | (int(ip) & 0xFFFFFFFF), "012x")
