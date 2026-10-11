"""Find date/time stamps in log text and rewrite them in another time zone. Standard library only.

Recognised (most network and server logs):
  ISO 8601 / RFC 3339  2026-10-10T11:02:03.123Z   2026-10-10 11:02:03 -0400   2026/10/10 11:02:03
  syslog / Cisco / XR  Oct 10 11:02:03            *Oct 10 2026 11:02:03.123 UTC:   Oct  1 09:00:00 EDT
  ctime / date(1)      Sat Oct 10 11:02:03 2026   Sat Oct 10 11:02:03 EDT 2026
  RFC 2822 / Apache    Sat, 10 Oct 2026 11:02:03 -0400   10/Oct/2026:11:02:03 -0400   10-Oct-2026 11:02
  numeric              10/10/2026 11:02:03 AM     10.10.2026 11:02:03   10-10-26 23:02
  Unix epoch (opt-in)  1791630123   1791630123456
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

import subnetcalc_core as core

MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
MONTH_FULL = ["January", "February", "March", "April", "May", "June", "July", "August", "September",
              "October", "November", "December"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

# Common abbreviations -> UTC offset in minutes. CST/IST/AST are read as US Central, India, Atlantic.
TZ_ABBREV = {
    "UTC": 0, "GMT": 0, "UT": 0, "Z": 0, "WET": 0, "WEST": 60, "BST": 60, "CET": 60, "CEST": 120,
    "MET": 60, "MEST": 120, "EET": 120, "EEST": 180, "MSK": 180, "IST": 330, "PKT": 300,
    "ICT": 420, "WIB": 420, "HKT": 480, "SGT": 480, "PHT": 480, "AWST": 480, "JST": 540, "KST": 540,
    "ACST": 570, "ACDT": 630, "AEST": 600, "AEDT": 660, "NZST": 720, "NZDT": 780,
    "EST": -300, "EDT": -240, "CST": -360, "CDT": -300, "MST": -420, "MDT": -360,
    "PST": -480, "PDT": -420, "AKST": -540, "AKDT": -480, "HST": -600, "AST": -240, "ADT": -180,
    "NST": -210, "NDT": -150,
}

_MON = (r"(?i:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?"
        r"|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)")
_DOW = r"(?i:mon(?:day)?|tue(?:s(?:day)?)?|wed(?:nesday)?|thu(?:r(?:s(?:day)?)?)?|fri(?:day)?|sat(?:urday)?|sun(?:day)?)"
_TIME = (r"(?P<hour>\d{1,2}):(?P<minute>\d{2})(?::(?P<second>\d{2})(?:[.,](?P<frac>\d{1,9}))?)?"
         r"(?:[ \t]?(?P<ampm>[AaPp][Mm])\b)?(?!\d)(?!:\d)")
_ABBR = "|".join(sorted((k for k in TZ_ABBREV if k != "Z"), key=len, reverse=True))
# Bare "Z" and "+05" only count when glued to the time ("11:02:03Z"), so "11:02 -10 dBm" isn't a zone.
_TZ = (rf"(?P<tz>(?:UTC|GMT)[+-]\d{{1,2}}(?::?\d{{2}})?(?![\d:])|(?<=\d)Z\b|[+-]\d{{2}}:?\d{{2}}(?![\d:])"
       rf"|(?<=\d)[+-]\d{{2}}(?![\d:])|(?:{_ABBR})\b)")

PATTERNS = [
    ("ISO 8601", re.compile(
        rf"(?<![\d.])(?P<year>\d{{4}})(?P<dsep>[-/.])(?P<month>\d{{1,2}})(?P=dsep)(?P<day>\d{{1,2}})"
        rf"(?:T|[ \t]+|_){_TIME}(?:[ \t]?{_TZ})?")),
    ("syslog", re.compile(
        rf"(?<![\w])(?:(?P<dow>{_DOW}),?[ \t]+)?(?P<month>{_MON})\.?(?P<pday>[ \t]{{1,2}}\d{{1,2}})"
        rf"(?:,?[ \t]+(?P<year>\d{{4}}))?,?[ \t]+{_TIME}(?:[ \t]?{_TZ})?"
        rf"(?:[ \t]+(?P<year2>(?:19|20)\d{{2}})(?![\w:.]))?")),
    ("dd Mon yyyy", re.compile(
        rf"(?<![\w])(?:(?P<dow>{_DOW}),?[ \t]+)?(?P<day>\d{{1,2}})(?P<dsep>[ \-/])(?P<month>{_MON})(?P=dsep)"
        rf"(?P<year>\d{{4}}|\d{{2}})(?:[ :T]|,[ \t]){_TIME}(?:[ \t]?{_TZ})?")),
    ("numeric", re.compile(
        rf"(?<![\d/.:-])(?P<n1>\d{{1,2}})(?P<dsep>[/.\-])(?P<n2>\d{{1,2}})(?P=dsep)(?P<year>\d{{4}}|\d{{2}})"
        rf"(?:,?[ \t]+|[ \t]*-[ \t]*|T){_TIME}(?:[ \t]?{_TZ})?")),
]
EPOCH = re.compile(r"(?<![\w.:/-])(?P<epoch>1\d{9}(?P<ms>\d{3})?(?:\.(?P<efrac>\d{1,9}))?)(?![\w.])")


@dataclass
class Options:
    source_zone: str = "UTC"            # zone for stamps that don't say
    target_zone: str = "UTC"
    trust_stamp_zone: bool = True       # use an offset/abbreviation written in the stamp
    shift_seconds: float = 0            # extra correction for a device clock that's off
    year: Optional[int] = None          # for stamps without a year; None = most recent past
    day_first: bool = False             # numeric 03/04/2026 = 3 April
    output: str = "keep"                # keep / readable / iso / custom
    custom_format: str = "%Y-%m-%d %H:%M:%S %Z"
    append: bool = False                # keep the original and add " [converted]"
    add_zone: bool = False              # keep format: add the zone name to stamps that had none
    epoch: bool = False
    now: Optional[datetime] = None      # for tests


@dataclass
class Stamp:
    line: int                           # 1-based
    col: int                            # 0-based start column in the original line
    end_col: int
    out_col: int = 0                    # start/end column in the converted line
    out_end_col: int = 0
    kind: str = ""
    original: str = ""
    converted: str = ""
    source: Optional[datetime] = None   # aware, as read
    result: Optional[datetime] = None   # aware, in the target zone
    zone_note: str = ""                 # where the source zone came from
    note: str = ""                      # DST gap/overlap or similar


@dataclass
class Result:
    text: str
    stamps: List[Stamp] = field(default_factory=list)
    kinds: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- parsing


def parse_shift(text: str) -> float:
    """'+5h', '-1:30', '90s', '-00:00:42', '2d 3h', '' -> seconds."""
    t = text.strip().lower().replace(" ", "")
    if not t:
        return 0.0
    sign = -1 if t.startswith("-") else 1
    t = t.lstrip("+-")
    if re.fullmatch(r"\d+(?::\d{1,2}){1,2}(?:\.\d+)?", t):
        parts = [float(p) for p in t.split(":")]
        while len(parts) < 3:
            parts.append(0.0)
        return sign * (parts[0] * 3600 + parts[1] * 60 + parts[2])
    units = {"d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0.001}
    total, pos = 0.0, 0
    for m in re.finditer(r"(\d+(?:\.\d+)?)(ms|d|h|m|s)?", t):
        if m.start() != pos:
            raise ValueError(f"Can't read shift '{text}'. Try +5h, -1:30, 90s or 2d 3h.")
        total += float(m.group(1)) * units[m.group(2) or "s"]
        pos = m.end()
    if pos != len(t):
        raise ValueError(f"Can't read shift '{text}'. Try +5h, -1:30, 90s or 2d 3h.")
    return sign * total


def tz_offset(text: str) -> Optional[timedelta]:
    if text in TZ_ABBREV:
        return timedelta(minutes=TZ_ABBREV[text])
    m = re.fullmatch(r"(?:UTC|GMT)?([+-])(\d{1,2}):?(\d{2})?", text)
    if not m:
        return None
    mins = int(m.group(2)) * 60 + int(m.group(3) or 0)
    return timedelta(minutes=mins if m.group(1) == "+" else -mins)


def _month_num(text: str) -> int:
    return MONTHS.index(text[:3].lower()) + 1


def _read(kind: str, m: re.Match, opts: Options) -> Optional[Tuple[datetime, bool]]:
    """Naive datetime from a match, plus whether the year was guessed. None if not a real date."""
    g = m.groupdict()
    try:
        if kind == "numeric":
            a, b = int(g["n1"]), int(g["n2"])
            day_first = opts.day_first or g["dsep"] == "."
            if day_first and b > 12 >= a:
                day_first = False
            elif not day_first and a > 12 >= b:
                day_first = True
            day, month = (a, b) if day_first else (b, a)
        else:
            month = int(g["month"]) if g["month"].isdigit() else _month_num(g["month"])
            day = int((g.get("day") or g.get("pday") or "").strip(" -"))
        year_text = g.get("year") or g.get("year2")
        guessed = year_text is None
        if guessed:
            year = opts.year or (opts.now or datetime.now()).year
        else:
            year = int(year_text)
            if len(year_text) == 2:
                year += 2000 if year < 70 else 1900
        hour, minute = int(g["hour"]), int(g["minute"])
        if g["ampm"]:
            if not 1 <= hour <= 12:
                return None
            hour = hour % 12 + (12 if g["ampm"].lower() == "pm" else 0)
        second = int(g["second"] or 0)
        frac = g["frac"] or ""
        micro = int((frac + "000000")[:6]) if frac else 0
        dt = datetime(year, month, day, hour, minute, min(second, 59), micro)
        if guessed and opts.year is None:
            now = opts.now or datetime.now()
            if dt > now + timedelta(days=2):   # a December line read in January belongs to last year
                dt = dt.replace(year=year - 1)
        return dt, guessed
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- formatting


def _case_like(sample: str, word: str) -> str:
    if sample.isupper() and len(sample) > 1:
        return word.upper()
    if sample.islower():
        return word.lower()
    return word


def _name_like(sample: str, full: str) -> str:
    """Month/day name in the same length and case style as `sample`."""
    s = sample.rstrip(".")
    if len(s) <= 3:
        word = full[:3]
    elif len(s) == 4 and full[:4].lower() == s.lower():     # "Sept", "Tues", "Thur"
        word = full[:4]
    elif len(s) == len(full):
        word = full
    else:
        word = full[:3] if len(s) < len(full) else full
    return _case_like(s, word)


def _num_like(sample: str, n: int, pad: bool = True) -> str:
    """Number in the same padding style as `sample` ('07' zero-padded, ' 7' space-padded, '7' none)."""
    if sample.startswith("0") and len(sample) == 2:
        return f"{n:02d}"
    if sample.startswith(" "):
        return f"{n:>2}"
    if len(sample) == 1:
        return str(n)
    return f"{n:02d}" if pad else str(n)        # '10', '23': style unknown


def _tz_like(sample: str, dt: datetime) -> str:
    off = dt.utcoffset() or timedelta(0)
    mins = int(off.total_seconds() // 60)
    sign = "+" if mins >= 0 else "-"
    h, mm = divmod(abs(mins), 60)
    if sample == "Z":
        return "Z" if mins == 0 else f"{sign}{h:02d}:{mm:02d}"
    if re.fullmatch(r"[+-]\d{2}:\d{2}", sample):
        return f"{sign}{h:02d}:{mm:02d}"
    if re.fullmatch(r"[+-]\d{4}", sample):
        return f"{sign}{h:02d}{mm:02d}"
    if re.fullmatch(r"[+-]\d{2}", sample):
        return f"{sign}{h:02d}" + (f":{mm:02d}" if mm else "")
    m = re.fullmatch(r"(UTC|GMT)[+-].*", sample)
    if m:
        return m.group(1) + (f"{sign}{h}" + (f":{mm:02d}" if mm else "") if mins else "")
    return zone_abbrev(dt)


def zone_abbrev(dt: datetime) -> str:
    name = dt.tzname() or ""
    return name if name else _tz_like("+00:00", dt)


def _frac_like(sample: str, dt: datetime) -> str:
    return f"{dt.microsecond:06d}{'0' * 3}"[:len(sample)]


def _rewrite(kind: str, m: re.Match, out: datetime, opts: Options) -> str:
    """Re-render the matched text with `out`, keeping every field's original style."""
    g = m.groupdict()
    start = m.start()
    text = m.group(0)
    edits = []        # (start, end, replacement) relative to the match

    def put(name, value):
        if g.get(name) is not None:
            edits.append((m.start(name) - start, m.end(name) - start, value))

    if kind == "numeric":
        a, b = int(g["n1"]), int(g["n2"])
        day_first = opts.day_first or g["dsep"] == "."
        if day_first and b > 12 >= a:
            day_first = False
        elif not day_first and a > 12 >= b:
            day_first = True
        first, second = (out.day, out.month) if day_first else (out.month, out.day)
        put("n1", _num_like(g["n1"], first))
        put("n2", _num_like(g["n2"], second))
    else:
        if g["month"].isdigit():
            put("month", _num_like(g["month"], out.month))
        else:
            put("month", _name_like(g["month"], MONTH_FULL[out.month - 1]))
        if g.get("pday") is not None:
            p = g["pday"]
            digits = p.lstrip(" \t")
            if digits.startswith("0"):
                put("pday", " " + f"{out.day:02d}")
            elif len(p) == 2:                       # "Oct 7" stays unpadded
                put("pday", " " + str(out.day))
            else:                                   # syslog style "Oct  7" / "Oct 17"
                put("pday", " " + f"{out.day:>2}")
        else:
            put("day", _num_like(g["day"], out.day))
    for yname in ("year", "year2"):
        if g.get(yname) is not None:
            put(yname, f"{out.year:04d}" if len(g[yname]) == 4 else f"{out.year % 100:02d}")
    if g.get("dow") is not None:
        put("dow", _name_like(g["dow"], DAYS[out.weekday()]))
    if g["ampm"]:
        h12 = out.hour % 12 or 12
        put("hour", _num_like(g["hour"], h12, pad=False))
        put("ampm", _case_like(g["ampm"], "PM" if out.hour >= 12 else "AM"))
    else:
        put("hour", _num_like(g["hour"], out.hour))
    put("minute", f"{out.minute:02d}")
    put("second", f"{out.second:02d}")
    if g["frac"]:
        put("frac", _frac_like(g["frac"], out))
    if g.get("tz") is not None:
        put("tz", _tz_like(g["tz"], out))
    elif opts.add_zone:
        last = max(m.end(n) for n in ("minute", "second", "frac", "ampm") if g.get(n) is not None) - start
        edits.append((last, last, " " + zone_abbrev(out)))
    for s, e, v in sorted(edits, reverse=True):
        text = text[:s] + v + text[e:]
    return text


def _fixed_format(out: datetime, opts: Options, frac_digits: int) -> str:
    frac = f".{_frac_like('0' * frac_digits, out)}" if frac_digits else ""
    if opts.output == "iso":
        return out.strftime("%Y-%m-%dT%H:%M:%S") + frac + _tz_like("+00:00", out)
    if opts.output == "custom" and opts.custom_format.strip():
        fmt = opts.custom_format.replace("%f", f"{out.microsecond:06d}")
        if "%Z" in fmt:
            fmt = fmt.replace("%Z", zone_abbrev(out).replace("%", "%%"))
        return out.strftime(fmt)
    return out.strftime("%Y-%m-%d %H:%M:%S") + frac + " " + zone_abbrev(out)


# --------------------------------------------------------------------------- main entry


def find_matches(text: str, opts: Options):
    """Non-overlapping (start, end, kind, match) in text order."""
    found = []
    for kind, rx in PATTERNS:
        for m in rx.finditer(text):
            found.append((m.start(), m.end(), kind, m))
    if opts.epoch:
        for m in EPOCH.finditer(text):
            found.append((m.start(), m.end(), "Unix epoch", m))
    found.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    out, last_end = [], -1
    for item in found:
        if item[0] >= last_end:
            out.append(item)
            last_end = item[1]
    return out


def convert_text(text: str, opts: Options) -> Result:
    target = core.get_zone(opts.target_zone)
    shift = timedelta(seconds=opts.shift_seconds)
    line_starts = [0] + [m.end() for m in re.finditer("\n", text)]
    pieces, stamps, kinds = [], [], {}
    pos = 0
    out_line_delta = {}                 # line -> running change in length so far on that line
    for start, end, kind, m in find_matches(text, opts):
        note = ""
        if kind == "Unix epoch":
            raw = m.group("epoch")
            secs = int(raw[:13]) / 1000 if m.group("ms") else float(raw)
            src = datetime.fromtimestamp(0, timezone.utc) + timedelta(seconds=secs)
            zone_note = "epoch (UTC)"
            frac_digits = 3 if m.group("ms") else len(m.group("efrac") or "")
        else:
            read = _read(kind, m, opts)
            if read is None:
                continue
            naive, guessed = read
            tz_text = m.groupdict().get("tz")
            off = tz_offset(tz_text) if tz_text and opts.trust_stamp_zone else None
            if off is not None:
                src = naive.replace(tzinfo=timezone(off))
                zone_note = f"{tz_text} in stamp"
            else:
                src, note = core.localize(naive, opts.source_zone)
                note = note or ""
                zone_note = f"{opts.source_zone} (assumed)"
            if guessed:
                zone_note += f", {naive.year} guessed"
            frac_digits = len(m.group("frac") or "")
        result = (src + shift).astimezone(target)
        if kind == "Unix epoch" or opts.output != "keep":
            new = _fixed_format(result, opts, frac_digits)
        else:
            new = _rewrite(kind, m, result, opts)
        original = m.group(0)
        replacement = f"{original} [{new}]" if opts.append else new
        line = bisect.bisect_right(line_starts, start)
        col = start - line_starts[line - 1]
        delta = out_line_delta.get(line, 0)
        out_col = col + delta
        if opts.append:
            out_col += len(original) + 2
        out_line_delta[line] = delta + len(replacement) - len(original)
        pieces.append(text[pos:start])
        pieces.append(replacement)
        pos = end
        stamps.append(Stamp(line, col, end - line_starts[line - 1], out_col, out_col + len(new), kind, original,
                            new, src, result, zone_note, note))
        kinds[kind] = kinds.get(kind, 0) + 1
    pieces.append(text[pos:])
    return Result("".join(pieces), stamps, kinds)
