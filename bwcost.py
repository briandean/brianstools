"""Bandwidth cost math: monthly cost, one-time cost, term and circuit size -> cost per Mbps / Gbps, per
user, and per GB actually transferred. Standard library only."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

RATE_UNITS = {"Mbps": 1.0, "Gbps": 1000.0, "Tbps": 1_000_000.0}
TERM_UNITS = {"months": 1, "years": 12}
SECONDS_PER_MONTH = 365.2425 * 86400 / 12          # average month, 30.44 days


def parse_number(text: str) -> Optional[float]:
    """'$1,250.50' / '1250' / '1.5k' / '2e3' -> float (None if empty or not a number)."""
    t = str(text).strip().replace(",", "").replace("$", "").replace("_", "").replace(" ", "")
    if not t:
        return None
    mult = 1.0
    m = re.fullmatch(r"(.*?)([kKmM])", t)
    if m and re.fullmatch(r"[\d.eE+-]+", m.group(1) or "x"):
        t, mult = m.group(1), 1000.0 if m.group(2) in "kK" else 1_000_000.0
    try:
        v = float(t) * mult
    except ValueError:
        return None
    return v if v == v and v not in (float("inf"), float("-inf")) else None


@dataclass
class Quote:
    monthly: float                    # recurring cost per month (MRC)
    term_months: float
    mbps: Optional[float]             # circuit size in Mbps (None: per-user costs only, e.g. a capital quote)
    one_time: float = 0.0             # install / NRC
    spread_one_time: bool = True      # spread the one-time cost across the term (else it's paid up front)
    users: Optional[float] = None     # users (subscribers) sharing it each month
    utilization: float = 100.0        # average % used, for the per-GB figures


@dataclass
class Result:
    effective_monthly: float          # MRC (+ the one-time cost spread across the term, if spreading)
    first_month: float                # what the first bill comes to (MRC + the one-time cost if paid up front)
    total: float                      # whole-term cost
    annual: float
    per_mbps: Optional[float]         # per Mbps per month (None without a bandwidth)
    per_gbps: Optional[float]
    per_user: Optional[float]         # per user per month
    per_user_term: Optional[float]
    mbps_per_user: Optional[float]
    gb_per_month: Optional[float]     # data moved at the given utilization (decimal GB)
    per_gb: Optional[float]
    per_tb: Optional[float]


def compute(q: Quote) -> Result:
    if q.monthly < 0 or q.one_time < 0:
        raise ValueError("Costs can't be negative.")
    if q.term_months <= 0:
        raise ValueError("The term must be at least one month.")
    if q.mbps is None and not q.users:
        raise ValueError("Enter the bandwidth, or tick Divide by users to work out per-user costs without it.")
    if q.mbps is not None and q.mbps <= 0:
        raise ValueError("The bandwidth must be more than 0.")
    if q.monthly == 0 and q.one_time == 0:
        raise ValueError("Enter a monthly cost, a one-time cost, or both.")
    if q.users is not None and q.users <= 0:
        raise ValueError("Users must be more than 0.")
    if not 0 < q.utilization <= 100:
        raise ValueError("Utilization must be between 0 and 100%.")
    eff = q.monthly + (q.one_time / q.term_months if q.spread_one_time else 0.0)
    first = eff if q.spread_one_time else q.monthly + q.one_time
    total = q.monthly * q.term_months + q.one_time          # the one-time cost is paid either way
    per_mbps = eff / q.mbps if q.mbps else None
    gb = q.mbps * 1e6 / 8 * SECONDS_PER_MONTH * (q.utilization / 100) / 1e9 if q.mbps else None
    u = q.users
    return Result(
        effective_monthly=eff, first_month=first, total=total, annual=eff * 12, per_mbps=per_mbps,
        per_gbps=per_mbps * 1000 if per_mbps is not None else None,
        per_user=eff / u if u else None, per_user_term=total / u if u else None,
        mbps_per_user=q.mbps / u if u and q.mbps else None,
        gb_per_month=gb, per_gb=eff / gb if gb else None, per_tb=eff / gb * 1000 if gb else None)


def money(v: Optional[float]) -> str:
    """$1,234.56 for normal amounts; more decimals for fractions of a cent (e.g. $0.0042)."""
    if v is None:
        return "–"
    a = abs(v)
    if a >= 1 or a == 0:
        return f"${v:,.2f}"
    if a >= 0.01:
        return f"${v:,.4f}"
    return f"${v:.6f}"


def rate(mbps: Optional[float]) -> str:
    if mbps is None:
        return "–"
    if mbps >= 1_000_000:
        return f"{mbps / 1_000_000:,.3g} Tbps"
    if mbps >= 1000:
        return f"{mbps / 1000:,.4g} Gbps"
    if mbps >= 1:
        return f"{mbps:,.4g} Mbps"
    return f"{mbps * 1000:,.4g} kbps"


def volume(gb: float) -> str:
    if gb >= 1_000_000:
        return f"{gb / 1_000_000:,.2f} PB"
    if gb >= 1000:
        return f"{gb / 1000:,.2f} TB"
    return f"{gb:,.1f} GB"


def term_text(months: float) -> str:
    if months % 12 == 0 and months >= 12:
        y = int(months // 12)
        return f"{y} year{'s' if y != 1 else ''} ({int(months)} months)"
    return f"{months:g} month{'s' if months != 1 else ''}"
