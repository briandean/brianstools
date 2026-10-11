"""Networks for an ASN from outside the IRR / RPKI: what it announces in BGP (RIPEstat, from RIPE RIS
route collectors) and what its organization holds at ARIN (Whois-RWS). Standard library only."""
from __future__ import annotations

import ipaddress
from typing import List, Optional, Tuple

import arinwhois

RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}&sourceapp=BriansTools"
MAX_ORG_NETS = 2000


def announced_prefixes(asn: str, timeout: float = 20.0, url: str = RIPESTAT_URL,
                       cache: Optional[dict] = None) -> List[str]:
    """Prefixes the ASN originated in BGP over the last two weeks, as seen by RIPE RIS."""
    data = arinwhois.fetch_url(url.format(asn=asn), "application/json", timeout, cache=cache, source="RIPEstat")
    out = []
    for p in (data.get("data") or {}).get("prefixes") or []:
        pfx = p.get("prefix") if isinstance(p, dict) else None
        if pfx and pfx not in out:
            out.append(pfx)
    return out


def arin_networks(asn: str, base: str = arinwhois.BASE_URL, timeout: float = 20.0,
                  cache: Optional[dict] = None) -> Tuple[str, List[Tuple[str, str, str]], str]:
    """(org name, [(cidr, net handle, net name)], note) for the organization that holds `asn` at ARIN.
    ASNs from other registries return no networks and a note saying where they're registered."""
    try:
        a = arinwhois.parse_asn(arinwhois.fetch_json(f"asn/{asn}", base, timeout, cache))
    except arinwhois.WhoisError as exc:
        if getattr(exc, "not_found", False):
            return "", [], ""                  # not an ARIN ASN: nothing to add, nothing to report
        return "", [], f"{asn}: ARIN lookup failed ({exc})"
    if not a.org_handle:
        return "", [], f"{asn}: no organization at ARIN"
    rir, _ = arinwhois.other_rir(a.org_handle, a.org_name)
    if rir:
        return a.org_name, [], f"{asn} is registered with {rir.split(' (')[0]}, not ARIN"
    try:
        data = arinwhois.fetch_json(f"org/{a.org_handle}/nets", base, timeout, cache)
    except arinwhois.WhoisError as exc:
        if getattr(exc, "not_found", False):
            return a.org_name, [], ""
        return a.org_name, [], f"{asn}: couldn't list {a.org_handle}'s networks ({exc})"
    nets = arinwhois.child(data, "nets") or data
    refs = arinwhois.as_list(arinwhois.child(nets, "netRef"))
    out: List[Tuple[str, str, str]] = []
    for r in refs:
        if not isinstance(r, dict):
            continue
        try:
            start = ipaddress.ip_address(r.get("@startAddress", ""))
            end = ipaddress.ip_address(r.get("@endAddress", ""))
            cidrs = list(ipaddress.summarize_address_range(start, end))
        except (ValueError, TypeError):
            continue
        for c in cidrs:
            out.append((str(c), r.get("@handle", ""), r.get("@name", "")))
        if len(out) >= MAX_ORG_NETS:
            break
    note = ""
    if str(arinwhois.text(arinwhois.child(nets, "limitExceeded"))).lower() == "true" or len(out) >= MAX_ORG_NETS:
        note = f"{asn}: {a.org_name} has more networks than ARIN lists at once; only the first {len(out):,} are shown"
    return a.org_name, out, note
