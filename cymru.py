"""Team Cymru IP-to-ASN mapping: origin AS, BGP prefix, country, registry, allocation date and AS name for
IP addresses, prefixes and AS numbers. Standard library only.

Two ways to ask, same data (https://www.team-cymru.com/ip-asn-mapping):
  * whois, bulk mode, TCP port 43 at whois.cymru.com: one connection answers a whole list.
  * DNS TXT records: origin.asn.cymru.com / origin6.asn.cymru.com for addresses, asn.cymru.com for AS
    names. Useful where outbound port 43 is blocked; one or two queries per item.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

WHOIS_HOST = "whois.cymru.com"
WHOIS_PORT = 43
DNS_ORIGIN4 = "origin.asn.cymru.com"
DNS_ORIGIN6 = "origin6.asn.cymru.com"
DNS_ASN = "asn.cymru.com"
WEBSITE = "https://www.team-cymru.com"
INFO_URL = "https://www.team-cymru.com/ip-asn-mapping"
CANARY_ASN = "15169"                 # DNS sanity check: this AS's record is always published
BULK_CHUNK = 1000                    # lines per whois connection (the service takes many thousands)
REGISTRIES = {"arin": "ARIN", "ripencc": "RIPE NCC", "ripe": "RIPE NCC", "apnic": "APNIC",
              "lacnic": "LACNIC", "afrinic": "AFRINIC", "other": "Other"}


class CymruError(Exception):
    pass


@dataclass
class CymruRecord:
    query: str                       # what was asked (IP, prefix, or AS123)
    kind: str                        # "ip" or "asn"
    asns: List[str] = field(default_factory=list)   # origin AS numbers ("" when not announced)
    prefix: str = ""                 # covering BGP prefix
    cc: str = ""
    registry: str = ""               # arin / ripencc / apnic / lacnic / afrinic
    allocated: str = ""              # YYYY-MM-DD
    as_name: str = ""
    error: str = ""
    note: str = ""
    source: str = ""                 # "whois" or "DNS"

    @property
    def asn(self) -> str:
        return self.asns[0] if self.asns else ""

    @property
    def origin(self) -> str:
        """'AS15169' or 'AS1 / AS2' for multi-origin prefixes; '' when not announced."""
        return " / ".join(f"AS{a}" for a in self.asns)

    @property
    def registry_name(self) -> str:
        return REGISTRIES.get(self.registry.lower(), self.registry.upper()) if self.registry else ""

    @property
    def announced(self) -> bool:
        return bool(self.asns)


# --------------------------------------------------------------------------- queries


def query_key(q: str) -> Tuple[str, str]:
    """('ip', '8.8.8.8') / ('ip', '2001:db8::') for a prefix's first address / ('asn', '15169')."""
    s = q.strip()
    m = re.fullmatch(r"(?i)(?:AS)?\s*(\d{1,10})(?:\.(\d{1,5}))?", s)
    if m and (s.upper().startswith("AS") or "." not in s):
        n = int(m.group(1)) * 65536 + int(m.group(2)) if m.group(2) else int(m.group(1))
        if n < 2 ** 32:
            return "asn", str(n)
    try:
        if "/" in s:
            return "ip", str(ipaddress.ip_network(s, strict=False).network_address)
        return "ip", str(ipaddress.ip_address(s))
    except ValueError:
        raise CymruError(f"{q}: not an IP address, prefix or AS number") from None


def _norm_ip(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return text.strip()


# --------------------------------------------------------------------------- whois (bulk, TCP 43)


def build_bulk(keys: Iterable[Tuple[str, str]]) -> bytes:
    lines = ["begin", "verbose"]
    for kind, val in keys:
        lines.append(f"AS{val}" if kind == "asn" else val)
    lines.append("end")
    return ("\n".join(lines) + "\n").encode("ascii")


def parse_bulk(text: str) -> Tuple[Dict[str, List[List[str]]], Dict[str, List[List[str]]], List[str]]:
    """Bulk verbose output -> ({ip: [rows]}, {asn: [rows]}, [error lines]).

    IP rows:  AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name   (one row per origin AS)
    ASN rows: AS | CC | Registry | Allocated | AS Name"""
    ips: Dict[str, List[List[str]]] = {}
    asns: Dict[str, List[List[str]]] = {}
    errors: List[str] = []
    for line in text.splitlines():
        if line.lower().startswith("error"):
            errors.append(line.strip())
            continue
        if "|" not in line or line.startswith("Bulk mode"):
            continue
        f = [p.strip() for p in line.split("|")]
        if f[0].upper() == "AS":                     # a header row
            continue
        if len(f) >= 7:
            f = f[:6] + ["|".join(f[6:]).strip()]    # AS names never contain '|', but be safe
            ips.setdefault(_norm_ip(f[1]), []).append(f)
        elif len(f) >= 5:
            f = f[:4] + ["|".join(f[4:]).strip()]
            asns.setdefault(f[0], []).append(f)
    return ips, asns, errors


def _clean(v: str) -> str:
    return "" if v.upper() in ("NA", "N/A") else v


def record_from_ip_rows(query: str, rows: List[List[str]]) -> CymruRecord:
    r = CymruRecord(query=query, kind="ip", source="whois")
    for f in rows:
        asn = _clean(f[0])
        if asn and asn not in r.asns:
            r.asns.append(asn)
    first = next((f for f in rows if _clean(f[0])), rows[0])
    r.prefix, r.cc, r.registry, r.allocated = _clean(first[2]), first[3], first[4], first[5]
    r.as_name = " / ".join(dict.fromkeys(_clean(f[6]) for f in rows if _clean(f[6])))
    if not r.asns:
        r.note = "Not announced in BGP (no origin AS seen by Team Cymru's peers)"
    elif len(r.asns) > 1:
        r.note = f"Multiple origins: {r.origin}"
    return r


def record_from_asn_rows(query: str, rows: List[List[str]]) -> CymruRecord:
    f = rows[0]
    r = CymruRecord(query=query, kind="asn", asns=[f[0]] if _clean(f[0]) else [], cc=f[1], registry=f[2],
                    allocated=f[3], as_name=_clean(f[4]), source="whois")
    if not r.as_name and not r.registry:
        r.error = "No data (unassigned or reserved AS number?)"
    return r


def whois_bulk(queries: List[str], host: str = WHOIS_HOST, port: int = WHOIS_PORT, timeout: float = 20.0,
               connect: Callable = socket.create_connection) -> Dict[str, CymruRecord]:
    """Look up many IPs / prefixes / ASNs with one whois connection per BULK_CHUNK lines."""
    out: Dict[str, CymruRecord] = {}
    keyed: List[Tuple[str, Tuple[str, str]]] = []
    for q in queries:
        try:
            keyed.append((q, query_key(q)))
        except CymruError as exc:
            out[q] = CymruRecord(query=q, kind="", error=str(exc))
    uniq = list(dict.fromkeys(k for _, k in keyed))
    ips: Dict[str, List[List[str]]] = {}
    asns: Dict[str, List[List[str]]] = {}
    for i in range(0, len(uniq), BULK_CHUNK):
        chunk = uniq[i:i + BULK_CHUNK]
        text = _talk(build_bulk(chunk), host, port, timeout, connect)
        a, b, _errs = parse_bulk(text)
        ips.update(a)
        asns.update(b)
    for q, (kind, val) in keyed:
        if kind == "ip":
            rows = ips.get(val)
            r = record_from_ip_rows(q, rows) if rows else CymruRecord(query=q, kind="ip", source="whois",
                                                                       error="No data returned")
        else:
            rows = asns.get(val)
            r = record_from_asn_rows(q, rows) if rows else CymruRecord(query=q, kind="asn", source="whois",
                                                                        error="No data returned")
        if kind == "ip" and "/" in q and not r.error:
            r.note = (f"Looked up by its first address ({val}). " + r.note).strip()
        out[q] = r
    return out


def _talk(payload: bytes, host: str, port: int, timeout: float, connect: Callable) -> str:
    try:
        sock = connect((host, port), timeout=timeout)
    except socket.timeout:
        raise CymruError(f"{host}:{port} didn't answer within {timeout:g}s (is outbound TCP port 43 "
                         "blocked?)") from None
    except OSError as exc:
        raise CymruError(f"couldn't connect to {host}:{port}: {exc.strerror or exc}") from None
    chunks = []
    try:
        sock.settimeout(timeout)
        sock.sendall(payload)
        deadline = time.monotonic() + max(timeout, 60.0)
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
            if time.monotonic() > deadline:
                raise CymruError(f"{host}:{port}: the answer took too long")
    except socket.timeout:
        if not chunks:
            raise CymruError(f"{host}:{port} stopped answering") from None
    except OSError as exc:
        raise CymruError(f"{host}:{port}: {exc.strerror or exc}") from None
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return b"".join(chunks).decode("utf-8", "replace")


# --------------------------------------------------------------------------- DNS


def origin_name(ip: str) -> str:
    """8.8.8.8 -> 8.8.8.8.origin.asn.cymru.com reversed; IPv6 by nibbles under origin6."""
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        return ".".join(reversed(str(a).split("."))) + "." + DNS_ORIGIN4
    nib = a.exploded.replace(":", "")
    return ".".join(reversed(nib)) + "." + DNS_ORIGIN6


def parse_origin_txt(txts: List[str]) -> Optional[List[str]]:
    """Origin TXT strings -> fields of the most specific prefix: [ASNs, prefix, CC, registry, allocated]."""
    best, best_len = None, -1
    for t in txts:
        f = [p.strip() for p in t.strip().strip('"').split("|")]
        if len(f) < 5:
            continue
        try:
            plen = ipaddress.ip_network(f[1], strict=False).prefixlen
        except ValueError:
            plen = 0
        if plen > best_len:
            best, best_len = f[:5], plen
    return best


def parse_asn_txt(txts: List[str]) -> Optional[List[str]]:
    """AS TXT -> [ASN, CC, registry, allocated, AS name]."""
    for t in txts:
        f = [p.strip() for p in t.strip().strip('"').split("|")]
        if len(f) >= 5:
            return f[:4] + ["|".join(f[4:]).strip()]
    return None


def _txt(name: str, server: str, timeout: float, resolver: Callable) -> List[str]:
    return resolver(name, server, timeout)


def default_resolver(name: str, server: str, timeout: float) -> List[str]:
    import dnsdig
    res = dnsdig.query(name, "TXT", server=server, timeout=timeout)
    if res.message.rcode not in (0, 3):           # NOERROR / NXDOMAIN are answers; SERVFAIL, REFUSED… aren't
        raise CymruError(f"{res.server} answered {res.message.rcode_name}")
    out = []
    for rr in res.message.answer:
        if rr.type_name == "TXT":       # '"part1" "part2"' -> 'part1part2'
            parts = re.findall(r'"((?:[^"\\]|\\.)*)"', rr.text)
            out.append("".join(parts) if parts else rr.text)
    return out


def dns_lookup(query: str, server: str = "", timeout: float = 4.0, resolver: Callable = default_resolver,
               as_names: Optional[Dict[str, str]] = None) -> CymruRecord:
    """One item over DNS. `as_names` caches AS name lookups across items."""
    if not server:
        import dnsdig
        server = (dnsdig.system_resolvers() or ["1.1.1.1"])[0]
    as_names = {} if as_names is None else as_names
    try:
        kind, val = query_key(query)
    except CymruError as exc:
        return CymruRecord(query=query, kind="", error=str(exc), source="DNS")

    def name_of(asn: str) -> Tuple[str, Optional[List[str]]]:
        if asn not in as_names:
            f = parse_asn_txt(_txt(f"AS{asn}.{DNS_ASN}", server, timeout, resolver))
            as_names[asn] = f
        f = as_names[asn]
        return (f[4] if f else ""), f

    try:
        if kind == "asn":
            name, f = name_of(val)
            if not f:
                return CymruRecord(query=query, kind="asn", source="DNS",
                                   error="No data (unassigned or reserved AS number?)")
            return CymruRecord(query=query, kind="asn", asns=[f[0]], cc=f[1], registry=f[2], allocated=f[3],
                               as_name=_clean(name), source="DNS")
        f = parse_origin_txt(_txt(origin_name(val), server, timeout, resolver))
        r = CymruRecord(query=query, kind="ip", source="DNS")
        if not f:
            r.note = "Not announced in BGP (no origin AS seen by Team Cymru's peers)"
            return r
        r.asns = [a for a in f[0].split() if _clean(a)]
        r.prefix, r.cc, r.registry, r.allocated = f[1], f[2], f[3], f[4]
        r.as_name = " / ".join(n for n in (name_of(a)[0] for a in r.asns) if n)
        if len(r.asns) > 1:
            r.note = f"Multiple origins: {r.origin}"
        if "/" in query:
            r.note = (f"Looked up by its first address ({val}). " + r.note).strip()
        return r
    except Exception as exc:                          # DnsError, timeouts: report on this row
        return CymruRecord(query=query, kind=kind, source="DNS", error=f"DNS lookup failed: {exc}")


# --------------------------------------------------------------------------- one entry point


def lookup_many(queries: List[str], via: str = "auto", host: str = WHOIS_HOST, port: int = WHOIS_PORT,
                dns_server: str = "", timeout: float = 20.0, connect: Callable = socket.create_connection,
                resolver: Callable = default_resolver,
                progress: Optional[Callable[[int, int], None]] = None,
                stop: Optional[Callable[[], bool]] = None) -> Tuple[Dict[str, CymruRecord], str]:
    """-> ({query: record}, note). via = 'whois', 'dns', or 'auto' (whois, then DNS if port 43 fails)."""
    note = ""
    if via in ("auto", "whois"):
        try:
            return whois_bulk(queries, host, port, timeout, connect), ""
        except CymruError as exc:
            if via == "whois":
                return {q: CymruRecord(query=q, kind="", error=str(exc), source="whois") for q in queries}, str(exc)
            note = f"whois failed ({exc}); used DNS instead"
    out: Dict[str, CymruRecord] = {}
    names: Dict[str, Optional[List[str]]] = {}
    # A resolver that blocks or rewrites these names would make every address look "not announced", so first
    # check a record that always exists.
    if not dns_server:
        import dnsdig
        dns_server = (dnsdig.system_resolvers() or ["1.1.1.1"])[0]
    canary = None
    try:
        canary = parse_asn_txt(resolver(f"AS{CANARY_ASN}.{DNS_ASN}", dns_server, min(timeout, 5.0)))
        problem = "" if canary else (f"{dns_server} returned no Team Cymru records (AS{CANARY_ASN}.{DNS_ASN} should "
                                     "always exist), so its answers can't be trusted. Is DNS filtered here?")
    except Exception as exc:
        problem = f"DNS lookup failed: {exc}"
    if canary:
        names[CANARY_ASN] = canary
    if problem:
        note = (note + "; " if note else "") + problem
        return {q: CymruRecord(query=q, kind="", source="DNS", error=problem) for q in queries}, note
    failed, ok = 0, False
    for i, q in enumerate(queries, 1):
        if stop and stop():
            break
        if failed >= 3 and not ok:               # DNS isn't working at all: don't wait out every item
            out[q] = CymruRecord(query=q, kind="", source="DNS", error=f"Skipped: {last}")
            continue
        r = out[q] = dns_lookup(q, dns_server, min(timeout, 5.0), resolver, names)
        if r.error.startswith("DNS lookup failed"):
            failed, last = failed + 1, r.error
        else:
            ok = True
        if progress:
            progress(i, len(queries))
    return out, note


def format_record(r: CymruRecord) -> str:
    """Details text for one record."""
    w = 16
    lines = [f"# {r.query}  (Team Cymru IP to ASN mapping, via {r.source or 'whois'})"]
    if r.error:
        lines.append(f"{'Error':<{w}}{r.error}")
        return "\n".join(lines)
    if r.kind == "ip":
        lines.append(f"{'Origin AS':<{w}}{r.origin or '(not announced)'}")
        lines.append(f"{'BGP prefix':<{w}}{r.prefix or '–'}")
    else:
        lines.append(f"{'AS number':<{w}}AS{r.asn}")
    if r.as_name:
        lines.append(f"{'AS name':<{w}}{r.as_name}")
    if r.cc:
        lines.append(f"{'Country':<{w}}{r.cc}")
    if r.registry:
        lines.append(f"{'Registry':<{w}}{r.registry_name}")
    if r.allocated:
        lines.append(f"{'Allocated':<{w}}{r.allocated}")
    if r.note:
        lines.append(f"{'Note':<{w}}{r.note}")
    lines += ["", "# Country, registry and allocation date describe the registry allocation that covers",
              "# the prefix; the AS name is the origin network's registered name."]
    return "\n".join(lines)
