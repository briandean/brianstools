"""IRR / RPKI: expand an ASN or AS-SET from an IRR server (the same IRRd queries bgpq4 uses), check every
route object against RPKI (RFC 6811 origin validation using a VRP export), and write router prefix filters
for IOS-XR, IOS-XE, NX-OS, Junos and Arista EOS. Standard library only.

IRRd query protocol (port 43, as used by bgpq3/bgpq4):
    !!                      keep the connection open for more queries
    !nNAME                  identify the client
    !sRADB,RIPE,...         sources to search (blank = the server's default list)
    !iAS-SET,1              members of an as-set / route-set, expanded recursively
    !gAS65000               IPv4 route objects with origin AS65000
    !6AS65000               IPv6 route6 objects with origin AS65000
Replies: "A<bytes>\\n<data>\\nC\\n" (data), "C\\n" (nothing), "D\\n" (key not found), "F <text>\\n" (error).
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

IRR_SERVERS = ["whois.radb.net", "rr.ntt.net", "rr.arin.net"]
DEFAULT_SERVER = "whois.radb.net"
SOURCE_HINT = "RPKI,RIPE,ARIN,APNIC,AFRINIC,LACNIC,RADB"

VRP_SOURCES = {
    "Cloudflare (rpki.cloudflare.com)": "https://rpki.cloudflare.com/rpki.json",
    "rpki-client console (console.rpki-client.org)": "https://console.rpki-client.org/vrps.json",
}
DEFAULT_VRP_URL = "https://rpki.cloudflare.com/rpki.json"
VRP_MAX_AGE = 6 * 3600                      # refresh the cached VRP file after this many seconds

_ASN = re.compile(r"^(?:AS)?(\d{1,10})$", re.I)
_SET = re.compile(r"^(?:AS\d+:)?(?:AS|RS)-[\w.:-]+$|^AS\d+:(?:AS|RS)-[\w.:-]+(?::[\w.-]+)*$", re.I)


def _user_agent() -> str:
    try:
        from version import USER_AGENT
        return USER_AGENT
    except ImportError:
        return "BriansTools (+https://brianstools.net)"


class IrrError(Exception):
    pass


class Cancelled(IrrError):
    pass


# --------------------------------------------------------------------------- query parsing


def parse_queries(text: str) -> Tuple[List[str], List[str]]:
    """'AS65000, AS-FOO 64500 192.0.2.0/24 2001:db8::1' ->
    (['AS65000', 'AS-FOO', 'AS64500', '192.0.2.0/24', '2001:db8::1/128'], bad tokens).
    A single address becomes a host prefix (its covering route objects are looked up)."""
    good, bad = [], []
    for tok in re.split(r"[\s,;]+", text.strip()):
        if not tok:
            continue
        m = _ASN.match(tok)
        if m and int(m.group(1)) < 2 ** 32:
            q = f"AS{int(m.group(1))}"
        elif _SET.match(tok):
            q = tok.upper()
        elif ("." in tok or ":" in tok) and _prefix_or_none(tok):
            q = _prefix_or_none(tok)
        else:
            bad.append(tok)
            continue
        if q not in good:
            good.append(q)
    return good, bad


def _prefix_or_none(tok: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_network(tok.split("%")[0], strict=False))
    except ValueError:
        return None


def is_prefix(q: str) -> bool:
    return "/" in q and _prefix_or_none(q) is not None


def is_set(name: str) -> bool:
    return not _ASN.match(name) and not is_prefix(name)


PREFIX_MATCHES = {"Exact and covering (less specific)": ("", ",L"),
                  "Exact and more specific": ("", ",M"),
                  "Exact only": ("",)}


def parse_rpsl(text: str) -> List[Dict[str, str]]:
    """RPSL objects (blank-line separated) -> [{attribute: value, ...}] (first value of each attribute;
    descr lines joined)."""
    objs = []
    for block in re.split(r"\n\s*\n", text.strip()):
        obj: Dict[str, str] = {}
        last = None
        for line in block.splitlines():
            if not line.strip() or line.startswith(("%", "#")):
                continue
            if line[:1] in " \t+" and last:                 # continuation line
                obj[last] += " " + line.strip(" \t+")
                continue
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            last = k
            if k == "descr" and k in obj:
                obj[k] += " / " + v
            elif k not in obj:
                obj[k] = v
        if obj:
            objs.append(obj)
    return objs


def default_name(queries: Sequence[str]) -> str:
    """A filter name from the first query: AS-EXAMPLE, AS65000 ... (only letters, digits, - and _)."""
    base = queries[0] if queries else "IRR-FILTER"
    return re.sub(r"[^A-Za-z0-9_-]+", "_", base).strip("_") or "IRR-FILTER"


# --------------------------------------------------------------------------- IRRd client


class IrrClient:
    """A persistent IRRd connection (whois.radb.net, rr.ntt.net, or your own IRRd)."""

    def __init__(self, server: str = DEFAULT_SERVER, port: int = 43, sources: str = "", timeout: float = 30.0,
                 stop: Optional[threading.Event] = None):
        self.server, self.port, self.timeout, self.stop = server, port, timeout, stop
        try:
            self.sock = socket.create_connection((server, port), timeout=timeout)
        except OSError as exc:
            raise IrrError(f"Couldn't connect to {server}:{port} ({exc})") from None
        self.buf = b""
        self._send("!!\n")
        self._send("!nBriansTools\n")
        self._reply()
        if sources.strip():
            src = ",".join(s.strip().upper() for s in re.split(r"[\s,]+", sources) if s.strip())
            self._send(f"!s{src}\n")
            code, data = self._reply()
            if code == "F":
                raise IrrError(f"{server} rejected the sources {src}: {data}")

    def close(self):
        try:
            self.sock.sendall(b"q\n")
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _send(self, text: str):
        try:
            self.sock.sendall(text.encode())
        except OSError as exc:
            raise IrrError(f"Lost the connection to {self.server} ({exc})") from None

    def _fill(self):
        if self.stop is not None and self.stop.is_set():
            raise Cancelled("Stopped.")
        try:
            chunk = self.sock.recv(65536)
        except socket.timeout:
            raise IrrError(f"{self.server} stopped answering (timed out)") from None
        except OSError as exc:
            raise IrrError(f"Lost the connection to {self.server} ({exc})") from None
        if not chunk:
            raise IrrError(f"{self.server} closed the connection")
        self.buf += chunk

    def _line(self) -> str:
        while b"\n" not in self.buf:
            self._fill()
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode("utf-8", "replace").rstrip("\r")

    def _reply(self) -> Tuple[str, str]:
        """('A', data) / ('C', '') / ('D', '') / ('F', message)."""
        while True:
            line = self._line()
            if line:
                break
        if line.startswith("A"):
            try:
                n = int(line[1:])
            except ValueError:
                raise IrrError(f"Unexpected reply from {self.server}: {line[:80]}") from None
            while len(self.buf) < n:
                self._fill()
            data, self.buf = self.buf[:n], self.buf[n:]
            end = self._line()
            while not end:
                end = self._line()
            return "A", data.decode("utf-8", "replace").strip()
        if line[0] in "CD":
            return line[0], ""
        if line.startswith("F"):
            return "F", line[1:].strip()
        raise IrrError(f"Unexpected reply from {self.server}: {line[:80]}")

    def query(self, q: str) -> Tuple[str, str]:
        self._send(q + "\n")
        return self._reply()

    def many(self, queries: List[str], batch: int = 50) -> List[Tuple[str, str]]:
        """Pipeline queries (send a batch, read the replies in order), like bgpq4 does."""
        out = []
        for i in range(0, len(queries), batch):
            part = queries[i:i + batch]
            self._send("".join(q + "\n" for q in part))
            out += [self._reply() for _ in part]
        return out

    def route_objects(self, prefix: str, option: str = "") -> List[Dict[str, str]]:
        """route / route6 objects for a prefix: '' exact, ',L' all less specific (covering), ',M' more specific."""
        code, data = self.query(f"!r{prefix}{option}")
        if code == "F":
            raise IrrError(f"{self.server} couldn't look up {prefix}: {data}")
        return parse_rpsl(data) if code == "A" else []

    def expand_set(self, name: str) -> List[str]:
        code, data = self.query(f"!i{name},1")
        if code == "D":
            raise IrrError(f"{name} wasn't found in the IRR")
        if code == "F":
            raise IrrError(f"{self.server} couldn't expand {name}: {data}")
        return data.split() if code == "A" else []


# --------------------------------------------------------------------------- results


@dataclass
class Route:
    prefix: str                 # canonical, e.g. 192.0.2.0/24
    origin: str                 # AS65000 ("" for route-set members)
    version: int
    rpki: str = ""              # Valid / Invalid / Not found / (blank = not checked)
    rpki_detail: str = ""
    excluded: str = ""          # why it's left out of the filter ("" = included)
    in_filter: str = ""         # how it ended up in the generated filter (see mark_in_filter)
    leaks: bool = False         # left out, yet a wider entry's le range still matches it
    source: str = ""            # IRR database(s) the object is in (prefix lookups)
    descr: str = ""
    found: str = ""             # how a prefix lookup found it: exact / covering / more specific
    kinds: List[str] = field(default_factory=lambda: ["IRR"])   # IRR / ROA / BGP / ARIN: where it was seen

    @property
    def where(self) -> str:
        """'IRR (RADB, ARIN), ROA, BGP' for the Source column."""
        return ", ".join(f"IRR ({self.source})" if k == "IRR" and self.source else k for k in self.kinds)

    @property
    def in_irr(self) -> bool:
        return "IRR" in self.kinds

    @property
    def net(self):
        return ipaddress.ip_network(self.prefix)


@dataclass
class Expansion:
    queries: List[str]
    asns: List[str] = field(default_factory=list)
    routes: List[Route] = field(default_factory=list)
    per_asn: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    server: str = ""
    sources: str = ""
    members: List[str] = field(default_factory=list)    # ASNs from the ASN / AS-SET queries (not prefix lookups)


def expand(queries: Sequence[str], server: str = DEFAULT_SERVER, sources: str = "", ipv4: bool = True,
           ipv6: bool = True, port: int = 43, timeout: float = 30.0, stop: Optional[threading.Event] = None,
           progress: Optional[Callable[[str], None]] = None, client_factory=IrrClient,
           prefix_match: str = "Exact and covering (less specific)") -> Expansion:
    """Expand ASNs / AS-SETs / route-sets into route objects (origin kept for RPKI checks), and look up
    the route objects registered for prefixes / addresses."""
    res = Expansion(list(queries), server=server, sources=sources)
    say = progress or (lambda m: None)
    with client_factory(server, port, sources, timeout, stop) as c:
        asns: List[str] = []
        loose: List[Tuple[str, str]] = []           # prefixes from route-sets (no origin)
        by_key: Dict[Tuple[str, str], Route] = {}
        for q in queries:
            if is_prefix(q):
                qnet = ipaddress.ip_network(q)
                if (qnet.version == 4 and not ipv4) or (qnet.version == 6 and not ipv6):
                    res.warnings.append(f"{q}: IPv{qnet.version} isn't ticked")
                    continue
                say(f"Looking up route objects for {q} …")
                hits = 0
                for opt in PREFIX_MATCHES.get(prefix_match, ("", ",L")):
                    try:
                        objs = c.route_objects(q, opt)
                    except Cancelled:
                        raise
                    except IrrError as exc:
                        res.warnings.append(str(exc))
                        continue
                    for o in objs:
                        pfx = o.get("route") or o.get("route6")
                        origin_m = _ASN.match(o.get("origin", "").strip())
                        if not pfx or not origin_m:
                            continue
                        try:
                            net = ipaddress.ip_network(pfx, strict=False)
                        except ValueError:
                            continue
                        origin = f"AS{int(origin_m.group(1))}"
                        how = ("exact" if net == qnet else "covering" if qnet.subnet_of(net)
                               else "more specific" if net.subnet_of(qnet) else "")
                        key = (str(net), origin)
                        r = by_key.get(key)
                        if r is None:
                            r = Route(str(net), origin, net.version, descr=o.get("descr", ""),
                                      source=o.get("source", "").upper(), found=f"{how} {q}".strip())
                            by_key[key] = r
                            res.routes.append(r)
                            hits += 1
                        else:
                            src = o.get("source", "").upper()
                            if src and src not in r.source.split(", "):
                                r.source = ", ".join(x for x in (r.source, src) if x)
                        if origin not in res.per_asn:
                            res.per_asn[origin] = (0, 0)
                if not hits:
                    res.warnings.append(f"No route objects found for {q}")
                continue
            if not is_set(q):
                if q not in asns:
                    asns.append(q)
                continue
            say(f"Expanding {q} …")
            try:
                members = c.expand_set(q)
            except Cancelled:
                raise
            except IrrError as exc:
                res.warnings.append(str(exc))
                continue
            for m in members:
                if _ASN.match(m):
                    a = f"AS{int(_ASN.match(m).group(1))}"
                    if a not in asns:
                        asns.append(a)
                else:
                    try:
                        loose.append((str(ipaddress.ip_network(m.split("^")[0], strict=False)), q))
                    except ValueError:
                        pass
        res.asns = asns
        res.members = list(asns)
        seen = set(by_key)
        cmds = []
        for a in asns:
            if ipv4:
                cmds.append((a, 4, f"!g{a}"))
            if ipv6:
                cmds.append((a, 6, f"!6{a}"))
        done = 0
        for i in range(0, len(cmds), 100):
            part = cmds[i:i + 100]
            say(f"Getting route objects: {done:,} of {len(cmds):,} queries …")
            replies = c.many([q for _, _, q in part])
            for (a, ver, _), (code, data) in zip(part, replies):
                if code == "F":
                    res.warnings.append(f"{a}: {data}")
                    continue
                n = 0
                for p in data.split() if code == "A" else []:
                    try:
                        net = ipaddress.ip_network(p, strict=False)
                    except ValueError:
                        continue
                    key = (str(net), a)
                    if key in seen:
                        continue
                    seen.add(key)
                    res.routes.append(Route(str(net), a, net.version))
                    n += 1
                v4, v6 = res.per_asn.get(a, (0, 0))
                res.per_asn[a] = (v4 + n, v6) if ver == 4 else (v4, v6 + n)
            done += len(part)
        for p, q in loose:
            net = ipaddress.ip_network(p)
            if (ipv4 and net.version == 4) or (ipv6 and net.version == 6):
                if (p, "") not in seen:
                    seen.add((p, ""))
                    res.routes.append(Route(p, "", net.version))
    finish_expansion(res)
    return res


# --------------------------------------------------------------------------- RPKI (RFC 6811)

_VRP_PREFIX = re.compile(r'"prefix"\s*:\s*"([^"]+)"')
_VRP_ASN = re.compile(r'"asn"\s*:\s*"?(?:AS)?(\d+)"?', re.I)
_VRP_MAXLEN = re.compile(r'"max(?:_?[lL]ength)"\s*:\s*(\d+)')


def _supernets(net) -> List[str]:
    return [str(net.supernet(new_prefix=n)) for n in range(0, net.prefixlen + 1)]


def vrps_covering(vrp_text: str, prefixes: Iterable[str]) -> Dict[str, List[Tuple[int, int]]]:
    """From a VRP JSON export (Cloudflare / rpki-client / Routinator / StayRTR format), the VRPs whose prefix
    covers any of `prefixes`: {vrp prefix: [(asn, maxLength), ...]}. One regex pass, no full JSON load."""
    wanted = set()
    for p in prefixes:
        wanted.update(_supernets(ipaddress.ip_network(p)))
    found: Dict[str, List[Tuple[int, int]]] = {}
    for m in _VRP_PREFIX.finditer(vrp_text):
        pfx = m.group(1).strip().lower()           # exports use canonical text, as ipaddress does
        if pfx not in wanted:
            continue
        start = vrp_text.rfind("{", 0, m.start())
        end = vrp_text.find("}", m.end())
        obj = vrp_text[start:end + 1]
        a, ml = _VRP_ASN.search(obj), _VRP_MAXLEN.search(obj)
        if not a:
            continue
        maxlen = int(ml.group(1)) if ml else int(pfx.split("/")[1])
        found.setdefault(pfx, [])
        if (int(a.group(1)), maxlen) not in found[pfx]:
            found[pfx].append((int(a.group(1)), maxlen))
    return found


def validate(prefix: str, origin: str, vrps: Dict[str, List[Tuple[int, int]]]) -> Tuple[str, str]:
    """RFC 6811 origin validation -> (state, detail)."""
    net = ipaddress.ip_network(prefix)
    covering = []
    for sup in _supernets(net):
        for asn, maxlen in vrps.get(sup, ()):
            covering.append((sup, asn, maxlen))
    if not covering:
        return "Not found", "No ROA covers this prefix"
    m = _ASN.match(origin or "")
    if not m:
        return "", "No origin AS (route-set member)"
    asn = int(m.group(1))
    for sup, a, maxlen in covering:
        if a == asn and a != 0 and net.prefixlen <= maxlen:
            return "Valid", f"ROA {sup} max /{maxlen} AS{a}"
    same = [(sup, a, maxlen) for sup, a, maxlen in covering if a == asn and a != 0]
    if same:
        sup, a, maxlen = max(same, key=lambda x: x[2])
        return "Invalid", f"Too specific: ROA {sup} allows up to /{maxlen} for AS{a}"
    others = sorted({f"AS{a}" for _, a, _ in covering})
    return "Invalid", f"Wrong origin: ROAs allow {', '.join(others[:4])}{' …' if len(others) > 4 else ''}"


def roas_for_asns(vrp_text: str, asns: Iterable[str]) -> List[Tuple[str, int, str]]:
    """Every VRP (ROA payload) whose origin is one of `asns`: [(prefix, maxLength, 'AS65000')]."""
    want = {int(_ASN.match(a).group(1)) for a in asns if _ASN.match(a)}
    want.discard(0)
    out, seen = [], set()
    for m in _VRP_ASN.finditer(vrp_text):
        asn = int(m.group(1))
        if asn not in want:
            continue
        start = vrp_text.rfind("{", 0, m.start())
        end = vrp_text.find("}", m.end())
        obj = vrp_text[start:end + 1]
        p, ml = _VRP_PREFIX.search(obj), _VRP_MAXLEN.search(obj)
        if not p:
            continue
        try:
            net = ipaddress.ip_network(p.group(1).strip(), strict=False)
        except ValueError:
            continue
        maxlen = int(ml.group(1)) if ml else net.prefixlen
        key = (str(net), maxlen, asn)
        if key not in seen:
            seen.add(key)
            out.append((str(net), maxlen, f"AS{asn}"))
    return out


def merge_route(res: "Expansion", prefix: str, origin: str, kind: str, found: str = "", descr: str = "",
                ipv4: bool = True, ipv6: bool = True) -> Optional[Route]:
    """Add a prefix seen somewhere other than the IRR (ROA / BGP / ARIN), or tag an existing row with it."""
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None
    if (net.version == 4 and not ipv4) or (net.version == 6 and not ipv6):
        return None
    key = (str(net), origin)
    index = getattr(res, "_index", None)
    if index is None:
        index = res._index = {(r.prefix, r.origin): r for r in res.routes}
    r = index.get(key)
    if r is None:
        r = Route(str(net), origin, net.version, found=found, descr=descr, kinds=[kind])
        res.routes.append(r)
        index[key] = r
    elif kind not in r.kinds:
        r.kinds.append(kind)
        if descr and not r.descr:
            r.descr = descr
    return r


def finish_expansion(res: "Expansion"):
    """Recount routes per origin and sort (after merging other sources)."""
    counts: Dict[str, List[int]] = {a: [0, 0] for a in res.asns}
    for r in res.routes:
        if r.origin:
            counts.setdefault(r.origin, [0, 0])[0 if r.version == 4 else 1] += 1
    res.asns = list(counts)
    res.per_asn = {a: (c[0], c[1]) for a, c in counts.items()}
    res.routes.sort(key=lambda r: (r.version, r.net.network_address, r.net.prefixlen, r.origin))


def check_rpki(routes: List[Route], vrp_text: str):
    vrps = vrps_covering(vrp_text, [r.prefix for r in routes])
    for r in routes:
        r.rpki, r.rpki_detail = validate(r.prefix, r.origin, vrps)


def vrp_summary(vrp_text: str) -> int:
    return len(_VRP_PREFIX.findall(vrp_text))


def download_vrps(dest: Path, url: str = DEFAULT_VRP_URL, progress: Optional[Callable[[int, int], None]] = None,
                  stop: Optional[threading.Event] = None, timeout: float = 60.0) -> int:
    """Download a VRP JSON export to `dest` (replaced only when complete and sane). Returns the VRP count."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".download")
    req = urllib.request.Request(url, headers={"User-Agent": _user_agent(), "Accept": "application/json"})

    def opener(verify: bool):
        if not url.startswith("https://"):
            return urllib.request.urlopen(req, timeout=timeout)
        if verify:
            try:
                from arinwhois import trusted_context
                ctx = trusted_context()
            except ImportError:
                ctx = ssl.create_default_context()
        else:
            ctx = ssl._create_unverified_context()
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)

    try:
        try:
            resp = opener(True)
        except urllib.error.URLError as exc:
            if isinstance(exc, urllib.error.HTTPError) or not isinstance(exc.reason, ssl.SSLError):
                raise
            resp = opener(False)
        with resp, open(part, "wb") as fh:
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            while True:
                if stop is not None and stop.is_set():
                    raise Cancelled("Download cancelled.")
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
        text = part.read_text(encoding="utf-8", errors="replace")
        n = vrp_summary(text)
        if n < 1:
            raise IrrError("That URL didn't return a VRP list (no \"prefix\" entries found).")
        os.replace(part, dest)
        return n
    except urllib.error.HTTPError as exc:
        raise IrrError(f"{url} returned HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        raise IrrError(f"Couldn't reach {url} ({exc.reason})") from None
    except OSError as exc:
        raise IrrError(f"Download failed: {exc}") from None
    finally:
        try:
            part.unlink()
        except OSError:
            pass


# --------------------------------------------------------------------------- building the filter


def apply_filters(routes: Iterable[Route], leave_out_invalid: bool = True, max4: Optional[int] = 24,
                  max6: Optional[int] = 48, require_irr: bool = False):
    """Mark routes that won't go in the filter (and why)."""
    for r in routes:
        limit = max4 if r.version == 4 else max6
        if leave_out_invalid and r.rpki == "Invalid":
            r.excluded = "RPKI invalid"
        elif require_irr and not r.in_irr:
            r.excluded = "No IRR route object"
        elif limit is not None and r.net.prefixlen > limit:
            r.excluded = f"Longer than /{limit}"
        else:
            r.excluded = ""


@dataclass
class Entry:
    net: object                 # ipaddress network
    le: Optional[int] = None    # allow more-specifics up to this length (None = exact)

    @property
    def prefix(self) -> str:
        return str(self.net)


def build_entries(routes: Iterable[Route], version: int, max_len: Optional[int] = None,
                  more_specifics: Optional[int] = None) -> List[Entry]:
    """Filter entries for one address family from the included routes.
    max_len: leave out prefixes longer than this. more_specifics: add 'le N' and drop prefixes already
    covered by a shorter entry's range (bgpq4 -R style)."""
    nets = sorted({r.net for r in routes if r.version == version and not r.excluded},
                  key=lambda n: (n.network_address, n.prefixlen))
    if max_len is not None:
        nets = [n for n in nets if n.prefixlen <= max_len]
    if not more_specifics:
        return [Entry(n) for n in nets]
    out: List[Entry] = []
    for n in sorted(nets, key=lambda n: (n.prefixlen, n.network_address)):
        le = more_specifics if n.prefixlen < more_specifics else None
        if any(e.le and n.subnet_of(e.net) and n.prefixlen <= e.le for e in out if e.net.version == n.version):
            continue                               # already allowed by a shorter entry's range
        out.append(Entry(n, le))
    out.sort(key=lambda e: (e.net.network_address, e.net.prefixlen))
    return out


def mark_in_filter(routes: Iterable[Route], entries: Iterable[Entry]):
    """Set each route's in_filter text from the entries actually generated: its own entry (exact or with
    a range), inside a wider entry's range, or left out and why."""
    by_prefix = {e.prefix: e for e in entries}
    ranged = sorted((e for e in by_prefix.values() if e.le), key=lambda c: c.net.prefixlen)

    def covering(net):
        return next((c for c in ranged if c.net.version == net.version and net != c.net
                     and net.subnet_of(c.net) and net.prefixlen <= c.le), None)

    for r in routes:
        r.leaks = False
        if r.excluded:
            cover = covering(r.net)
            if cover:                          # left out, but a wider entry's le range still accepts it
                r.leaks = True
                r.in_filter = f"No – {r.excluded}, but {cover.prefix} le {cover.le} still matches it"
            else:
                r.in_filter = f"No – {r.excluded}"
            continue
        e = by_prefix.get(r.prefix)
        if e is not None:
            r.in_filter = f"Yes – {e.prefix} le {e.le}" if e.le else "Yes – exact"
            continue
        cover = covering(r.net)
        r.in_filter = f"Yes – inside {cover.prefix} le {cover.le}" if cover else "No – not in the filter"


FORMATS = ["Cisco IOS-XR (prefix-set)", "Cisco IOS-XE (prefix-list)", "Cisco NX-OS (prefix-list)",
           "Juniper Junos (set commands)", "Arista EOS (prefix-list)", "Nokia SR OS (MD-CLI)",
           "Nokia SR OS (classic CLI)", "Nokia SR Linux (prefix-set)", "Plain list"]


def render(fmt: str, name: str, v4: List[Entry], v6: List[Entry], header: Sequence[str] = (),
           both: Tuple[bool, bool] = (True, True)) -> str:
    """Router config for the chosen platform. IPv4 goes in NAME-V4, IPv6 in NAME-V6."""
    name = re.sub(r"[^A-Za-z0-9_-]+", "_", name).strip("_") or "IRR-FILTER"
    fams = [(4, f"{name}-V4", v4), (6, f"{name}-V6", v6)]
    fams = [f for f, want in zip(fams, both) if want]
    key = fmt.split(" ")[1] if fmt.startswith(("Cisco", "Juniper", "Arista")) else "Plain"
    if fmt.startswith("Arista"):
        key = "EOS"
    elif fmt.startswith("Nokia SR OS (MD"):
        key = "MD-CLI"
    elif fmt.startswith("Nokia SR OS"):
        key = "SROS-classic"
    elif fmt.startswith("Nokia SR Linux"):
        key = "SRL"
    comment = {"IOS-XR": "#", "IOS-XE": "!", "NX-OS": "!", "Junos": "#", "EOS": "!", "Plain": "#",
               "MD-CLI": "#", "SROS-classic": "#", "SRL": "#"}[key]
    lines = [f"{comment} {h}" if h else comment for h in header]
    if key == "MD-CLI":
        lines.append("/configure policy-options")
    elif key == "SROS-classic":
        lines += ["/configure router policy-options", "begin"]

    def rng(e: Entry, junos=False):
        if e.le is None:
            return "exact" if junos else ""
        return f"upto /{e.le}" if junos else f"le {e.le}"

    for ver, lname, entries in fams:
        if key == "IOS-XR":
            lines.append(f"prefix-set {lname}")
            body = [f"  {e.prefix}" + (f" {rng(e)}" if e.le else "") for e in entries]
            lines += [b + ("," if i < len(body) - 1 else "") for i, b in enumerate(body)]
            lines.append("end-set")
            lines.append("!")
        elif key in ("IOS-XE", "NX-OS"):
            kw = "ip" if ver == 4 else "ipv6"
            lines.append(f"no {kw} prefix-list {lname}")
            if not entries:
                lines.append(f"{kw} prefix-list {lname} seq 5 deny {'0.0.0.0/0' if ver == 4 else '::/0'}")
            for i, e in enumerate(entries, 1):
                lines.append(f"{kw} prefix-list {lname} seq {i * 5} permit {e.prefix}" + (f" {rng(e)}" if e.le else ""))
            lines.append("!")
        elif key == "EOS":
            kw = "ip" if ver == 4 else "ipv6"
            lines.append(f"no {kw} prefix-list {lname}")
            lines.append(f"{kw} prefix-list {lname}")
            if not entries:
                lines.append(f"   seq 10 deny {'0.0.0.0/0' if ver == 4 else '::/0'}")
            for i, e in enumerate(entries, 1):
                lines.append(f"   seq {i * 10} permit {e.prefix}" + (f" {rng(e)}" if e.le else ""))
            lines.append("!")
        elif key == "Junos":
            ranged = any(e.le for e in entries)
            if ranged:                                   # prefix-lists can't do ranges; route-filter-lists can
                lines.append(f"delete policy-options route-filter-list {lname}")
                for e in entries:
                    lines.append(f"set policy-options route-filter-list {lname} {e.prefix} {rng(e, junos=True)}")
            else:
                lines.append(f"delete policy-options prefix-list {lname}")
                for e in entries:
                    lines.append(f"set policy-options prefix-list {lname} {e.prefix}")
                if not entries:
                    lines.append(f"set policy-options prefix-list {lname}")   # empty list matches nothing
        elif key == "MD-CLI":                            # SR OS model-driven CLI
            lines.append(f'delete prefix-list "{lname}"')
            lines.append(f'prefix-list "{lname}" {{')
            for e in entries:
                if e.le:
                    lines += [f"    prefix {e.prefix} type through {{", f"        through-length {e.le}", "    }"]
                else:
                    lines += [f"    prefix {e.prefix} type exact {{", "    }"]
            lines.append("}")
        elif key == "SROS-classic":                      # SR OS classic CLI
            lines.append(f'no prefix-list "{lname}"')
            lines.append(f'prefix-list "{lname}"')
            for e in entries:
                lines.append(f"    prefix {e.prefix} " + (f"through {e.le}" if e.le else "exact"))
            lines.append("exit")
        elif key == "SRL":                               # SR Linux
            lines.append(f"delete / routing-policy prefix-set {lname}")
            if not entries:
                lines.append(f"set / routing-policy prefix-set {lname}")
            for e in entries:
                rng_ = f"{e.net.prefixlen}..{e.le}" if e.le else "exact"
                lines.append(f"set / routing-policy prefix-set {lname} prefix {e.prefix} mask-length-range {rng_}")
        else:
            lines += [e.prefix + (f" {rng(e)}" if e.le else "") for e in entries]
    if key == "SROS-classic":
        lines.append("commit")
    elif key == "MD-CLI":
        lines.append("# then: commit (from edit-config private / exclusive)")
    elif key == "SRL":
        lines.append("# then: commit now (from enter candidate)")
    return "\n".join(lines).rstrip("!\n") + "\n"
