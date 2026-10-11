"""ARIN Whois-RWS client (https://www.arin.net/resources/registry/whois/rws/api/).

Standard library only. Uses the documented REST resources with a ``.json`` suffix:
  /rest/ip/{ip}   /rest/cidr/{prefix}/{len}   /rest/asn/{ASn}   /rest/net/{handle}
  /rest/org/{handle}   /rest/org/{handle}/pocs   /rest/customer/{handle}   /rest/poc/{handle}

ARIN's JSON follows the "BadgerFish" convention: element text is under "$", XML attributes
are keys starting with "@", and a repeated element is a list – but a single one is a plain
object. The helpers below accept either shape everywhere.

Use of ARIN Whois data is subject to ARIN's Whois Terms of Use.
"""
from __future__ import annotations

import ipaddress
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

BASE_URL = "https://whois.arin.net/rest"
RDAP_URL = "https://rdap.arin.net/registry"      # redirects to the right RIR (RDAP bootstrap)
RIR_RDAP = {"RIPE": "https://rdap.db.ripe.net", "APNIC": "https://rdap.apnic.net",
            "LACNIC": "https://rdap.lacnic.net/rdap", "AFRINIC": "https://rdap.afrinic.net/rdap"}
WEB_URL = "https://search.arin.net/rdap/?query={query}"
TOU_URL = "https://www.arin.net/resources/registry/whois/tou/"
try:
    from version import USER_AGENT
except ImportError:                                   # (used on its own)
    USER_AGENT = "BriansTools (+https://brianstools.net)"
OTHER_RIRS = {
    "RIPE": ("RIPE NCC (Europe, Middle East, Central Asia)", "https://apps.db.ripe.net/db-web-ui/query?searchtext={q}"),
    "APNIC": ("APNIC (Asia Pacific)", "https://wq.apnic.net/static/search.html?query={q}"),
    "LACNIC": ("LACNIC (Latin America & Caribbean)", "https://query.milacnic.lacnic.net/search?id={q}"),
    "AFRINIC": ("AFRINIC (Africa)", "https://afrinic.net/whois?searchtext={q}"),
}
POC_FUNCTIONS = {"AB": "Abuse", "AD": "Admin", "N": "NOC", "T": "Tech", "R": "Routing", "DNS": "DNS"}


class WhoisError(Exception):
    pass


# --------------------------------------------------------------------------- BadgerFish helpers


def as_list(node) -> list:
    if node is None:
        return []
    return node if isinstance(node, list) else [node]


def text(node, default: str = "") -> str:
    """Text content of an element: {"$": "x"} -> "x"; lists are joined; plain strings pass through."""
    if node is None:
        return default
    if isinstance(node, list):
        return ", ".join(t for t in (text(n) for n in node) if t)
    if isinstance(node, dict):
        v = node.get("$")
        return default if v is None else str(v)
    return str(node)


def child(node, name: str):
    """node[name], also matching namespaced keys like 'ns4:net'."""
    if not isinstance(node, dict):
        return None
    if name in node:
        return node[name]
    for k, v in node.items():
        if k.split(":")[-1] == name:
            return v
    return None


def lines(node) -> List[str]:
    """Multi-line fields (comment, streetAddress) come as {"line": [{"@number": "0", "$": "…"}]}."""
    items = as_list(child(node, "line")) if isinstance(node, dict) else as_list(node)
    items = sorted(items, key=lambda x: int(x.get("@number", 0)) if isinstance(x, dict) and
                   str(x.get("@number", "0")).isdigit() else 0)
    return [text(i) for i in items if text(i)]


def ref(node) -> Tuple[str, str]:
    """orgRef / parentNetRef / customerRef -> (handle, name)."""
    if not isinstance(node, dict):
        return "", ""
    return node.get("@handle", ""), node.get("@name", "")


def date(node) -> str:
    return text(node)[:10]


# --------------------------------------------------------------------------- HTTP


_ssl_fallback_used = False


# --------------------------------------------------------------------------- TLS trust

MAC_KEYCHAINS = ("/System/Library/Keychains/SystemRootCertificates.keychain",   # Apple's built-in roots
                 "/Library/Keychains/System.keychain")                          # admin / MDM-installed roots
_PEM = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)
_trust = {}


def keychain_pems(run=None, keychains=MAC_KEYCHAINS) -> List[str]:
    """Root certificates from the macOS Keychain, as PEM blocks (via the built-in `security` tool)."""
    import subprocess
    run = run or subprocess.run
    pems: List[str] = []
    for kc in keychains:
        try:
            out = run(["/usr/bin/security", "find-certificate", "-a", "-p", kc],
                      capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError, ValueError):
            continue
        for pem in _PEM.findall(out or ""):
            if pem not in pems:
                pems.append(pem)
    return pems


def add_pems(ctx: ssl.SSLContext, pems: List[str]) -> int:
    """Load PEM certificates one at a time (a single odd one mustn't spoil the rest)."""
    added = 0
    for pem in pems:
        try:
            ctx.load_verify_locations(cadata=pem)
            added += 1
        except (ssl.SSLError, ValueError):
            pass
    return added


def trusted_context() -> ssl.SSLContext:
    """A verifying SSL context that trusts this computer's own certificate store:
    Windows certificate store and Linux /etc/ssl (Python does this itself), plus the macOS Keychain,
    which Python's OpenSSL never reads on its own. Built once per run."""
    if "ctx" in _trust:
        return _trust["ctx"]
    ctx = ssl.create_default_context()
    source = "system store"
    if sys.platform == "darwin":
        n = add_pems(ctx, keychain_pems())
        if n:
            source = f"macOS Keychain ({n} roots)"
    if not ctx.cert_store_stats().get("x509_ca"):
        try:                                   # last resort: certifi, if it happens to be installed
            import certifi  # type: ignore
            ctx.load_verify_locations(certifi.where())
            source = "certifi"
        except (ImportError, OSError, ssl.SSLError):
            source = "none"
    _trust.update(ctx=ctx, source=source)
    return ctx


def trust_source() -> str:
    trusted_context()
    return _trust["source"]


def fetch_url(url: str, accept: str = "application/json", timeout: float = 15.0,
              cache: Optional[dict] = None, source: str = "ARIN") -> dict:
    """GET a JSON document. Raises WhoisError (with a 'not_found' flag for 404s)."""
    global _ssl_fallback_used
    if cache is not None and url in cache:
        return cache[url]
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": USER_AGENT})
    try:
        try:
            ctx = trusted_context() if url.startswith("https://") else None
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.URLError as exc:
            # Verified HTTPS failed even with the local certificate store (e.g. no roots could be loaded, or
            # an intercepting proxy we don't trust). Whois/RDAP data is public: retry over HTTPS without
            # verifying, then plain HTTP, rather than failing outright.
            if (isinstance(exc, urllib.error.HTTPError) or not url.startswith("https://")
                    or not isinstance(getattr(exc, "reason", None), ssl.SSLError)):
                raise
            _ssl_fallback_used = True
            try:
                ctx = ssl._create_unverified_context()
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    data = json.loads(resp.read().decode("utf-8", "replace"))
            except urllib.error.HTTPError:
                raise
            except urllib.error.URLError:
                req = urllib.request.Request("http://" + url[len("https://"):], headers=req.headers)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        err = WhoisError("No record found" if exc.code == 404 else f"{source} returned HTTP {exc.code}")
        err.not_found = exc.code == 404
        raise err from None
    except urllib.error.URLError as exc:
        raise WhoisError(f"Couldn't reach {source} ({exc.reason})") from None
    except (OSError, ValueError) as exc:
        raise WhoisError(f"Couldn't read {source}'s reply: {exc}") from None
    if cache is not None:
        cache[url] = data
    return data


def fetch_json(path: str, base: str = BASE_URL, timeout: float = 15.0, cache: Optional[dict] = None) -> dict:
    """ARIN Whois-RWS: GET {base}/{path}.json"""
    return fetch_url(f"{base}/{path}.json", "application/json", timeout, cache)


def ssl_fallback_used() -> bool:
    return _ssl_fallback_used


# --------------------------------------------------------------------------- records


@dataclass
class NetBlock:
    start: str
    end: str
    cidr: str
    type_code: str
    type_name: str


@dataclass
class Net:
    handle: str = ""
    name: str = ""
    start: str = ""
    end: str = ""
    blocks: List[NetBlock] = field(default_factory=list)
    org_handle: str = ""
    org_name: str = ""
    customer_handle: str = ""
    customer_name: str = ""
    parent_handle: str = ""
    parent_name: str = ""
    origin_as: List[str] = field(default_factory=list)
    registered: str = ""
    updated: str = ""
    comments: List[str] = field(default_factory=list)
    version: str = ""

    @property
    def cidrs(self) -> str:
        return ", ".join(b.cidr for b in self.blocks) or (f"{self.start} - {self.end}" if self.start else "")

    @property
    def type_name(self) -> str:
        return ", ".join(sorted({b.type_name for b in self.blocks if b.type_name}))

    def contains(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
            return ipaddress.ip_address(self.start) <= a <= ipaddress.ip_address(self.end)
        except ValueError:
            return False


@dataclass
class Org:
    handle: str = ""
    name: str = ""
    street: List[str] = field(default_factory=list)
    city: str = ""
    state: str = ""
    postal: str = ""
    country: str = ""
    country_name: str = ""
    registered: str = ""
    updated: str = ""
    comments: List[str] = field(default_factory=list)
    is_customer: bool = False

    @property
    def address(self) -> str:
        parts = self.street + [" ".join(p for p in (self.city, self.state, self.postal) if p)]
        if self.country:
            parts.append(self.country)
        return ", ".join(p for p in parts if p)


@dataclass
class Poc:
    function: str = ""
    handle: str = ""
    name: str = ""
    emails: List[str] = field(default_factory=list)
    phones: List[str] = field(default_factory=list)


@dataclass
class Asn:
    handle: str = ""
    name: str = ""
    start: str = ""
    end: str = ""
    org_handle: str = ""
    org_name: str = ""
    registered: str = ""
    updated: str = ""
    comments: List[str] = field(default_factory=list)


@dataclass
class RdapInfo:
    """Owner details from another registry's RDAP service (RIPE, APNIC, LACNIC, AFRINIC)."""
    handle: str = ""
    name: str = ""                 # AS name or network name
    org: str = ""                  # registrant organisation
    org_handle: str = ""
    country: str = ""
    abuse_emails: List[str] = field(default_factory=list)
    remarks: List[str] = field(default_factory=list)
    start: str = ""
    end: str = ""
    cidrs: List[str] = field(default_factory=list)
    source: str = ""               # e.g. whois.ripe.net


def _vcard(entity: dict, prop: str) -> List[str]:
    out = []
    card = entity.get("vcardArray")
    if isinstance(card, list) and len(card) > 1 and isinstance(card[1], list):
        for item in card[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == prop:
                val = item[3]
                if isinstance(val, list):
                    val = " ".join(str(v) for v in val if v)
                if val:
                    out.append(str(val))
    return out


def _walk_entities(entities):
    for e in entities or []:
        if isinstance(e, dict):
            yield e
            yield from _walk_entities(e.get("entities"))


def parse_rdap(data: dict) -> RdapInfo:
    info = RdapInfo(handle=str(data.get("handle", "")), name=str(data.get("name", "")),
                    country=str(data.get("country", "")), source=str(data.get("port43", "")))
    if "startAutnum" in data:
        info.start, info.end = str(data.get("startAutnum", "")), str(data.get("endAutnum", ""))
    else:
        info.start, info.end = str(data.get("startAddress", "")), str(data.get("endAddress", ""))
    for c in data.get("cidr0_cidrs", []) or []:
        pfx = c.get("v4prefix") or c.get("v6prefix")
        if pfx:
            info.cidrs.append(f"{pfx}/{c.get('length')}")
    registrants = [e for e in _walk_entities(data.get("entities")) if "registrant" in (e.get("roles") or [])]
    best = next((e for e in registrants if "org" in _vcard(e, "kind")), None) \
        or next((e for e in registrants if str(e.get("handle", "")).upper().startswith("ORG-")), None) \
        or (registrants[0] if registrants else None)
    if best:
        info.org = (_vcard(best, "fn") or [""])[0]
        info.org_handle = str(best.get("handle", ""))
    for e in _walk_entities(data.get("entities")):
        if "abuse" in (e.get("roles") or []):
            for mail in _vcard(e, "email"):
                if mail not in info.abuse_emails:
                    info.abuse_emails.append(mail)
    for r in data.get("remarks", []) or []:
        for d in r.get("description", []) or []:
            if d and len(info.remarks) < 4:
                info.remarks.append(str(d))
    return info


@dataclass
class WhoisResult:
    query: str
    kind: str                         # ip / cidr / asn / net / org / poc
    net: Optional[Net] = None
    asn: Optional[Asn] = None
    org: Optional[Org] = None
    pocs: List[Poc] = field(default_factory=list)
    other_rir: str = ""               # e.g. "RIPE NCC (Europe …)" when ARIN points elsewhere
    other_rir_url: str = ""
    error: str = ""
    note: str = ""
    rdap: Optional[RdapInfo] = None
    domain: Any = None                # domainwhois.DomainInfo for domain-name lookups
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def owner(self) -> str:
        """Best available owner name (other registry's registrant when ARIN only points there)."""
        if self.rdap and self.rdap.org:
            return self.rdap.org
        if self.org:
            return self.org.name
        if self.net:
            return self.net.org_name
        if self.asn:
            return self.asn.org_name
        return ""

    @property
    def name(self) -> str:
        if self.rdap and self.rdap.name:
            return self.rdap.name
        if self.asn:
            return self.asn.name
        return self.net.name if self.net else ""

    @property
    def country(self) -> str:
        if self.rdap and self.rdap.country:
            return self.rdap.country
        return self.org.country if self.org and not self.other_rir else ""

    @property
    def abuse_emails(self) -> List[str]:
        out = list(self.rdap.abuse_emails) if self.rdap else []
        for p in self.pocs:
            if p.function == "Abuse":
                out += [e for e in p.emails if e not in out]
        return out


def parse_net(data: dict) -> Net:
    n = child(data, "net") or data
    net = Net(handle=text(child(n, "handle")), name=text(child(n, "name")),
              start=text(child(n, "startAddress")), end=text(child(n, "endAddress")),
              registered=date(child(n, "registrationDate")), updated=date(child(n, "updateDate")),
              comments=lines(child(n, "comment")) if child(n, "comment") else [],
              version=text(child(n, "version")))
    for b in as_list(child(child(n, "netBlocks"), "netBlock")):
        start, length = text(child(b, "startAddress")), text(child(b, "cidrLength"))
        net.blocks.append(NetBlock(start, text(child(b, "endAddress")),
                                   f"{start}/{length}" if start and length else "",
                                   text(child(b, "type")), text(child(b, "description"))))
    net.org_handle, net.org_name = ref(child(n, "orgRef"))
    net.customer_handle, net.customer_name = ref(child(n, "customerRef"))
    net.parent_handle, net.parent_name = ref(child(n, "parentNetRef"))
    net.origin_as = [text(a) for a in as_list(child(child(n, "originASes"), "originAS")) if text(a)]
    return net


def parse_org(data: dict, customer: bool = False) -> Org:
    o = child(data, "customer" if customer else "org") or data
    country = child(o, "iso3166-1") or {}
    return Org(handle=text(child(o, "handle")), name=text(child(o, "name")) or text(child(o, "customerName")),
               street=lines(child(o, "streetAddress")) if child(o, "streetAddress") else [],
               city=text(child(o, "city")), state=text(child(o, "iso3166-2")),
               postal=text(child(o, "postalCode")), country=text(child(country, "code2")),
               country_name=text(child(country, "name")),
               registered=date(child(o, "registrationDate")), updated=date(child(o, "updateDate")),
               comments=lines(child(o, "comment")) if child(o, "comment") else [], is_customer=customer)


def parse_poc(data: dict, function: str = "") -> Poc:
    p = child(data, "poc") or data
    # Role contacts (e.g. "Abuse") keep the role name in lastName, like ARIN's own whois output
    name = text(child(p, "lastName")) if text(child(p, "contactType")) == "ROLE" else ""
    if not name:
        name = " ".join(x for x in (text(child(p, "firstName")), text(child(p, "lastName"))) if x) \
               or text(child(p, "companyName"))
    emails = [text(e) for e in as_list(child(child(p, "emails"), "email")) if text(e)]
    phones = []
    for ph in as_list(child(child(p, "phones"), "phone")):
        num = text(child(child(ph, "number"), "phoneNumber")) or text(child(ph, "number"))
        if num:
            phones.append(num)
    return Poc(function=function, handle=text(child(p, "handle")), name=name, emails=emails, phones=phones)


def poc_links(data: dict) -> List[Tuple[str, str, str]]:
    """/org/{h}/pocs -> [(function, handle, name)]."""
    root = child(data, "pocs") or data
    out = []
    for link in as_list(child(root, "pocLinkRef")):
        if isinstance(link, dict):
            fn = link.get("@description") or POC_FUNCTIONS.get(link.get("@function", ""), link.get("@function", ""))
            out.append((fn, link.get("@handle", ""), link.get("@name", "")))
    return out


def parse_asn(data: dict) -> Asn:
    a = child(data, "asn") or data
    oh, on = ref(child(a, "orgRef"))
    return Asn(handle=text(child(a, "handle")), name=text(child(a, "name")),
               start=text(child(a, "startAsNumber")), end=text(child(a, "endAsNumber")), org_handle=oh,
               org_name=on, registered=date(child(a, "registrationDate")), updated=date(child(a, "updateDate")),
               comments=lines(child(a, "comment")) if child(a, "comment") else [])


def other_rir(org_handle: str, org_name: str) -> Tuple[str, str]:
    for key, (label, url) in OTHER_RIRS.items():
        if org_handle.upper().startswith(key) or key in org_name.upper():
            return label, url
    return "", ""


# --------------------------------------------------------------------------- lookups


def classify_query(q: str) -> Tuple[str, str]:
    """Returns (kind, normalized query). kind: ip / cidr / asn / net / poc / org."""
    q = q.strip()
    try:
        return "ip", str(ipaddress.ip_address(q))
    except ValueError:
        pass
    if "/" in q:
        try:
            n = ipaddress.ip_network(q, strict=False)
            return "cidr", str(n)
        except ValueError:
            pass
    m = re.fullmatch(r"(?i)(?:as)?\s*(\d{1,10})", q)
    if m:
        return "asn", f"AS{m.group(1)}"
    if q.upper().startswith(("NET-", "NET6-")):
        return "net", q.upper()
    if q.upper().endswith("-ARIN"):
        return "poc", q.upper()
    return "org", q.upper()


def rir_key(label: str) -> str:
    return next((k for k in OTHER_RIRS if label.upper().startswith(k)), "")


def fetch_rdap(kind: str, q: str, rir: str, rdap_base: str, timeout: float, cache: Optional[dict]) -> RdapInfo:
    """RDAP lookup via ARIN's bootstrap redirector, falling back to the registry's own RDAP server."""
    path = f"autnum/{q[2:]}" if kind == "asn" else f"ip/{q}"
    urls = [f"{rdap_base}/{path}"]
    if rir in RIR_RDAP and rdap_base == RDAP_URL:
        urls.append(f"{RIR_RDAP[rir]}/{path}")
    last = None
    for url in urls:
        try:
            return parse_rdap(fetch_url(url, "application/rdap+json", timeout, cache, source="RDAP"))
        except WhoisError as exc:
            last = exc
    raise last


def lookup(query: str, contacts: bool = True, base: str = BASE_URL, cache: Optional[dict] = None,
           timeout: float = 15.0, follow_rdap: bool = True, rdap_base: str = RDAP_URL) -> WhoisResult:
    res = _lookup_arin(query, contacts, base, cache, timeout)
    if follow_rdap and res.other_rir and res.kind in ("ip", "cidr", "asn") and not res.error:
        q = res.query.split("/")[0] if res.kind == "cidr" else res.query
        try:
            res.rdap = fetch_rdap("asn" if res.kind == "asn" else "ip", q, rir_key(res.other_rir),
                                  rdap_base, timeout, cache)
        except WhoisError as exc:
            res.note = (res.note + f" Couldn't get owner details from {res.other_rir.split(' (')[0]}: {exc}.").strip()
    return res


def _lookup_arin(query: str, contacts: bool, base: str, cache: Optional[dict], timeout: float) -> WhoisResult:
    kind, q = classify_query(query)
    res = WhoisResult(query=q, kind=kind)
    get = lambda path: fetch_json(path, base, timeout, cache)
    try:
        if kind in ("ip", "cidr", "net"):
            if kind == "ip":
                path = f"ip/{q}"
            elif kind == "cidr":
                prefix, length = q.split("/")
                path = f"cidr/{prefix}/{length}"
            else:
                path = f"net/{q}"
            data = get(path)
            res.raw["net"] = data
            if kind == "cidr" and child(data, "net") is None:
                # CIDR queries may return a list of netRefs; take the most specific and fetch it
                refs = as_list(child(child(data, "nets"), "netRef")) or as_list(child(data, "netRef"))
                if not refs:
                    raise WhoisError("No network found for that prefix")
                h = refs[-1].get("@handle", "") if isinstance(refs[-1], dict) else ""
                data = get(f"net/{h}")
                res.raw["net"] = data
            res.net = parse_net(data)
            oh, on = res.net.org_handle, res.net.org_name
            if res.net.customer_handle:
                res.org = parse_org(get(f"customer/{res.net.customer_handle}"), customer=True)
                res.note = f"Reassigned by {res.net.parent_name or res.net.parent_handle} to a customer record."
            elif oh:
                res.org = parse_org(get(f"org/{oh}"))
            res.other_rir, url = other_rir(oh, on or (res.org.name if res.org else ""))
            if res.other_rir:
                res.other_rir_url = url.format(q=q.split("/")[0])
            if contacts and oh and not res.other_rir:
                res.pocs = fetch_pocs(get, f"org/{oh}/pocs")
            if contacts and res.net.customer_handle and not res.pocs and res.net.parent_handle:
                res.pocs = fetch_pocs(get, f"net/{res.net.handle}/pocs")
        elif kind == "asn":
            data = get(f"asn/{q}")
            res.raw["asn"] = data
            res.asn = parse_asn(data)
            if res.asn.org_handle:
                res.org = parse_org(get(f"org/{res.asn.org_handle}"))
                res.other_rir, url = other_rir(res.asn.org_handle, res.asn.org_name)
                if res.other_rir:
                    res.other_rir_url = url.format(q=q)
                elif contacts:
                    res.pocs = fetch_pocs(get, f"org/{res.asn.org_handle}/pocs")
        elif kind == "org":
            res.org = parse_org(get(f"org/{q}"))
            if contacts:
                res.pocs = fetch_pocs(get, f"org/{q}/pocs")
        elif kind == "poc":
            res.pocs = [parse_poc(get(f"poc/{q}"))]
    except WhoisError as exc:
        res.error = str(exc)
    return res


def fetch_pocs(get, path: str, limit: int = 8) -> List[Poc]:
    try:
        links = poc_links(get(path))
    except WhoisError:
        return []
    order = {"Abuse": 0, "NOC": 1, "Tech": 2, "Admin": 3}
    links.sort(key=lambda l: order.get(l[0], 9))
    pocs = []
    for fn, handle, name in links[:limit]:
        try:
            pocs.append(parse_poc(get(f"poc/{handle}"), fn))
        except WhoisError:
            pocs.append(Poc(fn, handle, name))
    return pocs


# --------------------------------------------------------------------------- text helpers

_V4 = r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?:/\d{1,2})?(?![\d.])"
_V6 = r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?(?![0-9A-Fa-f:])"
_AS = r"(?i)\bAS\s?(\d{1,10})\b"


_PATH_LABEL = re.compile(r"(?i)^\s*(?:as[\s_-]?path|path)\s*[:=]?\s*")
_ORIGIN = {"i", "e", "?", "igp", "egp", "incomplete"}
_ASDOT = re.compile(r"^(\d{1,5})\.(\d{1,5})$")


def parse_asn_token(tok: str) -> Optional[int]:
    """'15169', 'AS15169', asdot '1.10' -> int; None if it isn't an ASN."""
    tok = tok.strip().upper()
    if tok.startswith("AS"):
        tok = tok[2:]
    if tok.isdigit():
        n = int(tok)
        return n if 0 < n <= 4294967295 else None
    m = _ASDOT.match(tok)
    if m and int(m.group(1)) <= 65535 and int(m.group(2)) <= 65535:
        return int(m.group(1)) * 65536 + int(m.group(2))
    return None


def _path_tokens(segment: str) -> Optional[List[int]]:
    """If every token is an ASN, AS-set/confed bracket or origin code, return the ASNs; else None."""
    seg = segment.replace("{", " ").replace("}", " ").replace("(", " ").replace(")", " ") \
        .replace("[", " ").replace("]", " ").replace(",", " ")
    asns = []
    for tok in seg.split():
        if tok.lower() in _ORIGIN:
            continue
        n = parse_asn_token(tok)
        if n is None:
            return None
        asns.append(n)
    return asns or None


def as_path_from_line(line: str) -> Optional[List[int]]:
    """Find an AS path in one line of text. Recognises:
      * a bare path:                  3356 174 15169
      * a labelled path:              AS path: 3356 15169 I    /   Path: 3356 15169
      * a 'show ip bgp' table row:    *> 8.8.8.0/24  203.0.113.1  0  100  0  3356 15169 i
    """
    s = line.strip().rstrip(",;")
    if not s:
        return None
    s = re.sub(r",?\s*\((?:received|best|used|external|internal|aggregated)[^)]*\)\s*$", "", s, flags=re.I)
    labelled = _PATH_LABEL.match(s)
    if labelled:
        return _path_tokens(s[labelled.end():])
    whole = _path_tokens(s)
    if whole:
        return whole
    # BGP table row: path = numbers after the weight (0 or 32768) that follows the last IP, ending in an origin code
    toks = s.split()
    if toks and toks[-1].lower() in ("i", "e", "?"):
        last_ip = max((i for i, tk in enumerate(toks) if re.fullmatch(_V4, tk) or
                       (":" in tk and re.fullmatch(_V6, tk))), default=None)
        if last_ip is not None:
            tail = toks[last_ip + 1:-1]
            if all(t.isdigit() or _ASDOT.match(t) or t.strip("{}()[],").isdigit() for t in tail):
                weights = [i for i, tk in enumerate(tail) if tk in ("0", "32768")]
                if weights:
                    path = _path_tokens(" ".join(tail[weights[-1] + 1:]))
                    return path or None
    return None


def extract_as_paths(text_in: str) -> List[List[Tuple[int, int]]]:
    """Every AS path in the text, prepends collapsed: [[(3356, 1), (174, 3), (15169, 1)], …]"""
    paths = []
    for line in text_in.splitlines():
        path = as_path_from_line(line)
        if not path:
            continue
        collapsed = []
        for asn in path:
            if collapsed and collapsed[-1][0] == asn:
                collapsed[-1] = (asn, collapsed[-1][1] + 1)
            else:
                collapsed.append((asn, 1))
        paths.append(collapsed)
    return paths


def extract_queries(text_in: str, include_asn: bool = True, bare_asns: bool = True) -> List[str]:
    """Pull IPv4/IPv6 addresses, prefixes and ASNs out of free text, in order, de-duplicated.
    ASNs are found as 'AS1234' anywhere, and – with bare_asns – as plain numbers in AS-path lines."""
    found = []
    for line in text_in.splitlines():
        hits = []
        if include_asn and bare_asns:
            path = as_path_from_line(line)
            if path:
                start = len(line) - len(line.lstrip())
                if not re.search(_V4, line) and ":" not in line.replace("path:", "").replace("Path:", ""):
                    for i, asn in enumerate(path):          # a pure path line: keep path order
                        hits.append((start + i * 1e-3, f"AS{asn}"))
                else:
                    end = len(line)
                    for i, asn in enumerate(path):
                        hits.append((end + i * 1e-3, f"AS{asn}"))
        for m in re.finditer(_V4, line):
            hits.append((m.start(), m.group(0)))
        for m in re.finditer(_V6, line):
            cand = m.group(0)
            try:
                ipaddress.ip_network(cand, strict=False) if "/" in cand else ipaddress.ip_address(cand)
                hits.append((m.start(), cand))
            except ValueError:
                pass
        if include_asn:
            for m in re.finditer(_AS, line):
                hits.append((m.start(), f"AS{m.group(1)}"))
        for _, h in sorted(hits):
            if h not in found:
                found.append(h)
    return found


def asn_note(asn: int) -> str:
    if 64512 <= asn <= 65534 or 4200000000 <= asn <= 4294967294:
        return "Private ASN (RFC 6996)"
    if 64496 <= asn <= 64511 or 65536 <= asn <= 65551:
        return "Documentation ASN (RFC 5398)"
    if asn == 23456:
        return "AS_TRANS (RFC 6793)"
    if asn in (65535, 4294967295):
        return "Reserved ASN"
    return ""


def local_note(query: str) -> str:
    """Addresses/ASNs ARIN can't usefully answer for (private, CGNAT, documentation…)."""
    if query.upper().startswith("AS") and query[2:].isdigit():
        return asn_note(int(query[2:]))
    try:
        ip = ipaddress.ip_network(query, strict=False).network_address
    except ValueError:
        return ""
    if ip.version == 4:
        for net, label in (("10.0.0.0/8", "Private (RFC 1918)"), ("172.16.0.0/12", "Private (RFC 1918)"),
                           ("192.168.0.0/16", "Private (RFC 1918)"), ("100.64.0.0/10", "Shared/CGNAT (RFC 6598)"),
                           ("127.0.0.0/8", "Loopback"), ("169.254.0.0/16", "Link-local"),
                           ("192.0.2.0/24", "Documentation"), ("198.51.100.0/24", "Documentation"),
                           ("203.0.113.0/24", "Documentation"), ("224.0.0.0/4", "Multicast"),
                           ("240.0.0.0/4", "Reserved"), ("0.0.0.0/8", "\"This\" network")):
            if ip in ipaddress.ip_network(net):
                return label
        return ""
    if ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_loopback:
        return "Private / link-local / multicast IPv6"
    return ""


def format_result(r: WhoisResult) -> str:
    out = []
    add = lambda k, v: out.append(f"{k + ':':<20}{v}") if v else None
    out.append(f"# ARIN Whois-RWS lookup for {r.query}")
    if r.error:
        out.append(f"# Error: {r.error}")
        return "\n".join(out)
    if r.net:
        n = r.net
        out.append("")
        add("NetRange", f"{n.start} - {n.end}")
        add("CIDR", n.cidrs)
        add("NetName", n.name)
        add("NetHandle", n.handle)
        add("Parent", f"{n.parent_name} ({n.parent_handle})" if n.parent_handle else "")
        add("NetType", n.type_name)
        add("OriginAS", ", ".join(n.origin_as))
        add("Organization", f"{n.org_name} ({n.org_handle})" if n.org_handle else "")
        add("Customer", f"{n.customer_name} ({n.customer_handle})" if n.customer_handle else "")
        add("RegDate", n.registered)
        add("Updated", n.updated)
        for c in n.comments:
            add("Comment", c)
    if r.asn:
        a = r.asn
        out.append("")
        add("ASNumber", a.start if a.start == a.end else f"{a.start} - {a.end}")
        add("ASName", a.name)
        add("ASHandle", a.handle)
        add("Organization", f"{a.org_name} ({a.org_handle})" if a.org_handle else "")
        add("RegDate", a.registered)
        add("Updated", a.updated)
        for c in a.comments:
            add("Comment", c)
    if r.org:
        o = r.org
        out.append("")
        add("CustName" if o.is_customer else "OrgName", o.name)
        add("OrgId", o.handle)
        for s in o.street:
            add("Address", s)
        add("City", o.city)
        add("StateProv", o.state)
        add("PostalCode", o.postal)
        add("Country", f"{o.country} ({o.country_name})" if o.country_name else o.country)
        add("RegDate", o.registered)
        add("Updated", o.updated)
        for c in o.comments:
            add("Comment", c)
    for p in r.pocs:
        out.append("")
        label = (p.function or "Contact").replace(" ", "")
        add(f"{label}Handle", p.handle)
        add(f"{label}Name", p.name)
        for e in p.emails:
            add(f"{label}Email", e)
        for ph in p.phones:
            add(f"{label}Phone", ph)
    if r.rdap:
        d = r.rdap
        out += ["", f"# Owner details from {r.other_rir.split(' (')[0]} (RDAP{', ' + d.source if d.source else ''})"]
        add("Handle", d.handle)
        add("ASName" if r.kind == "asn" else "NetName", d.name)
        if d.cidrs:
            add("CIDR", ", ".join(d.cidrs))
        elif d.start and r.kind != "asn":
            add("Range", f"{d.start} - {d.end}")
        add("Owner", f"{d.org} ({d.org_handle})" if d.org_handle else d.org)
        add("Country", d.country)
        for e in d.abuse_emails:
            add("AbuseEmail", e)
        for rm in d.remarks:
            add("Remarks", rm)
    elif r.other_rir:
        out += ["", f"# This space is registered with {r.other_rir}. ARIN only points to it –",
                f"# for full details query that registry: {r.other_rir_url}"]
    if r.note:
        out += ["", "# " + r.note]
    return "\n".join(out)
