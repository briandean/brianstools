"""Domain-name whois: RDAP first, classic port-43 WHOIS as a fallback. Standard library only.

RDAP:   IANA's bootstrap file (https://data.iana.org/rdap/dns.json) maps each TLD to its registry's
        RDAP server (e.g. .com -> rdap.verisign.com). The registry answer usually links ("related")
        to the registrar's RDAP server, which is followed for registrant details.
WHOIS:  for TLDs without RDAP (many ccTLDs, e.g. .io, .de) ask whois.iana.org which server runs the
        TLD, then query that server on TCP port 43 and pick out the common fields.
"""
from __future__ import annotations

import json
import os
import re
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import arinwhois

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
IANA_WHOIS = ("whois.iana.org", 43)
BOOTSTRAP_MAX_AGE = 7 * 86400
FALLBACK_RDAP = {"com": "https://rdap.verisign.com/com/v1/", "net": "https://rdap.verisign.com/net/v1/",
                 "org": "https://rdap.publicinterestregistry.org/rdap/"}
# registries that need a special query format (keyed by TLD, so a renamed server still works)
WHOIS_QUERY_FORMAT = {"de": "-T dn,ace {}", "jp": "{}/e", "com": "domain {}", "net": "domain {}"}
_DOMAIN = re.compile(r"(?i)(?<![\w.@/-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{1,59}|[a-z]{2,63}))\.?(?![\w-])")
_NOT_FOUND = re.compile(r"(?i)(no match|not found|no data found|no entries found|status:\s*free|"
                        r"is available for registration|no object found|domain not found)")


class DomainError(Exception):
    pass


@dataclass
class DomainInfo:
    query: str
    domain: str = ""
    registrar: str = ""
    registrar_id: str = ""
    registrar_url: str = ""
    abuse_email: str = ""
    abuse_phone: str = ""
    registrant_org: str = ""
    registrant_country: str = ""
    created: str = ""
    updated: str = ""
    expires: str = ""
    statuses: List[str] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    dnssec: str = ""
    source: str = ""                  # "RDAP rdap.verisign.com + rdap.markmonitor.com" / "WHOIS whois.nic.io"
    raw: str = ""                     # port-43 text
    error: str = ""
    note: str = ""
    not_registered: bool = False      # the registry has no record: the name isn't registered

    @property
    def days_to_expiry(self) -> Optional[int]:
        try:
            exp = time.strptime(self.expires[:10], "%Y-%m-%d")
            return int((time.mktime(exp) - time.time()) // 86400)
        except (ValueError, OverflowError):
            return None


# --------------------------------------------------------------------------- bootstrap

_bootstrap: Optional[Dict[str, str]] = None


def load_bootstrap(cache_dir: Optional[Path] = None, url: str = BOOTSTRAP_URL, timeout: float = 15.0) -> Dict[str, str]:
    """TLD -> RDAP base URL, from IANA (cached on disk for a week)."""
    global _bootstrap
    if _bootstrap is not None:
        return _bootstrap
    cache = Path(cache_dir) / "rdap-dns.json" if cache_dir else None
    data = None
    if cache and cache.exists() and time.time() - cache.stat().st_mtime < BOOTSTRAP_MAX_AGE:
        try:
            data = json.loads(cache.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
    if data is None:
        try:
            data = arinwhois.fetch_url(url, "application/json", timeout, source="IANA")
            if cache:
                try:
                    cache.parent.mkdir(parents=True, exist_ok=True)
                    cache.write_text(json.dumps(data), encoding="utf-8")
                except OSError:
                    pass
        except arinwhois.WhoisError:
            if cache and cache.exists():              # stale is better than nothing
                try:
                    data = json.loads(cache.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    data = None
    mapping = dict(FALLBACK_RDAP)
    for service in (data or {}).get("services", []):
        if isinstance(service, list) and len(service) == 2 and service[1]:
            for tld in service[0]:
                mapping[tld.lower()] = service[1][0]
    _bootstrap = mapping
    return mapping


def reset_bootstrap():
    global _bootstrap
    _bootstrap = None


# --------------------------------------------------------------------------- RDAP


def _event(data: dict, action: str) -> str:
    for ev in data.get("events", []) or []:
        if ev.get("eventAction") == action:
            return str(ev.get("eventDate", ""))[:10]
    return ""


def _adr_country(entity: dict) -> str:
    card = entity.get("vcardArray")
    if isinstance(card, list) and len(card) > 1:
        for item in card[1]:
            if isinstance(item, list) and item and item[0] == "adr":
                params = item[1] if len(item) > 1 and isinstance(item[1], dict) else {}
                if params.get("cc"):
                    return str(params["cc"]).upper()
                val = item[3] if len(item) > 3 else None
                if isinstance(val, list) and val and isinstance(val[-1], str) and val[-1]:
                    return val[-1]
    return ""


def apply_rdap(info: DomainInfo, data: dict, registrar_level: bool = False):
    if not info.domain:
        info.domain = str(data.get("ldhName", "")).lower()
    info.created = info.created or _event(data, "registration")
    info.expires = _event(data, "expiration") or info.expires
    info.updated = _event(data, "last changed") or info.updated
    if data.get("status") and not info.statuses:
        info.statuses = [str(s) for s in data["status"]]
    if data.get("nameservers") and not info.nameservers:
        info.nameservers = [str(n.get("ldhName", "")).lower() for n in data["nameservers"] if n.get("ldhName")]
    sd = data.get("secureDNS")
    if isinstance(sd, dict) and "delegationSigned" in sd and not info.dnssec:
        info.dnssec = "signed" if sd.get("delegationSigned") else "unsigned"
    for ent in arinwhois._walk_entities(data.get("entities")):
        roles = ent.get("roles") or []
        if "registrar" in roles and not info.registrar:
            info.registrar = (arinwhois._vcard(ent, "fn") or [""])[0]
            for pid in ent.get("publicIds", []) or []:
                if "IANA" in str(pid.get("type", "")):
                    info.registrar_id = str(pid.get("identifier", ""))
            info.registrar_url = (arinwhois._vcard(ent, "url") or [info.registrar_url])[0]
        if "abuse" in roles:
            info.abuse_email = info.abuse_email or (arinwhois._vcard(ent, "email") or [""])[0]
            tel = (arinwhois._vcard(ent, "tel") or [""])[0]
            info.abuse_phone = info.abuse_phone or tel.replace("tel:", "")
        if "registrant" in roles:
            org = (arinwhois._vcard(ent, "org") or arinwhois._vcard(ent, "fn") or [""])[0]
            if org and "redacted" not in org.lower():
                info.registrant_org = info.registrant_org or org
            cc = _adr_country(ent)
            if cc and "redacted" not in cc.lower():
                info.registrant_country = info.registrant_country or cc


def _related_link(data: dict) -> str:
    for link in data.get("links", []) or []:
        if link.get("rel") == "related" and "rdap" in str(link.get("type", "rdap")).lower():
            href = link.get("href", "")
            if "/domain/" in href:
                return href
    return ""


def rdap_lookup(domain: str, base: str, timeout: float = 15.0, follow_registrar: bool = True) -> DomainInfo:
    info = DomainInfo(query=domain)
    url = base.rstrip("/") + "/domain/" + domain
    data = arinwhois.fetch_url(url, "application/rdap+json", timeout, source="RDAP")
    apply_rdap(info, data)
    hosts = [_host(url)]
    related = _related_link(data)
    if follow_registrar and related:
        try:
            reg = arinwhois.fetch_url(related, "application/rdap+json", timeout, source="registrar RDAP")
            apply_rdap(info, reg, registrar_level=True)
            hosts.append(_host(related))
        except arinwhois.WhoisError as exc:
            info.note = f"Registrar RDAP not available ({exc})."
    info.source = "RDAP " + " + ".join(hosts)
    return info


def _host(url: str) -> str:
    return re.sub(r"^\w+://([^/]+).*$", r"\1", url)


# --------------------------------------------------------------------------- port 43


def whois43(query: str, server: str, port: int = 43, timeout: float = 15.0) -> str:
    try:
        with socket.create_connection((server, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall((query + "\r\n").encode("idna" if not query.isascii() else "ascii"))
            chunks = []
            while True:
                data = s.recv(65536)
                if not data:
                    break
                chunks.append(data)
                if sum(len(c) for c in chunks) > 2_000_000:
                    break
    except socket.timeout:
        raise DomainError(f"{server} didn't answer on port {port} (blocked by a firewall?)") from None
    except OSError as exc:
        raise DomainError(f"Couldn't connect to {server}:{port} ({exc.strerror or exc})") from None
    raw = b"".join(chunks)
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


_whois_servers: Dict[str, str] = {}


def whois_server_for(tld: str, iana: Tuple[str, int] = IANA_WHOIS, timeout: float = 15.0) -> str:
    tld = tld.lower()
    if tld in _whois_servers:
        return _whois_servers[tld]
    text_ = whois43(tld, *iana, timeout=timeout)
    m = re.search(r"(?im)^\s*(?:refer|whois):\s*(\S+)", text_)
    if not m:
        raise DomainError(f"IANA has no WHOIS server for .{tld}")
    _whois_servers[tld] = m.group(1).strip()
    return _whois_servers[tld]


_FIELDS = {
    "registrar": ["Registrar", "Sponsoring Registrar", "registrar", "Registrar Name", "Registrar Organization"],
    "registrar_id": ["Registrar IANA ID"],
    "registrar_url": ["Registrar URL", "Referral URL"],
    "abuse_email": ["Registrar Abuse Contact Email", "Abuse Contact Email"],
    "abuse_phone": ["Registrar Abuse Contact Phone"],
    "registrant_org": ["Registrant Organization", "Registrant Organisation", "Registrant", "org", "Organization"],
    "registrant_country": ["Registrant Country", "Registrant Country Code", "country"],
    "created": ["Creation Date", "Created On", "Created", "created", "Registered on", "Registration Time",
                "Domain Registration Date", "registered"],
    "updated": ["Updated Date", "Last Updated", "Last Modified", "Changed", "changed", "last-update", "Last updated"],
    "expires": ["Registry Expiry Date", "Registrar Registration Expiration Date", "Expiry Date", "Expiration Date",
                "Expires On", "Expires", "paid-till", "Expiration Time", "Domain Expiration Date", "expire"],
    "dnssec": ["DNSSEC", "dnssec"],
}


def parse_whois_text(text_: str, info: DomainInfo) -> DomainInfo:
    pairs = []
    for line in text_.splitlines():
        m = re.match(r"^\s*([A-Za-z][\w ./()-]{0,60}?)\s*:\s*(.*\S)\s*$", line)
        if m and not line.lstrip().startswith(("%", "#", ">>>")):
            pairs.append((m.group(1).strip(), m.group(2).strip()))
    lower = [(k.lower(), v) for k, v in pairs]
    for attr, keys in _FIELDS.items():
        if getattr(info, attr):
            continue
        for key in keys:
            val = next((v for k, v in lower if k == key.lower()), "")
            if val and "redacted" not in val.lower():
                if attr in ("created", "updated", "expires"):
                    m = re.search(r"\d{4}[-./]\d{2}[-./]\d{2}", val)
                    val = m.group(0).replace(".", "-").replace("/", "-") if m else val
                setattr(info, attr, val)
                break
    if not info.nameservers:
        ns = [v.split()[0].lower().rstrip(".") for k, v in lower
              if k in ("name server", "nameserver", "nserver", "name servers", "nameservers") and v]
        info.nameservers = list(dict.fromkeys(ns))
    if not info.statuses:
        st = [v.split()[0] for k, v in lower if k in ("domain status", "status", "state") and v]
        info.statuses = list(dict.fromkeys(st))
    return info


def whois_lookup(domain: str, timeout: float = 15.0, iana: Tuple[str, int] = IANA_WHOIS,
                 follow_registrar: bool = True, port: int = 43) -> DomainInfo:
    tld = domain.rsplit(".", 1)[-1]
    server = whois_server_for(tld, iana, timeout)
    query = WHOIS_QUERY_FORMAT.get(tld.lower(), "{}").format(domain)
    text_ = whois43(query, server, port, timeout)
    if _NOT_FOUND.search(text_[:2000]) and not re.search(r"(?im)^\s*(domain name|domain)\s*:", text_):
        raise DomainError("No record found")
    info = DomainInfo(query=domain, domain=domain, raw=text_, source=f"WHOIS {server}")
    parse_whois_text(text_, info)
    # thin registries (e.g. .com over port 43) point at the registrar's own whois server
    m = re.search(r"(?im)^\s*Registrar WHOIS Server:\s*(\S+)", text_)
    if follow_registrar and m and m.group(1).lower() != server.lower():
        reg_server = re.sub(r"^\w+://", "", m.group(1)).strip("/")
        try:
            reg_text = whois43(domain, reg_server, port, timeout)
            parse_whois_text(reg_text, info)
            info.raw += f"\n\n# ---- registrar WHOIS ({reg_server}) ----\n" + reg_text
            info.source += f" + {reg_server}"
        except DomainError:
            pass
    return info


# --------------------------------------------------------------------------- top level


def candidates(name: str) -> List[str]:
    """www.mail.example.co.uk -> [www.mail.example.co.uk, mail.example.co.uk, example.co.uk]"""
    labels = name.lower().strip(".").split(".")
    return [".".join(labels[i:]) for i in range(0, max(1, len(labels) - 1))][:5]


def lookup_domain(name: str, timeout: float = 15.0, follow_registrar: bool = True,
                  cache_dir: Optional[Path] = None, bootstrap_url: str = BOOTSTRAP_URL,
                  iana: Tuple[str, int] = IANA_WHOIS, whois_port: int = 43) -> DomainInfo:
    name = name.strip().strip(".").lower()
    try:
        name = name.encode("idna").decode("ascii") if not name.isascii() else name
    except UnicodeError:
        pass
    tld = name.rsplit(".", 1)[-1]
    rdap_base = load_bootstrap(cache_dir, bootstrap_url, timeout).get(tld)
    rdap_errors: List[str] = []
    whois_errors: List[str] = []

    def found(info, how=""):
        info.query = name
        notes = []
        if info.domain and info.domain != name:
            notes.append(f"{name} is a host name; showing its registered domain {info.domain}.")
        if how:
            notes.append(how)
        if info.note:
            notes.append(info.note)
        info.note = " ".join(notes)
        return info

    if rdap_base:
        for cand in candidates(name):
            try:
                return found(rdap_lookup(cand, rdap_base, timeout, follow_registrar))
            except arinwhois.WhoisError as exc:
                if getattr(exc, "not_found", False):
                    continue                    # 404 = registry has no such domain
                rdap_errors.append(f"RDAP: {exc}")
                break                           # server/network problem – ask port-43 WHOIS instead
        if not rdap_errors:
            return not_registered(name, "the registry's RDAP service")

    # No RDAP for this TLD, or RDAP couldn't be reached: port-43 WHOIS.
    whois_not_found = False
    for cand in candidates(name):
        try:
            return found(whois_lookup(cand, timeout, iana, follow_registrar, whois_port),
                         "RDAP couldn't be reached, so port-43 WHOIS was used." if rdap_errors else "")
        except DomainError as exc:
            if str(exc) == "No record found":
                whois_not_found = True
                continue
            whois_errors.append(f"WHOIS: {exc}")
            break
    if whois_not_found and not whois_errors:
        return not_registered(name, "the registry's WHOIS server")
    return DomainInfo(query=name, error="Couldn't check this domain: " + "; ".join(rdap_errors + whois_errors))


def not_registered(name: str, where: str) -> DomainInfo:
    return DomainInfo(query=name, not_registered=True,
                      error=f"Domain not found: {name} doesn't appear to be registered (no record at {where}).")


def is_domain(s: str) -> bool:
    """True for names like example.com / 3com.com / www.bbc.co.uk (not IPs, prefixes or handles)."""
    s = s.strip().rstrip(".")
    if not s or "/" in s or ":" in s or re.fullmatch(r"[\d.]+", s):
        return False
    return bool(re.fullmatch(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{1,59}|[a-z]{2,63})", s))


def extract_domains(text_in: str, known_tlds: Optional[set] = None) -> List[str]:
    """Domain / host names in free text. With known_tlds, only names ending in a real TLD are kept
    (so file names like settings.json or version strings aren't mistaken for domains)."""
    out = []
    for m in _DOMAIN.finditer(text_in):
        name = m.group(1).lower()
        tld = name.rsplit(".", 1)[-1]
        if known_tlds is not None and tld not in known_tlds:
            continue
        if re.fullmatch(r"[\d.]+", name):
            continue
        if name not in out:
            out.append(name)
    return out


COMMON_TLDS = set("""com net org edu gov mil int info biz io co us uk de fr nl eu ca au jp cn in br ru it es se no
fi dk ch at be pl cz ie nz za mx ar cl kr tw hk sg my id th vn ph tr il ae sa app dev cloud ai me tv cc ws xyz online
site tech store shop blog news agency email live media network systems solutions services company group global
""".split())


def known_tlds(cache_dir: Optional[Path] = None) -> set:
    tlds = set(COMMON_TLDS)
    if _bootstrap:
        tlds |= set(_bootstrap)
    return tlds


def format_domain(info: DomainInfo) -> str:
    out = [f"# Domain whois for {info.query}"]
    if info.not_registered:
        out += ["", "Not registered", "", info.error.replace("Domain not found: ", ""),
                "", "The registry has no record of this name, so it's most likely available to register."]
        return "\n".join(out)
    if info.error:
        out.append(f"# Error: {info.error}")
        return "\n".join(out)
    add = lambda k, v: out.append(f"{k + ':':<20}{v}") if v else None
    out.append("")
    add("Domain", info.domain)
    add("Registrar", info.registrar + (f" (IANA ID {info.registrar_id})" if info.registrar_id else ""))
    add("Registrar URL", info.registrar_url)
    add("Registrant Org", info.registrant_org or "(not published / redacted)")
    add("Registrant Country", info.registrant_country)
    add("Created", info.created)
    add("Updated", info.updated)
    days = info.days_to_expiry
    add("Expires", info.expires + (f"  ({days} days)" if days is not None else ""))
    for s in info.statuses:
        add("Status", s)
    for ns in info.nameservers:
        add("Name Server", ns)
    add("DNSSEC", info.dnssec)
    add("Abuse Email", info.abuse_email)
    add("Abuse Phone", info.abuse_phone)
    add("Source", info.source)
    if info.note:
        out += ["", "# " + info.note]
    if info.raw:
        out += ["", "# ---- raw WHOIS response ----", info.raw.strip()]
    return "\n".join(out)
