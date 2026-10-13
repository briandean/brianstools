"""PeeringDB lookups (https://www.peeringdb.com/api): networks, exchanges, facilities and organizations, laid
out the way the PeeringDB website shows them. Standard library only (plus arinwhois's HTTPS helper).

The GUI only draws what this module returns: a Record with field sections, a side column, and tables.
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import arinwhois

API_URL = "https://www.peeringdb.com/api"
SITE_URL = "https://www.peeringdb.com"
APIKEY_URL = "https://docs.peeringdb.com/howto/api_keys/"
KINDS = ("net", "ix", "fac", "org")
KIND_NAMES = {"net": "Network", "ix": "Exchange", "fac": "Facility", "org": "Organization"}
SEARCH_LIMIT = 25
MEMBER_LIMIT = 5000


class PdbError(Exception):
    def __init__(self, msg: str, not_found: bool = False, status: int = 0):
        super().__init__(msg)
        self.not_found, self.status = not_found, status


# --------------------------------------------------------------------------- what was typed


def classify(text: str) -> Tuple[str, Any]:
    """-> ('net'|'ix'|'fac'|'org', id) for a PeeringDB link or 'ix 26'; ('asn', 15169); ('ip', '206.126.110.58');
    ('search', 'text'); or ('', '') for empty input."""
    t = " ".join(str(text).split())
    if not t:
        return "", ""
    m = re.search(r"(?i)peeringdb\.com/(?:api/)?(net|ix|fac|org)/(\d+)", t)
    if m:
        return m.group(1).lower(), int(m.group(2))
    m = re.fullmatch(r"(?i)(net|ix|fac|org)\s*[/#: ]\s*(\d+)", t)
    if m:
        return m.group(1).lower(), int(m.group(2))
    m = re.fullmatch(r"(?i)(?:AS\s*)?(\d{1,10})", t)
    if m and int(m.group(1)) < 2 ** 32:
        return "asn", int(m.group(1))
    m = re.fullmatch(r"(?i)AS(\d{1,5})\.(\d{1,5})", t)            # asdot
    if m:
        return "asn", int(m.group(1)) * 65536 + int(m.group(2))
    try:
        return "ip", str(ipaddress.ip_address(t.split("/")[0]))
    except ValueError:
        pass
    return "search", t


def site_url(kind: str, obj_id: Any) -> str:
    return f"{SITE_URL}/{kind}/{obj_id}"


# --------------------------------------------------------------------------- the API


class Client:
    """Small PeeringDB API client. `api_key` is optional (a free key from your PeeringDB profile raises the
    rate limit and shows contacts that are hidden from anonymous users)."""

    def __init__(self, api_key: str = "", base: str = API_URL, timeout: float = 20.0,
                 fetch: Optional[Callable] = None):
        self.api_key = api_key.strip()
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.cache: Dict[str, Any] = {}
        self.calls = 0
        self._fetch = fetch or arinwhois.fetch_url

    def get(self, path: str, **params) -> List[dict]:
        q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        url = f"{self.base}/{path}" + (f"?{q}" if q else "")
        if url in self.cache:
            return self.cache[url]
        headers = {"Authorization": f"Api-Key {self.api_key}"} if self.api_key else None
        self.calls += 1
        try:
            data = self._fetch(url, "application/json", self.timeout, None, "PeeringDB", headers)
        except arinwhois.WhoisError as exc:
            status = getattr(exc, "status", 0)
            if status == 429:
                raise PdbError("PeeringDB's rate limit was reached. Wait a minute and try again"
                               + ("." if self.api_key else ", or add a free API key (it allows more queries)."),
                               status=429) from None
            if status in (401, 403):
                raise PdbError("PeeringDB refused the API key (HTTP %d). Check it, or clear it to query "
                               "anonymously." % status, status=status) from None
            raise PdbError(str(exc), not_found=getattr(exc, "not_found", False), status=status) from None
        rows = data.get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            raise PdbError("PeeringDB sent an unexpected reply")
        self.cache[url] = rows
        return rows

    def one(self, kind: str, obj_id: int, depth: int = 2) -> dict:
        rows = self.get(f"{kind}/{int(obj_id)}", depth=depth)
        if not rows:
            raise PdbError(f"No {KIND_NAMES[kind].lower()} with id {obj_id} in PeeringDB", not_found=True)
        return rows[0]

    def org_or_none(self, org_id) -> Optional[dict]:
        if not org_id:
            return None
        try:
            return self.one("org", org_id, depth=0)
        except PdbError as exc:
            if exc.status == 429:
                raise
            return None


# --------------------------------------------------------------------------- what the GUI draws


@dataclass
class Field:
    label: str
    value: str = ""
    link: str = ""            # URL to open (http…, mailto:…) or an in-app target "pdb:net/123"


@dataclass
class Section:
    title: str = ""
    fields: List[Field] = field(default_factory=list)
    table: Optional[Tuple[List[str], List[List[str]]]] = None    # a small inline table (contacts)
    note: str = ""


@dataclass
class Table:
    title: str
    columns: List[str]
    rows: List[List[str]] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)   # per row: "pdb:ix/123" opened by double-click
    widths: List[int] = field(default_factory=list)
    numeric: Tuple[str, ...] = ()
    note: str = ""
    highlight: int = -1                                 # row index to select (e.g. the IP that was looked up)


@dataclass
class Record:
    kind: str                 # net / ix / fac / org / search
    obj_id: Any = None
    title: str = ""
    subtitle: str = ""
    url: str = ""             # the page on peeringdb.com
    main: List[Section] = field(default_factory=list)
    side: List[Section] = field(default_factory=list)
    tables: List[Table] = field(default_factory=list)
    note: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- formatting helpers

NOT_DISCLOSED = "Not Disclosed"


def yes_no(v) -> str:
    return "Yes" if v else "No"


def check(v) -> str:
    return "☑" if v else "☐"


def speed(mbps) -> str:
    """Port speed as the site shows it: 100M, 1G, 10G, 100G, 1.2T."""
    try:
        n = int(mbps)
    except (TypeError, ValueError):
        return ""
    if n >= 1_000_000:
        return f"{n / 1_000_000:g}T"
    if n >= 1000:
        return f"{n / 1000:g}G"
    return f"{n}M"


def country(code: str) -> str:
    return COUNTRIES.get((code or "").upper(), code or "")


def social(items) -> str:
    out = []
    for s in items or []:
        if isinstance(s, dict) and s.get("identifier"):
            out.append(f"{s.get('service', '')}: {s['identifier']}".strip(": "))
    return ", ".join(out)


def _url(v: str) -> str:
    v = (v or "").strip()
    if not v:
        return ""
    return v if re.match(r"(?i)^[a-z][a-z0-9+.-]*:", v) else "http://" + v


def F(label: str, value: Any = "", link: str = "") -> Field:
    if value is None:
        value = ""
    return Field(label, str(value), link)


def website(label: str, v: str) -> Field:
    return F(label, v, _url(v))


def email(label: str, v: str) -> Field:
    return F(label, v, f"mailto:{v}" if v else "")


def address(d: dict) -> str:
    parts = [d.get("address1"), d.get("address2")]
    unit = ", ".join(x for x in (("Floor " + d["floor"]) if d.get("floor") else "",
                                 ("Suite " + d["suite"]) if d.get("suite") else "") if x)
    city = ", ".join(x for x in (d.get("city"), " ".join(x for x in (d.get("state"), d.get("zipcode")) if x)) if x)
    lines = [x for x in parts if x] + ([unit] if unit else []) + ([city] if city else [])
    if d.get("country"):
        lines.append(country(d["country"]))
    return "\n".join(lines)


def _sorted(rows: List[Tuple[List[str], str]], key=lambda r: r[0][0].lower()):
    rows.sort(key=key)
    return [r for r, _ in rows], [t for _, t in rows]


# --------------------------------------------------------------------------- records


def net_record(net: dict, org: Optional[dict], has_key: bool = False, ip: str = "") -> Record:
    nid = net.get("id")
    org_name = (org or {}).get("name") or net.get("org_name", "")
    types = net.get("info_types") or ([net["info_type"]] if net.get("info_type") else [])
    protocols = (f"{check(net.get('info_unicast'))} Unicast IPv4   {check(net.get('info_multicast'))} Multicast   "
                 f"{check(net.get('info_ipv6'))} IPv6   {check(net.get('info_never_via_route_servers'))} "
                 "Never via route servers")
    main = Section("", [
        F("Organization", org_name, f"pdb:org/{net['org_id']}" if net.get("org_id") else ""),
        F("Also Known As", net.get("aka")),
        F("Long Name", net.get("name_long")),
        website("Company Website", (org or {}).get("website", "")),
        website("Company Website Override", net.get("website", "")),
        F("Social Media", social(net.get("social_media"))),
        F("ASN", net.get("asn")),
        F("IRR as-set", net.get("irr_as_set")),
        website("Route Server URL", net.get("route_server", "")),
        website("Looking Glass URL", net.get("looking_glass", "")),
        F("Network Types", ", ".join(types)),
        F("IPv4 Prefixes", net.get("info_prefixes4")),
        F("IPv6 Prefixes", net.get("info_prefixes6")),
        F("Traffic Levels", net.get("info_traffic") or NOT_DISCLOSED),
        F("Traffic Ratios", net.get("info_ratio") or NOT_DISCLOSED),
        F("Geographic Scope", net.get("info_scope") or NOT_DISCLOSED),
        F("Protocols Supported", protocols),
        F("Last Updated", net.get("updated")),
        F("Public Peering Info Updated", net.get("netixlan_updated")),
        F("Peering Facility Info Updated", net.get("netfac_updated")),
        F("Contact Info Updated", net.get("poc_updated")),
        F("Notes", (net.get("notes") or "").strip()),
        F("RIR Status", net.get("rir_status")),
        F("RIR Status Updated", net.get("rir_status_updated")),
    ])
    if net.get("status_dashboard"):
        main.fields.append(website("Status Dashboard", net["status_dashboard"]))
    policy = Section("Peering Policy Information", [
        website("Peering Policy", net.get("policy_url", "")),
        F("General Policy", net.get("policy_general")),
        F("Multiple Locations", net.get("policy_locations")),
        F("Ratio Requirement", yes_no(net.get("policy_ratio"))),
        F("Contract Requirement", net.get("policy_contracts")),
    ])
    pocs = [p for p in net.get("poc_set") or [] if isinstance(p, dict)]
    contacts = Section("Contact Information", table=(
        ["Role", "Name", "Visibility", "Phone", "E-Mail"],
        [[p.get("role", ""), p.get("name", ""), p.get("visible", ""), p.get("phone", ""), p.get("email", "")]
         for p in pocs]))
    if not has_key:
        contacts.note = "Some contacts are only shown to logged-in PeeringDB users. Add an API key to see them."
    if not pocs:
        contacts.note = ("No public contacts. " + contacts.note).strip()

    fac_names = {f.get("fac_id"): f.get("name", "") for f in net.get("netfac_set") or [] if isinstance(f, dict)}
    ix_rows, hl_ip = [], ""
    for x in net.get("netixlan_set") or []:
        if not isinstance(x, dict):
            continue
        port = fac_names.get(x.get("net_side_id"), "") if x.get("net_side_id") else ""
        ix_rows.append(([x.get("name", ""), str(x.get("asn", "")), x.get("ipaddr4") or "", x.get("ipaddr6") or "",
                         speed(x.get("speed")), port, yes_no(x.get("is_rs_peer")), yes_no(x.get("bfd_support")),
                         "Operational" if x.get("operational", True) else "Not operational"],
                        f"pdb:ix/{x.get('ix_id')}"))
    ix_vals, ix_targets = _sorted(ix_rows, key=lambda r: (r[0][0].lower(), r[0][2], r[0][3]))
    exchanges = Table("Public Peering Exchange Points",
                      ["Exchange", "ASN", "IPv4", "IPv6", "Capacity", "Port Location", "RS Peer", "BFD Support",
                       "Status"], ix_vals, ix_targets, [220, 70, 130, 210, 75, 170, 70, 90, 110], ("ASN",))
    if ip:
        for i, row in enumerate(ix_vals):
            if ip in (row[2], row[3]) or _same_ip(ip, row[2]) or _same_ip(ip, row[3]):
                exchanges.highlight = i
                break
    fac_rows = [([f.get("name", ""), str(f.get("local_asn", "")), country(f.get("country", "")), f.get("city", "")],
                 f"pdb:fac/{f.get('fac_id')}") for f in net.get("netfac_set") or [] if isinstance(f, dict)]
    fac_vals, fac_targets = _sorted(fac_rows, key=lambda r: (r[0][2].lower(), r[0][3].lower(), r[0][0].lower()))
    facilities = Table("Interconnection Facilities", ["Facility", "ASN", "Country", "City"], fac_vals, fac_targets,
                       [300, 70, 200, 160], ("ASN",))
    return Record("net", nid, net.get("name", ""), f"AS{net.get('asn', '')}", site_url("net", nid),
                  [main], [policy, contacts], [exchanges, facilities], raw={"net": net, "org": org})


def ix_record(ix: dict, org: Optional[dict], members: List[dict], nets: Dict[int, dict], facs: List[dict],
              lans: List[dict]) -> Record:
    iid = ix.get("id")
    protocols = (f"{check(ix.get('proto_unicast'))} Unicast IPv4   {check(ix.get('proto_multicast'))} Multicast   "
                 f"{check(ix.get('proto_ipv6'))} IPv6")
    main = Section("", [
        F("Organization", (org or {}).get("name") or ix.get("org_name", ""),
          f"pdb:org/{ix['org_id']}" if ix.get("org_id") else ""),
        F("Also Known As", ix.get("aka")),
        F("Long Name", ix.get("name_long")),
        F("City", ix.get("city")),
        F("Country", country(ix.get("country", ""))),
        F("Continental Region", ix.get("region_continent")),
        F("Media Type", ix.get("media")),
        F("Service Level", ix.get("service_level")),
        F("Terms", ix.get("terms")),
        F("Protocols Supported", protocols),
        website("Company Website", ix.get("website", "")),
        F("Social Media", social(ix.get("social_media"))),
        website("Traffic Stats Website", ix.get("url_stats", "")),
        F("Last Updated", ix.get("updated")),
        F("Notes", (ix.get("notes") or "").strip()),
    ])
    if ix.get("status_dashboard"):
        main.fields.append(website("Status Dashboard", ix["status_dashboard"]))
    contact = Section("Contact Information", [
        email("Technical Email", ix.get("tech_email", "")), F("Technical Phone", ix.get("tech_phone")),
        email("Policy Email", ix.get("policy_email", "")), F("Policy Phone", ix.get("policy_phone")),
        email("Sales Email", ix.get("sales_email", "")), F("Sales Phone", ix.get("sales_phone")),
    ])
    side = [contact]
    pfx_rows = []
    for lan in lans:
        fields = [F("MTU", lan.get("mtu")), F("DOT1Q", yes_no(lan.get("dot1q_support"))),
                  F("Route Server ASN", lan.get("rs_asn") or ""),
                  F("ARP Sponge", lan.get("arp_sponge") or ""),
                  website("IX-F Member Export", lan.get("ixf_ixp_member_list_url", ""))]
        side.append(Section("LAN" if len(lans) == 1 else f"LAN {lan.get('name') or lan.get('id')}", fields))
        for p in lan.get("ixpfx_set") or []:
            if isinstance(p, dict):
                pfx_rows.append([p.get("protocol", ""), p.get("prefix", ""), yes_no(p.get("in_dfz"))])
    if pfx_rows:
        side.append(Section("Prefixes", table=(["Protocol", "Prefix", "In DFZ"], pfx_rows)))
    peer_rows = []
    for m in members:
        n = nets.get(m.get("net_id"), {})
        peer_rows.append(([n.get("name") or f"AS{m.get('asn', '')}", str(m.get("asn", "")), m.get("ipaddr4") or "",
                           m.get("ipaddr6") or "", speed(m.get("speed")), n.get("policy_general", ""),
                           yes_no(m.get("is_rs_peer")), yes_no(m.get("bfd_support"))],
                          f"pdb:net/{m.get('net_id')}"))
    pv, pt = _sorted(peer_rows)
    peers = Table("Peers at this Exchange Point", ["Peer Name", "ASN", "IPv4", "IPv6", "Speed", "Policy",
                                                  "RS Peer", "BFD Support"], pv, pt,
                  [240, 70, 130, 210, 70, 90, 70, 90], ("ASN",))
    if len(members) >= MEMBER_LIMIT:
        peers.note = f"Only the first {MEMBER_LIMIT:,} connections are listed."
    fac_rows = [([f.get("name", ""), country(f.get("country", "")), f.get("city", "")], f"pdb:fac/{f.get('fac_id')}")
                for f in facs]
    fv, ft = _sorted(fac_rows)
    local = Table("Local Facilities", ["Facility", "Country", "City"], fv, ft, [300, 200, 160])
    sub = ", ".join(x for x in (ix.get("city"), country(ix.get("country", ""))) if x)
    return Record("ix", iid, ix.get("name", ""), sub, site_url("ix", iid), [main], side, [peers, local],
                  raw={"ix": ix, "org": org})


def fac_record(fac: dict, org: Optional[dict], nets: List[dict], netfacs: List[dict], ixs: List[dict]) -> Record:
    fid = fac.get("id")
    campus = fac.get("campus") if isinstance(fac.get("campus"), dict) else {}
    main = Section("", [
        F("Organization", (org or {}).get("name") or fac.get("org_name", ""),
          f"pdb:org/{fac['org_id']}" if fac.get("org_id") else ""),
        F("Campus", campus.get("name", "") if campus else ""),
        F("Also Known As", fac.get("aka")),
        F("Long Name", fac.get("name_long")),
        website("Company Website", fac.get("website", "")),
        F("Social Media", social(fac.get("social_media"))),
        F("CLLI Code", fac.get("clli")),
        F("NPA-NXX", fac.get("npanxx")),
        F("Address", address(fac)),
        F("Continental Region", fac.get("region_continent")),
        F("Latitude, Longitude", f"{fac['latitude']}, {fac['longitude']}"
          if fac.get("latitude") is not None and fac.get("longitude") is not None else ""),
        F("Property", fac.get("property")),
        F("Diverse Serving Substations", "" if fac.get("diverse_serving_substations") is None
          else yes_no(fac.get("diverse_serving_substations"))),
        F("Available Voltage Services", ", ".join(fac.get("available_voltage_services") or [])),
        F("Last Updated", fac.get("updated")),
        F("Notes", (fac.get("notes") or "").strip()),
    ])
    if fac.get("status_dashboard"):
        main.fields.append(website("Status Dashboard", fac["status_dashboard"]))
    contact = Section("Contact Information", [
        email("Sales Email", fac.get("sales_email", "")), F("Sales Phone", fac.get("sales_phone")),
        email("Technical Email", fac.get("tech_email", "")), F("Technical Phone", fac.get("tech_phone")),
    ])
    ix_rows = [([x.get("name", ""), x.get("city", ""), country(x.get("country", ""))], f"pdb:ix/{x.get('id')}")
               for x in ixs]
    iv, it = _sorted(ix_rows)
    local_asn = {nf.get("net_id"): nf.get("local_asn") for nf in netfacs}
    net_rows = [([n.get("name", ""), str(local_asn.get(n.get("id")) or n.get("asn", "")),
                  n.get("policy_general", "")], f"pdb:net/{n.get('id')}") for n in nets]
    nv, nt = _sorted(net_rows)
    sub = ", ".join(x for x in (fac.get("city"), country(fac.get("country", ""))) if x)
    return Record("fac", fid, fac.get("name", ""), sub, site_url("fac", fid), [main], [contact],
                  [Table("Exchanges", ["Exchange", "City", "Country"], iv, it, [300, 160, 200]),
                   Table("Networks", ["Peer Name", "ASN", "Policy"], nv, nt, [320, 80, 100], ("ASN",))],
                  raw={"fac": fac, "org": org})


def org_record(org: dict, nets: List[dict], ixs: List[dict], facs: List[dict]) -> Record:
    oid = org.get("id")
    main = Section("", [
        F("Also Known As", org.get("aka")),
        F("Long Name", org.get("name_long")),
        website("Company Website", org.get("website", "")),
        F("Social Media", social(org.get("social_media"))),
        F("Address", address(org)),
        F("Last Updated", org.get("updated")),
        F("Notes", (org.get("notes") or "").strip()),
    ])
    nv, nt = _sorted([([n.get("name", ""), str(n.get("asn", "")), n.get("policy_general", "")],
                       f"pdb:net/{n.get('id')}") for n in nets])
    iv, it = _sorted([([x.get("name", ""), x.get("city", ""), country(x.get("country", ""))], f"pdb:ix/{x.get('id')}")
                      for x in ixs])
    fv, ft = _sorted([([f.get("name", ""), f.get("city", ""), country(f.get("country", ""))],
                       f"pdb:fac/{f.get('id')}") for f in facs])
    return Record("org", oid, org.get("name", ""), "Organization", site_url("org", oid), [main], [],
                  [Table("Networks", ["Network", "ASN", "Policy"], nv, nt, [320, 80, 100], ("ASN",)),
                   Table("Exchanges", ["Exchange", "City", "Country"], iv, it, [300, 160, 200]),
                   Table("Facilities", ["Facility", "City", "Country"], fv, ft, [300, 160, 200])],
                  raw={"org": org})


# --------------------------------------------------------------------------- lookups


def _same_ip(a: str, b: str) -> bool:
    try:
        return bool(a and b) and ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return False


def load(client: Client, kind: str, value: Any, progress: Optional[Callable[[str], None]] = None) -> Record:
    """Look up what classify() found. Raises PdbError."""
    say = progress or (lambda _m: None)
    has_key = bool(client.api_key)
    if kind == "asn":
        say(f"Looking up AS{value} …")
        rows = client.get("net", asn=int(value), depth=2)
        if not rows:
            raise PdbError(f"AS{value} has no PeeringDB record", not_found=True)
        net = rows[0]
        return net_record(net, client.org_or_none(net.get("org_id")), has_key)
    if kind == "net":
        say(f"Looking up network {value} …")
        net = client.one("net", value)
        return net_record(net, client.org_or_none(net.get("org_id")), has_key)
    if kind == "ip":
        ver = ipaddress.ip_address(value).version
        say(f"Looking for {value} on an exchange LAN …")
        rows = client.get("netixlan", **{f"ipaddr{ver}": value})
        if not rows:
            raise PdbError(f"{value} isn't an exchange peering address in PeeringDB", not_found=True)
        x = rows[0]
        net = client.one("net", x["net_id"])
        rec = net_record(net, client.org_or_none(net.get("org_id")), has_key, ip=value)
        rec.note = (f"{value} is AS{x.get('asn', '')} {net.get('name', '')} on {x.get('name', 'an exchange')}"
                    + (f" ({speed(x.get('speed'))})" if x.get("speed") else "") + ".")
        return rec
    if kind == "ix":
        say(f"Looking up exchange {value} …")
        ix = client.one("ix", value, depth=0)
        say(f"{ix.get('name', 'Exchange')}: peers, facilities and prefixes …")
        members = client.get("netixlan", ix_id=int(value), limit=MEMBER_LIMIT)
        nets = {n["id"]: n for n in client.get("net", ix_id=int(value), limit=MEMBER_LIMIT) if "id" in n}
        facs = client.get("ixfac", ix_id=int(value))
        lans = client.get("ixlan", ix_id=int(value), depth=2)
        return ix_record(ix, client.org_or_none(ix.get("org_id")), members, nets, facs, lans)
    if kind == "fac":
        say(f"Looking up facility {value} …")
        fac = client.one("fac", value, depth=1)
        say(f"{fac.get('name', 'Facility')}: networks and exchanges …")
        nets = client.get("net", fac_id=int(value), limit=MEMBER_LIMIT)
        netfacs = client.get("netfac", fac_id=int(value), limit=MEMBER_LIMIT)
        ixs = client.get("ix", fac_id=int(value))
        org = fac.get("org") if isinstance(fac.get("org"), dict) else client.org_or_none(fac.get("org_id"))
        return fac_record(fac, org, nets, netfacs, ixs)
    if kind == "org":
        say(f"Looking up organization {value} …")
        org = client.one("org", value, depth=0)
        say(f"{org.get('name', 'Organization')}: networks, exchanges and facilities …")
        return org_record(org, client.get("net", org_id=int(value)), client.get("ix", org_id=int(value)),
                          client.get("fac", org_id=int(value)))
    if kind == "search":
        return search(client, str(value), say)
    raise PdbError("Enter an ASN, a PeeringDB link, an exchange IP address, or a name to search for.")


def search(client: Client, text: str, say=lambda _m: None) -> Record:
    """Networks, exchanges, facilities and organizations whose name contains `text`."""
    rows: List[Tuple[List[str], str]] = []
    for kind in KINDS:
        say(f"Searching {KIND_NAMES[kind].lower()} names for “{text}” …")
        for d in client.get(kind, name__contains=text, limit=SEARCH_LIMIT):
            if kind == "net":
                detail, where = f"AS{d.get('asn', '')}", d.get("policy_general", "")
            elif kind == "org":
                detail, where = "", ", ".join(x for x in (d.get("city"), country(d.get("country", ""))) if x)
            else:
                detail, where = "", ", ".join(x for x in (d.get("city"), country(d.get("country", ""))) if x)
            rows.append(([KIND_NAMES[kind], d.get("name", ""), detail, where], f"pdb:{kind}/{d.get('id')}"))
    order = {KIND_NAMES[k]: i for i, k in enumerate(KINDS)}
    vals, targets = _sorted(rows, key=lambda r: (order[r[0][0]], r[0][1].lower()))
    t = Table("Matches", ["Type", "Name", "ASN", "Where / policy"], vals, targets, [100, 340, 90, 260], ("ASN",))
    if any(sum(1 for r in vals if r[0] == KIND_NAMES[k]) >= SEARCH_LIMIT for k in KINDS):
        t.note = f"Showing up to {SEARCH_LIMIT} matches of each type; type more of the name to narrow it down."
    rec = Record("search", text, f"Search: {text}", f"{len(vals)} match{'es' if len(vals) != 1 else ''}",
                 f"{SITE_URL}/search?q={urllib.parse.quote(text)}", tables=[t])
    if not vals:
        rec.note = f"Nothing in PeeringDB has “{text}” in its name."
    return rec


def record_text(rec: Record) -> str:
    """Plain-text version of a record (for Copy all)."""
    import texttable
    out = [rec.title + (f"  ({rec.subtitle})" if rec.subtitle else ""), rec.url, ""]
    if rec.note:
        out += [rec.note, ""]
    for sec in rec.main + rec.side:
        if sec.title:
            out.append(sec.title)
        w = max((len(f.label) for f in sec.fields), default=0)
        for f in sec.fields:
            lines = f.value.splitlines() or [""]
            out.append(f"  {f.label:<{w}}  {lines[0]}".rstrip())
            out += [f"  {'':<{w}}  {line}" for line in lines[1:]]
        if sec.table and sec.table[1]:
            out += ["  " + line for line in texttable.format_table(sec.table[0], sec.table[1]).splitlines()]
        if sec.note:
            out.append(f"  {sec.note}")
        out.append("")
    for t in rec.tables:
        out.append(f"{t.title} ({len(t.rows)})")
        if t.rows:
            out += ["  " + line for line in texttable.format_table(t.columns, t.rows).splitlines()]
        out.append("")
    return "\n".join(out).rstrip() + "\n"


# --------------------------------------------------------------------------- country names (ISO 3166)

COUNTRIES = dict(
    AD="Andorra", AE="United Arab Emirates", AF="Afghanistan", AG="Antigua and Barbuda", AI="Anguilla",
    AL="Albania", AM="Armenia", AO="Angola", AQ="Antarctica", AR="Argentina", AS="American Samoa", AT="Austria",
    AU="Australia", AW="Aruba", AX="Åland Islands", AZ="Azerbaijan", BA="Bosnia and Herzegovina", BB="Barbados",
    BD="Bangladesh", BE="Belgium", BF="Burkina Faso", BG="Bulgaria", BH="Bahrain", BI="Burundi", BJ="Benin",
    BL="Saint Barthélemy", BM="Bermuda", BN="Brunei", BO="Bolivia", BQ="Bonaire, Sint Eustatius and Saba",
    BR="Brazil", BS="Bahamas", BT="Bhutan", BW="Botswana", BY="Belarus", BZ="Belize", CA="Canada",
    CC="Cocos (Keeling) Islands", CD="Congo (the Democratic Republic of the)", CF="Central African Republic",
    CG="Congo", CH="Switzerland", CI="Côte d'Ivoire", CK="Cook Islands", CL="Chile", CM="Cameroon", CN="China",
    CO="Colombia", CR="Costa Rica", CU="Cuba", CV="Cabo Verde", CW="Curaçao", CX="Christmas Island",
    CY="Cyprus", CZ="Czechia", DE="Germany", DJ="Djibouti", DK="Denmark", DM="Dominica",
    DO="Dominican Republic", DZ="Algeria", EC="Ecuador", EE="Estonia", EG="Egypt", ER="Eritrea", ES="Spain",
    ET="Ethiopia", FI="Finland", FJ="Fiji", FK="Falkland Islands (Malvinas)", FM="Micronesia", FO="Faroe Islands",
    FR="France", GA="Gabon", GB="United Kingdom", GD="Grenada", GE="Georgia", GF="French Guiana", GG="Guernsey",
    GH="Ghana", GI="Gibraltar", GL="Greenland", GM="Gambia", GN="Guinea", GP="Guadeloupe",
    GQ="Equatorial Guinea", GR="Greece", GT="Guatemala", GU="Guam", GW="Guinea-Bissau", GY="Guyana",
    HK="Hong Kong", HN="Honduras", HR="Croatia", HT="Haiti", HU="Hungary", ID="Indonesia", IE="Ireland",
    IL="Israel", IM="Isle of Man", IN="India", IO="British Indian Ocean Territory", IQ="Iraq", IR="Iran",
    IS="Iceland", IT="Italy", JE="Jersey", JM="Jamaica", JO="Jordan", JP="Japan", KE="Kenya", KG="Kyrgyzstan",
    KH="Cambodia", KI="Kiribati", KM="Comoros", KN="Saint Kitts and Nevis", KP="North Korea", KR="South Korea",
    KW="Kuwait", KY="Cayman Islands", KZ="Kazakhstan", LA="Laos", LB="Lebanon", LC="Saint Lucia",
    LI="Liechtenstein", LK="Sri Lanka", LR="Liberia", LS="Lesotho", LT="Lithuania", LU="Luxembourg", LV="Latvia",
    LY="Libya", MA="Morocco", MC="Monaco", MD="Moldova", ME="Montenegro", MF="Saint Martin (French part)",
    MG="Madagascar", MH="Marshall Islands", MK="North Macedonia", ML="Mali", MM="Myanmar", MN="Mongolia",
    MO="Macao", MP="Northern Mariana Islands", MQ="Martinique", MR="Mauritania", MS="Montserrat", MT="Malta",
    MU="Mauritius", MV="Maldives", MW="Malawi", MX="Mexico", MY="Malaysia", MZ="Mozambique", NA="Namibia",
    NC="New Caledonia", NE="Niger", NF="Norfolk Island", NG="Nigeria", NI="Nicaragua", NL="Netherlands",
    NO="Norway", NP="Nepal", NR="Nauru", NU="Niue", NZ="New Zealand", OM="Oman", PA="Panama", PE="Peru",
    PF="French Polynesia", PG="Papua New Guinea", PH="Philippines", PK="Pakistan", PL="Poland",
    PM="Saint Pierre and Miquelon", PR="Puerto Rico", PS="Palestine, State of", PT="Portugal", PW="Palau",
    PY="Paraguay", QA="Qatar", RE="Réunion", RO="Romania", RS="Serbia", RU="Russia", RW="Rwanda",
    SA="Saudi Arabia", SB="Solomon Islands", SC="Seychelles", SD="Sudan", SE="Sweden", SG="Singapore",
    SH="Saint Helena, Ascension and Tristan da Cunha", SI="Slovenia", SK="Slovakia", SL="Sierra Leone",
    SM="San Marino", SN="Senegal", SO="Somalia", SR="Suriname", SS="South Sudan", ST="Sao Tome and Principe",
    SV="El Salvador", SX="Sint Maarten (Dutch part)", SY="Syria", SZ="Eswatini", TC="Turks and Caicos Islands",
    TD="Chad", TG="Togo", TH="Thailand", TJ="Tajikistan", TL="Timor-Leste", TM="Turkmenistan", TN="Tunisia",
    TO="Tonga", TR="Türkiye", TT="Trinidad and Tobago", TV="Tuvalu", TW="Taiwan", TZ="Tanzania", UA="Ukraine",
    UG="Uganda", US="United States of America", UY="Uruguay", UZ="Uzbekistan", VA="Holy See",
    VC="Saint Vincent and the Grenadines", VE="Venezuela", VG="Virgin Islands (British)",
    VI="Virgin Islands (U.S.)", VN="Viet Nam", VU="Vanuatu", WF="Wallis and Futuna", WS="Samoa", YE="Yemen",
    YT="Mayotte", ZA="South Africa", ZM="Zambia", ZW="Zimbabwe")
