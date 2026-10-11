"""digr: a small dig-style DNS client (not ISC dig). Standard library only.

query()   sends one query to a server (UDP, retrying over TCP if the reply is truncated).
trace()   resolves iteratively from a root server, like `dig +trace`.
format_message()  renders a response the way dig does.
"""
from __future__ import annotations

import base64
import ipaddress
import re
import os
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# --------------------------------------------------------------------------- constants

TYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "HINFO": 13, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "NAPTR": 35, "DNAME": 39, "OPT": 41, "DS": 43, "SSHFP": 44,
    "RRSIG": 46, "NSEC": 47, "DNSKEY": 48, "NSEC3": 50, "TLSA": 52, "SVCB": 64, "HTTPS": 65,
    "ANY": 255, "CAA": 257,
}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
QUERY_TYPES = ["A", "AAAA", "ANY", "CAA", "CNAME", "DNSKEY", "DS", "HTTPS", "MX", "NAPTR", "NS",
               "PTR", "SOA", "SRV", "SSHFP", "SVCB", "TLSA", "TXT"]
CLASSES = {"IN": 1, "CH": 3, "HS": 4, "ANY": 255}
CLASS_NAMES = {v: k for k, v in CLASSES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
          6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE", 16: "BADVERS"}

ROOT_SERVERS = [  # IANA root hints (named.root)
    ("a.root-servers.net", "198.41.0.4", "2001:503:ba3e::2:30"),
    ("b.root-servers.net", "170.247.170.2", "2801:1b8:10::b"),
    ("c.root-servers.net", "192.33.4.12", "2001:500:2::c"),
    ("d.root-servers.net", "199.7.91.13", "2001:500:2d::d"),
    ("e.root-servers.net", "192.203.230.10", "2001:500:a8::e"),
    ("f.root-servers.net", "192.5.5.241", "2001:500:2f::f"),
    ("g.root-servers.net", "192.112.36.4", "2001:500:12::d0d"),
    ("h.root-servers.net", "198.97.190.53", "2001:500:1::53"),
    ("i.root-servers.net", "192.36.148.17", "2001:7fe::53"),
    ("j.root-servers.net", "192.58.128.30", "2001:503:c27::2:30"),
    ("k.root-servers.net", "193.0.14.129", "2001:7fd::1"),
    ("l.root-servers.net", "199.7.83.42", "2001:500:9f::42"),
    ("m.root-servers.net", "202.12.27.33", "2001:dc3::35"),
]
PUBLIC_RESOLVERS = [
    ("Google", "8.8.8.8"), ("Google", "8.8.4.4"), ("Cloudflare", "1.1.1.1"), ("Cloudflare", "1.0.0.1"),
    ("Quad9", "9.9.9.9"), ("OpenDNS", "208.67.222.222"),
]


class DnsError(Exception):
    pass


# --------------------------------------------------------------------------- names


def normalize_name(name: str) -> str:
    name = name.strip()
    if not name or name == ".":
        return "."
    return name if name.endswith(".") else name + "."


def encode_name(name: str) -> bytes:
    name = normalize_name(name)
    if name == ".":
        return b"\x00"
    out = b""
    for label in name[:-1].split("."):
        if not label:
            raise DnsError(f"empty label in {name!r}")
        try:
            raw = label.encode("ascii")
        except UnicodeEncodeError:
            raw = label.encode("idna")
        if len(raw) > 63:
            raise DnsError(f"label too long: {label[:20]}…")
        out += bytes([len(raw)]) + raw
    if len(out) + 1 > 255:
        raise DnsError("name too long")
    return out + b"\x00"


_SPECIAL = set('.\\"();@$')


def _escape_label(raw: bytes) -> str:
    out = []
    for b in raw:
        ch = chr(b)
        if ch in _SPECIAL:
            out.append("\\" + ch)
        elif 0x21 <= b <= 0x7E:
            out.append(ch)
        else:
            out.append(f"\\{b:03d}")
    return "".join(out)


def read_name(msg: bytes, offset: int) -> Tuple[str, int]:
    """Decode a (possibly compressed) name. Returns (name, offset after the name)."""
    labels, jumped, end, hops = [], False, offset, 0
    while True:
        if offset >= len(msg):
            raise DnsError("name runs past end of message")
        length = msg[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(msg):
                raise DnsError("bad compression pointer")
            pointer = ((length & 0x3F) << 8) | msg[offset + 1]
            if not jumped:
                end = offset + 2
            jumped = True
            offset = pointer
            hops += 1
            if hops > 64:
                raise DnsError("compression loop")
            continue
        if length & 0xC0:
            raise DnsError("unsupported label type")
        offset += 1
        if length == 0:
            break
        labels.append(_escape_label(msg[offset:offset + length]))
        offset += length
    if not jumped:
        end = offset
    return (".".join(labels) + ".") if labels else ".", end


def reverse_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer + "."


# --------------------------------------------------------------------------- messages


@dataclass
class RR:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    text: str = ""            # presentation form of rdata

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.rtype, f"TYPE{self.rtype}")

    @property
    def class_name(self) -> str:
        return CLASS_NAMES.get(self.rclass, f"CLASS{self.rclass}")


@dataclass
class Message:
    id: int
    flags: int
    question: List[Tuple[str, int, int]] = field(default_factory=list)
    answer: List[RR] = field(default_factory=list)
    authority: List[RR] = field(default_factory=list)
    additional: List[RR] = field(default_factory=list)
    size: int = 0
    opt: Optional[RR] = None

    @property
    def rcode(self) -> int:
        ext = (self.opt.ttl >> 24) & 0xFF if self.opt else 0
        return (ext << 4) | (self.flags & 0xF)

    @property
    def rcode_name(self) -> str:
        return RCODES.get(self.rcode, f"RCODE{self.rcode}")

    def flag(self, name: str) -> bool:
        bit = {"qr": 15, "aa": 10, "tc": 9, "rd": 8, "ra": 7, "ad": 5, "cd": 4}[name]
        return bool(self.flags >> bit & 1)

    @property
    def flag_names(self) -> List[str]:
        return [f for f in ("qr", "aa", "tc", "rd", "ra", "ad", "cd") if self.flag(f)]


def build_query(name: str, qtype: int, qclass: int = 1, rd: bool = True, edns: bool = True,
                dnssec: bool = False, cd: bool = False, qid: Optional[int] = None) -> Tuple[int, bytes]:
    qid = random.randint(0, 0xFFFF) if qid is None else qid
    flags = (0x0100 if rd else 0) | (0x0010 if cd else 0)
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 1 if edns else 0)
    body = encode_name(name) + struct.pack(">HH", qtype, qclass)
    if edns:
        body += b"\x00" + struct.pack(">HHIH", 41, 1232, 0x8000 if dnssec else 0, 0)
    return qid, header + body


def _type_bitmap(data: bytes) -> str:
    types, i = [], 0
    while i + 2 <= len(data):
        window, length = data[i], data[i + 1]
        bitmap = data[i + 2:i + 2 + length]
        for byte_i, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    t = window * 256 + byte_i * 8 + bit
                    types.append(TYPE_NAMES.get(t, f"TYPE{t}"))
        i += 2 + length
    return " ".join(types)


def _char_strings(data: bytes) -> List[str]:
    out, i = [], 0
    while i < len(data):
        n = data[i]
        s = data[i + 1:i + 1 + n]
        txt = "".join(chr(b) if 0x20 <= b <= 0x7E and chr(b) not in '"\\' else
                      ("\\" + chr(b) if chr(b) in '"\\' else f"\\{b:03d}") for b in s)
        out.append(f'"{txt}"')
        i += 1 + n
    return out


def rdata_text(msg: bytes, rtype: int, start: int, rdlen: int) -> str:
    d = msg[start:start + rdlen]
    try:
        if rtype == 1 and rdlen == 4:
            return str(ipaddress.IPv4Address(d))
        if rtype == 28 and rdlen == 16:
            return str(ipaddress.IPv6Address(d))
        if rtype in (2, 5, 12, 39):
            return read_name(msg, start)[0]
        if rtype == 15:
            return f"{struct.unpack('>H', d[:2])[0]} {read_name(msg, start + 2)[0]}"
        if rtype == 16:
            return " ".join(_char_strings(d))
        if rtype == 13:
            return " ".join(_char_strings(d))
        if rtype == 6:
            mname, off = read_name(msg, start)
            rname, off = read_name(msg, off)
            serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", msg[off:off + 20])
            return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
        if rtype == 33:
            prio, weight, port = struct.unpack(">HHH", d[:6])
            return f"{prio} {weight} {port} {read_name(msg, start + 6)[0]}"
        if rtype == 35:
            order, pref = struct.unpack(">HH", d[:4])
            i, parts = 4, []
            for _ in range(3):
                n = d[i]
                parts.append(_char_strings(d[i:i + 1 + n])[0])
                i += 1 + n
            return f"{order} {pref} {' '.join(parts)} {read_name(msg, start + i)[0]}"
        if rtype == 257:
            flags, tlen = d[0], d[1]
            tag = d[2:2 + tlen].decode("ascii", "replace")
            value = d[2 + tlen:].decode("utf-8", "replace").replace('"', '\\"')
            return f'{flags} {tag} "{value}"'
        if rtype == 43:
            keytag, alg, dtype = struct.unpack(">HBB", d[:4])
            return f"{keytag} {alg} {dtype} {d[4:].hex().upper()}"
        if rtype == 48:
            flags, proto, alg = struct.unpack(">HBB", d[:4])
            return f"{flags} {proto} {alg} {base64.b64encode(d[4:]).decode()}"
        if rtype == 46:
            covered, alg, labels, ottl, exp, inc, keytag = struct.unpack(">HBBIIIH", d[:18])
            signer, off = read_name(msg, start + 18)
            sig = base64.b64encode(msg[off:start + rdlen]).decode()
            ts = lambda t: time.strftime("%Y%m%d%H%M%S", time.gmtime(t))
            return (f"{TYPE_NAMES.get(covered, covered)} {alg} {labels} {ottl} {ts(exp)} {ts(inc)} "
                    f"{keytag} {signer} {sig}")
        if rtype == 47:
            nxt, off = read_name(msg, start)
            return f"{nxt} {_type_bitmap(msg[off:start + rdlen])}"
        if rtype == 44:
            return f"{d[0]} {d[1]} {d[2:].hex().upper()}"
        if rtype == 52:
            return f"{d[0]} {d[1]} {d[2]} {d[3:].hex().upper()}"
        if rtype in (64, 65):
            prio = struct.unpack(">H", d[:2])[0]
            target, off = read_name(msg, start + 2)
            params, i = [], off
            names = {0: "mandatory", 1: "alpn", 2: "no-default-alpn", 3: "port", 4: "ipv4hint",
                     5: "ech", 6: "ipv6hint"}
            while i + 4 <= start + rdlen:
                key, ln = struct.unpack(">HH", msg[i:i + 4])
                val = msg[i + 4:i + 4 + ln]
                k = names.get(key, f"key{key}")
                if key == 1:
                    alpns, j = [], 0
                    while j < len(val):
                        alpns.append(val[j + 1:j + 1 + val[j]].decode("ascii", "replace"))
                        j += 1 + val[j]
                    params.append(f'{k}="{",".join(alpns)}"')
                elif key == 3:
                    params.append(f"{k}={struct.unpack('>H', val)[0]}")
                elif key == 4:
                    params.append(k + "=" + ",".join(str(ipaddress.IPv4Address(val[j:j + 4]))
                                                     for j in range(0, len(val), 4)))
                elif key == 6:
                    params.append(k + "=" + ",".join(str(ipaddress.IPv6Address(val[j:j + 16]))
                                                     for j in range(0, len(val), 16)))
                elif key == 2:
                    params.append(k)
                else:
                    params.append(f"{k}={base64.b64encode(val).decode() if key == 5 else val.hex()}")
                i += 4 + ln
            return " ".join([str(prio), target] + params)
    except (DnsError, struct.error, IndexError, ValueError):
        pass
    return f"\\# {rdlen} {d.hex().upper()}" if rdlen else "\\# 0"


def parse_message(msg: bytes) -> Message:
    if len(msg) < 12:
        raise DnsError("reply too short")
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", msg[:12])
    m = Message(qid, flags, size=len(msg))
    off = 12
    for _ in range(qd):
        name, off = read_name(msg, off)
        qtype, qclass = struct.unpack(">HH", msg[off:off + 4])
        off += 4
        m.question.append((name, qtype, qclass))
    for section, count in ((m.answer, an), (m.authority, ns), (m.additional, ar)):
        for _ in range(count):
            name, off = read_name(msg, off)
            if off + 10 > len(msg):
                raise DnsError("record runs past end of message")
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
            off += 10
            if off + rdlen > len(msg):
                raise DnsError("record data runs past end of message")
            rr = RR(name, rtype, rclass, ttl, msg[off:off + rdlen])
            if rtype == 41:
                m.opt = rr
            else:
                rr.text = rdata_text(msg, rtype, off, rdlen)
                section.append(rr)
            off += rdlen
    return m


# --------------------------------------------------------------------------- transport


@dataclass
class QueryResult:
    message: Message
    server: str
    port: int
    protocol: str            # UDP or TCP
    elapsed_ms: float
    truncated_retry: bool = False


def _family(ip: str):
    return socket.AF_INET6 if ":" in ip else socket.AF_INET


def _recv_exact(sock, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise DnsError("connection closed early")
        data += chunk
    return data


def send(server_ip: str, payload: bytes, qid: int, port: int = 53, timeout: float = 3.0,
         tcp: bool = False) -> Tuple[bytes, str]:
    if not tcp:
        with socket.socket(_family(server_ip), socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (server_ip, port))
            deadline = time.monotonic() + timeout
            while True:
                s.settimeout(max(0.05, deadline - time.monotonic()))
                data, _ = s.recvfrom(65535)
                if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == qid:
                    return data, "UDP"
                if time.monotonic() > deadline:
                    raise socket.timeout("timed out")
    with socket.create_connection((server_ip, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(struct.pack(">H", len(payload)) + payload)
        length = struct.unpack(">H", _recv_exact(s, 2))[0]
        return _recv_exact(s, length), "TCP"


def resolve_server(server: str) -> str:
    """Server may be an IP or a hostname (looked up with the system resolver)."""
    server = server.strip().strip("[]")
    try:
        return str(ipaddress.ip_address(server))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(server, 53, type=socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise DnsError(f"can't resolve server name {server!r}: {exc}") from None
    v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
    return (v4 or [infos[0][4][0]])[0]


def query(name: str, qtype: str = "A", server: str = "8.8.8.8", port: int = 53, qclass: str = "IN",
          rd: bool = True, tcp: bool = False, dnssec: bool = False, timeout: float = 3.0) -> QueryResult:
    ip = resolve_server(server)
    qt = TYPES.get(qtype.upper()) or int(qtype.upper().replace("TYPE", ""))
    qid, payload = build_query(name, qt, CLASSES.get(qclass.upper(), 1), rd=rd, dnssec=dnssec)
    start = time.perf_counter()
    try:
        data, proto = send(ip, payload, qid, port, timeout, tcp)
        msg = parse_message(data)
        retried = False
        if msg.flag("tc") and not tcp:
            data, proto = send(ip, payload, qid, port, timeout, True)
            msg = parse_message(data)
            retried = True
    except socket.timeout:
        raise DnsError(f"no reply from {ip}#{port} within {timeout:g}s (blocked or unreachable?)") from None
    except OSError as exc:
        raise DnsError(f"{ip}#{port}: {exc.strerror or exc}") from None
    return QueryResult(msg, ip, port, proto, (time.perf_counter() - start) * 1000, retried)


def system_resolvers() -> List[str]:
    """This computer's DNS servers: /etc/resolv.conf on macOS / Linux, the registry on Windows."""
    import sys
    if sys.platform == "win32":
        try:
            return windows_resolvers()
        except Exception:
            return []
    found = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    ip = parts[1].split("%")[0]
                    try:
                        ipaddress.ip_address(ip)
                        found.append(ip)
                    except ValueError:
                        pass
    except OSError:
        pass
    return found


def _split_servers(value) -> List[str]:
    """Registry NameServer values are 'a.b.c.d,e.f.g.h' or space-separated (or a list)."""
    if isinstance(value, (list, tuple)):
        value = " ".join(str(v) for v in value)
    out = []
    for part in re.split(r"[\s,;]+", str(value or "")):
        part = part.split("%")[0]
        try:
            ip = ipaddress.ip_address(part)
        except ValueError:
            continue
        if ip.is_unspecified or str(ip).startswith("fec0:0:0:ffff::"):   # Windows' stale IPv6 placeholders
            continue
        out.append(str(ip))
    return out


def windows_resolvers(winreg=None) -> List[str]:
    """DNS servers of the connected adapters, from the Tcpip / Tcpip6 registry keys.
    Static (NameServer) wins over DHCP-assigned (DhcpNameServer); adapters without an address are skipped."""
    if winreg is None:
        import winreg  # type: ignore
    hklm = winreg.HKEY_LOCAL_MACHINE

    def value(key, name):
        try:
            return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return None

    found: List[str] = []
    for base, v6 in ((r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces", False),
                     (r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces", True)):
        try:
            root = winreg.OpenKey(hklm, base)
        except OSError:
            continue
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            try:
                key = winreg.OpenKey(root, sub)
            except OSError:
                continue
            if not v6:                                   # only adapters that actually have an address
                addrs = _split_servers(value(key, "DhcpIPAddress")) + _split_servers(value(key, "IPAddress"))
                if not addrs:
                    continue
            servers = _split_servers(value(key, "NameServer")) or _split_servers(value(key, "DhcpNameServer"))
            for ip in servers:
                if ip not in found:
                    found.append(ip)
    if not found:                                        # machine-wide setting, if any
        try:
            key = winreg.OpenKey(hklm, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
            found = _split_servers(value(key, "NameServer")) or _split_servers(value(key, "DhcpNameServer"))
        except OSError:
            pass
    return found


# --------------------------------------------------------------------------- dig-style output


def _rr_line(rr: RR, question: bool = False) -> str:
    if question:
        return f";{rr.name:<31}\t{rr.class_name}\t{rr.type_name}"
    return f"{rr.name:<23}\t{rr.ttl}\t{rr.class_name}\t{rr.type_name}\t{rr.text}"


def format_message(res: QueryResult, header_note: str = "") -> str:
    m = res.message
    lines = []
    if header_note:
        lines.append(header_note)
    if res.truncated_retry:
        lines.append(";; Truncated, retrying in TCP mode.")
    lines.append(";; Got answer:")
    lines.append(f";; ->>HEADER<<- opcode: QUERY, status: {m.rcode_name}, id: {m.id}")
    lines.append(f";; flags: {' '.join(m.flag_names)}; QUERY: {len(m.question)}, ANSWER: {len(m.answer)}, "
                 f"AUTHORITY: {len(m.authority)}, ADDITIONAL: {len(m.additional) + (1 if m.opt else 0)}")
    if m.opt:
        do = " do" if m.opt.ttl & 0x8000 else ""
        lines += ["", ";; OPT PSEUDOSECTION:",
                  f"; EDNS: version: {(m.opt.ttl >> 16) & 0xFF}, flags:{do}; udp: {m.opt.rclass}"]
    lines += ["", ";; QUESTION SECTION:"]
    for name, qt, qc in m.question:
        lines.append(_rr_line(RR(name, qt, qc, 0, b""), question=True))
    for title, section in (("ANSWER", m.answer), ("AUTHORITY", m.authority), ("ADDITIONAL", m.additional)):
        if section:
            lines += ["", f";; {title} SECTION:"] + [_rr_line(rr) for rr in section]
    lines += ["", f";; Query time: {res.elapsed_ms:.0f} msec",
              f";; SERVER: {res.server}#{res.port}({res.server}) ({res.protocol})",
              f";; WHEN: {time.strftime('%a %b %d %H:%M:%S %Z %Y')}",
              f";; MSG SIZE  rcvd: {m.size}"]
    return "\n".join(lines)


def short_answers(m: Message, qtype: str = "") -> List[str]:
    """+short style: rdata of the answer section."""
    return [rr.text for rr in m.answer if not qtype or qtype == "ANY" or rr.type_name in (qtype, "CNAME")]


# --------------------------------------------------------------------------- iterative trace


@dataclass
class TraceStep:
    zone: str
    server_name: str
    server_ip: str
    result: Optional[QueryResult] = None
    error: str = ""
    note: str = ""


@dataclass
class TraceResult:
    steps: List[TraceStep] = field(default_factory=list)
    answers: List[RR] = field(default_factory=list)
    final: Optional[QueryResult] = None
    status: str = ""
    error: str = ""


def _is_subdomain(child: str, parent: str) -> bool:
    child, parent = child.lower(), parent.lower()
    return parent == "." or child == parent or child.endswith("." + parent)


def trace(name: str, qtype: str = "A", root: Optional[Tuple[str, str]] = None, qclass: str = "IN",
          port: int = 53, dnssec: bool = False, timeout: float = 3.0, use_ipv6: bool = False,
          _depth: int = 0, _log: Optional[TraceResult] = None, roots=None) -> TraceResult:
    """Iterative resolution starting at a root server (no recursion requested)."""
    log = _log or TraceResult()
    roots = roots or [(n, v6 if use_ipv6 else v4) for n, v4, v6 in ROOT_SERVERS]
    if root:
        servers = [root] + [r for r in roots if r != root]
    else:
        servers = roots[:]
        random.shuffle(servers)
    qname = normalize_name(name)
    zone, cname_hops = ".", 0
    qt = TYPES.get(qtype.upper(), 1)

    for _ in range(40):
        result, step = None, None
        for sname, sip in servers[:4]:                     # try up to 4 servers for this zone
            step = TraceStep(zone, sname, sip)
            log.steps.append(step)
            try:
                result = query(qname, qtype, sip, port, qclass, rd=False, dnssec=dnssec, timeout=timeout)
                step.result = result
                break
            except DnsError as exc:
                step.error = str(exc)
        if result is None:
            log.error = f"No server for {zone} answered."
            return log
        m = result.message
        if m.rcode != 0:
            log.status, log.final = m.rcode_name, result
            step.note = f"{m.rcode_name} from {step.server_name}"
            return log
        owned = [rr for rr in m.answer if rr.name.lower() == qname.lower()]
        if owned:
            hits = [rr for rr in owned if rr.rtype == qt or qtype.upper() == "ANY"]
            if hits or qt == 5:
                log.answers += owned
                log.status, log.final = "NOERROR", result
                step.note = f"answer from {step.server_name}" + (" (authoritative)" if m.flag("aa") else "")
                return log
            cnames = [rr for rr in owned if rr.rtype == 5]
            if cnames:
                log.answers += cnames
                target = cnames[0].text
                step.note = f"CNAME → {target}; restarting at the root"
                cname_hops += 1
                if cname_hops > 8:
                    log.error = "Too many CNAMEs."
                    return log
                # the same reply may already contain the target's records
                more = [rr for rr in m.answer if rr.name.lower() == target.lower() and rr.rtype == qt]
                if more and m.flag("aa"):
                    log.answers += more
                    log.status, log.final = "NOERROR", result
                    return log
                qname, zone = target, "."
                servers = roots[:]
                random.shuffle(servers)
                continue
        ns_rrs = [rr for rr in m.authority if rr.rtype == 2 and _is_subdomain(qname, rr.name)
                  and _is_subdomain(rr.name, zone) and rr.name.lower() != zone.lower()]
        if not ns_rrs:
            log.status, log.final = "NOERROR (no records of that type)", result
            step.note = f"no {qtype} records – {step.server_name} returned NODATA"
            return log
        new_zone = ns_rrs[0].name
        ns_names = [rr.text for rr in ns_rrs if rr.name == new_zone]
        glue_type = 28 if use_ipv6 else 1
        glue = {}
        for rr in m.additional:
            if rr.rtype == glue_type and rr.name.lower() in {n.lower() for n in ns_names}:
                glue.setdefault(rr.name.lower(), rr.text)
        next_servers = [(n, glue[n.lower()]) for n in ns_names if n.lower() in glue]
        step.note = f"referral to {new_zone} ({len(ns_names)} NS{', glue for ' + str(len(next_servers)) if next_servers else ', no glue'})"
        if not next_servers:
            if _depth >= 4:
                log.error = f"Gave up resolving name servers for {new_zone} (too deep)."
                return log
            for ns in ns_names[:3]:
                sub = trace(ns, "AAAA" if use_ipv6 else "A", None, qclass, port, False, timeout, use_ipv6,
                            _depth + 1, TraceResult(), roots)
                ips = [rr.text for rr in sub.answers if rr.rtype == glue_type]
                step.note += f"; looked up {ns} → {', '.join(ips) or 'nothing'}"
                if ips:
                    next_servers = [(ns, ip) for ip in ips]
                    break
            if not next_servers:
                log.error = f"Couldn't find an address for any name server of {new_zone}."
                return log
        random.shuffle(next_servers)
        servers, zone = next_servers, new_zone
    log.error = "Too many referrals."
    return log


def format_trace(tr: TraceResult, name: str, qtype: str) -> str:
    out = [f"; <<>> iterative trace <<>> {name} {qtype}", ""]
    for i, s in enumerate(tr.steps, 1):
        if s.error:
            out.append(f";; step {i}: {s.server_name} ({s.server_ip}) for zone {s.zone} – {s.error}")
            out.append("")
            continue
        r = s.result
        m = r.message
        records = m.answer or [rr for rr in m.authority if rr.rtype in (2, 6)]
        for rr in records:
            out.append(_rr_line(rr))
        if m.answer or not records:
            pass
        out.append(f";; Received {m.size} bytes from {s.server_ip}#{r.port}({s.server_name}) in "
                   f"{r.elapsed_ms:.0f} ms [{r.protocol}]  — {s.note}")
        out.append("")
    if tr.error:
        out.append(f";; ERROR: {tr.error}")
    else:
        out.append(f";; RESULT: {tr.status}")
    return "\n".join(out)
