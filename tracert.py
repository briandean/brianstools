"""Traceroute helper: runs the operating system's traceroute and parses its output.

Raw ICMP sockets need admin/root rights, so instead of sending probes ourselves we
run the built-in tool (macOS/Linux `traceroute`, Windows `tracert`), which already
has the needed privileges, and parse each line as it arrives.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class Probe:
    host: str = ""          # hostname (or the IP when DNS is off)
    ip: str = ""
    rtt: Optional[float] = None      # None = timed out (*)
    note: str = ""          # !H, !N, <MPLS…>, [AS…] etc.
    text: str = ""          # the time exactly as the tool printed it ("0.978", "<1")


@dataclass
class Hop:
    number: int
    probes: List[Probe] = field(default_factory=list)
    message: str = ""       # e.g. Windows "Request timed out."

    @property
    def responders(self) -> List[Tuple[str, str]]:
        seen = []
        for p in self.probes:
            if p.ip and (p.host, p.ip) not in seen:
                seen.append((p.host, p.ip))
        return seen

    @property
    def rtts(self) -> List[float]:
        return [p.rtt for p in self.probes if p.rtt is not None]

    @property
    def lost(self) -> int:
        return sum(1 for p in self.probes if p.rtt is None)

    @property
    def notes(self) -> str:
        out = []
        for p in self.probes:
            if p.note and p.note not in out:
                out.append(p.note)
        if self.message:
            out.append(self.message)
        return " ".join(out)


def platform_kind() -> str:
    return "windows" if sys.platform == "win32" else "unix"


def find_tool(ipv6: bool = False) -> Optional[str]:
    if platform_kind() == "windows":
        return shutil.which("tracert") or shutil.which("tracert.exe")
    if ipv6 and sys.platform == "darwin":
        return shutil.which("traceroute6") or "/usr/sbin/traceroute6"
    return shutil.which("traceroute") or ("/usr/sbin/traceroute" if sys.platform == "darwin" else None)


def build_command(target: str, resolve: bool = True, max_hops: int = 30, queries: int = 3,
                  wait: float = 2.0, ipv6: bool = False, icmp: bool = False,
                  kind: Optional[str] = None, tool: Optional[str] = None) -> List[str]:
    kind = kind or platform_kind()
    if kind == "windows":
        cmd = [tool or "tracert"]
        if not resolve:
            cmd.append("-d")
        cmd += ["-h", str(max_hops), "-w", str(int(wait * 1000))]
        cmd.append("-6" if ipv6 else "-4")
        return cmd + [target]
    cmd = [tool or "traceroute"]
    if ipv6 and not (tool or "").endswith("traceroute6"):
        cmd.append("-6")
    if not resolve:
        cmd.append("-n")
    if icmp:
        cmd.append("-I")
    cmd += ["-m", str(max_hops), "-q", str(queries), "-w", str(max(1, int(round(wait))))]
    return cmd + [target]


_IP_RE = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+(?:%\w+)?)"


def _is_ip(tok: str) -> bool:
    try:
        ipaddress.ip_address(tok.split("%")[0])
        return True
    except ValueError:
        return False


def parse_unix_line(line: str) -> Optional[Hop]:
    """' 5  r1.example.net (192.0.2.1)  10.1 ms  9.8 ms r2 (192.0.2.2)  11.0 ms !H'"""
    m = re.match(r"^\s*(\d+)\s+(.*)$", line)
    if not m:
        return None
    hop = Hop(int(m.group(1)))
    toks = m.group(2).split()
    host, ip, pending_name = "", "", ""
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok == "*":
            hop.probes.append(Probe(host, ip, None))
        elif i + 1 < len(toks) and toks[i + 1] == "ms" and re.fullmatch(r"\d+(?:\.\d+)?", tok):
            hop.probes.append(Probe(host, ip, float(tok), text=tok))
            i += 1
        elif re.fullmatch(r"\d+(?:\.\d+)?ms", tok):
            hop.probes.append(Probe(host, ip, float(tok[:-2]), text=tok[:-2]))
        elif tok.startswith("(") and tok.endswith(")") and _is_ip(tok[1:-1]):
            ip = tok[1:-1]
            host = pending_name or ip
            pending_name = ""
        elif _is_ip(tok):
            host, ip, pending_name = tok, tok, ""
        elif tok.startswith(("!", "<", "[")):           # !H !N, <MPLS:L=…>, [AS…]
            if hop.probes:
                hop.probes[-1].note = (hop.probes[-1].note + " " + tok).strip()
            else:
                hop.message = (hop.message + " " + tok).strip()
        else:
            pending_name = tok
        i += 1
    return hop


def parse_windows_line(line: str) -> Optional[Hop]:
    """'  2     9 ms     8 ms    <1 ms  host.example.net [10.0.0.1]'  /  '  3     *        *        *     Request timed out.'"""
    m = re.match(r"^\s*(\d+)\s+(.*)$", line)
    if not m or not re.search(r"ms|\*", m.group(2)):
        return None
    hop = Hop(int(m.group(1)))
    rest = m.group(2)
    rtts, texts = [], []
    pos = 0
    for mm in re.finditer(r"\s*(?:(<?\d+)\s*ms|(\*))", rest):
        if mm.start() != pos or len(rtts) >= 3:
            break
        if mm.group(2):
            rtts.append(None)
            texts.append("*")
        else:
            v = mm.group(1)
            rtts.append(0.5 if v.startswith("<") else float(v))
            texts.append(v)
        pos = mm.end()
    tail = rest[pos:].strip()
    host, ip = "", ""
    br = re.match(r"^(\S+)\s+\[(" + _IP_RE + r")\]\s*$", tail)
    if br:
        host, ip = br.group(1), br.group(2)
    elif tail and _is_ip(tail.split()[0]):
        host = ip = tail.split()[0]
        extra = tail[len(ip):].strip()
        if extra:
            hop.message = extra
    elif tail:
        hop.message = tail
    for r, txt in zip(rtts, texts):
        hop.probes.append(Probe(host, ip, r, text=txt))
    if not rtts and tail:
        hop.message = tail
    return hop


def parse_line(line: str, kind: Optional[str] = None) -> Optional[Hop]:
    kind = kind or platform_kind()
    return parse_windows_line(line) if kind == "windows" else parse_unix_line(line)


def merge(existing: Hop, new: Hop) -> Hop:
    """Linux/macOS may print a hop's probes over continuation lines; combine them."""
    existing.probes.extend(new.probes)
    if new.message:
        existing.message = (existing.message + " " + new.message).strip()
    return existing


def popen(cmd: List[str]) -> subprocess.Popen:
    kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                  bufsize=1, universal_newlines=True, errors="replace")
    if platform_kind() == "windows":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        kwargs["encoding"] = "oem"          # tracert writes in the console code page
    return subprocess.Popen(cmd, **kwargs)


class TraceParser:
    """Feed output lines one at a time; keeps hops (including continuation lines)."""

    def __init__(self, kind: Optional[str] = None):
        self.kind = kind or platform_kind()
        self.hops: dict = {}
        self.last: Optional[int] = None
        self.header = ""

    def feed(self, line: str) -> Optional[int]:
        """Returns the hop number that changed, or None."""
        if line.lower().startswith(("traceroute", "tracing route")):
            self.header = line.strip()
            return None
        hop = parse_line(line, self.kind)
        if hop is None and self.last is not None and line.startswith((" ", "\t")) and \
                re.search(r"\bms\b|\*", line) and self.kind == "unix":
            hop = parse_unix_line(f"{self.last} {line.strip()}")
        if hop is None:
            return None
        if hop.number in self.hops:
            merge(self.hops[hop.number], hop)
        else:
            self.hops[hop.number] = hop
        self.last = hop.number
        return hop.number
