"""Ping helper: one system `ping` per probe, parsed into success/RTT/TTL, plus running stats.

Sending ICMP ourselves needs admin/root rights, so each probe runs the built-in ping
(which already has them) with a count of 1. That gives an exact result for every probe
on macOS, Linux and Windows.
"""
from __future__ import annotations

import math
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional


def platform_kind() -> str:
    if sys.platform == "win32":
        return "windows"
    return "mac" if sys.platform == "darwin" else "linux"


def find_tool(ipv6: bool = False, kind: Optional[str] = None) -> Optional[str]:
    kind = kind or platform_kind()
    if kind == "mac" and ipv6:
        return shutil.which("ping6") or "/sbin/ping6"
    if kind == "mac":
        return shutil.which("ping") or "/sbin/ping"
    return shutil.which("ping")


def default_size(kind: Optional[str] = None) -> int:
    """Payload bytes ping sends when no size is given: 32 on Windows, 56 on macOS / Linux."""
    return 32 if (kind or platform_kind()) == "windows" else 56


def explain_command(cmd: str, kind: Optional[str] = None) -> str:
    """Plain-English meaning of the flags in a probe command, e.g.
    'ping -c 1 -W 2000 8.8.8.8' -> '-c 1: one probe per run · -W 2000: wait up to 2000 ms for a reply ·
    packet size: default (56 bytes)'."""
    kind = kind or platform_kind()
    toks = cmd.split()
    parts, size = [], None
    for i, t in enumerate(toks[:-1]):
        nxt = toks[i + 1]
        if t in ("-c", "-n") and nxt.isdigit():
            parts.append(f"{t} {nxt}: one probe per run" if nxt == "1" else f"{t} {nxt}: {nxt} probes")
        elif t == "-W" and nxt.isdigit():
            unit = "ms" if kind == "mac" else "s"
            parts.append(f"-W {nxt}: wait up to {nxt} {unit} for a reply")
        elif t == "-w" and nxt.isdigit() and kind == "windows":
            parts.append(f"-w {nxt}: wait up to {nxt} ms for a reply")
        elif t in ("-s", "-l") and nxt.isdigit():
            size = int(nxt)
            parts.append(f"{t} {nxt}: {nxt}-byte payload")
    if size is None:
        parts.append(f"packet size: default ({default_size(kind)} bytes, no size flag)")
    return "  ·  ".join(parts)


def build_command(ip: str, timeout: float = 2.0, size: Optional[int] = None, ipv6: bool = False,
                  kind: Optional[str] = None, tool: Optional[str] = None) -> List[str]:
    kind = kind or platform_kind()
    if kind == "windows":
        cmd = [tool or "ping", "-n", "1", "-w", str(int(timeout * 1000))]
        if size is not None:
            cmd += ["-l", str(size)]
        return cmd + ["-6" if ipv6 else "-4", ip]
    if kind == "mac":
        cmd = [tool or ("ping6" if ipv6 else "ping"), "-c", "1"]
        if not ipv6:                       # macOS ping: -W is milliseconds (ping6 has no -W)
            cmd += ["-W", str(int(timeout * 1000))]
        if size is not None:
            cmd += ["-s", str(size)]
        return cmd + [ip]
    cmd = [tool or "ping", "-c", "1", "-W", str(max(1, math.ceil(timeout)))]   # Linux: seconds
    if ipv6:
        cmd.append("-6")
    if size is not None:
        cmd += ["-s", str(size)]
    return cmd + [ip]


@dataclass
class ProbeResult:
    ok: bool
    rtt: Optional[float] = None      # ms
    ttl: Optional[int] = None
    status: str = ""                 # Reply / Timeout / Unreachable / Error
    detail: str = ""


_TIME = re.compile(r"time\s*([=<])\s*([\d.]+)\s*ms", re.I)
_TTL = re.compile(r"\bttl\s*=\s*(\d+)", re.I)


def parse_output(text: str, returncode: int = 0) -> ProbeResult:
    """Interpret the output of a single-probe ping on any OS."""
    lower = text.lower()
    t = _TIME.search(text)
    ttl = _TTL.search(text)
    # Windows prints "Reply from 10.0.0.1: Destination host unreachable." – a reply, but a failure.
    if "unreachable" in lower:
        line = next((ln.strip() for ln in text.splitlines() if "unreachable" in ln.lower()), "")
        return ProbeResult(False, status="Unreachable", detail=line)
    if t and ttl:
        rtt = float(t.group(2))
        if t.group(1) == "<":            # Windows "time<1ms"
            rtt = min(rtt, 0.5)
        return ProbeResult(True, rtt, int(ttl.group(1)), "Reply")
    for needle, status in (("unknown host", "Error"), ("cannot resolve", "Error"),
                           ("could not find host", "Error"), ("general failure", "Error"),
                           ("transmit failed", "Error"), ("operation not permitted", "Error"),
                           ("ttl expired", "TTL expired"), ("time to live exceeded", "TTL expired")):
        if needle in lower:
            line = next((ln.strip() for ln in text.splitlines() if needle in ln.lower()), needle)
            return ProbeResult(False, status=status, detail=line)
    return ProbeResult(False, status="Timeout")


def resolve(target: str, ipv6: bool = False) -> str:
    """Resolve once up front so every probe pings the same address."""
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    try:
        infos = socket.getaddrinfo(target.strip().strip("[]"), None, family)
    except socket.gaierror:
        if ipv6:
            raise
        infos = socket.getaddrinfo(target.strip().strip("[]"), None)   # maybe it's v6-only
    return infos[0][4][0]


def run_probe(cmd: List[str], timeout: float) -> ProbeResult:
    kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                  universal_newlines=True, errors="replace", timeout=timeout + 3)
    if platform_kind() == "windows":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        kwargs["encoding"] = "oem"
    try:
        proc = subprocess.run(cmd, **kwargs)
    except subprocess.TimeoutExpired:
        return ProbeResult(False, status="Timeout")
    except OSError as exc:
        return ProbeResult(False, status="Error", detail=str(exc))
    return parse_output(proc.stdout or "", proc.returncode)


@dataclass
class PingStats:
    sent: int = 0
    ok: int = 0
    rtts: List[float] = field(default_factory=list)
    longest_outage: int = 0
    current_outage: int = 0
    _jitter_sum: float = 0.0
    _last_rtt: Optional[float] = None

    def add(self, r: ProbeResult):
        self.sent += 1
        if r.ok and r.rtt is not None:
            self.ok += 1
            if self._last_rtt is not None:
                self._jitter_sum += abs(r.rtt - self._last_rtt)
            self._last_rtt = r.rtt
            self.rtts.append(r.rtt)
            self.current_outage = 0
        else:
            self.current_outage += 1
            self.longest_outage = max(self.longest_outage, self.current_outage)

    @property
    def failed(self) -> int:
        return self.sent - self.ok

    @property
    def loss_pct(self) -> float:
        return 100.0 * self.failed / self.sent if self.sent else 0.0

    @property
    def best(self) -> Optional[float]:
        return min(self.rtts) if self.rtts else None

    @property
    def worst(self) -> Optional[float]:
        return max(self.rtts) if self.rtts else None

    @property
    def average(self) -> Optional[float]:
        return sum(self.rtts) / len(self.rtts) if self.rtts else None

    @property
    def jitter(self) -> Optional[float]:
        """Mean difference between consecutive successful replies (ms)."""
        return self._jitter_sum / (len(self.rtts) - 1) if len(self.rtts) > 1 else None

    @property
    def stdev(self) -> Optional[float]:
        if len(self.rtts) < 2:
            return None
        avg = self.average
        return math.sqrt(sum((x - avg) ** 2 for x in self.rtts) / (len(self.rtts) - 1))


def format_duration(seconds: float) -> str:
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    return (f"{d}d " if d else "") + f"{h:02d}:{m:02d}:{s:02d}"
