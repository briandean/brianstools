"""Ping sweep: expand IPs / subnets / ranges and ping each a few times in parallel. Standard library only."""
from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

import pinger

MAX_HOSTS = 4096

_V4 = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
_V6 = r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%\w+)?"
_TOKEN = re.compile(
    rf"(?<![\w.:])(?:"
    rf"(?P<range>(?P<r1>{_V4})\s*-\s*(?P<r2>{_V4}|\d{{1,3}}))(?![\w.])"
    rf"|(?P<cidr>{_V4}/\d{{1,2}})(?![\w.])"
    rf"|(?P<mask>{_V4})\s+(?P<m2>255\.(?:\d{{1,3}}\.){{2}}\d{{1,3}})(?![\w.])"
    rf"|(?P<ip>{_V4})(?![\w.])"
    rf"|(?P<v6>{_V6}(?:/\d{{1,3}})?)(?![\w:])"
    rf")")
_HOST = re.compile(r"^(?=.{1,253}$)(?!\d+$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                   r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")


@dataclass
class Targets:
    hosts: List[str] = field(default_factory=list)      # IPs or host names, in input order, no repeats
    spans: List[Tuple[int, int]] = field(default_factory=list)   # character spans used, for highlighting
    warnings: List[str] = field(default_factory=list)


def _hosts_of(net) -> List[str]:
    return [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]


def expand_targets(text: str, limit: int = MAX_HOSTS) -> Targets:
    """IPs, CIDRs (10.0.0.0/24), 'ip mask', ranges (10.0.0.1-10.0.0.50 or 10.0.0.1-50),
    IPv6 addresses / small prefixes, and lines that are just a host name. Anything else is ignored."""
    out = Targets()
    seen = set()
    total_wanted = 0

    def add(items):
        nonlocal total_wanted
        for h in items:
            total_wanted += 1
            if h not in seen and len(out.hosts) < limit:
                seen.add(h)
                out.hosts.append(h)

    names = []                                  # host names on a line of their own
    pos = 0
    for line in text.splitlines(keepends=True):
        name = line.strip()
        if name and _HOST.match(name) and "." in name and not _TOKEN.search(name):
            names.append((pos + line.index(name), name))
        pos += len(line)
    name_iter = iter(names)
    pending = next(name_iter, None)

    def flush_names(upto):
        nonlocal pending
        while pending and pending[0] < upto:
            add([pending[1].rstrip(".")])
            out.spans.append((pending[0], pending[0] + len(pending[1])))
            pending = next(name_iter, None)

    for m in _TOKEN.finditer(text):
        flush_names(m.start())
        g = m.groupdict()
        try:
            if g["range"]:
                a = ipaddress.IPv4Address(g["r1"])
                if "." in g["r2"]:
                    b = ipaddress.IPv4Address(g["r2"])
                elif int(g["r2"]) <= 255:                  # 10.0.0.1-50 = last octet
                    b = ipaddress.IPv4Address(int(a) & 0xFFFFFF00 | int(g["r2"]))
                else:
                    raise ValueError
                if b < a:
                    a, b = b, a
                size = int(b) - int(a) + 1
                if size > limit:
                    out.warnings.append(f"{g['range']} has {size:,} addresses; only the first {limit:,} are swept.")
                add(str(ipaddress.IPv4Address(i)) for i in range(int(a), int(a) + min(size, limit)))
            elif g["cidr"] or g["mask"]:
                spec = g["cidr"] or f"{g['mask']}/{g['m2']}"
                net = ipaddress.IPv4Network(spec, strict=False)
                if net.num_addresses - 2 > limit:
                    out.warnings.append(f"{net} has {net.num_addresses:,} addresses; "
                                        f"only the first {limit:,} are swept.")
                    add(str(net.network_address + i) for i in range(1, limit + 1))
                else:
                    add(_hosts_of(net))
            elif g["ip"]:
                add([g["ip"]])
            elif g["v6"]:
                spec = g["v6"]
                if spec.count(":") < 2 or spec.split("/")[0].strip(":") == "":
                    continue
                if "/" in spec:
                    net = ipaddress.IPv6Network(spec, strict=False)
                    if net.num_addresses > limit:
                        out.warnings.append(f"{net} is too big to sweep (/116 or smaller works).")
                        continue
                    add(_hosts_of(net))
                else:
                    ipaddress.IPv6Address(spec.split("%")[0])
                    add([spec])
            else:
                continue
        except ValueError:
            continue
        out.spans.append((m.start(), m.end()))
    flush_names(len(text) + 1)
    if len(out.hosts) >= limit and total_wanted > limit and not out.warnings:
        out.warnings.append(f"Stopped at {limit:,} addresses.")
    return out


@dataclass
class HostResult:
    host: str
    ip: str = ""
    sent: int = 0
    received: int = 0
    rtts: List[float] = field(default_factory=list)
    ttl: Optional[int] = None
    status: str = "Pending"     # Alive / Partial / No reply / Unreachable / Error / Pending
    detail: str = ""
    name: str = ""

    @property
    def alive(self) -> bool:
        return self.received > 0

    @property
    def best(self) -> Optional[float]:
        return min(self.rtts) if self.rtts else None

    @property
    def average(self) -> Optional[float]:
        return sum(self.rtts) / len(self.rtts) if self.rtts else None


def ip_sort_key(host: str):
    try:
        a = ipaddress.ip_address(host.split("%")[0])
        return (a.version, int(a), "")
    except ValueError:
        return (9, 0, host.lower())


def ping_host(host: str, count: int = 2, timeout: float = 1.0, resolve_names: bool = False,
              stop: Optional[threading.Event] = None, interval: float = 0.2,
              runner: Callable = pinger.run_probe) -> HostResult:
    r = HostResult(host)
    try:
        ip = host if _is_ip(host) else pinger.resolve(host)
    except OSError as exc:
        r.status, r.detail = "Error", f"Can't resolve: {exc}"
        return r
    r.ip = ip
    is6 = ":" in ip
    tool = pinger.find_tool(is6)
    if not tool:
        r.status, r.detail = "Error", "ping isn't installed"
        return r
    cmd = pinger.build_command(ip, timeout, None, is6, tool=tool)
    statuses = []
    for n in range(count):
        if stop is not None and stop.is_set():
            break
        if n and stop is not None and stop.wait(interval):
            break
        elif n and stop is None:
            time.sleep(interval)
        p = runner(cmd, timeout)
        if p.status == "Stopped":                     # killed by Stop: don't count it
            break
        r.sent += 1
        statuses.append(p.status)
        if p.ok and p.rtt is not None:
            r.received += 1
            r.rtts.append(p.rtt)
            r.ttl = p.ttl
        elif p.detail and not r.detail:
            r.detail = p.detail
    if r.sent == 0:
        r.status = "Stopped"
    elif r.received == r.sent:
        r.status = "Alive"
    elif r.received:
        r.status = "Partial"
    elif "Unreachable" in statuses:
        r.status = "Unreachable"
    elif "Error" in statuses:
        r.status = "Error"
    else:
        r.status = "No reply"
    if resolve_names and not (stop is not None and stop.is_set()):
        try:
            r.name = socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            r.name = ""
    elif not _is_ip(host):
        r.name = host
    return r


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.split("%")[0])
        return True
    except ValueError:
        return False


class KillableRunner:
    """Runs single-probe pings and can kill every one still running (used by Stop)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.procs = set()
        self.stopped = False

    def __call__(self, cmd, timeout: float) -> pinger.ProbeResult:
        import subprocess
        kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                      universal_newlines=True, errors="replace")
        if pinger.platform_kind() == "windows":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            kwargs["encoding"] = "oem"
        with self.lock:
            if self.stopped:
                return pinger.ProbeResult(False, status="Stopped")
            try:
                proc = subprocess.Popen(cmd, **kwargs)
            except OSError as exc:
                return pinger.ProbeResult(False, status="Error", detail=str(exc))
            self.procs.add(proc)
        try:
            out, _ = proc.communicate(timeout=timeout + 3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return pinger.ProbeResult(False, status="Stopped" if self.stopped else "Timeout")
        finally:
            with self.lock:
                self.procs.discard(proc)
        if self.stopped:
            return pinger.ProbeResult(False, status="Stopped")
        return pinger.parse_output(out or "", proc.returncode)

    def kill_all(self):
        with self.lock:
            self.stopped = True
            procs = list(self.procs)
        for p in procs:
            try:
                p.kill()
            except OSError:
                pass


def sweep(hosts: List[str], on_result: Callable[[HostResult], None], count: int = 2, timeout: float = 1.0,
          workers: int = 64, resolve_names: bool = False, stop: Optional[threading.Event] = None,
          runner: Optional[Callable] = None):
    """Ping every host (blocking); on_result is called from worker threads as each one finishes.
    Setting `stop` cancels the hosts still queued; pass a KillableRunner and call kill_all() to also
    end the pings already in flight."""
    stop = stop or threading.Event()
    runner = runner or pinger.run_probe

    def one(h):
        if stop.is_set():
            return
        r = ping_host(h, count, timeout, resolve_names, stop, runner=runner)
        if not stop.is_set() or r.status != "Stopped":
            on_result(r)

    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(hosts) or 1)))
    try:
        futures = [pool.submit(one, h) for h in hosts]
        for f in futures:
            while not f.done():
                if stop.wait(0.05):
                    for g in futures:
                        g.cancel()           # never-started hosts are dropped at once
                    return
    finally:
        pool.shutdown(wait=False)
