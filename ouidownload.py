"""Download the IEEE oui.txt vendor list (the app saves it next to settings.json). Standard library only."""
from __future__ import annotations

import os
import re
import ssl
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
# IEEE's site turns away some non-browser clients, so identify like a normal browser.
try:
    from version import VERSION as _v
    _ver = f"BriansTools/{_v}"
except ImportError:
    _ver = "BriansTools"
BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36 " + _ver)
MIN_ENTRIES = 1000            # the real file has 35,000+ vendor lines; anything tiny is an error page
STALE_DAYS = 90
_HEX_LINE = re.compile(r"^\s*[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}\s+\(hex\)", re.M)

# FOLDERID_Documents — follows OneDrive / redirected Documents folders on Windows.
_FOLDERID_DOCUMENTS = "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}"


class DownloadError(Exception):
    pass


class DownloadCancelled(DownloadError):
    pass


@dataclass
class DownloadResult:
    path: Path
    entries: int
    size: int
    verified: bool = True          # False if TLS verification had to be skipped


# --------------------------------------------------------------------------- Documents folder

def _windows_documents() -> Optional[Path]:
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8)]

    guid = GUID()
    ctypes.oledll.ole32.CLSIDFromString(_FOLDERID_DOCUMENTS, ctypes.byref(guid))
    out = ctypes.c_wchar_p()
    ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(out))
    try:
        return Path(out.value) if out.value else None
    finally:
        ctypes.windll.ole32.CoTaskMemFree(out)


def _xdg_documents(run=subprocess.run, home: Optional[Path] = None) -> Optional[Path]:
    home = home or Path.home()
    try:
        out = run(["xdg-user-dir", "DOCUMENTS"], capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        out = ""
    if out and Path(out) != home:          # xdg-user-dir prints $HOME when the folder isn't set
        return Path(out)
    return None


def documents_folder(platform: Optional[str] = None, home: Optional[Path] = None,
                     windows_lookup: Callable = None, run=subprocess.run) -> Path:
    """The user's Documents folder on Windows, macOS and Linux."""
    platform = platform or sys.platform
    home = home or Path.home()
    found = None
    try:
        if platform.startswith("win"):
            found = (windows_lookup or _windows_documents)()
        elif platform != "darwin":
            found = _xdg_documents(run, home)
    except Exception:                      # any ctypes / lookup trouble: use the usual place
        found = None
    return Path(found) if found else home / "Documents"


def default_oui_path(**kw) -> Path:
    return documents_folder(**kw) / "oui.txt"


# --------------------------------------------------------------------------- download

def _open(url: str, timeout: float, verify: bool):
    req = urllib.request.Request(url, headers={"User-Agent": BROWSER_UA, "Accept": "text/plain,*/*"})
    if verify:
        try:
            from arinwhois import trusted_context      # uses the macOS Keychain / Windows store too
            ctx = trusted_context()
        except ImportError:
            ctx = ssl.create_default_context()
    else:
        ctx = ssl._create_unverified_context()
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)


def count_entries(path: Path) -> int:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return len(_HEX_LINE.findall(fh.read()))


def download_oui(dest: Path, url: str = OUI_URL, progress: Optional[Callable[[int, int], None]] = None,
                 stop: Optional[threading.Event] = None, timeout: float = 30.0,
                 min_entries: int = MIN_ENTRIES, opener: Callable = _open) -> DownloadResult:
    """Download oui.txt to `dest` (folders are created). The new file only replaces an existing one
    once it has fully downloaded and looks like the real IEEE list. progress(done_bytes, total_or_0)."""
    dest = Path(dest)
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DownloadError(f"Can't create {dest.parent}: {exc}") from None
    part = dest.with_name(dest.name + ".download")
    verified = True
    try:
        try:
            resp = opener(url, timeout, True)
        except urllib.error.URLError as exc:
            # An intercepting proxy whose certificate this computer doesn't trust: the list is public
            # data and gets checked below, so retry without verification rather than fail.
            if isinstance(exc, urllib.error.HTTPError) or not isinstance(exc.reason, ssl.SSLError):
                raise
            verified = False
            resp = opener(url, timeout, False)
        with resp:
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            with open(part, "wb") as fh:
                while True:
                    if stop is not None and stop.is_set():
                        raise DownloadCancelled("Download cancelled.")
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    fh.write(chunk)
                    done += len(chunk)
                    if progress:
                        progress(done, total)
        if total and done < total:
            raise DownloadError(f"The download stopped early ({done:,} of {total:,} bytes).")
        entries = count_entries(part)
        if entries < min_entries:
            raise DownloadError("The server sent something that isn't the IEEE oui.txt list "
                                f"({entries} vendor lines). Try again later, or use the browser link.")
        os.replace(part, dest)
        return DownloadResult(dest, entries, done, verified)
    except urllib.error.HTTPError as exc:
        raise DownloadError(f"IEEE returned HTTP {exc.code} {exc.reason}.") from None
    except urllib.error.URLError as exc:
        raise DownloadError(f"Couldn't reach IEEE ({exc.reason}).") from None
    except DownloadError:
        raise
    except OSError as exc:
        raise DownloadError(f"Download failed: {exc}") from None
    finally:
        try:
            part.unlink()
        except OSError:
            pass
