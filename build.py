#!/usr/bin/env python3
"""Build a standalone app for the OS you run this on (PyInstaller can't cross-compile).

    python3 -m pip install pyinstaller tzdata
    python3 build.py

Before packaging this compiles the help file (help.md -> help/index.html) and stamps the version from
version.py into the app (Windows file properties, macOS Info.plist).

Output:
  Windows: dist/Brian's Tools.exe
  macOS:   dist/Brian's Tools.app
  Linux:   dist/brians-tools
"""
import os
import plistlib
import subprocess
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
os.chdir(here)
sys.path.insert(0, str(here))

import helpgen  # noqa: E402
import version  # noqa: E402

print(f"Building {version.APP_NAME} {version.VERSION}")
page = helpgen.build()
print(f"Help compiled: {page.relative_to(here)} ({page.stat().st_size // 1024} KB)")

if sys.platform == "darwin":
    name, icon, mode = version.BUILD_NAME, "icon.icns", "--onedir"   # .app bundle
elif sys.platform == "win32":
    name, icon, mode = version.BUILD_NAME, "icon.ico", "--onefile"
else:
    name, icon, mode = "brians-tools", None, "--onefile"

cmd = [
    sys.executable, "-m", "PyInstaller", "brianstools.py",
    "--name", name, "--windowed", mode, "--noconfirm", "--clean",
    "--add-data", f"icon.png{os.pathsep}.",
    "--add-data", f"icons{os.pathsep}icons",
    "--add-data", f"help{os.pathsep}help",
]
if icon:
    cmd += ["--icon", icon]
try:  # bundle the time zone database (needed on Windows, harmless elsewhere)
    import tzdata  # noqa: F401
    cmd += ["--collect-data", "tzdata"]
except ImportError:
    if sys.platform == "win32":
        print("WARNING: 'pip install tzdata' first, or the Time Zones tab will be empty in the build.")
if sys.platform == "darwin":
    cmd += ["--osx-bundle-identifier", "com.wctel.brianstools"]


def windows_version_file() -> Path:
    """A PyInstaller version resource, so Explorer's Properties > Details shows the version."""
    path = here / "build" / "version_info.txt"
    path.parent.mkdir(exist_ok=True)
    path.write_text(version.windows_version_resource(), encoding="utf-8")
    return path


def stamp_mac_bundle() -> None:
    plist = here / "dist" / f"{name}.app" / "Contents" / "Info.plist"
    if not plist.exists():
        print(f"WARNING: {plist} not found; version not stamped.")
        return
    with open(plist, "rb") as f:
        info = plistlib.load(f)
    info.update({
        "CFBundleShortVersionString": version.VERSION,
        "CFBundleVersion": version.VERSION,
        "CFBundleDisplayName": version.APP_NAME,
        "NSHumanReadableCopyright": f"{version.APP_NAME} · {version.WEBSITE_LABEL}",
        "NSHighResolutionCapable": True,
    })
    with open(plist, "wb") as f:
        plistlib.dump(info, f)
    print(f"Stamped {plist.relative_to(here)} with version {version.VERSION}")
    # PyInstaller signs the bundle ad hoc; editing Info.plist breaks that seal, so sign it again.
    subprocess.call(["codesign", "--force", "--deep", "--sign", "-", str(plist.parents[1])])


if sys.platform == "win32":
    cmd += ["--version-file", str(windows_version_file())]

print(" ".join(cmd))
rc = subprocess.call(cmd)
if rc == 0 and sys.platform == "darwin":
    stamp_mac_bundle()
if rc == 0:
    print(f"Done: {version.APP_NAME} {version.VERSION}")
sys.exit(rc)
