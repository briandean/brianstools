"""Brian's Tools version information (one place for the app, the help file and the build).

Versions are pre-1.0 and date-based: 0.YYYY.MMDD (e.g. 0.2026.1011 = 11 October 2026). Three whole
numbers, so the same string works as a macOS bundle version and a Windows file version.
"""
APP_NAME = "Brian's Tools"
BUILD_NAME = "Brian's Tools"                # app / .exe file name
TAGLINE = "Network Toolbox"
VERSION = "0.2026.1012.2"
RELEASE_DATE = "2026-10-12"
WEBSITE = "https://brianstools.net"
WEBSITE_LABEL = "brianstools.net"
USER_AGENT = f"BriansTools/{VERSION} (+{WEBSITE})"


def version_tuple() -> tuple:
    """(0, 2026, 1011, 0): for the Windows version resource."""
    parts = [int(p) for p in VERSION.split(".")][:4]
    return tuple(parts + [0] * (4 - len(parts)))


def pretty_date() -> str:
    """'October 11, 2026' on every platform (no %-d, which Windows doesn't support)."""
    from datetime import date
    y, m, d = (int(x) for x in RELEASE_DATE.split("-"))
    dt = date(y, m, d)
    return f"{dt:%B} {dt.day}, {dt.year}"


def windows_version_resource() -> str:
    """PyInstaller --version-file text (Explorer shows it under Properties > Details)."""
    v = version_tuple()
    dotted = ".".join(str(n) for n in v)
    return f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={v}, prodvers={v}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1,
                    subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'Brian Dean'),
      StringStruct('FileDescription', {APP_NAME!r}),
      StringStruct('FileVersion', {dotted!r}),
      StringStruct('InternalName', 'BriansTools'),
      StringStruct('OriginalFilename', {BUILD_NAME + '.exe'!r}),
      StringStruct('ProductName', {APP_NAME!r}),
      StringStruct('ProductVersion', {VERSION!r}),
      StringStruct('Comments', {WEBSITE!r})])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
