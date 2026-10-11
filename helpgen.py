#!/usr/bin/env python3
"""Build the help file: help.md (the editable source) -> help/index.html (one self-contained page).

    python3 helpgen.py

build.py runs this before packaging, so every build ships with up-to-date help. Standard library only:
a small Markdown converter for what help.md uses (headings, paragraphs, nested lists, tables, fenced code,
**bold**, `code` and [links](https://...)).
"""
from __future__ import annotations

import base64
import html
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import version  # noqa: E402

SOURCE = HERE / "help.md"
OUTPUT = HERE / "help" / "index.html"


def slug(text: str, used: set) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "section"
    base, n = s, 2
    while s in used:
        s, n = f"{base}-{n}", n + 1
    used.add(s)
    return s


def inline(text: str) -> str:
    """Escape, then apply `code`, **bold**, [links](url) and <https://autolinks>."""
    out, pos = [], 0
    for m in re.finditer(r"`([^`]+)`", text):            # code spans first, so their contents stay literal
        out.append(_fmt(text[pos:m.start()]))
        out.append(f"<code>{html.escape(m.group(1))}</code>")
        pos = m.end()
    out.append(_fmt(text[pos:]))
    return "".join(out)


def _fmt(t: str) -> str:
    links = []

    def keep(label, url):
        links.append((label, url))
        return f"\x00{len(links) - 1}\x00"

    t = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", lambda m: keep(m.group(1), m.group(2)), t)
    t = re.sub(r"<(https?://[^>\s]+)>", lambda m: keep(m.group(1), m.group(1)), t)
    t = html.escape(t, quote=False)
    t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
    for i, (label, url) in enumerate(links):
        ext = ' target="_blank" rel="noopener"' if url.startswith("http") else ""
        t = t.replace(f"\x00{i}\x00", f'<a href="{html.escape(url)}"{ext}>{_fmt(label) if label != url else html.escape(label)}</a>')
    return t


def convert(md: str):
    """Markdown -> (body html, [(level, id, title)])."""
    lines = md.split("\n")
    out, toc, used = [], [], set()
    para: list = []
    stack: list = []                  # indents of open <ul>/<ol> (each with an open <li>)
    kinds: list = []

    def flush_para():
        if para:
            out.append(f"<p>{inline(' '.join(p.strip() for p in para))}</p>")
            para.clear()

    def close_lists(to_indent=-1):
        while stack and stack[-1] > to_indent:
            stack.pop()
            out.append(f"</li></{kinds.pop()}>")

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if stripped.startswith("```"):                     # fenced code (may sit inside a list item)
            flush_para()
            code = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i][indent:] if lines[i][:indent].strip() == "" else lines[i])
                i += 1
            if not stack:
                close_lists()
            out.append(f"<pre><code>{html.escape(chr(10).join(code))}</code></pre>")
            i += 1
            continue
        h = re.match(r"^(#{1,4})\s+(.*)$", line)
        if h:
            flush_para()
            close_lists()
            level, title = len(h.group(1)), h.group(2).strip()
            hid = slug(title, used)
            if level in (2, 3):
                toc.append((level, hid, title))
            out.append(f'<h{level} id="{hid}">{inline(title)}</h{level}>')
            i += 1
            continue
        if stripped.startswith("|"):                       # table
            flush_para()
            close_lists()
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{2,}:?", c) for c in cells):
                    rows.append(cells)
                i += 1
            if rows:
                head, *body = rows
                out.append("<table><thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in head) + "</tr></thead><tbody>")
                for r in body:
                    out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>")
                out.append("</tbody></table>")
            continue
        b = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", line)
        if b:
            flush_para()
            ind = len(b.group(1))
            kind = "ol" if b.group(2)[0].isdigit() else "ul"
            if not stack or ind > stack[-1]:
                stack.append(ind)
                kinds.append(kind)
                out.append(f"<{kind}><li>")
            else:
                close_lists(ind)
                if stack and stack[-1] == ind and kinds[-1] != kind:     # bullets -> numbers: a new list
                    stack.pop()
                    out.append(f"</li></{kinds.pop()}>")
                if stack and stack[-1] == ind:
                    out.append("</li><li>")
                else:
                    stack.append(ind)
                    kinds.append(kind)
                    out.append(f"<{kind}><li>")
            out.append(inline(b.group(3)))
            i += 1
            continue
        if not stripped:
            flush_para()
            # a blank line ends a list unless the next non-blank line continues it
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            nxt = lines[j] if j < len(lines) else ""
            if stack and not (re.match(r"^\s*([-*]|\d+\.)\s", nxt) or (nxt.startswith(" ") and nxt.strip())):
                close_lists()
            i += 1
            continue
        if stack and indent > 0:                           # continuation text inside a list item
            out.append(" " + inline(stripped))
        else:
            close_lists()
            para.append(line)
        i += 1
    flush_para()
    close_lists()
    return "\n".join(out), toc


CSS = """
:root{--bg:#f6f7f9;--panel:#ffffff;--fg:#0f172a;--muted:#475569;--line:#d9dde3;--accent:#0891b2;--cyan:#22c3ee;
--code:#eef2f6;--navy:#0f172a}
@media (prefers-color-scheme:dark){:root{--bg:#0b1220;--panel:#111a2b;--fg:#e2e8f0;--muted:#94a3b8;--line:#243047;
--accent:#22c3ee;--code:#1b2538}}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,
"Helvetica Neue",Arial,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header{background:var(--navy);color:#fff;padding:20px 28px;display:flex;gap:16px;align-items:center}
header img{width:56px;height:56px;border-radius:12px}
header h1{margin:0;font-size:26px;letter-spacing:.2px}
header .tag{color:var(--cyan);font-weight:600}
header .ver{color:#cbd5e1;font-size:14px;margin-top:2px}
header .ver a{color:var(--cyan)}
.wrap{display:flex;max-width:1200px;margin:0 auto}
nav{position:sticky;top:0;align-self:flex-start;width:270px;max-height:100vh;overflow:auto;padding:20px 12px 40px 20px;
font-size:14px}
nav a{display:block;padding:3px 8px;border-radius:6px;color:var(--fg)}
nav a:hover{background:var(--code);text-decoration:none}
nav .l2{font-weight:650;margin-top:10px}
nav .l3{padding-left:20px;color:var(--muted)}
main{flex:1;min-width:0;padding:8px 32px 80px;background:var(--panel);border-left:1px solid var(--line);
border-right:1px solid var(--line)}
h1,h2,h3{line-height:1.25}
main h1{display:none}
h2{margin:44px 0 12px;padding-top:12px;border-top:2px solid var(--line);font-size:24px}
h3{margin:28px 0 8px;font-size:19px}
h2+h3{margin-top:12px}
p{margin:8px 0}
ul,ol{margin:6px 0 6px 0;padding-left:22px}
li{margin:3px 0}
code{background:var(--code);padding:1px 5px;border-radius:5px;font:0.9em ui-monospace,"SF Mono",Menlo,Consolas,
"Cascadia Mono",monospace}
pre{background:var(--code);padding:12px 14px;border-radius:8px;overflow:auto}
pre code{padding:0;background:none}
table{border-collapse:collapse;margin:10px 0 14px;width:100%;font-size:15px}
th,td{border:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}
th{background:var(--code)}
footer{color:var(--muted);font-size:13px;text-align:center;padding:20px}
@media (max-width:900px){.wrap{display:block}nav{position:static;width:auto;max-height:none}main{border:0}}
@media print{nav,header img{display:none}body{background:#fff}main{border:0}}
"""


def build(source: Path = SOURCE, output: Path = OUTPUT) -> Path:
    md = source.read_text(encoding="utf-8")
    ver = (f"Version {version.VERSION} · released {version.pretty_date()} · "
           f"[{version.WEBSITE_LABEL}]({version.WEBSITE})")
    md = md.replace("{{version_line}}", ver).replace("{{version}}", version.VERSION)
    body, toc = convert(md)
    logo = HERE / "icons" / "bt-icon-128.png"
    if not logo.exists():
        logo = HERE / "icons" / "bt-icon-64.png"
    img = (f'<img alt="" src="data:image/png;base64,{base64.b64encode(logo.read_bytes()).decode()}">'
           if logo.exists() else "")
    nav = "\n".join(f'<a class="l{lvl}" href="#{hid}">{inline(title)}</a>' for lvl, hid, title in toc)
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{version.APP_NAME} Help · {version.VERSION}</title>
<style>{CSS}</style></head>
<body>
<header>{img}<div><h1>{version.APP_NAME} Help</h1>
<div class="tag">{version.TAGLINE}</div>
<div class="ver">Version {version.VERSION} · {version.pretty_date()} ·
<a href="{version.WEBSITE}" target="_blank" rel="noopener">{version.WEBSITE_LABEL}</a></div></div></header>
<div class="wrap"><nav>{nav}</nav>
<main>
{body}
</main></div>
<footer>{version.APP_NAME} {version.VERSION} · <a href="{version.WEBSITE}">{version.WEBSITE_LABEL}</a></footer>
</body></html>
"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(page, encoding="utf-8")
    return output


if __name__ == "__main__":
    p = build()
    print(f"Wrote {p} ({p.stat().st_size // 1024} KB)")
