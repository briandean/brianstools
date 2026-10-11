"""Plain-text tables for copying: columns padded with spaces so they line up under their headers
in any monospaced view (email, tickets, terminals, Notepad). Standard library only."""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Sequence

GAP = 2
_NUM = re.compile(r"^[-+]?(?:\d[\d,]*)?(?:\.\d+)?(?:\s?(?:%|ms|s))?$")
_BOLD = str.maketrans({chr(0x1D7EC + i): str(i) for i in range(10)})    # bold digits used in tables


def _cell(v) -> str:
    text = "" if v is None else str(v)
    return " ".join(text.translate(_BOLD).replace("\t", " ").split("\n")).rstrip()


def _numeric(values: List[str]) -> bool:
    filled = [v for v in values if v]
    return bool(filled) and all(_NUM.match(v) and any(c.isdigit() for c in v) for v in filled)


def format_table(headers: Optional[Sequence[str]], rows: Iterable[Sequence], indent: str = "",
                 rule: bool = True, gap: int = GAP) -> str:
    """Rows of values -> aligned text. Number-only columns are right-aligned; the last column isn't
    padded, so lines have no trailing spaces. With headers, a dashed rule goes under them."""
    body = [[_cell(v) for v in r] for r in rows]
    head = [_cell(h) for h in headers] if headers else None
    ncols = max([len(head or [])] + [len(r) for r in body] + [0])
    if not ncols:
        return ""
    for r in body:
        r.extend([""] * (ncols - len(r)))
    if head is not None:
        head.extend([""] * (ncols - len(head)))
    cols = list(zip(*body)) if body else [[] for _ in range(ncols)]
    widths = [max([len(v) for v in cols[i]] + [len(head[i]) if head else 0]) for i in range(ncols)]
    right = [_numeric(list(cols[i])) for i in range(ncols)]
    # drop columns that are empty everywhere (including the header)
    keep = [i for i in range(ncols) if widths[i] > 0]

    def line(cells):
        parts = []
        for n, i in enumerate(keep):
            v = cells[i]
            last = n == len(keep) - 1
            if right[i]:
                parts.append(v.rjust(widths[i]))
            else:
                parts.append(v if last else v.ljust(widths[i]))
        return (indent + (" " * gap).join(parts)).rstrip()

    out = []
    if head is not None:
        out.append(line(head))
        if rule:
            out.append((indent + (" " * gap).join("-" * widths[i] for i in keep)).rstrip())
    out += [line(r) for r in body]
    return "\n".join(out)


def align_tabs(text: str, gap: int = GAP) -> str:
    """Align every run of consecutive tab-separated lines (e.g. dig-style records) with spaces.
    Other lines are left as they are."""
    lines = text.split("\n")
    out, run = [], []

    def flush():
        if run:
            out.extend(format_table(None, [l.split("\t") for l in run], gap=gap).split("\n"))
            run.clear()

    for l in lines:
        if "\t" in l and not l.lstrip().startswith(";;"):
            run.append(l)
        else:
            flush()
            out.append(l)
    flush()
    return "\n".join(out)


def tree_table(tree, items=None, skip=()) -> str:
    """A ttk.Treeview's visible columns (headings as titles) for the given rows (default: all)."""
    cols = list(tree["columns"])
    names = [str(tree.heading(c, "text")).rstrip(" ▲▼") or c for c in cols]
    keep = [i for i, c in enumerate(cols) if c not in skip and names[i] not in skip]
    items = tree.get_children("") if items is None else items
    rows = []
    for it in items:
        vals = list(tree.item(it, "values"))
        vals += [""] * (len(cols) - len(vals))
        rows.append([vals[i] for i in keep])
    return format_table([names[i] for i in keep], rows)
