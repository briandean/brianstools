"""Text comparison helpers (difflib based). Standard library only."""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


@dataclass
class Options:
    ignore_case: bool = False
    whitespace: str = "none"          # none / trailing / ends / all
    ignore_blank: bool = False
    ignore_regex: str = ""            # lines matching this are left out of the comparison
    sort_lines: bool = False


@dataclass
class Line:
    no: int                           # 1-based line number in the original text
    text: str                         # original text (no newline)
    key: str                          # normalized text used for comparing


@dataclass
class Row:
    tag: str                          # equal / delete / insert / replace
    left: Optional[Line]
    right: Optional[Line]
    left_spans: List[Tuple[int, int]] = field(default_factory=list)    # changed character ranges
    right_spans: List[Tuple[int, int]] = field(default_factory=list)


@dataclass
class Stats:
    left_lines: int = 0
    right_lines: int = 0
    equal: int = 0
    changed: int = 0
    removed: int = 0
    added: int = 0
    ignored_left: int = 0
    ignored_right: int = 0

    @property
    def similarity(self) -> float:
        total = max(self.left_lines, self.right_lines)
        return 100.0 * self.equal / total if total else 100.0

    @property
    def identical(self) -> bool:
        return self.changed == self.removed == self.added == 0


def compile_ignore(pattern: str):
    if not pattern.strip():
        return None
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Ignore pattern isn't a valid regex: {exc}") from None


def normalize(line: str, opts: Options) -> str:
    if opts.whitespace == "trailing":
        line = line.rstrip()
    elif opts.whitespace == "ends":
        line = line.strip()
    elif opts.whitespace == "all":
        line = " ".join(line.split())
    if opts.ignore_case:
        line = line.casefold()
    return line


def prepare(text: str, opts: Options) -> Tuple[List[Line], int]:
    """Lines to compare (after ignore rules) and how many were ignored."""
    rx = compile_ignore(opts.ignore_regex)
    out, ignored = [], 0
    for n, raw in enumerate(text.splitlines(), 1):
        if opts.ignore_blank and not raw.strip():
            ignored += 1
            continue
        if rx and rx.search(raw):
            ignored += 1
            continue
        out.append(Line(n, raw, normalize(raw, opts)))
    if opts.sort_lines:
        out.sort(key=lambda l: (l.key, l.no))
    return out, ignored


def _char_spans(a: str, b: str) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    la, lb = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            if i2 > i1:
                la.append((i1, i2))
            if j2 > j1:
                lb.append((j1, j2))
    return la, lb


def compare(left_text: str, right_text: str, opts: Optional[Options] = None) -> Tuple[List[Row], Stats]:
    opts = opts or Options()
    a, ia = prepare(left_text, opts)
    b, ib = prepare(right_text, opts)
    stats = Stats(len(a), len(b), ignored_left=ia, ignored_right=ib)
    sm = difflib.SequenceMatcher(None, [l.key for l in a], [l.key for l in b],
                                 autojunk=len(a) + len(b) > 40000)
    rows: List[Row] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for x, y in zip(a[i1:i2], b[j1:j2]):
                rows.append(Row("equal", x, y))
            stats.equal += i2 - i1
        elif tag == "delete":
            rows += [Row("delete", x, None) for x in a[i1:i2]]
            stats.removed += i2 - i1
        elif tag == "insert":
            rows += [Row("insert", None, y) for y in b[j1:j2]]
            stats.added += j2 - j1
        else:  # replace: pair lines up, extras become plain deletes/inserts
            left, right = a[i1:i2], b[j1:j2]
            for k in range(max(len(left), len(right))):
                x = left[k] if k < len(left) else None
                y = right[k] if k < len(right) else None
                if x and y:
                    ls, rs = _char_spans(x.text, y.text)
                    rows.append(Row("replace", x, y, ls, rs))
                    stats.changed += 1
                elif x:
                    rows.append(Row("delete", x, None))
                    stats.removed += 1
                else:
                    rows.append(Row("insert", None, y))
                    stats.added += 1
    return rows, stats


def unified(left_text: str, right_text: str, opts: Optional[Options] = None, context: int = 3,
            left_name: str = "left", right_name: str = "right") -> str:
    """Unified diff (like `diff -u`) that honours the ignore options; shows the original text."""
    opts = opts or Options()
    a, _ = prepare(left_text, opts)
    b, _ = prepare(right_text, opts)
    sm = difflib.SequenceMatcher(None, [l.key for l in a], [l.key for l in b],
                                 autojunk=len(a) + len(b) > 40000)
    out = [f"--- {left_name}", f"+++ {right_name}"]
    for group in sm.get_grouped_opcodes(context):
        i1, i2 = group[0][1], group[-1][2]
        j1, j2 = group[0][3], group[-1][4]
        ls = a[i1].no if i1 < len(a) else (a[-1].no if a else 0)
        rs = b[j1].no if j1 < len(b) else (b[-1].no if b else 0)
        out.append(f"@@ -{ls},{i2 - i1} +{rs},{j2 - j1} @@")
        for tag, x1, x2, y1, y2 in group:
            if tag == "equal":
                out += [" " + l.text for l in a[x1:x2]]
                continue
            out += ["-" + l.text for l in a[x1:x2]]
            out += ["+" + l.text for l in b[y1:y2]]
    return "\n".join(out) if len(out) > 2 else ""


def set_compare(left_text: str, right_text: str, opts: Optional[Options] = None):
    """Ignoring order: (only_in_left, only_in_right, in_both) – original text, first occurrence kept."""
    opts = opts or Options()
    a, _ = prepare(left_text, opts)
    b, _ = prepare(right_text, opts)
    ka = {}
    for l in a:
        ka.setdefault(l.key, l.text)
    kb = {}
    for l in b:
        kb.setdefault(l.key, l.text)
    only_a = [t for k, t in ka.items() if k not in kb]
    only_b = [t for k, t in kb.items() if k not in ka]
    both = [t for k, t in ka.items() if k in kb]
    return only_a, only_b, both


def read_text_file(path, max_bytes: int = 25_000_000) -> str:
    """Read a text file whatever its encoding (UTF-8/16 with or without BOM, else Latin-1)."""
    p = Path(path)
    if p.stat().st_size > max_bytes:
        raise ValueError(f"{p.name} is larger than {max_bytes // 1_000_000} MB")
    data = p.read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    if b"\x00" in data[:4096] and not data.startswith(b"\xef\xbb\xbf"):
        try:
            return data.decode("utf-16-le")
        except UnicodeDecodeError:
            raise ValueError(f"{p.name} looks like a binary file") from None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")
