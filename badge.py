"""Tiny anti-aliased stroke font for tab badges like "(3)" with the number in a status colour.
Tk can't colour part of a tab label, so the badge is drawn as a PNG image. Standard library only."""
from __future__ import annotations

import base64
import struct
import zlib
from typing import List, Sequence, Tuple

# Glyphs on a 4-wide x 6-high grid (y down); each is a list of polylines.
GLYPHS = {
    "0": [[(1, 0), (3, 0), (4, 1), (4, 5), (3, 6), (1, 6), (0, 5), (0, 1), (1, 0)]],
    "1": [[(1, 1), (2, 0), (2, 6)], [(1, 6), (3, 6)]],
    "2": [[(0, 1), (1, 0), (3, 0), (4, 1), (4, 2), (0, 6), (4, 6)]],
    "3": [[(0, 0), (4, 0), (2, 2.5), (3, 2.5), (4, 3.5), (4, 5), (3, 6), (1, 6), (0, 5)]],
    "4": [[(3, 6), (3, 0), (0, 4), (4, 4)]],
    "5": [[(4, 0), (0, 0), (0, 2.5), (3, 2.5), (4, 3.5), (4, 5), (3, 6), (1, 6), (0, 5)]],
    "6": [[(3, 0), (1, 0), (0, 1), (0, 5), (1, 6), (3, 6), (4, 5), (4, 3.5), (3, 2.5), (0, 2.5)]],
    "7": [[(0, 0), (4, 0), (1.5, 6)]],
    "8": [[(1, 0), (3, 0), (4, 1), (4, 2), (3, 3), (1, 3), (0, 4), (0, 5), (1, 6), (3, 6), (4, 5), (4, 4),
           (3, 3), (1, 3), (0, 2), (0, 1), (1, 0)]],
    "9": [[(4, 3.5), (1, 3.5), (0, 2.5), (0, 1), (1, 0), (3, 0), (4, 1), (4, 5), (3, 6), (1, 6)]],
    "(": [[(1.6, -0.3), (0.5, 1.4), (0.5, 4.6), (1.6, 6.3)]],
    ")": [[(0.4, -0.3), (1.5, 1.4), (1.5, 4.6), (0.4, 6.3)]],
}
WIDTH = {"(": 2.0, ")": 2.0}


def _rgb(color: str) -> Tuple[int, int, int]:
    c = color.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def render(items: Sequence[Tuple[str, str]], height: int, gap: float = 0.0) -> Tuple[str, int, int]:
    """[(text, '#rrggbb'), ...] -> (base64 PNG, width, height). Glyph height is ~60% of `height`,
    vertically centred, strokes about 1/9 of the glyph height (a bold look at tab-label sizes)."""
    gh = max(6.0, height * 0.58)              # glyph height in px
    scale = gh / 6.0
    half = max(0.75, gh / 11.0)                # half stroke width
    pad = half + 1.0
    top = (height - gh) / 2.0
    segs: List[Tuple[float, float, float, float, int]] = []     # x0, y0, x1, y1, colour index
    colors: List[Tuple[int, int, int]] = []
    x = pad + gap
    for text, color in items:
        colors.append(_rgb(color))
        ci = len(colors) - 1
        for ch in text:
            for line in GLYPHS.get(ch, []):
                for (ax, ay), (bx, by) in zip(line, line[1:]):
                    segs.append((x + ax * scale, top + ay * scale, x + bx * scale, top + by * scale, ci))
            x += (WIDTH.get(ch, 4.0) + 1.6) * scale
    width = int(x - 1.6 * scale + pad + 1)
    rows = []
    for py in range(height):
        row = bytearray([0])
        cy = py + 0.5
        for px in range(width):
            cx = px + 0.5
            best_a, best_c = 0.0, 0
            for x0, y0, x1, y1, ci in segs:
                if cx < min(x0, x1) - half - 1 or cx > max(x0, x1) + half + 1 or \
                        cy < min(y0, y1) - half - 1 or cy > max(y0, y1) + half + 1:
                    continue
                dx, dy = x1 - x0, y1 - y0
                ll = dx * dx + dy * dy
                t = 0.0 if ll == 0 else max(0.0, min(1.0, ((cx - x0) * dx + (cy - y0) * dy) / ll))
                d = ((cx - x0 - t * dx) ** 2 + (cy - y0 - t * dy) ** 2) ** 0.5
                a = max(0.0, min(1.0, half + 0.5 - d))
                if a > best_a:
                    best_a, best_c = a, ci
            r, g, b = colors[best_c] if colors else (0, 0, 0)
            row += bytes((r, g, b, int(best_a * 255)))
        rows.append(bytes(row))

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(b"".join(rows))) + chunk(b"IEND", b""))
    return base64.b64encode(png).decode(), width, height


def count_badge(n: int, number_color: str, paren_color: str, height: int) -> str:
    """'(n)' with the parentheses in the label colour and the number in `number_color`."""
    return render([("(", paren_color), (str(n), number_color), (")", paren_color)], height, gap=1.0)[0]
