#!/usr/bin/env python3
"""Brian's Tools — network admin toolkit for Windows, macOS, and Linux (Tkinter).

Run:  python3 brianstools.py
Standard library only (Python 3.8+ with Tk).
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime
import os
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import ttk

import arinwhois
import cymru
import peeringdb
import badge
import bwcost
import asnsources
import dnsdig
import domainwhois
import logtime
import irrtool
import ouidownload
import subnetcalc_core as core
import pinger
import routetable
import sendto
import sweep
import textdiff
import texttable
import tracert

import version
APP_NAME = version.APP_NAME
SPLIT_LIMIT_V4 = 4096
SPLIT_LIMIT_V6 = 2048
HERE = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))  # PyInstaller-aware

DEFAULT_SUMMARY = """# one per line: CIDR, "ip mask", or a range "a - b"
10.20.0.0/24
10.20.1.0/24
10.20.2.0 255.255.254.0
10.20.4.10 - 10.20.4.200
"""


# --------------------------------------------------------------------------- settings


def _settings_dir(win: str, mac: str, unix: str) -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home())) / win
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / mac
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / unix


def settings_path() -> Path:
    return _settings_dir("BriansTools", "BriansTools", "brianstools") / "settings.json"


def legacy_settings_path() -> Path:
    """Where settings lived when the app was called Subnet Calculator."""
    return _settings_dir("SubnetCalc", "SubnetCalc", "subnetcalc") / "settings.json"


def load_settings() -> dict:
    for path in (settings_path(), legacy_settings_path()):   # carry settings over from the old name
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return {}


def save_settings(data: dict) -> None:
    try:
        p = settings_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


# --------------------------------------------------------------------------- colors

# Brand palettes (see the brand kit): navy #0F172A, cyan #22C3EE, slate #94A3B8 / #64748B, mist #F8FAFC.
# Light mode uses a cool slate-gray page; dark mode uses the logo's navy. Cyan is the accent.
LIGHT_COLORS = {
    "page": "#d9dde3", "chrome": "#f1f5f9", "fg": "#0f172a", "field": "#ffffff", "field_fg": "#0f172a",
    "border": "#64748b", "trough": "#e2e8f0", "button": "#ffffff", "button_active": "#e0f7fd",
    "button_pressed": "#bae6fd", "accent": "#0f172a", "accent_fg": "#ffffff", "accent_active": "#1e293b",
    "heading": "#e2e8f0", "select_bg": "#0f172a", "select_fg": "#ffffff", "tab": "#c3c9d2",
    "tab_active": "#e2e8f0", "disabled": "#94a3b8",
    "muted": "#475569", "chrome_muted": "#475569", "link": "#1d4ed8", "warn": "#9a3412", "error": "#b91c1c",
    "badge_bg": "#0f172a", "badge_fg": "#ffffff", "cal_other": "#475569", "cal_sel": "#0f172a",
    "nomac": "#64748b", "filler": "#e2e8f0",
}
DARK_COLORS = {
    "page": "#0f172a", "chrome": "#0b1120", "fg": "#f8fafc", "field": "#1e293b", "field_fg": "#f8fafc",
    "border": "#475569", "trough": "#1e293b", "button": "#1e293b", "button_active": "#334155",
    "button_pressed": "#475569", "accent": "#22c3ee", "accent_fg": "#0f172a", "accent_active": "#67d8f3",
    "heading": "#334155", "select_bg": "#22c3ee", "select_fg": "#0f172a", "tab": "#1e293b",
    "tab_active": "#334155", "disabled": "#64748b",
    "muted": "#94a3b8", "chrome_muted": "#94a3b8", "link": "#22c3ee", "warn": "#f5a54a", "error": "#ff7b6e",
    "badge_bg": "#164e63", "badge_fg": "#e0f7fd", "cal_other": "#64748b", "cal_sel": "#22c3ee",
    "nomac": "#8b9ab0", "filler": "#334155",
}
APPEARANCES = (("system", "Follow system"), ("light", "Light"), ("dark", "Dark"))
# Mouse selection in text boxes: a light cyan with black text in both modes, so selected text stays
# readable on top of the app's own highlights (green/orange/red/yellow, which also use black text).
TEXT_SELECT = {"background": "#9ee6f7", "foreground": "#000000", "inactive": "#c9f1fb"}
# Highlight backgrounds stay light in both modes, so their text is always black.
HIGHLIGHT_MAC = {"background": "#cdeed5", "foreground": "#000000"}
HIGHLIGHT_DUP = {"background": "#ffd9a0", "foreground": "#000000"}


def system_is_dark(root: tk.Tk) -> bool:
    """Is the operating system set to dark mode? (macOS, Windows 10/11, GNOME/KDE-ish Linux.)"""
    try:
        if root.tk.call("tk", "windowingsystem") == "aqua":
            try:  # Tk 8.6.10+: follows System Settings → Appearance
                return bool(int(root.tk.call("::tk::unsupported::MacWindowStyle", "isdark", root)))
            except tk.TclError:
                pass
            try:
                import subprocess
                out = subprocess.run(["defaults", "read", "-g", "AppleInterfaceStyle"], capture_output=True,
                                     text=True, timeout=2).stdout
                return "dark" in out.lower()
            except (OSError, subprocess.SubprocessError):
                return False
        if sys.platform == "win32":
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            return winreg.QueryValueEx(key, "AppsUseLightTheme")[0] == 0
        theme = os.environ.get("GTK_THEME", "")
        if theme:
            return "dark" in theme.lower()
        import shutil
        import subprocess
        if shutil.which("gsettings"):
            for k in ("color-scheme", "gtk-theme"):
                out = subprocess.run(["gsettings", "get", "org.gnome.desktop.interface", k],
                                     capture_output=True, text=True, timeout=2).stdout
                if "dark" in out.lower():
                    return True
    except Exception:
        pass
    return False


is_dark_mode = system_is_dark          # older name


def match_theme(app, widget):
    """Colour a classic Tk widget (Text, Listbox, Canvas) to match the current theme."""
    c = app.colors
    try:
        if isinstance(widget, tk.Canvas):
            widget.configure(background=c["page"])
            return
        if isinstance(widget, tk.Text):
            widget.configure(background=c["field"], foreground=c["field_fg"], highlightbackground=c["border"],
                             highlightcolor=c["accent"], insertbackground=c["fg"],
                             selectbackground=TEXT_SELECT["background"], selectforeground=TEXT_SELECT["foreground"],
                             inactiveselectbackground=TEXT_SELECT["inactive"])
            # the 'sel' tag also carries the colours, so they win over any highlight tag underneath
            widget.tag_configure("sel", background=TEXT_SELECT["background"], foreground=TEXT_SELECT["foreground"])
            widget.tag_raise("sel")
            return
        widget.configure(background=c["field"], foreground=c["field_fg"], selectbackground=c["select_bg"],
                         selectforeground=c["select_fg"], highlightbackground=c["border"],
                         highlightcolor=c["accent"])
    except tk.TclError:
        pass


# --------------------------------------------------------------------------- helpers


class Debouncer:
    """Run `fn` once input has been quiet for `ms` milliseconds."""

    def __init__(self, widget: tk.Misc, ms: int, fn):
        self.widget, self.ms, self.fn, self.job = widget, ms, fn, None

    def __call__(self, *_):
        if self.job:
            self.widget.after_cancel(self.job)
        self.job = self.widget.after(self.ms, self._run)

    def _run(self):
        self.job = None
        self.fn()


class AutoScrollbar(ttk.Scrollbar):
    """A scrollbar that only shows itself (via grid) when there's something to scroll."""

    def set(self, first, last):
        need = float(first) > 0.0 or float(last) < 1.0
        if need and not self.winfo_ismapped():
            self.grid()
        elif not need and self.winfo_ismapped():
            self.grid_remove()
        super().set(first, last)


def make_tree(parent, columns, widths, sizer=True) -> ttk.Treeview:
    """A Treeview with a vertical scrollbar and a horizontal one that appears when the columns are wider
    than the table. Columns never shrink below their set width (they scroll instead), and the table
    doesn't make the whole page wider: it scrolls sideways on its own."""
    frame = ttk.Frame(parent)
    tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse", height=8)
    for col, width in zip(columns, widths):
        tree.heading(col, text=col)
        tree.column(col, width=width, minwidth=width, stretch=(col != "#"), anchor="w")
    sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    hs = AutoScrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=sb.set, xscrollcommand=hs.set)
    tree.grid(row=0, column=0, sticky="nsew")
    sb.grid(row=0, column=1, sticky="ns")
    hs.grid(row=1, column=0, sticky="ew")
    hs.grid_remove()
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    # Request only the table's height, not its full column width, so a wide table scrolls by itself
    # instead of widening the page. Keep the requested height in step with rows / font / scrollbar.
    frame.grid_propagate(False)
    frame.configure(width=300)

    job = {"id": None}

    def sync():
        try:
            h = tree.winfo_reqheight() + (hs.winfo_reqheight() if hs.winfo_ismapped() else 0)
            grip = getattr(tree, "grip", None)
            if grip is not None:
                h += grip.winfo_reqheight()
            if int(frame.cget("height")) != h:
                frame.configure(height=h)
            job["id"] = frame.after(300, sync)
        except tk.TclError:
            job["id"] = None

    def stop(event):
        if event.widget is frame and job["id"]:
            try:
                frame.after_cancel(job["id"])
            except tk.TclError:
                pass
            job["id"] = None

    def sync_now():
        try:
            h = tree.winfo_reqheight() + (hs.winfo_reqheight() if hs.winfo_ismapped() else 0)
            grip = getattr(tree, "grip", None)
            if grip is not None:
                h += grip.winfo_reqheight()
            frame.configure(height=h)
        except tk.TclError:
            pass

    frame.bind("<Destroy>", stop, add="+")
    sync()
    tree.container = frame  # type: ignore[attr-defined]
    tree.hbar = hs          # type: ignore[attr-defined]
    tree.sync_height = sync_now  # type: ignore[attr-defined]
    if sizer:
        frame.after_idle(lambda: BoxSizer.auto(tree, frame))
    return tree


def _owner_tab(widget):
    """The tool tab a widget belongs to (None inside a dialog window)."""
    w = widget.master
    while w is not None:
        if isinstance(w, tk.Toplevel):
            return None
        if isinstance(w, ttk.Frame) and type(w).__name__.endswith("Tab") and hasattr(w, "app"):
            return w
        w = w.master
    return None


class BoxSizer:
    """A grip along the bottom of a text box or table: drag it to make the box taller or shorter.
    Double-click it to go back to the automatic height. Heights are saved (in lines / rows, so they
    follow the text size) under "box_heights" in settings.json."""

    MIN_UNITS, MAX_UNITS = 2, 300

    @classmethod
    def auto(cls, target, container):
        """Add a grip if `target` is in a tool tab (dialogs resize with their window instead)."""
        try:
            if getattr(target, "grip", None) is not None or not target.winfo_exists():
                return None
        except tk.TclError:
            return None
        tab = _owner_tab(target)
        if tab is None:
            return None
        return cls(tab.app, container, [target], key=cls._key_for(tab, target))

    @staticmethod
    def _key_for(tab, target):
        for name, val in vars(tab).items():
            if val is target:
                return f"{type(tab).__name__}.{name}"
            if isinstance(val, (list, tuple)):
                for i, v in enumerate(val):
                    if v is target:
                        return f"{type(tab).__name__}.{name}{i}"
        return None                               # made on the fly: resizable, but not remembered

    def __init__(self, app, container, targets, key=None):
        self.app, self.container, self.targets, self.key = app, container, list(targets), key
        self.lock = None                          # how the box stretched before the user sized it
        self.user_sized = False
        self.default_units = self._units()
        self.drag = None
        g = self.grip = ttk.Frame(container, style="Grip.TFrame", height=9, cursor="sb_v_double_arrow")
        self.bar = ttk.Frame(g, style="GripBar.TFrame", width=40, height=3, cursor="sb_v_double_arrow")
        self.bar.place(relx=0.5, rely=0.5, anchor="center")
        if container.grid_slaves():
            cols, rows = container.grid_size()
            g.grid(row=rows, column=0, columnspan=max(1, cols), sticky="ew")
        else:
            g.pack(side="bottom", fill="x")
        for t in self.targets:
            t.grip = g
            t.sizer = self
        for w in (g, self.bar):
            w.bind("<ButtonPress-1>", self._press)
            w.bind("<B1-Motion>", self._motion)
            w.bind("<ButtonRelease-1>", self._release)
            w.bind("<Double-Button-1>", self._reset)
            w.bind("<Enter>", lambda e: self.bar.configure(style="GripBarHot.TFrame"))
            w.bind("<Leave>", lambda e: self.drag is None and self.bar.configure(style="GripBar.TFrame"))
        container.bind("<Map>", self._mapped, add="+")
        self._resync()
        saved = (app.settings.get("box_heights") or {}).get(key) if key else None
        if isinstance(saved, (int, float)) and saved >= self.MIN_UNITS:
            self._unlock()
            self._set_units(int(saved))

    # ---- measuring (Text heights are in lines, Treeview heights in rows)

    def _units(self):
        try:
            return int(self.targets[0].cget("height"))
        except (tk.TclError, ValueError):
            return 10

    def _unit_px(self, t):
        if isinstance(t, ttk.Treeview):
            st = ttk.Style(t)
            for name in (t.cget("style"), "Treeview"):
                v = st.lookup(name, "rowheight") if name else ""
                if v not in ("", None):
                    try:
                        return max(1, int(float(v)))
                    except ValueError:
                        pass
            return 20
        try:
            return max(1, tkfont.Font(font=t.cget("font")).metrics("linespace"))
        except tk.TclError:
            return 16

    def _set_units(self, n):
        n = max(self.MIN_UNITS, min(self.MAX_UNITS, int(n)))
        for t in self.targets:
            try:
                if int(t.cget("height")) != n:
                    t.configure(height=n)
            except tk.TclError:
                pass
        self._resync()

    def _resync(self):
        for t in self.targets:
            f = getattr(t, "sync_height", None)
            if f:
                f()
        w = self.container
        while w is not None:                      # let the page's scroll area catch up right away
            if isinstance(w, ScrollPage):
                w._layout_soon()
                break
            w = w.master

    # ---- stretching: a box the user has sized keeps that size instead of filling spare space

    def _unlock(self):
        """Stop the box stretching into spare space. Safe to repeat: a view that's packed again
        (switching views re-applies expand) is caught when it's shown (<Map>)."""
        self.user_sized = True
        c = self.container
        try:
            mgr = c.winfo_manager()
            if mgr == "pack":
                expand = str(c.pack_info().get("expand")) in ("1", "true", "True")
                if expand:
                    c.pack_configure(expand=False)
                if self.lock is None or expand:
                    self.lock = ("pack", expand or (self.lock or ("pack", False))[1])
            elif mgr == "grid":
                info = c.grid_info()
                master, row = info["in"], int(info["row"])
                weight = master.grid_rowconfigure(row)["weight"]
                if weight:
                    master.grid_rowconfigure(row, weight=0)
                if self.lock is None or weight:
                    self.lock = ("grid", master, row, weight)
        except (tk.TclError, KeyError, ValueError):
            pass

    def _mapped(self, e):
        if e.widget is self.container and self.user_sized:
            self._unlock()

    def _relock(self):
        lock, self.lock = self.lock, None
        self.user_sized = False
        try:
            if lock and lock[0] == "pack" and lock[1]:
                self.container.pack_configure(expand=True)
            elif lock and lock[0] == "grid" and lock[3]:
                lock[1].grid_rowconfigure(lock[2], weight=lock[3])
        except tk.TclError:
            pass

    # ---- mouse

    def _press(self, e):
        t = self.targets[0]
        unit = self._unit_px(t)
        units = self._units()
        extra = t.winfo_reqheight() - units * unit          # borders, padding, table heading
        shown = (t.winfo_height() - extra) / unit if t.winfo_ismapped() else units
        self._unlock()
        start = max(self.MIN_UNITS, int(round(shown)))
        self._set_units(start)                              # no jump when a stretched box is grabbed
        self.drag = (e.y_root, start, unit)
        self.bar.configure(style="GripBarHot.TFrame")
        return "break"

    def _motion(self, e):
        if not self.drag:
            return
        y0, start, unit = self.drag
        self._set_units(start + round((e.y_root - y0) / unit))
        return "break"

    def _release(self, e):
        if not self.drag:
            return
        self.drag = None
        self.bar.configure(style="GripBar.TFrame")
        if self.key:
            self.app.settings.setdefault("box_heights", {})[self.key] = self._units()
        return "break"

    def _reset(self, e=None):
        self.drag = None
        self._relock()
        self._set_units(self.default_units)
        if self.key:
            (self.app.settings.get("box_heights") or {}).pop(self.key, None)
        self.app.flash("Box height reset")
        return "break"


def autosize_columns(tree: ttk.Treeview, font, columns=None, max_px: int = 600, pad: int = 24):
    """Widen columns to fit their heading and contents (up to max_px), so long values can be read by
    scrolling the table sideways instead of being cut off."""
    cols = columns or tree["columns"]
    heading_font = tkfont.nametofont("TkHeadingFont")
    for col in cols:
        want = heading_font.measure(str(tree.heading(col, "text"))) + pad
        for iid in tree.get_children(""):
            want = max(want, font.measure(str(tree.set(iid, col))) + pad)
        want = min(max_px, want)
        if want > int(tree.column(col, "width")):
            tree.column(col, width=want, minwidth=want)


class ScrollPage(ttk.Frame):
    """A frame with scrollbars that appear when they're needed.

    Put content in `.body`. When the window is big enough the content stretches to fill it
    (so tables grow); when it's smaller than the content needs, the page scrolls instead:
    vertically (scrollbar on the right) and horizontally (scrollbar along the bottom).
    """

    def __init__(self, master):
        super().__init__(master)
        self.canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0,
                                yscrollincrement=16, xscrollincrement=16)   # one wheel step = 16 px
        self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.hbar = ttk.Scrollbar(self, orient="horizontal", command=self.canvas.xview)
        self.canvas.configure(yscrollcommand=self.vbar.set, xscrollcommand=self.hbar.set)
        self.vbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self._hbar_shown = False
        self.body = ttk.Frame(self.canvas)
        self._win = self.canvas.create_window(0, 0, window=self.body, anchor="nw")
        # Window resizes send a burst of <Configure> events (a flood of them during a live resize on
        # macOS). Re-laying out the whole page for each one made the app hang, so they're coalesced.
        self._layout_job = None
        self.canvas.bind("<Configure>", self._layout_soon)
        self.body.bind("<Configure>", self._layout_soon)
        # Match the canvas background to the themed frame background.
        bg = ttk.Style(self).lookup("TFrame", "background")
        if bg:
            self.canvas.configure(background=bg)
        self._size = None
        self._watch_job = self.after(250, self._watch)
        self.bind("<Destroy>", self._stop_watch, add="+")

    def _measure(self):
        return (self.canvas.winfo_width(), self.canvas.winfo_height(),
                self.body.winfo_reqwidth(), self.body.winfo_reqheight())

    def _layout_soon(self, _=None):
        if self._layout_job is None:
            self._layout_job = self.after(30, self._layout_now)

    def _layout_now(self):
        self._layout_job = None
        try:
            self._layout()
        except tk.TclError:
            pass

    def _layout(self, _=None):
        cw, ch, rw, rh = self._measure()
        if cw <= 1:                                  # not on screen yet
            return
        need_h = rw > cw
        if need_h != self._hbar_shown:               # show/hide the bottom scrollbar as needed
            self._hbar_shown = need_h
            if need_h:
                self.hbar.pack(side="bottom", fill="x", before=self.canvas)
            else:
                self.hbar.pack_forget()
                self.canvas.xview_moveto(0)
            # the canvas changes height; its own <Configure> brings us back here with the new size
        width, height = max(cw, rw), max(ch, rh)
        self._size = (cw, ch, rw, rh)
        self.canvas.itemconfigure(self._win, width=width, height=height)
        self.canvas.configure(scrollregion=(0, 0, width, height))

    def _watch(self):
        """The body is given a fixed size, so it gets no <Configure> when its content grows or
        shrinks (e.g. a details pane appearing). Check the requested size a few times a second."""
        try:
            if self.winfo_ismapped() and self._measure() != self._size:
                self._layout()
            self._watch_job = self.after(250, self._watch)
        except tk.TclError:
            self._watch_job = None                   # window closed

    def _stop_watch(self, event):
        if event.widget is self and self._layout_job:
            try:
                self.after_cancel(self._layout_job)
            except tk.TclError:
                pass
            self._layout_job = None
        if event.widget is self and self._watch_job:
            try:
                self.after_cancel(self._watch_job)
            except tk.TclError:
                pass
            self._watch_job = None

    def scroll(self, units: int):
        self._layout()
        if self.body.winfo_reqheight() > self.canvas.winfo_height():
            self.canvas.yview_scroll(units, "units")

    def scroll_x(self, units: int):
        self._layout()
        if self.body.winfo_reqwidth() > self.canvas.winfo_width():
            self.canvas.xview_scroll(units, "units")


# --------------------------------------------------------------------------- calculator tab


class CalculatorTab(ttk.Frame):
    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        self.history: list[str] = []
        self.iface = None
        self.split_prefix = {4: app.settings.get("split4", 28), 6: app.settings.get("split6", 64)}

        # Input row
        top = ttk.Frame(self)
        top.pack(fill="x")
        self.back_btn = ttk.Button(top, text="‹ Back", width=7, command=self.go_back, state="disabled")
        self.back_btn.pack(side="left", padx=(0, 8))
        self.input_var = tk.StringVar(value=app.settings.get("input", "192.168.10.77/26"))
        self.entry = ttk.Entry(top, textvariable=self.input_var, font=app.big_mono)
        self.entry.pack(side="left", fill="x", expand=True)
        ttk.Label(self, text="e.g.  10.0.0.1/24   ·   10.0.0.1 255.255.255.0   ·   10.0.0.1 0.0.0.255   ·   2001:db8::/48",
                  style="Hint.TLabel").pack(anchor="w", pady=(4, 8))

        # Header: subnet, type badge, copy-as menu
        head = ttk.Frame(self)
        head.pack(fill="x")
        self.title_lbl = ttk.Label(head, style="Title.TLabel")
        self.title_lbl.pack(side="left")
        self.type_lbl = ttk.Label(head, style="Badge.TLabel")
        self.type_lbl.pack(side="left", padx=10)
        self.copy_as = ttk.Menubutton(head, text="Copy as ▾")
        self.copy_menu = tk.Menu(self.copy_as, tearoff=False)
        self.copy_as["menu"] = self.copy_menu
        self.copy_as.pack(side="right")
        self.customer_btn = ttk.Button(head, text="Copy Subnet Summary", command=self.copy_customer)
        self.customer_btn.pack(side="right", padx=(0, 6))

        # Details on top, split table below (the whole page scrolls if the window is short).
        self.error_lbl = ttk.Label(self, style="Hint.TLabel")
        self.details = ttk.Frame(self)
        self.details.pack(fill="x", pady=(8, 8))
        self.details.columnconfigure(1, weight=1)

        # Split section
        self.split_frame = ttk.Frame(self)
        self.split_frame.pack(fill="both", expand=True)
        ttk.Separator(self.split_frame).pack(fill="x", pady=(0, 8))
        self.split_shown = True
        bar = ttk.Frame(self.split_frame)
        bar.pack(fill="x")
        ttk.Label(bar, text="Split into  /").pack(side="left")
        self.split_var = tk.StringVar()
        self.spin = ttk.Spinbox(bar, from_=0, to=32, width=4, textvariable=self.split_var,
                                command=self.on_split_change, font=app.mono)
        self.spin.pack(side="left", padx=(2, 10))
        self.spin.bind("<Return>", lambda e: self.on_split_change())
        self.spin.bind("<FocusOut>", lambda e: self.on_split_change())
        self.split_info = ttk.Label(bar, style="Hint.TLabel")
        self.split_info.pack(side="left")
        ttk.Button(bar, text="Copy list", command=self.copy_split_list).pack(side="right")
        self.split_note = ttk.Label(self.split_frame, style="Hint.TLabel")
        self.split_note.pack(anchor="w")

        self.tree_holder = ttk.Frame(self.split_frame)
        self.tree_holder.pack(fill="both", expand=True, pady=(4, 4))
        self.tree4 = make_tree(self.tree_holder, ("#", "Subnet", "Host range", "Broadcast"), (50, 160, 260, 130))
        self.tree6 = make_tree(self.tree_holder, ("#", "Subnet", "Last address"), (50, 260, 300))
        for tree in (self.tree4, self.tree6):
            tree.bind("<Double-1>", self.open_selected)
            tree.bind("<Return>", self.open_selected)
            tree.bind(app.right_click, self.tree_menu)

        foot = ttk.Frame(self.split_frame)
        foot.pack(fill="x")
        ttk.Label(foot, text="Double-click a subnet (or select it and press Return) to open it in IP Calc.",
                  style="Hint.TLabel").pack(side="left")
        ttk.Button(foot, text="Open Selected", command=self.open_selected).pack(side="right")

        self.debounce = Debouncer(self, 120, self.refresh)
        self.input_var.trace_add("write", self.debounce)
        self.refresh()

    # ---- state changes

    def load(self, text: str, remember: bool = True):
        """Put a subnet into the input field (drill-down)."""
        current = self.input_var.get()
        if text == current:
            return
        if remember:
            self.history.append(current)
        self.input_var.set(text)
        self.refresh()
        self.entry.icursor("end")

    def go_back(self, *_):
        if self.history:
            self.input_var.set(self.history.pop())
            self.refresh()

    def on_split_change(self):
        if not self.iface:
            return
        try:
            value = int(self.split_var.get())
        except ValueError:
            value = self.split_prefix[self.iface.version]
        net = self.iface.network
        value = max(net.prefixlen, min(net.max_prefixlen, value))
        self.split_prefix[self.iface.version] = value
        self.render_split()

    # ---- rendering

    def refresh(self):
        self.back_btn.configure(state="normal" if self.history else "disabled")
        self.error_lbl.pack_forget()
        text = self.input_var.get()
        self.iface = core.parse(text)
        for w in self.details.winfo_children():
            w.destroy()

        if self.iface is None:
            self.title_lbl.configure(text="")
            self.type_lbl.configure(text="")
            self.copy_as.state(["disabled"])
            self.customer_btn.state(["disabled"])
            self.error_lbl.configure(text="Enter an IPv4 or IPv6 address with a prefix length or netmask."
                                     if not text.strip() else
                                     "Not a valid address. Try 10.0.0.1/24, 10.0.0.1 255.255.255.0, or 2001:db8::/48.")
            self.error_lbl.pack(anchor="w", before=self.details)
            self.show_split(False)
            return

        iface = self.iface
        self.title_lbl.configure(text=str(iface.network))
        self.type_lbl.configure(text=f" {core.address_type(iface.ip)} ")
        self.copy_as.state(["!disabled"])
        self.customer_btn.state(["!disabled"])
        self.copy_menu.delete(0, "end")
        for label, value in core.copy_formats(iface):
            self.copy_menu.add_command(label=f"{label}:   {value}", command=lambda v=value: self.app.copy(v))

        for r, (label, value) in enumerate(core.details(iface)):
            ttk.Label(self.details, text=label, style="Key.TLabel").grid(row=r, column=0, sticky="e", padx=(0, 12), pady=1)
            var = tk.StringVar(value=value)
            ent = ttk.Entry(self.details, textvariable=var, state="readonly", font=self.app.mono,
                            style="Value.TEntry")
            ent.var = var  # keep a reference
            ent.grid(row=r, column=1, sticky="ew", pady=1)
            ttk.Button(self.details, text="Copy", style="Small.TButton",
                       command=lambda v=value: self.app.copy(v)).grid(row=r, column=2, padx=(6, 0), pady=1)

        has_split = iface.network.prefixlen < iface.network.max_prefixlen
        self.show_split(has_split)
        if has_split:
            self.render_split()

    def show_split(self, show: bool):
        if show and not self.split_shown:
            self.split_frame.pack(fill="both", expand=True)
        elif not show and self.split_shown:
            self.split_frame.pack_forget()
        self.split_shown = show

    def render_split(self):
        iface = self.iface
        net = iface.network
        v = iface.version
        prefix = max(net.prefixlen, min(net.max_prefixlen, self.split_prefix[v]))
        self.spin.configure(from_=net.prefixlen, to=net.max_prefixlen)
        self.split_var.set(str(prefix))

        limit = SPLIT_LIMIT_V4 if v == 4 else SPLIT_LIMIT_V6
        subs = core.split(net, prefix, limit)
        total = core.subnet_count(net, prefix)
        if v == 4:
            per = core.usable_hosts_text(subs[0]).split(" ")[0] if subs else "0"
            self.split_info.configure(text=f"{core.grouped(total)} subnet{'s' if total != 1 else ''} × {per} usable")
        else:
            self.split_info.configure(text=f"{core.count_text(prefix - net.prefixlen)} subnets")
        self.split_note.configure(
            text=f"Showing the first {core.grouped(len(subs))} of {core.grouped(total)}." if total > len(subs) else "")

        tree = self.tree4 if v == 4 else self.tree6
        other = self.tree6 if v == 4 else self.tree4
        other.container.pack_forget()
        tree.container.pack(fill="both", expand=True)
        tree.delete(*tree.get_children())
        for i, s in enumerate(subs, 1):
            if v == 4:
                first, last = core.host_range(s)
                values = (i, str(s), f"{first} – {last}", str(s.broadcast_address))
            else:
                values = (i, str(s), str(s.broadcast_address))
            tree.insert("", "end", iid=str(s), values=values)
        self.current_subs = subs

    # ---- split table actions

    def active_tree(self) -> ttk.Treeview:
        return self.tree6 if self.iface and self.iface.version == 6 else self.tree4

    def open_selected(self, *_):
        sel = self.active_tree().selection()
        if sel:
            self.load(sel[0])
        return "break"

    def tree_menu(self, event):
        tree = event.widget
        row = tree.identify_row(event.y)
        if not row:
            return
        tree.selection_set(row)
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label=f"Open {row} in IP Calc", command=lambda: self.load(row))
        menu.add_command(label=f"Copy {row}", command=lambda: self.app.copy(row))
        menu.add_command(label=f"Ping sweep {row}", command=lambda: self.app.goto_sweep(row))
        self.app.popup_tree_menu(menu, event)

    def copy_customer(self):
        """Network, gateway (first address), usable range, mask and broadcast, ready to paste in an email."""
        if self.iface:
            self.app.copy(core.customer_details(self.iface))

    def copy_split_list(self):
        self.app.copy("\n".join(str(s) for s in getattr(self, "current_subs", [])))


# --------------------------------------------------------------------------- summarize tab


class SummarizeTab(ttk.Frame):
    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True)

        left = ttk.Frame(paned, padding=(0, 0, 8, 0))
        ttk.Label(left, text="Input", style="Title.TLabel").pack(anchor="w")
        self.text = scrolled_text(left, app, width=34, height=20)
        self.text.container.pack(fill="both", expand=True, pady=4)
        self.text.insert("1.0", app.settings.get("summary", DEFAULT_SUMMARY))
        ttk.Label(left, text="Lines starting with # are ignored. Commas also separate entries.",
                  style="Hint.TLabel", wraplength=280).pack(anchor="w")
        paned.add(left, weight=1)

        right = ttk.Frame(paned, padding=(8, 0, 0, 0))
        bar = ttk.Frame(right)
        bar.pack(fill="x")
        self.count_lbl = ttk.Label(bar, style="Title.TLabel")
        self.count_lbl.pack(side="left")
        ttk.Button(bar, text="Copy", command=self.copy_all).pack(side="right")
        self.tree = make_tree(right, ("Block", "Addresses"), (200, 110))
        self.tree.container.pack(fill="both", expand=True, pady=4)
        self.tree.bind("<Double-1>", self.open_selected)
        self.tree.bind("<Return>", self.open_selected)
        self.tree.bind(app.right_click, self.tree_menu)
        ttk.Label(right, text="Double-click a block to open it in IP Calc.",
                  style="Hint.TLabel").pack(anchor="w")
        self.info = ttk.Frame(right)
        self.info.pack(fill="x", pady=(8, 0))
        self.info.columnconfigure(1, weight=1)
        self.warn_lbl = ttk.Label(right, style="Warn.TLabel", wraplength=360)
        self.warn_lbl.pack(anchor="w", pady=(6, 0))
        self.bad_lbl = ttk.Label(right, style="Error.TLabel", wraplength=360)
        self.bad_lbl.pack(anchor="w")
        paned.add(right, weight=1)

        self.debounce = Debouncer(self, 200, self.refresh)
        self.text.bind("<<Modified>>", self._modified)
        self.refresh()

    def _modified(self, _):
        if self.text.edit_modified():
            self.text.edit_modified(False)
            self.debounce()

    def get_text(self) -> str:
        return self.text.get("1.0", "end-1c")

    def refresh(self):
        r = core.summarize(self.get_text())
        self.result = r
        self.count_lbl.configure(text=f"Aggregated ({len(r.aggregated)})")
        self.tree.delete(*self.tree.get_children())
        for n in r.aggregated:
            self.tree.insert("", "end", iid=str(n), values=(str(n), core.grouped(n.num_addresses)))

        for w in self.info.winfo_children():
            w.destroy()
        rows = [("Total addresses", core.grouped(r.total_addresses))]
        if r.supernet:
            rows += [("Covering supernet", str(r.supernet)), ("Supernet size", core.grouped(r.supernet.num_addresses))]
        for i, (k, v) in enumerate(rows):
            ttk.Label(self.info, text=k, style="Key.TLabel").grid(row=i, column=0, sticky="e", padx=(0, 12), pady=2)
            var = tk.StringVar(value=v)
            e = ttk.Entry(self.info, textvariable=var, state="readonly", font=self.app.mono, style="Value.TEntry")
            e.var = var
            e.grid(row=i, column=1, sticky="ew", pady=2)
            ttk.Button(self.info, text="Copy", style="Small.TButton",
                       command=lambda v=v: self.app.copy(v)).grid(row=i, column=2, padx=(6, 0), pady=1)

        extra = (r.supernet.num_addresses - r.total_addresses) if r.supernet else 0
        self.warn_lbl.configure(text=f"The supernet also covers {core.grouped(extra)} addresses not in your list."
                                if extra > 0 else "")
        self.bad_lbl.configure(text=("Couldn't parse: " + ", ".join(r.invalid)) if r.invalid else "")

    def open_selected(self, *_):
        sel = self.tree.selection()
        if sel:
            self.app.open_in_calculator(sel[0])
        return "break"

    def tree_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label=f"Open {row} in IP Calc", command=lambda: self.app.open_in_calculator(row))
        menu.add_command(label=f"Copy {row}", command=lambda: self.app.copy(row))
        self.app.popup_tree_menu(menu, event)

    def copy_all(self):
        self.app.copy("\n".join(str(n) for n in self.result.aggregated))


# --------------------------------------------------------------------------- bits & bytes tab


class BitsTab(ttk.Frame):
    """Data-size converter: one amount in, every unit out."""

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        s = app.settings

        bar = ttk.Frame(self)
        bar.pack(fill="x")
        ttk.Label(bar, text="Amount:").pack(side="left")
        self.amount_var = tk.StringVar(value=s.get("bits_amount", "1000000000"))
        self.amount = ttk.Entry(bar, textvariable=self.amount_var, width=20, font=app.mono)
        self.amount.pack(side="left", padx=(4, 12))
        ttk.Label(bar, text="Units:").pack(side="left")
        unit = s.get("bits_unit", "bits")
        self.unit_var = tk.StringVar(value=unit if unit in core.UNIT_NAMES else "bits")
        ttk.Combobox(bar, textvariable=self.unit_var, values=core.UNIT_NAMES, state="readonly",
                     width=11).pack(side="left", padx=(4, 8))
        ttk.Button(bar, text="Calculate", command=self.refresh).pack(side="left")
        notation = s.get("bits_notation", '"kilo" is 1024')
        self.notation_var = tk.StringVar(value=notation if notation in core.NOTATIONS else '"kilo" is 1024')
        ttk.Combobox(bar, textvariable=self.notation_var, values=list(core.NOTATIONS), state="readonly",
                     width=14).pack(side="right", padx=(4, 0))
        ttk.Label(bar, text="Notation Type:").pack(side="right")
        ttk.Label(self, text="Accepts 1234, 1,234, 1.5, or 1e9.  Results update as you type.",
                  style="Hint.TLabel").pack(anchor="w", pady=(4, 10))

        self.title_lbl = ttk.Label(self, style="Title.TLabel")
        self.title_lbl.pack(anchor="w")
        self.note_lbl = ttk.Label(self, style="Hint.TLabel")
        self.note_lbl.pack(anchor="w", pady=(0, 8))
        self.error_lbl = ttk.Label(self, style="Error.TLabel")

        self.grid_frame = ttk.Frame(self)
        self.grid_frame.pack(fill="x")
        self.grid_frame.columnconfigure(1, weight=1)
        self.value_vars = {}
        for r, name in enumerate(core.UNIT_NAMES):
            ttk.Label(self.grid_frame, text=name, style="Key.TLabel").grid(
                row=r, column=0, sticky="e", padx=(0, 12), pady=1)
            var = tk.StringVar()
            ttk.Entry(self.grid_frame, textvariable=var, state="readonly", font=app.mono,
                      style="Value.TEntry").grid(row=r, column=1, sticky="ew", pady=1)
            ttk.Button(self.grid_frame, text="Copy", style="Small.TButton",
                       command=lambda v=var: self.app.copy(v.get())).grid(row=r, column=2, padx=(6, 0), pady=1)
            self.value_vars[name] = var

        self.debounce = Debouncer(self, 120, self.refresh)
        for var in (self.amount_var, self.unit_var, self.notation_var):
            var.trace_add("write", self.debounce)
        self.amount.bind("<Return>", lambda e: self.refresh())
        self.refresh()

    def refresh(self):
        amount = core.parse_amount(self.amount_var.get())
        unit = self.unit_var.get()
        base = core.NOTATIONS[self.notation_var.get()]
        if amount is None:
            self.title_lbl.configure(text="")
            self.note_lbl.configure(text="")
            self.error_lbl.configure(text="Enter a positive number, e.g. 1500, 1,500, 1.5, or 1e9.")
            self.error_lbl.pack(anchor="w", before=self.grid_frame, pady=(0, 8))
            for var in self.value_vars.values():
                var.set("")
            return
        self.error_lbl.pack_forget()
        self.title_lbl.configure(text=f"{core.format_amount(amount)} {unit}")
        self.note_lbl.configure(text=core.notation_note(unit, base))
        for name, value in core.convert_data(amount, unit, base):
            self.value_vars[name].set(core.format_amount(value))


# --------------------------------------------------------------------------- time zones tab


class TimeZoneTab(ttk.Frame):
    """Convert a date/time in one zone to any set of zones."""

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        problem = core.timezone_support()
        if problem:
            ttk.Label(self, text=problem, style="Error.TLabel").pack(anchor="w")
            self.available = False
            return
        self.available = True
        s = app.settings
        self.zones = core.all_timezones()
        zone_set = set(self.zones)

        # Input row
        bar = ttk.Frame(self)
        bar.pack(fill="x")
        ttk.Label(bar, text="Date & time:").pack(side="left")
        self.when_var = tk.StringVar()
        self.when = ttk.Entry(bar, textvariable=self.when_var, width=20, font=app.mono)
        self.when.pack(side="left", padx=(4, 6))
        ttk.Button(bar, text="Now", command=self.set_now).pack(side="left")
        source = s.get("tz_source") or core.local_timezone_name()
        self.source_var = tk.StringVar(value=source if source in zone_set else "UTC")
        self.source = ttk.Combobox(bar, textvariable=self.source_var, values=self.zones, width=26)
        self.source.pack(side="right")
        ttk.Label(bar, text="From time zone:").pack(side="right", padx=(12, 4))
        ttk.Label(self, text="e.g.  2026-10-10 14:30   ·   10/10/2026 2:30 PM   ·   2026-10-10T14:30.  "
                  "Type in the time zone box to jump to a zone.", style="Hint.TLabel").pack(anchor="w", pady=(4, 8))

        self.src_lbl = ttk.Label(self, style="Title.TLabel")
        self.src_lbl.pack(anchor="w")
        self.note_lbl = ttk.Label(self, style="Warn.TLabel", wraplength=760)
        self.error_lbl = ttk.Label(self, style="Error.TLabel")

        body = ttk.Frame(self)
        self.body = body
        body.pack(fill="both", expand=True, pady=(8, 0))
        body.columnconfigure(1, weight=1)
        body.rowconfigure(1, weight=1)

        # Left: all zones, searchable
        ttk.Label(body, text="All time zones", style="Key.TLabel").grid(row=0, column=0, sticky="w")
        left = ttk.Frame(body)
        left.grid(row=1, column=0, sticky="nsw", padx=(0, 12))
        self.filter_var = tk.StringVar()
        filt = ttk.Entry(left, textvariable=self.filter_var)
        filt.pack(fill="x")
        ttk.Label(left, text="Search, e.g. tokyo, europe, new york", style="Hint.TLabel").pack(anchor="w", pady=(2, 4))
        lb_frame = ttk.Frame(left)
        lb_frame.pack(fill="both", expand=True)
        self.listbox = tk.Listbox(lb_frame, selectmode="extended", width=24, height=16, font=app.mono,
                                  activestyle="none", exportselection=False)
        match_theme(app, self.listbox)
        lsb = ttk.Scrollbar(lb_frame, orient="vertical", command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=lsb.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        lsb.pack(side="right", fill="y")
        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=(6, 0))
        ttk.Button(btns, text="Add →", command=self.add_selected).pack(side="left")
        ttk.Button(btns, text="Add all shown", command=self.add_all_shown).pack(side="left", padx=6)
        self.listbox.bind("<Double-1>", lambda e: self.add_selected())
        self.listbox.bind("<Return>", lambda e: self.add_selected())
        self.filter_var.trace_add("write", lambda *_: self.fill_list())
        filt.bind("<Return>", lambda e: self.add_selected() if self.listbox.size() == 1 else None)

        # Right: converted times
        head = ttk.Frame(body)
        head.grid(row=0, column=1, sticky="ew")
        self.count_lbl = ttk.Label(head, style="Key.TLabel")
        self.count_lbl.pack(side="left")
        right = ttk.Frame(body)
        right.grid(row=1, column=1, sticky="nsew")
        self.tree = make_tree(right, ("Time zone", "Date & time", "Abbr", "UTC offset", "Day"),
                              (170, 175, 55, 95, 42))
        self.tree.configure(selectmode="extended", height=16)
        self.tree.column("Abbr", stretch=False)
        self.tree.column("UTC offset", stretch=False)
        self.tree.column("Day", stretch=False, anchor="center")
        self.tree.container.pack(fill="both", expand=True)
        self.tree.bind("<Delete>", lambda e: self.remove_selected())
        self.tree.bind("<BackSpace>", lambda e: self.remove_selected())
        self.tree.bind("<Double-1>", self.use_as_source)
        self.tree.bind(app.right_click, self.tree_menu)
        rb = ttk.Frame(right)
        rb.pack(fill="x", pady=(6, 0))
        ttk.Button(rb, text="Remove", command=self.remove_selected).pack(side="left")
        ttk.Button(rb, text="Clear", command=self.clear).pack(side="left", padx=6)
        ttk.Button(rb, text="Reset to defaults", command=self.reset).pack(side="left")
        ttk.Button(rb, text="Copy all", command=self.copy_all).pack(side="right")
        ttk.Label(right, text="Double-click a row to convert from that zone instead. Delete removes a row.",
                  style="Hint.TLabel").pack(anchor="w", pady=(4, 0))

        saved = [z for z in s.get("tz_targets", core.DEFAULT_TARGET_ZONES) if z in zone_set]
        self.targets: list = saved if "tz_targets" in s else [z for z in core.DEFAULT_TARGET_ZONES if z in zone_set]

        self.debounce = Debouncer(self, 150, self.refresh)
        self.when_var.trace_add("write", self.debounce)
        self.source_var.trace_add("write", self.debounce)
        self.source.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        self.source.bind("<KeyRelease>", self.jump_source)
        self.fill_list()
        self.set_now()

    # ---- zone list

    def fill_list(self):
        words = self.filter_var.get().lower().replace("_", " ").split()
        self.listbox.delete(0, "end")
        for z in self.zones:
            hay = z.lower().replace("_", " ")
            if all(w in hay for w in words):
                self.listbox.insert("end", z)

    def add_zones(self, zones):
        added = [z for z in zones if z not in self.targets]
        self.targets.extend(added)
        self.refresh()
        if added:
            self.app.flash(f"Added {len(added)} time zone{'s' if len(added) != 1 else ''}")

    def add_selected(self):
        self.add_zones([self.listbox.get(i) for i in self.listbox.curselection()])
        return "break"

    def add_all_shown(self):
        self.add_zones(list(self.listbox.get(0, "end")))

    def remove_selected(self):
        sel = set(self.tree.selection())
        if sel:
            self.targets = [z for z in self.targets if z not in sel]
            self.refresh()
        return "break"

    def clear(self):
        self.targets = []
        self.refresh()

    def reset(self):
        self.targets = [z for z in core.DEFAULT_TARGET_ZONES if z in self.zones]
        self.refresh()

    # ---- source / time

    def set_now(self):
        name = self.source_var.get()
        try:
            now = datetime.now(core.get_zone(name))
        except Exception:
            now = datetime.now()
        self.when_var.set(now.strftime("%Y-%m-%d %H:%M"))
        self.refresh()

    def jump_source(self, event):
        """Typing in the zone box: show matching zones in the dropdown list."""
        if event.keysym in ("Return", "Up", "Down", "Escape", "Tab"):
            return
        text = self.source_var.get().lower().replace("_", " ")
        matches = [z for z in self.zones if text in z.lower().replace("_", " ")] if text else self.zones
        self.source.configure(values=matches or self.zones)

    def use_as_source(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        local = self.rows_by_zone[row].local
        self.source_var.set(row)
        self.when_var.set(local.strftime("%Y-%m-%d %H:%M"))
        self.refresh()
        return "break"

    # ---- output

    def show_message(self, label: ttk.Label, text: str):
        label.configure(text=text)
        if text:
            label.pack(anchor="w", before=self.body)
        else:
            label.pack_forget()

    def refresh(self):
        if not self.available:
            return
        self.count_lbl.configure(text=f"Converted to {len(self.targets)} time zone{'s' if len(self.targets) != 1 else ''}")
        self.tree.delete(*self.tree.get_children())
        self.rows_by_zone = {}
        naive = core.parse_datetime(self.when_var.get())
        source = self.source_var.get().strip()
        if source not in self.zones:
            self.src_lbl.configure(text="")
            self.show_message(self.note_lbl, "")
            self.show_message(self.error_lbl, f"Unknown time zone: {source or '(empty)'}. Pick one from the list.")
            return
        if naive is None:
            self.src_lbl.configure(text="")
            self.show_message(self.note_lbl, "")
            self.show_message(self.error_lbl, "Enter a date and time, e.g. 2026-10-10 14:30 or 10/10/2026 2:30 PM.")
            return
        self.show_message(self.error_lbl, "")
        src, note, rows = core.convert_time(naive, source, self.targets)
        self.src_lbl.configure(text=f"{source}:  {core.describe(src)}    ·    Epoch {int(src.timestamp())}")
        self.show_message(self.note_lbl, note or "")
        for r in rows:
            day = "" if r.day_shift == 0 else f"{r.day_shift:+d}"
            self.tree.insert("", "end", iid=r.zone, values=(
                r.zone, r.local.strftime("%a %Y-%m-%d %H:%M"), r.abbrev, core.format_offset(r.offset), day))
            self.rows_by_zone[r.zone] = r

    def row_text(self, zone: str) -> str:
        return texttable.tree_table(self.tree, [zone])

    def copy_all(self):
        self.app.copy(texttable.tree_table(self.tree))

    def tree_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        if row not in self.tree.selection():
            self.tree.selection_set(row)
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label=f"Copy {row}", command=lambda: self.app.copy(self.row_text(row)))
        menu.add_command(label=f"Convert from {row}",
                         command=lambda: self.use_as_source(type("E", (), {"y": event.y})()))
        menu.add_command(label="Remove", command=self.remove_selected)
        self.app.popup_tree_menu(menu, event)


# --------------------------------------------------------------------------- add / subtract time tab


def link(parent, text, command, style="Link.TLabel") -> ttk.Label:
    lbl = ttk.Label(parent, text=text, style=style, cursor="hand2")
    lbl.bind("<Button-1>", lambda e: command())
    return lbl


class CalendarPopup(tk.Toplevel):
    """Small month calendar; calls on_pick(date) when a day is clicked."""

    def __init__(self, master, initial, on_pick, anchor=None):
        super().__init__(master)
        if anchor is not None:  # open just below the button that opened it
            self.geometry(f"+{anchor.winfo_rootx()}+{anchor.winfo_rooty() + anchor.winfo_height() + 4}")
        self.title("Pick a date")
        self.resizable(False, False)
        self.transient(master.winfo_toplevel())
        self.on_pick = on_pick
        self.year, self.month = initial.year, initial.month
        self.selected = initial
        top = ttk.Frame(self, padding=8)
        top.pack(fill="both")
        nav = ttk.Frame(top)
        nav.pack(fill="x")
        ttk.Button(nav, text="‹", width=3, command=lambda: self.shift(-1)).pack(side="left")
        self.title_lbl = ttk.Label(nav, style="Title.TLabel", anchor="center")
        self.title_lbl.pack(side="left", fill="x", expand=True)
        ttk.Button(nav, text="›", width=3, command=lambda: self.shift(1)).pack(side="right")
        self.grid_frame = ttk.Frame(top)
        self.grid_frame.pack(pady=(6, 0))
        link(top, "Today", lambda: self.pick(datetime.now().date())).pack(anchor="w", pady=(6, 0))
        self.bind("<Escape>", lambda e: self.destroy())
        self.draw()
        self.grab_set()

    def shift(self, months):
        total = self.year * 12 + self.month - 1 + months
        self.year, self.month = divmod(total, 12)
        self.month += 1
        self.draw()

    def draw(self):
        import calendar
        for w in self.grid_frame.winfo_children():
            w.destroy()
        self.title_lbl.configure(text=f"{calendar.month_name[self.month]} {self.year}")
        for c, name in enumerate(core.WEEKDAY_NAMES):
            ttk.Label(self.grid_frame, text=name[:2], style="Key.TLabel", anchor="center",
                      width=4).grid(row=0, column=c)
        for r, week in enumerate(calendar.Calendar(firstweekday=0).monthdatescalendar(self.year, self.month), 1):
            for c, day in enumerate(week):
                style = "CalSel.TButton" if day == self.selected else (
                    "Cal.TButton" if day.month == self.month else "CalOther.TButton")
                ttk.Button(self.grid_frame, text=str(day.day), width=3, style=style,
                           command=lambda d=day: self.pick(d)).grid(row=r, column=c, padx=1, pady=1)

    def pick(self, day):
        self.on_pick(day)
        self.destroy()


class AddTimeTab(ttk.Frame):
    """Add or subtract years … seconds from a start date/time."""

    FIELDS_DATE = ("Years", "Months", "Weeks", "Days")
    FIELDS_TIME = ("Hours", "Minutes", "Seconds")

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        mono = app.mono
        form = ttk.Frame(self)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)

        # ---- left: start date / time
        left = ttk.Frame(form)
        left.grid(row=0, column=0, sticky="nw")
        ttk.Label(left, text="Start Date", style="Title.TLabel").grid(row=0, column=0, columnspan=6, sticky="w")
        self.month_v, self.day_v, self.year_v = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.hour_v, self.min_v, self.sec_v = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for col, (lbl, var, w, ph) in enumerate([("Month:", self.month_v, 4, "mm"), ("Day:", self.day_v, 4, "dd"),
                                                  ("Year:", self.year_v, 6, "yyyy")]):
            ttk.Label(left, text=lbl, style="Field.TLabel").grid(row=1, column=col * 2, sticky="w", pady=(6, 0))
            ttk.Entry(left, textvariable=var, width=w, font=mono, justify="center").grid(row=2, column=col * 2, sticky="w")
            if col < 2:
                ttk.Label(left, text="/").grid(row=2, column=col * 2 + 1, padx=3)
        ttk.Label(left, text="Date:", style="Field.TLabel").grid(row=1, column=6, sticky="w", padx=(8, 0), pady=(6, 0))
        self.pick_btn = ttk.Button(left, text="▦ Pick", width=7, command=self.open_calendar)
        self.pick_btn.grid(row=2, column=6, padx=(8, 0), sticky="w")
        link(left, "Today", self.set_today).grid(row=3, column=0, columnspan=6, sticky="w", pady=(2, 10))

        self.time_labels = []
        self.time_entries = []
        for col, (lbl, var) in enumerate([("Hour:", self.hour_v), ("Minute:", self.min_v), ("Second:", self.sec_v)]):
            l = ttk.Label(left, text=lbl, style="Field.TLabel")
            l.grid(row=4, column=col * 2, sticky="w")
            e = ttk.Entry(left, textvariable=var, width=4, font=mono, justify="center")
            e.grid(row=5, column=col * 2, sticky="w")
            self.time_labels.append(l)
            self.time_entries.append(e)
            if col < 2:
                ttk.Label(left, text=":").grid(row=5, column=col * 2 + 1, padx=3)
        tl = ttk.Frame(left)
        tl.grid(row=6, column=0, columnspan=7, sticky="w", pady=(2, 8))
        link(tl, "Now", self.set_now).pack(side="left")
        ttk.Label(tl, text="  |  ", style="Hint.TLabel").pack(side="left")
        link(tl, "Start of Day", lambda: self.set_time(0, 0, 0)).pack(side="left")
        ttk.Label(tl, text="  |  ", style="Hint.TLabel").pack(side="left")
        link(tl, "Noon", lambda: self.set_time(12, 0, 0)).pack(side="left")
        self.use_time = tk.BooleanVar(value=True)
        ttk.Checkbutton(left, text="Include time of day", variable=self.use_time,
                        command=self.toggle_time).grid(row=7, column=0, columnspan=7, sticky="w")
        ttk.Label(left, text="Hours use the 24-hour clock (e.g. 14 = 2 PM).",
                  style="Hint.TLabel").grid(row=8, column=0, columnspan=7, sticky="w")

        # ---- right: what to add
        right = ttk.Frame(form)
        right.grid(row=0, column=1, sticky="ne", padx=(24, 0))
        ttk.Label(right, text="Add/Subtract:", style="Field.TLabel").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.op_v = tk.StringVar(value="(+) Add")
        ttk.Combobox(right, textvariable=self.op_v, values=["(+) Add", "(−) Subtract"], state="readonly",
                     width=12).grid(row=2, column=0, sticky="w", padx=(0, 12))
        self.amount_vars = {}
        for col, name in enumerate(self.FIELDS_DATE, 1):
            ttk.Label(right, text=name + ":", style="Field.TLabel").grid(row=1, column=col, sticky="w", pady=(6, 0))
            var = tk.StringVar()
            ttk.Entry(right, textvariable=var, width=7, font=mono, justify="center").grid(
                row=2, column=col, sticky="w", padx=(0, 10))
            self.amount_vars[name] = var
        for col, name in enumerate(self.FIELDS_TIME, 1):
            ttk.Label(right, text=name + ":", style="Field.TLabel").grid(row=4, column=col, sticky="w", pady=(16, 0))
            var = tk.StringVar()
            ttk.Entry(right, textvariable=var, width=7, font=mono, justify="center").grid(
                row=5, column=col, sticky="w", padx=(0, 10))
            self.amount_vars[name] = var
        link(right, "Clear", self.clear_amounts).grid(row=3, column=1, sticky="w", pady=(2, 0))

        # weekday filter
        self.only_weekdays = tk.BooleanVar(value=False)
        ttk.Checkbutton(right, text="Include only certain weekdays", variable=self.only_weekdays,
                        command=self.toggle_weekdays).grid(row=6, column=0, columnspan=5, sticky="w", pady=(14, 0))
        self.wd_frame = ttk.Frame(right)
        self.wd_vars = []
        for d, name in enumerate(core.WEEKDAY_NAMES):
            v = tk.BooleanVar(value=d < 5)
            ttk.Checkbutton(self.wd_frame, text=name, variable=v, command=self.refresh).pack(side="left", padx=(0, 6))
            self.wd_vars.append(v)
        link(self.wd_frame, "Mon–Fri", lambda: self.set_weekdays(range(5))).pack(side="left", padx=(6, 0))
        ttk.Label(right, text="Applies to weeks and days, e.g. 10 business days.",
                  style="Hint.TLabel").grid(row=8, column=0, columnspan=5, sticky="w")

        # ---- repeat + calculate
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", pady=(14, 0))
        self.repeat = tk.BooleanVar(value=False)
        ttk.Checkbutton(bottom, text="Repeat", variable=self.repeat, command=self.refresh).pack(side="left")
        self.repeat_n = tk.StringVar(value="10")
        ttk.Spinbox(bottom, from_=2, to=500, width=5, textvariable=self.repeat_n, command=self.refresh).pack(
            side="left", padx=(6, 4))
        ttk.Label(bottom, text="times", style="Hint.TLabel").pack(side="left")
        ttk.Button(bottom, text="Calculate New Date", style="Accent.TButton", command=self.refresh).pack(side="right")

        # ---- results
        ttk.Separator(self).pack(fill="x", pady=12)
        self.result_title = ttk.Label(self, style="Big.TLabel")
        self.result_title.pack(anchor="w")
        self.error_lbl = ttk.Label(self, style="Error.TLabel")
        self.note_lbl = ttk.Label(self, style="Warn.TLabel", wraplength=760)
        self.details = ttk.Frame(self)
        self.details.pack(fill="x", pady=(8, 0))
        self.details.columnconfigure(1, weight=1)
        self.repeat_frame = ttk.Frame(self)
        self.repeat_tree = make_tree(self.repeat_frame, ("#", "Date & time", "Day", "From start"), (50, 220, 110, 330))
        self.repeat_tree.container.pack(fill="both", expand=True, pady=(8, 0))
        rb = ttk.Frame(self.repeat_frame)
        rb.pack(fill="x", pady=(4, 0))
        ttk.Button(rb, text="Copy list", command=self.copy_repeats).pack(side="right")

        self.debounce = Debouncer(self, 150, self.refresh)
        for v in [self.month_v, self.day_v, self.year_v, self.hour_v, self.min_v, self.sec_v, self.op_v,
                  self.repeat_n, *self.amount_vars.values()]:
            v.trace_add("write", self.debounce)
        self.set_now()

    # ---- quick setters

    def set_date(self, d):
        self.month_v.set(f"{d.month:02d}")
        self.day_v.set(f"{d.day:02d}")
        self.year_v.set(str(d.year))

    def set_time(self, h, m, s):
        self.use_time.set(True)
        self.toggle_time()
        self.hour_v.set(f"{h:02d}")
        self.min_v.set(f"{m:02d}")
        self.sec_v.set(f"{s:02d}")

    def set_today(self):
        self.set_date(datetime.now())

    def set_now(self):
        now = datetime.now()
        self.set_date(now)
        self.set_time(now.hour, now.minute, now.second)

    def open_calendar(self):
        start = self.read_start(quiet=True)
        CalendarPopup(self, (start or datetime.now()).date(), self.set_date, anchor=self.pick_btn)

    def toggle_time(self):
        state = "normal" if self.use_time.get() else "disabled"
        for e in self.time_entries:
            e.configure(state=state)
        self.refresh()

    def toggle_weekdays(self):
        if self.only_weekdays.get():
            self.wd_frame.grid(row=7, column=0, columnspan=5, sticky="w", pady=(4, 0))
        else:
            self.wd_frame.grid_forget()
        self.refresh()

    def set_weekdays(self, days):
        for d, v in enumerate(self.wd_vars):
            v.set(d in days)
        self.refresh()

    def clear_amounts(self):
        for v in self.amount_vars.values():
            v.set("")

    # ---- reading input

    def read_start(self, quiet=False):
        try:
            y, mo, d = int(self.year_v.get()), int(self.month_v.get()), int(self.day_v.get())
            if self.use_time.get():
                h = int(self.hour_v.get() or 0)
                mi = int(self.min_v.get() or 0)
                s = int(self.sec_v.get() or 0)
            else:
                h = mi = s = 0
            return datetime(y, mo, d, h, mi, s)
        except ValueError:
            return None

    def read_amounts(self):
        out = {}
        for name, var in self.amount_vars.items():
            text = var.get().strip().replace(",", "")
            if not text:
                out[name] = 0
                continue
            try:
                out[name] = int(text)
            except ValueError:
                raise ValueError(f"{name} must be a whole number.")
        return out

    # ---- output

    def fmt(self, dt: datetime) -> str:
        return f"{dt:%Y-%m-%d %H:%M:%S}" if self.use_time.get() else f"{dt:%Y-%m-%d}"

    def fmt_long(self, dt: datetime) -> str:
        base = f"{dt:%A}, {dt:%B} {dt.day}, {dt.year}"
        if self.use_time.get():
            hour12 = dt.hour % 12 or 12
            base += f"  at  {dt:%H:%M:%S}  ({hour12}:{dt:%M:%S} {'AM' if dt.hour < 12 else 'PM'})"
        return base

    def show(self, label, text):
        label.configure(text=text)
        if text:
            label.pack(anchor="w", before=self.details)
        else:
            label.pack_forget()

    def refresh(self):
        for w in self.details.winfo_children():
            w.destroy()
        self.repeat_tree.delete(*self.repeat_tree.get_children())
        self.results = []
        start = self.read_start()
        if start is None:
            self.result_title.configure(text="")
            self.show(self.note_lbl, "")
            self.show(self.error_lbl, "Enter a valid start date (and time): month 1–12, a day that exists in that "
                                      "month, hour 0–23, minute and second 0–59.")
            self.repeat_frame.pack_forget()
            return
        try:
            amounts = self.read_amounts()
            sign = -1 if self.op_v.get().startswith("(−)") else 1
            weekdays = ({d for d, v in enumerate(self.wd_vars) if v.get()}
                        if self.only_weekdays.get() else core.ALL_WEEKDAYS)
            if not weekdays:
                raise ValueError("Pick at least one weekday.")
            kwargs = {k.lower(): v for k, v in amounts.items()}
            repeats = 1
            if self.repeat.get():
                try:
                    repeats = max(1, min(500, int(self.repeat_n.get())))
                except ValueError:
                    repeats = 1
            current, notes = start, []
            for _ in range(repeats):
                r = core.date_math(current, sign=sign, weekdays=weekdays, **kwargs)
                notes.extend(n for n in r.notes if n not in notes)
                current = r.result
                self.results.append(current)
        except (ValueError, OverflowError) as exc:
            msg = str(exc)
            if "out of range" in msg or isinstance(exc, OverflowError):
                msg = "The result is outside the supported range (years 1–9999)."
            self.result_title.configure(text="")
            self.show(self.note_lbl, "")
            self.show(self.error_lbl, msg)
            self.repeat_frame.pack_forget()
            return

        self.show(self.error_lbl, "")
        self.show(self.note_lbl, "  ".join(notes))
        end = self.results[0]
        self.result_title.configure(text=f"Result:  {self.fmt_long(end)}")
        delta = end - start
        rows = [
            ("Start", self.fmt(start) + f"  ({start:%a})"),
            ("Result", self.fmt(end) + f"  ({end:%a})"),
            ("Difference", core.describe_span(start, end)),
            ("Total days", f"{abs(delta.total_seconds()) / 86400:,.6f}".rstrip("0").rstrip(".")),
            ("Total hours", f"{abs(delta.total_seconds()) / 3600:,.4f}".rstrip("0").rstrip(".")),
            ("Day of year", f"{end.timetuple().tm_yday} of {366 if end.year % 4 == 0 and (end.year % 100 or end.year % 400 == 0) else 365}"),
            ("ISO week", f"Week {end.isocalendar()[1]} of {end.isocalendar()[0]}"),
        ]
        local_zone = self.app.local_zone
        local_epoch = core.epoch_seconds(end, local_zone)
        rows += [
            (f"Epoch ({local_zone})", str(local_epoch)),
            ("Epoch ms", str(local_epoch * 1000)),
            ("Epoch (if UTC)", str(core.epoch_seconds(end, "UTC"))),
        ]
        for i, (k, v) in enumerate(rows):
            ttk.Label(self.details, text=k, style="Key.TLabel").grid(row=i, column=0, sticky="e", padx=(0, 12), pady=1)
            var = tk.StringVar(value=v)
            e = ttk.Entry(self.details, textvariable=var, state="readonly", font=self.app.mono, style="Value.TEntry")
            e.var = var
            e.grid(row=i, column=1, sticky="ew", pady=1)
            ttk.Button(self.details, text="Copy", style="Small.TButton",
                       command=lambda v=v: self.app.copy(v)).grid(row=i, column=2, padx=(6, 0), pady=1)

        if self.repeat.get() and len(self.results) > 1:
            self.repeat_frame.pack(fill="both", expand=True, pady=(8, 0))
            for i, dt in enumerate(self.results, 1):
                self.repeat_tree.insert("", "end", values=(i, self.fmt(dt), f"{dt:%A}", core.describe_span(start, dt)))
        else:
            self.repeat_frame.pack_forget()

    def copy_repeats(self):
        self.app.copy(texttable.tree_table(self.repeat_tree))


# --------------------------------------------------------------------------- MAC format tab

DEFAULT_MACS = """Paste MAC addresses, one per line, or any text that contains them
(e.g. 'show mac address-table' output). Other text is ignored.

 100    0011.22aa.bbcc    DYNAMIC     Gi1/0/1
 100    00-11-22-AA-BB-CD DYNAMIC     Gi1/0/2
00:11:22:aa:bb:cc
001122AABBCE
"""


def scrolled_text(parent, app, sizer=True, **kw) -> tk.Text:
    frame = ttk.Frame(parent)
    kw.setdefault("wrap", "none")
    text = tk.Text(frame, font=app.mono, undo=True, relief="solid", borderwidth=1, **kw)
    ys = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
    xs = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
    text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
    text.grid(row=0, column=0, sticky="nsew")
    ys.grid(row=0, column=1, sticky="ns")
    xs.grid(row=1, column=0, sticky="ew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    if kw["wrap"] != "none":
        xs.grid_remove()                     # wrapped text never scrolls sideways
    text.container = frame
    match_theme(app, text)
    if sizer:
        frame.after_idle(lambda: BoxSizer.auto(text, frame))
    return text


def repaint_text(text: tk.Text):
    """Redraw a text box's visible lines from scratch (no pixel copying), cheaply: re-configuring a tag
    that spans the whole text invalidates every displayed line without re-measuring the document."""
    try:
        if not text.winfo_exists():
            return
        text.tag_add("_repaint", "1.0", "end")
        text.tag_lower("_repaint")                   # lowest priority: never overrides real highlighting
        text.tag_configure("_repaint", underline=False)
    except tk.TclError:
        pass


def setup_mac_tags(app, text: tk.Text):
    text.tag_configure("mac", **HIGHLIGHT_MAC)
    text.tag_configure("dup", **HIGHLIGHT_DUP)
    text.tag_configure("nomac", foreground=app.colors["nomac"])
    text.tag_raise("sel")


def highlight_macs(text: tk.Text, content: str, dups: set):
    """Green = MAC found, orange = duplicate, grey = line with no MAC."""
    for tag in ("mac", "dup", "nomac"):
        text.tag_remove(tag, "1.0", "end")
    for n, line in enumerate(content.splitlines(), 1):
        matches = list(core.MAC_REGEX.finditer(line))
        if not matches and line.strip():
            text.tag_add("nomac", f"{n}.0", f"{n}.end")
        for m in matches:
            tag = "dup" if core.normalize_mac(m.group(0)) in dups else "mac"
            text.tag_add(tag, f"{n}.{m.start()}", f"{n}.{m.end()}")


_PLAIN_DIGITS = str.maketrans({chr(0x1D7EC + i): str(i) for i in range(10)})


def plain_digits(text: str) -> str:
    """Turn the bold digits used for emphasis in tables (𝟭𝟱𝟬𝟬) back into ordinary ones."""
    return text.translate(_PLAIN_DIGITS)


def make_sortable(tree: ttk.Treeview, numeric=()):
    """Click a column heading to sort by it; click again to reverse."""
    state = {"col": None, "rev": False}

    def key_for(col, value):
        if col in numeric:
            try:
                return (0, float(str(value).replace(",", "")))
            except ValueError:
                return (1, 0.0)
        return (0, str(value).lower())

    def sort(col):
        rev = state["rev"] = (not state["rev"]) if state["col"] == col else False
        state["col"] = col
        items = [(key_for(col, tree.set(i, col)), i) for i in tree.get_children("")]
        items.sort(reverse=rev)
        for idx, (_, iid) in enumerate(items):
            tree.move(iid, "", idx)
        for c in tree["columns"]:
            tree.heading(c, text=c + ((" ▼" if rev else " ▲") if c == col else ""))

    for c in tree["columns"]:
        tree.heading(c, command=lambda c=c: sort(c))


class MacTab(ttk.Frame):
    """Find MAC addresses in pasted text and rewrite them in a chosen format."""

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        s = app.settings

        # ---- options
        opts = ttk.Frame(self)
        opts.pack(fill="x")
        style = s.get("mac_style", "colon")
        self.style_v = tk.StringVar(value=style if style in core.MAC_STYLES else "colon")
        self.case_v = tk.StringVar(value=s.get("mac_case", "lower"))
        self.mode_v = tk.StringVar(value=s.get("mac_mode", "list"))
        self.dedupe_v = tk.BooleanVar(value=s.get("mac_dedupe", False))

        box = ttk.LabelFrame(opts, text=" Convert to ", padding=(10, 4))
        box.pack(side="left", fill="y")
        for key, label in core.MAC_STYLES.items():
            ttk.Radiobutton(box, text=label, value=key, variable=self.style_v,
                            command=self.refresh).pack(anchor="w")
        box = ttk.LabelFrame(opts, text=" Letters ", padding=(10, 4))
        box.pack(side="left", fill="y", padx=10)
        ttk.Radiobutton(box, text="lowercase  (aa:bb…)", value="lower", variable=self.case_v,
                        command=self.refresh).pack(anchor="w")
        ttk.Radiobutton(box, text="UPPERCASE  (AA:BB…)", value="upper", variable=self.case_v,
                        command=self.refresh).pack(anchor="w")
        box = ttk.LabelFrame(opts, text=" Output ", padding=(10, 4))
        box.pack(side="left", fill="y")
        ttk.Radiobutton(box, text="MAC addresses only, one per line", value="list", variable=self.mode_v,
                        command=self.refresh).pack(anchor="w")
        ttk.Radiobutton(box, text="Keep original lines, convert MACs in place", value="inplace",
                        variable=self.mode_v, command=self.refresh).pack(anchor="w")
        self.dedupe_cb = ttk.Checkbutton(box, text="Remove duplicates", variable=self.dedupe_v, command=self.refresh)
        self.dedupe_cb.pack(anchor="w")

        # ---- input / output
        panes = ttk.Frame(self)
        panes.pack(fill="both", expand=True, pady=(10, 0))
        panes.columnconfigure(0, weight=1, uniform="io")
        panes.columnconfigure(1, weight=1, uniform="io")
        panes.rowconfigure(1, weight=1)
        head_l = ttk.Frame(panes)
        head_l.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ttk.Label(head_l, text="Source", style="Title.TLabel").pack(side="left")
        ttk.Button(head_l, text="Clear", style="Small.TButton", command=self.clear).pack(side="right")
        ttk.Button(head_l, text="Paste", style="Small.TButton", command=self.paste).pack(side="right", padx=4)
        head_r = ttk.Frame(panes)
        head_r.grid(row=0, column=1, sticky="ew", padx=(6, 0))
        ttk.Label(head_r, text="Converted", style="Title.TLabel").pack(side="left")
        ttk.Button(head_r, text="Copy", style="Small.TButton", command=self.copy_output).pack(side="right")

        self.src = scrolled_text(panes, app, height=16, width=40)
        self.src.container.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=(4, 0))
        self.out = scrolled_text(panes, app, height=16, width=40)
        self.out.container.grid(row=1, column=1, sticky="nsew", padx=(6, 0), pady=(4, 0))
        self.out.configure(state="disabled")
        setup_mac_tags(app, self.src)
        self.src.insert("1.0", s.get("mac_input", DEFAULT_MACS))
        ttk.Label(panes, text="Green = MAC found · Orange = duplicate MAC · Grey = line with no MAC",
                  style="Hint.TLabel").grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        # ---- stats + details
        self.stats_lbl = ttk.Label(self, style="Field.TLabel")
        self.stats_lbl.pack(anchor="w", pady=(10, 4))
        lists = ttk.Frame(self)
        lists.pack(fill="x")
        lists.columnconfigure(0, weight=1, uniform="l")
        lists.columnconfigure(1, weight=1, uniform="l")
        self.dup_lbl = ttk.Label(lists, text="Duplicates", style="Key.TLabel")
        self.dup_lbl.grid(row=0, column=0, sticky="w")
        self.skip_lbl = ttk.Label(lists, text="Lines with no MAC address", style="Key.TLabel")
        self.skip_lbl.grid(row=0, column=1, sticky="w", padx=(12, 0))
        self.dup_tree = make_tree(lists, ("MAC address", "Times seen"), (220, 100))
        self.dup_tree.configure(height=5)
        self.dup_tree.container.grid(row=1, column=0, sticky="nsew")
        self.skip_tree = make_tree(lists, ("Line", "Text"), (60, 300))
        self.skip_tree.configure(height=5)
        self.skip_tree.column("Line", stretch=False)
        self.skip_tree.container.grid(row=1, column=1, sticky="nsew", padx=(12, 0))
        self.dup_tree.bind(app.right_click, self.dup_menu)
        ttk.Button(lists, text="Copy duplicates", style="Small.TButton",
                   command=self.copy_duplicates).grid(row=2, column=0, sticky="w", pady=(4, 0))

        self.debounce = Debouncer(self, 200, self.refresh)
        self.src.bind("<<Modified>>", self._modified)
        self.refresh()

    # ---- actions

    def _modified(self, _):
        if self.src.edit_modified():
            self.src.edit_modified(False)
            self.debounce()

    def get_text(self) -> str:
        return self.src.get("1.0", "end-1c")

    def clear(self):
        self.src.delete("1.0", "end")
        self.refresh()

    def paste(self):
        try:
            text = self.app.root.clipboard_get()
        except tk.TclError:
            return
        self.src.delete("1.0", "end")
        self.src.insert("1.0", text)
        self.refresh()

    def copy_output(self):
        self.app.copy("\n".join(self.result.output_lines))

    def copy_duplicates(self):
        upper = self.case_v.get() == "upper"
        self.app.copy("\n".join(core.format_mac(m, self.style_v.get(), upper) for m, _ in self.result.duplicates))

    def dup_menu(self, event):
        row = self.dup_tree.identify_row(event.y)
        if not row:
            return
        self.dup_tree.selection_set(row)
        value = self.dup_tree.item(row, "values")[0]
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label=f"Copy {value}", command=lambda: self.app.copy(value))
        self.app.popup_tree_menu(menu, event)

    # ---- output

    def refresh(self):
        text = self.get_text()
        style, upper = self.style_v.get(), self.case_v.get() == "upper"
        in_place = self.mode_v.get() == "inplace"
        self.dedupe_cb.configure(state="disabled" if in_place else "normal")
        r = core.convert_macs(text, style, upper, in_place=in_place, dedupe=self.dedupe_v.get() and not in_place)
        self.result = r

        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        self.out.insert("1.0", "\n".join(r.output_lines))
        self.out.configure(state="disabled")

        highlight_macs(self.src, text, {m for m, _ in r.duplicates})

        dup_extra = sum(c - 1 for _, c in r.duplicates)
        self.stats_lbl.configure(text=(
            f"Lines: {r.line_count}    ·    MACs found: {len(r.macs)}    ·    Unique: {r.unique_count}    ·    "
            f"Duplicates: {len(r.duplicates)}" + (f" ({dup_extra} extra)" if dup_extra else "") +
            f"    ·    Lines with no MAC: {len(r.lines_without_mac)}"))

        self.dup_tree.delete(*self.dup_tree.get_children())
        for mac, count in r.duplicates:
            self.dup_tree.insert("", "end", values=(core.format_mac(mac, style, upper), count))
        self.dup_lbl.configure(text=f"Duplicates ({len(r.duplicates)})")
        self.skip_tree.delete(*self.skip_tree.get_children())
        for n, line in r.lines_without_mac:
            self.skip_tree.insert("", "end", values=(n, line))
        self.skip_lbl.configure(text=f"Lines with no MAC address ({len(r.lines_without_mac)})")


# --------------------------------------------------------------------------- MAC lookup tab

DEFAULT_LOOKUP = """Paste MAC addresses or any text containing them; other text is ignored.
 100    0000.0c07.ac0a    STATIC      Vl100      <- HSRP group 10
 100    0000.5e00.0114    STATIC      Vl100      <- VRRP VRID 20
 100    0007.b400.0102    DYNAMIC     Gi1/0/3    <- GLBP group 1
01:00:5e:00:00:05   33:33:00:00:00:01   01:80:c2:00:00:0e
f0:b2:b9:12:34:56
"""


def app_folder() -> Path:
    """Folder the app runs from (the folder containing the .app on macOS builds)."""
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve()
        for parent in exe.parents:
            if parent.suffix == ".app":
                return parent.parent
        return exe.parent
    return Path(__file__).resolve().parent


def oui_home() -> Path:
    """Where Download oui.txt saves the vendor list: next to settings.json."""
    return settings_path().parent / "oui.txt"


def move_old_oui_download(settings: dict) -> None:
    """Earlier versions downloaded oui.txt into Documents. Move it next to settings.json, once."""
    saved = settings.get("oui_path", "")
    if not saved:
        return
    old, new = Path(saved), oui_home()
    try:
        if old == new or old.name != "oui.txt" or old.parent != ouidownload.documents_folder() \
                or not old.is_file():
            return
        if not new.exists():
            import shutil
            new.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(old), str(new))
        settings["oui_path"] = str(new)
    except OSError:
        pass                                   # leave it where it is; it still loads from there


def find_oui_txt(saved: str = "") -> Path:
    candidates = []
    if saved:
        candidates.append(Path(saved))
    candidates += [oui_home(), app_folder() / "oui.txt", Path.cwd() / "oui.txt",
                   Path.home() / "Downloads" / "oui.txt"]
    for c in candidates:
        if c.is_file():
            return c
    return None


class MacLookupTab(ttk.Frame):
    """Vendor lookup (from a local IEEE oui.txt) plus multicast / FHRP identification."""

    COLUMNS = ("MAC address", "Vendor", "Country", "Type", "Details", "Count")

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        s = app.settings
        self.db = None
        self.db_path = None
        self.loading = False

        # ---- vendor database status
        dbbar = ttk.Frame(self)
        dbbar.pack(fill="x")
        ttk.Label(dbbar, text="Vendor database:", style="Field.TLabel").pack(side="left")
        self.db_lbl = ttk.Label(dbbar, style="Key.TLabel")
        self.dl_stop = None             # threading.Event while a download is running
        self.auto_tried = False
        self.db_text = ""
        link(dbbar, "IEEE site", self.open_download).pack(side="right", padx=(8, 0))
        ttk.Button(dbbar, text="Reload", style="Small.TButton", command=self.reload).pack(side="right", padx=(8, 0))
        ttk.Button(dbbar, text="Choose file…", style="Small.TButton", command=self.choose_file).pack(
            side="right", padx=(8, 0))
        self.dl_btn = ttk.Button(dbbar, text="Download oui.txt", style="Small.TButton", command=self.download)
        self.dl_btn.pack(side="right")
        self.db_lbl.configure(width=1)                   # a long path is clipped instead of widening the page
        self.db_lbl.pack(side="left", padx=(6, 8), fill="x", expand=True)   # packed last: buttons keep their room
        self.db_err = ttk.Label(self, style="Warn.TLabel", wraplength=900)

        # ---- source
        head = ttk.Frame(self)
        head.pack(fill="x", pady=(10, 0))
        self.head = head
        ttk.Label(head, text="Source", style="Title.TLabel").pack(side="left")
        ttk.Button(head, text="Clear", style="Small.TButton", command=self.clear).pack(side="right")
        ttk.Button(head, text="Paste", style="Small.TButton", command=self.paste).pack(side="right", padx=4)
        self.src = scrolled_text(self, app, height=9)
        self.src.container.pack(fill="x", pady=(4, 0))
        setup_mac_tags(app, self.src)
        self.src.insert("1.0", s.get("lookup_input", DEFAULT_LOOKUP))
        ttk.Label(self, text="Green = MAC found · Orange = duplicate MAC · Grey = line with no MAC",
                  style="Hint.TLabel").pack(anchor="w", pady=(2, 0))

        # ---- options + stats
        opts = ttk.Frame(self)
        opts.pack(fill="x", pady=(10, 4))
        ttk.Label(opts, text="Show MACs as:").pack(side="left")
        self.style_names = {v: k for k, v in core.MAC_STYLES.items()}
        style = s.get("lookup_style", "colon")
        self.style_v = tk.StringVar(value=core.MAC_STYLES.get(style, core.MAC_STYLES["colon"]))
        ttk.Combobox(opts, textvariable=self.style_v, values=list(core.MAC_STYLES.values()),
                     state="readonly", width=26).pack(side="left", padx=(4, 10))
        self.upper_v = tk.BooleanVar(value=s.get("lookup_upper", False))
        ttk.Checkbutton(opts, text="UPPERCASE", variable=self.upper_v, command=self.refresh).pack(side="left")
        self.filter_v = tk.StringVar()
        ttk.Entry(opts, textvariable=self.filter_v, width=24).pack(side="right")
        ttk.Label(opts, text="Filter results:").pack(side="right", padx=(0, 4))
        self.stats_lbl = ttk.Label(self, style="Field.TLabel", wraplength=950)
        self.stats_lbl.pack(anchor="w", pady=(2, 4))

        # ---- results
        self.tree = make_tree(self, self.COLUMNS, (175, 190, 75, 105, 380, 62))
        self.tree.configure(height=12, selectmode="extended")
        for col in ("Country", "Count"):
            self.tree.column(col, stretch=False, anchor="center")
        self.tree.column("MAC address", stretch=False)
        self.tree.column("Type", stretch=False)
        self.tree.container.pack(fill="both", expand=True)
        make_sortable(self.tree, numeric=("Count",))
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)
        self.tree.bind(app.right_click, self.tree_menu)
        self.tree.tag_configure("fhrp", foreground=app.colors["link"])
        self.tree.tag_configure("mcast", foreground=app.colors["warn"])
        self.tree.tag_configure("unknown", foreground=app.colors["muted"])

        btns = ttk.Frame(self)
        btns.pack(fill="x", pady=(4, 0))
        ttk.Label(btns, text="Click a heading to sort. Blue = HSRP/VRRP/GLBP · Orange = multicast/broadcast · "
                             "Grey = vendor not found", style="Hint.TLabel").pack(side="left")
        ttk.Button(btns, text="Copy table", style="Small.TButton", command=self.copy_all).pack(side="right")
        ttk.Button(btns, text="Copy selected", style="Small.TButton", command=self.copy_selected).pack(
            side="right", padx=4)

        ttk.Label(self, text="Selected", style="Key.TLabel").pack(anchor="w", pady=(8, 0))
        self.detail = scrolled_text(self, app, height=5, wrap="word")
        self.detail.container.pack(fill="x")
        self.detail.configure(state="disabled")

        self.debounce = Debouncer(self, 250, self.refresh)
        self.src.bind("<<Modified>>", self._modified)
        self.style_v.trace_add("write", lambda *_: self.refresh())
        self.filter_v.trace_add("write", self.debounce)
        self.rows = {}
        move_old_oui_download(app.settings)
        self.reload(initial=True)

    # ---- vendor database

    def reload(self, initial=False):
        path = find_oui_txt(self.app.settings.get("oui_path", ""))
        if path is None:
            self.db, self.db_path = None, None
            self.db_lbl.configure(text="oui.txt not found")
            self.dl_btn.configure(text="Download oui.txt")
            self.show_db_error(
                f"Click Download oui.txt to save the latest IEEE list to {oui_home()}, "
                "or click Choose file… to use one you already have. Special addresses (multicast, "
                "HSRP/VRRP/GLBP) are still identified without it.")
            self.refresh()
            if not initial and self.winfo_ismapped():
                self.on_shown()
            return
        self.start_load(path)

    def start_load(self, path: Path):
        import threading
        self.loading = True
        self.db_lbl.configure(text=f"Loading {path} …")
        self.show_db_error("")
        result = {}

        def work():
            try:
                db = core.OuiDatabase()
                for f in core.find_oui_files(path):
                    db.load_file(f)
                result["db"] = db
            except Exception as exc:          # unreadable file etc.
                result["error"] = str(exc)

        thread = threading.Thread(target=work, daemon=True)
        thread.start()

        def poll():
            if thread.is_alive():
                self.after(100, poll)
                return
            self.loading = False
            if "error" in result:
                self.db, self.db_path = None, None
                self.db_lbl.configure(text="Couldn't read the vendor file")
                self.show_db_error(f"{path}: {result['error']}")
            else:
                self.db, self.db_path = result["db"], path
                stamp = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d")
                extra = [Path(f).name for f in self.db.files[1:]]
                self.db_text = (f"{path}  ·  {len(self.db):,} prefixes  ·  file dated {stamp}"
                                + (f"  ·  plus {', '.join(extra)}" if extra else ""))
                self.db_lbl.configure(text=self.db_text)
                self.dl_btn.configure(text="Update oui.txt")
                age = (datetime.now() - datetime.fromtimestamp(path.stat().st_mtime)).days
                if len(self.db) == 0:
                    self.show_db_error("No vendor entries found in that file. Is it the IEEE oui.txt? "
                                       "Click Download oui.txt to get the real one.")
                elif age > ouidownload.STALE_DAYS:
                    self.show_db_error(f"This vendor list is {age} days old. Click Update oui.txt to get "
                                       "the newest IEEE list (new vendors are added every week).")
            self.refresh()

        self.after(100, poll)

    def choose_file(self):
        from tkinter import filedialog
        start = self.db_path.parent if self.db_path else Path.home()
        name = filedialog.askopenfilename(parent=self, title="Choose oui.txt", initialdir=str(start),
                                          filetypes=[("Text files", "*.txt"), ("All files", "*")])
        if name:
            self.app.settings["oui_path"] = name
            self.start_load(Path(name))

    def open_download(self):
        import webbrowser
        webbrowser.open(core.OUI_DOWNLOAD_URL)

    def on_shown(self):
        """First time the tab is opened without a vendor list: fetch it automatically (once per run)."""
        if self.db is None and not self.loading and self.dl_stop is None and not self.auto_tried \
                and self.app.settings.get("oui_auto_download", True):
            self.auto_tried = True
            self.download(auto=True)

    def download(self, auto=False):
        """Download oui.txt next to settings.json (or replace the copy there); click again to cancel."""
        import threading
        if self.dl_stop is not None:
            self.dl_stop.set()
            return
        dest = oui_home()
        stop = threading.Event()
        self.dl_stop = stop
        self.dl_btn.configure(text="Cancel download")
        self.show_db_error("")
        state = {"done": 0, "total": 0}
        result = {}

        def progress(done, total):
            state["done"], state["total"] = done, total

        def work():
            try:
                result["ok"] = ouidownload.download_oui(dest, core.OUI_DOWNLOAD_URL, progress, stop)
            except ouidownload.DownloadError as exc:
                result["error"] = exc

        thread = threading.Thread(target=work, daemon=True)
        thread.start()
        what = "Downloading oui.txt from IEEE" + (" (first use)" if auto else "")

        def poll():
            if not self.winfo_exists():
                return
            if thread.is_alive():
                mb, total = state["done"] / 1e6, state["total"] / 1e6
                if total:
                    msg = f"{what} … {mb:.1f} of {total:.1f} MB ({state['done'] * 100 // state['total']}%)"
                else:
                    msg = f"{what} … {mb:.1f} MB"
                self.db_lbl.configure(text=msg)
                self.after(150, poll)
                return
            self.dl_stop = None
            self.dl_btn.configure(text="Update oui.txt" if self.db is not None else "Download oui.txt")
            if "ok" in result:
                r = result["ok"]
                self.app.settings["oui_path"] = str(r.path)
                note = "" if r.verified else " (certificate check skipped)"
                self.app.flash(f"Downloaded the latest oui.txt to {r.path}{note}.")
                self.start_load(r.path)
                return
            err = result.get("error")
            self.db_lbl.configure(text=self.db_text if self.db is not None else "oui.txt not found")
            if isinstance(err, ouidownload.DownloadCancelled):
                self.app.flash("oui.txt download cancelled.")
                if self.db is None:
                    self.reload_message()
                return
            self.show_db_error(f"Couldn't download oui.txt: {err} You can also click IEEE site, save the "
                               f"file as {dest}, then click Reload.")

        self.after(150, poll)

    def reload_message(self):
        self.show_db_error(f"Click Download oui.txt to save the latest IEEE list to "
                           f"{oui_home()}, or click Choose file… to use one you have.")

    def stop_download(self):
        if self.dl_stop is not None:
            self.dl_stop.set()

    def show_db_error(self, text):
        self.db_err.configure(text=text)
        if text:
            self.db_err.pack(anchor="w", pady=(4, 0), before=self.head)
        else:
            self.db_err.pack_forget()

    # ---- source box

    def _modified(self, _):
        if self.src.edit_modified():
            self.src.edit_modified(False)
            self.debounce()

    def get_text(self) -> str:
        return self.src.get("1.0", "end-1c")

    def clear(self):
        self.src.delete("1.0", "end")
        self.refresh()

    def paste(self):
        try:
            text = self.app.root.clipboard_get()
        except tk.TclError:
            return
        self.src.delete("1.0", "end")
        self.src.insert("1.0", text)
        self.refresh()

    # ---- results

    def style_key(self) -> str:
        return self.style_names.get(self.style_v.get(), "colon")

    def refresh(self):
        text = self.get_text()
        r = core.convert_macs(text)
        highlight_macs(self.src, text, {m for m, _ in r.duplicates})
        counts = {}
        for m in r.macs:
            counts[m] = counts.get(m, 0) + 1

        style, upper = self.style_key(), self.upper_v.get()
        words = self.filter_v.get().lower().split()
        self.tree.delete(*self.tree.get_children())
        self.rows = {}
        stats = {"known": 0, "unknown": 0, "mcast": 0, "fhrp": 0, "local": 0}
        for mac in counts:                          # dict keeps first-seen order
            cls = core.classify_mac(mac)
            entry = self.db.lookup(mac) if self.db else None
            vendor, country = "", ""
            if entry:
                vendor, country = entry.org, entry.country
                stats["known"] += 1
            elif cls.category == "Multicast" and self.db:
                # multicast group addresses carry the protocol owner's OUI with the group bit set
                owner = self.db.lookup(format(int(mac, 16) & ~(1 << 40), "012x"))
                vendor = f"({owner.org})" if owner else "—"
            elif cls.category in ("Multicast", "Broadcast"):
                vendor = "—"
            elif cls.scope == "Locally administered":
                vendor = "(locally administered – no vendor)"
            else:
                vendor = "Unknown" if self.db else "(no oui.txt loaded)"
                stats["unknown"] += 1 if self.db else 0
            if cls.category in ("Multicast", "Broadcast"):
                stats["mcast"] += 1
            if cls.category == "FHRP virtual":
                stats["fhrp"] += 1
            if cls.scope == "Locally administered" and cls.category == "Unicast":
                stats["local"] += 1
            detail = cls.detail
            if entry and entry.is_registry_block:
                detail = (detail + "; " if detail else "") + \
                    "smaller IEEE block – add mam.txt / oui36.txt next to oui.txt for the exact company"
            shown = core.format_mac(mac, style, upper)
            values = (shown, vendor, country, cls.category, detail, counts[mac])
            self.rows[mac] = (values, entry, cls)
            hay = " ".join(str(v) for v in values).lower() + " " + mac
            if words and not all(w in hay for w in words):
                continue
            tag = ("fhrp",) if cls.category == "FHRP virtual" else ("mcast",) if cls.category in (
                "Multicast", "Broadcast") else ("unknown",) if not entry else ()
            self.tree.insert("", "end", iid=mac, values=values, tags=tag)

        dup_count = sum(1 for c in counts.values() if c > 1)
        shown_rows = len(self.tree.get_children())
        self.stats_lbl.configure(text=(
            f"Lines: {r.line_count}  ·  MACs found: {len(r.macs)}  ·  Unique: {len(counts)}  ·  "
            f"Duplicates: {dup_count}  ·  Vendor found: {stats['known']}  ·  Unknown vendor: {stats['unknown']}  ·  "
            f"Multicast/broadcast: {stats['mcast']}  ·  HSRP/VRRP/GLBP: {stats['fhrp']}  ·  "
            f"Locally administered: {stats['local']}"
            + (f"  ·  Showing {shown_rows} (filtered)" if words else "")))
        self.show_detail()

    def describe(self, mac: str) -> str:
        values, entry, cls = self.rows[mac]
        lines = [f"{values[0]}   ({core.format_mac(mac, 'dotted')} · {core.format_mac(mac, 'dash', True)})",
                 f"Type: {cls.category} · {cls.scope}" + (f" · {cls.detail}" if cls.detail else "")]
        if entry:
            prefix_hex = format(int(mac, 16) >> (48 - entry.bits), "X").zfill((entry.bits + 3) // 4)
            lines.append(f"Vendor: {entry.org}   [{entry.block} prefix {prefix_hex}/{entry.bits}]")
            if entry.address:
                lines.append("Address: " + ", ".join(entry.address))
        return "\n".join(lines)

    def show_detail(self, _=None):
        sel = self.tree.selection()
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        if sel:
            self.detail.insert("1.0", self.describe(sel[0]))
        else:
            self.detail.insert("1.0", "Select a row to see the vendor's full address and prefix.")
        self.detail.configure(state="disabled")

    def row_tsv(self, iid) -> str:
        return texttable.tree_table(self.tree, [iid])

    def copy_all(self):
        self.app.copy(texttable.tree_table(self.tree))

    def copy_selected(self):
        if self.tree.selection():
            self.app.copy(texttable.tree_table(self.tree, self.tree.selection()))

    def tree_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        if row not in self.tree.selection():
            self.tree.selection_set(row)
        values = self.tree.item(row, "values")
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label=f"Copy MAC {values[0]}", command=lambda: self.app.copy(values[0]))
        if values[1]:
            menu.add_command(label=f"Copy vendor {values[1]}", command=lambda: self.app.copy(values[1]))
        menu.add_command(label="Copy row", command=lambda: self.app.copy(self.row_tsv(row)))
        self.app.popup_tree_menu(menu, event)


# --------------------------------------------------------------------------- DNS dig tab

TRACE_CHOICE = "Trace from root (iterative, like dig +trace)"
RANDOM_ROOT = "Random root server"


class DigTab(ttk.Frame):
    """DNS Digr: dig-style DNS lookups (built-in client, not the dig program) against a chosen server, or iteratively from the root hints."""

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        s = app.settings
        self.running = False

        # ---- query row
        row = ttk.Frame(self)
        row.pack(fill="x")
        ttk.Label(row, text="Name:", style="Field.TLabel").pack(side="left")
        self.history = list(s.get("dig_history", []))
        self.name_v = tk.StringVar(value=self.history[0] if self.history else "example.com")
        self.name_box = ttk.Combobox(row, textvariable=self.name_v, values=self.history, width=34, font=app.mono)
        self.name_box.pack(side="left", padx=(4, 10))
        ttk.Label(row, text="Type:", style="Field.TLabel").pack(side="left")
        self.type_v = tk.StringVar(value=s.get("dig_type", "A"))
        ttk.Combobox(row, textvariable=self.type_v, values=dnsdig.QUERY_TYPES, width=7).pack(side="left", padx=(4, 10))
        ttk.Label(row, text="Class:", style="Field.TLabel").pack(side="left")
        self.class_v = tk.StringVar(value="IN")
        ttk.Combobox(row, textvariable=self.class_v, values=["IN", "CH"], width=4, state="readonly").pack(
            side="left", padx=(4, 10))
        self.dig_btn = ttk.Button(row, text="Digr", style="Accent.TButton", command=self.run)
        self.dig_btn.pack(side="left")

        # ---- server row
        srv = ttk.Frame(self)
        srv.pack(fill="x", pady=(10, 0))
        ttk.Label(srv, text="Server:", style="Field.TLabel").pack(side="left")
        choices = [TRACE_CHOICE]
        choices += [f"System resolver  {ip}" for ip in dnsdig.system_resolvers()]
        choices += [f"{name}  {ip}" for name, ip in dnsdig.PUBLIC_RESOLVERS]
        choices += [f"{n}  {v4}" for n, v4, _ in dnsdig.ROOT_SERVERS]
        self.server_v = tk.StringVar(value=s.get("dig_server", TRACE_CHOICE))
        ttk.Combobox(srv, textvariable=self.server_v, values=choices, width=44).pack(side="left", padx=(4, 10))
        ttk.Label(srv, text="Port:").pack(side="left")
        self.port_v = tk.StringVar(value="53")
        ttk.Entry(srv, textvariable=self.port_v, width=6).pack(side="left", padx=(4, 10))
        self.root_lbl = ttk.Label(srv, text="Start at:")
        self.root_lbl.pack(side="left")
        self.root_v = tk.StringVar(value=s.get("dig_root", RANDOM_ROOT))
        self.root_box = ttk.Combobox(srv, textvariable=self.root_v, state="readonly", width=34,
                                     values=[RANDOM_ROOT] + [f"{n}  {v4}" for n, v4, _ in dnsdig.ROOT_SERVERS])
        self.root_box.pack(side="left", padx=(4, 0))

        # ---- options
        opt = ttk.Frame(self)
        opt.pack(fill="x", pady=(8, 0))
        self.tcp_v = tk.BooleanVar(value=False)
        self.rd_v = tk.BooleanVar(value=True)
        self.dnssec_v = tk.BooleanVar(value=False)
        self.v6_v = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="Use TCP", variable=self.tcp_v).pack(side="left")
        self.rd_cb = ttk.Checkbutton(opt, text="Recursion desired (RD)", variable=self.rd_v)
        self.rd_cb.pack(side="left", padx=12)
        ttk.Checkbutton(opt, text="DNSSEC records (DO bit)", variable=self.dnssec_v).pack(side="left")
        self.v6_cb = ttk.Checkbutton(opt, text="Trace over IPv6", variable=self.v6_v)
        self.v6_cb.pack(side="left", padx=12)
        ttk.Label(opt, text="Timeout (s):").pack(side="left")
        self.timeout_v = tk.StringVar(value="3")
        ttk.Entry(opt, textvariable=self.timeout_v, width=4).pack(side="left", padx=(4, 0))
        ttk.Label(self, text="Pick a server, type any IP or hostname, or leave it on Trace to resolve step by step "
                             "from a root server. An IP in the Name box is looked up as PTR (reverse DNS).",
                  style="Hint.TLabel", wraplength=950).pack(anchor="w", pady=(6, 0))

        # ---- answer summary
        ttk.Separator(self).pack(fill="x", pady=10)
        top = ttk.Frame(self)
        top.pack(fill="x")
        self.status_lbl = ttk.Label(top, style="Big.TLabel")
        self.status_lbl.pack(side="left")
        ttk.Button(top, text="Copy answers", style="Small.TButton", command=self.copy_answers).pack(side="right")
        self.answers = scrolled_text(self, app, height=5)
        self.answers.container.pack(fill="x", pady=(6, 0))
        self.answers.configure(state="disabled")

        # ---- full output
        head = ttk.Frame(self)
        head.pack(fill="x", pady=(10, 0))
        ttk.Label(head, text="Full output", style="Title.TLabel").pack(side="left")
        ttk.Button(head, text="Copy output", style="Small.TButton", command=self.copy_output).pack(side="right")
        self.out = scrolled_text(self, app, height=20)
        self.out.container.pack(fill="both", expand=True, pady=(4, 0))
        self.out.tag_configure("comment", foreground=app.colors["muted"])
        self.out.tag_configure("error", foreground=app.colors["error"])
        self.out.configure(state="disabled")
        self.answer_lines = []

        self.name_box.bind("<Return>", lambda e: self.run())
        self.server_v.trace_add("write", lambda *_: self.update_mode())
        self.update_mode()
        self.set_output("Enter a name and press Digr (or Return).", [])

    # ---- helpers

    def is_trace(self) -> bool:
        v = self.server_v.get().strip()
        return not v or v == TRACE_CHOICE

    def update_mode(self):
        trace = self.is_trace()
        self.root_box.configure(state="readonly" if trace else "disabled")
        self.rd_cb.configure(state="disabled" if trace else "normal")
        self.v6_cb.configure(state="normal" if trace else "disabled")

    def server_ip(self) -> str:
        """Last word of the combobox entry ('Google  8.8.8.8' -> '8.8.8.8')."""
        return self.server_v.get().split()[-1]

    def set_output(self, text: str, answers, status: str = "", ok: bool = True):
        self.status_lbl.configure(text=status, foreground=self.app.colors["error"] if not ok else "")
        for widget, content in ((self.answers, "\n".join(answers) or "(no answers)"), (self.out, text)):
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("1.0", content)
            widget.configure(state="disabled")
        self.out.configure(state="normal")
        for n, line in enumerate(text.splitlines(), 1):
            if line.startswith(";; ERROR") or line.startswith(";; step") and "–" in line:
                self.out.tag_add("error", f"{n}.0", f"{n}.end")
            elif line.startswith(";"):
                self.out.tag_add("comment", f"{n}.0", f"{n}.end")
        self.out.configure(state="disabled")
        self.answer_lines = answers

    def remember(self, name: str):
        self.history = [name] + [h for h in self.history if h != name][:19]
        self.name_box.configure(values=self.history)

    # ---- run

    def run(self):
        if self.running:
            return "break"
        name = self.name_v.get().strip()
        if not name:
            return "break"
        qtype = self.type_v.get().strip().upper() or "A"
        qclass = self.class_v.get()
        note = ""
        try:
            import ipaddress as _ip
            _ip.ip_address(name)
            name, note = dnsdig.reverse_name(name), f";; {self.name_v.get().strip()} is an IP address – looking up PTR {dnsdig.reverse_name(self.name_v.get().strip())}"
            qtype = "PTR"
        except ValueError:
            pass
        if qtype not in dnsdig.TYPES and not qtype.startswith("TYPE"):
            self.set_output(f";; ERROR: unknown record type {qtype}", [], "Unknown type", ok=False)
            return "break"
        try:
            port = int(self.port_v.get())
            timeout = max(0.5, float(self.timeout_v.get()))
        except ValueError:
            self.set_output(";; ERROR: port and timeout must be numbers", [], "Bad option", ok=False)
            return "break"
        self.remember(self.name_v.get().strip())
        trace = self.is_trace()
        server = None if trace else self.server_ip()
        root = None
        if trace and self.root_v.get() != RANDOM_ROOT:
            rname, rip = self.root_v.get().split()
            root = (rname, rip)
            if self.v6_v.get():
                root = next(((n, v6) for n, v4, v6 in dnsdig.ROOT_SERVERS if n == rname), root)
        opts = dict(tcp=self.tcp_v.get(), rd=self.rd_v.get(), dnssec=self.dnssec_v.get(), v6=self.v6_v.get())

        import threading
        self.running = True
        self.dig_btn.configure(text="Querying…", state="disabled")
        target = server or "root servers"
        self.set_output(f";; Querying {target} for {name} {qtype} …", [], "Working…")
        box = {}

        def work():
            try:
                if trace:
                    tr = dnsdig.trace(name, qtype, root, qclass, port, opts["dnssec"], timeout, opts["v6"])
                    text = dnsdig.format_trace(tr, name, qtype)
                    answers = [f"{rr.type_name:<6} {rr.text}" for rr in tr.answers]
                    status = tr.error and "Trace failed" or tr.status
                    box["r"] = (text, answers, status, not tr.error and tr.status.startswith("NOERROR"))
                else:
                    res = dnsdig.query(name, qtype, server, port, qclass, rd=opts["rd"], tcp=opts["tcp"],
                                       dnssec=opts["dnssec"], timeout=timeout)
                    cmd = (f"; <<>> digr <<>> @{server} {name} {qtype}" + ("" if qclass == "IN" else f" {qclass}")
                           + (" +tcp" if opts["tcp"] else "") + ("" if opts["rd"] else " +norecurse")
                           + (" +dnssec" if opts["dnssec"] else ""))
                    text = dnsdig.format_message(res, cmd)
                    m = res.message
                    answers = [f"{rr.type_name:<6} {rr.text}" for rr in m.answer]
                    if not m.answer and m.authority and not opts["rd"]:
                        answers = [f"(referral) NS {rr.text}" for rr in m.authority if rr.rtype == 2]
                    status = f"{m.rcode_name}  ·  {res.elapsed_ms:.0f} ms  ·  {len(m.answer)} answer(s)"
                    box["r"] = (text, answers, status, m.rcode == 0)
            except dnsdig.DnsError as exc:
                box["r"] = (f";; ERROR: {exc}", [], "No answer", False)
            except Exception as exc:  # unexpected – show it rather than hang
                box["r"] = (f";; ERROR: {type(exc).__name__}: {exc}", [], "Error", False)

        thread = threading.Thread(target=work, daemon=True)
        thread.start()

        def poll():
            if thread.is_alive():
                self.after(100, poll)
                return
            text, answers, status, ok = box["r"]
            if note:
                text = note + "\n" + text
            self.set_output(text, answers, status, ok)
            self.running = False
            self.dig_btn.configure(text="Digr", state="normal")

        self.after(100, poll)
        return "break"

    def copy_answers(self):
        self.app.copy(texttable.align_tabs("\n".join(self.answer_lines)))

    def copy_output(self):
        self.app.copy(texttable.align_tabs(self.out.get("1.0", "end-1c")))


# --------------------------------------------------------------------------- traceroute tab


class TracerouteTab(ttk.Frame):
    """Runs the system traceroute (tracert on Windows) and shows hops live."""

    COLUMNS = ("Hop", "Host", "IP address", "Type", "Times (ms)", "Avg", "Loss", "Notes")

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        s = app.settings
        self.proc = None
        self.queue = None
        self.windows = tracert.platform_kind() == "windows"

        row = ttk.Frame(self)
        row.pack(fill="x")
        ttk.Label(row, text="Target:", style="Field.TLabel").pack(side="left")
        self.history = list(s.get("trace_history", []))
        self.target_v = tk.StringVar(value=self.history[0] if self.history else "8.8.8.8")
        self.target_box = ttk.Combobox(row, textvariable=self.target_v, values=self.history, width=34,
                                       font=app.mono)
        self.target_box.pack(side="left", padx=(4, 12))
        self.resolve_v = tk.BooleanVar(value=s.get("trace_resolve", True))
        ttk.Checkbutton(row, text="Resolve hostnames (DNS)", variable=self.resolve_v).pack(side="left")
        self.v6_v = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="IPv6", variable=self.v6_v).pack(side="left", padx=12)
        self.stop_btn = ttk.Button(row, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="right")
        self.start_btn = ttk.Button(row, text="Start", style="Accent.TButton", command=self.start)
        self.start_btn.pack(side="right", padx=6)

        opt = ttk.Frame(self)
        opt.pack(fill="x", pady=(8, 0))
        self.max_v = tk.StringVar(value=str(s.get("trace_max", 30)))
        self.q_v = tk.StringVar(value=str(s.get("trace_queries", 3)))
        self.wait_v = tk.StringVar(value=str(s.get("trace_wait", 2)))
        self.icmp_v = tk.BooleanVar(value=False)
        ttk.Label(opt, text="Max hops:").pack(side="left")
        ttk.Entry(opt, textvariable=self.max_v, width=4).pack(side="left", padx=(4, 12))
        ttk.Label(opt, text="Probes per hop:").pack(side="left")
        q = ttk.Entry(opt, textvariable=self.q_v, width=3)
        q.pack(side="left", padx=(4, 12))
        ttk.Label(opt, text="Wait per probe (s):").pack(side="left")
        ttk.Entry(opt, textvariable=self.wait_v, width=4).pack(side="left", padx=(4, 12))
        icmp = ttk.Checkbutton(opt, text="Use ICMP instead of UDP", variable=self.icmp_v)
        icmp.pack(side="left")
        if self.windows:
            q.configure(state="disabled")
            icmp.configure(state="disabled")
            hint = "Windows tracert always uses ICMP and 3 probes per hop."
        elif sys.platform.startswith("linux"):
            hint = "ICMP mode needs root on Linux. Some routers drop UDP probes – try ICMP if hops show * * *."
        else:
            hint = "Some routers and firewalls drop UDP probes – try ICMP if hops show * * *."
        ttk.Label(self, text=hint + "  With DNS off, no reverse lookups are done (faster).",
                  style="Hint.TLabel", wraplength=950).pack(anchor="w", pady=(6, 0))

        cmdrow = ttk.Frame(self)
        cmdrow.pack(fill="x", pady=(8, 0))
        ttk.Label(cmdrow, text="Command:", style="Key.TLabel").pack(side="left")
        self.cmd_v = tk.StringVar()
        ttk.Entry(cmdrow, textvariable=self.cmd_v, state="readonly", font=app.mono,
                  style="Value.TEntry").pack(side="left", fill="x", expand=True, padx=(6, 0))

        ttk.Separator(self).pack(fill="x", pady=10)
        top = ttk.Frame(self)
        top.pack(fill="x")
        self.status_lbl = ttk.Label(top, style="Title.TLabel")
        self.status_lbl.pack(side="left")
        ttk.Button(top, text="Copy table", style="Small.TButton", command=self.copy_table).pack(side="right")

        self.tree = make_tree(self, self.COLUMNS, (45, 200, 135, 185, 215, 55, 50, 110))
        self.tree.configure(height=16)
        for col in ("Hop", "Avg", "Loss"):
            self.tree.column(col, stretch=False, anchor="center")
        for col in ("IP address", "Type", "Times (ms)"):
            self.tree.column(col, stretch=False)
        self.tree.container.pack(fill="both", expand=True, pady=(6, 0))
        self.tree.tag_configure("dead", foreground=app.colors["muted"])
        self.tree.tag_configure("lossy", foreground=app.colors["warn"])
        self.tree.bind(app.right_click, self.tree_menu)
        self.tree.bind("<Double-1>", self.open_in_ipcalc)
        ttk.Label(self, text="Double-click a hop to open its IP in IP Calc. Right-click for more.",
                  style="Hint.TLabel").pack(anchor="w", pady=(4, 0))

        head = ttk.Frame(self)
        head.pack(fill="x", pady=(10, 0))
        ttk.Label(head, text="Raw output", style="Title.TLabel").pack(side="left")
        ttk.Button(head, text="Copy output", style="Small.TButton", command=self.copy_output).pack(side="right")
        self.raw = scrolled_text(self, app, height=8)
        self.raw.container.pack(fill="x", pady=(4, 0))
        self.raw.configure(state="disabled")

        self.target_box.bind("<Return>", lambda e: self.start())
        self.parser = tracert.TraceParser()
        self.update_command()
        for v in (self.target_v, self.resolve_v, self.v6_v, self.max_v, self.q_v, self.wait_v, self.icmp_v):
            v.trace_add("write", lambda *_: self.update_command())
        self.status_lbl.configure(text="Enter a hostname or IP and press Start.")

    # ---- command

    def options(self):
        try:
            max_hops = max(1, min(64, int(self.max_v.get())))
            queries = max(1, min(10, int(self.q_v.get())))
            wait = max(0.5, min(30.0, float(self.wait_v.get())))
        except ValueError:
            raise ValueError("Max hops, probes and wait must be numbers.")
        return max_hops, queries, wait

    def command(self):
        target = self.target_v.get().strip()
        ipv6 = self.v6_v.get() or ":" in target
        max_hops, queries, wait = self.options()
        tool = tracert.find_tool(ipv6)
        return tracert.build_command(target or "<target>", self.resolve_v.get(), max_hops, queries, wait,
                                     ipv6, self.icmp_v.get(), tool=tool), tool

    def update_command(self):
        try:
            cmd, _ = self.command()
            self.cmd_v.set(" ".join(cmd))
        except ValueError as exc:
            self.cmd_v.set(str(exc))

    # ---- run / stop

    def start(self):
        if self.proc:
            return "break"
        target = self.target_v.get().strip()
        if not target or any(c in target for c in " ;&|`$<>\"\'"):
            self.status_lbl.configure(text="Enter a single hostname or IP address.")
            return "break"
        try:
            cmd, tool = self.command()
        except ValueError as exc:
            self.status_lbl.configure(text=str(exc))
            return "break"
        if not tool:
            self.status_lbl.configure(text="traceroute isn't installed. On Linux: sudo apt install traceroute "
                                           "(or dnf install traceroute).")
            return "break"
        self.history = [target] + [h for h in self.history if h != target][:19]
        self.target_box.configure(values=self.history)
        self.tree.delete(*self.tree.get_children())
        self.set_raw("$ " + " ".join(cmd) + "\n")
        self.parser = tracert.TraceParser()
        self.target = target
        try:
            self.proc = tracert.popen(cmd)
        except OSError as exc:
            self.status_lbl.configure(text=f"Couldn't run {cmd[0]}: {exc}")
            self.proc = None
            return "break"
        import queue
        import threading
        self.queue = queue.Queue()
        proc, q = self.proc, self.queue

        def reader():
            for line in proc.stdout:
                q.put(line)
            proc.wait()
            q.put(None)

        threading.Thread(target=reader, daemon=True).start()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_lbl.configure(text=f"Tracing {target} …")
        self.started = datetime.now()
        self.after(100, self.poll)
        return "break"

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except OSError:
                pass
            self.stopped = True

    def poll(self):
        import queue as _q
        done = False
        while True:
            try:
                line = self.queue.get_nowait()
            except _q.Empty:
                break
            if line is None:
                done = True
                break
            self.append_raw(line)
            changed = self.parser.feed(line.rstrip("\n"))
            if changed is not None:
                self.show_hop(self.parser.hops[changed])
                self.status_lbl.configure(text=f"Tracing {self.target} … hop {changed}")
        if done:
            self.finish()
        else:
            self.after(100, self.poll)

    def finish(self):
        code = self.proc.returncode if self.proc else None
        stopped = getattr(self, "stopped", False)
        self.proc = None
        self.stopped = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        hops = self.parser.hops
        secs = (datetime.now() - self.started).total_seconds()
        if stopped:
            msg = f"Stopped after {len(hops)} hop(s)."
        elif not hops:
            msg = f"No hops – see the raw output below (exit code {code})."
        else:
            last = hops[max(hops)]
            ips = {ip for _, ip in last.responders}
            msg = (f"Done – {len(hops)} hop(s) in {secs:.1f}s"
                   + (f", last reply from {', '.join(sorted(ips))}" if ips else ", last hop didn't reply"))
        self.status_lbl.configure(text=msg)

    # ---- table

    def show_hop(self, hop):
        responders = hop.responders
        hosts = " / ".join(h for h, ip in responders if h and h != ip) or (
            "" if responders else "* no reply")
        ips = " / ".join(ip for _, ip in responders)
        types = []
        for _, ip in responders:
            try:
                kind = core.address_type(ipaddress.ip_address(ip.split("%")[0]))
            except ValueError:
                kind = ""
            if kind and kind not in types:
                types.append(kind)
        times = "  ".join("*" if p.rtt is None else (p.text or f"{p.rtt:g}") for p in hop.probes)
        rtts = hop.rtts
        avg = f"{sum(rtts) / len(rtts):.1f}" if rtts else "–"
        total = len(hop.probes)
        loss = f"{round(100 * hop.lost / total)}%" if total else ""
        tag = ("dead",) if total and hop.lost == total else ("lossy",) if hop.lost else ()
        values = (hop.number, hosts, ips, ", ".join(types), times, avg, loss, hop.notes)
        iid = str(hop.number)
        if self.tree.exists(iid):
            self.tree.item(iid, values=values, tags=tag)
        else:
            self.tree.insert("", "end", iid=iid, values=values, tags=tag)
        self.tree.see(iid)

    def hop_ip(self, iid):
        ips = self.tree.set(iid, "IP address")
        return ips.split(" / ")[0] if ips else ""

    def open_in_ipcalc(self, event=None):
        row = self.tree.identify_row(event.y) if event else (self.tree.selection() or [""])[0]
        ip = self.hop_ip(row) if row else ""
        if ip:
            self.app.open_in_calculator(ip)
        return "break"

    def tree_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        ip = self.hop_ip(row)
        host = self.tree.set(row, "Host")
        menu = tk.Menu(self, tearoff=False)
        if ip:
            menu.add_command(label=f"Copy IP {ip}", command=lambda: self.app.copy(ip))
        if host and not host.startswith("*"):
            menu.add_command(label=f"Copy host {host}", command=lambda: self.app.copy(host))
        menu.add_command(label="Copy row", command=lambda: self.app.copy(texttable.tree_table(self.tree, [row])))
        if ip:
            menu.add_separator()
            menu.add_command(label=f"Open {ip} in IP Calc", command=lambda: self.app.open_in_calculator(ip))
            menu.add_command(label=f"Reverse DNS for {ip} (DNS Digr)", command=lambda: self.app.dig_ptr(ip))
        self.app.popup_tree_menu(menu, event)

    # ---- raw output / copy

    def set_raw(self, text):
        self.raw.configure(state="normal")
        self.raw.delete("1.0", "end")
        self.raw.insert("1.0", text)
        self.raw.configure(state="disabled")

    def append_raw(self, text):
        self.raw.configure(state="normal")
        self.raw.insert("end", text)
        self.raw.see("end")
        self.raw.configure(state="disabled")

    def copy_table(self):
        self.app.copy(texttable.tree_table(self.tree))

    def copy_output(self):
        self.app.copy(self.raw.get("1.0", "end-1c"))


# --------------------------------------------------------------------------- ping tab


class PingSession:
    """One target in the Ping tool: its settings, live stats, and full probe history."""

    MAX_LOG = 50000

    def __init__(self, target: str, note: str = ""):
        self.target = target
        self.note = note
        self.ip = ""
        self.cmd = ""
        self.stats = pinger.PingStats()
        self.log = []                 # (n, datetime, ProbeResult)
        self.started = None
        self.ended = None
        self.thread = None
        self.stop_event = None
        self.user_stopped = False
        self.error = ""
        self.size = None              # payload bytes of the last start (None = ping's default)

    @property
    def running(self) -> bool:
        return self.thread is not None

    @property
    def last(self):
        return self.log[-1][2] if self.log else None

    def elapsed(self) -> float:
        if not self.started:
            return 0.0
        return ((self.ended or datetime.now()) - self.started).total_seconds()

    def state(self) -> str:
        if self.error:
            return "Error"
        if self.running:
            return "Pinging" if self.ip else "Resolving"
        if not self.started:
            return "Idle"
        return "Stopped" if self.user_stopped else "Finished"


class PingTab(ttk.Frame):
    """Ping several targets at once; live stats per target; history shown for the selected one."""

    TARGET_COLUMNS = ("Target", "Note", "IP", "Size", "State", "Sent", "OK", "Failed", "Loss", "Last", "Best", "Avg",
                      "Worst", "Run time")
    LOG_COLUMNS = ("#", "Time", "Result", "RTT (ms)", "TTL", "Details")
    TILES = (("sent", "Sent"), ("ok", "Succeeded"), ("failed", "Failed"), ("loss", "Loss"),
             ("best", "Best"), ("avg", "Average"), ("worst", "Worst"), ("jitter", "Jitter"),
             ("outage", "Longest outage"), ("elapsed", "Total time"))
    MAX_TARGETS = 256
    SHOW_LOG = 5000                # rows put in the history table; Copy/Save include everything

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        s = app.settings
        self.sessions = {}             # key -> PingSession, in add order
        self.selected = None           # key shown in the details pane
        self.queue = None
        self._polling = False

        row = ttk.Frame(self)
        row.pack(fill="x")
        ttk.Label(row, text="Add targets:", style="Field.TLabel").pack(side="left")
        self.history = list(s.get("ping_history", []))
        self.target_v = tk.StringVar(value=self.history[0] if self.history else "8.8.8.8")
        self.target_box = ttk.Combobox(row, textvariable=self.target_v, values=self.history, width=30,
                                       font=app.mono)
        self.target_box.pack(side="left", padx=(4, 10))
        ttk.Label(row, text="Note:").pack(side="left")
        self.note_v = tk.StringVar()
        self.note_entry = ttk.Entry(row, textvariable=self.note_v, width=22)
        self.note_entry.pack(side="left", padx=(4, 6))
        ttk.Button(row, text="Add & start", style="Accent.TButton", command=self.start).pack(side="left")
        ttk.Button(row, text="Add list…", command=self.add_list_dialog).pack(side="left", padx=(6, 0))
        ttk.Button(row, text="Paste list", command=self.paste_list).pack(side="left", padx=6)
        self.v6_v = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="IPv6", variable=self.v6_v).pack(side="left", padx=(6, 0))
        ttk.Label(self, text="One or more hosts/IPs separated by spaces or commas (the note goes on each). For a list "
                  "with a note per address use Add list… or Paste list: one per line, note after a space or comma. "
                  "Double-click a note to edit it.", style="Hint.TLabel", wraplength=1100).pack(anchor="w", pady=(2, 0))

        opt = ttk.Frame(self)
        opt.pack(fill="x", pady=(8, 0))
        self.count_v = tk.StringVar(value=str(s.get("ping_count", 0)))
        self.interval_v = tk.StringVar(value=str(s.get("ping_interval", 1)))
        self.timeout_v = tk.StringVar(value=str(s.get("ping_timeout", 2)))
        self.size_v = tk.StringVar(value=str(s.get("ping_size", "")))
        for label, var, width in (("Count (0 = until stopped):", self.count_v, 6),
                                  ("Interval (s):", self.interval_v, 5),
                                  ("Timeout (s):", self.timeout_v, 5),
                                  ("Packet size (bytes, blank = default):", self.size_v, 6)):
            ttk.Label(opt, text=label).pack(side="left")
            ttk.Entry(opt, textvariable=var, width=width).pack(side="left", padx=(4, 12))

        ttk.Separator(self).pack(fill="x", pady=10)

        top = ttk.Frame(self)
        top.pack(fill="x")
        self.status_lbl = ttk.Label(top, style="Title.TLabel")
        self.status_lbl.pack(side="left")
        ttk.Button(top, text="Remove all", style="Small.TButton", command=self.remove_all).pack(side="right")
        ttk.Button(top, text="Stop all", style="Small.TButton", command=self.stop).pack(side="right", padx=4)
        ttk.Button(top, text="Start all", style="Small.TButton", command=self.start_all).pack(side="right")
        sel = ttk.Frame(self)
        sel.pack(fill="x", pady=(6, 0))
        ttk.Label(sel, text="Selected:").pack(side="left")
        self.start_btn = ttk.Button(sel, text="▶ Start", style="Small.TButton", command=self.start_selected)
        self.start_btn.pack(side="left", padx=(6, 0))
        self.stop_btn = ttk.Button(sel, text="■ Stop", style="Small.TButton", command=self.stop_selected)
        self.stop_btn.pack(side="left", padx=4)
        ttk.Button(sel, text="Restart (clear history)", style="Small.TButton",
                   command=self.restart_selected).pack(side="left")
        ttk.Button(sel, text="Remove", style="Small.TButton", command=self.remove_selected).pack(side="left", padx=4)
        ttk.Button(sel, text="Copy table", style="Small.TButton", command=self.copy_table).pack(side="right")

        self.tree = make_tree(self, self.TARGET_COLUMNS, (150, 160, 110, 58, 75, 50, 50, 55, 60, 84, 62, 62, 62, 84))
        self.tree.configure(height=6, selectmode="extended", style="Ping.Treeview")
        for c in self.TARGET_COLUMNS[5:]:
            self.tree.column(c, stretch=False, anchor="e")
        self.tree.column("Size", stretch=False, anchor="e")
        self.tree.column("IP", stretch=False)
        self.tree.column("State", stretch=False)
        self.tree.container.pack(fill="x", pady=(4, 0))
        for tag, colors in SWEEP_COLORS.items():
            self.tree.tag_configure(tag, **colors)
        self.tree.tag_configure("idle", foreground=app.colors["muted"])
        make_sortable(self.tree, numeric=("Size", "Sent", "OK", "Failed", "Loss", "Last", "Best", "Avg", "Worst"))
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.update_sel_color(), add="+")
        self.tree.bind("<Delete>", lambda e: self.remove_selected())
        self.tree.bind("<BackSpace>", lambda e: self.remove_selected())
        self.tree.bind(app.right_click, self.tree_menu)
        self.tree.bind("<Double-1>", self.on_double)
        self.note_editor = None

        # ---- details of the selected target (hidden until one is selected)
        self.empty_lbl = ttk.Label(self, style="Hint.TLabel",
                                   text="Select a target above to see its statistics and ping history.")
        self.empty_lbl.pack(anchor="w", pady=(10, 0))
        self.detail = ttk.Frame(self)
        dh = ttk.Frame(self.detail)
        dh.pack(fill="x", pady=(10, 0))
        self.detail_lbl = ttk.Label(dh, style="Title.TLabel")
        self.detail_lbl.pack(side="left")
        ttk.Button(dh, text="Copy summary", style="Small.TButton", command=self.copy_summary).pack(side="right")
        tiles = ttk.Frame(self.detail)
        tiles.pack(fill="x", pady=(6, 0))
        self.tile_vals = {}
        for i, (key, label) in enumerate(self.TILES):
            box = ttk.Frame(tiles, padding=(10, 6), relief="groove", borderwidth=1)
            box.grid(row=i // 5, column=i % 5, sticky="nsew", padx=3, pady=3)
            ttk.Label(box, text=label, style="Key.TLabel").pack(anchor="w")
            val = ttk.Label(box, text="–", style="Big.TLabel")
            val.pack(anchor="w")
            self.tile_vals[key] = val
        for c in range(5):
            tiles.columnconfigure(c, weight=1, uniform="tile")
        self.times_lbl = ttk.Label(self.detail, style="Field.TLabel")
        self.times_lbl.pack(anchor="w", pady=(4, 0))
        self.cmd_lbl = ttk.Label(self.detail, style="Hint.TLabel")
        self.cmd_lbl.pack(anchor="w")
        lh = ttk.Frame(self.detail)
        lh.pack(fill="x", pady=(10, 0))
        self.log_lbl = ttk.Label(lh, text="History", style="Title.TLabel")
        self.log_lbl.pack(side="left")
        self.failonly_v = tk.BooleanVar(value=s.get("ping_failonly", False))
        ttk.Checkbutton(lh, text="Failures only", variable=self.failonly_v,
                        command=self.fill_log).pack(side="left", padx=(12, 0))
        ttk.Button(lh, text="Save history…", style="Small.TButton", command=self.save_log).pack(side="right")
        ttk.Button(lh, text="Copy history", style="Small.TButton", command=self.copy_log).pack(side="right", padx=4)
        self.log = make_tree(self.detail, self.LOG_COLUMNS, (60, 190, 110, 90, 60, 400))
        self.log.configure(height=14)
        for col in ("#", "RTT (ms)", "TTL"):
            self.log.column(col, stretch=False, anchor="center")
        self.log.column("Time", stretch=False)
        self.log.column("Result", stretch=False)
        self.log.container.pack(fill="both", expand=True, pady=(4, 0))
        self.log.tag_configure("fail", foreground=app.colors["error"])
        self.log.tag_configure("unreach", foreground=app.colors["warn"])

        self.target_box.bind("<Return>", lambda e: self.start())
        self.note_entry.bind("<Return>", lambda e: self.start())
        saved = []
        for t in s.get("ping_targets", []):         # last session's list comes back, not running
            if isinstance(t, str):
                saved.append(t)
            elif isinstance(t, dict) and isinstance(t.get("target"), str):
                saved.append(f"{t['target']} {t.get('note', '')}".strip())
        if saved:
            self.add_targets("\n".join(saved) + "\n", start=False, select=False)
        self.update_status()
        self.bind("<Destroy>", lambda e: self.shutdown() if e.widget is self else None, add="+")
        self._tick()

    # ---- adding targets

    def _expand(self, tok: str):
        """One token -> hosts. IPs, ranges, small subnets, and host names (dotted or single-label)."""
        if not tok or any(c in tok for c in "&|`$<>\"'()"):
            return []
        found = sweep.expand_targets(tok, limit=self.MAX_TARGETS).hosts
        if not found and sweep._HOST.match(tok) and not tok.replace(".", "").isdigit():
            found = [tok.rstrip(".")]
        return found

    def parse_targets(self, text: str, note: str = ""):
        """[(target, note)] and the tokens that weren't usable.
        Single line: every token is a target and all get `note`.
        Several lines: one target per line, anything after it (space or comma) is that line's note."""
        out, bad = [], []
        if "\n" in text:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = re.split(r"[\s,;]+", line, maxsplit=1)
                hosts = self._expand(parts[0])
                if not hosts:
                    bad.append(parts[0])
                    continue
                line_note = parts[1].strip(" ,;\t") if len(parts) > 1 else ""
                out += [(h, line_note or note) for h in hosts]
        else:
            for tok in re.split(r"[\s,;]+", text.strip()):
                if not tok:
                    continue
                hosts = self._expand(tok)
                if hosts:
                    out += [(h, note) for h in hosts]
                else:
                    bad.append(tok)
        merged = {}
        for t, n in out:                              # one entry per target; first non-empty note wins
            k = self.key(t)
            if k not in merged:
                merged[k] = [t, n]
            elif n and not merged[k][1]:
                merged[k][1] = n
        return [tuple(v) for v in merged.values()], bad

    def paste_list(self):
        try:
            text = self.app.root.clipboard_get()
        except tk.TclError:
            return
        self.add_targets(text if "\n" in text.strip() else text, start=True)

    def add_list_dialog(self):
        win = tk.Toplevel(self)
        win.title("Add ping targets")
        win.transient(self.winfo_toplevel())
        frame = ttk.Frame(win, padding=12)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="One per line: IP or host name, then an optional note after a space or comma.",
                  style="Field.TLabel").pack(anchor="w")
        ttk.Label(frame, text="e.g.   192.0.2.1 Core router\n        192.0.2.10, Office printer\n        "
                  "198.51.100.1-4 Lab switches", style="Hint.TLabel", justify="left").pack(anchor="w", pady=(2, 6))
        text = scrolled_text(frame, self.app, height=12, width=60)
        text.container.pack(fill="both", expand=True)
        text.focus_set()
        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(8, 0))

        def go(start):
            content = text.get("1.0", "end-1c")
            if self.add_targets(content + "\n", start=start):
                win.destroy()

        ttk.Button(btns, text="Cancel", command=win.destroy).pack(side="right")
        ttk.Button(btns, text="Add", command=lambda: go(False)).pack(side="right", padx=6)
        ttk.Button(btns, text="Add & start", style="Accent.TButton", command=lambda: go(True)).pack(side="right")
        win.bind("<Escape>", lambda e: win.destroy())
        self.list_dialog = win                         # for tests
        self.list_text = text
        return win

    def start(self):
        """Add whatever is in the target box (one or many) with the note, and start them."""
        if self.add_targets(self.target_v.get(), start=True, remember=True, note=self.note_v.get().strip()):
            self.note_v.set("")
        return "break"

    def add_targets(self, text: str, start: bool = True, select: bool = True, remember: bool = False,
                    note: str = ""):
        pairs, bad = self.parse_targets(text, note)
        targets = [t for t, _ in pairs]
        if not targets:
            self.status_lbl.configure(text="Enter hostnames or IP addresses (e.g. 8.8.8.8 1.1.1.1 router1).")
            return []
        room = self.MAX_TARGETS - len(self.sessions)
        added = [t for t in targets if self.key(t) not in self.sessions]
        if len(added) > room:
            self.app.flash(f"Only {self.MAX_TARGETS} targets at once; {len(added) - room} not added.")
            added = added[:room]
            targets = [t for t in targets if self.key(t) in self.sessions or t in added]
        notes = dict(pairs)
        for t in targets:
            k = self.key(t)
            if k in self.sessions:
                if notes.get(t):                       # re-adding with a note updates it
                    self.sessions[k].note = notes[t]
                    self.refresh_row(k)
            else:
                sess = PingSession(t, notes.get(t, ""))
                self.sessions[k] = sess
                self.tree.insert("", "end", iid=k, values=self.row_values(sess), tags=("idle",))
        entry = text.strip()
        if remember and entry and "\n" not in entry and len(entry) < 200:
            self.history = [entry] + [h for h in self.history if h != entry][:19]
            self.target_box.configure(values=self.history)
        if start:
            for t in targets:
                self.start_session(self.key(t))
        if select and targets:
            keys = [self.key(t) for t in targets]
            self.tree.selection_set(keys)
            self.tree.see(keys[0])
            self.show_session(keys[0])
        if bad:
            self.app.flash(f"Ignored: {' '.join(bad[:5])}{' …' if len(bad) > 5 else ''}")
        self.update_status()
        return targets

    # ---- notes

    def on_double(self, event):
        row = self.tree.identify_row(event.y)
        if row and self.tree.identify_column(event.x) == "#2":
            self.edit_note(row)
            return "break"

    def edit_note(self, key=None):
        key = key or (self.selected_keys() or [None])[0]
        if key not in self.sessions:
            return
        self.tree.see(key)
        self.update_idletasks()
        bbox = self.tree.bbox(key, "Note")
        if not bbox:
            return
        if self.note_editor:
            self.note_editor.destroy()
        var = tk.StringVar(value=self.sessions[key].note)
        ed = ttk.Entry(self.tree, textvariable=var)
        x, y, w, h = bbox
        ed.place(x=x, y=y, width=max(w, 160), height=h)
        ed.focus_set()
        ed.select_range(0, "end")
        self.note_editor = ed

        def save(_=None):
            if self.note_editor is ed:
                self.note_editor = None
                self.set_note(key, var.get())
                ed.destroy()

        def cancel(_=None):
            self.note_editor = None             # first, so the FocusOut from destroy doesn't save
            ed.destroy()

        ed.bind("<Return>", save)
        ed.bind("<KP_Enter>", save)
        ed.bind("<FocusOut>", save)
        ed.bind("<Escape>", cancel)

    def set_note(self, key, note: str):
        if key in self.sessions:
            self.sessions[key].note = note.strip()
            self.refresh_row(key)
            if key == self.selected:
                self.update_detail()

    @staticmethod
    def key(target: str) -> str:
        return target.strip().lower()

    # ---- running

    def read_options(self):
        try:
            count = max(0, int(self.count_v.get() or 0))
            interval = max(0.2, float(self.interval_v.get()))
            timeout = max(0.2, float(self.timeout_v.get()))
            size = int(self.size_v.get()) if self.size_v.get().strip() else None
            if size is not None and not 0 <= size <= 65500:
                raise ValueError
        except ValueError:
            raise ValueError("Count, interval, timeout and size must be numbers "
                             "(interval and timeout at least 0.2 s).")
        return count, interval, timeout, size

    def start_session(self, key: str, fresh: bool = False):
        sess = self.sessions.get(key)
        if sess is None or sess.running:
            return
        try:
            count, interval, timeout, size = self.read_options()
        except ValueError as exc:
            self.status_lbl.configure(text=str(exc))
            return
        ipv6 = self.v6_v.get() or ":" in sess.target
        if not pinger.find_tool(ipv6):
            self.status_lbl.configure(text="ping isn't installed (Linux: sudo apt install iputils-ping).")
            return
        sess.size = size
        if fresh:
            sess.stats, sess.log, sess.started = pinger.PingStats(), [], None
        # Starting again continues the same history and statistics; the run time restarts.
        sess.started = sess.started if sess.log and not fresh else datetime.now()
        sess.ended, sess.user_stopped, sess.error = None, False, ""
        sess.stop_event = threading.Event()
        if self.queue is None:
            import queue
            self.queue = queue.Queue()
        q, stop, target = self.queue, sess.stop_event, sess.target
        first_n = len(sess.log)

        def work():
            try:
                ip = pinger.resolve(target, ipv6)
            except OSError as exc:
                q.put((key, "error", f"Can't resolve {target}: {exc}"))
                q.put((key, "done", stop))
                return
            is6 = ":" in ip
            cmd = pinger.build_command(ip, timeout, size, is6, tool=pinger.find_tool(is6))
            q.put((key, "resolved", (ip, " ".join(cmd))))
            begin = time.monotonic()
            n = 0
            while not stop.is_set() and (count == 0 or n < count):
                n += 1
                stamp = datetime.now()
                result = pinger.run_probe(cmd, timeout)
                if stop.is_set() and not result.ok:
                    break                       # don't count a probe cut short by Stop
                q.put((key, "probe", (first_n + n, stamp, result)))
                stop.wait(max(0.0, begin + n * interval - time.monotonic()))
            q.put((key, "done", stop))

        sess.thread = threading.Thread(target=work, daemon=True)
        sess.thread.start()
        self.refresh_row(key)
        if not self._polling:
            self._polling = True
            self._poll_job = self.after(100, self.poll)

    def stop_session(self, key: str):
        sess = self.sessions.get(key)
        if sess and sess.running:
            sess.stop_event.set()
            sess.user_stopped = True

    @property
    def worker(self):
        """Truthy while any target is being pinged (kept for older callers)."""
        return any(s.running for s in self.sessions.values()) or None

    def stop(self):
        for k in list(self.sessions):
            self.stop_session(k)

    def start_all(self):
        for k in list(self.sessions):
            self.start_session(k)

    def selected_keys(self):
        return [k for k in self.tree.selection() if k in self.sessions]

    def start_selected(self):
        for k in self.selected_keys():
            self.start_session(k)

    def stop_selected(self):
        for k in self.selected_keys():
            self.stop_session(k)

    def restart_selected(self):
        keys = self.selected_keys()
        for k in keys:
            self.stop_session(k)

        def go():
            if any(self.sessions[k].running for k in keys if k in self.sessions):
                self.after(100, go)
                return
            for k in keys:
                if k in self.sessions:
                    self.start_session(k, fresh=True)
            if self.selected in keys:
                self.show_session(self.selected)
        go()

    def remove_selected(self):
        keys = self.selected_keys()
        for k in keys:
            self.stop_session(k)
            self.sessions.pop(k, None)
            if self.tree.exists(k):
                self.tree.delete(k)
        if self.selected in keys:
            self.show_session(None)
        self.update_status()

    def remove_all(self):
        self.tree.selection_set(list(self.sessions))
        self.remove_selected()

    def clear(self):
        """Older callers: clear the selected target's history."""
        if self.selected and not self.sessions[self.selected].running:
            sess = self.sessions[self.selected]
            sess.stats, sess.log, sess.started, sess.ended = pinger.PingStats(), [], None, None
            self.show_session(self.selected)

    def poll(self):
        import queue as _q
        touched = set()
        handled = 0
        while handled < 2000:
            try:
                key, kind, data = self.queue.get_nowait()
            except _q.Empty:
                break
            handled += 1
            sess = self.sessions.get(key)
            if sess is None:
                continue                      # removed while running
            touched.add(key)
            if kind == "resolved":
                sess.ip, sess.cmd = data
            elif kind == "probe":
                n, stamp, r = data
                sess.stats.add(r)
                sess.log.append(data)
                if len(sess.log) > PingSession.MAX_LOG:
                    del sess.log[:5000]
                if key == self.selected:
                    self.add_log_row(n, stamp, r)
            elif kind == "error":
                sess.error = data
            elif kind == "done":
                if data is sess.stop_event:       # ignore a stale "done" from an earlier run
                    sess.thread = None
                    sess.ended = datetime.now()
        for key in touched:
            self.refresh_row(key)
        if self.selected in touched:
            self.update_detail()
        self.update_status()
        if any(s.running for s in self.sessions.values()) or not self.queue.empty():
            self._poll_job = self.after(100, self.poll)
        else:
            self._polling = False

    def _tick(self):
        """Keep run-time columns/tiles ticking once a second."""
        for k, sess in self.sessions.items():
            if sess.running:
                self.refresh_row(k)
        if self.selected and self.selected in self.sessions and self.sessions[self.selected].running:
            self.update_detail()
        self._tick_job = self.after(1000, self._tick)

    def shutdown(self):
        """Window closing: stop every ping and cancel timers."""
        try:
            self.stop()
        except tk.TclError:
            pass
        for job in (getattr(self, "_tick_job", None), getattr(self, "_poll_job", None)):
            if job:
                try:
                    self.after_cancel(job)
                except tk.TclError:
                    pass

    # ---- target table

    @staticmethod
    def ms(v):
        return "" if v is None else f"{v:.1f}" if v >= 1 else f"{v:.2f}"

    def row_values(self, sess: PingSession):
        st = sess.stats
        last = sess.last
        last_txt = "" if last is None else (self.ms(last.rtt) if last.ok else last.status)
        return (sess.target, sess.note, sess.ip if sess.ip != sess.target else "", self.size_text(sess),
                sess.state(), st.sent, st.ok,
                st.failed,
                f"{st.loss_pct:.1f}%" if st.sent else "", last_txt, self.ms(st.best), self.ms(st.average),
                self.ms(st.worst), pinger.format_duration(sess.elapsed()) if sess.started else "")

    @staticmethod
    def tag_for(sess: PingSession) -> str:
        last = sess.last
        if sess.error or (last is not None and not last.ok):
            return "dead"
        if last is None:
            return "idle"
        return "partial" if sess.stats.failed else "alive"

    JUMBO = 1024                   # sizes above this are shown in bold
    _BOLD = str.maketrans("0123456789", "".join(chr(0x1D7EC + i) for i in range(10)))   # 𝟬𝟭𝟮… (sans bold)

    def size_text(self, sess: PingSession) -> str:
        """Payload size for the table; bold (Unicode bold digits) when it's over 1024 bytes."""
        if not sess.started and not sess.running:
            return ""
        size = sess.size if sess.size is not None else pinger.default_size()
        return str(size).translate(self._BOLD) if size > self.JUMBO else str(size)

    # Status colours for the text of a selected row, readable on the near-black selection highlight.
    SEL_TEXT = {"alive": "#4ade80", "partial": "#fbbf24", "dead": "#f87171", "idle": "#cbd5e1"}

    def update_sel_color(self):
        """With one target selected and a dark highlight, colour its text by ping status."""
        c = self.app.colors
        st = ttk.Style(self)
        sel = self.tree.selection()
        fg = c["select_fg"]
        bg = c["select_bg"].lstrip("#")
        dark = sum(int(bg[i:i + 2], 16) * w for i, w in ((0, .299), (2, .587), (4, .114))) < 96
        if dark and len(sel) == 1 and sel[0] in self.sessions:
            fg = self.SEL_TEXT.get(self.tag_for(self.sessions[sel[0]]), fg)
        if getattr(self, "_sel_fg", None) != fg:
            self._sel_fg = fg
            st.map("Ping.Treeview", foreground=[("selected", fg)], background=[("selected", c["select_bg"])])

    def refresh_row(self, key):
        sess = self.sessions.get(key)
        if sess and self.tree.exists(key):
            self.tree.item(key, values=self.row_values(sess), tags=(self.tag_for(sess),))
            if key in self.tree.selection():
                self.update_sel_color()

    def update_status(self):
        n = len(self.sessions)
        running = sum(1 for s in self.sessions.values() if s.running)
        # tab reads "Ping (3)" while 3 targets are pinging; the number takes the colour of the worst one
        tags = {self.tag_for(s) for s in self.sessions.values() if s.running}
        worst = "down" if "dead" in tags else "loss" if "partial" in tags else "good" if "alive" in tags else None
        self.app.set_badge("ping", running, worst)
        failing = sum(1 for s in self.sessions.values() if self.tag_for(s) == "dead")
        if not n:
            self.status_lbl.configure(text="Add one or more hosts or IPs and press Add & start.")
            return
        msg = f"{n} target{'s' if n != 1 else ''}  ·  {running} pinging"
        if failing:
            msg += f"  ·  {failing} failing"
        self.status_lbl.configure(text=msg)

    def tree_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        if row not in self.tree.selection():
            self.tree.selection_set(row)
        sess = self.sessions[row]
        target = sess.ip or sess.target
        menu = tk.Menu(self, tearoff=False)
        if sess.running:
            menu.add_command(label="Stop", command=self.stop_selected)
        else:
            menu.add_command(label="Start", command=self.start_selected)
        menu.add_command(label="Edit note…", command=lambda: self.edit_note(row))
        menu.add_command(label="Restart (clear history)", command=self.restart_selected)
        menu.add_command(label="Remove", command=self.remove_selected)
        menu.add_separator()
        menu.add_command(label=f"Traceroute to {target}", command=lambda: self.app.goto_trace(target))
        menu.add_command(label=f"Copy {target}", command=lambda: self.app.copy(target))
        self.app.popup_tree_menu(menu, event)

    def copy_table(self):
        if self.tree.get_children():
            self.app.copy(texttable.tree_table(self.tree))

    # ---- details of the selected target

    def on_select(self, _=None):
        sel = self.selected_keys()
        if sel and sel[0] != self.selected:
            self.show_session(sel[0])
        elif not sel:
            self.show_session(None)

    def show_session(self, key):
        self.selected = key if key in self.sessions else None
        if self.selected is None:
            self.detail.pack_forget()
            self.empty_lbl.pack(anchor="w", pady=(10, 0))
            return
        self.empty_lbl.pack_forget()
        self.detail.pack(fill="both", expand=True)
        self.fill_log()
        self.update_detail()

    def fill_log(self):
        self.log.delete(*self.log.get_children())
        sess = self.sessions.get(self.selected)
        if not sess:
            return
        rows = [e for e in sess.log if not (self.failonly_v.get() and e[2].ok)]
        shown = rows[-self.SHOW_LOG:]
        for n, stamp, r in reversed(shown):              # newest probe at the top
            self._insert_log(n, stamp, r)
        more = len(rows) - len(shown)
        self.log_lbl.configure(text="History, newest first" + (
            f"  (latest {len(shown):,} of {len(rows):,} shown; Copy/Save include all)" if more
            else f"  ({len(rows):,})"))
        self.log.yview_moveto(0)

    def _insert_log(self, n, stamp, r, index="end"):
        rtt = "" if r.rtt is None else (f"{r.rtt:g}" if r.rtt >= 1 else "<1")
        tag = () if r.ok else ("unreach",) if r.status == "Unreachable" else ("fail",)
        self.log.insert("", index, values=(n, stamp.strftime("%Y-%m-%d %H:%M:%S"), r.status, rtt,
                                           r.ttl or "", r.detail), tags=tag)

    def add_log_row(self, n, stamp, r):
        if self.failonly_v.get() and r.ok:
            return
        kids = self.log.get_children()
        at_top = not kids or self.log.yview()[0] <= 0.0
        self._insert_log(n, stamp, r, index=0)           # newest probe at the top
        if len(kids) >= self.SHOW_LOG:
            self.log.delete(kids[-1])                     # drop the oldest shown row
        if at_top:
            self.log.yview_moveto(0)
        else:
            self.log.yview_scroll(1, "units")             # scrolled down to read older rows: keep them in place
        sess = self.sessions[self.selected]
        total = sum(1 for e in sess.log if not (self.failonly_v.get() and e[2].ok))
        self.log_lbl.configure(text=f"History, newest first  ({total:,})")

    def update_detail(self):
        sess = self.sessions.get(self.selected)
        if not sess:
            return
        s = sess.stats
        ms = lambda v: "–" if v is None else f"{v:.2f} ms" if v < 10 else f"{v:.1f} ms"
        vals = {
            "sent": f"{s.sent:,}", "ok": f"{s.ok:,}", "failed": f"{s.failed:,}",
            "loss": f"{s.loss_pct:.1f}%" if s.sent else "–",
            "best": ms(s.best), "avg": ms(s.average), "worst": ms(s.worst), "jitter": ms(s.jitter),
            "outage": f"{s.longest_outage} probe{'s' if s.longest_outage != 1 else ''}" if s.sent else "–",
            "elapsed": pinger.format_duration(sess.elapsed()) if sess.started else "–",
        }
        for key, label in self.tile_vals.items():
            label.configure(text=vals[key])
        self.tile_vals["failed"].configure(foreground=self.app.colors["error"] if s.failed else "")
        shown = sess.target if not sess.ip or sess.ip == sess.target else f"{sess.target} [{sess.ip}]"
        state = sess.error or {"Pinging": "pinging…", "Resolving": "resolving…"}.get(sess.state(),
                                                                                  sess.state().lower())
        self.detail_lbl.configure(text=f"{shown}  —  " + (f"{sess.note}  —  " if sess.note else "") + state)
        when = f"Started {sess.started:%Y-%m-%d %H:%M:%S}" if sess.started else ""
        if sess.ended and sess.started:
            when += f"   ·   Ended {sess.ended:%Y-%m-%d %H:%M:%S}"
        self.times_lbl.configure(text=when)
        self.cmd_lbl.configure(text=f"Command per probe: {sess.cmd}\n{pinger.explain_command(sess.cmd)}"
                                    if sess.cmd else "")

    def summary(self, key=None) -> str:
        sess = self.sessions.get(key or self.selected)
        if not sess:
            return ""
        s = sess.stats
        ms = lambda v: "–" if v is None else f"{v:.2f} ms"
        lines = [f"Ping {sess.target}" + (f" [{sess.ip}]" if sess.ip and sess.ip != sess.target else ""),
                 f"Note: {sess.note}" if sess.note else "",
                 f"Started: {sess.started:%Y-%m-%d %H:%M:%S}" if sess.started else "",
                 f"Total time: {pinger.format_duration(sess.elapsed())}",
                 f"Sent: {s.sent}   Succeeded: {s.ok}   Failed: {s.failed}   Loss: {s.loss_pct:.1f}%",
                 f"Best: {ms(s.best)}   Average: {ms(s.average)}   Worst: {ms(s.worst)}   Jitter: {ms(s.jitter)}",
                 f"Longest outage: {s.longest_outage} consecutive failed probe(s)"]
        return "\n".join(l for l in lines if l)

    def copy_summary(self):
        text = "\n\n".join(self.summary(k) for k in self.selected_keys()) or self.summary()
        if text:
            self.app.copy(text)

    def log_text(self, tsv: bool = False) -> str:
        sess = self.sessions.get(self.selected)
        if not sess:
            return ""
        rows = []
        for n, stamp, r in sess.log:
            if self.failonly_v.get() and r.ok:
                continue
            rtt = "" if r.rtt is None else f"{r.rtt:g}"
            rows.append((n, stamp.strftime("%Y-%m-%d %H:%M:%S"), r.status, rtt, r.ttl or "", r.detail))
        rows.reverse()                                    # newest first, like the table
        if tsv:                                   # for spreadsheets (Save as .tsv)
            return "\n".join("\t".join(str(v) for v in r) for r in [self.LOG_COLUMNS] + rows)
        return texttable.format_table(self.LOG_COLUMNS, rows)

    def copy_log(self):
        if self.selected:
            self.app.copy(self.log_text())

    def save_log(self):
        if not self.selected:
            return
        from tkinter import filedialog
        sess = self.sessions[self.selected]
        safe = re.sub(r"[^\w.-]", "_", sess.target)
        name = filedialog.asksaveasfilename(parent=self, title="Save ping history", defaultextension=".tsv",
                                            initialfile=f"ping-{safe}-{datetime.now():%Y%m%d-%H%M}.tsv",
                                            filetypes=[("Tab-separated", "*.tsv"), ("Text", "*.txt"),
                                                       ("All files", "*")])
        if name:
            try:
                tsv = name.lower().endswith(".tsv")
                Path(name).write_text(self.summary() + "\n\n" + self.log_text(tsv=tsv) + "\n", encoding="utf-8")
                self.app.flash(f"Saved {name}")
            except OSError as exc:
                self.app.flash(f"Couldn't save: {exc}")


# --------------------------------------------------------------------------- whois tab (Team Cymru)


def he_url(query: str, rec) -> str:
    """Hurricane Electric's BGP Toolkit page for a Cymru answer."""
    import urllib.parse
    if rec.kind == "asn":
        return f"https://bgp.he.net/AS{rec.asn}"
    if "/" in query:
        return "https://bgp.he.net/net/" + urllib.parse.quote(query, safe="/:")
    return "https://bgp.he.net/ip/" + urllib.parse.quote(query, safe=":")



class WhoisTab(ttk.Frame):
    """IP / prefix / ASN lookups. Source "cymru" (the default): Team Cymru's IP to ASN mapping service (whois
    bulk mode on TCP 43, or DNS). Source "arin": ARIN's Whois-RWS, with the other registries via RDAP.
    Domain names use RDAP / WHOIS either way; ARIN handles (NET-…, ORG-…) always go to ARIN."""

    COLUMNS = ("Query", "Network", "Origin AS", "Owner", "Country", "Type", "Allocated", "Notes")
    ARIN_COLUMNS = ("Query", "Network", "Net name", "Organization", "Country", "Type", "Abuse email", "Notes")
    SOURCES = ("cymru", "arin")
    MAX_LOOKUPS = 2000
    VIA = (("auto", "Auto (whois, DNS if port 43 is blocked)"), ("whois", "whois (TCP 43)"), ("dns", "DNS"))

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        s = app.settings
        self.base = s.get("arin_base", arinwhois.BASE_URL)      # overrides only for testing
        self.rdap_base = s.get("rdap_base", arinwhois.RDAP_URL)
        self.cymru_host = s.get("cymru_host", cymru.WHOIS_HOST)          # overrides only for testing
        self.cymru_port = int(s.get("cymru_port", cymru.WHOIS_PORT))
        self.cymru_dns = s.get("cymru_dns_server", "")                     # blank = this computer's resolver
        self.cache = {}
        self.results = {}
        self.worker = None
        self.stop_event = None

        head = ttk.Frame(self)
        head.pack(fill="x")
        ttk.Label(head, text="Look up", style="Title.TLabel").pack(side="left")
        ttk.Label(head, text="  IPs, prefixes, ASNs (15169 / AS15169), BGP AS paths, or domain names",
                  style="Hint.TLabel").pack(side="left")
        ttk.Button(head, text="Clear", style="Small.TButton", command=self.clear_source).pack(side="right")
        ttk.Button(head, text="Paste", style="Small.TButton", command=self.paste).pack(side="right", padx=4)
        self.src = scrolled_text(self, app, height=5)
        self.src.container.pack(fill="x", pady=(4, 0))
        self.src.tag_configure("hit", **HIGHLIGHT_MAC)
        self.src.tag_raise("sel")
        self.src.insert("1.0", s.get("whois_input", "8.8.8.8\n3356 174 15169"))

        what = ttk.Frame(self)
        what.pack(fill="x", pady=(8, 0))
        self.do_ips_v = tk.BooleanVar(value=s.get("whois_ips", True))
        self.do_asns_v = tk.BooleanVar(value=s.get("whois_asns", True))
        self.bare_v = tk.BooleanVar(value=s.get("whois_bare_asns", True))
        self.do_domains_v = tk.BooleanVar(value=s.get("whois_domains", True))
        ttk.Label(what, text="Look up:", style="Field.TLabel").pack(side="left")
        for text_, var in (("IP addresses / prefixes", self.do_ips_v), ("ASNs", self.do_asns_v),
                           ("Plain numbers in AS paths are ASNs", self.bare_v), ("Domain names", self.do_domains_v)):
            ttk.Checkbutton(what, text=text_, variable=var, command=self.highlight).pack(side="left", padx=(8, 4))
        src = ttk.Frame(self)
        src.pack(fill="x", pady=(6, 0))
        self.contacts_v = tk.BooleanVar(value=s.get("whois_contacts", True))
        self.skip_v = tk.BooleanVar(value=s.get("whois_skip_private", True))
        self.rdap_v = tk.BooleanVar(value=s.get("whois_rdap", True))
        source = s.get("whois_source", "cymru")
        self.source_v = tk.StringVar(value=source if source in self.SOURCES else "cymru")
        ttk.Label(src, text="Source:", style="Field.TLabel").pack(side="left")
        ttk.Radiobutton(src, text="Ask", value="cymru", variable=self.source_v,
                        command=self.source_changed).pack(side="left", padx=(8, 0))
        link(src, "Team Cymru", lambda: __import__("webbrowser").open(cymru.WEBSITE),
             style="FieldLink.TLabel").pack(side="left", padx=(2, 4))
        ttk.Label(src, text="via").pack(side="left")
        names = dict(self.VIA)
        self.via_v = tk.StringVar(value=names.get(s.get("whois_via", "auto"), names["auto"]))
        self.via_box = ttk.Combobox(src, textvariable=self.via_v, values=list(names.values()), state="readonly",
                                    width=36)
        self.via_box.pack(side="left", padx=(4, 20))
        ttk.Radiobutton(src, text="ARIN and the other registries (RDAP)", value="arin", variable=self.source_v,
                        command=self.source_changed).pack(side="left")
        opt = ttk.Frame(self)
        opt.pack(fill="x", pady=(4, 0))
        ttk.Checkbutton(opt, text="Skip private / reserved", variable=self.skip_v).pack(side="left")
        self.contacts_cb = ttk.Checkbutton(opt, variable=self.contacts_v)
        self.contacts_cb.pack(side="left", padx=12)
        self.rdap_cb = ttk.Checkbutton(opt, text="Get owners from other registries (RIPE, APNIC, LACNIC, AFRINIC)",
                                       variable=self.rdap_v)
        self.stop_btn = ttk.Button(opt, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="right")
        self.go_btn = ttk.Button(opt, text="Look up", style="Accent.TButton", command=self.start)
        self.go_btn.pack(side="right", padx=6)

        ttk.Separator(self).pack(fill="x", pady=10)
        top = ttk.Frame(self)
        top.pack(fill="x")
        self.status_lbl = ttk.Label(top, style="Title.TLabel")
        self.status_lbl.pack(side="left")
        ttk.Button(top, text="Copy table", style="Small.TButton", command=self.copy_table).pack(side="right")

        self.path_frame = ttk.Frame(self)
        ph = ttk.Frame(self.path_frame)
        ph.pack(fill="x")
        ttk.Label(ph, text="AS path owners", style="Field.TLabel").pack(side="left")
        ttk.Button(ph, text="Copy paths", style="Small.TButton", command=self.copy_paths).pack(side="right")
        self.path_text = scrolled_text(self.path_frame, app, height=4)
        self.path_text.container.pack(fill="x", pady=(2, 0))
        self.path_text.configure(state="disabled", wrap="word")
        self.path_text.tag_configure("asn", font=app.mono)
        self.paths = []

        self.col_widths = (115, 130, 90, 220, 62, 120, 90, 160)
        self.tree = make_tree(self, self.COLUMNS, self.col_widths)
        self._autosize_job = None
        self.tree.configure(height=9, selectmode="browse")
        self.tree.column("Country", stretch=False, anchor="center")
        self.tree.container.pack(fill="both", expand=True, pady=(6, 0))
        self.tree_container = self.tree.container
        make_sortable(self.tree)
        self.tree.tag_configure("error", foreground=app.colors["error"])
        self.tree.tag_configure("rir", foreground=app.colors["warn"])
        self.tree.tag_configure("local", foreground=app.colors["muted"])
        self.tree.bind("<<TreeviewSelect>>", self.show_detail)
        self.tree.bind(app.right_click, self.tree_menu)

        dh = ttk.Frame(self)
        dh.pack(fill="x", pady=(10, 0))
        ttk.Label(dh, text="Details", style="Title.TLabel").pack(side="left")
        ttk.Button(dh, text="Copy details", style="Small.TButton", command=self.copy_detail).pack(side="right")
        self.web_btn = ttk.Button(dh, text="Open in bgp.he.net", style="Small.TButton", command=self.open_web)
        self.web_btn.pack(side="right", padx=4)
        self.rir_btn = ttk.Button(dh, text="Open other registry", style="Small.TButton", command=self.open_rir)
        self.detail = scrolled_text(self, app, height=16)
        self.detail.container.pack(fill="both", expand=True, pady=(4, 0))
        self.detail.configure(state="disabled")
        web = __import__("webbrowser")
        self.foot_cymru = ttk.Frame(self)
        # every label boundary falls on a word gap (ttk labels keep a few pixels of border around them)
        for text_, url in (("IP and ASN data from", None), ("Team Cymru", cymru.WEBSITE), ("via its", None),
                           ("IP to ASN mapping service", cymru.INFO_URL),
                           ("(whois.cymru.com). Domains via RDAP / WHOIS.", None)):
            if url:
                w = link(self.foot_cymru, text_, lambda u=url: web.open(u), style="HintLink.TLabel")
            else:
                w = ttk.Label(self.foot_cymru, text=text_, style="Hint.TLabel")
            w.pack(side="left", padx=(0, 1))
        self.foot_arin = ttk.Frame(self)
        for text_, url in (("Data from ARIN Whois-RWS (whois.arin.net) and the other registries' RDAP. Use is "
                            "subject to ARIN's", None), ("Whois Terms of Use", arinwhois.TOU_URL)):
            if url:
                w = link(self.foot_arin, text_, lambda u=url: web.open(u), style="HintLink.TLabel")
            else:
                w = ttk.Label(self.foot_arin, text=text_, style="Hint.TLabel")
            w.pack(side="left", padx=(0, 1))
        self.mode = None
        self.source_changed()

        self.debounce = Debouncer(self, 250, self.highlight)
        self.src.bind("<<Modified>>", self._modified)
        self.src.bind("<Control-Return>", lambda e: self.start())
        self.src.bind("<Command-Return>", lambda e: self.start())
        self.status_lbl.configure(text="Enter something to look up and press Look up (Ctrl/⌘+Return).")
        self.tlds = set(domainwhois.COMMON_TLDS)
        self.domain_cache_dir = settings_path().parent
        self.bootstrap_url = s.get("domain_bootstrap_url", domainwhois.BOOTSTRAP_URL)   # override for testing
        self.iana_whois = tuple(s.get("domain_iana_whois", domainwhois.IANA_WHOIS))
        self.whois_port = int(s.get("domain_whois_port", 43))
        self.highlight()
        import threading

        def load_tlds():
            try:
                domainwhois.load_bootstrap(self.domain_cache_dir, self.bootstrap_url, 10)
                self.tlds = domainwhois.known_tlds()
            except Exception:
                pass
        threading.Thread(target=load_tlds, daemon=True).start()

    def via_key(self) -> str:
        return {v: k for k, v in self.VIA}.get(self.via_v.get(), "auto")

    def source_key(self) -> str:
        v = self.source_v.get()
        return v if v in self.SOURCES else "cymru"

    def source_changed(self):
        """Show the options and footer for the chosen source (the table follows on the next Look up)."""
        cymru_mode = self.source_key() == "cymru"
        self.via_box.configure(state="readonly" if cymru_mode else "disabled")
        self.contacts_cb.configure(text="Registrar contacts for domains" if cymru_mode else "Include contacts")
        if cymru_mode:
            self.rdap_cb.pack_forget()
        elif not self.rdap_cb.winfo_ismapped():
            self.rdap_cb.pack(side="left", after=self.contacts_cb)
        show, hide = (self.foot_cymru, self.foot_arin) if cymru_mode else (self.foot_arin, self.foot_cymru)
        hide.pack_forget()
        show.pack(fill="x", pady=(4, 0))
        if not self.results:
            self.set_columns(self.source_key())

    def columns_for(self, mode):
        if mode == "arin":
            return self.ARIN_COLUMNS, (115, 115, 110, 160, 62, 120, 170, 120)
        return self.COLUMNS, (115, 130, 90, 220, 62, 120, 90, 160)

    def set_columns(self, mode):
        """Switch the table between the Team Cymru and ARIN column sets."""
        if mode == self.mode:
            return
        self.mode = mode
        cols, widths = self.columns_for(mode)
        self.col_widths = widths
        self.tree.delete(*self.tree.get_children())
        self.tree.configure(columns=cols, displaycolumns=cols)
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, minwidth=w, stretch=True, anchor="w")
        self.tree.column("Country", stretch=False, anchor="center")
        make_sortable(self.tree)

    # ---- source box

    def _modified(self, _):
        if self.src.edit_modified():
            self.src.edit_modified(False)
            self.debounce()

    def get_text(self):
        return self.src.get("1.0", "end-1c")

    def queries(self):
        text = self.get_text().strip()
        found = arinwhois.extract_queries(text, include_asn=self.do_asns_v.get(), bare_asns=self.bare_v.get())
        if not self.do_ips_v.get():
            found = [q for q in found if q.upper().startswith("AS")]
        if self.do_domains_v.get():
            found += [d for d in domainwhois.extract_domains(text, self.tlds) if d not in found]
        if not found and text and len(text.split()) == 1:
            found = [text]                       # a bare handle like GOGL or NET-8-8-8-0-2
        return found

    def highlight(self):
        self.src.tag_remove("hit", "1.0", "end")
        pats = []
        if self.do_ips_v.get():
            pats += [arinwhois._V4, arinwhois._V6]
        if self.do_asns_v.get():
            pats.append(arinwhois._AS)
        for n, line in enumerate(self.get_text().splitlines(), 1):
            for pat in pats:
                for m in re.finditer(pat, line):
                    self.src.tag_add("hit", f"{n}.{m.start()}", f"{n}.{m.end()}")
            if self.do_domains_v.get():
                for m in domainwhois._DOMAIN.finditer(line):
                    if m.group(1).lower().rsplit(".", 1)[-1] in self.tlds:
                        self.src.tag_add("hit", f"{n}.{m.start(1)}", f"{n}.{m.end(1)}")
            if self.do_asns_v.get() and self.bare_v.get():
                path = arinwhois.as_path_from_line(line)
                if path:      # the path is the last N numbers on the line
                    nums = [m for m in re.finditer(r"(?<![\w.:/])\d+(?:\.\d+)?(?![\w.:/])", line)]
                    for m in nums[-len(path):]:
                        self.src.tag_add("hit", f"{n}.{m.start()}", f"{n}.{m.end()}")

    def paste(self):
        try:
            text = self.app.root.clipboard_get()
        except tk.TclError:
            return
        self.src.delete("1.0", "end")
        self.src.insert("1.0", text)
        self.highlight()

    def clear_source(self):
        self.src.delete("1.0", "end")

    # ---- run

    def start(self):
        if self.worker:
            return "break"
        queries = self.queries()
        if not queries:
            self.status_lbl.configure(text="Nothing to look up – enter an IP, prefix, or ASN.")
            return "break"
        truncated = len(queries) > self.MAX_LOOKUPS
        queries = queries[:self.MAX_LOOKUPS]
        mode = self.source_key()
        self.set_columns(mode)
        self.tree.delete(*self.tree.get_children())
        for col, w in zip(self.columns_for(mode)[0], self.col_widths):   # default widths for a new search
            self.tree.column(col, width=w, minwidth=w)
        self.results = {}
        self.set_detail("")
        contacts, skip, follow = self.contacts_v.get(), self.skip_v.get(), self.rdap_v.get()
        via = self.via_key()
        self.paths = arinwhois.extract_as_paths(self.get_text()) if self.do_asns_v.get() and self.bare_v.get() else []
        self.show_paths()
        import queue
        import threading
        self.queue = queue.Queue()
        self.stop_event = threading.Event()
        q, stop, base, cache = self.queue, self.stop_event, self.base, self.cache

        def is_cymru(query):
            try:
                cymru.query_key(query)
                return True
            except cymru.CymruError:
                return False

        def work():
            local = {}
            for query in queries:
                if not domainwhois.is_domain(query):
                    note = arinwhois.local_note(query)
                    if note and skip:
                        local[query] = note
            asks = [x for x in queries if x not in local and not domainwhois.is_domain(x) and is_cymru(x)]
            if mode == "arin":
                asks = []                                     # ARIN / RDAP, one at a time below
            done_nets = []
            recs = {}
            if asks:
                q.put(("status", f"Asking Team Cymru about {len(asks)} item(s) …"))
                recs, note = cymru.lookup_many(
                    asks, via=via, host=self.cymru_host, port=self.cymru_port, dns_server=self.cymru_dns,
                    progress=lambda i, n: q.put(("status", f"Team Cymru over DNS: {i} of {n} …")),
                    stop=stop.is_set)
                if note:
                    q.put(("note", note))
            for i, query in enumerate(queries, 1):
                if stop.is_set():
                    break
                if query in local:
                    r = arinwhois.WhoisResult(query=query, kind="local", note=local[query])
                elif domainwhois.is_domain(query):
                    info = domainwhois.lookup_domain(query, timeout=15, follow_registrar=contacts,
                                                     cache_dir=self.domain_cache_dir, bootstrap_url=self.bootstrap_url,
                                                     iana=self.iana_whois, whois_port=self.whois_port)
                    r = arinwhois.WhoisResult(query=query, kind="domain", domain=info,
                                              error="" if info.not_registered else info.error)
                elif query in recs:
                    rec = recs[query]
                    kind = "asn" if rec.kind == "asn" else ("cidr" if "/" in query else "ip")
                    r = arinwhois.WhoisResult(query=query, kind=kind, error=rec.error, note=rec.note,
                                              raw={"cymru": rec})
                elif mode == "cymru" and is_cymru(query):
                    continue                                  # stopped before Team Cymru answered
                elif mode == "arin":
                    # reuse an earlier answer for addresses in the same network – but not for other registries,
                    # where ARIN only returns the whole regional block (e.g. a RIPE /8)
                    reuse = next((d for d in done_nets if d.net and not d.other_rir and "/" not in query
                                  and d.net.contains(query)), None)
                    if reuse:
                        import copy
                        r = copy.copy(reuse)
                        r.query = query
                        r.note = (f"Same network as {reuse.query}. " + (reuse.note or "")).strip()
                    else:
                        r = arinwhois.lookup(query, contacts=contacts, base=base, cache=cache, follow_rdap=follow,
                                             rdap_base=self.rdap_base)
                        if r.net:
                            done_nets.append(r)
                else:                                         # an ARIN handle such as NET-8-8-8-0-2 or GOGL
                    r = arinwhois.lookup(query, contacts=contacts, base=base, cache=cache, follow_rdap=True,
                                         rdap_base=self.rdap_base)
                    r.note = ("ARIN handle (Team Cymru only maps IPs and ASNs). " + (r.note or "")).strip()
                q.put(("result", (i, r)))
            q.put(("done", None))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()
        self.total = len(queries)
        self.truncated = truncated
        self.go_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.via_note = ""
        self.status_lbl.configure(text=f"Looking up {self.total} item(s)" + (" at ARIN" if mode == "arin" else "")
                                  + " …")
        self.after(100, self.poll)
        return "break"

    def stop(self):
        if self.stop_event and self.worker:
            self.stop_event.set()

    def poll(self):
        import queue as _q
        finished = False
        while True:
            try:
                kind, data = self.queue.get_nowait()
            except _q.Empty:
                break
            if kind == "result":
                i, r = data
                self.add_result(i, r)
                if r.kind in ("asn", "local") and self.paths:
                    self.show_paths()
                self.status_lbl.configure(text=f"Looked up {i} of {self.total} …")
            elif kind == "status":
                self.status_lbl.configure(text=data)
            elif kind == "note":
                self.via_note = data
            else:
                finished = True
        if finished:
            self.worker = None
            self.go_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            errors = sum(1 for r in self.results.values() if r.error)
            msg = f"Done – {len(self.results)} result(s)" + (f", {errors} error(s)" if errors else "")
            if self.truncated:
                msg += f" (only the first {self.MAX_LOOKUPS} were looked up)"
            if self.via_note:
                msg += f" · {self.via_note}"
            if arinwhois.ssl_fallback_used():
                msg += (" · certificate checks skipped: couldn't verify the servers with this computer's "
                        f"certificates ({arinwhois.trust_source()})")
            self.status_lbl.configure(text=msg)
            kids = self.tree.get_children()
            if kids and not self.tree.selection():
                self.tree.selection_set(kids[0])
        else:
            self.after(100, self.poll)

    def add_result(self, i, r):
        iid = f"r{i}"
        self.results[iid] = r
        rec = r.raw.get("cymru") if r.raw else None
        if rec is not None:
            values, tag = self.cymru_row(r, rec)
            self.tree.insert("", "end", iid=iid, values=values, tags=tag)
            if self._autosize_job:
                self.after_cancel(self._autosize_job)
            self._autosize_job = self.after(150, lambda: autosize_columns(self.tree, self.app.mono, max_px=520))
            return
        org = r.owner
        country = r.country
        if r.error:
            values = (r.query, "", "", "", "", "Domain" if r.kind == "domain" else "", "", r.error)
            tag = ("error",)
        elif r.kind == "domain" and r.domain.not_registered:
            tld = r.query.rsplit(".", 1)[-1]
            values = (r.query, "", "", "", "", f"Domain .{tld}", "", "Not registered (domain not found)")
            tag = ("local",)
        elif r.kind == "domain":
            d = r.domain
            days = d.days_to_expiry
            notes = f"Expires {d.expires}" + (f" ({days} days)" if days is not None else "") if d.expires else ""
            if d.note and "host name" in d.note:
                notes = (notes + " · registered domain " + d.domain).strip(" ·")
            if self.mode == "arin":
                values = (r.query, d.domain, d.registrar, d.registrant_org or "(not published)",
                          d.registrant_country, "Domain ." + d.domain.rsplit(".", 1)[-1], d.abuse_email, notes)
            else:
                if d.registrar:
                    notes = (f"Registrar {d.registrar} · " + notes).strip(" ·")
                values = (r.query, d.domain, "", d.registrant_org or "(not published)", d.registrant_country,
                          "Domain ." + d.domain.rsplit(".", 1)[-1], (d.created or "")[:10], notes)
            tag = ("rir",) if days is not None and days < 30 else ()
        elif r.kind == "local":
            values = (r.query, "", "", "", "", r.note, "", "Not looked up (local / special-use address)")
            tag = ("local",)
        else:
            rir = r.other_rir.split(" (")[0]
            if r.net:
                network = ", ".join(r.rdap.cidrs) if r.rdap and r.rdap.cidrs else r.net.cidrs
                name, typ = r.name, r.net.type_name
            elif r.asn:
                network, name, typ = r.query, r.name, "ASN"
            else:
                network, name, typ = "", "", r.kind.upper()
            if r.rdap:
                notes = f"Owner from {rir} (RDAP)"
                typ = f"{typ} · {rir}" if r.asn else typ
            elif r.other_rir:
                notes = f"Registered with {rir}" + (" – " + r.note if r.note else "")
            else:
                notes = r.note
            if self.mode == "arin":
                values = (r.query, network, name, org, country, typ, ", ".join(r.abuse_emails), notes)
            else:
                notes = " · ".join(x for x in (name, ", ".join(r.abuse_emails), notes) if x)
                values = (r.query, network, "", org, country, typ, "", notes)
            tag = ("rir",) if r.other_rir else ()
        self.tree.insert("", "end", iid=iid, values=values, tags=tag)
        if self._autosize_job:                       # widen columns to fit (table scrolls sideways if needed)
            self.after_cancel(self._autosize_job)
        self._autosize_job = self.after(150, lambda: autosize_columns(self.tree, self.app.mono, max_px=520))

    def cymru_row(self, r, rec):
        """Table values for a Team Cymru answer."""
        if rec.error:
            return (r.query, "", "", "", "", "ASN" if rec.kind == "asn" else "", "", rec.error), ("error",)
        reg = rec.registry_name
        if rec.kind == "asn":
            typ = "ASN" + (f" · {reg}" if reg else "")
            return (r.query, "", f"AS{rec.asn}", rec.as_name, rec.cc, typ, rec.allocated, rec.note), ()
        typ = ("Prefix" if "/" in r.query else "IP") + (f" · {reg}" if reg else "")
        tag = () if rec.announced else ("local",)
        if len(rec.asns) > 1:
            tag = ("rir",)
        return (r.query, rec.prefix, rec.origin or "not announced", rec.as_name, rec.cc, typ, rec.allocated,
                rec.note), tag

    # ---- details

    def selected(self):
        sel = self.tree.selection()
        return self.results.get(sel[0]) if sel else None

    def set_detail(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def show_detail(self, _=None):
        r = self.selected()
        if not r:
            return
        rec = r.raw.get("cymru") if r.raw else None
        self.web_btn.configure(text="Open in ICANN Lookup" if r.kind == "domain" else
                               "Open in bgp.he.net" if rec is not None else "Open in ARIN Search")
        if rec is not None:
            self.set_detail(cymru.format_record(rec))
        elif r.kind == "domain":
            self.set_detail(domainwhois.format_domain(r.domain))
        elif r.kind == "local":
            self.set_detail(f"# {r.query}: {r.note}\n# Private, CGNAT and other special-use addresses aren't "
                            "registered to anyone, so they were skipped.\n# Untick 'Skip private …' to send them "
                            "to Team Cymru anyway.")
        else:
            self.set_detail(arinwhois.format_result(r))
        if r.other_rir:
            self.rir_btn.pack(side="right", padx=4, before=self.web_btn)
            self.rir_btn.configure(text=f"Open {r.other_rir.split(' (')[0]}")
        else:
            self.rir_btn.pack_forget()

    def open_web(self):
        r = self.selected()
        if r:
            import urllib.parse
            import webbrowser
            rec = r.raw.get("cymru") if r.raw else None
            if r.kind == "domain":
                name = r.domain.domain or r.query
                webbrowser.open("https://lookup.icann.org/en/lookup?name=" + urllib.parse.quote(name))
            elif rec is not None:
                webbrowser.open(he_url(r.query, rec))
            else:
                webbrowser.open(arinwhois.WEB_URL.format(query=urllib.parse.quote(r.query)))

    def open_rir(self):
        r = self.selected()
        if r and r.other_rir_url:
            import webbrowser
            webbrowser.open(r.other_rir_url)

    def tree_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        r = self.results[row]
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label=f"Copy {r.query}", command=lambda: self.app.copy(r.query))
        rec = r.raw.get("cymru") if r.raw else None
        if rec is not None and not rec.error:
            if rec.origin:
                menu.add_command(label=f"Copy origin {rec.origin}", command=lambda: self.app.copy(rec.origin))
            if rec.as_name:
                menu.add_command(label="Copy AS name", command=lambda: self.app.copy(rec.as_name))
            if rec.prefix:
                menu.add_command(label=f"Open {rec.prefix} in IP Calc",
                                 command=lambda: self.app.open_in_calculator(rec.prefix))
            menu.add_command(label="Open in bgp.he.net",
                             command=lambda: __import__("webbrowser").open(he_url(r.query, rec)))
        if r.abuse_emails:
            menu.add_command(label=f"Copy abuse email {r.abuse_emails[0]}",
                             command=lambda: self.app.copy(", ".join(r.abuse_emails)))
        if r.net and r.net.cidrs:
            menu.add_command(label=f"Open {r.net.blocks[0].cidr if r.net.blocks else r.query} in IP Calc",
                             command=lambda: self.app.open_in_calculator(
                                 r.net.blocks[0].cidr if r.net.blocks else r.query))
        if r.kind == "domain":
            menu.add_command(label=f"DNS Digr {r.query}", command=lambda: self.app.goto_dig(r.query))
            menu.add_command(label=f"Ping {r.query}", command=lambda: self.app.goto_ping(r.query))
            menu.add_command(label=f"Traceroute to {r.query}", command=lambda: self.app.goto_trace(r.query))
        if r.kind == "ip":
            menu.add_command(label=f"Ping {r.query}", command=lambda: self.app.goto_ping(r.query))
            menu.add_command(label=f"Traceroute to {r.query}", command=lambda: self.app.goto_trace(r.query))
        self.app.popup_tree_menu(menu, event)

    def owner_for(self, asn: int) -> str:
        for r in self.results.values():
            if r.query == f"AS{asn}":
                if r.kind == "local":
                    return r.note
                if r.error:
                    return "?"
                rec = r.raw.get("cymru") if r.raw else None
                if rec is not None:
                    return rec.as_name or "?"
                return r.owner or r.name
        return "…"

    def path_lines(self):
        lines_ = []
        for i, path in enumerate(self.paths, 1):
            hops = []
            for asn, count in path:
                rep_ = f" ×{count}" if count > 1 else ""
                hops.append(f"AS{asn}{rep_} ({self.owner_for(asn)})")
            lines_.append((f"Path {i}: " if len(self.paths) > 1 else "") + "  →  ".join(hops))
        return lines_

    def show_paths(self):
        if not self.paths:
            self.path_frame.pack_forget()
            return
        if not self.path_frame.winfo_ismapped():
            self.path_frame.pack(fill="x", pady=(6, 0), before=self.tree_container)
        self.path_text.configure(state="normal")
        self.path_text.delete("1.0", "end")
        self.path_text.insert("1.0", "\n".join(self.path_lines()))
        self.path_text.configure(state="disabled", height=min(6, max(2, len(self.paths) * 2)))

    def copy_paths(self):
        self.app.copy("\n".join(self.path_lines()))

    def copy_table(self):
        self.app.copy(texttable.tree_table(self.tree))

    def copy_detail(self):
        self.app.copy(self.detail.get("1.0", "end-1c"))


# --------------------------------------------------------------------------- app


# --------------------------------------------------------------------------- compare tab

DIFF_COLORS = {   # light backgrounds in both modes, so text on them is always black
    "del": "#ffd7d5", "ins": "#d4f5d9", "chg": "#fff1bd",
    "delchar": "#ff9c95", "inschar": "#8fdf9f",
}
WS_MODES = [("Compare all whitespace", "none"), ("Ignore trailing whitespace", "trailing"),
            ("Ignore leading & trailing", "ends"), ("Ignore all whitespace changes", "all")]
DEFAULT_IGNORE = r"^!|Building configuration|Current configuration|ntp clock-period|Last configuration change"


class CompareTab(ttk.Frame):
    """Compare two texts or files: side by side, unified diff, or lines unique to each side."""

    AUTO_LIMIT = 1_000_000          # characters; above this, compare only when the button is pressed

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        s = app.settings
        self.names = ["", ""]
        self.rows, self.stats, self.unified_text = [], None, ""
        self.hunks, self.hunk_idx = [], -1
        self._syncing = False

        head = ttk.Frame(self)
        head.pack(fill="x")
        ttk.Label(head, text="Compare", style="Title.TLabel").pack(side="left")
        ttk.Label(head, text="  open two files or paste text into each side", style="Hint.TLabel").pack(side="left")

        # ---- inputs
        inputs = ttk.Frame(self)
        inputs.pack(fill="x", pady=(6, 0))
        inputs.columnconfigure(0, weight=1, uniform="side")
        inputs.columnconfigure(1, weight=1, uniform="side")
        self.src, self.name_lbls, self.count_lbls = [], [], []
        for col, title in enumerate(("Left (original)", "Right (changed)")):
            box = ttk.Frame(inputs)
            box.grid(row=0, column=col, sticky="nsew", padx=(0, 6) if col == 0 else (6, 0))
            bar = ttk.Frame(box)
            bar.pack(fill="x")
            ttk.Label(bar, text=title, style="Field.TLabel").pack(side="left")
            ttk.Button(bar, text="Clear", style="Small.TButton",
                       command=lambda c=col: self.clear_side(c)).pack(side="right")
            ttk.Button(bar, text="Paste", style="Small.TButton",
                       command=lambda c=col: self.paste(c)).pack(side="right", padx=4)
            ttk.Button(bar, text="Open file…", style="Small.TButton",
                       command=lambda c=col: self.open_file(c)).pack(side="right")
            info = ttk.Frame(box)
            info.pack(fill="x")
            name = ttk.Label(info, style="Hint.TLabel")
            name.pack(side="left")
            cnt = ttk.Label(info, style="Hint.TLabel")
            cnt.pack(side="right")
            t = scrolled_text(box, app, height=10, width=40)
            t.container.pack(fill="both", expand=True, pady=(2, 0))
            t.bind("<<Modified>>", self._modified)
            t.bind("<Control-Return>", lambda e: self.compare())
            t.bind("<Command-Return>", lambda e: self.compare())
            self.src.append(t)
            self.name_lbls.append(name)
            self.count_lbls.append(cnt)

        # ---- options
        opt = ttk.Frame(self)
        opt.pack(fill="x", pady=(8, 0))
        self.case_v = tk.BooleanVar(value=s.get("compare_case", False))
        self.blank_v = tk.BooleanVar(value=s.get("compare_blank", False))
        self.sort_v = tk.BooleanVar(value=s.get("compare_sort", False))
        ws_key = s.get("compare_ws", "none")
        self.ws_v = tk.StringVar(value=next((lbl for lbl, k in WS_MODES if k == ws_key), WS_MODES[0][0]))
        ws = ttk.Combobox(opt, textvariable=self.ws_v, values=[l for l, _ in WS_MODES], state="readonly", width=27)
        ws.pack(side="left")
        ws.bind("<<ComboboxSelected>>", lambda e: self.options_changed())
        for text_, var in (("Ignore case", self.case_v), ("Ignore blank lines", self.blank_v),
                           ("Sort lines first", self.sort_v)):
            ttk.Checkbutton(opt, text=text_, variable=var, command=self.options_changed).pack(side="left", padx=(10, 0))
        self.go_btn = ttk.Button(opt, text="Compare", style="Accent.TButton", command=self.compare)
        self.go_btn.pack(side="right")
        ttk.Button(opt, text="⇄ Swap", command=self.swap).pack(side="right", padx=6)

        opt2 = ttk.Frame(self)
        opt2.pack(fill="x", pady=(6, 0))
        self.ignore_on_v = tk.BooleanVar(value=s.get("compare_ignore_on", False))
        ttk.Checkbutton(opt2, text="Ignore lines matching regex:", variable=self.ignore_on_v,
                        command=self.options_changed).pack(side="left")
        self.ignore_v = tk.StringVar(value=s.get("compare_regex", DEFAULT_IGNORE))
        self.ignore_entry = ttk.Entry(opt2, textvariable=self.ignore_v, font=app.mono)
        self.ignore_entry.pack(side="left", fill="x", expand=True, padx=(6, 0))
        self.ignore_v.trace_add("write", lambda *a: self.ignore_on_v.get() and self.debounce())

        ttk.Separator(self).pack(fill="x", pady=10)

        # ---- result header
        top = ttk.Frame(self)
        top.pack(fill="x")
        self.status_lbl = ttk.Label(top, style="Title.TLabel")
        self.status_lbl.pack(side="left")
        self.pos_lbl = ttk.Label(top, style="Hint.TLabel")
        self.pos_lbl.pack(side="right")
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(6, 0))
        self.view_v = tk.StringVar(value=s.get("compare_view", "side"))
        for text_, val in (("Side by side", "side"), ("Unified diff", "unified"), ("Unique lines", "unique")):
            ttk.Radiobutton(bar, text=text_, value=val, variable=self.view_v,
                            command=self.show_view).pack(side="left", padx=(0, 10))
        self.hide_v = tk.BooleanVar(value=s.get("compare_hide_equal", False))
        ttk.Checkbutton(bar, text="Only differences, context", variable=self.hide_v,
                        command=self.render).pack(side="left", padx=(10, 4))
        self.ctx_v = tk.IntVar(value=s.get("compare_context", 3))
        ttk.Spinbox(bar, from_=0, to=99, width=3, textvariable=self.ctx_v,
                    command=self.render).pack(side="left")
        ttk.Button(bar, text="Save diff…", style="Small.TButton", command=self.save_diff).pack(side="right")
        ttk.Button(bar, text="Copy diff", style="Small.TButton", command=self.copy_diff).pack(side="right", padx=4)
        ttk.Button(bar, text="Next ▼", style="Small.TButton", command=lambda: self.goto_hunk(1)).pack(side="right")
        ttk.Button(bar, text="▲ Prev", style="Small.TButton",
                   command=lambda: self.goto_hunk(-1)).pack(side="right", padx=4)

        self.views = ttk.Frame(self)
        self.views.pack(fill="both", expand=True, pady=(6, 0))

        # side by side: two texts sharing one vertical and one horizontal scrollbar
        self.side_frame = ttk.Frame(self.views)
        self.side = []
        for col in (0, 1):
            t = tk.Text(self.side_frame, font=app.mono, wrap="none", height=22, width=40, relief="solid",
                        borderwidth=1, state="disabled", cursor="arrow")
            match_theme(app, t)
            t.grid(row=0, column=col * 2, sticky="nsew", padx=(0, 4) if col == 0 else (0, 0))
            t.configure(yscrollcommand=lambda f, l, src=t: self._sync_y(src, f, l),
                        xscrollcommand=lambda f, l, src=t: self._sync_x(src, f, l))
            self._diff_tags(t)
            self.side.append(t)
        self.vbar = ttk.Scrollbar(self.side_frame, orient="vertical",
                                  command=lambda *a: [t.yview(*a) for t in self.side])
        self.hbar = ttk.Scrollbar(self.side_frame, orient="horizontal",
                                  command=lambda *a: [t.xview(*a) for t in self.side])
        self.vbar.grid(row=0, column=3, sticky="ns")
        self.hbar.grid(row=1, column=0, columnspan=3, sticky="ew")
        self.side_frame.rowconfigure(0, weight=1)
        self.side_frame.columnconfigure(0, weight=1, uniform="side")
        self.side_frame.columnconfigure(2, weight=1, uniform="side")
        self.after_idle(lambda: BoxSizer(app, self.side_frame, self.side, key="CompareTab.side"))

        # unified diff
        self.uni_frame = ttk.Frame(self.views)
        self.uni = scrolled_text(self.uni_frame, app, height=22)
        self.uni.container.pack(fill="both", expand=True)
        self.uni.configure(state="disabled")
        self._diff_tags(self.uni)

        # unique lines (order ignored)
        self.uniq_frame = ttk.Frame(self.views)
        self.uniq_frame.columnconfigure(0, weight=1, uniform="side")
        self.uniq_frame.columnconfigure(1, weight=1, uniform="side")
        self.uniq_frame.rowconfigure(1, weight=1)
        self.uniq, self.uniq_lbls = [], []
        for col in (0, 1):
            h = ttk.Frame(self.uniq_frame)
            h.grid(row=0, column=col, sticky="ew", padx=(0, 6) if col == 0 else (6, 0))
            lbl = ttk.Label(h, style="Field.TLabel")
            lbl.pack(side="left")
            ttk.Button(h, text="Copy", style="Small.TButton",
                       command=lambda c=col: self.app.copy(self.uniq[c].get("1.0", "end-1c"))).pack(side="right")
            t = scrolled_text(self.uniq_frame, app, height=20, width=40)
            t.container.grid(row=1, column=col, sticky="nsew", padx=(0, 6) if col == 0 else (6, 0), pady=(2, 0))
            t.configure(state="disabled")
            t.tag_configure("del", background=DIFF_COLORS["del"], foreground="#000000")
            t.tag_configure("ins", background=DIFF_COLORS["ins"], foreground="#000000")
            self.uniq.append(t)
            self.uniq_lbls.append(lbl)
        self.uniq_hint = ttk.Label(self.uniq_frame, style="Hint.TLabel",
                                   text="Lines that appear on only one side, ignoring order and duplicates "
                                        "(handy for ACLs, prefix lists, VLAN lists, MAC tables).")
        self.uniq_hint.grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        self.debounce = Debouncer(self, 400, self.auto_compare)
        self.show_view()
        self.update_counts()
        self.status_lbl.configure(text="Open or paste text on both sides to compare.")

    # ---- helpers

    def _diff_tags(self, t: tk.Text):
        c = self.app.colors
        for name in ("del", "ins", "chg"):
            t.tag_configure(name, background=DIFF_COLORS[name], foreground="#000000")
        t.tag_configure("delchar", background=DIFF_COLORS["delchar"], foreground="#000000")
        t.tag_configure("inschar", background=DIFF_COLORS["inschar"], foreground="#000000")
        t.tag_configure("filler", background=c["filler"])
        t.tag_configure("gutter", foreground=c["muted"])
        t.tag_configure("fold", foreground=c["muted"], justify="left")
        t.tag_configure("hunk", foreground=c["link"])
        t.tag_configure("head", foreground=c["muted"])
        t.tag_configure("cur", underline=True)
        for tag in ("delchar", "inschar", "cur"):
            t.tag_raise(tag)
        t.tag_lower("gutter")          # on highlighted lines the black text wins
        t.tag_raise("sel")

    def _sync_y(self, src, first, last):
        self.vbar.set(first, last)
        if not self._syncing:
            self._syncing = True
            for t in self.side:
                if t is not src:
                    t.yview_moveto(first)
            self._syncing = False

    def _sync_x(self, src, first, last):
        self.hbar.set(first, last)
        if not self._syncing:
            self._syncing = True
            for t in self.side:
                if t is not src:
                    t.xview_moveto(first)
            self._syncing = False

    def options(self) -> textdiff.Options:
        ws = next((k for lbl, k in WS_MODES if lbl == self.ws_v.get()), "none")
        return textdiff.Options(ignore_case=self.case_v.get(), whitespace=ws, ignore_blank=self.blank_v.get(),
                                ignore_regex=self.ignore_v.get() if self.ignore_on_v.get() else "",
                                sort_lines=self.sort_v.get())

    def text_of(self, side: int) -> str:
        return self.src[side].get("1.0", "end-1c")

    def set_side(self, side: int, text: str, name: str = ""):
        self.src[side].delete("1.0", "end")
        self.src[side].insert("1.0", text)
        self.src[side].edit_reset()
        self.names[side] = name
        self.name_lbls[side].configure(text=f"{Path(name).name}  —  {Path(name).parent}" if name else "")
        self.update_counts()

    def update_counts(self):
        for side in (0, 1):
            text = self.text_of(side)
            n = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
            self.count_lbls[side].configure(text=f"{n:,} line{'s' if n != 1 else ''}")

    def _modified(self, e):
        if e.widget.edit_modified():
            e.widget.edit_modified(False)
            self.update_counts()
            self.debounce()

    def options_changed(self):
        self.debounce()

    def auto_compare(self):
        if len(self.text_of(0)) + len(self.text_of(1)) <= self.AUTO_LIMIT:
            self.compare()
        else:
            self.status_lbl.configure(text="Large input — press Compare (Ctrl/⌘+Return) to run.")

    # ---- actions

    def open_file(self, side: int):
        from tkinter import filedialog
        start = self.app.settings.get("compare_dir", str(Path.home()))
        name = filedialog.askopenfilename(parent=self, title=f"Open {'left' if side == 0 else 'right'} file",
                                          initialdir=start,
                                          filetypes=[("Text / config files", "*.txt *.cfg *.conf *.log *.csv *.json "
                                                      "*.xml *.yaml *.yml *.ini *.md"), ("All files", "*")])
        if name:
            self.load_file(side, name)

    def load_file(self, side: int, path):
        p = Path(path)
        try:
            text = textdiff.read_text_file(p)
        except (OSError, ValueError) as exc:
            self.status_lbl.configure(text=f"Couldn't open {p.name}: {exc}")
            return
        self.app.settings["compare_dir"] = str(p.parent)
        self.set_side(side, text, str(p))
        self.compare()

    def paste(self, side: int):
        try:
            text = self.app.root.clipboard_get()
        except tk.TclError:
            return
        self.set_side(side, text, "")
        self.compare()

    def clear_side(self, side: int):
        self.set_side(side, "", "")
        self.compare()

    def swap(self):
        a, b = self.text_of(0), self.text_of(1)
        na, nb = self.names
        self.set_side(0, b, nb)
        self.set_side(1, a, na)
        self.compare()

    def compare(self):
        left, right = self.text_of(0), self.text_of(1)
        opts = self.options()
        try:
            textdiff.compile_ignore(opts.ignore_regex)
        except ValueError as exc:
            self.status_lbl.configure(text=str(exc))
            self.ignore_entry.state(["invalid"])
            return
        self.ignore_entry.state(["!invalid"])
        if not left and not right:
            self.rows, self.stats, self.unified_text = [], None, ""
            self.status_lbl.configure(text="Open or paste text on both sides to compare.")
            self.render()
            return
        self.status_lbl.configure(text="Comparing…")
        self.update_idletasks()
        self.rows, self.stats = textdiff.compare(left, right, opts)
        self.unified_text = textdiff.unified(left, right, opts, self.context(),
                                             self.names[0] or "left", self.names[1] or "right")
        self.only = textdiff.set_compare(left, right, opts)
        st = self.stats
        if st.identical:
            msg = "No differences" + (" (after ignore rules)" if self.ignored_any(opts) else "")
        else:
            parts = []
            for n, word in ((st.changed, "changed"), (st.added, "added"), (st.removed, "removed")):
                if n:
                    parts.append(f"{n:,} {word}")
            parts.append(f"{st.equal:,} identical")
            sim = int(st.similarity * 10) / 10          # round down so a near-match never shows 100%
            msg = " · ".join(parts) + f" · {sim:.1f}% similar"
        ign = st.ignored_left + st.ignored_right
        if ign:
            msg += f" · {ign:,} line{'s' if ign != 1 else ''} ignored"
        self.status_lbl.configure(text=msg)
        self.render()

    @staticmethod
    def ignored_any(opts) -> bool:
        return (opts.ignore_case or opts.whitespace != "none" or opts.ignore_blank
                or bool(opts.ignore_regex) or opts.sort_lines)

    def context(self) -> int:
        try:
            return max(0, int(self.ctx_v.get()))
        except (tk.TclError, ValueError):
            return 3

    # ---- rendering

    def show_view(self):
        for f in (self.side_frame, self.uni_frame, self.uniq_frame):
            f.pack_forget()
        {"side": self.side_frame, "unified": self.uni_frame,
         "unique": self.uniq_frame}[self.view_v.get()].pack(fill="both", expand=True)
        self.hunk_idx = -1
        self.update_pos()

    def render(self):
        if self.rows or self.stats:
            # context changes alter the unified hunks too
            self.unified_text = textdiff.unified(self.text_of(0), self.text_of(1), self.options(), self.context(),
                                                 self.names[0] or "left", self.names[1] or "right")
        self.render_side()
        self.render_unified()
        self.render_unique()
        self.hunk_idx = -1
        self.update_pos()

    def render_side(self):
        rows = self.rows
        width = len(str(max([r.left.no for r in rows if r.left] + [r.right.no for r in rows if r.right] + [1])))
        blank_gutter = " " * width + "  "
        ctx = self.context()
        hide = self.hide_v.get()
        # which rows to show; long runs of equal rows fold to one line when hiding
        keep = [True] * len(rows)
        if hide:
            changed = [r.tag != "equal" for r in rows]
            near = [False] * len(rows)
            for i, c in enumerate(changed):
                if c:
                    for k in range(max(0, i - ctx), min(len(rows), i + ctx + 1)):
                        near[k] = True
            keep = near
        lines = ([], [])
        tags = ([], [])                # (line_no_in_view, tag, spans)
        self.hunks = []
        prev_tag, folded = "equal", 0
        view_no = 0

        def flush_fold():
            nonlocal folded, view_no
            if folded:
                view_no += 1
                label = f"⋯ {folded:,} identical line{'s' if folded != 1 else ''} hidden ⋯"
                for s_ in (0, 1):
                    lines[s_].append(label)
                    tags[s_].append((view_no, "fold", []))
                folded = 0

        for i, r in enumerate(rows):
            if not keep[i]:
                folded += 1
                prev_tag = "equal"
                continue
            flush_fold()
            view_no += 1
            if r.tag != "equal" and prev_tag == "equal":
                self.hunks.append(view_no)
            prev_tag = r.tag
            for s_, ln, spans in ((0, r.left, r.left_spans), (1, r.right, r.right_spans)):
                if ln is None:
                    lines[s_].append(blank_gutter)
                    tags[s_].append((view_no, "filler", []))
                    continue
                lines[s_].append(f"{ln.no:>{width}}  {ln.text}")
                if r.tag == "equal":
                    continue
                line_tag = {"delete": "del", "insert": "ins", "replace": "chg"}[r.tag]
                tags[s_].append((view_no, line_tag, spans))
        flush_fold()
        off = width + 2
        for s_, t in enumerate(self.side):
            t.configure(state="normal")
            t.delete("1.0", "end")
            t.insert("1.0", "\n".join(lines[s_]))
            for n, tag, spans in tags[s_]:
                t.tag_add(tag, f"{n}.0", f"{n}.0 lineend+1c")
                char_tag = "delchar" if s_ == 0 else "inschar"
                for a, b in spans:
                    t.tag_add(char_tag, f"{n}.{off + a}", f"{n}.{off + b}")
            if view_no <= 20000:
                for n in range(1, view_no + 1):
                    t.tag_add("gutter", f"{n}.0", f"{n}.{off}")
            t.configure(state="disabled")
            t.yview_moveto(0)
            t.xview_moveto(0)

    def render_unified(self):
        t = self.uni
        t.configure(state="normal")
        t.delete("1.0", "end")
        text = self.unified_text
        if not text:
            text = "No differences." if self.stats else ""
        t.insert("1.0", text)
        for n, line in enumerate(text.splitlines(), 1):
            if line.startswith(("--- ", "+++ ")) and n <= 2:
                t.tag_add("head", f"{n}.0", f"{n}.end")
            elif line.startswith("@@"):
                t.tag_add("hunk", f"{n}.0", f"{n}.end")
            elif line.startswith("-"):
                t.tag_add("del", f"{n}.0", f"{n}.0 lineend+1c")
            elif line.startswith("+"):
                t.tag_add("ins", f"{n}.0", f"{n}.0 lineend+1c")
        t.configure(state="disabled")

    def render_unique(self):
        only = getattr(self, "only", ([], [], []))
        if not self.stats:
            only = ([], [], [])
        for s_, (items, tag, word) in enumerate(((only[0], "del", "left"), (only[1], "ins", "right"))):
            t = self.uniq[s_]
            t.configure(state="normal")
            t.delete("1.0", "end")
            t.insert("1.0", "\n".join(items))
            if items:
                t.tag_add(tag, "1.0", "end")
            t.configure(state="disabled")
            self.uniq_lbls[s_].configure(text=f"Only in {word} ({len(items):,})")

    # ---- navigation / export

    def view_hunks(self):
        if self.view_v.get() == "side":
            return self.hunks, self.side
        if self.view_v.get() == "unified":
            lines = self.unified_text.splitlines()
            return [n for n, l in enumerate(lines, 1) if l.startswith("@@")], [self.uni]
        return [], []

    def goto_hunk(self, step: int):
        hunks, texts = self.view_hunks()
        if not hunks:
            self.update_pos()
            return
        self.hunk_idx = (self.hunk_idx + step) % len(hunks) if self.hunk_idx >= 0 else (0 if step > 0 else len(hunks) - 1)
        line = hunks[self.hunk_idx]
        for t in texts:
            t.tag_remove("cur", "1.0", "end")
            total = int(t.index("end-1c").split(".")[0])
            t.yview_moveto(max(0, (line - 4)) / max(1, total))
            t.tag_add("cur", f"{line}.0", f"{line}.end")
        self.update_pos()

    def update_pos(self):
        hunks, _ = self.view_hunks()
        if not hunks:
            self.pos_lbl.configure(text="")
        elif self.hunk_idx < 0:
            self.pos_lbl.configure(text=f"{len(hunks):,} difference{'s' if len(hunks) != 1 else ''}")
        else:
            self.pos_lbl.configure(text=f"Difference {self.hunk_idx + 1:,} of {len(hunks):,}")

    def diff_for_export(self) -> str:
        if self.view_v.get() == "unique" and self.stats:
            a, b = self.only[0], self.only[1]
            return ("# Only in " + (self.names[0] or "left") + "\n" + "\n".join(a) +
                    "\n\n# Only in " + (self.names[1] or "right") + "\n" + "\n".join(b) + "\n")
        return self.unified_text + ("\n" if self.unified_text else "")

    def copy_diff(self):
        text = self.diff_for_export()
        if text.strip():
            self.app.copy(text)
        else:
            self.app.flash("No differences to copy.")

    def save_diff(self):
        text = self.diff_for_export()
        if not text.strip():
            self.app.flash("No differences to save.")
            return
        from tkinter import filedialog
        unique = self.view_v.get() == "unique"
        name = filedialog.asksaveasfilename(parent=self, title="Save differences",
                                            initialdir=self.app.settings.get("compare_dir", str(Path.home())),
                                            initialfile="unique-lines.txt" if unique else "compare.diff",
                                            defaultextension=".txt" if unique else ".diff",
                                            filetypes=[("Diff", "*.diff *.patch"), ("Text", "*.txt"), ("All files", "*")])
        if name:
            try:
                Path(name).write_text(text, encoding="utf-8")
                self.app.flash(f"Saved {name}")
            except OSError as exc:
                self.app.flash(f"Couldn't save: {exc}")

    def settings_dict(self) -> dict:
        return dict(compare_case=self.case_v.get(), compare_blank=self.blank_v.get(), compare_sort=self.sort_v.get(),
                    compare_ws=self.options().whitespace, compare_ignore_on=self.ignore_on_v.get(),
                    compare_regex=self.ignore_v.get(), compare_view=self.view_v.get(),
                    compare_hide_equal=self.hide_v.get(), compare_context=self.context())


# --------------------------------------------------------------------------- log times tab

HIGHLIGHT_ZONED = {"background": "#cfe3ff", "foreground": "#000000"}   # stamp carried its own zone
LOG_OUTPUTS = [
    ("Keep each timestamp's format", "keep"),
    ("2026-10-10 07:02:03 EDT", "readable"),
    ("ISO 8601  2026-10-10T07:02:03-04:00", "iso"),
    ("Custom (strftime)", "custom"),
]


def zone_combo(parent, var: tk.StringVar, zones, width=26) -> ttk.Combobox:
    """Editable zone picker; typing filters the dropdown (e.g. 'chicago', 'europe')."""
    box = ttk.Combobox(parent, textvariable=var, values=zones, width=width)

    def filt(event):
        if event.keysym in ("Return", "Up", "Down", "Escape", "Tab"):
            return
        text = var.get().lower().replace("_", " ")
        matches = [z for z in zones if text in z.lower().replace("_", " ")] if text else zones
        box.configure(values=matches or zones)

    box.bind("<KeyRelease>", filt)
    return box


class LogTimeTab(ttk.Frame):
    """Find every date/time in a log and rewrite it in another time zone, in place."""

    AUTO_LIMIT = 1_000_000          # characters; bigger logs convert when the button is pressed
    MAX_ROWS = 5000

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        problem = core.timezone_support()
        self.available = not problem
        if problem:
            ttk.Label(self, text=problem, style="Error.TLabel").pack(anchor="w")
            return
        s = app.settings
        self.zones = core.all_timezones()
        self.zone_set = set(self.zones) | {"UTC"}
        self.file_path = ""
        self.result = None
        self.job = 0                # generation counter so stale background results are dropped
        self.busy = False

        head = ttk.Frame(self)
        head.pack(fill="x")
        ttk.Label(head, text="Log times", style="Title.TLabel").pack(side="left")
        ttk.Label(head, text="  open a log or paste text; every date/time found is converted in place",
                  style="Hint.TLabel").pack(side="left")
        ttk.Button(head, text="Clear", style="Small.TButton", command=self.clear).pack(side="right")
        ttk.Button(head, text="Paste", style="Small.TButton", command=self.paste).pack(side="right", padx=4)
        ttk.Button(head, text="Open file…", style="Small.TButton", command=self.open_file).pack(side="right")
        info = ttk.Frame(self)
        info.pack(fill="x")
        self.file_lbl = ttk.Label(info, style="Hint.TLabel")
        self.file_lbl.pack(side="left")
        self.count_lbl = ttk.Label(info, style="Hint.TLabel")
        self.count_lbl.pack(side="right")
        self.src = scrolled_text(self, app, height=10)
        self.src.container.pack(fill="both", expand=True, pady=(2, 0))
        self.src.tag_configure("stamp", **HIGHLIGHT_MAC)
        self.src.tag_configure("zoned", **HIGHLIGHT_ZONED)
        self.src.tag_configure("cur", underline=True)
        self.src.tag_raise("sel")
        self.src.insert("1.0", SAMPLE_LOG)
        self.src.edit_reset()
        self.src.edit_modified(False)

        # ---- options
        opt = ttk.Frame(self)
        opt.pack(fill="x", pady=(8, 0))
        opt.columnconfigure(3, weight=1)
        local = core.local_timezone_name()
        src_zone = s.get("logtime_source", "UTC")
        dst_zone = s.get("logtime_target", local)
        self.src_zone_v = tk.StringVar(value=src_zone if src_zone in self.zone_set else "UTC")
        self.dst_zone_v = tk.StringVar(value=dst_zone if dst_zone in self.zone_set else local)
        ttk.Label(opt, text="Times in the log are in:").grid(row=0, column=0, sticky="w")
        zone_combo(opt, self.src_zone_v, self.zones).grid(row=0, column=1, sticky="w", padx=(4, 6))
        quick = ttk.Frame(opt)
        quick.grid(row=0, column=2, sticky="w")
        ttk.Button(quick, text="UTC", style="Small.TButton",
                   command=lambda: self.src_zone_v.set("UTC")).pack(side="left")
        ttk.Button(quick, text="Local", style="Small.TButton",
                   command=lambda: self.src_zone_v.set(local)).pack(side="left", padx=4)
        self.trust_v = tk.BooleanVar(value=s.get("logtime_trust", True))
        ttk.Checkbutton(opt, text="…unless the timestamp says its own zone (UTC, EDT, -0400, Z)",
                        variable=self.trust_v, command=self.changed).grid(row=0, column=3, sticky="w", padx=(10, 0))

        ttk.Label(opt, text="Convert to:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        zone_combo(opt, self.dst_zone_v, self.zones).grid(row=1, column=1, sticky="w", padx=(4, 6), pady=(6, 0))
        quick2 = ttk.Frame(opt)
        quick2.grid(row=1, column=2, sticky="w", pady=(6, 0))
        ttk.Button(quick2, text="UTC", style="Small.TButton",
                   command=lambda: self.dst_zone_v.set("UTC")).pack(side="left")
        ttk.Button(quick2, text="Local", style="Small.TButton",
                   command=lambda: self.dst_zone_v.set(local)).pack(side="left", padx=4)
        ttk.Button(opt, text="⇄ Swap zones", style="Small.TButton",
                   command=self.swap_zones).grid(row=1, column=3, sticky="w", padx=(10, 0), pady=(6, 0))

        row3 = ttk.Frame(self)
        row3.pack(fill="x", pady=(8, 0))
        ttk.Label(row3, text="Clock correction:").pack(side="left")
        self.shift_v = tk.StringVar(value=s.get("logtime_shift", ""))
        self.shift_entry = ttk.Entry(row3, textvariable=self.shift_v, width=10, font=app.mono)
        self.shift_entry.pack(side="left", padx=(4, 4))
        ttk.Label(row3, text="e.g. -2m 13s for a clock running fast", style="Hint.TLabel").pack(side="left")
        ttk.Label(row3, text="Year when missing:").pack(side="left", padx=(16, 4))
        this_year = datetime.now().year
        self.year_v = tk.StringVar(value=str(s.get("logtime_year", "Auto")))
        ttk.Combobox(row3, textvariable=self.year_v, width=6,
                     values=["Auto"] + [str(this_year - i) for i in range(6)]).pack(side="left")
        ttk.Label(row3, text="Numeric dates:").pack(side="left", padx=(16, 4))
        self.order_v = tk.StringVar(value=s.get("logtime_order", "Month first (10/31)"))
        order = ttk.Combobox(row3, textvariable=self.order_v, state="readonly", width=18,
                             values=["Month first (10/31)", "Day first (31/10)"])
        order.pack(side="left")
        order.bind("<<ComboboxSelected>>", lambda e: self.changed())

        row4 = ttk.Frame(self)
        row4.pack(fill="x", pady=(8, 0))
        ttk.Label(row4, text="Output:").pack(side="left")
        out_key = s.get("logtime_output", "keep")
        self.output_v = tk.StringVar(value=next((l for l, k in LOG_OUTPUTS if k == out_key), LOG_OUTPUTS[0][0]))
        out = ttk.Combobox(row4, textvariable=self.output_v, state="readonly", width=34,
                           values=[l for l, _ in LOG_OUTPUTS])
        out.pack(side="left", padx=(4, 6))
        out.bind("<<ComboboxSelected>>", lambda e: (self.update_custom(), self.changed()))
        self.custom_v = tk.StringVar(value=s.get("logtime_custom", "%Y-%m-%d %H:%M:%S %Z"))
        self.custom_entry = ttk.Entry(row4, textvariable=self.custom_v, width=24, font=app.mono)
        self.custom_entry.pack(side="left")
        self.go_btn = ttk.Button(row4, text="Convert", style="Accent.TButton", command=self.convert)
        self.go_btn.pack(side="right")

        row5 = ttk.Frame(self)
        row5.pack(fill="x", pady=(6, 0))
        self.append_v = tk.BooleanVar(value=s.get("logtime_append", False))
        self.addzone_v = tk.BooleanVar(value=s.get("logtime_add_zone", False))
        self.epoch_v = tk.BooleanVar(value=s.get("logtime_epoch", False))
        for text_, var in (("Keep the original and add the converted time in [brackets]", self.append_v),
                           ("Add the zone name to times that had none", self.addzone_v),
                           ("Also convert Unix epoch numbers", self.epoch_v)):
            ttk.Checkbutton(row5, text=text_, variable=var, command=self.changed).pack(side="left", padx=(0, 14))

        ttk.Separator(self).pack(fill="x", pady=10)

        top = ttk.Frame(self)
        top.pack(fill="x")
        self.status_lbl = ttk.Label(top, style="Title.TLabel")
        self.status_lbl.pack(side="left")
        ttk.Button(top, text="Save as…", style="Small.TButton", command=self.save).pack(side="right")
        ttk.Button(top, text="Copy output", style="Small.TButton", command=self.copy_output).pack(side="right", padx=4)
        self.note_lbl = ttk.Label(self, style="Warn.TLabel", wraplength=900)
        self.note_lbl.pack(anchor="w")
        self.out = scrolled_text(self, app, height=14)
        self.out.container.pack(fill="both", expand=True, pady=(4, 0))
        self.out.configure(state="disabled")
        self.out.tag_configure("stamp", **HIGHLIGHT_MAC)
        self.out.tag_configure("zoned", **HIGHLIGHT_ZONED)
        self.out.tag_configure("cur", underline=True)
        self.out.tag_raise("sel")
        ttk.Label(self, text="Green: zone assumed from the setting above.  Blue: zone written in the timestamp.  "
                  "Click a row below to find it in the text.", style="Hint.TLabel").pack(anchor="w", pady=(4, 0))

        self.tree = make_tree(self, ("Line", "Original", "Converted", "Format", "Zone used", "Note"),
                              (50, 250, 270, 105, 240, 160))
        self.tree.configure(height=8, selectmode="browse")
        self.tree.column("Line", stretch=False, anchor="e")
        self.tree.container.pack(fill="both", expand=True, pady=(8, 0))
        self.tree.tag_configure("note", foreground=app.colors["warn"])
        make_sortable(self.tree, numeric=("Line",))
        self.tree.bind("<<TreeviewSelect>>", self.show_row)

        self.debounce = Debouncer(self, 400, self.auto_convert)
        self.src.bind("<<Modified>>", self._modified)
        self.src.bind("<Control-Return>", lambda e: self.convert())
        self.src.bind("<Command-Return>", lambda e: self.convert())
        for var in (self.src_zone_v, self.dst_zone_v, self.shift_v, self.year_v, self.custom_v):
            var.trace_add("write", lambda *a: self.changed())
        self.update_custom()
        self.update_count()
        self.convert()

    # ---- input

    def text(self) -> str:
        return self.src.get("1.0", "end-1c")

    def set_text(self, text: str, path: str = ""):
        self.src.delete("1.0", "end")
        self.src.insert("1.0", text)
        self.src.edit_reset()
        self.src.edit_modified(False)       # converted below; don't queue a second run
        self.file_path = path
        self.file_lbl.configure(text=f"{Path(path).name}  —  {Path(path).parent}" if path else "")
        self.update_count()
        self.convert()

    def update_count(self):
        t = self.text()
        n = t.count("\n") + (1 if t and not t.endswith("\n") else 0)
        self.count_lbl.configure(text=f"{n:,} line{'s' if n != 1 else ''}")

    def _modified(self, _):
        if self.src.edit_modified():
            self.src.edit_modified(False)
            self.update_count()
            self.debounce()

    def open_file(self):
        from tkinter import filedialog
        name = filedialog.askopenfilename(parent=self, title="Open log file",
                                          initialdir=self.app.settings.get("logtime_dir", str(Path.home())),
                                          filetypes=[("Logs and text", "*.log *.txt *.out *.csv *.json *.cfg"),
                                                     ("All files", "*")])
        if name:
            self.load_file(name)

    def load_file(self, path):
        p = Path(path)
        try:
            text = textdiff.read_text_file(p)
        except (OSError, ValueError) as exc:
            self.status_lbl.configure(text=f"Couldn't open {p.name}: {exc}")
            return
        self.app.settings["logtime_dir"] = str(p.parent)
        self.set_text(text, str(p))

    def paste(self):
        try:
            text = self.app.root.clipboard_get()
        except tk.TclError:
            return
        self.set_text(text)

    def clear(self):
        self.set_text("")

    def swap_zones(self):
        a, b = self.src_zone_v.get(), self.dst_zone_v.get()
        self.src_zone_v.set(b)
        self.dst_zone_v.set(a)

    def update_custom(self):
        self.custom_entry.state(["!disabled"] if self.output_key() == "custom" else ["disabled"])

    def output_key(self) -> str:
        return next((k for l, k in LOG_OUTPUTS if l == self.output_v.get()), "keep")

    # ---- conversion

    def options(self) -> logtime.Options:
        """Current settings, or raise ValueError with a message for the status line."""
        for label, var in (("Time zone", self.src_zone_v), ("Convert-to zone", self.dst_zone_v)):
            if var.get() not in self.zone_set:
                raise ValueError(f"{label} '{var.get()}' isn't a known zone. Pick one from the list.")
        year_text = self.year_v.get().strip()
        if year_text.lower() in ("", "auto"):
            year = None
        elif year_text.isdigit() and 1970 <= int(year_text) <= 2100:
            year = int(year_text)
        else:
            raise ValueError("Year when missing should be Auto or a year like 2026.")
        try:
            shift = logtime.parse_shift(self.shift_v.get())
            self.shift_entry.state(["!invalid"])
        except ValueError:
            self.shift_entry.state(["invalid"])
            raise
        return logtime.Options(
            source_zone=self.src_zone_v.get(), target_zone=self.dst_zone_v.get(),
            trust_stamp_zone=self.trust_v.get(), shift_seconds=shift, year=year,
            day_first=self.order_v.get().startswith("Day"), output=self.output_key(),
            custom_format=self.custom_v.get(), append=self.append_v.get(),
            add_zone=self.addzone_v.get(), epoch=self.epoch_v.get())

    def changed(self):
        self.debounce()

    def auto_convert(self):
        if len(self.text()) <= self.AUTO_LIMIT:
            self.convert()
        else:
            self.status_lbl.configure(text="Large log — press Convert (Ctrl/⌘+Return) to run.")

    def convert(self):
        try:
            opts = self.options()
        except ValueError as exc:
            self.status_lbl.configure(text=str(exc))
            return
        text = self.text()
        self.job += 1
        job = self.job
        if len(text) < 200_000:            # small: do it right away
            self.go_btn.state(["!disabled"])
            self.show(job, text, self._run(text, opts))
            return
        self.status_lbl.configure(text="Converting…")
        self.go_btn.state(["disabled"])
        box = {}

        def work():
            box["r"] = self._run(text, opts)

        t = threading.Thread(target=work, daemon=True)
        t.start()

        def poll():
            if t.is_alive():
                self.after(100, poll)
            elif job == self.job:               # a newer run owns the button and status otherwise
                self.go_btn.state(["!disabled"])
                self.show(job, text, box.get("r"))

        self.after(100, poll)

    @staticmethod
    def _run(text, opts):
        try:
            return logtime.convert_text(text, opts)
        except Exception as exc:          # bad strftime pattern and similar
            return exc

    def show(self, job, text, result):
        if job != self.job:
            return
        if isinstance(result, Exception):
            self.status_lbl.configure(text=f"Couldn't convert: {result}")
            return
        self.result = result
        st = result.stamps
        for t in (self.src, self.out):
            for tag in ("stamp", "zoned", "cur"):
                t.tag_remove(tag, "1.0", "end")
        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        self.out.insert("1.0", result.text)
        for s_ in st:
            tag = "zoned" if s_.zone_note.endswith("in stamp") or "in stamp," in s_.zone_note \
                or s_.kind == "Unix epoch" else "stamp"
            self.src.tag_add(tag, f"{s_.line}.{s_.col}", f"{s_.line}.{s_.end_col}")
            self.out.tag_add(tag, f"{s_.line}.{s_.out_col}", f"{s_.line}.{s_.out_end_col}")
        self.out.configure(state="disabled")

        self.tree.delete(*self.tree.get_children())
        for i, s_ in enumerate(st[:self.MAX_ROWS]):
            self.tree.insert("", "end", iid=str(i), tags=("note",) if s_.note else (),
                             values=(s_.line, s_.original, s_.converted, s_.kind, s_.zone_note, s_.note))
        if not text.strip():
            msg = "Open or paste a log to convert its timestamps."
        elif not st:
            msg = "No dates/times found."
        else:
            kinds = ", ".join(f"{k} {n:,}" for k, n in sorted(result.kinds.items(), key=lambda x: -x[1]))
            lines = len({s_.line for s_ in st})
            msg = f"{len(st):,} timestamp{'s' if len(st) != 1 else ''} on {lines:,} line{'s' if lines != 1 else ''}" \
                  f"  ·  {kinds}"
            if len(st) > self.MAX_ROWS:
                msg += f"  ·  table shows the first {self.MAX_ROWS:,}"
        self.status_lbl.configure(text=msg)
        notes = [s_ for s_ in st if s_.note]
        guessed = sum(1 for s_ in st if "guessed" in s_.zone_note)
        warn = []
        if notes:
            warn.append(f"{len(notes):,} time{'s' if len(notes) != 1 else ''} fall in a DST change "
                        f"(see the Note column), e.g. line {notes[0].line}: {notes[0].note}")
        if guessed and self.year_v.get().strip().lower() in ("", "auto"):
            warn.append(f"{guessed:,} timestamp{'s' if guessed != 1 else ''} have no year; the most recent "
                        "past date was assumed (set Year when missing to override).")
        self.note_lbl.configure(text="\n".join(warn))

    # ---- table / export

    def show_row(self, _=None):
        sel = self.tree.selection()
        if not sel or not self.result:
            return
        s_ = self.result.stamps[int(sel[0])]
        for t, a, b in ((self.src, s_.col, s_.end_col), (self.out, s_.out_col, s_.out_end_col)):
            t.tag_remove("cur", "1.0", "end")
            t.tag_add("cur", f"{s_.line}.{a}", f"{s_.line}.{b}")
            t.see(f"{s_.line}.{a}")

    def output_text(self) -> str:
        return self.result.text if self.result else ""

    def copy_output(self):
        if self.output_text():
            self.app.copy(self.output_text())

    def save(self):
        text = self.output_text()
        if not text:
            self.app.flash("Nothing to save.")
            return
        from tkinter import filedialog
        zone = self.dst_zone_v.get().split("/")[-1]
        if self.file_path:
            p = Path(self.file_path)
            initial, folder = f"{p.stem}-{zone}{p.suffix or '.log'}", str(p.parent)
        else:
            initial, folder = f"converted-{zone}.log", self.app.settings.get("logtime_dir", str(Path.home()))
        name = filedialog.asksaveasfilename(parent=self, title="Save converted log", initialdir=folder,
                                            initialfile=initial, defaultextension=".log",
                                            filetypes=[("Log / text", "*.log *.txt"), ("All files", "*")])
        if name:
            try:
                Path(name).write_text(text, encoding="utf-8")
                self.app.flash(f"Saved {name}")
            except OSError as exc:
                self.app.flash(f"Couldn't save: {exc}")

    def settings_dict(self) -> dict:
        if not self.available:
            return {}
        return dict(logtime_source=self.src_zone_v.get(), logtime_target=self.dst_zone_v.get(),
                    logtime_trust=self.trust_v.get(), logtime_shift=self.shift_v.get(),
                    logtime_year=self.year_v.get(), logtime_order=self.order_v.get(),
                    logtime_output=self.output_key(), logtime_custom=self.custom_v.get(),
                    logtime_append=self.append_v.get(), logtime_add_zone=self.addzone_v.get(),
                    logtime_epoch=self.epoch_v.get())


SAMPLE_LOG = """\
*Oct 10 2026 15:02:03.123 UTC: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
RP/0/RP0/CPU0:Oct 10 15:02:04.877 UTC: bgp[1052]: %ROUTING-BGP-5-ADJCHANGE : neighbor 192.0.2.2 Down
Oct 10 15:02:05 edge-r1 sshd[2210]: Accepted publickey for admin from 10.0.0.5
2026-10-10T15:02:06.250Z grafana alert: BGP session down on edge-r1
10.0.0.5 - - [10/Oct/2026:15:03:00 +0000] "GET /api/health HTTP/1.1" 200 17
"""


# --------------------------------------------------------------------------- ping sweep tab

SWEEP_COLORS = {   # light backgrounds in both modes, so the text on them is black
    "alive": {"background": "#cdeed5", "foreground": "#000000"},
    "partial": {"background": "#ffe2a8", "foreground": "#000000"},
    "dead": {"background": "#ffd7d5", "foreground": "#000000"},
}


class SweepTab(ttk.Frame):
    """Ping every address in a list / subnet / range a couple of times and show which answer."""

    COLUMNS = ("Action", "IP address", "Status", "Replies", "Best (ms)", "Avg (ms)", "TTL", "Name", "Details")
    PING_LABEL = "▶ Ping"

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        s = app.settings
        self.results = {}          # host -> HostResult
        self.order = []            # hosts in sweep order
        self.worker = None
        self.stop_event = None
        self.queue = None
        self.runner = None
        self.started = None

        head = ttk.Frame(self)
        head.pack(fill="x")
        ttk.Label(head, text="Ping sweep", style="Title.TLabel").pack(side="left")
        ttk.Label(head, text="  IPs, subnets (10.0.0.0/24, 10.0.0.0 255.255.255.0), ranges (10.0.0.1-50), "
                  "host names, or any pasted text", style="Hint.TLabel").pack(side="left")
        ttk.Button(head, text="Clear", style="Small.TButton", command=self.clear_input).pack(side="right")
        ttk.Button(head, text="Paste", style="Small.TButton", command=self.paste).pack(side="right", padx=4)
        self.src = scrolled_text(self, app, height=5)
        self.src.container.pack(fill="x", pady=(4, 0))
        self.src.tag_configure("hit", **HIGHLIGHT_MAC)
        self.src.tag_raise("sel")
        self.src.insert("1.0", s.get("sweep_input", "192.168.1.0/24"))
        self.count_lbl = ttk.Label(self, style="Hint.TLabel")
        self.count_lbl.pack(anchor="w", pady=(2, 0))

        opt = ttk.Frame(self)
        opt.pack(fill="x", pady=(8, 0))
        self.count_v = tk.StringVar(value=str(s.get("sweep_count", 2)))
        self.timeout_v = tk.StringVar(value=str(s.get("sweep_timeout", 1)))
        self.workers_v = tk.StringVar(value=str(s.get("sweep_workers", 64)))
        for label, var, lo, hi in (("Pings per address:", self.count_v, 1, 10),
                                   ("Timeout (s):", self.timeout_v, 1, 10),
                                   ("At once:", self.workers_v, 1, 256)):
            ttk.Label(opt, text=label).pack(side="left", padx=(0 if label.startswith("Pings") else 12, 4))
            ttk.Spinbox(opt, from_=lo, to=hi, width=4, textvariable=var).pack(side="left")
        self.names_v = tk.BooleanVar(value=s.get("sweep_names", False))
        ttk.Checkbutton(opt, text="Look up names (reverse DNS)", variable=self.names_v).pack(side="left", padx=(14, 0))
        self.stop_btn = ttk.Button(opt, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="right")
        self.go_btn = ttk.Button(opt, text="Sweep", style="Accent.TButton", command=self.start)
        self.go_btn.pack(side="right", padx=6)

        ttk.Separator(self).pack(fill="x", pady=10)

        top = ttk.Frame(self)
        top.pack(fill="x")
        self.status_lbl = ttk.Label(top, style="Title.TLabel")
        self.status_lbl.pack(side="left")
        self.progress = ttk.Progressbar(top, length=200, mode="determinate")
        self.progress.pack(side="right")
        self.warn_lbl = ttk.Label(self, style="Warn.TLabel", wraplength=900)

        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(6, 0))
        self.bar = bar
        self.show_v = tk.StringVar(value=s.get("sweep_show", "all"))
        ttk.Label(bar, text="Show:").pack(side="left")
        for text_, val in (("All", "all"), ("Alive", "alive"), ("Not alive", "dead")):
            ttk.Radiobutton(bar, text=text_, value=val, variable=self.show_v,
                            command=self.apply_filter).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="Copy table", style="Small.TButton", command=self.copy_table).pack(side="right")
        ttk.Button(bar, text="Copy not alive", style="Small.TButton",
                   command=lambda: self.copy_list(False)).pack(side="right", padx=4)
        ttk.Button(bar, text="Copy alive", style="Small.TButton",
                   command=lambda: self.copy_list(True)).pack(side="right")
        ttk.Button(bar, text="▶ Ping all alive", style="Small.TButton",
                   command=self.ping_alive).pack(side="right", padx=(0, 10))
        ttk.Button(bar, text="▶ Ping selected", style="Small.TButton",
                   command=self.ping_selected).pack(side="right", padx=(0, 4))

        self.tree = make_tree(self, self.COLUMNS, (78, 130, 130, 65, 75, 75, 45, 190, 200))
        self.tree.configure(height=16, selectmode="extended")
        self.tree.column("Action", stretch=False, anchor="center")
        for c in ("Replies", "Best (ms)", "Avg (ms)", "TTL"):
            self.tree.column(c, stretch=False, anchor="e")
        self.tree.container.pack(fill="both", expand=True, pady=(6, 0))
        for tag, colors in SWEEP_COLORS.items():
            self.tree.tag_configure(tag, **colors)
        self.tree.tag_configure("pending", foreground=app.colors["muted"])
        self.tree.tag_configure("stopped", foreground=app.colors["muted"])
        self._sortable()
        self.tree.bind("<ButtonRelease-1>", self.on_click)
        self.tree.bind("<Motion>", self.on_motion)
        self.tree.bind("<Double-1>", lambda e: self.ping_selected())
        self.tree.bind("<Return>", lambda e: self.ping_selected())
        self.tree.bind(app.right_click, self.tree_menu)
        ttk.Label(self, text="Green = every ping answered · orange = some answered · red = no answer.  "
                  "Click ▶ Ping (or double-click a row) to add that address to the Ping tool and start it.",
                  style="Hint.TLabel").pack(anchor="w", pady=(4, 0))

        self.debounce = Debouncer(self, 300, self.highlight)
        self.src.bind("<<Modified>>", self._modified)
        self.src.bind("<Control-Return>", lambda e: self.start())
        self.src.bind("<Command-Return>", lambda e: self.start())
        self.status_lbl.configure(text="Enter addresses and press Sweep (Ctrl/⌘+Return).")
        self.highlight()

    # ---- input

    def get_text(self) -> str:
        return self.src.get("1.0", "end-1c")

    def _modified(self, _):
        if self.src.edit_modified():
            self.src.edit_modified(False)
            self.debounce()

    def highlight(self):
        t = sweep.expand_targets(self.get_text())
        self.src.tag_remove("hit", "1.0", "end")
        for a, b in t.spans:
            self.src.tag_add("hit", f"1.0+{a}c", f"1.0+{b}c")
        n = len(t.hosts)
        msg = f"{n:,} address{'es' if n != 1 else ''} to sweep"
        if t.warnings:
            msg += "  ·  " + " ".join(t.warnings)
        self.count_lbl.configure(text=msg)
        return t

    def paste(self):
        try:
            text = self.app.root.clipboard_get()
        except tk.TclError:
            return
        self.src.delete("1.0", "end")
        self.src.insert("1.0", text)
        self.highlight()

    def clear_input(self):
        self.src.delete("1.0", "end")
        self.highlight()

    def load(self, text: str, start: bool = True):
        """Used by other tabs, e.g. IP Calc → Ping sweep this subnet."""
        self.src.delete("1.0", "end")
        self.src.insert("1.0", text)
        self.highlight()
        if start:
            self.start()

    # ---- sweep

    def read_options(self):
        try:
            count = int(self.count_v.get())
            timeout = float(self.timeout_v.get())
            workers = int(self.workers_v.get())
        except ValueError:
            raise ValueError("Pings, timeout and 'at once' must be numbers.") from None
        if not (1 <= count <= 10 and 0.2 <= timeout <= 10 and 1 <= workers <= 256):
            raise ValueError("Pings 1–10, timeout 0.2–10 s, at once 1–256.")
        return count, timeout, workers

    def start(self):
        if self.worker:
            return "break"
        targets = self.highlight()
        if not targets.hosts:
            self.status_lbl.configure(text="Nothing to sweep: enter IPs, a subnet, or a range.")
            return "break"
        try:
            count, timeout, workers = self.read_options()
        except ValueError as exc:
            self.status_lbl.configure(text=str(exc))
            return "break"
        if not pinger.find_tool(False):
            self.status_lbl.configure(text="ping isn't installed (Linux: sudo apt install iputils-ping).")
            return "break"
        if targets.warnings:
            self.warn_lbl.configure(text=" ".join(targets.warnings))
            self.warn_lbl.pack(anchor="w", before=self.bar)
        else:
            self.warn_lbl.pack_forget()

        import queue
        self.queue = queue.Queue()
        self.stop_event = threading.Event()
        self.results = {h: sweep.HostResult(h) for h in targets.hosts}
        self.order = list(targets.hosts)
        self.tree.delete(*self.tree.get_children())
        for h in self.order:
            self.tree.insert("", "end", iid=h, values=self.row_values(self.results[h]), tags=("pending",))
        self.progress.configure(maximum=len(self.order), value=0)
        self.started = time.monotonic()
        self.runner = sweep.KillableRunner()
        q, stop, hosts, names, runner = self.queue, self.stop_event, list(self.order), self.names_v.get(), self.runner

        def work():
            sweep.sweep(hosts, q.put, count, timeout, workers, names, stop, runner)
            q.put(None)

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()
        self.go_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.update_status(running=True)
        self.after(100, self.poll)
        return "break"

    def stop(self):
        """Stop at once: cancel queued hosts, kill pings in flight, and free the buttons right away."""
        if not self.worker or not self.stop_event:
            return
        self.stop_event.set()
        self.runner.kill_all()
        self.drain()                              # keep results that already came back
        self.worker = None                        # late stragglers go to the old queue and are ignored
        self.queue = None
        for h, r in self.results.items():
            if r.status == "Pending":
                r.status = "Stopped"
                if self.tree.exists(h):
                    self.tree.item(h, values=self.row_values(r), tags=("stopped",))
        self.go_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.update_status(running=False)

    def drain(self, limit=None) -> bool:
        """Apply queued results to the table. True when the sweep thread has finished."""
        import queue as _q
        n = 0
        while self.queue is not None and (limit is None or n < limit):
            try:
                r = self.queue.get_nowait()
            except _q.Empty:
                break
            if r is None:
                return True
            self.results[r.host] = r
            if self.tree.exists(r.host):
                self.tree.item(r.host, values=self.row_values(r), tags=(self.tag_for(r),))
            n += 1
        return False

    def poll(self):
        if self.worker is None or self.queue is None:      # stopped: stop() already tidied up
            return
        before = sum(1 for r in self.results.values() if r.status != "Pending")
        finished = self.drain(limit=500)
        done = sum(1 for r in self.results.values() if r.status != "Pending")
        self.progress.configure(value=done)
        if done != before and self.show_v.get() != "all":
            self.apply_filter()
        if finished:
            self.worker = None
            self.go_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self.update_status(running=False)
        else:
            self.update_status(running=True)
            self.after(100, self.poll)

    # ---- table

    @staticmethod
    def tag_for(r) -> str:
        if r.status == "Pending":
            return "pending"
        if r.status == "Stopped":
            return "stopped"
        if r.received and r.received == r.sent:
            return "alive"
        return "partial" if r.received else "dead"

    def row_values(self, r):
        fmt = lambda v: f"{v:.1f}" if v is not None else ""
        replies = f"{r.received}/{r.sent}" if r.sent else ""
        status = {"Partial": "Alive (some lost)", "Stopped": "Not tested"}.get(r.status, r.status)
        host = r.host if not r.ip or r.ip == r.host else f"{r.ip}"
        name = r.name or ("" if r.host == host else r.host)
        return (self.PING_LABEL, host, status, replies, fmt(r.best), fmt(r.average),
                r.ttl if r.ttl is not None else "", name, r.detail)

    def _sortable(self):
        """Sort by heading; IP addresses sort numerically, the Action column doesn't sort."""
        state = {"col": None, "rev": False}

        def key(col, iid):
            v = self.tree.set(iid, col)
            if col == "IP address":
                return sweep.ip_sort_key(v)
            if col in ("Best (ms)", "Avg (ms)", "TTL"):
                try:
                    return (0, float(v))
                except ValueError:
                    return (1, 0.0)
            if col == "Replies":
                r = self.results.get(iid)
                return (-(r.received / r.sent) if r and r.sent else 1, )
            return (str(v).lower(),)

        def sort(col):
            rev = state["rev"] = (not state["rev"]) if state["col"] == col else False
            state["col"] = col
            items = sorted(self.tree.get_children(""), key=lambda i: key(col, i), reverse=rev)
            for idx, iid in enumerate(items):
                self.tree.move(iid, "", idx)
            self.order = items + [h for h in self.order if h not in set(items)]
            for c in self.COLUMNS:
                self.tree.heading(c, text=c + ((" ▼" if rev else " ▲") if c == col else ""))

        for c in self.COLUMNS:
            if c != "Action":
                self.tree.heading(c, command=lambda c=c: sort(c))

    def apply_filter(self):
        mode = self.show_v.get()
        for idx, h in enumerate(self.order):
            r = self.results.get(h)
            if r is None:
                continue
            show = mode == "all" or (r.status not in ("Pending", "Stopped")
                                     and (r.alive if mode == "alive" else not r.alive))
            if show:
                self.tree.move(h, "", idx)       # re-attaches a detached row in its place
            else:
                self.tree.detach(h)

    def on_motion(self, event):
        col = self.tree.identify_column(event.x)
        over = col == "#1" and self.tree.identify_region(event.x, event.y) == "cell"
        self.tree.configure(cursor="hand2" if over else "")

    def on_click(self, event):
        if self.tree.identify_region(event.x, event.y) != "cell" or self.tree.identify_column(event.x) != "#1":
            return
        row = self.tree.identify_row(event.y)
        if row:
            self.ping(row)

    def target_of(self, iid) -> str:
        r = self.results.get(iid)
        return (r.ip or r.host) if r else iid

    def ping_lines(self, iids) -> str:
        """'ip name' per line, so a reverse-DNS name becomes the Ping note."""
        lines = []
        for i in iids:
            r = self.results.get(i)
            note = (r.name if r and r.name and r.name != self.target_of(i) else "")
            lines.append(f"{self.target_of(i)} {note}".strip())
        return "\n".join(lines) + "\n"

    def ping(self, iid):
        self.app.start_ping(self.ping_lines([iid]))

    def ping_selected(self):
        sel = self.tree.selection()
        if sel:
            self.app.start_ping(self.ping_lines(sel))
        return "break"

    def ping_alive(self):
        iids = [h for h in self.order if self.results.get(h) and self.results[h].status not in ("Pending", "Stopped")
                and self.results[h].alive]
        if iids:
            self.app.start_ping(self.ping_lines(iids[:PingTab.MAX_TARGETS]))
        else:
            self.app.flash("No alive addresses to add.")

    def tree_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        if row not in self.tree.selection():
            self.tree.selection_set(row)
        ip = self.target_of(row)
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label=f"Add {ip} to the Ping tool", command=lambda: self.app.start_ping(ip))
        if len(self.tree.selection()) > 1:
            menu.add_command(label=f"Add the {len(self.tree.selection())} selected to the Ping tool",
                             command=self.ping_selected)
        menu.add_command(label=f"Traceroute to {ip}", command=lambda: self.app.goto_trace(ip))
        menu.add_command(label=f"Reverse DNS (PTR) for {ip}", command=lambda: self.app.dig_ptr(ip))
        menu.add_separator()
        menu.add_command(label=f"Copy {ip}", command=lambda: self.app.copy(ip))
        self.app.popup_tree_menu(menu, event)

    def update_status(self, running: bool):
        rs = list(self.results.values())
        done = [r for r in rs if r.status not in ("Pending", "Stopped")]
        alive = sum(1 for r in done if r.alive)
        partial = sum(1 for r in done if r.alive and r.received < r.sent)
        elapsed = pinger.format_duration(time.monotonic() - self.started) if self.started else ""
        if running:
            msg = f"Sweeping… {len(done):,} of {len(rs):,} done"
        elif self.stop_event and self.stop_event.is_set() and len(done) < len(rs):
            msg = f"Stopped · {len(done):,} of {len(rs):,} tested"
        else:
            msg = f"Swept {len(done):,} address{'es' if len(done) != 1 else ''}"
        msg += f"  ·  {alive:,} alive"
        if partial:
            msg += f" ({partial:,} with loss)"
        msg += f"  ·  {len(done) - alive:,} not alive  ·  {elapsed}"
        self.status_lbl.configure(text=msg)

    def hosts_where(self, alive: bool):
        return [self.target_of(h) for h in self.order
                if self.results.get(h) and self.results[h].status not in ("Pending", "Stopped")
                and self.results[h].alive == alive]

    def copy_list(self, alive: bool):
        items = self.hosts_where(alive)
        if items:
            self.app.copy("\n".join(items))
        else:
            self.app.flash("Nothing to copy.")

    def copy_table(self):
        if self.tree.get_children(""):
            self.app.copy(texttable.tree_table(self.tree, skip=("Action",)))

    def settings_dict(self) -> dict:
        return dict(sweep_input=self.get_text(), sweep_count=self.count_v.get(), sweep_timeout=self.timeout_v.get(),
                    sweep_workers=self.workers_v.get(), sweep_names=self.names_v.get(), sweep_show=self.show_v.get())



# --------------------------------------------------------------------------- route table tab

SAMPLE_ROUTES = """\
Codes: L - local, C - connected, S - static, B - BGP, O - OSPF, IA - OSPF inter area, E2 - OSPF external type 2

Gateway of last resort is 192.0.2.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 192.0.2.1
      10.0.0.0/8 is variably subnetted, 6 subnets, 3 masks
C        10.0.0.0/30 is directly connected, GigabitEthernet0/0
L        10.0.0.2/32 is directly connected, GigabitEthernet0/0
O        10.1.1.0/24 [110/2] via 10.0.0.1, 00:01:23, GigabitEthernet0/0
O IA     10.1.2.0/24 [110/12] via 10.0.0.1, 2d03h, GigabitEthernet0/0
                     [110/12] via 10.0.0.5, 2d03h, GigabitEthernet0/1
O        10.1.3.0/24 [110/65536] via 10.0.0.5, 00:00:40, GigabitEthernet0/1
O E2     172.16.0.0/16 [110/20] via 10.0.0.1, 1w2d, GigabitEthernet0/0
B        198.51.100.0/24 [20/0] via 192.0.2.1, 3w0d
"""


class RouteTableTab(ttk.Frame):
    """Summarise 'show ip route' / 'show route' output from IOS, IOS-XE, IOS-XR, NX-OS, Junos and EOS."""

    MAX_ROWS = 5000
    TILES = (("total", "Total routes"), ("protocols", "Protocols"), ("nexthops", "Next hops"),
             ("recent", "Changed < 5 min"), ("unusual", "Unusual metrics"), ("ecmp", "ECMP routes"))

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        self.parsed = None
        self.summary = None
        self.job = 0
        self.focus_desc = ""
        self.focus_fn = None

        head = ttk.Frame(self)
        head.pack(fill="x")
        ttk.Label(head, text="Route table", style="Title.TLabel").pack(side="left")
        ttk.Label(head, text="  paste 'show ip route' / 'show route' from IOS, IOS-XE, IOS-XR, NX-OS, Junos or EOS",
                  style="Hint.TLabel").pack(side="left")
        ttk.Button(head, text="Clear", style="Small.TButton", command=lambda: self.set_text("")).pack(side="right")
        ttk.Button(head, text="Paste", style="Small.TButton", command=self.paste).pack(side="right", padx=4)
        ttk.Button(head, text="Open file…", style="Small.TButton", command=self.open_file).pack(side="right")
        self.src = scrolled_text(self, app, height=10)
        self.src.container.pack(fill="x", pady=(4, 0))
        self.src.insert("1.0", SAMPLE_ROUTES)
        self.src.edit_modified(False)

        ttk.Separator(self).pack(fill="x", pady=10)
        top = ttk.Frame(self)
        top.pack(fill="x")
        self.status_lbl = ttk.Label(top, style="Title.TLabel")
        self.status_lbl.pack(side="left")
        ttk.Button(top, text="Copy summary", style="Small.TButton", command=self.copy_summary).pack(side="right")
        self.warn_lbl = ttk.Label(self, style="Warn.TLabel", wraplength=1000)
        self.warn_lbl.pack(anchor="w")

        tiles = ttk.Frame(self)
        tiles.pack(fill="x", pady=(6, 0))
        self.tile_vals = {}
        for i, (key, label) in enumerate(self.TILES):
            box = ttk.Frame(tiles, padding=(10, 6), relief="groove", borderwidth=1)
            box.grid(row=0, column=i, sticky="nsew", padx=3)
            ttk.Label(box, text=label, style="Key.TLabel").pack(anchor="w")
            val = ttk.Label(box, text="–", style="Big.TLabel")
            val.pack(anchor="w")
            self.tile_vals[key] = val
            tiles.columnconfigure(i, weight=1, uniform="tile")

        grid = ttk.Frame(self)
        grid.pack(fill="x", pady=(12, 0))
        grid.columnconfigure(0, weight=1, uniform="half")
        grid.columnconfigure(1, weight=1, uniform="half")
        self.proto_tree = self._section(grid, "Routes by protocol", ("Protocol", "Routes", "Share", "Breakdown"),
                                        (110, 70, 60, 200), row=0, col=0, height=7)
        self.if_tree = self._section(grid, "Routes by interface", ("Interface", "Routes", "Next hops"),
                                     (200, 70, 80), row=0, col=1, height=7)
        self.nh_tree = self._section(self, "Next hops", ("Next hop", "Interface", "Routes", "Protocols"),
                                     (200, 200, 70, 300), height=8)
        self.recent_lbl = None
        self.recent_tree = self._section(self, "Changed in the last 5 minutes",
                                         ("Prefix", "Protocol", "Age", "Next hop", "Interface"),
                                         (180, 110, 90, 200, 200), height=6, label_attr="recent_lbl")
        self.unusual_tree = self._section(self, "Unusually high metrics",
                                          ("Prefix", "Protocol", "AD/Metric", "Next hop", "Why"),
                                          (170, 100, 110, 160, 520), height=5, label_attr="unusual_lbl")
        for t in (self.unusual_tree,):
            t.tag_configure("flag", **SWEEP_COLORS["partial"])

        # all routes, filterable
        ah = ttk.Frame(self)
        ah.pack(fill="x", pady=(14, 0))
        ttk.Label(ah, text="All routes", style="Title.TLabel").pack(side="left")
        self.focus_lbl = ttk.Label(ah, style="Hint.TLabel")
        self.focus_lbl.pack(side="left", padx=(10, 0))
        ttk.Button(ah, text="Copy table", style="Small.TButton", command=self.copy_routes).pack(side="right")
        self.find_clear = ttk.Button(ah, text="✕", style="Small.TButton", width=2,
                                     command=lambda: self.find_v.set(""))
        self.find_clear.pack(side="right", padx=(2, 8))
        self.find_v = tk.StringVar()
        ttk.Entry(ah, textvariable=self.find_v, width=24).pack(side="right", padx=(4, 0))
        ttk.Label(ah, text="Find:").pack(side="right")
        # filter bar: says what the list is filtered by, with a one-click way to clear it
        fb = ttk.Frame(self)
        fb.pack(fill="x", pady=(6, 0))
        ttk.Label(fb, text="Filter:", style="Field.TLabel").pack(side="left")
        self.chip = ttk.Button(fb, style="Accent.TButton", command=self.clear_focus)
        self.chip_hint = ttk.Label(fb, style="Hint.TLabel")
        self.chip_hint.pack(side="left", padx=(8, 0))
        self.find_v.trace_add("write", lambda *a: self.fill_routes())
        self.route_tree = make_tree(self, ("Prefix", "Protocol", "AD", "Metric", "Next hop(s)", "Interface(s)",
                                           "Age", "Table"), (170, 100, 50, 90, 220, 220, 100, 90))
        self.route_tree.configure(height=14)
        self.route_tree.container.pack(fill="both", expand=True, pady=(4, 0))
        self.route_tree.tag_configure("flag", **SWEEP_COLORS["partial"])
        self.route_tree.tag_configure("recent", **SWEEP_COLORS["alive"])
        make_sortable(self.route_tree, numeric=("AD", "Metric"))
        ttk.Label(self, style="Hint.TLabel",
                  text="Click a protocol, interface or next hop above to list its routes here. "
                       "Orange = unusually high metric · green = changed in the last 5 minutes.").pack(anchor="w",
                                                                                                      pady=(4, 0))
        self.filter_trees = {self.proto_tree: "protocol", self.if_tree: "interface", self.nh_tree: "nexthop"}
        for tree, kind in self.filter_trees.items():
            tree.bind("<<TreeviewSelect>>", lambda e, t=tree, k=kind: self.focus_from(t, k))
            tree.bind("<ButtonPress-1>", lambda e, t=tree: self._click_filter_row(e, t), add="+")
            tree.bind("<Escape>", lambda e: self.clear_focus())
        self.route_tree.bind("<Escape>", lambda e: self.clear_focus())
        app.root.bind_all("<Escape>", self._escape, add="+")   # Esc anywhere on this tab clears the filter
        self.focus_src = None

        self.debounce = Debouncer(self, 400, self.analyze)
        self.src.bind("<<Modified>>", self._modified)
        self.analyze()

    def _section(self, parent, title, cols, widths, row=None, col=None, height=6, label_attr=None):
        box = ttk.Frame(parent)
        if row is None:
            box.pack(fill="x", pady=(12, 0))
        else:
            box.grid(row=row, column=col, sticky="nsew", padx=(0, 6) if col == 0 else (6, 0))
        h = ttk.Frame(box)
        h.pack(fill="x")
        lbl = ttk.Label(h, text=title, style="Title.TLabel")
        lbl.pack(side="left")
        if label_attr:
            note = ttk.Label(h, style="Hint.TLabel")
            note.pack(side="left", padx=(10, 0))
            setattr(self, label_attr, note)
        tree = make_tree(box, cols, widths)
        tree.configure(height=height)
        tree.container.pack(fill="x", pady=(4, 0))
        ttk.Button(h, text="Copy", style="Small.TButton",
                   command=lambda t=tree: self.copy_tree(t)).pack(side="right")
        num = tuple(c for c in cols if c in ("Routes", "Next hops", "Share"))
        make_sortable(tree, numeric=num)
        return tree

    # ---- input

    def get_text(self):
        return self.src.get("1.0", "end-1c")

    def set_text(self, text):
        self.src.delete("1.0", "end")
        self.src.insert("1.0", text)
        self.src.edit_modified(False)
        self.analyze()

    def paste(self):
        try:
            self.set_text(self.app.root.clipboard_get())
        except tk.TclError:
            pass

    def open_file(self):
        from tkinter import filedialog
        name = filedialog.askopenfilename(parent=self, title="Open route table output",
                                          initialdir=self.app.settings.get("routes_dir", str(Path.home())),
                                          filetypes=[("Text / logs", "*.txt *.log *.cfg *.out"), ("All files", "*")])
        if not name:
            return
        try:
            text = textdiff.read_text_file(name)
        except (OSError, ValueError) as exc:
            self.status_lbl.configure(text=f"Couldn't open: {exc}")
            return
        self.app.settings["routes_dir"] = str(Path(name).parent)
        self.set_text(text)

    def _modified(self, _):
        if self.src.edit_modified():
            self.src.edit_modified(False)
            self.debounce()

    # ---- analysis

    def analyze(self):
        text = self.get_text()
        self.job += 1
        job = self.job
        if len(text) < 300_000:
            p = routetable.parse(text)
            self.show(job, p, routetable.summarise(p))
            return
        self.status_lbl.configure(text="Reading routes…")
        box = {}

        def work():
            p = routetable.parse(text)
            box["r"] = (p, routetable.summarise(p))

        t = threading.Thread(target=work, daemon=True)
        t.start()

        def poll():
            if t.is_alive():
                self.after(150, poll)
            elif job == self.job:
                self.show(job, *box["r"])

        self.after(150, poll)

    def show(self, job, parsed, s):
        if job != self.job:
            return
        self.parsed, self.summary = parsed, s
        if not parsed.routes:
            self.status_lbl.configure(text="Paste route table output above." if not self.get_text().strip()
                                      else "No routes recognised.")
        else:
            tables = f"  ·  {len(parsed.tables)} tables/VRFs" if len(parsed.tables) > 1 else ""
            self.status_lbl.configure(text=f"{parsed.platform}  ·  {s.total:,} routes{tables}")
        self.warn_lbl.configure(text="  ".join(parsed.warnings))
        vals = {"total": s.total, "protocols": len(s.by_protocol), "nexthops": len(s.next_hops),
                "recent": len(s.recent) if parsed.has_ages else "n/a", "unusual": len(s.unusual), "ecmp": s.ecmp}
        for k, v in vals.items():
            self.tile_vals[k].configure(text=f"{v:,}" if isinstance(v, int) else v)
        self.tile_vals["unusual"].configure(foreground=self.app.colors["warn"] if s.unusual else "")

        fill = lambda tree, rows: (tree.delete(*tree.get_children()),
                                   [tree.insert("", "end", iid=str(i), values=r) for i, r in enumerate(rows)])
        total = max(1, s.total)
        fill(self.proto_tree, [(p, f"{c:,}", f"{100 * c / total:.1f}%", d) for p, c, d in s.by_protocol])
        fill(self.if_tree, [(i, f"{c:,}", n) for i, c, n in s.interfaces])
        fill(self.nh_tree, [(ip or "(directly connected)", intf or "(recursive)", f"{c:,}", pr)
                            for ip, intf, c, pr in s.next_hops])
        hop = lambda r: (", ".join(h.ip for h in r.next_hops if h.ip), ", ".join(h.interface for h in r.next_hops
                                                                                  if h.interface))
        fill(self.recent_tree, [(r.prefix, r.proto_label, r.age_text, *hop(r)) for r in s.recent])
        self.recent_lbl.configure(text="" if parsed.has_ages or not parsed.routes
                                  else "this output doesn't show route ages (Arista EOS and IOS IPv6 don't)")
        fill(self.unusual_tree, [(r.prefix, r.proto_label, f"{r.distance}/{r.metric}", hop(r)[0] or hop(r)[1], r.flag)
                                 for r in s.unusual])
        for i in self.unusual_tree.get_children():
            self.unusual_tree.item(i, tags=("flag",))
        self.unusual_lbl.configure(text="none found" if parsed.routes and not s.unusual else "")
        for t in (self.unusual_tree, self.nh_tree, self.proto_tree):
            autosize_columns(t, self.app.mono, max_px=700)
        self.clear_focus()

    # ---- all-routes table

    def _escape(self, event):
        if self.app.current == "routes" and self.focus_fn and event.widget.winfo_toplevel() is self.app.root:
            self.clear_focus()

    def _click_filter_row(self, event, tree):
        """Clicking the row that's already the filter turns the filter off."""
        row = tree.identify_row(event.y)
        if row and self.focus_src == (tree, row):
            self.clear_focus()
            return "break"

    def focus_from(self, tree, kind):
        sel = tree.selection()
        if not sel or not self.summary:
            return
        if self.focus_src == (tree, sel[0]):
            return
        for other in self.filter_trees:              # only one filter at a time: clear the other tables
            if other is not tree and other.selection():
                other.selection_remove(*other.selection())
        self.focus_src = (tree, sel[0])
        v = tree.item(sel[0], "values")
        if kind == "protocol":
            name = v[0]
            self.focus_fn = lambda r: r.protocol == name
            self.focus_desc = f"{name} routes"
        elif kind == "interface":
            intf = v[0]
            self.focus_fn = lambda r: any(h.interface == intf for h in r.next_hops)
            self.focus_desc = f"routes out {intf}"
        else:
            ip = "" if v[0] == "(directly connected)" else v[0]
            intf = "" if v[1] == "(recursive)" else v[1]
            self.focus_fn = lambda r: any(h.ip == ip and h.interface == intf for h in r.next_hops)
            self.focus_desc = f"routes via {ip or 'directly connected'}" + (f" on {intf}" if intf else "")
        self.fill_routes()

    def clear_focus(self):
        self.focus_fn, self.focus_desc, self.focus_src = None, "", None
        for tree in getattr(self, "filter_trees", {}):
            if tree.selection():
                tree.selection_remove(*tree.selection())
        self.fill_routes()

    def visible_routes(self):
        if not self.parsed:
            return []
        rs = self.parsed.routes
        if self.focus_fn:
            rs = [r for r in rs if self.focus_fn(r)]
        q = self.find_v.get().strip().lower()
        if q:
            rs = [r for r in rs if q in r.prefix.lower() or q in r.proto_label.lower() or
                  any(q in h.ip.lower() or q in h.interface.lower() for h in r.next_hops)]
        return rs

    def fill_routes(self):
        t = self.route_tree
        t.delete(*t.get_children())
        rs = self.visible_routes()
        for i, r in enumerate(rs[:self.MAX_ROWS]):
            tags = ("flag",) if r.flag else ("recent",) if r.age is not None and r.age < routetable.RECENT_SECONDS \
                else ()
            t.insert("", "end", iid=str(i), tags=tags, values=(
                r.prefix, r.proto_label, "" if r.distance is None else r.distance,
                "" if r.metric is None else r.metric, ", ".join(h.ip for h in r.next_hops if h.ip),
                ", ".join(h.interface for h in r.next_hops if h.interface), r.age_text, r.table))
        total = len(self.parsed.routes) if self.parsed else 0
        shown = f"first {self.MAX_ROWS:,} of {len(rs):,}" if len(rs) > self.MAX_ROWS else f"{len(rs):,}"
        filtered = bool(self.focus_fn or self.find_v.get().strip())
        self.focus_lbl.configure(text=(f"showing {shown} of {total:,} routes" if filtered else f"{total:,} routes")
                                 if total else "")
        if self.focus_fn:
            self.chip.configure(text=f"{self.focus_desc}   ✕")
            self.chip.pack(side="left", padx=(8, 0), before=self.chip_hint)
            self.chip_hint.configure(text="click ✕, press Esc, or click the highlighted row again to show all routes")
        else:
            self.chip.pack_forget()
            self.chip_hint.configure(text="none — click a protocol, interface or next hop above to show only its "
                                          "routes" if total else "")
        if self.find_v.get().strip():
            self.find_clear.state(["!disabled"])
        else:
            self.find_clear.state(["disabled"])

    # ---- export

    def copy_tree(self, tree):
        if tree.get_children():
            self.app.copy(texttable.tree_table(tree))

    def copy_routes(self):
        rs = self.visible_routes()
        if not rs:
            return
        rows = [(r.prefix, r.proto_label, "" if r.distance is None else r.distance,
                 "" if r.metric is None else r.metric,
                 ", ".join(h.ip for h in r.next_hops if h.ip), ", ".join(h.interface for h in r.next_hops if h.interface),
                 r.age_text, r.table, r.flag) for r in rs]
        self.app.copy(texttable.format_table(
            ("Prefix", "Protocol", "AD", "Metric", "Next hop(s)", "Interface(s)", "Age", "Table", "Note"), rows))

    def copy_summary(self):
        if self.parsed and self.parsed.routes:
            self.app.copy(routetable.report(self.parsed, self.summary))


# --------------------------------------------------------------------------- IRR / RPKI tab


class IrrTab(ttk.Frame):
    """Expand ASNs / AS-SETs from an IRR, check each route object against RPKI, and write prefix filters."""

    COLUMNS = ("Prefix", "Origin", "Source", "RPKI", "RPKI detail", "In filter", "Found by", "Description")
    ASN_COLUMNS = ("ASN", "IPv4", "IPv6")
    MAX_ROWS = 5000

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        s = app.settings
        self.result = None
        self.worker = None
        self.stop_event = None
        self.queue = None
        self.history = list(s.get("irr_history", []))
        self.vrp_path = settings_path().parent / "rpki-vrps.json"

        head = ttk.Frame(self)
        head.pack(fill="x")
        ttk.Label(head, text="IRR / RPKI", style="Title.TLabel").pack(side="left")
        ttk.Label(head, text="  Expand ASNs and AS-SETs or look up a prefix's route objects in the IRR, check them "
                             "against RPKI, and build prefix filters", style="Hint.TLabel").pack(side="left")

        row = ttk.Frame(self)
        row.pack(fill="x", pady=(8, 0))
        ttk.Label(row, text="ASNs / AS-SETs / prefixes:", style="Field.TLabel").pack(side="left")
        self.query_v = tk.StringVar(value=self.history[0] if self.history else "")
        self.query_box = ttk.Combobox(row, textvariable=self.query_v, values=self.history, width=44,
                                      font=app.mono)
        self.query_box.pack(side="left", padx=(6, 8))
        self.query_box.bind("<Return>", lambda e: self.start())
        self.go_btn = ttk.Button(row, text="Look up", style="Accent.TButton", command=self.start)
        self.go_btn.pack(side="left")
        self.stop_btn = ttk.Button(row, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Label(row, text="e.g. AS65000  AS-EXAMPLE  192.0.2.0/24  2001:db8::1", style="Hint.TLabel").pack(
            side="left", padx=(8, 0))

        row2 = ttk.Frame(self)
        row2.pack(fill="x", pady=(6, 0))
        ttk.Label(row2, text="IRR server:", style="Field.TLabel").pack(side="left")
        self.server_v = tk.StringVar(value=s.get("irr_server", irrtool.DEFAULT_SERVER))
        ttk.Combobox(row2, textvariable=self.server_v, values=irrtool.IRR_SERVERS, width=20).pack(
            side="left", padx=(6, 12))
        ttk.Label(row2, text="Sources:", style="Field.TLabel").pack(side="left")
        self.sources_v = tk.StringVar(value=s.get("irr_sources", ""))
        ttk.Entry(row2, textvariable=self.sources_v, width=30, font=app.mono).pack(side="left", padx=(6, 4))
        self.sources_hint = ttk.Label(self, text=f"Sources: blank = the server's default list, e.g. "
                                                 f"{irrtool.SOURCE_HINT}", style="Hint.TLabel")
        row3 = ttk.Frame(self)
        row3.pack(fill="x", pady=(6, 0))
        ttk.Label(row2, text="   Prefixes match:", style="Field.TLabel").pack(side="left")
        pm = s.get("irr_prefix_match", next(iter(irrtool.PREFIX_MATCHES)))
        self.pmatch_v = tk.StringVar(value=pm if pm in irrtool.PREFIX_MATCHES else next(iter(irrtool.PREFIX_MATCHES)))
        ttk.Combobox(row2, textvariable=self.pmatch_v, values=list(irrtool.PREFIX_MATCHES), state="readonly",
                     width=32).pack(side="left", padx=(6, 0))
        self.v4_v = tk.BooleanVar(value=s.get("irr_v4", True))
        self.v6_v = tk.BooleanVar(value=s.get("irr_v6", True))
        ttk.Checkbutton(row3, text="IPv4", variable=self.v4_v).pack(side="left")
        ttk.Checkbutton(row3, text="IPv6", variable=self.v6_v).pack(side="left", padx=(8, 16))
        self.rpki_v = tk.BooleanVar(value=s.get("irr_rpki", True))
        ttk.Checkbutton(row3, text="Check RPKI using VRPs from", variable=self.rpki_v).pack(side="left")
        self.vrp_v = tk.StringVar(value=s.get("irr_vrp_source", next(iter(irrtool.VRP_SOURCES))))
        ttk.Combobox(row3, textvariable=self.vrp_v, values=list(irrtool.VRP_SOURCES), width=40).pack(
            side="left", padx=(6, 6))
        self.vrp_btn = ttk.Button(row3, text="Update VRPs", style="Small.TButton", command=self.update_vrps)
        self.vrp_btn.pack(side="left")
        row4 = ttk.Frame(self)
        row4.pack(fill="x", pady=(6, 0))
        ttk.Label(row4, text="Networks for each ASN from:", style="Field.TLabel").pack(side="left")
        self.scope_v = tk.StringVar(value=s.get("irr_scope", "records"))
        ttk.Radiobutton(row4, text="IRR / RPKI records only", value="records", variable=self.scope_v).pack(
            side="left", padx=(8, 0))
        ttk.Radiobutton(row4, text="Also BGP announcements (RIPEstat) and ARIN registrations", value="all",
                        variable=self.scope_v).pack(side="left", padx=(12, 0))
        self.vrp_lbl = ttk.Label(self, style="Hint.TLabel")
        self.vrp_lbl.pack(anchor="w", pady=(2, 0))
        self.sources_hint.pack(anchor="w")
        self.show_vrp_status()

        ttk.Separator(self).pack(fill="x", pady=10)
        top = ttk.Frame(self)
        top.pack(fill="x")
        self.status_lbl = ttk.Label(top, style="Title.TLabel", text="Enter an ASN or AS-SET and press Look up.")
        self.status_lbl.pack(side="left")
        self.summary_lbl = ttk.Label(self, style="Field.TLabel", wraplength=1000, justify="left")
        self.summary_lbl.pack(anchor="w", pady=(2, 0))
        self.warn_lbl = ttk.Label(self, style="Warn.TLabel", wraplength=1000, justify="left")

        tables = ttk.Frame(self)
        tables.pack(fill="x", pady=(6, 0))
        self.tables = tables
        left = ttk.Frame(tables)
        left.pack(side="left", fill="y")
        lh = ttk.Frame(left)
        lh.pack(fill="x")
        ttk.Label(lh, text="ASNs", style="Key.TLabel").pack(side="left")
        ttk.Button(lh, text="Copy", style="Small.TButton",
                   command=lambda: self.app.copy(texttable.tree_table(self.asn_tree))).pack(side="right")
        self.asn_tree = make_tree(left, self.ASN_COLUMNS, (110, 60, 60))
        self.asn_tree.configure(height=12)
        for c in ("IPv4", "IPv6"):
            self.asn_tree.column(c, anchor="e", stretch=False)
        self.asn_tree.container.pack(fill="y", expand=True, pady=(4, 0))
        make_sortable(self.asn_tree, numeric=("IPv4", "IPv6"))
        right = ttk.Frame(tables)
        right.pack(side="left", fill="both", expand=True, padx=(12, 0))
        rh = ttk.Frame(right)
        rh.pack(fill="x")
        ttk.Label(rh, text="Route objects", style="Key.TLabel").pack(side="left")
        self.show_v = tk.StringVar(value="All")
        ttk.Button(rh, text="Copy table", style="Small.TButton",
                   command=lambda: self.app.copy(texttable.tree_table(self.tree))).pack(side="right")
        ttk.Combobox(rh, textvariable=self.show_v, state="readonly", width=16,
                     values=["All", "RPKI invalid", "RPKI not found", "RPKI valid", "Left out of filter",
                             "Not in IRR"]).pack(
            side="right", padx=6)
        ttk.Label(rh, text="Show:").pack(side="right")
        self.tree = make_tree(right, self.COLUMNS, (170, 85, 170, 90, 300, 220, 190, 220))
        self.tree.configure(height=12, selectmode="extended")
        self.tree.column("Origin", stretch=False)
        self.tree.column("RPKI", stretch=False)
        self.tree.container.pack(fill="both", expand=True, pady=(4, 0))
        make_sortable(self.tree)
        self.tree.tag_configure("Valid", **SWEEP_COLORS["alive"])
        self.tree.tag_configure("Invalid", **SWEEP_COLORS["dead"])
        self.tree.tag_configure("out", foreground=app.colors["muted"])
        self.rows_note = ttk.Label(self, style="Hint.TLabel")
        self.rows_note.pack(anchor="w")
        self.show_v.trace_add("write", lambda *_: self.fill_routes())

        # ---- filter
        ttk.Separator(self).pack(fill="x", pady=10)
        ttk.Label(self, text="Prefix filter", style="Title.TLabel").pack(anchor="w")
        f1 = ttk.Frame(self)
        f1.pack(fill="x", pady=(6, 0))
        self.drop_invalid_v = tk.BooleanVar(value=s.get("irr_drop_invalid", True))
        ttk.Checkbutton(f1, text="Leave out RPKI-invalid routes", variable=self.drop_invalid_v).pack(side="left")
        self.need_irr_v = tk.BooleanVar(value=s.get("irr_need_irr", False))
        self.maxlen_on_v = tk.BooleanVar(value=s.get("irr_maxlen_on", True))
        ttk.Checkbutton(f1, text="Leave out prefixes longer than IPv4 /", variable=self.maxlen_on_v).pack(
            side="left", padx=(16, 0))
        self.max4_v = tk.StringVar(value=str(s.get("irr_max4", 24)))
        self.max6_v = tk.StringVar(value=str(s.get("irr_max6", 48)))
        ttk.Entry(f1, textvariable=self.max4_v, width=4).pack(side="left")
        ttk.Label(f1, text="  IPv6 /").pack(side="left")
        ttk.Entry(f1, textvariable=self.max6_v, width=4).pack(side="left")
        ttk.Checkbutton(f1, text="Leave out prefixes with no IRR route object", variable=self.need_irr_v).pack(
            side="left", padx=(16, 0))
        f2 = ttk.Frame(self)
        f2.pack(fill="x", pady=(6, 0))
        self.ms_v = tk.BooleanVar(value=s.get("irr_more_specifics", False))
        ttk.Checkbutton(f2, text="Accept more-specifics (le) up to IPv4 /", variable=self.ms_v).pack(side="left")
        self.ms4_v = tk.StringVar(value=str(s.get("irr_ms4", 24)))
        self.ms6_v = tk.StringVar(value=str(s.get("irr_ms6", 48)))
        ttk.Entry(f2, textvariable=self.ms4_v, width=4).pack(side="left")
        ttk.Label(f2, text="  IPv6 /").pack(side="left")
        ttk.Entry(f2, textvariable=self.ms6_v, width=4).pack(side="left")
        ttk.Label(f2, text="   (prefixes already inside a wider entry's range are dropped)",
                  style="Hint.TLabel").pack(side="left")
        f3 = ttk.Frame(self)
        f3.pack(fill="x", pady=(6, 0))
        ttk.Label(f3, text="Format:", style="Field.TLabel").pack(side="left")
        fmt = s.get("irr_format", irrtool.FORMATS[0])
        self.format_v = tk.StringVar(value=fmt if fmt in irrtool.FORMATS else irrtool.FORMATS[0])
        ttk.Combobox(f3, textvariable=self.format_v, values=irrtool.FORMATS, state="readonly", width=30).pack(
            side="left", padx=(6, 12))
        ttk.Label(f3, text="Name:", style="Field.TLabel").pack(side="left")
        self.name_v = tk.StringVar(value="")
        ttk.Entry(f3, textvariable=self.name_v, width=26, font=app.mono).pack(side="left", padx=(6, 4))
        ttk.Label(f3, text="-V4 / -V6 are added", style="Hint.TLabel").pack(side="left")
        ttk.Button(f3, text="Save…", style="Small.TButton", command=self.save_output).pack(side="right")
        ttk.Button(f3, text="Copy config", style="Small.TButton",
                   command=lambda: self.app.copy(self.output_text())).pack(side="right", padx=6)
        self.filter_lbl = ttk.Label(self, style="Hint.TLabel")
        self.filter_lbl.pack(anchor="w", pady=(4, 0))
        self.out = scrolled_text(self, app, height=16)
        self.out.container.pack(fill="both", expand=True, pady=(4, 0))
        self.out.configure(state="disabled")
        self.debounce = Debouncer(self, 200, self.render)
        for v in (self.drop_invalid_v, self.need_irr_v, self.maxlen_on_v, self.max4_v, self.max6_v, self.ms_v, self.ms4_v,
                  self.ms6_v, self.format_v, self.name_v):
            v.trace_add("write", self.debounce)

    # ---- VRPs

    def vrp_url(self) -> str:
        v = self.vrp_v.get().strip()
        return irrtool.VRP_SOURCES.get(v, v)

    def show_vrp_status(self):
        p = self.vrp_path
        if not p.exists():
            self.vrp_lbl.configure(text="No VRPs downloaded yet. They're fetched the first time you check RPKI "
                                        "(any JSON VRP export works, e.g. your own Routinator: "
                                        "http://validator:8323/json).")
            return
        age = time.time() - p.stat().st_mtime
        mins = max(1, int(age / 60))
        hrs = f"{age / 3600:.1f} hours" if age >= 3600 else f"{mins} minute{'s' if mins != 1 else ''}"
        src = self.app.settings.get("irr_vrp_cached_url", "")
        self.vrp_lbl.configure(text=f"VRPs: {p.name} from {src or 'unknown source'}, {hrs} old "
                                    f"(refreshed automatically after {irrtool.VRP_MAX_AGE // 3600} hours).")

    def vrps_fresh(self) -> bool:
        p = self.vrp_path
        return (p.exists() and time.time() - p.stat().st_mtime < irrtool.VRP_MAX_AGE
                and self.app.settings.get("irr_vrp_cached_url") == self.vrp_url())

    def update_vrps(self):
        if self.worker:
            return
        self.run_job(vrp_only=True)

    # ---- running

    def start(self):
        if self.worker:
            return "break"
        queries, bad = irrtool.parse_queries(self.query_v.get())
        if not queries:
            self.status_lbl.configure(text="Enter an ASN (AS65000), an AS-SET (AS-EXAMPLE), or a prefix (192.0.2.0/24).")
            return "break"
        if not (self.v4_v.get() or self.v6_v.get()):
            self.status_lbl.configure(text="Tick IPv4, IPv6, or both.")
            return "break"
        text = " ".join(queries)
        self.history = [text] + [h for h in self.history if h != text][:19]
        self.query_box.configure(values=self.history)
        if bad:
            self.app.flash(f"Skipped (not an ASN, AS-SET or prefix): {', '.join(bad)}")
        self.render()                       # current filter options applied to what's shown until new results land
        self.run_job(queries=queries)
        return "break"

    def run_job(self, queries=None, vrp_only=False):
        import queue as _q
        self.queue = _q.Queue()
        self.stop_event = threading.Event()
        server = self.server_v.get().strip() or irrtool.DEFAULT_SERVER
        port = 43
        if ":" in server and server.count(":") == 1:
            server, port = server.split(":")[0], int(server.split(":")[1] or 43)
        sources, v4, v6, pmatch = self.sources_v.get(), self.v4_v.get(), self.v6_v.get(), self.pmatch_v.get()
        scope = self.scope_v.get()
        arin_base = self.app.settings.get("arin_base", arinwhois.BASE_URL)
        ripestat = self.app.settings.get("ripestat_url", asnsources.RIPESTAT_URL)
        want_rpki = self.rpki_v.get() or vrp_only
        url, fresh = self.vrp_url(), self.vrps_fresh() and not vrp_only
        q, stop, vrp_path = self.queue, self.stop_event, self.vrp_path

        def say(msg):
            q.put(("status", msg))

        def work():
            try:
                res = None
                if queries:
                    res = irrtool.expand(queries, server, sources, v4, v6, port=port, stop=stop, progress=say,
                                         prefix_match=pmatch)
                vrp_text = None
                if want_rpki and (vrp_only or (res and (res.routes or res.members))):
                    if not fresh:
                        say(f"Downloading VRPs from {url} …")
                        n = irrtool.download_vrps(
                            vrp_path, url, stop=stop,
                            progress=lambda d, t: say(f"Downloading VRPs … {d / 1e6:.1f}"
                                                      + (f" of {t / 1e6:.1f}" if t else "") + " MB"))
                        q.put(("vrp", url, n))
                    vrp_text = vrp_path.read_text(encoding="utf-8", errors="replace")
                if res and res.members:
                    self.add_other_sources(res, vrp_text, scope, v4, v6, stop, say, arin_base, ripestat)
                if res and vrp_text and res.routes:
                    say(f"Checking {len(res.routes):,} routes against RPKI …")
                    irrtool.check_rpki(res.routes, vrp_text)
                q.put(("done", res))
            except irrtool.Cancelled:
                q.put(("stopped",))
            except (irrtool.IrrError, OSError, ValueError) as exc:
                q.put(("error", str(exc)))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()
        self.go_btn.configure(state="disabled")
        self.vrp_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_lbl.configure(text="Working …")
        self.after(100, self.poll)

    MAX_EXTERNAL_ASNS = 50

    def add_other_sources(self, res, vrp_text, scope, v4, v6, stop, say, arin_base, ripestat):
        """Add each member ASN's ROAs (from the VRPs) and, in the wider scope, its BGP announcements
        (RIPEstat) and ARIN-registered networks. Runs on the worker thread."""
        from concurrent.futures import ThreadPoolExecutor
        if vrp_text:
            for pfx, maxlen, asn in irrtool.roas_for_asns(vrp_text, res.members):
                irrtool.merge_route(res, pfx, asn, "ROA", found=f"ROA (max /{maxlen})", ipv4=v4, ipv6=v6)
        if scope != "all":
            irrtool.finish_expansion(res)
            return
        asns = res.members[:self.MAX_EXTERNAL_ASNS]
        if len(res.members) > len(asns):
            res.warnings.append(f"BGP and ARIN data fetched for the first {len(asns)} of {len(res.members):,} ASNs.")
        cache = {}

        def one(asn):
            if stop.is_set():
                return asn, [], ("", [], ""), ""
            err = ""
            try:
                bgp = asnsources.announced_prefixes(asn, url=ripestat, cache=None)
            except arinwhois.WhoisError as exc:
                bgp, err = [], f"{asn}: RIPEstat lookup failed ({exc})"
            arin = asnsources.arin_networks(asn, base=arin_base, cache=cache)
            return asn, bgp, arin, err

        done = 0
        with ThreadPoolExecutor(max_workers=6) as pool:
            for asn, bgp, (org, nets, note), err in pool.map(one, asns):
                done += 1
                say(f"BGP and ARIN data: {done} of {len(asns)} ASNs …")
                if stop.is_set():
                    raise irrtool.Cancelled("Stopped.")
                for pfx in bgp:
                    irrtool.merge_route(res, pfx, asn, "BGP", found="announced in BGP (RIPE RIS)", ipv4=v4, ipv6=v6)
                for cidr, handle, name in nets:
                    irrtool.merge_route(res, cidr, asn, "ARIN", found=f"ARIN {handle}",
                                        descr=f"{name} ({org})" if org else name, ipv4=v4, ipv6=v6)
                for w in (err, note):
                    if w and "registered with" not in w:
                        res.warnings.append(w)
        irrtool.finish_expansion(res)

    def poll(self):
        if self.queue is None:
            return
        while not self.queue.empty():
            msg = self.queue.get()
            kind = msg[0]
            if kind == "status":
                self.status_lbl.configure(text=msg[1])
            elif kind == "vrp":
                self.app.settings["irr_vrp_cached_url"] = msg[1]
                self.show_vrp_status()
                self.app.flash(f"Downloaded {msg[2]:,} VRPs.")
            else:
                self.finish()
                if kind == "done":
                    if msg[1] is not None:
                        self.show_result(msg[1])
                    else:
                        self.status_lbl.configure(text="VRPs updated.")
                elif kind == "stopped":
                    self.status_lbl.configure(text="Stopped.")
                else:
                    self.status_lbl.configure(text="Couldn't finish")
                    self.show_warning(msg[1])
                return
        if self.worker:
            self.after(100, self.poll)

    def finish(self):
        self.worker = None
        self.go_btn.configure(state="normal")
        self.vrp_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def stop(self):
        if self.stop_event:
            self.stop_event.set()

    def show_warning(self, text):
        self.warn_lbl.configure(text=text)
        if text:
            self.warn_lbl.pack(anchor="w", pady=(4, 0), before=self.tables)
        else:
            self.warn_lbl.pack_forget()

    # ---- showing results

    def show_result(self, res):
        self.result = res
        if not self.name_v.get().strip() or getattr(self, "_auto_name", None) == self.name_v.get():
            self._auto_name = irrtool.default_name(res.queries)
            self.name_v.set(self._auto_name)
        v4 = sum(1 for r in res.routes if r.version == 4)
        v6 = len(res.routes) - v4
        self.status_lbl.configure(text=f"{' '.join(res.queries)[:80]}:  {len(res.asns):,} ASN"
                                       f"{'s' if len(res.asns) != 1 else ''}  ·  {v4:,} IPv4 and {v6:,} IPv6 "
                                       f"prefixes")
        checked = [r for r in res.routes if r.rpki]
        if checked:
            from collections import Counter
            c = Counter(r.rpki for r in checked)
            rpki = (f"RPKI: {c.get('Valid', 0):,} valid  ·  {c.get('Invalid', 0):,} invalid  ·  "
                    f"{c.get('Not found', 0):,} not found (no ROA)")
        else:
            rpki = "RPKI not checked."
        kinds = {}
        for r in res.routes:
            for k in r.kinds:
                kinds[k] = kinds.get(k, 0) + 1
        seen = "  ·  ".join(f"{k} {kinds[k]:,}" for k in ("IRR", "ROA", "BGP", "ARIN") if k in kinds)
        not_irr = sum(1 for r in res.routes if not r.in_irr)
        extra = (f"\nPrefixes seen in: {seen}" + (f"  ·  {not_irr:,} not in the IRR (Show → Not in IRR)"
                                                   if not_irr else "")) if len(kinds) > 1 else ""
        self.summary_lbl.configure(text=f"From {res.server}" + (f" (sources {res.sources})" if res.sources.strip()
                                                                 else " (server's default sources)") + f".  {rpki}"
                                        + extra)
        self.show_warning("  ·  ".join(res.warnings[:6]) + (" …" if len(res.warnings) > 6 else ""))
        self.asn_tree.delete(*self.asn_tree.get_children())
        for a in res.asns:
            n4, n6 = res.per_asn.get(a, (0, 0))
            self.asn_tree.insert("", "end", values=(a, n4, n6))
        self.render()

    def limits(self):
        def num(v, lo, hi, default):
            try:
                n = int(str(v.get()).strip().lstrip("/"))
                return n if lo <= n <= hi else default
            except ValueError:
                return default
        max4 = num(self.max4_v, 1, 32, 24) if self.maxlen_on_v.get() else None
        max6 = num(self.max6_v, 1, 128, 48) if self.maxlen_on_v.get() else None
        ms4 = num(self.ms4_v, 1, 32, 24) if self.ms_v.get() else None
        ms6 = num(self.ms6_v, 1, 128, 48) if self.ms_v.get() else None
        return max4, max6, ms4, ms6

    def fill_routes(self):
        self.tree.delete(*self.tree.get_children())
        res = self.result
        if not res:
            return
        show = self.show_v.get()
        rows = [r for r in res.routes
                if show == "All" or (show == "Left out of filter" and r.excluded)
                or (show == "Not in IRR" and not r.in_irr)
                or (show.startswith("RPKI ") and r.rpki.lower() == show[5:].lower())]
        for r in rows[:self.MAX_ROWS]:
            tags = (r.rpki,) if r.rpki in ("Valid", "Invalid") else ("out",) if r.excluded else ()
            self.tree.insert("", "end", values=(r.prefix, r.origin, r.where, r.rpki or "–", r.rpki_detail,
                                                r.in_filter or ("No – " + r.excluded if r.excluded else "Yes"),
                                                r.found, r.descr), tags=tags)
        self.rows_note.configure(text=f"Showing the first {self.MAX_ROWS:,} of {len(rows):,} rows (the filter "
                                      f"below includes everything)." if len(rows) > self.MAX_ROWS else "")

    def render(self):
        res = self.result
        if not res:
            return
        max4, max6, ms4, ms6 = self.limits()
        irrtool.apply_filters(res.routes, self.drop_invalid_v.get(), max4, max6, require_irr=self.need_irr_v.get())
        v4 = irrtool.build_entries(res.routes, 4, more_specifics=ms4)
        v6 = irrtool.build_entries(res.routes, 6, more_specifics=ms6)
        irrtool.mark_in_filter(res.routes, v4 + v6)       # the table's "In filter" column follows the output
        left = sum(1 for r in res.routes if r.excluded)
        header = [f"{APP_NAME}: IRR {' '.join(res.queries)} via {res.server}"
                  + (f" sources {res.sources.strip()}" if res.sources.strip() else ""),
                  f"{datetime.now():%Y-%m-%d %H:%M}  ·  {len(v4):,} IPv4 / {len(v6):,} IPv6 entries"
                  + (f"  ·  {left:,} route objects left out" if left else "")]
        text = irrtool.render(self.format_v.get(), self.name_v.get(), v4, v6, header,
                              both=(self.v4_v.get(), self.v6_v.get()))
        self.out.configure(state="normal")
        self.out.delete("1.0", "end")
        self.out.insert("1.0", text)
        self.out.configure(state="disabled")
        why = {}
        for r in res.routes:
            if r.excluded:
                why[r.excluded] = why.get(r.excluded, 0) + 1
        leaks = [r for r in res.routes if r.leaks]
        self.filter_lbl.configure(text=f"{len(v4):,} IPv4 and {len(v6):,} IPv6 entries"
                                       + (". Left out: " + ", ".join(f"{n:,} {k if k.startswith('RPKI') else k[0].lower() + k[1:]}"
                                                                   for k, n in why.items())
                                          if why else ".")
                                       + (f"  ⚠ {len(leaks):,} left-out prefix{'es are' if len(leaks) != 1 else ' is'} "
                                          f"still matched by a wider entry's le range (see In filter)."
                                          if leaks else ""),
                                  style="Warn.TLabel" if leaks else "Hint.TLabel")
        self.fill_routes()

    def output_text(self) -> str:
        return self.out.get("1.0", "end-1c")

    def save_output(self):
        if not self.result:
            return
        from tkinter import filedialog
        ext = ".txt"
        name = filedialog.asksaveasfilename(parent=self, title="Save prefix filter", defaultextension=ext,
                                            initialfile=f"{self.name_v.get() or 'irr-filter'}{ext}",
                                            filetypes=[("Text", "*.txt *.cfg *.conf"), ("All files", "*")])
        if name:
            try:
                Path(name).write_text(self.output_text(), encoding="utf-8")
                self.app.flash(f"Saved {name}")
            except OSError as exc:
                self.app.flash(f"Couldn't save: {exc}")

    def load(self, text: str, run: bool = True):
        """Used by Send to: pick the ASNs / AS-SETs out of any text."""
        found = []
        toks = re.findall(r"(?:AS\d+:)?(?:AS|RS)-[\w.:-]+|\bAS\d{1,10}\b", text, re.I)
        # plain numbers: after remote-as / peer-as / asn / origin, or a text that's only numbers (an AS path)
        toks += re.findall(r"(?:remote-as|peer-as|local-as|neighbor-as|\basn?|origin)[\s:=]+(\d{1,10})\b", text, re.I)
        if re.fullmatch(r"[\d\s,{}\[\]()]+", text.strip() or "x"):
            toks += re.findall(r"\d{1,10}", text)
        for m in re.finditer(r"(?<![\w.:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})"
                             r"(?:/\d{1,3})?(?![\w.:])", text):
            q = irrtool._prefix_or_none(m.group(0))
            if q:
                toks.append(m.group(0))
        for tok in toks:
            q, _ = irrtool.parse_queries(tok)
            for x in q:
                if x not in found:
                    found.append(x)
        if found:
            self.query_v.set(" ".join(found[:20]))
            if run:
                self.start()
        return found

    def settings_dict(self) -> dict:
        return dict(irr_history=self.history, irr_server=self.server_v.get(), irr_sources=self.sources_v.get(),
                    irr_v4=self.v4_v.get(), irr_v6=self.v6_v.get(), irr_rpki=self.rpki_v.get(),
                    irr_vrp_source=self.vrp_v.get(), irr_drop_invalid=self.drop_invalid_v.get(),
                    irr_maxlen_on=self.maxlen_on_v.get(), irr_max4=self.max4_v.get(), irr_max6=self.max6_v.get(),
                    irr_more_specifics=self.ms_v.get(), irr_ms4=self.ms4_v.get(), irr_ms6=self.ms6_v.get(),
                    irr_prefix_match=self.pmatch_v.get(), irr_scope=self.scope_v.get(),
                    irr_need_irr=self.need_irr_v.get(),
                    irr_format=self.format_v.get())



# --------------------------------------------------------------------------- bandwidth cost tab


class BandwidthCostTab(ttk.Frame):
    """Cost per Mbps / Gbps (and per user, per GB moved) for circuit quotes, compared side by side.
    The comparison list is saved to costs.json in the settings folder."""

    COLUMNS = ("Note", "Bandwidth", "Monthly", "One-time", "One-time is", "Term", "Eff. monthly", "Total", "Per Mbps",
               "Per Gbps", "Users", "Per user/mo", "Per user/term", "Per GB", "Added")
    FIELDS = (("per_mbps", "Per Mbps / month"), ("per_gbps", "Per Gbps / month"),
              ("effective_monthly", "Effective monthly"), ("first_month", "First month's bill"),
              ("annual", "Per year"), ("total", "Whole term"),
              ("per_user", "Per user / month"), ("per_user_term", "Per user, whole term"),
              ("mbps_per_user", "Bandwidth per user"), ("gb_per_month", "Data per month"),
              ("per_gb", "Per GB moved"), ("per_tb", "Per TB moved"))

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        s = app.settings
        self.path = settings_path().parent / "costs.json"
        self.entries = self.load_entries()
        self.editing = None                               # index of the row loaded for editing

        ttk.Label(self, text="Bandwidth Cost", style="Title.TLabel").pack(anchor="w")
        ttk.Label(self, text="Monthly cost, any one-time cost, the term and the circuit size give the cost per "
                             "Mbps and Gbps. Add several quotes to compare them below.", style="Hint.TLabel").pack(
            anchor="w", pady=(2, 8))
        form = ttk.Frame(self)
        form.pack(fill="x")
        cur = s.get("bw_form", {})
        self.note_v = tk.StringVar(value=cur.get("note", ""))
        self.monthly_v = tk.StringVar(value=cur.get("monthly", "1500"))
        self.nrc_v = tk.StringVar(value=cur.get("one_time", "0"))
        self.spread_v = tk.BooleanVar(value=cur.get("spread", True))
        self.term_v = tk.StringVar(value=cur.get("term", "36"))
        self.term_unit_v = tk.StringVar(value=cur.get("term_unit", "months"))
        self.bw_v = tk.StringVar(value=cur.get("bandwidth", "10"))
        self.bw_unit_v = tk.StringVar(value=cur.get("bw_unit", "Gbps"))
        self.users_on_v = tk.BooleanVar(value=cur.get("users_on", False))
        self.users_v = tk.StringVar(value=cur.get("users", "500"))
        self.util_v = tk.StringVar(value=cur.get("utilization", "100"))
        mono = app.mono
        rows = [
            ("Note:", [(ttk.Entry, dict(textvariable=self.note_v, width=46))],
             "e.g. vendor, circuit, location"),
            ("Monthly cost:", [(ttk.Entry, dict(textvariable=self.monthly_v, width=14, font=mono))],
             "recurring (MRC), e.g. 1500 or $1,500; blank or 0 for a one-time (capital) quote"),
            ("One-time cost:", [(ttk.Entry, dict(textvariable=self.nrc_v, width=14, font=mono)),
                                (ttk.Checkbutton, dict(text="Spread over the term", variable=self.spread_v))],
             "install / NRC (0 if none); untick to count it up front instead"),
            ("Term:", [(ttk.Entry, dict(textvariable=self.term_v, width=8, font=mono)),
                       (ttk.Combobox, dict(textvariable=self.term_unit_v, values=list(bwcost.TERM_UNITS),
                                           state="readonly", width=8))], ""),
            ("Bandwidth:", [(ttk.Entry, dict(textvariable=self.bw_v, width=8, font=mono)),
                            (ttk.Combobox, dict(textvariable=self.bw_unit_v, values=list(bwcost.RATE_UNITS),
                                                state="readonly", width=6))],
             "leave blank with Divide by users ticked for per-user costs only"),
            ("Avg. utilization %:", [(ttk.Entry, dict(textvariable=self.util_v, width=8, font=mono))],
             "only for the per-GB figures (how full the circuit runs)"),
        ]
        for r, (label, widgets, hint) in enumerate(rows):
            ttk.Label(form, text=label, style="Field.TLabel").grid(row=r, column=0, sticky="e", padx=(0, 8), pady=2)
            cell = ttk.Frame(form)
            cell.grid(row=r, column=1, sticky="w", pady=2)
            for cls, kw in widgets:
                cls(cell, **kw).pack(side="left", padx=(0, 6))
            if hint:
                ttk.Label(cell, text=hint, style="Hint.TLabel").pack(side="left", padx=(4, 0))
        ucell = ttk.Frame(form)
        ucell.grid(row=len(rows), column=1, sticky="w", pady=2)
        ttk.Checkbutton(form, text="Divide by users:", variable=self.users_on_v).grid(
            row=len(rows), column=0, sticky="e", padx=(0, 8))
        ttk.Entry(ucell, textvariable=self.users_v, width=8, font=mono).pack(side="left")
        ttk.Label(ucell, text="users (subscribers) sharing it each month", style="Hint.TLabel").pack(
            side="left", padx=(10, 0))

        self.error_lbl = ttk.Label(self, style="Error.TLabel")
        self.result_title = ttk.Label(self, style="Key.TLabel")
        self.result_title.pack(anchor="w", pady=(10, 2))
        self.grid_frame = ttk.Frame(self)
        self.grid_frame.pack(fill="x")
        self.value_vars = {}
        for r, (key, label) in enumerate(self.FIELDS):
            ttk.Label(self.grid_frame, text=label, style="Key.TLabel").grid(row=r, column=0, sticky="e",
                                                                          padx=(0, 12), pady=1)
            var = tk.StringVar()
            ttk.Entry(self.grid_frame, textvariable=var, state="readonly", font=mono, style="Value.TEntry",
                      width=40).grid(row=r, column=1, sticky="w", pady=1)
            ttk.Button(self.grid_frame, text="Copy", style="Small.TButton",
                       command=lambda v=var: self.app.copy(v.get())).grid(row=r, column=2, padx=(6, 0), pady=1,
                                                                         sticky="w")
            self.value_vars[key] = var

        btns = ttk.Frame(self)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Add to comparison", style="Accent.TButton", command=self.add).pack(side="left")
        self.update_btn = ttk.Button(btns, text="Update selected", command=self.update_selected, state="disabled")
        self.update_btn.pack(side="left", padx=6)
        ttk.Button(btns, text="Copy this quote", style="Small.TButton", command=self.copy_quote).pack(
            side="left", padx=(6, 0))

        ttk.Separator(self).pack(fill="x", pady=10)
        head = ttk.Frame(self)
        head.pack(fill="x")
        self.table_lbl = ttk.Label(head, text="Comparison", style="Title.TLabel")
        self.table_lbl.pack(side="left")
        ttk.Button(head, text="Copy table", style="Small.TButton", command=self.copy_table).pack(side="right")
        ttk.Button(head, text="Clear all", style="Small.TButton", command=self.clear_all).pack(side="right", padx=6)
        ttk.Button(head, text="Remove", style="Small.TButton", command=self.remove_selected).pack(side="right")
        self.tree = make_tree(self, self.COLUMNS, (200, 85, 90, 85, 85, 70, 100, 105, 90, 95, 60, 95, 100, 95, 120))
        self.tree.configure(height=8, selectmode="extended")
        for c in self.COLUMNS[1:-1]:
            self.tree.column(c, anchor="e", stretch=False)
        self.tree.container.pack(fill="both", expand=True, pady=(4, 0))
        make_sortable(self.tree, numeric=("Monthly", "One-time", "Eff. monthly", "Total", "Per Mbps", "Per Gbps",
                                          "Users", "Per user/mo", "Per user/term", "Per GB"))
        self.tree.tag_configure("best", **SWEEP_COLORS["alive"])
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Delete>", lambda e: self.remove_selected())
        self.tree.bind("<BackSpace>", lambda e: self.remove_selected())
        self.saved_lbl = ttk.Label(self, style="Hint.TLabel",
                                   text=f"Saved automatically to {self.path}. Green = lowest cost per Mbps (or per user "
                                        f"when no quote has a bandwidth). "
                                        f"Click a row to load it above; Update selected saves changes.")
        self.saved_lbl.pack(anchor="w", pady=(4, 0))

        self.debounce = Debouncer(self, 150, self.refresh)
        for v in (self.monthly_v, self.nrc_v, self.spread_v, self.term_v, self.term_unit_v, self.bw_v, self.bw_unit_v,
                  self.users_on_v, self.users_v, self.util_v, self.note_v):
            v.trace_add("write", self.debounce)
        self.refresh()
        self.fill_table()

    # ---- inputs / results

    def form(self) -> dict:
        return dict(note=self.note_v.get().strip(), monthly=self.monthly_v.get(), one_time=self.nrc_v.get(),
                    spread=self.spread_v.get(),
                    term=self.term_v.get(), term_unit=self.term_unit_v.get(), bandwidth=self.bw_v.get(),
                    bw_unit=self.bw_unit_v.get(), users_on=self.users_on_v.get(), users=self.users_v.get(),
                    utilization=self.util_v.get())

    @staticmethod
    def quote_from(d: dict) -> "bwcost.Quote":
        num = bwcost.parse_number
        monthly, nrc, term, bw = num(d.get("monthly", "")), num(d.get("one_time", "") or "0"), \
            num(d.get("term", "")), num(d.get("bandwidth", ""))
        util = num(d.get("utilization", "") or "100")
        users = num(d.get("users", "")) if d.get("users_on") else None
        if monthly is None:
            if str(d.get("monthly", "")).strip():
                raise ValueError("The monthly cost must be a number, e.g. 1500.")
            monthly = 0.0                         # blank: one-time (capital) cost only
        if nrc is None:
            raise ValueError("The one-time cost must be a number (0 if none).")
        if term is None:
            raise ValueError("Enter the term, e.g. 36 months or 3 years.")
        if bw is None and (str(d.get("bandwidth", "")).strip() or not d.get("users_on")):
            raise ValueError("Enter the bandwidth, e.g. 10 Gbps (or tick Divide by users and leave it blank "
                             "for per-user costs only).")
        if d.get("users_on") and users is None:
            raise ValueError("Enter the number of users, or untick Divide by users.")
        if util is None:
            raise ValueError("Utilization must be a number between 1 and 100.")
        return bwcost.Quote(monthly=monthly, one_time=nrc, spread_one_time=bool(d.get("spread", True)),
                            term_months=term * bwcost.TERM_UNITS.get(d.get("term_unit", "months"), 1),
                            mbps=bw * bwcost.RATE_UNITS.get(d.get("bw_unit", "Mbps"), 1) if bw is not None else None,
                            users=users,
                            utilization=util)

    def refresh(self):
        try:
            q = self.quote_from(self.form())
            r = bwcost.compute(q)
        except ValueError as exc:
            self.error_lbl.configure(text=str(exc))
            self.error_lbl.pack(anchor="w", pady=(8, 0), before=self.result_title)
            for v in self.value_vars.values():
                v.set("")
            self.result_title.configure(text="")
            return None
        self.error_lbl.pack_forget()
        m = bwcost.money
        what = bwcost.rate(q.mbps) if q.mbps else "Service"
        how = "(spread over the term)" if q.spread_one_time else "(paid up front)"
        if q.monthly:
            title = (f"{what} for {m(q.monthly)}/month over {bwcost.term_text(q.term_months)}"
                     + (f" + {m(q.one_time)} one-time {how}" if q.one_time else ""))
        else:
            title = f"{what}: {m(q.one_time)} one-time over {bwcost.term_text(q.term_months)} {how}"
        if q.users:
            title += f", shared by {q.users:,.0f} users"
        self.result_title.configure(text=title)
        nobw = "– (no bandwidth entered)"
        vals = dict(per_mbps=m(r.per_mbps) if r.per_mbps is not None else nobw,
                    per_gbps=m(r.per_gbps) if r.per_gbps is not None else nobw,
                    effective_monthly=m(r.effective_monthly) + (
                        ("  (monthly + one-time spread over the term)" if q.spread_one_time
                         else "  (monthly only; one-time cost paid up front)") if q.one_time else ""),
                    first_month=m(r.first_month) + ("  (includes the one-time cost)"
                                                    if q.one_time and not q.spread_one_time else ""),
                    annual=m(r.annual), total=m(r.total),
                    per_user=m(r.per_user) if r.per_user is not None else "– (tick Divide by users)",
                    per_user_term=m(r.per_user_term) if r.per_user_term is not None else "–",
                    mbps_per_user=bwcost.rate(r.mbps_per_user) if r.mbps_per_user is not None else "–",
                    gb_per_month=f"{bwcost.volume(r.gb_per_month)} at {q.utilization:g}% average"
                    if r.gb_per_month is not None else nobw,
                    per_gb=m(r.per_gb) if r.per_gb is not None else nobw,
                    per_tb=m(r.per_tb) if r.per_tb is not None else nobw)
        for k, v in vals.items():
            self.value_vars[k].set(v)
        return q, r

    def copy_quote(self):
        out = self.refresh()
        if not out:
            return
        note = self.note_v.get().strip()
        rows = [(label, self.value_vars[k].get()) for k, label in self.FIELDS]
        head = ([note] if note else []) + [self.result_title.cget("text")]
        self.app.copy("\n".join(head) + "\n" + texttable.format_table(None, rows))

    # ---- comparison table (saved to costs.json)

    def load_entries(self) -> list:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def save_entries(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps(self.entries, indent=2), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as exc:
            self.app.flash(f"Couldn't save {self.path.name}: {exc}")

    def row_values(self, d: dict):
        m = bwcost.money
        try:
            q = self.quote_from(d)
            r = bwcost.compute(q)
        except ValueError:
            return None, None
        term = q.term_months
        opt = lambda v: m(v) if v is not None else ""
        return (d.get("note", ""), bwcost.rate(q.mbps) if q.mbps else "", m(q.monthly), m(q.one_time),
                ("Spread" if q.spread_one_time else "Up front") if q.one_time else "",
                f"{int(term) if term == int(term) else term:g} mo", m(r.effective_monthly), m(r.total),
                opt(r.per_mbps), opt(r.per_gbps), f"{q.users:,.0f}" if q.users else "",
                m(r.per_user) if r.per_user is not None else "", m(r.per_user_term) if r.per_user_term is not None
                else "", opt(r.per_gb), d.get("added", "")), r

    def fill_table(self):
        self.tree.delete(*self.tree.get_children())
        best, rows = None, []
        for i, d in enumerate(self.entries):
            vals, r = self.row_values(d)
            if vals is None:
                continue
            rows.append((i, vals, r))
        # green: lowest cost per Mbps; if no quote has a bandwidth, lowest cost per user per month
        key = "per_mbps" if any(r.per_mbps is not None for _, _, r in rows) else "per_user"
        for i, vals, r in rows:
            v = getattr(r, key)
            if v is not None and (best is None or v < best[1]):
                best = (i, v)
        for i, vals, _ in rows:
            self.tree.insert("", "end", iid=str(i), values=vals,
                             tags=("best",) if best and best[0] == i and len(rows) > 1 else ())
        self.table_lbl.configure(text=f"Comparison  ({len(rows)} quote{'s' if len(rows) != 1 else ''})")

    def add(self):
        if not self.refresh():
            return
        d = self.form()
        d["added"] = datetime.now().strftime("%Y-%m-%d %H:%M")
        self.entries.append(d)
        self.save_entries()
        self.fill_table()
        self.tree.selection_set(str(len(self.entries) - 1))
        self.tree.see(str(len(self.entries) - 1))
        self.app.flash(f"Added {d['note'] or 'the quote'} to the comparison (saved to {self.path.name}).")

    def on_select(self, _=None):
        sel = self.tree.selection()
        if len(sel) != 1:
            self.editing = None
            self.update_btn.configure(state="disabled")
            return
        i = int(sel[0])
        d = self.entries[i]
        self.editing = i
        for var, key in ((self.note_v, "note"), (self.monthly_v, "monthly"), (self.nrc_v, "one_time"),
                         (self.term_v, "term"), (self.term_unit_v, "term_unit"), (self.bw_v, "bandwidth"),
                         (self.bw_unit_v, "bw_unit"), (self.users_v, "users"), (self.util_v, "utilization")):
            var.set(d.get(key, ""))
        self.users_on_v.set(bool(d.get("users_on")))
        self.spread_v.set(bool(d.get("spread", True)))
        self.update_btn.configure(state="normal")
        self.refresh()

    def update_selected(self):
        if self.editing is None or self.editing >= len(self.entries) or not self.refresh():
            return
        d = self.form()
        d["added"] = self.entries[self.editing].get("added", "")
        self.entries[self.editing] = d
        self.save_entries()
        keep = str(self.editing)
        self.fill_table()
        self.tree.selection_set(keep)
        self.app.flash("Updated the selected quote (saved).")

    def remove_selected(self):
        sel = sorted((int(i) for i in self.tree.selection()), reverse=True)
        if not sel:
            return
        for i in sel:
            del self.entries[i]
        self.editing = None
        self.update_btn.configure(state="disabled")
        self.save_entries()
        self.fill_table()
        self.app.flash(f"Removed {len(sel)} quote{'s' if len(sel) != 1 else ''}.")

    def clear_all(self):
        if not self.entries:
            return
        from tkinter import messagebox
        if not messagebox.askyesno(APP_NAME, f"Remove all {len(self.entries)} quotes from the comparison?",
                                   parent=self):
            return
        self.entries = []
        self.save_entries()
        self.fill_table()

    def copy_table(self):
        if not self.tree.get_children():
            self.app.flash("Nothing to copy yet. Add a quote first.")
            return
        self.app.copy(f"Bandwidth cost comparison ({datetime.now():%Y-%m-%d})\n\n"
                      + texttable.tree_table(self.tree))

    def settings_dict(self) -> dict:
        return dict(bw_form=self.form())


# --------------------------------------------------------------------------- PeeringDB tab


class PeeringDBTab(ttk.Frame):
    """Networks, exchanges, facilities and organizations from PeeringDB, laid out like peeringdb.com."""

    MAX_TEXT_LINES = 34

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=12)
        self.app = app
        s = app.settings
        self.api_url = s.get("peeringdb_api_url", peeringdb.API_URL)          # override only for testing
        self.client = None
        self.record = None
        self.history = []                    # (kind, value) of earlier records, for Back
        self.current = None
        self.worker = None
        self.links = {}
        self.table_widgets = []

        head = ttk.Frame(self)
        head.pack(fill="x")
        ttk.Label(head, text="PeeringDB", style="Title.TLabel").pack(side="left")
        ttk.Label(head, text="  ASN, network / exchange / facility name, exchange peering IP, or a peeringdb.com link",
                  style="Hint.TLabel").pack(side="left")
        row = ttk.Frame(self)
        row.pack(fill="x", pady=(6, 0))
        self.back_btn = ttk.Button(row, text="◀ Back", command=self.back, state="disabled", width=7)
        self.back_btn.pack(side="left")
        self.query_v = tk.StringVar(value=s.get("peeringdb_query", "AS10279"))
        self.entry = ttk.Entry(row, textvariable=self.query_v, width=44, font=app.mono)
        self.entry.pack(side="left", padx=6)
        self.entry.bind("<Return>", lambda e: self.start())
        self.entry.bind("<KP_Enter>", lambda e: self.start())
        self.go_btn = ttk.Button(row, text="Look up", style="Accent.TButton", command=self.start)
        self.go_btn.pack(side="left")
        link(row, "Get one", lambda: __import__("webbrowser").open(peeringdb.APIKEY_URL),
             style="HintLink.TLabel").pack(side="right")
        self.key_v = tk.StringVar(value=s.get("peeringdb_api_key", ""))
        ttk.Entry(row, textvariable=self.key_v, width=26, show="•").pack(side="right", padx=(4, 6))
        ttk.Label(row, text="API key (optional):").pack(side="right")

        ttk.Separator(self).pack(fill="x", pady=10)
        self.status_lbl = ttk.Label(self, style="Hint.TLabel",
                                    text="Enter an ASN (e.g. 10279), a name, an exchange IP, or a PeeringDB link, "
                                         "and press Look up.")
        self.status_lbl.pack(anchor="w")

        self.result = ttk.Frame(self)
        th = ttk.Frame(self.result)
        th.pack(fill="x", pady=(4, 0))
        self.title_lbl = ttk.Label(th, style="Big.TLabel")
        self.title_lbl.pack(side="left")
        self.sub_lbl = ttk.Label(th, style="Hint.TLabel")
        self.sub_lbl.pack(side="left", padx=(10, 0), pady=(6, 0))
        ttk.Button(th, text="Copy all", style="Small.TButton", command=self.copy_all).pack(side="right")
        self.site_link = link(th, "View on PeeringDB ↗", self.open_site, style="FieldLink.TLabel")
        self.site_link.pack(side="right", padx=10)
        self.note_lbl = ttk.Label(self.result, style="Field.TLabel", wraplength=900, justify="left")
        cols = ttk.Frame(self.result)
        cols.pack(fill="x", pady=(8, 0))
        cols.columnconfigure(0, weight=3, uniform="pdb")
        cols.columnconfigure(1, weight=2, uniform="pdb")
        self.main_text = scrolled_text(cols, app, height=12, width=30, wrap="word")   # grows with the window
        self.main_text.container.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self.side_text = scrolled_text(cols, app, height=12, width=30, wrap="word")   # grows with the window
        self.side_text.container.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        for t in (self.main_text, self.side_text):
            t.configure(state="disabled", cursor="arrow")
            self._text_tags(t)
        self.tables_frame = ttk.Frame(self.result)
        self.tables_frame.pack(fill="both", expand=True)
        ttk.Label(self, text="Data from PeeringDB (peeringdb.com), the freely available interconnection database. "
                             "Double-click a row to open it here; right-click for more.",
                  style="Hint.TLabel").pack(side="bottom", anchor="w", pady=(8, 0))

    # ---- text panes

    def _text_tags(self, t):
        c = self.app.colors
        bold = tkfont.Font(font=self.app.mono)
        bold.configure(weight="bold")
        self._bold = bold
        t.tag_configure("h", font=bold, spacing1=6, spacing3=4)
        t.tag_configure("lbl", foreground=c["muted"])
        t.tag_configure("note", foreground=c["muted"])
        t.tag_configure("link", foreground=c["link"], underline=True)
        t.tag_bind("link", "<Enter>", lambda e, w=t: w.configure(cursor="hand2"))
        t.tag_bind("link", "<Leave>", lambda e, w=t: w.configure(cursor="arrow"))

    def _add_link(self, t, start, end, target):
        tag = f"L{len(self.links)}"
        self.links[tag] = target
        t.tag_add("link", start, end)
        t.tag_add(tag, start, end)
        t.tag_bind(tag, "<Button-1>", lambda e, x=target: self.follow(x))

    def _render_sections(self, t, sections):
        t.configure(state="normal")
        t.delete("1.0", "end")
        cw = self.app.mono.measure("0")
        for n, sec in enumerate(sections):
            if sec.title:
                t.insert("end", ("\n" if n else "") + sec.title + "\n", "h")
            w = max((len(f.label) for f in sec.fields), default=0)
            margin = f"m{w}"
            t.tag_configure(margin, lmargin2=(w + 2) * cw)
            for f in sec.fields:
                lines = f.value.splitlines() or [""]
                t.insert("end", f"{f.label:<{w}}  ", ("lbl", margin))
                for i, line in enumerate(lines):
                    if i:
                        t.insert("end", " " * (w + 2), margin)
                    start = t.index("end-1c")
                    t.insert("end", line, margin)
                    if f.link and line:
                        self._add_link(t, start, t.index("end-1c"), f.link)
                    t.insert("end", "\n", margin)
            if sec.table:
                cols, rows = sec.table
                if rows:
                    start_line = int(t.index("end-1c").split(".")[0])
                    t.insert("end", texttable.format_table(cols, rows) + "\n")
                    self._link_contacts(t, f"{start_line}.0", "end")
                    t.tag_add("lbl", f"{start_line}.0", f"{start_line}.end")
            if sec.note:
                t.insert("end", sec.note + "\n", "note")
        t.delete("end-2c", "end-1c") if t.get("end-2c", "end-1c") == "\n" else None
        t.configure(state="disabled")

    def _link_contacts(self, t, start, end):
        text = t.get(start, end)
        for m in re.finditer(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+|https?://\S+", text):
            a = f"{start}+{m.start()}c"
            self._add_link(t, a, f"{start}+{m.end()}c",
                           m.group(0) if m.group(0).startswith("http") else "mailto:" + m.group(0))

    def _lines(self, t) -> int:
        """Content height in text lines, counting wrapped lines and the headings' extra spacing."""
        t.update_idletasks()
        try:
            px = int(t.count("1.0", "end", "ypixels")[0])
            return -(-px // max(1, self.app.mono.metrics("linespace"))) + 1
        except (tk.TclError, TypeError, IndexError):
            return int(t.index("end-1c").split(".")[0]) + 2

    def _fit_panes(self):
        """Both panes share a row: size them to the longer one's content (unless sized with a grip)."""
        panes = [self.main_text] + ([self.side_text] if self.side_text.container.winfo_manager() else [])
        n = max(3, min(self.MAX_TEXT_LINES, max(self._lines(t) for t in panes)))
        for t in panes:
            sizer = getattr(t, "sizer", None)
            if not (sizer is not None and sizer.user_sized) and int(t.cget("height")) != n:
                t.configure(height=n)

    # ---- tables

    def _build_tables(self, tables):
        for w in self.table_widgets:
            w.destroy()
        self.table_widgets = []
        for tbl in tables:
            box = ttk.Frame(self.tables_frame)
            box.pack(fill="x", pady=(14, 0))
            self.table_widgets.append(box)
            h = ttk.Frame(box)
            h.pack(fill="x")
            ttk.Label(h, text=tbl.title, style="Title.TLabel").pack(side="left")
            ttk.Label(h, text=f"  {len(tbl.rows):,}", style="Hint.TLabel").pack(side="left", pady=(4, 0))
            if tbl.note:
                ttk.Label(h, text="   " + tbl.note, style="Hint.TLabel").pack(side="left", pady=(4, 0))
            widths = tbl.widths or [150] * len(tbl.columns)
            tree = make_tree(box, tbl.columns, widths, sizer=False)
            tree.configure(height=max(2, min(14, len(tbl.rows))), selectmode="extended")
            tree.container.pack(fill="x", pady=(4, 0))
            BoxSizer(self.app, tree.container, [tree])
            ttk.Button(h, text="Copy", style="Small.TButton",
                       command=lambda t=tree: self.app.copy(texttable.tree_table(t))).pack(side="right")
            if not tbl.rows:
                ttk.Label(box, text="None listed.", style="Hint.TLabel").pack(anchor="w")
            targets = {}
            for i, row in enumerate(tbl.rows):
                iid = tree.insert("", "end", values=row)
                targets[iid] = tbl.targets[i] if i < len(tbl.targets) else ""
                if i == tbl.highlight:
                    tree.selection_set(iid)
                    tree.see(iid)
            tree.targets = targets
            tree.spec = tbl
            make_sortable(tree, numeric=tbl.numeric)
            tree.bind("<Double-1>", lambda e, t=tree: self._open_row(t, e))
            tree.bind("<Return>", lambda e, t=tree: self._open_row(t, None))
            tree.bind(self.app.right_click, lambda e, t=tree: self._row_menu(t, e))
            autosize_columns(tree, self.app.mono, max_px=360)

    def _open_row(self, tree, e):
        iid = tree.identify_row(e.y) if e is not None else (tree.focus() or "")
        target = tree.targets.get(iid, "")
        if target:
            self.follow(target)
        return "break"

    def _row_menu(self, tree, e):
        iid = tree.identify_row(e.y)
        if not iid:
            return
        if iid not in tree.selection():
            tree.selection_set(iid)
        values = dict(zip(tree["columns"], tree.item(iid, "values")))
        target = tree.targets.get(iid, "")
        name = str(next(iter(values.values()), ""))
        menu = tk.Menu(self, tearoff=False)
        if target:
            kind, oid = target[4:].split("/", 1)
            menu.add_command(label=f"Open {sendto.preview(name, 40)} here", command=lambda: self.follow(target))
            menu.add_command(label="Open on peeringdb.com",
                             command=lambda: __import__("webbrowser").open(peeringdb.site_url(kind, oid)))
            menu.add_separator()
        asn = str(values.get("ASN", "")).strip()
        if asn.isdigit():
            menu.add_command(label=f"Whois AS{asn}", command=lambda: self.app.send_to("whois", f"AS{asn}"))
            menu.add_command(label=f"IRR / RPKI for AS{asn}", command=lambda: self.app.send_to("irr", f"AS{asn}"))
        for col in ("IPv4", "IPv6"):
            ip = str(values.get(col, "")).strip()
            if ip:
                menu.add_command(label=f"Ping {ip}", command=lambda x=ip: self.app.send_to("ping", x))
                menu.add_command(label=f"Copy {ip}", command=lambda x=ip: self.app.copy(x))
        prefix = str(values.get("Prefix", "")).strip()
        if prefix:
            menu.add_command(label=f"Open {prefix} in IP Calc", command=lambda: self.app.open_in_calculator(prefix))
        rows = texttable.tree_table(tree, tree.selection())
        menu.add_command(label="Copy row" if len(tree.selection()) == 1 else f"Copy {len(tree.selection())} rows",
                         command=lambda: self.app.copy(rows))
        self.app.popup_tree_menu(menu, e)
        return "break"

    # ---- running a lookup

    def follow(self, target: str):
        """A link in the results: pdb:kind/id opens here; anything else opens in the browser / mail app."""
        if target.startswith("pdb:"):
            kind, oid = target[4:].split("/", 1)
            if oid.isdigit():
                self.query_v.set(peeringdb.site_url(kind, oid))
                self.run(kind, int(oid))
            return
        import webbrowser
        webbrowser.open(target)

    def start(self):
        kind, value = peeringdb.classify(self.query_v.get())
        if not kind:
            self.status_lbl.configure(text="Enter an ASN, a name, an exchange IP address, or a PeeringDB link.")
            return "break"
        self.run(kind, value)
        return "break"

    def get_client(self):
        key = self.key_v.get().strip()
        if self.client is None or self.client.api_key != key:
            self.client = peeringdb.Client(api_key=key, base=self.api_url)
        return self.client

    def run(self, kind, value, remember=True):
        if self.worker:
            return
        if remember and self.current and self.current != (kind, value):
            self.history.append(self.current)
        self.pending = (kind, value)
        import queue
        import threading
        self.queue = queue.Queue()
        client, q = self.get_client(), self.queue

        def work():
            try:
                q.put(("done", peeringdb.load(client, kind, value, progress=lambda m: q.put(("status", m)))))
            except peeringdb.PdbError as exc:
                q.put(("error", exc))
            except Exception as exc:                      # never leave the tab stuck
                q.put(("error", peeringdb.PdbError(f"Lookup failed: {exc}")))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()
        self.go_btn.configure(state="disabled")
        self.status_lbl.configure(text="Asking PeeringDB …", style="Hint.TLabel")
        self.after(80, self.poll)

    def poll(self):
        import queue as _q
        while True:
            try:
                kind, data = self.queue.get_nowait()
            except _q.Empty:
                self.after(80, self.poll)
                return
            if kind == "status":
                self.status_lbl.configure(text=data)
                continue
            self.worker = None
            self.go_btn.configure(state="normal")
            if kind == "error":
                if self.history and self.history[-1] == self.current:
                    self.history.pop()                  # nothing new was shown: Back stays where it was
                self.status_lbl.configure(text=str(data), style="Error.TLabel")
            else:
                self.current = self.pending
                self.show_record(data)
            self.back_btn.configure(state="normal" if self.history else "disabled")
            return

    def back(self):
        if self.history and not self.worker:
            kind, value = self.history.pop()
            self.query_v.set(peeringdb.site_url(kind, value) if kind in peeringdb.KINDS else
                             (f"AS{value}" if kind == "asn" else str(value)))
            self.current = None
            self.run(kind, value, remember=False)

    def show_record(self, rec):
        self.record = rec
        self.links = {}
        if not self.result.winfo_ismapped():
            self.result.pack(fill="both", expand=True)
        self.title_lbl.configure(text=rec.title)
        self.sub_lbl.configure(text=rec.subtitle)
        self.site_link.configure(text="View on PeeringDB ↗" if rec.kind != "search" else "Search on PeeringDB ↗")
        if rec.note:
            self.note_lbl.configure(text=rec.note)
            self.note_lbl.pack(anchor="w", pady=(6, 0), after=self.title_lbl.master)
        else:
            self.note_lbl.pack_forget()
        cols = self.main_text.container.master
        if rec.main or rec.side:
            cols.pack(fill="x", pady=(8, 0), before=self.tables_frame)
            self._render_sections(self.main_text, rec.main)
            self._render_sections(self.side_text, rec.side)
            if rec.side:
                self.side_text.container.grid()
            else:
                self.side_text.container.grid_remove()
            self._fit_panes()
            self.after(250, self._fit_panes)       # once the panes have their final width, wrapping may add lines
        else:
            cols.pack_forget()
        self._build_tables(rec.tables)
        calls = self.client.calls if self.client else 0
        what = {"search": "Search results", "net": "Network", "ix": "Exchange", "fac": "Facility",
                "org": "Organization"}.get(rec.kind, "Record")
        self.status_lbl.configure(text=f"{what} from PeeringDB · {calls} API quer{'y' if calls == 1 else 'ies'} "
                                       "this session", style="Hint.TLabel")
        if rec.kind == "search" and len(rec.tables[0].rows) == 1 and rec.tables[0].targets:
            self.current = None                         # one match: open it straight away (Back skips the search)
            self.follow(rec.tables[0].targets[0])

    def open_site(self):
        if self.record and self.record.url:
            import webbrowser
            webbrowser.open(self.record.url)

    def copy_all(self):
        if self.record:
            self.app.copy(peeringdb.record_text(self.record))

    def load(self, text: str) -> str:
        """Send to: pick a PeeringDB link, ASN, or IP out of `text`, or use the first line as a name search."""
        m = re.search(r"(?i)peeringdb\.com/(?:net|ix|fac|org)/\d+", text)
        a = re.search(r"(?i)\bAS\s?(\d{1,10})\b", text)
        ip = sendto.IPV4.search(text) or sendto._first_v6(text)
        if m:
            q = m.group(0)
        elif a:
            q = f"AS{a.group(1)}"
        elif ip:
            q = ip.group(0)
        else:
            q = sendto.first_line(text)
        self.query_v.set(q)
        self.start()
        return q

    def settings_dict(self):
        return {"peeringdb_query": self.query_v.get(), "peeringdb_api_key": self.key_v.get().strip()}



# --------------------------------------------------------------------------- home tab

TOOL_INFO = {
    "calc": "Subnet details for any IPv4 or IPv6 address: network, mask, wildcard, host range, splits, "
            "and a copy-ready subnet summary.",
    "summary": "Collapse a list of subnets, ranges, or IP/mask pairs into the fewest covering prefixes.",
    "bwcost": "Cost per Mbps and Gbps for a circuit quote (monthly, one-time, term, bandwidth), optionally per user, "
              "with a saved table to compare quotes.",
    "bits": "Convert data sizes and rates between bits and bytes, in decimal (kB, MB) and binary (KiB, MiB) units.",
    "tz": "Convert a date and time into any set of time zones around the world, with daylight saving handled.",
    "addtime": "Add or subtract years down to seconds from a date and time, and see the result as a Unix epoch.",
    "mac": "Reformat lists of MAC addresses (3-dot, dash, colon, upper/lower case), find duplicates, and pull "
           "MACs out of any pasted text.",
    "lookup": "Find the vendor for MAC addresses from the IEEE OUI list, and spot multicast and HSRP / VRRP / "
              "GLBP virtual MACs.",
    "dig": "DNS lookups with dig-style output: query any server, or trace a name down from the root servers.",
    "ping": "Ping many hosts at once with live loss and latency stats, a note per host, and a full ping history.",
    "sweep": "Ping every address in a list, range, or subnet and see at a glance which ones are alive.",
    "trace": "Traceroute to a host, with or without name lookups, filling in each hop as it answers.",
    "whois": "Who announces an IP or prefix and who owns an ASN or BGP AS path (Team Cymru, or ARIN and the "
             "other registries), plus domain-name WHOIS.",
    "routes": "Summarise 'show ip route' / 'show route' from IOS, XE, XR, NX-OS, Junos or EOS: routes by "
              "protocol, next hops, recent changes and unusually high metrics.",
    "irr": "Expand an ASN or AS-SET from the IRR (like bgpq4), check every route object against RPKI, and build "
           "prefix filters for IOS-XR, IOS-XE, NX-OS, Junos, Arista EOS, Nokia SR OS or SR Linux.",
    "peeringdb": "Look up a network, exchange, facility or organization in PeeringDB by ASN, name, exchange IP or "
                 "link: peering policy, contacts, exchange ports and facilities, laid out like the website.",
    "compare": "Compare two files or pasted text side by side, as a unified diff, or as the lines unique to each.",
    "logtime": "Find every date and time in a log and convert it to another time zone, right in place.",
}


class HomeTab(ttk.Frame):
    """Start page: every tool with a one-line description, a button to open it, and a favourite star."""

    def __init__(self, master, app: "App"):
        super().__init__(master, padding=16)
        self.app = app
        self.stars = {}

    def build(self):
        app = self.app
        head = ttk.Frame(self)
        head.pack(fill="x")
        try:
            self.logo = tk.PhotoImage(file=str(HERE / "icons" / "bt-icon-64.png"))
            ttk.Label(head, image=self.logo).pack(side="left", padx=(0, 14))
        except tk.TclError:
            self.logo = None
        words = ttk.Frame(head)
        words.pack(side="left", fill="y")
        ttk.Label(words, text=APP_NAME, style="Big.TLabel").pack(anchor="w")
        ttk.Label(words, text=version.TAGLINE,
                  style="Hint.TLabel").pack(anchor="w", pady=(2, 0))
        vrow = ttk.Frame(words)
        vrow.pack(anchor="w", pady=(4, 0))
        ttk.Label(vrow, text=f"Version {version.VERSION}  ·", style="Hint.TLabel").pack(side="left")
        link(vrow, version.WEBSITE_LABEL, app.open_website).pack(side="left", padx=(4, 0))
        ttk.Label(vrow, text="·", style="Hint.TLabel").pack(side="left", padx=(4, 0))
        link(vrow, "Help", app.open_help).pack(side="left", padx=(4, 0))
        intro = ttk.Label(self, style="Hint.TLabel", wraplength=1000, width=1,
                  text="Click a tool's name to open it in a tab; it stays open until you close it with the × on "
                       "the tab. ★ marks a favorite: favorites open as tabs every time the app starts. Click the "
                       "star to add or remove one. Every tool is also in the ☰ Tools menu.")
        intro.pack(anchor="w", fill="x", pady=(12, 0))
        intro.bind("<Configure>", self._rewrap)

        group = None
        grid = None
        n = 0
        for key, label, grp, _ in app.tools:
            if key == "home":
                continue
            if grp != group:
                group = grp
                ttk.Label(self, text=grp, style="Title.TLabel").pack(anchor="w", pady=(16, 4))
                grid = ttk.Frame(self)
                grid.pack(fill="x")
                grid.columnconfigure(0, weight=1, uniform="card")
                grid.columnconfigure(1, weight=1, uniform="card")
                n = 0
            card = ttk.Frame(grid, padding=(12, 8), relief="groove", borderwidth=1)
            card.grid(row=n // 2, column=n % 2, sticky="nsew", padx=(0 if n % 2 == 0 else 6, 6 if n % 2 == 0 else 0),
                      pady=3)
            n += 1
            top = ttk.Frame(card)
            top.pack(fill="x")
            ttk.Button(top, text=label, style="Accent.TButton",
                       command=lambda k=key: app.show(k)).pack(side="left")
            star = ttk.Button(top, style="Small.TButton", width=3, command=lambda k=key: app.toggle_favorite(k))
            star.pack(side="right")
            self.stars[key] = star
            desc = ttk.Label(card, text=TOOL_INFO.get(key, ""), wraplength=470, justify="left", width=1)  # width=1: never widens the page
            desc.pack(anchor="w", fill="x", pady=(6, 0))
            desc.bind("<Configure>", self._rewrap)
            for w in (card, desc):
                w.bind("<Double-1>", lambda e, k=key: app.show(k))
        mod = "⌘" if app.is_mac else "Ctrl+"
        ttk.Label(self, style="Hint.TLabel",
                  text=f"Shortcuts: {mod}1–9 jumps to a tab · {mod}W closes the tab · {mod}L goes to IP Calc · Tools → Text size and "
                       f"Appearance change how the app looks.").pack(anchor="w", pady=(16, 0))
        self.refresh_stars()

    @staticmethod
    def _rewrap(e):
        """Wrap a description to its width, in 24 px steps, so resizing can't bounce back and forth."""
        w = max(200, e.width - 4)
        w -= w % 24
        try:
            cur = int(float(str(e.widget.cget("wraplength")) or 0))
        except ValueError:
            cur = 0
        if abs(cur - w) >= 24:
            e.widget.configure(wraplength=w)

    def refresh_stars(self):
        for key, btn in self.stars.items():
            fav = key in self.app.favorites
            btn.configure(text="★" if fav else "☆")


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.settings = load_settings()
        self.local_zone = core.local_timezone_name() if core.timezone_support() is None else "local time"
        ws = root.tk.call("tk", "windowingsystem")
        self.is_mac = ws == "aqua"
        mod = "Command" if self.is_mac else "Control"
        self.tk_version = tuple(int(n) for n in re.findall(r"\d+", str(root.tk.call("info", "patchlevel")))[:2])
        # Right button: <Button-2> on macOS with Tk 8.6, <Button-3> everywhere else (Tk 8.7+ fixed macOS).
        self.right_click = "<Button-2>" if self.is_mac and self.tk_version < (8, 7) else "<Button-3>"

        root.title(APP_NAME)
        height = min(900, root.winfo_screenheight() - 120)
        width = min(1040, root.winfo_screenwidth() - 80)
        root.geometry(self.settings.get("geometry", f"{width}x{height}"))
        root.minsize(560, 360)
        self._set_icon()
        self._style(ws)

        bar = ttk.Frame(root, style="Chrome.TFrame")
        bar.pack(fill="x", padx=8, pady=(8, 0))
        self.tools_menu = tk.Menu(root, tearoff=False, postcommand=self._fill_tools_menu)
        self.fav_menu = tk.Menu(self.tools_menu, tearoff=False)
        if self.logo_small:                          # BT mark on its own, left of the Tools menu
            self.logo_lbl = ttk.Label(bar, image=self.logo_small, style="Chrome.TLabel")
            self.logo_lbl.pack(side="left", padx=(0, 8))
        self.tools_btn = ttk.Menubutton(bar, text="☰  Tools", menu=self.tools_menu, style="Tools.TMenubutton")
        self.tools_btn.pack(side="left")
        self.star_btn = ttk.Button(bar, style="Small.TButton", command=self.toggle_favorite)
        self.star_btn.pack(side="left", padx=(8, 0))
        ttk.Label(bar, style="ChromeHint.TLabel",
                  text=f"Tabs stay open until you close them (hover a tab for its ×) · favorites open at every "
                       f"launch · drag to reorder · right-click a tab for options").pack(side="left", padx=(10, 0))
        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=8, pady=(6, 8))
        self.notebook = nb
        self.home_page = ScrollPage(nb)
        self.calc_page = ScrollPage(nb)
        self.summary_page = ScrollPage(nb)
        self.bits_page = ScrollPage(nb)
        self.tz_page = ScrollPage(nb)
        self.addtime_page = ScrollPage(nb)
        self.mac_page = ScrollPage(nb)
        self.lookup_page = ScrollPage(nb)
        self.dig_page = ScrollPage(nb)
        self.trace_page = ScrollPage(nb)
        self.ping_page = ScrollPage(nb)
        self.sweep_page = ScrollPage(nb)
        self.whois_page = ScrollPage(nb)
        self.routes_page = ScrollPage(nb)
        self.irr_page = ScrollPage(nb)
        self.pdb_page = ScrollPage(nb)
        self.bwcost_page = ScrollPage(nb)
        self.compare_page = ScrollPage(nb)
        self.logtime_page = ScrollPage(nb)
        self.home = HomeTab(self.home_page.body, self)
        self.calc = CalculatorTab(self.calc_page.body, self)
        self.summary = SummarizeTab(self.summary_page.body, self)
        self.bits = BitsTab(self.bits_page.body, self)
        self.tz = TimeZoneTab(self.tz_page.body, self)
        self.addtime = AddTimeTab(self.addtime_page.body, self)
        self.mac = MacTab(self.mac_page.body, self)
        self.lookup = MacLookupTab(self.lookup_page.body, self)
        self.dig = DigTab(self.dig_page.body, self)
        self.trace = TracerouteTab(self.trace_page.body, self)
        self.ping = PingTab(self.ping_page.body, self)
        self.sweep = SweepTab(self.sweep_page.body, self)
        self.whois = WhoisTab(self.whois_page.body, self)
        self.routes = RouteTableTab(self.routes_page.body, self)
        self.irr = IrrTab(self.irr_page.body, self)
        self.pdb = PeeringDBTab(self.pdb_page.body, self)
        self.bwcost = BandwidthCostTab(self.bwcost_page.body, self)
        self.compare = CompareTab(self.compare_page.body, self)
        self.logtime = LogTimeTab(self.logtime_page.body, self)
        self.calc.pack(fill="both", expand=True)
        self.summary.pack(fill="both", expand=True)
        self.bits.pack(fill="both", expand=True)
        self.tz.pack(fill="both", expand=True)
        self.addtime.pack(fill="both", expand=True)
        self.mac.pack(fill="both", expand=True)
        self.lookup.pack(fill="both", expand=True)
        self.dig.pack(fill="both", expand=True)
        self.trace.pack(fill="both", expand=True)
        self.ping.pack(fill="both", expand=True)
        self.sweep.pack(fill="both", expand=True)
        self.whois.pack(fill="both", expand=True)
        self.routes.pack(fill="both", expand=True)
        self.irr.pack(fill="both", expand=True)
        self.pdb.pack(fill="both", expand=True)
        self.bwcost.pack(fill="both", expand=True)
        self.compare.pack(fill="both", expand=True)
        self.logtime.pack(fill="both", expand=True)
        self.home.pack(fill="both", expand=True)
        # (key, menu/tab label, menu group, page) — the order here is the default favourites order
        self.tools = [
            ("home", "Home", "Start", self.home_page),
            ("calc", "IP Calc", "IP", self.calc_page),
            ("summary", "IP Summarize", "IP", self.summary_page),
            ("bits", "Bits & Bytes", "IP", self.bits_page),
            ("bwcost", "Bandwidth Cost", "IP", self.bwcost_page),
            ("tz", "Time Zones", "Time", self.tz_page),
            ("addtime", "Time Calc", "Time", self.addtime_page),
            ("mac", "MAC Format", "MAC", self.mac_page),
            ("lookup", "MAC Lookup", "MAC", self.lookup_page),
            ("dig", "DNS Digr", "Network", self.dig_page),
            ("ping", "Ping", "Network", self.ping_page),
            ("sweep", "Ping Sweep", "Network", self.sweep_page),
            ("trace", "Traceroute", "Network", self.trace_page),
            ("whois", "Whois", "Network", self.whois_page),
            ("routes", "Route Table", "Network", self.routes_page),
            ("irr", "IRR / RPKI", "Network", self.irr_page),
            ("peeringdb", "PeeringDB", "Network", self.pdb_page),
            ("compare", "Compare", "Text & logs", self.compare_page),
            ("logtime", "Log Times", "Text & logs", self.logtime_page),
        ]
        self.label_of = {k: label for k, label, _, _ in self.tools}
        self.page_of = {k: page for k, _, _, page in self.tools}
        self.key_of = {str(page): k for k, _, _, page in self.tools}
        saved = self.settings.get("favorites")
        keys = [t[0] for t in self.tools]
        self.favorites = [k for k in saved if k in self.page_of] if isinstance(saved, list) else list(keys)
        # Tools added in a newer version show up as favorites once, next to their neighbour.
        known = self.settings.get("known_tools", [k for k in keys if k not in ("sweep", "home")])
        for i, k in enumerate(keys):
            if k not in known and k not in self.favorites:
                prev = keys[i - 1] if i else None
                pos = (self.favorites.index(prev) + 1 if prev in self.favorites
                       else 0 if prev is None else len(self.favorites))
                self.favorites.insert(pos, k)
        # Favorites are the tabs that open at every launch; anything else you open stays until you close it.
        self.opened = []                    # non-favorite tabs open this session, in order
        self.closed_favs = set()            # favorites closed this session (back at the next launch)
        last = self.settings.get("last_tool")
        self.current = last if last in self.favorites else (self.favorites[0] if self.favorites else "home")
        self.open_tab(self.current)
        self._rebuilding = False
        self._drag = None
        self.home.build()
        self._install_text_menus()
        self._install_text_repaint()
        self.rebuild_tabs()
        nb.bind("<<NotebookTabChanged>>", self._tab_changed)
        nb.bind("<<NotebookTabChanged>>", self._tab_shown, add="+")
        self.root.after(1000, self._tab_shown)     # in case the app opened on MAC Lookup
        nb.bind(self.right_click, self._tab_menu)
        nb.bind("<ButtonPress-1>", self._drag_start, add="+")
        nb.bind("<B1-Motion>", self._drag_move, add="+")
        nb.bind("<ButtonRelease-1>", self._drag_end, add="+")
        if self.right_click != "<Button-2>":
            nb.bind("<Button-2>", self._middle_close, add="+")        # middle-click closes, like a browser
        self._closing = None
        self._bind_mousewheel()
        self._fit_tabs()

        self.status = ttk.Label(root, style="ChromeHint.TLabel", anchor="w")
        self.status.pack(fill="x", padx=14, pady=(0, 6))

        root.bind_all(f"<{mod}-bracketleft>", lambda e: self.calc.go_back())
        root.bind_all(f"<{mod}-l>", lambda e: (self.show("calc"), self.calc.entry.focus_set(),
                                               self.calc.entry.select_range(0, "end")))
        for n in range(1, 10):
            root.bind_all(f"<{mod}-Key-{n}>", lambda e, n=n: self.show_nth(n))
        root.bind_all(f"<{mod}-w>", lambda e: self.close_tab())
        root.bind_all(f"<{mod}-comma>", lambda e: self.edit_settings())
        root.bind_all("<F1>", lambda e: self.open_help())
        if self.is_mac:
            try:                                  # app menu → Settings… (⌘,) on macOS
                root.createcommand("tk::mac::ShowPreferences", self.edit_settings)
                root.createcommand("tk::mac::ShowHelp", self.open_help)        # Help menu → Brian's Tools Help
                root.createcommand("tkAboutDialog", self.show_about)          # app menu → About Brian's Tools
            except tk.TclError:
                pass
        self.restart_requested = False
        self._saved_mtime = None
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(3000, self._watch_system_theme)
        if self.current == "calc":
            self.calc.entry.focus_set()

    # ---- navigation: Tools menu + favourite tabs

    def _tab_shown(self, _=None):
        """Let a tool react to being opened (MAC Lookup fetches oui.txt on first use)."""
        def check():
            if not self._rebuilding and self.key_of.get(str(self.notebook.select())) == "lookup":
                self.lookup.on_shown()
        self.root.after(300, check)

    def tab_keys(self) -> list:
        """Open tabs in order: favorites (pinned, reopen at every launch) then tools opened this session."""
        return [k for k in self.favorites if k not in self.closed_favs] + \
               [k for k in self.opened if k not in self.favorites]

    def rebuild_tabs(self):
        """Make the notebook show exactly tab_keys(), in order, with the current tool selected."""
        nb = self.notebook
        want = self.tab_keys()
        if self.current not in want:                     # shouldn't happen; keep the current tool visible
            self.opened.append(self.current)
            want.append(self.current)
        self._rebuilding = True
        try:
            for tab in nb.tabs():
                if self.key_of.get(str(tab)) not in want:
                    nb.forget(tab)
            for i, k in enumerate(want):
                page = self.page_of[k]
                managed = [str(t) for t in nb.tabs()]
                if str(page) in managed:
                    if managed.index(str(page)) != i:
                        nb.insert(i, page)
                else:
                    nb.insert(i if i < len(managed) else "end", page, text=self.tab_text(k))
            nb.select(self.page_of[self.current])
            for k in want:
                if getattr(self, "badges", {}).get(k, (0, None))[0]:
                    self._apply_badge(k)
        finally:
            self._rebuilding = False
        self.update_star()
        if hasattr(self, "home"):
            self.home.refresh_stars()
        self._fit_tabs()

    # status colours for tab badges, readable on both the tab and the selected-tab backgrounds
    BADGE_COLORS = {False: {"good": "#15803d", "loss": "#ca8a04", "down": "#dc2626"},
                    True: {"good": "#4ade80", "loss": "#fbbf24", "down": "#f87171"}}

    def tab_text(self, key: str) -> str:
        """Tab label; a count drawn as a coloured badge image when the tool reports one, e.g. Ping (3)."""
        n, _ = getattr(self, "badges", {}).get(key, (0, None))
        if n and not getattr(self, "_badge_imgs", {}).get(key):
            return f"{self.label_of[key]} ({n})"              # (text fallback if the image couldn't be made)
        return self.label_of[key]

    def set_badge(self, key: str, n: int, status: str = None):
        """Show '(n)' after a tab's label, n coloured by status: good (green), loss (yellow), down (red),
        or None (the label colour, e.g. no replies yet)."""
        if not hasattr(self, "badges"):
            self.badges = {}
        if self.badges.get(key) == (n, status):
            return
        self.badges[key] = (n, status)
        self._apply_badge(key)

    def _apply_badge(self, key: str):
        page = getattr(self, "page_of", {}).get(key)           # (not built yet while tools start up)
        if page is None or str(page) not in [str(t) for t in self.notebook.tabs()]:
            return
        if not hasattr(self, "_badge_imgs"):
            self._badge_imgs = {}
        n, status = self.badges.get(key, (0, None))
        if not n:
            self._badge_imgs.pop(key, None)
            self.notebook.tab(page, text=self.label_of[key], image="")
            return
        c = self.colors
        label_fg = c["fg"]
        color = self.BADGE_COLORS[bool(self.dark)].get(status, label_fg)
        try:
            height = tkfont.nametofont("TkDefaultFont").metrics("linespace")
            img = tk.PhotoImage(master=self.root, data=badge.count_badge(n, color, label_fg, height))
        except (tk.TclError, ValueError):
            img = None
        self._badge_imgs[key] = img
        if img is None:
            self.notebook.tab(page, text=self.tab_text(key), image="")
        else:
            self.notebook.tab(page, text=self.label_of[key], image=img, compound="right")

    def _apply_all_badges(self):
        for key in list(getattr(self, "badges", {})):
            self._apply_badge(key)

    def open_tab(self, key: str):
        """Make sure `key` has a tab (without selecting it)."""
        if key in self.favorites:
            self.closed_favs.discard(key)
        elif key not in self.opened:
            self.opened.append(key)

    def show(self, key_or_page):
        """Open a tool. Its tab stays open until you close it."""
        key = key_or_page if isinstance(key_or_page, str) else self.key_of[str(key_or_page)]
        self.open_tab(key)
        self.current = key
        self.rebuild_tabs()

    def close_tab(self, key: str = None):
        """Close a tab. A favorite only closes for this session; it's back at the next launch."""
        key = key or self.current
        tabs = self.tab_keys()
        if key not in tabs:
            return
        i = tabs.index(key)
        if key in self.favorites:
            self.closed_favs.add(key)
        if key in self.opened:
            self.opened.remove(key)
        rest = self.tab_keys()
        if key == self.current:
            if rest:
                self.current = rest[min(i, len(rest) - 1)]     # the tab that slid into its place
            else:
                self.current = "home"                          # never leave the window empty
                self.open_tab("home")
        self.rebuild_tabs()
        if key in self.favorites:
            self.flash(f"Closed {self.label_of[key]}. It's a favorite, so it opens again next launch.")

    def close_other_tabs(self, key: str):
        for k in self.tab_keys():
            if k != key:
                if k in self.favorites:
                    self.closed_favs.add(k)
                elif k in self.opened:
                    self.opened.remove(k)
        self.current = key
        self.rebuild_tabs()

    def close_non_favorites(self):
        self.opened = []
        if self.current not in self.favorites or self.current in self.closed_favs:
            keys = self.tab_keys()
            self.current = keys[0] if keys else "home"
            self.open_tab(self.current)
        self.rebuild_tabs()

    def show_nth(self, n: int):
        tabs = self.notebook.tabs()
        if 0 < n <= len(tabs):
            self.show(self.key_of[str(tabs[n - 1])])

    def _tab_changed(self, _=None):
        if self._rebuilding:
            return
        key = self.key_of.get(str(self.notebook.select()))
        if key and key != self.current:
            self.current = key
            self.update_star()

    def is_favorite(self, key=None) -> bool:
        return (key or self.current) in self.favorites

    def toggle_favorite(self, key=None):
        """Favorites are the tabs that open at every launch. Un-favoriting leaves the tab open for now."""
        key = key or self.current
        visible = key in self.tab_keys()
        if key in self.favorites:
            self.favorites.remove(key)
            self.closed_favs.discard(key)
            if visible and key not in self.opened:
                self.opened.insert(0, key)                # stays open, now as an ordinary tab
            self.flash(f"Removed {self.label_of[key]} from favorites. It won't open at launch.")
        else:
            self.favorites.append(key)
            if key in self.opened:
                self.opened.remove(key)
            self.closed_favs.discard(key)                 # a new favorite gets its tab straight away
            self.flash(f"Added {self.label_of[key]} to favorites. It opens at every launch.")
        self.rebuild_tabs()

    def set_favorites(self, keys):
        """Replace the favorites. Every favorite gets a tab; tabs that stop being favorites stay open."""
        visible = self.tab_keys()
        self.favorites = [k for k in keys if k in self.page_of]
        self.closed_favs = set()
        self.opened = [k for k in visible if k not in self.favorites]
        self.rebuild_tabs()

    def move_tab(self, key, delta=None, to=None):
        """Reorder within its own group (favorites first, then the other open tabs)."""
        group = self.favorites if key in self.favorites else self.opened
        if key not in group:
            return
        shown = [k for k in group if k in self.tab_keys()]
        i = shown.index(key)
        j = to if to is not None else max(0, min(len(shown) - 1, i + delta))
        if i == j:
            return
        target = shown[j]
        group.remove(key)
        group.insert(group.index(target) + (1 if j > i else 0), key)
        self.rebuild_tabs()

    move_favorite = move_tab                              # older name

    def update_star(self):
        if self.is_favorite():
            self.star_btn.configure(text=f"★ {self.label_of[self.current]} is a favorite")
        else:
            self.star_btn.configure(text=f"☆ Make {self.label_of[self.current]} a favorite")

    def _fill_tools_menu(self):
        m = self.tools_menu
        m.delete(0, "end")
        self._current_v = tk.StringVar(value=self.current)
        group = None
        for key, label, grp, _ in self.tools:
            if grp != group:
                if group is not None:
                    m.add_separator()
                m.add_command(label=grp.upper(), state="disabled")
                group = grp
            m.add_radiobutton(label=f"   {label}", variable=self._current_v, value=key,
                              accelerator="★" if key in self.favorites else "",
                              command=lambda k=key: self.show(k))
        m.add_separator()
        cur = self.label_of[self.current]
        m.add_command(label=f"Remove {cur} from favorites" if self.is_favorite() else f"Add {cur} to favorites",
                      command=self.toggle_favorite)
        f = self.fav_menu
        f.delete(0, "end")
        self._fav_vars = {}
        for key, label, _, _ in self.tools:
            v = tk.BooleanVar(value=key in self.favorites)
            self._fav_vars[key] = v
            f.add_checkbutton(label=label, variable=v, command=lambda k=key: self.toggle_favorite(k))
        f.add_separator()
        f.add_command(label="Make every tool a favorite", command=lambda: self.set_favorites([t[0] for t in self.tools]))
        f.add_command(label="Clear all favorites", command=lambda: self.set_favorites([]))
        m.add_cascade(label="Favorites (open at launch)", menu=f)
        m.add_command(label="Close tab", accelerator=f"{'⌘' if self.is_mac else 'Ctrl+'}W", command=self.close_tab)
        m.add_command(label="Close all tabs that aren't favorites", command=self.close_non_favorites,
                      state="normal" if any(k not in self.favorites for k in self.tab_keys()) else "disabled")
        ts = tk.Menu(m, tearoff=False)
        self._size_v = tk.StringVar(value=self.text_size)
        for key, label, _ in self.TEXT_SIZES:
            ts.add_radiobutton(label=label, variable=self._size_v, value=key,
                               command=lambda k=key: self.apply_text_size(k))
        m.add_cascade(label="Text size", menu=ts)
        ap = tk.Menu(m, tearoff=False)
        self._appearance_v = tk.StringVar(value=self.appearance)
        for key, label in APPEARANCES:
            ap.add_radiobutton(label=label, variable=self._appearance_v, value=key,
                               command=lambda k=key: self.set_appearance(k))
        m.add_cascade(label="Appearance", menu=ap)
        st = tk.Menu(m, tearoff=False)
        st.add_command(label="Edit settings…", accelerator=f"{'⌘' if self.is_mac else 'Ctrl+'},",
                       command=self.edit_settings)
        st.add_command(label="Open settings.json in text editor", command=self.open_settings_external)
        st.add_command(label=f"Show settings folder", command=self.show_settings_folder)
        st.add_separator()
        st.add_command(label="Reset all settings…", command=self.reset_settings)
        m.add_cascade(label="Settings", menu=st)
        m.add_separator()
        m.add_command(label=f"{APP_NAME} Help", accelerator="F1", command=self.open_help)
        m.add_command(label=f"Website: {version.WEBSITE_LABEL}", command=self.open_website)
        m.add_command(label=f"About {APP_NAME}", command=self.show_about)

    def _tab_at(self, event):
        try:
            idx = self.notebook.index(f"@{event.x},{event.y}")
        except tk.TclError:
            return None
        tabs = self.notebook.tabs()
        return self.key_of.get(str(tabs[idx])) if 0 <= idx < len(tabs) else None

    def _on_close_x(self, event) -> bool:
        try:
            return "close" in str(self.notebook.identify(event.x, event.y))
        except tk.TclError:
            return False

    def _tab_menu(self, event):
        key = self._tab_at(event)
        if not key:
            return
        label = self.label_of[key]
        mod = "⌘" if self.is_mac else "Ctrl+"
        menu = tk.Menu(self.root, tearoff=False)
        menu.add_command(label=f"Close {label}", accelerator=f"{mod}W" if key == self.current else "",
                         command=lambda: self.close_tab(key))
        menu.add_command(label="Close other tabs", command=lambda: self.close_other_tabs(key),
                         state="normal" if len(self.tab_keys()) > 1 else "disabled")
        menu.add_separator()
        if key in self.favorites:
            menu.add_command(label=f"Remove {label} from favorites", command=lambda: self.toggle_favorite(key))
        else:
            menu.add_command(label=f"Make {label} a favorite (open at launch)",
                             command=lambda: self.toggle_favorite(key))
        group = [k for k in (self.favorites if key in self.favorites else self.opened) if k in self.tab_keys()]
        i = group.index(key) if key in group else 0
        menu.add_separator()
        menu.add_command(label="Move left", command=lambda: self.move_tab(key, -1),
                         state="normal" if i > 0 else "disabled")
        menu.add_command(label="Move right", command=lambda: self.move_tab(key, 1),
                         state="normal" if i < len(group) - 1 else "disabled")
        menu.tk_popup(event.x_root, event.y_root)

    def _drag_start(self, event):
        self._drag = None
        if self._on_close_x(event):                      # press on × : close on release, don't select
            self._closing = self._tab_at(event)
            return "break"
        self._closing = None
        self._drag = self._tab_at(event)

    def _drag_end(self, event):
        closing, self._closing, self._drag = getattr(self, "_closing", None), None, None
        if closing and self._on_close_x(event) and self._tab_at(event) == closing:
            self.close_tab(closing)
            return "break"

    def _middle_close(self, event):
        key = self._tab_at(event)
        if key:
            self.close_tab(key)

    def _drag_move(self, event):
        key = self._drag
        if not key:
            return
        over = self._tab_at(event)
        same = (key in self.favorites) == (over in self.favorites)
        if over and over != key and same:
            group = [k for k in (self.favorites if key in self.favorites else self.opened) if k in self.tab_keys()]
            self.move_tab(key, to=group.index(over))      # take the hovered tab's place

    # ---- the × on each tab (shown when the pointer is over the tab)

    @staticmethod
    def _x_png(size: int, rgb: str) -> str:
        """A small anti-aliased × as base64 PNG (transparent background)."""
        import base64, struct, zlib
        r, g, b = (int(rgb[i:i + 2], 16) for i in (1, 3, 5))
        m = size * 0.28                      # margin
        half = max(0.75, size / 14)          # half stroke width
        rows = []
        for y in range(size):
            row = bytearray([0])
            for x in range(size):
                px, py = x + 0.5, y + 0.5
                d = 1e9
                for (x0, y0, x1, y1) in ((m, m, size - m, size - m), (m, size - m, size - m, m)):
                    dx, dy = x1 - x0, y1 - y0
                    t = max(0.0, min(1.0, ((px - x0) * dx + (py - y0) * dy) / (dx * dx + dy * dy)))
                    d = min(d, ((px - x0 - t * dx) ** 2 + (py - y0 - t * dy) ** 2) ** 0.5)
                a = max(0.0, min(1.0, half + 0.5 - d))
                row += bytes((r, g, b, int(a * 255)))
            rows.append(bytes(row))

        def chunk(kind, data):
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
               + chunk(b"IDAT", zlib.compress(b"".join(rows))) + chunk(b"IEND", b""))
        return base64.b64encode(png).decode()

    def _x_size(self) -> int:
        try:
            return max(10, int(tkfont.nametofont("TkDefaultFont").metrics("linespace") * 0.7))
        except tk.TclError:
            return 12

    def _update_close_x(self):
        """Create (once) or recolour/resize the tab × images and add the × to the tab layout."""
        c = getattr(self, "colors", None) or LIGHT_COLORS
        size = self._x_size()
        x = self._x_png(size, c["muted"])
        if not hasattr(self, "_x_imgs"):
            self._x_imgs = (tk.PhotoImage(master=self.root, width=size, height=size),     # blank: keeps tab widths
                            tk.PhotoImage(master=self.root, data=x))
            st = ttk.Style(self.root)
            try:
                st.element_create("Notebook.close", "image", self._x_imgs[0],
                                  ("active", "!disabled", self._x_imgs[1]), sticky="", padding=(8, 0, 0, 0))
            except tk.TclError:
                pass                                      # already there (second App in tests)
            st.layout("TNotebook.Tab", [("Notebook.tab", {"sticky": "nswe", "children": [
                ("Notebook.padding", {"side": "top", "sticky": "nswe", "children": [
                    ("Notebook.focus", {"side": "left", "sticky": "nswe", "children": [
                        ("Notebook.label", {"side": "top", "sticky": ""})]}),
                    ("Notebook.close", {"side": "left", "sticky": ""})]})]})])
        else:
            self._x_imgs[0].blank()
            self._x_imgs[0].configure(width=size, height=size)
            self._x_imgs[1].configure(data=x)

    def _fit_tabs(self):
        """Widen the window (if the screen allows) so every tab label shows in full."""
        self.root.update_idletasks()
        need = self.notebook.winfo_reqwidth() + 16
        m = re.match(r"(\d+)x(\d+)(.*)", self.root.geometry())
        if m and int(m.group(1)) < need:
            width = min(need, self.root.winfo_screenwidth() - 40)
            self.root.geometry(f"{width}x{m.group(2)}{m.group(3) if 'geometry' in self.settings else ''}")

    def _bind_mousewheel(self):
        """Wheel / trackpad scrolls whatever is under the pointer: a text box or table that has its own
        scrolling to do, otherwise the page. Handles every Tk flavour:
          * Tk 8.6 on macOS: <MouseWheel> with small whole-number deltas (wheel and trackpad);
          * Windows, and Tk 8.7 / 9 everywhere: <MouseWheel> deltas in multiples of 120;
          * Tk 8.7 / 9 on macOS: trackpads send <TouchpadScroll> (pixel deltas), not <MouseWheel>;
          * X11: buttons 4 / 5 (and Shift for sideways).
        Tk's own per-widget wheel bindings are removed so each scroll happens exactly once."""
        debug = bool(os.environ.get("BRIANSTOOLS_DEBUG_WHEEL"))
        self._tp_acc = [0.0, 0.0]                      # trackpad pixels not yet turned into scroll steps

        def target(event):
            widget = self.root.winfo_containing(event.x_root, event.y_root)
            if widget is None or widget.winfo_class() in ("TSpinbox", "TCombobox"):
                return None
            return widget

        def on_wheel(event):
            widget = target(event)
            if event.num == 4:
                units, notch = -1, True
            elif event.num == 5:
                units, notch = 1, True
            elif abs(event.delta) >= 120:               # Windows; Tk 8.7+ on every platform
                units, notch = -round(event.delta / 120), True
            elif self.is_mac:                           # Tk 8.6 on macOS: already in steps
                units, notch = -event.delta, False
            else:                                       # fine-grained Windows touchpads
                units, notch = (-1 if event.delta > 0 else 1 if event.delta < 0 else 0), False
            horizontal = bool(event.state & 0x0001)     # Shift + wheel (also sideways swipes on macOS)
            if debug:
                print(f"wheel num={event.num} delta={event.delta} state={event.state} -> units={units} "
                      f"over={widget.winfo_class() if widget else None}", file=sys.stderr)
            if widget is not None and units:
                self._scroll_at(widget, units, horizontal, notch)

        def on_touchpad(event):                         # Tk 8.7 / 9 on macOS
            widget = target(event)
            d = int(event.delta)
            dx, dy = (d >> 16) & 0xFFFF, d & 0xFFFF
            dx, dy = (dx - 0x10000 if dx & 0x8000 else dx), (dy - 0x10000 if dy & 0x8000 else dy)
            horizontal = abs(dx) > abs(dy)
            i = 0 if horizontal else 1
            self._tp_acc[i] -= dx if horizontal else dy
            self._tp_acc[1 - i] = 0.0
            units = int(self._tp_acc[i] / 12)           # one step per ~12 px of finger movement
            if debug:
                print(f"touchpad dx={dx} dy={dy} -> units={units} over={widget.winfo_class() if widget else None}",
                      file=sys.stderr)
            if units:
                self._tp_acc[i] -= units * 12
                if widget is not None:
                    self._scroll_at(widget, units, horizontal, False)

        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>", "<Shift-MouseWheel>", "<Shift-Button-4>",
                    "<Shift-Button-5>", "<TouchpadScroll>", "<Shift-TouchpadScroll>"):
            for cls in ("TScrollbar", "Scrollbar", "Text", "Treeview", "Listbox", "Canvas", "TEntry", "Entry"):
                try:
                    self.root.bind_class(cls, seq, "")
                except tk.TclError:
                    pass                                # <TouchpadScroll> doesn't exist before Tk 8.7
        self.root.bind_class("Text", "<<Selection>>", lambda e: e.widget.tag_raise("sel"), add="+")
        for seq in ("<MouseWheel>", "<Shift-MouseWheel>", "<Button-4>", "<Button-5>", "<Shift-Button-4>",
                    "<Shift-Button-5>"):
            self.root.bind_all(seq, on_wheel, add="+")
        self._on_wheel, self._on_touchpad = on_wheel, on_touchpad      # (for tests)
        for seq in ("<TouchpadScroll>", "<Shift-TouchpadScroll>"):
            try:
                self.root.bind_all(seq, on_touchpad, add="+")
            except tk.TclError:
                pass

    def _scroll_at(self, widget, units: int, horizontal: bool, notch: bool):
        """Scroll the box under the pointer if it has somewhere to go, else the page it's on."""
        target = self._do_scroll(widget, units, horizontal, notch)
        if target is not None:
            self._settle_after_scroll(target)

    def _settle_after_scroll(self, target):
        """Once scrolling stops, repaint what was scrolled. On macOS, Tk scrolls by copying pixels and can
        leave blank patches in text boxes and tables (dragging the page scrollbar used to clear them);
        a full repaint 120 ms after the last wheel / trackpad event fixes that."""
        pending = getattr(self, "_settle_pending", None)
        if pending is None:
            pending = self._settle_pending = set()
        pending.add(target)
        if getattr(self, "_settle_job", None):
            self.root.after_cancel(self._settle_job)
        self._settle_job = self.root.after(120, self._settle_now)

    def _settle_now(self):
        self._settle_job = None
        targets, self._settle_pending = getattr(self, "_settle_pending", set()), set()
        for t in targets:
            try:
                if not t.winfo_exists():
                    continue
                widgets = [t]
                if isinstance(t, ScrollPage):
                    widgets = [t.canvas] + [w for w in self._descendants(t.body)
                                            if w.winfo_class() in ("Text", "Canvas", "Treeview", "Listbox")]
                for w in widgets:
                    if not w.winfo_ismapped():
                        continue
                    if w.winfo_class() == "Treeview":
                        w.configure(style=w.cget("style"))          # ttk: forces a full redisplay
                    elif w.winfo_class() == "Text":
                        repaint_text(w)
                    else:
                        w.configure(background=w.cget("background"))   # Canvas: full redraw
            except tk.TclError:
                pass

    def _install_text_repaint(self):
        """Every text box on a tool page repaints itself fully whenever its view moves (wheel, its own
        scrollbar, arrow keys, see()). Tk normally scrolls a text box by copying pixels; on macOS, when part
        of the box is off-screen (below the window edge), the copy smears its last visible line into the
        rest of the box. A full repaint of the visible lines avoids that."""
        for _, _, _, page in self.tools:
            for w in self._descendants(page.body):
                if w.winfo_class() == "Text":
                    self._watch_text_view(w)

    def _watch_text_view(self, text: tk.Text):
        for opt in ("yscrollcommand", "xscrollcommand"):
            old = text.tk.splitlist(text.cget(opt)) if str(text.cget(opt)) else ()
            last = {"v": None}

            def changed(*args, old=old, last=last, text=text):
                if old:
                    try:
                        text.tk.call(*old, *args)
                    except tk.TclError:
                        pass
                try:                                   # what's at the top-left corner: changes only on a real scroll
                    top = text.index("@0,0")
                except tk.TclError:
                    return
                if top != last["v"]:
                    last["v"] = top
                    self._repaint_soon(text)

            text.configure(**{opt: changed})

    def _repaint_soon(self, text):
        pending = getattr(self, "_repaint_pending", None)
        if pending is None:
            pending = self._repaint_pending = set()
        if not pending:
            self.root.after_idle(self._repaint_now)
        pending.add(text)

    def _repaint_now(self):
        pending, self._repaint_pending = getattr(self, "_repaint_pending", set()), set()
        for t in pending:
            repaint_text(t)

    @staticmethod
    def _descendants(widget):
        out = []
        stack = list(widget.winfo_children())
        while stack:
            w = stack.pop()
            out.append(w)
            stack.extend(w.winfo_children())
        return out

    def _do_scroll(self, widget, units: int, horizontal: bool, notch: bool):
        """Scroll and return what moved (the box, the page, or None)."""
        cls = widget.winfo_class()
        if cls in ("TScrollbar", "Scrollbar"):
            # Over a scrollbar: scroll whatever that scrollbar drives.
            if isinstance(widget.master, ScrollPage):
                if widget is widget.master.vbar:
                    widget.master.scroll(units)
                    return widget.master
                if widget is widget.master.hbar:
                    widget.master.scroll_x(units)
                    return widget.master
            cmd = str(widget.cget("command"))
            if cmd:
                try:
                    widget.tk.eval(f"{cmd} scroll {units * (3 if notch else 1)} units")
                except tk.TclError:
                    pass
            return next((w for w in widget.master.winfo_children()
                         if w.winfo_class() in ("Text", "Treeview", "Listbox", "Canvas")), None)
        if cls in ("Treeview", "Text", "Listbox"):
            try:
                first, last = widget.xview() if horizontal else widget.yview()
            except (tk.TclError, ValueError):
                first, last = 0.0, 1.0
            if first > 0.0 or last < 1.0:              # it has its own scrolling to do
                step = units * 3 if notch else units
                if horizontal:
                    widget.xview_scroll(step, "units")
                else:
                    widget.yview_scroll(step, "units")
                return widget
        page = widget                                  # everything else (or a box that fits): the page
        while page is not None and not isinstance(page, ScrollPage):
            page = page.master
        if page is None:
            return None
        if horizontal:
            page.scroll_x(units * (3 if notch else 1))
        else:
            page.scroll(units * (3 if notch else 1))
        return page

    def _set_icon(self):
        """Window / taskbar / Dock icon from the brand kit, at several sizes so each OS picks a sharp one."""
        self._icons = []
        # Largest first: macOS (Aqua) Tk uses only the first image for the Dock, so it must be the
        # 1024 px macOS-style artwork. Windows and Linux take the whole list and pick the size they need.
        names = ["bt-icon-macos-1024.png"] if self.is_mac else ["bt-icon-1024.png"]
        names += [f"bt-icon-{n}.png" for n in (512, 256, 128, 64, 48, 32, 16)]
        for name in names:
            try:
                self._icons.append(tk.PhotoImage(file=str(HERE / "icons" / name)))
            except tk.TclError:
                pass
        if not self._icons:                          # older layout: just icon.png
            try:
                self._icons.append(tk.PhotoImage(file=str(HERE / "icon.png")))
            except tk.TclError:
                return                               # old Tk without PNG support; harmless
        try:
            self.root.iconphoto(True, *self._icons)
        except tk.TclError:
            pass
        try:                                         # small mark shown left of the Tools menu
            self.logo_small = tk.PhotoImage(file=str(HERE / "icons" / "bt-icon-32.png"))
        except tk.TclError:
            self.logo_small = None

    def _style(self, ws: str):
        style = ttk.Style(self.root)
        style.theme_use("clam")                      # fully themeable on every OS (aqua/vista can't be recoloured)
        self.appearance = self.settings.get("appearance", "system")
        self.dark = self.resolve_dark()
        self.colors = DARK_COLORS if self.dark else LIGHT_COLORS
        # Fonts: the platform's own UI font (SF Pro on macOS, Segoe UI on Windows, the desktop font on
        # Linux) and a good monospace for addresses/tables. Sizes follow the Text size setting.
        self.mono = tkfont.nametofont("TkFixedFont").copy()
        fam = self.pick_mono_family()
        if fam:
            self.mono.configure(family=fam)
        self.big_mono = self.mono.copy()
        base = tkfont.nametofont("TkDefaultFont")
        title = base.copy()
        title.configure(weight="bold")
        small = base.copy()
        self._fonts = (title, small)
        style.configure("Title.TLabel", font=title)
        style.configure("Hint.TLabel", font=small)
        style.configure("HintLink.TLabel", font=small)              # a link inside a hint line
        style.configure("ChromeHint.TLabel", font=small)
        style.configure("Badge.TLabel", font=small)
        style.configure("Warn.TLabel", font=small)
        style.configure("Error.TLabel", font=small)
        style.configure("Small.TButton", font=small, padding=(6, 0))
        big = base.copy()
        big.configure(weight="bold")
        field_font = base.copy()
        field_font.configure(weight="bold")
        self._fonts += (big, field_font)
        self.title_font, self.small_font, self.big_font, self.field_font = title, small, big, field_font
        self._base_sizes = {}
        for name in ("TkDefaultFont", "TkTextFont", "TkHeadingFont", "TkMenuFont", "TkCaptionFont",
                     "TkSmallCaptionFont", "TkTooltipFont", "TkIconFont"):
            try:
                self._base_sizes[name] = tkfont.nametofont(name).cget("size")
            except tk.TclError:
                pass
        self._ui_size = abs(base.cget("size")) or 12
        self._mono_size = max(11, abs(tkfont.nametofont("TkFixedFont").cget("size")))
        self.text_size = self.settings.get("text_size", "medium")
        self.apply_text_size(self.text_size, initial=True)
        style.configure("Big.TLabel", font=big)
        style.configure("Field.TLabel", font=field_font)
        style.configure("FieldLink.TLabel", font=field_font)        # a link inside a field label
        style.configure("Accent.TButton", font=field_font)
        style.configure("Tools.TMenubutton", font=field_font, padding=(10, 3))
        style.configure("Cal.TButton", padding=(2, 1))
        style.configure("CalOther.TButton", padding=(2, 1))
        style.configure("CalSel.TButton", padding=(2, 1), font=field_font)
        style.configure("Value.TEntry", padding=(4, 1))
        style.configure("Treeview", font=self.mono, rowheight=int(self.mono.metrics("linespace") * 1.4))
        self.apply_theme(initial=True)

    # ---- appearance (light / dark / follow system)

    def resolve_dark(self) -> bool:
        if self.appearance == "dark":
            return True
        if self.appearance == "light":
            return False
        return system_is_dark(self.root)

    def theme_styles(self, c):
        """Every ttk style colour, from palette `c`."""
        st = ttk.Style(self.root)
        st.configure(".", background=c["page"], foreground=c["fg"], fieldbackground=c["field"],
                     bordercolor=c["border"], lightcolor=c["page"], darkcolor=c["page"], troughcolor=c["trough"],
                     selectbackground=c["select_bg"], selectforeground=c["select_fg"], insertcolor=c["fg"],
                     focuscolor=c["accent"], arrowcolor=c["fg"])
        st.map(".", foreground=[("disabled", c["disabled"])], background=[("disabled", c["page"])])
        for name in ("TFrame", "TLabelframe", "TPanedwindow"):
            st.configure(name, background=c["page"])
        st.configure("TLabelframe.Label", background=c["page"], foreground=c["fg"])
        st.configure("TLabel", background=c["page"], foreground=c["fg"])
        st.configure("Chrome.TFrame", background=c["chrome"])
        st.configure("Chrome.TLabel", background=c["chrome"], foreground=c["fg"])
        st.configure("ChromeHint.TLabel", background=c["chrome"], foreground=c["chrome_muted"])
        for name, key in (("Hint.TLabel", "muted"), ("Key.TLabel", "muted"), ("Warn.TLabel", "warn"),
                          ("Error.TLabel", "error"), ("Link.TLabel", "link"), ("FieldLink.TLabel", "link"),
                          ("HintLink.TLabel", "link")):
            st.configure(name, background=c["page"], foreground=c[key])
        st.configure("Badge.TLabel", background=c["badge_bg"], foreground=c["badge_fg"])
        for name in ("TCheckbutton", "TRadiobutton"):
            st.configure(name, background=c["page"], foreground=c["fg"], indicatorbackground=c["field"],
                         indicatorforeground=c["fg"], upperbordercolor=c["border"], lowerbordercolor=c["border"])
            st.map(name, background=[("active", c["page"])],
                   indicatorbackground=[("pressed", c["button_pressed"]), ("selected", c["field"])])
        btn = dict(background=c["button"], foreground=c["fg"], bordercolor=c["border"], lightcolor=c["button"],
                   darkcolor=c["button"])
        for name in ("TButton", "TMenubutton"):
            st.configure(name, **btn)
            st.map(name, background=[("disabled", c["button"]), ("pressed", c["button_pressed"]),
                                     ("active", c["button_active"])],
                   lightcolor=[("pressed", c["button_pressed"]), ("active", c["button_active"])],
                   darkcolor=[("pressed", c["button_pressed"]), ("active", c["button_active"])],
                   foreground=[("disabled", c["disabled"])])
        st.configure("Accent.TButton", background=c["accent"], foreground=c["accent_fg"], lightcolor=c["accent"],
                     darkcolor=c["accent"], bordercolor=c["accent"])
        st.map("Accent.TButton", background=[("disabled", c["button"]), ("pressed", c["accent_active"]),
                                             ("active", c["accent_active"])],
               lightcolor=[("active", c["accent_active"])], darkcolor=[("active", c["accent_active"])],
               foreground=[("disabled", c["disabled"])])
        st.configure("CalOther.TButton", foreground=c["cal_other"])
        st.configure("CalSel.TButton", foreground=c["cal_sel"])
        field = dict(fieldbackground=c["field"], foreground=c["field_fg"], insertcolor=c["field_fg"],
                     bordercolor=c["border"], lightcolor=c["field"], darkcolor=c["field"],
                     background=c["button"], arrowcolor=c["fg"])
        for name in ("TEntry", "TCombobox", "TSpinbox"):
            st.configure(name, **field)
            st.map(name, fieldbackground=[("readonly", c["field"]), ("disabled", c["trough"])],
                   foreground=[("disabled", c["disabled"])], background=[("active", c["button_active"])],
                   selectbackground=[("!focus", c["select_bg"])], selectforeground=[("!focus", c["select_fg"])])
        st.configure("Treeview", background=c["field"], fieldbackground=c["field"], foreground=c["field_fg"],
                     bordercolor=c["border"], lightcolor=c["field"], darkcolor=c["field"])
        st.map("Treeview", background=[("selected", c["select_bg"])], foreground=[("selected", c["select_fg"])])
        st.configure("Treeview.Heading", background=c["heading"], foreground=c["fg"], bordercolor=c["border"],
                     lightcolor=c["heading"], darkcolor=c["heading"], relief="flat")
        st.map("Treeview.Heading", background=[("active", c["button_active"])])
        st.configure("TNotebook", background=c["chrome"], bordercolor=c["border"], lightcolor=c["chrome"],
                     darkcolor=c["chrome"])
        st.configure("TNotebook.Tab", background=c["tab"], foreground=c["fg"], bordercolor=c["border"],
                     lightcolor=c["tab"], darkcolor=c["tab"])
        # Selected tab stands a few pixels taller than the rest (same colours as before).
        st.configure("TNotebook", tabmargins=(0, 5, 0, 0))     # first tab lines up with the page's left edge
        st.configure("TNotebook.Tab", padding=(8, 3, 8, 3))
        st.map("TNotebook.Tab", padding=[("selected", (8, 3, 8, 3))], expand=[("selected", (0, 4, 0, 0))])
        st.map("TNotebook.Tab", background=[("selected", c["page"]), ("active", c["tab_active"])],
               lightcolor=[("selected", c["page"])], darkcolor=[("selected", c["page"])],
               foreground=[("selected", c["fg"])])
        st.configure("TScrollbar", background=c["button"], troughcolor=c["trough"], bordercolor=c["border"],
                     arrowcolor=c["fg"], lightcolor=c["button"], darkcolor=c["button"])
        st.map("TScrollbar", background=[("active", c["button_active"]), ("disabled", c["trough"])])
        st.configure("TSeparator", background=c["border"])
        st.configure("Grip.TFrame", background=c["page"])          # box resize grips
        st.configure("GripBar.TFrame", background=c["border"])
        st.configure("GripBarHot.TFrame", background=c["accent"])
        st.configure("TProgressbar", background=c["accent"], troughcolor=c["trough"], bordercolor=c["border"],
                     lightcolor=c["accent"], darkcolor=c["accent"])
        st.configure("Sash", background=c["page"])
        # Classic-widget defaults for anything created later (menus, combobox drop-downs, dialogs).
        o = self.root.option_add
        for pat, val in (("*Menu.background", c["field"]), ("*Menu.foreground", c["field_fg"]),
                         ("*Menu.activeBackground", c["select_bg"]), ("*Menu.activeForeground", c["select_fg"]),
                         ("*Menu.selectColor", c["fg"]),
                         ("*TCombobox*Listbox.background", c["field"]), ("*TCombobox*Listbox.foreground", c["field_fg"]),
                         ("*TCombobox*Listbox.selectBackground", c["select_bg"]),
                         ("*TCombobox*Listbox.selectForeground", c["select_fg"]),
                         ("*Toplevel.background", c["page"])):
            o(pat, val)

    def apply_theme(self, initial: bool = False):
        """(Re)colour the whole app for the current appearance setting."""
        old = getattr(self, "_applied_colors", None)
        self.dark = self.resolve_dark()
        c = self.colors = DARK_COLORS if self.dark else LIGHT_COLORS
        self.theme_styles(c)
        try:                                         # macOS title bar to match
            self.root.tk.call("::tk::unsupported::MacWindowStyle", "appearance", self.root,
                              {"light": "aqua", "dark": "darkaqua"}.get(self.appearance, "auto"))
        except tk.TclError:
            pass
        self.root.configure(background=c["chrome"])
        if not initial and old is not c:
            self._recolor(self.root, old or {}, c)
        self._applied_colors = c
        self._update_close_x()
        if hasattr(self, "notebook"):
            self._apply_all_badges()
        if hasattr(self, "ping"):
            self.ping._sel_fg = None
            self.ping.update_sel_color()

    def _recolor(self, widget, old, new):
        """Walk every widget: classic widgets get the new palette; colours set from the old palette
        (tag colours, label foregrounds) are swapped for the matching new ones."""
        remap = {}
        # Text/label colours win over structural ones when two palette entries share a value.
        order = [k for k in old if k not in ("muted", "link", "warn", "error", "nomac")] + \
            ["nomac", "link", "warn", "error", "muted"]
        for k in order:
            if k in old and k in new:
                remap[old[k].lower()] = new[k]
        for k, v in HIGHLIGHT_MAC.items():
            remap.pop(v.lower(), None)

        def swap(value):
            return remap.get(str(value).lower()) if value else None

        def visit(w):
            cls = w.winfo_class()
            try:
                if cls in ("Text", "Listbox", "Canvas"):
                    match_theme(self, w)
                elif cls == "Toplevel":
                    w.configure(background=new["page"])
                elif cls == "Menu":
                    w.configure(background=new["field"], foreground=new["field_fg"],
                                activebackground=new["select_bg"], activeforeground=new["select_fg"])
                elif cls == "TLabel":
                    v = swap(w.cget("foreground"))
                    if v:
                        w.configure(foreground=v)
                if cls == "Text":
                    for tag in w.tag_names():
                        for opt in ("foreground", "background"):
                            v = swap(w.tag_cget(tag, opt))
                            if v:
                                w.tag_configure(tag, **{opt: v})
                elif cls == "Treeview":
                    for tag in set(t for i in w.get_children() for t in w.item(i, "tags")) | \
                            {"fhrp", "mcast", "unknown", "dead", "lossy", "idle", "fail", "unreach", "error",
                             "rir", "local", "note", "pending", "stopped"}:
                        for opt in ("foreground", "background"):
                            try:
                                v = swap(w.tag_configure(tag, opt))
                            except tk.TclError:
                                v = None
                            if v:
                                w.tag_configure(tag, **{opt: v})
            except tk.TclError:
                pass
            for child in w.winfo_children():
                visit(child)

        visit(widget)

    def set_appearance(self, mode: str):
        self.appearance = mode if mode in dict(APPEARANCES) else "system"
        self.settings["appearance"] = self.appearance
        self.apply_theme()
        self.flash(f"Appearance: {dict(APPEARANCES)[self.appearance]}"
                   + (f" ({'dark' if self.dark else 'light'})" if self.appearance == "system" else ""))

    def _watch_system_theme(self):
        """In 'Follow system' mode, notice when the OS switches between light and dark."""
        if self.appearance == "system" and (self.is_mac or sys.platform == "win32"):
            if system_is_dark(self.root) != self.dark:
                self.apply_theme()
        self.root.after(3000, self._watch_system_theme)

    TEXT_SIZES = (("small", "Small", -2), ("medium", "Medium (default)", -1), ("large", "Large", 0),
                  ("larger", "Larger", 1))

    @staticmethod
    def pick_mono_family():
        """A clean monospace that's on this machine: SF Mono/Menlo, Cascadia/Consolas, DejaVu/Liberation."""
        prefs = {"darwin": ("SF Mono", "Menlo", "Monaco"),
                 "win32": ("Cascadia Mono", "Cascadia Code", "Consolas")}.get(
            sys.platform, ("DejaVu Sans Mono", "Liberation Mono", "Noto Sans Mono", "Ubuntu Mono"))
        try:
            have = {f.lower(): f for f in tkfont.families()}
        except tk.TclError:
            return None
        for name in prefs:
            if name.lower() in have:
                return have[name.lower()]
        return None

    def apply_text_size(self, key: str, initial: bool = False):
        """Resize every font in the app. 'medium' is a step smaller than the system default."""
        delta = dict((k, d) for k, _, d in self.TEXT_SIZES).get(key, -1)
        self.text_size = key if key in dict((k, d) for k, _, d in self.TEXT_SIZES) else "medium"

        def sized(orig, extra=0):
            size = max(8, abs(orig) + delta + extra)
            return -size if orig < 0 else size      # keep pixel (negative) vs point sizes as they were

        for name, orig in self._base_sizes.items():
            tkfont.nametofont(name).configure(size=sized(orig))
        ui = self._ui_size + delta
        self.title_font.configure(size=max(10, ui + 3))
        self.small_font.configure(size=max(8, ui - 1))
        self.big_font.configure(size=max(12, ui + 5))
        self.field_font.configure(size=max(8, ui))
        self.mono.configure(size=max(8, self._mono_size + delta))
        self.big_mono.configure(size=self.mono.cget("size") + 4)
        ttk.Style(self.root).configure("Treeview", rowheight=int(self.mono.metrics("linespace") * 1.4))
        if not initial:
            self.settings["text_size"] = self.text_size
            self._update_close_x()
            self._apply_all_badges()
            self.root.after(50, self._fit_tabs)
            self.flash(f"Text size: {dict((k, l) for k, l, _ in self.TEXT_SIZES)[self.text_size]}")

    # ---- right-click menu on any text: cut / copy / paste, and send to another tool

    def _install_text_menus(self):
        seqs = {self.right_click}
        if self.is_mac:                                # Ctrl-click is a right-click on a Mac
            seqs.add("<Control-Button-1>")
        for cls in ("Text", "Entry", "TEntry", "TCombobox"):
            for seq in seqs:
                self.root.bind_class(cls, seq, self._text_menu, add="+")
        for seq in seqs:
            self.root.bind_class("Treeview", seq, self._plain_tree_menu, add="+")

    def _plain_tree_menu(self, e):
        """Tables that don't have their own right-click menu get Copy + Send to."""
        tree = e.widget
        if any(tree.bind(seq) for seq in ("<Button-2>", "<Button-3>", "<Control-Button-1>")):
            return None
        row = tree.identify_row(e.y)
        if not row:
            return None
        try:
            cell = self._tree_text(tree, e)
        except (tk.TclError, ValueError, IndexError):
            cell = ""
        picked = tree.selection() if row in tree.selection() else (row,)   # don't change the selection
        rows = texttable.tree_table(tree, picked)
        menu = tk.Menu(self.root, tearoff=False)
        if cell:
            menu.add_command(label=f"Copy “{sendto.preview(cell)}”", command=lambda: self.copy(cell))
        n = len(picked)
        menu.add_command(label="Copy row" if n == 1 else f"Copy {n} rows", command=lambda: self.copy(rows))
        menu.add_separator()
        self.add_send_menu(menu, cell)
        menu.tk_popup(e.x_root, e.y_root)
        return "break"

    def _text_info(self, w, e):
        """(selected text, word under the pointer, editable?) for a Text or Entry widget."""
        sel = token = ""
        if isinstance(w, tk.Text):
            try:
                sel = w.get("sel.first", "sel.last")
            except tk.TclError:
                pass
            line, col = map(int, w.index(f"@{e.x},{e.y}").split("."))
            token = sendto.token_at(w.get(f"{line}.0", f"{line}.end"), col)
            editable = str(w.cget("state")) == "normal"
        else:
            try:
                if w.selection_present():
                    sel = w.get()[w.index("sel.first"):w.index("sel.last")]
            except tk.TclError:
                pass
            token = sendto.token_at(w.get(), w.index(f"@{e.x}"))
            if isinstance(w, ttk.Entry):
                editable = w.instate(["!disabled", "!readonly"])
            else:
                editable = str(w.cget("state")) == "normal"
        return sel, token, editable

    def _text_menu(self, e):
        w = e.widget
        try:
            sel, token, editable = self._text_info(w, e)
        except (tk.TclError, ValueError, AttributeError):
            return None
        key = "⌘" if self.is_mac else "Ctrl+"
        menu = tk.Menu(self.root, tearoff=False)
        if editable:
            menu.add_command(label="Cut", accelerator=f"{key}X", state="normal" if sel else "disabled",
                             command=lambda: w.event_generate("<<Cut>>"))
        if sel:
            menu.add_command(label="Copy", accelerator=f"{key}C", command=lambda: self.copy(sel))
        elif token:
            menu.add_command(label=f"Copy “{sendto.preview(token)}”", command=lambda: self.copy(token))
        else:
            menu.add_command(label="Copy", accelerator=f"{key}C", state="disabled")
        if editable:
            try:
                has_clip = bool(self.root.clipboard_get())
            except tk.TclError:
                has_clip = False
            menu.add_command(label="Paste", accelerator=f"{key}V", state="normal" if has_clip else "disabled",
                             command=lambda: (w.focus_set(), w.event_generate("<<Paste>>")))
        menu.add_command(label="Select all", accelerator=f"{key}A", command=lambda: self._select_all(w))
        menu.add_separator()
        self.add_send_menu(menu, sel or token, "selection" if sel else "")
        menu.tk_popup(e.x_root, e.y_root)
        return "break"

    @staticmethod
    def _select_all(w):
        w.focus_set()
        if isinstance(w, tk.Text):
            w.tag_add("sel", "1.0", "end-1c")
        else:
            w.selection_range(0, "end")
            w.icursor("end")

    def add_send_menu(self, menu, text: str, what: str = ""):
        """Add a 'Send … to ▸' cascade listing every tool (same groups as the Tools menu)."""
        sub = tk.Menu(menu, tearoff=False)
        group = None
        for key, label, grp, _ in self.tools:
            if key == "home":
                continue
            if grp != group:
                if group is not None:
                    sub.add_separator()
                sub.add_command(label=grp.upper(), state="disabled")
                group = grp
            if key == "compare":
                for side, name in ((0, "left"), (1, "right")):
                    sub.add_command(label=f"   Compare ({name} side)",
                                    command=lambda s=side: self.send_to("compare", text, side=s))
            else:
                sub.add_command(label=f"   {label}", command=lambda k=key: self.send_to(k, text))
        p = sendto.preview(text)
        if not p:
            menu.add_cascade(label="Send selection to", menu=sub, state="disabled")
        else:
            menu.add_cascade(label=f"Send “{p}” to", menu=sub)

    def popup_tree_menu(self, menu, e):
        """Show a table's right-click menu with a Send-to cascade for the clicked cell (or the
        clicked column of every selected row)."""
        text = ""
        try:
            text = self._tree_text(e.widget, e)
        except (tk.TclError, ValueError, IndexError):
            pass
        if text:
            menu.add_separator()
            self.add_send_menu(menu, text)
        menu.tk_popup(e.x_root, e.y_root)

    @staticmethod
    def _tree_text(tree, e) -> str:
        row, col = tree.identify_row(e.y), tree.identify_column(e.x)
        if not row or not col:
            return ""

        def cell(item):
            if col == "#0":
                return str(tree.item(item, "text"))
            value = str(tree.set(item, tree.column(col, "id")))
            if value.startswith("▶"):            # a button-style cell (▶ Ping): use the row's first real value
                value = next((str(v) for v in tree.item(item, "values") if str(v).strip()
                              and not str(v).startswith("▶")), "")
            return value

        rows = tree.selection() if row in tree.selection() and len(tree.selection()) > 1 else (row,)
        values = [cell(r).strip() for r in rows]
        return plain_digits("\n".join(v for v in values if v))

    def send_to(self, key: str, text: str, side: int = 0):
        """Use `text` as input to another tool, then switch to it."""
        text = text.strip("\r\n")
        if not text.strip():
            return
        self.show(key)
        try:
            self.page_of[key].canvas.yview_moveto(0)
        except (AttributeError, tk.TclError):
            pass
        label = self.label_of[key]
        msg = self._receive(key, text, side)
        self.flash(msg or f"Sent to {label}.")

    @staticmethod
    def _replace(widget: tk.Text, text: str):
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.edit_modified(False)

    def _receive(self, key: str, text: str, side: int = 0):
        if key == "calc":
            subnet = sendto.first_subnet(text)
            self.calc.load(subnet)
            self.calc.refresh()
            return f"IP Calc: {subnet}"
        if key == "summary":
            self._replace(self.summary.text, text)
            self.summary.refresh()
        elif key == "bits":
            num, unit = sendto.data_amount(text)
            if num is None:
                return "Bits & Bytes: no number found in what you sent."
            self.bits.amount_var.set(num)
            if unit:
                self.bits.unit_var.set(unit)
            self.bits.refresh()
            return f"Bits & Bytes: {num} {unit or self.bits.unit_var.get()}"
        elif key == "tz":
            dt = sendto.first_datetime(text)
            self.tz.when_var.set(dt.strftime("%Y-%m-%d %H:%M:%S") if dt else sendto.first_line(text))
            self.tz.refresh()
            if dt is None:
                return "Time Zones: no date or time found in what you sent."
        elif key == "addtime":
            dt = sendto.first_datetime(text)
            if dt is None:
                return "Time Calc: no date or time found in what you sent."
            a = self.addtime
            a.use_time.set(True)
            for var, value in ((a.month_v, dt.month), (a.day_v, dt.day), (a.year_v, dt.year),
                               (a.hour_v, f"{dt.hour:02d}"), (a.min_v, f"{dt.minute:02d}"),
                               (a.sec_v, f"{dt.second:02d}")):
                var.set(str(value))
            a.refresh()
            return f"Time Calc: start {dt:%Y-%m-%d %H:%M:%S}"
        elif key in ("mac", "lookup"):
            tab = self.mac if key == "mac" else self.lookup
            self._replace(tab.src, text)
            tab.refresh()
        elif key == "dig":
            name = sendto.first_target(text)
            self.dig.name_v.set(name)
            self.dig.run()
            return f"DNS Digr: {name}"
        elif key == "ping":
            items = sendto.ping_list(text, self.ping._expand)
            if not items:
                return "Ping: no IP addresses or host names found in what you sent."
            added = self.ping.add_targets(items, start=True)
            return f"Ping: started {len(added)} target{'s' if len(added) != 1 else ''}." if added else None
        elif key == "sweep":
            self.sweep.load(text, start=False)
            n = len(sweep.expand_targets(text).hosts)
            return f"Ping Sweep: {n:,} address{'es' if n != 1 else ''} ready. Press Start to sweep."
        elif key == "trace":
            target = sendto.first_target(text)
            self.trace.target_v.set(target)
            if not self.trace.proc:
                self.trace.start()
            return f"Traceroute: {target}"
        elif key == "whois":
            self._replace(self.whois.src, text)
            self.whois.highlight()
            if not self.whois.worker:
                self.whois.start()
        elif key == "routes":
            self.routes.set_text(text)
        elif key == "bwcost":
            b = self.bwcost
            m = re.search(r"\$\s?([\d,]+(?:\.\d+)?)", text)
            num, unit = sendto.data_amount(text)
            units = {"megabits": "Mbps", "gigabits": "Gbps", "terabits": "Tbps"}
            if m:
                b.monthly_v.set(m.group(1))
            if num and unit in units:
                b.bw_v.set(num)
                b.bw_unit_v.set(units[unit])
            if not m and not (num and unit in units):
                return "Bandwidth Cost: no $ amount or Mbps/Gbps rate found in what you sent."
            b.refresh()
        elif key == "peeringdb":
            return f"PeeringDB: {self.pdb.load(text)}"
        elif key == "irr":
            found = self.irr.load(text)
            if not found:
                return "IRR / RPKI: no ASN or AS-SET found in what you sent."
            return f"IRR / RPKI: {' '.join(found[:5])}{' …' if len(found) > 5 else ''}"
        elif key == "compare":
            self.compare.set_side(side, text, "")
            self.compare.compare()
            return f"Compare: put in the {'left' if side == 0 else 'right'} side."
        elif key == "logtime":
            self.logtime.set_text(text)
        return None

    # ---- help, website, about

    def help_path(self) -> Path:
        """The help page, copied to the settings folder so the browser keeps a stable file to show
        (a one-file build unpacks into a temporary folder that's deleted when the app quits)."""
        bundled = HERE / "help" / "index.html"
        if not bundled.exists():                          # running from source without a built help file
            try:
                import helpgen
                helpgen.build()
            except Exception:
                pass
        dest = settings_path().parent / "help" / "index.html"
        try:
            data = bundled.read_bytes()
            if not dest.exists() or dest.read_bytes() != data:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
            return dest
        except OSError:
            return bundled

    def open_help(self):
        import webbrowser
        p = self.help_path()
        if not p.exists():
            self.flash(f"The help file is missing. It's also at {version.WEBSITE_LABEL}.")
            webbrowser.open(version.WEBSITE)
            return
        webbrowser.open(p.resolve().as_uri())
        self.flash("Opened the help in your browser.")

    def open_website(self):
        import webbrowser
        webbrowser.open(version.WEBSITE)

    def version_info(self) -> str:
        import platform
        return (f"{APP_NAME} {version.VERSION} ({version.pretty_date()})\n{version.WEBSITE}\n"
                f"Python {platform.python_version()} · Tk {self.root.tk.call('info', 'patchlevel')} · "
                f"{platform.system()} {platform.release()} ({platform.machine()})\n"
                f"Settings: {settings_path().parent}")

    def show_about(self):
        if getattr(self, "_about_win", None) is not None and self._about_win.winfo_exists():
            self._about_win.lift()
            return self._about_win
        win = tk.Toplevel(self.root)
        win.title(f"About {APP_NAME}")
        win.transient(self.root)
        win.resizable(False, False)
        self._about_win = win
        f = ttk.Frame(win, padding=20)
        f.pack(fill="both", expand=True)
        try:
            self._about_logo = tk.PhotoImage(file=str(HERE / "icons" / "bt-icon-128.png"))
            ttk.Label(f, image=self._about_logo).pack(pady=(0, 10))
        except tk.TclError:
            pass
        ttk.Label(f, text=APP_NAME, style="Big.TLabel").pack()
        ttk.Label(f, text=version.TAGLINE, style="Hint.TLabel").pack(pady=(2, 10))
        ttk.Label(f, text=f"Version {version.VERSION}", style="Key.TLabel").pack()
        ttk.Label(f, text=f"Released {version.pretty_date()}", style="Hint.TLabel").pack(pady=(2, 8))
        link(f, version.WEBSITE_LABEL, self.open_website).pack()
        import platform
        ttk.Label(f, style="Hint.TLabel", justify="center",
                  text=f"Python {platform.python_version()} · Tk {self.root.tk.call('info', 'patchlevel')}\n"
                       f"{platform.system()} {platform.release()}").pack(pady=(10, 0))
        b = ttk.Frame(f)
        b.pack(pady=(14, 0))
        ttk.Button(b, text="Help", command=self.open_help).pack(side="left")
        ttk.Button(b, text="Copy version info", command=lambda: self.copy(self.version_info())).pack(
            side="left", padx=6)
        ttk.Button(b, text="Close", style="Accent.TButton", command=win.destroy).pack(side="left")
        win.bind("<Escape>", lambda e: win.destroy())
        return win

    # ---- shared actions

    def copy(self, text: str):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update_idletasks()
        first = text.splitlines()[0] if text else ""
        more = f"  (+{text.count(chr(10))} more lines)" if "\n" in text else ""
        self.flash(f"Copied: {first}{more}")

    def flash(self, msg: str):
        self.status.configure(text=msg)
        if getattr(self, "_flash_job", None):
            self.root.after_cancel(self._flash_job)
        self._flash_job = self.root.after(2500, lambda: self.status.configure(text=""))

    def goto_dig(self, name: str):
        self.show(self.dig_page)
        self.dig.name_v.set(name)
        self.dig.run()

    def goto_ping(self, target: str):
        """Add `target` to the Ping tool's list (without starting) and show it."""
        self.show(self.ping_page)
        self.ping.add_targets(target, start=False)

    def start_ping(self, target: str):
        """Add `target` (one or several) to the Ping tool and start pinging it."""
        self.show(self.ping_page)
        self.ping.add_targets(target, start=True)

    def goto_sweep(self, text: str):
        self.show(self.sweep_page)
        self.sweep.load(text)

    def goto_trace(self, target: str):
        self.show(self.trace_page)
        self.trace.target_v.set(target)

    def dig_ptr(self, ip: str):
        """Jump to the DNS Digr tab and run a reverse lookup."""
        self.show(self.dig_page)
        self.dig.name_v.set(ip)
        self.dig.run()

    def open_in_calculator(self, subnet: str):
        self.show(self.calc_page)
        self.calc_page.canvas.yview_moveto(0)
        self.calc.load(subnet)

    def collect_settings(self) -> dict:
        """Bring self.settings up to date with what's on screen (what would be saved on close)."""
        self.settings.update(
            input=self.calc.input_var.get(),
            split4=self.calc.split_prefix[4],
            split6=self.calc.split_prefix[6],
            summary=self.summary.get_text(),
            bits_amount=self.bits.amount_var.get(),
            bits_unit=self.bits.unit_var.get(),
            bits_notation=self.bits.notation_var.get(),
            mac_input=self.mac.get_text(),
            mac_style=self.mac.style_v.get(),
            mac_case=self.mac.case_v.get(),
            mac_mode=self.mac.mode_v.get(),
            mac_dedupe=self.mac.dedupe_v.get(),
            lookup_input=self.lookup.get_text(),
            lookup_style=self.lookup.style_key(),
            lookup_upper=self.lookup.upper_v.get(),
            dig_history=self.dig.history,
            dig_type=self.dig.type_v.get(),
            dig_server=self.dig.server_v.get(),
            dig_root=self.dig.root_v.get(),
            trace_history=self.trace.history,
            trace_resolve=self.trace.resolve_v.get(),
            trace_max=self.trace.max_v.get(),
            trace_queries=self.trace.q_v.get(),
            trace_wait=self.trace.wait_v.get(),
            ping_history=self.ping.history,
            ping_targets=[{"target": x.target, "note": x.note} for x in self.ping.sessions.values()],
            ping_count=self.ping.count_v.get(),
            ping_interval=self.ping.interval_v.get(),
            ping_timeout=self.ping.timeout_v.get(),
            ping_size=self.ping.size_v.get(),
            ping_failonly=self.ping.failonly_v.get(),
            whois_input=self.whois.get_text(),
            whois_contacts=self.whois.contacts_v.get(),
            whois_skip_private=self.whois.skip_v.get(),
            whois_rdap=self.whois.rdap_v.get(),
            whois_via=self.whois.via_key(),
            whois_source=self.whois.source_key(),
            whois_ips=self.whois.do_ips_v.get(),
            whois_asns=self.whois.do_asns_v.get(),
            whois_bare_asns=self.whois.bare_v.get(),
            whois_domains=self.whois.do_domains_v.get(),
            geometry=self.root.geometry(),
            favorites=self.favorites,
            known_tools=[t[0] for t in self.tools],
            last_tool=self.current,
            text_size=self.text_size,
            appearance=self.appearance,
            **self.compare.settings_dict(),
            **self.sweep.settings_dict(),
            **self.logtime.settings_dict(),
            **self.irr.settings_dict(),
            **self.bwcost.settings_dict(),
            **self.pdb.settings_dict(),
        )
        if self.tz.available:
            self.settings.update(tz_source=self.tz.source_var.get(), tz_targets=self.tz.targets)
        return self.settings

    def _stop_everything(self):
        self.trace.stop()
        self.ping.shutdown()
        self.sweep.stop()
        self.lookup.stop_download()
        self.whois.stop()
        self.irr.stop()

    def on_close(self):
        self.collect_settings()
        self._stop_everything()
        save_settings(self.settings)
        self._saved_mtime = None
        self.root.destroy()

    def restart(self, save: bool = True):
        """Close and reopen the app window (in the same process) so every setting is read fresh."""
        if save:
            self.collect_settings()
            save_settings(self.settings)
        self._stop_everything()
        self.restart_requested = True
        try:                                           # this window's timers mustn't fire in the next one
            for job in self.root.tk.splitlist(self.root.tk.call("after", "info")):
                self.root.tk.call("after", "cancel", job)
        except tk.TclError:
            pass
        self.root.destroy()

    # ---- settings file: edit in the app, open in an editor, show the folder, reset

    def edit_settings(self):
        """In-app editor for settings.json. Saving restarts the window so every change takes effect."""
        import json as _json
        if getattr(self, "_settings_win", None) is not None and self._settings_win.winfo_exists():
            self._settings_win.lift()
            return self._settings_win
        path = settings_path()
        win = tk.Toplevel(self.root)
        win.title(f"{APP_NAME} – settings")
        win.transient(self.root)
        win.geometry("760x620")
        self._settings_win = win
        frame = ttk.Frame(win, padding=12)
        frame.pack(fill="both", expand=True)
        top = ttk.Frame(frame)
        top.pack(fill="x")
        ttk.Label(top, text="settings.json", style="Title.TLabel").pack(side="left")
        link(top, "Show in folder", self.show_settings_folder).pack(side="right")
        ttk.Button(top, text="Open in text editor", style="Small.TButton",
                   command=lambda: (win.destroy(), self.open_settings_external())).pack(side="right", padx=8)
        ttk.Label(frame, text=str(path), style="Hint.TLabel").pack(anchor="w", pady=(2, 0))
        ttk.Label(frame, style="Hint.TLabel", wraplength=720, justify="left",
                  text="This is everything the app remembers, as it is right now. Edit values in JSON "
                       "(\"double quotes\", true / false, [lists]). Save & restart reopens the window with "
                       "your changes; open tabs that aren't favorites close.").pack(anchor="w", pady=(4, 6))
        text = scrolled_text(frame, self, height=24)
        text.container.pack(fill="both", expand=True)
        text.tag_configure("bad", background=self.colors["warn"], foreground="#ffffff")
        status = ttk.Label(frame, style="Warn.TLabel", wraplength=720, justify="left")
        status.pack(anchor="w", pady=(6, 0))

        def load_current():
            text.delete("1.0", "end")
            text.insert("1.0", _json.dumps(self.collect_settings(), indent=2, ensure_ascii=False))
            text.edit_reset()
            status.configure(text="")

        def parse():
            text.tag_remove("bad", "1.0", "end")
            raw = text.get("1.0", "end-1c")
            try:
                data = _json.loads(raw)
            except ValueError as exc:
                line, col = getattr(exc, "lineno", 1), getattr(exc, "colno", 1)
                text.tag_add("bad", f"{line}.0", f"{line}.end")
                text.see(f"{line}.0")
                text.mark_set("insert", f"{line}.{max(0, col - 1)}")
                status.configure(text=f"Not valid JSON – line {line}, column {col}: {getattr(exc, 'msg', exc)}")
                return None
            if not isinstance(data, dict):
                status.configure(text="The settings must be one JSON object: { \"key\": value, … }")
                return None
            return data

        def tidy():
            data = parse()
            if data is not None:
                text.delete("1.0", "end")
                text.insert("1.0", _json.dumps(data, indent=2, ensure_ascii=False))
                status.configure(text="")

        def save():
            data = parse()
            if data is None:
                return
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(_json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            except OSError as exc:
                status.configure(text=f"Couldn't save: {exc}")
                return
            win.destroy()
            self.restart(save=False)

        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(8, 0))
        ttk.Button(btns, text="Format", command=tidy).pack(side="left")
        ttk.Button(btns, text="Revert", command=load_current).pack(side="left", padx=6)
        ttk.Button(btns, text="Save & restart", style="Accent.TButton", command=save).pack(side="right")
        ttk.Button(btns, text="Cancel", command=win.destroy).pack(side="right", padx=6)
        win.bind("<Escape>", lambda e: win.destroy())
        mod = "Command" if self.is_mac else "Control"
        win.bind(f"<{mod}-s>", lambda e: save())
        load_current()
        text.focus_set()
        self._settings_text, self._settings_save, self._settings_status = text, save, status   # for tests
        return win

    def _open_path(self, path: Path, edit: bool = False, reveal: bool = False):
        import subprocess
        try:
            if sys.platform == "darwin":
                args = ["open", "-R", str(path)] if reveal else (["open", "-t", str(path)] if edit else ["open", str(path)])
                subprocess.Popen(args)
            elif sys.platform == "win32":
                if reveal:
                    subprocess.Popen(["explorer", "/select,", str(path)])
                elif edit:
                    subprocess.Popen(["notepad.exe", str(path)])
                else:
                    os.startfile(str(path))                   # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", str(path.parent if reveal else path)])
        except OSError as exc:
            self.flash(f"Couldn't open {path}: {exc}")

    def show_settings_folder(self):
        path = settings_path()
        self.collect_settings()
        save_settings(self.settings)                           # make sure the file exists
        self._open_path(path, reveal=True)

    def open_settings_external(self):
        """Save the current settings, open settings.json in the system text editor, and watch it."""
        path = settings_path()
        self.collect_settings()
        save_settings(self.settings)
        try:
            self._saved_mtime = path.stat().st_mtime
        except OSError:
            self._saved_mtime = None
        self._open_path(path, edit=True)
        self.flash("Editing settings.json in your text editor. Save it there and the app will offer to restart.")
        if not getattr(self, "_watch_settings_job", None):
            self._watch_settings_job = self.root.after(1500, self._watch_settings_file)

    def _outside_edit_pending(self) -> bool:
        try:
            return self._saved_mtime is not None and settings_path().stat().st_mtime != self._saved_mtime
        except (OSError, AttributeError):
            return False

    def _watch_settings_file(self):
        """Notice when settings.json is saved from another editor, and offer to restart with it."""
        self._watch_settings_job = None
        if getattr(self, "_saved_mtime", None) is None:
            return
        path = settings_path()
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = self._saved_mtime
        if mtime != self._saved_mtime:
            self._saved_mtime = mtime
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                self.flash(f"settings.json has an error, so it wasn't applied: {exc}")
            else:
                from tkinter import messagebox
                if messagebox.askyesno(
                        APP_NAME, "settings.json was changed in another editor.\n\nRestart the window now to use "
                        "the changes?\n\nIf you don't, the app's own settings will be saved over your edits "
                        "when it closes.", parent=self.root):
                    self.restart(save=False)
                    return
        self._watch_settings_job = self.root.after(1500, self._watch_settings_file)

    def reset_settings(self):
        from tkinter import messagebox
        if not messagebox.askyesno(
                APP_NAME, "Reset every setting to its default?\n\nFavorites, tool inputs, ping targets, "
                "appearance and window size are all cleared. Your oui.txt is kept.", parent=self.root):
            return
        try:
            settings_path().parent.mkdir(parents=True, exist_ok=True)
            settings_path().write_text("{}", encoding="utf-8")      # (an empty file, not a missing one)
        except OSError as exc:
            self.flash(f"Couldn't reset: {exc}")
            return
        self.restart(save=False)


def main():
    if sys.platform == "win32":
        try:  # crisp text on high-DPI Windows displays
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    while True:
        root = tk.Tk()
        app = App(root)
        root.mainloop()
        if not getattr(app, "restart_requested", False):
            break


if __name__ == "__main__":
    main()
