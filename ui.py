"""
ui.py — LogSentinel GUI

Features:
  - Live log monitoring (tail -f)
  - GeoIP lookup for flagged IPs
  - Whitelist / blacklist IP management
  - Email alerts on critical findings
  - SIEM-style dashboard with canvas charts
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import threading
import os
import time
import collections

from parser import analyse, AnalysisReport
from exporter import export_txt, export_csv
from geoip import lookup as geo_lookup, format_location
from iplist import IPLists
from alerter import load_config, save_config, send_alert
from triage import triage_alert, load_api_key, save_api_key

# ── Palette ───────────────────────────────────────────────────────────────────
BG        = "#080808"
BG2       = "#111111"
BG3       = "#1a1a1a"
BORDER    = "#2a2a2a"
BORDER_HI = "#ffffff"
FG        = "#ffffff"
FG_DIM    = "#666666"
FG_MID    = "#aaaaaa"
DANGER    = "#cc3333"
WARN      = "#cc8833"
SUCCESS   = "#44aa66"
MONO      = ("Courier New", 10)
MONO_LG   = ("Courier New", 13, "bold")
MONO_SM   = ("Courier New", 8)


def styled_button(parent, text, command, danger=False, ghost=False, small=False):
    if danger:
        bg, fg, abg, hl = "#1a0a0a", DANGER, "#2a0f0f", DANGER
    elif ghost:
        bg, fg, abg, hl = BG3, FG_MID, BG2, BORDER
    else:
        bg, fg, abg, hl = FG, BG, "#cccccc", FG
    font = ("Courier New", 8) if small else ("Courier New", 10, "bold")
    return tk.Button(
        parent, text=text, command=command,
        bg=bg, fg=fg, activebackground=abg, activeforeground=fg,
        relief="flat", padx=12, pady=5, cursor="hand2",
        font=font, bd=0,
        highlightthickness=1, highlightbackground=hl, highlightcolor=hl,
    )


def styled_entry(parent, width=30, font=MONO, show=""):
    return tk.Entry(
        parent, width=width, font=font, show=show,
        bg=BG3, fg=FG, insertbackground=FG,
        relief="flat", highlightthickness=1,
        highlightbackground=BORDER, highlightcolor=BORDER_HI,
    )


def make_scrolled_text(parent):
    frame = tk.Frame(parent, bg=BG)
    frame.pack(fill="both", expand=True, padx=2, pady=2)
    text = tk.Text(frame, font=MONO, bg=BG, fg=FG,
                   insertbackground=FG, relief="flat",
                   highlightthickness=0, wrap="none",
                   state="disabled", padx=12, pady=10)
    vsb = ttk.Scrollbar(frame, orient="vertical",   command=text.yview)
    hsb = ttk.Scrollbar(frame, orient="horizontal", command=text.xview)
    text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    vsb.pack(side="right",  fill="y")
    hsb.pack(side="bottom", fill="x")
    text.pack(fill="both", expand=True)
    text.tag_configure("header",  foreground=FG,     font=("Courier New", 10, "bold"))
    text.tag_configure("dim",     foreground=FG_DIM)
    text.tag_configure("mid",     foreground=FG_MID)
    text.tag_configure("danger",  foreground=DANGER)
    text.tag_configure("warn",    foreground=WARN)
    text.tag_configure("success", foreground=SUCCESS)
    text.tag_configure("accent",  foreground=FG,     font=("Courier New", 10, "bold"))
    return text


def write_text(widget, content: list):
    widget.config(state="normal")
    widget.delete("1.0", "end")
    for text, tag in content:
        widget.insert("end", text, tag)
    widget.config(state="disabled")


# ── Email config dialog ───────────────────────────────────────────────────────

class EmailConfigDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Email Alert Config")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.grab_set()
        self.transient(master)
        self._config = load_config()
        self._build()

    def _build(self):
        tk.Frame(self, bg=FG, height=2).pack(fill="x")
        tk.Label(self, text="EMAIL ALERT CONFIGURATION",
                 font=("Courier New", 11, "bold"), bg=BG, fg=FG, pady=12).pack()
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        body = tk.Frame(self, bg=BG, padx=24, pady=16)
        body.pack(fill="both")

        # Enable toggle
        self._enabled = tk.BooleanVar(value=self._config.get("enabled", False))
        tk.Checkbutton(body, text="Enable email alerts", variable=self._enabled,
                       bg=BG, fg=FG, selectcolor=BG3, activebackground=BG,
                       activeforeground=FG, font=MONO, cursor="hand2").pack(
            anchor="w", pady=(0, 12))

        fields = [
            ("SMTP HOST",  "smtp_host", False),
            ("SMTP PORT",  "smtp_port", False),
            ("USERNAME",   "username",  False),
            ("PASSWORD",   "password",  True),
            ("FROM",       "from_addr", False),
            ("TO",         "to_addr",   False),
        ]
        self._vars = {}
        for label, key, secret in fields:
            tk.Label(body, text=label, font=MONO_SM, bg=BG,
                     fg=FG_DIM, anchor="w").pack(fill="x", pady=(6, 2))
            var = tk.StringVar(value=str(self._config.get(key, "")))
            self._vars[key] = var
            e = styled_entry(body, width=40, show="*" if secret else "")
            e.insert(0, var.get())
            e.bind("<KeyRelease>", lambda ev, k=key, w=e: self._vars[k].set(w.get()))
            e.pack(fill="x", ipady=5)

        tk.Label(body, text="For Gmail: use an App Password, not your main password.",
                 font=("Courier New", 7), bg=BG, fg=FG_DIM).pack(
            anchor="w", pady=(8, 0))

        tk.Frame(body, bg=BORDER, height=1).pack(fill="x", pady=(16, 12))
        btn_row = tk.Frame(body, bg=BG)
        btn_row.pack(fill="x", pady=(0, 4))
        styled_button(btn_row, "[ CANCEL ]", self.destroy, ghost=True).pack(
            side="right", padx=(8, 0))
        styled_button(btn_row, "[ SAVE ]", self._save).pack(side="right")

    def _save(self):
        cfg = {k: v.get() for k, v in self._vars.items()}
        cfg["enabled"] = self._enabled.get()
        try:
            cfg["smtp_port"] = int(cfg["smtp_port"])
        except ValueError:
            cfg["smtp_port"] = 587
        save_config(cfg)
        messagebox.showinfo("Saved", "Email config saved.", parent=self)
        self.destroy()


# ── IP Manager dialog ─────────────────────────────────────────────────────────

class IPManagerDialog(tk.Toplevel):
    def __init__(self, master, iplists: IPLists):
        super().__init__(master)
        self.title("IP List Manager")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.grab_set()
        self.transient(master)
        self._iplists = iplists
        self._build()

    def _build(self):
        tk.Frame(self, bg=FG, height=2).pack(fill="x")
        tk.Label(self, text="IP WHITELIST / BLACKLIST",
                 font=("Courier New", 11, "bold"), bg=BG, fg=FG, pady=12).pack()
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        body = tk.Frame(self, bg=BG, padx=20, pady=12)
        body.pack(fill="both", expand=True)

        # Input row
        input_row = tk.Frame(body, bg=BG)
        input_row.pack(fill="x", pady=(0, 12))
        tk.Label(input_row, text="IP ADDRESS", font=MONO_SM,
                 bg=BG, fg=FG_DIM).pack(side="left", padx=(0, 8))
        self._ip_entry = styled_entry(input_row, width=20)
        self._ip_entry.pack(side="left", ipady=4)
        styled_button(input_row, "WHITELIST", self._add_white,
                      ghost=True, small=True).pack(side="left", padx=(8, 4))
        styled_button(input_row, "BLACKLIST", self._add_black,
                      danger=True, small=True).pack(side="left")

        # Two columns
        cols = tk.Frame(body, bg=BG)
        cols.pack(fill="both", expand=True)

        for title, color, attr in [
            ("WHITELISTED", SUCCESS, "whitelist"),
            ("BLACKLISTED", DANGER,  "blacklist"),
        ]:
            col = tk.Frame(cols, bg=BG2, highlightthickness=1,
                           highlightbackground=BORDER)
            col.pack(side="left", fill="both", expand=True, padx=(0, 6))
            tk.Label(col, text=title, font=("Courier New", 9, "bold"),
                     bg=BG2, fg=color, pady=6).pack()
            tk.Frame(col, bg=BORDER, height=1).pack(fill="x")
            lb = tk.Listbox(col, bg=BG3, fg=FG, font=MONO_SM,
                            selectbackground=BG2, relief="flat",
                            highlightthickness=0, height=12)
            lb.pack(fill="both", expand=True, padx=4, pady=4)
            if attr == "whitelist":
                self._white_lb = lb
            else:
                self._black_lb = lb

        self._refresh_lists()

        btn_row = tk.Frame(body, bg=BG)
        btn_row.pack(fill="x", pady=(12, 0))
        styled_button(btn_row, "REMOVE SELECTED",
                      self._remove_selected, ghost=True, small=True).pack(side="left")
        styled_button(btn_row, "[ CLOSE ]", self.destroy).pack(side="right")

    def _add_white(self):
        ip = self._ip_entry.get().strip()
        if ip:
            self._iplists.add_white(ip)
            self._ip_entry.delete(0, "end")
            self._refresh_lists()

    def _add_black(self):
        ip = self._ip_entry.get().strip()
        if ip:
            self._iplists.add_black(ip)
            self._ip_entry.delete(0, "end")
            self._refresh_lists()

    def _remove_selected(self):
        for lb, remove_fn in [
            (self._white_lb, self._iplists.remove_white),
            (self._black_lb, self._iplists.remove_black),
        ]:
            sel = lb.curselection()
            if sel:
                ip = lb.get(sel[0])
                remove_fn(ip)
        self._refresh_lists()

    def _refresh_lists(self):
        self._white_lb.delete(0, "end")
        for ip in self._iplists.whitelist:
            self._white_lb.insert("end", ip)
        self._black_lb.delete(0, "end")
        for ip in self._iplists.blacklist:
            self._black_lb.insert("end", ip)


# ── Main App ──────────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LogSentinel 2.0")
        self.geometry("1100x720")
        self.minsize(900, 580)
        self.configure(bg=BG)

        style = ttk.Style(self)
        style.theme_use("default")
        for s in ("Vertical.TScrollbar", "Horizontal.TScrollbar"):
            style.configure(s, background=BG3, troughcolor=BG2,
                            arrowcolor=BORDER, bordercolor=BORDER, relief="flat")

        self._report: AnalysisReport | None = None
        self._log_text  = ""
        self._full_path = ""
        self._iplists   = IPLists()
        self._live_monitoring = False
        self._live_thread = None
        self._live_pos  = 0
        self._triage_history = []
        self._api_key = load_api_key()

        self._build()

    def _build(self):
        # Top bar
        top = tk.Frame(self, bg=BG2, highlightthickness=1, highlightbackground=BORDER)
        top.pack(fill="x", side="top")
        tk.Frame(top, bg=FG, height=2).pack(fill="x", side="top")
        inner = tk.Frame(top, bg=BG2, pady=10)
        inner.pack(fill="x")
        tk.Label(inner, text="LOGSENTINEL 2.0",
                 font=("Courier New", 14, "bold"), bg=BG2, fg=FG).pack(
            side="left", padx=16)
        tk.Label(inner, text="THREAT DETECTION  *  AI TRIAGE  *  LOG ANALYSIS",
                 font=MONO_SM, bg=BG2, fg=FG_DIM).pack(side="left")

        styled_button(inner, "[ EXPORT TXT ]", self._export_txt,
                      ghost=True).pack(side="right", padx=(0, 8))
        styled_button(inner, "[ EXPORT CSV ]", self._export_csv,
                      ghost=True).pack(side="right", padx=(0, 4))
        styled_button(inner, "EMAIL CONFIG",   self._open_email_config,
                      ghost=True).pack(side="right", padx=(0, 4))
        styled_button(inner, "IP LISTS",       self._open_ip_manager,
                      ghost=True).pack(side="right", padx=(0, 4))

        # Main layout
        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=12, pady=12)

        left = tk.Frame(main, bg=BG2, width=260,
                        highlightthickness=1, highlightbackground=BORDER)
        left.pack(side="left", fill="y", padx=(0, 10))
        left.pack_propagate(False)
        self._build_left(left)

        right = tk.Frame(main, bg=BG)
        right.pack(side="left", fill="both", expand=True)
        self._build_right(right)

    # ── Left panel ────────────────────────────────────────────────────────────

    def _build_left(self, parent):
        tk.Frame(parent, bg=FG, height=2).pack(fill="x")
        tk.Label(parent, text="CONFIGURATION",
                 font=("Courier New", 9, "bold"),
                 bg=BG2, fg=FG_DIM, pady=8).pack()
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x")

        body = tk.Frame(parent, bg=BG2, padx=14, pady=10)
        body.pack(fill="both", expand=True)

        # File
        tk.Label(body, text="LOG FILE", font=MONO_SM, bg=BG2, fg=FG_DIM,
                 anchor="w").pack(fill="x", pady=(0, 4))
        self._filepath_var = tk.StringVar(value="No file selected")
        tk.Label(body, textvariable=self._filepath_var,
                 font=("Courier New", 8), bg=BG3, fg=FG_MID,
                 wraplength=210, justify="left", pady=6, padx=6,
                 anchor="w").pack(fill="x")
        styled_button(body, "[ BROWSE FILE ]", self._browse).pack(
            fill="x", pady=(6, 8), ipady=3)

        # Live monitor toggle
        self._live_var = tk.BooleanVar(value=False)
        live_row = tk.Frame(body, bg=BG2)
        live_row.pack(fill="x", pady=(0, 12))
        tk.Checkbutton(live_row, text="Live Monitor (tail -f)",
                       variable=self._live_var,
                       command=self._toggle_live,
                       bg=BG2, fg=FG_MID, selectcolor=BG3,
                       activebackground=BG2, activeforeground=FG,
                       font=("Courier New", 8), cursor="hand2").pack(
            side="left")
        self._live_dot = tk.Label(live_row, text="●", font=("Courier New", 10),
                                  bg=BG2, fg=FG_DIM)
        self._live_dot.pack(side="right")

        tk.Frame(body, bg=BORDER, height=1).pack(fill="x", pady=(0, 10))

        # Keywords
        tk.Label(body, text="KEYWORD SEARCH", font=MONO_SM, bg=BG2,
                 fg=FG_DIM, anchor="w").pack(fill="x", pady=(0, 2))
        tk.Label(body, text="Comma-separated, supports regex.",
                 font=("Courier New", 7), bg=BG2, fg=FG_DIM,
                 justify="left", anchor="w").pack(fill="x")
        self._keywords_entry = tk.Text(body, height=3, font=MONO_SM,
                                       bg=BG3, fg=FG, insertbackground=FG,
                                       relief="flat", highlightthickness=1,
                                       highlightbackground=BORDER,
                                       highlightcolor=BORDER_HI)
        self._keywords_entry.pack(fill="x", pady=(4, 10))

        tk.Frame(body, bg=BORDER, height=1).pack(fill="x", pady=(0, 10))

        # Threshold
        tk.Label(body, text="BRUTE FORCE THRESHOLD", font=MONO_SM,
                 bg=BG2, fg=FG_DIM, anchor="w").pack(fill="x", pady=(0, 2))
        row = tk.Frame(body, bg=BG2)
        row.pack(fill="x", pady=(4, 12))
        self._thresh_var = tk.IntVar(value=5)
        self._thresh_lbl = tk.Label(row, text="5",
                                    font=("Courier New", 11, "bold"),
                                    bg=BG2, fg=FG, width=3)
        self._thresh_lbl.pack(side="right")
        tk.Scale(row, from_=1, to=20, orient="horizontal",
                 variable=self._thresh_var,
                 command=lambda v: self._thresh_lbl.config(text=str(int(float(v)))),
                 bg=BG2, fg=FG, troughcolor=BG3,
                 highlightthickness=0, sliderrelief="flat",
                 activebackground=FG, showvalue=False).pack(
            side="left", fill="x", expand=True)

        tk.Frame(body, bg=BORDER, height=1).pack(fill="x", pady=(0, 12))

        styled_button(body, "[ RUN ANALYSIS ]", self._run_analysis).pack(
            fill="x", ipady=6)
        styled_button(body, "[ SEND ALERT ]", self._send_alert,
                      ghost=True).pack(fill="x", pady=(6, 0), ipady=4)

        self._status_var = tk.StringVar(value="")
        tk.Label(body, textvariable=self._status_var,
                 font=("Courier New", 8), bg=BG2, fg=FG_DIM,
                 wraplength=210, justify="left").pack(fill="x", pady=(8, 0))

    # ── Right panel ───────────────────────────────────────────────────────────

    def _build_right(self, parent):
        self._tab_var  = tk.StringVar(value="dashboard")
        self._tab_btns = {}

        tab_bar = tk.Frame(parent, bg=BG2,
                           highlightthickness=1, highlightbackground=BORDER)
        tab_bar.pack(fill="x")

        tabs = [
            ("dashboard", "DASHBOARD"),
            ("overview",  "OVERVIEW"),
            ("flagged",   "FLAGGED"),
            ("ips",       "IP REPORT"),
            ("keywords",  "KEYWORDS"),
            ("live",      "LIVE LOG"),
            ("raw",       "RAW LOG"),
            ("triage",    "AI TRIAGE"),
        ]
        for tab_id, label in tabs:
            btn = tk.Button(
                tab_bar, text=label,
                font=("Courier New", 9, "bold"),
                bg=BG2, fg=FG_DIM, relief="flat",
                padx=12, pady=8, cursor="hand2", bd=0,
                command=lambda t=tab_id: self._switch_tab(t),
            )
            btn.pack(side="left")
            self._tab_btns[tab_id] = btn

        self._content = tk.Frame(parent, bg=BG)
        self._content.pack(fill="both", expand=True)

        # Build all tab frames
        self._dashboard_frame = tk.Frame(self._content, bg=BG)
        self._overview_frame  = tk.Frame(self._content, bg=BG)
        self._flagged_frame   = tk.Frame(self._content, bg=BG)
        self._ip_frame        = tk.Frame(self._content, bg=BG)
        self._keywords_frame  = tk.Frame(self._content, bg=BG)
        self._live_frame      = tk.Frame(self._content, bg=BG)
        self._raw_frame       = tk.Frame(self._content, bg=BG)
        self._triage_frame    = tk.Frame(self._content, bg=BG)

        self._build_dashboard()
        self._overview_text  = make_scrolled_text(self._overview_frame)
        self._flagged_text   = make_scrolled_text(self._flagged_frame)
        self._ip_text        = make_scrolled_text(self._ip_frame)
        self._keywords_text  = make_scrolled_text(self._keywords_frame)
        self._live_text      = make_scrolled_text(self._live_frame)
        self._raw_text       = make_scrolled_text(self._raw_frame)
        self._build_triage_tab()

        self._switch_tab("dashboard")

    def _switch_tab(self, tab_id):
        self._tab_var.set(tab_id)
        for tid, btn in self._tab_btns.items():
            if tid == tab_id:
                btn.config(bg=BG3, fg=FG,
                           highlightthickness=1,
                           highlightbackground=BORDER_HI,
                           highlightcolor=BORDER_HI)
            else:
                btn.config(bg=BG2, fg=FG_DIM, highlightthickness=0)
        frames = {
            "dashboard": self._dashboard_frame,
            "overview":  self._overview_frame,
            "flagged":   self._flagged_frame,
            "ips":       self._ip_frame,
            "keywords":  self._keywords_frame,
            "live":      self._live_frame,
            "raw":       self._raw_frame,
            "triage":    self._triage_frame,
        }
        for f in frames.values():
            f.pack_forget()
        frames[tab_id].pack(fill="both", expand=True)

    # ── Dashboard (SIEM charts) ───────────────────────────────────────────────

    def _build_dashboard(self):
        f = self._dashboard_frame
        f.columnconfigure(0, weight=1)
        f.columnconfigure(1, weight=1)
        f.rowconfigure(0, weight=0)
        f.rowconfigure(1, weight=1)
        f.rowconfigure(2, weight=1)

        # Stat cards row
        cards_row = tk.Frame(f, bg=BG)
        cards_row.grid(row=0, column=0, columnspan=2, sticky="ew", padx=4, pady=(8, 6))

        self._stat_vars = {}
        for col_i, (key, label, color) in enumerate([
            ("flagged",   "FLAGGED",     DANGER),
            ("brute",     "BRUTE FORCE", DANGER),
            ("logins",    "FAILED AUTH", WARN),
            ("sus_ips",   "SUSP. IPs",   WARN),
            ("keywords",  "KW MATCHES",  FG_MID),
        ]):
            card = tk.Frame(cards_row, bg=BG2, highlightthickness=1,
                            highlightbackground=BORDER)
            card.pack(side="left", fill="x", expand=True, padx=(0, 6))
            var = tk.StringVar(value="--")
            self._stat_vars[key] = var
            tk.Label(card, textvariable=var,
                     font=("Courier New", 22, "bold"),
                     bg=BG2, fg=color, pady=6).pack()
            tk.Label(card, text=label, font=("Courier New", 7),
                     bg=BG2, fg=FG_DIM).pack(pady=(0, 8))

        # Bar chart: top IPs
        ip_chart_frame = tk.Frame(f, bg=BG2, highlightthickness=1,
                                   highlightbackground=BORDER)
        ip_chart_frame.grid(row=1, column=0, sticky="nsew", padx=(4, 6), pady=(0, 6))
        tk.Label(ip_chart_frame, text="TOP THREAT IPs",
                 font=("Courier New", 9, "bold"),
                 bg=BG2, fg=FG_DIM, pady=6).pack()
        tk.Frame(ip_chart_frame, bg=BORDER, height=1).pack(fill="x")
        self._ip_chart = tk.Canvas(ip_chart_frame, bg=BG2,
                                    highlightthickness=0, height=200)
        self._ip_chart.pack(fill="both", expand=True, padx=8, pady=8)

        # Bar chart: event type breakdown
        evt_chart_frame = tk.Frame(f, bg=BG2, highlightthickness=1,
                                    highlightbackground=BORDER)
        evt_chart_frame.grid(row=1, column=1, sticky="nsew", padx=(0, 4), pady=(0, 6))
        tk.Label(evt_chart_frame, text="EVENT BREAKDOWN",
                 font=("Courier New", 9, "bold"),
                 bg=BG2, fg=FG_DIM, pady=6).pack()
        tk.Frame(evt_chart_frame, bg=BORDER, height=1).pack(fill="x")
        self._evt_chart = tk.Canvas(evt_chart_frame, bg=BG2,
                                     highlightthickness=0, height=200)
        self._evt_chart.pack(fill="both", expand=True, padx=8, pady=8)

        # Timeline chart
        tl_frame = tk.Frame(f, bg=BG2, highlightthickness=1,
                             highlightbackground=BORDER)
        tl_frame.grid(row=2, column=0, columnspan=2, sticky="nsew",
                       padx=4, pady=(0, 4))
        tk.Label(tl_frame, text="THREAT TIMELINE (flagged events per log section)",
                 font=("Courier New", 9, "bold"),
                 bg=BG2, fg=FG_DIM, pady=6).pack()
        tk.Frame(tl_frame, bg=BORDER, height=1).pack(fill="x")
        self._tl_chart = tk.Canvas(tl_frame, bg=BG2,
                                    highlightthickness=0, height=160)
        self._tl_chart.pack(fill="both", expand=True, padx=8, pady=8)

        # Placeholder text
        self._ip_chart.create_text(10, 10, text="Run analysis to populate",
                                    anchor="nw", fill=FG_DIM,
                                    font=("Courier New", 9))
        self._evt_chart.create_text(10, 10, text="Run analysis to populate",
                                     anchor="nw", fill=FG_DIM,
                                     font=("Courier New", 9))
        self._tl_chart.create_text(10, 10, text="Run analysis to populate",
                                    anchor="nw", fill=FG_DIM,
                                    font=("Courier New", 9))

    def _draw_bar_chart(self, canvas, items, color=DANGER, label_key="label"):
        """Draw a horizontal bar chart. items = list of (label, value)."""
        canvas.delete("all")
        if not items:
            canvas.create_text(10, 10, text="No data", anchor="nw",
                                fill=FG_DIM, font=("Courier New", 9))
            return
        canvas.update_idletasks()
        w = canvas.winfo_width()  or 300
        h = canvas.winfo_height() or 200

        max_val = max(v for _, v in items) or 1
        bar_h   = min(28, (h - 20) // len(items))
        label_w = 160
        bar_w   = w - label_w - 50

        for i, (label, val) in enumerate(items):
            y = 10 + i * (bar_h + 6)
            # Label
            canvas.create_text(0, y + bar_h // 2, text=label[:22],
                                anchor="w", fill=FG_MID,
                                font=("Courier New", 8))
            # Bar background
            canvas.create_rectangle(label_w, y, label_w + bar_w, y + bar_h,
                                     fill=BG3, outline=BORDER)
            # Bar fill
            fill_w = int(bar_w * val / max_val)
            if fill_w > 0:
                canvas.create_rectangle(label_w, y,
                                         label_w + fill_w, y + bar_h,
                                         fill=color, outline="")
            # Value
            canvas.create_text(label_w + bar_w + 6, y + bar_h // 2,
                                text=str(val), anchor="w",
                                fill=FG, font=("Courier New", 8, "bold"))

    def _draw_timeline(self, canvas, entries):
        """Draw a simple line chart of flagged events over time."""
        canvas.delete("all")
        if not entries:
            return
        canvas.update_idletasks()
        w = canvas.winfo_width()  or 600
        h = canvas.winfo_height() or 160

        # Bucket flagged entries into 20 equal segments
        total   = len(entries)
        buckets = 20
        size    = max(1, total // buckets)
        counts  = []
        for i in range(buckets):
            chunk = entries[i * size: (i + 1) * size]
            counts.append(sum(1 for e in chunk if e.flags))

        max_c = max(counts) or 1
        pad   = 20
        cw    = (w - pad * 2) / buckets
        ch    = h - pad * 2

        # Axes
        canvas.create_line(pad, pad, pad, h - pad, fill=BORDER)
        canvas.create_line(pad, h - pad, w - pad, h - pad, fill=BORDER)

        # Plot
        pts = []
        for i, c in enumerate(counts):
            x = pad + i * cw + cw / 2
            y = h - pad - (c / max_c) * ch
            pts.append((x, y))

        for i in range(len(pts) - 1):
            x1, y1 = pts[i]
            x2, y2 = pts[i + 1]
            canvas.create_line(x1, y1, x2, y2, fill=DANGER, width=2)

        for x, y in pts:
            canvas.create_oval(x - 3, y - 3, x + 3, y + 3,
                                fill=DANGER, outline="")

    def _update_dashboard(self, r: AnalysisReport):
        self._stat_vars["flagged"].set(str(r.flagged_lines))
        self._stat_vars["brute"].set(str(len(r.brute_force_ips)))
        self._stat_vars["logins"].set(str(r.failed_logins))
        self._stat_vars["sus_ips"].set(str(len(r.suspicious_ips)))
        self._stat_vars["keywords"].set(str(len(r.keyword_matches)))

        # Top IPs chart
        top_ips = sorted(r.suspicious_ips.items(), key=lambda x: x[1], reverse=True)[:8]
        self._draw_bar_chart(self._ip_chart, top_ips, color=DANGER)

        # Event type breakdown
        type_counts = collections.Counter()
        for entry in r.flagged_entries:
            for flag in entry.flags:
                base = flag.split(":")[0]
                type_counts[base] += 1
        evt_items = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        self._draw_bar_chart(self._evt_chart, evt_items, color=WARN)

        # Timeline
        self._draw_timeline(self._tl_chart, r.entries)

    # ── File / live monitor ───────────────────────────────────────────────────

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select log file",
            filetypes=[("Log files", "*.log *.txt *.evtx *.csv"),
                       ("All files", "*.*")])
        if path:
            self._full_path = path
            self._filepath_var.set(os.path.basename(path))
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    self._log_text = f.read()
                    self._live_pos = f.tell()
                write_text(self._raw_text, [(self._log_text, "mid")])
                self._status_var.set(
                    f"Loaded {len(self._log_text.splitlines())} lines.")
            except Exception as e:
                messagebox.showerror("Error", f"Could not read file:\n{e}")

    def _toggle_live(self):
        if self._live_var.get():
            if not self._full_path:
                messagebox.showwarning("No file",
                                       "Load a file first before enabling live monitoring.")
                self._live_var.set(False)
                return
            self._live_monitoring = True
            self._live_dot.config(fg=SUCCESS)
            self._live_thread = threading.Thread(
                target=self._live_tail, daemon=True)
            self._live_thread.start()
            self._switch_tab("live")
        else:
            self._live_monitoring = False
            self._live_dot.config(fg=FG_DIM)

    def _live_tail(self):
        """Tail the file and append new lines to the live tab."""
        write_text(self._live_text, [
            ("LIVE MONITORING ACTIVE\n", "header"),
            (f"Watching: {self._full_path}\n\n", "dim"),
        ])
        try:
            with open(self._full_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._live_pos)
                while self._live_monitoring:
                    line = f.readline()
                    if line:
                        self.after(0, lambda l=line: self._append_live(l))
                    else:
                        time.sleep(0.5)
        except Exception as e:
            self.after(0, lambda: self._append_live(f"[ERROR] {e}\n"))

    def _append_live(self, line: str):
        w = self._live_text
        w.config(state="normal")
        # Colour based on threat indicators
        lower = line.lower()
        if any(p in lower for p in ("fail", "error", "invalid", "denied", "401", "403")):
            tag = "danger"
        elif any(p in lower for p in ("warn", "block")):
            tag = "warn"
        else:
            tag = "mid"
        w.insert("end", line, tag)
        w.see("end")
        w.config(state="disabled")

    # ── Analysis ──────────────────────────────────────────────────────────────

    def _run_analysis(self):
        if not self._log_text:
            messagebox.showwarning("No file", "Please load a log file first.")
            return
        kw_raw   = self._keywords_entry.get("1.0", "end").strip()
        keywords = [k.strip() for k in kw_raw.split(",") if k.strip()] if kw_raw else []
        threshold = self._thresh_var.get()
        self._status_var.set("Analysing...")
        self.update_idletasks()

        def run():
            r = analyse(self._log_text, keywords, threshold)
            self._report = r
            self.after(0, lambda: self._display_report(r))

        threading.Thread(target=run, daemon=True).start()

    def _display_report(self, r: AnalysisReport):
        self._status_var.set(
            f"Done. {r.flagged_lines} flags in {r.parsed_lines} lines.")
        self._update_dashboard(r)

        # ── Overview ──────────────────────────────────────────────────────────
        ov = []
        ov += [("=" * 60 + "\n", "dim"), ("  ANALYSIS COMPLETE\n", "header"),
               ("=" * 60 + "\n\n", "dim")]
        ov += [("LOG METADATA\n", "header"), ("-" * 40 + "\n", "dim")]
        ov += [("  Type detected   ", "dim"), (f"{r.log_type.upper()}\n", "accent")]
        ov += [("  Total lines     ", "dim"), (f"{r.total_lines}\n", "mid")]
        ov += [("  Parsed lines    ", "dim"), (f"{r.parsed_lines}\n\n", "mid")]
        ov += [("THREAT SUMMARY\n", "header"), ("-" * 40 + "\n", "dim")]
        ov += [("  Flagged events   ", "dim"),
               (f"{r.flagged_lines}\n", "danger" if r.flagged_lines else "success")]
        ov += [("  Brute force IPs  ", "dim"),
               (f"{len(r.brute_force_ips)}\n", "danger" if r.brute_force_ips else "success")]
        ov += [("  Failed logins    ", "dim"),
               (f"{r.failed_logins}\n", "warn" if r.failed_logins else "success")]
        ov += [("  Suspicious IPs   ", "dim"),
               (f"{len(r.suspicious_ips)}\n", "warn" if r.suspicious_ips else "success")]
        ov += [("  Keyword matches  ", "dim"),
               (f"{len(r.keyword_matches)}\n\n", "warn" if r.keyword_matches else "success")]
        if r.brute_force_ips:
            ov += [("BRUTE FORCE ALERTS\n", "header"), ("-" * 40 + "\n", "dim")]
            for ip in r.brute_force_ips:
                count  = r.suspicious_ips.get(ip, "?")
                status = self._iplists.status(ip)
                tag    = "success" if status == "whitelisted" else "danger"
                ov += [("  [ALERT] ", "danger"),
                       (f"{ip:<20} {count} attempts [{status.upper()}]\n", tag)]
        write_text(self._overview_text, ov)

        # ── Flagged ───────────────────────────────────────────────────────────
        fl = []
        if not r.flagged_entries:
            fl += [("  No flagged entries.\n", "success")]
        else:
            fl += [("FLAGGED LOG ENTRIES\n", "header"), ("-" * 60 + "\n", "dim")]
            for entry in r.flagged_entries:
                flags   = " | ".join(entry.flags)
                fl_tag  = "danger" if any("LOGIN" in f for f in entry.flags) else "warn"
                ip_status = ""
                if entry.ip:
                    s = self._iplists.status(entry.ip)
                    if s != "unknown":
                        ip_status = f" [{s.upper()}]"
                fl += [
                    (f"  Line {entry.line_number:<6} ", "dim"),
                    (f"[{flags}]{ip_status}\n", fl_tag),
                    (f"  {entry.raw.strip()[:120]}\n\n", "mid"),
                ]
        write_text(self._flagged_text, fl)

        # ── IP Report (with GeoIP) ────────────────────────────────────────────
        ip_c = []
        if not r.suspicious_ips:
            ip_c += [("  No suspicious IP activity.\n", "success")]
        else:
            ip_c += [("SUSPICIOUS IP ACTIVITY  (fetching GeoIP...)\n", "header"),
                     ("-" * 70 + "\n", "dim")]
            write_text(self._ip_text, ip_c)
            # GeoIP in background
            threading.Thread(
                target=self._fill_ip_report, args=(r,), daemon=True).start()
            return
        write_text(self._ip_text, ip_c)

        # ── Keywords ──────────────────────────────────────────────────────────
        kw_c = []
        if not r.keyword_matches:
            kw_c += [("  No keyword matches.\n", "success")]
        else:
            kw_c += [("KEYWORD MATCHES\n", "header"), ("-" * 60 + "\n", "dim")]
            for line_num, keyword, raw in r.keyword_matches:
                kw_c += [
                    (f"  Line {line_num:<6} ", "dim"),
                    (f"[{keyword}]\n", "warn"),
                    (f"  {raw[:120]}\n\n", "mid"),
                ]
        write_text(self._keywords_text, kw_c)
        self._switch_tab("dashboard")

    def _fill_ip_report(self, r: AnalysisReport):
        """Fetch GeoIP for each suspicious IP, then update the tab."""
        rows = []
        for ip, count in sorted(r.suspicious_ips.items(),
                                 key=lambda x: x[1], reverse=True):
            geo      = geo_lookup(ip)
            location = format_location(geo)
            isp      = geo.get("isp", "") if geo else ""
            is_bf    = ip in r.brute_force_ips
            status   = self._iplists.status(ip)
            rows.append((ip, count, location, isp, is_bf, status))

        ip_c = []
        ip_c += [("SUSPICIOUS IP ACTIVITY\n", "header"), ("-" * 80 + "\n", "dim")]
        ip_c += [("  IP               FAILS  LOCATION                     ISP              STATUS\n", "dim")]
        ip_c += [("-" * 80 + "\n", "dim")]

        for ip, count, location, isp, is_bf, status in rows:
            if status == "whitelisted":
                row_tag = "success"
                badge   = "[WHITELISTED]"
            elif is_bf:
                row_tag = "danger"
                badge   = "[BRUTE FORCE]"
            elif status == "blacklisted":
                row_tag = "danger"
                badge   = "[BLACKLISTED]"
            else:
                row_tag = "warn"
                badge   = "[SUSPICIOUS]"

            ip_c += [
                (f"  {ip:<18} {count:<6} {location[:28]:<28} {isp[:16]:<16} ", "mid"),
                (f"{badge}\n", row_tag),
            ]
        self.after(0, lambda: write_text(self._ip_text, ip_c))
        self.after(0, lambda: write_text(self._keywords_text, self._make_kw_content(r)))
        self.after(0, lambda: self._switch_tab("dashboard"))

    def _make_kw_content(self, r):
        kw_c = []
        if not r.keyword_matches:
            kw_c += [("  No keyword matches.\n", "success")]
        else:
            kw_c += [("KEYWORD MATCHES\n", "header"), ("-" * 60 + "\n", "dim")]
            for line_num, keyword, raw in r.keyword_matches:
                kw_c += [
                    (f"  Line {line_num:<6} ", "dim"),
                    (f"[{keyword}]\n", "warn"),
                    (f"  {raw[:120]}\n\n", "mid"),
                ]
        return kw_c

    # ── Email alert ───────────────────────────────────────────────────────────

    def _send_alert(self):
        if not self._report:
            messagebox.showwarning("No report", "Run an analysis first.")
            return
        config = load_config()
        if not config.get("enabled"):
            if messagebox.askyesno("Email not configured",
                                   "Email alerts are not configured.\nOpen config now?"):
                self._open_email_config()
            return
        self._status_var.set("Sending alert...")
        self.update_idletasks()

        def send():
            ok, msg = send_alert(self._report, config)
            self.after(0, lambda: self._status_var.set(msg))
            self.after(0, lambda: (messagebox.showinfo if ok else messagebox.showerror)(
                "Email Alert", msg))

        threading.Thread(target=send, daemon=True).start()

    # ── Dialogs ───────────────────────────────────────────────────────────────

    def _open_email_config(self):
        EmailConfigDialog(self)

    def _open_ip_manager(self):
        IPManagerDialog(self, self._iplists)

    # ── Export ────────────────────────────────────────────────────────────────

    def _export_txt(self):
        if not self._report:
            messagebox.showwarning("No report", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt")],
            initialfile="report.txt")
        if path:
            export_txt(self._report, path)
            messagebox.showinfo("Exported", f"Saved to:\n{path}")

    def _export_csv(self):
        if not self._report:
            messagebox.showwarning("No report", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv")],
            initialfile="flagged.csv")
        if path:
            export_csv(self._report, path)
            messagebox.showinfo("Exported", f"Saved to:\n{path}")


    # ── AI Triage Tab ─────────────────────────────────────────────────────────

    def _build_triage_tab(self):
        f = self._triage_frame

        # Header
        hdr = tk.Frame(f, bg=BG2, highlightthickness=1, highlightbackground=BORDER)
        hdr.pack(fill="x")
        tk.Frame(hdr, bg=FG, height=2).pack(fill="x")
        hdr_inner = tk.Frame(hdr, bg=BG2, pady=10, padx=16)
        hdr_inner.pack(fill="x")
        tk.Label(hdr_inner, text="AI TRIAGE ASSISTANT",
                 font=("Courier New", 12, "bold"), bg=BG2, fg=FG).pack(side="left")
        tk.Label(hdr_inner,
                 text="Powered by Claude  *  MITRE ATT&CK mapping  *  SOC triage walkthrough",
                 font=("Courier New", 8), bg=BG2, fg=FG_DIM).pack(side="left", padx=(12, 0))
        styled_button(hdr_inner, "[ API KEY ]",
                      self._set_api_key, ghost=True, small=True).pack(side="right")
        styled_button(hdr_inner, "[ CLEAR CHAT ]",
                      self._clear_triage, ghost=True, small=True).pack(side="right", padx=(0, 6))

        # Main area: chat history + input
        body = tk.Frame(f, bg=BG)
        body.pack(fill="both", expand=True, padx=12, pady=8)

        # Chat history display
        chat_frame = tk.Frame(body, bg=BG)
        chat_frame.pack(fill="both", expand=True, pady=(0, 8))

        self._triage_text = tk.Text(
            chat_frame, font=("Courier New", 10), bg=BG, fg=FG,
            insertbackground=FG, relief="flat", highlightthickness=1,
            highlightbackground=BORDER, wrap="word",
            state="disabled", padx=14, pady=10,
        )
        vsb = ttk.Scrollbar(chat_frame, orient="vertical",
                            command=self._triage_text.yview)
        self._triage_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._triage_text.pack(fill="both", expand=True)

        # Tags
        self._triage_text.tag_configure("user_label",  foreground=FG_DIM,
                                         font=("Courier New", 8, "bold"))
        self._triage_text.tag_configure("user_text",   foreground=FG_MID,
                                         font=("Courier New", 10))
        self._triage_text.tag_configure("ai_label",    foreground=FG,
                                         font=("Courier New", 8, "bold"))
        self._triage_text.tag_configure("section",     foreground=FG,
                                         font=("Courier New", 10, "bold"))
        self._triage_text.tag_configure("critical",    foreground=DANGER,
                                         font=("Courier New", 10, "bold"))
        self._triage_text.tag_configure("high",        foreground=WARN,
                                         font=("Courier New", 10, "bold"))
        self._triage_text.tag_configure("medium",      foreground="#cccc33",
                                         font=("Courier New", 10, "bold"))
        self._triage_text.tag_configure("low",         foreground=SUCCESS,
                                         font=("Courier New", 10, "bold"))
        self._triage_text.tag_configure("mitre",       foreground="#5599ff",
                                         font=("Courier New", 10))
        self._triage_text.tag_configure("body",        foreground=FG_MID,
                                         font=("Courier New", 10))
        self._triage_text.tag_configure("thinking",    foreground=FG_DIM,
                                         font=("Courier New", 9, "italic"))
        self._triage_text.tag_configure("divider",     foreground=BORDER,
                                         font=("Courier New", 8))

        # Preset buttons
        preset_frame = tk.Frame(body, bg=BG)
        preset_frame.pack(fill="x", pady=(0, 6))
        tk.Label(preset_frame, text="QUICK INSERT:", font=("Courier New", 8),
                 bg=BG, fg=FG_DIM).pack(side="left", padx=(0, 8))

        presets = [
            ("Brute Force",     "Failed password for root from 203.0.113.45 — 10 attempts in 30 seconds"),
            ("SQL Injection",   'GET /products?id=1 UNION SELECT username,password FROM users HTTP/1.1 400'),
            ("Path Traversal",  "GET /../../../etc/passwd HTTP/1.1 400"),
            ("XSS Attempt",     "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1 400"),
            ("From Report",     None),
        ]
        for label, text in presets:
            btn = tk.Button(
                preset_frame, text=label,
                font=("Courier New", 8), bg=BG3, fg=FG_DIM,
                relief="flat", padx=8, pady=3, cursor="hand2", bd=0,
                highlightthickness=1, highlightbackground=BORDER,
                command=lambda t=text, l=label: self._insert_preset(t, l),
            )
            btn.pack(side="left", padx=(0, 4))

        # Input area
        input_frame = tk.Frame(body, bg=BG2, highlightthickness=1,
                               highlightbackground=BORDER)
        input_frame.pack(fill="x")
        tk.Label(input_frame, text="ALERT / LOG SNIPPET",
                 font=("Courier New", 8), bg=BG2, fg=FG_DIM,
                 pady=6, padx=12, anchor="w").pack(fill="x")

        self._triage_input = tk.Text(
            input_frame, height=5, font=("Courier New", 10),
            bg=BG3, fg=FG, insertbackground=FG,
            relief="flat", highlightthickness=0,
            wrap="word", padx=12, pady=8,
        )
        self._triage_input.pack(fill="x")

        btn_row = tk.Frame(input_frame, bg=BG2, pady=8, padx=12)
        btn_row.pack(fill="x")
        styled_button(btn_row, "[ ANALYZE ALERT ]",
                      self._run_triage).pack(side="left")
        tk.Label(btn_row,
                 text="Ctrl+Enter to submit  *  Multi-turn conversation supported",
                 font=("Courier New", 7), bg=BG2, fg=FG_DIM).pack(
            side="left", padx=(12, 0))

        self._triage_input.bind("<Control-Return>",
                                lambda _: self._run_triage())

        # Welcome message
        self._append_triage_message("ai", None,
            "SOC TRIAGE ASSISTANT READY\n\n"
            "Paste a raw alert, log line, or suspicious event into the box below "
            "and I will walk you through:\n\n"
            "  *  Threat classification and severity\n"
            "  *  Step-by-step triage investigation\n"
            "  *  Recommended containment actions\n"
            "  *  MITRE ATT&CK technique mapping\n"
            "  *  False positive indicators\n\n"
            "You can also use the QUICK INSERT buttons above to load example alerts, "
            "or click FROM REPORT to automatically load your latest analysis findings.\n\n"
            "Set your Anthropic API key with the [ API KEY ] button to get started."
        )

    def _insert_preset(self, text, label):
        if label == "From Report":
            if not self._report or not self._report.flagged_entries:
                messagebox.showwarning("No report",
                                       "Run an analysis first to load alerts from report.",
                                       parent=self)
                return
            # Build a summary of top flagged entries
            lines = ["=== LOGSENTINEL ANALYSIS REPORT ==="]
            lines.append(f"Log type: {self._report.log_type.upper()}")
            lines.append(f"Total flagged: {self._report.flagged_lines}")
            if self._report.brute_force_ips:
                lines.append(f"Brute force IPs: {', '.join(self._report.brute_force_ips)}")
            lines.append("")
            lines.append("TOP FLAGGED ENTRIES:")
            for entry in self._report.flagged_entries[:8]:
                flags = ", ".join(entry.flags)
                lines.append(f"Line {entry.line_number} [{flags}]: {entry.raw.strip()[:120]}")
            text = "\n".join(lines)

        self._triage_input.delete("1.0", "end")
        self._triage_input.insert("1.0", text)

    def _run_triage(self):
        alert = self._triage_input.get("1.0", "end").strip()
        if not alert:
            return
        if not self._api_key:
            messagebox.showwarning("No API key",
                                   "Set your Anthropic API key first with the [ API KEY ] button.",
                                   parent=self)
            return

        self._triage_input.delete("1.0", "end")
        self._append_triage_message("user", None, alert)
        self._append_triage_thinking()

        def call_api():
            response, history = triage_alert(alert, self._api_key,
                                             self._triage_history)
            self._triage_history = history
            self.after(0, lambda: self._append_triage_response(response))

        threading.Thread(target=call_api, daemon=True).start()

    def _append_triage_message(self, role, _unused, text):
        w = self._triage_text
        w.config(state="normal")
        if role == "user":
            w.insert("end", "\nYOU\n", "user_label")
            w.insert("end", text + "\n", "user_text")
        else:
            w.insert("end", "\nAI ANALYST\n", "ai_label")
            self._render_triage_response(w, text)
        w.insert("end", "\n" + "-" * 60 + "\n", "divider")
        w.see("end")
        w.config(state="disabled")

    def _append_triage_thinking(self):
        w = self._triage_text
        w.config(state="normal")
        w.insert("end", "\nAI ANALYST\n", "ai_label")
        w.insert("end", "Analyzing alert...\n", "thinking")
        w.see("end")
        w.config(state="disabled")
        self._thinking_index = w.index("end-2l")

    def _append_triage_response(self, response):
        w = self._triage_text
        w.config(state="normal")
        # Remove "Analyzing..." line
        try:
            w.delete(self._thinking_index, self._thinking_index + " +2l")
        except Exception:
            pass
        self._render_triage_response(w, response)
        w.insert("end", "\n" + "-" * 60 + "\n", "divider")
        w.see("end")
        w.config(state="disabled")

    def _render_triage_response(self, widget, text):
        """Render AI response with colored sections and MITRE highlighting."""
        import re
        lines = text.split("\n")
        for line in lines:
            # Section headers === SECTION ===
            if line.strip().startswith("===") and line.strip().endswith("==="):
                widget.insert("end", "\n" + line + "\n", "section")
            # Severity tags
            elif "CRITICAL" in line.upper() and "SEVERITY" in line.upper():
                widget.insert("end", line + "\n", "critical")
            elif "HIGH" in line.upper() and "SEVERITY" in line.upper():
                widget.insert("end", line + "\n", "high")
            elif "MEDIUM" in line.upper() and "SEVERITY" in line.upper():
                widget.insert("end", line + "\n", "medium")
            elif "LOW" in line.upper() and "SEVERITY" in line.upper():
                widget.insert("end", line + "\n", "low")
            # MITRE ATT&CK technique IDs  e.g. T1110
            elif re.search(r'T\d{4}(\.\d{3})?', line):
                widget.insert("end", line + "\n", "mitre")
            else:
                widget.insert("end", line + "\n", "body")

    def _clear_triage(self):
        self._triage_history = []
        w = self._triage_text
        w.config(state="normal")
        w.delete("1.0", "end")
        w.config(state="disabled")
        self._append_triage_message("ai", None,
            "Chat cleared. Paste a new alert to begin triage.")

    def _set_api_key(self):
        key = simpledialog.askstring(
            "Anthropic API Key",
            "Enter your Anthropic API key:\n(Get one at console.anthropic.com)",
            show="*", parent=self,
        )
        if key and key.strip():
            self._api_key = key.strip()
            save_api_key(self._api_key)
            messagebox.showinfo("Saved", "API key saved.", parent=self)


def run():
    App().mainloop()
