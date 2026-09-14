#!/usr/bin/env python3
"""
SentinelIQ // Modern Cyber Defense Dashboard & Behavioral Shield
Powered by WinSentry Engine
Author: SentinelIQ Defensive Team
Zero network footprint, 100% offline local operations.
"""

import os
import sys
import json
import time
import math
import ctypes
import threading
import subprocess
import webbrowser
from pathlib import Path
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox

# Import behavioral engine & live telemetry helpers
try:
    import winreg
except ImportError:
    winreg = None

try:
    from winsentry_behavioral import (
        BehavioralEngine, DEFAULT_BASELINE_FILE,
        collect_established_connections, collect_process_telemetry,
        SUSPICIOUS_SPAWNS, REMOTE_CONTROL_TOOLS
    )
except ImportError:
    BehavioralEngine = None
    DEFAULT_BASELINE_FILE = "winsentry_baseline.json"
    collect_established_connections = None
    collect_process_telemetry = None
    SUSPICIOUS_SPAWNS = set()
    REMOTE_CONTROL_TOOLS = set()

if getattr(sys, "frozen", False):
    SCRIPT_DIR = Path(sys.executable).resolve().parent
else:
    SCRIPT_DIR = Path(__file__).resolve().parent

JSON_REPORT_FILE = SCRIPT_DIR / "winsentry_report.json"
HTML_REPORT_FILE = SCRIPT_DIR / "WinSentry_Report.html"
PDF_REPORT_FILE = SCRIPT_DIR / "WinSentry_Report_Encrypted.pdf"
PS_SCANNER_FILE = SCRIPT_DIR / "WinSentry.ps1"


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# =========================================================================
# THEME CONFIGURATION (Refined Dark Cyberpunk / SaaS Security Palette)
# =========================================================================
class Theme:
    BG_ROOT = "#0A0B10"          # Deepest void black
    BG_SIDEBAR = "#0D0F18"       # Modern left sidebar rail
    BG_MAIN = "#0F111A"          # Main canvas background
    BG_CARD = "#141724"          # Elevated card surfaces
    BG_CARD_LIGHT = "#1A1E30"    # Hover / secondary card fill
    BG_HEADER = "#11131F"        # Top app header bar

    BORDER = "#1E2338"           # Refined subtle card borders
    BORDER_LIGHT = "#28304D"     # Hover border
    BORDER_CYAN = "#00E5FF"      # Accent border
    BORDER_BLUE = "#38BDF8"

    TEXT_WHITE = "#F8FAFC"       # Pure white headers
    TEXT_SECONDARY = "#94A3B8"   # Slate body text
    TEXT_MUTED = "#64748B"       # Subtle captions and labels
    TEXT_DARK = "#334155"

    CYAN = "#00E5FF"             # Neon Cyan
    BLUE = "#38BDF8"             # Vibrant Sky Blue
    GREEN = "#10B981"            # Mint Green (Clean / Safe)
    AMBER = "#F59E0B"            # Warm Amber (Medium Risk)
    RED = "#EF4444"              # Alert Red (Critical / High)
    PURPLE = "#A855F7"           # Soft Violet
    ROSE = "#F43F5E"


# =========================================================================
# CUSTOM WIDGETS
# =========================================================================
class CircularGauge(tk.Canvas):
    """Modern circular ring gauge drawing posture scores with anti-aliasing arcs."""
    def __init__(self, parent, size=150, **kwargs):
        super().__init__(parent, width=size, height=size, bg=Theme.BG_CARD,
                         highlightthickness=0, **kwargs)
        self.size = size
        self.score = None
        self.pad = 14
        self.ring_width = 12
        self.draw()

    def set_score(self, score):
        self.score = score
        self.draw()

    def draw(self):
        self.delete("all")
        s = self.size
        p = self.pad
        w = self.ring_width

        cx, cy = s / 2, s / 2
        r = (s - p * 2) / 2

        # 1. Background Track Ring
        self.create_oval(p, p, s - p, s - p, outline=Theme.BORDER, width=w)

        # 2. Value Arc
        if self.score is not None:
            # Score color
            if self.score >= 80:
                color = Theme.GREEN
                status_text = "EXCELLENT"
            elif self.score >= 50:
                color = Theme.AMBER
                status_text = "MODERATE"
            else:
                color = Theme.RED
                status_text = "HIGH RISK"

            extent = - (self.score / 100.0) * 359.9
            self.create_arc(p, p, s - p, s - p, start=90, extent=extent,
                            style=tk.ARC, outline=color, width=w)

            # Center Score Number
            self.create_text(cx, cy - 8, text=str(self.score), fill=Theme.TEXT_WHITE,
                             font=("Segoe UI", 28, "bold"))
            # Center Sub-label
            self.create_text(cx, cy + 22, text=f"/ 100  •  {status_text}", fill=color,
                             font=("Segoe UI", 8, "bold"))
        else:
            # Unscanned / Clean state
            self.create_text(cx, cy - 6, text="--", fill=Theme.TEXT_MUTED,
                             font=("Segoe UI", 30, "bold"))
            self.create_text(cx, cy + 22, text="AWAITING AUDIT", fill=Theme.TEXT_MUTED,
                             font=("Segoe UI", 8, "bold"))


class ModernButton(tk.Frame):
    """Custom styled button with animated hover state, border glows, and rounded feel."""
    def __init__(self, parent, text, command=None, bg_color=Theme.BG_CARD_LIGHT,
                 fg_color=Theme.TEXT_WHITE, hover_bg=None, hover_fg=None,
                 border_color=Theme.BORDER, font=("Segoe UI", 9, "bold"),
                 padx=14, pady=6, cursor="hand2", icon=None):
        super().__init__(parent, bg=border_color, padx=1, pady=1)

        self.command = command
        self.bg_color = bg_color
        self.fg_color = fg_color
        self.hover_bg = hover_bg or self._lighten(bg_color)
        self.hover_fg = hover_fg or fg_color
        self.border_color = border_color

        self.btn_lbl = tk.Label(
            self, text=f"{icon + '  ' if icon else ''}{text}",
            bg=self.bg_color, fg=self.fg_color, font=font,
            padx=padx, pady=pady, cursor=cursor
        )
        self.btn_lbl.pack(fill=tk.BOTH, expand=True)

        self.btn_lbl.bind("<Enter>", self._on_enter)
        self.btn_lbl.bind("<Leave>", self._on_leave)
        self.btn_lbl.bind("<Button-1>", lambda e: self.command() if self.command else None)
        self.bind("<Button-1>", lambda e: self.command() if self.command else None)

    def _on_enter(self, e):
        self.btn_lbl.config(bg=self.hover_bg, fg=self.hover_fg)
        self.config(bg=Theme.BORDER_CYAN)

    def _on_leave(self, e):
        self.btn_lbl.config(bg=self.bg_color, fg=self.fg_color)
        self.config(bg=self.border_color)

    def _lighten(self, hex_color):
        if hex_color.startswith("#"):
            return hex_color
        return hex_color

    def set_text(self, text, icon=None):
        self.btn_lbl.config(text=f"{icon + '  ' if icon else ''}{text}")


# =========================================================================
# MAIN DESKTOP APPLICATION
# =========================================================================
class SentinelIQApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("SentinelIQ // Security Posture Auditor & Behavioral Shield")
        self.geometry("1180x760")
        self.minsize(1050, 680)
        self.configure(bg=Theme.BG_ROOT)

        self.is_admin = is_admin()
        self.behavioral_engine = BehavioralEngine(baseline_path=str(SCRIPT_DIR / DEFAULT_BASELINE_FILE)) if BehavioralEngine else None

        self.report_data = None
        self.detected_remote_threats = []
        self.live_shield_active = False
        self.live_shield_thread = None
        self.active_scan_thread = None

        self.current_page = "dashboard"
        self.nav_buttons = {}

        self._setup_ttk_styles()
        self._build_layout()
        self.clear_view()
        self._update_baseline_status()

    def _setup_ttk_styles(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        self.style.configure(".", background=Theme.BG_MAIN, foreground=Theme.TEXT_WHITE, font=("Segoe UI", 9))

        # Modern Treeview Styling
        self.style.configure(
            "Cyber.Treeview",
            background=Theme.BG_CARD,
            foreground=Theme.TEXT_WHITE,
            fieldbackground=Theme.BG_CARD,
            rowheight=32,
            borderwidth=0,
            font=("Segoe UI", 9)
        )
        self.style.map(
            "Cyber.Treeview",
            background=[("selected", "#1E2742")],
            foreground=[("selected", Theme.CYAN)]
        )
        self.style.configure(
            "Cyber.Treeview.Heading",
            background=Theme.BG_CARD_LIGHT,
            foreground=Theme.BLUE,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            borderwidth=0
        )
        self.style.map(
            "Cyber.Treeview.Heading",
            background=[("active", "#252C47")]
        )

        # Subtle Progress Bar
        self.style.configure(
            "Cyber.Horizontal.TProgressbar",
            troughcolor=Theme.BG_CARD,
            background=Theme.CYAN,
            thickness=4,
            borderwidth=0
        )

        # Scrollbar styling
        self.style.configure("Vertical.TScrollbar", background=Theme.BG_CARD_LIGHT, troughcolor=Theme.BG_MAIN, borderwidth=0)

    def _build_layout(self):
        # Master container
        self.master_frame = tk.Frame(self, bg=Theme.BG_ROOT)
        self.master_frame.pack(fill=tk.BOTH, expand=True)

        # -------------------------------------------------------------
        # 1. LEFT SIDEBAR NAVIGATION RAIL
        # -------------------------------------------------------------
        self.sidebar = tk.Frame(self.master_frame, bg=Theme.BG_SIDEBAR, width=240,
                                highlightthickness=1, highlightbackground=Theme.BORDER)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)

        # App Brand Header
        brand_frame = tk.Frame(self.sidebar, bg=Theme.BG_SIDEBAR, padx=18, pady=22)
        brand_frame.pack(fill=tk.X)

        title_lbl = tk.Label(brand_frame, text="🛡️ SentinelIQ", font=("Segoe UI", 16, "bold"),
                             fg=Theme.BLUE, bg=Theme.BG_SIDEBAR)
        title_lbl.pack(anchor="w")

        powered_lbl = tk.Label(brand_frame, text="POWERED BY WINSENTRY ENGINE", font=("Segoe UI", 7, "bold"),
                               fg=Theme.TEXT_MUTED, bg=Theme.BG_SIDEBAR)
        powered_lbl.pack(anchor="w", pady=(2, 0))

        # Divider
        tk.Frame(self.sidebar, bg=Theme.BORDER, height=1).pack(fill=tk.X, padx=16, pady=(0, 15))

        # Host & Privilege Pill
        admin_pill = tk.Frame(self.sidebar, bg=Theme.BG_CARD, highlightthickness=1,
                              highlightbackground=Theme.BORDER, padx=12, pady=8)
        admin_pill.pack(fill=tk.X, padx=14, pady=(0, 20))

        hostname = os.environ.get("COMPUTERNAME", "LOCALHOST")
        user = os.environ.get("USERNAME", "USER")
        tk.Label(admin_pill, text=f"{hostname} \\ {user}", font=("Segoe UI", 8, "bold"),
                 fg=Theme.TEXT_SECONDARY, bg=Theme.BG_CARD, anchor="w").pack(fill=tk.X)

        status_text = "● ELEVATED ADMIN" if self.is_admin else "● STANDARD USER"
        status_color = Theme.GREEN if self.is_admin else Theme.AMBER
        tk.Label(admin_pill, text=status_text, font=("Segoe UI", 7, "bold"),
                 fg=status_color, bg=Theme.BG_CARD, anchor="w").pack(fill=tk.X, pady=(2, 0))

        # Nav Menu Items
        self.nav_frame = tk.Frame(self.sidebar, bg=Theme.BG_SIDEBAR)
        self.nav_frame.pack(fill=tk.X, padx=10)

        nav_items = [
            ("dashboard", "📊  Dashboard", "Overview & Posture"),
            ("behavioral", "🧠  Behavioral Shield", "Offline Anomaly Engine"),
            ("findings", "🔍  Findings Explorer", "Detailed Audit Trail"),
            ("logs", "📜  System Logs", "Console & Stream")
        ]

        for page_id, label, sub in nav_items:
            self._create_nav_item(page_id, label, sub)

        # Sidebar Footer Baseline Status Pill
        sidebar_foot = tk.Frame(self.sidebar, bg=Theme.BG_CARD, highlightthickness=1,
                                highlightbackground=Theme.BORDER, padx=12, pady=10)
        sidebar_foot.pack(side=tk.BOTTOM, fill=tk.X, padx=12, pady=16)

        self.lbl_sidebar_baseline = tk.Label(sidebar_foot, text="● BASELINE NOT FOUND", font=("Segoe UI", 8, "bold"),
                                             fg=Theme.AMBER, bg=Theme.BG_CARD, anchor="w")
        self.lbl_sidebar_baseline.pack(fill=tk.X)

        tk.Label(sidebar_foot, text="Zero-network local profiling", font=("Segoe UI", 7),
                 fg=Theme.TEXT_MUTED, bg=Theme.BG_CARD, anchor="w").pack(fill=tk.X, pady=(2, 0))

        # -------------------------------------------------------------
        # 2. MAIN WORKSPACE AREA
        # -------------------------------------------------------------
        self.main_content = tk.Frame(self.master_frame, bg=Theme.BG_MAIN)
        self.main_content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Top Global Action Bar
        self._build_top_action_bar()

        # Workspace Page Container
        self.page_container = tk.Frame(self.main_content, bg=Theme.BG_MAIN)
        self.page_container.pack(fill=tk.BOTH, expand=True, padx=22, pady=(10, 16))

        # Pages
        self.pages = {}
        self.pages["dashboard"] = self._create_dashboard_page()
        self.pages["behavioral"] = self._create_behavioral_page()
        self.pages["findings"] = self._create_findings_page()
        self.pages["logs"] = self._create_logs_page()

        self.show_page("dashboard")

    def _create_nav_item(self, page_id, label, sub):
        item_frame = tk.Frame(self.nav_frame, bg=Theme.BG_SIDEBAR, cursor="hand2")
        item_frame.pack(fill=tk.X, pady=3)

        # Active indicator bar
        ind = tk.Frame(item_frame, bg=Theme.BG_SIDEBAR, width=4)
        ind.pack(side=tk.LEFT, fill=tk.Y)

        txt_frame = tk.Frame(item_frame, bg=Theme.BG_SIDEBAR, padx=10, pady=8)
        txt_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        lbl_main = tk.Label(txt_frame, text=label, font=("Segoe UI", 10, "bold"),
                            fg=Theme.TEXT_SECONDARY, bg=Theme.BG_SIDEBAR, anchor="w")
        lbl_main.pack(fill=tk.X)

        lbl_sub = tk.Label(txt_frame, text=sub, font=("Segoe UI", 7),
                           fg=Theme.TEXT_MUTED, bg=Theme.BG_SIDEBAR, anchor="w")
        lbl_sub.pack(fill=tk.X)

        # Binding clicks
        for w in [item_frame, txt_frame, lbl_main, lbl_sub]:
            w.bind("<Button-1>", lambda e, p=page_id: self.show_page(p))
            w.bind("<Enter>", lambda e, f=item_frame, p=page_id: self._nav_hover(f, p, True))
            w.bind("<Leave>", lambda e, f=item_frame, p=page_id: self._nav_hover(f, p, False))

        self.nav_buttons[page_id] = {
            "frame": item_frame,
            "txt_frame": txt_frame,
            "ind": ind,
            "lbl_main": lbl_main,
            "lbl_sub": lbl_sub
        }

    def _nav_hover(self, frame, page_id, is_enter):
        if self.current_page == page_id:
            return
        bg = Theme.BG_CARD if is_enter else Theme.BG_SIDEBAR
        fg = Theme.TEXT_WHITE if is_enter else Theme.TEXT_SECONDARY
        frame.config(bg=bg)
        self.nav_buttons[page_id]["txt_frame"].config(bg=bg)
        self.nav_buttons[page_id]["lbl_main"].config(bg=bg, fg=fg)
        self.nav_buttons[page_id]["lbl_sub"].config(bg=bg)

    def show_page(self, page_id):
        self.current_page = page_id

        # Update sidebar styling
        for pid, widgets in self.nav_buttons.items():
            if pid == page_id:
                widgets["frame"].config(bg=Theme.BG_CARD_LIGHT)
                widgets["txt_frame"].config(bg=Theme.BG_CARD_LIGHT)
                widgets["ind"].config(bg=Theme.BLUE)
                widgets["lbl_main"].config(bg=Theme.BG_CARD_LIGHT, fg=Theme.BLUE)
                widgets["lbl_sub"].config(bg=Theme.BG_CARD_LIGHT, fg=Theme.TEXT_SECONDARY)
            else:
                widgets["frame"].config(bg=Theme.BG_SIDEBAR)
                widgets["txt_frame"].config(bg=Theme.BG_SIDEBAR)
                widgets["ind"].config(bg=Theme.BG_SIDEBAR)
                widgets["lbl_main"].config(bg=Theme.BG_SIDEBAR, fg=Theme.TEXT_SECONDARY)
                widgets["lbl_sub"].config(bg=Theme.BG_SIDEBAR, fg=Theme.TEXT_MUTED)

        # Show target page
        for pid, page in self.pages.items():
            if pid == page_id:
                page.pack(fill=tk.BOTH, expand=True)
            else:
                page.pack_forget()

        # Update top bar title
        page_titles = {
            "dashboard": ("Security Posture Dashboard", "Comprehensive system audit across 9 security vectors"),
            "behavioral": ("Behavioral Anomaly Shield", "Real-time LotL detection, masquerading analysis & baseline profiling"),
            "findings": ("Security Findings Explorer", "Deep-dive remediation commands and vulnerability details"),
            "logs": ("Real-Time Telemetry & Console", "Execution logs and background threat monitoring stream")
        }
        t, d = page_titles.get(page_id, ("SentinelIQ", ""))
        self.lbl_top_title.config(text=t)
        self.lbl_top_sub.config(text=d)

    # -------------------------------------------------------------
    # TOP ACTION BAR
    # -------------------------------------------------------------
    def _build_top_action_bar(self):
        top_bar = tk.Frame(self.main_content, bg=Theme.BG_HEADER, height=68,
                           highlightthickness=1, highlightbackground=Theme.BORDER)
        top_bar.pack(fill=tk.X)
        top_bar.pack_propagate(False)

        # Title & Subtitle Left
        title_box = tk.Frame(top_bar, bg=Theme.BG_HEADER, padx=22)
        title_box.pack(side=tk.LEFT, fill=tk.Y, pady=10)

        self.lbl_top_title = tk.Label(title_box, text="Security Posture Dashboard",
                                      font=("Segoe UI", 13, "bold"), fg=Theme.TEXT_WHITE, bg=Theme.BG_HEADER)
        self.lbl_top_title.pack(anchor="w")

        self.lbl_top_sub = tk.Label(title_box, text="Comprehensive system audit across 9 security vectors",
                                    font=("Segoe UI", 8), fg=Theme.TEXT_MUTED, bg=Theme.BG_HEADER)
        self.lbl_top_sub.pack(anchor="w", pady=(1, 0))

        # Action Buttons Right
        btn_box = tk.Frame(top_bar, bg=Theme.BG_HEADER, padx=20)
        btn_box.pack(side=tk.RIGHT, fill=tk.Y, pady=12)

        # Primary RUN SCAN Button (Emerald Glowing Pill)
        self.btn_run_scan = ModernButton(
            btn_box, text="RUN AUDIT", command=self.start_system_audit,
            bg_color="#059669", fg_color=Theme.TEXT_WHITE, hover_bg="#10B981",
            border_color="#047857", icon="🚀", padx=16, pady=6
        )
        self.btn_run_scan.pack(side=tk.LEFT, padx=5)

        # Clear View Button
        btn_clear = ModernButton(
            btn_box, text="Clear", command=self.clear_view,
            bg_color=Theme.BG_CARD, fg_color=Theme.TEXT_MUTED, hover_bg=Theme.BG_CARD_LIGHT,
            hover_fg=Theme.TEXT_WHITE, icon="🧹", padx=10, pady=6
        )
        btn_clear.pack(side=tk.LEFT, padx=5)

        # Load Saved Scan Button
        btn_load = ModernButton(
            btn_box, text="Load Prior", command=self._load_latest_report,
            bg_color=Theme.BG_CARD, fg_color=Theme.TEXT_MUTED, hover_bg=Theme.BG_CARD_LIGHT,
            hover_fg=Theme.BLUE, icon="📂", padx=10, pady=6
        )
        btn_load.pack(side=tk.LEFT, padx=5)

        # HTML Report Button
        btn_html = ModernButton(
            btn_box, text="HTML Report", command=self.open_html_report,
            bg_color=Theme.BG_CARD, fg_color=Theme.CYAN, hover_bg=Theme.BG_CARD_LIGHT,
            icon="📄", padx=10, pady=6
        )
        btn_html.pack(side=tk.LEFT, padx=5)

        # PDF Report Button
        btn_pdf = ModernButton(
            btn_box, text="Encrypted PDF", command=self.open_pdf_report,
            bg_color=Theme.BG_CARD, fg_color=Theme.PURPLE, hover_bg=Theme.BG_CARD_LIGHT,
            icon="🔒", padx=10, pady=6
        )
        btn_pdf.pack(side=tk.LEFT, padx=5)

    # -------------------------------------------------------------
    # PAGE 1: DASHBOARD
    # -------------------------------------------------------------
    def _create_dashboard_page(self):
        page = tk.Frame(self.page_container, bg=Theme.BG_MAIN)

        # 1. Top Cards Row (Score Gauge + 4 Severity Stat Cards)
        top_row = tk.Frame(page, bg=Theme.BG_MAIN)
        top_row.pack(fill=tk.X, pady=(0, 14))

        # Left: Donut Gauge Card
        gauge_card = tk.Frame(top_row, bg=Theme.BG_CARD, highlightthickness=1,
                              highlightbackground=Theme.BORDER, width=280, height=170)
        gauge_card.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 12))
        gauge_card.pack_propagate(False)

        # Gauge Card Header
        gc_hdr = tk.Frame(gauge_card, bg=Theme.BG_CARD, padx=14, pady=10)
        gc_hdr.pack(fill=tk.X)
        tk.Label(gc_hdr, text="COMPLIANCE RISK SCORE", font=("Segoe UI", 8, "bold"),
                 fg=Theme.BLUE, bg=Theme.BG_CARD).pack(side=tk.LEFT)
        self.lbl_last_scan_badge = tk.Label(gc_hdr, text="AWAITING AUDIT", font=("Segoe UI", 7, "bold"),
                                            fg=Theme.TEXT_MUTED, bg=Theme.BG_CARD_LIGHT, padx=6, pady=2)
        self.lbl_last_scan_badge.pack(side=tk.RIGHT)

        # Circular Gauge Canvas Widget
        self.gauge_widget = CircularGauge(gauge_card, size=120)
        self.gauge_widget.pack(expand=True, pady=(0, 6))

        # Right: Severity Counters (4 Cards)
        sev_container = tk.Frame(top_row, bg=Theme.BG_MAIN)
        sev_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.sev_cards = {}
        sev_data = [
            ("CRITICAL", Theme.RED, "Immediate action required"),
            ("HIGH", Theme.ROSE, "Severe posture misconfiguration"),
            ("MEDIUM", Theme.AMBER, "Suspicious persistence / drift"),
            ("LOW", Theme.BLUE, "Informational & policy hygiene")
        ]

        for i, (name, color, desc) in enumerate(sev_data):
            card = tk.Frame(sev_container, bg=Theme.BG_CARD, highlightthickness=1,
                            highlightbackground=Theme.BORDER)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0 if i == 0 else 8, 0))

            # Top glowing color bar
            bar = tk.Frame(card, bg=color, height=3)
            bar.pack(fill=tk.X)

            c_inner = tk.Frame(card, bg=Theme.BG_CARD, padx=14, pady=12)
            c_inner.pack(fill=tk.BOTH, expand=True)

            tk.Label(c_inner, text=name, font=("Segoe UI", 8, "bold"),
                     fg=Theme.TEXT_MUTED, bg=Theme.BG_CARD, anchor="w").pack(fill=tk.X)

            lbl_val = tk.Label(c_inner, text="0", font=("Segoe UI", 26, "bold"),
                               fg=color, bg=Theme.BG_CARD, anchor="w")
            lbl_val.pack(fill=tk.X, pady=(4, 0))

            tk.Label(c_inner, text=desc, font=("Segoe UI", 7),
                     fg=Theme.TEXT_MUTED, bg=Theme.BG_CARD, anchor="w").pack(fill=tk.X, pady=(4, 0))

            self.sev_cards[name] = lbl_val

        # 1.5. Remote Intrusion & Reverse Shell Guard Banner
        self.remote_banner = tk.Frame(page, bg=Theme.BG_CARD, highlightthickness=1,
                                      highlightbackground=Theme.BORDER, padx=14, pady=10)
        self.remote_banner.pack(fill=tk.X, pady=(0, 12))

        rb_left = tk.Frame(self.remote_banner, bg=Theme.BG_CARD)
        rb_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.lbl_remote_icon = tk.Label(rb_left, text="🛡️", font=("Segoe UI", 16),
                                        fg=Theme.CYAN, bg=Theme.BG_CARD)
        self.lbl_remote_icon.pack(side=tk.LEFT, padx=(0, 12))

        rb_text = tk.Frame(rb_left, bg=Theme.BG_CARD)
        rb_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.lbl_remote_title = tk.Label(rb_text, text="REMOTE INTRUSION SHIELD: READY",
                                         font=("Segoe UI", 9, "bold"), fg=Theme.TEXT_WHITE, bg=Theme.BG_CARD, anchor="w")
        self.lbl_remote_title.pack(fill=tk.X)

        self.lbl_remote_desc = tk.Label(rb_text, text="Auditing active reverse shell sockets, covert RDP shadowing, concurrent backdoors & abusive RMM tools.",
                                        font=("Segoe UI", 8), fg=Theme.TEXT_MUTED, bg=Theme.BG_CARD, anchor="w")
        self.lbl_remote_desc.pack(fill=tk.X, pady=(2, 0))

        # Right Action Container
        self.rb_actions = tk.Frame(self.remote_banner, bg=Theme.BG_CARD)
        self.rb_actions.pack(side=tk.RIGHT)

        self.btn_remote_check = ModernButton(
            self.rb_actions, text="Quick Remote Check", command=self.run_quick_remote_check,
            bg_color=Theme.BG_CARD_LIGHT, fg_color=Theme.CYAN, hover_bg="#222B42",
            icon="⚡", padx=10, pady=4
        )
        self.btn_remote_check.pack(side=tk.LEFT, padx=4)

        self.btn_remote_sever = ModernButton(
            self.rb_actions, text="Sever Threats", command=self.sever_remote_threats,
            bg_color="#7F1D1D", fg_color=Theme.TEXT_WHITE, hover_bg="#DC2626",
            icon="🛑", padx=10, pady=4
        )

        # 2. Bottom Grid: 9 Security Modules Vector Cards
        mod_panel = tk.Frame(page, bg=Theme.BG_CARD, highlightthickness=1, highlightbackground=Theme.BORDER)
        mod_panel.pack(fill=tk.BOTH, expand=True)

        mp_hdr = tk.Frame(mod_panel, bg=Theme.BG_CARD, padx=16, pady=12)
        mp_hdr.pack(fill=tk.X)

        tk.Label(mp_hdr, text="SECURITY POSTURE VECTORS (9 AUDIT MODULES)", font=("Segoe UI", 9, "bold"),
                 fg=Theme.TEXT_WHITE, bg=Theme.BG_CARD).pack(side=tk.LEFT)
        tk.Label(mp_hdr, text="Pure CIM/WMI • Read-Only • Zero Network Lag", font=("Segoe UI", 8),
                 fg=Theme.TEXT_MUTED, bg=Theme.BG_CARD).pack(side=tk.RIGHT)

        grid_frame = tk.Frame(mod_panel, bg=Theme.BG_CARD, padx=12, pady=6)
        grid_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 12))

        self.module_widgets = {}
        modules_info = [
            ("defender_health", "🛡️ Defender Health", "Real-time protection, tamper lock, exclusions"),
            ("remote_access", "🔌 Remote Access", "Open RDP ports, active sessions, WinRM tools"),
            ("network", "🌐 Network Analysis", "Listening ports, unowned TCP connections"),
            ("persistence", "🪤 Persistence Engine", "Run keys, startup scripts, IFEO hijackers"),
            ("accounts", "👥 Account Governance", "Local admin group, empty/non-expiring passwords"),
            ("patching", "🩹 Patch Currency", "Installed Windows hotfixes & build readiness"),
            ("defender_activity", "🚨 Defender Activity", "Threat detection history & remediation log"),
            ("system_health", "💻 System Health", "Physical disk SMART, TPM 2.0, Restore points"),
            ("behavioral_analysis", "🧠 Behavioral Analysis", "Offline anomaly score, LotL shell lineages")
        ]

        for idx, (mod_id, title, desc) in enumerate(modules_info):
            r, c = divmod(idx, 3)
            box = tk.Frame(grid_frame, bg=Theme.BG_CARD_LIGHT, highlightthickness=1,
                           highlightbackground=Theme.BORDER, padx=12, pady=10)
            box.grid(row=r, column=c, sticky="nsew", padx=4, pady=4)
            grid_frame.grid_columnconfigure(c, weight=1)
            grid_frame.grid_rowconfigure(r, weight=1)

            # Top: title & status pill
            hdr = tk.Frame(box, bg=Theme.BG_CARD_LIGHT)
            hdr.pack(fill=tk.X)

            tk.Label(hdr, text=title, font=("Segoe UI", 9, "bold"),
                     fg=Theme.TEXT_WHITE, bg=Theme.BG_CARD_LIGHT).pack(side=tk.LEFT)

            pill = tk.Label(hdr, text="READY", font=("Segoe UI", 7, "bold"),
                            fg=Theme.TEXT_MUTED, bg="#111422", padx=6, pady=2)
            pill.pack(side=tk.RIGHT)

            tk.Label(box, text=desc, font=("Segoe UI", 8),
                     fg=Theme.TEXT_MUTED, bg=Theme.BG_CARD_LIGHT, anchor="w").pack(fill=tk.X, pady=(6, 0))

            self.module_widgets[mod_id] = pill

        return page

    # -------------------------------------------------------------
    # PAGE 2: BEHAVIORAL SHIELD
    # -------------------------------------------------------------
    def _create_behavioral_page(self):
        page = tk.Frame(self.page_container, bg=Theme.BG_MAIN)

        # Top Control Card
        ctrl_card = tk.Frame(page, bg=Theme.BG_CARD, highlightthickness=1,
                             highlightbackground=Theme.BORDER, padx=16, pady=12)
        ctrl_card.pack(fill=tk.X, pady=(0, 12))

        # Status & Duration Selector
        left_ctrl = tk.Frame(ctrl_card, bg=Theme.BG_CARD)
        left_ctrl.pack(side=tk.LEFT)

        self.lbl_beh_status_pill = tk.Label(
            left_ctrl, text="● BASELINE: AWAITING CALIBRATION",
            font=("Segoe UI", 8, "bold"), fg=Theme.AMBER, bg=Theme.BG_CARD_LIGHT,
            padx=10, pady=4
        )
        self.lbl_beh_status_pill.pack(side=tk.LEFT, padx=(0, 15))

        tk.Label(left_ctrl, text="Learn Duration:", font=("Segoe UI", 8),
                 fg=Theme.TEXT_MUTED, bg=Theme.BG_CARD).pack(side=tk.LEFT, padx=(0, 4))

        self.learn_duration_var = tk.StringVar(value="30")
        dur_box = ttk.Combobox(left_ctrl, textvariable=self.learn_duration_var,
                               values=["15", "30", "60", "120"], width=3, state="readonly")
        dur_box.pack(side=tk.LEFT, padx=(0, 2))
        tk.Label(left_ctrl, text="s", font=("Segoe UI", 8), fg=Theme.TEXT_MUTED, bg=Theme.BG_CARD).pack(side=tk.LEFT, padx=(0, 12))

        # Calibration Button
        btn_learn = ModernButton(
            left_ctrl, text="Learn Normal Baseline", command=self.start_learning_baseline,
            bg_color="#1E3A8A", fg_color=Theme.TEXT_WHITE, hover_bg="#2563EB",
            icon="🧠", padx=12, pady=5
        )
        btn_learn.pack(side=tk.LEFT, padx=4)

        # On-Demand Scan
        btn_scan = ModernButton(
            left_ctrl, text="Scan Anomalies Now", command=self.scan_behavioral_anomalies,
            bg_color=Theme.BG_CARD_LIGHT, fg_color=Theme.CYAN, hover_bg="#222B42",
            icon="⚡", padx=12, pady=5
        )
        btn_scan.pack(side=tk.LEFT, padx=4)

        # Live Shield Toggle (Right)
        right_ctrl = tk.Frame(ctrl_card, bg=Theme.BG_CARD)
        right_ctrl.pack(side=tk.RIGHT)

        self.btn_live_shield = tk.Button(
            right_ctrl, text="🛡️  Live Shield: OFF", font=("Segoe UI", 9, "bold"),
            bg=Theme.BG_CARD_LIGHT, fg=Theme.TEXT_MUTED, activebackground="#252C47",
            activeforeground=Theme.TEXT_WHITE, bd=1, relief="solid", padx=14, pady=5,
            cursor="hand2", command=self.toggle_live_shield
        )
        self.btn_live_shield.pack(side=tk.RIGHT)

        # Behavioral Findings Table
        table_frame = tk.Frame(page, bg=Theme.BG_CARD, highlightthickness=1, highlightbackground=Theme.BORDER)
        table_frame.pack(fill=tk.BOTH, expand=True)

        # Table Header Bar
        tb_hdr = tk.Frame(table_frame, bg=Theme.BG_CARD, padx=14, pady=10)
        tb_hdr.pack(fill=tk.X)

        tk.Label(tb_hdr, text="FLAGGED BEHAVIORAL THREATS & LOTL ANOMALIES", font=("Segoe UI", 9, "bold"),
                 fg=Theme.TEXT_WHITE, bg=Theme.BG_CARD).pack(side=tk.LEFT)

        btn_term = ModernButton(
            tb_hdr, text="Terminate Selected Process", command=self.terminate_selected_process,
            bg_color="#7F1D1D", fg_color=Theme.TEXT_WHITE, hover_bg="#991B1B",
            icon="⛔", padx=12, pady=4
        )
        btn_term.pack(side=tk.RIGHT)

        # Treeview
        cols = ("severity", "score", "process", "pid", "parent", "reasons")
        self.beh_tree = ttk.Treeview(table_frame, columns=cols, show="headings", style="Cyber.Treeview")

        self.beh_tree.heading("severity", text="SEVERITY")
        self.beh_tree.heading("score", text="SCORE")
        self.beh_tree.heading("process", text="PROCESS NAME")
        self.beh_tree.heading("pid", text="PID")
        self.beh_tree.heading("parent", text="PARENT PROCESS")
        self.beh_tree.heading("reasons", text="ANOMALY INDICATORS")

        self.beh_tree.column("severity", width=90, anchor="center")
        self.beh_tree.column("score", width=70, anchor="center")
        self.beh_tree.column("process", width=140)
        self.beh_tree.column("pid", width=70, anchor="center")
        self.beh_tree.column("parent", width=140)
        self.beh_tree.column("reasons", width=460)

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.beh_tree.yview, style="Vertical.TScrollbar")
        self.beh_tree.configure(yscroll=scrollbar.set)

        self.beh_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.beh_tree.bind("<Double-1>", self.on_behavioral_item_select)

        # Tag colors
        self.beh_tree.tag_configure("critical", foreground=Theme.RED)
        self.beh_tree.tag_configure("high", foreground=Theme.ROSE)
        self.beh_tree.tag_configure("medium", foreground=Theme.AMBER)
        self.beh_tree.tag_configure("low", foreground=Theme.BLUE)

        return page

    # -------------------------------------------------------------
    # PAGE 3: FINDINGS EXPLORER
    # -------------------------------------------------------------
    def _create_findings_page(self):
        page = tk.Frame(self.page_container, bg=Theme.BG_MAIN)

        # Filter Card
        filter_card = tk.Frame(page, bg=Theme.BG_CARD, highlightthickness=1,
                               highlightbackground=Theme.BORDER, padx=16, pady=10)
        filter_card.pack(fill=tk.X, pady=(0, 12))

        tk.Label(filter_card, text="Filter Severity:", font=("Segoe UI", 8, "bold"),
                 fg=Theme.TEXT_MUTED, bg=Theme.BG_CARD).pack(side=tk.LEFT, padx=(0, 10))

        self.filter_var = tk.StringVar(value="ALL")
        for val in ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            rb = tk.Radiobutton(
                filter_card, text=val, variable=self.filter_var, value=val,
                bg=Theme.BG_CARD, fg=Theme.TEXT_WHITE, selectcolor=Theme.BG_CARD_LIGHT,
                activebackground=Theme.BG_CARD, activeforeground=Theme.CYAN,
                font=("Segoe UI", 8), command=self.populate_findings_table
            )
            rb.pack(side=tk.LEFT, padx=6)

        # Table Container
        tree_card = tk.Frame(page, bg=Theme.BG_CARD, highlightthickness=1, highlightbackground=Theme.BORDER)
        tree_card.pack(fill=tk.BOTH, expand=True)

        cols = ("id", "severity", "module", "title", "detail")
        self.findings_tree = ttk.Treeview(tree_card, columns=cols, show="headings", style="Cyber.Treeview")

        self.findings_tree.heading("id", text="ID")
        self.findings_tree.heading("severity", text="SEVERITY")
        self.findings_tree.heading("module", text="MODULE")
        self.findings_tree.heading("title", text="FINDING TITLE")
        self.findings_tree.heading("detail", text="DETAIL SUMMARY")

        self.findings_tree.column("id", width=80, anchor="center")
        self.findings_tree.column("severity", width=95, anchor="center")
        self.findings_tree.column("module", width=150)
        self.findings_tree.column("title", width=280)
        self.findings_tree.column("detail", width=420)

        scrollbar = ttk.Scrollbar(tree_card, orient=tk.VERTICAL, command=self.findings_tree.yview, style="Vertical.TScrollbar")
        self.findings_tree.configure(yscroll=scrollbar.set)

        self.findings_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.findings_tree.bind("<Double-1>", self.on_finding_item_select)

        # Colors
        self.findings_tree.tag_configure("critical", foreground=Theme.RED)
        self.findings_tree.tag_configure("high", foreground=Theme.ROSE)
        self.findings_tree.tag_configure("medium", foreground=Theme.AMBER)
        self.findings_tree.tag_configure("low", foreground=Theme.BLUE)
        self.findings_tree.tag_configure("info", foreground=Theme.TEXT_MUTED)

        return page

    # -------------------------------------------------------------
    # PAGE 4: LOGS & CONSOLE
    # -------------------------------------------------------------
    def _create_logs_page(self):
        page = tk.Frame(self.page_container, bg=Theme.BG_MAIN)

        log_card = tk.Frame(page, bg=Theme.BG_CARD, highlightthickness=1, highlightbackground=Theme.BORDER)
        log_card.pack(fill=tk.BOTH, expand=True)

        hdr = tk.Frame(log_card, bg=Theme.BG_CARD, padx=16, pady=10)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="SYSTEM TELEMETRY CONSOLE STREAM", font=("Segoe UI", 9, "bold"),
                 fg=Theme.TEXT_WHITE, bg=Theme.BG_CARD).pack(side=tk.LEFT)

        self.log_text = tk.Text(log_card, bg="#08090E", fg=Theme.GREEN, insertbackground=Theme.CYAN,
                                font=("Consolas", 9), wrap="word", bd=0, padx=16, pady=14)
        scrollbar = ttk.Scrollbar(log_card, orient=tk.VERTICAL, command=self.log_text.yview, style="Vertical.TScrollbar")
        self.log_text.configure(yscroll=scrollbar.set)

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.log("SentinelIQ Desktop Interface initialized.")
        self.log("Powered by WinSentry Security Posture Engine.")
        self.log("Ready for air-gapped auditing and offline behavioral protection.")

        return page

    def log(self, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)

    # -------------------------------------------------------------
    # LOGIC & ACTIONS
    # -------------------------------------------------------------
    def clear_view(self):
        """Resets the dashboard to clean, uncalculated initial state."""
        self.report_data = None
        self.detected_remote_threats = []
        self.gauge_widget.set_score(None)

        for card in self.sev_cards.values():
            card.config(text="0")

        for pill in self.module_widgets.values():
            pill.config(text="READY", fg=Theme.TEXT_MUTED, bg="#111422")

        self.lbl_last_scan_badge.config(text="AWAITING AUDIT", fg=Theme.TEXT_MUTED, bg=Theme.BG_CARD_LIGHT)

        # Reset remote intrusion banner
        bg_idle = Theme.BG_CARD
        if hasattr(self, "remote_banner"):
            self.remote_banner.config(bg=bg_idle, highlightbackground=Theme.BORDER)
            for w in (self.remote_banner, self.lbl_remote_icon.master, self.lbl_remote_title.master, self.rb_actions):
                try:
                    w.config(bg=bg_idle)
                except Exception:
                    pass
            self.lbl_remote_icon.config(text="🛡️", fg=Theme.CYAN, bg=bg_idle)
            self.lbl_remote_title.config(text="REMOTE INTRUSION SHIELD: AWAITING AUDIT", fg=Theme.TEXT_WHITE, bg=bg_idle)
            self.lbl_remote_desc.config(
                text="Auditing active reverse shell sockets, covert RDP shadowing, concurrent backdoors & abusive RMM tools.",
                fg=Theme.TEXT_MUTED, bg=bg_idle
            )
            self.btn_remote_sever.pack_forget()

        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)

        for item in self.beh_tree.get_children():
            self.beh_tree.delete(item)

        self.log("[*] Dashboard view reset. Ready for scan.")

    def _update_baseline_status(self):
        baseline_file = SCRIPT_DIR / DEFAULT_BASELINE_FILE
        if baseline_file.exists():
            try:
                with open(baseline_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                count = data.get("metadata", {}).get("total_unique_processes", len(data.get("known_processes", {})))
                self.lbl_sidebar_baseline.config(text=f"● BASELINE: {count} PROCS", fg=Theme.GREEN)
                self.lbl_beh_status_pill.config(text=f"● BASELINE: {count} PROCS LEARNED", fg=Theme.GREEN)
            except Exception:
                self.lbl_sidebar_baseline.config(text="● BASELINE: READY", fg=Theme.GREEN)
                self.lbl_beh_status_pill.config(text="● BASELINE: READY", fg=Theme.GREEN)
        else:
            self.lbl_sidebar_baseline.config(text="● BASELINE: NOT LEARNED", fg=Theme.AMBER)
            self.lbl_beh_status_pill.config(text="● BASELINE: NOT LEARNED", fg=Theme.AMBER)

    def _load_latest_report(self):
        if not JSON_REPORT_FILE.exists():
            messagebox.showinfo("No Saved Report", "No previous report file found on disk.")
            return
        try:
            with open(JSON_REPORT_FILE, "r", encoding="utf-8-sig") as f:
                self.report_data = json.load(f)
            self._update_dashboard_metrics()
            self.populate_findings_table()
            self.log("[+] Loaded previous report from winsentry_report.json")
        except Exception as e:
            self.log(f"Error reading report: {e}")

    def _update_dashboard_metrics(self):
        if not self.report_data:
            return

        risk_score = self.report_data.get("risk_score", 0)
        self.gauge_widget.set_score(risk_score)

        # Count severities
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        modules = self.report_data.get("modules", {})
        for mod_name, mod_data in modules.items():
            findings = mod_data.get("findings", [])
            for f in findings:
                s = f.get("severity", "").upper()
                if s in sev_counts:
                    sev_counts[s] += 1

            # Update module status pill
            if mod_name in self.module_widgets:
                stat = mod_data.get("status", "ok")
                find_cnt = len(findings)
                pill = self.module_widgets[mod_name]
                if stat == "skipped":
                    pill.config(text="SKIPPED", fg=Theme.AMBER, bg="#2A2415")
                elif find_cnt > 0:
                    badge_col = Theme.RED if find_cnt >= 2 else Theme.AMBER
                    pill.config(text=f"{find_cnt} FINDINGS", fg=badge_col, bg="#2D171A")
                else:
                    pill.config(text="CLEAN", fg=Theme.GREEN, bg="#0E271D")

        for sev, count in sev_counts.items():
            if sev in self.sev_cards:
                self.sev_cards[sev].config(text=str(count))

        scan_time = self.report_data.get("scan_metadata", {}).get("scan_time_utc", "Unknown")
        self.lbl_last_scan_badge.config(
            text=f"SCANNED: {scan_time[11:19]} UTC",
            fg=Theme.BLUE, bg=Theme.BG_CARD_LIGHT
        )

        # Evaluate Remote Control posture from report
        rem_findings = modules.get("remote_access", {}).get("findings", [])
        rem_threats = []
        for f in rem_findings:
            fid = f.get("id", "")
            fsev = f.get("severity", "").upper()
            if fid.startswith("REM-SHELL") or fid.startswith("REM-ACT") or fid in ("REM-SHADOW", "REM-CONCUR") or (fid == "REM-04" and fsev in ("HIGH", "CRITICAL")):
                rem_threats.append({
                    "type": "report_finding",
                    "name": f.get("title", fid),
                    "pid": None,
                    "detail": f.get("title", "") + ": " + f.get("detail", "").split("\n")[0],
                    "remediation": f.get("remediation_command", "")
                })
        self._apply_remote_status(rem_threats)

    # -------------------------------------------------------------
    # REMOTE INTRUSION & MALICIOUS CONTROL DEFENSE
    # -------------------------------------------------------------
    def run_quick_remote_check(self):
        """Runs a fast (1-2s) live inspection for active reverse shells, RMM tools, and RDP shadowing."""
        self.log("[*] Running quick remote intrusion audit (active sockets, RMM tools & registry)...")
        self.lbl_remote_desc.config(text="Auditing established network sockets, interactive shells & remote management tools...")
        threading.Thread(target=self._quick_remote_check_worker, daemon=True).start()

    def _quick_remote_check_worker(self):
        threats = []
        try:
            # 1. Check established connections on shell interpreters & running RMM tools
            if collect_established_connections and collect_process_telemetry:
                conns = collect_established_connections()
                procs = collect_process_telemetry()
                for p in procs:
                    pid = p.get("ProcessId")
                    name = (p.get("Name") or "").strip()
                    name_lower = name.lower()
                    path = p.get("ExecutablePath") or ""

                    # Active reverse shell check (shell with established non-loopback socket)
                    if pid in conns and name_lower in SUSPICIOUS_SPAWNS:
                        endpoints = ", ".join(conns[pid][:3])
                        threats.append({
                            "type": "reverse_shell",
                            "name": name,
                            "pid": pid,
                            "detail": f"Active reverse shell socket: {name} (PID: {pid}) -> {endpoints}",
                            "remediation": f"Stop-Process -Id {pid} -Force"
                        })

                    # Active remote control tool check
                    if name_lower in REMOTE_CONTROL_TOOLS:
                        endpoints = f" [Connected to: {', '.join(conns[pid][:2])}]" if pid in conns else ""
                        threats.append({
                            "type": "remote_tool",
                            "name": name,
                            "pid": pid,
                            "detail": f"Remote control tool active in memory: {name} (PID: {pid}){endpoints}",
                            "remediation": f"Stop-Process -Id {pid} -Force"
                        })

            # 2. Check covert RDP shadowing policy in registry
            if winreg:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services") as key:
                        val, _ = winreg.QueryValueEx(key, "Shadow")
                        if val in (1, 3):
                            desc = "Full Control without user consent" if val == 1 else "View Session without user consent"
                            threats.append({
                                "type": "shadow",
                                "name": "RDP Shadowing",
                                "pid": None,
                                "detail": f"Covert RDP Shadowing enabled (Shadow={val}: {desc})",
                                "remediation": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' -Name 'Shadow' -Value 0"
                            })
                except Exception:
                    pass

                # 3. Check concurrent RDP session backdoor
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Control\Terminal Server") as key:
                        val, _ = winreg.QueryValueEx(key, "fSingleSessionPerUser")
                        if val == 0:
                            threats.append({
                                "type": "concur",
                                "name": "Concurrent RDP",
                                "pid": None,
                                "detail": "Concurrent RDP sessions enabled (fSingleSessionPerUser=0: silent parallel logons)",
                                "remediation": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fSingleSessionPerUser' -Value 1"
                            })
                except Exception:
                    pass

        except Exception as e:
            self.after(0, self.log, f"[!] Quick remote check error: {e}")

        self.after(0, self._apply_remote_status, threats)

    def _apply_remote_status(self, threats):
        self.detected_remote_threats = threats
        pill = self.module_widgets.get("remote_access")

        if threats:
            bg_alert = "#2D1216"
            self.remote_banner.config(bg=bg_alert, highlightbackground=Theme.RED)
            for w in (self.remote_banner, self.lbl_remote_icon.master, self.lbl_remote_title.master, self.rb_actions):
                try:
                    w.config(bg=bg_alert)
                except Exception:
                    pass

            self.lbl_remote_icon.config(text="🚨", fg=Theme.RED, bg=bg_alert)
            self.lbl_remote_title.config(
                text=f"CRITICAL ALERT: {len(threats)} UNAUTHORIZED REMOTE CONTROL THREAT(S) DETECTED!",
                fg=Theme.RED, bg=bg_alert
            )

            summary = " | ".join(t["detail"] for t in threats[:2])
            if len(threats) > 2:
                summary += f" (+{len(threats)-2} more)"

            self.lbl_remote_desc.config(text=summary, fg=Theme.TEXT_WHITE, bg=bg_alert)
            self.btn_remote_sever.pack(side=tk.LEFT, padx=4)

            if pill:
                pill.config(text=f"{len(threats)} THREATS", fg=Theme.RED, bg="#2D171A")

            self.log(f"[!] REMOTE ACCESS ALERT: {len(threats)} unauthorized remote threat(s) active:")
            for t in threats:
                self.log(f"    -> {t['detail']}")
        else:
            bg_clean = "#0A2218"
            self.remote_banner.config(bg=bg_clean, highlightbackground=Theme.GREEN)
            for w in (self.remote_banner, self.lbl_remote_icon.master, self.lbl_remote_title.master, self.rb_actions):
                try:
                    w.config(bg=bg_clean)
                except Exception:
                    pass

            self.lbl_remote_icon.config(text="🟢", fg=Theme.GREEN, bg=bg_clean)
            self.lbl_remote_title.config(
                text="REMOTE ACCESS SECURE: NO UNAUTHORIZED CONTROL DETECTED",
                fg=Theme.GREEN, bg=bg_clean
            )
            self.lbl_remote_desc.config(
                text="Zero active reverse shell sockets • RDP shadowing disabled • No suspicious RMM tools active.",
                fg=Theme.TEXT_SECONDARY, bg=bg_clean
            )
            self.btn_remote_sever.pack_forget()

            if pill and pill.cget("text") == "READY":
                pill.config(text="CLEAN", fg=Theme.GREEN, bg="#0E271D")

            self.log("[+] Remote access status: Clean. No unauthorized remote control sessions detected.")

    def sever_remote_threats(self):
        if not self.detected_remote_threats:
            messagebox.showinfo("No Threats", "No active remote threats currently detected.")
            return

        threat_list_msg = "\n".join(f"• {t['detail']}" for t in self.detected_remote_threats)
        msg = (
            f"SentinelIQ has identified the following active remote control threats:\n\n"
            f"{threat_list_msg}\n\n"
            f"Do you want to immediately SEVER these sessions, terminate the processes, and restore secure registry policies?"
        )
        if not messagebox.askyesno("Confirm Sever & Terminate", msg, icon="warning"):
            return

        self.log("[*] Executing emergency threat sever action...")
        for t in self.detected_remote_threats:
            cmd = t.get("remediation")
            if cmd:
                try:
                    subprocess.run(["powershell", "-NoProfile", "-Command", cmd], check=True)
                    self.log(f"[+] Successfully executed: {cmd}")
                except Exception as e:
                    self.log(f"[!] Failed to execute remediation: {e}")

        messagebox.showinfo("Sever Complete", "Remediation commands executed. Verifying remote access posture now...")
        self.run_quick_remote_check()

    def populate_findings_table(self):
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)

        if not self.report_data:
            return

        filter_sev = self.filter_var.get()
        modules = self.report_data.get("modules", {})

        for mod_name, mod_data in modules.items():
            for f in mod_data.get("findings", []):
                sev = f.get("severity", "INFO")
                if filter_sev != "ALL" and sev != filter_sev:
                    continue

                fid = f.get("id", "")
                title = f.get("title", "")
                detail = f.get("detail", "").replace("\n", "  |  ")

                tag = sev.lower()
                item_id = self.findings_tree.insert("", tk.END, values=(fid, sev, mod_name.replace("_", " ").title(), title, detail), tags=(tag,))
                self.findings_tree.item(item_id, tags=(tag,))

    # -------------------------------------------------------------
    # SYSTEM AUDIT EXECUTION
    # -------------------------------------------------------------
    def start_system_audit(self):
        if self.active_scan_thread and self.active_scan_thread.is_alive():
            messagebox.showinfo("Scan in Progress", "A system audit is already running.")
            return

        self.log("[*] Launching WinSentry posture auditor...")
        self.lbl_top_sub.config(text="Running full security audit across 9 vectors...", fg=Theme.CYAN)

        self.active_scan_thread = threading.Thread(target=self._run_audit_worker, daemon=True)
        self.active_scan_thread.start()

    def _run_audit_worker(self):
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", str(PS_SCANNER_FILE),
            "-NoPrompt"
        ]
        try:
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=str(SCRIPT_DIR), startupinfo=startupinfo
            )

            for line in proc.stdout:
                l_str = line.strip()
                if l_str:
                    self.after(0, self.log, l_str)

            proc.wait()
            self.after(0, self._on_audit_complete)
        except Exception as e:
            self.after(0, self.log, f"Scan Error: {e}")
            self.after(0, self._on_audit_complete)

    def _on_audit_complete(self):
        self.log("[+] Posture audit finished successfully.")
        self.lbl_top_sub.config(text="Comprehensive system audit across 9 security vectors", fg=Theme.TEXT_MUTED)
        self._load_latest_report()
        messagebox.showinfo("Audit Complete", "SentinelIQ posture audit finished!\nReports updated.")

    # -------------------------------------------------------------
    # BEHAVIORAL CALIBRATION & ANOMALY SCAN
    # -------------------------------------------------------------
    def start_learning_baseline(self):
        if not self.behavioral_engine:
            messagebox.showerror("Error", "Behavioral engine module not available.")
            return

        try:
            dur = int(self.learn_duration_var.get())
        except ValueError:
            dur = 30

        self.log(f"[*] Commencing baseline calibration phase ({dur}s)...")
        self.lbl_beh_status_pill.config(text=f"● CALIBRATING BASELINE ({dur}s)...", fg=Theme.CYAN)

        threading.Thread(target=self._learn_worker, args=(dur,), daemon=True).start()

    def _learn_worker(self, duration):
        def cb(elapsed, total, count):
            self.after(0, self.lbl_beh_status_pill.config, {"text": f"● SAMPLING ({elapsed}/{total}s) - {count} PROCS"})

        self.behavioral_engine.learn_baseline(duration_seconds=duration, interval_seconds=3, callback=cb)
        self.after(0, self._on_learn_complete)

    def _on_learn_complete(self):
        self.log("[+] Offline behavioral baseline successfully written to winsentry_baseline.json")
        self._update_baseline_status()
        messagebox.showinfo("Baseline Calibrated", "Usual system behavior has been calibrated and saved offline!")

    def scan_behavioral_anomalies(self):
        if not self.behavioral_engine:
            messagebox.showerror("Error", "Behavioral engine module not available.")
            return

        self.log("[*] Scanning running processes against baseline...")
        threading.Thread(target=self._scan_behavioral_worker, daemon=True).start()

    def _scan_behavioral_worker(self):
        findings = self.behavioral_engine.detect_anomalies(sensitivity="medium")
        self.after(0, self._populate_behavioral_tree, findings)

    def _populate_behavioral_tree(self, findings):
        for item in self.beh_tree.get_children():
            self.beh_tree.delete(item)

        if not findings:
            self.log("[+] No behavioral anomalies detected! All processes align with baseline.")
            return

        self.log(f"[!] Flagged {len(findings)} behavioral anomalies:")
        for f in findings:
            sev = f.get("severity", "INFO")
            score = f.get("anomaly_score", 0)
            pname = f.get("process_name", "")
            pid = f.get("pid", "")
            detail = f.get("detail", "")
            parent = "Unknown"
            for line in detail.splitlines():
                if line.startswith("Parent:"):
                    parent = line.split(":", 1)[1].strip()

            reasons = f.get("title", "")
            tag = sev.lower()

            item_id = self.beh_tree.insert("", tk.END, values=(sev, f"{score}/100", pname, pid, parent, reasons), tags=(tag,))
            self.beh_tree.item(item_id, tags=(tag,))
            self.log(f" -> [{sev}] {pname} (PID: {pid}) - Score: {score}/100")

    def toggle_live_shield(self):
        if not self.live_shield_active:
            self.live_shield_active = True
            self.btn_live_shield.config(text="🛡️  Live Shield: ACTIVE", bg="#065F46", fg=Theme.GREEN)
            self.log("[*] Live Behavioral Shield ACTIVATED (Monitoring every 5s).")
            self.live_shield_thread = threading.Thread(target=self._live_shield_loop, daemon=True)
            self.live_shield_thread.start()
        else:
            self.live_shield_active = False
            self.btn_live_shield.config(text="🛡️  Live Shield: OFF", bg=Theme.BG_CARD_LIGHT, fg=Theme.TEXT_MUTED)
            self.log("[*] Live Behavioral Shield DEACTIVATED.")

    def _live_shield_loop(self):
        while self.live_shield_active:
            try:
                findings = self.behavioral_engine.detect_anomalies(sensitivity="medium")
                if findings:
                    self.after(0, self._populate_behavioral_tree, findings)
            except Exception:
                pass
            time.sleep(5)

    def terminate_selected_process(self):
        selected = self.beh_tree.selection()
        if not selected:
            messagebox.showinfo("Select Process", "Please select a process from the table first.")
            return

        values = self.beh_tree.item(selected[0], "values")
        pname, pid = values[2], values[3]

        if not messagebox.askyesno("Confirm Termination", f"Terminate process {pname} (PID: {pid})?"):
            return

        try:
            subprocess.run(["powershell", "-NoProfile", "-Command", f"Stop-Process -Id {pid} -Force"], check=True)
            self.log(f"[+] Terminated anomalous process {pname} (PID: {pid})")
            self.beh_tree.delete(selected[0])
            messagebox.showinfo("Terminated", f"Process {pname} (PID: {pid}) terminated.")
        except Exception as e:
            messagebox.showerror("Termination Failed", f"Failed to terminate PID {pid}: {e}")

    # -------------------------------------------------------------
    # MODAL DIALOGS & REPORT OPENERS
    # -------------------------------------------------------------
    def on_behavioral_item_select(self, event):
        selected = self.beh_tree.selection()
        if not selected:
            return
        values = self.beh_tree.item(selected[0], "values")
        pname, pid = values[2], values[3]
        messagebox.showinfo(
            f"Anomalous Process: {pname}",
            f"Process: {pname}\nPID: {pid}\nSeverity: {values[0]}\nScore: {values[1]}\nParent: {values[4]}\nIndicators: {values[5]}"
        )

    def on_finding_item_select(self, event):
        selected = self.findings_tree.selection()
        if not selected:
            return
        values = self.findings_tree.item(selected[0], "values")
        fid, sev, mod, title, detail = values

        # Look up recommendation and remediation_command in report_data
        remediation_cmd = ""
        recommendation = ""
        if self.report_data:
            for mod_key, mod_info in self.report_data.get("modules", {}).items():
                for f in mod_info.get("findings", []):
                    if f.get("id") == fid:
                        remediation_cmd = (f.get("remediation_command") or "").strip()
                        recommendation = (f.get("recommendation") or "").strip()
                        break

        win = tk.Toplevel(self)
        win.title(f"Finding Detail - {fid}")
        win.geometry("680x520")
        win.configure(bg=Theme.BG_ROOT)

        tk.Label(win, text=f"[{sev}] {title}", font=("Segoe UI", 11, "bold"),
                 fg=Theme.CYAN, bg=Theme.BG_ROOT, wraplength=640).pack(padx=20, pady=(20, 6), anchor="w")

        tk.Label(win, text=f"Module: {mod} | Finding ID: {fid}", font=("Segoe UI", 8),
                 fg=Theme.TEXT_MUTED, bg=Theme.BG_ROOT).pack(padx=20, anchor="w")

        txt = tk.Text(win, bg=Theme.BG_CARD, fg=Theme.TEXT_WHITE, font=("Segoe UI", 9),
                      wrap="word", bd=1, padx=12, pady=12)
        txt.pack(fill=tk.BOTH, expand=True, padx=20, pady=12)

        content_text = detail.replace("  |  ", "\n")
        if recommendation:
            content_text += f"\n\n--- RECOMMENDATION ---\n{recommendation}"
        if remediation_cmd:
            content_text += f"\n\n--- REMEDIATION POWERSHELL COMMAND ---\n{remediation_cmd}"

        txt.insert(tk.END, content_text)
        txt.config(state="disabled")

        btn_row = tk.Frame(win, bg=Theme.BG_ROOT)
        btn_row.pack(fill=tk.X, padx=20, pady=(0, 16))

        if remediation_cmd:
            def _copy_cmd():
                self.clipboard_clear()
                self.clipboard_append(remediation_cmd)
                messagebox.showinfo("Copied", "Remediation command copied to clipboard.", parent=win)

            def _exec_remediation():
                if messagebox.askyesno("Confirm Remediation", f"Execute this PowerShell remediation command?\n\n{remediation_cmd}", parent=win):
                    try:
                        subprocess.run(["powershell", "-NoProfile", "-Command", remediation_cmd], check=True)
                        self.log(f"[+] Remediated finding {fid}: {remediation_cmd}")
                        messagebox.showinfo("Success", f"Remediation command for {fid} executed successfully.", parent=win)
                        win.destroy()
                        self.start_system_audit()
                    except Exception as err:
                        messagebox.showerror("Execution Failed", f"Command execution failed: {err}", parent=win)

            btn_exec = ModernButton(
                btn_row, text="Run Remediation", command=_exec_remediation,
                bg_color="#059669", fg_color=Theme.TEXT_WHITE, hover_bg="#10B981",
                icon="⚡", padx=12, pady=5
            )
            btn_exec.pack(side=tk.LEFT, padx=(0, 8))

            btn_copy = ModernButton(
                btn_row, text="Copy Command", command=_copy_cmd,
                bg_color=Theme.BG_CARD_LIGHT, fg_color=Theme.TEXT_WHITE, hover_bg="#252C47",
                icon="📋", padx=12, pady=5
            )
            btn_copy.pack(side=tk.LEFT, padx=(0, 8))

        btn_close = tk.Button(btn_row, text="Close", font=("Segoe UI", 9, "bold"),
                              bg=Theme.BG_CARD_LIGHT, fg=Theme.TEXT_WHITE, bd=0,
                              padx=16, pady=5, command=win.destroy)
        btn_close.pack(side=tk.RIGHT)

    def open_html_report(self):
        if HTML_REPORT_FILE.exists():
            webbrowser.open(HTML_REPORT_FILE.as_uri())
        else:
            messagebox.showinfo("Not Found", "HTML report not yet generated. Please run an audit first.")

    def open_pdf_report(self):
        if PDF_REPORT_FILE.exists():
            os.startfile(str(PDF_REPORT_FILE))
        else:
            messagebox.showinfo("Not Found", "Encrypted PDF report not yet generated. Please run an audit first.")


def main():
    app = SentinelIQApp()
    app.mainloop()


if __name__ == "__main__":
    main()
