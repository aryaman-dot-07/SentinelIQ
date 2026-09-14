#!/usr/bin/env python3
"""
Generate SentinelIQ Presentation matching the user's reference design.
Creates SentinelIQ_Presentation.pptx with dark aesthetic, precise layouts,
two-tone typography, highlight cards, comparison matrices, and clean footers.
"""

import sys
from pathlib import Path
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

OUTPUT_FILE = Path(__file__).resolve().parent / "SentinelIQ_Presentation.pptx"

# Reference Palette
COLOR_BG = RGBColor(11, 13, 20)           # #0B0D14 Deep black-navy
COLOR_CARD_BG = RGBColor(18, 21, 32)      # #121520 Card background
COLOR_CARD_BORDER = RGBColor(31, 36, 51)  # #1F2433 Subtle card border

COLOR_CYAN = RGBColor(0, 229, 255)        # #00E5FF Neon Cyan tag
COLOR_BLUE = RGBColor(56, 189, 248)       # #38BDF8 Sky Blue wordmark
COLOR_RED = RGBColor(244, 63, 94)         # #F43F5E Coral Red tag
COLOR_ORANGE = RGBColor(251, 146, 60)     # #FB923C Amber Orange
COLOR_GREEN = RGBColor(52, 211, 153)      # #34D399 Mint Green
COLOR_WHITE = RGBColor(255, 255, 255)     # #FFFFFF Pure White
COLOR_MUTED = RGBColor(148, 163, 184)     # #94A3B8 Slate Gray
COLOR_DIM = RGBColor(100, 116, 139)       # #64748B Dim Slate
COLOR_FOOTER = RGBColor(71, 85, 105)      # #475569 Footer text


def set_slide_bg(slide):
    background = slide.background
    fill = background.fill
    fill.solid()
    fill.fore_color.rgb = COLOR_BG


def add_slide_header(slide, tag_text, title_text, subtitle_text=None, tag_color=COLOR_CYAN):
    # Tag: e.g. "● THE REAL PROBLEM"
    tag_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.42), Inches(11.7), Inches(0.35))
    tf_tag = tag_box.text_frame
    tf_tag.word_wrap = True
    p_tag = tf_tag.paragraphs[0]
    p_tag.text = f"●  {tag_text.upper()}"
    p_tag.font.size = Pt(10)
    p_tag.font.bold = True
    p_tag.font.color.rgb = tag_color

    # Title
    title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.75), Inches(11.7), Inches(0.75))
    tf_title = title_box.text_frame
    tf_title.word_wrap = True
    p_title = tf_title.paragraphs[0]
    p_title.text = title_text
    p_title.font.size = Pt(22)
    p_title.font.bold = True
    p_title.font.color.rgb = COLOR_WHITE

    # Subtitle (optional)
    if subtitle_text:
        sub_box = slide.shapes.add_textbox(Inches(0.8), Inches(1.45), Inches(11.7), Inches(0.5))
        tf_sub = sub_box.text_frame
        tf_sub.word_wrap = True
        p_sub = tf_sub.paragraphs[0]
        p_sub.text = subtitle_text
        p_sub.font.size = Pt(11)
        p_sub.font.color.rgb = COLOR_MUTED


def add_footer(slide, section_name, slide_num):
    # Left Section Name
    f_left = slide.shapes.add_textbox(Inches(0.8), Inches(6.9), Inches(8.0), Inches(0.3))
    tf_l = f_left.text_frame
    p_l = tf_l.paragraphs[0]
    p_l.text = f"SENTINELIQ / {section_name.upper()}"
    p_l.font.size = Pt(8.5)
    p_l.font.bold = True
    p_l.font.color.rgb = COLOR_FOOTER

    # Right Slide Number
    f_right = slide.shapes.add_textbox(Inches(11.5), Inches(6.9), Inches(1.0), Inches(0.3))
    tf_r = f_right.text_frame
    p_r = tf_r.paragraphs[0]
    p_r.text = f"{slide_num:02d}"
    p_r.alignment = PP_ALIGN.RIGHT
    p_r.font.size = Pt(8.5)
    p_r.font.bold = True
    p_r.font.color.rgb = COLOR_FOOTER


def build_deck():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # =========================================================================
    # SLIDE 1: Title Slide (Exact match to Reference Page 1)
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s1)

    # Main Title (Two-tone: Sentinel in Blue, IQ in White)
    title_box = s1.shapes.add_textbox(Inches(1.2), Inches(2.2), Inches(10.5), Inches(1.5))
    tf1 = title_box.text_frame
    tf1.word_wrap = True
    p1 = tf1.paragraphs[0]

    run_sentinel = p1.add_run()
    run_sentinel.text = "Sentinel"
    run_sentinel.font.size = Pt(64)
    run_sentinel.font.bold = True
    run_sentinel.font.color.rgb = COLOR_BLUE

    run_iq = p1.add_run()
    run_iq.text = "IQ"
    run_iq.font.size = Pt(64)
    run_iq.font.bold = True
    run_iq.font.color.rgb = COLOR_WHITE

    # Subtitle
    sub_box = s1.shapes.add_textbox(Inches(1.2), Inches(3.7), Inches(10.5), Inches(0.8))
    tf_sub = sub_box.text_frame
    tf_sub.word_wrap = True
    p_sub = tf_sub.paragraphs[0]
    p_sub.text = "Why SentinelIQ is not antivirus — and what it actually does instead."
    p_sub.font.size = Pt(17)
    p_sub.font.color.rgb = COLOR_MUTED

    # Divider line
    line = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(1.2), Inches(6.5), Inches(10.9), Inches(0.015))
    line.fill.solid()
    line.fill.fore_color.rgb = COLOR_CARD_BORDER
    line.line.color.rgb = COLOR_CARD_BORDER

    # Bottom Right tag
    foot = s1.shapes.add_textbox(Inches(7.5), Inches(6.6), Inches(4.6), Inches(0.35))
    tf_f = foot.text_frame
    p_f = tf_f.paragraphs[0]
    p_f.alignment = PP_ALIGN.RIGHT
    p_f.text = "POWERED BY WINSENTRY ENGINE"
    p_f.font.size = Pt(8.5)
    p_f.font.bold = True
    p_f.font.color.rgb = COLOR_FOOTER

    # =========================================================================
    # SLIDE 2: Goals & Problem (Exact match to Reference Page 2)
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s2)
    add_slide_header(
        s2,
        tag_text="THE REAL PROBLEM",
        title_text="Misconfiguration is invisible and it drifts silently over time.",
        subtitle_text="A machine can be fully patched and still be quietly more exposed than it was last month: a new admin account, a Defender exclusion nobody remembers adding, a tamper-protection toggle nobody flipped back.",
        tag_color=COLOR_CYAN
    )

    # Left: Highlighted "Visibility Gap" Card (Thin Pink Border)
    left_card = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(2.1), Inches(5.4), Inches(4.5))
    left_card.fill.solid()
    left_card.fill.fore_color.rgb = COLOR_CARD_BG
    left_card.line.color.rgb = COLOR_RED
    left_card.line.width = Pt(1.5)

    l_box = s2.shapes.add_textbox(Inches(1.05), Inches(2.35), Inches(4.9), Inches(4.0))
    tf_l = l_box.text_frame
    tf_l.word_wrap = True

    p_lt = tf_l.paragraphs[0]
    p_lt.text = "THE VISIBILITY GAP"
    p_lt.font.size = Pt(10)
    p_lt.font.bold = True
    p_lt.font.color.rgb = COLOR_RED
    p_lt.space_after = Pt(14)

    p_lc = tf_l.add_paragraph()
    p_lc.text = "Antivirus and Defender tell you about threats they already recognize, right now. Neither one tells you whether your machine's overall exposure went up or down since the last time you checked."
    p_lc.font.size = Pt(13)
    p_lc.font.color.rgb = COLOR_WHITE
    p_lc.space_after = Pt(22)

    p_lf = tf_l.add_paragraph()
    p_lf.text = "That's the gap SentinelIQ fills: not detecting known threats, but tracking configuration exposure and behavioral drift over time."
    p_lf.font.size = Pt(11.5)
    p_lf.font.italic = True
    p_lf.font.color.rgb = COLOR_MUTED

    # Right: 4 Stacked Dark Cards
    stack_items = [
        ("Settings scattered across the system", "Security-relevant state lives in the registry, Defender policy, and local account config — no single place shows it all."),
        ("Exclusions leave no trail", "A scan-exclusion path added months ago stays invisible until something recalls it exists."),
        ("Protection can be silently disabled", "Tamper protection or real-time monitoring can be off while everything still looks normal."),
        ("Privilege quietly accumulates", "Everyday accounts can pick up admin rights over time, widening blast radius with no alert.")
    ]

    for idx, (title, desc) in enumerate(stack_items):
        top_y = Inches(2.1) + idx * Inches(1.15)
        card = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.5), top_y, Inches(6.0), Inches(1.02))
        card.fill.solid()
        card.fill.fore_color.rgb = COLOR_CARD_BG
        card.line.color.rgb = COLOR_CARD_BORDER
        card.line.width = Pt(1)

        tbox = s2.shapes.add_textbox(Inches(6.65), top_y + Inches(0.1), Inches(5.7), Inches(0.85))
        tf_item = tbox.text_frame
        tf_item.word_wrap = True

        p_it = tf_item.paragraphs[0]
        p_it.text = title
        p_it.font.size = Pt(11)
        p_it.font.bold = True
        p_it.font.color.rgb = COLOR_WHITE
        p_it.space_after = Pt(2)

        p_id = tf_item.add_paragraph()
        p_id.text = desc
        p_id.font.size = Pt(9.5)
        p_id.font.color.rgb = COLOR_MUTED

    add_footer(s2, "PROBLEM REFRAME", 2)

    # =========================================================================
    # SLIDE 3: Comparison Matrix (Exact match to Reference Page 3)
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s3)
    add_slide_header(
        s3,
        tag_text="ADDRESSING THE QUESTION",
        title_text="“Isn't this just antivirus?” — No. Here's the actual difference.",
        tag_color=COLOR_RED
    )

    # Matrix Table Container
    table_card = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(11.7), Inches(4.5))
    table_card.fill.solid()
    table_card.fill.fore_color.rgb = COLOR_CARD_BG
    table_card.line.color.rgb = COLOR_CARD_BORDER
    table_card.line.width = Pt(1)

    # Column Headers
    hdr_box1 = s3.shapes.add_textbox(Inches(1.0), Inches(1.9), Inches(3.0), Inches(0.4))
    hdr_box1.text_frame.paragraphs[0].text = "DIMENSION"
    hdr_box1.text_frame.paragraphs[0].font.size = Pt(10)
    hdr_box1.text_frame.paragraphs[0].font.bold = True
    hdr_box1.text_frame.paragraphs[0].font.color.rgb = COLOR_MUTED

    hdr_box2 = s3.shapes.add_textbox(Inches(4.5), Inches(1.9), Inches(3.5), Inches(0.4))
    hdr_box2.text_frame.paragraphs[0].text = "ANTIVIRUS / DEFENDER"
    hdr_box2.text_frame.paragraphs[0].font.size = Pt(10.5)
    hdr_box2.text_frame.paragraphs[0].font.bold = True
    hdr_box2.text_frame.paragraphs[0].font.color.rgb = COLOR_RED

    hdr_box3 = s3.shapes.add_textbox(Inches(8.5), Inches(1.9), Inches(3.8), Inches(0.4))
    hdr_box3.text_frame.paragraphs[0].text = "SENTINELIQ"
    hdr_box3.text_frame.paragraphs[0].font.size = Pt(10.5)
    hdr_box3.text_frame.paragraphs[0].font.bold = True
    hdr_box3.text_frame.paragraphs[0].font.color.rgb = COLOR_GREEN

    # Rows Data
    rows = [
        ("What it detects", "Known malware signatures & active threats", "Misconfiguration & exposure drift"),
        ("When it acts", "Automatically, in real time", "Never — you review and run every fix"),
        ("What it touches", "Quarantines, deletes, mutates state", "Strictly read-only, zero mutation"),
        ("What it outputs", "A pass/fail alert", "An auditable 0–100 score — and a diff since last scan"),
        ("Best for", "Stopping a known threat now", "Proving exposure went up or down over time")
    ]

    for idx, (dim, av, sq) in enumerate(rows):
        ry = Inches(2.4) + idx * Inches(0.7)

        # Row line divider
        r_line = s3.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(1.0), ry, Inches(11.3), Inches(0.01))
        r_line.fill.solid()
        r_line.fill.fore_color.rgb = COLOR_CARD_BORDER
        r_line.line.color.rgb = COLOR_CARD_BORDER

        # Dim
        db = s3.shapes.add_textbox(Inches(1.0), ry + Inches(0.12), Inches(3.2), Inches(0.5))
        db.text_frame.paragraphs[0].text = dim
        db.text_frame.paragraphs[0].font.size = Pt(11)
        db.text_frame.paragraphs[0].font.color.rgb = COLOR_MUTED

        # AV
        ab = s3.shapes.add_textbox(Inches(4.5), ry + Inches(0.12), Inches(3.7), Inches(0.5))
        ab.text_frame.paragraphs[0].text = av
        ab.text_frame.paragraphs[0].font.size = Pt(11)
        ab.text_frame.paragraphs[0].font.color.rgb = COLOR_WHITE

        # SentinelIQ
        sb = s3.shapes.add_textbox(Inches(8.5), ry + Inches(0.12), Inches(3.8), Inches(0.5))
        sb.text_frame.paragraphs[0].text = sq
        sb.text_frame.paragraphs[0].font.size = Pt(11)
        sb.text_frame.paragraphs[0].font.bold = True
        sb.text_frame.paragraphs[0].font.color.rgb = COLOR_WHITE

    # Bottom In One Line Callout
    call_box = s3.shapes.add_textbox(Inches(0.8), Inches(6.35), Inches(11.7), Inches(0.4))
    tf_call = call_box.text_frame
    p_call = tf_call.paragraphs[0]
    r_c1 = p_call.add_run()
    r_c1.text = "In one line: "
    r_c1.font.bold = True
    r_c1.font.italic = True
    r_c1.font.size = Pt(11)
    r_c1.font.color.rgb = COLOR_WHITE

    r_c2 = p_call.add_run()
    r_c2.text = "Antivirus answers “is there malware right now?” SentinelIQ answers “how exposed is this machine, and how did that change since last week?”"
    r_c2.font.italic = True
    r_c2.font.size = Pt(11)
    r_c2.font.color.rgb = COLOR_MUTED

    add_footer(s3, "NOT ANTIVIRUS", 3)

    # =========================================================================
    # SLIDE 4: Architecture & Workflow (Exact match to Reference Page 4)
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s4)
    add_slide_header(
        s4,
        tag_text="HOW IT WORKS",
        title_text="One read-only engine. No network calls. No auto-remediation.",
        tag_color=COLOR_CYAN
    )

    steps = [
        ("01 · AUDIT", "WinSentry Engine", "PowerShell reads Defender state, network posture, persistence points, accounts, and patch history — pure CIM/WMI, zero third-party agents, zero mutation.", COLOR_CYAN),
        ("02 · SCORE + DIFF", "Python Orchestrator", "Weighs each module into one auditable 0–100 score, and — the part antivirus never does — diffs the new scan against the last one to show exactly what changed.", COLOR_CYAN),
        ("03 · REPORT", "Encrypted, Local Output", "An AES-encrypted PDF and console, with plain-English findings and copyable PowerShell fixes. Nothing is auto-applied — you stay in control.", COLOR_CYAN)
    ]

    cw = Inches(3.65)
    for idx, (step_num, title, body, col) in enumerate(steps):
        cx = Inches(0.8) + idx * Inches(4.0)
        card = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, cx, Inches(2.0), cw, Inches(4.4))
        card.fill.solid()
        card.fill.fore_color.rgb = COLOR_CARD_BG
        card.line.color.rgb = COLOR_CARD_BORDER
        card.line.width = Pt(1)

        tbox = s4.shapes.add_textbox(cx + Inches(0.25), Inches(2.2), cw - Inches(0.5), Inches(4.0))
        tf_s = tbox.text_frame
        tf_s.word_wrap = True

        p_num = tf_s.paragraphs[0]
        p_num.text = step_num
        p_num.font.size = Pt(9.5)
        p_num.font.bold = True
        p_num.font.color.rgb = col
        p_num.space_after = Pt(10)

        p_t = tf_s.add_paragraph()
        p_t.text = title
        p_t.font.size = Pt(16)
        p_t.font.bold = True
        p_t.font.color.rgb = COLOR_WHITE
        p_t.space_after = Pt(20)

        p_b = tf_s.add_paragraph()
        p_b.text = body
        p_b.font.size = Pt(11.5)
        p_b.font.color.rgb = COLOR_MUTED

        # Arrow indicator between cards
        if idx < 2:
            arr_box = s4.shapes.add_textbox(cx + cw, Inches(3.8), Inches(0.35), Inches(0.5))
            arr_tf = arr_box.text_frame
            arr_p = arr_tf.paragraphs[0]
            arr_p.text = "→"
            arr_p.font.size = Pt(18)
            arr_p.font.color.rgb = COLOR_DIM

    add_footer(s4, "ARCHITECTURE", 4)

    # =========================================================================
    # SLIDE 5: Tech Stack (New Slide in Same Reference Style)
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s5)
    add_slide_header(
        s5,
        tag_text="TECHNOLOGY STACK",
        title_text="Engineered for offline execution and zero-dependency auditing.",
        subtitle_text="Leveraging native Windows instrumentation, modern Python ML runtimes, and local cryptographic sealing.",
        tag_color=COLOR_CYAN
    )

    stack_cards = [
        ("Core Languages", "PowerShell 5.1 / 7+", "Direct CIM/WMI querying, Authenticode signature checks, and system policy audits without third-party agents."),
        ("OS Instrumentation", "WMI, CIM & NetTCP", "Extracts process ancestry (Win32_Process), unowned sockets, Defender status, and user privileges."),
        ("Desktop GUI & Packaging", "Tkinter & PyInstaller", "High-performance dark theme dashboard compiled into a standalone 13.7 MB WinSentry.exe with zero console flicker."),
        ("Local Storage & Crypto", "AES-256 & SHA-256", "Generates password-locked executive PDFs (PyPDF2) and offline baseline JSONs. Zero external databases.")
    ]

    for idx, (category, tech, desc) in enumerate(stack_cards):
        cx = Inches(0.8) + idx * Inches(3.0)
        c_shape = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, cx, Inches(2.2), Inches(2.75), Inches(4.2))
        c_shape.fill.solid()
        c_shape.fill.fore_color.rgb = COLOR_CARD_BG
        c_shape.line.color.rgb = COLOR_CARD_BORDER
        c_shape.line.width = Pt(1)

        tbox = s5.shapes.add_textbox(cx + Inches(0.18), Inches(2.35), Inches(2.4), Inches(3.8))
        tf_tc = tbox.text_frame
        tf_tc.word_wrap = True

        p_cat = tf_tc.paragraphs[0]
        p_cat.text = category.upper()
        p_cat.font.size = Pt(9)
        p_cat.font.bold = True
        p_cat.font.color.rgb = COLOR_BLUE
        p_cat.space_after = Pt(8)

        p_tech = tf_tc.add_paragraph()
        p_tech.text = tech
        p_tech.font.size = Pt(14)
        p_tech.font.bold = True
        p_tech.font.color.rgb = COLOR_WHITE
        p_tech.space_after = Pt(14)

        p_desc = tf_tc.add_paragraph()
        p_desc.text = desc
        p_desc.font.size = Pt(10.5)
        p_desc.font.color.rgb = COLOR_MUTED

    add_footer(s5, "TECH STACK", 5)

    # =========================================================================
    # SLIDE 6: Offline Behavioral Engine (New Slide in Same Reference Style)
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s6)
    add_slide_header(
        s6,
        tag_text="BEHAVIORAL ANOMALY ENGINE",
        title_text="Learning normal routines to catch living-off-the-land attacks.",
        subtitle_text="Zero-cloud behavioral detection: calibrates a legitimate process baseline offline, then flags abnormal execution trees.",
        tag_color=COLOR_CYAN
    )

    # Left Card: The 2-Phase Engine
    b_left = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(2.2), Inches(5.4), Inches(4.3))
    b_left.fill.solid()
    b_left.fill.fore_color.rgb = COLOR_CARD_BG
    b_left.line.color.rgb = COLOR_CYAN
    b_left.line.width = Pt(1.5)

    b_tbox = s6.shapes.add_textbox(Inches(1.05), Inches(2.4), Inches(4.9), Inches(3.8))
    tf_b = b_tbox.text_frame
    tf_b.word_wrap = True

    p_bt = tf_b.paragraphs[0]
    p_bt.text = "OFFLINE ANOMALY SCORING (0 - 100)"
    p_bt.font.size = Pt(10)
    p_bt.font.bold = True
    p_bt.font.color.rgb = COLOR_CYAN
    p_bt.space_after = Pt(10)

    p_b1 = tf_b.add_paragraph()
    p_b1.text = "Phase 1: Baseline Learning Mode"
    p_b1.font.size = Pt(12)
    p_b1.font.bold = True
    p_b1.font.color.rgb = COLOR_WHITE
    p_b1_sub = tf_b.add_paragraph()
    p_b1_sub.text = "Samples clean system activity for 30–60s and serializes legitimate process ancestry and sockets to winsentry_baseline.json."
    p_b1_sub.font.size = Pt(10)
    p_b1_sub.font.color.rgb = COLOR_MUTED
    p_b1_sub.space_after = Pt(12)

    p_b2 = tf_b.add_paragraph()
    p_b2.text = "Phase 2: Live Anomaly Scoring"
    p_b2.font.size = Pt(12)
    p_b2.font.bold = True
    p_b2.font.color.rgb = COLOR_WHITE
    p_b2_sub = tf_b.add_paragraph()
    p_b2_sub.text = "Evaluates live processes: High-risk parent spawning shell (+65 pts), Masquerading (+70 pts), Temp path execution (+40 pts)."
    p_b2_sub.font.size = Pt(10)
    p_b2_sub.font.color.rgb = COLOR_MUTED

    # Right: 3 Stacked Detection Rule Cards
    b_rules = [
        ("Living-off-the-Land (LotL) Defense", "Detects when non-shell apps (Chrome, Word, Acrobat) abnormally spawn cmd.exe, PowerShell, or rundll32.exe."),
        ("Masquerading & Typosquatting", "Applies Levenshtein distance checks to catch malicious binaries mimicking core system processes (e.g. uihost vs sihost)."),
        ("Live Behavioral Shield", "Background daemon evaluating active processes every 5 seconds with one-click administrative termination.")
    ]

    for idx, (title, desc) in enumerate(b_rules):
        top_y = Inches(2.2) + idx * Inches(1.48)
        card = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.5), top_y, Inches(6.0), Inches(1.35))
        card.fill.solid()
        card.fill.fore_color.rgb = COLOR_CARD_BG
        card.line.color.rgb = COLOR_CARD_BORDER
        card.line.width = Pt(1)

        tbox = s6.shapes.add_textbox(Inches(6.7), top_y + Inches(0.12), Inches(5.6), Inches(1.1))
        tf_r = tbox.text_frame
        tf_r.word_wrap = True

        p_rt = tf_r.paragraphs[0]
        p_rt.text = title
        p_rt.font.size = Pt(11.5)
        p_rt.font.bold = True
        p_rt.font.color.rgb = COLOR_WHITE
        p_rt.space_after = Pt(3)

        p_rd = tf_r.add_paragraph()
        p_rd.text = desc
        p_rd.font.size = Pt(10)
        p_rd.font.color.rgb = COLOR_MUTED

    add_footer(s6, "BEHAVIORAL ENGINE", 6)

    # =========================================================================
    # SLIDE 7: Team Roles & Responsibilities (Requirement 4)
    # =========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s7)
    add_slide_header(
        s7,
        tag_text="ROLES & RESPONSIBILITIES",
        title_text="Divided engineering ownership across architecture & ML interface.",
        subtitle_text="Clear individual responsibilities spanning core PowerShell telemetry, behavioral modeling, and desktop GUI delivery.",
        tag_color=COLOR_CYAN
    )

    # Role Card 1: Akul Attre
    r1_card = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(2.2), Inches(5.6), Inches(4.3))
    r1_card.fill.solid()
    r1_card.fill.fore_color.rgb = COLOR_CARD_BG
    r1_card.line.color.rgb = COLOR_CARD_BORDER
    r1_card.line.width = Pt(1)

    r1_box = s7.shapes.add_textbox(Inches(1.05), Inches(2.35), Inches(5.1), Inches(4.0))
    tf_r1 = r1_box.text_frame
    tf_r1.word_wrap = True

    p_r1_name = tf_r1.paragraphs[0]
    p_r1_name.text = "Akul Attre"
    p_r1_name.font.size = Pt(16)
    p_r1_name.font.bold = True
    p_r1_name.font.color.rgb = COLOR_WHITE

    p_r1_role = tf_r1.add_paragraph()
    p_r1_role.text = "LEAD SECURITY ARCHITECT & CORE POWERSHELL ENGINEER"
    p_r1_role.font.size = Pt(9.5)
    p_r1_role.font.bold = True
    p_r1_role.font.color.rgb = COLOR_BLUE
    p_r1_role.space_after = Pt(12)

    bullets_r1 = [
        "Core Security Philosophy: Conceived the zero-trace, zero-mutation blue-team posture auditor architecture.",
        "Auditing Engine: Authored WinSentry.ps1 and implemented the foundational modules (Defender, Remote Access, Persistence).",
        "Typosquatting Algorithm: Programmed Levenshtein edit-distance matching against protected core system binaries.",
        "Cryptographic PDF Reporting: Designed winsentry_report.py to compile AES-encrypted PDFs with SHA-256 sidecars.",
        "Scoring Methodology: Formulated the transparent 0–100 mathematical risk scoring weight model."
    ]
    for b in bullets_r1:
        p = tf_r1.add_paragraph()
        p.text = f"•  {b}"
        p.font.size = Pt(9.5)
        p.font.color.rgb = COLOR_MUTED
        p.space_after = Pt(4)

    # Role Card 2: Aryaman
    r2_card = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(2.2), Inches(5.7), Inches(4.3))
    r2_card.fill.solid()
    r2_card.fill.fore_color.rgb = COLOR_CARD_BG
    r2_card.line.color.rgb = COLOR_CARD_BORDER
    r2_card.line.width = Pt(1)

    r2_box = s7.shapes.add_textbox(Inches(7.05), Inches(2.35), Inches(5.2), Inches(4.0))
    tf_r2 = r2_box.text_frame
    tf_r2.word_wrap = True

    p_r2_name = tf_r2.paragraphs[0]
    p_r2_name.text = "Aryaman"
    p_r2_name.font.size = Pt(16)
    p_r2_name.font.bold = True
    p_r2_name.font.color.rgb = COLOR_WHITE

    p_r2_role = tf_r2.add_paragraph()
    p_r2_role.text = "ML BEHAVIORAL ENGINE & DESKTOP INTERFACE DEVELOPER"
    p_r2_role.font.size = Pt(9.5)
    p_r2_role.font.bold = True
    p_r2_role.font.color.rgb = COLOR_GREEN
    p_r2_role.space_after = Pt(12)

    bullets_r2 = [
        "Offline Behavioral Engine: Architected winsentry_behavioral.py, creating the offline baseline learning and anomaly detector.",
        "LotL & Ancestry Detection: Engineered heuristic scoring for high-risk parent process shell spawns and temp path executions.",
        "Modern Cyberpunk Desktop GUI: Developed app.py using Tkinter/ttk with live risk gauges and real-time shield monitoring.",
        "Standalone Executable Packaging: Orchestrated PyInstaller toolchains to compile the self-contained 13.7 MB WinSentry.exe.",
        "Integration & Bug Resolution: Connected Module 9 into core scanner and fixed Windows 11 datetime hotfix parsing bugs."
    ]
    for b in bullets_r2:
        p = tf_r2.add_paragraph()
        p.text = f"•  {b}"
        p.font.size = Pt(9.5)
        p.font.color.rgb = COLOR_MUTED
        p.space_after = Pt(4)

    add_footer(s7, "TEAM ROLES", 7)

    # =========================================================================
    # SLIDE 8: The Differentiator & Drift (Exact match to Reference Page 5)
    # =========================================================================
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s8)
    add_slide_header(
        s8,
        tag_text="THE DIFFERENTIATOR",
        title_text="A score isn't a verdict. A trend is.",
        subtitle_text="Antivirus gives you a point-in-time verdict. SentinelIQ's -CompareTo diff engine already tracks posture across scans — this is the view no AV dashboard shows you.",
        tag_color=COLOR_CYAN
    )

    # Left: Score Trend Graphic Card
    trend_card = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(2.2), Inches(6.0), Inches(4.3))
    trend_card.fill.solid()
    trend_card.fill.fore_color.rgb = COLOR_CARD_BG
    trend_card.line.color.rgb = COLOR_CARD_BORDER
    trend_card.line.width = Pt(1)

    t_box = s8.shapes.add_textbox(Inches(1.0), Inches(2.4), Inches(5.6), Inches(3.9))
    tf_tr = t_box.text_frame
    tf_tr.word_wrap = True

    p_tt = tf_tr.paragraphs[0]
    p_tt.text = "PROGRESSION ACROSS SCANS (0–100)"
    p_tt.font.size = Pt(10)
    p_tt.font.bold = True
    p_tt.font.color.rgb = COLOR_MUTED
    p_tt.space_after = Pt(14)

    scores = [
        ("Scan 1 (Initial Unhardened)", "54 / 100", COLOR_RED),
        ("Scan 2 (After Defender Tuning)", "61 / 100", COLOR_ORANGE),
        ("Scan 3 (Exclusions Cleaned)", "72 / 100", COLOR_CYAN),
        ("Scan 4 (Hardened Baseline)", "88 / 100", COLOR_GREEN)
    ]
    for s_name, score_val, col in scores:
        p_row = tf_tr.add_paragraph()
        r1 = p_row.add_run()
        r1.text = f"{s_name}:  "
        r1.font.size = Pt(11)
        r1.font.color.rgb = COLOR_MUTED

        r2 = p_row.add_run()
        r2.text = score_val
        r2.font.size = Pt(13)
        r2.font.bold = True
        r2.font.color.rgb = col
        p_row.space_after = Pt(10)

    # Right: 3 Stacked Diff Cards
    diffs = [
        ("Scan 1 → 2", "Tamper protection re-enabled (+7)", COLOR_CYAN),
        ("Scan 2 → 3", "3 stale Defender exclusions removed (+11)", COLOR_CYAN),
        ("Scan 3 → 4", "Unquoted service path fixed, admin creep reverted (+16)", COLOR_GREEN)
    ]

    for idx, (title, desc, col) in enumerate(diffs):
        top_y = Inches(2.2) + idx * Inches(1.48)
        card = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(7.1), top_y, Inches(5.4), Inches(1.35))
        card.fill.solid()
        card.fill.fore_color.rgb = COLOR_CARD_BG
        card.line.color.rgb = COLOR_CARD_BORDER
        card.line.width = Pt(1)

        tbox = s8.shapes.add_textbox(Inches(7.3), top_y + Inches(0.15), Inches(5.0), Inches(1.0))
        tf_d = tbox.text_frame
        tf_d.word_wrap = True

        p_dt = tf_d.paragraphs[0]
        p_dt.text = title
        p_dt.font.size = Pt(11)
        p_dt.font.bold = True
        p_dt.font.color.rgb = col
        p_dt.space_after = Pt(4)

        p_dd = tf_d.add_paragraph()
        p_dd.text = desc
        p_dd.font.size = Pt(10.5)
        p_dd.font.color.rgb = COLOR_WHITE

    add_footer(s8, "DRIFT TRACKING", 8)

    # =========================================================================
    # SLIDE 9: The One-Line Answer (Exact match to Reference Page 7)
    # =========================================================================
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s9)

    # Center Feature Card
    center_card = s9.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.0), Inches(1.3), Inches(11.333), Inches(5.0))
    center_card.fill.solid()
    center_card.fill.fore_color.rgb = COLOR_CARD_BG
    center_card.line.color.rgb = COLOR_CARD_BORDER
    center_card.line.width = Pt(1)

    c_box = s9.shapes.add_textbox(Inches(1.5), Inches(1.7), Inches(10.333), Inches(4.2))
    tf_c = c_box.text_frame
    tf_c.word_wrap = True

    p_tag = tf_c.paragraphs[0]
    p_tag.text = "THE ONE-LINE ANSWER"
    p_tag.font.size = Pt(11)
    p_tag.font.bold = True
    p_tag.font.color.rgb = COLOR_BLUE
    p_tag.space_after = Pt(18)

    p_hero = tf_c.add_paragraph()
    p_hero.text = "SentinelIQ isn't detecting malware faster than Defender — it's the compliance layer that shows whether your security configuration is getting better or worse, with proof, over time."
    p_hero.font.size = Pt(18)
    p_hero.font.bold = True
    p_hero.font.color.rgb = COLOR_WHITE
    p_hero.space_after = Pt(28)

    bullets = [
        "Zero network calls, zero state mutation — strictly read-only",
        "Auditable 0–100 score with a full diff between scans",
        "Offline behavioral baseline engine to detect living-off-the-land attacks",
        "Human approves every fix — nothing is auto-remediated"
    ]
    for b in bullets:
        p = tf_c.add_paragraph()
        run_dot = p.add_run()
        run_dot.text = "●  "
        run_dot.font.color.rgb = COLOR_CYAN
        run_dot.font.size = Pt(11)

        run_txt = p.add_run()
        run_txt.text = b
        run_txt.font.size = Pt(12)
        run_txt.font.color.rgb = COLOR_MUTED
        p.space_after = Pt(8)

    add_footer(s9, "CLOSING POSITIONING", 9)

    prs.save(OUTPUT_FILE)
    print(f"[+] SentinelIQ presentation created successfully at: {OUTPUT_FILE}")


if __name__ == "__main__":
    build_deck()
