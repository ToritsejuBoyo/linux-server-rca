#!/usr/bin/env python3
"""
Agensi Marketplace Asset Generator for linux-server-rca.

Generates:
1. 512x512 square skill logo (logo-512x512.png)
2. 4 high-definition 1280x720 screenshots for marketplace listing:
   - 01-terminal-collector.png (Live Linux read-only telemetry collection & sanitization)
   - 02-root-cause-analysis.png (Synthesized diagnostic verdict & 5-branch decision tree)
   - 03-itsm-escalation-brief.png (Copy-paste incident brief & non-destructive playbook)
   - 04-telemetry-architecture.png (Enterprise read-only architecture & compliance)
"""

import math
import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ASSETS_DIR = Path("C:/Users/Toju/Desktop/agensi-linux-server-rca-assets")
ASSETS_DIR.mkdir(parents=True, exist_ok=True)


def get_font(size: int, bold: bool = False):
    font_names = [
        "consolab.ttf" if bold else "consola.ttf",
        "segoeuib.ttf" if bold else "segoeui.ttf",
        "arialbd.ttf" if bold else "arial.ttf"
    ]
    for name in font_names:
        try:
            return ImageFont.truetype(name, size)
        except Exception:
            continue
    return ImageFont.load_default()


# ----------------------------------------------------------------------
# 1. Skill Logo Generator (512x512)
# ----------------------------------------------------------------------
def generate_logo():
    size = 512
    img = Image.new("RGBA", (size, size), (15, 23, 42, 255))  # #0F172A
    draw = ImageDraw.Draw(img)

    # Subtle radial emerald glow behind center icon
    center_x, center_y = size // 2, size // 2 - 25
    for r in range(180, 0, -5):
        alpha = int(45 * (1 - r / 180))
        draw.ellipse(
            [(center_x - r, center_y - r), (center_x + r, center_y + r)],
            fill=(16, 185, 129, alpha)
        )

    # Rounded outer border with emerald/cyan gradient
    margin = 16
    draw.rounded_rectangle(
        [(margin, margin), (size - margin, size - margin)],
        radius=48,
        outline=(52, 211, 153, 190),
        width=4
    )

    # Stylized Linux Terminal Shell Container & Tux/Diagnostic Badge
    term_w, term_h = 220, 160
    tx, ty = center_x - term_w // 2, center_y - term_h // 2 - 15

    # Terminal card
    draw.rounded_rectangle(
        [(tx, ty), (tx + term_w, ty + term_h)],
        radius=16,
        fill=(30, 41, 59, 255),
        outline=(51, 65, 85, 255),
        width=2
    )

    # Terminal header dots
    draw.ellipse([(tx + 16, ty + 14), (tx + 26, ty + 24)], fill=(239, 68, 68, 255))
    draw.ellipse([(tx + 34, ty + 14), (tx + 44, ty + 24)], fill=(245, 158, 11, 255))
    draw.ellipse([(tx + 52, ty + 14), (tx + 62, ty + 24)], fill=(16, 185, 129, 255))

    # Terminal prompt symbol `>_` and diagnostic cross
    prompt_font = get_font(44, bold=True)
    draw.text((tx + 22, ty + 42), ">_", font=prompt_font, fill=(52, 211, 153, 255))

    # Diagnostic Heartbeat / Pulse across bottom of terminal card
    pulse_y = ty + 115
    pts = [
        (tx + 20, pulse_y),
        (tx + 70, pulse_y),
        (tx + 95, pulse_y - 30),
        (tx + 115, pulse_y + 25),
        (tx + 135, pulse_y - 45),
        (tx + 155, pulse_y + 20),
        (tx + 175, pulse_y),
        (tx + 200, pulse_y)
    ]
    for w, a in [(6, 60), (4, 140), (2, 255)]:
        draw.line(pts, fill=(56, 189, 248, a), width=w, joint="curve")

    # Pulse ping dot
    draw.ellipse([(tx + 135 - 5, pulse_y - 45 - 5), (tx + 135 + 5, pulse_y - 45 + 5)], fill=(255, 255, 255, 255))

    # Badge Text
    title_font = get_font(28, bold=True)
    sub_font = get_font(18, bold=True)

    text_main = "LINUX SERVER"
    text_sub = "RCA & TRIAGE"

    bbox_main = draw.textbbox((0, 0), text_main, font=title_font)
    w_main = bbox_main[2] - bbox_main[0]
    draw.text(((size - w_main) // 2, 380), text_main, font=title_font, fill=(241, 245, 249, 255))

    bbox_sub = draw.textbbox((0, 0), text_sub, font=sub_font)
    w_sub = bbox_sub[2] - bbox_sub[0]
    draw.text(((size - w_sub) // 2, 420), text_sub, font=sub_font, fill=(52, 211, 153, 255))

    logo_path = ASSETS_DIR / "logo-512x512.png"
    img.save(logo_path, "PNG")
    print(f"[+] Generated Skill Logo: {logo_path}")


# ----------------------------------------------------------------------
# 2. Screenshot 1: Interactive Terminal Collector
# ----------------------------------------------------------------------
def generate_screenshot_1():
    w, h = 1280, 720
    img = Image.new("RGB", (w, h), (15, 23, 42))
    draw = ImageDraw.Draw(img)

    # Top header bar
    draw.rectangle([(0, 0), (w, 48)], fill=(30, 41, 59))
    draw.ellipse([(20, 16), (32, 28)], fill=(239, 68, 68))
    draw.ellipse([(42, 16), (54, 28)], fill=(245, 158, 11))
    draw.ellipse([(64, 16), (76, 28)], fill=(16, 185, 129))

    title_font = get_font(15, bold=True)
    draw.text((w // 2 - 180, 14), "root@prod-rhel-node01: ~ / linux-server-rca", font=title_font, fill=(148, 163, 184))

    code_font = get_font(14)
    code_bold = get_font(14, bold=True)
    emerald = (52, 211, 153)
    cyan = (56, 189, 248)
    yellow = (251, 191, 36)
    red = (248, 113, 113)
    white = (255, 255, 255)
    gray = (148, 163, 184)

    lines = [
        (30, 70, "admin@prod-rhel-node01:~$ ", emerald, code_bold),
        (280, 70, "sudo ./scripts/collect-linux-rca.sh --sanitize --output ./linux-telemetry.json", white, code_bold),
        (30, 105, "[*] Linux Server RCA Telemetry Collector v1.2.0 (100% Read-Only Mode)", cyan, code_bold),
        (30, 128, "[*] Host: RHEL 9.3 Enterprise Linux (Kernel 5.14.0-362.8.1.el9_3.x86_64)", gray, code_font),
        (30, 151, "[+] Systemd Subsystem: Scanned 184 active units (1 FAILED unit detected)........ [CAPTURED]", emerald, code_font),
        (30, 174, "[+] Inode & Storage: Scanned 8 mountpoints (100% inode saturation on /var/spool).. [ALERT]", red, code_bold),
        (30, 197, "[+] Kernel Memory Ring: Correlating dmesg ringbuffer for OOM killer invocations... [CAPTURED]", emerald, code_font),
        (30, 220, "[+] Storage I/O Subsystem: Evaluated iostat/vmstat for D-state blocked processes... [CAPTURED]", emerald, code_font),
        (30, 243, "[+] Network Subsystem: Socket listeners and TCP connection states audit.......... [CAPTURED]", emerald, code_font),
        (30, 275, "[-] Client-Side Telemetry Scrubbing Active (--sanitize):", yellow, code_bold),
        (30, 298, "    - Internal IPv4 addresses mapped: 10.240.12.84 -> 192.0.2.14 (RFC 5737)", gray, code_font),
        (30, 321, "    - Corporate hostnames hashed:     prod-db01.corp.internal -> host-789a.example.com", gray, code_font),
        (30, 344, "    - User accounts sanitized:        deploy-user -> user-01@example.com", gray, code_font),
        (30, 380, "[+] Telemetry bundle compiled: ./linux-telemetry.json (38.4 KB)", emerald, code_bold),
        (30, 410, "admin@prod-rhel-node01:~$ ", emerald, code_bold),
        (280, 410, "python3 scripts/parse-linux-rca.py -i ./linux-telemetry.json", white, code_bold),
        (30, 445, "=========================================================================================", gray, code_font),
        (30, 470, "ROOT CAUSE IDENTIFIED: INODE EXHAUSTION (100% SATURATION ON /var/spool/postfix)", red, code_bold),
        (30, 495, "Primary Impact:   Services reporting 'No space left on device' despite 184 GB free disk space.", white, code_font),
        (30, 520, "Root Trigger:     Over 4,200,000 orphaned undelivered mail spool files in /var/spool/postfix/maildrop", yellow, code_font),
        (30, 545, "Remediation:      Non-destructive spool archive & cleanup playbook generated in ./rca-report.md", emerald, code_font),
        (30, 570, "ITIL Ticket Brief: Copy-paste L2 escalation brief ready for ServiceNow / Jira / PagerDuty.", cyan, code_font),
        (30, 600, "=========================================================================================", gray, code_font),
    ]

    for item in lines:
        x, y, text, col, fnt = item
        draw.text((x, y), text, font=fnt, fill=col)

    path = ASSETS_DIR / "01-terminal-collector.png"
    img.save(path, "PNG")
    print(f"[+] Generated Screenshot 1: {path}")


# ----------------------------------------------------------------------
# 3. Screenshot 2: AI Root Cause Analysis Dashboard
# ----------------------------------------------------------------------
def generate_screenshot_2():
    w, h = 1280, 720
    img = Image.new("RGB", (w, h), (15, 23, 42))
    draw = ImageDraw.Draw(img)

    # Top header
    draw.rectangle([(0, 0), (w, 56)], fill=(30, 41, 59))
    hdr_font = get_font(18, bold=True)
    draw.text((32, 16), "Linux Server Root Cause Analysis (RCA) Decision Engine", font=hdr_font, fill=(241, 245, 249))

    # Metric Cards Top
    card_y = 76
    cards = [
        ("Diagnostic Verdict", "INODE SATURATION", (239, 68, 68), (254, 226, 226)),
        ("Decision Tree Branch", "Filesystem / Inodes", (56, 189, 248), (224, 242, 254)),
        ("Confidence Score", "99.2%", (52, 211, 153), (209, 250, 229)),
        ("Evidence Scope", "df -i vs df -h", (251, 191, 36), (254, 243, 199))
    ]

    card_w = (w - 64 - 36) // 4
    for idx, (lbl, val, col_fg, col_bg) in enumerate(cards):
        cx = 32 + idx * (card_w + 12)
        draw.rounded_rectangle([(cx, card_y), (cx + card_w, card_y + 80)], radius=8, fill=(30, 41, 59), outline=(51, 65, 85), width=1)
        draw.text((cx + 16, card_y + 12), lbl, font=get_font(13), fill=(148, 163, 184))
        draw.text((cx + 16, card_y + 36), val, font=get_font(20, bold=True), fill=col_fg)

    # Main Body: RCA Findings Breakdown
    body_y = 176
    draw.rounded_rectangle([(32, body_y), (w - 32, h - 32)], radius=12, fill=(30, 41, 59), outline=(51, 65, 85), width=1)

    draw.text((54, body_y + 24), "Synthesized Root Cause & Forensic Evidence (5-Branch Decision Tree)", font=get_font(18, bold=True), fill=(241, 245, 249))

    items = [
        ("Diagnostic Category:", "Branch 3: Silent Inode Table Saturation (Ext4 / XFS Filesystem)", (248, 113, 113)),
        ("Primary Symptom:", "'ENOSPC: No space left on device' when creating new sockets or temp files.", (255, 255, 255)),
        ("Storage Metrics:", "Byte Space: 184 GB Free (38% Used) | Inode Table: 0 Free (100% Inodes Used)", (251, 191, 36)),
        ("Hot Directory:", "/var/spool/postfix/maildrop (Contains 4,210,944 zero-byte notification logs)", (56, 189, 248)),
        ("Systemd Impact:", "gitlab-runner.service failing with 'status=203/EXEC: failed to create lock'", (248, 113, 113)),
        ("Kernel OOM State:", "No active OOM killer invocations in dmesg (Memory pressure ruled out).", (52, 211, 153)),
        ("Storage I/O Latency:", "Average I/O wait: 1.2% (Disks responsive; no physical hardware degradation).", (52, 211, 153)),
        ("Immediate Fix:", "Execute non-destructive targeted find/delete batch script (see Section 3).", (52, 211, 153)),
    ]

    curr_y = body_y + 70
    for label, val, val_col in items:
        draw.text((54, curr_y), label, font=get_font(14, bold=True), fill=(148, 163, 184))
        draw.text((260, curr_y), val, font=get_font(14), fill=val_col)
        curr_y += 34

    path = ASSETS_DIR / "02-root-cause-analysis.png"
    img.save(path, "PNG")
    print(f"[+] Generated Screenshot 2: {path}")


# ----------------------------------------------------------------------
# 4. Screenshot 3: ITSM Escalation Brief & Remediation Playbook
# ----------------------------------------------------------------------
def generate_screenshot_3():
    w, h = 1280, 720
    img = Image.new("RGB", (w, h), (15, 23, 42))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (w, 56)], fill=(30, 41, 59))
    draw.text((32, 16), "Automated Incident Escalation Brief (ServiceNow / Jira / PagerDuty)", font=get_font(18, bold=True), fill=(241, 245, 249))

    draw.rounded_rectangle([(32, 76), (w - 32, h - 32)], radius=12, fill=(11, 17, 32), outline=(51, 65, 85), width=1)

    brief_text = [
        ("### P1/P2 Incident Diagnostic Brief: Linux Production Inode Exhaustion", (52, 211, 153), True),
        ("", (255, 255, 255), False),
        ("**Incident Summary:** Application deployments failing with 'No space left on device'.", (241, 245, 249), False),
        ("**Target Node:** `prod-rhel-node01` (RHEL 9.3) | **Triaged By:** linux-server-rca agent", (148, 163, 184), False),
        ("**Classification:** Priority 2 Operational Outage | **Downtime Avoided:** 2.5 Hours", (148, 163, 184), False),
        ("", (255, 255, 255), False),
        ("#### Technical Root Cause Evidence:", (56, 189, 248), True),
        ("1. **Forensic Discrepancy:** 'df -h' displays 184 GB available, but 'df -i' shows 100% inode capacity exhausted.", (255, 255, 255), False),
        ("2. **Identified Culprit:** Unchecked cronjob spawned 4.2M orphaned mail drop files in /var/spool/postfix/maildrop.", (255, 255, 255), False),
        ("3. **Downstream Failure:** Systemd services unable to allocate POSIX file descriptors or write PID locks.", (255, 255, 255), False),
        ("", (255, 255, 255), False),
        ("#### Non-Destructive Remediation Playbook:", (251, 191, 36), True),
        ("# Step 1: Safely purge orphaned spool files in batches without freezing kernel directory dentry cache", (148, 163, 184), False),
        ("find /var/spool/postfix/maildrop -type f -mtime +7 -delete", (52, 211, 153), True),
        ("# Step 2: Restart affected failed service and verify status", (148, 163, 184), False),
        ("systemctl restart gitlab-runner && systemctl is-active gitlab-runner", (52, 211, 153), True),
        ("# Step 3: Verify available inode headroom immediately", (148, 163, 184), False),
        ("df -i /var/spool/postfix", (52, 211, 153), True),
    ]

    curr_y = 100
    for line, col, is_bold in brief_text:
        if line:
            draw.text((60, curr_y), line, font=get_font(14, bold=is_bold), fill=col)
        curr_y += 24

    path = ASSETS_DIR / "03-itsm-escalation-brief.png"
    img.save(path, "PNG")
    print(f"[+] Generated Screenshot 3: {path}")


# ----------------------------------------------------------------------
# 4. Screenshot 4: Telemetry Architecture & Safety Guardrails
# ----------------------------------------------------------------------
def generate_screenshot_4():
    w, h = 1280, 720
    img = Image.new("RGB", (w, h), (15, 23, 42))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (w, 56)], fill=(30, 41, 59))
    draw.text((32, 16), "Enterprise Security & Decision Tree Architecture", font=get_font(18, bold=True), fill=(241, 245, 249))

    pillars = [
        ("1. 100% Read-Only Telemetry", "Collector runs only non-mutating inspection commands (journalctl, dmesg, df, free, vmstat). Never executes kill, rm, or reboot.", (52, 211, 153)),
        ("2. 5-Branch Deterministic Decision Tree", "Automated classification of Systemd Exit Codes, Kernel OOM Events, Inode Saturation, Storage I/O Wait, and Read-Only Filesystems.", (56, 189, 248)),
        ("3. Client-Side Secret & PII Sanitization", "Automated SHA-256 masking on hostnames, usernames, private RFC 1918 IPs, and secrets before data leaves the local host.", (251, 191, 36)),
        ("4. Zero External Dependencies", "Built strictly with Python standard library and POSIX Linux tools (awk, sed, grep). No pip install, zero EDR alerts.", (168, 85, 247))
    ]

    for idx, (title, desc, col) in enumerate(pillars):
        py = 88 + idx * 136
        draw.rounded_rectangle([(32, py), (w - 32, py + 116)], radius=10, fill=(30, 41, 59), outline=(51, 65, 85), width=1)
        draw.rectangle([(32, py), (42, py + 116)], fill=col)
        draw.text((64, py + 18), title, font=get_font(18, bold=True), fill=col)
        draw.text((64, py + 52), desc, font=get_font(14), fill=(203, 213, 225))

    path = ASSETS_DIR / "04-telemetry-architecture.png"
    img.save(path, "PNG")
    print(f"[+] Generated Screenshot 4: {path}")


def main():
    print("[*] Generating Agensi Marketplace Assets for linux-server-rca...")
    generate_logo()
    generate_screenshot_1()
    generate_screenshot_2()
    generate_screenshot_3()
    generate_screenshot_4()
    print(f"\n[+] All assets successfully generated in: {ASSETS_DIR}")


if __name__ == "__main__":
    main()
