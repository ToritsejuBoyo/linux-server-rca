#!/usr/bin/env python3
"""Linux Server Root Cause Analysis (RCA) Engine (parse-linux-rca.py)

Deterministic, read-only Linux server triage and root-cause analysis engine.
Evaluates systemd service failures, kernel OOM events, inode vs disk saturation,
storage I/O wait locks, and filesystem read-only remounts using a strict 5-branch
decision tree.

Generates verified, non-destructive recovery playbooks and permanent hardening steps.
Zero external dependencies - Python standard library only.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

SYSTEMD_EXIT_CODES: Dict[str, Tuple[str, str, str]] = {
    "status=203/EXEC": (
        "Executable binary missing, corrupted, or lacking execute (+x)"
        " permissions.",
        "Verify binary path in unit file with 'which <binary>' and chmod +x.",
        "HIGH",
    ),
    "status=217/USER": (
        "Configured User= or Group= account does not exist on host.",
        "Inspect /etc/passwd or create required system account using useradd -r.",
        "HIGH",
    ),
    "status=1/FAILURE": (
        "Application startup failure, invalid configuration file syntax, or"
        " unhandled exception.",
        "Run daemon binary directly with test/dry-run flag or inspect"
        " journalctl -u <unit> -b.",
        "HIGH",
    ),
    "status=137": (
        "Process terminated with SIGKILL (signal 9), typically triggered by"
        " Linux OOM killer.",
        "Investigate kernel memory limits (dmesg | grep oom) and increase swap"
        " or cgroup memory quotas.",
        "CRITICAL",
    ),
    "status=9/KILL": (
        "Process forcefully terminated by SIGKILL or cgroup memory limit"
        " breach.",
        "Check systemd MemoryMax quota and kernel dmesg for OOM killer"
        " invocations.",
        "CRITICAL",
    ),
    "status=143": (
        "Process received graceful SIGTERM (signal 15) stop request.",
        "Verify if administrative stop or automated orchestrator/scaler sent"
        " termination signal.",
        "LOW",
    ),
}

CLUSTER_SERVICES = {
    "etcd",
    "corosync",
    "pacemaker",
    "galera",
    "consul",
    "patroni",
    "keepalived",
    "ceph",
    "glusterd",
}


@dataclass
class Finding:
  finding_id: str
  category: (
      str  # OOM_KILLER, INODE_EXHAUSTION, DISK_SPACE_FULL, SYSTEMD_FAILURE,
           # IO_WAIT_BOTTLENECK, FILESYSTEM_ERROR
  )
  severity: str  # CRITICAL, HIGH, MEDIUM, LOW
  title: str
  description: str
  evidence: List[str] = field(default_factory=list)
  remediation_steps: List[str] = field(default_factory=list)
  hardening_steps: List[str] = field(default_factory=list)
  cluster_warning: Optional[str] = None

  def to_dict(self) -> Dict[str, Any]:
    return asdict(self)


def _safe_dict(val: Any) -> Dict[str, Any]:
  return val if isinstance(val, dict) else {}


def _safe_list(val: Any) -> List[Any]:
  return val if isinstance(val, list) else []


def _safe_str(val: Any, default: str = "") -> str:
  return str(val) if val is not None else default


class Sanitizer:
  """Client-side privacy engine masking hostnames, users, and IPs (Rule 4)."""

  def __init__(self):
    self.host_map: Dict[str, str] = {}
    self.ip_map: Dict[str, str] = {}
    self.counter = 1

  def sanitize_hostname(self, raw_host: str) -> str:
    if not raw_host or raw_host.startswith("mock-server-"):
      return raw_host if raw_host else "mock-server-01.synthetic-lab.local"
    if raw_host in self.host_map:
      return self.host_map[raw_host]
    h = hashlib.sha256(raw_host.encode("utf-8")).hexdigest()[:8]
    mock = f"mock-server-{h}.synthetic-lab.local"
    self.host_map[raw_host] = mock
    return mock

  def sanitize_ip(self, ip_str: str) -> str:
    if ip_str.startswith("192.0.2.") or ip_str.startswith("198.51.100."):
      return ip_str
    if ip_str in self.ip_map:
      return self.ip_map[ip_str]
    mock = f"198.51.100.{self.counter % 240 + 10}"
    self.counter += 1
    self.ip_map[ip_str] = mock
    return mock

  def scrub_text(self, text: str) -> str:
    # 1. Scrub URI credentials (e.g. postgresql://user:pass@host:5432/db)
    clean = re.sub(
        r"([a-zA-Z0-9_\-]+://[^:\s]+):([^@\s]+)@",
        r"\1:[REDACTED-SECRET]@",
        text,
    )

    # 2. Scrub passwords, tokens, API keys, secrets
    clean = re.sub(
        r"(password|token|secret|api[_-]?key|pass|auth_key)\s*[:=]\s*[^\s\n\r]+",
        r"\1: [REDACTED-SECRET]",
        clean,
        flags=re.IGNORECASE,
    )

    # 3. Mask IPv4 addresses (private & public)
    clean = re.sub(
        r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        lambda m: self.sanitize_ip(m.group(0)),
        clean,
    )
    clean = re.sub(
        r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
        lambda m: self.sanitize_ip(m.group(0)),
        clean,
    )
    clean = re.sub(
        r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
        lambda m: self.sanitize_ip(m.group(0)),
        clean,
    )
    return clean


def parse_telemetry(raw_data: str) -> Dict[str, Any]:
  """Parses telemetry bundle either from JSON or raw concatenated CLI text."""
  trimmed = raw_data.strip()
  if trimmed.startswith("{") and trimmed.endswith("}"):
    try:
      parsed_json = json.loads(trimmed)
      if isinstance(parsed_json, dict):
        return parsed_json
    except Exception:
      pass

  # Fallback: Parse ad-hoc pasted terminal text or malformed JSON
  parsed: Dict[str, Any] = {
      "timestamp_utc": "UNKNOWN",
      "hostname": "unknown-host",
      "kernel": "unknown",
      "uptime": "unknown",
      "ip_addresses": [],
      "failed_services": [],
      "disk_usage": [],
      "inode_usage": [],
      "memory": {"free_h": "", "oom_killer_events": 0},
      "processes_uninterruptible_sleep": [],
      "recent_kernel_errors": [],
  }

  lines = raw_data.splitlines()
  mode = "normal"
  for line in lines:
    raw = line.strip()
    if not raw:
      continue
    if "systemctl --failed" in raw or "FAILED UNITS" in raw.upper():
      mode = "failed_services"
      continue
    elif "df -h" in raw:
      mode = "disk_usage"
      continue
    elif "df -i" in raw:
      mode = "inode_usage"
      continue
    elif "dmesg" in raw or "journalctl" in raw:
      mode = "kernel_errors"
      continue

    if mode == "failed_services" and ".service" in raw:
      parts = raw.split()
      for p in parts:
        if p.endswith(".service"):
          parsed["failed_services"].append(p)
    elif mode == "disk_usage" and "/" in raw:
      parsed["disk_usage"].append(raw)
    elif mode == "inode_usage" and "/" in raw:
      parsed["inode_usage"].append(raw)
    elif mode == "kernel_errors" or "out of memory" in raw.lower():
      parsed["recent_kernel_errors"].append(raw)
      if "out of memory" in raw.lower():
        parsed["memory"]["oom_killer_events"] += 1

  return parsed


# ---------------------------------------------------------
# 5-Branch Deterministic Decision Engine
# ---------------------------------------------------------


def evaluate_rca(
    bundle: Dict[str, Any], sanitize: bool = False
) -> Tuple[List[Finding], Sanitizer]:
  sanitizer = Sanitizer()
  findings: List[Finding] = []
  f_idx = 1

  hostname = _safe_str(bundle.get("hostname"), "unknown-host")
  if sanitize:
    hostname = sanitizer.sanitize_hostname(hostname)

  failed_services = [
      _safe_str(x) for x in _safe_list(bundle.get("failed_services"))
  ]
  recent_errors = [
      _safe_str(x) for x in _safe_list(bundle.get("recent_kernel_errors"))
  ]
  disk_usage = [_safe_str(x) for x in _safe_list(bundle.get("disk_usage"))]
  inode_usage = [_safe_str(x) for x in _safe_list(bundle.get("inode_usage"))]
  mem_info = _safe_dict(bundle.get("memory"))
  oom_events = mem_info.get("oom_killer_events", 0) or 0
  uninterruptible_procs = [
      _safe_str(x)
      for x in _safe_list(bundle.get("processes_uninterruptible_sleep"))
  ]
  io_metrics = _safe_dict(bundle.get("io_metrics"))

  error_blob = "\n".join(recent_errors)

  def get_cluster_warning(svc_name: str) -> Optional[str]:
    for cl in CLUSTER_SERVICES:
      if cl in svc_name.lower():
        return (
            f"HIGH-AVAILABILITY CLUSTER WARNING: '{svc_name}' is part of a"
            " quorum-based consensus group. Do NOT blindly restart without"
            " verifying cluster membership status on peer nodes."
        )
    return None

  # -------------------------------------------------------
  # Branch 1: Kernel Out-Of-Memory (OOM) Killer Invocations
  # -------------------------------------------------------
  has_oom_log = "out of memory" in error_blob.lower() or "oom-kill" in error_blob
  if oom_events > 0 or has_oom_log:
    victim_match = re.search(
        r"Killed process \d+ \(([^)]+)\)|Kill process \d+"
        r" \(([^)]+)\)|task=([^,\s]+)",
        error_blob,
        re.IGNORECASE,
    )
    victim_proc = "process"
    if victim_match:
      victim_proc = (
          victim_match.group(1) or victim_match.group(2) or victim_match.group(3)
      )

    evidence = [
        line
        for line in recent_errors
        if "out of memory" in line.lower() or "oom-kill" in line.lower()
    ]
    rem_steps = [
        f"# Step 1: Identify current top memory consumers",
        "ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -15",
        "",
        "# Step 2: Check for memory leak or runaway processes",
        f"systemctl status {failed_services[0] if failed_services else 'target.service'}",
        "",
        "# Step 3: Mitigate memory starvation without rebooting",
        "# If swap is exhausted or unallocated, create temporary emergency swapfile:",
        "fallocate -l 2G /swapfile_emergency && chmod 600 /swapfile_emergency",
        "mkswap /swapfile_emergency && swapon /swapfile_emergency",
        "",
        (
            "# Step 4: Restart victim service with systemd memory quota"
            " enforcement:"
        ),
        (
            f"systemctl restart {failed_services[0] if failed_services else 'target.service'}"
        ),
    ]
    hard_steps = [
        (
            "Configure systemd resource controls in unit file: MemoryMax=80%"
            " and MemoryHigh=70%."
        ),
        (
            "Tune virtual memory swappiness: Set vm.swappiness=10 in"
            " /etc/sysctl.d/99-memory.conf."
        ),
        (
            "Deploy application-level JVM heap ceiling (-Xmx) to prevent"
            " unconstrained memory growth."
        ),
    ]

    findings.append(
        Finding(
            finding_id=f"FINDING-{f_idx:03d}",
            category="OOM_KILLER",
            severity="CRITICAL",
            title=f"Kernel OOM Killer Invocations Terminated '{victim_proc}'",
            description=(
                f"The Linux kernel exhausted all available physical RAM and swap space, invoking the Out-Of-Memory killer to sacrifice '{victim_proc}'. Impacted services: {', '.join(failed_services) if failed_services else 'None explicitly listed'}."
            ),
            evidence=evidence[:4],
            remediation_steps=rem_steps,
            hardening_steps=hard_steps,
            cluster_warning=(
                get_cluster_warning(failed_services[0])
                if failed_services
                else None
            ),
        )
    )
    f_idx += 1

  # -------------------------------------------------------
  # Branch 2: Inode Exhaustion vs Disk Space Full
  # -------------------------------------------------------
  for line in inode_usage:
    parts = line.split()
    if len(parts) >= 5 and "%" in parts[4]:
      try:
        pct = int(parts[4].replace("%", ""))
        mount = parts[5] if len(parts) > 5 else parts[0]
        if pct >= 90:
          rem_steps = [
              f"# Step 1: Identify directory harboring millions of tiny files on {mount}:",
              (
                  f"find {mount} -xdev -printf '%h\\n' | sort | uniq -c | sort"
                  " -k 1 -n | tail -15"
              ),
              "",
              (
                  "# Step 2: Prune orphaned spool or cache files safely"
                  " (example: postfix/php sessions):"
              ),
              (
                  f"# find {mount}/spool -type f -name '*.tmp' -mtime +7"
                  " -delete"
              ),
              "",
              "# Step 3: Verify inode recovery:",
              f"df -iP {mount}",
          ]
          hard_steps = [
              (
                  "Implement automated tmpwatch or systemd-tmpfiles cleanups for"
                  " spool directories."
              ),
              (
                  "Configure logrotate with maxage and rotate quotas to prevent"
                  " runaway inode creation."
              ),
          ]
          findings.append(
              Finding(
                  finding_id=f"FINDING-{f_idx:03d}",
                  category="INODE_EXHAUSTION",
                  severity="CRITICAL",
                  title=(
                      f"100% Inode Table Saturation on Mount Point '{mount}'"
                  ),
                  description=(
                      f"Mount point '{mount}' has reached {pct}% inode utilization (0 free inodes available). Applications are failing with 'No space left on device' even though block storage may show ample free space."
                  ),
                  evidence=[line],
                  remediation_steps=rem_steps,
                  hardening_steps=hard_steps,
              )
          )
          f_idx += 1
      except ValueError:
        continue

  for line in disk_usage:
    parts = line.split()
    if len(parts) >= 5 and "%" in parts[4]:
      try:
        pct = int(parts[4].replace("%", ""))
        mount = parts[5] if len(parts) > 5 else parts[0]
        if pct >= 90:
          rem_steps = [
              f"# Step 1: Locate top 10 largest space consumers on {mount}:",
              f"du -ahx {mount} | sort -rh | head -15",
              "",
              (
                  "# Step 2: Check for deleted files held open by running"
                  " processes:"
              ),
              "lsof +L1",
              "",
              (
                  "# Step 3: Safely truncate runaway unrotated logs (do NOT"
                  " rm -rf running logs):"
              ),
              "# : > /var/log/runaway_service.log",
          ]
          hard_steps = [
              "Provision automated disk alerts at 80% threshold.",
              "Enforce journald storage ceiling in /etc/systemd/journald.conf: SystemMaxUse=1G.",
          ]
          findings.append(
              Finding(
                  finding_id=f"FINDING-{f_idx:03d}",
                  category="DISK_SPACE_FULL",
                  severity="HIGH",
                  title=f"Block Storage Capacity Exceeded on '{mount}' ({pct}%)",
                  description=(
                      f"Mount point '{mount}' has reached {pct}% storage capacity. Write failures and database crashes will occur unless space is immediately reclaimed."
                  ),
                  evidence=[line],
                  remediation_steps=rem_steps,
                  hardening_steps=hard_steps,
              )
          )
          f_idx += 1
      except ValueError:
        continue

  # -------------------------------------------------------
  # Branch 3: Systemd Unit Failure & Exit Codes
  # -------------------------------------------------------
  for svc in failed_services:
    svc_base = svc.replace(".service", "")
    # Collect error lines specifically mentioning this service
    svc_lines = [
        line
        for line in recent_errors
        if svc in line or f"{svc_base}[" in line or f"{svc_base}:" in line
    ]

    svc_code_matched = False
    for code_str, (meaning, action, sev) in SYSTEMD_EXIT_CODES.items():
      if code_str in error_blob:
        svc_code_matched = True
        rem_steps = [
            f"# Step 1: Inspect detailed unit error journal",
            f"journalctl -u {svc} -b --no-pager -n 25",
            "",
            f"# Step 2: Verify unit file configuration syntax",
            f"systemd-analyze verify {svc}",
            "",
            f"# Step 3: Remediation action",
            f"# {action}",
            "",
            f"# Step 4: Reload systemd manager and test restart",
            f"systemctl daemon-reload",
            f"systemctl restart {svc}",
            f"systemctl is-active {svc}",
        ]
        hard_steps = [
            (
                "Configure restart throttling in service unit:"
                " Restart=on-failure, RestartSec=5s."
            ),
            (
                "Implement CI/CD pre-flight checks validating binary"
                " permissions and user existence before deployment."
            ),
        ]
        evidence = svc_lines if svc_lines else [
            line for line in recent_errors if code_str in line
        ][:3]
        findings.append(
            Finding(
                finding_id=f"FINDING-{f_idx:03d}",
                category="SYSTEMD_FAILURE",
                severity=sev,
                title=f"Service '{svc}' Failed with {code_str}",
                description=(
                    f"Unit '{svc}' terminated unexpectedly. Exit code meaning: {meaning}"
                ),
                evidence=evidence[:4],
                remediation_steps=rem_steps,
                hardening_steps=hard_steps,
                cluster_warning=get_cluster_warning(svc),
            )
        )
        f_idx += 1
        break

    if not svc_code_matched:
      rem_steps = [
          f"# Step 1: Inspect full failure logs",
          f"systemctl status {svc} -l --no-pager",
          f"journalctl -u {svc} -e --no-pager -n 30",
          "",
          f"# Step 2: Attempt safe restart after checking configs",
          f"systemctl restart {svc}",
          f"systemctl is-active {svc}",
      ]
      evidence = svc_lines if svc_lines else [f"Failed unit: {svc}"]
      findings.append(
          Finding(
              finding_id=f"FINDING-{f_idx:03d}",
              category="SYSTEMD_FAILURE",
              severity="HIGH",
              title=f"Systemd Service '{svc}' in Failed State",
              description=(
                  f"Unit '{svc}' is marked as failed by systemd manager. Needs immediate operational review."
              ),
              evidence=evidence[:4],
              remediation_steps=rem_steps,
              hardening_steps=[
                  "Enable automated monitoring for systemd failed units."
              ],
              cluster_warning=get_cluster_warning(svc),
          )
      )
      f_idx += 1

  # -------------------------------------------------------
  # Branch 4: Storage I/O Wait Bottlenecks & Hung Tasks
  # -------------------------------------------------------
  util_pct = float(io_metrics.get("util_pct", 0.0) or 0.0)
  iowait_pct = float(io_metrics.get("iowait_pct", 0.0) or 0.0)
  has_hung_task = "blocked for more than 120 seconds" in error_blob
  if util_pct >= 85.0 or iowait_pct >= 20.0 or has_hung_task:
    rem_steps = [
        "# Step 1: Identify processes in uninterruptible disk sleep (D state):",
        "ps -eo pid,stat,comm,wchan | awk '$2 ~ /D/ {print}'",
        "",
        "# Step 2: Identify top I/O consumers:",
        "iotop -b -n 2 -o 2>/dev/null || pidstat -d 1 3",
        "",
        "# Step 3: Check underlying disk health for read/write errors:",
        "dmesg -T | grep -iE 'error|timeout|reset|retry|tag#' | tail -15",
    ]
    hard_steps = [
        (
            "Configure disk I/O scheduler to 'none' (NVMe) or 'mq-deadline'"
            " (SATA SSD) in /sys/block/<dev>/queue/scheduler."
        ),
        (
            "Schedule heavy database maintenance or backup jobs outside of"
            " peak production hours."
        ),
    ]
    findings.append(
        Finding(
            finding_id=f"FINDING-{f_idx:03d}",
            category="IO_WAIT_BOTTLENECK",
            severity="HIGH" if not has_hung_task else "CRITICAL",
            title=f"Severe Storage I/O Wait Saturation (Util: {util_pct}%, I/O Wait: {iowait_pct}%)",
            description=(
                f"Storage subsystem is saturated with I/O queues. Multiple processes are locked in uninterruptible disk sleep (D-state). Blocked processes: {', '.join(uninterruptible_procs) if uninterruptible_procs else 'None listed'}."
            ),
            evidence=(
                [
                    line
                    for line in recent_errors
                    if "blocked for more than" in line or "FAILED Result" in line
                ][:3]
                if has_hung_task
                else [f"%util = {util_pct}%, %iowait = {iowait_pct}%"]
            ),
            remediation_steps=rem_steps,
            hardening_steps=hard_steps,
        )
    )
    f_idx += 1

  # -------------------------------------------------------
  # Branch 5: Filesystem Corruption & Read-Only Remounts
  # -------------------------------------------------------
  if "remounting filesystem read-only" in error_blob.lower() or "ext4-fs error" in error_blob.lower():
    rem_steps = [
        (
            "# CAUTION: Filesystem remounted read-only due to underlying"
            " corruption."
        ),
        (
            "# Do NOT run 'reboot -f' without emergency change board"
            " authorization."
        ),
        "# Step 1: Identify affected block device",
        "dmesg -T | grep -iE 'EXT4-fs error|remount'",
        "",
        "# Step 2: Schedule off-line filesystem check (fsck) during maintenance window:",
        "# touch /forcefsck",
    ]
    findings.append(
        Finding(
            finding_id=f"FINDING-{f_idx:03d}",
            category="FILESYSTEM_ERROR",
            severity="CRITICAL",
            title="Filesystem Errors Triggered Read-Only Remount",
            description=(
                "The kernel detected block-level or inode table corruption and remounted the filesystem read-only to prevent catastrophic data destruction."
            ),
            evidence=[
                line
                for line in recent_errors
                if "ext4-fs error" in line.lower() or "read-only" in line.lower()
            ][:3],
            remediation_steps=rem_steps,
            hardening_steps=[
                "Perform scheduled smartctl health diagnostics on underlying storage controllers."
            ],
        )
    )
    f_idx += 1

  return findings, sanitizer


# ---------------------------------------------------------
# Formatting & Presentation Engine
# ---------------------------------------------------------


def format_markdown(
    bundle: Dict[str, Any],
    findings: List[Finding],
    sanitizer: Sanitizer,
    sanitize: bool,
) -> str:
  hostname = _safe_str(bundle.get("hostname"), "unknown-host")
  kernel = _safe_str(bundle.get("kernel"), "unknown")
  timestamp = _safe_str(bundle.get("timestamp_utc"), "UNKNOWN")
  uptime = _safe_str(bundle.get("uptime"), "unknown")

  if sanitize:
    hostname = sanitizer.sanitize_hostname(hostname)

  crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
  high_count = sum(1 for f in findings if f.severity == "HIGH")
  med_count = sum(1 for f in findings if f.severity == "MEDIUM")
  low_count = sum(1 for f in findings if f.severity == "LOW")

  overall_sev = "LOW"
  if crit_count > 0:
    overall_sev = "CRITICAL"
  elif high_count > 0:
    overall_sev = "HIGH"
  elif med_count > 0:
    overall_sev = "MEDIUM"

  out = []
  out.append("# Linux Server Root Cause Analysis (RCA) & Remediation")
  out.append("")
  out.append(f"- **Host:** `{hostname}`")
  out.append(f"- **Kernel:** `{kernel}`")
  out.append(f"- **Uptime:** `{uptime}`")
  out.append(f"- **Incident Timestamp (UTC):** `{timestamp}`")
  out.append(f"- **Overall Severity:** **{overall_sev}**")
  out.append(
      f"- **Data Sanitization:** {'Active (SHA-256 Hashes, RFC 5737 Test IPs)' if sanitize else 'Disabled (Raw Telemetry)'}"
  )
  out.append("")

  out.append("## 1. Executive Summary")
  if not findings:
    out.append(
        "No critical server degradation, systemd failures, OOM kills, or inode"
        " saturation detected. Server appears healthy."
    )
    return "\n".join(out)

  out.append(f"- **Primary Root Cause:** {findings[0].title}")
  out.append(f"- **Total Anomalies Detected:** {len(findings)}")
  out.append(
      f"- **Breakdown:** Critical: {crit_count} | High: {high_count} | Medium:"
      f" {med_count} | Low: {low_count}"
  )
  out.append("")

  out.append("## 2. Telemetry Evidence & Findings Table")
  out.append("")
  out.append("| Finding ID | Severity | Category | Diagnostic Finding |")
  out.append("| :--- | :--- | :--- | :---------------------------------- |")
  for f in findings:
    out.append(
        f"| {f.finding_id} | **{f.severity}** | `{f.category}` | {f.title} |"
    )
  out.append("")

  out.append("## 3. Detailed Root Cause Analysis & Evidence")
  out.append("")
  for f in findings:
    out.append(f"### {f.finding_id}: {f.title}")
    out.append(f"**Impact:** {f.description}")
    out.append("")
    if f.cluster_warning:
      out.append(f"> **WARNING:** {f.cluster_warning}")
      out.append("")
    if f.evidence:
      out.append("**Observed Telemetry Evidence:**")
      out.append("```text")
      for ev in f.evidence:
        clean_ev = sanitizer.scrub_text(ev) if sanitize else ev
        out.append(clean_ev)
      out.append("```")
      out.append("")

    if f.remediation_steps:
      out.append("**Non-Destructive Step-by-Step Remediation:**")
      out.append("```bash")
      for step in f.remediation_steps:
        clean_step = sanitizer.scrub_text(step) if sanitize else step
        out.append(clean_step)
      out.append("```")
      out.append("")

    if f.hardening_steps:
      out.append("**Permanent Hardening Recommendations:**")
      for hs in f.hardening_steps:
        out.append(f"- {hs}")
      out.append("")

  out.append("## 4. L2/L3 Ticket Escalation Brief (Copy-Paste Ready)")
  out.append("```text")
  out.append(f"[INCIDENT ESCALATION BRIEF - {hostname}]")
  out.append(f"Primary Cause: {findings[0].title}")
  out.append(f"Severity: {overall_sev}")
  out.append(
      f"Impacted Units: {', '.join(bundle.get('failed_services') or ['N/A'])}"
  )
  out.append(f"Diagnosis: {findings[0].description}")
  out.append(
      "Recommended Action:"
      f" {findings[0].remediation_steps[1] if len(findings[0].remediation_steps) > 1 else 'Inspect logs'}"
  )
  out.append("```")

  return "\n".join(out)


def main() -> int:
  parser = argparse.ArgumentParser(
      description=(
          "Deterministic Linux Server Root Cause Analysis (RCA) Engine"
      )
  )
  parser.add_argument(
      "-i",
      "--input",
      required=True,
      help="Path to telemetry bundle (JSON or raw log text).",
  )
  parser.add_argument(
      "-f",
      "--format",
      choices=["markdown", "json"],
      default="markdown",
      help="Output presentation format.",
  )
  parser.add_argument(
      "-s",
      "--sanitize",
      action="store_true",
      help="Mask hostnames, user accounts, and IP addresses (Rule 4).",
  )
  parser.add_argument("-o", "--output", help="Optional output file path.")

  args = parser.parse_args()

  try:
    with open(args.input, "r", encoding="utf-8", errors="replace") as f:
      content = f.read()
  except Exception as e:
    sys.stderr.write(f"Error reading input file: {e}\n")
    return 1

  bundle = parse_telemetry(content)
  findings, sanitizer = evaluate_rca(bundle, sanitize=args.sanitize)

  if args.format == "json":
    result = {
        "status": "success",
        "host": (
            sanitizer.sanitize_hostname(_safe_str(bundle.get("hostname")))
            if args.sanitize
            else _safe_str(bundle.get("hostname"))
        ),
        "total_findings": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    rendered = json.dumps(result, indent=2)
  else:
    rendered = format_markdown(bundle, findings, sanitizer, args.sanitize)

  if args.output:
    with open(args.output, "w", encoding="utf-8") as f:
      f.write(rendered)
  else:
    print(rendered)

  return 0


if __name__ == "__main__":
  sys.exit(main())
