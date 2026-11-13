---
name: linux-server-rca
description: >-
  Diagnoses unresponsive or degraded Linux servers (RHEL, Ubuntu, Debian, Rocky Linux) by
  analyzing systemd service failures, journalctl/dmesg crash logs, OOM killer triggers, disk I/O
  bottlenecks, and inode exhaustion. Outputs a precise root cause analysis and verified,
  non-destructive recovery steps. Use when triaging a hung or degraded Linux host, investigating a
  failed systemd unit, analyzing journalctl or dmesg output, chasing high iowait or a full
  filesystem, or diagnosing an OOM-killed process.
license: MIT
version: 1.0.0
metadata:
  standard: agentskills.io
  dependencies: none (Python standard library only)
  access: read-only collectors; no state is modified on target systems
---

# Linux Systemd, Journalctl & Disk I/O Bottleneck RCA (`linux-server-rca`)

## Purpose & Target Roles
Designed for **Linux System Administrators, DevOps Engineers, and Site Reliability Engineers (SREs)**. This skill eliminates trial-and-error troubleshooting during server degradation, unhandled kernel panics, or application freeze events by interpreting system metrics and journal logs with deterministic diagnostic rigor.

## Operating Rules & Safety Guardrails
1. **Never Prescribe Destructive Resets:** Do NOT recommend `reboot -f`, `rm -rf`, or clearing `/var/log` blindly. Always diagnose root causes first.
2. **Read-Only Telemetry:** Rely strictly on read-only commands (`systemctl status`, `journalctl`, `dmesg`, `iostat`, `df -i`, `free -m`, `vmstat`, `/proc/`).
3. **Storage & Inode Distinction:** Always evaluate both block storage (`df -h`) and inode table capacity (`df -i`). Inode exhaustion causes write failures even when disk shows 50% free space.
4. **OOM vs. Memory Leak Isolation:** Distinguish between a sudden burst invocation triggering the Linux Out-Of-Memory (OOM) killer and a slow, persistent memory leak in background daemons.
5. **Cluster & High-Availability Awareness:** Verify cluster quorum status (etcd, Pacemaker, Corosync, Galera) before recommending service restarts on multi-node systems.
6. **Mandatory Client-Side Sanitization:** Always execute with `--sanitize` to mask hostnames and usernames using SHA-256 and map IP addresses to RFC 5737 test prefixes.

---

## Step 1: Telemetry & Input Acquisition

### Option 1: Bundled Read-Only Shell Script (Recommended for Live Hosts)
Run the collector script on the affected Linux host:
```bash
bash scripts/collect-linux-rca.sh --sanitize > /tmp/linux-triage.json
```

### Option 2: Standalone Deterministic Python Parser
Run the offline analyzer against the collected JSON bundle or raw log export:
```bash
python scripts/parse-linux-rca.py -i /tmp/linux-triage.json --sanitize --format markdown
```

### Option 3: Ad-Hoc Logs & CLI Snippets
Accept pasted outputs from:
- `systemctl --failed --no-legend`
- `journalctl -p 3 -xb -n 25 --no-pager`
- `dmesg -T | grep -iE 'oom|kill|error|corrupt|disk'`
- `df -hP && df -iP`
- `free -h`
- `ps -eo pid,stat,comm | awk '$2 ~ /D/'`

---

## Step 2: 5-Branch Diagnostic Decision Tree

1. **Branch 1: Systemd Service & Exit Code Failures:**
   Inspect failed systemd units (`systemctl --failed`). Map exit codes:
   - `status=203/EXEC`: Executable binary missing, corrupted, or lacking execute permissions.
   - `status=217/USER`: Configured `User=` or `Group=` does not exist.
   - `status=1/FAILURE`: Application config syntax error or unhandled exception.
   - `status=137/SIGKILL`: Process killed by OOM killer or external SIGKILL.
2. **Branch 2: Memory Starvation & Kernel OOM Killer:**
   Scan `dmesg` and journal logs for: `Out of memory: Kill process <PID> (<name>) score <score>`. Identify terminated process, verify total-vm and anon-rss, and recommend swapfile creation or systemd `MemoryMax=` ceilings.
3. **Branch 3: Inode vs. Disk Space Exhaustion:**
   Review `df -h` and `df -i`. Check `/var`, `/tmp`, and `/opt`. If inodes reach 90-100% while byte space is under 80%, identify runaway spool queues (postfix, PHP sessions) without deleting live files.
4. **Branch 4: Storage I/O Wait Bottlenecks:**
   Examine `%util` and `%iowait`. If `%util` reaches 85-100% or tasks report `blocked for more than 120 seconds`, identify processes in uninterruptible disk sleep (`D` state in `ps`).
5. **Branch 5: Filesystem Corruption & Read-Only Remounts:**
   Detect `EXT4-fs error ... Remounting filesystem read-only`. Warn administrator against unsafe reboots.

---

## Step 3: Structured Deliverable Generation
Populate and return the report following `assets/linux-rca-report-template.md`:
1. **Executive Incident Summary:** Primary bottleneck, impacted services, and overall severity.
2. **Telemetry Evidence Table:** Metrics, observed values, and baseline normal thresholds.
3. **Step-by-Step Remediation Plan:** Safe, verified, non-destructive terminal commands.
4. **Permanent Hardening Recommendations:** Long-term configuration fixes (systemd restart policies, `vm.swappiness`, logrotate).
5. **L2/L3 Ticket Escalation Brief:** Clean copy-paste incident summary for Jira / ServiceNow.

---

## Bundled Resources Reference
- **Telemetry Collector:** `scripts/collect-linux-rca.sh` (Read-only native Bash collector with /proc fallbacks).
- **RCA Parser:** `scripts/parse-linux-rca.py` (Zero-dependency Python 3 deterministic analyzer with SHA-256 sanitization).
- **Technical Reference:** `references/linux-troubleshooting-matrix.md` (Systemd exit codes, kernel error thresholds, and OOM patterns).
- **Output Template:** `assets/linux-rca-report-template.md` (Standard RCA and ticket escalation template).

---

## Data Handling & Sanitization

Sanitization runs **client-side, before any output is produced**, so credentials and
personal data are removed on the operator's machine rather than being sent to a model
or pasted into a ticket.

Two layers apply:

1. This skill's own domain-aware masking (hostnames, accounts, and the identifiers
   specific to this domain).
2. A shared residual pass, [`scripts/sanitizer.py`](scripts/sanitizer.py), vendored
   identically across every skill in the library. It is the common floor: private keys,
   cloud provider keys, JWTs and bearer tokens, connection-string passwords, assigned
   secrets, emails, IPv4/IPv6 addresses, MAC addresses, GUIDs, SSNs, payment card
   numbers, and phone numbers.

The contract is enforced by `tests/sanitizer_conformance_test.py`, which runs the same
adversarial corpus in every skill. Documentation placeholders (RFC 5737/3849 addresses,
RFC 7042 MAC ranges, `example.com` names, and existing `[REDACTED-*]` tokens) are
preserved, so the pass is safe to apply more than once.

Sanitization is thorough and tested, but it is not a substitute for reading output
before sharing it outside your organization.
