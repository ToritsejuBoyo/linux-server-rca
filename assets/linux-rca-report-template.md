# Linux Server Root Cause Analysis (RCA) & Remediation

**Host:** `{{HOSTNAME}}`  
**Kernel:** `{{KERNEL_VERSION}}`  
**Incident Date (UTC):** `{{TIMESTAMP_UTC}}`  
**Severity:** `{{SEVERITY}}` (CRITICAL / HIGH / MEDIUM / LOW)

---

## 1. Executive Summary
- **Primary Bottleneck:** `{{PRIMARY_BOTTLENECK}}` (e.g., OOM Killer termination of JVM, Inode exhaustion on `/var/spool`, I/O wait lock)
- **Impacted Daemons:** `{{IMPACTED_SERVICES}}`
- **Root Cause Category:** `{{RCA_CATEGORY}}` (Resource Saturation / Configuration Error / Disk Full / Hardware Fault)

---

## 2. Telemetry Evidence Table

| Component | Diagnostic Metric / Command | Observed Value | Normal Threshold |
| --- | --- | --- | --- |
| **Failed Services** | `systemctl --failed` | `{{FAILED_SERVICE_NAME}}` | 0 failed units |
| **Memory / OOM** | `dmesg | grep oom` | `{{OOM_LOG_SNIPPET}}` | 0 OOM events |
| **Disk Storage** | `df -hP {{MOUNT_POINT}}` | `{{DISK_USED_PCT}}%` | < 85% |
| **Inode Usage** | `df -iP {{MOUNT_POINT}}` | `{{INODE_USED_PCT}}%` | < 85% |
| **I/O Latency** | `iostat -xz` | `%util = {{IO_UTIL}}%` | < 70% |

---

## 3. Step-by-Step Remediation Playbook (Non-Destructive)

Execute the following commands in sequence:

```bash
# Step 1: Mitigate immediate bottleneck
{{MITIGATION_COMMANDS}}

# Step 2: Restart affected service safely
{{SERVICE_RECOVERY_COMMANDS}}

# Step 3: Validate recovery
systemctl is-active {{PRIMARY_SERVICE_NAME}}
```

---

## 4. Permanent Hardening Recommendations
1. `{{HARDENING_STEP_1}}`
2. `{{HARDENING_STEP_2}}`
