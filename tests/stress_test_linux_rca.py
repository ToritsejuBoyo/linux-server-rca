#!/usr/bin/env python3
"""Comprehensive 38-Test Stress & Fuzzing Battery for Linux Server RCA (stress_test_linux_rca.py)

Executes 38 distinct tests covering:
- Malformed inputs, binary garbage, HTML, empty payloads (Tests 1-7)
- Kernel OOM killer variations across RHEL, Ubuntu, cgroup v2 (Tests 8-10)
- Inode vs disk space exhaustion boundary conditions (Tests 11-15)
- Systemd exit code diagnostics & cluster awareness (Tests 16-23)
- Storage I/O wait saturation & filesystem corruption (Tests 24-26)
- Compound disaster scenarios (Test 27)
- Adversarial credential & network sanitization (Tests 28-29)
- Massive scale log throughput benchmark (Test 30)
- Enterprise hardened diagnostics: CHDIR, SETSCHEDULER, STDIN (Tests 31-33)
- Snap/loop mount filtering (Test 34)
- Variable hung task intervals & storage block timeouts (Tests 35-36)
- Multi-service exit code isolation (Test 37)
- Comprehensive IPv6, public IPv4, and UPN sanitization (Test 38)
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import time
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
_candidate_1 = ROOT_DIR / "scripts" / "parse-linux-rca.py"
_candidate_2 = (
    ROOT_DIR / "skills" / "linux-server-rca" / "scripts" / "parse-linux-rca.py"
)
SCRIPT_PATH = _candidate_1 if _candidate_1.exists() else _candidate_2

spec = importlib.util.spec_from_file_location("parse_linux", str(SCRIPT_PATH))
rca = importlib.util.module_from_spec(spec)
sys.modules["parse_linux"] = rca
spec.loader.exec_module(rca)


class LinuxServerRCAThirtyTestSuite(unittest.TestCase):

  # -------------------------------------------------------------
  # Group 1: Malformed, Corrupted & Boundary Inputs (Tests 1-7)
  # -------------------------------------------------------------

  def test_01_empty_input(self):
    """Test 01: Completely empty input string (0 bytes)."""
    bundle = rca.parse_telemetry("")
    findings, sanitizer = rca.evaluate_rca(bundle, sanitize=True)
    md = rca.format_markdown(bundle, findings, sanitizer, sanitize=True)
    self.assertIn("No critical server degradation", md)
    self.assertEqual(len(findings), 0)

  def test_02_whitespace_only(self):
    """Test 02: Whitespace, tabs, and newline only input."""
    bundle = rca.parse_telemetry("   \n\t\r\n   \n")
    findings, sanitizer = rca.evaluate_rca(bundle, sanitize=True)
    md = rca.format_markdown(bundle, findings, sanitizer, sanitize=True)
    self.assertIn("No critical server degradation", md)
    self.assertEqual(len(findings), 0)

  def test_03_corrupted_json_truncated(self):
    """Test 03: Truncated JSON payload mid-stream."""
    truncated = '{"timestamp_utc": "2026-11-06T00:00:00Z", "failed_services": ["nginx'
    bundle = rca.parse_telemetry(truncated)
    findings, _ = rca.evaluate_rca(bundle, sanitize=True)
    self.assertIsInstance(findings, list)

  def test_04_binary_garbage(self):
    """Test 04: Non-ASCII raw binary byte sequences."""
    garbage = "\x00\x01\x02\x03\xff\xfe\xfd\x80\x90\xaa\xbb\xcc"
    bundle = rca.parse_telemetry(garbage)
    findings, _ = rca.evaluate_rca(bundle, sanitize=True)
    self.assertIsInstance(findings, list)

  def test_05_html_error_page(self):
    """Test 05: HTTP 502 Bad Gateway HTML string instead of JSON."""
    html_page = """<!DOCTYPE html>
        <html><head><title>502 Bad Gateway</title></head>
        <body><center><h1>502 Bad Gateway</h1></center><hr><center>nginx/1.18.0</center></body>
        </html>"""
    bundle = rca.parse_telemetry(html_page)
    findings, _ = rca.evaluate_rca(bundle, sanitize=True)
    self.assertIsInstance(findings, list)

  def test_06_null_payload_all_keys(self):
    """Test 06: JSON where every single key has null value."""
    payload = json.dumps({
        "timestamp_utc": None,
        "hostname": None,
        "kernel": None,
        "uptime": None,
        "ip_addresses": None,
        "failed_services": None,
        "disk_usage": None,
        "inode_usage": None,
        "memory": None,
        "processes_uninterruptible_sleep": None,
        "recent_kernel_errors": None,
    })
    bundle = rca.parse_telemetry(payload)
    findings, sanitizer = rca.evaluate_rca(bundle, sanitize=True)
    md = rca.format_markdown(bundle, findings, sanitizer, sanitize=True)
    self.assertIn("mock-server-", md)
    self.assertEqual(len(findings), 0)

  def test_07_empty_dict_payload(self):
    """Test 07: JSON with empty object '{}'."""
    bundle = rca.parse_telemetry("{}")
    findings, sanitizer = rca.evaluate_rca(bundle, sanitize=True)
    self.assertEqual(len(findings), 0)

  # -------------------------------------------------------------
  # Group 2: Kernel Out-Of-Memory (OOM) Killer Variations (Tests 8-10)
  # -------------------------------------------------------------

  def test_08_kernel_oom_legacy_rhel7(self):
    """Test 08: Legacy RHEL 7 / CentOS 7 kernel OOM kill log format."""
    payload = {
        "hostname": "legacy-db01.corp",
        "failed_services": ["mysqld.service"],
        "memory": {"oom_killer_events": 1},
        "recent_kernel_errors": [
            (
                "kernel: [12903.11] Out of memory: Kill process 22910 (mysqld)"
                " score 890 or sacrifice child"
            ),
            (
                "systemd[1]: mysqld.service: Main process exited, code=killed,"
                " status=9/KILL"
            ),
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    oom = next((f for f in findings if f.category == "OOM_KILLER"), None)
    self.assertIsNotNone(oom)
    self.assertIn("mysqld", oom.title)

  def test_09_kernel_oom_cgroup_v2_ubuntu24(self):
    """Test 09: Modern Ubuntu 24.04 / RHEL 9 cgroup v2 container OOM kill format."""
    payload = {
        "hostname": "k8s-pod-node.corp",
        "failed_services": ["containerd.service"],
        "memory": {"oom_killer_events": 1},
        "recent_kernel_errors": [
            (
                "kernel: [4421.90] oom-kill:constraint=CONSTRAINT_MEMCG,"
                "task=python_worker,pid=14092,uid=1000"
            ),
            (
                "systemd[1]: containerd.service: Main process exited,"
                " code=killed, status=9/KILL"
            ),
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    oom = next((f for f in findings if f.category == "OOM_KILLER"), None)
    self.assertIsNotNone(oom)
    self.assertIn("python_worker", oom.title)

  def test_10_kernel_oom_multiple_victims(self):
    """Test 10: Log with multiple victim processes in same incident."""
    payload = {
        "hostname": "busy-host.corp",
        "failed_services": ["elasticsearch.service"],
        "memory": {"oom_killer_events": 2},
        "recent_kernel_errors": [
            "kernel: Out of memory: Killed process 501 (logstash)",
            "kernel: Out of memory: Killed process 502 (java)",
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    oom = next((f for f in findings if f.category == "OOM_KILLER"), None)
    self.assertIsNotNone(oom)
    self.assertEqual(oom.severity, "CRITICAL")

  # -------------------------------------------------------------
  # Group 3: Inode vs Storage Exhaustion Disambiguation (Tests 11-15)
  # -------------------------------------------------------------

  def test_11_inode_exhaustion_100pct_var(self):
    """Test 11: 100% Inode saturation on /var with 50% block space free."""
    payload = {
        "disk_usage": ["/dev/sda2 100G 50G 50G 50% /var"],
        "inode_usage": ["/dev/sda2 6553600 6553600 0 100% /var"],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    inode_find = next((f for f in findings if f.category == "INODE_EXHAUSTION"), None)
    self.assertIsNotNone(inode_find)
    self.assertEqual(inode_find.severity, "CRITICAL")
    self.assertIn("/var", inode_find.title)

  def test_12_inode_exhaustion_92pct_threshold(self):
    """Test 12: Inode usage at 92% (triggers threshold >= 90%)."""
    payload = {
        "inode_usage": ["/dev/sda1 1000000 920000 80000 92% /opt"],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    self.assertTrue(any(f.category == "INODE_EXHAUSTION" for f in findings))

  def test_13_inode_normal_89pct_boundary(self):
    """Test 13: Inode usage at 89% (strictly below 90% threshold -> no alarm)."""
    payload = {
        "inode_usage": ["/dev/sda1 1000000 890000 110000 89% /opt"],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    self.assertFalse(any(f.category == "INODE_EXHAUSTION" for f in findings))

  def test_14_disk_space_full_99pct_root(self):
    """Test 14: Block disk space at 99% on root filesystem."""
    payload = {
        "disk_usage": ["/dev/mapper/rootvg-root 50G 49.5G 0.5G 99% /"],
        "inode_usage": ["/dev/mapper/rootvg-root 2000000 200000 1800000 10% /"],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    disk_find = next((f for f in findings if f.category == "DISK_SPACE_FULL"), None)
    self.assertIsNotNone(disk_find)
    self.assertEqual(disk_find.severity, "HIGH")

  def test_15_disk_space_normal_85pct_boundary(self):
    """Test 15: Block disk space at 85% (strictly below 90% threshold -> no alarm)."""
    payload = {
        "disk_usage": ["/dev/sda1 100G 85G 15G 85% /data"],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    self.assertFalse(any(f.category == "DISK_SPACE_FULL" for f in findings))

  # -------------------------------------------------------------
  # Group 4: Systemd Service Unit Failures & Quorum (Tests 16-23)
  # -------------------------------------------------------------

  def test_16_systemd_exit_203_exec(self):
    """Test 16: status=203/EXEC missing binary executable."""
    payload = {
        "failed_services": ["api-worker.service"],
        "recent_kernel_errors": [
            "systemd[1]: api-worker.service: Main process exited, code=exited,"
            " status=203/EXEC"
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if f.category == "SYSTEMD_FAILURE")
    self.assertIn("status=203/EXEC", f.title)
    self.assertEqual(f.severity, "HIGH")

  def test_17_systemd_exit_217_user(self):
    """Test 17: status=217/USER missing configured user account."""
    payload = {
        "failed_services": ["prometheus.service"],
        "recent_kernel_errors": [
            "systemd[1]: prometheus.service: Main process exited, code=exited,"
            " status=217/USER"
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if f.category == "SYSTEMD_FAILURE")
    self.assertIn("status=217/USER", f.title)
    self.assertTrue(any("useradd" in step for step in f.remediation_steps))

  def test_18_systemd_exit_1_failure(self):
    """Test 18: status=1/FAILURE application configuration syntax crash."""
    payload = {
        "failed_services": ["nginx.service"],
        "recent_kernel_errors": [
            "nginx[102]: nginx: [emerg] unknown directive 'proxy_pas' in /etc/nginx/nginx.conf:45",
            "systemd[1]: nginx.service: Main process exited, code=exited, status=1/FAILURE",
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if f.category == "SYSTEMD_FAILURE")
    self.assertIn("status=1/FAILURE", f.title)

  def test_19_systemd_exit_137_sigkill(self):
    """Test 19: status=137 process killed forcefully."""
    payload = {
        "failed_services": ["redis.service"],
        "recent_kernel_errors": [
            "systemd[1]: redis.service: Main process exited, code=killed,"
            " status=137"
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if f.category == "SYSTEMD_FAILURE")
    self.assertIn("status=137", f.title)
    self.assertEqual(f.severity, "CRITICAL")

  def test_20_systemd_exit_143_sigterm(self):
    """Test 20: status=143 graceful shutdown request (low severity)."""
    payload = {
        "failed_services": ["sidecar.service"],
        "recent_kernel_errors": [
            "systemd[1]: sidecar.service: Main process exited, code=exited,"
            " status=143"
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if f.category == "SYSTEMD_FAILURE")
    self.assertEqual(f.severity, "LOW")

  def test_21_systemd_exit_unknown_code(self):
    """Test 21: Non-standard unmapped exit code (e.g. status=255/UNKNOWN)."""
    payload = {
        "failed_services": ["custom-sandbox.service"],
        "recent_kernel_errors": [
            "systemd[1]: custom-sandbox.service: Main process exited,"
            " code=exited, status=255/UNKNOWN"
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if f.category == "SYSTEMD_FAILURE")
    self.assertIn("custom-sandbox.service", f.title)

  def test_22_cluster_quorum_warning_etcd(self):
    """Test 22: Clustered etcd.service triggers High-Availability quorum warning."""
    payload = {
        "failed_services": ["etcd.service"],
        "recent_kernel_errors": [
            "systemd[1]: etcd.service: Main process exited, code=exited,"
            " status=1/FAILURE"
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if "etcd" in f.title)
    self.assertIsNotNone(f.cluster_warning)
    self.assertIn("HIGH-AVAILABILITY CLUSTER WARNING", f.cluster_warning)

  def test_23_cluster_quorum_warning_galera(self):
    """Test 23: Clustered galera.service triggers split-brain warning."""
    payload = {
        "failed_services": ["galera-cluster.service"],
        "recent_kernel_errors": [
            "systemd[1]: galera-cluster.service: Main process exited,"
            " code=exited, status=1/FAILURE"
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if "galera" in f.title)
    self.assertIsNotNone(f.cluster_warning)
    self.assertIn("HIGH-AVAILABILITY CLUSTER WARNING", f.cluster_warning)

  # -------------------------------------------------------------
  # Group 5: Storage I/O Wait Saturation & Filesystem Errors (Tests 24-26)
  # -------------------------------------------------------------

  def test_24_io_wait_high_util_99pct(self):
    """Test 24: Device utilization at 99.8% and %iowait at 42%."""
    payload = {
        "io_metrics": {"util_pct": 99.8, "iowait_pct": 42.0},
        "processes_uninterruptible_sleep": ["backup-tar (PID: 3341, State: D)"],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    io_find = next(f for f in findings if f.category == "IO_WAIT_BOTTLENECK")
    self.assertEqual(io_find.severity, "HIGH")
    self.assertIn("backup-tar", io_find.description)

  def test_25_io_wait_hung_task_d_state(self):
    """Test 25: Kernel hung task message with process in D-state."""
    payload = {
        "io_metrics": {"util_pct": 90.0, "iowait_pct": 35.0},
        "recent_kernel_errors": [
            "INFO: task postgres:1290 blocked for more than 120 seconds.",
            "echo 0 > /proc/sys/kernel/hung_task_timeout_secs disables this message.",
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    io_find = next(f for f in findings if f.category == "IO_WAIT_BOTTLENECK")
    self.assertEqual(io_find.severity, "CRITICAL")

  def test_26_filesystem_ext4_readonly_remount(self):
    """Test 26: EXT4-fs error triggering kernel read-only remount."""
    payload = {
        "recent_kernel_errors": [
            "kernel: [1892.44] EXT4-fs error (device sda1): ext4_lookup: deleted inode referenced: 1441793",
            "kernel: [1892.45] Remounting filesystem read-only",
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    fs_find = next((f for f in findings if f.category == "FILESYSTEM_ERROR"), None)
    self.assertIsNotNone(fs_find)
    self.assertEqual(fs_find.severity, "CRITICAL")
    self.assertTrue(any("fsck" in step for step in fs_find.remediation_steps))

  # -------------------------------------------------------------
  # Group 6: Compound Catastrophe Scenarios (Test 27)
  # -------------------------------------------------------------

  def test_27_compound_catastrophe_6_failures(self):
    """Test 27: Simultaneous OOM + Inode 100% + Disk 99% + Failed Unit + I/O Wait + Read-Only."""
    payload = {
        "hostname": "prod-catastrophe-node",
        "failed_services": ["cockroachdb.service"],
        "disk_usage": ["/dev/sda1 100G 99G 1G 99% /"],
        "inode_usage": ["/dev/sda2 1000000 1000000 0 100% /var"],
        "memory": {"oom_killer_events": 1},
        "io_metrics": {"util_pct": 99.5, "iowait_pct": 55.0},
        "recent_kernel_errors": [
            "kernel: Out of memory: Kill process 120 (cockroach) score 950",
            "systemd[1]: cockroachdb.service: Main process exited, code=killed, status=137",
            "INFO: task cockroach:120 blocked for more than 120 seconds.",
            "kernel: EXT4-fs error (device sda1): remounting filesystem read-only",
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    self.assertEqual(len(findings), 6)
    categories = {f.category for f in findings}
    self.assertEqual(
        categories,
        {
            "OOM_KILLER",
            "INODE_EXHAUSTION",
            "DISK_SPACE_FULL",
            "SYSTEMD_FAILURE",
            "IO_WAIT_BOTTLENECK",
            "FILESYSTEM_ERROR",
        },
    )

  # -------------------------------------------------------------
  # Group 7: Adversarial Security & Sanitization Checks (Tests 28-29)
  # -------------------------------------------------------------

  def test_28_adversarial_sanitization_uri_passwords(self):
    """Test 28: Scrub database URI credentials with special chars."""
    sanitizer = rca.Sanitizer()
    log_sample = (
        "Failed connecting to"
        " postgresql://svc_user:P@ssw0rd!#%&*=99@10.0.1.25:5432/finance_db"
    )
    scrubbed = sanitizer.scrub_text(log_sample)
    self.assertNotIn("P@ssw0rd!#%&*=99", scrubbed)
    self.assertIn("[REDACTED-SECRET]", scrubbed)

  def test_29_adversarial_sanitization_private_ips(self):
    """Test 29: Obfuscate private 10.x, 172.16.x, and 192.168.x IPs."""
    sanitizer = rca.Sanitizer()
    sample = "Packet drop from 10.10.10.10 to 172.20.5.5 and 192.168.100.1"
    scrubbed = sanitizer.scrub_text(sample)
    self.assertNotIn("10.10.10.10", scrubbed)
    self.assertNotIn("172.20.5.5", scrubbed)
    self.assertNotIn("192.168.100.1", scrubbed)
    self.assertIn("198.51.100.", scrubbed)

  # -------------------------------------------------------------
  # Group 8: Massive Scale Performance Benchmark (Test 30)
  # -------------------------------------------------------------

  def test_30_massive_scale_50k_lines_throughput(self):
    """Test 30: Throughput benchmark processing 50,000 log lines in under 1 second."""
    logs = [
        f"Nov 06 01:00:{i%60:02d} srv proc[{i}]: connection accepted from"
        f" client {i}"
        for i in range(50000)
    ]
    logs[10000] = (
        "Nov 06 01:00:15 srv kernel: Out of memory: Kill process 880 (worker)"
        " score 900"
    )

    payload = {
        "hostname": "big-log-node.local",
        "failed_services": ["worker.service"],
        "memory": {"oom_killer_events": 1},
        "recent_kernel_errors": logs,
    }

    t0 = time.time()
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, sanitizer = rca.evaluate_rca(bundle, sanitize=True)
    md = rca.format_markdown(bundle, findings, sanitizer, sanitize=True)
    elapsed = time.time() - t0

    print(
        f"\n[SCALE TEST 30] 50,000 lines triaged and rendered in"
        f" {elapsed:.3f}s"
    )
    self.assertLess(elapsed, 1.0, "50k log lines must parse in under 1.0 second")
    self.assertGreater(len(findings), 0)

  # -------------------------------------------------------------
  # Group 9: Enterprise Hardened Diagnostic Coverage (Tests 31-38)
  # -------------------------------------------------------------

  def test_31_systemd_exit_200_chdir(self):
    """Test 31: status=200/CHDIR missing working directory."""
    payload = {
        "failed_services": ["app-backend.service"],
        "recent_kernel_errors": [
            "systemd[1]: app-backend.service: Main process exited, code=exited, status=200/CHDIR"
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if f.category == "SYSTEMD_FAILURE")
    self.assertIn("status=200/CHDIR", f.title)
    self.assertIn("WorkingDirectory", f.description)

  def test_32_systemd_exit_214_setscheduler(self):
    """Test 32: status=214/SETSCHEDULER missing real-time capabilities."""
    payload = {
        "failed_services": ["rt-audio.service"],
        "recent_kernel_errors": [
            "systemd[1]: rt-audio.service: Main process exited, code=exited, status=214/SETSCHEDULER"
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if f.category == "SYSTEMD_FAILURE")
    self.assertIn("status=214/SETSCHEDULER", f.title)
    self.assertTrue(any("CAP_SYS_NICE" in h for h in f.remediation_steps))

  def test_33_systemd_exit_208_stdin(self):
    """Test 33: status=208/STDIN file descriptor redirection failure."""
    payload = {
        "failed_services": ["collector.service"],
        "recent_kernel_errors": [
            "systemd[1]: collector.service: Main process exited, code=exited, status=208/STDIN"
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if f.category == "SYSTEMD_FAILURE")
    self.assertIn("status=208/STDIN", f.title)

  def test_34_snap_loop_mount_filtering(self):
    """Test 34: Ensure Ubuntu /dev/loop and /snap mounts at 100% do not trigger false alarms."""
    payload = {
        "disk_usage": [
            "/dev/sda1 100G 40G 60G 40% /",
            "/dev/loop0 55M 55M 0 100% /snap/core/1234",
            "/dev/loop1 64M 64M 0 100% /snap/core22/864",
        ],
        "inode_usage": [
            "/dev/sda1 6553600 500000 6053600 8% /",
            "/dev/loop0 12800 12800 0 100% /snap/core/1234",
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    disk_or_inode = [
        f for f in findings if f.category in ("DISK_SPACE_FULL", "INODE_EXHAUSTION")
    ]
    self.assertEqual(len(disk_or_inode), 0, "Snap/loop devices at 100% must be ignored")

  def test_35_variable_hung_task_duration(self):
    """Test 35: Detect hung tasks with variable intervals (e.g. 60s or 300s)."""
    payload = {
        "recent_kernel_errors": [
            "INFO: task postgres:1849 blocked for more than 60 seconds.",
            "echo 0 > /proc/sys/kernel/hung_task_timeout_secs disables this message.",
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    io_find = next(f for f in findings if f.category == "IO_WAIT_BOTTLENECK")
    self.assertEqual(io_find.severity, "CRITICAL")
    self.assertTrue(
        any("blocked for more than 60 seconds" in ev for ev in io_find.evidence)
    )

  def test_36_storage_block_controller_error(self):
    """Test 36: Detect storage block driver and NVMe command timeouts."""
    payload = {
        "recent_kernel_errors": [
            "kernel: [ 102.345] blk_update_request: I/O error, dev sda, sector 98765432 op 0x0:(READ)",
            "kernel: [ 102.346] Buffer I/O error on dev sda1, logical block 12345, async page read",
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    io_find = next(f for f in findings if f.category == "IO_WAIT_BOTTLENECK")
    self.assertEqual(io_find.severity, "CRITICAL")
    self.assertTrue(any("blk_update_request" in ev for ev in io_find.evidence))

  def test_37_multiservice_exit_code_isolation(self):
    """Test 37: Isolate distinct exit codes for multiple failed services without crosstalk."""
    payload = {
        "failed_services": ["web-proxy.service", "cache-store.service"],
        "recent_kernel_errors": [
            "systemd[1]: web-proxy.service: Main process exited, code=exited, status=203/EXEC",
            "systemd[1]: Failed to start web-proxy.service.",
            "systemd[1]: cache-store.service: Main process exited, code=exited, status=1/FAILURE",
            "systemd[1]: Failed to start cache-store.service.",
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    svc_findings = [f for f in findings if f.category == "SYSTEMD_FAILURE"]
    self.assertEqual(len(svc_findings), 2)
    f_proxy = next(f for f in svc_findings if "web-proxy.service" in f.title)
    f_cache = next(f for f in svc_findings if "cache-store.service" in f.title)
    self.assertIn("status=203/EXEC", f_proxy.title)
    self.assertIn("status=1/FAILURE", f_cache.title)

  def test_38_adversarial_sanitization_ipv6_and_emails(self):
    """Test 38: Scrub public IPv4, IPv6 addresses, and corporate UPNs (Rule 4)."""
    sanitizer = rca.Sanitizer()
    raw = (
        "Alert sent to admin.ops@enterprise.corp regarding host fe80::215:5dff:fe00:402 "
        "connecting to public api 142.250.190.46 and IPv6 2001:0db8:85a3:0000:0000:8a2e:0370:7334."
    )
    scrubbed = sanitizer.scrub_text(raw)
    self.assertNotIn("admin.ops@enterprise.corp", scrubbed)
    self.assertIn("user-masked@synthetic-test.local", scrubbed)
    self.assertNotIn("142.250.190.46", scrubbed)
    self.assertNotIn("2001:0db8:85a3:0000:0000:8a2e:0370:7334", scrubbed)
    self.assertIn("2001:db8::1", scrubbed)


def main():
  print("======================================================================")
  print("Executing Comprehensive 38-Test Stress & Fuzzing Battery")
  print("======================================================================")
  suite = unittest.TestLoader().loadTestsFromTestCase(
      LinuxServerRCAThirtyTestSuite
  )
  runner = unittest.TextTestRunner(verbosity=2)
  res = runner.run(suite)
  if res.wasSuccessful():
    print(
        f"\nSUCCESS: All {res.testsRun} rigorous stress tests passed with exit"
        " code 0."
    )
    return 0
  else:
    print(
        f"\nFAILURE: {len(res.failures)} failed, {len(res.errors)} errors out"
        f" of {res.testsRun} tests."
    )
    return 1


if __name__ == "__main__":
  sys.exit(main())
