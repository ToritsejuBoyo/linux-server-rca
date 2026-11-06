#!/usr/bin/env python3
"""Comprehensive 30-Test Stress & Fuzzing Battery for Linux Server RCA (stress_test_linux_rca.py)

Executes 30 distinct tests covering:
- Malformed inputs, binary garbage, HTML, empty payloads (Tests 1-7)
- Kernel OOM killer variations across RHEL, Ubuntu, cgroup v2 (Tests 8-10)
- Inode vs disk space exhaustion boundary conditions (Tests 11-15)
- Systemd exit code diagnostics & cluster awareness (Tests 16-23)
- Storage I/O wait saturation & filesystem corruption (Tests 24-26)
- Compound disaster scenarios (Test 27)
- Adversarial credential & network sanitization (Tests 28-29)
- Massive scale log throughput benchmark (Test 30)
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
        "hostname": "batch-worker.corp",
        "failed_services": ["celery.service"],
        "memory": {"oom_killer_events": 2},
        "recent_kernel_errors": [
            (
                "kernel: Out of memory: Kill process 501 (celery) score 950 or"
                " sacrifice child"
            ),
            (
                "kernel: Out of memory: Kill process 502 (redis) score 920 or"
                " sacrifice child"
            ),
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    oom = next((f for f in findings if f.category == "OOM_KILLER"), None)
    self.assertIsNotNone(oom)
    self.assertEqual(oom.severity, "CRITICAL")

  # -------------------------------------------------------------
  # Group 3: Inode vs. Disk Storage Boundary Conditions (Tests 11-15)
  # -------------------------------------------------------------

  def test_11_inode_exhaustion_100pct_var(self):
    """Test 11: 100% Inode saturation on /var with 50% block space free."""
    payload = {
        "disk_usage": ["/dev/sda2 100G 50G 50G 50% /var"],
        "inode_usage": ["/dev/sda2 6553600 6553600 0 100% /var"],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    inode_f = next((f for f in findings if f.category == "INODE_EXHAUSTION"), None)
    self.assertIsNotNone(inode_f)
    self.assertEqual(inode_f.severity, "CRITICAL")
    self.assertIn("/var", inode_f.title)

  def test_12_inode_exhaustion_92pct_threshold(self):
    """Test 12: Inode usage at 92% (triggers threshold >= 90%)."""
    payload = {
        "inode_usage": ["/dev/sda1 1000000 920000 80000 92% /spool"],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    self.assertTrue(any(f.category == "INODE_EXHAUSTION" for f in findings))

  def test_13_inode_normal_89pct_boundary(self):
    """Test 13: Inode usage at 89% (strictly below 90% threshold -> no alarm)."""
    payload = {
        "inode_usage": ["/dev/sda1 1000000 890000 110000 89% /spool"],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    self.assertFalse(any(f.category == "INODE_EXHAUSTION" for f in findings))

  def test_14_disk_space_full_99pct_root(self):
    """Test 14: Block disk space at 99% on root filesystem."""
    payload = {
        "disk_usage": ["/dev/sda1 100G 99G 1G 99% /"],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    disk_f = next((f for f in findings if f.category == "DISK_SPACE_FULL"), None)
    self.assertIsNotNone(disk_f)
    self.assertEqual(disk_f.severity, "HIGH")

  def test_15_disk_space_normal_85pct_boundary(self):
    """Test 15: Block disk space at 85% (strictly below 90% threshold -> no alarm)."""
    payload = {
        "disk_usage": ["/dev/sda1 100G 85G 15G 85% /"],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    self.assertFalse(any(f.category == "DISK_SPACE_FULL" for f in findings))

  # -------------------------------------------------------------
  # Group 4: Systemd Failure Exit Codes & Cluster Awareness (Tests 16-23)
  # -------------------------------------------------------------

  def test_16_systemd_exit_203_exec(self):
    """Test 16: status=203/EXEC missing binary executable."""
    payload = {
        "failed_services": ["app.service"],
        "recent_kernel_errors": [
            "systemd[1]: app.service: Main process exited, code=exited,"
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
        "failed_services": ["daemon.service"],
        "recent_kernel_errors": [
            "systemd[1]: daemon.service: Main process exited, code=exited,"
            " status=217/USER"
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if f.category == "SYSTEMD_FAILURE")
    self.assertIn("status=217/USER", f.title)
    self.assertIn("useradd -r", " ".join(f.remediation_steps))

  def test_18_systemd_exit_1_failure(self):
    """Test 18: status=1/FAILURE application configuration syntax crash."""
    payload = {
        "failed_services": ["nginx.service"],
        "recent_kernel_errors": [
            "systemd[1]: nginx.service: Main process exited, code=exited,"
            " status=1/FAILURE"
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if f.category == "SYSTEMD_FAILURE")
    self.assertIn("status=1/FAILURE", f.title)

  def test_19_systemd_exit_137_sigkill(self):
    """Test 19: status=137 process killed forcefully."""
    payload = {
        "failed_services": ["worker.service"],
        "recent_kernel_errors": [
            "systemd[1]: worker.service: Main process exited, code=killed,"
            " status=137"
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if f.category == "SYSTEMD_FAILURE")
    self.assertEqual(f.severity, "CRITICAL")
    self.assertIn("status=137", f.title)

  def test_20_systemd_exit_143_sigterm(self):
    """Test 20: status=143 graceful shutdown request (low severity)."""
    payload = {
        "failed_services": ["cron.service"],
        "recent_kernel_errors": [
            "systemd[1]: cron.service: Main process exited, code=killed,"
            " status=143"
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    f = next(f for f in findings if f.category == "SYSTEMD_FAILURE")
    self.assertEqual(f.severity, "LOW")

  def test_21_systemd_exit_unknown_code(self):
    """Test 21: Non-standard unmapped exit code (e.g. status=226/NAMESPACE)."""
    payload = {
        "failed_services": ["custom-sandbox.service"],
        "recent_kernel_errors": [
            "systemd[1]: custom-sandbox.service: Main process exited,"
            " code=exited, status=226/NAMESPACE"
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
        "io_metrics": {
            "device": "nvme0n1",
            "util_pct": 99.8,
            "iowait_pct": 42.0,
        },
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    io_f = next((f for f in findings if f.category == "IO_WAIT_BOTTLENECK"), None)
    self.assertIsNotNone(io_f)
    self.assertIn("99.8%", io_f.title)

  def test_25_io_wait_hung_task_d_state(self):
    """Test 25: Kernel hung task message with process in D-state."""
    payload = {
        "processes_uninterruptible_sleep": ["mysqld (PID: 2401, State: D)"],
        "recent_kernel_errors": [
            "INFO: task mysqld:2401 blocked for more than 120 seconds."
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    io_f = next((f for f in findings if f.category == "IO_WAIT_BOTTLENECK"), None)
    self.assertIsNotNone(io_f)
    self.assertEqual(io_f.severity, "CRITICAL")
    self.assertIn("mysqld", io_f.description)

  def test_26_filesystem_ext4_readonly_remount(self):
    """Test 26: EXT4-fs error triggering kernel read-only remount."""
    payload = {
        "recent_kernel_errors": [
            (
                "kernel: [129.40] EXT4-fs error (device sda1): ext4_lookup:"
                " deleted inode referenced: 99120"
            ),
            (
                "kernel: [129.41] Aborting journal on device sda1."
                " Remounting filesystem read-only"
            ),
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(payload))
    findings, _ = rca.evaluate_rca(bundle, sanitize=False)
    fs_f = next((f for f in findings if f.category == "FILESYSTEM_ERROR"), None)
    self.assertIsNotNone(fs_f)
    self.assertEqual(fs_f.severity, "CRITICAL")
    self.assertIn("Read-Only Remount", fs_f.title)

  # -------------------------------------------------------------
  # Group 6: Compound Catastrophe Scenario (Test 27)
  # -------------------------------------------------------------

  def test_27_compound_catastrophe_6_failures(self):
    """Test 27: Simultaneous OOM + Inode 100% + Disk 99% + Failed Unit + I/O Wait + Read-Only."""
    compound = {
        "hostname": "prod-catastrophe.synthetic.local",
        "failed_services": ["etcd.service", "api.service"],
        "disk_usage": ["/dev/sda1 100G 99G 1G 99% /"],
        "inode_usage": ["/dev/sda2 1000000 1000000 0 100% /var"],
        "memory": {"oom_killer_events": 1},
        "io_metrics": {"util_pct": 99.5, "iowait_pct": 35.0},
        "recent_kernel_errors": [
            (
                "kernel: Out of memory: Kill process 1024 (api) score 950 or"
                " sacrifice child"
            ),
            (
                "kernel: EXT4-fs error: Remounting filesystem read-only on"
                " device sda1"
            ),
            (
                "systemd[1]: etcd.service: Main process exited, code=killed,"
                " status=9/KILL"
            ),
            "INFO: task api:1024 blocked for more than 120 seconds.",
        ],
    }
    bundle = rca.parse_telemetry(json.dumps(compound))
    findings, _ = rca.evaluate_rca(bundle, sanitize=True)
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


def main():
  print("======================================================================")
  print("Executing Comprehensive 30-Test Stress & Fuzzing Battery")
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
