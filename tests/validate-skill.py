#!/usr/bin/env python3
"""Automated Validation Harness for Linux Server RCA Skill (validate-skill.py)

Executes 7 deterministic validation suites to verify:
1. Kernel OOM killer event detection and victim process isolation.
2. Inode exhaustion disambiguation vs block storage capacity.
3. Systemd failure exit code interpretation (status=203/EXEC, status=1/FAILURE).
4. Storage I/O wait saturation and hung task / D-state process identification.
5. Client-side data sanitization (SHA-256 host hashing, RFC 5737 test IPs, secret scrubbing).
6. Non-destructive safety guardrails (zero rm -rf or forced reboot commands).
7. agentskills.io SKILL.md specification and zero-dependency compliance.

Returns exit code 0 on 100% test pass.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT_DIR / "scripts" / "parse-linux-rca.py"
FIXTURES_DIR = ROOT_DIR / "tests" / "fixtures"
SKILL_MD = ROOT_DIR / "SKILL.md"


class TestLinuxServerRCA(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    # Dynamically import parse-linux-rca.py as module
    spec = importlib.util.spec_from_file_location(
        "parse_linux", str(SCRIPT_PATH)
    )
    cls.rca = importlib.util.module_from_spec(spec)
    sys.modules["parse_linux"] = cls.rca
    spec.loader.exec_module(cls.rca)

  def test_01_oom_killer_rca(self):
    """Suite 1: Validate kernel OOM killer isolation and victim process detection."""
    fixture = FIXTURES_DIR / "fixture-oom-killer.json"
    content = fixture.read_text(encoding="utf-8")
    bundle = self.rca.parse_telemetry(content)
    findings, _ = self.rca.evaluate_rca(bundle, sanitize=False)

    categories = {f.category for f in findings}
    self.assertIn(
        "OOM_KILLER", categories, "Expected OOM_KILLER finding category"
    )

    oom_find = next(f for f in findings if f.category == "OOM_KILLER")
    self.assertEqual(oom_find.severity, "CRITICAL")
    self.assertIn("synthetic-java", oom_find.title)
    self.assertTrue(
        any("fallocate" in step for step in oom_find.remediation_steps),
        "Expected emergency swap allocation step",
    )
    self.assertTrue(
        any("MemoryMax" in h for h in oom_find.hardening_steps),
        "Expected systemd MemoryMax hardening",
    )

  def test_02_inode_exhaustion_disambiguation(self):
    """Suite 2: Validate 100% inode exhaustion detection despite free block disk space."""
    fixture = FIXTURES_DIR / "fixture-inode-exhaustion.json"
    content = fixture.read_text(encoding="utf-8")
    bundle = self.rca.parse_telemetry(content)
    findings, _ = self.rca.evaluate_rca(bundle, sanitize=False)

    categories = {f.category for f in findings}
    self.assertIn(
        "INODE_EXHAUSTION",
        categories,
        "Expected INODE_EXHAUSTION finding category",
    )

    inode_find = next(f for f in findings if f.category == "INODE_EXHAUSTION")
    self.assertEqual(inode_find.severity, "CRITICAL")
    self.assertIn("/var", inode_find.title)
    self.assertTrue(
        any("df -iP" in step for step in inode_find.remediation_steps),
        "Expected df -iP verification command",
    )

  def test_03_systemd_exit_codes(self):
    """Suite 3: Validate systemd unit failure mapping (status=203/EXEC)."""
    fixture = FIXTURES_DIR / "fixture-systemd-failed-exec.json"
    content = fixture.read_text(encoding="utf-8")
    bundle = self.rca.parse_telemetry(content)
    findings, _ = self.rca.evaluate_rca(bundle, sanitize=False)

    exec_find = next(f for f in findings if f.category == "SYSTEMD_FAILURE")
    self.assertEqual(exec_find.severity, "HIGH")
    self.assertIn("status=203/EXEC", exec_find.title)
    self.assertIn("synthetic-nginx.service", exec_find.title)
    self.assertTrue(
        any("which" in step for step in exec_find.remediation_steps),
        "Expected executable path verification in remediation",
    )

  def test_04_storage_iowait_bottleneck(self):
    """Suite 4: Validate storage I/O wait saturation and D-state hung tasks."""
    fixture = FIXTURES_DIR / "fixture-disk-io-bottleneck.json"
    content = fixture.read_text(encoding="utf-8")
    bundle = self.rca.parse_telemetry(content)
    findings, _ = self.rca.evaluate_rca(bundle, sanitize=False)

    io_find = next(f for f in findings if f.category == "IO_WAIT_BOTTLENECK")
    self.assertEqual(io_find.severity, "CRITICAL")
    self.assertIn("99.4%", io_find.title)
    self.assertTrue(
        any("iotop" in step for step in io_find.remediation_steps),
        "Expected iotop or pidstat in remediation",
    )

  def test_05_client_side_sanitization(self):
    """Suite 5: Validate SHA-256 host hashing, RFC 5737 IP mapping, and secret scrubbing."""
    sanitizer = self.rca.Sanitizer()

    # Hostname hashing
    raw_host = "prod-db01.internal.corp"
    masked_host = sanitizer.sanitize_hostname(raw_host)
    self.assertTrue(
        masked_host.startswith("mock-server-"),
        f"Expected mock-server- prefix, got {masked_host}",
    )
    self.assertIn(".synthetic-lab.local", masked_host)

    # IP address masking to RFC 5737
    raw_ip = "10.250.40.1"
    masked_ip = sanitizer.sanitize_ip(raw_ip)
    self.assertTrue(
        masked_ip.startswith("198.51.100.") or masked_ip.startswith("192.0.2."),
        f"Expected RFC 5737 address, got {masked_ip}",
    )

    # Secret scrubbing
    text_with_secret = (
        "service_token: ghp_9876543210abcdef\ndatabase_password: secret123"
    )
    scrubbed = sanitizer.scrub_text(text_with_secret)
    self.assertNotIn("ghp_9876543210abcdef", scrubbed)
    self.assertNotIn("secret123", scrubbed)
    self.assertIn("[REDACTED-SECRET]", scrubbed)

  def test_06_non_destructive_safety_guardrails(self):
    """Suite 6: Verify strict absence of destructive reset commands across all playbooks."""
    fixtures = [
        "fixture-oom-killer.json",
        "fixture-inode-exhaustion.json",
        "fixture-systemd-failed-exec.json",
        "fixture-disk-io-bottleneck.json",
    ]
    destructive_commands = ["rm -rf", "reboot -f", "init 6", "kill -9 -1"]

    for fix_name in fixtures:
      content = (FIXTURES_DIR / fix_name).read_text(encoding="utf-8")
      bundle = self.rca.parse_telemetry(content)
      findings, _ = self.rca.evaluate_rca(bundle, sanitize=False)
      for f in findings:
        for step in f.remediation_steps:
          for bad_cmd in destructive_commands:
            self.assertNotIn(
                bad_cmd,
                step,
                f"Destructive command '{bad_cmd}' found in {f.finding_id}",
            )

  def test_07_agentskills_specification_and_dependencies(self):
    """Suite 7: Verify SKILL.md metadata, agentskills.io conformity, and zero external packages."""
    self.assertTrue(SKILL_MD.exists(), "SKILL.md must exist in root directory")
    skill_text = SKILL_MD.read_text(encoding="utf-8")

    # Frontmatter check
    self.assertTrue(
        skill_text.startswith("---"), "SKILL.md must have YAML frontmatter"
    )
    self.assertIn("name: linux-server-rca", skill_text)
    self.assertIn("description:", skill_text)

    # Rule 3 check: Zero third-party packages in scripts
    with open(SCRIPT_PATH, "r", encoding="utf-8") as f:
      code = f.read()

    forbidden_packages = [
        "requests",
        "psutil",
        "paramiko",
        "fabric",
        "ansible",
        "pandas",
    ]
    for pkg in forbidden_packages:
      self.assertNotIn(
          f"import {pkg}", code, f"Forbidden external dependency: {pkg}"
      )
      self.assertNotIn(
          f"from {pkg}", code, f"Forbidden external dependency: {pkg}"
      )


def main():
  print("======================================================================")
  print("Running Automated Verification Suite for linux-server-rca")
  print("======================================================================")
  suite = unittest.TestLoader().loadTestsFromTestCase(TestLinuxServerRCA)
  runner = unittest.TextTestRunner(verbosity=2)
  result = runner.run(suite)
  if result.wasSuccessful():
    print("\nAll 7 verification suites passed successfully (Exit code: 0).")
    return 0
  else:
    print(
        f"\nVerification failed: {len(result.failures)} failures,"
        f" {len(result.errors)} errors."
    )
    return 1


if __name__ == "__main__":
  sys.exit(main())
