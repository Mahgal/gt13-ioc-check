#!/usr/bin/env python3
"""Unit tests for gt13_ioc_check.py. Run: python3 tests/run_tests.py"""
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "gt13_ioc_check.py")


def run_cli(args, input_text=None):
    return subprocess.run(
        [sys.executable, SCRIPT] + args,
        input=input_text, capture_output=True, text=True, timeout=30,
    )


def log_line(ip="203.0.113.7", ua="curl/8.5.0", extra=""):
    return ('%s - - [25/Nov/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 15 '
            '"-" "%s"%s' % (ip, ua, extra))


class TestIocMatching(unittest.TestCase):
    def test_domain_match(self):
        line = log_line(extra=' "https://newpayapp.com/x"')
        r = run_cli([], input_text=line + "\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[domain] newpayapp.com", r.stdout)

    def test_subdomain_match_reports_subdomain(self):
        line = log_line(extra=' "https://api-zt.newpayapp.com/"')
        r = run_cli([], input_text=line + "\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[domain] api-zt.newpayapp.com", r.stdout)

    def test_user_agent_match_long(self):
        line = log_line(ua="Mozilla/5.0 (X11; Linux x86_64) research")
        r = run_cli([], input_text=line + "\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[user-agent] Mozilla/5.0 (X11; Linux x86_64) research",
                      r.stdout)

    def test_user_agent_match_short(self):
        line = log_line(ua="Mozilla/5.0 research")
        r = run_cli([], input_text=line + "\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[user-agent] Mozilla/5.0 research", r.stdout)

    def test_ip_match(self):
        line = log_line(ip="45.130.83.49")
        r = run_cli([], input_text=line + "\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[ip] 45.130.83.49", r.stdout)

    def test_ip_prefix_no_false_positive(self):
        # 45.92.229.10 is listed; 45.92.229.100 is NOT -- must not match.
        line = log_line(ip="45.92.229.100")
        r = run_cli([], input_text=line + "\n")
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("[ip]", r.stdout)

    def test_hassh_match(self):
        line = log_line(extra=' hassh=eeca2460550b9ded084ecf2f70a75356')
        r = run_cli([], input_text=line + "\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[hassh] eeca2460550b9ded084ecf2f70a75356", r.stdout)

    def test_artifact_match(self):
        line = log_line(extra=' preload error /usr/lib/.libproc.so')
        r = run_cli([], input_text=line + "\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[artifact] /usr/lib/.libproc.so", r.stdout)

    def test_defanged_domain_handling(self):
        # Analysts paste defanged indicators; the scanner must still flag them.
        line = log_line(extra=' "https://data-zt.newpayapp[.]com/zult"')
        r = run_cli([], input_text=line + "\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[domain] data-zt.newpayapp.com", r.stdout)


class TestExitCodesAndFixtures(unittest.TestCase):
    def test_clean_log_exit_0(self):
        r = run_cli([os.path.join(ROOT, "fixtures", "clean.log")])
        self.assertEqual(r.returncode, 0)
        self.assertIn("0 hits", r.stdout)
        self.assertIn("RESULT: clean", r.stdout)

    def test_sample_log_exit_1_three_hits(self):
        r = run_cli([os.path.join(ROOT, "fixtures", "sample.log")])
        self.assertEqual(r.returncode, 1)
        self.assertIn("3 hits: domain=1 user-agent=1 ip=1 hassh=0 artifact=0",
                      r.stdout)
        self.assertIn("line 2 [ip] 45.92.229.10", r.stdout)
        self.assertIn("line 4 [domain] data-zt.newpayapp.com", r.stdout)
        self.assertIn("line 5 [user-agent]", r.stdout)

    def test_malformed_lines_skipped(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log",
                                         delete=False) as fh:
            fh.write("garbage\n")
            fh.write("!!!\n")
            fh.write("\n")
            fh.write(log_line() + "\n")
            path = fh.name
        try:
            r = run_cli([path])
        finally:
            os.unlink(path)
        self.assertEqual(r.returncode, 0)
        self.assertIn("scanned 1 lines (3 skipped), 0 hits", r.stdout)

    def test_usage_error_unknown_flag(self):
        r = run_cli(["--bogus"])
        self.assertEqual(r.returncode, 2)

    def test_usage_error_missing_file(self):
        r = run_cli(["/nonexistent/nope.log"])
        self.assertEqual(r.returncode, 2)

    def test_stdin_scan(self):
        r = run_cli([], input_text=log_line(ip="45.92.229.10") + "\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("[ip] 45.92.229.10", r.stdout)


class TestDemo(unittest.TestCase):
    def test_demo_exit_0(self):
        r = run_cli(["--demo"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("BEFORE", r.stdout)
        self.assertIn("AFTER", r.stdout)
        self.assertIn("3 hits", r.stdout)

    def test_demo_deterministic(self):
        first = run_cli(["--demo"])
        second = run_cli(["--demo"])
        self.assertEqual(first.stdout, second.stdout)
        self.assertEqual(first.returncode, second.returncode)

    def test_demo_matches_fixture(self):
        """The demo replays fixtures/sample.log: same 3 hit lines."""
        demo = run_cli(["--demo"]).stdout
        scan = run_cli([os.path.join(ROOT, "fixtures", "sample.log")]).stdout
        demo_hits = [l for l in demo.splitlines() if l.startswith("line ")]
        scan_hits = [l for l in scan.splitlines() if l.startswith("line ")]
        self.assertEqual(demo_hits, scan_hits)

    def test_ioc_counts(self):
        """Sanity: the embedded IoC set matches the published report."""
        sys.path.insert(0, ROOT)
        import gt13_ioc_check as mod
        self.assertEqual(len(mod.IPS), 69)
        self.assertEqual(len(mod.DOMAINS), 4)
        self.assertEqual(len(mod.USER_AGENTS), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
