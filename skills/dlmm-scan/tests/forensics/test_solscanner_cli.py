"""HS-ASSESS-T1: SolScanner as its own first-wave collector (solscanner_scan.py command line). Offline: the bounded read
is replaced by the real parser over saved streams (fake transport) or by a refusing stub; no network, no key.
DS-SCANNER-FREE-T1: the command line reads only the free keyless endpoint (no key, no paid API) and classifies the answer
(source legacy_keyless, or a reason with needs_browser); test_scanner_keyless.py covers the classification and
test_scanner_browser.py the follow-up lane that reads a token the keyless endpoint cannot."""

from __future__ import annotations

import contextlib
import copy
import datetime as dt
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
import solscanner_scan as ss  # noqa: E402
from test_solscanner_scan import ALTAI, CAPE, NOW_ALTAI, NOW_CAPE, NOW_SPACE, SPACE, Opener, Response, stream  # noqa: E402

UTC = dt.timezone.utc


def parsed(name, mint, now):
    """The real bounded parser over a saved SolScanner stream, as the live read would return it."""
    return ss.collect_solscanner(mint, opener=Opener(Response(stream(name))), now=lambda: now)


KEYLESS = "free keyless endpoint, cached by Scanner"
BROWSER = "needs_browser: the scanner_browser follow-up lane reads it"


def cli(argv, collect):
    """The command line with collect_solscanner (the one bounded read) replaced; collect_keyless calls it with only the mint
    and its `http` hook (DS-SCANNER-FREE-T1), which a replaced read leaves empty."""
    def read(m, **_kw):
        if isinstance(collect, BaseException):
            raise collect
        return collect(m)

    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(ss, "collect_solscanner", side_effect=read) as call, contextlib.redirect_stdout(out), \
         contextlib.redirect_stderr(err):
        code = ss.main(argv)
    return code, out.getvalue(), err.getvalue(), call


class SolScannerCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_one_bounded_read_saved_as_the_file_assess_accepts(self):
        for name, mint, now, expect in (("cape", CAPE, NOW_CAPE, f"ok (1 bundle group; fresh scan; {KEYLESS}; corroboration only)"),
                                        ("space-inu", SPACE, NOW_SPACE, f"ok (8 bundle groups; provider_stale; {KEYLESS}; corroboration only)"),
                                        ("altai-the-tiger", ALTAI, NOW_ALTAI, f"ok (5 bundle groups; expired_scan; {KEYLESS}; corroboration only)")):
            with self.subTest(name):
                result = parsed(name, mint, now)
                path = self.tmp / name / "solscanner.json"
                code, out, err, call = cli([mint, "--out", str(path)], lambda m, r=result: copy.deepcopy(r))
                self.assertEqual(code, 0, err)
                call.assert_called_once()  # one read, no retry, no second request
                self.assertEqual(call.call_args.args, (mint,))
                self.assertEqual(out.strip(), expect)
                saved = json.loads(path.read_text())
                self.assertEqual({k: saved[k] for k in result}, result)  # the result exactly as the parser returned it
                self.assertEqual((saved["source"], saved["keyless_status"], saved["keyless_reason"], saved["needs_browser"], saved["scans_spent"]),
                                 ("legacy_keyless", "answered", None, False, 0))  # plus where it was read
                hf.validate_solscanner_result(saved)  # the same strict revalidation report and assess apply
                args = types.SimpleNamespace(solscanner_json=str(path))
                self.assertEqual(hf.load_solscanner(args, mint), saved)

    def test_a_failed_read_is_saved_as_unavailable_and_never_crashes(self):
        def boom(_mint):
            raise RuntimeError("https://api.solscanner.app/contracts/x?token=SECRETVALUE")

        path = self.tmp / "solscanner.json"
        code, out, err, _ = cli([CAPE, "--out", str(path)], boom)
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), f"unavailable (network_error; {BROWSER}; the result file records it)")
        self.assertNotIn("SECRETVALUE", out + err + path.read_text())
        self.assertNotIn("Traceback", out + err)
        saved = json.loads(path.read_text())
        self.assertEqual((saved["reason"], saved["groups"], saved["mint"]), ("network_error", [], CAPE))
        hf.validate_solscanner_result(saved)
        self.assertEqual(hf.solscanner_finding_for(saved)["status"], "unavailable")

    def test_reasons_from_the_parser_are_passed_through(self):
        for reason in ("timeout", "http_error", "malformed_sse", "identity_mismatch"):
            with self.subTest(reason):
                result = ss._empty(CAPE, "2026-10-14T10:05:00Z", reason)
                path = self.tmp / f"{reason}.json"
                code, out, _, _ = cli([CAPE, "--out", str(path)], lambda m, r=result: copy.deepcopy(r))
                self.assertEqual(code, 0)
                self.assertEqual(out.strip(), f"unavailable ({reason}; {BROWSER}; the result file records it)")
                hf.validate_solscanner_result(json.loads(path.read_text()))

    def test_bad_mint_exits_2_before_any_read(self):
        code, out, err, call = cli(["not-a-mint!", "--out", str(self.tmp / "x.json")], AssertionError)
        self.assertEqual(code, 2)
        self.assertIn("mint is not a valid base58 Solana address", err)
        call.assert_not_called()
        self.assertFalse((self.tmp / "x.json").exists())

    def test_unwritable_out_exits_2(self):
        result = parsed("cape", CAPE, NOW_CAPE)
        code, _, err, _ = cli([CAPE, "--out", str(self.tmp)], lambda m: copy.deepcopy(result))  # a folder, not a file
        self.assertEqual(code, 2)
        self.assertIn("--out is not a writable file path", err)

    def test_out_is_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            ss.main([CAPE])
        self.assertEqual(ctx.exception.code, 2)

    def test_runnable_from_the_command_line_and_reads_no_environment(self):
        """DS-SCANNER-FREE-T1 restores HS-ASSESS-T1's check: no key, no environment variable, no .env (the paid API path of
        DS-SCANNER-API-T1 is gone)."""
        proc = subprocess.run([sys.executable, "-I", str(SCRIPTS / "solscanner_scan.py"), "--help"], capture_output=True, text=True, timeout=60, env={"PATH": os.environ.get("PATH", "")})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--out PATH", proc.stdout)
        self.assertIn("no key, no credits", proc.stdout)
        self.assertNotIn("--env-file", proc.stdout)
        text = (SCRIPTS / "solscanner_scan.py").read_text()
        self.assertIsNone(re.search(r"(?m)^\s*(import os|from os\b)|\bos\.(environ|getenv)|\bgetenv\(|\benviron\[", text), "solscanner_scan.py must read no environment variable (no key)")
        self.assertIsNone(re.search(r"(?i)scanner_net_api_key|x-api-key|authorization|\.env\b|api\.scanner\.net", text), "no key, no credential header, no paid API host")

    def test_cli_plus_assess_matches_report_with_live_solscanner_when_the_read_fails(self):
        """The unreachable case: `report --solscanner` (whose fetch raises) and solscanner CLI + funders + assess give the
        same assessment.json and the same report apart from the documented lines."""
        import test_assess as ta

        case = ta.case_stopped_failures()
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            boom = RuntimeError("down")
            with mock.patch.object(ss, "collect_solscanner", side_effect=boom):
                code_a, _, _ = ta._run(["report", case.mint, "--top", "40", "--workers", "1", "--out", str(tmp / "a"), "--solscanner"], fake=case.fake())
            code_b, _, _ = ta._run(["funders", case.mint, "--top", "40", "--workers", "1", "--out", str(tmp / "b")], fake=case.fake())
            code_c, out, _, _ = cli([case.mint, "--out", str(tmp / "b" / "solscanner.json")], boom)
            code_s, _, err = ta.run_assess(case.mint, tmp / "b", ["--solscanner-json", str(tmp / "b" / "solscanner.json")])
            self.assertEqual((code_a, code_b, code_c, code_s), (0, 0, 0, 0), err)
            self.assertEqual(out.strip(), f"unavailable (network_error; {BROWSER}; the result file records it)")
            a, b = ta._files(tmp / "a"), ta._files(tmp / "b")
            self.assertEqual(a["assessment.json"], b["assessment.json"])
            self.assertEqual(ta.undocumented(ta.report_differences(a["report.md"], b["report.md"])), [])
            self.assertIn("SolScanner public scan: unavailable", b["report.md"])
            # DS-SCANNER-FREE-T1: both name the source the same way (the engine's own --solscanner read is the same keyless read)
            line = "source: free endpoint not read: network_error; the scanner_browser follow-up lane reads it from the logged-in scanner.net page"
            self.assertIn(line, a["report.md"])
            self.assertIn(line, b["report.md"])


if __name__ == "__main__":
    unittest.main()
