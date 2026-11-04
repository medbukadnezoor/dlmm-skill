"""HS-ASSESS-T1: SolScanner as its own first-wave collector (solscanner_scan.py command line). Offline: the bounded read
is replaced by the real parser over saved streams (fake transport) or by a refusing stub; no network, no key.
DS-SCANNER-API-T1: the command line now tries the Scanner API first when a key is set; these tests run it with the key
loader stubbed to "no key" (the legacy keyless path), so they never read a real .env (test_scanner_api.py covers the API)."""

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


NO_KEY = "Scanner API not read: no_key"
LEGACY = f"legacy keyless SolScanner endpoint, {NO_KEY}"


def cli(argv, collect):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(ss, "load_key", return_value=(None, "no_key", None)), mock.patch.object(ss, "env_key_set", return_value=False), \
         mock.patch.object(ss, "collect_solscanner", side_effect=collect) as call, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = ss.main(argv)
    return code, out.getvalue(), err.getvalue(), call


class SolScannerCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_one_bounded_read_saved_as_the_file_assess_accepts(self):
        for name, mint, now, expect in (("cape", CAPE, NOW_CAPE, f"ok (1 bundle group; fresh scan; {LEGACY}; corroboration only)"),
                                        ("space-inu", SPACE, NOW_SPACE, f"ok (8 bundle groups; provider_stale; {LEGACY}; corroboration only)"),
                                        ("altai-the-tiger", ALTAI, NOW_ALTAI, f"ok (5 bundle groups; expired_scan; {LEGACY}; corroboration only)")):
            with self.subTest(name):
                result = parsed(name, mint, now)
                path = self.tmp / name / "solscanner.json"
                code, out, err, call = cli([mint, "--out", str(path)], lambda m, r=result: copy.deepcopy(r))
                self.assertEqual(code, 0, err)
                call.assert_called_once_with(mint)  # one read, no retry, no second request
                self.assertEqual(out.strip(), expect)
                saved = json.loads(path.read_text())
                self.assertEqual({k: saved[k] for k in result}, result)  # the result exactly as the parser returned it
                self.assertEqual((saved["source"], saved["api_status"], saved["api_reason"], saved["legacy_status"], saved["scans_spent"]),
                                 ("legacy_keyless", "not_sent", "no_key", "answered", None))  # plus which endpoint answered
                hf.validate_solscanner_result(saved)  # the same strict revalidation report and assess apply
                args = types.SimpleNamespace(solscanner_json=str(path))
                self.assertEqual(hf.load_solscanner(args, mint), saved)

    def test_a_failed_read_is_saved_as_unavailable_and_never_crashes(self):
        def boom(_mint):
            raise RuntimeError("https://api.solscanner.app/contracts/x?token=SECRETVALUE")

        path = self.tmp / "solscanner.json"
        code, out, err, _ = cli([CAPE, "--out", str(path)], boom)
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), f"unavailable (network_error; {NO_KEY}; the result file records it)")
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
                self.assertEqual(out.strip(), f"unavailable ({reason}; {NO_KEY}; the result file records it)")
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

    def test_runnable_from_the_command_line_and_reads_only_its_key_names(self):
        """DS-SCANNER-API-T1 (was: reads no environment): the only environment variables read are the two spellings of the
        Scanner key and the HOLDER_FORENSICS_ENV setting that points at the repository .env."""
        proc = subprocess.run([sys.executable, "-I", str(SCRIPTS / "solscanner_scan.py"), "--help"], capture_output=True, text=True, timeout=60, env={"PATH": os.environ.get("PATH", "")})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--out PATH", proc.stdout)
        self.assertIn("--env-file PATH", proc.stdout)
        self.assertIn("x-api-key", proc.stdout)
        self.assertIn("no key, no", proc.stdout)  # the legacy fallback: no key, no credits
        text = (SCRIPTS / "solscanner_scan.py").read_text()
        reads = set(re.findall(r"os\.environ\.get\(([^,)]+)", text)) | set(re.findall(r"os\.environ\[([^\]]+)\]", text))
        self.assertEqual(reads, {"name", '"HOLDER_FORENSICS_ENV"'})  # `name` loops over API_KEY_NAMES only
        self.assertEqual(ss.API_KEY_NAMES, ("SCANNER_NET_API_KEY", "scanner_net_api_key"))
        self.assertEqual(len(re.findall(r"for name in API_KEY_NAMES", text)), 3)
        self.assertIsNone(re.search(r"\bgetenv\(|os\.environ\.items|os\.environ\.copy|dict\(os\.environ", text))

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
            self.assertEqual(out.strip(), f"unavailable (network_error; {NO_KEY}; the result file records it)")
            a, b = ta._files(tmp / "a"), ta._files(tmp / "b")
            self.assertEqual(a["assessment.json"], b["assessment.json"])
            self.assertEqual(ta.undocumented(ta.report_differences(a["report.md"], b["report.md"])), [])
            self.assertIn("SolScanner public scan: unavailable", b["report.md"])
            # DS-SCANNER-API-T1: both name the source the same way (the engine's own --solscanner read is keyless too)
            line = "source: none answered (Scanner API not read: no_key; legacy keyless SolScanner endpoint not read: network_error)"
            self.assertIn(line, a["report.md"])
            self.assertIn(line, b["report.md"])


if __name__ == "__main__":
    unittest.main()
