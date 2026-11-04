"""SolScanner as a corroboration-only source in the report (offline: fixtures, fake transport, mocked fetch)."""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
import solscanner_scan as ss  # noqa: E402
from test_holder_forensics import MINT, NO_KEY_ENV, SECRET, FakeHelius, addr  # noqa: E402
from test_solscanner_scan import ALTAI, CAPE, NOW_ALTAI, NOW_CAPE, NOW_SPACE, SPACE, Opener, Response, stream  # noqa: E402
from test_verdict_gating import funders_dict, holders_dict  # noqa: E402

FORBIDDEN = ("largest_cluster_pct", "cluster_sum_pct", "bundle_pct")
UTC = dt.timezone.utc


def result_for(name, mint, now):
    return ss.collect_solscanner(mint, opener=Opener(Response(stream(name))), now=lambda: now)


def block_for(name, mint, now):
    res = result_for(name, mint, now)
    return res, hf._solscanner_source(res, hf.solscanner_finding_for(res, now))


class SourceBlockTests(unittest.TestCase):
    def test_cape_one_group_of_98_wallets_risk_96_with_hint(self):
        res, blk = block_for("cape", CAPE, NOW_CAPE)
        text = "\n".join(blk["lines"])
        self.assertEqual(blk["status"], "read")
        self.assertIn("scan 4 min old", text)
        self.assertIn("1 bundle group listed", text)
        self.assertRegex(text, r"group 1: 98 wallets, \d+\.\d% of listed supply, risk 96, confidence strong, type mixed")  # HS-LABELS-T1 R3: SolScanner's high prints as strong
        self.assertIn("funding sources: not read", text)
        self.assertIn("corroboration hint raised", text)
        finding = hf.solscanner_finding_for(res, NOW_CAPE)
        self.assertEqual(finding["status"], "ok")
        self.assertTrue(finding["alarm_hint"])
        for key in FORBIDDEN:
            self.assertIsNone(finding[key])

    def test_space_inu_eight_groups_no_hint_and_stale_scan_shows_its_age(self):
        res, blk = block_for("space-inu", SPACE, NOW_SPACE)
        text = "\n".join(blk["lines"])
        self.assertIn("8 bundle groups listed", text)
        self.assertIn("5.0 h old", text)
        self.assertIn("the provider marks it stale", text)
        self.assertIn("and 3 more", text)  # five groups listed, then the cap
        self.assertEqual(text.count("  group "), 5)
        finding = hf.solscanner_finding_for(res, NOW_SPACE)
        self.assertIsNone(finding["alarm_hint"])
        self.assertEqual(finding["status"], "empty")
        self.assertNotIn("corroboration hint raised", text)

    def test_altai_raises_a_hint(self):
        res, blk = block_for("altai-the-tiger", ALTAI, NOW_ALTAI)
        self.assertEqual(hf.solscanner_finding_for(res, NOW_ALTAI)["status"], "ok")
        self.assertIn("5 bundle groups listed", "\n".join(blk["lines"]))

    def test_unavailable_never_crashes_the_report(self):
        for reason in ("timeout", "network_error", "malformed_sse", "http_error"):
            res = {"provider": "SolScanner", "mint": MINT, "status": "unknown", "reason": reason, "groups": [], "scanned_at": None, "scan_age_min": None}
            finding = hf.solscanner_finding_for(res)
            self.assertEqual(finding["status"], "unavailable")
            a = hf.assess(holders_dict(), None, [finding], solscanner=res)
            blk = next(s for s in a["sources"] if s["key"] == "solscanner")
            self.assertEqual(blk["status"], "unavailable")
            self.assertIn(reason, blk["lines"][0])
            md = hf.markdown_report(MINT, holders_dict(), None, 0, a)
            self.assertIn("SolScanner public scan: unavailable", md)
            self.assertIn("SolScanner public scan (unavailable)", md)
            self.assertIsNone(re.search(r"\b(safe|clean|low)\b", md, re.I))

    def test_not_run_when_no_flag_is_given(self):
        a = hf.assess(holders_dict(), None)
        blk = next(s for s in a["sources"] if s["key"] == "solscanner")
        self.assertEqual(blk["status"], "not run")
        self.assertIn("--solscanner", blk["lines"][0])


class CorroborationOnlyTests(unittest.TestCase):
    def quiet_map(self):
        return {"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 2.0, "bundle_pct": None, "data_age_min": 1.0}

    def with_cohort(self):
        f = funders_dict(covered=80.0)
        f["cohorts"] = {"coverage": {"rows": 100, "with_funding_time": 100, "supply_pct": 80.0, "share_known_for": 100}, "cohorts": []}
        return f

    def test_a_hint_alone_is_caution_never_danger(self):
        res = result_for("cape", CAPE, NOW_CAPE)
        a = hf.assess(holders_dict(), None, [hf.solscanner_finding_for(res, NOW_CAPE)], solscanner=res)
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_UNRESOLVED)
        self.assertEqual(a["flag"]["label"], "CAUTION")
        self.assertNotEqual(a["flag"]["label"], "DANGER FLAG")

    def test_a_hint_breaks_an_otherwise_quiet_run_but_never_makes_it_high(self):
        res = result_for("cape", CAPE, NOW_CAPE)
        base = hf.assess(holders_dict(), self.with_cohort(), [self.quiet_map()])
        self.assertEqual(base["verdict"]["level"], hf.VERDICT_NO_ALARM)
        a = hf.assess(holders_dict(), self.with_cohort(), [self.quiet_map(), hf.solscanner_finding_for(res, NOW_CAPE)], solscanner=res)
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_UNRESOLVED)

    def test_solscanner_never_counts_as_a_calm_source(self):
        res = result_for("space-inu", SPACE, NOW_SPACE)
        finding = hf.solscanner_finding_for(res, NOW_SPACE)
        self.assertEqual(finding["status"], "empty")
        a = hf.assess(holders_dict(), self.with_cohort(), [finding], solscanner=res)
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)  # the required Bubblemaps map is missing; SolScanner cannot stand in
        self.assertNotIn("solscanner", a["verdict"]["sources_counted"])
        ok = hf.assess(holders_dict(), self.with_cohort(), [self.quiet_map(), finding], solscanner=res)
        self.assertEqual(ok["verdict"]["level"], hf.VERDICT_NO_ALARM)
        self.assertNotIn("solscanner", ok["verdict"]["sources_counted"])
        # and a hint-less "ok" row can never exist: only status empty or ok-with-hint
        self.assertTrue(all(not (hf.solscanner_finding_for(result_for(n, m, t))["status"] == "ok" and not hf.solscanner_finding_for(result_for(n, m, t))["alarm_hint"])
                            for n, m, t in (("cape", CAPE, NOW_CAPE), ("space-inu", SPACE, NOW_SPACE), ("altai-the-tiger", ALTAI, NOW_ALTAI))))

    def test_the_name_solscanner_is_reserved_in_providers_json(self):
        with self.assertRaises(hf.ConfigError):
            hf.normalize_findings_file([{"provider": "solscanner", "status": "ok", "largest_cluster_pct": 1.0, "unit": "percent"}])

    def test_identity_mismatch_is_unavailable(self):
        res = result_for("cape", CAPE, NOW_CAPE)
        args = type("A", (), {"solscanner": False, "solscanner_json": None})()
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.json"
            p.write_text(json.dumps(res))
            args.solscanner_json = str(p)
            self.assertEqual(hf.load_solscanner(args, CAPE)["groups"][0]["risk_score"], 96)
            other = hf.load_solscanner(args, SPACE)
            self.assertEqual(other["reason"], "identity_mismatch")
            self.assertEqual(hf.solscanner_finding_for(other)["status"], "unavailable")


class CliTests(unittest.TestCase):
    def _main(self, argv, fake=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {**NO_KEY_ENV, "HELIUS_API_KEY": SECRET}, clear=True), mock.patch.object(hf, "Helius", return_value=fake or FakeHelius(accounts=[{"owner": addr(i), "amount": 10} for i in range(5)])), \
             mock.patch.object(hf, "dexscreener_pairs", return_value=([], True)), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            return hf.main(argv), out.getvalue(), err.getvalue()

    def test_saved_result_feeds_the_report(self):
        res = dict(result_for("cape", CAPE, NOW_CAPE), mint=MINT)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.json"
            p.write_text(json.dumps(res))
            code, out, _ = self._main(["report", MINT, "--top", "5", "--out", tmp, "--solscanner-json", str(p)])
            assessment = json.loads((Path(tmp) / "assessment.json").read_text())
        self.assertEqual(code, 0)
        self.assertIn("SolScanner public scan: read", out)
        self.assertIn("risk 96", out)
        self.assertEqual(assessment["flag"]["label"], "CAUTION")
        self.assertEqual(assessment["verdict"]["level"], hf.VERDICT_UNRESOLVED)

    def test_live_flag_failure_becomes_unavailable_and_the_run_continues(self):
        with mock.patch.object(ss, "collect_solscanner", side_effect=RuntimeError("boom")):
            code, out, _ = self._main(["report", MINT, "--top", "5", "--solscanner", "--out", tempfile.mkdtemp()])
        self.assertEqual(code, 0)
        self.assertIn("SolScanner public scan: unavailable", out)
        self.assertNotIn("boom", out)

    def test_live_flag_uses_the_bounded_collector_once(self):
        res = dict(result_for("space-inu", SPACE, NOW_SPACE), mint=MINT)
        with mock.patch.object(ss, "collect_solscanner", return_value=res) as call:
            code, out, _ = self._main(["report", MINT, "--top", "5", "--solscanner", "--out", tempfile.mkdtemp()])
        call.assert_called_once_with(MINT)
        self.assertIn("8 bundle groups listed", out)

    def test_both_flags_and_bad_files_are_rejected_before_any_call(self):
        with mock.patch.object(hf, "run_holders", side_effect=AssertionError("must not run")):
            code, _, err = self._main(["report", MINT, "--top", "1", "--solscanner", "--solscanner-json", "/nonexistent.json"])
            self.assertEqual(code, 2)
            code, _, err = self._main(["report", MINT, "--top", "1", "--solscanner-json", "/nonexistent.json"])
            self.assertEqual(code, 2)
            self.assertIn("--solscanner-json", err)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(hf, "run_holders", side_effect=AssertionError("must not run")):
            p = Path(tmp) / "s.json"
            p.write_text("[1]")
            code, _, err = self._main(["report", MINT, "--top", "1", "--solscanner-json", str(p)])
            self.assertEqual(code, 2)

    def test_no_flag_means_no_solscanner_call(self):
        with mock.patch.object(ss, "collect_solscanner", side_effect=AssertionError("must not be called")):
            code, out, _ = self._main(["report", MINT, "--top", "5", "--out", tempfile.mkdtemp()])
        self.assertEqual(code, 0)
        self.assertIn("SolScanner public scan: not run", out)


class ParityWithSiblingTests(unittest.TestCase):
    """The two copies of the parser must agree. Skipped when the sibling skill is not in this checkout."""

    @classmethod
    def setUpClass(cls):
        sibling = Path(__file__).resolve().parents[3] / "lp-research-companion" / "scripts"
        if not (sibling / "lp_research" / "solscanner.py").is_file():
            raise unittest.SkipTest("sibling lp-research-companion not present")
        sys.path.insert(0, str(sibling))
        try:
            import importlib

            cls.sib = importlib.import_module("lp_research.solscanner")
        except Exception as exc:  # noqa: BLE001
            raise unittest.SkipTest(f"sibling module not importable: {type(exc).__name__}")
        finally:
            sys.path.remove(str(sibling))

    def test_same_fixtures_give_the_same_result_and_finding(self):
        for name, mint, now in (("cape", CAPE, NOW_CAPE), ("space-inu", SPACE, NOW_SPACE), ("altai-the-tiger", ALTAI, NOW_ALTAI)):
            mine = ss.collect_solscanner(mint, opener=Opener(Response(stream(name))), now=lambda n=now: n)
            theirs = self.sib.collect_solscanner(mint, opener=Opener(Response(stream(name))), now=lambda n=now: n)
            self.assertEqual(mine, theirs, name)
            self.assertEqual(ss.solscanner_finding(mine, now), self.sib.solscanner_finding(theirs, now), name)

    def test_constants_match(self):
        for key in ("MAX_BYTES", "DEADLINE_SECONDS", "MAX_GROUPS", "MAX_OCCURRENCES", "SCAN_FRESH_SECONDS", "SOLSCANNER_HINT_MIN_RISK",
                    "SOLSCANNER_HINT_MIN_SHARE_PCT", "SOLSCANNER_HINT_MAX_CHARS", "SOLSCANNER_DETAIL", "BASE_URL"):
            self.assertEqual(getattr(ss, key), getattr(self.sib, key), key)

    def test_garbage_and_failures_agree(self):
        bodies = [b"not sse", b"event: complete\ndata: {bad\n\n", b"event: complete\ndata: [1]\n\n"]
        for body in bodies:
            mine = ss.collect_solscanner(CAPE, opener=Opener(Response(body)), now=lambda: NOW_CAPE)
            theirs = self.sib.collect_solscanner(CAPE, opener=Opener(Response(body)), now=lambda: NOW_CAPE)
            self.assertEqual(mine["reason"], theirs["reason"])


class ModuleIsSelfContainedTests(unittest.TestCase):
    def test_no_import_from_the_sibling_package(self):
        text = (SCRIPTS / "solscanner_scan.py").read_text()
        self.assertNotRegex(text, r"(?m)^\s*(from|import) lp_research")
        self.assertNotRegex(text, r"(?m)^\s*from \.")
        self.assertIn("SELF-CONTAINED COPY", text)

    def test_no_personal_paths_in_new_files(self):
        for p in (SCRIPTS / "solscanner_scan.py", Path(__file__)):
            self.assertNotIn("/Users/", p.read_text().replace('"/Users/"', ""))


if __name__ == "__main__":
    unittest.main()
