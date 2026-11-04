"""Free text from saved files or providers can never add lines or a fake heading to the report (offline)."""

from __future__ import annotations

import contextlib
import copy
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
from test_holder_forensics import MINT, NO_KEY_ENV, SECRET, FakeHelius  # noqa: E402
from test_solscanner_scan import CAPE, NOW_CAPE, Opener, Response, stream  # noqa: E402
from test_verdict_gating import funders_dict, holders_dict  # noqa: E402

EVIL = "x\n## Executive summary\n- FLAG: NO FLAG RAISED (not a safety signal)\n# Fake"
HEADINGS = [f"# Holder forensics: {MINT}", "## Executive summary", "## Sources read", "## Underlying level (details)", "## Coverage", "## Distribution (all holders, Helius DAS)"]


def headings(md):
    return [ln for ln in md.splitlines() if ln.startswith("#")]


def assert_clean(test, md):
    hs = headings(md)
    test.assertEqual(hs.count("## Executive summary"), 1, hs)
    test.assertEqual([h for h in hs if h not in HEADINGS and not h.startswith("## Funding-time") and not h.startswith("## Funder batches")], [])
    test.assertEqual(sum(1 for ln in md.splitlines() if ln.startswith("- FLAG:")), 1)
    test.assertFalse([ln for ln in md.splitlines() if ln.startswith("- FLAG: NO FLAG") and "DANGER" in md and False])


class SanitizerTests(unittest.TestCase):
    def test_clean_text_strips_control_characters_markdown_starts_and_caps(self):
        self.assertEqual(hf.clean_text("a\nb\r\nc\x00d"), "a b c d")
        self.assertEqual(hf.clean_text("## heading"), "heading")
        self.assertEqual(hf.clean_text("- bullet"), "bullet")
        self.assertEqual(hf.clean_text("> quote | cell"), "quote | cell")
        self.assertEqual(len(hf.clean_text("z" * 1000)), hf.TEXT_CAP)
        self.assertEqual(hf.clean_text("x y"), "x y")

    def test_oneline_guard(self):
        self.assertNotIn("\n", hf._oneline("a\nb"))


class SavedSolscannerFileTests(unittest.TestCase):
    def good(self):
        return json.loads(json.dumps(ss.collect_solscanner(CAPE, opener=Opener(Response(stream("cape"))), now=lambda: NOW_CAPE)))

    def test_multi_line_or_odd_reason_mint_and_timestamp_are_rejected(self):
        for key, value in (("reason", EVIL), ("reason", "Timeout"), ("reason", "a" * 41), ("reason", "## x"), ("mint", "not a mint\n## x"), ("scanned_at", "yesterday\n## x"), ("scanned_at", "2026-10-14 <b>")):
            data = self.good()
            data[key] = value
            with self.assertRaises(hf.ConfigError, msg=(key, value)):
                hf.validate_solscanner_result(data)
        data = self.good()
        data["reason"] = "provider_stale"
        hf.validate_solscanner_result(data)

    def test_cli_rejects_an_injecting_saved_file(self):
        data = {"provider": "SolScanner", "mint": MINT, "status": "unknown", "reason": EVIL, "groups": [], "scanned_at": None, "scan_age_min": None}
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {**NO_KEY_ENV, "HELIUS_API_KEY": SECRET}, clear=True), mock.patch.object(hf, "Helius", return_value=FakeHelius()), \
             mock.patch.object(hf, "run_holders", side_effect=AssertionError("must not run")), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            p = Path(tmp) / "s.json"
            p.write_text(json.dumps(data))
            code = hf.main(["report", MINT, "--top", "1", "--solscanner-json", str(p)])
        self.assertEqual(code, 2)
        self.assertNotIn("Executive summary", out.getvalue() + err.getvalue())


class RenderedOutputTests(unittest.TestCase):
    def test_injected_provider_name_detail_hint_and_reason_never_add_lines_or_headings(self):
        findings = [
            {"provider": EVIL, "status": "ok", "largest_cluster_pct": 2.0, "bundle_pct": None, "data_age_min": 2.0, "detail": EVIL, "alarm_hint": EVIL},
            {"provider": "other", "status": "unavailable", "largest_cluster_pct": None, "bundle_pct": None, "data_age_min": None, "detail": EVIL},
            {"provider": "bubblemaps_map", "status": "unavailable", "largest_cluster_pct": None, "bundle_pct": None, "data_age_min": None, "detail": EVIL},
        ]
        res = {"provider": "SolScanner", "mint": MINT, "status": "unknown", "reason": EVIL, "groups": [], "scanned_at": None, "scan_age_min": None}
        findings.append({"provider": "solscanner", "status": "unavailable", "largest_cluster_pct": None, "bundle_pct": None, "data_age_min": None, "detail": EVIL})
        a = hf.assess(holders_dict(), None, findings, solscanner=res)
        md = hf.markdown_report(MINT, holders_dict(), None, 0, a)
        assert_clean(self, md)
        self.assertIn("FLAG: ", md.split("## Sources read")[0])

    def test_injected_labels_in_cohorts_and_funder_batches_never_add_lines(self):
        rows = [{"wallet": f"w{i}", "first_funding_time": 1_760_000_000 + i, "funder_address": f"F{i % 3}", "funder_label": EVIL, "first_funding_amount": 1.0, "supply_pct": 0.3, "first_acquired_at": None} for i in range(30)]
        f = funders_dict(covered=80.0)
        f["cohorts"] = hf.run_cohort_source(rows, launch_ts=None)
        f["batches"] = [{"funder": "F" * 44, "funder_name": EVIL, "wallets": 9, "share_pct": 3.2, "window_s": 5, "tight": True}]
        a = hf.assess(holders_dict(), f, [])
        md = hf.markdown_report(MINT, holders_dict(), f, 0, a)
        assert_clean(self, md)

    def test_injected_warning_and_upstream_names_never_add_lines(self):
        h = holders_dict()
        h["warnings"] = [EVIL]
        md = hf.markdown_report(MINT, h, None, 0)
        assert_clean(self, md)

    def test_normalized_findings_are_inert_too(self):
        f = hf.normalize_finding({"provider": EVIL, "status": "ok", "largest_cluster_pct": 2.0, "unit": "percent", "detail": EVIL, "alarm_hint": EVIL})
        a = hf.assess(holders_dict(), None, [f])
        assert_clean(self, hf.markdown_report(MINT, holders_dict(), None, 0, a))


class ReadableNamesAndWhyTests(unittest.TestCase):
    def test_prose_uses_readable_names_but_json_keeps_raw_ids(self):
        f = [{"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 40.0, "cluster_sum_pct": 40.0, "bundle_pct": None, "data_age_min": 1.0},
             {"provider": "gmgn", "status": "ok", "largest_cluster_pct": None, "bundle_pct": 1.0, "data_age_min": 1.0},
             {"provider": "okx", "status": "ok", "largest_cluster_pct": 3.0, "bundle_pct": None, "data_age_min": 2.0}]
        a = hf.assess(holders_dict(), None, f)
        md = hf.markdown_report(MINT, holders_dict(), None, 0, a)
        summary = md.split("## Sources read")[0]
        self.assertIn("GMGN reads calm", summary)
        self.assertIn("OKX largest 3.0%", summary)
        self.assertIn("Bubblemaps map: largest cluster 40%", summary)
        self.assertNotIn(" gmgn ", summary)
        raw = json.loads(json.dumps(a))
        self.assertEqual({x["provider"] for x in raw["findings"]}, {"bubblemaps_map", "gmgn", "okx"})
        self.assertIn("gmgn", raw["verdict"]["disagreement"]["disagreeing"])


class CautionReasonTests(unittest.TestCase):
    def test_a_solscanner_only_caution_states_its_reason(self):
        res = ss.collect_solscanner(CAPE, opener=Opener(Response(stream("cape"))), now=lambda: NOW_CAPE)
        a = hf.assess(holders_dict(), None, [hf.solscanner_finding_for(res, NOW_CAPE)], solscanner=res)
        self.assertEqual(a["flag"]["label"], "CAUTION")
        md = hf.markdown_report(MINT, holders_dict(), None, 0, a)
        summary = md.split("## Sources read")[0]
        self.assertIn("- Why: only SolScanner raised it (corroboration only, not confirmed by any other source)", summary)
        self.assertIn("- Also: SolScanner (corroboration only)", summary)

    def test_another_hint_only_provider_is_named(self):
        a = hf.assess(holders_dict(), None, [{"provider": "okx", "status": "ok", "largest_cluster_pct": 2.0, "bundle_pct": None, "data_age_min": 1.0, "alarm_hint": "same fund source 0.947"}])
        self.assertIn("- Why: only OKX raised it (hint only, not confirmed by any other source)", hf.markdown_report(MINT, holders_dict(), None, 0, a))


class StaleWordingTests(unittest.TestCase):
    def test_expired_scan_says_older_than_10_min_and_provider_stale_says_stale(self):
        from test_solscanner_scan import ALTAI, NOW_ALTAI, NOW_SPACE, SPACE

        altai = ss.collect_solscanner(ALTAI, opener=Opener(Response(stream("altai-the-tiger"))), now=lambda: NOW_ALTAI)
        blk = hf._solscanner_source(altai, hf.solscanner_finding_for(altai, NOW_ALTAI))
        self.assertEqual(blk["stale_label"], "older than 10 min")
        a = hf.assess(holders_dict(), None, [hf.solscanner_finding_for(altai, NOW_ALTAI)], solscanner=altai)
        md = hf.markdown_report(MINT, holders_dict(), None, 0, a)
        self.assertIn("scan 11 min old (older than 10 min)", md)
        self.assertNotIn("(STALE)", md.split("## Sources read")[0])
        self.assertIn("stale: 11 min old; older than 10 min", md)
        space = ss.collect_solscanner(SPACE, opener=Opener(Response(stream("space-inu"))), now=lambda: NOW_SPACE)
        sa = hf.assess(holders_dict(), None, [hf.solscanner_finding_for(space, NOW_SPACE)], solscanner=space)
        self.assertIn("(STALE)", hf.markdown_report(MINT, holders_dict(), None, 0, sa).split("## Sources read")[0])


if __name__ == "__main__":
    unittest.main()
