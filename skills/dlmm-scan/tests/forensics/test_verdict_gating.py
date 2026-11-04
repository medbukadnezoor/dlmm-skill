"""Verdict gating: a report must never read as an all-clear on thin evidence (offline, no network)."""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from unittest import mock  # noqa: E402

import helius_forensics as hf  # noqa: E402
from test_holder_forensics import MINT, FakeHelius, addr, factory_records  # noqa: E402

REASSURING_WORDS = re.compile(r"\b(clean|low|NONE)\b")


def holders_dict(infra=0.0):
    return {"token_accounts": 500, "warnings": [], "distribution": {"owners": 480, "gini": 0.9, "top": {"top_10": 30.0}, "infrastructure_pct": infra, "buckets": {}}}


def funders_dict(*, covered=80.0, with_funder=100, aborted=None, level="NOT_DETECTED"):
    return {
        "examined_wallets": 100, "requested_wallets": 100, "failed_wallets": 0, "with_funder": with_funder, "covered_supply_pct": covered,
        "examined_supply_pct": covered, "aborted": aborted, "batches": [], "upstream": [],
        "verdict": {"level": level, "share_pct": 0.0, "wallets": 0, "batch_funders": 0, "cadence": {}, "reasons": [], "thresholds_are": "UNVALIDATED heuristics"},
    }


def ran(name="funding-time cohort (all funders, labeled included)", state="ran"):
    return [{"name": "funder-batch (per funder, 300 s tight window)", "state": "ran", "detail": ""}, {"name": name, "state": state, "detail": ""}]


class DecideVerdictTests(unittest.TestCase):
    def cov(self, **kw):
        return hf.coverage_block(holders_dict(), funders_dict(**kw))

    def test_own_alarm_is_high_whatever_else_is_missing(self):
        v = hf.decide_verdict(self.cov(covered=5.0), ran(state="not_run"), ["funder-batch STRONG"])
        self.assertEqual(v["level"], hf.VERDICT_HIGH)

    def test_no_alarm_needs_cohort_coverage_and_two_sources(self):
        peers = [{"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 2.0, "data_age_min": 1.0}]
        v = hf.decide_verdict(self.cov(), ran(), [], peers)
        self.assertEqual(v["level"], hf.VERDICT_NO_ALARM)
        self.assertEqual(len(v["sources_counted"]), 2)

    def test_single_source_is_limited(self):
        v = hf.decide_verdict(self.cov(), ran(), [], [])
        self.assertEqual(v["level"], hf.VERDICT_LIMITED)
        self.assertTrue(any("independent cluster-capable" in r for r in v["reasons"]))

    def test_cohort_not_run_is_limited_even_with_two_peers(self):
        peers = [{"provider": p, "status": "ok", "largest_cluster_pct": 1.0, "data_age_min": 1.0} for p in ("bubblemaps_map", "other")]
        self.assertEqual(hf.decide_verdict(self.cov(), ran(state="not_run"), [], peers)["level"], hf.VERDICT_LIMITED)

    def test_coverage_under_bar_is_limited(self):
        peers = [{"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 1.0, "data_age_min": 1.0}]
        v = hf.decide_verdict(self.cov(covered=hf.COVERAGE_MIN_SUPPLY_PCT - 1), ran(), [], peers)
        self.assertEqual(v["level"], hf.VERDICT_LIMITED)
        self.assertTrue(any("is needed" in r for r in v["reasons"]))

    def test_coverage_exactly_at_bar_passes(self):
        peers = [{"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 1.0, "data_age_min": 1.0}]
        self.assertEqual(hf.decide_verdict(self.cov(covered=hf.COVERAGE_MIN_SUPPLY_PCT), ran(), [], peers)["level"], hf.VERDICT_NO_ALARM)

    def test_aborted_run_is_limited(self):
        peers = [{"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 1.0, "data_age_min": 1.0}]
        self.assertEqual(hf.decide_verdict(self.cov(aborted="credit budget reached"), ran(), [], peers)["level"], hf.VERDICT_LIMITED)

    def test_empty_unavailable_and_bundle_only_rows_are_not_sources(self):
        peers = [
            {"provider": "a", "status": "empty", "largest_cluster_pct": 0.0},
            {"provider": "b", "status": "unavailable", "largest_cluster_pct": None},
            {"provider": "c", "status": "ok", "largest_cluster_pct": None, "bundle_pct": 0.5},
        ]
        v = hf.decide_verdict(self.cov(), ran(), [], peers)
        self.assertEqual(v["level"], hf.VERDICT_LIMITED)
        self.assertEqual(v["sources_counted"], ["own funding-time cohort detector"])

    def test_infrastructure_is_excluded_from_the_coverage_basis(self):
        c = hf.coverage_block(holders_dict(infra=50.0), funders_dict(covered=35.0))
        self.assertEqual(c["covered_noninfra_pct"], 70.0)
        self.assertEqual(c["covered_supply_pct"], 35.0)

    def test_unverified_levels_never_use_reassuring_words(self):
        for level in (hf.VERDICT_HIGH, hf.VERDICT_UNRESOLVED, hf.VERDICT_LIMITED, hf.VERDICT_NO_ALARM):
            self.assertIsNone(REASSURING_WORDS.search(level))
            self.assertIsNone(REASSURING_WORDS.search(hf._LEVEL_TEXT[level]))


class AssessAndReportTests(unittest.TestCase):
    def test_holders_only_run_is_limited_with_detectors_not_run(self):
        a = hf.assess(holders_dict(), None)
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)
        self.assertEqual(a["detectors"][0]["state"], "not_run")
        md = hf.markdown_report(MINT, holders_dict(), None, 100)
        self.assertIn("LIMITED", md)
        self.assertIn("NOT RUN", md)
        self.assertIn("Supply examined", md)
        self.assertIsNone(REASSURING_WORDS.search(md))

    def test_quiet_run_with_good_coverage_is_still_limited_without_cohort_detector(self):
        a = hf.assess(holders_dict(), funders_dict())
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)
        md = hf.markdown_report(MINT, holders_dict(), funders_dict(), 100)
        self.assertIn("not an all-clear", md.lower())
        self.assertIsNone(REASSURING_WORDS.search(md))

    def test_factory_pattern_is_high_and_prints_level(self):
        batches = hf.detect_batches(factory_records())
        funders = funders_dict(level="STRONG")
        funders["verdict"] = hf.classify(batches)
        funders["batches"] = [{k: v for k, v in b.items() if k != "members"} for b in batches]
        a = hf.assess(holders_dict(), funders)
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_HIGH)
        md = hf.markdown_report(MINT, holders_dict(), funders, 1)
        self.assertIn("FACTORY_PATTERN: **STRONG**", md)
        self.assertIn("HIGH", md)

    def test_no_funding_records_is_unavailable_not_quiet(self):
        a = hf.assess(holders_dict(), funders_dict(with_funder=0, covered=0.0))
        self.assertEqual(a["detectors"][0]["state"], "unavailable")
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)

    def test_aborted_run_marks_detector_partial(self):
        a = hf.assess(holders_dict(), funders_dict(aborted="credit budget reached"))
        self.assertEqual(a["detectors"][0]["state"], "partial")
        self.assertIn("ran PARTIALLY", hf.markdown_report(MINT, holders_dict(), funders_dict(aborted="credit budget reached"), 1))


class EndToEndTests(unittest.TestCase):
    def test_ordinary_token_run_is_limited_and_writes_assessment(self):
        accounts = [{"owner": addr(i), "amount": 10} for i in range(40)]
        funded = {addr(i): {"funder": f"CEX{i % 3}".ljust(44, "C"), "funderName": "Binance Hot Wallet 2", "timestamp": 2_592_000 * i} for i in range(40)}
        fake = FakeHelius(accounts=accounts, funded=funded)
        with mock.patch.object(hf, "dexscreener_pairs", return_value=([], True)):
            holders = hf.run_holders(fake, MINT)
        funders = hf.run_funders(fake, holders, top=40)
        self.assertEqual(funders["examined_supply_pct"], 100.0)
        a = hf.assess(hf._public(holders), funders)
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)
        self.assertEqual(a["coverage"]["examined_wallets"], 40)


if __name__ == "__main__":
    unittest.main()
