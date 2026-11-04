"""Cross-provider disagreement rule and the required Bubblemaps map step (offline)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
from test_holder_forensics import MINT, NO_KEY_ENV, SECRET, FakeHelius, addr  # noqa: E402
from test_verdict_gating import funders_dict, holders_dict, ran  # noqa: E402


def f(provider, cluster=None, bundle=None, age=1.0, status="ok", hint=None):
    return {"provider": provider, "status": status, "largest_cluster_pct": cluster, "bundle_pct": bundle, "data_age_min": age, "alarm_hint": hint}


def cov(covered=80.0):
    return hf.coverage_block(holders_dict(), funders_dict(covered=covered))


class DisagreementTests(unittest.TestCase):
    def test_no_alarm_returns_none(self):
        self.assertIsNone(hf.apply_disagreement([f("a", 5.0, 10.0)], hf.VERDICT_NO_ALARM)["level"])

    def test_bars_are_inclusive(self):
        self.assertEqual(hf.apply_disagreement([f("a", hf.CLUSTER_ALARM_PCT)], hf.VERDICT_LIMITED)["alarming"], ["a"])
        self.assertEqual(hf.apply_disagreement([f("a", None, hf.BUNDLE_ALARM_PCT)], hf.VERDICT_LIMITED)["alarming"], ["a"])
        self.assertIsNone(hf.apply_disagreement([f("a", hf.CLUSTER_ALARM_PCT - 0.1, hf.BUNDLE_ALARM_PCT - 0.1)], hf.VERDICT_LIMITED)["level"])

    def test_cape_like_bubblemaps_alarm_against_quiet_gmgn_and_own_is_unresolved_naming_both(self):
        out = hf.apply_disagreement([f("bubblemaps_map", 25.45), f("gmgn", None, 0.76)], hf.VERDICT_NO_ALARM)
        self.assertEqual(out["level"], hf.VERDICT_UNRESOLVED)
        self.assertEqual(out["alarming"], ["bubblemaps_map"])
        self.assertIn("gmgn", out["disagreeing"])
        self.assertIn("own detectors", out["disagreeing"])
        self.assertIn("bubblemaps_map", out["reasons"][0])

    def test_uncontradicted_alarm_is_high_and_own_high_is_high(self):
        self.assertEqual(hf.apply_disagreement([f("bubblemaps_map", 25.0)], hf.VERDICT_LIMITED)["level"], hf.VERDICT_HIGH)
        self.assertEqual(hf.apply_disagreement([f("bubblemaps_map", 25.0), f("gmgn", 1.0)], hf.VERDICT_HIGH)["level"], hf.VERDICT_HIGH)

    def test_only_status_ok_can_alarm(self):
        for st in ("empty", "unavailable", "skipped"):
            self.assertIsNone(hf.apply_disagreement([f("x", 90.0, 90.0, status=st)], hf.VERDICT_LIMITED)["level"])

    def test_stale_provider_can_still_raise_an_alarm(self):
        out = hf.apply_disagreement([f("old_map", 40.0, age=600.0)], hf.VERDICT_LIMITED)
        self.assertEqual(out["level"], hf.VERDICT_HIGH)

    def test_alarm_hint_raises_unresolved_even_when_label_is_low(self):
        out = hf.apply_disagreement([f("okx", 2.0, hint="same-fund-source 0.947")], hf.VERDICT_NO_ALARM)
        self.assertEqual(out["level"], hf.VERDICT_UNRESOLVED)
        self.assertIn("okx", out["reasons"][0])
        self.assertFalse(hf.all_clear_counts(f("okx", 2.0, hint="x"), 100.0))

    def test_normalize_keeps_hint_and_rejects_bad_values(self):
        n = hf.normalize_finding({"provider": "okx<script>", "status": "weird", "largest_cluster_pct": 25, "alarm_hint": "sub-metric high"})
        self.assertEqual(n["status"], "unavailable")
        self.assertNotIn("<", n["provider"])
        self.assertEqual(n["alarm_hint"], "sub-metric high")
        self.assertIsNone(hf.normalize_finding("nope"))
        for st in hf.PROVIDER_STATUSES:
            self.assertEqual(hf.normalize_finding({"provider": "p", "status": st, "largest_cluster_pct": 1.0 if st == "ok" else None})["status"], st)
        with self.assertRaises(hf.ConfigError):
            hf.normalize_finding({"provider": "p", "status": "ok", "largest_cluster_pct": 250})


class StaleRuleTests(unittest.TestCase):
    def test_stale_all_clear_on_young_token_does_not_count(self):
        peers = [f("bubblemaps_map", 2.0, age=hf.STALE_ALL_CLEAR_MIN + 1)]
        v = hf.decide_verdict(cov(), ran(), [], peers, token_age_h=0.75, required=("bubblemaps_map",))
        self.assertEqual(v["level"], hf.VERDICT_LIMITED)
        self.assertTrue(any("not counted" in r for r in v["reasons"]))

    def test_fresh_all_clear_on_young_token_counts(self):
        peers = [f("bubblemaps_map", 2.0, age=hf.STALE_ALL_CLEAR_MIN)]
        self.assertEqual(hf.decide_verdict(cov(), ran(), [], peers, token_age_h=0.75, required=("bubblemaps_map",))["level"], hf.VERDICT_NO_ALARM)

    def test_unknown_age_on_young_token_does_not_count_but_old_token_is_fine(self):
        peers = [f("bubblemaps_map", 2.0, age=None)]
        self.assertEqual(hf.decide_verdict(cov(), ran(), [], peers, token_age_h=1.0)["level"], hf.VERDICT_LIMITED)
        self.assertEqual(hf.decide_verdict(cov(), ran(), [], peers, token_age_h=None)["level"], hf.VERDICT_LIMITED)
        self.assertEqual(hf.decide_verdict(cov(), ran(), [], peers, token_age_h=hf.YOUNG_TOKEN_MAX_AGE_H + 1)["level"], hf.VERDICT_NO_ALARM)

    def test_stale_alarm_beats_everything(self):
        peers = [f("bubblemaps_map", 44.0, age=900.0)]
        # own detectors ran quiet (ran()) so the stale alarm is a disagreement; it is never ignored or downgraded to LIMITED
        self.assertEqual(hf.decide_verdict(cov(), ran(), [], peers, token_age_h=0.75)["level"], hf.VERDICT_UNRESOLVED)
        self.assertEqual(hf.decide_verdict(cov(), ran(state="not_run"), [], peers, token_age_h=0.75)["level"], hf.VERDICT_HIGH)


class RequiredMapTests(unittest.TestCase):
    def test_absent_map_blocks_no_alarm_and_is_reported(self):
        a = hf.assess(holders_dict(), funders_dict(), [f("other_a", 1.0), f("other_b", 1.0)])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)
        self.assertTrue(any("bubblemaps_map step did not run" in r for r in a["verdict"]["reasons"]))
        md = hf.markdown_report(MINT, holders_dict(), funders_dict(), 1, a)
        self.assertIn("bubblemaps_map: NOT RUN", md)

    def test_unreadable_or_empty_map_blocks_no_alarm(self):
        for fnd in (hf.bubblemaps_finding({"mint": MINT, "parse_ok": False}, MINT), hf.bubblemaps_finding({"mint": MINT, "parse_ok": True, "clusters": [], "largest_pool_share_pct": 99.0, "age_min_after": 1}, MINT)):
            a = hf.assess(holders_dict(), funders_dict(), [fnd])
            self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)
        self.assertEqual(fnd["status"], "empty")

    def test_map_for_another_mint_is_unavailable(self):
        self.assertEqual(hf.bubblemaps_finding({"mint": "other", "parse_ok": True, "clusters": [{"supply_pct": 50.0}]}, MINT)["status"], "unavailable")

    def test_cape_map_adds_file_age_and_alarms(self):
        m = {"mint": MINT, "parse_ok": True, "age_min_after": 1.0, "refresh_effective": False, "clusters": [{"cluster": 1, "wallets": 283, "supply_pct": 25.45}, {"cluster": 2, "wallets": 59, "supply_pct": 17.44}]}
        fnd = hf.bubblemaps_finding(m, MINT, extra_age_min=4.0)
        self.assertEqual((fnd["status"], fnd["largest_cluster_pct"], fnd["data_age_min"]), ("ok", 25.45, 5.0))
        a = hf.assess(holders_dict(), funders_dict(), [fnd])
        self.assertIn(a["verdict"]["level"], (hf.VERDICT_HIGH, hf.VERDICT_UNRESOLVED))
        self.assertNotEqual(a["verdict"]["level"], hf.VERDICT_NO_ALARM)

    def test_cape_like_with_quiet_own_and_quiet_gmgn_is_unresolved(self):
        a = hf.assess(holders_dict(), funders_dict(), [f("bubblemaps_map", 25.45), f("gmgn", None, 0.76)])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_UNRESOLVED)  # quiet GMGN disagrees with the Bubblemaps alarm
        self.assertIn("bubblemaps_map", a["verdict"]["reasons"][0])
        self.assertIn("gmgn", a["verdict"]["reasons"][0])
        alone = hf.assess(holders_dict(), funders_dict(), [f("bubblemaps_map", 25.45)])
        self.assertEqual(alone["verdict"]["level"], hf.VERDICT_HIGH)  # nobody contradicts it
        calm_gmgn = hf.apply_disagreement([f("bubblemaps_map", 25.45), f("gmgn", None, 0.76)], hf.VERDICT_LIMITED)
        self.assertEqual(calm_gmgn["level"], hf.VERDICT_UNRESOLVED)


class CliTests(unittest.TestCase):
    def _main(self, argv, fake):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {**NO_KEY_ENV, "HELIUS_API_KEY": SECRET}, clear=True), mock.patch.object(hf, "Helius", return_value=fake), \
             mock.patch.object(hf, "dexscreener_pairs", return_value=([], True)), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            return hf.main(argv), out.getvalue(), err.getvalue()

    def test_missing_input_file_fails_before_any_call(self):
        with mock.patch.object(hf, "run_holders", side_effect=AssertionError("must not run")):
            code, _, err = self._main(["report", MINT, "--top", "1", "--bubblemaps-json", "/nonexistent/map.json"], FakeHelius())
        self.assertEqual(code, 2)
        self.assertIn("--bubblemaps-json", err)

    def test_report_without_map_says_step_did_not_run(self):
        accounts = [{"owner": addr(i), "amount": 10} for i in range(5)]
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self._main(["report", MINT, "--top", "5", "--out", tmp], FakeHelius(accounts=accounts))
        self.assertIn("bubblemaps_map: NOT RUN", out)
        self.assertIn("LIMITED", out)

    def test_report_with_saved_map_alarms(self):
        accounts = [{"owner": addr(i), "amount": 10} for i in range(5)]
        m = {"mint": MINT, "parse_ok": True, "age_min_after": 1.0, "clusters": [{"cluster": 1, "wallets": 9, "supply_pct": 30.0}]}
        with tempfile.TemporaryDirectory() as tmp:
            mp = Path(tmp) / "map.json"
            mp.write_text(json.dumps(m))
            code, out, _ = self._main(["report", MINT, "--top", "5", "--out", tmp, "--bubblemaps-json", str(mp)], FakeHelius(accounts=accounts))
            self.assertTrue((Path(tmp) / "assessment.json").exists())
        self.assertIn("bubblemaps_map alarms", out)
        self.assertIn("HIGH", out)

    def test_providers_json_rows_are_normalized(self):
        accounts = [{"owner": addr(i), "amount": 10} for i in range(5)]
        with tempfile.TemporaryDirectory() as tmp:
            pj = Path(tmp) / "p.json"
            pj.write_text(json.dumps([{"provider": "insightx", "status": "empty", "largest_cluster_pct": 0.0, "unit": "percent"}]))
            _, out, _ = self._main(["report", MINT, "--top", "5", "--out", tmp, "--providers-json", str(pj)], FakeHelius(accounts=accounts))
        self.assertIn("insightx: ran, EMPTY", out)


if __name__ == "__main__":
    unittest.main()
