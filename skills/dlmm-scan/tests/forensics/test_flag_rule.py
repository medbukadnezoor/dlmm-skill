"""Flag rule: HIGH is DANGER; UNRESOLVED is DANGER too when a cluster-grade provider finding is over its bar (owner rule:
clear large clusters mean a dangerous token). Presentation only: the underlying level never changes."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
from test_verdict_gating import funders_dict, holders_dict  # noqa: E402

DANGER, CAUTION, NONE = "DANGER FLAG", "CAUTION", "NO FLAG RAISED (not a safety signal)"


def f(provider="bubblemaps_map", cluster=None, total=None, bundle=None, age=1.0, hint=None, status="ok"):
    return {"provider": provider, "status": status, "largest_cluster_pct": cluster, "cluster_sum_pct": total, "bundle_pct": bundle, "data_age_min": age, "alarm_hint": hint}


CALM_GMGN = f("gmgn", bundle=1.0)


def flag(findings, funders=None):
    a = hf.assess(holders_dict(), funders, findings)
    return a["flag"]["label"], a


def with_cohort_ran():
    d = funders_dict(covered=80.0)
    d["cohorts"] = {"coverage": {"rows": 100, "with_funding_time": 100, "supply_pct": 80.0, "share_known_for": 100}, "cohorts": []}
    return d


class DangerMatrixTests(unittest.TestCase):
    def test_provider_clusters_at_or_over_the_bars_are_danger(self):
        cases = {
            "largest 15%": f(cluster=15.0),
            "largest 40%": f(cluster=40.0),
            "aggregate 30% with largest 10%": f(cluster=10.0, total=30.0),
            "bundles 31%": f("gmgn", bundle=31.0),
            "40% with 500 minute old data": f(cluster=40.0, age=500.0),
        }
        for name, finding in cases.items():
            label, a = flag([finding])
            self.assertEqual(label, DANGER, name)
            self.assertEqual(a["verdict"]["level"], hf.VERDICT_HIGH, name)  # nobody contradicts: the level itself is HIGH

    def test_just_under_the_bars_is_no_flag(self):
        label, a = flag([f(cluster=14.9, total=29.9), f("gmgn", bundle=29.9)])
        self.assertEqual(label, NONE)
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)

    def test_solscanner_hint_alone_is_caution(self):
        label, a = flag([f("solscanner", hint="corrob only 98w r96 44pct 4m")])
        self.assertEqual((label, a["verdict"]["level"]), (CAUTION, hf.VERDICT_UNRESOLVED))

    def test_calm_bubblemaps_plus_solscanner_hint_is_caution(self):
        label, a = flag([f(cluster=2.0, total=3.0), f("solscanner", hint="corrob only 98w r96 44pct 4m")])
        self.assertEqual((label, a["verdict"]["level"]), (CAUTION, hf.VERDICT_UNRESOLVED))

    def test_alarm_hint_only_finding_is_caution(self):
        label, _ = flag([f("okx", cluster=2.0, hint="same fund source 0.947")])
        self.assertEqual(label, CAUTION)

    def test_cluster_over_the_bar_against_a_calm_provider_is_danger_naming_the_disagreement(self):
        label, a = flag([f(cluster=40.0), CALM_GMGN])
        self.assertEqual(label, "DANGER FLAG (clear large cluster; sources disagree: GMGN reads calm)")
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_UNRESOLVED)  # the gating logic still says UNRESOLVED

    def test_same_with_own_detectors_fully_run_names_them_too(self):
        label, a = flag([f(cluster=40.0), CALM_GMGN], with_cohort_ran())
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_UNRESOLVED)
        self.assertTrue(label.startswith("DANGER FLAG (clear large cluster; sources disagree: "))
        self.assertIn("own detectors read calm", label)
        self.assertIn("GMGN reads calm", label)

    def test_single_sign_cohort_and_stale_unknown_conditions_stay_caution_or_no_flag(self):
        d = funders_dict(covered=80.0)
        rows = [{"wallet": f"w{i}", "first_funding_time": 1_760_000_000 + i, "funder_address": f"F{i % 3}", "funder_label": None, "first_funding_amount": 1.0, "supply_pct": 0.3, "first_acquired_at": None} for i in range(30)]
        d["cohorts"] = hf.run_cohort_source(rows, launch_ts=None)  # similar amounts only: one sign
        label, a = flag([f(cluster=2.0)], d)
        self.assertEqual((label, a["verdict"]["level"]), (CAUTION, hf.VERDICT_UNRESOLVED))
        stale = f(cluster=2.0, age=900.0)
        label, a = flag([stale])
        self.assertEqual(label, NONE)

    def test_empty_unavailable_and_skipped_never_make_danger(self):
        for status in ("empty", "unavailable", "skipped"):
            label, _ = flag([f(cluster=90.0, status=status)])
            self.assertNotEqual(label, DANGER, status)

    def test_assessment_json_keeps_the_underlying_level_plus_flag(self):
        label, a = flag([f(cluster=40.0), CALM_GMGN])
        data = json.loads(json.dumps(a))
        self.assertEqual(data["verdict"]["level"], "UNRESOLVED")
        self.assertEqual(data["flag"]["level"], "UNRESOLVED")
        self.assertTrue(data["flag"]["label"].startswith("DANGER FLAG"))

    def test_flag_for_without_findings_keeps_the_plain_mapping(self):
        v = lambda level: {"level": level, "reasons": ["r"]}  # noqa: E731
        self.assertEqual(hf.flag_for(v(hf.VERDICT_UNRESOLVED))["label"], CAUTION)
        self.assertEqual(hf.flag_for(v(hf.VERDICT_HIGH))["label"], DANGER)


if __name__ == "__main__":
    unittest.main()
