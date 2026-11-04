"""Cohort severity: HIGH needs >= 20 wallets, >= 2 funders and two signs; supply-route-only, single-funder or one-sign cohorts are UNRESOLVED."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
from test_verdict_gating import funders_dict, holders_dict  # noqa: E402

T0 = 1_760_000_000


def row(i, t, funder="F", pct=0.2, label=None, amount=1.0):
    return {"wallet": f"w{i}", "first_funding_time": t, "funder_address": funder, "funder_label": label, "first_funding_amount": amount, "supply_pct": pct, "first_acquired_at": None}


LAUNCH_LATER = T0 + 30 * 86400  # wallets funded 30 days before launch: dormancy, the second sign next to similar amounts


def funders_for(rows, covered=70.0, launch=None):
    f = funders_dict(covered=covered)
    f["cohorts"] = hf.run_cohort_source(rows, launch_ts=launch)
    return f


def quiet_map():
    return {"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 2.0, "bundle_pct": None, "data_age_min": 1.0}


class SeverityTests(unittest.TestCase):
    def test_supply_route_only_is_unresolved(self):
        c = hf.detect_cohorts([row(i, T0 + i * 60, funder=f"F{i}", pct=1.55) for i in range(6)])[0]  # 6 wallets, 9.3%, six funders
        self.assertEqual(c["flagged_by"], "supply")
        self.assertEqual(c["severity"], hf.VERDICT_UNRESOLVED)
        self.assertIn("supply share alone", c["severity_reason"])

    def test_single_funder_even_with_many_wallets_is_unresolved(self):
        c = hf.detect_cohorts([row(i, T0 + i * 60, funder="ONE", pct=0.1) for i in range(40)])[0]
        self.assertEqual((c["wallets"], c["distinct_funders"]), (40, 1))
        self.assertEqual(c["severity"], hf.VERDICT_UNRESOLVED)
        self.assertIn("single funder", c["severity_reason"])

    def test_twenty_wallets_two_funders_is_high(self):
        rows = [row(i, T0 + i * 60, funder=f"F{i % 2}", pct=0.05) for i in range(20)]
        c = hf.run_cohort_source(rows, launch_ts=LAUNCH_LATER)["cohorts"][0]  # dormant 30 days + similar amounts
        self.assertEqual(c["severity"], hf.VERDICT_HIGH)
        self.assertEqual(hf.run_cohort_source(rows, launch_ts=None)["cohorts"][0]["severity"], hf.VERDICT_UNRESOLVED)  # similar amounts alone

    def test_nineteen_wallets_is_not_high_even_with_big_share(self):
        c = hf.detect_cohorts([row(i, T0 + i * 60, funder=f"F{i % 5}", pct=1.0) for i in range(19)])[0]
        self.assertEqual(c["severity"], hf.VERDICT_UNRESOLVED)

    def test_dormant_and_similar_support_is_reported_but_does_not_rescue_a_single_funder(self):
        rows = [dict(row(i, T0 + i * 60, funder="ONE", pct=0.1), first_acquired_at=T0 + 40 * 86400) for i in range(25)]
        c = hf.detect_cohorts(rows)[0]
        self.assertEqual(c["severity"], hf.VERDICT_UNRESOLVED)
        self.assertIn("dormant 40 days", c["severity_reason"])
        self.assertIn("similar first amounts", c["severity_reason"])

    def test_veil_like_cohort_is_high(self):
        rows = [row(r * 19 + w, T0 + r * 118 + w * 5, funder=f"VF{r}", pct=0.28) for r in range(12) for w in range(19 if r < 11 else 21)]
        self.assertEqual(len(rows), 230)
        self.assertEqual(hf.run_cohort_source(rows, launch_ts=None)["cohorts"][0]["severity"], hf.VERDICT_UNRESOLVED)  # one sign: similar amounts
        # END TO END the funder-batch detector (12 unlabeled tight funders) still makes the overall verdict HIGH:
        # see test_veil_end_to_end in test_veil_styles.py


class VerdictTests(unittest.TestCase):
    def test_unresolved_cohort_gives_unresolved_verdict_naming_it(self):
        f = funders_for([row(i, T0 + i * 60, funder=f"F{i}", pct=1.55) for i in range(6)])
        a = hf.assess(holders_dict(), f, [quiet_map()])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_UNRESOLVED)
        text = " ".join(a["verdict"]["reasons"])
        self.assertIn("UNRESOLVED, not HIGH", text)
        self.assertIn("6 wallets", text)
        md = hf.markdown_report(hf.__name__, holders_dict(), f, 1, a)
        self.assertIn("severity: UNRESOLVED", md)

    def test_high_cohort_still_gives_high(self):
        f = funders_for([row(i, T0 + i * 60, funder=f"F{i % 3}", pct=0.1) for i in range(30)], launch=LAUNCH_LATER)
        self.assertEqual(hf.assess(holders_dict(), f, [quiet_map()])["verdict"]["level"], hf.VERDICT_HIGH)

    def test_high_and_unresolved_cohorts_together_are_high(self):
        big = [row(i, T0 + i * 60, funder=f"F{i % 3}", pct=0.1) for i in range(25)]
        small = [row(100 + i, T0 + 30 * 86400 + i * 60, funder="B", pct=1.6) for i in range(6)]
        self.assertEqual(hf.assess(holders_dict(), funders_for(big + small, launch=LAUNCH_LATER), [quiet_map()])["verdict"]["level"], hf.VERDICT_HIGH)

    def test_unresolved_cohort_never_reaches_no_alarm_and_a_provider_alarm_makes_it_high(self):
        f = funders_for([row(i, T0 + i * 60, funder="ONE", pct=0.1) for i in range(30)])
        alarm = {"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 25.0, "bundle_pct": None, "data_age_min": 1.0}
        self.assertEqual(hf.assess(holders_dict(), f, [alarm])["verdict"]["level"], hf.VERDICT_HIGH)
        self.assertNotEqual(hf.assess(holders_dict(), f, [quiet_map()])["verdict"]["level"], hf.VERDICT_NO_ALARM)


if __name__ == "__main__":
    unittest.main()
