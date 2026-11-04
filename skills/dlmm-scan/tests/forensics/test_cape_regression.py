"""Regression tests from the CAPE miss (2026-10-14) and a VEIL-shaped case. Offline, fixture-driven, no credits.

Positives: CAPE cluster 2 (50 wallets first funded 2026-08-19 10:17:27 to 16:01:42 UTC through six labeled
exchanges/services) and a synthetic VEIL-like factory (230 wallets, 12 funders about 2 min apart).
Negatives here are SYNTHETIC independent holders only; real-token negatives are a TODO (test_negative_controls_todo.py).
"""

from __future__ import annotations

import csv
import datetime as dt
import json
import random
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
from test_holder_forensics import MINT, factory_records  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cape_cohort_fixture.csv"


def _unix(text: str) -> int:
    return int(dt.datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp())


def load_fixture():
    rows = []
    with FIXTURE.open(newline="") as fh:
        for r in csv.DictReader(fh):
            label = r["first_funder_label"] if r["first_funder_label"] not in ("", "unlabeled") else None
            rows.append(
                {
                    "group": r["group"],
                    "wallet": r["wallet"],
                    "first_funding_time": _unix(r["first_funded_utc"]),
                    "funder_address": r["first_funder"],
                    "funder_label": label,
                    "first_funding_amount": float(r["first_funding_sol"]),
                    "supply_pct": float(r["supply_pct_bubblemaps"]),
                    "first_acquired_at": None,
                }
            )
    return rows


def helius_records(rows):
    """Fixture rows in the shape build_records() produces, for the full report path."""
    return [
        {"wallet": r["wallet"], "share_pct": r["supply_pct"], "funder": r["funder_address"], "funder_name": r["funder_label"], "funder_type": None, "funded_at": r["first_funding_time"], "first_amount_sol": r["first_funding_amount"]}
        for r in rows
    ]


def holders_dict(infra=0.0, launch=None):
    return {"token_accounts": 3000, "warnings": [], "earliest_pair_created_at": launch, "distribution": {"owners": 2900, "gini": 0.9, "top": {}, "infrastructure_pct": infra, "buckets": {}}}


def funders_from(rows, covered, **kw):
    recs = helius_records(rows)
    batches = hf.detect_batches(recs)
    return {
        "examined_wallets": len(rows), "requested_wallets": len(rows), "failed_wallets": 0, "with_funder": len(rows), "covered_supply_pct": covered, "examined_supply_pct": covered,
        "aborted": kw.get("aborted"), "verdict": hf.classify(batches), "batches": [], "upstream": [],
        "cohorts": hf.run_cohort_source(hf.helius_cohort_rows(recs), launch_ts=kw.get("launch"), acquisitions=kw.get("acq")),
    }


class FixtureShapeTests(unittest.TestCase):
    def test_fixture_matches_the_handoff(self):
        rows = load_fixture()
        by = {g: [r for r in rows if r["group"] == g] for g in ("C1 sample", "C2", "C3")}
        self.assertEqual({g: len(v) for g, v in by.items()}, {"C1 sample": 30, "C2": 50, "C3": 8})
        c2 = by["C2"]
        self.assertEqual(min(r["first_funding_time"] for r in c2), _unix("2026-08-19 10:17:27"))
        self.assertEqual(max(r["first_funding_time"] for r in c2), _unix("2026-08-19 16:01:42"))
        self.assertEqual(len({r["funder_label"] for r in c2}), 6)
        self.assertTrue(all(r["funder_label"] for r in c2))
        self.assertAlmostEqual(sum(r["supply_pct"] for r in c2), 17.44, places=1)

    def test_fixture_holds_only_public_columns(self):
        header = FIXTURE.read_text().splitlines()[0]
        self.assertEqual(header, "group,wallet,supply_pct_bubblemaps,first_funder,first_funder_label,first_funded_utc,first_funding_sol")
        self.assertNotIn("/Users", FIXTURE.read_text())


class CapeCohortDetectionTests(unittest.TestCase):
    def test_cluster_2_is_flagged_as_one_50_wallet_cohort(self):
        rows = [r for r in load_fixture() if r["group"] == "C2"]
        cohorts = hf.detect_cohorts(rows)
        self.assertEqual(len(cohorts), 1)
        c = cohorts[0]
        self.assertEqual(c["wallets"], 50)
        self.assertAlmostEqual(c["share_pct"], 17.44, places=1)
        self.assertLess(c["window_s"], hf.COHORT_WINDOW_S)
        self.assertEqual(c["distinct_funders"], 6)
        self.assertEqual(c["labeled_funder_wallets"], 50)  # every funder is a labeled exchange/service and it is still flagged
        self.assertEqual({m["label"] for m in c["funder_mix"]}, {"FixedFloat Hot Wallet", "Gate Hot Wallet", "KuCoin Hot Wallet 2", "Bitget Hot Wallet", "Relay Solver", "Binance Hot Wallet 2"})
        self.assertEqual(c["flagged_by"], "wallets+supply")
        self.assertTrue(0.8 <= c["first_amounts"]["median"] <= 1.5)  # handoff: about 0.8 to 1.4 SOL each (a few outliers exist)

    def test_whole_fixture_flags_exactly_cluster_2(self):
        rows = load_fixture()
        cohorts = hf.detect_cohorts(rows)
        self.assertEqual(len(cohorts), 1)
        group = {r["wallet"]: r["group"] for r in rows}
        self.assertEqual({group[w] for w in cohorts[0]["members"]}, {"C2"})
        self.assertEqual(cohorts[0]["wallets"], 50)

    def test_cluster_3_eight_wallets_is_not_a_cohort(self):
        rows = [r for r in load_fixture() if r["group"] == "C3"]
        self.assertEqual(len(rows), 8)
        self.assertEqual(hf.detect_cohorts(rows), [])
        self.assertEqual(hf.detect_cohorts(rows, min_wallets=20, min_supply_pct=hf.COHORT_MIN_SUPPLY_PCT), [])
        self.assertLess(sum(r["supply_pct"] for r in rows), hf.COHORT_MIN_SUPPLY_PCT)

    def test_cluster_1_sample_spread_over_months_is_not_a_cohort(self):
        self.assertEqual(hf.detect_cohorts([r for r in load_fixture() if r["group"] == "C1 sample"]), [])

    def test_old_funder_batch_logic_misses_cape_which_is_why_the_cohort_detector_exists(self):
        rows = [r for r in load_fixture() if r["group"] == "C2"]
        verdict = hf.classify(hf.detect_batches(helius_records(rows)))
        self.assertEqual(verdict["level"], "NOT_DETECTED")  # labeled funders, 3-15 wallets each over hours
        self.assertEqual(len(hf.detect_cohorts(rows)), 1)

    def test_cape_through_the_report_path_is_high_not_no_alarm(self):
        """Dormant 56 days (funded before the 2026-10-14 launch) plus synchronized buying (GMGN start_holding_at times
        of the cohort wallets): two signs, so HIGH. Without acquisition data CAPE has dormancy only: UNRESOLVED."""
        rows = load_fixture()
        launch = _unix("2026-10-14 09:04:00")
        gmgn = {r["wallet"]: r["first_acquired_at"] for r in hf.gmgn_cohort_rows(json.loads((FIXTURE.parent / "cape_gmgn.json").read_text())) if r["first_acquired_at"]}
        funders = funders_from(rows, covered=31.0, launch=launch, acq=gmgn)
        a = hf.assess(holders_dict(launch=launch), funders)
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_HIGH)
        md = hf.markdown_report(MINT, holders_dict(), funders, 8800, a)
        self.assertIn("50 wallets", md)
        self.assertIn("Gate Hot Wallet", md)
        self.assertIn("HIGH", md)
        self.assertIn("dormant 56 days", md)
        alone = hf.assess(holders_dict(launch=launch), funders_from(rows, covered=31.0, launch=launch))
        self.assertEqual(alone["verdict"]["level"], hf.VERDICT_UNRESOLVED)

    def test_cape_with_acquisition_times_adds_the_corroboration(self):
        rows = [r for r in load_fixture() if r["group"] == "C2"]
        launch = _unix("2026-10-14 09:04:00")
        acq = {r["wallet"]: launch + 1308 + i * 15 for i, r in enumerate(rows[:36])}  # 21.8 min onward, n=36, about 9 min span
        source = hf.run_cohort_source(hf.helius_cohort_rows(helius_records(rows), acq), launch_ts=launch, acquisitions=acq)
        c = source["cohorts"][0]
        self.assertTrue(c["acquisition"]["flag"])
        self.assertAlmostEqual(c["dormant_gap_s"]["median"] / 86400, 56.0, delta=1.0)


class CapeLikeVerdictTests(unittest.TestCase):
    """CAPE-like inputs must end HIGH or UNRESOLVED; coverage-limited quiet inputs must end LIMITED."""

    def bm(self, pct=25.45, age=1.0):
        return {"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": pct, "bundle_pct": None, "data_age_min": age}

    def gmgn(self):
        return {"provider": "gmgn", "status": "ok", "largest_cluster_pct": None, "bundle_pct": 0.76, "data_age_min": 1.0}

    def test_bubblemaps_alarm_with_no_cohort_data_is_high(self):
        a = hf.assess(holders_dict(), None, [self.bm()])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_HIGH)

    def test_bubblemaps_alarm_against_quiet_gmgn_and_quiet_own_is_unresolved_naming_it(self):
        rows = [r for r in load_fixture() if r["group"] == "C1 sample"]  # own detector ran and found no cohort
        funders = funders_from(rows, covered=70.0)
        a = hf.assess(holders_dict(), funders, [self.bm(), self.gmgn()])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_UNRESOLVED)
        self.assertIn("bubblemaps_map", " ".join(a["verdict"]["reasons"]))
        self.assertIn("gmgn", " ".join(a["verdict"]["reasons"]))

    def test_only_the_gmgn_bundler_tag_and_jupiter_style_quiet_inputs_are_limited_not_clear(self):
        a = hf.assess(holders_dict(), None, [self.gmgn()])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)

    def test_low_coverage_quiet_run_is_limited(self):
        rows = [r for r in load_fixture() if r["group"] == "C1 sample"]
        funders = funders_from(rows, covered=hf.COVERAGE_MIN_SUPPLY_PCT - 5)
        quiet_map = {"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 2.0, "bundle_pct": None, "data_age_min": 1.0}
        a = hf.assess(holders_dict(), funders, [quiet_map])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)

    def test_full_quiet_run_with_map_and_fresh_data_can_reach_no_alarm_but_never_clean(self):
        rows = [r for r in load_fixture() if r["group"] == "C1 sample"]
        funders = funders_from(rows, covered=70.0)
        quiet_map = {"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 2.0, "bundle_pct": None, "data_age_min": 1.0}
        a = hf.assess(holders_dict(), funders, [quiet_map])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_NO_ALARM)
        md = hf.markdown_report(MINT, holders_dict(), funders, 1, a)
        self.assertNotIn("clean", md.lower())
        self.assertIn("NOT proof", md)

    def test_stale_map_on_a_young_token_blocks_no_alarm(self):
        rows = [r for r in load_fixture() if r["group"] == "C1 sample"]
        funders = funders_from(rows, covered=70.0)
        stale = {"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 2.0, "bundle_pct": None, "data_age_min": 45.0}
        now = 1_000_000.0
        holders = holders_dict(launch=int(now - 45 * 60))
        self.assertEqual(hf.assess(holders, funders, [stale], now=now)["verdict"]["level"], hf.VERDICT_LIMITED)


class VeilLikeAndNegativeTests(unittest.TestCase):
    def test_veil_like_230_wallets_12_funders_two_minutes_apart_is_flagged(self):
        recs = []
        for r in range(12):
            for w in range(19 if r < 11 else 21):
                recs.append({"wallet": f"v{r}_{w}", "share_pct": 0.28, "funder": f"VF{r}", "funder_name": None, "funder_type": None, "funded_at": 1_000_000 + r * 118 + w * 5, "first_amount_sol": 2.5})
        self.assertEqual(len(recs), 230)
        cohorts = hf.detect_cohorts(hf.helius_cohort_rows(recs))
        self.assertEqual(len(cohorts), 1)
        self.assertEqual((cohorts[0]["wallets"], cohorts[0]["distinct_funders"]), (230, 12))
        self.assertTrue(cohorts[0]["first_amounts"]["similar"])
        self.assertAlmostEqual(cohorts[0]["share_pct"], 64.4, places=1)

    def test_independent_holders_funded_over_months_are_not_flagged(self):
        rng = random.Random(7)
        rows = [{"wallet": f"i{n}", "first_funding_time": 1_700_000_000 + rng.randrange(0, 150 * 86400), "funder_address": f"X{n % 40}", "funder_label": "Binance Hot Wallet 2" if n % 3 else None,
                 "first_funding_amount": rng.uniform(0.05, 20.0), "supply_pct": 0.3, "first_acquired_at": None} for n in range(250)]
        self.assertEqual(hf.detect_cohorts(rows), [])

    def test_one_funder_every_two_days_is_not_flagged(self):
        rows = [{"wallet": f"s{n}", "first_funding_time": 1_700_000_000 + n * 2 * 86400, "funder_address": "ONE", "funder_label": None, "first_funding_amount": 1.0, "supply_pct": 0.2, "first_acquired_at": None} for n in range(120)]
        self.assertEqual(hf.detect_cohorts(rows), [])

    def test_hourly_funding_stays_under_the_wallet_bar(self):
        rows = [{"wallet": f"h{n}", "first_funding_time": 1_700_000_000 + n * 3600, "funder_address": f"F{n % 7}", "funder_label": None, "first_funding_amount": 1.0, "supply_pct": 0.2, "first_acquired_at": None} for n in range(200)]
        # 7 wallets per 6 h window x 0.2% = 1.4%: neither the 20-wallet nor the 5% bar
        self.assertEqual(hf.detect_cohorts(rows), [])

    def test_synthetic_independent_run_through_the_report_path_is_limited_or_no_alarm_never_high(self):
        rng = random.Random(11)
        recs = [{"wallet": f"i{n}", "share_pct": 0.3, "funder": f"X{n}", "funder_name": None, "funder_type": None, "funded_at": 1_700_000_000 + rng.randrange(0, 200 * 86400), "first_amount_sol": 1.0} for n in range(250)]
        batches = hf.detect_batches(recs)
        funders = {
            "examined_wallets": 250, "requested_wallets": 250, "failed_wallets": 0, "with_funder": 250, "covered_supply_pct": 75.0, "examined_supply_pct": 75.0, "aborted": None,
            "verdict": hf.classify(batches), "batches": [], "upstream": [], "cohorts": hf.run_cohort_source(hf.helius_cohort_rows(recs), launch_ts=None),
        }
        a = hf.assess(holders_dict(), funders)
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)  # the Bubblemaps map step did not run
        self.assertEqual(funders["cohorts"]["cohorts"], [])

    def test_factory_records_helper_still_flagged_by_both_detectors(self):
        recs = factory_records()
        self.assertEqual(hf.classify(hf.detect_batches(recs))["level"], "STRONG")
        self.assertEqual(len(hf.detect_cohorts(hf.helius_cohort_rows(recs))), 1)


if __name__ == "__main__":
    unittest.main()
