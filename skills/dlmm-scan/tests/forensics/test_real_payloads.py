"""Real provider payloads (public addresses and numbers only, trimmed to the fields the adapters read).

Negatives: Space Inu and Altai the Tiger (2026-10-14, GMGN top 100, Jupiter datapi top 100, Bubblemaps map).
Positive: CAPE (same day, GMGN and Jupiter top 100). Limits of this evidence: only TWO negative tokens, both with
older wallets. A brand-new organic token with many fresh exchange-funded buyers is the known false-positive risk and
is NOT covered here. Jupiter shares assume the 1e9 pump.fun supply (no supply is stored in the payload).
"""

from __future__ import annotations

import csv
import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
PUMP_SUPPLY = 1e9
CAPE_LAUNCH = 1_791_968_640  # 2026-10-14 09:04:00 UTC
SPACE_INU = "HfpLdX35Kc6b7zDNWbe5x1xWLekKUXPYZbmz71vMpump"
ALTAI = "Gyk9Z93Ri2JUjqES9HTpc7pxCJTLD7vhBhEjBhyApump"


def load(name):
    return json.loads((FIX / name).read_text())


def rows(token, source):
    payload = load(f"{token}_{source}.json")
    return hf.gmgn_cohort_rows(payload) if source == "gmgn" else hf.jupiter_cohort_rows(payload, total_supply=PUMP_SUPPLY)


def holders_stub():
    return {"token_accounts": 3000, "warnings": [], "_balances": {}, "earliest_pair_created_at": None, "distribution": {"owners": 2900, "infrastructure_pct": 0.0}}


class NegativeControlTests(unittest.TestCase):
    def test_no_flagged_cohort_via_either_adapter(self):
        for token in ("space_inu", "altai_the_tiger"):
            for source in ("gmgn", "jupiter"):
                r = rows(token, source)
                self.assertEqual(len(r), 100, (token, source))
                self.assertGreater(hf.source_coverage(r)["with_funding_time"], 80, (token, source))
                self.assertEqual(hf.detect_cohorts(r), [], (token, source))

    def test_negative_tokens_never_reach_high(self):
        for token, mint in (("space_inu", SPACE_INU), ("altai_the_tiger", ALTAI)):
            bubble = hf.bubblemaps_finding(load(f"{token}_bubblemaps.json"), mint)
            self.assertEqual(bubble["status"], "ok")
            self.assertEqual(hf.finding_alarms(bubble), [])
            sources = hf.provider_cohort_sources(holders_stub(), load(f"{token}_gmgn.json"), load(f"{token}_jupiter.json"))
            a = hf.assess(holders_stub(), None, [bubble], provider_cohorts=sources)
            self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)  # no Helius full list ran: unverified, but no alarm
            self.assertNotIn(a["verdict"]["level"], (hf.VERDICT_HIGH, hf.VERDICT_UNRESOLVED))

    def test_bubblemaps_negatives_match_the_recorded_clusters(self):
        space = hf.bubblemaps_finding(load("space_inu_bubblemaps.json"), SPACE_INU)
        altai = hf.bubblemaps_finding(load("altai_the_tiger_bubblemaps.json"), ALTAI)
        self.assertAlmostEqual(space["largest_cluster_pct"], 5.24)
        self.assertAlmostEqual(altai["largest_cluster_pct"], 3.42)
        self.assertLess(space["cluster_sum_pct"], hf.AGGREGATE_CLUSTER_ALARM_PCT)
        self.assertLess(altai["cluster_sum_pct"], hf.AGGREGATE_CLUSTER_ALARM_PCT)

    def test_negative_fixtures_hold_only_public_fields(self):
        for p in FIX.glob("*.json"):
            text = p.read_text()
            self.assertNotIn("/Users", text)
            self.assertNotIn("api_key", text.lower())


class CapeRealPayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (FIX / "cape_cohort_fixture.csv").open(newline="") as fh:
            cls.c2 = {r["wallet"] for r in csv.DictReader(fh) if r["group"] == "C2"}

    def big_and_small(self, source):
        # the CAPE wallets were funded about 56 days before the 2026-10-14 09:04 UTC launch
        gm_acq = {r["wallet"]: r["first_acquired_at"] for r in rows("cape", "gmgn") if r["first_acquired_at"]}
        cohorts = hf.run_cohort_source(rows("cape", source), launch_ts=CAPE_LAUNCH, acquisitions=gm_acq if source == "jupiter" else None)["cohorts"]
        big = [c for c in cohorts if c["wallets"] >= hf.COHORT_MIN_WALLETS]
        small = [c for c in cohorts if c["wallets"] < hf.COHORT_MIN_WALLETS]
        return cohorts, big, small

    def test_big_cohort_is_flagged_high_in_both_sources_and_covers_37_farm_wallets(self):
        for source in ("gmgn", "jupiter"):
            cohorts, big, _ = self.big_and_small(source)
            self.assertEqual(len(big), 1, source)
            c = big[0]
            self.assertEqual(c["severity"], hf.VERDICT_HIGH, source)
            self.assertEqual(c["distinct_funders"], 6, source)
            self.assertEqual(len(set(c["members"]) & self.c2), 37, source)

    def test_cape_via_jupiter_alone_with_no_acquisition_data_is_unresolved(self):
        """Jupiter datapi rows carry funding but no acquisition time. With the launch time alone CAPE shows ONE sign
        (dormant 56 days); synchronized buying needs GMGN start_holding_at (or --acquisition-json) and the amounts
        are not similar. One sign is UNRESOLVED; with GMGN acquisition times (test above) it is HIGH."""
        res = hf.run_cohort_source(rows("cape", "jupiter"), launch_ts=CAPE_LAUNCH)["cohorts"]
        big = [c for c in res if c["wallets"] >= hf.COHORT_MIN_WALLETS][0]
        self.assertEqual(list(hf.cohort_signs(big)), ["dormancy"])
        self.assertEqual(big["severity"], hf.VERDICT_UNRESOLVED)
        self.assertIn("one sign only: dormancy", big["severity_reason"])

    def test_cape_gmgn_has_two_signs(self):
        big = hf.run_cohort_source(rows("cape", "gmgn"), launch_ts=CAPE_LAUNCH)["cohorts"][0]
        self.assertEqual(sorted(hf.cohort_signs(big)), ["dormancy", "synchronized acquisition"])

    def test_gmgn_supply_of_the_37_farm_wallets_is_about_15_percent(self):
        by_wallet = {r["wallet"]: r["supply_pct"] for r in rows("cape", "gmgn")}
        self.assertAlmostEqual(sum(by_wallet[w] for w in self.c2 if w in by_wallet and w in {m for m in hf.detect_cohorts(rows("cape", "gmgn"))[0]["members"]}), 15.25, delta=0.3)

    def test_second_small_binance_cohort_is_unresolved_never_high(self):
        for source in ("gmgn", "jupiter"):
            _, _, small = self.big_and_small(source)
            self.assertEqual(len(small), 1, source)
            c = small[0]
            self.assertEqual((c["wallets"], c["distinct_funders"], c["flagged_by"]), (6, 1, "supply"), source)
            self.assertEqual(c["severity"], hf.VERDICT_UNRESOLVED, source)
            self.assertGreater(c["share_pct"], 9.0)

    def test_cape_payloads_end_high_through_assess_and_the_report(self):
        sources = hf.provider_cohort_sources(holders_stub(), load("cape_gmgn.json"), load("cape_jupiter.json"))
        a = hf.assess(holders_stub(), None, provider_cohorts=sources)
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_HIGH)
        md = hf.markdown_report("CAPE", holders_stub(), None, 0, a, sources)
        self.assertIn("severity: UNRESOLVED", md)  # the small Binance cohort is named, not hidden
        self.assertIn("severity: HIGH", md)

    def test_small_cohort_alone_is_unresolved_in_the_verdict(self):
        gm = hf.gmgn_cohort_rows(load("cape_gmgn.json"))
        small_only = [r for r in gm if r["wallet"] not in self.c2]  # drop the farm wallets
        res = hf.run_cohort_source(small_only, launch_ts=None)
        funders = {
            "examined_wallets": 60, "requested_wallets": 60, "failed_wallets": 0, "with_funder": 60, "covered_supply_pct": 70.0, "examined_supply_pct": 70.0, "aborted": None,
            "verdict": {"level": "NOT_DETECTED", "share_pct": 0, "wallets": 0, "batch_funders": 0, "cadence": {}, "reasons": [], "thresholds_are": "x"}, "batches": [], "upstream": [], "cohorts": res,
        }
        self.assertTrue(all(c["severity"] == hf.VERDICT_UNRESOLVED for c in res["cohorts"]))
        a = hf.assess(holders_stub(), funders, [{"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 2.0, "bundle_pct": None, "data_age_min": 1.0}])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_UNRESOLVED)


if __name__ == "__main__":
    unittest.main()
