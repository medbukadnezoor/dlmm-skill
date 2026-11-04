"""HIGH needs a discriminator beyond '20 wallets from 2 funders funded close together' (dormancy, synchronized
buying, or scripted amounts). Otherwise the cohort is UNRESOLVED (funded together, unproven)."""

from __future__ import annotations

import math
import random
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
from test_verdict_gating import funders_dict, holders_dict  # noqa: E402

T0 = 1_760_000_000
H = 3600
DAY = 86400


def row(i, t, funder, pct=0.2, amount=1.0, acquired=None, label=None):
    return {"wallet": f"w{i}", "first_funding_time": t, "funder_address": funder, "funder_label": label, "first_funding_amount": amount, "supply_pct": pct, "first_acquired_at": acquired}


def veil_rows(amounts=None):
    """230 wallets, 12 funders, rounds about 2 minutes apart (VEIL 2026-10-13); each wallet got 2-3 SOL."""
    rng = random.Random(3)
    out = []
    for r in range(12):
        for w in range(19 if r < 11 else 21):
            amt = amounts(rng) if amounts else rng.uniform(2.0, 3.0)
            out.append(row(r * 19 + w, T0 + r * 118 + w * 5, f"VF{r}", pct=0.28, amount=amt))
    assert len(out) == 230
    return out


class DiscriminatorTests(unittest.TestCase):
    """HIGH needs two of three signs: dormancy (7+ days), synchronized acquisition, similar amounts."""

    def source(self, rows, launch=None, acq=None):
        return hf.run_cohort_source(rows, launch_ts=launch, acquisitions=acq)["cohorts"]

    def funders(self, rows, launch, acq=None):
        f = funders_dict(covered=70.0)
        f["cohorts"] = hf.run_cohort_source(rows, launch_ts=launch, acquisitions=acq)
        return f

    def wide_rows(self, n=30, span=H):
        rng = random.Random(5)
        return [row(i, T0 + rng.randrange(span), f"F{i % 6}", pct=0.2, amount=math.exp(rng.gauss(0, 1.5))) for i in range(n)]

    def similar_rows(self, n=30, span=H):
        rng = random.Random(6)
        return [row(i, T0 + rng.randrange(span), f"F{i % 6}", pct=0.2, amount=rng.uniform(2.0, 3.0)) for i in range(n)]

    def sync_acq(self, rows, offset=0):
        return {r["wallet"]: T0 + 2 * H + offset + i * 10 for i, r in enumerate(rows)}  # all inside about 5 minutes of each other

    def test_each_single_sign_is_unresolved_and_names_the_sign_and_the_missing_ones(self):
        cases = {
            "dormancy": (self.wide_rows(), T0 + 30 * DAY, None),
            "synchronized acquisition": (self.wide_rows(), None, "sync"),
            "similar amounts": (self.similar_rows(), None, None),
        }
        for sign, (rows, launch, acq_kind) in cases.items():
            acq = {r["wallet"]: T0 + 2 * H + i * 10 for i, r in enumerate(rows)} if acq_kind else None
            c = self.source(rows, launch=launch, acq=acq)[0]
            self.assertEqual(c["severity"], hf.VERDICT_UNRESOLVED, sign)
            self.assertIn(f"one sign only: {sign}", c["severity_reason"])
            self.assertIn("HIGH needs 2", c["severity_reason"])
            for other in hf.SIGN_NAMES:
                if other != sign:
                    self.assertIn(other, c["severity_reason"].split("missing:")[1], (sign, other))

    def test_each_pair_of_signs_is_high(self):
        rows = self.wide_rows()
        dormant_and_sync = self.source(rows, acq={r["wallet"]: T0 + 10 * DAY + i * 10 for i, r in enumerate(rows)})[0]
        self.assertEqual(dormant_and_sync["severity"], hf.VERDICT_HIGH)
        self.assertIn("dormant 10 days", dormant_and_sync["severity_reason"])
        self.assertIn("bought within", dormant_and_sync["severity_reason"])
        sim = self.similar_rows()
        dormant_and_similar = self.source(sim, launch=T0 + 30 * DAY)[0]
        self.assertEqual(dormant_and_similar["severity"], hf.VERDICT_HIGH)
        sync_and_similar = self.source(sim, acq=self.sync_acq(sim))[0]
        self.assertEqual(sync_and_similar["severity"], hf.VERDICT_HIGH)
        self.assertIn("similar first amounts", sync_and_similar["severity_reason"])

    def test_veil_like_cohort_alone_has_exactly_one_sign_similar_amounts(self):
        """The cohort detector sees VEIL's scripted 2-3 SOL amounts but no dormancy (funded seconds after the pair was
        created) and no narrow acquisition window (12 rounds over about 23 minutes). One sign is UNRESOLVED. The overall
        verdict is HIGH through the funder-batch detector: see test_veil_styles.py."""
        c = self.source(veil_rows(), launch=T0 - 6, acq={r["wallet"]: r["first_funding_time"] for r in veil_rows()})[0]
        self.assertEqual((c["wallets"], c["distinct_funders"], c["severity"]), (230, 12, hf.VERDICT_UNRESOLVED))
        self.assertEqual(list(hf.cohort_signs(c)), ["similar amounts"])
        self.assertFalse(c["acquisition"]["flag"])
        self.assertTrue(all(2.0 <= a <= 3.0 for a in [c["first_amounts"]["min"], c["first_amounts"]["max"]]))

    def test_veil_like_without_amount_similarity_has_no_signs(self):
        rows = veil_rows(amounts=lambda rng: math.exp(rng.gauss(math.log(1.5), 1.4)))
        c = self.source(rows, launch=T0 - 6)[0]
        self.assertFalse(c["first_amounts"]["similar"])
        self.assertEqual(c["severity"], hf.VERDICT_UNRESOLVED)
        self.assertIn("no sign of dormancy, synchronized buying or scripted amounts", c["severity_reason"])
        a = hf.assess(holders_dict(), self.funders(rows, T0 - 6), [])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_UNRESOLVED)
        self.assertIn("no sign of dormancy", " ".join(a["verdict"]["reasons"]))

    def test_funded_after_launch_is_not_dormancy(self):
        rows = self.similar_rows()
        self.assertEqual(self.source(rows, launch=T0 - 600)[0]["severity"], hf.VERDICT_UNRESOLVED)  # similar amounts only
        self.assertEqual(self.source(rows, launch=T0 + 6 * DAY)[0]["severity"], hf.VERDICT_UNRESOLVED)  # 6 days: under the 7 day minimum

    def test_dormant_gap_from_acquisition_times_beats_launch(self):
        rows = self.similar_rows()
        acq = {r["wallet"]: r["first_funding_time"] + 10 * DAY for r in rows}
        self.assertEqual(self.source(rows, launch=T0 - 600, acq=acq)[0]["severity"], hf.VERDICT_HIGH)  # dormant 10 days + similar amounts
        acq_short = {r["wallet"]: r["first_funding_time"] + 2 * H for r in rows}
        # acquisition times exist, so a launch time that makes the gap look long is NOT used
        self.assertEqual(self.source(rows, launch=T0 + 30 * DAY, acq=acq_short)[0]["severity"], hf.VERDICT_UNRESOLVED)

    def test_missing_data_is_unresolved(self):
        self.assertEqual(self.source(self.wide_rows(), launch=None, acq=None)[0]["severity"], hf.VERDICT_UNRESOLVED)

    def test_single_funder_and_supply_route_stay_unresolved_even_with_all_signs(self):
        rows = [row(i, T0 + i, "ONE", amount=1.0) for i in range(30)]
        self.assertEqual(self.source(rows, launch=T0 + 60 * DAY, acq=self.sync_acq(rows))[0]["severity"], hf.VERDICT_UNRESOLVED)
        few = [row(i, T0 + i, f"F{i}", pct=2.0, amount=1.0) for i in range(6)]
        self.assertEqual(self.source(few, launch=T0 + 60 * DAY, acq=self.sync_acq(few))[0]["severity"], hf.VERDICT_UNRESOLVED)

    def test_acquisition_flag_alone_on_a_supply_route_cohort_is_not_high(self):
        few = [row(i, T0 + i, f"F{i}", pct=2.0, amount=1.0) for i in range(12)]
        acq = {r["wallet"]: T0 + DAY + i for i, r in enumerate(few)}
        c = self.source(few, acq=acq)[0]
        self.assertTrue(c["acquisition"]["flag"])
        self.assertEqual(c["severity"], hf.VERDICT_UNRESOLVED)


class OrganicScenarioTests(unittest.TestCase):
    """Seeded organic scenarios that each show ONE sign (or none): never HIGH."""

    def check_never_high(self, rows, launch, acq):
        src = hf.run_cohort_source(rows, launch_ts=launch, acquisitions=acq)
        for c in src["cohorts"]:
            self.assertNotEqual(c["severity"], hf.VERDICT_HIGH, c["severity_reason"])
        f = funders_dict(covered=70.0)
        f["cohorts"] = src
        self.assertNotEqual(hf.assess(holders_dict(), f, []) ["verdict"]["level"], hf.VERDICT_HIGH)
        return src["cohorts"]

    def test_influencer_burst_buys_within_ten_minutes_after_recent_funding(self):
        """Many exchange funders, wide amounts, funded shortly before the call; everyone buys in a 10 minute burst.
        One sign (synchronized acquisition) only."""
        for seed in range(10):
            rng = random.Random(f"burst-{seed}")
            rows = [row(i, T0 + rng.randrange(2 * H), f"EX{rng.randrange(15)}", pct=0.2, amount=math.exp(rng.gauss(math.log(1.5), 1.3)), label="Exchange Hot Wallet") for i in range(120)]
            acq = {r["wallet"]: T0 + 3 * H + rng.randrange(540) for r in rows}
            cohorts = self.check_never_high(rows, T0 + 2 * H, acq)
            self.assertTrue(cohorts and cohorts[0]["acquisition"]["flag"], seed)

    def test_prefunded_community_in_a_burst_with_spread_out_buys(self):
        """Wallets pre-funded 8-30 days before launch in a burst; buys spread over hours. One sign (dormancy) only."""
        for seed in range(10):
            rng = random.Random(f"prefund-{seed}")
            rows = [row(i, T0 + rng.randrange(3 * H), f"EX{rng.randrange(15)}", pct=0.2, amount=math.exp(rng.gauss(math.log(1.5), 1.3))) for i in range(120)]
            launch = T0 + rng.randrange(8 * DAY, 30 * DAY)
            acq = {r["wallet"]: launch + rng.randrange(6 * H) for r in rows}
            cohorts = self.check_never_high(rows, launch, None)  # dormancy from launch time
            self.assertTrue(cohorts and "dormancy" in hf.cohort_signs(cohorts[0]), seed)
            self.check_never_high(rows, launch, acq)

    def test_round_number_amounts_alone(self):
        """Exchange withdrawals of 1 SOL, funded recently, spread-out buys. One sign (similar amounts) only."""
        for seed in range(10):
            rng = random.Random(f"round-{seed}")
            rows = [row(i, T0 + rng.randrange(3 * H), f"EX{rng.randrange(15)}", pct=0.2, amount=1.0, label="Exchange Hot Wallet") for i in range(120)]
            acq = {r["wallet"]: r["first_funding_time"] + rng.randrange(600, 5 * H) for r in rows}
            cohorts = self.check_never_high(rows, T0 + 3 * H, acq)
            self.assertTrue(cohorts and list(hf.cohort_signs(cohorts[0])) == ["similar amounts"], seed)


class OrganicLaunchMonteCarloTests(unittest.TestCase):
    """Seeded, deterministic Monte Carlo of ORGANIC young launches. Assumptions: 250 holders; Pareto-like shares
    (1/rank) normalised to 60% of supply; first-funding times uniform over a span of 1 h, 6 h, 24 h, 3 d or 7 d;
    15 exchange-like funders (labeled, chosen at random); wide-ranging first amounts (lognormal, median 1.5 SOL,
    sigma 1.3); each wallet acquires the token 1 minute to 3 hours after its own funding; the first pair is created
    5 minutes after the earliest funding. None of this is a scripted farm, so no run may end HIGH (UNRESOLVED is
    allowed: funded together, unproven)."""

    SPANS = {"1h": H, "6h": 6 * H, "24h": 24 * H, "3d": 3 * DAY, "7d": 7 * DAY}

    def launch_rows(self, rng, span):
        weights = [1.0 / (rank + 1) for rank in range(250)]
        total = sum(weights)
        rows = []
        for i in range(250):
            t = T0 + rng.randrange(span)
            rows.append(row(i, t, f"EX{rng.randrange(15)}", pct=weights[i] / total * 60.0, amount=math.exp(rng.gauss(math.log(1.5), 1.3)),
                            acquired=t + rng.randrange(60, 3 * H), label="Exchange Hot Wallet"))
        rng.shuffle(rows)
        return rows

    def test_organic_young_launches_never_end_high(self):
        flagged_runs = 0
        for name, span in self.SPANS.items():
            for seed in range(20):
                rng = random.Random(f"{name}-{seed}")
                rows = self.launch_rows(rng, span)
                launch = min(r["first_funding_time"] for r in rows) + 300
                src = hf.run_cohort_source(rows, launch_ts=launch)
                acq = {r["wallet"]: r["first_acquired_at"] for r in rows}
                src_acq = hf.run_cohort_source(rows, launch_ts=launch, acquisitions=acq)
                for res in (src, src_acq):
                    flagged_runs += bool(res["cohorts"])
                    for c in res["cohorts"]:
                        self.assertNotEqual(c["severity"], hf.VERDICT_HIGH, (name, seed, c["wallets"], c["distinct_funders"], c["severity_reason"]))
                f = funders_dict(covered=70.0)
                f["cohorts"] = src_acq
                self.assertNotEqual(hf.assess(holders_dict(), f, [])["verdict"]["level"], hf.VERDICT_HIGH, (name, seed))
        self.assertGreater(flagged_runs, 100)  # the test is not vacuous: short spans do get flagged, as UNRESOLVED


if __name__ == "__main__":
    unittest.main()
