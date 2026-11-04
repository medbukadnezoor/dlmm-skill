"""Two farm styles, two detectors (offline, synthetic, shaped like the real VEIL story of 2026-10-13).

VEIL: about 230 wallets, 12 funders about 2 minutes apart starting ~6 s after the pair was created; each wallet got
2-3 SOL and bought the same second. The cohort detector sees ONE sign only (similar amounts): no dormancy (funded
after launch) and no narrow acquisition window (12 rounds spread over about 23 minutes). The funder-batch detector
sees 12 unlabeled funders each feeding 19-21 wallets within about 100 s: FACTORY_PATTERN STRONG. So the overall
verdict is HIGH through the funder-batch path. The cohort detector's job is the CAPE style (exchange-funded, dormant,
synchronized buying), the funder-batch detector's job is the VEIL style (unlabeled scripted funders).

KNOWN LIMIT: the same VEIL-style pattern funded DIRECTLY through labeled exchanges defeats the funder-batch detector
(labeled batches are ignored) and shows only one cohort sign, so it reads UNRESOLVED, never HIGH and never NO_ALARM.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
from test_cohort_discriminators import T0, veil_rows  # noqa: E402
from test_cape_regression import holders_dict  # noqa: E402

LAUNCH = T0 - 6  # the pair was created 6 seconds before the first funding round


def run_style(labeled: bool):
    rows = veil_rows()
    acq = {r["wallet"]: r["first_funding_time"] for r in rows}  # each wallet bought the same second it was funded
    recs = [
        {"wallet": r["wallet"], "share_pct": r["supply_pct"], "funder": r["funder_address"], "funder_name": "Exchange Hot Wallet" if labeled else None, "funder_type": None,
         "funded_at": r["first_funding_time"], "first_amount_sol": r["first_funding_amount"]}
        for r in rows
    ]
    batches = hf.detect_batches(recs)
    funders = {
        "examined_wallets": 230, "requested_wallets": 230, "failed_wallets": 0, "with_funder": 230, "covered_supply_pct": 64.4, "examined_supply_pct": 64.4, "aborted": None,
        "verdict": hf.classify(batches, LAUNCH), "batches": [{k: v for k, v in b.items() if k != "members"} for b in batches], "upstream": [],
        "cohorts": hf.run_cohort_source(hf.helius_cohort_rows(recs, acq), launch_ts=LAUNCH, acquisitions=acq),
    }
    return funders


def quiet_map():
    return {"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 2.0, "bundle_pct": None, "data_age_min": 1.0}


class VeilStyleTests(unittest.TestCase):
    def test_veil_end_to_end_cohort_unresolved_but_verdict_high_via_funder_batch(self):
        f = run_style(labeled=False)
        cohort = f["cohorts"]["cohorts"][0]
        self.assertEqual((cohort["wallets"], cohort["distinct_funders"]), (230, 12))
        self.assertEqual(cohort["severity"], hf.VERDICT_UNRESOLVED)
        self.assertEqual(list(hf.cohort_signs(cohort)), ["similar amounts"])  # exactly one sign
        self.assertIn("one sign only: similar amounts", cohort["severity_reason"])
        self.assertEqual(f["verdict"]["level"], "STRONG")
        a = hf.assess(holders_dict(launch=LAUNCH), f, [quiet_map()])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_HIGH)
        text = " ".join(a["verdict"]["reasons"])
        self.assertIn("FACTORY_PATTERN STRONG", text)
        self.assertIn("one sign only", text)  # the cohort is still named, as unresolved

    def test_veil_style_funded_directly_through_labeled_exchanges_is_unresolved_known_limit(self):
        f = run_style(labeled=True)
        self.assertEqual(f["verdict"]["level"], "NOT_DETECTED")  # labeled batches are ignored by the funder-batch detector
        cohort = f["cohorts"]["cohorts"][0]
        self.assertEqual(cohort["severity"], hf.VERDICT_UNRESOLVED)
        self.assertEqual(cohort["labeled_funder_wallets"], 230)
        a = hf.assess(holders_dict(launch=LAUNCH), f, [quiet_map()])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_UNRESOLVED)
        self.assertNotEqual(a["verdict"]["level"], hf.VERDICT_NO_ALARM)
        md = hf.markdown_report("VEIL", holders_dict(launch=LAUNCH), f, 0, a)
        self.assertIn("UNRESOLVED", md)
        self.assertIsNone(re.search(r"\b(clean|low|NONE)\b", md))
        self.assertIn("What to do next", md)

    def test_labeled_variant_without_any_cohort_data_would_not_be_unresolved(self):
        """Control: if the cohort detector did not run at all, the same labeled data is merely LIMITED, so the
        UNRESOLVED above comes from the cohort detector and not from the missing pieces."""
        f = run_style(labeled=True)
        f = {k: v for k, v in f.items() if k != "cohorts"}
        a = hf.assess(holders_dict(launch=LAUNCH), f, [quiet_map()])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)


if __name__ == "__main__":
    unittest.main()
