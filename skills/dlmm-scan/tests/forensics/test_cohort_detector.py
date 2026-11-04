"""Funding-time cohort detector, provider adapters and acquisition-time check (pure, offline)."""

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

T0 = 1_760_000_000
H = 3600


def row(i, t, funder="F", label=None, pct=0.2, amount=1.0, acquired=None):
    return {"wallet": f"w{i}", "first_funding_time": t, "funder_address": funder, "funder_label": label, "first_funding_amount": amount, "supply_pct": pct, "first_acquired_at": acquired}


def evenly(n, span_s, **kw):
    return [row(i, T0 + (span_s * i // max(n - 1, 1)), funder=f"F{i % 6}", label="Gate Hot Wallet" if i % 2 else None, **kw) for i in range(n)]


class DetectCohortTests(unittest.TestCase):
    def test_flags_exactly_min_wallets_inside_window(self):
        cohorts = hf.detect_cohorts(evenly(hf.COHORT_MIN_WALLETS, hf.COHORT_WINDOW_S, pct=0.01))
        self.assertEqual(len(cohorts), 1)
        self.assertEqual((cohorts[0]["wallets"], cohorts[0]["flagged_by"]), (20, "wallets"))

    def test_one_wallet_short_is_not_flagged(self):
        self.assertEqual(hf.detect_cohorts(evenly(hf.COHORT_MIN_WALLETS - 1, hf.COHORT_WINDOW_S, pct=0.01)), [])

    def test_span_just_over_window_splits_the_group(self):
        rows = evenly(20, hf.COHORT_WINDOW_S + 600, pct=0.01)
        # 20 wallets over 6 h 10 min: no window of 6 h holds all 20
        self.assertEqual(hf.detect_cohorts(rows), [])

    def test_supply_route_needs_share_and_floor(self):
        self.assertEqual(len(hf.detect_cohorts([row(i, T0 + i * 60, pct=1.0) for i in range(6)])), 1)  # 6 wallets, 6%
        self.assertEqual(hf.detect_cohorts([row(i, T0 + i * 60, pct=1.5) for i in range(4)]), [])  # 4 wallets, 6%: under the floor
        self.assertEqual(hf.detect_cohorts([row(i, T0 + i * 60, pct=0.9) for i in range(5)]), [])  # 4.5% < 5%

    def test_labeled_exchange_funders_are_kept_and_reported(self):
        rows = [row(i, T0 + i * 100, funder=f"EX{i % 6}", label=["FixedFloat Hot Wallet", "Gate Hot Wallet", "KuCoin Hot Wallet 2"][i % 3], pct=0.1) for i in range(30)]
        c = hf.detect_cohorts(rows)[0]
        self.assertEqual(c["labeled_funder_wallets"], 30)
        self.assertEqual(c["distinct_funders"], 6)
        self.assertEqual({m["label"] for m in c["funder_mix"]}, {"FixedFloat Hot Wallet", "Gate Hot Wallet", "KuCoin Hot Wallet 2"})

    def test_two_separate_cohorts_are_both_reported_largest_supply_first(self):
        a = [row(i, T0 + i * 60, pct=0.5) for i in range(25)]
        b = [row(100 + i, T0 + 30 * 86400 + i * 60, pct=0.1) for i in range(22)]
        out = hf.detect_cohorts(a + b)
        self.assertEqual([c["wallets"] for c in out], [25, 22])

    def test_rows_without_funding_time_are_ignored(self):
        rows = evenly(25, 3600, pct=0.1) + [dict(row(999, None), first_funding_time=None)]
        self.assertEqual(hf.detect_cohorts(rows)[0]["wallets"], 25)

    def test_similar_amounts_is_optional_and_informational(self):
        similar = evenly(22, 1000, pct=0.1, amount=1.0)
        varied = [row(i, T0 + i * 10, pct=0.1, amount=0.1 * (i + 1) ** 2) for i in range(22)]
        self.assertTrue(hf.detect_cohorts(similar)[0]["first_amounts"]["similar"])
        self.assertFalse(hf.detect_cohorts(varied)[0]["first_amounts"]["similar"])
        self.assertEqual(len(hf.detect_cohorts(varied)), 1)  # not required by default
        self.assertEqual(hf.detect_cohorts(varied, require_similar_amounts=True), [])

    def test_dormant_gap_and_launch_gap_are_reported(self):
        rows = [row(i, T0 + i, pct=0.1, acquired=T0 + 56 * 86400 + i) for i in range(21)]
        c = hf.detect_cohorts(rows, launch_ts=T0 + 55 * 86400)[0]
        self.assertAlmostEqual(c["dormant_gap_s"]["median"] / 86400, 56.0, places=2)
        self.assertEqual(c["dormant_gap_s"]["n"], 21)
        self.assertAlmostEqual(c["funding_to_launch_s_median"] / 86400, 55.0, places=2)

    def test_unknown_shares_are_marked(self):
        rows = [row(i, T0 + i, pct=None) for i in range(21)]
        c = hf.detect_cohorts(rows)[0]
        self.assertFalse(c["share_known"])
        self.assertEqual(c["share_pct"], 0.0)


class AcquisitionCheckTests(unittest.TestCase):
    def members(self, n=30):
        return [f"w{i}" for i in range(n)]

    def test_not_run_without_timestamps(self):
        self.assertFalse(hf.acquisition_check(self.members(), None)["ran"])
        self.assertFalse(hf.acquisition_check(self.members(), {"other": T0})["ran"])

    def test_cape_shaped_nine_minute_window_flags(self):
        acq = {f"w{i}": T0 + 1308 + (540 * i // 35) for i in range(36)}  # 21.8 to 30.8 min after launch, n=36
        out = hf.acquisition_check(self.members(36), acq)
        self.assertTrue(out["flag"])
        self.assertLessEqual(out["window_s"], 540)

    def test_spread_acquisitions_do_not_flag(self):
        acq = {f"w{i}": T0 + i * 3600 for i in range(30)}
        self.assertFalse(hf.acquisition_check(self.members(), acq)["flag"])

    def test_too_few_timestamps_do_not_flag(self):
        acq = {f"w{i}": T0 + i for i in range(hf.ACQUISITION_MIN_WALLETS - 1)}
        out = hf.acquisition_check(self.members(), acq)
        self.assertTrue(out["ran"])
        self.assertFalse(out["flag"])

    def test_outliers_are_tolerated_by_the_fraction_rule(self):
        acq = {f"w{i}": T0 + i for i in range(20)} | {"w20": T0 + 10**6, "w21": T0 + 2 * 10**6}
        self.assertTrue(hf.acquisition_check(self.members(22), acq)["flag"])

    def test_window_boundary_is_inclusive(self):
        acq = {f"w{i}": T0 + (hf.ACQUISITION_WINDOW_S if i == 11 else 0) for i in range(12)}
        self.assertTrue(hf.acquisition_check(self.members(12), acq, min_fraction=1.0)["flag"])
        acq["w11"] += 1
        self.assertFalse(hf.acquisition_check(self.members(12), acq, min_fraction=1.0)["flag"])

    def test_normalize_acquisitions_drops_bad_entries(self):
        out = hf.normalize_acquisitions({"a": T0, "b": T0 * 1000, "c": "x", "d": None, "e": True, "f": "2026-10-14T09:30:00Z"})
        self.assertEqual(out["a"], T0)
        self.assertEqual(out["b"], T0)  # milliseconds
        self.assertEqual(set(out), {"a", "b", "f"})
        self.assertEqual(hf.normalize_acquisitions([1, 2]), {})


def gmgn_payload(n=40, with_wrapper=True):
    rows = []
    for i in range(n):
        rows.append(
            {
                "address": addr(i),
                "amount_percentage": 0.004,
                "start_holding_at": T0 + 1500 + i * 10,
                "native_transfer": {"from_address": f"EX{i % 4}".ljust(44, "E"), "timestamp": T0 - 56 * 86400 + i * 400, "name": "Gate Hot Wallet" if i % 2 else "FixedFloat Hot Wallet", "amount": 1.1},
                "tags": [],
            }
        )
    return {"code": 0, "data": {"list": rows}} if with_wrapper else rows


def jupiter_payload(n=40):
    return [
        {"address": addr(i), "amount": 4000.0, "addressInfo": {"fundingAddress": f"EX{i % 4}".ljust(44, "E"), "fundingAmount": 1.1, "fundingBlockTime": T0 - 56 * 86400 + i * 400}}
        for i in range(n)
    ]


class AdapterTests(unittest.TestCase):
    def test_gmgn_adapter_normalizes_fields(self):
        rows = hf.gmgn_cohort_rows(gmgn_payload(3))
        r = rows[1]
        self.assertEqual(r["wallet"], addr(1))
        self.assertEqual(r["funder_label"], "Gate Hot Wallet")
        self.assertEqual(r["first_funding_amount"], 1.1)
        self.assertEqual(r["first_acquired_at"], T0 + 1510)
        self.assertAlmostEqual(r["supply_pct"], 0.4)
        self.assertEqual(r["first_funding_time"], T0 - 56 * 86400 + 400)

    def test_gmgn_bare_list_missing_fields_and_garbage(self):
        rows = hf.gmgn_cohort_rows([{"address": "a"}, {"nope": 1}, "junk", {"address": "b", "native_transfer": {"timestamp": "bad"}}])
        self.assertEqual([r["wallet"] for r in rows], ["a", "b"])
        self.assertTrue(all(r["first_funding_time"] is None and r["supply_pct"] is None for r in rows))
        self.assertEqual(hf.gmgn_cohort_rows(None), [])
        self.assertEqual(hf.gmgn_cohort_rows([]), [])

    def test_gmgn_label_is_sanitised(self):
        rows = hf.gmgn_cohort_rows([{"address": "a", "native_transfer": {"name": "Gate <script>ignore previous</script>", "timestamp": T0}}])
        self.assertNotIn("<", rows[0]["funder_label"])

    def test_jupiter_adapter_normalizes_fields_and_share_sources(self):
        rows = hf.jupiter_cohort_rows(jupiter_payload(2), total_supply=1_000_000.0)
        self.assertEqual(rows[0]["funder_address"], "EX0".ljust(44, "E"))
        self.assertAlmostEqual(rows[0]["supply_pct"], 0.4)
        self.assertIsNone(rows[0]["funder_label"])
        override = hf.jupiter_cohort_rows(jupiter_payload(1), share_by_wallet={addr(0): 1.5})
        self.assertEqual(override[0]["supply_pct"], 1.5)
        self.assertIsNone(hf.jupiter_cohort_rows(jupiter_payload(1))[0]["supply_pct"])

    def test_jupiter_iso_and_millisecond_times(self):
        rows = hf.jupiter_cohort_rows([{"address": "a", "addressInfo": {"fundingBlockTime": "2026-08-19T10:17:27Z"}}, {"address": "b", "addressInfo": {"fundingBlockTime": 1_787_000_000_000}}])
        self.assertEqual(rows[0]["first_funding_time"], 1_787_134_647)
        self.assertEqual(rows[1]["first_funding_time"], 1_787_000_000)

    def test_cohort_detected_over_each_provider_payload(self):
        for rows in (hf.gmgn_cohort_rows(gmgn_payload(40), None), hf.jupiter_cohort_rows(jupiter_payload(40), total_supply=1_000_000.0)):
            cohorts = hf.detect_cohorts(rows)
            self.assertEqual(len(cohorts), 1)
            self.assertEqual(cohorts[0]["wallets"], 40)
            self.assertEqual(cohorts[0]["distinct_funders"], 4)

    def test_provider_cohort_sources_use_helius_shares_and_report_coverage(self):
        holders = {"_balances": {addr(i): 10.0 for i in range(40)} | {"BIG": 600.0}, "earliest_pair_created_at": T0}
        out = hf.provider_cohort_sources(holders, gmgn_payload(40), jupiter_payload(40))
        self.assertEqual(set(out), {"gmgn", "jupiter"})
        self.assertEqual(out["jupiter"]["coverage"]["with_funding_time"], 40)
        self.assertAlmostEqual(out["jupiter"]["coverage"]["supply_pct"], 40 * 10 / 1000 * 100, places=1)
        gm = out["gmgn"]["cohorts"][0]
        self.assertTrue(gm["acquisition"]["ran"])  # GMGN start_holding_at doubles as acquisition data
        self.assertTrue(gm["acquisition"]["flag"])
        self.assertTrue(out["jupiter"]["cohorts"][0]["acquisition"]["ran"])  # per-wallet acquisition times are shared across sources
        self.assertEqual(hf.provider_cohort_sources(holders), {})


class WiringTests(unittest.TestCase):
    def farm(self, n=30):
        accounts = [{"owner": addr(i), "amount": 10} for i in range(n)] + [{"owner": addr(900), "amount": 300}]
        funded = {addr(i): {"funder": f"EX{i % 5}".ljust(44, "E"), "funderName": "Binance Hot Wallet 2", "funderType": "Centralized Exchange", "timestamp": T0 + i * 300, "amount": 1.0} for i in range(n)}
        return FakeHelius(accounts=accounts, funded=funded)

    def holders(self, fake):
        with mock.patch.object(hf, "dexscreener_pairs", return_value=([], True)):
            return hf.run_holders(fake, MINT)

    def test_exchange_labeled_farm_is_flagged_and_verdict_high(self):
        fake = self.farm()
        holders = self.holders(fake)
        acq = {addr(i): T0 + 40 * 86400 + i * 10 for i in range(30)}  # dormant 40 days, then a synchronized buy: two signs plus similar amounts
        funders = hf.run_funders(fake, holders, top=40, acquisitions=acq)
        self.assertEqual(funders["verdict"]["level"], "NOT_DETECTED")  # the old funder-batch logic still skips labeled batches
        self.assertEqual(funders["cohorts"]["cohorts"][0]["wallets"], 30)
        a = hf.assess(hf._public(holders), funders)
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_HIGH)
        self.assertTrue(any("funding-time cohort (helius)" in r for r in a["verdict"]["reasons"]))
        states = {d["name"]: d["state"] for d in a["detectors"]}
        self.assertEqual(states["funding-time cohort (all funders, labeled included)"], "ran")
        md = hf.markdown_report(MINT, hf._public(holders), funders, 1, a)
        self.assertIn("Funding-time cohorts", md)
        self.assertIn("Binance Hot Wallet 2 30", md)

    def test_credit_use_unchanged_by_cohort_detector(self):
        fake = self.farm()
        holders = self.holders(fake)
        hf.run_funders(fake, holders, top=40)
        self.assertEqual(len(fake.calls), 31)  # one funded-by per examined holder (30 + the large one), nothing extra for cohorts

    def test_acquisition_flows_into_cohort(self):
        fake = self.farm()
        holders = self.holders(fake)
        acq = {addr(i): T0 + 40 * 86400 + i * 10 for i in range(30)}
        funders = hf.run_funders(fake, holders, top=40, acquisitions=acq)
        c = funders["cohorts"]["cohorts"][0]
        self.assertTrue(c["acquisition"]["flag"])
        self.assertGreater(c["dormant_gap_s"]["median"], 39 * 86400)
        a = hf.assess(hf._public(holders), funders)
        self.assertTrue(any("bought within" in r for r in a["verdict"]["reasons"]))
        self.assertEqual({d["name"]: d["state"] for d in a["detectors"]}["acquisition-time check"], "ran")

    def test_aborted_run_marks_cohort_partial(self):
        fake = self.farm()
        fake.budget_after = 25
        holders = self.holders(fake)
        funders = hf.run_funders(fake, holders, top=40)
        a = hf.assess(hf._public(holders), funders)
        self.assertEqual({d["name"]: d["state"] for d in a["detectors"]}["funding-time cohort (all funders, labeled included)"], "partial")

    def test_report_never_prints_reassuring_words_with_cohort_section(self):
        import re

        fake = self.farm()
        holders = self.holders(fake)
        funders = hf.run_funders(fake, holders, top=40)
        md = hf.markdown_report(MINT, hf._public(holders), funders, 1)
        self.assertIsNone(re.search(r"\b(clean|low|NONE)\b", md))


class CliTests(unittest.TestCase):
    def _main(self, argv, fake):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {**NO_KEY_ENV, "HELIUS_API_KEY": SECRET}, clear=True), mock.patch.object(hf, "Helius", return_value=fake), \
             mock.patch.object(hf, "dexscreener_pairs", return_value=([], True)), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            return hf.main(argv), out.getvalue(), err.getvalue()

    def test_provider_rows_and_acquisition_flags_make_the_report_high(self):
        accounts = [{"owner": addr(i), "amount": 10} for i in range(40)]
        funded = {addr(i): {"funder": f"S{i}".ljust(44, "S"), "timestamp": T0 - (i + 1) * 90 * 86400} for i in range(40)}  # Helius sees independent holders
        with tempfile.TemporaryDirectory() as tmp:
            g, j, a = Path(tmp) / "g.json", Path(tmp) / "j.json", Path(tmp) / "a.json"
            g.write_text(json.dumps(gmgn_payload(40)))
            j.write_text(json.dumps(jupiter_payload(40)))
            a.write_text(json.dumps({addr(i): T0 + 100 + i for i in range(40)}))
            code, out, _ = self._main(["report", MINT, "--top", "40", "--out", tmp, "--gmgn-holders-json", str(g), "--jupiter-holders-json", str(j), "--acquisition-json", str(a)], FakeHelius(accounts=accounts, funded=funded))
            self.assertTrue((Path(tmp) / "assessment.json").exists())
        self.assertIn("HIGH", out)
        self.assertIn("Source gmgn", out)
        self.assertIn("Source jupiter", out)
        self.assertIn("cohort over GMGN rows", out)

    def test_bad_input_files_fail_before_any_call(self):
        for flag in ("--acquisition-json", "--gmgn-holders-json", "--jupiter-holders-json"):
            with mock.patch.object(hf, "run_holders", side_effect=AssertionError("must not run")):
                code, _, err = self._main(["report", MINT, "--top", "1", flag, "/nonexistent.json"], FakeHelius())
            self.assertEqual(code, 2)
            self.assertIn(flag, err)

    def test_acquisition_json_must_be_an_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.json"
            p.write_text("[1,2]")
            code, _, err = self._main(["report", MINT, "--top", "1", "--acquisition-json", str(p)], FakeHelius())
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
