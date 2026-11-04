"""NO_ALARM gate hardening: truncated lists, unreliable pool exclusion, explicit units, aggregate cluster alarm."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
from test_holder_forensics import MINT  # noqa: E402
from test_verdict_gating import funders_dict, holders_dict, ran  # noqa: E402


def quiet_map():
    return {"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 2.0, "bundle_pct": None, "data_age_min": 1.0}


def funders_with_cohort(**kw):
    f = funders_dict(**kw)
    f["cohorts"] = {"coverage": {"rows": 100, "with_funding_time": 100, "supply_pct": 80.0, "share_known_for": 100}, "cohorts": []}
    return f


class BaselineTests(unittest.TestCase):
    def test_baseline_reaches_no_alarm(self):
        a = hf.assess(holders_dict(), funders_with_cohort(), [quiet_map()])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_NO_ALARM)


class TruncationAndPoolTests(unittest.TestCase):
    def test_truncated_holder_list_blocks_no_alarm(self):
        h = holders_dict()
        h["truncated"] = True
        a = hf.assess(h, funders_with_cohort(), [quiet_map()])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)
        self.assertTrue(any("truncated" in r for r in a["verdict"]["reasons"]))
        self.assertIn("TRUNCATED", hf.markdown_report(MINT, h, funders_with_cohort(), 1, a))

    def test_unmatched_pool_blocks_no_alarm_and_does_not_inflate_coverage(self):
        h = holders_dict(infra=0.0)
        h["warnings"] = ["no pool owner matched the holder list; pools may be counted as holders (use --exclude ADDRESS)"]
        cov = hf.coverage_block(h, funders_dict(covered=70.0))
        self.assertFalse(cov["pool_exclusion_reliable"])
        a = hf.assess(h, funders_with_cohort(covered=70.0), [quiet_map()])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)
        self.assertTrue(any("pool exclusion unreliable" in r for r in a["verdict"]["reasons"]))
        self.assertIn("Pool exclusion unreliable", hf.markdown_report(MINT, h, funders_with_cohort(covered=70.0), 1, a))

    def test_failed_dexscreener_lookup_blocks_no_alarm_and_coverage_uses_total_supply(self):
        h = holders_dict(infra=50.0)  # a (possibly wrong) infrastructure share must not shrink the denominator
        h["warnings"] = ["Dexscreener lookup failed: pool exclusion and launch time are unknown"]
        cov = hf.coverage_block(h, funders_dict(covered=35.0))
        self.assertEqual(cov["covered_noninfra_pct"], 35.0)
        self.assertEqual(hf.assess(h, funders_with_cohort(covered=70.0), [quiet_map()])["verdict"]["level"], hf.VERDICT_LIMITED)

    def test_reliable_pool_still_uses_the_ordinary_wallet_basis(self):
        self.assertEqual(hf.coverage_block(holders_dict(infra=50.0), funders_dict(covered=35.0))["covered_noninfra_pct"], 70.0)


class UnitTests(unittest.TestCase):
    def test_fraction_unit_is_converted(self):
        f = hf.normalize_finding({"provider": "p", "status": "ok", "largest_cluster_pct": 0.25, "cluster_sum_pct": 0.4, "bundle_pct": 0.1, "unit": "fraction"})
        self.assertEqual((f["largest_cluster_pct"], f["cluster_sum_pct"], f["bundle_pct"]), (25.0, 40.0, 10.0))

    def test_fraction_out_of_range_is_rejected(self):
        with self.assertRaises(hf.ConfigError):
            hf.normalize_finding({"provider": "p", "status": "ok", "largest_cluster_pct": 25, "unit": "fraction"})

    def test_ambiguous_file_is_rejected(self):
        with self.assertRaises(hf.ConfigError) as ctx:
            hf.normalize_findings_file([{"provider": "p", "status": "ok", "largest_cluster_pct": 0.3, "bundle_pct": 0.5}])
        self.assertIn("ambiguous", str(ctx.exception))

    def test_file_level_and_row_level_units_resolve_the_ambiguity(self):
        rows = [{"provider": "p", "status": "ok", "largest_cluster_pct": 0.3}]
        self.assertEqual(hf.normalize_findings_file({"unit": "fraction", "providers": rows})[0]["largest_cluster_pct"], 30.0)
        self.assertEqual(hf.normalize_findings_file({"unit": "percent", "providers": rows})[0]["largest_cluster_pct"], 0.3)
        self.assertEqual(hf.normalize_findings_file([{**rows[0], "unit": "fraction"}])[0]["largest_cluster_pct"], 30.0)

    def test_values_above_one_without_unit_are_percent_and_zero_is_unit_free(self):
        out = hf.normalize_findings_file([{"provider": "p", "status": "ok", "largest_cluster_pct": 25.0}, {"provider": "q", "status": "empty", "largest_cluster_pct": 0.0}])
        self.assertEqual([f["largest_cluster_pct"] for f in out], [25.0, 0.0])

    def test_mixed_units_are_rejected_even_when_other_values_exceed_one(self):
        for row in (
            {"provider": "p", "status": "ok", "largest_cluster_pct": 25.0, "bundle_pct": 0.5},  # one field fraction-looking, one percent
            {"provider": "p", "status": "ok", "largest_cluster_pct": 0.3},
        ):
            with self.assertRaises(hf.ConfigError, msg=repr(row)):
                hf.normalize_findings_file([row])
        with self.assertRaises(hf.ConfigError):  # one clear row does not excuse an ambiguous one
            hf.normalize_findings_file([{"provider": "a", "status": "ok", "largest_cluster_pct": 25.0}, {"provider": "b", "status": "ok", "bundle_pct": 0.5}])

    def test_explicit_unit_makes_small_values_fine(self):
        out = hf.normalize_findings_file([{"provider": "a", "status": "ok", "largest_cluster_pct": 25.0, "bundle_pct": 0.5, "unit": "percent"}])
        self.assertEqual(out[0]["bundle_pct"], 0.5)

    def test_bad_file_unit_and_shape_are_rejected(self):
        with self.assertRaises(hf.ConfigError):
            hf.normalize_findings_file({"unit": "bps", "providers": []})
        with self.assertRaises(hf.ConfigError):
            hf.normalize_findings_file({"providers": "x"})


class AggregateClusterTests(unittest.TestCase):
    def map_json(self, shares):
        return {"mint": MINT, "parse_ok": True, "age_min_after": 1.0, "clusters": [{"cluster": i, "wallets": 9, "supply_pct": p} for i, p in enumerate(shares)]}

    def test_two_ten_percent_clusters_plus_others_over_the_aggregate_bar_alarm(self):
        f = hf.bubblemaps_finding(self.map_json([10.0, 10.0, 5.0, 5.0]), MINT)
        self.assertEqual(f["largest_cluster_pct"], 10.0)
        self.assertEqual(f["cluster_sum_pct"], 30.0)
        self.assertTrue(hf.finding_alarms(f))
        a = hf.assess(holders_dict(), None, [f])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_HIGH)

    def test_cape_cluster_list_alarms_on_the_sum(self):
        f = hf.bubblemaps_finding(self.map_json([25.45, 17.44, 1.02]), MINT)
        self.assertAlmostEqual(f["cluster_sum_pct"], 43.91)

    def test_just_under_the_aggregate_bar_does_not_alarm(self):
        f = hf.bubblemaps_finding(self.map_json([10.0, 10.0, 9.9]), MINT)
        self.assertEqual(hf.finding_alarms(f), [])

    def test_provider_row_with_sum_alarms_even_when_largest_is_small(self):
        f = hf.normalize_finding({"provider": "x", "status": "ok", "largest_cluster_pct": 10, "cluster_sum_pct": 31, "unit": "percent"})
        self.assertIn("clusters together", hf.finding_alarms(f)[0])

    def test_sum_in_a_non_ok_finding_never_alarms(self):
        f = hf.normalize_finding({"provider": "x", "status": "empty", "cluster_sum_pct": 90, "unit": "percent"})
        self.assertEqual(hf.finding_alarms(f), [])



class ProviderNameTests(unittest.TestCase):
    def test_duplicate_names_within_the_file_are_rejected(self):
        rows = [{"provider": "gmgn", "status": "ok", "largest_cluster_pct": 30.0}, {"provider": "GMGN", "status": "ok", "largest_cluster_pct": 5.0}]
        with self.assertRaises(hf.ConfigError) as ctx:
            hf.normalize_findings_file(rows)
        self.assertIn("twice", str(ctx.exception))

    def test_bubblemaps_map_name_is_reserved_for_the_map_step(self):
        for name in ("bubblemaps_map", "Bubblemaps_Map"):
            with self.assertRaises(hf.ConfigError) as ctx:
                hf.normalize_findings_file([{"provider": name, "status": "ok", "largest_cluster_pct": 1.0, "unit": "percent", "data_age_min": 0}])
            self.assertIn("reserved", str(ctx.exception))

    def test_self_declared_map_cannot_fake_the_required_step_end_to_end(self):
        import contextlib, io, json, os, tempfile
        from unittest import mock
        from test_holder_forensics import NO_KEY_ENV, SECRET, FakeHelius
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {**NO_KEY_ENV, "HELIUS_API_KEY": SECRET}, clear=True), \
             mock.patch.object(hf, "run_holders", side_effect=AssertionError("must not run")), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            p = Path(tmp) / "p.json"
            p.write_text(json.dumps([{"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 1.0, "unit": "percent", "data_age_min": 0}]))
            code = hf.main(["report", MINT, "--top", "1", "--providers-json", str(p)])
        self.assertEqual(code, 2)
        self.assertIn("reserved", err.getvalue())

    def test_duplicate_between_bubblemaps_json_and_providers_json_is_rejected(self):
        import argparse, json, tempfile
        with tempfile.TemporaryDirectory() as tmp:
            m, p = Path(tmp) / "m.json", Path(tmp) / "p.json"
            m.write_text(json.dumps({"mint": MINT, "parse_ok": True, "age_min_after": 1.0, "clusters": [{"supply_pct": 30.0}]}))
            p.write_text(json.dumps([{"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 1.0, "unit": "percent"}]))
            args = argparse.Namespace(bubblemaps_json=str(m), providers_json=str(p))
            with self.assertRaises(hf.ConfigError):
                hf.load_findings(args, MINT)
            # a non-reserved clash is also rejected: a provider name used by both inputs
            p.write_text(json.dumps([{"provider": "other", "status": "ok", "largest_cluster_pct": 1.0, "unit": "percent"}]))
            self.assertEqual([f["provider"] for f in hf.load_findings(args, MINT)], ["bubblemaps_map", "other"])




class FieldIntegrityTests(unittest.TestCase):
    """A present but unreadable or out-of-range field rejects the input; it must never read as 'no alarm'."""

    def check_rejects(self, row, file_unit=None):
        data = {"unit": file_unit, "providers": [row]} if file_unit else [row]
        with self.assertRaises(hf.ConfigError, msg=repr(row)):
            hf.normalize_findings_file(data)

    def test_out_of_range_for_the_unit(self):
        self.check_rejects({"provider": "p", "status": "ok", "unit": "fraction", "largest_cluster_pct": 0.01, "cluster_sum_pct": 45})
        self.check_rejects({"provider": "p", "status": "ok", "unit": "fraction", "largest_cluster_pct": 0.01, "bundle_pct": 45})
        self.check_rejects({"provider": "p", "status": "ok", "unit": "percent", "largest_cluster_pct": 1, "cluster_sum_pct": 450})
        self.check_rejects({"provider": "p", "status": "ok", "unit": "percent", "largest_cluster_pct": 1, "cluster_sum_pct": -45})

    def test_non_numeric_values(self):
        self.check_rejects({"provider": "p", "status": "ok", "unit": "percent", "largest_cluster_pct": 10, "cluster_sum_pct": "45"})
        self.check_rejects({"provider": "p", "status": "ok", "unit": "percent", "largest_cluster_pct": 10, "bundle_pct": True})
        self.check_rejects({"provider": "p", "status": "ok", "unit": "percent", "largest_cluster_pct": 10, "data_age_min": "5"})
        self.check_rejects({"provider": "p", "status": "ok", "largest_cluster_pct": 10, "bundle_pct": float("nan")})

    def test_percent_largest_with_fraction_looking_sibling_is_rejected(self):
        # explicit percent, largest 1%, but the sum says 0.45: a sum can never be below the largest cluster
        self.check_rejects({"provider": "p", "status": "ok", "unit": "percent", "largest_cluster_pct": 1, "cluster_sum_pct": 0.45})
        self.check_rejects({"provider": "p", "status": "ok", "largest_cluster_pct": 1, "cluster_sum_pct": 0.45}, file_unit="percent")

    def test_valid_values_and_nulls_pass(self):
        out = hf.normalize_findings_file([{"provider": "p", "status": "ok", "unit": "fraction", "largest_cluster_pct": 0.1, "cluster_sum_pct": 0.45, "bundle_pct": None}])
        self.assertEqual((out[0]["largest_cluster_pct"], out[0]["cluster_sum_pct"], out[0]["bundle_pct"]), (10.0, 45.0, None))

    def test_ok_finding_with_nothing_readable_is_unavailable_and_visible(self):
        f = hf.normalize_finding({"provider": "mystery", "status": "ok"})
        self.assertEqual(f["status"], "unavailable")
        self.assertTrue(f["unreadable"])
        peers = [f, {"provider": "other", "status": "ok", "largest_cluster_pct": 1.0, "bundle_pct": None, "data_age_min": 1.0}]
        a = hf.assess(holders_dict(), funders_with_cohort(), [quiet_map()] + [f])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_NO_ALARM)  # the unreadable row neither helps nor blocks
        self.assertNotIn("mystery", a["verdict"]["sources_counted"])
        md = hf.markdown_report(MINT, holders_dict(), funders_with_cohort(), 1, a)
        self.assertIn("provider mystery: ANSWERED BUT UNREADABLE", md)
        only = hf.assess(holders_dict(), funders_with_cohort(), [f])
        self.assertEqual(only["verdict"]["level"], hf.VERDICT_LIMITED)  # the map is required and missing; unreadable is not a source
        self.assertEqual(len(peers), 2)

    def test_hint_only_ok_finding_stays_readable(self):
        f = hf.normalize_finding({"provider": "okx", "status": "ok", "alarm_hint": "same fund source 0.947"})
        self.assertEqual(f["status"], "ok")


class BubblemapsClusterIntegrityTests(unittest.TestCase):
    def test_a_bad_cluster_entry_makes_the_map_unavailable_not_ok(self):
        for clusters in ([{"supply_pct": 2}, {"supply_pct": "45"}], [{"supply_pct": 2}, {"supply_pct": 150}], [{"supply_pct": 2}, {"supply_pct": None}], [{"supply_pct": 2}, "junk"], [{"supply_pct": -1}]):
            f = hf.bubblemaps_finding({"mint": MINT, "parse_ok": True, "age_min_after": 1.0, "clusters": clusters}, MINT)
            self.assertEqual(f["status"], "unavailable", clusters)
            self.assertIsNone(f["largest_cluster_pct"])
            a = hf.assess(holders_dict(), funders_with_cohort(), [f])
            self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)

    def test_clusters_field_must_be_a_list(self):
        self.assertEqual(hf.bubblemaps_finding({"mint": MINT, "parse_ok": True, "clusters": {"a": 1}}, MINT)["status"], "unavailable")

    def test_good_clusters_still_ok(self):
        self.assertEqual(hf.bubblemaps_finding({"mint": MINT, "parse_ok": True, "age_min_after": 1.0, "clusters": [{"supply_pct": 2}, {"supply_pct": 3.5}]}, MINT)["status"], "ok")


if __name__ == "__main__":
    unittest.main()
