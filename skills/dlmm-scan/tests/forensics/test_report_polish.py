"""Group D: envelope unwrapping, loud empty parses, unknown supply share, next steps, plain wording."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
from test_cohort_detector import T0, gmgn_payload, jupiter_payload  # noqa: E402
from test_holder_forensics import MINT, NO_KEY_ENV, SECRET, FakeHelius  # noqa: E402
from test_verdict_gating import funders_dict, holders_dict  # noqa: E402


class PayloadShapeTests(unittest.TestCase):
    def test_probe_envelope_with_body_is_unwrapped(self):
        env = {"provider": "gmgn", "http_status": 200, "body": gmgn_payload(5)}
        self.assertEqual(len(hf.gmgn_cohort_rows(env)), 5)
        jenv = {"provider": "jupiter", "http_status": 200, "body": {"holders": jupiter_payload(4), "count": 4}}
        self.assertEqual(len(hf.jupiter_cohort_rows(jenv)), 4)

    def test_non_empty_payload_with_zero_rows_raises(self):
        for bad in ({"data": {"list": "x"}}, {"unexpected": [1, 2]}, {"body": {"nothing": 1}}, ["junk", 3]):
            with self.assertRaises(hf.ConfigError, msg=repr(bad)):
                hf.gmgn_cohort_rows(bad)
            with self.assertRaises(hf.ConfigError, msg=repr(bad)):
                hf.jupiter_cohort_rows(bad)

    def test_rows_without_any_address_raise(self):
        with self.assertRaises(hf.ConfigError):
            hf.gmgn_cohort_rows([{"amount_percentage": 0.1}])

    def test_truly_empty_payloads_are_empty(self):
        for empty in (None, [], {}):
            self.assertEqual(hf.gmgn_cohort_rows(empty), [])
            self.assertEqual(hf.jupiter_cohort_rows(empty), [])

    def test_cli_rejects_a_changed_shape_before_any_call(self):
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {**NO_KEY_ENV, "HELIUS_API_KEY": SECRET}, clear=True), \
             mock.patch.object(hf, "run_holders", side_effect=AssertionError("must not run")), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            p = Path(tmp) / "g.json"
            p.write_text(json.dumps({"code": 0, "data": {"rows": []}}))
            code = hf.main(["report", MINT, "--top", "1", "--gmgn-holders-json", str(p)])
        self.assertEqual(code, 2)
        self.assertIn("provider format may have changed", err.getvalue())


class UnknownShareTests(unittest.TestCase):
    def test_jupiter_rows_without_supply_say_unknown_not_zero(self):
        holders = {"_balances": {}, "earliest_pair_created_at": None}
        src = hf.provider_cohort_sources(holders, None, jupiter_payload(40))
        a = hf.assess(holders_dict(), None, provider_cohorts=src)
        md = hf.markdown_report(MINT, holders_dict(), None, 0, a, src)
        self.assertIn("supply share unknown", md)
        self.assertIn("40 wallets, supply share unknown", md)
        self.assertNotIn("40 wallets, 0.0%", md)
        self.assertTrue(any("supply share unknown" in r for r in a["verdict"]["reasons"]))

    def test_partial_unknown_uses_at_least(self):
        rows = [dict(r, supply_pct=None if i < 3 else 0.5) for i, r in enumerate(hf.jupiter_cohort_rows(jupiter_payload(30), total_supply=1e9))]
        c = hf.detect_cohorts(rows)[0]
        self.assertEqual(c["share_unknown_wallets"], 3)
        self.assertIn("at least", hf.share_text(c))

    def test_known_share_prints_percent(self):
        c = hf.detect_cohorts(hf.gmgn_cohort_rows(gmgn_payload(30)))[0]
        self.assertTrue(hf.share_text(c).endswith("% of supply"))


class NextStepTests(unittest.TestCase):
    def test_each_verdict_has_a_plain_next_step(self):
        high = hf.assess(holders_dict(), None, [{"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 30.0, "data_age_min": 1.0}])
        self.assertIn("Do not enter", hf.next_step(high))
        limited = hf.assess(holders_dict(), funders_dict(covered=10.0))
        step = hf.next_step(limited)
        self.assertIn("Bubblemaps step", step)
        self.assertIn("raise --funders-top", step)  # DS-DEPTH-GUARD-T1 amendment: the funded-by depth flag since PR #202
        self.assertNotIn("raise --top to check", step)
        unresolved = hf.assess(holders_dict(), None, [{"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 30.0, "data_age_min": 1.0}, {"provider": "gmgn", "status": "ok", "bundle_pct": 0.5, "largest_cluster_pct": None, "data_age_min": 1.0}])
        self.assertEqual(unresolved["verdict"]["level"], hf.VERDICT_UNRESOLVED)
        self.assertIn("bubblemaps_map", hf.next_step(unresolved))
        self.assertIn("gmgn", hf.next_step(unresolved))
        self.assertIn("What to do next", hf.markdown_report(MINT, holders_dict(), None, 0, limited))

    def test_pool_and_truncation_steps(self):
        h = holders_dict()
        h["truncated"] = True
        h["warnings"] = ["no pool owner matched the holder list; pools may be counted as holders (use --exclude ADDRESS)"]
        step = hf.next_step(hf.assess(h, funders_dict()))
        self.assertIn("--exclude", step)
        self.assertIn("truncated", step)

    def test_no_alarm_step_is_not_reassurance(self):
        self.assertIn("not proof", hf.next_step({"verdict": {"level": hf.VERDICT_NO_ALARM, "reasons": []}, "coverage": {}}))


class WordingTests(unittest.TestCase):
    def test_funder_mix_collapses_repeated_labels(self):
        rows = hf.jupiter_cohort_rows(jupiter_payload(40), total_supply=1e9)
        src = {"jupiter": hf.run_cohort_source(rows, launch_ts=None)}
        md = hf.markdown_report(MINT, holders_dict(), None, 0, hf.assess(holders_dict(), None, provider_cohorts=src), src)
        self.assertIn("funder mix: unlabeled 40", md)
        self.assertEqual(md.count("unlabeled"), 1)

    def test_single_funder_grammar_and_no_nested_parentheses_in_severity(self):
        rows = [dict(r, funder_address="ONE") for r in hf.gmgn_cohort_rows(gmgn_payload(30))]
        src = {"gmgn": hf.run_cohort_source(rows, launch_ts=None)}
        md = hf.markdown_report(MINT, holders_dict(), None, 0, hf.assess(holders_dict(), None, provider_cohorts=src), src)
        self.assertIn("1 funder,", md)
        self.assertNotIn("1 funders", md)
        self.assertNotIn("cohort(s)", md)
        self.assertNotRegex(md, r"\([^()]*\([^()]*\)")

    def test_jargon_removed_and_provisional_stated_once_per_block(self):
        md = hf.markdown_report(MINT, holders_dict(), funders_dict(), 1)
        self.assertNotIn("non-infrastructure", md)
        self.assertNotIn(" bar", md)
        self.assertEqual(len(re.findall(r"provisional", md, re.I)), 0)
        rows = hf.gmgn_cohort_rows(gmgn_payload(30))
        src = {"gmgn": hf.run_cohort_source(rows, launch_ts=None)}
        md2 = hf.markdown_report(MINT, holders_dict(), None, 0, hf.assess(holders_dict(), None, provider_cohorts=src), src)
        self.assertEqual(len(re.findall(r"provisional", md2, re.I)), 1)

    def test_blockers_use_plain_wording(self):
        a = hf.assess(holders_dict(), funders_dict(covered=10.0))
        text = " ".join(a["verdict"]["reasons"])
        self.assertIn("supply held by ordinary wallets", text)
        self.assertNotIn("non-infrastructure", text)


class GlossaryTests(unittest.TestCase):
    def test_glossary_is_last_and_empty_buckets_are_hidden(self):
        h = holders_dict()
        md = hf.markdown_report(MINT, h, funders_dict(), 1)
        self.assertEqual(md.strip().splitlines()[-1].split(":")[0], "Glossary")
        for word in ("cohort", "Bubblemaps map", "concentration"):
            self.assertIn(word, md.strip().splitlines()[-1])
        self.assertNotIn("Size buckets", md)  # holders_dict has no bucket data
        self.assertNotIn("Top holders: \n", md)
        self.assertNotIn("Gini", md)
        h["distribution"]["buckets"] = {">=1%": {"wallets": 2, "supply_pct": 5.0}}
        h["distribution"]["top"] = {"top_10": 30.0}
        md = hf.markdown_report(MINT, h, funders_dict(), 1)
        self.assertIn("Size buckets: >=1%: 2 wallets, 5.0%", md)
        self.assertIn("Top holders: top 10 30.0%", md)


class RuleTextTests(unittest.TestCase):
    def cape_report(self):
        from test_cape_regression import funders_from, holders_dict as cape_holders, load_fixture, _unix, FIXTURE

        launch = _unix("2026-10-14 09:04:00")
        gmgn = {r["wallet"]: r["first_acquired_at"] for r in hf.gmgn_cohort_rows(json.loads((FIXTURE.parent / "cape_gmgn.json").read_text())) if r["first_acquired_at"]}
        f = funders_from(load_fixture(), covered=31.0, launch=launch, acq=gmgn)
        a = hf.assess(cape_holders(launch=launch), f)
        return a, hf.markdown_report(MINT, cape_holders(launch=launch), f, 0, a)

    def test_report_states_the_exact_high_rule(self):
        _, md = self.cape_report()
        self.assertIn("HIGH needs 20+ wallets, 2+ funders and 2 of: dormant 7+ days, synchronized acquisition, similar amounts; anything less is UNRESOLVED", md)
        self.assertNotIn("smaller or single-funder cohorts", md)

    def test_high_banner_shows_the_signs_that_fired(self):
        a, md = self.cape_report()
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_HIGH)
        verdict_section = md.split("## Coverage")[0]
        self.assertIn("dormant 56 days", verdict_section)
        self.assertRegex(verdict_section, r"bought within \d+ s of each other")

    def test_unrun_funders_step_prints_not_run_not_zero_of_zero(self):
        md = hf.markdown_report(MINT, holders_dict(), None, 0)
        self.assertIn("Wallets examined: not run", md)
        self.assertIn("Supply examined: not run", md)
        self.assertNotIn("0 of 0", md)
        ran = hf.markdown_report(MINT, holders_dict(), funders_dict(), 0)
        self.assertIn("Wallets examined: 100 of 100 requested", ran)


if __name__ == "__main__":
    unittest.main()
