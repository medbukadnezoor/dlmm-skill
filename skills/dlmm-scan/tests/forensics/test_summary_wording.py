"""Wording and honesty of the executive summary: plain hints, one mention, stale reads, Why/Also split, none (offline)."""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
import solscanner_scan as ss  # noqa: E402
from test_cape_regression import holders_dict as cape_holders  # noqa: E402
from test_evidence_report import CAPE_MINT, SPACE_MINT, cape_map, line, section  # noqa: E402
from test_real_payloads import CAPE_LAUNCH, load  # noqa: E402
from test_solscanner_scan import ALTAI, CAPE, NOW_ALTAI, NOW_CAPE, NOW_SPACE, SPACE, Opener, Response, stream  # noqa: E402
from test_verdict_gating import funders_dict, holders_dict  # noqa: E402


def ss_result(name, mint, now):
    return ss.collect_solscanner(mint, opener=Opener(Response(stream(name))), now=lambda: now)


def cape_full():
    h = cape_holders(launch=CAPE_LAUNCH)
    h["_balances"] = {}
    src = hf.provider_cohort_sources(h, load("cape_gmgn.json"), load("cape_jupiter.json"))
    res = ss_result("cape", CAPE, NOW_CAPE)
    a = hf.assess(h, None, [cape_map(), hf.solscanner_finding_for(res, NOW_CAPE)], provider_cohorts=src, solscanner=res)
    return a, hf.markdown_report(CAPE_MINT, h, None, 0, a, src)


class PlainHintTests(unittest.TestCase):
    def test_solscanner_hint_is_plain_words_and_appears_once(self):
        a, md = cape_full()
        why_also = line(md, "Why:") + "\n" + line(md, "Also:")
        self.assertIn("SolScanner (corroboration only): 1 bundle group, 98 wallets, 44% of listed supply, risk 96, scan 4 min old", why_also)
        self.assertNotIn("corrob only", md.split("## Sources read")[0])
        self.assertNotIn("98w r96", md.split("## Underlying level")[0])
        self.assertEqual(why_also.count("SolScanner"), 1)
        self.assertEqual(line(md, "Why:").count("corroboration"), 0)  # it is a minor item: the Also line, not the main reason

    def test_why_and_also_split_and_summary_stays_within_the_cap(self):
        a, md = cape_full()
        lines = section(md, "Executive summary")
        self.assertLessEqual(len(lines), hf.SUMMARY_MAX_LINES)
        why, also = line(md, "Why:"), line(md, "Also:")
        self.assertTrue(why.startswith("- Why: Bubblemaps map: largest cluster 25.45% of supply (bar 15%)"))
        self.assertIn("cohort", why)
        self.assertIn("(UNRESOLVED)", also)  # the 6-wallet single-funder cohort is minor
        self.assertNotIn("(UNRESOLVED)", why)


class StaleReadTests(unittest.TestCase):
    def space(self):
        h = cape_holders()
        h["_balances"] = {}
        res = ss_result("space-inu", SPACE, NOW_SPACE)
        bm = hf.bubblemaps_finding(load("space_inu_bubblemaps.json"), SPACE_MINT)
        a = hf.assess(h, None, [bm, hf.solscanner_finding_for(res, NOW_SPACE)], solscanner=res)
        return a, hf.markdown_report(SPACE_MINT, h, None, 0, a)

    def test_a_five_hour_old_solscanner_scan_does_not_read_as_current(self):
        a, md = self.space()
        clusters = line(md, "Largest clusters:")
        self.assertIn("scan 5.0 h old (STALE)", clusters)
        could = line(md, "Could not read:")
        self.assertIn("fresh SolScanner public scan data (stale: 5.0 h old; the provider marks it stale)", could)

    def test_an_old_bubblemaps_map_is_stale_and_says_refresh_not_confirmed(self):
        old = {"mint": SPACE_MINT, "parse_ok": True, "age_min_after": 45.0, "refresh_effective": False, "clusters": [{"wallets": 5, "supply_pct": 5.24}]}
        a = hf.assess(holders_dict(), None, [hf.bubblemaps_finding(old, SPACE_MINT)])
        md = hf.markdown_report("MINT", holders_dict(), None, 0, a)
        self.assertIn("map 45 min old, STALE", line(md, "Largest clusters:"))
        could = line(md, "Could not read:")
        self.assertIn("fresh Bubblemaps free map data (stale: 45 min old, older than the 15 min freshness limit; refresh not confirmed)", could)

    def test_a_fresh_map_without_a_refresh_is_not_stale(self):
        fresh = {"mint": SPACE_MINT, "parse_ok": True, "age_min_after": 1.0, "refresh_effective": False, "clusters": [{"wallets": 5, "supply_pct": 5.24}]}
        a = hf.assess(holders_dict(), None, [hf.bubblemaps_finding(fresh, SPACE_MINT)])
        md = hf.markdown_report("MINT", holders_dict(), None, 0, a)
        self.assertNotIn("STALE", line(md, "Largest clusters:"))
        self.assertNotIn("stale", line(md, "Could not read:"))

    def test_stale_provider_data_is_listed(self):
        f = {"provider": "okx", "status": "ok", "largest_cluster_pct": 2.0, "bundle_pct": None, "data_age_min": 120.0}
        a = hf.assess(holders_dict(), None, [f])
        self.assertIn("fresh Provider OKX (--providers-json) data (stale: 2.0 h old", line(hf.markdown_report("MINT", holders_dict(), None, 0, a), "Could not read:"))


class NoneWordingTests(unittest.TestCase):
    def test_reports_never_print_python_none(self):
        a, md = cape_full()
        cases = [md, hf.markdown_report("MINT", holders_dict(), None, 0), hf.markdown_report("MINT", holders_dict(), funders_dict(), 0)]
        findings = [{"provider": "okx", "status": "ok", "largest_cluster_pct": 2.0, "cluster_sum_pct": None, "bundle_pct": None, "data_age_min": None, "alarm_hint": None}]
        cases.append(hf.markdown_report("MINT", holders_dict(), None, 0, hf.assess(holders_dict(), None, findings)))
        for text in cases:
            self.assertIsNone(re.search(r"\bNone\b", text), re.search(r".{40}\bNone\b.{20}", text) and re.search(r".{40}\bNone\b.{20}", text).group(0))
        self.assertIn("| okx | 2.0 | none | none | none |", cases[-1])


if __name__ == "__main__":
    unittest.main()
