"""Evidence-first report: executive summary, FLAG mapping and SOURCES READ (offline, presentation only)."""

from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
from test_cape_regression import holders_dict as cape_holders  # noqa: E402
from test_real_payloads import CAPE_LAUNCH, load  # noqa: E402
from test_verdict_gating import funders_dict, holders_dict  # noqa: E402

CAPE_MINT = "CXuxsSC2CeyszHZNAQAgwguWzaNhWvbGD7J8xpxwpump"
SPACE_MINT = "HfpLdX35Kc6b7zDNWbe5x1xWLekKUXPYZbmz71vMpump"
REASSURING = re.compile(r"\b(safe|clean|low)\b|\bNONE\b", re.I)
ORDER = ["Helius full holder list", "Bubblemaps free map", "SolScanner public scan", "GMGN holder rows", "Jupiter datapi holder rows"]


def section(md: str, header: str) -> list[str]:
    body = md.split(f"## {header}\n", 1)[1].split("\n## ", 1)[0]
    return [ln for ln in body.splitlines() if ln.strip()]


def cape_map():
    return hf.bubblemaps_finding({"mint": CAPE_MINT, "parse_ok": True, "age_min_after": 1.0, "refresh_effective": True,
                                  "clusters": [{"cluster": 1, "wallets": 283, "supply_pct": 25.45}, {"cluster": 2, "wallets": 59, "supply_pct": 17.44}, {"cluster": 3, "wallets": 9, "supply_pct": 1.02}]}, CAPE_MINT)


def cape_report():
    h = cape_holders(launch=CAPE_LAUNCH)
    h["_balances"] = {}
    src = hf.provider_cohort_sources(h, load("cape_gmgn.json"), load("cape_jupiter.json"))
    a = hf.assess(h, None, [cape_map()], provider_cohorts=src)
    return a, hf.markdown_report(CAPE_MINT, h, None, 0, a, src)


def space_report():
    h = cape_holders()
    h["_balances"] = {}
    h["distribution"]["top_ex_infra"] = {"top_1": 6.2, "top_10": 31.5}
    src = hf.provider_cohort_sources(h, load("space_inu_gmgn.json"), load("space_inu_jupiter.json"))
    bm = hf.bubblemaps_finding(load("space_inu_bubblemaps.json"), SPACE_MINT)
    a = hf.assess(h, None, [bm], provider_cohorts=src)
    return a, hf.markdown_report(SPACE_MINT, h, None, 0, a, src)


class FlagMappingTests(unittest.TestCase):
    def verdict(self, level, reasons=("because",)):
        return {"level": level, "reasons": list(reasons)}

    def test_mapping_for_each_level(self):
        self.assertEqual(hf.flag_for(self.verdict(hf.VERDICT_HIGH))["label"], "DANGER FLAG")
        self.assertEqual(hf.flag_for(self.verdict(hf.VERDICT_UNRESOLVED))["label"], "CAUTION")
        for level in (hf.VERDICT_LIMITED, hf.VERDICT_NO_ALARM):
            f = hf.flag_for(self.verdict(level))
            self.assertEqual(f["label"], "NO FLAG RAISED (not a safety signal)")
            self.assertEqual(f["why"], [])
        self.assertIn("coverage is limited", hf.flag_for(self.verdict(hf.VERDICT_LIMITED, ["only 10% checked"]))["caveat"])

    def test_flag_is_in_assessment_json_next_to_the_underlying_level(self):
        a, _ = cape_report()
        self.assertEqual(a["flag"]["label"], "DANGER FLAG")
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_HIGH)
        json.dumps(a)  # serializable
        self.assertIn("sources", a)


class ExecutiveSummaryTests(unittest.TestCase):
    def test_summary_is_first_short_and_ends_with_the_owner_line(self):
        for build in (cape_report, space_report):
            _, md = build()
            self.assertLess(md.index("## Executive summary"), md.index("## Sources read"))
            lines = section(md, "Executive summary")
            self.assertLessEqual(len(lines), hf.SUMMARY_MAX_LINES)
            self.assertGreaterEqual(len(lines), 6)
            self.assertIn("Your call: this tool raises a danger flag only on clear large clusters; no flag is NOT a safety signal.", lines[-1])

    def test_cape_like_input_renders_danger_flag_with_reasons(self):
        a, md = cape_report()
        lines = section(md, "Executive summary")
        text = "\n".join(lines)
        self.assertIn("FLAG: DANGER FLAG", text)
        why = next(ln for ln in lines if ln.startswith("- Why:"))
        self.assertIn("cohort", why)
        self.assertIn("Largest clusters: Bubblemaps largest 25.45% (all together 43.91%; map 1 min old)", text)
        self.assertIn("Funding cohorts", text)
        self.assertIn("Not requested: SolScanner public scan", text)  # an optional source nobody asked for is named, not hidden
        could = next(ln for ln in lines if ln.startswith("- Could not read:"))
        self.assertIn("Helius funding lookups and the funding-time cohort detector (not run)", could)
        self.assertIn(CAPE_MINT, text)
        self.assertIn("UTC", text)

    def test_limited_renders_no_flag_with_caveat_and_never_reassures(self):
        a, md = space_report()
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)
        text = "\n".join(section(md, "Executive summary"))
        self.assertIn("FLAG: NO FLAG RAISED (not a safety signal)", text)
        self.assertIn("Note: coverage is limited", text)
        self.assertNotIn("DANGER", text)
        self.assertIsNone(re.search(r"\b(safe|clean|low)\b", md, re.I))
        self.assertIsNone(re.search(r"\bNONE\b", md))

    def test_a_large_cluster_against_a_calm_source_is_danger_naming_the_disagreement(self):
        h = holders_dict()
        a = hf.assess(h, None, [{"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 30.0, "bundle_pct": None, "data_age_min": 1.0},
                                {"provider": "gmgn", "status": "ok", "largest_cluster_pct": None, "bundle_pct": 0.5, "data_age_min": 1.0}])
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_UNRESOLVED)  # the underlying level is unchanged
        self.assertEqual(a["flag"]["label"], "DANGER FLAG (clear large cluster; sources disagree: GMGN reads calm)")
        md = hf.markdown_report("MINT", h, None, 0, a)
        why = next(ln for ln in section(md, "Executive summary") if ln.startswith("- Why:"))
        self.assertTrue(why.startswith("- Why: Bubblemaps map: largest cluster 30% of supply (bar 15%)"))
        self.assertIn("GMGN", why)

    def test_holder_numbers_come_from_the_distribution_excluding_pools(self):
        owners = {f"w{i}": float(100 - i) for i in range(30)} | {"POOL": 500.0}
        d = hf.distribution(owners, {"POOL"})
        self.assertAlmostEqual(d["top_ex_infra"]["top_1"], 100 / sum(owners.values()) * 100, places=2)
        self.assertLess(d["top_ex_infra"]["top_1"], d["top"]["top_1"])  # the pool is the biggest owner and is excluded
        h = {"token_accounts": 31, "warnings": [], "distribution": {k: v for k, v in d.items() if k != "ranked"}}
        md = hf.markdown_report("MINT", h, None, 0)
        self.assertIn(f"top holder {d['top_ex_infra']['top_1']}% and top 10 {d['top_ex_infra']['top_10']}%", md)


class SourcesReadTests(unittest.TestCase):
    def test_every_source_is_listed_in_fixed_order_with_status_and_numbers(self):
        a, md = cape_report()
        names = [s["name"] for s in a["sources"]]
        self.assertEqual(names[:5], ORDER)
        block = "\n".join(section(md, "Sources read"))
        positions = [block.index(n) for n in ORDER]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("Bubblemaps free map: read, 1 min old", block)
        self.assertIn("cluster 1: 283 wallets, 25.45%", block)
        self.assertIn("3 clusters; largest 25.45%; all together 43.91% of supply", block)
        self.assertIn("SolScanner public scan: not run", block)
        self.assertIn("100 rows read; 99 carry a funding time", block)
        self.assertIn("funding cohorts found: 2", block)
        self.assertIn("cohort: 53 wallets, 26.01% of supply, 6 funders, HIGH", block)
        self.assertIn("supply share unknown", block)  # Jupiter rows without supply
        self.assertEqual(block.count("cannot see:"), 5)

    def test_not_run_sources_say_how_to_run_them(self):
        a = hf.assess(holders_dict(), None)
        by = {s["key"]: s for s in a["sources"]}
        self.assertEqual(by["bubblemaps_map"]["status"], "not run")
        self.assertEqual(by["gmgn"]["status"], "not run")
        self.assertIn("--gmgn-holders-json", by["gmgn"]["lines"][0])
        self.assertEqual(by["helius"]["status"], "read")
        self.assertIn("funding lookups: not run", " ".join(by["helius"]["lines"]))

    def test_helius_block_reports_funding_numbers_batches_and_cohorts(self):
        f = funders_dict(covered=70.0)
        f["batches"] = [{"funder": "F" * 44, "funder_name": "Gate Hot Wallet", "wallets": 9, "share_pct": 3.2}]
        a = hf.assess(holders_dict(), f)
        text = " ".join(next(s for s in a["sources"] if s["key"] == "helius")["lines"])
        self.assertIn("funding checked for 100 of 100 wallets", text)
        self.assertIn("Gate Hot Wallet: 9 wallets, 3.2% of supply", text)

    def test_other_providers_and_unavailable_statuses_are_shown(self):
        findings = [{"provider": "insightx", "status": "empty", "largest_cluster_pct": None, "bundle_pct": None, "data_age_min": 2.0, "detail": "no analysis"},
                    {"provider": "okx", "status": "ok", "largest_cluster_pct": 2.0, "cluster_sum_pct": None, "bundle_pct": None, "data_age_min": 3.0, "alarm_hint": "same fund source 0.947"},
                    {"provider": "cabal", "status": "unavailable", "largest_cluster_pct": None, "bundle_pct": None, "data_age_min": None, "detail": "http error"}]
        a = hf.assess(holders_dict(), None, findings)
        by = {s["key"]: s for s in a["sources"]}
        self.assertEqual((by["insightx"]["status"], by["okx"]["status"], by["cabal"]["status"]), ("empty", "read", "unavailable"))
        self.assertIn("alarm hint: same fund source 0.947", by["okx"]["lines"][0])
        self.assertEqual(a["flag"]["label"], "CAUTION")

    def test_long_lists_are_capped_with_and_n_more(self):
        clusters = [{"cluster": i, "wallets": 3, "supply_pct": 1.0} for i in range(30)]
        bm = hf.bubblemaps_finding({"mint": CAPE_MINT, "parse_ok": True, "age_min_after": 1.0, "clusters": clusters}, CAPE_MINT)
        a = hf.assess(holders_dict(), None, [bm])
        lines = next(s for s in a["sources"] if s["key"] == "bubblemaps_map")["lines"]
        self.assertLessEqual(len(lines), 2 + hf.LIST_CAP + 1)
        self.assertTrue(lines[-1].startswith("and "))

    def test_tag_summary_counts_inert_labels(self):
        payload = [{"address": "a", "tags": ["bundler", "sniper"]}, {"address": "b", "tags": ["bundler<script>"]}, {"address": "c", "holderTags": ["kol"]}]
        tags = hf.tag_summary(payload)
        self.assertGreaterEqual(tags["bundler"], 1)
        self.assertNotIn("<", " ".join(tags))
        self.assertIn("kol", tags)

    def test_solscanner_block_from_a_result_dict(self):
        result = {"status": "ok", "reason": None, "scan_age_min": 4.0, "is_stale": False,
                  "groups": [{"wallets": [{"address": "A" * 40, "share_pct": 40.0}, {"address": "B" * 40, "share_pct": 4.4}], "risk_score": 96, "confidence": "high", "bundle_type": "mixed"}]}
        blk = hf._solscanner_source(result, {"provider": "solscanner", "status": "ok", "alarm_hint": "corrob only"})
        text = "\n".join(blk["lines"])
        self.assertEqual(blk["status"], "read")
        self.assertIn("scan 4 min old", text)
        self.assertIn("group 1: 2 wallets, 44.4% of listed supply, risk 96, confidence strong, type mixed", text)  # HS-LABELS-T1 R3: SolScanner's high prints as strong
        self.assertIn("funding sources: not read", text)
        self.assertEqual(hf._solscanner_source({"groups": [], "reason": "timeout"}, {"provider": "solscanner", "status": "unavailable"})["status"], "unavailable")


def line(md, prefix):
    return next(ln for ln in section(md, "Executive summary") if ln.startswith(f"- {prefix}"))


class SummaryConsistencyTests(unittest.TestCase):
    def full_run(self):
        """Everything required ran: Helius funding lookups with a cohort result, the Bubblemaps map, acquisition times."""
        f = funders_dict(covered=80.0)
        f["cohorts"] = hf.run_cohort_source([], launch_ts=None, acquisitions={"w": 1})
        f["acquisition_supplied"] = True
        quiet = {"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 2.0, "cluster_sum_pct": 3.0, "bundle_pct": None, "data_age_min": 1.0, "clusters": [{"wallets": 3, "supply_pct": 2.0}], "cluster_count": 1}
        a = hf.assess(holders_dict(), f, [quiet])
        return a, hf.markdown_report("MINT", holders_dict(), f, 0, a)

    def test_a_fully_read_case_prints_nothing(self):
        a, md = self.full_run()
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_NO_ALARM)
        self.assertEqual(line(md, "Could not read:"), "- Could not read: nothing.")
        self.assertIn("Helius holder list and funding lookups (100 wallets)", line(md, "Read:"))
        self.assertNotIn("(live)", md.split("## Sources read")[0])

    def test_note_or_why_mentions_of_a_missing_step_are_also_in_could_not_read(self):
        cases = []
        a, md = space_report()
        cases.append(md)
        h = holders_dict()
        cases.append(hf.markdown_report("MINT", h, None, 0, hf.assess(h, None, [])))
        f = funders_dict(covered=10.0)  # funding ran but the cohort result is missing and coverage is low
        cases.append(hf.markdown_report("MINT", holders_dict(), f, 0, hf.assess(holders_dict(), f, [])))
        for md in cases:
            summary = "\n".join(section(md, "Executive summary"))
            could = line(md, "Could not read:")
            if "cohort detector did not complete" in summary:
                self.assertIn("funding-time cohort detector", could, md[:900])
            if "run the funders step" in summary:
                self.assertIn("funding lookups", could)
            if "under" in summary and "minimum" in summary or "was checked; at least" in summary:
                self.assertIn("supply coverage", could)
            self.assertNotEqual(could, "- Could not read: nothing.")

    def test_space_inu_note_and_could_not_read_agree(self):
        import solscanner_scan as ss
        from test_solscanner_scan import NOW_SPACE, Opener, Response, SPACE, stream

        h = cape_holders()
        h["_balances"] = {}
        src = hf.provider_cohort_sources(h, load("space_inu_gmgn.json"), load("space_inu_jupiter.json"))
        res = ss.collect_solscanner(SPACE, opener=Opener(Response(stream("space-inu"))), now=lambda: NOW_SPACE)
        a = hf.assess(h, None, [hf.bubblemaps_finding(load("space_inu_bubblemaps.json"), SPACE_MINT), hf.solscanner_finding_for(res, NOW_SPACE)], provider_cohorts=src, solscanner=res)
        md = hf.markdown_report(SPACE_MINT, h, None, 0, a, src)
        self.assertIn("funding-time cohort detector did not complete", line(md, "Note:"))
        could = line(md, "Could not read:")
        self.assertIn("funding-time cohort detector", could)
        self.assertIn("SolScanner funding sources", could)
        self.assertNotIn("nothing", could)

    def test_partial_run_and_truncation_and_unreliable_pool_are_listed(self):
        f = funders_dict(covered=80.0, aborted="credit budget reached")
        f["cohorts"] = hf.run_cohort_source([], launch_ts=None)
        h = holders_dict()
        h["truncated"] = True
        h["warnings"] = ["no pool owner matched the holder list; pools may be counted as holders (use --exclude ADDRESS)"]
        could = line(hf.markdown_report("MINT", h, f, 0, hf.assess(h, f, [])), "Could not read:")
        for word in ("Helius funding lookups", "funding-time cohort detector", "truncated", "pool exclusion"):
            self.assertIn(word, could)

    def test_unavailable_and_empty_sources_are_listed(self):
        findings = [{"provider": "bubblemaps_map", "status": "unavailable", "largest_cluster_pct": None, "bundle_pct": None, "data_age_min": None, "detail": "layout changed"},
                    {"provider": "insightx", "status": "empty", "largest_cluster_pct": None, "bundle_pct": None, "data_age_min": 2.0, "detail": "no analysis"}]
        a = hf.assess(holders_dict(), None, findings)
        could = line(hf.markdown_report("MINT", holders_dict(), None, 0, a), "Could not read:")
        self.assertIn("Bubblemaps free map (unavailable)", could)
        self.assertIn("Provider InsightX (--providers-json) (empty)", could)


class WhyNamesEveryClearLargeClusterTests(unittest.TestCase):
    def test_bubblemaps_cluster_leads_the_why_line_with_its_bars(self):
        a, md = cape_report()
        why = line(md, "Why:")
        self.assertTrue(why.startswith("- Why: Bubblemaps map: largest cluster 25.45% of supply (bar 15%); all clusters together 43.91% (bar 30%)"))
        self.assertIn("cohort", why)  # the existing cohort reasons are kept after it
        self.assertLessEqual(len(section(md, "Executive summary")), hf.SUMMARY_MAX_LINES)

    def test_each_alarming_provider_and_bundle_share_is_named_and_solscanner_is_only_corroboration(self):
        findings = [
            {"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 18.0, "cluster_sum_pct": 18.0, "bundle_pct": None, "data_age_min": 1.0},
            {"provider": "gmgn", "status": "ok", "largest_cluster_pct": None, "bundle_pct": 31.0, "data_age_min": 1.0},
            {"provider": "solscanner", "status": "ok", "largest_cluster_pct": None, "bundle_pct": None, "data_age_min": 4.0, "alarm_hint": "corrob only 98w r96 44pct"},
        ]
        a = hf.assess(holders_dict(), None, findings)
        md = hf.markdown_report("MINT", holders_dict(), None, 0, a)
        why, also = line(md, "Why:"), line(md, "Also:")
        self.assertIn("Bubblemaps map: largest cluster 18% of supply (bar 15%)", why)
        self.assertIn("GMGN: bundles 31% of supply (bar 30%)", why)
        self.assertNotIn("hint", why)  # corroboration is a minor item: it goes on the Also line
        self.assertIn("hint (corroboration only)", also)

    def test_summary_stays_within_the_line_cap_with_many_reasons(self):
        a, md = cape_report()
        self.assertLessEqual(len(section(md, "Executive summary")), hf.SUMMARY_MAX_LINES)


if __name__ == "__main__":
    unittest.main()
