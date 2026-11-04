"""HS-OWNER-1019-T1 (owner decision 2026-10-19, Option A): honest wording for wallets whose funder is unknown.

A provider row with a funding time but no funder address used to be counted under one shared "unknown" funder, so a
cohort whose funders were all unknown read "a single funder fed all N wallets". Now the unknown-funder wallets are
counted as unknown (`unknown_funder_wallets`), `distinct_funders` counts known funders only, and the report, the
Sources-read block and the executive summary say "funder unknown for X of Y wallets". No verdict, flag or severity
changes: the HIGH rule still counts the unknown-funder wallets together as one funder (funders_toward_high), which these
tests check against the pre-change count on all, some and no funder addresses, on synthetic rows and on the real CAPE
GMGN and Jupiter payloads with funder addresses removed. Offline, standard library only."""

from __future__ import annotations

import json
import random
import re
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
from test_verdict_gating import funders_dict, holders_dict  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
T0 = 1_760_000_000
LAUNCH_LATER = T0 + 30 * 86400  # funded 30 days before launch: dormancy, the second sign next to similar amounts
CAPE_LAUNCH = 1_791_968_640  # 2026-10-14 09:04:00 UTC
REASSURING = re.compile(r"\b(clean|low|safe|None)\b")
# The rule as it is (Architect decision on the HS-OWNER-1019-T1 escalation): the unknown-funder wallets count together as
# one funder, so "HIGH needs 2+ known funders" would be false for one known funder plus unknown ones (kept HIGH).
RULE_TEXT = "HIGH needs 2+ funders, and wallets with an unknown funder count together as one"
KNOWN_FUNDERS_CLAIM = re.compile(r"(?i)(?:\d+|\})\s*\+\s*known funders?")  # also a templated number: {COHORT_HIGH_MIN_FUNDERS}+ known funders


def row(i, funder, t=None, pct=0.1, amount=1.0, label=None):
    return {"wallet": f"w{i}", "first_funding_time": T0 + i * 60 if t is None else t, "funder_address": funder, "funder_label": label,
            "first_funding_amount": amount, "supply_pct": pct, "first_acquired_at": None}


def old_funder_count(members):
    """The count the HIGH rule used before HS-OWNER-1019-T1: every missing funder merged into one 'unknown' funder."""
    return len({m.get("funder_address") or "unknown" for m in members})


def old_level(c, members):
    """Severity level under the pre-change rule (levels only; the reference for 'no severity change')."""
    signs = hf.cohort_signs(c)
    if c["wallets"] < hf.COHORT_HIGH_MIN_WALLETS or old_funder_count(members) < hf.COHORT_HIGH_MIN_FUNDERS or len(signs) < hf.COHORT_HIGH_MIN_SIGNS:
        return hf.VERDICT_UNRESOLVED
    return hf.VERDICT_HIGH


def cohorts_of(rows, launch=LAUNCH_LATER, acquisitions=None):
    return hf.run_cohort_source(rows, launch_ts=launch, acquisitions=acquisitions)["cohorts"]


def report_for(source, rows, launch=LAUNCH_LATER):
    src = {source: hf.run_cohort_source(rows, launch_ts=launch)}
    quiet = {"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 2.0, "cluster_sum_pct": 2.0, "bundle_pct": None, "data_age_min": 1.0}
    a = hf.assess(holders_dict(), None, [quiet], provider_cohorts=src)
    return a, hf.markdown_report("MINT", holders_dict(), None, 0, a, src)


def line(md, start):
    return next(ln for ln in md.splitlines() if ln.startswith(start))


class SyntheticAllSomeNoneTests(unittest.TestCase):
    def test_none_unknown_keeps_the_old_wording_exactly(self):
        c = cohorts_of([row(i, f"F{i % 3}") for i in range(40)])[0]
        self.assertEqual((c["wallets"], c["distinct_funders"], c["unknown_funder_wallets"], c["severity"]), (40, 3, 0, hf.VERDICT_HIGH))
        self.assertEqual(c["severity_reason"], "40 wallets from 3 funders; signs: dormant 30 days, similar first amounts")
        self.assertEqual(hf.funder_text(c), "3 funders")
        single = cohorts_of([row(i, "ONE") for i in range(40)])[0]
        self.assertEqual((single["distinct_funders"], single["unknown_funder_wallets"], single["severity"]), (1, 0, hf.VERDICT_UNRESOLVED))
        self.assertEqual(single["severity_reason"], "a single funder fed all 40 wallets; signs: dormant 30 days, similar first amounts")
        _, md = report_for("gmgn", [row(i, f"F{i % 3}") for i in range(40)])
        self.assertNotIn("funder unknown", md)

    def test_all_unknown_says_funder_unknown_never_a_single_funder(self):
        rows = [row(i, None) for i in range(40)]
        c = cohorts_of(rows)[0]
        self.assertEqual((c["wallets"], c["distinct_funders"], c["unknown_funder_wallets"], c["funder_mix"]), (40, 0, 40, []))
        self.assertEqual(c["severity"], hf.VERDICT_UNRESOLVED)  # as before: no known funder never reaches HIGH
        self.assertEqual(old_level(c, rows), hf.VERDICT_UNRESOLVED)
        self.assertEqual(c["severity_reason"], f"funder unknown for 40 of 40 wallets; {RULE_TEXT}; signs: dormant 30 days, similar first amounts")
        self.assertEqual(hf.funder_text(c), "no known funder, funder unknown for 40 of 40 wallets")
        a, md = report_for("gmgn", rows)
        self.assertEqual((a["verdict"]["level"], a["flag"]["label"]), (hf.VERDICT_UNRESOLVED, hf.FLAG_CAUTION))
        self.assertNotIn("a single funder fed", md)  # (the glossary still defines FACTORY_PATTERN as a check for a single funder)
        self.assertIn(f"funder unknown for 40 of 40 wallets; {RULE_TEXT}", line(md, "    - severity:"))
        self.assertIn("funder mix: funder unknown 40", md)
        self.assertIn("cohort: 40 wallets, 4.0% of supply, no known funder, funder unknown for 40 of 40 wallets, UNRESOLVED", md)  # Sources read
        self.assertIn("funder unknown for 40 of 40 wallets", line(md, "- Also:"))  # executive summary
        self.assertIn("via no known funder, funder unknown for 40 of 40 wallets", " ".join(a["verdict"]["reasons"]))

    def test_some_unknown_with_one_known_funder_keeps_high_and_says_how_it_counted(self):
        """The RISKS case of the ticket: one known funder plus unknown-funder wallets counted 2 funders before. Counting
        known funders only would turn this HIGH into UNRESOLVED, so the old count is kept and the reason says so."""
        rows = [row(i, "ONE" if i < 25 else None) for i in range(40)]
        c = cohorts_of(rows)[0]
        self.assertEqual((c["distinct_funders"], c["unknown_funder_wallets"], hf.funders_toward_high(c), old_funder_count(rows)), (1, 15, 2, 2))
        self.assertEqual(c["severity"], hf.VERDICT_HIGH)
        self.assertEqual(old_level(c, rows), hf.VERDICT_HIGH)
        self.assertEqual(c["severity_reason"], "40 wallets, 1 known funder, funder unknown for 15 of 40 wallets, counted together as a second funder toward HIGH; "
                                               "signs: dormant 30 days, similar first amounts")
        a, md = report_for("jupiter", rows)
        self.assertEqual((a["verdict"]["level"], a["flag"]["label"]), (hf.VERDICT_HIGH, hf.FLAG_DANGER))
        self.assertIn("funder mix: unlabeled 25, funder unknown 15", md)
        self.assertIn("funder unknown for 15 of 40 wallets", line(md, "- Why:"))
        none_sign = cohorts_of(rows, launch=None)[0]  # similar amounts only, no dormancy: one sign
        self.assertEqual(none_sign["severity"], hf.VERDICT_UNRESOLVED)
        no_sign = cohorts_of([dict(r, first_funding_amount=1.0 + (i % 7) * 3) for i, r in enumerate(rows)], launch=None)[0]
        self.assertEqual(no_sign["severity_reason"], f"40 wallets, 1 known funder, funder unknown for 15 of 40 wallets, counted together as a second funder toward HIGH: {hf.NO_DISCRIMINATOR_REASON}")

    def test_some_unknown_with_several_known_funders(self):
        rows = [row(i, f"F{i % 3}" if i % 4 else None) for i in range(40)]
        c = cohorts_of(rows)[0]
        self.assertEqual((c["distinct_funders"], c["unknown_funder_wallets"], c["severity"]), (3, 10, hf.VERDICT_HIGH))
        self.assertEqual(c["severity_reason"], "40 wallets, 3 known funders, funder unknown for 10 of 40 wallets; signs: dormant 30 days, similar first amounts")
        self.assertEqual(sum(m["wallets"] for m in c["funder_mix"]), 30)
        self.assertNotIn("unknown", {m["funder"] for m in c["funder_mix"]})

    def test_supply_route_cohort_with_unknown_funders_keeps_its_reason(self):
        rows = [row(i, None if i % 2 else f"F{i}", pct=1.55) for i in range(6)]
        c = hf.detect_cohorts(rows)[0]
        self.assertEqual((c["flagged_by"], c["severity"], c["unknown_funder_wallets"], c["distinct_funders"]), ("supply", hf.VERDICT_UNRESOLVED, 3, 3))
        self.assertTrue(c["severity_reason"].startswith("only 6 wallets, flagged by supply share alone"))

    def test_report_wording_rules_hold_with_unknown_funders(self):
        for rows in ([row(i, None) for i in range(40)], [row(i, "ONE" if i < 25 else None) for i in range(40)]):
            _, md = report_for("gmgn", rows)
            self.assertIsNone(REASSURING.search(md), REASSURING.search(md) and REASSURING.search(md).group(0))
            self.assertNotRegex(md, r"\([^()]*\([^()]*\)")  # no nested parentheses (test_report_polish rule)
            self.assertNotIn("1 funders", md)


class RuleWordingTests(unittest.TestCase):
    """Architect decision on the HS-OWNER-1019-T1 escalation: the HIGH rule keeps counting the unknown-funder wallets
    together as one funder, so the wording states that rule and never claims HIGH needs 2+ KNOWN funders."""

    def test_skill_file_and_code_never_say_known_funders_are_needed(self):
        skill = Path(__file__).resolve().parents[2]
        files = [skill / "SKILL.md", *sorted((skill / "scripts").rglob("*.py"))]
        self.assertGreater(len(files), 5)
        for path in files:
            self.assertIsNone(KNOWN_FUNDERS_CLAIM.search(path.read_text(encoding="utf-8")), path.name)
        self.assertIn(RULE_TEXT, (skill / "SKILL.md").read_text(encoding="utf-8"))
        self.assertIn("and wallets with an unknown funder count together as one", (skill / "scripts" / "helius_forensics.py").read_text(encoding="utf-8"))
        for old in ("HIGH needs 2+ known funders", "needs 2 + known funder", "HIGH NEEDS 2+ KNOWN FUNDERS", 'f"HIGH needs {COHORT_HIGH_MIN_FUNDERS}+ known funders"'):  # negative checks
            self.assertIsNotNone(KNOWN_FUNDERS_CLAIM.search(old), old)

    def test_the_stated_rule_matches_the_kept_count(self):
        """The all-unknown reason says unknown-funder wallets count together as one funder; the mixed case shows it."""
        mixed = cohorts_of([row(i, "ONE" if i < 25 else None) for i in range(40)])[0]
        self.assertEqual((hf.funders_toward_high(mixed), mixed["severity"]), (2, hf.VERDICT_HIGH))
        self.assertIn("counted together as a second funder toward HIGH", mixed["severity_reason"])
        none_known = cohorts_of([row(i, None) for i in range(40)])[0]
        self.assertEqual((hf.funders_toward_high(none_known), none_known["severity"]), (1, hf.VERDICT_UNRESOLVED))
        self.assertIn(RULE_TEXT, none_known["severity_reason"])


class SameSeverityAsBeforeTests(unittest.TestCase):
    def test_random_cohorts_keep_the_old_count_and_level(self):
        """Seeded random cohorts with funder fields None, '', the text 'unknown' and addresses, in random mixes: the HIGH
        rule's funder count equals the pre-change count and the level equals the pre-change level every time."""
        seen = {"high_with_unknowns": 0, "all_unknown": 0, "one_known_plus_unknown": 0}
        for seed in range(300):
            rng = random.Random(seed)
            n = rng.randrange(5, 60)
            known = [f"K{k}" for k in range(rng.randrange(0, 5))]
            missing_rate = rng.choice((0.0, 0.2, 0.5, 0.9, 1.0))
            missing = rng.choice(((None,), ("",), ("unknown",), (None, "", "unknown")))  # how a missing funder looks in this cohort
            pool = known or [None]
            rows = []
            for i in range(n):
                funder = rng.choice(missing) if rng.random() < missing_rate else rng.choice(pool)
                rows.append(row(i, funder, t=T0 + rng.randrange(0, 3 * 3600), pct=rng.choice((0.05, 0.4, 2.0)), amount=rng.choice((1.0, 1.0, 1.0 + rng.random() * 9))))
            acq = {r["wallet"]: T0 + 40 * 86400 + rng.randrange(0, 400) for r in rows} if rng.random() < 0.5 else None
            by_wallet = {r["wallet"]: r for r in rows}
            for c in hf.run_cohort_source(rows, launch_ts=rng.choice((None, LAUNCH_LATER)), acquisitions=acq)["cohorts"]:
                members = [by_wallet[w] for w in c["members"]]
                self.assertEqual(hf.funders_toward_high(c), old_funder_count(members), seed)
                self.assertEqual(c["severity"], old_level(c, members), (seed, c["severity_reason"]))
                self.assertEqual(c["distinct_funders"], len({m["funder_address"] for m in members if m["funder_address"]}), seed)
                self.assertEqual(c["unknown_funder_wallets"], sum(1 for m in members if not m["funder_address"]), seed)
                if "single funder" in c["severity_reason"]:
                    self.assertEqual((c["distinct_funders"], c["unknown_funder_wallets"]), (1, 0), seed)
                unknown = c["unknown_funder_wallets"]
                seen["high_with_unknowns"] += bool(unknown and c["severity"] == hf.VERDICT_HIGH)
                seen["all_unknown"] += bool(unknown == c["wallets"])
                seen["one_known_plus_unknown"] += bool(unknown and c["distinct_funders"] == 1 and c["severity"] == hf.VERDICT_HIGH)
        self.assertTrue(all(seen.values()), seen)  # the sample really covers the interesting mixes


def gmgn_without_funders(payload, keep):
    out = json.loads(json.dumps(payload))
    for i, r in enumerate(hf._unwrap(out)):
        nt = r.get("native_transfer")
        if isinstance(nt, dict) and not keep(i, nt.get("from_address")):
            nt.pop("from_address", None)
    return out


def jupiter_without_funders(payload, keep):
    out = json.loads(json.dumps(payload))
    for i, r in enumerate(hf._unwrap(out)):
        info = r.get("addressInfo")
        if isinstance(info, dict) and not keep(i, info.get("fundingAddress")):
            info.pop("fundingAddress", None)
    return out


class CapePayloadTests(unittest.TestCase):
    """The real CAPE GMGN and Jupiter top-100 payloads with all, some or none of the funder addresses removed."""

    @classmethod
    def setUpClass(cls):
        cls.gmgn = json.loads((FIX / "cape_gmgn.json").read_text())
        cls.jup = json.loads((FIX / "cape_jupiter.json").read_text())
        rows = hf.gmgn_cohort_rows(cls.gmgn)
        cls.acq = {r["wallet"]: r["first_acquired_at"] for r in rows if r["first_acquired_at"]}
        cls.farm_funder = hf.run_cohort_source(rows, launch_ts=CAPE_LAUNCH)["cohorts"][0]["funder_mix"][0]["funder"]

    def big(self, source, payload):
        rows = hf.gmgn_cohort_rows(payload) if source == "gmgn" else hf.jupiter_cohort_rows(payload, total_supply=1e9)
        cohorts = hf.run_cohort_source(rows, launch_ts=CAPE_LAUNCH, acquisitions=self.acq if source == "jupiter" else None)["cohorts"]
        by_wallet = {r["wallet"]: r for r in rows}
        for c in cohorts:
            self.assertEqual(c["severity"], old_level(c, [by_wallet[w] for w in c["members"]]), (source, c["severity_reason"]))
        return next(c for c in cohorts if c["wallets"] >= hf.COHORT_MIN_WALLETS)

    def variants(self, source):
        strip = gmgn_without_funders if source == "gmgn" else jupiter_without_funders
        base = self.gmgn if source == "gmgn" else self.jup
        return {"none": base, "all": strip(base, lambda i, f: False), "every_other": strip(base, lambda i, f: i % 2 == 0),
                "one_known": strip(base, lambda i, f: f == self.farm_funder)}

    def test_none_removed_is_unchanged(self):
        for source in ("gmgn", "jupiter"):
            c = self.big(source, self.variants(source)["none"])
            self.assertEqual((c["distinct_funders"], c["unknown_funder_wallets"], c["severity"]), (6, 0, hf.VERDICT_HIGH), source)
            self.assertTrue(c["severity_reason"].startswith(f"{c['wallets']} wallets from 6 funders; signs: dormant 56 days, bought within"), source)

    def test_all_removed_reads_funder_unknown_for_53_of_53(self):
        c = self.big("gmgn", self.variants("gmgn")["all"])
        self.assertEqual((c["wallets"], c["distinct_funders"], c["unknown_funder_wallets"], c["severity"]), (53, 0, 53, hf.VERDICT_UNRESOLVED))
        self.assertTrue(c["severity_reason"].startswith(f"funder unknown for 53 of 53 wallets; {RULE_TEXT}; signs: dormant 56 days"))
        self.assertNotIn("single funder", c["severity_reason"])
        j = self.big("jupiter", self.variants("jupiter")["all"])
        self.assertEqual((j["distinct_funders"], j["unknown_funder_wallets"], j["severity"]), (0, j["wallets"], hf.VERDICT_UNRESOLVED))

    def test_some_removed_keeps_every_severity(self):
        for source in ("gmgn", "jupiter"):
            other = self.big(source, self.variants(source)["every_other"])
            self.assertEqual((other["distinct_funders"], other["severity"]), (6, hf.VERDICT_HIGH), source)
            self.assertGreater(other["unknown_funder_wallets"], 0, source)
            one = self.big(source, self.variants(source)["one_known"])
            self.assertEqual((one["distinct_funders"], one["severity"]), (1, hf.VERDICT_HIGH), source)  # kept HIGH (escalated case)
            self.assertIn("counted together as a second funder toward HIGH", one["severity_reason"], source)

    def test_assess_and_report_on_cape_with_all_funders_unknown(self):
        h = {"token_accounts": 3000, "warnings": [], "_balances": {}, "earliest_pair_created_at": CAPE_LAUNCH, "distribution": {"owners": 2900, "infrastructure_pct": 0.0}}
        src = hf.provider_cohort_sources(h, self.variants("gmgn")["all"], None, acquisitions=self.acq)
        a = hf.assess(h, funders_dict(), provider_cohorts=src)
        md = hf.markdown_report("CAPE", h, funders_dict(), 0, a, src)
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_UNRESOLVED)
        self.assertIn(f"severity: UNRESOLVED: funder unknown for 53 of 53 wallets; {RULE_TEXT}", md)
        self.assertNotIn("a single funder fed all 53 wallets", md)
        self.assertIn("funder unknown for 53 of 53 wallets", line(md, "- Also:"))


if __name__ == "__main__":
    unittest.main()
