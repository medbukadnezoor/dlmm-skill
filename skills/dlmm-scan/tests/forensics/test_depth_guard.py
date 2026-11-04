"""DS-DEPTH-GUARD-T1: NO_ALARM is not allowed while the listed holders that funded-by did not check could hide a cohort.

Owner decisions: 2026-10-28 "Merge now, add a guard next (Recommended)"; 2026-10-29 "Detector's own bar (Recommended)".
holders.json lists 250 holders and funded-by covers the top 100 (--funders-top, PR #202). These tests prove, offline
(fakes only, frozen clock, dummy key; the assess step runs with sockets refused and no key):
(1) a funding farm at ranks 101-160 reads LIMITED with the reason at depth 100, never NO_ALARM, and HIGH at depth 250;
(2) a tail below both of the detector's bars keeps NO_ALARM possible;
(3) full depth (every listed ordinary holder checked) gives exactly the verdict decided without the guard;
(4) raised flags never change: a provider alarm with calm own detectors stays UNRESOLVED with "own detectors" named as
    disagreeing, HIGH stays HIGH, and neither carries the depth reason;
(5) the guard reads the detector's constants at call time (patching them moves it) and never counts pools;
(6) the wording: no clean, low or safe; an unknown share is never printed as 0; the summary Note shows the whole reason."""

from __future__ import annotations

import json
import random
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
import test_assess as ta  # noqa: E402
from test_holder_forensics import MINT, addr  # noqa: E402
from test_parallel_rows import funder_addr  # noqa: E402
from test_verdict_gating import funders_dict, holders_dict, ran  # noqa: E402

NOW = int(ta.FROZEN_TS)
LAUNCH = NOW - 30 * 86_400
POOL = addr(990)
CALM_MAP = [(3, 1.0)]     # a fresh, quiet Bubblemaps map
ALARM_MAP = [(30, 20.0)]  # largest cluster at or over CLUSTER_ALARM_PCT: a provider alarm


# ----------------------------------------------------------------------------- synthetic scans (fakes only)

class _Token:
    """A pool plus ordinary wallets in rank order; each wallet funded on its own over months unless a farm funds it."""

    def __init__(self, seed=7):
        self.rng = random.Random(seed)
        self.accounts = [{"owner": POOL, "amount": 20_000.0}]
        self.funded, self.acq, self.n = {}, {}, 0

    def independent(self, amount):
        w = addr(self.n)
        self.n += 1
        self.accounts.append({"owner": w, "amount": amount})
        self.funded[w] = {"funder": funder_addr(f"I{self.n}"), "funderName": None, "funderType": None,
                          "timestamp": NOW - self.rng.randrange(40, 300) * 86_400 + self.rng.randrange(86_400), "amount": round(self.rng.uniform(0.5, 40), 3)}
        self.acq[w] = LAUNCH + self.rng.randrange(0, 29 * 86_400)

    def farm(self, count, amount):
        """`count` wallets from 6 unlabeled funders, funded 5 s apart and buying the same second (the Verifier's farm)."""
        t0 = LAUNCH + 600
        for i in range(count):
            w = addr(self.n)
            self.n += 1
            self.accounts.append({"owner": w, "amount": amount - i * 0.01})
            self.funded[w] = {"funder": funder_addr("F" + "ABCDEF"[i * 6 // count]), "funderName": None, "funderType": None,
                              "timestamp": t0 + i * 5, "amount": round(self.rng.uniform(2.0, 2.2), 3)}
            self.acq[w] = t0 + i * 5

    def case(self, name, depth, *, top=250, clusters=CALM_MAP):
        return ta.Case(name, MINT, self.accounts, self.funded, top=top, pairs=[{"pairAddress": POOL, "pairCreatedAt": LAUNCH * 1000}],
                       inputs={"--bubblemaps-json": ta._map(MINT, clusters, age=2.0), "--acquisition-json": self.acq},
                       collector_args=["--funders-top", str(depth)])


def farm_below_100(depth):
    """Ranks 1-100 independent; ranks 101-160 the farm (60 wallets, about 11% of supply); ranks 161-250 independent."""
    t = _Token()
    for i in range(100):
        t.independent(700.0 - i)
    t.farm(60, 200.0)
    for i in range(90):
        t.independent(100.0 - i * 0.01)
    return t.case(f"farm_below_100_depth_{depth}", depth)


def farm_inside_100(depth):
    """The same farm at ranks 41-100, inside the funded-by depth, plus an independent tail at ranks 101-250."""
    t = _Token()
    for i in range(40):
        t.independent(700.0 - i)
    t.farm(60, 300.0)
    for i in range(150):
        t.independent(100.0 - i * 0.01)
    return t.case(f"farm_inside_100_depth_{depth}", depth)


def quiet(depth, tail, *, tail_amount=100.0, clusters=CALM_MAP):
    """Ranks 1-100 independent and `tail` independent wallets below them; holders.json lists all of them."""
    t = _Token()
    for i in range(100):
        t.independent(700.0 - i)
    for i in range(tail):
        t.independent(tail_amount - i * 0.01)
    return t.case(f"quiet_tail_{tail}_depth_{depth}", depth, top=100 + tail, clusters=clusters)


def _assessment(r):
    return json.loads(r["assess_files"]["assessment.json"])


def _summary_note(report):
    return next((ln for ln in report.splitlines() if ln.startswith("- Note: ")), "")


# ----------------------------------------------------------------------------- end to end (report, funders + assess)

class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tail_small = hf.COHORT_MIN_WALLETS_FLOOR - 1  # below both bars: fewer wallets than the supply route's floor
        cls.r = {}
        with tempfile.TemporaryDirectory() as tmp:
            for key, case in (
                ("farm100", farm_below_100(100)), ("farm250", farm_below_100(250)),
                ("inside100", farm_inside_100(100)), ("inside250", farm_inside_100(250)),
                ("quiet100", quiet(100, 150)), ("quiet250", quiet(250, 150)),
                ("small100", quiet(100, tail_small, tail_amount=215.0)), ("smallfull", quiet(100 + tail_small, tail_small, tail_amount=215.0)),
                ("alarm100", quiet(100, 150, clusters=ALARM_MAP)), ("alarm250", quiet(250, 150, clusters=ALARM_MAP)),
            ):
                keep = Path(tmp) / key
                r = ta.equivalence(case, keep_dir=keep)
                # the unchecked set, derived from the collector's saved files only (holders.json + funders.json)
                r["unchecked"] = hf.unchecked_listed(json.loads((keep / "run" / "holders.json").read_text()), json.loads((keep / "run" / "funders.json").read_text()))
                cls.r[key] = r

    def test_every_case_runs_offline_and_assess_matches_report(self):
        for key, r in self.r.items():
            with self.subTest(key):
                self.assertEqual((r["exit_report"], r["exit_funders"], r["exit_assess"], r["exit_assess_copy"]), (0, 0, 0, 0), r["assess_stderr"])
                self.assertEqual(r["refused_calls"], 0, "assess tried the network or a key")
                self.assertTrue(r["assessment_identical"] and r["assessment_identical_copy"])
                self.assertEqual(ta.undocumented(r["report_diffs"]), [])

    def test_criterion_1_farm_below_the_depth_reads_limited_with_the_reason(self):
        a = _assessment(self.r["farm100"])
        self.assertEqual(a["coverage"]["examined_wallets"], 100)
        u = self.r["farm100"]["unchecked"]
        self.assertEqual((u["checked"], u["wallets"], u["first"], u["last"], u["share_unknown_wallets"]), (100, 150, 101, 250, 0))
        self.assertGreaterEqual(a["coverage"]["covered_noninfra_pct"], hf.COVERAGE_MIN_SUPPLY_PCT)  # the coverage bar alone lets it through
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_LIMITED)
        self.assertEqual(a["flag"]["label"], hf.FLAG_NONE)
        self.assertEqual(len(a["verdict"]["reasons"]), 1)
        reason = a["verdict"]["reasons"][0]
        self.assertEqual(a["verdict"]["no_alarm_blockers"], [reason])
        self.assertRegex(reason, r"^funding was checked on the top 100 holders only; 150 holders ranked 101-250 \(\d+\.\d+% of supply\) were not checked, "
                                 r"enough to hide a cohort the detector would flag$")
        report = self.r["farm100"]["assess_files"]["report.md"]
        self.assertIn(f"- FLAG: {hf.FLAG_NONE}", report)
        self.assertIn(f"- {reason}", report)  # the Underlying level section lists it
        self.assertEqual(_summary_note(report), f"- Note: coverage is limited: {reason}")  # whole, never cut, in the summary
        self.assertIn("- Could not read: funding lookups below the top 100 holders (funded-by depth).", report)  # never "nothing"
        self.assertIn("rerun funded-by with a larger --funders-top", report)  # What to do next names the right flag
        self.assertNotIn("add a second independent cluster source", report)

    def test_criterion_1_the_same_farm_at_full_depth_is_high(self):
        a = _assessment(self.r["farm250"])
        self.assertEqual((a["verdict"]["level"], a["flag"]["label"]), (hf.VERDICT_HIGH, hf.FLAG_DANGER))
        self.assertFalse(any(r.startswith(hf.DEPTH_GUARD_START) for r in a["verdict"]["reasons"]))

    def test_criterion_2_a_tail_below_both_bars_keeps_no_alarm(self):
        a = _assessment(self.r["small100"])
        self.assertEqual(a["coverage"]["examined_wallets"], 100)
        u = self.r["small100"]["unchecked"]
        self.assertEqual((u["checked"], u["wallets"]), (100, hf.COHORT_MIN_WALLETS_FLOOR - 1))
        self.assertLess(u["supply_pct"], hf.COHORT_MIN_SUPPLY_PCT)
        self.assertAlmostEqual(u["supply_pct"], 1.0, delta=0.1)  # the ticket's example: 4 wallets, about 1% of supply
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_NO_ALARM)
        self.assertEqual(a["verdict"]["no_alarm_blockers"], [])
        self.assertNotIn("(funded-by depth)", self.r["small100"]["assess_files"]["report.md"])

    def test_criterion_3_full_depth_is_unchanged(self):
        for key, level in (("quiet250", hf.VERDICT_NO_ALARM), ("smallfull", hf.VERDICT_NO_ALARM), ("farm250", hf.VERDICT_HIGH)):
            with self.subTest(key):
                a = _assessment(self.r[key])
                self.assertEqual(a["verdict"]["level"], level)
                self.assertEqual(self.r[key]["unchecked"]["wallets"], 0)  # every listed ordinary holder was looked up
                self.assertFalse(any(DEPTH_RE.search(r) for r in a["verdict"]["reasons"]))
        self.assertEqual(_assessment(self.r["quiet100"])["verdict"]["level"], hf.VERDICT_LIMITED)  # the same token at depth 100

    def test_criterion_4_raised_flags_never_change(self):
        for cut, full, level in (("alarm100", "alarm250", hf.VERDICT_UNRESOLVED), ("inside100", "inside250", hf.VERDICT_HIGH)):
            with self.subTest(cut):
                a, b = _assessment(self.r[cut]), _assessment(self.r[full])
                self.assertEqual(a["coverage"]["examined_wallets"], 100)
                self.assertEqual(self.r[cut]["unchecked"]["wallets"], 150)  # the guard's condition holds, yet nothing moves
                self.assertEqual(a["verdict"]["level"], level)
                self.assertEqual(a["verdict"], b["verdict"])
                self.assertEqual(a["flag"], b["flag"])
                self.assertFalse(any(DEPTH_RE.search(r) for r in a["verdict"]["reasons"]))
                for text in (hf.DEPTH_GUARD_START, "(funded-by depth)", "--funders-top"):
                    self.assertNotIn(text, self.r[cut]["assess_files"]["report.md"])
        dis = _assessment(self.r["alarm100"])["verdict"]["disagreement"]
        self.assertEqual(dis["disagreeing"], ["own detectors"])  # the depth guard does not touch the own level the disagreement rule reads

    def test_criterion_6_no_reassuring_words_and_no_key(self):
        for key, r in self.r.items():
            with self.subTest(key):
                self.assertIsNone(ta.REASSURING_WORDS.search(r["assess_files"]["report.md"]))
                self.assertNotIn(ta.SECRET, r["assess_files"]["report.md"] + r["assess_files"]["assessment.json"] + r["assess_stdout"] + r["assess_stderr"])


DEPTH_RE = re.compile(r"^funding was checked on the top \d+ holders only")


# ----------------------------------------------------------------------------- the rule itself (pure)

def listed(checked, tail_shares, *, infra_rows=(), pool_rows=()):
    """holders.json top_holders with `checked` ordinary wallets that funded-by looked up, then the tail (shares in % of
    total supply; None = unknown) and, inside the tail range, rows marked infrastructure (`infra_rows`) or listed in
    pool_addresses only (`pool_rows`). Returns (holders, funders) as assess receives them."""
    rows, rank = [], 0
    ordinary = [(addr(i), 1.0) for i in range(checked)] + [(addr(500 + i), s) for i, s in enumerate(tail_shares)]
    pools = [addr(800 + i) for i in range(len(pool_rows))]
    marked = [addr(900 + i) for i in range(len(infra_rows))]
    for w, s in ordinary[:checked]:
        rank += 1
        rows.append({"rank": rank, "wallet": w, "share_pct": s, "infrastructure": False})
    for w, s in list(zip(marked, infra_rows)) + list(zip(pools, pool_rows)):
        rank += 1
        rows.append({"rank": rank, "wallet": w, "share_pct": s, "infrastructure": w in marked})
    for w, s in ordinary[checked:]:
        rank += 1
        rows.append({"rank": rank, "wallet": w, "share_pct": s, "infrastructure": False})
    holders = {"pool_addresses": pools, "top_holders": rows}
    funders = {"rows": [{"wallet": w} for w, _ in ordinary[:checked]]}
    return holders, funders


def reason(checked, tail_shares, **kw):
    return hf.depth_guard_reason(hf.unchecked_listed(*listed(checked, tail_shares, **kw)))


PEERS = [{"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 1.0, "data_age_min": 1.0}]


class RuleTests(unittest.TestCase):
    def test_wallet_bar_is_the_detectors_own(self):
        n = hf.COHORT_MIN_WALLETS
        self.assertIsNone(reason(100, [0.001] * (n - 1)))
        self.assertIsNotNone(reason(100, [0.001] * n))

    def test_supply_bar_needs_the_wallet_floor(self):
        floor, bar = hf.COHORT_MIN_WALLETS_FLOOR, hf.COHORT_MIN_SUPPLY_PCT
        self.assertIsNotNone(reason(100, [bar / floor] * floor))             # exactly at the supply bar with the floor
        self.assertIsNone(reason(100, [bar / floor * 0.998] * floor))        # just under the supply bar
        self.assertIsNone(reason(100, [10 * bar / (floor - 1)] * (floor - 1)))  # far over the bar, one wallet under the floor

    def test_ticket_example_four_wallets_one_percent(self):
        self.assertIsNone(reason(100, [0.25] * 4))

    def test_patching_the_detector_constants_moves_the_guard(self):
        n, floor, bar = hf.COHORT_MIN_WALLETS, hf.COHORT_MIN_WALLETS_FLOOR, hf.COHORT_MIN_SUPPLY_PCT
        with mock.patch.object(hf, "COHORT_MIN_WALLETS", n + 1):
            self.assertIsNone(reason(100, [0.001] * n))
        with mock.patch.object(hf, "COHORT_MIN_WALLETS", n - 1):
            self.assertIsNotNone(reason(100, [0.001] * (n - 1)))
        with mock.patch.object(hf, "COHORT_MIN_SUPPLY_PCT", bar + 0.5):
            self.assertIsNone(reason(100, [bar / floor] * floor))
        with mock.patch.object(hf, "COHORT_MIN_SUPPLY_PCT", bar - 0.5):
            self.assertIsNotNone(reason(100, [bar / floor * 0.998] * floor))
        with mock.patch.object(hf, "COHORT_MIN_WALLETS_FLOOR", floor + 1):
            self.assertIsNone(reason(100, [bar / floor] * floor))

    def test_pools_and_infrastructure_rows_are_never_counted(self):
        floor, bar = hf.COHORT_MIN_WALLETS_FLOOR, hf.COHORT_MIN_SUPPLY_PCT
        few = [0.25] * (floor - 1)  # below both bars on their own
        big = [bar] * hf.COHORT_MIN_WALLETS  # would pass both bars if counted
        for kw in ({"infra_rows": big}, {"pool_rows": big}, {"infra_rows": big, "pool_rows": big}):
            with self.subTest(kw=list(kw)):
                u = hf.unchecked_listed(*listed(100, few, **kw))
                self.assertEqual((u["wallets"], u["checked"], u["first"], u["last"]), (floor - 1, 100, 101, 100 + floor - 1))
                self.assertAlmostEqual(u["supply_pct"], sum(few))
                self.assertIsNone(hf.depth_guard_reason(u))

    def test_ranks_count_ordinary_holders_only(self):
        r = reason(100, [0.1] * 150, pool_rows=[0.5] * 3)
        self.assertIn("150 holders ranked 101-250 (15.0% of supply)", r)

    def test_full_depth_and_no_funders_give_no_reason(self):
        self.assertIsNone(reason(250, []))
        self.assertIsNone(hf.unchecked_listed(listed(100, [1.0] * 150)[0], None))
        self.assertIsNone(hf.depth_guard_reason(None))

    def test_unknown_share_is_never_printed_as_zero(self):
        floor, n = hf.COHORT_MIN_WALLETS_FLOOR, hf.COHORT_MIN_WALLETS
        all_unknown = reason(100, [None] * floor)  # could be large: blocks with the floor of wallets
        self.assertIn(f"{floor} holders ranked 101-{100 + floor} (supply share unknown)", all_unknown)
        some = reason(100, [None, 0.5] + [None] * (floor - 2))
        self.assertIn(f"(at least 0.5% of supply, share unknown for {floor - 1})", some)
        tiny = reason(100, [0.0001] * n)  # known but tiny: not rounded to 0
        self.assertIn("(under 0.01% of supply)", tiny)
        for text in (all_unknown, some, tiny):
            self.assertNotRegex(text, r"\(0(\.0+)?% ")
            self.assertIsNone(ta.REASSURING_WORDS.search(text))
        self.assertIsNone(reason(100, [None] * (floor - 1)))  # under the floor, even unknown cannot form the supply route


class DecideVerdictTests(unittest.TestCase):
    def cov(self, **kw):
        return hf.coverage_block(holders_dict(), funders_dict(**kw))

    def unchecked(self, wallets):
        return hf.unchecked_listed(*listed(100, [0.1] * wallets))

    def test_no_alarm_moves_to_limited_with_the_reason_only(self):
        self.assertEqual(hf.decide_verdict(self.cov(), ran(), [], PEERS)["level"], hf.VERDICT_NO_ALARM)
        v = hf.decide_verdict(self.cov(), ran(), [], PEERS, unchecked=self.unchecked(150))
        self.assertEqual(v["level"], hf.VERDICT_LIMITED)
        self.assertEqual(len(v["no_alarm_blockers"]), 1)
        self.assertTrue(v["no_alarm_blockers"][0].startswith(hf.DEPTH_GUARD_START))
        flag = hf.flag_for(v, PEERS)
        self.assertEqual(flag["label"], hf.FLAG_NONE)
        self.assertEqual(flag["caveat"], f"coverage is limited: {v['reasons'][0]}")

    def test_nothing_unchecked_is_exactly_the_old_verdict(self):
        for kw, peers in (({}, PEERS), ({}, []), ({"covered": 30.0}, PEERS), ({"aborted": "credit budget reached"}, PEERS)):
            with self.subTest(kw=kw, peers=len(peers)):
                self.assertEqual(hf.decide_verdict(self.cov(**kw), ran(), [], peers, unchecked=self.unchecked(0)),
                                 hf.decide_verdict(self.cov(**kw), ran(), [], peers))
                self.assertEqual(hf.decide_verdict(self.cov(**kw), ran(), [], peers, unchecked=None), hf.decide_verdict(self.cov(**kw), ran(), [], peers))

    def test_raised_flags_are_identical_with_or_without_the_guard(self):
        alarm = [{"provider": "bubblemaps_map", "status": "ok", "largest_cluster_pct": 20.0, "data_age_min": 1.0}]
        for name, args, kw in (
            ("own alarm", ([], ["funder-batch FACTORY_PATTERN STRONG"]), {}),
            ("own unresolved", ([], []), {"own_unresolved": ["funding-time cohort (helius): 6 wallets; UNRESOLVED, not HIGH"]}),
            ("provider alarm, own calm", (alarm, []), {}),
        ):
            with self.subTest(name):
                findings, own_alarms = args
                old = hf.decide_verdict(self.cov(), ran(), own_alarms, findings, **kw)
                new = hf.decide_verdict(self.cov(), ran(), own_alarms, findings, unchecked=self.unchecked(150), **kw)
                self.assertIn(old["level"], (hf.VERDICT_HIGH, hf.VERDICT_UNRESOLVED))
                self.assertEqual(new, old)
                self.assertEqual(hf.flag_for(new, findings), hf.flag_for(old, findings))

    def test_limited_keeps_every_other_blocker(self):
        old = hf.decide_verdict(self.cov(covered=30.0), ran(), [], [])
        new = hf.decide_verdict(self.cov(covered=30.0), ran(), [], [], unchecked=self.unchecked(150))
        self.assertEqual(new["level"], hf.VERDICT_LIMITED)
        self.assertEqual([r for r in new["no_alarm_blockers"] if not r.startswith(hf.DEPTH_GUARD_START)], old["no_alarm_blockers"])
        self.assertEqual(len(new["no_alarm_blockers"]), len(old["no_alarm_blockers"]) + 1)

    def test_next_step_points_to_funders_top_once(self):
        """Amendment: under the coverage bar the advice is --funders-top (the funded-by depth since PR #202), never "raise
        --top to check more wallets"; with the depth reason too, one --funders-top step, not two."""
        for covered, unchecked, depth_step in ((30.0, 0, False), (30.0, 150, False), (80.0, 150, True)):
            with self.subTest(covered=covered, unchecked=unchecked):
                cov = self.cov(covered=covered)
                step = hf.next_step({"verdict": hf.decide_verdict(cov, ran(), [], PEERS, unchecked=self.unchecked(unchecked)), "coverage": cov})
                self.assertNotIn("raise --top to check", step)
                self.assertEqual(step.count("raise --funders-top") + step.count("rerun funded-by with a larger --funders-top"), 1)
                self.assertEqual("rerun funded-by with a larger --funders-top" in step, depth_step)
                self.assertIn(f"{hf.COST_FUNDED_BY} Helius credits a wallet; the owner decides", step)
                self.assertIsNone(ta.REASSURING_WORDS.search(step))


if __name__ == "__main__":
    unittest.main()
