"""DS-SPLIT-GUARD-T1: NO_ALARM is not allowed when a cohort could be split across the funded-by depth.

Owner decisions: 2026-10-29 "Detector's own bar (Recommended)" (the depth guard) and "do the next stuff" (this ticket). The
depth guard (DS-DEPTH-GUARD-T1) compares the unchecked listed holders ALONE with the detector's bars. When fewer of them
are unchecked (a small token, or --funders-top close to the listed count), a farm can sit half above and half below the
depth. These tests prove, offline (fakes only, frozen clock, dummy key; assess runs with sockets refused and no key):
(1) a farm of 10 checked wallets (ranks 91-100, one funding window) plus 10 unchecked (ranks 101-110) reads LIMITED with
    the reason, never NO_ALARM; without this guard it read NO_ALARM; at full depth the same farm is HIGH;
(2) checked windows plus the unchecked tail that stay under both bars keep NO_ALARM possible;
(3) full depth (nothing unchecked) gives exactly the verdict decided without the guard;
(4) raised flags never change and never carry the reason;
(5) the guard reads COHORT_MIN_WALLETS, COHORT_MIN_SUPPLY_PCT, COHORT_MIN_WALLETS_FLOOR and COHORT_WINDOW_S at call time;
(6) it searches the detector's own rows (same wallets, same first-funding times; rows the detector skips are skipped,
    reported cohort members are left out) through detect_cohorts itself, whose output does not change;
(7) the wording: no clean, low or safe; an unknown share is never printed as 0; the summary Note shows the whole reason,
    and the Could not read and What to do next lines name the funded-by depth."""

from __future__ import annotations

import copy
import json
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
from test_depth_guard import ALARM_MAP, CALM_MAP, PEERS, _Token  # noqa: E402
from test_holder_forensics import MINT, addr  # noqa: E402
from test_parallel_rows import funder_addr  # noqa: E402
from test_verdict_gating import funders_dict, holders_dict, ran  # noqa: E402

T0 = 1_790_000_000
SPLIT_RE = re.compile(r"^funding was checked on the top \d+ holders only; (?:\d+ checked holders funded within [\d.]+ h|1 checked holder) \(.+\) "
                      r"plus \d+ unchecked ranked \d+(?:-\d+)? \(.+\) may be a split cohort$")


def _assessment(r):
    return json.loads(r["assess_files"]["assessment.json"])


def _line(report, prefix):
    return next((ln for ln in report.splitlines() if ln.startswith(prefix)), "")


# ----------------------------------------------------------------------------- synthetic scans (fakes only)

def split_token(checked, unchecked, depth, *, clusters=CALM_MAP):
    """A small token: 100 - `checked` independent wallets, then one farm of checked + unchecked wallets (6 unlabeled funders,
    funded 5 s apart, buying the same second, about 0.04% of supply each). holders.json lists every holder (fewer than
    250), so with --funders-top 100 the farm's first `checked` wallets are looked up and the rest are not."""
    t = _Token()
    for i in range(100 - checked):
        t.independent(700.0 - i)
    t.farm(checked + unchecked, 30.0)
    return t.case(f"split_{checked}_{unchecked}_depth_{depth}", depth, clusters=clusters)


def without_guard():
    return mock.patch.object(hf, "split_guard_reason", return_value=None)


def same_output(a, b):
    """assessment.json byte-identical, and report.md identical but for the documented lines (the collector files' save time)."""
    return a["assess_files"]["assessment.json"] == b["assess_files"]["assessment.json"] and not ta.undocumented(
        ta.report_differences(a["assess_files"]["report.md"], b["assess_files"]["report.md"]))


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        below = hf.COHORT_MIN_WALLETS - 1 - 10  # checked farm wallets that, with the 10 unchecked, stay one under the wallet bar
        cls.r = {}
        with tempfile.TemporaryDirectory() as tmp:
            for key, case, guard in (
                ("split100", split_token(10, 10, 100), True), ("split100_before", split_token(10, 10, 100), False),
                ("splitfull", split_token(10, 10, 250), True), ("splitfull_before", split_token(10, 10, 250), False),
                ("below100", split_token(below, 10, 100), True),
                ("alarm100", split_token(10, 10, 100, clusters=ALARM_MAP), True), ("alarm100_before", split_token(10, 10, 100, clusters=ALARM_MAP), False),
            ):
                keep = Path(tmp) / key
                if guard:
                    r = ta.equivalence(case, keep_dir=keep)
                else:
                    with without_guard():
                        r = ta.equivalence(case, keep_dir=keep)
                hraw, fraw = json.loads((keep / "run" / "holders.json").read_text()), json.loads((keep / "run" / "funders.json").read_text())
                r["unchecked"] = hf.unchecked_listed(hraw, fraw)
                holders, _ = hf.load_run_holders(hraw, MINT)
                r["funders"] = hf.load_run_funders(fraw, holders, case.inputs["--acquisition-json"])
                r["holders"] = holders
                cls.r[key] = r

    def test_every_case_runs_offline_and_assess_matches_report(self):
        for key, r in self.r.items():
            with self.subTest(key):
                self.assertEqual((r["exit_report"], r["exit_funders"], r["exit_assess"], r["exit_assess_copy"]), (0, 0, 0, 0), r["assess_stderr"])
                self.assertEqual(r["refused_calls"], 0, "assess tried the network or a key")
                self.assertTrue(r["assessment_identical"] and r["assessment_identical_copy"])
                self.assertEqual(ta.undocumented(r["report_diffs"]), [])

    def test_criterion_1_split_farm_reads_limited_with_the_reason(self):
        u = self.r["split100"]["unchecked"]
        self.assertEqual((u["checked"], u["wallets"], u["first"], u["last"]), (100, 10, 101, 110))
        self.assertIsNone(hf.depth_guard_reason(u))  # the tail alone is under the bar: the depth guard cannot see this farm
        before, after = _assessment(self.r["split100_before"]), _assessment(self.r["split100"])
        self.assertEqual(before["verdict"]["level"], hf.VERDICT_NO_ALARM)  # without the guard
        self.assertEqual(after["verdict"]["level"], hf.VERDICT_LIMITED)
        self.assertEqual(after["flag"]["label"], hf.FLAG_NONE)
        self.assertEqual(len(after["verdict"]["reasons"]), 1)
        reason = after["verdict"]["reasons"][0]
        self.assertEqual(after["verdict"]["no_alarm_blockers"], [reason])
        self.assertRegex(reason, r"^funding was checked on the top 100 holders only; 10 checked holders funded within 6 h \(0\.\d+% of supply\) "
                                 r"plus 10 unchecked ranked 101-110 \(0\.\d+%\) may be a split cohort$")
        report = self.r["split100"]["assess_files"]["report.md"]
        self.assertIn(f"- FLAG: {hf.FLAG_NONE}", report)
        self.assertIn(f"- {reason}", report)  # the Underlying level section lists it
        self.assertEqual(_line(report, "- Note: "), f"- Note: coverage is limited: {reason}")  # whole, never cut, in the summary
        self.assertIn("- Could not read: funding lookups below the top 100 holders (funded-by depth).", report)
        self.assertIn("rerun funded-by with a larger --funders-top", _line(report, "- What to do next:"))
        self.assertNotIn("add a second independent cluster source", report)
        # everything but the verdict, its reasons and the lines that print them is the same as without the guard
        self.assertEqual({k: v for k, v in after.items() if k not in ("verdict", "flag")}, {k: v for k, v in before.items() if k not in ("verdict", "flag")})
        self.assertEqual(after["flag"]["label"], before["flag"]["label"])

    def test_criterion_1_the_same_farm_at_full_depth_is_high(self):
        a = _assessment(self.r["splitfull"])
        self.assertEqual(self.r["splitfull"]["unchecked"]["wallets"], 0)
        self.assertEqual((a["verdict"]["level"], a["flag"]["label"]), (hf.VERDICT_HIGH, hf.FLAG_DANGER))
        self.assertEqual(self.r["splitfull"]["funders"]["cohorts"]["cohorts"][0]["wallets"], 20)  # the detector finds the whole farm

    def test_criterion_2_below_both_bars_keeps_no_alarm(self):
        r = self.r["below100"]
        u = r["unchecked"]
        self.assertEqual((u["checked"], u["wallets"]), (100, 10))
        self.assertLess(u["supply_pct"], hf.COHORT_MIN_SUPPLY_PCT)
        a = _assessment(r)
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_NO_ALARM)
        self.assertEqual(a["verdict"]["no_alarm_blockers"], [])
        self.assertNotIn("(funded-by depth)", r["assess_files"]["report.md"])

    def test_criterion_3_full_depth_is_unchanged(self):
        self.assertEqual(self.r["splitfull"]["unchecked"]["wallets"], 0)
        self.assertTrue(same_output(self.r["splitfull"], self.r["splitfull_before"]))

    def test_criterion_4_raised_flags_never_change(self):
        a, b = _assessment(self.r["alarm100"]), _assessment(self.r["alarm100_before"])
        self.assertEqual(self.r["alarm100"]["unchecked"]["wallets"], 10)
        self.assertIsNotNone(hf.split_guard_reason(self.r["alarm100"]["unchecked"]))  # the guard's condition holds, yet nothing moves
        self.assertEqual(a["verdict"]["level"], hf.VERDICT_UNRESOLVED)
        self.assertTrue(same_output(self.r["alarm100"], self.r["alarm100_before"]))
        self.assertEqual(a["verdict"]["disagreement"]["disagreeing"], ["own detectors"])
        self.assertFalse(any(SPLIT_RE.search(x) for x in a["verdict"]["reasons"]))
        self.assertEqual(a["flag"], b["flag"])

    def test_criterion_6_the_guard_searches_the_detectors_own_rows(self):
        """checked_rows are the rows funders_result gave the cohort detector (build_records + helius_cohort_rows from the
        holder balances): same wallets, same order, same first-funding times; shares as saved in funders.json rows."""
        for key in ("split100", "below100", "alarm100"):
            with self.subTest(key):
                r = self.r[key]
                funded = {row["wallet"]: {"funder": row["funder"], "timestamp": row["funded_at"]} for row in r["funders"]["rows"] if row["status"] == "funded"}
                detector_rows = hf.helius_cohort_rows(hf.build_records(r["holders"]["_balances"], funded))
                guard_rows = hf.unchecked_listed(hf._public(r["holders"]), r["funders"])["checked_rows"]
                self.assertEqual([(x["wallet"], x["first_funding_time"]) for x in guard_rows], [(x["wallet"], x["first_funding_time"]) for x in detector_rows])
                for g, d in zip(guard_rows, detector_rows):
                    self.assertAlmostEqual(g["supply_pct"], d["supply_pct"], places=4)
                self.assertEqual(r["funders"]["cohorts"]["cohorts"], [])  # no reported cohort to leave out here
                self.assertEqual(hf.detect_cohorts(guard_rows), [])

    def test_criterion_7_no_reassuring_words_and_no_key(self):
        for key, r in self.r.items():
            with self.subTest(key):
                self.assertIsNone(ta.REASSURING_WORDS.search(r["assess_files"]["report.md"]))
                self.assertNotIn(ta.SECRET, r["assess_files"]["report.md"] + r["assess_files"]["assessment.json"] + r["assess_stdout"] + r["assess_stderr"])


# ----------------------------------------------------------------------------- the rule itself (pure)

def scan(window, tail, *, spread_s=60, others=0, cohorts=(), statuses=None, times=None, funders=None):
    """holders.json top_holders and funders.json rows as assess receives them. `window`: shares (% of total supply) of the
    checked wallets first funded `spread_s` apart in one window; `others`: checked wallets funded 30 days apart (outside
    any window, 0.01% each); `tail`: shares of the unchecked listed holders below them (None = unknown). `statuses`,
    `times` and `funders` override a checked row's status, funded_at or funder by position (applied in that order)."""
    checked = [(addr(i), s) for i, s in enumerate(window)] + [(addr(300 + i), 0.01) for i in range(others)]
    tail_rows = [(addr(600 + i), s) for i, s in enumerate(tail)]
    holders = {"pool_addresses": [], "top_holders": [{"rank": n, "wallet": w, "share_pct": s, "infrastructure": False}
                                                     for n, (w, s) in enumerate(checked + tail_rows, 1)]}
    rows = []
    for i, (w, s) in enumerate(checked):
        t = T0 + i * spread_s if i < len(window) else T0 - (i + 1) * 30 * 86_400
        row = {"rank": i + 1, "wallet": w, "share_pct": s, "status": "funded", "funder": funder_addr(f"S{i % 6}"), "funder_name": None,
               "funder_type": None, "funded_at": t, "funded_at_utc": None, "first_amount_sol": 1.0}
        if statuses and i in statuses:
            row.update(status=statuses[i], funder=None if statuses[i] != "funded" else row["funder"], funded_at=None if statuses[i] != "funded" else t)
        if times and i in times:
            row["funded_at"] = times[i]
        if funders and i in funders:
            row["funder"] = funders[i]
        rows.append(row)
    return holders, {"rows": rows, "cohorts": {"coverage": {}, "cohorts": [{"members": list(m)} for m in cohorts]}}


def split(window, tail, **kw):
    return hf.split_guard_reason(hf.unchecked_listed(*scan(window, tail, **kw)))


TINY = 0.01  # % of supply: far under the supply bar however many are added here


class RuleTests(unittest.TestCase):
    def test_wallet_bar_counts_both_sides_of_the_depth(self):
        n = hf.COHORT_MIN_WALLETS
        self.assertIsNotNone(split([TINY] * 10, [TINY] * (n - 10)))
        self.assertIsNone(split([TINY] * 9, [TINY] * (n - 10)))
        self.assertIsNone(split([TINY] * 10, [TINY] * (n - 11)))
        self.assertIsNotNone(split([TINY] * (n - 1), [TINY]))  # near-full --funders-top: one unchecked holder

    def test_supply_bar_counts_both_shares_and_needs_the_floor(self):
        floor, bar = hf.COHORT_MIN_WALLETS_FLOOR, hf.COHORT_MIN_SUPPLY_PCT
        k = floor - 1  # with the one unchecked holder: exactly the floor of wallets
        self.assertIsNotNone(split([bar / 8] * 4 + [0.0] * (k - 4), [bar / 2]))        # together exactly at the supply bar
        self.assertIsNone(split([bar / 8 * 0.99] * 4 + [0.0] * (k - 4), [bar / 2]))    # just under the supply bar
        self.assertIsNone(split([bar] * (k - 1), [bar / 2]))                             # far over the bar, one wallet under the floor
        self.assertIsNone(split([bar / 8] * 4 + [0.0] * (k - 4), [TINY]))               # the tail's share is part of the bar

    def test_an_unknown_unchecked_share_counts_as_large(self):
        floor = hf.COHORT_MIN_WALLETS_FLOOR
        self.assertIsNotNone(split([TINY] * (floor - 2), [None, None]))
        self.assertIsNone(split([TINY] * (floor - 3), [None, None]))  # still needs the floor of wallets
        self.assertIsNone(split([TINY] * (floor - 2), [TINY, TINY]))  # the same with known tiny shares

    def test_the_window_is_the_detectors(self):
        n, w = hf.COHORT_MIN_WALLETS, hf.COHORT_WINDOW_S
        self.assertIsNotNone(split([TINY] * 10, [TINY] * (n - 10), spread_s=w // 9))       # 10 wallets spanning exactly one window
        self.assertIsNone(split([TINY] * 10, [TINY] * (n - 10), spread_s=w // 9 + 1))      # one second wider: no window holds 10
        self.assertIsNone(split([], [TINY] * (n - 2), others=n))                           # many checked, each in its own window
        self.assertIsNotNone(split([], [TINY] * (n - 1), others=1))  # with n - 1 unchecked, one checked wallet reaches the wallet bar

    def test_patching_each_detector_constant_moves_the_guard(self):
        n, floor, bar, w = hf.COHORT_MIN_WALLETS, hf.COHORT_MIN_WALLETS_FLOOR, hf.COHORT_MIN_SUPPLY_PCT, hf.COHORT_WINDOW_S
        at_supply_bar = [bar / 8] * 4 + [0.0] * (floor - 5)
        cases = (
            ("COHORT_MIN_WALLETS", n + 1, lambda: split([TINY] * 10, [TINY] * (n - 10))),
            ("COHORT_MIN_SUPPLY_PCT", bar + 0.5, lambda: split(at_supply_bar, [bar / 2])),
            ("COHORT_MIN_WALLETS_FLOOR", floor + 1, lambda: split(at_supply_bar, [bar / 2])),
            ("COHORT_WINDOW_S", w - 1, lambda: split([TINY] * 10, [TINY] * (n - 10), spread_s=w // 9)),
        )
        for name, value, probe in cases:
            with self.subTest(name):
                self.assertIsNotNone(probe())
                with mock.patch.object(hf, name, value):
                    self.assertIsNone(probe())
        with mock.patch.object(hf, "COHORT_MIN_WALLETS", n - 1):
            self.assertIsNotNone(split([TINY] * 9, [TINY] * (n - 10)))
        with mock.patch.object(hf, "COHORT_WINDOW_S", w * 2):
            self.assertIsNotNone(split([TINY] * 10, [TINY] * (n - 10), spread_s=w // 9 * 2))
            self.assertIn(f"funded within {w * 2 / 3600:g} h", split([TINY] * 10, [TINY] * (n - 10)))

    def test_rows_the_detector_skips_are_skipped(self):
        n = hf.COHORT_MIN_WALLETS
        window, tail = [TINY] * 10, [TINY] * (n - 10)
        self.assertIsNotNone(split(window, tail))
        for name, kw, rows in (("no funding record", {"statuses": {3: "no_funding_record"}}, 9), ("failed", {"statuses": {3: "failed"}}, 9),
                               ("not reached", {"statuses": {3: "not_reached"}}, 9), ("no first-funding time", {"times": {3: None}}, 9),
                               ("time not a number", {"times": {3: "2026-10-01"}}, 9), ("time is a bool", {"times": {3: True}}, 9),
                               ("time 0 (build_records keeps it, detect_cohorts skips it)", {"times": {3: 0}}, 10),
                               # rows build_records never makes a record of, even if they carry a time
                               ("failed row that still carries a time", {"statuses": {3: "failed"}, "times": {3: T0 + 180}}, 9),
                               ("no funding record that still carries a time", {"statuses": {3: "no_funding_record"}, "times": {3: T0 + 180}}, 9),
                               ("funded row with no funder address", {"funders": {3: None}}, 9)):
            with self.subTest(name):
                self.assertIsNone(split(window, tail, **kw))
                u = hf.unchecked_listed(*scan(window, tail, **kw))
                self.assertEqual(u["checked"], 10)  # still a checked holder: it has a funders.json row
                self.assertEqual(len(u["checked_rows"]), rows)

    def test_reported_cohort_members_are_left_out(self):
        n = hf.COHORT_MIN_WALLETS
        self.assertIsNone(split([TINY] * 10, [TINY] * (n - 10), cohorts=[[addr(0)]]))
        self.assertIsNotNone(split([TINY] * 11, [TINY] * (n - 10), cohorts=[[addr(0)]]))

    def test_nothing_unchecked_or_a_tail_over_the_bar_gives_no_split_reason(self):
        n = hf.COHORT_MIN_WALLETS
        self.assertIsNone(split([TINY] * 30, []))
        self.assertIsNone(hf.split_guard_reason(None))
        self.assertIsNone(hf.unchecked_listed(scan([TINY] * 10, [TINY])[0], None))
        u = hf.unchecked_listed(*scan([TINY] * 10, [TINY] * n))
        self.assertIsNotNone(hf.depth_guard_reason(u))
        self.assertIsNone(hf.split_guard_reason(u))  # the depth guard's own reason covers it

    def test_detect_cohorts_and_the_rows_are_untouched(self):
        holders, funders = scan([TINY] * 10, [TINY] * 10)
        u = hf.unchecked_listed(holders, funders)
        before = copy.deepcopy(u)
        self.assertIsNotNone(hf.split_guard_reason(u))
        self.assertEqual(u, before)
        self.assertEqual(hf.detect_cohorts(u["checked_rows"]), [])  # the detector's own result over these rows: no cohort
        self.assertEqual(hf.detect_cohorts.__kwdefaults__, {"window_s": hf.COHORT_WINDOW_S, "min_wallets": hf.COHORT_MIN_WALLETS,
                                                            "min_supply_pct": hf.COHORT_MIN_SUPPLY_PCT, "floor_wallets": hf.COHORT_MIN_WALLETS_FLOOR,
                                                            "require_similar_amounts": False, "launch_ts": None})

    def test_wording(self):
        n, h = hf.COHORT_MIN_WALLETS, f"{hf.COHORT_WINDOW_S / 3600:g}"
        self.assertEqual(split([0.1] * 10, [0.05] * (n - 10)),
                         f"funding was checked on the top 10 holders only; 10 checked holders funded within {h} h (1.0% of supply) "
                         f"plus {n - 10} unchecked ranked 11-{n} (0.5%) may be a split cohort")
        one = split([0.1] * (n - 1), [0.2])
        self.assertIn(f"plus 1 unchecked ranked {n} (0.2%) may be a split cohort", one)
        self.assertNotIn(f"{n}-{n}", one)
        single = split([2.0], [None] * (hf.COHORT_MIN_WALLETS_FLOOR - 1))  # a window of one wallet: no "funded within" for one wallet
        self.assertEqual(single, f"funding was checked on the top 1 holders only; 1 checked holder (2.0% of supply) plus {hf.COHORT_MIN_WALLETS_FLOOR - 1} "
                                 f"unchecked ranked 2-{hf.COHORT_MIN_WALLETS_FLOOR} (supply share unknown) may be a split cohort")
        whale = split([hf.COHORT_MIN_SUPPLY_PCT + 1.0], [TINY] * (hf.COHORT_MIN_WALLETS_FLOOR - 1))  # the supply route: one large checked holder
        self.assertIn(f"1 checked holder ({round(hf.COHORT_MIN_SUPPLY_PCT + 1.0, 2)}% of supply) plus", whale)
        for text in (split([0.1] * 10, [0.05] * (n - 10)), one, single, whale):
            self.assertRegex(text, SPLIT_RE)
            self.assertTrue(text.startswith(hf.DEPTH_GUARD_START))
            self.assertIsNone(ta.REASSURING_WORDS.search(text))

    def test_unknown_share_is_never_printed_as_zero(self):
        floor, n = hf.COHORT_MIN_WALLETS_FLOOR, hf.COHORT_MIN_WALLETS
        all_unknown = split([TINY] * (floor - 2), [None, None])
        self.assertIn("plus 2 unchecked ranked 4-5 (supply share unknown)", all_unknown)
        some = split([TINY] * (floor - 2), [None, 0.5])
        self.assertIn("(at least 0.5%, share unknown for 1)", some)
        tiny = split([0.0001] * 10, [0.0001] * (n - 10))
        self.assertIn("(under 0.01% of supply) plus", tiny)
        self.assertIn("(under 0.01%) may be", tiny)
        unknown_checked = hf.unchecked_listed(*scan([TINY] * 10, [TINY] * (n - 10)))
        for row in unknown_checked["checked_rows"][:3]:
            row["supply_pct"] = None
        h = f"{hf.COHORT_WINDOW_S / 3600:g}"
        self.assertIn(f"10 checked holders funded within {h} h (at least 0.07% of supply, share unknown for 3)", hf.split_guard_reason(unknown_checked))
        for row in unknown_checked["checked_rows"]:
            row["supply_pct"] = None
        self.assertIn(f"10 checked holders funded within {h} h (supply share unknown)", hf.split_guard_reason(unknown_checked))
        for text in (all_unknown, some, tiny):
            self.assertNotRegex(text, r"\(0(\.0+)?%")
            self.assertIsNone(ta.REASSURING_WORDS.search(text))


class DecideVerdictTests(unittest.TestCase):
    def cov(self, **kw):
        return hf.coverage_block(holders_dict(), funders_dict(**kw))

    def unchecked(self, k=10):
        return hf.unchecked_listed(*scan([TINY] * k, [TINY] * 10))

    def test_no_alarm_moves_to_limited_with_the_reason_only(self):
        self.assertEqual(hf.decide_verdict(self.cov(), ran(), [], PEERS, unchecked=self.unchecked(hf.COHORT_MIN_WALLETS - 11))["level"], hf.VERDICT_NO_ALARM)
        v = hf.decide_verdict(self.cov(), ran(), [], PEERS, unchecked=self.unchecked())
        self.assertEqual(v["level"], hf.VERDICT_LIMITED)
        self.assertEqual(len(v["no_alarm_blockers"]), 1)
        self.assertEqual(v["no_alarm_blockers"], [hf.split_guard_reason(self.unchecked())])
        flag = hf.flag_for(v, PEERS)
        self.assertEqual(flag["label"], hf.FLAG_NONE)
        self.assertEqual(flag["caveat"], f"coverage is limited: {v['reasons'][0]}")

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
                new = hf.decide_verdict(self.cov(), ran(), own_alarms, findings, unchecked=self.unchecked(), **kw)
                self.assertIn(old["level"], (hf.VERDICT_HIGH, hf.VERDICT_UNRESOLVED))
                self.assertEqual(new, old)
                self.assertEqual(hf.flag_for(new, findings), hf.flag_for(old, findings))

    def test_limited_keeps_every_other_blocker(self):
        old = hf.decide_verdict(self.cov(covered=30.0), ran(), [], [])
        new = hf.decide_verdict(self.cov(covered=30.0), ran(), [], [], unchecked=self.unchecked())
        self.assertEqual(new["level"], hf.VERDICT_LIMITED)
        self.assertEqual([r for r in new["no_alarm_blockers"] if not SPLIT_RE.search(r)], old["no_alarm_blockers"])
        self.assertEqual(len(new["no_alarm_blockers"]), len(old["no_alarm_blockers"]) + 1)

    def test_next_step_points_to_funders_top_once(self):
        for covered, depth_step in ((30.0, False), (80.0, True)):
            with self.subTest(covered=covered):
                cov = self.cov(covered=covered)
                step = hf.next_step({"verdict": hf.decide_verdict(cov, ran(), [], PEERS, unchecked=self.unchecked()), "coverage": cov})
                self.assertEqual(step.count("raise --funders-top") + step.count("rerun funded-by with a larger --funders-top"), 1)
                self.assertEqual("rerun funded-by with a larger --funders-top" in step, depth_step)
                self.assertIn(f"{hf.COST_FUNDED_BY} Helius credits a wallet; the owner decides", step)
                self.assertIsNone(ta.REASSURING_WORDS.search(step))


if __name__ == "__main__":
    unittest.main()
