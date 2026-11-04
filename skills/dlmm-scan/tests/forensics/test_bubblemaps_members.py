"""HS-BM-MEMBERS-T1: who is in each Bubblemaps cluster at scan time, and the pre-refresh cluster line (offline tests).

Fixtures (public data only, trimmed to the fields used; see each file's note):
- pokemon_address_list_live_20261020.json: a live read of the free map (2026-10-20, every cluster expanded, rows by list
  index), before and after a refresh, the default-window size read and the post-refresh settle polls;
- pokemon_bubblemaps_map_20261020.json: the Pokémon run's saved map file (16.21% pre-refresh, 12.33% refreshed);
- pokemon_cluster1_screenshot_members.json: Cluster 1 as the owner's screenshot shows it (8 holders, 3 linking);
- pokemon_holders_top_20261020.json, pokemon_gmgn_tags_20261020.json, pokemon_funders_names_20261020.json: that run's
  holder list, GMGN tags and first-funder names;
- proto_dkyc_members_20261020.json, proto_9a1v_members_20261020.json: the prototype's member reads with their holder lists.
No browser, no network, no key.
"""

from __future__ import annotations

import contextlib
import copy
import difflib
import io
import json
import os
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import bubblemaps_map as bm  # noqa: E402
import helius_forensics as hf  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
POK = "D42TjMjz5H7toPu5md5KBXreZkCSdZMEfLQwmBhJXvb1"
VERDICT_WORDS = re.compile(r"\b(clean|low|safe)\b", re.I)
OWNER_TABLE = [  # the owner's screenshot table (ticket HS-BM-MEMBERS-T1): map rank, full address, method
    (4, "DuARUpsEzdVbVpSnbGipLJvWxaXUCPLDJDjNov6Rc6s6", "prefix_suffix"),
    (5, "Be24Gbf5KisDk1LcWWZsBn8dvB816By7YzYF5zWZnRR6", "rank_share"),
    (6, "6DQAGJT7VZPVBsuG4kn3AvpyHCEi7B2RFFvMZdbqQqqP", "prefix_suffix"),
    (7, "79nMjs72wH4wDJXrHMK71UnfKPSaBmNHJ21kfh3KCDV3", "prefix_suffix"),
    (14, "5ppcc7wMNd7uHeMSu8ZyvdYCNnBgWzskJoxxHcHmz2kP", "prefix_suffix"),
    (31, "5DbP2Ry4iLFCzBWCFAw9ro6HQp7BodMPqmPKEr7t91AJ", "prefix_suffix"),
    (36, "3aQVh49CtuKG7DEstdf4xCLXTcprqHDaehiLBYjnCvq4", "prefix_suffix"),
    (142, "EqBQhoU88ty3a3aDphDRCBuiRirjUsFSFi4UHGY64qvv", "prefix_suffix"),
]


def load(name: str):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def live():
    return load("pokemon_address_list_live_20261020.json")


def items(rows):
    return bm._valid_items(rows)


def pokemon_holders() -> dict:
    """A consistent in-memory holder list for the Pokémon mint built from the trimmed top_holders (balances from shares)."""
    top = load("pokemon_holders_top_20261020.json")["top_holders"]
    balances = {r["wallet"]: float(round(r["share_pct"] * 1e9)) for r in top}
    rest = 100 * 1e9 - sum(balances.values())  # the rest of the supply in small wallets below the top list, so shares stay real
    digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    for i in range(2700):
        balances["Dust" + "".join(digits[(i // 33 ** k) % 33] for k in range(3)) + "z" * 33] = float(round(rest / 2700))
    pools = {r["wallet"] for r in top if r["infrastructure"]}
    dist = hf.distribution(balances, pools)
    ranked = dist.pop("ranked")
    return {"mint": POK, "token_accounts": len(balances), "truncated": False, "earliest_pair_created_at": None, "pool_addresses": sorted(pools),
            "distribution": dist, "warnings": [], "top_holders": hf.top_holder_rows(ranked, pools, 250), "_ranked": ranked, "_balances": balances}


def pokemon_map_with_cluster1() -> dict:
    m = load("pokemon_bubblemaps_map_20261020.json")
    c1 = load("pokemon_cluster1_screenshot_members.json")
    for c in m["clusters"]:
        if c["cluster"] == 1:
            c.update(members=copy.deepcopy(c1["members"]), members_complete=True)
        else:
            c.update(members=None, members_complete=False, members_note="not in the screenshot")
    m.update(members_parse_ok=True, members_reason=None)
    return m


# ----------------------------------------------------------------------------- a virtualised Address List, offline


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class FakeAddressList:
    """The live page's Address List as measured on 2026-10-20: rows in list order, a cluster's member rows present only
    while it is open, rows rendered only near the visible part (35 px each, a few rows of overscan). It answers only the
    three scripts of bubblemaps_map (rows snapshot, scroll, a header's expand toggle) and records every call."""

    ROW, OVERSCAN = 35, 4

    @staticmethod
    def number(text):  # the fake's own header rule (independent of bubblemaps_map.parse_header, so a broken parser cannot hide)
        m = re.match(r"^Cluster\s+(\d+)", " ".join(str(text).split()))
        return int(m.group(1)) if m else None

    def __init__(self, entries, *, view=828, clock=None, cost_s=0.01, broken=None, body=None):
        self.entries, self.view, self.top = entries, view, 0.0
        self.clock = clock or Clock()
        self.cost_s, self.broken, self.body = cost_s, broken, body
        self.open: set[int] = set()
        self.scripts: list[str] = []
        self.clicks: list[int] = []

    @classmethod
    def from_rows(cls, rows, **kw):
        entries, cur = [], None
        for r in rows:
            fields = {k: r.get(k) for k in ("text", "name", "share", "hidden", "wand", "clock")}
            if r["kind"] == "header":
                cur = ["cluster", fields, []]
                entries.append(cur)
            elif r["kind"] == "member":
                cur[2].append(fields)
            else:
                cur = None
                entries.append(["top", {"text": "", "name": None, "share": None, "hidden": False, "wand": False, "clock": False}, []])
        return cls(entries, **kw)

    def rows(self):
        out = []
        for kind, fields, members in self.entries:
            if kind == "top":
                out.append({**fields, "kind": "top"})
                continue
            out.append({**fields, "kind": "header"})
            if self.number(fields["text"]) in self.open:
                out += [{**m, "kind": "member"} for m in members]
        for i, r in enumerate(out):
            r["idx"] = i
        return out

    def evaluate(self, script, arg=None):
        self.clock.t += self.cost_s
        self.scripts.append(script)
        if self.broken == "raise":
            raise RuntimeError("page gone")
        rows = self.rows()
        height = len(rows) * self.ROW
        if script == bm.ROWS_JS:
            if self.broken == "no_list":
                return {"error": "address_list_not_found"}
            first = max(0, int(self.top // self.ROW) - self.OVERSCAN)
            last = min(len(rows), int((self.top + self.view) // self.ROW) + 1 + self.OVERSCAN)
            shown = copy.deepcopy(rows[first:last])
            if self.broken == "no_headers":
                for r in shown:
                    r["kind"] = "top" if r["kind"] == "header" else r["kind"]
            if self.broken == "odd_header":
                for r in shown:
                    if r["kind"] == "header":
                        r["text"] = r["text"].replace("(", "[").replace(")", "]")
            return {"items": shown, "top": self.top, "height": height, "view": self.view}
        if script == bm.SCROLL_JS:
            self.top = max(0.0, min(float(arg), max(0.0, height - self.view)))
            return True
        if script == bm.CLICK_JS:
            idx, n = arg
            if idx >= len(rows) or rows[idx]["kind"] != "header" or self.number(rows[idx]["text"]) != n:
                return False
            self.clicks.append(n)
            if self.broken == "no_close" and n in self.open:
                return True  # the toggle answers but the cluster stays open
            self.open ^= {n}
            return True
        raise AssertionError("the member read ran a script other than its three")

    def wait_for_timeout(self, ms):
        self.clock.t += ms / 1000

    def set_viewport_size(self, size):
        self.view = size["height"] - 160

    def inner_text(self, selector):
        return self.body(self.clock.t)


# ----------------------------------------------------------------------------- the parser


class ParserTests(unittest.TestCase):
    def test_live_list_parses_every_cluster_and_header_count_is_holders_plus_linking(self):
        for key in ("before_refresh", "after_refresh"):
            parsed = bm.parse_list(items(live()[key]), at_end=True)
            self.assertEqual(parsed["problems"], [], key)
            self.assertEqual([c["cluster"] for c in parsed["clusters"]], list(range(1, 9)), key)
            for c in parsed["clusters"]:
                kinds = bm._count_kinds(c["members"])
                self.assertTrue(c["members_complete"], (key, c["cluster"], c.get("members_note")))
                self.assertEqual(kinds["holder"] + kinds["linking"] + kinds["hidden"], c["wallets"], (key, c["cluster"]))
        c1 = bm.parse_list(items(live()["before_refresh"]), at_end=True)["clusters"][0]
        self.assertEqual((c1["wallets"], c1["supply_pct"]), (10, 11.45))
        self.assertEqual([m["rank"] for m in c1["members"] if m["kind"] == "holder"], [4, 5, 6, 11, 14, 28, 34])
        self.assertEqual(c1["members"][0], {"rank": 4, "shown": "DuARUp...c6s6", "label": None, "share_pct": 2.6, "kind": "holder", "share_shown": "2.60%"})
        self.assertEqual(c1["members"][3]["label"], "pump.fun Creator (JAf1)")
        self.assertIsNone(c1["members"][3]["shown"])
        self.assertEqual([(m["kind"], m["linking_icon"]) for m in c1["members"][7:]], [("linking", "wand")] * 3)
        c7 = bm.parse_list(items(live()["before_refresh"]), at_end=True)["clusters"][6]
        clock_rows = [m for m in c7["members"] if m.get("linking_icon") == "clock"]
        self.assertEqual(len(clock_rows), 1)  # the dated "PumpSwap Pool - <date>" row: no rank, no share, clock icon
        self.assertIsNone(clock_rows[0]["rank"])

    def test_kinds_linking_hidden_and_shares_kept_as_displayed(self):
        rows = [
            {"idx": 0, "kind": "header", "text": "Cluster 3\n(5)\n< 0.01%"},
            {"idx": 1, "kind": "member", "text": "#7 | AbCdEf...WxYz | 1.20%", "name": "AbCdEf...WxYz", "share": "1.20%", "hidden": False, "wand": False, "clock": False},
            {"idx": 2, "kind": "member", "text": "#1 | PumpSwap Pool | 6.32%", "name": "PumpSwap Pool", "share": "6.32%", "hidden": True, "wand": False, "clock": False},
            {"idx": 3, "kind": "member", "text": "#240 | 9xYz12...abCD | < 0.01%", "name": "9xYz12...abCD", "share": "< 0.01%", "hidden": False, "wand": False, "clock": False},
            {"idx": 4, "kind": "member", "text": "Fireblocks Custody", "name": "Fireblocks Custody", "share": None, "hidden": False, "wand": True, "clock": False},
            {"idx": 5, "kind": "member", "text": "no icon", "name": "QwErTy...uIoP", "share": None, "hidden": False, "wand": False, "clock": False},
            {"idx": 6, "kind": "top"},
        ]
        c = bm.parse_list(items(rows), at_end=False)["clusters"][0]
        self.assertEqual((c["cluster"], c["wallets"], c["supply_pct"], c.get("supply_lt")), (3, 5, 0.01, True))
        kinds = [m["kind"] for m in c["members"]]
        self.assertEqual(kinds, ["holder", "hidden", "holder", "linking", "linking"])
        self.assertEqual(c["members"][0]["share_shown"], "1.20%")
        self.assertEqual((c["members"][2]["share_pct"], c["members"][2]["share_lt"], c["members"][2]["share_shown"]), (0.01, True, "< 0.01%"))
        self.assertEqual(c["members"][3]["linking_icon"], "wand")
        self.assertIsNone(c["members"][4]["linking_icon"])  # no rank and no share: linking, icon unknown
        self.assertTrue(c["members_complete"])

    def test_missing_or_extra_rows_are_never_silently_short(self):
        base = live()["before_refresh"]
        gap = [r for r in base if r["idx"] != 3]  # one member row of Cluster 1 missing from the read
        c1 = bm.parse_list(items(gap), at_end=True)["clusters"][0]
        self.assertFalse(c1["members_complete"])
        self.assertIn("missing", c1["members_note"])
        cut = [r for r in base if r["idx"] <= 5]  # the read stopped inside Cluster 1
        c1 = bm.parse_list(items(cut), at_end=False)["clusters"][0]
        self.assertFalse(c1["members_complete"])
        self.assertIn("stopped before the end", c1["members_note"])
        short = copy.deepcopy(base)
        short[0]["text"] = "Cluster 1\n(12)\n11.45%"  # header says 12, 10 rows listed
        c1 = bm.parse_list(items(short), at_end=True)["clusters"][0]
        self.assertFalse(c1["members_complete"])
        self.assertIn("the header says 12 wallets", c1["members_note"])

    def test_labels_are_inert_and_shown_addresses_base58_only(self):
        row = {"idx": 1, "kind": "member", "text": "#9 | x", "share": "1.00%", "hidden": False, "wand": False, "clock": False}
        self.assertEqual(bm.member_row({**row, "name": "AbCdEf…WxYz"})["shown"], "AbCdEf...WxYz")
        for bad in ("AbC0Ef...WxYz", "AbCdEf...Wx Yz", "AbCdEf..WxYz", "<b>AbCdEf...WxYz</b>"):
            m = bm.member_row({**row, "name": bad})
            self.assertIsNone(m["shown"], bad)
        m = bm.member_row({**row, "name": "SAFE wallet <script>|`[x](y)\nnext"})
        self.assertIsNone(m["shown"])
        self.assertNotRegex(m["label"].replace(hf.pw.PLACEHOLDER, ""), r"[<>|`\[\]\n#]")
        self.assertIn(hf.pw.PLACEHOLDER, m["label"])
        self.assertLessEqual(len(m["label"]), bm.LABEL_CAP + hf.pw.GROWTH_LIMIT)

    def test_shared_rules_match_the_forensics_engine(self):
        self.assertEqual(bm.CLUSTER_BAR_PCT, hf.CLUSTER_ALARM_PCT)
        self.assertEqual(bm.AGGREGATE_BAR_PCT, hf.AGGREGATE_CLUSTER_ALARM_PCT)
        self.assertEqual(bm.SHOWN_RE.pattern, hf.MAP_SHOWN_RE.pattern)
        self.assertEqual(bm.MAP_LABEL_STRIP.pattern, hf.MAP_LABEL_STRIP.pattern)


# ----------------------------------------------------------------------------- the browser steps, on the offline list


class ReadLoopTests(unittest.TestCase):
    def size_read(self):
        return copy.deepcopy(live()["size_read_default_window"])

    def test_final_read_expands_each_cluster_once_and_finds_the_clusters_the_size_read_missed(self):
        page = FakeAddressList.from_rows(live()["before_refresh"])
        result = {"clusters": self.size_read()}
        sizes = [(c["cluster"], c["wallets"], c["supply_pct"]) for c in result["clusters"]]
        bm.read_final_members(page, result, clock=page.clock)
        self.assertTrue(result["members_parse_ok"], result.get("members_reason"))
        self.assertEqual([(c["cluster"], c["wallets"], c["supply_pct"]) for c in result["clusters"]], sizes)  # sizes never change
        self.assertEqual(len(sizes), 7)  # the default-window size read saw 7 of the 8 clusters
        self.assertTrue(all(c["members_complete"] for c in result["clusters"]))
        self.assertEqual([c["cluster"] for c in result["clusters_list_only"]], [8])
        self.assertEqual(len(result["clusters_list_only"][0]["members"]), 3)
        self.assertEqual(sorted(page.clicks), list(range(1, 9)))  # one expand toggle per cluster, nothing else clicked
        self.assertEqual(set(page.scripts), {bm.ROWS_JS, bm.SCROLL_JS, bm.CLICK_JS})
        self.assertLess(result["members_seconds"], bm.MEMBERS_BUDGET_S)
        self.assertEqual(result["members_list_clusters"], 8)

    def test_a_cluster_already_open_is_not_clicked_shut(self):
        page = FakeAddressList.from_rows(live()["before_refresh"])
        page.open = {1}
        result = {"clusters": self.size_read()}
        bm.read_final_members(page, result, clock=page.clock)
        self.assertNotIn(1, page.clicks)
        self.assertTrue(result["clusters"][0]["members_complete"])
        self.assertIn("Cluster 1 was already open", result["members_reason"])

    def test_the_budget_is_a_hard_cap(self):
        entries = []
        for n in range(1, 61):  # a long list: 60 clusters of 20 members
            entries.append(["cluster", {"text": f"Cluster {n}\n(20)\n{max(0.01, 20 - n * 0.3):.2f}%"}, [
                {"text": f"#{n * 20 + k} | AbCdE{chr(65 + k)}...WxYz | 0.01%", "name": f"AbCdE{chr(65 + k)}...WxYz", "share": "0.01%", "hidden": False, "wand": False, "clock": False}
                for k in range(20)]])
            entries.append(["top", {"text": ""}, []])
        page = FakeAddressList(entries, cost_s=0.25)
        result = {"clusters": [{"cluster": n, "wallets": 20, "supply_pct": round(max(0.01, 20 - n * 0.3), 2)} for n in range(1, 61)]}
        bm.read_final_members(page, result, clock=page.clock)
        self.assertTrue(result["members_parse_ok"])
        self.assertIn("time budget reached", result["members_reason"])
        self.assertLessEqual(result["members_seconds"], bm.MEMBERS_BUDGET_S + 10)  # checked before every step; one slow step at most
        self.assertTrue(result["clusters"][0]["members_complete"])
        self.assertTrue(any(c["members"] is None and c["members_note"] == "this cluster was not found in the list read" for c in result["clusters"]))
        self.assertTrue(all(c["members"] is None or isinstance(c["members"], list) for c in result["clusters"]))

    def test_a_changed_layout_fails_loudly_and_keeps_the_sizes(self):
        for broken, needle in (("no_list", "could not be read"), ("no_headers", "found no cluster rows"), ("odd_header", "does not read as"), ("raise", "browser step failed")):
            page = FakeAddressList.from_rows(live()["before_refresh"], broken=broken)
            result = {"clusters": self.size_read(), "parse_ok": True}
            sizes = [(c["cluster"], c["wallets"], c["supply_pct"]) for c in result["clusters"]]
            bm.read_final_members(page, result, clock=page.clock)
            self.assertIs(result["members_parse_ok"], False, broken)
            self.assertIn(needle, result["members_reason"], broken)
            self.assertIn("sizes", result["members_reason"], broken)
            self.assertEqual([(c["cluster"], c["wallets"], c["supply_pct"]) for c in result["clusters"]], sizes, broken)
            self.assertTrue(all(c["members"] is None and c["members_complete"] is False for c in result["clusters"]), broken)  # never "no members"
            self.assertIs(result["parse_ok"], True, broken)

    def test_pre_refresh_read_takes_the_clusters_over_the_bar_and_closes_them_again(self):
        rows = copy.deepcopy(live()["before_refresh"])
        rows[0]["text"] = "Cluster 1\n(10)\n16.21%"
        page = FakeAddressList.from_rows(rows)
        result = {"clusters_before": [{"cluster": 1, "wallets": 10, "supply_pct": 16.21}, {"cluster": 2, "wallets": 4, "supply_pct": 2.96}]}
        bm.read_pre_refresh_members(page, result, clock=page.clock)
        self.assertTrue(result["members_before_read"], result.get("members_before_reason"))
        self.assertEqual(result["members_before_clusters"], [1])
        self.assertEqual(len(result["clusters_before"][0]["members"]), 10)
        self.assertTrue(result["clusters_before"][0]["members_complete"])
        self.assertNotIn("members", result["clusters_before"][1])
        self.assertEqual(page.clicks, [1, 1])  # opened, read, closed
        self.assertEqual(page.open, set())  # the refreshed size read sees the list as before
        self.assertEqual(page.top, 0.0)
        self.assertLessEqual(result["members_before_seconds"], bm.PRE_MEMBERS_BUDGET_S)

    def test_pre_refresh_read_is_skipped_when_the_line_cannot_print(self):
        page = FakeAddressList.from_rows(live()["before_refresh"])
        result = {"clusters_before": [{"cluster": 1, "wallets": 10, "supply_pct": 12.0}, {"cluster": 2, "wallets": 4, "supply_pct": 10.0}]}
        bm.read_pre_refresh_members(page, result, clock=page.clock)
        self.assertFalse(result["members_before_read"])
        self.assertIn("not needed", result["members_before_reason"])
        self.assertEqual(page.scripts, [])
        self.assertEqual(bm.pre_refresh_targets([{"cluster": 1, "supply_pct": 12.0}, {"cluster": 2, "supply_pct": 10.0}, {"cluster": 3, "supply_pct": 9.0}]), [1])  # 31% together
        self.assertEqual(bm.pre_refresh_targets([{"cluster": 1, "supply_pct": 16.0}, {"cluster": 2, "supply_pct": 15.0}]), [1, 2])


class RepairRoundOneReadTests(unittest.TestCase):
    """HS-BM-MEMBERS-T1 repair round 1: a cluster the pre-refresh read cannot close is reported in a field of its own (R1);
    the run budget bounds the optional parts (R3)."""

    def rows_over_bar(self):
        rows = copy.deepcopy(live()["before_refresh"])
        rows[0]["text"] = "Cluster 1\n(10)\n16.21%"
        return rows

    def test_a_cluster_that_cannot_be_closed_is_recorded(self):
        page = FakeAddressList.from_rows(self.rows_over_bar(), broken="no_close")
        result = {"clusters_before": [{"cluster": 1, "wallets": 10, "supply_pct": 16.21}]}
        bm.read_pre_refresh_members(page, result, clock=page.clock)
        self.assertTrue(result["members_before_read"])  # its rows were read
        self.assertEqual(len(result["clusters_before"][0]["members"]), 10)
        self.assertEqual(result["members_before_not_closed"], [1])
        self.assertEqual(page.open, {1})
        self.assertLessEqual(result["members_before_seconds"], bm.PRE_MEMBERS_BUDGET_S + bm.STEP_TIMEOUT_MS / 1000 + 1)

    def test_closed_clusters_leave_no_field(self):
        page = FakeAddressList.from_rows(self.rows_over_bar())
        result = {"clusters_before": [{"cluster": 1, "wallets": 10, "supply_pct": 16.21}]}
        bm.read_pre_refresh_members(page, result, clock=page.clock)
        self.assertNotIn("members_before_not_closed", result)

    def test_pre_refresh_read_needs_its_time_and_the_refresh_part_left(self):
        page = FakeAddressList.from_rows(self.rows_over_bar())
        result = {"clusters_before": [{"cluster": 1, "wallets": 10, "supply_pct": 16.21}]}
        bm.read_pre_refresh_members(page, result, clock=page.clock, deadline=page.clock.t + bm.PRE_MEMBERS_BUDGET_S + bm.REFRESH_RESERVE_S - 1)
        self.assertFalse(result["members_before_read"])
        self.assertIn("skipped: 42 s left of the 100 s run budget", result["members_before_reason"])
        self.assertEqual(page.scripts, [])  # nothing opened, so nothing to close

    def test_final_read_with_no_time_left_fails_loudly_and_keeps_the_sizes(self):
        page = FakeAddressList.from_rows(live()["before_refresh"])
        result = {"clusters": copy.deepcopy(live()["size_read_default_window"])}
        sizes = [(c["cluster"], c["wallets"], c["supply_pct"]) for c in result["clusters"]]
        bm.read_final_members(page, result, clock=page.clock, deadline=page.clock.t + 0.5)
        self.assertIs(result["members_parse_ok"], False)
        self.assertIn("no time left in the 100 s run budget", result["members_reason"])
        self.assertEqual([(c["cluster"], c["wallets"], c["supply_pct"]) for c in result["clusters"]], sizes)
        self.assertTrue(all(c["members"] is None for c in result["clusters"]))
        self.assertEqual(page.scripts, [])

    def test_final_read_stops_at_the_run_deadline(self):
        page = FakeAddressList.from_rows(live()["before_refresh"], cost_s=0.5)
        result = {"clusters": copy.deepcopy(live()["size_read_default_window"])}
        bm.read_final_members(page, result, clock=page.clock, deadline=page.clock.t + 5)
        self.assertIn("time budget", result["members_reason"])
        self.assertNotIn("layout", result["members_reason"])  # running out of time is never reported as a changed page
        self.assertLessEqual(result["members_seconds"], 5 + 4)

    def test_settle_cap_from_the_run_budget_never_under_the_minimum(self):
        before = [[1, 10, 11.45]]
        clock = Clock()
        page = FakeAddressList([], clock=clock, body=lambda t: SettleTests.body(before))
        _, info = bm.wait_for_settle(page, SettleTests.body(before, "1h ago"), clock=clock, cap_s=30)
        self.assertGreaterEqual(info["settle_s"], 30)
        self.assertLess(info["settle_s"], 32)
        self.assertEqual(info["settle_cap_s"], 30)
        self.assertIn("within 30 s", info["settle_note"])
        clock = Clock()
        page = FakeAddressList([], clock=clock, body=lambda t: SettleTests.body(before))
        _, info = bm.wait_for_settle(page, SettleTests.body(before, "1h ago"), clock=clock, cap_s=5)
        self.assertGreaterEqual(info["settle_s"], bm.SETTLE_MIN_S)  # the old fixed 20 s stays the floor
        self.assertLess(info["settle_s"], bm.SETTLE_MIN_S + 2)


class _Pill:
    def __init__(self, page):
        self.page = page

    def evaluate(self, expression, timeout=None):
        assert timeout == bm.PILL_TIMEOUT_MS
        self.page.clock.t += 0.05
        return self.page.pill_disabled

    def click(self, timeout=None):
        assert timeout == bm.CLICK_TIMEOUT_MS
        self.page.clock.t += self.page.click_s
        self.page.refreshed_at = self.page.clock.t


class _PillList:
    def __init__(self, page):
        self.page = page

    def filter(self, **kw):
        return self

    def count(self):
        return 1

    @property
    def first(self):
        return _Pill(self.page)


class FakeMapPage(FakeAddressList):
    """The whole map page for read_map, offline: page load time, the age pill, the cluster list in the page text before
    and after a refresh (unchanged for ever when change_after_s is None, the slowest case)."""

    def __init__(self, entries, *, goto_s=6.0, click_s=7.9, pill_disabled=False, change_after_s=None, **kw):
        super().__init__(entries, **kw)
        self.goto_s, self.click_s, self.pill_disabled, self.change_after_s = goto_s, click_s, pill_disabled, change_after_s
        self.refreshed_at = None

    def goto(self, url, wait_until=None, timeout=None):
        assert timeout == bm.PAGE_LOAD_TIMEOUT_MS
        self.clock.t += self.goto_s

    def inner_text(self, selector):
        t, at = self.clock.t, self.refreshed_at
        age = "just now" if at is not None and t - at >= 9 else "1h ago"
        heads = [" ".join(f["text"].split()) for kind, f, _ in self.entries if kind == "cluster"]
        if at is not None and self.change_after_s is not None and t - at >= self.change_after_s:
            heads = [h[:-1] + "1%" if h.endswith("%") else h for h in heads]
        return f"{age} " + " ".join(heads) + " PumpSwap Pool 6.55%"

    def get_by_role(self, role):
        return _PillList(self)

    def get_by_text(self, pattern):
        return _PillList(self)


def fake_camoufox(page, launch_s, close_s=1.5):
    class Browser:
        contexts: list = []

        def new_page(self):
            return page

    class Session:
        def __init__(self, **kw):
            pass

        def __enter__(self):
            page.clock.t += launch_s
            return Browser()

        def __exit__(self, *exc):
            page.clock.t += close_s
            return False

    mod = types.ModuleType("camoufox.sync_api")
    mod.Camoufox = Session
    pkg = types.ModuleType("camoufox")
    pkg.sync_api = mod
    return {"camoufox": pkg, "camoufox.sync_api": mod}


WORST_CASE_S = 106.0  # the documented bound (bubblemaps_map, comment above RUN_BUDGET_S) for a browser launch of up to 10 s


class RunBoundTests(unittest.TestCase):
    """read_map end to end on a fake page and a fake clock (no browser): the run's wall time stays within the documented
    worst case, and the required size read is never lost to the member reads or the settle wait (R3)."""

    def run_map(self, *, launch_s, goto_s, cost_s, change_after_s=None, pill_disabled=False):
        rows = copy.deepcopy(live()["before_refresh"])
        rows[0]["text"] = "Cluster 1\n(10)\n16.21%"  # a pre-refresh cluster over the bar: the pre-refresh read is wanted
        page = FakeMapPage.from_rows(rows, cost_s=cost_s)
        page.goto_s, page.click_s, page.pill_disabled, page.change_after_s, page.refreshed_at = goto_s, 7.9, pill_disabled, change_after_s, None
        with mock.patch.dict(sys.modules, fake_camoufox(page, launch_s)):
            out = bm.read_map(POK, max_age_min=15, headed=False, screenshot=None, keep_open=0, clock=page.clock)
        return out, page.clock.t, page

    def assert_sizes_read(self, out, largest):
        self.assertTrue(out["parse_ok"])
        self.assertEqual(out["clusters"][0]["supply_pct"], largest)  # the required size read is there
        self.assertEqual(out["clusters_before"][0]["supply_pct"], 16.21)
        self.assertTrue(out["refreshed"])
        self.assertIn("settle_s", out)

    def test_worst_case_slow_page_load(self):
        """Launch 10 s, page load 44.9 s (just under its timeout), no change after the refresh: the fixed part alone uses
        the budget, so the optional parts shrink to nothing and the run still ends within the bound."""
        out, total, _ = self.run_map(launch_s=10, goto_s=44.9, cost_s=0.01)
        self.assert_sizes_read(out, 16.21)
        self.assertIn("skipped:", out["members_before_reason"])
        self.assertEqual(out["settle_cap_s"], bm.SETTLE_MIN_S)
        self.assertLessEqual(total, WORST_CASE_S)

    def test_worst_case_slow_member_reads(self):
        """Launch 10 s, a fast page load, a slow page during the member reads (0.5 s per page call) and no change after the
        refresh: every optional part runs to its own cap and the run still ends within the bound."""
        out, total, _ = self.run_map(launch_s=10, goto_s=5, cost_s=0.5)
        self.assert_sizes_read(out, 16.21)
        self.assertEqual(out["members_before_clusters"], [1])
        self.assertIn("time budget", out["members_reason"] or "")
        self.assertLessEqual(total, WORST_CASE_S)

    def test_typical_run(self):
        out, total, page = self.run_map(launch_s=3, goto_s=6, cost_s=0.01, change_after_s=33)
        self.assert_sizes_read(out, 16.211)  # the list after it changed (the fake adds a digit), not the pre-refresh 16.21
        self.assertTrue(out["members_before_read"])
        self.assertNotIn("members_before_not_closed", out)
        self.assertGreaterEqual(out["settle_list_changed_s"], 33)
        self.assertTrue(out["members_parse_ok"])
        self.assertLess(total, 90)

    def test_every_documented_figure_matches_the_constants(self):
        fixed = 10 + bm.PAGE_LOAD_TIMEOUT_MS / 1000 + bm.FIRST_WAIT_MS / 1000 + bm.PILL_TIMEOUT_MS / 1000 + bm.CLICK_TIMEOUT_MS / 1000 + bm.SETTLE_MIN_S
        self.assertEqual(fixed, 103.0)  # L + 93 with L = 10
        self.assertLessEqual(max(fixed + 1, bm.RUN_BUDGET_S + 4) + 2, WORST_CASE_S)
        self.assertLessEqual(WORST_CASE_S, 110)


class SettleTests(unittest.TestCase):
    @staticmethod
    def body(clusters, age="just now"):
        return f"{age} " + " ".join(f"Cluster {n} ({w}) {p}%" for n, w, p in clusters)

    def run_polls(self, polls, before):
        clock = Clock()

        def text(t):
            seen = [p for p in polls if p["since_click_s"] <= t + 1e-9]
            return self.body(seen[-1]["clusters"], seen[-1]["age"]) if seen else self.body(before, "1h ago")

        page = FakeAddressList([], clock=clock, body=text)
        return bm.wait_for_settle(page, self.body(before, "1h ago"), clock=clock)

    def test_live_refresh_waits_until_the_new_clusters_arrive(self):
        polls = live()["refresh_settle_polls"]
        before = polls[0]["clusters"]
        _, info = self.run_polls(polls, before)
        self.assertGreaterEqual(info["settle_list_changed_s"], 32.0)  # live: the old list stayed until about 33 s
        self.assertGreaterEqual(info["settle_s"], info["settle_list_changed_s"] + bm.SETTLE_STABLE_S)
        self.assertLess(info["settle_s"], bm.SETTLE_CAP_S)
        self.assertIsNone(info["settle_note"])
        body, _ = self.run_polls(polls, before)
        self.assertEqual(bm.parse_clusters(body)[0]["supply_pct"], 11.51)  # the refreshed list, not the pre-refresh 11.45

    def test_no_change_stops_at_the_cap_and_says_so(self):
        before = [[1, 10, 11.45]]
        _, info = self.run_polls([{"since_click_s": 0.0, "age": "just now", "clusters": before}], before)
        self.assertGreaterEqual(info["settle_s"], bm.SETTLE_CAP_S)
        self.assertLess(info["settle_s"], bm.SETTLE_CAP_S + 2)
        self.assertIsNone(info["settle_list_changed_s"])
        self.assertIn("may still be the pre-refresh ones", info["settle_note"])

    def test_a_page_change_outside_the_clusters_does_not_end_the_wait(self):
        """DKYc, 2026-10-20: 5 s after the refresh click the pool share changed while the cluster headers kept their old
        values; the clusters themselves changed later. Only the cluster list ends the wait."""
        before = [[1, 3, 5.99], [2, 3, 2.54]]
        pool = lambda p: f" PumpSwap Pool {p}%"  # noqa: E731
        clock = Clock()

        def text(t):
            clusters = before if t < 30 else [[1, 2, 4.10], [2, 3, 2.54]]
            return self.body(clusters, "just now" if t >= 9 else "2h ago") + pool(7.17 if t < 5 else 9.99)

        page = FakeAddressList([], clock=clock, body=text)
        body, info = bm.wait_for_settle(page, self.body(before, "2h ago") + pool(7.17), clock=clock)
        self.assertGreaterEqual(info["settle_list_changed_s"], 30.0)
        self.assertGreaterEqual(info["settle_s"], 35.0)
        self.assertEqual(bm.parse_clusters(body)[0]["supply_pct"], 4.10)
        self.assertEqual(bm._list_key("Cluster 1 (3) 5.99% PumpSwap Pool 7.17%"), bm._list_key("Cluster 1 (3) 5.99% PumpSwap Pool 9.99%"))

    def test_never_earlier_than_the_old_fixed_wait(self):
        before = [[1, 10, 11.45]]
        polls = [{"since_click_s": 0.0, "age": "1h ago", "clusters": before}, {"since_click_s": 3.0, "age": "just now", "clusters": [[1, 9, 12.0]]}]
        _, info = self.run_polls(polls, before)
        self.assertEqual(info["settle_list_changed_s"], 3.0)
        self.assertGreaterEqual(info["settle_s"], bm.SETTLE_MIN_S)
        self.assertLess(info["settle_s"], bm.SETTLE_MIN_S + 2)


# ----------------------------------------------------------------------------- offline resolution


def holder_rows(group):
    return [m for m in group if m["kind"] == "holder"]


class ResolutionTests(unittest.TestCase):
    def test_pokemon_cluster1_resolves_to_the_owner_table(self):
        group = copy.deepcopy(load("pokemon_cluster1_screenshot_members.json")["members"])
        hf.resolve_members([group], load("pokemon_holders_top_20261020.json"))
        got = [(m["rank"], m["address"], m["method"]) for m in holder_rows(group)]
        self.assertEqual(got, OWNER_TABLE)
        eqb = holder_rows(group)[-1]
        self.assertEqual((eqb["rank"], eqb["helius_rank"]), (142, 143))  # #142 on the map, #143 in the Helius list
        self.assertEqual([m["kind"] for m in group[8:]], ["linking"] * 3)
        self.assertTrue(all("address" not in m for m in group[8:]))
        for m in holder_rows(group):
            self.assertRegex(m["address"], hf.BASE58_RE)

    def test_same_cluster_from_the_in_memory_ranking(self):
        group = copy.deepcopy(load("pokemon_cluster1_screenshot_members.json")["members"])
        hf.resolve_members([group], pokemon_holders())
        self.assertEqual([(m["rank"], m["address"], m["method"]) for m in holder_rows(group)], OWNER_TABLE)

    def test_two_holders_with_the_same_shown_form_stay_unresolved(self):
        holders = {"top_holders": [{"rank": 3, "wallet": "AbCdEf" + "1" * 30 + "WxYz", "share_pct": 2.0}, {"rank": 9, "wallet": "AbCdEf" + "2" * 30 + "WxYz", "share_pct": 1.0}]}
        group = [{"rank": 3, "shown": "AbCdEf...WxYz", "label": None, "share_pct": 2.0, "kind": "holder"}]
        hf.resolve_members([group], holders)
        self.assertIsNone(group[0]["address"])
        self.assertEqual(group[0]["unresolved"], "2 holders show as AbCdEf...WxYz")  # never picked by rank either

    def test_no_holders_json_leaves_everything_unresolved_without_a_crash(self):
        group = copy.deepcopy(load("pokemon_cluster1_screenshot_members.json")["members"])
        hf.resolve_members([group], None)
        self.assertTrue(all(m["address"] is None and "no holders.json" in m["unresolved"] for m in holder_rows(group)))
        d = hf.bubblemaps_display(pokemon_map_with_cluster1(), POK, None)
        self.assertTrue(d["members"]["read"])
        self.assertTrue(all(m["address"] is None for m in holder_rows(d["members"]["clusters"][0]["members"])))
        lines = hf.bubblemaps_member_lines({"bubblemaps_members": d["members"], "bubblemaps_pre_refresh": d["pre_refresh"]})
        self.assertTrue(any("#5 map label pump.fun Creator (JAf1) 2.52%: not resolved" in ln for ln in lines))

    def test_rank_drift_within_and_outside_the_tolerance(self):
        def w(i):
            return "Wa11et" + "".join("ABCDEFGHJK"[int(d)] for d in f"{i:02d}") + "x" * 26 + "Endd"

        holders = {"top_holders": [{"rank": r, "wallet": w(r), "share_pct": s} for r, s in ((10, 3.0), (12, 1.02), (16, 1.01), (20, 0.70), (21, 0.71))]}

        def resolve(rank, share):
            g = [{"rank": rank, "shown": None, "label": "a label", "share_pct": share, "kind": "holder"}]
            hf.resolve_members([g], holders)
            return g[0]

        m = resolve(10, 1.0)  # rank 10 does not fit the share; rank 12 (drift 2) does, and only it
        self.assertEqual((m["address"], m["method"], m["helius_rank"]), (w(12), "rank_share", 12))
        m = resolve(13, 1.0)  # rank 16 fits the share but is 3 away, rank 12 is 1 away: two candidates
        self.assertIsNone(m["address"])
        self.assertIn("2 holders fit", m["unresolved"])
        m = resolve(5, 1.0)  # nothing within 3 ranks
        self.assertIn("no holder fits", m["unresolved"])
        m = resolve(12, 1.08)  # share 0.06 points away
        self.assertIsNone(m["address"])
        m = resolve(20, 0.70)  # exact rank first: rank 20 fits, rank 21 (0.71) fits too but the exact rank wins
        self.assertEqual((m["address"], m["helius_rank"]), (w(20), 20))

    def test_a_holder_matched_by_its_shown_address_is_not_taken_again(self):
        holders = load("pokemon_holders_top_20261020.json")
        group = [{"rank": 6, "shown": None, "label": "x", "share_pct": 2.50, "kind": "holder"}, {"rank": 5, "shown": "Be24Gb...ZnRR6", "label": None, "share_pct": 2.52, "kind": "holder"}]
        hf.resolve_members([group], holders)
        self.assertEqual(group[1]["method"], "prefix_suffix")
        self.assertEqual(group[0]["address"], "6DQAGJT7VZPVBsuG4kn3AvpyHCEi7B2RFFvMZdbqQqqP")  # Be24Gb (2.52) fits too but is taken

    def test_the_rank_window_skips_a_holder_matched_by_its_shown_address(self):
        """R2: the exact rank does not fit; within +-3 two holders fit the share, one of them already matched by its shown
        address: only the other one is left, so the label row resolves to it (without the exclusion it would be 2 fits)."""
        a, b, c = ("AaaaaA" + "x" * 30 + "Aend", "BbbbbB" + "x" * 30 + "Bend", "CccccC" + "x" * 30 + "Cend")
        holders = {"top_holders": [{"rank": 10, "wallet": a, "share_pct": 1.00}, {"rank": 11, "wallet": b, "share_pct": 1.50}, {"rank": 12, "wallet": c, "share_pct": 1.02}]}
        group = [{"rank": 10, "shown": "AaaaaA...Aend", "label": None, "share_pct": 1.00, "kind": "holder"},
                 {"rank": 11, "shown": None, "label": "a label", "share_pct": 1.01, "kind": "holder"}]
        hf.resolve_members([group], holders)
        self.assertEqual((group[0]["address"], group[0]["method"]), (a, "prefix_suffix"))
        self.assertEqual((group[1]["address"], group[1]["method"], group[1]["helius_rank"]), (c, "rank_share", 12))

    def test_the_exact_rank_skips_a_holder_matched_by_its_shown_address(self):
        """The exact rank fits but that holder is already matched by its shown address: the label row goes to the +-3
        window instead of taking it twice."""
        a, c = "AaaaaA" + "x" * 30 + "Aend", "CccccC" + "x" * 30 + "Cend"
        holders = {"top_holders": [{"rank": 11, "wallet": a, "share_pct": 1.00}, {"rank": 13, "wallet": c, "share_pct": 1.02}]}
        group = [{"rank": 11, "shown": "AaaaaA...Aend", "label": None, "share_pct": 1.00, "kind": "holder"},
                 {"rank": 11, "shown": None, "label": "a label", "share_pct": 1.01, "kind": "holder"}]
        hf.resolve_members([group], holders)
        self.assertEqual((group[1]["address"], group[1]["helius_rank"]), (c, 13))

    def test_owner_balances_fallback_reaches_below_the_top_list(self):
        deep = "DeEpW4" + "z" * 34 + "Tayk"
        holders = {"top_holders": [{"rank": 1, "wallet": "TopWa1" + "y" * 34 + "Head", "share_pct": 90.0}],
                   "owner_balances": {"TopWa1" + "y" * 34 + "Head": 900.0, deep: 1.0, "OtherW" + "x" * 34 + "Rest": 99.0}}
        group = [{"rank": 3, "shown": "DeEpW4...Tayk", "label": None, "share_pct": 0.1, "kind": "holder"}]
        hf.resolve_members([group], holders)
        self.assertEqual((group[0]["address"], group[0]["helius_rank"]), (deep, 3))

    def test_prototype_reads(self):
        # DKYc with the full holders.json: 27 / 2 / 2; the fixture keeps top_holders only, so one wallet below that list stays unresolved
        for name, expect in (("proto_dkyc_members_20261020.json", {"prefix_suffix": 26, "rank_share": 2, None: 3}), ("proto_9a1v_members_20261020.json", {"prefix_suffix": 15})):
            data = load(name)
            groups = [c["members"] for c in data["clusters"]]
            hf.resolve_members(groups, {"top_holders": data["top_holders"]})
            got: dict = {}
            for m in (m for g in groups for m in holder_rows(g)):
                got[m["method"]] = got.get(m["method"], 0) + 1
                if m["method"] == "prefix_suffix":
                    head, tail = m["shown"].split("...")
                    self.assertTrue(m["address"].startswith(head) and m["address"].endswith(tail))
            self.assertEqual(got, expect, name)


# ----------------------------------------------------------------------------- the pre-refresh line and the report


class DisplayTests(unittest.TestCase):
    def assess_pair(self, map_raw, gmgn=None):
        holders = pokemon_holders()
        finding = hf.bubblemaps_finding(map_raw, POK)
        plain = hf.assess(hf._public(holders), None, [finding])
        display = hf.bubblemaps_display(map_raw, POK, holders, None, gmgn)
        shown = hf.assess(hf._public(holders), None, [hf.bubblemaps_finding(map_raw, POK)], bubblemaps_members=display)
        return holders, plain, shown

    def test_the_pokemon_map_prints_the_pre_refresh_line_next_to_the_flag(self):
        holders, plain, a = self.assess_pair(load("pokemon_bubblemaps_map_20261020.json"))
        self.assertTrue(a["bubblemaps_pre_refresh"]["line"].startswith(
            "clear large cluster seen by Bubblemaps (pre-refresh snapshot, 33 min old): largest 16.21% (14 wallets); the refreshed map reads 12.33%; not in the verdict; "))
        self.assertIs(a["bubblemaps_pre_refresh"]["counted"], False)
        summary = hf.executive_summary(POK, holders, a)
        self.assertTrue(summary[1].startswith("FLAG: "))
        self.assertTrue(summary[2].startswith("clear large cluster seen by Bubblemaps (pre-refresh snapshot, 33 min old): largest 16.21%"))
        self.assertLessEqual(len(summary), hf.SUMMARY_MAX_LINES)
        self.assertEqual(summary[-1], hf.executive_summary(POK, holders, plain)[-1])
        self.assertEqual(json.dumps(a["flag"]), json.dumps(plain["flag"]))
        self.assertEqual(json.dumps(a["verdict"]), json.dumps(plain["verdict"]))

    def test_below_the_bar_or_no_effective_refresh_prints_nothing(self):
        m = load("pokemon_bubblemaps_map_20261020.json")
        m["clusters_before"][0]["supply_pct"] = 14.99
        self.assertIsNone(hf.bubblemaps_display(m, POK)["pre_refresh"])
        m = load("pokemon_bubblemaps_map_20261020.json")
        m["refresh_effective"] = False
        self.assertIsNone(hf.bubblemaps_display(m, POK)["pre_refresh"])
        holders, plain, a = self.assess_pair(m)
        self.assertEqual(hf.executive_summary(POK, holders, a), hf.executive_summary(POK, holders, plain))

    def test_clusters_together_over_the_bar_print_too(self):
        m = load("pokemon_bubblemaps_map_20261020.json")
        m["clusters_before"] = [{"cluster": 1, "wallets": 9, "supply_pct": 12.0}, {"cluster": 2, "wallets": 5, "supply_pct": 10.0}, {"cluster": 3, "wallets": 4, "supply_pct": 9.0}]
        line = hf.bubblemaps_display(m, POK)["pre_refresh"]["line"]
        self.assertIn("largest 12% (9 wallets); all clusters together 31%; the refreshed map reads 12.33%, together 21.56%; not in the verdict", line)

    def test_flag_and_verdict_never_move_whatever_the_members_say(self):
        maps = [load("pokemon_bubblemaps_map_20261020.json"), pokemon_map_with_cluster1()]
        big = pokemon_map_with_cluster1()
        big["clusters_list_only"] = [{"cluster": 9, "wallets": 40, "supply_pct": 25.0, "members": [], "members_complete": False}]
        big["clusters_before"][0]["supply_pct"] = 45.0
        maps.append(big)
        broken = pokemon_map_with_cluster1()
        broken.update(members_parse_ok=False, members_reason="layout changed")
        maps.append(broken)
        for m in maps:
            _, plain, a = self.assess_pair(m, load("pokemon_gmgn_tags_20261020.json"))
            self.assertEqual(json.dumps(a["flag"], indent=1), json.dumps(plain["flag"], indent=1))
            self.assertEqual(json.dumps(a["verdict"], indent=1), json.dumps(plain["verdict"], indent=1))
            self.assertEqual(a["findings"], plain["findings"])
            self.assertEqual({k: v for k, v in a.items() if not k.startswith("bubblemaps_")}, plain)

    def test_member_table_with_claims_and_the_bundler_cross_check(self):
        holders = pokemon_holders()
        d = hf.bubblemaps_display(pokemon_map_with_cluster1(), POK, holders, load("pokemon_funders_names_20261020.json"), load("pokemon_gmgn_tags_20261020.json"))
        lines = hf.bubblemaps_member_lines({"bubblemaps_members": d["members"], "bubblemaps_pre_refresh": d["pre_refresh"]})
        text = "\n".join(lines)
        self.assertIn("Cluster 1, 11 wallets, 12.33%: 8 holders, 3 linking, 0 hidden; all rows read", text)
        self.assertIn("#4 `DuARUpsEzdVbVpSnbGipLJvWxaXUCPLDJDjNov6Rc6s6` 2.59% (resolved by prefix and suffix); GMGN claims: bundler, top_holder, transfer_in; Helius first funder: FOMO Co-signer", text)
        self.assertIn("#5 `Be24Gbf5KisDk1LcWWZsBn8dvB816By7YzYF5zWZnRR6` 2.52% (map label pump.fun Creator (JAf1); resolved by rank and share)", text)
        self.assertIn("#142 `EqBQhoU88ty3a3aDphDRCBuiRirjUsFSFi4UHGY64qvv` 0.10% (resolved by prefix and suffix; Helius #143); GMGN: not in its top 100 rows", text)
        self.assertEqual(text.count("linking wallet, holds none:"), 3)
        self.assertIn("GMGN claims bundler on 3 of 8 holders", text)
        self.assertIn("GMGN bundler-tagged wallets outside every listed Bubblemaps cluster: 26 of 29", text)
        self.assertIn("Cluster 2, 9 wallets, 2.76%: members not read (not in the screenshot)", text)
        self.assertTrue(lines[-1].startswith("  - members cannot show:"))

    def test_saved_rows_are_checked_again_and_provider_text_stays_inert(self):
        m = pokemon_map_with_cluster1()
        rows = m["clusters"][0]["members"]
        rows.append({"rank": "x", "shown": None, "label": "bad", "share_pct": 1.0, "kind": "holder"})
        rows.append({"rank": 9, "shown": "<script>", "label": None, "share_pct": 1.0, "kind": "holder"})
        rows.append({"rank": 9, "shown": None, "label": None, "share_pct": 1.0, "kind": "owner"})
        rows[8]["label"] = "Safe Wallet\n## heading [x](y) `code`"
        d = hf.bubblemaps_display(m, POK, pokemon_holders())
        c1 = d["members"]["clusters"][0]
        self.assertEqual(c1["refused_rows"], 3)
        self.assertFalse(c1["members_complete"])
        lines = hf.bubblemaps_member_lines({"bubblemaps_members": d["members"], "bubblemaps_pre_refresh": d["pre_refresh"]})
        text = "\n".join(lines)
        self.assertIn("3 saved rows refused", text)
        self.assertIn(hf.pw.PLACEHOLDER, text)
        self.assertIn("linking wallet, holds none: [provider word removed] Wallet heading x code", text)
        self.assertNotIn("`code`", text)
        self.assertNotIn("##", text)

    def test_live_dkyc_read_with_short_member_lists_is_flagged_not_hidden(self):
        """Live DKYc read (2026-10-20, run 4): three clusters listed fewer member rows than their headers; the report says
        so for each of them and the rows that were read are still shown."""
        d = hf.bubblemaps_display(load("dkyc_bubblemaps_map_live_20261020.json"), "DKYcjobF7HPtL9RyQBRdeRQ2iWvizpfbgWwPWNXdpump")
        flagged = {c["cluster"]: c for c in d["members"]["clusters"] if not c["members_complete"]}
        self.assertEqual(sorted(flagged), [1, 3, 4])
        self.assertIn("the header says 3 wallets", flagged[1]["members_note"])
        self.assertEqual([c["cluster"] for c in d["members"]["list_only"]], [7, 8, 9, 10])
        text = "\n".join(hf.bubblemaps_member_lines({"bubblemaps_members": d["members"], "bubblemaps_pre_refresh": d["pre_refresh"]}))
        self.assertIn("Cluster 1, 3 wallets, 5.99%: 1 holders, 0 linking, 0 hidden; NOT every row was read; read 1 rows", text)
        self.assertIn("further down the list: 4 more cluster(s) the size read did not see (display only, not counted)", text)
        self.assertIn("GMGN bundler cross-check: not read", text)
        self.assertIsNone(d["pre_refresh"])  # pre-refresh largest 5.99%: under the bar, nothing next to the FLAG

    def test_a_cluster_left_open_before_the_refresh_is_always_shown(self):
        """R1: the warning reaches assessment.json and report.md whether or not the pre-refresh rows were read, next to the
        pre-refresh line when that prints; flag and verdict unchanged."""
        m = pokemon_map_with_cluster1()
        m["clusters_before"][0].update(members=copy.deepcopy(load("pokemon_cluster1_screenshot_members.json")["members"]), members_complete=True)
        m.update(members_before_read=True, members_before_reason=None, members_before_not_closed=[1])
        holders, plain, a = self.assess_pair(m)
        note = "the pre-refresh member read could not close Cluster 1 before the refresh, so the refreshed size read may list fewer clusters"
        self.assertEqual(a["bubblemaps_members"]["pre_refresh_not_closed"]["clusters"], [1])
        self.assertIn(note, a["bubblemaps_members"]["pre_refresh_not_closed"]["note"])
        self.assertEqual(a["bubblemaps_pre_refresh"]["not_closed"]["clusters"], [1])
        self.assertIn("its members are listed under Sources read", a["bubblemaps_pre_refresh"]["line"])
        self.assertIn(note, a["bubblemaps_pre_refresh"]["line"])
        summary = hf.executive_summary(POK, holders, a)
        self.assertIn(note, summary[2])
        md = hf.markdown_report(POK, holders, None, 0, a)
        self.assertIn(f"  - size read warning: {note}", md)
        self.assertEqual(json.dumps(a["flag"]), json.dumps(plain["flag"]))
        self.assertEqual(json.dumps(a["verdict"]), json.dumps(plain["verdict"]))
        # no effective refresh: no pre-refresh line, the warning still shows in the Bubblemaps block
        m["refresh_effective"] = False
        _, plain, a = self.assess_pair(m)
        self.assertIsNone(a["bubblemaps_pre_refresh"])
        self.assertIn("size read warning:", "\n".join(hf.bubblemaps_member_lines(a)))
        self.assertEqual(json.dumps(a["verdict"]), json.dumps(plain["verdict"]))
        # members not read, warning present: shown too
        m.update(refresh_effective=True, members_parse_ok=False, members_reason="layout changed")
        _, _, a = self.assess_pair(m)
        self.assertIn("size read warning:", "\n".join(hf.bubblemaps_member_lines(a)))
        self.assertIsNone(VERDICT_WORDS.search(a["bubblemaps_pre_refresh"]["line"]))

    def test_other_mint_or_no_map_adds_nothing(self):
        self.assertIsNone(hf.bubblemaps_display(load("pokemon_bubblemaps_map_20261020.json"), "So11111111111111111111111111111111111111112"))
        self.assertIsNone(hf.bubblemaps_display(None, POK))
        a = hf.assess(hf._public(pokemon_holders()), None, [])
        self.assertNotIn("bubblemaps_members", a)
        self.assertEqual(hf.bubblemaps_member_lines(a), [])

    def test_new_output_never_says_clean_low_or_safe(self):
        holders = pokemon_holders()
        m = pokemon_map_with_cluster1()
        m["clusters_list_only"] = [{"cluster": 9, "wallets": 2, "supply_pct": 0.05, "members": [], "members_complete": False, "members_note": "x"}]
        m.update(settle_s=38.0, settle_list_changed_s=33.0)
        for variant in (m, {**m, "members_parse_ok": False, "members_reason": "the Address List could not be read"}, load("pokemon_bubblemaps_map_20261020.json")):
            d = hf.bubblemaps_display(variant, POK, holders, load("pokemon_funders_names_20261020.json"), load("pokemon_gmgn_tags_20261020.json"))
            a = hf.assess(hf._public(holders), None, [hf.bubblemaps_finding(variant, POK)], bubblemaps_members=d)
            new = hf.bubblemaps_member_lines(a) + [hf.executive_summary(POK, holders, a)[2]]
            for ln in new:
                self.assertIsNone(VERDICT_WORDS.search(ln.replace(hf.pw.PLACEHOLDER, "")), ln)
        for text in (bm.__doc__, hf.MEMBERS_CANNOT_SHOW):
            self.assertIsNone(re.search(r"\b(clean|safe)\b", text, re.I))


class AssessCliTests(unittest.TestCase):
    """The offline assess subcommand over a saved run folder: the flag and the verdict are the same as without the member
    display (what origin/master writes for the same files), and report.md only gains lines."""

    def run_assess(self, folder: Path, map_raw: dict, tag: str, *, display: bool = True) -> tuple[dict, str]:
        path = folder.parent / "map.json"
        path.write_text(json.dumps(map_raw))
        os.utime(path, (1_800_000_000, 1_800_000_000))
        out = folder.parent / f"out-{tag}"
        argv = ["assess", POK, "--from", str(folder), "--out", str(out), "--bubblemaps-json", str(path),
                "--gmgn-holders-json", str(FIX / "pokemon_gmgn_tags_20261020.json")]
        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            if not display:  # no display fields: the assessment and report the code before HS-BM-MEMBERS-T1 wrote
                stack.enter_context(mock.patch.object(hf, "bubblemaps_display", lambda *a, **k: None))
            self.assertEqual(hf.main(argv), 0)
        return json.loads((out / "assessment.json").read_text()), (out / "report.md").read_text()

    def test_same_flag_and_verdict_and_only_new_report_lines(self):
        for map_raw in (load("pokemon_bubblemaps_map_20261020.json"), pokemon_map_with_cluster1()):
            with tempfile.TemporaryDirectory() as tmp:
                run = Path(tmp) / "run"
                run.mkdir()
                with contextlib.redirect_stdout(io.StringIO()):
                    hf._write(run, pokemon_holders(), None, 0, POK)
                a0, r0 = self.run_assess(run, map_raw, "plain", display=False)
                a1, r1 = self.run_assess(run, map_raw, "members")
            self.assertEqual(json.dumps(a0["flag"], indent=1), json.dumps(a1["flag"], indent=1))
            self.assertEqual(json.dumps(a0["verdict"], indent=1), json.dumps(a1["verdict"], indent=1))
            self.assertEqual({k: v for k, v in a1.items() if not k.startswith("bubblemaps_")}, a0)
            diff = [ln for ln in difflib.unified_diff(r0.splitlines(), r1.splitlines(), lineterm="", n=0) if not ln.startswith(("---", "+++", "@@"))]
            self.assertEqual([ln for ln in diff if ln.startswith("-") and not ln.startswith("-Generated ")], [])  # only the Generated time may differ
            added = [ln[1:] for ln in diff if ln.startswith("+") and not ln.startswith("+Generated ")]
            self.assertTrue(added[0].startswith("- clear large cluster seen by Bubblemaps (pre-refresh snapshot, 33 min old): largest 16.21% (14 wallets)"))
            self.assertEqual(r1.splitlines()[r1.splitlines().index(added[0]) - 1][:8], "- FLAG: ")  # next to the FLAG
            for ln in added:
                self.assertIsNone(VERDICT_WORDS.search(ln.replace(hf.pw.PLACEHOLDER, "")), ln)
            if map_raw.get("members_parse_ok"):
                self.assertTrue(any("#5 `Be24Gbf5KisDk1LcWWZsBn8dvB816By7YzYF5zWZnRR6` 2.52%" in ln for ln in added))


if __name__ == "__main__":
    unittest.main()
