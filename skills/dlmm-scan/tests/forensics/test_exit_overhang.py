"""HS-OVERHANG-T1: the EXIT OVERHANG flag line and its block (scripts/exit_overhang.py --present), offline.

Fixtures: fixtures/exit_overhang/<run>/ holds byte-identical copies of four saved files of three scans that dumped (mil
2026-10-24, Marvin and $BILLIONS 2026-10-25; public data): gmgn_holder_pnl.json, holders.json, creator_fees.json and
followup/create_slot_trace.json. The expected numbers are the replay's (DLMM evidence HOLDER-SCAN-OVERHANG-20261025,
overhang_check.py and overhang-results.txt).

Covers the ticket's acceptance criteria: the three replays (1); pools, infrastructure rows, pool_addresses and spin-off
bonding curves never counted as wallets (2); the bars at 2.0 / 1.99 / 1.0 / 0.99 (3); unusable avg_cost values shown apart
as no cost basis, never in the ratio, never a crash (4); the main pool from creator_fees first, the named fallback, and
not read when neither exists (5); GMGN not ok or a missing file reads not read, exit 0, never not raised (6); no verdict
words, and not raised always with "(not a safety signal)" (7); the run folder unchanged and the engines never reading
the output (8); no network import (9). Repair R1 (Verifier caveats on 9f28e99): a fallback main pool named in the flag line
itself (C2), "more than 99% lower" instead of "about 100% lower" (C3), "(dev included)" only when the trace names a dev
(C4), the transfer_in line worded as counted at GMGN's average buy (C5), the no-average-buy line saying what it counts and
that the holder PnL block's count differs (C1), and the biggest bags sorted largest first on unsorted input. Repair R2: the
fallback warning points both ways ("the ratio may be too high or too low"), pinned on the Verifier's case where a pool row
larger than the canonical pool turns DANGER 2.0x into not raised 0.8x (R2-1), and tagged transfer_in wallets without a GMGN
average buy sit under no cost basis, as the line now says (R2-2)."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import exit_overhang as eo  # noqa: E402
import gmgn_rows as gr  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "exit_overhang"
MIL = FIX / "20261024T050031Z-3w67qwokqjcS6KbZhzNonhmFNGjYbWneB7g5HTXwpump"
MARVIN = FIX / "20261025T031703Z-FmuciqKXRRnKqhi7BNin5mYH6fm3oTrfVB5A5Fyrpump"
BILLIONS = FIX / "20261025T060315Z-9uNgkUWsRDCMsnE6UX9aJ9bCwj3Lw3pjTU4TnMEnpump"
SPIN_OFF_CURVES = ("AFq3nk3ssHAcfhYUmn9EoiSqwzMydjLBAhFET59qsVu5", "B6iHwi5eGeKJW6nejM2GZqeHHFbzwnPMiYg2joyFcsgH")  # $BILLIONS: pump.fun curves of coins quoted in it
MARK = "[for the executive summary] "
# The replay's numbers (overhang-results.txt): wallets and share at entry <= 1/2 and <= 1/3 of the price with the ratio to
# the main pool, no cost basis, transfer_in tag, main pool (address, share) and all pool rows together.
EXPECTED = {
    "mil": (MIL, (48, "33.59", "3.6"), (31, "22.75", "2.5"), (3, "0.89"), (21, "14.02"), ("63cdEBLRBRTYqxfmqs3q3bVDDUuFxqFn8opj3SYLPZti", "9.23"), "13.71"),
    "Marvin": (MARVIN, (43, "25.26", "4.1"), (33, "19.56", "3.1"), (4, "1.12"), (13, "10.10"), ("FYLA8ej1X6n4nBiEKCZ3zmvACeH5MhdPRkkgPqtWsm1n", "6.22"), "6.82"),
    "$BILLIONS": (BILLIONS, (48, "23.02", "3.2"), (7, "3.48", "0.5"), (4, "3.21"), (11, "6.68"), ("3daykMmmqP2J4d9Z3Rg1AZZJdit5vyrSZ2BSJ93aNswr", "7.21"), "9.23"),
}
BILLIONS_BLOCK = [
    "[for the executive summary] EXIT OVERHANG: DANGER (provisional) — 23.02% of supply sits in 48 wallets that bought at half today's price or less: 3.2x the main pool's tokens.",
    "Exit overhang (cheap-entry bags vs the main pool; GMGN top 100; provisional)",
    "  price at scan $0.000456, market cap $448k: median of GMGN's usd_value / balance, times the median supply (balance / share of supply) of "
    "983,211,121 tokens; GMGN snapshot 2026-10-25 06:03 UTC = 2026-10-25 13:03 WIB",
    "  main pool: 3daykMmmqP2J4d9Z3Rg1AZZJdit5vyrSZ2BSJ93aNswr, 7.21% of supply (holders.json), found through creator_fees: the canonical PumpSwap "
    "pool of this token; all pool rows together (holders.json infrastructure rows): 9.23% of supply, 5 rows",
    "  entry at or below 1/2 of today's price (bought at or below $224k market cap): 48 wallets, 23.02% of supply = 3.2x the main pool's tokens",
    "  entry at or below 1/3 of today's price (bought at or below $149k market cap): 7 wallets, 3.48% of supply = 0.5x the main pool's tokens",
    "  pool math: if all the wallets at or below 1/2 (48 wallets) sold into the main pool at once, constant-product pool math puts the price about 94% lower; "
    "real dumps are spread out, and other pools and buyers absorb some of it",
    "  the five biggest such bags (entry = GMGN's average buy as a market cap):",
    "    #1 CE44oKS3wpUerx8afyeii56u5oQjBLZknzm4Q2CYHUz9: 2.10% of supply, entry $154k market cap, bought 2.9x below today's price",
    "    #2 8BVNwPGGYqMxn8NnyrC66kkcwBy83W3DLK4T9X5RZDfX: 1.88% of supply, entry $167k market cap, bought 2.7x below today's price",
    "    #3 9z332Pxs4xaz7CdE4sYPEHu9a9qrxcUTkbvMXVo1q1Q8: 1.63% of supply, entry $177k market cap, bought 2.5x below today's price",
    "    #4 8zdqiwWsKUzdKSDAksh58EcAF2Eqk3hXr1FnapnkQuYX: 1.55% of supply, entry $203k market cap, bought 2.2x below today's price; "
    "transfer_in (GMGN tag): entry may be cheaper than shown",
    "    #5 4xbeoxDPTUeiaAvt5afxNtLHPYqUW7Xb3X4sK8sMvCqQ: 1.13% of supply, entry $36.1k market cap, bought 12.4x below today's price",
    "  no cost basis here = no average buy from GMGN: 4 wallets, 3.21% of supply (GMGN's top 100 after pools and holders.json infrastructure rows "
    "are removed; not in the ratio; the holder PnL block also counts a GMGN PnL as a cost basis, so its number differs)",
    "  GMGN transfer_in tag: 11 wallets, 6.68% of supply (counted above at GMGN's average buy where GMGN has one, otherwise under no cost basis; "
    "their real entry may be cheaper)",
    "  dev-sent bags (counted at zero cost; follow-up lane wallet_rpc_reads, public Solana RPC; owner decision 2026-10-27: \"Count at zero cost "
    "(Recommended)\"): not read (followup/wallet_rpc_reads.json missing); nothing counted",
    "  create-slot buyers still holding: 0 of 5 traced wallets (dev included), 0.00% of supply (holders.json); entry near zero; counted above only "
    "when GMGN has their cost",
    "  bars: DANGER at 2x, CAUTION at 1x the main pool's tokens; provisional and unvalidated: tested on 3 coins that dumped and 0 that held",
    "  cannot see: holders outside GMGN's top 100 (47.10% of supply); wallets that bought through apps without a cost record; tokens received by "
    "transfer; sellers' intent; whether GMGN's basis is average or FIFO (its numbers are used as given)",
    "  presentation flag only: never an engine input, never passed to assess, never counted toward NO_ALARM; it never changes the forensics or "
    "analysis FLAG, verdict or threshold",
]
VERDICT_RE = re.compile(r"(?i)\b(?:clean|safe|safer|safest|low|legit|safu)\b|low[\s_-]*risk|nobody")
NO_ALARM_RE = re.compile(r"(?i)no[\s_-]*alarm")  # allowed only in "never counted toward NO_ALARM"
NOT_RAISED_RE = re.compile(r"not raised(?! \(not a safety signal\))")

# ----------------------------------------------------------------------------- synthetic run folders

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MINT = "Mint" + "1" * 36 + "pump"
POOL = "PooLA" + "1" * 39
POOL_B = "PooLB" + "1" * 39
PRICE = 0.001  # USD per token in every synthetic row
SUPPLY = 1_000_000_000.0


def addr(i: int) -> str:
    return "Syn" + B58[i % 58] + B58[i // 58 % 58] + "1" * 39


def row(address: str, share: float, avg_cost=None, *, addr_type: int = 0, transfer_in: bool = False) -> dict:
    balance = share * SUPPLY
    return {"address": address, "amount_percentage": share, "addr_type": addr_type, "pool": addr_type == 2, "exchange": None,
            "avg_cost": avg_cost, "unrealized_pnl": None, "balance": balance, "usd_value": balance * PRICE, "transfer_in": transfer_in, "app_tags": []}


def write_run(folder: Path, rows: list[dict], *, pool_pct: float = 12.5, infra: dict | None = None, pool_addresses: list | None = None,
              fees: dict | None | bool = True, gmgn: dict | None = None, holders: dict | None = None, trace: dict | None = None) -> Path:
    """A run folder with the files the script reads. infra: holders.json infrastructure rows {address: share_pct}
    (default: the pool at pool_pct). fees True: creator_fees names POOL as this token's identified canonical pool; a dict
    replaces the file; None leaves it out."""
    folder.mkdir(parents=True, exist_ok=True)
    infra = {POOL: pool_pct} if infra is None else infra
    data = {"schema": eo.PNL_SCHEMA, "provider": "GMGN", "mint": MINT, "status": "ok", "reason": None, "fetched_at": "2026-10-25T06:03:55Z",
            "presentation_only": True, "fields_missing": [], "rows": [row(POOL, pool_pct / 100, addr_type=2), *rows]}
    data.update(gmgn or {})
    (folder / eo.PNL_FILE).write_text(json.dumps(data), encoding="utf-8")
    top = [{"rank": n, "wallet": a, "share_pct": s, "infrastructure": True} for n, (a, s) in enumerate(infra.items(), 1)]
    top += [{"rank": len(top) + n, "wallet": r["address"], "share_pct": (r["amount_percentage"] if isinstance(r.get("amount_percentage"), float) else 0) * 100,
             "infrastructure": False} for n, r in enumerate(rows, 1) if isinstance(r, dict) and isinstance(r.get("address"), str)]
    hold = {"mint": MINT, "pool_addresses": list(infra) if pool_addresses is None else pool_addresses, "top_holders": top,
            "owner_balances": {t["wallet"]: t["share_pct"] * 1e6 for t in top}}
    hold.update(holders or {})
    (folder / eo.HOLDERS_FILE).write_text(json.dumps(hold), encoding="utf-8")
    if fees is True:
        fees = {"schema": eo.FEES_SCHEMA, "mint": MINT, "status": "ok", "reason": None,
                "pools": [{"address": POOL, "status": "identified", "base_mint": MINT, "canonical": True}, {"address": "x", "status": "not_found"}]}
    if isinstance(fees, dict):
        (folder / eo.FEES_FILE).write_text(json.dumps(fees), encoding="utf-8")
    if trace is not None:
        (folder / "followup").mkdir(exist_ok=True)
        (folder / eo.TRACE_FILE).write_text(json.dumps(trace), encoding="utf-8")
    return folder


def cheap(i: int, share: float, multiple: float = 4.0, **kw) -> dict:
    """A wallet whose GMGN average buy is 1/multiple of the price."""
    return row(addr(i), share, PRICE / multiple, **kw)


def dear(i: int, share: float) -> dict:
    return row(addr(i), share, PRICE)  # bought at today's price


def run_main(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = eo.main(argv)
        except SystemExit as stop:  # argparse refuses a bad command line with exit 2
            code = stop.code
    return code, out.getvalue(), err.getvalue()


class TempRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def copy(self, run: Path, name: str = "run") -> Path:
        return Path(shutil.copytree(run, self.tmp / name))


# ----------------------------------------------------------------------------- 1: the three replays


class FixtureReplayTests(unittest.TestCase):
    def test_the_fixtures_are_the_saved_files(self):
        for name, (run, *_) in EXPECTED.items():
            for f in (eo.PNL_FILE, eo.HOLDERS_FILE, eo.FEES_FILE, eo.TRACE_FILE):
                self.assertTrue((run / f).is_file(), f"{name}: {f}")

    def test_all_three_flag_lines_read_danger_with_the_replay_numbers(self):
        for name, (run, (n, pct, ratio), *_) in EXPECTED.items():
            with self.subTest(name):
                self.assertEqual(eo.present(run)[0], f"{MARK}EXIT OVERHANG: DANGER (provisional) — {pct}% of supply sits in {n} wallets that bought at "
                                                     f"half today's price or less: {ratio}x the main pool's tokens.")

    def test_every_replay_number(self):
        for name, (run, half, third, no_basis, tagged, (pool, pool_pct), all_pools) in EXPECTED.items():
            with self.subTest(name):
                m = eo.measure(run)
                self.assertEqual((len(m["cheap"]), f"{eo._total(m['cheap']):.2f}", f"{m['ratio']:.1f}"), half)
                self.assertEqual((len(m["deep"]), f"{eo._total(m['deep']):.2f}", f"{m['deep_ratio']:.1f}"), third)
                self.assertEqual((len(m["no_basis"]), f"{eo._total(m['no_basis']):.2f}"), no_basis)
                self.assertEqual((len(m["transfer_in"]), f"{eo._total(m['transfer_in']):.2f}"), tagged)
                self.assertEqual((m["pool"], f"{m['pool_pct']:.2f}", f"{m['pool_rows_pct']:.2f}"), (pool, pool_pct, all_pools))
                self.assertTrue(m["pool_how"].startswith("found through creator_fees"), m["pool_how"])
                lines = eo.present(run)
                self.assertIn(f"{half[0]} wallets, {half[1]}% of supply = {half[2]}x the main pool's tokens", lines[4])
                self.assertIn(f"{third[0]} wallets, {third[1]}% of supply = {third[2]}x the main pool's tokens", lines[5])
                self.assertTrue(any(x.startswith(f"  no cost basis here = no average buy from GMGN: {no_basis[0]} wallets, {no_basis[1]}% of supply (") for x in lines))
                self.assertIn(f"  GMGN transfer_in tag: {tagged[0]} wallets, {tagged[1]}% of supply (counted above at GMGN's average buy where GMGN has one, "
                              "otherwise under no cost basis; their real entry may be cheaper)", lines)
                self.assertNotIn("main pool by fallback", lines[0], "creator_fees named the pool on all three")
                # R2-2: a tagged wallet with an average buy is counted by it; one without is under no cost basis, never in the ratio
                cheap_ids, no_basis_ids = {id(x) for x in m["cheap"]}, {id(x) for x in m["no_basis"]}
                for r in m["transfer_in"]:
                    if r["avg_cost"]:
                        self.assertNotIn(id(r), no_basis_ids)
                        self.assertEqual(id(r) in cheap_ids, r["multiple"] >= eo.OVERHANG_ENTRY_MULTIPLE)
                    else:
                        self.assertIn(id(r), no_basis_ids)
                        self.assertNotIn(id(r), cheap_ids)

    def test_tagged_wallets_without_an_average_buy_sit_under_no_cost_basis(self):
        """R2-2: on $BILLIONS 4 of the 11 transfer_in wallets (3.21% of the 6.68%) have no GMGN average buy: they are the
        no-cost-basis wallets, not counted in the ratio."""
        m = eo.measure(BILLIONS)
        without = [r for r in m["transfer_in"] if not r["avg_cost"]]
        self.assertEqual((len(m["transfer_in"]), len(without), f"{eo._total(without):.2f}"), (11, 4, "3.21"))
        self.assertEqual({r["address"] for r in without}, {r["address"] for r in m["no_basis"]})
        self.assertFalse({r["address"] for r in without} & {r["address"] for r in m["cheap"]})

    def test_the_billions_block_as_printed(self):
        self.assertEqual(eo.present(BILLIONS), BILLIONS_BLOCK)

    def test_the_command_line_prints_the_block_and_exits_0(self):
        code, out, err = run_main(["--present", str(BILLIONS)])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out.splitlines(), BILLIONS_BLOCK)

    def test_the_mark_is_the_gmgn_rows_mark(self):
        self.assertEqual(eo.SUMMARY_MARK, gr.PNL_SUMMARY_MARK)


# ----------------------------------------------------------------------------- 2: what never counts as a wallet


class ExclusionTests(TempRun):
    def test_pools_infrastructure_pool_addresses_and_spin_off_curves_are_never_wallets(self):
        for name, (run, *_) in EXPECTED.items():
            with self.subTest(name):
                m = eo.measure(run)
                holders = json.loads((run / eo.HOLDERS_FILE).read_text())
                never = {r["wallet"] for r in holders["top_holders"] if r["infrastructure"]} | set(holders["pool_addresses"])
                never |= {r["address"] for r in m["rows"] if r["pool"]}
                self.assertEqual({r["address"] for r in m["wallets"]} & never, set())
                self.assertEqual(len(m["wallets"]) + len({r["address"] for r in m["rows"]} & never), len(m["rows"]))
        m = eo.measure(BILLIONS)
        rows = {r["address"]: r for r in m["rows"]}
        for curve in SPIN_OFF_CURVES:
            self.assertIn(curve, rows, "the curve is a GMGN row, so excluding it is tested")
            self.assertNotIn(curve, {r["address"] for r in m["wallets"]})
        self.assertFalse(rows[SPIN_OFF_CURVES[0]]["pool"], "GMGN does not mark it as a pool: only holders.json removes it")
        self.assertFalse(any(curve in line for line in eo.present(BILLIONS) for curve in SPIN_OFF_CURVES))

    def test_the_exclusion_bites(self):
        """Negative check: with the curve dropped from holders.json's infrastructure rows and pool_addresses, it counts as a wallet."""
        run = self.copy(BILLIONS)
        holders = json.loads((run / eo.HOLDERS_FILE).read_text())
        holders["pool_addresses"] = [a for a in holders["pool_addresses"] if a != SPIN_OFF_CURVES[0]]
        for r in holders["top_holders"]:
            if r["wallet"] == SPIN_OFF_CURVES[0]:
                r["infrastructure"] = False
        (run / eo.HOLDERS_FILE).write_text(json.dumps(holders))
        self.assertIn(SPIN_OFF_CURVES[0], {r["address"] for r in eo.measure(run)["wallets"]})

    def test_a_gmgn_pool_row_is_removed_even_outside_holders_json(self):
        run = write_run(self.tmp / "r", [cheap(1, 0.2), row(addr(2), 0.3, PRICE / 10, addr_type=2)])
        m = eo.measure(run)
        self.assertEqual([r["address"] for r in m["wallets"]], [addr(1)])


# ----------------------------------------------------------------------------- 3: the bars


class BarTests(TempRun):
    def flag(self, share: float, name: str) -> str:
        return eo.present(write_run(self.tmp / name, [cheap(1, share), dear(2, 0.05)], pool_pct=12.5))[0]

    def test_the_bars_at_the_boundaries(self):
        head = f"{MARK}EXIT OVERHANG: "
        self.assertEqual(self.flag(0.25, "2.00"), head + "DANGER (provisional) — 25.00% of supply sits in 1 wallet that bought at half today's price "
                                                         "or less: 2.0x the main pool's tokens.")
        self.assertEqual(self.flag(0.24875, "1.99"), head + "CAUTION (provisional) — 24.88% of supply sits in 1 wallet that bought at half today's "
                                                            "price or less: 1.99x the main pool's tokens.")
        self.assertEqual(self.flag(0.125, "1.00"), head + "CAUTION (provisional) — 12.50% of supply sits in 1 wallet that bought at half today's "
                                                          "price or less: 1.0x the main pool's tokens.")
        self.assertEqual(self.flag(0.12375, "0.99"), head + "not raised (not a safety signal) — 12.38% of supply sits in 1 wallet that bought at "
                                                            "half today's price or less: 0.99x the main pool's tokens.")

    def test_the_level_function_and_the_constants(self):
        self.assertEqual((eo.OVERHANG_DANGER_RATIO, eo.OVERHANG_CAUTION_RATIO, eo.OVERHANG_ENTRY_MULTIPLE, eo.OVERHANG_DEEP_ENTRY_MULTIPLE), (2.0, 1.0, 2.0, 3.0))
        for ratio, want in ((2.0, "DANGER (provisional)"), (5.0, "DANGER (provisional)"), (1.99, "CAUTION (provisional)"), (1.0, "CAUTION (provisional)"),
                            (0.99, "not raised (not a safety signal)"), (0.0, "not raised (not a safety signal)")):
            self.assertEqual(eo.level(ratio), want, ratio)
        self.assertEqual([eo._times(r) for r in (3.19, 1.96, 1.99, 0.96, 2.0, 0.5)], ["3.2x", "1.96x", "1.99x", "0.96x", "2.0x", "0.5x"])

    def test_the_entry_bar_is_half_the_price_or_less(self):
        run = write_run(self.tmp / "e", [cheap(1, 0.1, multiple=2.0), cheap(2, 0.1, multiple=1.99), cheap(3, 0.1, multiple=3.0)], pool_pct=10.0)
        m = eo.measure(run)
        self.assertEqual(sorted(r["address"] for r in m["cheap"]), sorted([addr(1), addr(3)]))
        self.assertEqual([r["address"] for r in m["deep"]], [addr(3)])
        self.assertEqual(f"{m['ratio']:.1f}", "2.0")

    def test_no_cheap_wallet_reads_not_raised_with_its_numbers(self):
        lines = eo.present(write_run(self.tmp / "n", [dear(1, 0.3)]))
        self.assertEqual(lines[0], f"{MARK}EXIT OVERHANG: not raised (not a safety signal) — 0.00% of supply sits in 0 wallets that bought at half "
                                   "today's price or less: 0.0x the main pool's tokens.")
        self.assertIn("  pool math and biggest bags: no wallet in GMGN's top 100 bought at or below 1/2 of today's price (by GMGN's average buy)", lines)

    def test_a_drop_that_rounds_to_100_reads_more_than_99_percent(self):
        """C3: never "about 100% lower". Ratio 13 gives 99.49% (about 99%), ratio 14 gives 99.56% (rounds to 100: more than 99%)."""
        for name, share, want in (("13x", 0.13, "about 99% lower"), ("14x", 0.14, "more than 99% lower"), ("182x", 0.5659, "more than 99% lower")):
            with self.subTest(name):
                lines = eo.present(write_run(self.tmp / name, [cheap(1, share)], pool_pct=1.0 if name != "182x" else 0.31))
                math_line = next(x for x in lines if x.startswith("  pool math: "))
                self.assertIn(f"puts the price {want};", math_line)
                self.assertNotIn("about 100%", "\n".join(lines))

    def test_the_pool_math_line(self):
        lines = eo.present(write_run(self.tmp / "p", [cheap(1, 0.125)], pool_pct=12.5))  # ratio 1: 1 - (1/2)^2 = 75%
        self.assertIn("  pool math: if all the wallets at or below 1/2 (1 wallet) sold into the main pool at once, constant-product pool math puts the price "
                      "about 75% lower; real dumps are spread out, and other pools and buyers absorb some of it", lines)


class BiggestBagsTests(TempRun):
    def test_the_five_biggest_bags_are_sorted_largest_first_on_unsorted_input(self):
        """Test gap (Repair R1): GMGN's row order is not by share; the bag list is sorted by share, largest first, and a tie
        keeps GMGN's order."""
        shares = [0.01, 0.05, 0.02, 0.07, 0.03, 0.06, 0.04, 0.05]  # addr(1)..addr(8); addr(2) and addr(8) tie at 5%
        lines = eo.present(write_run(self.tmp / "sort", [cheap(i, s) for i, s in enumerate(shares, 1)], pool_pct=10.0))
        bags = [x for x in lines if x.startswith("    #")]
        self.assertEqual([x.split(":", 1)[0] for x in bags], [f"    #1 {addr(4)}", f"    #2 {addr(6)}", f"    #3 {addr(2)}", f"    #4 {addr(8)}", f"    #5 {addr(7)}"])
        self.assertEqual([x.split(": ", 1)[1].split(" of supply")[0] for x in bags], ["7.00%", "6.00%", "5.00%", "5.00%", "4.00%"])
        self.assertIn("  the five biggest such bags (entry = GMGN's average buy as a market cap):", lines)


# ----------------------------------------------------------------------------- 4: unusable average buys


class GarbageCostTests(TempRun):
    GARBAGE = (None, 0, 0.0, -1.0, "0.0001", float("nan"), float("inf"), True, False, [0.0001], {"v": 1})

    def test_unusable_avg_cost_is_no_cost_basis_never_in_the_ratio_never_a_crash(self):
        rows = [cheap(0, 0.2)] + [row(addr(i), 0.01, value) for i, value in enumerate(self.GARBAGE, 1)]
        run = write_run(self.tmp / "g", rows, pool_pct=10.0)
        m = eo.measure(run)
        self.assertEqual([r["address"] for r in m["cheap"]], [addr(0)])
        self.assertEqual(len(m["no_basis"]), len(self.GARBAGE))
        lines = eo.present(run)
        self.assertEqual(lines[0], f"{MARK}EXIT OVERHANG: DANGER (provisional) — 20.00% of supply sits in 1 wallet that bought at half today's price "
                                   "or less: 2.0x the main pool's tokens.")
        self.assertTrue(any(x.startswith(f"  no cost basis here = no average buy from GMGN: {len(self.GARBAGE)} wallets, 11.00% of supply (") for x in lines))

    def test_no_usable_average_buy_at_all_reads_not_read(self):
        run = write_run(self.tmp / "a", [row(addr(i), 0.1, value) for i, value in enumerate(self.GARBAGE)])
        self.assertEqual(eo.present(run)[0], f"{MARK}EXIT OVERHANG: not read (GMGN gave no usable average buy)")

    def test_garbage_shares_and_prices_never_crash(self):
        rows = [cheap(1, 0.2), {**cheap(2, 0.1), "amount_percentage": "0.1"}, {**cheap(3, 0.1), "balance": None, "usd_value": float("nan")},
                {**cheap(4, 0.1), "amount_percentage": 7.0}, {"address": 12}, "not a row", {**cheap(1, 0.9)}]
        lines = eo.present(write_run(self.tmp / "s", rows, pool_pct=10.0))
        # kept: #1 (20%), #2 and #4 (share unreadable: counted with 0%, as the replay does), #3 (no price, its share counts);
        # skipped: a non-text address, a non-row and the repeated #1
        self.assertEqual(lines[0], f"{MARK}EXIT OVERHANG: DANGER (provisional) — 30.00% of supply sits in 4 wallets that bought at half today's price "
                                   "or less: 3.0x the main pool's tokens.")


# ----------------------------------------------------------------------------- 5: the main pool


class MainPoolTests(TempRun):
    ROWS = [cheap(1, 0.2), dear(2, 0.1)]

    def line(self, lines: list[str]) -> str:
        return next(x for x in lines if x.startswith("  main pool: "))

    def test_creator_fees_canonical_first_even_when_another_pool_row_is_larger(self):
        run = write_run(self.tmp / "c", self.ROWS, infra={POOL_B: 20.0, POOL: 10.0},
                        fees={"schema": eo.FEES_SCHEMA, "mint": MINT, "status": "ok", "pools": [{"address": POOL, "status": "identified", "base_mint": MINT}]})
        m = eo.measure(run)
        self.assertEqual((m["pool"], m["pool_pct"], f"{m['ratio']:.1f}"), (POOL, 10.0, "2.0"))
        self.assertEqual(self.line(eo.present(run)), f"  main pool: {POOL}, 10.00% of supply (holders.json), found through creator_fees: the canonical "
                                                     "PumpSwap pool of this token; all pool rows together (holders.json infrastructure rows): 30.00% of supply, 2 rows")

    def test_the_fallback_is_the_largest_pool_row_and_is_named(self):
        cases = {
            "missing": (None, "creator_fees.json missing"),
            "unavailable": ({"schema": eo.FEES_SCHEMA, "mint": MINT, "status": "unavailable", "reason": "rpc_timeout", "pools": []}, "creator_fees unavailable: rpc_timeout"),
            "other base mint": ({"schema": eo.FEES_SCHEMA, "mint": MINT, "status": "ok", "pools": [{"address": POOL, "status": "identified", "base_mint": POOL_B}]},
                                "no identified pool of this token in creator_fees"),
            "not identified": ({"schema": eo.FEES_SCHEMA, "mint": MINT, "status": "ok", "pools": [{"address": POOL, "status": "unavailable", "base_mint": MINT}]},
                               "no identified pool of this token in creator_fees"),
            "other mint": ({"schema": eo.FEES_SCHEMA, "mint": POOL_B, "status": "ok", "pools": []}, "creator_fees.json is for another mint"),
            "foreign file": ({"schema": "something/1"}, "creator_fees.json unreadable"),
            "pool not in holders": ({"schema": eo.FEES_SCHEMA, "mint": MINT, "status": "ok", "pools": [{"address": "PooLC" + "1" * 39, "status": "identified", "base_mint": MINT}]},
                                    "the creator_fees canonical pool has no share in the holders.json rows"),
        }
        for name, (fees, why) in cases.items():
            with self.subTest(name):
                run = write_run(self.tmp / name.replace(" ", "-"), self.ROWS, infra={POOL_B: 20.0, POOL: 10.0}, fees=fees)
                m = eo.measure(run)
                self.assertEqual((m["pool"], m["pool_pct"], f"{m['ratio']:.1f}"), (POOL_B, 20.0, "1.0"))
                lines = eo.present(run)
                self.assertEqual(self.line(lines), f"  main pool: {POOL_B}, 20.00% of supply (holders.json), fallback: the largest holders.json "
                                                   f"pool row ({why}); it could be another pool or a spin-off coin's bonding curve; all pool rows "
                                                   "together (holders.json infrastructure rows): 30.00% of supply, 2 rows")
                self.assertEqual(lines[0], f"{MARK}EXIT OVERHANG: CAUTION (provisional) — 20.00% of supply sits in 1 wallet that bought at half today's "
                                           f"price or less: 1.0x the main pool's tokens (main pool by fallback: {why}; the ratio may be too high or too low).")

    def test_the_fallback_on_a_real_run_gives_the_same_pool(self):
        run = self.copy(BILLIONS)
        (run / eo.FEES_FILE).unlink()
        m = eo.measure(run)
        self.assertEqual((m["pool"], f"{m['ratio']:.1f}"), ("3daykMmmqP2J4d9Z3Rg1AZZJdit5vyrSZ2BSJ93aNswr", "3.2"))
        self.assertTrue(m["pool_how"].startswith("fallback: the largest holders.json pool row (creator_fees.json missing)"))
        self.assertEqual(eo.present(run)[0], f"{MARK}EXIT OVERHANG: DANGER (provisional) — 23.02% of supply sits in 48 wallets that bought at half "
                                             "today's price or less: 3.2x the main pool's tokens (main pool by fallback: creator_fees.json missing; "
                                             "the ratio may be too high or too low).")

    def test_a_fallback_pool_larger_than_the_canonical_pool_deflates_the_ratio(self):
        """R2-1 (the Verifier's case): canonical pool 5%, a second pool row 12%, cheap wallets 10%. With creator_fees: DANGER
        2.0x. On the fallback the largest row (12%) is taken: 0.8x, not raised, so the warning must point both ways, never
        "overstated" only."""
        rows = [cheap(1, 0.10), dear(2, 0.05)]
        infra = {POOL: 5.0, POOL_B: 12.0}
        canonical = eo.present(write_run(self.tmp / "with-fees", rows, infra=infra))
        self.assertEqual(canonical[0], f"{MARK}EXIT OVERHANG: DANGER (provisional) — 10.00% of supply sits in 1 wallet that bought at half today's price "
                                       "or less: 2.0x the main pool's tokens.")
        fallback = eo.present(write_run(self.tmp / "no-fees", rows, infra=infra, fees=None))
        self.assertEqual(fallback[0], f"{MARK}EXIT OVERHANG: not raised (not a safety signal) — 10.00% of supply sits in 1 wallet that bought at half "
                                      "today's price or less: 0.8x the main pool's tokens (main pool by fallback: creator_fees.json missing; the ratio "
                                      "may be too high or too low).")
        self.assertNotIn("overstated", "\n".join(canonical + fallback))

    def test_a_tiny_side_pool_by_fallback_is_named_in_the_flag_line(self):
        """C2: the Verifier's non-pump run 20261025T070706Z-9jBB...: creator_fees empty (no_pump_curve) and one 0.31% Meteora
        row as the only pool row gave 182.4x. The flag line itself must say the main pool came from the fallback."""
        fees = {"schema": eo.FEES_SCHEMA, "mint": MINT, "status": "empty", "reason": "no_pump_curve", "pools": [{"address": POOL_B, "status": "not_found"}]}
        run = write_run(self.tmp / "side-pool", [cheap(1, 0.5659), dear(2, 0.1)], pool_pct=0.31, fees=fees)
        lines = eo.present(run)
        self.assertEqual(lines[0], f"{MARK}EXIT OVERHANG: DANGER (provisional) — 56.59% of supply sits in 1 wallet that bought at half today's price "
                                   "or less: 182.5x the main pool's tokens (main pool by fallback: creator_fees empty: no_pump_curve; the ratio may be too high or too low).")
        self.assertIn("fallback: the largest holders.json pool row (creator_fees empty: no_pump_curve)", self.line(lines))

    def test_no_pool_reserve_reads_not_read(self):
        for name, kwargs in (("no pool row", {"infra": {}, "fees": None}), ("infra row not a pool", {"infra": {POOL: 10.0}, "pool_addresses": [], "fees": None}),
                             ("zero share", {"infra": {POOL: 0.0}, "fees": None})):
            with self.subTest(name):
                lines = eo.present(write_run(self.tmp / name.replace(" ", "-"), self.ROWS, **kwargs))
                self.assertEqual(lines, [f"{MARK}EXIT OVERHANG: not read (no pool reserve found)", f"{eo.TITLE}: not read (no pool reserve found)"])


# ----------------------------------------------------------------------------- 6: not read


class NotReadTests(TempRun):
    def expect(self, run: Path, why: str) -> None:
        self.assertEqual(eo.present(run), [f"{MARK}EXIT OVERHANG: not read ({why})", f"{eo.TITLE}: not read ({why})"])
        code, out, err = run_main(["--present", str(run)])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out.splitlines()[0], f"{MARK}EXIT OVERHANG: not read ({why})")

    def test_gmgn_missing_not_ok_or_unreadable(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        self.expect(empty, "gmgn_holder_pnl.json missing")
        for status, reason, why in (("unavailable", "http_429", "GMGN unavailable: http_429"), ("empty", None, "GMGN empty: unknown"),
                                    ("unavailable", "Bad Reason!\nx", "GMGN unavailable: badreasonx")):
            with self.subTest(status):
                self.expect(write_run(self.tmp / f"{status}-{why[-4:]}", [cheap(1, 0.3)], gmgn={"status": status, "reason": reason, "rows": []}), why)
        bad = write_run(self.tmp / "bad", [cheap(1, 0.3)])
        (bad / eo.PNL_FILE).write_text("{not json", encoding="utf-8")
        self.expect(bad, "gmgn_holder_pnl.json unreadable")
        self.expect(write_run(self.tmp / "schema", [cheap(1, 0.3)], gmgn={"schema": "other/1"}), "gmgn_holder_pnl.json unreadable")
        self.expect(write_run(self.tmp / "norows", [], gmgn={"rows": []}), "no GMGN rows")

    def test_a_needed_field_missing_from_every_row(self):
        self.expect(write_run(self.tmp / "listed", [cheap(1, 0.3)], gmgn={"fields_missing": ["avg_cost"]}), "field missing: avg_cost")
        run = write_run(self.tmp / "absent", [cheap(1, 0.3)])
        data = json.loads((run / eo.PNL_FILE).read_text())
        for r in data["rows"]:
            r.pop("usd_value")
        (run / eo.PNL_FILE).write_text(json.dumps(data))
        self.expect(run, "field missing: usd_value")

    def test_holders_json_missing_or_for_another_mint(self):
        run = write_run(self.tmp / "h", [cheap(1, 0.3)])
        (run / eo.HOLDERS_FILE).unlink()
        self.expect(run, "holders.json missing")
        self.expect(write_run(self.tmp / "m", [cheap(1, 0.3)], holders={"mint": POOL_B}), "holders.json is for another mint")
        self.expect(write_run(self.tmp / "u", [cheap(1, 0.3)], holders={"top_holders": "x"}), "holders.json unreadable")

    def test_the_real_run_with_gmgn_not_ok(self):
        run = self.copy(BILLIONS)
        data = json.loads((run / eo.PNL_FILE).read_text())
        data.update(status="unavailable", reason="request_failed", rows=[])
        (run / eo.PNL_FILE).write_text(json.dumps(data))
        self.expect(run, "GMGN unavailable: request_failed")

    def test_a_bad_command_line_exits_2(self):
        for argv in ([], ["--present"], ["--present", str(self.tmp / "nowhere")], ["--present", str(BILLIONS / eo.PNL_FILE)], ["mint", "--present", str(BILLIONS)]):
            with self.subTest(argv):
                code, out, _ = run_main(argv)
                self.assertEqual((code, out), (2, ""))


# ----------------------------------------------------------------------------- create-slot buyers


class CreateSlotTests(TempRun):
    def trace(self, wallets: list[str], status: str = "ok", mint: str = MINT, dev: bool = True) -> dict:
        return {"schema": eo.TRACE_SCHEMA, "mint": mint, "status": status, "reason": "no_create_tx_pointer" if status == "unavailable" else None,
                "presentation_only": True,
                "trace": {"wallets": [{"wallet": w, "role": "dev" if n == 0 and dev else "wallet"} for n, w in enumerate(wallets)]}}

    def slot_line(self, run: Path) -> str:
        return next(x for x in eo.present(run) if "create-slot" in x)

    def test_buyers_still_holding_from_holders_json(self):
        rows = [cheap(1, 0.2), dear(2, 0.1)]
        run = write_run(self.tmp / "t", rows, pool_pct=10.0, trace=self.trace([addr(2), addr(9)]))
        self.assertEqual(self.slot_line(run), "  create-slot buyers still holding: 1 of 2 traced wallets (dev included), 25.00% of supply (holders.json); "
                                              "entry near zero; counted above only when GMGN has their cost")

    def test_dev_included_only_when_the_trace_names_a_dev(self):
        """C4: the 9jBB trace has six wallets and no dev role; "(dev included)" would be false there."""
        run = write_run(self.tmp / "nodev", [cheap(1, 0.2), dear(2, 0.1)], pool_pct=10.0, trace=self.trace([addr(2), addr(9)], dev=False))
        self.assertEqual(self.slot_line(run), "  create-slot buyers still holding: 1 of 2 traced wallets, 25.00% of supply (holders.json); "
                                              "entry near zero; counted above only when GMGN has their cost")
        self.assertNotIn("dev included", self.slot_line(run))

    def test_the_trace_not_read_never_hides_the_flag(self):
        cases = {"missing": (None, "create-slot trace not read (followup/create_slot_trace.json missing)"),
                 "unavailable": (self.trace([], "unavailable"), "create-slot trace not read (create_slot_trace unavailable: no_create_tx_pointer)"),
                 "other mint": (self.trace([addr(2)], mint=POOL_B), "create-slot trace not read (followup/create_slot_trace.json is for another mint)"),
                 "foreign": ({"schema": "x"}, "create-slot trace not read (followup/create_slot_trace.json unreadable)")}
        for name, (trace, want) in cases.items():
            with self.subTest(name):
                run = write_run(self.tmp / name.replace(" ", "-"), [cheap(1, 0.2)], pool_pct=10.0, trace=trace)
                self.assertEqual(self.slot_line(run), f"  {want}")
                self.assertTrue(eo.present(run)[0].startswith(f"{MARK}EXIT OVERHANG: DANGER (provisional)"))

    def test_the_fixtures_have_no_create_slot_buyer_left(self):
        for name, run, n in (("mil", MIL, 18), ("Marvin", MARVIN, 6), ("$BILLIONS", BILLIONS, 5)):
            with self.subTest(name):
                self.assertEqual(self.slot_line(run), f"  create-slot buyers still holding: 0 of {n} traced wallets (dev included), 0.00% of supply "
                                                      "(holders.json); entry near zero; counted above only when GMGN has their cost")


# ----------------------------------------------------------------------------- 7: wording


class WordingTests(TempRun):
    def all_outputs(self) -> list[str]:
        lines = [x for run in (MIL, MARVIN, BILLIONS) for x in eo.present(run)]
        for name, rows in (("danger", [cheap(1, 0.3)]), ("caution", [cheap(1, 0.15)]), ("none", [cheap(1, 0.05)]), ("zero", [dear(1, 0.3)])):
            lines += eo.present(write_run(self.tmp / name, rows, pool_pct=12.5))
        empty = self.tmp / "empty"
        empty.mkdir()
        lines += eo.present(empty)
        lines += eo.present(write_run(self.tmp / "nopool", [cheap(1, 0.3)], infra={}, fees=None))
        return lines

    def test_no_verdict_words_and_not_raised_always_says_not_a_safety_signal(self):
        lines = self.all_outputs()
        self.assertGreater(len(lines), 60)
        for line in lines:
            self.assertIsNone(VERDICT_RE.search(line), line)
            self.assertIsNone(NOT_RAISED_RE.search(line), line)
            self.assertEqual(len(NO_ALARM_RE.findall(line)), line.count("never counted toward NO_ALARM"), line)
        self.assertTrue(any("not raised (not a safety signal)" in x for x in lines), "the not-raised case is covered")
        self.assertTrue(any("EXIT OVERHANG: not read (" in x for x in lines), "the not-read case is covered")
        for line in lines:
            if "not read" in line:
                self.assertNotIn("not raised", line)

    def test_the_wording_check_bites(self):
        for text in ("EXIT OVERHANG: clean", "risk is low", "looks safe", "EXIT OVERHANG: not raised", "not raised — 1%"):
            self.assertTrue(VERDICT_RE.search(text) or NOT_RAISED_RE.search(text), text)


# ----------------------------------------------------------------------------- 8 and 9: offline, read only, never an engine input


class OfflineAndEngineTests(TempRun):
    def test_no_network_or_process_import_and_no_skill_import(self):
        tree = ast.parse((SCRIPTS / "exit_overhang.py").read_text(encoding="utf-8"))
        imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        self.assertLessEqual(imported, {"__future__", "argparse", "datetime", "json", "math", "re", "statistics", "sys", "pathlib", "typing"})
        for banned in ("urllib", "http", "socket", "ssl", "subprocess", "requests", "os", "importlib", "gmgn_rows", "helius_forensics"):
            self.assertNotIn(banned, imported, banned)
        text = (SCRIPTS / "exit_overhang.py").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"(?:https?|wss?)://", text))
        self.assertNotIn("environ", text)
        self.assertNotIn("getenv", text)

    def test_the_run_folder_is_unchanged(self):
        run = self.copy(BILLIONS)

        def snapshot():
            return {p.relative_to(run).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(run.rglob("*")) if p.is_file()}

        before = snapshot()
        run_main(["--present", str(run)])
        self.assertEqual(snapshot(), before)

    def test_neither_engine_reads_the_flag(self):
        for path in [SCRIPTS / "helius_forensics.py", SCRIPTS / "holder_analysis.py", *sorted((SCRIPTS / "ha").glob("*.py"))]:
            text = path.read_text(encoding="utf-8")
            for needle in ("exit_overhang", "EXIT OVERHANG", "overhang"):
                self.assertNotIn(needle, text, path.name)
        synth = next(e for e in json.loads((SCRIPTS.parent / "collectors.json").read_text())["entries"] if e["id"] == "synthesis")
        self.assertNotIn("exit_overhang", json.dumps(synth["input_flags"]) + synth["command"])
        self.assertIn("python3 -I skills/dlmm-scan/scripts/exit_overhang.py --present <RUN>", synth["present_commands"])


if __name__ == "__main__":
    unittest.main()
