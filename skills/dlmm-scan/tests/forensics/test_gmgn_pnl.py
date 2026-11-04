"""HS-PNL-T1: holder cost and PnL from the existing GMGN read (`gmgn_rows.py`), presentation only. Offline: fake transport,
dummy key, the real YMB GMGN answer of 2026-10-24 (fixtures/ymb_gmgn_top100_live_20261024.json: all 100 rows, trimmed to
the fields the collector reads; public data).

Covers the ticket's acceptance criteria: one request per collect and the status line unchanged (1); gmgn_top100.json
(apart from the addr_type line DS-GMGN-POOLS-T1 adds to each row, cut from the raw bytes) and gmgn_acquisition.json
byte-identical to master 3b3dce5 for the same mocked answer (2); the YMB replay reproducing the
expected numbers (3); pools (addr_type 2) out of every count and named in the coverage line (4); the cost-basis rule (5);
partial sellers on GMGN's own unrealized PnL (6); garbage values as null, never 0, never a crash (7); identity labels
inert, verdict words replaced, key echoes dropped (8); --present not read with the reason, exit 0 (9); assess unchanged
with the new file present, the file refused when passed to assess by mistake, and the engines never reading it (10); no
verdict words in any printed line (11)."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import math
import os
import re
import shutil
import statistics
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import gmgn_rows as gr  # noqa: E402
import helius_forensics as hf  # noqa: E402
import provider_words as pw  # noqa: E402
from test_assess import CAPE_LAUNCH, _map, _run, cape_holdings, run_assess  # noqa: E402
from test_gmgn_rows import DUMMY_KEY, NOW, Clock, FakeOpener, FakeResponse, body_of, fixture, http_error, synthetic_address  # noqa: E402
from test_solscanner_scan import CAPE  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
SKILL = Path(__file__).resolve().parents[2]
YMB = "2TKDNLwVTbhVVy7jCvSDz6ic4REAqQshZ9n9ZTxmpump"
YMB_TS = 1_792_803_758  # the fixture's fetched_at: 2026-10-24 01:02:38 UTC = 08:02:38 WIB
FRANK = "498g1rVnFcnjBjpfw1xyqA1WvgQXUU8RWuELjxkjAayQ"
PARTIAL_SELLER = "HUg1XNBfdJbFDLEaMBmc2VWf6SCrBkFe11E83ktXXz3f"  # sold 87%: GMGN's PnL -5.7%, average-cost PnL would be about -41%
POOLS = {"BcbQfEr3NKp8tJfbCmveqSS1o87npjfSbxuuLDSHwpsU", "GA7aoowCQ5oVycYXte61C3kdri7oZ56HuJwNUGkygx3",
         "C9hqyiLqqKHZnNaqnhGQLYQ9J9JDAszpsR8TpHEpqhpt", "5gnm34F1Sr26BWY1VZvCfjHZT28VqiCNWbU3YPdvgDt1"}
# Master 3b3dce5 (before HS-PNL-T1), same mocked answer, dummy key, clock frozen at the read time (sha256 of the files)
MASTER_SHA = {
    "ymb": {"gmgn_top100.json": "76e1192348cc1546f12e10d9d3a3a1c104e908a6fead6608f9a093b19a8c0f99",
            "gmgn_acquisition.json": "bb06b43ea2f762854f3c45b3ebaed0fb3b5b6caf84591bf0476a16bbcbc656fb"},
    "cape": {"gmgn_top100.json": "bb6e847bb30991c9b282d8505d12e6ecc636fd1ceaaef339145bb2c849df6d18",
             "gmgn_acquisition.json": "ca5d1edebdd470b935354a89da4acfc3e721db66b15a80449afebdaf7e987735"},
}
MASTER_STATUS = "ok (100 rows; 100 with a first-buy time; acquisition map: 100 wallets; 1 GMGN call, weight 5 each)\n"
SUMMARY_YMB = ("[for the executive summary] Holder PnL (GMGN top 100, presentation only): 93 of 96 in the red, 42.72% of supply; "
               "weighted average buy at $1.28M vs $549k now")
VERDICT_RE = re.compile(r"(?i)\b(?:clean|safe|safer|safest|low|legit|safu)\b|no[\s_-]*alarm|low[\s_-]*risk|nobody in the red")
PLACEHOLDER_RE = re.compile(r"\[provider word removed(?: x\d+)?\]")


def ymb_payload():
    return json.loads((FIX / "ymb_gmgn_top100_live_20261024.json").read_text(encoding="utf-8"))


def ymb_raw_rows():
    return ymb_payload()["data"]["list"]


def collect_main(out: Path, payload=None, *, answers=None, mint=YMB, now=YMB_TS, env=None):
    """gmgn_rows.main on a fake transport with a frozen clock. Returns (exit code, stdout, stderr, opener)."""
    opener = FakeOpener(*(answers if answers is not None else [FakeResponse(body_of(payload))]))
    o, e = io.StringIO(), io.StringIO()
    env = {"GMGN_API_KEY": DUMMY_KEY} if env is None else env
    base = {k: v for k, v in os.environ.items() if k not in ("GMGN_API_KEY", "HOLDER_FORENSICS_ENV")}
    with mock.patch.dict(os.environ, base | env, clear=True), mock.patch.object(gr, "default_opener", return_value=opener), \
         mock.patch.object(gr.time, "time", return_value=float(now)), mock.patch.object(gr.time, "sleep"), \
         contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        code = gr.main([mint, "--out", str(out)])
    return code, o.getvalue(), e.getvalue(), opener


def present_main(argv):
    o, e = io.StringIO(), io.StringIO()
    with mock.patch.object(gr, "default_opener", side_effect=AssertionError("--present must not open a connection")), \
         mock.patch.object(gr, "load_key", side_effect=AssertionError("--present must not read a key")), \
         mock.patch.object(gr, "find_env_file", side_effect=AssertionError("--present must not look for a .env")), \
         contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        code = gr.main(argv)
    return code, o.getvalue(), e.getvalue()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wallet(i, **fields):
    """A synthetic raw GMGN row (valid address, first-buy time) with PnL fields."""
    row = {"address": synthetic_address(i), "amount_percentage": 0.01, "addr_type": 0, "exchange": "", "start_holding_at": 1_791_968_647,
           "tags": [], "maker_token_tags": [], "balance": 10_000_000.0, "usd_value": 10_000.0, "avg_cost": 0.002, "unrealized_pnl": -0.5,
           "sell_amount_percentage": 0, "name": None, "twitter_username": None, "twitter_name": None}
    row.update(fields)
    return row


def run_synthetic(tmp: Path, rows, *, key=DUMMY_KEY):
    """Collect a synthetic payload into tmp (CAPE as the mint) and return (saved PnL file, printed block lines)."""
    code, _, err, _ = collect_main(tmp, {"data": {"list": rows}}, mint=CAPE, now=NOW, env={"GMGN_API_KEY": key})
    assert code == 0, err
    return json.loads((tmp / gr.PNL_FILE).read_text()), gr.present(tmp)


class OneResponseTests(unittest.TestCase):
    """Criteria 1 and 2: the same single request, the same status line, the same two files byte for byte (gmgn_top100.json
    apart from the addr_type line DS-GMGN-POOLS-T1 adds to each row)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_one_call_per_collect_and_the_status_line_unchanged(self):
        code, out, err, opener = collect_main(self.tmp, ymb_payload())
        self.assertEqual((code, out, err, len(opener.requests)), (0, MASTER_STATUS, "", 1))
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["gmgn_acquisition.json", "gmgn_holder_pnl.json", "gmgn_top100.json"])
        top, pnl = (json.loads((self.tmp / name).read_text()) for name in (gr.TOP100_FILE, gr.PNL_FILE))
        self.assertEqual(top["request"]["attempts"], 1)
        for field in ("mint", "status", "reason", "fetched_at"):
            self.assertEqual(pnl[field], top[field], field)
        self.assertEqual((pnl["status"], pnl["rows_read"], pnl["fetched_at"], pnl["presentation_only"]), ("ok", 100, "2026-10-24T01:02:38Z", True))
        self.assertEqual([r["address"] for r in pnl["rows"]], [r["address"] for r in top["list"]], "same wallets, same order")

    def test_top100_and_acquisition_are_byte_identical_to_master(self):
        for name, payload, mint, now in (("ymb", ymb_payload(), YMB, YMB_TS), ("cape", fixture("cape"), CAPE, NOW)):
            with self.subTest(name):
                out = self.tmp / name
                code, line, _, opener = collect_main(out, payload, mint=mint, now=now)
                self.assertEqual((code, line, len(opener.requests)), (0, MASTER_STATUS, 1))
                for file, digest in MASTER_SHA[name].items():
                    got = sha(out / file)
                    if file == gr.TOP100_FILE:  # DS-GMGN-POOLS-T1: only the one added raw line per row, addr_type, is cut
                        raw, removed = re.subn(rb'(?m)^   "addr_type": (?:0|1|2|null),\n', b"", (out / file).read_bytes())
                        self.assertEqual(removed, len(json.loads((out / file).read_text())["list"]), f"{name}: one addr_type line per row")
                        got = hashlib.sha256(raw).hexdigest()
                    self.assertEqual(got, digest, f"{name} {file} differs from master 3b3dce5")

    def test_the_raw_sink_changes_nothing_in_the_result(self):
        raw: list = []
        with_sink = gr.collect_gmgn_rows(YMB, DUMMY_KEY, opener=FakeOpener(FakeResponse(body_of(ymb_payload()))), now=Clock(YMB_TS).now,
                                         monotonic=lambda: 0.0, new_client_id=lambda: "11111111-2222-4333-8444-555555555555", raw_holders=raw)
        without = gr.collect_gmgn_rows(YMB, DUMMY_KEY, opener=FakeOpener(FakeResponse(body_of(ymb_payload()))), now=Clock(YMB_TS).now,
                                       monotonic=lambda: 0.0, new_client_id=lambda: "11111111-2222-4333-8444-555555555555")
        self.assertEqual(json.dumps(with_sink, indent=1), json.dumps(without, indent=1))
        self.assertEqual(raw, ymb_raw_rows(), "the sink holds the raw rows of that one answer")
        self.assertEqual(gr.holder_pnl(with_sink, raw, DUMMY_KEY)["rows_read"], 100)

    def test_a_retry_after_a_short_rate_limit_still_builds_from_the_one_answer_read(self):
        answers = [http_error(429, b'{"error":"RATE_LIMIT_EXCEEDED"}', {"X-RateLimit-Reset": str(YMB_TS + 2)}), FakeResponse(body_of(ymb_payload()))]
        code, line, _, opener = collect_main(self.tmp, answers=answers)
        self.assertEqual((code, len(opener.requests)), (0, 2), "the existing one-retry rule, unchanged")
        self.assertTrue(line.startswith("ok (100 rows;") and line.rstrip().endswith("2 GMGN calls, weight 5 each)"), line)
        self.assertEqual(json.loads((self.tmp / gr.PNL_FILE).read_text())["rows_read"], 100)

    def test_status_reason_and_time_mirror_gmgn_top100_when_not_ok(self):
        renamed = json.loads(json.dumps(fixture("cape")))
        for row in hf._unwrap(renamed):
            row["first_buy_at"] = row.pop("start_holding_at")
        cases = [("missing_key", [], {}), ("authentication_failed", [http_error(401)], None), ("invalid_json", [FakeResponse(b"<html>busy</html>")], None),
                 ("holder_list_empty", [FakeResponse(b'{"data":{"list":[]}}')], None), ("first_buy_field_missing", [FakeResponse(body_of(renamed))], None)]
        for reason, answers, env in cases:
            with self.subTest(reason), mock.patch.object(gr, "find_env_file", return_value=None):
                out = self.tmp / reason
                code, line, _, _ = collect_main(out, answers=answers, mint=CAPE, now=NOW, env=env)
                top, pnl = (json.loads((out / name).read_text()) for name in (gr.TOP100_FILE, gr.PNL_FILE))
                self.assertEqual(code, 0)
                self.assertEqual((pnl["status"], pnl["reason"], pnl["fetched_at"], pnl["rows"]), (top["status"], top["reason"], top["fetched_at"], []))
                self.assertEqual(pnl["reason"], reason)
                lines = gr.present(out)
                self.assertEqual(lines, [f"[for the executive summary] Holder PnL (GMGN top 100, presentation only): not read (GMGN {top['status']}: {reason})",
                                         f"Holder cost and PnL (GMGN top 100, presentation only): not read (GMGN {top['status']}: {reason})"])


class YmbReplayTests(unittest.TestCase):
    """Criterion 3 (and 4): the YMB answer of 2026-10-24 08:02 WIB prints the numbers in the ticket."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        code, _, err, _ = collect_main(cls.tmp, ymb_payload())
        assert code == 0, err
        code, cls.out, err = present_main(["--present", str(cls.tmp)])
        assert code == 0 and err == "", err
        cls.lines = cls.out.splitlines()
        cls.saved = json.loads((cls.tmp / gr.PNL_FILE).read_text())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def line(self, start):
        found = [ln for ln in self.lines if ln.startswith(start)]
        self.assertEqual(len(found), 1, start)
        return found[0]

    def test_the_summary_line_comes_first_and_is_marked(self):
        self.assertEqual(self.lines[0], SUMMARY_YMB)
        self.assertEqual(self.lines[1], "Holder cost and PnL (GMGN top 100, presentation only)")

    def test_counts_and_shares(self):
        self.assertEqual(self.line("  in the red:"), "  in the red: 93 wallets, 42.72% of supply | in the green (unrealized PnL 0% or more): 2 wallets, 0.68% of supply "
                                                     "| no cost basis: 1 wallet, 0.21% of supply")
        coverage = self.line("  coverage:")
        for needle in ("GMGN snapshot 2026-10-24 01:02 UTC = 2026-10-24 08:02 WIB", "100 rows read", "4 pools removed (addr_type 2: meteora_dlmm 3, pump_amm 1), 10.65% of supply",
                       "96 wallets left, 43.60% of supply", "top 100 = 54.26% of supply", "USD; GMGN's own numbers, not on-chain proof"):
            self.assertIn(needle, coverage)

    def test_pnl_market_caps_and_bands_match_the_ticket(self):
        pnl = self.line("  unrealized PnL")
        median, weighted = (float(x) for x in re.search(r"median ([+-][\d.]+)%, supply-weighted ([+-][\d.]+)%", pnl).groups())
        self.assertLessEqual(abs(median - -53.4), 0.1)
        self.assertLessEqual(abs(weighted - -49.6), 0.1)
        self.assertIn("over the 95 wallets with one", pnl)
        avg = self.line("  supply-weighted average buy")
        self.assertIn("market cap $1.28M vs $549k now", avg)
        self.assertIn("market cap now $549k = price $0.000551 (usd_value / balance) x supply 996,547,708 tokens (balance / share of supply)", self.out)
        self.assertIn("the rows agree within 1%", self.out)
        bands = self.line("  cost bands")
        expected = {"below the current price (under $549k)": (0, 0.0), "1-1.5x ($549k-$824k)": (8, 5.8), "1.5-3x ($824k-$1.65M)": (73, 30.2),
                    "3x or more ($1.65M and above)": (14, 7.4), "no average buy from GMGN": (1, 0.21)}
        for name, (wallets, share) in expected.items():
            got = re.search(re.escape(name) + r": (\d+) wallets?, ([\d.]+)%", bands)
            self.assertIsNotNone(got, name)
            self.assertEqual(int(got.group(1)), wallets, name)
            self.assertLessEqual(abs(float(got.group(2)) - share), 0.05, name)

    def test_an_independent_recomputation_agrees_within_the_ticket_tolerances(self):
        """Straight from the raw fixture, without the collector: mcaps within 1%, PnL within 0.1 point."""
        rows = [r for r in ymb_raw_rows() if r["addr_type"] != 2]
        price = statistics.median(r["usd_value"] / r["balance"] for r in rows)
        supply = statistics.median(r["balance"] / r["amount_percentage"] for r in rows)
        costed = [r for r in rows if (r["avg_cost"] or 0) > 0]
        avg_buy = sum(r["avg_cost"] * r["balance"] for r in costed) / sum(r["balance"] for r in costed)
        self.assertLessEqual(abs(price * supply / 549_000 - 1), 0.01)
        self.assertLessEqual(abs(avg_buy * supply / 1_280_000 - 1), 0.01)
        with_pnl = [r for r in rows if r["unrealized_pnl"] is not None]
        self.assertLessEqual(abs(statistics.median(r["unrealized_pnl"] for r in with_pnl) * 100 - -53.4), 0.1)
        weighted = sum(r["unrealized_pnl"] * r["amount_percentage"] for r in with_pnl) / sum(r["amount_percentage"] for r in with_pnl)
        self.assertLessEqual(abs(weighted * 100 - -49.6), 0.1)

    def test_the_20_largest_and_the_named_holders(self):
        head = self.line("  20 largest non-pool holders")
        self.assertTrue(head.endswith(": 0 in the green, 20 in the red, 0 without an unrealized PnL"), head)
        start = self.lines.index(head)
        top = self.lines[start + 1:start + 21]
        self.assertEqual([ln.split()[0] for ln in top], [f"#{i}" for i in range(1, 21)])
        self.assertTrue(top[0].startswith("    #1 DdM1tyCdoEyoxYYmGMjdf5rRPcpmj3UzZTpE7ScuTf7d: 1.59% of supply, unrealized PnL -60.8%, sold 33%, entry $1.36M"), top[0])
        self.assertIn("#11 4YxyRTLsK88uQ83bWoanu1x2FHo312b7JrcRqYPudD4p sol.engineer (@sol_engineer): 0.88% of supply, unrealized PnL -71.9%, sold 0%", self.out)
        self.assertIn("transfer_in (GMGN tag): the cost basis may not cover transferred tokens", top[1])
        frank = [ln for ln in self.lines if FRANK in ln]
        self.assertEqual(len(frank), 1)
        self.assertIn(f"#41 {FRANK} Frank (@frankdegods): 0.39% of supply, unrealized PnL -56.0%, sold 0%, entry $1.25M; GMGN tags: fomo, kol", frank[0])
        self.assertIn("  named holders outside the 20 largest (GMGN's name or X handle, its claim): 5", self.lines)

    def test_pools_are_out_of_every_count_and_named_in_the_coverage_line(self):
        for pool in POOLS:
            self.assertNotIn(pool, self.out)
        self.assertEqual(sorted(r["address"] for r in self.saved["rows"] if r["pool"]), sorted(POOLS))
        self.assertTrue(all(r["addr_type"] == 2 for r in self.saved["rows"] if r["pool"]))
        self.assertEqual({r["exchange"] for r in self.saved["rows"] if r["pool"]}, {"pump_amm", "meteora_dlmm"})

    def test_the_cannot_see_and_presentation_lines(self):
        cannot = self.line("  cannot see:")
        for needle in ("holders outside GMGN's top 100 (45.74% of supply)", "buys routed through apps without a cost record (1 wallet here without a cost basis)",
                       "11 wallets carry GMGN's transfer_in tag, 6.14% of supply", "whether GMGN's basis is average or FIFO"):
            self.assertIn(needle, cannot)
        self.assertEqual(self.lines[-1], "  presentation only: never an engine input, never passed to assess, never changes a FLAG, verdict or threshold")

    def test_the_saved_file_keeps_gmgns_numbers_names_and_tags(self):
        raw = {r["address"]: r for r in ymb_raw_rows()}
        for row in self.saved["rows"]:
            src = raw[row["address"]]
            for field in gr.PNL_NUMBER_FIELDS:
                value = src.get(field)
                self.assertEqual(row[field], None if value is None else float(value), (row["address"], field))
            self.assertEqual(row["transfer_in"], "transfer_in" in src["maker_token_tags"])
            self.assertEqual(row["app_tags"], sorted(set(src["tags"]) & set(gr.APP_TAGS)))
        frank = next(r for r in self.saved["rows"] if r["address"] == FRANK)
        self.assertEqual((frank["name"], frank["twitter_username"], frank["twitter_name"], frank["app_tags"]), ("Frank", "frankdegods", "Frank", ["fomo", "kol"]))
        self.assertEqual(self.saved["fields_missing"], [])
        self.assertEqual(sorted(gr.APP_TAGS), ["axiom", "bullx", "fomo", "gmgn", "kol", "padre", "photon", "trojan"])
        seen = {t for r in ymb_raw_rows() for t in r["tags"]}
        self.assertEqual(seen - set(gr.APP_TAGS), {"fresh_wallet", "wash_trader"}, "every app name GMGN used on YMB is on the allowlist")


class CostBasisTests(unittest.TestCase):
    """Criteria 5 and 6: GMGN's cost-basis rule, and its unrealized PnL used as given (never recomputed)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_the_cost_basis_rule(self):
        rows = [wallet(0, avg_cost=None, unrealized_pnl=-0.3),   # app-routed buy: no average buy, but a PnL -> has a cost basis, in the red
                wallet(1, avg_cost=0.002, unrealized_pnl=None),  # an average buy but no PnL -> cost basis, PnL not given
                wallet(2, avg_cost=None, unrealized_pnl=None),   # neither -> no cost basis
                wallet(3, avg_cost=0, unrealized_pnl=None),      # an average buy of 0 is no cost basis
                wallet(4, avg_cost=None, unrealized_pnl=0.1)]    # green
        _, lines = run_synthetic(self.tmp, rows)
        split = next(ln for ln in lines if ln.startswith("  in the red:"))
        self.assertEqual(split, "  in the red: 1 wallet, 1.00% of supply | in the green (unrealized PnL 0% or more): 1 wallet, 1.00% of supply "
                                "| no cost basis: 2 wallets, 2.00% of supply | cost basis but no unrealized PnL from GMGN: 1 wallet, 1.00% of supply")
        text = "\n".join(lines)
        self.assertIn(f"{synthetic_address(1)}: 1.00% of supply, unrealized PnL not given by GMGN", text)
        self.assertIn(f"{synthetic_address(2)}: 1.00% of supply, no cost basis", text)
        self.assertIn(f"{synthetic_address(0)}: 1.00% of supply, unrealized PnL -30.0%, sold 0%, entry n/a (no average buy)", text)
        self.assertIn("no average buy from GMGN: 4 wallets, 4.00%", text)

    def test_a_partial_seller_keeps_gmgns_unrealized_pnl(self):
        """GMGN's PnL for a partial seller is on the remaining position; recomputing it from the average buy would flip the
        sign here (average buy 0.001, price 0.0012: +20%), so the wallet stays in the red as GMGN says (-5%)."""
        rows = [wallet(0, avg_cost=0.001, balance=10_000_000.0, usd_value=12_000.0, sell_amount_percentage=0.8, unrealized_pnl=-0.05),
                wallet(1, avg_cost=0.002, balance=10_000_000.0, usd_value=12_000.0, unrealized_pnl=-0.4)]
        saved, lines = run_synthetic(self.tmp, rows)
        self.assertEqual(saved["rows"][0]["unrealized_pnl"], -0.05)
        self.assertIn("  in the red: 2 wallets, 2.00% of supply", "\n".join(lines))
        self.assertIn(f"{synthetic_address(0)}: 1.00% of supply, unrealized PnL -5.0%, sold 80%", "\n".join(lines))

    def test_the_real_partial_seller_of_ymb(self):
        raw = next(r for r in ymb_raw_rows() if r["address"] == PARTIAL_SELLER)
        row = gr.pnl_row(raw)
        price = raw["usd_value"] / raw["balance"]
        self.assertGreater(raw["sell_amount_percentage"], 0.8)
        self.assertLess(abs(row["unrealized_pnl"] - -0.0565), 0.001, "GMGN's remaining-position PnL, as given")
        self.assertLess(price / raw["avg_cost"] - 1, -0.40, "the average-cost PnL would read about -41%")
        self.assertAlmostEqual(row["unrealized_pnl"], raw["unrealized_profit"] / (raw["usd_value"] - raw["unrealized_profit"]), places=9)


class RepairR1Tests(unittest.TestCase):
    """Repair R1 (Verifier round 1): F1 the transfer_in mark comes from GMGN's transfer_in maker tag only (its
    history_transfer_in_amount carries dust sprays: about 0.22 tokens to 58 of 96 YMB wallets); F2 the price / supply
    disagreement line (more than 1%: the spread is stated and the median used) and the exactly-0% PnL boundary (in the
    green: "0% or more")."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_transfer_in_comes_from_the_maker_tag_only(self):
        rows = [wallet(0, history_transfer_in_amount=0.219),                                    # a dust spray, no tag: not marked
                wallet(1, history_transfer_in_amount=5_000_000.0),                              # a large amount, no tag: not marked (tag only)
                wallet(2, maker_token_tags=["transfer_in"]),                                    # the tag, no amount field: marked
                wallet(3, maker_token_tags=["bundler", "transfer_in"], history_transfer_in_amount=0)]  # the tag, amount 0: marked
        saved, lines = run_synthetic(self.tmp, rows)
        self.assertEqual([r["transfer_in"] for r in saved["rows"]], [False, False, True, True])
        self.assertNotIn("history_transfer_in_amount", saved["rows"][0], "the dust-polluted amount is never kept")
        for i, marked in ((0, False), (1, False), (2, True), (3, True)):
            line = next(ln for ln in lines if synthetic_address(i) in ln)
            self.assertEqual("transfer_in (GMGN tag)" in line, marked, line)
        self.assertIn("2 wallets carry GMGN's transfer_in tag, 2.00% of supply", "\n".join(lines))
        self.assertFalse(gr.pnl_row(wallet(4, history_transfer_in_amount=0.219))["transfer_in"])

    def market_cap_line(self, rows, name):
        _, lines = run_synthetic(self.tmp / name, rows)
        return next(ln for ln in lines if ln.startswith("  market cap now")), lines

    def test_rows_that_disagree_on_supply_state_the_spread_and_use_the_median(self):
        # price 0.001 on every row; supply 1.0e9, 1.1e9 and 1.0e9: a 10% spread, median 1.0e9 (the mean would be 1.033e9)
        cap, lines = self.market_cap_line([wallet(0), wallet(1, balance=11_000_000.0, usd_value=11_000.0), wallet(2)], "supply")
        self.assertEqual(cap, "  market cap now $1M = price $0.00100 (usd_value / balance) x supply 1,000,000,000 tokens (balance / share of supply); "
                              "medians over 3 wallets; the rows disagree on the supply by 10.0% (the median is used)")
        self.assertIn("market cap $2M vs $1M now", "\n".join(lines), "the average buy uses the median supply too")
        self.assertIn("1-1.5x ($1M-$1.5M)", "\n".join(lines))

    def test_rows_that_disagree_on_price_and_rows_within_1_percent(self):
        cap, _ = self.market_cap_line([wallet(0), wallet(1, usd_value=10_200.0), wallet(2)], "price")
        self.assertTrue(cap.endswith("; medians over 3 wallets; the rows disagree on the price by 2.0% (the median is used)"), cap)
        self.assertIn("price $0.00100", cap)
        cap, _ = self.market_cap_line([wallet(0), wallet(1, balance=10_050_000.0, usd_value=10_050.0), wallet(2)], "close")
        self.assertTrue(cap.endswith("; the rows agree within 1%"), cap)
        self.assertNotIn("disagree", cap)

    def test_exactly_zero_pnl_counts_as_in_the_green(self):
        rows = [wallet(0, unrealized_pnl=0), wallet(1, unrealized_pnl=-0.2), wallet(2, unrealized_pnl=0.0)]
        _, lines = run_synthetic(self.tmp, rows)
        text = "\n".join(lines)
        self.assertIn("  in the red: 1 wallet, 1.00% of supply | in the green (unrealized PnL 0% or more): 2 wallets, 2.00% of supply "
                      "| no cost basis: 0 wallets, 0.00% of supply", lines)
        self.assertIn("  unrealized PnL (GMGN's, over the 3 wallets with one): median +0.0%, supply-weighted -6.7%", lines)
        self.assertIn(": 2 in the green, 1 in the red, 0 without an unrealized PnL", text)
        self.assertIn(f"{synthetic_address(0)}: 1.00% of supply, unrealized PnL +0.0%", text)
        self.assertTrue(lines[0].endswith("Holder PnL (GMGN top 100, presentation only): 1 of 3 in the red, 1.00% of supply; weighted average buy at $2M vs $1M now"), lines[0])


class GarbageTests(unittest.TestCase):
    """Criterion 7: garbage is null, never 0, and never crashes --present; a renamed field reads not read."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_values_are_validated(self):
        garbage = ("0.5", "", "NaN", float("nan"), float("inf"), float("-inf"), True, False, None, [1], {"v": 1}, 10 ** 400)
        for field in gr.PNL_NUMBER_FIELDS:
            for value in garbage:
                with self.subTest(field=field, value=repr(value)[:20]):
                    self.assertIsNone(gr._pnl_number(value, field))
        for field, value in (("balance", -1), ("usd_value", -0.01), ("avg_cost", -2), ("sell_amount_percentage", 1.5), ("sell_amount_percentage", -0.1),
                             ("unrealized_pnl", -1.5), ("total_cost", -3)):
            self.assertIsNone(gr._pnl_number(value, field), (field, value))
        self.assertEqual([gr._pnl_number(v, "unrealized_pnl") for v in (-1, 0, 7.5)], [-1.0, 0.0, 7.5])
        self.assertEqual([gr._pnl_number(v, "profit") for v in (-22894.01, 0)], [-22894.01, 0.0])
        self.assertEqual([gr._addr_type(v) for v in (2, 0, "2", True, 2.0, -1, None)], [2, 0, None, None, None, None, None])

    def test_a_garbage_row_is_null_never_zero_and_the_block_prints(self):
        bad = wallet(0, balance="12", usd_value=True, avg_cost=float("nan"), unrealized_pnl="-0.5", sell_amount_percentage=float("inf"),
                     profit={"x": 1}, addr_type="2", amount_percentage=0.02)
        saved, lines = run_synthetic(self.tmp, [bad, wallet(1), wallet(2, unrealized_pnl=0.2)])
        row = saved["rows"][0]
        for field in ("balance", "usd_value", "avg_cost", "unrealized_pnl", "sell_amount_percentage", "profit"):
            self.assertIsNone(row[field], field)
        self.assertEqual((row["addr_type"], row["pool"]), (None, False))
        self.assertIn(f"{synthetic_address(0)}: 2.00% of supply, no cost basis, sold n/a, entry n/a (no average buy)", "\n".join(lines))

    def test_a_damaged_saved_file_never_crashes_present(self):
        _, _ = run_synthetic(self.tmp, [wallet(i, unrealized_pnl=-0.1 * (i + 1)) for i in range(5)])
        path = self.tmp / gr.PNL_FILE
        good = json.loads(path.read_text())
        damage = {
            "values": lambda d: [r.update(balance="x", usd_value=float("nan"), unrealized_pnl=float("inf"), avg_cost=-1, amount_percentage=7, name=5,
                                          app_tags="fomo", transfer_in="yes") for r in d["rows"][:3]],
            "rows not a list": lambda d: d.update(rows="many"),
            "bad addresses": lambda d: [r.update(address="0xdeadbeef") for r in d["rows"]],
            "duplicate rows": lambda d: d.update(rows=d["rows"] * 2),
            "fields_missing not a list": lambda d: d.update(fields_missing="unrealized_pnl"),
            "every value null": lambda d: [r.update({f: None for f in gr.PNL_NUMBER_FIELDS} | {"amount_percentage": None}) for r in d["rows"]],
            "schema": lambda d: d.update(schema="other/1"),
            "presentation flag": lambda d: d.update(presentation_only=False),
            "status": lambda d: d.update(status="maybe"),
        }
        for name, change in damage.items():
            with self.subTest(name):
                data = json.loads(json.dumps(good))
                change(data)
                path.write_text(json.dumps(data))
                code, out, err = present_main(["--present", str(self.tmp)])
                self.assertEqual((code, err), (0, ""))
                self.assertTrue(out.startswith("[for the executive summary] Holder PnL (GMGN top 100, presentation only): "), out)
                self.assertNotIn("Traceback", out)
                for line in out.splitlines():
                    self.assertIsNone(re.search(r"(?i)\bnan\b|\binf\b|infinity", line), line)
                second = out.splitlines()[1]
                if name in ("values", "duplicate rows", "every value null"):  # damaged values read as unknown; the block still prints
                    self.assertEqual(second, "Holder cost and PnL (GMGN top 100, presentation only)", name)
                elif name in ("rows not a list", "bad addresses"):
                    self.assertTrue(second.endswith("not read (no wallet rows after removing pools)"), second)
                else:
                    self.assertTrue(second.endswith("not read (gmgn_holder_pnl.json unreadable)"), second)
                if name == "values":
                    self.assertIn(f"{synthetic_address(0)}: share unknown, no cost basis, sold 0%, entry n/a (no average buy)", out)
                    self.assertIn("  in the red: 2 wallets, 2.00% of supply", out, "the two undamaged red wallets still count")
        for text in ("{not json", "", "[]", "null", '{"schema": "holder-scan-gmgn-holder-pnl/1"}'):
            with self.subTest(text=text):
                path.write_text(text)
                code, out, _ = present_main(["--present", str(self.tmp)])
                self.assertEqual(code, 0)
                self.assertIn("not read (gmgn_holder_pnl.json unreadable)", out)

    def test_a_renamed_pnl_field_reads_field_missing_never_zeros(self):
        for field, new in (("unrealized_pnl", "unrealised_pnl"), ("avg_cost", "average_cost"), ("addr_type", "address_type"), ("balance", "amount")):
            with self.subTest(field):
                payload = ymb_payload()
                for row in payload["data"]["list"]:
                    row[new] = row.pop(field)
                out = self.tmp / field
                code, line, _, _ = collect_main(out, payload)
                self.assertEqual((code, line), (0, MASTER_STATUS), "gmgn_top100.json reads none of the PnL fields: still ok")
                saved = json.loads((out / gr.PNL_FILE).read_text())
                self.assertEqual((saved["status"], saved["fields_missing"]), ("ok", [field]))
                lines = gr.present(out)
                self.assertEqual(lines[1], f"Holder cost and PnL (GMGN top 100, presentation only): not read (field missing: {field})")
                self.assertNotIn("in the red: 0", "\n".join(lines))

    def test_identity_fields_renamed_say_names_not_read(self):
        payload = ymb_payload()
        for row in payload["data"]["list"]:
            for field in gr.PNL_IDENTITY_FIELDS:
                row["x_" + field] = row.pop(field)
        collect_main(self.tmp, payload)
        lines = gr.present(self.tmp)
        self.assertIn("  named holders: not read (field missing: name, twitter_username, twitter_name)", lines)
        self.assertEqual(lines[0], SUMMARY_YMB, "the numbers are still read")

    def test_only_pools_left(self):
        _, lines = run_synthetic(self.tmp, [wallet(0, addr_type=2, exchange="pump_amm"), wallet(1, addr_type=2, exchange="meteora_dlmm")])
        self.assertEqual(lines[1], "Holder cost and PnL (GMGN top 100, presentation only): not read (no wallet rows after removing pools)")


class IdentityAndWordingTests(unittest.TestCase):
    """Criteria 8 and 11: identity labels are inert (verdict words replaced, key echoes dropped, handles as plain text) and
    no printed line carries a verdict word."""

    KEY = "gmgnK3y-7f3a9c41e2b8d6aa01b2c3d4e5f6a7b8"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def adversarial(self):
        key = self.KEY
        return [
            wallet(0, name="Safe Trader", twitter_username="LowRisk", twitter_name="CLEAN"),
            wallet(1, name="Binance " + key, twitter_username=key[:12], twitter_name="pre " + key[5:20] + " post"),
            wallet(2, name="<b>s<x></x>afe</b>", twitter_username="[click](https://evil.example)", twitter_name="Evil\n# heading | table"),
            wallet(3, name="5AF3 l0w", twitter_username="no_alarm", twitter_name="‮efas", exchange="safe dex", unrealized_pnl=0.3),
            wallet(4, name="SafePal", twitter_username="Lowell", twitter_name="Cleanup", tags=["fomo", "SAFE", "kol", 5, {"a": 1}],
                   maker_token_tags=["transfer_in", "sniper"]),
            wallet(5, addr_type=2, exchange="rug free pool"),
        ]

    def test_labels_are_inert_and_key_echoes_dropped(self):
        saved, lines = run_synthetic(self.tmp, self.adversarial(), key=self.KEY)
        rows = {r["address"]: r for r in saved["rows"]}
        first, echo, markup, signs, real = (rows[synthetic_address(i)] for i in range(5))
        self.assertEqual((first["name"], first["twitter_username"], first["twitter_name"]), ("[provider word removed] Trader", "[provider word removed]", "[provider word removed]"))
        self.assertEqual((echo["name"], echo["twitter_username"], echo["twitter_name"]), (None, None, None), "a label echoing the key is dropped")
        self.assertEqual((signs["name"], signs["twitter_username"]), ("[provider word removed x2]", "[provider word removed]"))
        self.assertEqual((real["name"], real["twitter_username"], real["twitter_name"]), ("SafePal", "Lowell", "Cleanup"), "words inside longer words are kept")
        self.assertEqual((real["app_tags"], real["transfer_in"]), (["fomo", "kol"], True))
        for value in (markup["name"], markup["twitter_username"], markup["twitter_name"]):
            if value is not None:
                self.assertRegex(value, r"^[\w .\-\[\]]{1,80}$")
        self.assertEqual(rows[synthetic_address(5)]["exchange"], "[provider word removed] pool")
        text = "\n".join(lines) + json.dumps(saved)
        for i in range(len(self.KEY) - gr.KEY_PIECE + 1):
            self.assertNotIn(self.KEY[i:i + gr.KEY_PIECE], text)
        for line in lines:
            self.assertNotIn("‮", line)
            self.assertNotIn("](", line)
            self.assertNotIn("<", line)
        self.assertEqual(lines[-1], "  " + pw.removed_line(pw.count(lines[:-1])))
        self.assertGreater(pw.count(lines[:-1]), 0)

    def test_no_verdict_word_in_any_printed_line(self):
        _, adversarial = run_synthetic(self.tmp / "adv", self.adversarial(), key=self.KEY)
        collect_main(self.tmp / "ymb", ymb_payload())
        for name, lines in (("ymb", gr.present(self.tmp / "ymb")), ("adversarial", adversarial), ("missing", gr.present(self.tmp / "nothing-here"))):
            with self.subTest(name):
                self.assertTrue(lines)
                for line in lines:
                    self.assertEqual(gr.neutralize(line)[1], 0, line)
                    self.assertIsNone(VERDICT_RE.search(PLACEHOLDER_RE.sub(" ", line.replace(pw.removed_line(pw.count(lines)), ""))), line)

    def test_the_counted_line_matches_provider_words(self):
        for n in (1, 2, 7):
            self.assertEqual(gr.removed_line(n), pw.removed_line(n))
        texts = ["a [provider word removed] b", "[provider word removed x3]", None, "plain"]
        self.assertEqual(gr.count_removed(texts), pw.count(texts))


class PresentCliTests(unittest.TestCase):
    """Criterion 9: --present is offline, reads only the saved file and says not read with the reason, exit 0."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_without_the_file(self):
        code, out, err = present_main(["--present", str(self.tmp)])
        self.assertEqual((code, err), (0, ""))
        # HS-CASCADE-T1: the same command prints the copy-trade cascade section right after the block (not read here too)
        self.assertEqual(out.splitlines(), ["[for the executive summary] Holder PnL (GMGN top 100, presentation only): not read (gmgn_holder_pnl.json missing)",
                                            "Holder cost and PnL (GMGN top 100, presentation only): not read (gmgn_holder_pnl.json missing)",
                                            "[for the executive summary] Copy-trade cascade risk (presentation only): not read (gmgn_holder_pnl.json missing)",
                                            "Copy-trade cascade (presentation only): not read (gmgn_holder_pnl.json missing)"])

    def test_with_status_not_ok(self):
        with mock.patch.object(gr, "find_env_file", return_value=None):
            collect_main(self.tmp, answers=[], mint=CAPE, now=NOW, env={})
        code, out, _ = present_main(["--present", str(self.tmp)])
        self.assertEqual(code, 0)
        self.assertIn("not read (GMGN unavailable: missing_key)", out.splitlines()[1])
        self.assertNotIn("in the red", out)

    def test_bad_command_lines_exit_2(self):
        for argv, message in (([CAPE, "--present", str(self.tmp)], "error: --present takes only the run folder"),
                              (["--present", str(self.tmp / "missing")], "error: --present is not a run folder"),
                              (["--present", str(self.tmp), "--out", str(self.tmp)], "error: --present takes only the run folder"),
                              ([CAPE], "error: --out is required")):
            with self.subTest(argv=argv[:2]):
                code, out, err = present_main(argv)
                self.assertEqual((code, out, err.strip()), (2, "", message))

    def test_python_minus_i_runs_present_offline(self):
        """The registered form: the script run on its own with -I (no skill folder on sys.path, no network)."""
        import subprocess  # noqa: PLC0415 - a test-only child process; no network: the folder holds only the saved file

        collect_main(self.tmp, ymb_payload())
        done = subprocess.run([sys.executable, "-I", str(SCRIPTS / "gmgn_rows.py"), "--present", str(self.tmp)], capture_output=True, text=True, timeout=60,
                              env={"PATH": os.environ.get("PATH", "")})
        self.assertEqual((done.returncode, done.stderr), (0, ""))
        self.assertEqual(done.stdout.splitlines()[0], SUMMARY_YMB)


class AssessIsolationTests(unittest.TestCase):
    """Criterion 10: assess gives the same bytes with the new file in the run folder, refuses it when passed by mistake,
    and neither engine mentions it."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        pool, accounts, funded = cape_holdings()
        from test_parallel_rows import ParallelFake

        cls.run_dir = cls.tmp / "cape-run"
        code, _, _ = _run(["funders", CAPE, "--top", "100", "--workers", "6", "--out", str(cls.run_dir)], fake=ParallelFake(accounts, funded),
                          pairs=[{"pairAddress": pool, "pairCreatedAt": CAPE_LAUNCH * 1000}])
        assert code == 0
        cls.map_file = cls.tmp / "map.json"
        cls.map_file.write_text(json.dumps(_map(CAPE, [(115, 25.45), (50, 17.44)])))
        code, _, err, _ = collect_main(cls.run_dir, fixture("cape"), mint=CAPE, now=NOW)
        assert code == 0, err
        assert (cls.run_dir / gr.PNL_FILE).is_file()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def assess(self, extra, name):
        out = self.tmp / name
        code, _, err = run_assess(CAPE, self.run_dir, extra, out=out)
        return code, err, ((out / "assessment.json").read_bytes() if code == 0 else None), ((out / "report.md").read_bytes() if code == 0 else None)

    def test_assess_is_byte_identical_with_and_without_the_new_file(self):
        gmgn = ["--gmgn-holders-json", str(self.run_dir / gr.TOP100_FILE), "--acquisition-json", str(self.run_dir / gr.ACQUISITION_FILE)]
        saved = (self.run_dir / gr.PNL_FILE).read_bytes()
        for extra, tag in ((["--bubblemaps-json", str(self.map_file), *gmgn], "map-gmgn"), (gmgn, "gmgn"), ([], "none")):
            with self.subTest(tag):
                code, err, with_file, md_with = self.assess(extra, f"{tag}-with")
                self.assertEqual(code, 0, err)
                (self.run_dir / gr.PNL_FILE).unlink()
                try:
                    code, err, without, md_without = self.assess(extra, f"{tag}-without")
                finally:
                    (self.run_dir / gr.PNL_FILE).write_bytes(saved)
                self.assertEqual(code, 0, err)
                self.assertEqual((with_file, md_with), (without, md_without), "byte-identical assessment.json and report.md")
                a = json.loads(with_file)
                self.assertEqual((a["flag"], a["verdict"]), (json.loads(without)["flag"], json.loads(without)["verdict"]))
        a = json.loads(self.assess(["--bubblemaps-json", str(self.map_file), *gmgn], "flag-check")[2])
        self.assertEqual((a["verdict"]["level"], a["flag"]["label"]), (hf.VERDICT_HIGH, hf.FLAG_DANGER), "the CAPE alarm stands")

    def test_passed_to_assess_by_mistake_it_is_refused(self):
        # Holder rows sit under "rows", a key the engine's unwrapper does not read: as a GMGN or Jupiter rows file it is
        # refused (exit 2). (The engine takes any JSON object as an --acquisition-json map; that is its existing rule,
        # unchanged here; SKILL.md names gmgn_acquisition.json as the only GMGN file for that flag.)
        for flag in ("--gmgn-holders-json", "--jupiter-holders-json"):
            with self.subTest(flag):
                code, err, _, _ = self.assess([flag, str(self.run_dir / gr.PNL_FILE)], f"refused{flag}")
                self.assertEqual(code, 2, err)
        with self.assertRaises(hf.ConfigError):
            hf.gmgn_cohort_rows(json.loads((self.run_dir / gr.PNL_FILE).read_text()))

    def test_neither_engine_reads_the_new_file(self):
        for path in [SCRIPTS / "helius_forensics.py", SCRIPTS / "holder_analysis.py", *sorted((SCRIPTS / "ha").glob("*.py"))]:
            text = path.read_text(encoding="utf-8")
            for needle in ("gmgn_holder_pnl", "holder_pnl"):
                self.assertNotIn(needle, text, path.name)
        synth = next(e for e in json.loads((SKILL / "collectors.json").read_text())["entries"] if e["id"] == "synthesis")
        self.assertNotIn("gmgn_holder_pnl", json.dumps(synth["input_flags"]))


class SkillAndRegistryTests(unittest.TestCase):
    """SKILL.md and collectors.json name the new file and the offline block, presentation only."""

    @classmethod
    def setUpClass(cls):
        cls.text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        cls.reg = json.loads((SKILL / "collectors.json").read_text(encoding="utf-8"))

    def test_the_registry_lists_the_new_output_file(self):
        entry = next(e for e in self.reg["entries"] if e["id"] == "gmgn_rows")
        self.assertEqual(entry["output"], ["gmgn_top100.json", "gmgn_acquisition.json", "gmgn_holder_pnl.json", "gmgn_rows.err"])
        self.assertEqual(entry["command"], "python3 -I skills/dlmm-scan/scripts/gmgn_rows.py <MINT> --out <RUN> 2> <RUN>/gmgn_rows.err", "the collector command is unchanged")

    def test_the_gmgn_section_names_the_file_and_the_present_command(self):
        body = self.text.split("## Collector `gmgn_rows`", 1)[1].split("\n## ", 1)[0]
        for needle in ("`<RUN>/gmgn_holder_pnl.json`", "python3 -I skills/dlmm-scan/scripts/gmgn_rows.py --present <RUN>", "same single response",
                       "byte-identical", "never an engine input", "never passed to `assess`", "never counted toward NO_ALARM", "`addr_type` 2",
                       "not read (field missing", "`transfer_in`", "tests/forensics/test_gmgn_pnl.py"):
            self.assertIn(needle, body, needle)

    def test_the_synthesis_copies_the_block_and_the_summary_line(self):
        synth = self.text.split("## Synthesis (top tier): `SUMMARY.md`", 1)[1].split("\n## ", 1)[0]
        for needle in ("gmgn_rows.py --present <RUN>", "Holder PnL (GMGN top 100, presentation only)", "after the FLAG lines", "[for the executive summary]",
                       "copy", "never passed to `assess`", "never counted toward NO_ALARM"):
            self.assertIn(needle, synth, needle)


class NoUsablePnlSummaryTests(unittest.TestCase):
    """HS-CASCADE-T1 amendment A1: with the unrealized_pnl field present but no usable value on any non-pool wallet row, the
    marked summary line reads not read, never "0 of N in the red"; the block body still prints and explains it. YMB, which has
    PnL values, is unchanged (YmbReplayTests)."""

    NOT_READ = "[for the executive summary] Holder PnL (GMGN top 100, presentation only): not read (GMGN gave no usable unrealized PnL)"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def check(self, rows, name):
        saved, lines = run_synthetic(self.tmp / name, rows)
        self.assertNotIn("unrealized_pnl", saved["fields_missing"], "the field is present: this is not the renamed-field case")
        self.assertEqual(lines[0], self.NOT_READ)
        self.assertEqual(lines[1], "Holder cost and PnL (GMGN top 100, presentation only)", "the block body still prints")
        self.assertIn("  unrealized PnL: not read (no wallet row carries one)", lines)
        self.assertIsNone(re.search(r"\b0 of \d+ in the red", "\n".join(lines)))
        return lines

    def test_every_wallet_value_null_or_unusable(self):
        lines = self.check([wallet(0, unrealized_pnl=None), wallet(1, unrealized_pnl="-0.5"), wallet(2, unrealized_pnl=float("nan"))], "null")
        self.assertIn("  in the red: 0 wallets, 0.00% of supply | in the green (unrealized PnL 0% or more): 0 wallets, 0.00% of supply "
                      "| no cost basis: 0 wallets, 0.00% of supply | cost basis but no unrealized PnL from GMGN: 3 wallets, 3.00% of supply", lines)

    def test_only_a_pool_has_a_value(self):
        self.check([wallet(0, unrealized_pnl=None), wallet(1, addr_type=2, exchange="pump_amm", unrealized_pnl=-0.4)], "pool")

    def test_one_usable_value_keeps_the_count(self):
        _, lines = run_synthetic(self.tmp, [wallet(0, unrealized_pnl=None), wallet(1, unrealized_pnl=-0.2)])
        self.assertTrue(lines[0].startswith("[for the executive summary] Holder PnL (GMGN top 100, presentation only): 1 of 2 in the red, 1.00% of supply; "), lines[0])

    def test_usable_values_all_0_percent_or_more_give_0_in_the_red(self):
        """Repair R2 (R2-1): A1 keys on usable values, not on red ones: with every usable PnL at 0% or more (exactly 0% included)
        the summary is a real count, "0 of N in the red", never not read."""
        for name, rows in (("green", [wallet(0, unrealized_pnl=0.2)]), ("zero", [wallet(0, unrealized_pnl=0.0), wallet(1, unrealized_pnl=None)]),
                           ("zero and green", [wallet(0, unrealized_pnl=0), wallet(1, unrealized_pnl=0.5)])):
            with self.subTest(name):
                _, lines = run_synthetic(self.tmp / name.replace(" ", "-"), rows)
                head = f"[for the executive summary] Holder PnL (GMGN top 100, presentation only): 0 of {len(rows)} in the red, 0.00% of supply; "
                self.assertTrue(lines[0].startswith(head), lines[0])
                self.assertNotIn("not read", lines[0])


if __name__ == "__main__":
    unittest.main()
