"""HS-COHORT-POOLS-T1: pools, bonding curves and other infrastructure never count as cohort wallets (pure, offline).

The GMGN and Jupiter funding-time cohort passes drop this run's infrastructure rows first: holders.json `pool_addresses`
(the Dexscreener pairs plus every --exclude address), `top_holders` rows marked infrastructure, and GMGN rows with
addr_type 2. The coverage records what was removed and the Sources-read block says it in plain words. The fixture is the
$BILLIONS run of 2026-10-25, where four pool rows made a 5-"wallet" Jupiter cohort of 9.34% of supply (the wallet held
0.27%) and the only forensics warning was that false CAUTION.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
from test_holder_forensics import MINT, FakeHelius, addr  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "billions_cohort_pools_live_20261025.json"
T0 = 1_760_000_000
VERDICT_WORDS = re.compile(r"\b(clean|safe|low)\b", re.IGNORECASE)


def billions():
    """holders (as provider_cohort_sources reads them) and the Jupiter rows of the $BILLIONS cohort. Balances are the
    saved shares (percent) plus one filler owner, so every share is exactly the saved one."""
    fx = json.loads(FIX.read_text())
    balances = {r["wallet"]: r["share_pct"] for r in fx["top_holders"]}
    balances["REST" + "K" * 40] = 100.0 - sum(balances.values())
    holders = {"mint": fx["mint"], "token_accounts": 3637, "truncated": False, "earliest_pair_created_at": fx["earliest_pair_created_at"],
               "pool_addresses": fx["pool_addresses"], "distribution": {}, "warnings": [], "top_holders": fx["top_holders"], "_balances": balances}
    return holders, fx["jupiter_rows"]


def jrow(address, t, funder="F0", amount=1000.0):
    return {"address": address, "amount": amount, "addressInfo": {"fundingAddress": funder.ljust(44, "F"), "fundingAmount": 1.0, "fundingBlockTime": t}}


def grow(address, t, frac, funder="F0", addr_type=0):
    return {"address": address, "amount_percentage": frac, "addr_type": addr_type, "start_holding_at": t + 86400,
            "native_transfer": {"from_address": funder.ljust(44, "F"), "timestamp": t, "amount": 1.0, "name": None}}


def holders_with(balances, pools=(), top=()):
    return {"_balances": dict(balances), "earliest_pair_created_at": T0, "pool_addresses": list(pools), "top_holders": list(top)}


class BillionsFixtureTests(unittest.TestCase):
    """Acceptance 1: the $BILLIONS Jupiter cohort was made of four pool rows plus one wallet."""

    POOLS = ("3daykMmm", "12EfRFF3", "AFq3nk3s", "B6iHwi5e")

    def test_without_the_fix_the_rows_form_the_5_wallet_9_34_pct_cohort(self):
        holders, rows = billions()
        share = {w: b for w, b in holders["_balances"].items()}
        old = hf.run_cohort_source(hf.jupiter_cohort_rows(rows, share), launch_ts=holders["earliest_pair_created_at"])
        self.assertEqual([(c["wallets"], c["share_pct"]) for c in old["cohorts"]], [(5, 9.34)])
        self.assertEqual(sorted(w[:8] for w in old["cohorts"][0]["members"] if w in holders["pool_addresses"]), sorted(self.POOLS))

    def test_the_jupiter_pass_drops_the_pools_and_forms_no_cohort(self):
        holders, rows = billions()
        res = hf.provider_cohort_sources(holders, jupiter_payload=rows)["jupiter"]
        self.assertEqual(res["cohorts"], [])
        self.assertEqual(res["coverage"]["infrastructure_removed"], {"rows": 4, "supply_pct": 9.07, "share_unknown_rows": 0})
        self.assertEqual((res["coverage"]["rows"], res["coverage"]["with_funding_time"]), (1, 1))  # the one wallet is still read
        self.assertAlmostEqual(res["coverage"]["supply_pct"], 0.27, places=2)

    def test_the_flag_reason_is_gone_and_the_sources_line_names_the_removal(self):
        holders, rows = billions()
        share = {w: b for w, b in holders["_balances"].items()}
        before = {"jupiter": hf.run_cohort_source(hf.jupiter_cohort_rows(rows, share), launch_ts=holders["earliest_pair_created_at"])}
        a_before = hf.assess(hf._public(holders), None, provider_cohorts=before)
        self.assertEqual(a_before["flag"]["label"], hf.FLAG_CAUTION)
        self.assertTrue(any(r.startswith("funding-time cohort (jupiter): 5 wallets, 9.34% of supply") for r in a_before["flag"]["why"]))
        after = hf.provider_cohort_sources(holders, jupiter_payload=rows)
        a = hf.assess(hf._public(holders), None, provider_cohorts=after)
        self.assertNotEqual(a["flag"]["label"], hf.FLAG_CAUTION)
        self.assertFalse(any("funding-time cohort (jupiter)" in r for r in a["verdict"]["reasons"] + a["flag"]["why"]))
        lines = next(s for s in a["sources"] if s["key"] == "jupiter")["lines"]
        self.assertIn("pools and bonding curves removed: 4 rows, 9.07% of supply", lines)
        self.assertEqual(lines.index("pools and bonding curves removed: 4 rows, 9.07% of supply"), 1)  # right after the rows line
        md = hf.markdown_report(holders["mint"], hf._public(holders), None, 0, a, after)
        self.assertIn("  - pools and bonding curves removed: 4 rows, 9.07% of supply", md)
        self.assertEqual(a["cohort_sources"]["jupiter"]["coverage"]["infrastructure_removed"]["rows"], 4)  # assessment.json keeps the record


class InfrastructureSourcesTests(unittest.TestCase):
    """Acceptance 2-4: every kind of infrastructure row leaves; real wallets stay."""

    def test_gmgn_addr_type_2_row_is_dropped_even_when_not_in_holders_json(self):
        wallets = [grow(addr(i), T0 + i * 60, 0.005) for i in range(5)]  # 5 wallets, 2.5% together: no cohort alone
        pool = grow(addr(99), T0 + 30, 0.07, addr_type=hf.GMGN_POOL_ADDR_TYPE)  # 7%: with it, 6 rows and 9.5% would flag
        holders = holders_with({})  # nothing in pool_addresses or top_holders
        self.assertEqual(len(hf.run_cohort_source(hf.gmgn_cohort_rows([*wallets, pool]), launch_ts=T0)["cohorts"]), 1)  # the old pass
        res = hf.provider_cohort_sources(holders, gmgn_payload={"code": 0, "data": {"list": [*wallets, pool]}})["gmgn"]
        self.assertEqual(res["cohorts"], [])
        self.assertEqual(res["coverage"]["infrastructure_removed"], {"rows": 1, "supply_pct": 7.0, "share_unknown_rows": 0})
        self.assertEqual(res["coverage"]["rows"], 5)

    def test_saved_gmgn_rows_without_addr_type_drop_pool_addresses_and_infrastructure_rows(self):
        """Repair R1 (Verifier C1): the gmgn_rows collector's gmgn_top100.json keeps no addr_type, so in the normal pipeline
        the GMGN pass relies on holders.json alone: a row whose address is in pool_addresses, or is a top_holders row
        marked infrastructure, must leave before the cohort pass."""
        pool = addr(98)
        balances = {addr(i): 0.5 for i in range(5)} | {pool: 7.0, "REST": 90.5}  # 5 wallets, 2.5% together: no cohort alone
        rows = [grow(addr(i), T0 + i * 60, 0.005) for i in range(5)] + [grow(pool, T0 + 30, 0.07)]
        payload = {"status": "ok", "list": [{k: v for k, v in r.items() if k != "addr_type"} | {"tags": [], "maker_token_tags": []} for r in rows]}
        self.assertFalse(any("addr_type" in r for r in payload["list"]))
        old = hf.run_cohort_source(hf.gmgn_cohort_rows(payload, balances), launch_ts=T0)  # the pass without the fix
        self.assertEqual([(c["wallets"], c["share_pct"], pool in c["members"]) for c in old["cohorts"]], [(6, 9.5, True)])
        for kind, holders in (("pool_addresses", holders_with(balances, pools=[pool])),
                              ("top_holders infrastructure", holders_with(balances, top=[{"rank": 1, "wallet": pool, "share_pct": 7.0, "infrastructure": True}]))):
            with self.subTest(kind):
                out = hf.provider_cohort_sources(holders, gmgn_payload=payload)
                res = out["gmgn"]
                self.assertEqual(res["cohorts"], [])
                self.assertEqual(res["coverage"]["infrastructure_removed"], {"rows": 1, "supply_pct": 7.0, "share_unknown_rows": 0})
                self.assertEqual(res["coverage"]["rows"], 5)
                a = hf.assess(holders | {"distribution": {}, "warnings": []}, None, provider_cohorts=out)
                self.assertFalse(any("funding-time cohort (gmgn)" in r for r in a["verdict"]["reasons"]))
                self.assertIn("pools and bonding curves removed: 1 row, 7.0% of supply", next(s for s in a["sources"] if s["key"] == "gmgn")["lines"])

    def test_addr_type_other_than_the_int_2_is_not_a_pool(self):
        rows = [grow(addr(i), T0 + i * 60, 0.01) for i in range(5)]
        for value in (1, "2", True, 2.0, None):
            rows[0]["addr_type"] = value
            res = hf.provider_cohort_sources(holders_with({}), gmgn_payload=rows)["gmgn"]
            self.assertEqual(res["coverage"]["infrastructure_removed"]["rows"], 0, value)

    def test_pool_address_not_in_top_holders_is_dropped(self):
        pool = addr(77)
        balances = {addr(i): 0.5 for i in range(5)} | {pool: 8.0, "REST": 89.5}  # 5 wallets, 2.5% together: no cohort alone
        rows = [jrow(addr(i), T0 + i * 60) for i in range(5)] + [jrow(pool, T0 + 10)]
        holders = holders_with(balances, pools=[pool], top=[{"rank": 2, "wallet": addr(0), "share_pct": 0.5, "infrastructure": False}])
        self.assertEqual(len(hf.run_cohort_source(hf.jupiter_cohort_rows(rows, balances), launch_ts=T0)["cohorts"]), 1)  # 10.5% with the pool: the old pass flags it
        res = hf.provider_cohort_sources(holders, jupiter_payload=rows)["jupiter"]
        self.assertEqual(res["cohorts"], [])
        self.assertEqual(res["coverage"]["infrastructure_removed"], {"rows": 1, "supply_pct": 8.0, "share_unknown_rows": 0})

    def test_top_holders_infrastructure_row_is_dropped_even_without_pool_addresses(self):
        pool = addr(78)
        balances = {addr(i): 0.5 for i in range(5)} | {pool: 8.0, "REST": 89.5}
        rows = [jrow(addr(i), T0 + i * 60) for i in range(5)] + [jrow(pool, T0 + 10)]
        holders = holders_with(balances, top=[{"rank": 1, "wallet": pool, "share_pct": 8.0, "infrastructure": True}])
        res = hf.provider_cohort_sources(holders, jupiter_payload=rows)["jupiter"]
        self.assertEqual((res["cohorts"], res["coverage"]["infrastructure_removed"]["rows"]), ([], 1))

    def test_exclude_address_is_dropped(self):
        locker = addr(500)
        accounts = [{"owner": addr(i), "amount": 5} for i in range(5)] + [{"owner": locker, "amount": 80}, {"owner": addr(900), "amount": 895}]  # 2.5% + 8% of 1000
        with mock.patch.object(hf, "dexscreener_pairs", return_value=([], True)):
            holders = hf.run_holders(FakeHelius(accounts=accounts), MINT, extra_exclude={locker})
        self.assertIn(locker, holders["pool_addresses"])  # --exclude reaches pool_addresses (run_holders)
        rows = [jrow(addr(i), T0 + i * 60) for i in range(5)] + [jrow(locker, T0 + 10)]
        res = hf.provider_cohort_sources(holders, jupiter_payload=rows)["jupiter"]
        self.assertEqual(res["cohorts"], [])
        self.assertEqual(res["coverage"]["infrastructure_removed"], {"rows": 1, "supply_pct": 8.0, "share_unknown_rows": 0})

    def test_wallet_sharing_a_funder_with_a_pool_still_counts(self):
        pool = addr(88)
        n = hf.COHORT_MIN_WALLETS
        balances = {addr(i): 0.1 for i in range(n)} | {pool: 9.0, "REST": 100.0 - 9.0 - 0.1 * n}
        rows = [jrow(addr(i), T0 + i * 60, funder="SHARED" if i < 3 else f"F{i % 4}") for i in range(n)] + [jrow(pool, T0 + 5, funder="SHARED")]
        res = hf.provider_cohort_sources(holders_with(balances, pools=[pool]), jupiter_payload=rows)["jupiter"]
        self.assertEqual(len(res["cohorts"]), 1)
        c = res["cohorts"][0]
        self.assertEqual(c["wallets"], n)
        self.assertNotIn(pool, c["members"])
        self.assertTrue({addr(0), addr(1), addr(2)} <= set(c["members"]))  # the wallets fed by the pool's funder stay
        shared = next(m for m in c["funder_mix"] if m["funder"] == "SHARED".ljust(44, "F"))
        self.assertEqual(shared["wallets"], 3)
        self.assertEqual(res["coverage"]["infrastructure_removed"]["rows"], 1)

    def test_helius_cohort_pass_already_skips_pools(self):
        pool = addr(66)
        accounts = [{"owner": addr(i), "amount": 10} for i in range(5)] + [{"owner": pool, "amount": 500}]
        funded = {w: {"funder": "F".ljust(44, "F"), "timestamp": T0 + 60, "amount": 1.0} for w in [addr(i) for i in range(5)] + [pool]}
        fake = FakeHelius(accounts=accounts, funded=funded)
        with mock.patch.object(hf, "dexscreener_pairs", return_value=([{"pairAddress": pool}], True)):
            holders = hf.run_holders(fake, MINT)
        funders = hf.run_funders(fake, holders, top=10)
        self.assertNotIn(pool, fake.calls)
        self.assertTrue(all(pool not in c["members"] for c in funders["cohorts"]["cohorts"]))


class RemovedLineTests(unittest.TestCase):
    """Goal 2 and acceptance 6: plain words, no verdict word, an unknown share is never 0."""

    def test_line_wording(self):
        self.assertEqual(hf.removed_infrastructure_text({"rows": 4, "supply_pct": 9.07, "share_unknown_rows": 0}), "pools and bonding curves removed: 4 rows, 9.07% of supply")
        self.assertEqual(hf.removed_infrastructure_text({"rows": 1, "supply_pct": 7.21, "share_unknown_rows": 0}), "pools and bonding curves removed: 1 row, 7.21% of supply")
        self.assertEqual(hf.removed_infrastructure_text({"rows": 0, "supply_pct": 0.0, "share_unknown_rows": 0}), "pools removed: none in these rows")

    def test_unknown_share_is_never_printed_as_zero(self):
        self.assertEqual(hf.removed_infrastructure_text({"rows": 2, "supply_pct": 0.0, "share_unknown_rows": 2}), "pools and bonding curves removed: 2 rows, supply share unknown")
        self.assertEqual(hf.removed_infrastructure_text({"rows": 3, "supply_pct": 1.5, "share_unknown_rows": 1}),
                         "pools and bonding curves removed: 3 rows, at least 1.5% of supply (share unknown for 1 row)")
        res = hf.provider_cohort_sources(holders_with({}, pools=["POOL"]), jupiter_payload=[jrow("POOL", T0)])["jupiter"]  # no Helius share, no supply
        self.assertEqual(res["coverage"]["infrastructure_removed"], {"rows": 1, "supply_pct": 0.0, "share_unknown_rows": 1})
        self.assertNotIn("0.0%", hf.removed_infrastructure_text(res["coverage"]["infrastructure_removed"]))

    def test_nothing_removed_says_so_and_no_line_carries_a_verdict_word(self):
        rows = [jrow(addr(i), T0 + i * 60) for i in range(3)]
        holders = holders_with({addr(i): 1.0 for i in range(3)} | {"REST": 97.0}, pools=[addr(400)])
        cohorts = hf.provider_cohort_sources(holders, gmgn_payload=[grow(addr(i), T0, 0.01) for i in range(3)], jupiter_payload=rows)
        a = hf.assess(holders | {"distribution": {}, "warnings": []}, None, provider_cohorts=cohorts)
        for key in ("gmgn", "jupiter"):
            lines = next(s for s in a["sources"] if s["key"] == key)["lines"]
            self.assertIn("pools removed: none in these rows", lines)
            self.assertEqual(next(s for s in a["sources"] if s["key"] == key)["status"], "read")
        for text in ("pools removed: none in these rows", "pools and bonding curves removed: 4 rows, 9.07% of supply",
                     hf.removed_infrastructure_text({"rows": 2, "supply_pct": 0.0, "share_unknown_rows": 2})):
            self.assertIsNone(VERDICT_WORDS.search(text), text)

    def test_only_pool_rows_still_reads_as_read_not_empty(self):
        res = hf.provider_cohort_sources(holders_with({"POOL": 10.0, "REST": 90.0}, pools=["POOL"]), jupiter_payload=[jrow("POOL", T0)])
        a = hf.assess({"distribution": {}, "warnings": [], "earliest_pair_created_at": T0}, None, provider_cohorts=res)
        block = next(s for s in a["sources"] if s["key"] == "jupiter")
        self.assertEqual(block["status"], "read")
        self.assertIn("pools and bonding curves removed: 1 row, 10.0% of supply", block["lines"])


if __name__ == "__main__":
    unittest.main()
