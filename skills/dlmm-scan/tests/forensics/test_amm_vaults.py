"""DS-AMM-VAULTS-T1: shared DEX vault authorities count as pools (pure, offline).

Raydium CPMM, Raydium AMM v4, Meteora DAMM v2 and Meteora DBC keep the token vaults of every pool of the program under ONE
authority PDA, not under the pair address Dexscreener lists. Before this change such a pool was counted as a holder: on
$LAUNCH (2026-10-26) the Raydium CPMM authority GpMZbSM2... (4.64%) was the top holder, and the EXIT OVERHANG line read
9.9x against a 1.90% Meteora DLMM pool. run_holders now adds each of these authorities that holds the token to the pool set.

Covers the ticket's acceptance criteria: every authority derived again here from its cited program id and seed, by this
file's own derivation, and matched with the cited lines (fixtures/amm_vaults/citations.json; the cached Meteora pages too
when the provider-docs cache is on this machine) (1); on $LAUNCH and The White Whale the authority is infrastructure, out of
the top-holder line, never looked up by run_funders, dropped from the GMGN and Jupiter cohort passes and counted in
"pools hold" (2); rows of other owners unchanged, and an authority that holds nothing adds nothing (3); the $LAUNCH EXIT
OVERHANG against the 4.64% row, still named as a fallback (4). Repair R1: the "no pool owner matched" warning, and the
"pool exclusion unreliable" state it feeds, is decided exactly as before, on the Dexscreener pairs and --exclude owners
only, so a dust-sized authority can never silence it (NoPoolWarningTests). Fixtures: fixtures/amm_vaults/ holds trimmed public data of
the two saved scans (written by the author's private fixture scripts of DS-AMM-VAULTS-T1).

DS-AMM-VAULTS-T2 (LaunchLabAndDynamicVaultTests) adds two more: the Raydium LaunchLab authority (one shared address, cited from
raydium-io/raydium-cpi and raydium-sdk-V2 at pinned commits) and THIS mint's Meteora Dynamic Vault PDA (one per mint, the owner
of the token vault that DAMM v1 pools use; cited from the provider-docs cache). Each is derived again here from the cited lines,
checked against the live example in fixtures/amm_vaults/live_example_20261028.json (free public RPC, no key), counted as a
pool only when it holds the token, and never allowed to silence the no-pool warning. Fixture script: the author's private
DS-AMM-VAULTS-T2 script.
"""

from __future__ import annotations

import base64
import hashlib
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

import exit_overhang as eo  # noqa: E402
import helius_forensics as hf  # noqa: E402
from test_holder_forensics import FakeHelius  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "amm_vaults"
CITATIONS = json.loads((FIX / "citations.json").read_text(encoding="utf-8"))
LAUNCH = json.loads((FIX / "launch_20261026.json").read_text(encoding="utf-8"))
WHALE = json.loads((FIX / "white_whale_20261025.json").read_text(encoding="utf-8"))
METEORA_CACHE = Path(os.environ.get("PROVIDER_DOCS_CACHE") or "provider-docs-cache-not-set") / "meteora" / "fulldocs.pages" / "developer-guides"

CPMM = "GpMZbSM2GgvTKHJirzeGfMFoaZ8UR2X7F4v8vHTvxFbL"
AMM_V4 = "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1"
DAMM_V2 = "HLnpSz9h2S4hiLQ43rnSD9XkcUThA7B8hQMKmDaiTLcC"
DBC = "FhVo3mqL8PW5pH5U2CN4XE33DokiyZnUwuGpH2hmHLuM"
LAUNCHLAB = "WLHv2UAZm6z4KyaaELi5pjdbJh6RESMva1Rnn8pJVVh"
EXPECTED = {CPMM: "Raydium CPMM", AMM_V4: "Raydium AMM v4", DAMM_V2: "Meteora DAMM v2", DBC: "Meteora DBC", LAUNCHLAB: "Raydium LaunchLab"}
LIVE = json.loads((FIX / "live_example_20261028.json").read_text(encoding="utf-8"))
VERDICT_WORDS = re.compile(r"\b(clean|safe|low)\b", re.IGNORECASE)

# ----------------------------------------------------------------------------- this file's own derivation (independent)
_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P


def b58(raw: bytes) -> str:
    n, out = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _ALPHABET[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def unb58(text: str) -> bytes:
    n = 0
    for ch in text:
        n = n * 58 + _ALPHABET.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


def on_curve(raw: bytes) -> bool:
    """RFC 8032 point decoding: the 32 bytes are a curve point when x^2 = (y^2 - 1) / (d y^2 + 1) has a root mod p."""
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    if y >= _P:
        return False
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    return x2 == 0 or pow(x2, (_P - 1) // 2, _P) == 1


def pda(seed: bytes, program_id: str) -> str:
    """Pubkey::find_program_address([seed], program_id): the first bump from 255 down that leaves the curve."""
    for bump in range(255, -1, -1):
        digest = hashlib.sha256(seed + bytes([bump]) + unb58(program_id) + b"ProgramDerivedAddress").digest()
        if not on_curve(digest):
            return b58(digest)
    raise AssertionError("no bump")


def cited(program: dict) -> tuple[str, bytes]:
    """Program id and seed read back out of the cited lines (not from the module under test)."""
    lines = [c["text"] for s in program["sources"] for c in s["lines"]]
    ids = set()
    for ln in lines:
        if "declare_id!" in ln or "Mainnet Beta" in ln:
            ids |= set(re.findall(r"[1-9A-HJ-NP-Za-km-z]{32,44}", ln))
    seeds = set()
    for pattern in (r'AUTH_SEED: &str = "([^"]+)";', r'= b"([^"]+)";', r"`derivePoolAuthority\(\)` \| `([a-z_]+)`", r"PDA from `([a-z_]+)`"):
        for ln in lines:
            seeds |= set(re.findall(pattern, ln))
    assert len(ids) == 1 and len(seeds) == 1, (program["name"], ids, seeds)
    return ids.pop(), seeds.pop().encode()


# ----------------------------------------------------------------------------- fixtures as run_holders inputs


def rest_owner(i: int) -> str:
    return ("Rest" + "".join("ABCDEFGHJK"[int(c)] for c in f"{i:05d}")).ljust(44, "z")


def accounts_of(fx: dict) -> list[dict]:
    """Token accounts that give the saved shares exactly: the kept owners with their raw balances, then the rest of the raw
    supply spread evenly over as many synthetic owners as the scan had left (each far below every kept top-30 owner)."""
    kept = [{"owner": o, "amount": b} for o, b in fx["owners"]]
    n = fx["owners_saved"] - len(kept)
    each = (fx["supply_raw"] - sum(b for _, b in fx["owners"])) / n
    assert each < min(b for _, b in fx["owners"][:30])
    return kept + [{"owner": rest_owner(i), "amount": each} for i in range(n)]


def holders_of(fx: dict, *, authorities: dict | None = None):
    """run_holders over the fixture (Dexscreener replaced by the saved pool_addresses). `authorities={}` replays the code
    before this change, whose pool set had no authorities (and, since T2, no per-mint Dynamic Vault either)."""
    fake = FakeHelius(accounts=accounts_of(fx))
    pairs = [{"pairAddress": a, "pairCreatedAt": fx["earliest_pair_created_at"] * 1000} for a in fx["pool_addresses"]]
    table = hf.SHARED_VAULT_AUTHORITIES if authorities is None else authorities
    vault = hf.dynamic_vault_authority if authorities is None else (lambda mint: None)
    with mock.patch.object(hf, "dexscreener_pairs", return_value=(pairs, True)), mock.patch.object(hf, "SHARED_VAULT_AUTHORITIES", table), \
            mock.patch.object(hf, "dynamic_vault_authority", vault):
        return fake, hf.run_holders(fake, fx["mint"])


def synthetic(balances: dict, pools=()):
    fake = FakeHelius(accounts=[{"owner": o, "amount": b} for o, b in balances.items()])
    with mock.patch.object(hf, "dexscreener_pairs", return_value=([{"pairAddress": p} for p in pools], True)):
        return fake, hf.run_holders(fake, "HgTGdc29D5bDMrDvsCLnorxz899VyDj7ZN7FPa6vpump")


def wallet(i: int) -> str:
    return ("W" + "".join("ABCDEFGHJK"[int(c)] for c in f"{i:03d}")).ljust(44, "K")


def first_wallet(holders: dict) -> dict:
    return next(r for r in holders["top_holders"] if not r["infrastructure"])


# ----------------------------------------------------------------------------- 1. citations


class CitedAuthorityTests(unittest.TestCase):
    def test_each_authority_is_derived_again_from_its_cited_program_id_and_seed(self):
        derived = {}
        for program in CITATIONS["programs"]:
            program_id, seed = cited(program)
            self.assertEqual((program_id, seed.decode()), (program["program_id"], program["seed"]), program["name"])
            derived[pda(seed, program_id)] = program["name"]
        self.assertEqual(derived, EXPECTED)
        self.assertEqual(hf.SHARED_VAULT_AUTHORITIES, EXPECTED)

    def test_the_module_carries_the_cited_program_ids_and_seeds(self):
        self.assertEqual([(n, p, s) for n, p, s in hf.SHARED_VAULT_PROGRAMS],
                         [(p["name"], *cited(p)) for p in CITATIONS["programs"]])

    def test_meteora_authorities_match_the_address_the_docs_print(self):
        for program in CITATIONS["programs"]:
            if program["cited_authority"] is None:
                continue
            program_id, seed = cited(program)
            self.assertEqual(pda(seed, program_id), program["cited_authority"])
            self.assertTrue(any(program["cited_authority"] in c["text"] for s in program["sources"] for c in s["lines"]))

    def test_raydium_ids_are_the_mainnet_builds_and_pinned_to_a_commit(self):
        raydium = [p for p in CITATIONS["programs"] if p["name"].startswith("Raydium")]
        self.assertEqual([p["name"] for p in raydium], ["Raydium CPMM", "Raydium AMM v4", "Raydium LaunchLab"])
        for program in raydium:
            declare = [c for s in program["sources"] for c in s["lines"] if "declare_id!" in c["text"]]
            self.assertEqual(len(declare), 1)
            self.assertEqual(declare[0]["line_above"].strip(), '#[cfg(not(feature = "devnet"))]')
            for s in program["sources"]:
                self.assertRegex(s["where"], r"^https://raw\.githubusercontent\.com/raydium-io/raydium-(cp-swap|amm|cpi|sdk-V2)/[0-9a-f]{40}/")
                self.assertRegex(s["sha256"], r"^[0-9a-f]{64}$")

    def test_module_derivation_agrees_with_this_files_on_other_seeds(self):
        for seed, program in ((b"pool-authority", hf.SHARED_VAULT_PROGRAMS[2][1]), (b"amm_config_account_seed", hf.SHARED_VAULT_PROGRAMS[1][1]), (b"x", hf.SHARED_VAULT_PROGRAMS[0][1])):
            self.assertEqual(hf.find_program_address([seed], program), pda(seed, program))
            self.assertNotIn(pda(seed, program), EXPECTED)

    @unittest.skipUnless(METEORA_CACHE.is_dir(), "the provider-docs Meteora cache is not on this machine")
    def test_cited_meteora_lines_are_in_the_provider_docs_cache(self):
        meteora = [p for p in CITATIONS["programs"] + CITATIONS["mint_vaults"] if p["name"].startswith("Meteora")]
        self.assertEqual(len(meteora), 3)
        for program in meteora:
            for s in program["sources"]:
                path = METEORA_CACHE / s["where"].split("developer-guides/", 1)[1]
                text = path.read_text(encoding="utf-8").splitlines()
                for c in s["lines"]:
                    self.assertEqual(text[c["line"] - 1], c["text"], f"{path.name}:{c['line']}")


# ----------------------------------------------------------------------------- 2. $LAUNCH and The White Whale


class LaunchAndWhiteWhaleTests(unittest.TestCase):
    def test_launch_raydium_cpmm_authority_is_a_pool_not_the_top_holder(self):
        _, before = holders_of(LAUNCH, authorities={})
        self.assertEqual(before["distribution"]["top_ex_infra"], LAUNCH["saved_distribution"]["top_ex_infra"])  # the saved numbers rebuilt
        self.assertEqual(before["distribution"]["infrastructure_pct"], 4.97)
        self.assertEqual((before["top_holders"][0]["wallet"], before["top_holders"][0]["infrastructure"]), (CPMM, False))
        self.assertNotIn(CPMM, before["pool_addresses"])
        _, after = holders_of(LAUNCH)
        self.assertIn(CPMM, after["pool_addresses"])
        self.assertEqual(after["top_holders"][0], {"rank": 1, "wallet": CPMM, "share_pct": 4.6405, "infrastructure": True})
        self.assertEqual((first_wallet(after)["wallet"], first_wallet(after)["share_pct"]), ("2cnsrrC4RUSUhTT1wGc9XYmmSjQCBf9pVUGDHudSJsVn", 3.2817))
        self.assertEqual(after["distribution"]["top_ex_infra"], {"top_1": 3.28, "top_10": 17.74})
        self.assertEqual(after["distribution"]["infrastructure_pct"], 9.61)  # 4.97 + 4.64 (and the DAMM v2 authority's 0.0006)

    def test_white_whale_same_address_leaves_the_top_holder_line(self):
        _, before = holders_of(WHALE, authorities={})
        self.assertEqual(before["distribution"]["top_ex_infra"], WHALE["saved_distribution"]["top_ex_infra"])
        self.assertEqual(first_wallet(before)["wallet"], CPMM)
        self.assertEqual(before["distribution"]["infrastructure_pct"], 0.36)
        _, after = holders_of(WHALE)
        self.assertEqual(first_wallet(after)["wallet"], "GgA4iFgFcFgQ5Fs3iM7kf8YQKejH7L7zjswxV1UqJ8Gg")
        self.assertEqual(after["distribution"]["top_ex_infra"], {"top_1": 3.71, "top_10": 21.35})
        self.assertEqual(after["distribution"]["infrastructure_pct"], 6.22)  # 0.36 + 5.78 (CPMM) + 0.08 (DAMM v2)
        infra = {r["wallet"] for r in after["top_holders"] if r["infrastructure"]}
        self.assertTrue({CPMM, DAMM_V2} <= infra)

    def test_run_funders_never_looks_up_the_authority(self):
        for fx in (LAUNCH, WHALE):
            fake, before = holders_of(fx, authorities={})
            hf.run_funders(fake, before, top=5)
            self.assertEqual(fake.calls[0], CPMM)  # before: the vault authority was examined as the biggest "wallet"
            fake, after = holders_of(fx)
            res = hf.run_funders(fake, after, top=5)
            self.assertNotIn(CPMM, fake.calls)
            self.assertEqual(fake.calls, [o for o, _ in after["_ranked"] if o not in set(after["pool_addresses"])][:5])
            self.assertEqual(res["requested_wallets"], 5)

    def test_cohort_passes_drop_the_authority_row(self):
        for fx in (LAUNCH, WHALE):
            gmgn, jupiter = {"list": fx["gmgn_top100_cpmm_row"]}, {"holders": fx["jupiter_top100_cpmm_row"]}
            _, before = holders_of(fx, authorities={})
            old = hf.provider_cohort_sources(before, gmgn, jupiter)
            self.assertEqual(old["gmgn"]["coverage"]["infrastructure_removed"]["rows"], 0)
            self.assertEqual(old["jupiter"]["coverage"]["infrastructure_removed"]["rows"], 0)
            _, after = holders_of(fx)
            new = hf.provider_cohort_sources(after, gmgn, jupiter)
            share = round(dict(after["_ranked"])[CPMM], 2)
            for src in ("gmgn", "jupiter"):
                self.assertEqual(new[src]["coverage"]["infrastructure_removed"], {"rows": 1, "supply_pct": share, "share_unknown_rows": 0}, src)
                self.assertEqual(new[src]["coverage"]["rows"], 0, src)

    def test_holders_json_written_by_run_holders_is_read_back_by_assess(self):
        _, after = holders_of(LAUNCH)
        raw = json.loads(json.dumps(hf._public(after) | {"owner_balances": after["_balances"], "credits_spent": 0}))
        holders, _ = hf.load_run_holders(raw, LAUNCH["mint"])
        self.assertIn(CPMM, holders["pool_addresses"])
        self.assertEqual(holders["distribution"]["infrastructure_pct"], 9.61)


# ----------------------------------------------------------------------------- 3. every authority; other rows unchanged


class PoolSetTests(unittest.TestCase):
    def test_every_authority_holding_the_token_is_a_pool(self):
        for authority, name in EXPECTED.items():
            balances = {authority: 30.0, **{wallet(i): 10.0 - i * 0.5 for i in range(10)}}
            fake, holders = synthetic(balances)
            self.assertIn(authority, holders["pool_addresses"], name)
            self.assertEqual(holders["top_holders"][0], {"rank": 1, "wallet": authority, "share_pct": round(30 / sum(balances.values()) * 100, 4), "infrastructure": True})
            self.assertEqual(holders["distribution"]["infrastructure_pct"], round(30 / sum(balances.values()) * 100, 2))
            self.assertEqual(holders["warnings"], [hf.WARN_NO_POOL], name)  # R1: no pair or --exclude owner matched, so the old warning stays
            hf.run_funders(fake, holders, top=3)
            self.assertNotIn(authority, fake.calls, name)

    def test_only_pool_under_a_cpmm_authority_keeps_the_old_warning_and_is_still_excluded(self):
        balances = {CPMM: 40.0, **{wallet(i): 6.0 for i in range(10)}}
        fake, holders = synthetic(balances, pools=[wallet(950)])  # Dexscreener lists a pair whose address owns no token account
        self.assertEqual(holders["warnings"], [hf.WARN_NO_POOL])
        self.assertEqual(holders["pool_addresses"], sorted([CPMM, wallet(950)]))
        self.assertTrue(holders["top_holders"][0]["infrastructure"])
        self.assertEqual(holders["distribution"]["infrastructure_pct"], 40.0)
        self.assertEqual(holders["distribution"]["top_ex_infra"]["top_1"], 6.0)
        hf.run_funders(fake, holders, top=3)
        self.assertNotIn(CPMM, fake.calls)
        cov = hf.coverage_block(hf._public(holders), None)
        self.assertFalse(cov["pool_exclusion_reliable"])

    def test_without_an_authority_the_holder_list_is_byte_identical_to_the_old_pool_set(self):
        balances = {wallet(i): 50.0 - i for i in range(40)}
        pool = wallet(900)
        balances[pool] = 70.0
        _, now = synthetic(balances, pools=[pool])
        with mock.patch.object(hf, "SHARED_VAULT_AUTHORITIES", {}):
            _, old = synthetic(balances, pools=[pool])
        self.assertEqual(json.dumps(hf._public(now)), json.dumps(hf._public(old)))

    def test_only_the_authority_row_changes_and_the_next_wallet_joins_the_list(self):
        balances = {wallet(i): 50.0 - i for i in range(30)}
        balances[CPMM] = 60.0
        with mock.patch.object(hf, "SHARED_VAULT_AUTHORITIES", {}):
            _, old = synthetic(balances)
        _, now = synthetic(balances)
        old_top = hf.top_holder_rows(old["_ranked"], set(old["pool_addresses"]), 25)
        now_top = hf.top_holder_rows(now["_ranked"], set(now["pool_addresses"]), 25)
        self.assertEqual(now_top[: len(old_top)], [dict(r, infrastructure=True) if r["wallet"] == CPMM else r for r in old_top])
        self.assertEqual(len(now_top), len(old_top) + 1)
        self.assertFalse(now_top[-1]["infrastructure"])
        self.assertEqual(now["distribution"]["owners"], old["distribution"]["owners"])
        self.assertEqual(now["_ranked"], old["_ranked"])  # shares are of the whole supply, pools included: unchanged
        self.assertEqual(set(now["pool_addresses"]) - set(old["pool_addresses"]), {CPMM})

    def test_an_authority_that_holds_nothing_adds_nothing(self):
        balances = {wallet(i): 10.0 + i for i in range(12)}
        _, holders = synthetic(balances, pools=[wallet(5)])
        self.assertEqual(holders["pool_addresses"], [wallet(5)])
        self.assertFalse(set(EXPECTED) & set(holders["pool_addresses"]))

    def test_near_misses_are_not_pools(self):
        near = {pda(b"pool-authority", hf.SHARED_VAULT_PROGRAMS[2][1]): "hyphen instead of underscore",
                pda(b"vault_and_lp_mint_auth_seed", "DRaycpLY18LhpbydsBWbVJtxpNv9oXPgjRSfpF2bWpYb"): "the CPMM devnet program",
                hf.SHARED_VAULT_PROGRAMS[0][1]: "the CPMM program id itself"}
        balances = {**{a: 20.0 for a in near}, **{wallet(i): 5.0 for i in range(5)}}
        _, holders = synthetic(balances)
        self.assertEqual(holders["pool_addresses"], [])
        self.assertFalse(any(r["infrastructure"] for r in holders["top_holders"]))

    def test_extra_exclude_and_dexscreener_pairs_still_count(self):
        balances = {CPMM: 10.0, wallet(1): 8.0, wallet(2): 6.0, wallet(3): 4.0}
        fake = FakeHelius(accounts=[{"owner": o, "amount": b} for o, b in balances.items()])
        with mock.patch.object(hf, "dexscreener_pairs", return_value=([{"pairAddress": wallet(2)}], True)):
            holders = hf.run_holders(fake, "HgTGdc29D5bDMrDvsCLnorxz899VyDj7ZN7FPa6vpump", {wallet(3)})
        self.assertEqual(holders["pool_addresses"], sorted([CPMM, wallet(2), wallet(3)]))


class NoPoolWarningTests(unittest.TestCase):
    """Repair R1: the warning and everything it feeds are decided on the Dexscreener pairs and --exclude owners alone, as on
    master. Checked two ways: against the same code with an empty authority table, and by absolute expectations for the
    matched-pair, dust, CPMM-only (PoolSetTests) and --exclude cases."""

    DUST = {DAMM_V2: 0.01}  # 0.01% of a 100-unit supply: the dust the DAMM v2 authority holds in 17 of the 20 saved scans

    def holders(self, pools=(), exclude=()):
        balances = {wallet(900): 20.0, **self.DUST, **{wallet(i): (79.99 / 40) for i in range(40)}}  # wallet(900): an unlisted program's pool
        fake = FakeHelius(accounts=[{"owner": o, "amount": b} for o, b in balances.items()])
        with mock.patch.object(hf, "dexscreener_pairs", return_value=([{"pairAddress": p} for p in pools], True)):
            return hf.run_holders(fake, "HgTGdc29D5bDMrDvsCLnorxz899VyDj7ZN7FPa6vpump", set(exclude))

    def test_dust_authority_never_silences_the_warning_while_the_real_pool_counts_as_a_holder(self):
        holders = self.holders(pools=[wallet(951)])
        self.assertIn(DAMM_V2, holders["pool_addresses"])  # the dust authority is still a pool
        self.assertEqual(holders["distribution"]["infrastructure_pct"], 0.01)
        self.assertEqual(holders["warnings"], [hf.WARN_NO_POOL])
        self.assertEqual(first_wallet(holders)["wallet"], wallet(900))  # the unlisted pool still counts as a holder, as the warning says
        cov = hf.coverage_block(hf._public(holders), None)
        self.assertFalse(cov["pool_exclusion_reliable"])
        lines = [ln for src in hf.read_sources(hf._public(holders), None, [], None) for ln in src["lines"]]
        self.assertTrue(any("(pool exclusion unreliable)" in ln for ln in lines))

    def test_exclude_of_the_real_pool_clears_the_warning_and_reads_reliable(self):
        """R2: the owner's own remedy (rerun with --exclude <pool owner>) with no Dexscreener pair matched: no warning, pool
        exclusion reliable and no unreliable note, as on master. A pool set taken before the --exclude owners fails here."""
        holders = self.holders(pools=[wallet(951)], exclude=[wallet(900)])
        self.assertEqual(holders["warnings"], [])
        self.assertTrue(hf.coverage_block(hf._public(holders), None)["pool_exclusion_reliable"])
        lines = [ln for src in hf.read_sources(hf._public(holders), None, [], None) for ln in src["lines"]]
        self.assertFalse(any("(pool exclusion unreliable)" in ln for ln in lines))
        self.assertEqual(holders["distribution"]["infrastructure_pct"], 20.01)  # the excluded pool and the dust authority
        self.assertEqual(sorted(holders["pool_addresses"]), sorted([wallet(900), wallet(951), DAMM_V2]))
        self.assertEqual(self.holders(exclude=[wallet(900)])["warnings"], [])  # no pair listed at all: the same

    def test_the_warning_equals_the_same_code_with_an_empty_authority_table(self):
        for name, kwargs in (("no pair", {}), ("an unmatched pair", {"pools": [wallet(951)]}), ("a matched pair", {"pools": [wallet(900)]}),
                             ("--exclude", {"exclude": [wallet(900)]})):
            with self.subTest(name):
                now = self.holders(**kwargs)
                with mock.patch.object(hf, "SHARED_VAULT_AUTHORITIES", {}):
                    old = self.holders(**kwargs)
                self.assertEqual(now["warnings"], old["warnings"])
                self.assertEqual(hf.coverage_block(hf._public(now), None)["pool_exclusion_reliable"],
                                 hf.coverage_block(hf._public(old), None)["pool_exclusion_reliable"])
                self.assertEqual(set(now["pool_addresses"]) - set(old["pool_addresses"]), {DAMM_V2})
        self.assertEqual(self.holders(pools=[wallet(900)])["warnings"], [])  # a matched pair still clears it, as before


# ----------------------------------------------------------------------------- DS-AMM-VAULTS-T2: LaunchLab and this mint's Dynamic Vault

VAULT_CITE = CITATIONS["mint_vaults"][0]
LAUNCHLAB_CITE = next(p for p in CITATIONS["programs"] if p["name"] == "Raydium LaunchLab")
DAMM_V1_PROGRAM = "Eo7WjKq67rjJQSZxS6z3YkapzY3eMj6Xy8X5EQVn5UaB"  # provider-docs cache damm-v1/index.md, "Program IDs"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
SYNTH_MINT = "HgTGdc29D5bDMrDvsCLnorxz899VyDj7ZN7FPa6vpump"  # the mint synthetic() scans
USDC, WSOL = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "So11111111111111111111111111111111111111112"
_KEY = r"`([1-9A-HJ-NP-Za-km-z]{32,44})`"


def cited_vault(entry: dict) -> tuple[str, bytes, bytes, bytes]:
    """Program id, vault seed word, base key and token-vault seed word, read back out of the cited Meteora lines (the PDA Map
    row and the Rust derivation must agree on the word and on the order: word, token mint, base)."""
    lines = [c["text"] for s in entry["sources"] for c in s["lines"]]
    program = {k for ln in lines if ln.startswith("| Mainnet Beta |") for k in re.findall(_KEY, ln)}
    base = {k for ln in lines if ln.startswith("| `VAULT_BASE_KEY` |") for k in re.findall(_KEY, ln)}
    word = {w for ln in lines for w in re.findall(r"^\| Rebalance vault \| .+ \| `([a-z_]+)`, token mint, `VAULT_BASE_KEY` \|$", ln)}
    word |= {w for ln in lines for w in re.findall(r'^\s*&\[b"([a-z_]+)"\.as_ref\(\), token_mint\.as_ref\(\), base\.as_ref\(\)\],$', ln)}
    token_word = {w for ln in lines for w in re.findall(r"^\| Token vault \| .+ \| `([a-z_]+)`, vault \|$", ln)}
    assert len(program) == len(base) == len(word) == len(token_word) == 1, (program, base, word, token_word)
    return program.pop(), word.pop().encode(), unb58(base.pop()), token_word.pop().encode()


def vault_of(mint: str) -> str:
    program, word, base, _ = cited_vault(VAULT_CITE)
    return pda(word + unb58(mint) + base, program)


def token_vault_of(vault: str) -> str:
    program, _, _, token_word = cited_vault(VAULT_CITE)
    return pda(token_word + unb58(vault), program)


def t1_code():
    """The same code as T1 shipped it: the four T1 authorities, no LaunchLab, no Dynamic Vault."""
    t1 = {a: n for a, n in hf.SHARED_VAULT_AUTHORITIES.items() if a != LAUNCHLAB}
    return mock.patch.multiple(hf, SHARED_VAULT_AUTHORITIES=t1, dynamic_vault_authority=lambda mint: None)


def warning_holders(dust: str, pools=(), exclude=()):
    """NoPoolWarningTests' setup with `dust` (0.01%) in place of the DAMM v2 authority: wallet(900) is an unlisted program's pool."""
    balances = {wallet(900): 20.0, dust: 0.01, **{wallet(i): (79.99 / 40) for i in range(40)}}
    fake = FakeHelius(accounts=[{"owner": o, "amount": b} for o, b in balances.items()])
    with mock.patch.object(hf, "dexscreener_pairs", return_value=([{"pairAddress": p} for p in pools], True)):
        return hf.run_holders(fake, SYNTH_MINT, set(exclude))


class LaunchLabAndDynamicVaultTests(unittest.TestCase):
    def test_launchlab_authority_is_derived_from_the_cited_lines_and_equals_the_sdk_address(self):
        program_id, seed = cited(LAUNCHLAB_CITE)
        self.assertEqual((program_id, seed), ("LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj", b"vault_auth_seed"))
        self.assertEqual(pda(seed, program_id), LAUNCHLAB)
        sdk = [c["text"] for s in LAUNCHLAB_CITE["sources"] if s["where"].endswith("/src/common/programId.ts") for c in s["lines"]]
        self.assertEqual(sdk, [f'export const LAUNCHPAD_PROGRAM = new PublicKey("{program_id}");', f'export const LAUNCHPAD_AUTH = new PublicKey("{LAUNCHLAB}");'])
        ctx = [c["text"].strip() for s in LAUNCHLAB_CITE["sources"] if s["where"].endswith("/launch-cpi/src/context.rs") for c in s["lines"]]
        self.assertIn("crate::AUTH_SEED.as_bytes(),", ctx)
        self.assertEqual(ctx.count("token::authority = authority,"), 2)  # the base and the quote pool vault
        self.assertEqual(hf.SHARED_VAULT_AUTHORITIES[LAUNCHLAB], "Raydium LaunchLab")
        self.assertEqual(LAUNCHLAB_CITE["read_on"], "2026-10-28")

    def test_dynamic_vault_is_derived_per_mint_from_the_cited_seeds(self):
        program, word, base, token_word = cited_vault(VAULT_CITE)
        self.assertEqual((program, word, b58(base), token_word), (hf.DYNAMIC_VAULT_PROGRAM, b"vault", hf.DYNAMIC_VAULT_BASE, b"token_vault"))
        mints = [USDC, WSOL, SYNTH_MINT, LAUNCH["mint"], WHALE["mint"], LIVE["launchlab"]["mint"]]
        vaults = [hf.dynamic_vault_authority(m) for m in mints]
        self.assertEqual(vaults, [vault_of(m) for m in mints])
        self.assertEqual(len(set(vaults)), len(mints))  # one per mint, not one shared address
        self.assertEqual(vaults[:2], ["3ESUFCnRNgZ7Mn2mPPUMmXYaKU8jpnV9VtA17M7t2mHQ", "FERjPVNEa7Udq8CEv68h6tPL46Tq7ieE49HrE2wea3XT"])  # the live example
        for bad in ("Mint" + "1" * 36 + "pump", "0OIl" * 8):  # not 32 bytes, not base58
            self.assertIsNone(hf.dynamic_vault_authority(bad))

    def test_live_damm_v1_pool_stores_the_derived_vaults_and_each_vault_owns_its_token_vault(self):
        acc = LIVE["dynamic_vault"]["accounts"]
        program, _, base, _ = cited_vault(VAULT_CITE)
        printed = [re.findall(_KEY, c["text"]) for s in VAULT_CITE["sources"] for c in s["lines"] if "MAINNET_POOL.USDC_SOL" in c["text"]]
        pool = acc["damm_v1_usdc_sol_pool"]
        self.assertEqual(printed, [["5yuefgbJJpmFNK2iiYbLSpv1aZXq7F9AUKkZKErTYCvs"]])
        self.assertEqual((pool["address"], pool["program_owner"]), (printed[0][0], DAMM_V1_PROGRAM))
        raw = base64.b64decode(pool["data_base64"])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), pool["data_sha256"])
        # Pool after the 8-byte discriminator: lp_mint, token_a_mint, token_b_mint, a_vault, b_vault (damm-v1/program/accounts.md)
        self.assertEqual([b58(raw[o:o + 32]) for o in (40, 72, 104, 136)], [USDC, WSOL, vault_of(USDC), vault_of(WSOL)])
        for name, mint in (("USDC", USDC), ("SOL", WSOL)):
            vault, token_vault = vault_of(mint), token_vault_of(vault_of(mint))
            state = acc[f"dynamic_vault_{name}"]
            self.assertEqual((state["address"], state["program_owner"]), (vault, program))
            kept = base64.b64decode(state["data_base64"])
            self.assertEqual((kept[19:51], kept[83:115], kept[1107:1139]), (unb58(token_vault), unb58(mint), base))  # token_vault, token_mint, base
            tv = acc[f"dynamic_vault_{name}_token_vault"]
            data = base64.b64decode(tv["data_base64"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), tv["data_sha256"])
            self.assertEqual((tv["address"], tv["program_owner"], b58(data[0:32]), b58(data[32:64])), (token_vault, TOKEN_PROGRAM, mint, vault), name)

    def test_live_launchlab_authority_owns_the_token_accounts_the_saved_scan_counted(self):
        live = LIVE["launchlab"]
        program_id, seed = cited(LAUNCHLAB_CITE)
        authority = pda(seed, program_id)
        self.assertEqual(live["owner"], authority)
        own_atas = {pda(unb58(authority) + unb58(tp) + unb58(live["mint"]), ATA_PROGRAM) for tp in (TOKEN_PROGRAM, TOKEN_2022)}
        total = 0
        for a in live["accounts"]:
            data = base64.b64decode(a["data_base64"])
            self.assertEqual((a["program_owner"], b58(data[0:32]), b58(data[32:64])), (TOKEN_PROGRAM, live["mint"], authority), a["address"])
            self.assertNotIn(a["address"], own_atas)  # program-made vaults, not the authority's own wallet account
            total += int.from_bytes(data[64:72], "little")
        self.assertEqual(len(live["accounts"]), 75)
        self.assertAlmostEqual(total / live["saved_raw_balance"], 1, delta=0.02)  # read about 6 hours after that scan
        share = round(live["saved_raw_balance"] / live["saved_supply_raw"] * 100, 4)
        self.assertEqual(share, 0.2652)  # rank 49 of that scan, counted as a wallet before this change

    def test_this_mints_dynamic_vault_holding_the_token_is_a_pool_and_never_looked_up(self):
        vault = vault_of(SYNTH_MINT)
        balances = {vault: 25.0, **{wallet(i): 10.0 - i * 0.5 for i in range(10)}}
        fake, holders = synthetic(balances)
        self.assertEqual(holders["pool_addresses"], [vault])
        self.assertEqual(holders["top_holders"][0], {"rank": 1, "wallet": vault, "share_pct": round(25 / sum(balances.values()) * 100, 4), "infrastructure": True})
        self.assertEqual(holders["distribution"]["infrastructure_pct"], round(25 / sum(balances.values()) * 100, 2))
        hf.run_funders(fake, holders, top=3)
        self.assertNotIn(vault, fake.calls)

    def test_another_mints_dynamic_vault_or_the_token_vault_itself_is_not_a_pool(self):
        near = {vault_of(USDC): "USDC's vault", vault_of(WSOL): "SOL's vault", vault_of(LAUNCH["mint"]): "another memecoin's vault",
                token_vault_of(vault_of(SYNTH_MINT)): "this mint's token vault (an account, not its owner)",
                pda(b"vault" + unb58(hf.DYNAMIC_VAULT_BASE) + unb58(SYNTH_MINT), hf.DYNAMIC_VAULT_PROGRAM): "base before mint"}
        balances = {**{a: 20.0 for a in near}, **{wallet(i): 5.0 for i in range(5)}}
        _, holders = synthetic(balances)
        self.assertEqual(holders["pool_addresses"], [])
        self.assertFalse(any(r["infrastructure"] for r in holders["top_holders"]))

    def test_a_holder_owned_by_neither_address_is_unchanged(self):
        balances = {wallet(i): 50.0 - i for i in range(40)}
        balances[wallet(900)] = 70.0
        balances[CPMM] = 15.0
        _, now = synthetic(balances, pools=[wallet(900)])
        with t1_code():
            _, old = synthetic(balances, pools=[wallet(900)])
        self.assertEqual(json.dumps(hf._public(now)), json.dumps(hf._public(old)))
        vault = vault_of(SYNTH_MINT)
        both = {**balances, LAUNCHLAB: 30.5, vault: 25.5}  # both inside the 30-wallet window
        _, now = synthetic(both, pools=[wallet(900)])
        with t1_code():
            _, old = synthetic(both, pools=[wallet(900)])
        self.assertEqual(set(now["pool_addresses"]) - set(old["pool_addresses"]), {LAUNCHLAB, vault})
        old_top = hf.top_holder_rows(old["_ranked"], set(old["pool_addresses"]), 30)
        now_top = hf.top_holder_rows(now["_ranked"], set(now["pool_addresses"]), 30)
        self.assertEqual(now_top[: len(old_top)], [dict(r, infrastructure=True) if r["wallet"] in (LAUNCHLAB, vault) else r for r in old_top])
        self.assertEqual(len(now_top), len(old_top) + 2)  # the next two ordinary wallets join the list
        self.assertEqual(now["_ranked"], old["_ranked"])

    def test_an_address_that_holds_nothing_adds_nothing(self):
        balances = {wallet(i): 10.0 + i for i in range(12)}
        _, holders = synthetic(balances, pools=[wallet(5)])
        self.assertEqual(holders["pool_addresses"], [wallet(5)])
        self.assertIsNotNone(hf.dynamic_vault_authority(SYNTH_MINT))

    def test_neither_new_address_silences_the_no_pool_warning(self):
        for dust in (LAUNCHLAB, vault_of(SYNTH_MINT)):
            for name, kwargs in (("no pair", {}), ("an unmatched pair", {"pools": [wallet(951)]}), ("a matched pair", {"pools": [wallet(900)]}),
                                 ("--exclude", {"exclude": [wallet(900)]})):
                with self.subTest(dust=dust[:8], case=name):
                    now = warning_holders(dust, **kwargs)
                    with t1_code():
                        old = warning_holders(dust, **kwargs)
                    self.assertEqual(now["warnings"], old["warnings"])
                    self.assertEqual(hf.coverage_block(hf._public(now), None)["pool_exclusion_reliable"],
                                     hf.coverage_block(hf._public(old), None)["pool_exclusion_reliable"])
                    self.assertEqual(set(now["pool_addresses"]) - set(old["pool_addresses"]), {dust})
            unmatched = warning_holders(dust, pools=[wallet(951)])
            self.assertEqual(unmatched["warnings"], [hf.WARN_NO_POOL])
            self.assertEqual(first_wallet(unmatched)["wallet"], wallet(900))  # the unlisted pool still counts as a holder, as the warning says
            self.assertEqual(warning_holders(dust, exclude=[wallet(900)])["warnings"], [])

    def test_no_verdict_word_in_the_skill_sentence(self):
        line = next(ln for ln in (SCRIPTS.parent / "SKILL.md").read_text(encoding="utf-8").splitlines() if "DS-AMM-VAULTS-T2" in ln)
        self.assertIn("Raydium LaunchLab", line)
        self.assertIsNone(VERDICT_WORDS.search(line))


# ----------------------------------------------------------------------------- 4. EXIT OVERHANG on $LAUNCH and The White Whale


def overhang(fx: dict, holders: dict) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp)
        (run / "holders.json").write_text(json.dumps(hf._public(holders) | {"owner_balances": holders["_balances"], "credits_spent": 0}))
        (run / "gmgn_holder_pnl.json").write_text(json.dumps(fx["gmgn_holder_pnl"]))
        (run / "creator_fees.json").write_text(json.dumps(fx["creator_fees"]))
        return eo.present(run)


class ExitOverhangTests(unittest.TestCase):
    FALLBACK = "(main pool by fallback: creator_fees empty: no_pump_curve; the ratio may be too high or too low)."

    def test_launch_reads_against_the_4_64_pct_raydium_pool_still_by_fallback(self):
        before = overhang(LAUNCH, holders_of(LAUNCH, authorities={})[1])
        self.assertEqual(before[0], "[for the executive summary] EXIT OVERHANG: DANGER (provisional) — 18.81% of supply sits in 34 wallets that bought at half "
                                    f"today's price or less: 9.9x the main pool's tokens {self.FALLBACK}")
        self.assertTrue(any(ln.startswith("  main pool: FZWxV7C4JKKe3wX54MM6QpcVAHtyGrtnPFmihysWfiDB, 1.90% of supply (holders.json), fallback:") for ln in before))
        after = overhang(LAUNCH, holders_of(LAUNCH)[1])
        self.assertEqual(after[0], "[for the executive summary] EXIT OVERHANG: DANGER (provisional) — 18.81% of supply sits in 34 wallets that bought at half "
                                   f"today's price or less: 4.1x the main pool's tokens {self.FALLBACK}")
        self.assertTrue(any(ln.startswith(f"  main pool: {CPMM}, 4.64% of supply (holders.json), fallback: the largest holders.json pool row") for ln in after))
        self.assertTrue(any("all pool rows together (holders.json infrastructure rows): 9.60% of supply, 5 rows" in ln for ln in after))
        self.assertEqual([ln for ln in after if ln.startswith("  no cost basis")], [ln for ln in before if ln.startswith("  no cost basis")])  # GMGN already marked it a pool

    def test_white_whale_main_pool_is_the_raydium_authority_and_it_leaves_the_wallet_rows(self):
        before = overhang(WHALE, holders_of(WHALE, authorities={})[1])
        self.assertIn("182.4x the main pool's tokens", before[0])
        self.assertTrue(any(ln.startswith("  no cost basis here = no average buy from GMGN: 3 wallets, 7.01% of supply") for ln in before))
        after = overhang(WHALE, holders_of(WHALE)[1])
        self.assertEqual(after[0], "[for the executive summary] EXIT OVERHANG: DANGER (provisional) — 56.59% of supply sits in 78 wallets that bought at half "
                                   f"today's price or less: 9.8x the main pool's tokens {self.FALLBACK}")
        self.assertTrue(any(ln.startswith(f"  main pool: {CPMM}, 5.78% of supply (holders.json), fallback:") for ln in after))
        self.assertTrue(any(ln.startswith("  no cost basis here = no average buy from GMGN: 2 wallets, 1.19% of supply") for ln in after))  # GMGN said addr_type 0

    def test_no_verdict_word_in_the_changed_lines_or_the_new_code(self):
        for fx in (LAUNCH, WHALE):
            before, after = overhang(fx, holders_of(fx, authorities={})[1]), overhang(fx, holders_of(fx)[1])
            for ln in set(after) - set(before):  # exit_overhang's own fallback warning (unchanged) says "too high or too low": not a verdict
                self.assertIsNone(VERDICT_WORDS.search(ln.replace("the ratio may be too high or too low", "")), ln)
        text = (SCRIPTS / "helius_forensics.py").read_text(encoding="utf-8")
        block = text[text.index("# ----------------------------------------------------------------------------- shared DEX vault authorities (cited)"):text.index("def run_holders(")]
        self.assertIsNone(VERDICT_WORDS.search(block))


if __name__ == "__main__":
    unittest.main()
