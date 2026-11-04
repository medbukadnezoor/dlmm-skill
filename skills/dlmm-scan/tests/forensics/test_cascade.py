"""HS-CASCADE-T1: the copy-trade cascade section that `gmgn_rows.py --present <RUN>` prints right after the holder cost and
PnL block, presentation only. Offline: fake GMGN transport, dummy keys, the real YMB GMGN answer of 2026-10-24
(fixtures/ymb_gmgn_top100_live_20261024.json) and the real watchlist (references/fomo_cascade_watchlist.json, HS-WATCHLIST-T1),
plus synthetic rows and synthetic watchlist files.

Covers the ticket's acceptance criteria: the YMB replay (frankdegods matched by wallet and GMGN handle, 0.39%, -56%, sold 0%,
in the red) (1); case-insensitive handle match with @ stripped, wallet match, no match on a part of a handle or a display
name (2); the 0.1% bar on watchlist and named lines and the under-bar count with a 0.05% match (3); pools out of every count
and the exact YMB Fomo-app count (4); a missing or malformed watchlist or gmgn_holder_pnl.json reads "not read (<reason>)",
exit 0, never "no cascade risk" (5); inert labels, key echoes dropped, no verdict words (6); assess byte-identical with and
without the section, and the engines never read either file (7). Also the identity-strength rule (HS-WATCHLIST-T1 Verifier
F1): a match through an unconfirmed X handle prints the name-only note, and a Fomo status other than matched never supplies a
wallet or a follower count."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import gmgn_rows as gr  # noqa: E402
import provider_words as pw  # noqa: E402
from test_assess import _map, _run, cape_holdings, run_assess, CAPE_LAUNCH  # noqa: E402
from test_gmgn_pnl import FRANK, POOLS, VERDICT_RE, PLACEHOLDER_RE, collect_main, present_main, wallet, ymb_payload, ymb_raw_rows  # noqa: E402
from test_gmgn_rows import DUMMY_KEY, NOW, fixture, synthetic_address  # noqa: E402
from test_solscanner_scan import CAPE  # noqa: E402

SKILL = Path(__file__).resolve().parents[2]
WATCHLIST = SKILL / "references" / "fomo_cascade_watchlist.json"
YMB_WHEN = "2026-10-24 01:02 UTC = 2026-10-24 08:02 WIB"
FRANK_LINE = ("    Copy-trade cascade risk: frankdegods (owner-named; Fomo followers 354,795 verified 2026-10-24) holds 0.39% of supply ($2.17k), "
              "unrealized -56.0%, sold 0%, matched by wallet and GMGN handle; in the red: a one-clip sell is likely, and copy bots mirror sells "
              "within about 1-3 s")
SUMMARY = "[for the executive summary] Copy-trade cascade risk (presentation only): frankdegods 0.39% (-56%)"
RED = "in the red: a one-clip sell is likely, and copy bots mirror sells within about 1-3 s"
NOT_PROOF = "no cascade risk"
SYNTH_TIME = "2026-10-19 08:53 UTC = 2026-10-19 15:53 WIB"  # NOW of the synthetic collects (the snapshot time saved by the collector)


def entry(x_handle, *, tier="tier1", x_status="as_in_report", fomo_status="matched", handle=None, wallet_address=None, followers=None,
          self_reported=None, checked_at="2026-10-24T02:21:31Z", candidates=()):
    """A watchlist entry in the HS-WATCHLIST-T1 shape."""
    return {"x_handle": x_handle, "x_handle_status": x_status, "display_name": None, "tier": tier, "evidence": "test", "source": "test",
            "evidence_date": "2026-10-24", "added": "2026-10-24", "followers_self_reported": self_reported, "followers_self_reported_source": None,
            "fomo": {"status": fomo_status, "reason": None, "query": x_handle, "handle": handle, "user_id": None, "followers": followers,
                     "solana_wallet": wallet_address, "candidates": list(candidates), "checked_at": checked_at, "credits_cost": 250}}


def write_watchlist(path: Path, entries, **top) -> Path:
    data = {"schema": gr.WATCHLIST_SCHEMA, "as_of": "2026-10-24", "note": "test", "entries": entries} | top
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def section(tmp: Path, rows, entries, *, key=DUMMY_KEY, **top):
    """Collect synthetic GMGN rows into tmp (CAPE as the mint, the frozen clock), write a watchlist, return the section."""
    code, _, err, _ = collect_main(tmp, {"data": {"list": rows}}, mint=CAPE, now=NOW, env={"GMGN_API_KEY": key})
    assert code == 0, err
    return gr.cascade_present(tmp, write_watchlist(tmp / "watchlist.json", entries, **top))


def text_of(lines) -> str:
    return "\n".join(lines)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class YmbReplayTests(unittest.TestCase):
    """Criteria 1 and 4 on the real YMB answer and the real watchlist file, through the registered command."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        code, _, err, _ = collect_main(cls.tmp, ymb_payload())
        assert code == 0, err
        code, cls.out, err = present_main(["--present", str(cls.tmp)])
        assert code == 0 and err == "", err
        cls.lines = cls.out.splitlines()
        cls.block = gr.present(cls.tmp)
        cls.section = cls.lines[len(cls.block):]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_the_pnl_block_is_unchanged_and_the_section_follows_it(self):
        self.assertEqual(self.lines[:len(self.block)], self.block, "the HS-PNL-T1 block prints first, unchanged")
        self.assertEqual(self.section, gr.cascade_present(self.tmp))
        self.assertEqual(self.section[0], SUMMARY)
        self.assertEqual(self.section[1], "Copy-trade cascade (presentation only)")
        self.assertEqual(self.section[-1], "  presentation only: never an engine input, never passed to assess, never changes a FLAG, verdict or threshold")

    def test_frankdegods_is_matched_by_wallet_and_gmgn_handle(self):
        self.assertIn("  watchlist traders holding 0.1% of supply or more: 1", self.section)
        self.assertIn(FRANK_LINE, self.section)
        frank = next(ln for ln in self.section if "Copy-trade cascade risk: frankdegods" in ln)
        share, pnl, sold = re.search(r"holds ([\d.]+)% of supply .*unrealized ([+-][\d.]+)%, sold (\d+)%", frank).groups()
        self.assertEqual((share, sold), ("0.39", "0"))
        self.assertLessEqual(abs(float(pnl) - -56), 1)
        self.assertIn(RED, frank)
        self.assertNotIn(FRANK, self.out.split("Copy-trade cascade (presentation only)", 1)[1], "the section names handles, not full addresses")

    def test_the_watchlist_wallet_is_the_gmgn_row_of_frankdegods(self):
        """The README says frankdegods matched by wallet too: the Fomo-verified main wallet equals the full YMB row address."""
        listed = next(e for e in json.loads(WATCHLIST.read_text())["entries"] if e["x_handle"] == "frankdegods")
        self.assertEqual((listed["fomo"]["status"], listed["fomo"]["solana_wallet"]), ("matched", FRANK))
        row = next(r for r in ymb_raw_rows() if r["address"] == FRANK)
        self.assertEqual((row["twitter_username"], row["addr_type"]), ("frankdegods", 0))

    def test_the_named_holders_not_on_the_watchlist(self):
        start = self.section.index("  named by GMGN, not on the watchlist (an X handle or GMGN's kol tag), at 0.1% of supply or more: 5")
        tail = "; not on the watchlist; GMGN's labels are claims"
        self.assertEqual(self.section[start + 1:start + 6], [
            "    @sol_engineer: 0.88% of supply, unrealized -71.9%, sold 0%" + tail,
            "    @Loopierr (GMGN kol tag): 0.48% of supply, unrealized -52.7%, sold 0%" + tail,
            "    @CookerFlips (GMGN kol tag): 0.48% of supply, unrealized -74.7%, sold 0%" + tail,
            "    @FundamentumG: 0.43% of supply, unrealized -4.1%, sold 0%" + tail,
            "    @Cryptofuture200: 0.19% of supply, unrealized -53.9%, sold 22%" + tail])
        self.assertFalse([ln for ln in self.section if "@frankdegods" in ln], "a watchlist match is not repeated as named")

    def test_the_fomo_app_count_equals_the_fixture(self):
        """Criterion 4: the exact number of non-pool rows GMGN tags fomo in the fixture (no pool carries the tag)."""
        rows = [r for r in ymb_raw_rows() if r["addr_type"] != 2]
        fomo = [r for r in rows if "fomo" in r["tags"]]
        red = [r for r in fomo if r["unrealized_pnl"] is not None and r["unrealized_pnl"] < 0]
        self.assertEqual((len(rows), len(fomo), len(red)), (96, 42, 41))
        expected = (f"  Fomo app: GMGN tags 42 of the 96 non-pool holders in its top 100 as trading through the Fomo app: "
                    f"{sum(r['amount_percentage'] for r in fomo) * 100:.2f}% of supply, 41 in the red ({sum(r['amount_percentage'] for r in red) * 100:.2f}% of supply). "
                    "Copy-trading runs on that app; this does not show which of them copy whom.")
        self.assertIn(expected, self.section)
        self.assertIn("19.12% of supply, 41 in the red (18.85% of supply)", expected)
        self.assertFalse([r for r in ymb_raw_rows() if r["address"] in POOLS and "fomo" in r["tags"]])

    def test_under_the_bar_cannot_see_and_watchlist_lines(self):
        self.assertIn("  under the 0.1% bar: 0 more watchlist traders hold under 0.1% of supply, not listed", self.section)
        watch = next(ln for ln in self.section if ln.startswith("  watchlist: "))
        for needle in ("references/fomo_cascade_watchlist.json, 20 traders as of 2026-10-24", "static and dated", "not proof", YMB_WHEN,
                       "96 wallets after removing pools", "(11 of 20 entries have one, 2 of them through a name-only Fomo account: heat, TJR)",
                       "never a display name or part of a handle"):
            self.assertIn(needle, watch)
        cannot = next(ln for ln in self.section if ln.startswith("  this section cannot see: "))
        for needle in ("holders outside GMGN's top 100 (45.74% of supply)", "a wallet other than the Fomo main wallet and without an X handle on GMGN",
                       "(Fomo-verified main wallet: 11 of 20 entries have one, 2 of them through a name-only Fomo account: heat, TJR; "
                       "no Fomo match for theunipcs, rasmr_eth, blknoiz06)",f"sells after GMGN's snapshot ({YMB_WHEN}): a sell seconds later is not in these rows",
                       "traders not on the watchlist (as of 2026-10-24; static, refreshed only when the owner asks)"):
            self.assertIn(needle, cannot)

    def test_no_verdict_word_and_no_reassurance(self):
        for line in self.section:
            self.assertEqual(gr.neutralize(line)[1], 0, line)
            self.assertIsNone(VERDICT_RE.search(line), line)
            self.assertNotIn(NOT_PROOF, line.lower())


class MatchingRuleTests(unittest.TestCase):
    """Criterion 2 and the identity-strength rule."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def risk_lines(self, lines):
        return [ln for ln in lines if ln.startswith("    Copy-trade cascade risk: ")]

    def test_handles_match_whole_any_case_with_the_at_sign_stripped(self):
        rows = [wallet(0, twitter_username="frankdegods"), wallet(1, twitter_username="@Quanterty"), wallet(2, twitter_username="BREZ_FOMO")]
        entries = [entry("@FrankDeGods", tier="owner"), entry("QUANTERTY"), entry("brezscales", handle="brez_fomo")]
        lines = section(self.tmp, rows, entries)
        risk = self.risk_lines(lines)
        self.assertEqual(len(risk), 3, text_of(lines))
        for shown in ("FrankDeGods", "QUANTERTY", "brezscales"):
            self.assertTrue(any(f"risk: {shown} (" in ln and "matched by GMGN handle" in ln for ln in risk), shown)
        saved = json.loads((self.tmp / gr.PNL_FILE).read_text())
        self.assertEqual(saved["rows"][1]["twitter_username"], "Quanterty", "GMGN's @ is dropped when the label is saved")

    def test_no_match_on_part_of_a_handle_or_a_display_name(self):
        rows = [wallet(0, twitter_username="frankdegods_alt"), wallet(1, twitter_username="xfrankdegods"), wallet(2, twitter_username="frank"),
                wallet(3, name="frankdegods", twitter_name="frankdegods"), wallet(4, twitter_username="frank degods"),
                wallet(5, twitter_username="theunipics")]
        entries = [entry("frankdegods", tier="owner"), entry("degods"),
                   entry("theunipcs", fomo_status="ambiguous", candidates=["theunipics"])]
        lines = section(self.tmp, rows, entries)
        self.assertEqual(self.risk_lines(lines), [], text_of(lines))
        self.assertIn(f"  no watchlist trader seen among GMGN's top 100 at {SYNTH_TIME}", lines)
        self.assertNotIn("[for the executive summary]", text_of(lines), "no summary line without a match")
        named = text_of(lines)
        for handle in ("@frankdegods_alt", "@xfrankdegods", "@frank:", "@theunipics"):
            self.assertIn(handle, named, "unmatched handles are named, not on the watchlist")

    def test_wallet_match_alone(self):
        lines = section(self.tmp, [wallet(0), wallet(1, twitter_username="someone_else")],
                        [entry("pointfarmcap", wallet_address=synthetic_address(1), followers=445981)])
        risk = self.risk_lines(lines)
        self.assertEqual(len(risk), 1)
        self.assertIn("risk: pointfarmcap (tier 1; Fomo followers 445,981 verified 2026-10-24) holds 1.00% of supply ($10k), unrealized -50.0%, sold 0%, "
                      "matched by wallet; " + RED, risk[0])
        self.assertNotIn("@someone_else", text_of(lines), "a wallet match is not repeated as named")

    def test_a_fomo_status_other_than_matched_never_supplies_a_wallet_or_followers(self):
        rows = [wallet(0), wallet(1, twitter_username="blknoiz06")]
        entries = [entry("ansem_alt", fomo_status="ambiguous", handle="ansem_alt_fomo", wallet_address=synthetic_address(0), followers=999_999),
                   entry("blknoiz06", fomo_status="not_found", wallet_address=synthetic_address(0), followers=777_777, self_reported=12_000)]
        lines = section(self.tmp, rows, entries)
        risk = self.risk_lines(lines)
        self.assertEqual(len(risk), 1, text_of(lines))
        self.assertIn("risk: blknoiz06 (tier 1; Fomo followers self-reported 12,000) holds 1.00% of supply", risk[0])
        self.assertIn("matched by GMGN handle", risk[0])
        self.assertNotIn("matched by wallet", text_of(lines))
        for number in ("999,999", "777,777"):
            self.assertNotIn(number, text_of(lines))
        self.assertIn("no Fomo match for ansem_alt, blknoiz06", text_of(lines))
        lines = section(self.tmp / "b", [wallet(0, twitter_username="ansem_alt_fomo")], entries[:1])
        self.assertEqual(self.risk_lines(lines), [], "an unmatched Fomo result's handle is never a match key")

    def test_an_unconfirmed_x_handle_prints_the_name_only_note(self):
        rows = [wallet(0, amount_percentage=0.004, unrealized_pnl=-0.3), wallet(1, amount_percentage=0.002, twitter_username="Banks", unrealized_pnl=0.2)]
        entries = [entry("TJR", x_status="unconfirmed", handle="tjr", wallet_address=synthetic_address(0)),
                   entry("Banks", tier="tier2", x_status="unconfirmed", handle="banks"),
                   entry("cosby", tier="tier2", handle="cosby", followers=63372)]
        lines = section(self.tmp, rows, entries)
        risk = self.risk_lines(lines)
        self.assertEqual(len(risk), 2, text_of(lines))
        self.assertEqual(risk[0], "    Copy-trade cascade risk: TJR (tier 1; Fomo followers unknown) holds 0.40% of supply ($10k), unrealized -30.0%, sold 0%, "
                                  "matched by wallet (name-only match: the Fomo account tjr is not confirmed to be the trader in the research); " + RED)
        self.assertEqual(risk[1], "    Copy-trade cascade risk: Banks (tier 2; Fomo followers unknown) holds 0.20% of supply ($10k), unrealized +20.0%, sold 0%, "
                                  "matched by GMGN handle (name-only match: the Fomo account banks is not confirmed to be the trader in the research)")
        self.assertEqual(lines[0], "[for the executive summary] Copy-trade cascade risk (presentation only): TJR 0.40% (-30%, name-only match), "
                                   "Banks 0.20% (+20%, name-only match)")

    def test_an_x_handle_status_that_is_not_as_in_report_counts_as_name_only(self):
        listed = entry("heat", handle="heat")
        listed.pop("x_handle_status")
        lines = section(self.tmp, [wallet(0, twitter_username="heat")], [listed])
        self.assertIn("(name-only match: the Fomo account heat is not confirmed to be the trader in the research)", text_of(lines))
        lines = section(self.tmp / "b", [wallet(0, twitter_username="heat")], [entry("heat", x_status="unconfirmed", fomo_status="not_found")])
        self.assertIn("(name-only match: the handle heat is not confirmed to be the trader in the research)", text_of(lines))


class BarAndOrderTests(unittest.TestCase):
    """Criterion 3: the 0.1% bar on watchlist and named lines; the under-bar count (a 0.05% match); share order."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_005_percent_match_is_counted_not_listed(self):
        rows = [wallet(0, amount_percentage=0.0005, twitter_username="orangie"), wallet(1, amount_percentage=0.0005, twitter_username="not_listed_kol"),
                wallet(2, amount_percentage=0.0005, tags=["kol"])]
        lines = section(self.tmp, rows, [entry("orangie", tier="owner", followers=210098)])
        text = text_of(lines)
        self.assertNotIn("Copy-trade cascade risk: orangie", text)
        self.assertNotIn("[for the executive summary]", text)
        self.assertIn(f"  no watchlist trader at 0.1% of supply or more among GMGN's top 100 at {SYNTH_TIME}", lines)
        self.assertIn("  under the 0.1% bar: 1 more watchlist trader holds under 0.1% of supply, not listed", lines)
        self.assertIn("  named by GMGN, not on the watchlist (an X handle or GMGN's kol tag), at 0.1% of supply or more: 0; "
                      "2 more under 0.1% of supply or without a share, not listed", lines)
        self.assertNotIn("@not_listed_kol", text)

    def test_the_bar_is_inclusive_and_shares_without_a_value_are_counted(self):
        rows = [wallet(0, amount_percentage=0.001, twitter_username="cosby"), wallet(1, amount_percentage=0.000999, twitter_username="jpegkite"),
                wallet(2, amount_percentage=None, twitter_username="travladd")]
        lines = section(self.tmp, rows, [entry("cosby", tier="tier2"), entry("jpegkite", tier="tier2"), entry("travladd", tier="tier2")])
        risk = [ln for ln in lines if ln.startswith("    Copy-trade cascade risk: ")]
        self.assertEqual(len(risk), 1)
        self.assertIn("risk: cosby (tier 2; Fomo followers unknown) holds 0.10% of supply", risk[0])
        self.assertIn("  under the 0.1% bar: 1 more watchlist trader holds under 0.1% of supply, not listed; 1 more without a share from GMGN, not listed", lines)

    def test_sorted_by_share_and_the_red_phrase_only_when_negative(self):
        rows = [wallet(0, amount_percentage=0.002, twitter_username="cosby", unrealized_pnl=0.0), wallet(1, amount_percentage=0.005, twitter_username="orangie"),
                wallet(2, amount_percentage=0.003, twitter_username="jelitics", unrealized_pnl=None, avg_cost=None)]
        lines = section(self.tmp, rows, [entry("cosby", tier="tier2"), entry("orangie", tier="owner"), entry("Jelitics", tier="tier2", handle="jelitics")])
        risk = [ln for ln in lines if ln.startswith("    Copy-trade cascade risk: ")]
        self.assertEqual([ln.split()[3] for ln in risk], ["orangie", "Jelitics", "cosby"])
        self.assertTrue(risk[0].endswith(RED))
        self.assertIn("unrealized PnL not given by GMGN", risk[1])
        self.assertIn("unrealized +0.0%", risk[2])
        for ln in risk[1:]:
            self.assertNotIn("in the red", ln)
        self.assertEqual(lines[0], "[for the executive summary] Copy-trade cascade risk (presentation only): orangie 0.50% (-50%), Jelitics 0.30% (PnL not given), "
                                   "cosby 0.20% (+0%)")


class PoolTests(unittest.TestCase):
    """Criterion 4: pools (addr_type 2) are out of every match and count."""

    def test_a_pool_never_matches_and_never_counts(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            rows = [wallet(0, addr_type=2, exchange="pump_amm", twitter_username="frankdegods", tags=["fomo", "kol"], amount_percentage=0.05),
                    wallet(1, tags=["fomo"]), wallet(2, twitter_username="sol_engineer")]
            lines = section(tmp, rows, [entry("frankdegods", tier="owner", wallet_address=synthetic_address(0))])
            text = text_of(lines)
            self.assertNotIn("Copy-trade cascade risk: frankdegods", text)
            self.assertIn(f"  no watchlist trader seen among GMGN's top 100 at {SYNTH_TIME}", lines)
            self.assertIn("  named by GMGN, not on the watchlist (an X handle or GMGN's kol tag), at 0.1% of supply or more: 1", lines)
            self.assertIn("GMGN tags 1 of the 2 non-pool holders in its top 100 as trading through the Fomo app: 1.00% of supply, 1 in the red (1.00% of supply)", text)
            self.assertIn("(2 wallets after removing pools)", text)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class NotReadTests(unittest.TestCase):
    """Criterion 5: a missing or malformed watchlist or gmgn_holder_pnl.json reads not read with the reason, exit 0."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def expect(self, lines, reason):
        self.assertEqual(lines, [f"[for the executive summary] Copy-trade cascade risk (presentation only): not read ({reason})",
                                 f"Copy-trade cascade (presentation only): not read ({reason})"])
        self.assertNotIn(NOT_PROOF, text_of(lines).lower())

    def test_the_watchlist_missing_or_malformed(self):
        collect_main(self.tmp, ymb_payload())
        wl = self.tmp / "wl.json"
        self.expect(gr.cascade_present(self.tmp, self.tmp / "absent.json"), "fomo_cascade_watchlist.json missing")
        for text in ("{not json", "", "[]", "null", json.dumps({"schema": "other/1", "entries": []}), json.dumps({"schema": gr.WATCHLIST_SCHEMA, "entries": "x"}),
                     json.dumps({"schema": gr.WATCHLIST_SCHEMA})):
            with self.subTest(text=text[:30]):
                wl.write_text(text)
                self.expect(gr.cascade_present(self.tmp, wl), "fomo_cascade_watchlist.json unreadable")
        write_watchlist(wl, [None, 5, {"x_handle": ""}, {"tier": "owner"}])
        self.expect(gr.cascade_present(self.tmp, wl), "fomo_cascade_watchlist.json holds no readable entry")
        self.expect(gr.cascade_present(self.tmp, self.tmp), "fomo_cascade_watchlist.json unreadable")

    def test_a_partly_damaged_watchlist_still_reads_and_says_so(self):
        collect_main(self.tmp, ymb_payload())
        good = json.loads(WATCHLIST.read_text())
        good["entries"] += [None, {"x_handle": 7}]
        good["entries"][0]["fomo"]["followers"] = True     # a bool is not a follower count
        good["as_of"] = "24 Oct"
        lines = gr.cascade_present(self.tmp, write_watchlist(self.tmp / "wl.json", good["entries"], as_of="24 Oct"))
        text = text_of(lines)
        self.assertIn("20 traders as of an unknown date (2 unreadable entries skipped)", text)
        self.assertIn("Copy-trade cascade risk: frankdegods (owner-named; Fomo followers unknown) holds 0.39% of supply", text)

    def test_the_pnl_file_missing_not_ok_or_a_field_renamed(self):
        self.expect(gr.cascade_present(self.tmp), "gmgn_holder_pnl.json missing")
        with mock.patch.object(gr, "find_env_file", return_value=None):
            collect_main(self.tmp / "nokey", answers=[], mint=CAPE, now=NOW, env={})
        self.expect(gr.cascade_present(self.tmp / "nokey"), "GMGN unavailable: missing_key")
        for field, new in (("unrealized_pnl", "unrealised_pnl"), ("addr_type", "address_type"), ("amount_percentage", "share")):
            with self.subTest(field):
                payload = ymb_payload()
                for row in payload["data"]["list"]:
                    row[new] = row.pop(field)
                collect_main(self.tmp / field, payload)
                self.expect(gr.cascade_present(self.tmp / field), f"field missing: {field}")
        (self.tmp / "foreign").mkdir()
        (self.tmp / "foreign" / gr.PNL_FILE).write_text('{"rows": []}')
        self.expect(gr.cascade_present(self.tmp / "foreign"), "gmgn_holder_pnl.json unreadable")

    def test_gmgn_handles_renamed_matches_by_wallet_only(self):
        payload = ymb_payload()
        for row in payload["data"]["list"]:
            row["x_handle"] = row.pop("twitter_username")
        collect_main(self.tmp, payload)
        lines = gr.cascade_present(self.tmp)
        text = text_of(lines)
        self.assertIn("  GMGN's X handles: not read (field missing: twitter_username); matching by wallet only, and the named list below shows kol-tagged holders only", lines)
        self.assertIn("risk: frankdegods (owner-named; Fomo followers 354,795 verified 2026-10-24) holds 0.39% of supply ($2.17k), unrealized -56.0%, sold 0%, "
                      "matched by wallet; " + RED, text)
        self.assertIn("at 0.1% of supply or more: 2", text)
        self.assertEqual(text.count("    kol tag, no handle: "), 2)

    def test_the_cli_exits_0_with_a_missing_watchlist_and_damaged_values(self):
        collect_main(self.tmp, ymb_payload())
        with mock.patch.object(gr, "WATCHLIST_FILE", self.tmp / "absent.json"):
            code, out, err = present_main(["--present", str(self.tmp)])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out.splitlines()[-2:], ["[for the executive summary] Copy-trade cascade risk (presentation only): not read (fomo_cascade_watchlist.json missing)",
                                                 "Copy-trade cascade (presentation only): not read (fomo_cascade_watchlist.json missing)"])
        path = self.tmp / gr.PNL_FILE
        data = json.loads(path.read_text())
        for r in data["rows"]:
            r.update(amount_percentage=float("nan"), unrealized_pnl="x", twitter_username=5, app_tags="fomo", usd_value=float("inf"), addr_type=True)
        path.write_text(json.dumps(data))
        code, out, err = present_main(["--present", str(self.tmp)])
        self.assertEqual((code, err), (0, ""))
        section_lines = out.split("Copy-trade cascade (presentation only)", 1)[1].splitlines()
        self.assertIn("  no watchlist trader at 0.1% of supply or more among GMGN's top 100 at " + YMB_WHEN, section_lines)
        self.assertIn("  under the 0.1% bar: 0 more watchlist traders hold under 0.1% of supply, not listed; 1 more without a share from GMGN, not listed", section_lines)
        for line in out.splitlines():
            self.assertIsNone(re.search(r"(?i)\bnan\b|\binf\b|infinity|traceback", line), line)

    def test_unexpected_values_read_as_not_read_never_a_crash(self):
        collect_main(self.tmp, ymb_payload())
        with mock.patch.object(gr, "_watch_entry", side_effect=RuntimeError("boom")):
            self.expect(gr.cascade_present(self.tmp), "gmgn_holder_pnl.json or fomo_cascade_watchlist.json values unreadable")


class WordingAndLabelTests(unittest.TestCase):
    """Criterion 6: watchlist and GMGN handles are inert labels (verdict words replaced, markup dropped, key echoes dropped);
    no verdict word in any printed line; an empty match is never 'no cascade risk'."""

    KEY = "gmgnK3y-7f3a9c41e2b8d6aa01b2c3d4e5f6a7b8"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_adversarial_labels_are_inert_and_counted(self):
        key = self.KEY
        rows = [wallet(0, twitter_username="no_alarm", amount_percentage=0.004),
                wallet(1, twitter_username=key[:14], amount_percentage=0.003),           # echoes the GMGN key: dropped at collect time
                wallet(2, twitter_username="Safe", amount_percentage=0.002),
                wallet(3, amount_percentage=0.002)]
        entries = [entry("Safe", tier="SAFE"),                                          # a verdict word: shown as the placeholder, never a match key
                   entry("[click](https://evil.example)", handle="<b>low</b>", wallet_address=synthetic_address(3), x_status="unconfirmed"),
                   entry("rug free", fomo_status="ambiguous")]
        lines = section(self.tmp, rows, entries, key=key)
        text = text_of(lines)
        for i in range(len(key) - gr.KEY_PIECE + 1):
            self.assertNotIn(key[i:i + gr.KEY_PIECE], text)
        self.assertNotIn("Copy-trade cascade risk: [provider word removed] (", text, "a placeholder never matches a placeholder")
        risk = [ln for ln in lines if ln.startswith("    Copy-trade cascade risk: ")]
        self.assertEqual(len(risk), 1, text)
        self.assertIn("risk: click (tier 1; Fomo followers unknown) holds 0.20% of supply", risk[0])
        self.assertIn("(name-only match: the Fomo account [provider word removed] is not confirmed to be the trader in the research)", risk[0])
        for share in ("0.40%", "0.20%"):
            self.assertTrue(any(ln.startswith(f"    @[provider word removed]: {share} of supply") for ln in lines), share)
        self.assertIn("no Fomo match for [provider word removed]", text)
        for line in lines:
            self.assertNotIn("](", line)
            self.assertNotIn("<", line)
        self.assertEqual(lines[-1], "  " + pw.removed_line(pw.count(lines[:-1])))
        self.assertGreater(pw.count(lines[:-1]), 0)
        for line in lines:
            self.assertEqual(gr.neutralize(line)[1], 0, line)
            self.assertIsNone(VERDICT_RE.search(PLACEHOLDER_RE.sub(" ", line.replace(pw.removed_line(pw.count(lines[:-1])), ""))), line)

    def test_no_verdict_word_in_any_case(self):
        cases = {"empty": ([wallet(0)], [entry("orangie")]), "under": ([wallet(0, amount_percentage=0.0001, twitter_username="orangie")], [entry("orangie")]),
                 "green": ([wallet(0, twitter_username="orangie", unrealized_pnl=0.4)], [entry("orangie", followers=1)])}
        for name, (rows, entries) in cases.items():
            with self.subTest(name):
                lines = section(self.tmp / name, rows, entries)
                for line in lines:
                    self.assertEqual(gr.neutralize(line)[1], 0, line)
                    self.assertIsNone(VERDICT_RE.search(line), line)
                    self.assertNotIn(NOT_PROOF, line.lower())
        self.assertIsNone(VERDICT_RE.search(gr.CASCADE_RED + gr.CASCADE_TITLE + gr.CASCADE_SUMMARY_HEAD))


class IsolationTests(unittest.TestCase):
    """Criterion 7: the section writes nothing, opens no connection and reads no key; assess gives the same bytes with and
    without the section (and the watchlist file) in the run folder; neither engine names either file."""

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

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def assess(self, name):
        out = self.tmp / name
        gmgn = ["--bubblemaps-json", str(self.map_file), "--gmgn-holders-json", str(self.run_dir / gr.TOP100_FILE),
                "--acquisition-json", str(self.run_dir / gr.ACQUISITION_FILE)]
        code, _, err = run_assess(CAPE, self.run_dir, gmgn, out=out)
        self.assertEqual(code, 0, err)
        return (out / "assessment.json").read_bytes(), (out / "report.md").read_bytes()

    def test_the_section_writes_nothing_and_reads_no_key(self):
        before = {p.name: sha(p) for p in self.run_dir.iterdir() if p.is_file()}
        watch = sha(WATCHLIST)
        code, out, err = present_main(["--present", str(self.run_dir)])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("Copy-trade cascade (presentation only)", out)
        self.assertEqual({p.name: sha(p) for p in self.run_dir.iterdir() if p.is_file()}, before)
        self.assertEqual(sha(WATCHLIST), watch)

    def test_assess_is_byte_identical_with_and_without_the_section(self):
        without = self.assess("without")
        shutil.copyfile(WATCHLIST, self.run_dir / gr.WATCHLIST_NAME)
        try:
            present_main(["--present", str(self.run_dir)])
            with_section = self.assess("with")
        finally:
            (self.run_dir / gr.WATCHLIST_NAME).unlink()
        self.assertEqual(with_section, without, "byte-identical assessment.json and report.md")
        flag = json.loads(with_section[0])
        self.assertEqual((flag["flag"], flag["verdict"]), (json.loads(without[0])["flag"], json.loads(without[0])["verdict"]))

    def test_neither_engine_reads_the_watchlist_or_the_pnl_file(self):
        for path in [SCRIPTS / "helius_forensics.py", SCRIPTS / "holder_analysis.py", *sorted((SCRIPTS / "ha").glob("*.py"))]:
            text = path.read_text(encoding="utf-8")
            for needle in ("fomo_cascade_watchlist", "watchlist", "gmgn_holder_pnl"):
                self.assertNotIn(needle, text, path.name)
        synth = next(e for e in json.loads((SKILL / "collectors.json").read_text())["entries"] if e["id"] == "synthesis")
        self.assertNotIn("watchlist", json.dumps(synth["input_flags"]))
        self.assertNotIn("watchlist", synth["command"])


class RepairR1Tests(unittest.TestCase):
    """Repair R1 (Verifier round 1): F1 the Fomo-app in-the-red count at exactly 0% PnL (0 is not in the red); F3 the
    wallet count says how many verified wallets came with a name-only Fomo account, computed from x_handle_status."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_fomo_wallet_at_exactly_0_percent_is_not_in_the_red(self):
        rows = [wallet(0, tags=["fomo"], unrealized_pnl=0), wallet(1, tags=["fomo"], unrealized_pnl=0.0),
                wallet(2, tags=["fomo"], unrealized_pnl=-0.1, amount_percentage=0.02), wallet(3, tags=["fomo"], unrealized_pnl=None, avg_cost=None),
                wallet(4, unrealized_pnl=-0.3)]
        lines = section(self.tmp, rows, [entry("orangie")])
        saved = json.loads((self.tmp / gr.PNL_FILE).read_text())
        self.assertEqual([r["unrealized_pnl"] for r in saved["rows"][:2]], [0.0, 0.0])
        self.assertIn("  Fomo app: GMGN tags 4 of the 5 non-pool holders in its top 100 as trading through the Fomo app: 5.00% of supply, "
                      "1 in the red (2.00% of supply). Copy-trading runs on that app; this does not show which of them copy whom.", lines)

    def test_the_name_only_wallet_count_comes_from_the_x_handle_status(self):
        no_status = entry("Banks", tier="tier2", handle="banks", wallet_address=synthetic_address(12))
        no_status.pop("x_handle_status")
        entries = [entry("cosby", wallet_address=synthetic_address(10)), entry("TJR", x_status="unconfirmed", handle="tjr", wallet_address=synthetic_address(11)),
                   no_status, entry("heat", x_status="unconfirmed", handle="heat"),                       # name-only, but no wallet: not counted
                   entry("theunipcs", x_status="unconfirmed", fomo_status="ambiguous", wallet_address=synthetic_address(13))]  # not matched: no wallet
        lines = section(self.tmp, [wallet(0)], entries)
        note = "3 of 5 entries have one, 2 of them through a name-only Fomo account: TJR, Banks"
        self.assertIn(f"by the Fomo-verified main wallet ({note}) or GMGN's X handle", lines[1])
        self.assertIn(f"(Fomo-verified main wallet: {note}; no Fomo match for theunipcs)", text_of(lines))
        lines = section(self.tmp / "b", [wallet(0)], [entry("cosby", wallet_address=synthetic_address(10)), entry("orangie")])
        self.assertIn("by the Fomo-verified main wallet (1 of 2 entries have one) or GMGN's X handle", lines[1])
        self.assertIn("(Fomo-verified main wallet: 1 of 2 entries have one); sells after", text_of(lines))
        self.assertNotIn("name-only", text_of(lines))


class RepairR2Tests(unittest.TestCase):
    """Repair R2 (R2-2): the Fomo-app line follows the A1 rule. When Fomo-tagged non-pool wallets exist but none has a usable
    PnL, its in-the-red part reads not read, never "0 in the red (0.00% of supply)"; the count and share stay. A real 0% is a
    usable value, and with no Fomo-tagged wallet at all "0 in the red" is a real count of none."""

    TAIL = ". Copy-trading runs on that app; this does not show which of them copy whom."

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fomo_line(self, rows, name):
        lines = section(self.tmp / name, rows, [entry("orangie")])
        return next(ln for ln in lines if ln.startswith("  Fomo app: "))

    def test_fomo_wallets_without_a_usable_pnl_read_not_read(self):
        rows = [wallet(0, tags=["fomo"], unrealized_pnl=None, avg_cost=None), wallet(1, tags=["fomo"], unrealized_pnl="-0.4", amount_percentage=0.02),
                wallet(2, unrealized_pnl=-0.5), wallet(3, addr_type=2, exchange="pump_amm", tags=["fomo"], unrealized_pnl=-0.3)]
        line = self.fomo_line(rows, "none-usable")
        self.assertEqual(line, "  Fomo app: GMGN tags 2 of the 3 non-pool holders in its top 100 as trading through the Fomo app: 3.00% of supply, "
                               "in the red: not read (no usable PnL)" + self.TAIL)
        self.assertNotIn("0 in the red", line)

    def test_a_usable_value_or_no_fomo_wallet_keeps_the_count(self):
        line = self.fomo_line([wallet(0, tags=["fomo"], unrealized_pnl=0.0), wallet(1, tags=["fomo"], unrealized_pnl=None)], "zero")
        self.assertEqual(line, "  Fomo app: GMGN tags 2 of the 2 non-pool holders in its top 100 as trading through the Fomo app: 2.00% of supply, "
                               "0 in the red (0.00% of supply)" + self.TAIL)
        line = self.fomo_line([wallet(0, unrealized_pnl=None), wallet(1)], "no-fomo")
        self.assertEqual(line, "  Fomo app: GMGN tags 0 of the 2 non-pool holders in its top 100 as trading through the Fomo app: 0.00% of supply, "
                               "0 in the red (0.00% of supply)" + self.TAIL)


class SkillTextTests(unittest.TestCase):
    """SKILL.md: the synthesis copies the section and its summary line as printed, right after the FLAG lines; presentation
    only; the watchlist is static and dated."""

    def test_the_synthesis_step_names_the_section_and_its_summary_line(self):
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        synth = text.split("## Synthesis (top tier): `SUMMARY.md`", 1)[1].split("\n## ", 1)[0]
        for needle in ("Copy-trade cascade risk (presentation only)", "Copy-trade cascade (presentation only)", "right after the FLAG lines",
                       "exactly as printed", "never \"no cascade risk\"", "static and dated", "references/fomo_cascade_watchlist.json",
                       "never an engine input", "never counted toward NO_ALARM", "never passed to `assess`", "0.1% of supply"):
            self.assertIn(needle, synth, needle)
        gmgn = text.split("## Collector `gmgn_rows`", 1)[1].split("\n## ", 1)[0]
        self.assertIn("Copy-trade cascade (presentation only)", gmgn)


if __name__ == "__main__":
    unittest.main()
