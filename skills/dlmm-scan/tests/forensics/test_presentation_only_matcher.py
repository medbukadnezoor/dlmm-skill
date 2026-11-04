"""HS-PROV-T2 criterion 7 (carried from HS-PROV-T1 R6): the forensics engine's presentation-only name matcher, hardened.

`helius_forensics.presentation_only_provider` refuses Solana Tracker, MadeOnSol and Fomo API names in --providers-json.
HS-PROV-T1 matched case, spaces and punctuation insensitively; the Verifier's bypass list (look-alike letters, full-width
and accented forms, abbreviations) slipped past. Now the name is folded first (compatibility forms as in NFKC, accents
and invisible format characters dropped, Cyrillic / Greek / small-capital / Latin look-alikes mapped to Latin; a second pass reads digits and
signs used as letters, a capital I used as l and "rn" used as m), aliases ("Sol Tracker", "Solana Track") count anywhere
in the name, and the bare abbreviations ST and MOS only as the whole name. The no-false-refusal list stays accepted.
Input acceptance only: no threshold, verdict or flag rule changes."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
from test_assess import _map, _run, case_negative_space_inu, run_assess  # noqa: E402

# The Verifier's bypass list from HS-PROV-T1 (Cyrillic, full-width, accented, abbreviated), grouped, plus the other cheap
# look-alike tricks the folding covers. Each must be refused with the right provider label.
BYPASS = {
    "Solana Tracker": [
        "\u0405\u043el\u0430n\u0430 \u0422r\u0430\u0441k\u0435r",            # Cyrillic S, o, a, a, T, a, c, e
        "S\u043elana Tracker",                                                # one Cyrillic o
        "\uff33\uff4f\uff4c\uff41\uff4e\uff41 \uff34\uff52\uff41\uff43\uff4b\uff45\uff52",  # full-width
        "S\u00f3l\u00e1na Tr\u00e2cker", "So\u0301lana Tracker",             # accented, precomposed and combining
        "S\u03bflana \u03a4racker",      # Greek omicron and Tau
        "\u1d0f" + "Solana Tracker",                                         # a small-capital prefix does not hide it
        "\ua731\u1d0f\u029f\u1d00\u0274\u1d00 \u1d1b\u0280\u1d00\u1d04\u1d0b\u1d07\u0280",  # small capitals
        "\U0001d412\U0001d428\U0001d425\U0001d41a\U0001d427\U0001d41a Tracker",  # mathematical bold
        "\u24c8\u24de\u24db\u24d0\u24dd\u24d0 \u24c9\u24e1\u24d0\u24d2\u24da\u24d4\u24e1",  # circled letters
        "Solana\u200bTracker", "Solana\u00adTracker", "Sol\u200dana Tra\u2060cker",  # zero-width and soft hyphen
        "S0lana Tracker", "$olana Tracker", "So1ana Tracker", "SoIana Tracker", "So|ana Tracker",
        "Sol Tracker", "SolTracker", "sol-trackr", "Solana Trackr", "Solana Track (bundlers)", "SOL_TRACKER v2",
        "ST", "S.T.", "s t", "5T", "\uff33\uff34",                            # the bare abbreviation, as the whole name
        "ST bundles", "Solana ST", "st-bundles", "(ST)", "ST/bundlers", "S.T. bundles", "5T bundles",  # ... or as a separate word (N1)
        "Solanna Tracker", "Sollana Trackker", "Soll Trackker", "SOLANA TRACKERR",                   # repeated letters collapsed (N1)
    ],
    "MadeOnSol": [
        "\u041cade\u041enSol", "M\u0430de\u041en\u0405ol",                    # Cyrillic M, O, S, a
        "\u039cade\u03bfns\u03bfl",                                           # Greek Mu and omicron
        "\uff2d\uff41\uff44\uff45\uff2f\uff4e\uff33\uff4f\uff4c",            # full-width
        "M\u00e1d\u00e9 \u00d3n S\u00f6l", "Made On Sol", "made-on-sol", "MadeOnSolana", "Made0nS0l", "rnadeonsol", "r\u200bnadeonsol", "r n a d e o n s o l", "MadeOnSoI",
        "\u1d0d\u1d00\u1d05\u1d07\u1d0f\u0274\ua731\u1d0f\u029f",            # small capitals
        "MOS", "M.O.S.", "m0s", "\uff2d\uff2f\uff33",                        # the bare abbreviation, as the whole name
        "MOS cluster", "M.O.S. holders", "bundles (MOS)",                                             # ... or as a separate word (N1)
        "Maddeonsol", "Made Onn Sol", "MMadeOnSoll",                                                 # repeated letters collapsed (N1)
    ],
    "Fomo API": [
        "F\u043emo API", "F\u03bfm\u03bf", "\uff26\uff4f\uff4d\uff4f \uff21\uff30\uff29", "F\u014cM\u014c", "Fo\u0301mo API", "F0M0 API", "f0mo",
        "\U0001d405\U0001d428\U0001d426\U0001d428", "\ua730\u1d0f\u1d0d\u1d0f", "\u0192omo", "\u0191OMO", "Fo\u200bmo", "fomo.family", "FOMO API (tracked traders)", "Fommo", "FFOMO API", "Foomoo",
    ],
}

# Real provider names that must stay accepted (no false refusal): the Verifier's list plus look-alike-prone real names.
ACCEPTED = ["okx", "insightx", "cabalspy", "gmgn", "bubblemaps", "arkham", "GetXAPI", "Alchemy", "jupiter", "lp_research_scan", "RugCheck", "Birdeye", "DexScreener",
            "Solscan", "SolanaFM", "Tracker Bot", "Solana Beach",
            "OKX Web3", "InsightX (free)", "Bubblemaps API", "GMGN.ai", "Birdeye v2", "Jupiter datapi", "Helius", "Photon", "BullX", "Axiom", "Nansen", "Cielo",
            "Step Finance", "stats", "Stream", "Mosaic", "Cosmos", "Most", "Mostly", "STR", "MOSS", "Step", "Stats", "Moss", "Mossy", "1st place",
            "Main Street", "Mosquito", "Assist", "Mississippi", "Steam", "Moonshot", "Pump.fun stats", "Top 100", "x402", "Pump.fun",
            "SolSniffer", "TrenchBot", "Soul Scanner", "Stalkchain", "Moralis", "Shyft", "Solana Explorer", "Tracker", "Sol Incinerator", "Trackoor"]


class MatcherTests(unittest.TestCase):
    def test_the_pinned_tokens_are_unchanged(self):
        self.assertEqual(hf.PRESENTATION_ONLY_PROVIDERS, {"solanatracker": "Solana Tracker", "madeonsol": "MadeOnSol", "fomo": "Fomo API"})
        self.assertEqual(hf.PRESENTATION_ONLY_ALIASES, {"soltrack": "Solana Tracker", "solanatrack": "Solana Tracker"})
        self.assertEqual(hf.PRESENTATION_ONLY_ABBREVIATIONS, {"st": "Solana Tracker", "mos": "MadeOnSol"})

    def test_the_verifier_bypass_list_is_refused(self):
        for label, names in BYPASS.items():
            for name in names:
                with self.subTest(name=ascii(name)):
                    self.assertEqual(hf.presentation_only_provider(name), label)
                    with self.assertRaises(hf.ConfigError) as ctx:
                        hf.normalize_findings_file({"unit": "percent", "providers": [{"provider": name, "status": "ok", "largest_cluster_pct": 0.0}]})
                    self.assertIn(f"cannot supply {label}: it is a presentation-only provider", str(ctx.exception))

    def test_the_bypass_list_slipped_past_the_old_matcher(self):
        """Control: the HS-PROV-T1 matcher (casefold, letters and digits only) missed most of these, which is why they are
        tested here at all."""
        import re

        def old(name):
            key = re.sub(r"[^0-9a-z]", "", name.casefold())
            return next((label for token, label in hf.PRESENTATION_ONLY_PROVIDERS.items() if token in key), None)

        missed = [n for names in BYPASS.values() for n in names if old(n) is None]
        self.assertGreaterEqual(len(missed), 40)
        for name in ("\u0405\u043el\u0430n\u0430 \u0422r\u0430\u0441k\u0435r", "Sol Tracker", "ST", "MOS", "F\u043emo API", "S\u00f3l\u00e1na Tr\u00e2cker"):
            self.assertIn(name, missed, ascii(name))

    def test_the_no_false_refusal_list_stays_accepted(self):
        for name in ACCEPTED:
            with self.subTest(name=name):
                self.assertIsNone(hf.presentation_only_provider(name))
        findings = hf.normalize_findings_file({"unit": "percent", "providers": [{"provider": n, "status": "ok", "largest_cluster_pct": 1.0} for n in ACCEPTED[:17]]})
        self.assertEqual(len(findings), 17)
        for value in (None, 7, ["Solana Tracker"], {"name": "fomo"}, b"fomo"):
            self.assertIsNone(hf.presentation_only_provider(value))

    def test_nfkc_first_would_change_nothing(self):
        """The matcher applies the compatibility mapping of NFKC through NFKD (which also splits accents off), so a separate
        NFKC step would be a no-op: NFKD(NFKC(name)) == NFKD(name) for every name tested here."""
        import unicodedata

        for name in [n for names in BYPASS.values() for n in names] + ACCEPTED:
            self.assertEqual(unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", name)), unicodedata.normalize("NFKD", name), ascii(name))
            self.assertEqual(hf._fold_provider_name(unicodedata.normalize("NFKC", name)), hf._fold_provider_name(name), ascii(name))

    def test_abbreviations_count_as_a_separate_word_never_inside_a_longer_word(self):
        """N1: ST and MOS are refused as the whole name or a separate word of it, never inside a longer word, and never
        after collapsing repeated letters ("Moss" would collapse to "mos")."""
        for name in ("ST", " st ", "S-T", "MOS", "m.o.s", "ST bundles", "MOS cluster", "Solana ST", "st-bundles", "bundles (MOS)", "S.T. bundles"):
            self.assertIsNotNone(hf.presentation_only_provider(name), name)
        for name in ("Step", "stats", "Stats", "Step Finance", "Mosaic", "Cosmos", "most", "1st", "1st place", "STR", "MOSS", "Moss", "Mossy", "Main Street", "Assist"):
            self.assertIsNone(hf.presentation_only_provider(name), name)

    def test_repeated_letters_are_collapsed_for_the_names_only(self):
        for name, label in (("Fommo", "Fomo API"), ("Maddeonsol", "MadeOnSol"), ("Solanna Tracker", "Solana Tracker"), ("Sooltrack", "Solana Tracker")):
            self.assertEqual(hf.presentation_only_provider(name), label, name)
        for name in ("Bubblemaps", "Mississippi", "Moonshot", "Assist", "Moss"):
            self.assertIsNone(hf.presentation_only_provider(name), name)

    def test_the_refusal_names_the_provider_never_echoes_the_raw_name(self):
        with self.assertRaises(hf.ConfigError) as ctx:
            hf.normalize_findings_file([{"provider": "\u0405\u043elana Tracker\n# <b>injected</b>", "status": "ok", "largest_cluster_pct": 0.0, "unit": "percent"}])
        self.assertEqual(str(ctx.exception), "--providers-json cannot supply Solana Tracker: it is a presentation-only provider, shown by the synthesis next to the FLAGs and never an engine input")


class AssessRefusesLookalikesTests(unittest.TestCase):
    """End to end: a hand-copied calm number under a look-alike name is refused by assess (exit 2, one plain line)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        case = case_negative_space_inu()
        cls.mint = case.mint
        cls.run_dir = cls.tmp / "run"
        code, _, _ = _run(["funders", case.mint, "--top", "5", "--workers", "6", *case.collector_args, "--out", str(cls.run_dir)], fake=case.fake(), pairs=case.pairs)
        assert code == 0
        cls.alarm_map = cls.tmp / "map.json"
        cls.alarm_map.write_text(json.dumps(_map(case.mint, [(40, 25.0)], age=2.0)))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_lookalike_names_are_refused_and_the_map_alarm_stands(self):
        for name, label in (("\u0405\u043el\u0430n\u0430 \u0422r\u0430\u0441k\u0435r", "Solana Tracker"), ("MOS", "MadeOnSol"), ("\uff26\uff4f\uff4d\uff4f", "Fomo API")):
            with self.subTest(name=ascii(name)):
                path = self.tmp / f"providers-{label.replace(' ', '')}.json"
                path.write_text(json.dumps({"unit": "percent", "providers": [{"provider": name, "status": "ok", "largest_cluster_pct": 0.008, "bundle_pct": 0.008, "data_age_min": 1}]}))
                code, _, err = run_assess(self.mint, self.run_dir, ["--bubblemaps-json", str(self.alarm_map), "--providers-json", str(path)], out=self.tmp / f"out-{label}")
                self.assertEqual(code, 2)
                self.assertEqual(err.strip(), f"error: --providers-json cannot supply {label}: it is a presentation-only provider, shown by the synthesis next to the FLAGs and never an engine input")
        code, _, err = run_assess(self.mint, self.run_dir, ["--bubblemaps-json", str(self.alarm_map)], out=self.tmp / "alone")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads((self.tmp / "alone" / "assessment.json").read_text())["flag"]["label"], hf.FLAG_DANGER)


if __name__ == "__main__":
    unittest.main()
