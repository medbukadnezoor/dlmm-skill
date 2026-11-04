"""HS-LABELS-T1: provider text can never print "clean", "safe" or "low" (or the other listed words and phrases), and the
labeled-funder count names the labeled wallets whose funder address is unknown (Verifier note N2 of HS-OWNER-1019-T1).

One shared rule (scripts/provider_words.py) replaces every listed word or phrase in provider-supplied text with
"[provider word removed]" (several in a row: "[provider word removed x3]") and every report or --present block that shows it
counts it. These tests cover: the documented list; adversarial spellings (case, look-alikes, full-width, accents, invisible
characters, digits and signs as letters, spaced and sign-split letters, markdown, HTML entities and tags, bidi controls);
results never longer than the sanitizer's cap; this tool's own wording never touched (the empty-map detail, SolScanner's
own "10w" hint, documented provider levels printed in our own words); real labels from the saved fixtures and the presentation-only matcher's
no-false-refusal list unchanged; a seeded fuzz over every sanitizer of both engines and every collector; every text path
(GMGN funder names, Jupiter tags, Helius funder / type / upstream names, --providers-json provider names, details and alarm
hints, SolScanner levels and types, Solana Tracker / MadeOnSol / Fomo --present, run folders saved before this rule read
back by assess); the N2 wording; verdicts, flags and severities unchanged; this tool's own wording untouched; and the
byte-identical copy of the rule in gmgn_rows.py. `visible()` below is an independent check (regular expressions over folded
text), not the rule's own code. Offline, standard library only."""

from __future__ import annotations

import argparse
import collections
import copy
import html
import json
import random
import re
import shutil
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import fomoapi as fa  # noqa: E402
import gmgn_rows as gr  # noqa: E402
import helius_forensics as hf  # noqa: E402
import jupiter_rows as jr  # noqa: E402
import madeonsol as mo  # noqa: E402
import provider_words as pw  # noqa: E402
import solanatracker as st  # noqa: E402
import test_assess as ta  # noqa: E402
import test_fomoapi as tfa  # noqa: E402
import test_madeonsol as tmo  # noqa: E402
import test_solanatracker as tst  # noqa: E402
from ha import evidence as ha_evidence  # noqa: E402
from ha import gating as ha_gating  # noqa: E402
from test_presentation_only_matcher import ACCEPTED, BYPASS  # noqa: E402
from test_unknown_funders import CAPE_LAUNCH, gmgn_without_funders  # noqa: E402
from test_cape_regression import holders_dict as cape_holders  # noqa: E402
from test_verdict_gating import holders_dict  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
P = pw.PLACEHOLDER
WORDS = ("clean", "safe", "safer", "safest", "low", "legit", "safu")
PHRASES = (("low", "risk"), ("lowest", "risk"), ("no", "risk"), ("zero", "risk"), ("risk", "free"), ("rug", "free"), ("safe", "to", "buy"),
           ("not", "a", "rug"), ("no", "rug"), ("rug", "proof"), ("no", "alarm"))
MARKER = re.compile(r"\[provider word removed(?: x\d+)?\]")  # one placeholder, or several in a row collapsed into one counted placeholder
CAPS = {"helius_forensics.safe_label": 32, "helius_forensics.clean_provider_text": 120, "ha.gating._text": 48, "ha.evidence.clean_text": 120,
        "gmgn_rows.safe_label": 32, "jupiter_rows.safe_label": 32, "solanatracker.safe_label": 32, "madeonsol.safe_label": 32, "fomoapi.safe_label": 32,
        "solanatracker._text": 80, "madeonsol._text": 80, "fomoapi._text": 80}
TICKET_EXAMPLE = "safe | clean | low risk"

# Real labels that must pass unchanged: every funder name in the saved fixtures (GMGN native_transfer names, the CAPE funding
# CSV), GMGN's documented tags, the live MadeOnSol / Fomo / SolScanner values, Solana Tracker's documented risk names (except
# "Very Low Liquidity", whose whole word "Low" is removed by design), the longer words the ticket names, and the
# presentation-only matcher's no-false-refusal and bypass lists (HS-PROV-T2).
FIXTURE_FUNDER_NAMES = sorted({(r.get("native_transfer") or {}).get("name") for f in FIX.glob("*_gmgn.json") for r in hf._unwrap(json.loads(f.read_text()))} - {None}
                              | {line.split(",")[4] for line in (FIX / "cape_cohort_fixture.csv").read_text().splitlines()[1:]})
REAL_LABELS = FIXTURE_FUNDER_NAMES + sorted(gr.MAKER_TAGS | gr.GENERAL_TAGS) + [
    "unranked", "limited_history", "CAT PEPE", "CAPE", "pumpfun", "swap_only", "same_batch_block_time_second", "admitted_previously", "accumulating",
    "negative", "insufficient_data", "same_slot", "atomic_tx", "HerrOdinn", "Duki13", "live-fomo", "live-top-holders", "mixed", "same_source", "high", "medium",
    "Freeze Authority Enabled", "Mint Authority Enabled", "Top 10 Holders", "Bundler Holdings", "Dev Holdings", "Snipers", "Insiders", "LP not burned or not locked",
    "Bonding curve not complete", "Suspicious Volume", "No social media", "Centralized Exchange", "Bridge", "bundler", "sniper", "insider", "influencer", "smartMoney",
    "SafePal", "Lowell", "Cleanup", "Slow", "Unsafe", "Saferoom", "Safety", "Lower", "Below", "Flow", "Allow", "Glow", "Cleanest", "Legitimate", "Safeguard",
] + ACCEPTED + [n for names in BYPASS.values() for n in names]


def _fold(text: str, signs: bool, strip_tags: bool = True) -> str:
    out = []
    text = html.unescape(html.unescape(text))
    if strip_tags:  # as a renderer shows it (tags hidden); otherwise as a plain-text reader sees it (repair R7: "<SAFE>")
        text = re.sub(r"<[^<>]*>", "", text)
    for ch in unicodedata.normalize("NFKD", text):
        if unicodedata.category(ch) in ("Mn", "Me", "Cf"):
            continue
        ch = ch.translate(pw.PROVIDER_LOOKALIKES).casefold().translate(pw.PROVIDER_LOOKALIKES)
        out.append(ch.translate(pw.PROVIDER_LOOKALIKE_SIGNS) if signs else ch)
    folded = "".join(out)
    return folded.replace("rn", "m").replace("i", "l") if signs else folded


def visible(text: str) -> list[str]:
    """Every listed word or phrase a reader could make out in `text` (placeholders removed), under the documented
    contract, written independently of the rule's code with regular expressions over folded text: (1) a word whose letters
    (each possibly repeated) are separated by signs only, standing alone; a phrase is such words with any gap or none
    between them; (2) a run of single letters (a repeated letter counts as one) separated by spaces or signs, searched for a
    listed word or a phrase written together anywhere inside it. Both checked on the plain folding and on the folding that
    reads digits and signs as letters. A word split by a space into longer pieces ("sa fe", "1 ow") is outside the contract
    (a documented residual), so the fuzz below never builds one on purpose. HTML entities and tags and bidi controls are
    undone first, and tags are read both ways (repair R7): hidden, as a renderer shows them ("s<x></x>afe" reads as safe), and
    as written, as a plain-text reader sees them ("<SAFE>" reads as SAFE)."""
    text = MARKER.sub(" qxq ", text)  # a removed word interrupts: "no [provider word removed] risk" is not the phrase "no risk"
    found = []
    targets = WORDS + tuple(" ".join(p) for p in PHRASES)
    readings = [(signs, strip) for signs in (False, True) for strip in (True, False)]
    folds = {r: _fold(text, *r) for r in readings}
    runs = {r: _single_runs(folds[r]) for r in readings}
    for target in targets:
        hits = []
        for reading in readings:
            signs, folded = reading[0], folds[reading]
            key = (lambda w: w.replace("rn", "m").replace("i", "l")) if signs else (lambda w: w)
            word_patterns = [r"[^0-9a-z\s]*".join(re.escape(c) + "+" for c in key(w)) for w in target.split()]
            pattern = r"(?<![0-9a-z])" + r"[^0-9a-z]*".join(word_patterns) + r"(?![0-9a-z])"
            tight = len(re.findall(pattern, folded))
            spaced = sum(_occurrences(_collapse_run(run), key(target.replace(" ", ""))) for run in runs[reading])
            hits.append(max(tight, spaced))  # "s.a.f.e" is both: one place
        found += [target] * max(hits)  # one place counts once, whichever folding shows it
    return sorted(found)


def _single_runs(folded: str) -> list[str]:
    """Runs of two or more single letters (a repeated letter counts as one) separated by spaces or signs, joined."""
    runs, current = [], []
    for token in re.findall(r"[0-9a-z]+|[^0-9a-z]+", folded):
        if re.fullmatch(r"[0-9a-z]+", token):
            if len(set(token)) == 1:
                current.append(token[0])
                continue
            if len(current) > 1:
                runs.append("".join(current))
            current = []
    if len(current) > 1:
        runs.append("".join(current))
    return runs


def _collapse_run(run: str) -> str:
    return re.sub(r"(.)\1+", r"\1", run)


def _occurrences(run: str, target: str) -> int:
    return run.count(_collapse_run(target))


# ----------------------------------------------------------------------------- adversarial spellings (seeded)

_LOOKALIKE_OF: dict[str, list[str]] = collections.defaultdict(list)
for _code, _latin in pw.PROVIDER_LOOKALIKES.items():
    if _latin.islower():
        _LOOKALIKE_OF[_latin].append(chr(_code))
_SIGN_OF = {"s": ["5", "$"], "a": ["4", "@"], "e": ["3"], "o": ["0"], "l": ["1", "|", "I"], "t": ["7"], "i": ["1", "|"]}
_INVISIBLE = ["​", "­", "⁠", "﻿", "‍"]


def _letters(word: str, rng: random.Random) -> str:
    out = []
    for c in word:
        r = rng.random()
        if not (c.isascii() and c.isalpha()):
            out.append(c)
        elif r < 0.15 and _LOOKALIKE_OF.get(c.lower()):
            out.append(rng.choice(_LOOKALIKE_OF[c.lower()]))
        elif r < 0.25 and c.lower() in _SIGN_OF:
            out.append(rng.choice(_SIGN_OF[c.lower()]))
        elif r < 0.32:
            out.append(chr((0xFF21 + ord(c) - ord("A")) if c.isupper() else (0xFF41 + ord(c) - ord("a"))))  # full-width
        elif r < 0.37:
            out.append(chr((0x1D400 + ord(c) - ord("A")) if c.isupper() else (0x1D41A + ord(c) - ord("a"))))  # mathematical bold
        elif r < 0.44:
            out.append(c + "́")  # combining accent
        elif r < 0.50:
            out.append(c + rng.choice(_INVISIBLE))
        elif r < 0.56:
            out.append(c * rng.randint(2, 3))  # repeated letter
        else:
            out.append(c.upper() if rng.random() < 0.5 else c)
    return "".join(out)


def spelling(target: str, rng: random.Random) -> str:
    """One adversarial spelling of a listed word or phrase."""
    words = target.split()
    style = rng.random()
    if style < 0.2:  # spaced or sign-split single letters, the same separator throughout
        sep = rng.choice([" ", ".", "-", "_", "*", "/", " . ", "  ", ", "])
        text = sep.join(c for c in "".join(words))
    elif style < 0.35 and len(words) > 1:  # a phrase written together, camel case or with signs between the words
        sep = rng.choice(["", "-", "_", ".", "  "])
        text = sep.join(w.capitalize() if sep == "" and rng.random() < 0.6 else w for w in words)
    else:
        text = " ".join(words)
    text = _letters(text, rng)
    wrap = rng.choice(["{}", "{}", "**{}**", "`{}`", "_{}_", "~~{}~~", "[{}](https://x)", "<b>{}</b>", "# {}", "> {}", "| {} |", "\"{}\"", "({})"])
    return wrap.format(text)


def sanitizers() -> dict:
    """Every function that turns provider text into something printed or saved, in both engines and every collector."""
    return {
        "helius_forensics.safe_label": hf.safe_label, "helius_forensics.clean_provider_text": hf.clean_provider_text,
        "ha.gating._text": ha_gating._text, "ha.evidence.clean_text": ha_evidence.clean_text,
        "gmgn_rows.safe_label": gr.safe_label, "jupiter_rows.safe_label": jr.safe_label, "solanatracker.safe_label": st.safe_label,
        "madeonsol.safe_label": mo.safe_label, "fomoapi.safe_label": fa.safe_label,
        "solanatracker._text": st._text, "madeonsol._text": mo._text, "fomoapi._text": fa._text,
    }


# ----------------------------------------------------------------------------- the rule


class RuleTests(unittest.TestCase):
    def test_the_documented_list_is_pinned(self):
        self.assertEqual(pw.VERDICT_WORDS, WORDS)
        self.assertEqual(pw.VERDICT_PHRASES, PHRASES)
        self.assertEqual(pw.PLACEHOLDER, "[provider word removed]")
        self.assertEqual((pw.marker(1), pw.marker(3)), (P, "[provider word removed x3]"))
        self.assertEqual(visible(P), [], "the placeholder itself holds no listed word")
        self.assertEqual(pw.LEVEL_WORDS, {"low": "weak", "medium": "medium", "high": "strong"})

    def test_the_tickets_example_is_removed_and_counted(self):
        out, n = pw.neutralize(TICKET_EXAMPLE)
        self.assertEqual((out, n), (f"{P} | {P} | {P}", 3))
        self.assertEqual(pw.neutral(TICKET_EXAMPLE), "[provider word removed x3]", "a run of removed words is one counted placeholder")
        self.assertEqual(pw.count([pw.neutral(TICKET_EXAMPLE), P]), 4)
        self.assertEqual(visible(TICKET_EXAMPLE), ["clean", "low", "low risk", "safe"], "the check sees the words before the rule")
        self.assertEqual(visible(out), [])

    def test_every_word_and_phrase_in_plain_spellings(self):
        for target in WORDS + tuple(" ".join(p) for p in PHRASES):
            for text in (target, target.upper(), target.title(), f"x {target} y", f"{target}!", f"({target})", target.replace(" ", "-"), target.replace(" ", "_"),
                         target.replace(" ", ""), "".join(w.capitalize() for w in target.split())):
                with self.subTest(text=text):
                    out, n = pw.neutralize(text)
                    self.assertEqual(visible(out), [], out)
                    self.assertGreaterEqual(n, 1)
                    self.assertRegex(out, MARKER)

    def test_adversarial_spellings(self):
        cases = ["safer", "SAFEST", "lowest risk", "Zero-Risk", "rug free", "rug-free", "RugFree", "no rug", "NoRug", "S&#65;FE", "s<b></b>afe", "&lt;b&gt;safe",
                 "&amp;#115;afe", "$ a f e", "$-aa-f-\u1d1c", "|ow", "s a f e", "S.A.F.E", "s-a-f-e", "s_a_f_e", "c*l*e*a*n", "l / o / w", "**safe**", "`clean`", "_low_", "~~legit~~", "[safe](http://x)", "<b>clean</b>",
                 "ѕаfе", "ＳＡＦＥ", "\U0001d42c\U0001d41a\U0001d41f\U0001d41e", "ⓢⓐⓕⓔ", "sáfe", "sáfe", "sa​fe",
                 "cl­ean", "5AF3", "$afe", "s@fe", "l0w", "10W", "c1ean", "c|ean", "cIean", "LEG1T", "saaafe", "cleeean", "loooow", "SAFUUU", "łow", "ʟᴏᴡ",
                 "LowRisk", "low-risk", "LOW_RISK", "no risk", "No-Risk", "riskfree", "Risk Free", "safe to buy", "SafeToBuy", "not a rug", "Not-A-Rug", "notarug",
                 "rug proof", "rugproof", "Rug-Proof", "NO_ALARM", "no alarm", "NoAlarm", "funds are safu", "a s a f e", "s a f e r", "s a f e s t", "L O W"]
        for text in cases:
            with self.subTest(text=ascii(text)):
                out, n = pw.neutralize(text)
                self.assertGreaterEqual(n, 1, ascii(text))
                self.assertEqual(visible(out), [], ascii(out))

    def test_real_labels_pass_unchanged(self):
        self.assertGreater(len(FIXTURE_FUNDER_NAMES), 20)
        for label in REAL_LABELS:
            with self.subTest(label=ascii(label)):
                self.assertEqual(pw.neutralize(label), (label, 0))
                self.assertEqual(visible(label), [], "the check agrees: no listed word in a real label")
                for f in (hf.safe_label, gr.safe_label, st.safe_label):
                    self.assertEqual(f(label), hf._label_chars(label), "every label rule gives exactly the old label")

    def test_whole_word_boundaries_as_documented(self):
        self.assertEqual(pw.neutral("Clean-up"), f"{P}-up")
        self.assertEqual(pw.neutral("safe-pal"), f"{P}-pal")
        self.assertEqual(pw.neutral("Very Low Liquidity"), f"Very {P} Liquidity", "as free text; solanatracker.py prints its two documented names in its own words")
        self.assertEqual(pw.neutral("low_liquidity"), f"{P}_liquidity")
        for text in ("SafePal", "Lowell", "Cleanup", "Slow", "Unsafe", "Binancesafe", "Saferoom", "Safety", "lowered", "Lowest", "cle an", "Sa Fe", "rugged", "No Rugs"):
            self.assertEqual(pw.neutral(text), text)

    def test_rule_is_idempotent_and_a_placeholder_survives_every_sanitizer(self):
        rng = random.Random(7)
        for _ in range(300):
            text = f"{rng.choice(REAL_LABELS)} {spelling(rng.choice(WORDS + tuple(' '.join(p) for p in PHRASES)), rng)}"
            once = pw.neutral(text)
            self.assertEqual(pw.neutral(once), once)
            for name, f in sanitizers().items():
                first = f(text)
                if first is None:
                    continue
                self.assertEqual(f(first), first, (name, ascii(text)))  # a label read back gives the same label
        for name, f in sanitizers().items():
            self.assertIn(P, f(f"Binance {P} Hot Wallet") or "", name)
            self.assertIn("[provider word removed x2]", f("Binance [provider word removed x2]") or "", name)

    def test_without_a_listed_word_every_sanitizer_is_unchanged(self):
        old_label = hf._label_chars
        old_clean = lambda v, cap=hf.TEXT_CAP: hf._MD_START_RE.sub("", " ".join(hf._CONTROL_RE.sub(" ", str(v)).split()))[:cap]  # noqa: E731
        old_gating = lambda v: "".join(ch for ch in v if ch.isalnum() or ch in " ._-:/%")[:48].strip() or None if isinstance(v, str) and v.strip() else None  # noqa: E731
        old_text = lambda v, cap=80, rx=st.TEXT_RE: " ".join(rx.sub("", " ".join(str(v).split())).split())[:cap].strip() or "unknown"  # noqa: E731
        rng = random.Random(11)
        samples = REAL_LABELS + ["", "  ", None, 7, "x" * 90, "Evil\n# <b>Fake heading</b> | table", "- leading dash", "a" * 40 + " b", "​zero"]
        samples += ["".join(rng.choice("abcdefgh ijk-._/|*#<>&;") for _ in range(rng.randint(1, 70))) for _ in range(300)]
        for v in samples:
            if isinstance(v, str) and (visible(v) or pw.inert(v) != v):  # a listed word, HTML, a markdown link or a bidi control: changed on purpose
                continue
            with self.subTest(v=ascii(v)[:60]):
                self.assertEqual(hf.safe_label(v), old_label(v))
                self.assertEqual(hf.clean_provider_text(v), old_clean(v))
                self.assertEqual(hf.clean_provider_text(v, 40), old_clean(v, 40))
                self.assertEqual(ha_gating._text(v), old_gating(v))
                self.assertEqual(st._text(v), old_text(v))
                self.assertEqual(mo._text(v), old_text(v, rx=mo.TEXT_RE))
                self.assertEqual(fa._text(v), old_text(v, rx=fa.TEXT_RE))

    def test_signs_a_sanitizer_drops_are_read_before_they_go(self):
        """Found by the output sweep: "$ a f E" lost its "$" to the label rule and left "a f E", which a report then printed
        next to its own count ("..., a f E 5", read as "safe"). The raw text is now neutralized before any character is
        dropped, and again after."""
        for raw in ("$ a f E", "$-aa-f-\u1d1c", "|ow", "@ll clear $afe", "!egit"):
            for name, f in sanitizers().items():
                out = f(raw)
                with self.subTest(raw=ascii(raw), sanitizer=name):
                    if visible(raw):
                        self.assertIn(P, out or "")
        self.assertEqual(hf.safe_label("$ a f E"), P)

    def test_html_markdown_and_bidi_are_made_inert(self):
        """Hardening (a): an RLO can show "EFAS" as SAFE; entities and tags can hide letters; a markdown link can hide its
        target. Every sanitizer drops bidi controls, decodes entities, drops tags and reduces links to their text."""
        for raw, expected in (("\u202eEFAS", "EFAS"), ("S&#65;FE", P), ("s<b></b>afe", P), ("[safe](https://x.example)", P), ("Gate<i>.io</i>", "Gate.io"),
                              ("\u2066Binance\u2069", "Binance"), ("A&amp;B", None)):
            for name, f in sanitizers().items():
                out = f(raw)
                with self.subTest(raw=ascii(raw), sanitizer=name):
                    self.assertFalse(re.search("[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]", out or ""), "no bidi control left")
                    self.assertNotIn("<", out or "")
                    self.assertEqual(visible(out or ""), [])
                    if expected is not None:
                        self.assertEqual(out, expected)

    def test_angle_brackets_that_are_not_html_tags_are_kept(self):
        """N1 (review of dc71087): only HTML tags, comments and declarations are dropped; "<5% and >" or "<dev>" is text, as
        before (each sanitizer's own character rule decides, exactly as the old rule did). Any tag-like text is still read as
        invisible while matching, so it cannot split a word."""
        for raw in ("bundle <5% and >2%", "C++ <dev>", "a < b > c", "x<y and y>z", "<3 holders", "1 << 2 >> 3"):
            with self.subTest(raw=raw):
                self.assertEqual(pw.inert(raw), raw)
                self.assertEqual(hf.safe_label(raw), hf._label_chars(raw), "the old label rule exactly")
                self.assertEqual(hf.clean_provider_text(raw), hf.clean_text(raw), "the old text rule exactly")
                self.assertEqual(ha_evidence.clean_text(raw), raw)
        self.assertEqual(hf.safe_label("bundle <5% and >2%"), "bundle 5 and 2")
        self.assertEqual(hf.clean_provider_text("C++ <dev>"), "C++ <dev>")
        self.assertEqual(hf.safe_label("C++ <dev>"), "C dev")
        for raw, expected in (("x <b>bold</b> y", "x bold y"), ("<span class=\"x\">Gate</span>.io", "Gate.io"), ("a<br/>b", "ab"), ("a<BR>b", "ab"),
                              ("<script>alert(1)</script>Kraken", "alert(1)Kraken"), ("Bybit<!-- safe -->", "Bybit"), ("<!DOCTYPE html>OKX", "OKX"),
                              ("Gate</i >.io", "Gate.io")):
            with self.subTest(raw=raw):
                self.assertEqual(pw.inert(raw), expected, "real tags and comments are still dropped")
        for raw in ("s<x></x>afe", "s<dev>afe", "c<foo bar>lean", "l<q-1>o</q-1>w r<z>isk"):
            for name, f in sanitizers().items():
                with self.subTest(raw=raw, sanitizer=name):
                    self.assertIn(P, f(raw) or "")
                    self.assertEqual(visible(f(raw) or ""), [])

    def test_tag_like_text_is_read_both_ways_and_bogus_comments_are_dropped(self):
        """R7 (review of 046affa): tag-like text that is not an HTML tag stays in the output, so it is read both ways: as
        written ("<SAFE>", "<x low risk>", "<legit> Treasury": a plain-text reader sees the word) and hidden ("s<x></x>afe": a
        renderer joins the letters). The HTML bogus comments are dropped as a renderer drops them. Ordinary angle brackets
        stay exactly as the old rule left them."""
        for raw in ("<SAFE>", "<clean>", "<x low risk>", "<legit> Treasury", "</clean>", "<x safe>", "<SAFE> Scanner", "s<x></x>afe", "c<dev>lean",
                    "s<?x?>afe", "s</ x>afe", "s<![CDATA[x]]>afe", "s</>afe", "<sa>fe", "s<x>a<y>f<z>e", "<b><SAFE></b>"):
            for name, f in sanitizers().items():
                with self.subTest(raw=raw, sanitizer=name):
                    out = f(raw) or ""
                    self.assertIn(P, out)
                    self.assertEqual(visible(out), [])
        self.assertEqual(ha_evidence.clean_text("<SAFE>"), f"<{P}>", "the brackets stay, the word goes")
        self.assertEqual(hf.clean_provider_text("<x low risk>"), f"<x {P}>")
        self.assertEqual(hf.clean_provider_text("<legit> Treasury"), f"<{P}> Treasury")
        self.assertEqual(hf.safe_label("<SAFE>"), P)
        for raw, expected in (("s<?x?>afe", "safe"), ("s</ x>afe", "safe"), ("s<![CDATA[x]]>afe", "safe"), ("a</>b", "ab"), ("a<!x>b", "ab"),
                              ("a<?php echo 1 ?>b", "ab")):
            with self.subTest(raw=raw):
                self.assertEqual(pw.inert(raw), expected, "an HTML bogus comment is dropped, as a renderer drops it")
        for raw in ("C++ <dev>", "bundle <5% and >2%", "x < y > z", "a<b", "a > b", "<3", "<dev> notes"):
            with self.subTest(raw=raw):
                self.assertEqual(hf.clean_provider_text(raw), hf.clean_text(raw), "the old text rule exactly")
                self.assertEqual(ha_evidence.clean_text(raw), raw)
                self.assertEqual(hf.safe_label(raw), hf._label_chars(raw), "the old label rule exactly")

    def test_a_cut_never_cuts_a_placeholder(self):
        """B2: the cut falls where the old rule cut; a placeholder cut by it stays whole."""
        label = hf.safe_label("safe safe safe safe safe safe safe")  # 34 characters: the old rule cut the last "safe" to "sa"
        self.assertEqual(label, "[provider word removed x7]")
        self.assertEqual(hf.safe_label("Binance Hot Wallet Number 2 West low risk"), "Binance Hot Wallet Number 2 West", "a word past the cut is cut, as before")
        self.assertEqual(hf.safe_label("Binance Hot Wallet Number 2 low risk"), f"Binance Hot Wallet Number 2 {P}", "a phrase the cut halves: the placeholder, whole")
        self.assertEqual(hf.safe_label("Lowell Fund Holdings Group Inc Ltd"), "Lowell Fund Holdings Group Inc L", "no listed word: the old rule exactly")
        self.assertEqual(hf.safe_label("Binance Holdings Group Ltd 1 Lowell"), f"Binance Holdings Group Ltd 1 {P}", "a cut that leaves Low: marked, as it would read")
        self.assertEqual(hf.safe_label(label), label)
        self.assertEqual(hf.clean_provider_text(label, 40), label)

    def test_the_cut_keeps_the_text_the_old_rule_kept(self):
        """B2 (review of dc71087): the real CAPE OKX alarm hint keeps its metric; other words of a provider text stay."""
        hint = "same fund source 0.947 vs Low headline"
        self.assertEqual(hf.safe_label(hint), f"same fund source 0.947 vs {P} he", "cut where the old rule cut (\"vs Low he\"), then marked")
        for name, f in sanitizers().items():
            with self.subTest(sanitizer=name):
                self.assertIn("same fund source 0.947 vs " + P, f(hint))
        for raw, words in (("Low Liquidity Risk", "Liquidity Risk"), ("Very Low Liquidity!", "Liquidity"), ("Clean Energy Fund", "Energy Fund"),
                           ("Binance Hot Wallet 2 safe", "Binance Hot Wallet 2"), ("RugCheck Safe", "RugCheck"), ("Low Risk Labs", "Labs")):
            for name, f in sanitizers().items():
                with self.subTest(raw=raw, sanitizer=name):
                    out = f(raw)
                    self.assertIn(P, out)
                    self.assertTrue(all(w in out for w in words.split()), out)
                    self.assertEqual(visible(out), [])
        self.assertEqual(hf.safe_label("Very Low Liquidity!"), f"Very {P} Liquidity")
        self.assertEqual(hf.clean_provider_text("Clean Energy Fund"), f"{P} Energy Fund")

    def test_a_line_this_tool_shortens_never_cuts_a_placeholder(self):
        """B2: the executive summary's 110-character reason cut and the 200-character caveat note keep a placeholder whole
        ("[p..." would read as nothing); without a placeholder at the cut they cut exactly as before."""
        reason = "x" * 100 + " " + P + " tail of the reason"
        self.assertEqual(hf._short_reason(reason), "x" * 100 + " " + P + "...")
        plain = "y" * 150
        self.assertEqual(hf._short_reason(plain), plain[:107] + "...")
        self.assertEqual(pw.keep_whole("abc", 2), "ab")
        self.assertEqual(pw.keep_whole(f"ab{P}cd", 5), f"ab{P}")
        self.assertEqual(pw.keep_whole(f"ab{P}cd", 2), "ab")

    def test_growth_over_the_cap_is_bounded(self):
        """B2: a result is longer than its cap only by the placeholders' extra length (each placeholder stands for at least
        one character the old rule kept), and never by more than GROWTH_LIMIT; placeholders in a row are one counted one."""
        self.assertEqual(pw.GROWTH_LIMIT, 3 * len(P))
        raws = ("safe x " * 200, "s a f e " * 100, "safe a " * 12, "low x " * 40, "safe " * 300, "x" * 500 + " safe", "clean 1 low 2 safe 3 legit 4 " * 9,
                f"{P} a " * 40, "Binance Hot Wallet 2 safe", "same fund source 0.947 vs Low headline", "safe x clean x low risk x safu x legit")
        for raw in raws:
            for name, f in sanitizers().items():
                out = f(raw) or ""
                with self.subTest(raw=raw[:30], sanitizer=name):
                    extra = sum(len(m) - 1 for m in re.findall(r"\[provider word removed(?: x\d+)?\]", out))
                    self.assertLessEqual(len(out), CAPS[name] + extra)
                    self.assertLessEqual(len(out), CAPS[name] + pw.GROWTH_LIMIT)
                    self.assertEqual(visible(out), [])
                    self.assertNotRegex(out, r"\[provider word removed(?: x\d+)?\][^\w\[\]]*\[provider word removed", "placeholders in a row are one")
            self.assertLessEqual(len(pw.neutral(raw)), len(raw) + pw.GROWTH_LIMIT)
        self.assertEqual(hf.safe_label("safe a " * 12), f"{P} a {P} a [provider word removed x3]", "past the limit the last words go, never a placeholder")
        self.assertEqual(pw.fit(f"{P} {P} x {P}", 30), "[provider word removed x3]")
        self.assertEqual(pw.fit(f"ab {P}", 5), P, "a placeholder is never cut: the shortest honest form")

    def test_seeded_fuzz_no_listed_word_survives_any_sanitizer(self):
        """3,000 seeded adversarial spellings, embedded in real labels at random places, through all twelve sanitizers:
        nothing a reader could make out as a listed word survives (visible() is empty)."""
        rng = random.Random(20261019)
        targets = WORDS + tuple(" ".join(p) for p in PHRASES)
        failures = []
        for i in range(3000):
            base = rng.choice(REAL_LABELS)
            word = spelling(rng.choice(targets), rng)
            text = rng.choice([f"{word} {base}", f"{base} {word}", f"{base} {word} {rng.choice(REAL_LABELS)}", word])
            self.assertTrue(visible(text) or not any(c.isalpha() for c in word), ascii(text))
            for name, f in sanitizers().items():
                out = f(text)
                if isinstance(out, str) and (visible(out) or len(out) > CAPS[name] + pw.GROWTH_LIMIT):
                    failures.append((name, ascii(text), ascii(out), visible(out), len(out)))
        self.assertEqual(failures[:5], [])

    def test_the_matcher_and_the_rule_fold_with_the_same_tables(self):
        self.assertIs(hf.PROVIDER_LOOKALIKES, pw.PROVIDER_LOOKALIKES)
        self.assertIs(hf.PROVIDER_LOOKALIKE_SIGNS, pw.PROVIDER_LOOKALIKE_SIGNS)


class GmgnCopyTests(unittest.TestCase):
    """gmgn_rows.py keeps its SELF-CONTAINED COPY rule: it imports nothing from the skill, so it holds a byte-identical copy
    of the shared block of provider_words.py, and both behave the same."""

    BEGIN, END = "# ---- BEGIN shared verdict-word block", "# ---- END shared verdict-word block"

    def block(self, path: Path) -> str:
        text = path.read_text(encoding="utf-8")
        self.assertEqual((text.count(self.BEGIN), text.count(self.END)), (1, 1), path.name)
        return text[text.index(self.BEGIN):text.index("\n", text.index(self.END)) + 1]

    def test_the_copy_is_byte_identical(self):
        self.assertEqual(self.block(SCRIPTS / "gmgn_rows.py"), self.block(SCRIPTS / "provider_words.py"))

    def test_the_copy_behaves_the_same(self):
        rng = random.Random(3)
        texts = REAL_LABELS + [spelling(rng.choice(WORDS + tuple(" ".join(p) for p in PHRASES)), rng) for _ in range(500)]
        for t in texts:
            self.assertEqual(gr.neutralize(t), pw.neutralize(t), ascii(t))
            self.assertEqual(gr.safe_label(t), hf.safe_label(t), ascii(t))
        self.assertEqual((gr.PLACEHOLDER, gr.VERDICT_WORDS, gr.VERDICT_PHRASES), (pw.PLACEHOLDER, pw.VERDICT_WORDS, pw.VERDICT_PHRASES))

    def test_a_key_hidden_in_markup_is_still_dropped(self):
        """Dropping HTML first must not let a key echo through: the old character-only label is checked too."""
        key = "dummy-gmgn-key-7f3a9c41e2b8d6"
        for safe_label in (gr.safe_label, st.safe_label, mo.safe_label, fa.safe_label):
            self.assertIsNone(safe_label("Binance " + key[:5] + "<" + key[5:10] + ">" + key[10:15], key))
            self.assertIsNone(safe_label("Binance " + key[:4] + "<b>" + key[4:14] + "</b>", key))
            self.assertEqual(safe_label("Binance", key), "Binance")


# ----------------------------------------------------------------------------- the forensics engine, end to end


def _poison(case: ta.Case, poisoned: bool) -> ta.Case:
    """The CAPE all-inputs scenario with provider text on every path the forensics engine prints: Helius funder names and
    types, GMGN funder names, Jupiter tags, --providers-json provider names, alarm hints and details, SolScanner's level and
    type. `poisoned` puts listed words there; otherwise neutral words of the same kind (the control)."""
    w = (lambda bad, ok: bad if poisoned else ok)
    for info in case.funded.values():
        if isinstance(info, dict) and info.get("funderName") == "KuCoin Hot Wallet 2":
            info["funderName"], info["funderType"] = w(TICKET_EXAMPLE, "river | pine | tall mesa"), w("Clean Exchange", "Delta Exchange")
        elif isinstance(info, dict) and info.get("funderName") == "Gate Hot Wallet":
            info["funderName"] = w("SAFE ѕаfе l0w", "OPAL tide moss")
    gmgn = case.inputs["--gmgn-holders-json"]
    for i, r in enumerate(hf._unwrap(gmgn)):
        nt = r.get("native_transfer")
        if isinstance(nt, dict) and i % 3 == 0:
            nt["name"] = w(["Not-A-Rug", "**safe** to buy", "s a f e"][i % 9 // 3], ["Old-Oak-Hut", "**plum** to bay", "p l u m"][i % 9 // 3])
    jup = case.inputs["--jupiter-holders-json"]
    for i, r in enumerate(hf._unwrap(jup)):
        r["holderTags"] = ["bundler", w("SAFU", "kiwi"), w("rug_proof", "oak_grove")] if i % 4 == 0 else ["bundler"]
    providers = case.inputs["--providers-json"]["providers"]
    providers[0].update(provider=w("Safe Scanner", "Other Scanner"), alarm_hint=w("low risk, legit, not a rug", "same fund source 0.947"))
    providers[1].update(provider=w("CleanTool", "PlainTool"), detail=w("No risk at all", "empty cluster list"))
    ss = case.inputs["--solscanner-json"]
    for g in ss["groups"]:
        g.update(confidence=w("low", "medium"), bundle_type=w("safe", "mixed"))
    return case


def _run_both(make=ta.case_cape_all_inputs) -> tuple[dict, dict]:
    return ta.equivalence(_poison(make(), True)), ta.equivalence(_poison(make(), False))


class ForensicsPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bad, cls.ok = _run_both()

    def test_the_flow_runs_and_assess_rebuilds_the_same_files(self):
        for r in (self.bad, self.ok):
            self.assertEqual((r["exit_report"], r["exit_funders"], r["exit_assess"], r["exit_assess_copy"], r["refused_calls"]), (0, 0, 0, 0, 0))
            self.assertTrue(r["assessment_identical"] and r["assessment_identical_copy"], r["case"])
            self.assertEqual(ta.undocumented(r["report_diffs"]), [])

    def test_no_listed_word_reaches_any_output(self):
        for name in ("report.md", "assessment.json"):
            for flow in ("report_files", "assess_files", "copy_files"):
                bad, ok = self.bad[flow].get(name), self.ok[flow].get(name)
                if bad is None:
                    continue
                with self.subTest(flow=flow, file=name):
                    self.assertEqual(visible(bad), visible(ok), "only this tool's own wording, the same as in the control run")
                    self.assertRegex(bad, MARKER)
                    self.assertNotRegex(ok, MARKER)
        self.assertEqual(visible(self.bad["assess_stdout"]), visible(self.ok["assess_stdout"]))

    def test_every_path_shows_the_placeholder(self):
        md = self.bad["assess_files"]["report.md"]
        lines = md.splitlines()

        def has(test, what):
            self.assertTrue(any(MARKER.search(ln) and test(ln) for ln in lines), what)

        has(lambda ln: ln.startswith("    - funder mix:") and "FixedFloat Hot Wallet" in ln, "Helius funder names in the funder mix")
        has(lambda ln: ln.startswith("    - funder mix:") and "Gate.io" in ln, "GMGN funder names in the funder mix")
        has(lambda ln: re.fullmatch(r"    \[provider word removed(?: x\d+)?\].*: \d+ wallets, [0-9.]+% of supply", ln), "funder batches in Sources read")
        has(lambda ln: ln.startswith("| `"), "funder-batch table (Helius funder names)")
        has(lambda ln: ln.startswith("  - tags (Jupiter's claims"), "Jupiter tags")
        has(lambda ln: ln.startswith(f"- Provider {P} Scanner (--providers-json)"), "--providers-json provider name")
        has(lambda ln: "alarm hint: [provider word removed" in ln, "--providers-json alarm hint")
        has(lambda ln: ln.startswith("  - provider CleanTool: ran, EMPTY") and ln.endswith(f"{P} at all"), "--providers-json detail (CleanTool is one longer word: kept)")
        has(lambda ln: ln.startswith(f"- {P} Scanner alarm hint:"), "the verdict reasons")
        has(lambda ln: ln.startswith(f"| {P} Scanner |"), "the provider table")
        has(lambda ln: "group 1:" in ln and f"confidence weak, type {P}" in ln, "SolScanner level in our words (weak), bundle type removed")
        has(lambda ln: ln.startswith("- Also:") or ln.startswith("- Why:"), "the executive summary")
        has(lambda ln: ln.startswith("- Provider words removed:"), "the counted line")
        count = int(re.search(r"- Provider words removed: (\d+) ", md).group(1))
        body = md.replace(re.search(r"- Provider words removed: .*", md).group(0), "")
        self.assertEqual(count, pw.count([body]))
        a = json.loads(self.bad["assess_files"]["assessment.json"])
        self.assertTrue(any(MARKER.search(f["provider"]) for f in a["findings"]))
        self.assertTrue(any(MARKER.search(f.get("alarm_hint") or "") for f in a["findings"]))
        self.assertTrue(any(MARKER.search(r) for r in a["verdict"]["reasons"]))
        self.assertNotIn("Provider words removed", self.ok["assess_files"]["report.md"], "no placeholder, no counted line")

    def test_verdict_flag_and_severity_are_unchanged(self):
        x, y = json.loads(self.bad["assess_files"]["assessment.json"]), json.loads(self.ok["assess_files"]["assessment.json"])
        self.assertEqual((x["verdict"]["level"], x["flag"]["level"], x["flag"]["caveat"]), (y["verdict"]["level"], y["flag"]["level"], y["flag"]["caveat"]))
        self.assertEqual(re.sub(r"\(.*\)", "", x["flag"]["label"]), re.sub(r"\(.*\)", "", y["flag"]["label"]))
        self.assertEqual([(d["name"], d["state"]) for d in x["detectors"]], [(d["name"], d["state"]) for d in y["detectors"]])
        self.assertEqual([(f["status"], f["largest_cluster_pct"], f.get("cluster_sum_pct"), f["bundle_pct"], bool(f.get("alarm_hint"))) for f in x["findings"]],
                         [(f["status"], f["largest_cluster_pct"], f.get("cluster_sum_pct"), f["bundle_pct"], bool(f.get("alarm_hint"))) for f in y["findings"]])
        sev = lambda md: re.findall(r"- severity: (\w+)", md)  # noqa: E731
        self.assertEqual(sev(self.bad["assess_files"]["report.md"]), sev(self.ok["assess_files"]["report.md"]))
        self.assertEqual(x["coverage"], y["coverage"])


class UpstreamPathTests(unittest.TestCase):
    """Upstream funder names (Helius funded-by of each unlabeled batch funder): the VEIL-style scenario, whose round
    funders were funded by exchanges, with listed words in those exchange labels."""

    @staticmethod
    def case(poisoned: bool) -> ta.Case:
        case = ta.case_veil(False)
        for info in case.funded.values():
            if isinstance(info, dict) and info.get("funderName") == "Binance Hot Wallet 2":
                info["funderName"] = "Low Risk Desk" if poisoned else "Tall Pine Desk"
        return case

    def test_upstream_names_lose_the_listed_words_and_nothing_else_moves(self):
        bad, ok = ta.equivalence(self.case(True)), ta.equivalence(self.case(False))
        md_bad, md_ok = bad["assess_files"]["report.md"], ok["assess_files"]["report.md"]
        upstream = next(ln for ln in md_bad.splitlines() if ln.startswith("Upstream funders of the batch funders:"))
        self.assertIn(f"{P} Desk", upstream)
        self.assertEqual(visible(md_bad), visible(md_ok))
        x, y = json.loads(bad["assess_files"]["assessment.json"]), json.loads(ok["assess_files"]["assessment.json"])
        self.assertEqual((x["verdict"]["level"], x["flag"]), (y["verdict"]["level"], y["flag"]))
        self.assertTrue(bad["assessment_identical"] and bad["assessment_identical_copy"])


# B1 (review of dc71087): pairs of distinct --providers-json names whose printed names collided (exit 2 on dc71087,
# accepted on base 7143d14); the last pair is added here (both print as "[provider word removed] Desk")
PROVIDER_PAIRS = (("Safe Scanner", "Clean Scanner"), ("SAFE Scanner 0", "clean Scanner 1"), ("Safe Scanner A", "Safe Scanner B"),
                  ("Low Risk Labs", "Safe Labs"), ("RugCheck Safe", "RugCheck Clean"), ("Binance Hot Wallet 2 safe", "Binance Hot Wallet 8 safe"),
                  ("Zero Risk Desk", "Risk Free Desk"))
CONTROL_PAIR = ("Alpha Scanner", "Beta Scanner")


def _pair_providers(a: str, b: str) -> dict:
    """One provider alarming (largest cluster 40%), one calm (6%): the names are all that differ between runs."""
    return {"unit": "percent", "providers": [
        {"provider": a, "status": "ok", "largest_cluster_pct": 40.0, "data_age_min": 3.0},
        {"provider": b, "status": "ok", "largest_cluster_pct": 6.0, "cluster_sum_pct": 9.0, "data_age_min": 3.0}]}


class ProvidersJsonPairsTests(unittest.TestCase):
    """B1: load_findings tells --providers-json providers apart by the name under the old character rule (the raw name), as
    normalize_findings_file does, never by the printed name; report and assess accept every pair and reach the verdict
    the same files reach with neutral names; true duplicates and reserved names are still refused."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _args(self, payload, with_map=True):
        prov = self.tmp / "providers.json"
        prov.write_text(json.dumps(payload))
        bmap = self.tmp / "map.json"
        bmap.write_text(json.dumps({"mint": ta.CAPE, "parse_ok": True, "age_min_after": 1.0, "clusters": []}))
        return argparse.Namespace(providers_json=str(prov), bubblemaps_json=str(bmap) if with_map else None)

    def test_load_findings_accepts_every_pair(self):
        for a, b in PROVIDER_PAIRS:
            for with_map in (True, False):
                with self.subTest(pair=(a, b), with_map=with_map):
                    found = hf.load_findings(self._args(_pair_providers(a, b), with_map), ta.CAPE)
                    names = [f["provider"] for f in found]
                    self.assertEqual(len(names), 3 if with_map else 2)
                    self.assertEqual(names[-2:], [hf.safe_label(a), hf.safe_label(b)])
                    self.assertTrue(all(P in n for n in names[-2:]))

    def test_true_duplicates_and_reserved_names_are_still_refused(self):
        for a, b in (("Safe Scanner", "SAFE scanner"), ("okx", "OKX"), ("Low Risk Labs", "low risk labs")):
            with self.subTest(pair=(a, b)), self.assertRaises(hf.ConfigError) as cm:
                hf.load_findings(self._args(_pair_providers(a, b)), ta.CAPE)
            self.assertIn("twice; each provider must appear once", str(cm.exception))
            self.assertEqual(visible(str(cm.exception)), [])
        for name in ("bubblemaps_map", "Bubblemaps_Map", "solscanner", "SolScanner"):
            for with_map in (True, False):
                with self.subTest(name=name, with_map=with_map), self.assertRaises(hf.ConfigError) as cm:
                    hf.load_findings(self._args(_pair_providers(name, "Other Scanner"), with_map), ta.CAPE)
                self.assertIn("is reserved for --bubblemaps-json", str(cm.exception))

    def _run(self, make, pair):
        case = make()
        case.inputs["--providers-json"] = _pair_providers(*pair)
        return ta.equivalence(case)

    def test_report_and_assess_accept_every_pair_with_the_controls_verdict(self):
        for make in (ta.case_cape_all_inputs, ta.case_negative_space_inu):
            control = self._run(make, CONTROL_PAIR)
            self.assertEqual((control["exit_report"], control["exit_assess"], control["exit_assess_copy"]), (0, 0, 0))
            for pair in PROVIDER_PAIRS:
                with self.subTest(case=make.__name__, pair=pair):
                    r = self._run(make, pair)
                    self.assertEqual((r["exit_report"], r["exit_funders"], r["exit_assess"], r["exit_assess_copy"]), (0, 0, 0, 0), r["assess_stderr"])
                    self.assertTrue(r["assessment_identical"] and r["assessment_identical_copy"])
                    x, y = json.loads(r["report_files"]["assessment.json"]), json.loads(control["report_files"]["assessment.json"])
                    shown = [hf.safe_label(n) for n in pair]

                    def named(obj, names):  # the provider names as printed, replaced by stand-ins (one stand-in when they print alike)
                        text = json.dumps(obj)
                        for k, n in enumerate(names):
                            text = text.replace(n, "NAME" if shown[0] == shown[1] else f"NAME{k}")
                        return text
                    self.assertEqual(r["verdict"], control["verdict"])
                    self.assertEqual(x["flag"]["level"], y["flag"]["level"])
                    self.assertEqual(named(x["flag"], shown), named(y["flag"], CONTROL_PAIR), "the same FLAG, names aside")
                    self.assertEqual(named(x["verdict"], shown), named(y["verdict"], CONTROL_PAIR), "the same verdict and reasons, names aside")
                    self.assertEqual(len(x["findings"]), len(y["findings"]))
                    md = r["assess_files"]["report.md"]
                    self.assertEqual(sum(ln.startswith("- Provider ") and "(--providers-json)" in ln for ln in md.splitlines()), 2, "two Sources-read blocks")
                    self.assertEqual(visible(md), visible(control["assess_files"]["report.md"]))
                    self.assertNotIn("is given by both", r["assess_stderr"])
                    self.assertNotRegex(md, r"\[p(?!rovider word removed)", "a shortened line never cuts a placeholder")

    def test_report_and_assess_still_refuse_a_true_duplicate(self):
        case = ta.case_cape_all_inputs()
        case.inputs["--providers-json"] = _pair_providers("Safe Scanner", "SAFE scanner")
        r = ta.equivalence(case)
        self.assertEqual((r["exit_report"], r["exit_assess"], r["exit_assess_copy"]), (2, 2, 2))
        self.assertIn(f"lists provider {P} scanner twice", r["assess_stderr"])


def _angle(case: ta.Case, poisoned: bool) -> ta.Case:
    """R7: the CAPE all-inputs scenario with tag-like provider text on the forensics paths (Helius funder names, GMGN funder
    names, Jupiter tags, --providers-json names, alarm hints and details); the control has the same shapes, neutral words."""
    w = (lambda bad, ok: bad if poisoned else ok)
    for info in case.funded.values():
        if isinstance(info, dict) and info.get("funderName") == "KuCoin Hot Wallet 2":
            info["funderName"], info["funderType"] = w("<clean> Exchange", "<delta> Exchange"), w("<x safe>", "<x pine>")
    for i, r in enumerate(hf._unwrap(case.inputs["--gmgn-holders-json"])):
        nt = r.get("native_transfer")
        if isinstance(nt, dict) and i % 3 == 0:
            nt["name"] = w("<legit> Desk", "<river> Desk")
    for i, r in enumerate(hf._unwrap(case.inputs["--jupiter-holders-json"])):
        r["holderTags"] = ["bundler", w("<safe>", "<oak>"), w("<x rug proof>", "<x old oak>")] if i % 4 == 0 else ["bundler"]
    providers = case.inputs["--providers-json"]["providers"]
    providers[0].update(provider=w("<SAFE> Scanner", "<PINE> Scanner"), alarm_hint=w("<x low risk>", "<x oak tree>"))
    providers[1].update(provider=w("</clean> Tool", "</plain> Tool"), detail=w("s<?x?>afe", "p<?x?>ine"))
    return case


class AngleBracketPathTests(unittest.TestCase):
    """R7 end to end: tag-like provider text never shows a listed word in the forensics report, assessment or summary."""

    @classmethod
    def setUpClass(cls):
        cls.bad, cls.ok = ta.equivalence(_angle(ta.case_cape_all_inputs(), True)), ta.equivalence(_angle(ta.case_cape_all_inputs(), False))

    def test_no_listed_word_in_any_output_and_the_verdict_is_the_controls(self):
        for r in (self.bad, self.ok):
            self.assertEqual((r["exit_report"], r["exit_assess"], r["exit_assess_copy"]), (0, 0, 0))
        for flow in ("report_files", "assess_files", "copy_files"):
            for name in ("report.md", "assessment.json"):
                bad, ok = self.bad[flow].get(name), self.ok[flow].get(name)
                if bad is None:
                    continue
                with self.subTest(flow=flow, file=name):
                    self.assertEqual(visible(bad), visible(ok), "only this tool's own wording, as in the control run")
                    self.assertRegex(bad, MARKER)
        self.assertEqual(visible(self.bad["assess_stdout"]), visible(self.ok["assess_stdout"]))
        self.assertEqual((self.bad["verdict"], re.sub(r"\(.*\)", "", self.bad["flag"])), (self.ok["verdict"], re.sub(r"\(.*\)", "", self.ok["flag"])))
        md = self.bad["assess_files"]["report.md"]
        self.assertIn(f"- Provider {P} Scanner (--providers-json)", md, "a provider name is a label: its brackets go, as before; the word goes")
        self.assertIn(f"alarm hint: x {P}", md, "the alarm hint is a label too: its brackets go, as before; the word goes")
        self.assertNotRegex(md, r"\[p(?!rovider word removed)")


class ProvidersJsonAcceptanceTests(unittest.TestCase):
    """Which --providers-json files are accepted is unchanged: names are compared as before the rule; only what is
    printed loses the listed words."""

    def test_two_names_that_both_become_the_placeholder_are_still_two_providers(self):
        rows = [{"provider": n, "status": "ok", "largest_cluster_pct": 1.0, "unit": "percent"} for n in ("safe", "clean", "LOW")]
        findings = hf.normalize_findings_file(rows)
        self.assertEqual([f["provider"] for f in findings], [P, P, P])
        self.assertEqual(len({id(f) for f in findings}), 3)

    def test_a_duplicate_is_still_refused_and_the_message_holds_no_listed_word(self):
        rows = [{"provider": n, "status": "ok", "largest_cluster_pct": 1.0, "unit": "percent"} for n in ("Safe", "safe")]
        with self.assertRaises(hf.ConfigError) as cm:
            hf.normalize_findings_file(rows)
        self.assertEqual(str(cm.exception), f"--providers-json lists provider {P} twice; each provider must appear once")
        with self.assertRaises(hf.ConfigError) as cm:
            hf.normalize_findings_file([{"provider": "Clean Scan", "status": "ok", "largest_cluster_pct": 0.5}])
        self.assertIn(f"ambiguous for {P} scan", str(cm.exception))

    def test_reserved_and_presentation_only_names_are_refused_as_before(self):
        for name in ("bubblemaps_map", "Solana Tracker", "safe MadeOnSol"):
            with self.assertRaises(hf.ConfigError):
                hf.normalize_findings_file([{"provider": name, "status": "ok", "largest_cluster_pct": 1.0, "unit": "percent"}])


class OldRunFolderTests(unittest.TestCase):
    """A run folder saved before this rule (funder labels with listed words in funders.json) still assesses, and its
    report prints the placeholder; an edited label is still refused (test_assess.RefusalTests)."""

    def test_labels_saved_by_the_old_rule_are_read_with_the_rule(self):
        case = _poison(ta.case_cape_all_inputs(), True)
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "run"
            with mock.patch.object(hf, "safe_label", hf._label_chars):  # the label rule before HS-LABELS-T1
                code, _, _ = ta._run(["funders", case.mint, "--top", str(case.top), "--workers", "1", "--out", str(run)], fake=case.fake(), pairs=case.pairs)
            self.assertEqual(code, 0)
            saved = (run / "funders.json").read_text()
            self.assertIn("safe  clean  low risk", saved, "the old rule saved the words")
            code, out, err = ta.run_assess(case.mint, run)
            self.assertEqual(code, 0, err)
            md = (run / "report.md").read_text()
            self.assertEqual(visible(md), visible(md.replace(P, "")), "no listed word from the saved labels")
            self.assertNotIn("safe  clean  low risk", md)
            self.assertIn("[provider word removed x3]", md)


# ----------------------------------------------------------------------------- collectors: saved files and --present


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_gmgn_rows_saves_the_funder_name_without_listed_words(self):
        payload = copy.deepcopy(json.loads((FIX / "cape_gmgn.json").read_text()))
        for r, name in zip(hf._unwrap(payload)[:4], (TICKET_EXAMPLE, "S.A.F.E", "Binance", "LEGIT Wallet")):
            r.setdefault("native_transfer", {"from_address": r["address"], "timestamp": 1_790_000_000})["name"] = name
        rows, _ = gr.sanitize_rows(hf._unwrap(payload), 1_792_400_000)
        names = [r["native_transfer"]["name"] for r in rows[:4]]
        self.assertEqual(names, ["[provider word removed x3]", P, "Binance", f"{P} Wallet"])
        self.assertEqual(visible(json.dumps(rows)), [])

    def test_jupiter_rows_saves_tags_without_listed_words(self):
        rows, _ = jr.sanitize_rows([{"owner": tst.CAPE, "amount": 1.0, "tags": ["bundler", "Safe", "low risk", "Not A Rug", "smartMoney"]}])
        self.assertEqual(rows[0]["tags"], sorted({"bundler", P, "smartmoney"}))
        self.assertEqual(list(jr.tag_claims(rows)["tags"]), sorted([P, "bundler", "smartmoney"], key=lambda t: t))

    def test_solanatracker_saves_and_presents_risk_names_without_listed_words(self):
        def mutate(token, bundlers):
            token["risk"]["risks"] = [{"name": n, "level": "warning"} for n in ("Very Low Liquidity", "SAFE token", "Mint Authority Enabled", "no risk found")]
        run = self.tmp / "st"
        res = tst.write_result(run, mutate)
        self.assertEqual([f["name"] for f in res["token_risk"]["risk"]["risks"]], ["Very Low Liquidity", f"{P} token", "Mint Authority Enabled", f"{P} found"],
                         "R3: the documented liquidity name stays Solana Tracker's code in the file")
        lines = st.present(run)
        control = st.present(self._st_control())
        self.assertEqual(visible("\n".join(lines)), visible("\n".join(control)), "only the fixed note's own wording")
        self.assertIn("risk factors (Solana Tracker's claims): very thin liquidity (warning)", "\n".join(lines), "R3: printed in our words, level kept")
        self.assertTrue(lines[-1].startswith("  Provider words removed: 2 "), lines[-1])

    def test_solanatracker_documented_liquidity_names_exact_whole_name_only(self):
        """R3: only the two documented names, whole name, any case or spacing, are printed in our words; anything else
        with the word low is free text and loses the word."""
        names = ["Very Low Liquidity", "Low Liquidity", "LOW   liquidity", "very low liquidity", "Very Low Liquidity!", "Low Liquidity Pool"]
        run = self.tmp / "st-liq"
        res = tst.write_result(run, lambda t, b: t["risk"].update(risks=[{"name": n, "level": "danger"} for n in names]))
        self.assertEqual([f["name"] for f in res["token_risk"]["risk"]["risks"]],
                         ["Very Low Liquidity", "Low Liquidity", "Low Liquidity", "Very Low Liquidity", f"Very {P} Liquidity", f"{P} Liquidity Pool"],
                         "free text keeps the placeholder and its other words (B2: cut where the old rule cut, then marked)")
        text = "\n".join(st.present(run))
        self.assertIn("very thin liquidity (danger), thin liquidity (danger), thin liquidity (danger), very thin liquidity (danger), "
                      f"Very {P} Liquidity (danger), {P} Liquidity Pool (danger)", text)

    def _st_control(self) -> Path:
        run = self.tmp / "st-control"
        tst.write_result(run, lambda t, b: t["risk"].update(risks=[{"name": n, "level": "warning"} for n in ("Very Thin Liquidity", "NEW token", "Mint Authority Enabled", "no data found")]))
        return run

    def test_solanatracker_present_neutralizes_a_file_saved_before_the_rule(self):
        run = self.tmp / "st-old"
        tst.write_result(run)
        data = json.loads((run / st.OUT_FILE).read_text())
        data["token_risk"]["risk"]["risks"] = [{"name": "Safe", "level": "info"}]
        data["reason"] = "clean"
        (run / st.OUT_FILE).write_text(json.dumps(data))
        text = "\n".join(st.present(run))
        self.assertIn(f"{P} (info)", text)
        self.assertNotIn("Safe (info)", text)

    def test_madeonsol_saves_and_presents_labels_and_levels_without_listed_words(self):
        def mutate(t, b):
            t["token"]["deployer"]["tier"] = "SAFE dev"
            t["deployer_profile"]["deployer"]["tier"] = "SAFE dev"
            t["token"]["kol_activity"]["signal"] = "legit"
            t["buyer_quality"].update(confidence="low", signal="positive", score=72)
            b["bundle"]["holdings_basis"] = "clean_swaps"
        run = self.tmp / "mo"
        res = tmo.write_result(run, mutate)
        self.assertEqual(res["token"]["deployer"]["tier"], f"{P} dev")
        self.assertEqual(res["token"]["kol_activity"]["signal"], P)
        self.assertEqual(res["token"]["buyer_quality"]["confidence"], "low", "R3: MadeOnSol's documented level stays its code in the file")
        self.assertEqual(res["numbers"]["buyer_quality_confidence"]["value"], "low")
        saved = copy.deepcopy(res)
        saved["token"]["buyer_quality"]["confidence"] = saved["numbers"]["buyer_quality_confidence"]["value"] = "<code>"
        self.assertEqual(visible(json.dumps(saved)), visible(json.dumps(tmo.write_result(self.tmp / "mo-plain"))), "no other listed word in the saved file")
        lines = mo.present(run)
        text = "\n".join(lines)
        self.assertIn("data confidence weak", text, "R3: printed in our words")
        self.assertIn(f"tier {P} dev", text)
        self.assertIn(f"signal {P};", text)
        self.assertIn(f"basis {P}_swaps", text)
        control = self.tmp / "mo-control"
        tmo.write_result(control, lambda t, b: (t["token"]["deployer"].update(tier="NEW dev"), t["deployer_profile"]["deployer"].update(tier="NEW dev"),
                                                t["token"]["kol_activity"].update(signal="mixed"), t["buyer_quality"].update(confidence="medium", signal="positive", score=72),
                                                b["bundle"].update(holdings_basis="other_swaps")))
        self.assertEqual(visible(text), visible("\n".join(mo.present(control))))
        self.assertTrue(lines[-1].startswith("  Provider words removed: 3 "), lines[-1])
        for code, shown in (("medium", "medium"), ("high", "strong"), ("insufficient_data", "insufficient_data")):
            run2 = self.tmp / f"mo-{code}"
            tmo.write_result(run2, lambda t, b, code=code: t["buyer_quality"].update(confidence=code, signal="positive", score=72))
            self.assertIn(f"data confidence {shown})", "\n".join(mo.present(run2)))

    def test_fomoapi_saves_and_presents_handles_without_listed_words(self):
        run = self.tmp / "fa"
        res = tfa.write_result(run, lambda p: (p["holders"][0].update(handle="SafeTrader"), p["holders"][1].update(handle="LOW_RISK")))
        self.assertEqual([r["handle"] for r in res["holders"]], ["SafeTrader", P])
        lines = fa.present(run)
        text = "\n".join(lines)
        self.assertIn("SafeTrader ($", text)
        self.assertIn(f"{P} ($", text)
        self.assertTrue(lines[-1].startswith("  Provider words removed: 1 "), lines[-1])
        control = self.tmp / "fa-control"
        tfa.write_result(control, lambda p: (p["holders"][0].update(handle="SafeTrader"), p["holders"][1].update(handle="MID_DESK")))
        self.assertEqual(visible(text), visible("\n".join(fa.present(control))), "only the fixed note's own wording (NO_ALARM)")

    def test_no_placeholder_no_counted_line(self):
        for present, write in ((st.present, tst.write_result), (mo.present, tmo.write_result), (fa.present, tfa.write_result)):
            run = self.tmp / present.__module__
            write(run)
            lines = present(run)
            self.assertFalse(any("Provider words removed" in ln for ln in lines), present.__module__)


# ----------------------------------------------------------------------------- N2: labeled funders with no address


class LabeledUnknownFunderTests(unittest.TestCase):
    """N2: a provider can name a funder without its address (GMGN native_transfer.name with no from_address). Those wallets
    are counted in "via labeled funders" and are unknown-funder wallets at the same time; the cohort line now says so."""

    @classmethod
    def setUpClass(cls):
        cls.gmgn = json.loads((FIX / "cape_gmgn.json").read_text())
        for i, r in enumerate(hf._unwrap(cls.gmgn)):
            r["native_transfer"] = {**(r.get("native_transfer") or {}), "name": ["Binance", "KuCoin Hot Wallet 2", "FixedFloat Hot Wallet"][i % 3]}

    def report(self, payload):
        holders = cape_holders(launch=CAPE_LAUNCH)
        src = hf.provider_cohort_sources(holders, payload, None)
        a = hf.assess(holders, None, [], provider_cohorts=src)
        return src["gmgn"]["cohorts"], a, hf.markdown_report(ta.CAPE, holders, None, 0, a, src)

    def test_all_labeled_wallets_without_an_address_are_named(self):
        payload = gmgn_without_funders(self.gmgn, lambda i, f: False)
        cohorts, a, md = self.report(payload)
        c = max(cohorts, key=lambda c: c["wallets"])
        self.assertEqual(c["labeled_unknown_funder_wallets"], c["labeled_funder_wallets"])
        self.assertEqual(c["unknown_funder_wallets"], c["wallets"])
        n = c["labeled_funder_wallets"]
        self.assertIn(f"no known funder, funder unknown for {c['wallets']} of {c['wallets']} wallets, {n} via labeled funders, {n} of them with no funder address; flagged by", md)
        self.assertTrue(any(f"{n} through labeled funders, {n} of them with no funder address" in r for r in a["verdict"]["reasons"]))

    def test_some_labeled_wallets_without_an_address(self):
        payload = gmgn_without_funders(self.gmgn, lambda i, f: i % 2 == 0)
        cohorts, _, md = self.report(payload)
        for c in cohorts:
            members = set(c["members"])
            rows = [r for r in hf.gmgn_cohort_rows(payload) if r["wallet"] in members]
            self.assertEqual(c["labeled_unknown_funder_wallets"], sum(1 for r in rows if r["funder_label"] and not r["funder_address"]))
            if c["labeled_unknown_funder_wallets"]:
                self.assertIn(f"{c['labeled_funder_wallets']} via labeled funders, {c['labeled_unknown_funder_wallets']} of them with no funder address;", md)

    def test_with_every_address_known_the_line_is_as_before(self):
        cohorts, a, md = self.report(self.gmgn)
        for c in cohorts:
            self.assertEqual(c["labeled_unknown_funder_wallets"], 0)
        self.assertNotIn("of them with no funder address", md)
        self.assertFalse(any("of them with no funder address" in r for r in a["verdict"]["reasons"]))

    def test_counts_and_severities_do_not_move(self):
        for keep in (lambda i, f: False, lambda i, f: i % 2 == 0, lambda i, f: True):
            payload = gmgn_without_funders(self.gmgn, keep)
            cohorts, a, _ = self.report(payload)
            with mock.patch.object(hf, "labeled_funder_text", lambda c, via: f"{c['labeled_funder_wallets']} {via} labeled funders"):
                cohorts_old, a_old, _ = self.report(payload)
            self.assertEqual([(c["wallets"], c["severity"], c["labeled_funder_wallets"], c["unknown_funder_wallets"], c["distinct_funders"]) for c in cohorts],
                             [(c["wallets"], c["severity"], c["labeled_funder_wallets"], c["unknown_funder_wallets"], c["distinct_funders"]) for c in cohorts_old])
            self.assertEqual((a["verdict"]["level"], a["flag"]), (a_old["verdict"]["level"], a_old["flag"] | {"why": a["flag"]["why"]}))


# ----------------------------------------------------------------------------- this tool's own wording is untouched


def _b58(i: int) -> str:
    digits, out, n = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", "", i + 1
    while n:
        n, r = divmod(n, 58)
        out = digits[r] + out
    return ("Sc" + out).ljust(40, "z")


def _solscanner_result(wallets: int, confidence: str = "high") -> dict:
    """A saved SolScanner result with one bundle group of `wallets` wallets, 44% of supply, risk 96 (it raises the hint)."""
    addrs = [_b58(7000 + i) for i in range(wallets)]
    return {"provider": "SolScanner", "mint": ta.CAPE, "status": "ok", "reason": None, "scanned_at": "2026-10-14T10:01:00Z", "is_stale": False, "scan_age_min": 4.0,
            "groups": [{"wallets": [{"address": a, "share_pct": 44.0 / wallets} for a in addrs], "risk_score": 96, "confidence": confidence, "bundle_type": "mixed"}]}


def _full_report(findings: list, solscanner: dict | None = None) -> tuple[dict, str]:
    with ta.frozen_clock():
        a = hf.assess(holders_dict(), None, findings, solscanner=solscanner)
        return a, hf.markdown_report(ta.CAPE, holders_dict(), None, 0, a)


class OwnWordingTests(unittest.TestCase):
    def test_empty_map_report_keeps_its_own_wording_and_has_no_count_line(self):
        """R1: with an empty Bubblemaps map the engine's own detail "unknown, not clean" is printed as written (Sources read
        and the detectors list), and the report has no "Provider words removed" line (it removed nothing)."""
        empty = hf.bubblemaps_finding({"mint": ta.CAPE, "parse_ok": True, "age_min_after": 1.0, "clusters": []}, ta.CAPE)
        a, md = _full_report([empty])
        self.assertEqual(md.count("unknown, not clean"), 2, md)
        self.assertNotIn("Provider words removed", md)
        self.assertNotRegex(md, MARKER)
        _, md_skipped = _full_report([])  # the "skipped" row assess inserts for a map that did not run: own wording too
        self.assertIn("no --bubblemaps-json given, so the step did not run", md_skipped)
        self.assertNotRegex(md_skipped, MARKER)

    def test_solscanner_wallet_counts_stay_numbers(self):
        """R2: SolScanner's own hint ("corrob only 10w r96 44pct ...") is built from validated numbers: 10w and 100w are
        wallet counts, never read as a word; no placeholder, no count line."""
        for wallets in (10, 100):
            result = _solscanner_result(wallets)
            finding = hf.solscanner_finding_for(result, ta.FROZEN)
            self.assertTrue(finding["alarm_hint"].startswith(f"corrob only {wallets}w r96"), finding["alarm_hint"])
            a, md = _full_report([finding], result)
            with self.subTest(wallets=wallets):
                self.assertIn(f"solscanner alarm hint: corrob only {wallets}w r96", md)
                self.assertNotRegex(md, MARKER)
                self.assertNotIn("Provider words removed", md)
                self.assertTrue(any(f"corrob only {wallets}w" in r for r in a["verdict"]["reasons"]))

    def test_solscanner_levels_print_in_our_words_and_stay_codes_in_the_file(self):
        """R3: SolScanner's validated confidence (low / medium / high) prints as weak / medium / strong; the saved result
        keeps SolScanner's code (assess re-validates it against that list)."""
        for code, shown in (("low", "weak"), ("medium", "medium"), ("high", "strong")):
            result = _solscanner_result(98, code)
            hf.validate_solscanner_result(result)
            _, md = _full_report([hf.solscanner_finding_for(result, ta.FROZEN)], result)
            self.assertIn(f"risk 96, confidence {shown}, type mixed", md)
            self.assertNotRegex(md, MARKER)
            self.assertEqual(result["groups"][0]["confidence"], code)

    def test_every_own_text_site_keeps_its_wording(self):
        """R2 audit: the own texts that reach a provider-text print path are printed as written."""
        self.assertEqual(hf._display_name("own detectors"), "own detectors")
        unreadable = hf.normalize_finding({"provider": "okx", "status": "ok"})
        self.assertEqual(hf.finding_text(unreadable, "detail"), "answered but unreadable: no usable value")
        for code in hf.SOLSCANNER_OWN_REASONS:
            self.assertEqual(pw.neutralize(code), (code, 0), code)
        blk = hf._solscanner_source({"groups": [], "reason": "network_error"}, {"provider": "solscanner", "status": "unavailable"})
        self.assertEqual(blk["lines"], ["could not be read: network_error"])
        blk = hf._solscanner_source({"groups": [], "reason": "safe"}, {"provider": "solscanner", "status": "unavailable"})
        self.assertEqual(blk["lines"], [f"could not be read: {P}"], "an unknown reason in an edited file is provider text")
        with tempfile.TemporaryDirectory() as tmp:  # the collectors' own notes are printed as written ("a low number is not an all-clear")
            for module, write in ((st, tst.write_result), (mo, tmo.write_result), (fa, tfa.write_result)):
                run = Path(tmp) / module.__name__
                write(run)
                text = "\n".join(module.present(run))
                self.assertIn(module.PRESENTATION_NOTE, text)
                self.assertIn(module.CANNOT_SEE, text)
                self.assertNotRegex(text, MARKER)

    def test_fixed_wording_is_not_neutralized(self):
        empty = hf.bubblemaps_finding({"mint": ta.CAPE, "parse_ok": True, "age_min_after": 1.0, "clusters": []}, ta.CAPE)
        self.assertIn("unknown, not clean", empty["detail"])
        sources = hf.read_sources(holders_dict(), None, [empty], None)
        self.assertIn("no clusters parsed (drained or empty map); unknown, not clean", sources[1]["lines"][0])
        self.assertIn("a low number is not an all-clear", st.PRESENTATION_NOTE)
        self.assertEqual(hf.normalize_finding({"provider": "solscanner", "status": "empty", "detail": "corroboration only not all clear"})["detail"],
                         "corroboration only not all clear")


if __name__ == "__main__":
    unittest.main()
