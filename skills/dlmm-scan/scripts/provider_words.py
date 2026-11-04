"""Verdict words in untrusted provider text (HS-LABELS-T1): the one shared rule for both engines and every collector.

This skill never calls a holder set "clean", "safe" or "low" (the CAPE lesson). Provider text is untrusted: funder names,
tags, risk-factor names, KOL handles, usernames, statuses and hand-supplied provider findings come from someone else, and a
provider label such as "safe | clean | low risk" must never sit next to a FLAG where it could read as this tool's verdict.
Every provider-supplied text value passes through this rule before it reaches a report, a summary, a --present block or a
saved display field: a verdict word or phrase is replaced by PLACEHOLDER (several in a row by one counted placeholder,
"[provider word removed x3]"), and every report and --present block that shows one says how many it shows (removed_line).
This tool's own fixed wording never passes through here.

The rule (documented in SKILL.md, "Provider text: verdict words removed"):
  words    clean, safe, safer, safest, low, legit, safu ("safu" is the crypto spelling of safe, as in "funds are safu")
  phrases  low risk, lowest risk, no risk, zero risk, risk free, rug free, safe to buy, not a rug, no rug, rug proof,
           no alarm (this tool's calmest level is NO_ALARM)
Matching is whole-word and case-insensitive. A word inside a longer word is never touched ("SafePal", "Lowell", "Cleanup",
"Slow", "Unsafe", "Saferoom" pass unchanged); a hyphen, dot, underscore or any other sign is a word boundary ("Clean-up" and
"safe-pal" lose their verdict word). A phrase matches with any separators or none between its words ("low-risk", "LowRisk",
"rug_proof", "NO_ALARM"). Before matching, the text is made inert: bidi controls dropped (an RLO can make "EFAS" show as
SAFE), HTML entities decoded and HTML tags and comments dropped ("S&#65;FE", "s<b></b>afe"), markdown links reduced to
their text; HTML "bogus comments" ("<?x?>", "</ x>", "<![CDATA[x]]>") are dropped too. Angle brackets that are not an HTML
tag stay ("bundle <5% and >2%", "C++ <dev>"); any other tag-like text ("<x>", "<SAFE>") stays and is read both ways, hidden
and visible, so it can neither split a word ("s<x></x>afe" is caught) nor hide one ("<SAFE>" is caught).
It is then folded the way the presentation-only provider matcher of helius_forensics.py folds provider names (that matcher
uses the same tables, defined here): Unicode compatibility folding as in NFKC done through NFKD, accents and invisible format
characters (zero-width, soft hyphen) dropped, Cyrillic / Greek / small-capital / Latin look-alikes mapped to Latin; a second
pass reads digits and signs used as letters ("5AF3", "$afe", "l0w", "c|ean"), a capital I used as l and "rn" used as m;
repeated letters are collapsed ("saaafe", "cleeean"). Letters spaced out or split by signs are joined ("s a f e", "S.A.F.E",
"c*l*e*a*n", "**safe**", "sa-fe"); a run of single spaced letters is searched for a verdict word anywhere inside it.

A sanitizer cuts like it did before this rule, then marks (cut()): the rule runs on the raw text (so "$ a f e" is caught
before the "$" is dropped), each placeholder counts as the length of the text it replaced, the sanitizer's own character
rule and cut run exactly as before (so the cut falls where it fell, and "same fund source 0.947 vs Low he" keeps its
0.947 as "same fund source 0.947 vs [provider word removed] he"), and the rule runs again on what is left. A text can
therefore be longer than its cap only by the placeholders' extra length, and never by more than GROWTH_LIMIT (three
placeholders): past that, the provider's last words are dropped (fit(); a placeholder is never cut).

Standard library only, no network, no key: imported by helius_forensics.py, ha/gating.py, ha/evidence.py, ha/analysis.py,
ha/report.py, jupiter_rows.py, solanatracker.py, madeonsol.py and fomoapi.py. gmgn_rows.py keeps a stand-alone copy of the
shared block (its SELF-CONTAINED COPY rule); tests/forensics/test_provider_words.py keeps the two identical.
"""

from __future__ import annotations

import html
import re
import unicodedata
from typing import Any, Callable, Iterable

# ---- BEGIN shared verdict-word block (gmgn_rows.py holds a byte-identical copy; test_provider_words.py checks it) --------
# ---- folding tables (moved here from helius_forensics.py by HS-LABELS-T1; that module imports them, unchanged) ----------
# HS-PROV-T2 (criterion 7): common Cyrillic / Greek / small-capital / Latin look-alikes mapped to Latin, and digits and signs
# used as letters. The presentation-only provider matcher (helius_forensics.presentation_only_provider) and the verdict-word
# rule below fold with exactly these tables.
_LOOKALIKE_PAIRS = ("АA ВB ЕE КK МM НH ОO РP СC ТT УY ХX ЅS ІI ЈJ Ӏl "
                    "ԚQ ԜW ҮY аa вb еe кk мm нh оo рp сc тt уy хx ѕs "
                    "іi јj ӏl ԁd ԛq ԝw үy ѵv ΑA ΒB ΕE ΖZ ΗH ΙI ΚK ΜM "
                    "ΝN ΟO ΡP ΤT ΥY ΧX αa βb γy εe ιi κk νv οo ρp τt "
                    "υu χx ωw ᴀa ʙb ᴄc ᴅd ᴇe ꜰf ɢg ʜh ɪi ᴊj ᴋk ʟl ᴍm "
                    "ɴn ᴏo ᴘp ʀr ꜱs ᴛt ᴜu ᴠv ᴡw ʏy ᴢz ıi łl øo đd ħh "
                    "ŧt ƒf ŁL ØO ĐD ĦH ŦT ɡg")
PROVIDER_LOOKALIKES = str.maketrans({pair[0]: pair[1] for pair in _LOOKALIKE_PAIRS.split()})
PROVIDER_LOOKALIKE_SIGNS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a", "|": "l", "!": "i"})

# ---- the rule ------------------------------------------------------------------------------------------------------------
PLACEHOLDER = "[provider word removed]"
VERDICT_WORDS = ("clean", "safe", "safer", "safest", "low", "legit", "safu")
VERDICT_PHRASES = (("low", "risk"), ("lowest", "risk"), ("no", "risk"), ("zero", "risk"), ("risk", "free"), ("rug", "free"), ("safe", "to", "buy"),
                   ("not", "a", "rug"), ("no", "rug"), ("rug", "proof"), ("no", "alarm"))
_MAX_SPAN_TOKENS = 24            # letters joined into one candidate word at most (a spaced-out phrase fits)
_MAX_JOINED = 64                 # longest joined candidate looked at (doubled letters included)
_DROPPED = frozenset({"Mn", "Me", "Cf"})  # accents and other combining marks, zero-width and other invisible format characters
_MARKER = re.compile(r"(\[provider word removed(?: x\d+)?\])")  # one placeholder, or several collapsed into one: "[provider word removed x3]"
_MARKER_RUN = re.compile(r"\[provider word removed(?: x\d+)?\](?:[^\w\[\]]*\[provider word removed(?: x\d+)?\])+")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]")  # bidi embedding, override, isolate and mark characters
# HTML element names (HTML living standard plus common obsolete ones): only these, comments and declarations are dropped as
# tags, so angle brackets in ordinary text stay ("bundle <5% and >2%", "C++ <dev>"); HS-LABELS-T1 review item N1
HTML_ELEMENTS = ("a abbr acronym address area article aside audio b base basefont bdi bdo big blink blockquote body br button "
                 "canvas caption center cite code col colgroup data datalist dd del details dfn dialog dir div dl dt em embed "
                 "fieldset figcaption figure font footer form frame frameset h1 h2 h3 h4 h5 h6 head header hgroup hr html i "
                 "iframe img input ins kbd label legend li link main map mark marquee math menu meta meter nav nobr noscript "
                 "object ol optgroup option output p param picture plaintext pre progress q rp rt ruby s samp script search "
                 "section select slot small source span strike strong style sub summary sup svg table tbody td template "
                 "textarea tfoot th thead time title tr track tt u ul var video wbr xmp").split()
# Dropped as a renderer drops them: comments, CDATA sections, and the HTML "bogus comments" ("<!x>", "<?x?>", "</ x>", "</>",
# all up to the next ">"); and HTML element tags, whose name follows "<" or "</" directly ("< b >" is text)
_TAG = re.compile(r"<!--.{0,500}?-->|<!\[CDATA\[.{0,500}?\]\]>|<![^>]{0,200}>|<\?[^>]{0,200}>|</(?![A-Za-z])[^>]{0,200}>"
                  r"|</?(?:" + "|".join(HTML_ELEMENTS) + r")(?=[\s/>])[^<>]{0,200}>", re.IGNORECASE | re.DOTALL)
# Any other tag-like text ("<dev>", "<x>", "<SAFE>") stays in the output, so the rule reads it both ways (repair R7): hidden
# (a renderer may hide it: "s<x></x>afe" reads as safe) and visible (a plain-text reader sees it: "<SAFE>" reads as SAFE)
_TAG_LIKE = re.compile(r"</?[A-Za-z][^<>]{0,200}>")
_MD_LINK = re.compile(r"\[([^\[\]]{0,200})\]\([^()]{0,500}\)")
# Two rare letters that every sanitizer's character rule keeps: while a sanitizer cuts, each placeholder is held as a run of
# one of them, as long as the text it replaced (cut()); a provider text cannot hold them (they read as "o")
_HOLD = ("\ua66d", "\ua66e")
_HOLD_RUN = re.compile("\ua66d+|\ua66e+")
GROWTH_LIMIT = 3 * len(PLACEHOLDER)  # a text is never longer than its cap plus this (three placeholders' worth)


def inert(text: str) -> str:
    """What the text says, without what changes how it renders: HTML entities decoded (twice, for "&amp;#65;"), HTML tags
    and comments dropped, markdown links reduced to their text, bidi controls dropped. Used before matching, on provider
    text only. Angle brackets that are not an HTML tag are kept."""
    text = html.unescape(html.unescape(text))
    while True:
        stripped = _MD_LINK.sub(r"\1", _TAG.sub("", text))
        if stripped == text:
            break
        text = stripped
    return _BIDI.sub("", text)


def _collapse(text: str) -> str:
    return re.sub(r"(.)\1+", r"\1", text)


def _signs_key(text: str) -> str:
    """The second pass also reads "rn" as m and a capital I (casefolded to i) as l, as the provider matcher does."""
    return text.replace("rn", "m").replace("i", "l")


def _targets(key: Callable[[str], str]) -> tuple[frozenset[str], frozenset[str]]:
    whole = {key(w) for w in VERDICT_WORDS} | {key("".join(p)) for p in VERDICT_PHRASES}
    return frozenset(whole), frozenset(_collapse(t) for t in whole)


_PASSES = {"plain": (lambda s: s, *_targets(lambda s: s)), "signs": (_signs_key, *_targets(_signs_key))}


def _folded(text: str, signs: bool, hide: bool) -> list[tuple[str, int]]:
    """(folded character, index in `text`) for every character that survives folding (tag-like text skipped when `hide`)."""
    hidden = {i for m in _TAG_LIKE.finditer(text) for i in range(m.start(), m.end())} if hide else set()
    out: list[tuple[str, int]] = []
    for i, ch in enumerate(text):
        if i in hidden:
            continue
        for part in unicodedata.normalize("NFKD", ch):
            if unicodedata.category(part) in _DROPPED:
                continue
            for c in part.translate(PROVIDER_LOOKALIKES).casefold().translate(PROVIDER_LOOKALIKES):
                out.append((c.translate(PROVIDER_LOOKALIKE_SIGNS) if signs else c, i))
    return out


def _tokens(text: str, signs: bool, hide: bool) -> list[tuple[str, int, int]]:
    """Runs of letters and digits after folding: (folded text, first index, end index) in `text`."""
    tokens: list[tuple[str, int, int]] = []
    word: list[str] = []
    start = end = 0
    for c, i in _folded(text, signs, hide):
        if c.isalnum():
            if not word:
                start = i
            word.append(c)
            end = i + 1
        elif word:
            tokens.append(("".join(word), start, end))
            word = []
    if word:
        tokens.append(("".join(word), start, end))
    return tokens


def _matches(text: str, signs: bool, hide: bool = False) -> list[tuple[int, int]]:
    """(start, end) ranges of `text` that hold a verdict word or phrase, for one folding pass."""
    key, whole, collapsed = _PASSES["signs" if signs else "plain"]
    tokens = _tokens(text, signs, hide)
    n = len(tokens)
    if not n:
        return []

    def is_target(joined: str, wanted: frozenset[str], wanted_collapsed: frozenset[str]) -> bool:
        k = key(joined)
        return k in wanted or _collapse(k) in wanted_collapsed

    def joinable(k: int) -> bool:
        """Tokens k and k+1 form one word: only signs between them (no space), or both are single spaced letters (a letter
        repeated, "rrr", counts as one letter)."""
        between = text[tokens[k][2]:tokens[k + 1][1]]
        tight = not any(ch.isspace() for ch in (_TAG_LIKE.sub("", between) if hide else between))
        return tight or (len(_collapse(tokens[k][0])) == 1 and len(_collapse(tokens[k + 1][0])) == 1)

    joins = [joinable(k) for k in range(n - 1)]
    words: dict[int, list[tuple[int, str]]] = {}  # start token -> [(end token, joined text)] of every candidate word
    found: list[tuple[int, int]] = []
    for i in range(n):
        joined = ""
        for j in range(i, min(n, i + _MAX_SPAN_TOKENS)):
            if j > i and not joins[j - 1]:
                break
            joined += tokens[j][0]
            if len(joined) > _MAX_JOINED:
                break
            words.setdefault(i, []).append((j, joined))
            if is_target(joined, whole, collapsed):
                found.append((tokens[i][1], tokens[j][2]))
    for phrase in VERDICT_PHRASES:  # word by word, any separators between the words
        wanted = [(frozenset({key(w)}), frozenset({_collapse(key(w))})) for w in phrase]

        def ends(start: int, index: int) -> list[int]:
            if index == len(phrase):
                return [start - 1]
            out: list[int] = []
            for j, joined in words.get(start, []):
                if is_target(joined, *wanted[index]):
                    out += ends(j + 1, index + 1)
            return out

        for i in range(n):
            for last in ends(i, 0):
                found.append((tokens[i][1], tokens[last][2]))
    return found


def marker(n: int) -> str:
    """The placeholder for n removed words or phrases in a row."""
    return PLACEHOLDER if n == 1 else f"[provider word removed x{n}]"


def _marker_count(text: str) -> int:
    found = re.fullmatch(r"\[provider word removed(?: x(\d+))?\]", text)
    return int(found.group(1)) if found and found.group(1) else 1


def _spans(piece: str) -> list[list[int]]:
    """Every verdict word or phrase in `piece` as [start, end], overlapping ones merged."""
    merged: list[list[int]] = []
    hides = (False, True) if _TAG_LIKE.search(piece) else (False,)  # without tag-like text the two readings are the same
    found = [span for signs in (False, True) for hide in hides for span in _matches(piece, signs, hide)]  # every reading
    for start, end in sorted(set(found)):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def _replace(text: str) -> tuple[list[str], list[str | None]]:
    """The text made inert with every verdict word or phrase replaced, as pieces: provider text at even and placeholders
    at odd indices; and for each placeholder the text it replaced (None for a placeholder already in the text)."""
    out, replaced = [""], []
    for k, part in enumerate(_MARKER.split(text)):
        if k % 2:
            out += [part, ""]
            replaced.append(None)
            continue
        piece, at = inert(part), 0
        for start, end in _spans(piece):
            out[-1] += piece[at:start]
            out += [PLACEHOLDER, ""]
            replaced.append(piece[start:end])
            at = end
        out[-1] += piece[at:]
    return out, replaced


def neutralize(text: Any) -> tuple[Any, int]:
    """(text made inert, with every verdict word or phrase replaced by PLACEHOLDER, how many were replaced). A placeholder
    already in the text is kept as it is (so the rule can run twice); anything that is not a string is returned unchanged."""
    if not isinstance(text, str) or not text:
        return text, 0
    pieces, replaced = _replace(text)
    return "".join(pieces), sum(1 for r in replaced if r is not None)


def collapse(text: str) -> str:
    """Placeholders separated only by spaces or signs become one counted placeholder ("[provider word removed x3]")."""
    return _MARKER_RUN.sub(lambda m: marker(sum(_marker_count(x) for x in _MARKER.findall(m.group(0)))), text)


def fit(text: str, cap: int) -> str:
    """The text with its placeholders collapsed and, when it is longer than `cap`, the last words of provider text dropped
    (never a placeholder) until it fits; if only placeholders are left and they still do not fit, one counted placeholder
    (the shortest honest form). A text without a placeholder is returned as it is. Used for the growth limit only: the
    normal cut is cut()'s, where the old rule cut."""
    text = collapse(text)
    if len(text) <= cap or not _MARKER.search(text):
        return text
    total = sum(_marker_count(x) for x in _MARKER.findall(text))
    parts = _MARKER.split(text)
    while len(collapse("".join(parts)).strip()) > cap:
        k = next((i for i in range(len(parts) - 1, -1, -2) if parts[i].strip()), None)
        if k is None:
            break
        last = re.search(r"\S+\s*$", parts[k])
        parts[k] = parts[k][:last.start()]
    text = collapse("".join(parts)).strip()
    return text if len(text) <= cap else marker(total)


def neutral(text: Any) -> Any:
    """neutralize() without the count, placeholders in a row collapsed; for text that is already cut (a saved label) or
    was never cut. Never longer than the text plus GROWTH_LIMIT."""
    out, _ = neutralize(text)
    if not isinstance(out, str) or not _MARKER.search(out):
        return out
    return fit(collapse(out), len(text) + GROWTH_LIMIT)


def cut(value: str, clean: Callable[[str], str], cap: int, trim: bool = True) -> str:
    """Cut like the old rule, then mark (HS-LABELS-T1 B2). The old rule of a sanitizer was clean(value)[:cap], stripped
    when `trim`. Here the rule runs on the raw text first (a spelling that uses signs `clean` drops, "$ a f e", is caught
    before they go); each placeholder is held as a run of one hold letter as long as clean() keeps of the text it replaced
    (a placeholder already in the text: one letter), so the old rule cuts where it cut; the runs become placeholders again,
    the rule runs once more (a cut or a dropped sign can make a word: "Lowell" cut to "Low"), placeholders in a row are
    collapsed. The result is longer than `cap` only by the placeholders' extra length, never by more than GROWTH_LIMIT.
    Without a verdict word, HTML tag, entity, markdown link or bidi control it is the old rule exactly."""
    pieces, replaced = _replace(value)
    held: list[str] = []
    for k, piece in enumerate(pieces):
        if k % 2 == 0:
            held.append(piece.replace(_HOLD[0], "o").replace(_HOLD[1], "o"))
        else:
            size = 1 if replaced[k // 2] is None else max(1, len(clean(replaced[k // 2])))
            held.append(_HOLD[(k // 2) % 2] * size)  # neighbouring placeholders alternate letters: their runs stay apart
    text = clean("".join(held))[:cap]
    text = text.strip() if trim else text
    marks = iter(pieces[1::2])
    text = _HOLD_RUN.sub(lambda m: next(marks, PLACEHOLDER), text)
    text = fit(collapse(neutralize(text)[0]), cap + GROWTH_LIMIT)
    return text.strip() if trim else text


def label(value: Any, strip: re.Pattern[str] | Callable[[str], str], cap: int = 32) -> str | None:
    """A short inert label: cut() with `strip` (a pattern of the characters a label cannot hold, or a function that drops
    them) as the character rule. None for anything that is not non-blank text. A label that is already safe comes back
    unchanged, so a saved label read back gives the same label. Without a verdict word, HTML tag, entity, markdown link or
    bidi control the result is the old rule exactly: strip(value)[:cap].strip()."""
    if not isinstance(value, str) or not value.strip():
        return None
    drop = strip if callable(strip) else (lambda s: strip.sub("", s))  # a compiled pattern is not callable
    return cut(value, drop, cap) or None
# ---- END shared verdict-word block ---------------------------------------------------------------------------------------


def count(texts: Iterable[Any]) -> int:
    """How many provider words or phrases the given lines show as removed (a counted placeholder counts its number)."""
    return sum(_marker_count(m) for t in texts if isinstance(t, str) for m in _MARKER.findall(t))


def keep_whole(text: str, at: int) -> str:
    """text[:at] for a line this tool shortens, moved past a placeholder the cut would split (a placeholder is never cut:
    "[p..." would read as nothing). Without a placeholder at the cut it is text[:at] exactly."""
    for m in _MARKER.finditer(text):
        if m.start() < at < m.end():
            return text[:m.end()]
    return text[:at]


def removed_line(n: int) -> str:
    """The one counted line every report and --present block adds when it shows a placeholder."""
    return (f"Provider words removed: {n} (shown as {PLACEHOLDER}, several in a row as [provider word removed xN]: a provider's own "
            "word or phrase that could read as a verdict, removed under this skill's rule; it is the provider's text, never this tool's verdict)")


# Provider levels checked against a short documented list (SolScanner's group confidence, MadeOnSol's buyer-quality data
# confidence) are printed in this tool's own words, never as the provider's "low" (HS-LABELS-T1 R3); the saved files keep the
# provider's code.
LEVEL_WORDS = {"low": "weak", "medium": "medium", "high": "strong"}


def level_text(value: Any) -> str | None:
    """A documented provider level in this tool's own words; None when it is not one of them."""
    return LEVEL_WORDS.get(value.strip().lower()) if isinstance(value, str) else None
