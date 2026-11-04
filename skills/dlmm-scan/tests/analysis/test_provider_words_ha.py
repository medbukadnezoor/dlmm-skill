"""HS-LABELS-T1 in the analysis engine: provider text (Jupiter's token symbol, name and launchpad, Jupiter tags and audit
flags, Helius identity names, --external-artifact provider names, details and alarm hints) never prints "clean", "safe" or
"low" or the other listed words and phrases; they are replaced by "[provider word removed]" (several in a row by one counted
placeholder) and counted. Two providers whose names both lose a word stay two providers (R5). Jupiter's audit flags print
only as true / false (R4). Bidi controls, HTML and markdown links are made inert. Classification, signals, verdict and flag
are unchanged. Offline: fake Helius and Jupiter clients."""

import html
import json
import re
import unicodedata

import provider_words as pw
from ha import gating, report
from test_analysis import W1, W2, FakeHelius, FakeJupiter, run

P = pw.PLACEHOLDER
OWN = {"no alarm"}  # this tool's own wording in every analysis report ("NO_ALARM needs at least 60%"), never removed
MARKER = re.compile(r"\[provider word removed(?: x\d+)?\]")
WORDS = ("clean", "safe", "safer", "safest", "low", "legit", "safu")
PHRASES = ("low risk", "lowest risk", "no risk", "zero risk", "risk free", "rug free", "safe to buy", "not a rug", "no rug", "rug proof", "no alarm")


def visible(text):
    """Listed words a reader could make out (letters split by signs only, phrases across any gap), on two foldings, with
    tags read both ways (repair R7): as written ("<SAFE>") and hidden, as a renderer shows them ("s<x></x>afe")."""
    text = MARKER.sub(" qxq ", html.unescape(html.unescape(text)))
    found = []
    for target in WORDS + PHRASES:
        hits = []
        for signs, source in ((s, x) for s in (False, True) for x in (text, re.sub(r"<[^<>]*>", "", text))):
            folded = "".join(c.translate(pw.PROVIDER_LOOKALIKES).casefold().translate(pw.PROVIDER_LOOKALIKES) for c in unicodedata.normalize("NFKD", source)
                             if unicodedata.category(c) not in ("Mn", "Me", "Cf"))
            if signs:
                folded = folded.translate(pw.PROVIDER_LOOKALIKE_SIGNS).replace("rn", "m").replace("i", "l")
            key = (lambda w: w.replace("rn", "m").replace("i", "l")) if signs else (lambda w: w)
            words = [r"[^0-9a-z\s]*".join(re.escape(c) + "+" for c in key(w)) for w in target.split()]
            hits.append(len(re.findall(r"(?<![0-9a-z])" + r"[^0-9a-z]*".join(words) + r"(?![0-9a-z])", folded)))
        found += [target] * max(hits)
    return sorted(found)


def make(poisoned, tmp_path):
    w = (lambda bad, ok: bad if poisoned else ok)

    class Jupiter(FakeJupiter):
        def token(self, mint):
            t = super().token(mint)
            t.update(symbol=w("SAFE", "PINE"), name=w("Clean Low Risk Coin", "Quiet River Coin"), launchpad=w("legit.fun", "river.fun"))
            return t

        def holders(self, mint, limit=100):
            d = super().holders(mint, limit)
            d["holders"][0]["tags"] = ["bundler", w("safe", "oak"), w("not a rug", "old oak")]
            return d

    class Helius(FakeHelius):
        def identities(self, owners):
            self._hit("identities")
            return {W1: {"name": w("SAFU Treasury", "Pine Treasury"), "category": "Fund", "tags": []}, W2: {"name": w("s a f e wallet", "p i n e wallet"), "category": None, "tags": []}}

    path = tmp_path / f"evidence-{poisoned}.json"
    path.write_text(json.dumps({"provider_findings": [
        {"provider": w("Safe Scanner", "Pine Scanner"), "status": "ok", "unit": "percent", "largest_cluster_pct": 5.0, "data_age_min": 1.0,
         "alarm_hint": w("low risk, legit", "same fund source"), "detail": w("clean result", "plain result")},
        {"provider": w("NO_ALARM bot", "TALL_PINE bot"), "status": "empty", "unit": "percent", "detail": w("rug proof", "rug report")},
    ]}))
    return run(helius=Helius(), jupiter=Jupiter(), external_artifact=path)


def test_no_listed_word_reaches_the_report_or_the_artifact(tmp_path):
    bad, ok = make(True, tmp_path), make(False, tmp_path)
    text_bad, text_ok = report.render(bad), report.render(ok)
    assert visible(text_bad) == visible(text_ok), "only this tool's own wording, the same as in the control run"
    assert MARKER.search(text_bad) and not MARKER.search(text_ok)
    blob_bad, blob_ok = json.dumps(bad), json.dumps(ok)
    assert visible(blob_bad) == visible(blob_ok)
    assert "Provider words removed:" in text_bad and "Provider words removed:" not in text_ok
    count = int(re.search(r"- Provider words removed: (\d+) ", text_bad).group(1))
    assert count == pw.count([text_bad.replace(re.search(r"- Provider words removed: .*", text_bad).group(0), "")])


def test_every_text_path_shows_the_placeholder(tmp_path):
    art = make(True, tmp_path)
    text = report.render(art)
    assert text.startswith(f"# Holder analysis: {P} (")                                       # token symbol
    assert art["token"]["name"] == "[provider word removed x2] Coin" and art["token"]["launchpad"] == f"{P}.fun"  # name ("Clean", "Low Risk"), launchpad
    rows = {r["owner"]: r for r in art["top_holders"]}
    assert rows[W1]["identity"] == f"{P} Treasury" and rows[W2]["identity"] == f"{P} wallet"  # Helius identity names
    assert rows[W1]["jupiter_tags"] == ["bundler", P, P]                                      # Jupiter tags (one placeholder each)
    assert re.search(r"tags on top holders: .*\[provider word removed\] 2", text)
    names = [f["provider"] for f in art["coverage"]["findings"]]
    assert names == [f"{P} Scanner", f"{P} bot"]                                               # --external-artifact provider names
    assert art["coverage"]["findings"][0]["alarm_hint"] == "[provider word removed x2]"         # alarm hint
    assert art["coverage"]["findings"][0]["detail"] == f"{P} result" and art["coverage"]["findings"][1]["detail"] == P
    assert any(r.startswith(f"{P} Scanner alarm hint: [provider word removed x2]") for r in art["overall"]["verdict"]["reasons"])
    assert f"| {P} Treasury |" in text and f"| bundler,{P},{P} |" in text                     # top-holders table


def test_classification_signals_verdict_and_flag_are_unchanged(tmp_path):
    bad, ok = make(True, tmp_path), make(False, tmp_path)
    assert [(r["owner"], r["kind"], r["share"]) for r in bad["top_holders"]] == [(r["owner"], r["kind"], r["share"]) for r in ok["top_holders"]]
    assert [(s["name"], s["value"], s["level"]) for s in bad["signals"]] == [(s["name"], s["value"], s["level"]) for s in ok["signals"]]
    for key in ("holder_risk", "data_quality", "unknown_signals", "core_unknown_signals", "provider_disagreements"):
        assert bad["overall"][key] == ok["overall"][key], key
    vb, vo = bad["overall"]["verdict"], ok["overall"]["verdict"]
    assert vb["level"] == vo["level"] and len(vb["reasons"]) == len(vo["reasons"])
    fb, fo = bad["overall"]["flag"], ok["overall"]["flag"]
    assert (fb["level"], fb["caveat"], re.sub(r"\(.*\)", "", fb["label"])) == (fo["level"], fo["caveat"], re.sub(r"\(.*\)", "", fo["label"]))
    assert [(f["status"], f["largest_cluster_pct"], bool(f["alarm_hint"])) for f in bad["coverage"]["findings"]] == \
           [(f["status"], f["largest_cluster_pct"], bool(f["alarm_hint"])) for f in ok["coverage"]["findings"]]


def test_no_placeholder_no_counted_line_and_real_labels_unchanged():
    art = run()
    assert "Provider words removed" not in report.render(art)
    for label in ("SafePal", "Lowell", "Cleanup", "Slow", "Unsafe", "Binance Hot Wallet 2", "OKX: Hot Wallet", "baton"):
        assert gating._text(label) == label
        assert gating.provider_prose(label) == label


def test_two_providers_whose_names_both_lose_a_word_stay_two_providers(tmp_path):
    """R5: "Safe Scanner" (40%, alarms) and "Clean Scanner" (6%) both print as "[provider word removed] Scanner" but stay
    two providers: two Sources-read blocks, no duplicate-provider status, and the alarming block is there."""
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps({"provider_findings": [
        {"provider": "Safe Scanner", "status": "ok", "unit": "percent", "largest_cluster_pct": 40.0, "data_age_min": 1.0},
        {"provider": "Clean Scanner", "status": "ok", "unit": "percent", "largest_cluster_pct": 6.0, "data_age_min": 1.0}]}))
    art = run(external_artifact=path)
    blocks = [s for s in art["sources"] if s["name"] == f"Provider {P} Scanner (artifact)"]
    assert len(blocks) == 2
    assert {b["lines"][0] for b in blocks} == {"largest cluster 40.0%", "largest cluster 6.0%"}
    assert "external_artifact.duplicate_providers" not in art["providers"]
    assert gating.duplicate_providers(art["coverage"]["findings"]) == []
    assert art["overall"]["verdict"]["level"] == gating.VERDICT_HIGH
    text = report.render(art)
    assert "largest cluster 40.0%" in text and "largest cluster 6.0%" in text
    assert set(visible(json.dumps(art))) <= OWN and set(visible(text)) <= OWN
    same = tmp_path / "same.json"  # the same name twice is still a duplicate, as before
    same.write_text(json.dumps({"provider_findings": [{"provider": "Safe Scanner", "status": "ok", "unit": "percent", "largest_cluster_pct": 40.0, "data_age_min": 1.0},
                                                      {"provider": "SAFE scanner", "status": "ok", "unit": "percent", "largest_cluster_pct": 6.0, "data_age_min": 1.0}]}))
    dup = run(external_artifact=same)
    assert dup["providers"]["external_artifact.duplicate_providers"]["names"] == [f"{P.lower()} scanner"]


def test_a_case_only_duplicate_is_flagged_and_shown_as_two_blocks_as_before(tmp_path):
    """N2 (review of dc71087): "Safe Scanner" and "safe scanner" are a duplicate (flagged, case-insensitive, as before) and,
    as before, two Sources-read blocks (the block key keeps the name's case); the alarming 40% block is there."""
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps({"provider_findings": [
        {"provider": "Safe Scanner", "status": "ok", "unit": "percent", "largest_cluster_pct": 40.0, "data_age_min": 1.0},
        {"provider": "safe scanner", "status": "ok", "unit": "percent", "largest_cluster_pct": 6.0, "data_age_min": 1.0}]}))
    art = run(external_artifact=path)
    names = sorted(s["name"] for s in art["sources"] if s["name"].startswith("Provider "))
    assert names == [f"Provider {P} Scanner (artifact)", f"Provider {P} scanner (artifact)"]
    assert {s["lines"][0] for s in art["sources"] if s["name"].startswith("Provider ")} == {"largest cluster 40.0%", "largest cluster 6.0%"}
    assert art["providers"]["external_artifact.duplicate_providers"]["names"] == [f"{P.lower()} scanner"]
    assert art["overall"]["verdict"]["level"] == gating.VERDICT_HIGH
    keys = [f["provider_key"] for f in art["coverage"]["findings"]]
    assert keys[0] != keys[1] and gating.finding_identity(art["coverage"]["findings"][0]) == gating.finding_identity(art["coverage"]["findings"][1])
    assert set(visible(json.dumps(art))) <= OWN and set(visible(report.render(art))) <= OWN


def _angle(poisoned, tmp_path):
    """R7: tag-like provider text in the token symbol and name, Jupiter tags, Helius identities and the external artifact."""
    w = (lambda bad, ok: bad if poisoned else ok)

    class Jupiter(FakeJupiter):
        def token(self, mint):
            t = super().token(mint)
            t.update(symbol=w("<SAFE>", "<PINE>"), name=w("<Clean> Coin", "<Quiet> Coin"), launchpad=w("<legit>.fun", "<river>.fun"))
            return t

        def holders(self, mint, limit=100):
            d = super().holders(mint, limit)
            d["holders"][0]["tags"] = ["bundler", w("<clean>", "<oak>"), w("<x low risk>", "<x old oak>"), w("s<?x?>afe", "p<?x?>ine")]
            return d

    class Helius(FakeHelius):
        def identities(self, owners):
            self._hit("identities")
            return {W1: {"name": w("<legit> Treasury", "<river> Treasury"), "category": "Fund", "tags": []},
                    W2: {"name": w("s</ x>afe wallet", "p</ x>ine wallet"), "category": None, "tags": []}}

    path = tmp_path / f"angle-{poisoned}.json"
    path.write_text(json.dumps({"provider_findings": [
        {"provider": w("<safe> Scanner", "<pine> Scanner"), "status": "ok", "unit": "percent", "largest_cluster_pct": 5.0, "data_age_min": 1.0,
         "alarm_hint": w("</clean>", "</plain>"), "detail": w("s<![CDATA[x]]>afe", "p<![CDATA[x]]>ine")}]}))
    return run(helius=Helius(), jupiter=Jupiter(), external_artifact=path)


def test_tag_like_provider_text_never_shows_a_listed_word_in_the_rendered_report(tmp_path):
    """R7 (review of 046affa): a token named <SAFE> never shows SAFE: not in the title, the Token line, the top-holders
    table (Jupiter tags, Helius identities), the Sources-read blocks or the artifact."""
    bad, ok = _angle(True, tmp_path), _angle(False, tmp_path)
    text_bad, text_ok = report.render(bad), report.render(ok)
    assert visible(text_bad) == visible(text_ok) and set(visible(text_bad)) <= OWN
    assert visible(json.dumps(bad)) == visible(json.dumps(ok))
    assert text_bad.startswith(f"# Holder analysis: <{P}> (")
    assert f"Token <{P}> (" in text_bad
    rows = {r["owner"]: r for r in bad["top_holders"]}
    assert rows[W1]["identity"] == f"<{P}> Treasury" and rows[W2]["identity"] == f"{P} wallet"
    assert rows[W1]["jupiter_tags"] == ["bundler", f"<{P}>", f"<x {P}>", P]
    assert bad["token"]["name"] == f"<{P}> Coin" and bad["token"]["launchpad"] == f"<{P}>.fun"
    assert "Provider words removed:" in text_bad and "Provider words removed:" not in text_ok
    assert bad["overall"]["verdict"]["level"] == ok["overall"]["verdict"]["level"] and bad["overall"]["flag"]["level"] == ok["overall"]["flag"]["level"]


def test_jupiter_audit_flags_print_only_as_true_or_false():
    """R4: a Jupiter audit flag that is not true / false is provider text: it is kept and printed as "not read (unexpected
    value)"; the agreement check still uses Jupiter's value, as before (a text value never agrees)."""
    class Odd(FakeJupiter):
        def token(self, mint):
            t = super().token(mint)
            t["audit"].update(mintAuthorityDisabled="safe", freezeAuthorityDisabled="Low risk")
            return t

    art = run(jupiter=Odd())
    scalars = {s["check"]: s for s in art["crosscheck"]["scalars"]}
    for check in ("mint_authority_disabled", "freeze_authority_disabled"):
        assert scalars[check]["jupiter"] == "not read (unexpected value)"
        assert scalars[check]["agree"] is False
    text = report.render(art)
    assert "- mint_authority_disabled: DISAGREE (jupiter=not read (unexpected value), helius=True)" in text
    assert visible(text) == visible(report.render(run())) and visible(json.dumps(art["crosscheck"])) == []
    plain = {s["check"]: s for s in run()["crosscheck"]["scalars"]}
    assert plain["mint_authority_disabled"]["jupiter"] is True and plain["mint_authority_disabled"]["agree"] is True


def test_bidi_html_and_markdown_in_creator_text_are_inert(tmp_path):
    """Hardening (a): a token symbol with an RLO ("EFAS" shown reversed as SAFE), an entity-encoded name, a tag-split
    identity and a markdown-link tag print inert, and the listed words are removed."""
    class Creator(FakeJupiter):
        def token(self, mint):
            t = super().token(mint)
            t.update(symbol="\u202eEFAS", name="S&#65;FE coin")
            return t

        def holders(self, mint, limit=100):
            d = super().holders(mint, limit)
            d["holders"][0]["tags"] = ["bundler", "[safe](https://x.example)"]
            return d

    class Ids(FakeHelius):
        def identities(self, owners):
            self._hit("identities")
            return {W1: {"name": "s<b></b>afe vault", "category": "Fund", "tags": []}}

    art = run(helius=Ids(), jupiter=Creator())
    text = report.render(art)
    assert not re.search("[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]", text + json.dumps(art, ensure_ascii=False))
    assert text.startswith("# Holder analysis: EFAS (")
    assert art["token"]["name"] == f"{P} coin" and {r["owner"]: r for r in art["top_holders"]}[W1]["identity"] == f"{P} vault"
    assert "<" not in text.split("## Top holders")[1]
    assert set(visible(text)) <= OWN
