"""HS-WATCHLIST-T1: the copy-trade cascade watchlist (references/fomo_cascade_watchlist.json) and its owner-ask check on Fomo
API's trader search (scripts/watchlist_verify.py). Offline: a fake transport, a fake clock and dummy keys; no network.
Fomo API is an independent, unofficial API, not affiliated with fomo.family.

Covers: the watchlist file (20 entries, the chosen tiers in order, evidence / source / dates from the research report,
self-reported counts, unconfirmed handles, the filled fomo objects); request construction (host, the one search path with
its fixed query, the Bearer Authorization header only, fomoapi.py's opener, key loader and send_once by import) and the
URL allowlist; the exact-handle rule (matched / ambiguous / not_found) and the loud shape guards (the run stops after the
first changed answer); value validation; the call cap, the pace (at most 15 a minute), the retry caps, the stop at the
first 402 and at a call above 250 credits; --dry-run (no key read, no request, no file written); the credit headers;
the key never printed, saved or in an error; the saved file."""

from __future__ import annotations

import ast
import contextlib
import copy
import email.message
import io
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import fomoapi as fa  # noqa: E402
import watchlist_verify as wv  # noqa: E402

WATCHLIST = SCRIPTS.parent / "references" / "fomo_cascade_watchlist.json"
DUMMY_KEY = "fomo-dummy-key-7c2a9e41b0d3"
SECRET = "fomo_SeCrEt-0d1e2f3a4b5c6d7e8f9a"
WALLET = "5AhfPStn66hRYoNNDfJHSDgCH7fBbwMQZUECRrhTo62F"   # the cached docs' example wallet (public)
USER_ID = "659b1c2d3e4f5a6b7c8d9e0f"
NAMES = ["frankdegods", "theunipcs", "brezscales", "orangie", "pointfarmcap", "rasmr_eth", "Quanterty", "heat", "TJR", "cosby", "CryptoKaleo",
         "EricCryptoman", "travladd", "Jelitics", "DNS_ERR", "mrpunkdoteth", "jpegkite", "Banks", "notthreadguy", "blknoiz06"]
TIERS = ["owner"] * 4 + ["tier1"] * 5 + ["tier2"] * 11
FOMO_KEYS = {"status", "reason", "query", "handle", "user_id", "followers", "solana_wallet", "candidates", "checked_at", "credits_cost"}
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


# ----------------------------------------------------------------------------- fakes


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200, headers: dict | None = None):
        self._buf, self.status = io.BytesIO(body), status
        self.headers = email.message.Message()
        for k, v in (headers or {}).items():
            self.headers[k] = v

    def read(self, n=-1):
        return self._buf.read(n)

    def close(self):
        pass


def credit_headers(cost="250", remaining="249750"):
    out = {}
    if cost is not None:
        out["x-credits-cost"] = cost
    if remaining is not None:
        out["x-credits-remaining"] = remaining
    return out


def trader(handle, user_id=USER_ID, followers=1000, wallet=WALLET, **extra):
    row = {"type": "trader", "handle": handle, "displayName": handle.title(), "userId": user_id, "followers": followers,
           "wallets": {"solana": wallet, "evm": "0x7b4d16237683fe1765e727eadf99c6f02adf0b59"}, "pnlUsd": 1234.5}
    row.update(extra)
    return row


def answer(*rows, container="results", cost="250", remaining="249750", payload=None):
    body = payload if payload is not None else ({container: list(rows)} if container else list(rows))
    return FakeResponse(json.dumps(body).encode(), headers=credit_headers(cost, remaining))


def http_error(code, headers=None, body=b""):
    msg = email.message.Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError(f"https://{fa.HOST}/v2/search", code, "error", msg, io.BytesIO(body))


class Clock:
    def __init__(self):
        self.t, self.sleeps = 1000.0, []

    def monotonic(self):
        return self.t

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.t += seconds

    def now(self):
        return 1_792_800_000.0 + self.t


class Opener:
    def __init__(self, answers, clock=None, on_open=None):
        self.answers, self.clock, self.on_open, self.requests = list(answers), clock, on_open, []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout, self.clock.t if self.clock else None))
        if self.on_open:
            self.on_open()
        item = self.answers.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def doc_with(handles, tier="tier2"):
    return {"schema": wv.SCHEMA, "as_of": "2026-10-24", "fomo_verification": None,
            "entries": [{"x_handle": h, "x_handle_status": "as_in_report", "tier": tier, "fomo": None} for h in handles]}


def run(doc, answers, key=DUMMY_KEY):
    clock, lines = Clock(), []
    opener = Opener(answers, clock)
    summary = wv.run(doc, key, opener, now=clock.now, monotonic=clock.monotonic, sleep=clock.sleep, emit=lines.append)
    return summary, lines, opener, clock


def statuses(doc):
    return [(e["fomo"]["status"], e["fomo"]["reason"]) for e in doc["entries"]]


def run_main(argv, opener, env=None):
    out, err = io.StringIO(), io.StringIO()
    env = {"FOMOAPI_KEY": DUMMY_KEY} if env is None else env
    base = {k: v for k, v in os.environ.items() if k not in ("FOMOAPI_KEY", "HOLDER_FORENSICS_ENV")}
    with mock.patch.dict(os.environ, base | env, clear=True), mock.patch.object(fa, "default_opener", return_value=opener), \
         mock.patch.object(wv.time, "sleep"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = wv.main(argv)
    return code, out.getvalue(), err.getvalue()


class TempDir(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def small_file(self, handles, tier="tier2") -> Path:
        path = self.tmp / "watchlist.json"
        path.write_text(json.dumps(doc_with(handles, tier), indent=2) + "\n", encoding="utf-8")
        return path


# ----------------------------------------------------------------------------- the watchlist file


class WatchlistFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WATCHLIST.read_text(encoding="utf-8")
        cls.doc = json.loads(cls.text)
        cls.by = {e["x_handle"]: e for e in cls.doc["entries"]}

    def test_twenty_entries_with_the_chosen_tiers_in_order(self):
        self.assertEqual([e["x_handle"] for e in self.doc["entries"]], NAMES)
        self.assertEqual([e["tier"] for e in self.doc["entries"]], TIERS)
        self.assertEqual({t: TIERS.count(t) for t in wv.TIERS}, {"owner": 4, "tier1": 5, "tier2": 11})
        self.assertEqual(self.doc["selection"]["owner_words"], "Yours + tier 1 + tier 2")
        self.assertIn("13 leaderboard whales", self.doc["selection"]["not_included"])

    def test_top_level_schema_date_and_note(self):
        self.assertEqual((self.doc["schema"], self.doc["as_of"]), (wv.SCHEMA, "2026-10-24"))
        self.assertTrue(self.doc["note"].startswith("Public claims and observations, not proof; follower counts as stated per entry"))
        for needle in ("refreshed only when the owner asks", "scripts/watchlist_verify.py", "GetXAPI only on request", "never an engine input"):
            self.assertIn(needle, self.doc["note"], needle)
        self.assertIn("FOMO-CASCADE-TRADERS-20261024/REPORT.md", self.doc["source_report"])
        self.assertEqual(wv.load_watchlist(WATCHLIST)[1], None, "the script accepts the file")

    def test_the_purpose_is_not_twenty_documented_cascades(self):
        """Repair R1 (Verifier F8): public posts tie the traders to copy-trading followers; cascades are documented for some only."""
        purpose = self.doc["purpose"]
        for needle in ("public posts tie to copy-trading followers", "a documented cascade exists for some entries only", "tier 2 is weaker evidence",
                       "Public claims, not proof"):
            self.assertIn(needle, purpose, needle)
        self.assertNotIn("Fomo traders whose sells copy-trade bots mirror within seconds", purpose)

    def test_each_entry_has_evidence_source_and_dates_from_the_report(self):
        base = {"x_handle", "x_handle_status", "display_name", "tier", "evidence", "source", "evidence_date", "added", "followers_self_reported",
                "followers_self_reported_source", "fomo"}
        for e in self.doc["entries"]:
            with self.subTest(e["x_handle"]):
                self.assertEqual(set(e) - {"x_handle_note"}, base)
                self.assertTrue(isinstance(e["evidence"], str) and 10 <= len(e["evidence"]) <= 300)
                self.assertTrue(isinstance(e["source"], str) and re.search(r"20\d\d-\d\d", e["source"]), "a dated source")
                self.assertRegex(e["evidence_date"], r"^2026-\d{2}(-\d{2})?(\.\.\d{2})?$")
                self.assertEqual(e["added"], "2026-10-24")
                self.assertTrue(e["display_name"] is None or isinstance(e["display_name"], str))
                self.assertIsNone(re.search(r"(?i)\b(clean|safe|low)\b", e["evidence"] + " " + e["source"]), "CAPE wording rule")
                self.assertEqual(wv.query_of(e["x_handle"]), e["x_handle"])
                self.assertEqual(fa.safe_label(e["x_handle"], DUMMY_KEY), e["x_handle"], "every listed name survives as an inert label")
        self.assertIn("@Petitefleeeur 2026-09-29", self.by["pointfarmcap"]["source"])
        self.assertIn("@theunipcs 2026-10-05", self.by["theunipcs"]["source"])
        self.assertIn("0.39% of supply", self.by["frankdegods"]["evidence"])
        self.assertEqual((self.by["brezscales"]["display_name"], self.by["blknoiz06"]["display_name"], self.by["pointfarmcap"]["display_name"]), ("Brez Scales", "Ansem", "PFC"))

    def test_unconfirmed_handles_are_marked_never_guessed(self):
        unconfirmed = [e["x_handle"] for e in self.doc["entries"] if e["x_handle_status"] == "unconfirmed"]
        self.assertEqual(unconfirmed, ["heat", "TJR", "Banks"])
        for e in self.doc["entries"]:
            self.assertIn(e["x_handle_status"], ("as_in_report", "unconfirmed"))
            self.assertEqual("x_handle_note" in e, e["x_handle_status"] == "unconfirmed", e["x_handle"])

    def test_self_reported_counts_as_the_report_states_them(self):
        counts = {e["x_handle"]: e["followers_self_reported"] for e in self.doc["entries"] if e["followers_self_reported"] is not None}
        self.assertEqual(counts, {"Quanterty": 220000, "heat": 100000, "DNS_ERR": 20000, "mrpunkdoteth": 11500, "jpegkite": 10000})
        for e in self.doc["entries"]:
            has = e["followers_self_reported"] is not None
            self.assertEqual(isinstance(e["followers_self_reported_source"], str), has, e["x_handle"])
            if has:
                self.assertIn("own post", e["followers_self_reported_source"])

    def test_fomo_objects_are_valid_and_the_run_stayed_in_its_caps(self):
        filled = [e for e in self.doc["entries"] if e["fomo"] is not None]
        self.assertIn(len(filled), (0, 20), "a run fills every entry")
        for e in filled:
            fomo = e["fomo"]
            with self.subTest(e["x_handle"]):
                self.assertEqual(set(fomo), FOMO_KEYS)
                self.assertIn(fomo["status"], wv.STATUSES)
                self.assertEqual(fomo["query"], e["x_handle"])
                self.assertTrue(fomo["handle"] is None or fa.safe_label(fomo["handle"]) == fomo["handle"])
                self.assertTrue(fomo["user_id"] is None or wv.USER_ID_RE.fullmatch(fomo["user_id"]))
                self.assertTrue(fomo["followers"] is None or (isinstance(fomo["followers"], int) and fomo["followers"] >= 0))
                self.assertTrue(fomo["solana_wallet"] is None or fa.SOLANA_ADDRESS_RE.fullmatch(fomo["solana_wallet"]))
                self.assertTrue(isinstance(fomo["candidates"], list) and len(fomo["candidates"]) <= wv.RESULT_LIMIT)
                self.assertTrue(fomo["checked_at"] is None or ISO_RE.match(fomo["checked_at"]))
                self.assertTrue(fomo["credits_cost"] is None or 0 <= fomo["credits_cost"] <= 2 * wv.CREDITS_PER_CALL)
                if fomo["status"] == "matched":
                    self.assertEqual((fomo["reason"], fomo["candidates"]), (None, []))
                    self.assertEqual(fomo["handle"].lower(), e["x_handle"].lower(), "matched only on the exact handle")
                if fomo["status"] in ("ambiguous", "not_found"):
                    self.assertEqual((fomo["handle"], fomo["user_id"], fomo["followers"], fomo["solana_wallet"]), (None, None, None, None), "never a guess")
        if filled:
            run_ = self.doc["fomo_verification"]
            self.assertLessEqual(run_["calls_sent"], wv.MAX_CALLS)
            self.assertLessEqual(run_["credits_charged"], wv.MAX_CALLS * wv.CREDITS_PER_CALL)
            self.assertEqual(run_["host"], "api.fomoapi.io")
            self.assertEqual(sum(run_["counts"].values()), 20)

    def test_the_file_keeps_the_format_the_script_writes(self):
        self.assertEqual(json.dumps(self.doc, indent=2, ensure_ascii=False) + "\n", self.text)


# ----------------------------------------------------------------------------- request and transport


class RequestTests(TempDir):
    def test_one_documented_get_per_name_with_the_bearer_header_only(self):
        doc = doc_with(["frankdegods", "@Banks"])
        summary, _, opener, _ = run(doc, [answer(trader("frankdegods")), answer(trader("Banks"))])
        self.assertEqual(summary["calls_sent"], 2)
        for (request, timeout, _), query in zip(opener.requests, ("frankdegods", "Banks")):
            url = urllib.parse.urlparse(request.full_url)
            self.assertEqual((url.scheme, url.hostname, url.port, url.path, url.query), ("https", "api.fomoapi.io", None, "/v2/search", f"q={query}&type=traders&limit=5"))
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(dict(request.header_items()), {"Authorization": f"Bearer {DUMMY_KEY}", "Accept": "application/json", "User-agent": wv.USER_AGENT})
            self.assertEqual(timeout, fa.TIMEOUT_S)

    def test_only_the_allowlisted_https_host_path_and_query(self):
        good = "https://api.fomoapi.io/v2/search?q=heat&type=traders&limit=5"
        wv.check_search_url(good, "heat")
        for url in ("http://api.fomoapi.io/v2/search?q=heat&type=traders&limit=5", "https://api.fomoapi.io.evil.example/v2/search?q=heat&type=traders&limit=5",
                    "https://evil.example/v2/search?q=heat&type=traders&limit=5", "https://api.fomoapi.io:8443/v2/search?q=heat&type=traders&limit=5",
                    "https://api.fomoapi.io:abc/v2/search?q=heat&type=traders&limit=5", "https://u:p@api.fomoapi.io/v2/search?q=heat&type=traders&limit=5",
                    "https://api.fomoapi.io/v2/users/heat", "https://api.fomoapi.io/v2/users/heat?q=heat&type=traders&limit=5",
                    "https://api.fomoapi.io/v2/search/?q=heat&type=traders&limit=5", "https://api.fomoapi.io/v2/tokens/search?q=heat&type=traders&limit=5",
                    "https://api.fomoapi.io/token/x/holders?q=heat&type=traders&limit=5", "https://api.fomoapi.io/v2/search?q=heat&type=all&limit=5",
                    "https://api.fomoapi.io/v2/search?q=heat&type=traders&limit=100", "https://api.fomoapi.io/v2/search?q=heat&type=traders&limit=5&deep=1",
                    "https://api.fomoapi.io/v2/search?q=other&type=traders&limit=5", "https://api.fomoapi.io/v2/search?q=heat&type=traders&limit=5#x",
                    "https://api.fomoapi.io/v2/trading/buy", "https://fomoapi.io/pricing"):
            with self.subTest(url), self.assertRaises(fa.Failure):
                wv.check_search_url(url, "heat")
        opener = Opener([answer()])
        bad = urllib.request.Request("https://example.com/v2/search?q=heat&type=traders&limit=5")
        with self.assertRaises(fa.Failure):
            fa.send_once(bad, opener, "heat", monotonic=Clock().monotonic, check=lambda url: wv.check_search_url(url, "heat"))
        self.assertEqual(opener.requests, [], "a refused URL is never sent")

    def test_fomoapis_own_holders_check_stays_the_default(self):
        """The tiny fomoapi.py change: without `check` send_once still allows only the holders path, so the search URL is refused."""
        opener = Opener([answer()])
        request = wv.build_search_request("heat", DUMMY_KEY)
        with self.assertRaises(fa.Failure) as caught:
            fa.send_once(request, opener, "So11111111111111111111111111111111111111112", monotonic=Clock().monotonic)
        self.assertEqual((caught.exception.reason, opener.requests), ("path_not_allowlisted", []))

    def test_the_opener_key_loader_and_send_once_are_fomoapis(self):
        path = self.small_file(["heat"])
        opener = Opener([answer(trader("heat"))])
        with mock.patch.object(fa, "send_once", wraps=fa.send_once) as send, mock.patch.object(fa, "load_key", wraps=fa.load_key) as load:
            code, out, _ = run_main(["--watchlist", str(path)], opener)
        self.assertEqual((code, send.call_count, load.call_count, len(opener.requests)), (0, 1, 1, 1))
        self.assertIn("heat (tier2): matched", out)
        real = fa.default_opener()
        self.assertFalse(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in real.handlers), "no environment proxy")
        self.assertTrue(any(isinstance(h, fa.NoRedirect) for h in real.handlers), "no redirects")

    def test_transport_failures_are_fixed_codes(self):
        cases = [(http_error(302), "redirect_disallowed"), (FakeResponse(b"", status=301), "redirect_disallowed"), (http_error(401, body=b"bad key"), "authentication_failed"),
                 (http_error(403), "access_denied"), (http_error(404), "not_found"), (http_error(500), "server_error"), (http_error(503), "service_unavailable"),
                 (http_error(418), "http_error"), (socket.timeout(), "timeout"), (urllib.error.URLError(OSError("refused")), "network_error"),
                 (RuntimeError(f"boom {DUMMY_KEY}"), "network_error")]
        for item, reason in cases:
            with self.subTest(reason=reason):
                doc = doc_with(["heat", "cosby"])
                summary, lines, opener, _ = run(doc, [item, answer(trader("cosby"))])
                self.assertEqual(statuses(doc), [("failed", reason), ("matched", None)], "a failed name does not stop the run")
                self.assertEqual((summary["stopped"], len(opener.requests)), (None, 2))
                self.assertNotIn(DUMMY_KEY, "\n".join(lines) + json.dumps(doc))
        with mock.patch.object(fa, "MAX_BYTES", 1000):
            doc = doc_with(["heat"])
            run(doc, [FakeResponse(b"x" * 1001)])
        self.assertEqual(statuses(doc), [("failed", "response_too_large")])


# ----------------------------------------------------------------------------- matching and the shape guards


class MatchingTests(unittest.TestCase):
    def one(self, handle, *rows, container="results", payload=None):
        doc = doc_with([handle])
        summary, lines, _, _ = run(doc, [answer(*rows, container=container, payload=payload)])
        return doc["entries"][0]["fomo"], summary, lines

    def test_exact_handle_case_insensitive_is_matched_with_its_values(self):
        fomo, _, lines = self.one("frankdegods", trader("FrankDeGods", followers=249483), trader("frankdegods_alt"), trader("frank"))
        self.assertEqual((fomo["status"], fomo["reason"], fomo["handle"], fomo["user_id"], fomo["followers"], fomo["solana_wallet"], fomo["candidates"]),
                         ("matched", None, "FrankDeGods", USER_ID, 249483, WALLET, []))
        self.assertEqual((fomo["credits_cost"], fomo["query"]), (250, "frankdegods"))
        self.assertTrue(ISO_RE.match(fomo["checked_at"]))
        self.assertIn("frankdegods (tier2): matched; Fomo handle FrankDeGods; followers 249,483; wallet 5AhfPS…o62F; 250 credits", lines)

    def test_a_leading_at_is_stripped_on_both_sides(self):
        self.assertEqual(self.one("frankdegods", trader("@frankdegods"))[0]["status"], "matched")
        self.assertEqual(self.one("@heat", trader("HEAT"))[0]["status"], "matched")

    def test_a_display_name_only_hit_is_ambiguous_with_candidates(self):
        fomo, _, lines = self.one("frankdegods", trader("frank_d", displayName="frankdegods"), trader("degods_fan"))
        self.assertEqual((fomo["status"], fomo["reason"], fomo["candidates"]), ("ambiguous", "no_exact_handle_match", ["frank_d", "degods_fan"]))
        self.assertEqual((fomo["handle"], fomo["user_id"], fomo["followers"], fomo["solana_wallet"]), (None, None, None, None), "never a guess")
        self.assertIn("frankdegods (tier2): ambiguous (no_exact_handle_match; candidates: frank_d, degods_fan); 250 credits", lines)

    def test_two_exact_handles_are_ambiguous(self):
        fomo = self.one("heat", trader("heat"), trader("HEAT", userId="other1"))[0]
        self.assertEqual((fomo["status"], fomo["reason"], fomo["candidates"]), ("ambiguous", "several_exact_matches", ["heat", "HEAT"]))

    def test_no_trader_result_is_not_found(self):
        token = {"type": "token", "symbol": "HEAT", "address": WALLET, "name": "heat"}
        for rows in ((), (token,)):
            fomo, _, lines = self.one("heat", *rows)
            self.assertEqual((fomo["status"], fomo["candidates"]), ("not_found", []))
            self.assertIn("heat (tier2): not_found (no trader result); 250 credits", lines)

    def test_the_result_list_may_be_top_level_or_under_traders_or_data(self):
        for container in (None, "traders", "data"):
            self.assertEqual(self.one("heat", trader("heat"), container=container)[0]["status"], "matched", container)

    def test_a_changed_shape_stops_the_run_after_the_first_call(self):
        bare = trader("heat")
        cases = {
            "result_list_missing": {"items": [bare]},
            "result_not_object": {"results": ["heat"]},
            "type_missing": {"results": [{k: v for k, v in bare.items() if k != "type"}]},
            "type_unknown": {"results": [dict(bare, type="traders")]},
            "trader_fields_missing": {"results": [{k: v for k, v in bare.items() if k != "userId"}]},
        }
        variants = list(cases.items()) + [("trader_fields_missing", {"results": [{k: v for k, v in bare.items() if k != "wallets"}]}),
                                          ("trader_fields_missing", {"results": [{k: v for k, v in bare.items() if k != "handle"}]})]
        for detail, payload in variants:
            with self.subTest(detail):
                doc = doc_with(["heat", "cosby", "TJR"])
                summary, lines, opener, _ = run(doc, [answer(payload=payload), answer(trader("cosby")), answer(trader("TJR"))])
                self.assertEqual(statuses(doc), [("failed", f"shape_mismatch:{detail}"), ("failed", "not_sent_run_stopped"), ("failed", "not_sent_run_stopped")])
                self.assertEqual((len(opener.requests), summary["stopped"], summary["calls_sent"]), (1, "shape_mismatch", 1))
                self.assertIn("RUN STOPPED EARLY (shape_mismatch); names not sent are failed (not_sent_run_stopped)", lines)
                self.assertTrue(any(line.startswith("first answer shape: ") for line in lines))
                self.assertIsNone(doc["entries"][1]["fomo"]["checked_at"])
        doc = doc_with(["heat", "cosby"])
        summary, _, opener, _ = run(doc, [FakeResponse(b"<html>", headers=credit_headers()), answer(trader("cosby"))])
        self.assertEqual((statuses(doc)[0], summary["stopped"], len(opener.requests)), (("failed", "invalid_json"), "invalid_json", 1))

    def test_the_shape_line_names_fields_only(self):
        _, _, lines = self.one("heat", trader("heat", secretNote="do this now"))
        shape = next(line for line in lines if line.startswith("first answer shape: "))
        self.assertIn("top level: results; first trader result: displayName, followers, handle, pnlUsd, secretNote, type, userId, wallets", shape)
        self.assertNotIn("do this now", shape)
        self.assertNotIn(WALLET, shape)

    def test_values_are_validated_and_anything_else_is_null(self):
        for followers in (-1, 1.5, True, "1000", 2e9, None):
            with self.subTest(followers=followers):
                self.assertIsNone(self.one("heat", trader("heat", followers=followers))[0]["followers"])
        no_top = trader("heat", profile={"followers": 77})
        del no_top["followers"]
        self.assertEqual(self.one("heat", no_top)[0]["followers"], 77, "the profile count when there is no top-level one")
        self.assertEqual(self.one("heat", trader("heat", followers=12.0))[0]["followers"], 12)
        for wallet in ("0x7b4d16237683fe1765e727eadf99c6f02adf0b59", "short", "0OIl" * 10, 12345, None):
            with self.subTest(wallet=wallet):
                self.assertIsNone(self.one("heat", trader("heat", wallet=wallet))[0]["solana_wallet"])
        self.assertIsNone(self.one("heat", trader("heat", wallets={"solana": WALLET, "verified": False}))[0]["solana_wallet"], "an unverified wallet is dropped")
        self.assertIsNone(self.one("heat", trader("heat", wallets=None))[0]["solana_wallet"])
        self.assertEqual(self.one("heat", trader("heat", wallets={"solana": WALLET, "verified": True}))[0]["solana_wallet"], WALLET)
        for user_id in ("abc def", {"x": 1}, "x" * 65, -3, True, "<b>1</b>"):
            with self.subTest(user_id=user_id):
                self.assertIsNone(self.one("heat", trader("heat", userId=user_id))[0]["user_id"])
        self.assertEqual(self.one("heat", trader("heat", userId=4242))[0]["user_id"], "4242")
        fomo = self.one("heat", trader("<script>alert(1)</script> [x](http://e.vil)"), trader("a\nb safe trader"))[0]
        self.assertEqual(fomo["status"], "ambiguous")
        for label in fomo["candidates"]:
            self.assertRegex(label, r"^[\w .\-\[\]]{1,60}$", "candidates are inert labels")
            self.assertNotRegex(label, r"(?i)\bsafe\b")


# ----------------------------------------------------------------------------- caps, pace, retries, stops


class CapsTests(TempDir):
    def test_the_pace_is_at_most_15_requests_a_minute(self):
        doc = doc_with(NAMES)
        summary, _, opener, clock = run(doc, [answer(trader(n)) for n in NAMES])
        starts = [t for _, _, t in opener.requests]
        self.assertEqual((len(starts), summary["calls_sent"]), (20, 20))
        self.assertTrue(all(b - a >= wv.MIN_INTERVAL_S for a, b in zip(starts, starts[1:])))
        self.assertLessEqual(max(sum(1 for s in starts if t <= s < t + 60) for t in starts), 15)
        self.assertAlmostEqual(sum(clock.sleeps), 19 * wv.MIN_INTERVAL_S)
        self.assertEqual(summary["counts"], {"matched": 20, "ambiguous": 0, "not_found": 0, "failed": 0})

    def test_one_retry_per_name_after_a_short_429_and_at_most_5_in_all(self):
        answers = []
        for n in NAMES[:5]:
            answers += [http_error(429, headers={"Retry-After": "1"}), answer(trader(n))]
        answers += [http_error(429, headers={"Retry-After": "1"}) for _ in NAMES[5:]]
        doc = doc_with(NAMES)
        summary, _, opener, clock = run(doc, answers)
        self.assertEqual((len(opener.requests), summary["calls_sent"], summary["retries"]), (25, 25, 5))
        self.assertLessEqual(len(opener.requests), wv.MAX_CALLS)
        self.assertEqual(statuses(doc), [("matched", None)] * 5 + [("failed", "rate_limited")] * 15)
        self.assertEqual(clock.sleeps.count(1.0), 5)
        doc = doc_with(["heat", "cosby"])
        summary, _, opener, _ = run(doc, [http_error(429, headers={"Retry-After": "1"}), http_error(429, headers={"Retry-After": "1"}), answer(trader("cosby"))])
        self.assertEqual((statuses(doc), summary["retries"], len(opener.requests)), ([("failed", "rate_limited"), ("matched", None)], 1, 3), "never a second retry")

    def test_no_retry_without_a_short_retry_after(self):
        for number, item in enumerate((http_error(429), http_error(429, headers={"Retry-After": "60"}), http_error(503, headers={"Retry-After": "1"}))):
            with self.subTest(case=number):
                doc = doc_with(["heat", "cosby"])
                summary, _, opener, _ = run(doc, [item, answer(trader("cosby"))])
                self.assertEqual((len(opener.requests), summary["retries"], statuses(doc)[1]), (2, 0, ("matched", None)))

    def test_the_run_stops_at_the_first_402(self):
        doc = doc_with(["frankdegods", "heat", "cosby", "TJR"])
        stop = http_error(402, headers=credit_headers("0", "0"), body=b'{"error": "credits_exhausted"}')
        summary, lines, opener, _ = run(doc, [answer(trader("frankdegods")), stop, answer(trader("cosby")), answer(trader("TJR"))])
        self.assertEqual(len(opener.requests), 2)
        self.assertEqual(statuses(doc), [("matched", None), ("failed", "credits_exhausted"), ("failed", "not_sent_run_stopped"), ("failed", "not_sent_run_stopped")])
        self.assertEqual((summary["stopped"], summary["credits_charged"]), ("credits_exhausted", 250))
        self.assertIn("RUN STOPPED EARLY (credits_exhausted); names not sent are failed (not_sent_run_stopped)", lines)
        self.assertIn("cosby (tier2): failed (not_sent_run_stopped); no call sent", lines)
        self.assertTrue(lines[-2].startswith("total: 2 Fomo API calls sent (0 retries after a 429); 250 credits charged by x-credits-cost; 0 credits remaining"))

    def test_a_call_above_250_credits_stops_the_run(self):
        doc = doc_with(["heat", "cosby"])
        summary, _, opener, _ = run(doc, [answer(trader("heat"), cost="2500"), answer(trader("cosby"))])
        self.assertEqual((statuses(doc), summary["stopped"], len(opener.requests)),
                         ([("matched", None), ("failed", "not_sent_run_stopped")], "credits_cost_above_250", 1))
        self.assertEqual(doc["entries"][0]["fomo"]["credits_cost"], 2500)

    def test_the_call_cap_holds_even_when_names_and_retries_would_pass_it(self):
        doc = doc_with(["a1", "a2", "a3", "a4"])
        with mock.patch.object(wv, "MAX_CALLS", 3):
            summary, _, opener, _ = run(doc, [answer(trader(n)) for n in ("a1", "a2", "a3", "a4")])
        self.assertEqual(len(opener.requests), 3)
        self.assertEqual(statuses(doc)[2:], [("matched", None), ("failed", "call_cap_reached")])
        self.assertEqual(summary["stopped"], "call_cap_reached")

    def test_more_than_20_names_is_refused_before_any_call_or_key_read(self):
        path = self.small_file([f"name{i}" for i in range(21)])
        opener = Opener([])
        with mock.patch.object(fa, "load_key", side_effect=AssertionError("no key read")):
            code, out, err = run_main(["--watchlist", str(path)], opener)
        self.assertEqual((code, out, opener.requests), (2, "", []))
        self.assertEqual(err.strip(), "error: more than 20 names: a run is capped at 25 calls; nothing sent")
        for bad in ({"schema": "other"}, {"schema": wv.SCHEMA, "entries": []}, doc_with(["two words"]), doc_with(["heat", "HEAT"]), doc_with(["heat"], tier="tier9")):
            path.write_text(json.dumps(bad))
            self.assertEqual(run_main(["--watchlist", str(path), "--dry-run"], opener)[0], 2, bad)
        self.assertEqual(opener.requests, [])

    def test_dry_run_reads_no_key_sends_nothing_and_writes_nothing(self):
        path = self.tmp / "watchlist.json"
        shutil.copy(WATCHLIST, path)
        before = path.read_bytes()
        opener = Opener([])
        with mock.patch.object(fa, "load_key", side_effect=AssertionError("no key read")), mock.patch.object(fa, "find_env_file", side_effect=AssertionError("no .env")):
            code, out, err = run_main(["--dry-run", "--watchlist", str(path)], opener)
        self.assertEqual((code, err, opener.requests, path.read_bytes()), (0, "", [], before))
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("Copy-trade cascade watchlist check (HS-WATCHLIST-T1; owner-ask maintenance, never part of a scan;"))
        self.assertIn("plan: 20 names, one GET /v2/search?q=<handle>&type=traders&limit=5 each on api.fomoapi.io: 20 calls, 5,000 credits at 250 a call "
                      "(at most 25 calls and 6,250 credits with up to 5 retries after a short 429) of the free key's 250,000 a month; at most 15 requests a minute", lines[1])
        self.assertEqual(sum(1 for line in lines if line.startswith("  would send GET /v2/search?q=")), 20)
        self.assertIn("  would send GET /v2/search?q=TJR&type=traders&limit=5 for TJR (tier1, X handle unconfirmed)", lines)
        self.assertEqual(lines[-1], "dry run: no key read, no request sent, the watchlist file unchanged")

    def test_the_plan_is_printed_before_the_first_request(self):
        path = self.small_file(["heat"])
        seen = []
        out_buffer = io.StringIO()
        opener = Opener([answer(trader("heat"))], on_open=lambda: seen.append(out_buffer.getvalue()))
        base = {k: v for k, v in os.environ.items() if k not in ("FOMOAPI_KEY", "HOLDER_FORENSICS_ENV")}
        with mock.patch.dict(os.environ, base | {"FOMOAPI_KEY": DUMMY_KEY}, clear=True), mock.patch.object(fa, "default_opener", return_value=opener), \
             mock.patch.object(wv.time, "sleep"), contextlib.redirect_stdout(out_buffer):
            code = wv.main(["--watchlist", str(path)])
        self.assertEqual(code, 0)
        self.assertEqual(len(seen), 1)
        self.assertIn("plan: 1 name, one GET /v2/search", seen[0])


# ----------------------------------------------------------------------------- credits


class CreditTests(unittest.TestCase):
    def test_totals_come_from_the_headers(self):
        doc = doc_with(["heat", "cosby", "TJR"])
        summary, lines, _, _ = run(doc, [answer(trader("heat"), remaining="249750"), answer(trader("cosby"), remaining="249500"), answer(remaining="249250")])
        self.assertEqual((summary["credits_charged"], summary["calls_without_credit_header"]), (750, 0))
        self.assertEqual([e["fomo"]["credits_cost"] for e in doc["entries"]], [250, 250, 250])
        self.assertEqual(lines[-1], "total: 3 Fomo API calls sent (0 retries after a 429); 750 credits charged by x-credits-cost; 249,250 credits remaining "
                                    "(last x-credits-remaining); matched 2, ambiguous 0, not_found 1, failed 0")

    def test_a_missing_or_malformed_header_is_not_read_never_0(self):
        doc = doc_with(["heat", "cosby"])
        summary, lines, _, _ = run(doc, [answer(trader("heat"), cost=None, remaining=None), answer(trader("cosby"), cost="1e3", remaining="-5")])
        self.assertEqual([e["fomo"]["credits_cost"] for e in doc["entries"]], [None, None])
        self.assertEqual((summary["credits_charged"], summary["calls_without_credit_header"]), (0, 2))
        self.assertIn("heat (tier2): matched; Fomo handle heat; followers 1,000; wallet 5AhfPS…o62F; credits not reported", lines)
        self.assertIn("(2 calls without the header); credits remaining not reported", lines[-1])


# ----------------------------------------------------------------------------- the key and the saved file


class KeyAndSaveTests(TempDir):
    def test_the_key_never_reaches_an_output(self):
        b58_key = "HfpLdX35Kc6b7zDNWbe5x1xWLekKUXPYZbmz71vM"
        for key in (SECRET, b58_key):
            with self.subTest(key=key[:6]):
                path = self.small_file(["frankdegods", "heat", "cosby", "TJR", "Banks"])
                echo = answer(trader("frankdegods", userId=key[3:20].replace("+", "-"), wallet="22" + b58_key, displayName=key, **{key: 1}),
                              cost=key, remaining=key)
                candidates = answer(trader(key), trader(f"x {key[5:18]}"), trader("frank_d"))
                answers = [echo, candidates, http_error(401, body=key.encode()), RuntimeError(f"Authorization: Bearer {key}"),
                           http_error(403, headers={"x-credits-cost": key})]
                code, out, err = run_main(["--watchlist", str(path)], Opener(answers), env={"FOMOAPI_KEY": key})
                self.assertEqual(code, 0)
                saved = path.read_text()
                for text in (out, err, saved):
                    self.assertFalse(fa.echoes_key(text, key), "an 8-character piece of the key reached an output")
                doc = json.loads(saved)
                self.assertEqual(doc["entries"][1]["fomo"]["candidates"], ["frank_d"], "candidates echoing the key are dropped")
                self.assertEqual([e["fomo"]["status"] for e in doc["entries"]], ["matched", "ambiguous", "failed", "failed", "failed"])
                self.assertIsNone(doc["entries"][0]["fomo"]["user_id"])
                if key == b58_key:
                    self.assertIsNone(doc["entries"][0]["fomo"]["solana_wallet"], "an address sharing a run with the key is dropped")

    def test_missing_key_sends_nothing_and_leaves_the_file(self):
        path = self.small_file(["heat"])
        before = path.read_bytes()
        opener = Opener([answer(trader("heat"))])
        with mock.patch.object(fa, "find_env_file", return_value=None):
            code, out, _ = run_main(["--watchlist", str(path)], opener, env={})
        self.assertEqual((code, opener.requests, path.read_bytes()), (2, [], before))
        self.assertEqual(out.splitlines()[-1], "unavailable (missing_key; no Fomo API call sent; the watchlist file unchanged)")

    def test_the_env_file_goes_through_fomoapis_single_variable_loader(self):
        env_file = self.tmp / ".env"
        env_file.write_text("OTHER_API_KEY=not-this-one-123456\nFOMOAPI_KEY=\"from-file-0123456789\"\n")
        path = self.small_file(["heat"])
        opener = Opener([answer(trader("heat"))])
        code, _, _ = run_main(["--watchlist", str(path), "--env-file", str(env_file)], opener, env={})
        self.assertEqual(code, 0)
        self.assertEqual(opener.requests[0][0].get_header("Authorization"), "Bearer from-file-0123456789")

    def test_holder_forensics_env_points_the_loader_at_the_dlmm_env(self):
        """Repair R1 (Verifier F5): the documented alternative to --env-file, HOLDER_FORENSICS_ENV, reaches fomoapi.py's loader."""
        env_file = self.tmp / "dlmm.env"
        env_file.write_text("FOMOAPI_KEY=from-setting-0123456789\n")
        path = self.small_file(["heat"])
        opener = Opener([answer(trader("heat"))])
        code, _, _ = run_main(["--watchlist", str(path)], opener, env={"HOLDER_FORENSICS_ENV": str(env_file)})
        self.assertEqual(code, 0)
        self.assertEqual(opener.requests[0][0].get_header("Authorization"), "Bearer from-setting-0123456789")

    def test_the_saved_file_keeps_the_static_fields_and_fills_every_fomo_object(self):
        path = self.tmp / "watchlist.json"
        original = json.loads(WATCHLIST.read_text())
        for e in original["entries"]:
            e["fomo"] = None
        original["fomo_verification"] = None
        path.write_text(json.dumps(original, indent=2, ensure_ascii=False) + "\n")
        answers = [answer(trader(n, followers=100 + i)) for i, n in enumerate(NAMES)]
        code, out, _ = run_main(["--watchlist", str(path)], Opener(answers))
        self.assertEqual(code, 0)
        saved = json.loads(path.read_text())
        strip = lambda d: [{k: v for k, v in e.items() if k != "fomo"} for e in d["entries"]]  # noqa: E731
        self.assertEqual(strip(saved), strip(original), "only the fomo objects change")
        self.assertEqual({k: v for k, v in saved.items() if k not in ("entries", "fomo_verification")}, {k: v for k, v in original.items() if k not in ("entries", "fomo_verification")})
        self.assertTrue(all(set(e["fomo"]) == FOMO_KEYS and e["fomo"]["status"] == "matched" for e in saved["entries"]))
        run_ = saved["fomo_verification"]
        self.assertEqual((run_["calls_sent"], run_["credits_charged"], run_["stopped"], run_["request"], run_["host"]),
                         (20, 5000, None, "GET /v2/search?q=<handle>&type=traders&limit=5", "api.fomoapi.io"))
        self.assertTrue(out.splitlines()[-1].startswith("saved: watchlist.json (20 entries"))
        self.assertFalse((self.tmp / "watchlist.json.tmp").exists())

    def test_a_stopped_run_saves_what_was_read_and_exits_3_an_unwritable_file_exits_2(self):
        path = self.small_file(["heat", "cosby"])
        code, out, _ = run_main(["--watchlist", str(path)], Opener([http_error(402), answer(trader("cosby"))]))
        self.assertEqual(code, 3)
        self.assertEqual([e["fomo"]["reason"] for e in json.loads(path.read_text())["entries"]], ["credits_exhausted", "not_sent_run_stopped"])
        path = self.small_file(["heat"])
        before = path.read_bytes()
        with mock.patch.object(wv.os, "replace", side_effect=OSError("read-only")):
            code, _, err = run_main(["--watchlist", str(path)], Opener([answer(trader("heat"))]))
        self.assertEqual((code, err.strip(), path.read_bytes()), (2, "error: the watchlist file was not saved (not_writable)", before))


class SelfContainedTests(unittest.TestCase):
    def test_standard_library_and_fomoapi_only_one_path_get_only_no_key_name(self):
        text = (SCRIPTS / "watchlist_verify.py").read_text()
        tree = ast.parse(text)
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
        self.assertEqual(sorted(modules - set(sys.stdlib_module_names) - {"__future__", "fomoapi"}), [])
        self.assertNotIn("FOMOAPI_KEY", text, "the key name stays in fomoapi.py (per-file key binding)")
        self.assertNotIn("/Users/", text)
        strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        self.assertFalse([s for s in strings if "/v2/users" in s or "/v2/trading" in s or "/pay/" in s or "/ws/" in s or "wss:" in s])
        methods = {kw.value.value for n in ast.walk(tree) if isinstance(n, ast.Call) for kw in n.keywords if kw.arg == "method" and isinstance(kw.value, ast.Constant)}
        self.assertEqual(methods, {"GET"})
        self.assertEqual((wv.SEARCH_PATH, wv.MAX_CALLS, wv.MAX_NAMES, wv.MAX_RETRIES, wv.MIN_INTERVAL_S, wv.CREDITS_PER_CALL), ("/v2/search", 25, 20, 5, 4.0, 250))


if __name__ == "__main__":
    unittest.main()
