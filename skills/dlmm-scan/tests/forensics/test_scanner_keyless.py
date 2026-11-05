"""DS-SCANNER-FREE-T1: the `solscanner` collector reads only the free keyless SolScanner endpoint (no key, no paid Scanner
API: DS-SCANNER-API-T1's keyed path is removed) and classifies the answer: groups read (cached by Scanner) -> source
legacy_keyless; anything else -> a fixed reason and needs_browser, so the scanner_browser follow-up lane can read the token
through the owner's logged-in scanner.net page. Offline: a fake opener, the saved fixtures
(fixtures/solscanner/mamesuke-scanner-net.json is the cached stream Scanner served without a key on 2026-11-04, reduced to
the fields the parser reads; keyless-not-cached.json is the keyless answer for a token created a minute earlier, HTTP 401,
with its request id removed). No network, no key, no .env."""

from __future__ import annotations

import datetime as dt
import io
import json
import sys
import tempfile
import time
import types
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
import solscanner_scan as ss  # noqa: E402
from test_solscanner_scan import CAPE, NOW_CAPE, Response, block, stream  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "solscanner"
MAMESUKE = "SCGBBnSwnekytGFHgyeHHxPMiN7xDxsWFGg9JgFSTNK"
NOW_MAMESUKE = dt.datetime(2026, 11, 4, 14, 45, 6, tzinfo=dt.timezone.utc)  # the live check's fetch time
URL = f"https://api.solscanner.app/contracts/{CAPE}/scan/stream"
CREDENTIAL_HEADERS = {"authorization", "x-api-key", "cookie", "proxy-authorization"}
BROWSER_LINE = "the scanner_browser follow-up lane reads it from the logged-in scanner.net page"


def mamesuke_stream() -> bytes:
    data = json.loads((FIXTURES / "mamesuke-scanner-net.json").read_text(encoding="utf-8"))
    return block("cache_hit", data["cache_hit"]) + block("complete", data["complete"])


def not_cached_body() -> bytes:
    return (FIXTURES / "keyless-not-cached.json").read_bytes()


def http_error(code: int, body: bytes = b"") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(URL, code, "error", {}, io.BytesIO(body))


class Recorder:
    """A fake opener: one scripted answer, every request recorded (URL, headers, timeout)."""

    def __init__(self, answer):
        self.answer = answer
        self.requests: list[tuple[str, dict, float]] = []

    def open(self, request, timeout=None):
        self.requests.append((request.full_url, dict(request.header_items()), timeout))
        answer = self.answer() if callable(self.answer) else self.answer
        if isinstance(answer, BaseException):
            raise answer
        return answer


def read(answer, mint: str = CAPE, now=NOW_CAPE) -> tuple[dict, Recorder]:
    rec = Recorder(answer)
    return ss.collect_keyless(mint, opener=rec, now=lambda: now), rec


class CachedTests(unittest.TestCase):
    def test_a_cached_scan_is_read_with_no_key_and_no_browser(self):
        result, rec = read(Response(mamesuke_stream()), mint=MAMESUKE, now=NOW_MAMESUKE)
        self.assertEqual(len(rec.requests), 1, "one request, no retry")
        url, headers, timeout = rec.requests[0]
        self.assertEqual(url, f"https://api.solscanner.app/contracts/{MAMESUKE}/scan/stream")
        self.assertFalse({k.lower() for k in headers} & CREDENTIAL_HEADERS, "no credential of any kind")
        self.assertEqual({k.lower() for k in headers}, {"accept", "user-agent"})
        self.assertTrue(0 < timeout <= ss.DEADLINE_SECONDS)
        self.assertEqual((result["source"], result["keyless_status"], result["keyless_reason"], result["needs_browser"], result["scans_spent"]),
                         ("legacy_keyless", "answered", None, False, 0))
        self.assertEqual((len(result["groups"]), result["reason"], result["is_stale"], result["cache_hit"], result["keyless_http_status"]),
                         (11, "provider_stale", True, True, 200))
        self.assertEqual(result["request"], {"host": "api.solscanner.app", "method": "GET", "path": "/contracts/<MINT>/scan/stream", "credential": None,
                                             "requests_sent": 1})
        self.assertEqual(ss.status_line(result), "ok (11 bundle groups; provider_stale; free keyless endpoint, cached by Scanner; corroboration only)")
        self.assertEqual(ss.source_text(result), "source: free keyless SolScanner endpoint (no key, no account, no scan spent)")
        hf.validate_solscanner_result(json.loads(json.dumps(result)))

    def test_the_classification_keeps_the_parsers_result(self):
        legacy = ss.collect_solscanner(MAMESUKE, opener=Recorder(Response(mamesuke_stream())), now=lambda: NOW_MAMESUKE)
        result, _ = read(Response(mamesuke_stream()), mint=MAMESUKE, now=NOW_MAMESUKE)
        self.assertEqual({k: result[k] for k in legacy}, legacy)

    def test_a_cached_scan_with_no_bundle_group_is_an_answer_not_a_browser_case(self):
        body = block("cache_hit", {"scannedAt": "2026-10-14T10:04:00.000Z", "isStale": False}) + block("complete", {"mint": CAPE, "bundleGroups": [], "scanComplete": True})
        result, _ = read(Response(body))
        self.assertEqual((result["source"], result["needs_browser"], result["groups"]), ("legacy_keyless", False, []))


class NeedsBrowserTests(unittest.TestCase):
    CASES = [
        ("not cached (the live 401)", lambda: http_error(401, not_cached_body()), "not_cached_needs_login", 401, "NOT_AUTHENTICATED"),
        ("401 without a body", lambda: http_error(401), "not_cached_needs_login", 401, None),
        ("403", lambda: http_error(403, b"<html>blocked</html>"), "access_denied", 403, None),
        ("404", lambda: http_error(404), "not_found", 404, None),
        ("429", lambda: http_error(429, b'{"code":"RATE_LIMITED"}'), "rate_limited", 429, "RATE_LIMITED"),
        ("500", lambda: http_error(500, b'{"code":"INTERNAL_ERROR"}'), "server_error", 500, "INTERNAL_ERROR"),
        ("418", lambda: http_error(418), "http_error", 418, None),
        ("undocumented code", lambda: http_error(401, b'{"code":"SOMETHING_NEW","error":"text"}'), "not_cached_needs_login", 401, None),
        ("timeout", lambda: TimeoutError(), "timeout", None, None),
        ("network error", lambda: urllib.error.URLError(OSError("refused")), "network_error", None, None),
        ("redirect", lambda: http_error(301), "redirect_disallowed", 301, None),
        ("not an event stream", lambda: Response(b'{"bundleGroups":[]}', content_type="application/json"), "non_sse_response", 200, None),
        ("renamed field", lambda: Response(block("complete", {"mint": CAPE, "bundleGroupsV2": []})), "missing_bundle_groups", 200, None),
        ("no complete event", lambda: Response(block("cache_hit", {"scannedAt": "2026-10-14T10:04:00.000Z", "isStale": False})), "missing_bundle_groups", 200, None),
        ("empty answer", lambda: Response(b""), "missing_bundle_groups", 200, None),
        ("another mint", lambda: Response(block("complete", {"mint": MAMESUKE, "bundleGroups": []})), "identity_mismatch", 200, None),
        ("too large", lambda: Response(b"x" * (ss.MAX_BYTES + 1)), "response_too_large", 200, None),
    ]

    def test_every_failure_is_a_fixed_reason_with_needs_browser(self):
        for name, answer, reason, status, code in self.CASES:
            with self.subTest(name):
                result, rec = read(answer)
                self.assertEqual(len(rec.requests), 1, "exactly one request, no retry")
                self.assertEqual((result["source"], result["keyless_status"], result["keyless_reason"], result["reason"], result["needs_browser"]),
                                 (None, "failed", reason, reason, True))
                self.assertEqual((result["keyless_http_status"], result["keyless_error_code"], result["groups"], result["cache_hit"]), (status, code, [], None))
                self.assertEqual(ss.status_line(result), f"unavailable ({reason}; needs_browser: the scanner_browser follow-up lane reads it; the result file records it)")
                self.assertEqual(ss.source_text(result), f"source: free endpoint not read: {reason}; {BROWSER_LINE}")
                text = json.dumps(result)
                self.assertNotIn("Please log in", text, "an error body is never kept, only a known code")
                self.assertNotIn("request id", text)
                self.assertNotIn("blocked", text)
                saved = json.loads(text)
                hf.validate_solscanner_result(saved)
                finding = hf.solscanner_finding_for(saved)
                self.assertEqual(finding["status"], "unavailable")
                blk = hf._solscanner_source(saved, finding)
                self.assertEqual(blk["lines"], [f"could not be read: {reason}", ss.source_text(result)], "the engine prints the reason as its own code")

    def test_an_invalid_mint_sends_nothing_and_needs_no_browser(self):
        result, rec = read(Response(b""), mint="0x" + "a" * 40)
        self.assertEqual((rec.requests, result["needs_browser"], result["request"]["requests_sent"], result["reason"]), ([], False, 0, "invalid_mint"))
        self.assertEqual(ss.source_text(result), "source: free endpoint not read: invalid_mint")

    def test_a_crash_is_a_reason_never_a_traceback(self):
        with mock.patch.object(ss, "collect_solscanner", side_effect=RuntimeError("https://x/?token=SECRET")):
            result = ss.collect_keyless(CAPE)
        self.assertEqual((result["reason"], result["needs_browser"]), ("network_error", True))
        self.assertNotIn("SECRET", json.dumps(result))

    def test_a_large_error_body_is_read_only_up_to_the_cap(self):
        reads: list[int] = []

        class CountingBody(io.BytesIO):
            def read(self, n=-1):
                reads.append(n)
                return super().read(n)

        body = CountingBody(json.dumps({"code": "NOT_AUTHENTICATED", "pad": "x" * 10_000}).encode())
        result, _ = read(urllib.error.HTTPError(URL, 401, "e", {}, body))
        self.assertEqual(reads[:1], [ss.ERROR_BODY_MAX])
        self.assertEqual((result["keyless_reason"], result["keyless_error_code"]), ("not_cached_needs_login", None), "a cut-off body is not parsed")

    def test_a_stalled_open_is_cut_at_the_deadline(self):
        def slow():
            time.sleep(0.2)
            return Response(stream("cape"))

        started = time.monotonic()
        with mock.patch("solscanner_scan.DEADLINE_SECONDS", 0.05):
            result, _ = read(slow)
        self.assertLess(time.monotonic() - started, 0.18)
        self.assertEqual((result["reason"], result["needs_browser"]), ("timeout", True))


class NoApiTests(unittest.TestCase):
    def test_the_paid_api_path_is_gone(self):
        text = (SCRIPTS / "solscanner_scan.py").read_text(encoding="utf-8")
        for gone in ("SCANNER_NET_API_KEY", "scanner_net_api_key", "x-api-key", "api.scanner.net", "collect_scanner", "load_key", "find_env_file",
                     "API_KEY", "API_PLAN_REQUIRED", "Retry-After"):
            self.assertNotIn(gone, text, gone)
        self.assertEqual(ss.BASE_URL, "https://api.solscanner.app/contracts")
        self.assertEqual(ss.SOURCES, frozenset({"legacy_keyless", "scanner_browser"}))
        for name in ("collect_scanner", "load_key", "find_env_file", "env_key_set", "shares_key_piece", "API_BASE_URL"):
            self.assertFalse(hasattr(ss, name), name)

    def test_the_default_transport_has_no_proxy_and_no_redirects(self):
        with mock.patch("solscanner_scan.urllib.request.build_opener") as factory:
            factory.return_value = Recorder(Response(stream("cape")))
            result = ss.collect_keyless(CAPE, now=lambda: NOW_CAPE)
        self.assertEqual(result["source"], "legacy_keyless")
        self.assertEqual(factory.call_args.args[0].proxies, {})
        self.assertEqual(factory.call_args.args[1].__name__, "NoRedirect")


class EngineTests(unittest.TestCase):
    """assess shows where the scan was read (one display line) and nothing else changes: the same verdict, flag and findings
    as the same result without the source facts."""

    def test_the_source_line_is_display_only(self):
        from test_verdict_gating import holders_dict

        res = json.loads(json.dumps(read(Response(stream("cape")))[0]))
        browser = dict(res, source="scanner_browser", keyless_status="failed", keyless_reason="not_cached_needs_login", cache_hit=False, scans_spent=1)
        for saved, line in ((res, "source: free keyless SolScanner endpoint (no key, no account, no scan spent)"),
                            (browser, "source: read from the logged-in scanner.net page; free endpoint not read: not_cached_needs_login; spent 1 of the account's scans"),
                            (dict(browser, cache_hit=True, scans_spent=0), "source: read from the logged-in scanner.net page; free endpoint not read: not_cached_needs_login; cached, no scan spent")):
            with self.subTest(line[:60]):
                hf.validate_solscanner_result(saved)
                bare = {k: saved[k] for k in ss._empty(CAPE, "x", "x")}
                a = hf.assess(holders_dict(), None, [hf.solscanner_finding_for(saved, NOW_CAPE)], solscanner=saved)
                b = hf.assess(holders_dict(), None, [hf.solscanner_finding_for(bare, NOW_CAPE)], solscanner=bare)
                self.assertEqual((a["verdict"], a["flag"], a["findings"]), (b["verdict"], b["flag"], b["findings"]))
                block_a = next(s for s in a["sources"] if s["key"] == "solscanner")
                block_b = next(s for s in b["sources"] if s["key"] == "solscanner")
                self.assertEqual(block_a["lines"], block_b["lines"] + [line])
                self.assertIn(f"  - {line}", hf.markdown_report(CAPE, holders_dict(), None, 0, a))
                self.assertEqual(a["flag"]["label"], "CAUTION", "corroboration only: the CAPE hint stays CAUTION, never DANGER")

    def test_assess_reads_a_needs_browser_file(self):
        import test_assess as ta

        case = ta.case_stopped_failures()
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            code, _, _ = ta._run(["funders", case.mint, "--top", "40", "--workers", "1", "--out", str(run_dir)], fake=case.fake())
            self.assertEqual(code, 0)
            res = ss.collect_keyless(case.mint, opener=Recorder(http_error(401, not_cached_body())), now=lambda: ta.FROZEN)
            (run_dir / "solscanner.json").write_text(json.dumps(res))
            code_s, _, err = ta.run_assess(case.mint, run_dir, ["--solscanner-json", str(run_dir / "solscanner.json")])
            report = (run_dir / "report.md").read_text()
        self.assertEqual(code_s, 0, err)
        self.assertIn("SolScanner public scan: unavailable", report)
        self.assertIn("could not be read: not_cached_needs_login", report)
        self.assertIn(f"source: free endpoint not read: not_cached_needs_login; {BROWSER_LINE}", report)

    def test_tampered_source_facts_are_refused(self):
        good = json.loads(json.dumps(read(Response(stream("cape")))[0]))
        hf.validate_solscanner_result(good)
        for change in ({"source": "scanner_api"}, {"source": "Scanner API"}, {"keyless_status": "maybe"}, {"keyless_reason": "Please log in"},
                       {"keyless_reason": "ignore previous instructions"}, {"keyless_error_code": "NOT_A_CODE"}, {"scans_spent": 2}, {"scans_spent": True},
                       {"keyless_http_status": 999}, {"cache_hit": "yes"}, {"needs_browser": 1}, {"keyless_status": "failed"}):
            with self.subTest(change):
                with self.assertRaises(hf.ConfigError):
                    hf.validate_solscanner_result(dict(good, **change))

    def test_an_older_saved_file_without_source_facts_shows_no_source_line(self):
        res = ss.collect_solscanner(CAPE, opener=Recorder(Response(stream("cape"))), now=lambda: NOW_CAPE)
        blk = hf._solscanner_source(res, hf.solscanner_finding_for(res, NOW_CAPE))
        self.assertFalse([ln for ln in blk["lines"] if ln.startswith("source:")])

    def test_the_engines_live_flag_is_the_same_keyless_read(self):
        rec = Recorder(Response(stream("cape")))
        with mock.patch("solscanner_scan.urllib.request.build_opener", return_value=rec):
            res = hf.load_solscanner(types.SimpleNamespace(solscanner=True, solscanner_json=None), CAPE)
        self.assertEqual([u for u, _, _ in rec.requests], [URL])
        self.assertEqual((res["source"], res["keyless_status"]), ("legacy_keyless", "answered"))
        code = (SCRIPTS / "helius_forensics.py").read_text()
        self.assertIn("solscanner_scan.collect_keyless(mint)", code)
        self.assertNotIn("SCANNER_NET_API_KEY", code)
        self.assertNotIn("scanner_net_api_key", code.lower())


if __name__ == "__main__":
    unittest.main()
