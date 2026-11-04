"""DS-SCANNER-API-T1: the `solscanner` collector reads Scanner (formerly SolScanner) through the Scanner API with the
owner's key first and falls back to the legacy keyless SolScanner endpoint. Offline: a routing fake opener, dummy
sk_live_ keys, the saved fixtures (fixtures/solscanner/mamesuke-scanner-net.json is the stream api.scanner.net served on
2026-11-04, reduced to the fields the parser reads; scanner-api-plan-required.json is the owner's key's live 403 answer
with the message and the request id removed). No network, no real key, no real .env."""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
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
NOW_MAMESUKE = dt.datetime(2026, 11, 4, 13, 27, 17, tzinfo=dt.timezone.utc)  # the live check's fetch time
KEY = "sk_live_" + "Zq9" * 14 + "Z"  # dummy, the documented shape: sk_live_ + 43 letters and digits
OTHER_KEY = "sk_live_" + "Yw4" * 14 + "Y"
API_URL = f"https://api.scanner.net/contracts/{CAPE}/scan/stream"
LEGACY_URL = f"https://api.solscanner.app/contracts/{CAPE}/scan/stream"
CREDENTIAL_HEADERS = {"authorization", "x-api-key", "cookie", "proxy-authorization"}


def mamesuke_stream() -> bytes:
    data = json.loads((FIXTURES / "mamesuke-scanner-net.json").read_text(encoding="utf-8"))
    return block("cache_hit", data["cache_hit"]) + block("complete", data["complete"])


def plan_required_body() -> bytes:
    return (FIXTURES / "scanner-api-plan-required.json").read_bytes()


def http_error(url: str, code: int, body: bytes = b"", headers: dict | None = None) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, code, "error", headers or {}, io.BytesIO(body))


def error_body(code: str) -> bytes:
    return json.dumps({"error": f"private text {KEY}", "code": code, "requestId": "req-123"}).encode()


class Router:
    """A fake opener: answers per host from a queue, records every request (URL, headers, timeout)."""

    def __init__(self, api=(), legacy=()):
        self.answers = {"api.scanner.net": list(api), "api.solscanner.app": list(legacy)}
        self.requests: list[tuple[str, dict, float]] = []

    def open(self, request, timeout=None):
        self.requests.append((request.full_url, dict(request.header_items()), timeout))
        host = request.full_url.split("/")[2]
        queue = self.answers[host]
        if not queue:
            raise AssertionError(f"unexpected request to {host}")
        answer = queue.pop(0)
        if callable(answer):
            answer = answer()
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def urls(self) -> list[str]:
        return [u for u, _, _ in self.requests]


def run(router: Router, key: str | None = KEY, mint: str = CAPE, now=NOW_CAPE, **kw) -> tuple[dict, list[float]]:
    slept: list[float] = []
    result = ss.collect_scanner(mint, key, opener=router, now=lambda: now, sleep=slept.append, **kw)
    return result, slept


def fresh_cape() -> Response:
    return Response(stream("cape"))


class ApiFirstTests(unittest.TestCase):
    def test_api_answer_is_used_and_the_legacy_endpoint_is_never_called(self):
        router = Router(api=[Response(mamesuke_stream())])
        result, slept = run(router, mint=MAMESUKE, now=NOW_MAMESUKE, key_variable="SCANNER_NET_API_KEY")
        self.assertEqual(router.urls(), [f"https://api.scanner.net/contracts/{MAMESUKE}/scan/stream"])
        self.assertEqual(slept, [])
        self.assertEqual((result["source"], result["api_status"], result["api_reason"], result["legacy_status"]), ("scanner_api", "answered", None, "not_sent"))
        self.assertEqual((len(result["groups"]), result["reason"], result["is_stale"], result["scan_complete"]), (11, "provider_stale", True, True))
        self.assertIsNone(result["scans_spent"], "Scanner reports no count: null, never 0")
        self.assertIs(result["api_cache_hit"], True)
        self.assertEqual(result["request"]["api"], {"host": "api.scanner.net", "method": "GET", "path": "/contracts/<MINT>/scan/stream", "auth_header": "x-api-key",
                                                    "key_variable": "SCANNER_NET_API_KEY", "requests_sent": 1})
        self.assertEqual(result["request"]["legacy"]["requests_sent"], 0)
        self.assertEqual(ss.status_line(result), "ok (11 bundle groups; provider_stale; Scanner API; cached result; corroboration only)")
        self.assertEqual(ss.source_text(result), "source: Scanner API (api.scanner.net, the owner's key; scans spent: not reported by Scanner; "
                                                 "a cached result, free by Scanner's docs)")
        hf.validate_solscanner_result(json.loads(json.dumps(result)))

    def test_the_api_answer_parses_exactly_like_the_legacy_stream(self):
        """The same bytes through both endpoints give the same observation (only the source facts differ)."""
        api, _ = run(Router(api=[Response(mamesuke_stream())]), mint=MAMESUKE, now=NOW_MAMESUKE)
        legacy = ss.collect_solscanner(MAMESUKE, opener=Router(legacy=[Response(mamesuke_stream())]), now=lambda: NOW_MAMESUKE)
        self.assertEqual({k: api[k] for k in legacy}, legacy)

    def test_one_credential_only_in_the_x_api_key_header_never_in_the_url(self):
        router = Router(api=[fresh_cape()])
        result, _ = run(router)
        url, headers, timeout = router.requests[0]
        self.assertEqual(url, API_URL)
        self.assertTrue(url.startswith("https://"))
        self.assertNotIn("sk_live", url)
        lower = {k.lower(): v for k, v in headers.items()}
        self.assertEqual(set(lower) & CREDENTIAL_HEADERS, {"x-api-key"}, "exactly one credential")
        self.assertEqual(lower["x-api-key"], KEY)
        self.assertFalse({"origin", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest"} & set(lower), "no browser-like headers (API_KEY_BROWSER_NOT_ALLOWED)")
        self.assertEqual(lower["accept"], "text/event-stream")
        self.assertTrue(0 < timeout <= ss.DEADLINE_SECONDS)
        self.assertEqual(result["source"], "scanner_api")

    def test_the_legacy_request_carries_no_key(self):
        router = Router(api=[http_error(API_URL, 403, plan_required_body())], legacy=[fresh_cape()])
        run(router)
        url, headers, _ = router.requests[1]
        self.assertEqual(url, LEGACY_URL)
        self.assertFalse({k.lower() for k in headers} & CREDENTIAL_HEADERS)
        self.assertNotIn(KEY, json.dumps(headers))

    def test_without_a_key_only_the_legacy_endpoint_is_called(self):
        for key, reason in ((None, "no_key"), ("sk_live_short", "key_format"), (KEY + " ", "key_format"), ("Bearer " + KEY, "key_format")):
            with self.subTest(reason=reason, key=key and key[:12]):
                router = Router(legacy=[fresh_cape()])
                result, _ = run(router, key=key)
                self.assertEqual(router.urls(), [LEGACY_URL])
                self.assertEqual((result["source"], result["api_status"], result["api_reason"], result["legacy_status"]), ("legacy_keyless", "not_sent", reason, "answered"))
                self.assertEqual(result["request"]["api"]["requests_sent"], 0)
                self.assertIsNone(result["request"]["api"]["key_variable"])

    def test_the_loader_reason_is_kept_when_there_is_no_key(self):
        router = Router(legacy=[fresh_cape()])
        result, _ = run(router, key=None, key_reason="env_file_unreadable")
        self.assertEqual(result["api_reason"], "env_file_unreadable")


class FallbackTests(unittest.TestCase):
    CASES = [
        ("401 invalid key", lambda: http_error(API_URL, 401, error_body("API_KEY_INVALID")), "authentication_failed", 401, "API_KEY_INVALID"),
        ("401 revoked", lambda: http_error(API_URL, 401, error_body("API_KEY_REVOKED")), "key_revoked", 401, "API_KEY_REVOKED"),
        ("402 credits", lambda: http_error(API_URL, 402, error_body("INSUFFICIENT_CREDITS")), "insufficient_credits", 402, "INSUFFICIENT_CREDITS"),
        ("403 plan (the live answer)", lambda: http_error(API_URL, 403, plan_required_body()), "plan_required", 403, "API_PLAN_REQUIRED"),
        ("403 route", lambda: http_error(API_URL, 403, error_body("API_KEY_ROUTE_NOT_ALLOWED")), "route_not_allowed", 403, "API_KEY_ROUTE_NOT_ALLOWED"),
        ("403 ip", lambda: http_error(API_URL, 403, error_body("API_KEY_IP_NOT_ALLOWED")), "ip_not_allowed", 403, "API_KEY_IP_NOT_ALLOWED"),
        ("403 undocumented code", lambda: http_error(API_URL, 403, error_body("SOMETHING_NEW")), "access_denied", 403, None),
        ("403 html body", lambda: http_error(API_URL, 403, b"<html>blocked</html>"), "access_denied", 403, None),
        ("404 route", lambda: http_error(API_URL, 404, b""), "route_not_found", 404, None),
        ("429 without Retry-After", lambda: http_error(API_URL, 429, error_body("API_KEY_RATE_LIMITED")), "rate_limited", 429, "API_KEY_RATE_LIMITED"),
        ("429 Retry-After 30", lambda: http_error(API_URL, 429, error_body("API_KEY_RATE_LIMITED"), {"Retry-After": "30"}), "rate_limited", 429, "API_KEY_RATE_LIMITED"),
        ("500", lambda: http_error(API_URL, 500, b""), "server_error", 500, None),
        ("timeout", lambda: TimeoutError(), "timeout", None, None),
        ("network error", lambda: urllib.error.URLError(OSError("refused")), "network_error", None, None),
        ("redirect", lambda: http_error(API_URL, 301, b"", {"Location": "https://evil.example/x"}), "redirect_disallowed", 301, None),
        ("not an event stream", lambda: Response(json.dumps({"bundleGroups": []}).encode(), content_type="application/json"), "non_sse_response", 200, None),
        ("renamed field", lambda: Response(block("cache_hit", {"scannedAt": "2026-10-14T10:04:00.000Z", "isStale": False})
                                           + block("complete", {"mint": CAPE, "bundleGroupsV2": []})), "missing_bundle_groups", 200, None),
        ("another mint", lambda: Response(block("complete", {"mint": MAMESUKE, "bundleGroups": []})), "identity_mismatch", 200, None),
    ]

    def test_every_api_failure_falls_back_to_exactly_one_legacy_request(self):
        for name, answer, reason, status, code in self.CASES:
            with self.subTest(name):
                router = Router(api=[answer], legacy=[fresh_cape()])
                result, slept = run(router)
                self.assertEqual(router.urls(), [API_URL, LEGACY_URL], "one API request (no retry), then exactly one legacy request")
                self.assertEqual(slept, [])
                self.assertEqual((result["source"], result["api_status"], result["api_reason"], result["legacy_status"]), ("legacy_keyless", "failed", reason, "answered"))
                self.assertEqual((result["api_http_status"], result["api_error_code"]), (status, code))
                self.assertEqual((result["status"], result["reason"], len(result["groups"])), ("ok", None, 1))
                self.assertEqual((result["request"]["api"]["requests_sent"], result["request"]["legacy"]["requests_sent"]), (1, 1))
                text = json.dumps(result)
                self.assertNotIn("private text", text, "an error body is never kept, only the documented code")
                self.assertNotIn("req-123", text)
                self.assertFalse(ss.shares_key_piece(text, KEY))
                self.assertIn(f"Scanner API not read: {reason}", ss.source_text(result))
                hf.validate_solscanner_result(json.loads(text))

    def test_both_failing_is_unavailable_with_both_reasons(self):
        router = Router(api=[http_error(API_URL, 403, plan_required_body())], legacy=[http_error(LEGACY_URL, 500, b"down")])
        result, _ = run(router)
        self.assertEqual(router.urls(), [API_URL, LEGACY_URL])
        self.assertIsNone(result["source"])
        self.assertEqual((result["api_reason"], result["legacy_status"], result["legacy_reason"], result["reason"], result["groups"]),
                         ("plan_required", "failed", "http_error", "http_error", []))
        self.assertEqual(ss.status_line(result), "unavailable (http_error; Scanner API not read: plan_required; the result file records it)")
        self.assertEqual(ss.source_text(result), "source: none answered (Scanner API not read: plan_required; legacy keyless SolScanner endpoint not read: http_error)")
        saved = json.loads(json.dumps(result))
        hf.validate_solscanner_result(saved)
        finding = hf.solscanner_finding_for(saved)
        self.assertEqual(finding["status"], "unavailable")
        blk = hf._solscanner_source(saved, finding)
        self.assertEqual(blk["lines"], ["could not be read: http_error", ss.source_text(result)])

    def test_no_key_and_the_legacy_endpoint_failing(self):
        router = Router(legacy=[TimeoutError()])
        result, _ = run(router, key=None)
        self.assertEqual(router.urls(), [LEGACY_URL])
        self.assertEqual((result["source"], result["api_reason"], result["legacy_reason"]), (None, "no_key", "timeout"))
        self.assertEqual(ss.status_line(result), "unavailable (timeout; Scanner API not read: no_key; the result file records it)")

    def test_a_legacy_crash_is_a_reason_never_a_traceback(self):
        with mock.patch.object(ss, "collect_solscanner", side_effect=RuntimeError(f"https://x/?k={KEY}")):
            result, _ = run(Router(), key=None)
        self.assertEqual((result["source"], result["legacy_reason"], result["reason"]), (None, "network_error", "network_error"))
        self.assertNotIn(KEY, json.dumps(result))


class RetryTests(unittest.TestCase):
    def test_one_retry_after_a_short_429_then_the_api_answers(self):
        router = Router(api=[http_error(API_URL, 429, error_body("API_KEY_RATE_LIMITED"), {"Retry-After": "2"}), fresh_cape()])
        result, slept = run(router)
        self.assertEqual(router.urls(), [API_URL, API_URL])
        self.assertEqual(slept, [2.0])
        self.assertEqual((result["source"], result["request"]["api"]["requests_sent"]), ("scanner_api", 2))

    def test_a_429_with_retry_after_of_exactly_5_s_is_retried_once(self):
        router = Router(api=[http_error(API_URL, 429, b"", {"Retry-After": "5"}), http_error(API_URL, 429, b"", {"Retry-After": "1"})], legacy=[fresh_cape()])
        result, slept = run(router)
        self.assertEqual(router.urls(), [API_URL, API_URL, LEGACY_URL], "at most 1 retry, then the fallback")
        self.assertEqual(slept, [5.0])
        self.assertEqual((result["source"], result["api_reason"], result["request"]["api"]["requests_sent"]), ("legacy_keyless", "rate_limited", 2))

    def test_a_503_is_retried_once_after_a_second(self):
        router = Router(api=[http_error(API_URL, 503, error_body("INTERNAL_ERROR")), fresh_cape()])
        result, slept = run(router)
        self.assertEqual(slept, [ss.API_503_WAIT_S])
        self.assertEqual((result["source"], result["request"]["api"]["requests_sent"]), ("scanner_api", 2))
        router = Router(api=[http_error(API_URL, 503, b""), http_error(API_URL, 503, b"")], legacy=[fresh_cape()])
        result, slept = run(router)
        self.assertEqual(router.urls(), [API_URL, API_URL, LEGACY_URL])
        self.assertEqual((result["api_reason"], len(slept)), ("server_error", 1))

    def test_no_retry_for_anything_else(self):
        for answer in (http_error(API_URL, 429, b"", {"Retry-After": "6"}), http_error(API_URL, 429, b"", {"Retry-After": "soon"}), http_error(API_URL, 502, b""),
                       http_error(API_URL, 503, b"", {"Retry-After": "60"}), http_error(API_URL, 401, b""), TimeoutError()):
            with self.subTest(answer=repr(answer)[:40]):
                router = Router(api=[answer], legacy=[fresh_cape()])
                _, slept = run(router)
                self.assertEqual(router.urls(), [API_URL, LEGACY_URL])
                self.assertEqual(slept, [])


class CapsTests(unittest.TestCase):
    def test_the_bounds_are_the_legacy_bounds(self):
        self.assertEqual((ss.MAX_BYTES, ss.DEADLINE_SECONDS, ss.API_RETRY_MAX_WAIT_S, ss.API_ERROR_BODY_MAX), (1024 * 1024, 10.0, 5.0, 4096))
        self.assertTrue(ss.API_BASE_URL.startswith("https://api.scanner.net/"))

    def test_an_oversized_api_answer_falls_back(self):
        router = Router(api=[Response(b"x" * (ss.MAX_BYTES + 1))], legacy=[fresh_cape()])
        result, _ = run(router)
        self.assertEqual((result["api_reason"], result["source"]), ("response_too_large", "legacy_keyless"))

    def test_a_stalled_api_open_is_cut_at_the_deadline_then_the_fallback_runs(self):
        def slow():
            time.sleep(0.2)
            return fresh_cape()

        router = Router(api=[slow], legacy=[fresh_cape()])
        started = time.monotonic()
        with mock.patch("solscanner_scan.DEADLINE_SECONDS", 0.05):
            result, _ = run(router)
        self.assertLess(time.monotonic() - started, 0.18)
        self.assertEqual((result["api_reason"], result["source"]), ("timeout", "legacy_keyless"))

    def test_a_large_error_body_is_read_only_up_to_the_cap(self):
        reads: list[int] = []

        class CountingBody(io.BytesIO):
            def read(self, n=-1):
                reads.append(n)
                return super().read(n)

        body = CountingBody(json.dumps({"code": "API_PLAN_REQUIRED", "pad": "x" * 10_000}).encode())
        router = Router(api=[urllib.error.HTTPError(API_URL, 403, "e", {}, body)], legacy=[fresh_cape()])
        result, _ = run(router)
        self.assertEqual(reads[:1], [ss.API_ERROR_BODY_MAX])
        self.assertEqual((result["api_reason"], result["api_error_code"]), ("access_denied", None), "a cut-off body is not parsed: no code, plain 403")

    def test_the_default_transport_has_no_proxy_and_no_redirects(self):
        with mock.patch("solscanner_scan.urllib.request.build_opener") as factory:
            factory.return_value = Router(api=[fresh_cape()])
            result = ss.collect_scanner(CAPE, KEY, now=lambda: NOW_CAPE)
        self.assertEqual(result["source"], "scanner_api")
        self.assertEqual(factory.call_args.args[0].proxies, {})
        self.assertEqual(factory.call_args.args[1].__name__, "NoRedirect")


class KeyEchoTests(unittest.TestCase):
    PIECE = "Hjk2Lmn9"
    ECHO_KEY = "sk_live_" + "A" * 35 + PIECE  # dummy; its last 8 characters are a valid base58 run
    ECHO_WALLET = PIECE + "W" * 36

    def test_a_saved_wallet_sharing_8_characters_with_the_key_is_dropped(self):
        groups = [{"groupId": 1, "riskScore": 50, "confidence": "low", "bundleType": "mixed",
                   "wallets": [{"address": self.ECHO_WALLET, "percentageOfSupply": 3.0}, {"address": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "percentageOfSupply": 2.0}]}]
        body = block("cache_hit", {"scannedAt": "2026-10-14T10:04:00.000Z", "isStale": False}) + block("complete", {"mint": CAPE, "bundleGroups": groups, "scanComplete": True})
        result, _ = run(Router(api=[Response(body)]), key=self.ECHO_KEY)
        self.assertEqual(result["key_echo_dropped"], 1)
        self.assertEqual([w["address"] for w in result["groups"][0]["wallets"]], ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"])
        self.assertFalse(ss.shares_key_piece(json.dumps(result), self.ECHO_KEY))

    def test_main_withholds_a_result_that_still_echoes_the_key(self):
        leaked = dict(ss._empty(CAPE, "2026-10-14T10:05:00Z", "provider_stale"), source="legacy_keyless", api_reason="no_key", note=KEY[10:20])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "solscanner.json"
            stdout = io.StringIO()
            with mock.patch.object(ss, "load_key", return_value=(KEY, None, "SCANNER_NET_API_KEY")), mock.patch.object(ss, "env_key_set", return_value=True), \
                 mock.patch.object(ss, "collect_scanner", return_value=leaked), contextlib.redirect_stdout(stdout):
                code = ss.main([CAPE, "--out", str(out)])
            saved = json.loads(out.read_text())
        self.assertEqual(code, 0)
        self.assertEqual((saved["reason"], saved["groups"]), ("key_echo_withheld", []))
        self.assertNotIn("source", saved)
        self.assertEqual(stdout.getvalue().strip(), "unavailable (key_echo_withheld; the result file records it)")
        hf.validate_solscanner_result(saved)
        self.assertEqual(hf.solscanner_finding_for(saved)["status"], "unavailable")


class KeyLoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def env(self, **values):
        clean = {k: v for k, v in os.environ.items() if k not in ss.API_KEY_NAMES and k != "HOLDER_FORENSICS_ENV"}
        return mock.patch.dict(os.environ, {**clean, **values}, clear=True)

    def dotenv(self, text: str) -> Path:
        path = self.tmp / ".env"
        path.write_text(text, encoding="utf-8")
        return path

    def test_environment_first_upper_case_then_the_owners_lower_case_spelling(self):
        with self.env(SCANNER_NET_API_KEY=KEY, scanner_net_api_key=OTHER_KEY):
            self.assertEqual(ss.load_key(None), (KEY, None, "SCANNER_NET_API_KEY"))
            self.assertTrue(ss.env_key_set())
        with self.env(scanner_net_api_key=OTHER_KEY):
            self.assertEqual(ss.load_key(self.dotenv(f"SCANNER_NET_API_KEY={KEY}\n")), (OTHER_KEY, None, "scanner_net_api_key"))
        with self.env():
            self.assertFalse(ss.env_key_set())
            self.assertEqual(ss.load_key(None), (None, "no_key", None))

    def test_only_that_one_variable_is_read_from_the_dotenv(self):
        text = (f"HELIUS_API_KEY=sk_live_{'H' * 43}\nOTHER=sk_live_{'O' * 43}\n# scanner_net_api_key={OTHER_KEY}\n"
                f"export scanner_net_api_key=\"{KEY}\"  \nSCANNER_NET_API_KEY_OLD={OTHER_KEY}\n")
        with self.env():
            self.assertEqual(ss.load_key(self.dotenv(text)), (KEY, None, "scanner_net_api_key"))
            both = self.dotenv(f"scanner_net_api_key={OTHER_KEY}\nSCANNER_NET_API_KEY={KEY} # the paid key\n")
            self.assertEqual(ss.load_key(both), (KEY, None, "SCANNER_NET_API_KEY"), "the upper-case line wins, an inline comment is dropped")
            self.assertEqual(ss.load_key(self.dotenv("HELIUS_API_KEY=abc\n")), (None, "no_key", None))
            self.assertEqual(ss.load_key(self.dotenv("scanner_net_api_key=not-a-key\n")), (None, "key_format", None))
            self.assertEqual(ss.load_key(self.tmp / "missing" / ".env"), (None, "env_file_unreadable", None))

    def test_the_command_line_reads_the_lower_case_key_from_env_file_and_never_shows_it(self):
        env_file = self.dotenv(f"OTHER_SECRET=topsecretvalue\nscanner_net_api_key={KEY}\n")
        router = Router(api=[http_error(f"https://api.scanner.net/contracts/{MAMESUKE}/scan/stream", 403, plan_required_body())],
                        legacy=[Response(mamesuke_stream())])
        out, err = io.StringIO(), io.StringIO()
        target = self.tmp / "run" / "solscanner.json"
        with self.env(), mock.patch("solscanner_scan.urllib.request.build_opener", return_value=router), \
             mock.patch.object(ss, "utc_now", return_value=NOW_MAMESUKE), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ss.main([MAMESUKE, "--out", str(target), "--env-file", str(env_file)])
        self.assertEqual(code, 0, err.getvalue())
        self.assertEqual(out.getvalue().strip(), "ok (11 bundle groups; provider_stale; legacy keyless SolScanner endpoint, Scanner API not read: plan_required; corroboration only)")
        saved_text = target.read_text()
        for text in (saved_text, out.getvalue(), err.getvalue()):
            self.assertFalse(ss.shares_key_piece(text, KEY))
            self.assertNotIn("topsecretvalue", text)
        saved = json.loads(saved_text)
        self.assertEqual((saved["request"]["api"]["key_variable"], saved["request"]["api"]["auth_header"]), ("scanner_net_api_key", "x-api-key"))
        self.assertEqual(router.urls(), [f"https://api.scanner.net/contracts/{MAMESUKE}/scan/stream", f"https://api.solscanner.app/contracts/{MAMESUKE}/scan/stream"])
        hf.validate_solscanner_result(saved)

    def test_a_set_environment_key_skips_the_dotenv(self):
        with self.env(SCANNER_NET_API_KEY=KEY), mock.patch.object(ss, "find_env_file", side_effect=AssertionError("must not look for the .env")), \
             mock.patch.object(ss, "collect_scanner", return_value=ss._empty(CAPE, "2026-10-14T10:05:00Z", "timeout")) as call, contextlib.redirect_stdout(io.StringIO()):
            ss.main([CAPE, "--out", str(self.tmp / "s.json")])
        self.assertEqual(call.call_args.args, (CAPE, KEY))
        self.assertEqual(call.call_args.kwargs, {"key_reason": None, "key_variable": "SCANNER_NET_API_KEY"})


class EngineTests(unittest.TestCase):
    """assess shows which endpoint answered (one display line) and nothing else changes: the same verdict and flag as the
    same result without the source facts; the engine's own --solscanner read never reaches the Scanner API."""

    def labelled(self, router, key=KEY):
        return run(router, key=key)[0]

    def test_the_source_line_is_display_only(self):
        from test_verdict_gating import holders_dict

        for router, line in ((Router(api=[fresh_cape()]), "source: Scanner API (api.scanner.net, the owner's key; scans spent: not reported by Scanner; a cached result, free by Scanner's docs)"),
                             (Router(api=[http_error(API_URL, 403, plan_required_body())], legacy=[fresh_cape()]),
                              "source: legacy keyless SolScanner endpoint (Scanner API not read: plan_required; the keyless read uses none of the plan's scans)")):
            with self.subTest(line[:40]):
                res = json.loads(json.dumps(self.labelled(router)))
                hf.validate_solscanner_result(res)
                bare = {k: res[k] for k in ss._empty(CAPE, "x", "x")}
                a = hf.assess(holders_dict(), None, [hf.solscanner_finding_for(res, NOW_CAPE)], solscanner=res)
                b = hf.assess(holders_dict(), None, [hf.solscanner_finding_for(bare, NOW_CAPE)], solscanner=bare)
                self.assertEqual((a["verdict"], a["flag"], a["findings"]), (b["verdict"], b["flag"], b["findings"]))
                block_a = next(s for s in a["sources"] if s["key"] == "solscanner")
                block_b = next(s for s in b["sources"] if s["key"] == "solscanner")
                self.assertEqual(block_a["lines"], block_b["lines"] + [line])
                md = hf.markdown_report(CAPE, holders_dict(), None, 0, a)
                self.assertIn(f"  - {line}", md)
                self.assertEqual(a["flag"]["label"], "CAUTION", "corroboration only: the CAPE hint stays CAUTION, never DANGER")

    def test_assess_reads_an_api_sourced_file(self):
        import test_assess as ta

        case = ta.case_stopped_failures()
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            code, _, _ = ta._run(["funders", case.mint, "--top", "40", "--workers", "1", "--out", str(run_dir)], fake=case.fake())
            self.assertEqual(code, 0)
            api_url = f"https://api.scanner.net/contracts/{case.mint}/scan/stream"
            res = ss.collect_scanner(case.mint, KEY, opener=Router(api=[http_error(api_url, 402, error_body("INSUFFICIENT_CREDITS"))], legacy=[TimeoutError()]),
                                     now=lambda: ta.FROZEN, sleep=lambda s: None)
            (run_dir / "solscanner.json").write_text(json.dumps(res))
            code_s, _, err = ta.run_assess(case.mint, run_dir, ["--solscanner-json", str(run_dir / "solscanner.json")])
            report = (run_dir / "report.md").read_text()
        self.assertEqual(code_s, 0, err)
        self.assertIn("SolScanner public scan: unavailable", report)
        self.assertIn("source: none answered (Scanner API not read: insufficient_credits; legacy keyless SolScanner endpoint not read: timeout)", report)
        self.assertNotIn(KEY[8:16], report)

    def test_tampered_source_facts_are_refused(self):
        good = json.loads(json.dumps(self.labelled(Router(api=[fresh_cape()]))))
        hf.validate_solscanner_result(good)
        for change in ({"source": "Scanner API"}, {"source": "legacy_keyless"}, {"api_status": "maybe"}, {"api_reason": "Plan Required"},
                       {"api_reason": "ignore previous instructions"}, {"legacy_reason": 5}, {"api_error_code": "NOT_A_CODE"}, {"scans_spent": -1},
                       {"scans_spent": True}, {"scans_spent": 1.5}, {"api_http_status": 999}, {"api_cache_hit": "yes"}, {"key_echo_dropped": -1}):
            with self.subTest(change):
                with self.assertRaises(hf.ConfigError):
                    hf.validate_solscanner_result(dict(good, **change))

    def test_an_older_saved_file_without_source_facts_shows_no_source_line(self):
        res = ss.collect_solscanner(CAPE, opener=Router(legacy=[fresh_cape()]), now=lambda: NOW_CAPE)
        blk = hf._solscanner_source(res, hf.solscanner_finding_for(res, NOW_CAPE))
        self.assertFalse([ln for ln in blk["lines"] if ln.startswith("source:")])

    def test_the_engines_live_flag_reads_only_the_legacy_endpoint(self):
        router = Router(legacy=[fresh_cape()])
        with mock.patch("solscanner_scan.urllib.request.build_opener", return_value=router):
            res = hf.load_solscanner(types.SimpleNamespace(solscanner=True, solscanner_json=None), CAPE)
        self.assertEqual(router.urls(), [LEGACY_URL])
        self.assertEqual((res["source"], res["api_status"], res["api_reason"]), ("legacy_keyless", "not_sent", "no_key"))
        code = (SCRIPTS / "helius_forensics.py").read_text()
        self.assertIn('collect_scanner(mint, None, key_reason="no_key")', code)
        self.assertNotIn("SCANNER_NET_API_KEY", code)
        self.assertNotIn("scanner_net_api_key", code.lower(), "the engine names neither spelling of the Scanner key")


if __name__ == "__main__":
    unittest.main()
