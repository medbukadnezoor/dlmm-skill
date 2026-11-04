"""HS-PROV-T2: the `madeonsol` collector (two fixed, bounded MadeOnSol calls on the free BASIC tier, sent at the same time)
and its offline `--present` mode. Offline: fake transport, dummy keys, the live CAPE answers of 2026-10-19 saved as
fixtures (public data only; MadeOnSol's request ids removed).

Covers: request construction (host, the two documented paths and the fixed include query, the Bearer Authorization
header only, no env proxy, no redirects, size and time bounds, both calls at once, never a PRO-only or /rhc/ path); the
one retry after a short 429 and never more (at most 4 calls per scan), no retry on a daily-quota 429; the fixed reason
codes picked from a 403 / 429 body (tier_required, demo_key_not_allowed, daily_quota_exhausted); the hard wall-clock
deadline; the ok / empty / unavailable paths and the loud field guards against the live answer; the single-variable key
loader, the key never reaching an output and the key-echo guards; the --present block (Dev / deployer, launch bundle,
KOL positions, buyer quality, the PRO-only lines as not read, shares cut toward zero, never 0 for unread, never a crash on
a malformed file); and the presentation-only rule: a high MadeOnSol bundle share gives the late-source line next to the
FLAGs but never lowers or replaces a FLAG, and a low one never enables NO_ALARM (assess never reads the file and refuses
it as --providers-json)."""

from __future__ import annotations

import ast
import contextlib
import copy
import email.message
import io
import json
import os
import random
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
import madeonsol as mo  # noqa: E402
from test_assess import CAPE_LAUNCH, _map, _run, cape_holdings, case_negative_space_inu, run_assess  # noqa: E402
from test_solscanner_scan import CAPE, SPACE  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
DUMMY_KEY = "msk_dummy-madeonsol-key-7c1d9e4b"
TOKEN_PATH = f"/api/v1/token/{CAPE}"
BUNDLE_PATH = f"/api/v1/tokens/{CAPE}/bundle"
DEPLOYER = "DhetAKJMgunfD7zYxBQnWsWYdFF8zpdTCYaKWkJSMK2Q"
LATE = "clear large cluster seen by MadeOnSol, not yet in the engine verdicts"
FLAG_WORDS = re.compile(r"DANGER FLAG|CAUTION|NO FLAG RAISED")
REASSURING = re.compile(r"\b(clean|safe|low)\b", re.IGNORECASE)
PRO = "not read (needs MadeOnSol PRO; owner decision)"


def token_fixture():
    return json.loads((FIX / "cape_madeonsol_token_live_20261019.json").read_text())


def bundle_fixture():
    return json.loads((FIX / "cape_madeonsol_bundle_live_20261019.json").read_text())


def body_of(payload) -> bytes:
    return json.dumps(payload).encode()


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200, chunk: int | None = None):
        self._buf, self.status, self._chunk = io.BytesIO(body), status, chunk

    def read(self, n=-1):
        return self._buf.read(n if self._chunk is None else min(n, self._chunk))

    def close(self):
        pass


def http_error(code, path=TOKEN_PATH, headers=None, body=b""):
    msg = email.message.Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError(f"https://{mo.HOST}{path}", code, "error", msg, io.BytesIO(body))


class Router:
    """Answers by request path (the two calls run in two threads); records every request with its timeout."""

    def __init__(self, token=None, bundle=None, barrier=None):
        self.answers = {TOKEN_PATH: list(token if token is not None else [FakeResponse(body_of(token_fixture()))]),
                        BUNDLE_PATH: list(bundle if bundle is not None else [FakeResponse(body_of(bundle_fixture()))])}
        self.requests, self.lock, self.barrier = [], threading.Lock(), barrier

    def open(self, request, timeout=None):
        path = urllib.parse.urlparse(request.full_url).path
        with self.lock:
            self.requests.append((request, timeout))
            answer = self.answers[path].pop(0)
        if self.barrier is not None:
            self.barrier.wait()
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return answer()
        return answer

    def count(self, path):
        return sum(1 for r, _ in self.requests if urllib.parse.urlparse(r.full_url).path == path)


def collect(router, key=DUMMY_KEY, sleeps=None):
    sleeps = [] if sleeps is None else sleeps
    return mo.collect_madeonsol(CAPE, key, opener=router, now=lambda: 1_792_388_755.0, monotonic=time.monotonic, sleep=sleeps.append)


def run_main(argv, router, env=None):
    out, err = io.StringIO(), io.StringIO()
    env = {"MADEONSOL_API_KEY": DUMMY_KEY} if env is None else env
    base = {k: v for k, v in os.environ.items() if k not in ("MADEONSOL_API_KEY", "HOLDER_FORENSICS_ENV")}
    with mock.patch.dict(os.environ, base | env, clear=True), mock.patch.object(mo, "default_opener", return_value=router), \
         mock.patch.object(mo.time, "sleep"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = mo.main(argv)
    return code, out.getvalue(), err.getvalue()


def write_result(folder: Path, mutate=None) -> dict:
    """A madeonsol.json in `folder` from the live fixtures, optionally with changed answers."""
    token, bundle = token_fixture(), bundle_fixture()
    if mutate:
        mutate(token, bundle)
    res = collect(Router([FakeResponse(body_of(token))], [FakeResponse(body_of(bundle))]))
    folder.mkdir(parents=True, exist_ok=True)
    (folder / mo.OUT_FILE).write_text(json.dumps(res, indent=1))
    return res


def held(value):
    return lambda t, b: b["bundle"].update(held_pct_of_supply=value)


class RequestConstructionTests(unittest.TestCase):
    def test_two_documented_gets_with_the_bearer_header_only(self):
        router = Router()
        res = collect(router)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(len(router.requests), 2)
        seen = set()
        for request, timeout in router.requests:
            url = urllib.parse.urlparse(request.full_url)
            self.assertEqual((url.scheme, url.hostname, url.port), ("https", "madeonsol.com", None))
            seen.add((url.path, url.query))
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(dict(request.header_items()), {"Authorization": f"Bearer {DUMMY_KEY}", "Accept": "application/json", "User-agent": mo.USER_AGENT})
            self.assertEqual(timeout, mo.TIMEOUT_S)
        self.assertEqual(seen, {(TOKEN_PATH, "include=deployer,buyer_quality"), (BUNDLE_PATH, "")})
        self.assertEqual(res["request"], {"method": "GET", "host": "madeonsol.com", "paths": ["/api/v1/token/<MINT>?include=deployer,buyer_quality", "/api/v1/tokens/<MINT>/bundle"],
                                          "auth_header_names": ["Authorization"], "auth_scheme": "Bearer", "tier": "BASIC (free)", "requests_per_scan": 2, "max_requests": 4,
                                          "free_calls_per_day": 200, "requests_sent": 2,
                                          "not_called": {"cap_table": "/api/v1/tokens/<MINT>/cap-table", "fee_shares": "/api/v1/tokens/<MINT>/fee-shares"}})

    def test_both_calls_are_sent_at_the_same_time(self):
        res = collect(Router(barrier=threading.Barrier(2, timeout=2.0)))
        self.assertEqual((res["token"]["status"], res["bundle"]["status"]), ("ok", "ok"), "a one-by-one sender would break the two-party barrier")

    def test_default_opener_ignores_env_proxies_and_refuses_redirects(self):
        with mock.patch.dict(os.environ, {"https_proxy": "http://proxy.invalid:3128", "HTTPS_PROXY": "http://proxy.invalid:3128"}):
            opener = mo.default_opener()
        self.assertFalse(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in opener.handlers))
        self.assertTrue(any(isinstance(h, mo.NoRedirect) for h in opener.handlers))
        self.assertFalse(any(type(h) is urllib.request.HTTPRedirectHandler for h in opener.handlers))

    def test_only_the_allowlisted_https_host_paths_and_query(self):
        q = "?include=deployer,buyer_quality"
        for url in (f"http://madeonsol.com{TOKEN_PATH}{q}", f"https://madeonsol.com.evil.example{TOKEN_PATH}{q}", f"https://madeonsol.com:8443{TOKEN_PATH}{q}",
                    f"https://user:pw@madeonsol.com{TOKEN_PATH}{q}", f"https://madeonsol.com{TOKEN_PATH}", f"https://madeonsol.com{TOKEN_PATH}?include=deployer",
                    f"https://madeonsol.com{BUNDLE_PATH}?include_balances=true", f"https://madeonsol.com/api/v1/tokens/{CAPE}/cap-table",
                    f"https://madeonsol.com/api/v1/tokens/{CAPE}/fee-shares", f"https://madeonsol.com/api/v1/tokens/{CAPE}/holders",
                    f"https://madeonsol.com/api/v1/rhc/tokens/{CAPE}/bundle", f"https://madeonsol.com/api/v1/token/{SPACE}{q}", "https://madeonsol.com/api/v1/webhooks",
                    f"https://madeonsol.com/api/x402/tokens/{CAPE}/bundle"):
            with self.subTest(url), self.assertRaises(mo.Failure):
                mo.check_url(url, CAPE)
        router = Router()
        with self.assertRaises(mo.Failure):
            mo.send_once(urllib.request.Request("https://example.com" + TOKEN_PATH), router, CAPE, monotonic=time.monotonic)
        self.assertEqual(router.requests, [], "a refused URL is never opened")

    def test_never_a_pro_only_rhc_or_non_get_call(self):
        text = (SCRIPTS / "madeonsol.py").read_text()
        code = ast.parse(text)
        strings = [n.value for n in ast.walk(code) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        self.assertFalse([s for s in strings if "/rhc" in s or "x402" in s or "webhook" in s.lower() or "subscription" in s.lower()])
        methods = {kw.value.value for n in ast.walk(code) if isinstance(n, ast.Call) for kw in n.keywords
                   if kw.arg == "method" and isinstance(kw.value, ast.Constant)}
        self.assertEqual(methods, {"GET"})
        self.assertNotIn("data=", text.replace("data_observed", "").replace("data_status", ""))

    def test_redirect_size_and_error_bounds(self):
        cases = [(http_error(302), "redirect_disallowed", 302), (FakeResponse(b"", status=301), "redirect_disallowed", 301), (http_error(401), "authentication_failed", 401),
                 (http_error(403), "access_denied", 403), (http_error(404), "not_found", 404), (http_error(400), "bad_request", 400), (http_error(500), "server_error", 500),
                 (http_error(503, headers={"Retry-After": "1"}), "service_unavailable", 503), (http_error(418), "http_error", 418), (socket.timeout(), "timeout", None),
                 (urllib.error.URLError(OSError("refused")), "network_error", None), (RuntimeError(f"boom {DUMMY_KEY}"), "network_error", None),
                 (FakeResponse(b"<html>"), "invalid_json", 200)]
        for answer, reason, status in cases:
            with self.subTest(reason=reason, answer=type(answer).__name__):
                router = Router(token=[answer])
                res = collect(router)
                self.assertEqual((res["token"]["status"], res["token"]["reason"], res["token"]["http_status"], router.count(TOKEN_PATH)), ("unavailable", reason, status, 1))
                self.assertEqual(res["status"], "ok", "the bundle part was still read")
                self.assertNotIn(DUMMY_KEY, json.dumps(res))
        with mock.patch.object(mo, "MAX_BYTES", 1000):
            res = collect(Router(token=[FakeResponse(b"x" * 1001, chunk=100)]))
        self.assertEqual(res["token"]["reason"], "response_too_large")


class ErrorBodyTests(unittest.TestCase):
    """A 403 or 429 body is read (bounded) only to pick one fixed code; nothing from it reaches an output."""

    def test_fixed_codes_from_the_documented_error_bodies(self):
        cases = [(403, {"error": "tier_required", "message": "PRO needed", "your_tier": "BASIC", "required_tier": "PRO"}, "tier_required"),
                 (403, {"error": "demo_key_endpoint_not_allowed", "message": "demo"}, "demo_key_not_allowed"),
                 (403, {"error": "origin_not_allowed"}, "access_denied"), (403, {"error": "tier_required_but_renamed"}, "access_denied"),
                 (429, {"error": "rate_limit_exceeded", "error_kind": "daily", "tier": "BASIC", "limit": 200}, "daily_quota_exhausted"),
                 (429, {"error": "rate_limit_exceeded", "error_kind": "burst"}, "rate_limited")]
        for code, body, reason in cases:
            with self.subTest(reason=reason, body=body):
                res = collect(Router(token=[http_error(code, body=body_of(body))]))
                self.assertEqual((res["token"]["status"], res["token"]["reason"], res["token"]["http_status"]), ("unavailable", reason, code))
                self.assertNotIn("PRO needed", json.dumps(res))
        for raw in (b"", b"<html>", b"[1,2]", b"\xff\xfe"):
            with self.subTest(raw=raw):
                self.assertEqual(collect(Router(token=[http_error(403, body=raw)]))["token"]["reason"], "access_denied")

    def test_the_error_body_is_read_only_up_to_the_bound(self):
        reads = []

        class Body(io.BytesIO):
            def read(self, n=-1):
                reads.append(n)
                return super().read(n)

        msg = email.message.Message()
        error = urllib.error.HTTPError(f"https://{mo.HOST}{TOKEN_PATH}", 403, "error", msg, Body(b'{"error": "tier_required"}' + b" " * 100_000))
        res = collect(Router(token=[error]))
        self.assertEqual(res["token"]["reason"], "tier_required")
        self.assertEqual(reads, [mo.ERROR_BODY_MAX])

    def test_other_error_bodies_are_never_read(self):
        reads = []

        class Body(io.BytesIO):
            def read(self, n=-1):
                reads.append(n)
                return super().read(n)

        for code in (401, 404, 500, 503):
            error = urllib.error.HTTPError(f"https://{mo.HOST}{TOKEN_PATH}", code, "error", email.message.Message(), Body(b'{"error": "tier_required"}'))
            collect(Router(token=[error]))
        self.assertEqual(reads, [])


class RateLimitTests(unittest.TestCase):
    def test_one_retry_after_a_short_429(self):
        for headers, wait in (({"Retry-After": "1"}, 1.0), ({"Retry-After": "0"}, 0.5), ({"Retry-After": "5"}, 5.0)):
            with self.subTest(headers=headers):
                sleeps = []
                router = Router(token=[http_error(429, headers=headers), FakeResponse(body_of(token_fixture()))])
                res = collect(router, sleeps=sleeps)
                self.assertEqual((res["token"]["status"], res["token"]["attempts"], router.count(TOKEN_PATH), sleeps), ("ok", 2, 2, [wait]))
                self.assertEqual(res["request"]["requests_sent"], 3)

    def test_never_more_than_one_retry_and_at_most_four_calls(self):
        sleeps = []
        short = {"Retry-After": "1"}
        router = Router(token=[http_error(429, headers=short), http_error(429, headers=short), FakeResponse(b"{}")],
                        bundle=[http_error(429, BUNDLE_PATH, headers=short), http_error(429, BUNDLE_PATH, headers=short), FakeResponse(b"{}")])
        res = collect(router, sleeps=sleeps)
        self.assertEqual((res["status"], res["token"]["reason"], res["bundle"]["reason"]), ("unavailable", "rate_limited", "rate_limited"))
        self.assertEqual((len(router.requests), res["request"]["requests_sent"]), (4, 4))
        self.assertEqual(len(sleeps), 2)

    def test_no_retry_without_a_short_retry_after_on_a_daily_quota_or_another_error(self):
        daily = body_of({"error": "rate_limit_exceeded", "error_kind": "daily"})
        for answer in (http_error(429), http_error(429, headers={"Retry-After": "60"}), http_error(429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}),
                       http_error(429, headers={"Retry-After": "1"}, body=daily), http_error(401), http_error(503, headers={"Retry-After": "1"})):
            with self.subTest(code=answer.code, retry_after=answer.headers.get("Retry-After")):
                sleeps = []
                router = Router(token=[answer, FakeResponse(body_of(token_fixture()))])
                res = collect(router, sleeps=sleeps)
                self.assertEqual((res["token"]["attempts"], router.count(TOKEN_PATH), sleeps), (1, 1, []))


class DripResponse:
    """Drip-feeds one byte every 10 ms inside one read. Gives up after 3 s so a broken bound cannot hang the suite."""

    status = 200

    def __init__(self, stop):
        self.stop, self.start = stop, time.monotonic()

    def read(self, n=-1):
        got = b""
        while not self.stop.is_set() and time.monotonic() - self.start < 3.0 and len(got) < n:
            time.sleep(0.01)
            got += b"x"
        return got

    def close(self):
        pass


class HardDeadlineTests(unittest.TestCase):
    DEADLINE = 0.5
    MARGIN = 0.5

    def setUp(self):
        self.stop = threading.Event()
        patcher = mock.patch.object(mo, "TIMEOUT_S", self.DEADLINE)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.stop.set)

    def test_drip_feeds_on_both_calls_end_at_one_deadline(self):
        router = Router(token=[lambda: DripResponse(self.stop)], bundle=[lambda: DripResponse(self.stop)])
        started = time.monotonic()
        res = collect(router)
        self.assertEqual((res["status"], res["token"]["reason"], res["bundle"]["reason"]), ("unavailable", "timeout", "timeout"))
        self.assertLess(time.monotonic() - started, self.DEADLINE + self.MARGIN)

    def test_a_stalled_open_ends_at_the_deadline(self):
        def stall():
            self.stop.wait(3.0)
            raise OSError("released")

        started = time.monotonic()
        res = collect(Router(token=[stall]))
        self.assertEqual((res["token"]["reason"], res["bundle"]["status"]), ("timeout", "ok"))
        self.assertLess(time.monotonic() - started, self.DEADLINE + self.MARGIN)


class StatusAndGuardTests(unittest.TestCase):
    def parsed(self, mutate_token=None, mutate_bundle=None):
        t, b = token_fixture(), bundle_fixture()
        if mutate_token:
            mutate_token(t)
        if mutate_bundle:
            mutate_bundle(b)
        return collect(Router([FakeResponse(body_of(t))], [FakeResponse(body_of(b))]))

    def test_live_cape_answers(self):
        res = self.parsed()
        self.assertEqual((res["status"], res["token"]["status"], res["bundle"]["status"], res["token"]["identity"], res["bundle"]["identity"]),
                         ("ok", "ok", "ok", "confirmed", "confirmed"))
        dep = res["token"]["deployer"]
        self.assertEqual((dep["status"], dep["source"], dep["wallet"], dep["tier"], dep["is_tracked"], dep["tokens_deployed"], dep["bonded"], dep["bond_rate_pct"],
                          dep["recent_bond_rate_pct"], dep["best_token_peak_mc_usd"]),
                         ("ok", "deployer_profile", DEPLOYER, "unranked", False, 1, 1, 100.0, 100.0, 1213791.76))
        b = res["bundle"]
        self.assertEqual((b["wallet_count"], b["bundle_kind"], b["held_pct_of_supply"], b["held_ratio_pct"], b["fully_exited"], b["holdings_basis"]),
                         (20, "same_slot", 80.68, 94.57, False, "swap_only"))
        kol = res["token"]["kol_activity"]
        self.assertEqual((kol["buying_kols"], kol["selling_kols"], kol["net_flow_sol"], kol["signal"], kol["window_hours"]), (4, 4, 9.84878, "accumulating", 168.0))
        self.assertEqual([x["name"] for x in kol["top_buyers"]], [None] * 4, "names are blank on the free tier")
        self.assertEqual(res["token"]["early_buyers"], {"cohort": 20, "still_holding": 4, "sold": 16, "launch_cohort_sol": 91.288433, "launch_cohort_size": 20})
        bq = res["token"]["buyer_quality"]
        self.assertEqual((bq["score"], bq["signal"], bq["confidence"], bq["bundle_buyer_count"], bq["dump_cluster_count"], bq["recycled_early_buyer_count"]),
                         (0.0, "negative", "insufficient_data", 20, 1, 15))
        self.assertEqual(res["pro_only"], {"cap_table": {"status": "not_called", "reason": mo.PRO_NOTE}, "fee_shares": {"status": "not_called", "reason": mo.PRO_NOTE}})
        self.assertEqual(res["numbers"]["cap_table"], {"value": None, "not_read": mo.PRO_NOTE})
        self.assertEqual(res["numbers"]["fee_share_recipients"], {"value": None, "not_read": mo.PRO_NOTE})
        self.assertEqual(res["numbers"]["dev_holding_pct"], {"value": None, "not_read": "not in the free MadeOnSol answer"})
        self.assertEqual(mo.status_line(res), "ok (token: ok; bundle: ok; cap table and fee shares not called (needs MadeOnSol PRO; owner decision); 2 MadeOnSol calls (free tier: 200 a day))")

    def test_token_part_guards(self):
        cases = [
            (lambda t: t.pop("token"), ("unavailable", "token_missing")),
            (lambda t: t.update(token=[1]), ("unavailable", "token_missing")),
            (lambda t: t["token"].update(mint=SPACE), ("unavailable", "identity_mismatch")),
            (lambda t: [t["token"].pop(k) for k in ("deployer", "kol_activity", "early_buyer_exit", "launch_cohort_sol", "launch_cohort_size")] + [t.pop("deployer_profile"), t.pop("buyer_quality")],
             ("unavailable", "token_fields_missing")),
            (lambda t: (t.update(token={"mint": CAPE, "Deployer": {}, "KOL": {}}), t.pop("deployer_profile"), t.pop("buyer_quality")), ("unavailable", "token_fields_missing")),
            ([1, 2], ("unavailable", "invalid_shape")),
        ]
        for change, expected in cases:
            with self.subTest(expected=expected):
                if callable(change):
                    res = self.parsed(change)
                else:
                    res = collect(Router([FakeResponse(body_of(change))]))
                self.assertEqual((res["token"]["status"], res["token"]["reason"]), expected)
                self.assertEqual(res["status"], "ok", "the bundle part was still read")
                n = res["numbers"]
                self.assertIsNone(n["dev_tier"]["value"])
                self.assertTrue(n["dev_tier"]["not_read"].startswith("token snapshot unavailable"))

    def test_deployer_block_guards_and_fallback(self):
        def mismatch(t):
            t["deployer_profile"]["deployer"]["wallet_address"] = CAPE

        def renamed(t):
            for k in ("tier", "total_tokens_deployed", "total_bonded", "bonding_rate", "recent_bond_rate"):
                t["deployer_profile"]["deployer"]["x_" + k] = t["deployer_profile"]["deployer"].pop(k)

        def no_profile(t):
            t.pop("deployer_profile")

        def nothing(t):
            t.pop("deployer_profile")
            t["token"].pop("deployer")

        def include_failed(t):
            t.pop("deployer_profile")
            t["token"].pop("deployer")
            t["include_errors"] = {"deployer": "timeout"}

        self.assertEqual((lambda d: (d["status"], d["reason"]))(self.parsed(mismatch)["token"]["deployer"]), ("unavailable", "deployer_mismatch"))
        self.assertEqual((lambda d: (d["status"], d["reason"]))(self.parsed(renamed)["token"]["deployer"]), ("unavailable", "deployer_fields_missing"))
        fallback = self.parsed(no_profile)["token"]["deployer"]
        self.assertEqual((fallback["status"], fallback["source"], fallback["wallet"], fallback["tokens_deployed"], fallback["bonded"], fallback["tier"]),
                         ("ok", "token.deployer", DEPLOYER, 1, 1, "unranked"))
        self.assertEqual((lambda d: (d["status"], d["reason"]))(self.parsed(nothing)["token"]["deployer"]), ("not_in_answer", "deployer_missing"))
        res = self.parsed(include_failed)
        self.assertEqual((res["token"]["deployer"]["status"], res["token"]["deployer"]["reason"]), ("unavailable", "include_failed"))
        self.assertEqual(res["numbers"]["dev_tier"]["not_read"], "deployer unavailable: include_failed")
        self.assertEqual(res["token"]["status"], "ok", "the other blocks were still read")

    def test_a_bond_rate_outside_0_to_1_is_not_read(self):
        res = self.parsed(lambda t: t["deployer_profile"]["deployer"].update(bonding_rate=40, recent_bond_rate=0.25))
        n = res["numbers"]
        self.assertEqual(n["dev_bond_rate_pct"], {"value": None, "not_read": "not a fraction of 1 as documented"})
        self.assertEqual(n["dev_recent_bond_rate_pct"], {"value": 25.0, "not_read": None})

    def test_other_block_guards(self):
        res = self.parsed(lambda t: t["token"]["kol_activity"].update(status="unavailable"))
        self.assertEqual((res["token"]["kol_activity"]["status"], res["token"]["kol_activity"]["reason"]), ("unavailable", "kol_activity_not_ok"))
        res = self.parsed(lambda t: t["token"].update(kol_activity={"status": "ok", "kols": 4}))
        self.assertEqual(res["token"]["kol_activity"]["reason"], "kol_fields_missing")
        self.assertEqual(res["numbers"]["kol_buying"]["not_read"], "kol activity unavailable: kol_fields_missing")
        res = self.parsed(lambda t: t.update(buyer_quality={"mint": CAPE, "points": 3}))
        self.assertEqual(res["token"]["buyer_quality"]["reason"], "buyer_quality_fields_missing")
        res = self.parsed(lambda t: (t.pop("buyer_quality"), t.update(include_errors=["buyer_quality"])))
        self.assertEqual(res["token"]["buyer_quality"]["reason"], "include_failed")

    def test_bundle_part_guards(self):
        cases = [
            (lambda b: b.pop("bundle"), ("unavailable", "bundle_missing")),
            (lambda b: b["bundle"].update(held_pct_of_supply=80.68), ("unavailable", "bundle_unit_unexpected")),
            (lambda b: b["bundle"].update(held_pct_of_supply=-0.1), ("unavailable", "bundle_unit_unexpected")),
            (lambda b: b["bundle"].pop("held_pct_of_supply"), ("unavailable", "bundle_share_field_missing")),
            (lambda b: b["bundle"].update(held_pct_of_supply="0.8"), ("unavailable", "bundle_share_field_missing")),
            (lambda b: b.update(mint=SPACE), ("unavailable", "identity_mismatch")),
            (lambda b: b["coverage"].update(data_observed=False), ("empty", "not_captured")),
        ]
        for change, expected in cases:
            with self.subTest(expected=expected):
                res = self.parsed(mutate_bundle=change)
                self.assertEqual((res["bundle"]["status"], res["bundle"]["reason"]), expected)
                n = res["numbers"]["bundle_held_pct"]
                self.assertEqual((n["value"], n["not_read"]), (None, f"bundle summary {expected[0]}: {expected[1]}"), "never 0 when not read")

    def test_no_bundle_cohort_is_ok_but_the_share_reads_not_read(self):
        res = self.parsed(mutate_bundle=lambda b: b.update(bundle={"wallet_count": 0, "bundle_kind": "none", "held_pct_of_supply": None}))
        self.assertEqual(res["bundle"]["status"], "ok")
        self.assertEqual(res["numbers"]["bundle_held_pct"], {"value": None, "not_read": "no bundle cohort found by MadeOnSol"})

    def test_overall_status(self):
        res = collect(Router([http_error(401)], [http_error(401, BUNDLE_PATH)]))
        self.assertEqual((res["status"], res["reason"]), ("unavailable", "token: authentication_failed; bundle: authentication_failed"))
        res = collect(Router([http_error(401)], [FakeResponse(body_of(dict(bundle_fixture(), coverage={"data_observed": False})))]))
        self.assertEqual((res["status"], res["reason"]), ("empty", "token: authentication_failed; bundle: not_captured"))
        self.assertTrue(mo.status_line(res).startswith("empty (MadeOnSol has no data for this token: unknown, not a reassurance"))

    def test_a_kol_status_is_one_fixed_code_never_provider_text(self):
        """C3: any KOL status other than ok becomes the fixed code kol_activity_not_ok; no provider text reaches the reason,
        not even an upper-cased echo of a lower-case key (the old code lowered the status after the key check)."""
        secret = "msk_lowercase-secret-key-0d1e2f3a"
        for status in ("unavailable", "DEGRADED", secret.upper(), secret, f"x {secret.upper()} y", ["ok"], 5):
            with self.subTest(status=str(status)[:12]):
                t = token_fixture()
                t["token"]["kol_activity"]["status"] = status
                res = collect(Router([FakeResponse(body_of(t))]), key=secret)
                self.assertEqual((res["token"]["kol_activity"]["status"], res["token"]["kol_activity"]["reason"]), ("unavailable", "kol_activity_not_ok"))
                self.assertFalse(mo.shares_key_piece(json.dumps(res).lower(), secret), "no piece of the key, in any case")
        for status in ("ok", "OK", " Ok "):
            t = token_fixture()
            t["token"]["kol_activity"]["status"] = status
            self.assertEqual(collect(Router([FakeResponse(body_of(t))]))["token"]["kol_activity"]["status"], "ok")

    def test_an_unforeseen_answer_is_a_fixed_code_with_the_calls_counted(self):
        with mock.patch.object(mo, "parse_token", side_effect=RuntimeError(f"boom {DUMMY_KEY}")):
            res = collect(Router())
        self.assertEqual((res["token"]["status"], res["token"]["reason"], res["token"]["attempts"], res["bundle"]["status"], res["request"]["requests_sent"]),
                         ("unavailable", "parse_error", 1, "ok", 2))
        self.assertNotIn(DUMMY_KEY, json.dumps(res))
        rng = random.Random(20261019)
        junk = [None, True, 0, -1.5, "x", [], [1, "a"], {}, {"a": [1]}, ["ok"], {"status": ["ok"]}, float("inf")]
        for i in range(300):
            t, b = token_fixture(), bundle_fixture()
            nodes = [t, b, *[v for v in (*t.values(), *b.values(), *t["token"].values()) if isinstance(v, dict)]]  # collected before any damage
            for _ in range(rng.randint(1, 6)):
                node = rng.choice(nodes)
                node[rng.choice(list(node) or ["x"])] = copy.deepcopy(rng.choice(junk))
            res = collect(Router([FakeResponse(json.dumps(t, allow_nan=True).encode())], [FakeResponse(json.dumps(b, allow_nan=True).encode())]))
            self.assertIn(res["status"], ("ok", "empty", "unavailable"))
            self.assertEqual(res["request"]["requests_sent"], 2)
            self.assertTrue(isinstance(res["numbers"], dict) and all("value" in v for v in res["numbers"].values()))

    def test_values_are_validated(self):
        def junk(t):
            d = t["deployer_profile"]["deployer"]
            d.update(total_tokens_deployed="5", total_bonded=True, best_token_peak_mc=float("nan"), tier="Elite\n# heading <b>x</b>")
            t["token"]["kol_activity"].update(buying_kols=-1, net_flow_sol="9", signal="SHOUT\nnow")
            t["buyer_quality"].update(score=101, signal="great")

        res = self.parsed(junk)
        dep, kol, bq = res["token"]["deployer"], res["token"]["kol_activity"], res["token"]["buyer_quality"]
        self.assertEqual((dep["tokens_deployed"], dep["bonded"], dep["best_token_peak_mc_usd"], dep["tier"]), (None, None, None, "Elite heading x"))  # HS-LABELS-T1 hardening (a): inline HTML tags are dropped, not left as letters
        self.assertEqual((kol["buying_kols"], kol["net_flow_sol"], kol["signal"]), (None, None, "SHOUTnow"))
        self.assertEqual((bq["status"], bq["reason"]), ("unavailable", "buyer_quality_fields_missing"), "a score out of 0-100 and an unknown signal are not read: loud")


class KeyHandlingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_the_key_never_reaches_an_output(self):
        secret = "msk_SeCrEt-MOS-0d1e2f3a4b5c6d7e8f9a"

        def echo_token():
            t = token_fixture()
            t["deployer_profile"]["deployer"]["tier"] = secret
            t["token"]["deployer"]["history_status"] = f"x {secret[:12]}"
            t["token"]["kol_activity"]["top_buyers"] = [{"name": secret, "sol_amount": 1.0}, {"name": "Real Kol", "sol_amount": 2.0}]
            t["token"]["symbol"] = secret[4:20]
            return FakeResponse(body_of(t))

        def echo_bundle():
            b = bundle_fixture()
            b["bundle"]["holdings_basis"] = secret
            b["bundle"]["bundle_kind"] = secret
            return FakeResponse(body_of(b))

        scripts = {
            "ok": ([FakeResponse(body_of(token_fixture()))], None),
            "tier": ([http_error(403, body=body_of({"error": "tier_required", "message": f"key {secret} is BASIC"}))], [http_error(401, BUNDLE_PATH, body=secret.encode())]),
            "boom": ([RuntimeError(f"request with Authorization Bearer {secret} failed")], [RuntimeError(secret)]),
            "echo": ([echo_token()], [echo_bundle()]),
        }
        for name, (token, bundle) in scripts.items():
            with self.subTest(name):
                out_dir = self.tmp / name
                code, out, err = run_main([CAPE, "--out", str(out_dir)], Router(token, bundle), env={"MADEONSOL_API_KEY": secret})
                self.assertEqual(code, 0)
                for text in [out, err] + [p.read_text() for p in out_dir.iterdir()]:
                    self.assertFalse(mo.shares_key_piece(text, secret), f"{name}: an 8-character piece of the key reached an output")
                present_out = io.StringIO()
                with contextlib.redirect_stdout(present_out):
                    mo.main(["--present", str(out_dir)])
                self.assertFalse(mo.shares_key_piece(present_out.getvalue(), secret))
        saved = json.loads((self.tmp / "echo" / mo.OUT_FILE).read_text())
        self.assertEqual([x["name"] for x in saved["token"]["kol_activity"]["top_buyers"]], [None, "Real Kol"])

    def test_single_variable_loader(self):
        env = self.tmp / ".env"
        env.write_text("# comment\nOTHER_VALUE=abc123456789\nMADEONSOL_API_KEY_OLD=zzzzzzzzzzzz\nexport MADEONSOL_API_KEY='msk_from-file-0123456789'  \n"
                       "MADEONSOL_API_KEY=second-line-ignored\nFOMOAPI_KEY=not-this-one-0123\n")
        base = {k: v for k, v in os.environ.items() if k != "MADEONSOL_API_KEY"}
        with mock.patch.dict(os.environ, base, clear=True):
            self.assertEqual(mo.load_key(env), ("msk_from-file-0123456789", None))
            self.assertEqual(mo.load_key(None), (None, "missing_key"))
            env.write_text("MADEONSOL_API_KEY=has a space inside\n")
            self.assertEqual(mo.load_key(env), (None, "key_format"))
            env.write_text("MADEONSOL_API_KEY=short\n")
            self.assertEqual(mo.load_key(env), (None, "key_format"))
            self.assertEqual(mo.load_key(self.tmp / "missing.env"), (None, "env_file_unreadable"))
        with mock.patch.dict(os.environ, base | {"MADEONSOL_API_KEY": "msk_from-environment-123"}, clear=True):
            self.assertEqual(mo.load_key(env), ("msk_from-environment-123", None), "the environment wins over the file")

    def test_env_file_lookup_order_and_no_lookup_when_the_environment_has_the_key(self):
        explicit, setting = self.tmp / "a.env", self.tmp / "b.env"
        explicit.write_text("X=1\n")
        setting.write_text("X=1\n")
        with mock.patch.dict(os.environ, {"HOLDER_FORENSICS_ENV": str(setting)}):
            self.assertEqual(mo.find_env_file(str(explicit)), explicit)
            self.assertEqual(mo.find_env_file(None), setting)
        with mock.patch.object(mo, "find_env_file", side_effect=AssertionError("must not look for a .env")):
            code, out, _ = run_main([CAPE, "--out", str(self.tmp / "run")], Router())
        self.assertEqual(code, 0, out)

    def test_missing_key_sends_nothing(self):
        router = Router()
        code, out, _ = run_main([CAPE, "--out", str(self.tmp / "run"), "--env-file", str(self.tmp / "none.env")], router, env={})
        self.assertEqual((code, router.requests), (0, []))
        self.assertEqual(out.strip(), "unavailable (missing_key; no MadeOnSol call sent)")
        saved = json.loads((self.tmp / "run" / mo.OUT_FILE).read_text())
        self.assertEqual(saved["numbers"]["dev_tier"]["not_read"], "token snapshot not_sent")


SYMBOL_KEY = "msk_Ab3/xY9+Qz7=Lm4/Np8+Rt6=Uv2/Wk5"   # a key with characters a label cannot hold
B58_KEY = "HfpLdX35Kc6b7zDNWbe5x1xWLekKUXPYZbmz71vM"  # an address-shaped (base58) key


class KeyEchoHardeningTests(unittest.TestCase):
    """Provider text is dropped when its raw form or its label echoes the key (or the key without the characters a label
    cannot hold), and addresses are dropped on any shared 8-character run, not only on equality."""

    def test_a_key_with_slash_plus_equals_echoed_in_a_label_is_dropped(self):
        raw = f"Tier {SYMBOL_KEY[:16]} x"
        self.assertFalse(mo.shares_key_piece(mo.LABEL_RE.sub("", raw)[:32].strip(), SYMBOL_KEY))
        self.assertIsNone(mo.safe_label(raw, SYMBOL_KEY))
        pre_stripped = "Tier " + mo.LABEL_RE.sub("", SYMBOL_KEY)[:14]
        self.assertIsNone(mo.safe_label(pre_stripped, SYMBOL_KEY))
        self.assertEqual(mo.safe_label("unranked", SYMBOL_KEY), "unranked")

    def test_an_echo_past_the_label_cut_is_caught_on_the_raw_text(self):
        raw = "Deployer history status is xxxx " + DUMMY_KEY
        self.assertEqual(len("Deployer history status is xxxx "), 32)
        self.assertFalse(mo.echoes_key(mo.LABEL_RE.sub("", raw)[:32], DUMMY_KEY))
        self.assertIsNone(mo.safe_label(raw, DUMMY_KEY))

    def test_a_key_interleaved_with_markup_is_caught_on_the_label(self):
        raw = DUMMY_KEY[:5] + "<" + DUMMY_KEY[5:10] + ">" + DUMMY_KEY[10:15] + "|" + DUMMY_KEY[15:20]
        self.assertFalse(mo.echoes_key(raw, DUMMY_KEY))
        self.assertIsNone(mo.safe_label(raw, DUMMY_KEY))

    def test_address_fields_drop_a_prefixed_or_partial_key(self):
        prefixed = "22" + B58_KEY
        partial = CAPE[:20] + B58_KEY[10:20] + CAPE[30:]
        for wallet in (prefixed, partial):
            with self.subTest(wallet=wallet[:8]):
                self.assertTrue(mo.SOLANA_ADDRESS_RE.fullmatch(wallet))
                t = token_fixture()
                t["deployer_profile"]["deployer"]["wallet_address"] = wallet
                t["token"]["deployer"].update(wallet=wallet, address=wallet)
                res = collect(Router([FakeResponse(body_of(t))]), key=B58_KEY)
                self.assertIsNone(res["token"]["deployer"]["wallet"])
                self.assertFalse(mo.shares_key_piece(json.dumps(res), B58_KEY))
        self.assertEqual(mo._address(DEPLOYER, B58_KEY), DEPLOYER)

    def test_real_values_are_not_dropped(self):
        for key in (SYMBOL_KEY, B58_KEY, "msk_live_0f9e8d7c6b5a4f3e2d1c", DUMMY_KEY):
            with self.subTest(key=key[:6]):
                res = collect(Router(), key=key)
                self.assertEqual((res["token"]["deployer"]["wallet"], res["token"]["deployer"]["tier"], res["token"]["symbol"], res["bundle"]["holdings_basis"]),
                                 (DEPLOYER, "unranked", "CAPE", "swap_only"))


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_bad_input_exits_2_without_a_call(self):
        router = Router()
        for argv in (["not-a-mint", "--out", str(self.tmp)], [CAPE], ["--present", str(self.tmp / "missing")], [CAPE, "--present", str(self.tmp)]):
            with self.subTest(argv):
                code, _, err = run_main(argv, router)
                self.assertEqual(code, 2)
                self.assertTrue(err.startswith("error:"))
        self.assertEqual(router.requests, [])

    def test_present_reads_no_key_and_opens_no_connection(self):
        write_result(self.tmp)

        def refuse(*_a, **_k):
            raise AssertionError("network or key access in --present")

        out = io.StringIO()
        with mock.patch.object(mo, "load_key", side_effect=refuse), mock.patch.object(mo, "find_env_file", side_effect=refuse), \
             mock.patch.object(mo, "default_opener", side_effect=refuse), mock.patch.object(socket, "create_connection", refuse), \
             mock.patch.object(socket.socket, "connect", refuse), contextlib.redirect_stdout(out):
            code = mo.main(["--present", str(self.tmp)])
        self.assertEqual(code, 0)
        self.assertIn("MadeOnSol (collector madeonsol, free BASIC tier): read", out.getvalue())


class PresentTests(unittest.TestCase):
    """The synthesis's block: Dev / deployer, launch bundle, KOL positions, the PRO-only lines, and the late-source line."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def lines(self, mutate=None, name="run"):
        run = self.tmp / name
        write_result(run, mutate)
        return mo.present(run)

    def test_live_cape_block(self):
        lines = self.lines()
        text = "\n".join(lines)
        self.assertEqual(lines[0].split(";")[0], "MadeOnSol (collector madeonsol, free BASIC tier): read")
        self.assertIn("2 calls of the free tier's 200 a day", lines[0])
        for needle in ("  Dev / deployer (MadeOnSol's claims): DhetAK...MK2Q; tier unranked (not tracked by MadeOnSol); tokens deployed 1; bonded 1; bond rate 100%; "
                       "recent bond rate 100%; best token peak market cap $1,213,791; current dev holding not read (not in the free MadeOnSol answer)",
                       "  launch bundle (MadeOnSol's claim; its launch cohort: 20 wallets; first 20 buyers, 3 or more in one slot; same-slot can be coincidental): bought and not sold through swaps 80.68% of supply "
                       "(transfers out are not subtracted, so it can over-read; not a balance check; basis swap_only); not sold through swaps: 94.57% of what they bought; "
                       "all sold through swaps: no",
                       "  first 20 buyers (MadeOnSol's launch cohort): 20 buyers, 4 still hold, 16 sold; they spent 91.28 SOL at launch",
                       "  KOL positions (MadeOnSol's KOL roster, last 168 h): 4 KOLs bought for 52.4 SOL, 4 sold for 42.55 SOL, net +9.848 SOL; "
                       "MadeOnSol's signal accumulating; names are not on the free tier",
                       "  buyer quality (MadeOnSol's 0-100 score over the first 20 buyers, its claim): 0 (signal negative, data confidence insufficient_data); "
                       "bundle buyers 20, recycled early buyers 15, dump clusters 1",
                       f"  cap table: {PRO}", f"  creator-fee recipients: {PRO}", "  cannot see: its own bundle definition", "a low number is not an all-clear"):
            self.assertIn(needle, text)
        self.assertEqual(lines[-1], f"{LATE}: MadeOnSol claims its launch cohort (20 wallets; first 20 buyers, 3 or more in one slot; same-slot can be coincidental) bought and has not sold through swaps 80.68% of supply; "
                                    "transfers out are not subtracted, so it can over-read; not a balance check; MadeOnSol's own first 20 buyers: 4 still hold, 16 sold "
                                    "(bar: bundles 30%+ BUNDLE_ALARM_PCT)")
        self.assertIsNone(re.search(r"(?i)held now|holds? [^;]{0,60}% of supply now|hold [0-9.]+%", text), "C1: the swap-derived share is never worded as a holding")
        self.assertIsNone(FLAG_WORDS.search(text), "the presenter never writes a FLAG")
        self.assertIsNone(REASSURING.search(text.replace("a low number is not an all-clear", "")))

    def test_the_bundle_share_is_checked_against_the_bundles_bar_and_cut_toward_zero(self):
        self.assertEqual(hf.BUNDLE_ALARM_PCT, 30.0)
        under = self.lines(held(0.29999), "under")
        self.assertFalse(any(line.startswith(LATE) for line in under), "29.999% shows no line")
        self.assertIn("bought and not sold through swaps 29.99% of supply", "\n".join(under), "shown cut toward zero, never rounded up to the bar")
        self.assertTrue(any(line.startswith(LATE) and "bought and has not sold through swaps 30% of supply" in line for line in self.lines(held(0.30), "at")), "at the bar counts")
        self.assertFalse(any(line.startswith(LATE) for line in self.lines(held(0.0), "zero")))
        self.assertIn("bought and not sold through swaps 0% of supply", "\n".join(self.lines(held(0.0), "zero2")), "a read 0 is shown as read")

    def test_a_fraction_just_under_the_bar_is_cut_never_rounded_up(self):
        """N2: the fraction-to-percent step itself cuts toward zero (from the decimal value sent), so 0.29999999999 never
        becomes a 30 that reaches the bundles bar, and exact decimals stay exact."""
        cases = {0.29999999999: 29.999999999, 0.3: 30.0, 0.57: 57.0, 0.8068: 80.68, 0.15: 15.0, 0.07: 7.0, 1.0: 100.0, 0.0: 0.0, 1e-9: 1e-7, 0.9457: 94.57}
        for value, percent in cases.items():
            with self.subTest(value=value):
                self.assertEqual(mo._fraction_pct(value), (percent, False))
        lines = self.lines(held(0.29999999999), "just-under")
        self.assertFalse(any(line.startswith(LATE) for line in lines), "29.999999999% shows no line")
        self.assertIn("bought and not sold through swaps 29.99% of supply", "\n".join(lines))
        rate = self.lines(lambda t, b: t["deployer_profile"]["deployer"].update(bonding_rate=0.29999999999), "rate")
        self.assertIn("bond rate 29.99%", "\n".join(rate))

    def test_the_late_line_names_an_atomic_bundle_and_leaves_out_an_unread_first_20_count(self):
        def atomic(t, b):
            b["bundle"]["bundle_kind"] = "atomic_tx"
            t["token"].pop("early_buyer_exit")

        line = [ln for ln in self.lines(atomic, "atomic") if ln.startswith(LATE)][0]
        self.assertIn("MadeOnSol claims its launch cohort (20 wallets; first 20 buyers, one atomic transaction) bought and has not sold through swaps 80.68% of supply", line)
        self.assertNotIn("first 20 buyers:", line, "MadeOnSol's first-20 count is added only when the answer has it")

    def test_madeonsols_confidence_is_labelled_as_data_confidence(self):
        lines = self.lines(lambda t, b: t["buyer_quality"].update(confidence="low", signal="positive", score=72), "confidence")
        self.assertIn("72 (signal positive, data confidence weak)", "\n".join(lines), "MadeOnSol's data confidence, never a risk reading")  # HS-LABELS-T1 R3: low / medium / high print as weak / medium / strong

    def test_numbers_without_a_matching_bar_are_only_shown(self):
        def big(t, b):
            b["bundle"]["held_pct_of_supply"] = 0.01
            t["buyer_quality"]["breakdown"].update(bundle_buyer_count=20, dump_cluster_count=9)
            t["token"]["kol_activity"].update(buying_kols=50, net_flow_sol=-500.0)
            t["token"]["early_buyer_exit"].update(still_holding=20, sold=0)

        lines = self.lines(big, "big")
        self.assertFalse(any(line.startswith(LATE) for line in lines))
        self.assertIn("net -500 SOL", "\n".join(lines))

    def test_unread_numbers_are_not_read_never_zero(self):
        run = self.tmp / "partial"
        res = collect(Router([http_error(401)], [FakeResponse(body_of(bundle_fixture()))]))
        run.mkdir()
        (run / mo.OUT_FILE).write_text(json.dumps(res))
        text = "\n".join(mo.present(run))
        self.assertIn("  Dev / deployer (MadeOnSol's claims): not read (token snapshot unavailable: authentication_failed); current dev holding not read (not in the free MadeOnSol answer)", text)
        self.assertIn("  first 20 buyers (MadeOnSol's launch cohort): not read (token snapshot unavailable: authentication_failed)", text)
        self.assertIn("  KOL positions (MadeOnSol's KOL roster): not read (token snapshot unavailable: authentication_failed)", text)
        self.assertIn("bought and not sold through swaps 80.68% of supply", text, "the bundle call was read and is shown")
        self.assertNotIn("tokens deployed 0", text)
        self.assertIn(f"cap table: {PRO}", text)

    def test_a_failed_scan_still_names_the_pro_only_lines_and_never_a_late_line(self):
        run = self.tmp / "failed"
        run.mkdir()
        res = collect(Router([http_error(401)], [http_error(401, BUNDLE_PATH)]))
        (run / mo.OUT_FILE).write_text(json.dumps(res))
        lines = mo.present(run)
        self.assertEqual(lines[0].split(";")[0], "MadeOnSol (collector madeonsol, free BASIC tier): unavailable (token: authentication_failed")
        self.assertIn(f"  cap table: {PRO}", lines)
        self.assertFalse(any(line.startswith(LATE) for line in lines))

    def test_missing_or_foreign_file_is_not_read(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        self.assertEqual(mo.present(empty), ["MadeOnSol: not read (madeonsol.json missing)"])
        (empty / mo.OUT_FILE).write_text(json.dumps({"schema": "something-else", "status": "ok", "presentation_only": True, "numbers": {"bundle_held_pct": {"value": 99}}}))
        self.assertEqual(mo.present(empty), ["MadeOnSol: not read (madeonsol.json unreadable)"])
        (empty / mo.OUT_FILE).write_text(json.dumps({"schema": mo.SCHEMA, "status": "ok", "numbers": {"bundle_held_pct": {"value": 99}}}))
        self.assertEqual(mo.present(empty), ["MadeOnSol: not read (madeonsol.json unreadable)"], "a file without the presentation-only mark is not read")


class MalformedSavedFileTests(unittest.TestCase):
    """--present never crashes on a hand-edited or truncated madeonsol.json; anything unreadable is not read."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def present_with(self, change):
        """A saved file with a low bundle share (no late-source line of its own), then damaged by `change`."""
        run = self.tmp / f"run{len(list(self.tmp.iterdir()))}"
        res = write_result(run, held(0.01))
        change(res)
        (run / mo.OUT_FILE).write_text(json.dumps(res))
        return mo.present(run)

    def test_missing_or_malformed_numbers_block_reads_not_read(self):
        for change, needle in ((lambda r: r.pop("numbers"), "Dev / deployer (MadeOnSol's claims): not read (numbers block missing)"),
                               (lambda r: r.update(numbers=[1, 2]), "launch bundle (MadeOnSol's claim; first 20 buyers, 3 or more in one slot): not read (numbers block missing)"),
                               (lambda r: r.update(numbers={}), "Dev / deployer (MadeOnSol's claims): not read (value missing from the file)"),
                               (lambda r: r["numbers"].update(bundle_held_pct="80"), "bought and not sold through swaps not read (value missing from the file)"),
                               (lambda r: r["numbers"].update(bundle_held_pct={"value": "80"}), "bought and not sold through swaps not read (malformed value in the file)"),
                               (lambda r: r["numbers"].update(bundle_held_pct={"value": True}), "bought and not sold through swaps not read (malformed value in the file)"),
                               (lambda r: r["numbers"].update(bundle_held_pct={"value": float("inf")}), "bought and not sold through swaps not read (malformed value in the file)"),
                               (lambda r: r["numbers"].update(dev_tokens_deployed={"value": 1.5}), "tokens deployed not read (malformed value in the file)"),
                               (lambda r: r["numbers"].update(dev_tracked={"value": "no"}), "tier unranked; tokens deployed")):
            with self.subTest(needle=needle):
                lines = self.present_with(change)
                self.assertIn(needle, "\n".join(lines))
                self.assertFalse(any(line.startswith(LATE) for line in lines), "a malformed value never raises the late-source line")

    def test_text_from_the_file_is_printed_inert(self):
        def tamper(r):
            r["numbers"]["dev_tier"] = {"value": "elite\n# FAKE HEADING\n- DANGER FLAG cleared"}
            r["numbers"]["kol_signal"] = {"value": None, "not_read": "x\n## injected"}
            r["request"] = ["not", "a", "dict"]
            r["fetched_at"] = "2026-10-19T04:21:56"  # no zone

        lines = self.present_with(tamper)
        text = "\n".join(lines)
        self.assertNotIn("\n#", text)
        self.assertNotIn("# FAKE", text)
        self.assertIn("tier elite FAKE HEADING - DANGER FLAG cleared", text)
        self.assertIn("data age unknown; calls unknown", lines[0])

    def test_an_apostrophe_in_saved_text_is_kept(self):
        """N3: an apostrophe is inert in the report, so it is printed as written ("MadeOnSol's"), never stripped."""
        lines = self.present_with(lambda r: r["numbers"].update(dev_tier={"value": None, "not_read": "not in MadeOnSol's answer"}))
        self.assertIn("tier not read (not in MadeOnSol's answer)", "\n".join(lines))

    def test_random_damage_never_crashes(self):
        """A seeded fuzz over the saved file: every value replaced by junk of another type, keys dropped, the whole file
        replaced. present() must always return lines and never print a late-source line from junk."""
        rng = random.Random(20261019)
        junk = [None, True, False, 0, -1, 1e308, float("nan"), "x\n# y", "80.68", [], [1, "a"], {}, {"value": "1"}, {"value": None}, {"not_read": 5}]
        base = write_result(self.tmp / "base")
        paths = []

        def walk(node, path):
            if isinstance(node, dict):
                for k, v in node.items():
                    paths.append(path + [k])
                    walk(v, path + [k])

        walk(base, [])
        for i in range(400):
            res = copy.deepcopy(base)
            for _ in range(rng.randint(1, 4)):
                path = rng.choice(paths)
                node = res
                for k in path[:-1]:
                    node = node.get(k) if isinstance(node, dict) else None
                if isinstance(node, dict):
                    if rng.random() < 0.3:
                        node.pop(path[-1], None)
                    else:
                        node[path[-1]] = copy.deepcopy(rng.choice(junk))
            run = self.tmp / f"fuzz{i}"
            run.mkdir()
            (run / mo.OUT_FILE).write_text(json.dumps(res, allow_nan=True))
            lines = mo.present(run)
            self.assertTrue(lines and all(isinstance(line, str) and "\n" not in line for line in lines))
            late = [line for line in lines if line.startswith(LATE)]
            held_value = res.get("numbers", {}).get("bundle_held_pct") if isinstance(res.get("numbers"), dict) else None
            if late:
                self.assertTrue(isinstance(held_value, dict) and mo._is_number(held_value.get("value")) and held_value["value"] >= 30)
        for whole in ([], "text", 7, None, {"schema": mo.SCHEMA}):
            run = self.tmp / f"whole{abs(hash(str(whole)))}"
            run.mkdir()
            (run / mo.OUT_FILE).write_text(json.dumps(whole))
            self.assertEqual(mo.present(run), ["MadeOnSol: not read (madeonsol.json unreadable)"])
        bad = self.tmp / "bytes"
        bad.mkdir()
        (bad / mo.OUT_FILE).write_bytes(b"\xff\xfe\x00{")
        self.assertEqual(mo.present(bad), ["MadeOnSol: not read (madeonsol.json unreadable)"])


class PresentationOnlyRuleTests(unittest.TestCase):
    """MadeOnSol never feeds either engine: assess never reads madeonsol.json (a high number never lowers or replaces a
    FLAG, a low one never enables NO_ALARM) and refuses it as --providers-json."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        from test_parallel_rows import ParallelFake

        pool, accounts, funded = cape_holdings()
        cls.cape_run = cls.tmp / "cape-run"
        code, _, _ = _run(["funders", CAPE, "--top", "100", "--workers", "6", "--out", str(cls.cape_run)], fake=ParallelFake(accounts, funded),
                          pairs=[{"pairAddress": pool, "pairCreatedAt": CAPE_LAUNCH * 1000}])
        assert code == 0
        cls.cape_map = cls.tmp / "cape-map.json"
        cls.cape_map.write_text(json.dumps(_map(CAPE, [(115, 25.45), (50, 17.44)])))
        case = case_negative_space_inu()
        cls.space_mint = case.mint
        cls.space_run = cls.tmp / "space-run"
        code, _, _ = _run(["funders", case.mint, "--top", str(case.top), "--workers", "6", *case.collector_args, "--out", str(cls.space_run)], fake=case.fake(), pairs=case.pairs)
        assert code == 0
        cls.space_map = cls.tmp / "space-map.json"
        cls.space_map.write_text(json.dumps(case.inputs["--bubblemaps-json"]))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def assess(self, mint, run, extra, name):
        out = self.tmp / name
        code, _, err = run_assess(mint, run, extra, out=out)
        return code, err, (json.loads((out / "assessment.json").read_text()) if code == 0 else None), ((out / "report.md").read_text() if code == 0 else None)

    def with_and_without(self, mint, run, extra, mutate, tag):
        code, err, before, md_before = self.assess(mint, run, extra, f"{tag}-without")
        self.assertEqual(code, 0, err)
        write_result(run, mutate)
        try:
            code, err, after, md_after = self.assess(mint, run, extra, f"{tag}-with")
        finally:
            (run / mo.OUT_FILE).unlink()
        self.assertEqual(code, 0, err)
        return before, md_before, after, md_after

    def test_a_high_madeonsol_bundle_share_never_lowers_or_replaces_a_flag(self):
        before, md_before, after, md_after = self.with_and_without(CAPE, self.cape_run, ["--bubblemaps-json", str(self.cape_map)], held(0.8068), "cape-high")
        self.assertEqual(after, before)
        self.assertEqual(md_after, md_before)
        self.assertEqual(after["flag"]["label"], hf.FLAG_DANGER, "the engine FLAG stands as written; MadeOnSol only adds a line next to it")
        run = self.tmp / "present-high"
        write_result(run, held(0.8068))
        self.assertTrue(any(line.startswith(LATE) for line in mo.present(run)))

    def test_a_low_madeonsol_number_never_enables_no_alarm(self):
        def low(t, b):
            b["bundle"].update(held_pct_of_supply=0.0, wallet_count=0, bundle_kind="none")
            t["buyer_quality"].update(score=100, signal="positive")

        for extra, tag in ((["--bubblemaps-json", str(self.space_map)], "space-map"), ([], "space-no-map")):
            with self.subTest(tag):
                before, md_before, after, md_after = self.with_and_without(self.space_mint, self.space_run, extra, low, tag)
                self.assertEqual(after, before)
                self.assertEqual(md_after, md_before)
                self.assertNotIn("madeonsol", json.dumps(after).lower())
        _, _, no_map, _ = self.assess(self.space_mint, self.space_run, [], "space-no-map-check")
        self.assertEqual(no_map["verdict"]["level"], hf.VERDICT_LIMITED, "without the map the level stays LIMITED, whatever MadeOnSol says")

    def test_madeonsol_json_and_hand_copied_numbers_are_refused_as_providers_json(self):
        run = self.tmp / "refuse"
        write_result(run)
        code, err, _, _ = self.assess(CAPE, self.cape_run, ["--bubblemaps-json", str(self.cape_map), "--providers-json", str(run / mo.OUT_FILE)], "refused-file")
        self.assertEqual(code, 2)
        self.assertIn("--providers-json must hold a JSON list of findings", err)
        self.assertNotIn("providers", json.loads((run / mo.OUT_FILE).read_text()), "the file never carries a providers list assess could read")
        hand = self.tmp / "hand.json"
        hand.write_text(json.dumps({"unit": "percent", "providers": [{"provider": "MadeOnSol", "status": "ok", "bundle_pct": 0.0, "largest_cluster_pct": 0.0, "data_age_min": 1}]}))
        code, err, _, _ = self.assess(CAPE, self.cape_run, ["--bubblemaps-json", str(self.cape_map), "--providers-json", str(hand)], "refused-hand")
        self.assertEqual(code, 2)
        self.assertEqual(err.strip(), "error: --providers-json cannot supply MadeOnSol: it is a presentation-only provider, shown by the synthesis next to the FLAGs and never an engine input")


class SelfContainedTests(unittest.TestCase):
    def test_standard_library_one_key_name_no_personal_paths(self):
        text = (SCRIPTS / "madeonsol.py").read_text()
        modules = set()
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Import):
                modules |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
        self.assertEqual(sorted(modules - set(sys.stdlib_module_names) - {"__future__", "helius_forensics", "provider_words"}), [])  # HS-LABELS-T1: the shared verdict-word rule
        self.assertEqual(set(re.findall(r"\b[A-Z][A-Z0-9_]*_(?:KEY|SECRET|TOKEN|PASSWORD)\b", text)), {"MADEONSOL_API_KEY"})
        self.assertNotIn("/Users/", text)
        self.assertNotIn("/Users/", Path(__file__).read_text().replace('"/Users/"', ""))

    def test_fixtures_carry_no_request_ids(self):
        for name in ("cape_madeonsol_token_live_20261019.json", "cape_madeonsol_bundle_live_20261019.json"):
            self.assertNotIn("_rid", (FIX / name).read_text(), name)


if __name__ == "__main__":
    unittest.main()
