"""HS-PROV-T2: the `fomoapi` collector (one fixed, bounded Fomo API call: which Fomo-tracked traders hold the token) and
its offline `--present` mode. Offline: fake transport, dummy keys, the live CAPE answer of 2026-10-19 saved as a fixture
(public data only). Fomo API is an independent, unofficial API, not affiliated with fomo.family.

Covers: request construction (host, the documented holders path with the fixed Solana network query, the Bearer
Authorization header only, no env proxy, no redirects, size and time bounds); the one retry after a short 429 and never
more (at most 2 calls per scan); the fixed reason codes (credits_exhausted for 402, ...); the hard wall-clock deadline;
the ok / empty / unavailable paths and the loud field guards against the live answer; the single-variable key loader
(FOMOAPI_KEY), the key never reaching an output and the key-echo guards on handles and wallets; the --present block
("Fomo-tracked traders holding", FOMO's dev flag, information only, never a late-source line, never a crash on a malformed
file); and the presentation-only rule (assess never reads fomoapi.json and refuses the provider name)."""

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

import fomoapi as fa  # noqa: E402
import helius_forensics as hf  # noqa: E402
from test_assess import _map, _run, case_negative_space_inu, run_assess  # noqa: E402
from test_solscanner_scan import CAPE, SPACE  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
DUMMY_KEY = "fomo-dummy-key-3b9c1e7d5a20"
PATH = f"/token/{CAPE}/holders"
QUERY = "network=1399811149&limit=100"
LATE = "clear large cluster seen by"
FLAG_WORDS = re.compile(r"DANGER FLAG|CAUTION|NO FLAG RAISED")
REASSURING = re.compile(r"\b(clean|safe|low)\b", re.IGNORECASE)


def holders_fixture():
    return json.loads((FIX / "cape_fomoapi_holders_live_20261019.json").read_text())


def body_of(payload) -> bytes:
    return json.dumps(payload).encode()


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200, chunk: int | None = None):
        self._buf, self.status, self._chunk = io.BytesIO(body), status, chunk

    def read(self, n=-1):
        return self._buf.read(n if self._chunk is None else min(n, self._chunk))

    def close(self):
        pass


def http_error(code, headers=None, body=b""):
    msg = email.message.Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError(f"https://{fa.HOST}{PATH}", code, "error", msg, io.BytesIO(body))


class Opener:
    def __init__(self, answers=None):
        self.answers = list(answers if answers is not None else [FakeResponse(body_of(holders_fixture()))])
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return answer()
        return answer


def collect(opener, key=DUMMY_KEY, sleeps=None):
    sleeps = [] if sleeps is None else sleeps
    return fa.collect_fomoapi(CAPE, key, opener=opener, now=lambda: 1_792_389_071.0, monotonic=time.monotonic, sleep=sleeps.append)


def run_main(argv, opener, env=None):
    out, err = io.StringIO(), io.StringIO()
    env = {"FOMOAPI_KEY": DUMMY_KEY} if env is None else env
    base = {k: v for k, v in os.environ.items() if k not in ("FOMOAPI_KEY", "HOLDER_FORENSICS_ENV")}
    with mock.patch.dict(os.environ, base | env, clear=True), mock.patch.object(fa, "default_opener", return_value=opener), \
         mock.patch.object(fa.time, "sleep"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = fa.main(argv)
    return code, out.getvalue(), err.getvalue()


def write_result(folder: Path, mutate=None) -> dict:
    payload = holders_fixture()
    if mutate:
        mutate(payload)
    res = collect(Opener([FakeResponse(body_of(payload))]))
    folder.mkdir(parents=True, exist_ok=True)
    (folder / fa.OUT_FILE).write_text(json.dumps(res, indent=1))
    return res


class RequestConstructionTests(unittest.TestCase):
    def test_one_documented_get_with_the_bearer_header_only(self):
        opener = Opener()
        res = collect(opener)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(len(opener.requests), 1)
        request, timeout = opener.requests[0]
        url = urllib.parse.urlparse(request.full_url)
        self.assertEqual((url.scheme, url.hostname, url.port, url.path, url.query), ("https", "api.fomoapi.io", None, PATH, QUERY))
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(dict(request.header_items()), {"Authorization": f"Bearer {DUMMY_KEY}", "Accept": "application/json", "User-agent": fa.USER_AGENT})
        self.assertEqual(timeout, fa.TIMEOUT_S)
        self.assertEqual(res["request"], {"method": "GET", "host": "api.fomoapi.io", "path": "/token/<MINT>/holders?network=1399811149&limit=100",
                                          "auth_header_names": ["Authorization"], "auth_scheme": "Bearer", "requests_per_scan": 1, "max_requests": 2,
                                          "credits_per_call": 250, "free_credits_per_month": 250000, "requests_sent": 1})
        self.assertEqual(res["independence"], "an independent, unofficial API, not affiliated with fomo.family")

    def test_default_opener_ignores_env_proxies_and_refuses_redirects(self):
        with mock.patch.dict(os.environ, {"https_proxy": "http://proxy.invalid:3128", "HTTPS_PROXY": "http://proxy.invalid:3128"}):
            opener = fa.default_opener()
        self.assertFalse(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in opener.handlers))
        self.assertTrue(any(isinstance(h, fa.NoRedirect) for h in opener.handlers))

    def test_only_the_allowlisted_https_host_path_and_query(self):
        for url in (f"http://api.fomoapi.io{PATH}?{QUERY}", f"https://api.fomoapi.io.evil.example{PATH}?{QUERY}", f"https://api.fomoapi.io:8443{PATH}?{QUERY}",
                    f"https://u:p@api.fomoapi.io{PATH}?{QUERY}", f"https://api.fomoapi.io{PATH}", f"https://api.fomoapi.io{PATH}?network=4663&limit=100",
                    f"https://api.fomoapi.io{PATH}?{QUERY}&deep=1", f"https://api.fomoapi.io/v2/token/{CAPE}/devs?{QUERY}", f"https://api.fomoapi.io/token/{SPACE}/holders?{QUERY}",
                    "https://api.fomoapi.io/v2/trading/buy", "https://fomoapi.io/pricing", f"https://api.fomoapi.io/v2/thesis/token/{CAPE}?{QUERY}"):
            with self.subTest(url), self.assertRaises(fa.Failure):
                fa.check_url(url, CAPE)
        opener = Opener()
        with self.assertRaises(fa.Failure):
            fa.send_once(urllib.request.Request("https://example.com" + PATH), opener, CAPE, monotonic=time.monotonic)
        self.assertEqual(opener.requests, [])

    def test_never_a_trading_payment_or_stream_call(self):
        code = ast.parse((SCRIPTS / "fomoapi.py").read_text())
        strings = [n.value for n in ast.walk(code) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        self.assertFalse([s for s in strings if "/v2/trading" in s or "/pay/" in s or "/ws/" in s or "wss:" in s])
        methods = {kw.value.value for n in ast.walk(code) if isinstance(n, ast.Call) for kw in n.keywords if kw.arg == "method" and isinstance(kw.value, ast.Constant)}
        self.assertEqual(methods, {"GET"})

    def test_redirect_size_and_error_bounds(self):
        cases = [(http_error(302), "redirect_disallowed", 302), (FakeResponse(b"", status=301), "redirect_disallowed", 301), (http_error(401), "authentication_failed", 401),
                 (http_error(402, body=b'{"error": "credits_exhausted"}'), "credits_exhausted", 402), (http_error(403), "access_denied", 403), (http_error(404), "not_found", 404),
                 (http_error(503, headers={"Retry-After": "1"}), "service_unavailable", 503), (http_error(500), "server_error", 500), (http_error(418), "http_error", 418),
                 (socket.timeout(), "timeout", None), (urllib.error.URLError(OSError("refused")), "network_error", None), (RuntimeError(f"boom {DUMMY_KEY}"), "network_error", None),
                 (FakeResponse(b"<html>"), "invalid_json", 200)]
        for answer, reason, status in cases:
            with self.subTest(reason=reason):
                opener = Opener([answer])
                res = collect(opener)
                self.assertEqual((res["status"], res["reason"], res["http_status"], len(opener.requests)), ("unavailable", reason, status, 1))
                self.assertNotIn(DUMMY_KEY, json.dumps(res))
        with mock.patch.object(fa, "MAX_BYTES", 1000):
            res = collect(Opener([FakeResponse(b"x" * 1001, chunk=100)]))
        self.assertEqual(res["reason"], "response_too_large")


class RateLimitTests(unittest.TestCase):
    def test_one_retry_after_a_short_429_and_never_more(self):
        sleeps = []
        opener = Opener([http_error(429, headers={"Retry-After": "2"}), FakeResponse(body_of(holders_fixture()))])
        res = collect(opener, sleeps=sleeps)
        self.assertEqual((res["status"], res["request"]["requests_sent"], len(opener.requests), sleeps), ("ok", 2, 2, [2.0]))
        sleeps = []
        opener = Opener([http_error(429, headers={"Retry-After": "1"}), http_error(429, headers={"Retry-After": "1"}), FakeResponse(b"{}")])
        res = collect(opener, sleeps=sleeps)
        self.assertEqual((res["status"], res["reason"], len(opener.requests), sleeps), ("unavailable", "rate_limited", 2, [1.0]))

    def test_no_retry_without_a_short_retry_after_or_on_another_error(self):
        for answer in (http_error(429), http_error(429, headers={"Retry-After": "60"}), http_error(402), http_error(503, headers={"Retry-After": "1"})):
            with self.subTest(code=answer.code):
                sleeps = []
                opener = Opener([answer, FakeResponse(body_of(holders_fixture()))])
                res = collect(opener, sleeps=sleeps)
                self.assertEqual((len(opener.requests), sleeps, res["status"]), (1, [], "unavailable"))


class HardDeadlineTests(unittest.TestCase):
    DEADLINE = 0.5
    MARGIN = 0.5

    def setUp(self):
        self.stop = threading.Event()
        patcher = mock.patch.object(fa, "TIMEOUT_S", self.DEADLINE)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.stop.set)

    def test_a_drip_feed_and_a_stalled_open_end_at_the_deadline(self):
        stop = self.stop

        class Drip:
            status = 200

            def __init__(self):
                self.start = time.monotonic()

            def read(self, n=-1):
                got = b""
                while not stop.is_set() and time.monotonic() - self.start < 3.0 and len(got) < n:
                    time.sleep(0.01)
                    got += b"x"
                return got

            def close(self):
                pass

        def stall():
            stop.wait(3.0)
            raise OSError("released")

        for answer in (Drip, stall):
            with self.subTest(answer=answer.__name__):
                started = time.monotonic()
                res = collect(Opener([answer]))
                self.assertEqual((res["status"], res["reason"]), ("unavailable", "timeout"))
                self.assertLess(time.monotonic() - started, self.DEADLINE + self.MARGIN)


class StatusAndGuardTests(unittest.TestCase):
    def parsed(self, mutate=None, payload=None):
        if payload is None:
            payload = holders_fixture()
            if mutate:
                mutate(payload)
        return collect(Opener([FakeResponse(body_of(payload))]))

    def test_live_cape_answer(self):
        res = self.parsed()
        self.assertEqual((res["status"], res["identity"], res["scope"], res["source"], res["stale"], res["total_holders"], res["count"], res["dev_field_present"]),
                         ("ok", "confirmed", "live-top-holders", "live-fomo", False, 208, 2, True))
        self.assertEqual([(h["handle"], h["valueUsd"], h["isDev"], h["wallet_solana"]) for h in res["holders"]],
                         [("HerrOdinn", 16.8861, False, None), ("Duki13", 5.38732, False, None)])
        self.assertEqual(set(res["holders"][0]), {"handle", "amount", "valueUsd", "costBasisUsd", "pnlUsd", "isDev", "verified", "wallet_solana"}, "documented fields only")
        self.assertNotIn("thesis", json.dumps(res))
        self.assertNotIn("we only return a wallet", json.dumps(res), "Fomo's free text is not kept")
        self.assertEqual(fa.status_line(res), "ok (2 Fomo-tracked traders listed; 1 Fomo API call, 250 credits)")

    def test_guards(self):
        cases = [
            (lambda p: p.update(token=SPACE), ("unavailable", "identity_mismatch")),
            (lambda p: p.pop("holders"), ("unavailable", "holder_list_missing")),
            (lambda p: p.update(holders={"a": 1}), ("unavailable", "holder_list_missing")),
            (lambda p: p.update(holders=[]), ("empty", "holder_list_empty")),
            (lambda p: p.update(available=False, reason="no-data", holders=[]), ("empty", "no_data")),
            (lambda p: p.update(available=False, reason="unknown-chain"), ("empty", "unknown_chain")),
            (lambda p: p.update(available=False, reason="something new"), ("empty", "not_available")),
            (lambda p: [r.update(user=r.pop("handle")) for r in p["holders"]], ("unavailable", "handle_field_missing")),
            (lambda p: p.update(holders=["HerrOdinn", 7]), ("unavailable", "handle_field_missing")),
        ]
        for change, expected in cases:
            with self.subTest(expected=expected):
                res = self.parsed(change)
                self.assertEqual((res["status"], res["reason"]), expected)
                self.assertNotIn("holders", res if res["status"] == "unavailable" else {})
        self.assertEqual((self.parsed(payload=[1])["status"], self.parsed(payload=[1])["reason"]), ("unavailable", "invalid_shape"))
        self.assertTrue(fa.status_line(self.parsed(lambda p: p.update(holders=[]))).startswith("empty (Fomo lists no tracked trader holding it"))

    def test_a_malformed_scope_or_reason_is_a_fixed_code_with_the_call_counted(self):
        """C2: scope / reason / source of another type than text give unavailable (malformed_answer), with the one call
        counted; never the crash path ("request_failed; no Fomo API call sent")."""
        for change in (lambda p: p.update(scope=["live-top-holders"]), lambda p: p.update(scope={"name": "live-top-holders"}),
                       lambda p: p.update(available=False, reason=["no-data"]), lambda p: p.update(available=False, reason={"code": "no-data"}),
                       lambda p: p.update(source=["live-fomo"])):
            with self.subTest():
                p = holders_fixture()
                change(p)
                res = self.parsed(payload=p)
                self.assertEqual((res["status"], res["reason"], res["request"]["requests_sent"]), ("unavailable", "malformed_answer", 1))
                self.assertEqual(fa.status_line(res), "unavailable (malformed_answer; 1 Fomo API call, 250 credits)")
                code, out, _ = run_main([CAPE, "--out", str(Path(tempfile.mkdtemp()) / "run")], Opener([FakeResponse(body_of(p))]))
                self.assertEqual((code, out.strip()), (0, "unavailable (malformed_answer; 1 Fomo API call, 250 credits)"))
        self.assertEqual(self.parsed(lambda p: p.update(scope="a-new-scope"))["status"], "ok", "an unknown text scope is read, shown as scope not stated")

    def test_an_unforeseen_answer_is_a_fixed_code_with_the_call_counted(self):
        with mock.patch.object(fa, "parse_holders", side_effect=RuntimeError(f"boom {DUMMY_KEY}")):
            res = collect(Opener())
        self.assertEqual((res["status"], res["reason"], res["request"]["requests_sent"]), ("unavailable", "parse_error", 1))
        self.assertNotIn(DUMMY_KEY, json.dumps(res))

    def test_rows_and_values_are_validated(self):
        def junk(p):
            p["holders"][0].update(valueUsd="16", amount=-5, isDev="yes", handle="Herr<b>Odinn</b>\n# x")
            p["holders"][1]["wallet"] = {"solana": CAPE, "verified": True}
            p["holders"][0]["wallet"] = {"solana": SPACE, "verified": False}
            p["holders"].append({"handle": None, "valueUsd": 1.0})
            p["scope"] = "made-up"
            p["source"] = "live-fomo-stale"

        res = self.parsed(junk)
        rows = res["holders"]
        self.assertEqual((rows[0]["handle"], rows[0]["valueUsd"], rows[0]["amount"], rows[0]["isDev"]), ("HerrOdinn x", None, None, None))  # HS-LABELS-T1 hardening (a): inline HTML tags are dropped, not left as letters
        self.assertEqual(rows[1]["wallet_solana"], CAPE, "a verified Solana wallet is kept")
        self.assertIsNone(rows[0]["wallet_solana"], "an unverified wallet is withheld, as Fomo itself does")
        self.assertEqual((res["scope"], res["stale"]), (None, True))

    def test_a_long_list_is_capped(self):
        res = self.parsed(lambda p: p.update(holders=[{"handle": f"t{i}", "valueUsd": 1.0} for i in range(150)]))
        self.assertEqual((len(res["holders"]), res["rows_dropped"]), (100, 50))


class KeyHandlingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_the_key_never_reaches_an_output(self):
        secret = "fomo_SeCrEt-0d1e2f3a4b5c6d7e8f9a"
        b58 = "HfpLdX35Kc6b7zDNWbe5x1xWLekKUXPYZbmz71vM"

        def echo():
            p = holders_fixture()
            p["holders"][0]["handle"] = secret
            p["holders"][1]["handle"] = f"x {secret[5:18]}"
            p["source"] = secret
            return FakeResponse(body_of(p))

        for name, answers, key in (("ok", [FakeResponse(body_of(holders_fixture()))], secret), ("auth", [http_error(401, body=secret.encode())], secret),
                                   ("boom", [RuntimeError(f"Authorization: Bearer {secret}")], secret), ("echo", [echo()], secret)):
            with self.subTest(name):
                out_dir = self.tmp / name
                code, out, err = run_main([CAPE, "--out", str(out_dir)], Opener(answers), env={"FOMOAPI_KEY": key})
                self.assertEqual(code, 0)
                for text in [out, err] + [p.read_text() for p in out_dir.iterdir()]:
                    self.assertFalse(fa.shares_key_piece(text, key), f"{name}: an 8-character piece of the key reached an output")
                present_out = io.StringIO()
                with contextlib.redirect_stdout(present_out):
                    fa.main(["--present", str(out_dir)])
                self.assertFalse(fa.shares_key_piece(present_out.getvalue(), key))
        p = holders_fixture()
        p["holders"][0]["wallet"] = {"solana": "22" + b58, "verified": True}
        res = collect(Opener([FakeResponse(body_of(p))]), key=b58)
        self.assertIsNone(res["holders"][0]["wallet_solana"], "an address sharing a run with the key is dropped, not only an equal one")
        self.assertEqual(res["holders"][0]["handle"], "HerrOdinn", "real handles are kept")

    def test_single_variable_loader_reads_the_owners_name(self):
        env = self.tmp / ".env"
        env.write_text("FOMO_API_KEY=the-index-name-not-used\nexport FOMOAPI_KEY=\"from-file-0123456789\"\nFOMOAPI_KEY=second-ignored\nMADEONSOL_API_KEY=msk_other_key_1234\n")
        base = {k: v for k, v in os.environ.items() if k not in ("FOMOAPI_KEY", "FOMO_API_KEY")}
        with mock.patch.dict(os.environ, base | {"FOMO_API_KEY": "env-index-name-ignored"}, clear=True):
            self.assertEqual(fa.load_key(env), ("from-file-0123456789", None), "only FOMOAPI_KEY is read, never FOMO_API_KEY")
            env.write_text("FOMO_API_KEY=only-the-other-name-123\n")
            self.assertEqual(fa.load_key(env), (None, "missing_key"))
            env.write_text("FOMOAPI_KEY=has space inside\n")
            self.assertEqual(fa.load_key(env), (None, "key_format"))
        with mock.patch.dict(os.environ, base | {"FOMOAPI_KEY": "from-environment-123"}, clear=True):
            self.assertEqual(fa.load_key(env), ("from-environment-123", None))

    def test_missing_key_sends_nothing(self):
        opener = Opener()
        code, out, _ = run_main([CAPE, "--out", str(self.tmp / "run"), "--env-file", str(self.tmp / "none.env")], opener, env={})
        self.assertEqual((code, opener.requests), (0, []))
        self.assertEqual(out.strip(), "unavailable (missing_key; no Fomo API call sent)")



SYMBOL_KEY = "fomo_Ab3/xY9+Qz7=Lm4/Np8+Rt6=Uv2"   # a key with characters a label cannot hold


class KeyEchoHardeningTests(unittest.TestCase):
    """Handles are dropped when the raw text or the label echoes the key (or the key without the characters a label
    cannot hold); the whole handle is dropped, never kept as a cut label."""

    def handle_after(self, handle, key):
        p = holders_fixture()
        p["holders"][0]["handle"] = handle
        return collect(Opener([FakeResponse(body_of(p))]), key=key)["holders"][0]["handle"]

    def test_an_echo_past_the_label_cut_is_caught_on_the_raw_text(self):
        raw = "Trader with a very long handle x " + DUMMY_KEY
        self.assertEqual(len("Trader with a very long handle x "), 33)
        self.assertFalse(fa.echoes_key(fa.LABEL_RE.sub("", raw)[:32], DUMMY_KEY), "the cut label alone holds no piece of the key")
        self.assertIsNone(fa.safe_label(raw, DUMMY_KEY))
        self.assertIsNone(self.handle_after(raw, DUMMY_KEY))

    def test_a_key_interleaved_with_markup_is_caught_on_the_label(self):
        raw = DUMMY_KEY[:5] + "<" + DUMMY_KEY[5:10] + ">" + DUMMY_KEY[10:15] + "|" + DUMMY_KEY[15:20]
        self.assertFalse(fa.echoes_key(raw, DUMMY_KEY))
        self.assertIsNone(self.handle_after(raw, DUMMY_KEY))

    def test_a_pre_stripped_symbol_key_is_caught(self):
        pre_stripped = "x " + fa.LABEL_RE.sub("", SYMBOL_KEY)[8:22]  # past the "fomo_Ab3" prefix, which the raw key also holds
        self.assertFalse(fa.shares_key_piece(pre_stripped, SYMBOL_KEY))
        self.assertIsNone(self.handle_after(pre_stripped, SYMBOL_KEY))

    def test_real_handles_are_kept(self):
        for key in (SYMBOL_KEY, DUMMY_KEY, "HfpLdX35Kc6b7zDNWbe5x1xWLekKUXPYZbmz71vM"):
            with self.subTest(key=key[:6]):
                res = collect(Opener(), key=key)
                self.assertEqual([h["handle"] for h in res["holders"]], ["HerrOdinn", "Duki13"])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_bad_input_exits_2_without_a_call(self):
        opener = Opener()
        for argv in (["not-a-mint", "--out", str(self.tmp)], [CAPE], ["--present", str(self.tmp / "missing")], [CAPE, "--present", str(self.tmp)]):
            with self.subTest(argv):
                code, _, err = run_main(argv, opener)
                self.assertEqual(code, 2)
                self.assertTrue(err.startswith("error:"))
        self.assertEqual(opener.requests, [])

    def test_present_reads_no_key_and_opens_no_connection(self):
        write_result(self.tmp)

        def refuse(*_a, **_k):
            raise AssertionError("network or key access in --present")

        out = io.StringIO()
        with mock.patch.object(fa, "load_key", side_effect=refuse), mock.patch.object(fa, "find_env_file", side_effect=refuse), \
             mock.patch.object(fa, "default_opener", side_effect=refuse), mock.patch.object(socket, "create_connection", refuse), \
             mock.patch.object(socket.socket, "connect", refuse), contextlib.redirect_stdout(out):
            code = fa.main(["--present", str(self.tmp)])
        self.assertEqual(code, 0)
        self.assertIn("Fomo API (collector fomoapi; an independent, unofficial API, not affiliated with fomo.family): read", out.getvalue())


class PresentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def lines(self, mutate=None, name="run"):
        run = self.tmp / name
        write_result(run, mutate)
        return fa.present(run)

    def test_live_cape_block_is_information_only(self):
        lines = self.lines()
        text = "\n".join(lines)
        self.assertEqual(lines[0].split(";")[0], "Fomo API (collector fomoapi")
        self.assertIn("an independent, unofficial API, not affiliated with fomo.family): read", lines[0])
        self.assertIn("1 call, 250 credits of the free key's 250,000 a month", lines[0])
        self.assertIn("  Fomo-tracked traders holding (FOMO's own top-holder list): 2 listed, worth $22.27 together: HerrOdinn ($16.88), Duki13 ($5.387); "
                      "FOMO reports 208 holders in total (its own count, not checked)", lines)
        self.assertIn("  dev flag (FOMO's claim): none of the listed traders is flagged as the dev; not proof the dev sold", lines)
        self.assertIn("is not a signal of safety or danger", text)
        self.assertNotIn(LATE, text, "Fomo has no share of supply: never a late-source line")
        self.assertIsNone(FLAG_WORDS.search(text))
        self.assertIsNone(REASSURING.search(text))

    def test_a_flagged_dev_and_many_traders(self):
        def many(p):
            p["holders"] = [{"handle": f"trader{i}", "valueUsd": 1000.0 * (i + 1), "isDev": i == 3} for i in range(12)]

        lines = self.lines(many, "many")
        text = "\n".join(lines)
        self.assertIn("12 listed, worth $78000 together", text)
        self.assertIn(", and 4 more", text)
        self.assertIn("  dev flag (FOMO's claim): trader3 flagged as the dev", lines)
        self.assertFalse(any(LATE in line for line in lines), "a large Fomo holding is information, never a late-source line")

    def test_empty_unavailable_and_missing(self):
        lines = self.lines(lambda p: p.update(holders=[]), "empty")
        self.assertIn("empty (holder_list_empty)", lines[0])
        self.assertIn("never \"nobody holds it\"", "\n".join(lines))
        run = self.tmp / "failed"
        run.mkdir()
        (run / fa.OUT_FILE).write_text(json.dumps(collect(Opener([http_error(402)]))))
        self.assertIn("unavailable (credits_exhausted)", fa.present(run)[0])
        empty = self.tmp / "nothing"
        empty.mkdir()
        self.assertEqual(fa.present(empty), ["Fomo API (collector fomoapi; an independent, unofficial API, not affiliated with fomo.family): not read (fomoapi.json missing)"])

    def test_an_apostrophe_in_saved_text_is_kept(self):
        """N3: an apostrophe is inert in the report, so it is printed as written, never stripped."""
        run = self.tmp / "apostrophe"
        res = write_result(run)
        res.update(status="unavailable", reason="FOMO's answer changed")
        (run / fa.OUT_FILE).write_text(json.dumps(res))
        self.assertIn("unavailable (FOMO's answer changed)", fa.present(run)[0])

    def test_random_damage_never_crashes(self):
        rng = random.Random(20261019)
        junk = [None, True, 0, -1, 1e308, float("nan"), "x\n# y", [], [1, "a"], {}, {"handle": 5}]
        base = write_result(self.tmp / "base")
        for i in range(300):
            res = copy.deepcopy(base)
            for _ in range(rng.randint(1, 4)):
                rows = res.get("holders") if isinstance(res.get("holders"), list) else []
                target = rng.choice([res, *[h for h in rows if isinstance(h, dict)]])
                key = rng.choice(list(target) or ["x"])
                if rng.random() < 0.3:
                    target.pop(key, None)
                else:
                    target[key] = copy.deepcopy(rng.choice(junk))
            run = self.tmp / f"fuzz{i}"
            run.mkdir()
            (run / fa.OUT_FILE).write_text(json.dumps(res, allow_nan=True))
            lines = fa.present(run)
            self.assertTrue(lines and all(isinstance(line, str) and "\n" not in line and "\n#" not in line for line in lines))
        for whole in ([], "text", 7, None):
            run = self.tmp / f"whole{abs(hash(str(whole)))}"
            run.mkdir()
            (run / fa.OUT_FILE).write_text(json.dumps(whole))
            self.assertTrue(fa.present(run)[0].endswith("not read (fomoapi.json unreadable)"))


class PresentationOnlyRuleTests(unittest.TestCase):
    """assess never reads fomoapi.json, and refuses Fomo API (and fomoapi.json) as --providers-json."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        case = case_negative_space_inu()
        cls.mint = case.mint
        cls.run_dir = cls.tmp / "space-run"
        code, _, _ = _run(["funders", case.mint, "--top", str(case.top), "--workers", "6", *case.collector_args, "--out", str(cls.run_dir)], fake=case.fake(), pairs=case.pairs)
        assert code == 0
        cls.space_map = cls.tmp / "space-map.json"
        cls.space_map.write_text(json.dumps(case.inputs["--bubblemaps-json"]))
        cls.alarm_map = cls.tmp / "alarm-map.json"
        cls.alarm_map.write_text(json.dumps(_map(case.mint, [(40, 25.0)], age=2.0)))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def assess(self, extra, name):
        out = self.tmp / name
        code, _, err = run_assess(self.mint, self.run_dir, extra, out=out)
        return code, err, (json.loads((out / "assessment.json").read_text()) if code == 0 else None), ((out / "report.md").read_text() if code == 0 else None)

    def test_fomoapi_json_in_the_run_folder_changes_nothing(self):
        for extra, tag in ((["--bubblemaps-json", str(self.space_map)], "map"), (["--bubblemaps-json", str(self.alarm_map)], "alarm"), ([], "no-map")):
            with self.subTest(tag):
                code, err, before, md_before = self.assess(extra, f"{tag}-without")
                self.assertEqual(code, 0, err)
                write_result(self.run_dir, lambda p: p.update(holders=[{"handle": f"t{i}", "valueUsd": 1e6, "isDev": False} for i in range(50)]))
                try:
                    code, err, after, md_after = self.assess(extra, f"{tag}-with")
                finally:
                    (self.run_dir / fa.OUT_FILE).unlink()
                self.assertEqual(code, 0, err)
                self.assertEqual((after, md_after), (before, md_before))
        _, _, alarm, _ = self.assess(["--bubblemaps-json", str(self.alarm_map)], "alarm-check")
        self.assertTrue(alarm["flag"]["label"].startswith(hf.FLAG_DANGER), "the map alarm stands; Fomo never softens it")

    def test_refused_as_providers_json(self):
        run = self.tmp / "refuse"
        write_result(run)
        code, err, _, _ = self.assess(["--providers-json", str(run / fa.OUT_FILE)], "refused-file")
        self.assertEqual(code, 2)
        self.assertIn("--providers-json must hold a JSON list of findings", err)
        hand = self.tmp / "hand.json"
        hand.write_text(json.dumps({"unit": "percent", "providers": [{"provider": "FOMO API (tracked traders)", "status": "ok", "largest_cluster_pct": 0.0, "data_age_min": 1}]}))
        code, err, _, _ = self.assess(["--bubblemaps-json", str(self.alarm_map), "--providers-json", str(hand)], "refused-hand")
        self.assertEqual(code, 2)
        self.assertEqual(err.strip(), "error: --providers-json cannot supply Fomo API: it is a presentation-only provider, shown by the synthesis next to the FLAGs and never an engine input")


class SelfContainedTests(unittest.TestCase):
    def test_standard_library_one_key_name_no_personal_paths(self):
        text = (SCRIPTS / "fomoapi.py").read_text()
        modules = set()
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Import):
                modules |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
        self.assertEqual(sorted(modules - set(sys.stdlib_module_names) - {"__future__", "provider_words"}), [])  # HS-LABELS-T1: the shared verdict-word rule
        self.assertEqual(set(re.findall(r"\b[A-Z][A-Z0-9_]*_(?:KEY|SECRET|TOKEN|PASSWORD)\b", text)), {"FOMOAPI_KEY"})
        self.assertNotIn("FOMO_API_KEY", text)
        self.assertNotIn("/Users/", text)


if __name__ == "__main__":
    unittest.main()
