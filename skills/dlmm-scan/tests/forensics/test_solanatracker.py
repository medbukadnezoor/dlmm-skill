"""HS-PROV-T1: the `solanatracker` collector (two fixed, bounded Solana Tracker requests sent at the same time) and its
offline `--present` mode. Offline: fake transport, dummy keys, the live CAPE answers of 2026-10-19 saved as fixtures.

Covers: request construction (host, the two documented paths, the x-api-key header, no env proxy, no redirects, size and
time bounds, both requests at once); the one retry after a short 429 and never more (at most 4 requests per scan); the
hard wall-clock deadline; the ok / empty / unavailable paths and the loud field guards; the single-variable key loader
and the key never reaching an output; and the presentation-only rule: a high Solana Tracker number gives the late-source
line next to the FLAGs but never lowers or replaces a FLAG, and a low one never enables NO_ALARM (assess never reads the
file and refuses it as --providers-json)."""

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

import gmgn_rows as gr  # noqa: E402
import helius_forensics as hf  # noqa: E402
import jupiter_rows as jr  # noqa: E402
import solanatracker as st  # noqa: E402
from test_assess import CAPE_LAUNCH, _map, _run, cape_holdings, case_negative_space_inu, run_assess  # noqa: E402
from test_solscanner_scan import CAPE, SPACE  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
DUMMY_KEY = "dummy-solanatracker-key-5e1d0c9b8a7f"
TOKEN_PATH = f"/tokens/{CAPE}"
BUNDLERS_PATH = f"/tokens/{CAPE}/bundlers"
LATE = "clear large cluster seen by Solana Tracker, not yet in the engine verdicts"
FLAG_WORDS = re.compile(r"DANGER FLAG|CAUTION|NO FLAG RAISED")
REASSURING = re.compile(r"\b(clean|safe|low)\b", re.IGNORECASE)


def token_fixture():
    return json.loads((FIX / "cape_solanatracker_token_live_20261019.json").read_text())


def bundlers_fixture():
    return json.loads((FIX / "cape_solanatracker_bundlers_live_20261019.json").read_text())


def body_of(payload) -> bytes:
    return json.dumps(payload).encode()


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200, chunk: int | None = None):
        self._buf, self.status, self._chunk = io.BytesIO(body), status, chunk

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, n=-1):
        return self._buf.read(n if self._chunk is None else min(n, self._chunk))

    def close(self):
        pass


def http_error(code, path=TOKEN_PATH, headers=None, body=b""):
    msg = email.message.Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError(f"https://{st.HOST}{path}", code, "error", msg, io.BytesIO(body))


class Router:
    """Answers by request path (the two requests run in two threads); records every request with its timeout."""

    def __init__(self, token=None, bundlers=None, barrier=None):
        self.answers = {TOKEN_PATH: list(token if token is not None else [FakeResponse(body_of(token_fixture()))]),
                        BUNDLERS_PATH: list(bundlers if bundlers is not None else [FakeResponse(body_of(bundlers_fixture()))])}
        self.requests, self.lock, self.barrier = [], threading.Lock(), barrier

    def open(self, request, timeout=None):
        path = urllib.parse.urlparse(request.full_url).path
        with self.lock:
            self.requests.append((request, timeout))
            answer = self.answers[path].pop(0)
        if self.barrier is not None:
            self.barrier.wait()  # both requests must be in flight at the same time
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return answer()
        return answer

    def count(self, path):
        return sum(1 for r, _ in self.requests if urllib.parse.urlparse(r.full_url).path == path)


def collect(router, key=DUMMY_KEY, sleeps=None, monotonic=None):
    sleeps = [] if sleeps is None else sleeps
    return st.collect_solanatracker(CAPE, key, opener=router, now=lambda: 1_792_405_316.0, monotonic=monotonic or time.monotonic, sleep=sleeps.append)


def run_main(argv, router, env=None):
    out, err = io.StringIO(), io.StringIO()
    env = {"SOLANATRACKER_API_KEY": DUMMY_KEY} if env is None else env
    base = {k: v for k, v in os.environ.items() if k not in ("SOLANATRACKER_API_KEY", "HOLDER_FORENSICS_ENV")}
    with mock.patch.dict(os.environ, base | env, clear=True), mock.patch.object(st, "default_opener", return_value=router), \
         mock.patch.object(st.time, "sleep"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = st.main(argv)
    return code, out.getvalue(), err.getvalue()


def write_result(folder: Path, mutate=None) -> dict:
    """A solanatracker.json in `folder` from the live fixtures, optionally with changed numbers."""
    token, bundlers = token_fixture(), bundlers_fixture()
    if mutate:
        mutate(token, bundlers)
    res = collect(Router([FakeResponse(body_of(token))], [FakeResponse(body_of(bundlers))]))
    folder.mkdir(parents=True, exist_ok=True)
    (folder / st.OUT_FILE).write_text(json.dumps(res, indent=1))
    return res


class RequestConstructionTests(unittest.TestCase):
    def test_two_documented_gets_with_the_key_header_only(self):
        router = Router()
        res = collect(router)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(len(router.requests), 2)
        paths = set()
        for request, timeout in router.requests:
            url = urllib.parse.urlparse(request.full_url)
            self.assertEqual((url.scheme, url.hostname, url.port, url.query), ("https", "data.solanatracker.io", None, ""))
            paths.add(url.path)
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(dict(request.header_items()), {"x-api-key": DUMMY_KEY, "Accept": "application/json", "User-agent": st.USER_AGENT})
            self.assertEqual(timeout, st.TIMEOUT_S)
        self.assertEqual(paths, {TOKEN_PATH, BUNDLERS_PATH})
        self.assertEqual(res["request"], {"method": "GET", "host": "data.solanatracker.io", "paths": ["/tokens/<MINT>", "/tokens/<MINT>/bundlers"],
                                          "auth_header_names": ["x-api-key"], "requests_per_scan": 2, "max_requests": 4, "requests_sent": 2})

    def test_both_requests_are_sent_at_the_same_time(self):
        res = collect(Router(barrier=threading.Barrier(2, timeout=2.0)))
        self.assertEqual((res["token_risk"]["status"], res["bundlers"]["status"]), ("ok", "ok"), "a one-by-one sender would break the two-party barrier")

    def test_default_opener_ignores_env_proxies_and_refuses_redirects(self):
        with mock.patch.dict(os.environ, {"https_proxy": "http://proxy.invalid:3128", "HTTPS_PROXY": "http://proxy.invalid:3128"}):
            opener = st.default_opener()
            plain = urllib.request.build_opener()
        self.assertTrue(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies.get("https") for h in plain.handlers))
        self.assertFalse(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in opener.handlers))
        self.assertTrue(any(isinstance(h, st.NoRedirect) for h in opener.handlers))
        self.assertFalse(any(type(h) is urllib.request.HTTPRedirectHandler for h in opener.handlers))

    def test_only_the_allowlisted_https_host_and_paths(self):
        for url in (f"http://data.solanatracker.io{TOKEN_PATH}", f"https://data.solanatracker.io.evil.example{TOKEN_PATH}", f"https://data.solanatracker.io:8443{TOKEN_PATH}",
                    f"https://user:pw@data.solanatracker.io{TOKEN_PATH}", f"https://data.solanatracker.io/tokens/{SPACE}", f"https://data.solanatracker.io{TOKEN_PATH}/holders",
                    f"https://data.solanatracker.io{TOKEN_PATH}?enrich=all", "https://data.solanatracker.io/price"):
            with self.subTest(url), self.assertRaises(st.Failure):
                st.check_url(url, CAPE)
        router = Router()
        with self.assertRaises(st.Failure):
            st.send_once(urllib.request.Request("https://example.com" + TOKEN_PATH), router, CAPE, monotonic=time.monotonic)
        self.assertEqual(router.requests, [], "a refused URL is never opened")

    def test_redirect_size_and_error_bounds(self):
        cases = [(http_error(302), "redirect_disallowed", 302), (FakeResponse(b"", status=301), "redirect_disallowed", 301), (http_error(401), "authentication_failed", 401),
                 (http_error(403), "access_denied", 403), (http_error(404), "not_found", 404), (http_error(500), "server_error", 500), (http_error(418), "http_error", 418),
                 (socket.timeout(), "timeout", None), (urllib.error.URLError(OSError("refused")), "network_error", None), (RuntimeError(f"boom {DUMMY_KEY}"), "network_error", None),
                 (FakeResponse(b"<html>"), "invalid_json", 200)]
        for answer, reason, status in cases:
            with self.subTest(reason=reason, answer=type(answer).__name__):
                router = Router(token=[answer])
                res = collect(router)
                self.assertEqual((res["token_risk"]["status"], res["token_risk"]["reason"], res["token_risk"]["http_status"], router.count(TOKEN_PATH)), ("unavailable", reason, status, 1))
                self.assertEqual(res["status"], "ok", "the bundlers part was still read")
                self.assertNotIn(DUMMY_KEY, json.dumps(res))
        with mock.patch.object(st, "MAX_BYTES", 1000):
            res = collect(Router(token=[FakeResponse(b"x" * 1001, chunk=100)]))
        self.assertEqual(res["token_risk"]["reason"], "response_too_large")


class RateLimitTests(unittest.TestCase):
    def test_one_retry_after_a_short_429(self):
        for headers, wait in (({"Retry-After": "1"}, 1.0), ({}, st.RETRY_DEFAULT_WAIT_S), ({"Retry-After": "0"}, 0.5)):
            with self.subTest(headers=headers):
                sleeps = []
                router = Router(token=[http_error(429, headers=headers), FakeResponse(body_of(token_fixture()))])
                res = collect(router, sleeps=sleeps)
                self.assertEqual((res["token_risk"]["status"], res["token_risk"]["attempts"], router.count(TOKEN_PATH), sleeps), ("ok", 2, 2, [wait]))
                self.assertEqual(res["request"]["requests_sent"], 3)

    def test_never_more_than_one_retry_and_at_most_four_requests(self):
        sleeps = []
        router = Router(token=[http_error(429), http_error(429), FakeResponse(b"{}")], bundlers=[http_error(429, BUNDLERS_PATH), http_error(429, BUNDLERS_PATH), FakeResponse(b"{}")])
        res = collect(router, sleeps=sleeps)
        self.assertEqual((res["status"], res["token_risk"]["reason"], res["bundlers"]["reason"]), ("unavailable", "rate_limited", "rate_limited"))
        self.assertEqual((len(router.requests), res["request"]["requests_sent"]), (4, 4))
        self.assertEqual(len(sleeps), 2)

    def test_no_retry_when_the_wait_is_long_or_unreadable_or_the_error_is_not_429(self):
        for answer in (http_error(429, headers={"Retry-After": "60"}), http_error(429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}), http_error(401), http_error(500)):
            with self.subTest(code=answer.code, retry_after=answer.headers.get("Retry-After")):
                sleeps = []
                router = Router(token=[answer, FakeResponse(body_of(token_fixture()))])
                res = collect(router, sleeps=sleeps)
                self.assertEqual((res["token_risk"]["attempts"], router.count(TOKEN_PATH), sleeps), (1, 1, []))


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
        patcher = mock.patch.object(st, "TIMEOUT_S", self.DEADLINE)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.stop.set)

    def test_drip_feeds_on_both_requests_end_at_one_deadline(self):
        router = Router(token=[lambda: DripResponse(self.stop)], bundlers=[lambda: DripResponse(self.stop)])
        started = time.monotonic()
        res = collect(router)
        took = time.monotonic() - started
        self.assertEqual((res["status"], res["token_risk"]["reason"], res["bundlers"]["reason"]), ("unavailable", "timeout", "timeout"))
        self.assertLess(took, self.DEADLINE + self.MARGIN, "the two requests run at the same time, each under its own hard deadline")

    def test_a_stalled_open_ends_at_the_deadline(self):
        def stall():
            self.stop.wait(3.0)
            raise OSError("released")

        router = Router(token=[stall])
        started = time.monotonic()
        res = collect(router)
        self.assertEqual((res["token_risk"]["reason"], res["bundlers"]["status"]), ("timeout", "ok"))
        self.assertLess(time.monotonic() - started, self.DEADLINE + self.MARGIN)


class StatusAndGuardTests(unittest.TestCase):
    def test_live_cape_answers(self):
        res = collect(Router())
        self.assertEqual(st.status_line(res), "ok (token risk: ok; bundlers: ok; 2 Solana Tracker requests)")
        self.assertEqual(res["token_risk"]["identity"], "confirmed")
        n = {k: (v["value"] if isinstance(v, dict) else v) for k, v in res["numbers"].items()}
        self.assertEqual((n["bundlers_list_wallets"], n["bundlers_risk_wallets"], n["snipers_wallets"], n["insiders_wallets"], n["holder_count"]), (54, 54, 0, 0, 1520))
        self.assertAlmostEqual(n["bundlers_list_pct"], 0.008009932, places=6)
        self.assertEqual((n["bundlers_list_initial_pct"], n["bundlers_risk_pct"], n["bundlers_risk_initial_pct"], n["top10_pct"], n["dev_pct"], n["risk_score"], n["rugged"]),
                         (0.25858, 0.008, 0.2544, 4.8543, 0.0, 0.0, False))
        self.assertEqual(n["bundlers_list_pct_basis"], "total share held now")
        self.assertEqual(len(res["bundlers"]["wallets"]), 54)
        self.assertEqual(set(res["bundlers"]["wallets"][0]), {"wallet", "percentage", "initialPercentage", "bundleTime"})

    def guarded(self, token=None, bundlers=None):
        t, b = token_fixture(), bundlers_fixture()
        if token:
            token(t)
        if bundlers:
            bundlers(b)
        return collect(Router([FakeResponse(body_of(t))], [FakeResponse(body_of(b))]))

    def test_token_part_guards(self):
        cases = {
            "risk_missing": lambda t: t.pop("risk"),
            "risk_fields_missing": lambda t: t.update(risk={"snipersInfo": {}, "insidersInfo": {}, "bundlersInfo": {}, "top10Holders": 4.8, "score": 0}),
            "identity_mismatch": lambda t: t["token"].update(mint=SPACE),
            "invalid_shape": None,
        }
        for reason, change in cases.items():
            with self.subTest(reason):
                res = self.guarded(token=change) if change else collect(Router([FakeResponse(b"[1, 2]")]))
                self.assertEqual((res["token_risk"]["status"], res["token_risk"]["reason"]), ("unavailable", reason))
                self.assertEqual(res["status"], "ok", "the bundlers part was still read")
                self.assertIsNone(res["numbers"]["snipers_pct"]["value"])
                self.assertIn(f"token risk unavailable: {reason}", res["numbers"]["snipers_pct"]["not_read"], "not read, never 0")

    def test_bundlers_part_guards(self):
        def rename_list(b):
            b["bundlerWallets"] = b.pop("wallets")

        def rename_shares(b):
            b.pop("percentage")
            for w in b["wallets"]:
                w["share"] = w.pop("percentage")

        res = self.guarded(bundlers=rename_list)
        self.assertEqual((res["bundlers"]["status"], res["bundlers"]["reason"]), ("unavailable", "bundler_list_missing"))
        res = self.guarded(bundlers=rename_shares)
        self.assertEqual((res["bundlers"]["status"], res["bundlers"]["reason"]), ("unavailable", "bundler_share_field_missing"))
        self.assertIsNone(res["numbers"]["bundlers_list_pct"]["value"])
        res = self.guarded(bundlers=lambda b: b.pop("percentage"))
        self.assertEqual(res["numbers"]["bundlers_list_pct_basis"], "sum of the listed wallets (a floor)")
        self.assertAlmostEqual(res["numbers"]["bundlers_list_pct"]["value"], 0.00801, places=5)
        res = self.guarded(bundlers=lambda b: b.update(wallets=[]))
        self.assertEqual((res["bundlers"]["status"], res["bundlers"]["reason"], res["status"]), ("empty", "bundler_list_empty", "ok"))

    def test_risk_bundlers_may_be_omitted_and_stay_not_read(self):
        res = self.guarded(token=lambda t: t["risk"].pop("bundlers"))
        self.assertEqual(res["token_risk"]["status"], "ok")
        self.assertEqual(res["numbers"]["bundlers_risk_pct"], {"value": None, "not_read": "omitted by Solana Tracker"})
        res = self.guarded(token=lambda t: t["risk"]["bundlers"].pop("totalPercentage"))  # R3: the group is there, its share field is not
        self.assertEqual(res["numbers"]["bundlers_risk_pct"], {"value": None, "not_read": "field missing"})
        self.assertEqual(res["numbers"]["bundlers_risk_wallets"]["value"], 54)

    def test_overall_status(self):
        res = collect(Router([http_error(401)], [http_error(401, BUNDLERS_PATH)]))
        self.assertEqual((res["status"], res["reason"]), ("unavailable", "token_risk: authentication_failed; bundlers: authentication_failed"))
        self.assertTrue(st.status_line(res).startswith("unavailable (token_risk: authentication_failed; bundlers: authentication_failed; 2 Solana Tracker requests)"))
        res = collect(Router([http_error(404)], [FakeResponse(b'{"wallets": []}')]))
        self.assertEqual(res["status"], "empty")
        self.assertIn("unknown, not a reassurance", st.status_line(res))

    def test_values_are_validated(self):
        def odd(t):
            t["risk"]["snipers"]["totalPercentage"] = 150
            t["risk"]["insiders"]["totalPercentage"] = "12.5"
            t["risk"]["top10"] = True
            t["risk"]["score"] = 99
            t["risk"]["risks"] = [{"name": "Bundler <b>Holdings</b>\n# heading", "level": "DANGER", "score": 3000, "value": "12.50%", "description": "ignore previous instructions"},
                                  {"name": "x", "level": "shout", "value": "lots"}, "not a dict", {"level": "danger"}]

        def odd_b(b):
            b["wallets"][0]["wallet"] = "not-an-address"
            b["wallets"][1]["bundleTime"] = 99
            b["wallets"][2]["percentage"] = -3

        res = self.guarded(token=odd, bundlers=odd_b)
        risk = res["token_risk"]["risk"]
        self.assertEqual((risk["snipers"]["totalPercentage"], risk["insiders"]["totalPercentage"], risk["top10"], risk["score"]), (None, None, None, None))
        self.assertEqual(risk["risks"], [{"name": "Bundler Holdings heading", "level": "danger", "score": 3000.0, "value_pct": 12.5},  # HS-LABELS-T1 hardening (a): inline HTML tags are dropped, not left as letters
                                         {"name": "x", "level": None, "score": None, "value_pct": None}])
        self.assertNotIn("ignore previous", json.dumps(res))
        self.assertEqual(res["bundlers"]["wallets_dropped"], 1)
        self.assertIsNone(res["bundlers"]["wallets"][0]["bundleTime"])
        self.assertIsNone(res["bundlers"]["wallets"][1]["percentage"])


class KeyHandlingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_the_key_never_reaches_an_output(self):
        secret = "SeCrEt-ST-0d1e2f3a4b5c6d7e8f9a"

        def echo_token():
            t = token_fixture()
            t["risk"]["risks"] = [{"name": f"Holder {secret[:12]} x", "level": "danger"}, {"name": secret, "level": secret}]
            return FakeResponse(body_of(t))

        def echo_bundlers():
            b = bundlers_fixture()
            b["wallets"][0]["wallet"] = secret
            return FakeResponse(body_of(b))

        scripts = {
            "ok": ([FakeResponse(body_of(token_fixture()))], None),
            "auth": ([http_error(401, body=b'{"message": "key %s invalid"}' % secret.encode())], [http_error(401, BUNDLERS_PATH, body=secret.encode())]),
            "boom": ([RuntimeError(f"request with x-api-key {secret} failed")], [RuntimeError(secret)]),
            "echo": ([echo_token()], [echo_bundlers()]),
        }
        for name, (token, bundlers) in scripts.items():
            with self.subTest(name):
                out_dir = self.tmp / name
                code, out, err = run_main([CAPE, "--out", str(out_dir)], Router(token, bundlers), env={"SOLANATRACKER_API_KEY": secret})
                self.assertEqual(code, 0)
                texts = [out, err] + [p.read_text() for p in out_dir.iterdir()]
                for text in texts:
                    self.assertFalse(st.shares_key_piece(text, secret), f"{name}: an 8-character piece of the key reached an output")
                present_out = io.StringIO()
                with contextlib.redirect_stdout(present_out):
                    st.main(["--present", str(out_dir)])
                self.assertFalse(st.shares_key_piece(present_out.getvalue(), secret))

    def test_single_variable_loader(self):
        env = self.tmp / ".env"
        env.write_text("# comment\nOTHER_VALUE=abc123456789\nSOLANATRACKER_API_KEY_OLD=zzzzzzzzzzzz\nexport SOLANATRACKER_API_KEY='from-file-0123456789'  \nSOLANATRACKER_API_KEY=second-line-ignored\n")
        base = {k: v for k, v in os.environ.items() if k != "SOLANATRACKER_API_KEY"}
        with mock.patch.dict(os.environ, base, clear=True):
            self.assertEqual(st.load_key(env), ("from-file-0123456789", None))
            self.assertEqual(st.load_key(None), (None, "missing_key"))
            env.write_text("SOLANATRACKER_API_KEY=has a space inside\n")
            self.assertEqual(st.load_key(env), (None, "key_format"))
            self.assertEqual(st.load_key(self.tmp / "missing.env"), (None, "env_file_unreadable"))
        with mock.patch.dict(os.environ, base | {"SOLANATRACKER_API_KEY": "from-environment-123"}, clear=True):
            self.assertEqual(st.load_key(env), ("from-environment-123", None), "the environment wins over the file")

    def test_env_file_lookup_order_and_no_lookup_when_the_environment_has_the_key(self):
        explicit, setting = self.tmp / "a.env", self.tmp / "b.env"
        explicit.write_text("X=1\n")
        setting.write_text("X=1\n")
        with mock.patch.dict(os.environ, {"HOLDER_FORENSICS_ENV": str(setting)}):
            self.assertEqual(st.find_env_file(str(explicit)), explicit)
            self.assertEqual(st.find_env_file(None), setting)
        with mock.patch.object(st, "find_env_file", side_effect=AssertionError("must not look for a .env")):
            code, out, _ = run_main([CAPE, "--out", str(self.tmp / "run")], Router())
        self.assertEqual(code, 0, out)

    def test_missing_key_sends_nothing(self):
        router = Router()
        code, out, _ = run_main([CAPE, "--out", str(self.tmp / "run"), "--env-file", str(self.tmp / "none.env")], router, env={})
        self.assertEqual((code, router.requests), (0, []))
        self.assertEqual(out.strip(), "unavailable (missing_key; no Solana Tracker request sent)")


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
        with mock.patch.object(st, "load_key", side_effect=refuse), mock.patch.object(st, "find_env_file", side_effect=refuse), \
             mock.patch.object(st, "default_opener", side_effect=refuse), mock.patch.object(socket, "create_connection", refuse), \
             mock.patch.object(socket.socket, "connect", refuse), contextlib.redirect_stdout(out):
            code = st.main(["--present", str(self.tmp)])
        self.assertEqual(code, 0)
        self.assertIn("Solana Tracker (collector solanatracker): read", out.getvalue())


class PresentTests(unittest.TestCase):
    """The synthesis's block: what Solana Tracker read, what it cannot see, and the late-source line at the bars."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def lines(self, mutate=None, name="run"):
        run = self.tmp / name
        write_result(run, mutate)
        return st.present(run)

    def test_live_cape_block_has_no_late_source_line_and_is_never_an_all_clear(self):
        lines = self.lines()
        text = "\n".join(lines)
        self.assertEqual(lines[0].split(";")[0], "Solana Tracker (collector solanatracker): read")
        for needle in ("bundlers now (bundlers list, total share held now): 0.008009% of supply, 54 wallets; bought 0.2585% at launch",
                       "bundlers now (token risk object): 0.008% of supply, 54 wallets; bought 0.2544% at launch", "snipers: 0% of supply, 0 wallets",
                       "insiders: 0% of supply, 0 wallets", "top 10 holders: 4.854% of supply", "holder count: 1520", "cannot see: its own bundler, sniper and insider definitions",
                       "a low number is not an all-clear", "never count toward NO_ALARM"):
            self.assertIn(needle, text)
        self.assertNotIn(LATE, text)
        self.assertIsNone(FLAG_WORDS.search(text), "the presenter never writes a FLAG")
        self.assertIsNone(REASSURING.search(text.replace("a low number is not an all-clear", "")))

    def test_bundler_share_at_or_over_the_bundles_bar_gives_the_late_source_line(self):
        def at(value):
            return lambda t, b: b.update(percentage=value)

        self.assertIn(f"{LATE}: bundlers hold 38.4% of supply (bundlers list) (Solana Tracker's own definition; bar: bundles 30%+ BUNDLE_ALARM_PCT)", self.lines(at(38.4), "high"))
        self.assertTrue(any(line.startswith(LATE) for line in self.lines(at(hf.BUNDLE_ALARM_PCT), "at-bar")), "at the bar counts")
        self.assertFalse(any(line.startswith(LATE) for line in self.lines(at(29.99), "under")), "under the bar adds nothing")

    def test_the_token_risk_bundler_share_is_checked_too(self):
        lines = self.lines(lambda t, b: t["risk"]["bundlers"].update(totalPercentage=31.0), "risk-bundlers")
        self.assertIn(f"{LATE}: bundlers hold 31% of supply (token risk object) (Solana Tracker's own definition; bar: bundles 30%+ BUNDLE_ALARM_PCT)", lines)

    def test_insiders_are_one_linked_group_checked_against_the_largest_cluster_bar(self):
        """R1 (Architect decision): insiders are one linked group, i.e. a cluster: the line appears at 15% or more."""
        def insiders(value):
            return lambda t, b: t["risk"]["insiders"].update(totalPercentage=value, count=12)

        self.assertEqual(hf.CLUSTER_ALARM_PCT, 15.0)
        under = self.lines(insiders(14.999), "insiders-under")
        self.assertFalse(any(line.startswith(LATE) for line in under), "14.999% shows no line")
        self.assertIn("  insiders: 14.99% of supply, 12 wallets", under, "shown cut toward zero, never rounded up to the bar")
        self.assertIn(f"{LATE}: insiders hold 15% of supply (one linked group) (Solana Tracker's own definition; bar: largest cluster 15%+ CLUSTER_ALARM_PCT)",
                      self.lines(insiders(15.0), "insiders-at"))
        self.assertIn(f"{LATE}: insiders hold 30% of supply (one linked group) (Solana Tracker's own definition; bar: largest cluster 15%+ CLUSTER_ALARM_PCT)",
                      self.lines(insiders(30.0), "insiders-over"))

    def test_numbers_are_shown_cut_toward_zero_never_rounded_up(self):
        cases = {14.999: "14.99", 29.9999: "29.99", 30.0: "30", 15.0: "15", 38.4: "38.4", 0.29: "0.29", 0.008009932257726822: "0.008009", 0.25858: "0.2585",
                 4.8543: "4.854", 0.0: "0", 100.0: "100", 1520: "1520", 0.00001234: "1.234e-05"}
        for value, text in cases.items():
            with self.subTest(value=value):
                self.assertEqual(st._fmt(value), text)

    def test_numbers_without_a_matching_bar_are_only_shown(self):
        def big(t, b):
            t["risk"]["snipers"]["totalPercentage"] = 90.0
            t["risk"]["dev"]["percentage"] = 50
            t["risk"]["top10"] = 80.0
            b["initialPercentage"] = 60.0

        lines = self.lines(big, "big")
        self.assertFalse(any(line.startswith(LATE) for line in lines))
        self.assertIn("  snipers: 90% of supply, 0 wallets", lines)

    def test_unread_numbers_are_not_read_never_zero(self):
        run = self.tmp / "partial"
        res = collect(Router([http_error(401)]))
        run.mkdir()
        (run / st.OUT_FILE).write_text(json.dumps(res))
        text = "\n".join(st.present(run))
        self.assertIn("snipers: not read (token risk unavailable: authentication_failed)", text)
        self.assertIn("holder count: not read (token risk unavailable: authentication_failed)", text)
        self.assertNotIn("snipers: 0", text)

    def test_missing_or_foreign_file_is_not_read(self):
        empty = self.tmp / "empty"
        empty.mkdir()
        self.assertEqual(st.present(empty)[0], "Solana Tracker: not read (solanatracker.json missing)")
        (empty / st.OUT_FILE).write_text(json.dumps({"schema": "something-else", "status": "ok", "numbers": {"bundlers_list_pct": {"value": 99}}}))
        lines = st.present(empty)
        self.assertEqual(lines[0], "Solana Tracker: not read (solanatracker.json unreadable)")
        self.assertFalse(any(line.startswith(LATE) for line in lines))

    def test_bundler_numbers_side_by_side_never_averaged(self):
        run = self.tmp / "side"
        write_result(run, lambda t, b: b.update(percentage=14.5))
        def gmgn_file(bundlers):
            gmgn = gr.collect_gmgn_rows(CAPE, "dummy-gmgn-key-7f3a9c41e2b8d6", opener=_GmgnOpener(bundlers), now=lambda: 1_792_400_000, sleep=lambda s: None,
                                        monotonic=lambda: 0.0, new_client_id=lambda: "11111111-2222-4333-8444-555555555555")
            (run / gr.TOP100_FILE).write_text(json.dumps(gmgn))
            return gmgn

        self.assertIn("GMGN tags no bundler in its top 100 (its claim; not an all-clear)", (gmgn_file(0), st.present(run)[-1])[1])
        gmgn = gmgn_file(5)
        jup = jr.collect_jupiter_rows(CAPE, opener=_JupOpener(), now=lambda: 1_792_400_000)
        (run / jr.OUT_FILE).write_text(json.dumps(jup))
        line = st.present(run)[-1]
        b = gmgn["tag_claims"]["maker_token_tags"]["bundler"]
        self.assertTrue(line.startswith("bundler share by provider (each its own definition and window; named side by side, never averaged): "))
        self.assertIn(f"GMGN claims bundler on {b['wallets']} wallets, {st._fmt(float(b['share_pct']))}% of supply (top 100)", line)
        self.assertIn("Jupiter tags no bundler in its top 100 (its claim; not an all-clear)", line)
        self.assertIn("Solana Tracker bundlers list: 14.5% of supply", line)
        self.assertNotIn("average", line.replace("never averaged", ""))
        (run / gr.TOP100_FILE).unlink()
        self.assertIn("GMGN: not read |", st.present(run)[-1])
        jup_pools_only = json.loads((FIX / "cape_jupiter_live_20261019.json").read_text())
        for r in jup_pools_only["holders"]:
            r.pop("holderTags", None)
            r.pop("walletCategories", None)
        with mock.patch.object(jr, "default_opener"):
            res = jr.collect_jupiter_rows(CAPE, opener=_Payload(jup_pools_only), now=lambda: 1_792_400_000)
        (run / jr.OUT_FILE).write_text(json.dumps(res))
        line = st.present(run)[-1]
        self.assertIn("Jupiter: tags unknown (no text tag field in any row)", line, "R4: object-valued pool tags never read as 'Jupiter tags no bundler'")
        self.assertNotIn("Jupiter tags no bundler", line)


class _Payload:
    def __init__(self, payload):
        self.payload = payload

    def open(self, request, timeout=None):
        return FakeResponse(json.dumps(self.payload).encode())


class _GmgnOpener:
    """The real CAPE GMGN payload; with `bundlers` set, that many of its top rows also carry GMGN's bundler tag."""

    def __init__(self, bundlers=0):
        self.bundlers = bundlers

    def open(self, request, timeout=None):
        payload = json.loads((FIX / "cape_gmgn.json").read_text())
        for row in hf._unwrap(payload)[: self.bundlers]:
            row["maker_token_tags"] = sorted(set(row.get("maker_token_tags") or []) | {"bundler"})
        return FakeResponse(json.dumps(payload).encode())


class _JupOpener:
    def open(self, request, timeout=None):
        return FakeResponse((FIX / "cape_jupiter_live_20261019.json").read_bytes())


class PresentationOnlyRuleTests(unittest.TestCase):
    """Solana Tracker never feeds either engine: assess never reads solanatracker.json (a high number never lowers or
    replaces a FLAG, a low one never enables NO_ALARM) and refuses it as --providers-json."""

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
            (run / st.OUT_FILE).unlink()
        self.assertEqual(code, 0, err)
        return before, md_before, after, md_after

    def test_a_high_solanatracker_bundle_share_never_lowers_or_replaces_a_flag(self):
        def high(t, b):
            b["percentage"] = 38.4
            t["risk"]["bundlers"]["totalPercentage"] = 38.4

        before, md_before, after, md_after = self.with_and_without(CAPE, self.cape_run, ["--bubblemaps-json", str(self.cape_map)], high, "cape-high")
        self.assertEqual(after, before)
        self.assertEqual(md_after, md_before)
        self.assertEqual(after["flag"]["label"], hf.FLAG_DANGER, "the engine FLAG stands as written; Solana Tracker only adds a line next to it")
        run = self.tmp / "present-high"
        write_result(run, high)
        self.assertTrue(any(line.startswith(LATE) for line in st.present(run)))

    def test_a_low_solanatracker_number_never_enables_no_alarm(self):
        def low(t, b):
            b["percentage"] = 0.0
            for g in ("snipers", "insiders", "bundlers"):
                t["risk"][g]["totalPercentage"] = 0.0

        for extra, tag in ((["--bubblemaps-json", str(self.space_map)], "space-map"), ([], "space-no-map")):
            with self.subTest(tag):
                before, md_before, after, md_after = self.with_and_without(self.space_mint, self.space_run, extra, low, tag)
                self.assertEqual(after, before)
                self.assertEqual(md_after, md_before)
                self.assertNotIn("solana", json.dumps(after["verdict"]).lower())
        _, _, no_map, _ = self.assess(self.space_mint, self.space_run, [], "space-no-map-check")
        self.assertEqual(no_map["verdict"]["level"], hf.VERDICT_LIMITED, "without the map the level stays LIMITED, whatever Solana Tracker says")

    def test_solanatracker_json_is_refused_as_providers_json(self):
        run = self.tmp / "refuse"
        write_result(run, lambda t, b: b.update(percentage=0.0))
        code, err, _, _ = self.assess(CAPE, self.cape_run, ["--bubblemaps-json", str(self.cape_map), "--providers-json", str(run / st.OUT_FILE)], "refused")
        self.assertEqual(code, 2)
        self.assertIn("--providers-json must hold a JSON list of findings", err)
        self.assertNotIn("providers", json.loads((run / st.OUT_FILE).read_text()), "the file never carries a providers list assess could read")


SYMBOL_KEY = "Ab3/xY9+Qz7=Lm4/Np8+Rt6=Uv2/Wk5"   # a key with characters a label cannot hold
B58_KEY = "HfpLdX35Kc6b7zDNWbe5x1xWLekKUXPYZbmz71vM"  # an address-shaped (base58) key


class KeyEchoHardeningTests(unittest.TestCase):
    """R2: provider text is dropped when its raw form or its label echoes the key (or the key without the characters a
    label cannot hold), and addresses are dropped on any shared 8-character run, not only on equality."""

    def test_a_key_with_slash_plus_equals_echoed_in_a_label_is_dropped(self):
        raw = f"Holder {SYMBOL_KEY[:14]} x"
        label = st.LABEL_RE.sub("", raw)[:32].strip()
        self.assertFalse(st.shares_key_piece(label, SYMBOL_KEY), "the label alone no longer shares a piece of the raw key")
        self.assertIsNone(st.safe_label(raw, SYMBOL_KEY))
        pre_stripped = "Holder " + st.LABEL_RE.sub("", SYMBOL_KEY)[:12]  # the provider already dropped the / + =
        self.assertFalse(st.shares_key_piece(pre_stripped, SYMBOL_KEY))
        self.assertIsNone(st.safe_label(pre_stripped, SYMBOL_KEY))
        t = token_fixture()
        t["risk"]["risks"] = [{"name": raw, "level": "danger"}, {"name": pre_stripped, "level": "warning"}, {"name": "Bundler Holdings", "level": "warning"}]
        res = collect(Router([FakeResponse(body_of(t))]), key=SYMBOL_KEY)
        self.assertEqual([f["name"] for f in res["token_risk"]["risk"]["risks"]], ["Bundler Holdings"])

    def test_an_echo_past_the_label_cut_is_caught_on_the_raw_text(self):
        key = DUMMY_KEY
        raw = "Top 10 Holders own more than xx " + key
        self.assertEqual(len("Top 10 Holders own more than xx "), 32)
        self.assertFalse(st.echoes_key(st.LABEL_RE.sub("", raw)[:32], key))
        self.assertIsNone(st.safe_label(raw, key))

    def test_a_key_interleaved_with_markup_is_caught_on_the_label(self):
        """No 8-character run of the key survives in the raw text, but the label rule removes the markup and rebuilds it."""
        key = DUMMY_KEY
        raw = key[:5] + "<" + key[5:10] + ">" + key[10:15] + "|" + key[15:20]
        self.assertFalse(st.echoes_key(raw, key))
        self.assertTrue(st.echoes_key(st.LABEL_RE.sub("", raw), key))
        self.assertIsNone(st.safe_label(raw, key))

    def test_an_address_shaped_key_with_a_prefix_is_dropped_from_wallet_fields(self):
        echoed = "22" + B58_KEY
        self.assertTrue(st.SOLANA_ADDRESS_RE.fullmatch(echoed) and echoed != B58_KEY, "exact equality would have kept it")
        b = bundlers_fixture()
        b["wallets"][0]["wallet"] = echoed
        res = collect(Router(bundlers=[FakeResponse(body_of(b))]), key=B58_KEY)
        self.assertEqual((len(res["bundlers"]["wallets"]), res["bundlers"]["wallets_dropped"]), (53, 1))
        self.assertFalse(st.shares_key_piece(json.dumps(res), B58_KEY))

    def test_a_partial_piece_of_the_key_in_a_wallet_field_is_dropped(self):
        wallet = CAPE[:20] + B58_KEY[10:20] + CAPE[30:]
        self.assertTrue(st.SOLANA_ADDRESS_RE.fullmatch(wallet))
        self.assertIsNone(st._address(wallet, B58_KEY))
        self.assertEqual(st._address(CAPE, B58_KEY), CAPE)

    def test_real_labels_and_wallets_are_not_dropped(self):
        """No false drops: realistic keys keep every live CAPE bundler wallet and the documented risk factor names."""
        names = ["Freeze Authority Enabled", "Mint Authority Enabled", "Top 10 Holders", "Bundler Holdings", "Dev Holdings", "Snipers", "Insiders",
                 "LP not burned or not locked", "Very Low Liquidity", "Bonding curve not complete", "Suspicious Volume", "No social media"]
        for key in (SYMBOL_KEY, B58_KEY, "sk-live-0f9e8d7c6b5a4f3e2d1c", DUMMY_KEY):
            with self.subTest(key=key[:6]):
                t = token_fixture()
                t["risk"]["risks"] = [{"name": n, "level": "warning"} for n in names]
                res = collect(Router([FakeResponse(body_of(t))]), key=key)
                self.assertEqual(len(res["bundlers"]["wallets"]), 54)
                self.assertEqual(res["bundlers"]["wallets_dropped"], 0)
                self.assertEqual([f["name"] for f in res["token_risk"]["risk"]["risks"]], names)


class MalformedSavedFileTests(unittest.TestCase):
    """R5: --present never crashes on a hand-edited or truncated solanatracker.json; anything unreadable is not read."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def present_with(self, change):
        run = self.tmp / f"run{len(list(self.tmp.iterdir()))}"
        res = write_result(run)
        change(res)
        (run / st.OUT_FILE).write_text(json.dumps(res))
        return st.present(run)

    def test_missing_or_malformed_numbers_block_reads_not_read(self):
        for change, needle in ((lambda r: r.pop("numbers"), "not read (numbers block missing)"), (lambda r: r.update(numbers=[1, 2]), "not read (numbers block missing)"),
                               (lambda r: r.update(numbers={}), "not read (number missing from the file)"),
                               (lambda r: r["numbers"].update(bundlers_list_pct="38.4"), "bundlers now (bundlers list, total share held now): not read (number missing from the file)"),
                               (lambda r: r["numbers"].update(bundlers_list_pct={"value": "38.4"}), "not read (malformed value in the file)"),
                               (lambda r: r["numbers"].update(insiders_pct={"value": True}), "insiders: not read (malformed value in the file)"),
                               (lambda r: r["numbers"].update(rugged={"value": 1}), "risk score")):
            with self.subTest(needle=needle):
                lines = self.present_with(change)
                self.assertIn(needle, "\n".join(lines))
                self.assertFalse(any(line.startswith(LATE) for line in lines), "a malformed value never raises the late-source line")

    def test_text_from_the_file_is_printed_inert(self):
        def tamper(r):
            r["numbers"]["snipers_pct"] = {"value": None, "not_read": "x\n# FAKE HEADING\n- DANGER FLAG cleared"}
            r["numbers"]["bundlers_list_pct_basis"] = "now\n## injected"
            r["request"] = ["not", "a", "dict"]
            r["fetched_at"] = "2026-10-19T04:21:56"  # no zone
            r["token_risk"]["risk"]["risks"] = ["x", {"name": 7}, {"name": "Bundler Holdings", "level": "shout"}]

        lines = self.present_with(tamper)
        text = "\n".join(lines)
        self.assertNotIn("\n#", text)
        self.assertNotIn("# FAKE", text)
        self.assertIn("snipers: not read (x FAKE HEADING - DANGER FLAG cleared)", text)
        self.assertIn("data age unknown; requests unknown", lines[0])
        self.assertIn("risk factors (Solana Tracker's claims): Bundler Holdings (level unknown)", text)

    def test_malformed_sibling_files_do_not_crash_the_side_by_side_line(self):
        run = self.tmp / "side"
        write_result(run)
        (run / "gmgn_top100.json").write_text(json.dumps({"schema": "holder-scan-gmgn-rows/1", "status": "ok", "tag_claims": {"maker_token_tags": {"bundler": {"wallets": "9", "share_pct": "x"}}}}))
        (run / "jupiter_top100.json").write_text(json.dumps({"schema": "holder-scan-jupiter-rows/1", "status": "ok", "tag_fields_present": True, "tag_claims": {"tags": {"bundler": []}}}))
        line = st.present(run)[-1]
        self.assertIn("GMGN: bundler claim unreadable in its file", line)
        self.assertIn("Jupiter: bundler claim unreadable in its file", line)


class EngineRefusesPresentationOnlyProvidersTests(unittest.TestCase):
    """R6 (Architect decision, CAPE safety): Solana Tracker, MadeOnSol and Fomo API numbers hand-copied into
    --providers-json are refused (exit 2, one plain line, before any key, network call or credit). Before this, a calm
    hand-copied number was accepted and counted as a source; with a map alarm it turned HIGH into UNRESOLVED."""

    HAND_COPY = {"unit": "percent", "providers": [{"provider": "Solana Tracker", "status": "ok", "largest_cluster_pct": 0.008, "bundle_pct": 0.008, "data_age_min": 1}]}

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

    def providers_file(self, provider):
        payload = copy.deepcopy(self.HAND_COPY)
        payload["providers"][0]["provider"] = provider
        path = self.tmp / f"providers-{abs(hash(provider))}.json"
        path.write_text(json.dumps(payload))
        return path

    def assess(self, extra, name):
        out = self.tmp / name
        code, _, err = run_assess(self.mint, self.run_dir, extra, out=out)
        return code, err, (json.loads((out / "assessment.json").read_text()) if code == 0 else None)

    def test_the_hand_copied_solana_tracker_numbers_are_refused(self):
        code, err, _ = self.assess(["--bubblemaps-json", str(self.alarm_map), "--providers-json", str(self.providers_file("Solana Tracker"))], "hand-copy")
        self.assertEqual(code, 2)
        self.assertEqual(err.strip(), "error: --providers-json cannot supply Solana Tracker: it is a presentation-only provider, shown by the synthesis next to the FLAGs and never an engine input")
        self.assertEqual(err.strip().count("\n"), 0, "one plain line")

    def test_control_a_calm_provider_would_have_softened_the_map_alarm(self):
        """Why the refusal matters: the same calm numbers under another provider name turn HIGH into UNRESOLVED."""
        code, err, alone = self.assess(["--bubblemaps-json", str(self.alarm_map)], "alone")
        self.assertEqual((code, alone["verdict"]["level"], alone["flag"]["label"]), (0, hf.VERDICT_HIGH, hf.FLAG_DANGER), err)
        code, err, softened = self.assess(["--bubblemaps-json", str(self.alarm_map), "--providers-json", str(self.providers_file("okx"))], "okx")
        self.assertEqual((code, softened["verdict"]["level"]), (0, hf.VERDICT_UNRESOLVED), err)
        self.assertIn("okx", softened["verdict"]["disagreement"]["disagreeing"])

    def test_spellings_are_matched_case_space_and_punctuation_insensitive(self):
        refused = {"Solana Tracker": ["Solana Tracker", "solanatracker", "SOLANA_TRACKER", "solana-tracker", "  Solana   Tracker ", "SolanaTracker (bundlers)", "solana.tracker v2",
                                      "x" * 40 + " Solana Tracker"],
                   "MadeOnSol": ["MadeOnSol", "madeonsol", "Made On Sol", "made_on_sol"],
                   "Fomo API": ["Fomo API", "fomo", "FOMO_api", "fomo-app"]}
        for label, names in refused.items():
            for name in names:
                with self.subTest(name=name):
                    self.assertEqual(hf.presentation_only_provider(name), label)
                    with self.assertRaises(hf.ConfigError) as ctx:
                        hf.normalize_findings_file({"unit": "percent", "providers": [{"provider": name, "status": "ok", "largest_cluster_pct": 0.0}]})
                    self.assertIn(f"cannot supply {label}: it is a presentation-only provider", str(ctx.exception))
        for name in ("okx", "insightx", "gmgn", "cabalspy", "bubblemaps", "jupiter", "rugcheck", None, 7):
            with self.subTest(accepted=name):
                self.assertIsNone(hf.presentation_only_provider(name))
        self.assertEqual([f["provider"] for f in hf.normalize_findings_file({"unit": "percent", "providers": [{"provider": "okx", "status": "ok", "largest_cluster_pct": 1.0}]})], ["okx"])

    def test_the_refusal_names_the_provider_never_echoes_the_raw_name(self):
        with self.assertRaises(hf.ConfigError) as ctx:
            hf.normalize_findings_file([{"provider": "Solana Tracker\n# <b>injected</b>", "status": "ok", "largest_cluster_pct": 0.0, "unit": "percent"}])
        self.assertNotIn("injected", str(ctx.exception))
        self.assertNotIn("\n", str(ctx.exception))

    def test_report_refuses_before_any_key_network_call_or_credit(self):
        def refuse(*_a, **_k):
            raise AssertionError("key, network or credit before the input check")

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(hf, "Helius", side_effect=refuse), mock.patch.object(hf, "load_key", side_effect=refuse), mock.patch.object(hf, "find_env_file", side_effect=refuse), \
             mock.patch.object(hf, "dexscreener_pairs", side_effect=refuse), mock.patch.object(hf, "run_holders", side_effect=refuse), \
             mock.patch.object(socket, "create_connection", refuse), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = hf.main(["report", self.mint, "--top", "1", "--providers-json", str(self.providers_file("Fomo API"))])
        self.assertEqual(code, 2)
        self.assertEqual(err.getvalue().strip(), "error: --providers-json cannot supply Fomo API: it is a presentation-only provider, shown by the synthesis next to the FLAGs and never an engine input")


class SelfContainedTests(unittest.TestCase):
    def test_standard_library_one_key_name_no_personal_paths(self):
        text = (SCRIPTS / "solanatracker.py").read_text()
        modules = set()
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Import):
                modules |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
        self.assertEqual(sorted(modules - set(sys.stdlib_module_names) - {"__future__", "helius_forensics", "provider_words"}), [])  # HS-LABELS-T1: the shared verdict-word rule
        self.assertEqual(set(re.findall(r"\b[A-Z][A-Z0-9_]*_(?:KEY|SECRET|TOKEN|PASSWORD)\b", text)), {"SOLANATRACKER_API_KEY"})
        self.assertNotIn("/Users/", text)
        self.assertNotIn("/Users/", Path(__file__).read_text().replace('"/Users/"', ""))


if __name__ == "__main__":
    unittest.main()
