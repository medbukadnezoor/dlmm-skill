"""DS-FEETVL-T1: the first-wave collector `lpagent_pools` (exactly one LP Agent /pools/discover request per scan, the
cross-check of the Meteora fee/TVL numbers). Offline: a counting fake opener, dummy keys only, the live answers of
2026-10-25 saved as fixtures in tests/forensics/fixtures/fee_tvl/ (response bodies only, no request headers).

Covers the ticket's acceptance criteria 6 and 7: exactly one request per run, plus at most one retry and only after a 429,
after waiting at least 12.5 s (counted with a mocked opener); no key -> status not ok "LPAGENT_API_KEY not set", exit 0, no
request; 401 / 403 / a 429 after the retry -> not ok, exit 0; the key never reaches the output, the saved file, an error or
a fixture. Plus the request (host, path, query, the x-api-key header and a User-Agent, no proxy, no redirects, bounds), the
single-variable key loader, and the live answer parsed (numbers sent as text, ISO times, exact mint rows only)."""

from __future__ import annotations

import contextlib
import email.message
import io
import json
import os
import re
import shutil
import socket
import sys
import tempfile
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

import lpagent_pools as lp  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "fee_tvl"
MINT_TOKEN = "tybY2LFHH91VdoPJJkkFAsYaD7wnQQAm3BYg1x3mint"
BILLIONS = "9uNgkUWsRDCMsnE6UX9aJ9bCwj3Lw3pjTU4TnMEnpump"
SOL = "So11111111111111111111111111111111111111112"
DUMMY_KEY = "lp-dummy-key-7c41e9a0b2d35f68"
QUERY = f"search={MINT_TOKEN}&platform=meteora&pageSize=20&min_liquidity=1000&sortBy=tvl"
NOW = 1_792_915_702.0  # 2026-10-25T08:08:22Z, when the mint answer was read


def fixture(name: str) -> bytes:
    return (FIX / name).read_bytes()


def mint_body() -> bytes:
    return fixture("lpagent_discover_mint_live_20261025.json")


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200):
        self._buf, self.status = io.BytesIO(body), status

    def read(self, n=-1):
        return self._buf.read(n)

    def close(self):
        pass


def http_error(code, headers=None):
    msg = email.message.Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError(f"https://{lp.HOST}{lp.DISCOVER_PATH}", code, "error", msg, io.BytesIO(b'{"message": "nope"}'))


class CountingOpener:
    """Counts every request opened; answers from a list."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def collect(answers, key=DUMMY_KEY, sleeps=None, mint=MINT_TOKEN):
    sleeps = [] if sleeps is None else sleeps
    opener = CountingOpener(answers)
    res = lp.collect_lpagent_pools(mint, key, opener=opener, now=lambda: NOW, monotonic=time.monotonic, sleep=sleeps.append)
    return res, opener


class TempDir(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_main(self, argv, opener, env=None):
        out, err = io.StringIO(), io.StringIO()
        base = {k: v for k, v in os.environ.items() if k not in ("LPAGENT_API_KEY", "HOLDER_FORENSICS_ENV")}
        env = {"LPAGENT_API_KEY": DUMMY_KEY} if env is None else env
        sleeps = []
        with mock.patch.dict(os.environ, base | env, clear=True), mock.patch.object(lp, "default_opener", return_value=opener), \
             mock.patch.object(lp, "find_env_file", return_value=None), mock.patch.object(lp.time, "sleep", side_effect=sleeps.append), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = lp.main(argv)
        return code, out.getvalue(), err.getvalue(), sleeps


# ----------------------------------------------------------------------------- the request


class RequestTests(unittest.TestCase):
    def test_one_documented_get_with_the_key_in_x_api_key_only(self):
        res, opener = collect([FakeResponse(mint_body())])
        self.assertEqual((res["status"], len(opener.requests), res["request"]["requests_sent"]), ("ok", 1, 1))
        request, timeout = opener.requests[0]
        url = urllib.parse.urlparse(request.full_url)
        self.assertEqual((url.scheme, url.hostname, url.port, url.path, url.query), ("https", "api.lpagent.io", None, "/open-api/v1/pools/discover", QUERY))
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(dict(request.header_items()), {"x-api-key": DUMMY_KEY, "Accept": "application/json", "User-agent": lp.USER_AGENT})
        self.assertEqual(timeout, lp.TIMEOUT_S)
        self.assertEqual(res["request"]["auth_header_names"], ["x-api-key"])
        self.assertNotIn(DUMMY_KEY, json.dumps(res))

    def test_default_opener_ignores_env_proxies_and_refuses_redirects(self):
        with mock.patch.dict(os.environ, {"https_proxy": "http://proxy.invalid:3128", "HTTPS_PROXY": "http://proxy.invalid:3128"}):
            opener = lp.default_opener()
        self.assertFalse(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in opener.handlers))
        self.assertTrue(any(isinstance(h, lp.NoRedirect) for h in opener.handlers))

    def test_only_the_allowlisted_https_host_path_and_query(self):
        path = lp.DISCOVER_PATH
        for url in (f"http://api.lpagent.io{path}?{QUERY}", f"https://api.lpagent.io.evil.example{path}?{QUERY}", f"https://api.lpagent.io:8443{path}?{QUERY}",
                    f"https://u:p@api.lpagent.io{path}?{QUERY}", f"https://api.lpagent.io{path}", f"https://api.lpagent.io{path}?{QUERY}&page=2",
                    f"https://api.lpagent.io/open-api/v1/pools/{MINT_TOKEN}/top-lpers", f"https://api.lpagent.io{path}?{QUERY.replace(MINT_TOKEN, BILLIONS)}",
                    "https://api.lpagent.io/open-api/v1/lp-positions/historical"):
            with self.subTest(url), self.assertRaises(lp.Failure):
                lp.check_url(url, MINT_TOKEN)


# ----------------------------------------------------------------------------- 6: exactly one request, the one retry


class OneRequestTests(TempDir):
    def test_exactly_one_request_per_run(self):
        opener = CountingOpener([FakeResponse(mint_body()), FakeResponse(mint_body())])
        code, out, _, sleeps = self.run_main([MINT_TOKEN, "--out", str(self.tmp)], opener)
        self.assertEqual((code, len(opener.requests), sleeps), (0, 1, []))
        self.assertEqual(out.strip(), "ok (3 LP Agent pools of this token; 1 LP Agent request)")

    def test_one_retry_only_after_a_429_and_only_after_at_least_12_5_s(self):
        for headers, wait in ((None, 12.5), ({"Retry-After": "3"}, 12.5), ({"Retry-After": "20"}, 20.0), ({"Retry-After": "30"}, 30.0)):
            with self.subTest(headers=headers):
                sleeps = []
                res, opener = collect([http_error(429, headers), FakeResponse(mint_body())], sleeps=sleeps)
                self.assertEqual((res["status"], len(opener.requests), sleeps, res["request"]["requests_sent"], res["request"]["waited_s"]), ("ok", 2, [wait], 2, wait))
                self.assertGreaterEqual(sleeps[0], lp.RETRY_MIN_WAIT_S)
        sleeps = []
        res, opener = collect([http_error(429), http_error(429), FakeResponse(mint_body())], sleeps=sleeps)
        self.assertEqual((res["status"], res["reason"], len(opener.requests), sleeps), ("unavailable", "rate_limited", 2, [12.5]))
        for headers in ({"Retry-After": "120"}, {"Retry-After": "soon"}):  # longer than 30 s, or unreadable: no retry
            with self.subTest(headers=headers):
                res, opener = collect([http_error(429, headers), FakeResponse(mint_body())])
                self.assertEqual((res["status"], res["reason"], len(opener.requests)), ("unavailable", "rate_limited", 1))

    def test_no_retry_on_any_other_failure(self):
        for answer, reason, status in ((http_error(401), "authentication_failed", 401), (http_error(403), "access_denied", 403), (http_error(500), "server_error", 500),
                                       (http_error(503), "service_unavailable", 503), (FakeResponse(b"", status=502), "server_error", 502), (http_error(404), "not_found", 404),
                                       (http_error(302), "redirect_disallowed", 302), (socket.timeout(), "timeout", None),
                                       (urllib.error.URLError(OSError("refused")), "network_error", None), (RuntimeError(f"boom {DUMMY_KEY}"), "network_error", None),
                                       (FakeResponse(b"<html>"), "invalid_json", 200)):
            with self.subTest(reason=reason):
                sleeps = []
                res, opener = collect([answer, FakeResponse(mint_body())], sleeps=sleeps)
                self.assertEqual((res["status"], res["reason"], res["http_status"], len(opener.requests), sleeps), ("unavailable", reason, status, 1, []))
                self.assertNotIn(DUMMY_KEY, json.dumps(res))
        with mock.patch.object(lp, "MAX_BYTES", 1000):
            res, _ = collect([FakeResponse(mint_body())])
        self.assertEqual(res["reason"], "response_too_large")

    def test_401_403_and_429_after_the_retry_exit_0_with_the_file_saved(self):
        for answers, line in (([http_error(401)], "unavailable (authentication_failed; 1 LP Agent request)"),
                              ([http_error(403)], "unavailable (access_denied; 1 LP Agent request)"),
                              ([http_error(429), http_error(429)], "unavailable (rate_limited; 2 LP Agent requests)")):
            with self.subTest(line):
                opener = CountingOpener(answers)
                code, out, err, _ = self.run_main([MINT_TOKEN, "--out", str(self.tmp)], opener)
                self.assertEqual((code, out.strip(), err), (0, line, ""))
                saved = json.loads((self.tmp / lp.OUT_FILE).read_text())
                self.assertEqual((saved["status"], saved["presentation_only"]), ("unavailable", True))

    def test_no_key_means_no_request_and_exit_0(self):
        opener = CountingOpener([FakeResponse(mint_body())])
        code, out, err, _ = self.run_main([MINT_TOKEN, "--out", str(self.tmp)], opener, env={})
        self.assertEqual((code, out.strip(), err, opener.requests), (0, "unavailable (LPAGENT_API_KEY not set; no LP Agent request sent)", "", []))
        saved = json.loads((self.tmp / lp.OUT_FILE).read_text())
        self.assertEqual((saved["status"], saved["reason"], saved["request"]["requests_sent"]), ("unavailable", "LPAGENT_API_KEY not set", 0))
        res, opener = collect([FakeResponse(mint_body())], key=None)
        self.assertEqual((res["reason"], opener.requests), ("LPAGENT_API_KEY not set", []))

    def test_bad_command_lines_exit_2_and_send_nothing(self):
        opener = CountingOpener([])
        for argv in (["not-a-mint", "--out", str(self.tmp)], [MINT_TOKEN], []):
            with self.subTest(argv=argv):
                code, _, _, _ = self.run_main(argv, opener)
                self.assertEqual(code, 2)
        self.assertEqual(opener.requests, [])

    def test_the_collector_reads_no_file_of_the_run_folder(self):
        for name in ("holders.json", "meteora_pools.json"):
            (self.tmp / name).write_text("{poison")
        code = (SCRIPTS / "lpagent_pools.py").read_text(encoding="utf-8")
        collect_code = code.split("def collect_lpagent_pools(", 1)[1].split("\ndef ", 1)[0]
        for needle in ("holders.json", "meteora_pools", "read_text", "open("):
            self.assertNotIn(needle, collect_code, needle)
        opener = CountingOpener([FakeResponse(mint_body())])
        self.assertEqual(self.run_main([MINT_TOKEN, "--out", str(self.tmp)], opener)[0], 0)
        self.assertEqual((self.tmp / "holders.json").read_text(), "{poison")


# ----------------------------------------------------------------------------- 7: the key never leaves the header


class KeyTests(TempDir):
    def write_env(self, text: str) -> Path:
        path = self.tmp / ".env"
        path.write_text(text)
        return path

    def test_the_single_variable_loader(self):
        env = self.write_env("HELIUS_API_KEY=helius-secret-value-1\nexport LPAGENT_API_KEY='lp-from-env-file-0123456789'\nOTHER=1\n")
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(lp.load_key(env), ("lp-from-env-file-0123456789", None))
            self.assertEqual(lp.load_key(self.write_env("# LPAGENT_API_KEY=commented\n")), (None, "LPAGENT_API_KEY not set"))
            self.assertEqual(lp.load_key(self.write_env("LPAGENT_API_KEY=has space inside\n")), (None, "key_format"))
            self.assertEqual(lp.load_key(self.write_env("LPAGENT_API_KEY=lp-value-12345678 # note\n")), ("lp-value-12345678", None))
            self.assertEqual(lp.load_key(None), (None, "LPAGENT_API_KEY not set"))
        with mock.patch.dict(os.environ, {"LPAGENT_API_KEY": "lp-from-environment-99"}, clear=True):
            self.assertEqual(lp.load_key(env), ("lp-from-environment-99", None), "the environment comes first")

    def test_the_key_never_reaches_stdout_stderr_the_file_or_an_error(self):
        scenarios = [[FakeResponse(mint_body())], [http_error(401)], [http_error(429), http_error(429)], [RuntimeError(f"failed with {DUMMY_KEY}")],
                     [FakeResponse(json.dumps({"status": "success", "data": [{"pool": DUMMY_KEY, "token0": MINT_TOKEN}]}).encode())]]
        for answers in scenarios:
            with self.subTest(len(answers)):
                code, out, err, _ = self.run_main([MINT_TOKEN, "--out", str(self.tmp)], CountingOpener(answers))
                saved = (self.tmp / lp.OUT_FILE).read_text()
                for text in (out, err, saved):
                    self.assertFalse(lp.shares_key_piece(text, DUMMY_KEY), text[:200])
                self.assertEqual(code, 0)

    def test_an_address_echoing_the_key_is_dropped(self):
        key = "5ZhTr1x7Ue9GmP2vQ3kLmNaBcD8EfG4h"  # a key that is itself valid base58, echoed as the pool address
        payload = json.loads(mint_body())
        payload["data"][0]["pool"] = key
        res, _ = collect([FakeResponse(json.dumps(payload).encode())], key=key)
        self.assertEqual(len(res["pools"]), 2)
        self.assertEqual(res["answer"]["unreadable_rows"], 1)
        self.assertNotIn(key, json.dumps(res))

    def test_the_fixtures_hold_no_key_like_text(self):
        pattern = re.compile(r"(?i)api-key|apikey|api_key=|bearer|x-api-key:")
        for path in sorted(FIX.glob("*.json")):
            with self.subTest(path.name):
                self.assertIsNone(pattern.search(path.read_text()), path.name)


# ----------------------------------------------------------------------------- parsing the live answer


class ParseTests(unittest.TestCase):
    def test_the_live_answer(self):
        res, _ = collect([FakeResponse(mint_body())])
        self.assertEqual((res["status"], res["answer"]), ("ok", {"rows_in_answer": 3, "other_token_rows_dropped": 0, "unreadable_rows": 0, "total_count": 3}))
        first = res["pools"][1]
        self.assertEqual(first, {"pool": "JvCVyYnvkzJcHBaM8NdrUVhCFnH2R2mWku1v9WFbXxr", "token0": MINT_TOKEN, "token1": SOL, "protocol": "meteora", "tvl": 8486.829459827823,
                                 "fee_24h": 12635.01288769163, "fee_tvl_ratio_24h": 148.877893063589, "vol_24h": 270632.9399027422, "bin_step": 200,
                                 "created_at": "2026-10-23T04:38:20Z", "first_pool_created_at": "2026-10-23T04:15:51Z"})
        for p in res["pools"]:  # LP Agent's fee_tvl_ratio is the 24h one, in percent
            self.assertAlmostEqual(p["fee_24h"] / p["tvl"] * 100, p["fee_tvl_ratio_24h"], delta=p["fee_tvl_ratio_24h"] * 0.005)

    def test_meta_is_stale_is_recorded(self):
        """Repair R1 (C3): LP Agent's meta.isStale and meta.lastUpdatedAt are kept (true / false / null; an ISO time or null)."""
        res, _ = collect([FakeResponse(mint_body())])
        self.assertEqual((res["stale"], res["last_updated_at"]), (False, "2026-10-25T08:05:06Z"))
        payload = json.loads(mint_body())
        for meta, expected in (({"isStale": True, "lastUpdatedAt": "2026-10-25T07:00:00Z"}, (True, "2026-10-25T07:00:00Z")), ({"isStale": "yes"}, (None, None)),
                               (None, (None, None)), ({"isStale": False, "lastUpdatedAt": None}, (False, None))):
            with self.subTest(meta=meta):
                payload["meta"] = meta
                res, _ = collect([FakeResponse(json.dumps(payload).encode())])
                self.assertEqual((res["status"], res["stale"], res["last_updated_at"]), ("ok", *expected))
        empty, _ = collect([FakeResponse(fixture("lpagent_discover_billions_live_20261025.json"))], mint=BILLIONS)
        self.assertEqual((empty["status"], empty["stale"], empty["last_updated_at"]), ("empty", False, None))
        self.assertEqual(collect([http_error(401)])[0]["stale"], None)

    def test_the_empty_live_answer(self):
        res, _ = collect([FakeResponse(fixture("lpagent_discover_billions_live_20261025.json"))], mint=BILLIONS)
        self.assertEqual((res["status"], res["reason"], res["pools"]), ("empty", "no_pool_listed", []))
        self.assertEqual(lp.status_line(res), "empty (LP Agent lists no Meteora pool of this token with $1,000+ liquidity; 1 LP Agent request)")

    def test_only_rows_of_this_mint_and_only_validated_values(self):
        payload = json.loads(mint_body())
        other = json.loads(json.dumps(payload["data"][0]))
        other.update(token0=BILLIONS, pool="7BQxnLbLQ1oKNyi5bZ4pj32orgLmcQKuzqtwk4B1czrf")
        payload["data"].append(other)
        row = payload["data"][2]
        row.update(tvl="NaN", fee_24h="1e999", fee_tvl_ratio=True, created_at="yesterday", first_pool_created_at="2026-10-23T04:15:51", protocol="<b>x</b>", bin_step=12.5)
        res, _ = collect([FakeResponse(json.dumps(payload).encode())])
        self.assertEqual(res["answer"]["other_token_rows_dropped"], 1)
        self.assertEqual([p["pool"] for p in res["pools"]], [r["pool"] for r in payload["data"][:3]])
        bad = res["pools"][2]
        self.assertEqual((bad["tvl"], bad["fee_24h"], bad["fee_tvl_ratio_24h"], bad["created_at"], bad["first_pool_created_at"], bad["protocol"], bad["bin_step"]),
                         (None, None, None, None, None, "other", None))

    def test_loud_guards(self):
        for body, status, reason in (({"status": "success", "data": "x"}, "unavailable", "pool_list_missing"), ([], "unavailable", "invalid_shape"),
                                     ({"status": "error", "data": []}, "unavailable", "provider_error"),
                                     ({"status": "success", "data": [{"pool": "JvCVyYnvkzJcHBaM8NdrUVhCFnH2R2mWku1v9WFbXxr", "token0": MINT_TOKEN, "liquidity": 5}]},
                                      "unavailable", "fee_tvl_field_missing")):
            with self.subTest(reason):
                res, _ = collect([FakeResponse(json.dumps(body).encode())])
                self.assertEqual((res["status"], res["reason"]), (status, reason))


if __name__ == "__main__":
    unittest.main()
