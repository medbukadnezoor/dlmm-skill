"""DS-FEETVL-T1: the first-wave collector `meteora_pools` (one free, keyless Meteora DLMM datapi read) and its offline
`--present` FEE/TVL line (Yun's rule, provisional). Offline: fake transport, the live answers of 2026-10-25 saved as fixtures
in tests/forensics/fixtures/fee_tvl/ (public data: response bodies only, no request headers).

Covers the ticket's acceptance criteria: (1) the age split (5 h 59 m -> 300%, 6 h 00 m -> 20%, unknown -> 20%, said so);
(2) the line outcomes (below the bar -> WARNING, exactly at the bar -> meets the bar, no counted pool -> WARNING, Meteora and
LP Agent both not read -> not read, Meteora not read with LP Agent read -> LP Agent's line, labelled); (3) only exact mint
matches are kept, blacklisted and dust pools never decide the line; (4) created_at is milliseconds (a live value) and the
pool age prints in hours / days; (5) "meets the bar" always carries "(not a safety signal)", no clean / safe / low;
(8) --present opens no connection; (9) assess is byte-identical with and without the new files and the engines never name
them. Plus the request (host, path, query, headers, bounds), the retry rule (one retry after a 429 or a 5xx), the loud
field guards and the four live evidence runs replayed line for line."""

from __future__ import annotations

import contextlib
import datetime as dt
import email.message
import hashlib
import io
import itertools
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

import creator_fees as cf  # noqa: E402  (DS-DLMM-SHARE-T1: the collector's own pair_volumes builds the saved pairs)
import helius_forensics as hf  # noqa: E402
import lpagent_pools as lp  # noqa: E402
import meteora_pools as mp  # noqa: E402
from test_assess import _map, _run, case_negative_space_inu, run_assess  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "fee_tvl"
BILLIONS = "9uNgkUWsRDCMsnE6UX9aJ9bCwj3Lw3pjTU4TnMEnpump"
MIL = "3w67qwokqjcS6KbZhzNonhmFNGjYbWneB7g5HTXwpump"
MINT_TOKEN = "tybY2LFHH91VdoPJJkkFAsYaD7wnQQAm3BYg1x3mint"
NO_POOL = "EAdkhQAtf1YYpWJeLJVsuDBuv94YC2T8tmso6ziwpump"
SOL = "So11111111111111111111111111111111111111112"
QUERY = "query={mint}&sort_by=fee_tvl_ratio_24h:desc&page_size=50"
LP_DUMMY_KEY = "lp-dummy-key-7c41e9a0b2d35f68"
REASSURING = re.compile(r"\b(clean|safe|low)\b", re.IGNORECASE)


def ts(text: str) -> float:
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


# the evidence runs of 2026-10-25 (DS-FEETVL-T1): when each Meteora answer was read
RUNS = {
    "billions": (BILLIONS, "meteora_pools_billions_live_20261025.json", "lpagent_discover_billions_live_20261025.json", ts("2026-10-25T08:05:55Z"), 1792903373),
    "mil": (MIL, "meteora_pools_mil_live_20261025.json", "lpagent_discover_billions_live_20261025.json", ts("2026-10-25T08:08:43Z"), 1792761876),
    "mint": (MINT_TOKEN, "meteora_pools_mint_live_20261025.json", "lpagent_discover_mint_live_20261025.json", ts("2026-10-25T08:08:22Z"), None),
    "nopool": (NO_POOL, "meteora_pools_nopool_live_20261025.json", "lpagent_discover_billions_live_20261025.json", ts("2026-10-25T08:09:09Z"), None),
}


def fixture(name: str) -> bytes:
    return (FIX / name).read_bytes()


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
    return urllib.error.HTTPError(f"https://{mp.HOST}/pools", code, "error", msg, io.BytesIO(b""))


class Opener:
    def __init__(self, answers):
        self.answers = list(answers)
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def collect(mint, answers, now=None, sleeps=None):
    sleeps = [] if sleeps is None else sleeps
    opener = Opener(answers)
    at = now if now is not None else ts("2026-10-25T08:05:55Z")
    res = mp.collect_meteora_pools(mint, opener=opener, now=lambda: at, monotonic=time.monotonic, sleep=sleeps.append)
    return res, opener


def lp_collect(mint, body: bytes, now: float):
    opener = Opener([FakeResponse(body)])
    return lp.collect_lpagent_pools(mint, LP_DUMMY_KEY, opener=opener, now=lambda: now, monotonic=time.monotonic, sleep=lambda s: None)


def present_lines(run: Path) -> list[str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = mp.main(["--present", str(run)])
    assert code == 0
    return out.getvalue().splitlines()


def addr(i: int) -> str:
    return ("Poo" + "1" * 40 + "ABCDEFGHJKLMNPQRSTUVWXYZ"[i])[:44]


def pool(i, tvl, fees24, ratio24, created=None, blacklisted=False, symbol="TOK", ratios=None):
    return {"address": addr(i), "this_token_side": "x", "symbol": symbol, "other_symbol": "SOL", "other_mint": SOL, "bin_step": 100, "base_fee_pct": 2.0,
            "tvl": tvl, "fees_24h": fees24, "volume_24h": None if fees24 is None else fees24 * 50,
            "fee_tvl_ratio": ratios or {"1h": 1.0, "4h": 4.0, "12h": 12.0, "24h": ratio24},
            "created_at_ms": None if created is None else int(created * 1000), "created_at": None if created is None else mp._iso(created), "blacklisted": blacklisted}


def met_file(mint, pools, fetched_at, status=None, reason=None):
    res = mp._base(mint, mp._iso(fetched_at))
    res.update(status=status or ("ok" if pools else "empty"), reason=reason, pools=pools, answer={"total": len(pools), "rows_in_answer": len(pools), "truncated": False})
    res["request"]["requests_sent"] = 1
    return res


def lp_file(mint, rows, fetched_at, status=None, reason=None):
    res = lp._base(mint, lp._iso(fetched_at))
    res.update(status=status or ("ok" if rows else "empty"), reason=reason, pools=rows)
    return res


def lp_row(i, mint, tvl, fee24, ratio24, created=None, first=None, protocol="meteora"):
    return {"pool": addr(i), "token0": mint, "token1": SOL, "protocol": protocol, "tvl": tvl, "fee_24h": fee24, "fee_tvl_ratio_24h": ratio24, "vol_24h": None, "bin_step": 100,
            "created_at": None if created is None else lp._iso(created), "first_pool_created_at": None if first is None else lp._iso(first)}


class TempRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.n = 0

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_with(self, met=None, lpa=None, holders=None) -> Path:
        self.n += 1
        run = self.tmp / f"run{self.n}"
        run.mkdir()
        for name, data in ((mp.OUT_FILE, met), (lp.OUT_FILE, lpa), ("holders.json", holders)):
            if data is not None:
                (run / name).write_text(data if isinstance(data, str) else json.dumps(data))
        return run

    def first(self, **kw) -> str:
        return present_lines(self.run_with(**kw))[0]

    def replay_run(self, name) -> Path:
        """A run folder rebuilt from the saved live answers of one evidence run (the collectors' own parsing, at the time
        each answer was read; holders.json reduced to the two fields --present reads)."""
        mint, met_name, lp_name, at, launch = RUNS[name]
        met, _ = collect(mint, [FakeResponse(fixture(met_name))], now=at)
        lpa = lp_collect(mint, fixture(lp_name), at)
        return self.run_with(met=met, lpa=lpa, holders={"mint": mint, "earliest_pair_created_at": launch} if launch else None)


# ----------------------------------------------------------------------------- the request


class RequestTests(unittest.TestCase):
    def test_one_documented_get_with_no_key(self):
        res, opener = collect(BILLIONS, [FakeResponse(fixture("meteora_pools_billions_live_20261025.json"))])
        self.assertEqual((res["status"], len(opener.requests)), ("ok", 1))
        request, timeout = opener.requests[0]
        url = urllib.parse.urlparse(request.full_url)
        self.assertEqual((url.scheme, url.hostname, url.port, url.path, url.query), ("https", "dlmm.datapi.meteora.ag", None, "/pools", QUERY.format(mint=BILLIONS)))
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(dict(request.header_items()), {"Accept": "application/json", "User-agent": mp.USER_AGENT})
        self.assertEqual(timeout, mp.TIMEOUT_S)
        self.assertEqual(res["request"], {"method": "GET", "host": "dlmm.datapi.meteora.ag", "path": "/pools?query=<MINT>&sort_by=fee_tvl_ratio_24h:desc&page_size=50",
                                          "keys": "none", "requests_per_scan": 1, "max_requests": 2, "requests_sent": 1})

    def test_default_opener_ignores_env_proxies_and_refuses_redirects(self):
        with mock.patch.dict(os.environ, {"https_proxy": "http://proxy.invalid:3128", "HTTPS_PROXY": "http://proxy.invalid:3128"}):
            opener = mp.default_opener()
        self.assertFalse(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in opener.handlers))
        self.assertTrue(any(isinstance(h, mp.NoRedirect) for h in opener.handlers))

    def test_only_the_allowlisted_https_host_path_and_query(self):
        q = QUERY.format(mint=BILLIONS)
        for url in (f"http://dlmm.datapi.meteora.ag/pools?{q}", f"https://dlmm.datapi.meteora.ag.evil.example/pools?{q}", f"https://dlmm.datapi.meteora.ag:8443/pools?{q}",
                    f"https://u:p@dlmm.datapi.meteora.ag/pools?{q}", "https://dlmm.datapi.meteora.ag/pools", f"https://dlmm.datapi.meteora.ag/pools?{q}&x=1",
                    f"https://dlmm.datapi.meteora.ag/pools/{BILLIONS}", f"https://dlmm.datapi.meteora.ag/pools?{QUERY.format(mint=MIL)}", f"https://damm-v2.datapi.meteora.ag/pools?{q}"):
            with self.subTest(url), self.assertRaises(mp.Failure):
                mp.check_url(url, BILLIONS)

    def test_retry_once_after_a_429_or_a_5xx_never_more(self):
        body = fixture("meteora_pools_billions_live_20261025.json")
        for first, waits in ((http_error(429), [1.5]), (http_error(429, {"Retry-After": "2"}), [2.0]), (http_error(503), [1.5]), (http_error(500), [1.5]), (FakeResponse(b"", status=502), [1.5])):
            with self.subTest(first=getattr(first, "code", getattr(first, "status", None))):
                sleeps = []
                res, opener = collect(BILLIONS, [first, FakeResponse(body)], sleeps=sleeps)
                self.assertEqual((res["status"], len(opener.requests), res["request"]["requests_sent"], sleeps), ("ok", 2, 2, waits))
        res, opener = collect(BILLIONS, [http_error(429), http_error(429)])
        self.assertEqual((res["status"], res["reason"], len(opener.requests)), ("unavailable", "rate_limited", 2))
        for answer, reason in ((http_error(429, {"Retry-After": "60"}), "rate_limited"), (http_error(404), "not_found"), (http_error(400), "bad_request"),
                               (http_error(302), "redirect_disallowed"), (socket.timeout(), "timeout"), (urllib.error.URLError(OSError("refused")), "network_error"),
                               (FakeResponse(b"<html>"), "invalid_json")):
            with self.subTest(reason=reason):
                res, opener = collect(BILLIONS, [answer])
                self.assertEqual((res["status"], res["reason"], len(opener.requests)), ("unavailable", reason, 1))
        with mock.patch.object(mp, "MAX_BYTES", 1000):
            res, _ = collect(BILLIONS, [FakeResponse(body)])
        self.assertEqual(res["reason"], "response_too_large")

    def test_status_lines(self):
        res, _ = collect(BILLIONS, [FakeResponse(fixture("meteora_pools_billions_live_20261025.json"))])
        self.assertEqual(mp.status_line(res), "ok (2 Meteora DLMM pools of this token; 1 Meteora datapi request)")
        res, _ = collect(NO_POOL, [FakeResponse(fixture("meteora_pools_nopool_live_20261025.json"))])
        self.assertEqual(mp.status_line(res), "empty (Meteora lists no DLMM pool of this token; 1 Meteora datapi request)")
        res, _ = collect(BILLIONS, [http_error(429), http_error(429)])
        self.assertEqual(mp.status_line(res), "unavailable (rate_limited; 2 Meteora datapi requests)")


# ----------------------------------------------------------------------------- 3 and 4: parsing the live answers


class ParseTests(unittest.TestCase):
    def test_the_live_billions_answer(self):
        res, _ = collect(BILLIONS, [FakeResponse(fixture("meteora_pools_billions_live_20261025.json"))])
        self.assertEqual([p["address"] for p in res["pools"]], ["3PH1oFKmzXdEQDe9y8cqXvJo3ag8sv4CS3ZXivGkqT8E", "12EfRFF3pHArkfaX1bA6TBi9J4Yg9wPCSpm895LWsQg3"])
        second = res["pools"][1]
        self.assertEqual((second["symbol"], second["other_symbol"], second["other_mint"], second["this_token_side"], second["bin_step"], second["base_fee_pct"], second["blacklisted"]),
                         ("BILLIONS", "SOL", SOL, "x", 200, 2.0, False))
        self.assertEqual(sorted(second["fee_tvl_ratio"]), ["12h", "1h", "24h", "4h"])
        self.assertTrue(second["windows_as_documented"])
        self.assertEqual(res["answer"], {"total": 2, "rows_in_answer": 2, "other_token_pools_dropped": 0, "unreadable_rows": 0, "truncated": False})

    def test_created_at_is_milliseconds_from_the_live_value(self):
        res, _ = collect(BILLIONS, [FakeResponse(fixture("meteora_pools_billions_live_20261025.json"))])
        created = {p["address"]: (p["created_at_ms"], p["created_at"]) for p in res["pools"]}
        self.assertEqual(created["12EfRFF3pHArkfaX1bA6TBi9J4Yg9wPCSpm895LWsQg3"], (1792903548000, "2026-10-25T04:45:48Z"))
        self.assertEqual(created["3PH1oFKmzXdEQDe9y8cqXvJo3ag8sv4CS3ZXivGkqT8E"], (1792907406000, "2026-10-25T05:50:06Z"))
        self.assertEqual(res["created_at_unit"], "milliseconds")
        now = ts("2026-10-25T08:05:55Z")
        for value in (1792903548, 0, -5, 1.7929e12, True, "1792903548000", int((now + 2 * 86400) * 1000)):  # seconds-sized, not a whole number, text, the future
            with self.subTest(value=value):
                self.assertEqual(mp.created_at_iso(value, now), (None, None))

    def test_fee_tvl_is_a_percent_matching_fees_over_tvl(self):
        for name, mint in (("meteora_pools_mint_live_20261025.json", MINT_TOKEN), ("meteora_pools_billions_live_20261025.json", BILLIONS), ("meteora_pools_mil_live_20261025.json", MIL)):
            res, _ = collect(mint, [FakeResponse(fixture(name))])
            for p in res["pools"]:
                if p["tvl"] and p["tvl"] > 100:
                    with self.subTest(pool=p["address"]):
                        self.assertAlmostEqual(p["fees_24h"] / p["tvl"] * 100, p["fee_tvl_ratio"]["24h"], delta=p["fee_tvl_ratio"]["24h"] * 0.005)

    def test_the_documented_windows_are_the_live_windows(self):
        for name in ("meteora_pools_mint_live_20261025.json", "meteora_pools_billions_live_20261025.json", "meteora_pools_mil_live_20261025.json"):
            for row in json.loads(fixture(name))["data"]:
                for block in ("fee_tvl_ratio", "fees", "volume"):
                    self.assertEqual(sorted(row[block]), sorted(mp.WINDOWS_DOCUMENTED), (name, block))

    def test_only_exact_mint_matches_are_kept(self):
        payload = json.loads(fixture("meteora_pools_billions_live_20261025.json"))
        impostor = json.loads(json.dumps(payload["data"][1]))
        impostor.update(address="7BQxnLbLQ1oKNyi5bZ4pj32orgLmcQKuzqtwk4B1czrf", name=f"{BILLIONS}-SOL", tvl=99999.0)
        impostor["token_x"]["address"] = MIL  # the name holds the mint, the tokens do not
        payload["data"].append(impostor)
        flipped = json.loads(json.dumps(payload["data"][1]))
        flipped.update(address="JvCVyYnvkzJcHBaM8NdrUVhCFnH2R2mWku1v9WFbXxr")
        flipped["token_x"], flipped["token_y"] = flipped["token_y"], flipped["token_x"]  # the mint on the y side counts
        payload["data"].append(flipped)
        res, _ = collect(BILLIONS, [FakeResponse(json.dumps(payload).encode())])
        self.assertEqual([p["address"] for p in res["pools"]], ["3PH1oFKmzXdEQDe9y8cqXvJo3ag8sv4CS3ZXivGkqT8E", "12EfRFF3pHArkfaX1bA6TBi9J4Yg9wPCSpm895LWsQg3",
                                                                 "JvCVyYnvkzJcHBaM8NdrUVhCFnH2R2mWku1v9WFbXxr"])
        self.assertEqual(res["pools"][2]["this_token_side"], "y")
        self.assertEqual(res["answer"]["other_token_pools_dropped"], 1)

    def test_a_missing_or_non_finite_number_is_null_never_zero(self):
        payload = json.loads(fixture("meteora_pools_billions_live_20261025.json"))
        row = payload["data"][1]
        row["tvl"], row["fees"]["24h"] = "854.3", None
        row["fee_tvl_ratio"]["4h"] = float("nan")
        del row["fee_tvl_ratio"]["1h"]
        row["pool_config"]["bin_step"] = True
        row["is_blacklisted"] = "no"
        res, _ = collect(BILLIONS, [FakeResponse(json.dumps(payload, allow_nan=True).encode())])
        p = res["pools"][1]
        self.assertEqual((p["tvl"], p["fees_24h"], p["fee_tvl_ratio"]["4h"], p["fee_tvl_ratio"]["1h"], p["bin_step"], p["blacklisted"], p["windows_as_documented"]),
                         (None, None, None, None, None, None, False))

    def test_loud_guards(self):
        cases = [({"data": "x"}, "unavailable", "pool_list_missing"), ([], "unavailable", "invalid_shape"), ({"total": 0, "data": []}, "empty", "no_dlmm_pool")]
        payload = json.loads(fixture("meteora_pools_billions_live_20261025.json"))
        renamed = json.loads(json.dumps(payload))
        for row in renamed["data"]:
            row["fee_tvl"] = row.pop("fee_tvl_ratio")
        cases.append((renamed, "unavailable", "fee_tvl_field_missing"))
        no_tvl = json.loads(json.dumps(payload))
        for row in no_tvl["data"]:
            row["liquidity"] = row.pop("tvl")
        cases.append((no_tvl, "unavailable", "tvl_field_missing"))
        for body, status, reason in cases:
            with self.subTest(reason):
                res, _ = collect(BILLIONS, [FakeResponse(json.dumps(body).encode())])
                self.assertEqual((res["status"], res["reason"]), (status, reason))

    def test_the_no_pool_answer_is_empty(self):
        res, _ = collect(NO_POOL, [FakeResponse(fixture("meteora_pools_nopool_live_20261025.json"))])
        self.assertEqual((res["status"], res["reason"], res["pools"]), ("empty", "no_dlmm_pool", []))

    def test_symbols_are_inert_labels_with_verdict_words_replaced(self):
        payload = json.loads(fixture("meteora_pools_billions_live_20261025.json"))
        payload["data"][1]["token_x"]["symbol"] = "SAFE\n## x"
        res, _ = collect(BILLIONS, [FakeResponse(json.dumps(payload).encode())])
        self.assertEqual(res["pools"][1]["symbol"], "[provider word removed] x")


class CommandLineTests(TempRun):
    def run_main(self, argv, opener):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(mp, "default_opener", return_value=opener), mock.patch.object(mp.time, "sleep"), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = mp.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_the_collector_writes_its_file_and_reads_no_other_file_of_the_run(self):
        for name in ("holders.json", "lpagent_pools.json", "creator_fees.json"):
            (self.tmp / name).write_text("{poison")
        with mock.patch.object(mp, "_read", side_effect=AssertionError("the collector read a run-folder file")):
            code, out, _ = self.run_main([BILLIONS, "--out", str(self.tmp)], Opener([FakeResponse(fixture("meteora_pools_billions_live_20261025.json"))]))
        self.assertEqual((code, out.strip()), (0, "ok (2 Meteora DLMM pools of this token; 1 Meteora datapi request)"))
        saved = json.loads((self.tmp / mp.OUT_FILE).read_text())
        self.assertEqual((saved["schema"], saved["collector"], saved["presentation_only"], saved["mint"]), ("holder-scan-meteora-pools/1", "meteora_pools", True, BILLIONS))

    def test_bad_command_lines_exit_2_and_send_nothing(self):
        net = Opener([])
        for argv in (["not-a-mint", "--out", str(self.tmp)], [BILLIONS], ["--present", str(self.tmp / "missing")], [BILLIONS, "--present", str(self.tmp)]):
            with self.subTest(argv=argv):
                code, _, err = self.run_main(argv, net)
                self.assertEqual(code, 2)
                self.assertTrue(err.startswith("error:"))
        self.assertEqual(net.requests, [])

    def test_a_failure_still_saves_the_file_and_exits_0(self):
        code, out, _ = self.run_main([BILLIONS, "--out", str(self.tmp)], Opener([http_error(429), http_error(429)]))
        self.assertEqual((code, out.strip()), (0, "unavailable (rate_limited; 2 Meteora datapi requests)"))
        self.assertEqual(json.loads((self.tmp / mp.OUT_FILE).read_text())["status"], "unavailable")


# ----------------------------------------------------------------------------- 1: the age split and the age sources


SCAN = ts("2026-10-25T08:00:00Z")


class AgeTests(TempRun):
    def line_for(self, age_s, ratio24):
        met = met_file(BILLIONS, [pool(0, 5000.0, ratio24 * 50, ratio24, created=SCAN - 3600)], SCAN)
        return self.first(met=met, holders={"mint": BILLIONS, "earliest_pair_created_at": int(SCAN - age_s)})

    def test_5h59m_takes_the_300_bar_and_6h00m_the_20_bar(self):
        self.assertEqual(self.line_for(5 * 3600 + 59 * 60, 250.0), "[for the executive summary] FEE/TVL (Yun's rule, provisional): WARNING — best Meteora DLMM pool earns "
                                                                   "250.0% of its TVL in fees over 24h; the bar for a token 5h 59m old is 300%.")
        self.assertEqual(self.line_for(6 * 3600, 250.0), "[for the executive summary] FEE/TVL (Yun's rule, provisional): meets the bar (not a safety signal) — best Meteora DLMM "
                                                         "pool 250.0% in 24h (bar 20%; token 6h 0m old).")
        self.assertEqual(self.line_for(6 * 3600 - 1, 250.0).split(" — ")[0], "[for the executive summary] FEE/TVL (Yun's rule, provisional): WARNING")  # 5 h 59 m 59 s
        self.assertEqual((mp.bar_for(6 * 3600 - 1), mp.bar_for(6 * 3600), mp.bar_for(None), mp.bar_for(0)), (300.0, 20.0, 20.0, 300.0))
        self.assertEqual(mp.age_text(6 * 3600 - 1), "5h 59m")

    def test_unknown_age_takes_the_20_bar_and_says_so(self):
        met = met_file(NO_POOL, [pool(0, 5000.0, 600.0, 12.0)], SCAN)  # no created_at, no holders.json, no LP Agent file
        lines = present_lines(self.run_with(met=met))
        self.assertEqual(lines[0], "[for the executive summary] FEE/TVL (Yun's rule, provisional): WARNING — best Meteora DLMM pool earns 12.0% of its TVL in fees over 24h; "
                                   "the bar for a token of unknown age (treated as 6 h or older) is 20%.")
        self.assertIn("  token age: unknown (no pair time in holders.json, no LP Agent first pool time, no DLMM pool time): treated as 6 h or older, so the 20% bar applies", lines[2])
        self.assertIn("  bar: 20% of TVL in fees over 24h for this token (age unknown;", lines[3])
        met["pools"][0]["fee_tvl_ratio"]["24h"] = 25.0
        self.assertEqual(self.first(met=met), "[for the executive summary] FEE/TVL (Yun's rule, provisional): meets the bar (not a safety signal) — best Meteora DLMM pool 25.0% "
                                              "in 24h (bar 20%; token age unknown, treated as 6 h or older).")

    def test_the_age_sources_in_order(self):
        met = met_file(MINT_TOKEN, [pool(0, 5000.0, 600.0, 12.0, created=SCAN - 2 * 3600)], SCAN)
        lpa = lp_file(MINT_TOKEN, [lp_row(5, MINT_TOKEN, 3000.0, 30.0, 1.0, created=SCAN - 3600, first=SCAN - 3 * 3600)], SCAN)
        holders = {"mint": MINT_TOKEN, "earliest_pair_created_at": int(SCAN - 4 * 3600)}
        age = lambda **kw: present_lines(self.run_with(**kw))[2]  # noqa: E731
        self.assertIn("token age: 4h 0m at scan, from the oldest trading pair (Dexscreener's earliest pair in holders.json, created 2026-10-25 04:00 UTC = 2026-10-25 11:00 WIB)",
                      age(met=met, lpa=lpa, holders=holders))
        self.assertIn("token age: 3h 0m at scan, from LP Agent's first_pool_created_at (2026-10-25 05:00 UTC = 2026-10-25 12:00 WIB; holders.json gave no pair time)",
                      age(met=met, lpa=lpa, holders={"mint": BILLIONS, "earliest_pair_created_at": int(SCAN - 9 * 86400)}))  # holders.json of another mint is ignored
        self.assertIn("token age: 2h 0m at scan, from the oldest DLMM pool (2026-10-25 06:00 UTC = 2026-10-25 13:00 WIB); the token may be older", age(met=met))
        self.assertIn("token age: 2h 0m at scan", age(met=met, holders={"mint": MINT_TOKEN, "earliest_pair_created_at": "1792903373"}))  # not a unix time: skipped
        self.assertIn("token age: 2h 0m at scan", age(met=met, holders="{broken"))


# ----------------------------------------------------------------------------- 2 and 3: the line outcomes


class LineTests(TempRun):
    HOLDERS = {"mint": MIL, "earliest_pair_created_at": int(SCAN - 2 * 86400)}  # 2 days old: the 20% bar

    def line(self, pools, **kw):
        return self.first(met=met_file(MIL, pools, SCAN), holders=self.HOLDERS, **kw)

    def test_below_at_and_above_the_bar(self):
        self.assertIn("WARNING — best Meteora DLMM pool earns 19.9% of its TVL in fees over 24h; the bar for a token 2d 0h old is 20%.", self.line([pool(0, 5000.0, 999.5, 19.99)]))
        self.assertIn("meets the bar (not a safety signal) — best Meteora DLMM pool 20.0% in 24h (bar 20%; token 2d 0h old).", self.line([pool(0, 5000.0, 1000.0, 20.0)]))
        self.assertIn("meets the bar (not a safety signal) — best Meteora DLMM pool 1,234.5% in 24h", self.line([pool(0, 5000.0, 61725.0, 1234.56), pool(1, 9000.0, 900.0, 10.0)]))

    def test_a_pool_at_exactly_2000_tvl_counts(self):
        """Repair R1 test gap: TVL $2,000.00 is counted, $1,999.99 is dust."""
        self.assertIn("meets the bar (not a safety signal) — best Meteora DLMM pool 25.0% in 24h", self.line([pool(0, 2000.0, 500.0, 25.0)]))
        self.assertIn("WARNING — no Meteora DLMM pool with $2,000+ TVL found for this token.", self.line([pool(0, 1999.99, 500.0, 25.0)]))
        self.assertTrue(mp._counted({"blacklisted": False, "tvl": 2000.0}))
        self.assertFalse(mp._counted({"blacklisted": False, "tvl": 1999.999}))

    def test_no_counted_pool_is_a_warning(self):
        expected = "[for the executive summary] FEE/TVL (Yun's rule, provisional): WARNING — no Meteora DLMM pool with $2,000+ TVL found for this token."
        self.assertEqual(self.line([pool(0, 1999.99, 9999.0, 500.0)]), expected)  # dust
        self.assertEqual(self.line([]), expected)  # Meteora read, no DLMM pool of this mint
        self.assertEqual(self.line([pool(0, 50000.0, 900000.0, 1800.0, blacklisted=True)]), expected)  # blacklisted
        self.assertEqual(self.line([pool(0, None, 10.0, 99.0, blacklisted=True)]), expected)  # blacklisted with its TVL not read
        self.assertEqual(self.line([pool(0, None, 10.0, 99.0)]),  # Repair R1 (C1): a TVL not read is never "no pool"
                         "[for the executive summary] FEE/TVL (Yun's rule): not read (TVL not read on 1 Meteora DLMM pool)")

    def test_an_unreadable_tvl_reads_not_read_never_no_pool(self):
        """Repair R1 (C1): no counted pool and at least one non-blacklisted pool whose TVL is missing, not a number or
        negative: "not read (TVL not read on N Meteora DLMM pools)", never "no pool"; a counted pool still decides."""
        missing, nan, negative = pool(0, None, 10.0, 99.0), pool(1, 5000.0, 10.0, 99.0), pool(2, -5000.0, 10.0, 99.0)
        met = met_file(MIL, [missing, nan, negative, pool(3, 1500.0, 15.0, 1.0)], SCAN)
        met["pools"][1]["tvl"] = float("nan")
        lines = present_lines(self.run_with(met=json.dumps(met, allow_nan=True), holders=self.HOLDERS))
        self.assertEqual(lines[0], "[for the executive summary] FEE/TVL (Yun's rule): not read (TVL not read on 3 Meteora DLMM pools)")
        self.assertIn(f"  TVL not read (cannot be counted or ruled out; with no counted pool the line reads not read): {addr(0)} (TVL not read, 24h fee/TVL 99.0%), "
                      f"{addr(1)} (TVL not read, 24h fee/TVL 99.0%), {addr(2)} (TVL not read, 24h fee/TVL 99.0%)", lines)
        self.assertIn(f"  under $2,000 TVL (dust; never decide the line): {addr(3)} (TVL $1.5k, 24h fee/TVL 1.0%)", lines)
        self.assertIn("WARNING — best Meteora DLMM pool earns 12.0%", self.line([missing, pool(4, 5000.0, 600.0, 12.0)]))  # a counted pool decides
        lpa = lp_file(MIL, [lp_row(0, MIL, None, 30.0, 40.0)], SCAN)
        self.assertEqual(self.first(lpa=lpa), "[for the executive summary] FEE/TVL (Yun's rule): not read (TVL not read on 1 Meteora DLMM pool; LP Agent figure, Meteora not read)")

    def test_blacklisted_and_dust_pools_never_decide_the_line(self):
        pools = [pool(0, 80000.0, 2e6, 2500.0, blacklisted=True), pool(1, 900.0, 9e5, 1e5), pool(2, 3000.0, 300.0, 10.0)]
        lines = present_lines(self.run_with(met=met_file(MIL, pools, SCAN), holders=self.HOLDERS))
        self.assertIn("WARNING — best Meteora DLMM pool earns 10.0% of its TVL in fees over 24h; the bar for a token 2d 0h old is 20%.", lines[0])
        self.assertTrue(any(line.startswith(f"  under $2,000 TVL (dust; never decide the line): {addr(1)} (TVL $900, 24h fee/TVL 100,000.0%)") for line in lines))
        self.assertTrue(any(line.startswith(f"  blacklisted by Meteora (never decide the line): {addr(0)} (TVL $80k, 24h fee/TVL 2,500.0%)") for line in lines))
        counted = [line for line in lines if line.startswith("    pool ")]
        self.assertEqual(len(counted), 1)
        self.assertIn(addr(2), counted[0])

    def test_meteora_and_lp_agent_both_not_read(self):
        self.assertEqual(self.first(), "[for the executive summary] FEE/TVL (Yun's rule): not read (Meteora not read: meteora_pools.json missing; LP Agent not read: "
                                       "lpagent_pools.json missing; the lpagent_pools collector did not run)")
        met = met_file(MIL, [], SCAN, status="unavailable", reason="rate_limited")
        lpa = lp_file(MIL, [], SCAN, status="unavailable", reason="LPAGENT_API_KEY not set")
        lines = present_lines(self.run_with(met=met, lpa=lpa))
        self.assertEqual(lines, ["[for the executive summary] FEE/TVL (Yun's rule): not read (Meteora not read: Meteora unavailable: rate_limited; LP Agent not read: "
                                 "LPAGENT_API_KEY not set)",
                                 "Pool fees vs TVL (Meteora DLMM; Yun's rule; provisional): not read (Meteora not read: Meteora unavailable: rate_limited; LP Agent not read: "
                                 "LPAGENT_API_KEY not set)"])
        self.assertEqual(self.first(met="{broken", lpa='{"schema": "x"}').split(" (")[1], "Yun's rule): not read")

    def test_meteora_not_read_lp_agent_read_gives_the_lp_agent_line_labelled(self):
        lpa = lp_file(MIL, [lp_row(0, MIL, 5000.0, 600.0, 12.0, created=SCAN - 86400, first=SCAN - 2 * 86400), lp_row(1, MIL, 900.0, 9000.0, 1000.0),
                            lp_row(2, MIL, 90000.0, 90000.0, 100.0, protocol="meteora_damm_v2")], SCAN)
        lines = present_lines(self.run_with(met=met_file(MIL, [], SCAN, status="unavailable", reason="timeout"), lpa=lpa))
        self.assertEqual(lines[0], "[for the executive summary] FEE/TVL (Yun's rule, provisional): WARNING — best Meteora DLMM pool earns 12.0% of its TVL in fees over 24h; "
                                   "the bar for a token 2d 0h old is 20% (LP Agent figure; Meteora not read).")
        self.assertIn("  Meteora DLMM datapi: not read (Meteora unavailable: timeout); the line uses LP Agent's figures (24h only, LP Agent's DLMM rows); "
                      "Meteora's blacklist is not visible in LP Agent's rows, so a pool Meteora blacklists could be counted here", lines)  # Repair R1 (C4)
        self.assertTrue(any("not DLMM by LP Agent's protocol field, never counted" in line and addr(2) in line for line in lines), "a DAMM v2 pool never decides the line")
        self.assertIn("token age: 2d 0h at scan, from LP Agent's first_pool_created_at", lines[2])
        lpa["pools"][0]["fee_tvl_ratio_24h"] = 20.0
        self.assertIn("meets the bar (not a safety signal) — best Meteora DLMM pool 20.0% in 24h (bar 20%; token 2d 0h old) (LP Agent figure; Meteora not read).",
                      self.first(lpa=lpa))
        self.assertEqual(self.first(lpa=lp_file(MIL, [], SCAN)), "[for the executive summary] FEE/TVL (Yun's rule, provisional): WARNING — no Meteora DLMM pool with $2,000+ "
                                                                  "TVL found for this token (LP Agent figure; Meteora not read).")

    def test_the_line_never_depends_on_lp_agent_while_meteora_is_readable(self):
        met = met_file(MIL, [pool(0, 5000.0, 600.0, 12.0)], SCAN)
        lpa = lp_file(MIL, [lp_row(0, MIL, 5000.0, 6000.0, 120.0)], SCAN)
        self.assertEqual(self.first(met=met, lpa=lpa, holders=self.HOLDERS), self.first(met=met, holders=self.HOLDERS))

    def test_a_percent_is_cut_never_rounded_up_onto_the_bar(self):
        for value, text in ((19.99, "19.9%"), (299.99, "299.9%"), (20.0, "20.0%"), (0.04, "0.0%"), (553715565.04, "553,715,565.0%")):
            self.assertEqual(mp.pct_text(value), text)
        self.assertTrue(mp.meets(20.000000000001, 20.0))
        self.assertFalse(mp.meets(19.9999999, 20.0))


# ----------------------------------------------------------------------------- the block


class BlockTests(TempRun):
    def test_counted_pool_lines_after_adding_2500_and_pool_age(self):
        met = met_file(MIL, [pool(0, 2500.0, 1000.0, 40.0, created=SCAN - 3 * 3600 - 7 * 60)], SCAN)
        lines = present_lines(self.run_with(met=met, holders={"mint": MIL, "earliest_pair_created_at": int(SCAN - 3 * 86400)}))
        self.assertIn(f"    pool {addr(0)} (TOK-SOL, bin step 100, base fee 2%): TVL $2.5k, 24h fees $1k, 24h volume $50k; fee/TVL 1h 1.0%, 4h 4.0%, 12h 12.0%, 24h 40.0%; "
                      "pool age 3h 7m (younger than 24 h); meets the bar (not a safety signal)", lines)
        self.assertIn("      after adding $2,500 (a small position): 20.0% (24h fees / (TVL + 2,500); your own liquidity counted in)", lines)
        self.assertIn("  note: for a pool younger than 24 h, the \"24h\" figures cover only its lifetime so far", lines)
        self.assertTrue(lines[-1].startswith("  presentation line only: never an engine input, never passed to assess, never counted toward NO_ALARM"))
        self.assertTrue(any(line.startswith("  cannot see: fees can drop fast after a pump") for line in lines))
        self.assertIn("owner's rule of 2026-10-25: 300% under 6 h, 20% from 6 h; provisional and unvalidated", lines[3])

    def test_the_lp_agent_cross_check(self):
        met = met_file(MIL, [pool(0, 10000.0, 2000.0, 20.0), pool(1, 10000.0, 2000.0, 20.0), pool(2, 4000.0, 400.0, 10.0)], SCAN)
        lpa = lp_file(MIL, [lp_row(0, MIL, 10900.0, 2000.0, 18.2), lp_row(1, MIL, 15000.0, 1800.0, 12.0), lp_row(9, MIL, 2000.0, 200.0, 10.0)], SCAN)
        lines = present_lines(self.run_with(met=met, lpa=lpa))
        self.assertIn(f"    pool {addr(0)}: LP Agent TVL $10.9k, 24h fee/TVL 18.2%: agrees within 10%", lines)
        self.assertIn(f"    pool {addr(1)}: LP Agent TVL $15k, 24h fee/TVL 12.0%: differs from Meteora (TVL +50%, 24h fee/TVL -40%)", lines)
        self.assertIn(f"    pool {addr(2)}: not listed by LP Agent", lines)
        self.assertIn(f"    LP Agent also lists {addr(9)} (TVL $2k, 24h fee/TVL 10.0%): not in Meteora's answer", lines)
        self.assertIn("  LP Agent cross-check: LP Agent lists no Meteora pool of this token with $1,000+ liquidity", present_lines(self.run_with(met=met, lpa=lp_file(MIL, [], SCAN))))
        self.assertIn("  LP Agent cross-check: not read (rate_limited)", present_lines(self.run_with(met=met, lpa=lp_file(MIL, [], SCAN, status="unavailable", reason="rate_limited"))))
        self.assertIn("  LP Agent cross-check: not read (lpagent_pools.json is for another mint)", present_lines(self.run_with(met=met, lpa=lp_file(BILLIONS, [], SCAN))))

    def test_the_cross_check_needs_both_numbers_within_10_percent_and_10_percent_exactly_is_within(self):
        """Repair R1 test gap: TVL and 24h fee/TVL must BOTH be within 10% of Meteora's; exactly 10% counts as within."""
        met = met_file(MIL, [pool(i, 10000.0, 2000.0, 20.0) for i in range(5)], SCAN)
        lpa = lp_file(MIL, [lp_row(0, MIL, 11000.0, 2000.0, 18.0),     # +10% and -10% exactly: within
                            lp_row(1, MIL, 9000.0, 2000.0, 22.0),      # -10% and +10% exactly: within
                            lp_row(2, MIL, 10500.0, 2000.0, 25.0),     # TVL within, fee/TVL +25%: differs
                            lp_row(3, MIL, 13000.0, 2000.0, 20.5),     # TVL +30%, fee/TVL within: differs
                            lp_row(4, MIL, 11002.0, 2000.0, 20.0)], SCAN)  # TVL +10.02%: differs
        lines = present_lines(self.run_with(met=met, lpa=lpa))
        verdicts = {i: next(line for line in lines if line.startswith(f"    pool {addr(i)}: LP Agent")).split(": ", 2)[2] for i in range(5)}
        self.assertEqual(verdicts, {0: "agrees within 10%", 1: "agrees within 10%", 2: "differs from Meteora (TVL +5%, 24h fee/TVL +25%)",
                                    3: "differs from Meteora (TVL +30%, 24h fee/TVL +2%)", 4: "differs from Meteora (TVL +10%, 24h fee/TVL +0%)"})

    def test_lp_agent_stale_data_is_said(self):
        """Repair R1 (C3): LP Agent's meta.isStale, saved by the collector, is named in the block when true, never otherwise."""
        met = met_file(MIL, [pool(0, 10000.0, 2000.0, 20.0)], SCAN)
        for rows in ([lp_row(0, MIL, 10000.0, 2000.0, 20.0)], []):
            lpa = lp_file(MIL, rows, SCAN)
            for flag, said in ((True, True), (False, False), (None, False)):
                lpa["stale"] = flag
                lines = present_lines(self.run_with(met=met, lpa=lpa))
                with self.subTest(rows=len(rows), stale=flag):
                    self.assertEqual(any("(LP Agent marks its data stale)" in line and "LP Agent cross-check" in line for line in lines), said)
        lpa = lp_file(MIL, [lp_row(0, MIL, 10000.0, 2000.0, 20.0)], SCAN)
        lpa["stale"] = True
        self.assertTrue(any(line.startswith("  LP Agent: read (one /pools/discover call) (LP Agent marks its data stale);") for line in present_lines(self.run_with(lpa=lpa))))
        real = lp_collect(MINT_TOKEN, fixture("lpagent_discover_mint_live_20261025.json"), ts("2026-10-25T08:08:22Z"))
        self.assertEqual((real["stale"], real["last_updated_at"]), (False, "2026-10-25T08:05:06Z"))

    def test_the_more_than_50_pools_note(self):
        """Repair R1 (C2): when Meteora reports more pools than one page, the block says only the first 50 by 24h fee/TVL were
        read (never that other tokens matched)."""
        payload = json.loads(fixture("meteora_pools_mint_live_20261025.json"))
        payload["total"] = 120
        met, _ = collect(MINT_TOKEN, [FakeResponse(json.dumps(payload).encode())], now=ts("2026-10-25T08:08:22Z"))
        self.assertTrue(met["answer"]["truncated"])
        lines = present_lines(self.run_with(met=met))
        self.assertIn("  Meteora DLMM datapi: read; 7 DLMM pools of this token; 1 request; more than 50 pools matched (Meteora reports 120): only the first 50 "
                      "by 24h fee/TVL were read", lines)
        self.assertFalse(any("other tokens" in line for line in lines))
        self.assertFalse(any("more than 50" in line for line in present_lines(self.replay_run("mint"))))

    def test_provider_words_in_symbols_are_counted(self):
        met = met_file(MIL, [pool(0, 5000.0, 600.0, 12.0, symbol="[provider word removed]")], SCAN)
        lines = present_lines(self.run_with(met=met))
        self.assertTrue(any("([provider word removed]-SOL, bin step 100" in line for line in lines))
        self.assertTrue(lines[-1].startswith("  Provider words removed: 1 "), lines[-1])
        self.assertFalse(any(line.startswith("  Provider words removed") for line in present_lines(self.run_with(met=met_file(MIL, [pool(0, 5000.0, 600.0, 12.0)], SCAN)))))

    def test_damaged_files_never_crash_and_never_meet_the_bar(self):
        good = met_file(MIL, [pool(0, 5000.0, 600.0, 120.0)], SCAN)
        damaged = [json.loads(json.dumps(good)) for _ in range(6)]
        damaged[0]["pools"] = [{"address": "x"}, 5, None]
        damaged[1]["pools"][0]["fee_tvl_ratio"] = "lots"
        damaged[2]["pools"][0]["tvl"] = float("inf")
        damaged[3]["fetched_at"] = "yesterday"
        damaged[4]["schema"] = "holder-scan-meteora-pools/2"
        damaged[5]["pools"][0]["fee_tvl_ratio"]["24h"] = -5.0
        for i, data in enumerate(damaged):
            with self.subTest(i):
                lines = present_lines(self.run_with(met=json.dumps(data, allow_nan=True)))
                self.assertNotIn("meets the bar", lines[0])
                self.assertTrue(lines[0].startswith("[for the executive summary] FEE/TVL (Yun's rule"))
        self.assertEqual(present_lines(self.run_with(met=json.dumps(damaged[1])))[0],
                         "[for the executive summary] FEE/TVL (Yun's rule): not read (24h fee/TVL not read on the Meteora DLMM pools with $2,000+ TVL)")
        future = json.loads(json.dumps(good))
        future["pools"][0]["created_at"] = "2099-01-01T00:00:00Z"
        lines = present_lines(self.run_with(met=future))
        self.assertTrue(any("pool age not read; meets the bar (not a safety signal)" in line for line in lines), "a pool time after the scan is not read, never an age")
        self.assertIn("token age: unknown", lines[2])
        with mock.patch.object(mp, "measure_and_print", side_effect=ValueError("boom")):
            self.assertEqual(mp.present(self.tmp), ["[for the executive summary] FEE/TVL (Yun's rule): not read (saved values unreadable)",
                                                    "Pool fees vs TVL (Meteora DLMM; Yun's rule; provisional): not read (saved values unreadable)"])


# ----------------------------------------------------------------------------- 5: wording


def wording_problems(lines):
    """Lines with a reassuring verdict word, or with "meets the bar" not followed by "(not a safety signal)"."""
    return [line for line in lines if REASSURING.search(line) or ("meets the bar" in line and "meets the bar (not a safety signal)" not in line)]


class WordingTests(TempRun):
    def scenario_outputs(self):
        holders = {"mint": MIL, "earliest_pair_created_at": int(SCAN - 86400)}
        for ratio in (5.0, 19.99, 20.0, 250.0, 350.0):
            yield present_lines(self.run_with(met=met_file(MIL, [pool(0, 5000.0, ratio * 50, ratio, created=SCAN - 7200), pool(1, 100.0, 1.0, 1.0)], SCAN), holders=holders,
                                              lpa=lp_file(MIL, [lp_row(0, MIL, 5100.0, ratio * 50, ratio)], SCAN)))
        yield present_lines(self.run_with(met=met_file(MIL, [], SCAN)))
        yield present_lines(self.run_with())
        yield present_lines(self.run_with(lpa=lp_file(MIL, [lp_row(0, MIL, 5000.0, 2000.0, 40.0)], SCAN)))
        for name in RUNS:
            yield present_lines(self.replay_run(name))

    def test_meets_the_bar_always_says_not_a_safety_signal_and_no_reassuring_word(self):
        outputs = list(self.scenario_outputs())
        self.assertEqual([wording_problems(lines) for lines in outputs], [[] for _ in outputs])
        self.assertGreater(sum("meets the bar (not a safety signal)" in line for lines in outputs for line in lines), 3)

    def test_the_check_bites(self):
        for text in ("FEE/TVL: meets the bar — best pool 30%", "pool looks safe", "risk is low", "a Clean pool"):
            self.assertEqual(wording_problems([text]), [text])
        self.assertEqual(wording_problems(["meets the bar (not a safety signal) — 30%", "below the bar", "not a safety signal"]), [])


# ----------------------------------------------------------------------------- the four live evidence runs, replayed


class LiveReplayTests(TempRun):
    def test_the_four_printed_lines(self):
        expected = {
            "billions": "[for the executive summary] FEE/TVL (Yun's rule, provisional): WARNING — no Meteora DLMM pool with $2,000+ TVL found for this token.",
            "mil": "[for the executive summary] FEE/TVL (Yun's rule, provisional): WARNING — no Meteora DLMM pool with $2,000+ TVL found for this token.",
            "mint": "[for the executive summary] FEE/TVL (Yun's rule, provisional): meets the bar (not a safety signal) — best Meteora DLMM pool 148.6% in 24h (bar 20%; token 2d 3h old).",
            "nopool": "[for the executive summary] FEE/TVL (Yun's rule, provisional): WARNING — no Meteora DLMM pool with $2,000+ TVL found for this token.",
        }
        for name, line in expected.items():
            with self.subTest(name):
                self.assertEqual(present_lines(self.replay_run(name))[0], line)

    def test_the_replayed_blocks(self):
        billions = present_lines(self.replay_run("billions"))
        self.assertIn("  token age: 3h 23m at scan, from the oldest trading pair (Dexscreener's earliest pair in holders.json, created 2026-10-25 04:42 UTC = 2026-10-25 11:42 WIB); "
                      "scan 2026-10-25 08:05 UTC = 2026-10-25 15:05 WIB", billions)
        self.assertIn("bar: 300% of TVL in fees over 24h for this token (younger than 6 h;", billions[3])
        mint = present_lines(self.replay_run("mint"))
        self.assertIn("  token age: 2d 3h at scan, from LP Agent's first_pool_created_at (2026-10-23 04:15 UTC = 2026-10-23 11:15 WIB; holders.json gave no pair time); "
                      "scan 2026-10-25 08:08 UTC = 2026-10-25 15:08 WIB", mint)
        self.assertEqual([line for line in mint if line.endswith("agrees within 10%")],
                         ["    pool JvCVyYnvkzJcHBaM8NdrUVhCFnH2R2mWku1v9WFbXxr: LP Agent TVL $8.49k, 24h fee/TVL 148.8%: agrees within 10%",
                          "    pool 8gaysp525Hb2dU9iQxd3T8hRWY1z5CfEH4WwxheY4DzL: LP Agent TVL $1.17k, 24h fee/TVL 66.2%: agrees within 10%",
                          "    pool 3ued9fQHLo5dyomDvhdPjmy5ET32e8YiCPUU3JwUx5Ja: LP Agent TVL $15.8k, 24h fee/TVL 44.8%: agrees within 10%"])
        nopool = present_lines(self.replay_run("nopool"))
        self.assertIn("  Meteora DLMM datapi: read; no DLMM pool of this token listed; 1 request", nopool)


# ----------------------------------------------------------------------------- 8 and 9: offline, never an engine input


class OfflineTests(TempRun):
    def test_present_opens_no_connection(self):
        run = self.replay_run("mint")

        def refuse(*_a, **_k):
            raise AssertionError("network access in --present")

        with mock.patch.object(mp, "default_opener", side_effect=refuse), mock.patch.object(lp, "default_opener", side_effect=refuse), \
             mock.patch.object(urllib.request, "urlopen", refuse), mock.patch.object(socket, "create_connection", refuse), \
             mock.patch.object(socket.socket, "connect", refuse):
            lines = present_lines(run)
        self.assertTrue(lines[0].startswith("[for the executive summary] FEE/TVL (Yun's rule, provisional): meets the bar (not a safety signal)"))

    def test_present_reads_no_key_and_writes_nothing(self):
        run = self.replay_run("mint")
        before = {p.name: p.read_bytes() for p in run.iterdir()}
        with mock.patch.dict(os.environ, {}, clear=True):
            present_lines(run)
        self.assertEqual({p.name: p.read_bytes() for p in run.iterdir()}, before)
        code = (SCRIPTS / "meteora_pools.py").read_text(encoding="utf-8")
        present_code = code.split("# ----------------------------------------------------------------------------- presentation (synthesis, offline)", 1)[1]
        for needle in ("environ", "getenv", "default_opener", "urlopen", "build_request", "send_once", "fetch(", "write_text", "_KEY"):
            self.assertNotIn(needle, present_code.split("def main(", 1)[0], needle)


class PresentationOnlyRuleTests(unittest.TestCase):
    """assess never reads meteora_pools.json or lpagent_pools.json: the same assessment.json and report.md with or without them."""

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

    def test_the_files_change_nothing(self):
        met, _ = collect(MINT_TOKEN, [FakeResponse(fixture("meteora_pools_mint_live_20261025.json"))])
        lpa = lp_collect(MINT_TOKEN, fixture("lpagent_discover_mint_live_20261025.json"), ts("2026-10-25T08:08:22Z"))
        met["mint"] = lpa["mint"] = self.mint
        for extra, tag in ((["--bubblemaps-json", str(self.space_map)], "map"), (["--bubblemaps-json", str(self.alarm_map)], "alarm"), ([], "no-map")):
            with self.subTest(tag):
                code, err, before, md_before = self.assess(extra, f"{tag}-without")
                self.assertEqual(code, 0, err)
                (self.run_dir / mp.OUT_FILE).write_text(json.dumps(met))
                (self.run_dir / lp.OUT_FILE).write_text(json.dumps(lpa))
                try:
                    code, err, after, md_after = self.assess(extra, f"{tag}-with")
                finally:
                    (self.run_dir / mp.OUT_FILE).unlink()
                    (self.run_dir / lp.OUT_FILE).unlink()
                self.assertEqual(code, 0, err)
                self.assertEqual((after, md_after), (before, md_before))
        _, _, alarm, _ = self.assess(["--bubblemaps-json", str(self.alarm_map)], "alarm-check")
        self.assertTrue(alarm["flag"]["label"].startswith(hf.FLAG_DANGER), "the map alarm stands; a pool meeting the bar never softens it")

    def test_refused_as_providers_json_and_unknown_to_both_engines(self):
        path = self.tmp / "pools.json"
        met, _ = collect(MINT_TOKEN, [FakeResponse(fixture("meteora_pools_mint_live_20261025.json"))])
        path.write_text(json.dumps(met))
        code, err, _, _ = self.assess(["--providers-json", str(path)], "refused")
        self.assertEqual(code, 2)
        for script in [SCRIPTS / "helius_forensics.py", SCRIPTS / "holder_analysis.py", *sorted((SCRIPTS / "ha").glob("*.py"))]:
            text = script.read_text(encoding="utf-8")
            for needle in ("meteora_pools", "lpagent", "FEE/TVL", "fee_tvl"):
                self.assertNotIn(needle, text, (script.name, needle))


# ----------------------------------------------------------------------------- DS-DLMM-SHARE-T1: the DLMM share line


ANAKIN = "ExxzYBTt3jwU5MUxuw2F4toYbTLdFwThSjyaCn6Xpump"
ANAKIN_RUN = FIX / "anakin_run_20261102T015725Z"  # the 2026-11-02 Anakin run: its meteora, LP Agent and creator_fees files, holders.json cut to two fields
ANAKIN_PUMPSWAP = "HJa61kEfSAwRt3DW9p15mLh6U5MaQgZGbE51ngg7bYtT"  # the canonical PumpSwap pool named in that run's creator_fees.json
ANAKIN_MET = {"2ZvxeVP9UXbCS1P3wjgUGz4xKHs9T7Ng75v2BoKMN2zM", "5EqdM7FBGypHBZAm8duPxioAeJ2BTG1SvDrrPKc3fyj3", "4yH1qg3kQzvddsnG9kftjP1HB1ouJMiCTfpvkDiN6eMY",
              "5uShBrn7Gy19cHyNist6hf3LxAzrWVKNSfgVCAqKwGmZ"}  # the 4 pools the run's block counts; Meteora reports $1,966,819.08 on them
ANAKIN_DS = {"2ZvxeVP9UXbCS1P3wjgUGz4xKHs9T7Ng75v2BoKMN2zM": 800000.0, "5EqdM7FBGypHBZAm8duPxioAeJ2BTG1SvDrrPKc3fyj3": 600000.0,
             "4yH1qg3kQzvddsnG9kftjP1HB1ouJMiCTfpvkDiN6eMY": 150000.0, "5uShBrn7Gy19cHyNist6hf3LxAzrWVKNSfgVCAqKwGmZ": 20000.0}  # Dexscreener's own: $1.57M
SMALLEST_DLMM = "5uShBrn7Gy19cHyNist6hf3LxAzrWVKNSfgVCAqKwGmZ"  # Meteora: $25,624.59 in 24 h
PUMP_COIN = "pumpCmXqMfrsAkQ5r49WcJnRayYRqmXz6ae8H7H9Dfn"
X_SEARCH_FIX = FIX.parent / "x_search"  # the Dexscreener token-pairs bodies saved live on 2026-10-25 by the x_search collector
SHARE = f"  {mp.SHARE_HEAD}: "


def pair_addr(i: int) -> str:
    """A valid 32-byte Solana address per i (creator_fees keeps a pair only when its address decodes to 32 bytes)."""
    return cf.b58encode(hashlib.sha256(f"ds-dlmm-share pair {i}".encode()).digest())


def live_pair(address, base, quote, h24, dex):
    """One pair in the live token-pairs shape (the x_search fixtures of 2026-10-25), provider text left out; h24 None drops it."""
    pair = {"chainId": "solana", "dexId": dex, "pairAddress": address, "baseToken": {"address": base}, "quoteToken": {"address": quote},
            "volume": {"m5": 0.0, "h1": 0.0, "h6": 0.0}}
    if h24 is not None:
        pair["volume"]["h24"] = h24
    return pair


def anakin_answer(quote_side=0, quote_volume=500.0, pumpswap=3395000.0, dlmm=None, drop=()):
    """A Dexscreener answer for Anakin: the PumpSwap pool, the four DLMM pools the run counts (Dexscreener's own 24 h figures,
    ANAKIN_DS, unlike Meteora's), one more Meteora pool (DAMM, $35k) and `quote_side` pairs of other coins priced in Anakin.
    With the defaults the base side holds $5,000,000."""
    body = [live_pair(ANAKIN_PUMPSWAP, ANAKIN, PUMP_COIN, pumpswap, "pumpswap")]
    body += [live_pair(a, ANAKIN, SOL, v, "meteora") for a, v in (dlmm or ANAKIN_DS).items() if a not in drop]
    body.append(live_pair(pair_addr(0), ANAKIN, SOL, 35000.0, "meteora"))
    body += [live_pair(pair_addr(100 + i), pair_addr(200 + i), ANAKIN, quote_volume, "pumpfun") for i in range(quote_side)]
    return body


def cf_file(mint, pairs=None, capped=False, dex_status="ok", reason=None, saved=True, at=None):
    """creator_fees.json as the collector writes it (its own _base), Dexscreener read; each of `pairs` is a volume (address
    pair_addr(i), quote SOL), (address, volume) or (address, volume, quote mint)."""
    res = cf._base(mint, cf._iso(SCAN if at is None else at))
    res["status"] = "ok"
    res["dexscreener"].update(status=dex_status, reason=reason)
    if pairs is not None:
        rows = []
        for i, entry in enumerate(pairs):
            address, volume, quote = (pair_addr(i), entry, SOL) if not isinstance(entry, tuple) else (entry + (SOL,))[:3]
            rows.append({"pair_address": address, "dex_id": "pumpswap", "quote_mint": quote, "volume_h24": volume})
        res["dexscreener_pairs"] = {"pairs_capped": capped, "pairs": rows}
    if not saved:
        del res["dexscreener_pairs"]
    return res


ONE_SOURCE = ("  DLMM share of the token's 24 h volume: 31.4 % ($1.57M of $5M, base-side pairs per Dexscreener (creator_fees.json){cap}; 4 DLMM pools counted, "
              "all in Dexscreener's list; Meteora reports $1.97M on them{quote})")


class DlmmShareTests(TempRun):
    """One line inside the block, right after the counted pools: the counted DLMM pools' 24 h volume over the 24 h volume of the
    Dexscreener pairs where the token is the base side, one source (Dexscreener) where every counted pool is in the saved
    pairs, Meteora's figure for a pool that is not ("mixed sources"); quote-side pairs named, never counted. Offline,
    presentation only; every other line is unchanged."""

    def anakin(self, body=None) -> Path:
        self.n += 1
        run = self.tmp / f"anakin{self.n}"
        shutil.copytree(ANAKIN_RUN, run)
        if body is not None:
            data = json.loads((run / cf.OUT_FILE).read_text())
            data["dexscreener_pairs"] = cf.pair_volumes(body, ANAKIN)
            (run / cf.OUT_FILE).write_text(json.dumps(data, indent=1))
        return run

    def with_cf(self, cf_data, **kw) -> Path:
        run = self.run_with(**kw)
        (run / cf.OUT_FILE).write_text(cf_data if isinstance(cf_data, str) else json.dumps(cf_data, allow_nan=True))
        return run

    def share(self, lines) -> str:
        found = [line for line in lines if line.startswith(SHARE)]
        self.assertEqual(len(found), 1, lines)
        return found[0]

    def test_the_anakin_run_saved_no_pair_volume_and_every_other_line_is_unchanged(self):
        """The 2026-11-02 Anakin run predates the saved pairs: the line reads not read (re-scan); every other line is the
        block origin/master printed for this folder (block_before_ds_dlmm_share.txt), byte for byte."""
        before = (ANAKIN_RUN / "block_before_ds_dlmm_share.txt").read_text(encoding="utf-8").splitlines()
        lines = present_lines(self.anakin())
        self.assertEqual(lines[14], "  DLMM share of the token's 24 h volume: not read (this run saved no per-pair volume; re-scan)")
        self.assertEqual(lines, before[:14] + [lines[14]] + before[14:])
        self.assertTrue(before[13].startswith("      after adding $2,500") and before[14].startswith("  LP Agent cross-check"), "right after the counted pools")
        self.assertEqual(lines[0], "[for the executive summary] FEE/TVL (Yun's rule, provisional): WARNING — best Meteora DLMM pool earns 10.1% of its TVL in fees "
                                   "over 24h; the bar for a token 3d 6h old is 20%.")
        self.assertEqual({line.split()[1] for line in before if line.startswith("    pool ") and " (Anakin-SOL, " in line}, ANAKIN_MET)

    def test_the_anakin_run_shape_one_source(self):
        """Every counted pool is in Dexscreener's list: Dexscreener's $1.57M on them over its $5M on the base-side pairs; Meteora's
        $1.97M is named, never mixed in; the two quote-side pairs ($7.5k each) are named, never counted."""
        before = (ANAKIN_RUN / "block_before_ds_dlmm_share.txt").read_text(encoding="utf-8").splitlines()
        lines = present_lines(self.anakin(anakin_answer(quote_side=2, quote_volume=7500.0)))
        expected = ONE_SOURCE.format(cap="", quote="; quote-side pairs (other coins priced in this token) $15k, not counted")
        self.assertEqual(lines, before[:14] + [expected] + before[14:])
        self.assertEqual(self.share(present_lines(self.anakin(anakin_answer()))), ONE_SOURCE.format(cap="", quote=""), "no quote-side pair: no clause")
        self.assertEqual(wording_problems(lines), [])

    def test_quote_side_volume_is_named_and_never_counted(self):
        line = self.share(present_lines(self.anakin(anakin_answer(quote_side=2, quote_volume=10000000.0))))
        self.assertEqual(line, ONE_SOURCE.format(cap="", quote="; quote-side pairs (other coins priced in this token) $20M, not counted"), "the share stays 31.4 %")
        body = anakin_answer(quote_side=2, quote_volume=7500.0)
        flipped = next(p for p in body if p["pairAddress"] == SMALLEST_DLMM)
        flipped["baseToken"], flipped["quoteToken"] = flipped["quoteToken"], flipped["baseToken"]  # a counted pool Dexscreener lists SOL-first
        line = self.share(present_lines(self.anakin(body)))
        self.assertEqual(line, ONE_SOURCE.format(cap="", quote="; quote-side pairs (other coins priced in this token) $15k, not counted"),
                         "a counted DLMM pool listed on the quote side counts on both sides, never as another coin's pair")
        self.assertTrue(self.share(present_lines(self.anakin(anakin_answer(quote_side=1, quote_volume=None)))).endswith(
            "; quote-side pairs (other coins priced in this token) 24 h volume not read, not counted)"))

    def test_a_capped_answer_says_first_30_pairs(self):
        line = self.share(present_lines(self.anakin(anakin_answer(quote_side=24))))
        self.assertEqual(line, ONE_SOURCE.format(cap=", first 30 pairs", quote="; quote-side pairs (other coins priced in this token) $12k, not counted"))
        self.assertNotIn("first 30", self.share(present_lines(self.anakin(anakin_answer(quote_side=23)))), "29 pairs: not capped")

    def test_a_pool_missing_from_the_list_falls_back_to_meteora_on_both_sides(self):
        """The 30-pair cap (or Dexscreener lacking a pool) leaves a counted pool out of the saved pairs: its Meteora figure goes
        into the numerator AND the total (Verifier caveat on PR #228: in the numerator only, the share read high), and the
        line says so; the same when the pool is listed without a 24 h volume."""
        expected = ("  DLMM share of the token's 24 h volume: 31.4 % ($1.58M of $5.01M, base-side pairs per Dexscreener (creator_fees.json); 4 DLMM pools counted "
                    "(mixed sources: 1 of 4 pools from Meteora, counted on both sides); Meteora reports $1.97M on them)")
        # ($1.55M + Meteora's $25,624.59) / ($4.98M + $25,624.59) = 31.47%; with the fallback in the numerator only it read 31.6 %
        self.assertEqual(self.share(present_lines(self.anakin(anakin_answer(drop={SMALLEST_DLMM})))), expected)
        silent = anakin_answer()
        del next(p for p in silent if p["pairAddress"] == SMALLEST_DLMM)["volume"]["h24"]
        self.assertEqual(self.share(present_lines(self.anakin(silent))), expected, "listed without a volume: the same fallback, nothing left out twice")
        capped = anakin_answer(quote_side=25, drop={SMALLEST_DLMM})  # 30 pairs and the smallest pool not among them
        self.assertEqual(len(capped), 30)
        self.assertIn(", first 30 pairs; 4 DLMM pools counted (mixed sources: 1 of 4 pools from Meteora, counted on both sides);",
                      self.share(present_lines(self.anakin(capped))))

    def test_the_live_anakin_answers_and_the_biggest_pool_missing(self):
        """The live 2026-11-02 06:55 UTC Anakin answers (this branch's creator_fees and meteora_pools collectors, free and
        keyless, saved in anakin_live_20261102T065530Z): one source gives 39.4 %. The Verifier's case: with the biggest pool
        2ZvxeVP9 dropped from the saved pairs its Meteora $1.14M goes into both figures, 41.5 %; in the numerator only it
        read 52.2 %."""
        live = FIX / "anakin_live_20261102T065530Z"
        self.assertEqual(self.share(present_lines(live)),
                         "  DLMM share of the token's 24 h volume: 39.4 % ($2.12M of $5.37M, base-side pairs per Dexscreener (creator_fees.json), first 30 pairs; "
                         "4 DLMM pools counted, all in Dexscreener's list; Meteora reports $2.94M on them; quote-side pairs (other coins priced in this token) "
                         "$156, not counted)")
        run = self.tmp / "verifier-case"
        shutil.copytree(live, run)
        data = json.loads((run / cf.OUT_FILE).read_text())
        data["dexscreener_pairs"]["pairs"] = [p for p in data["dexscreener_pairs"]["pairs"] if p["pair_address"] != "2ZvxeVP9UXbCS1P3wjgUGz4xKHs9T7Ng75v2BoKMN2zM"]
        (run / cf.OUT_FILE).write_text(json.dumps(data))
        line = self.share(present_lines(run))
        self.assertEqual(line, "  DLMM share of the token's 24 h volume: 41.5 % ($2.31M of $5.56M, base-side pairs per Dexscreener (creator_fees.json), first 30 pairs; "
                               "4 DLMM pools counted (mixed sources: 1 of 4 pools from Meteora, counted on both sides); Meteora reports $2.94M on them; quote-side "
                               "pairs (other coins priced in this token) $156, not counted)")
        self.assertNotIn("52.2", line)

    def test_the_numerator_is_always_part_of_the_total(self):
        """Every mix of listed, missing and listed-without-a-volume for the four Anakin pools: the share is at most 100 % and
        never "> 100 %" (the guard stays in the code)."""
        for states in itertools.product(("listed", "missing", "silent"), repeat=4):
            body = anakin_answer(drop={a for a, s in zip(ANAKIN_DS, states) if s == "missing"})
            for address, state in zip(ANAKIN_DS, states):
                if state == "silent":
                    del next(p for p in body if p["pairAddress"] == address)["volume"]["h24"]
            with self.subTest(states=states):
                line = self.share(present_lines(self.anakin(body)))
                self.assertNotIn("> 100 %", line)
                self.assertLessEqual(float(line.split(": ", 1)[1].split(" %", 1)[0]), 100.0)
                self.assertEqual("mixed sources" in line, any(s != "listed" for s in states))

    def test_the_billions_live_answers_replayed(self):
        """$BILLIONS on 2026-10-25: Meteora's live pools answer (dust pools only, none counted) and Dexscreener's live 30-pair
        token-pairs answer (5 base-side pairs, 25 coins priced in BILLIONS), saved by creator_fees' own parsing."""
        doc = json.loads((X_SEARCH_FIX / "x_search_billions_live_20261025.json").read_text())
        run = self.replay_run("billions")
        res = cf._base(BILLIONS, doc["read_at"])
        res["status"] = "ok"
        res["dexscreener"].update(cf.base_side_quotes(doc["dexscreener"], BILLIONS)[0])
        res["dexscreener_pairs"] = cf.pair_volumes(doc["dexscreener"], BILLIONS)
        (run / cf.OUT_FILE).write_text(json.dumps(res))
        lines = present_lines(run)
        self.assertEqual(self.share(lines), "  DLMM share of the token's 24 h volume: 0.0 % ($0 of $2.24M, base-side pairs per Dexscreener (creator_fees.json), first 30 pairs; "
                                            "0 DLMM pools counted; quote-side pairs (other coins priced in this token) $0, not counted)")
        self.assertEqual(lines.index(self.share(lines)), lines.index("  counted pools (not blacklisted, TVL $2,000 or more): none") + 1)

    def test_pairs_are_counted_once_per_address(self):
        dlmm_pool = dict(pool(0, 5000.0, 600.0, 12.0), address=pair_addr(50))  # Meteora: 24 h volume $30k; a 32-byte address the collector keeps
        met = met_file(MIL, [dlmm_pool], SCAN)
        data = cf_file(MIL, [(pair_addr(50), 20000.0), (pair_addr(1), 60000.0), (pair_addr(50), 1e9), (pair_addr(1), 1e9)])  # both pairs again: never twice
        line = self.share(present_lines(self.with_cf(data, met=met)))
        self.assertEqual(line, "  DLMM share of the token's 24 h volume: 25.0 % ($20k of $80k, base-side pairs per Dexscreener (creator_fees.json); 1 DLMM pool counted, "
                               "all in Dexscreener's list; Meteora reports $30k on them)")
        body = [live_pair(pair_addr(50), MIL, SOL, 20000.0, "meteora"), live_pair(pair_addr(1), MIL, SOL, 60000.0, "pumpswap"),
                live_pair(pair_addr(1), MIL, SOL, 1e9, "pumpswap"), live_pair(pair_addr(50), MIL, SOL, 1e9, "meteora")]
        data["dexscreener_pairs"] = cf.pair_volumes(body, MIL)  # the collector keeps the first entry of a repeated pair too
        self.assertEqual(self.share(present_lines(self.with_cf(data, met=met))), line)

    def test_a_big_fallback_no_longer_reads_over_100_and_exactly_100(self):
        """Before the fix these read "> 100 %" ($30k of $10k; $1.97M of $1M): the fallback volume now sits in the total too."""
        met = met_file(MIL, [pool(0, 5000.0, 600.0, 12.0)], SCAN)  # Meteora: $30k
        line = self.share(present_lines(self.with_cf(cf_file(MIL, [10000.0]), met=met)))
        self.assertEqual(line, "  DLMM share of the token's 24 h volume: 75.0 % ($30k of $40k, base-side pairs per Dexscreener (creator_fees.json); 1 DLMM pool counted "
                               "(mixed sources: 1 of 1 pools from Meteora, counted on both sides); Meteora reports $30k on them)")
        capped = [live_pair(ANAKIN_PUMPSWAP, ANAKIN, PUMP_COIN, 965000.0, "pumpswap")] + anakin_answer(quote_side=28, drop=set(ANAKIN_DS))[1:]
        self.assertEqual(len(capped), 30)
        line = self.share(present_lines(self.anakin(capped)))
        self.assertEqual(line, "  DLMM share of the token's 24 h volume: 66.2 % ($1.97M of $2.97M, base-side pairs per Dexscreener (creator_fees.json), first 30 pairs; "
                               "4 DLMM pools counted (mixed sources: 4 of 4 pools from Meteora, counted on both sides); Meteora reports $1.97M on them; quote-side pairs "
                               "(other coins priced in this token) $14k, not counted)")
        self.assertIn(": 100.0 % ($30k of $30k,", self.share(present_lines(self.with_cf(cf_file(MIL, [(addr(0), 30000.0)]), met=met))))
        self.assertIn(": 99.9 % ($30k of $30k,", self.share(present_lines(self.with_cf(cf_file(MIL, [(addr(0), 30000.0), (pair_addr(1), 0.01)]), met=met))),
                      "cut toward zero, never rounded up")

    def test_not_read_reasons(self):
        met = met_file(MIL, [pool(0, 5000.0, 600.0, 12.0)], SCAN)
        cases = [(None, "creator_fees.json missing; the creator_fees collector did not run"), ("{broken", "creator_fees.json unreadable"),
                 ({"schema": "holder-scan-creator-fees/2", "mint": MIL}, "creator_fees.json unreadable"),
                 (cf_file(BILLIONS, [1.0]), "creator_fees.json is for another mint"),
                 (cf_file(MIL, saved=False), "this run saved no per-pair volume; re-scan"),
                 (cf_file(MIL, dex_status="unavailable", reason="rate_limited"), "Dexscreener not read by the creator_fees collector: rate_limited"),
                 (cf_file(MIL, dex_status="not_sent"), "Dexscreener not read by the creator_fees collector: unknown"),
                 (cf_file(MIL, []), "Dexscreener lists no pair of this token in creator_fees.json"),
                 (cf_file(MIL, [None, None]), "no 24 h volume on a base-side Dexscreener pair in creator_fees.json"),
                 (cf_file(MIL, [(pair_addr(1), 5000.0, MIL)]), "no 24 h volume on a base-side Dexscreener pair in creator_fees.json")]  # quote side only
        for data, reason in cases:
            with self.subTest(reason=reason):
                run = self.run_with(met=met) if data is None else self.with_cf(data, met=met)
                self.assertEqual(self.share(present_lines(run)), f"  DLMM share of the token's 24 h volume: not read ({reason})")
        self.assertEqual(self.share(present_lines(self.with_cf(cf_file(MIL, [0.0, 0.0]), met=met))),
                         "  DLMM share of the token's 24 h volume: 100.0 % ($30k of $30k, base-side pairs per Dexscreener (creator_fees.json); 1 DLMM pool counted "
                         "(mixed sources: 1 of 1 pools from Meteora, counted on both sides); Meteora reports $30k on them)")
        empty = met_file(MIL, [pool(0, 1500.0, 15.0, 1.0)], SCAN)  # dust only: nothing counted, both sides $0
        self.assertEqual(self.share(present_lines(self.with_cf(cf_file(MIL, [0.0]), met=empty))),
                         "  DLMM share of the token's 24 h volume: not read (no 24 h volume: $0 on every base-side Dexscreener pair in creator_fees.json)")
        no_volume = met_file(MIL, [pool(0, 5000.0, None, 12.0)], SCAN)  # the counted pool's 24 h volume not read by Meteora nor listed
        self.assertEqual(self.share(present_lines(self.with_cf(cf_file(MIL, [5000.0]), met=no_volume))),
                         "  DLMM share of the token's 24 h volume: not read (24 h volume not read on the counted DLMM pools)")
        self.assertEqual(self.share(present_lines(self.with_cf(cf_file(MIL, [(addr(0), 1000.0), 4000.0]), met=no_volume))),
                         "  DLMM share of the token's 24 h volume: 20.0 % ($1k of $5k, base-side pairs per Dexscreener (creator_fees.json); 1 DLMM pool counted, "
                         "all in Dexscreener's list)", "listed: Dexscreener's figure stands without Meteora's")

    def test_missing_volumes_are_left_out_and_said(self):
        met = met_file(MIL, [pool(0, 5000.0, 600.0, 12.0), pool(1, 5000.0, None, 10.0)], SCAN)
        line = self.share(present_lines(self.with_cf(cf_file(MIL, [90000.0, None, 30000.0]), met=met)))
        self.assertEqual(line, "  DLMM share of the token's 24 h volume: 20.0 % ($30k of $150k, base-side pairs per Dexscreener (creator_fees.json); 2 DLMM pools counted "
                               "(mixed sources: 1 of 2 pools from Meteora, counted on both sides); Meteora reports $30k on 1 of them; 1 base-side Dexscreener pair "
                               "without a 24 h volume left out; 1 counted pool without a 24 h volume left out)")

    def test_lp_agent_figures_are_labelled(self):
        lpa = lp_file(MIL, [lp_row(0, MIL, 5000.0, 600.0, 12.0)], SCAN)
        lpa["pools"][0]["vol_24h"] = 20000.0
        met = met_file(MIL, [], SCAN, status="unavailable", reason="timeout")
        line = self.share(present_lines(self.with_cf(cf_file(MIL, [80000.0]), met=met, lpa=lpa)))
        self.assertEqual(line, "  DLMM share of the token's 24 h volume: 20.0 % ($20k of $100k, base-side pairs per Dexscreener (creator_fees.json); 1 DLMM pool counted "
                               "(mixed sources: 1 of 1 pools from LP Agent, counted on both sides); LP Agent reports $20k on them; LP Agent figure, Meteora not read)")
        line = self.share(present_lines(self.with_cf(cf_file(MIL, [(addr(0), 16000.0), 64000.0]), met=met, lpa=lpa)))
        self.assertEqual(line, "  DLMM share of the token's 24 h volume: 20.0 % ($16k of $80k, base-side pairs per Dexscreener (creator_fees.json); 1 DLMM pool counted, "
                               "all in Dexscreener's list; LP Agent reports $20k on them; LP Agent figure, Meteora not read)")

    def test_the_executive_line_and_every_other_line_never_change(self):
        holders = {"mint": MIL, "earliest_pair_created_at": int(SCAN - 2 * 86400)}
        scenarios = [dict(met=met_file(MIL, [pool(0, 5000.0, 600.0, 12.0, created=SCAN - 7200), pool(1, 900.0, 90.0, 10.0)], SCAN), holders=holders),
                     dict(met=met_file(MIL, [pool(0, 50000.0, 30000.0, 60.0), pool(1, 9000.0, 900.0, 10.0, blacklisted=True)], SCAN),
                          lpa=lp_file(MIL, [lp_row(0, MIL, 50500.0, 30000.0, 59.0)], SCAN)),
                     dict(met=met_file(MIL, [], SCAN), holders=holders),
                     dict(lpa=lp_file(MIL, [lp_row(0, MIL, 5000.0, 600.0, 12.0)], SCAN))]
        for i, kw in enumerate(scenarios):
            with self.subTest(i):
                without = present_lines(self.run_with(**kw))
                withit = present_lines(self.with_cf(cf_file(MIL, [100000.0, 50000.0], capped=True), **kw))
                self.assertEqual([x for x in withit if not x.startswith(SHARE)], [x for x in without if not x.startswith(SHARE)])
                self.assertEqual(withit.index(self.share(withit)), without.index(self.share(without)))
                self.assertEqual(withit[0], without[0], "the FEE/TVL executive line never depends on the share")
                self.assertEqual(wording_problems(withit), [])
        both_missing = present_lines(self.with_cf(cf_file(MIL, [1.0])))  # Meteora and LP Agent both not read: the two not-read lines only
        self.assertEqual(len(both_missing), 2)
        self.assertFalse(any(x.startswith(SHARE) for x in both_missing))

    def test_damage_never_costs_the_block(self):
        met = met_file(MIL, [pool(0, 5000.0, 600.0, 12.0)], SCAN)
        baseline = [x for x in present_lines(self.run_with(met=met)) if not x.startswith(SHARE)]
        damaged = []
        for saved in ("x", [], {"pairs": "x"}, {"pairs": [None, 5, "a", {"pair_address": "not-an-address", "volume_h24": 5.0}]},
                      {"pairs": [{"pair_address": pair_addr(0), "volume_h24": "lots"}, {"pair_address": pair_addr(1), "volume_h24": float("nan")},
                                 {"pair_address": pair_addr(2), "volume_h24": -5.0}, {"pair_address": pair_addr(3), "volume_h24": True}], "pairs_capped": "yes"}):
            data = cf_file(MIL)
            data["dexscreener_pairs"] = saved
            damaged.append(data)
        damaged += [cf_file(MIL, [1.0]) | {"dexscreener": "x"}, cf_file(MIL, [1.0]) | {"mint": 7}, [], "null"]
        for i, data in enumerate(damaged):
            with self.subTest(i):
                lines = present_lines(self.with_cf(data, met=met))
                self.assertTrue(self.share(lines).startswith(f"{SHARE}not read ("), self.share(lines))
                self.assertEqual([x for x in lines if not x.startswith(SHARE)], baseline)
        with mock.patch.object(mp, "share_line", side_effect=ValueError("boom")):
            lines = present_lines(self.with_cf(cf_file(MIL, [1.0]), met=met))
        self.assertEqual(self.share(lines), "  DLMM share of the token's 24 h volume: not read (saved values unreadable)")
        self.assertEqual([x for x in lines if not x.startswith(SHARE)], baseline)

    def test_offline_and_never_an_engine_input(self):
        run = self.anakin(anakin_answer())

        def refuse(*_a, **_k):
            raise AssertionError("network access in --present")

        before = {p.name: p.read_bytes() for p in run.iterdir()}
        with mock.patch.object(mp, "default_opener", side_effect=refuse), mock.patch.object(cf, "default_opener", side_effect=refuse), \
             mock.patch.object(urllib.request, "urlopen", refuse), mock.patch.object(socket, "create_connection", refuse), \
             mock.patch.object(socket.socket, "connect", refuse), mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(self.share(present_lines(run)).startswith(f"{SHARE}31.4 % ("))
        self.assertEqual({p.name: p.read_bytes() for p in run.iterdir()}, before, "--present writes nothing")
        for script in [SCRIPTS / "helius_forensics.py", SCRIPTS / "holder_analysis.py", *sorted((SCRIPTS / "ha").glob("*.py"))]:
            text = script.read_text(encoding="utf-8")
            for needle in ('"dexscreener_pairs"', "'dexscreener_pairs'", "volume_h24", "DLMM share", "creator_fees"):  # helius_forensics' own
                # dexscreener_pairs() function (its pool list for holders.json) is another thing: only the saved key is looked for
                self.assertNotIn(needle, text, (script.name, needle))
        self.assertTrue(present_lines(run)[-1].startswith("  presentation line only: never an engine input, never passed to assess, never counted toward NO_ALARM"))


if __name__ == "__main__":
    unittest.main()
