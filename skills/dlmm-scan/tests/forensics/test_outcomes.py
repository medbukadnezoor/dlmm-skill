"""DS-OUTCOMES-T1: scripts/outcomes.py, the maintenance script that records what the price did 1 h and 6 h after each saved
scan (GeckoTerminal's free 5-minute candles) and rebuilds outcomes.csv with the scan's warnings next to the outcome.
Offline: a counting fake opener, a fixed clock, and GeckoTerminal answers saved live on 2026-10-25 in
tests/forensics/fixtures/outcomes/ (public data: response bodies only, byte for byte). The run folders are copies of the
saved files in fixtures/exit_overhang/ (mil, Marvin, $BILLIONS) or small synthetic folders.

Covers the ticket's acceptance criteria: (1) one request per run, at most one retry and only after a 429, request starts
at least 12 s apart (PACING_S), runs younger than 6 h (6 h 10 min) pending with no request; (2) timestamps in seconds and the candle
containing the scan time chosen at the boundaries; (3) the class boundaries (exactly -50% dumped; -30% low with a -20%
close held; anything else in between); (4) a dead pool or empty candles read "no candles", never held, and a missing pool
"not read (no pool)" with no request; (5) the EXIT OVERHANG and FEE/TVL columns come from exit_overhang.py and
meteora_pools.py by import, "not read" when their inputs are missing; (6) only outcome.json and outcomes.csv are written,
every other file byte-identical; (7) no verdict words, held never called safe, the bars called unvalidated until about 10
held coins; (8) assess byte-identical with and without the new files, and the engines never read them. Plus the request
(host, path, query, headers, the URL check), the loud parse guards, the live answers replayed (Marvin dumped, mil in
between: its fall came after the 6 h mark) and the CSV formula guard."""

from __future__ import annotations

import contextlib
import csv
import email.message
import hashlib
import io
import json
import re
import shutil
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import exit_overhang as eo  # noqa: E402
import helius_forensics as hf  # noqa: E402
import meteora_pools as mp  # noqa: E402
import outcomes as oc  # noqa: E402
from test_assess import _map, _run, case_negative_space_inu, run_assess  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "outcomes"
EO_FIX = Path(__file__).resolve().parent / "fixtures" / "exit_overhang"
FEE_FIX = Path(__file__).resolve().parent / "fixtures" / "fee_tvl"
MIL_RUN = "20261024T050031Z-3w67qwokqjcS6KbZhzNonhmFNGjYbWneB7g5HTXwpump"
MARVIN_RUN = "20261025T031703Z-FmuciqKXRRnKqhi7BNin5mYH6fm3oTrfVB5A5Fyrpump"
BILLIONS_RUN = "20261025T060315Z-9uNgkUWsRDCMsnE6UX9aJ9bCwj3Lw3pjTU4TnMEnpump"
MIL_POOL = "63cdEBLRBRTYqxfmqs3q3bVDDUuFxqFn8opj3SYLPZti"
MARVIN_POOL = "FYLA8ej1X6n4nBiEKCZ3zmvACeH5MhdPRkkgPqtWsm1n"
EVQTA_MINT = "EVQtaC7JhakRZr4deKv8nbhqs9YaRt3eVDxt6DyQo6ea"
EVQTA_RUN = "20261021T235356Z-" + EVQTA_MINT
EVQTA_POOL = "DBAC6C42XHZ9LtEyVfvABCPvcwJgVYf5J411f8qvDsvC"
MINT = "3w67qwokqjcS6KbZhzNonhmFNGjYbWneB7g5HTXwpump"
POOL = MIL_POOL
SCAN = 1792818031  # 2026-10-24T05:00:31Z, the mil run folder name
LATER = 1792926552  # 2026-10-25T11:09:12Z, when the live answers were read
BILLIONS_SCAN_PLUS_3H = 1792908195 + 3 * 3600  # mil and Marvin ready, $BILLIONS (scan 06:03:15 UTC) pending
REASSURING = re.compile(r"\b(clean|safe|low)\b", re.IGNORECASE)


def fixture(name: str) -> bytes:
    return (FIX / name).read_bytes()


class Clock:
    """A fake monotonic clock: sleep advances it, so pacing is measured without waiting."""

    def __init__(self) -> None:
        self.t = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds


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
    return urllib.error.HTTPError(f"https://{oc.HOST}/api/v2", code, "error", msg, io.BytesIO(b""))


class Opener:
    """Counts every request, notes the fake clock at each start and answers from a list (a missing answer fails loudly)."""

    def __init__(self, answers, clock: Clock | None = None):
        self.answers, self.clock = list(answers), clock
        self.requests: list[tuple[str, dict, float | None]] = []

    def open(self, request, timeout=None):
        self.requests.append((request.full_url, dict(request.header_items()), self.clock.t if self.clock else None))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def candles_body(rows, mint=MINT, newest_first=True):
    return json.dumps({"data": {"id": "x", "type": "ohlcv_request_response", "attributes": {"ohlcv_list": sorted(rows, reverse=newest_first)}},
                       "meta": {"base": {"address": mint}, "quote": {"address": "So11111111111111111111111111111111111111112"}}}).encode()


def flat_rows(scan=SCAN, price=1.0, start_offset=-600, count=76):
    """Synthetic 5-minute candles at one price, aligned like GeckoTerminal's (start times on 5-minute marks)."""
    first = scan - scan % 300 + start_offset
    return [[first + i * 300, price, price, price, price, 10.0] for i in range(count)]


def with_lows(rows, low_at: dict[int, float], close_at: dict[int, float] | None = None):
    out = []
    for r in rows:
        r = list(r)
        if r[0] in low_at:
            r[3] = low_at[r[0]]
        if close_at and r[0] in close_at:
            r[4] = close_at[r[0]]
        out.append(r)
    return out


def measure_rows(rows, scan=SCAN, mint=MINT):
    candles, dropped, problem = oc.parse_candles(json.loads(candles_body(rows, mint)), mint, scan)
    assert problem is None, problem
    return oc.measure(candles, scan)


def copy_run(dst: Path, name: str) -> Path:
    shutil.copytree(EO_FIX / name, dst / name)
    return dst / name


def fallback_run(dst: Path) -> Path:
    """A synthetic EVQta run folder: creator_fees empty, the pool only as a holders.json infrastructure row in pool_addresses."""
    run = dst / EVQTA_RUN
    run.mkdir()
    (run / "holders.json").write_text(json.dumps({"mint": EVQTA_MINT, "pool_addresses": [EVQTA_POOL, "8FEerSaxBGmZXv2ZtM3pD6qWrcGBGSBmEp2iRBtPxuhR"],
                                                  "top_holders": [{"rank": 1, "wallet": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", "share_pct": 4.0, "infrastructure": False},
                                                                  {"rank": 2, "wallet": EVQTA_POOL, "share_pct": 1.5729, "infrastructure": True},
                                                                  {"rank": 3, "wallet": "8FEerSaxBGmZXv2ZtM3pD6qWrcGBGSBmEp2iRBtPxuhR", "share_pct": 0.2, "infrastructure": True}]}))
    (run / "creator_fees.json").write_text(json.dumps({"schema": eo.FEES_SCHEMA, "mint": EVQTA_MINT, "status": "empty", "reason": "no_pump_curve", "pools": []}))
    return run


def tree_hashes(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob("*")) if p.is_file()}


def run_main(argv, opener, now, clock=None):
    clock = clock or Clock()
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = oc.main(argv, opener=opener, now=lambda: now, monotonic=clock.monotonic, sleep=clock.sleep)
    return code, out.getvalue()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="outcomes-test-"))
        self.reports = self.tmp / "reports"
        self.reports.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class RequestTests(TempDirTest):
    """(1) one request per run, paced, at most one retry after a 429; pending runs send nothing; the exact request."""

    def test_one_request_per_run_paced_12_s_apart_and_the_exact_request(self):
        copy_run(self.reports, MIL_RUN)
        copy_run(self.reports, MARVIN_RUN)
        clock = Clock()
        opener = Opener([FakeResponse(fixture("mil_ohlcv_5m_live_20261025.json")), FakeResponse(fixture("marvin_ohlcv_5m_live_20261025.json"))], clock)
        code, out = run_main(["--reports", str(self.reports)], opener, LATER, clock)
        self.assertEqual(code, 0)
        self.assertEqual(len(opener.requests), 2, "one request per run")
        (url1, headers, t1), (url2, _, t2) = opener.requests
        self.assertGreaterEqual(t2 - t1, oc.PACING_S, "request starts at least 12 s apart")
        self.assertEqual(url1, f"https://api.geckoterminal.com/api/v2/networks/solana/pools/{MIL_POOL}/ohlcv/minute"
                               f"?aggregate=5&before_timestamp={SCAN + 6 * 3600 + 300}&limit=76&token={MINT}")
        self.assertIn(f"/pools/{MARVIN_POOL}/ohlcv/minute?aggregate=5&before_timestamp=1792920123&limit=76&token=FmuciqKXRRnKqhi7BNin5mYH6fm3oTrfVB5A5Fyrpump", url2)
        self.assertEqual({k.lower() for k in headers}, {"accept", "user-agent"}, "no key, no other header")
        self.assertIn("GeckoTerminal requests sent: 2 (0 retries after a 429)", out)
        self.assertEqual(oc.LIMIT, 76)
        self.assertEqual((oc.PACING_S, 60 / oc.PACING_S), (12.0, 5.0), "AMENDMENT A1: 5 a minute at most (429s came at 24 a minute)")

    def test_timestamps_are_unix_seconds(self):
        query = urllib.parse.parse_qs(urllib.parse.urlparse(oc.build_request(POOL, MINT, SCAN).full_url).query)
        self.assertEqual(query["before_timestamp"], [str(SCAN + 21900)])
        self.assertEqual(len(query["before_timestamp"][0]), 10, "seconds, never milliseconds")
        self.assertEqual(oc.parse_run_name(MIL_RUN), (float(SCAN), MINT))
        for bad in ("20261020-cluster-proto", "20261024T050031Z-notamint", "20261324T050031Z-" + MINT, MIL_RUN + "x" * 5):
            self.assertIsNone(oc.parse_run_name(bad), bad)

    def test_one_retry_only_after_a_429_and_never_after_other_failures(self):
        run = copy_run(self.reports, MIL_RUN)
        cases = [
            ([http_error(429), FakeResponse(fixture("mil_ohlcv_5m_live_20261025.json"))], 2, "ok", [oc.RETRY_DEFAULT_WAIT_S]),
            ([http_error(429, {"Retry-After": "7"}), http_error(429)], 2, "not read (rate limited; run again later)", [12.0]),  # never sooner than the pacing
            ([http_error(429, {"Retry-After": "30"}), FakeResponse(fixture("mil_ohlcv_5m_live_20261025.json"))], 2, "ok", [30.0]),
            ([http_error(429, {"Retry-After": "120"})], 1, "not read (rate limited; run again later)", []),
            ([http_error(500)], 1, "not read (server_error)", []),
            ([http_error(404)], 1, "not read (pool_not_on_geckoterminal)", []),
            ([http_error(301, {"Location": "https://evil.example/"})], 1, "not read (redirect_disallowed)", []),
            ([FakeResponse(b"{not json")], 1, "not read (invalid_json)", []),
        ]
        for answers, sent, status, retry_sleeps in cases:
            with self.subTest(status=status, sent=sent):
                clock = Clock()
                opener = Opener(answers, clock)
                result = oc.read_run(run, SCAN, MINT, opener, oc.Pacer(clock.monotonic, clock.sleep), now=LATER, monotonic=clock.monotonic)
                self.assertEqual(len(opener.requests), sent)
                self.assertEqual(result["request"]["requests_sent"], sent)
                self.assertEqual(result["status"], status)
                self.assertEqual(clock.sleeps, retry_sleeps, "the only waits are the retry waits (each is at least the 12 s pacing)")
                self.assertEqual(result["final"], status == "ok" or status == "not read (pool_not_on_geckoterminal)")
                if sent == 2:
                    self.assertGreaterEqual(opener.requests[1][2] - opener.requests[0][2], oc.PACING_S, "the retry is paced too")

    def test_runs_younger_than_6_h_are_pending_with_no_request(self):
        copy_run(self.reports, MIL_RUN)
        for age, pending in ((5 * 3600 + 59 * 60, True), (6 * 3600, True), (6 * 3600 + 599, True), (6 * 3600 + 600, False)):
            with self.subTest(age=age):
                opener = Opener([FakeResponse(fixture("mil_ohlcv_5m_live_20261025.json"))])
                code, out = run_main(["--reports", str(self.reports), "--refresh"], opener, SCAN + age)
                saved = json.loads((self.reports / MIL_RUN / "outcome.json").read_text())
                self.assertEqual((saved["status"] == "pending", len(opener.requests)), (pending, 0 if pending else 1))
                if pending:
                    self.assertEqual((saved["final"], saved["ready_after_utc"]), (False, "2026-10-24T11:10:31Z"))
                    self.assertIn("GeckoTerminal requests sent: 0", out)

    def test_a_final_outcome_is_not_read_again_a_pending_or_failed_one_is_and_refresh_reads_all(self):
        copy_run(self.reports, MIL_RUN)
        run_main(["--reports", str(self.reports)], Opener([]), SCAN + 3600)  # pending: no request
        opener = Opener([http_error(503)])
        run_main(["--reports", str(self.reports)], opener, LATER)  # pending is read again: a failed read
        self.assertEqual(len(opener.requests), 1)
        opener = Opener([FakeResponse(fixture("mil_ohlcv_5m_live_20261025.json"))])
        run_main(["--reports", str(self.reports)], opener, LATER)  # a failed read is read again
        self.assertEqual((len(opener.requests), json.loads((self.reports / MIL_RUN / "outcome.json").read_text())["status"]), (1, "ok"))
        opener = Opener([])
        code, _ = run_main(["--reports", str(self.reports)], opener, LATER)  # final: nothing sent (an answer would be popped)
        self.assertEqual((code, len(opener.requests)), (0, 0))
        opener = Opener([FakeResponse(fixture("mil_ohlcv_5m_live_20261025.json"))])
        run_main(["--reports", str(self.reports), "--refresh"], opener, LATER)
        self.assertEqual(len(opener.requests), 1)

    def test_run_limits_the_reads_and_bad_command_lines_exit_2(self):
        copy_run(self.reports, MIL_RUN)
        copy_run(self.reports, MARVIN_RUN)
        opener = Opener([FakeResponse(fixture("marvin_ohlcv_5m_live_20261025.json"))])
        code, _ = run_main(["--reports", str(self.reports), "--run", str(self.reports / MARVIN_RUN)], opener, LATER)
        self.assertEqual((code, len(opener.requests)), (0, 1))
        self.assertFalse((self.reports / MIL_RUN / "outcome.json").exists())
        rows = read_csv(self.reports / "outcomes.csv")
        self.assertEqual([r["outcome status"] for r in rows], ["not checked yet (no outcome.json)", "ok"], "the table still lists every run")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(run_main(["--reports", str(self.tmp / "missing")], Opener([]), LATER)[0], 2)
            self.assertEqual(run_main(["--reports", str(self.reports), "--run", "20261024T050031Z-other"], Opener([]), LATER)[0], 2)

    def test_the_url_check_refuses_anything_but_the_one_request(self):
        good = oc.build_request(POOL, MINT, SCAN).full_url
        oc.check_url(good, POOL, MINT, SCAN)
        for bad in (good.replace("https://", "http://"), good.replace("api.geckoterminal.com", "api.geckoterminal.com.evil.io"),
                    good.replace("api.geckoterminal.com", "api.geckoterminal.com:8443"), good.replace("https://", "https://user:pw@"),
                    good.replace("/minute", "/hour"), good.replace("limit=76", "limit=1000"), good + "&x=1", good + "#frag",
                    good.replace(f"token={MINT}", "token=base")):
            with self.subTest(bad=bad):
                with self.assertRaises(oc.Failure):
                    oc.check_url(bad, POOL, MINT, SCAN)
        with self.assertRaises(oc.Failure):
            oc.build_request("not-a-pool/../x", MINT, SCAN)

    def test_dry_run_sends_nothing_and_writes_nothing(self):
        copy_run(self.reports, MIL_RUN)
        before = tree_hashes(self.reports)
        opener = Opener([])
        code, out = run_main(["--reports", str(self.reports), "--dry-run"], opener, LATER)
        self.assertEqual((code, len(opener.requests), tree_hashes(self.reports)), (0, 0, before))
        self.assertIn(f"would read {MIL_RUN}: GET /api/v2/networks/solana/pools/{MIL_POOL}/ohlcv/minute?aggregate=5", out)
        self.assertIn("dry run: no request sent, nothing written", out)


class CandleTests(unittest.TestCase):
    """(2) the candle containing the scan time at the boundaries, (3) the classes, (4) dead pools, and the parse guards."""

    def test_the_candle_containing_the_scan_time_at_the_boundaries(self):
        base = 1792818000  # 05:00:00, a candle start
        rows = [[base - 600 + i * 300, 1.0 + i, 1.0 + i, 1.0 + i, 1.0 + i, 1.0] for i in range(10)]  # each candle's close differs
        for scan, start in ((base, base), (base + 1, base), (base + 299, base), (base + 300, base + 300), (base - 1, base - 300)):
            with self.subTest(scan=scan):
                m = measure_rows(rows, scan)
                self.assertEqual(m["price_at_scan_candle_utc"], oc._iso(start))
                self.assertEqual(m["price_at_scan_from"], "the close of the candle containing the scan time")

    def test_a_candle_ending_exactly_at_the_scan_time_does_not_contain_it(self):
        base = 1792818000
        rows = [[base, 2.0, 2.0, 2.0, 2.0, 1.0], [base + 600, 1.0, 1.0, 1.0, 1.0, 1.0]]  # no candle 05:05-05:10
        m = measure_rows(rows, base + 300)
        self.assertEqual((m["price_at_scan_candle_utc"], m["price_at_scan_usd"]), (oc._iso(base), 2.0))
        self.assertIn("the last candle in the 10 minutes before the scan", m["price_at_scan_from"], "05:00-05:05 ends at 05:05: it does not contain 05:05")

    def test_the_window_ends_at_6_h(self):
        start = SCAN - SCAN % 300
        rows = flat_rows(count=76) + [[start + 6 * 3600 + 300, 1.0, 1.0, 0.1, 0.1, 1.0]]  # a crash in the candle after the 6 h mark
        m = measure_rows(rows)
        self.assertEqual((m["class"], m["lowest_6h"]["change_pct"], m["plus_6h"]["change_pct"]), ("held", 0.0, 0.0), "a fall after the 6 h mark is not counted")

    def test_no_candle_at_the_scan_time_uses_the_last_one_in_the_10_minutes_before_else_not_read(self):
        scan = SCAN
        start = scan - scan % 300
        rows = [[start - 600, 3.0, 3.0, 3.0, 3.0, 1.0], [start - 300, 2.0, 2.0, 2.0, 2.0, 1.0], [start + 600, 1.0, 1.0, 1.0, 1.0, 1.0]]
        m = measure_rows(rows, scan)  # 04:50:00 starts before the window (scan - 10 min = 04:50:31); 04:55:00 is the last inside it
        self.assertEqual((m["status"], m["price_at_scan_usd"]), ("ok", 2.0))
        self.assertIn("the last candle in the 10 minutes before the scan", m["price_at_scan_from"])
        m = measure_rows([[start - 900, 2.0, 2.0, 2.0, 2.0, 1.0], [start + 600, 1.0, 1.0, 1.0, 1.0, 1.0]], scan)
        self.assertEqual(m["status"], "not read (no trade in the 10 minutes before the scan)")
        m = measure_rows([[start + 600, 1.0, 1.0, 1.0, 1.0, 1.0], [start + 900, 1.0, 1.0, 1.0, 1.0, 1.0]], scan)
        self.assertEqual(m["status"], "not read (candles start after the scan)")
        self.assertNotIn("class", m)

    def test_class_boundaries(self):
        start = SCAN - SCAN % 300
        mid, end = start + 3 * 3600, start + 6 * 3600 - 300  # a candle in the middle; the candle holding the 6 h mark is start + 6 h
        six = start + 6 * 3600
        cases = [
            ({mid: 0.5}, {}, "dumped"),                       # exactly -50%
            ({mid: 0.25}, {six: 1.5}, "dumped"),              # a deep fall that recovered is still dumped
            ({mid: 0.5000001}, {}, "in between"),             # just above -50%
            ({mid: 0.7}, {six: 0.8}, "held"),                 # exactly -30% low and -20% close
            ({mid: 0.6999999}, {six: 0.8}, "in between"),     # the low just under -30%
            ({mid: 0.7}, {six: 0.7999999}, "in between"),     # the close just under -20%
            ({}, {six: 1.9}, "held"),                         # never under the scan price
        ]
        for lows, closes, expected in cases:
            with self.subTest(lows=lows, closes=closes):
                rows = with_lows(flat_rows(), lows, closes)
                for r in rows:  # keep the high >= low and the close inside the candle
                    r[2] = max(r[2], r[4])
                    r[3] = min(r[3], r[4])
                m = measure_rows(rows)
                self.assertEqual((m["status"], m["class"]), ("ok", expected))
        self.assertEqual(end + 300, six)
        self.assertEqual((oc.classify(-50.0, 0.0), oc.classify(-30.0, -20.0), oc.classify(-30.000000001, -20.0), oc.classify(-29.0, -20.000000001)),
                         ("dumped", "held", "in between", "in between"))

    def test_float_noise_never_moves_a_class_bar(self):
        p0 = 0.000456
        rows = [[SCAN - SCAN % 300, p0, p0, p0, p0, 1.0], [SCAN - SCAN % 300 + 300, p0, p0, p0 * 0.5, p0, 1.0]]
        self.assertEqual(measure_rows(rows)["class"], "dumped", "0.000228 / 0.000456 is exactly -50%")
        rows = [[SCAN - SCAN % 300, 0.1, 0.1, 0.1, 0.1, 1.0], [SCAN - SCAN % 300 + 300, 0.1, 0.1, 0.07, 0.08, 1.0]]
        self.assertEqual(measure_rows(rows)["class"], "held", "0.07 / 0.1 and 0.08 / 0.1 are exactly -30% and -20%")

    def test_dead_pools_and_empty_candles_read_no_candles_never_held(self):
        empty = oc.parse_candles(json.loads(candles_body([])), MINT, SCAN)
        self.assertEqual(empty, ([], 0, None))
        self.assertEqual(oc.measure([], SCAN)["status"], "no candles")
        before_only = flat_rows(count=2)  # the scan's own candle and the one before: no trade after the scan
        m = measure_rows(before_only)
        self.assertEqual((m["status"], m.get("class")), ("no candles", None))
        old_only = [[SCAN - 86400, 1.0, 1.0, 1.0, 1.0, 1.0]]
        self.assertEqual(measure_rows(old_only)["status"], "no candles")

    def test_unreadable_rows_never_read_as_no_candles(self):
        """R2 (F2): an answer whose rows are all unreadable is candles_unreadable; only a genuinely empty list can be no candles."""
        rows = flat_rows(count=4)
        for name, bad in (("millisecond times", [[r[0] * 1000, *r[1:]] for r in rows]), ("missing fields", [r[:4] for r in rows]),
                          ("text prices", [[r[0], "1", "1", "1", "1", 1] for r in rows])):
            with self.subTest(name):
                payload = json.loads(candles_body([]))
                payload["data"]["attributes"]["ohlcv_list"] = bad
                self.assertEqual(oc.parse_candles(payload, MINT, SCAN), ([], 4, "candles_unreadable"))
        self.assertEqual(oc.parse_candles(json.loads(candles_body([])), MINT, SCAN), ([], 0, None), "a genuinely empty list is not a problem")

    def test_volume_vanished_is_named_and_the_class_is_kept(self):
        rows = [r for r in flat_rows() if r[0] <= SCAN + 3600]  # trading stops about 1 h after the scan
        m = measure_rows(rows)
        self.assertEqual((m["status"], m["volume_vanished"], m["class"]), ("ok", True, "held"))
        self.assertEqual(measure_rows(flat_rows())["volume_vanished"], False)

    def test_the_parse_guards(self):
        rows = flat_rows(count=4)
        bad = [[True, 1, 1, 1, 1, 1], [rows[0][0] * 1000, 1, 1, 1, 1, 1], [rows[1][0], -1.0, 1, 1, 1, 1], [rows[2][0] + 7, float("nan"), 1, 1, 1, 1],
               [rows[3][0] + 1, 1.0, 0.5, 0.9, 0.8, 1.0], ["x"], "row", [rows[0][0], 1.0, 1.0, 1.0]]
        payload = json.loads(candles_body(rows))
        payload["data"]["attributes"]["ohlcv_list"] += bad
        candles, dropped, problem = oc.parse_candles(payload, MINT, SCAN)
        self.assertEqual((len(candles), dropped, problem), (4, 8, None))
        self.assertEqual([c["start"] for c in candles], sorted(r[0] for r in rows), "sorted by start time (the answer is newest first)")
        self.assertEqual(oc.parse_candles(json.loads(candles_body(rows, mint=EVQTA_MINT)), MINT, SCAN)[2], "candles_for_another_token")
        for shape in ({}, {"data": {}}, {"data": {"attributes": {"ohlcv_list": "x"}}}, [], None):
            self.assertEqual(oc.parse_candles(shape, MINT, SCAN)[2], "shape_mismatch")
        no_meta = json.loads(candles_body(rows))
        no_meta.pop("meta")
        self.assertEqual(oc.parse_candles(no_meta, MINT, SCAN)[2], "candles_for_another_token", "the token side must be confirmed")


class LiveAnswerTests(TempDirTest):
    """The GeckoTerminal answers read live on 2026-10-25 (one request each), replayed: the token side, the pool choice and
    the classes. Marvin dumped (-82% at +52 min). mil reads in between: its lowest within 6 h was -43.3% at +5 h 19 min; the
    -88% the earlier evidence recorded came later (about -55% at +7 h; DS-OUTCOMES-T1 evidence, escalated, bars not tuned).
    $BILLIONS dumped (-87% at +1 h, -95% within 6 h)."""

    def test_marvin_dumped_and_mil_in_between_from_the_saved_answers(self):
        copy_run(self.reports, MIL_RUN)
        copy_run(self.reports, MARVIN_RUN)
        opener = Opener([FakeResponse(fixture("mil_ohlcv_5m_live_20261025.json")), FakeResponse(fixture("marvin_ohlcv_5m_live_20261025.json"))])
        run_main(["--reports", str(self.reports)], opener, LATER)
        mil = json.loads((self.reports / MIL_RUN / "outcome.json").read_text())
        marvin = json.loads((self.reports / MARVIN_RUN / "outcome.json").read_text())
        self.assertEqual((marvin["status"], marvin["class"], round(marvin["lowest_6h"]["change_pct"], 2), marvin["lowest_6h"]["after_scan"]),
                         ("ok", "dumped", -82.04, "+52m"))
        self.assertEqual((round(marvin["plus_1h"]["change_pct"], 2), round(marvin["plus_6h"]["change_pct"], 2), marvin["candles_in_window"]), (-73.24, -73.37, 74))
        self.assertEqual((mil["status"], mil["class"], round(mil["lowest_6h"]["change_pct"], 2), mil["lowest_6h"]["after_scan"]), ("ok", "in between", -43.25, "+5h 19m"))
        self.assertEqual((round(mil["plus_1h"]["change_pct"], 2), round(mil["plus_6h"]["change_pct"], 2)), (29.88, -27.07))
        self.assertEqual((mil["price_at_scan_candle_utc"], round(mil["price_at_scan_usd"], 9)), ("2026-10-24T05:00:00Z", 0.000362898))
        for o, pool in ((mil, MIL_POOL), (marvin, MARVIN_POOL)):
            self.assertEqual((o["pool"]["address"], o["pool"]["source"], o["final"], o["volume_vanished"]), (pool, "creator_fees", True, False))
            self.assertEqual((o["scan_time_from"], o["request"]["requests_sent"], o["request"]["keys"]), ("the run folder name (UTC)", 1, "none"))

    def test_billions_dumped_from_the_saved_answer(self):
        copy_run(self.reports, BILLIONS_RUN)
        opener = Opener([FakeResponse(fixture("billions_ohlcv_5m_live_20261025.json"))])
        run_main(["--reports", str(self.reports)], opener, BILLIONS_SCAN_PLUS_3H + 3 * 3600 + 660)
        o = json.loads((self.reports / BILLIONS_RUN / "outcome.json").read_text())
        self.assertEqual((o["status"], o["class"], round(o["lowest_6h"]["change_pct"], 2), o["lowest_6h"]["after_scan"]), ("ok", "dumped", -94.92, "+4h 46m"))
        self.assertEqual((round(o["plus_1h"]["change_pct"], 2), round(o["plus_6h"]["change_pct"], 2), o["pool"]["address"]),
                         (-87.38, -93.93, "3daykMmmqP2J4d9Z3Rg1AZZJdit5vyrSZ2BSJ93aNswr"))
        self.assertIn("/pools/3daykMmmqP2J4d9Z3Rg1AZZJdit5vyrSZ2BSJ93aNswr/ohlcv/minute?aggregate=5&before_timestamp=1792930095&limit=76&token=", opener.requests[0][0])

    def test_the_fallback_pool_is_named_and_read(self):
        run = fallback_run(self.reports)
        pool, how, source = oc.choose_pool(run, EVQTA_MINT)
        self.assertEqual((pool, source), (EVQTA_POOL, "holders_fallback"))
        self.assertTrue(how.startswith("fallback: the largest holders.json pool row, 1.57% of supply (creator_fees empty: no_pump_curve)"), how)
        opener = Opener([FakeResponse(fixture("evqta_fallback_pool_ohlcv_5m_live_20261025.json"))])
        run_main(["--reports", str(self.reports)], opener, LATER)
        o = json.loads((run / "outcome.json").read_text())
        self.assertEqual((o["class"], o["candles_in_window"], round(o["lowest_6h"]["change_pct"], 2)), ("dumped", 68, -73.01), "GeckoTerminal omits candles without trades")
        self.assertIn(f"/pools/{EVQTA_POOL}/", opener.requests[0][0])
        self.assertEqual(read_csv(self.reports / "outcomes.csv")[0]["main pool"], "fallback: largest holders.json pool row")

    def test_an_answer_for_a_rising_coin_reads_in_between(self):
        body = json.loads(fixture("d42t_ohlcv_5m_live_20261025.json"))
        mint, scan = body["meta"]["base"]["address"], 1792461332  # 20261020T015532Z
        candles, dropped, problem = oc.parse_candles(body, mint, scan)
        m = oc.measure(candles, scan)
        self.assertEqual((problem, dropped, m["class"], round(m["plus_6h"]["change_pct"], 2), round(m["lowest_6h"]["change_pct"], 2)), (None, 0, "in between", 109.82, -39.43))

    def test_unreadable_empty_and_mixed_answers_end_to_end(self):
        """R2 (F2): all rows unreadable -> not read (candles unreadable), not final, read again next run; an empty list -> no
        candles, final; some rows good and some unreadable -> read from the good rows, the dropped rows counted."""
        copy_run(self.reports, MARVIN_RUN)
        good = json.loads(fixture("marvin_ohlcv_5m_live_20261025.json"))
        rows = good["data"]["attributes"]["ohlcv_list"]
        unreadable = json.loads(json.dumps(good))
        unreadable["data"]["attributes"]["ohlcv_list"] = [[r[0] * 1000, *r[1:]] for r in rows]
        opener = Opener([FakeResponse(json.dumps(unreadable).encode())])
        code, out = run_main(["--reports", str(self.reports)], opener, LATER)
        o = json.loads((self.reports / MARVIN_RUN / "outcome.json").read_text())
        self.assertEqual((o["status"], o["reason"], o["final"], o["class"], o["candles_read"], o["rows_dropped"]),
                         ("not read (candles unreadable)", "candles_unreadable", False, None, 0, len(rows)))
        self.assertIn(f"{MARVIN_RUN}: not read (candles unreadable); 1 GeckoTerminal request", out)
        empty = json.loads(json.dumps(good))
        empty["data"]["attributes"]["ohlcv_list"] = []
        opener = Opener([FakeResponse(json.dumps(empty).encode())])
        run_main(["--reports", str(self.reports)], opener, LATER)
        o = json.loads((self.reports / MARVIN_RUN / "outcome.json").read_text())
        self.assertEqual((len(opener.requests), o["status"], o["final"], o["class"]), (1, "no candles", True, None), "not final before: read again; empty: final")
        mixed = json.loads(json.dumps(good))
        mixed["data"]["attributes"]["ohlcv_list"] = rows + [[r[0] * 1000, *r[1:]] for r in rows[:5]] + [["x"], [rows[0][0] + 1, "1", 1, 1, 1, 1]]
        opener = Opener([FakeResponse(json.dumps(mixed).encode())])
        run_main(["--reports", str(self.reports), "--refresh"], opener, LATER)
        o = json.loads((self.reports / MARVIN_RUN / "outcome.json").read_text())
        self.assertEqual((o["status"], o["class"], o["candles_read"], o["rows_dropped"], round(o["lowest_6h"]["change_pct"], 2)), ("ok", "dumped", len(rows), 7, -82.04))

    def test_a_missing_pool_is_not_read_with_no_request(self):
        run = self.reports / ("20261022T102356Z-" + "B28EEeqoZ8NhCtkXLmNkWQp2NUp9mixH54V4etaLpump")
        run.mkdir()
        (run / "bubblemaps_map.json").write_text("{}")
        old = self.reports / ("20261017T071103Z-" + "rVWG97Yj6ZbuF9zeQo8TosQG6mUcUeL8BocfHu3pump")
        old.mkdir()
        (old / "holders.json").write_text(json.dumps({"mint": "rVWG97Yj6ZbuF9zeQo8TosQG6mUcUeL8BocfHu3pump", "pool_addresses": [EVQTA_POOL]}))
        opener = Opener([])
        code, out = run_main(["--reports", str(self.reports)], opener, LATER)
        self.assertEqual((code, len(opener.requests)), (0, 0))
        for folder, why in ((run, "holders.json missing"), (old, "holders.json has no holder rows: an older scan format")):
            o = json.loads((folder / "outcome.json").read_text())
            self.assertEqual((o["status"], o["reason"], o["final"], o["request"]["requests_sent"]), ("not read (no pool)", "no_pool", True, 0))
            self.assertIn(why, o["pool"]["how"])
        self.assertIn(f"{run.name}: not read (no pool): creator_fees.json missing; holders.json missing; holder-analysis.json missing; 0 GeckoTerminal requests", out)


class ColumnTests(TempDirTest):
    """(5) the EXIT OVERHANG and FEE/TVL columns come from the two scripts by import; not read when their inputs are missing."""

    def test_exit_overhang_level_and_ratio_come_from_exit_overhang(self):
        for name in (MIL_RUN, MARVIN_RUN, BILLIONS_RUN):
            run = copy_run(self.reports, name)
            m = eo.measure(run)
            self.assertEqual(oc.exit_overhang_cells(run), (eo.level(m["ratio"]), m["ratio"]))
        self.assertEqual(oc.exit_overhang_cells(self.reports / MIL_RUN)[0], "DANGER (provisional)")
        with mock.patch.object(oc.eo, "level", return_value="CAUTION (provisional)") as level:
            self.assertEqual(oc.exit_overhang_cells(self.reports / MIL_RUN)[0], "CAUTION (provisional)", "by import, not a copy")
            level.assert_called_once()
        (self.reports / MIL_RUN / "gmgn_holder_pnl.json").unlink()
        self.assertEqual(oc.exit_overhang_cells(self.reports / MIL_RUN), ("not read (gmgn_holder_pnl.json missing)", None))
        (self.reports / MARVIN_RUN / "holders.json").write_text("{broken")
        self.assertEqual(oc.exit_overhang_cells(self.reports / MARVIN_RUN), ("not read (holders.json unreadable)", None))
        with mock.patch.object(oc.eo, "measure", side_effect=KeyError("x")):
            self.assertEqual(oc.exit_overhang_cells(self.reports / BILLIONS_RUN), ("not read (saved values unreadable)", None))

    def test_a_fallback_main_pool_is_named_in_the_exit_overhang_cell(self):
        run = copy_run(self.reports, BILLIONS_RUN)
        (run / "creator_fees.json").unlink()
        level, ratio = oc.exit_overhang_cells(run)
        self.assertTrue(level.endswith("; main pool by fallback)"), level)
        self.assertEqual(ratio, eo.measure(run)["ratio"])

    def test_fee_tvl_status_comes_from_meteora_pools_present(self):
        run = copy_run(self.reports, BILLIONS_RUN)
        self.assertTrue(oc.fee_tvl_cell(run).startswith("not read (Meteora not read: meteora_pools.json missing"))
        opener = Opener([FakeResponse((FEE_FIX / "meteora_pools_billions_live_20261025.json").read_bytes())])
        saved = mp.collect_meteora_pools(eo.measure(run)["mint"], opener=opener, now=lambda: 1792915555.0, monotonic=lambda: 0.0, sleep=lambda s: None)
        (run / "meteora_pools.json").write_text(json.dumps(saved))
        line = mp.present(run)[0]
        cell = oc.fee_tvl_cell(run)
        self.assertIn(cell, ("WARNING", "meets the bar (not a safety signal)"))
        self.assertTrue(line.startswith(f"{mp.SUMMARY_MARK}{mp.LINE_HEAD}: {cell} — "), line)
        with mock.patch.object(oc.mp, "present", return_value=[f"{mp.SUMMARY_MARK}{mp.LINE_HEAD}: meets the bar (not a safety signal) — x."]):
            self.assertEqual(oc.fee_tvl_cell(run), "meets the bar (not a safety signal)", "by import, not a copy")
        with mock.patch.object(oc.mp, "present", return_value=["something else"]):
            self.assertEqual(oc.fee_tvl_cell(run), "not read (line not recognized)")

    def test_the_flag_columns_read_the_engines_stored_flags(self):
        run = copy_run(self.reports, MIL_RUN)
        self.assertEqual(oc.forensics_flag(run), "not read (assessment.json missing)")
        (run / "assessment.json").write_text(json.dumps({"flag": {"label": "DANGER FLAG (clear large cluster; sources disagree: own detectors read calm)"}}))
        self.assertEqual(oc.forensics_flag(run), "DANGER FLAG (clear large cluster; sources disagree: own detectors read calm)")
        (run / "assessment.json").write_text(json.dumps({"verdict": {"level": "HIGH"}}))
        self.assertEqual(oc.forensics_flag(run), "not read (no flag in assessment.json)")
        (run / "holder-analysis.json").write_text(json.dumps({"mint": MINT, "overall": {"flag": {"label": "CAUTION\n## fake heading"}}}))
        self.assertEqual(oc.analysis_flag(run, MINT), "CAUTION fake heading", "one line, no markdown")
        (run / "holder-analysis.json").write_text(json.dumps({"mint": EVQTA_MINT, "overall": {"flag": {"label": "CAUTION"}}}))
        self.assertEqual(oc.analysis_flag(run, MINT), "not read (holder-analysis.json unreadable)")


class WritesAndWordingTests(TempDirTest):
    """(6) only outcome.json and outcomes.csv are written; (7) no verdict words; (8) assess unchanged, engines never read them."""

    def test_only_outcome_json_and_outcomes_csv_are_written(self):
        for name in (MIL_RUN, MARVIN_RUN, BILLIONS_RUN):
            copy_run(self.reports, name)
        (self.reports / "20261020-cluster-proto").mkdir()
        (self.reports / "20261020-cluster-proto" / "README.md").write_text("not a run folder")
        before = tree_hashes(self.reports)
        opener = Opener([FakeResponse(fixture("mil_ohlcv_5m_live_20261025.json")), FakeResponse(fixture("marvin_ohlcv_5m_live_20261025.json"))])
        code, out = run_main(["--reports", str(self.reports)], opener, BILLIONS_SCAN_PLUS_3H)
        after = tree_hashes(self.reports)
        self.assertEqual(code, 0)
        self.assertEqual({k: v for k, v in after.items() if k in before}, before, "no existing file changed")
        self.assertEqual(sorted(set(after) - set(before)), sorted([f"{MIL_RUN}/outcome.json", f"{MARVIN_RUN}/outcome.json", f"{BILLIONS_RUN}/outcome.json", "outcomes.csv"]))
        self.assertEqual(json.loads((self.reports / BILLIONS_RUN / "outcome.json").read_text())["status"], "pending")
        rows = read_csv(self.reports / "outcomes.csv")
        self.assertEqual([r["run"] for r in rows], sorted([MIL_RUN, MARVIN_RUN, BILLIONS_RUN]), "one row per run folder, none for other folders")
        self.assertEqual(list(rows[0]), list(oc.CSV_COLUMNS))

    def test_the_csv_row_and_the_summary(self):
        for name in (MIL_RUN, MARVIN_RUN):
            copy_run(self.reports, name)
        opener = Opener([FakeResponse(fixture("mil_ohlcv_5m_live_20261025.json")), FakeResponse(fixture("marvin_ohlcv_5m_live_20261025.json"))])
        code, out = run_main(["--reports", str(self.reports)], opener, LATER)
        rows = {r["run"]: r for r in read_csv(self.reports / "outcomes.csv")}
        marvin = rows[MARVIN_RUN]
        self.assertEqual((marvin["scan time (UTC)"], marvin["scan time (WIB)"], marvin["EXIT OVERHANG"], marvin["outcome status"], marvin["class"]),
                         ("2026-10-25 03:17 UTC", "2026-10-25 10:17 WIB", "DANGER (provisional)", "ok", "dumped"))
        self.assertEqual((marvin["price at scan (USD)"], marvin["change at 1 h (%)"], marvin["change at 6 h (%)"], marvin["lowest price within 6 h (%)"]),
                         ("0.000599441", "-73.24", "-73.37", "-82.04"))
        self.assertEqual(marvin["EXIT OVERHANG ratio (x)"], f"{eo.measure(self.reports / MARVIN_RUN)['ratio']:.2f}")
        self.assertEqual(rows[MIL_RUN]["class"], "in between")
        for needle in ("scans: 2; classed: 2; dumped 1; held 0; in between 1; not classed 0", "EXIT OVERHANG level x class (scans):",
                       "  level | dumped | held | in between | no class", "  DANGER | 1 | 0 | 1 | 0", "forensics FLAG x class (scans):", "  not read | 1 | 0 | 1 | 0",
                       "coins that held so far: 0 (target about 10 before the bars can be judged)", "PROVISIONAL and unvalidated",
                       "the EXIT OVERHANG and FEE/TVL bars stay unvalidated until about 10 held coins are on record", "it is not a safety signal"):
            self.assertIn(needle, out, needle)

    def test_held_coins_are_counted_once_per_coin(self):
        def row(run, mint, klass, level="not read (x)", flag="CAUTION"):
            return {"run": run, "mint": mint, "class": klass, "outcome status": "ok" if klass else "pending", "EXIT OVERHANG": level, "forensics FLAG": flag, "note": ""}
        rows = [row("a", "M1", "held"), row("b", "M1", "held"), row("c", "M2", "held", "not raised (not a safety signal)"), row("d", "M3", "dumped", "DANGER (provisional)"),
                row("e", "M4", "")]
        lines = oc.summary_lines(rows)
        self.assertIn("coins that held so far: 2 (target about 10 before the bars can be judged)", lines)
        self.assertIn("  (1 held scan; a coin counts once; held means only that the price stayed inside those bars for 6 h; it is not a safety signal)",
                      oc.summary_lines(rows[2:]))
        self.assertIn("  (3 held scans; a coin counts once; held means only that the price stayed inside those bars for 6 h; it is not a safety signal)", lines)
        self.assertIn("  not raised | 0 | 1 | 0 | 0", lines)
        self.assertIn("  CAUTION | 1 | 3 | 0 | 1", lines)

    def test_no_verdict_words_and_held_never_called_safe(self):
        for name in (MIL_RUN, MARVIN_RUN):
            copy_run(self.reports, name)
        opener = Opener([FakeResponse(fixture("mil_ohlcv_5m_live_20261025.json")), FakeResponse(fixture("marvin_ohlcv_5m_live_20261025.json"))])
        code, out = run_main(["--reports", str(self.reports)], opener, LATER)
        texts = [out, (self.reports / "outcomes.csv").read_text(), *(json.dumps(json.loads((self.reports / n / "outcome.json").read_text())) for n in (MIL_RUN, MARVIN_RUN))]
        for text in texts:
            self.assertIsNone(REASSURING.search(text.replace("NO FLAG RAISED (not a safety signal)", "")), text[:200])
        self.assertIsNone(re.search(r"(?i)held[^.;\n]{0,40}\bsafe", out))
        for text in (oc.NOTE, oc.HELD_NOTE, oc.CLASS_RULE, oc.CANNOT_SEE, " ".join(oc.summary_lines([]))):
            self.assertIsNone(REASSURING.search(text), text)

    def test_csv_cells_cannot_become_spreadsheet_formulas(self):
        self.assertEqual(oc._cell("forensics FLAG", "=HYPERLINK(\"x\")"), "'=HYPERLINK(\"x\")")
        for text in ("+1", "-x", "@x"):
            self.assertTrue(oc._cell("note", text).startswith("'"))
        self.assertEqual((oc._cell("change at 6 h (%)", -27.0650773), oc._cell("price at scan (USD)", 0.000362897781), oc._cell("class", None)), ("-27.07", "0.000362898", ""))
        self.assertEqual(oc.price_text(1234.5678), "1234.57")
        self.assertFalse([c for c in oc.CSV_COLUMNS if c[:1] in "=+-@"], "no header a spreadsheet would read as a formula")

    def test_no_network_on_import_and_the_transport_is_bounded(self):
        self.assertEqual(oc.MAX_BYTES, 2 * 1024 * 1024)
        clock = Clock()
        huge = FakeResponse(b"x" * (oc.MAX_BYTES + 1))
        with self.assertRaises(oc.Failure) as ctx:
            oc.send_once(oc.build_request(POOL, MINT, SCAN), Opener([huge]), POOL, MINT, SCAN, monotonic=clock.monotonic)
        self.assertEqual(ctx.exception.reason, "response_too_large")
        with self.assertRaises(oc.Failure) as ctx:
            oc.send_once(oc.build_request(POOL, MINT, SCAN), Opener([FakeResponse(b"{}", status=302)]), POOL, MINT, SCAN, monotonic=clock.monotonic)
        self.assertEqual(ctx.exception.reason, "redirect_disallowed")



class RateLimitStopTests(TempDirTest):
    """AMENDMENT A1: a 429 still there after the one retry stops the run; every later scan that needs a request reads
    "not read (rate limited; run again later)" with no request, not final, and the next run reads it. Scans that need no
    request (pending, no pool) are handled as usual. Under --refresh, later scans keep their final outcomes; only the scan
    whose own request met the lasting 429 loses its earlier outcome, and the next run reads it again (one request)."""

    NOW = 1792908195 + oc.READY_AFTER_S + 60  # mil, Marvin and $BILLIONS all ready
    YOUNG = "20261025T120000Z-" + "B28EEeqoZ8NhCtkXLmNkWQp2NUp9mixH54V4etaLpump"  # 12:00 UTC: pending at NOW
    NO_POOL = "20261024T120000Z-" + "B28EEeqoZ8NhCtkXLmNkWQp2NUp9mixH54V4etaLpump"  # between mil and Marvin, no pool files

    def setUp(self):
        super().setUp()
        for name in (MIL_RUN, MARVIN_RUN, BILLIONS_RUN):
            copy_run(self.reports, name)
        for name in (self.YOUNG, self.NO_POOL):
            (self.reports / name).mkdir()

    def outcome(self, name):
        return json.loads((self.reports / name / "outcome.json").read_text())

    def test_a_persistent_429_stops_the_run_and_the_next_run_reads_the_rest(self):
        clock = Clock()
        opener = Opener([http_error(429), http_error(429)], clock)
        code, out = run_main(["--reports", str(self.reports)], opener, self.NOW, clock)
        self.assertEqual((code, len(opener.requests)), (0, 2), "the scan's request and its one retry, then nothing")
        for name, reason, sent in ((MIL_RUN, "rate_limited", 2), (MARVIN_RUN, "not_sent_run_stopped", 0), (BILLIONS_RUN, "not_sent_run_stopped", 0)):
            o = self.outcome(name)
            self.assertEqual((o["status"], o["reason"], o["final"], o["request"]["requests_sent"]), (oc.RATE_LIMITED, reason, False, sent), name)
        self.assertEqual(self.outcome(self.NO_POOL)["status"], "not read (no pool)", "no request needed: handled as usual")
        self.assertEqual(self.outcome(self.YOUNG)["status"], "pending")
        self.assertIn("run stopped: GeckoTerminal still answered 429 (rate limited) after the one retry", out)
        self.assertIn("not read (rate limited; run again later): 3 scans; run the command again in a few minutes and they are read then", out)
        self.assertEqual({r["run"]: r["outcome status"] for r in read_csv(self.reports / "outcomes.csv")}[MARVIN_RUN], oc.RATE_LIMITED)
        clock = Clock()
        opener = Opener([FakeResponse(fixture(n)) for n in ("mil_ohlcv_5m_live_20261025.json", "marvin_ohlcv_5m_live_20261025.json", "billions_ohlcv_5m_live_20261025.json")], clock)
        code, out = run_main(["--reports", str(self.reports)], opener, self.NOW, clock)
        self.assertEqual(len(opener.requests), 3, "not final: the next run reads them")
        self.assertEqual([self.outcome(n)["class"] for n in (MIL_RUN, MARVIN_RUN, BILLIONS_RUN)], ["in between", "dumped", "dumped"])
        starts = [r[2] for r in opener.requests]
        self.assertTrue(all(b - a >= oc.PACING_S for a, b in zip(starts, starts[1:])), starts)
        self.assertNotIn("run stopped", out)
        self.assertNotIn("rate limited; run again later", out)

    def test_other_failures_do_not_stop_the_run(self):
        opener = Opener([http_error(500), FakeResponse(fixture("marvin_ohlcv_5m_live_20261025.json")), FakeResponse(fixture("billions_ohlcv_5m_live_20261025.json"))])
        run_main(["--reports", str(self.reports)], opener, self.NOW)
        self.assertEqual((len(opener.requests), self.outcome(MIL_RUN)["status"], self.outcome(MARVIN_RUN)["status"]), (3, "not read (server_error)", "ok"))

    def test_a_stopped_refresh_keeps_later_final_outcomes_and_re_reads_the_429_scan_next_run(self):
        opener = Opener([FakeResponse(fixture(n)) for n in ("mil_ohlcv_5m_live_20261025.json", "marvin_ohlcv_5m_live_20261025.json", "billions_ohlcv_5m_live_20261025.json")])
        run_main(["--reports", str(self.reports)], opener, self.NOW)
        kept = {n: (self.reports / n / "outcome.json").read_bytes() for n in (MARVIN_RUN, BILLIONS_RUN)}
        opener = Opener([http_error(429), http_error(429)])
        code, out = run_main(["--reports", str(self.reports), "--refresh"], opener, self.NOW)
        self.assertEqual((len(opener.requests), self.outcome(MIL_RUN)["status"]), (2, oc.RATE_LIMITED))
        self.assertEqual({n: (self.reports / n / "outcome.json").read_bytes() for n in kept}, kept, "the final outcomes after the stop stay as they were")
        self.assertFalse(self.outcome(MIL_RUN)["final"], "the scan that met the 429 lost its earlier outcome: not final")
        opener = Opener([FakeResponse(fixture("mil_ohlcv_5m_live_20261025.json"))])
        run_main(["--reports", str(self.reports)], opener, self.NOW)
        self.assertEqual((len(opener.requests), self.outcome(MIL_RUN)["class"]), (1, "in between"), "the next run reads it again, at the cost of one request")


class AnalysisPoolFallbackTests(TempDirTest):
    """AMENDMENT A1: when neither creator_fees.json nor holders.json names a pool, the largest liquidity_pool row of
    holder-analysis.json for this mint is the main pool, named "(pool from holder-analysis.json)"."""

    MINT = "rVWG97Yj6ZbuF9zeQo8TosQG6mUcUeL8BocfHu3pump"
    RUN = "20261017T071103Z-" + MINT
    POOL = "E3uzs2APAc4m6CSTCEZDA65yY1orfTvhCGotWyEjbbzr"
    SCAN = int(oc.parse_run_name(RUN)[0])  # 2026-10-17T07:11:03Z

    def make(self, rows, mint=None, holders_rows=None):
        run = self.reports / self.RUN
        run.mkdir(exist_ok=True)
        holders = {"mint": self.MINT, "pool_addresses": [self.POOL, EVQTA_POOL]}  # the older format: no holder rows
        if holders_rows is not None:
            holders["top_holders"] = holders_rows
        (run / "holders.json").write_text(json.dumps(holders))
        (run / "holder-analysis.json").write_text(json.dumps({"schema": "holder-analysis/1", "mint": mint or self.MINT, "top_holders": rows}))
        return run

    def lp(self, owner, share, kind="liquidity_pool"):
        return {"kind": kind, "owner": owner, "share": share, "amount": 1.0}

    def test_the_largest_liquidity_pool_row_is_named(self):
        run = self.make([self.lp("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", 0.30, kind="wallet"), self.lp(EVQTA_POOL, 0.05), self.lp(self.POOL, 0.056817),
                         self.lp("not-an-address", 0.40), self.lp("8FEerSaxBGmZXv2ZtM3pD6qWrcGBGSBmEp2iRBtPxuhR", "0.9"),
                         self.lp("9wQczRH7uhAVqTkFHqF1tqb6zgZjjq1KcQzw9b5Ri1yN", 1.5), "row"])
        pool, how, source = oc.choose_pool(run, self.MINT)
        self.assertEqual((pool, source), (self.POOL, "analysis_fallback"))
        self.assertEqual(how, "fallback (pool from holder-analysis.json): the largest liquidity_pool row, 5.68% of supply (creator_fees.json missing; "
                              "holders.json has no holder rows: an older scan format); it could be another pool of the token")

    def test_the_token_side_is_checked_and_rows_without_a_pool_read_no_pool(self):
        run = self.make([self.lp(self.POOL, 0.05)], mint=EVQTA_MINT)
        pool, how, _ = oc.choose_pool(run, self.MINT)
        self.assertIsNone(pool)
        self.assertTrue(how.endswith("holder-analysis.json is for another mint"), how)
        run = self.make([self.lp(self.POOL, 0.05, kind="wallet"), self.lp(self.POOL, 0.0)])
        self.assertEqual(oc.choose_pool(run, self.MINT)[1], "creator_fees.json missing; holders.json has no holder rows: an older scan format; "
                                                            "holder-analysis.json has no liquidity_pool row")
        (run / "holder-analysis.json").write_text("{broken")
        self.assertTrue(oc.choose_pool(run, self.MINT)[1].endswith("holder-analysis.json unreadable"))

    def test_creator_fees_and_holders_json_come_first(self):
        holder_row = [{"rank": 1, "wallet": EVQTA_POOL, "share_pct": 1.2, "infrastructure": True}]
        run = self.make([self.lp(self.POOL, 0.20)], holders_rows=holder_row)
        self.assertEqual(oc.choose_pool(run, self.MINT)[:1] + oc.choose_pool(run, self.MINT)[2:], (EVQTA_POOL, "holders_fallback"))
        (run / "creator_fees.json").write_text(json.dumps({"schema": eo.FEES_SCHEMA, "mint": self.MINT, "status": "ok", "reason": None,
                                                            "pools": [{"address": "Af7W724Kw2A7Z5PbaCAS6RNQ8ubiKEWqiSa715bxgbFA", "status": "identified", "base_mint": self.MINT}]}))
        self.assertEqual(oc.choose_pool(run, self.MINT)[2], "creator_fees")

    def test_end_to_end_the_request_goes_to_that_pool_and_the_candles_token_side_is_checked(self):
        run = self.make([self.lp(self.POOL, 0.056817)])
        rows = flat_rows(scan=self.SCAN)
        opener = Opener([FakeResponse(candles_body(rows, mint=self.MINT))])
        run_main(["--reports", str(self.reports)], opener, self.SCAN + oc.READY_AFTER_S)
        self.assertIn(f"/pools/{self.POOL}/ohlcv/minute?aggregate=5&before_timestamp={self.SCAN + 21900}&limit=76&token={self.MINT}", opener.requests[0][0])
        o = json.loads((run / "outcome.json").read_text())
        self.assertEqual((o["status"], o["class"], o["pool"]["source"]), ("ok", "held", "analysis_fallback"))
        self.assertEqual(read_csv(self.reports / "outcomes.csv")[0]["main pool"], "fallback: largest liquidity_pool row (pool from holder-analysis.json)")
        opener = Opener([FakeResponse(candles_body(rows, mint=EVQTA_MINT))])
        run_main(["--reports", str(self.reports), "--refresh"], opener, self.SCAN + oc.READY_AFTER_S)
        self.assertEqual(json.loads((run / "outcome.json").read_text())["status"], "not read (candles_for_another_token)")


class AssessUnchangedTests(unittest.TestCase):
    """(8) assess never reads outcome.json or outcomes.csv: the same assessment.json and report.md with or without them, and
    neither engine names them."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="outcomes-assess-"))
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

    def test_the_new_files_change_nothing(self):
        outcome = {"schema": oc.SCHEMA, "run": self.run_dir.name, "mint": self.mint, "status": "ok", "class": "dumped", "final": True}
        for extra, tag in ((["--bubblemaps-json", str(self.space_map)], "map"), (["--bubblemaps-json", str(self.alarm_map)], "alarm"), ([], "no-map")):
            with self.subTest(tag):
                code, err, before, md_before = self.assess(extra, f"{tag}-without")
                self.assertEqual(code, 0, err)
                (self.run_dir / oc.OUT_FILE).write_text(json.dumps(outcome))
                (self.tmp / oc.CSV_FILE).write_text("run,class\nspace-run,dumped\n")
                try:
                    code, err, after, md_after = self.assess(extra, f"{tag}-with")
                finally:
                    (self.run_dir / oc.OUT_FILE).unlink()
                    (self.tmp / oc.CSV_FILE).unlink()
                self.assertEqual(code, 0, err)
                self.assertEqual((after, md_after), (before, md_before))
        _, _, alarm, _ = self.assess(["--bubblemaps-json", str(self.alarm_map)], "alarm-check")
        self.assertTrue(alarm["flag"]["label"].startswith(hf.FLAG_DANGER), "the map alarm stands; an outcome never changes a FLAG")

    def test_neither_engine_names_the_outcome_files(self):
        for engine in [SCRIPTS / "helius_forensics.py", SCRIPTS / "holder_analysis.py", *sorted((SCRIPTS / "ha").glob("*.py"))]:
            text = engine.read_text(encoding="utf-8")
            for needle in ("outcome.json", "outcomes.csv", "outcomes.py", "import outcomes", "geckoterminal"):
                self.assertNotIn(needle, text, (engine.name, needle))


if __name__ == "__main__":
    unittest.main()
