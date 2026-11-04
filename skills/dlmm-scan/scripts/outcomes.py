#!/usr/bin/env python3
"""What the price did after each saved dlmm-scan (DS-OUTCOMES-T1): the price 1 h and 6 h after the scan, from
GeckoTerminal's free 5-minute candles, written next to the warnings the scan raised.

Owner (2026-10-25, HS-OVERHANG-T1): "Small script, next ticket (Recommended)": a free script that fills in the 1 h / 6 h
price for each saved scan, so the EXIT OVERHANG bars and Yun's fee/TVL bars can be checked against coins that held, not
only against coins that dumped. No paid calls.

MAINTENANCE ONLY, NOT A SCAN LANE: run it by hand (the owner asks, or the synthesis reminds the owner 6 h after a scan);
it is never part of a scan wave, never on by default and never an engine input. It never changes a FLAG, verdict or
threshold.

Request (GeckoTerminal public API, provider-docs cache current/geckoterminal/apiguide.md: root
https://api.geckoterminal.com/api/v2, no key, 30 calls a minute, OHLCV by pool address with timeframe day | hour | minute
and an aggregate, timestamps in unix seconds; the ohlcv endpoint takes a token address of the pool (changelog, 28 February
2024)), exactly one per saved scan:
  GET /api/v2/networks/solana/pools/<POOL>/ohlcv/minute?aggregate=5&before_timestamp=<scan + 6 h + 5 min>&limit=76&token=<MINT>
76 five-minute candles cover the scan time - 10 min to the scan time + 6 h. Host api.geckoterminal.com only, https only, that
path and query only (checked before every send), no key, no redirects, no environment proxy, 2 MiB and a hard 30 s
wall-clock limit per attempt (the bounded worker of meteora_pools.py, by import); one request start every 12 s at most
(PACING_S: 5 a minute; on 2026-10-25 GeckoTerminal let about 5 requests through at 24 a minute and then answered 429, below
its documented 30); at most one retry, only after a 429 (its Retry-After within 60 s, else 20 s). A 429 still there after
the one retry stops the run: that scan and every later scan that needs a request read "not read (rate limited; run again
later)", not final, so the next run reads them.

Main pool: the creator_fees.json canonical PumpSwap pool of the token, else the largest holders.json pool row (named as a
fallback; the same reads exit_overhang.py uses, by import), else the largest liquidity_pool row of holder-analysis.json
for this mint (named "(pool from holder-analysis.json)"; older scans saved no holder rows in holders.json). None of the
three: "not read (no pool)", no request.

Per run it writes <RUN>/outcome.json and nothing else in the run folder: the scan time (from the folder name, UTC), the pool
and how it was chosen, the price at scan (the close of the candle containing the scan time; else the last candle in the 10
minutes before), the change at +1 h and +6 h (closes of the candles containing those times, or the last before them), the
lowest price within 6 h and when, the highest price within 6 h, the candles read, and the status: ok, pending (a scan
younger than 6 h 10 min: the candle holding the 6 h mark must be closed and indexed; no request), not read (<reason>) or
no candles (an empty candle list, or readable candles with no trade in the 6 h after the scan: a dead pool, never held).
An answer whose candle rows are all unreadable is "not read (candles unreadable)", not final: the next run reads it again. Then it rebuilds <REPORTS>/outcomes.csv (one row
per run folder) with the forensics FLAG, the analysis FLAG, the EXIT OVERHANG level and ratio (exit_overhang.py, by import)
and the FEE/TVL status (meteora_pools.py --present's line, by import) next to the outcome, and prints a summary.

Classes (PROVISIONAL, unvalidated; see the constants below): dumped when the lowest price within 6 h is 50% or more under
the price at scan; held when the lowest price stayed within 30% and the +6 h close is at most 20% down; in between otherwise.
"held" means only that the price stayed inside those bars for 6 h: it is not a safety signal. The bars of the scan stay
unvalidated until about 10 held coins are on record.

Usage: outcomes.py --reports <DIR> [--run <FOLDER> ...] [--refresh] [--dry-run]. A run folder is read when it has no
outcome.json, or one that is not final (pending, or a request that failed); --refresh reads every run folder again;
--run limits the reads to the named folders (outcomes.csv still lists every run folder). --dry-run prints the plan only:
no request, nothing written. Exit 0 when done, 2 for a bad command line or an unwritable file. Standard library only;
Python >= 3.10.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import math
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

if str(Path(__file__).resolve().parent) not in sys.path:  # python3 -I leaves the script's folder off sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import exit_overhang as eo  # noqa: E402  (the EXIT OVERHANG level and ratio, and the main-pool reads, by import)
import meteora_pools as mp  # noqa: E402  (the FEE/TVL line, and the bounded transport worker, by import)

# ----------------------------------------------------------------------------- PROVISIONAL (unvalidated)
# DS-OUTCOMES-T1 (2026-10-25): first definitions, not tuned on any data. They label what the price did; they are not a
# trade signal and never feed a FLAG. Review them when about 10 held coins are on record.
DUMPED_LOWEST_PCT = -50.0       # lowest price within 6 h at or under this change from the price at scan: dumped
HELD_LOWEST_PCT = -30.0         # held: the lowest price within 6 h at or above this change ...
HELD_CLOSE_6H_PCT = -20.0       # ... and the +6 h close at or above this change; anything else is in between
HELD_TARGET = 10                # held coins wanted on record before the bars can be judged
# ----------------------------------------------------------------------------- end PROVISIONAL

HOST = "api.geckoterminal.com"
NETWORK = "solana"
TIMEFRAME = "minute"
AGGREGATE = 5
CANDLE_S = 300                  # one 5-minute candle; GeckoTerminal stamps a candle with its start, in unix seconds
BEFORE_S = 600                  # the window starts 10 min before the scan
PLUS_1H_S = 3600
WINDOW_S = 6 * 3600             # the window ends 6 h after the scan
READY_AFTER_S = WINDOW_S + 600  # read 6 h 10 min after the scan: the candle holding the 6 h mark is closed and indexed
VANISHED_S = 3600               # no candle in the last hour of the window: "volume vanished" is named, the class stays
LIMIT = (BEFORE_S + WINDOW_S + CANDLE_S) // CANDLE_S + 1  # 76 candles: 75 intervals plus one for the alignment
PACING_S = 12.0                 # one request start every 12 s at most: 5 a minute (DS-OUTCOMES-T1 A1: 429s came at 24 a minute)
RETRY_MAX_WAIT_S = 60.0         # retry a 429 once only when its Retry-After ends this soon
RETRY_DEFAULT_WAIT_S = 20.0     # a 429 without Retry-After is retried once after this wait
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = 30.0                # per attempt: a hard wall-clock limit on open + every read + close (worker thread)
USER_AGENT = "holder-scan-outcomes/1.0"
OUT_FILE = "outcome.json"
CSV_FILE = "outcomes.csv"
SCHEMA = "holder-scan-outcome/1"
RUN_RE = re.compile(r"^(\d{8}T\d{6}Z)-([1-9A-HJ-NP-Za-km-z]{32,44})$")
SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
LABEL_RE = re.compile(r"[^A-Za-z0-9 ()_:;,.'/%+-]")
WIB = dt.timezone(dt.timedelta(hours=7))
HTTP_REASONS = {400: "bad_request", 401: "access_denied", 403: "access_denied", 404: "pool_not_on_geckoterminal", 429: "rate_limited",
                503: "service_unavailable"}
FINAL_FAILURES = ("bad_request", "pool_not_on_geckoterminal")  # a read that failed for these is not retried on the next run
RATE_LIMITED = "not read (rate limited; run again later)"     # a 429 after the one retry, and every later scan of that run
PROBLEM_TEXT = {"candles_unreadable": "candles unreadable"}     # status words for a parse problem (else its reason code)
ANALYSIS_FILE = "holder-analysis.json"
ANALYSIS_POOL_KIND = "liquidity_pool"
CLASSES = ("dumped", "held", "in between")
NOT_CLASSED = "no class"
CLASS_RULE = (f"dumped = the lowest price within 6 h at least {-DUMPED_LOWEST_PCT:g}% under the price at scan; held = the lowest price "
              f"within {-HELD_LOWEST_PCT:g}% and the 6 h close at most {-HELD_CLOSE_6H_PCT:g}% down; in between otherwise; "
              "PROVISIONAL and unvalidated")
HELD_NOTE = "held means only that the price stayed inside those bars for 6 h; it is not a safety signal"
NOTE = ("maintenance only, never part of a scan; an outcome is never an engine input and never changes a FLAG, verdict or "
        "threshold; " + HELD_NOTE)
CANNOT_SEE = ("one pool only (the scan's main pool): a token that moved to another pool after the scan is followed on the old pool "
              "(see volume_vanished); 5-minute candles hide moves inside a candle's open and close; GeckoTerminal lists only candles "
              "with trades")
CSV_COLUMNS = ("run", "mint", "scan time (UTC)", "scan time (WIB)", "forensics FLAG", "analysis FLAG", "EXIT OVERHANG", "EXIT OVERHANG ratio (x)",
               "FEE/TVL", "outcome status", "main pool", "price at scan (USD)", "change at 1 h (%)", "change at 6 h (%)",
               "lowest price within 6 h (%)", "class", "note")


class Failure(Exception):
    """A failed attempt, reduced to a fixed reason code. Never carries request or response text."""

    def __init__(self, reason: str, http_status: int | None = None, retry_wait: float | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status
        self.retry_wait = retry_wait


# ----------------------------------------------------------------------------- times


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def utc_text(ts: float) -> str:
    return f"{dt.datetime.fromtimestamp(ts, dt.timezone.utc):%Y-%m-%d %H:%M} UTC"


def wib_text(ts: float) -> str:
    return f"{dt.datetime.fromtimestamp(ts, WIB):%Y-%m-%d %H:%M} WIB"


def after_text(seconds: float) -> str:
    """An offset from the scan cut toward zero: "+2h 05m", "+40m"."""
    minutes = int(max(0.0, seconds) // 60)
    return f"+{minutes // 60}h {minutes % 60:02d}m" if minutes >= 60 else f"+{minutes}m"


def parse_run_name(name: str) -> tuple[float, str] | None:
    """(scan time as unix seconds, mint) from a run folder name <YYYYMMDDTHHMMSSZ>-<MINT>; anything else is None."""
    match = RUN_RE.fullmatch(name)
    if not match:
        return None
    try:
        when = dt.datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None
    return when.timestamp(), match.group(2)


# ----------------------------------------------------------------------------- the main pool (offline)


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None


def _holders_pool(run: Path, mint: str) -> tuple[str | None, float | None, str]:
    """(the largest holders.json pool row: an infrastructure row listed in pool_addresses, the rows exit_overhang reads, its
    share in percent, or None and why)."""
    holders = _read(run / eo.HOLDERS_FILE)
    if not (run / eo.HOLDERS_FILE).exists():
        return None, None, f"{eo.HOLDERS_FILE} missing"
    if isinstance(holders, dict) and holders.get("mint") == mint and not isinstance(holders.get("top_holders"), list):
        return None, None, f"{eo.HOLDERS_FILE} has no holder rows: an older scan format"
    try:
        shares, infra, pools = eo._holder_shares(eo._load_holders(run, mint))
    except eo.NotRead as problem:
        return None, None, str(problem)
    candidates = [(share, wallet) for wallet, share in infra.items() if wallet in pools and share > 0]
    if not candidates:
        return None, None, f"{eo.HOLDERS_FILE} has no pool row"
    share, wallet = max(candidates)
    return wallet, share, ""


def _analysis_pool(run: Path, mint: str) -> tuple[str | None, float | None, str]:
    """(the largest liquidity_pool row of holder-analysis.json for this mint, its share in percent, or None and why). The
    file must name this mint (the token side, as for the other two files); a row counts only with kind liquidity_pool, a
    valid address as owner and a share (a fraction of supply) above 0 and at most 1."""
    path = run / ANALYSIS_FILE
    data = _read(path)
    if not path.exists():
        return None, None, f"{ANALYSIS_FILE} missing"
    if not (isinstance(data, dict) and isinstance(data.get("top_holders"), list)):
        return None, None, f"{ANALYSIS_FILE} unreadable"
    if data.get("mint") != mint:
        return None, None, f"{ANALYSIS_FILE} is for another mint"
    candidates = []
    for row in data["top_holders"]:
        if not isinstance(row, dict) or row.get("kind") != ANALYSIS_POOL_KIND:
            continue
        owner, share = row.get("owner"), _number(row.get("share"))
        if isinstance(owner, str) and SOLANA_ADDRESS_RE.fullmatch(owner) and share is not None and 0 < share <= 1:
            candidates.append((share * 100, owner))
    if not candidates:
        return None, None, f"{ANALYSIS_FILE} has no {ANALYSIS_POOL_KIND} row"
    share, owner = max(candidates)
    return owner, share, ""


def choose_pool(run: Path, mint: str) -> tuple[str | None, str, str | None]:
    """(pool address or None, how it was chosen or why there is none, source "creator_fees" / "holders_fallback" /
    "analysis_fallback" / None). The creator_fees.json canonical pool first (exit_overhang's read), else the largest
    holders.json pool row, else the largest liquidity_pool row of holder-analysis.json; each fallback is named."""
    address, why = eo._canonical_pool(run, mint)
    if address is not None:
        return address, "creator_fees.json: the canonical PumpSwap pool of this token", "creator_fees"
    pool, share, holders_why = _holders_pool(run, mint)
    if pool is not None:
        return pool, (f"fallback: the largest {eo.HOLDERS_FILE} pool row, {share:.2f}% of supply ({why}); it could be another pool "
                      "of the token"), "holders_fallback"
    pool, share, analysis_why = _analysis_pool(run, mint)
    if pool is not None:
        return pool, (f"fallback (pool from {ANALYSIS_FILE}): the largest {ANALYSIS_POOL_KIND} row, {share:.2f}% of supply ({why}; "
                      f"{holders_why}); it could be another pool of the token"), "analysis_fallback"
    return None, f"{why}; {holders_why}; {analysis_why}", None


# ----------------------------------------------------------------------------- request


def ohlcv_path(pool: str) -> str:
    return f"/api/v2/networks/{NETWORK}/pools/{pool}/ohlcv/{TIMEFRAME}"


def window_end(scan_ts: float) -> int:
    """before_timestamp: the scan time + 6 h + one candle, in whole unix seconds."""
    return int(scan_ts) + WINDOW_S + CANDLE_S


def ohlcv_query(mint: str, scan_ts: float) -> str:
    return f"aggregate={AGGREGATE}&before_timestamp={window_end(scan_ts)}&limit={LIMIT}&token={mint}"


def check_url(url: str, pool: str, mint: str, scan_ts: float) -> None:
    """https only, host api.geckoterminal.com only, port 443, no credentials, the ohlcv path of this pool with exactly the
    fixed query for this run. Raises Failure with a fixed code."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise Failure("scheme_not_https")
    try:
        port = parsed.port
    except ValueError:
        raise Failure("host_not_allowlisted") from None
    if parsed.hostname != HOST or port not in (None, 443) or parsed.username or parsed.password:
        raise Failure("host_not_allowlisted")
    if not (SOLANA_ADDRESS_RE.fullmatch(pool) and SOLANA_ADDRESS_RE.fullmatch(mint)):
        raise Failure("path_not_allowlisted")
    if parsed.path != ohlcv_path(pool) or parsed.query != ohlcv_query(mint, scan_ts) or parsed.params or parsed.fragment:
        raise Failure("path_not_allowlisted")


def build_request(pool: str, mint: str, scan_ts: float) -> urllib.request.Request:
    url = f"https://{HOST}{ohlcv_path(pool)}?{ohlcv_query(mint, scan_ts)}"
    check_url(url, pool, mint, scan_ts)
    request = urllib.request.Request(url, method="GET")
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", USER_AGENT)
    return request


def _retry_after(exc: urllib.error.HTTPError) -> float | None:
    """The wait before the one retry after a 429: its Retry-After seconds when they end within RETRY_MAX_WAIT_S,
    RETRY_DEFAULT_WAIT_S without one; None (no retry) when it asks for longer or is unreadable."""
    headers = getattr(exc, "headers", None)
    raw = headers.get("Retry-After") if headers is not None else None
    if raw is None:
        return RETRY_DEFAULT_WAIT_S
    text = str(raw).strip()
    if not re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,3})?", text):
        return None
    wait = max(PACING_S, float(text))
    return wait if wait <= RETRY_MAX_WAIT_S else None


def send_once(request: urllib.request.Request, opener: Any, pool: str, mint: str, scan_ts: float, *, monotonic: Callable[[], float]) -> bytes:
    """One attempt. Returns the body (at most MAX_BYTES) or raises Failure with a fixed code. Opening, every read and the
    error close run under one hard wall-clock deadline of TIMEOUT_S (meteora_pools' bounded worker). An error body is never
    read."""
    check_url(request.full_url, pool, mint, scan_ts)
    deadline = monotonic() + TIMEOUT_S

    def remaining() -> float:
        return deadline - monotonic()

    response = None
    try:
        response = mp._bounded_call(lambda: opener.open(request, timeout=TIMEOUT_S), remaining())
        status = int(getattr(response, "status", 200) or 200)
        if 300 <= status < 400:
            raise Failure("redirect_disallowed", status)
        if status != 200:
            raise Failure(HTTP_REASONS.get(status, "server_error" if 500 <= status <= 599 else "http_error"), status)
        chunks, total = [], 0
        while True:
            chunk = mp._bounded_call(lambda: response.read(65536), remaining())
            if not isinstance(chunk, bytes):
                raise Failure("invalid_response")
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_BYTES:
                raise Failure("response_too_large")
            chunks.append(chunk)
        return b"".join(chunks)
    except Failure:
        raise
    except urllib.error.HTTPError as exc:
        try:
            if 300 <= exc.code < 400:
                raise Failure("redirect_disallowed", exc.code) from None
            if exc.code == 429:
                raise Failure("rate_limited", 429, retry_wait=_retry_after(exc)) from None
            raise Failure(HTTP_REASONS.get(exc.code, "server_error" if 500 <= exc.code <= 599 else "http_error"), exc.code) from None
        finally:
            try:
                mp._bounded_call(exc.close, remaining())
            except Exception:  # noqa: BLE001
                pass
    except (TimeoutError, socket.timeout):
        raise Failure("timeout") from None
    except urllib.error.URLError as exc:
        raise Failure("timeout" if isinstance(exc.reason, (TimeoutError, socket.timeout)) else "network_error") from None
    except Exception:  # noqa: BLE001 - never let exception text out
        raise Failure("network_error") from None
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            try:
                mp._bounded_call(close, remaining())
            except Exception:  # noqa: BLE001 - cleanup cannot extend the deadline
                pass


class Pacer:
    """One request start every PACING_S at most, across every run and retry of one invocation."""

    def __init__(self, monotonic: Callable[[], float], sleep: Callable[[float], None]) -> None:
        self.monotonic, self.sleep, self.last = monotonic, sleep, None
        self.sent = self.retries = 0

    def wait(self) -> None:
        if self.last is not None:
            gap = self.last + PACING_S - self.monotonic()
            if gap > 0:
                self.sleep(gap)
        self.last = self.monotonic()
        self.sent += 1


def fetch(pool: str, mint: str, scan_ts: float, opener: Any, pacer: Pacer, *, monotonic: Callable[[], float]) -> dict[str, Any]:
    """The one request of a run, plus at most one retry, only after a 429. Returns {body, attempts, reason, http_status};
    never raises."""
    out: dict[str, Any] = {"body": None, "attempts": 0, "reason": None, "http_status": None}
    for attempt in (1, 2):
        try:
            request = build_request(pool, mint, scan_ts)
        except Failure as failure:  # checked before anything is sent or counted
            out.update(reason=failure.reason)
            return out
        pacer.wait()
        out["attempts"] = attempt
        try:
            out.update(body=send_once(request, opener, pool, mint, scan_ts, monotonic=monotonic), reason=None, http_status=200)
            return out
        except Failure as failure:
            out.update(reason=failure.reason, http_status=failure.http_status)
            if attempt == 1 and failure.reason == "rate_limited" and failure.retry_wait is not None:
                pacer.retries += 1
                pacer.sleep(failure.retry_wait)
                continue
            return out
        except Exception:  # noqa: BLE001 - defensive: no exception text leaves this function
            out.update(reason="request_failed", http_status=None)
            return out
    return out


# ----------------------------------------------------------------------------- candles (provider data is untrusted)


def _number(value: Any) -> float | None:
    """A finite JSON number as a float; text, a bool, NaN or inf is None (never 0)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def parse_candles(payload: Any, mint: str, scan_ts: float) -> tuple[list[dict[str, float]], int, str | None]:
    """(candles sorted by start time, rows dropped, a not-read reason or None). The answer's shape, as in the saved
    GeckoTerminal answers: {data: {attributes: {ohlcv_list: [[start, open, high, low, close, volume], ...]}}, meta: {base:
    {address}, quote: {...}}}, newest first. A row is kept only with a whole start time near the window and positive,
    finite prices (high >= low); a repeated start time keeps the first row. A list whose rows are all unreadable (for
    example millisecond times or missing fields) is candles_unreadable, never an empty list: only a genuinely empty list can
    become "no candles". With candles, meta.base must be this mint (the request asks for it): another token is not read."""
    data = payload.get("data") if isinstance(payload, dict) else None
    attributes = data.get("attributes") if isinstance(data, dict) else None
    rows = attributes.get("ohlcv_list") if isinstance(attributes, dict) else None
    if not isinstance(rows, list):
        return [], 0, "shape_mismatch"
    candles: dict[int, dict[str, float]] = {}
    dropped = 0
    for row in rows:
        start = row[0] if isinstance(row, list) and len(row) >= 5 else None
        if isinstance(start, bool) or not isinstance(start, int) or not scan_ts - 30 * 86400 <= start <= scan_ts + 2 * 86400:
            dropped += 1
            continue
        o, hi, lo, c = (_number(v) for v in row[1:5])
        if None in (o, hi, lo, c) or min(o, hi, lo, c) <= 0 or hi < lo or start in candles:
            dropped += 1
            continue
        volume = _number(row[5]) if len(row) > 5 else None
        candles[start] = {"start": start, "open": o, "high": hi, "low": lo, "close": c, "volume": volume if volume is not None and volume >= 0 else None}
    if rows and not candles:
        return [], dropped, "candles_unreadable"
    if candles:
        meta = payload.get("meta")
        base = meta.get("base") if isinstance(meta, dict) else None
        if not (isinstance(base, dict) and base.get("address") == mint):
            return [], dropped, "candles_for_another_token"
    return [candles[k] for k in sorted(candles)], dropped, None


def _pct(price: float, base: float) -> float:
    return round((price - base) / base * 100, 9)  # rounded far below the printed digits: float noise never moves a bar


def classify(lowest_pct: float, close_6h_pct: float) -> str:
    """dumped at or under the dumped bar; held at or above both held bars; in between otherwise (PROVISIONAL)."""
    if lowest_pct <= DUMPED_LOWEST_PCT:
        return "dumped"
    if lowest_pct >= HELD_LOWEST_PCT and close_6h_pct >= HELD_CLOSE_6H_PCT:
        return "held"
    return "in between"


def _close_at(candles: list[dict[str, float]], at: float) -> dict[str, float] | None:
    """The candle containing `at`, or the last candle before it."""
    before = [c for c in candles if c["start"] <= at]
    return before[-1] if before else None


def measure(candles: list[dict[str, float]], scan_ts: float) -> dict[str, Any]:
    """The outcome numbers from the candles, or {"status": ..., "reason": ...} when they cannot be read."""
    window = [c for c in candles if scan_ts - BEFORE_S <= c["start"] <= scan_ts + WINDOW_S]
    after = [c for c in window if c["start"] > scan_ts]
    if not after:
        why = "no candle in the window" if not window else "no trade in the 6 h after the scan"
        return {"status": "no candles", "reason": "no_trade_after_scan", "detail": why}
    before = [c for c in window if c["start"] <= scan_ts]
    containing = [c for c in before if c["start"] + CANDLE_S > scan_ts]
    if containing:
        at_scan, scan_from = containing[-1], "the close of the candle containing the scan time"
    elif before:
        at_scan, scan_from = before[-1], "the close of the last candle in the 10 minutes before the scan (no trade in the scan's own 5 minutes)"
    elif any(c["start"] < scan_ts - BEFORE_S for c in candles):
        return {"status": "not read (no trade in the 10 minutes before the scan)", "reason": "no_price_at_scan"}
    else:
        return {"status": "not read (candles start after the scan)", "reason": "candles_start_after_scan"}
    price = at_scan["close"]
    span = [c for c in window if c["start"] + CANDLE_S > scan_ts]  # the candle containing the scan time, then every later one
    lowest = min(span, key=lambda c: (c["low"], c["start"]))
    highest = max(span, key=lambda c: (c["high"], -c["start"]))
    one, six = _close_at(window, scan_ts + PLUS_1H_S), _close_at(window, scan_ts + WINDOW_S)
    last = after[-1]["start"]
    vanished = last <= scan_ts + WINDOW_S - VANISHED_S
    volumes = [c["volume"] for c in after if c["volume"] is not None]

    def point(c: dict[str, float], key: str) -> dict[str, Any]:
        when = "the scan's own candle" if c["start"] <= scan_ts else after_text(c["start"] - scan_ts)
        return {"price_usd": c[key], "change_pct": _pct(c[key], price), "candle_start_utc": _iso(c["start"]), "after_scan": when}

    out = {"status": "ok", "reason": None, "price_at_scan_usd": price, "price_at_scan_from": scan_from, "price_at_scan_candle_utc": _iso(at_scan["start"]),
           "plus_1h": point(one, "close"), "plus_6h": point(six, "close"), "lowest_6h": point(lowest, "low"), "highest_6h": point(highest, "high"),
           "candles_in_window": len(window), "candles_after_scan": len(after), "last_candle_utc": _iso(last), "last_candle_after_scan": after_text(last - scan_ts),
           "volume_usd_after_scan": round(sum(volumes), 2) if volumes else None, "volume_vanished": vanished}
    out["class"] = classify(out["lowest_6h"]["change_pct"], out["plus_6h"]["change_pct"])
    return out


# ----------------------------------------------------------------------------- one run


def _base(run: Path, scan_ts: float, mint: str, checked_at: float) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "script": "outcomes.py", "run": run.name, "mint": mint, "scan_time_utc": _iso(scan_ts), "scan_time_wib": wib_text(scan_ts),
        "scan_time_from": "the run folder name (UTC)", "checked_at": _iso(checked_at), "status": None, "reason": None, "final": True, "class": None,
        "pool": {"address": None, "how": None, "source": None},
        "request": {"method": "GET", "host": HOST, "path": f"{ohlcv_path('<POOL>')}?aggregate={AGGREGATE}&before_timestamp=<scan + 6 h + 5 min>&limit={LIMIT}&token=<MINT>",
                    "keys": "none", "requests_sent": 0, "http_status": None, "window_start_utc": _iso(scan_ts - BEFORE_S), "window_end_utc": _iso(scan_ts + WINDOW_S)},
        "candles_read": 0, "rows_dropped": 0,
        "provisional": {"dumped_lowest_pct": DUMPED_LOWEST_PCT, "held_lowest_pct": HELD_LOWEST_PCT, "held_close_6h_pct": HELD_CLOSE_6H_PCT, "rule": CLASS_RULE},
        "note": NOTE, "cannot_see": CANNOT_SEE,
    }


def read_run(run: Path, scan_ts: float, mint: str, opener: Any, pacer: Pacer, *, now: float, monotonic: Callable[[], float],
             stopped: bool = False) -> dict[str, Any]:
    """The outcome of one saved scan: pending (no request) when younger than READY_AFTER_S, not read (no pool) when no main
    pool is found (no request), not read (rate limited; run again later) with no request when the run was stopped by a
    429, else exactly one request (plus at most one retry after a 429)."""
    result = _base(run, scan_ts, mint, now)
    if now < scan_ts + READY_AFTER_S:
        result.update(status="pending", reason="younger_than_6h", final=False, ready_after_utc=_iso(scan_ts + READY_AFTER_S))
        return result
    pool, how, source = choose_pool(run, mint)
    result["pool"] = {"address": pool, "how": how, "source": source}
    if pool is None:
        result.update(status="not read (no pool)", reason="no_pool")
        return result
    if stopped:
        result.update(status=RATE_LIMITED, reason="not_sent_run_stopped", final=False)
        return result
    got = fetch(pool, mint, scan_ts, opener, pacer, monotonic=monotonic)
    result["request"].update(requests_sent=got["attempts"], http_status=got["http_status"])
    if got["reason"] == "rate_limited":
        result.update(status=RATE_LIMITED, reason="rate_limited", final=False)
        return result
    if got["reason"] is not None:
        result.update(status=f"not read ({got['reason']})", reason=got["reason"], final=got["reason"] in FINAL_FAILURES)
        return result
    try:
        payload = json.loads(got["body"].decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError, AttributeError):
        result.update(status="not read (invalid_json)", reason="invalid_json", final=False)
        return result
    try:
        candles, dropped, problem = parse_candles(payload, mint, scan_ts)
        result.update(candles_read=len(candles), rows_dropped=dropped)
        if problem is not None:
            result.update(status=f"not read ({PROBLEM_TEXT.get(problem, problem)})", reason=problem, final=False)
            return result
        result.update(measure(candles, scan_ts))
    except Exception:  # noqa: BLE001 - an answer the guards did not foresee: a fixed code, the call still counted
        result.update(status="not read (parse_error)", reason="parse_error", final=False)
    return result


# ----------------------------------------------------------------------------- the table (offline, from saved files)


def _label(value: Any) -> str | None:
    """An engine's FLAG label as one short line: letters, digits, spaces and plain punctuation only."""
    if not isinstance(value, str):
        return None
    return " ".join(LABEL_RE.sub("", value).split())[:120] or None


def forensics_flag(run: Path) -> str:
    """assessment.json flag.label (the forensics FLAG), or not read (<reason>)."""
    path = run / "assessment.json"
    data = _read(path)
    if not path.exists():
        return "not read (assessment.json missing)"
    flag = data.get("flag") if isinstance(data, dict) else None
    return (_label(flag.get("label")) if isinstance(flag, dict) else None) or "not read (no flag in assessment.json)"


def analysis_flag(run: Path, mint: str) -> str:
    """holder-analysis.json overall.flag.label (the analysis FLAG), or not read (<reason>)."""
    path = run / "holder-analysis.json"
    data = _read(path)
    if not path.exists():
        return "not read (holder-analysis.json missing)"
    if not isinstance(data, dict) or data.get("mint") not in (None, mint):
        return "not read (holder-analysis.json unreadable)"
    overall = data.get("overall") if isinstance(data.get("overall"), dict) else {}
    flag = overall.get("flag") if isinstance(overall.get("flag"), dict) else {}
    return _label(flag.get("label")) or "not read (no flag in holder-analysis.json)"


def exit_overhang_cells(run: Path) -> tuple[str, float | None]:
    """(EXIT OVERHANG level, ratio) through exit_overhang.measure and exit_overhang.level, by import; "not read (<reason>)"
    when its inputs are missing or unreadable."""
    try:
        m = eo.measure(run)
    except eo.NotRead as why:
        return f"not read ({why})", None
    except Exception:  # noqa: BLE001 - a damaged file reads as not read, as in exit_overhang.present
        return "not read (saved values unreadable)", None
    level = eo.level(m["ratio"])
    if m["pool_fallback"]:
        level = level.replace(")", "; main pool by fallback)", 1) if level.endswith(")") else f"{level} (main pool by fallback)"
    return level, m["ratio"]


def fee_tvl_cell(run: Path) -> str:
    """The FEE/TVL status from meteora_pools.present's first line, by import: WARNING, meets the bar (not a safety signal)
    or not read (<reason>)."""
    try:
        line = mp.present(run)[0]
    except Exception:  # noqa: BLE001 - present never raises; defensive
        return "not read (saved values unreadable)"
    line = line[len(mp.SUMMARY_MARK):] if line.startswith(mp.SUMMARY_MARK) else line
    for head in (mp.LINE_HEAD + ": ", mp.NOT_READ_HEAD + ": "):
        if line.startswith(head):
            line = line[len(head):]
            break
    status = line.split(" — ", 1)[0].strip().rstrip(".")
    return status if status.startswith("not read") or status in ("WARNING", "meets the bar (not a safety signal)") else "not read (line not recognized)"


def load_outcome(run: Path) -> dict[str, Any] | None:
    data = _read(run / OUT_FILE)
    return data if isinstance(data, dict) and data.get("schema") == SCHEMA and data.get("run") == run.name else None


def row_of(run: Path, scan_ts: float, mint: str, outcome: dict[str, Any] | None) -> dict[str, Any]:
    level, ratio = exit_overhang_cells(run)
    row: dict[str, Any] = {"run": run.name, "mint": mint, "scan time (UTC)": utc_text(scan_ts), "scan time (WIB)": wib_text(scan_ts),
                           "forensics FLAG": forensics_flag(run), "analysis FLAG": analysis_flag(run, mint), "EXIT OVERHANG": level,
                           "EXIT OVERHANG ratio (x)": ratio, "FEE/TVL": fee_tvl_cell(run)}
    o = outcome or {}
    status = o.get("status") if isinstance(o.get("status"), str) else "not checked yet (no outcome.json)"
    pool = o.get("pool") if isinstance(o.get("pool"), dict) else {}
    source = {"creator_fees": "creator_fees canonical pool", "holders_fallback": "fallback: largest holders.json pool row",
              "analysis_fallback": "fallback: largest liquidity_pool row (pool from holder-analysis.json)"}.get(pool.get("source"), "")
    notes = []
    if status == "ok":
        if o.get("volume_vanished") is True:
            notes.append(f"volume vanished: last candle {o.get('last_candle_after_scan')} after the scan")
        if "before the scan" in str(o.get("price_at_scan_from")):
            notes.append("price at scan from the last candle before the scan")
    ok = status == "ok"
    row.update({"outcome status": status, "main pool": source,
                "price at scan (USD)": _number(o.get("price_at_scan_usd")) if ok else None,
                "change at 1 h (%)": _number((o.get("plus_1h") or {}).get("change_pct")) if ok else None,
                "change at 6 h (%)": _number((o.get("plus_6h") or {}).get("change_pct")) if ok else None,
                "lowest price within 6 h (%)": _number((o.get("lowest_6h") or {}).get("change_pct")) if ok else None,
                "class": o.get("class") if ok and o.get("class") in CLASSES else "", "note": "; ".join(notes)})
    return row


def price_text(value: float) -> str:
    """A price with 6 significant digits and no exponent ("0.000456123")."""
    if value <= 0:
        return "0"
    return f"{value:.{max(2, 5 - math.floor(math.log10(value)))}f}"


def _cell(column: str, value: Any) -> str:
    """A CSV cell: a price with 6 significant digits, other numbers with 2 decimals (no exponent); text that a spreadsheet
    would read as a formula gets a leading apostrophe."""
    if value is None:
        return ""
    if isinstance(value, float):
        return price_text(value) if column == "price at scan (USD)" else f"{value:.2f}"
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def csv_text(rows: list[dict[str, Any]]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for row in rows:
        writer.writerow([_cell(c, row[c]) for c in CSV_COLUMNS])
    return out.getvalue()


def _group(text: str, names: tuple[str, ...]) -> str:
    return next((n for n in names if text.startswith(n)), "not read")


def summary_lines(rows: list[dict[str, Any]]) -> list[str]:
    klass = [r["class"] or NOT_CLASSED for r in rows]
    statuses = [r["outcome status"] for r in rows]
    lines = [f"scans: {len(rows)}; classed: {sum(1 for k in klass if k != NOT_CLASSED)}; " + "; ".join(f"{k} {klass.count(k)}" for k in CLASSES)
             + f"; not classed {klass.count(NOT_CLASSED)} (pending {statuses.count('pending')}, no candles {statuses.count('no candles')}, "
             f"not read {sum(1 for s in statuses if s.startswith('not read'))}, not checked yet {sum(1 for s in statuses if s.startswith('not checked'))})"]
    columns = (*CLASSES, NOT_CLASSED)
    for title, key, names in (("EXIT OVERHANG level x class (scans)", "EXIT OVERHANG", ("DANGER", "CAUTION", "not raised")),
                              ("forensics FLAG x class (scans)", "forensics FLAG", ("DANGER FLAG", "CAUTION", "NO FLAG RAISED"))):
        lines.append(f"{title}:")
        lines.append("  " + " | ".join(["level", *columns]))
        for name in (*names, "not read"):
            counts = [sum(1 for r, k in zip(rows, klass) if _group(r[key], names) == name and k == c) for c in columns]
            lines.append("  " + " | ".join([name, *(str(n) for n in counts)]))
    held = sorted({r["mint"] for r in rows if r["class"] == "held"})
    lines.append(f"coins that held so far: {len(held)} (target about {HELD_TARGET} before the bars can be judged)")
    scans = sum(1 for r in rows if r["class"] == "held")
    lines.append(f"  ({scans} held scan{'' if scans == 1 else 's'}; a coin counts once; {HELD_NOTE})")
    limited = [r["run"] for r in rows if r["outcome status"] == RATE_LIMITED]
    if limited:
        lines.append(f"{RATE_LIMITED}: {len(limited)} scan{'' if len(limited) == 1 else 's'}; run the command again in a few minutes and "
                     "they are read then")
    vanished = [r["run"] for r in rows if r["note"].startswith("volume vanished")]
    if vanished:
        lines.append("volume vanished before the 6 h mark (the pool stopped trading; the token may have moved to another pool): " + ", ".join(vanished))
    lines.append(f"classes: {CLASS_RULE}")
    lines.append("the EXIT OVERHANG and FEE/TVL bars stay unvalidated until about 10 held coins are on record")
    return lines


# ----------------------------------------------------------------------------- CLI


def run_folders(reports: Path) -> list[tuple[Path, float, str]]:
    found = []
    for path in sorted(reports.iterdir()):
        parsed = parse_run_name(path.name) if path.is_dir() and not path.is_symlink() else None
        if parsed is not None:
            found.append((path, parsed[0], parsed[1]))
    return found


def run_line(o: dict[str, Any]) -> str:
    sent = o["request"]["requests_sent"]
    calls = f"{sent} GeckoTerminal request{'s' if sent != 1 else ''}"
    if o["status"] == "ok":
        return (f"{o['run']}: ok; class {o['class']}; price at scan ${price_text(o['price_at_scan_usd'])}; +1 h {o['plus_1h']['change_pct']:+.1f}%; "
                f"+6 h {o['plus_6h']['change_pct']:+.1f}%; lowest within 6 h {o['lowest_6h']['change_pct']:+.1f}% at {o['lowest_6h']['after_scan']}; "
                f"{o['candles_in_window']} candles; pool {o['pool']['source']}; {calls}")
    if o["status"] == "pending":
        return f"{o['run']}: pending (younger than 6 h 10 min; read after {o['ready_after_utc']}); no request"
    detail = f": {o['pool']['how']}" if o["reason"] == "no_pool" else f" ({o['detail']})" if o.get("detail") else ""
    return f"{o['run']}: {o['status']}{detail}; {calls}"


def main(argv: list[str] | None = None, *, opener: Any | None = None, now: Callable[[], float] | None = None,
         monotonic: Callable[[], float] | None = None, sleep: Callable[[float], None] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Maintenance, never part of a scan: for each saved dlmm-scan run folder at least 6 h 10 min old, read "
                                                 "GeckoTerminal's free 5-minute candles of the run's main pool (one request, no key, 12 s apart), "
                                                 f"write <RUN>/{OUT_FILE} and rebuild <REPORTS>/{CSV_FILE} with the scan's warnings next to what the price did.")
    parser.add_argument("--reports", metavar="DIR", required=True, help="the reports folder holding the run folders <UTC>-<MINT>")
    parser.add_argument("--run", metavar="FOLDER", action="append", default=[], help="read only this run folder (repeatable); the table still lists all")
    parser.add_argument("--refresh", action="store_true", help=f"read again even when {OUT_FILE} is final")
    parser.add_argument("--dry-run", action="store_true", help="print the plan only: no request, nothing written")
    args = parser.parse_args(argv)
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    reports = Path(args.reports)
    if not reports.is_dir():
        print("error: --reports is not a folder", file=sys.stderr)
        return 2
    runs = run_folders(reports)
    names = {Path(r).name for r in args.run}
    unknown = sorted(names - {p.name for p, _, _ in runs})
    if unknown:
        print(f"error: --run names no run folder of --reports: {', '.join(unknown)}", file=sys.stderr)
        return 2
    print(f"Outcomes after each saved scan (DS-OUTCOMES-T1; GeckoTerminal 5-minute candles, free, no key; {NOTE})")
    opener = opener or mp.default_opener()
    pacer = Pacer(monotonic, sleep)
    stopped = False
    outcomes: dict[str, dict[str, Any] | None] = {}
    for path, scan_ts, mint in runs:
        saved = load_outcome(path)
        outcomes[path.name] = saved
        if names and path.name not in names:
            continue
        if saved is not None and saved.get("final") is True and (not args.refresh or stopped):
            continue  # after the stop, --refresh keeps every later scan's final outcome
        if args.dry_run:
            if now() < scan_ts + READY_AFTER_S:
                print(f"  would skip {path.name}: pending (younger than 6 h 10 min); no request")
                continue
            pool, how, _ = choose_pool(path, mint)
            print(f"  would read {path.name}: GET {ohlcv_path(pool)}?{ohlcv_query(mint, scan_ts)} ({how})" if pool
                  else f"  would skip {path.name}: not read (no pool): {how}; no request")
            continue
        result = read_run(path, scan_ts, mint, opener, pacer, now=now(), monotonic=monotonic, stopped=stopped)
        stopped = stopped or result["reason"] == "rate_limited"
        try:
            (path / OUT_FILE).write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
        except OSError:
            print(f"error: {path.name}/{OUT_FILE} is not writable", file=sys.stderr)
            return 2
        outcomes[path.name] = result
        print(run_line(result), flush=True)
    if args.dry_run:
        print("dry run: no request sent, nothing written")
        return 0
    rows = [row_of(path, scan_ts, mint, outcomes[path.name]) for path, scan_ts, mint in runs]
    try:
        (reports / CSV_FILE).write_text(csv_text(rows), encoding="utf-8")
    except OSError:
        print(f"error: {CSV_FILE} is not writable", file=sys.stderr)
        return 2
    print(f"GeckoTerminal requests sent: {pacer.sent} ({pacer.retries} retr{'ies' if pacer.retries != 1 else 'y'} after a 429)")
    if stopped:
        print("run stopped: GeckoTerminal still answered 429 (rate limited) after the one retry; the scans left read "
              f"\"{RATE_LIMITED}\" (not final): run the command again in a few minutes")
    for line in summary_lines(rows):
        print(line)
    print(f"wrote {CSV_FILE}: {len(rows)} row{'s' if len(rows) != 1 else ''} (one per run folder)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
