#!/usr/bin/env python3
"""Meteora DLMM pools of a token for dlmm-scan (first-wave collector `meteora_pools`, DS-FEETVL-T1): one free, keyless,
bounded read of Meteora's DLMM datapi, and the offline FEE/TVL line (Yun's rule, provisional).

Owner (2026-10-25): before putting liquidity in, the scan must say whether the token's Meteora DLMM pools earn enough fees
for Yun's rule, with a warning when they do not: a 24h fee/TVL of 300% for a token younger than 6 h, 20% from 6 h.

Collector (network): meteora_pools.py <MINT> --out <RUN> sends one GET to the documented pools list (provider-docs cache
current/meteora/fulldocs.pages/api-reference/dlmm/pools/pools.md):
  GET /pools?query=<MINT>&sort_by=fee_tvl_ratio_24h:desc&page_size=50   on dlmm.datapi.meteora.ag
`query` matches names, tokens or addresses, so only pools whose token_x or token_y address equals the mint are kept. Host
dlmm.datapi.meteora.ag only, https only, no key, no redirects, no environment proxy, 2 MiB and a hard 30 s wall-clock
limit per attempt (opening, every read and closing under one deadline, worker thread: the creator_fees.py pattern), at most
one retry, only after a 429 (its Retry-After within 5 s, else 1.5 s) or a 5xx (after 1.5 s). Calls per scan: 1 (at most
2). Free (the cached docs: 30 requests a second for every DLMM API). It writes <RUN>/meteora_pools.json and reads no other
file of the run folder (a first-wave collector waits for nothing). Per pool: address, pair symbols (inert labels), the
other token's mint, bin step, base fee %, TVL, 24h fees, 24h volume, fee/TVL for 1h, 4h, 12h and 24h (Meteora's own
numbers, in percent), the pool's created_at (milliseconds since 1970 in the live answers of 2026-10-25, saved as ISO UTC)
and the blacklisted flag. A number that is missing or not finite is null, never 0; a renamed load-bearing field is loud
(unavailable), never ok.

Synthesis (offline, no network, no key): meteora_pools.py --present <RUN> reads meteora_pools.json, lpagent_pools.json
(the LP Agent cross-check, when that collector ran), holders.json (the token's oldest trading pair) and creator_fees.json
(the Dexscreener pairs and their 24 h volume, for the DLMM share line: DS-DLMM-SHARE-T1) and prints first the FEE/TVL
line, marked [for the executive summary], then the block "Pool fees vs TVL (Meteora DLMM; Yun's rule; provisional)".
SUMMARY.md copies the line without the mark right after the EXIT OVERHANG line. A PRESENTATION LINE ONLY:
never an engine input, never passed to assess, never counted toward NO_ALARM; it never changes the forensics or analysis
FLAG, verdict or threshold, and "meets the bar" is not a safety signal. Standard library only; Python >= 3.10.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import queue
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

if str(Path(__file__).resolve().parent) not in sys.path:  # python3 -I leaves the script's folder off sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import provider_words as pw  # noqa: E402  (HS-LABELS-T1: verdict words in provider text; standard library only, no network)

# ----------------------------------------------------------------------------- PROVISIONAL (unvalidated)
# Owner decisions of 2026-10-25 (DS-FEETVL-T1): a token younger than 6 h needs a 24h fee/TVL of 300%, a token 6 h old or
# older 20%. Pools under $2,000 TVL are dust and never decide the line. No outcomes are recorded yet: keep these provisional.
FEE_TVL_YOUNG_BAR_PCT = 300.0       # 24h fees as a percent of TVL, for a token younger than YOUNG_TOKEN_MAX_AGE_S
FEE_TVL_OLD_BAR_PCT = 20.0          # the same, for a token YOUNG_TOKEN_MAX_AGE_S old or older (also when the age is unknown)
YOUNG_TOKEN_MAX_AGE_S = 6 * 3600    # 6 h: younger is "new"
COUNTED_POOL_MIN_TVL_USD = 2000.0   # a pool under this TVL is dust: listed, never decides the line
SMALL_POSITION_USD = 2500.0         # a small position: the "after adding" line, information only, never a bar
LPAGENT_AGREE_REL = 0.10            # the LP Agent cross-check "agrees" when TVL and 24h fee/TVL are both within 10% of Meteora's
# ----------------------------------------------------------------------------- end PROVISIONAL

HOST = "dlmm.datapi.meteora.ag"
POOLS_PATH = "/pools"
SORT_BY = "fee_tvl_ratio_24h:desc"
PAGE_SIZE = 50
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = 30.0                 # per attempt: a hard wall-clock limit on open + every read + close (worker thread)
RETRY_MAX_WAIT_S = 5.0           # retry a 429 once only when its Retry-After ends this soon
RETRY_DEFAULT_WAIT_S = 1.5       # a 429 without Retry-After, or a 5xx, is retried once after this wait
REQUESTS_PER_SCAN = 1
MAX_REQUESTS = 2
USER_AGENT = "holder-scan-meteora-pools/1.0"
SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
LABEL_RE = re.compile(r"[^\w .\-]")  # the forensics adapter's LABEL_RE: letters, digits, _, space, dot and hyphen only
OUT_FILE = "meteora_pools.json"
SCHEMA = "holder-scan-meteora-pools/1"
WINDOWS_DOCUMENTED = ("30m", "1h", "2h", "4h", "12h", "24h")  # TimeWindowData in the cached pools.md
WINDOWS_KEPT = ("1h", "4h", "12h", "24h")
CREATED_AT_UNIT = "milliseconds"  # live answers of 2026-10-25 (BILLIONS pools: 1792903548000 = 2026-10-25 04:45:48 UTC)
CREATED_AT_MIN_MS = 1_577_836_800_000  # 2020-01-01: an older (or a seconds-sized) value is not read
HTTP_REASONS = {400: "bad_request", 401: "access_denied", 403: "access_denied", 404: "not_found", 429: "rate_limited", 503: "service_unavailable"}
CANNOT_SEE = ("Meteora's own indexer numbers at one moment (fees can drop fast after a pump); DLMM pools only (no DAMM, "
              "PumpSwap or Raydium pools); fees per window, not who earned them or where your liquidity would sit")
PRESENTATION_NOTE = ("presentation line only: never an engine input, never passed to assess, never counted toward NO_ALARM; it never "
                     "changes the forensics or analysis FLAG, verdict or threshold; a pool at or above the bar is not a safety signal")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect (returning None makes urllib raise the 3xx as an HTTPError)."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class Failure(Exception):
    """A failed attempt, reduced to a fixed reason code. Never carries request text."""

    def __init__(self, reason: str, http_status: int | None = None, retry_wait: float | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status
        self.retry_wait = retry_wait


# ----------------------------------------------------------------------------- request


def pools_query(mint: str) -> str:
    return f"query={mint}&sort_by={SORT_BY}&page_size={PAGE_SIZE}"


def check_url(url: str, mint: str) -> None:
    """https only, host dlmm.datapi.meteora.ag only, the documented /pools path with this mint's fixed query only, no port
    other than 443, no credentials in the URL."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise Failure("scheme_not_https")
    if parsed.hostname != HOST or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise Failure("host_not_allowlisted")
    if parsed.path != POOLS_PATH or parsed.query != pools_query(mint) or parsed.params or parsed.fragment:
        raise Failure("path_not_allowlisted")


def build_request(mint: str) -> urllib.request.Request:
    url = f"https://{HOST}{POOLS_PATH}?{pools_query(mint)}"
    check_url(url, mint)
    request = urllib.request.Request(url, method="GET")
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", USER_AGENT)
    return request


def default_opener() -> urllib.request.OpenerDirector:
    """No environment proxy (an explicit empty ProxyHandler), no redirects, default TLS verification."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def _bounded_call(function: Callable[[], Any], timeout: float) -> Any:
    """Run one blocking transport step (open, read, close) in a daemon worker and wait at most `timeout` seconds: a hard
    wall-clock bound (the creator_fees.py and fomoapi.py pattern). A socket timeout alone restarts on every byte, so a
    server that drip-feeds bytes could otherwise hold the collector far past the deadline."""
    if timeout <= 0:
        raise TimeoutError
    result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def invoke() -> None:
        try:
            result.put((True, function()))
        except BaseException as exc:  # handed back to the bounded caller
            result.put((False, exc))

    worker = threading.Thread(target=invoke, name="meteora-pools-transport", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise TimeoutError
    succeeded, value = result.get_nowait()
    if not succeeded:
        if isinstance(value, Exception):
            raise value
        raise OSError
    return value


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
    wait = max(0.5, float(text))
    return wait if wait <= RETRY_MAX_WAIT_S else None


def _status_failure(status: int) -> Failure:
    if 500 <= status <= 599:
        return Failure(HTTP_REASONS.get(status, "server_error"), status, retry_wait=RETRY_DEFAULT_WAIT_S)
    return Failure(HTTP_REASONS.get(status, "http_error"), status)


def send_once(request: urllib.request.Request, opener: Any, mint: str | None, *, monotonic: Callable[[], float],
              url_check: Callable[[str], None] | None = None) -> bytes:
    """One attempt. Returns the body (at most MAX_BYTES) or raises Failure with a fixed code. Opening, every read and the
    error close run under one hard wall-clock deadline of TIMEOUT_S. An error body is never read. The URL is checked first:
    by check_url for this mint by default, or by `url_check` when one is given (pool_discovery.py passes its own)."""
    if url_check is None:
        check_url(request.full_url, mint)
    else:
        url_check(request.full_url)
    deadline = monotonic() + TIMEOUT_S

    def remaining() -> float:
        return deadline - monotonic()

    response = None
    try:
        response = _bounded_call(lambda: opener.open(request, timeout=TIMEOUT_S), remaining())
        status = int(getattr(response, "status", 200) or 200)
        if 300 <= status < 400:
            raise Failure("redirect_disallowed", status)
        if status != 200:
            raise _status_failure(status)
        chunks, total = [], 0
        while True:
            chunk = _bounded_call(lambda: response.read(65536), remaining())
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
            raise _status_failure(exc.code) from None
        finally:
            try:
                _bounded_call(exc.close, remaining())
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
                _bounded_call(close, remaining())
            except Exception:  # noqa: BLE001 - cleanup cannot extend the deadline
                pass


def fetch(mint: str | None, opener: Any, *, monotonic: Callable[[], float], sleep: Callable[[float], None],
          build: Callable[[], urllib.request.Request] | None = None, url_check: Callable[[str], None] | None = None) -> dict[str, Any]:
    """The documented request, plus at most one retry after a 429 or a 5xx. Returns {body, attempts, reason, http_status};
    never raises. By default the request and its URL check are this mint's (build_request, check_url); pool_discovery.py
    passes its own `build` and `url_check` (mint None) and reuses this loop by import."""
    out: dict[str, Any] = {"body": None, "attempts": 0, "reason": None, "http_status": None}
    for attempt in (1, 2):
        out["attempts"] = attempt
        try:
            request = build_request(mint) if build is None else build()
            out.update(body=send_once(request, opener, mint, monotonic=monotonic, url_check=url_check), reason=None, http_status=200)
            return out
        except Failure as failure:
            out.update(reason=failure.reason, http_status=failure.http_status)
            if attempt == 1 and failure.retry_wait is not None:
                sleep(failure.retry_wait)
                continue
            return out
        except Exception:  # noqa: BLE001 - defensive: no exception text leaves this function
            out.update(reason="request_failed", http_status=None)
            return out
    return out


# ----------------------------------------------------------------------------- parsing (provider text is untrusted)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _number(value: Any, lo: float = 0.0, hi: float = 1e18) -> float | None:
    """A finite JSON number in [lo, hi] as a float; text, a bool, NaN, inf or a value out of range is None (never 0)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) and lo <= number <= hi else None


def _count(value: Any) -> int | None:
    number = _number(value, 0, 10**9)
    return int(number) if number is not None and number.is_integer() else None


def _address(value: Any) -> str | None:
    return value if isinstance(value, str) and SOLANA_ADDRESS_RE.fullmatch(value) else None


def _label(value: Any) -> str | None:
    """A token symbol as a short inert label (LABEL_RE, 16 characters, verdict words replaced: provider_words)."""
    return pw.label(value, LABEL_RE, 16)


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def created_at_iso(value: Any, now_ts: float) -> tuple[int | None, str | None]:
    """(the raw value, ISO UTC) for a pool's created_at in milliseconds since 1970 (the unit of the live answers); a value
    that is not a whole number, older than 2020-01-01 (a seconds-sized value lands in 1970) or more than a day ahead of the
    scan is (None, None): not read, never guessed."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None, None
    if not CREATED_AT_MIN_MS <= value <= (now_ts + 86400) * 1000:
        return None, None
    return value, _iso(value / 1000)


def parse_pools(payload: Any, mint: str, now_ts: float) -> dict[str, Any]:
    """The pools answer, field names as in the cached docs and the live answers of 2026-10-25: {total, pages, current_page,
    page_size, data: [{address, token_x {address, symbol}, token_y {...}, pool_config {bin_step, base_fee_pct}, tvl, fees,
    volume, fee_tvl_ratio (each {30m, 1h, 2h, 4h, 12h, 24h}), created_at, is_blacklisted}]}. Only pools whose token_x or
    token_y address is the mint are kept (query is fuzzy). Loud guards: no pool list gives unavailable
    (pool_list_missing); kept pools of which none has a readable 24h fee/TVL give unavailable (fee_tvl_field_missing), none
    with a readable TVL give unavailable (tvl_field_missing); no pool of this mint gives empty (no_dlmm_pool)."""
    if not isinstance(payload, dict):
        return {"status": "unavailable", "reason": "invalid_shape"}
    rows = payload.get("data")
    if not isinstance(rows, list):
        return {"status": "unavailable", "reason": "pool_list_missing"}
    total = _count(payload.get("total"))
    kept: list[dict[str, Any]] = []
    other = unreadable = 0
    for row in rows:
        if not isinstance(row, dict):
            unreadable += 1
            continue
        x, y = _dict(row.get("token_x")), _dict(row.get("token_y"))
        if x.get("address") == mint:
            side, this, that = "x", x, y
        elif y.get("address") == mint:
            side, this, that = "y", y, x
        else:
            other += 1
            continue
        address = _address(row.get("address"))
        if address is None:
            unreadable += 1
            continue
        config, fees, volume, ratio = _dict(row.get("pool_config")), _dict(row.get("fees")), _dict(row.get("volume")), _dict(row.get("fee_tvl_ratio"))
        created_ms, created = created_at_iso(row.get("created_at"), now_ts)
        bin_step = _count(config.get("bin_step"))
        kept.append({
            "address": address, "this_token_side": side, "symbol": _label(this.get("symbol")), "other_symbol": _label(that.get("symbol")),
            "other_mint": _address(that.get("address")), "bin_step": bin_step if bin_step and bin_step <= 10000 else None,
            "base_fee_pct": _number(config.get("base_fee_pct"), 0.0, 100.0), "tvl": _number(row.get("tvl")),
            "fees_24h": _number(fees.get("24h")), "volume_24h": _number(volume.get("24h")),
            "fee_tvl_ratio": {w: _number(ratio.get(w)) for w in WINDOWS_KEPT},
            "windows_as_documented": all(w in ratio for w in WINDOWS_DOCUMENTED),
            "created_at_ms": created_ms, "created_at": created,
            "blacklisted": row.get("is_blacklisted") if isinstance(row.get("is_blacklisted"), bool) else None,
        })
    answer = {"total": total, "rows_in_answer": len(rows), "other_token_pools_dropped": other, "unreadable_rows": unreadable,
              "truncated": total is not None and total > len(rows)}
    if not kept:
        return {"status": "empty", "reason": "no_dlmm_pool", "answer": answer, "pools": []}
    if all(p["fee_tvl_ratio"]["24h"] is None for p in kept):
        return {"status": "unavailable", "reason": "fee_tvl_field_missing", "answer": answer}
    if all(p["tvl"] is None for p in kept):
        return {"status": "unavailable", "reason": "tvl_field_missing", "answer": answer}
    kept.sort(key=lambda p: -(p["fee_tvl_ratio"]["24h"] if p["fee_tvl_ratio"]["24h"] is not None else -1.0))  # stable: Meteora's order on ties
    return {"status": "ok", "reason": None, "answer": answer, "pools": kept}


# ----------------------------------------------------------------------------- collect


def _base(mint: str, fetched_at: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "collector": "meteora_pools", "provider": "Meteora DLMM datapi", "mint": mint, "status": "unavailable", "reason": None,
        "fetched_at": fetched_at, "http_status": None,
        "request": {"method": "GET", "host": HOST, "path": f"{POOLS_PATH}?query=<MINT>&sort_by={SORT_BY}&page_size={PAGE_SIZE}", "keys": "none",
                    "requests_per_scan": REQUESTS_PER_SCAN, "max_requests": MAX_REQUESTS, "requests_sent": 0},
        "docs": "provider-docs current/meteora/fulldocs.pages/api-reference/dlmm/pools/pools.md (GET /pools; fee_tvl_ratio in percent per 30m 1h 2h 4h 12h 24h)",
        "created_at_unit": CREATED_AT_UNIT, "answer": None, "pools": [],
        "presentation_only": True, "note": PRESENTATION_NOTE, "cannot_see": CANNOT_SEE,
    }


def _decode(body: Any) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError, AttributeError):
        return None


def collect_meteora_pools(
    mint: str,
    *,
    opener: Any | None = None,
    now: Callable[[], float] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """The documented request with at most one retry after a 429 or a 5xx. Returns the meteora_pools.json result; never
    raises for provider or transport failures. Reads no file of the run folder."""
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    result = _base(mint, _iso(now()))
    got = fetch(mint, opener or default_opener(), monotonic=monotonic, sleep=sleep)
    result["request"]["requests_sent"] = got["attempts"]
    result["http_status"] = got["http_status"]
    fetched = now()
    result["fetched_at"] = _iso(fetched)
    if got["reason"] is not None:
        result["reason"] = got["reason"]
        return result
    payload = _decode(got["body"])
    if payload is None:
        result["reason"] = "invalid_json"
        return result
    try:
        result.update(parse_pools(payload, mint, fetched))
    except Exception:  # noqa: BLE001 - a malformed answer the guards did not foresee: a fixed code, the call still counted
        result.update(status="unavailable", reason="parse_error")
    return result


def status_line(result: dict[str, Any]) -> str:
    sent = result["request"]["requests_sent"]
    calls = f"{sent} Meteora datapi request{'s' if sent != 1 else ''}"
    if result["status"] == "ok":
        n = len(result["pools"])
        return f"ok ({n} Meteora DLMM pool{'s' if n != 1 else ''} of this token; {calls})"
    if result["status"] == "empty":
        return f"empty (Meteora lists no DLMM pool of this token; {calls})"
    return f"unavailable ({result['reason']}; {calls})"


# ----------------------------------------------------------------------------- presentation (synthesis, offline)


SUMMARY_MARK = "[for the executive summary] "  # the same text as gmgn_rows.PNL_SUMMARY_MARK and exit_overhang.SUMMARY_MARK
LINE_HEAD = "FEE/TVL (Yun's rule, provisional)"
NOT_READ_HEAD = "FEE/TVL (Yun's rule)"
TITLE = "Pool fees vs TVL (Meteora DLMM; Yun's rule; provisional)"
LP_SUFFIX = " (LP Agent figure; Meteora not read)"
LP_NOT_READ_SUFFIX = "; LP Agent figure, Meteora not read"  # the same label inside a not-read reason
LP_STALE = " (LP Agent marks its data stale)"
LP_FILE = "lpagent_pools.json"
LP_SCHEMA = "holder-scan-lpagent-pools/1"
LP_DLMM_PROTOCOL = "meteora"     # LP Agent's protocol name for a Meteora DLMM pool (meteora_damm_v2 is DAMM v2)
HOLDERS_FILE = "holders.json"
CF_FILE = "creator_fees.json"    # DS-DLMM-SHARE-T1: the creator_fees collector saves the Dexscreener pairs and their 24 h volume
CF_SCHEMA = "holder-scan-creator-fees/1"
DEX_PAIRS_CAP = 30               # creator_fees.DEX_PAIRS_CAP: a Dexscreener answer of 30 pairs is read as capped (more may exist)
SHARE_HEAD = "DLMM share of the token's 24 h volume"
NO_PAIR_LIST = "this run saved no per-pair volume; re-scan"  # a run made before the creator_fees collector saved the pairs
WIB = dt.timezone(dt.timedelta(hours=7))
REASON_RE = re.compile(r"[^A-Za-z0-9_ ]")
DUST_CAP = 6                     # dust or blacklisted pools named before "and N more"
BAR_WHY = ("owner's rule of 2026-10-25: 300% under 6 h, 20% from 6 h; "
           "provisional and unvalidated")
LIFETIME_NOTE = "for a pool younger than 24 h, the \"24h\" figures cover only its lifetime so far"
PRESENT_CANNOT_SEE = ("fees can drop fast after a pump (a snapshot at scan time); the windows are Meteora's own (its indexer's 1h, 4h, "
                      "12h and 24h); fee/TVL is the pool average, not what your bins would earn; LP Agent shares a 5 requests-a-minute "
                      "key with the trading bot, so its cross-check can be not read (rate limited)")


class NotRead(Exception):
    """A source cannot be read; the reason is printed."""


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None


def _reason(value: Any) -> str:
    """A reason read back from a saved file: letters, digits, _ and spaces only, capped."""
    return (" ".join(REASON_RE.sub("", value).split())[:64] if isinstance(value, str) else "") or "unknown"


def _parse_time(value: Any) -> float | None:
    """A saved ISO time with a time zone as a unix time; anything else is None."""
    try:
        when = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError, OverflowError):
        return None
    return when.timestamp() if when.tzinfo is not None else None


def _when(ts: float) -> str:
    utc = dt.datetime.fromtimestamp(ts, dt.timezone.utc)
    return f"{utc:%Y-%m-%d %H:%M} UTC = {utc.astimezone(WIB):%Y-%m-%d %H:%M} WIB"


def age_text(seconds: float) -> str:
    """An age cut toward zero: "2d 4h", "5h 59m", "42m" (5 h 59 min 59 s reads 5h 59m, never 6h)."""
    minutes = int(max(0.0, seconds) // 60)
    days, hours, mins = minutes // 1440, (minutes % 1440) // 60, minutes % 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {mins}m"
    return f"{mins}m"


def pct_text(value: float) -> str:
    """A percent cut toward zero to 1 decimal, with thousands separators ("19.9%" for 19.99: never rounded up onto a bar)."""
    return f"{math.floor(round(value, 9) * 10) / 10:,.1f}%"


def bar_text(bar: float) -> str:
    return f"{bar:g}%"


def usd_text(value: float) -> str:
    """Three significant digits with k / M / B ("$1.28M", "$854"); under $1 reads "under $1"."""
    if value < 1:
        return "under $1"
    value = float(f"{value:.3g}")
    for scale, suffix in ((1e9, "B"), (1e6, "M"), (1e3, "k")):
        if value >= scale:
            return f"${value / scale:.3g}{suffix}"
    return f"${value:.3g}"


def _maybe(value: Any, fmt: Callable[[float], str]) -> str:
    number = _number(value)
    return fmt(number) if number is not None else "not read"


def _load_meteora(run: Path) -> dict[str, Any]:
    path = run / OUT_FILE
    data = _read(path)
    if not path.exists():
        raise NotRead(f"{OUT_FILE} missing")
    if not (isinstance(data, dict) and data.get("schema") == SCHEMA and data.get("status") in ("ok", "empty", "unavailable")
            and _address(data.get("mint")) and _parse_time(data.get("fetched_at")) is not None):
        raise NotRead(f"{OUT_FILE} unreadable")
    if data["status"] == "unavailable":
        raise NotRead(f"Meteora unavailable: {_reason(data.get('reason'))}")
    if not isinstance(data.get("pools"), list):
        raise NotRead(f"{OUT_FILE} unreadable")
    return data


def _load_lpagent(run: Path, mint: str | None) -> dict[str, Any]:
    path = run / LP_FILE
    data = _read(path)
    if not path.exists():
        raise NotRead(f"{LP_FILE} missing; the lpagent_pools collector did not run")
    if not (isinstance(data, dict) and data.get("schema") == LP_SCHEMA and data.get("status") in ("ok", "empty", "unavailable")
            and _address(data.get("mint")) and _parse_time(data.get("fetched_at")) is not None):
        raise NotRead(f"{LP_FILE} unreadable")
    if mint is not None and data["mint"] != mint:
        raise NotRead(f"{LP_FILE} is for another mint")
    if data["status"] == "unavailable":
        raise NotRead(_reason(data.get("reason")))
    if not isinstance(data.get("pools"), list):
        raise NotRead(f"{LP_FILE} unreadable")
    return data


def _meteora_pools(data: dict[str, Any]) -> list[dict[str, Any]]:
    """The saved pools, every value validated again (a damaged entry is skipped, a damaged number is None)."""
    pools, seen = [], set()
    for p in data["pools"]:
        address = _address(p.get("address")) if isinstance(p, dict) else None
        if address is None or address in seen:
            continue
        seen.add(address)
        ratio = _dict(p.get("fee_tvl_ratio"))
        bin_step = _count(p.get("bin_step"))
        pools.append({"address": address, "symbol": _label(p.get("symbol")), "other_symbol": _label(p.get("other_symbol")),
                      "bin_step": bin_step, "base_fee_pct": _number(p.get("base_fee_pct"), 0.0, 100.0), "tvl": _number(p.get("tvl")),
                      "fees_24h": _number(p.get("fees_24h")), "volume_24h": _number(p.get("volume_24h")),
                      "ratio": {w: _number(ratio.get(w)) for w in WINDOWS_KEPT}, "created": _parse_time(p.get("created_at")),
                      "blacklisted": p.get("blacklisted") is True})
    return pools


def _lp_pools(data: dict[str, Any], mint: str) -> list[dict[str, Any]]:
    """The saved LP Agent rows of this mint, validated again, in the same shape as the Meteora pools."""
    pools, seen = [], set()
    for p in data["pools"]:
        address = _address(p.get("pool")) if isinstance(p, dict) else None
        if address is None or address in seen or mint not in (p.get("token0"), p.get("token1")):
            continue
        seen.add(address)
        pools.append({"address": address, "symbol": None, "other_symbol": None, "bin_step": _count(p.get("bin_step")), "base_fee_pct": None,
                      "tvl": _number(p.get("tvl")), "fees_24h": _number(p.get("fee_24h")), "volume_24h": _number(p.get("vol_24h")),
                      "ratio": {w: (_number(p.get("fee_tvl_ratio_24h")) if w == "24h" else None) for w in WINDOWS_KEPT},
                      "created": _parse_time(p.get("created_at")), "first_pool": _parse_time(p.get("first_pool_created_at")),
                      "blacklisted": False, "dlmm": p.get("protocol") == LP_DLMM_PROTOCOL})
    return pools


def token_age(run: Path, mint: str, scan: float, pools: list[dict[str, Any]], lp: list[dict[str, Any]]) -> tuple[float | None, str]:
    """(age in seconds at scan, where it came from). Order: holders.json earliest_pair_created_at (Dexscreener's earliest
    pair), LP Agent's first_pool_created_at, the oldest DLMM pool's created_at (the token may be older); else unknown."""
    holders = _read(run / HOLDERS_FILE)
    launch = holders.get("earliest_pair_created_at") if isinstance(holders, dict) and holders.get("mint") == mint else None
    if isinstance(launch, int) and not isinstance(launch, bool) and 0 < launch <= scan + 3600:
        return scan - launch, f"the oldest trading pair (Dexscreener's earliest pair in {HOLDERS_FILE}, created {_when(launch)})"
    firsts = [p["first_pool"] for p in lp if p.get("first_pool") is not None and p["first_pool"] <= scan + 3600]
    if firsts:
        return scan - min(firsts), f"LP Agent's first_pool_created_at ({_when(min(firsts))}; {HOLDERS_FILE} gave no pair time)"
    created = [p["created"] for p in pools if p["created"] is not None and p["created"] <= scan + 3600]
    if created:
        return scan - min(created), f"the oldest DLMM pool ({_when(min(created))}); the token may be older"
    return None, "unknown (no pair time in holders.json, no LP Agent first pool time, no DLMM pool time)"


def bar_for(age: float | None) -> float:
    """300% for a token younger than 6 h; 20% from 6 h and when the age is unknown."""
    return FEE_TVL_YOUNG_BAR_PCT if age is not None and age < YOUNG_TOKEN_MAX_AGE_S else FEE_TVL_OLD_BAR_PCT


def meets(value: float, bar: float) -> bool:
    return round(value, 9) >= bar  # float noise never moves a pool exactly at the bar


def flag_line(best: dict[str, Any] | None, bar: float, age: float | None, suffix: str = "") -> str:
    if best is None:
        return f"{LINE_HEAD}: WARNING — no Meteora DLMM pool with ${COUNTED_POOL_MIN_TVL_USD:,.0f}+ TVL found for this token{suffix}."
    x = pct_text(best["ratio"]["24h"])
    if meets(best["ratio"]["24h"], bar):
        token = f"token {age_text(age)} old" if age is not None else "token age unknown, treated as 6 h or older"
        return f"{LINE_HEAD}: meets the bar (not a safety signal) — best Meteora DLMM pool {x} in 24h (bar {bar_text(bar)}; {token}){suffix}."
    token = f"a token {age_text(age)} old" if age is not None else "a token of unknown age (treated as 6 h or older)"
    return f"{LINE_HEAD}: WARNING — best Meteora DLMM pool earns {x} of its TVL in fees over 24h; the bar for {token} is {bar_text(bar)}{suffix}."


def _counted(pool: dict[str, Any]) -> bool:
    return not pool["blacklisted"] and pool["tvl"] is not None and pool["tvl"] >= COUNTED_POOL_MIN_TVL_USD


def _pool_lines(p: dict[str, Any], scan: float, bar: float) -> list[str]:
    pair = f"{p['symbol']}-{p['other_symbol']}, " if p["symbol"] and p["other_symbol"] else ""
    config = ", ".join(x for x in (f"bin step {p['bin_step']}" if p["bin_step"] else "", f"base fee {p['base_fee_pct']:g}%" if p["base_fee_pct"] is not None else "") if x)
    ratios = ", ".join(f"{w} {_maybe(p['ratio'][w], pct_text)}" for w in WINDOWS_KEPT)
    created = p["created"] if p["created"] is not None and p["created"] <= scan + 3600 else None  # a time after the scan is not read
    age = f"pool age {age_text(scan - created)}" if created is not None else "pool age not read"
    young = " (younger than 24 h)" if created is not None and scan - created < 86400 else ""
    ratio = p["ratio"]["24h"]
    verdict = ("24h fee/TVL not read" if ratio is None else "meets the bar (not a safety signal)" if meets(ratio, bar) else "below the bar")
    lines = [f"    pool {p['address']} ({pair}{config or 'config not read'}): TVL {_maybe(p['tvl'], usd_text)}, 24h fees {_maybe(p['fees_24h'], usd_text)}, "
             f"24h volume {_maybe(p['volume_24h'], usd_text)}; fee/TVL {ratios}; {age}{young}; {verdict}"]
    if p["fees_24h"] is not None and p["tvl"] is not None:
        lines.append(f"      after adding ${SMALL_POSITION_USD:,.0f} (a small position): {pct_text(p['fees_24h'] / (p['tvl'] + SMALL_POSITION_USD) * 100)} "
                     "(24h fees / (TVL + 2,500); your own liquidity counted in)")
    return lines


def _short_list(pools: list[dict[str, Any]]) -> str:
    shown = [f"{p['address']} (TVL {_maybe(p['tvl'], usd_text)}, 24h fee/TVL {_maybe(p['ratio']['24h'], pct_text)})" for p in pools[:DUST_CAP]]
    return ", ".join(shown) + (f", and {len(pools) - DUST_CAP} more" if len(pools) > DUST_CAP else "")


def _rel(a: float, b: float) -> float:
    """(a - b) / b, with b = 0 reading 0 when a is 0 too."""
    if b == 0:
        return 0.0 if a == 0 else math.inf
    return (a - b) / b


def _signed(rel: float) -> str:
    return "far apart" if not math.isfinite(rel) else f"{'+' if rel >= 0 else '-'}{math.floor(abs(rel) * 100 + 1e-9)}%"


def _cross_check(met: list[dict[str, Any]], lp: list[dict[str, Any]]) -> list[str]:
    by = {p["address"]: p for p in lp}
    lines = []
    for p in met:
        q = by.get(p["address"])
        if q is None:
            if _counted(p):
                lines.append(f"    pool {p['address']}: not listed by LP Agent")
            continue
        figures = f"LP Agent TVL {_maybe(q['tvl'], usd_text)}, 24h fee/TVL {_maybe(q['ratio']['24h'], pct_text)}"
        pairs = [(name, q[k] if k != "ratio" else q["ratio"]["24h"], p[k] if k != "ratio" else p["ratio"]["24h"]) for name, k in (("TVL", "tvl"), ("24h fee/TVL", "ratio"))]
        if any(a is None or b is None for _, a, b in pairs):
            lines.append(f"    pool {p['address']}: {figures}; not compared (a number not read)")
            continue
        rels = [(name, _rel(a, b)) for name, a, b in pairs]
        if all(round(abs(r), 9) <= LPAGENT_AGREE_REL for _, r in rels):  # both within 10%; exactly 10% is within
            lines.append(f"    pool {p['address']}: {figures}: agrees within 10%")
        else:
            lines.append(f"    pool {p['address']}: {figures}: differs from Meteora (" + ", ".join(f"{name} {_signed(r)}" for name, r in rels) + ")")
    known = {p["address"] for p in met}
    for q in lp:
        if q["address"] not in known:
            kind = "" if q["dlmm"] else " (not a DLMM pool by LP Agent's protocol field)"
            lines.append(f"    LP Agent also lists {q['address']}{kind} (TVL {_maybe(q['tvl'], usd_text)}, 24h fee/TVL {_maybe(q['ratio']['24h'], pct_text)}): "
                         "not in Meteora's answer")
    return lines


def _dex_pairs(run: Path, mint: str) -> tuple[list[tuple[str, bool, float | None]], bool]:
    """DS-DLMM-SHARE-T1: ([(pair address, whether this token is the quote side, 24 h volume)] once per pair address; whether
    Dexscreener's answer was capped), read from the dexscreener_pairs the creator_fees collector saved. The token is the
    quote side when the saved quote_mint is the mint (the collector keeps only pairs of this mint). Raises NotRead."""
    path = run / CF_FILE
    data = _read(path)
    if not path.exists():
        raise NotRead(f"{CF_FILE} missing; the creator_fees collector did not run")
    if not (isinstance(data, dict) and data.get("schema") == CF_SCHEMA and _address(data.get("mint"))):
        raise NotRead(f"{CF_FILE} unreadable")
    if data["mint"] != mint:
        raise NotRead(f"{CF_FILE} is for another mint")
    if "dexscreener_pairs" not in data:
        raise NotRead(NO_PAIR_LIST)
    dex = _dict(data.get("dexscreener"))
    if dex.get("status") != "ok":
        raise NotRead(f"Dexscreener not read by the creator_fees collector: {_reason(dex.get('reason'))}")
    saved = data["dexscreener_pairs"]
    if not isinstance(saved, dict) or not isinstance(saved.get("pairs"), list):
        raise NotRead(f"{CF_FILE} unreadable")
    pairs, seen = [], set()
    for p in saved["pairs"]:
        address = _address(p.get("pair_address")) if isinstance(p, dict) else None
        if address is None or address in seen:
            continue
        seen.add(address)
        pairs.append((address, p.get("quote_mint") == mint, _number(p.get("volume_h24"))))
    return pairs, saved.get("pairs_capped") is True


def _usd0(value: float) -> str:
    return "$0" if value == 0 else usd_text(value)


def _plural(k: int, word: str) -> str:
    return f"{k} {word}{'s' if k != 1 else ''}"


def share_line(run: Path, mint: str, counted: list[dict[str, Any]], inner: str = "", source_name: str = "Meteora") -> str:
    """DS-DLMM-SHARE-T1: how much of the token's 24 h volume went through the counted DLMM pools (the pools the block counts),
    one source where it can: Dexscreener's own 24 h volume on the counted pool addresses over Dexscreener's 24 h volume on
    the pairs where this token is the BASE side (a counted pool Dexscreener lists on the quote side counts on both sides).
    A counted pool missing from the saved pairs (the 30-pair cap, or not listed) or without a volume there takes
    `source_name`'s own figure on BOTH sides, numerator and total, and the line says "mixed sources ... counted on both
    sides": the numerator is always part of the total. Quote-side pairs (other coins priced in this token) are named, never
    counted. "> 100 %" stays as a guard (the sources disagree), unreachable while the numerator is part of the total; not
    read with the reason when no pair volume was saved. Presentation only."""
    try:
        pairs, capped = _dex_pairs(run, mint)
    except NotRead as why:
        return f"  {SHARE_HEAD}: not read ({why})"
    if not pairs:
        return f"  {SHARE_HEAD}: not read (Dexscreener lists no pair of this token in {CF_FILE})"
    by_address = {address: (quote_side, volume) for address, quote_side, volume in pairs}
    own = {p["address"] for p in counted}
    base_known = [volume for address, quote_side, volume in pairs if (not quote_side or address in own) and volume is not None]
    quote = [volume for address, quote_side, volume in pairs if quote_side and address not in own]
    if not base_known:
        return f"  {SHARE_HEAD}: not read (no 24 h volume on a base-side Dexscreener pair in {CF_FILE})"
    numerator, fallback, added, left_out = [], set(), [], 0
    for p in counted:
        dex_volume = by_address.get(p["address"], (False, None))[1]
        if dex_volume is not None:
            numerator.append(dex_volume)
        elif p["volume_24h"] is not None:
            fallback.add(p["address"])
            numerator.append(p["volume_24h"])
            added.append(p["volume_24h"])  # a fallback pool's volume goes into the total too
        else:
            left_out += 1
    n = len(counted)
    if counted and not numerator:
        return f"  {SHARE_HEAD}: not read (24 h volume not read on the counted DLMM pools{inner})"
    total, dlmm = math.fsum(base_known + added), math.fsum(numerator)
    if total == 0 and dlmm == 0:
        return f"  {SHARE_HEAD}: not read (no 24 h volume: $0 on every base-side Dexscreener pair in {CF_FILE})"
    over = round(dlmm, 2) > round(total, 2)
    share = "> 100 %" if over else f"{math.floor(round(min(dlmm / total, 1.0) * 100, 9) * 10) / 10:.1f} %"
    scope = f"base-side pairs per Dexscreener ({CF_FILE})" + (f", first {DEX_PAIRS_CAP} pairs" if capped else "")
    pools = _plural(n, "DLMM pool") + " counted"
    if n and fallback:
        pools += f" (mixed sources: {len(fallback)} of {n} pools from {source_name}, counted on both sides)"
    elif n and not left_out:
        pools += ", all in Dexscreener's list"
    parts = [f"{_usd0(dlmm)} of {_usd0(total)}, {scope}", pools]
    reported = [p["volume_24h"] for p in counted if p["volume_24h"] is not None]
    if reported:
        parts.append(f"{source_name} reports {_usd0(math.fsum(reported))} on " + ("them" if len(reported) == n else f"{len(reported)} of them"))
    silent = sum(1 for address, quote_side, volume in pairs if (not quote_side or address in own) and volume is None and address not in fallback)
    if silent:
        parts.append(_plural(silent, "base-side Dexscreener pair") + " without a 24 h volume left out")
    if left_out:
        parts.append(_plural(left_out, "counted pool") + " without a 24 h volume left out")
    if quote:
        known = [v for v in quote if v is not None]
        parts.append("quote-side pairs (other coins priced in this token) " + (_usd0(math.fsum(known)) if known else "24 h volume not read") + ", not counted")
    if over:
        parts.append("the sources disagree: the counted pools' 24 h volume is more than Dexscreener's on the base-side pairs")
    return f"  {SHARE_HEAD}: {share} (" + "; ".join(parts) + f"{inner})"


def measure_and_print(run: Path) -> list[str]:
    met_data = lp_data = None
    met_why = lp_why = ""
    try:
        met_data = _load_meteora(run)
    except NotRead as why:
        met_why = str(why)
    mint = met_data["mint"] if met_data else None
    try:
        lp_data = _load_lpagent(run, mint)
    except NotRead as why:
        lp_why = str(why)
    if met_data is None and lp_data is None:
        why = f"Meteora not read: {met_why}; LP Agent not read: {lp_why}"
        return [f"{SUMMARY_MARK}{NOT_READ_HEAD}: not read ({why})", f"{TITLE}: not read ({why})"]
    mint = mint or lp_data["mint"]
    scan = _parse_time((met_data or lp_data)["fetched_at"])
    met = _meteora_pools(met_data) if met_data else []
    lp = _lp_pools(lp_data, mint) if lp_data else []
    age, age_from = token_age(run, mint, scan, met, lp)
    bar = bar_for(age)
    if met_data:
        source, suffix, inner = met, "", ""
    else:
        source, suffix, inner = [p for p in lp if p["dlmm"]], LP_SUFFIX, LP_NOT_READ_SUFFIX
    counted = sorted((p for p in source if _counted(p) and p["ratio"]["24h"] is not None), key=lambda p: -p["ratio"]["24h"])
    best = counted[0] if counted else None
    no_tvl = [p for p in source if not p["blacklisted"] and p["tvl"] is None]  # missing, not a number, negative: cannot be counted or ruled out
    if best is None and any(_counted(p) for p in source):  # $2,000+ TVL pools whose 24h fee/TVL was not read: never "no pool"
        line = f"{NOT_READ_HEAD}: not read (24h fee/TVL not read on the Meteora DLMM pools with ${COUNTED_POOL_MIN_TVL_USD:,.0f}+ TVL{inner})"
    elif best is None and no_tvl:  # Repair R1 (C1): an unreadable TVL may hide a real pool: never "no pool"
        line = f"{NOT_READ_HEAD}: not read (TVL not read on {len(no_tvl)} Meteora DLMM pool{'s' if len(no_tvl) != 1 else ''}{inner})"
    else:
        line = flag_line(best, bar, age, suffix)
    lines = [f"{SUMMARY_MARK}{line}", TITLE]
    lines.append(f"  token age: {age_text(age) + ' at scan, from ' + age_from if age is not None else age_from + ': treated as 6 h or older, so the 20% bar applies'}; "
                 f"scan {_when(scan)}")
    why = "age unknown" if age is None else "younger than 6 h" if age < YOUNG_TOKEN_MAX_AGE_S else "6 h or older"
    lines.append(f"  bar: {bar_text(bar)} of TVL in fees over 24h for this token ({why}; {BAR_WHY})")
    if met_data:
        answer = _dict(met_data.get("answer"))
        sent = _count(_dict(met_data.get("request")).get("requests_sent"))
        listed = f"{len(met)} DLMM pool{'s' if len(met) != 1 else ''} of this token" if met else "no DLMM pool of this token listed"
        lines.append(f"  Meteora DLMM datapi: read; {listed}; {sent if sent is not None else 'unknown'} request{'s' if sent != 1 else ''}"
                     + (f"; more than {PAGE_SIZE} pools matched" + (f" (Meteora reports {total})" if (total := _count(answer.get("total"))) is not None else "")
                        + f": only the first {PAGE_SIZE} by 24h fee/TVL were read" if answer.get("truncated") is True else ""))
    else:
        lines.append(f"  Meteora DLMM datapi: not read ({met_why}); the line uses LP Agent's figures (24h only, LP Agent's DLMM rows); Meteora's blacklist "
                     "is not visible in LP Agent's rows, so a pool Meteora blacklists could be counted here")
    shown = [p for p in source if _counted(p)]
    if shown:
        lines.append(f"  counted pools (not blacklisted, TVL ${COUNTED_POOL_MIN_TVL_USD:,.0f} or more), best 24h fee/TVL first:")
        for p in sorted(shown, key=lambda p: -(p["ratio"]["24h"] if p["ratio"]["24h"] is not None else -1.0)):
            lines += _pool_lines(p, scan, bar)
    else:
        lines.append(f"  counted pools (not blacklisted, TVL ${COUNTED_POOL_MIN_TVL_USD:,.0f} or more): none")
    try:  # DS-DLMM-SHARE-T1: one added line; a damaged creator_fees.json never costs the rest of the block
        lines.append(share_line(run, mint, shown, inner, "Meteora" if met_data else "LP Agent"))
    except Exception:  # noqa: BLE001
        lines.append(f"  {SHARE_HEAD}: not read (saved values unreadable)")
    dust = [p for p in source if not p["blacklisted"] and p["tvl"] is not None and not _counted(p)]
    if dust:
        lines.append(f"  under ${COUNTED_POOL_MIN_TVL_USD:,.0f} TVL (dust; never decide the line): {_short_list(dust)}")
    if no_tvl:
        lines.append(f"  TVL not read (cannot be counted or ruled out; with no counted pool the line reads not read): {_short_list(no_tvl)}")
    blacklisted = [p for p in source if p["blacklisted"]]
    if blacklisted:
        lines.append(f"  blacklisted by Meteora (never decide the line): {_short_list(blacklisted)}")
    stale = LP_STALE if lp_data is not None and lp_data.get("stale") is True else ""  # Repair R1 (C3): LP Agent's own meta.isStale
    if lp_data is None:
        lines.append(f"  LP Agent cross-check: not read ({lp_why})")
    elif not met_data:
        other = [p for p in lp if not p["dlmm"]]
        lines.append(f"  LP Agent: read (one /pools/discover call){stale}; {len(lp)} pool{'s' if len(lp) != 1 else ''} of this token listed"
                     + (f"; not DLMM by LP Agent's protocol field, never counted: {_short_list(other)}" if other else ""))
    elif not lp:
        lines.append(f"  LP Agent cross-check{stale}: LP Agent lists no Meteora pool of this token with $1,000+ liquidity")
    else:
        lines.append(f"  LP Agent cross-check (one /pools/discover call; LP Agent's 24h figure; agrees = TVL and 24h fee/TVL both within 10%){stale}:")
        lines += _cross_check(met, lp) or ["    no Meteora pool of this token to compare"]
    lines += [f"  note: {LIFETIME_NOTE}", f"  cannot see: {PRESENT_CANNOT_SEE}", f"  {PRESENTATION_NOTE}"]
    removed = pw.count(lines)
    if removed:  # HS-LABELS-T1: say how many placeholders this block shows
        lines.append(f"  {pw.removed_line(removed)}")
    return lines


def present(run: Path) -> list[str]:
    """The FEE/TVL line (marked) and the block, offline (no network, no key). Missing, foreign or malformed files read as
    not read, never as a crash and never as "meets the bar"."""
    try:
        return measure_and_print(run)
    except Exception:  # noqa: BLE001 - a damaged file never crashes the synthesis; it reads as not read
        return [f"{SUMMARY_MARK}{NOT_READ_HEAD}: not read (saved values unreadable)", f"{TITLE}: not read (saved values unreadable)"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read the Meteora DLMM pools of a Solana mint from Meteora's free datapi (one request, no key; "
                                                 "bounded: 2 MiB, 30 s, no redirects, no env proxy, at most one retry after a 429 or a 5xx) "
                                                 f"and save {OUT_FILE}; or, with --present RUN_DIR, print the FEE/TVL line (Yun's rule, "
                                                 "provisional) and its block offline. Presentation only: never an engine input.")
    parser.add_argument("mint", nargs="?")
    parser.add_argument("--out", metavar="RUN_DIR", help="run folder to write meteora_pools.json into (no other file of it is read)")
    parser.add_argument("--present", metavar="RUN_DIR", help="offline: print the line and the block from a saved run folder (no network, no key)")
    args = parser.parse_args(argv)
    if args.present is not None:
        if args.mint or args.out:
            print("error: --present takes only the run folder", file=sys.stderr)
            return 2
        run = Path(args.present)
        if not run.is_dir():
            print("error: --present is not a run folder", file=sys.stderr)
            return 2
        for line in present(run):
            print(line)
        return 0
    if not isinstance(args.mint, str) or not SOLANA_ADDRESS_RE.fullmatch(args.mint):
        print("error: mint is not a valid base58 Solana address", file=sys.stderr)
        return 2
    if not args.out:
        print("error: --out is required", file=sys.stderr)
        return 2
    run = Path(args.out)
    try:
        run.mkdir(parents=True, exist_ok=True)
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    try:
        result = collect_meteora_pools(args.mint)
    except Exception:  # noqa: BLE001 - never print a traceback
        result = _base(args.mint, _iso(time.time()))
        result["reason"] = "request_failed"
    try:
        (run / OUT_FILE).write_text(json.dumps(result, indent=1), encoding="utf-8")
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    print(status_line(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
