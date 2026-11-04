#!/usr/bin/env python3
"""LP Agent's Meteora pools of a token for dlmm-scan (first-wave collector `lpagent_pools`, DS-FEETVL-T1): exactly one
bounded, read-only request per scan, the cross-check of the Meteora DLMM fee/TVL numbers.

LP Agent (api.lpagent.io) is a third-party LP tool. Its /pools/discover list gives, per pool, the TVL, the 24h fees and a
fee/TVL ratio that is always the 24h one, in percent (LP Agent's docs, checked 2026-10-18), plus the pool's
created_at and the token's first_pool_created_at (a token-age proxy). The synthesis compares it with Meteora's own numbers
(meteora_pools.py --present); it never decides the FEE/TVL line while Meteora is readable.

Request (provider-docs cache current/lpagentio/fulldocs.pages/api-reference/pools/discover-pools.md):
  GET /open-api/v1/pools/discover?search=<MINT>&platform=meteora&pageSize=20&min_liquidity=1000&sortBy=tvl
Host api.lpagent.io only, https only, the key only in the x-api-key header, a User-Agent, no redirects, no environment
proxy, 2 MiB and a hard 30 s wall-clock limit per attempt (opening, every read and closing under one deadline, worker
thread: the fomoapi.py pattern). EXACTLY ONE request per scan; at most one retry, only after a 429, and only after waiting
at least 12.5 s (the Retry-After when it is longer, up to 30 s; longer: no retry). The owner's key is a Basic lifetime plan
at 5 requests a minute, and the live trading bot uses the same key, so a 429 is expected now
and then: it is reported, never hidden.

Key: only LPAGENT_API_KEY (the name in the repository .env), from the environment first, then exactly that one variable from the
repository .env (single-variable parser; the file is never sourced). It is sent only in the x-api-key header and is never printed,
logged, saved or put in an error: every failure becomes a fixed reason ("LPAGENT_API_KEY not set" when there is none; then
no request is sent). Provider text is untrusted: only validated addresses, numbers, times and LP Agent's protocol name (from
a fixed list) are kept, and an address sharing 8 or more consecutive characters with the key is dropped.

Collector: lpagent_pools.py <MINT> --out <RUN> writes <RUN>/lpagent_pools.json and prints one line: ok (...), empty (...) or
unavailable (<reason>; ...). Exit 0 whenever the file was saved (no key, 401 / 403, a 429 after the retry and every other
failure included); exit 2 for a bad mint or an unwritable --out. It reads no file of the run folder (a first-wave collector
waits for nothing). On by default by the owner's decision of 2026-10-25 ("On every scan (Recommended)", recorded in
collectors.json and pinned in tests/test_execution_rule.py). LP Agent's meta.isStale / meta.lastUpdatedAt are saved as
stale / last_updated_at. PRESENTATION ONLY: never an engine input. Standard library only; Python >= 3.10.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
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

HOST = "api.lpagent.io"
DISCOVER_PATH = "/open-api/v1/pools/discover"
PAGE_SIZE = 20
MIN_LIQUIDITY_USD = 1000         # LP Agent lists dust pools first without it (memory note, 2026-10-18)
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = 30.0                 # per attempt: a hard wall-clock limit on open + every read + close (worker thread)
RETRY_MIN_WAIT_S = 12.5          # the one retry after a 429 waits at least this long (5 requests a minute = one per 12 s)
RETRY_MAX_WAIT_S = 30.0          # a Retry-After longer than this: no retry
REQUESTS_PER_SCAN = 1
MAX_REQUESTS = 2
RATE_LIMIT_PER_MINUTE = 5        # the owner's Basic lifetime plan, shared with the live trading bot
USER_AGENT = "holder-scan-lpagent-pools/1.0"
KEY_NAME = "LPAGENT_API_KEY"
KEY_HEADER = "x-api-key"
NO_KEY_REASON = f"{KEY_NAME} not set"
KEY_RE = re.compile(r"^[\x21-\x7e]{8,512}$")  # printable, no spaces: a valid header value; the value is never echoed
KEY_PIECE = 8                    # an address sharing this many consecutive characters with the key is dropped
SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
NUMBER_TEXT_RE = re.compile(r"^-?[0-9]{1,15}(?:\.[0-9]{1,18})?(?:[eE][-+]?[0-9]{1,3})?$")
PROTOCOLS = ("meteora", "meteora_damm_v2")  # LP Agent's names: meteora = DLMM, meteora_damm_v2 = DAMM v2 (memory note)
OUT_FILE = "lpagent_pools.json"
SCHEMA = "holder-scan-lpagent-pools/1"
HTTP_REASONS = {400: "bad_request", 401: "authentication_failed", 402: "payment_required", 403: "access_denied", 404: "not_found",
                429: "rate_limited", 503: "service_unavailable"}
CANNOT_SEE = ("LP Agent's own indexer numbers at one moment; its fee/TVL is always the 24h one; pools under $1,000 of liquidity "
              "are not listed (min_liquidity); one call, so a 429 from the shared 5 requests-a-minute key reads not read")
PRESENTATION_NOTE = ("presentation only: a cross-check of Meteora's numbers; never an engine input, never passed to assess, never "
                     "counted toward NO_ALARM; it never changes a FLAG, verdict or threshold")


def discover_query(mint: str) -> str:
    return f"search={mint}&platform=meteora&pageSize={PAGE_SIZE}&min_liquidity={MIN_LIQUIDITY_USD}&sortBy=tvl"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect (returning None makes urllib raise the 3xx as an HTTPError)."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class Failure(Exception):
    """A failed attempt, reduced to a fixed reason code. Never carries request text, headers or the key."""

    def __init__(self, reason: str, http_status: int | None = None, retry_wait: float | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status
        self.retry_wait = retry_wait


# ----------------------------------------------------------------------------- key (single-variable loader)


def find_env_file(explicit: str | None = None) -> Path | None:
    """Locate the repository .env without reading it: --env-file, then HOLDER_FORENSICS_ENV, then the base checkout of a
    .claude/worktrees checkout, then <repo>/.env. Only known locations, never an arbitrary ancestor."""
    skill_dir = Path(__file__).resolve().parents[1]
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    if os.environ.get("HOLDER_FORENSICS_ENV"):
        candidates.append(Path(os.environ["HOLDER_FORENSICS_ENV"]))
    marker = f"{os.sep}.claude{os.sep}worktrees{os.sep}"
    if marker in str(skill_dir):
        candidates.append(Path(str(skill_dir).split(marker)[0]) / ".env")
    candidates.append(skill_dir.parents[1] / ".env")
    for path in candidates:
        if path.is_file():
            return path
    return None


def _clean_env_value(value: str) -> str:
    value = value.strip()
    if value[:1] in ("'", '"') and value[-1:] == value[:1] and len(value) >= 2:
        return value[1:-1].strip()
    return re.split(r"\s+#", value, maxsplit=1)[0].strip()  # drop an unquoted inline comment


def load_key(env_file: Path | None) -> tuple[str | None, str | None]:
    """(key, None) or (None, reason). Environment first, then exactly the one LPAGENT_API_KEY line of the .env; no other
    line is kept. Never logs or returns the value in a reason."""
    key = os.environ.get(KEY_NAME, "").strip()
    if not key and env_file is not None:
        try:
            text = env_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None, "env_file_unreadable"
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("export "):
                line = line[7:].lstrip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, _, value = line.partition("=")
            if name.strip() == KEY_NAME:
                key = _clean_env_value(value)
                break
    if not key:
        return None, NO_KEY_REASON
    if not KEY_RE.match(key):
        return None, "key_format"
    return key, None


# ----------------------------------------------------------------------------- request


def check_url(url: str, mint: str) -> None:
    """https only, host api.lpagent.io only, the documented discover path with this mint's fixed query only, no port other
    than 443, no credentials in the URL."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise Failure("scheme_not_https")
    if parsed.hostname != HOST or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise Failure("host_not_allowlisted")
    if parsed.path != DISCOVER_PATH or parsed.query != discover_query(mint) or parsed.params or parsed.fragment:
        raise Failure("path_not_allowlisted")


def build_request(mint: str, key: str) -> urllib.request.Request:
    url = f"https://{HOST}{DISCOVER_PATH}?{discover_query(mint)}"
    check_url(url, mint)
    request = urllib.request.Request(url, method="GET")
    request.headers[KEY_HEADER] = key  # set directly so the header keeps the documented name
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", USER_AGENT)
    return request


def default_opener() -> urllib.request.OpenerDirector:
    """No environment proxy (an explicit empty ProxyHandler), no redirects, default TLS verification."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def _bounded_call(function: Callable[[], Any], timeout: float) -> Any:
    """Run one blocking transport step (open, read, close) in a daemon worker and wait at most `timeout` seconds: a hard
    wall-clock bound (the fomoapi.py and creator_fees.py pattern)."""
    if timeout <= 0:
        raise TimeoutError
    result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def invoke() -> None:
        try:
            result.put((True, function()))
        except BaseException as exc:  # handed back to the bounded caller
            result.put((False, exc))

    worker = threading.Thread(target=invoke, name="lpagent-pools-transport", daemon=True)
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


def _retry_wait(exc: urllib.error.HTTPError) -> float | None:
    """The wait before the one retry after a 429: at least RETRY_MIN_WAIT_S (12.5 s), longer when Retry-After asks for it,
    and no retry (None) when Retry-After asks for more than RETRY_MAX_WAIT_S or is unreadable."""
    headers = getattr(exc, "headers", None)
    raw = headers.get("Retry-After") if headers is not None else None
    if raw is None:
        return RETRY_MIN_WAIT_S
    text = str(raw).strip()
    if not re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,3})?", text):
        return None
    wait = max(RETRY_MIN_WAIT_S, float(text))
    return wait if wait <= RETRY_MAX_WAIT_S else None


def send_once(request: urllib.request.Request, opener: Any, mint: str, *, monotonic: Callable[[], float]) -> bytes:
    """One attempt. Returns the body (at most MAX_BYTES) or raises Failure with a fixed code. Opening, every read and the
    error close run under one hard wall-clock deadline of TIMEOUT_S. An error body is never read."""
    check_url(request.full_url, mint)
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
            raise Failure(HTTP_REASONS.get(status, "server_error" if 500 <= status <= 599 else "http_error"), status)
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
                raise Failure("rate_limited", 429, retry_wait=_retry_wait(exc)) from None
            raise Failure(HTTP_REASONS.get(exc.code, "server_error" if 500 <= exc.code <= 599 else "http_error"), exc.code) from None
        finally:
            try:
                _bounded_call(exc.close, remaining())
            except Exception:  # noqa: BLE001
                pass
    except (TimeoutError, socket.timeout):
        raise Failure("timeout") from None
    except urllib.error.URLError as exc:
        raise Failure("timeout" if isinstance(exc.reason, (TimeoutError, socket.timeout)) else "network_error") from None
    except Exception:  # noqa: BLE001 - never let exception text (which can carry request details) out
        raise Failure("network_error") from None
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            try:
                _bounded_call(close, remaining())
            except Exception:  # noqa: BLE001 - cleanup cannot extend the deadline
                pass


def fetch(mint: str, key: str, opener: Any, *, monotonic: Callable[[], float], sleep: Callable[[float], None]) -> dict[str, Any]:
    """The one documented request, plus at most one retry after a 429 (after waiting at least 12.5 s). Returns {body,
    attempts, reason, http_status, waited_s}; never raises."""
    out: dict[str, Any] = {"body": None, "attempts": 0, "reason": None, "http_status": None, "waited_s": 0.0}
    for attempt in (1, 2):
        out["attempts"] = attempt
        try:
            out.update(body=send_once(build_request(mint, key), opener, mint, monotonic=monotonic), reason=None, http_status=200)
            return out
        except Failure as failure:
            out.update(reason=failure.reason, http_status=failure.http_status)
            if attempt == 1 and failure.http_status == 429 and failure.retry_wait is not None:
                sleep(failure.retry_wait)
                out["waited_s"] = failure.retry_wait
                continue
            return out
        except Exception:  # noqa: BLE001 - defensive: no exception text leaves this function
            out.update(reason="request_failed", http_status=None)
            return out
    return out


# ----------------------------------------------------------------------------- parsing (provider text is untrusted)


def shares_key_piece(text: Any, key: str | None) -> bool:
    """True when `text` and the key share any run of KEY_PIECE (8) or more consecutive characters."""
    if not key or not isinstance(text, str) or not text:
        return False
    if len(key) < KEY_PIECE:
        return key in text
    return any(key[i:i + KEY_PIECE] in text for i in range(len(key) - KEY_PIECE + 1))


def _address(value: Any, key: str | None) -> str | None:
    return value if isinstance(value, str) and SOLANA_ADDRESS_RE.fullmatch(value) and not shares_key_piece(value, key) else None


def _number(value: Any, lo: float = 0.0, hi: float = 1e18) -> float | None:
    """A finite number in [lo, hi], or a short decimal text of one (LP Agent sends some USD figures as text); anything
    else is None (never 0)."""
    if isinstance(value, str) and NUMBER_TEXT_RE.fullmatch(value.strip()):
        value = float(value.strip())
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) and lo <= number <= hi else None


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _time(value: Any) -> str | None:
    """An ISO time with a time zone (LP Agent: "2023-11-07T05:31:56Z" in the docs), kept as ISO UTC; else None."""
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        when = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        return None
    if when.tzinfo is None:
        return None
    return when.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def parse_discover(payload: Any, mint: str, key: str | None) -> dict[str, Any]:
    """The discover answer, field names as in the cached docs and the memory note: {status, data: [{pool, token0, token1,
    protocol, tvl, fee_24h, fee_tvl_ratio, vol_24h, bin_step, created_at, first_pool_created_at, ...}], pagination, meta
    {lastUpdatedAt, isStale}} (meta seen in the live answers of 2026-10-25: kept as stale / last_updated_at). Only
    rows whose token0 or token1 is the mint are kept. Loud guards: no data list gives unavailable (pool_list_missing); a
    status other than success gives unavailable (provider_error); kept rows of which none has a readable TVL and fee/TVL
    give unavailable (fee_tvl_field_missing); no row of this mint gives empty (no_pool_listed)."""
    if not isinstance(payload, dict):
        return {"status": "unavailable", "reason": "invalid_shape"}
    meta = _dict(payload.get("meta"))  # Repair R1 (C3): LP Agent's own freshness flag, kept as sent (true / false), else null
    fresh = {"stale": meta.get("isStale") if isinstance(meta.get("isStale"), bool) else None, "last_updated_at": _time(meta.get("lastUpdatedAt"))}
    if isinstance(payload.get("status"), str) and payload["status"] != "success":
        return {"status": "unavailable", "reason": "provider_error", **fresh}
    rows = payload.get("data")
    if not isinstance(rows, list):
        return {"status": "unavailable", "reason": "pool_list_missing", **fresh}
    pagination = _dict(payload.get("pagination"))
    total = pagination.get("totalCount")
    kept, other, unreadable = [], 0, 0
    for row in rows:
        if not isinstance(row, dict):
            unreadable += 1
            continue
        if mint not in (row.get("token0"), row.get("token1")):
            other += 1
            continue
        pool = _address(row.get("pool"), key)
        if pool is None:
            unreadable += 1
            continue
        protocol = row.get("protocol")
        bin_step = _number(row.get("bin_step"), 1, 10000)
        kept.append({
            "pool": pool, "token0": _address(row.get("token0"), key), "token1": _address(row.get("token1"), key),
            "protocol": protocol if protocol in PROTOCOLS else ("other" if protocol is not None else None),
            "tvl": _number(row.get("tvl")), "fee_24h": _number(row.get("fee_24h")), "fee_tvl_ratio_24h": _number(row.get("fee_tvl_ratio")),
            "vol_24h": _number(row.get("vol_24h")), "bin_step": int(bin_step) if bin_step is not None and bin_step.is_integer() else None,
            "created_at": _time(row.get("created_at")), "first_pool_created_at": _time(row.get("first_pool_created_at")),
        })
    answer = {"rows_in_answer": len(rows), "other_token_rows_dropped": other, "unreadable_rows": unreadable,
              "total_count": int(total) if isinstance(total, int) and not isinstance(total, bool) and total >= 0 else None}
    if not kept:
        return {"status": "empty", "reason": "no_pool_listed", "answer": answer, "pools": [], **fresh}
    if all(p["tvl"] is None or p["fee_tvl_ratio_24h"] is None for p in kept):
        return {"status": "unavailable", "reason": "fee_tvl_field_missing", "answer": answer, **fresh}
    return {"status": "ok", "reason": None, "answer": answer, "pools": kept, **fresh}


# ----------------------------------------------------------------------------- collect


def _base(mint: str, fetched_at: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "collector": "lpagent_pools", "provider": "LP Agent", "mint": mint, "status": "unavailable", "reason": None,
        "fetched_at": fetched_at, "http_status": None,
        "request": {"method": "GET", "host": HOST, "path": f"{DISCOVER_PATH}?search=<MINT>&platform=meteora&pageSize={PAGE_SIZE}&min_liquidity={MIN_LIQUIDITY_USD}&sortBy=tvl",
                    "auth_header_names": [KEY_HEADER], "requests_per_scan": REQUESTS_PER_SCAN, "max_requests": MAX_REQUESTS,
                    "retry_only_after_429_waiting_at_least_s": RETRY_MIN_WAIT_S, "rate_limit_per_minute": RATE_LIMIT_PER_MINUTE,
                    "requests_sent": 0, "waited_s": 0.0},
        "docs": "provider-docs current/lpagentio/fulldocs.pages/api-reference/pools/discover-pools.md",
        "answer": None, "pools": [], "stale": None, "last_updated_at": None, "presentation_only": True, "note": PRESENTATION_NOTE, "cannot_see": CANNOT_SEE,
    }


def _decode(body: Any) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError, AttributeError):
        return None


def collect_lpagent_pools(
    mint: str,
    key: str | None,
    *,
    key_reason: str | None = None,
    opener: Any | None = None,
    now: Callable[[], float] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """One request (at most one retry after a 429, after at least 12.5 s). Returns the lpagent_pools.json result; never
    raises for provider or transport failures; without a key it sends nothing. Reads no file of the run folder."""
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    result = _base(mint, _iso(now()))
    if not key:
        result["reason"] = key_reason or NO_KEY_REASON
        return result
    got = fetch(mint, key, opener or default_opener(), monotonic=monotonic, sleep=sleep)
    result["request"].update(requests_sent=got["attempts"], waited_s=got["waited_s"])
    result["http_status"] = got["http_status"]
    result["fetched_at"] = _iso(now())
    if got["reason"] is not None:
        result["reason"] = got["reason"]
        return result
    payload = _decode(got["body"])
    if payload is None:
        result["reason"] = "invalid_json"
        return result
    try:
        result.update(parse_discover(payload, mint, key))
    except Exception:  # noqa: BLE001 - a malformed answer the guards did not foresee: a fixed code, the call still counted
        result.update(status="unavailable", reason="parse_error")
    return result


def status_line(result: dict[str, Any]) -> str:
    sent = result["request"]["requests_sent"]
    calls = f"{sent} LP Agent request{'s' if sent != 1 else ''}" if sent else "no LP Agent request sent"
    if result["status"] == "ok":
        n = len(result["pools"])
        return f"ok ({n} LP Agent pool{'s' if n != 1 else ''} of this token; {calls})"
    if result["status"] == "empty":
        return f"empty (LP Agent lists no Meteora pool of this token with $1,000+ liquidity; {calls})"
    return f"unavailable ({result['reason']}; {calls})"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read LP Agent's Meteora pools of a Solana mint (exactly one /pools/discover request; the "
                                                 "owner's key at 5 requests a minute, shared with the trading bot; bounded: 2 MiB, 30 s, no "
                                                 "redirects, no env proxy, at most one retry after a 429 and at least 12.5 s) and save "
                                                 f"{OUT_FILE}. The cross-check of meteora_pools.py --present. Presentation only.")
    parser.add_argument("mint")
    parser.add_argument("--out", metavar="RUN_DIR", required=True, help="run folder to write lpagent_pools.json into (no other file of it is read)")
    parser.add_argument("--env-file", metavar="PATH", help=f"the repository .env ({KEY_NAME} in the environment is used first)")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    if not SOLANA_ADDRESS_RE.fullmatch(args.mint):
        print("error: mint is not a valid base58 Solana address", file=sys.stderr)
        return 2
    run = Path(args.out)
    try:
        run.mkdir(parents=True, exist_ok=True)
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    try:
        key, reason = load_key(None if os.environ.get(KEY_NAME, "").strip() else find_env_file(args.env_file))
        result = collect_lpagent_pools(args.mint, key, key_reason=reason)
    except Exception:  # noqa: BLE001 - never print a traceback (it could carry request details)
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
