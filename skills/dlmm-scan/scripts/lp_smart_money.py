#!/usr/bin/env python3
"""Who LPs the main Meteora DLMM pool of a token, their PnL now and whether they are proven LPers, for dlmm-scan (follow-up
lane `lp_smart_money`, DS-LP-SMART-T1): at most 4 bounded, read-only LP Agent calls per scan, presentation only.

Owner request (2026-10-26): "add smart money labels from lpagent and their positions, their current pnl at the time of the
scan, etc for conviction in holding a dlmm position in LP". Owner decisions of 2026-10-26: the source is each big wallet's
LP Agent lifetime LP record ("Lifetime LP record (Recommended)"); the budget is 1 pool-positions call plus the records of the
3 biggest wallets, 4 calls per scan, on every scan ("1 + 3 wallets (Recommended)"); the pool is the largest-TVL DLMM pool
of the scan's free Meteora data ("Largest-TVL DLMM pool (Recommended)"); the bar is win rate 60% or more over 20 or more
LPs with a total PnL above 0 ("Win >=60%, >=20 LPs, PnL>0 (Recommended)"), provisional, shown next to the numbers, never a
FLAG. Decision 5 (2026-10-26, after Verifier round 1): "LP Agent's figure (Recommended)": the bar uses LP Agent's own
win_rate.ALL, which is not win_lp / total_lp on any recorded wallet (it appears to leave out LPs that ended flat: inferred,
undocumented); the block prints the strict "X of Y LPs won (Z%)" next to it.

1. Pool (offline, no call): the largest-TVL Meteora DLMM pool of this mint in <RUN>/meteora_pools.json (status ok, TVL at
   least meteora_pools.COUNTED_POOL_MIN_TVL_USD, the FEE/TVL rule's dust bar, by import; blacklisted pools skipped); else the
   largest LP Agent DLMM row of <RUN>/lpagent_pools.json (protocol meteora, the same TVL bar, a pool Meteora blacklists
   skipped); else empty (no_dlmm_pool) and no call.
2. Call 1: GET /open-api/v1/pools/<POOL>/positions?status=Open&page=1&pageSize=20&order_by=inputNative&sort_order=desc
   (provider-docs current/lpagentio/fulldocs.pages/api-reference/pools/get-positions-for-a-specific-pool.md): one page of the
   20 open positions with the largest input. Per position: owner, position address, value now, input, PnL now (USD and %),
   fees, bin range (tickLower / tickUpper) against the pool's active bin, LP Agent's strategy label and the creation time.
3. Calls 2-4: GET /open-api/v1/lp-positions/overview?owner=<WALLET>&protocol=meteora (provider-docs
   .../positions/get-overview-metrics-for-lp-positions.md) for the 3 biggest distinct owners by value now in this pool (sum
   of their open positions on that page; an emptied position, value 0, counts nothing): their lifetime LP record (LPs,
   wins, win rate and total PnL per window, ROI, inflow, open LPs, first and last activity). The lane never calls
   /top-lpers (Premium or Enterprise plans only; 401 on the owner's key, 2026-10-19).

Requests: host api.lpagent.io only, https only, GET only, the two paths and fixed queries above only, the key only in the
x-api-key header, a User-Agent, no redirects, no environment proxy, 2 MiB and a hard 30 s wall-clock limit per attempt
(lpagent_pools.py's bounded call, by import). Pace: each attempt starts at least MIN_GAP_S (12.5 s) after the previous LP
Agent attempt ended, and the first one at least 12.5 s after <RUN>/lpagent_pools.json fetched_at (plus 1 s, because that
time is cut to the second) when that is recent; the owner's Basic lifetime plan allows 5 requests a minute and the live
trading bot shares the key. At most one retry per call, only after a 429, after
lpagent_pools.py's wait (_retry_wait, by import: at least 12.5 s, a Retry-After up to 30 s; longer: no retry): at most
MAX_CALLS (4) calls and MAX_REQUESTS (8) requests per scan. A failed call makes only its part not read; after a call ends
rate limited (or refused: 401, 402, 403) no further call is sent and the wallets left read "not read (not sent: ...)".
lpagent_pools.send_once checks its own discover URL, so this file has its own send_once on the same bounded pattern with
this file's URL check; the bounded call, the Failure codes, the HTTP reason codes, the 429 wait, the opener, the number and
time readers and the key loader are lpagent_pools.py's, by import.

Key: only LPAGENT_API_KEY, through lpagent_pools.py's single-variable loader (environment first, then that one variable from
the repository .env), by import. It is sent only in the x-api-key header and never printed, logged, saved or put in an error:
every failure is a fixed reason code; an address sharing 8 or more consecutive characters with the key is dropped
(lpagent_pools.shares_key_piece), and the saved file is checked once more before it is written. Provider text is untrusted:
pair names, token names, logos, messages and LP Agent's strategy label are never saved or printed as sent; only validated
addresses, numbers, dates and fixed codes are kept (the strategy label is mapped to a fixed word).

Collector: lp_smart_money.py <MINT> --out <RUN> reads <RUN>/meteora_pools.json and <RUN>/lpagent_pools.json, writes
<RUN>/followup/lp_smart_money.json and prints one line: ok (...), empty (...) or unavailable (<reason>; ...). Exit 0
whenever the file was saved; exit 2 for a bad mint or --out. It is a follow-up lane because it reads first-wave files.
Synthesis (offline, no network, no key): lp_smart_money.py --present <RUN> also reads <RUN>/holders.json (share and rank)
and <RUN>/followup/create_slot_trace.json (this token's dev wallets, only when ok or empty) through quote_curves.py's
readers, by import, and prints the LP SMART MONEY line (marked [for the executive summary]) and the block. PRESENTATION
ONLY: LP Agent's numbers are LP Agent's claims; the label is a provisional bar with no negative controls; never an engine
input, never passed to assess, never counted toward NO_ALARM; it never changes a FLAG, verdict or threshold. Standard
library only; Python >= 3.10.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # python3 -I leaves the script's folder off sys.path
    sys.path.insert(0, str(HERE))

import lpagent_pools as lp  # noqa: E402  (the key loader, the key-echo guard, the bounded call, the 429 wait, the opener, by import)
import meteora_pools as mp  # noqa: E402  (the dust bar and the number and age texts, by import)
import quote_curves as qc  # noqa: E402  (this token's dev wallets and the holder index, offline readers, by import)

# ----------------------------------------------------------------------------- PROVISIONAL (unvalidated)
# Owner decision of 2026-10-26 (DS-LP-SMART-T1, "Win >=60%, >=20 LPs, PnL>0 (Recommended)"): a wallet is a "proven LPer" when
# LP Agent's lifetime record (window ALL) shows a win rate of 60% or more over 20 or more LPs and a total PnL above 0 (USD).
# No negative controls and no outcomes yet: shown next to the numbers, never a FLAG, never a verdict input. The win rate is LP
# Agent's own win_rate.ALL (decision 5, "LP Agent's figure (Recommended)"), never win_lp / total_lp, which is printed beside it.
PROVEN_MIN_WIN_RATE = 0.60
PROVEN_MIN_LPS = 20
PROVEN_MIN_TOTAL_PNL_USD = 0.0   # strictly above
BAR_WINDOW = "ALL"
# ----------------------------------------------------------------------------- end PROVISIONAL

HOST = lp.HOST
POSITIONS_PATH = "/open-api/v1/pools/{pool}/positions"
POSITIONS_PATH_RE = re.compile(r"^/open-api/v1/pools/([1-9A-HJ-NP-Za-km-z]{32,44})/positions$")
POSITIONS_QUERY = "status=Open&page=1&pageSize=20&order_by=inputNative&sort_order=desc"
PAGE_SIZE = 20
OVERVIEW_PATH = "/open-api/v1/lp-positions/overview"
OVERVIEW_PROTOCOL = "meteora"
MAX_WALLETS = 3
MAX_CALLS = 1 + MAX_WALLETS      # 4
MAX_REQUESTS = 2 * MAX_CALLS     # 8: one retry per call, only after a 429
MIN_GAP_S = lp.RETRY_MIN_WAIT_S  # 12.5 s between LP Agent attempts (5 requests a minute = one per 12 s)
FETCHED_AT_SLACK_S = 1.0         # lpagent_pools.json fetched_at is cut to the second
MIN_POOL_TVL_USD = mp.COUNTED_POOL_MIN_TVL_USD
USER_AGENT = "holder-scan-lp-smart-money/1.0"
OUT_DIR = "followup"
OUT_FILE = "lp_smart_money.json"
SCHEMA = "holder-scan-lp-smart-money/1"
SUMMARY_MARK = mp.SUMMARY_MARK
NOT_FOUND_MESSAGE = "Owner overview not found"  # the documented error text, compared only, never kept or printed
STOP_REASONS = ("rate_limited", "authentication_failed", "payment_required", "access_denied")
DATE_RE = re.compile(r"^([0-9]{4}-[0-9]{2}-[0-9]{2})(?:[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,6})?)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)?$")
CANNOT_SEE = ("LP Agent's numbers at one moment (its PnL method, its windows, its indexer; not checked on-chain here); only "
              f"the first page of {PAGE_SIZE} open positions, the largest input first, so a wallet's other positions in this pool "
              f"and positions further down are not read; only the {MAX_WALLETS} biggest wallets by value now get a lifetime record; "
              "a lifetime record covers every Meteora pool the wallet LPed, not this token; a big LPer can be this token's dev or "
              "an insider providing exit liquidity; the shared 5 requests-a-minute key can read not read (rate limited)")
PRESENTATION_NOTE = ("presentation only: LP Agent's claims shown next to the holder forensics; never an engine input, never "
                     "passed to assess, never counted toward NO_ALARM; it never changes a FLAG, verdict or threshold; a proven "
                     "LPer in the pool is not a safety signal")


# ----------------------------------------------------------------------------- small validated readers


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None


def _signed_number(value: Any) -> float | None:
    """A finite number or short numeric text (LP Agent sends some as text), negative allowed; else None (never 0)."""
    return lp._number(value, -1e18, 1e18)


def _count(value: Any) -> int | None:
    number = lp._number(value, 0, 1e12)
    return int(number) if number is not None and number.is_integer() else None


def _int(value: Any) -> int | None:
    number = lp._number(value, -1e9, 1e9)
    return int(number) if number is not None and number.is_integer() else None


def _date(value: Any) -> str | None:
    """A date from LP Agent's activity times ("2025-07-30 16:03:45.000" in the docs, no time zone): the day only."""
    match = DATE_RE.fullmatch(value.strip()) if isinstance(value, str) and len(value) <= 40 else None
    if not match:
        return None
    try:
        dt.date.fromisoformat(match.group(1))
    except ValueError:
        return None
    return match.group(1)


def _window(value: Any, window: str = BAR_WINDOW) -> float | None:
    """One window of LP Agent's per-window objects ({"ALL": ..., "7D": ...}); a plain number has no window: None."""
    return _signed_number(value.get(window)) if isinstance(value, dict) else None


def strategy_code(value: Any) -> str:
    """LP Agent's strategy label mapped to a fixed code (the label itself is provider text and is never kept)."""
    if value is None or value == "":
        return "none"
    if not isinstance(value, str) or len(value) > 40:
        return "other"
    key = re.sub(r"[\s_\-]", "", value).lower()
    for prefix, shape in (("bidask", "bid_ask"), ("spot", "spot"), ("curve", "curve")):
        if key.startswith(prefix):
            rest = key[len(prefix):]
            return {"": shape, "imbalanced": f"{shape}_imbalanced", "balanced": f"{shape}_balanced"}.get(rest, "other")
    return "other"


# ----------------------------------------------------------------------------- request


def positions_url(pool: str) -> str:
    return f"https://{HOST}{POSITIONS_PATH.format(pool=pool)}?{POSITIONS_QUERY}"


def overview_query(owner: str) -> str:
    return f"owner={owner}&protocol={OVERVIEW_PROTOCOL}"


def overview_url(owner: str) -> str:
    return f"https://{HOST}{OVERVIEW_PATH}?{overview_query(owner)}"


def check_url(url: str) -> str:
    """https only, host api.lpagent.io only, no port other than 443, no credentials, and only the two documented paths with
    their fixed queries: the open positions of one pool, or one wallet's Meteora overview. Returns which one."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise lp.Failure("scheme_not_https")
    if parsed.hostname != HOST or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise lp.Failure("host_not_allowlisted")
    if parsed.params or parsed.fragment:
        raise lp.Failure("path_not_allowlisted")
    match = POSITIONS_PATH_RE.fullmatch(parsed.path)
    if match and parsed.query == POSITIONS_QUERY:
        return "positions"
    owner = parsed.query.removeprefix("owner=").removesuffix(f"&protocol={OVERVIEW_PROTOCOL}")
    if parsed.path == OVERVIEW_PATH and lp.SOLANA_ADDRESS_RE.fullmatch(owner) and parsed.query == overview_query(owner):
        return "overview"
    raise lp.Failure("path_not_allowlisted")


def build_request(url: str, key: str) -> urllib.request.Request:
    check_url(url)
    request = urllib.request.Request(url, method="GET")
    request.headers[lp.KEY_HEADER] = key  # set directly so the header keeps the documented name
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", USER_AGENT)
    return request


def default_opener() -> urllib.request.OpenerDirector:
    """lpagent_pools.py's opener: no environment proxy, no redirects, default TLS verification."""
    return lp.default_opener()


def send_once(request: urllib.request.Request, opener: Any, *, monotonic: Callable[[], float]) -> bytes:
    """One attempt, on lpagent_pools.send_once's bounded pattern with this file's URL check: the body (at most 2 MiB) or
    lp.Failure with a fixed code. Opening, every read and the error close run under one hard deadline of 30 s. An error body
    is never read."""
    check_url(request.full_url)
    if request.get_method() != "GET":
        raise lp.Failure("method_not_allowlisted")
    deadline = monotonic() + lp.TIMEOUT_S

    def remaining() -> float:
        return deadline - monotonic()

    response = None
    try:
        response = lp._bounded_call(lambda: opener.open(request, timeout=lp.TIMEOUT_S), remaining())
        status = int(getattr(response, "status", 200) or 200)
        if 300 <= status < 400:
            raise lp.Failure("redirect_disallowed", status)
        if status != 200:
            raise lp.Failure(lp.HTTP_REASONS.get(status, "server_error" if 500 <= status <= 599 else "http_error"), status)
        chunks, total = [], 0
        while True:
            chunk = lp._bounded_call(lambda: response.read(65536), remaining())
            if not isinstance(chunk, bytes):
                raise lp.Failure("invalid_response")
            if not chunk:
                break
            total += len(chunk)
            if total > lp.MAX_BYTES:
                raise lp.Failure("response_too_large")
            chunks.append(chunk)
        return b"".join(chunks)
    except lp.Failure:
        raise
    except urllib.error.HTTPError as exc:
        try:
            if 300 <= exc.code < 400:
                raise lp.Failure("redirect_disallowed", exc.code) from None
            if exc.code == 429:
                raise lp.Failure("rate_limited", 429, retry_wait=lp._retry_wait(exc)) from None
            raise lp.Failure(lp.HTTP_REASONS.get(exc.code, "server_error" if 500 <= exc.code <= 599 else "http_error"), exc.code) from None
        finally:
            try:
                lp._bounded_call(exc.close, remaining())
            except Exception:  # noqa: BLE001
                pass
    except (TimeoutError, socket.timeout):
        raise lp.Failure("timeout") from None
    except urllib.error.URLError as exc:
        raise lp.Failure("timeout" if isinstance(exc.reason, (TimeoutError, socket.timeout)) else "network_error") from None
    except Exception:  # noqa: BLE001 - never let exception text (which can carry request details) out
        raise lp.Failure("network_error") from None
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            try:
                lp._bounded_call(close, remaining())
            except Exception:  # noqa: BLE001 - cleanup cannot extend the deadline
                pass


class Pace:
    """Every LP Agent attempt of this lane: each starts at least MIN_GAP_S after the previous one ended (the first at the
    given start), at most one retry per call and only after a 429 (lpagent_pools.py's wait), at most MAX_REQUESTS in all.
    Every attempt is written to the request ledger (call, target, attempt, wait, gap, times, status, reason)."""

    def __init__(self, now: Callable[[], float], monotonic: Callable[[], float], sleep: Callable[[float], None], first_wait_s: float) -> None:
        self._now, self._monotonic, self._sleep = now, monotonic, sleep
        self._next = monotonic() + max(0.0, first_wait_s)
        self._last_end: float | None = None
        self.ledger: list[dict[str, Any]] = []

    @property
    def requests(self) -> int:
        return len(self.ledger)

    def call(self, kind: str, target: str, url: str, key: str, opener: Any) -> dict[str, Any]:
        """One call (at most one retry after a 429). Returns {body, reason, http_status, attempts}; never raises."""
        out: dict[str, Any] = {"body": None, "reason": None, "http_status": None, "attempts": 0}
        for attempt in (1, 2):
            if self.requests >= MAX_REQUESTS:
                out.update(reason="request_cap", http_status=None)
                return out
            wait = max(0.0, self._next - self._monotonic())
            if wait > 0:
                self._sleep(wait)
            start = self._monotonic()
            entry = {"call": kind, "target": target, "attempt": attempt, "waited_s": round(wait, 3),
                     "gap_after_previous_s": round(start - self._last_end, 3) if self._last_end is not None else None,
                     "started_at": lp._iso(self._now()), "http_status": None, "reason": None, "duration_s": None}
            self.ledger.append(entry)
            out["attempts"] = attempt
            retry: float | None = None
            try:
                out.update(body=send_once(build_request(url, key), opener, monotonic=self._monotonic), reason=None, http_status=200)
            except lp.Failure as failure:
                out.update(body=None, reason=failure.reason, http_status=failure.http_status)
                retry = failure.retry_wait
            except Exception:  # noqa: BLE001 - defensive: no exception text leaves this method
                out.update(body=None, reason="request_failed", http_status=None)
            end = self._monotonic()
            self._last_end, self._next = end, end + MIN_GAP_S
            entry.update(http_status=out["http_status"], reason=out["reason"], duration_s=round(end - start, 3))
            if out["reason"] is None:
                return out
            if attempt == 1 and out["http_status"] == 429 and retry is not None:
                self._next = max(self._next, end + retry)
                continue
            return out
        return out


# ----------------------------------------------------------------------------- the pool (offline, from the first-wave files)


def choose_pool(run: Path, mint: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """The largest-TVL Meteora DLMM pool of this mint: meteora_pools.json first (TVL at least the dust bar, not blacklisted),
    else lpagent_pools.json (LP Agent's DLMM rows, the same bar, a pool Meteora blacklists skipped). Returns (pool or None,
    how each file was read and what was skipped)."""
    how: dict[str, Any] = {"meteora_pools.json": "missing", "lpagent_pools.json": "not needed", "dust_pools_skipped": 0,
                           "blacklisted_pools_skipped": 0, "tvl_not_read": 0, "min_tvl_usd": MIN_POOL_TVL_USD}
    blacklisted: set[str] = set()
    met = _read_json(run / mp.OUT_FILE)
    if (run / mp.OUT_FILE).exists():
        if not (isinstance(met, dict) and met.get("schema") == mp.SCHEMA and met.get("status") in ("ok", "empty", "unavailable")):
            how["meteora_pools.json"] = "unreadable"
        elif met.get("mint") != mint:
            how["meteora_pools.json"] = "other_mint"
        elif met["status"] == "unavailable":
            how["meteora_pools.json"] = "unavailable"
        else:
            how["meteora_pools.json"] = "read"
            eligible = []
            for p in _list(met.get("pools")):
                p = _dict(p)
                address, tvl = mp._address(p.get("address")), mp._number(p.get("tvl"))
                if address is None:
                    continue
                if p.get("blacklisted") is True:
                    blacklisted.add(address)
                    how["blacklisted_pools_skipped"] += 1
                elif tvl is None:
                    how["tvl_not_read"] += 1
                elif tvl < MIN_POOL_TVL_USD:
                    how["dust_pools_skipped"] += 1
                else:
                    eligible.append({"address": address, "tvl": tvl, "source": "meteora_pools.json", "this_token_side": p.get("this_token_side") if p.get("this_token_side") in ("x", "y") else None,
                                     "bin_step": mp._count(p.get("bin_step")), "other_mint": mp._address(p.get("other_mint"))})
            if eligible:
                return max(eligible, key=lambda p: (p["tvl"], p["address"])), how
    lpa = _read_json(run / lp.OUT_FILE)
    if not (run / lp.OUT_FILE).exists():
        how["lpagent_pools.json"] = "missing"
    elif not (isinstance(lpa, dict) and lpa.get("schema") == lp.SCHEMA and lpa.get("status") in ("ok", "empty", "unavailable")):
        how["lpagent_pools.json"] = "unreadable"
    elif lpa.get("mint") != mint:
        how["lpagent_pools.json"] = "other_mint"
    elif lpa["status"] != "ok":
        how["lpagent_pools.json"] = lpa["status"]
    else:
        how["lpagent_pools.json"] = "read"
        eligible = []
        for p in _list(lpa.get("pools")):
            p = _dict(p)
            address, tvl = mp._address(p.get("pool")), mp._number(p.get("tvl"))
            if address is None or p.get("protocol") != "meteora" or mint not in (p.get("token0"), p.get("token1")):
                continue
            if address in blacklisted:  # already counted from Meteora's rows
                continue
            if tvl is not None and tvl >= MIN_POOL_TVL_USD:
                side = "x" if p.get("token0") == mint else "y"
                eligible.append({"address": address, "tvl": tvl, "source": "lpagent_pools.json", "this_token_side": side,
                                 "bin_step": mp._count(p.get("bin_step")), "other_mint": mp._address(p.get("token1") if side == "x" else p.get("token0"))})
        if eligible:
            return max(eligible, key=lambda p: (p["tvl"], p["address"])), how
    return None, how


def first_wait_s(run: Path, mint: str, now_ts: float) -> tuple[float, str | None]:
    """How long the first call waits: until lpagent_pools.json fetched_at + 1 s + 12.5 s when that is still ahead (the
    first-wave LP Agent call on the same key), never longer than that; 0 without a readable file of this mint."""
    data = _read_json(run / lp.OUT_FILE)
    if not (isinstance(data, dict) and data.get("schema") == lp.SCHEMA and data.get("mint") == mint):
        return 0.0, None
    fetched = mp._parse_time(data.get("fetched_at"))
    if fetched is None:
        return 0.0, None
    limit = FETCHED_AT_SLACK_S + MIN_GAP_S
    return min(limit, max(0.0, fetched + limit - now_ts)), lp._iso(fetched)


# ----------------------------------------------------------------------------- parsing (provider text is untrusted)


def _decode(body: Any) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError, AttributeError):
        return None


def parse_positions(payload: Any, pool: str, key: str | None) -> dict[str, Any]:
    """The positions answer, field names as in the cached docs and LP Agent's position objects: {status, data: {pagination
    {total}, positions: [{owner, position, currentValue, inputValue, pnl {value, percent}, fee, tickLower, tickUpper,
    strategyType, createdAt, status, ...}], activeBin {binId}}}. Loud guards: no position list gives unavailable
    (position_list_missing); positions none of which names a readable owner give unavailable (owner_field_missing), none with
    a readable value now give unavailable (value_field_missing); no open position gives empty (no_open_position)."""
    if not isinstance(payload, dict):
        return {"status": "unavailable", "reason": "invalid_shape"}
    if isinstance(payload.get("status"), str) and payload["status"] != "success":
        return {"status": "unavailable", "reason": "provider_error"}
    data = payload.get("data")
    rows = data.get("positions") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return {"status": "unavailable", "reason": "position_list_missing"}
    pagination = _dict(data.get("pagination"))
    active = _int(_dict(data.get("activeBin")).get("binId"))
    total = _count(pagination.get("totalCount")) if "totalCount" in pagination else _count(pagination.get("total"))  # live 2026-10-26: totalCount
    answer = {"rows_in_answer": len(rows), "total_open": total, "other_pool_rows_dropped": 0, "closed_rows_dropped": 0,
              "unreadable_rows": 0, "owner_not_read": 0, "active_bin": active}
    positions = []
    for row in rows:
        if not isinstance(row, dict):
            answer["unreadable_rows"] += 1
            continue
        if isinstance(row.get("pool"), str) and row["pool"] != pool:
            answer["other_pool_rows_dropped"] += 1
            continue
        if row.get("status") not in (None, "Open"):
            answer["closed_rows_dropped"] += 1
            continue
        owner = lp._address(row.get("owner"), key)
        if owner is None:
            answer["owner_not_read"] += 1
        pnl = _dict(row.get("pnl"))
        lower, upper = _int(row.get("tickLower")), _int(row.get("tickUpper"))
        if lower is not None and upper is not None and lower > upper:
            lower = upper = None
        # fees: the live answers of 2026-10-26 sent "fee": null with collectedFee and unCollectedFee (USD numbers; a text
        # uncollectedFee too): earned = claimed + unclaimed, only when both are readable
        claimed = lp._number(row.get("collectedFee"))
        unclaimed = lp._number(row.get("unCollectedFee")) if "unCollectedFee" in row else lp._number(row.get("uncollectedFee"))
        fee = lp._number(row.get("fee"))
        positions.append({
            "position": lp._address(row.get("position"), key), "owner": owner, "value_now_usd": lp._number(row.get("currentValue")),
            "input_usd": lp._number(row.get("inputValue")), "input_native": lp._number(row.get("inputNative")),
            "pnl_usd": _signed_number(pnl.get("value")), "pnl_pct": _signed_number(pnl.get("percent")), "pnl_native": _signed_number(pnl.get("valueNative")),
            "fees_usd": fee if fee is not None else (claimed + unclaimed if claimed is not None and unclaimed is not None else None),
            "claimed_fees_usd": claimed, "unclaimed_fees_usd": unclaimed,
            "bin_lower": lower, "bin_upper": upper, "in_range": row.get("inRange") if isinstance(row.get("inRange"), bool) else None,
            "strategy": strategy_code(row.get("strategyType")), "created_at": lp._time(row.get("createdAt")),
        })
    if not rows or not positions:
        return {"status": "empty", "reason": "no_open_position", "answer": answer, "positions": []}
    if all(p["owner"] is None for p in positions):
        return {"status": "unavailable", "reason": "owner_field_missing", "answer": answer}
    if all(p["value_now_usd"] is None for p in positions):
        return {"status": "unavailable", "reason": "value_field_missing", "answer": answer}
    return {"status": "ok", "reason": None, "answer": answer, "positions": positions}


def biggest_wallets(positions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The MAX_WALLETS biggest distinct owners by value now in this pool (the sum over their positions on the page with a
    readable value; an emptied position counts nothing), the largest first; owners with no value above 0 are not chosen."""
    value: dict[str, float] = {}
    for p in positions:
        if p["owner"] is not None and p["value_now_usd"] is not None:
            value[p["owner"]] = value.get(p["owner"], 0.0) + p["value_now_usd"]
    ranked = sorted(((v, o) for o, v in value.items() if v > 0), key=lambda t: (-t[0], t[1]))
    return [{"owner": o, "value_now_usd": v} for v, o in ranked[:MAX_WALLETS]]


def parse_overview(payload: Any, owner: str, key: str | None) -> dict[str, Any]:
    """One wallet's overview answer, field names as in the cached docs: {status, data: {owner, protocol, total_lp, win_lp,
    win_rate {ALL, ...}, total_pnl {ALL, ...}, roi, total_inflow, avg_age_hour, opening_lp, first_activity, last_activity,
    updated_at}} (data as one object, or a list holding one). Numbers LP Agent sends as text are read as numbers; anything
    else is null, never 0. Loud guards: the documented "Owner overview not found" error gives no_record; another error status
    provider_error; a record for another wallet owner_mismatch; a record with none of the bar fields record_fields_missing."""
    if not isinstance(payload, dict):
        return {"status": "unavailable", "reason": "invalid_shape"}
    if isinstance(payload.get("status"), str) and payload["status"] != "success":
        return {"status": "unavailable", "reason": "no_record" if payload.get("message") == NOT_FOUND_MESSAGE else "provider_error"}
    data = payload.get("data")
    if isinstance(data, list):
        data = data[0] if len(data) == 1 else None
    if not isinstance(data, dict):
        return {"status": "unavailable", "reason": "record_missing"}
    if "owner" in data and data.get("owner") != owner:
        return {"status": "unavailable", "reason": "owner_mismatch"}
    win_rate = _window(data.get("win_rate"))
    record = {
        "total_lp": _count(data.get("total_lp")), "win_lp": _count(data.get("win_lp")),
        "win_rate_all": win_rate if win_rate is not None and 0.0 <= win_rate <= 1.0 else None,
        "total_pnl_all_usd": _window(data.get("total_pnl")), "total_fee_all_usd": _window(data.get("total_fee")),
        "roi": _signed_number(data.get("roi")), "total_inflow_usd": lp._number(data.get("total_inflow")),
        "avg_age_hour": lp._number(data.get("avg_age_hour")), "opening_lp": _count(data.get("opening_lp")),
        "first_activity": _date(data.get("first_activity")), "last_activity": _date(data.get("last_activity")),
        "updated_at": _date(data.get("updated_at")), "protocol_echo": data.get("protocol") == OVERVIEW_PROTOCOL,
    }
    if record["total_lp"] is None and record["win_rate_all"] is None and record["total_pnl_all_usd"] is None:
        return {"status": "unavailable", "reason": "record_fields_missing"}
    return {"status": "read", "reason": None, **record}


# ----------------------------------------------------------------------------- collect


def _base(mint: str, fetched_at: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "lane": "lp_smart_money", "provider": "LP Agent", "mint": mint, "status": "unavailable", "reason": None,
        "fetched_at": fetched_at, "http_status": None,
        "request": {"method": "GET", "host": HOST, "paths": [f"{POSITIONS_PATH.replace('{pool}', '<POOL>')}?{POSITIONS_QUERY}",
                                                              f"{OVERVIEW_PATH}?owner=<WALLET>&protocol={OVERVIEW_PROTOCOL}"],
                    "auth_header_names": [lp.KEY_HEADER], "max_calls": MAX_CALLS, "max_requests": MAX_REQUESTS, "min_gap_s": MIN_GAP_S,
                    "retry_only_after_429_waiting_at_least_s": lp.RETRY_MIN_WAIT_S, "rate_limit_per_minute": lp.RATE_LIMIT_PER_MINUTE,
                    "first_call_after_lpagent_pools_fetched_at": None, "first_wait_s": 0.0, "calls_sent": 0, "requests_sent": 0, "ledger": []},
        "docs": "provider-docs current/lpagentio/fulldocs.pages/api-reference/pools/get-positions-for-a-specific-pool.md and "
                "positions/get-overview-metrics-for-lp-positions.md",
        "pool_from": {}, "pool": None, "answer": None, "positions": [], "wallets": [],
        "bar": {"min_win_rate": PROVEN_MIN_WIN_RATE, "min_lps": PROVEN_MIN_LPS, "total_pnl_above_usd": PROVEN_MIN_TOTAL_PNL_USD, "window": BAR_WINDOW,
                "decided": "owner decision 2026-10-26 (provisional; applied by --present, never by the collector)"},
        "presentation_only": True, "note": PRESENTATION_NOTE, "cannot_see": CANNOT_SEE,
    }


def collect_lp_smart_money(
    mint: str,
    run: Path,
    key: str | None,
    *,
    key_reason: str | None = None,
    opener: Any | None = None,
    now: Callable[[], float] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """The pool from the saved first-wave files, then at most MAX_CALLS LP Agent calls, paced. Returns the
    lp_smart_money.json result; never raises for provider or transport failures; without a pool or a key it sends nothing."""
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    result = _base(mint, lp._iso(now()))
    pace: Pace | None = None

    def finish(status: str, reason: str | None = None) -> dict[str, Any]:
        result.update(status=status, reason=reason, fetched_at=lp._iso(now()))
        if pace is not None:
            result["request"].update(ledger=pace.ledger, requests_sent=pace.requests, calls_sent=len({(e["call"], e["target"]) for e in pace.ledger}))
        return result

    pool, how = choose_pool(run, mint)
    result.update(pool_from=how, pool=pool)
    if pool is None:
        return finish("empty", "no_dlmm_pool")
    if not key:
        return finish("unavailable", key_reason or lp.NO_KEY_REASON)
    wait, after = first_wait_s(run, mint, now())
    result["request"].update(first_call_after_lpagent_pools_fetched_at=after, first_wait_s=round(wait, 3))
    pace = Pace(now, monotonic, sleep, wait)
    opener = opener or default_opener()
    got = pace.call("positions", pool["address"], positions_url(pool["address"]), key, opener)
    result["http_status"] = got["http_status"]
    if got["reason"] is not None:
        return finish("unavailable", got["reason"])
    payload = _decode(got["body"])
    if payload is None:
        return finish("unavailable", "invalid_json")
    try:
        parsed = parse_positions(payload, pool["address"], key)
    except Exception:  # noqa: BLE001 - a malformed answer the guards did not foresee: a fixed code, the call still counted
        parsed = {"status": "unavailable", "reason": "parse_error"}
    result["answer"] = parsed.get("answer")
    if parsed["status"] != "ok":
        return finish(parsed["status"], parsed["reason"])
    result["positions"] = parsed["positions"]
    stopped: str | None = None
    for wallet in biggest_wallets(parsed["positions"]):
        entry = {**wallet, "status": "not_read", "reason": None}
        if stopped:
            entry["reason"] = f"not_sent_after_{stopped}"
        else:
            got = pace.call("overview", wallet["owner"], overview_url(wallet["owner"]), key, opener)
            entry["http_status"] = got["http_status"]
            if got["reason"] is not None:
                entry.update(status="unavailable", reason="no_record" if got["http_status"] == 404 else got["reason"])
                if got["reason"] in STOP_REASONS:
                    stopped = got["reason"]
            else:
                body = _decode(got["body"])
                try:
                    entry.update(parse_overview(body, wallet["owner"], key) if body is not None else {"status": "unavailable", "reason": "invalid_json"})
                except Exception:  # noqa: BLE001
                    entry.update(status="unavailable", reason="parse_error")
        result["wallets"].append(entry)
    return finish("ok")


def status_line(result: dict[str, Any]) -> str:
    sent = result["request"]["requests_sent"]
    calls = f"{sent} LP Agent request{'s' if sent != 1 else ''}" if sent else "no LP Agent request sent"
    if result["status"] == "ok":
        wallets = result["wallets"]
        read = sum(1 for w in wallets if w.get("status") == "read")
        return (f"ok (main DLMM pool {result['pool']['address']}: {len(result['positions'])} open positions read, {len(wallets)} wallet "
                f"record{'s' if len(wallets) != 1 else ''} asked, {read} read; {calls})")
    if result["status"] == "empty":
        what = (f"no Meteora DLMM pool with ${MIN_POOL_TVL_USD:,.0f}+ TVL in this scan's pool files" if result["reason"] == "no_dlmm_pool"
                else "LP Agent lists no open position in the main DLMM pool")
        return f"empty ({what}; {calls})"
    return f"unavailable ({result['reason']}; {calls})"


# ----------------------------------------------------------------------------- presentation (synthesis, offline)


TITLE = "LP smart money (follow-up lane lp_smart_money; LP Agent's numbers; the main Meteora DLMM pool; provisional bar; presentation only)"
LINE_HEAD = "LP SMART MONEY"
BAR_TEXT = "win ≥ 60% over ≥ 20 LPs, PnL > 0; provisional"
WIN_RATE_NOTE = "its own method; it appears to leave out LPs that ended flat"
BAR_LINE = (f"bar: a proven LPer (provisional) has LP Agent's win rate of 60% or more over 20 or more LPs and a total PnL above $0 in LP Agent's "
            f"lifetime record (window {BAR_WINDOW}); owner decisions of 2026-10-26; LP Agent's win rate is not won LPs over all LPs "
            "(on all 9 wallets recorded on 2026-10-26 it was higher; it appears to leave out LPs that ended flat: inferred, undocumented), and the bar uses "
            "LP Agent's figure by the owner's choice \"LP Agent's figure (Recommended)\", with the strict count \"X of Y LPs won\" printed next to "
            "it; unvalidated, no negative controls; it never changes a FLAG, verdict or NO_ALARM")
KNOWN_CODES = frozenset({
    "no_dlmm_pool", "no_open_position", "invalid_shape", "provider_error", "position_list_missing", "owner_field_missing", "value_field_missing",
    "invalid_json", "parse_error", "request_failed", "request_cap", "no_record", "record_missing", "owner_mismatch", "record_fields_missing",
    "rate_limited", "authentication_failed", "payment_required", "access_denied", "not_found", "bad_request", "service_unavailable",
    "server_error", "http_error", "redirect_disallowed", "timeout", "network_error", "response_too_large", "invalid_response",
    "scheme_not_https", "host_not_allowlisted", "path_not_allowlisted", "method_not_allowlisted", "key_format", "env_file_unreadable",
    lp.NO_KEY_REASON, "key_echo_dropped",
    *(f"not_sent_after_{r}" for r in STOP_REASONS),
})
REASON_TEXT = {
    "no_dlmm_pool": f"no Meteora DLMM pool with ${MIN_POOL_TVL_USD:,.0f}+ TVL in this scan's pool files; no call sent",
    "no_open_position": "LP Agent lists no open position in the main DLMM pool",
    "no_record": "LP Agent has no LP record for this wallet",
    "rate_limited": "rate_limited; the LP Agent key is shared with the trading bot",
    "not_sent_after_rate_limited": "not sent: the shared LP Agent key was rate limited",
    "not_sent_after_authentication_failed": "not sent: LP Agent refused the key",
    "not_sent_after_payment_required": "not sent: LP Agent refused the key",
    "not_sent_after_access_denied": "not sent: LP Agent refused the key",
}
STRATEGY_TEXT = {"spot": "spot", "curve": "curve", "bid_ask": "bid-ask", "none": "no label"}
DEV_TAG = "this token's dev (create-slot trace)"


def _code(value: Any) -> str:
    """A reason code read back from the saved file: printed only when it is one of the fixed codes."""
    return value if isinstance(value, str) and value in KNOWN_CODES else "unrecognized code"


def _reason_text(value: Any) -> str:
    code = _code(value)
    return REASON_TEXT.get(code, code)


def _addr(value: Any) -> str | None:
    return value if isinstance(value, str) and lp.SOLANA_ADDRESS_RE.fullmatch(value) else None


def _short(value: Any) -> str:
    address = _addr(value)
    return f"`{address[:6]}…`" if address else "`unknown`"


def _num(value: Any) -> float | None:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


def _usd(value: float) -> str:
    """$0, "under $0.01", "$0.42" under $1, else meteora_pools' three significant digits ("$1.28M"); the size only (signs
    are added by _signed_usd)."""
    if value == 0:
        return "$0"
    if abs(value) < 0.01:
        return "under $0.01"
    if abs(value) < 1:
        return f"${math.floor(abs(value) * 100) / 100:.2f}"
    return mp.usd_text(abs(value))


def _signed_usd(value: float) -> str:
    return ("+" if value > 0 else "-" if value < 0 else "") + _usd(value)


def _signed_pct(value: float) -> str:
    """A signed percent cut toward zero: 1 decimal from 1% ("+12.3%"), 2 decimals under 1% ("-0.46%", "+0.04%")."""
    size = abs(value)
    text = mp.pct_text(size) if size >= 1 else f"{math.floor(round(size, 9) * 100) / 100:.2f}%"
    return ("+" if value > 0 else "-" if value < 0 else "") + text


def _maybe(value: Any, fmt: Callable[[float], str], missing: str = "not read") -> str:
    number = _num(value)
    return fmt(number) if number is not None else missing


def _age_min(value: Any) -> float | None:
    when = mp._parse_time(value)
    return None if when is None else max(0.0, (time.time() - when) / 60)


def label(wallet: dict[str, Any]) -> tuple[str, str]:
    """(code, text) by the owner's provisional bar on the ALL window: proven / under / not_read. A record not read is never
    'under the bar'; a record with a bar field not read is not labelled."""
    if wallet.get("status") != "read":
        return "not_read", f"record not read ({_reason_text(wallet.get('reason'))})"
    rate, lps, pnl = _num(wallet.get("win_rate_all")), wallet.get("total_lp"), _num(wallet.get("total_pnl_all_usd"))
    lps = lps if isinstance(lps, int) and not isinstance(lps, bool) and lps >= 0 else None
    missing = [name for name, v in (("win rate", rate), ("LP count", lps), ("total PnL", pnl)) if v is None]
    if missing:
        return "not_read", f"record not read ({' and '.join(missing)} not read)"
    # the percent as printed (meteora_pools.pct_text rounds to 9 decimals, then cuts to 1): float noise never moves a rate
    # across the bar, and a rate printed "59.9%" is never labelled proven
    short = [why for ok, why in ((round(rate * 100, 9) >= PROVEN_MIN_WIN_RATE * 100, f"LP Agent's win rate under {PROVEN_MIN_WIN_RATE * 100:g}%"),
                                 (lps >= PROVEN_MIN_LPS, f"fewer than {PROVEN_MIN_LPS} LPs"),
                                 (pnl > PROVEN_MIN_TOTAL_PNL_USD, "total PnL not above $0")) if not ok]
    if not short:
        return "proven", "proven LPer (provisional bar)"
    return "under", f"under the bar ({'; '.join(short)}; provisional)"


def _joined(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _tags(owner: str, dev: list[str], holders: dict[str, Any]) -> list[str]:
    """What this scan's saved files say about an LP wallet: this token's dev (create-slot trace), and a top holder of this
    token at the scan (a holders.json top_holders row: share and rank; dust balances outside those rows are not named)."""
    tags = [DEV_TAG] if owner in dev else []
    if holders.get("state") == "read" and owner in holders["rows"]:
        share, rank = holders["rows"][owner]
        text = qc._pct(share)
        tags.append(f"a top holder of this token at the scan: {text or 'share not read'}" + (f", holder rank #{rank}" if rank else ""))
    return tags


def _range(p: dict[str, Any], active: int | None, side: str | None) -> str:
    lower, upper = p.get("bin_lower"), p.get("bin_upper")
    if not (isinstance(lower, int) and isinstance(upper, int)) or isinstance(lower, bool) or isinstance(upper, bool) or lower > upper:
        return "range not read"
    bins = f"bins {lower} to {upper}"
    if not isinstance(active, int) or isinstance(active, bool):
        return f"{bins}; active bin not read"
    where = "below the active bin" if upper < active else "above the active bin" if lower > active else "in range (holds the active bin)"
    if side in ("x", "y") and where != "in range (holds the active bin)":
        under = (upper < active) == (side == "x")  # bin ids price X in Y: for a Y-side token the direction turns around
        where += f" ({'under' if under else 'over'} this token's price)"
    return f"{where}, {bins}, active {active}"


def _strategy(code: Any) -> str:
    """The saved strategy code as fixed words; LP Agent's own label text is never shown."""
    if not isinstance(code, str):
        return "strategy not read"
    shape, suffix = code, ""
    for end, words in (("_imbalanced", " (imbalanced)"), ("_balanced", " (balanced)")):
        if code.endswith(end):
            shape, suffix = code[: -len(end)], words
            break
    word = STRATEGY_TEXT.get(shape)
    if word is None or (shape == "none" and suffix):
        return "strategy: LP Agent's label not shown (not spot, curve or bid-ask)"
    if shape == "none":
        return "no strategy label from LP Agent"
    return f"strategy {word}{suffix} (LP Agent's label)"


def _age(created: Any, fetched: float | None) -> str:
    when = mp._parse_time(created)
    if when is None or fetched is None or when > fetched + 3600:
        return "age not read"
    return f"age {mp.age_text(fetched - when)}"


def _fees(p: dict[str, Any]) -> str:
    claimed, unclaimed = _num(p.get("claimed_fees_usd")), _num(p.get("unclaimed_fees_usd"))
    split = f" (claimed {_usd(claimed)}, unclaimed {_usd(unclaimed)})" if claimed is not None and unclaimed is not None else ""
    return f"fees earned {_maybe(p.get('fees_usd'), _usd)}" + (split if _num(p.get("fees_usd")) is not None else "")


def _position_line(p: dict[str, Any], active: int | None, side: str | None, fetched: float | None, dev: list[str], holders: dict[str, Any]) -> str:
    owner = _addr(p.get("owner"))
    pnl = _maybe(p.get("pnl_usd"), _signed_usd)
    pct = _maybe(p.get("pnl_pct"), _signed_pct, "")
    parts = [f"value now {_maybe(p.get('value_now_usd'), _usd)}", f"PnL now {pnl}" + (f" ({pct})" if pct and pnl != "not read" else ""),
             _fees(p), _range(p, active, side), _strategy(p.get("strategy")), _age(p.get("created_at"), fetched)]
    tags = _tags(owner, dev, holders) if owner else []
    who = f"{_short(owner)} ({owner})" if owner else "owner not read"
    return f"    {who}: " + "; ".join(parts) + (f"; {'; '.join(tags)}" if tags else "")


def _strict_count(wins: int | None, lps: int | None) -> str:
    """The strict count next to LP Agent's win rate (owner decision 5 of 2026-10-26): "5,041 of 9,513 LPs won (53.0%)"; a count
    not read reads "not read", never 0% (and a share that cannot be formed reads "share not read")."""
    if wins is None and lps is None:
        return "LPs won not read"
    if wins is None:
        return f"LPs won not read (of {lps:,} LPs)"
    if lps is None:
        return f"{wins:,} LPs won (LP count not read)"
    share = f"{wins / lps * 100:.1f}%" if 0 < lps and 0 <= wins <= lps else "share not read"  # a count, not a bar input: plain rounding
    return f"{wins:,} of {lps:,} LPs won ({share})"


def _wallet_line(w: dict[str, Any], dev: list[str], holders: dict[str, Any]) -> str:
    owner = _addr(w.get("owner")) or "unknown"
    code, text = label(w)
    head = f"    {_short(owner)} ({owner}): {_maybe(w.get('value_now_usd'), _usd)} in this pool now"
    tags = _tags(owner, dev, holders)
    if w.get("status") != "read":
        return f"{head}: {text}" + (f"; {'; '.join(tags)}" if tags else "")
    lps, wins, opening = (w.get(k) if isinstance(w.get(k), int) and not isinstance(w.get(k), bool) else None for k in ("total_lp", "win_lp", "opening_lp"))
    rate = _maybe(w.get("win_rate_all"), lambda v: mp.pct_text(v * 100))
    record = [f"LP Agent's win rate {rate} ({WIN_RATE_NOTE}); {_strict_count(wins, lps)}",
              f"total PnL {_maybe(w.get('total_pnl_all_usd'), _signed_usd)}", f"ROI {_maybe(w.get('roi'), lambda v: _signed_pct(v * 100))}",
              f"open LPs {opening:,}" if opening is not None else "open LPs not read",
              f"last activity {w['last_activity']} (LP Agent's date)" if isinstance(w.get("last_activity"), str) and _date(w["last_activity"]) else "last activity not read"]
    return f"{head}; lifetime (window {BAR_WINDOW}): " + ", ".join(record) + f": {text}" + (f"; {'; '.join(tags)}" if tags else "")


def _pool_text(pool: dict[str, Any]) -> str:
    return f"{_short(pool.get('address'))}, TVL {_maybe(pool.get('tvl'), _usd)}"


def _summary_line(result: dict[str, Any], dev: list[str], holders: dict[str, Any]) -> str:
    pool = _dict(result.get("pool"))
    where = f"the main DLMM pool ({_pool_text(pool)})"
    wallets = [w for w in _list(result.get("wallets")) if isinstance(w, dict) and _addr(w.get("owner"))]
    if not wallets:
        return f"{LINE_HEAD}: not read (no open position with value now read in {where}; no LP record asked)"
    labels = [(w, label(w)[0]) for w in wallets]
    proven = [w for w, code in labels if code == "proven"]
    under = [w for w, code in labels if code == "under"]
    not_read = [w for w, code in labels if code == "not_read"]
    n = len(wallets)
    group = "the biggest LP" if n == 1 else f"the {n} biggest LPs"
    if not proven and not under:
        reasons = sorted({_reason_text(w.get("reason")) if w.get("status") != "read" else "a bar field not read" for w in not_read})
        return f"{LINE_HEAD}: not read (the LP records of {group} in {where} were not read: {'; '.join(reasons)})"
    missing = f"; {len(not_read)} record{'s' if len(not_read) != 1 else ''} not read" if not_read else ""
    names = [w["owner"] for w in wallets]
    extra = []
    dev_lps = [o for o in names if o in dev]
    if dev_lps:
        extra.append(f"{_joined([_short(o) for o in dev_lps])} {'is' if len(dev_lps) == 1 else 'are'} this token's dev")
    holding = [o for o in names if holders.get("state") == "read" and o in holders["rows"] and o not in dev_lps]
    if holding:
        extra.append(_joined([f"{_short(o)} is a top holder of this token ({qc._pct(holders['rows'][o][0]) or 'share not read'}"
                              + (f", rank #{holders['rows'][o][1]}" if holders["rows"][o][1] else "") + ")" for o in holding]))
    tail = (f"; {'; '.join(extra)}" if extra else "") + " (LP Agent's numbers; presentation only)."
    if not proven:
        if n == 1:
            return f"{LINE_HEAD}: {group} in {where} is not a proven LPer by the bar ({BAR_TEXT}){tail}"
        if not not_read:
            return f"{LINE_HEAD}: none of {group} in {where} is a proven LPer by the bar ({BAR_TEXT}){tail}"
        who = "the one whose record was read is not" if len(under) == 1 else f"none of the {len(under)} whose records were read is"
        return f"{LINE_HEAD}: of {group} in {where}, {who} a proven LPer by the bar ({BAR_TEXT}){missing}{tail}"
    positions = [p for p in _list(result.get("positions")) if isinstance(p, dict) and p.get("owner") in {w["owner"] for w in proven}]
    value = sum(_num(w.get("value_now_usd")) or 0.0 for w in proven)
    pnl_known = [p for p in positions if _num(p.get("pnl_usd")) is not None]
    pnl = sum(p["pnl_usd"] for p in pnl_known)
    base = [p for p in pnl_known if _num(p.get("input_usd")) is not None and p["input_usd"] > 0]
    pct = f" ({_signed_pct(sum(p['pnl_usd'] for p in base) / sum(p['input_usd'] for p in base) * 100)})" if base and len(base) == len(pnl_known) else ""
    pnl_text = f"PnL now {_signed_usd(pnl)}{pct}" if pnl_known else "PnL now not read"
    if pnl_known and len(pnl_known) < len(positions):
        pnl_text += f" (PnL not read on {len(positions) - len(pnl_known)} of their positions)"
    if n == 1:
        subject = f"{group} in {where} is a proven LPer"
    else:
        subject = f"{len(proven)} of {group} in {where} {'is a proven LPer' if len(proven) == 1 else 'are proven LPers'}"
    return f"{LINE_HEAD}: {subject} ({BAR_TEXT}): {_usd(value)} in the pool now, {pnl_text}{missing}{tail}"


def _valid_saved(data: Any) -> bool:
    return (isinstance(data, dict) and data.get("schema") == SCHEMA and data.get("status") in ("ok", "empty", "unavailable")
            and data.get("presentation_only") is True and _addr(data.get("mint")) is not None)


def _ledger_text(request: dict[str, Any]) -> str:
    ledger = [e for e in _list(request.get("ledger")) if isinstance(e, dict)]
    if not ledger:
        return "no LP Agent call sent"
    parts = []
    for e in ledger:
        what = "positions" if e.get("call") == "positions" else f"record {_short(e.get('target'))}"
        status = e.get("http_status") if isinstance(e.get("http_status"), int) and not isinstance(e.get("http_status"), bool) else _code(e.get("reason"))
        gap = _num(e.get("gap_after_previous_s"))
        parts.append(f"{what} {status}" + (f" ({gap:.1f} s after the previous)" if gap is not None else "") + (" (retry)" if e.get("attempt") == 2 else ""))
    gaps = [g for g in (_num(e.get("gap_after_previous_s")) for e in ledger) if g is not None]
    first = _num(request.get("first_wait_s"))
    return (f"{len(ledger)} LP Agent request{'s' if len(ledger) != 1 else ''}: " + ", ".join(parts)
            + (f"; smallest gap {min(gaps):.1f} s" if gaps else "") + (f"; the first waited {first:.1f} s after the first-wave LP Agent call" if first else ""))


def present(run: Path) -> list[str]:
    """The LP SMART MONEY line (marked) and the block. Reads only saved files (followup/lp_smart_money.json, holders.json,
    followup/create_slot_trace.json): no network, no key. A missing, foreign or malformed file or value reads as not read,
    never as a crash and never as a label."""
    path = run / OUT_DIR / OUT_FILE
    data = _read_json(path)
    if not _valid_saved(data):
        why = f"{OUT_DIR}/{OUT_FILE} " + ("missing" if not path.exists() else "unreadable")
        return [f"{SUMMARY_MARK}{LINE_HEAD}: not read ({why})", f"{TITLE}: not read ({why})"]
    try:
        mint = data["mint"]
        dev, dev_reason = qc.this_token_dev(run, mint)
        holders = qc.holder_index(run, mint)
        pool = _dict(data.get("pool"))
        fetched = mp._parse_time(data.get("fetched_at"))
        age = _age_min(data.get("fetched_at"))
        request = _dict(data.get("request"))
        if data["status"] == "ok" and _addr(pool.get("address")):
            summary = _summary_line(data, dev, holders)
        elif data["status"] == "empty" and data.get("reason") == "no_open_position" and _addr(pool.get("address")):
            summary = f"{LINE_HEAD}: not read (LP Agent lists no open position in the main DLMM pool ({_pool_text(pool)}))"
        else:
            summary = f"{LINE_HEAD}: not read ({_reason_text(data.get('reason'))})"
        lines = [SUMMARY_MARK + summary, TITLE]
        lines.append(f"  LP Agent: {'read' if data['status'] == 'ok' else 'not read (' + _reason_text(data.get('reason')) + ')'}"
                     + (f"; data age {age:.0f} min" if age is not None else "; data age unknown") + f"; {_ledger_text(request)}")
    except Exception:  # noqa: BLE001 - a damaged header is not read, never a crash
        return [f"{SUMMARY_MARK}{LINE_HEAD}: not read (saved values unreadable)", f"{TITLE}: not read (saved values unreadable)", f"  {PRESENTATION_NOTE}"]
    try:
        if _addr(pool.get("address")):
            side = pool.get("this_token_side") if pool.get("this_token_side") in ("x", "y") else None
            source = "Meteora's figure, meteora_pools.json" if pool.get("source") == "meteora_pools.json" else "LP Agent's figure, lpagent_pools.json (Meteora not read or no pool there)"
            lines.append(f"  pool: {pool['address']} (the largest-TVL Meteora DLMM pool of this scan, TVL {_maybe(pool.get('tvl'), _usd)}, {source}"
                         + (f"; this token is its {side.upper()} side" if side else "") + ")")
        how = _dict(data.get("pool_from"))
        skipped = [f"{n} {what}" for n, what in ((how.get("dust_pools_skipped"), f"under ${MIN_POOL_TVL_USD:,.0f} TVL (dust)"),
                                                (how.get("blacklisted_pools_skipped"), "blacklisted by Meteora"), (how.get("tvl_not_read"), "TVL not read"))
                   if isinstance(n, int) and not isinstance(n, bool) and n > 0]
        if skipped:
            lines.append(f"  pools not chosen: {', '.join(skipped)}")
        if data["status"] == "ok":
            answer = _dict(data.get("answer"))
            active = answer.get("active_bin") if isinstance(answer.get("active_bin"), int) and not isinstance(answer.get("active_bin"), bool) else None
            side = pool.get("this_token_side") if pool.get("this_token_side") in ("x", "y") else None
            positions = [p for p in _list(data.get("positions")) if isinstance(p, dict)]
            total = answer.get("total_open") if isinstance(answer.get("total_open"), int) and not isinstance(answer.get("total_open"), bool) else None
            shown = [p for p in positions if _num(p.get("value_now_usd")) != 0]
            emptied = len(positions) - len(shown)
            lines.append(f"  open positions read: {len(positions)} (LP Agent's first page of {PAGE_SIZE}, the largest input first"
                         + (f"; LP Agent counts {total:,} open" if total is not None else "; LP Agent's open count not read") + ")"
                         + (f"; {emptied} emptied (value now $0) not listed" if emptied else ""))
            for p in sorted(shown, key=lambda p: (_num(p.get("value_now_usd")) is None, -(_num(p.get("value_now_usd")) or 0.0))):
                lines.append(_position_line(p, active, side, fetched, dev, holders))
            wallets = [w for w in _list(data.get("wallets")) if isinstance(w, dict)]
            lines.append(f"  lifetime LP records of the {len(wallets)} biggest wallet{'s' if len(wallets) != 1 else ''} by value now (LP Agent, every Meteora pool they LPed, not only this one):"
                         if wallets else "  lifetime LP records: none asked (no wallet with value now above $0 on the page)")
            for w in wallets:
                lines.append(_wallet_line(w, dev, holders))
            lines.append(f"  this token's dev (create-slot trace): {_joined(dev)}" if dev else f"  this token's dev not known ({dev_reason}): LP wallets not matched to the dev")
            if holders.get("state") != "read":
                lines.append(f"  holdings of this token not read ({holders.get('state')})")
            lines.append(f"  {BAR_LINE}")
        elif data["status"] == "empty" and data.get("reason") == "no_open_position":
            lines.append("  LP Agent lists no open position in this pool (not an all-clear; its indexer can lag)")
    except Exception:  # noqa: BLE001 - a damaged entry is not read, never a crash
        lines.append("  not read (unreadable entry)")
    lines += [f"  cannot see: {CANNOT_SEE}", f"  {PRESENTATION_NOTE}"]
    return lines


# ----------------------------------------------------------------------------- command line


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read who LPs the largest-TVL Meteora DLMM pool of this scan on LP Agent (one open-positions call, "
                                                 f"then the lifetime LP records of the {MAX_WALLETS} biggest wallets: at most {MAX_CALLS} calls, "
                                                 f"{MAX_REQUESTS} requests, at least {MIN_GAP_S:g} s apart, on the owner's key shared with the trading bot; "
                                                 "bounded: 2 MiB, 30 s, no redirects, no env proxy) and save "
                                                 f"{OUT_DIR}/{OUT_FILE}; or, with --present RUN_DIR, print the LP SMART MONEY line and block offline. "
                                                 "Presentation only.")
    parser.add_argument("mint", nargs="?")
    parser.add_argument("--out", metavar="RUN_DIR", help="run folder: the pool is read from its meteora_pools.json and lpagent_pools.json")
    parser.add_argument("--env-file", metavar="PATH", help=f"the repository .env ({lp.KEY_NAME} in the environment is used first)")
    parser.add_argument("--present", metavar="RUN_DIR", help="offline: print the line and the block from a saved run folder (no network, no key)")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    if args.present is not None:
        if args.mint or args.out or args.env_file:
            print("error: --present takes only the run folder", file=sys.stderr)
            return 2
        run = Path(args.present)
        if not run.is_dir():
            print("error: --present is not a run folder", file=sys.stderr)
            return 2
        for line in present(run):
            print(line)
        return 0
    if not isinstance(args.mint, str) or not lp.SOLANA_ADDRESS_RE.fullmatch(args.mint):
        print("error: mint is not a valid base58 Solana address", file=sys.stderr)
        return 2
    if not args.out:
        print("error: --out is required", file=sys.stderr)
        return 2
    run = Path(args.out)
    try:
        (run / OUT_DIR).mkdir(parents=True, exist_ok=True)
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    key = None
    try:
        key, reason = lp.load_key(None if os.environ.get(lp.KEY_NAME, "").strip() else lp.find_env_file(args.env_file))
        result = collect_lp_smart_money(args.mint, run, key, key_reason=reason)
    except Exception:  # noqa: BLE001 - never print a traceback (it could carry request details)
        result = _base(args.mint, lp._iso(time.time()))
        result["reason"] = "request_failed"
    text = json.dumps(result, indent=1)
    # backstop: the key itself is never saved. The 8-character guard stays on every provider address (per field); this
    # whole-file check looks for the key, because a vendor key can share a short prefix with this file's own field names
    # (live 2026-10-26: the 8-character check on the whole file matched a fixed field name and dropped a good result)
    if key and (key in text or json.dumps(key)[1:-1] in text):  # the key, also as JSON would escape it
        sent = result["request"]["requests_sent"]
        result = _base(args.mint, result["fetched_at"])
        result.update(reason="key_echo_dropped")
        result["request"]["requests_sent"] = sent
        text = json.dumps(result, indent=1)
    try:
        (run / OUT_DIR / OUT_FILE).write_text(text, encoding="utf-8")
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    print(status_line(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
