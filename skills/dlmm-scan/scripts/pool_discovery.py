#!/usr/bin/env python3
"""Pool discovery for dlmm-scan (DS-DISCOVER-T1): one free, keyless read of Meteora's DLMM pool list, ranked by 24h
fee/TVL under the discovery screen and grouped by token, so the owner can pick ONE token for the full scan.

Owner (2026-11-04 14:06 WIB): "I want to add the pool discovery of high fee/tvl pools into the skill as well".
The discovery screen: a token market cap over $250k, then Yun's 24h fee/TVL bar on the token's best pool.

OWNER-ASK DISCOVERY, NOT A SCAN LANE: run it by hand when the owner asks ("pool discovery", "find pools", "high fee/TVL
pools"); it is never part of a scan wave, never on by default and never an engine input, and it never changes a FLAG,
verdict or threshold. High fee/TVL is not vetting (the owner's MAMESUKE scan of 2026-11-03 found the worst holder picture
of the day): discovery is the free first step, the full scan checks the one pick, and the Helius budget rules stay as
they are.

Request (provider-docs cache current/meteora/fulldocs.pages/api-reference/dlmm/pools/pools.md), exactly one per run:
  GET /pools?page_size=200&sort_by=fee_tvl_ratio_24h:desc&filter_by=is_blacklisted=false && tvl>=2000 && fee_tvl_ratio_24h>=20
on dlmm.datapi.meteora.ag, filter_by URL-encoded (quote_plus). Both numbers are meteora_pools.py's COUNTED_POOL_MIN_TVL_USD
and FEE_TVL_OLD_BAR_PCT, by import. filter_by has no market-cap field, so the market-cap screen runs here, on the non-quote
token's market_cap. The request loop (meteora_pools.fetch and send_once), the bounded transport worker, the opener (https
only, no redirects, no environment proxy), the 2 MiB cap, the hard 30 s wall-clock limit per attempt and the retry waits
are meteora_pools.py's, by import, given this script's own request and URL check (that host, that path and exactly that
query): at most one retry, only after a 429 (its Retry-After within 5 s, else 1.5 s) or a 5xx (after 1.5 s). When
Meteora's total is larger than the rows read, the output says how many were not read.

Screen (the PROVISIONAL block below plus meteora_pools.py's bar, by import): the quote side is the side whose mint is wSOL,
USDC or USDT and the token is the other side (both or neither: left out and counted); a counted pool is not blacklisted
with a TVL of at least $2,000; the token's market cap (Meteora's figure) is at least $250,000 (a market cap that is not
read leaves the token out, counted, never passed); the token's best counted pool meets Yun's 24h fee/TVL bar for the
token's age (bar_for, meets), the age being that of the token's oldest pool in the answer ("at least <age> old"; the
token may be older, so the bar can only be the stricter one). Missing or non-finite numbers are null, never 0; a renamed
load-bearing field is loud (unavailable); symbols, names and launchpads are inert labels (provider_words).

Output: <REPORTS>/discovery/<UTC>/pool_discovery.json and DISCOVERY.md (the printed text); --out DIR overrides; it never
writes in a scan run folder <UTC>-<MINT> (outcomes.py's run-folder names, by import). From <REPORTS> it reads only the
run-folder NAMES (scanned before; the full scans of the last 24 h), never a file inside them. The Meteora links it prints
(METEORA_APP_POOL_URL followed by the pool address) are for the owner to open; this script never requests them, and the
rule test allows that one display-only host in this one file (DISPLAY_ONLY_HOSTS in tests/test_execution_rule.py).

Usage: pool_discovery.py [--reports DIR] [--out DIR] [--top N] [--min-mcap USD]. Exit 0 when the files were saved (also
when Meteora was not read: the reason is printed and saved), 2 for a bad command line or an unwritable folder. Standard
library only; Python >= 3.10.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

if str(Path(__file__).resolve().parent) not in sys.path:  # python3 -I leaves the script's folder off sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import meteora_pools as mp  # noqa: E402  (the bar, the counted-pool TVL, the request loop and bounded transport, and the number parsing, by import)
import outcomes as oc  # noqa: E402  (the scan run-folder names <UTC>-<MINT>, by import)
import provider_words as pw  # noqa: E402  (verdict words in provider text; standard library only, no network)

# ----------------------------------------------------------------------------- PROVISIONAL (unvalidated)
# DS-DISCOVER-T1 (2026-11-04). The discovery screen: token market cap over $250k. The counted-pool TVL
# ($2,000) and Yun's age-based 24h fee/TVL bar (300% under 6 h, 20% from 6 h) are meteora_pools.py's
# (COUNTED_POOL_MIN_TVL_USD, bar_for, meets), by import, never copied. No outcomes are recorded yet: keep these provisional.
MIN_TOKEN_MCAP_USD = 250_000.0      # --min-mcap: the token's market cap (Meteora's figure) must be at least this
FADING_PACE = 0.5                   # last 2 h fee pace under half the 12 h pace reads "(fading)": information only, never a filter
PACE_MIN_POOL_AGE_S = 12 * 3600     # the pace is read only for a pool at least 12 h old (its 12 h window is full)
TOP_DEFAULT = 15                    # --top: tokens printed
# ----------------------------------------------------------------------------- end PROVISIONAL

PAGE_SIZE = 200
FILTER_BY = f"is_blacklisted=false && tvl>={mp.COUNTED_POOL_MIN_TVL_USD:g} && fee_tvl_ratio_24h>={mp.FEE_TVL_OLD_BAR_PCT:g}"
DISCOVERY_QUERY = f"page_size={PAGE_SIZE}&sort_by={mp.SORT_BY}&filter_by={urllib.parse.quote_plus(FILTER_BY)}"
REQUESTS_PER_RUN = 1
MAX_REQUESTS = 2
USER_AGENT = "dlmm-scan-pool-discovery/1.0"
QUOTE_MINTS = {"So11111111111111111111111111111111111111112": "SOL", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "USDC",
               "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB": "USDT"}
WINDOWS = ("1h", "2h", "4h", "12h", "24h")
WINDOWS_PRINTED = ("1h", "4h", "24h")
QTF_MODE = 1                        # collect_fee_mode 1 = OnlyY: fees in token Y only (Meteora's changelog, lb_clmm 0.12.0): QTF only when Y is the quote
INPUT_ONLY_MODE = 0                 # collect_fee_mode 0 = InputOnly, the default; any other value is undocumented: QTF not read
QTF_TEXT = "QTF (fees paid in the quote token only)"
ONLY_Y_TOKEN_TEXT = "fee mode 1: fees paid in the token only (Meteora OnlyY, token on the Y side); not QTF"  # mode 1 with the quote on X
METEORA_APP_POOL_URL = "https://app.meteora.ag/dlmm/"  # display only: printed as <this><address> for the owner to open; never requested
SCAN_DAY_S = 86400
SCANS_PER_DAY = 2                   # SKILL.md "Helius budget (owner 2026-10-28)", rule 3: at most 2 full scans a day
SKILL = Path(__file__).resolve().parents[1]
DEFAULT_REPORTS = SKILL / "reports"
DISCOVERY_DIR = "discovery"
JSON_FILE = "pool_discovery.json"
MD_FILE = "DISCOVERY.md"
SCHEMA = "dlmm-scan-pool-discovery/1"
NAME_CAP = 32
LAUNCHPAD_CAP = 24
NOT_VETTED = ("**Candidates by fee/TVL only, not vetted.** A top fee/TVL token can carry the worst holder picture: the owner's "
              "MAMESUKE scan of 2026-11-03 found about 79% of supply sent to one wallet at launch. Run the full scan on the one you "
              "pick before you LP.")
NOTE = ("owner-ask discovery, never part of a scan; never an engine input; it never changes a FLAG, verdict or threshold; "
        "\"meets the bar\" is not a safety signal; the Helius budget rules of a full scan are unchanged")
CANNOT_SEE = ("one Meteora snapshot (fee/TVL moves minute to minute; a pool can leave the list minutes later); market cap and holders "
              "are Meteora's numbers (GMGN or Dexscreener can differ); DLMM pools only (no DAMM, PumpSwap or Raydium pools); pools "
              "under $2,000 TVL are never listed even when their fee/TVL is high (a MAMESUKE-USDC pool 7WWt... read 354% on "
              "$1.7k TVL, 2026-11-04); fee/TVL is the pool average, not what your bins would earn; the token's age "
              "is its oldest listed DLMM pool's (the token may be older); nothing here checks the holders: that is the full scan")
LIFETIME = "younger than 24 h: its 24h figures cover its life so far"


# ----------------------------------------------------------------------------- request


def check_url(url: str) -> None:
    """https only, host dlmm.datapi.meteora.ag only, port 443, no credentials, the /pools path with exactly the fixed
    discovery query. Raises meteora_pools.Failure with a fixed code."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise mp.Failure("scheme_not_https")
    try:
        port = parsed.port
    except ValueError:
        raise mp.Failure("host_not_allowlisted") from None
    if parsed.hostname != mp.HOST or port not in (None, 443) or parsed.username or parsed.password:
        raise mp.Failure("host_not_allowlisted")
    if parsed.path != mp.POOLS_PATH or parsed.query != DISCOVERY_QUERY or parsed.params or parsed.fragment:
        raise mp.Failure("path_not_allowlisted")


def build_request() -> urllib.request.Request:
    url = f"https://{mp.HOST}{mp.POOLS_PATH}?{DISCOVERY_QUERY}"
    check_url(url)
    request = urllib.request.Request(url, method="GET")
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", USER_AGENT)
    return request


# ----------------------------------------------------------------------------- parsing (provider text is untrusted)


def _sides(row: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]] | None:
    x, y = mp._dict(row.get("token_x")), mp._dict(row.get("token_y"))
    return (x, y) if mp._address(x.get("address")) and mp._address(y.get("address")) else None


def _token_and_quote(row: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """(the token side, the quote side) when exactly one side's mint is wSOL, USDC or USDT; else None."""
    sides = _sides(row)
    if sides is None:
        return None
    x, y = sides
    if (x["address"] in QUOTE_MINTS) == (y["address"] in QUOTE_MINTS):
        return None
    return (x, y) if y["address"] in QUOTE_MINTS else (y, x)


def _mcap(value: Any) -> float | None:
    """A market cap in USD; 0 or less is not read (a token with a pool holding TVL has a price)."""
    number = mp._number(value)
    return number if number is not None and number > 0 else None


def _name(value: Any, cap: int) -> str | None:
    return pw.label(value, mp.LABEL_RE, cap)


def renamed_field(rows: list[dict[str, Any]], now_ts: float) -> str | None:
    """The reason code of a load-bearing field that no row carries (a renamed field: unavailable, never ok), or None. The
    market cap is looked for on the token side of the rows that have one."""
    paired = [pair for pair in (_token_and_quote(r) for r in rows) if pair is not None]
    checks = (
        ("token_field_missing", any(_sides(r) is not None for r in rows)),
        ("tvl_field_missing", any(mp._number(r.get("tvl")) is not None for r in rows)),
        ("fee_tvl_field_missing", any(mp._number(mp._dict(r.get("fee_tvl_ratio")).get("24h")) is not None for r in rows)),
        ("market_cap_field_missing", not paired or any(_mcap(token.get("market_cap")) is not None for token, _ in paired)),
        ("created_at_field_missing", any(mp.created_at_iso(r.get("created_at"), now_ts)[0] is not None for r in rows)),
        ("blacklisted_field_missing", any(isinstance(r.get("is_blacklisted"), bool) for r in rows)),
    )
    return next((reason for reason, readable in checks if not readable), None)


POOL_REASONS = ("unreadable", "not_one_quote_side", "blacklisted", "tvl_not_read", "under_tvl", "fee_tvl_not_read", "under_fee_tvl_filter")


def parse_answer(payload: Any, now_ts: float) -> dict[str, Any]:
    """The pools answer, field names as in the cached docs and the live answer of 2026-11-04: {total, pages, current_page,
    page_size, data: [{address, token_x {address, symbol, name, holders, market_cap}, token_y {...}, pool_config {bin_step,
    base_fee_pct, collect_fee_mode}, tvl, volume, fee_tvl_ratio (each {30m, 1h, 2h, 4h, 12h, 24h}), created_at (ms),
    is_blacklisted, launchpad}]}. Returns {status, reason, answer, left_out, pools, token_rows}: pools are the counted rows
    (one SOL, USDC or USDT side; not blacklisted; TVL at least $2,000; 24h fee/TVL at least the filter's 20%); token_rows
    holds, per token mint, the creation times of every row of that token (for its age)."""
    if not isinstance(payload, dict):
        return {"status": "unavailable", "reason": "invalid_shape"}
    rows = payload.get("data")
    if not isinstance(rows, list):
        return {"status": "unavailable", "reason": "pool_list_missing"}
    total = mp._count(payload.get("total"))
    answer = {"total": total, "pages": mp._count(payload.get("pages")), "page_size": mp._count(payload.get("page_size")), "rows_in_answer": len(rows),
              "not_read": max(total - len(rows), 0) if total is not None else None}
    left_out = {reason: 0 for reason in POOL_REASONS}
    if not rows:
        return {"status": "empty", "reason": "no_pool_met_the_filter", "answer": answer, "left_out": left_out, "pools": [], "token_rows": {}}
    renamed = renamed_field([r for r in rows if isinstance(r, dict)], now_ts)
    if renamed is not None:
        return {"status": "unavailable", "reason": renamed, "answer": answer}
    pools: list[dict[str, Any]] = []
    token_rows: dict[str, list[float]] = {}
    for row in rows:
        address = mp._address(row.get("address")) if isinstance(row, dict) else None
        if address is None or _sides(row) is None:
            left_out["unreadable"] += 1
            continue
        pair = _token_and_quote(row)
        if pair is None:
            left_out["not_one_quote_side"] += 1
            continue
        token, quote = pair
        quote_side = "y" if quote["address"] == mp._dict(row.get("token_y")).get("address") else "x"
        created_ms, created = mp.created_at_iso(row.get("created_at"), now_ts)
        times = token_rows.setdefault(token["address"], [])
        if created_ms is not None:
            times.append(created_ms / 1000)
        config, ratio = mp._dict(row.get("pool_config")), mp._dict(row.get("fee_tvl_ratio"))
        bin_step, mode = mp._count(config.get("bin_step")), mp._count(config.get("collect_fee_mode"))
        pool = {
            "address": address, "mint": token["address"], "symbol": mp._label(token.get("symbol")), "name": _name(token.get("name"), NAME_CAP),
            "quote": QUOTE_MINTS[quote["address"]], "market_cap_usd": _mcap(token.get("market_cap")), "holders": mp._count(token.get("holders")),
            "launchpad": _name(row.get("launchpad"), LAUNCHPAD_CAP), "bin_step": bin_step if bin_step and bin_step <= 10000 else None,
            "base_fee_pct": mp._number(config.get("base_fee_pct"), 0.0, 100.0), "collect_fee_mode": mode,
            "quote_side": quote_side, "qtf": (quote_side == "y") if mode == QTF_MODE else False if mode == INPUT_ONLY_MODE else None,
            "tvl": mp._number(row.get("tvl")),
            "volume_24h": mp._number(mp._dict(row.get("volume")).get("24h")), "fee_tvl_ratio": {w: mp._number(ratio.get(w)) for w in WINDOWS},
            "created_at_ms": created_ms, "created_at": created,
            "blacklisted": row.get("is_blacklisted") if isinstance(row.get("is_blacklisted"), bool) else None,
        }
        fee24 = pool["fee_tvl_ratio"]["24h"]
        if pool["blacklisted"] is True:
            left_out["blacklisted"] += 1
        elif pool["tvl"] is None:
            left_out["tvl_not_read"] += 1
        elif pool["tvl"] < mp.COUNTED_POOL_MIN_TVL_USD:
            left_out["under_tvl"] += 1
        elif fee24 is None:
            left_out["fee_tvl_not_read"] += 1
        elif not mp.meets(fee24, mp.FEE_TVL_OLD_BAR_PCT):
            left_out["under_fee_tvl_filter"] += 1
        else:
            pools.append(pool)
    return {"status": "ok", "reason": None, "answer": answer, "left_out": left_out, "pools": pools, "token_rows": token_rows}


# ----------------------------------------------------------------------------- the screen (offline)


def fee_pace(pool: dict[str, Any], now_ts: float) -> tuple[float | None, str]:
    """(the last 2 h fee pace as a share of the 12 h pace: (fee/TVL 2h / 2) / (fee/TVL 12h / 12), why it is not read). Only
    for a pool at least 12 h old with both windows read; information only, never a filter."""
    if pool["created_at_ms"] is None:
        return None, "pool age not read"
    if now_ts - pool["created_at_ms"] / 1000 < PACE_MIN_POOL_AGE_S:
        return None, "pool younger than 12 h"
    two, twelve = pool["fee_tvl_ratio"]["2h"], pool["fee_tvl_ratio"]["12h"]
    if two is None or twelve is None:
        return None, "2 h or 12 h fee/TVL not read"
    if twelve <= 0:
        return None, "no fees in 12 h"
    return (two / 2) / (twelve / 12), ""


def _pool_out(pool: dict[str, Any], bar: float, now_ts: float) -> dict[str, Any]:
    pace, why = fee_pace(pool, now_ts)
    keep = ("address", "bin_step", "base_fee_pct", "collect_fee_mode", "quote_side", "qtf", "tvl", "volume_24h", "fee_tvl_ratio", "created_at")
    out = {k: pool[k] for k in keep}
    out.update(pair=f"{pool['symbol'] or '?'}-{pool['quote']}", link=f"{METEORA_APP_POOL_URL}{pool['address']}",
               fee_pace_2h_vs_12h=pace, fee_pace_not_read=why or None, fading=pace is not None and round(pace, 9) < FADING_PACE,
               meets_bar=mp.meets(pool["fee_tvl_ratio"]["24h"], bar))
    return out


def _first(pools: list[dict[str, Any]], key: str) -> Any:
    """The first readable value of `key` over the token's pools, best 24h fee/TVL first."""
    return next((p[key] for p in pools if p[key] is not None), None)


def screen(parsed: dict[str, Any], now_ts: float, min_mcap: float) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """(tokens that passed the screen, ranked by their best counted pool's 24h fee/TVL; token-level left-out counts). A
    token's market cap is read from its largest-TVL counted pool with a readable figure; not read leaves it out. Its age is
    that of its oldest pool in the answer; its bar is meteora_pools.bar_for(age) and its best pool must meet it."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for pool in parsed["pools"]:
        groups.setdefault(pool["mint"], []).append(pool)
    left = {"market_cap_under": [0, 0], "market_cap_not_read": [0, 0], "below_bar": [0, 0]}  # [tokens, pools]
    tokens = []
    for mint, pools in groups.items():
        pools = sorted(pools, key=lambda p: -p["fee_tvl_ratio"]["24h"])  # stable: Meteora's order on ties
        by_tvl = sorted(pools, key=lambda p: -p["tvl"])
        source = next((p for p in by_tvl if p["market_cap_usd"] is not None), None)
        if source is None or source["market_cap_usd"] < min_mcap:
            reason = "market_cap_not_read" if source is None else "market_cap_under"
            left[reason][0] += 1
            left[reason][1] += len(pools)
            continue
        times = parsed["token_rows"].get(mint) or []
        oldest = min(times) if times else None
        age = max(0.0, now_ts - oldest) if oldest is not None else None
        bar = mp.bar_for(age)
        best = pools[0]
        if not mp.meets(best["fee_tvl_ratio"]["24h"], bar):
            left["below_bar"][0] += 1
            left["below_bar"][1] += len(pools)
            continue
        tokens.append({
            "mint": mint, "symbol": _first(pools, "symbol"), "name": _first(pools, "name"), "market_cap_usd": source["market_cap_usd"],
            "market_cap_from_pool": source["address"], "holders": source["holders"] if source["holders"] is not None else _first(pools, "holders"),
            "launchpad": _first(pools, "launchpad"), "age_s_at_least": age, "oldest_pool_created_at": mp._iso(oldest) if oldest is not None else None,
            "bar_pct": bar, "best_pool": _pool_out(best, bar, now_ts), "other_pools": [_pool_out(p, bar, now_ts) for p in pools[1:]],
        })
    tokens.sort(key=lambda t: -t["best_pool"]["fee_tvl_ratio"]["24h"])  # stable: Meteora's order on ties
    for rank, token in enumerate(tokens, 1):
        token["rank"] = rank
    return tokens, {k: {"tokens": v[0], "pools": v[1]} for k, v in left.items()}


# ----------------------------------------------------------------------------- saved scans (names only)


def saved_scans(reports: Path) -> list[tuple[float, str, str]] | None:
    """(scan time, mint, folder name) for every scan run folder <UTC>-<MINT> of the reports folder, by outcomes.py's
    run-folder rule (the discovery/ folder and any other name are ignored); None when the folder cannot be listed."""
    try:
        return [(ts, mint, path.name) for path, ts, mint in oc.run_folders(reports)] if reports.is_dir() else None
    except OSError:
        return None


def in_run_folder(path: Path) -> bool:
    """True when the path is a scan run folder <UTC>-<MINT> or lies inside one: discovery never writes there."""
    return any(oc.parse_run_name(part) is not None for part in path.resolve().parts)


# ----------------------------------------------------------------------------- collect


def _base(fetched_at: str, min_mcap: float, top: int) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "script": "pool_discovery.py", "status": "unavailable", "reason": None, "fetched_at": fetched_at, "http_status": None,
        "request": {"method": "GET", "host": mp.HOST, "path": f"{mp.POOLS_PATH}?{DISCOVERY_QUERY}", "filter_by": FILTER_BY, "keys": "none",
                    "requests_per_run": REQUESTS_PER_RUN, "max_requests": MAX_REQUESTS, "requests_sent": 0},
        "docs": "provider-docs current/meteora/fulldocs.pages/api-reference/dlmm/pools/pools.md (GET /pools; sort_by, filter_by; fee_tvl_ratio in percent)",
        "answer": None,
        "filters": {"min_token_mcap_usd": min_mcap, "counted_pool_min_tvl_usd": mp.COUNTED_POOL_MIN_TVL_USD, "fee_tvl_young_bar_pct": mp.FEE_TVL_YOUNG_BAR_PCT,
                    "fee_tvl_old_bar_pct": mp.FEE_TVL_OLD_BAR_PCT, "young_token_max_age_s": mp.YOUNG_TOKEN_MAX_AGE_S, "quote_mints": QUOTE_MINTS,
                    "token_age_from": "the token's oldest pool in the answer (the token may be older)", "fading_pace": FADING_PACE, "top": top},
        "left_out": None, "tokens": [], "full_scans_last_24h": None, "note": NOTE, "cannot_see": CANNOT_SEE,
    }


def discover(*, opener: Any | None = None, now: Callable[[], float] | None = None, monotonic: Callable[[], float] | None = None,
             sleep: Callable[[float], None] | None = None, reports: Path = DEFAULT_REPORTS, min_mcap: float = MIN_TOKEN_MCAP_USD,
             top: int = TOP_DEFAULT) -> dict[str, Any]:
    """The one request (at most one retry), the screen and the saved-scan names. Returns the pool_discovery.json result;
    never raises for provider or transport failures."""
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    result = _base(mp._iso(now()), min_mcap, top)
    got = mp.fetch(None, opener or mp.default_opener(), monotonic=monotonic, sleep=sleep, build=build_request, url_check=check_url)
    result["request"]["requests_sent"] = got["attempts"]
    result["http_status"] = got["http_status"]
    fetched = now()
    result["fetched_at"] = mp._iso(fetched)
    scans = saved_scans(reports)
    result["full_scans_last_24h"] = None if scans is None else sum(1 for ts, _, _ in scans if ts > fetched - SCAN_DAY_S)
    if got["reason"] is not None:
        result["reason"] = got["reason"]
        return result
    payload = mp._decode(got["body"])
    if payload is None:
        result["reason"] = "invalid_json"
        return result
    try:
        parsed = parse_answer(payload, fetched)
        result.update(status=parsed["status"], reason=parsed["reason"], answer=parsed.get("answer"), left_out={"pools": parsed.get("left_out")})
        if parsed["status"] != "ok":
            return result
        tokens, token_left = screen(parsed, fetched, min_mcap)
    except Exception:  # noqa: BLE001 - a malformed answer the guards did not foresee: a fixed code, the call still counted
        result.update(status="unavailable", reason="parse_error", left_out=None, tokens=[])
        return result
    newest: dict[str, tuple[float, str]] = {}
    for ts, mint, name in scans or []:
        if mint not in newest or ts > newest[mint][0]:
            newest[mint] = (ts, name)
    for token in tokens:
        seen = newest.get(token["mint"])
        token["scanned_before"] = {"run": seen[1], "scan_time_utc": mp._iso(seen[0])} if seen else None
        token["shown"] = token["rank"] <= top
    result["left_out"]["tokens"] = token_left
    result["tokens"] = tokens
    return result


# ----------------------------------------------------------------------------- presentation


def _pct(value: Any) -> str:
    return mp._maybe(value, mp.pct_text)


def _usd(value: Any) -> str:
    return mp._maybe(value, mp.usd_text)


def _config(p: dict[str, Any]) -> str:
    only_y_token = p["collect_fee_mode"] == QTF_MODE and p["quote_side"] == "x"  # OnlyY with the token on Y: fees in the token, not QTF
    qtf = QTF_TEXT if p["qtf"] is True else ONLY_Y_TOKEN_TEXT if only_y_token else "not QTF" if p["qtf"] is False else (
        "fee mode not read" if p["collect_fee_mode"] is None else f"fee mode {p['collect_fee_mode']} (undocumented; QTF not read)")
    parts = [f"bin step {p['bin_step']}" if p["bin_step"] else "bin step not read",
             f"base fee {p['base_fee_pct']:g}%" if p["base_fee_pct"] is not None else "base fee not read", qtf]
    return ", ".join(parts)


def _age(p: dict[str, Any], now_ts: float) -> str:
    created = mp._parse_time(p["created_at"]) if p["created_at"] else None
    if created is None:
        return "pool age not read"
    young = f" ({LIFETIME})" if now_ts - created < 86400 else ""
    return f"pool age {mp.age_text(now_ts - created)}{young}"


def _verdict(p: dict[str, Any], bar: float) -> str:
    return "meets the bar (not a safety signal)" if p["meets_bar"] else f"below the bar ({mp.bar_text(bar)})"


def _pace(p: dict[str, Any]) -> str:
    if p["fee_pace_2h_vs_12h"] is None:
        return f"fee pace, last 2 h vs 12 h: not read ({p['fee_pace_not_read']})"
    shown = math.floor(round(p["fee_pace_2h_vs_12h"], 9) * 100) / 100  # cut toward zero: 0.499 never prints as 0.50
    return f"fee pace, last 2 h vs 12 h: {shown:.2f}×" + (" (fading)" if p["fading"] else "")


def _when(iso: str) -> str:
    ts = mp._parse_time(iso)
    return f"{oc.utc_text(ts)} ({oc.wib_text(ts)})"


def token_lines(t: dict[str, Any], now_ts: float) -> list[str]:
    symbol = t["symbol"] or "(no symbol)"
    title = f"{symbol} ({t['name']})" if t["name"] and t["name"] != t["symbol"] else symbol
    age = (f"at least {mp.age_text(t['age_s_at_least'])} old (oldest listed DLMM pool; the token may be older)" if t["age_s_at_least"] is not None
           else "age not read (no readable pool time): treated as 6 h or older")
    young = "younger than 6 h" if t["age_s_at_least"] is not None and t["age_s_at_least"] < mp.YOUNG_TOKEN_MAX_AGE_S else "6 h or older"
    holders = f"Meteora holders {t['holders']:,}" if t["holders"] is not None else "Meteora holders not read"
    b = t["best_pool"]
    lines = [f"## {t['rank']}. {title}", "",
             f"- mint `{t['mint']}`",
             f"- market cap {_usd(t['market_cap_usd'])} (Meteora); {holders}; launchpad {t['launchpad'] or 'not listed'}",
             f"- {age}; Yun's bar {mp.bar_text(t['bar_pct'])} ({young})",
             f"- best pool: {b['pair']} `{b['address']}` {b['link']}",
             f"  - {_config(b)}; TVL {_usd(b['tvl'])}; 24h volume {_usd(b['volume_24h'])}",
             "  - fee/TVL " + ", ".join(f"{w} {_pct(b['fee_tvl_ratio'][w])}" for w in WINDOWS_PRINTED) + f"; {_age(b, now_ts)}",
             f"  - {_pace(b)}",
             f"  - 24h fee/TVL {_pct(b['fee_tvl_ratio']['24h'])}: {_verdict(b, t['bar_pct'])}"]
    if t["other_pools"]:
        lines.append(f"- other listed pools of this token ({len(t['other_pools'])}):")
        for p in t["other_pools"]:
            lines.append(f"  - {p['pair']} `{p['address']}` ({_config(p)}): TVL {_usd(p['tvl'])}; 24h fee/TVL {_pct(p['fee_tvl_ratio']['24h'])}; "
                         f"{_age(p, now_ts)}; {_verdict(p, t['bar_pct'])}; {p['link']}")
    else:
        lines.append("- other listed pools of this token: none")
    seen = t.get("scanned_before")
    lines.append(f"- scanned before: {_when(seen['scan_time_utc'])}; reuse that run unless you want a fresh read" if seen else "- not scanned yet")
    return lines + [""]


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'s' if n != 1 else ''}"


def render(result: dict[str, Any], saved_to: str) -> list[str]:
    """The printed text (and DISCOVERY.md): a header that says these are candidates, not vetted; the ranked tokens; the
    counts; the full scans of the last 24 h; and, last, the Next line."""
    now_ts = mp._parse_time(result["fetched_at"])
    filters = result["filters"]
    sent = result["request"]["requests_sent"]
    lines = ["# Pool discovery: Meteora DLMM pools ranked by 24h fee/TVL (owner asks; not a scan)", "",
             f"- read {_when(result['fetched_at'])}; {_plural(sent, 'Meteora DLMM datapi request')}, free, no key",
             f"- {NOT_VETTED}",
             f"- screen (provisional): token market cap at least {mp.usd_text(filters['min_token_mcap_usd']) if filters['min_token_mcap_usd'] >= 1 else '$0'} "
             f"(Meteora's figure); pool TVL at least ${mp.COUNTED_POOL_MIN_TVL_USD:,.0f} and not blacklisted; one side SOL, USDC or USDT; the token's best "
             f"pool at or above Yun's 24h fee/TVL bar: {mp.bar_text(mp.FEE_TVL_YOUNG_BAR_PCT)} for a token younger than 6 h, "
             f"{mp.bar_text(mp.FEE_TVL_OLD_BAR_PCT)} from 6 h (token age = its oldest listed DLMM pool)", ""]
    shown = [t for t in result["tokens"] if t.get("shown")]
    if result["status"] == "unavailable":
        lines += [f"Meteora DLMM datapi: not read ({result['reason']}); no list this time.", ""]
    elif result["status"] == "empty":
        lines += ["Meteora lists no pool that meets the filter right now.", ""]
    elif not shown:
        lines += ["No token passed the screen right now (the counts below say why).", ""]
    for token in shown:
        lines += token_lines(token, now_ts)
    lines += ["## Counts", ""]
    answer = result.get("answer") or {}
    if answer:
        total, read = answer.get("total"), answer.get("rows_in_answer")
        if total is None:
            lines.append(f"- {_plural(read, 'pool')} read; Meteora's total not read")
        elif answer.get("not_read"):
            lines.append(f"- Meteora reports {total} pools for this filter; the first {read} by 24h fee/TVL were read, {answer['not_read']} not read")
        else:
            lines.append(f"- Meteora reports {total} pools for this filter; {read} read (all)")
    left = result.get("left_out") or {}
    tok, pools = left.get("tokens"), left.get("pools")
    if tok:
        lines.append(f"- left out, tokens: market cap under {mp.usd_text(filters['min_token_mcap_usd']) if filters['min_token_mcap_usd'] >= 1 else '$0'}: "
                     f"{tok['market_cap_under']['tokens']} ({_plural(tok['market_cap_under']['pools'], 'pool')}); "
                     f"market cap not read: {tok['market_cap_not_read']['tokens']} ({_plural(tok['market_cap_not_read']['pools'], 'pool')}); "
                     f"below Yun's bar: {tok['below_bar']['tokens']} ({_plural(tok['below_bar']['pools'], 'pool')})")
    if pools:
        lines.append(f"- left out, pools: not exactly one SOL, USDC or USDT side: {pools['not_one_quote_side']}; "
                     f"under ${mp.COUNTED_POOL_MIN_TVL_USD:,.0f} TVL: {pools['under_tvl']}; blacklisted: {pools['blacklisted']}; "
                     f"24h fee/TVL under {mp.bar_text(mp.FEE_TVL_OLD_BAR_PCT)}: {pools['under_fee_tvl_filter']}; 24h fee/TVL not read: {pools['fee_tvl_not_read']}; "
                     f"TVL not read: {pools['tvl_not_read']}; unreadable: {pools['unreadable']}")
        outside = pools["under_tvl"] + pools["blacklisted"] + pools["under_fee_tvl_filter"]
        lines.append("- Meteora's filter: every pool read matched it" if not outside else
                     f"- Meteora's filter: {_plural(outside, 'pool')} did not match the requested filter and were left out (Meteora may have changed filter_by)")
    if result["status"] == "ok":
        lines.append(f"- shown: {len(shown)} of {_plural(len(result['tokens']), 'token')} that passed the screen (--top {filters['top']})")
    scans = result.get("full_scans_last_24h")
    rule = f"at most {SCANS_PER_DAY} a day; ask before a third"
    lines.append(f"- full scans in the last 24 h: {scans} ({rule})" if scans is not None else
                 f"- full scans in the last 24 h: not read (no reports folder; {rule})")
    lines += [f"- cannot see: {CANNOT_SEE}", f"- note: {NOTE}", f"- saved: {saved_to}"]
    removed = pw.count(lines)
    if removed:
        lines.append(f"- {pw.removed_line(removed)}")
    lines += ["", "Next: say `dlmm scan <mint>` for the one you pick." if result["status"] == "ok" and shown else
              "Next: run the same command again later; or say `dlmm scan <mint>` for a token you already have."]
    return lines


# ----------------------------------------------------------------------------- CLI


def _display(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def main(argv: list[str] | None = None, *, opener: Any | None = None, now: Callable[[], float] | None = None,
         monotonic: Callable[[], float] | None = None, sleep: Callable[[float], None] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Owner-ask pool discovery, never part of a scan: one free, keyless Meteora DLMM datapi read (bounded: "
                                                 "2 MiB, 30 s, no redirects, no env proxy, at most one retry after a 429 or a 5xx) of the pools ranked by "
                                                 "24h fee/TVL, screened by Yun's rule and grouped by token; saves pool_discovery.json and DISCOVERY.md.")
    parser.add_argument("--reports", metavar="DIR", help="the reports folder whose scan run-folder NAMES are read (default: this skill's reports folder)")
    parser.add_argument("--out", metavar="DIR", help="folder to save into (default: <reports>/discovery/<UTC>); never a scan run folder")
    parser.add_argument("--top", type=int, default=TOP_DEFAULT, help=f"tokens printed (default {TOP_DEFAULT}, 1 to {PAGE_SIZE})")
    parser.add_argument("--min-mcap", type=float, default=MIN_TOKEN_MCAP_USD, help=f"token market cap at least this many USD (default {MIN_TOKEN_MCAP_USD:,.0f})")
    args = parser.parse_args(argv)
    now = now or time.time
    if not 1 <= args.top <= PAGE_SIZE:
        print(f"error: --top must be 1 to {PAGE_SIZE}", file=sys.stderr)
        return 2
    if not (math.isfinite(args.min_mcap) and args.min_mcap >= 0):
        print("error: --min-mcap must be a number of USD, 0 or more", file=sys.stderr)
        return 2
    reports = Path(args.reports) if args.reports else DEFAULT_REPORTS
    out = Path(args.out) if args.out else reports / DISCOVERY_DIR / dt.datetime.fromtimestamp(now(), dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if in_run_folder(out):
        print("error: --out is a scan run folder <UTC>-<MINT> or inside one; discovery never writes there", file=sys.stderr)
        return 2
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    try:
        result = discover(opener=opener, now=now, monotonic=monotonic, sleep=sleep, reports=reports, min_mcap=args.min_mcap, top=args.top)
    except Exception:  # noqa: BLE001 - never print a traceback
        result = _base(mp._iso(now()), args.min_mcap, args.top)
        result["reason"] = "request_failed"
    lines = render(result, f"`{_display(out / JSON_FILE)}` and `{_display(out / MD_FILE)}`")
    text = "\n".join(lines) + "\n"
    try:
        (out / JSON_FILE).write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
        (out / MD_FILE).write_text(text, encoding="utf-8")
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
