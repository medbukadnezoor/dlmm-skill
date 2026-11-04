#!/usr/bin/env python3
"""Copy-trade cascade watchlist: check each listed trader once on Fomo API's trader search (HS-WATCHLIST-T1).

OWNER-ASK MAINTENANCE ONLY. Run it only when the owner asks for a refresh of references/fomo_cascade_watchlist.json. It is
never part of a scan wave, never on by default and never an engine input: the watchlist is presentation data. Fomo API
(api.fomoapi.io) is an independent, unofficial developer API, not affiliated with fomo.family.

Request (provider-docs cache, fomoapi.md "Search"), once per listed name:
  GET /v2/search?q=<handle>&type=traders&limit=5
Host api.fomoapi.io only, https only, path /v2/search with exactly that query only (checked before every send). The key,
the bounded transport and the inert labels are fomoapi.py's, by import: its single-variable key loader (the one name in
fomoapi.KEY_NAME, nothing else of the .env), its send_once (the key only in the Authorization header as a Bearer token,
no redirects, no environment proxy, 2 MiB and a hard 30 s wall-clock limit per attempt, an error body never read), its
inert labels with the key-echo guard, and its address and count checks.

Caps: at most 20 names and 25 calls a run (one call per name plus at most 5 retries, each only after a 429 whose
Retry-After ends within 5 s, at most one per name); one request start every 4 s at most (15 a minute; the free key allows
20); 250 credits a call (5,000 for 20 names, at most 6,250). The run stops at the first 402 (credits_exhausted), at an
answer whose shape is not the documented one (shape_mismatch: no result list, a result without `type` or with a type
other than trader or token, or a trader result without a handle, `userId` or wallet field; or invalid JSON) and after
a call whose x-credits-cost is above 250; names not sent then are failed (not_sent_run_stopped). It prints the plan and
the credit estimate first; --dry-run stops there: no key read, no request, no file written.

Result per entry (the entry's `fomo` object): matched only when exactly one trader result's handle equals the listed
handle (case-insensitive, a leading @ stripped); trader results without such a match, or with more than one, are
ambiguous with the candidate handles listed (never a guess); no trader result is not_found; a failed call is failed with
a fixed reason code. Kept: Fomo's handle (an inert label), its userId (letters, digits, _ and - only), followers (a
non-negative integer), the main Solana wallet (a base58 address; dropped when Fomo marks it unverified), the UTC check
time and the call's x-credits-cost; anything else is null. A value sharing 8 or more consecutive characters with the key
is dropped. It prints one line per name and the totals (credits charged by x-credits-cost, the last x-credits-remaining)
and never prints, logs or saves the key; every failure is a fixed reason code.

Usage: watchlist_verify.py [--dry-run] [--watchlist PATH] [--env-file PATH]. Exit 0 when the run finished and the file was
saved, 3 when it stopped early (the file is saved with what was read), 2 for a bad watchlist file, a missing key or an
unwritable file. Standard library only; Python >= 3.10.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

if str(Path(__file__).resolve().parent) not in sys.path:  # python3 -I leaves the script's folder off sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import fomoapi as fa  # noqa: E402  (the key loader, the bounded transport and the inert labels, by import)

SEARCH_PATH = "/v2/search"
RESULT_LIMIT = 5
MAX_NAMES = 20
MAX_RETRIES = 5
MAX_CALLS = MAX_NAMES + MAX_RETRIES   # 25
MIN_INTERVAL_S = 4.0                 # one request start every 4 s at most: 15 a minute
CREDITS_PER_CALL = fa.CREDITS_PER_CALL  # 250: a search is a direct call (cached docs)
USER_AGENT = "holder-scan-watchlist-verify/1.0"
WATCHLIST = Path(__file__).resolve().parents[1] / "references" / "fomo_cascade_watchlist.json"
SCHEMA = "holder-scan-fomo-cascade-watchlist/1"
TIERS = ("owner", "tier1", "tier2")
STATUSES = ("matched", "ambiguous", "not_found", "failed")
QUERY_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")
USER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
HEADER_INT_RE = re.compile(r"^[0-9]{1,12}$")
RESULT_LISTS = ("results", "traders", "data")   # where the trader results may sit; anything else is shape_mismatch
SHAPE_NAMES_CAP = 40
STOP_REASONS = ("credits_exhausted", "shape_mismatch", "invalid_json", "parse_error", "credits_cost_above_250", "call_cap_reached")
NOTE = "Fomo API is an independent, unofficial API, not affiliated with fomo.family"


# ----------------------------------------------------------------------------- request


def query_of(handle: Any) -> str | None:
    """The search text for a listed handle: a leading @ stripped, letters, digits and _ only (else None)."""
    if not isinstance(handle, str):
        return None
    text = handle[1:] if handle.startswith("@") else handle
    return text if QUERY_RE.fullmatch(text) else None


def search_query(query: str) -> str:
    return f"q={urllib.parse.quote(query, safe='')}&type=traders&limit={RESULT_LIMIT}"


def check_search_url(url: str, query: str) -> None:
    """https only, host api.fomoapi.io only, port 443, no credentials in the URL, the path /v2/search with exactly the
    fixed query for this name. Raises fomoapi.Failure with a fixed code."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise fa.Failure("scheme_not_https")
    try:
        port = parsed.port
    except ValueError:
        raise fa.Failure("host_not_allowlisted") from None
    if parsed.hostname != fa.HOST or port not in (None, 443) or parsed.username or parsed.password:
        raise fa.Failure("host_not_allowlisted")
    if parsed.path != SEARCH_PATH or parsed.query != search_query(query) or parsed.params or parsed.fragment:
        raise fa.Failure("path_not_allowlisted")


def build_search_request(query: str, key: str) -> urllib.request.Request:
    url = f"https://{fa.HOST}{SEARCH_PATH}?{search_query(query)}"
    check_search_url(url, query)
    request = urllib.request.Request(url, method="GET")
    request.headers["Authorization"] = f"Bearer {key}"  # set directly so the header keeps the documented name
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", USER_AGENT)
    return request


def _header_int(headers: Any, name: str) -> int | None:
    getter = getattr(headers, "get", None)
    raw = getter(name) if callable(getter) else None
    text = str(raw).strip() if raw is not None else ""
    return int(text) if HEADER_INT_RE.fullmatch(text) else None


class CreditTap:
    """Wraps the bounded opener for ONE call and keeps only the two credit headers of the answer (an HTTP error's too):
    x-credits-cost and x-credits-remaining, as non-negative integers. Nothing else of the answer, never a request header."""

    def __init__(self, opener: Any) -> None:
        self._opener = opener
        self.cost: int | None = None
        self.remaining: int | None = None

    def _keep(self, headers: Any) -> None:
        if headers is not None:
            self.cost = _header_int(headers, "x-credits-cost")
            self.remaining = _header_int(headers, "x-credits-remaining")

    def open(self, request: Any, timeout: Any = None) -> Any:
        try:
            response = self._opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            self._keep(getattr(exc, "headers", None))
            raise
        self._keep(getattr(response, "headers", None))
        return response


# ----------------------------------------------------------------------------- parsing (provider text is untrusted)


def _norm(handle: str) -> str:
    return (handle[1:] if handle.startswith("@") else handle).lower()


def _raw_handle(row: dict[str, Any]) -> str | None:
    for name in ("handle", "userHandle"):
        if isinstance(row.get(name), str) and row[name].strip():
            return row[name]
    return None


def _user_id(value: Any, key: str | None) -> str | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        value = str(value)
    return value if isinstance(value, str) and USER_ID_RE.fullmatch(value) and not fa.echoes_key(value, key) else None


def _followers(row: dict[str, Any]) -> int | None:
    if "followers" in row:
        return fa._count(row.get("followers"))
    profile = row.get("profile")
    return fa._count(profile.get("followers")) if isinstance(profile, dict) else None


def _wallet(row: dict[str, Any], key: str | None) -> str | None:
    """The main Solana wallet: `wallets.solana` (or `wallet.solana`), a base58 address; dropped when Fomo marks the
    wallet unverified (verified: false) or when it shares a run with the key."""
    for name in ("wallets", "wallet"):
        value = row.get(name)
        if isinstance(value, dict):
            return None if value.get("verified") is False else fa._address(value.get("solana"), key)
        if isinstance(value, str):
            return fa._address(value, key)
    return None


def _result_rows(payload: Any) -> list[Any] | None:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for name in RESULT_LISTS:
            if isinstance(payload.get(name), list):
                return payload[name]
    return None


def _empty(status: str, reason: str | None = None) -> dict[str, Any]:
    return {"status": status, "reason": reason, "handle": None, "user_id": None, "followers": None, "solana_wallet": None, "candidates": []}


def parse_search(payload: Any, query: str, key: str | None) -> dict[str, Any]:
    """One search answer for one listed name. Loud on a changed shape: no result list (shape_mismatch:result_list_missing),
    a result that is not an object (shape_mismatch:result_not_object), has no `type` (shape_mismatch:type_missing) or a
    `type` other than trader or token (shape_mismatch:type_unknown), a trader result without a handle, `userId` or wallet
    field (shape_mismatch:trader_fields_missing)."""
    rows = _result_rows(payload)
    if rows is None:
        return _empty("failed", "shape_mismatch:result_list_missing")
    traders = []
    for row in rows:
        if not isinstance(row, dict):
            return _empty("failed", "shape_mismatch:result_not_object")
        if "type" not in row:
            return _empty("failed", "shape_mismatch:type_missing")
        if row.get("type") not in ("trader", "token"):  # the documented two; another value would silently read as not_found
            return _empty("failed", "shape_mismatch:type_unknown")
        if row.get("type") != "trader":
            continue  # a token result (type=traders should leave none)
        if _raw_handle(row) is None or "userId" not in row or not any(name in row for name in ("wallets", "wallet")):
            return _empty("failed", "shape_mismatch:trader_fields_missing")
        traders.append(row)
    if not traders:
        return _empty("not_found")
    exact = [row for row in traders if _norm(_raw_handle(row)) == _norm(query)]
    if len(exact) == 1:
        row = exact[0]
        return {"status": "matched", "reason": None, "handle": fa.safe_label(_raw_handle(row), key), "user_id": _user_id(row.get("userId"), key),
                "followers": _followers(row), "solana_wallet": _wallet(row, key), "candidates": []}
    candidates = [label for label in (fa.safe_label(_raw_handle(row), key) for row in traders) if label][:RESULT_LIMIT]
    out = _empty("ambiguous", "several_exact_matches" if exact else "no_exact_handle_match")
    out["candidates"] = candidates
    return out


def shape_line(payload: Any, key: str | None) -> str:
    """The field names (only the names, as inert labels) of the first answer: its top level and its first trader result."""
    def names(obj: Any) -> str:
        if not isinstance(obj, dict):
            return "not an object"
        kept = sorted({label for label in (fa.safe_label(str(k), key) for k in list(obj)[:SHAPE_NAMES_CAP]) if label})
        return ", ".join(kept) if kept else "none"
    top = "a list" if isinstance(payload, list) else names(payload)
    rows = _result_rows(payload) or []
    trader = next((r for r in rows if isinstance(r, dict) and r.get("type") == "trader"), None)
    return f"first answer shape: top level: {top}; first trader result: " + (names(trader) if trader is not None else "none in the answer")


# ----------------------------------------------------------------------------- run


def _fomo(result: dict[str, Any], query: str | None, checked_at: str | None, credits: int | None) -> dict[str, Any]:
    return {"status": result["status"], "reason": result["reason"], "query": query, "handle": result["handle"], "user_id": result["user_id"],
            "followers": result["followers"], "solana_wallet": result["solana_wallet"], "candidates": result["candidates"],
            "checked_at": checked_at, "credits_cost": credits}


def _short(address: Any) -> str:
    return f"{address[:6]}…{address[-4:]}" if isinstance(address, str) and len(address) > 10 else "not given"


def _int_text(value: Any) -> str:
    return f"{value:,}" if isinstance(value, int) and not isinstance(value, bool) else "not given"


def label_of(entry: dict[str, Any]) -> str:
    unconfirmed = ", X handle unconfirmed" if entry.get("x_handle_status") == "unconfirmed" else ""
    return f"{entry['x_handle']} ({entry['tier']}{unconfirmed})"


def name_line(entry: dict[str, Any]) -> str:
    fomo = entry["fomo"]
    credits = (f"{fomo['credits_cost']} credits" if isinstance(fomo.get("credits_cost"), int)
               else "no call sent" if fomo.get("checked_at") is None else "credits not reported")
    head = label_of(entry)
    if fomo["status"] == "matched":
        return (f"{head}: matched; Fomo handle {fomo['handle'] or 'not kept'}; followers {_int_text(fomo['followers'])}; "
                f"wallet {_short(fomo['solana_wallet'])}; {credits}")
    if fomo["status"] == "ambiguous":
        return f"{head}: ambiguous ({fomo['reason']}; candidates: {', '.join(fomo['candidates']) or 'none readable'}); {credits}"
    if fomo["status"] == "not_found":
        return f"{head}: not_found (no trader result); {credits}"
    return f"{head}: failed ({fomo['reason']}); {credits}"


def run(doc: dict[str, Any], key: str, opener: Any, *, now: Callable[[], float], monotonic: Callable[[], float],
        sleep: Callable[[float], None], emit: Callable[[str], None]) -> dict[str, Any]:
    """One paced pass over the entries: at most MAX_CALLS calls, one start every MIN_INTERVAL_S, at most one retry per name
    (MAX_RETRIES in all) after a short 429, a stop at the first 402, a changed shape or a call above 250 credits. Fills each
    entry's `fomo` object and returns the run summary."""
    calls = retries = cost_total = cost_unknown = 0
    remaining: int | None = None
    stop: str | None = None
    last_start: float | None = None
    shape_shown = False
    for entry in doc["entries"]:
        query = query_of(entry["x_handle"])
        if stop is not None:
            entry["fomo"] = _fomo(_empty("failed", "not_sent_run_stopped"), query, None, None)
            emit(name_line(entry))
            continue
        credits: int | None = None
        retried = False
        while True:
            if calls >= MAX_CALLS:
                result, stop = _empty("failed", "call_cap_reached"), "call_cap_reached"
                break
            if last_start is not None:
                wait = last_start + MIN_INTERVAL_S - monotonic()
                if wait > 0:
                    sleep(wait)
            last_start = monotonic()
            calls += 1
            tap = CreditTap(opener)
            body, failure = None, None
            try:
                body = fa.send_once(build_search_request(query, key), tap, query, monotonic=monotonic,
                                    check=lambda url, q=query: check_search_url(url, q))
            except fa.Failure as exc:
                failure = exc
            except Exception:  # noqa: BLE001 - no exception text (which can carry request details) leaves this function
                failure = fa.Failure("request_failed")
            if tap.cost is None:
                cost_unknown += 1
            else:
                cost_total += tap.cost
                credits = (credits or 0) + tap.cost
                if tap.cost > CREDITS_PER_CALL:
                    stop = "credits_cost_above_250"
            if tap.remaining is not None:
                remaining = tap.remaining
            if failure is not None:
                if (failure.reason == "rate_limited" and failure.retry_wait is not None and not retried and retries < MAX_RETRIES
                        and calls < MAX_CALLS and stop is None):
                    retries += 1
                    retried = True
                    sleep(failure.retry_wait)
                    continue
                result = _empty("failed", failure.reason)
                if failure.http_status == 402 or failure.reason == "credits_exhausted":
                    stop = "credits_exhausted"
                break
            payload = fa._decode(body)
            if payload is None:
                result, stop = _empty("failed", "invalid_json"), "invalid_json"
                break
            if not shape_shown:
                emit(shape_line(payload, key))
                shape_shown = True
            try:
                result = parse_search(payload, query, key)
            except Exception:  # noqa: BLE001 - an answer the guards did not foresee: a fixed code, the call still counted
                result, stop = _empty("failed", "parse_error"), "parse_error"
            if str(result["reason"]).startswith("shape_mismatch"):
                stop = "shape_mismatch"
            break
        entry["fomo"] = _fomo(result, query, fa._iso(now()), credits)
        emit(name_line(entry))
    counts = {status: sum(1 for e in doc["entries"] if e["fomo"]["status"] == status) for status in STATUSES}
    summary = {"checked_at": fa._iso(now()), "request": f"GET {SEARCH_PATH}?q=<handle>&type=traders&limit={RESULT_LIMIT}", "host": fa.HOST,
               "calls_sent": calls, "retries": retries, "credits_charged": cost_total, "calls_without_credit_header": cost_unknown,
               "stopped": stop, "counts": counts}
    doc["fomo_verification"] = summary
    emit(f"total: {calls} Fomo API call{'s' if calls != 1 else ''} sent ({retries} retr{'ies' if retries != 1 else 'y'} after a 429); "
         f"{cost_total:,} credits charged by x-credits-cost" + (f" ({cost_unknown} call{'s' if cost_unknown != 1 else ''} without the header)" if cost_unknown else "")
         + "; " + (f"{remaining:,} credits remaining (last x-credits-remaining)" if remaining is not None else "credits remaining not reported")
         + "; " + ", ".join(f"{status} {counts[status]}" for status in STATUSES))
    if stop is not None:
        emit(f"RUN STOPPED EARLY ({stop}); names not sent are failed (not_sent_run_stopped)")
    return summary


# ----------------------------------------------------------------------------- file and CLI


def load_watchlist(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None, "the watchlist file is missing or not JSON"
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or not isinstance(doc.get("entries"), list):
        return None, "not a copy-trade cascade watchlist file"
    entries = doc["entries"]
    if not entries:
        return None, "the watchlist has no entries"
    if len(entries) > MAX_NAMES:
        return None, f"more than {MAX_NAMES} names: a run is capped at {MAX_CALLS} calls; nothing sent"
    seen = set()
    for number, entry in enumerate(entries, 1):
        if not isinstance(entry, dict) or query_of(entry.get("x_handle")) is None or entry.get("tier") not in TIERS:
            return None, f"entry {number} has no plain handle or no known tier"
        name = _norm(entry["x_handle"])
        if name in seen:
            return None, f"entry {number} repeats a handle"
        seen.add(name)
    return doc, None


def plan_lines(doc: dict[str, Any]) -> list[str]:
    n = len(doc["entries"])
    return [f"Copy-trade cascade watchlist check (HS-WATCHLIST-T1; owner-ask maintenance, never part of a scan; {NOTE})",
            f"plan: {n} name{'s' if n != 1 else ''}, one GET {SEARCH_PATH}?q=<handle>&type=traders&limit={RESULT_LIMIT} each on {fa.HOST}: "
            f"{n} call{'s' if n != 1 else ''}, {n * CREDITS_PER_CALL:,} credits at {CREDITS_PER_CALL} a call (at most {MAX_CALLS} calls and "
            f"{MAX_CALLS * CREDITS_PER_CALL:,} credits with up to {MAX_RETRIES} retries after a short 429) of the free key's "
            f"{fa.FREE_CREDITS_PER_MONTH:,} a month; at most {int(60 / MIN_INTERVAL_S)} requests a minute (about {int(n * MIN_INTERVAL_S)} s); "
            "stops at the first 402"]


def save(path: Path, doc: dict[str, Any], key: str) -> str | None:
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    if fa.echoes_key(text, key):  # backstop: every kept value is already checked
        return "key_echo_backstop"
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        return "not_writable"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Owner-ask maintenance: check each trader of the copy-trade cascade watchlist once on Fomo API's "
                                                 "trader search (GET /v2/search, 250 credits a call, at most 25 calls, 15 a minute, stop at the "
                                                 "first 402) and write the result into the watchlist file. Never part of a scan. --dry-run: the "
                                                 "plan only, no key read, no request.")
    parser.add_argument("--dry-run", action="store_true", help="print the plan and the calls it would send; no key read, no request, no file written")
    parser.add_argument("--watchlist", metavar="PATH", default=str(WATCHLIST), help="the watchlist file (default: references/fomo_cascade_watchlist.json)")
    parser.add_argument("--env-file", metavar="PATH", help="the repository .env (the Fomo key in the environment is used first)")
    args = parser.parse_args(argv)
    path = Path(args.watchlist)
    doc, problem = load_watchlist(path)
    if doc is None:
        print(f"error: {problem}", file=sys.stderr)
        return 2
    for line in plan_lines(doc):
        print(line)
    if args.dry_run:
        for entry in doc["entries"]:
            print(f"  would send GET {SEARCH_PATH}?{search_query(query_of(entry['x_handle']))} for {label_of(entry)}")
        print("dry run: no key read, no request sent, the watchlist file unchanged")
        return 0
    try:
        key, reason = fa.load_key(None if os.environ.get(fa.KEY_NAME, "").strip() else fa.find_env_file(args.env_file))
    except Exception:  # noqa: BLE001 - never a traceback
        key, reason = None, "key_load_failed"
    if not key:
        print(f"unavailable ({reason}; no Fomo API call sent; the watchlist file unchanged)")
        return 2

    def emit(line: str) -> None:
        print("(line withheld: it shared a piece of the key)" if fa.echoes_key(line, key) else line, flush=True)

    try:
        summary = run(doc, key, fa.default_opener(), now=time.time, monotonic=time.monotonic, sleep=time.sleep, emit=emit)
    except Exception:  # noqa: BLE001 - never print a traceback (it could carry request details)
        print("unavailable (run_failed; the watchlist file unchanged)")
        return 2
    problem = save(path, doc, key)
    if problem:
        print(f"error: the watchlist file was not saved ({problem})", file=sys.stderr)
        return 2
    print(f"saved: {path.name} ({len(doc['entries'])} entries; fomo_verification filled)")
    return 3 if summary["stopped"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
