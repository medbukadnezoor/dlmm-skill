#!/usr/bin/env python3
"""Jupiter datapi top-100 holder rows for dlmm-scan (first-wave collector `jupiter_rows`): one bounded, read-only
request. Free, no key.

It REUSES the analysis engine's Jupiter client in this skill (scripts/ha/jupiter.py JupiterClient.holders: the same
host, the same GET /v1/holders/<mint>?limit=100 request, the same "no holder list" shape check and the same row
normalizer, over scripts/ha/transport.py with its host allowlist, https-only rule and size cap) and adds the collector
guards around it: no environment proxy and no redirects (its own opener), a hard wall-clock deadline over the whole
read (worker thread, like gmgn_rows.py and solscanner_scan.py), fixed reason codes, and documented fields only.

The endpoint is undocumented (no Jupiter docs cover datapi); every failure is unavailable with a reason, never zero.

Writes into --out (the run folder):
  jupiter_top100.json  status ok | empty | unavailable with a fixed reason code, the request facts (host, path, query
                       field names; no key exists), the holder count datapi reports, Jupiter's tag claims, and the
                       rows under "holders" with datapi's own field names, so helius_forensics.py assess
                       --jupiter-holders-json reads this file exactly like a raw datapi answer: address, amount (token
                       units), addressInfo {fundingAddress, fundingAmount, fundingBlockTime} and tags (Jupiter's
                       holderTags / walletCategories / tags merged, lowercased and reduced to inert labels, as the
                       analysis engine's normalizer does). Nothing else from the answer is kept.

A renamed load-bearing field is loud, never ok: no row with a readable funding time gives unavailable
(funding_field_missing); funding times but no readable funder in any row gives unavailable (funder_field_missing)
(read as ok, every unknown funder would look like one shared funder and a multi-funder farm would read calmer). When no
row carries a text-tag field (holderTags or walletCategories as a list of text, or tags holding text; datapi's
object-valued tags are pool labels and do not count), the status stays ok (the rows still feed the cohort detector) but
tag_fields_present is false and tag_claims is null: Jupiter's tags are then unknown, never "no bundlers".

Requests per scan: 1 (the client's transport retries a 429, a 5xx or a network failure at most twice, 1 s then 2 s
apart: at most 3). Prints one line: ok (...), empty (...) or unavailable (<reason>; ...). Exit 0 whenever
jupiter_top100.json was saved; exit 2 for a bad mint or an unwritable --out. Standard library only; Python >= 3.10.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import queue
import re
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import provider_words as pw  # noqa: E402  (HS-LABELS-T1: verdict words in provider text; standard library only, no network)
from ha.jupiter import HOST, JupiterClient  # noqa: E402
from ha.transport import TransportError  # noqa: E402

HOLDERS_PATH = "/v1/holders/<MINT>"
LIMIT = 100                      # datapi lists the top 100 holders only
MAX_REQUESTS = 3                 # 1 request plus at most 2 retries inside ha/transport.py (429, 5xx or network failure)
TIMEOUT_S = 30.0                 # hard wall-clock limit on the whole read (worker thread); also the socket timeout
OUT_FILE = "jupiter_top100.json"
SCHEMA = "holder-scan-jupiter-rows/1"
SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
ISO_TIME_RE = re.compile(r"^[0-9T:.\-+Z ]{10,40}$")
LABEL_RE = re.compile(r"[^\w .\-]")  # the forensics adapter's LABEL_RE: letters, digits, _, space, dot and hyphen only
MIN_UNIX = 1_262_304_000         # 2010-01-01: older "times" are not real Solana activity
FUTURE_SLACK_S = 86_400
MAX_TAGS_PER_ROW = 16
TAG_CLAIMS_NOTE = ("Jupiter's own labels: claims, not proof. Top 100 rows only, so every count is a floor of Jupiter's "
                   "view, never a total. Jupiter's bundler definition is its own (GMGN, Solana Tracker and Bubblemaps "
                   "use theirs): name each provider's number, never average them.")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect (returning None makes urllib raise the 3xx as an HTTPError, which the transport reduces to
    redirect_disallowed)."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class RawKeepingClient(JupiterClient):
    """The analysis engine's Jupiter client, unchanged, that also keeps the raw answer of its last request, so the
    collector can tell which rows carried a text-tag field (the client's normalizer merges the tag fields)."""

    raw: Any = None

    def _get(self, path: str, query: dict[str, Any] | None = None) -> Any:
        self.raw = super()._get(path, query)
        return self.raw


def has_text_tag_field(row: dict[str, Any]) -> bool:
    """holderTags or walletCategories as a list that is empty or holds text, or any of the three holding text. Object
    lists (datapi's tags with pool labels) are not text tags."""
    for field in ("holderTags", "walletCategories", "tags"):
        value = row.get(field)
        if isinstance(value, list) and (any(isinstance(v, str) for v in value) or (not value and field != "tags")):
            return True
    return False


class CountingOpener:
    """Counts every request the client's transport sends (retries included), for the request facts."""

    def __init__(self, opener: Any) -> None:
        self.opener, self.sent = opener, 0

    def open(self, request: Any, timeout: Any = None) -> Any:
        self.sent += 1
        return self.opener.open(request, timeout=timeout)


def default_opener() -> urllib.request.OpenerDirector:
    """No environment proxy (an explicit empty ProxyHandler), no redirects, default TLS verification."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def _bounded_call(function: Callable[[], Any], timeout: float) -> Any:
    """Run the whole read (open, every read, close, the client's retries) in a daemon worker and wait at most `timeout`
    seconds: a hard wall-clock bound, the same way gmgn_rows.py and solscanner_scan.py do it. A socket timeout alone
    restarts on every byte, so a server that drip-feeds bytes (or a stalled DNS or TLS step) could otherwise hold the
    collector far past the deadline. An abandoned read publishes nothing."""
    if timeout <= 0:
        raise TimeoutError
    result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def invoke() -> None:
        try:
            result.put((True, function()))
        except BaseException as exc:  # handed back to the bounded caller
            result.put((False, exc))

    worker = threading.Thread(target=invoke, name="jupiter-rows-transport", daemon=True)
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


# ----------------------------------------------------------------------------- rows (datapi names kept)


def _finite(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _non_negative(value: Any) -> float | None:
    number = _finite(value)
    return number if number is not None and number >= 0 else None


def funding_time(value: Any, now: float | None = None) -> int | str | None:
    """datapi's fundingBlockTime as given (an ISO-8601 string, or unix seconds / milliseconds), kept only when it reads
    as a plausible time (2010 to one day ahead); the forensics adapter then reads it exactly as from a raw answer."""
    ceiling = (time.time() if now is None else now) + FUTURE_SLACK_S
    if isinstance(value, str):
        text = value.strip()
        if not ISO_TIME_RE.fullmatch(text):
            return None
        try:
            parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None
        return value if MIN_UNIX <= parsed.timestamp() <= ceiling else None
    number = _finite(value)
    if number is None or number <= 0:
        return None
    seconds = number / 1000 if number > 1e12 else number
    return value if MIN_UNIX <= seconds <= ceiling else None


def safe_label(value: Any) -> str | None:
    """The forensics adapter's inert-label rule (LABEL_RE, 32 characters, verdict words replaced by the placeholder:
    provider_words, HS-LABELS-T1)."""
    return pw.label(value, LABEL_RE)


def sanitize_rows(normalized: list[dict[str, Any]], now: float | None = None) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Rows from ha/jupiter.py normalize_holder output, written back under datapi's own names (the shape
    --jupiter-holders-json reads). Invalid addresses and duplicates are dropped (first row kept), then the list is cut
    to LIMIT. Every value is a validated address, number or time; tags are inert labels. Returns (rows, dropped)."""
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    dropped = {"invalid_address": 0, "duplicate": 0, "over_limit": 0}
    for holder in normalized:
        address = holder.get("owner")
        if not isinstance(address, str) or not SOLANA_ADDRESS_RE.fullmatch(address):
            dropped["invalid_address"] += 1
            continue
        if address in seen:
            dropped["duplicate"] += 1
            continue
        seen.add(address)
        row: dict[str, Any] = {"address": address, "amount": _non_negative(holder.get("amount"))}
        funder = holder.get("funder")
        info = {
            "fundingAddress": funder if isinstance(funder, str) and SOLANA_ADDRESS_RE.fullmatch(funder) else None,
            "fundingAmount": _non_negative(holder.get("funding_amount")),
            "fundingBlockTime": funding_time(holder.get("funded_at"), now),
        }
        if any(v is not None for v in info.values()):
            row["addressInfo"] = info
        tags = holder.get("tags")
        if isinstance(tags, list):  # None means the row carried no tag field at all: keep that distinct from []
            row["tags"] = sorted({label.lower() for t in tags if (label := safe_label(t))})[:MAX_TAGS_PER_ROW]
        rows.append(row)
    dropped["over_limit"] = max(0, len(rows) - LIMIT)
    return rows[:LIMIT], dropped


def tag_claims(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Wallets and token amount per Jupiter tag, as Jupiter's claims (shares of supply come from the Helius list in the
    forensics report; datapi rows carry token amounts, not shares)."""
    buckets: dict[str, dict[str, Any]] = {}
    for row in rows:
        for tag in row.get("tags") or []:
            b = buckets.setdefault(tag, {"wallets": 0, "amount": 0.0, "amount_unknown_wallets": 0})
            b["wallets"] += 1
            if row["amount"] is None:
                b["amount_unknown_wallets"] += 1
            else:
                b["amount"] += row["amount"]
    ordered = sorted(buckets.items(), key=lambda kv: (-kv[1]["wallets"], kv[0]))
    return {"note": TAG_CLAIMS_NOTE, "tags": {t: b | {"amount": round(b["amount"], 6)} for t, b in ordered}}


# ----------------------------------------------------------------------------- collect


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _base(mint: str, fetched_at: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "provider": "Jupiter datapi", "mint": mint, "status": "unavailable", "reason": None, "http_status": None,
        "fetched_at": fetched_at,
        "request": {"method": "GET", "host": HOST, "path": HOLDERS_PATH, "query_fields": ["limit"], "limit": LIMIT, "auth_header_names": [],
                    "requests_sent": 0, "max_requests": MAX_REQUESTS},
        "holder_count": None, "rows_read": 0, "with_funding_time": 0, "with_funder": 0, "rows_dropped": None,
        "tag_fields_present": None, "tag_claims": None,
        "cannot_see": "only the top 100 holders (everything below rank 100 is invisible); the endpoint is undocumented and may change",
        "holders": [],
    }


REASONS = {"unexpected_shape": "holder_list_missing"}


def collect_jupiter_rows(mint: str, *, opener: Any | None = None, now: Callable[[], float] | None = None) -> dict[str, Any]:
    """One read through ha/jupiter.py JupiterClient.holders under a hard deadline. Returns the jupiter_top100.json
    result; never raises for provider or transport failures."""
    now = now or time.time
    result = _base(mint, _iso(now()))
    counting = CountingOpener(opener or default_opener())
    client = RawKeepingClient(opener=counting, timeout=max(1, int(TIMEOUT_S)))
    try:
        answer = _bounded_call(lambda: client.holders(mint, limit=LIMIT), TIMEOUT_S)
    except TransportError as exc:  # the transport's fixed reason codes (no request text, no URL)
        result.update(reason=REASONS.get(exc.reason, exc.reason), http_status=exc.http_status)
        result["request"]["requests_sent"] = counting.sent
        return result
    except TimeoutError:  # the hard wall-clock deadline ended the read
        result["reason"] = "timeout"
        result["request"]["requests_sent"] = counting.sent
        return result
    except Exception:  # noqa: BLE001 - never let exception text (which can carry request details) out
        result["reason"] = "request_failed"
        result["request"]["requests_sent"] = counting.sent
        return result
    result["request"]["requests_sent"] = counting.sent
    result.update(http_status=200, fetched_at=_iso(now()))
    count = answer.get("count") if isinstance(answer, dict) else None
    result["holder_count"] = count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else None
    normalized = answer.get("holders") if isinstance(answer, dict) else None
    if not isinstance(normalized, list):
        result["reason"] = "holder_list_missing"
        return result
    if not normalized:
        result.update(status="empty", reason="holder_list_empty")  # unknown, never read as "no holders"
        return result
    raw_rows = [r for r in (client.raw or {}).get("holders") or [] if isinstance(r, dict)] if isinstance(client.raw, dict) else []
    if len(raw_rows) == len(normalized):  # the same rows the client normalized, in the same order
        normalized = [n if has_text_tag_field(raw) else dict(n, tags=None) for n, raw in zip(normalized, raw_rows)]
    else:  # cannot pair the rows: treat the tags as unknown rather than guess
        normalized = [dict(n, tags=None) for n in normalized]
    rows, dropped = sanitize_rows(normalized, now())
    result["rows_dropped"] = dropped
    if not rows:
        result["reason"] = "no_valid_holder_rows"  # a non-empty list with no usable row means the format changed
        return result
    with_time = sum(1 for r in rows if (r.get("addressInfo") or {}).get("fundingBlockTime") is not None)
    with_funder = sum(1 for r in rows if (r.get("addressInfo") or {}).get("fundingAddress"))
    # A renamed load-bearing field must be loud, never "ok": no funding time anywhere drops the cohort detector over
    # these rows; funding times without any funder would read every wallet as fed by one unknown funder.
    if not with_time:
        result["reason"] = "funding_field_missing"
        return result
    if not with_funder:
        result["reason"] = "funder_field_missing"
        return result
    tagged = any("tags" in r for r in rows)
    result.update(status="ok", rows_read=len(rows), with_funding_time=with_time, with_funder=with_funder, tag_fields_present=tagged,
                  tag_claims=tag_claims(rows) if tagged else None, holders=rows)
    return result


def status_line(result: dict[str, Any]) -> str:
    sent = result["request"]["requests_sent"]
    calls = f"{sent} Jupiter request{'s' if sent != 1 else ''} (free, no key)" if sent else "no Jupiter request sent"
    if result["status"] == "ok":
        tags = "tags read" if result["tag_fields_present"] else "tags unknown (no text tag field in any row)"
        return f"ok ({result['rows_read']} rows; {result['with_funding_time']} with a funding time; {tags}; {calls})"
    if result["status"] == "empty":
        return f"empty (Jupiter returned an empty holder list: unknown, not a reassurance; {calls})"
    return f"unavailable ({result['reason']}; {calls})"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read Jupiter datapi's top-100 holder rows for a Solana mint once (free, no key; bounded: "
                                                 "30 s, no redirects, no env proxy) and save "
                                                 f"{OUT_FILE} for helius_forensics.py assess --jupiter-holders-json.")
    parser.add_argument("mint")
    parser.add_argument("--out", required=True, metavar="RUN_DIR", help="run folder to save the file into")
    args = parser.parse_args(argv)
    mint = args.mint
    if not isinstance(mint, str) or not SOLANA_ADDRESS_RE.fullmatch(mint):
        print("error: mint is not a valid base58 Solana address", file=sys.stderr)
        return 2
    out = Path(args.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    try:
        result = collect_jupiter_rows(mint)
    except Exception:  # noqa: BLE001 - never print a traceback (it could carry request details)
        result = _base(mint, _iso(time.time()))
        result["reason"] = "request_failed"
    try:
        (out / OUT_FILE).write_text(json.dumps(result, indent=1), encoding="utf-8")
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    print(status_line(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
