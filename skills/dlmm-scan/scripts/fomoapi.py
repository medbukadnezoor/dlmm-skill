#!/usr/bin/env python3
"""Fomo API: which Fomo-tracked traders hold a token, for dlmm-scan (first-wave collector `fomoapi`): one fixed, bounded,
read-only request.

Fomo API (api.fomoapi.io) is an independent, unofficial developer API; it is not affiliated with fomo.family (the Fomo
trading app). Its holder list names Fomo traders by their handle: information, not a signal of safety or danger.

PRESENTATION ONLY. The list never feeds either engine: it is shown in the synthesis's "Sources read" only.
helius_forensics.py refuses Fomo API as a --providers-json provider (exit 2). Fomo's rows carry token amounts and USD
values, not shares of supply, so no Fomo number matches a cluster or bundle bar and this collector never prints a
late-source line. An empty list is never "nobody holds it" and never an all-clear.

Request (provider-docs cache, fomoapi.md "Token holders"):
  GET /token/<mint>/holders?network=1399811149&limit=100   (1399811149 is Fomo's Solana network id)
Host api.fomoapi.io only, https only, the key in the Authorization header as a Bearer token, no redirects, no
environment proxy, 2 MiB and a hard 30 s wall-clock limit per attempt (opening, every read and closing under one
deadline, worker thread, like solanatracker.py), and at most one retry, only after a 429 whose Retry-After ends within
5 s (without one there is no retry). Calls per scan: 1 (at most 2), 250 credits each, of the free key's 250,000 credits
a month (0.1% of the month per scan).

Key: only FOMOAPI_KEY (the name in the owner's .env), from the environment first, then exactly that one variable from
the repository .env (single-variable parser; the file is never sourced). It is sent only in the Authorization header and is
never printed, logged, saved or put in an error: every failure becomes a fixed reason code. Provider text is untrusted:
handles are reduced to short inert labels, every other kept value is a validated number, flag or address, and any kept
text whose raw form or label shares 8 or more consecutive characters with the key (or with the key stripped of the
characters a label cannot hold) is dropped; address fields use the same shared-piece check.

A renamed load-bearing field is loud, never ok (see parse_holders); a number that is not read is reported as not read,
never as 0.

Collector: fomoapi.py <MINT> --out <RUN> writes <RUN>/fomoapi.json and prints one line: ok (...), empty (...) or
unavailable (<reason>; ...). Exit 0 whenever the file was saved; exit 2 for a bad mint or an unwritable --out.
Synthesis (offline, no network, no key): fomoapi.py --present <RUN> prints the Sources-read block ("Fomo-tracked
traders holding"). Standard library only; Python >= 3.10.
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

if str(Path(__file__).resolve().parent) not in sys.path:  # python3 -I leaves the script's folder off sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import provider_words as pw  # noqa: E402  (HS-LABELS-T1: verdict words in provider text; standard library only, no network)

HOST = "api.fomoapi.io"
HOLDERS_PATH = "/token/<MINT>/holders"
SOLANA_NETWORK_ID = "1399811149"
ROW_LIMIT = 100
QUERY = f"network={SOLANA_NETWORK_ID}&limit={ROW_LIMIT}"
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = 30.0                 # per attempt: a hard wall-clock limit on open + every read + close (worker thread)
RETRY_MAX_WAIT_S = 5.0           # retry a 429 once only when its Retry-After ends this soon
REQUESTS_PER_SCAN = 1
MAX_REQUESTS = 2
CREDITS_PER_CALL = 250           # a token-holders call, per the cached docs
FREE_CREDITS_PER_MONTH = 250_000
USER_AGENT = "holder-scan-fomoapi/1.0"
KEY_NAME = "FOMOAPI_KEY"
AUTH_HEADER_NAMES = ("Authorization",)
KEY_RE = re.compile(r"^[\x21-\x7e]{8,512}$")  # printable, no spaces: a valid header value; the value is never echoed
KEY_PIECE = 8                    # provider text sharing this many consecutive characters with the key is dropped
SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
LABEL_RE = re.compile(r"[^\w .\-]")  # the forensics adapter's LABEL_RE: letters, digits, _, space, dot and hyphen only
OUT_FILE = "fomoapi.json"
SCHEMA = "holder-scan-fomoapi/1"
HTTP_REASONS = {400: "bad_request", 401: "authentication_failed", 402: "credits_exhausted", 403: "access_denied", 404: "not_found",
                429: "rate_limited", 503: "service_unavailable"}
INDEPENDENCE_NOTE = "an independent, unofficial API, not affiliated with fomo.family"
CANNOT_SEE = ("only traders Fomo tracks (Fomo app users with a handle), never the whole holder list; amounts and USD values, "
              "not shares of supply; no funding links; the list has no completeness flag")
PRESENTATION_NOTE = ("presentation only and information only: a Fomo-tracked trader holding the token is not a signal of "
                     "safety or danger; never an engine input, never counts toward NO_ALARM and never softens a FLAG")


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
    """(key, None) or (None, reason). Environment first, then exactly the one FOMOAPI_KEY line of the .env; no other
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
        return None, "missing_key"
    if not KEY_RE.match(key):
        return None, "key_format"
    return key, None


# ----------------------------------------------------------------------------- request


def holders_path(mint: str) -> str:
    return f"/token/{urllib.parse.quote(mint, safe='')}/holders"


def check_url(url: str, mint: str) -> None:
    """https only, host api.fomoapi.io only, the documented holders path for this mint with its fixed query only, no port
    other than 443, no credentials in the URL."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise Failure("scheme_not_https")
    if parsed.hostname != HOST or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise Failure("host_not_allowlisted")
    if parsed.path != holders_path(mint) or parsed.query != QUERY or parsed.params or parsed.fragment:
        raise Failure("path_not_allowlisted")


def build_request(mint: str, key: str) -> urllib.request.Request:
    url = f"https://{HOST}{holders_path(mint)}?{QUERY}"
    check_url(url, mint)
    request = urllib.request.Request(url, method="GET")
    request.headers["Authorization"] = f"Bearer {key}"  # set directly so the header keeps the documented name
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", USER_AGENT)
    return request


def default_opener() -> urllib.request.OpenerDirector:
    """No environment proxy (an explicit empty ProxyHandler), no redirects, default TLS verification."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def _bounded_call(function: Callable[[], Any], timeout: float) -> Any:
    """Run one blocking transport step (open, read, close) in a daemon worker and wait at most `timeout` seconds: a hard
    wall-clock bound, the same way solanatracker.py and gmgn_rows.py do it. A socket timeout alone restarts on every
    byte, so a server that drip-feeds bytes (or a stalled DNS or TLS step) could otherwise hold the collector far past
    the deadline. An abandoned step publishes nothing and cannot retry."""
    if timeout <= 0:
        raise TimeoutError
    result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def invoke() -> None:
        try:
            result.put((True, function()))
        except BaseException as exc:  # handed back to the bounded caller
            result.put((False, exc))

    worker = threading.Thread(target=invoke, name="fomoapi-transport", daemon=True)
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
    """The wait a 429 allows before the one retry: Retry-After seconds within RETRY_MAX_WAIT_S; None (no retry) when it
    asks for longer, is unreadable or is absent."""
    headers = getattr(exc, "headers", None)
    raw = headers.get("Retry-After") if headers is not None else None
    if raw is None:
        return None
    text = str(raw).strip()
    if not re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,3})?", text):
        return None
    wait = max(0.5, float(text))
    return wait if wait <= RETRY_MAX_WAIT_S else None


def send_once(request: urllib.request.Request, opener: Any, mint: str, *, monotonic: Callable[[], float],
              check: Callable[[str], None] | None = None) -> bytes:
    """One attempt. Returns the body (at most MAX_BYTES) or raises Failure with a fixed code. Opening, every read and the
    error close run under one hard wall-clock deadline of TIMEOUT_S, so the attempt ends by then whatever the server does.
    An error body is never read. `check` (HS-WATCHLIST-T1: watchlist_verify.py's own allowlist of its one search path)
    replaces the holders-path check; without it this collector's check_url runs exactly as before."""
    if check is None:
        check_url(request.full_url, mint)
    else:
        check(request.full_url)
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
                raise Failure("rate_limited", 429, retry_wait=_retry_after(exc)) from None
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
    """The documented request, plus at most one retry after a short 429. Returns {body, attempts, reason, http_status};
    never raises."""
    out: dict[str, Any] = {"body": None, "attempts": 0, "reason": None, "http_status": None}
    for attempt in (1, 2):
        out["attempts"] = attempt
        try:
            out.update(body=send_once(build_request(mint, key), opener, mint, monotonic=monotonic), reason=None, http_status=200)
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


# ----------------------------------------------------------------------------- sanitizing (provider text is untrusted)


def shares_key_piece(text: Any, key: str | None) -> bool:
    """True when `text` and the key share any run of KEY_PIECE (8) or more consecutive characters."""
    if not key or not isinstance(text, str) or not text:
        return False
    if len(key) < KEY_PIECE:
        return key in text
    return any(key[i:i + KEY_PIECE] in text for i in range(len(key) - KEY_PIECE + 1))


def echoes_key(text: Any, key: str | None) -> bool:
    """True when `text` shares a KEY_PIECE run with the key, or with the key stripped of the characters a label cannot
    hold (LABEL_RE), so an echo of a key with / + = survives neither as raw text nor as a label."""
    if not key:
        return False
    stripped = LABEL_RE.sub("", key)
    return shares_key_piece(text, key) or (stripped != key and len(stripped) >= KEY_PIECE and shares_key_piece(text, stripped))


def safe_label(value: Any, key: str | None = None) -> str | None:
    """A short inert label (the forensics adapter's rule: LABEL_RE, 32 characters, verdict words replaced by the
    placeholder: provider_words, HS-LABELS-T1); None when the raw text or the label echoes the key."""
    if not isinstance(value, str) or not value.strip() or echoes_key(value, key) or echoes_key(LABEL_RE.sub("", value), key):
        return None  # the old character-only label is checked too (HS-LABELS-T1: dropping HTML first must never let an echo through)
    label = pw.label(value, LABEL_RE)
    return None if echoes_key(label, key) else label


def _number(value: Any, lo: float, hi: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return float(value) if lo <= value <= hi else None


def _count(value: Any) -> int | None:
    number = _number(value, 0, 10**9)
    return int(number) if number is not None and number.is_integer() else None


def _address(value: Any, key: str | None) -> str | None:
    """A Solana address, dropped when it shares a KEY_PIECE run with the key (not only when it equals it)."""
    return value if isinstance(value, str) and SOLANA_ADDRESS_RE.fullmatch(value) and not echoes_key(value, key) else None


SCOPES = frozenset({"live-top-holders", "tracked-traders"})
NOT_AVAILABLE = {"no-data": "no_data", "unknown-chain": "unknown_chain"}
ROWS_KEPT = 100


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def parse_holders(payload: Any, mint: str, key: str | None) -> dict[str, Any]:
    """The holders answer, field names as in the docs and the live answer of 2026-10-19: {token, scope, source, count,
    totalHolders, holders: [{handle, amount, valueUsd, costBasisUsd, pnlUsd, isDev, verified, wallet {solana, verified}}]}.
    Rows keep only those fields: the handle as an inert label, the numbers validated, the Solana wallet only when Fomo
    marks it verified (Fomo withholds unverified ones). Loud guards: an answer for another mint gives unavailable
    (identity_mismatch); a `scope`, `reason` or `source` that is not text gives unavailable (malformed_answer);
    `available: false` gives empty (no_data / unknown_chain: never "no holders"); no holder list
    gives unavailable (holder_list_missing); an empty list gives empty (holder_list_empty: unknown, never "nobody holds
    it"); rows of which none has a readable handle give unavailable (handle_field_missing)."""
    if not isinstance(payload, dict):
        return {"status": "unavailable", "reason": "invalid_shape"}
    token = payload.get("token")
    if token is not None and token != mint:
        return {"status": "unavailable", "reason": "identity_mismatch"}
    if any(payload.get(name) is not None and not isinstance(payload.get(name), str) for name in ("scope", "reason", "source")):
        return {"status": "unavailable", "reason": "malformed_answer"}  # documented as text: another type is a changed answer
    if payload.get("available") is False:
        reason = payload.get("reason")
        return {"status": "empty", "reason": NOT_AVAILABLE.get(reason, "not_available") if isinstance(reason, str) else "not_available"}
    rows = payload.get("holders")
    if not isinstance(rows, list):
        return {"status": "unavailable", "reason": "holder_list_missing"}
    scope = payload.get("scope") if isinstance(payload.get("scope"), str) and payload.get("scope") in SCOPES else None
    source = safe_label(payload.get("source"), key)
    stale = payload.get("stale") if isinstance(payload.get("stale"), bool) else (source == "live-fomo-stale")
    base = {"identity": "confirmed" if token == mint else "not_in_answer", "scope": scope, "source": source, "stale": stale,
            "age_seconds": _number(payload.get("ageSeconds"), 0.0, 1e9), "total_holders": _count(payload.get("totalHolders")), "count": _count(payload.get("count"))}
    if not rows:
        return {"status": "empty", "reason": "holder_list_empty", **base, "holders": []}
    kept, dropped = [], 0
    for row in rows[:ROWS_KEPT]:
        if not isinstance(row, dict):
            dropped += 1
            continue
        wallet = _dict(row.get("wallet"))
        kept.append({
            "handle": safe_label(row.get("handle"), key), "amount": _number(row.get("amount"), 0.0, 1e18), "valueUsd": _number(row.get("valueUsd"), 0.0, 1e12),
            "costBasisUsd": _number(row.get("costBasisUsd"), 0.0, 1e12), "pnlUsd": _number(row.get("pnlUsd"), -1e12, 1e12),
            "isDev": row.get("isDev") if isinstance(row.get("isDev"), bool) else None, "verified": row.get("verified") if isinstance(row.get("verified"), bool) else None,
            "wallet_solana": _address(wallet.get("solana"), key) if wallet.get("verified") is True else None,
        })
    if not any(r["handle"] for r in kept):
        return {"status": "unavailable", "reason": "handle_field_missing"}
    return {"status": "ok", "reason": None, **base, "rows_dropped": dropped + max(0, len(rows) - ROWS_KEPT),
            "dev_field_present": any(r["isDev"] is not None for r in kept), "holders": kept}


# ----------------------------------------------------------------------------- collect


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _base(mint: str, fetched_at: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "provider": "Fomo API", "independence": INDEPENDENCE_NOTE, "mint": mint, "status": "unavailable", "reason": None,
        "fetched_at": fetched_at, "http_status": None,
        "request": {"method": "GET", "host": HOST, "path": f"{HOLDERS_PATH}?{QUERY}", "auth_header_names": list(AUTH_HEADER_NAMES), "auth_scheme": "Bearer",
                    "requests_per_scan": REQUESTS_PER_SCAN, "max_requests": MAX_REQUESTS, "credits_per_call": CREDITS_PER_CALL,
                    "free_credits_per_month": FREE_CREDITS_PER_MONTH, "requests_sent": 0},
        "presentation_only": True, "note": PRESENTATION_NOTE, "cannot_see": CANNOT_SEE,
    }


def _decode(body: Any) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError, AttributeError):
        return None


def collect_fomoapi(
    mint: str,
    key: str | None,
    *,
    key_reason: str | None = None,
    opener: Any | None = None,
    now: Callable[[], float] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """The documented request with at most one retry after a short 429. Returns the fomoapi.json result; never raises for
    provider or transport failures."""
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    result = _base(mint, _iso(now()))
    if not key:
        result["reason"] = key_reason or "missing_key"
        return result
    got = fetch(mint, key, opener or default_opener(), monotonic=monotonic, sleep=sleep)
    result["request"]["requests_sent"] = got["attempts"]
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
        result.update(parse_holders(payload, mint, key))
    except Exception:  # noqa: BLE001 - a malformed answer the guards did not foresee: a fixed code, the call still counted
        result.update(status="unavailable", reason="parse_error")
    return result


def status_line(result: dict[str, Any]) -> str:
    sent = result["request"]["requests_sent"]
    calls = f"{sent} Fomo API call{'s' if sent != 1 else ''}, {CREDITS_PER_CALL * sent} credits" if sent else "no Fomo API call sent"
    if result["status"] == "ok":
        return f"ok ({len(result.get('holders') or [])} Fomo-tracked traders listed; {calls})"
    if result["status"] == "empty":
        return f"empty (Fomo lists no tracked trader holding it ({result.get('reason')}): unknown, not a signal either way; {calls})"
    return f"unavailable ({result['reason']}; {calls})"


# ----------------------------------------------------------------------------- presentation (synthesis, offline)


TEXT_RE = re.compile(r"[^\w .:;,()%+\-']")  # saved-file text printed by --present: no newlines, no markdown marks (an apostrophe is inert)
LIST_CAP = 8                     # traders named before "and N more"


def _text(value: Any, cap: int = 80) -> str:
    """Any text taken from a saved file before it is printed: inert characters only, capped, verdict words replaced by the
    placeholder (HS-LABELS-T1, provider_words.cut: made inert first, cut where it was cut before, then marked)."""
    return pw.cut(str(value), lambda s: " ".join(TEXT_RE.sub("", " ".join(s.split())).split()), cap) or "unknown"  # cut as before, then marked


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _fmt(value: Any) -> str:
    """4 significant digits, cut toward zero (never rounded up)."""
    if not _is_number(value):
        return "unknown"
    value = float(value)
    if value == 0:
        return "0"
    scale = 10 ** (3 - math.floor(math.log10(abs(value))))
    return f"{math.trunc(value * scale + math.copysign(1e-9, value)) / scale:g}"


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None


def _valid_saved(data: Any) -> bool:
    return isinstance(data, dict) and data.get("schema") == SCHEMA and data.get("status") in ("ok", "empty", "unavailable") and data.get("presentation_only") is True


def _age_min(value: Any) -> float | None:
    try:
        fetched = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if fetched.tzinfo is None:
            return None
        return max(0.0, (dt.datetime.now(dt.timezone.utc) - fetched).total_seconds() / 60)
    except (ValueError, TypeError, OverflowError):
        return None


def present(run: Path) -> list[str]:
    """The Sources-read block for Fomo API ("Fomo-tracked traders holding"). Reads only the saved file in the run folder:
    no network, no key. A missing, foreign or malformed file or value reads as not read, never as 0 and never as a crash.
    Fomo's rows carry amounts and USD values, not shares of supply: no late-source line is ever printed here."""
    data = _read_json(run / OUT_FILE)
    result = data if _valid_saved(data) else None
    head = f"Fomo API (collector fomoapi; {INDEPENDENCE_NOTE})"
    if result is None:
        return [f"{head}: not read ({OUT_FILE} " + ("missing" if not (run / OUT_FILE).exists() else "unreadable") + ")"]
    sent = _dict(result.get("request")).get("requests_sent")
    sent_text = (f"{sent} call{'s' if sent != 1 else ''}, {sent * CREDITS_PER_CALL} credits of the free key's {FREE_CREDITS_PER_MONTH:,} a month"
                 if isinstance(sent, int) and not isinstance(sent, bool) else "calls unknown")
    age = _age_min(result.get("fetched_at"))
    state = {"ok": "read", "empty": "empty", "unavailable": "unavailable"}[result["status"]]
    line = f"{head}: {state}" + ("" if result["status"] == "ok" else f" ({_text(result.get('reason'), 160)})")
    lines = [line + (f"; data age {age:.0f} min" if age is not None else "; data age unknown") + f"; {sent_text}"]
    if result["status"] == "empty":
        lines.append("  Fomo-tracked traders holding: none listed by Fomo (unknown, not a signal either way; never \"nobody holds it\")")
    elif result["status"] == "ok":
        rows = [r for r in result.get("holders") if isinstance(r, dict)] if isinstance(result.get("holders"), list) else []
        named = [r for r in rows if isinstance(r.get("handle"), str) and r["handle"].strip()]
        values = [r["valueUsd"] for r in named if _is_number(r.get("valueUsd"))]
        scope_value = result.get("scope")
        scope = ({"live-top-holders": "FOMO's own top-holder list", "tracked-traders": "Fomo API's tracked traders (fallback list)"}.get(scope_value, "scope not stated")
                 if isinstance(scope_value, str) else "scope not stated")
        stale = result.get("stale") is True
        shown = [f"{_text(r['handle'], 32)} (" + (f"${_fmt(r['valueUsd'])}" if _is_number(r.get("valueUsd")) else "value not read") + ")" for r in named[:LIST_CAP]]
        total = result.get("total_holders")
        total_text = (f"; FOMO reports {total} holders in total (its own count, not checked)" if isinstance(total, int) and not isinstance(total, bool) else "")
        if named:
            lines.append(f"  Fomo-tracked traders holding ({scope}" + (", stale list" if stale else "") + f"): {len(named)} listed"
                         + (f", worth ${_fmt(sum(values))} together" if len(values) == len(named) else "") + ": " + ", ".join(shown)
                         + (f", and {len(named) - LIST_CAP} more" if len(named) > LIST_CAP else "") + total_text)
        else:
            lines.append("  Fomo-tracked traders holding: not read (no readable handle in the file)")
        devs = [r for r in named if r.get("isDev") is True]
        if any(isinstance(r.get("isDev"), bool) for r in named):
            lines.append("  dev flag (FOMO's claim): " + (", ".join(_text(r["handle"], 32) for r in devs[:LIST_CAP]) + " flagged as the dev" if devs
                                                         else "none of the listed traders is flagged as the dev; not proof the dev sold"))
        else:
            lines.append("  dev flag (FOMO's claim): not read (field missing)")
    lines += [f"  cannot see: {CANNOT_SEE}", f"  {PRESENTATION_NOTE}"]
    removed = pw.count(lines)
    if removed:  # HS-LABELS-T1: say how many placeholders this block shows
        lines.append(f"  {pw.removed_line(removed)}")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read which Fomo-tracked traders hold a Solana mint from Fomo API (an independent, unofficial API, "
                                                 "not affiliated with fomo.family; one call, 250 credits of the free key's 250,000 a month; bounded: "
                                                 f"2 MiB, 30 s, no redirects, no env proxy, at most one retry after a short 429) and save {OUT_FILE}; or, "
                                                 "with --present RUN_DIR, print the synthesis's Sources-read block offline. Presentation only: never "
                                                 "an engine input.")
    parser.add_argument("mint", nargs="?")
    parser.add_argument("--out", metavar="RUN_DIR", help="run folder to save the file into")
    parser.add_argument("--env-file", metavar="PATH", help=f"the repository .env ({KEY_NAME} in the environment is used first)")
    parser.add_argument("--present", metavar="RUN_DIR", help="offline: print the Sources-read block from a saved run folder (no network, no key)")
    args = parser.parse_args(argv)
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
    mint = args.mint
    if not isinstance(mint, str) or not SOLANA_ADDRESS_RE.fullmatch(mint):
        print("error: mint is not a valid base58 Solana address", file=sys.stderr)
        return 2
    if not args.out:
        print("error: --out is required", file=sys.stderr)
        return 2
    out = Path(args.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    try:
        key, reason = load_key(None if os.environ.get(KEY_NAME, "").strip() else find_env_file(args.env_file))
        result = collect_fomoapi(mint, key, key_reason=reason)
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
