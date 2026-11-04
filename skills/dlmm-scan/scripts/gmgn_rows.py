#!/usr/bin/env python3
"""GMGN top-100 holder rows for dlmm-scan (first-wave collector `gmgn_rows`): one bounded, read-only GMGN request.

SELF-CONTAINED COPY. The request construction and the row sanitizing below are a deliberate duplicate of
skills/lp-research-companion/scripts/lp_research/gmgn.py (collect_gmgn's request: the X-APIKEY header plus the
timestamp and client_id query fields; find_holder_list; allowed_tags with its MAKER_TAGS / GENERAL_TAGS allowlists; the
address, share, funder, funding-time, first-buy, wallet-creation and prior-transaction fields of sanitize_gmgn), so
dlmm-scan imports nothing from the sibling skill. Differences: the User-Agent; the transport guards (no environment
proxy, a hard wall-clock deadline per attempt, at most one retry after a documented rate limit, key-echo drops); rows keep the raw GMGN field names
(so the forensics GMGN adapter reads them exactly like a raw payload); and the run-folder files and command line.
tests/forensics/test_gmgn_rows.py compares request construction and row sanitizing with the sibling when it is present
in the checkout (skipped when it is not). Change both together.

Paid: every call costs GMGN rate-limit weight 5 (provider-docs cache, gmgn skills.md, "Rate Limit Handling"). It runs only
when the owner asks, once per token per scan.

Writes into --out (the run folder):
  gmgn_top100.json       status ok | empty | unavailable with a fixed reason code, the request facts (host, path, query
                         field names, auth header NAME; never a value), GMGN's tag claims with their supply shares, and
                         the rows under "list", limited to documented fields: address, amount_percentage (share of
                         supply, 0-1), tags, maker_token_tags, start_holding_at, native_transfer {from_address, amount,
                         timestamp, name} (name = GMGN's funder label, reduced to an inert label exactly as the
                         forensics adapter's safe_label does), created_at and prior_transaction_count when present,
                         and addr_type (DS-GMGN-POOLS-T1: the int 0 wallet, 1 burn or 2 DEX pool or exchange, else
                         null; the GMGN cohort pass of assess drops the rows marked 2)
  gmgn_acquisition.json  {wallet: start_holding_at}, valid unix seconds only; written only when the status is ok and at
                         least one row has a first-buy time (it feeds the acquisition-time check of the offline assess)
  gmgn_holder_pnl.json   HS-PNL-T1, PRESENTATION ONLY (never an assess input, never read by either engine): holder cost
                         and PnL per row, built from the SAME single response (no extra request). Status, reason and
                         fetched_at mirror gmgn_top100.json; the rows sit under "rows" (a key the forensics engine does
                         not read, so this file passed to assess by mistake is refused, exit 2) and are the same wallets
                         in the same order: address, amount_percentage, addr_type (2 = pool or exchange) and exchange (an inert label), GMGN's cost,
                         PnL, sold, balance and USD fields as validated finite numbers (anything else is null, never 0),
                         transfer_in (GMGN's transfer_in maker tag), app_tags (a fixed allowlist, APP_TAGS) and the
                         identity labels name / twitter_username / twitter_name (inert labels, verdict words replaced,
                         key echoes dropped). fields_missing names a field absent from every row (a renamed field).
gmgn_top100.json, gmgn_acquisition.json and the status line are byte-identical to what they were before HS-PNL-T1, apart
from the addr_type field DS-GMGN-POOLS-T1 adds to each gmgn_top100.json row.

Offline (synthesis): gmgn_rows.py --present <RUN> reads <RUN>/gmgn_holder_pnl.json (no network, no key) and prints
the "Holder cost and PnL (GMGN top 100, presentation only)" block; its first line is the executive-summary line. Right
after it, the same command prints the "Copy-trade cascade (presentation only)" section (HS-CASCADE-T1), read from the same
saved file and the skill's static, dated watchlist references/fomo_cascade_watchlist.json (read only; no network, no key):
watchlist traders holding 0.1% of supply or more, a count of those under it, named holders not on the list, the Fomo-app
wallet count and what it cannot see; its first line, when a listed trader holds 0.1% or more, is its executive-summary line.

Key: only GMGN_API_KEY, from the environment first, then exactly that one variable from the repository .env (single-variable
parser; the file is never sourced). It is sent only in the X-APIKEY header and is never printed, logged, saved or put
in an error: every failure becomes a fixed reason code. Provider text is untrusted: tags are kept only when they are
one of the documented tag names, the funder name is reduced to a short inert label, every other value is a validated
number, address or time.

A renamed load-bearing field is loud, never ok: rows with funding times but no readable native_transfer.from_address in
any row give unavailable (funder_field_missing), and rows with no start_holding_at in any row give unavailable
(first_buy_field_missing); in both cases no acquisition map is written (the cached docs name the funder field both
from_address and address, so it is never guessed). Every attempt has a hard wall-clock limit (TIMEOUT_S, worker thread).

Prints one line: ok (...), empty (...) or unavailable (<reason>; ...). Exit 0 whenever gmgn_top100.json was saved;
exit 2 for a bad mint or an unwritable --out. --present exits 0 (a missing or unreadable file prints "not read (...)");
exit 2 only for a bad --present command line. Standard library only; Python >= 3.10.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import math
import os
import queue
import re
import socket
import statistics
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable

GMGN_HOST = "openapi.gmgn.ai"
GMGN_HOLDERS_PATH = "/v1/market/token_top_holders"
CHAIN = "sol"
LIMIT = 100                      # GMGN's maximum for this route: the top 100 holders only
RATE_WEIGHT = 5                  # documented rate-limit weight of this route
MAX_BYTES = 5 * 1024 * 1024      # same cap as the sibling's MAX_PROVIDER_BYTES
TIMEOUT_S = 30.0                 # per attempt: a hard wall-clock limit on open + every read (worker thread), and the socket timeout
RETRY_MAX_WAIT_S = 5.0           # retry once only when the documented cooldown ends this soon (gmgn-cli's auto-retry bound)
RETRY_DEFAULT_WAIT_S = 2.0       # backoff when a 429 carries no reset time
ERROR_BODY_BYTES = 64 * 1024     # an error body is read only for its documented error code, then dropped
USER_AGENT = "holder-scan-gmgn-rows/1.0"
KEY_NAME = "GMGN_API_KEY"
KEY_RE = re.compile(r"^[\x21-\x7e]{8,512}$")  # printable, no spaces: a valid header value; the value is never echoed
KEY_PIECE = 8                    # provider text sharing this many consecutive characters with the key is dropped
SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
DECIMAL_RE = re.compile(r"^[0-9]{1,24}(?:\.[0-9]{1,24})?$")
LABEL_RE = re.compile(r"[^\w .\-]")  # the forensics adapter's LABEL_RE: letters, digits, _, space, dot and hyphen only
MIN_UNIX = 1_262_304_000         # 2010-01-01: older "times" are not real Solana activity
FUTURE_SLACK_S = 86_400
QUERY_FIELDS = ("chain", "address", "limit", "timestamp", "client_id")
AUTH_HEADER_NAMES = ("X-APIKEY",)
TOP100_FILE = "gmgn_top100.json"
ACQUISITION_FILE = "gmgn_acquisition.json"
PNL_FILE = "gmgn_holder_pnl.json"
SCHEMA = "holder-scan-gmgn-rows/1"
PNL_SCHEMA = "holder-scan-gmgn-holder-pnl/1"

# Documented tag values (provider-docs cache, gmgn skills.md); identical to the sibling's allowlists.
MAKER_TAGS = {"bundler", "rat_trader", "sniper", "whale", "top_holder", "transfer_in", "dev_team", "creator"}
GENERAL_TAGS = {"smart_degen", "pump_smart", "renowned", "fresh_wallet", "wash_trader", "kol"}
TAG_CLAIMS_NOTE = ("GMGN's own labels: claims, not proof. Its bundler tag can include app traders whose buys were routed in "
                   "bundles (for example Fomo); top 100 rows only, so every share is a floor of GMGN's view, never a total.")

# Documented GMGN error codes (gmgn skills.md, "Error Codes"); anything else is reduced to the HTTP status class.
DOCUMENTED_ERRORS = frozenset({
    "AUTH_KEY_INVALID", "AUTH_IP_BLOCKED", "AUTH_INVALID", "AUTH_SIGNATURE_INVALID", "AUTH_TIMESTAMP_EXPIRED",
    "AUTH_CLIENT_ID_REPLAYED", "AUTH_REPLAY_CHECK_UNAVAILABLE", "RATE_LIMIT_EXCEEDED", "RATE_LIMIT_BANNED",
    "RATE_LIMIT_BANNED_MAX", "PLAN_UPGRADE_REQUIRED", "CHAIN_NOT_SUPPORTED", "BAD_REQUEST", "INTERNAL_API_UNAVAILABLE",
})
RETRYABLE_RATE_LIMITS = frozenset({"RATE_LIMIT_EXCEEDED", "RATE_LIMIT_BANNED", None})  # never RATE_LIMIT_BANNED_MAX
HTTP_REASONS = {400: "bad_request", 401: "authentication_failed", 403: "access_denied", 404: "not_found", 429: "rate_limited"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect (returning None makes urllib raise the 3xx as an HTTPError)."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class Failure(Exception):
    """A failed attempt, reduced to a fixed reason code. Never carries request text, headers or the key."""

    def __init__(self, reason: str, http_status: int | None = None, retry_wait: float | None = None, reset_at: int | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status
        self.retry_wait = retry_wait
        self.reset_at = reset_at


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
    """(key, None) or (None, reason). Environment first, then exactly the one GMGN_API_KEY line of the .env; no other
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


# ----------------------------------------------------------------------------- request (same construction as the sibling)


def check_url(url: str) -> None:
    """https only, host openapi.gmgn.ai only, the holders path only, no port other than 443, no credentials in the URL."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise Failure("scheme_not_https")
    if parsed.hostname != GMGN_HOST or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise Failure("host_not_allowlisted")
    if parsed.path != GMGN_HOLDERS_PATH:
        raise Failure("path_not_allowlisted")


def build_request(mint: str, key: str, *, timestamp: int, client_id: str) -> urllib.request.Request:
    """GET /v1/market/token_top_holders?chain=sol&address=<mint>&limit=100&timestamp=<now>&client_id=<uuid4>, key in the
    X-APIKEY header: the same query, header names and header handling as the sibling's collect_gmgn (only the User-Agent
    differs). timestamp must be within GMGN's +-5 s window and client_id must be new for every attempt (anti-replay)."""
    query = {"chain": CHAIN, "address": mint, "limit": str(LIMIT), "timestamp": str(timestamp), "client_id": client_id}
    url = f"https://{GMGN_HOST}{GMGN_HOLDERS_PATH}?{urllib.parse.urlencode(query)}"
    check_url(url)
    request = urllib.request.Request(url, method="GET")
    request.headers["X-APIKEY"] = key  # set directly, as the sibling does, so the header keeps its exact name
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", USER_AGENT)
    return request


def default_opener() -> urllib.request.OpenerDirector:
    """No environment proxy (an explicit empty ProxyHandler), no redirects, default TLS verification."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value) and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,12}", value.strip()):
        return int(value.strip())
    return None


def _error_code(raw: bytes) -> tuple[str | None, int | None]:
    """The documented error code and reset_at of an error body (nothing else is kept)."""
    try:
        body = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None, None
    if not isinstance(body, dict):
        return None, None
    code = body.get("error")
    return (code if isinstance(code, str) and code in DOCUMENTED_ERRORS else None), _int_or_none(body.get("reset_at"))


def _http_failure(code: int, error: str | None) -> Failure:
    if error is not None:
        return Failure(error.lower(), code)
    if code in HTTP_REASONS:
        return Failure(HTTP_REASONS[code], code)
    return Failure("server_error" if 500 <= code <= 599 else "http_error", code)


def _rate_limited(exc: urllib.error.HTTPError, raw: bytes, now: Callable[[], float]) -> Failure:
    """A 429: retry once only for a documented request-frequency limit whose cooldown ends within RETRY_MAX_WAIT_S
    (X-RateLimit-Reset header or reset_at body field; RETRY_DEFAULT_WAIT_S when neither is given). RATE_LIMIT_BANNED_MAX
    is never retried: every request before reset_at restarts the 5-minute ban."""
    error, reset_body = _error_code(raw)
    reset_header = _int_or_none(exc.headers.get("X-RateLimit-Reset")) if getattr(exc, "headers", None) is not None else None
    reset = reset_body or reset_header
    reset = reset if reset is not None and MIN_UNIX <= reset <= now() + 3600 else None
    wait = max(0.5, reset - now() + 0.5) if reset is not None else RETRY_DEFAULT_WAIT_S
    retry = wait if (error in RETRYABLE_RATE_LIMITS and wait <= RETRY_MAX_WAIT_S) else None
    return Failure((error or "RATE_LIMITED").lower(), 429, retry_wait=retry, reset_at=reset)


def _bounded_call(function: Callable[[], Any], timeout: float) -> Any:
    """Run one blocking transport step (open, read, close) in a daemon worker and wait at most `timeout` seconds: a hard
    wall-clock bound, the same way solscanner_scan.py does it. A socket timeout alone restarts on every byte, so a
    server that drip-feeds bytes (or a stalled DNS or TLS step) could otherwise hold the collector far past the
    deadline. An abandoned step publishes nothing and cannot retry."""
    if timeout <= 0:
        raise TimeoutError
    result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def invoke() -> None:
        try:
            result.put((True, function()))
        except BaseException as exc:  # handed back to the bounded caller
            result.put((False, exc))

    worker = threading.Thread(target=invoke, name="gmgn-rows-transport", daemon=True)
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


def send_once(request: urllib.request.Request, opener: Any, *, now: Callable[[], float], monotonic: Callable[[], float]) -> bytes:
    """One attempt. Returns the body (at most MAX_BYTES) or raises Failure with a fixed code. Opening, every read and the
    error-body read run under one hard wall-clock deadline of TIMEOUT_S (_bounded_call), so the attempt ends by then
    whatever the server does."""
    check_url(request.full_url)
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
            raise _http_failure(status, None)
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
            try:
                raw = _bounded_call(lambda: exc.read(ERROR_BODY_BYTES), remaining())
            except Exception:  # noqa: BLE001 - the body is advisory only
                raw = b""
            raw = raw if isinstance(raw, bytes) else b""
            if exc.code == 429:
                raise _rate_limited(exc, raw, now) from None
            raise _http_failure(exc.code, _error_code(raw)[0]) from None
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


# ----------------------------------------------------------------------------- rows (same sanitizing as the sibling)


def find_holder_list(value: Any, depth: int = 0) -> list[dict[str, Any]] | None:
    """The holder list under holders / list / items / data / result (any depth up to 5); [] when empty, None when
    missing. Identical to the sibling's find_holder_list."""
    if depth > 5:
        return None
    if isinstance(value, list):
        if not value:
            return []
        if all(isinstance(item, dict) for item in value):
            return value
        return None
    if not isinstance(value, dict):
        return None
    for key in ("holders", "list", "items", "data", "result"):
        if key in value:
            found = find_holder_list(value[key], depth + 1)
            if found is not None:
                return found
    return None


def allowed_tags(holder: dict[str, Any]) -> tuple[list[str], list[str]]:
    """(maker_token_tags, tags), each kept only when it is a documented tag name, sorted and unique (the sibling's
    allowed_tags; non-string entries are skipped here instead of raising)."""
    maker = holder.get("maker_token_tags")
    general = holder.get("tags")
    return (
        sorted({t for t in maker if isinstance(t, str) and t in MAKER_TAGS}) if isinstance(maker, list) else [],
        sorted({t for t in general if isinstance(t, str) and t in GENERAL_TAGS}) if isinstance(general, list) else [],
    )


def _finite(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def share_fraction(value: Any) -> float | None:
    """Share of total supply as GMGN gives it (0-1), like the sibling's ratio(); anything else is unknown."""
    number = _finite(value)
    return number if number is not None and 0 <= number <= 1 else None


def unix_time(value: Any, now: float | None = None) -> int | None:
    """A plausible unix time in seconds (2010 to one day ahead), else None. GMGN uses 0 for unknown."""
    number = _finite(value)
    if number is None:
        return None
    ceiling = (time.time() if now is None else now) + FUTURE_SLACK_S
    return int(number) if MIN_UNIX <= number <= ceiling else None


def _amount(value: Any) -> str | float | None:
    """The funding amount keeps GMGN's type: a plain decimal string stays text (the forensics adapter reads numeric
    amounts only, so a raw payload and this file give identical cohorts), a finite non-negative number stays a number."""
    if isinstance(value, str):
        return value if DECIMAL_RE.fullmatch(value) else None
    number = _finite(value)
    return number if number is not None and number >= 0 and not isinstance(value, bool) else None


# SELF-CONTAINED COPY (HS-LABELS-T1): the block between the BEGIN and END lines below is a byte-identical copy of the
# shared verdict-word block of scripts/provider_words.py (this collector imports nothing from the skill, as the rest of
# this file); tests/forensics/test_provider_words.py fails when the two differ. Change both together.
# ---- BEGIN shared verdict-word block (gmgn_rows.py holds a byte-identical copy; test_provider_words.py checks it) --------
# ---- folding tables (moved here from helius_forensics.py by HS-LABELS-T1; that module imports them, unchanged) ----------
# HS-PROV-T2 (criterion 7): common Cyrillic / Greek / small-capital / Latin look-alikes mapped to Latin, and digits and signs
# used as letters. The presentation-only provider matcher (helius_forensics.presentation_only_provider) and the verdict-word
# rule below fold with exactly these tables.
_LOOKALIKE_PAIRS = ("АA ВB ЕE КK МM НH ОO РP СC ТT УY ХX ЅS ІI ЈJ Ӏl "
                    "ԚQ ԜW ҮY аa вb еe кk мm нh оo рp сc тt уy хx ѕs "
                    "іi јj ӏl ԁd ԛq ԝw үy ѵv ΑA ΒB ΕE ΖZ ΗH ΙI ΚK ΜM "
                    "ΝN ΟO ΡP ΤT ΥY ΧX αa βb γy εe ιi κk νv οo ρp τt "
                    "υu χx ωw ᴀa ʙb ᴄc ᴅd ᴇe ꜰf ɢg ʜh ɪi ᴊj ᴋk ʟl ᴍm "
                    "ɴn ᴏo ᴘp ʀr ꜱs ᴛt ᴜu ᴠv ᴡw ʏy ᴢz ıi łl øo đd ħh "
                    "ŧt ƒf ŁL ØO ĐD ĦH ŦT ɡg")
PROVIDER_LOOKALIKES = str.maketrans({pair[0]: pair[1] for pair in _LOOKALIKE_PAIRS.split()})
PROVIDER_LOOKALIKE_SIGNS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a", "|": "l", "!": "i"})

# ---- the rule ------------------------------------------------------------------------------------------------------------
PLACEHOLDER = "[provider word removed]"
VERDICT_WORDS = ("clean", "safe", "safer", "safest", "low", "legit", "safu")
VERDICT_PHRASES = (("low", "risk"), ("lowest", "risk"), ("no", "risk"), ("zero", "risk"), ("risk", "free"), ("rug", "free"), ("safe", "to", "buy"),
                   ("not", "a", "rug"), ("no", "rug"), ("rug", "proof"), ("no", "alarm"))
_MAX_SPAN_TOKENS = 24            # letters joined into one candidate word at most (a spaced-out phrase fits)
_MAX_JOINED = 64                 # longest joined candidate looked at (doubled letters included)
_DROPPED = frozenset({"Mn", "Me", "Cf"})  # accents and other combining marks, zero-width and other invisible format characters
_MARKER = re.compile(r"(\[provider word removed(?: x\d+)?\])")  # one placeholder, or several collapsed into one: "[provider word removed x3]"
_MARKER_RUN = re.compile(r"\[provider word removed(?: x\d+)?\](?:[^\w\[\]]*\[provider word removed(?: x\d+)?\])+")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]")  # bidi embedding, override, isolate and mark characters
# HTML element names (HTML living standard plus common obsolete ones): only these, comments and declarations are dropped as
# tags, so angle brackets in ordinary text stay ("bundle <5% and >2%", "C++ <dev>"); HS-LABELS-T1 review item N1
HTML_ELEMENTS = ("a abbr acronym address area article aside audio b base basefont bdi bdo big blink blockquote body br button "
                 "canvas caption center cite code col colgroup data datalist dd del details dfn dialog dir div dl dt em embed "
                 "fieldset figcaption figure font footer form frame frameset h1 h2 h3 h4 h5 h6 head header hgroup hr html i "
                 "iframe img input ins kbd label legend li link main map mark marquee math menu meta meter nav nobr noscript "
                 "object ol optgroup option output p param picture plaintext pre progress q rp rt ruby s samp script search "
                 "section select slot small source span strike strong style sub summary sup svg table tbody td template "
                 "textarea tfoot th thead time title tr track tt u ul var video wbr xmp").split()
# Dropped as a renderer drops them: comments, CDATA sections, and the HTML "bogus comments" ("<!x>", "<?x?>", "</ x>", "</>",
# all up to the next ">"); and HTML element tags, whose name follows "<" or "</" directly ("< b >" is text)
_TAG = re.compile(r"<!--.{0,500}?-->|<!\[CDATA\[.{0,500}?\]\]>|<![^>]{0,200}>|<\?[^>]{0,200}>|</(?![A-Za-z])[^>]{0,200}>"
                  r"|</?(?:" + "|".join(HTML_ELEMENTS) + r")(?=[\s/>])[^<>]{0,200}>", re.IGNORECASE | re.DOTALL)
# Any other tag-like text ("<dev>", "<x>", "<SAFE>") stays in the output, so the rule reads it both ways (repair R7): hidden
# (a renderer may hide it: "s<x></x>afe" reads as safe) and visible (a plain-text reader sees it: "<SAFE>" reads as SAFE)
_TAG_LIKE = re.compile(r"</?[A-Za-z][^<>]{0,200}>")
_MD_LINK = re.compile(r"\[([^\[\]]{0,200})\]\([^()]{0,500}\)")
# Two rare letters that every sanitizer's character rule keeps: while a sanitizer cuts, each placeholder is held as a run of
# one of them, as long as the text it replaced (cut()); a provider text cannot hold them (they read as "o")
_HOLD = ("\ua66d", "\ua66e")
_HOLD_RUN = re.compile("\ua66d+|\ua66e+")
GROWTH_LIMIT = 3 * len(PLACEHOLDER)  # a text is never longer than its cap plus this (three placeholders' worth)


def inert(text: str) -> str:
    """What the text says, without what changes how it renders: HTML entities decoded (twice, for "&amp;#65;"), HTML tags
    and comments dropped, markdown links reduced to their text, bidi controls dropped. Used before matching, on provider
    text only. Angle brackets that are not an HTML tag are kept."""
    text = html.unescape(html.unescape(text))
    while True:
        stripped = _MD_LINK.sub(r"\1", _TAG.sub("", text))
        if stripped == text:
            break
        text = stripped
    return _BIDI.sub("", text)


def _collapse(text: str) -> str:
    return re.sub(r"(.)\1+", r"\1", text)


def _signs_key(text: str) -> str:
    """The second pass also reads "rn" as m and a capital I (casefolded to i) as l, as the provider matcher does."""
    return text.replace("rn", "m").replace("i", "l")


def _targets(key: Callable[[str], str]) -> tuple[frozenset[str], frozenset[str]]:
    whole = {key(w) for w in VERDICT_WORDS} | {key("".join(p)) for p in VERDICT_PHRASES}
    return frozenset(whole), frozenset(_collapse(t) for t in whole)


_PASSES = {"plain": (lambda s: s, *_targets(lambda s: s)), "signs": (_signs_key, *_targets(_signs_key))}


def _folded(text: str, signs: bool, hide: bool) -> list[tuple[str, int]]:
    """(folded character, index in `text`) for every character that survives folding (tag-like text skipped when `hide`)."""
    hidden = {i for m in _TAG_LIKE.finditer(text) for i in range(m.start(), m.end())} if hide else set()
    out: list[tuple[str, int]] = []
    for i, ch in enumerate(text):
        if i in hidden:
            continue
        for part in unicodedata.normalize("NFKD", ch):
            if unicodedata.category(part) in _DROPPED:
                continue
            for c in part.translate(PROVIDER_LOOKALIKES).casefold().translate(PROVIDER_LOOKALIKES):
                out.append((c.translate(PROVIDER_LOOKALIKE_SIGNS) if signs else c, i))
    return out


def _tokens(text: str, signs: bool, hide: bool) -> list[tuple[str, int, int]]:
    """Runs of letters and digits after folding: (folded text, first index, end index) in `text`."""
    tokens: list[tuple[str, int, int]] = []
    word: list[str] = []
    start = end = 0
    for c, i in _folded(text, signs, hide):
        if c.isalnum():
            if not word:
                start = i
            word.append(c)
            end = i + 1
        elif word:
            tokens.append(("".join(word), start, end))
            word = []
    if word:
        tokens.append(("".join(word), start, end))
    return tokens


def _matches(text: str, signs: bool, hide: bool = False) -> list[tuple[int, int]]:
    """(start, end) ranges of `text` that hold a verdict word or phrase, for one folding pass."""
    key, whole, collapsed = _PASSES["signs" if signs else "plain"]
    tokens = _tokens(text, signs, hide)
    n = len(tokens)
    if not n:
        return []

    def is_target(joined: str, wanted: frozenset[str], wanted_collapsed: frozenset[str]) -> bool:
        k = key(joined)
        return k in wanted or _collapse(k) in wanted_collapsed

    def joinable(k: int) -> bool:
        """Tokens k and k+1 form one word: only signs between them (no space), or both are single spaced letters (a letter
        repeated, "rrr", counts as one letter)."""
        between = text[tokens[k][2]:tokens[k + 1][1]]
        tight = not any(ch.isspace() for ch in (_TAG_LIKE.sub("", between) if hide else between))
        return tight or (len(_collapse(tokens[k][0])) == 1 and len(_collapse(tokens[k + 1][0])) == 1)

    joins = [joinable(k) for k in range(n - 1)]
    words: dict[int, list[tuple[int, str]]] = {}  # start token -> [(end token, joined text)] of every candidate word
    found: list[tuple[int, int]] = []
    for i in range(n):
        joined = ""
        for j in range(i, min(n, i + _MAX_SPAN_TOKENS)):
            if j > i and not joins[j - 1]:
                break
            joined += tokens[j][0]
            if len(joined) > _MAX_JOINED:
                break
            words.setdefault(i, []).append((j, joined))
            if is_target(joined, whole, collapsed):
                found.append((tokens[i][1], tokens[j][2]))
    for phrase in VERDICT_PHRASES:  # word by word, any separators between the words
        wanted = [(frozenset({key(w)}), frozenset({_collapse(key(w))})) for w in phrase]

        def ends(start: int, index: int) -> list[int]:
            if index == len(phrase):
                return [start - 1]
            out: list[int] = []
            for j, joined in words.get(start, []):
                if is_target(joined, *wanted[index]):
                    out += ends(j + 1, index + 1)
            return out

        for i in range(n):
            for last in ends(i, 0):
                found.append((tokens[i][1], tokens[last][2]))
    return found


def marker(n: int) -> str:
    """The placeholder for n removed words or phrases in a row."""
    return PLACEHOLDER if n == 1 else f"[provider word removed x{n}]"


def _marker_count(text: str) -> int:
    found = re.fullmatch(r"\[provider word removed(?: x(\d+))?\]", text)
    return int(found.group(1)) if found and found.group(1) else 1


def _spans(piece: str) -> list[list[int]]:
    """Every verdict word or phrase in `piece` as [start, end], overlapping ones merged."""
    merged: list[list[int]] = []
    hides = (False, True) if _TAG_LIKE.search(piece) else (False,)  # without tag-like text the two readings are the same
    found = [span for signs in (False, True) for hide in hides for span in _matches(piece, signs, hide)]  # every reading
    for start, end in sorted(set(found)):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def _replace(text: str) -> tuple[list[str], list[str | None]]:
    """The text made inert with every verdict word or phrase replaced, as pieces: provider text at even and placeholders
    at odd indices; and for each placeholder the text it replaced (None for a placeholder already in the text)."""
    out, replaced = [""], []
    for k, part in enumerate(_MARKER.split(text)):
        if k % 2:
            out += [part, ""]
            replaced.append(None)
            continue
        piece, at = inert(part), 0
        for start, end in _spans(piece):
            out[-1] += piece[at:start]
            out += [PLACEHOLDER, ""]
            replaced.append(piece[start:end])
            at = end
        out[-1] += piece[at:]
    return out, replaced


def neutralize(text: Any) -> tuple[Any, int]:
    """(text made inert, with every verdict word or phrase replaced by PLACEHOLDER, how many were replaced). A placeholder
    already in the text is kept as it is (so the rule can run twice); anything that is not a string is returned unchanged."""
    if not isinstance(text, str) or not text:
        return text, 0
    pieces, replaced = _replace(text)
    return "".join(pieces), sum(1 for r in replaced if r is not None)


def collapse(text: str) -> str:
    """Placeholders separated only by spaces or signs become one counted placeholder ("[provider word removed x3]")."""
    return _MARKER_RUN.sub(lambda m: marker(sum(_marker_count(x) for x in _MARKER.findall(m.group(0)))), text)


def fit(text: str, cap: int) -> str:
    """The text with its placeholders collapsed and, when it is longer than `cap`, the last words of provider text dropped
    (never a placeholder) until it fits; if only placeholders are left and they still do not fit, one counted placeholder
    (the shortest honest form). A text without a placeholder is returned as it is. Used for the growth limit only: the
    normal cut is cut()'s, where the old rule cut."""
    text = collapse(text)
    if len(text) <= cap or not _MARKER.search(text):
        return text
    total = sum(_marker_count(x) for x in _MARKER.findall(text))
    parts = _MARKER.split(text)
    while len(collapse("".join(parts)).strip()) > cap:
        k = next((i for i in range(len(parts) - 1, -1, -2) if parts[i].strip()), None)
        if k is None:
            break
        last = re.search(r"\S+\s*$", parts[k])
        parts[k] = parts[k][:last.start()]
    text = collapse("".join(parts)).strip()
    return text if len(text) <= cap else marker(total)


def neutral(text: Any) -> Any:
    """neutralize() without the count, placeholders in a row collapsed; for text that is already cut (a saved label) or
    was never cut. Never longer than the text plus GROWTH_LIMIT."""
    out, _ = neutralize(text)
    if not isinstance(out, str) or not _MARKER.search(out):
        return out
    return fit(collapse(out), len(text) + GROWTH_LIMIT)


def cut(value: str, clean: Callable[[str], str], cap: int, trim: bool = True) -> str:
    """Cut like the old rule, then mark (HS-LABELS-T1 B2). The old rule of a sanitizer was clean(value)[:cap], stripped
    when `trim`. Here the rule runs on the raw text first (a spelling that uses signs `clean` drops, "$ a f e", is caught
    before they go); each placeholder is held as a run of one hold letter as long as clean() keeps of the text it replaced
    (a placeholder already in the text: one letter), so the old rule cuts where it cut; the runs become placeholders again,
    the rule runs once more (a cut or a dropped sign can make a word: "Lowell" cut to "Low"), placeholders in a row are
    collapsed. The result is longer than `cap` only by the placeholders' extra length, never by more than GROWTH_LIMIT.
    Without a verdict word, HTML tag, entity, markdown link or bidi control it is the old rule exactly."""
    pieces, replaced = _replace(value)
    held: list[str] = []
    for k, piece in enumerate(pieces):
        if k % 2 == 0:
            held.append(piece.replace(_HOLD[0], "o").replace(_HOLD[1], "o"))
        else:
            size = 1 if replaced[k // 2] is None else max(1, len(clean(replaced[k // 2])))
            held.append(_HOLD[(k // 2) % 2] * size)  # neighbouring placeholders alternate letters: their runs stay apart
    text = clean("".join(held))[:cap]
    text = text.strip() if trim else text
    marks = iter(pieces[1::2])
    text = _HOLD_RUN.sub(lambda m: next(marks, PLACEHOLDER), text)
    text = fit(collapse(neutralize(text)[0]), cap + GROWTH_LIMIT)
    return text.strip() if trim else text


def label(value: Any, strip: re.Pattern[str] | Callable[[str], str], cap: int = 32) -> str | None:
    """A short inert label: cut() with `strip` (a pattern of the characters a label cannot hold, or a function that drops
    them) as the character rule. None for anything that is not non-blank text. A label that is already safe comes back
    unchanged, so a saved label read back gives the same label. Without a verdict word, HTML tag, entity, markdown link or
    bidi control the result is the old rule exactly: strip(value)[:cap].strip()."""
    if not isinstance(value, str) or not value.strip():
        return None
    drop = strip if callable(strip) else (lambda s: strip.sub("", s))  # a compiled pattern is not callable
    return cut(value, drop, cap) or None
# ---- END shared verdict-word block ---------------------------------------------------------------------------------------


def safe_label(value: Any, key: str | None = None) -> str | None:
    """GMGN's funder name (native_transfer.name, for example "Binance") as a short inert label: the same rule as
    helius_forensics.safe_label (LABEL_RE, 32 characters, verdict words replaced by the placeholder: the copied block above,
    HS-LABELS-T1), so the adapter reads the same label as from a raw payload. With `key` given, None when the raw text or
    the label echoes the key (echoes_key); without it, unchanged."""
    if not isinstance(value, str) or not value.strip() or echoes_key(value, key) or echoes_key(LABEL_RE.sub("", value), key):
        return None  # the old character-only label is checked too (HS-LABELS-T1: dropping HTML first must never let an echo through)
    name = label(value, LABEL_RE)
    return None if echoes_key(name, key) else name


def _count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    if value < 0 or int(value) != value:
        return None
    return int(value)


def shares_key_piece(text: Any, key: str | None) -> bool:
    """True when `text` and the key share any run of KEY_PIECE (8) or more consecutive characters, in either direction
    (a shared run of 8+ characters always contains a shared run of exactly 8, so one scan over the key's windows covers
    both directions)."""
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


def sanitize_rows(holders: list[dict[str, Any]], now: float | None = None, key: str | None = None) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Rows limited to documented fields, raw GMGN names kept. Invalid addresses and duplicates are dropped (first row
    kept), then the list is cut to LIMIT, as the sibling does. With `key` given, nothing the provider sent can carry the
    key back out: a row whose address shares an 8+ character run with the key is dropped, such a funder address becomes
    None, and a funder name whose raw text or label echoes the key becomes None (echoes_key). DS-GMGN-POOLS-T1: every
    row keeps GMGN's addr_type (0 = wallet, 1 = burn/dead, 2 = DEX pool or exchange) when it is the int 0, 1 or 2 (the
    _addr_type rule: never a bool, text or float), else None, so the forensics GMGN cohort pass can drop GMGN-marked
    pools; it is GMGN's claim, never proof, and the only field added. Returns (rows, dropped counts)."""
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    dropped = {"invalid_address": 0, "duplicate": 0, "over_limit": 0, "key_echo": 0}
    for holder in holders:
        address = holder.get("address")
        if not isinstance(address, str) or not SOLANA_ADDRESS_RE.fullmatch(address):
            dropped["invalid_address"] += 1
            continue
        if echoes_key(address, key):
            dropped["key_echo"] += 1
            continue
        if address in seen:
            dropped["duplicate"] += 1
            continue
        seen.add(address)
        maker, general = allowed_tags(holder)
        addr_type = _addr_type(holder.get("addr_type"))
        row: dict[str, Any] = {
            "address": address,
            "amount_percentage": share_fraction(holder.get("amount_percentage")),
            "addr_type": addr_type if addr_type in (0, 1, 2) else None,
            "tags": general,
            "maker_token_tags": maker,
            "start_holding_at": unix_time(holder.get("start_holding_at"), now),
        }
        nt = holder.get("native_transfer")
        if isinstance(nt, dict):
            funder = nt.get("from_address")
            row["native_transfer"] = {
                "from_address": funder if isinstance(funder, str) and SOLANA_ADDRESS_RE.fullmatch(funder) and not echoes_key(funder, key) else None,
                "amount": _amount(nt.get("amount")),
                "timestamp": unix_time(nt.get("timestamp"), now),
                "name": safe_label(nt.get("name"), key),
            }
        created = unix_time(holder.get("created_at"), now)
        if created is not None:
            row["created_at"] = created
        prior = _count(holder.get("prior_transaction_count"))
        if prior is not None:
            row["prior_transaction_count"] = prior
        rows.append(row)
    dropped["over_limit"] = max(0, len(rows) - LIMIT)
    return rows[:LIMIT], dropped


def tag_claims(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Wallets and supply share (percent of total supply, GMGN's own share figure) per GMGN tag, as GMGN's claims."""
    out: dict[str, Any] = {"note": TAG_CLAIMS_NOTE, "maker_token_tags": {}, "tags": {}}
    for field in ("maker_token_tags", "tags"):
        buckets: dict[str, dict[str, Any]] = {}
        for row in rows:
            for tag in row[field]:
                b = buckets.setdefault(tag, {"wallets": 0, "share_pct": 0.0, "share_unknown_wallets": 0})
                b["wallets"] += 1
                if row["amount_percentage"] is None:
                    b["share_unknown_wallets"] += 1
                else:
                    b["share_pct"] += row["amount_percentage"] * 100
        out[field] = {t: b | {"share_pct": round(b["share_pct"], 4)} for t, b in sorted(buckets.items(), key=lambda kv: (-kv[1]["share_pct"], kv[0]))}
    return out


def acquisition_map(rows: list[dict[str, Any]], now: float | None = None) -> dict[str, int]:
    """{wallet: start_holding_at} for rows with a valid first-buy time (the --acquisition-json shape of assess)."""
    out = {}
    for r in rows:
        value = r.get("start_holding_at")
        if isinstance(value, int) and not isinstance(value, bool) and unix_time(value, now) == value:
            out[r["address"]] = value
    return out


# ----------------------------------------------------------------------------- holder cost and PnL (HS-PNL-T1, presentation only)
# Built from the same raw rows sanitize_rows read (one response, no extra request), into its own file: gmgn_top100.json is
# an assess input and sanitize_rows is held in parity with the sibling, so HS-PNL-T1 touched neither (DS-GMGN-POOLS-T1
# later added addr_type to sanitize_rows; the parity fields are unchanged). Field meanings: the cached
# gmgn-skills docs (gmgn-token skill, "Cost & P&L", "Identity & Holdings", "Wallet Identity"); all money is USD.

POOL_ADDR_TYPE = 2               # GMGN addr_type: 0 = wallet, 1 = burn/dead, 2 = DEX pool or exchange
# value bounds (low, high; None = open): a value outside them, text, a bool, NaN or inf is None, never 0
PNL_NUMBER_FIELDS: dict[str, tuple[float | None, float | None]] = {
    "avg_cost": (0.0, None), "avg_sold": (0.0, None),
    "unrealized_pnl": (-1.0, None),          # a ratio: 0.5 = +50%; GMGN's own basis, used as given (never recomputed)
    "unrealized_profit": (None, None), "realized_profit": (None, None), "profit": (None, None),
    "total_cost": (0.0, None), "history_bought_cost": (0.0, None), "history_sold_income": (0.0, None),
    "buy_amount_cur": (0.0, None), "sell_amount_cur": (0.0, None),
    "sell_amount_percentage": (0.0, 1.0),    # share of the bought tokens sold, 0-1
    "balance": (0.0, None), "usd_value": (0.0, None),
}
PNL_IDENTITY_FIELDS = ("name", "twitter_username", "twitter_name")
# Fields the printed block relies on: when one is absent from every row (a renamed field) the block reads "not read
# (field missing: ...)", never a count of zeros.
PNL_BLOCK_FIELDS = ("amount_percentage", "addr_type", "balance", "usd_value", "avg_cost", "unrealized_pnl", "sell_amount_percentage")
PNL_TRACKED_FIELDS = ("amount_percentage", "addr_type", "exchange", *PNL_NUMBER_FIELDS, *PNL_IDENTITY_FIELDS)
# GMGN `tags` values kept as app tags (a fixed allowlist; anything else is dropped), with the source of each name:
# the cached gmgn-skills docs (gmgn-token skill: its dex_bot tag covers "Axiom, Photon, BullX, Trojan, GMGN, Drops, PepeBoost,
# Padre" and its `tags` example is ["axiom"]; gmgn-holder-analysis skill: app-routed buys carry a `fomo` frontend tag or a
# `gmgn` tag) and the YMB answer of 2026-10-24 (tests/forensics/fixtures/ymb_gmgn_top100_live_20261024.json: fomo 42 rows,
# gmgn 14, axiom 11, padre 5, trojan 4, photon 3, kol 3). `kol` is GMGN's documented key-opinion-leader tag, not an app.
APP_TAGS = {
    "fomo": "gmgn-holder-analysis skill (fomo frontend tag); YMB 2026-10-24",
    "axiom": "gmgn-token skill (dex_bot list, tags example); YMB 2026-10-24",
    "photon": "gmgn-token skill (dex_bot list); YMB 2026-10-24",
    "gmgn": "gmgn-token skill (dex_bot list); gmgn-holder-analysis skill; YMB 2026-10-24",
    "trojan": "gmgn-token skill (dex_bot list); YMB 2026-10-24",
    "padre": "gmgn-token skill (dex_bot list); YMB 2026-10-24",
    "bullx": "gmgn-token skill (dex_bot list); not seen on YMB",
    "kol": "documented GMGN tag (GENERAL_TAGS); YMB 2026-10-24",
}
PNL_NOTE = ("presentation only: GMGN's own cost and PnL numbers in USD from the same single response as gmgn_top100.json, not "
            "on-chain proof; never an engine input, never passed to assess, never changes a FLAG, verdict or threshold")


def _bounded(value: Any, low: float | None, high: float | None) -> float | None:
    """A finite JSON number within [low, high] as a float; text, a bool, NaN, inf, a huge integer or a value outside the
    bounds is None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    if not math.isfinite(number) or (low is not None and number < low) or (high is not None and number > high):
        return None
    return number


def _pnl_number(value: Any, field: str) -> float | None:
    """A GMGN cost / PnL / sold / balance / USD value as a finite number within its bounds, else None (never 0)."""
    return _bounded(value, *PNL_NUMBER_FIELDS[field])


def _addr_type(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255 else None


def pnl_row(holder: dict[str, Any], key: str | None = None) -> dict[str, Any]:
    """One row of gmgn_holder_pnl.json: validated numbers only, GMGN's names kept; text only as inert labels (safe_label:
    verdict words replaced, key echoes dropped); app tags only from APP_TAGS; transfer_in from GMGN's maker tag only (its
    history_transfer_in_amount carries dust sprays)."""
    addr_type = _addr_type(holder.get("addr_type"))
    maker, general = holder.get("maker_token_tags"), holder.get("tags")
    row: dict[str, Any] = {"address": holder["address"], "amount_percentage": share_fraction(holder.get("amount_percentage")),
                           "addr_type": addr_type, "pool": addr_type == POOL_ADDR_TYPE, "exchange": safe_label(holder.get("exchange"), key)}
    row.update({field: _pnl_number(holder.get(field), field) for field in PNL_NUMBER_FIELDS})
    row["transfer_in"] = isinstance(maker, list) and any(isinstance(t, str) and t == "transfer_in" for t in maker)
    row["app_tags"] = sorted({t for t in general if isinstance(t, str) and t in APP_TAGS}) if isinstance(general, list) else []
    row.update({field: safe_label(holder.get(field), key) for field in PNL_IDENTITY_FIELDS})
    return row


def holder_pnl(result: dict[str, Any], holders: list[Any], key: str | None = None) -> dict[str, Any]:
    """gmgn_holder_pnl.json for one collect: status, reason and fetched_at mirror gmgn_top100.json (`result`); with status
    ok, one row per wallet kept in result["list"] (same order; the first raw row of each address, as sanitize_rows keeps
    it), built from the raw rows of the same response, under "rows": the forensics engine reads holder rows only under
    body / list / holders / data / items, so this file passed to assess by mistake is refused. Never changes `result`."""
    out: dict[str, Any] = {
        "schema": PNL_SCHEMA, "provider": "GMGN", "mint": result.get("mint"), "chain": CHAIN, "status": result.get("status"),
        "reason": result.get("reason"), "fetched_at": result.get("fetched_at"), "source_file": TOP100_FILE, "presentation_only": True,
        "note": PNL_NOTE, "money": "USD", "app_tag_allowlist": sorted(APP_TAGS), "fields_missing": [], "rows_read": 0, "rows": [],
    }
    if result.get("status") != "ok":
        return out
    kept = {r["address"] for r in result.get("list") or []}
    seen: set[str] = set()
    raw: list[dict[str, Any]] = []
    for holder in holders:
        address = holder.get("address") if isinstance(holder, dict) else None
        if isinstance(address, str) and address in kept and address not in seen:
            seen.add(address)
            raw.append(holder)
    out["fields_missing"] = [field for field in PNL_TRACKED_FIELDS if not any(field in holder for holder in raw)]
    out["rows"] = [pnl_row(holder, key) for holder in raw]
    out["rows_read"] = len(out["rows"])
    return out


# ----------------------------------------------------------------------------- collect (one call, at most one retry)


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _base(mint: str, fetched_at: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "provider": "GMGN", "mint": mint, "chain": CHAIN, "status": "unavailable", "reason": None, "http_status": None,
        "fetched_at": fetched_at,
        "request": {"method": "GET", "host": GMGN_HOST, "path": GMGN_HOLDERS_PATH, "query_fields": list(QUERY_FIELDS), "limit": LIMIT,
                    "auth_header_names": list(AUTH_HEADER_NAMES), "rate_weight": RATE_WEIGHT, "attempts": 0},
        "rows_read": 0, "with_start_holding_at": 0, "with_funding_time": 0, "rows_dropped": None, "rate_limit_reset_at": None,
        "tag_claims": None, "list": [],
    }


def collect_gmgn_rows(
    mint: str,
    key: str | None,
    *,
    key_reason: str | None = None,
    opener: Any | None = None,
    now: Callable[[], float] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
    new_client_id: Callable[[], str] | None = None,
    raw_holders: list[Any] | None = None,
) -> dict[str, Any]:
    """Exactly one GMGN request, plus at most one retry after a documented short rate limit (fresh timestamp and
    client_id). Returns the gmgn_top100.json result; never raises for provider or transport failures. With `raw_holders`
    (a list), the raw holder rows of that same response are appended to it for gmgn_holder_pnl.json (HS-PNL-T1); the
    request, the attempts and the result are the same with or without it."""
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    new_client_id = new_client_id or (lambda: str(uuid.uuid4()))
    result = _base(mint, _iso(now()))
    if not key:
        result["reason"] = key_reason or "missing_key"
        return result
    transport = opener or default_opener()
    body = None
    for attempt in (1, 2):
        result["request"]["attempts"] = attempt
        try:
            body = send_once(build_request(mint, key, timestamp=int(now()), client_id=new_client_id()), transport, now=now, monotonic=monotonic)
            break
        except Failure as failure:
            result.update(reason=failure.reason, http_status=failure.http_status, rate_limit_reset_at=failure.reset_at)
            if attempt == 1 and failure.retry_wait is not None:
                sleep(failure.retry_wait)
                continue
            return result
        except Exception:  # noqa: BLE001 - defensive: no exception text leaves this function
            result.update(reason="request_failed", http_status=None)
            return result
    result.update(reason=None, http_status=200, rate_limit_reset_at=None, fetched_at=_iso(now()))
    try:
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError, AttributeError):
        result["reason"] = "invalid_json"
        return result
    holders = find_holder_list(payload)
    if holders is None:
        result["reason"] = "holder_list_missing"
        return result
    if not holders:
        result["status"] = "empty"  # unknown, never read as "no holders"
        result["reason"] = "holder_list_empty"
        return result
    if raw_holders is not None:
        raw_holders.extend(holders)
    rows, dropped = sanitize_rows(holders, now(), key)
    result["rows_dropped"] = dropped
    if not rows:
        result["reason"] = "no_valid_holder_rows"  # a non-empty list with no usable row means the format changed
        return result
    # A renamed load-bearing field must be loud, never "ok". The cached docs name the funder field both
    # native_transfer.from_address and native_transfer.address: rows with funding times but no readable funder anywhere
    # would turn a multi-funder farm into "a single funder fed all wallets" (a calmer cohort). Rows without any first-buy
    # time would silently drop the acquisition-time check, the reason this collector exists. Partial gaps stay ok.
    funded = [r for r in rows if (r.get("native_transfer") or {}).get("timestamp") is not None]
    if funded and not any((r.get("native_transfer") or {}).get("from_address") for r in rows):
        result["reason"] = "funder_field_missing"
        return result
    if not any(r["start_holding_at"] is not None for r in rows):
        result["reason"] = "first_buy_field_missing"
        return result
    result.update(
        status="ok",
        rows_read=len(rows),
        with_start_holding_at=sum(1 for r in rows if r["start_holding_at"] is not None),
        with_funding_time=sum(1 for r in rows if (r.get("native_transfer") or {}).get("timestamp") is not None),
        tag_claims=tag_claims(rows),
        list=rows,
    )
    return result


def status_line(result: dict[str, Any], acquisition_written: int | None) -> str:
    calls = result["request"]["attempts"]
    call_text = f"{calls} GMGN call{'s' if calls != 1 else ''}, weight {RATE_WEIGHT} each" if calls else "no GMGN call sent"
    if result["status"] == "ok":
        acq = f"acquisition map: {acquisition_written} wallets" if acquisition_written else "no first-buy times, acquisition map not written"
        return f"ok ({result['rows_read']} rows; {result['with_start_holding_at']} with a first-buy time; {acq}; {call_text})"
    if result["status"] == "empty":
        return f"empty (GMGN returned an empty holder list: unknown, not a reassurance; {call_text})"
    return f"unavailable ({result['reason']}; {call_text})"


# ----------------------------------------------------------------------------- presentation (synthesis, offline; HS-PNL-T1)


WIB = dt.timezone(dt.timedelta(hours=7))
PNL_TITLE = "Holder cost and PnL (GMGN top 100, presentation only)"
PNL_SUMMARY_MARK = "[for the executive summary] "
PNL_SUMMARY_HEAD = "Holder PnL (GMGN top 100, presentation only)"
PNL_TOP_N = 20
PNL_NAMED_CAP = 20
PNL_SPREAD = 0.01                # a price or supply spread over 1% across the rows is stated; the median is used
PNL_PRESENTATION_LINE = "presentation only: never an engine input, never passed to assess, never changes a FLAG, verdict or threshold"
REASON_RE = re.compile(r"[^a-z0-9_]")


class NotRead(Exception):
    """The block cannot be shown; the reason is printed as "not read (<reason>)"."""


def count_removed(texts: list[Any]) -> int:
    """How many provider words the lines show as removed (provider_words.count; this file imports nothing from the skill)."""
    return sum(_marker_count(m) for t in texts if isinstance(t, str) for m in _MARKER.findall(t))


def removed_line(n: int) -> str:
    """The counted line every --present block adds when it shows a placeholder (the text of provider_words.removed_line)."""
    return (f"Provider words removed: {n} (shown as {PLACEHOLDER}, several in a row as [provider word removed xN]: a provider's own "
            "word or phrase that could read as a verdict, removed under this skill's rule; it is the provider's text, never this tool's verdict)")


def _reason(value: Any) -> str:
    """A reason code read back from the saved file: lower-case letters, digits and _ only."""
    return (REASON_RE.sub("", value.lower())[:64] if isinstance(value, str) else "") or "unknown"


def _saved_label(value: Any) -> str | None:
    """A label read back from the saved file, through the rule again (a saved label comes back unchanged)."""
    return label(value, LABEL_RE) if isinstance(value, str) else None


def _when(value: Any) -> str:
    try:
        utc = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return "time unknown"
    return f"{utc:%Y-%m-%d %H:%M} UTC = {utc.astimezone(WIB):%Y-%m-%d %H:%M} WIB"


def _usd(value: float) -> str:
    """Three significant digits with k / M / B ("$1.28M", "$549k")."""
    value = float(f"{value:.3g}")
    for scale, suffix in ((1e9, "B"), (1e6, "M"), (1e3, "k")):
        if abs(value) >= scale:
            return f"${value / scale:.3g}{suffix}"
    return f"${value:.3g}"


def _price(value: float) -> str:
    """A token price with three significant digits and no exponent ("$0.000551")."""
    return f"${value:.{max(2, 2 - math.floor(math.log10(value)))}f}" if value > 0 else "$0"


def _pct(value: float) -> str:
    return f"{value:.2f}%"


def _wallets(n: int) -> str:
    return f"{n} wallet{'' if n == 1 else 's'}"


def _share_pct(rows: list[dict[str, Any]]) -> float:
    return sum(r["share"] for r in rows if r["share"] is not None) * 100


def _saved_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    """The saved rows, every value validated again (the file can be edited or damaged): a row without a valid address or a
    repeated address is skipped; a malformed number is None (never 0); labels go through the rule again."""
    rows, seen = [], set()
    items = data.get("rows")
    for r in items if isinstance(items, list) else []:
        address = r.get("address") if isinstance(r, dict) else None
        if not isinstance(address, str) or not SOLANA_ADDRESS_RE.fullmatch(address) or address in seen:
            continue
        seen.add(address)
        tags = r.get("app_tags")
        row: dict[str, Any] = {"address": address, "share": _bounded(r.get("amount_percentage"), 0.0, 1.0),
                               "pool": _addr_type(r.get("addr_type")) == POOL_ADDR_TYPE, "exchange": _saved_label(r.get("exchange")),
                               "transfer_in": r.get("transfer_in") is True,
                               "app_tags": sorted({t for t in tags if isinstance(t, str) and t in APP_TAGS}) if isinstance(tags, list) else []}
        row.update({field: _pnl_number(r.get(field), field) for field in PNL_NUMBER_FIELDS})
        row.update({field: _saved_label(r.get(field)) for field in PNL_IDENTITY_FIELDS})
        rows.append(row)
    return rows


def _median_or_spread(values: list[float]) -> tuple[float, float]:
    """(median, spread) where spread = (max - min) / median."""
    middle = statistics.median(values)
    return middle, (max(values) - min(values)) / middle


def _who(r: dict[str, Any]) -> str:
    name = r["name"] or r["twitter_name"]
    handle = f"@{r['twitter_username']}" if r["twitter_username"] else None
    if name and handle:
        return f" {name} ({handle})"
    return f" {name or handle}" if (name or handle) else ""


def _holder_line(rank: int, r: dict[str, Any], supply: float | None) -> str:
    pnl = r["unrealized_pnl"]
    has_basis = (r["avg_cost"] or 0) > 0 or pnl is not None
    parts = [f"{_pct(r['share'] * 100)} of supply" if r["share"] is not None else "share unknown",
             f"unrealized PnL {pnl * 100:+.1f}%" if pnl is not None else ("unrealized PnL not given by GMGN" if has_basis else "no cost basis"),
             f"sold {r['sell_amount_percentage'] * 100:.0f}%" if r["sell_amount_percentage"] is not None else "sold n/a",
             (f"entry {_usd(r['avg_cost'] * supply)}" if supply else "entry n/a (supply not read)") if (r["avg_cost"] or 0) > 0 else "entry n/a (no average buy)"]
    text = f"    #{rank} {r['address']}{_who(r)}: " + ", ".join(parts)
    if r["app_tags"]:
        text += "; GMGN tags: " + ", ".join(r["app_tags"])
    if r["transfer_in"]:
        text += "; transfer_in (GMGN tag): the cost basis may not cover transferred tokens"
    return text


def pnl_block(data: dict[str, Any]) -> tuple[str, list[str]]:
    """(executive-summary text, block lines) from a saved gmgn_holder_pnl.json with status ok. Raises NotRead when a field
    the block relies on is missing from every row or no wallet row is left."""
    missing = data.get("fields_missing")
    if not isinstance(missing, list) or not all(isinstance(f, str) for f in missing):
        raise NotRead(f"{PNL_FILE} unreadable")
    gone = [f for f in PNL_BLOCK_FIELDS if f in missing]
    if gone:
        raise NotRead("field missing: " + ", ".join(gone))
    rows = _saved_rows(data)
    pools = [r for r in rows if r["pool"]]
    wallets = [r for r in rows if not r["pool"]]
    if not wallets:
        raise NotRead("no wallet rows after removing pools")
    exchanges: dict[str, int] = {}
    for r in pools:
        exchanges[r["exchange"] or "unnamed"] = exchanges.get(r["exchange"] or "unnamed", 0) + 1
    pool_names = ", ".join(f"{name} {n}" for name, n in sorted(exchanges.items(), key=lambda kv: (-kv[1], kv[0])))
    no_share = sum(1 for r in rows if r["share"] is None)
    top_share = _share_pct(rows)
    lines = [f"  coverage: GMGN snapshot {_when(data.get('fetched_at'))}; {len(rows)} rows read; {len(pools)} pool{'' if len(pools) == 1 else 's'} removed "
             f"(addr_type 2{': ' + pool_names if pools else ''}), {_pct(_share_pct(pools))} of supply; {_wallets(len(wallets))} left, "
             f"{_pct(_share_pct(wallets))} of supply; top 100 = {_pct(top_share)} of supply"
             + (f" ({no_share} rows without a share)" if no_share else "") + "; USD; GMGN's own numbers, not on-chain proof"]

    def basis(r: dict[str, Any]) -> bool:  # GMGN's own rule: an average buy above 0, or an unrealized PnL
        return (r["avg_cost"] or 0) > 0 or r["unrealized_pnl"] is not None

    red = [r for r in wallets if r["unrealized_pnl"] is not None and r["unrealized_pnl"] < 0]
    green = [r for r in wallets if r["unrealized_pnl"] is not None and r["unrealized_pnl"] >= 0]
    basis_no_pnl = [r for r in wallets if basis(r) and r["unrealized_pnl"] is None]
    no_basis = [r for r in wallets if not basis(r)]
    split = [f"in the red: {_wallets(len(red))}, {_pct(_share_pct(red))} of supply",
             f"in the green (unrealized PnL 0% or more): {_wallets(len(green))}, {_pct(_share_pct(green))} of supply",
             f"no cost basis: {_wallets(len(no_basis))}, {_pct(_share_pct(no_basis))} of supply"]
    if basis_no_pnl:
        split.append(f"cost basis but no unrealized PnL from GMGN: {_wallets(len(basis_no_pnl))}, {_pct(_share_pct(basis_no_pnl))} of supply")
    lines.append("  " + " | ".join(split))
    with_pnl = red + green
    if with_pnl:
        weighed = [r for r in with_pnl if r["share"]]
        weighted = (f"supply-weighted {sum(r['unrealized_pnl'] * r['share'] for r in weighed) / sum(r['share'] for r in weighed) * 100:+.1f}%"
                    if weighed else "supply-weighted not read (no share)")
        lines.append(f"  unrealized PnL (GMGN's, over the {_wallets(len(with_pnl))} with one): median "
                     f"{statistics.median(r['unrealized_pnl'] for r in with_pnl) * 100:+.1f}%, {weighted}")
    else:
        lines.append("  unrealized PnL: not read (no wallet row carries one)")

    prices = [r["usd_value"] / r["balance"] for r in wallets if r["usd_value"] and r["balance"]]
    supplies = [r["balance"] / r["share"] for r in wallets if r["balance"] and r["share"]]
    price = supply = mcap = None
    if prices and supplies:
        (price, price_spread), (supply, supply_spread) = _median_or_spread(prices), _median_or_spread(supplies)
        mcap = price * supply
        agree = [f"the rows disagree on the {what} by {spread * 100:.1f}% (the median is used)" for what, spread in (("price", price_spread), ("supply", supply_spread))
                 if spread > PNL_SPREAD]
        lines.append(f"  market cap now {_usd(mcap)} = price {_price(price)} (usd_value / balance) x supply {supply:,.0f} tokens (balance / share of supply); "
                     f"medians over {_wallets(min(len(prices), len(supplies)))}; " + ("; ".join(agree) if agree else "the rows agree within 1%"))
    else:
        lines.append("  market cap now: not read (no wallet row with a balance, a USD value and a share)")

    costed = [r for r in wallets if (r["avg_cost"] or 0) > 0 and r["balance"]]
    avg_buy = sum(r["avg_cost"] * r["balance"] for r in costed) / sum(r["balance"] for r in costed) if costed else None
    if avg_buy is not None and mcap is not None:
        lines.append(f"  supply-weighted average buy {_price(avg_buy)} per token = market cap {_usd(avg_buy * supply)} vs {_usd(mcap)} now "
                     f"({_wallets(len(costed))} with an average buy, {_pct(_share_pct(costed))} of supply; weighted by balance)")
        bands = [("below the current price", 0.0, 1.0, f"under {_usd(mcap)}"), ("1-1.5x", 1.0, 1.5, f"{_usd(mcap)}-{_usd(1.5 * mcap)}"),
                 ("1.5-3x", 1.5, 3.0, f"{_usd(1.5 * mcap)}-{_usd(3 * mcap)}"), ("3x or more", 3.0, math.inf, f"{_usd(3 * mcap)} and above")]
        cells = []
        for name, low, high, span in bands:
            inside = [r for r in costed if low <= r["avg_cost"] / price < high]
            cells.append(f"{name} ({span}): {_wallets(len(inside))}, {_pct(_share_pct(inside))}")
        costed_ids = {id(r) for r in costed}
        no_entry = [r for r in wallets if id(r) not in costed_ids]
        if no_entry:
            cells.append(f"no average buy from GMGN: {_wallets(len(no_entry))}, {_pct(_share_pct(no_entry))}")
        lines.append("  cost bands (entry market cap = GMGN's average buy x supply; wallets, share of supply): " + " | ".join(cells))
        summary_buy = f"weighted average buy at {_usd(avg_buy * supply)} vs {_usd(mcap)} now"
    else:
        why = "no wallet row with an average buy and a balance" if avg_buy is None else "market cap not read"
        lines.append(f"  supply-weighted average buy and cost bands: not read ({why})")
        summary_buy = f"weighted average buy not read ({why})"

    ranked = sorted(wallets, key=lambda r: -(r["share"] or 0.0))  # stable: GMGN's order on equal shares
    top = ranked[:PNL_TOP_N]
    top_red = sum(1 for r in top if r["unrealized_pnl"] is not None and r["unrealized_pnl"] < 0)
    top_green = sum(1 for r in top if r["unrealized_pnl"] is not None and r["unrealized_pnl"] >= 0)
    lines.append(f"  {len(top)} largest non-pool holders (rank among the wallets of GMGN's top 100 after pools; PnL = GMGN's unrealized PnL; "
                 f"entry = average buy as a market cap): {top_green} in the green, {top_red} in the red, {len(top) - top_red - top_green} without an unrealized PnL")
    lines += [_holder_line(rank, r, supply) for rank, r in enumerate(top, 1)]
    if all(f in missing for f in PNL_IDENTITY_FIELDS):
        lines.append("  named holders: not read (field missing: " + ", ".join(PNL_IDENTITY_FIELDS) + ")")
    else:
        named = [(rank, r) for rank, r in enumerate(ranked, 1) if rank > PNL_TOP_N and _who(r)]
        lines.append(f"  named holders outside the {len(top)} largest (GMGN's name or X handle, its claim): " + (str(len(named)) if named else "none in GMGN's rows"))
        lines += [_holder_line(rank, r, supply) for rank, r in named[:PNL_NAMED_CAP]]
        if len(named) > PNL_NAMED_CAP:
            lines.append(f"    and {len(named) - PNL_NAMED_CAP} more")
    moved = [r for r in wallets if r["transfer_in"]]
    lines.append(f"  cannot see: holders outside GMGN's top 100 ({_pct(max(0.0, 100 - top_share))} of supply"
                 + (", less the rows without a share" if no_share else "") + "); buys routed through apps without a cost record "
                 f"({_wallets(len(no_basis))} here without a cost basis); tokens received by transfer ({_wallets(len(moved))} carry GMGN's transfer_in tag, "
                 f"{_pct(_share_pct(moved))} of supply; their cost basis may not cover those tokens); whether GMGN's basis is average or FIFO "
                 "(its numbers are used as given; a partial seller's PnL is on GMGN's remaining-position basis)")
    lines.append(f"  {PNL_PRESENTATION_LINE}")
    # HS-CASCADE-T1 amendment A1: with the field present but no usable value on any wallet row, the summary line is not read,
    # never "0 of N in the red" (the block above still explains it)
    summary = (f"{len(red)} of {len(wallets)} in the red, {_pct(_share_pct(red))} of supply; {summary_buy}" if with_pnl
               else "not read (GMGN gave no usable unrealized PnL)")
    return summary, lines


def _load_pnl(run: Path) -> dict[str, Any]:
    """The saved <run>/gmgn_holder_pnl.json with status ok, or NotRead with the reason (missing, unreadable or a foreign
    file, GMGN not ok). Shared by the holder PnL block and the copy-trade cascade section."""
    path = run / PNL_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        data = None
    if not path.exists():
        raise NotRead(f"{PNL_FILE} missing")
    if not (isinstance(data, dict) and data.get("schema") == PNL_SCHEMA and data.get("presentation_only") is True
            and data.get("status") in ("ok", "empty", "unavailable")):
        raise NotRead(f"{PNL_FILE} unreadable")
    if data["status"] != "ok":
        raise NotRead(f"GMGN {data['status']}: {_reason(data.get('reason'))}")
    return data


def present(run: Path) -> list[str]:
    """The holder cost and PnL block from <run>/gmgn_holder_pnl.json, offline (no network, no key). First line: the
    executive-summary line, marked. A missing, foreign or malformed file, a status other than ok, or a field missing from
    every row reads "not read (<reason>)", never "nobody in the red"."""
    try:
        summary, body = pnl_block(_load_pnl(run))
    except NotRead as why:
        return [f"{PNL_SUMMARY_MARK}{PNL_SUMMARY_HEAD}: not read ({why})", f"{PNL_TITLE}: not read ({why})"]
    except Exception:  # noqa: BLE001 - a damaged file never crashes the synthesis; it reads as not read
        return [f"{PNL_SUMMARY_MARK}{PNL_SUMMARY_HEAD}: not read ({PNL_FILE} values unreadable)", f"{PNL_TITLE}: not read ({PNL_FILE} values unreadable)"]
    lines = [f"{PNL_SUMMARY_MARK}{PNL_SUMMARY_HEAD}: {summary}", PNL_TITLE, *body]
    removed = count_removed(lines)
    if removed:
        lines.append(f"  {removed_line(removed)}")
    return lines


# ----------------------------------------------------------------------------- copy-trade cascade (synthesis, offline; HS-CASCADE-T1)
# Printed by --present right after the holder cost and PnL block, from the same saved gmgn_holder_pnl.json and the skill's
# static, dated watchlist (HS-WATCHLIST-T1). No network, no key; never an engine input. Owner decisions of 2026-10-24:
# watchlist traders only at 0.1% of supply or more (one count line for the rest), also the named holders not on the list and
# the Fomo-app wallet count; "a flag at least" is one executive-summary line after the FLAG lines (FLAG and verdict untouched).

WATCHLIST_FILE = Path(__file__).resolve().parents[1] / "references" / "fomo_cascade_watchlist.json"
WATCHLIST_NAME = "fomo_cascade_watchlist.json"
WATCHLIST_SCHEMA = "holder-scan-fomo-cascade-watchlist/1"
CASCADE_TITLE = "Copy-trade cascade (presentation only)"
CASCADE_SUMMARY_HEAD = "Copy-trade cascade risk (presentation only)"
CASCADE_BAR = 0.001              # 0.1% of supply as a fraction (GMGN's amount_percentage is 0-1); at or over it a holder is listed
CASCADE_FIELDS = ("amount_percentage", "addr_type", "unrealized_pnl")  # absent from every row (a renamed field): the section is not read
CASCADE_TIERS = {"owner": "owner-named", "tier1": "tier 1", "tier2": "tier 2"}
CASCADE_RED = "in the red: a one-clip sell is likely, and copy bots mirror sells within about 1-3 s"
CASCADE_NAMES_CAP = 10
HANDLE_RE = re.compile(r"[A-Za-z0-9_]{1,32}")  # a plain X or Fomo handle after one leading @; a display name never is one
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _handle_key(value: Any) -> str | None:
    """The match form of a handle: one leading @ stripped, lower-cased; only for a plain handle (letters, digits and _)
    that the verdict-word rule leaves as it is. A display name, a placeholder or text with spaces never matches, and
    matching compares whole handles, never a part of one."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    text = text[1:] if text.startswith("@") else text
    return text.lower() if HANDLE_RE.fullmatch(text) and label(text, LABEL_RE) == text else None


def _whole(value: Any) -> int | None:
    """A non-negative whole number saved as a JSON integer (not a bool), else None."""
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 10 ** 12 else None


def _day(value: Any) -> str | None:
    """YYYY-MM-DD from a saved date or ISO time (read as UTC), else None."""
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        if DATE_RE.fullmatch(value):
            return dt.date.fromisoformat(value).isoformat()
        moment = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        return None
    return (moment if moment.tzinfo else moment.replace(tzinfo=dt.timezone.utc)).astimezone(dt.timezone.utc).date().isoformat()


def _watch_entry(raw: Any) -> dict[str, Any] | None:
    """One watchlist entry, validated again (the file can be edited); None without usable X handle text. Only a Fomo result
    with status matched supplies a wallet, a Fomo handle or a Fomo follower count (an ambiguous or not_found entry's
    candidates are never used). Any X handle status other than as_in_report is a name-only identity."""
    if not isinstance(raw, dict):
        return None
    shown = _saved_label(raw.get("x_handle"))
    if shown is None:
        return None
    fomo = raw.get("fomo") if isinstance(raw.get("fomo"), dict) else {}
    matched = fomo.get("status") == "matched"
    wallet = fomo.get("solana_wallet") if matched else None
    fomo_handle = fomo.get("handle") if matched else None
    tier = raw.get("tier")
    return {
        "shown": shown,
        "keys": {k for k in (_handle_key(raw.get("x_handle")), _handle_key(fomo_handle)) if k},
        "wallet": wallet if isinstance(wallet, str) and SOLANA_ADDRESS_RE.fullmatch(wallet) else None,
        "fomo_matched": matched,
        "fomo_handle": _saved_label(fomo_handle),
        "followers": _whole(fomo.get("followers")) if matched else None,
        "verified": _day(fomo.get("checked_at")) if matched else None,
        "self_reported": _whole(raw.get("followers_self_reported")),
        "tier": CASCADE_TIERS.get(tier, "tier not given") if isinstance(tier, str) else "tier not given",
        "name_only": raw.get("x_handle_status") != "as_in_report",
    }


def _load_watchlist(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """(entries, facts) from the static watchlist file, or NotRead with the reason. An unreadable entry is skipped and
    counted; a file with no readable entry is not read."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise NotRead(f"{WATCHLIST_NAME} missing") from None
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        raise NotRead(f"{WATCHLIST_NAME} unreadable") from None
    items = data.get("entries") if isinstance(data, dict) else None
    if not (isinstance(data, dict) and data.get("schema") == WATCHLIST_SCHEMA and isinstance(items, list)):
        raise NotRead(f"{WATCHLIST_NAME} unreadable")
    entries = [e for e in (_watch_entry(raw) for raw in items) if e is not None]
    if not entries:
        raise NotRead(f"{WATCHLIST_NAME} holds no readable entry")
    as_of = data.get("as_of")
    return entries, {"as_of": _day(as_of) if isinstance(as_of, str) and DATE_RE.fullmatch(as_of) else None, "skipped": len(items) - len(entries)}


def _pnl_text(pnl: float | None) -> str:
    return f"unrealized {pnl * 100:+.1f}%" if pnl is not None else "unrealized PnL not given by GMGN"


def _sold_text(sold: float | None) -> str:
    return f"sold {sold * 100:.0f}%" if sold is not None else "sold n/a"


def _cascade_line(r: dict[str, Any], e: dict[str, Any], by_wallet: bool, by_handle: bool) -> str:
    """"Copy-trade cascade risk: <handle> (<tier>; Fomo followers ...) holds <x>% of supply ($<usd>), unrealized <pnl>%,
    sold <s>%, matched by <wallet | GMGN handle>", the name-only note for an unconfirmed X handle, the in-the-red phrase."""
    if e["followers"] is not None:
        followers = f"Fomo followers {e['followers']:,} verified {e['verified'] or '(date not given)'}"
    elif e["self_reported"] is not None:
        followers = f"Fomo followers self-reported {e['self_reported']:,}"
    else:
        followers = "Fomo followers unknown"
    usd = f"({_usd(r['usd_value'])})" if r["usd_value"] is not None else "(USD value not given)"
    how = " and ".join(name for name, hit in (("wallet", by_wallet), ("GMGN handle", by_handle)) if hit)
    text = (f"    Copy-trade cascade risk: {e['shown']} ({e['tier']}; {followers}) holds {_pct(r['share'] * 100)} of supply {usd}, "
            f"{_pnl_text(r['unrealized_pnl'])}, {_sold_text(r['sell_amount_percentage'])}, matched by {how}")
    if e["name_only"]:
        who = f"the Fomo account {e['fomo_handle']}" if e["fomo_handle"] else f"the handle {e['shown']}"
        text += f" (name-only match: {who} is not confirmed to be the trader in the research)"
    if r["unrealized_pnl"] is not None and r["unrealized_pnl"] < 0:
        text += f"; {CASCADE_RED}"
    return text


def cascade_block(data: dict[str, Any], entries: list[dict[str, Any]], facts: dict[str, Any]) -> tuple[str | None, list[str]]:
    """(executive-summary text or None, section lines) from a saved gmgn_holder_pnl.json with status ok and the watchlist.
    Pools (addr_type 2) are out of every match and count. A holder matches an entry when its address equals the entry's
    Fomo-verified main wallet, or its GMGN X handle equals the entry's X or Fomo handle as a whole (any case, @ stripped).
    Raises NotRead when a field the section relies on is missing from every row or no wallet row is left."""
    missing = data.get("fields_missing")
    if not isinstance(missing, list) or not all(isinstance(f, str) for f in missing):
        raise NotRead(f"{PNL_FILE} unreadable")
    gone = [f for f in CASCADE_FIELDS if f in missing]
    if gone:
        raise NotRead("field missing: " + ", ".join(gone))
    rows = _saved_rows(data)
    wallets = [r for r in rows if not r["pool"]]
    if not wallets:
        raise NotRead("no wallet rows after removing pools")
    handles = "twitter_username" not in missing
    when = _when(data.get("fetched_at"))
    pairs: list[tuple[dict[str, Any], dict[str, Any], bool, bool]] = []
    for r in wallets:
        key = _handle_key(r["twitter_username"]) if handles else None
        for e in entries:
            by_wallet = e["wallet"] is not None and e["wallet"] == r["address"]
            by_handle = key is not None and key in e["keys"]
            if by_wallet or by_handle:
                pairs.append((r, e, by_wallet, by_handle))
    listed = sorted((p for p in pairs if p[0]["share"] is not None and p[0]["share"] >= CASCADE_BAR), key=lambda p: -p[0]["share"])
    under = sum(1 for p in pairs if p[0]["share"] is not None and p[0]["share"] < CASCADE_BAR)
    no_share = sum(1 for p in pairs if p[0]["share"] is None)
    with_wallet = sum(1 for e in entries if e["wallet"])
    # Repair R1 (F3): wallets that came with a name-only Fomo account (an X handle status other than as_in_report) are said so
    name_only_wallets = [e["shown"] for e in entries if e["wallet"] and e["name_only"]]
    wallet_note = f"{with_wallet} of {len(entries)} entries have one"
    if name_only_wallets:
        wallet_note += (f", {len(name_only_wallets)} of them through a name-only Fomo account: " + ", ".join(name_only_wallets[:CASCADE_NAMES_CAP])
                        + (f" and {len(name_only_wallets) - CASCADE_NAMES_CAP} more" if len(name_only_wallets) > CASCADE_NAMES_CAP else ""))
    as_of = facts["as_of"] or "an unknown date"
    lines = [f"  watchlist: references/{WATCHLIST_NAME}, {len(entries)} traders as of {as_of}"
             + (f" ({facts['skipped']} unreadable {'entry' if facts['skipped'] == 1 else 'entries'} skipped)" if facts["skipped"] else "")
             + f"; static and dated; public claims and observations, not proof; matched against GMGN's snapshot {when} ({_wallets(len(wallets))} "
             f"after removing pools) by the Fomo-verified main wallet ({wallet_note}) or GMGN's X handle (equal to the "
             "entry's X or Fomo handle as a whole, any case, @ stripped; never a display name or part of a handle); listed at 0.1% of supply or more"]
    if not handles:
        lines.append("  GMGN's X handles: not read (field missing: twitter_username); matching by wallet only, and the named list below shows kol-tagged holders only")
    if listed:
        lines.append(f"  watchlist traders holding 0.1% of supply or more: {len(listed)}")
        lines += [_cascade_line(*p) for p in listed]
    elif pairs:
        lines.append(f"  no watchlist trader at 0.1% of supply or more among GMGN's top 100 at {when}")
    else:
        lines.append(f"  no watchlist trader seen among GMGN's top 100 at {when}")
    lines.append(f"  under the 0.1% bar: {under} more watchlist trader{' holds' if under == 1 else 's hold'} under 0.1% of supply, not listed"
                 + (f"; {no_share} more without a share from GMGN, not listed" if no_share else ""))

    matched = {id(p[0]) for p in pairs}
    named = [r for r in wallets if id(r) not in matched and ((handles and r["twitter_username"]) or "kol" in r["app_tags"])]
    named_listed = sorted((r for r in named if r["share"] is not None and r["share"] >= CASCADE_BAR), key=lambda r: -r["share"])
    rest = len(named) - len(named_listed)
    lines.append(f"  named by GMGN, not on the watchlist (an X handle or GMGN's kol tag), at 0.1% of supply or more: {len(named_listed)}"
                 + (f"; {rest} more under 0.1% of supply or without a share, not listed" if rest else ""))
    for r in named_listed:
        if handles and r["twitter_username"]:
            who = f"@{r['twitter_username']}" + (" (GMGN kol tag)" if "kol" in r["app_tags"] else "")
        else:
            who = "kol tag, no handle"
        lines.append(f"    {who}: {_pct(r['share'] * 100)} of supply, {_pnl_text(r['unrealized_pnl'])}, {_sold_text(r['sell_amount_percentage'])}; "
                     "not on the watchlist; GMGN's labels are claims")

    fomo = [r for r in wallets if "fomo" in r["app_tags"]]
    fomo_pnl = [r for r in fomo if r["unrealized_pnl"] is not None]
    fomo_red = [r for r in fomo_pnl if r["unrealized_pnl"] < 0]
    # Repair R2 (the A1 rule): Fomo-tagged wallets with no usable PnL read not read, never a made-up "0 in the red"
    # (with no Fomo-tagged wallet at all, 0 in the red is a real count of none)
    red_part = (f"{len(fomo_red)} in the red ({_pct(_share_pct(fomo_red))} of supply)" if fomo_pnl or not fomo
                else "in the red: not read (no usable PnL)")
    lines.append(f"  Fomo app: GMGN tags {len(fomo)} of the {len(wallets)} non-pool holders in its top 100 as trading through the Fomo app: "
                 f"{_pct(_share_pct(fomo))} of supply, {red_part}. "
                 "Copy-trading runs on that app; this does not show which of them copy whom.")

    unmatched = [e["shown"] for e in entries if not e["fomo_matched"]]
    no_fomo = ""
    if unmatched:
        no_fomo = "; no Fomo match for " + ", ".join(unmatched[:CASCADE_NAMES_CAP]) + (f" and {len(unmatched) - CASCADE_NAMES_CAP} more" if len(unmatched) > CASCADE_NAMES_CAP else "")
    outside = max(0.0, 100 - _share_pct(rows))
    lines.append(f"  this section cannot see: holders outside GMGN's top 100 ({_pct(outside)} of supply"
                 + (", less the rows without a share" if any(r["share"] is None for r in rows) else "") + "); a listed trader holding through a "
                 f"wallet other than the Fomo main wallet and without an X handle on GMGN (Fomo-verified main wallet: {wallet_note}{no_fomo}); sells after GMGN's snapshot ({when}): a sell seconds later is not in these rows; traders not on the watchlist (as of "
                 f"{as_of}; static, refreshed only when the owner asks); how many copy traders follow each trader (Fomo follower counts are only a proxy); "
                 "Fomo-app wallets that GMGN does not tag")
    lines.append(f"  {PNL_PRESENTATION_LINE}")
    summary = ", ".join(f"{e['shown']} {_pct(r['share'] * 100)} ("
                        + (f"{r['unrealized_pnl'] * 100:+.0f}%" if r["unrealized_pnl"] is not None else "PnL not given")
                        + (", name-only match" if e["name_only"] else "") + ")" for r, e, _, _ in listed)
    return summary or None, lines


def cascade_present(run: Path, watchlist: Path | None = None) -> list[str]:
    """The copy-trade cascade section from <run>/gmgn_holder_pnl.json and the watchlist file, offline (no network, no key).
    First line, only when a watchlist trader holds 0.1% of supply or more: the executive-summary line, marked. A missing,
    foreign or malformed file, GMGN not ok, or a field missing from every row reads "not read (<reason>)" (with a marked
    summary line), never "no cascade risk"."""
    try:
        data = _load_pnl(run)
        entries, facts = _load_watchlist(WATCHLIST_FILE if watchlist is None else watchlist)
        summary, body = cascade_block(data, entries, facts)
    except NotRead as why:
        return [f"{PNL_SUMMARY_MARK}{CASCADE_SUMMARY_HEAD}: not read ({why})", f"{CASCADE_TITLE}: not read ({why})"]
    except Exception:  # noqa: BLE001 - a damaged file never crashes the synthesis; it reads as not read
        why = f"{PNL_FILE} or {WATCHLIST_NAME} values unreadable"
        return [f"{PNL_SUMMARY_MARK}{CASCADE_SUMMARY_HEAD}: not read ({why})", f"{CASCADE_TITLE}: not read ({why})"]
    lines = ([f"{PNL_SUMMARY_MARK}{CASCADE_SUMMARY_HEAD}: {summary}"] if summary else []) + [CASCADE_TITLE, *body]
    removed = count_removed(lines)
    if removed:
        lines.append(f"  {removed_line(removed)}")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read GMGN's top-100 holder rows for a Solana mint once (paid: rate weight 5; bounded: 5 MiB, "
                                                 "30 s, no redirects, no env proxy, at most one retry after a short documented rate limit) and save "
                                                 f"{TOP100_FILE} and {ACQUISITION_FILE} for helius_forensics.py assess, and {PNL_FILE} (holder cost and PnL "
                                                 "from the same response; presentation only). Only when the owner asked for GMGN. With --present RUN_DIR: "
                                                 "print the holder cost and PnL block and the copy-trade cascade section offline (no network, no key).")
    parser.add_argument("mint", nargs="?")
    parser.add_argument("--out", metavar="RUN_DIR", help="run folder to save the files into")
    parser.add_argument("--env-file", metavar="PATH", help=f"the repository .env ({KEY_NAME} in the environment is used first)")
    parser.add_argument("--present", metavar="RUN_DIR", help=f"offline: print the holder cost and PnL block from {PNL_FILE}, then the copy-trade "
                                                               f"cascade section from it and references/{WATCHLIST_NAME} (no network, no key)")
    args = parser.parse_args(argv)
    if args.present is not None:
        if args.mint or args.out or args.env_file:
            print("error: --present takes only the run folder", file=sys.stderr)
            return 2
        run = Path(args.present)
        if not run.is_dir():
            print("error: --present is not a run folder", file=sys.stderr)
            return 2
        for line in present(run) + cascade_present(run):  # HS-CASCADE-T1: the cascade section right after the PnL block
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
    key: str | None = None
    raw: list[Any] = []  # the raw rows of the one response, for gmgn_holder_pnl.json (no second request)
    try:
        key, reason = load_key(None if os.environ.get(KEY_NAME, "").strip() else find_env_file(args.env_file))
        result = collect_gmgn_rows(mint, key, key_reason=reason, raw_holders=raw)
    except Exception:  # noqa: BLE001 - never print a traceback (it could carry request details)
        result = _base(mint, _iso(time.time()))
        result["reason"] = "request_failed"
    acq =acquisition_map(result["list"]) if result["status"] == "ok" else {}
    try:
        (out / TOP100_FILE).write_text(json.dumps(result, indent=1), encoding="utf-8")
        if acq:
            (out / ACQUISITION_FILE).write_text(json.dumps(acq, indent=1), encoding="utf-8")
        elif (out / ACQUISITION_FILE).is_file():
            (out / ACQUISITION_FILE).unlink()  # never leave an older map next to a result that has none
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    try:  # HS-PNL-T1: presentation only; never changes the files above, the status line or the exit code
        pnl = holder_pnl(result, raw if result["status"] == "ok" else [], key)
    except Exception:  # noqa: BLE001 - the PnL file never stops the collector
        pnl = holder_pnl(result | {"status": "unavailable", "reason": "holder_pnl_build_failed"}, [], None)
    try:
        (out / PNL_FILE).write_text(json.dumps(pnl, indent=1), encoding="utf-8")
    except OSError:
        print(f"error: {PNL_FILE} could not be saved (presentation only; {TOP100_FILE} was saved)", file=sys.stderr)
    print(status_line(result, len(acq) or None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
