#!/usr/bin/env python3
"""MadeOnSol token snapshot, deployer profile and launch-bundle summary for dlmm-scan (first-wave collector `madeonsol`):
two fixed, bounded, read-only requests sent at the same time, on MadeOnSol's free BASIC tier only.

PRESENTATION ONLY. MadeOnSol's numbers never feed either engine: they are shown in the synthesis's "Sources read" and, at
or over the existing provider bars (MadeOnSol's swap-derived launch-cohort share against bundles 30%+ BUNDLE_ALARM_PCT),
as "clear large cluster seen by MadeOnSol, not yet in the engine verdicts" next to the FLAGs (the late-source rule). That
share is what the cohort bought minus what it sold through swaps: tokens moved out by transfer are never subtracted, so it
can over-read and is not a balance check; it is always worded as MadeOnSol's claim, never as what the wallets hold now.
helius_forensics.py refuses MadeOnSol as a --providers-json provider (exit 2). A low number is never an all-clear, never
counts toward NO_ALARM and never softens a FLAG. MadeOnSol's bundle definition (3 or more wallets buying in one slot) and
its deployer tiers are its own: name them next to GMGN's, Jupiter's and Solana Tracker's, never merge or average them.

Requests (provider-docs cache, madeonsol/apireference.md "GET /token/{mint}" and "GET /tokens/{mint}/bundle"; base /api/v1):
  GET /api/v1/token/<mint>?include=deployer,buyer_quality
        the per-mint snapshot (deployer reputation, KOL smart-money activity, the first-20-buyer launch cohort and how
        many of them still hold) with the deployer's profile (tier, tokens deployed, bonded count, bond rates) and the
        buyer-quality score embedded in the same answer: ONE call, on every tier; a failing include is named in
        include_errors and never fails the call. The deployer is known from this one call, so there is no follow-up lane.
  GET /api/v1/tokens/<mint>/bundle
        the launch-bundle summary (BASIC: the summary block only): wallets, kind, share of supply still held
Both on host madeonsol.com only, https only, the key in the Authorization header as a Bearer token, no redirects, no
environment proxy, 4 MiB and a hard 30 s wall-clock limit per attempt (opening, every read and closing under one
deadline, worker thread, like solanatracker.py), and at most one retry per request, only after a 429 whose Retry-After
ends within 5 s (MadeOnSol documents Retry-After on every 429; without one there is no retry, so no call of the 200-a-day
free quota is spent on a guess). Calls per scan: 2 (at most 4 with the retries) of the free tier's 200 a day.

Not called (paid only): /api/v1/tokens/<mint>/cap-table ("BASIC: 403") and /api/v1/tokens/<mint>/fee-shares ("PRO+")
need MadeOnSol PRO, which the owner has not bought. Both are reported as "not read (needs MadeOnSol PRO; owner
decision)", never as empty and never as zero.

Key: only MADEONSOL_API_KEY, from the environment first, then exactly that one variable from the repository .env
(single-variable parser; the file is never sourced). It is sent only in the Authorization header and is never printed,
logged, saved or put in an error: every failure becomes a fixed reason code (a 403 or 429 error body is read, bounded,
only to pick one code from a fixed list). Provider text is untrusted: kept text is reduced to short inert labels or
checked against a short allowlist, every other kept value is a validated number, flag or address, and any kept text whose
raw form or label shares 8 or more consecutive characters with the key (or with the key stripped of the characters a
label cannot hold) is dropped; address fields use the same shared-piece check.

A renamed load-bearing field is loud, never ok (see parse_token and parse_bundle); a number that is not read is
reported as not read, never as 0.

Collector: madeonsol.py <MINT> --out <RUN> writes <RUN>/madeonsol.json and prints one line: ok (...), empty (...) or
unavailable (<reason>; ...). Exit 0 whenever the file was saved; exit 2 for a bad mint or an unwritable --out.
Synthesis (offline, no network, no key): madeonsol.py --present <RUN> prints the Sources-read block (Dev / deployer,
launch bundle, KOL positions, buyer quality, the two PRO-only lines) and any late-source line. Standard library only;
Python >= 3.10.
"""

from __future__ import annotations

import argparse
import datetime as dt
import decimal
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

HOST = "madeonsol.com"
TOKEN_PATH = "/api/v1/token/<MINT>"
TOKEN_QUERY = "include=deployer,buyer_quality"
BUNDLE_PATH = "/api/v1/tokens/<MINT>/bundle"
PARTS = ("token", "bundle")
PRO_ONLY = {"cap_table": "/api/v1/tokens/<MINT>/cap-table", "fee_shares": "/api/v1/tokens/<MINT>/fee-shares"}
PRO_NOTE = "needs MadeOnSol PRO; owner decision"
MAX_BYTES = 4 * 1024 * 1024
ERROR_BODY_MAX = 16 * 1024       # a 403 / 429 error body is read only this far, only to pick a fixed reason code
TIMEOUT_S = 30.0                 # per attempt: a hard wall-clock limit on open + every read + close (worker thread)
RETRY_MAX_WAIT_S = 5.0           # retry a 429 once only when its Retry-After ends this soon
REQUESTS_PER_SCAN = 2
MAX_REQUESTS = 4                 # each of the two requests retried at most once
FREE_CALLS_PER_DAY = 200         # MadeOnSol BASIC (free) tier, per the cached docs
USER_AGENT = "holder-scan-madeonsol/1.0"
KEY_NAME = "MADEONSOL_API_KEY"
AUTH_HEADER_NAMES = ("Authorization",)
KEY_RE = re.compile(r"^[\x21-\x7e]{8,512}$")  # printable, no spaces: a valid header value; the value is never echoed
KEY_PIECE = 8                    # provider text sharing this many consecutive characters with the key is dropped
SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
LABEL_RE = re.compile(r"[^\w .\-]")  # the forensics adapter's LABEL_RE: letters, digits, _, space, dot and hyphen only
OUT_FILE = "madeonsol.json"
SCHEMA = "holder-scan-madeonsol/1"
HTTP_REASONS = {400: "bad_request", 401: "authentication_failed", 403: "access_denied", 404: "not_found", 429: "rate_limited",
                503: "service_unavailable"}
ERROR_CODES = {"tier_required": "tier_required", "demo_key_endpoint_not_allowed": "demo_key_not_allowed"}
CANNOT_SEE = ("its own bundle definition (3 or more wallets buying in one slot, which can be coincidental, from its own "
              "trade capture of launchpad tokens, mostly pump.fun) and its own deployer tiers; its bundle share counts swaps "
              "only (bought minus sold; tokens moved out by transfer are not subtracted), so it can over-read and is not a "
              "balance check; no funding links between wallets, so no funding cohorts; tokens outside its launchpad capture "
              "read as not captured; on the free tier no bundle wallets, no cap table and no creator-fee recipients")
PRESENTATION_NOTE = ("presentation only: these numbers never feed either engine, never count toward NO_ALARM and never "
                     "soften a FLAG; a low number is not an all-clear")


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
    """(key, None) or (None, reason). Environment first, then exactly the one MADEONSOL_API_KEY line of the .env; no
    other line is kept. Never logs or returns the value in a reason."""
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


# ----------------------------------------------------------------------------- requests


def part_path(part: str, mint: str) -> str:
    quoted = urllib.parse.quote(mint, safe="")
    return f"/api/v1/token/{quoted}" if part == "token" else f"/api/v1/tokens/{quoted}/bundle"


def part_query(part: str) -> str:
    return TOKEN_QUERY if part == "token" else ""


def check_url(url: str, mint: str) -> None:
    """https only, host madeonsol.com only, one of the two documented paths for this mint with its fixed query only, no
    port other than 443, no credentials in the URL."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise Failure("scheme_not_https")
    if parsed.hostname != HOST or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise Failure("host_not_allowlisted")
    allowed = {(part_path(p, mint), part_query(p)) for p in PARTS}
    if (parsed.path, parsed.query) not in allowed or parsed.params or parsed.fragment:
        raise Failure("path_not_allowlisted")


def build_request(part: str, mint: str, key: str) -> urllib.request.Request:
    query = part_query(part)
    url = f"https://{HOST}{part_path(part, mint)}" + (f"?{query}" if query else "")
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

    worker = threading.Thread(target=invoke, name="madeonsol-transport", daemon=True)
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
    asks for longer, is unreadable or is absent (MadeOnSol documents it on every 429)."""
    headers = getattr(exc, "headers", None)
    raw = headers.get("Retry-After") if headers is not None else None
    if raw is None:
        return None
    text = str(raw).strip()
    if not re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,3})?", text):
        return None
    wait = max(0.5, float(text))
    return wait if wait <= RETRY_MAX_WAIT_S else None


def _error_code(exc: urllib.error.HTTPError, remaining: Callable[[], float]) -> str | None:
    """A fixed reason code picked from a 403 / 429 error body (read at most ERROR_BODY_MAX bytes under the deadline):
    tier_required, demo_key_not_allowed or daily_quota_exhausted; None when the body says nothing on the fixed list.
    No body text ever leaves this function."""
    try:
        raw = _bounded_call(lambda: exc.read(ERROR_BODY_MAX), remaining())
        body = json.loads(raw.decode("utf-8")) if isinstance(raw, bytes) and raw else None
    except Exception:  # noqa: BLE001 - an unreadable body falls back to the status code
        return None
    if not isinstance(body, dict):
        return None
    error = body.get("error")
    if isinstance(error, str) and error in ERROR_CODES:
        return ERROR_CODES[error]
    if error == "rate_limit_exceeded" and body.get("error_kind") == "daily":
        return "daily_quota_exhausted"
    return None


def send_once(request: urllib.request.Request, opener: Any, mint: str, *, monotonic: Callable[[], float]) -> bytes:
    """One attempt. Returns the body (at most MAX_BYTES) or raises Failure with a fixed code. Opening, every read and the
    error close run under one hard wall-clock deadline of TIMEOUT_S, so the attempt ends by then whatever the server does.
    Only a 403 or 429 error body is read (bounded), and only to pick a fixed code."""
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
                code = _error_code(exc, remaining)
                raise Failure(code or "rate_limited", 429, retry_wait=None if code == "daily_quota_exhausted" else _retry_after(exc)) from None
            if exc.code == 403:
                raise Failure(_error_code(exc, remaining) or "access_denied", 403) from None
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


def fetch_part(part: str, mint: str, key: str, opener: Any, *, monotonic: Callable[[], float], sleep: Callable[[float], None]) -> dict[str, Any]:
    """One documented request, plus at most one retry after a short 429. Returns {body, attempts, reason, http_status};
    never raises."""
    out: dict[str, Any] = {"body": None, "attempts": 0, "reason": None, "http_status": None}
    for attempt in (1, 2):
        out["attempts"] = attempt
        try:
            out.update(body=send_once(build_request(part, mint, key), opener, mint, monotonic=monotonic), reason=None, http_status=200)
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


def _choice(value: Any, allowed: frozenset[str]) -> str | None:
    return value.strip().lower() if isinstance(value, str) and value.strip().lower() in allowed else None


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _iso_time(value: Any) -> str | None:
    """An ISO time as MadeOnSol sends it, kept only when it parses with a zone (re-written in a fixed form)."""
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _fraction_pct(value: Any) -> tuple[float | None, bool]:
    """A MadeOnSol share sent as a fraction of 1 (documented for held_pct_of_supply, "clamped 0-1"; the live CAPE answer
    of 2026-10-19 confirms it: tokens_held / circulating supply = 0.8068) as percent. Returns (percent or None,
    unit_unexpected): a number outside 0..1 is not guessed into a percent. The percent is cut toward zero at 9 decimals
    from the decimal value MadeOnSol sent, never rounded up: 0.29999999999 gives 29.999999999, never a 30 that would reach
    the bundles bar (the never-rounded-up rule of HS-PROV-T1)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None, False
    if 0.0 <= value <= 1.0:
        percent = (decimal.Decimal(repr(float(value))) * 100).quantize(decimal.Decimal("0.000000001"), rounding=decimal.ROUND_DOWN)
        return float(percent), False
    return None, True


SIGNALS = frozenset({"positive", "neutral", "negative"})
KOL_SIGNALS = frozenset({"accumulating", "distributing", "neutral", "mixed"})
CONFIDENCES = frozenset({"insufficient_data", "low", "medium", "high"})
BUNDLE_KINDS = frozenset({"atomic_tx", "same_slot", "none"})


def sanitize_deployer(token: dict[str, Any], profile_body: Any, key: str | None) -> dict[str, Any]:
    """The Dev / deployer block, from the embedded deployer profile (deployer_profile.deployer: the /deployer-hunter
    answer) with the snapshot's own deployer reputation (token.deployer) as the fallback, under MadeOnSol's own names.
    Status ok, unavailable (deployer_mismatch / deployer_fields_missing) or not_in_answer. Bond rates are fractions of 1
    (CAPE live: 1 deployed, 1 bonded, bonding_rate 1), kept as percent; a rate outside 0..1 is not read."""
    snap = _dict(token.get("deployer"))
    body = _dict(profile_body)
    prof = _dict(body.get("deployer")) if body.get("is_deployer") is True else {}
    if not snap and not prof:
        return {"status": "not_in_answer", "reason": "deployer_missing"}
    snap_wallet = _address(snap.get("wallet") if snap.get("wallet") is not None else snap.get("address"), key)
    prof_wallet = _address(prof.get("wallet_address"), key)
    if snap_wallet and prof_wallet and snap_wallet != prof_wallet:
        return {"status": "unavailable", "reason": "deployer_mismatch"}
    source = "deployer_profile" if prof else "token.deployer"
    src = prof or snap
    unexpected = []

    def rate(name: str) -> float | None:
        value, odd = _fraction_pct(src.get(name))
        if odd:
            unexpected.append(name)
        return value

    out = {
        "status": "ok", "reason": None, "source": source, "wallet": prof_wallet or snap_wallet,
        "tier": safe_label(src.get("tier"), key), "is_tracked": prof.get("is_tracked") if isinstance(prof.get("is_tracked"), bool) else None,
        "tokens_deployed": _count(prof.get("total_tokens_deployed") if prof else snap.get("total_deployed")),
        "bonded": _count(src.get("total_bonded")), "bond_rate_pct": rate("bonding_rate"), "recent_bond_rate_pct": rate("recent_bond_rate"),
        "best_token_peak_mc_usd": _number(prof.get("best_token_peak_mc"), 0.0, 1e15), "last_deploy_at": _iso_time(prof.get("last_deploy_at")),
        "history_status": safe_label(snap.get("history_status"), key), "units_unexpected": unexpected,
    }
    if not any(out[k] is not None for k in ("tier", "tokens_deployed", "bonded", "bond_rate_pct", "recent_bond_rate_pct")) and not unexpected:
        return {"status": "unavailable", "reason": "deployer_fields_missing"}
    return out


def sanitize_kol(token: dict[str, Any], key: str | None) -> dict[str, Any]:
    """KOL activity on the token (the snapshot's kol_activity, MadeOnSol's own KOL roster and window). KOL names are
    blank on the free tier; any name kept is an inert label."""
    kol = token.get("kol_activity")
    if not isinstance(kol, dict):
        return {"status": "not_in_answer", "reason": "kol_activity_missing"}
    state = kol.get("status")
    if state is not None and not (isinstance(state, str) and state.strip().lower() == "ok"):  # one fixed code: no provider text in the reason
        return {"status": "unavailable", "reason": "kol_activity_not_ok"}
    buyers = [b for b in kol.get("top_buyers") if isinstance(b, dict)] if isinstance(kol.get("top_buyers"), list) else []
    out = {
        "status": "ok", "reason": None, "buying_kols": _count(kol.get("buying_kols")), "selling_kols": _count(kol.get("selling_kols")),
        "unique_kols": _count(kol.get("unique_kols")), "buys": _count(kol.get("buys")), "sells": _count(kol.get("sells")),
        "buy_sol": _number(kol.get("buy_sol"), 0.0, 1e9), "sell_sol": _number(kol.get("sell_sol"), 0.0, 1e9),
        "net_flow_sol": _number(kol.get("net_flow_sol"), -1e9, 1e9), "signal": _choice(kol.get("signal"), KOL_SIGNALS) or safe_label(kol.get("signal"), key),
        "window_hours": _number(kol.get("window_hours"), 0.0, 1e5),
        "top_buyers": [{"name": safe_label(b.get("name"), key), "sol_amount": _number(b.get("sol_amount"), 0.0, 1e9)} for b in buyers[:10]],
    }
    if all(out[k] is None for k in ("buying_kols", "selling_kols", "unique_kols", "net_flow_sol", "buy_sol", "sell_sol")):
        return {"status": "unavailable", "reason": "kol_fields_missing"}
    return out


def sanitize_buyer_quality(body: Any, key: str | None) -> dict[str, Any]:
    """The embedded buyer-quality answer: MadeOnSol's 0-100 score over the first 20 buyers and its breakdown counts."""
    if not isinstance(body, dict):
        return {"status": "not_in_answer", "reason": "buyer_quality_missing"}
    br = _dict(body.get("breakdown"))
    out = {
        "status": "ok", "reason": None, "score": _number(body.get("score"), 0.0, 100.0), "signal": _choice(body.get("signal"), SIGNALS),
        "confidence": _choice(body.get("confidence"), CONFIDENCES), "placeholder": isinstance(body.get("note"), str) and bool(body.get("note").strip()),
        "bundle_buyer_count": _count(br.get("bundle_buyer_count")), "dump_cluster_count": _count(br.get("dump_cluster_count")),
        "recycled_early_buyer_count": _count(br.get("recycled_early_buyer_count")), "kol_count": _count(br.get("kol_count")),
        "bot_dominated": br.get("bot_dominated") if isinstance(br.get("bot_dominated"), bool) else None,
    }
    if out["score"] is None and out["signal"] is None:
        return {"status": "unavailable", "reason": "buyer_quality_fields_missing"}
    return out


def _include_failed(payload: dict[str, Any], name: str) -> bool:
    errors = payload.get("include_errors")
    if isinstance(errors, dict):
        return name in errors
    if isinstance(errors, list):
        return any(e == name or (isinstance(e, dict) and (e.get("name") == name or e.get("include") == name)) for e in errors)
    return False


def parse_token(payload: Any, mint: str, key: str | None) -> dict[str, Any]:
    """The token part (GET /token/<mint>?include=deployer,buyer_quality), field names as in the live answer of
    2026-10-19: the snapshot under `token` (deployer reputation `deployer`, `kol_activity`, `early_buyer_exit`,
    `launch_cohort_sol` / `launch_cohort_size`), the embedded `deployer_profile` and `buyer_quality`.
    Loud guards: no `token` object gives unavailable (token_missing); a snapshot for another mint gives unavailable
    (identity_mismatch); a snapshot with none of its blocks readable gives unavailable (token_fields_missing). Each block
    reports its own state; an include that failed is named (include_failed), never read as empty."""
    if not isinstance(payload, dict):
        return {"status": "unavailable", "reason": "invalid_shape"}
    token = payload.get("token")
    if not isinstance(token, dict):
        return {"status": "unavailable", "reason": "token_missing"}
    seen_mint = token.get("mint")
    if seen_mint is not None and seen_mint != mint:
        return {"status": "unavailable", "reason": "identity_mismatch"}
    deployer = sanitize_deployer(token, payload.get("deployer_profile"), key)
    if deployer["status"] != "ok" and _include_failed(payload, "deployer") and not token.get("deployer"):
        deployer = {"status": "unavailable", "reason": "include_failed"}
    quality = sanitize_buyer_quality(payload.get("buyer_quality"), key)
    if quality["status"] != "ok" and _include_failed(payload, "buyer_quality"):
        quality = {"status": "unavailable", "reason": "include_failed"}
    exit_block = _dict(token.get("early_buyer_exit"))
    early = {"cohort": _count(exit_block.get("cohort")), "still_holding": _count(exit_block.get("still_holding")), "sold": _count(exit_block.get("sold")),
             "launch_cohort_sol": _number(token.get("launch_cohort_sol"), 0.0, 1e9), "launch_cohort_size": _count(token.get("launch_cohort_size"))}
    out = {
        "status": "ok", "reason": None, "identity": "confirmed" if seen_mint == mint else "not_in_answer", "as_of": _iso_time(payload.get("as_of")),
        "symbol": safe_label(token.get("symbol"), key), "name": safe_label(token.get("name"), key), "launchpad": safe_label(token.get("launchpad"), key),
        "first_seen_at": _iso_time(token.get("first_seen_at")), "age_seconds": _number(token.get("age_seconds"), 0.0, 1e10),
        "is_blacklisted": token.get("is_blacklisted") if isinstance(token.get("is_blacklisted"), bool) else None,
        "blacklist_category": safe_label(token.get("blacklist_category"), key),
        "deployer": deployer, "kol_activity": sanitize_kol(token, key), "early_buyers": early, "buyer_quality": quality,
    }
    if (deployer["status"] != "ok" and out["kol_activity"]["status"] != "ok" and quality["status"] != "ok"
            and all(v is None for v in early.values())):
        return {"status": "unavailable", "reason": "token_fields_missing"}
    return out


def parse_bundle(payload: Any, mint: str, key: str | None) -> dict[str, Any]:
    """The bundle part (GET /tokens/<mint>/bundle; BASIC: the summary `bundle` block, no wallets), field names as in the
    docs and the live answer of 2026-10-19. held_pct_of_supply is a fraction of 1 ("net held / supply, clamped 0-1"),
    kept as percent. Loud guards: an answer for another mint gives unavailable (identity_mismatch); MadeOnSol's coverage
    saying it captured no trades for the mint gives empty (not_captured: unknown, never "no bundle"); no `bundle` object
    gives unavailable (bundle_missing); a share outside 0..1 gives unavailable (bundle_unit_unexpected); a cohort without a
    readable share gives unavailable (bundle_share_field_missing)."""
    if not isinstance(payload, dict):
        return {"status": "unavailable", "reason": "invalid_shape"}
    seen_mint = payload.get("mint")
    if seen_mint is not None and seen_mint != mint:
        return {"status": "unavailable", "reason": "identity_mismatch"}
    coverage = _dict(payload.get("coverage"))
    observed = coverage.get("data_observed") if isinstance(coverage.get("data_observed"), bool) else None
    bundle = payload.get("bundle")
    if observed is False:
        return {"status": "empty", "reason": "not_captured", "eligibility": safe_label(coverage.get("eligibility"), key)}
    if not isinstance(bundle, dict):
        return {"status": "unavailable", "reason": "bundle_missing"}
    held_pct, odd = _fraction_pct(bundle.get("held_pct_of_supply"))
    held_ratio_pct, odd_ratio = _fraction_pct(bundle.get("held_ratio"))
    if odd:
        return {"status": "unavailable", "reason": "bundle_unit_unexpected"}
    kind = _choice(bundle.get("bundle_kind"), BUNDLE_KINDS)
    wallets = _count(bundle.get("wallet_count"))
    if held_pct is None and kind != "none" and wallets != 0:
        return {"status": "unavailable", "reason": "bundle_share_field_missing"}
    return {
        "status": "ok", "reason": None, "identity": "confirmed" if seen_mint == mint else "not_in_answer",
        "wallet_count": wallets, "bundle_kind": kind or safe_label(bundle.get("bundle_kind"), key), "held_pct_of_supply": held_pct,
        "held_ratio_pct": None if odd_ratio else held_ratio_pct, "fully_exited": bundle.get("fully_exited") if isinstance(bundle.get("fully_exited"), bool) else None,
        "holdings_basis": safe_label(bundle.get("holdings_basis"), key), "bundle_detection": safe_label(bundle.get("bundle_detection"), key),
        "data_observed": observed, "eligibility": safe_label(coverage.get("eligibility"), key),
    }


# ----------------------------------------------------------------------------- collect


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _base(mint: str, fetched_at: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "provider": "MadeOnSol", "mint": mint, "status": "unavailable", "reason": None, "fetched_at": fetched_at,
        "request": {"method": "GET", "host": HOST, "paths": [f"{TOKEN_PATH}?{TOKEN_QUERY}", BUNDLE_PATH], "auth_header_names": list(AUTH_HEADER_NAMES),
                    "auth_scheme": "Bearer", "tier": "BASIC (free)", "requests_per_scan": REQUESTS_PER_SCAN, "max_requests": MAX_REQUESTS,
                    "free_calls_per_day": FREE_CALLS_PER_DAY, "requests_sent": 0, "not_called": dict(PRO_ONLY)},
        "presentation_only": True, "note": PRESENTATION_NOTE, "cannot_see": CANNOT_SEE,
        "token": {"status": "not_sent", "reason": None, "http_status": None, "attempts": 0},
        "bundle": {"status": "not_sent", "reason": None, "http_status": None, "attempts": 0},
        "pro_only": {"cap_table": {"status": "not_called", "reason": PRO_NOTE}, "fee_shares": {"status": "not_called", "reason": PRO_NOTE}},
    }


def _decode(body: Any) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError, AttributeError):
        return None


def collect_madeonsol(
    mint: str,
    key: str | None,
    *,
    key_reason: str | None = None,
    opener: Any | None = None,
    now: Callable[[], float] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """The two documented requests, sent at the same time (two threads), each with at most one retry after a short 429.
    Returns the madeonsol.json result; never raises for provider or transport failures."""
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    result = _base(mint, _iso(now()))
    if not key:
        result["reason"] = key_reason or "missing_key"
        result["numbers"] = numbers(result)
        return result
    transport = opener or default_opener()
    fetched: dict[str, dict[str, Any]] = {}

    def run(part: str) -> None:
        fetched[part] = fetch_part(part, mint, key, transport, monotonic=monotonic, sleep=sleep)

    threads = [threading.Thread(target=run, args=(part,), name=f"madeonsol-{part}", daemon=True) for part in PARTS]
    for t in threads:
        t.start()
    for t in threads:  # each part is bounded by its own deadlines; this join is only a backstop
        t.join(2 * TIMEOUT_S + RETRY_MAX_WAIT_S + 5)
    for part in PARTS:
        got = fetched.get(part) or {"body": None, "attempts": 1, "reason": "timeout", "http_status": None}
        facts = {"attempts": got["attempts"], "http_status": got["http_status"]}
        if got["reason"] is not None:
            result[part] = {"status": "unavailable", "reason": got["reason"], **facts}
            continue
        payload = _decode(got["body"])
        if payload is None:
            result[part] = {"status": "unavailable", "reason": "invalid_json", **facts}
            continue
        try:
            parsed = parse_token(payload, mint, key) if part == "token" else parse_bundle(payload, mint, key)
        except Exception:  # noqa: BLE001 - a malformed answer the guards did not foresee: a fixed code, the calls still counted
            parsed = {"status": "unavailable", "reason": "parse_error"}
        result[part] = parsed | facts
    result["request"]["requests_sent"] = sum(result[p]["attempts"] for p in PARTS)
    result["fetched_at"] = _iso(now())
    states = [result[p]["status"] for p in PARTS]
    if "ok" in states:
        result.update(status="ok", reason=None)
    elif "empty" in states:
        result.update(status="empty", reason="; ".join(f"{p}: {result[p]['reason']}" for p in PARTS))
    else:
        result.update(status="unavailable", reason="; ".join(f"{p}: {result[p]['reason']}" for p in PARTS))
    result["numbers"] = numbers(result)
    return result


def numbers(result: dict[str, Any]) -> dict[str, Any]:
    """The headline values for presentation, each read or not read (with the reason); never 0 for unread. The cap table
    and the creator-fee recipients are always not read (needs MadeOnSol PRO; owner decision)."""
    tok, bun = _dict(result.get("token")), _dict(result.get("bundle"))
    tok_why = None if tok.get("status") == "ok" else f"token snapshot {tok.get('status')}" + (f": {tok.get('reason')}" if tok.get("reason") else "")
    bun_why = None if bun.get("status") == "ok" else f"bundle summary {bun.get('status')}" + (f": {bun.get('reason')}" if bun.get("reason") else "")

    def block(name: str) -> tuple[dict[str, Any], str | None]:
        if tok_why:
            return {}, tok_why
        b = _dict(tok.get(name))
        if b.get("status") != "ok":
            return b, f"{name.replace('_', ' ')} {b.get('status')}: {b.get('reason')}"
        return b, None

    def entry(value: Any, why: str | None, missing: str = "field missing") -> dict[str, Any]:
        if why:
            return {"value": None, "not_read": why}
        return {"value": value, "not_read": None if value is not None else missing}

    dep, dep_why = block("deployer")
    kol, kol_why = block("kol_activity")
    bq, bq_why = block("buyer_quality")
    early = _dict(tok.get("early_buyers"))
    odd = dep.get("units_unexpected") or []
    pro = {"value": None, "not_read": PRO_NOTE}
    return {
        "dev_wallet": entry(dep.get("wallet"), dep_why), "dev_tier": entry(dep.get("tier"), dep_why), "dev_tracked": entry(dep.get("is_tracked"), dep_why),
        "dev_tokens_deployed": entry(dep.get("tokens_deployed"), dep_why), "dev_bonded": entry(dep.get("bonded"), dep_why),
        "dev_bond_rate_pct": entry(dep.get("bond_rate_pct"), dep_why, "not a fraction of 1 as documented" if "bonding_rate" in odd else "field missing"),
        "dev_recent_bond_rate_pct": entry(dep.get("recent_bond_rate_pct"), dep_why, "not a fraction of 1 as documented" if "recent_bond_rate" in odd else "field missing"),
        "dev_best_peak_mc_usd": entry(dep.get("best_token_peak_mc_usd"), dep_why),
        "dev_holding_pct": {"value": None, "not_read": "not in the free MadeOnSol answer"},
        "bundle_held_pct": entry(bun.get("held_pct_of_supply"), bun_why, "no bundle cohort found by MadeOnSol" if bun.get("bundle_kind") == "none" else "field missing"),
        "bundle_wallets": entry(bun.get("wallet_count"), bun_why), "bundle_kind": entry(bun.get("bundle_kind"), bun_why),
        "bundle_held_ratio_pct": entry(bun.get("held_ratio_pct"), bun_why), "bundle_fully_exited": entry(bun.get("fully_exited"), bun_why),
        "bundle_holdings_basis": entry(bun.get("holdings_basis"), bun_why),
        "early_buyers": entry(early.get("cohort"), tok_why), "early_buyers_still_holding": entry(early.get("still_holding"), tok_why),
        "early_buyers_sold": entry(early.get("sold"), tok_why), "launch_cohort_sol": entry(early.get("launch_cohort_sol"), tok_why),
        "kol_buying": entry(kol.get("buying_kols"), kol_why), "kol_selling": entry(kol.get("selling_kols"), kol_why),
        "kol_buy_sol": entry(kol.get("buy_sol"), kol_why), "kol_sell_sol": entry(kol.get("sell_sol"), kol_why),
        "kol_net_flow_sol": entry(kol.get("net_flow_sol"), kol_why), "kol_signal": entry(kol.get("signal"), kol_why),
        "kol_window_hours": entry(kol.get("window_hours"), kol_why),
        "buyer_quality_score": entry(bq.get("score"), bq_why), "buyer_quality_signal": entry(bq.get("signal"), bq_why),
        "buyer_quality_confidence": entry(bq.get("confidence"), bq_why), "bundle_buyers": entry(bq.get("bundle_buyer_count"), bq_why),
        "dump_clusters": entry(bq.get("dump_cluster_count"), bq_why), "recycled_early_buyers": entry(bq.get("recycled_early_buyer_count"), bq_why),
        "cap_table": dict(pro), "fee_share_recipients": dict(pro),
    }


def status_line(result: dict[str, Any]) -> str:
    sent = result["request"]["requests_sent"]
    calls = f"{sent} MadeOnSol call{'s' if sent != 1 else ''} (free tier: {FREE_CALLS_PER_DAY} a day)" if sent else "no MadeOnSol call sent"
    parts = "; ".join(f"{p}: {result[p]['status']}" + (f" ({result[p]['reason']})" if result[p].get("reason") else "") for p in PARTS)
    if result["status"] == "ok":
        return f"ok ({parts}; cap table and fee shares not called ({PRO_NOTE}); {calls})"
    if result["status"] == "empty":
        return f"empty (MadeOnSol has no data for this token: unknown, not a reassurance; {parts}; {calls})"
    return f"unavailable ({result['reason']}; {calls})"


# ----------------------------------------------------------------------------- presentation (synthesis, offline)


TEXT_RE = re.compile(r"[^\w .:;,()%+\-']")  # saved-file text printed by --present: no newlines, no markdown marks (an apostrophe is inert)


def _text(value: Any, cap: int = 80) -> str:
    """Any text taken from a saved file before it is printed: inert characters only, capped, verdict words replaced by the
    placeholder (HS-LABELS-T1, provider_words.cut: made inert first, cut where it was cut before, then marked), also in a
    file saved before the rule."""
    return pw.cut(str(value), lambda s: " ".join(TEXT_RE.sub("", " ".join(s.split())).split()), cap) or "unknown"  # cut as before, then marked


def _level(value: Any) -> str:
    """MadeOnSol's documented confidence (low / medium / high) in this tool's words, weak / medium / strong (HS-LABELS-T1
    R3; the saved file keeps MadeOnSol's code); anything else, insufficient_data included, through _text."""
    return pw.level_text(value) or _text(value)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _fmt(value: Any) -> str:
    """4 significant digits, cut toward zero (never rounded up): 29.999% prints as 29.99%, never as a 30% that the bar
    check did not see, and a tiny share never prints as 0."""
    if not _is_number(value):
        return "unknown"
    value = float(value)
    if value == 0:
        return "0"
    scale = 10 ** (3 - math.floor(math.log10(abs(value))))
    return f"{math.trunc(value * scale + math.copysign(1e-9, value)) / scale:g}"  # the 1e-9 only absorbs binary representation error


def _usd(value: Any) -> str:
    return f"${math.trunc(value):,}" if _is_number(value) and abs(value) < 1e15 else "unknown"


KINDS = {"text": lambda v: isinstance(v, str) and bool(v.strip()), "flag": lambda v: isinstance(v, bool), "count": lambda v: isinstance(v, int) and not isinstance(v, bool) and v >= 0,
         "number": _is_number}


def _entry(numbers_block: Any, name: str, kind: str = "number") -> dict[str, Any]:
    """One value from a saved file, validated before it is shown or compared with a bar: the expected type, else not read
    with the reason. A missing or malformed numbers block reads as not read, never as 0 and never as a crash."""
    n = _dict(numbers_block).get(name)
    if not isinstance(n, dict):
        return {"value": None, "not_read": "numbers block missing" if not isinstance(numbers_block, dict) else "value missing from the file"}
    value = n.get("value")
    if value is None:
        return {"value": None, "not_read": _text(n.get("not_read") or "field missing")}
    if KINDS[kind](value):
        return {"value": value, "not_read": None}
    return {"value": None, "not_read": "malformed value in the file"}


def _show(n: dict[str, Any], fmt: Callable[[Any], str] = _fmt, suffix: str = "") -> str:
    return f"not read ({n['not_read']})" if n["value"] is None else f"{fmt(n['value'])}{suffix}"


def _block_reason(entries: list[dict[str, Any]]) -> str | None:
    """The one reason when every value of a block is unread for the same reason (printed once), else None."""
    reasons = {n["not_read"] for n in entries if n["value"] is None}
    return reasons.pop() if len(reasons) == 1 and all(n["value"] is None for n in entries) else None


def _short(address: str) -> str:
    return f"{address[:6]}...{address[-4:]}" if len(address) > 12 else address


def _cohort_text(numbers_block: Any) -> str:
    """MadeOnSol's launch cohort as it defines it, from validated values only."""
    wallets = _entry(numbers_block, "bundle_wallets", "count")["value"]
    kind = _entry(numbers_block, "bundle_kind", "text")["value"]
    how = "one atomic transaction" if kind == "atomic_tx" else "3 or more in one slot; same-slot can be coincidental"
    return (f"{wallets} wallets; " if wallets is not None else "") + f"first 20 buyers, {how}"


def _early_text(numbers_block: Any) -> str:
    """MadeOnSol's own count of the first 20 buyers still holding and sold, when the answer had both."""
    still = _entry(numbers_block, "early_buyers_still_holding", "count")["value"]
    sold = _entry(numbers_block, "early_buyers_sold", "count")["value"]
    return f"MadeOnSol's own first 20 buyers: {still} still hold, {sold} sold" if still is not None and sold is not None else ""


def late_source_lines(result: dict[str, Any] | None) -> list[str]:
    """MadeOnSol numbers at or over the existing provider bars, as the late-source line. The one bundle share MadeOnSol
    returns on the free tier is held_pct_of_supply, which it computes from swaps only: what its launch cohort bought minus
    what it sold through swaps; tokens moved out by transfer are never subtracted, so it can over-read and is not a balance
    check. It is still compared with bundles 30%+ (BUNDLE_ALARM_PCT), the cautious direction (a clear large cluster from any
    source goes next to the FLAGs), and always worded as MadeOnSol's claim, never as what the wallets hold now, with
    MadeOnSol's own first-20-buyers count beside it. The buyer-quality counts and the KOL flows have no matching bar and are
    only shown. A number under its bar adds nothing: it is never an all-clear."""
    if not isinstance(result, dict) or result.get("status") != "ok":
        return []
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:  # python3 -I leaves the script's folder off sys.path
        sys.path.insert(0, here)
    import helius_forensics as hf  # the single named thresholds; imported only for presentation (no network here)

    n = result.get("numbers")
    held = _entry(n, "bundle_held_pct")["value"]
    if held is None or held < hf.BUNDLE_ALARM_PCT:
        return []
    early = _early_text(n)
    return [f"clear large cluster seen by MadeOnSol, not yet in the engine verdicts: MadeOnSol claims its launch cohort ({_cohort_text(n)}) "
            f"bought and has not sold through swaps {_fmt(float(held))}% of supply; transfers out are not subtracted, so it can over-read; "
            f"not a balance check" + (f"; {early}" if early else "") + f" (bar: bundles {hf.BUNDLE_ALARM_PCT:g}%+ BUNDLE_ALARM_PCT)"]


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
    """The Sources-read block for MadeOnSol (Dev / deployer, launch bundle, first 20 buyers, KOL positions, buyer quality,
    the two PRO-only lines) and any late-source line. Reads only the saved file in the run folder: no network, no key. A
    missing, foreign or malformed file or value reads as not read, never as 0."""
    data = _read_json(run / OUT_FILE)
    result = data if _valid_saved(data) else None
    if result is None:
        return [f"MadeOnSol: not read ({OUT_FILE} " + ("missing" if not (run / OUT_FILE).exists() else "unreadable") + ")"]
    sent = _dict(result.get("request")).get("requests_sent")
    sent_text = f"{sent} calls of the free tier's {FREE_CALLS_PER_DAY} a day" if isinstance(sent, int) and not isinstance(sent, bool) else "calls unknown"
    age = _age_min(result.get("fetched_at"))
    state = {"ok": "read", "empty": "empty", "unavailable": "unavailable"}[result["status"]]
    head = f"MadeOnSol (collector madeonsol, free BASIC tier): {state}"
    if result["status"] != "ok":
        head += f" ({_text(result.get('reason'), 160)})"
    lines = [head + (f"; data age {age:.0f} min" if age is not None else "; data age unknown") + f"; {sent_text}"]
    pro_line = [f"  cap table: not read ({PRO_NOTE})", f"  creator-fee recipients: not read ({PRO_NOTE})"]
    if result["status"] == "ok":
        n = result.get("numbers")
        e = {name: _entry(n, name, kind) for name, kind in (
            ("dev_wallet", "text"), ("dev_tier", "text"), ("dev_tracked", "flag"), ("dev_tokens_deployed", "count"), ("dev_bonded", "count"),
            ("dev_bond_rate_pct", "number"), ("dev_recent_bond_rate_pct", "number"), ("dev_best_peak_mc_usd", "number"), ("dev_holding_pct", "number"),
            ("bundle_held_pct", "number"), ("bundle_wallets", "count"), ("bundle_kind", "text"), ("bundle_held_ratio_pct", "number"),
            ("bundle_fully_exited", "flag"), ("bundle_holdings_basis", "text"), ("early_buyers", "count"), ("early_buyers_still_holding", "count"),
            ("early_buyers_sold", "count"), ("launch_cohort_sol", "number"), ("kol_buying", "count"), ("kol_selling", "count"), ("kol_buy_sol", "number"),
            ("kol_sell_sol", "number"), ("kol_net_flow_sol", "number"), ("kol_signal", "text"), ("kol_window_hours", "number"),
            ("buyer_quality_score", "number"), ("buyer_quality_signal", "text"), ("buyer_quality_confidence", "text"), ("bundle_buyers", "count"),
            ("dump_clusters", "count"), ("recycled_early_buyers", "count"))}
        wallet = e["dev_wallet"]["value"]
        tracked = e["dev_tracked"]["value"]
        dev = ("  Dev / deployer (MadeOnSol's claims): " + (_text(_short(wallet)) if wallet else f"wallet not read ({e['dev_wallet']['not_read']})")
               + f"; tier {_show(e['dev_tier'], _text)}" + ("" if tracked is None else (" (tracked by MadeOnSol)" if tracked else " (not tracked by MadeOnSol)"))
               + f"; tokens deployed {_show(e['dev_tokens_deployed'], str)}; bonded {_show(e['dev_bonded'], str)}"
               + f"; bond rate {_show(e['dev_bond_rate_pct'], suffix='%')}; recent bond rate {_show(e['dev_recent_bond_rate_pct'], suffix='%')}"
               + f"; best token peak market cap {_show(e['dev_best_peak_mc_usd'], _usd)}; current dev holding {_show(e['dev_holding_pct'], suffix='% of supply')}")
        basis = e["bundle_holdings_basis"]["value"]
        bundle = (f"  launch bundle (MadeOnSol's claim; its launch cohort: {_cohort_text(n)}): bought and not sold through swaps "
                  f"{_show(e['bundle_held_pct'], suffix='% of supply')} (transfers out are not subtracted, so it can over-read; not a balance check"
                  + (f"; basis {_text(basis)}" if basis else "") + ")"
                  + ("" if e["bundle_held_ratio_pct"]["value"] is None else f"; not sold through swaps: {_fmt(e['bundle_held_ratio_pct']['value'])}% of what they bought")
                  + ("" if e["bundle_fully_exited"]["value"] is None else f"; all sold through swaps: {'yes' if e['bundle_fully_exited']['value'] else 'no'}"))
        early = (f"  first 20 buyers (MadeOnSol's launch cohort): {_show(e['early_buyers'], str)} buyers, {_show(e['early_buyers_still_holding'], str)} still hold, "
                 f"{_show(e['early_buyers_sold'], str)} sold; they spent {_show(e['launch_cohort_sol'], suffix=' SOL')} at launch")
        net = e["kol_net_flow_sol"]["value"]
        net_text = _show(e["kol_net_flow_sol"], suffix=" SOL") if net is None else (("+" if net > 0 else "") + _fmt(net) + " SOL")
        window = e["kol_window_hours"]["value"]
        kol = (f"  KOL positions (MadeOnSol's KOL roster" + (f", last {_fmt(window)} h" if window is not None else "") + "): "
               f"{_show(e['kol_buying'], str)} KOLs bought for {_show(e['kol_buy_sol'], suffix=' SOL')}, {_show(e['kol_selling'], str)} sold for "
               f"{_show(e['kol_sell_sol'], suffix=' SOL')}, net {net_text}; MadeOnSol's signal {_show(e['kol_signal'], _text)}; names are not on the free tier")
        quality = (f"  buyer quality (MadeOnSol's 0-100 score over the first 20 buyers, its claim): {_show(e['buyer_quality_score'])} "
                   f"(signal {_show(e['buyer_quality_signal'], _text)}, data confidence {_show(e['buyer_quality_confidence'], _level)}); "
                   f"bundle buyers {_show(e['bundle_buyers'], str)}, recycled early buyers {_show(e['recycled_early_buyers'], str)}, "
                   f"dump clusters {_show(e['dump_clusters'], str)}")
        blocks = [dev, bundle, early, kol, quality]
        for index, (label, names) in enumerate((
                ("  Dev / deployer (MadeOnSol's claims)", ("dev_wallet", "dev_tier", "dev_tokens_deployed", "dev_bonded", "dev_bond_rate_pct", "dev_recent_bond_rate_pct",
                                                           "dev_best_peak_mc_usd")),
                ("  launch bundle (MadeOnSol's claim; first 20 buyers, 3 or more in one slot)", ("bundle_held_pct", "bundle_wallets", "bundle_kind", "bundle_held_ratio_pct",
                                                                                                      "bundle_fully_exited")),
                ("  first 20 buyers (MadeOnSol's launch cohort)", ("early_buyers", "early_buyers_still_holding", "early_buyers_sold", "launch_cohort_sol")),
                ("  KOL positions (MadeOnSol's KOL roster)", ("kol_buying", "kol_selling", "kol_buy_sol", "kol_sell_sol", "kol_net_flow_sol", "kol_signal")),
                ("  buyer quality (MadeOnSol's 0-100 score over the first 20 buyers, its claim)", ("buyer_quality_score", "buyer_quality_signal", "buyer_quality_confidence")))):
            reason = _block_reason([e[name] for name in names])
            if reason is not None:  # every value of the block unread for one reason: say it once (still never 0)
                blocks[index] = f"{label}: not read ({reason})" + (f"; current dev holding {_show(e['dev_holding_pct'])}" if index == 0 else "")
        lines += blocks
    lines += pro_line + [f"  cannot see: {CANNOT_SEE}", f"  {PRESENTATION_NOTE}"]
    lines += late_source_lines(result)
    removed = pw.count(lines)
    if removed:  # HS-LABELS-T1: say how many placeholders this block shows
        lines.append(f"  {pw.removed_line(removed)}")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read MadeOnSol's token snapshot (with the deployer profile and buyer quality embedded) and its "
                                                 "launch-bundle summary for a Solana mint (two calls at once on the free BASIC tier; bounded: 4 MiB, "
                                                 "30 s, no redirects, no env proxy, at most one retry each after a short 429) and save "
                                                 f"{OUT_FILE}; or, with --present RUN_DIR, print the synthesis's Sources-read block offline. "
                                                 "Presentation only: never an engine input.")
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
        result = collect_madeonsol(mint, key, key_reason=reason)
    except Exception:  # noqa: BLE001 - never print a traceback (it could carry request details)
        result = _base(mint, _iso(time.time()))
        result["reason"] = "request_failed"
        result["numbers"] = numbers(result)
    try:
        (out / OUT_FILE).write_text(json.dumps(result, indent=1), encoding="utf-8")
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    print(status_line(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
