#!/usr/bin/env python3
"""Solana Tracker token risk numbers and bundler list for dlmm-scan (first-wave collector `solanatracker`): two fixed,
bounded, read-only requests sent at the same time.

PRESENTATION ONLY. Solana Tracker's numbers never feed either engine: they are shown in the synthesis's "Sources read"
and, at or over the existing provider bars (bundler share held now against bundles 30%+ BUNDLE_ALARM_PCT; insiders, one
linked group of wallets, i.e. a cluster, against largest cluster 15%+ CLUSTER_ALARM_PCT), as "clear large cluster seen by
Solana Tracker, not yet in the engine verdicts" next to the FLAGs (the late-source rule). helius_forensics.py refuses
Solana Tracker as a --providers-json provider (exit 2). A low number is never an all-clear, never counts toward NO_ALARM and
never softens a FLAG. Solana Tracker's bundler, sniper and insider definitions are its own: name its numbers next to
GMGN's and Jupiter's, never merge or average them.

Requests (provider-docs cache, solanatracker fulldocs.md "Get Token Information" and "Get Token Bundlers"):
  GET /tokens/<mint>            the token object with its risk object (snipers, insiders, bundlers (the docs say it may be
                                omitted), top10, dev, score, rugged, risks) and the holder count
  GET /tokens/<mint>/bundlers   the top 500 bundler wallets and statistics
Both on host data.solanatracker.io only, https only, the key in the x-api-key header, no redirects, no environment proxy,
4 MiB and a hard 30 s wall-clock limit per attempt (opening, every read and closing under one deadline, worker thread,
like gmgn_rows.py), and at most one retry per request, only after a 429 whose Retry-After ends within 5 s (1.5 s backoff
when none is given). Requests per scan: 2 (at most 4 with the retries).

Key: only SOLANATRACKER_API_KEY, from the environment first, then exactly that one variable from the repository .env
(single-variable parser; the file is never sourced). It is sent only in the x-api-key header and is never printed,
logged, saved or put in an error: every failure becomes a fixed reason code. Provider text is untrusted: risk factor
names are reduced to short inert labels, levels to a short allowlist, every other kept value is a validated number,
flag or address, and any kept text whose raw form or label shares 8 or more consecutive characters with the key (or with
the key stripped of the characters a label cannot hold) is dropped; address fields use the same shared-piece check.

A renamed load-bearing field is loud, never ok: a token answer without a risk object gives the token part unavailable
(risk_missing); a risk object with none of snipers / insiders / bundlers / top10 / dev readable gives unavailable
(risk_fields_missing); a token answer for another mint gives unavailable (identity_mismatch); a bundlers answer without a
wallet list gives unavailable (bundler_list_missing); a wallet list where no wallet has a readable share and no total is
given gives unavailable (bundler_share_field_missing). A number that is not read is reported as not read, never as 0.

Collector: solanatracker.py <MINT> --out <RUN> writes <RUN>/solanatracker.json and prints one line: ok (...), empty (...)
or unavailable (<reason>; ...). Exit 0 whenever the file was saved; exit 2 for a bad mint or an unwritable --out.
Synthesis (offline, no network, no key): solanatracker.py --present <RUN> prints the Sources-read block, any late-source
line and the bundler numbers of GMGN, Jupiter and Solana Tracker side by side. Standard library only; Python >= 3.10.
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

HOST = "data.solanatracker.io"
TOKEN_PATH = "/tokens/<MINT>"
BUNDLERS_PATH = "/tokens/<MINT>/bundlers"
PARTS = ("token_risk", "bundlers")
MAX_BYTES = 4 * 1024 * 1024
TIMEOUT_S = 30.0                 # per attempt: a hard wall-clock limit on open + every read + close (worker thread)
RETRY_MAX_WAIT_S = 5.0           # retry a 429 once only when its Retry-After ends this soon
RETRY_DEFAULT_WAIT_S = 1.5       # backoff when a 429 carries no Retry-After (free plan: 3 requests per second)
REQUESTS_PER_SCAN = 2
MAX_REQUESTS = 4                 # each of the two requests retried at most once
USER_AGENT = "holder-scan-solanatracker/1.0"
KEY_NAME = "SOLANATRACKER_API_KEY"
AUTH_HEADER_NAMES = ("x-api-key",)
KEY_RE = re.compile(r"^[\x21-\x7e]{8,512}$")  # printable, no spaces: a valid header value; the value is never echoed
KEY_PIECE = 8                    # provider text sharing this many consecutive characters with the key is dropped
SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
LABEL_RE = re.compile(r"[^\w .\-]")  # the forensics adapter's LABEL_RE: letters, digits, _, space, dot and hyphen only
VALUE_PCT_RE = re.compile(r"^\s*([0-9]{1,3}(?:\.[0-9]{1,6})?)\s*%\s*$")
LEVELS = frozenset({"danger", "warning", "info"})
# HS-LABELS-T1 R3: Solana Tracker's two documented liquidity risk names (exact whole name, any case or spacing) are kept as
# Solana Tracker's own code in solanatracker.json and printed in this tool's words, never as the provider's "low"
DOCUMENTED_RISK_NAMES = {"very low liquidity": ("Very Low Liquidity", "very thin liquidity"), "low liquidity": ("Low Liquidity", "thin liquidity")}
RISK_GROUPS = ("snipers", "insiders", "bundlers")
BUNDLER_WALLETS_KEPT = 500       # the bundlers list is documented as the top 500 bundler wallets
RISK_FACTORS_KEPT = 30
OUT_FILE = "solanatracker.json"
SCHEMA = "holder-scan-solanatracker/1"
HTTP_REASONS = {400: "bad_request", 401: "authentication_failed", 403: "access_denied", 404: "not_found", 429: "rate_limited"}
CANNOT_SEE = ("its own bundler, sniper and insider definitions (not GMGN's, Jupiter's or Bubblemaps'); the bundlers list is "
              "capped at the top 500 bundler wallets; the risk object may omit bundlers; no funding links between wallets, "
              "so no funding cohorts")
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
    """(key, None) or (None, reason). Environment first, then exactly the one SOLANATRACKER_API_KEY line of the .env;
    no other line is kept. Never logs or returns the value in a reason."""
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
    return f"/tokens/{quoted}" if part == "token_risk" else f"/tokens/{quoted}/bundlers"


def check_url(url: str, mint: str) -> None:
    """https only, host data.solanatracker.io only, one of the two documented paths for this mint only, no query, no
    port other than 443, no credentials in the URL."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise Failure("scheme_not_https")
    if parsed.hostname != HOST or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise Failure("host_not_allowlisted")
    if parsed.path not in {part_path(p, mint) for p in PARTS} or parsed.query or parsed.params or parsed.fragment:
        raise Failure("path_not_allowlisted")


def build_request(part: str, mint: str, key: str) -> urllib.request.Request:
    url = f"https://{HOST}{part_path(part, mint)}"
    check_url(url, mint)
    request = urllib.request.Request(url, method="GET")
    request.headers["x-api-key"] = key  # set directly so the header keeps the documented name
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", USER_AGENT)
    return request


def default_opener() -> urllib.request.OpenerDirector:
    """No environment proxy (an explicit empty ProxyHandler), no redirects, default TLS verification."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def _bounded_call(function: Callable[[], Any], timeout: float) -> Any:
    """Run one blocking transport step (open, read, close) in a daemon worker and wait at most `timeout` seconds: a hard
    wall-clock bound, the same way gmgn_rows.py and solscanner_scan.py do it. A socket timeout alone restarts on every
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

    worker = threading.Thread(target=invoke, name="solanatracker-transport", daemon=True)
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
    """The wait a 429 allows before the one retry: Retry-After seconds within RETRY_MAX_WAIT_S, RETRY_DEFAULT_WAIT_S when
    the header is absent, None (no retry) when it asks for longer or is unreadable."""
    headers = getattr(exc, "headers", None)
    raw = headers.get("Retry-After") if headers is not None else None
    if raw is None:
        return RETRY_DEFAULT_WAIT_S
    text = str(raw).strip()
    if not re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,3})?", text):
        return None
    wait = max(0.5, float(text))
    return wait if wait <= RETRY_MAX_WAIT_S else None


def send_once(request: urllib.request.Request, opener: Any, mint: str, *, monotonic: Callable[[], float]) -> bytes:
    """One attempt. Returns the body (at most MAX_BYTES) or raises Failure with a fixed code. Opening, every read and the
    error close run under one hard wall-clock deadline of TIMEOUT_S, so the attempt ends by then whatever the server does.
    An error body is never read."""
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


def pct(value: Any) -> float | None:
    """A share of total supply in percent (Solana Tracker's unit: 0 to 100)."""
    return _number(value, 0.0, 100.0)


def _count(value: Any) -> int | None:
    number = _number(value, 0, 10**9)
    return int(number) if number is not None and number.is_integer() else None


def _address(value: Any, key: str | None) -> str | None:
    """A Solana address, dropped when it shares a KEY_PIECE run with the key (not only when it equals it)."""
    return value if isinstance(value, str) and SOLANA_ADDRESS_RE.fullmatch(value) and not echoes_key(value, key) else None


def _unix_ms(value: Any) -> int | None:
    """bundleTime as Solana Tracker sends it (unix milliseconds), kept only when plausible (2010 to one day ahead)."""
    number = _number(value, 1_262_304_000_000, (time.time() + 86_400) * 1000)
    return int(number) if number is not None else None


def _bundler_wallets(items: Any, key: str | None) -> tuple[list[dict[str, Any]], int]:
    """Bundler wallet rows kept as {wallet, percentage, initialPercentage, bundleTime} (the live answer's names);
    invalid or key-equal addresses are dropped. Returns (rows, dropped)."""
    rows: list[dict[str, Any]] = []
    dropped = 0
    for item in items if isinstance(items, list) else []:
        address = _address(item.get("wallet"), key) if isinstance(item, dict) else None
        if address is None:
            dropped += 1
            continue
        rows.append({"wallet": address, "percentage": pct(item.get("percentage")), "initialPercentage": pct(item.get("initialPercentage")),
                     "bundleTime": _unix_ms(item.get("bundleTime"))})
    return rows[:BUNDLER_WALLETS_KEPT], dropped


def sanitize_risk(risk: dict[str, Any], key: str | None) -> dict[str, Any]:
    """The risk object limited to the fields this collector reads, with Solana Tracker's own names. The groups' wallet
    lists are not kept (the docs name their wallet field `address`, the live answer of 2026-10-19 `wallet`; the
    bundlers request supplies the full bundler list)."""
    out: dict[str, Any] = {}
    for group in RISK_GROUPS:
        value = risk.get(group)
        if isinstance(value, dict):
            out[group] = {"count": _count(value.get("count")), "totalPercentage": pct(value.get("totalPercentage"))}
            if group == "bundlers":
                out[group]["totalInitialPercentage"] = pct(value.get("totalInitialPercentage"))
    if "top10" in risk:
        out["top10"] = pct(risk.get("top10"))
    dev = risk.get("dev")
    if isinstance(dev, dict):
        out["dev"] = {"percentage": pct(dev.get("percentage")), "amount": _number(dev.get("amount"), 0.0, 1e30)}
    out["score"] = _number(risk.get("score"), 0.0, 10.0)
    out["rugged"] = risk.get("rugged") if isinstance(risk.get("rugged"), bool) else None
    factors = []
    for item in risk.get("risks") if isinstance(risk.get("risks"), list) else []:
        if not isinstance(item, dict):
            continue
        raw_name = item.get("name")
        documented = DOCUMENTED_RISK_NAMES.get(" ".join(raw_name.split()).lower()) if isinstance(raw_name, str) else None
        name = documented[0] if documented and not echoes_key(raw_name, key) else safe_label(raw_name, key)
        if not name:
            continue
        level = item.get("level")
        level = level.strip().lower() if isinstance(level, str) and level.strip().lower() in LEVELS else None
        value = item.get("value")
        match = VALUE_PCT_RE.fullmatch(value) if isinstance(value, str) else None
        factors.append({"name": name, "level": level, "score": _number(item.get("score"), 0.0, 1e6), "value_pct": pct(float(match.group(1))) if match else None})
    out["risks"] = factors[:RISK_FACTORS_KEPT]
    return out


def readable_risk_fields(risk: dict[str, Any]) -> list[str]:
    """Which load-bearing risk numbers were readable (group shares or counts, top10, dev share)."""
    found = [g for g in RISK_GROUPS if isinstance(risk.get(g), dict) and (risk[g]["totalPercentage"] is not None or risk[g]["count"] is not None)]
    if risk.get("top10") is not None:
        found.append("top10")
    if isinstance(risk.get("dev"), dict) and risk["dev"]["percentage"] is not None:
        found.append("dev")
    return found


def parse_token(payload: Any, mint: str, key: str | None) -> dict[str, Any]:
    """The token-risk part: {status, reason, holders, risk}."""
    if not isinstance(payload, dict):
        return {"status": "unavailable", "reason": "invalid_shape"}
    token = payload.get("token")
    seen_mint = token.get("mint") if isinstance(token, dict) else None
    if seen_mint is not None and seen_mint != mint:
        return {"status": "unavailable", "reason": "identity_mismatch"}
    risk = payload.get("risk")
    if not isinstance(risk, dict):
        return {"status": "unavailable", "reason": "risk_missing"}
    sanitized = sanitize_risk(risk, key)
    if not readable_risk_fields(sanitized):
        return {"status": "unavailable", "reason": "risk_fields_missing"}
    return {"status": "ok", "reason": None, "identity": "confirmed" if seen_mint == mint else "not_in_answer", "holders": _count(payload.get("holders")), "risk": sanitized}


def parse_bundlers(payload: Any, key: str | None) -> dict[str, Any]:
    """The bundlers part: {status, reason, total, percentage, initialPercentage, listed_sum_pct, wallets}, with the live
    answer's names (2026-10-19: total = bundler wallets, percentage = share of supply they hold now, initialPercentage =
    share they bought; the docs do not list these fields). An empty list is empty (unknown), never zero."""
    if not isinstance(payload, dict):
        return {"status": "unavailable", "reason": "invalid_shape"}
    items = payload.get("wallets")
    if not isinstance(items, list):
        return {"status": "unavailable", "reason": "bundler_list_missing"}
    wallets, dropped = _bundler_wallets(items, key)
    base = {"total": _count(payload.get("total")), "percentage": pct(payload.get("percentage")), "initialPercentage": pct(payload.get("initialPercentage"))}
    if not items:
        return {"status": "empty", "reason": "bundler_list_empty", **base, "listed_sum_pct": None, "wallets_dropped": 0, "wallets": []}
    shares = [w["percentage"] for w in wallets if w["percentage"] is not None]
    if base["percentage"] is None and not shares:  # a renamed share field must be loud, never "0% bundled"
        return {"status": "unavailable", "reason": "bundler_share_field_missing"}
    return {"status": "ok", "reason": None, **base, "listed_sum_pct": round(sum(shares), 6) if shares else None, "wallets_dropped": dropped, "wallets": wallets}


# HS-T3-CREATESLOT: the token's creation fields, kept as the free pointer of the create_slot_trace follow-up lane, which
# verifies them on-chain. No new request: they ride in the GET /tokens/<mint> answer read above. Field names: the cached
# docs' creation object (fulldocs.md changelog "Pool creation data": a `creation` object with `creator`, `created_tx` and
# `created_time`; "Token creation is also available on the Data API"). Only the creator address, the creation signature
# and the creation time are kept, each validated; any other creation text is dropped. A missing creation object or
# signature is recorded as absent with a fixed reason, never guessed; a creator or time that fails its check is dropped.
SIGNATURE_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{64,90}$")
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
CREATION_MIN_TS = 1_577_836_800  # 2020-01-01T00:00:00Z: no Solana mainnet token is older


def _signature(value: Any, key: str | None) -> str | None:
    """A transaction signature (base58 of exactly 64 bytes), dropped when it shares a KEY_PIECE run with the key."""
    if not isinstance(value, str) or not SIGNATURE_RE.fullmatch(value) or echoes_key(value, key):
        return None
    number = 0
    for char in value:
        number = number * 58 + B58_ALPHABET.index(char)
    size = (number.bit_length() + 7) // 8 + len(value) - len(value.lstrip("1"))
    return value if size == 64 else None


def _creation_time(value: Any, now: float) -> int | None:
    """created_time in unix seconds (a value in unix milliseconds, the unit of the docs' createdAt, is converted), kept
    only when plausible: 2020 to one day ahead."""
    number = _number(value, 0.0, 1e15)
    if number is None or not number.is_integer():
        return None
    seconds = int(number) // 1000 if number >= 1e11 else int(number)
    return seconds if CREATION_MIN_TS <= seconds <= now + 86_400 else None


def parse_creation(payload: Any, mint: str, key: str | None, now: float) -> dict[str, Any]:
    """{status: ok, created_tx, creator, created_time} or {status: absent, reason} from the token answer."""
    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(token, dict):
        return {"status": "absent", "reason": "token_missing"}
    if token.get("mint") is not None and token.get("mint") != mint:
        return {"status": "absent", "reason": "identity_mismatch"}
    creation = token.get("creation")
    if not isinstance(creation, dict):
        return {"status": "absent", "reason": "creation_missing"}
    signature = _signature(creation.get("created_tx"), key)
    if signature is None:
        return {"status": "absent", "reason": "created_tx_missing" if creation.get("created_tx") is None else "created_tx_invalid"}
    return {"status": "ok", "reason": None, "created_tx": signature, "creator": _address(creation.get("creator"), key),
            "created_time": _creation_time(creation.get("created_time"), now)}


# ----------------------------------------------------------------------------- collect


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _base(mint: str, fetched_at: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "provider": "Solana Tracker", "mint": mint, "status": "unavailable", "reason": None, "fetched_at": fetched_at,
        "request": {"method": "GET", "host": HOST, "paths": [TOKEN_PATH, BUNDLERS_PATH], "auth_header_names": list(AUTH_HEADER_NAMES),
                    "requests_per_scan": REQUESTS_PER_SCAN, "max_requests": MAX_REQUESTS, "requests_sent": 0},
        "presentation_only": True, "note": PRESENTATION_NOTE, "cannot_see": CANNOT_SEE,
        "token_risk": {"status": "not_sent", "reason": None, "http_status": None, "attempts": 0},
        "bundlers": {"status": "not_sent", "reason": None, "http_status": None, "attempts": 0},
    }


def _decode(body: Any) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError, AttributeError):
        return None


def collect_solanatracker(
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
    Returns the solanatracker.json result; never raises for provider or transport failures."""
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    result = _base(mint, _iso(now()))
    if not key:
        result["reason"] = key_reason or "missing_key"
        return result
    transport = opener or default_opener()
    fetched: dict[str, dict[str, Any]] = {}

    def run(part: str) -> None:
        fetched[part] = fetch_part(part, mint, key, transport, monotonic=monotonic, sleep=sleep)

    threads = [threading.Thread(target=run, args=(part,), name=f"solanatracker-{part}", daemon=True) for part in PARTS]
    for t in threads:
        t.start()
    for t in threads:  # each part is bounded by its own deadlines; this join is only a backstop
        t.join(2 * TIMEOUT_S + RETRY_MAX_WAIT_S + 5)
    creation: dict[str, Any] = {"status": "not_read", "reason": "token_answer_not_read"}  # HS-T3-CREATESLOT
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
        if part == "token_risk":
            creation = parse_creation(payload, mint, key, now())
        parsed = parse_token(payload, mint, key) if part == "token_risk" else parse_bundlers(payload, key)
        result[part] = parsed | facts
    result["creation"] = creation
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
    """The headline numbers for presentation, each read or not read (with the reason); never 0 for unread."""
    tok, bun = result.get("token_risk") or {}, result.get("bundlers") or {}
    risk = tok.get("risk") or {}
    tok_why = None if tok.get("status") == "ok" else f"token risk {tok.get('status')}: {tok.get('reason')}"
    bun_why = None if bun.get("status") == "ok" else f"bundlers list {bun.get('status')}: {bun.get('reason')}"

    def entry(value: Any, why_part: str | None, missing: str = "field missing") -> dict[str, Any]:
        if why_part:
            return {"value": None, "not_read": why_part}
        return {"value": value, "not_read": None if value is not None else missing}

    def group(name: str, field: str) -> Any:
        g = risk.get(name)
        return g.get(field) if isinstance(g, dict) else None

    # Solana Tracker may omit the whole bundlers group (documented); a group without its share field is a missing field
    risk_bundlers_missing = "field missing" if isinstance(risk.get("bundlers"), dict) else "omitted by Solana Tracker"

    bundle_now = bun.get("percentage")
    return {
        "bundlers_list_pct": entry(bundle_now if bundle_now is not None else bun.get("listed_sum_pct"), bun_why),
        "bundlers_list_pct_basis": None if bun_why else ("total share held now" if bundle_now is not None else "sum of the listed wallets (a floor)"),
        "bundlers_list_initial_pct": entry(bun.get("initialPercentage"), bun_why),
        "bundlers_list_wallets": entry(bun.get("total") if bun.get("total") is not None else (len(bun.get("wallets") or []) or None), bun_why),
        "bundlers_risk_pct": entry(group("bundlers", "totalPercentage"), tok_why, risk_bundlers_missing),
        "bundlers_risk_initial_pct": entry(group("bundlers", "totalInitialPercentage"), tok_why, risk_bundlers_missing),
        "bundlers_risk_wallets": entry(group("bundlers", "count"), tok_why, risk_bundlers_missing),
        "snipers_pct": entry(group("snipers", "totalPercentage"), tok_why),
        "snipers_wallets": entry(group("snipers", "count"), tok_why),
        "insiders_pct": entry(group("insiders", "totalPercentage"), tok_why),
        "insiders_wallets": entry(group("insiders", "count"), tok_why),
        "dev_pct": entry((risk.get("dev") or {}).get("percentage"), tok_why),
        "top10_pct": entry(risk.get("top10"), tok_why),
        "holder_count": entry(tok.get("holders"), tok_why),
        "risk_score": entry(risk.get("score"), tok_why),
        "rugged": entry(risk.get("rugged"), tok_why),
    }


def status_line(result: dict[str, Any]) -> str:
    sent = result["request"]["requests_sent"]
    calls = f"{sent} Solana Tracker request{'s' if sent != 1 else ''}" if sent else "no Solana Tracker request sent"
    parts = "; ".join(f"{p.replace('_', ' ')}: {result[p]['status']}" + (f" ({result[p]['reason']})" if result[p].get("reason") else "") for p in PARTS)
    if result["status"] == "ok":
        return f"ok ({parts}; {calls})"
    if result["status"] == "empty":
        return f"empty (Solana Tracker lists no bundler wallets and gave no risk numbers: unknown, not a reassurance; {parts}; {calls})"
    return f"unavailable ({result['reason']}; {calls})"


# ----------------------------------------------------------------------------- presentation (synthesis, offline)


TEXT_RE = re.compile(r"[^\w .:;,()%+\-]")  # saved-file text printed by --present: no newlines, no markdown marks


def _text(value: Any, cap: int = 80) -> str:
    """Any text taken from a saved file before it is printed: inert characters only, capped, verdict words replaced by the
    placeholder (HS-LABELS-T1, provider_words.cut: made inert first, cut where it was cut before, then marked)."""
    return pw.cut(str(value), lambda s: " ".join(TEXT_RE.sub("", " ".join(s.split())).split()), cap) or "unknown"  # cut as before, then marked


def _risk_name(name: str) -> str:
    """A risk-factor name for printing: a documented liquidity name in this tool's words ("very thin liquidity"), anything
    else through _text (provider text: the rule)."""
    documented = DOCUMENTED_RISK_NAMES.get(" ".join(name.split()).lower())
    return documented[1] if documented else _text(name, 32)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _fmt(value: Any) -> str:
    """4 significant digits, cut toward zero (never rounded up): 14.999% prints as 14.99%, never as a 15% that the bar
    check did not see, and a tiny share never prints as 0."""
    if not isinstance(value, float) or value == 0 or not math.isfinite(value):
        return str(value) if not isinstance(value, float) else f"{value:g}"
    scale = 10 ** (3 - math.floor(math.log10(abs(value))))
    return f"{math.trunc(value * scale + math.copysign(1e-9, value)) / scale:g}"  # the 1e-9 only absorbs binary representation error


def _entry(numbers_block: Any, name: str, kind: str = "number") -> dict[str, Any]:
    """One headline number from a saved file, validated before it is shown or compared with a bar: a finite number (a
    true/false flag for `rugged`), else not read with the reason. A missing or malformed numbers block reads as not
    read, never as 0 and never as a crash."""
    n = _dict(numbers_block).get(name)
    if not isinstance(n, dict):
        return {"value": None, "not_read": "numbers block missing" if not isinstance(numbers_block, dict) else "number missing from the file"}
    value = n.get("value")
    if value is None:
        return {"value": None, "not_read": _text(n.get("not_read") or "field missing")}
    if (isinstance(value, bool) if kind == "flag" else _is_number(value)):
        return {"value": value, "not_read": None}
    return {"value": None, "not_read": "malformed value in the file"}


def _line(label: str, n: dict[str, Any], unit: str = "% of supply") -> str:
    if n["value"] is None:
        return f"{label}: not read ({n['not_read']})"
    return f"{label}: {_fmt(n['value'])}{unit}"


def _count_text(n: dict[str, Any], suffix: str) -> str:
    value = n["value"]
    return f", {value} {suffix}" if isinstance(value, int) and not isinstance(value, bool) else ""


def late_source_lines(result: dict[str, Any] | None) -> list[str]:
    """Solana Tracker numbers at or over the existing provider bars, as the late-source line. The bundler share held now
    (either source) against bundles 30%+ (BUNDLE_ALARM_PCT); insiders, one linked group of wallets (a cluster), against
    largest cluster 15%+ (CLUSTER_ALARM_PCT). Snipers, the developer share and the top-10 share have no matching bar and
    are shown only. A number under its bar adds nothing: it is never an all-clear."""
    if not isinstance(result, dict) or result.get("status") != "ok":
        return []
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:  # python3 -I leaves the script's folder off sys.path
        sys.path.insert(0, here)
    import helius_forensics as hf  # the single named thresholds; imported only for presentation (no network here)

    checks = [
        ("bundlers_list_pct", "bundlers hold {v}% of supply (bundlers list)", hf.BUNDLE_ALARM_PCT, "bundles", "BUNDLE_ALARM_PCT"),
        ("bundlers_risk_pct", "bundlers hold {v}% of supply (token risk object)", hf.BUNDLE_ALARM_PCT, "bundles", "BUNDLE_ALARM_PCT"),
        ("insiders_pct", "insiders hold {v}% of supply (one linked group)", hf.CLUSTER_ALARM_PCT, "largest cluster", "CLUSTER_ALARM_PCT"),
    ]
    out = []
    for field, text, bar, bar_name, constant in checks:
        value = _entry(result.get("numbers"), field)["value"]
        if value is not None and value >= bar:
            out.append(f"clear large cluster seen by Solana Tracker, not yet in the engine verdicts: {text.format(v=_fmt(float(value)))} "
                       f"(Solana Tracker's own definition; bar: {bar_name} {bar:g}%+ {constant})")
    return out


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None


def _valid_saved(data: Any, schema: str) -> bool:
    return isinstance(data, dict) and data.get("schema") == schema and data.get("status") in ("ok", "empty", "unavailable")


def bundler_side_by_side(run: Path, result: dict[str, Any] | None) -> str:
    """GMGN's, Jupiter's and Solana Tracker's bundler numbers on one line, each named with its own definition and
    window; never averaged, never one cancelling another. Every value is validated before it is printed."""
    parts = []
    gmgn = _read_json(run / "gmgn_top100.json")
    if _valid_saved(gmgn, "holder-scan-gmgn-rows/1") and gmgn["status"] == "ok":
        b = _dict(_dict(_dict(gmgn.get("tag_claims")).get("maker_token_tags")).get("bundler"))
        wallets, share = b.get("wallets"), b.get("share_pct")
        if isinstance(wallets, int) and not isinstance(wallets, bool) and _is_number(share):
            parts.append(f"GMGN claims bundler on {wallets} wallets, {_fmt(float(share))}% of supply (top 100)")
        elif b:
            parts.append("GMGN: bundler claim unreadable in its file")
        else:
            parts.append("GMGN tags no bundler in its top 100 (its claim; not an all-clear)")
    else:
        parts.append("GMGN: not read" + (f" ({_text(gmgn['status'])}: {_text(gmgn.get('reason'))})" if _valid_saved(gmgn, "holder-scan-gmgn-rows/1") else ""))
    jup = _read_json(run / "jupiter_top100.json")
    if _valid_saved(jup, "holder-scan-jupiter-rows/1") and jup["status"] == "ok":
        b = _dict(_dict(jup.get("tag_claims")).get("tags")).get("bundler")
        wallets = _dict(b).get("wallets")
        if jup.get("tag_fields_present") is not True:
            parts.append("Jupiter: tags unknown (no text tag field in any row)")
        elif isinstance(wallets, int) and not isinstance(wallets, bool):
            parts.append(f"Jupiter claims bundler on {wallets} wallets (top 100; its rows carry token amounts, not shares)")
        elif b is not None:
            parts.append("Jupiter: bundler claim unreadable in its file")
        else:
            parts.append("Jupiter tags no bundler in its top 100 (its claim; not an all-clear)")
    else:
        parts.append("Jupiter: not read" + (f" ({_text(jup['status'])}: {_text(jup.get('reason'))})" if _valid_saved(jup, "holder-scan-jupiter-rows/1") else ""))
    if result is not None and result.get("status") == "ok":
        n = result.get("numbers")
        parts.append("; ".join([_line("Solana Tracker bundlers list", _entry(n, "bundlers_list_pct")), _line("token risk object", _entry(n, "bundlers_risk_pct"))]))
    else:
        parts.append("Solana Tracker: not read" + (f" ({_text(result['status'])}: {_text(result.get('reason'))})" if result else ""))
    return "bundler share by provider (each its own definition and window; named side by side, never averaged): " + " | ".join(parts)


def present(run: Path) -> list[str]:
    """The Sources-read block for Solana Tracker, any late-source line, and the bundler numbers side by side. Reads only
    saved files in the run folder: no network, no key. A missing, foreign or malformed file or field reads as not read."""
    data = _read_json(run / OUT_FILE)
    result = data if _valid_saved(data, SCHEMA) and data.get("presentation_only") is True else None
    lines = []
    if result is None:
        lines.append(f"Solana Tracker: not read ({OUT_FILE} " + ("missing" if not (run / OUT_FILE).exists() else "unreadable") + ")")
    else:
        sent = _dict(result.get("request")).get("requests_sent")
        sent_text = f"{sent} requests" if isinstance(sent, int) and not isinstance(sent, bool) else "requests unknown"
        age = None
        try:
            fetched = dt.datetime.fromisoformat(str(result.get("fetched_at")).replace("Z", "+00:00"))
            age = max(0.0, (dt.datetime.now(dt.timezone.utc) - fetched).total_seconds() / 60)
        except (ValueError, TypeError, OverflowError):
            pass
        state = {"ok": "read", "empty": "empty", "unavailable": "unavailable"}[result["status"]]
        head = f"Solana Tracker (collector solanatracker): {state}"
        if result["status"] != "ok":
            head += f" ({_text(result.get('reason'), 160)})"
        head += f"; data age {age:.0f} min" if age is not None else "; data age unknown"
        lines.append(f"{head}; {sent_text}")
        if result["status"] == "ok":
            n = result.get("numbers")
            e = {name: _entry(n, name, "flag" if name == "rugged" else "number") for name in (
                "bundlers_list_pct", "bundlers_list_initial_pct", "bundlers_list_wallets", "bundlers_risk_pct", "bundlers_risk_initial_pct", "bundlers_risk_wallets",
                "snipers_pct", "snipers_wallets", "insiders_pct", "insiders_wallets", "dev_pct", "top10_pct", "holder_count", "risk_score", "rugged")}
            basis = _dict(n).get("bundlers_list_pct_basis")
            lines += [
                "  " + _line("bundlers now (bundlers list" + (f", {_text(basis)}" if isinstance(basis, str) else "") + ")", e["bundlers_list_pct"])
                + _count_text(e["bundlers_list_wallets"], "wallets")
                + ("" if e["bundlers_list_initial_pct"]["value"] is None else f"; bought {_fmt(e['bundlers_list_initial_pct']['value'])}% at launch"),
                "  " + _line("bundlers now (token risk object)", e["bundlers_risk_pct"]) + _count_text(e["bundlers_risk_wallets"], "wallets")
                + ("" if e["bundlers_risk_initial_pct"]["value"] is None else f"; bought {_fmt(e['bundlers_risk_initial_pct']['value'])}% at launch"),
                "  " + _line("snipers", e["snipers_pct"]) + _count_text(e["snipers_wallets"], "wallets"),
                "  " + _line("insiders", e["insiders_pct"]) + _count_text(e["insiders_wallets"], "wallets"),
                "  " + _line("developer", e["dev_pct"]),
                "  " + _line("top 10 holders", e["top10_pct"]),
                "  " + _line("holder count", e["holder_count"], unit=""),
                "  " + _line("risk score (Solana Tracker's own 1-10 score, its claim)", e["risk_score"], unit=" of 10")
                + ("" if e["rugged"]["value"] is None else f"; rugged flag: {'yes' if e['rugged']['value'] else 'no'}"),
            ]
            factors = _dict(_dict(result.get("token_risk")).get("risk")).get("risks")
            shown = [f"{_risk_name(f['name'])} ({f['level'] if f.get('level') in LEVELS else 'level unknown'})"
                     for f in (factors if isinstance(factors, list) else []) if isinstance(f, dict) and isinstance(f.get("name"), str)]
            if shown:
                lines.append("  risk factors (Solana Tracker's claims): " + ", ".join(shown[:8]) + (f", and {len(shown) - 8} more" if len(shown) > 8 else ""))
        lines.append(f"  cannot see: {CANNOT_SEE}")
        lines.append(f"  {PRESENTATION_NOTE}")
    lines += late_source_lines(result)
    lines.append(bundler_side_by_side(run, result))
    removed = pw.count(lines)
    if removed:  # HS-LABELS-T1: say how many placeholders this block shows
        lines.append(f"  {pw.removed_line(removed)}")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read Solana Tracker's token risk numbers and bundler list for a Solana mint (two requests at once; "
                                                 "free-plan key; bounded: 4 MiB, 30 s, no redirects, no env proxy, at most one retry each after a "
                                                 f"short 429) and save {OUT_FILE}; or, with --present RUN_DIR, print the synthesis's Sources-read "
                                                 "block offline. Presentation only: never an engine input.")
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
        result = collect_solanatracker(mint, key, key_reason=reason)
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
