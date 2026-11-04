#!/usr/bin/env python3
"""PDA identity reads for dlmm-scan (follow-up lane `pda_identity_reads`): what is a program-account holder row?

A holder row that is a program account (holder-analysis kind program_account / controlled_vault, or an off-curve
non-infrastructure wallet in holders.json) can be a time lock, a pool, a multisig or another program vault, and they
mean different things. This collector reads those accounts once over the free public Solana RPC (no key, no Helius
credits) and identifies two kinds, decoded from cited layouts; everything else stays "unidentified program account
(owner program <id>)", never "wallet":

(a) Streamflow streams and locks (program strmRqUCoQUgGUan5YhzUZa6KqdzwX5L6FpUxfmKg5m). The holder row is the stream's
    escrow: a token account that is its own authority, at the program address derived from ("strm", stream). The
    escrow does not name its stream, so ONE program-account lookup per escrow (getProgramAccounts on the Streamflow
    program, filtered on the stream's mint and escrow fields) finds it; at most MAX_STREAM_LOOKUPS per scan, sent at
    the same time. A target that is itself a Streamflow stream account is decoded directly. No free per-account read
    links the escrow to its stream: the cached sources derive the escrow from the stream, never the reverse, and the
    escrow's own fields name no stream. So when the lookup fails, the row stays "escrow-style token account (its own
    authority): unavailable (stream_lookup_failed, <code>)", not confirmed as Streamflow, never a guessed lock.
(b) PumpSwap pools (pump_amm program pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA): base and quote mint, which side this
    token is; a pool where this token is the QUOTE mint is infrastructure (quote side), with an --exclude hint.

Cited layouts (provider-docs cache, read by hand, never guessed):
- Streamflow stream: current/streamflow/protocol.md, Streamflow js-sdk packages/stream/solana/layout.ts (streamLayout,
  field order and sizes), constants.ts (PROGRAM_ID mainnet, ESCROW_SEED "strm", and its named struct offsets: sender 49, recipient 113,
  mint 177, closed 671, old metadata 714, which the summed field sizes reproduce), contractUtils.ts (calculateUnlockedAmount, isTokenLock). The integer fields are little-endian
  (the layout's typed fields are @solana/buffer-layout u32 / f32, little-endian; the live MAKERS stream decodes to its
  deposit second only that way).
- PumpSwap pool: current/pumpfun/idls.md, pump_amm.json (program address, account Pool discriminator
  [241,154,109,4,17,177,109,188], type Pool fields, and the create_pool seeds "pool", index, creator, base_mint,
  quote_mint). Anchor accounts: 8-byte discriminator, then the fields packed in order.
- SPL Token and Token-2022 base layouts: current/spltoken/layouts.md, token interface state.rs (Mint: 36, 8 supply,
  1 decimals, 1 is_initialized, 36 = 82 bytes; Account: 32 mint, 32 owner, 8 amount, ... = 165 bytes; u64 little-endian).
Every decoded account is validated (owner program, length, mint, timestamps, flags, amounts and the program address the
program itself would derive); a mismatch gives unavailable (layout_mismatch) for that target, never a guessed lock.

Requests (one host, POST JSON-RPC only): api.mainnet-beta.solana.com, https only, path / only, methods
getMultipleAccounts (one batch: the mint plus up to MAX_TARGETS targets, base64 with a dataSlice of DATA_SLICE_BYTES per
account) and getProgramAccounts (the escrow lookups); no key, no extra headers, no redirects, no environment proxy,
MAX_BYTES per answer and a hard TIMEOUT_S wall-clock limit per attempt (opening, every read and closing under one
deadline, worker thread, the fomoapi.py / solanatracker.py pattern), at most one retry per request and only after a 429
(Retry-After up to RETRY_MAX_WAIT_S, 10 s: the public RPC asks for 10 s; RETRY_DEFAULT_WAIT_S without one).
Calls per scan: 1 batch read plus at most MAX_STREAM_LOOKUPS lookups (at most 4; at most 8 with the 429 retries). Free.
Worst-case wall time: 2 stages (the batch, then the lookups at once), each at most about 70 s (30 s, a retry wait of at
most 10 s, 30 s; the lookup join waits 75 s): about 140 s, 10 s more than with the old 5 s wait. There is no lane-wide
deadline.

PRESENTATION ONLY: the identities are shown next to the holder rows by the synthesis (--present); this file is never an
engine input and changes no verdict, flag or threshold. A lock says when tokens can move, not who controls them.

Collector: pda_identity.py <MINT> --out <RUN> [--target ADDRESS ...] reads its targets from <RUN>/holder-analysis.json
and <RUN>/holders.json (plus any --target), writes <RUN>/followup/pda_identity_reads.json and prints one line: ok (...),
empty (...) or unavailable (<reason>; ...). Exit 0 whenever the file was saved; exit 2 for a bad mint, target or --out.
Synthesis (offline, no network): pda_identity.py --present <RUN>. Standard library only; Python >= 3.10.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import math
import queue
import re
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from ha.solana import b58decode, is_on_curve  # noqa: E402

HOST = "api.mainnet-beta.solana.com"
RPC_ENDPOINT = f"https://{HOST}"
ALLOWED_METHODS = ("getMultipleAccounts", "getProgramAccounts")
MAX_KEYS_PER_BATCH = 100         # getMultipleAccounts: at most 100 public keys per request (provider-docs helius.md)
MAX_TARGETS = MAX_KEYS_PER_BATCH - 1  # the mint rides in the same batch
MAX_STREAM_LOOKUPS = 3           # getProgramAccounts calls per scan, sent at the same time
DATA_SLICE_BYTES = 1104          # the first bytes of each account: a Streamflow stream account is 1104 bytes (live MAKERS
#                                  stream); every field read here ends by byte 819
MAX_LOOKUP_RESULTS = 2           # more than one stream naming the same escrow is ambiguous
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = 30.0                 # per attempt: a hard wall-clock limit on open + every read + close (worker thread)
RETRY_MAX_WAIT_S = 10.0          # retry a 429 once only when its Retry-After ends this soon (the public RPC asks for 10 s)
RETRY_DEFAULT_WAIT_S = 1.5       # a 429 without Retry-After is retried once after this wait
MAX_REQUESTS = 2 * (1 + MAX_STREAM_LOOKUPS)
USER_AGENT = "holder-scan-pda-identity/1.0"
SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
OUT_DIR = "followup"
OUT_FILE = "pda_identity_reads.json"
SCHEMA = "holder-scan-pda-identity/1"
HTTP_REASONS = {400: "bad_request", 401: "access_denied", 403: "access_denied", 404: "not_found", 410: "method_unavailable",
                413: "request_too_large", 429: "rate_limited", 503: "service_unavailable"}

# ----------------------------------------------------------------------------- cited program ids and layouts

SYSTEM_PROGRAM = "11111111111111111111111111111111"
TOKEN_PROGRAMS = {"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "SPL Token", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": "Token-2022"}
STREAMFLOW_PROGRAM = "strmRqUCoQUgGUan5YhzUZa6KqdzwX5L6FpUxfmKg5m"  # constants.ts PROGRAM_ID[Mainnet]
STREAMFLOW_ESCROW_SEED = b"strm"                                  # constants.ts ESCROW_SEED
PUMP_AMM_PROGRAM = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"     # pump_amm.json "address"
PUMP_AMM_POOL_DISCRIMINATOR = bytes([241, 154, 109, 4, 17, 177, 109, 188])  # pump_amm.json accounts: Pool
PUMP_AMM_POOL_SEED = b"pool"                                      # pump_amm.json create_pool: pool seeds [112,111,111,108]

# SPL token interface state.rs: Mint array_refs![src, 36, 8, 1, 1, 36]; Account array_refs![src, 32, 32, 8, 36, 1, 12, 8, 36]
MINT_LEN, MINT_SUPPLY, MINT_DECIMALS, MINT_IS_INITIALIZED = 82, 36, 44, 45
TOKEN_ACCOUNT_LEN, TOKEN_ACCOUNT_MINT, TOKEN_ACCOUNT_OWNER, TOKEN_ACCOUNT_AMOUNT, TOKEN_ACCOUNT_STATE = 165, 0, 32, 64, 108

# Streamflow js-sdk layout.ts streamLayout, offsets = the summed sizes of the fields before each one
STREAM_FIELDS_U64 = {"created_at": 9, "withdrawn_amount": 17, "canceled_at": 25, "end_time": 33, "last_withdrawn_at": 41,
                     "start_time": 409, "net_amount_deposited": 417, "period": 425, "amount_per_period": 433, "cliff": 441,
                     "cliff_amount": 449, "last_rate_change_time": 688, "funds_unlocked_at_last_rate_change": 696}
STREAM_FIELDS_ADDRESS = {"sender": 49, "recipient": 113, "mint": 177, "escrow_tokens": 209}
STREAM_FIELDS_FLAG = {"cancelable_by_sender": 457, "cancelable_by_recipient": 458, "automatic_withdrawal": 459,
                      "transferable_by_sender": 460, "transferable_by_recipient": 461, "can_topup": 462, "pausable": 539,
                      "can_update_rate": 540, "is_pda": 545, "closed": 671}
STREAM_LAYOUT_END = 819          # cancel_request_time (the last streamLayout field) ends here
STREAM_CROSS_CHECK = {"sender": 49, "recipient": 113, "mint": 177, "closed": 671, "old_metadata": 714}  # constants.ts names

# pump_amm.json type Pool after the 8-byte discriminator: pool_bump u8, index u16, creator, base_mint, quote_mint, lp_mint,
# pool_base_token_account, pool_quote_token_account (pubkeys), ...
POOL_BUMP, POOL_INDEX, POOL_CREATOR, POOL_BASE_MINT, POOL_QUOTE_MINT, POOL_LP_MINT, POOL_BASE_TA, POOL_QUOTE_TA, POOL_MIN_LEN = 8, 9, 11, 43, 75, 107, 139, 171, 203

MIN_TS = 1_609_459_200           # 2021-01-01T00:00:00Z: no Streamflow mainnet stream is older
MAX_TS = 7_258_118_400           # 2200-01-01T00:00:00Z: a later time is not a readable schedule
CLOCK_SLACK_S = 86_400

INDEPENDENCE_NOTE = "public Solana RPC, no key, free"
CANNOT_SEE = ("identifies only Streamflow streams and locks (program strmRq..., the escrow's stream found by one program-account "
              f"lookup per escrow, at most {MAX_STREAM_LOOKUPS} per scan) and PumpSwap pools (program pAMMBay...); every other program "
              "account stays unidentified with its owner program (for example other lockers, multisigs, other AMM vaults); one read at "
              "read time, no history (who funded a lock or when tokens left it is not read)")
PRESENTATION_NOTE = ("presentation only: an identity shown next to the holder row; never an engine input, never changes a FLAG, "
                     "verdict or threshold and never counts toward NO_ALARM; a lock says when tokens can move, not who controls them")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect (returning None makes urllib raise the 3xx as an HTTPError)."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class Failure(Exception):
    """A failed attempt, reduced to a fixed reason code. Never carries request or response text."""

    def __init__(self, reason: str, http_status: int | None = None, retry_wait: float | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status
        self.retry_wait = retry_wait


# ----------------------------------------------------------------------------- addresses


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    out = ""
    while number:
        number, rest = divmod(number, 58)
        out = _B58[rest] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def is_address(value: Any) -> bool:
    if not isinstance(value, str) or not SOLANA_ADDRESS_RE.fullmatch(value):
        return False
    try:
        return len(b58decode(value)) == 32
    except ValueError:
        return False


def off_curve(address: str) -> bool:
    try:
        return not is_on_curve(address)
    except ValueError:
        return False


def find_program_address(seeds: list[bytes], program_id: str) -> tuple[str | None, int | None]:
    """Solana's program-derived address: the first bump from 255 down whose sha256(seeds, bump, program, marker) is off
    the ed25519 curve (getProgramDerivedAddress / findProgramAddressSync in the cached pump.fun and Streamflow sources)."""
    program = b58decode(program_id)
    for bump in range(255, -1, -1):
        digest = hashlib.sha256(b"".join(seeds) + bytes([bump]) + program + b"ProgramDerivedAddress").digest()
        candidate = b58encode(digest)
        if off_curve(candidate):
            return candidate, bump
    return None, None


# ----------------------------------------------------------------------------- request


def check_url(url: str) -> None:
    """https only, host api.mainnet-beta.solana.com only, path / only, no query, no port other than 443, no credentials."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise Failure("scheme_not_https")
    if parsed.hostname != HOST or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise Failure("host_not_allowlisted")
    if parsed.path not in ("", "/") or parsed.query or parsed.params or parsed.fragment:
        raise Failure("path_not_allowlisted")


def build_request(payload: dict[str, Any]) -> urllib.request.Request:
    check_url(RPC_ENDPOINT)
    if payload.get("method") not in ALLOWED_METHODS:
        raise Failure("method_not_allowlisted")
    request = urllib.request.Request(RPC_ENDPOINT, data=json.dumps(payload, separators=(",", ":")).encode("utf-8"), method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", USER_AGENT)
    return request


def batch_payload(keys: list[str]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": "getMultipleAccounts",
            "params": [keys, {"encoding": "base64", "commitment": "confirmed", "dataSlice": {"offset": 0, "length": DATA_SLICE_BYTES}}]}


def lookup_payload(mint: str, escrow: str) -> dict[str, Any]:
    """The Streamflow stream naming this escrow: its mint field (offset 177) and escrow_tokens field (offset 209)."""
    filters = [{"memcmp": {"offset": STREAM_FIELDS_ADDRESS["mint"], "bytes": mint}}, {"memcmp": {"offset": STREAM_FIELDS_ADDRESS["escrow_tokens"], "bytes": escrow}}]
    return {"jsonrpc": "2.0", "id": 1, "method": "getProgramAccounts",
            "params": [STREAMFLOW_PROGRAM, {"encoding": "base64", "commitment": "confirmed", "dataSlice": {"offset": 0, "length": DATA_SLICE_BYTES}, "filters": filters}]}


def default_opener() -> urllib.request.OpenerDirector:
    """No environment proxy (an explicit empty ProxyHandler), no redirects, default TLS verification."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def _bounded_call(function: Callable[[], Any], timeout: float) -> Any:
    """Run one blocking transport step (open, read, close) in a daemon worker and wait at most `timeout` seconds: a hard
    wall-clock bound, the way fomoapi.py, solanatracker.py and gmgn_rows.py do it. A socket timeout alone restarts on
    every byte, so a server that drip-feeds bytes (or a stalled DNS or TLS step) could otherwise hold the collector far
    past the deadline. An abandoned step publishes nothing and cannot retry."""
    if timeout <= 0:
        raise TimeoutError
    result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def invoke() -> None:
        try:
            result.put((True, function()))
        except BaseException as exc:  # handed back to the bounded caller
            result.put((False, exc))

    worker = threading.Thread(target=invoke, name="pda-identity-transport", daemon=True)
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


def send_once(request: urllib.request.Request, opener: Any, *, monotonic: Callable[[], float]) -> bytes:
    """One attempt. Returns the body (at most MAX_BYTES) or raises Failure with a fixed code. Opening, every read and the
    error close run under one hard wall-clock deadline of TIMEOUT_S. An error body is never read."""
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
    except Exception:  # noqa: BLE001 - never let exception text out
        raise Failure("network_error") from None
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            try:
                _bounded_call(close, remaining())
            except Exception:  # noqa: BLE001 - cleanup cannot extend the deadline
                pass


def rpc_call(payload: dict[str, Any], opener: Any, *, monotonic: Callable[[], float], sleep: Callable[[float], None]) -> dict[str, Any]:
    """One JSON-RPC request plus at most one retry after a 429. Returns {result, attempts, reason, http_status,
    rpc_error_code}; never raises. A JSON-RPC error answer is rpc_error with its numeric code only (its message is not
    kept)."""
    out: dict[str, Any] = {"result": None, "attempts": 0, "reason": None, "http_status": None, "rpc_error_code": None}
    for attempt in (1, 2):
        out["attempts"] = attempt
        try:
            body = send_once(build_request(payload), opener, monotonic=monotonic)
            out.update(reason=None, http_status=200)
        except Failure as failure:
            out.update(reason=failure.reason, http_status=failure.http_status)
            if attempt == 1 and failure.retry_wait is not None:
                sleep(failure.retry_wait)
                continue
            return out
        except Exception:  # noqa: BLE001 - defensive: no exception text leaves this function
            out.update(reason="request_failed", http_status=None)
            return out
        try:
            answer = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            out["reason"] = "invalid_json"
            return out
        if not isinstance(answer, dict):
            out["reason"] = "invalid_shape"
        elif answer.get("error") is not None:
            code = answer["error"].get("code") if isinstance(answer["error"], dict) else None
            out.update(reason="rpc_error", rpc_error_code=code if isinstance(code, int) and not isinstance(code, bool) else None)
        elif "result" not in answer:
            out["reason"] = "invalid_shape"
        else:
            out["result"] = answer["result"]
        return out
    return out


# ----------------------------------------------------------------------------- decoding (cited layouts, validated)


def _u64(raw: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", raw, offset)[0]


def _key(raw: bytes, offset: int) -> str:
    return b58encode(raw[offset:offset + 32])


def _account(value: Any) -> dict[str, Any] | None:
    """A getMultipleAccounts / getProgramAccounts account value -> {owner, data, space, lamports}; None when it is not a
    readable base64 account."""
    if not isinstance(value, dict) or not is_address(value.get("owner")):
        return None
    data = value.get("data")
    if not (isinstance(data, list) and len(data) == 2 and data[1] == "base64" and isinstance(data[0], str)):
        return None
    try:
        raw = base64.b64decode(data[0], validate=True)
    except (binascii.Error, ValueError):
        return None
    space = value.get("space")
    lamports = value.get("lamports")
    return {"owner": value["owner"], "data": raw, "space": space if isinstance(space, int) and not isinstance(space, bool) and space >= 0 else None,
            "lamports": lamports if isinstance(lamports, int) and not isinstance(lamports, bool) else None}


def decode_mint(account: dict[str, Any] | None) -> dict[str, Any] | None:
    """The scanned mint (SPL Token or Token-2022 base layout): supply and decimals, or None when it is not a readable,
    initialized mint."""
    if account is None or account["owner"] not in TOKEN_PROGRAMS or len(account["data"]) < MINT_LEN:
        return None
    raw = account["data"]
    if raw[MINT_IS_INITIALIZED] != 1 or raw[MINT_DECIMALS] > 30:
        return None
    return {"program": account["owner"], "supply_raw": _u64(raw, MINT_SUPPLY), "decimals": raw[MINT_DECIMALS]}


def decode_token_account(account: dict[str, Any]) -> dict[str, Any] | None:
    raw = account["data"]
    if account["owner"] not in TOKEN_PROGRAMS or len(raw) < TOKEN_ACCOUNT_LEN or raw[TOKEN_ACCOUNT_STATE] not in (1, 2):
        return None
    return {"mint": _key(raw, TOKEN_ACCOUNT_MINT), "authority": _key(raw, TOKEN_ACCOUNT_OWNER), "amount_raw": _u64(raw, TOKEN_ACCOUNT_AMOUNT),
            "frozen": raw[TOKEN_ACCOUNT_STATE] == 2}


def decode_stream(address: str, account: dict[str, Any], mint: str, now: int) -> dict[str, Any]:
    """A Streamflow stream account -> {status: identified, kind: streamflow, ...} or {status: unavailable, reason:
    layout_mismatch | mint_mismatch, check}. Never guesses: any failed check refuses the whole decode."""
    def refuse(check: str, reason: str = "layout_mismatch") -> dict[str, Any]:
        return {"status": "unavailable", "reason": reason, "check": check}

    raw = account["data"]
    if account["owner"] != STREAMFLOW_PROGRAM:
        return refuse("owner_program")
    if len(raw) < STREAM_LAYOUT_END or (account["space"] is not None and account["space"] < STREAM_LAYOUT_END):
        return refuse("length")
    fields: dict[str, Any] = {name: _u64(raw, off) for name, off in STREAM_FIELDS_U64.items()}
    fields.update({name: _key(raw, off) for name, off in STREAM_FIELDS_ADDRESS.items()})
    flags = {name: raw[off] for name, off in STREAM_FIELDS_FLAG.items()}
    if any(v not in (0, 1) for v in flags.values()):
        return refuse("flags")
    if fields["mint"] != mint:
        return refuse("mint", "mint_mismatch")
    expected_escrow, _bump = find_program_address([STREAMFLOW_ESCROW_SEED, b58decode(address)], STREAMFLOW_PROGRAM)
    if expected_escrow != fields["escrow_tokens"]:
        return refuse("escrow_derivation")
    created, start, cliff, end = fields["created_at"], fields["start_time"], fields["cliff"], fields["end_time"]
    if not (MIN_TS <= created <= now + CLOCK_SLACK_S) or not all(MIN_TS <= t < MAX_TS for t in (start, cliff, end)) or not start <= cliff <= end:
        return refuse("timestamps")
    if any(fields[name] and not (created <= fields[name] <= now + CLOCK_SLACK_S) for name in ("canceled_at", "last_withdrawn_at")):
        return refuse("timestamps")
    if fields["last_rate_change_time"] and not (MIN_TS <= fields["last_rate_change_time"] < MAX_TS):
        return refuse("timestamps")
    deposited = fields["net_amount_deposited"]
    if deposited == 0 or fields["period"] == 0 or fields["withdrawn_amount"] > deposited or fields["cliff_amount"] > deposited \
            or fields["funds_unlocked_at_last_rate_change"] > deposited:
        return refuse("amounts")
    stream = {
        "status": "identified", "reason": None, "kind": "streamflow", "program": STREAMFLOW_PROGRAM, "stream": address,
        "escrow": fields["escrow_tokens"], "sender": fields["sender"], "recipient": fields["recipient"], "mint": fields["mint"],
        "created_at": created, "start": start, "cliff": cliff, "end": end, "period_s": fields["period"],
        "deposited_raw": deposited, "withdrawn_raw": fields["withdrawn_amount"], "cliff_amount_raw": fields["cliff_amount"],
        "amount_per_period_raw": fields["amount_per_period"], "canceled_at": fields["canceled_at"] or None,
        "last_withdrawn_at": fields["last_withdrawn_at"] or None, "last_rate_change_time": fields["last_rate_change_time"],
        "funds_unlocked_at_last_rate_change_raw": fields["funds_unlocked_at_last_rate_change"],
        **{name: bool(value) for name, value in flags.items()},
    }
    stream["stream_type"] = stream_type(stream)
    stream["unlocked_at_read_raw"] = unlocked_at(stream, now)
    upcoming = next_unlock(stream, now)
    stream["next_unlock"] = {"at": upcoming[0], "amount_raw": upcoming[1]} if upcoming else None
    return stream


def unlocked_at(stream: dict[str, Any], t: int) -> int:
    """Streamflow's own calculateUnlockedAmount (contractUtils.ts), in integers; never below 0."""
    deposited = stream["deposited_raw"]
    if t < stream["cliff"]:
        return 0
    if t > stream["end"]:
        return deposited
    changed = stream["last_rate_change_time"]
    saved = stream["cliff_amount_raw"] if changed == 0 else stream["funds_unlocked_at_last_rate_change_raw"]
    saved_t = stream["cliff"] if changed == 0 else changed
    streamed = ((t - saved_t) // stream["period_s"]) * stream["amount_per_period_raw"] + saved
    return max(0, min(streamed, deposited))


def next_unlock(stream: dict[str, Any], now: int) -> tuple[int, int] | None:
    """(time, amount) of the next increase of the unlocked amount after `now`, by the same formula; None when everything
    is unlocked or the stream was closed or canceled."""
    if stream["closed"] or stream["canceled_at"]:
        return None
    current = unlocked_at(stream, now)
    if current >= stream["deposited_raw"]:
        return None
    period = stream["period_s"]
    base = stream["cliff"] if stream["last_rate_change_time"] == 0 else stream["last_rate_change_time"]
    first = 0 if now < base else (now - base) // period + 1
    candidates = {stream["cliff"], stream["end"] + 1, base + first * period, base + (first + 1) * period}
    for t in sorted(c for c in candidates if c > now):
        later = unlocked_at(stream, t)
        if later > current:
            return t, later - current
    return None


def stream_type(stream: dict[str, Any]) -> str:
    """Streamflow's isTokenLock (contractUtils.ts): 'lock' or 'vesting'."""
    if stream["can_topup"] or stream["automatic_withdrawal"] or stream["cancelable_by_sender"] or stream["cancelable_by_recipient"] or stream["transferable_by_sender"]:
        return "vesting"
    if stream["cliff_amount_raw"] >= stream["deposited_raw"] - 1:
        return "lock" if stream["end"] - stream["cliff"] <= 1 else "vesting"
    return "vesting"


def decode_pool(address: str, account: dict[str, Any], mint: str) -> dict[str, Any]:
    """A pump_amm account -> PumpSwap pool identity, or unidentified (another pump_amm account type), or unavailable
    (layout_mismatch) when a Pool fails its checks."""
    raw = account["data"]
    if raw[:8] != PUMP_AMM_POOL_DISCRIMINATOR:
        return {"status": "unidentified", "reason": None, "kind": "unidentified", "detail": "not_a_pool_account"}
    if len(raw) < POOL_MIN_LEN or (account["space"] is not None and account["space"] < POOL_MIN_LEN):
        return {"status": "unavailable", "reason": "layout_mismatch", "check": "length"}
    creator, base, quote = _key(raw, POOL_CREATOR), _key(raw, POOL_BASE_MINT), _key(raw, POOL_QUOTE_MINT)
    derived, bump = find_program_address([PUMP_AMM_POOL_SEED, raw[POOL_INDEX:POOL_INDEX + 2], b58decode(creator), b58decode(base), b58decode(quote)], PUMP_AMM_PROGRAM)
    if derived != address or bump != raw[POOL_BUMP]:
        return {"status": "unavailable", "reason": "layout_mismatch", "check": "pool_derivation"}
    side = "quote" if quote == mint else "base" if base == mint else "neither"
    return {"status": "identified", "reason": None, "kind": "pumpswap_pool", "program": PUMP_AMM_PROGRAM, "side": side,
            "base_mint": base, "quote_mint": quote, "creator": creator, "index": struct.unpack_from("<H", raw, POOL_INDEX)[0],
            "lp_mint": _key(raw, POOL_LP_MINT), "pool_base_token_account": _key(raw, POOL_BASE_TA), "pool_quote_token_account": _key(raw, POOL_QUOTE_TA),
            "infrastructure": side == "quote", "exclude_hint": f"--exclude {address}" if side == "quote" else None}


def classify(address: str, value: Any, mint: str, now: int) -> dict[str, Any]:
    """One target from the batch read. Escrow-style token accounts get status 'lookup' (the stream is found next)."""
    if value is None:
        return {"status": "unidentified", "reason": None, "kind": "unidentified", "owner_program": None, "detail": "no_account"}
    account = _account(value)
    if account is None:
        return {"status": "unavailable", "reason": "account_unreadable", "owner_program": value.get("owner") if isinstance(value, dict) and is_address(value.get("owner")) else None}
    base = {"owner_program": account["owner"], "data_len": len(account["data"]), "space": account["space"]}
    if account["owner"] == STREAMFLOW_PROGRAM:
        return {**base, **decode_stream(address, account, mint, now), "found_by": "direct"}
    if account["owner"] == PUMP_AMM_PROGRAM:
        return {**base, **decode_pool(address, account, mint)}
    if account["owner"] in TOKEN_PROGRAMS:
        token = decode_token_account(account)
        if token is None:
            return {**base, "status": "unidentified", "reason": None, "kind": "unidentified", "detail": "token_program_account"}
        if token["mint"] == mint and token["authority"] == address:
            return {**base, "status": "lookup", "reason": None, "kind": "escrow_candidate", "escrow_balance_raw": token["amount_raw"]}
        detail = "token_account_of_another_mint" if token["mint"] != mint else "token_account"
        return {**base, "status": "unidentified", "reason": None, "kind": "unidentified", "detail": detail, "token_authority": token["authority"]}
    detail = "system_owned_off_curve" if account["owner"] == SYSTEM_PROGRAM and off_curve(address) else "system_owned" if account["owner"] == SYSTEM_PROGRAM else None
    return {**base, "status": "unidentified", "reason": None, "kind": "unidentified", "detail": detail}


def resolve_escrow(target: dict[str, Any], got: dict[str, Any], mint: str, now: int) -> dict[str, Any]:
    """The answer of one escrow lookup -> the target's identity."""
    escrow = target["address"]
    if got["reason"] is not None:
        return {"status": "unavailable", "reason": "stream_lookup_failed", "lookup_reason": got["reason"], "rpc_error_code": got.get("rpc_error_code")}
    rows = got["result"]
    if isinstance(rows, dict) and isinstance(rows.get("value"), list):  # withContext form
        rows = rows["value"]
    if not isinstance(rows, list):
        return {"status": "unavailable", "reason": "stream_lookup_failed", "lookup_reason": "invalid_shape"}
    if not rows:
        return {"status": "unidentified", "reason": None, "kind": "unidentified", "detail": "self_owned_token_account_no_stream"}
    if len(rows) >= MAX_LOOKUP_RESULTS:
        return {"status": "unavailable", "reason": "stream_lookup_ambiguous"}
    row = rows[0]
    stream_address = row.get("pubkey") if isinstance(row, dict) else None
    account = _account(row.get("account")) if isinstance(row, dict) else None
    if not is_address(stream_address) or account is None:
        return {"status": "unavailable", "reason": "stream_lookup_failed", "lookup_reason": "invalid_shape"}
    decoded = decode_stream(stream_address, account, mint, now)
    if decoded["status"] == "identified" and decoded["escrow"] != escrow:
        return {"status": "unavailable", "reason": "layout_mismatch", "check": "escrow"}
    return {**decoded, "found_by": "program_account_lookup"}


# ----------------------------------------------------------------------------- targets from the saved holder rows


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None


def collect_targets(run: Path, mint: str, extra: list[str]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Targets in order (explicit --target first, then holder-analysis.json program_account / controlled_vault rows,
    then holders.json off-curve non-infrastructure rows the analysis engine did not already identify), deduplicated.
    Returns (targets, how each saved file was read)."""
    found: dict[str, dict[str, Any]] = {}
    read: dict[str, str] = {}

    def add(address: str, source: str, share: float | None) -> None:
        if address == mint or not is_address(address):
            return
        entry = found.setdefault(address, {"address": address, "from": [], "row_share_pct": None})
        if source not in entry["from"]:
            entry["from"].append(source)
        if entry["row_share_pct"] is None and share is not None:
            entry["row_share_pct"] = share

    for address in extra:
        add(address, "--target", None)
    known_kinds: dict[str, str] = {}
    analysis = _read_json(run / "holder-analysis.json")
    if not (run / "holder-analysis.json").exists():
        read["holder-analysis.json"] = "missing"
    elif not isinstance(analysis, dict) or not isinstance(analysis.get("top_holders"), list):
        read["holder-analysis.json"] = "unreadable"
    elif analysis.get("mint") != mint:
        read["holder-analysis.json"] = "other_mint"
    else:
        read["holder-analysis.json"] = "read"
        for row in analysis["top_holders"]:
            if isinstance(row, dict) and is_address(row.get("owner")) and isinstance(row.get("kind"), str):
                known_kinds[row["owner"]] = row["kind"]
                if row["kind"] in ("program_account", "controlled_vault"):
                    share = row.get("share")
                    add(row["owner"], f"holder-analysis.json {row['kind']}", round(share * 100, 6) if isinstance(share, (int, float)) and not isinstance(share, bool) and math.isfinite(share) else None)
    holders = _read_json(run / "holders.json")
    if not (run / "holders.json").exists():
        read["holders.json"] = "missing"
    elif not isinstance(holders, dict) or holders.get("mint") != mint:
        read["holders.json"] = "unreadable" if not isinstance(holders, dict) else "other_mint"
    elif not isinstance(holders.get("top_holders"), list):
        read["holders.json"] = "no_top_holders"
    else:
        read["holders.json"] = "read"
        for row in holders["top_holders"]:
            if not isinstance(row, dict) or row.get("infrastructure") is not False or not is_address(row.get("wallet")):
                continue
            address = row["wallet"]
            if known_kinds.get(address) in ("liquidity_pool", "exchange", "burn") or not off_curve(address):
                continue
            share = row.get("share_pct")
            add(address, "holders.json off-curve", share if isinstance(share, (int, float)) and not isinstance(share, bool) and math.isfinite(share) else None)
    return list(found.values()), read


# ----------------------------------------------------------------------------- collect


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _base(mint: str, fetched_at: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "lane": "pda_identity_reads", "mint": mint, "status": "unavailable", "reason": None, "fetched_at": fetched_at,
        "http_status": None, "rpc_error_code": None, "slot": None,
        "request": {"host": HOST, "path": "/", "methods": list(ALLOWED_METHODS), "keys": "none", "batch_calls": 0, "stream_lookups": 0,
                    "requests_sent": 0, "max_requests": MAX_REQUESTS, "max_targets": MAX_TARGETS, "max_stream_lookups": MAX_STREAM_LOOKUPS,
                    "data_slice_bytes": DATA_SLICE_BYTES},
        "layouts": {"streamflow": "provider-docs current/streamflow/protocol.md (js-sdk layout.ts, constants.ts, contractUtils.ts)",
                    "pump_amm": "provider-docs current/pumpfun/idls.md (pump_amm.json: Pool, create_pool seeds)",
                    "spl_token": "provider-docs current/spltoken/layouts.md (token interface state.rs: Mint, Account)"},
        "targets_from": {}, "targets_not_read": 0, "mint_info": None, "targets": [],
        "presentation_only": True, "note": PRESENTATION_NOTE, "cannot_see": CANNOT_SEE,
    }


def collect_pda_identity(
    mint: str,
    targets: list[dict[str, Any]],
    *,
    targets_from: dict[str, str] | None = None,
    opener: Any | None = None,
    now: Callable[[], float] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """One batch read of the mint and the targets, then at most MAX_STREAM_LOOKUPS escrow lookups sent at the same time.
    Returns the pda_identity_reads.json result; never raises for provider or transport failures."""
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    result = _base(mint, _iso(now()))
    result["targets_from"] = dict(targets_from or {})
    kept = targets[:MAX_TARGETS]
    result["targets_not_read"] = max(0, len(targets) - MAX_TARGETS)
    if not kept:
        result.update(status="empty", reason="no_targets")
        return result
    opener = opener or default_opener()
    got = rpc_call(batch_payload([mint, *[t["address"] for t in kept]]), opener, monotonic=monotonic, sleep=sleep)
    result["request"]["batch_calls"] = 1
    result["request"]["requests_sent"] = got["attempts"]
    result.update(http_status=got["http_status"], rpc_error_code=got["rpc_error_code"], fetched_at=_iso(now()))
    if got["reason"] is not None:
        result["reason"] = got["reason"]
        return result
    answer = got["result"]
    values = answer.get("value") if isinstance(answer, dict) else None
    if not isinstance(values, list) or len(values) != len(kept) + 1:
        result["reason"] = "invalid_shape"
        return result
    context = answer.get("context")
    slot = context.get("slot") if isinstance(context, dict) else None
    result["slot"] = slot if isinstance(slot, int) and not isinstance(slot, bool) else None
    mint_info = decode_mint(_account(values[0]) if values[0] is not None else None)
    if mint_info is None:
        result["reason"] = "mint_not_found" if values[0] is None else "mint_unreadable"
        return result
    result["mint_info"] = mint_info
    read_at = int(now())
    rows: list[dict[str, Any]] = []
    for target, value in zip(kept, values[1:]):
        try:
            identity = classify(target["address"], value, mint, read_at)
        except Exception:  # noqa: BLE001 - an account the guards did not foresee: a fixed code, never a crash
            identity = {"status": "unavailable", "reason": "parse_error"}
        rows.append({**target, **identity})
    candidates = [row for row in rows if row["status"] == "lookup"]
    for row in candidates[MAX_STREAM_LOOKUPS:]:
        row.update(status="unavailable", reason="stream_lookup_cap", kind="escrow_candidate")
    chosen = candidates[:MAX_STREAM_LOOKUPS]
    answers: dict[int, dict[str, Any]] = {}

    def lookup(index: int, row: dict[str, Any]) -> None:
        answers[index] = rpc_call(lookup_payload(mint, row["address"]), opener, monotonic=monotonic, sleep=sleep)

    workers = [threading.Thread(target=lookup, args=(i, row), name="pda-identity-lookup", daemon=True) for i, row in enumerate(chosen)]
    for worker in workers:  # every lookup is sent at the same time: no one-by-one loop
        worker.start()
    for worker in workers:
        worker.join(2 * TIMEOUT_S + RETRY_MAX_WAIT_S + 5)
    for i, row in enumerate(chosen):
        got_lookup = answers.get(i) or {"result": None, "attempts": 0, "reason": "timeout", "http_status": None, "rpc_error_code": None}
        result["request"]["stream_lookups"] += 1
        result["request"]["requests_sent"] += got_lookup["attempts"]
        balance = row.get("escrow_balance_raw")
        try:
            identity = resolve_escrow(row, got_lookup, mint, read_at)
        except Exception:  # noqa: BLE001
            identity = {"status": "unavailable", "reason": "parse_error"}
        row.update(identity)
        if identity.get("status") == "identified":
            row["escrow_balance_raw"] = balance
    for row in rows:
        if row.get("kind") == "streamflow" and row.get("status") == "identified":
            held = row.get("escrow_balance_raw")
            held = held if isinstance(held, int) else row["deposited_raw"] - row["withdrawn_raw"]
            row["held_raw"] = held
            row["held_basis"] = "escrow balance" if isinstance(row.get("escrow_balance_raw"), int) else "deposited minus withdrawn"
    result["targets"] = rows
    result.update(status="ok", reason=None)
    return result


def status_line(result: dict[str, Any]) -> str:
    sent = result["request"]["requests_sent"]
    calls = f"{sent} call{'s' if sent != 1 else ''} to the public Solana RPC" if sent else "no RPC call sent"
    if result["status"] == "empty":
        return f"empty (no program-account rows to identify; {calls})"
    if result["status"] != "ok":
        return f"unavailable ({result['reason']}; {calls})"
    rows = result["targets"]
    counts = {
        "Streamflow": sum(1 for r in rows if r.get("status") == "identified" and r.get("kind") == "streamflow"),
        "PumpSwap pool": sum(1 for r in rows if r.get("status") == "identified" and r.get("kind") == "pumpswap_pool"),
        "unidentified": sum(1 for r in rows if r.get("status") == "unidentified"),
        "not read": sum(1 for r in rows if r.get("status") == "unavailable"),
    }
    parts = ", ".join(f"{n} {name}" for name, n in counts.items() if n)
    return f"ok ({len(rows)} target{'s' if len(rows) != 1 else ''}: {parts}; {calls})"


# ----------------------------------------------------------------------------- presentation (synthesis, offline)


KNOWN_CODES = frozenset({
    "scheme_not_https", "host_not_allowlisted", "path_not_allowlisted", "method_not_allowlisted", "redirect_disallowed", "bad_request",
    "access_denied", "not_found", "method_unavailable", "request_too_large", "rate_limited", "service_unavailable", "server_error",
    "http_error", "invalid_response", "response_too_large", "timeout", "network_error", "request_failed", "invalid_json", "invalid_shape",
    "rpc_error", "no_targets", "mint_not_found", "mint_unreadable", "account_unreadable", "parse_error", "layout_mismatch", "mint_mismatch",
    "stream_lookup_failed", "stream_lookup_ambiguous", "stream_lookup_cap", "owner_program", "length", "flags", "mint", "escrow_derivation",
    "timestamps", "amounts", "escrow", "pool_derivation",
})


def _code(value: Any) -> str:
    """A reason or check code read back from the saved file: printed only when it is one of this script's fixed codes, so
    no saved text (a tampered file included) reaches the report."""
    return value if isinstance(value, str) and value in KNOWN_CODES else "unrecognized code"


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _addr(value: Any) -> str:
    return value if isinstance(value, str) and SOLANA_ADDRESS_RE.fullmatch(value) else "unknown"


def _utc(ts: Any) -> str:
    value = _int(ts)
    if value is None or not (0 < value < MAX_TS):
        return "unknown"
    return dt.datetime.fromtimestamp(value, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _tokens(raw: Any, decimals: Any) -> str:
    """A token amount from base units, cut toward zero to 2 decimals, never rounded up."""
    amount, places = _int(raw), _int(decimals)
    if amount is None or places is None or amount < 0 or not 0 <= places <= 30:
        return "unknown"
    whole, frac = divmod(amount, 10 ** places)
    cents = (frac * 100) // (10 ** places) if places else 0
    return f"{whole:,}.{cents:02d}"


def _share(raw: Any, supply: Any) -> str:
    """Share of supply in percent, cut toward zero to 2 decimals (0.00999% reads 'under 0.01%'), never rounded up."""
    amount, total = _int(raw), _int(supply)
    if amount is None or total is None or total <= 0 or amount < 0:
        return "unknown share"
    hundredths = amount * 10000 // total
    if hundredths == 0 and amount > 0:
        return "under 0.01%"
    return f"{hundredths // 100}.{hundredths % 100:02d}%"


def _period(seconds: Any) -> str:
    value = _int(seconds)
    if value is None or value <= 0:
        return "unknown period"
    for size, name in ((86400, "day"), (3600, "hour"), (60, "minute")):
        if value % size == 0:
            n = value // size
            return f"{n} {name}{'s' if n != 1 else ''}"
    return f"{value} s"


def _age_min(value: Any) -> float | None:
    try:
        fetched = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if fetched.tzinfo is None:
            return None
        return max(0.0, (dt.datetime.now(dt.timezone.utc) - fetched).total_seconds() / 60)
    except (ValueError, TypeError, OverflowError):
        return None


def _valid_saved(data: Any) -> bool:
    return isinstance(data, dict) and data.get("schema") == SCHEMA and data.get("status") in ("ok", "empty", "unavailable") and data.get("presentation_only") is True


def _flag(row: dict[str, Any], name: str) -> bool | None:
    value = row.get(name)
    return value if isinstance(value, bool) else None


def _stream_line(row: dict[str, Any], mint_info: dict[str, Any]) -> str:
    decimals, supply = mint_info.get("decimals"), mint_info.get("supply_raw")
    kind = "Streamflow lock" if row.get("stream_type") == "lock" else "Streamflow vesting stream"
    held = row.get("held_raw")
    basis = "in the escrow" if row.get("held_basis") == "escrow balance" else "deposited minus withdrawn"
    head = f"{kind} of {_share(held, supply)} of supply ({_tokens(held, decimals)} tokens {basis})"
    sender, recipient = _addr(row.get("sender")), _addr(row.get("recipient"))
    who = f"recipient {recipient} (also the sender)" if sender == recipient else f"recipient {recipient}, sender {sender}"
    cliff_amount, deposited = _int(row.get("cliff_amount_raw")), _int(row.get("deposited_raw"))
    parts = [who]
    upcoming = row.get("next_unlock") if isinstance(row.get("next_unlock"), dict) else None
    if _flag(row, "closed"):
        parts.append("stream closed")
    elif _int(row.get("canceled_at")):
        parts.append(f"canceled {_utc(row.get('canceled_at'))}")
    elif row.get("stream_type") == "lock":
        all_of_it = cliff_amount is not None and deposited is not None and cliff_amount >= deposited - 1
        amount = "all of it" if all_of_it else _tokens(cliff_amount, decimals) + " tokens"
        parts.append(f"unlocks {_utc(row.get('cliff'))} (cliff, {amount})" if upcoming else f"unlocked since {_utc(row.get('cliff'))} (cliff passed, {amount})")
    else:
        parts.append(f"starts {_utc(row.get('start'))}, cliff {_utc(row.get('cliff'))} ({_tokens(cliff_amount, decimals)} tokens), then "
                     f"{_tokens(row.get('amount_per_period_raw'), decimals)} every {_period(row.get('period_s'))} until {_utc(row.get('end'))}; "
                     f"unlocked at read time {_tokens(row.get('unlocked_at_read_raw'), decimals)} (Streamflow's own formula)")
        parts.append(f"next unlock {_utc(upcoming.get('at'))} ({_tokens(upcoming.get('amount_raw'), decimals)} tokens)" if upcoming else "fully unlocked")
    by_sender, by_recipient = _flag(row, "cancelable_by_sender"), _flag(row, "cancelable_by_recipient")
    parts.append("not cancellable" if by_sender is False and by_recipient is False else
                 "cancellable by " + " and ".join(n for n, v in (("the sender", by_sender), ("the recipient", by_recipient)) if v) if by_sender or by_recipient else "cancellable: not read")
    t_sender, t_recipient = _flag(row, "transferable_by_sender"), _flag(row, "transferable_by_recipient")
    parts.append("not transferable" if t_sender is False and t_recipient is False else
                 "transferable by " + " and ".join(n for n, v in (("the sender", t_sender), ("the recipient", t_recipient)) if v) if t_sender or t_recipient else "transferable: not read")
    parts.append("top-up allowed" if _flag(row, "can_topup") else "no top-up")
    if _flag(row, "pausable"):
        parts.append("pausable")
    if _flag(row, "can_update_rate"):
        parts.append("rate can be changed by the sender")
    if _flag(row, "automatic_withdrawal"):
        parts.append("automatic withdrawal")
    tail = f"withdrawn so far {_tokens(row.get('withdrawn_raw'), decimals)}; stream {_addr(row.get('stream'))} (created {_utc(row.get('created_at'))})"
    return f"{head}: " + ", ".join(parts) + f"; {tail}"


def _pool_line(row: dict[str, Any], address: str) -> str:
    side = row.get("side")
    if side == "quote":
        return (f"PumpSwap pool (this token is the quote side): infrastructure (quote side), consider --exclude {address}; "
                f"pair {_addr(row.get('base_mint'))} / this token")
    if side == "base":
        return f"PumpSwap pool (this token is the base side): pool; pair this token / {_addr(row.get('quote_mint'))}"
    return f"PumpSwap pool of other tokens (neither side is this token): pair {_addr(row.get('base_mint'))} / {_addr(row.get('quote_mint'))}"


ESCROW_NOT_CONFIRMED = ("not confirmed as Streamflow and no lock details read: the escrow names no stream (only the Streamflow lookup "
                        "finds it) and other programs' escrows have the same shape")
UNIDENTIFIED_DETAIL = {
    "no_account": "no account at this address",
    "system_owned_off_curve": "system-owned off-curve address",
    "system_owned": "system-owned address",
    "not_a_pool_account": "a pump_amm account that is not a pool",
    "token_program_account": "a token-program account that is not a token account",
    "token_account": "a token account with another authority",
    "token_account_of_another_mint": "a token account of another mint",
    "self_owned_token_account_no_stream": "a token account that is its own authority (escrow-style); no Streamflow stream names it",
}


def _target_line(row: dict[str, Any], mint_info: dict[str, Any]) -> str:
    address = _addr(row.get("address"))
    status = row.get("status")
    if status == "identified" and row.get("kind") == "streamflow":
        return f"  {address}: {_stream_line(row, mint_info)}"
    if status == "identified" and row.get("kind") == "pumpswap_pool":
        return f"  {address}: {_pool_line(row, address)}"
    if status == "unidentified":
        owner = row.get("owner_program")
        owner_text = _addr(owner) if owner is not None else "unknown"
        detail = UNIDENTIFIED_DETAIL.get(row.get("detail")) if isinstance(row.get("detail"), str) else None
        return f"  {address}: unidentified program account (owner program {owner_text})" + (f"; {detail}" if detail else "")
    if status == "unavailable":
        extra = f", {_code(row.get('lookup_reason'))}" if row.get("lookup_reason") is not None else ""
        check = f", check {_code(row.get('check'))}" if row.get("check") is not None else ""
        codes = f"{_code(row.get('reason'))}{extra}{check}"
        if row.get("kind") == "escrow_candidate":  # the stream was not read: never called Streamflow, never a guessed lock
            return (f"  {address}: escrow-style token account (its own authority): unavailable ({codes}); {ESCROW_NOT_CONFIRMED}")
        return f"  {address}: not identified: unavailable ({codes})"
    return f"  {address}: not read (unreadable entry)"


def present(run: Path) -> list[str]:
    """The block the synthesis prints next to the holder rows. Reads only the saved file: no network, no key. A missing,
    foreign or malformed file or value reads as not read, never as a crash."""
    path = run / OUT_DIR / OUT_FILE
    data = _read_json(path)
    result = data if _valid_saved(data) else None
    head = f"PDA identity reads (follow-up lane pda_identity_reads; {INDEPENDENCE_NOTE})"
    if result is None:
        return [f"{head}: not read ({OUT_DIR}/{OUT_FILE} " + ("missing" if not path.exists() else "unreadable") + ")"]
    request = result.get("request") if isinstance(result.get("request"), dict) else {}
    sent, lookups = _int(request.get("requests_sent")), _int(request.get("stream_lookups"))
    calls = (f"{sent} call{'s' if sent != 1 else ''}" + (f" ({lookups} Streamflow lookup{'s' if lookups != 1 else ''})" if lookups else "")) if sent is not None else "calls unknown"
    age = _age_min(result.get("fetched_at"))
    state = {"ok": "read", "empty": "empty", "unavailable": "unavailable"}[result["status"]]
    line = f"{head}: {state}" + ("" if result["status"] == "ok" else f" ({_code(result.get('reason'))})")
    lines = [line + (f"; data age {age:.0f} min" if age is not None else "; data age unknown") + f"; {calls}"]
    if result["status"] == "empty":
        lines.append("  no program-account holder rows to identify (nothing read)")
    elif result["status"] == "ok":
        mint_info = result.get("mint_info") if isinstance(result.get("mint_info"), dict) else {}
        rows = [r for r in result.get("targets") if isinstance(r, dict)] if isinstance(result.get("targets"), list) else []
        for row in rows:
            try:
                lines.append(_target_line(row, mint_info))
            except Exception:  # noqa: BLE001 - a damaged entry is not read, never a crash
                lines.append(f"  {_addr(row.get('address'))}: not read (unreadable entry)")
        if not rows:
            lines.append("  no target in the file")
        skipped = _int(result.get("targets_not_read"))
        if skipped:
            lines.append(f"  {skipped} more program-account rows not read (cap of {MAX_TARGETS} per scan)")
    lines += [f"  cannot see: {CANNOT_SEE}", f"  {PRESENTATION_NOTE}"]
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Identify program-account holder rows (Streamflow streams and locks, PumpSwap pools) "
                                                 "over the free public Solana RPC (no key; 1 batch read plus at most "
                                                 f"{MAX_STREAM_LOOKUPS} Streamflow lookups; bounded: 2 MiB, 30 s, no redirects, no env proxy) and "
                                                 f"save {OUT_DIR}/{OUT_FILE}; or, with --present RUN_DIR, print the block offline. "
                                                 "Presentation only: never an engine input.")
    parser.add_argument("mint", nargs="?")
    parser.add_argument("--out", metavar="RUN_DIR", help="run folder: targets are read from its holder-analysis.json and holders.json")
    parser.add_argument("--target", action="append", default=[], metavar="ADDRESS", help="an extra target address (repeatable)")
    parser.add_argument("--present", metavar="RUN_DIR", help="offline: print the block from a saved run folder (no network, no key)")
    args = parser.parse_args(argv)
    if args.present is not None:
        if args.mint or args.out or args.target:
            print("error: --present takes only the run folder", file=sys.stderr)
            return 2
        run = Path(args.present)
        if not run.is_dir():
            print("error: --present is not a run folder", file=sys.stderr)
            return 2
        for line in present(run):
            print(line)
        return 0
    if not is_address(args.mint):
        print("error: mint is not a valid base58 Solana address", file=sys.stderr)
        return 2
    if any(not is_address(t) for t in args.target):
        print("error: --target is not a valid base58 Solana address", file=sys.stderr)
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
    try:
        targets, read = collect_targets(run, args.mint, args.target)
        result = collect_pda_identity(args.mint, targets, targets_from=read)
    except Exception:  # noqa: BLE001 - never print a traceback
        result = _base(args.mint, _iso(time.time()))
        result["reason"] = "request_failed"
    try:
        (run / OUT_DIR / OUT_FILE).write_text(json.dumps(result, indent=1), encoding="utf-8")
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    print(status_line(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
