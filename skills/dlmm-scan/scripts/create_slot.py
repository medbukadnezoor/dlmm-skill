#!/usr/bin/env python3
"""Create-slot trace for dlmm-scan (follow-up lane `create_slot_trace`): who bought in the token's create slot, read for free.

Wallets that buy in the same slot as the create (co-signed, paid for by one wallet, or first funded by one wallet) are the
clearest sign of a dev-run bundle, and they were found by hand. This collector finds the token's create transaction from a
free pointer, verifies it on-chain over the free public Solana RPC (no key, no Helius credits), reads the create slot and the
next SLOTS_AFTER slots, and reports what was seen:
- the creator (deployer) and the dev's buy inside the create transaction (tokens and share of supply);
- every other wallet whose balance of this token rose in those slots (amount, share, slot, the fee payer and signers of its
  transaction);
- co-signed buys (one transaction signed by or crediting several of these wallets) and one fee payer behind several;
- a shared first funder, joined offline from this scan's saved first-wave funded-by rows (funders.json, holder-analysis.json;
  no call). A wallet missing there reads "not in this scan's funded-by data".
Same-slot buyers can be the dev's own wallets or ordinary snipers and bots: the block says what was seen, never intent.

Free pointer to the create transaction, in this order, verified on-chain either way (never guessed):
(a) Solana Tracker's creation fields, saved by the first-wave collector solanatracker.py in <RUN>/solanatracker.json (no new
    call): token.creation.created_tx (field names: provider-docs current/solanatracker/fulldocs.md changelog "Pool creation
    data"; confirmed live 2026-10-19).
(b) getSignaturesForAddress (newest to oldest, current/solana/rpc.md) on an account the create transaction creates, derived
    from cited seeds (current/pumpfun/idls.md pump.json; publicdocs.md COIN_CREATION.md), the oldest successful signature
    being the create: for a Token-2022 coin (create_v2) its mayhem_state PDA ("mayhem-state", mint) under the Mayhem program,
    which no other instruction of the cached pump, pump_amm and pump_fees IDLs names; for an SPL Token coin (legacy create)
    its Metaplex metadata PDA ("metadata", Metaplex program, mint), named in the cached IDLs only by pump's create,
    set_creator and set_metaplex_creator and pump_amm's set_coin_creator; then the bonding curve ("bonding-curve", mint),
    busy while the coin trades on it. The token
    program comes from this scan's saved holder-analysis.json (unknown: all three in that order). At most
    MAX_SIGNATURE_PAGES pages of 1,000 in total; a longer history reads unavailable, and a coin that is not a pump.fun coin
    has none of these accounts. Live 2026-10-19: 索拉纳's bonding curve had more than 3,000 signatures (its first 3 pages
    reached back only 1.5 minutes before graduation), so the curve alone could not point to its create.
Neither: unavailable (no_create_tx_pointer).

Verification (create_tx_mismatch otherwise): the transaction succeeded and carries a pump `create` or `create_v2`
instruction (top level or inner; discriminators from pump.json) whose first account is THIS mint and whose third account
is this mint's bonding-curve PDA; or, for another launchpad, the transaction initializes THIS mint (a jsonParsed spl-token
initializeMint or initializeMint2 whose info.mint is the mint, top level or inner: current/solana/parsedinstructions.md,
Agave parse_token.rs and parse_instruction.rs) and mints an amount above 0 (no balance of the mint before, a positive total
after); then no creator is named. The creator named is the account pump's COIN_CREATION.md calls `user` ("Transaction
signer and payer"), with the instruction's `creator` argument when it differs.

Requests (one host, POST JSON-RPC only): api.mainnet-beta.solana.com, https only, path / only, methods getSignaturesForAddress
(pointer (b) only), getTransaction (jsonParsed, one call) and getBlock (transactionDetails "accounts", the smallest detail
level that carries the signers and the token balances, current/solana/rpc.md getBlock; rewards off; the create slot and the
next 2 slots, sent at the same time); maxSupportedTransactionVersion 1 (a block with a v1 transaction fails the whole call
with -32015 at 0). No key, no extra headers, no redirects, no environment proxy, MAX_BYTES per answer (MAX_BLOCK_BYTES for
a block), a hard TIMEOUT_S wall-clock limit per attempt (opening, every read and closing under one deadline, worker thread:
the pda_identity.py pattern), at most one retry per request and only after a 429 (Retry-After up to 10 s, else 1.5 s;
the public RPC asks for 10 s). Calls per scan: 1 getTransaction + 3 getBlock (+ at most 3 signature pages for pointer
(b)): at most 7, at most 14 requests.
Worst-case wall time: about 2 stages with pointer (a), about 5 with pointer (b), each at most about 70 s (30 s, a retry
wait of at most 10 s, 30 s; the block join waits 75 s): about 140 s, or about 350 s (about 6 minutes) with pointer (b),
5 s more per stage than with the old 5 s wait. There is no lane-wide deadline. A transaction without metadata or token
balances (the docs allow null) is counted per slot as not read and keeps its slot out of any 'no other wallet' or empty
conclusion; every read slot affected gives unavailable (layout_mismatch, transaction_meta); no block read gives
unavailable (blocks_not_read).

PRESENTATION ONLY: the synthesis prints the block with --present; this file is never an engine input and changes no verdict,
flag or threshold. It prints only addresses, signatures, slots, times, numbers and fixed phrases (no provider text).

Collector: create_slot.py <MINT> --out <RUN> writes <RUN>/followup/create_slot_trace.json and prints one line: ok (...),
empty (...) or unavailable (<reason>; ...). Exit 0 whenever the file was saved; exit 2 for a bad mint or --out.
Synthesis (offline, no network): create_slot.py --present <RUN>. Standard library only; Python >= 3.10.
"""

from __future__ import annotations

import argparse
import datetime as dt
import decimal
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
ALLOWED_METHODS = ("getSignaturesForAddress", "getTransaction", "getBlock")
SLOTS_AFTER = 2                  # the create slot and the next 2 slots
MAX_SIGNATURE_PAGES = 3          # pointer (b): at most 3 pages of SIGNATURE_PAGE signatures, newest to oldest
SIGNATURE_PAGE = 1000            # the documented maximum limit of getSignaturesForAddress
MAX_BYTES = 2 * 1024 * 1024      # a transaction or a page of 1,000 signatures
MAX_BLOCK_BYTES = 16 * 1024 * 1024  # one block at transactionDetails "accounts": measured 1.5 to 2.1 MB (SEXCOIN slots, 2026-10-19); about 7x headroom, and 3 at once stay under the public RPC's 100 MB per 30 s
TIMEOUT_S = 30.0                 # per attempt: a hard wall-clock limit on open + every read + close (worker thread)
RETRY_MAX_WAIT_S = 10.0          # retry a 429 once only when its Retry-After ends this soon (the public RPC asks for 10 s)
RETRY_DEFAULT_WAIT_S = 1.5       # a 429 without Retry-After is retried once after this wait
MAX_CALLS = MAX_SIGNATURE_PAGES + 1 + 1 + SLOTS_AFTER
MAX_REQUESTS = 2 * MAX_CALLS
USER_AGENT = "holder-scan-create-slot/1.0"
SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
SIGNATURE_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{64,90}$")
OUT_DIR = "followup"
OUT_FILE = "create_slot_trace.json"
SCHEMA = "holder-scan-create-slot/1"
SOLANATRACKER_SCHEMA = "holder-scan-solanatracker/1"
HTTP_REASONS = {400: "bad_request", 401: "access_denied", 403: "access_denied", 404: "not_found", 410: "method_unavailable",
                413: "request_too_large", 429: "rate_limited", 503: "service_unavailable"}
SKIPPED_SLOT_CODES = (-32007, -32009)  # Agave rpc-client-api custom_error.rs: SlotSkipped, LongTermStorageSlotSkipped

# ----------------------------------------------------------------------------- cited program ids and layouts

PUMP_PROGRAM = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"         # pump.json "address"
PUMP_AMM_PROGRAM = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"     # pump.json migrate: pump_amm
MAYHEM_PROGRAM = "MAyhSmzXzV1pTf7LsNkrNwkWKTo4ougAJ1PPg47MD4e"       # pump.json create_v2: mayhem_program_id
WSOL_MINT = "So11111111111111111111111111111111111111112"           # pump.json migrate: wsol_mint
CREATE_DISCRIMINATORS = {bytes([24, 30, 200, 40, 5, 28, 7, 119]): "create",        # pump.json instructions: create
                         bytes([214, 144, 76, 236, 95, 139, 49, 180]): "create_v2"}  # pump.json instructions: create_v2
CREATE_ACCOUNT_MINT, CREATE_ACCOUNT_BONDING_CURVE = 0, 2                      # pump.json create / create_v2 accounts
CREATE_ACCOUNT_USER = {"create": 7, "create_v2": 5}                           # `user`: COIN_CREATION.md account 6 of create_v2
BONDING_CURVE_SEED = b"bonding-curve"
MAYHEM_STATE_SEED = b"mayhem-state"                                # pump.json create_v2: mayhem_state seeds (COIN_CREATION.md #13)
METAPLEX_PROGRAM = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"   # pump.json create: mpl_token_metadata
METADATA_SEED = b"metadata"                                        # pump.json create: metadata seeds ("metadata", program, mint)
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"  # pump.json create_v2: token_program
SPL_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"   # pump.json create: token_program
POOL_AUTHORITY_SEED = b"pool-authority"
POOL_SEED = b"pool"
SOL_VAULT_SEED = b"sol-vault"
MAX_ARG_STRING = 1024            # name, symbol and uri are skipped, never kept (creator-chosen text); a longer one is refused

MIN_TS = 1_577_836_800           # 2020-01-01T00:00:00Z
CLOCK_SLACK_S = 86_400

INDEPENDENCE_NOTE = "public Solana RPC, no key, free"
WORDING_NOTE = ("same-slot buyers can be the dev's own wallets or ordinary snipers and bots: this block says what was seen "
                "on-chain, not who controls the wallets")
CANNOT_SEE = ("only the create slot and the next 2 slots (a second wave of buys in later slots is not read); balances that "
              "rose, not who controls a wallet; a buy routed through a program account (a trading-app vault, for example) "
              "shows as that program account; the first-funder join uses only this scan's saved funded-by rows (top holders), "
              "so a wallet that sold or sits outside them reads 'not in this scan's funded-by data'; without Solana Tracker's "
              "creation tx the create is found only for pump.fun coins whose create-time account (mayhem_state, Metaplex metadata, "
              f"or the bonding curve) has at most {MAX_SIGNATURE_PAGES * SIGNATURE_PAGE:,} signatures; sells, "
              "where the dev's tokens went next, funder chains and lookup-table authorities are not read")
PRESENTATION_NOTE = ("presentation only: what was seen in the create slot; never an engine input, never changes a FLAG, "
                     "verdict or threshold and never counts toward NO_ALARM; nothing seen here is an all-clear")


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


def is_signature(value: Any) -> bool:
    if not isinstance(value, str) or not SIGNATURE_RE.fullmatch(value):
        return False
    try:
        return len(b58decode(value)) == 64
    except ValueError:
        return False


def off_curve(address: str) -> bool:
    try:
        return not is_on_curve(address)
    except ValueError:
        return False


def find_program_address(seeds: list[bytes], program_id: str) -> str | None:
    """Solana's program-derived address: the first bump from 255 down whose sha256(seeds, bump, program, marker) is off the
    ed25519 curve (findProgramAddressSync in the cached pump.fun sources)."""
    program = b58decode(program_id)
    for bump in range(255, -1, -1):
        candidate = b58encode(hashlib.sha256(b"".join(seeds) + bytes([bump]) + program + b"ProgramDerivedAddress").digest())
        if off_curve(candidate):
            return candidate
    return None


def bonding_curve_of(mint: str) -> str | None:
    return find_program_address([BONDING_CURVE_SEED, b58decode(mint)], PUMP_PROGRAM)


def known_program_accounts(mint: str) -> dict[str, str]:
    """Program accounts of this coin that receive tokens, derived from cited seeds and named (never called wallets)."""
    named = {}
    curve = bonding_curve_of(mint)
    if curve:
        named[curve] = "pump bonding curve of this mint"
    authority = find_program_address([POOL_AUTHORITY_SEED, b58decode(mint)], PUMP_PROGRAM)
    if authority:
        pool = find_program_address([POOL_SEED, struct.pack("<H", 0), b58decode(authority), b58decode(mint), b58decode(WSOL_MINT)], PUMP_AMM_PROGRAM)
        if pool:
            named[pool] = "canonical PumpSwap pool of this mint"
    vault = find_program_address([SOL_VAULT_SEED], MAYHEM_PROGRAM)
    if vault:
        named[vault] = "pump Mayhem sol vault"
    return named


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


def signatures_payload(address: str, before: str | None) -> dict[str, Any]:
    config: dict[str, Any] = {"limit": SIGNATURE_PAGE, "commitment": "confirmed"}
    if before:
        config["before"] = before
    return {"jsonrpc": "2.0", "id": 1, "method": "getSignaturesForAddress", "params": [address, config]}


def transaction_payload(signature: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": "getTransaction",
            "params": [signature, {"encoding": "jsonParsed", "commitment": "confirmed", "maxSupportedTransactionVersion": 1}]}


def block_payload(slot: int) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": "getBlock",
            "params": [slot, {"encoding": "json", "transactionDetails": "accounts", "rewards": False, "commitment": "confirmed",
                              "maxSupportedTransactionVersion": 1}]}


def default_opener() -> urllib.request.OpenerDirector:
    """No environment proxy (an explicit empty ProxyHandler), no redirects, default TLS verification."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def _bounded_call(function: Callable[[], Any], timeout: float) -> Any:
    """Run one blocking transport step (open, read, close) in a daemon worker and wait at most `timeout` seconds: a hard
    wall-clock bound, the way pda_identity.py, fomoapi.py and solanatracker.py do it. A socket timeout alone restarts on
    every byte, so a server that drip-feeds bytes could otherwise hold the collector far past the deadline."""
    if timeout <= 0:
        raise TimeoutError
    result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def invoke() -> None:
        try:
            result.put((True, function()))
        except BaseException as exc:  # handed back to the bounded caller
            result.put((False, exc))

    worker = threading.Thread(target=invoke, name="create-slot-transport", daemon=True)
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


def send_once(request: urllib.request.Request, opener: Any, *, monotonic: Callable[[], float], max_bytes: int | None = None) -> bytes:
    """One attempt. Returns the body (at most max_bytes, default MAX_BYTES) or raises Failure with a fixed code. Opening,
    every read and the error close run under one hard wall-clock deadline of TIMEOUT_S. An error body is never read."""
    check_url(request.full_url)
    max_bytes = MAX_BYTES if max_bytes is None else max_bytes
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
            if total > max_bytes:
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


def rpc_call(payload: dict[str, Any], opener: Any, *, monotonic: Callable[[], float], sleep: Callable[[float], None],
             max_bytes: int | None = None) -> dict[str, Any]:
    """One JSON-RPC request plus at most one retry after a 429. Returns {result, attempts, reason, http_status,
    rpc_error_code, bytes}; never raises. A JSON-RPC error answer is rpc_error with its numeric code only (its message is
    not kept)."""
    out: dict[str, Any] = {"method": payload.get("method"), "result": None, "attempts": 0, "reason": None, "http_status": None,
                           "rpc_error_code": None, "bytes": 0}
    for attempt in (1, 2):
        out["attempts"] = attempt
        try:
            body = send_once(build_request(payload), opener, monotonic=monotonic, max_bytes=max_bytes)
            out.update(reason=None, http_status=200, bytes=out["bytes"] + len(body))
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


# ----------------------------------------------------------------------------- small validated readers


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class Mismatch(Exception):
    """A failed check on chain data, reduced to a fixed check code."""

    def __init__(self, check: str) -> None:
        super().__init__(check)
        self.check = check


# ----------------------------------------------------------------------------- pointer (a): saved Solana Tracker fields


def pointer_from_solanatracker(run: Path, mint: str) -> dict[str, Any]:
    """The creation signature Solana Tracker gave in this scan's saved solanatracker.json, re-validated here."""
    path = run / "solanatracker.json"
    out: dict[str, Any] = {"source": "solanatracker", "status": "absent", "reason": None, "signature": None, "creator": None, "created_time": None}
    data = _read_json(path)
    if not path.exists():
        out["reason"] = "solanatracker_file_missing"
    elif not isinstance(data, dict) or data.get("schema") != SOLANATRACKER_SCHEMA:
        out["reason"] = "solanatracker_file_unreadable"
    elif data.get("mint") != mint:
        out["reason"] = "solanatracker_other_mint"
    elif not isinstance(data.get("creation"), dict):
        out["reason"] = "creation_fields_missing"
    elif data["creation"].get("status") != "ok" or not is_signature(data["creation"].get("created_tx")):
        out["reason"] = "creation_fields_missing" if data["creation"].get("status") != "ok" else "created_tx_invalid"
    else:
        creation = data["creation"]
        created = _int(creation.get("created_time"))
        out.update(status="ok", signature=creation["created_tx"], creator=creation.get("creator") if is_address(creation.get("creator")) else None,
                   created_time=created if created is not None and created >= MIN_TS else None)
    return out


# ----------------------------------------------------------------------------- pointer (b): the oldest signature of a create-time account


def pointer_accounts(mint: str, token_program: str | None) -> list[tuple[str, str | None]]:
    """The accounts pointer (b) reads, in order, each derived from cited seeds. A Token-2022 coin is a create_v2 coin, whose
    mayhem_state PDA no other instruction of the cached pump, pump_amm and pump_fees IDLs names; an SPL Token coin is a
    legacy create coin, whose Metaplex metadata PDA only pump's create, set_creator and set_metaplex_creator and pump_amm's
    set_coin_creator name; the bonding
    curve (busy while the coin trades on it) comes last. The token program comes from this scan's saved
    holder-analysis.json; unknown tries all three."""
    raw = b58decode(mint)
    mayhem = ("mayhem_state", find_program_address([MAYHEM_STATE_SEED, raw], MAYHEM_PROGRAM))
    metadata = ("metadata", find_program_address([METADATA_SEED, b58decode(METAPLEX_PROGRAM), raw], METAPLEX_PROGRAM))
    curve = ("bonding_curve", bonding_curve_of(mint))
    if token_program == TOKEN_2022_PROGRAM:
        return [mayhem, curve]
    if token_program == SPL_TOKEN_PROGRAM:
        return [metadata, curve]
    return [mayhem, metadata, curve]


def saved_token_program(run: Path, mint: str) -> str | None:
    data = _read_json(run / "holder-analysis.json")
    if not isinstance(data, dict) or data.get("mint") != mint:
        return None
    program = _dict(data.get("token")).get("token_program")
    return program if program in (TOKEN_2022_PROGRAM, SPL_TOKEN_PROGRAM) else None


def pointer_from_signatures(mint: str, token_program: str | None, opener: Any, calls: list[dict[str, Any]], *,
                            monotonic: Callable[[], float], sleep: Callable[[float], None]) -> dict[str, Any]:
    """getSignaturesForAddress pages (newest to oldest, current/solana/rpc.md) over the pointer accounts in order, at most
    MAX_SIGNATURE_PAGES pages in total; the oldest successful signature of the first account whose history start is reached."""
    out: dict[str, Any] = {"source": "oldest_signature", "status": "absent", "reason": None, "account": None, "address": None, "signature": None,
                           "slot": None, "block_time": None, "token_program": token_program, "pages": 0, "tried": []}
    for kind, address in pointer_accounts(mint, token_program):
        if out["pages"] >= MAX_SIGNATURE_PAGES:
            break
        tried = {"account": kind, "address": address, "pages": 0, "signatures_seen": 0, "outcome": None}
        out["tried"].append(tried)
        if address is None:
            tried["outcome"] = "no_address"
            continue
        before, oldest_ok, last_slot = None, None, None
        while out["pages"] < MAX_SIGNATURE_PAGES:
            got = rpc_call(signatures_payload(address, before), opener, monotonic=monotonic, sleep=sleep)
            calls.append(_call_facts(got))
            out["pages"] += 1
            tried["pages"] += 1
            page = got["result"]
            if got["reason"] is not None or not isinstance(page, list) or len(page) > SIGNATURE_PAGE:
                tried.update(outcome="signatures_read_failed", read_reason=got["reason"] or "invalid_shape", rpc_error_code=got["rpc_error_code"])
                out["reason"] = "signatures_read_failed"
                return out  # a failed read is loud: no further account is tried
            for entry in page:
                signature, slot = _dict(entry).get("signature"), _int(_dict(entry).get("slot"))
                if not is_signature(signature) or slot is None or (last_slot is not None and slot > last_slot):
                    tried.update(outcome="signatures_read_failed", read_reason="invalid_shape")
                    out["reason"] = "signatures_read_failed"
                    return out
                last_slot = slot
                tried["signatures_seen"] += 1
                if entry.get("err") is None:
                    oldest_ok = {"signature": signature, "slot": slot, "block_time": _int(entry.get("blockTime"))}
            if len(page) < SIGNATURE_PAGE:  # the start of this account's history is reached
                break
            before = page[-1]["signature"]
        else:
            tried["outcome"] = "history_too_long"
            continue
        if oldest_ok is None:
            tried["outcome"] = "no_signatures" if tried["signatures_seen"] == 0 else "no_successful_signature"
            continue
        tried["outcome"] = "found"
        out.update(status="ok", reason=None, account=kind, address=address, **oldest_ok)
        return out
    out["reason"] = out["tried"][-1]["outcome"] if out["tried"] else "no_address"
    return out


def _call_facts(got: dict[str, Any]) -> dict[str, Any]:
    return {"method": got["method"], "attempts": got["attempts"], "reason": got["reason"], "http_status": got["http_status"],
            "rpc_error_code": got["rpc_error_code"], "bytes": got["bytes"]}


# ----------------------------------------------------------------------------- the create transaction


def _keys(message_keys: Any) -> list[dict[str, Any]]:
    """Annotated account keys ({pubkey, signer}) of a jsonParsed transaction or an 'accounts' block entry."""
    if not isinstance(message_keys, list) or not message_keys:
        raise Mismatch("account_keys")
    keys = []
    for item in message_keys:
        pubkey = item.get("pubkey") if isinstance(item, dict) else None
        if not is_address(pubkey) or not isinstance(item.get("signer"), bool):
            raise Mismatch("account_keys")
        keys.append({"pubkey": pubkey, "signer": item["signer"]})
    return keys


def token_deltas(meta: dict[str, Any], keys: list[dict[str, Any]], mint: str) -> tuple[dict[str, int], set[int], bool, bool]:
    """Per owner, post minus pre raw balance of this mint (current/solana/rpc.md token balances: accountIndex, mint,
    owner, uiTokenAmount.amount). Returns (deltas, decimals seen, any pre entry, any post entry). A balance whose owner was
    not recorded is keyed 'account:<token account>'."""
    deltas: dict[str, int] = {}
    decimals: set[int] = set()
    seen = {"preTokenBalances": False, "postTokenBalances": False}
    for side, sign in (("preTokenBalances", -1), ("postTokenBalances", 1)):
        entries = meta.get(side)
        if not isinstance(entries, list):  # null or missing balances are unknown, never empty (current/solana/rpc.md: array | null)
            raise Mismatch("transaction_meta")
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("mint") != mint:
                continue
            index, amount = _int(entry.get("accountIndex")), _dict(entry.get("uiTokenAmount")).get("amount")
            places = _int(_dict(entry.get("uiTokenAmount")).get("decimals"))
            if index is None or not 0 <= index < len(keys) or not isinstance(amount, str) or not amount.isdigit() or places is None:
                raise Mismatch("token_balances")
            owner = entry.get("owner")
            key = owner if is_address(owner) else "account:" + keys[index]["pubkey"]
            deltas[key] = deltas.get(key, 0) + sign * int(amount)
            decimals.add(places)
            seen[side] = True
    return deltas, decimals, seen["preTokenBalances"], seen["postTokenBalances"]


def _instructions(tx: dict[str, Any], meta: dict[str, Any]) -> list[dict[str, Any]]:
    """Top-level then inner instructions of a jsonParsed transaction (partially decoded form: programId, accounts, data)."""
    found = list(_dict(tx.get("message")).get("instructions") or [])
    for group in meta.get("innerInstructions") or []:
        found += list(_dict(group).get("instructions") or [])
    return [ix for ix in found if isinstance(ix, dict)]


def _skip_string(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise Mismatch("create_args")
    size = struct.unpack_from("<I", data, offset)[0]
    if size > MAX_ARG_STRING or offset + 4 + size > len(data):
        raise Mismatch("create_args")
    return offset + 4 + size


def decode_create(ix: dict[str, Any], mint: str, curve: str | None) -> dict[str, Any] | None:
    """A pump create / create_v2 instruction for THIS mint -> {kind, user, creator}; None when it is not one; Mismatch when
    it claims to be one and fails a check (pump.json accounts and args: name, symbol, uri strings, then creator pubkey)."""
    if ix.get("programId") != PUMP_PROGRAM or not isinstance(ix.get("data"), str) or not isinstance(ix.get("accounts"), list):
        return None
    try:
        data = b58decode(ix["data"])
    except ValueError:
        return None
    kind = CREATE_DISCRIMINATORS.get(data[:8])
    accounts = ix["accounts"]
    if kind is None or not accounts or accounts[CREATE_ACCOUNT_MINT] != mint:
        return None
    if len(accounts) <= CREATE_ACCOUNT_USER[kind] or not all(is_address(a) for a in accounts):
        raise Mismatch("create_accounts")
    if accounts[CREATE_ACCOUNT_BONDING_CURVE] != curve:
        raise Mismatch("bonding_curve_derivation")
    offset = 8
    for _ in range(3):  # name, symbol, uri: skipped, never kept
        offset = _skip_string(data, offset)
    if offset + 32 > len(data) or data[offset:offset + 32] == bytes(32):
        raise Mismatch("create_args")
    return {"kind": kind, "user": accounts[CREATE_ACCOUNT_USER[kind]], "creator": b58encode(data[offset:offset + 32])}


def initializes_mint(tx: dict[str, Any], meta: dict[str, Any], mint: str) -> bool:
    """True when the transaction initializes THIS mint: a jsonParsed spl-token instruction (both token programs parse as
    program "spl-token", parse_instruction.rs) of type initializeMint or initializeMint2 whose info.mint is the mint
    (parse_token.rs: account 0), top level or inner."""
    for ix in _instructions(tx, meta):
        parsed = ix.get("parsed")
        if ix.get("program") == "spl-token" and ix.get("programId") in (SPL_TOKEN_PROGRAM, TOKEN_2022_PROGRAM) and isinstance(parsed, dict) \
                and parsed.get("type") in ("initializeMint", "initializeMint2") and _dict(parsed.get("info")).get("mint") == mint:
            return True
    return False


def verify_create_tx(result: Any, signature: str, mint: str, expected_slot: int | None, now: float) -> dict[str, Any]:
    """The getTransaction answer -> the verified create facts. Raises Mismatch(check) on any failed check."""
    if not isinstance(result, dict):
        raise Mismatch("not_found")
    slot, block_time, meta, tx = _int(result.get("slot")), _int(result.get("blockTime")), result.get("meta"), result.get("transaction")
    if slot is None or not isinstance(meta, dict) or not isinstance(tx, dict):
        raise Mismatch("transaction_shape")
    if block_time is not None and not MIN_TS <= block_time <= now + CLOCK_SLACK_S:
        raise Mismatch("block_time")
    signatures = tx.get("signatures")
    if not isinstance(signatures, list) or not signatures or signatures[0] != signature:
        raise Mismatch("signature")
    if expected_slot is not None and slot != expected_slot:
        raise Mismatch("slot")
    if meta.get("err") is not None:
        raise Mismatch("transaction_failed")
    keys = _keys(_dict(tx.get("message")).get("accountKeys"))
    signers = [k["pubkey"] for k in keys if k["signer"]]
    if not keys[0]["signer"]:
        raise Mismatch("account_keys")
    deltas, decimals, any_pre, any_post = token_deltas(meta, keys, mint)
    curve = bonding_curve_of(mint)
    create = None
    for ix in _instructions(tx, meta):
        create = decode_create(ix, mint, curve)
        if create:
            break
    if len(decimals) > 1:
        raise Mismatch("token_balances")
    supply = sum(v for v in deltas.values() if v > 0) if not any_pre and any_post else None
    if create:
        method = "pump_" + create["kind"]
    elif initializes_mint(tx, meta, mint) and supply:
        method = "initialize_mint"
    else:
        raise Mismatch("no_create_of_this_mint")
    deployer = create["user"] if create else None
    creator = create["creator"] if create else None
    dev = [w for w in dict.fromkeys([deployer, creator]) if w]
    dev_buys = {w: deltas.get(w, 0) for w in dev if deltas.get(w, 0) > 0}
    return {"signature": signature, "slot": slot, "block_time": block_time, "method": method, "deployer": deployer,
            "deployer_signed": deployer in signers if deployer else None, "creator": creator, "fee_payer": keys[0]["pubkey"],
            "signers": signers, "mint_signed": mint in signers, "decimals": next(iter(decimals)) if decimals else None,
            "supply_at_create_raw": supply, "dev_wallets": dev, "dev_buys_raw": dev_buys, "dev_buy_raw": sum(dev_buys.values())}


# ----------------------------------------------------------------------------- the blocks


def read_block(got: dict[str, Any], slot: int, mint: str, create_signature: str | None) -> dict[str, Any]:
    """One getBlock answer -> {slot, status, ..., transactions: [txs of this mint whose balances rose]}."""
    facts = {"slot": slot, "status": "unavailable", "reason": None, "rpc_error_code": got.get("rpc_error_code"), "attempts": got["attempts"],
             "bytes": got["bytes"], "block_time": None, "transactions_in_block": None, "touching_mint": 0, "failed_touching_mint": 0,
             "create_position": None, "without_meta": 0, "buys": []}
    if got["reason"] == "rpc_error" and got.get("rpc_error_code") in SKIPPED_SLOT_CODES:
        return {**facts, "status": "skipped", "reason": "slot_skipped"}
    if got["reason"] is not None:
        return {**facts, "reason": got["reason"]}
    block = got["result"]
    if block is None:
        return {**facts, "reason": "block_not_available"}
    try:
        if not isinstance(block, dict) or not isinstance(block.get("transactions"), list):
            raise Mismatch("block_shape")
        facts["block_time"] = _int(block.get("blockTime"))
        facts["transactions_in_block"] = len(block["transactions"])
        seen_create = False
        for position, item in enumerate(block["transactions"]):
            tx, meta = _dict(_dict(item).get("transaction")), _dict(item).get("meta")
            signatures = tx.get("signatures")
            if not isinstance(signatures, list) or not signatures or not is_signature(signatures[0]):
                raise Mismatch("block_shape")
            if signatures[0] == create_signature:
                seen_create = True
                facts["create_position"] = position
            if not isinstance(meta, dict) or not all(isinstance(meta.get(side), list) for side in ("preTokenBalances", "postTokenBalances")):
                facts["without_meta"] += 1  # no metadata or no token balances: this transaction is not read, never counted as no buy
                continue
            if not any(isinstance(e, dict) and e.get("mint") == mint for side in ("preTokenBalances", "postTokenBalances") for e in meta[side]):
                continue
            facts["touching_mint"] += 1
            if meta.get("err") is not None:
                facts["failed_touching_mint"] += 1
                continue
            keys = _keys(tx.get("accountKeys"))
            deltas, _decimals, _pre, _post = token_deltas(meta, keys, mint)
            credited = {owner: amount for owner, amount in deltas.items() if amount > 0}
            if credited:
                facts["buys"].append({"slot": slot, "position": position, "signature": signatures[0], "fee_payer": keys[0]["pubkey"],
                                      "signers": [k["pubkey"] for k in keys if k["signer"]], "credited": credited,
                                      "is_create_tx": signatures[0] == create_signature})
        if create_signature is not None and not seen_create:
            raise Mismatch("create_tx_not_in_block")
    except Mismatch as exc:
        return {**facts, "status": "unavailable", "reason": "layout_mismatch", "check": exc.check, "buys": []}
    return {**facts, "status": "read"}


# ----------------------------------------------------------------------------- saved first-wave files (offline)


def scan_supply(run: Path, mint: str, decimals: int | None) -> dict[str, Any] | None:
    """The mint's supply as this scan's analysis collector read it (holder-analysis.json token.supply_ui, token.decimals),
    in raw units, cut toward zero; None when missing, for another mint or with other decimals."""
    data = _read_json(run / "holder-analysis.json")
    if not isinstance(data, dict) or data.get("mint") != mint:
        return None
    token = _dict(data.get("token"))
    places, supply_ui = _int(token.get("decimals")), token.get("supply_ui")
    if places is None or places != decimals or not 0 <= places <= 18 or isinstance(supply_ui, bool) or not isinstance(supply_ui, (int, float)) \
            or not math.isfinite(supply_ui) or supply_ui <= 0:
        return None
    raw = int((decimal.Decimal(repr(supply_ui)) * (10 ** places)).to_integral_value(rounding=decimal.ROUND_DOWN))
    return {"raw": raw, "decimals": places, "source": "holder-analysis.json"} if raw > 0 else None


def funded_by(run: Path, mint: str) -> dict[str, Any]:
    """This scan's saved funded-by rows: wallet -> [{funder, source, funded_at}], the funders those files label as a service
    (an exchange, bridge or app), and how each file was read. No network."""
    by_wallet: dict[str, list[dict[str, Any]]] = {}
    labelled: set[str] = set()
    read: dict[str, str] = {}

    def add(wallet: str, funder: str, source: str, funded_at: int | None) -> None:
        entries = by_wallet.setdefault(wallet, [])
        for entry in entries:
            if entry["funder"] == funder:
                entry["sources"] = sorted(set(entry["sources"]) | {source})
                entry["funded_at"] = entry["funded_at"] if entry["funded_at"] is not None else funded_at
                return
        entries.append({"funder": funder, "sources": [source], "funded_at": funded_at})

    holders = _read_json(run / "holders.json")
    funders = _read_json(run / "funders.json")
    if not (run / "funders.json").exists():
        read["funders.json"] = "missing"
    elif not isinstance(holders, dict) or holders.get("mint") != mint:
        read["funders.json"] = "holders.json other mint or unreadable"
    elif not isinstance(funders, dict):
        read["funders.json"] = "unreadable"
    elif not isinstance(funders.get("rows"), list):
        read["funders.json"] = "no rows (older format)"
    else:
        read["funders.json"] = "read"
        for row in funders["rows"]:
            row = _dict(row)
            if row.get("status") == "funded" and is_address(row.get("wallet")) and is_address(row.get("funder")):
                ts = _int(row.get("funded_at"))
                add(row["wallet"], row["funder"], "funders.json", ts if ts is not None and ts >= MIN_TS else None)
                if row.get("funder_name") is not None or row.get("funder_type") is not None:
                    labelled.add(row["funder"])
    analysis = _read_json(run / "holder-analysis.json")
    if not (run / "holder-analysis.json").exists():
        read["holder-analysis.json"] = "missing"
    elif not isinstance(analysis, dict) or analysis.get("mint") != mint:
        read["holder-analysis.json"] = "other mint or unreadable"
    else:
        read["holder-analysis.json"] = "read"
        for row in analysis.get("top_holders") if isinstance(analysis.get("top_holders"), list) else []:
            row = _dict(row)
            if is_address(row.get("owner")) and is_address(row.get("funder")):
                add(row["owner"], row["funder"], "holder-analysis.json", None)
        services = _dict(_dict(analysis.get("clusters")).get("service_funder_wallets"))
        labelled |= {a for a in services if is_address(a)}
    return {"by_wallet": by_wallet, "labelled": labelled, "read": read}


# ----------------------------------------------------------------------------- the trace


def trace(create: dict[str, Any], slots: list[dict[str, Any]], mint: str, funding: dict[str, Any]) -> dict[str, Any]:
    """Buyers, program accounts, co-signed buys, shared fee payers and shared first funders over the read slots."""
    named = known_program_accounts(mint)
    dev = set(create["dev_wallets"])
    buys = [b for s in slots if s["status"] == "read" for b in s["buys"]]
    wallets: dict[str, dict[str, Any]] = {}
    excluded: dict[str, dict[str, Any]] = {}
    for buy in buys:
        for owner, amount in buy["credited"].items():
            if owner.startswith("account:"):
                kind, name = "unattributed", "token account whose owner was not recorded"
            elif owner in named:
                kind, name = "program", named[owner]
            elif off_curve(owner):
                kind, name = "program", "program account (address off the ed25519 curve)"
            else:
                kind, name = ("dev" if owner in dev else "wallet"), None
            if kind in ("program", "unattributed"):
                entry = excluded.setdefault(owner, {"address": owner.removeprefix("account:"), "kind": kind, "name": name, "amount_raw": 0, "slots": []})
                entry["amount_raw"] += amount
                entry["slots"] = sorted(set(entry["slots"]) | {buy["slot"]})
                continue
            entry = wallets.setdefault(owner, {"wallet": owner, "role": kind, "amount_raw": 0, "first_slot": buy["slot"], "first_position": buy["position"],
                                               "slots": [], "txs": [], "fee_payers": [], "signed_own_tx": False, "in_create_tx": False})
            entry["amount_raw"] += amount
            entry["slots"] = sorted(set(entry["slots"]) | {buy["slot"]})
            entry["txs"].append(buy["signature"])
            entry["fee_payers"] = list(dict.fromkeys(entry["fee_payers"] + [buy["fee_payer"]]))
            entry["signed_own_tx"] = entry["signed_own_tx"] or owner in buy["signers"]
            entry["in_create_tx"] = entry["in_create_tx"] or buy["is_create_tx"]
    parties = set(wallets) | {w for w in dev if not off_curve(w)}
    cosigned, payer_groups = [], {}
    for buy in buys:
        credited = [o for o in buy["credited"] if o in wallets]
        signed = [s for s in buy["signers"] if s in parties]
        group = list(dict.fromkeys(credited + signed))
        if len(group) >= 2:
            cosigned.append({"signature": buy["signature"], "slot": buy["slot"], "position": buy["position"], "wallets": group,
                             "signed_by": signed, "credited": credited, "is_create_tx": buy["is_create_tx"]})
        if credited:
            payer = payer_groups.setdefault(buy["fee_payer"], {"fee_payer": buy["fee_payer"], "wallets": [], "txs": []})
            payer["wallets"] = list(dict.fromkeys(payer["wallets"] + credited))
            payer["txs"].append(buy["signature"])
    listed = {c["signature"] for c in cosigned}  # a fee payer seen only in co-signed buys is already shown there
    shared_payers = [g for g in payer_groups.values() if len(set(g["wallets"]) | ({g["fee_payer"]} & parties)) >= 2 and not set(g["txs"]) <= listed]
    funders: dict[str, list[str]] = {}
    for wallet in wallets:
        for entry in funding["by_wallet"].get(wallet, []):
            funders.setdefault(entry["funder"], []).append(wallet)
    shared = [{"funder": f, "wallets": ws, "labelled_service": f in funding["labelled"], "is_dev": f in dev, "is_create_slot_wallet": f in wallets}
              for f, ws in sorted(funders.items(), key=lambda kv: (-len(kv[1]), kv[0])) if len(ws) >= 2 or f in dev or f in wallets]
    for wallet, entry in wallets.items():
        entry["first_funders"] = [{"funder": e["funder"], "sources": e["sources"], "funded_at": e["funded_at"]} for e in funding["by_wallet"].get(wallet, [])]
    order = sorted(wallets.values(), key=lambda w: (w["role"] != "dev", w["first_slot"], w["first_position"], w["wallet"]))
    return {"wallets": order, "excluded": sorted(excluded.values(), key=lambda e: (-e["amount_raw"], e["address"])), "cosigned": cosigned,
            "shared_fee_payers": shared_payers, "shared_funders": shared, "buy_transactions": len(buys)}


# ----------------------------------------------------------------------------- collect


def _base(mint: str, fetched_at: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "lane": "create_slot_trace", "mint": mint, "status": "unavailable", "reason": None, "check": None, "fetched_at": fetched_at,
        "request": {"host": HOST, "path": "/", "methods": list(ALLOWED_METHODS), "keys": "none", "calls": [], "requests_sent": 0, "bytes_received": 0,
                    "max_calls": MAX_CALLS, "max_requests": MAX_REQUESTS, "max_bytes": MAX_BYTES, "max_block_bytes": MAX_BLOCK_BYTES,
                    "slots_after": SLOTS_AFTER, "max_signature_pages": MAX_SIGNATURE_PAGES},
        "sources": {"pump": "provider-docs current/pumpfun/idls.md (pump.json: create, create_v2, bonding-curve, pool-authority, sol-vault seeds; "
                            "migrate pool seeds) and publicdocs.md (COIN_CREATION.md: account `user` = transaction signer and payer)",
                    "rpc": "provider-docs current/solana/rpc.md (official Solana docs: getBlock transactionDetails accounts, getTransaction, "
                           "getSignaturesForAddress, token balances, public mainnet limits; Agave custom_error.rs codes)",
                    "solanatracker": "provider-docs current/solanatracker/fulldocs.md (creation object: creator, created_tx, created_time)"},
        "pointer": None, "create_tx": None, "supply": None, "slots": [], "trace": None, "funded_by_read": {},
        "presentation_only": True, "note": PRESENTATION_NOTE, "wording": WORDING_NOTE, "cannot_see": CANNOT_SEE,
    }


def collect_create_slot(
    mint: str,
    run: Path,
    *,
    opener: Any | None = None,
    now: Callable[[], float] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """Pointer, verified create transaction, the create slot and the next SLOTS_AFTER slots (sent at the same time), then the
    offline trace. Returns the create_slot_trace.json result; never raises for provider or transport failures."""
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    result = _base(mint, _iso(now()))
    calls: list[dict[str, Any]] = result["request"]["calls"]

    def finish(status: str, reason: str | None = None, check: str | None = None) -> dict[str, Any]:
        result.update(status=status, reason=reason, check=check, fetched_at=_iso(now()))
        result["request"]["requests_sent"] = sum(c["attempts"] for c in calls)
        result["request"]["bytes_received"] = sum(c["bytes"] for c in calls)
        return result

    pointer = pointer_from_solanatracker(run, mint)
    if pointer["status"] != "ok":
        tried = {"solanatracker": pointer["reason"]}
        opener = opener or default_opener()
        pointer = pointer_from_signatures(mint, saved_token_program(run, mint), opener, calls, monotonic=monotonic, sleep=sleep)
        pointer["solanatracker_reason"] = tried["solanatracker"]
    result["pointer"] = pointer
    if pointer["status"] != "ok":
        return finish("unavailable", "no_create_tx_pointer")
    opener = opener or default_opener()
    got = rpc_call(transaction_payload(pointer["signature"]), opener, monotonic=monotonic, sleep=sleep)
    calls.append(_call_facts(got))
    if got["reason"] is not None:
        return finish("unavailable", "create_tx_read_failed", got["reason"])
    try:
        create = verify_create_tx(got["result"], pointer["signature"], mint, pointer.get("slot"), now())
    except Mismatch as exc:
        return finish("unavailable", "create_tx_mismatch", exc.check)
    except Exception:  # noqa: BLE001 - an answer the checks did not foresee: a fixed code, never a crash
        return finish("unavailable", "create_tx_mismatch", "parse_error")
    if pointer["source"] == "solanatracker":
        create["solanatracker_creator_matches"] = (pointer["creator"] in (create["deployer"], create["creator"])) if pointer["creator"] else None
        create["solanatracker_time_offset_s"] = (pointer["created_time"] - create["block_time"]) if pointer["created_time"] and create["block_time"] else None
    result["create_tx"] = create
    slots = [create["slot"] + i for i in range(SLOTS_AFTER + 1)]
    answers: dict[int, dict[str, Any]] = {}

    def fetch(slot: int) -> None:
        answers[slot] = rpc_call(block_payload(slot), opener, monotonic=monotonic, sleep=sleep, max_bytes=MAX_BLOCK_BYTES)

    workers = [threading.Thread(target=fetch, args=(slot,), name="create-slot-block", daemon=True) for slot in slots]
    for worker in workers:  # the three blocks are sent at the same time: no one-by-one loop
        worker.start()
    for worker in workers:
        worker.join(2 * TIMEOUT_S + RETRY_MAX_WAIT_S + 5)
    for slot in slots:
        got_block = answers.get(slot) or {"method": "getBlock", "result": None, "attempts": 0, "reason": "timeout", "http_status": None,
                                          "rpc_error_code": None, "bytes": 0}
        calls.append(_call_facts(got_block))
        try:
            read = read_block(got_block, slot, mint, create["signature"] if slot == create["slot"] else None)
        except Exception:  # noqa: BLE001
            read = {"slot": slot, "status": "unavailable", "reason": "parse_error", "buys": []}
        result["slots"].append(read)
        got_block["result"] = None  # a block can be tens of MB: drop it once read
    supply = scan_supply(run, mint, create["decimals"])
    at_create = create["supply_at_create_raw"]
    rejected = None
    # HS-FOLLOWUPS-T1 (T3 N10): only a pump coin's supply can never rise above the amount minted at create: pump.fun
    # mints it in the create under its own mint-authority PDA (COIN_CREATION.md) and the coin's mint authority is then
    # revoked (the saved SEXCOIN and 索拉纳 analysis files read mint_authority null), so it can only fall (burns).
    # Another launchpad's mint (initialize_mint) can mint more later, so its scan supply is kept; _share never prints a
    # share over 100%.
    if supply and at_create and supply["raw"] > at_create and create["method"] in ("pump_create", "pump_create_v2"):
        supply, rejected = None, "above_minted_at_create"
    result["supply"] = {"basis": "scan" if supply else ("create" if at_create else None), "scan_raw": supply["raw"] if supply else None,
                        "scan_source": supply["source"] if supply else None, "scan_rejected": rejected, "at_create_raw": at_create,
                        "decimals": create["decimals"]}
    funding = funded_by(run, mint)
    result["funded_by_read"] = funding["read"]
    try:
        result["trace"] = trace(create, result["slots"], mint, funding)
    except Exception:  # noqa: BLE001
        return finish("unavailable", "parse_error")
    others = [w for w in result["trace"]["wallets"] if w["role"] == "wallet"]
    read = [s for s in result["slots"] if s["status"] == "read"]
    whole = [s for s in read if not s.get("without_meta")]
    if not read:
        return finish("unavailable", "blocks_not_read")
    if not whole:
        return finish("unavailable", "layout_mismatch", "transaction_meta")
    complete = all(s["status"] == "skipped" or (s["status"] == "read" and not s.get("without_meta")) for s in result["slots"])
    return finish("empty" if not others and complete else "ok")


def status_line(result: dict[str, Any]) -> str:
    sent = result["request"]["requests_sent"]
    calls = f"{sent} call{'s' if sent != 1 else ''} to the public Solana RPC" if sent else "no RPC call sent"
    if result["status"] not in ("ok", "empty"):
        check = f", check {result['check']}" if result.get("check") else ""
        return f"unavailable ({result['reason']}{check}; {calls})"
    create = result["create_tx"]
    others = [w for w in result["trace"]["wallets"] if w["role"] == "wallet"]
    read = sum(1 for s in result["slots"] if s["status"] == "read")
    head = "ok" if result["status"] == "ok" else "empty"
    return (f"{head} (create slot {create['slot']}, {read} of {len(result['slots'])} slots read; {len(others)} other "
            f"wallet{'s' if len(others) != 1 else ''} bought; {calls})")


# ----------------------------------------------------------------------------- presentation (synthesis, offline)


KNOWN_CODES = frozenset({
    "scheme_not_https", "host_not_allowlisted", "path_not_allowlisted", "method_not_allowlisted", "redirect_disallowed", "bad_request",
    "access_denied", "not_found", "method_unavailable", "request_too_large", "rate_limited", "service_unavailable", "server_error",
    "http_error", "invalid_response", "response_too_large", "timeout", "network_error", "request_failed", "invalid_json", "invalid_shape",
    "rpc_error", "no_create_tx_pointer", "create_tx_read_failed", "create_tx_mismatch", "parse_error", "layout_mismatch", "slot_skipped",
    "block_not_available", "solanatracker_file_missing", "solanatracker_file_unreadable", "solanatracker_other_mint", "creation_fields_missing",
    "created_tx_invalid", "no_address", "found", "signatures_read_failed", "no_signatures", "no_successful_signature", "history_too_long",
    "account_keys", "token_balances", "create_accounts", "bonding_curve_derivation", "create_args", "not_found", "transaction_shape",
    "block_time", "signature", "slot", "transaction_failed", "no_create_of_this_mint", "block_shape", "create_tx_not_in_block",
    "blocks_not_read", "transaction_meta",
})
METHOD_TEXT = {"pump_create": "pump create", "pump_create_v2": "pump create_v2",
               "initialize_mint": "the mint initialized and first minted in this tx (spl-token initializeMint), not a pump create"}
POINTER_TEXT = {"solanatracker": "Solana Tracker's creation tx (saved solanatracker.json)",
                "oldest_signature": "the oldest successful signature of"}
EXCLUDED_NAMES = {name: name for name in ("pump bonding curve of this mint", "canonical PumpSwap pool of this mint", "pump Mayhem sol vault",
                                         "program account (address off the ed25519 curve)", "token account whose owner was not recorded")}
ACCOUNT_TEXT = {"mayhem_state": "this coin's pump mayhem_state account", "metadata": "this coin's Metaplex metadata account",
                "bonding_curve": "this coin's pump bonding curve"}


def _code(value: Any) -> str:
    """A reason or check code read back from the saved file: printed only when it is one of this script's fixed codes."""
    return value if isinstance(value, str) and value in KNOWN_CODES else "unrecognized code"


def _addr(value: Any) -> str:
    return value if isinstance(value, str) and SOLANA_ADDRESS_RE.fullmatch(value) else "unknown"


def _sig(value: Any) -> str:
    return value if isinstance(value, str) and SIGNATURE_RE.fullmatch(value) else "unknown"


def _utc(ts: Any) -> str:
    value = _int(ts)
    if value is None or not (0 < value < 7_258_118_400):
        return "unknown time"
    return dt.datetime.fromtimestamp(value, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _tokens(raw: Any, decimals: Any) -> str:
    """A token amount from base units, cut toward zero to 2 decimals, never rounded up."""
    amount, places = _int(raw), _int(decimals)
    if amount is None or places is None or amount < 0 or not 0 <= places <= 30:
        return "unknown"
    whole, frac = divmod(amount, 10 ** places)
    cents = (frac * 100) // (10 ** places) if places else 0
    return f"{whole:,}.{cents:02d}"


def _share(raw: Any, supply: Any) -> str:
    """Share of supply in percent, cut toward zero to 2 decimals (0.00999% reads 'under 0.01%'), never rounded up and never
    over 100% (an amount above the supply basis is not a readable share)."""
    amount, total = _int(raw), _int(supply)
    if amount is None or total is None or total <= 0 or amount < 0:
        return "unknown share"
    if amount > total:
        return OVER_BASIS
    hundredths = amount * 10000 // total
    if hundredths == 0 and amount > 0:
        return "under 0.01%"
    return f"{hundredths // 100}.{hundredths % 100:02d}%"


OVER_BASIS = "more than the supply basis (not a readable share)"


def _share_of(raw: Any, total: Any, what: str, over: str) -> str:
    """'<share> of <what>' (HS-FOLLOWUPS-T1, T3 N10 grammar): an amount above its basis reads '<over>, not a readable
    share' instead of 'more than the supply basis (not a readable share) of <what>'; never a share over 100%."""
    share = _share(raw, total)
    return f"{over}, not a readable share" if share == OVER_BASIS else f"{share} of {what}"


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


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _addrs(values: Any) -> str:
    return ", ".join(_addr(v) for v in _list(values)) or "none"


def _calls_text(request: dict[str, Any]) -> str:
    calls = [c for c in _list(request.get("calls")) if isinstance(c, dict)]
    counts: dict[str, int] = {}
    for c in calls:
        method = c.get("method") if c.get("method") in ALLOWED_METHODS else "other"
        counts[method] = counts.get(method, 0) + 1
    received = _int(request.get("bytes_received"))
    size = f", {received / 1_000_000:.1f} MB received" if received is not None and 0 <= received <= 10 ** 12 else ""
    if not calls:
        return "no RPC call"
    return f"{len(calls)} call{'s' if len(calls) != 1 else ''} (" + ", ".join(f"{n} {m}" for m, n in counts.items()) + ")" + size


def _wallet_line(w: dict[str, Any], create_slot: Any, decimals: Any, supply: Any) -> str:
    slots = [s for s in _list(w.get("slots")) if _int(s) is not None]
    where = ", ".join(f"slot {s}" + (" (create slot)" if s == create_slot else f" (create slot +{s - create_slot})" if _int(create_slot) is not None else "")
                      for s in slots) or "slot unknown"
    if _int(w.get("first_position")) is not None:
        where += f", position {w['first_position']} in its slot"
    txs = [_sig(t) for t in _list(w.get("txs"))]
    payers = [_addr(p) for p in _list(w.get("fee_payers"))]
    own = "signed its own buy" if w.get("signed_own_tx") is True else "did not sign its buy"
    extra = "; inside the create tx" if w.get("in_create_tx") is True else ""
    return (f"    {_addr(w.get('wallet'))}: {_tokens(w.get('amount_raw'), decimals)} tokens ({_share(w.get('amount_raw'), supply)}), {where}{extra}; "
            f"tx {', '.join(txs) or 'unknown'}; fee payer {', '.join(payers) or 'unknown'}; {own}")


FILE_STATES = ("read", "missing", "unreadable", "no rows (older format)", "other mint or unreadable", "holders.json other mint or unreadable")


def _funder_lines(trace_: dict[str, Any], dev: set[str], read: Any) -> list[str]:
    """The shared-first-funder join, attributed to the saved files it came from."""
    wallets = [w for w in _list(trace_.get("wallets")) if isinstance(w, dict)]
    others = [w for w in wallets if w.get("role") == "wallet"]
    if not others:
        return []
    files = ", ".join(f"{name} {state}" for name, state in sorted(_dict(read).items()) if name in ("funders.json", "holder-analysis.json") and state in FILE_STATES)
    lines = [f"  First funders (joined offline from this scan's saved funded-by rows, no call; {files or 'files not read'}):"]
    funded_at = {(_addr(w.get("wallet")), _addr(_dict(f).get("funder"))): _int(_dict(f).get("funded_at"))
                 for w in wallets for f in _list(w.get("first_funders"))}
    for group in [g for g in _list(trace_.get("shared_funders")) if isinstance(g, dict)]:
        funder = _addr(group.get("funder"))
        members = [_addr(w) for w in _list(group.get("wallets"))]
        other_members = [m for m in members if m not in dev]
        if other_members and len(other_members) == len(others) and len(others) > 1:
            who = f"all {len(others)} other create-slot wallets"
        else:
            who = f"{len(other_members)} of the {len(others)} other create-slot wallet{'s' if len(others) != 1 else ''}"
        if len(other_members) < len(members):
            who += " and the dev"
        times = {funded_at.get((m, funder)) for m in members}
        same = next(iter(times)) if len(times) == 1 and None not in times else None
        tags = [f"all funded at the same second, {_utc(same)}"] if same is not None and len(members) > 1 else []
        if group.get("is_dev") is True:
            tags.append("the funder is the dev")
        if group.get("is_create_slot_wallet") is True:
            tags.append("the funder is itself a create-slot wallet")
        if group.get("labelled_service") is True:
            tags.append("a labelled service wallet (exchange, bridge or app) in the funded-by data: weak linkage, not one owner")
        lines.append(f"    {funder} first funded {who}: " + ", ".join(m + (" (dev)" if m in dev else "") for m in members)
                     + (f" ({'; '.join(tags)})" if tags else ""))
    missing = [_addr(w.get("wallet")) for w in others if not _list(w.get("first_funders"))]
    if missing:
        lines.append(f"    not in this scan's funded-by data: {', '.join(missing)}")
    shown = {_addr(w) for g in _list(trace_.get("shared_funders")) if isinstance(g, dict) for w in _list(g.get("wallets"))}
    for w in [w for w in others if _list(w.get("first_funders")) and _addr(w.get("wallet")) not in shown]:
        funders = ", ".join(_addr(_dict(f).get("funder")) for f in _list(w.get("first_funders")))
        lines.append(f"    {_addr(w.get('wallet'))}: first funder {funders} (no other create-slot wallet shares it)")
    return lines


def _pick(table: dict[str, str], key: Any, default: str) -> str:
    """A fixed phrase for a code read back from the saved file; anything that is not one of the table's codes (a list, a
    dict, other text) reads as the default."""
    return table[key] if isinstance(key, str) and key in table else default


def present(run: Path) -> list[str]:
    """The block the synthesis prints. Reads only the saved file: no network, no key. A missing, foreign or malformed file
    or value reads as not read, never as a crash."""
    path = run / OUT_DIR / OUT_FILE
    data = _read_json(path)
    result = data if _valid_saved(data) else None
    head = f"Create slot (follow-up lane create_slot_trace; {INDEPENDENCE_NOTE})"
    if result is None:
        return [f"{head}: not read ({OUT_DIR}/{OUT_FILE} " + ("missing" if not path.exists() else "unreadable") + ")"]
    state = {"ok": "read", "empty": "read", "unavailable": "unavailable"}[result["status"]]
    try:
        reason = "" if result["status"] != "unavailable" else f" ({_code(result.get('reason'))}" + (f", check {_code(result.get('check'))}" if result.get("check") else "") + ")"
        age = _age_min(result.get("fetched_at"))
        lines = [f"{head}: {state}{reason}" + (f"; data age {age:.0f} min" if age is not None else "; data age unknown") + f"; {_calls_text(_dict(result.get('request')))}"]
    except Exception:  # noqa: BLE001 - a damaged header is not read, never a crash
        lines = [f"{head}: {state} (header not readable)"]
    try:
        pointer = _dict(result.get("pointer"))
        if result["status"] != "unavailable":
            lines += _ok_lines(result, pointer)
        elif result.get("reason") == "no_create_tx_pointer":
            lines += _no_pointer_lines(pointer)
        elif isinstance(result.get("create_tx"), dict):  # verified create, but no block could be used: say what is known
            lines += _create_lines(result, pointer)
            lines += ["  No buyer list: " + ("no block was read" if result.get("reason") == "blocks_not_read" else
                                             "every block read had transactions without metadata, so no buyer conclusion is drawn"),
                      _slots_line(result)]
    except Exception:  # noqa: BLE001 - a damaged file is not read, never a crash
        lines.append("  not read (unreadable entry)")
    lines += [f"  {WORDING_NOTE}", f"  cannot see: {CANNOT_SEE}", f"  {PRESENTATION_NOTE}"]
    return lines


def _no_pointer_lines(pointer: dict[str, Any]) -> list[str]:
    tried = [t for t in _list(pointer.get("tried")) if isinstance(t, dict)]
    reads = "; ".join(f"{_pick(ACCOUNT_TEXT, t.get('account'), 'account')} {_addr(t.get('address'))}: {_code(t.get('outcome'))}"
                      + (f" ({_code(t.get('read_reason'))})" if t.get("read_reason") else "")
                      + f", {_int(t.get('signatures_seen'))} signatures in {_int(t.get('pages'))} page{'s' if t.get('pages') != 1 else ''}" for t in tried)
    return [f"  no free pointer to the create tx: Solana Tracker {_code(pointer.get('solanatracker_reason'))}; "
            f"oldest-signature reads (at most {MAX_SIGNATURE_PAGES} pages of {SIGNATURE_PAGE:,}): {reads or 'none sent'}"]


def _basis(result: dict[str, Any]) -> tuple[Any, Any, Any]:
    supply = _dict(result.get("supply"))
    basis = supply.get("basis")
    total = supply.get("scan_raw") if basis == "scan" else supply.get("at_create_raw") if basis == "create" else None
    return basis, total, supply.get("decimals")


def _create_lines(result: dict[str, Any], pointer: dict[str, Any]) -> list[str]:
    create, supply = _dict(result.get("create_tx")), _dict(result.get("supply"))
    basis, total, decimals = _basis(result)
    slot = _int(create.get("slot"))
    deployer, creator = create.get("deployer"), create.get("creator")
    if deployer:
        who = f"by {_addr(deployer)} (the pump signer `user`" + (", also the `creator` argument)" if creator == deployer else f"; `creator` argument {_addr(creator)})")
        if create.get("deployer_signed") is False:
            who += ", which did not sign the transaction itself"
    else:
        who = f"creator not named (no pump create instruction); fee payer {_addr(create.get('fee_payer'))}"
    source = _pick(POINTER_TEXT, pointer.get("source"), "unknown pointer")
    if pointer.get("source") == "oldest_signature":
        source += f" {_pick(ACCOUNT_TEXT, pointer.get('account'), 'an account')} {_addr(pointer.get('address'))}"
    first = next((s for s in _list(result.get("slots")) if isinstance(s, dict) and slot is not None and s.get("slot") == slot), {})
    place, count = _int(first.get("create_position")), _int(first.get("transactions_in_block"))
    position = f" at position {place} of {count} in its slot" if place is not None else ""
    lines = [f"  Created in slot {slot if slot is not None else 'unknown'} at {_utc(create.get('block_time'))} {who}; create tx {_sig(create.get('signature'))}{position} "
             f"({_pick(METHOD_TEXT, create.get('method'), 'unknown method')}, verified on-chain; pointer: {source})"]
    if pointer.get("source") == "solanatracker" and create.get("solanatracker_creator_matches") is False:
        lines.append("  Solana Tracker's creator is not the on-chain signer or creator argument (the on-chain values are shown)")
    at_create = supply.get("at_create_raw")
    dev_raw = _int(create.get("dev_buy_raw"))
    if deployer and dev_raw:
        minted = f"the {_tokens(at_create, decimals)} minted at create"
        also = f" ({_share_of(dev_raw, at_create, minted, 'more than ' + minted)})" if basis == "scan" and _int(at_create) else ""
        lines.append(f"  The dev bought {_tokens(dev_raw, decimals)} tokens in the create tx: {_share_of(dev_raw, total, 'supply', 'more than the supply basis')}{also}")
    elif deployer:
        lines.append("  The dev's balance did not rise in the create tx (no dev buy inside it)")
    return lines


def _slots_line(result: dict[str, Any]) -> str:
    states = []
    for s in [s for s in _list(result.get("slots")) if isinstance(s, dict)]:
        if s.get("status") == "read":
            failed, missing = _int(s.get("failed_touching_mint")), _int(s.get("without_meta"))
            states.append(f"{_int(s.get('slot'))} read ({_int(s.get('transactions_in_block'))} transactions, {_int(s.get('touching_mint'))} touch this token"
                          + (f", {failed} of them failed" if failed else "")
                          + (f"; {missing} transaction{'s' if missing != 1 else ''} without metadata or token balances: not read" if missing else "") + ")")
        elif s.get("status") == "skipped":
            states.append(f"{_int(s.get('slot'))} skipped (no block in this slot)")
        else:
            check = f", check {_code(s.get('check'))}" if s.get("check") else ""
            states.append(f"{_int(s.get('slot'))} not read ({_code(s.get('reason'))}{check})")
    return "  Slots: " + ("; ".join(states) or "none read")


def _span(result: dict[str, Any], slot: int | None) -> str:
    """The slots a 'bought' or 'no other wallet' line may speak for: read in full (no transaction without metadata) or
    skipped. A slot not read, or read only in part, is named as such and never counted as seen."""
    slots = [s for s in _list(result.get("slots")) if isinstance(s, dict)]
    seen = [_int(s.get("slot")) for s in slots if _int(s.get("slot")) is not None
            and (s.get("status") == "skipped" or (s.get("status") == "read" and not _int(s.get("without_meta"))))]
    unread = (len(slots) if slots else SLOTS_AFTER + 1) - len(seen)
    if not seen:
        return "no slot read in full"
    if unread == 0 and slot is not None and seen == [slot + i for i in range(SLOTS_AFTER + 1)]:
        return f"slots {slot} to {slot + SLOTS_AFTER}"
    return (f"the slot{'s' if len(seen) != 1 else ''} read in full, {', '.join(str(x) for x in seen)} "
            f"({unread} of the {SLOTS_AFTER + 1} slots not read or read only in part)")


def _bought_in(result: dict[str, Any], slot: int | None, others: list[dict[str, Any]], span: str) -> tuple[str, str, str]:
    """Where the 'N other wallets bought' sentence says the buys were seen (HS-FOLLOWUPS-T1, T3 N9), as (where, a note
    before the create-slot count, a note after it). Every slot read in full or skipped: the whole window, as before.
    Otherwise the slots where these wallets' buys were actually seen (never a slot where none was seen), a slot read only
    in part marked as such, then how many of the slots were not read or read only in part."""
    if not (slot is not None and span == f"slots {slot} to {slot + SLOTS_AFTER}"):
        slots = [s for s in _list(result.get("slots")) if isinstance(s, dict)]
        part = {_int(s.get("slot")) for s in slots if s.get("status") == "read" and _int(s.get("without_meta"))}
        full = [s for s in slots if _int(s.get("slot")) is not None
                and (s.get("status") == "skipped" or (s.get("status") == "read" and not _int(s.get("without_meta"))))]
        unread = (len(slots) if slots else SLOTS_AFTER + 1) - len(full)
        seen = sorted({x for w in others for x in _list(w.get("slots")) if _int(x) is not None})
        if seen:
            names = [str(x) for x in seen]
            marked = [str(x) for x in seen if x in part]
            where = ("slot " if len(names) == 1 else "slots ") + _joined(names)
            before = "" if not marked else "read only in part; " if len(names) == 1 else f"{_joined(marked)} read only in part; "
            after = f"; {unread} of the {SLOTS_AFTER + 1} slots not read or read only in part" if unread > 0 else ""
            return where, before, after
    return span, "", ""


def _joined(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _ok_lines(result: dict[str, Any], pointer: dict[str, Any]) -> list[str]:
    create, trace_ = _dict(result.get("create_tx")), _dict(result.get("trace"))
    basis, total, decimals = _basis(result)
    slot = _int(create.get("slot"))
    lines = _create_lines(result, pointer)
    wallets = [w for w in _list(trace_.get("wallets")) if isinstance(w, dict)]
    dev_later = [w for w in wallets if w.get("role") == "dev" and any(s != slot or not w.get("in_create_tx") for s in _list(w.get("slots")))]
    for w in dev_later:
        lines.append(f"  The dev wallet {_addr(w.get('wallet'))} also gained {_tokens(w.get('amount_raw'), decimals)} tokens in these slots in total (create tx included)")
    others = [w for w in wallets if w.get("role") == "wallet"]
    span = _span(result, slot)
    if others:
        bought = sum(_int(w.get("amount_raw")) or 0 for w in others)
        in_create = [w for w in others if slot in _list(w.get("slots"))]
        where, before, after = _bought_in(result, slot, others, span)
        lines.append(f"  {len(others)} other wallet{'s' if len(others) != 1 else ''} bought in {where} ({before}{len(in_create)} in the create slot itself{after}): "
                     f"{_tokens(bought, decimals)} tokens, {_share_of(bought, total, 'supply in total', 'more than the supply basis in total')} "
                     "(amounts bought in these slots, not what they hold now)")
        lines += [_wallet_line(w, slot, decimals, total) for w in others]
    else:
        lines.append(f"  No other wallet's balance of this token rose in {span} (what was seen, not an all-clear)")
    for c in [c for c in _list(trace_.get("cosigned")) if isinstance(c, dict)]:
        signed, credited = _list(c.get("signed_by")), _list(c.get("credited"))
        lines.append(f"  Co-signed buy: tx {_sig(c.get('signature'))} (slot {_int(c.get('slot'))}" + (", the create tx" if c.get("is_create_tx") is True else "")
                     + f") is signed by {len(signed)} and credits {len(credited)} of these wallets: signed by {_addrs(signed)}; credits {_addrs(credited)}")
    dev = {w for w in _list(create.get("dev_wallets")) if isinstance(w, str)}
    for g in [g for g in _list(trace_.get("shared_fee_payers")) if isinstance(g, dict)]:
        payer = _addr(g.get("fee_payer"))
        tag = " (the dev)" if payer in dev else ""
        lines.append(f"  One fee payer behind several: {payer}{tag} paid the fees of {len(_list(g.get('txs')))} buy tx crediting {_addrs(g.get('wallets'))}")
    lines += _funder_lines(trace_, dev, result.get("funded_by_read"))
    for e in [e for e in _list(trace_.get("excluded")) if isinstance(e, dict)]:
        name = _pick(EXCLUDED_NAMES, e.get("name"), "program account")
        lines.append(f"  Not counted as a wallet: {_addr(e.get('address'))}, {name} (+{_tokens(e.get('amount_raw'), decimals)} tokens)")
    lines.append(_slots_line(result))
    lines.append(_supply_line(result))
    return lines


def _supply_line(result: dict[str, Any]) -> str:
    basis, total, decimals = _basis(result)
    if basis == "scan":
        at_create, scan = _int(_dict(result.get("supply")).get("at_create_raw")), _int(total)
        grew = (f"; above the {_tokens(at_create, decimals)} minted in the create tx, so more was minted after it"
                if at_create and scan is not None and scan > at_create else "")  # HS-FOLLOWUPS-T1 (T3 N10): not a pump coin
        return f"  Shares are of the mint's supply as this scan's analysis collector read it ({_tokens(total, decimals)} tokens, holder-analysis.json{grew}), cut toward zero"
    if basis == "create":
        why = ("this scan's own supply was above the amount minted at create, so it was not used" if _dict(result.get("supply")).get("scan_rejected") == "above_minted_at_create"
               else "this scan's own supply was not readable")
        return f"  Shares are of the supply minted in the create tx ({_tokens(total, decimals)} tokens; {why}), cut toward zero"
    return "  Shares are unknown: no readable supply"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Trace who bought in a token's create slot over the free public Solana RPC (no key; a free pointer "
                                                 "verified on-chain, the create slot and the next 2 slots; bounded: 30 s, no redirects, no env proxy) and "
                                                 f"save {OUT_DIR}/{OUT_FILE}; or, with --present RUN_DIR, print the block offline. Presentation only.")
    parser.add_argument("mint", nargs="?")
    parser.add_argument("--out", metavar="RUN_DIR", help="run folder: the pointer and the funded-by rows are read from its saved first-wave files")
    parser.add_argument("--present", metavar="RUN_DIR", help="offline: print the block from a saved run folder (no network, no key)")
    args = parser.parse_args(argv)
    if args.present is not None:
        if args.mint or args.out:
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
        result = collect_create_slot(args.mint, run)
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
