#!/usr/bin/env python3
"""Creator-fee recipient of a PumpSwap token for dlmm-scan (first-wave collector `creator_fees`): who collects the
creator fee on every trade of the token's canonical PumpSwap pool, read on-chain for free.

A pump.fun coin that graduated trades in a canonical PumpSwap pool. Every trade there pays a creator fee to the pool's
`coin_creator`: either a plain wallet, or a pump fees program SharingConfig that splits the fee between shareholders in
basis points (the coin creator opted into fee sharing), or, on a holder rewards coin, a pump.fun address that pays the
fee out to holders. Who that is (the dev, a narrative poster, a third party, the holders) is a trust signal that was
checked by hand. This collector finds the pool and reads it, and the SharingConfig when needed, once:

1. Dexscreener (GET /token-pairs/v1/solana/<MINT>, the documented "pools of a given token address"; no key): the pairs
   where this token is the base side give the quote mints. For each, the canonical pool address is DERIVED (never taken
   on trust from Dexscreener) and a pair counts only when its address equals the derivation. The SOL-paired canonical
   pool is always derived as well. From the same answer (no extra request) every Solana pair of this token, either side,
   is saved once per pair address with its dexId (a short identifier, never printed), quote mint and 24 h volume, and
   pairs_capped when the answer held 30 pairs: meteora_pools.py --present reads it for the DLMM share line
   (DS-DLMM-SHARE-T1).
2. Public Solana RPC, one getMultipleAccounts batch: the mint, the mint's SharingConfig address, the mint's pump.fun
   bonding curve and the candidate pools. The bonding curve names the coin's quote mint on-chain (`quote_mint`, the
   default address for a SOL-paired coin) and whether it graduated (`complete`), so the canonical pool is known without
   Dexscreener. Pool `coin_creator` is decoded; when it is the SharingConfig of this mint, its shareholders are decoded
   from the same batch.
3. At most one more getMultipleAccounts read, only when needed: the canonical pool the bonding curve names when it was
   not already a candidate (a coin paired with a token Dexscreener did not list), and any `coin_creator` that is another
   address, to say whether it is a wallet (system-owned or no account, on the ed25519 curve), the SharingConfig of a fee
   program, or another program's account (never called a wallet). When that read holds the pool the bonding curve
   names, the bonding curve's own `creator` field (read in step 2) goes into the same read as a candidate: a pool whose
   coin_creator equals it is classified from that answer. Any other coin creator first seen in that read is not read
   again (the cap is 3 calls): it is shown with its address and "not read", never as a wallet.

Cited layouts (provider-docs cache, read by hand, never guessed; the tests re-derive every offset from the cache):
- current/pumpfun/idls.md, pump_amm.json: program address; account Pool discriminator [241,154,109,4,17,177,109,188];
  type Pool fields in order after the 8-byte Anchor discriminator: pool_bump u8 (8), index u16 (9), creator (11),
  base_mint (43), quote_mint (75), lp_mint (107), pool_base_token_account (139), pool_quote_token_account (171), lp_supply
  u64 (203), coin_creator (211), is_mayhem_mode (243), is_cashback_coin (244), virtual_quote_reserves i128 (245),
  creator_fee_bps u64 (261), can_edit_creator_fee (269), is_holder_reward (270), ...; create_pool seeds "pool", index,
  creator, base_mint, quote_mint.
- current/pumpfun/idls.md, pump.json: program address; migrate seeds pool_authority = ("pool-authority", mint) under pump
  and pool = ("pool", [0, 0], pool_authority, mint, wsol_mint) under pump_amm, wsol_mint So111...112; account BondingCurve
  discriminator [23,183,248,55,96,216,172,96]; type BondingCurve: five u64 reserves fields (8..48), complete bool (48),
  creator (49, read only as a candidate coin creator), is_mayhem_mode (81), is_cashback_coin (82), quote_mint (83), ...
- current/pumpfun/idls.md, pump_fees.json: program address; account SharingConfig discriminator [216,74,9,0,56,140,93,75];
  type SharingConfig: bump u8 (8), version u8 (9), status ConfigStatus (10: 0 Paused, 1 Active), mint (11), admin (43),
  admin_revoked bool (75), shareholders vec<Shareholder {address, share_bps u16}> (u32 length at 76, 34-byte entries from
  80); constant SHARING_CONFIG_SEED "sharing-config"; create_fee_sharing_config seeds ("sharing-config", mint).
- current/pumpfun/publicdocs.md: PUMP_SWAP_CREATOR_FEE_README (coin_creator, canonical pools, pump_pool_authority_pda),
  FEE_PROGRAM_README (isPumpPool: pool.creator == pumpPoolAuthorityPda(baseMint)), CREATOR_FEE_SHARING (the SharingConfig
  PDA, at most 10 shareholders, no duplicates, every share_bps > 0, sum == 10_000, admin revoked after the one update),
  COLLECT_CREATOR_FEE (a coin creator owned by the pump fees program is a sharing_config), HOLDER_REWARDS_README
  (is_holder_reward: the creator fee goes to holders), PUMP_CASHBACK_README (cashback coins route it to traders),
  PUMP_PROGRAM_README (the bonding curve is the PDA ("bonding-curve", mint); fields appended by later upgrades, accounts
  written before a field existed are shorter and read the missing fields as 0 / false / Pubkey::default(); quote_mint is
  Pubkey::default() for SOL-paired coins) and CREATE_WITH_PUMP_COIN_QUOTE (a coin's pool is ("pool", 0u16,
  pool_authority, coin, quote) with wrapped SOL for a SOL-paired coin, or its quote mint otherwise).
- current/spltoken/layouts.md (token interface state.rs Mint: decimals 44, is_initialized 45; 82 bytes); integers are
  little-endian (Borsh).
Every decoded account is validated (owner program, discriminator, length, mint, enum and bool bytes, shareholder count,
duplicates, zero shares, the 10_000 bps sum, and the address the program itself would derive); a failed check gives
unavailable (layout_mismatch) or (mint_mismatch) with the check name. These runtime checks refuse most layout changes,
not all: a field inserted in the middle of the Pool struct could move coin_creator without failing any check, and the
address found there would then be read as the recipient. The real guards against that are pump.fun's documented
append-only layouts (fields are appended, PUMP_SWAP_CREATOR_FEE_README / PUMP_PROGRAM_README) and the cache-parity test
in tests/forensics/test_creator_fees.py, which fails as soon as the provider-docs cache refreshes with a changed IDL.

Requests: api.dexscreener.com (GET, https only, the one documented path, no query) and api.mainnet-beta.solana.com
(POST JSON-RPC getMultipleAccounts only, path /); no key, no extra headers, no redirects, no environment proxy, MAX_BYTES
per answer and a hard TIMEOUT_S wall-clock limit per attempt (opening, every read and closing under one deadline, worker
thread: the pda_identity.py pattern), at most one retry per request and only after a 429 whose Retry-After ends within
RETRY_MAX_WAIT_S, 10 s (the public Solana RPC asks for 10 s; the same rule holds for the Dexscreener lookup, which
x_search.py reuses), or after RETRY_DEFAULT_WAIT_S without one. Calls per scan: 1 Dexscreener + 1 or 2 Solana RPC (at most
3 calls, at most 6 requests with the retries). Free. Worst-case wall time: the 3 calls one after another, each at most
about 70 s (30 s, a retry wait of at most 10 s, 30 s): about 210 s, 15 s more than with the old 5 s wait. There is no
lane-wide deadline.

PRESENTATION ONLY: the synthesis prints the recipient with the offline --present, labelled with any identity the scan's
saved files already give (top holder #N, dev as MadeOnSol's claim); this file is never an engine input and changes no
verdict, flag or threshold. It prints only addresses, numbers, basis points, flags and fixed phrases: no provider-chosen
text (token names, Dexscreener labels, on-chain metadata) is read into the output.

Collector: creator_fees.py <MINT> --out <RUN> writes <RUN>/creator_fees.json and prints one line: ok (...), empty (what
was checked and not found: not graduated, no canonical pool for the bonding curve's quote, ...) or unavailable
(<reason>; ...). Exit 0 whenever the file was saved; exit 2 for a bad mint or --out.
It reads no other file of the run folder (a first-wave collector waits for nothing). Synthesis (offline, no network):
creator_fees.py --present <RUN>. Standard library only; Python >= 3.10.
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
from decimal import ROUND_DOWN, Decimal
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from ha.solana import b58decode, is_on_curve  # noqa: E402
import provider_words as pw  # noqa: E402  (DS-DLMM-SHARE-T1: verdict words in a saved dexId; standard library only, no network)

DEX_HOST = "api.dexscreener.com"
DEX_PATH_PREFIX = "/token-pairs/v1/solana/"   # provider-docs current/dexscreener.md: "Get the pools of a given token address"
RPC_HOST = "api.mainnet-beta.solana.com"
RPC_ENDPOINT = f"https://{RPC_HOST}"
ALLOWED_RPC_METHODS = ("getMultipleAccounts",)
DATA_SLICE_BYTES = 1024          # SharingConfig::MAX_SIZE (CREATOR_FEE_SHARING.md); a PumpSwap pool is 300 bytes
MAX_POOL_CANDIDATES = 8          # canonical pools read in the one batch (the SOL pair plus Dexscreener's other quotes)
MAX_DEX_PAIRS = 200              # pairs looked at in the Dexscreener answer
DEX_PAIRS_CAP = 30               # DS-DLMM-SHARE-T1: busy tokens' live answers held exactly 30 pairs (2026-10-25, 2026-11-02): more may exist
DEX_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")  # a dexId is saved only as a short identifier ("pumpswap", "meteora")
DEX_ID_STRIP = re.compile(r"[^a-z0-9_-]")
MAX_VOLUME_USD = 1e15            # a 24 h volume above this is not read
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = 30.0                 # per attempt: a hard wall-clock limit on open + every read + close (worker thread)
RETRY_MAX_WAIT_S = 10.0          # retry a 429 once only when its Retry-After ends this soon (the public RPC asks for 10 s)
RETRY_DEFAULT_WAIT_S = 1.5       # a 429 without Retry-After is retried once after this wait
MAX_CALLS = 3                    # 1 Dexscreener + at most 2 Solana RPC
MAX_REQUESTS = 2 * MAX_CALLS
USER_AGENT = "holder-scan-creator-fees/1.0"
SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
OUT_FILE = "creator_fees.json"
SCHEMA = "holder-scan-creator-fees/1"
HTTP_REASONS = {400: "bad_request", 401: "access_denied", 403: "access_denied", 404: "not_found", 410: "method_unavailable",
                413: "request_too_large", 429: "rate_limited", 503: "service_unavailable"}

# ----------------------------------------------------------------------------- cited program ids and layouts

SYSTEM_PROGRAM = "11111111111111111111111111111111"
DEFAULT_PUBKEY = "11111111111111111111111111111111"                 # Pubkey::default(): coin_creator not set
TOKEN_PROGRAMS = {"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "SPL Token", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": "Token-2022"}
PUMP_PROGRAM = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"        # pump.json "address"
PUMP_AMM_PROGRAM = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"     # pump_amm.json "address"
PUMP_FEES_PROGRAM = "pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ"    # pump_fees.json "address"
WSOL_MINT = "So11111111111111111111111111111111111111112"            # pump.json migrate: wsol_mint
POOL_DISCRIMINATOR = bytes([241, 154, 109, 4, 17, 177, 109, 188])     # pump_amm.json accounts: Pool
SHARING_CONFIG_DISCRIMINATOR = bytes([216, 74, 9, 0, 56, 140, 93, 75])  # pump_fees.json accounts: SharingConfig
POOL_SEED = b"pool"                                                  # pump_amm.json create_pool; pump.json migrate
POOL_AUTHORITY_SEED = b"pool-authority"                              # pump.json migrate: pool_authority
SHARING_CONFIG_SEED = b"sharing-config"                              # pump_fees.json constant SHARING_CONFIG_SEED
CANONICAL_POOL_INDEX = 0                                             # pump.json migrate: pool seed [0, 0]
BONDING_CURVE_SEED = b"bonding-curve"                                # PUMP_PROGRAM_README: PDA ["bonding-curve", mint]
BONDING_CURVE_DISCRIMINATOR = bytes([23, 183, 248, 55, 96, 216, 172, 96])  # pump.json accounts: BondingCurve

# pump_amm.json type Pool, offsets = 8-byte discriminator + the summed sizes of the fields before each one
POOL_BUMP, POOL_INDEX, POOL_CREATOR, POOL_BASE_MINT, POOL_QUOTE_MINT = 8, 9, 11, 43, 75
POOL_COIN_CREATOR, POOL_IS_MAYHEM_MODE, POOL_IS_CASHBACK_COIN = 211, 243, 244
POOL_CREATOR_FEE_BPS, POOL_CAN_EDIT_CREATOR_FEE, POOL_IS_HOLDER_REWARD = 261, 269, 270
POOL_READ_END = 271              # every field read here ends by is_holder_reward
# pump_fees.json type SharingConfig (Borsh: enum = 1 byte, bool = 1 byte, vec = u32 length + entries)
SC_BUMP, SC_VERSION, SC_STATUS, SC_MINT, SC_ADMIN, SC_ADMIN_REVOKED, SC_SHAREHOLDERS_LEN, SC_SHAREHOLDERS = 8, 9, 10, 11, 43, 75, 76, 80
SHAREHOLDER_SIZE = 34            # address (32) + share_bps u16 (2)
SC_STATUS_NAMES = {0: "paused", 1: "active"}  # pump_fees.json ConfigStatus variants in order: Paused, Active
MAX_SHAREHOLDERS = 10            # CREATOR_FEE_SHARING.md update_fee_shares_v2: at most 10 entries
BPS_TOTAL = 10_000               # CREATOR_FEE_SHARING.md: sum(share_bps) == 10_000
# SPL token interface state.rs Mint: array_refs![src, 36, 8, 1, 1, 36]
MINT_LEN, MINT_DECIMALS, MINT_IS_INITIALIZED = 82, 44, 45
# pump.json type BondingCurve after the 8-byte discriminator: virtual_token_reserves, virtual_quote_reserves,
# real_token_reserves, real_quote_reserves, token_total_supply (u64 each), complete bool (48), creator (49),
# is_mayhem_mode (81), is_cashback_coin (82), quote_mint (83), ...; every field from creator on was appended later, and an
# account written before it read the missing fields as Pubkey::default() (PUMP_PROGRAM_README)
CURVE_COMPLETE, CURVE_CREATOR, CURVE_QUOTE_MINT = 48, 49, 83
CURVE_BASE_END = CURVE_COMPLETE + 1   # the fields every bonding curve has
CURVE_CREATOR_END = CURVE_CREATOR + 32
CURVE_QUOTE_END = CURVE_QUOTE_MINT + 32
MAX_LABEL_RANK = 1000                 # a "top holder #N" label is printed only for an integer rank 1..1000

INDEPENDENCE_NOTE = "Dexscreener pool lookup and the public Solana RPC, no key, free"
CANNOT_SEE = ("only the canonical PumpSwap pool's creator fee (the pool pump.fun's migrate creates, found from the coin's bonding "
              "curve, the SOL-pair derivation and Dexscreener's pair list; other PumpSwap pools pay no creator fee) and the "
              "fee-sharing split; not who signs the claims or cranks the payouts (that needs transaction history), not where a "
              "recipient sends the fees next, not creator fees on the pump.fun bonding curve before graduation, and no other "
              "launchpad (not supported); when the bonding curve cannot be read, a pool paired with a token Dexscreener did not "
              "list is not checked; one read at read time, no history: an admin that is not revoked can still set the "
              "shareholders once, and pump.fun's community-takeover instruction (admin_cto_sharing_config in the cached pump_fees "
              "IDL, argument new_admin) can still set a new config admin even after 'admin revoked: yes'")
PRESENTATION_NOTE = ("presentation only: who receives the creator fee, shown next to the holder rows; never an engine input, never "
                     "changes a FLAG, verdict or threshold and never counts toward NO_ALARM")


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


def on_curve(address: str) -> bool:
    try:
        return is_on_curve(address)
    except ValueError:
        return False


def find_program_address(seeds: list[bytes], program_id: str) -> tuple[str | None, int | None]:
    """Solana's program-derived address: the first bump from 255 down whose sha256(seeds, bump, program, marker) is off
    the ed25519 curve (findProgramAddressSync; the same rule as pda_identity.py)."""
    program = b58decode(program_id)
    for bump in range(255, -1, -1):
        digest = hashlib.sha256(b"".join(seeds) + bytes([bump]) + program + b"ProgramDerivedAddress").digest()
        candidate = b58encode(digest)
        if not on_curve(candidate):
            return candidate, bump
    return None, None


def pool_authority(mint: str) -> str | None:
    """pump.json migrate: pool_authority = PDA("pool-authority", mint) under the pump program (PUMP_SWAP_CREATOR_FEE_README
    pump_pool_authority_pda)."""
    return find_program_address([POOL_AUTHORITY_SEED, b58decode(mint)], PUMP_PROGRAM)[0]


def canonical_pool(mint: str, quote_mint: str, authority: str | None = None) -> str | None:
    """The canonical PumpSwap pool of `mint` against `quote_mint`: PDA("pool", index 0, pool_authority(mint), mint,
    quote_mint) under pump_amm (pump.json migrate seeds; COLLECT_CREATOR_FEE.md pda::pump_amm::pool(0, ...))."""
    authority = authority or pool_authority(mint)
    if authority is None:
        return None
    seeds = [POOL_SEED, CANONICAL_POOL_INDEX.to_bytes(2, "little"), b58decode(authority), b58decode(mint), b58decode(quote_mint)]
    return find_program_address(seeds, PUMP_AMM_PROGRAM)[0]


def bonding_curve_address(mint: str) -> str | None:
    """PUMP_PROGRAM_README: each coin's bonding curve account is the PDA ("bonding-curve", mint) under the pump program."""
    return find_program_address([BONDING_CURVE_SEED, b58decode(mint)], PUMP_PROGRAM)[0]


def sharing_config_address(mint: str) -> tuple[str | None, int | None]:
    """pump_fees.json create_fee_sharing_config: sharing_config = PDA("sharing-config", mint) under the pump fees program."""
    return find_program_address([SHARING_CONFIG_SEED, b58decode(mint)], PUMP_FEES_PROGRAM)


# ----------------------------------------------------------------------------- requests


def check_url(url: str) -> str:
    """https only, no credentials, port 443 only, no query or fragment; host api.dexscreener.com with exactly the path
    /token-pairs/v1/solana/<address>, or host api.mainnet-beta.solana.com with path /. Returns which host it is."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise Failure("scheme_not_https")
    if parsed.hostname not in (DEX_HOST, RPC_HOST) or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise Failure("host_not_allowlisted")
    if parsed.query or parsed.params or parsed.fragment:
        raise Failure("path_not_allowlisted")
    if parsed.hostname == RPC_HOST:
        if parsed.path not in ("", "/"):
            raise Failure("path_not_allowlisted")
        return "rpc"
    if not parsed.path.startswith(DEX_PATH_PREFIX) or not is_address(parsed.path[len(DEX_PATH_PREFIX):]):
        raise Failure("path_not_allowlisted")
    return "dexscreener"


def dex_request(mint: str) -> urllib.request.Request:
    url = f"https://{DEX_HOST}{DEX_PATH_PREFIX}{mint}"
    if check_url(url) != "dexscreener":
        raise Failure("host_not_allowlisted")
    request = urllib.request.Request(url, method="GET")
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", USER_AGENT)
    return request


def rpc_request(payload: dict[str, Any]) -> urllib.request.Request:
    if check_url(RPC_ENDPOINT) != "rpc":
        raise Failure("host_not_allowlisted")
    if payload.get("method") not in ALLOWED_RPC_METHODS:
        raise Failure("method_not_allowlisted")
    request = urllib.request.Request(RPC_ENDPOINT, data=json.dumps(payload, separators=(",", ":")).encode("utf-8"), method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", USER_AGENT)
    return request


def batch_payload(keys: list[str]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": "getMultipleAccounts",
            "params": [keys, {"encoding": "base64", "commitment": "confirmed", "dataSlice": {"offset": 0, "length": DATA_SLICE_BYTES}}]}


def default_opener() -> urllib.request.OpenerDirector:
    """No environment proxy (an explicit empty ProxyHandler), no redirects, default TLS verification."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def _bounded_call(function: Callable[[], Any], timeout: float) -> Any:
    """Run one blocking transport step (open, read, close) in a daemon worker and wait at most `timeout` seconds: a hard
    wall-clock bound (the pda_identity.py, fomoapi.py and solanatracker.py pattern). A socket timeout alone restarts on
    every byte, so a server that drip-feeds bytes could otherwise hold the collector far past the deadline."""
    if timeout <= 0:
        raise TimeoutError
    result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def invoke() -> None:
        try:
            result.put((True, function()))
        except BaseException as exc:  # handed back to the bounded caller
            result.put((False, exc))

    worker = threading.Thread(target=invoke, name="creator-fees-transport", daemon=True)
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


def fetch_json(build: Callable[[], urllib.request.Request], opener: Any, *, monotonic: Callable[[], float], sleep: Callable[[float], None]) -> dict[str, Any]:
    """One request plus at most one retry after a 429. Returns {body, attempts, reason, http_status}; never raises."""
    out: dict[str, Any] = {"body": None, "attempts": 0, "reason": None, "http_status": None}
    for attempt in (1, 2):
        out["attempts"] = attempt
        try:
            raw = send_once(build(), opener, monotonic=monotonic)
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
            out["body"] = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            out["reason"] = "invalid_json"
        return out
    return out


def rpc_call(keys: list[str], opener: Any, *, monotonic: Callable[[], float], sleep: Callable[[float], None]) -> dict[str, Any]:
    """One getMultipleAccounts read. Returns {values, slot, attempts, reason, http_status, rpc_error_code}; never raises. A
    JSON-RPC error answer is rpc_error with its numeric code only (its message is not kept)."""
    got = fetch_json(lambda: rpc_request(batch_payload(keys)), opener, monotonic=monotonic, sleep=sleep)
    out = {"values": None, "slot": None, "attempts": got["attempts"], "reason": got["reason"], "http_status": got["http_status"], "rpc_error_code": None}
    if out["reason"] is not None:
        return out
    answer = got["body"]
    if not isinstance(answer, dict):
        out["reason"] = "invalid_shape"
    elif answer.get("error") is not None:
        code = answer["error"].get("code") if isinstance(answer["error"], dict) else None
        out.update(reason="rpc_error", rpc_error_code=code if isinstance(code, int) and not isinstance(code, bool) else None)
    else:
        result = answer.get("result")
        values = result.get("value") if isinstance(result, dict) else None
        if not isinstance(values, list) or len(values) != len(keys):
            out["reason"] = "invalid_shape"
        else:
            context = result.get("context")
            slot = context.get("slot") if isinstance(context, dict) else None
            out.update(values=values, slot=slot if isinstance(slot, int) and not isinstance(slot, bool) else None)
    return out


# ----------------------------------------------------------------------------- Dexscreener pairs -> canonical candidates


def base_side_quotes(body: Any, mint: str) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """From the Dexscreener answer (a JSON list of pairs, as documented), the (pair address, quote mint) of every Solana
    pair where this token is the base side. Only addresses are kept: no name, symbol, label, URL or other provider text.
    Returns (summary, pairs)."""
    if not isinstance(body, list):
        return {"status": "unavailable", "reason": "invalid_shape", "pairs_seen": None, "base_side_pairs": None, "base_side_quote_mints": None}, []
    found: list[tuple[str, str]] = []
    for pair in body[:MAX_DEX_PAIRS]:
        if not isinstance(pair, dict) or pair.get("chainId") != "solana":
            continue
        base, quote = pair.get("baseToken"), pair.get("quoteToken")
        address = pair.get("pairAddress")
        base_mint = base.get("address") if isinstance(base, dict) else None
        quote_mint = quote.get("address") if isinstance(quote, dict) else None
        if base_mint == mint and is_address(quote_mint) and is_address(address) and quote_mint != mint:
            found.append((address, quote_mint))
    return {"status": "ok", "reason": None, "pairs_seen": len(body), "base_side_pairs": len(found), "base_side_quote_mints": sorted({q for _, q in found})}, found


def _dex_id(value: Any) -> str | None:
    """Dexscreener's dexId as a short identifier (lowercase letters, digits, _ and -, at most 32 characters) with no verdict
    word under the shared rule (provider_words); anything else is None. Saved for the reader, never printed."""
    if not isinstance(value, str) or not DEX_ID_RE.fullmatch(value):
        return None
    return value if pw.label(value, DEX_ID_STRIP, 32) == value else None


def _volume(value: Any) -> float | None:
    """A 24 h volume in USD: a finite JSON number from 0 to MAX_VOLUME_USD; missing, text, a bool, NaN, negative or too big
    is None, never 0."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) and 0 <= number <= MAX_VOLUME_USD else None


def pair_volumes(body: Any, mint: str) -> dict[str, Any] | None:
    """DS-DLMM-SHARE-T1: from the same Dexscreener answer, every Solana pair where this token is the base or the quote side,
    once per pair address (the first entry kept): {pair_address, dex_id, quote_mint, volume_h24}. pairs_capped is true when
    the answer held DEX_PAIRS_CAP pairs or more (more pairs may exist). None when the answer is not a list. Presentation
    input only (the DLMM share line of meteora_pools.py --present): no engine reads it."""
    if not isinstance(body, list):
        return None
    pairs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pair in body[:MAX_DEX_PAIRS]:
        if not isinstance(pair, dict) or pair.get("chainId") != "solana":
            continue
        base, quote = pair.get("baseToken"), pair.get("quoteToken")
        address = pair.get("pairAddress")
        base_mint = base.get("address") if isinstance(base, dict) else None
        quote_mint = quote.get("address") if isinstance(quote, dict) else None
        if mint not in (base_mint, quote_mint) or not is_address(address) or address in seen:
            continue
        seen.add(address)
        volume = pair.get("volume")
        pairs.append({"pair_address": address, "dex_id": _dex_id(pair.get("dexId")), "quote_mint": quote_mint if is_address(quote_mint) else None,
                      "volume_h24": _volume(volume.get("h24") if isinstance(volume, dict) else None)})
    return {"pairs_capped": len(body) >= DEX_PAIRS_CAP, "pairs": pairs}


def pool_candidates(mint: str, dex_pairs: list[tuple[str, str]], authority: str | None) -> tuple[list[dict[str, Any]], int]:
    """The canonical pool for every quote mint Dexscreener lists against this token (kept only when Dexscreener's pair
    address equals the derivation) plus the SOL pair (always derived). Returns (candidates, the other base-side pairs:
    other DEXes' pools and any PumpSwap pool that is not the canonical one)."""
    candidates: dict[str, dict[str, Any]] = {}
    other = 0
    derived: dict[str, str | None] = {}
    for pair_address, quote in dex_pairs:
        if quote not in derived:
            derived[quote] = canonical_pool(mint, quote, authority)
        if derived[quote] == pair_address:
            entry = candidates.setdefault(pair_address, {"address": pair_address, "quote_mint": quote, "found_by": []})
            if "dexscreener" not in entry["found_by"]:
                entry["found_by"].append("dexscreener")
        else:
            other += 1
    sol_pool = canonical_pool(mint, WSOL_MINT, authority)
    sol_entry = None
    if sol_pool is not None:
        sol_entry = candidates.setdefault(sol_pool, {"address": sol_pool, "quote_mint": WSOL_MINT, "found_by": []})
        sol_entry["found_by"].append("derived_sol_pair")
    out = list(candidates.values())
    if len(out) > MAX_POOL_CANDIDATES:  # the cap never drops the always-derived SOL pair
        out = [c for c in out if c is not sol_entry][:MAX_POOL_CANDIDATES - (sol_entry is not None)] + ([sol_entry] if sol_entry else [])
    return out, other


# ----------------------------------------------------------------------------- decoding (cited layouts, validated)


def _key(raw: bytes, offset: int) -> str:
    return b58encode(raw[offset:offset + 32])


def _account(value: Any) -> dict[str, Any] | None:
    """A getMultipleAccounts account value -> {owner, data, space}; None when it is not a readable base64 account."""
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
    return {"owner": value["owner"], "data": raw, "space": space if isinstance(space, int) and not isinstance(space, bool) and space >= 0 else None}


def decode_mint(account: dict[str, Any] | None) -> dict[str, Any] | None:
    """The scanned mint (SPL Token or Token-2022 base layout), or None when it is not a readable, initialized mint. Only
    the program and decimals are kept (the Token-2022 metadata, provider-chosen text, is never read)."""
    if account is None or account["owner"] not in TOKEN_PROGRAMS or len(account["data"]) < MINT_LEN:
        return None
    raw = account["data"]
    if raw[MINT_IS_INITIALIZED] != 1 or raw[MINT_DECIMALS] > 30:
        return None
    return {"program": account["owner"], "decimals": raw[MINT_DECIMALS]}


def decode_bonding_curve(value: Any, mint: str) -> dict[str, Any]:
    """The mint's pump.fun bonding curve -> {status: identified, complete, quote_mint_field, pool_quote_mint,
    creator_field} or {status: not_found} or {status: unavailable, reason, check}. quote_mint_field is the field as stored
    (the default address for a SOL-paired coin, PUMP_PROGRAM_README); pool_quote_mint is the quote of the coin's canonical
    pool (wrapped SOL for a SOL-paired coin, CREATE_WITH_PUMP_COIN_QUOTE). creator_field (HS-FOLLOWUPS-T1) is the stored
    `creator` (offset 49), or None when the account ends before the field's last byte; it is only a candidate address
    for the coin creator read, never a recipient by itself. Never guesses: a refused curve names no pool and no creator."""
    def refuse(check: str, reason: str = "layout_mismatch") -> dict[str, Any]:
        return {"status": "unavailable", "reason": reason, "check": check}

    if value is None:
        return {"status": "not_found", "reason": None}
    account = _account(value)
    if account is None:
        return {"status": "unavailable", "reason": "account_unreadable"}
    raw, size = account["data"], account["space"] if account["space"] is not None else len(account["data"])
    if account["owner"] != PUMP_PROGRAM:
        return refuse("owner_program")
    if raw[:8] != BONDING_CURVE_DISCRIMINATOR:
        return refuse("discriminator")
    if size < CURVE_BASE_END or len(raw) < min(size, CURVE_QUOTE_END) or CURVE_QUOTE_MINT < size < CURVE_QUOTE_END:
        return refuse("length")  # shorter than the original fields, or cut inside quote_mint
    if raw[CURVE_COMPLETE] not in (0, 1):
        return refuse("flags")
    field = _key(raw, CURVE_QUOTE_MINT) if size >= CURVE_QUOTE_END else DEFAULT_PUBKEY  # written before the field existed
    if field == mint:
        return refuse("quote_mint")
    creator = _key(raw, CURVE_CREATOR) if size >= CURVE_CREATOR_END else None  # ends before the field: not read, never guessed
    return {"status": "identified", "reason": None, "data_len": size, "complete": raw[CURVE_COMPLETE] == 1,
            "quote_mint_field": field, "pool_quote_mint": WSOL_MINT if field == DEFAULT_PUBKEY else field, "creator_field": creator}


def _space_ok(account: dict[str, Any], needed: int) -> bool:
    return len(account["data"]) >= needed and (account["space"] is None or account["space"] >= needed)


def decode_pool(address: str, account: dict[str, Any], mint: str, authority: str | None) -> dict[str, Any]:
    """A canonical-pool candidate -> {status: identified, coin_creator, flags, ...} or {status: unavailable, reason:
    layout_mismatch | mint_mismatch, check}. Never guesses: any failed check refuses the whole decode."""
    def refuse(check: str, reason: str = "layout_mismatch") -> dict[str, Any]:
        return {"status": "unavailable", "reason": reason, "check": check}

    raw = account["data"]
    if account["owner"] != PUMP_AMM_PROGRAM:
        return refuse("owner_program")
    if raw[:8] != POOL_DISCRIMINATOR:
        return refuse("discriminator")
    if not _space_ok(account, POOL_READ_END):
        return refuse("length")
    flags = {"is_mayhem_mode": raw[POOL_IS_MAYHEM_MODE], "is_cashback_coin": raw[POOL_IS_CASHBACK_COIN],
             "can_edit_creator_fee": raw[POOL_CAN_EDIT_CREATOR_FEE], "is_holder_reward": raw[POOL_IS_HOLDER_REWARD]}
    if any(v not in (0, 1) for v in flags.values()):
        return refuse("flags")
    creator, base, quote = _key(raw, POOL_CREATOR), _key(raw, POOL_BASE_MINT), _key(raw, POOL_QUOTE_MINT)
    if base != mint:
        return refuse("mint", "mint_mismatch")
    seeds = [POOL_SEED, raw[POOL_INDEX:POOL_INDEX + 2], b58decode(creator), b58decode(base), b58decode(quote)]
    derived, bump = find_program_address(seeds, PUMP_AMM_PROGRAM)
    if derived != address or bump != raw[POOL_BUMP]:
        return refuse("pool_derivation")
    if authority is None or creator != authority:
        return refuse("canonical")  # isPumpPool (FEE_PROGRAM_README): pool.creator == pumpPoolAuthorityPda(baseMint)
    return {"status": "identified", "reason": None, "base_mint": base, "quote_mint": quote, "creator": creator,
            "index": struct.unpack_from("<H", raw, POOL_INDEX)[0], "canonical": True, "coin_creator": _key(raw, POOL_COIN_CREATOR),
            "creator_fee_bps_field": struct.unpack_from("<Q", raw, POOL_CREATOR_FEE_BPS)[0], **{k: bool(v) for k, v in flags.items()}}


def decode_sharing_config(address: str, account: dict[str, Any], mint: str) -> dict[str, Any]:
    """A pump fees SharingConfig -> {status: identified, shareholders, admin, admin_revoked, config_status, ...} or
    {status: unavailable, reason: layout_mismatch | mint_mismatch, check}. Every check of the cited docs is applied: one to
    ten shareholders, no duplicate, no zero share, shares summing to exactly 10_000 bps, the mint, and the address the
    pump fees program itself derives ("sharing-config", mint) with its stored bump."""
    def refuse(check: str, reason: str = "layout_mismatch") -> dict[str, Any]:
        return {"status": "unavailable", "reason": reason, "check": check}

    raw = account["data"]
    if account["owner"] != PUMP_FEES_PROGRAM:
        return refuse("owner_program")
    if raw[:8] != SHARING_CONFIG_DISCRIMINATOR:
        return refuse("discriminator")
    if not _space_ok(account, SC_SHAREHOLDERS):
        return refuse("length")
    if raw[SC_STATUS] not in SC_STATUS_NAMES:
        return refuse("status")
    if raw[SC_ADMIN_REVOKED] not in (0, 1):
        return refuse("flags")
    count = struct.unpack_from("<I", raw, SC_SHAREHOLDERS_LEN)[0]
    if not 1 <= count <= MAX_SHAREHOLDERS:
        return refuse("shareholder_count")
    if not _space_ok(account, SC_SHAREHOLDERS + count * SHAREHOLDER_SIZE):
        return refuse("length")
    holders = []
    for i in range(count):
        at = SC_SHAREHOLDERS + i * SHAREHOLDER_SIZE
        holders.append({"address": _key(raw, at), "share_bps": struct.unpack_from("<H", raw, at + 32)[0]})
    if any(h["share_bps"] == 0 for h in holders):
        return refuse("share_bps")
    if len({h["address"] for h in holders}) != count:
        return refuse("duplicate_shareholder")
    if sum(h["share_bps"] for h in holders) != BPS_TOTAL:
        return refuse("bps_sum")
    if _key(raw, SC_MINT) != mint:
        return refuse("mint", "mint_mismatch")
    derived, bump = sharing_config_address(mint)
    if derived != address or bump != raw[SC_BUMP]:
        return refuse("sharing_config_derivation")
    return {"status": "identified", "reason": None, "kind": "sharing_config", "address": address, "owner_program": PUMP_FEES_PROGRAM,
            "version": raw[SC_VERSION], "config_status": SC_STATUS_NAMES[raw[SC_STATUS]], "mint": mint, "admin": _key(raw, SC_ADMIN),
            "admin_revoked": raw[SC_ADMIN_REVOKED] == 1, "shareholders": holders, "bps_total": BPS_TOTAL}


def classify_recipient(address: str, value: Any, mint: str) -> dict[str, Any]:
    """The pool's coin_creator, from its account (or its absence): a wallet, the mint's SharingConfig, or another program's
    account (never called a wallet)."""
    if value is None:
        if on_curve(address):
            return {"status": "identified", "reason": None, "kind": "wallet", "address": address, "owner_program": None, "detail": "no_account"}
        return {"status": "identified", "reason": None, "kind": "program_address", "address": address, "owner_program": None, "detail": "no_account_off_curve"}
    account = _account(value)
    if account is None:
        return {"status": "unavailable", "reason": "account_unreadable", "address": address}
    owner = account["owner"]
    if owner == PUMP_FEES_PROGRAM and account["data"][:8] == SHARING_CONFIG_DISCRIMINATOR:
        return {**decode_sharing_config(address, account, mint), "address": address}
    if owner == SYSTEM_PROGRAM:
        if on_curve(address):
            return {"status": "identified", "reason": None, "kind": "wallet", "address": address, "owner_program": owner, "detail": "system_owned"}
        return {"status": "identified", "reason": None, "kind": "program_address", "address": address, "owner_program": owner, "detail": "system_owned_off_curve"}
    return {"status": "identified", "reason": None, "kind": "program_account", "address": address, "owner_program": owner, "detail": None}


# ----------------------------------------------------------------------------- collect


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _base(mint: str, fetched_at: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "collector": "creator_fees", "mint": mint, "status": "unavailable", "reason": None, "fetched_at": fetched_at,
        "request": {"keys": "none", "dexscreener": {"host": DEX_HOST, "method": "GET", "path": f"{DEX_PATH_PREFIX}<MINT>", "requests_sent": 0},
                    "rpc": {"host": RPC_HOST, "method": "POST", "path": "/", "rpc_methods": list(ALLOWED_RPC_METHODS), "calls": 0, "requests_sent": 0,
                            "data_slice_bytes": DATA_SLICE_BYTES},
                    "calls_sent": 0, "requests_sent": 0, "max_calls": MAX_CALLS, "max_requests": MAX_REQUESTS},
        "layouts": {"pump_amm": "provider-docs current/pumpfun/idls.md (pump_amm.json: Pool discriminator and fields, create_pool seeds)",
                    "pump": "provider-docs current/pumpfun/idls.md (pump.json: migrate seeds pool-authority and pool, wsol_mint)",
                    "pump_fees": "provider-docs current/pumpfun/idls.md (pump_fees.json: SharingConfig discriminator and fields, SHARING_CONFIG_SEED)",
                    "docs": "provider-docs current/pumpfun/publicdocs.md (PUMP_SWAP_CREATOR_FEE_README, FEE_PROGRAM_README, CREATOR_FEE_SHARING, COLLECT_CREATOR_FEE, HOLDER_REWARDS_README, PUMP_CASHBACK_README)",
                    "dexscreener": "provider-docs current/dexscreener.md (GET /token-pairs/v1/{chainId}/{tokenAddress})",
                    "spl_token": "provider-docs current/spltoken/layouts.md (token interface state.rs: Mint)"},
        "dexscreener": {"status": "not_sent", "reason": None, "http_status": None, "pairs_seen": None, "base_side_pairs": None,
                        "base_side_quote_mints": None, "other_base_side_pairs": None},
        "bonding_curve": {"address": None, "status": "not_read", "reason": None},
        "pool_authority": None, "sharing_config_address": None, "sharing_config_exists": None, "candidates": [], "mint_info": None, "slot": None,
        "http_status": None, "rpc_error_code": None, "pools": [], "presentation_only": True, "note": PRESENTATION_NOTE, "cannot_see": CANNOT_SEE,
        "dexscreener_pairs": None,  # DS-DLMM-SHARE-T1: pair_volumes() of the answer; None when Dexscreener was not read (last, so every older field keeps its place)
    }


def _count(result: dict[str, Any], kind: str, got: dict[str, Any]) -> None:
    request = result["request"]
    request[kind]["requests_sent"] += got["attempts"]
    if kind == "rpc":
        request["rpc"]["calls"] += 1
    request["calls_sent"] += 1
    request["requests_sent"] += got["attempts"]


def _decode_candidate(candidate: dict[str, Any], value: Any, mint: str, authority: str | None) -> dict[str, Any]:
    entry = {**candidate}
    if value is None:
        entry.update(status="not_found", reason=None)
        return entry
    account = _account(value)
    try:
        entry.update(decode_pool(candidate["address"], account, mint, authority) if account is not None
                     else {"status": "unavailable", "reason": "account_unreadable"})
    except Exception:  # noqa: BLE001 - an account the guards did not foresee: a fixed code, never a crash
        entry.update(status="unavailable", reason="parse_error")
    return entry


def collect_creator_fees(
    mint: str,
    *,
    opener: Any | None = None,
    now: Callable[[], float] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """1 Dexscreener lookup, 1 getMultipleAccounts batch (mint, SharingConfig, bonding curve, candidate pools), and at most
    1 more getMultipleAccounts for the pool the bonding curve names when it was not a candidate (with the bonding curve's
    `creator` as a candidate coin creator) and for any coin creator that is not this mint's SharingConfig. Returns the
    creator_fees.json result; never raises for provider or transport failures. Reads no file of the run folder."""
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    result = _base(mint, _iso(now()))
    opener = opener or default_opener()
    authority = pool_authority(mint)
    sharing, _bump = sharing_config_address(mint)
    curve_address = bonding_curve_address(mint)
    result.update(pool_authority=authority, sharing_config_address=sharing)
    result["bonding_curve"]["address"] = curve_address

    dex = fetch_json(lambda: dex_request(mint), opener, monotonic=monotonic, sleep=sleep)
    _count(result, "dexscreener", dex)
    pairs: list[tuple[str, str]] = []
    if dex["reason"] is not None:
        result["dexscreener"].update(status="unavailable", reason=dex["reason"], http_status=dex["http_status"])
    else:
        summary, pairs = base_side_quotes(dex["body"], mint)
        result["dexscreener"].update(summary, http_status=dex["http_status"])
        try:
            result["dexscreener_pairs"] = pair_volumes(dex["body"], mint)
        except Exception:  # noqa: BLE001 - the share list is an add-on: a pair the guards did not foresee never costs the recipient read
            result["dexscreener_pairs"] = None
    candidates, other = pool_candidates(mint, pairs, authority)
    result["dexscreener"]["other_base_side_pairs"] = other if result["dexscreener"]["status"] == "ok" else None
    result["candidates"] = candidates

    batch = [c["address"] for c in candidates]
    got = rpc_call([mint, sharing, curve_address, *batch], opener, monotonic=monotonic, sleep=sleep)
    _count(result, "rpc", got)
    result.update(http_status=got["http_status"], rpc_error_code=got["rpc_error_code"], slot=got["slot"], fetched_at=_iso(now()))
    if got["reason"] is not None:
        result["reason"] = got["reason"]
        return result
    values = got["values"]
    mint_info = decode_mint(_account(values[0]) if values[0] is not None else None)
    if mint_info is None:
        result["reason"] = "mint_not_found" if values[0] is None else "mint_unreadable"
        return result
    result["mint_info"] = mint_info
    known: dict[str, Any] = {sharing: values[1]}
    result["sharing_config_exists"] = values[1] is not None
    try:
        curve = decode_bonding_curve(values[2], mint)
    except Exception:  # noqa: BLE001
        curve = {"status": "unavailable", "reason": "parse_error"}
    result["bonding_curve"].update(curve)
    pools = [_decode_candidate(c, v, mint, authority) for c, v in zip(candidates, values[3:])]

    pending = None  # the canonical pool the bonding curve names, when the batch did not read it
    if curve["status"] == "identified" and curve["complete"]:
        curve_pool = canonical_pool(mint, curve["pool_quote_mint"], authority)
        result["bonding_curve"]["canonical_pool"] = curve_pool
        entry = next((c for c in candidates if c["address"] == curve_pool), None)
        if entry is None and curve_pool is not None:
            entry = {"address": curve_pool, "quote_mint": curve["pool_quote_mint"], "found_by": []}
            candidates.append(entry)
            pending = entry
        if entry is not None:
            entry["found_by"].append("bonding_curve_quote")
            for pool in pools:
                if pool["address"] == curve_pool:
                    pool["found_by"] = list(entry["found_by"])

    to_read = []
    for pool in pools:
        creator = pool.get("coin_creator") if pool["status"] == "identified" else None
        if creator and creator != DEFAULT_PUBKEY and creator not in known and creator not in to_read:
            to_read.append(creator)
    # HS-FOLLOWUPS-T1 (FEES N1): the pool read in the last call names a coin creator that cannot be read after it (the
    # cap is 3 calls). The bonding curve's own `creator` (offset 49, already in the batch-1 read) is where a canonical
    # pool's coin_creator comes from (PUMP_SWAP_CREATOR_FEE_README: Pool::coin_creator from BondingCurve::creator;
    # CREATOR_FEE_SHARING: create_fee_sharing_config moves both to the config), so it rides along in that same last call
    # as a candidate: a pool whose coin_creator equals it is classified from that answer; any other stays "not read".
    if pending and curve.get("creator_field") not in (None, DEFAULT_PUBKEY, pending["address"]) \
            and curve["creator_field"] not in known and curve["creator_field"] not in to_read:
        to_read.append(curve["creator_field"])
        result["bonding_curve"]["creator_read"] = True
    extra = ([pending["address"]] if pending else []) + to_read
    if extra:
        more = rpc_call(extra, opener, monotonic=monotonic, sleep=sleep)
        _count(result, "rpc", more)
        if more["reason"] is None:
            answers = dict(zip(extra, more["values"]))
            if pending:
                pools.append(_decode_candidate(pending, answers[pending["address"]], mint, authority))
            known.update({address: answers[address] for address in to_read})
        else:
            if pending:
                pools.append({**pending, "status": "unavailable", "reason": "pool_read_failed", "read_reason": more["reason"]})
            known.update({address: Failure(more["reason"], more["http_status"]) for address in to_read})
    result["pools"] = pools

    found = [p for p in pools if p["status"] == "identified"]
    for pool in found:
        creator = pool["coin_creator"]
        if creator == DEFAULT_PUBKEY:
            pool["recipient"] = {"status": "identified", "reason": None, "kind": "not_set", "address": creator}
            continue
        if creator not in known:  # first seen in the last allowed call: shown, never read as a wallet
            pool["recipient"] = {"status": "unavailable", "reason": "recipient_read_cap", "address": creator}
            continue
        value = known[creator]
        if isinstance(value, Failure):
            pool["recipient"] = {"status": "unavailable", "reason": "recipient_read_failed", "read_reason": value.reason, "address": creator}
            continue
        try:
            pool["recipient"] = classify_recipient(creator, value, mint)
        except Exception:  # noqa: BLE001
            pool["recipient"] = {"status": "unavailable", "reason": "parse_error", "address": creator}

    if found:
        result.update(status="ok", reason=None)
    elif any(p["status"] == "unavailable" for p in pools):
        result["reason"] = next(p["reason"] for p in pools if p["status"] == "unavailable")
    elif curve["status"] == "identified":
        result.update(status="empty", reason="no_canonical_pool" if curve["complete"] else "not_graduated")
    elif result["dexscreener"]["status"] != "ok":
        result["reason"] = "pool_lookup_failed"
    else:
        result.update(status="empty", reason="no_pump_curve" if curve["status"] == "not_found" else "no_canonical_pool_listed")
    return result


def _calls_text(result: dict[str, Any]) -> str:
    request = result.get("request") if isinstance(result.get("request"), dict) else {}
    dex = _int((request.get("dexscreener") or {}).get("requests_sent")) if isinstance(request.get("dexscreener"), dict) else None
    rpc = _int((request.get("rpc") or {}).get("requests_sent")) if isinstance(request.get("rpc"), dict) else None
    if dex is None or rpc is None:
        return "calls unknown"
    return f"{dex} Dexscreener request{'s' if dex != 1 else ''}, {rpc} Solana RPC request{'s' if rpc != 1 else ''}"


def status_line(result: dict[str, Any]) -> str:
    calls = _calls_text(result)
    if result["status"] == "empty":
        return f"empty ({_empty_text(result)}; {calls})"
    if result["status"] != "ok":
        return f"unavailable ({result['reason']}; {calls})"
    kinds = []
    for pool in (p for p in result["pools"] if p.get("status") == "identified"):
        recipient = pool.get("recipient") or {}
        if pool.get("is_holder_reward"):
            kinds.append("holders (holder rewards coin)")
        elif recipient.get("status") != "identified":
            kinds.append("recipient not read")
        elif recipient.get("kind") == "sharing_config":
            n = len(recipient["shareholders"])
            kinds.append(f"shared by {n} shareholder{'s' if n != 1 else ''}")
        else:
            kinds.append({"wallet": "a wallet", "program_account": "a program account", "program_address": "a program address",
                          "not_set": "no coin creator set"}.get(recipient.get("kind"), "unknown"))
    return f"ok (creator fees: {'; '.join(kinds)}; {calls})"


# ----------------------------------------------------------------------------- presentation (synthesis, offline)


KNOWN_CODES = frozenset({
    "scheme_not_https", "host_not_allowlisted", "path_not_allowlisted", "method_not_allowlisted", "redirect_disallowed", "bad_request",
    "access_denied", "not_found", "method_unavailable", "request_too_large", "rate_limited", "service_unavailable", "server_error",
    "http_error", "invalid_response", "response_too_large", "timeout", "network_error", "request_failed", "invalid_json", "invalid_shape",
    "rpc_error", "mint_not_found", "mint_unreadable", "account_unreadable", "parse_error", "layout_mismatch", "mint_mismatch",
    "pool_lookup_failed", "no_canonical_pool", "recipient_read_failed", "owner_program", "discriminator", "length", "flags", "mint",
    "pool_derivation", "canonical", "status", "shareholder_count", "share_bps", "duplicate_shareholder", "bps_sum", "sharing_config_derivation",
    "not_graduated", "no_pump_curve", "no_canonical_pool_listed", "recipient_read_cap", "pool_read_failed", "quote_mint",
})


def _code(value: Any) -> str:
    """A reason or check code read back from the saved file: printed only when it is one of this script's fixed codes, so
    no saved text (a tampered file included) reaches the report."""
    return value if isinstance(value, str) and value in KNOWN_CODES else "unrecognized code"


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _addr(value: Any) -> str:
    return value if is_address(value) else "unknown"


def _bps(value: Any) -> str:
    """Basis points as a percent with 2 decimals (exact: 1 bps = 0.01%)."""
    bps = _int(value)
    if bps is None or not 0 <= bps <= BPS_TOTAL:
        return "unknown share"
    return f"{bps // 100}.{bps % 100:02d}%"


def _pct(value: Any, scale: int = 1) -> str | None:
    """A saved share (percent, or a fraction with scale=100) in percent, cut toward zero to 2 decimals, never rounded up.
    Decimal on the number's own digits, so 0.29 stays 0.29% (float 0.29 * 100 is 28.999...)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    percent = Decimal(repr(value)) * scale
    if not 0 <= percent <= 100:
        return None
    hundredths = int((percent * 100).to_integral_value(rounding=ROUND_DOWN))
    return f"{hundredths // 100}.{hundredths % 100:02d}%"


def _age_min(value: Any) -> float | None:
    try:
        fetched = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if fetched.tzinfo is None:
            return None
        return max(0.0, (dt.datetime.now(dt.timezone.utc) - fetched).total_seconds() / 60)
    except (ValueError, TypeError, OverflowError):
        return None


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None


def known_labels(run: Path, mint: str) -> dict[str, list[str]]:
    """Identities the scan's saved first-wave files already give an address, as fixed phrases with numbers only: 'top
    holder #N (X% at scan)' from holders.json (forensics, rank in the full list) or holder-analysis.json (its row order),
    and 'dev (MadeOnSol's claim)' from madeonsol.json. Files of another mint are ignored; no provider text is copied."""
    labels: dict[str, list[str]] = {}

    def add(address: Any, text: str) -> None:
        if is_address(address) and text not in labels.setdefault(address, []):
            labels[address].append(text)

    holders = _read_json(run / "holders.json")
    ranked: set[str] = set()
    if isinstance(holders, dict) and holders.get("mint") == mint and isinstance(holders.get("top_holders"), list):
        for row in holders["top_holders"]:
            rank = _int(row.get("rank")) if isinstance(row, dict) else None
            if rank is not None and 1 <= rank <= MAX_LABEL_RANK and row.get("infrastructure") is False and is_address(row.get("wallet")):
                share = _pct(row.get("share_pct"))
                add(row["wallet"], f"top holder #{rank} in holders.json" + (f", {share} at scan" if share else ""))
                ranked.add(row["wallet"])
    analysis = _read_json(run / "holder-analysis.json")
    if isinstance(analysis, dict) and analysis.get("mint") == mint and isinstance(analysis.get("top_holders"), list):
        for position, row in enumerate(analysis["top_holders"][:MAX_LABEL_RANK], start=1):
            if isinstance(row, dict) and is_address(row.get("owner")) and row["owner"] not in ranked:
                pct = _pct(row.get("share"), 100)
                add(row["owner"], f"top holder #{position} in holder-analysis" + (f", {pct} at scan" if pct else ""))
    madeonsol = _read_json(run / "madeonsol.json")
    if isinstance(madeonsol, dict) and madeonsol.get("schema") == "holder-scan-madeonsol/1" and madeonsol.get("mint") == mint:
        token = madeonsol.get("token") if isinstance(madeonsol.get("token"), dict) else {}
        deployer = token.get("deployer") if isinstance(token.get("deployer"), dict) else {}
        if token.get("status") == "ok" and deployer.get("status") == "ok":
            add(deployer.get("wallet"), "dev (MadeOnSol's claim)")
    return labels


def _valid_saved(data: Any) -> bool:
    return (isinstance(data, dict) and data.get("schema") == SCHEMA and data.get("status") in ("ok", "empty", "unavailable")
            and data.get("presentation_only") is True and is_address(data.get("mint")))


def _who(address: Any, labels: dict[str, list[str]], curve: bool = False) -> str:
    """An address with what the saved files already say about it; with curve=True also 'off the ed25519 curve: a
    program-derived address, not a wallet' when it is (no private key can sign for it; computed offline, no read)."""
    text = _addr(address)
    found = list(labels.get(text) or []) if text != "unknown" else []
    if curve and text != "unknown" and not on_curve(text):
        found.append(OFF_CURVE_TEXT)
    return f"{text} ({'; '.join(found)})" if found else text


OFF_CURVE_TEXT = "off the ed25519 curve: a program-derived address, not a wallet"
KIND_TEXT = {
    "wallet": "wallet",
    "program_account": "program account, not a wallet",
    "program_address": "program-derived address, not a wallet",
}
DETAIL_TEXT = {
    "no_account": "no SOL account yet",
    "no_account_off_curve": "off the ed25519 curve, no account",
    "system_owned": None,
    "system_owned_off_curve": "system-owned, off the ed25519 curve",
}


FOUND_BY_TEXT = {"bonding_curve_quote": "the bonding curve's quote mint", "derived_sol_pair": "the SOL-pair derivation",
                 "dexscreener": "Dexscreener's pair list"}


def _checked_text(result: dict[str, Any]) -> str:
    """What the SOL-pair derivation and Dexscreener covered, from the saved counts (numbers only)."""
    dex = result.get("dexscreener") if isinstance(result.get("dexscreener"), dict) else {}
    quotes = dex.get("base_side_quote_mints")
    pairs = _int(dex.get("base_side_pairs"))
    if dex.get("status") != "ok" or not isinstance(quotes, list) or pairs is None:
        return "against SOL (Dexscreener's pair list not read)"
    if pairs == 0:
        return "against SOL (Dexscreener listed no pair with this token as the base side)"
    others = len({q for q in quotes if is_address(q) and q != WSOL_MINT})
    if others == 0:
        return f"against SOL (the only quote token in the {pairs} pair{'s' if pairs != 1 else ''} Dexscreener listed with this token as the base side)"
    return f"against SOL and the {others} other quote token{'s' if others != 1 else ''} Dexscreener listed"


def _empty_text(result: dict[str, Any]) -> str:
    """The empty case in words that say what was actually checked; never a bare 'not a PumpSwap token'."""
    reason = result.get("reason")
    curve = result.get("bonding_curve") if isinstance(result.get("bonding_curve"), dict) else {}
    if reason == "not_graduated":
        return (f"not graduated: the coin's pump.fun bonding curve {_addr(curve.get('address'))} is not complete, so it has no "
                "PumpSwap pool yet (creator fees on the bonding curve are not read)")
    if reason == "no_canonical_pool":
        return (f"graduated from its pump.fun bonding curve, but no canonical PumpSwap pool exists for its quote "
                f"{_addr(curve.get('pool_quote_mint'))} (checked {_addr(curve.get('canonical_pool'))}; for example an older coin "
                "migrated elsewhere: not supported)")
    if reason == "no_pump_curve":
        return (f"no pump.fun bonding curve account for this mint, and no canonical PumpSwap pool found {_checked_text(result)} "
                "(another launchpad: not supported)")
    if reason == "no_canonical_pool_listed":
        check = f", check {_code(curve.get('check'))}" if curve.get("check") is not None else ""
        return (f"no canonical PumpSwap pool found {_checked_text(result)}; the pump.fun bonding curve was not readable "
                f"({_code(curve.get('reason'))}{check}), so this does not rule out a coin that is not graduated, another "
                "launchpad, or a pool paired with a token Dexscreener did not list")
    return f"nothing found ({_code(reason)})"


def _recipient_text(recipient: dict[str, Any], labels: dict[str, list[str]]) -> str:
    kind = recipient.get("kind")
    address = _who(recipient.get("address"), labels)
    if recipient.get("status") != "identified":
        codes = _code(recipient.get("reason")) + (f", {_code(recipient.get('read_reason'))}" if recipient.get("read_reason") is not None else "")
        codes += f", check {_code(recipient.get('check'))}" if recipient.get("check") is not None else ""
        raw = _addr(recipient.get("address"))
        off = f"; {OFF_CURVE_TEXT}" if raw != "unknown" and not on_curve(raw) else ""
        return f"{address} (not read: unavailable ({codes}); no recipient guessed{off})"
    if kind == "not_set":
        return "no coin creator set on the pool (the default address)"
    if kind not in KIND_TEXT:
        return f"{address} (unrecognized entry)"
    parts = [KIND_TEXT[kind]]
    if kind == "program_account":
        parts.append(f"owner program {_addr(recipient.get('owner_program'))}")
    detail = DETAIL_TEXT.get(recipient.get("detail")) if isinstance(recipient.get("detail"), str) else None
    if detail:
        parts.append(detail)
    return f"{address} ({'; '.join(parts)})"


def _shared_lines(recipient: dict[str, Any], labels: dict[str, list[str]]) -> list[str]:
    holders = [h for h in recipient.get("shareholders") if isinstance(h, dict)] if isinstance(recipient.get("shareholders"), list) else []
    revoked = recipient.get("admin_revoked")
    revoked_text = "yes" if revoked is True else "no: the admin can still set the shareholders once" if revoked is False else "not read"
    paused = "; config paused" if recipient.get("config_status") == "paused" else ""
    shares = ", ".join(f"{_who(h.get('address'), labels, curve=True)} {_bps(h.get('share_bps'))}" for h in holders) or "no shareholder in the file"
    version = _int(recipient.get("version"))
    state = {"active": "active", "paused": "paused"}.get(recipient.get("config_status"), "not read")
    return [f"  Creator fees are shared: {shares} (admin revoked: {revoked_text}{paused})",
            f"  fee-sharing config {_addr(recipient.get('address'))} (pump fees program{'' if version is None else f', version {version}'}): "
            f"status {state}, admin {_who(recipient.get('admin'), labels, curve=True)}; the pool's coin creator is this config"]


def _pool_lines(pool: dict[str, Any], labels: dict[str, list[str]]) -> list[str]:
    recipient = pool.get("recipient") if isinstance(pool.get("recipient"), dict) else {}
    found_by = pool.get("found_by") if isinstance(pool.get("found_by"), list) else []
    sources = [FOUND_BY_TEXT[f] for f in FOUND_BY_TEXT if f in found_by]
    how = (", ".join(sources[:-1]) + " and " + sources[-1]) if len(sources) > 1 else sources[0] if sources else "source not read"
    pool_line = (f"  pool {_addr(pool.get('address'))}: canonical PumpSwap pool of this token, pair this token / {_addr(pool.get('quote_mint'))} "
                 f"(found by {how}; the address re-derived from the pool's own fields)")
    lines: list[str] = []
    shared = recipient.get("status") == "identified" and recipient.get("kind") == "sharing_config"
    if pool.get("is_holder_reward") is True:
        lines.append("  Creator fees go to holders: holder rewards coin (pump.fun's docs: the creator fee is set aside for holders and "
                     "pump.fun pays it out; the creator has nothing to claim)")
        lines += _shared_lines(recipient, labels) if shared else [f"  recorded coin creator: {_recipient_text(recipient, labels)}"]
    elif pool.get("is_cashback_coin") is True:
        lines.append("  Cashback coin (pump.fun's docs: the creator fee goes to the trader as cashback when the trade includes the "
                     "cashback accounts, otherwise to the coin creator below)")
        lines += _shared_lines(recipient, labels) if shared else [f"  Creator fees otherwise go to: {_recipient_text(recipient, labels)}"]
    elif shared:
        lines += _shared_lines(recipient, labels)
    elif recipient.get("kind") == "not_set" and recipient.get("status") == "identified":
        lines.append("  Creator fees: no coin creator is set on the pool (the default address); nobody is recorded to receive them yet")
    else:
        lines.append(f"  Creator fees go to: {_recipient_text(recipient, labels)}")
    lines.append(pool_line)
    return lines


def present(run: Path) -> list[str]:
    """The block the synthesis prints in the sources-read part of SUMMARY.md. Reads only saved files: no network, no key.
    A missing, foreign or malformed file or value reads as not read, never as a crash."""
    path = run / OUT_FILE
    data = _read_json(path)
    result = data if _valid_saved(data) else None
    head = f"Creator fees (collector creator_fees; {INDEPENDENCE_NOTE})"
    if result is None:
        return [f"{head}: not read ({OUT_FILE} " + ("missing" if not path.exists() else "unreadable") + ")"]
    age = _age_min(result.get("fetched_at"))
    state = {"ok": "read", "empty": "read", "unavailable": "unavailable"}[result["status"]]
    line = f"{head}: {state}" + ("" if result["status"] != "unavailable" else f" ({_code(result.get('reason'))})")
    lines = [line + (f"; data age {age:.0f} min" if age is not None else "; data age unknown") + f"; {_calls_text(result)}"]
    try:
        labels = known_labels(run, result["mint"])
    except Exception:  # noqa: BLE001 - labels are optional: never a crash
        labels = {}
    pools = [p for p in result.get("pools") if isinstance(p, dict)] if isinstance(result.get("pools"), list) else []
    dex = result.get("dexscreener") if isinstance(result.get("dexscreener"), dict) else {}
    if result["status"] == "empty":
        lines.append(f"  {_empty_text(result)}")
    elif result["status"] == "ok":
        for pool in pools:
            if pool.get("status") != "identified":
                continue
            try:
                lines += _pool_lines(pool, labels)
            except Exception:  # noqa: BLE001 - a damaged entry is not read, never a crash
                lines.append(f"  pool {_addr(pool.get('address'))}: not read (unreadable entry)")
        sharing = result.get("sharing_config_address")
        used = any(isinstance(p.get("recipient"), dict) and p["recipient"].get("address") == sharing for p in pools)
        if result.get("sharing_config_exists") is True and not used:
            lines.append(f"  a fee-sharing config {_addr(sharing)} exists for this mint, but the pool's coin creator is not it "
                         "(the config's split was not applied to the pool fee)")
    for pool in pools:
        if pool.get("status") == "unavailable":
            check = f", check {_code(pool.get('check'))}" if pool.get("check") is not None else ""
            lines.append(f"  pool {_addr(pool.get('address'))}: unavailable ({_code(pool.get('reason'))}{check}); no recipient guessed")
    if dex.get("status") == "unavailable":
        lines.append(f"  Dexscreener pool lookup: unavailable ({_code(dex.get('reason'))}); only the bonding curve's quote mint and the "
                     "SOL-pair derivation were checked")
    lines += [f"  cannot see: {CANNOT_SEE}", f"  {PRESENTATION_NOTE}"]
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Who receives the creator fee of a PumpSwap token: the canonical pool found with one free "
                                                 "Dexscreener lookup and read over the free public Solana RPC (no key; 1 Dexscreener + 1-2 "
                                                 "RPC calls; bounded: 2 MiB, 30 s, no redirects, no env proxy); save "
                                                 f"{OUT_FILE}; or, with --present RUN_DIR, print the block offline. Presentation only.")
    parser.add_argument("mint", nargs="?")
    parser.add_argument("--out", metavar="RUN_DIR", help="run folder to write creator_fees.json into (no other file of it is read)")
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
        run.mkdir(parents=True, exist_ok=True)
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    try:
        result = collect_creator_fees(args.mint)
    except Exception:  # noqa: BLE001 - never print a traceback
        result = _base(args.mint, _iso(time.time()))
        result["reason"] = "request_failed"
    try:
        (run / OUT_FILE).write_text(json.dumps(result, indent=1), encoding="utf-8")
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    print(status_line(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
