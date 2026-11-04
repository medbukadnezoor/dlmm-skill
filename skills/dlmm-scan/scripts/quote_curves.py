#!/usr/bin/env python3
"""Bonding curves of other coins quoted in this token, for dlmm-scan (follow-up lane `quote_curves`): which coin each curve
belongs to and who created it, read for free.

A pump.fun coin can be quoted in another token: its bonding curve then holds that token (the quote) as buyers pay in. A dev
can create such coins and quote them in its own token; the token then sits in those curves, the holder list shows it as
pools or unidentified program accounts, and whoever holds those coins can pull it back out by selling them. Case: BTC
(2026-10-25), whose dev 7Pyr5o... created the two coins whose curves held 10.31% and 3.99% of BTC's supply at the scan. This
collector finds those curves among this scan's saved holder rows and names, for each one, the coin and its creator from the
coin's verified create transaction, over the free public Solana RPC (no key, no Helius credits):

1. Candidates, read by the script itself from <RUN> with full addresses: holders.json pool_addresses, its top_holders rows
   marked infrastructure and its off-curve top_holders rows, and holder-analysis.json program_account / controlled_vault rows;
   the largest by share first, at most MAX_CANDIDATES, read in ONE getMultipleAccounts batch.
2. A row is "a pump.fun bonding curve of another coin quoted in this token" only when its owner program is pump, it carries
   the BondingCurve discriminator, the account reaches past the quote_mint field, quote_mint is THIS mint, and it is not this
   mint's own bonding curve (the PDA ("bonding-curve", mint)). A PumpSwap pool (owner pump_amm) never is one.
3. For the largest MAX_CURVES curves by share, in a bounded pool of MAX_WORKERS with one shared 429 pause: the other coin's
   mint (getTokenAccountsByOwner on the curve, Token-2022 first, SPL Token only when Token-2022 finds no other mint; the curve
   must be the PDA ("bonding-curve", that mint), else curve_mismatch), then that coin's create transaction, found and verified
   by create_slot.py's own pointer_from_signatures and verify_create_tx (imported, never copied): the deployer (pump's signer
   `user`), the `creator` argument, the signature and the time. The curve's own `creator` field is saved but never used: on
   BTC two curves' fields named other addresses than the signer of their verified create (fee sharing rewrites the field).
Curves past the cap are listed with their share as not read (cap); a failed read gives that curve unavailable with a fixed
reason code, never a guessed creator.

Cited layouts (provider-docs cache, read by hand, never guessed; the tests re-derive the offsets from the cache when present):
- current/pumpfun/idls.md, pump.json: program address; account BondingCurve discriminator [23,183,248,55,96,216,172,96];
  type BondingCurve after the 8-byte discriminator: five u64 reserves fields (8..48), complete bool (48), creator (49),
  is_mayhem_mode (81), is_cashback_coin (82), quote_mint (83..115), creator_fee_bps u64, can_edit_creator_fee, is_holder_reward,
  creator_fee u64, protocol_fees u64, depth u8, initial_virtual_quote_reserves u64, post_complete_base_out u64,
  post_complete_quote_in u64 (166 bytes in all). The same offsets as creator_fees.py; publicdocs.md PUMP_PROGRAM_README:
  fields were appended by later upgrades, an account written before quote_mint existed is shorter and quoted in SOL.
- current/spltoken/layouts.md, token interface state.rs Account: mint (0), owner (32), amount u64 (64), little-endian; the
  same base layout for SPL Token and Token-2022 accounts.
- Methods: current/solana/rpc.md (the account object; getMultipleAccounts, at most 100 keys) and
  current/helius.pages/docs/api-reference/rpc/http/gettokenaccountsbyowner.md (the standard method: owner, {programId},
  {encoding base64, dataSlice}).

Requests (one host, POST JSON-RPC only): api.mainnet-beta.solana.com, https only, path / only. This file's own request layer
sends only getMultipleAccounts (base64, a CURVE_SLICE_BYTES data slice) and getTokenAccountsByOwner (base64, a
TOKEN_SLICE_BYTES data slice) with no header but the content type; create_slot.py's layer (by import) sends the pointer's
getSignaturesForAddress pages and the getTransaction. Both: no key, no redirects, no environment proxy, MAX_BYTES per answer,
a hard TIMEOUT_S wall-clock limit per attempt, at most one retry per request and only after a 429 (Retry-After up to 10 s,
create_slot.py's RETRY_MAX_WAIT_S, else 1.5 s); here every worker waits out that one pause before its next request (inside
that request's TIMEOUT_S attempt). Pace: at most METHOD_PACE (8) requests of one method per METHOD_WINDOW_S (10 s) for the
whole pool. Live 2026-10-26 the public RPC answered with x-ratelimit-method-limit 10 for getTokenAccountsByOwner,
getSignaturesForAddress and getTransaction (50 for getMultipleAccounts), counted over a sliding 10 s with the refused requests
included, and an 11th request got a 429 with Retry-After 10, which the one retry now waits out (DS-RPC-RETRY-T1; before, it
ended the read); the pace keeps the lane's own requests under that limit (a scan needs about 6 of each, so it rarely waits)
and leaves room for the other follow-up lanes. Calls per scan: 1
batch plus, per curve read, at most 2 token-account reads, at most 3 signature pages and 1 transaction: at most MAX_CALLS
(37), at most MAX_REQUESTS (74) with the retries. Worst-case wall time: the batch, then two rounds of 3 curves, each at most
6 calls one after another (each read needs the one before it), each at most about 70 s (30 s, a retry wait of at most 10 s,
30 s), plus at most about 20 s of pace: about 15.5 minutes; a few seconds when the RPC answers. There is no extra lane-wide
deadline.

PRESENTATION ONLY: the synthesis prints the block with --present; this file is never an engine input and changes no verdict,
flag or threshold. It prints only addresses, signatures, times, numbers and fixed phrases (no provider text).

Collector: quote_curves.py <MINT> --out <RUN> [--workers N] reads its candidates from <RUN>/holders.json and
<RUN>/holder-analysis.json, writes <RUN>/followup/quote_curves.json and prints one line: ok (...), empty (...) or
unavailable (<reason>; ...). Exit 0 whenever the file was saved; exit 2 for a bad mint, --workers or --out.
Synthesis (offline, no network): quote_curves.py --present <RUN> also reads <RUN>/followup/create_slot_trace.json (this
token's dev wallets) and <RUN>/holders.json (shares and ranks). Standard library only; Python >= 3.10.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import collections
import concurrent.futures
import datetime as dt
import json
import math
import re
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import create_slot as cs  # noqa: E402  (the create-tx pointer, its verification, the guarded transport and the address helpers, by import)

HOST = "api.mainnet-beta.solana.com"
RPC_ENDPOINT = f"https://{HOST}"
ALLOWED_METHODS = ("getMultipleAccounts", "getTokenAccountsByOwner")      # this file's own request layer
REUSED_METHODS = ("getSignaturesForAddress", "getTransaction")             # create_slot.py's layer, by import
MAX_CANDIDATES = 100             # getMultipleAccounts: at most 100 public keys per request (current/solana/rpc.md)
MAX_CURVES = 6                   # curves whose coin and creator are read per scan, the largest by share first
MAX_WORKERS = 3                  # curves read at the same time
TOKEN_READS_PER_CURVE = 2        # Token-2022, then SPL Token only when Token-2022 finds no other mint
CALLS_PER_CURVE = TOKEN_READS_PER_CURVE + cs.MAX_SIGNATURE_PAGES + 1
MAX_CALLS = 1 + MAX_CURVES * CALLS_PER_CURVE
MAX_REQUESTS = 2 * MAX_CALLS
MAX_BYTES = 2 * 1024 * 1024
TIMEOUT_S = cs.TIMEOUT_S
METHOD_WINDOW_S = 10.0           # the public RPC's per-method window (live 2026-10-26, x-ratelimit-method-limit: 10 for
METHOD_PACE = 8                  # getTokenAccountsByOwner, getSignaturesForAddress, getTransaction); this lane sends at most 8
#                                  of one method per window, leaving room for the other follow-up lanes on the same host
SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
SIGNATURE_RE = cs.SIGNATURE_RE
OUT_DIR = "followup"
OUT_FILE = "quote_curves.json"
SCHEMA = "holder-scan-quote-curves/1"
SUMMARY_MARK = "[for the executive summary] "  # the same text as exit_overhang.SUMMARY_MARK

# ----------------------------------------------------------------------------- cited program ids and layouts

PUMP_PROGRAM = cs.PUMP_PROGRAM                                     # pump.json "address"
PUMP_AMM_PROGRAM = cs.PUMP_AMM_PROGRAM                             # pump_amm.json "address"
TOKEN_2022_PROGRAM = cs.TOKEN_2022_PROGRAM
SPL_TOKEN_PROGRAM = cs.SPL_TOKEN_PROGRAM
TOKEN_PROGRAMS = (TOKEN_2022_PROGRAM, SPL_TOKEN_PROGRAM)             # the order the other coin's token account is looked up
CURVE_DISCRIMINATOR = bytes([23, 183, 248, 55, 96, 216, 172, 96])  # pump.json accounts: BondingCurve
# pump.json type BondingCurve after the 8-byte discriminator: five u64 reserves (8..48), complete (48), creator (49),
# is_mayhem_mode (81), is_cashback_coin (82), quote_mint (83), ...; 166 bytes with every field of the cached IDL
CURVE_COMPLETE, CURVE_CREATOR, CURVE_QUOTE_MINT = 48, 49, 83
CURVE_BASE_END = CURVE_COMPLETE + 1   # the fields every bonding curve has
CURVE_QUOTE_END = CURVE_QUOTE_MINT + 32
CURVE_SLICE_BYTES = 166               # the whole cached BondingCurve; other accounts are only told apart by owner and discriminator
# token interface state.rs Account: array_refs![src, 32, 32, 8, ...]: mint, owner, amount
TOKEN_MINT, TOKEN_OWNER, TOKEN_AMOUNT = 0, 32, 64
TOKEN_SLICE_BYTES = TOKEN_AMOUNT + 8

INDEPENDENCE_NOTE = "public Solana RPC, no key, free"
CANNOT_SEE = (f"only this scan's saved pool, infrastructure and program-account rows (at most {MAX_CANDIDATES}, the largest first) "
              f"and pump.fun bonding curves (other launchpads' curves quoted in this token are not read); at most {MAX_CURVES} curves "
              "read per scan, the others listed with their share as not read; the creator is the signer and the creator argument of "
              "each coin's verified create transaction, so a dev that created those coins from another wallet is listed as another "
              "creator, not as this token's dev; the share is the curve's balance of this token at the scan, not what the dev can "
              "reach: whoever holds those coins can pull it out by selling them, and who holds them (the dev included) is not read; "
              "one read at read time, no history")
PRESENTATION_NOTE = ("presentation only: names the bonding curves of other coins quoted in this token next to the holder rows; "
                     "never an engine input, never changes a FLAG, verdict or threshold and never counts toward NO_ALARM; "
                     "nothing seen here is an all-clear")


# ----------------------------------------------------------------------------- small validated readers


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return float(value)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _key(raw: bytes, offset: int) -> str:
    return cs.b58encode(raw[offset:offset + 32])


is_address, off_curve = cs.is_address, cs.off_curve


# ----------------------------------------------------------------------------- request (this file's own layer)


def check_url(url: str) -> None:
    """https only, host api.mainnet-beta.solana.com only, path / only, no query, no port other than 443, no credentials
    (create_slot.send_once checks the request's address again before it opens anything)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise cs.Failure("scheme_not_https")
    if parsed.hostname != HOST or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise cs.Failure("host_not_allowlisted")
    if parsed.path not in ("", "/") or parsed.query or parsed.params or parsed.fragment:
        raise cs.Failure("path_not_allowlisted")


def build_request(payload: dict[str, Any]) -> urllib.request.Request:
    """A POST of one JSON-RPC payload whose method is one of this file's two; no header but the content type."""
    check_url(RPC_ENDPOINT)
    if payload.get("method") not in ALLOWED_METHODS:
        raise cs.Failure("method_not_allowlisted")
    request = urllib.request.Request(RPC_ENDPOINT, data=json.dumps(payload, separators=(",", ":")).encode("utf-8"), method="POST")
    request.add_header("Content-Type", "application/json")
    return request


def batch_payload(keys: list[str]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": "getMultipleAccounts",
            "params": [keys, {"encoding": "base64", "commitment": "confirmed", "dataSlice": {"offset": 0, "length": CURVE_SLICE_BYTES}}]}


def token_accounts_payload(owner: str, program: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": "getTokenAccountsByOwner",
            "params": [owner, {"programId": program}, {"encoding": "base64", "commitment": "confirmed",
                                                       "dataSlice": {"offset": 0, "length": TOKEN_SLICE_BYTES}}]}


def default_opener() -> urllib.request.OpenerDirector:
    """create_slot.py's opener: no environment proxy, no redirects, default TLS verification."""
    return cs.default_opener()


def rpc_call(payload: dict[str, Any], opener: Any, *, monotonic: Callable[[], float], sleep: Callable[[float], None]) -> dict[str, Any]:
    """One JSON-RPC request through create_slot.py's guarded send_once, plus at most one retry after a 429. Returns {method,
    result, attempts, reason, http_status, rpc_error_code, bytes}, the shape of create_slot.rpc_call; never raises. A
    JSON-RPC error answer is rpc_error with its numeric code only (its message is not kept)."""
    out: dict[str, Any] = {"method": payload.get("method"), "result": None, "attempts": 0, "reason": None, "http_status": None,
                           "rpc_error_code": None, "bytes": 0}
    for attempt in (1, 2):
        out["attempts"] = attempt
        try:
            body = cs.send_once(build_request(payload), opener, monotonic=monotonic, max_bytes=MAX_BYTES)
            out.update(reason=None, http_status=200, bytes=out["bytes"] + len(body))
        except cs.Failure as failure:
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


def _call_facts(got: dict[str, Any]) -> dict[str, Any]:
    return {"method": got["method"], "attempts": got["attempts"], "reason": got["reason"], "http_status": got["http_status"],
            "rpc_error_code": got["rpc_error_code"], "bytes": got["bytes"]}


class SharedPause:
    """One 429 pause for the whole pool: the wait before a retry is set here, and every worker waits it out before its next
    request (both request layers get `sleep` and the opener from here)."""

    def __init__(self, monotonic: Callable[[], float], sleep: Callable[[float], None]) -> None:
        self._monotonic, self._sleep = monotonic, sleep
        self._lock = threading.Lock()
        self._until = 0.0
        self.pauses = 0

    def wait(self) -> None:
        with self._lock:
            left = self._until - self._monotonic()
        if left > 0:
            self._sleep(left)

    def sleep(self, seconds: float) -> None:
        with self._lock:
            self._until = max(self._until, self._monotonic() + seconds)
            self.pauses += 1
        self.wait()


class MethodPace:
    """At most METHOD_PACE requests of one JSON-RPC method in any METHOD_WINDOW_S window, for the whole pool: each request
    takes the earliest free place in its method's window (first come, first served) and waits until then. The public RPC
    limits these methods per IP (live 2026-10-26: 10 per 10 s, and a 429 asks for 10 s, which the one retry waits out as a
    pause for the whole pool)."""

    def __init__(self, monotonic: Callable[[], float], sleep: Callable[[float], None]) -> None:
        self._monotonic, self._sleep = monotonic, sleep
        self._lock = threading.Lock()
        self._sent: dict[str, collections.deque[float]] = {}
        self.waits = 0

    def take(self, method: str) -> None:
        with self._lock:
            now = self._monotonic()
            sent = self._sent.setdefault(method, collections.deque())
            while sent and sent[0] <= now - METHOD_WINDOW_S:
                sent.popleft()
            at = max(now, sent[-1] if sent else now, sent[-METHOD_PACE] + METHOD_WINDOW_S if len(sent) >= METHOD_PACE else now)
            sent.append(at)
            if at > now:
                self.waits += 1
        if at > now:
            self._sleep(at - now)


class PausedOpener:
    """The opener every worker shares: each request first waits out the shared 429 pause and its method's pace, then goes
    to the real opener."""

    def __init__(self, opener: Any, pause: SharedPause, pace: MethodPace | None = None) -> None:
        self._opener, self._pause, self._pace = opener, pause, pace

    def open(self, request: Any, timeout: float | None = None) -> Any:
        self._pause.wait()
        if self._pace is not None:
            try:
                method = json.loads(request.data.decode("utf-8")).get("method")
            except (AttributeError, ValueError, UnicodeDecodeError):
                method = None
            self._pace.take(method if isinstance(method, str) else "other")
        return self._opener.open(request, timeout=timeout)


# ----------------------------------------------------------------------------- decoding (cited layouts, validated)


def _account(value: Any) -> dict[str, Any] | None:
    """A getMultipleAccounts / getTokenAccountsByOwner account -> {owner, data, space}; None when not readable base64."""
    if not isinstance(value, dict) or not is_address(value.get("owner")):
        return None
    data = value.get("data")
    if not (isinstance(data, list) and len(data) == 2 and data[1] == "base64" and isinstance(data[0], str)):
        return None
    try:
        raw = base64.b64decode(data[0], validate=True)
    except (binascii.Error, ValueError):
        return None
    space = _int(value.get("space"))
    return {"owner": value["owner"], "data": raw, "space": space if space is not None and space >= 0 else None}


def classify(address: str, value: Any, mint: str, own_curve: str | None) -> dict[str, Any]:
    """One candidate from the batch read -> {kind, ...}. kind 'curve' only for a pump.fun bonding curve of ANOTHER coin whose
    quote mint is this mint (owner program, discriminator, length and the complete byte checked)."""
    if value is None:
        return {"kind": "no_account"}
    account = _account(value)
    if account is None:
        return {"kind": "unreadable"}
    if account["owner"] == PUMP_AMM_PROGRAM:
        return {"kind": "pump_amm_account"}
    if account["owner"] != PUMP_PROGRAM:
        return {"kind": "other_program" if off_curve(address) else "other_account"}
    raw = account["data"]
    if raw[:8] != CURVE_DISCRIMINATOR:
        return {"kind": "other_pump_account"}
    size = account["space"] if account["space"] is not None else len(raw)
    if size < CURVE_BASE_END or len(raw) < min(size, CURVE_QUOTE_END) or CURVE_QUOTE_MINT < size < CURVE_QUOTE_END:
        return {"kind": "curve_refused", "check": "length"}
    if raw[CURVE_COMPLETE] not in (0, 1):
        return {"kind": "curve_refused", "check": "flags"}
    quote = _key(raw, CURVE_QUOTE_MINT) if size >= CURVE_QUOTE_END else None  # written before quote_mint existed: quoted in SOL
    if address == own_curve:
        return {"kind": "own_curve", "quote_mint": quote}
    if quote != mint:
        return {"kind": "curve_other_quote"}
    return {"kind": "curve", "complete": raw[CURVE_COMPLETE] == 1, "creator_field": _key(raw, CURVE_CREATOR), "data_len": size}


def token_accounts(result: Any, owner: str, program: str) -> list[dict[str, Any]]:
    """A getTokenAccountsByOwner answer (base64, data slice mint/owner/amount) -> [{token_account, mint, amount_raw}].
    Raises cs.Mismatch on any account that is not a token account of `program` owned by `owner`."""
    rows = result.get("value") if isinstance(result, dict) else None
    if not isinstance(rows, list):
        raise cs.Mismatch("token_accounts_shape")
    found = []
    for row in rows:
        pubkey = row.get("pubkey") if isinstance(row, dict) else None
        account = _account(row.get("account")) if isinstance(row, dict) else None
        if not is_address(pubkey) or account is None or account["owner"] != program or len(account["data"]) != TOKEN_SLICE_BYTES:
            raise cs.Mismatch("token_accounts_shape")
        raw = account["data"]
        if _key(raw, TOKEN_OWNER) != owner:
            raise cs.Mismatch("token_account_owner")
        found.append({"token_account": pubkey, "mint": _key(raw, TOKEN_MINT), "amount_raw": struct.unpack_from("<Q", raw, TOKEN_AMOUNT)[0]})
    return found


# ----------------------------------------------------------------------------- candidates from the saved holder rows


def collect_candidates(run: Path, mint: str) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Candidates (pool addresses, infrastructure and off-curve rows of holders.json; program_account / controlled_vault rows
    of holder-analysis.json), deduplicated, each with its share of supply at the scan (holders.json top row, else
    owner_balances over the distribution supply, else holder-analysis.json), the largest first and unknown shares last.
    Returns (candidates, how each saved file was read)."""
    found: dict[str, dict[str, Any]] = {}
    read: dict[str, str] = {}
    shares: dict[str, tuple[float, str, int | None]] = {}

    def add(address: Any, source: str) -> None:
        if not is_address(address) or address == mint:
            return
        entry = found.setdefault(address, {"address": address, "from": []})
        if source not in entry["from"]:
            entry["from"].append(source)

    holders = _read_json(run / "holders.json")
    if not (run / "holders.json").exists():
        read["holders.json"] = "missing"
    elif not isinstance(holders, dict):
        read["holders.json"] = "unreadable"
    elif holders.get("mint") != mint:
        read["holders.json"] = "other_mint"
    else:
        read["holders.json"] = "read"
        supply = _number(_dict(holders.get("distribution")).get("supply"))
        balances = _dict(holders.get("owner_balances"))
        for address, balance in balances.items():
            amount = _number(balance)
            if is_address(address) and amount is not None and amount >= 0 and supply and supply > 0:
                shares.setdefault(address, (amount / supply * 100, "holders.json owner_balances", None))  # exact: a tiny balance is never 0
        for row in _list(holders.get("top_holders")):
            row = _dict(row)
            address, share = row.get("wallet"), _number(row.get("share_pct"))
            if not is_address(address):
                continue
            if share is not None and share >= 0 and not (share == 0 and shares.get(address, (0.0,))[0] > 0):  # a row rounded to 0
                shares[address] = (share, "holders.json top_holders", _int(row.get("rank")))
            if row.get("infrastructure") is True:
                add(address, "holders.json infrastructure row")
            if off_curve(address):
                add(address, "holders.json off-curve row")
        for address in _list(holders.get("pool_addresses")):
            add(address, "holders.json pool_addresses")
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
            row = _dict(row)
            if row.get("kind") in ("program_account", "controlled_vault") and is_address(row.get("owner")):
                add(row["owner"], f"holder-analysis.json {row['kind']}")
                share = _number(row.get("share"))
                if share is not None and 0 <= share <= 1:
                    shares.setdefault(row["owner"], (round(share * 100, 4), "holder-analysis.json share", None))
    out = []
    for address, entry in found.items():
        share, source, rank = shares.get(address, (None, None, None))
        out.append({**entry, "share_pct": share, "share_source": source, "rank": rank})
    out.sort(key=lambda c: (c["share_pct"] is None, -(c["share_pct"] or 0.0), c["address"]))
    return out, read


# ----------------------------------------------------------------------------- one curve: its coin and its creator


def read_curve(curve: dict[str, Any], mint: str, opener: Any, *, now: Callable[[], float], monotonic: Callable[[], float],
               sleep: Callable[[float], None]) -> dict[str, Any]:
    """The other coin's mint (its token account held by the curve, derivation checked), then its create transaction through
    create_slot.py's pointer and verification. Never raises: a failed read is unavailable with a fixed code."""
    calls: list[dict[str, Any]] = []
    entry = {**curve, "status": "unavailable", "reason": None, "check": None, "read_reason": None, "rpc_error_code": None, "other_mint": None,
             "other_mints_seen": [], "token_program": None, "pointer": None, "deployer": None, "creator": None, "deployer_signed": None,
             "create_signature": None, "create_slot": None, "create_time": None, "method": None, "calls": calls}

    def fail(reason: str, check: str | None = None, got: dict[str, Any] | None = None) -> dict[str, Any]:
        entry.update(status="unavailable", reason=reason, check=check)
        if got is not None:
            entry.update(read_reason=got.get("reason"), rpc_error_code=got.get("rpc_error_code"))
        return entry

    try:
        address, others, program = curve["address"], [], None
        for program in TOKEN_PROGRAMS:
            got = rpc_call(token_accounts_payload(address, program), opener, monotonic=monotonic, sleep=sleep)
            calls.append(_call_facts(got))
            if got["reason"] is not None:
                return fail("token_accounts_read_failed", None, got)
            try:
                held = token_accounts(got["result"], address, program)
            except cs.Mismatch as exc:
                return fail("layout_mismatch", exc.check)
            others = [a for a in held if a["mint"] != mint]
            if others:
                break
        if not others:
            return fail("other_mint_not_found")
        entry["token_program"] = program
        entry["other_mints_seen"] = sorted({a["mint"] for a in others})
        derived = [m for m in entry["other_mints_seen"] if cs.bonding_curve_of(m) == address]
        if len(derived) != 1:
            return fail("curve_mismatch")
        other = entry["other_mint"] = derived[0]
        pointer = cs.pointer_from_signatures(other, program, opener, calls, monotonic=monotonic, sleep=sleep)
        tried = [{k: t.get(k) for k in ("account", "address", "pages", "signatures_seen", "outcome", "read_reason", "rpc_error_code")}
                 for t in _list(pointer.get("tried")) if isinstance(t, dict)]
        entry["pointer"] = {"status": pointer.get("status"), "reason": pointer.get("reason"), "account": pointer.get("account"),
                            "address": pointer.get("address"), "pages": pointer.get("pages"), "tried": tried}
        if pointer.get("status") != "ok":
            last = tried[-1] if tried else {}
            return fail("no_create_tx_pointer", pointer.get("reason"), {"reason": last.get("read_reason"), "rpc_error_code": last.get("rpc_error_code")})
        got = cs.rpc_call(cs.transaction_payload(pointer["signature"]), opener, monotonic=monotonic, sleep=sleep)
        calls.append(_call_facts(got))
        if got["reason"] is not None:
            return fail("create_tx_read_failed", None, got)
        try:
            create = cs.verify_create_tx(got["result"], pointer["signature"], other, pointer.get("slot"), now())
        except cs.Mismatch as exc:
            return fail("create_tx_mismatch", exc.check)
        if not create.get("deployer"):
            return fail("create_tx_mismatch", "no_pump_create")
        entry.update(status="read", deployer=create["deployer"], creator=create["creator"], deployer_signed=create["deployer_signed"],
                     create_signature=create["signature"], create_slot=create["slot"], create_time=create["block_time"], method=create["method"])
        return entry
    except Exception:  # noqa: BLE001 - an answer the checks did not foresee: a fixed code, never a crash
        return fail("parse_error")


# ----------------------------------------------------------------------------- collect


def _base(mint: str, fetched_at: str, workers: int) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "lane": "quote_curves", "mint": mint, "status": "unavailable", "reason": None, "fetched_at": fetched_at,
        "http_status": None, "rpc_error_code": None, "slot": None,
        "request": {"host": HOST, "path": "/", "methods": [*ALLOWED_METHODS, *REUSED_METHODS], "own_methods": list(ALLOWED_METHODS),
                    "methods_through_create_slot": list(REUSED_METHODS), "keys": "none", "calls": [], "requests_sent": 0, "bytes_received": 0,
                    "max_calls": MAX_CALLS, "max_requests": MAX_REQUESTS, "max_candidates": MAX_CANDIDATES, "max_curves": MAX_CURVES,
                    "workers": workers, "method_pace": f"at most {METHOD_PACE} requests of one method per {METHOD_WINDOW_S:.0f} s",
                    "rate_limit_pauses": 0, "pace_waits": 0},
        "sources": {"pump": "provider-docs current/pumpfun/idls.md (pump.json: BondingCurve discriminator and fields; bonding-curve seeds) and "
                            "publicdocs.md (PUMP_PROGRAM_README: appended fields)",
                    "spl_token": "provider-docs current/spltoken/layouts.md (token interface state.rs Account: mint, owner, amount)",
                    "rpc": "provider-docs current/solana/rpc.md (account object, getMultipleAccounts) and "
                           "current/helius.pages/docs/api-reference/rpc/http/gettokenaccountsbyowner.md",
                    "create_tx": "scripts/create_slot.py pointer_from_signatures and verify_create_tx (by import)"},
        "candidates_from": {}, "candidates": 0, "candidates_read": 0, "candidates_not_read": 0, "own_curve": None, "kinds": {},
        "curves": [], "curves_refused": [],
        "presentation_only": True, "note": PRESENTATION_NOTE, "cannot_see": CANNOT_SEE,
    }


def collect_quote_curves(
    mint: str,
    run: Path,
    *,
    workers: int = MAX_WORKERS,
    opener: Any | None = None,
    now: Callable[[], float] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """Candidates from the saved rows, one batch read, then at most MAX_CURVES curves read in a bounded pool of `workers`.
    Returns the quote_curves.json result; never raises for provider or transport failures."""
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    workers = max(1, min(MAX_WORKERS, workers))
    result = _base(mint, _iso(now()), workers)
    calls: list[dict[str, Any]] = result["request"]["calls"]
    pause, pace = SharedPause(monotonic, sleep), MethodPace(monotonic, sleep)

    def finish(status: str, reason: str | None = None) -> dict[str, Any]:
        result.update(status=status, reason=reason, fetched_at=_iso(now()))
        result["request"]["requests_sent"] = sum(c["attempts"] for c in calls)
        result["request"]["bytes_received"] = sum(c["bytes"] for c in calls)
        result["request"]["rate_limit_pauses"] = pause.pauses
        result["request"]["pace_waits"] = pace.waits
        return result

    candidates, read = collect_candidates(run, mint)
    result["candidates_from"] = read
    result["own_curve"] = own = cs.bonding_curve_of(mint)
    result["candidates"] = len(candidates)
    kept = candidates[:MAX_CANDIDATES]
    result["candidates_not_read"] = len(candidates) - len(kept)
    if not kept:
        return finish("empty" if read.get("holders.json") == "read" else "unavailable", "no_candidates" if read.get("holders.json") == "read" else "holders_not_read")
    shared = PausedOpener(opener or default_opener(), pause, pace)
    got = rpc_call(batch_payload([c["address"] for c in kept]), shared, monotonic=monotonic, sleep=pause.sleep)
    calls.append(_call_facts(got))
    result.update(http_status=got["http_status"], rpc_error_code=got["rpc_error_code"])
    if got["reason"] is not None:
        return finish("unavailable", got["reason"])
    answer = got["result"]
    values = answer.get("value") if isinstance(answer, dict) else None
    if not isinstance(values, list) or len(values) != len(kept):
        return finish("unavailable", "invalid_shape")
    result["slot"] = _int(_dict(answer.get("context")).get("slot"))
    result["candidates_read"] = len(kept)
    curves = []
    for candidate, value in zip(kept, values):
        try:
            kind = classify(candidate["address"], value, mint, own)
        except Exception:  # noqa: BLE001
            kind = {"kind": "curve_refused", "check": "parse_error"}
        result["kinds"][kind["kind"]] = result["kinds"].get(kind["kind"], 0) + 1
        if kind["kind"] == "curve":
            curves.append({**candidate, "complete": kind["complete"], "creator_field": kind["creator_field"], "data_len": kind["data_len"]})
        elif kind["kind"] == "curve_refused":
            result["curves_refused"].append({**candidate, "reason": "layout_mismatch", "check": kind["check"]})
    chosen, rest = curves[:MAX_CURVES], curves[MAX_CURVES:]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="quote-curves") as pool:  # never one by one
        futures = [pool.submit(read_curve, c, mint, shared, now=now, monotonic=monotonic, sleep=pause.sleep) for c in chosen]
        done = [f.result() for f in futures]
    for entry in done:
        curve_calls = entry.pop("calls")
        entry["calls"] = len(curve_calls)
        calls.extend({**c, "curve": entry["address"]} for c in curve_calls)
    result["curves"] = done + [{**c, "status": "not_read", "reason": "curve_cap"} for c in rest]
    if not curves:
        return finish("empty", "no_curves")
    return finish("ok")


def status_line(result: dict[str, Any]) -> str:
    sent = result["request"]["requests_sent"]
    calls = f"{sent} call{'s' if sent != 1 else ''} to the public Solana RPC" if sent else "no RPC call sent"
    if result["status"] == "empty":
        return f"empty (no bonding curve of another coin quoted in this token among {result['candidates_read']} rows read; {calls})"
    if result["status"] != "ok":
        return f"unavailable ({result['reason']}; {calls})"
    curves = result["curves"]
    read = sum(1 for c in curves if c["status"] == "read")
    failed = sum(1 for c in curves if c["status"] == "unavailable")
    capped = sum(1 for c in curves if c["status"] == "not_read")
    return (f"ok ({len(curves)} bonding curve{'s' if len(curves) != 1 else ''} of other coins quoted in this token: {read} read, {failed} unavailable, "
            f"{capped} not read (cap of {MAX_CURVES}); {calls})")


# ----------------------------------------------------------------------------- presentation (synthesis, offline)


KNOWN_CODES = frozenset(cs.KNOWN_CODES | {
    "holders_not_read", "no_candidates", "no_curves", "token_accounts_read_failed", "token_accounts_shape", "token_account_owner",
    "other_mint_not_found", "curve_mismatch", "no_pump_create", "curve_cap", "length", "flags", "parse_error",
})
CREATE_TRACE_SCHEMA = cs.SCHEMA


def _code(value: Any) -> str:
    """A reason or check code read back from the saved file: printed only when it is one of the fixed codes."""
    return value if isinstance(value, str) and value in KNOWN_CODES else "unrecognized code"


def _addr(value: Any) -> str:
    return value if isinstance(value, str) and SOLANA_ADDRESS_RE.fullmatch(value) else "unknown"


def _short(value: Any) -> str:
    address = _addr(value)
    return f"`{address[:6]}…`" if address != "unknown" else "`unknown`"


def _sig(value: Any) -> str:
    return value if isinstance(value, str) and SIGNATURE_RE.fullmatch(value) else "unknown"


def _utc(ts: Any) -> str:
    value = _int(ts)
    if value is None or not (0 < value < 7_258_118_400):
        return "unknown time"
    return dt.datetime.fromtimestamp(value, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _pct(value: Any) -> str | None:
    """A saved share of supply in percent to 2 decimals (as the EXIT OVERHANG block prints holders.json shares); a share
    under 0.005% that is above 0 reads 'under 0.01%'; anything unreadable is None (printed as not read, never as 0)."""
    share = _number(value)
    if share is None or share < 0 or share > 100:
        return None
    if 0 < share < 0.005:
        return "under 0.01%"
    return f"{share:.2f}%"


def _age_min(value: Any) -> float | None:
    try:
        fetched = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if fetched.tzinfo is None:
            return None
        return max(0.0, (dt.datetime.now(dt.timezone.utc) - fetched).total_seconds() / 60)
    except (ValueError, TypeError, OverflowError):
        return None


def _valid_saved(data: Any) -> bool:
    return (isinstance(data, dict) and data.get("schema") == SCHEMA and data.get("status") in ("ok", "empty", "unavailable")
            and data.get("presentation_only") is True and is_address(data.get("mint")))


def _calls_text(request: dict[str, Any]) -> str:
    calls = [c for c in _list(request.get("calls")) if isinstance(c, dict)]
    if not calls:
        return "no RPC call"
    counts: dict[str, int] = {}
    for c in calls:
        method = c.get("method") if c.get("method") in (*ALLOWED_METHODS, *REUSED_METHODS) else "other"
        counts[method] = counts.get(method, 0) + 1
    sent = _int(request.get("requests_sent"))
    retries = f"; {sent} requests with retries" if sent is not None and sent > len(calls) else ""
    return f"{len(calls)} call{'s' if len(calls) != 1 else ''} (" + ", ".join(f"{n} {m}" for m, n in counts.items()) + f"){retries}"


def this_token_dev(run: Path, mint: str) -> tuple[list[str], str | None]:
    """This token's dev wallets from the saved create-slot trace (create_tx.dev_wallets, only when it says ok or empty), or
    ([], why not)."""
    path = run / OUT_DIR / "create_slot_trace.json"
    data = _read_json(path)
    if not path.exists():
        return [], "create_slot_trace.json missing"
    if not isinstance(data, dict) or data.get("schema") != CREATE_TRACE_SCHEMA or data.get("status") not in ("ok", "empty", "unavailable"):
        return [], "create_slot_trace.json unreadable"
    if data.get("mint") != mint:
        return [], "create_slot_trace.json is for another mint"
    if data["status"] == "unavailable":
        return [], f"create-slot trace unavailable: {_code(data.get('reason'))}"
    dev = [w for w in dict.fromkeys(_list(_dict(data.get("create_tx")).get("dev_wallets"))) if is_address(w)]
    if not dev:
        return [], "the create-slot trace names no creator"
    return dev, None


def holder_index(run: Path, mint: str) -> dict[str, Any]:
    """This scan's holders.json: share and rank per top row, shares from owner_balances, and whether the list is complete."""
    data = _read_json(run / "holders.json")
    out: dict[str, Any] = {"state": "read", "rows": {}, "balances": {}, "complete": False}
    if not (run / "holders.json").exists():
        return {**out, "state": "holders.json missing"}
    if not isinstance(data, dict):
        return {**out, "state": "holders.json unreadable"}
    if data.get("mint") != mint:
        return {**out, "state": "holders.json is for another mint"}
    for row in _list(data.get("top_holders")):
        row = _dict(row)
        share = _number(row.get("share_pct"))
        if is_address(row.get("wallet")) and share is not None and row["wallet"] not in out["rows"]:
            out["rows"][row["wallet"]] = (share, _int(row.get("rank")))
    supply = _number(_dict(data.get("distribution")).get("supply"))
    balances = data.get("owner_balances")
    if isinstance(balances, dict) and supply and supply > 0:
        for address, balance in balances.items():
            amount = _number(balance)
            if is_address(address) and amount is not None and amount >= 0:
                out["balances"][address] = amount / supply * 100
        # "holds none" only from a full list: owner_balances read (not empty) AND the scan says the list was not cut short
        out["complete"] = data.get("truncated") is False and bool(out["balances"])
    return out


def _holding(wallet: str, holders: dict[str, Any]) -> str:
    if holders["state"] != "read":
        return f"its holding of this token not read ({holders['state']})"
    if wallet in holders["rows"]:
        share, rank = holders["rows"][wallet]
        text = _pct(share)
        return (f"holds {text} of this token" if text else "holds this token (share not read)") + (f" (holder rank #{rank})" if rank else "")
    if wallet in holders["balances"]:
        text = _pct(holders["balances"][wallet])
        return f"holds {text} of this token" if text else "holds this token (share not read)"
    if holders["complete"]:
        return "holds none of this token at the scan (this scan's full holder list)"
    return "its holding of this token not read (no full holder list saved)"


def _total(curves: list[dict[str, Any]], what: str) -> str:
    """'<x>% of <what>' summed over the curves, 'at least <x>% of <what> (the share of N not read)' when some shares are not
    readable, 'a share of <what> that was not read' when none is: an unknown share is never counted or printed as 0."""
    known = [_number(c.get("share_pct")) or 0.0 for c in curves if _pct(c.get("share_pct")) is not None]
    missing = len(curves) - len(known)
    text = _pct(sum(known)) if known else None
    if text is None:
        return f"a share of {what} that was not read"
    return f"{text} of {what}" if not missing else f"at least {text} of {what} (the share of {missing} not read)"


def _joined(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _dev_line(dev_curves: list[dict[str, Any]], dev: list[str]) -> str:
    matched = [w for w in dev if any(w in (c.get("deployer"), c.get("creator")) for c in dev_curves)]
    who = f"this token's dev {_short(matched[0])}" if len(matched) == 1 else f"this token's dev wallets {_joined([_short(w) for w in matched])}"
    n = len(dev_curves)
    held = _total(dev_curves, "its supply at the scan")
    parts = [f"{_short(c.get('other_mint'))} (curve {_short(c.get('address'))}, {_pct(c.get('share_pct')) or 'share not read'})" for c in dev_curves]
    if n == 1:
        return (f"DEV CURVES: {who} created 1 coin quoted in this token; its bonding curve held {held}: {parts[0]}. Whoever holds that coin "
                "can pull this token out of the curve by selling it; how much of it the dev holds was not read (presentation only).")
    return (f"DEV CURVES: {who} created {n} coins quoted in this token; their bonding curves held {held}: {_joined(parts)}. Whoever holds those "
            "coins can pull this token out of the curves by selling them; how much of them the dev holds was not read (presentation only).")


def _where(c: dict[str, Any]) -> str:
    share, rank = _pct(c.get("share_pct")), _int(c.get("rank"))
    return (f"{share} of supply at the scan" if share else "share of supply not read") + (f", holder rank #{rank}" if rank else "")


METHOD_TEXT = {"pump_create": "pump create", "pump_create_v2": "pump create_v2"}


def _curve_line(c: dict[str, Any], dev: list[str], dev_reason: str | None, holders: dict[str, Any]) -> str:
    address = _addr(c.get("address"))
    head = f"  {address} ({_where(c)}): the pump.fun bonding curve of {_addr(c.get('other_mint'))}"
    deployer, creator = _addr(c.get("deployer")), _addr(c.get("creator"))
    who = f"{deployer} (the pump signer `user`" + (", also the `creator` argument)" if creator == deployer else f"; `creator` argument {creator})")
    holdings = "; ".join(dict.fromkeys(f"{w} {_holding(w, holders)}" for w in (deployer, creator) if w != "unknown"))
    if deployer in dev:
        tie = "this token's dev"
    elif creator in dev:
        tie = f"its `creator` argument is this token's dev wallet; signed by another wallet; {holdings}"
    elif dev:
        tie = f"another creator (not this token's dev wallet); {holdings}"
    else:
        tie = f"this token's dev not known ({dev_reason}); {holdings}"
    state = "complete (the coin left its curve)" if c.get("complete") is True else "not complete (the coin still trades on its curve)" if c.get("complete") is False else "complete flag not read"
    method = METHOD_TEXT.get(c.get("method")) if isinstance(c.get("method"), str) else None
    return (f"{head}, created {_utc(c.get('create_time'))} by {who}: {tie}; create tx {_sig(c.get('create_signature'))} "
            f"({method or 'unknown method'}, verified on-chain); curve {state}")


def _unavailable_line(c: dict[str, Any]) -> str:
    codes = _code(c.get("reason")) + (f", {_code(c.get('check'))}" if c.get("check") else "") + (f", {_code(c.get('read_reason'))}" if c.get("read_reason") else "")
    if _int(c.get("rpc_error_code")) is not None:
        codes += f" {c['rpc_error_code']}"
    coin = f"; coin {_addr(c.get('other_mint'))}" if is_address(c.get("other_mint")) else ""
    return f"  {_addr(c.get('address'))} ({_where(c)}): a bonding curve of another coin quoted in this token; coin or creator not read: unavailable ({codes}){coin}; no creator named"


def present(run: Path) -> list[str]:
    """The DEV CURVES line (marked, only when a curve was created by this token's dev) and the block. Reads only saved files
    (followup/quote_curves.json, followup/create_slot_trace.json, holders.json): no network, no key. A missing, foreign or
    malformed file or value reads as not read, never as a crash."""
    path = run / OUT_DIR / OUT_FILE
    data = _read_json(path)
    result = data if _valid_saved(data) else None
    head = f"Bonding curves of other coins quoted in this token (follow-up lane quote_curves; {INDEPENDENCE_NOTE})"
    if result is None:
        return [f"{head}: not read ({OUT_DIR}/{OUT_FILE} " + ("missing" if not path.exists() else "unreadable") + ")"]
    try:
        mint = result["mint"]
        dev, dev_reason = this_token_dev(run, mint)
        holders = holder_index(run, mint)
        curves = [c for c in _list(result.get("curves")) if isinstance(c, dict)]
        read = [c for c in curves if c.get("status") == "read" and is_address(c.get("other_mint")) and is_address(c.get("deployer"))]
        dev_curves = [c for c in read if {c.get("deployer"), c.get("creator")} & set(dev)]
        lines = [SUMMARY_MARK + _dev_line(dev_curves, dev)] if dev_curves else []
        state = {"ok": "read", "empty": "read", "unavailable": "unavailable"}[result["status"]]
        reason = f" ({_code(result.get('reason'))})" if result["status"] == "unavailable" else ""
        age = _age_min(result.get("fetched_at"))
        lines.append(f"{head}: {state}{reason}" + (f"; data age {age:.0f} min" if age is not None else "; data age unknown")
                     + f"; {_calls_text(_dict(result.get('request')))}")
    except Exception:  # noqa: BLE001 - a damaged header is not read, never a crash
        return [f"{head}: not read (saved values unreadable)", f"  {PRESENTATION_NOTE}"]
    try:
        count = _int(result.get("candidates_read"))
        rows = f"{count} rows read" if count is not None else "the rows read"
        if result["status"] == "ok":
            lines.append(f"  {len(curves)} bonding curve{'s' if len(curves) != 1 else ''} of other pump.fun coins hold this token as their quote "
                         f"({_total(curves, 'supply at the scan')}), among {rows} (this scan's pool, infrastructure and program-account rows)")
            lines.append(f"  This token's dev (create-slot trace): {_joined(dev)}" if dev else f"  This token's dev not known ({dev_reason}): the creators are listed, none is matched")
            for c in read:
                lines.append(_curve_line(c, dev, dev_reason, holders))
            for c in [c for c in curves if c.get("status") == "unavailable" or (c.get("status") == "read" and c not in read)]:
                lines.append(_unavailable_line(c))
            capped = [c for c in curves if c.get("status") == "not_read"]
            if capped:
                lines.append(f"  Not read (cap of {MAX_CURVES} curves per scan): {len(capped)} more curve{'s' if len(capped) != 1 else ''}, {_total(capped, 'supply')}: "
                             + ", ".join(f"{_addr(c.get('address'))} ({_pct(c.get('share_pct')) or 'share not read'})" for c in capped))
            if dev and read and not dev_curves:
                lines.append(f"  None of the {len(read)} curve{'s' if len(read) != 1 else ''} read was created by this token's dev wallet (by the verified create "
                             "transactions; the curves not read are not covered)")
        elif result["status"] == "empty":
            lines.append(f"  no bonding curve of another coin quoted in this token among {rows} "
                         "(this scan's pool, infrastructure and program-account rows; what was seen, not an all-clear)")
        refused = [c for c in _list(result.get("curves_refused")) if isinstance(c, dict)]
        for c in refused:
            lines.append(f"  {_addr(c.get('address'))} ({_where(c)}): a pump bonding-curve account not read (layout_mismatch, check {_code(c.get('check'))})")
        skipped = _int(result.get("candidates_not_read"))
        if skipped:
            lines.append(f"  {skipped} more candidate rows not read (cap of {MAX_CANDIDATES} per scan, the smallest by share)")
    except Exception:  # noqa: BLE001 - a damaged file is not read, never a crash
        lines.append("  not read (unreadable entry)")
    lines += [f"  cannot see: {CANNOT_SEE}", f"  {PRESENTATION_NOTE}"]
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Name the pump.fun bonding curves of other coins quoted in this token among this scan's saved "
                                                 "holder rows, with each coin's creator from its verified create transaction, over the free "
                                                 f"public Solana RPC (no key; at most {MAX_CALLS} calls, {MAX_CURVES} curves, {MAX_WORKERS} at a time; "
                                                 "bounded: 2 MiB, 30 s, no redirects, no env proxy) and save "
                                                 f"{OUT_DIR}/{OUT_FILE}; or, with --present RUN_DIR, print the block offline. Presentation only.")
    parser.add_argument("mint", nargs="?")
    parser.add_argument("--out", metavar="RUN_DIR", help="run folder: candidates are read from its holders.json and holder-analysis.json")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help=f"curves read at the same time (1 to {MAX_WORKERS}, default {MAX_WORKERS})")
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
    if not 1 <= args.workers <= MAX_WORKERS:
        print(f"error: --workers must be 1 to {MAX_WORKERS}", file=sys.stderr)
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
        result = collect_quote_curves(args.mint, run, workers=args.workers)
    except Exception:  # noqa: BLE001 - never print a traceback
        result = _base(args.mint, _iso(time.time()), args.workers)
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
