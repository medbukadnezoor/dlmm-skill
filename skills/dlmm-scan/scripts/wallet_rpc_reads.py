#!/usr/bin/env python3
"""Single-wallet reads for dlmm-scan (follow-up lane `wallet_rpc_reads`): where the biggest wallets without a buy price got
their tokens, read for free.

A dev can hand part of its supply to a fresh wallet by a plain transfer. That wallet bought nothing, so GMGN has no cost
basis for it (often only its transfer_in tag) and the EXIT OVERHANG ratio left it out. Case: BTC (2026-10-25), whose
LoCKu4f3... (7.81% of supply, a plain system wallet with a vanity "LoCK" prefix, not a lock) got its whole bag, 75,000,000
BTC, in one Token-2022 transferChecked signed and paid by the dev 7Pyr5o... at 06:52:17 UTC. This collector reads, over the
free public Solana RPC (no key, no Helius credits), where such wallets got their tokens:

1. Targets, read by the script itself from <RUN> with full addresses: the NO_BASIS_WALLETS (5) largest non-pool wallets of
   gmgn_holder_pnl.json with no GMGN cost basis (avg_cost missing or not a number above 0) or with GMGN's transfer_in tag,
   then every non-infrastructure wallet above ABOVE_PCT (5%) of supply (holders.json top_holders and the GMGN rows), at most
   MAX_WALLETS (6) in all; pools (GMGN addr_type 2), holders.json infrastructure rows and pool_addresses are never targets
   (the same rows exit_overhang.py removes). The rest are saved with their share as not read (cap).
2. Per wallet, in a bounded pool of MAX_WORKERS with one shared 429 pause: its token accounts of THIS mint
   (getTokenAccountsByOwner with a mint filter, base64, the first 72 bytes: mint, owner, amount; decoded by quote_curves.py's
   token_accounts, imported), then one getSignaturesForAddress page (newest to oldest, at most 1,000) of each of its largest
   MAX_TOKEN_ACCOUNTS (2) token accounts, then getTransaction (jsonParsed) for its oldest successful transactions, up to
   MAX_TRANSACTIONS (3), at most CALLS_PER_WALLET (5) calls per wallet. getTransaction asks for maxSupportedTransactionVersion
   1 through create_slot.py's transaction_payload (imported): the cached getTransaction docs (helius.pages getTransaction.md)
   say 1 returns legacy, v0 and v1 transactions, and the hand read of 2026-10-25 met v1 transactions that 0 refused (-32015).
3. Each transaction read: the change of the wallet's balance of this mint (post minus pre token balances, by create_slot.py's
   token_deltas, imported); for an incoming change, every sender (an owner whose balance of this mint fell in that transaction,
   with the amount), the signers, the fee payer, the time and the signature, and whether a plain spl-token transfer or
   transferChecked instruction credited its token account at the top level (kind "transfer") or inside a program's
   instruction ("program_transfer"); an outgoing change is recorded with its receivers. Saved per wallet: whether any outgoing
   transfer was seen, whether the history was read to its start (a signature page shorter than 1,000) and whether the whole
   history was read (start reached and every successful transaction read): only then may a block call a transfer the only one.

Cited sources (provider-docs cache, read by hand): current/helius.pages/docs/api-reference/rpc/http/gettokenaccountsbyowner.md
(the mint filter, encoding, dataSlice), getsignaturesforaddress.md, gettransaction.md (maxSupportedTransactionVersion);
current/solana/rpc.md (token balances: accountIndex, mint, owner, uiTokenAmount); current/solana/parsedinstructions.md (Agave
parse_token.rs: transfer and transferChecked info.source, info.destination, info.authority); current/spltoken/layouts.md (token
interface state.rs Account: mint 0, owner 32, amount 64).

Requests (one host, POST JSON-RPC only): api.mainnet-beta.solana.com, https only, path / only (create_slot.py's check_url,
imported), only getTokenAccountsByOwner, getSignaturesForAddress and getTransaction, no header but the content type, sent
through create_slot.py's guarded send_once (imported): no key, no redirects, no environment proxy, MAX_BYTES per answer and a
hard TIMEOUT_S wall-clock limit per attempt. Retry: at most one per request, only after a 429, after its Retry-After when that
is at most RETRY_MAX_WAIT_S (10 s; the public RPC asks for 10 s), RETRY_DEFAULT_WAIT_S (1.5 s) without one, never when it asks
for longer or is unreadable; the wait is one pause for the whole pool (quote_curves.py's SharedPause and PausedOpener,
imported). This file's rpc_call applies the rule itself, from the Retry-After its opener notes on the request (create_slot.py's
own retry has the same 10 s limit since DS-RPC-RETRY-T1). Pace: at
most METHOD_PACE (4) requests of one method per METHOD_WINDOW_S (10 s) for the whole pool, half of quote_curves.py's 8, so both
lanes of the same follow-up wave fit under the public RPC's limit of about 10 per method per 10 s most of the time (live
2026-10-26: x-ratelimit-method-limit 10 for these three methods, refused requests counted, Retry-After 10 on a 429).
quote_curves.MethodPace holds its 8 as a module constant, so this lane keeps its own pace class with the same first-come rule.
Calls per scan: at most MAX_CALLS (30), at most MAX_REQUESTS (60) with the retries; 3 for a wallet whose history is one
transaction, 5 for most (measured 2026-10-27 on 10 saved scans: 226 calls over 50 wallets, about 4.5 per wallet, 41 of the 50
at the cap of 5; at most 25 calls and 26 requests in one scan).
Worst-case wall time: two rounds of 3 wallets, each at most 5 calls one after another (each read needs the one before it), each
at most about 70 s (30 s, a retry wait of at most 10 s, 30 s), plus the pace (at most about 10 s per method): about 12 minutes; a
few seconds to about half a minute when the RPC answers.

PRESENTATION ONLY: exit_overhang.py --present joins these reads with this token's dev wallets offline (a dev-sent bag counts at
zero cost, owner decision of 2026-10-27), and the synthesis prints this lane's block with --present; this file is never an
engine input and changes no verdict, flag or threshold. It saves and prints only addresses, signatures, slots, times, numbers
and fixed phrases (no provider text; no memo or log message is kept).

Collector: wallet_rpc_reads.py <MINT> --out <RUN> [--workers N] reads its targets from <RUN>/gmgn_holder_pnl.json and
<RUN>/holders.json, writes <RUN>/followup/wallet_rpc_reads.json and prints one line: ok (...), empty (...) or unavailable
(<reason>; ...). Exit 0 whenever the file was saved; exit 2 for a bad mint, --workers or --out.
Synthesis (offline, no network): wallet_rpc_reads.py --present <RUN> also reads <RUN>/followup/create_slot_trace.json (this
token's dev wallets, through quote_curves.py's this_token_dev). Standard library only; Python >= 3.10.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import datetime as dt
import json
import math
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import create_slot as cs  # noqa: E402  (guarded transport, address checks, payloads, token deltas, by import)
import quote_curves as qc  # noqa: E402  (token-account decoding, the shared 429 pause and the paused opener, by import)

HOST = cs.HOST
RPC_ENDPOINT = cs.RPC_ENDPOINT
ALLOWED_METHODS = ("getTokenAccountsByOwner", "getSignaturesForAddress", "getTransaction")
NO_BASIS_WALLETS = 5             # the largest non-pool wallets with no GMGN cost basis or GMGN's transfer_in tag
ABOVE_PCT = 5.0                  # plus every non-infrastructure wallet above this share of supply
MAX_WALLETS = 6                  # wallets read per scan, in all
MAX_TOKEN_ACCOUNTS = 2           # token accounts of this mint whose signature page is read, the largest first
MAX_TRANSACTIONS = 3             # the oldest successful transactions read per wallet
CALLS_PER_WALLET = 5             # 1 token-account read + signature pages + transactions, never more
MAX_CALLS = MAX_WALLETS * CALLS_PER_WALLET
MAX_REQUESTS = 2 * MAX_CALLS
MAX_WORKERS = 3                  # wallets read at the same time
MAX_BYTES = cs.MAX_BYTES
TIMEOUT_S = cs.TIMEOUT_S
METHOD_WINDOW_S = 10.0           # the public RPC's per-method window (live 2026-10-26: 10 per 10 s for these methods)
METHOD_PACE = 4                  # this lane sends at most 4 of one method per window; quote_curves.py sends at most 8
RETRY_MAX_WAIT_S = 10.0          # retry a 429 once when its Retry-After ends this soon (the public RPC asks for 10 s)
RETRY_DEFAULT_WAIT_S = cs.RETRY_DEFAULT_WAIT_S
SIGNATURE_PAGE = cs.SIGNATURE_PAGE
OUT_DIR = "followup"
OUT_FILE = "wallet_rpc_reads.json"
SCHEMA = "holder-scan-wallet-rpc-reads/1"
GMGN_FILE = "gmgn_holder_pnl.json"
GMGN_SCHEMA = "holder-scan-gmgn-holder-pnl/1"
HOLDERS_FILE = "holders.json"
POOL_ADDR_TYPE = 2               # GMGN addr_type 2 = DEX pool or exchange
TRANSFER_TYPES = ("transfer", "transferChecked")
NOTE_ATTR = "wallet_rpc_reads_429"

INDEPENDENCE_NOTE = "public Solana RPC, no key, free"
CANNOT_SEE = (f"only the wallets this scan's saved rows name (the {NO_BASIS_WALLETS} largest non-pool wallets with no GMGN cost basis or GMGN's "
              f"transfer_in tag, plus non-infrastructure wallets above {ABOVE_PCT:g}% of supply; at most {MAX_WALLETS} per scan) and only their "
              f"token accounts of this mint at read time (a closed token account is not read); one page of at most {SIGNATURE_PAGE:,} signatures "
              f"per token account and at most {MAX_TRANSACTIONS} of its oldest successful transactions, so a longer history or a later transfer "
              "is not read (each line says when); a sender is an owner whose balance of this token fell in the same transaction, so tokens "
              "routed through a program account show that program account; a dev that sends from a second wallet is another sender here, "
              "not this token's dev; who controls a wallet; one read at read time")
PRESENTATION_NOTE = ("presentation only: where the biggest wallets without a buy price got their tokens; never an engine input, never changes "
                     "a FLAG, verdict or threshold and never counts toward NO_ALARM; nothing seen here is an all-clear")


# ----------------------------------------------------------------------------- small validated readers


_int, _dict, _list = cs._int, cs._dict, qc._list
is_address, is_signature, off_curve = cs.is_address, cs.is_signature, cs.off_curve


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ----------------------------------------------------------------------------- request (this file's own layer)


def build_request(payload: dict[str, Any]) -> urllib.request.Request:
    """A POST of one JSON-RPC payload whose method is one of this lane's three; no header but the content type."""
    cs.check_url(RPC_ENDPOINT)
    if payload.get("method") not in ALLOWED_METHODS:
        raise cs.Failure("method_not_allowlisted")
    request = urllib.request.Request(RPC_ENDPOINT, data=json.dumps(payload, separators=(",", ":")).encode("utf-8"), method="POST")
    request.add_header("Content-Type", "application/json")
    return request


def token_accounts_payload(owner: str, mint: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": "getTokenAccountsByOwner",
            "params": [owner, {"mint": mint}, {"encoding": "base64", "commitment": "confirmed",
                                               "dataSlice": {"offset": 0, "length": qc.TOKEN_SLICE_BYTES}}]}


def default_opener() -> urllib.request.OpenerDirector:
    """create_slot.py's opener: no environment proxy, no redirects, default TLS verification."""
    return cs.default_opener()


class NotedOpener:
    """The opener of one request, plus a note of a 429's Retry-After on the request itself (create_slot.send_once reduces a
    429 to a fixed code; this lane reads the wait itself, up to RETRY_MAX_WAIT_S, the same 10 s as create_slot.py since
    DS-RPC-RETRY-T1)."""

    def __init__(self, opener: Any) -> None:
        self._opener = opener

    def open(self, request: Any, timeout: float | None = None) -> Any:
        try:
            response = self._opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                setattr(request, NOTE_ATTR, getattr(exc, "headers", None))
            raise
        if getattr(response, "status", 200) == 429:
            setattr(request, NOTE_ATTR, getattr(response, "headers", None))
        return response


def retry_wait(headers: Any) -> float | None:
    """The wait before the one retry after a 429: its Retry-After seconds when they end within RETRY_MAX_WAIT_S,
    RETRY_DEFAULT_WAIT_S without one; None (no retry) when it asks for longer or is unreadable."""
    raw = headers.get("Retry-After") if headers is not None and hasattr(headers, "get") else None
    if raw is None:
        return RETRY_DEFAULT_WAIT_S
    text = str(raw).strip()
    if not re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,3})?", text):
        return None
    wait = max(0.5, float(text))
    return wait if wait <= RETRY_MAX_WAIT_S else None


def rpc_call(payload: dict[str, Any], opener: Any, *, monotonic: Callable[[], float], sleep: Callable[[float], None]) -> dict[str, Any]:
    """One JSON-RPC request through create_slot.py's guarded send_once, plus at most one retry after a 429 (this lane's 10 s
    rule). Returns {method, result, attempts, reason, http_status, rpc_error_code, bytes}, the shape of create_slot.rpc_call;
    never raises. A JSON-RPC error answer is rpc_error with its numeric code only (its message is not kept)."""
    out: dict[str, Any] = {"method": payload.get("method"), "result": None, "attempts": 0, "reason": None, "http_status": None,
                           "rpc_error_code": None, "bytes": 0}
    for attempt in (1, 2):
        out["attempts"] = attempt
        request = None
        try:
            request = build_request(payload)
            body = cs.send_once(request, NotedOpener(opener), monotonic=monotonic, max_bytes=MAX_BYTES)
            out.update(reason=None, http_status=200, bytes=out["bytes"] + len(body))
        except cs.Failure as failure:
            out.update(reason=failure.reason, http_status=failure.http_status)
            wait = retry_wait(getattr(request, NOTE_ATTR, None)) if failure.reason == "rate_limited" else None
            if attempt == 1 and wait is not None:
                sleep(wait)
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


class MethodPace:
    """At most `limit` requests of one JSON-RPC method in any `window` seconds, for the whole pool: each request takes the
    earliest free place in its method's window (first come, first served) and waits until then."""

    def __init__(self, monotonic: Callable[[], float], sleep: Callable[[float], None], limit: int = METHOD_PACE, window: float = METHOD_WINDOW_S) -> None:
        self._monotonic, self._sleep, self.limit, self.window = monotonic, sleep, limit, window
        self._lock = threading.Lock()
        self._sent: dict[str, collections.deque[float]] = {}
        self.waits = 0

    def take(self, method: str) -> None:
        with self._lock:
            now = self._monotonic()
            sent = self._sent.setdefault(method, collections.deque())
            while sent and sent[0] <= now - self.window:
                sent.popleft()
            at = max(now, sent[-1] if sent else now, sent[-self.limit] + self.window if len(sent) >= self.limit else now)
            sent.append(at)
            if at > now:
                self.waits += 1
        if at > now:
            self._sleep(at - now)


# ----------------------------------------------------------------------------- decoding (cited layouts, validated)


def token_accounts(result: Any, owner: str, mint: str) -> tuple[list[dict[str, Any]], str | None]:
    """A getTokenAccountsByOwner answer (mint filter) -> ([{token_account, mint, amount_raw}], token program). Raises
    cs.Mismatch on any account that is not a token account of THIS mint owned by `owner` (quote_curves.token_accounts checks
    the program, the slice and the owner)."""
    rows = result.get("value") if isinstance(result, dict) else None
    if not isinstance(rows, list):
        raise cs.Mismatch("token_accounts_shape")
    if not rows:
        return [], None
    program = _dict(_dict(rows[0]).get("account")).get("owner")
    if program not in qc.TOKEN_PROGRAMS:
        raise cs.Mismatch("token_accounts_shape")
    found = qc.token_accounts(result, owner, program)
    if any(a["mint"] != mint for a in found) or len({a["token_account"] for a in found}) != len(found):
        raise cs.Mismatch("token_account_mint")
    return found, program


def signature_page(page: Any) -> list[dict[str, Any]]:
    """A getSignaturesForAddress page (newest to oldest) -> [{signature, slot, block_time, ok, position}]; Mismatch on a
    page that is not a list of at most SIGNATURE_PAGE valid entries in slot order."""
    if not isinstance(page, list) or len(page) > SIGNATURE_PAGE:
        raise cs.Mismatch("signatures_shape")
    out, last = [], None
    for position, entry in enumerate(page):
        signature, slot = _dict(entry).get("signature"), _int(_dict(entry).get("slot"))
        if not is_signature(signature) or slot is None or (last is not None and slot > last):
            raise cs.Mismatch("signatures_shape")
        last = slot
        out.append({"signature": signature, "slot": slot, "block_time": _int(entry.get("blockTime")), "ok": entry.get("err") is None, "position": position})
    return out


def _transfer_kind(tx: dict[str, Any], meta: dict[str, Any], accounts: set[str], side: str) -> str:
    """'transfer' when a top-level spl-token transfer or transferChecked moves this wallet's token account (side 'destination'
    for incoming, 'source' for outgoing), 'program_transfer' when one inside another program's instruction does, else 'other'
    (parse_token.rs: info.source, info.destination)."""
    def moves(ix: Any) -> bool:
        parsed = _dict(ix).get("parsed")
        return (_dict(ix).get("program") == "spl-token" and isinstance(parsed, dict) and parsed.get("type") in TRANSFER_TYPES
                and _dict(parsed.get("info")).get(side) in accounts)

    if any(moves(ix) for ix in _list(_dict(tx.get("message")).get("instructions"))):
        return "transfer"
    if any(moves(ix) for group in _list(meta.get("innerInstructions")) for ix in _list(_dict(group).get("instructions"))):
        return "program_transfer"
    return "other"


def _party(key: str, amount: int) -> dict[str, Any]:
    if key.startswith("account:"):
        return {"owner": None, "token_account": key.removeprefix("account:"), "amount_raw": amount}
    return {"owner": key, "token_account": None, "amount_raw": amount}


def read_transaction(result: Any, signature: str, slot: int | None, mint: str, wallet: str, accounts: set[str], now: float) -> dict[str, Any]:
    """A getTransaction answer (jsonParsed) -> what it did to this wallet's balance of this mint. Raises cs.Mismatch(check)."""
    if not isinstance(result, dict):
        raise cs.Mismatch("not_found")
    tx_slot, block_time, meta, tx = _int(result.get("slot")), _int(result.get("blockTime")), result.get("meta"), result.get("transaction")
    if tx_slot is None or not isinstance(meta, dict) or not isinstance(tx, dict):
        raise cs.Mismatch("transaction_shape")
    if block_time is not None and not cs.MIN_TS <= block_time <= now + cs.CLOCK_SLACK_S:
        raise cs.Mismatch("block_time")
    signatures = tx.get("signatures")
    if not isinstance(signatures, list) or not signatures or signatures[0] != signature:
        raise cs.Mismatch("signature")
    if slot is not None and tx_slot != slot:
        raise cs.Mismatch("slot")
    if meta.get("err") is not None:
        raise cs.Mismatch("transaction_failed")
    keys = cs._keys(_dict(tx.get("message")).get("accountKeys"))
    if not keys[0]["signer"]:
        raise cs.Mismatch("account_keys")
    deltas, decimals, _pre, _post = cs.token_deltas(meta, keys, mint)
    if len(decimals) > 1:
        raise cs.Mismatch("token_balances")
    own = {wallet} | {f"account:{a}" for a in accounts}
    change = sum(v for k, v in deltas.items() if k in own)
    direction = "in" if change > 0 else "out" if change < 0 else "none"
    senders = [_party(k, -v) for k, v in sorted(deltas.items()) if v < 0 and k not in own] if direction == "in" else []
    receivers = [_party(k, v) for k, v in sorted(deltas.items()) if v > 0 and k not in own] if direction == "out" else []
    kind = _transfer_kind(tx, meta, accounts, "destination" if direction == "in" else "source") if direction != "none" else None
    return {"signature": signature, "slot": tx_slot, "block_time": block_time, "direction": direction, "amount_raw": abs(change),
            "decimals": next(iter(decimals)) if decimals else None, "kind": kind, "senders": senders,
            "counterparty_owner": senders[0]["owner"] if len(senders) == 1 else None, "receivers": receivers,
            "signers": [k["pubkey"] for k in keys if k["signer"]], "fee_payer": keys[0]["pubkey"]}


# ----------------------------------------------------------------------------- targets from the saved rows


def collect_targets(run: Path, mint: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str]]:
    """(targets, wallets left out by the caps, how each saved file was read). Targets: the NO_BASIS_WALLETS largest non-pool
    GMGN wallets without a cost basis or with the transfer_in tag, then the non-infrastructure wallets above ABOVE_PCT, at
    most MAX_WALLETS; shares in percent (GMGN's, else holders.json's), unknown shares last and never 0."""
    read: dict[str, str] = {}
    holders = _read_json(run / HOLDERS_FILE)
    if not (run / HOLDERS_FILE).exists():
        read[HOLDERS_FILE] = "missing"
    elif not isinstance(holders, dict) or not isinstance(holders.get("top_holders"), list):
        read[HOLDERS_FILE] = "unreadable"
    elif holders.get("mint") != mint:
        read[HOLDERS_FILE] = "other_mint"
    else:
        read[HOLDERS_FILE] = "read"
    gmgn = _read_json(run / GMGN_FILE)
    if not (run / GMGN_FILE).exists():
        read[GMGN_FILE] = "missing"
    elif not (isinstance(gmgn, dict) and gmgn.get("schema") == GMGN_SCHEMA and isinstance(gmgn.get("rows"), list)):
        read[GMGN_FILE] = "unreadable"
    elif gmgn.get("mint") != mint:
        read[GMGN_FILE] = "other_mint"
    elif gmgn.get("status") != "ok":
        read[GMGN_FILE] = "not_ok"
    else:
        read[GMGN_FILE] = "read"
    if read[HOLDERS_FILE] != "read":
        return [], [], read
    excluded, top = {mint}, {}
    for row in holders["top_holders"]:
        row = _dict(row)
        wallet, share = row.get("wallet"), _number(row.get("share_pct"))
        if not is_address(wallet) or wallet in top:
            continue
        top[wallet] = share if share is not None and 0 <= share <= 100 else None
        if row.get("infrastructure") is True:
            excluded.add(wallet)
    excluded |= {a for a in _list(holders.get("pool_addresses")) if is_address(a)}
    found: dict[str, dict[str, Any]] = {}
    no_basis: list[str] = []
    if read[GMGN_FILE] == "read":
        for row in gmgn["rows"]:
            row = _dict(row)
            address = row.get("address")
            if not is_address(address) or address in found or address in excluded:
                continue
            addr_type = row.get("addr_type")
            if isinstance(addr_type, int) and not isinstance(addr_type, bool) and addr_type == POOL_ADDR_TYPE:
                excluded.add(address)
                continue
            share = _number(row.get("amount_percentage"))
            cost = _number(row.get("avg_cost"))
            why = ([] if cost is not None and cost > 0 else ["no GMGN cost basis"]) + (["GMGN transfer_in tag"] if row.get("transfer_in") is True else [])
            found[address] = {"address": address, "share_pct": share * 100 if share is not None and 0 <= share <= 1 else None,
                              "share_source": "gmgn_holder_pnl.json", "why": why}
            if why:
                no_basis.append(address)
    for wallet, share in top.items():
        if wallet in excluded:
            continue
        if wallet not in found:
            found[wallet] = {"address": wallet, "share_pct": share, "share_source": "holders.json", "why": []}
        elif found[wallet]["share_pct"] is None and share is not None:
            found[wallet].update(share_pct=share, share_source="holders.json")

    def order(address: str) -> tuple[bool, float]:
        share = found[address]["share_pct"]
        return share is None, -(share or 0.0)

    chosen = sorted(no_basis, key=order)  # stable: GMGN's order on equal shares
    above = sorted((a for a, t in found.items() if (t["share_pct"] or 0.0) > ABOVE_PCT), key=order)
    for address in above:
        found[address]["why"].append(f"above {ABOVE_PCT:g}% of supply")
    targets = list(dict.fromkeys(chosen[:NO_BASIS_WALLETS] + above))
    rest = [{**found[a], "status": "not_read", "reason": "wallet_cap"} for a in targets[MAX_WALLETS:] + [a for a in chosen[NO_BASIS_WALLETS:] if a not in targets]]
    return [found[a] for a in targets[:MAX_WALLETS]], rest, read


# ----------------------------------------------------------------------------- one wallet


def read_wallet(target: dict[str, Any], mint: str, opener: Any, *, now: Callable[[], float], monotonic: Callable[[], float],
                sleep: Callable[[float], None]) -> dict[str, Any]:
    """Its token accounts of this mint, one signature page each (at most MAX_TOKEN_ACCOUNTS), then its oldest successful
    transactions (at most MAX_TRANSACTIONS; at most CALLS_PER_WALLET calls in all). Never raises: a failed read is
    unavailable with a fixed code, a failed transaction read leaves the wallet partial."""
    calls: list[dict[str, Any]] = []
    entry = {**target, "status": "unavailable", "reason": None, "check": None, "read_reason": None, "rpc_error_code": None, "token_program": None,
             "token_accounts": [], "token_accounts_not_read": 0, "signatures_seen": 0, "successful_signatures": 0, "history_start_reached": None,
             "transactions_read": 0, "transactions_not_read": 0, "not_read_reasons": [], "complete": False, "events": [], "incoming": 0,
             "outgoing_seen": False, "calls": calls}

    def fail(reason: str, check: str | None = None, got: dict[str, Any] | None = None) -> dict[str, Any]:
        entry.update(status="unavailable", reason=reason, check=check)
        if got is not None:
            entry.update(read_reason=got.get("reason"), rpc_error_code=got.get("rpc_error_code"))
        return entry

    def call(payload: dict[str, Any]) -> dict[str, Any]:
        got = rpc_call(payload, opener, monotonic=monotonic, sleep=sleep)
        calls.append(cs._call_facts(got))
        return got

    try:
        wallet = target["address"]
        got = call(token_accounts_payload(wallet, mint))
        if got["reason"] is not None:
            return fail("token_accounts_read_failed", None, got)
        try:
            held, program = token_accounts(got["result"], wallet, mint)
        except cs.Mismatch as exc:
            return fail("layout_mismatch", exc.check)
        entry["token_program"] = program
        held.sort(key=lambda a: (-a["amount_raw"], a["token_account"]))
        if not held:
            entry.update(status="read", reason="no_token_account")
            return entry
        reading = held[:MAX_TOKEN_ACCOUNTS]
        entry["token_accounts_not_read"] = len(held) - len(reading)
        successful: dict[str, dict[str, Any]] = {}
        for account in reading:
            got = call(cs.signatures_payload(account["token_account"], None))
            if got["reason"] is not None:
                return fail("signatures_read_failed", None, got)
            try:
                page = signature_page(got["result"])
            except cs.Mismatch as exc:
                return fail("signatures_read_failed", exc.check)
            ok = [s for s in page if s["ok"]]
            entry["token_accounts"].append({"token_account": account["token_account"], "amount_raw": account["amount_raw"], "signatures_seen": len(page),
                                            "successful": len(ok), "start_reached": len(page) < SIGNATURE_PAGE})
            entry["signatures_seen"] += len(page)
            for s in ok:
                successful.setdefault(s["signature"], s)
        entry["successful_signatures"] = len(successful)
        entry["history_start_reached"] = all(a["start_reached"] for a in entry["token_accounts"])
        accounts = {a["token_account"] for a in held}
        oldest = sorted(successful.values(), key=lambda s: (s["slot"], -s["position"], s["signature"]))
        chosen = oldest[:max(0, min(MAX_TRANSACTIONS, CALLS_PER_WALLET - len(calls)))]
        for s in chosen:
            got = call(cs.transaction_payload(s["signature"]))
            if got["reason"] is not None:
                entry["transactions_not_read"] += 1
                entry["not_read_reasons"].append(got["reason"])
                entry.update(read_reason=got["reason"], rpc_error_code=got.get("rpc_error_code"))
                continue
            try:
                event = read_transaction(got["result"], s["signature"], s["slot"], mint, wallet, accounts, now())
            except cs.Mismatch as exc:
                entry["transactions_not_read"] += 1
                entry["not_read_reasons"].append(exc.check)
                entry["check"] = exc.check
                continue
            entry["events"].append(event)
        entry["transactions_read"] = len(entry["events"])
        entry["incoming"] = sum(1 for e in entry["events"] if e["direction"] == "in")
        entry["outgoing_seen"] = any(e["direction"] == "out" for e in entry["events"])
        entry["complete"] = bool(entry["history_start_reached"] and not entry["token_accounts_not_read"]
                                 and entry["transactions_read"] == entry["successful_signatures"] and not entry["transactions_not_read"])
        if entry["transactions_not_read"]:
            if not entry["events"]:
                return fail("transaction_read_failed", entry["check"])
            entry.update(status="partial", reason="transaction_read_failed")
            return entry
        entry.update(status="read", reason=None)
        return entry
    except Exception:  # noqa: BLE001 - an answer the checks did not foresee: a fixed code, never a crash
        return fail("parse_error")


# ----------------------------------------------------------------------------- collect


def _base(mint: str, fetched_at: str, workers: int) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "lane": "wallet_rpc_reads", "mint": mint, "status": "unavailable", "reason": None, "fetched_at": fetched_at,
        "request": {"host": HOST, "path": "/", "methods": list(ALLOWED_METHODS), "keys": "none", "calls": [], "requests_sent": 0, "bytes_received": 0,
                    "max_calls": MAX_CALLS, "max_requests": MAX_REQUESTS, "max_wallets": MAX_WALLETS, "calls_per_wallet": CALLS_PER_WALLET,
                    "workers": workers, "method_pace": f"at most {METHOD_PACE} requests of one method per {METHOD_WINDOW_S:.0f} s",
                    "retry": f"at most one per request, only after a 429: its Retry-After up to {RETRY_MAX_WAIT_S:.0f} s, {RETRY_DEFAULT_WAIT_S} s without one",
                    "get_transaction": "jsonParsed, maxSupportedTransactionVersion 1 (create_slot.transaction_payload)",
                    "rate_limit_pauses": 0, "pace_waits": 0},
        "sources": {"rpc": "provider-docs current/helius.pages/docs/api-reference/rpc/http/gettokenaccountsbyowner.md (mint filter, dataSlice), "
                           "getsignaturesforaddress.md, gettransaction.md (maxSupportedTransactionVersion); current/solana/rpc.md (token balances)",
                    "parsed": "provider-docs current/solana/parsedinstructions.md (parse_token.rs transfer and transferChecked: source, destination, authority)",
                    "spl_token": "provider-docs current/spltoken/layouts.md (token interface state.rs Account: mint, owner, amount)"},
        "targets_from": {}, "targets": 0, "wallets": [], "not_read": [],
        "presentation_only": True, "note": PRESENTATION_NOTE, "cannot_see": CANNOT_SEE,
    }


def collect_wallet_reads(
    mint: str,
    run: Path,
    *,
    workers: int = MAX_WORKERS,
    opener: Any | None = None,
    now: Callable[[], float] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """Targets from the saved rows, then at most MAX_WALLETS wallets read in a bounded pool of `workers`. Returns the
    wallet_rpc_reads.json result; never raises for provider or transport failures."""
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    workers = max(1, min(MAX_WORKERS, workers))
    result = _base(mint, _iso(now()), workers)
    calls: list[dict[str, Any]] = result["request"]["calls"]
    pause, pace = qc.SharedPause(monotonic, sleep), MethodPace(monotonic, sleep)

    def finish(status: str, reason: str | None = None) -> dict[str, Any]:
        result.update(status=status, reason=reason, fetched_at=_iso(now()))
        result["request"]["requests_sent"] = sum(c["attempts"] for c in calls)
        result["request"]["bytes_received"] = sum(c["bytes"] for c in calls)
        result["request"]["rate_limit_pauses"] = pause.pauses
        result["request"]["pace_waits"] = pace.waits
        return result

    targets, rest, read = collect_targets(run, mint)
    result.update(targets_from=read, targets=len(targets) + len(rest), not_read=rest)
    if not targets:
        return finish("empty", "no_targets") if read.get(HOLDERS_FILE) == "read" else finish("unavailable", "holders_not_read")
    shared = qc.PausedOpener(opener or default_opener(), pause, pace)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="wallet-rpc-reads") as pool:  # never one by one
        futures = [pool.submit(read_wallet, t, mint, shared, now=now, monotonic=monotonic, sleep=pause.sleep) for t in targets]
        done = [f.result() for f in futures]
    for entry in done:
        wallet_calls = entry.pop("calls")
        entry["calls"] = len(wallet_calls)
        calls.extend({**c, "wallet": entry["address"]} for c in wallet_calls)
    result["wallets"] = done
    if not any(w["status"] in ("read", "partial") for w in done):
        first = done[0]
        return finish("unavailable", first["read_reason"] if first.get("read_reason") in KNOWN_CODES else first["reason"])
    return finish("ok")


def status_line(result: dict[str, Any]) -> str:
    made, sent = len(result["request"]["calls"]), result["request"]["requests_sent"]
    calls = f"{made} call{'s' if made != 1 else ''} to the public Solana RPC" if made else "no RPC call sent"
    if sent > made:  # Repair R1: requests named as requests (a retry after a 429 is a second request of the same call), as the block says
        calls += f", {sent} requests with retries"
    if result["status"] == "empty":
        return f"empty (no target wallet among this scan's saved rows; {calls})"
    if result["status"] != "ok":
        return f"unavailable ({result['reason']}; {calls})"
    wallets = result["wallets"]
    read = sum(1 for w in wallets if w["status"] in ("read", "partial"))
    failed = sum(1 for w in wallets if w["status"] == "unavailable")
    incoming = sum(1 for w in wallets if w.get("incoming"))
    return (f"ok ({len(wallets)} wallet{'s' if len(wallets) != 1 else ''} read: {read} read, {failed} unavailable, {incoming} with an incoming "
            f"transfer seen, {len(result['not_read'])} not read (caps); {calls})")


# ----------------------------------------------------------------------------- presentation (synthesis, offline)


KNOWN_CODES = frozenset(qc.KNOWN_CODES | {
    "no_targets", "token_accounts_read_failed", "token_accounts_shape", "token_account_owner", "token_account_mint", "no_token_account",
    "signatures_read_failed", "signatures_shape", "transaction_read_failed", "wallet_cap", "parse_error",
})
KIND_TEXT = {"transfer": "a plain transfer", "program_transfer": "moved inside a program's instruction", "other": "no transfer instruction seen"}


def _code(value: Any) -> str:
    return value if isinstance(value, str) and value in KNOWN_CODES else "unrecognized code"


def _valid_saved(data: Any) -> bool:
    return (isinstance(data, dict) and data.get("schema") == SCHEMA and data.get("status") in ("ok", "empty", "unavailable")
            and data.get("presentation_only") is True and is_address(data.get("mint")))


def _party_text(p: dict[str, Any], dev: list[str]) -> str:
    owner = p.get("owner")
    if is_address(owner):
        tag = "this token's dev" if owner in dev else "a program account" if off_curve(owner) else "another wallet"
        return f"{owner} ({tag})"
    return f"token account {qc._addr(p.get('token_account'))} (owner not recorded)"


def _amount(raw: Any, decimals: Any) -> str:
    """A token amount cut toward zero to 2 decimals (create_slot.py's _tokens); a positive amount under 0.01 reads 'under 0.01'."""
    text = cs._tokens(raw, decimals)
    return "under 0.01" if text == "0.00" and (_int(raw) or 0) > 0 else text


def _event_text(e: dict[str, Any], dev: list[str]) -> str:
    amount = _amount(e.get("amount_raw"), e.get("decimals"))
    when = qc._utc(e.get("block_time"))
    kind = KIND_TEXT.get(e.get("kind")) if isinstance(e.get("kind"), str) else None
    signers = ", ".join(qc._addr(s) for s in _list(e.get("signers"))) or "unknown"
    tail = f"{kind or 'kind not read'}, signed by {signers}, fee payer {qc._addr(e.get('fee_payer'))}, tx {qc._sig(e.get('signature'))}"
    if e.get("direction") == "in":
        senders = [_party_text(_dict(p), dev) for p in _list(e.get("senders"))]
        return f"in: {amount} tokens from {', '.join(senders) or 'no sender whose balance fell (minted or unrecorded)'} at {when}, {tail}"
    if e.get("direction") == "out":
        to = [_party_text(_dict(p), dev) for p in _list(e.get("receivers"))]
        return f"out: {amount} tokens to {', '.join(to) or 'no receiver recorded'} at {when}, {tail}"
    return f"no change of its balance in tx {qc._sig(e.get('signature'))} at {when}"


def _history(w: dict[str, Any]) -> str:
    read, seen = _int(w.get("transactions_read")), _int(w.get("successful_signatures"))
    if w.get("complete") is True:
        return f"its whole token-account history was read ({read} transaction{'s' if read != 1 else ''})"
    if w.get("history_start_reached") is not True:
        return (f"history not read to its start (the one page read holds {_int(w.get('signatures_seen'))} signatures, the newest; older ones "
                f"are not seen): its {read} oldest successful transactions on that page were read")
    missing = _int(w.get("token_accounts_not_read"))
    extra = f"; {missing} more token account{'s' if missing != 1 else ''} not read (cap of {MAX_TOKEN_ACCOUNTS})" if missing else ""
    return f"history read in part: the {read} oldest of {seen if seen is not None else 'its'} successful transactions{extra}"


def _wallet_line(w: dict[str, Any], dev: list[str]) -> str:
    share = qc._pct(w.get("share_pct"))
    why = ", ".join(x for x in _list(w.get("why")) if isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_ %.]{1,40}", x))
    head = f"  {qc._addr(w.get('address'))} ({share + ' of supply' if share else 'share of supply not read'}{'; ' + why if why else ''})"
    status = w.get("status")
    if status == "unavailable":
        codes = _code(w.get("reason")) + (f", {_code(w.get('check'))}" if w.get("check") else "") + (f", {_code(w.get('read_reason'))}" if w.get("read_reason") else "")
        if _int(w.get("rpc_error_code")) is not None:
            codes += f" {w['rpc_error_code']}"
        return f"{head}: unavailable ({codes}); nothing read"
    if w.get("reason") == "no_token_account":
        return f"{head}: no token account of this mint at read time (it may have sold and closed it after the scan); history not read"
    events = [_event_text(_dict(e), dev) for e in _list(w.get("events")) if isinstance(e, dict)]
    out = "an outgoing transfer was seen" if w.get("outgoing_seen") is True else "no outgoing transfer seen in the transactions read"
    failed = _int(w.get("transactions_not_read"))
    part = f"; {failed} transaction{'s' if failed != 1 else ''} not read (" + ", ".join(_code(r) for r in _list(w.get("not_read_reasons"))) + ")" if failed else ""
    return f"{head}: {_history(w)}{part}; " + ("; ".join(events) if events else "no transaction read") + f"; {out}"


def present(run: Path) -> list[str]:
    """The block of this lane. Reads only saved files (followup/wallet_rpc_reads.json, followup/create_slot_trace.json): no
    network, no key. A missing, foreign or malformed file or value reads as not read, never as a crash."""
    path = run / OUT_DIR / OUT_FILE
    data = _read_json(path)
    result = data if _valid_saved(data) else None
    head = f"Single wallets read on-chain (follow-up lane wallet_rpc_reads; {INDEPENDENCE_NOTE})"
    if result is None:
        return [f"{head}: not read ({OUT_DIR}/{OUT_FILE} " + ("missing" if not path.exists() else "unreadable") + ")"]
    try:
        dev, dev_reason = qc.this_token_dev(run, result["mint"])
        state = {"ok": "read", "empty": "read", "unavailable": "unavailable"}[result["status"]]
        reason = f" ({_code(result.get('reason'))})" if result["status"] == "unavailable" else ""
        age = qc._age_min(result.get("fetched_at"))
        lines = [f"{head}: {state}{reason}" + (f"; data age {age:.0f} min" if age is not None else "; data age unknown")
                 + f"; {qc._calls_text(_dict(result.get('request')))}"]
    except Exception:  # noqa: BLE001 - a damaged header is not read, never a crash
        return [f"{head}: not read (saved values unreadable)", f"  {PRESENTATION_NOTE}"]
    try:
        wallets = [w for w in _list(result.get("wallets")) if isinstance(w, dict)]
        capped = [w for w in _list(result.get("not_read")) if isinstance(w, dict)]
        if result["status"] == "empty":
            lines.append("  no target wallet among this scan's saved rows (no non-pool wallet without a GMGN cost basis or with GMGN's transfer_in tag, "
                         f"none above {ABOVE_PCT:g}% of supply); what was seen, not an all-clear")
        elif wallets:
            lines.append(f"  {len(wallets)} wallet{'s' if len(wallets) != 1 else ''} read (the {NO_BASIS_WALLETS} largest non-pool wallets without a GMGN cost "
                         f"basis or with GMGN's transfer_in tag, plus non-infrastructure wallets above {ABOVE_PCT:g}%; at most {MAX_WALLETS})")
            lines.append(f"  This token's dev (create-slot trace): {', '.join(dev)}" if dev else f"  This token's dev not known ({dev_reason}): senders are listed, none is matched")
            lines += [_wallet_line(w, dev) for w in wallets]
        if capped:
            lines.append(f"  Not read (caps: {NO_BASIS_WALLETS} without a cost basis, {MAX_WALLETS} in all): {len(capped)} more wallet{'s' if len(capped) != 1 else ''}: "
                         + ", ".join(f"{qc._addr(w.get('address'))} ({qc._pct(w.get('share_pct')) or 'share not read'})" for w in capped))
    except Exception:  # noqa: BLE001 - a damaged file is not read, never a crash
        lines.append("  not read (unreadable entry)")
    lines += [f"  cannot see: {CANNOT_SEE}", f"  {PRESENTATION_NOTE}"]
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read where this scan's biggest wallets without a GMGN buy price got their tokens, over the free "
                                                 f"public Solana RPC (no key; at most {MAX_WALLETS} wallets, {MAX_CALLS} calls, {MAX_WORKERS} at a time; "
                                                 f"bounded: 2 MiB, 30 s, no redirects, no env proxy) and save {OUT_DIR}/{OUT_FILE}; or, with "
                                                 "--present RUN_DIR, print the block offline. Presentation only.")
    parser.add_argument("mint", nargs="?")
    parser.add_argument("--out", metavar="RUN_DIR", help="run folder: targets are read from its gmgn_holder_pnl.json and holders.json")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help=f"wallets read at the same time (1 to {MAX_WORKERS}, default {MAX_WORKERS})")
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
        result = collect_wallet_reads(args.mint, run, workers=args.workers)
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
