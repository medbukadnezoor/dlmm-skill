#!/usr/bin/env python3
"""Transfer graph for dlmm-scan (follow-up lane `transfer_graph`, HS-GRAPH-T1): funding bursts among the top holders, read
from Helius at scan time, and (opt-in, experimental) linked groups. Presentation only.

Default output (owner decision 2026-10-20, "Ship bursts, hold groups (Recommended)"): funding bursts (one wallet paying
10 or more of the holders within 5 min), dust sprays (bursts whose every recipient got under 0.01 SOL), repeated rounds
and the bursts of program accounts and services (never links). Linked groups (`direct`, `via_wallet`,
`via_wallet_pair`, the merged view and the Bubblemaps overlap) need --groups: on 10 live mints (2026-10-20) they matched
Bubblemaps pairs at pooled recall 11.4% and precision 3.1%, so they are experimental. Without --groups stage 3 is skipped:
on every recorded mint it changed no burst and no round (repair round 1, offline), and a scan costs about 6,000 credits
instead of about 12,000. Call C (SOL, newest 100) is read by default for the first 100 holders read (repair round 2):
without it the default missed the 78rn funding bursts and the GezC program-account rounds the recorded data holds.

Why: the free Bubblemaps map is often stale (up to 2 h old on 2026-10-20) and draws nothing for a farm whose pool was
already drained when the map was built (78rn and GezC rugged during the prototype of 2026-10-20). This lane reads the
holders' own transfers and the transfers of their main counterparties, and names linked wallets with full addresses and
the transfer behind each link. A link means "these wallets moved SOL or this token with each other, or with the same
outside wallet": what was seen, never proof of one owner.

Inputs (saved files of the run folder; no other source is read): <RUN>/holders.json from the forensics collector (the
ranked holder list; validated with helius_forensics.load_run_holders), and when present <RUN>/assessment.json
`bubblemaps_members` (the Bubblemaps cluster members that the synthesis's offline assess step resolved to full
addresses) for the overlap table, and <RUN>/followup/pda_identity_reads.json for pools. The app and relayer list is the
data file skills/dlmm-scan/references/transfer_graph_app_wallets.json (each entry with its reason and source).

Stages (all reads are Helius `getTransfersByAddress`, 10 credits each, up to 100 transfers per call; `sortOrder` "asc"
is oldest first, the default is newest first; `amount` and `uiAmount` are strings, so the raw `amount` and `decimals`
are used; `transfer` rows count, and `unwrap` rows whose SOL goes to another wallet):
1. Holders: the top --top (default 250) ordinary holders of holders.json (`infrastructure: false`, on the ed25519
   curve; off-curve rows are skipped and named). Per holder: A = this token, newest 100; B = SOL, oldest 100. C = SOL,
   newest 100, for the first --recent-sol-top holders read (default 100, the prototype's scope; 0 = off; --recent-sol
   reads it for every holder read).
2. Identity and exclusions: Helius batch identity (100 credits per call of up to 100 addresses, at most
   IDENTITY_MAX_ADDRESSES) for the burst senders (and, with --groups, the shared counterparties and the stage-3
   candidates). Never a link:
   a labelled service (SERVICE_RULE), the app and relayer list, an address off the curve, this token's pools and
   infrastructure rows (holders.json, plus pools named by the PDA reads when present), the mint, SOL and wSOL.
3. One hop out (only with --groups): per holder, its counterparties that sent it at least 0.1 SOL or received at least 0.1 SOL from it
   (rows B and C), not services, de-duplicated and ranked by the SOL they moved with the holders; up to --hop-max
   (default 300) of them get SOL oldest 100 + newest 100. Holders that appear in the same counterparty's own transfers
   are linked through it (the step that reproduced 5 of 6 testable Bubblemaps clusters on DKYc in the prototype).
4. Edges, each with its evidence (signature, time, amount, direction, which read found it): `direct` (holder to holder,
   this token or at least 0.001 SOL), `via_wallet` (two holders both moved at least 0.01 SOL, or any amount of this
   token, with the same outside wallet that can link), `via_wallet_pair` (two such outside wallets, both read one hop
   out, that moved at least 0.1 SOL with each other, each linked to holders: the Bubblemaps chain of two linking
   wallets, DKYc cluster 9 in the prototype), `burst` (one wallet that can link sent SOL (at least 0.001) or
   this token to 10 or more of these holders within 5 min; sends that keep coming within 5 min of each other extend
   the burst; never capped; a burst of at least 0.01 SOL, or of this token, is also a via_wallet link of its sender).
   A program account (off the curve, not this token's pool, not on the app list) that pays 10 or more holders SOL
   within 5 min, or a labelled service that pays them SOL or this token, is reported separately and never links; a
   program account paying out this token is almost always another pool's authority filling buys, so it is only counted.
5. Clusters: connected components over direct + via_wallet + via_wallet_pair; burst groups listed separately and also
   merged into a second, marked view; repeated rounds (the same holders paid by several senders) summarised; the overlap with each
   Bubblemaps cluster when assessment.json holds the members.

Budget: --max-credits (default 12,000). The estimate (stage 1: 20 per holder plus 10 per C read, 6,000 for 250 holders
with the default C; identity: the reserve of IDENTITY_MAX_ADDRESSES addresses at 100 per 100; stage 3: 20 per
counterparty; 7,000 in all by default) must fit; --hop-max is lowered first (to 250 with --groups and the default C), and
the run refuses to start when even 0 counterparties do not fit. Every call is charged before it is sent, under one lock
(helius_forensics.Budget), so parallel reads never spend past the cap; a refused charge stops new reads, and the result
is marked RUN STOPPED EARLY with the reason. Credits are reported per stage.

Requests: the analysis engine's HeliusClient (scripts/ha/helius.py: key in the x-api-key header, method allowlist,
host allowlist, https only, size cap, budget lock, batch identity) over its transport, with this lane's opener: no
environment proxy, no redirects, 2 MiB per answer, a hard 30 s wall-clock limit per attempt (open, every read and
close, in a worker thread), at most one retry and only after an HTTP 429 (1 s later; the 429 pauses every worker).
All workers share one pace of at most 6 requests per second (the key and its credits are shared with the live
stop-loss bots). Rate class: `getTransfersByAddress` is a Helius RPC method (mainnet RPC host; the cached docs list
no special limit for it, so the plan's RPC limit applies: 50 requests/s on Developer); batch identity is a Wallet API
call (the DAS & Enhanced group: 10 requests/s on Developer). Every failure is a fixed reason code; the key is never
printed, logged, saved or put in an error, and provider text that echoes it is dropped.

PRESENTATION ONLY: the synthesis prints the block with --present; this file is never an engine input and changes no
verdict, flag or threshold. Linked by on-chain transfers (what was seen), not proof of one owner.

Collector: transfer_graph.py <MINT> --out <RUN> [--groups] [--recent-sol-top N] writes <RUN>/followup/transfer_graph.json and prints one line: ok (...),
empty (...) or unavailable (<reason>; ...). Exit 0 whenever the file was saved (130 after Ctrl-C, with the partial
file saved); exit 2 for a bad mint, option or --out, or a missing or malformed key.
Synthesis (offline, no network, no key): transfer_graph.py --present <RUN> [--groups]. Standard library only; Python >= 3.10.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import decimal
import http.client
import json
import math
import os
import queue
import re
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:  # python -I does not add the script directory
    sys.path.insert(0, str(HERE))

import helius_forensics as hf  # noqa: E402  (Budget, BudgetError, RateGate (through HeliusClient), run_lookups, load_key, load_run_holders)
import provider_words as pw  # noqa: E402  (HS-LABELS-T1: verdict words in provider text; standard library only, no network)
from ha.helius import API_HOST, RPC_HOST, BudgetExhausted, HeliusClient  # noqa: E402
from ha.solana import BURN_ADDRESSES, b58decode, is_on_curve  # noqa: E402
from ha.transport import TransportError  # noqa: E402

SKILL_DIR = HERE.parent
APP_LIST_PATH = SKILL_DIR / "references" / "transfer_graph_app_wallets.json"
APP_LIST_SCHEMA = "holder-scan-transfer-graph-app-wallets/1"
OUT_DIR = "followup"
OUT_FILE = "transfer_graph.json"
SCHEMA = "holder-scan-transfer-graph/1"
KEY_NAME = "HELIUS_API_KEY"

SOL_MINT = "So11111111111111111111111111111111111111111"   # Helius getTransfersByAddress: native SOL
WSOL_MINT = "So11111111111111111111111111111111111111112"  # merged into SOL by the default solMode "merged"
METHOD = "getTransfersByAddress"
SORT_PARAM = "sortOrder"         # "asc" = oldest first; default newest first (verified live 2026-10-20)
PAGE_LIMIT = 100                 # the documented maximum (1 to 100)
COST_TRANSFERS = 10              # credits per getTransfersByAddress call (provider-docs current/helius.md, Historical Data Credits)
COST_IDENTITY = 100              # credits per POST /v1/wallet/batch-identity call (current/helius.md, Wallet API table)
IDENTITY_BATCH = 100             # addresses per batch-identity call (documented maximum)
IDENTITY_MAX_ADDRESSES = 1000    # identity lookups per scan: 10 calls, 1,000 credits
DEFAULT_TOP = 250                # Bubblemaps' window
DEFAULT_HOP_MAX = 300
DEFAULT_RECENT_SOL_TOP = 100     # read C (SOL, newest 100) for the first 100 holders read: on by default since repair round 2
                                 # (the prototype's scope; on the recorded data it finds the 78rn and GezC bursts the oldest rows miss)
DEFAULT_MAX_CREDITS = 12_000     # owner decision 2026-10-20 ("increase the credits budget for the scan ...")
REQUEST_RATE_CAP_PER_S = 6       # one shared pace for every worker of this lane
DEFAULT_WORKERS = 6
MAX_WORKERS = 10
MAX_CONSECUTIVE_FAILURES = 5
TIMEOUT_S = 30.0                 # per attempt: a hard wall-clock limit on open + every read + close (worker thread)
MAX_BYTES = 2 * 1024 * 1024      # one answer: 100 transfer rows are about 60 KB, 100 identities about 30 KB
LAMPORTS = 1_000_000_000
DIRECT_MIN_LAMPORTS = 1_000_000      # direct: at least 0.001 SOL (or any amount of this token)
VIA_MIN_LAMPORTS = 10_000_000        # via_wallet: at least 0.01 SOL (or any amount of this token)
HOP_MIN_LAMPORTS = 100_000_000       # stage-3 candidates: funders and receivers of at least 0.1 SOL
BURST_MIN_LAMPORTS = 1_000_000       # a SOL send counts toward a burst from 0.001 SOL (dust such as address poisoning is not a send)
DUST_MAX_LAMPORTS = 10_000_000       # a SOL burst whose every recipient got under 0.01 SOL is labelled a dust spray (shown, not funding)
BURST_MIN_HOLDERS = 10
BURST_WINDOW_S = 300
ROUND_MIN_OVERLAP = 0.8          # two bursts paid the same holders when their holder sets overlap by 80% (shared / union)
BM_WINDOW_RANK = 250             # Bubblemaps shows the top 250 holders: pair scores count holders up to this rank
BUSY_SPAN_S = 3600               # a read with more pages whose rows cover less than this is a busy wallet
EVIDENCE_PER_CLUSTER = 3
KEY_PIECE = 8
MIN_TS = 1_577_836_800           # 2020-01-01
SIG_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{64,90}$")
ADDR_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
LABEL_RE = re.compile(r"[^\w .\-&()]")
REASON_RE = re.compile(r"^[a-z0-9_]{1,48}$")
SERVICE_WORDS = ("exchange", "exchanges", "cex", "dex", "amm", "router", "bridge", "app", "aggregator", "bot", "program", "protocol")
SERVICE_CATEGORIES = ("authority", "transaction sending", "fees")
SERVICE_RULE = ("a Helius identity whose category or type, lower-cased and split on anything that is not a letter or a digit, holds one of "
                + ", ".join(SERVICE_WORDS) + ", or whose category is exactly Authority, Transaction Sending or Fees (case ignored); names and "
                "tags are not used (a tag such as 'Binance Deposit' marks one user's deposit address, which can be a real link)")
KIND_PARAMS = {  # read kind -> (mint filter, order); the holder's mint filter is filled in per run
    "A": ("TOKEN", "desc"), "B": (SOL_MINT, "asc"), "C": (SOL_MINT, "desc"), "HB": (SOL_MINT, "asc"), "HN": (SOL_MINT, "desc"),
}
HOP_KINDS = ("HB", "HN")
UNWRAP_OR_TRANSFER = ("transfer", "unwrap")  # row types that move SOL or this token from one wallet to another
READ_TEXT = {"A": "this token, newest 100", "B": "SOL, oldest 100", "C": "SOL, newest 100", "HB": "SOL, oldest 100", "HN": "SOL, newest 100"}
LINKED_NOTE = "Linked by on-chain transfers (what was seen), not proof of one owner."
BURST_NOTE = "A burst is payments that were seen (one sender, many of these holders, minutes apart), not proof of one owner."
EMPTY_BURSTS = "no funding bursts or dust sprays seen among the transfers read"
VALIDATION_LINE = ("Linked groups: experimental, not shown. On 10 live mints (2026-10-20) they matched Bubblemaps pairs at pooled recall "
                   "11.4% and precision 3.1%. To see them, run the lane with --groups (about 12,000 credits instead of about 6,000) and "
                   "print with --present <RUN> --groups.")
GROUPS_NOT_COLLECTED = "Linked groups (experimental): not collected in this run (the lane ran without --groups)."
CANNOT_SEE_BURSTS = ("sends beyond each holder's rows read (its newest 100 transfers of this token, its oldest 100 SOL transfers and, for the "
                     "first holders read, its newest 100 SOL transfers: a busy wallet's newest 100 can cover only minutes); payments to "
                     "holders outside the top holders read; a farm funded slowly "
                     "(fewer than 10 holders in any 5 minutes) or through exchanges, apps or bridges (labelled services are listed apart, "
                     "never as funding); who controls a wallet")
EMPTY_NOTE = "no links seen among the transfers read"
CANNOT_SEE = ("transfers beyond the rows read (100 per read: a busy wallet's newest 100 can cover only minutes, and the oldest 100 "
              "only its first activity); links through three or more outside wallets in a row, or through a wallet outside the "
              "counterparties read; holders outside the top holders read; links through exchanges, apps, bots, bridges and program accounts (never counted: "
              "they serve many unrelated users); trades routed through a pool; and who controls a wallet")
PRESENTATION_NOTE = ("presentation only: never an engine input; it changes no FLAG, verdict or threshold, and an empty graph is no "
                     "all-clear")


# ----------------------------------------------------------------------------- small helpers


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def is_address(value: Any) -> bool:
    if not isinstance(value, str) or not ADDR_RE.match(value):
        return False
    try:
        return len(b58decode(value)) == 32
    except ValueError:
        return False


_CURVE: dict[str, bool] = {}
_CURVE_LOCK = threading.Lock()


def on_curve(address: str) -> bool:
    """True for an address on the ed25519 curve (a wallet can sign for it); False for a program-derived address."""
    with _CURVE_LOCK:
        known = _CURVE.get(address)
    if known is None:
        try:
            known = is_address(address) and is_on_curve(address)
        except ValueError:
            known = False
        with _CURVE_LOCK:
            _CURVE[address] = known
    return known


def iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_text(ts: Any) -> str:
    if not _int(ts):
        return "time unknown"
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def cut(value: Any, places: int = 2) -> str:
    """A number cut toward zero (never rounded up) to `places` decimals."""
    try:
        d = decimal.Decimal(str(value))
    except (decimal.InvalidOperation, ValueError):
        return "?"
    if not d.is_finite():
        return "?"
    return str(d.quantize(decimal.Decimal(1).scaleb(-places), rounding=decimal.ROUND_DOWN))


def amount_text(raw: int, decimals: int) -> str:
    """An exact amount from the raw integer and the decimals (no float)."""
    d = decimal.Decimal(raw).scaleb(-decimals)
    text = format(d.normalize(), "f") if d else "0"
    return text


def sol_text(raw: int) -> str:
    """SOL cut toward zero to 4 decimals, trailing zeros dropped."""
    d = decimal.Decimal(raw).scaleb(-9).quantize(decimal.Decimal("0.0001"), rounding=decimal.ROUND_DOWN)
    text = format(d.normalize(), "f")
    return text if text != "0" else "under 0.0001"


def shares_key_piece(text: Any, key: str | None) -> bool:
    """True when `text` and the key share any run of KEY_PIECE (8) or more consecutive characters."""
    if not key or not isinstance(text, str) or not text:
        return False
    if len(key) < KEY_PIECE:
        return key in text
    return any(key[i:i + KEY_PIECE] in text for i in range(len(key) - KEY_PIECE + 1))


def echoes_key(text: Any, key: str | None) -> bool:
    """True when `text` shares a KEY_PIECE run with the key, or with the key stripped of the characters a label cannot
    hold, so an echo survives neither as raw text nor as a label."""
    if not key:
        return False
    stripped = LABEL_RE.sub("", key)
    return shares_key_piece(text, key) or (stripped != key and len(stripped) >= KEY_PIECE and shares_key_piece(text, stripped))


def provider_label(value: Any, key: str | None, cap: int = 40) -> str | None:
    """A Helius identity text as a short inert label with verdict words removed (provider_words); None when it is not
    text or echoes the key."""
    if not isinstance(value, str) or not value.strip() or echoes_key(value, key) or echoes_key(LABEL_RE.sub("", value), key):
        return None
    return pw.label(value, LABEL_RE, cap)


def reason_code(exc: BaseException) -> str:
    reason = getattr(exc, "reason", None)
    return reason if isinstance(reason, str) and REASON_RE.match(reason) else "request_failed"


# ----------------------------------------------------------------------------- transport: this lane's opener


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None  # urllib then raises the 3xx as an HTTPError, refused below


def default_opener() -> urllib.request.OpenerDirector:
    """No environment proxy (an explicit empty ProxyHandler), no redirects, default TLS verification."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


class Answer:
    """A fully read answer handed to the shared transport (ha/transport.py), which reads it like a urllib response."""

    def __init__(self, status: int, body: bytes) -> None:
        self.status, self._body = status, body

    def read(self, n: int = -1) -> bytes:
        return self._body if n is None or n < 0 else self._body[:n]

    def __enter__(self) -> "Answer":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


def _bounded(function: Callable[[], Any], timeout: float) -> Any:
    """Run one attempt (open, every read, close) in a daemon worker and wait at most `timeout` seconds: a socket timeout
    alone restarts on every byte, so a server that drip-feeds bytes could hold a read far past the limit."""
    result: queue.Queue = queue.Queue(maxsize=1)

    def invoke() -> None:
        try:
            result.put((True, function()))
        except BaseException as exc:  # noqa: BLE001 - handed back to the bounded caller
            result.put((False, exc))

    worker = threading.Thread(target=invoke, name="transfer-graph-attempt", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise TimeoutError
    ok, value = result.get_nowait()
    if not ok:
        raise value
    return value


class DeadlineOpener:
    """This lane's opener for the shared transport: no environment proxy, no redirects, MAX_BYTES per answer, a hard
    TIMEOUT_S wall-clock limit per attempt, and at most one retry, only after an HTTP 429. The transport retries a 429
    (it pauses the shared gate first); any other failure is turned into a fixed reason code here, so the transport does
    not retry it, and a second 429 within one call stops that call (the gate is paused again first)."""

    def __init__(self, inner: Any | None = None, *, timeout_s: float = TIMEOUT_S, max_bytes: int = MAX_BYTES) -> None:
        self.inner = inner or default_opener()
        self.timeout_s, self.max_bytes = timeout_s, max_bytes
        self.gate: Any = None
        self._local = threading.local()
        self._lock = threading.Lock()
        self.sent = 0
        self.rate_limited = 0

    def begin_call(self) -> None:
        self._local.saw_429 = False

    def open(self, request: Any, timeout: Any = None) -> Answer:
        with self._lock:
            self.sent += 1

        def attempt() -> tuple[int, bytes]:
            with self.inner.open(request, timeout=self.timeout_s) as response:
                status = int(getattr(response, "status", 200) or 200)
                return status, response.read(self.max_bytes + 1)

        try:
            status, body = _bounded(attempt, self.timeout_s)
        except urllib.error.HTTPError as exc:
            code = int(exc.code)
            if code == 429:
                with self._lock:
                    self.rate_limited += 1
                if not getattr(self._local, "saw_429", False):
                    self._local.saw_429 = True
                    raise  # the transport pauses the shared gate, waits 1 s and retries this call once
                exc.close()
                if self.gate is not None:
                    self.gate.pause(2.0)  # the last 429 still holds every worker back
                raise TransportError("rate_limited", http_status=429) from None
            exc.close()
            if 300 <= code < 400:
                raise TransportError("redirect_disallowed", http_status=code) from None
            raise TransportError({401: "auth_failed", 403: "access_denied", 404: "not_found"}.get(code, "http_error"), http_status=code) from None
        except TransportError:
            raise
        except TimeoutError:
            raise TransportError("timeout") from None
        except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError):
            raise TransportError("network_error") from None
        if 300 <= status < 400:
            raise TransportError("redirect_disallowed", http_status=status)
        if len(body) > self.max_bytes:
            raise TransportError("response_too_large")
        return Answer(status, body)


# ----------------------------------------------------------------------------- inputs


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def load_app_list(path: Path = APP_LIST_PATH) -> dict[str, dict[str, str]]:
    """The app and relayer list: address -> {reason, source}. A missing or malformed file raises ValueError (fail closed:
    without it the app wallets would link everything)."""
    data = _read_json(path)
    if not isinstance(data, dict) or data.get("schema") != APP_LIST_SCHEMA or not isinstance(data.get("entries"), list):
        raise ValueError("app_list_unreadable")
    out: dict[str, dict[str, str]] = {}
    for entry in data["entries"]:
        if not isinstance(entry, dict) or not is_address(entry.get("address")):
            raise ValueError("app_list_unreadable")
        reason, source = entry.get("reason"), entry.get("source")
        if not (isinstance(reason, str) and reason.strip() and isinstance(source, str) and source.strip()):
            raise ValueError("app_list_unreadable")
        out[entry["address"]] = {"reason": reason.strip(), "source": source.strip()}
    if not out:
        raise ValueError("app_list_unreadable")
    return out


def pick_holders(holders: dict[str, Any], top: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str]]:
    """(holders to read, skipped rows with the reason, infrastructure wallets). Ordinary rows in rank order, on the curve,
    up to `top`; off-curve rows are skipped and named."""
    used: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    infra: set[str] = set()
    for row in holders.get("top_holders") or []:
        wallet = row.get("wallet")
        if row.get("infrastructure"):
            if isinstance(wallet, str):
                infra.add(wallet)
            continue
        if len(used) >= top:
            break
        entry = {"rank": row["rank"], "wallet": wallet, "share_pct": float(row["share_pct"])}
        if not is_address(wallet):
            skipped.append(entry | {"reason": "not a valid address"})
        elif not on_curve(wallet):
            skipped.append(entry | {"reason": "off the curve (a program account, not a wallet)"})
        else:
            used.append(entry)
    return used, skipped, infra


def pda_pools(run: Path, mint: str) -> tuple[set[str], str]:
    """Pools named by the PDA identity reads (followup/pda_identity_reads.json), when that lane already wrote its file."""
    path = run / OUT_DIR / "pda_identity_reads.json"
    if not path.exists():
        return set(), "not present"
    data = _read_json(path)
    if not isinstance(data, dict) or data.get("mint") != mint:
        return set(), "unreadable or another mint"
    pools = {t["address"] for t in data.get("targets") or [] if isinstance(t, dict) and t.get("status") == "identified"
             and t.get("kind") == "pumpswap_pool" and is_address(t.get("address"))}
    return pools, "read"


def saved_members(run: Path, mint: str) -> tuple[dict[str, Any] | None, str]:
    """assessment.json `bubblemaps_members` (assess resolved the map's member rows to full addresses), or why not."""
    path = run / "assessment.json"
    if not path.exists():
        return None, "assessment.json not present"
    data = _read_json(path)
    if not isinstance(data, dict):
        return None, "assessment.json unreadable"
    holders_mint = (_read_json(run / "holders.json") or {}).get("mint") if (run / "holders.json").exists() else None
    if holders_mint not in (None, mint):
        return None, "the run folder is for another mint"
    members = data.get("bubblemaps_members")
    if members is None:
        return None, "assessment.json holds no Bubblemaps members (assess ran without the map, or before the member read)"
    if not isinstance(members, dict) or members.get("read") is not True or not isinstance(members.get("clusters"), list):
        return None, "the Bubblemaps members were not read" + (f" ({hf.clean_text(members.get('reason'), 120)})" if isinstance(members, dict) and members.get("reason") else "")
    return members, "read"


# ----------------------------------------------------------------------------- rows and facts


def parse_row(raw: Any, mint: str, key: str | None = None) -> dict[str, Any] | None:
    """One transfer row as a fact, or None when it cannot link anything: not a `transfer` (or an `unwrap` of SOL into
    another wallet), not SOL or this token, a side missing (a mint or burn), a field that does not check, or text that
    echoes the key. An `unwrap` row is the owner closing a wSOL account; its lamport destination can be another wallet
    (Helius: fromUserAccount = owner, toUserAccount = lamport destination), which moves SOL from one wallet to another:
    on startupSI (2026-10-20) every one of the 81 Bubblemaps linking wallets funded its holder this way."""
    kind = raw.get("type") if isinstance(raw, dict) else None
    if kind not in UNWRAP_OR_TRANSFER or (kind == "unwrap" and raw.get("mint") not in (SOL_MINT, WSOL_MINT)):
        return None
    sig, t, fr, to, m = raw.get("signature"), raw.get("blockTime"), raw.get("fromUserAccount"), raw.get("toUserAccount"), raw.get("mint")
    if not (isinstance(sig, str) and SIG_RE.match(sig)) or not _int(t) or t < MIN_TS:
        return None
    if not is_address(fr) or not is_address(to) or fr == to or echoes_key(fr, key) or echoes_key(to, key):
        return None
    asset = "SOL" if m in (SOL_MINT, WSOL_MINT) else "TOKEN" if m == mint else None
    dec, amount = raw.get("decimals"), raw.get("amount")
    if asset is None or not _int(dec) or not 0 <= dec <= 18 or (asset == "SOL" and dec != 9):
        return None
    if isinstance(amount, str) and amount.isdigit() and len(amount) <= 40:
        value = int(amount)
    elif _int(amount) and amount >= 0:
        value = amount
    else:
        return None
    return {"sig": sig, "t": t, "from": fr, "to": to, "asset": asset, "raw": value, "dec": dec}


def merge_facts(reads: list[tuple[str, str, dict[str, Any]]]) -> list[dict[str, Any]]:
    """De-duplicate the facts of every read (the same transfer is seen from both sides) and remember which reads found it."""
    found: dict[tuple, dict[str, Any]] = {}
    for kind, owner, read in reads:
        if read.get("status") != "ok":
            continue
        for row in read["rows"]:
            k = (row["sig"], row["from"], row["to"], row["asset"], row["raw"])
            fact = found.get(k)
            if fact is None:
                fact = found[k] = dict(row, reads=[])
            if len(fact["reads"]) < 4 and [kind, owner] not in fact["reads"]:
                fact["reads"].append([kind, owner])
    return sorted(found.values(), key=lambda f: (f["t"], f["sig"], f["from"], f["to"], f["asset"], f["raw"]))


def qualifies(fact: dict[str, Any], min_lamports: int) -> bool:
    return fact["raw"] > 0 if fact["asset"] == "TOKEN" else fact["raw"] >= min_lamports


def is_service(identity: dict[str, Any] | None) -> list[str]:
    """SERVICE_RULE on one Helius identity; the matched words (empty: not a service)."""
    if not isinstance(identity, dict):
        return []
    hits: list[str] = []
    for field in ("category", "type"):
        value = identity.get(field)
        if isinstance(value, str):
            words = set(re.split(r"[^a-z0-9]+", value.lower()))
            hits += [f"{field}:{w}" for w in SERVICE_WORDS if w in words]
    category = identity.get("category")
    if isinstance(category, str) and category.strip().lower() in SERVICE_CATEGORIES:
        hits.append(f"category:{category.strip().lower()}")
    return hits


def counterparties(facts: list[dict[str, Any]], holders: set[str], min_lamports: int) -> dict[str, dict[str, int]]:
    """outside wallet -> {holder: lamports} over SOL facts of at least `min_lamports` between them (either direction)."""
    out: dict[str, dict[str, int]] = collections.defaultdict(dict)
    for f in facts:
        if f["asset"] != "SOL" or f["raw"] < min_lamports:
            continue
        for holder, other in ((f["to"], f["from"]), (f["from"], f["to"])):
            if holder in holders and other not in holders:
                out[other][holder] = out[other].get(holder, 0) + f["raw"]
    return out


# ----------------------------------------------------------------------------- the graph (pure)


class _Union:
    def __init__(self, items: list[str]) -> None:
        self.parent = {i: i for i in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _transfer(f: dict[str, Any]) -> dict[str, Any]:
    kind, owner = f["reads"][0] if f.get("reads") else (None, None)
    return {"signature": f["sig"], "t": f["t"], "time": iso(f["t"]), "from": f["from"], "to": f["to"], "asset": f["asset"],
            "amount": amount_text(f["raw"], f["dec"]), "raw": f["raw"], "decimals": f["dec"], "read": kind, "read_of": owner}


def find_bursts(facts: list[dict[str, Any]], holders: dict[str, dict[str, Any]], usable: set[str]) -> list[dict[str, Any]]:
    """Every sender's bursts: sends (SOL from BURST_MIN_LAMPORTS, any amount of this token) to holders, split into
    sessions where each send follows the previous one within BURST_WINDOW_S; a session is a burst when some
    BURST_WINDOW_S window inside it reaches BURST_MIN_HOLDERS distinct holders. Senders are not filtered here. A SOL burst
    whose every recipient got under DUST_MAX_LAMPORTS in the session is labelled `dust_spray` (advertising, address
    poisoning or fee top-ups: shown, never called funding); thresholds and the floor are unchanged."""
    events: dict[tuple[str, str], dict[tuple[str, str], tuple[int, int]]] = collections.defaultdict(dict)
    for f in facts:
        if f["to"] in usable and f["from"] != f["to"] and qualifies(f, BURST_MIN_LAMPORTS):
            key = (f["sig"], f["to"])
            t, raw = events[(f["from"], f["asset"])].get(key, (f["t"], 0))
            events[(f["from"], f["asset"])][key] = (t, raw + f["raw"])
    bursts: list[dict[str, Any]] = []
    for (sender, asset), sends in events.items():
        items = sorted((t, to, sig, raw) for (sig, to), (t, raw) in sends.items())
        sessions: list[list[tuple[int, str, str, int]]] = [[items[0]]]
        for it in items[1:]:
            if it[0] - sessions[-1][-1][0] <= BURST_WINDOW_S:
                sessions[-1].append(it)
            else:
                sessions.append([it])
        for session in sessions:
            peak, j, counts = 0, 0, collections.Counter()
            for i, (t, to, _, _) in enumerate(session):
                counts[to] += 1
                while t - session[j][0] > BURST_WINDOW_S:
                    counts[session[j][1]] -= 1
                    if not counts[session[j][1]]:
                        del counts[session[j][1]]
                    j += 1
                peak = max(peak, len(counts))
            if peak < BURST_MIN_HOLDERS:
                continue
            members = sorted({to for _, to, _, _ in session}, key=lambda w: holders[w]["rank"])
            per_recipient: dict[str, int] = collections.Counter()
            for _, to, _, raw in session:
                per_recipient[to] += raw
            biggest = max(per_recipient.values())
            dust = asset == "SOL" and biggest < DUST_MAX_LAMPORTS
            bursts.append({"sender": sender, "asset": asset, "holders": [holders[w]["rank"] for w in members], "count": len(members),
                           "dust_spray": dust, "max_per_recipient_sol": sol_text(biggest) if asset == "SOL" else None,
                           "peak_in_window": peak, "start_t": session[0][0], "end_t": session[-1][0], "span_s": session[-1][0] - session[0][0],
                           "start": iso(session[0][0]), "share_pct_sum": round(sum(holders[w]["share_pct"] for w in members), 4),
                           "first_signature": session[0][2], "sender_rank": holders[sender]["rank"] if sender in holders else None})
    bursts.sort(key=lambda b: (-b["count"], b["start_t"], b["sender"], b["asset"]))
    return bursts


def find_rounds(bursts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Repeated rounds: bursts that paid about the same holders (shared holders at least ROUND_MIN_OVERLAP of the union
    with the family's first, largest burst), from 2 or more senders."""
    families: list[dict[str, Any]] = []
    for b in bursts:  # largest first
        hs = set(b["holders"])
        for fam in families:
            if fam["asset"] == b["asset"] and len(hs & fam["base"]) >= ROUND_MIN_OVERLAP * len(hs | fam["base"]):
                fam["bursts"].append(b)
                break
        else:
            families.append({"asset": b["asset"], "base": hs, "bursts": [b]})
    out = []
    for fam in families:
        senders = sorted({b["sender"] for b in fam["bursts"]})
        if len(senders) < 2:
            continue
        sizes = [b["count"] for b in fam["bursts"]]
        union = set().union(*(set(b["holders"]) for b in fam["bursts"]))
        out.append({"asset": fam["asset"], "senders": len(senders), "bursts": len(fam["bursts"]), "kinds": sorted({b["kind"] for b in fam["bursts"]}),
                    "typical_holders": int(statistics.median(sizes)), "holders_union": len(union), "first": iso(min(b["start_t"] for b in fam["bursts"])),
                    "last": iso(max(b["start_t"] for b in fam["bursts"])), "sender_list": senders[:20]})
    out.sort(key=lambda r: (-r["senders"], -r["typical_holders"]))
    return out


def build_graph(holders_used: list[dict[str, Any]], facts: list[dict[str, Any]], *, static: set[str], app: dict[str, Any],
                services: dict[str, list[str]], hop_read: set[str] | frozenset = frozenset()) -> dict[str, Any]:
    """Edges, clusters, bursts, rounds and the merged view from the facts. Pure: no network, no clock."""
    holders = {h["wallet"]: h for h in holders_used}

    def block(address: str) -> str | None:
        """Why an address can never link (None: it can)."""
        if address in static:
            return "static"
        if address in app:
            return "app_list"
        if address in services:
            return "service"
        if not on_curve(address):
            return "off_curve"
        return None

    blocked_holders = {w: r for w in holders if (r := block(w))}
    usable = {w for w in holders if w not in blocked_holders}
    direct: dict[tuple[str, str], list[dict[str, Any]]] = {}
    touch: dict[str, dict[str, list[dict[str, Any]]]] = collections.defaultdict(lambda: collections.defaultdict(list))
    for f in facts:
        a, b = f["from"], f["to"]
        if a in holders and b in holders:
            if a in usable and b in usable and qualifies(f, DIRECT_MIN_LAMPORTS):
                direct.setdefault(tuple(sorted((a, b), key=lambda w: holders[w]["rank"])), []).append(f)
            continue
        for holder, other in ((a, b), (b, a)):
            if holder in usable and other not in holders and block(other) is None and qualifies(f, VIA_MIN_LAMPORTS):
                touch[other][holder].append(f)
    direct_edges = []
    for (a, b), fs in sorted(direct.items(), key=lambda kv: (holders[kv[0][0]]["rank"], holders[kv[0][1]]["rank"])):
        direct_edges.append({"type": "direct", "a": a, "b": b, "rank_a": holders[a]["rank"], "rank_b": holders[b]["rank"], "transfers": len(fs),
                             "evidence": [_transfer(f) for f in fs[:3]]})
    via_edges = []
    for wallet, per in touch.items():
        if len(per) < 2:
            continue
        members = sorted(per, key=lambda w: holders[w]["rank"])
        sol = sum(f["raw"] for fs in per.values() for f in fs if f["asset"] == "SOL")
        via_edges.append({"type": "via_wallet", "wallet": wallet, "holders": [holders[w]["rank"] for w in members], "count": len(members), "sol_raw": sol,
                          "evidence": {str(holders[w]["rank"]): [_transfer(f) for f in sorted(per[w], key=lambda f: -f["raw"])[:2]] for w in members}})
    via_edges.sort(key=lambda e: (-e["count"], -e["sol_raw"], e["wallet"]))
    bridges: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for f in facts:  # via_wallet_pair: two counterparties, both read one hop out, that moved at least 0.1 SOL with each other
        a, b = f["from"], f["to"]
        if a not in hop_read or b not in hop_read or f["asset"] != "SOL" or f["raw"] < HOP_MIN_LAMPORTS or a not in touch or b not in touch:
            continue
        if block(a) or block(b):
            continue
        ha, hb = set(touch[a]), set(touch[b])
        if len(ha | hb) < 2 or ha >= hb or hb >= ha:
            continue  # one wallet's own via_wallet link already covers these holders
        bridges.setdefault(tuple(sorted((a, b))), []).append(f)
    pair_edges = []
    for (a, b), fs in bridges.items():
        members = sorted(set(touch[a]) | set(touch[b]), key=lambda w: holders[w]["rank"])
        pair_edges.append({"type": "via_wallet_pair", "wallets": [a, b], "holders": [holders[w]["rank"] for w in members], "count": len(members),
                           "bridge": [_transfer(f) for f in sorted(fs, key=lambda f: -f["raw"])[:2]],
                           "evidence": {str(holders[w]["rank"]): [_transfer(f) for f in sorted((touch[a].get(w) or touch[b].get(w)), key=lambda f: -f["raw"])[:1]] for w in members}})
    pair_edges.sort(key=lambda e: (-e["count"], e["wallets"]))

    bursts_all = find_bursts(facts, holders, usable)
    bursts, not_linked, pool_trades = [], [], 0
    for b in bursts_all:
        sender = b["sender"]
        if sender in static or sender in app:
            continue  # this token's pools and the listed app wallets: expected, never reported
        b["kind"] = "service" if sender in services else ("program_account" if not on_curve(sender) else "wallet")
        if b["kind"] == "program_account" and b["asset"] == "TOKEN":
            pool_trades += 1  # a program account paying out this token is almost always a pool's authority filling buys: counted only
            continue
        (bursts if b["kind"] == "wallet" else not_linked).append(b)
    rounds = find_rounds(bursts + not_linked)

    by_rank = {h["rank"]: h["wallet"] for h in holders_used}
    order = [h["wallet"] for h in holders_used]
    uf = _Union(order)
    for e in direct_edges:
        uf.union(e["a"], e["b"])
    for e in via_edges + pair_edges:
        ws = [by_rank[r] for r in e["holders"]]
        for w in ws[1:]:
            uf.union(ws[0], w)
    groups: dict[str, list[str]] = collections.defaultdict(list)
    for w in order:
        groups[uf.find(w)].append(w)
    comps = [ws for ws in groups.values() if len(ws) >= 2]
    comps.sort(key=lambda ws: (-sum(holders[w]["share_pct"] for w in ws), -len(ws), holders[ws[0]]["rank"]))
    clusters = []
    for n, ws in enumerate(comps, 1):
        wset = set(ws)
        d = [e for e in direct_edges if e["a"] in wset]
        v = [e for e in via_edges if by_rank[e["holders"][0]] in wset]
        vp = [e for e in pair_edges if by_rank[e["holders"][0]] in wset]
        evidence: list[dict[str, Any]] = []
        for e in d:
            if len(evidence) < EVIDENCE_PER_CLUSTER:
                evidence.append({"type": "direct", "transfers": e["evidence"][:1]})
        for e in v:
            if len(evidence) < EVIDENCE_PER_CLUSTER:
                firsts = [e["evidence"][str(r)][0] for r in e["holders"][:2]]
                evidence.append({"type": "via_wallet", "wallet": e["wallet"], "transfers": firsts})
        for e in vp:
            if len(evidence) < EVIDENCE_PER_CLUSTER:
                ends = [e["evidence"][str(r)][0] for r in (e["holders"][0], e["holders"][-1])]
                evidence.append({"type": "via_wallet_pair", "wallets": e["wallets"], "transfers": [ends[0], e["bridge"][0], ends[1]]})
        clusters.append({"id": n, "size": len(ws), "share_pct_sum": round(sum(holders[w]["share_pct"] for w in ws), 4),
                         "members": [{"rank": holders[w]["rank"], "wallet": w, "share_pct": holders[w]["share_pct"]} for w in ws],
                         "edge_counts": {"direct": len(d), "via_wallet": len(v), "via_wallet_pair": len(vp)}, "evidence": evidence,
                         "linking_wallets": [{"wallet": e["wallet"], "holders": e["count"], "sol": sol_text(e["sol_raw"]) if e["sol_raw"] else None} for e in v]
                         + [{"wallets": e["wallets"], "holders": e["count"]} for e in vp]})
    group_of = {m["wallet"]: cluster["id"] for cluster in clusters for m in cluster["members"]}

    muf = _Union(order)
    for ws in comps:
        for w in ws[1:]:
            muf.union(ws[0], w)
    for b in bursts:
        if b.get("dust_spray"):
            continue  # a dust spray is not funding: it never merges holders, not even in the marked view
        ws = [by_rank[r] for r in b["holders"]] + ([b["sender"]] if b["sender"] in usable else [])
        for w in ws[1:]:
            muf.union(ws[0], w)
    mgroups: dict[str, list[str]] = collections.defaultdict(list)
    for w in order:
        mgroups[muf.find(w)].append(w)
    merged = [ws for ws in mgroups.values() if len(ws) >= 2]
    merged.sort(key=lambda ws: (-sum(holders[w]["share_pct"] for w in ws), -len(ws), holders[ws[0]]["rank"]))
    merged_view = []
    for n, ws in enumerate(merged, 1):
        wset = set(ws)
        merged_view.append({"id": n, "size": len(ws), "share_pct_sum": round(sum(holders[w]["share_pct"] for w in ws), 4),
                            "members": [holders[w]["rank"] for w in ws],
                            "linked_groups": sorted({group_of[w] for w in ws if w in group_of}),
                            "bursts": sum(1 for b in bursts if not b.get("dust_spray") and set(by_rank[r] for r in b["holders"]) & wset)})
    return {"edges": {"direct": direct_edges, "via_wallet": via_edges, "via_wallet_pair": pair_edges}, "clusters": clusters, "bursts": bursts, "bursts_not_linked": not_linked,
            "program_token_bursts_not_listed": pool_trades,
            "rounds": rounds, "merged_view": merged_view,
            "holders_not_linked": [{"rank": holders[w]["rank"], "wallet": w, "why": r} for w, r in sorted(blocked_holders.items(), key=lambda kv: holders[kv[0]]["rank"])]}


# ----------------------------------------------------------------------------- the Bubblemaps overlap (pure)


def _pairs(label: dict[str, Any], universe: set[str]) -> set[tuple[str, str]]:
    by: dict[Any, list[str]] = collections.defaultdict(list)
    for w in sorted(universe):
        if label.get(w) is not None:
            by[label[w]].append(w)
    return {(a, b) for ws in by.values() for i, a in enumerate(ws) for b in ws[i + 1:]}


def bubblemaps_overlap(result: dict[str, Any], members: dict[str, Any] | None, members_state: str, ranked: list[tuple[str, float]] | None = None) -> dict[str, Any]:
    """Each Bubblemaps cluster (the size read's clusters and the clusters only the member list saw) against the linked
    groups: its holders both sides saw, how many sit in one group, and why each other one is missed; plus the pair counts
    within the holders both sides saw (helius rank up to BM_WINDOW_RANK)."""
    if members is None:
        return {"status": "not_read", "reason": members_state}
    used = {h["wallet"]: h for h in result.get("holders") or []}
    skipped = {h["wallet"]: h for h in result.get("holders_skipped") or []}
    rank_of = {w: i for i, (w, _) in enumerate(ranked or [], 1)}
    failed = {r["wallet"] for r in result.get("reads", {}).get("stage1_failed_holders", [])}
    group_of = {m["wallet"]: c["id"] for c in result.get("clusters") or [] for m in c["members"]}
    by_rank = {h["rank"]: h["wallet"] for h in used.values()}
    merged_of = {by_rank[r]: c["id"] for c in result.get("merged_view") or [] for r in c["members"] if r in by_rank}
    out_clusters = []
    label: dict[str, int] = {}
    listed = [(c, False) for c in members.get("clusters") or []] + [(c, True) for c in members.get("list_only") or []]
    for c, list_only in listed:
        n = c.get("cluster")
        rows_in = c.get("members")
        entry: dict[str, Any] = {"cluster": n, "wallets": c.get("wallets"), "supply_pct": c.get("supply_pct"), "members_complete": c.get("members_complete") is True}
        if list_only:
            entry["list_only"] = True  # seen by the map's member list only, not by its size read (display only)
        if not isinstance(rows_in, list):
            entry.update(members_read=False, rows=[])
            out_clusters.append(entry)
            continue
        rows = []
        for m in rows_in:
            if not isinstance(m, dict) or m.get("kind") != "holder":
                continue
            addr = m.get("address")
            shown = m.get("shown") or m.get("label")
            if not is_address(addr):
                rows.append({"shown": shown, "status": "not_resolved", "why": "the map row was not resolved to a full address"
                             + (f" ({hf.clean_text(m.get('unresolved'), 80)})" if m.get("unresolved") else "")})
                continue
            if addr in used:
                rows.append({"address": addr, "rank": used[addr]["rank"], "status": "seen", "group": group_of.get(addr), "merged": merged_of.get(addr)})
                label.setdefault(addr, n)
            elif addr in skipped:
                rows.append({"address": addr, "status": "outside", "why": f"not read: {skipped[addr]['reason']}"})
            else:
                rank = rank_of.get(addr)
                rows.append({"address": addr, "status": "outside", "why": f"outside the holders read (Helius rank {rank})" if rank else "outside the holders read"})
        seen = [r for r in rows if r["status"] == "seen"]
        counts = collections.Counter(r["group"] for r in seen if r["group"] is not None)
        best, matched = (counts.most_common(1)[0] if counts else (None, 0))
        for r in seen:
            if best is not None and r["group"] == best:
                r["why"] = None
            elif r["group"] is not None:
                r["why"] = f"linked, but in group {r['group']}"
            elif r["address"] in failed:
                r["why"] = "its own reads failed, and no link was seen among the other transfers read"
            elif r.get("merged") is not None:
                r["why"] = f"no transfer link seen; in merged group {r['merged']} through a funding burst"
            else:
                r["why"] = EMPTY_NOTE
        entry.update(members_read=True, holder_rows=len(rows), seen_by_both=len(seen), matched=matched if len(seen) >= 1 else 0, group=best, rows=rows)
        out_clusters.append(entry)
    universe = {w for w, h in used.items() if h["rank"] <= BM_WINDOW_RANK}
    bm_pairs = _pairs(label, universe)
    sizes = collections.Counter(group_of.values())
    ours = _pairs({w: g for w, g in group_of.items() if sizes[g] > 1}, universe)
    shared = bm_pairs & ours
    per_group: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for entry in out_clusters:
        if not entry.get("members_read"):
            continue
        in_group = collections.Counter(r["group"] for r in entry["rows"] if r["status"] == "seen" and r["group"] is not None)
        for g, k in in_group.items():
            per_group[str(g)].append({"bm_cluster": entry["cluster"], "in_group": k, "seen_by_both": entry["seen_by_both"]})
    return {"status": "read", "clusters": out_clusters, "groups": dict(per_group),
            "pairs": {"universe_holders": len(universe), "bubblemaps": len(bm_pairs), "graph": len(ours), "shared": len(shared),
                      "recall": round(len(shared) / len(bm_pairs), 4) if bm_pairs else None, "precision": round(len(shared) / len(ours), 4) if ours else None}}


# ----------------------------------------------------------------------------- the run


def estimate(holders: int, hop_max: int, recent_sol_top: int) -> dict[str, int]:
    """Credits before any read: stage 1 is A and B for every holder plus C for the first recent_sol_top holders."""
    if isinstance(recent_sol_top, bool) or not isinstance(recent_sol_top, int):
        raise TypeError("recent_sol_top is a number of holders")
    stage1 = (holders * 2 + min(max(recent_sol_top, 0), holders)) * COST_TRANSFERS
    identity = math.ceil(IDENTITY_MAX_ADDRESSES / IDENTITY_BATCH) * COST_IDENTITY
    stage3 = hop_max * 2 * COST_TRANSFERS
    return {"stage1": stage1, "identity": identity, "stage3": stage3, "total": stage1 + identity + stage3}


def plan_budget(holders: int, hop_max: int, recent_sol_top: int, max_credits: int) -> tuple[int | None, str | None, dict[str, int]]:
    """(hop_max to use or None when the run must refuse, the note, the estimate). --hop-max is lowered first."""
    est = estimate(holders, hop_max, recent_sol_top)
    if est["total"] <= max_credits:
        return hop_max, None, est
    room = max_credits - est["stage1"] - est["identity"]
    if room < 0:
        return None, (f"the estimate without any counterparty read ({est['stage1'] + est['identity']:,} credits) exceeds --max-credits "
                      f"{max_credits:,}: the run did not start"), est
    lowered = room // (2 * COST_TRANSFERS)
    note = f"--hop-max lowered from {hop_max} to {lowered} so the estimate fits --max-credits {max_credits:,}"
    return lowered, note, estimate(holders, lowered, recent_sol_top)


def _base(mint: str, started: str) -> dict[str, Any]:
    return {"schema": SCHEMA, "mint": mint, "status": "unavailable", "reason": None, "stopped_early": None, "fetched_at": started,
            "request": {"hosts": [RPC_HOST, API_HOST], "methods": [METHOD, "POST /v1/wallet/batch-identity"], "key": f"{KEY_NAME} (name only)",
                        "calls": {}, "credits": {"stage1": 0, "identity": 0, "stage3": 0, "total": 0}, "requests_sent": 0}}


class GraphRun:
    """One collector run. The reads land in this object as they finish, so an interrupted run can still be written."""

    def __init__(self, mint: str, run: Path, *, key: str, top: int = DEFAULT_TOP, hop_max: int = DEFAULT_HOP_MAX, max_credits: int = DEFAULT_MAX_CREDITS,
                 recent_sol_top: int = DEFAULT_RECENT_SOL_TOP, recent_sol: bool | None = None, workers: int = DEFAULT_WORKERS, inner_opener: Any = None,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep, wall: Callable[[], float] = time.time,
                 app_list_path: Path = APP_LIST_PATH, groups: bool = False) -> None:
        """recent_sol_top: read C (SOL, newest 100) for the first N holders read (default 100; 0 = off). recent_sol (the
        older switch, kept for the recorded runs of 2026-10-20): True = C for every holder read, False = off; None = use
        recent_sol_top."""
        self.mint, self.run_dir, self.key, self.groups = mint, run, key, groups
        self.top, self.hop_max_requested, self.max_credits, self.workers = top, hop_max, max_credits, workers
        self.recent_sol_top = max(0, int(recent_sol_top)) if recent_sol is None else (top if recent_sol else 0)
        self.inner_opener, self.clock, self.sleep, self.wall, self.app_list_path = inner_opener, clock, sleep, wall, app_list_path
        self.started = clock()
        self.result = _base(mint, iso(wall()))
        self.reads: dict[tuple[str, str], dict[str, Any]] = {}
        self.identities: dict[str, dict[str, Any]] = {}
        self.credits = {"stage1": 0, "identity": 0, "stage3": 0}
        self.calls = collections.Counter()
        self.stage_s: dict[str, float] = {}
        self.stopped: str | None = None
        self.lock = threading.Lock()
        self.holders_used: list[dict[str, Any]] = []
        self.ranked: list[tuple[str, float]] = []
        self.static: set[str] = set()
        self.app: dict[str, Any] = {}
        self.services: dict[str, list[str]] = {}
        self.candidates: list[tuple[str, int, int]] = []
        self.hop_targets: list[str] = []
        self.identity_plan: dict[str, Any] = {}
        self.opener: DeadlineOpener | None = None
        self.started_reads = False

    # ---- reads
    def _charge(self, stage: str, cost: int) -> None:
        self.budget.charge(cost)  # raises helius_forensics.BudgetError: nothing is sent
        with self.lock:
            self.credits[stage] += cost

    def _transfers(self, stage: str, kind: str, address: str) -> dict[str, Any]:
        mint_filter, order = KIND_PARAMS[kind]
        opts: dict[str, Any] = {"mint": self.mint if mint_filter == "TOKEN" else mint_filter, "limit": PAGE_LIMIT}
        if order == "asc":
            opts[SORT_PARAM] = "asc"
        self._charge(stage, COST_TRANSFERS)
        with self.lock:
            self.calls[kind] += 1
        try:
            self.opener.begin_call()
            answer = self.client.rpc(METHOD, [address, opts])
        except BudgetExhausted:
            raise hf.BudgetError("call budget reached") from None
        except TransportError as exc:
            return {"status": "failed", "reason": reason_code(exc)}
        data = answer.get("data") if isinstance(answer, dict) else None
        if not isinstance(data, list):
            return {"status": "failed", "reason": "unexpected_shape"}
        times = [r["blockTime"] for r in data if isinstance(r, dict) and _int(r.get("blockTime"))]
        rows = [r for r in (parse_row(x, self.mint, self.key) for x in data[:PAGE_LIMIT]) if r]
        return {"status": "ok", "n": len(data), "rows": rows, "more": bool(answer.get("paginationToken")),
                "first_t": min(times) if times else None, "last_t": max(times) if times else None}

    def _stage(self, stage: str, items: list[tuple[str, str]], lookup: Callable[[tuple[str, str]], dict[str, Any]], store: Callable[[tuple[str, str], dict[str, Any]], None]) -> str | None:
        """Run the reads of one stage in a bounded pool; store each as it finishes. Returns why the stage stopped early."""
        state = {"failed_in_a_row": 0, "stop": None}

        def on_outcome(i: int, outcome: tuple[str, Any]) -> bool:
            kind, value = outcome
            if kind == "budget":
                state["stop"] = state["stop"] or "credit budget reached"
                return True
            if kind != "ok":
                value = {"status": "failed", "reason": "unexpected_error"}
            store(items[i], value)
            if value.get("status") == "ok":
                state["failed_in_a_row"] = 0
                return False
            state["failed_in_a_row"] += 1
            if state["failed_in_a_row"] >= MAX_CONSECUTIVE_FAILURES:
                state["stop"] = f"{MAX_CONSECUTIVE_FAILURES} reads failed in a row"
                return True
            return False

        hf.run_lookups(items, lookup, self.workers, on_outcome)
        return state["stop"]

    def _store_read(self, item: tuple[str, str], value: dict[str, Any]) -> None:
        with self.lock:
            self.reads[item] = value

    def _identity_lookup(self, item: tuple[str, str]) -> dict[str, Any]:
        chunk = self.identity_chunks[int(item[1])]
        self._charge("identity", COST_IDENTITY)
        with self.lock:
            self.calls["identity"] += 1
        try:
            self.opener.begin_call()
            found = self.client.identities(chunk)
        except BudgetExhausted:
            raise hf.BudgetError("call budget reached") from None
        except TransportError as exc:
            return {"status": "failed", "reason": reason_code(exc)}
        return {"status": "ok", "found": found}

    def _store_identity(self, item: tuple[str, str], value: dict[str, Any]) -> None:
        with self.lock:
            self.reads[("identity", item[1])] = {"status": value.get("status"), "reason": value.get("reason")}
            for address, ident in (value.get("found") or {}).items():
                if is_address(address) and not echoes_key(address, self.key):
                    self.identities[address] = ident

    # ---- the stages
    def prepare(self) -> bool:
        """Inputs, exclusions and the budget plan, before any key use or credit. False when the run cannot start."""
        path = self.run_dir / "holders.json"
        if not path.exists():
            self.result["reason"] = "holders_json_missing"
            return False
        raw = _read_json(path)
        if not isinstance(raw, dict) or raw.get("mint") != self.mint:
            self.result["reason"] = "holders_json_other_mint" if isinstance(raw, dict) and is_address(raw.get("mint")) else "holders_json_unreadable"
            return False
        try:
            holders, credits = hf.load_run_holders(raw, self.mint)
        except hf.ForensicsError:
            self.result["reason"] = "holders_json_unreadable"
            return False
        try:
            self.app = load_app_list(self.app_list_path)
        except ValueError:
            self.result["reason"] = "app_list_unreadable"
            return False
        self.ranked = holders.get("_ranked") or []
        used, skipped, infra = pick_holders(holders, self.top)
        pools, pda_state = pda_pools(self.run_dir, self.mint)
        self.static = {self.mint, SOL_MINT, WSOL_MINT, *BURN_ADDRESSES, *holders.get("pool_addresses", []), *infra, *pools}
        self.holders_used = used
        infra_pct = holders.get("distribution", {}).get("infrastructure_pct")
        self.result.update(holders=used, holders_skipped=skipped,
                           inputs={"holders_json": "read", "holders_json_credits_spent": credits, "holder_accounts": holders.get("token_accounts"),
                                   "pool_share_pct": infra_pct, "pda_identity_reads": pda_state, "app_list": {"file": "skills/dlmm-scan/references/transfer_graph_app_wallets.json", "entries": len(self.app)}})
        if not used:
            self.result["reason"] = "no_holders_to_read"
            return False
        hop, note, est = plan_budget(len(used), self.hop_max_requested if self.groups else 0, self.recent_sol_top, self.max_credits)
        self.result["settings"] = {"groups": self.groups, "stage3": "read (--groups)" if self.groups else "skipped: linked groups are off (no --groups); on every recorded mint stage 3 changed no burst and no round",
                                   "top": self.top, "hop_max_requested": self.hop_max_requested, "hop_max_used": hop, "hop_max_note": note,
                                   "recent_sol_top": self.recent_sol_top, "recent_sol_holders": min(self.recent_sol_top, len(used)),
                                   "max_credits": self.max_credits, "workers": self.workers, "rate_cap_per_s": REQUEST_RATE_CAP_PER_S, "estimate": est,
                                   "thresholds": {"direct_min_sol": "0.001", "via_wallet_min_sol": "0.01", "hop_min_sol": "0.1", "burst_min_holders": BURST_MIN_HOLDERS,
                                                  "burst_window_s": BURST_WINDOW_S, "burst_min_sol": "0.001", "identity_max_addresses": IDENTITY_MAX_ADDRESSES}}
        if hop is None:
            self.result["reason"] = "credit_estimate_over_cap"
            return False
        self.hop_max = hop
        return True

    def run(self) -> dict[str, Any]:
        if not self.prepare():
            return self.finish()
        self.opener = DeadlineOpener(self.inner_opener)
        try:
            self.client = HeliusClient(self.key, max_calls=self.max_credits // COST_TRANSFERS + 1, opener=self.opener, timeout=int(TIMEOUT_S), clock=self.clock,
                                       sleep=self.sleep, rate_cap_per_s=REQUEST_RATE_CAP_PER_S)
        except TransportError:
            self.result["reason"] = "key_format"
            return self.finish()
        self.opener.gate = self.client.gate
        self.budget = hf.Budget(self.max_credits)
        self.started_reads = True
        # stage 1
        t0 = self.clock()
        items = [(k, h["wallet"]) for i, h in enumerate(self.holders_used) for k in self._kinds(i)]
        self.stopped = self._stage("stage1", items, lambda it: self._transfers("stage1", it[0], it[1]), self._store_read)
        self.stage_s["stage1"] = round(self.clock() - t0, 1)
        if self.stopped:
            return self.finish()
        # stage 2: identity of the burst senders, the shared counterparties and the stage-3 candidates
        t0 = self.clock()
        facts = self._facts()
        users = {h["wallet"] for h in self.holders_used}
        self.candidates = self._hop_candidates(facts, users) if self.groups else []
        wanted = self._identity_wanted(facts, users)
        self.identity_chunks = [wanted[i:i + IDENTITY_BATCH] for i in range(0, len(wanted), IDENTITY_BATCH)]
        self.stopped = self._stage("identity", [("identity", str(i)) for i in range(len(self.identity_chunks))], self._identity_lookup, self._store_identity)
        self.services = {a: hits for a, ident in self.identities.items() if (hits := is_service(ident))}
        self.stage_s["identity"] = round(self.clock() - t0, 1)
        if self.stopped or not self.groups:
            return self.finish()  # without --groups stage 3 is skipped: it changed no burst on any recorded mint
        # stage 3
        t0 = self.clock()
        self.hop_targets = [a for a, _, _ in self.candidates if a not in self.services][: self.hop_max]
        items = [(k, a) for a in self.hop_targets for k in ("HB", "HN")]
        self.stopped = self._stage("stage3", items, lambda it: self._transfers("stage3", it[0], it[1]), self._store_read)
        self.stage_s["stage3"] = round(self.clock() - t0, 1)
        return self.finish()

    def _kinds(self, i: int) -> tuple[str, ...]:
        """The stage-1 reads of the holder at position i of the holders read: A and B always, C for the first recent_sol_top."""
        return ("A", "B", "C") if i < self.recent_sol_top else ("A", "B")

    def _facts(self) -> list[dict[str, Any]]:
        with self.lock:
            reads = [(k, a, r) for (k, a), r in self.reads.items() if k in KIND_PARAMS]
        order = list(KIND_PARAMS)  # a fixed order, never the order the reads finished in: the same transfer seen by two reads
        reads.sort(key=lambda x: (order.index(x[0]), x[1]))  # (B and C, or HB and HN) always names the same read
        return merge_facts(reads)

    def _hop_candidates(self, facts: list[dict[str, Any]], users: set[str]) -> list[tuple[str, int, int]]:
        """(address, lamports moved with holders in sends of at least 0.1 SOL, holders) for every outside wallet that can be
        read: on the curve, not static, not on the app list; ranked by the SOL moved."""
        cps = counterparties(facts, users, HOP_MIN_LAMPORTS)
        out = [(a, sum(per.values()), len(per)) for a, per in cps.items() if a not in self.static and a not in self.app and on_curve(a)]
        out.sort(key=lambda c: (-c[1], -c[2], c[0]))
        return out

    def _identity_wanted(self, facts: list[dict[str, Any]], users: set[str]) -> list[str]:
        holders = {h["wallet"]: h for h in self.holders_used}
        senders = [b["sender"] for b in find_bursts(facts, holders, users) if b["sender"] not in self.static and b["sender"] not in self.app]
        if not self.groups:  # bursts only: the burst senders' identities decide wallet, program account or service
            ordered = list(dict.fromkeys(a for a in senders if is_address(a)))
            self.identity_plan = {"burst_senders": len(ordered), "shared_counterparties": "not looked up (no --groups)", "hop_candidates": 0, "wanted": len(ordered),
                                  "looked_up": min(len(ordered), IDENTITY_MAX_ADDRESSES), "not_looked_up": max(0, len(ordered) - IDENTITY_MAX_ADDRESSES)}
            return ordered[:IDENTITY_MAX_ADDRESSES]
        shared = collections.defaultdict(set)
        for f in facts:
            if not qualifies(f, VIA_MIN_LAMPORTS):
                continue
            for holder, other in ((f["from"], f["to"]), (f["to"], f["from"])):
                if holder in users and other != holder:
                    shared[other].add(holder)
        shared_list = sorted((a for a, hs in shared.items() if len(hs) >= 2 and a not in self.static and a not in self.app and on_curve(a)),
                             key=lambda a: (-len(shared[a]), a))
        ordered, seen = [], set()
        for a in [*senders, *shared_list, *(c[0] for c in self.candidates[: 2 * self.hop_max])]:  # a margin for the services skipped
            if a not in seen and is_address(a):
                seen.add(a)
                ordered.append(a)
        self.identity_plan = {"burst_senders": len(set(senders)), "shared_counterparties": len(shared_list), "hop_candidates": min(len(self.candidates), 2 * self.hop_max),
                              "wanted": len(ordered), "looked_up": min(len(ordered), IDENTITY_MAX_ADDRESSES), "not_looked_up": max(0, len(ordered) - IDENTITY_MAX_ADDRESSES)}
        return ordered[:IDENTITY_MAX_ADDRESSES]

    def finish(self, stopped: str | None = None) -> dict[str, Any]:
        """Build the graph from whatever was read and fill the result (also after Ctrl-C)."""
        if stopped:
            self.stopped = stopped
        r = self.result
        r["finished_at"] = iso(self.wall())
        r["wall_s"] = round(self.clock() - self.started, 1)
        r["stage_s"] = dict(self.stage_s)
        r["request"]["calls"] = {k: self.calls[k] for k in ("A", "B", "C", "identity", "HB", "HN") if self.calls[k]}
        r["request"]["credits"] = dict(self.credits, total=sum(self.credits.values()))
        r["request"]["requests_sent"] = self.opener.sent if self.opener else 0
        r["request"]["http_429"] = self.opener.rate_limited if self.opener else 0
        if not self.started_reads:
            if stopped and not r.get("reason"):
                r["reason"] = "interrupted"
            return r
        r["stopped_early"] = {"reason": self.stopped} if self.stopped else None
        facts = self._facts()
        hop_read = {a for a in self.hop_targets if any((self.reads.get((k, a)) or {}).get("status") == "ok" for k in HOP_KINDS)}
        graph = build_graph(self.holders_used, facts, static=self.static, app=self.app, services=self.services, hop_read=hop_read)
        if not self.groups:  # held (owner decision 2026-10-20): the linked groups are neither kept nor shown
            for k in ("edges", "clusters", "merged_view", "holders_not_linked"):
                graph.pop(k, None)
            graph["clusters"] = []
        r.update(graph)
        r["groups"] = {"collected": self.groups, "experimental": True, "note": VALIDATION_LINE}
        r["reads"] = self._read_summary()
        r["exclusions"] = self._exclusions()
        if self.groups:
            r["stage3"] = self._stage3_summary(facts)
            members, state = saved_members(self.run_dir, self.mint)
            r["bubblemaps_overlap"] = bubblemaps_overlap(r, members, state, self.ranked)
        ok_reads = sum(1 for (k, _), v in self.reads.items() if k in ("A", "B", "C") and v.get("status") == "ok")
        if not ok_reads:
            r["status"], r["reason"] = "unavailable", (self.stopped and "stopped_before_any_read") or "reads_failed"
        elif graph["clusters"] or graph["bursts"] or graph["bursts_not_linked"]:
            r["status"], r["reason"] = "ok", None
        else:
            r["status"], r["reason"] = "empty", None
        return r

    def _read_summary(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        users = [h["wallet"] for h in self.holders_used]
        stages = [("stage1", [(k, a) for i, a in enumerate(users) for k in self._kinds(i)])]
        if self.groups:
            stages.append(("stage3", [(k, a) for a in self.hop_targets for k in HOP_KINDS]))
        for stage, planned in stages:
            got = [self.reads.get(p) for p in planned]
            failed = collections.Counter(g["reason"] for g in got if g and g.get("status") == "failed")
            more = collections.Counter(k for (k, _), g in zip(planned, got) if g and g.get("status") == "ok" and g.get("more"))
            busy = sorted(((g["last_t"] - g["first_t"], k, a) for (k, a), g in zip(planned, got)
                           if g and g.get("status") == "ok" and g.get("more") and k in ("A", "C", "HN") and g.get("first_t") is not None
                           and g["last_t"] - g["first_t"] < BUSY_SPAN_S))
            out[stage] = {"planned": len(planned), "ok": sum(1 for g in got if g and g.get("status") == "ok"), "failed": sum(failed.values()),
                          "failed_reasons": dict(failed), "not_reached": sum(1 for g in got if g is None), "with_more_pages": dict(more),
                          "busy_reads": len(busy), "busy_examples": [{"wallet": a, "read": k, "minutes": round(span / 60, 1)} for span, k, a in busy[:5]]}
        bad = sorted({a for (k, a), g in self.reads.items() if k in ("A", "B", "C") and g.get("status") == "failed"})
        rank = {h["wallet"]: h["rank"] for h in self.holders_used}
        out["stage1_failed_holders"] = [{"rank": rank[a], "wallet": a} for a in bad if a in rank]
        ids = [g for (k, _), g in self.reads.items() if k == "identity"]
        out["identity"] = {"calls": len(ids), "failed": sum(1 for g in ids if g.get("status") != "ok")}
        return out

    def _exclusions(self) -> dict[str, Any]:
        services = []
        for a, hits in sorted(self.services.items()):
            ident = self.identities.get(a) or {}
            services.append({"address": a, "name": provider_label(ident.get("name"), self.key), "category": provider_label(ident.get("category"), self.key),
                             "type": provider_label(ident.get("type"), self.key), "matched": hits})
        labelled = {}
        for a, ident in sorted(self.identities.items()):
            if a in self.services:
                continue
            name = provider_label(ident.get("name"), self.key)
            if name:
                labelled[a] = {"name": name, "category": provider_label(ident.get("category"), self.key)}
        return {"service_rule": SERVICE_RULE, "services": services, "labelled_not_services": labelled, "identity": dict(self.identity_plan),
                "app_list": [{"address": a, "reason": v["reason"]} for a, v in sorted(self.app.items())],
                "never_link": "this token's mint, SOL and wSOL, burn addresses, this token's pools and infrastructure rows (holders.json, and pools from the PDA reads when present), every address off the curve, the app and relayer list and labelled services"}

    def _stage3_summary(self, facts: list[dict[str, Any]]) -> dict[str, Any]:
        rows = []
        info = {a: (sol, n) for a, sol, n in self.candidates}
        users = {h["wallet"] for h in self.holders_used}
        found = collections.defaultdict(set)
        for f in facts:
            for kind, owner in f["reads"]:
                if kind in ("HB", "HN"):
                    for side in (f["from"], f["to"]):
                        if side in users:
                            found[owner].add(side)
        for a in self.hop_targets:
            reads = [self.reads.get((k, a)) for k in ("HB", "HN")]
            status = "read" if all(r and r.get("status") == "ok" for r in reads) else ("partly read" if any(r and r.get("status") == "ok" for r in reads) else "not read")
            rows.append({"wallet": a, "sol_with_holders": sol_text(info[a][0]), "holders_in_stage1": info[a][1], "holders_in_own_rows": len(found.get(a, ())),
                         "status": status, "more_pages": any(r and r.get("more") for r in reads)})
        return {"candidates": len(self.candidates), "services_skipped": sum(1 for a, _, _ in self.candidates if a in self.services),
                "hop_max_used": getattr(self, "hop_max", None), "read": rows}


# ----------------------------------------------------------------------------- status line and --present


def status_line(result: dict[str, Any]) -> str:
    credits = (result.get("request") or {}).get("credits", {}).get("total", 0)
    tail = f"{credits:,} Helius credits; {result.get('wall_s', 0)} s"
    stop = result.get("stopped_early")
    stopped = f"; RUN STOPPED EARLY: {stop['reason']}" if isinstance(stop, dict) and stop.get("reason") else ""
    if result.get("status") == "unavailable":
        return f"unavailable ({result.get('reason') or 'unknown'}; {tail}{stopped})"
    collected = _groups_collected(result)
    bursts = result.get("bursts") or []
    dust = sum(1 for b in bursts if isinstance(b, dict) and b.get("dust_spray"))
    pool_n = result.get("program_token_bursts_not_listed")
    pool = f"; {_n(pool_n, 'program-account token burst')} counted (pool trades, not listed)" if _int(pool_n) and pool_n > 0 else ""
    if result.get("status") == "empty":
        return f"empty ({EMPTY_BURSTS}{' and no links' if collected else ''}{pool}; {tail}{stopped})"
    groups = f"{len(result.get('clusters') or [])} linked groups (experimental), " if collected else ""
    return (f"ok ({groups}{len(bursts) - dust} funding bursts, {dust} dust sprays, {len(result.get('bursts_not_linked') or [])} program or service bursts{pool}; "
            f"{tail}{stopped})")


def _groups_collected(result: dict[str, Any]) -> bool:
    """Whether the run collected the experimental linked groups (--groups). A file from before the flag holds edges."""
    g = result.get("groups")
    return g.get("collected") is True if isinstance(g, dict) else isinstance(result.get("edges"), dict)


def _addr(value: Any) -> str:
    return value if is_address(value) else "(address not readable)"


def _sig(value: Any) -> str:
    return value if isinstance(value, str) and SIG_RE.match(value) else "(signature not readable)"


def _minutes(seconds: Any) -> str:
    return f"{cut(seconds / 60, 1)} min" if isinstance(seconds, (int, float)) and not isinstance(seconds, bool) and seconds >= 0 else "time unknown"


def _transfer_text(tr: dict[str, Any], rank_of: dict[str, int]) -> str:
    def who(a: Any) -> str:
        return f"#{rank_of[a]} {_addr(a)}" if a in rank_of else _addr(a)

    asset = "SOL" if tr.get("asset") == "SOL" else "of this token"
    amount = tr.get("amount") if isinstance(tr.get("amount"), str) and re.fullmatch(r"[0-9.]{1,48}", tr["amount"]) else "?"
    read = READ_TEXT.get(tr.get("read"), "a read")
    whose = f"#{rank_of[tr['read_of']]}" if tr.get("read_of") in rank_of else _addr(tr.get("read_of"))
    return f"{amount} {asset} {who(tr.get('from'))} -> {who(tr.get('to'))} at {utc_text(tr.get('t'))} (signature {_sig(tr.get('signature'))}; found in {whose}'s {read})"


def _valid_saved(data: Any) -> bool:
    return isinstance(data, dict) and data.get("schema") == SCHEMA and data.get("status") in ("ok", "empty", "unavailable") and is_address(data.get("mint"))


def present(run: Path, groups: bool = False) -> list[str]:
    """The block the synthesis prints. Reads only the saved files (followup/transfer_graph.json, and assessment.json for
    the Bubblemaps overlap when the saved file has none): no network, no key. A missing or damaged file reads as not read,
    never as a crash and never as "no clusters". By default it shows the bursts only; the linked groups are experimental
    (owner decision 2026-10-20, "Ship bursts, hold groups (Recommended)") and are shown, labelled, only with groups=True
    and only when the run collected them."""
    path = run / OUT_DIR / OUT_FILE
    data = _read_json(path)
    head = "Transfer graph (follow-up lane transfer_graph; Helius transfers read at scan time)"
    if not _valid_saved(data):
        return [f"{head}: not read ({OUT_DIR}/{OUT_FILE} " + ("missing" if not path.exists() else "unreadable") + ")", f"  {PRESENTATION_NOTE}"]
    show = groups and _groups_collected(data)
    try:
        lines = _present_lines(run, data, groups, show)
    except Exception:  # noqa: BLE001 - a damaged file is not read, never a crash
        lines = [f"{head}: not read (unreadable entry in {OUT_DIR}/{OUT_FILE})"]
    lines += [f"  {BURST_NOTE}"] + ([f"  {LINKED_NOTE} (experimental linked groups)"] if show else [])
    lines += [f"  cannot see: {CANNOT_SEE_BURSTS}" + (f"; for the experimental linked groups: {CANNOT_SEE}" if show else ""), f"  {PRESENTATION_NOTE}"]
    removed = pw.count(lines)
    if removed:
        lines.append("  " + pw.removed_line(removed))
    return lines


def _present_lines(run: Path, d: dict[str, Any], groups_requested: bool = False, show: bool = False) -> list[str]:
    req = d.get("request") or {}
    credits = req.get("credits") or {}
    settings = d.get("settings") or {}
    holders = d.get("holders") or []
    rank_of = {h["wallet"]: h["rank"] for h in holders if isinstance(h, dict) and is_address(h.get("wallet")) and _int(h.get("rank"))}
    skipped = d.get("holders_skipped") or []
    collected = _groups_collected(d)
    stage3 = d.get("stage3") or {}
    read3 = sum(1 for r in stage3.get("read") or [] if r.get("status") != "not read")
    cap = settings.get("max_credits")
    cap_text = f" of the {cap:,} cap" if _int(cap) else ""
    head = (f"Transfer graph (follow-up lane transfer_graph; Helius, {credits.get('total', 0):,} credits{cap_text}; top {len(holders)} holders read"
            + (f" ({len(skipped)} skipped: off the curve or not an address)" if skipped else "")
            + (f", {read3} funders and receivers read" if collected else "") + f"; {_minutes(d.get('wall_s'))})")
    if d["status"] == "unavailable":
        out = [f"{head}: not read (unavailable: {d.get('reason') if isinstance(d.get('reason'), str) and REASON_RE.match(d['reason']) else 'unknown'})"]
        if isinstance(settings.get("hop_max_note"), str) and d.get("reason") == "credit_estimate_over_cap":
            out.append(f"  {settings['hop_max_note']}")
        return out
    clusters = d.get("clusters") or []
    bursts = d.get("bursts") or []
    funding = [b for b in bursts if not b.get("dust_spray")]
    dust = [b for b in bursts if b.get("dust_spray")]
    others = d.get("bursts_not_linked") or []
    pool_n = d.get("program_token_bursts_not_listed")
    pool = (f"; {_n(pool_n, 'burst')} of this token from program accounts counted, not listed (pool trades, not funding)"
            if _int(pool_n) and pool_n > 0 else "")
    if not bursts and not others and not (show and clusters):
        out = [f"{head}: {EMPTY_BURSTS}{pool}" + (f"; linked groups (experimental): {EMPTY_NOTE}" if show else "") + "."]
    else:
        out = [f"{head}: {_n(len(funding), 'funding burst')}, {_n(len(dust), 'dust spray')}, {_n(len(others), 'program account or service burst')}{pool}"
               + (f"; {_n(len(clusters), 'linked group')} (experimental)" if show else "") + "."]
    stop = d.get("stopped_early")
    if isinstance(stop, dict) and stop.get("reason"):
        out.append(f"  RUN STOPPED EARLY: {hf.clean_text(stop['reason'], 80)}; what follows uses only the reads that finished.")
    wallet_of = {h["rank"]: h["wallet"] for h in holders}
    if funding:
        out.append(f"  Funding bursts (one wallet sent SOL or this token to {BURST_MIN_HOLDERS} or more of these holders within {BURST_WINDOW_S // 60} min; never capped):")
        for b in funding[:8]:
            out.append("    - " + _burst_text(b, wallet_of))
        if len(funding) > 8:
            out.append(f"    - and {len(funding) - 8} more bursts (all in {OUT_DIR}/{OUT_FILE})")
    else:
        out.append(f"  Funding bursts: none seen (no wallet sent SOL or this token to {BURST_MIN_HOLDERS} or more of these holders within {BURST_WINDOW_S // 60} min "
                   "in the transfers read" + (", apart from the dust sprays below" if dust else "") + ").")
    if dust:
        out.append(f"  Dust sprays (one wallet sent {BURST_MIN_HOLDERS} or more of these holders under 0.01 SOL each within {BURST_WINDOW_S // 60} min: advertising, "
                   "address poisoning or a farm's fee top-ups; shown, not counted as funding):")
        for b in dust[:6]:
            out.append("    - " + _burst_text(b, wallet_of))
        if len(dust) > 6:
            out.append(f"    - and {len(dust) - 6} more dust sprays (all in {OUT_DIR}/{OUT_FILE})")
    rounds = d.get("rounds") or []
    for r in rounds[:4]:
        what = "SOL" if r.get("asset") == "SOL" else "this token"
        kinds = " and ".join(KIND_WORDS.get(k, "senders") for k in r.get("kinds") or [])
        out.append(f"  Repeated rounds: {r['senders']} senders each sent {what} to about the same {r['typical_holders']} holders ({r['bursts']} bursts, "
                   f"{r['holders_union']} holders in all, {r['first'][:10]} to {r['last'][:10]} UTC; the senders are {kinds}).")
    if others:
        out.append("  Bursts from program accounts or labelled services (never counted as links: a program account is not a wallet, and a service serves many users):")
        for b in others[:6]:
            out.append("    - " + _burst_text(b, wallet_of))
        if len(others) > 6:
            out.append(f"    - and {len(others) - 6} more (all in {OUT_DIR}/{OUT_FILE})")
    skipped_pool = d.get("program_token_bursts_not_listed")
    if _int(skipped_pool) and skipped_pool:
        out.append(f"  Not listed: {_n(skipped_pool, 'burst')} of this token from program accounts (almost always another pool's authority filling buys: trades, not funding).")
    if show:
        out += _group_lines(run, d, settings, clusters, funding, rank_of)
    elif groups_requested:
        out.append(f"  {GROUPS_NOT_COLLECTED}")
    else:
        out.append(f"  {VALIDATION_LINE}")
    out += _reads_lines(d, credits, collected)
    return out


def _group_lines(run: Path, d: dict[str, Any], settings: dict[str, Any], clusters: list[dict[str, Any]], funding: list[dict[str, Any]], rank_of: dict[str, int]) -> list[str]:
    """The experimental linked groups (only with --groups): every line is labelled experimental."""
    out = [f"  Linked groups (experimental; on 10 live mints, 2026-10-20, pooled recall 11.4% and precision 3.1% against Bubblemaps pairs):"]
    if isinstance(settings.get("hop_max_note"), str):
        out.append(f"  {settings['hop_max_note']}.")
    overlap = d.get("bubblemaps_overlap") or {}
    if overlap.get("status") != "read":
        members, state = saved_members(run, d["mint"])
        if members is not None:
            overlap = bubblemaps_overlap(d, members, state, None)
            overlap["computed"] = "at present time from assessment.json"
    groups_bm = overlap.get("groups") or {} if overlap.get("status") == "read" else {}
    if not clusters:
        out.append(f"  Group (experimental): {EMPTY_NOTE} (direct transfers and shared outside wallets).")
    for c in clusters[:10]:
        counts = c.get("edge_counts") or {}
        links = []
        if counts.get("direct"):
            links.append(f"{counts['direct']} direct")
        if counts.get("via_wallet"):
            links.append(f"{counts['via_wallet']} via an outside wallet")
        if counts.get("via_wallet_pair"):
            links.append(f"{counts['via_wallet_pair']} via two outside wallets that moved SOL with each other")
        bm = groups_bm.get(str(c["id"])) or []
        bm_text = ("; matches " + ", ".join(f"Bubblemaps cluster {m['bm_cluster']} ({m['in_group']} of {m['seen_by_both']})" for m in bm)) if bm else ""
        out.append(f"  Group {c['id']} (experimental): {c['size']} wallets, {cut(c['share_pct_sum'])}% of supply; links: {', '.join(links) or 'none'}{bm_text}")
        members = c.get("members") or []
        for m in members[:12]:
            out.append(f"    - #{m['rank']} {_addr(m.get('wallet'))} {cut(m.get('share_pct'))}%")
        if len(members) > 12:
            out.append(f"    - and {len(members) - 12} more (all in {OUT_DIR}/{OUT_FILE})")
        lw = c.get("linking_wallets") or []
        if lw:
            out.append("    linking wallets: " + "; ".join(_linking_text(w) for w in lw[:5])
                       + (f"; and {len(lw) - 5} more" if len(lw) > 5 else ""))
        for e in (c.get("evidence") or [])[:EVIDENCE_PER_CLUSTER]:
            trs = "; ".join(_transfer_text(t, rank_of) for t in e.get("transfers") or [])
            label = ("direct" if e.get("type") == "direct" else f"via wallets {' and '.join(_addr(w) for w in e.get('wallets') or [])}"
                     if e.get("type") == "via_wallet_pair" else f"via wallet {_addr(e.get('wallet'))}")
            out.append(f"    evidence ({label}): {trs}")
    if len(clusters) > 10:
        out.append(f"  and {len(clusters) - 10} more linked groups (experimental; all in {OUT_DIR}/{OUT_FILE})")
    merged = d.get("merged_view") or []
    if funding and merged:
        big = merged[0]
        out.append(f"  Merged view (experimental, marked: linked groups plus funding bursts, dust sprays left out; a burst is a funding pattern, not a transfer "
                   f"between the holders): {_n(len(merged), 'group')}; largest {big['size']} wallets, {cut(big['share_pct_sum'])}% of supply.")
    out += [line.replace("  Bubblemaps overlap", "  Bubblemaps overlap (experimental)", 1) for line in _overlap_lines(overlap)]
    return out


KIND_WORDS = {"wallet": "wallets", "program_account": "program accounts", "service": "labelled services"}


def _n(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")


def _linking_text(w: dict[str, Any]) -> str:
    if isinstance(w.get("wallets"), list):
        return f"{' and '.join(_addr(a) for a in w['wallets'])} (moved SOL with each other; {w.get('holders')} holders)"
    moved = f"{w.get('sol')} SOL" if isinstance(w.get("sol"), str) else "this token only"
    return f"{_addr(w.get('wallet'))} ({w.get('holders')} holders, {moved})"


def _burst_text(b: dict[str, Any], wallet_of: dict[int, str]) -> str:
    kind = {"wallet": "", "program_account": " (program account, off the curve, not a wallet)", "service": " (labelled service)"}.get(b.get("kind"), "")
    sender = _addr(b.get("sender")) + (f" (holder #{b['sender_rank']})" if _int(b.get("sender_rank")) else "") + kind
    what = "SOL" if b.get("asset") == "SOL" else "this token"
    most = b.get("max_per_recipient_sol")
    dust = (f"; dust spray: every recipient got under 0.01 SOL, the most {most} SOL" if isinstance(most, str) and re.fullmatch(r"[0-9.a-z ]{1,40}", most)
            else "; dust spray") if b.get("dust_spray") else ""
    return (f"{sender} sent {what} to {b['count']} holders within {_minutes(b.get('span_s'))} at {utc_text(b.get('start_t'))} "
            f"({cut(b.get('share_pct_sum'))}% of supply{dust}; first transfer {_sig(b.get('first_signature'))})")


def _overlap_lines(o: dict[str, Any]) -> list[str]:
    if o.get("status") != "read":
        reason = o.get("reason") if isinstance(o.get("reason"), str) else "not read"
        return [f"  Bubblemaps overlap: not read ({hf.clean_text(reason, 160)})."]
    out = ["  Bubblemaps overlap (map members resolved by assess; holders both sides saw)" + (f" ({o['computed']})" if o.get("computed") else "") + ":"]
    for c in o.get("clusters") or []:
        if not c.get("members_read"):
            out.append(f"    - cluster {c.get('cluster')}: members not read")
            continue
        if not c.get("seen_by_both"):
            out.append(f"    - cluster {c.get('cluster')}" + (" (member list only)" if c.get("list_only") else "") + f" ({c.get('holder_rows', 0)} holder rows): none of its holders was read here")
            continue
        missed = [r for r in c.get("rows") or [] if r.get("why")]
        miss_text = "; ".join(f"{_addr(r.get('address')) if r.get('address') else hf.clean_text(r.get('shown'), 40)}: {r['why']}" for r in missed[:4])
        more = f"; and {len(missed) - 4} more" if len(missed) > 4 else ""
        where = f" in group {c['group']}" if c.get("group") is not None else ""
        name = f"cluster {c.get('cluster')}" + (" (member list only)" if c.get("list_only") else "")
        out.append(f"    - {name}: {c.get('matched', 0)} of {c.get('seen_by_both')} seen by both linked{where}" + (f" (missed: {miss_text}{more})" if missed else ""))
    p = o.get("pairs") or {}
    if p:
        rec = f"{cut(p['recall'] * 100, 1)}%" if isinstance(p.get("recall"), (int, float)) else "n/a"
        prec = f"{cut(p['precision'] * 100, 1)}%" if isinstance(p.get("precision"), (int, float)) else "n/a"
        out.append(f"    pairs within the holders both saw (rank up to {BM_WINDOW_RANK}): Bubblemaps {p.get('bubblemaps')}, graph {p.get('graph')}, "
                   f"both {p.get('shared')} (Bubblemaps pairs also linked here: {rec}; graph pairs also in one Bubblemaps cluster: {prec})")
    return out


def _reads_lines(d: dict[str, Any], credits: dict[str, Any], collected: bool = True) -> list[str]:
    reads = d.get("reads") or {}
    s1, s3 = reads.get("stage1") or {}, reads.get("stage3") or {}
    hop = (f"funders and receivers {s3.get('ok', 0)} of {s3.get('planned', 0)} answered ({s3.get('failed', 0)} failed, {s3.get('not_reached', 0)} not reached)"
           if collected else "one hop out: not read (linked groups off; it changed no burst on any recorded mint)")
    out = [f"  Reads: holders {s1.get('ok', 0)} of {s1.get('planned', 0)} answered ({s1.get('failed', 0)} failed, {s1.get('not_reached', 0)} not reached); {hop}."]
    busy = (s1.get("busy_reads") or 0) + (s3.get("busy_reads") or 0)
    if busy:
        ex = [*(s1.get("busy_examples") or []), *(s3.get("busy_examples") or [])][:3]
        out.append(f"  Busy wallets: {busy} reads with more pages covered under 1 h (for example " + "; ".join(f"{_addr(e.get('wallet'))} {e.get('minutes')} min" for e in ex) + ").")
    stage3 = f", stage 3 (one hop out) {credits.get('stage3', 0):,}" if collected else ""
    out.append(f"  Credits: stage 1 (holders) {credits.get('stage1', 0):,}, identity {credits.get('identity', 0):,}{stage3}; total {credits.get('total', 0):,}; "
               f"wall time {_minutes(d.get('wall_s'))}.")
    return out


# ----------------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Funding bursts among the top holders from Helius transfer rows, and with --groups the experimental linked "
                                                 f"groups (follow-up lane transfer_graph; presentation only); writes {OUT_DIR}/{OUT_FILE}, or prints the block "
                                                 "offline with --present RUN_DIR.")
    parser.add_argument("mint", nargs="?")
    parser.add_argument("--out", metavar="RUN_DIR", help="run folder: holders.json (and assessment.json, when present) are read from it")
    parser.add_argument("--present", metavar="RUN_DIR", help="offline: print the block from a saved run folder (no network, no key)")
    parser.add_argument("--top", type=int, default=DEFAULT_TOP, help=f"ordinary holders to read, 1-1000 (default {DEFAULT_TOP})")
    parser.add_argument("--groups", action="store_true", help="also collect (or, with --present, show) the experimental linked groups: stage 3 runs, about "
                                                              "12,000 credits instead of about 6,000 (owner decision 2026-10-20: bursts by default, groups held)")
    parser.add_argument("--hop-max", type=int, default=DEFAULT_HOP_MAX, help=f"with --groups: counterparties read one hop out, 0-1000 (default {DEFAULT_HOP_MAX}; lowered first when the budget is short)")
    parser.add_argument("--max-credits", type=int, default=DEFAULT_MAX_CREDITS, help=f"hard Helius credit cap for this run (default {DEFAULT_MAX_CREDITS:,})")
    parser.add_argument("--recent-sol-top", type=int, default=DEFAULT_RECENT_SOL_TOP, metavar="N",
                        help=f"read the newest 100 SOL transfers (call C, 10 credits each) of the first N holders read, 0-1000 (default {DEFAULT_RECENT_SOL_TOP}; 0 = off)")
    parser.add_argument("--recent-sol", action="store_true", help="read call C for every holder read (the same as --recent-sol-top equal to --top)")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help=f"reads at once, 1-{MAX_WORKERS} (default {DEFAULT_WORKERS}); all share one pace of at most {REQUEST_RATE_CAP_PER_S} requests/s")
    parser.add_argument("--env-file", help="path to the repository .env (HELIUS_API_KEY in the environment is used first)")
    args = parser.parse_args(argv)
    if args.present is not None:
        if args.mint or args.out:
            print("error: --present takes only the run folder", file=sys.stderr)
            return 2
        run = Path(args.present)
        if not run.is_dir():
            print("error: --present is not a run folder", file=sys.stderr)
            return 2
        for line in present(run, groups=args.groups):
            print(line)
        return 0
    if not is_address(args.mint):
        print("error: mint is not a valid base58 Solana address", file=sys.stderr)
        return 2
    if not args.out:
        print("error: --out is required", file=sys.stderr)
        return 2
    if (not 1 <= args.top <= 1000 or not 0 <= args.hop_max <= 1000 or not 0 <= args.recent_sol_top <= 1000 or not 1 <= args.max_credits <= 1_000_000
            or not 1 <= args.workers <= MAX_WORKERS):
        print(f"error: --top 1-1000, --hop-max 0-1000, --recent-sol-top 0-1000, --max-credits 1-1,000,000, --workers 1-{MAX_WORKERS}", file=sys.stderr)
        return 2
    run = Path(args.out)
    try:
        (run / OUT_DIR).mkdir(parents=True, exist_ok=True)
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    try:
        env_file = None if os.environ.get(KEY_NAME) else hf.find_env_file(args.env_file)
        key = hf.load_key(env_file)
    except hf.ForensicsError as err:  # the forensics loader's fixed texts; never the value
        result = _base(args.mint, iso(time.time()))
        result["reason"] = "key_format" if "unexpected format" in str(err) else "missing_key"
        return _save(run, result, None)
    graph = GraphRun(args.mint, run, key=key, top=args.top, hop_max=args.hop_max, max_credits=args.max_credits,
                     recent_sol_top=args.top if args.recent_sol else args.recent_sol_top, workers=args.workers, groups=args.groups)
    code = 0
    try:
        result = graph.run()
    except KeyboardInterrupt:
        result, code = graph.finish("interrupted (Ctrl-C)"), 130
    except Exception:  # noqa: BLE001 - never a traceback: an error text could carry a request
        try:
            result = graph.finish("unexpected error")
        except Exception:  # noqa: BLE001
            result = _base(args.mint, iso(time.time()))
            result["reason"] = "unexpected_error"
    return _save(run, result, key, code)


def _save(run: Path, result: dict[str, Any], key: str | None, code: int = 0) -> int:
    text = json.dumps(result, indent=1)
    if shares_key_piece(text, key):  # last guard: the key never reaches the file
        result = _base(result.get("mint"), result.get("fetched_at") or iso(time.time()))
        result["reason"] = "key_echo_refused"
        text = json.dumps(result, indent=1)
    try:
        (run / OUT_DIR / OUT_FILE).write_text(text, encoding="utf-8")
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    print(status_line(result))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
