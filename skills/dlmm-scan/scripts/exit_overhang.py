#!/usr/bin/env python3
"""Exit overhang for dlmm-scan (HS-OVERHANG-T1): the owner's rug test, offline, from files the scan already saved.

Owner (2026-10-25): pump contracts are standard, "so the only way they can rug is to hold a huge token reserve from a very
low price or marketcap point". This script answers that before entry: do wallets holding bags bought far below today's
price outweigh the main pool's tokens?

Method (the replay in the DLMM evidence HOLDER-SCAN-OVERHANG-20261025/overhang_check.py, same definitions):
- price at scan = median of GMGN's usd_value / balance; supply = median of balance / amount_percentage (all rows with
  usable values; GMGN's numbers, its top 100 only);
- wallets = GMGN rows minus addr_type 2 (pools), minus holders.json infrastructure rows and pool_addresses (pools and the
  bonding curves of spin-off coins quoted in this token);
- entry multiple = price / GMGN's avg_cost, only when avg_cost is a number above 0; a wallet without one has no cost basis
  and is shown apart, never in the ratio;
- dev-sent bags (DS-DEV-BAGS-T1, owner decision of 2026-10-27, "Count at zero cost (Recommended)"): a wallet with no cost
  basis or with GMGN's transfer_in tag, not already at or below 1/2 by its average buy, whose transfers read by the follow-up
  lane wallet_rpc_reads (followup/wallet_rpc_reads.json) came from this token's dev wallets (followup/create_slot_trace.json
  create_tx.dev_wallets, only when the trace says ok or empty) counts at zero cost: the smaller of its share and the total the
  dev sent it (as a share of the median supply) joins the ratio's numerator; dev not known, the lane missing or not read:
  nothing new is counted and the block says why;
- main pool = the holders.json share of the creator_fees.json pool whose base_mint is the token and whose status is
  identified (the canonical PumpSwap pool); if none, the largest holders.json infrastructure row in pool_addresses, named
  as a fallback;
- ratio = share held by wallets with an entry multiple of 2 or more, plus the dev-sent bags' zero-cost shares, divided by the
  main pool's share.

First printed line, marked [for the executive summary]: the third flag line, "EXIT OVERHANG: DANGER (provisional)",
"CAUTION (provisional)", "not raised (not a safety signal)" or "not read (<reason>)"; a main pool found by the fallback is
named in the flag line itself ("main pool by fallback: <reason>; the ratio may be too high or too low"). Then the block "Exit overhang
(cheap-entry bags vs the main pool; GMGN top 100; provisional)". SUMMARY.md copies the flag line without the mark right
after the two engine FLAG lines, and the block into the sources read after the GMGN block, as printed.

A PRESENTATION FLAG ONLY: never an engine input, never passed to assess, never counted toward NO_ALARM; it never changes
the forensics or analysis FLAG, verdict or threshold. Reads gmgn_holder_pnl.json, holders.json, creator_fees.json and,
when present, followup/create_slot_trace.json and followup/wallet_rpc_reads.json; writes nothing. It prints only validated
addresses, signatures, numbers, fixed phrases and reason codes (no provider text). No network, no key; standard library only; Python >= 3.10.
Usage: exit_overhang.py --present <RUN>. Exit 0 whenever the run folder exists (a missing or bad file reads "not read
(<reason>)"); exit 2 only for a bad command line.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import re
import statistics
import sys
from pathlib import Path
from typing import Any

# ----------------------------------------------------------------------------- PROVISIONAL (unvalidated)
# Owner decisions of 2026-10-25 (HS-OVERHANG-T1): DANGER when the cheap-entry supply is 2x the main pool's tokens or more,
# CAUTION at 1x or more. Tested on 3 coins that dumped (mil, Marvin, $BILLIONS: 3.6x, 4.1x, 3.2x) and 0 that held; the base
# rate on coins that did not dump is unknown. Keep these provisional until outcomes with negative controls are recorded.
OVERHANG_DANGER_RATIO = 2.0         # cheap-entry supply / main pool's tokens at or over this: DANGER (provisional)
OVERHANG_CAUTION_RATIO = 1.0        # at or over this: CAUTION (provisional); below: not raised (not a safety signal)
OVERHANG_ENTRY_MULTIPLE = 2.0       # cheap entry: GMGN's average buy at or below 1/2 of the price at scan
OVERHANG_DEEP_ENTRY_MULTIPLE = 3.0  # also shown: at or below 1/3 of the price (information, never a bar)
BARS_TESTED = "tested on 3 coins that dumped and 0 that held"
# ----------------------------------------------------------------------------- end PROVISIONAL

SUMMARY_MARK = "[for the executive summary] "  # the same text as gmgn_rows.PNL_SUMMARY_MARK (this file imports nothing from the skill)
FLAG_HEAD = "EXIT OVERHANG"
TITLE = "Exit overhang (cheap-entry bags vs the main pool; GMGN top 100; provisional)"
NOT_RAISED = "not raised (not a safety signal)"
TOP_BAGS = 5
PNL_FILE = "gmgn_holder_pnl.json"
PNL_SCHEMA = "holder-scan-gmgn-holder-pnl/1"
HOLDERS_FILE = "holders.json"
FEES_FILE = "creator_fees.json"
FEES_SCHEMA = "holder-scan-creator-fees/1"
TRACE_FILE = "followup/create_slot_trace.json"
TRACE_SCHEMA = "holder-scan-create-slot/1"
READS_FILE = "followup/wallet_rpc_reads.json"   # the follow-up lane wallet_rpc_reads (DS-DEV-BAGS-T1)
READS_SCHEMA = "holder-scan-wallet-rpc-reads/1"
DEV_DECISION = "owner decision 2026-10-27: \"Count at zero cost (Recommended)\""
DEV_HEAD = "  dev-sent bags (counted at zero cost; follow-up lane wallet_rpc_reads, public Solana RPC; " + DEV_DECISION + ")"
SIGNATURE_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{64,90}$")
MAX_RAW = 2 ** 64 - 1               # an spl-token amount is a u64 (provider-docs current/spltoken/layouts.md); larger is a damaged value
MAX_DECIMALS = 18
POOL_ADDR_TYPE = 2                  # GMGN addr_type 2 = DEX pool or exchange
NEEDED_FIELDS = ("amount_percentage", "addr_type", "avg_cost", "balance", "usd_value")
SOLANA_ADDRESS_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
REASON_RE = re.compile(r"[^a-z0-9_]")
WIB = dt.timezone(dt.timedelta(hours=7))
PRESENTATION_LINE = ("presentation flag only: never an engine input, never passed to assess, never counted toward NO_ALARM; "
                     "it never changes the forensics or analysis FLAG, verdict or threshold")


class NotRead(Exception):
    """The flag cannot be read; the reason is printed as "not read (<reason>)"."""


class Unreadable(Exception):
    """A value in followup/wallet_rpc_reads.json does not validate (Repair R1): only the dev-sent line reads not read and
    nothing new is counted; the rest of the flag line and the block print as without the file."""


def _number(value: Any) -> float | None:
    """A finite JSON number as a float; text, a bool, NaN, inf or a huge integer is None (never 0)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def _positive(value: Any) -> float | None:
    number = _number(value)
    return number if number is not None and number > 0 else None


def _address(value: Any) -> str | None:
    return value if isinstance(value, str) and SOLANA_ADDRESS_RE.fullmatch(value) else None


def _reason(value: Any) -> str:
    """A reason code read back from a saved file: lower-case letters, digits and _ only."""
    return (REASON_RE.sub("", value.lower())[:64] if isinstance(value, str) else "") or "unknown"


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None


def _when(value: Any) -> str:
    try:
        utc = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return "time unknown"
    return f"{utc:%Y-%m-%d %H:%M} UTC = {utc.astimezone(WIB):%Y-%m-%d %H:%M} WIB"


def _usd(value: float) -> str:
    """Three significant digits with k / M / B ("$1.28M", "$224k"), as gmgn_rows.py prints market caps."""
    value = float(f"{value:.3g}")
    for scale, suffix in ((1e9, "B"), (1e6, "M"), (1e3, "k")):
        if abs(value) >= scale:
            return f"${value / scale:.3g}{suffix}"
    return f"${value:.3g}"


def _price(value: float) -> str:
    """A token price with three significant digits and no exponent ("$0.000456")."""
    return f"${value:.{max(2, 2 - math.floor(math.log10(value)))}f}" if value > 0 else "$0"


def _pct(value: float) -> str:
    return f"{value:.2f}%"


def _wallets(n: int) -> str:
    return f"{n} wallet{'' if n == 1 else 's'}"


def _times(ratio: float) -> str:
    """The ratio to 1 decimal ("3.2x"); a ratio just under a bar is cut, never rounded up onto it ("1.99x", not "2.0x")."""
    text = f"{ratio:.1f}"
    if any(ratio < bar <= float(text) for bar in (OVERHANG_DANGER_RATIO, OVERHANG_CAUTION_RATIO)):
        text = f"{math.floor(ratio * 100 + 1e-9) / 100:.2f}"
    return f"{text}x"


def _share(r: dict[str, Any]) -> float:
    return (r["share"] or 0.0) * 100


def _total(rows: list[dict[str, Any]]) -> float:
    return sum(_share(r) for r in rows)


def _load_gmgn(run: Path) -> dict[str, Any]:
    path = run / PNL_FILE
    data = _read(path)
    if not path.exists():
        raise NotRead(f"{PNL_FILE} missing")
    if not (isinstance(data, dict) and data.get("schema") == PNL_SCHEMA and data.get("status") in ("ok", "empty", "unavailable")):
        raise NotRead(f"{PNL_FILE} unreadable")
    if data["status"] != "ok":
        raise NotRead(f"GMGN {data['status']}: {_reason(data.get('reason'))}")
    if _address(data.get("mint")) is None or not isinstance(data.get("rows"), list):
        raise NotRead(f"{PNL_FILE} unreadable")
    return data


def _gmgn_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    """The saved rows, every value validated again: a row without a valid address or a repeated address is skipped; a
    malformed number is None (never 0)."""
    raw = [r for r in data["rows"] if isinstance(r, dict)]
    if not raw:
        raise NotRead("no GMGN rows")
    missing = data.get("fields_missing") if isinstance(data.get("fields_missing"), list) else []
    gone = [f for f in NEEDED_FIELDS if f in missing or not any(f in r for r in raw)]
    if gone:
        raise NotRead("field missing: " + ", ".join(gone))
    rows, seen = [], set()
    for r in raw:
        address = _address(r.get("address"))
        if address is None or address in seen:
            continue
        seen.add(address)
        share = _number(r.get("amount_percentage"))
        addr_type = r.get("addr_type")
        rows.append({"address": address, "share": share if share is not None and 0 <= share <= 1 else None,
                     "pool": isinstance(addr_type, int) and not isinstance(addr_type, bool) and addr_type == POOL_ADDR_TYPE,
                     "avg_cost": _positive(r.get("avg_cost")), "balance": _positive(r.get("balance")),
                     "usd_value": _positive(r.get("usd_value")), "transfer_in": r.get("transfer_in") is True})
    return rows


def _load_holders(run: Path, mint: str) -> dict[str, Any]:
    path = run / HOLDERS_FILE
    data = _read(path)
    if not path.exists():
        raise NotRead(f"{HOLDERS_FILE} missing")
    if not (isinstance(data, dict) and isinstance(data.get("top_holders"), list)):
        raise NotRead(f"{HOLDERS_FILE} unreadable")
    if data.get("mint") != mint:
        raise NotRead(f"{HOLDERS_FILE} is for another mint")
    return data


def _holder_shares(holders: dict[str, Any]) -> tuple[dict[str, float], dict[str, float], set[str]]:
    """(share of every holders.json top row, share of its infrastructure rows, pool_addresses), shares in percent."""
    shares: dict[str, float] = {}
    infra: dict[str, float] = {}
    for r in holders["top_holders"]:
        wallet = _address(r.get("wallet")) if isinstance(r, dict) else None
        share = _number(r.get("share_pct")) if wallet else None
        if wallet is None or share is None or share < 0 or wallet in shares:
            continue
        shares[wallet] = share
        if r.get("infrastructure") is True:
            infra[wallet] = share
    pools = holders.get("pool_addresses")
    return shares, infra, {a for a in pools if _address(a)} if isinstance(pools, list) else set()


def _canonical_pool(run: Path, mint: str) -> tuple[str | None, str]:
    """(the creator_fees.json pool whose base_mint is the token and whose status is identified, or None; why not)."""
    path = run / FEES_FILE
    data = _read(path)
    if not path.exists():
        return None, f"{FEES_FILE} missing"
    if not (isinstance(data, dict) and data.get("schema") == FEES_SCHEMA and data.get("status") in ("ok", "empty", "unavailable")):
        return None, f"{FEES_FILE} unreadable"
    if data.get("mint") != mint:
        return None, f"{FEES_FILE} is for another mint"
    if data["status"] != "ok":
        return None, f"creator_fees {data['status']}: {_reason(data.get('reason'))}"
    pools = data.get("pools") if isinstance(data.get("pools"), list) else []
    for pool in pools:
        if isinstance(pool, dict) and pool.get("status") == "identified" and pool.get("base_mint") == mint and _address(pool.get("address")):
            return pool["address"], ""
    return None, "no identified pool of this token in creator_fees"


def main_pool(run: Path, mint: str, shares: dict[str, float], infra: dict[str, float], pools: set[str]) -> tuple[str, float, str, str | None]:
    """(address, share in percent, how it was found, the fallback reason or None when creator_fees named the pool). Raises
    NotRead("no pool reserve found") when neither the creator_fees canonical pool nor a holders.json pool row gives a share
    above 0."""
    address, why = _canonical_pool(run, mint)
    if address is not None:
        if (shares.get(address) or 0) > 0:
            return address, shares[address], "found through creator_fees: the canonical PumpSwap pool of this token", None
        why = "the creator_fees canonical pool has no share in the holders.json rows"
    candidates = [(share, wallet) for wallet, share in infra.items() if wallet in pools and share > 0]
    if not candidates:
        raise NotRead("no pool reserve found")
    share, wallet = max(candidates)
    return wallet, share, (f"fallback: the largest holders.json pool row ({why}); it could be another pool or a spin-off coin's "
                           "bonding curve"), why


def _create_slot(run: Path, mint: str, holders: dict[str, Any]) -> str:
    """The create-slot line: buyers of the create slot (and the next 2 slots) still holding, by holders.json."""
    path = run / TRACE_FILE
    data = _read(path)
    if not path.exists():
        return f"create-slot trace not read ({TRACE_FILE} missing)"
    if not (isinstance(data, dict) and data.get("schema") == TRACE_SCHEMA and data.get("status") in ("ok", "empty", "unavailable")):
        return f"create-slot trace not read ({TRACE_FILE} unreadable)"
    if data.get("mint") != mint:
        return f"create-slot trace not read ({TRACE_FILE} is for another mint)"
    if data["status"] == "unavailable":
        return f"create-slot trace not read (create_slot_trace unavailable: {_reason(data.get('reason'))})"
    balances = holders.get("owner_balances")
    if not isinstance(balances, dict):
        return f"create-slot trace read, holdings not read ({HOLDERS_FILE} has no owner_balances)"
    values = [v for v in (_number(b) for b in balances.values()) if v is not None and v > 0]
    total = sum(values)
    trace = data.get("trace") if isinstance(data.get("trace"), dict) else {}
    entries = [w for w in (trace.get("wallets") if isinstance(trace.get("wallets"), list) else []) if isinstance(w, dict) and _address(w.get("wallet"))]
    traced = {w["wallet"] for w in entries}
    dev = " (dev included)" if any(w.get("role") == "dev" for w in entries) else ""  # C4: only when the trace names a dev
    holding = [w for w in traced if (_positive(balances.get(w)) or 0) > 0]
    share = sum(_positive(balances.get(w)) or 0.0 for w in holding) / total * 100 if total else 0.0
    return (f"create-slot buyers still holding: {len(holding)} of {len(traced)} traced wallets{dev}, {_pct(share)} of supply "
            "(holders.json); entry near zero; counted above only when GMGN has their cost")


def _count(value: Any) -> int | None:
    """A whole JSON number of 0 or more (an amount in base units, a count, a time); anything else is None (never 0)."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _unix_when(value: Any) -> str:
    ts = _count(value)
    if ts is None or ts > 7_258_118_400:
        return "time unknown"
    return _when(dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat())


def _tokens(value: float) -> str:
    """A token amount cut toward zero to whole tokens ("75,000,000"); a positive amount under 1 reads "under 1"."""
    return f"{math.floor(value):,}" if value >= 1 else "under 1"


def _dev_wallets(run: Path, mint: str) -> tuple[list[str], str | None]:
    """This token's dev wallets from the create-slot trace (create_tx.dev_wallets, only when it says ok or empty), or ([],
    why not)."""
    path = run / TRACE_FILE
    data = _read(path)
    if not path.exists():
        return [], f"{TRACE_FILE} missing"
    if not (isinstance(data, dict) and data.get("schema") == TRACE_SCHEMA and data.get("status") in ("ok", "empty", "unavailable")):
        return [], f"{TRACE_FILE} unreadable"
    if data.get("mint") != mint:
        return [], f"{TRACE_FILE} is for another mint"
    if data["status"] == "unavailable":
        return [], f"create_slot_trace unavailable: {_reason(data.get('reason'))}"
    create = data.get("create_tx") if isinstance(data.get("create_tx"), dict) else {}
    listed = create.get("dev_wallets") if isinstance(create.get("dev_wallets"), list) else []
    dev = list(dict.fromkeys(w for w in listed if _address(w)))
    return (dev, None) if dev else ([], "the create-slot trace names no creator")


def _wallet_reads(run: Path, mint: str) -> tuple[dict[str, Any] | None, str | None]:
    """The follow-up lane wallet_rpc_reads' saved file when it is this lane's script output for this mint and says ok or empty;
    else (None, why not). A hand-written file of another shape is unreadable."""
    path = run / READS_FILE
    data = _read(path)
    if not path.exists():
        return None, f"{READS_FILE} missing"
    if not (isinstance(data, dict) and data.get("schema") == READS_SCHEMA and data.get("status") in ("ok", "empty", "unavailable")
            and data.get("presentation_only") is True and isinstance(data.get("wallets"), list)):
        return None, f"{READS_FILE} unreadable"
    if data.get("mint") != mint:
        return None, f"{READS_FILE} is for another mint"
    if data["status"] == "unavailable":
        return None, f"wallet_rpc_reads unavailable: {_reason(data.get('reason'))}"
    return data, None


def _raw(value: Any, low: int = 0) -> int:
    """An amount in base units: a whole JSON number from `low` to MAX_RAW, else Unreadable (never 0, never an overflow)."""
    number = _count(value)
    if number is None or not low <= number <= MAX_RAW:
        raise Unreadable
    return number


def _dev_transfers(entry: dict[str, Any], dev: set[str]) -> list[dict[str, Any]]:
    """The incoming transfers of one read wallet whose senders include this token's dev wallets: per transfer the smaller of
    what the wallet received and what the dev wallets alone sent in it (tokens; another sender's part never counts), its
    time, signature and the dev sender. A sender whose owner was not recorded is never the dev. Raises Unreadable on any
    value that does not validate (the lane writes none: the file was damaged)."""
    events = entry.get("events")
    if not isinstance(events, list):
        raise Unreadable
    found = []
    for e in events:
        if not isinstance(e, dict):
            raise Unreadable
        if e.get("direction") != "in":
            continue
        signature, senders = e.get("signature"), e.get("senders")
        places = _count(e.get("decimals"))
        if not (isinstance(signature, str) and SIGNATURE_RE.fullmatch(signature)) or places is None or places > MAX_DECIMALS or not isinstance(senders, list):
            raise Unreadable
        raw, sent, sender = _raw(e.get("amount_raw"), 1), 0, None
        for s in senders:
            if not isinstance(s, dict):
                raise Unreadable
            owner, amount = s.get("owner"), _raw(s.get("amount_raw"))
            if owner is not None and not _address(owner):
                raise Unreadable
            if isinstance(owner, str) and owner in dev:
                sent += amount
                sender = sender or owner
        part = min(raw, sent)
        if part > 0:
            found.append({"tokens": part / 10 ** places, "time": e.get("block_time"), "signature": signature, "sender": sender})
    return found


def dev_bags(run: Path, mint: str, wallets: list[dict[str, Any]], cheap: list[dict[str, Any]], supply: float) -> dict[str, Any]:
    """The dev-sent bags (DS-DEV-BAGS-T1): among the wallets with no GMGN cost basis or GMGN's transfer_in tag that the lane
    read, those whose incoming transfers came from this token's dev wallets. Each counts at zero cost: the smaller of its share
    and the total the dev sent it (a share of the median supply). One already at or below 1/2 by its average buy is named
    and adds nothing. Dev not known or the lane not read: no bag, with the reason."""
    out: dict[str, Any] = {"why": None, "dev": [], "bags": [], "already": [], "read": 0, "fetched_at": None}
    reads, why = _wallet_reads(run, mint)
    if reads is None:
        return {**out, "why": why}
    dev, why = _dev_wallets(run, mint)
    if not dev:
        return {**out, "why": f"this token's dev not known: {why}"}
    entries: dict[str, dict[str, Any]] = {}
    for e in reads["wallets"]:
        if not isinstance(e, dict) or not _address(e.get("address")):
            raise Unreadable
        if e.get("status") in ("read", "partial"):  # an unavailable wallet counts nothing, whatever it carries
            entries.setdefault(e["address"], e)
    cheap_ids = {r["address"] for r in cheap}
    out.update(dev=dev, read=len(entries), fetched_at=reads.get("fetched_at"))
    for r in wallets:
        entry = entries.get(r["address"])
        if entry is None or (r["avg_cost"] and not r["transfer_in"]):
            continue
        sent = _dev_transfers(entry, set(dev))
        if not sent:
            continue
        bag = {"row": r, "entry": entry, "sent": sent, "tokens": sum(s["tokens"] for s in sent)}
        if r["address"] in cheap_ids:
            out["already"].append(bag)
            continue
        bag["sent_pct"] = bag["tokens"] / supply * 100
        bag["counted"] = min(_share(r), bag["sent_pct"]) if r["share"] is not None else None
        out["bags"].append(bag)
    out["bags"].sort(key=lambda b: -(b["counted"] or 0.0))  # stable: GMGN's order on equal shares
    return out


def measure(run: Path) -> dict[str, Any]:
    """Every number of the flag and the block, from the saved files. Raises NotRead with the reason."""
    data = _load_gmgn(run)
    mint = data["mint"]
    rows = _gmgn_rows(data)
    holders = _load_holders(run, mint)
    shares, infra, pools = _holder_shares(holders)
    pool_address, pool_pct, how, fallback = main_pool(run, mint, shares, infra, pools)
    prices = [r["usd_value"] / r["balance"] for r in rows if r["usd_value"] and r["balance"]]
    supplies = [r["balance"] / r["share"] for r in rows if r["balance"] and r["share"]]
    if not prices or not supplies:
        raise NotRead("price at scan not read (no GMGN row with a balance, a USD value and a share)")
    price, supply = statistics.median(prices), statistics.median(supplies)
    excluded = set(infra) | pools | {pool_address}
    wallets = [r for r in rows if not r["pool"] and r["address"] not in excluded]
    if not wallets:
        raise NotRead("no wallet rows after removing pools")
    costed = [r for r in wallets if r["avg_cost"]]
    if not costed:
        raise NotRead("GMGN gave no usable average buy")
    for r in costed:
        r["multiple"] = round(price / r["avg_cost"], 9)  # float noise never moves an entry exactly at a bar
    cheap = [r for r in costed if r["multiple"] >= OVERHANG_ENTRY_MULTIPLE]
    deep = [r for r in costed if r["multiple"] >= OVERHANG_DEEP_ENTRY_MULTIPLE]
    try:
        dev = dev_bags(run, mint, wallets, cheap, supply)
    except Exception:  # noqa: BLE001 - Repair R1: a damaged wallet_rpc_reads value reads only the dev-sent line as not read, never the whole flag
        dev = {"why": "wallet_rpc_reads values unreadable", "dev": [], "bags": [], "already": [], "read": 0, "fetched_at": None}
    counted = [b for b in dev["bags"] if b["counted"]]
    zero = sum(b["counted"] for b in counted)
    sent_ids = {b["row"]["address"] for b in counted}
    ratio = round((_total(cheap) + zero) / pool_pct, 9)  # rounded far below the printed digits, so float noise never moves a bar
    return {"mint": mint, "fetched_at": data.get("fetched_at"), "rows": rows, "price": price, "supply": supply, "mcap": price * supply,
            "pool": pool_address, "pool_pct": pool_pct, "pool_how": how, "pool_fallback": fallback, "pool_rows": len(infra), "pool_rows_pct": sum(infra.values()),
            "wallets": wallets, "cheap": cheap, "deep": deep, "ratio": ratio, "cheap_ratio": round(_total(cheap) / pool_pct, 9),
            "deep_ratio": round(_total(deep) / pool_pct, 9), "dev": dev, "dev_counted": counted, "dev_pct": zero,
            "no_basis": [r for r in wallets if not r["avg_cost"] and r["address"] not in sent_ids], "transfer_in": [r for r in wallets if r["transfer_in"]],
            "create_slot": _create_slot(run, mint, holders)}


def level(ratio: float) -> str:
    if ratio >= OVERHANG_DANGER_RATIO:
        return "DANGER (provisional)"
    if ratio >= OVERHANG_CAUTION_RATIO:
        return "CAUTION (provisional)"
    return NOT_RAISED


def _bag_line(rank: int, r: dict[str, Any], supply: float) -> str:
    text = (f"    #{rank} {r['address']}: {_pct(_share(r))} of supply, entry {_usd(r['avg_cost'] * supply)} market cap, "
            f"bought {r['multiple']:.1f}x below today's price")
    return text + ("; transfer_in (GMGN tag): entry may be cheaper than shown" if r["transfer_in"] else "")


def _history(entry: dict[str, Any], transfers: int) -> str:
    """How much of the wallet's token-account history the lane read; "the only transfer into it" only when it read all of it."""
    read, seen, incoming = _count(entry.get("transactions_read")), _count(entry.get("successful_signatures")), _count(entry.get("incoming"))
    if entry.get("complete") is True and read is not None:
        if incoming == 1 and transfers == 1 and entry.get("outgoing_seen") is False:
            return "its whole token-account history was read: the only transfer into it"
        return f"its whole token-account history was read ({read} transaction{'' if read == 1 else 's'})"
    if entry.get("history_start_reached") is not True:
        return "its history was not read to its start (more than one page of signatures): earlier transfers are not seen"
    return (f"its history was read in part ({read if read is not None else 'some'} of {seen if seen is not None else 'its'} transactions, the oldest): "
            "later transfers are not seen")


def _sends(bag: dict[str, Any]) -> str:
    return "; ".join(f"{_tokens(s['tokens'])} tokens from {s['sender']} at {_unix_when(s['time'])}, signature {s['signature']}" for s in bag["sent"])


def _dev_bag_line(bag: dict[str, Any]) -> str:
    r = bag["row"]
    tags = ", ".join(x for x in ("no GMGN cost basis" if not r["avg_cost"] else "", "GMGN transfer_in tag" if r["transfer_in"] else "") if x)
    share = f"{_pct(_share(r))} of supply (GMGN)" if r["share"] is not None else "share of supply not read (GMGN)"
    if bag["counted"] is None:
        counted = "its share is not read: not counted"
    else:
        counted = f"counted {_pct(bag['counted'])} at zero cost"
        if _share(r) - bag["sent_pct"] >= 0.005:
            counted += f"; the rest of its share ({_pct(_share(r) - bag['sent_pct'])}) did not come from the dev in the transfers read: not counted"
    return (f"    {r['address']}: {share}; {tags}; the dev sent it {_tokens(bag['tokens'])} tokens ({_pct(bag['sent_pct'])} of supply): {_sends(bag)}; "
            f"{counted}; {_history(bag['entry'], len(bag['sent']))}")


def _dev_lines(m: dict[str, Any]) -> list[str]:
    """The dev-sent bags lines (DS-DEV-BAGS-T1): the reason when nothing could be counted, else each bag."""
    d, counted = m["dev"], m["dev_counted"]
    if d["why"]:
        return [f"{DEV_HEAD}: not read ({d['why']}); nothing counted"]
    devs, read = ", ".join(d["dev"]), f"{_wallets(d['read'])} read, {_when(d['fetched_at'])}"
    if not d["bags"] and not d["already"]:
        return [f"{DEV_HEAD}: none seen: no transfer from this token's dev wallets ({devs}) into the {read}; nothing counted (what was read, "
                "not an all-clear)"]
    if counted:
        both = _total(m["cheap"]) + m["dev_pct"]
        head = (f"{DEV_HEAD}: {_pct(m['dev_pct'])} of supply in {_wallets(len(counted))} that got tokens by transfer from this token's dev wallets "
                f"({devs}), counted in the ratio; with the wallets at or below 1/2: {_pct(both)} of supply = {_times(m['ratio'])} the main pool's "
                f"tokens ({read})")
    else:
        head = f"{DEV_HEAD}: nothing new counted ({read})"
    lines = [head] + [_dev_bag_line(b) for b in d["bags"]]
    lines += [f"    {b['row']['address']}: the dev also sent it {_tokens(b['tokens'])} tokens ({_sends(b)}); already counted above at GMGN's average "
              "buy, nothing added" for b in d["already"]]
    return lines


def block(m: dict[str, Any]) -> list[str]:
    cheap, deep, mcap = m["cheap"], m["deep"], m["mcap"]
    counted = m["dev_counted"]
    # C2 (Repair R1, R2): the fallback takes the largest holders.json pool row. It can be smaller than the real pool (the real
    # pool was missed: the ratio comes out too high) or larger (a spin-off curve or a DLMM pool: too low), so the flag line says so
    fallback = f" (main pool by fallback: {m['pool_fallback']}; the ratio may be too high or too low)" if m["pool_fallback"] else ""
    plus = f", plus {_pct(m['dev_pct'])} the dev sent to {_wallets(len(counted))} at no cost" if counted else ""  # DS-DEV-BAGS-T1
    flag = (f"{FLAG_HEAD}: {level(m['ratio'])} — {_pct(_total(cheap))} of supply sits in {_wallets(len(cheap))} that bought at half "
            f"today's price or less{plus}: {_times(m['ratio'])} the main pool's tokens{fallback}.")
    drop = round((1 - (1 / (1 + m["ratio"])) ** 2) * 100)
    drop_text = "more than 99%" if drop >= 100 else f"about {drop}%"  # C3: never "about 100% lower"
    lines = [f"{SUMMARY_MARK}{flag}", TITLE,
             f"  price at scan {_price(m['price'])}, market cap {_usd(mcap)}: median of GMGN's usd_value / balance, times the median "
             f"supply (balance / share of supply) of {m['supply']:,.0f} tokens; GMGN snapshot {_when(m['fetched_at'])}",
             f"  main pool: {m['pool']}, {_pct(m['pool_pct'])} of supply (holders.json), {m['pool_how']}; all pool rows together "
             f"(holders.json infrastructure rows): {_pct(m['pool_rows_pct'])} of supply, {m['pool_rows']} row{'' if m['pool_rows'] == 1 else 's'}"]
    for name, multiple, chosen, ratio in (("1/2", OVERHANG_ENTRY_MULTIPLE, cheap, m["cheap_ratio"]), ("1/3", OVERHANG_DEEP_ENTRY_MULTIPLE, deep, m["deep_ratio"])):
        lines.append(f"  entry at or below {name} of today's price (bought at or below {_usd(mcap / multiple)} market cap): "
                     f"{_wallets(len(chosen))}, {_pct(_total(chosen))} of supply = {_times(ratio)} the main pool's tokens")
    if cheap or counted:
        who = " and ".join(x for x in (f"the wallets at or below 1/2 ({_wallets(len(cheap))})" if cheap else "",
                                       f"the wallets the dev sent its tokens to ({_wallets(len(counted))})" if counted else "") if x)
        lines.append(f"  pool math: if all {who} sold into the main pool at once, constant-product pool math "
                     f"puts the price {drop_text} lower; real dumps are spread out, and other pools and buyers absorb some of it")
    if cheap:
        biggest = sorted(cheap, key=lambda r: -_share(r))[:TOP_BAGS]  # stable: GMGN's order on equal shares
        lines.append(f"  the {'five' if len(biggest) == TOP_BAGS else len(biggest)} biggest such bag{'' if len(biggest) == 1 else 's'} "
                     "(entry = GMGN's average buy as a market cap):")
        lines += [_bag_line(rank, r, m["supply"]) for rank, r in enumerate(biggest, 1)]
    elif counted:
        lines.append("  biggest bags: no wallet in GMGN's top 100 bought at or below 1/2 of today's price (by GMGN's average buy)")
    else:
        lines.append("  pool math and biggest bags: no wallet in GMGN's top 100 bought at or below 1/2 of today's price (by GMGN's average buy)")
    apart = "; the dev-sent wallets counted at zero cost below are not in it" if counted else ""
    lines.append(f"  no cost basis here = no average buy from GMGN: {_wallets(len(m['no_basis']))}, {_pct(_total(m['no_basis']))} of supply "
                 f"(GMGN's top 100 after pools and holders.json infrastructure rows are removed; not in the ratio{apart}; the holder PnL block "
                 "also counts a GMGN PnL as a cost basis, so its number differs)")
    zero = ", or at zero cost when the dev sent them their tokens (next lines)" if counted else ""
    lines.append(f"  GMGN transfer_in tag: {_wallets(len(m['transfer_in']))}, {_pct(_total(m['transfer_in']))} of supply (counted above at "
                 f"GMGN's average buy where GMGN has one, otherwise under no cost basis{zero}; their real entry may be cheaper)")
    lines += _dev_lines(m)
    lines.append(f"  {m['create_slot']}")
    lines.append(f"  bars: DANGER at {OVERHANG_DANGER_RATIO:g}x, CAUTION at {OVERHANG_CAUTION_RATIO:g}x the main pool's tokens; "
                 f"provisional and unvalidated: {BARS_TESTED}")
    read = (", except transfers from this token's dev wallets into the wallets the follow-up lane wallet_rpc_reads read (at most 6; "
            "a dev that sends from a second wallet is missed)") if m["dev"]["why"] is None else ""  # only when the dev-sent bags were read
    lines.append(f"  cannot see: holders outside GMGN's top 100 ({_pct(max(0.0, 100 - _total(m['rows'])))} of supply); wallets that bought "
                 f"through apps without a cost record; tokens received by transfer{read}; sellers' intent; whether GMGN's basis is average or "
                 "FIFO (its numbers are used as given)")
    lines.append(f"  {PRESENTATION_LINE}")
    return lines


def present(run: Path) -> list[str]:
    """The flag line (marked) and the block, offline (no network, no key). A missing, foreign or malformed file, GMGN not
    ok, a needed field missing from every row or no pool reserve reads "not read (<reason>)", never "not raised"."""
    try:
        return block(measure(run))
    except NotRead as why:
        return [f"{SUMMARY_MARK}{FLAG_HEAD}: not read ({why})", f"{TITLE}: not read ({why})"]
    except Exception:  # noqa: BLE001 - a damaged file never crashes the synthesis; it reads as not read
        return [f"{SUMMARY_MARK}{FLAG_HEAD}: not read (saved values unreadable)", f"{TITLE}: not read (saved values unreadable)"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline: print the EXIT OVERHANG flag line and the exit overhang block (cheap-entry "
                                                 "bags vs the main pool) from a saved dlmm-scan run folder. No network, no key; "
                                                 "presentation flag only, never an engine input.")
    parser.add_argument("--present", metavar="RUN_DIR", required=True, help="the saved run folder (read only)")
    args = parser.parse_args(argv)
    run = Path(args.present)
    if not run.is_dir():
        print("error: --present is not a run folder", file=sys.stderr)
        return 2
    for line in present(run):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
