"""Pure cross-check logic: no network, no secrets, fully unit-testable.

Convention used everywhere: missing evidence is None / "unknown", never zero.
Shares are fractions of total on-chain supply (0.10 == 10%).
"""

from __future__ import annotations

import re
from typing import Any

from . import gating
from .solana import BURN_ADDRESSES, is_on_curve

# Wallet-age and clustering defaults. They are starting points, not backtested.
FRESH_DAYS = 7
RENT_LEVEL_SOL = 0.0025  # ~ATA rent (0.00203928); a co-signer topping up rent is not insider funding
SERVICE_FUNDER_TYPES = {"exchange", "authority", "protocol", "bridge", "service"}
EXCHANGE_CATEGORIES = {"exchange", "cex", "centralized exchange"}
MIN_CLUSTER_WALLETS = 2
REL_TOL = 0.02  # holder balance agreement between providers (timing skew allowance)
INFRA_KINDS = {"burn", "liquidity_pool", "exchange"}  # removed from concentration
MIN_COVERAGE = 0.5  # share of checked wallets that must have data before a wallet-level signal is trusted
CORE_SIGNALS = {"top1_ex_infra", "top10_ex_infra", "largest_cluster", "fresh_wallet_share", "mint_authority_active"}
_POOL_RE = re.compile(r"\b(pool|amm|liquidity|swap|raydium|orca|meteora|lifinity|phoenix|openbook)\b")
_CONTROL_RE = re.compile(r"(multisig|multi-sig|squads|treasury|team|dao|foundation|vesting|escrow|locker|admin|reserve|cold|hot)")

# (warn, fail) thresholds as fractions unless stated. Higher is worse.
THRESHOLDS = {
    "top1_ex_infra": (0.10, 0.20),
    "top10_ex_infra": (0.35, 0.50),
    "largest_cluster": (0.15, 0.30),
    "fresh_wallet_share": (0.15, 0.30),
    "tagged_bundler_share": (0.05, 0.15),
    "unidentified_pda_share": (0.05, 0.15),
    "jupiter_bot_holders_pct": (10.0, 25.0),  # Jupiter reports this in percent units
    "jupiter_bundler_holding_pct": (5.0, 15.0),  # percent units
}


# ---- row building ---------------------------------------------------------
def helius_rows(owners: dict[str, dict[str, int]], decimals: int, supply_raw: int) -> list[dict[str, Any]]:
    scale = 10**decimals
    rows = [
        {
            "owner": owner,
            "amount": info["amount_raw"] / scale,
            "share": info["amount_raw"] / supply_raw if supply_raw else None,
            "token_accounts": info["accounts"],
        }
        for owner, info in owners.items()
    ]
    return sorted(rows, key=lambda r: r["amount"], reverse=True)


def largest_account_rows(
    largest: list[dict[str, Any]], owner_of: dict[str, str], decimals: int, supply_raw: int
) -> list[dict[str, Any]]:
    """Top token accounts folded to owners. PARTIAL: an owner may hold more elsewhere."""
    totals: dict[str, dict[str, int]] = {}
    for row in largest:
        owner = owner_of.get(row["token_account"])
        if not owner:
            continue
        slot = totals.setdefault(owner, {"amount_raw": 0, "accounts": 0})
        slot["amount_raw"] += row["amount_raw"]
        slot["accounts"] += 1
    return helius_rows(totals, decimals, supply_raw)


def classify_owner(
    owner: str,
    *,
    owner_kind: str | None,
    identity: dict[str, Any] | None,
    pool_ids: set[str],
    tags: list[str] | None = None,
) -> str:
    """burn | liquidity_pool | exchange | controlled_vault | program_account | wallet.

    Only burn / liquidity_pool / exchange are removed from concentration
    (INFRA_KINDS). A multisig or treasury is a PDA too, but a person or team
    controls it, so it stays in concentration as controlled_vault.
    """
    if owner in BURN_ADDRESSES:
        return "burn"
    if owner in pool_ids:
        return "liquidity_pool"
    category = str((identity or {}).get("category") or "").strip().lower()
    id_tags = " ".join(str(t).lower() for t in (identity or {}).get("tags", []))
    id_text = f"{(identity or {}).get('name') or ''} {id_tags}".lower()
    if category in EXCHANGE_CATEGORIES or "exchange" in id_tags:
        return "exchange"
    is_program = bool(owner_kind and owner_kind.startswith("program:"))
    if not is_program:
        try:
            is_program = not is_on_curve(owner)
        except ValueError:
            pass
    if not is_program:
        return "wallet"  # a keypair wallet is never a pool, whatever its label says
    if _CONTROL_RE.search(id_text):
        return "controlled_vault"  # checked before the pool pattern: "Orca Foundation Treasury" is a treasury
    if _POOL_RE.search(id_text):
        return "liquidity_pool"
    return "program_account"


# ---- concentration --------------------------------------------------------
def concentration(rows: list[dict[str, Any]], kinds: dict[str, str], supply_total: float | None) -> dict[str, Any]:
    """Top-N share of supply under three views.

    all          every holder
    ex_infra     burn / liquidity pools / exchanges removed; multisigs, treasuries and
                 unidentified program accounts STAY (conservative, drives the signals)
    wallets_only keypair wallets only (optimistic; hides team vaults)
    """
    out: dict[str, Any] = {}
    allrows = [r for r in rows if r["share"] is not None]
    kind = lambda r: kinds.get(r["owner"], "wallet")  # noqa: E731
    ex_infra = [r for r in allrows if kind(r) not in INFRA_KINDS]
    wallets = [r for r in allrows if kind(r) == "wallet"]
    infra = sum(r["share"] for r in allrows if kind(r) in INFRA_KINDS)
    out["infra_share"] = round(infra, 6)
    out["controlled_vault_share"] = round(sum(r["share"] for r in allrows if kind(r) == "controlled_vault"), 6)
    out["unidentified_program_share"] = round(sum(r["share"] for r in allrows if kind(r) == "program_account"), 6)
    non_infra_supply = 1.0 - infra
    for n in (1, 5, 10, 20):
        out[f"top{n}_all"] = round(sum(r["share"] for r in allrows[:n]), 6)
        top_ex = sum(r["share"] for r in ex_infra[:n])
        out[f"top{n}_ex_infra"] = round(top_ex, 6)
        out[f"top{n}_ex_infra_of_non_infra_supply"] = round(top_ex / non_infra_supply, 6) if non_infra_supply > 0 else None
        out[f"top{n}_wallets_only"] = round(sum(r["share"] for r in wallets[:n]), 6)
    largest = ex_infra[0] if ex_infra else None
    out["largest_non_infra"] = {"owner": largest["owner"], "share": round(largest["share"], 6), "kind": kind(largest)} if largest else None
    out["rows_considered"] = len(allrows)
    out["non_infra_rows"] = len(ex_infra)
    out["top20_limited_by_rows"] = len(ex_infra) < 20  # too few rows classified for a trustworthy top-20
    return out


# ---- provider agreement ---------------------------------------------------
def compare_holders(
    helius: list[dict[str, Any]],
    jupiter: list[dict[str, Any]],
    *,
    top_n: int = 20,
    helius_complete: bool = False,
) -> dict[str, Any]:
    """Holder-level agreement between Helius (on-chain) and Jupiter (top-100 API)."""
    if not helius or not jupiter:
        return {"status": "unknown", "reason": "a source returned no holder rows"}
    jup = {r["owner"]: r for r in jupiter if r.get("owner")}
    top = helius[:top_n]
    compared, mismatched, missing = [], [], []
    for rank, row in enumerate(top, 1):
        peer = jup.get(row["owner"])
        if peer is None or peer.get("amount") is None:
            missing.append({"owner": row["owner"], "helius_rank": rank, "helius_share": _r(row["share"])})
            continue
        base = max(row["amount"], 1e-9)
        diff = abs(peer["amount"] - row["amount"]) / base
        item = {"owner": row["owner"], "helius_rank": rank, "helius_amount": row["amount"], "jupiter_amount": peer["amount"], "rel_diff": round(diff, 6)}
        compared.append(item)
        if diff > REL_TOL:
            mismatched.append(item)
    helius_set = {r["owner"] for r in top}
    jupiter_top = [r["owner"] for r in jupiter[:top_n] if r.get("owner")]
    overlap = len(helius_set & set(jupiter_top)) / max(len(helius_set), 1)
    jupiter_only: list[str] = []
    if helius_complete:
        known = {r["owner"] for r in helius}
        jupiter_only = [o for o in jupiter_top if o not in known]
    if missing or jupiter_only or overlap < 0.8:
        status = "poor" if overlap < 0.6 or len(missing) > top_n // 4 else "partial"
    elif mismatched:
        # balances that mostly disagree mean the sources describe different states, not timing skew
        status = "poor" if len(mismatched) * 2 >= max(len(compared), 1) else "partial"
    else:
        status = "strong"
    return {
        "status": status,
        "top_n": top_n,
        "compared": len(compared),
        "overlap_top_n": round(overlap, 4),
        "balance_mismatches": mismatched,
        "helius_top_missing_from_jupiter": missing,
        "jupiter_top_unknown_to_helius": jupiter_only,
        "note": "Jupiter lists the top 100 holders only; a Helius top-N owner absent from it means Jupiter is stale or ranks differently.",
    }


def external_rows(artifact: Any) -> dict[str, list[dict[str, Any]]]:
    """Pull GMGN / Bubblemaps holder rows out of an existing lp-research-companion
    evidence artifact (providers.gmgn.holders, providers.bubblemaps.nodes.top_holders)."""
    providers = (artifact or {}).get("providers") if isinstance(artifact, dict) else None
    found: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(providers, dict):
        return found
    gmgn = providers.get("gmgn")
    rows = gmgn.get("holders") if isinstance(gmgn, dict) else None
    if isinstance(rows, list):
        parsed = [
            {"owner": r.get("address"), "share": _share(r.get("share_total_supply"), r.get("share")), "tags": r.get("tags") or []}
            for r in rows
            if isinstance(r, dict) and r.get("address")
        ]
        if parsed:
            found["gmgn"] = parsed
    bubble = providers.get("bubblemaps")
    nodes = bubble.get("nodes") if isinstance(bubble, dict) else None
    rows = nodes.get("top_holders") if isinstance(nodes, dict) else None
    if isinstance(rows, list):
        parsed = [
            {"owner": r.get("address"), "share": _share(r.get("share")), "label": r.get("label")}
            for r in rows
            if isinstance(r, dict) and r.get("address")
        ]
        if parsed:
            found["bubblemaps"] = parsed
    return found


def _share(*values: Any) -> float | None:
    for value in values:
        if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1:
            return float(value)
    return None


def compare_external(helius: list[dict[str, Any]], ext: list[dict[str, Any]], *, top_n: int = 20, pp_tol: float = 0.005) -> dict[str, Any]:
    """Share-level agreement with a paid provider's holder list (tolerance in fraction of supply)."""
    if not helius or not ext:
        return {"status": "unknown"}
    peer = {r["owner"]: r for r in ext}
    top = helius[:top_n]
    diffs, missing = [], []
    for row in top:
        other = peer.get(row["owner"])
        if other is None or other.get("share") is None or row["share"] is None:
            missing.append(row["owner"])
            continue
        diffs.append({"owner": row["owner"], "helius_share": _r(row["share"]), "provider_share": _r(other["share"]), "abs_diff": round(abs(row["share"] - other["share"]), 6)})
    bad = [d for d in diffs if d["abs_diff"] > pp_tol]
    overlap = len(diffs) / max(len(top), 1)
    if overlap < 0.6 or (bad and len(bad) * 2 >= max(len(diffs), 1)):
        status = "poor"
    else:
        status = "strong" if overlap >= 0.9 and not bad else "partial"
    return {"status": status, "compared": len(diffs), "overlap_top_n": round(overlap, 4), "share_mismatches": bad, "missing_from_provider": missing}


def _flag_shown(value: Any) -> Any:
    return value if isinstance(value, bool) else "not read (unexpected value)"


def compare_scalars(
    *,
    jupiter_token: dict[str, Any] | None,
    mint: dict[str, Any] | None,
    supply_ui: float | None,
    helius_total_owners: int | None,
    helius_complete: bool,
    conc: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Field-by-field comparison of headline facts both sources report."""
    checks: list[dict[str, Any]] = []
    audit = (jupiter_token or {}).get("audit") or {}

    def add(name: str, jup: Any, chain: Any, agree: bool | None, note: str = "") -> None:
        checks.append({"check": name, "jupiter": jup, "helius": chain, "agree": agree, "note": note})

    # HS-LABELS-T1 R4: Jupiter's audit flags are kept and printed only as true / false; any other value is shown as "not read
    # (unexpected value)" (it is provider text). The agreement check uses the value as Jupiter sent it, as before.
    if mint is not None and jupiter_token is not None and "mintAuthorityDisabled" in audit:
        chain_disabled = mint.get("mint_authority") is None
        add("mint_authority_disabled", _flag_shown(audit["mintAuthorityDisabled"]), chain_disabled, audit["mintAuthorityDisabled"] == chain_disabled)
    if mint is not None and jupiter_token is not None and "freezeAuthorityDisabled" in audit:
        chain_disabled = mint.get("freeze_authority") is None
        add("freeze_authority_disabled", _flag_shown(audit["freezeAuthorityDisabled"]), chain_disabled, audit["freezeAuthorityDisabled"] == chain_disabled)
    total_supply = (jupiter_token or {}).get("totalSupply")
    if isinstance(total_supply, (int, float)) and supply_ui:
        rel = abs(total_supply - supply_ui) / supply_ui
        add("total_supply", total_supply, supply_ui, rel <= 0.001, "relative diff %.6f" % rel)
    holder_count = (jupiter_token or {}).get("holderCount")
    if isinstance(holder_count, int) and helius_total_owners is not None:
        rel = abs(holder_count - helius_total_owners) / max(helius_total_owners, 1)
        add(
            "holder_count",
            holder_count,
            helius_total_owners,
            (rel <= 0.05) if helius_complete else None,
            "complete scan" if helius_complete else "Helius scan incomplete; comparison not conclusive",
        )
    top_pct = audit.get("topHoldersPercentage")
    if isinstance(top_pct, (int, float)) and conc:
        add(
            "top_holders_percentage",
            round(top_pct / 100, 6),
            {k: conc.get(k) for k in ("top10_all", "top10_ex_infra", "top10_wallets_only", "top20_ex_infra")},
            None,
            "Jupiter's top-holders definition (count, infra handling) is undocumented; compare to the variants, do not treat as pass/fail",
        )
    return checks


# ---- funding & clusters ---------------------------------------------------
def is_service_funder(funding: dict[str, Any] | None) -> bool:
    if not funding:
        return False
    if funding.get("name"):
        return True
    if str(funding.get("type") or "").strip().lower() in SERVICE_FUNDER_TYPES:
        return True
    amount = funding.get("amount")
    return isinstance(amount, (int, float)) and amount <= RENT_LEVEL_SOL


def _service_addresses(funding: dict[str, dict[str, Any] | None]) -> set[str]:
    """Funders Helius itself labels as a named service/exchange (not merely rent-level)."""
    return {
        f["funder"]
        for f in funding.values()
        if f and (f.get("name") or str(f.get("type") or "").strip().lower() in SERVICE_FUNDER_TYPES)
    }


def _jupiter_funding(peer: dict[str, Any] | None, services: set[str] | None = None) -> dict[str, Any] | None:
    if not peer or not peer.get("funder"):
        return None
    # Jupiter gives no label; borrow Helius's so one CEX hot wallet is not a service via one provider and an insider via the other
    name = "service (labelled by Helius)" if services and peer["funder"] in services else None
    return {"funder": peer["funder"], "name": name, "type": None, "amount": peer.get("funding_amount")}


def compare_funding(helius_funding: dict[str, dict[str, Any] | None], jupiter_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Helius funded-by is the FIRST inbound SOL (often a rent top-up); Jupiter's
    fundingAddress is usually the first meaningful funding. Different funders are
    therefore expected, and only a difference between two substantive fundings is
    a real disagreement."""
    jup = {r["owner"]: r for r in jupiter_rows if r.get("owner")}
    services = _service_addresses(helius_funding)
    agree = rent_first = substantive = 0
    disagreements = []
    for wallet, funding in helius_funding.items():
        peer = _jupiter_funding(jup.get(wallet), services)
        if not funding or not peer:
            continue
        if funding["funder"] == peer["funder"]:
            agree += 1
        elif is_service_funder(funding) and not is_service_funder(peer):
            rent_first += 1
        else:
            substantive += 1
            disagreements.append(
                {"wallet": wallet, "helius_funder": funding["funder"], "helius_amount": funding.get("amount"), "jupiter_funder": peer["funder"], "jupiter_amount": peer.get("amount")}
            )
    return {
        "compared": agree + rent_first + substantive,
        "agree": agree,
        "helius_first_funding_is_service_level": rent_first,
        "different_substantive_funders": substantive,
        "disagreements": disagreements,
        "note": "Disagreement is expected when Helius's first inbound SOL is a rent/co-signer top-up; clustering uses both providers' funders.",
    }


def clusters(
    rows: list[dict[str, Any]],
    funding: dict[str, dict[str, Any] | None],
    jupiter_rows: list[dict[str, Any]],
    kinds: dict[str, str],
) -> dict[str, Any]:
    """Link wallets that share ANY non-service funder reported by either provider.

    Connected components with >= MIN_CLUSTER_WALLETS wallets are clusters; the
    evidence list says which provider supplied each link.
    """
    jup = {r["owner"]: r for r in jupiter_rows if r.get("owner")}
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        while parent.setdefault(node, node) != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    wallets = [r for r in rows if kinds.get(r["owner"], "wallet") == "wallet"]
    services = _service_addresses(funding)
    funders_of: dict[str, list[tuple[str, str]]] = {}
    service: dict[str, int] = {}
    covered = 0
    for row in wallets:
        wallet = row["owner"]
        has_data = False
        for provider, record in (("helius", funding.get(wallet)), ("jupiter", _jupiter_funding(jup.get(wallet), services))):
            if not record:
                continue
            has_data = True
            if is_service_funder(record):
                service[record["funder"]] = service.get(record["funder"], 0) + 1
                continue
            funders_of.setdefault(wallet, []).append((provider, record["funder"]))
            union(wallet, "funder:" + record["funder"])
        covered += has_data
    components: dict[str, list[dict[str, Any]]] = {}
    for row in wallets:
        if row["owner"] in funders_of:
            components.setdefault(find(row["owner"]), []).append(row)
    found = []
    for members in components.values():
        if len(members) < MIN_CLUSTER_WALLETS:
            continue
        links: dict[str, set[str]] = {}
        for member in members:
            for provider, funder in funders_of[member["owner"]]:
                links.setdefault(funder, set()).add(provider)
        shared = {f: sorted(p) for f, p in links.items() if sum(1 for m in members if any(f == x[1] for x in funders_of[m["owner"]])) >= 2}
        found.append(
            {
                "wallets": [m["owner"] for m in members],
                "wallet_count": len(members),
                "supply_share": round(sum(m["share"] or 0 for m in members), 6),
                "shared_funders": shared,
            }
        )
    found.sort(key=lambda c: c["supply_share"], reverse=True)
    covered_share = sum(r["share"] or 0 for r in wallets if funding.get(r["owner"]) or _jupiter_funding(jup.get(r["owner"]), services))
    return {
        "clusters": found,
        "covered_share": round(covered_share, 6),
        "service_funder_wallets": dict(sorted(service.items(), key=lambda kv: -kv[1])[:10]),
        "wallets_total": len(wallets),
        "wallets_with_funding_data": covered,
        "coverage": round(covered / len(wallets), 4) if wallets else None,
    }


# ---- freshness ------------------------------------------------------------
def freshness(rows: list[dict[str, Any]], first_activity: dict[str, int | None], launch_ts: int | None) -> dict[str, Any]:
    if launch_ts is None:
        return {"status": "unknown", "reason": "token launch time unavailable"}
    fresh_window = FRESH_DAYS * 86400
    classes: dict[str, list[str]] = {"born_after_launch": [], "fresh_pre_launch": [], "established": [], "unknown": []}
    share = {k: 0.0 for k in classes}
    for row in rows:
        ts = first_activity.get(row["owner"])
        if ts is None:
            key = "unknown"
        elif ts >= launch_ts:
            key = "born_after_launch"
        elif launch_ts - ts <= fresh_window:
            key = "fresh_pre_launch"
        else:
            key = "established"
        classes[key].append(row["owner"])
        share[key] += row["share"] or 0.0
    fresh_share = share["born_after_launch"] + share["fresh_pre_launch"]
    known = len(rows) - len(classes["unknown"])
    if not rows or known == 0:
        return {"status": "unknown", "reason": "no wallet history returned", "wallets_checked": len(rows)}
    return {
        "status": "ok" if known == len(rows) else "partial",
        "coverage": round(known / len(rows), 4),
        "fresh_days": FRESH_DAYS,
        "wallets_checked": len(rows),
        "counts": {k: len(v) for k, v in classes.items()},
        "supply_share": {k: round(v, 6) for k, v in share.items()},
        "fresh_supply_share": round(fresh_share, 6),
        "note": "born_after_launch includes organic late buyers; read it with the cluster result, not alone.",
    }


# ---- signals --------------------------------------------------------------
def _level(value: float | None, warn: float, fail: float) -> str:
    if value is None:
        return "unknown"
    return "fail" if value >= fail else "warn" if value >= warn else "ok"


def signal(name: str, value: float | None, basis: str) -> dict[str, Any]:
    warn, fail = THRESHOLDS[name]
    return {"name": name, "value": None if value is None else round(value, 6), "level": _level(value, warn, fail), "warn_at": warn, "fail_at": fail, "basis": basis}


def build_signals(
    *,
    conc: dict[str, Any] | None,
    cluster_info: dict[str, Any] | None,
    fresh: dict[str, Any] | None,
    jupiter_token: dict[str, Any] | None,
    tagged_bundler_share: float | None,
    unidentified_pda_share: float | None = None,
    mint_info: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    audit = (jupiter_token or {}).get("audit") or {}
    bundler = (audit.get("bundlerStats") or {}).get("holdingPct")
    largest = None
    cluster_note = ""
    if cluster_info is not None and (cluster_info.get("coverage") or 0) >= MIN_COVERAGE:
        largest = cluster_info["clusters"][0]["supply_share"] if cluster_info["clusters"] else 0.0
        cluster_note = f" [funding data for {cluster_info['wallets_with_funding_data']}/{cluster_info['wallets_total']} wallets]"
    fresh_value = None
    fresh_note = ""
    if fresh and fresh.get("status") in ("ok", "partial") and (fresh.get("coverage") or 0) >= MIN_COVERAGE:
        fresh_value = fresh["fresh_supply_share"]
        fresh_note = f" [wallet age known for {fresh['coverage']:.0%} of checked wallets]"
    authority = [
        _flag_signal("mint_authority_active", mint_info, "mint_authority", "fail", "a live mint authority can inflate supply (Helius getAccountInfo)"),
        _flag_signal("freeze_authority_active", mint_info, "freeze_authority", "warn", "a live freeze authority can freeze holders or pools (Helius getAccountInfo)"),
    ]
    return authority + [
        signal("top1_ex_infra", (conc or {}).get("top1_ex_infra"), "largest holder after removing burn/pools/exchanges; multisigs, treasuries and unidentified PDAs stay in (Helius on-chain)"),
        signal("top10_ex_infra", (conc or {}).get("top10_ex_infra"), "top-10 holders after removing burn/pools/exchanges; multisigs, treasuries and unidentified PDAs stay in (Helius on-chain)"),
        signal("largest_cluster", largest, "largest shared-funder group among top wallets (Helius funded-by, Jupiter fallback)" + cluster_note),
        signal("fresh_wallet_share", fresh_value, "top wallets first active <=7d before launch or after it (Helius history)" + fresh_note),
        signal("tagged_bundler_share", tagged_bundler_share, "share held by wallets Jupiter tags 'bundler'"),
        signal("unidentified_pda_share", unidentified_pda_share, "program-owned holders with no pool match or identity; may be a pool OR a team multisig/vesting vault, so verify by hand"),
        signal("jupiter_bot_holders_pct", audit.get("botHoldersPercentage"), "Jupiter audit.botHoldersPercentage (provider claim)"),
        signal("jupiter_bundler_holding_pct", bundler, "Jupiter audit.bundlerStats.holdingPct (provider claim)"),
    ]


def _flag_signal(name: str, mint_info: dict[str, Any] | None, field: str, level_if_set: str, basis: str) -> dict[str, Any]:
    """Boolean authority signal; unknown when the mint account could not be read."""
    if mint_info is None:
        value, level = None, "unknown"
    elif mint_info.get(field):
        value, level = "active", level_if_set
    else:
        value, level = "disabled", "ok"
    return {"name": name, "value": value, "level": level, "warn_at": None, "fail_at": None, "basis": basis}


def overall(
    signals: list[dict[str, Any]],
    agreement: dict[str, Any],
    scalars: list[dict[str, Any]],
    external: dict[str, Any] | None = None,
    *,
    coverage: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
    cohort_ran: bool = gating.OWN_COHORT_DETECTOR_AVAILABLE,
    token_age_h: float | None = None,
) -> dict[str, Any]:
    levels = [s["level"] for s in signals]
    disagreements = [c["check"] for c in scalars if c["agree"] is False]
    unknown = [s["name"] for s in signals if s["level"] == "unknown"]
    core_unknown = [name for name in unknown if name in CORE_SIGNALS]
    own_level = gating.VERDICT_HIGH if "fail" in levels else gating.VERDICT_UNRESOLVED if "warn" in levels else None
    decision = gating.decide_verdict(own_level, coverage, cohort_ran=cohort_ran, findings=findings, token_age_h=token_age_h)
    if "fail" in levels or decision["level"] == gating.VERDICT_HIGH:
        risk = "high"  # a fail is never softened
    elif "warn" in levels:
        risk = "elevated"
    elif decision["level"] == gating.VERDICT_UNRESOLVED:
        risk = "unresolved"  # a provider alarm or hint disagrees with the quiet signals
    elif core_unknown:
        risk = "unknown"  # every core signal must be measured before anything better than limited
    elif decision["level"] == gating.VERDICT_NO_ALARM:
        risk = "no_alarm"
    else:
        risk = "limited"  # nothing alarmed, but coverage or detectors fell short: never reads as "low"
    statuses = [agreement.get("status")] + [(e or {}).get("status") for e in (external or {}).values()]
    quality = "ok"
    if "poor" in statuses or disagreements:
        quality = "conflicting"
    elif any(s in ("unknown", "partial") for s in statuses):
        quality = "limited"
    return {
        "holder_risk": risk,
        "verdict": decision,
        "data_quality": quality,
        "unknown_signals": unknown,
        "core_unknown_signals": core_unknown,
        "provider_disagreements": disagreements,
        "caveat": "Heuristic screen with untested thresholds; an unknown reading is not a safety signal. Not a trade verdict.",
    }


def _r(value: float | None) -> float | None:
    return None if value is None else round(value, 6)
