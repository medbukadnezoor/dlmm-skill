"""Orchestrate Jupiter + Helius (+ optional paid-provider artifact) into one artifact.

Provider failures are recorded as explicit unavailable states with a reason; they
never become zero-valued metrics.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import provider_words as pw  # HS-LABELS-T1: verdict words in provider text (standard library only, no network)
from helius_forensics import presentation_only_provider, run_lookups

from . import crosscheck as cc
from . import evidence, gating
from .helius import BudgetExhausted, HeliusClient
from .jupiter import JupiterClient
from .solana import is_solana_address
from .transport import TransportError

SCHEMA = "holder-analysis/1"
# Wallet checks run at once (`--workers`, HS-POOL-T1). Default 4: every request of this engine passes one shared pace of
# helius.ANALYSIS_RATE_CAP_PER_S (2/s), so 4 wallets in flight keep that pace full while one Helius answer takes up to
# about 2 s (2 requests/s x 2 s = 4 requests in flight). More workers cannot go faster than the shared cap; they only
# leave more checks in flight when the run stops early. 1 = the old one-at-a-time loop.
DEFAULT_WORKERS = 4
MAX_WORKERS = 10
_UNREADABLE = object()


class ArtifactRefused(ValueError):
    """--external-artifact names a presentation-only provider in `provider_findings` (exit 2, before any call)."""


def read_external_artifact(path: Path) -> Any:
    """The parsed --external-artifact JSON (or _UNREADABLE), read once, before any provider call.

    Criterion 7 of HS-POOL-T1 (carried from HS-PROV-T1 R6): a `provider_findings` entry that names a presentation-only
    provider (Solana Tracker, MadeOnSol, Fomo API, in every spelling the forensics engine's matcher recognises; that
    matcher, helius_forensics.presentation_only_provider, is reused here, not copied) raises ArtifactRefused, as
    --providers-json does in the forensics engine: a number hand-copied from those sources must never count as a source.
    Input acceptance only: no threshold, verdict or flag rule changes."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return _UNREADABLE
    rows = raw.get("provider_findings") if isinstance(raw, dict) else None
    for row in rows if isinstance(rows, list) else []:
        refused = presentation_only_provider(row.get("provider")) if isinstance(row, dict) else None
        if refused:
            raise ArtifactRefused(f"--external-artifact cannot supply {refused}: it is a presentation-only provider, shown by the synthesis next to the FLAGs and never an engine input")
    return raw


def _check_wallet(helius: HeliusClient, wallet: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """One wallet's checks in the old loop's order: funded-by, then first activity. Returns (answers, stop): stop is None,
    or the reason the old loop would `break` on (budget_exhausted or the transport reason code). An unexpected exception
    is reduced to its type name and recorded the same way (unexpected_error) at every worker count; the old loop let it
    end the run with a traceback."""
    got: dict[str, Any] = {}
    try:
        got["funding"] = helius.funded_by(wallet)
        got["first_activity"] = helius.first_activity(wallet)
    except BudgetExhausted:
        return got, {"reason": "budget_exhausted"}
    except TransportError as exc:
        return got, {"reason": exc.reason}
    except Exception as exc:  # noqa: BLE001 - a worker must report, never die silently or print a traceback
        return got, {"reason": "unexpected_error", "error_type": type(exc).__name__}
    return got, None


def _iso_to_epoch(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def _guard(status: dict[str, Any], name: str, func: Any, *args: Any, **kwargs: Any) -> Any:
    """Run one provider call; record success or an explicit unavailable reason."""
    try:
        result = func(*args, **kwargs)
        status[name] = {"status": "ok"}
        return result
    except BudgetExhausted as exc:
        status[name] = {"status": "unavailable", "reason": "budget_exhausted", "detail": str(exc)}
    except TransportError as exc:
        status[name] = {"status": "unavailable", "reason": exc.reason, **({"http_status": exc.http_status} if exc.http_status else {})}
    return None


def run(
    mint: str,
    *,
    helius: HeliusClient | None,
    jupiter: JupiterClient | None,
    top: int = 20,
    funding_top: int = 20,
    max_pages: int = 10,
    external_artifact: Path | None = None,
    now: datetime | None = None,
    workers: int = 1,
) -> dict[str, Any]:
    if not is_solana_address(mint):
        raise ValueError("mint is not a valid Solana address")
    if not 1 <= workers <= MAX_WORKERS:
        raise ValueError(f"workers must be between 1 and {MAX_WORKERS}")
    raw_artifact = read_external_artifact(external_artifact) if external_artifact is not None else None  # may refuse: before any call
    status: dict[str, Any] = {}
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ---- Jupiter (free) ----
    token = holders_j = pools = None
    if jupiter is not None:
        token = _guard(status, "jupiter.token", jupiter.token, mint)
        holders_j = _guard(status, "jupiter.holders", jupiter.holders, mint, 100)
        pools = _guard(status, "jupiter.pools", jupiter.pools, mint)
    jupiter_rows = (holders_j or {}).get("holders", [])
    pool_ids = {p["id"] for p in (pools or []) if p.get("id")}

    # ---- Helius (paid) ----
    supply = mint_info = scan = largest_rows = None
    rows: list[dict[str, Any]] = []
    helius_complete = False
    total_owners = None
    if helius is not None:
        supply = _guard(status, "helius.supply", helius.token_supply, mint)
        mint_info = _guard(status, "helius.mint", helius.mint_info, mint)
        if supply:
            largest = _guard(status, "helius.largest_accounts", helius.largest_accounts, mint)
            if largest:
                owner_of = _guard(status, "helius.largest_owners", helius.token_account_owners, [r["token_account"] for r in largest])
                if owner_of:
                    largest_rows = cc.largest_account_rows(largest, owner_of, supply["decimals"], supply["raw"])
                    unresolved = [r["token_account"] for r in largest if r["token_account"] not in owner_of]
                    if unresolved:
                        status["helius.largest_owners"] = {"status": "partial", "reason": "unresolved_token_accounts", "count": len(unresolved)}
            holder_count = (token or {}).get("holderCount")
            if not (isinstance(holder_count, int) and holder_count > max_pages * 1000):
                scan = _guard(status, "helius.holder_scan", helius.all_holders, mint, max_pages=max_pages)
            else:
                status["helius.holder_scan"] = {"status": "skipped", "reason": f"holderCount {holder_count} exceeds {max_pages} pages; using top accounts"}
            if scan and scan["complete"]:
                rows = cc.helius_rows(scan["owners"], supply["decimals"], supply["raw"])
                helius_complete = True
                total_owners = len(rows)
            elif largest_rows:
                rows = largest_rows
                if scan and not scan["complete"]:
                    status["helius.holder_scan"] = {"status": "partial", "reason": "incomplete_scan", "pages": scan["pages"], "malformed_rows": scan.get("malformed_rows", 0)}
    # classify a window wider than --top so removing infrastructure cannot leave a short top-N
    classify_rows = rows[: max(top * 3, 60)]
    rows_top = classify_rows[:top]
    supply_ui = supply["raw"] / 10 ** supply["decimals"] if supply else None

    # ---- classification ----
    kinds: dict[str, str] = {}
    identities: dict[str, dict[str, Any]] = {}
    if helius is not None and classify_rows:
        owners = [r["owner"] for r in classify_rows]
        owner_kinds = _guard(status, "helius.owner_kinds", helius.owner_kinds, owners) or {}
        identities = _guard(status, "helius.identities", helius.identities, owners) or {}
        for owner in owners:
            kinds[owner] = cc.classify_owner(owner, owner_kind=owner_kinds.get(owner), identity=identities.get(owner), pool_ids=pool_ids)
    else:
        for r in classify_rows:
            kinds[r["owner"]] = cc.classify_owner(r["owner"], owner_kind=None, identity=None, pool_ids=pool_ids)

    conc = cc.concentration(classify_rows, kinds, supply_ui) if classify_rows else None

    # ---- wallet forensics (funding + age) ----
    funding: dict[str, dict[str, Any] | None] = {}
    first_activity: dict[str, int | None] = {}
    wallets = [r for r in classify_rows if kinds.get(r["owner"]) == "wallet"][:funding_top]
    if helius is not None:
        # HS-POOL-T1: `workers` wallets are checked at once, dispatched in wallet order (1 = the old loop, in this thread).
        # Every request still passes the client's shared pace and exact call budget. The first failure stops new wallets
        # from starting, as the old loop's `break` did; wallets already running finish and are kept. Results are put
        # together in wallet order, never completion order, so the artifact does not depend on the worker count.
        owners = [r["owner"] for r in wallets]
        outcomes = run_lookups(owners, lambda w: _check_wallet(helius, w), workers, lambda _i, o: o[0] != "ok" or o[1][1] is not None)
        stop: dict[str, Any] | None = None
        for i, owner in enumerate(owners):
            kind, value = outcomes.get(i, ("not_reached", None))
            if kind == "not_reached":
                continue
            got, failed = value if kind == "ok" else ({}, {"reason": "unexpected_error"})  # a worker that died still reports
            if "funding" in got:
                funding[owner] = got["funding"]
            if "first_activity" in got:
                first_activity[owner] = got["first_activity"]
            stop = stop or failed  # the first failure in wallet order names the reason
        if stop is None:
            status["helius.wallet_forensics"] = {"status": "ok", "wallets": len(wallets)}
        else:
            status["helius.wallet_forensics"] = {"status": "partial", **stop, "wallets_done": len(funding)}

    cluster_info = cc.clusters(wallets, funding, jupiter_rows, kinds) if wallets else None
    launch_ts = _iso_to_epoch(((token or {}).get("firstPool") or {}).get("createdAt")) or _iso_to_epoch((token or {}).get("createdAt"))
    fresh = cc.freshness(wallets, first_activity, launch_ts) if wallets and first_activity else {"status": "unknown", "reason": "no Helius wallet history"}

    # ---- cross-checks ----
    agreement = cc.compare_holders(rows, jupiter_rows, top_n=top, helius_complete=helius_complete)
    scalars = cc.compare_scalars(jupiter_token=token, mint=mint_info, supply_ui=supply_ui, helius_total_owners=total_owners, helius_complete=helius_complete, conc=conc)
    funding_check = cc.compare_funding(funding, jupiter_rows) if funding else {"compared": 0}
    external: dict[str, Any] = {}
    findings: list[dict[str, Any]] = []
    if external_artifact is not None:
        if raw_artifact is _UNREADABLE:  # read (and checked) once, at the start of the run
            status["external_artifact"] = {"status": "unavailable", "reason": "unreadable"}
            ext_rows = {}
        else:
            ext_rows = cc.external_rows(raw_artifact)
            try:
                file_age_min = max(0.0, ((now or datetime.now(timezone.utc)).timestamp() - Path(external_artifact).stat().st_mtime) / 60)
            except OSError:
                file_age_min = 0.0
            findings = gating.artifact_findings(raw_artifact, extra_age_min=file_age_min)
            dups = gating.duplicate_providers(findings)
            if dups:
                status["external_artifact.duplicate_providers"] = {"status": "partial", "reason": "duplicate_provider_names", "names": dups}
            if not ext_rows:
                status["external_artifact"] = {"status": "unavailable", "reason": "no_gmgn_or_bubblemaps_rows"}
        for name, ext in ext_rows.items():
            external[name] = cc.compare_external(rows, ext, top_n=top)
            status[f"external.{name}"] = {"status": "ok", "rows": len(ext)}

    # Jupiter tag fields are an undocumented schema: with no tag field on any row the bundler share is unknown, not zero
    tag_rows = [r for r in jupiter_rows if r["tags"] is not None]
    bundler_amount = sum(r["amount"] or 0 for r in tag_rows if "bundler" in r["tags"])
    tag_supply = supply_ui or (token or {}).get("totalSupply")  # Jupiter's total supply matched on-chain exactly in live checks
    tagged_bundler = (bundler_amount / tag_supply) if (isinstance(tag_supply, (int, float)) and tag_supply and tag_rows) else None
    unidentified_pda = (
        sum(r["share"] or 0 for r in rows_top if kinds.get(r["owner"]) == "program_account" and not (identities.get(r["owner"]) or {}).get("name"))
        if rows_top
        else None
    )
    signals = cc.build_signals(
        conc=conc,
        cluster_info=cluster_info,
        fresh=fresh,
        jupiter_token=token,
        tagged_bundler_share=tagged_bundler,
        unidentified_pda_share=unidentified_pda,
        mint_info=mint_info,
    )
    coverage = gating.coverage_block(conc, cluster_info, scan_complete=helius_complete)
    detectors = gating.detector_rows(cluster_info, fresh, cohort_ran=gating.OWN_COHORT_DETECTOR_AVAILABLE, min_coverage=cc.MIN_COVERAGE)
    token_age_h = max(0.0, ((now or datetime.now(timezone.utc)).timestamp() - launch_ts) / 3600) if launch_ts else None
    verdict = cc.overall(signals, agreement, scalars, external, coverage=coverage, findings=findings, token_age_h=token_age_h)

    def public_row(r: dict[str, Any]) -> dict[str, Any]:
        """The saved and printed copy of a top-holder row. HS-LABELS-T1: the identity name and the Jupiter tags are
        provider text, so their verdict words are replaced by the placeholder here; classification and the signals above
        used the provider's own text and are unchanged."""
        owner = r["owner"]
        jup = next((j for j in jupiter_rows if j["owner"] == owner), None)
        tags = (jup or {}).get("tags")
        return {
            "owner": owner,
            "share": None if r["share"] is None else round(r["share"], 6),
            "amount": r["amount"],
            "kind": kinds.get(owner),
            "identity": pw.neutral((identities.get(owner) or {}).get("name")),
            "jupiter_tags": [pw.neutral(t) for t in tags] if isinstance(tags, list) else tags,
            "funder": (funding.get(owner) or {}).get("funder"),
            "first_activity": first_activity.get(owner),
        }

    verdict["flag"] = gating.flag_for(verdict["verdict"], findings)
    artifact = {
        "schema": SCHEMA,
        "collected_at_utc": stamp,
        "mint": mint,
        "providers": status,
        "token": {  # symbol, name and launchpad are Jupiter's text: verdict words replaced by the placeholder (HS-LABELS-T1)
            "symbol": pw.neutral((token or {}).get("symbol")),
            "name": pw.neutral((token or {}).get("name")),
            "supply_ui": supply_ui,
            "decimals": (supply or {}).get("decimals"),
            "token_program": (mint_info or {}).get("token_program"),
            "mint_authority": (mint_info or {}).get("mint_authority") if mint_info else "unknown",
            "freeze_authority": (mint_info or {}).get("freeze_authority") if mint_info else "unknown",
            "extensions": (mint_info or {}).get("extensions"),
            "launched_at": launch_ts,
            "launchpad": pw.neutral((token or {}).get("launchpad")),
            "organic_score": (token or {}).get("organicScore"),
            "jupiter_holder_count": (token or {}).get("holderCount"),
        },
        "holder_scan": {"complete": helius_complete, "owners": total_owners, "basis": "full DAS scan" if helius_complete else "top token accounts only (partial)"},
        "top_holders": [public_row(r) for r in rows_top],
        "concentration": conc,
        "crosscheck": {"holders_vs_jupiter": agreement, "scalars": scalars, "funding": funding_check, "external": external},
        "clusters": cluster_info,
        "freshness": fresh,
        "signals": signals,
        "overall": verdict,
        "coverage": {**coverage, "detectors": detectors, "findings": findings, "token_age_h": None if token_age_h is None else round(token_age_h, 2)},
        "budget": {"helius_calls": dict(helius.calls) if helius else {}, "helius_total": helius.total_calls if helius else 0, "jupiter_calls": jupiter.calls if jupiter else 0},
    }
    artifact["sources"] = evidence.read_sources(artifact)
    return artifact
