"""Human-readable rendering of the holder-analysis artifact."""

from __future__ import annotations

from typing import Any

import provider_words as pw  # HS-LABELS-T1: verdict words in provider text (standard library only, no network)

from . import evidence, gating


def _pct(value: Any) -> str:
    return "n/a" if value is None else f"{value * 100:.2f}%"


def _short(address: Any) -> str:
    text = str(address or "")
    return text if len(text) <= 12 else f"{text[:5]}…{text[-5:]}"


_VERDICT_TEXT = {
    "HIGH": "HIGH: a signal failed or a provider alarmed; do not treat the holders as independent.",
    "UNRESOLVED": "UNRESOLVED: a warning or a provider disagreement is open; resolve it before relying on either side.",
    "LIMITED": "LIMITED (unverified): too little was checked to say anything is fine. This is NOT an all-clear.",
    "NO_ALARM": "NO_ALARM: every required check ran and none alarmed. This is NOT proof of independent holders.",
}
_STATE_TEXT = {"ran": "ran", "partial": "ran PARTIALLY", "not_run": "NOT RUN", "unavailable": "UNAVAILABLE"}


def _verdict_lines(artifact: dict[str, Any]) -> list[str]:
    verdict = artifact["overall"]["verdict"]
    cov = artifact["coverage"]
    lines = ["", "## Verdict and coverage", f"**{_VERDICT_TEXT[verdict['level']]}**"]
    lines += [f"- {r}" for r in verdict["reasons"]]
    lines.append(f"- What to do next: {gating.next_step(verdict, cov)}")
    lines += [
        f"- Wallets examined for funding: {cov['wallets_with_funding_data']} with data of {cov['wallets_checked']} checked; "
        f"supply examined {_pct(cov['examined_supply_share'])} of total ({_pct(cov['examined_noninfra_share'])} of the supply held by ordinary wallets, pools excluded). "
        f"NO_ALARM needs at least {_pct(gating.COVERAGE_MIN_SUPPLY_SHARE)} (thresholds are provisional)",
        f"- Holder scan: {'complete' if cov['holder_scan_complete'] else 'PARTIAL (top accounts only)'}",
        "- Detectors:",
    ]
    lines += [f"  - {d['name']}: {_STATE_TEXT[d['state']]}" + (f" ({d['detail']})" if d.get("detail") else "") for d in cov["detectors"]]
    if not cov.get("findings"):
        lines.append("  - external provider rows (Bubblemaps/GMGN/other): NOT SUPPLIED (no --external-artifact)")
    for f in cov.get("findings", []):
        state = {"ok": "ran", "empty": "ran, EMPTY (unknown, not a reassurance)", "unavailable": "ANSWERED BUT UNREADABLE" if f.get("unreadable") else "UNAVAILABLE", "skipped": "NOT RUN"}[f["status"]]
        age = "age unknown" if f.get("data_age_min") is None else f"age {f['data_age_min']:.0f} min"
        lines.append(f"  - provider {f['provider']}: {state}, {age}" + (f" ({f['detail']})" if f.get("detail") else ""))
    token_age = cov.get("token_age_h")
    lines.append("- Token age: " + ("unknown (treated as young)" if token_age is None else f"{token_age} h (young below {gating.YOUNG_TOKEN_MAX_AGE_H:g} h; provider all-clears older than {gating.STALE_ALL_CLEAR_MIN:g} min do not count)"))
    return lines


def render(artifact: dict[str, Any]) -> str:
    token = artifact["token"]
    overall = artifact["overall"]
    lines = [
        f"# Holder analysis: {evidence.clean_text(token.get('symbol') or '?', 30)} ({artifact['mint']})",
        "",
        "## Executive summary",
        "",
        *[f"- {ln}" for ln in evidence.executive_summary(artifact)],
        "",
        "## Sources read",
        *[line for src in artifact["sources"] for line in (
            [f"- {src['name']}: {src['status']}" + (f", {evidence._age_text(src['age'])}" if src["status"] == "read" and src["key"] not in ("helius", "jupiter") else "")]
            + [f"  - {ln}" if not ln.startswith("  ") else f"  {ln}" for ln in src["lines"]]
            + [f"  - cannot see: {src['cannot_see']}"])],
        "",
        "## Underlying level (details)",
        f"Collected {artifact['collected_at_utc']} | holder risk **{overall['holder_risk']}** | verdict **{overall['verdict']['level']}** | data quality **{overall['data_quality']}**",
        f"_{overall['caveat']}_",
        *(
            [f"**Not measured (core signals):** {', '.join(overall['core_unknown_signals'])}. The verdict cannot be NO_ALARM until these are known."]
            if overall.get("core_unknown_signals")
            else []
        ),
        *_verdict_lines(artifact),
        "",
        "## Providers",
    ]
    for name, info in sorted(artifact["providers"].items()):
        extra = f" ({info['reason']})" if info.get("reason") else ""
        lines.append(f"- {name}: {info['status']}{extra}")
    scan = artifact["holder_scan"]
    lines += [
        "",
        f"Holder scan: {scan['basis']}" + (f", {scan['owners']} owners" if scan.get("owners") is not None else ""),
        f"Authorities: mint={token.get('mint_authority') or 'disabled'}, freeze={token.get('freeze_authority') or 'disabled'}"
        + (f", extensions={','.join(token['extensions'])}" if token.get("extensions") else ""),
        "",
        "## Signals",
        "| signal | value | level | warn/fail | basis |",
        "|---|---|---|---|---|",
    ]
    for s in artifact["signals"]:
        if s["value"] is None:
            value = "n/a"
        elif isinstance(s["value"], str):
            value = s["value"]
        else:
            value = f"{s['value']:.4f}" if s["name"].startswith("jupiter_") else _pct(s["value"])
        limits = "n/a" if s["warn_at"] is None else f"{s['warn_at']}/{s['fail_at']}"
        lines.append(f"| {s['name']} | {value} | {s['level']} | {limits} | {s['basis']} |")
    conc = artifact.get("concentration")
    if conc:
        lines += [
            "",
            "## Concentration (share of total supply)",
            f"- removed as infrastructure (burn/pools/exchanges): {_pct(conc['infra_share'])}; "
            f"kept as controlled vaults (multisig/treasury): {_pct(conc['controlled_vault_share'])}; "
            f"kept as unidentified program accounts: {_pct(conc['unidentified_program_share'])}",
            "- top1 / top5 / top10 / top20, ex-infra (conservative, drives signals): "
            + " / ".join(_pct(conc[f"top{n}_ex_infra"]) for n in (1, 5, 10, 20)),
            "- top1 / top5 / top10 / top20, keypair wallets only (optimistic): "
            + " / ".join(_pct(conc[f"top{n}_wallets_only"]) for n in (1, 5, 10, 20)),
            "- top1 / top5 / top10 / top20, all holders: " + " / ".join(_pct(conc[f"top{n}_all"]) for n in (1, 5, 10, 20)),
        ]
        largest = conc.get("largest_non_infra")
        if largest:
            top_row = next((r for r in artifact["top_holders"] if r["owner"] == largest["owner"]), {})
            lines.append(f"- largest holder excluding pools and exchanges: {_short(largest['owner'])} {_pct(largest['share'])} ({largest['kind']}{', ' + evidence.clean_text(top_row['identity'], 60) if top_row.get('identity') else ''})")
    check = artifact["crosscheck"]
    agreement = check["holders_vs_jupiter"]
    lines += ["", "## Cross-check", f"- Helius vs Jupiter holders: **{agreement['status']}**"]
    if agreement.get("overlap_top_n") is not None:
        lines.append(
            f"  - top-{agreement['top_n']} overlap {agreement['overlap_top_n']:.0%}, balance mismatches {len(agreement['balance_mismatches'])}, "
            f"Helius top holders missing from Jupiter {len(agreement['helius_top_missing_from_jupiter'])}"
        )
    for item in check["scalars"]:
        mark = {True: "agree", False: "DISAGREE", None: "info"}[item["agree"]]
        lines.append(f"- {item['check']}: {mark} (jupiter={item['jupiter']}, helius={item['helius']}) {item['note']}".rstrip())
    funding = check.get("funding") or {}
    if funding.get("compared"):
        lines.append(
            f"- funders (Helius first inbound SOL vs Jupiter first meaningful funding), {funding['compared']} wallets: "
            f"{funding['agree']} same, {funding['helius_first_funding_is_service_level']} Helius first funding is rent/service-level, "
            f"{funding['different_substantive_funders']} differ substantively"
        )
    for name, ext in (check.get("external") or {}).items():
        lines.append(f"- {name} vs Helius: **{ext['status']}** (overlap {ext.get('overlap_top_n', 0):.0%}, share mismatches {len(ext.get('share_mismatches', []))})")
    clusters = artifact.get("clusters")
    if clusters is not None:
        lines += ["", "## Funding clusters (shared non-service funder)", f"- funding data for {clusters['wallets_with_funding_data']}/{clusters['wallets_total']} checked wallets"]
        if clusters["clusters"]:
            for c in clusters["clusters"]:
                funders = ", ".join(f"{_short(f)} [{'+'.join(p)}]" for f, p in c["shared_funders"].items()) or "linked"
                lines.append(f"- {c['wallet_count']} wallets, {_pct(c['supply_share'])} of supply via funder {funders}")
        else:
            lines.append("- none found among checked wallets")
        if clusters["service_funder_wallets"]:
            lines.append(f"- ignored as service/rent-level funding: {sum(clusters['service_funder_wallets'].values())} wallets")
    fresh = artifact.get("freshness") or {}
    if fresh.get("status") == "ok":
        lines += ["", "## Wallet age", f"- {fresh['counts']} | fresh supply share {_pct(fresh['fresh_supply_share'])} ({fresh['note']})"]
    lines += ["", "## Top holders", "| # | wallet | share | kind | identity | tags |", "|---|---|---|---|---|---|"]
    for i, row in enumerate(artifact["top_holders"], 1):
        tags = ",".join(evidence.cell(t) for t in (row.get("jupiter_tags") or []))
        lines.append(f"| {i} | {_short(row['owner'])} | {_pct(row['share'])} | {evidence.cell(row.get('kind') or '')} | {evidence.cell(row.get('identity') or '')} | {tags} |")
    budget = artifact["budget"]
    lines += ["", f"Budget: Helius {budget['helius_total']} calls {budget['helius_calls']}, Jupiter {budget['jupiter_calls']} calls"]
    lines += ["", "Glossary: concentration is how much of the supply a few wallets hold; a cluster is a group of wallets sharing a funder or flagged as linked by a provider; "
              "the Bubblemaps map is the free web map that groups linked wallets; a cohort is a group of wallets first funded close together in time (checked by the dlmm-scan forensics step)."]
    removed = pw.count(lines)
    if removed:  # HS-LABELS-T1: provider text that held a verdict word is shown as the placeholder; the last item of Sources read says how many
        lines.insert(lines.index("## Underlying level (details)") - 1, f"- {pw.removed_line(removed)}")
    return "\n".join(evidence.oneline(ln) for ln in lines) + "\n"
