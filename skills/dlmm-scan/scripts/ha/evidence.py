"""Evidence-first presentation: executive summary and per-source 'read' blocks. Pure, no network.

The tool shows what each source read and the owner decides. The flag is a mapping of the underlying level
(see gating.flag_for); nothing here changes a verdict.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

import provider_words as pw  # HS-LABELS-T1: verdict words in provider text (standard library only, no network)

from . import gating


def _pct(value: Any) -> str:
    return "n/a" if value is None else f"{value * 100:.2f}%"


def _age_text(minutes: float | None, unknown: str = "as supplied") -> str:
    if minutes is None:
        return unknown
    if minutes < 1:
        return "just now"
    if minutes < 60:
        return f"{minutes:.0f} min old"
    if minutes < 48 * 60:
        return f"{minutes / 60:.1f} h old"
    return f"{minutes / 1440:.1f} days old"


def _capped(items: list[str]) -> list[str]:
    cap = gating.LIST_CAP
    return items[:cap] + ([f"and {len(items) - cap} more"] if len(items) > cap else [])


def _step_status(providers: dict[str, Any], prefix: str) -> str:
    steps = [v.get("status") for k, v in providers.items() if k.startswith(prefix)]
    if not steps:
        return "not run"
    if any(s in ("ok", "partial") for s in steps):
        return "read"
    return "unavailable"


def read_sources(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    """What each source read, in a fixed order (Helius, Jupiter, Bubblemaps rows, GMGN rows, other providers)."""
    providers = artifact.get("providers") or {}
    conc = artifact.get("concentration") or {}
    scan = artifact.get("holder_scan") or {}
    clusters = artifact.get("clusters")
    fresh = artifact.get("freshness") or {}
    token = artifact.get("token") or {}
    findings = {f["provider"]: f for f in (artifact.get("coverage") or {}).get("findings", [])}
    by_identity: dict[str, dict[str, Any]] = {}  # HS-LABELS-T1 R5: one block per provider, told apart by the name before the rule
    for f in (artifact.get("coverage") or {}).get("findings", []):
        by_identity[gating.source_identity(f)] = f
    out: list[dict[str, Any]] = []

    h_status = _step_status(providers, "helius.")
    lines = [f"holder scan: {scan.get('basis')}" + (f", {scan.get('owners')} owners" if scan.get("owners") is not None else "")]
    if conc:
        lines.append(f"top holder {_pct(conc.get('top1_ex_infra'))}, top 10 {_pct(conc.get('top10_ex_infra'))} of supply excluding pools and exchanges; pools, exchanges and burn hold {_pct(conc.get('infra_share'))}")
    if clusters is not None:
        found = clusters.get("clusters", [])
        lines.append(f"funding checked for {clusters['wallets_with_funding_data']} of {clusters['wallets_total']} top wallets; shared-funder groups found: {len(found)}")
        lines += _capped([f"  group: {c['wallet_count']} wallets, {_pct(c['supply_share'])} of supply" for c in found])
    if fresh.get("status") in ("ok", "partial"):
        lines.append(f"wallet age: {fresh['counts']}; fresh supply share {_pct(fresh['fresh_supply_share'])}")
    out.append({"key": "helius", "name": "Helius on-chain data", "status": h_status, "age": 0.0 if h_status == "read" else None,
                "lines": lines if h_status == "read" else ["not read or unavailable (see Providers)"],
                "cannot_see": "funding and wallet age only for the top wallets; groups wallets by a shared funder, not by funding time"})

    j_status = _step_status(providers, "jupiter.")
    tags: dict[str, int] = {}
    for row in artifact.get("top_holders", []):
        for tag in row.get("jupiter_tags") or []:
            tags[tag] = tags.get(tag, 0) + 1
    sig = {s["name"]: s for s in artifact.get("signals", [])}
    none = lambda v: "none" if v is None else v  # noqa: E731
    jl = [f"holder count {none(token.get('jupiter_holder_count'))}; organic score {none(token.get('organic_score'))}",
          "tags on top holders: " + (", ".join(f"{k} {v}" for k, v in sorted(tags.items(), key=lambda kv: -kv[1])[:6]) if tags else "none present"),
          f"bundler holding {none(sig.get('jupiter_bundler_holding_pct', {}).get('value'))}%; bot holders {none(sig.get('jupiter_bot_holders_pct', {}).get('value'))}% (provider claims, information only)"]
    out.append({"key": "jupiter", "name": "Jupiter datapi", "status": j_status, "age": 0.0 if j_status == "read" else None,
                "lines": jl if j_status == "read" else ["not read or unavailable (see Providers)"],
                "cannot_see": "the top 100 holders only; the endpoint is undocumented; its aggregate shares are information only"})

    status_text = {"ok": "read", "empty": "empty", "unavailable": "unavailable", "skipped": "not run"}
    for key, name, limit in (("bubblemaps", "Bubblemaps rows (external artifact)", "the top 250 holders only; the data may be stale"),
                             ("gmgn", "GMGN rows (external artifact)", "the top 100 holders; its bundler tag covers launch-block buyers only")):
        f = findings.get(key)
        if f is None:
            out.append({"key": key, "name": name, "status": "not run", "age": None, "lines": ["not supplied (use --external-artifact)"], "cannot_see": limit})
            continue
        vals = [f"largest cluster {f['largest_cluster_pct']}%" if f.get("largest_cluster_pct") is not None else None,
                f"all clusters together {f['cluster_sum_pct']}%" if f.get("cluster_sum_pct") is not None else None,
                f"bundles {f['bundle_pct']}%" if f.get("bundle_pct") is not None else None]
        out.append({"key": key, "name": name, "status": status_text[f["status"]], "age": f.get("data_age_min"),
                    "lines": [", ".join(v for v in vals if v) or (f.get("detail") or "no values")], "cannot_see": limit})
    for key, f in by_identity.items():
        if key in ("bubblemaps", "gmgn"):
            continue
        vals = [f"largest cluster {f['largest_cluster_pct']}%" if f.get("largest_cluster_pct") is not None else None,
                f"alarm hint: {f['alarm_hint']}" if f.get("alarm_hint") else None]
        out.append({"key": f["provider"], "name": f"Provider {gating.provider_prose(f['provider'])} (artifact)", "status": status_text[f["status"]], "age": f.get("data_age_min"),
                    "lines": [", ".join(v for v in vals if v) or (f.get("detail") or "no values")],
                    "cannot_see": "whatever the provider does not report; an empty answer is unknown, not a reassurance"})
    return out


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f\u0085\u2028\u2029]+")
_MD_START_RE = re.compile(r"^[\s#>*+|\-=`~]+")
TEXT_CAP = 120  # longest single free-text value printed into a report (presentation limit)


def clean_text(value: Any, cap: int = TEXT_CAP) -> str:
    """The one sanitizer for free text from an artifact or provider before it is printed: no control characters or
    newlines (no extra lines), no leading markdown heading, quote, table or bullet marks, capped. HS-LABELS-T1: it is used
    only for provider text (symbol, identity, tags), so verdict words are replaced by the placeholder (provider_words.cut:
    made inert first, cut where the old rule cut, a placeholder counts as the text it replaced); otherwise unchanged."""
    return pw.cut(str(value), lambda s: _MD_START_RE.sub("", " ".join(_CONTROL_RE.sub(" ", s).split())), cap, trim=False)


def oneline(line: str) -> str:
    """Last guard over every rendered line."""
    return _CONTROL_RE.sub(" ", line)


def cell(value: Any) -> str:
    """A markdown table cell: sanitized, with the column separator neutralized."""
    return clean_text(value).replace("|", "/")


SIGNAL_LABELS = {
    "top1_ex_infra": "Top holder share",
    "top10_ex_infra": "Top 10 share",
    "largest_cluster": "Largest shared-funder group",
    "fresh_wallet_share": "Fresh wallet share",
    "tagged_bundler_share": "Jupiter-tagged bundler share",
    "unidentified_pda_share": "Unidentified program-account share",
    "jupiter_bot_holders_pct": "Jupiter bot holders",
    "jupiter_bundler_holding_pct": "Jupiter bundler holding",
    "mint_authority_active": "Mint authority",
    "freeze_authority_active": "Freeze authority",
}


def _is_stale(f: dict[str, Any]) -> bool:
    return f.get("status") == "ok" and (f.get("data_age_min") is None or f["data_age_min"] > gating.STALE_ALL_CLEAR_MIN)


def _display_name(provider: str) -> str:
    return {"bubblemaps": "Bubblemaps rows"}.get(provider) or gating.provider_prose(provider)


def cluster_alarm_texts(findings: list[dict[str, Any]]) -> list[str]:
    """Every clear large cluster or bundle share a provider reported over its bar, named with the bar; these lead the
    'Why' line. An alarm hint is corroboration wording only."""
    out = []
    for f in findings:
        if f.get("status") != "ok":
            continue
        parts = []
        if (f.get("largest_cluster_pct") or 0) >= gating.CLUSTER_ALARM_PCT:
            parts.append(f"largest cluster {f['largest_cluster_pct']:g}% of supply (bar {gating.CLUSTER_ALARM_PCT:g}%)")
        if (f.get("cluster_sum_pct") or 0) >= gating.AGGREGATE_CLUSTER_ALARM_PCT:
            parts.append(f"all clusters together {f['cluster_sum_pct']:g}% (bar {gating.AGGREGATE_CLUSTER_ALARM_PCT:g}%)")
        if (f.get("bundle_pct") or 0) >= gating.BUNDLE_ALARM_PCT:
            parts.append(f"bundles {f['bundle_pct']:g}% of supply (bar {gating.BUNDLE_ALARM_PCT:g}%)")
        if parts:
            out.append(f"{_display_name(f['provider'])}: " + "; ".join(parts))
        elif f.get("alarm_hint"):
            out.append(f"{_display_name(f['provider'])} hint (corroboration only): {f['alarm_hint']}")
    return out


def not_read_items(artifact: dict[str, Any]) -> list[str]:
    """Everything that was not run, unavailable, empty or only partly read (same facts as the Sources read blocks)."""
    items = ["funding-time cohort detector (not available in the dlmm-scan analysis step; run the dlmm-scan forensics step)"]
    cov = artifact["coverage"]
    if not cov.get("holder_scan_complete", False):
        items.append("the full holder scan (partial: top accounts only)")
    if cov.get("examined_noninfra_share", 0.0) < gating.COVERAGE_MIN_SUPPLY_SHARE:
        items.append(f"supply coverage (only {_pct(cov.get('examined_noninfra_share', 0.0))} of ordinary-wallet supply checked, minimum {_pct(gating.COVERAGE_MIN_SUPPLY_SHARE)})")
    stale = {gating.source_identity(f): f for f in artifact["coverage"].get("findings", []) if _is_stale(f)}
    for key, f in stale.items():
        items.append(f"fresh {gating.provider_prose(f['provider'])} data (stale: {_age_text(f.get('data_age_min'), 'age unknown')}, older than the {gating.STALE_ALL_CLEAR_MIN:g} min freshness limit)")
    for s in artifact["sources"]:
        if s["status"] == "read":
            continue
        if s["status"] == "not run" and s["key"] in ("bubblemaps", "gmgn"):
            continue  # optional external rows nobody supplied; named under 'Not requested'
        items.append(f"{s['name']} ({s['status']})")
    return items


def executive_summary(artifact: dict[str, Any]) -> list[str]:
    """At most SUMMARY_MAX_LINES plain-English lines; evidence first, the owner decides."""
    token = artifact["token"]
    flag = artifact["overall"]["flag"]
    sources = artifact["sources"]
    conc = artifact.get("concentration") or {}
    findings = artifact["coverage"].get("findings", [])
    lines = [f"Token {clean_text(token.get('symbol') or '?', 30)} ({artifact['mint']}), read {artifact['collected_at_utc'].replace('T', ' ').replace('Z', ' UTC')}.",
             f"FLAG: {flag['label']}"]
    if flag["why"]:
        failing = []
        for sg in artifact.get("signals", []):
            if sg["level"] not in ("fail", "warn") or sg.get("value") is None or sg.get("fail_at") is None or isinstance(sg["value"], str):
                continue
            fmt = (lambda v: f"{v:g}") if sg["name"].startswith("jupiter_") else _pct
            bar = sg["fail_at"] if sg["level"] == "fail" else sg["warn_at"]
            failing.append(f"{SIGNAL_LABELS.get(sg['name'], sg['name'])} {fmt(sg['value'])} ({sg['level']} at {fmt(bar)})")
        rest = [r for r in artifact["overall"]["verdict"].get("reasons", []) if " alarms" not in r and "at fail level" not in r and "at warn level" not in r and " alarm hint:" not in r]
        dis = artifact["overall"]["verdict"].get("disagreement") or {}
        texts = cluster_alarm_texts(findings)
        minor = [t for t in texts if "corroboration only" in t]
        main = [t for t in texts if t not in minor] + failing + [pw.keep_whole(r, 110) for r in rest]
        if artifact["overall"]["verdict"]["level"] == gating.VERDICT_UNRESOLVED and dis.get("disagreeing"):
            main.append("disagreeing source(s): " + ", ".join(gating.provider_prose(n) for n in dis["disagreeing"]))
        if not main:  # a CAUTION always states its reason
            hint_only = [f["provider"] for f in findings if f.get("status") == "ok" and f.get("alarm_hint") and not gating.finding_alarms(f)]
            if hint_only:
                main.append(f"only {', '.join(gating.provider_prose(n) for n in hint_only)} raised it (hint only, not confirmed by any other source)")
            else:
                main.append("no clear large cluster; only unproven items, see the Also line")
        if main:
            lines.append("Why: " + " | ".join(main[:5]))
        if minor:
            lines.append("Also: " + " | ".join(minor[:4]))
    elif flag["caveat"]:
        lines.append("Note: " + pw.keep_whole(flag["caveat"], 200))
    lines.append(f"Holders: top holder {_pct(conc.get('top1_ex_infra'))} and top 10 {_pct(conc.get('top10_ex_infra'))} of supply excluding pools and exchanges.")
    finds = [f for f in findings if f["status"] == "ok" and f.get("largest_cluster_pct") is not None]
    clusters = artifact.get("clusters")
    parts = [f"{gating.provider_prose(f['provider'])} largest {f['largest_cluster_pct']}%" + (f" (all together {f['cluster_sum_pct']}%; " if f.get("cluster_sum_pct") is not None else " (")
             + _age_text(f.get("data_age_min")) + (", STALE" if _is_stale(f) else "") + ")" for f in finds]
    if clusters is not None and (clusters.get("coverage") or 0) > 0:
        biggest = clusters["clusters"][0]["supply_share"] if clusters["clusters"] else 0.0
        parts.append(f"shared-funder groups among the top wallets: {len(clusters['clusters'])}, largest {_pct(biggest)}")
    lines.append("Largest clusters: " + ("; ".join(parts) if parts else "no source returned cluster data") + ".")
    lines.append("Funding cohorts (wallets first funded close together): not checked by the dlmm-scan analysis step; run the dlmm-scan forensics step.")
    read = [f"{s['name']} ({_age_text(s['age'])})" for s in sources if s["status"] == "read"]
    optional = [s["name"] for s in sources if s["key"] in ("bubblemaps", "gmgn") and s["status"] == "not run"]
    lines.append("Read: " + (", ".join(read) if read else "nothing") + "." + (f" Not requested: {', '.join(optional)}." if optional else ""))
    lines.append("Could not read: " + "; ".join(not_read_items(artifact)) + ".")
    lines.append("Your call: this tool raises a danger flag only on clear large clusters; no flag is NOT a safety signal.")
    return lines[: gating.SUMMARY_MAX_LINES]
