"""Verdict gating: coverage block, detector status and the HIGH / UNRESOLVED / LIMITED / NO_ALARM levels.

Pure functions, no network. Convention shared with crosscheck.py: shares are fractions of total on-chain
supply (0.10 == 10%). The same rules live in the forensics engine (scripts/helius_forensics.py) in percent units.

Unknown is not safe. NO_ALARM is never worded "clean" or "low", and it is not proof of independent holders.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any

import provider_words as pw  # HS-LABELS-T1: verdict words in provider text (standard library only, no network)

# ---- PROVISIONAL thresholds (the one place for them) -------------------------------------------------
# Every value below rests on TWO positive cases (VEIL 2026-10-13, CAPE 2026-10-14) and no validated negative
# controls. They exist so a report cannot read as an all-clear on thin evidence; they are not calibrated.
VERDICT_HIGH = "HIGH"
VERDICT_UNRESOLVED = "UNRESOLVED"
VERDICT_LIMITED = "LIMITED"  # aka "unverified": the checks that ran found nothing, but too little ran
VERDICT_NO_ALARM = "NO_ALARM"
COVERAGE_MIN_SUPPLY_SHARE = 0.60  # share of NON-infrastructure supply the wallet-level detectors must have seen
MIN_CLUSTER_SOURCES = 2  # independent cluster-capable sources needed for NO_ALARM (the cohort detector counts as one)
YOUNG_TOKEN_MAX_AGE_H = 24.0  # younger (or unknown age): a provider's all-clear must be fresh to count
CLUSTER_ALARM_PCT = 15.0  # a provider reporting a cluster this large (% of supply) alarms (CAPE handoff's example bar)
BUNDLE_ALARM_PCT = 30.0  # a provider reporting bundles this large (% of supply) alarms (same source)
STALE_ALL_CLEAR_MIN = 15.0  # on a young token a provider all-clear older than this does not count toward NO_ALARM
PROVIDER_STATUSES = ("ok", "empty", "unavailable", "skipped")
# Report layout (presentation only, no effect on any verdict): the report shows evidence and the owner decides.
SUMMARY_MAX_LINES = 12  # executive summary length ceiling, in lines
LIST_CAP = 8  # items listed per source before "and N more"
FLAG_DANGER = "DANGER FLAG"  # HIGH: a fail or an uncontradicted provider alarm
FLAG_CAUTION = "CAUTION"  # UNRESOLVED: a warning or a provider disagreement is open
FLAG_NONE = "NO FLAG RAISED (not a safety signal)"  # LIMITED and NO_ALARM: never reassurance
AGGREGATE_CLUSTER_ALARM_PCT = 30.0  # SUM of a provider's cluster shares alarms too (CAPE: about 43% across clusters, largest only 25%)
UNITS = ("percent", "fraction")
# The analysis step has no full-holder-list funding-time cohort detector (that is the forensics step). Until it
# gains one, NO_ALARM is unreachable here and the best result is LIMITED. Flip only with a real detector.
OWN_COHORT_DETECTOR_AVAILABLE = False


def coverage_block(conc: dict[str, Any] | None, cluster_info: dict[str, Any] | None, *, scan_complete: bool) -> dict[str, Any]:
    """What the wallet-level detectors actually looked at (fractions of total supply)."""
    infra = float((conc or {}).get("infra_share") or 0.0)
    ci = cluster_info or {}
    covered = float(ci.get("covered_share") or 0.0)
    basis = 1.0 - infra
    return {
        "wallets_checked": int(ci.get("wallets_total") or 0),
        "wallets_with_funding_data": int(ci.get("wallets_with_funding_data") or 0),
        "examined_supply_share": round(covered, 6),
        "examined_noninfra_share": round(min(1.0, covered / basis), 6) if basis > 0 else 0.0,
        "infra_share": round(infra, 6),
        "holder_scan_complete": bool(scan_complete),
    }


def detector_rows(cluster_info: dict[str, Any] | None, fresh: dict[str, Any] | None, *, cohort_ran: bool, min_coverage: float) -> list[dict[str, str]]:
    """Which detectors ran. state: ran | partial | not_run | unavailable."""
    rows: list[dict[str, str]] = []
    if cluster_info is None:
        rows.append({"name": "shared-funder clustering", "state": "not_run", "detail": "no wallets were checked"})
    elif (cluster_info.get("coverage") or 0) < min_coverage:
        rows.append({"name": "shared-funder clustering", "state": "unavailable", "detail": f"funding data for {cluster_info['wallets_with_funding_data']}/{cluster_info['wallets_total']} wallets"})
    else:
        state = "ran" if cluster_info["wallets_with_funding_data"] == cluster_info["wallets_total"] else "partial"
        rows.append({"name": "shared-funder clustering", "state": state, "detail": f"funding data for {cluster_info['wallets_with_funding_data']}/{cluster_info['wallets_total']} wallets"})
    fstatus = (fresh or {}).get("status")
    rows.append({"name": "wallet age", "state": {"ok": "ran", "partial": "partial"}.get(fstatus, "unavailable" if fresh else "not_run"), "detail": (fresh or {}).get("reason", "")})
    rows.append(
        {
            "name": "funding-time cohort (full holder list)",
            "state": "ran" if cohort_ran else "not_run",
            "detail": "" if cohort_ran else "not available in the dlmm-scan analysis step; run the dlmm-scan forensics step",
        }
    )
    rows.append({"name": "acquisition-time check", "state": "not_run", "detail": "not available in the dlmm-scan analysis step; run the dlmm-scan forensics step"})
    return rows


def _num(value: Any, lo: float = 0.0, hi: float = 100.0) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return float(value) if lo <= value <= hi else None


def _inert(text: str) -> str:
    return "".join(ch for ch in text if ch.isalnum() or ch in " ._-:/%")


def _text(value: Any) -> str | None:
    """Provider text reduced to inert characters, 48 at most, verdict words replaced by the placeholder (HS-LABELS-T1)."""
    return pw.label(value, _inert, 48)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _identity(raw_name: Any, shown: str) -> dict[str, str]:
    """HS-LABELS-T1 R5 / N2: a provider's identity stays its name before the rule, so two providers whose names both lose a
    word ("Safe Scanner", "Clean Scanner") are still two providers (duplicate check, one Sources-read block each). Stored
    only when the rule changed the name, as digests (the old name holds the removed word, so it is never saved): the
    lowercased name (the duplicate check, case-insensitive as before) and the name as written (the Sources-read blocks,
    case-preserving as before: "Safe Scanner" and "safe scanner" are flagged as duplicates and still shown as two blocks)."""
    old = (_inert(raw_name)[:48].strip() if isinstance(raw_name, str) else "") or "unnamed_provider"
    return {} if old == shown else {"provider_key": f"name-{_digest(old.lower())}-{_digest(old)}"}


def finding_identity(f: dict[str, Any]) -> str:
    """The key the duplicate check compares: the name before the rule (see _identity), lowercased, as before HS-LABELS-T1."""
    key = f.get("provider_key")
    return key.rsplit("-", 1)[0] if key else f["provider"].lower()


def source_identity(f: dict[str, Any]) -> str:
    """The key of a provider's Sources-read block: the name before the rule as written (see _identity), as before."""
    return f.get("provider_key") or f["provider"]


def normalize_finding(raw: Any, default_unit: str | None = None) -> dict[str, Any] | None:
    """Common provider-finding schema, always in PERCENT. A finding's own `unit` ("percent" or "fraction") wins over
    `default_unit`; fractions are converted. Provider text is untrusted and reduced to inert characters.

    A share or age field that is PRESENT and non-null but not a number, out of range for its unit, or a cluster sum
    below the largest cluster (mixed units) makes the whole finding `unavailable` with that reason: an unreadable
    value must never read as "no alarm". An `ok` finding with no readable value at all is `unavailable` and flagged
    `unreadable`, so it never counts as a source."""
    if not isinstance(raw, dict):
        return None
    status = raw.get("status")
    unit = raw.get("unit") if raw.get("unit") in UNITS else default_unit
    scale = 100.0 if unit == "fraction" else 1.0
    top = 1.0 if unit == "fraction" else 100.0
    problems: list[str] = []

    def field(key: str, hi: float, mult: float = 1.0) -> float | None:
        value = raw.get(key)
        if value is None:
            return None
        v = _num(value, 0.0, hi)
        if v is None:
            problems.append(f"{key} is not a number in range 0 to {hi:g}")
            return None
        return round(v * mult, 6)

    largest, total, bundle = field("largest_cluster_pct", top, scale), field("cluster_sum_pct", top, scale), field("bundle_pct", top, scale)
    age = field("data_age_min", 10**7)
    if largest is not None and total is not None and total + 1e-6 < largest:
        problems.append("cluster_sum_pct is smaller than largest_cluster_pct (mixed units?)")
    status = status if status in PROVIDER_STATUSES else "unavailable"
    hint = _text(raw.get("alarm_hint"))
    detail = _text(raw.get("detail")) or ""
    unreadable = False
    name = _text(raw.get("provider")) or "unnamed_provider"
    if problems:
        return {"provider": name, "status": "unavailable", "largest_cluster_pct": None, "cluster_sum_pct": None, "bundle_pct": None,
                "data_age_min": None, "detail": _text("unreadable value: " + "; ".join(problems)) or "unreadable value", "unreadable": True, "alarm_hint": None,
                **_identity(raw.get("provider"), name)}
    if status == "ok" and largest is None and total is None and bundle is None and not hint:
        status, unreadable, detail = "unavailable", True, "answered but unreadable: no usable value"
    return {
        "provider": name,
        "status": status,
        "largest_cluster_pct": largest,
        "cluster_sum_pct": total,
        "bundle_pct": bundle,
        "data_age_min": age,
        "detail": detail,
        "unreadable": unreadable,
        # a sub-metric contradicting the provider's own low label (OKX on CAPE): raises UNRESOLVED, never an all-clear
        "alarm_hint": hint,
        **_identity(raw.get("provider"), name),
    }


def normalize_findings_list(rows: Any, file_unit: str | None = None) -> list[dict[str, Any]]:
    """Findings from a `provider_findings` list. Units must be explicit (per finding or `file_unit`). If no unit is
    given and every share is <= 1 the value is ambiguous: the finding becomes `unavailable` with that reason
    instead of a fraction being silently read as percent."""
    out = []
    keys = ("largest_cluster_pct", "cluster_sum_pct", "bundle_pct")
    for raw in rows if isinstance(rows, list) else []:
        if not isinstance(raw, dict):
            continue
        if raw.get("unit") not in UNITS and file_unit is None:
            values = [v for k in keys if isinstance((v := raw.get(k)), (int, float)) and not isinstance(v, bool) and 0 < v <= 1]
            if values:  # ANY non-zero share <= 1 without a unit is ambiguous, even next to percent-looking fields
                f = normalize_finding({"provider": raw.get("provider"), "status": "unavailable", "detail": "ambiguous unit: add unit percent or fraction"})
                if f:
                    out.append(f)
                continue
        f = normalize_finding(raw, file_unit)
        if f:
            out.append(f)
    return out


def duplicate_providers(findings: list[dict[str, Any]]) -> list[str]:
    """Provider names that appear more than once. No finding is dropped (a duplicate alarm must still alarm); the
    caller records the duplication loudly instead."""
    seen: set[str] = set()
    dup: list[str] = []
    for f in findings:
        ident, name = finding_identity(f), f["provider"].lower()
        if ident in seen and name not in dup:
            dup.append(name)
        seen.add(ident)
    return dup


def finding_alarms(f: dict[str, Any]) -> list[str]:
    """Alarm reasons from one finding. Data of any age can alarm; only status ok can."""
    if f.get("status") != "ok":
        return []
    out = []
    if (f.get("largest_cluster_pct") or 0) >= CLUSTER_ALARM_PCT:
        out.append(f"largest cluster {f['largest_cluster_pct']:g}% >= {CLUSTER_ALARM_PCT:g}%")
    if (f.get("cluster_sum_pct") or 0) >= AGGREGATE_CLUSTER_ALARM_PCT:
        out.append(f"clusters together hold {f['cluster_sum_pct']:g}% >= {AGGREGATE_CLUSTER_ALARM_PCT:g}%")
    if (f.get("bundle_pct") or 0) >= BUNDLE_ALARM_PCT:
        out.append(f"bundles {f['bundle_pct']:g}% >= {BUNDLE_ALARM_PCT:g}%")
    return out


def is_young(token_age_h: float | None) -> bool:
    return token_age_h is None or token_age_h < YOUNG_TOKEN_MAX_AGE_H


def all_clear_counts(f: dict[str, Any], token_age_h: float | None) -> bool:
    """Needs readable data, no alarm or hint, and on a young (or unknown-age) token data no older than
    STALE_ALL_CLEAR_MIN; an unreadable data age counts as stale."""
    if f.get("status") != "ok" or finding_alarms(f) or f.get("alarm_hint"):
        return False
    if is_young(token_age_h):
        age = f.get("data_age_min")
        return age is not None and age <= STALE_ALL_CLEAR_MIN
    return True


def apply_disagreement(findings: list[dict[str, Any]], own_verdict: str) -> dict[str, Any]:
    """Cross-provider disagreement rule (pure). own_verdict: HIGH, UNRESOLVED, LIMITED or NO_ALARM (own signals
    alarmed / ran and found nothing). Returns HIGH or UNRESOLVED naming the alarming provider(s) and whoever
    disagrees, or level None when no provider alarms. An `alarm_hint` raises UNRESOLVED at least."""
    alarming = [{"provider": f["provider"], "reasons": finding_alarms(f)} for f in findings if finding_alarms(f)]
    hinted = [f for f in findings if f.get("status") == "ok" and f.get("alarm_hint") and not finding_alarms(f)]
    hint_reasons = [f"{f['provider']} alarm hint: {f['alarm_hint']} (the provider's own headline may disagree)" for f in hinted]
    if not alarming and not hinted:
        return {"level": None, "alarming": [], "disagreeing": [], "reasons": []}
    if not alarming:
        return {"level": VERDICT_UNRESOLVED, "alarming": [f["provider"] for f in hinted], "disagreeing": [], "reasons": hint_reasons}
    calm = [f["provider"] for f in findings if f.get("status") == "ok" and not finding_alarms(f) and not f.get("alarm_hint")]
    if own_verdict == VERDICT_NO_ALARM:
        calm.insert(0, "own detectors")
    if own_verdict == VERDICT_HIGH or not calm:
        level, reasons = VERDICT_HIGH, [f"{a['provider']} alarms: {'; '.join(a['reasons'])}" for a in alarming]
    else:
        level = VERDICT_UNRESOLVED
        reasons = [f"{a['provider']} alarms ({'; '.join(a['reasons'])}) while {', '.join(calm)} report no alarm" for a in alarming]
    return {"level": level, "alarming": [a["provider"] for a in alarming], "disagreeing": calm if level == VERDICT_UNRESOLVED else [], "reasons": reasons + hint_reasons}


def decide_verdict(
    own_level: str | None,
    coverage: dict[str, Any] | None,
    *,
    cohort_ran: bool,
    findings: list[dict[str, Any]] | None = None,
    token_age_h: float | None = None,
) -> dict[str, Any]:
    """own_level is HIGH / UNRESOLVED when this skill's own signals alarmed, else None.

    A provider alarm always surfaces as HIGH or UNRESOLVED (disagreement rule). NO_ALARM needs all of: coverage >=
    COVERAGE_MIN_SUPPLY_SHARE, the cohort detector ran, and MIN_CLUSTER_SOURCES independent cluster-capable
    sources whose all-clear counts (the cohort detector is one). Anything else that did not alarm is LIMITED."""
    findings = findings or []
    cov = coverage or {}
    quiet_own = VERDICT_NO_ALARM if cohort_ran and cov.get("examined_noninfra_share", 0.0) >= COVERAGE_MIN_SUPPLY_SHARE else VERDICT_LIMITED
    dis = apply_disagreement(findings, own_level if own_level == VERDICT_HIGH else quiet_own)
    if own_level == VERDICT_HIGH or dis["level"] == VERDICT_HIGH:
        reasons = (["a signal in this report is at fail level"] if own_level == VERDICT_HIGH else []) + dis["reasons"]
        return {"level": VERDICT_HIGH, "reasons": reasons, "sources_counted": [], "no_alarm_blockers": [], "disagreement": dis}
    if own_level == VERDICT_UNRESOLVED or dis["level"] == VERDICT_UNRESOLVED:
        reasons = (["a signal in this report is at warn level"] if own_level == VERDICT_UNRESOLVED else []) + dis["reasons"]
        return {"level": VERDICT_UNRESOLVED, "reasons": reasons, "sources_counted": [], "no_alarm_blockers": [], "disagreement": dis}
    blockers: list[str] = []
    if not cov.get("holder_scan_complete", False):
        blockers.append("the holder scan was incomplete (top accounts only); shares and coverage are partial")
    if not cohort_ran:
        blockers.append("no funding-time cohort detector ran over the full holder list")
    share = cov.get("examined_noninfra_share", 0.0)
    if share < COVERAGE_MIN_SUPPLY_SHARE:
        blockers.append(f"only {share:.0%} of the supply held by ordinary wallets was checked; at least {COVERAGE_MIN_SUPPLY_SHARE:.0%} is needed")
    sources = ["cohort detector"] if cohort_ran else []
    for f in findings:
        if f.get("status") != "ok" or f.get("largest_cluster_pct") is None:
            continue
        if all_clear_counts(f, token_age_h):
            sources.append(f["provider"])
        else:
            blockers.append(f"{f['provider']} all-clear not counted: data age {'none' if f.get('data_age_min') is None else f.get('data_age_min')} min on a young token (must be at most {STALE_ALL_CLEAR_MIN:g} min old)")
    if len(sources) < MIN_CLUSTER_SOURCES:
        blockers.append(f"{len(sources)} independent cluster-capable source(s) with a countable all-clear; {MIN_CLUSTER_SOURCES} are needed")
    if blockers:
        return {"level": VERDICT_LIMITED, "reasons": blockers, "sources_counted": sources, "no_alarm_blockers": blockers, "disagreement": dis}
    return {"level": VERDICT_NO_ALARM, "reasons": ["no detector alarmed; this is not proof of independent holders"], "sources_counted": sources, "no_alarm_blockers": [], "disagreement": dis}


def artifact_findings(artifact: Any, *, extra_age_min: float = 0.0) -> list[dict[str, Any]]:
    """Normalized findings from an lp-research-companion evidence artifact (--external-artifact rows).

    Bubblemaps (providers.bubblemaps): status ok or stale -> ok with its data age (+ artifact file age), unknown ->
    empty, anything else unavailable; an empty cluster list is empty, never zero concentration.
    GMGN (providers.gmgn.holders): bundler-tagged share of supply only, not cluster-capable. An already-normalized
    list under artifact["provider_findings"] is passed through normalize_finding."""
    providers = artifact.get("providers") if isinstance(artifact, dict) else None
    out: list[dict[str, Any]] = []
    if isinstance(artifact, dict) and isinstance(artifact.get("provider_findings"), list):
        out += normalize_findings_list(artifact["provider_findings"], artifact.get("provider_findings_unit") if artifact.get("provider_findings_unit") in UNITS else None)
    if not isinstance(providers, dict):
        return out
    bub = providers.get("bubblemaps")
    if isinstance(bub, dict):
        status = bub.get("status")
        clusters = bub.get("clusters") if isinstance(bub.get("clusters"), dict) else {}
        largest = clusters.get("largest_cluster_share")
        stats = bub.get("supply_stats") if isinstance(bub.get("supply_stats"), dict) else {}
        fresh = bub.get("freshness") if isinstance(bub.get("freshness"), dict) else {}
        age_s = fresh.get("age_seconds")
        row: dict[str, Any] = {"provider": "bubblemaps", "status": "unavailable", "detail": str(bub.get("reason") or status or "")}
        if status in ("ok", "stale") and isinstance(largest, (int, float)) and not isinstance(largest, bool):
            row.update(status="ok", largest_cluster_pct=largest * 100)
            top_sum = clusters.get("top_10_cluster_share_sum")
            if isinstance(top_sum, (int, float)) and not isinstance(top_sum, bool):
                row["cluster_sum_pct"] = min(100.0, top_sum * 100)
            bundles = stats.get("bundles")
            if isinstance(bundles, (int, float)) and not isinstance(bundles, bool):
                row["bundle_pct"] = bundles * 100
            if isinstance(age_s, (int, float)) and not isinstance(age_s, bool):
                row["data_age_min"] = age_s / 60 + max(extra_age_min, 0.0)
        elif status == "unknown":
            row["status"] = "empty"
        n = normalize_finding(row)
        if n:
            out.append(n)
    gm = providers.get("gmgn")
    rows = gm.get("holders") if isinstance(gm, dict) else None
    if isinstance(rows, list):
        shares = [(r.get("share_total_supply"), r.get("share"), r.get("tags")) for r in rows if isinstance(r, dict)]
        usable = [x for x in shares if any(isinstance(v, (int, float)) and not isinstance(v, bool) for v in x[:2])]
        if not usable:
            out.append(normalize_finding({"provider": "gmgn", "status": "empty", "detail": "no usable holder rows"}))
        else:
            total = 0.0
            for a, b, tags in usable:
                val = a if isinstance(a, (int, float)) and not isinstance(a, bool) else b
                if 0 <= val <= 1 and isinstance(tags, list) and any(str(t).lower() == "bundler" for t in tags):
                    total += val
            out.append(normalize_finding({"provider": "gmgn", "status": "ok", "bundle_pct": total * 100, "detail": "bundler-tagged top holders only; no cluster data"}))
    return out


def next_step(verdict: dict[str, Any], coverage: dict[str, Any]) -> str:
    """One plain 'what to do next' line per verdict."""
    level = verdict["level"]
    if level == VERDICT_HIGH:
        return "Do not enter on the assumption that holders are independent. Verify the flagged wallets by hand (Bubblemaps map, Solscan) before any decision."
    if level == VERDICT_UNRESOLVED:
        dis = verdict.get("disagreement") or {}
        names = sorted(set(dis.get("alarming", [])) | set(dis.get("disagreeing", [])))
        who = f"Compare {', '.join(names)} and run the dlmm-scan forensics step" if names else "Check the warned signals by hand and run the dlmm-scan forensics step"
        return f"{who}; do not treat the holders as independent until the conflict is explained."
    if level == VERDICT_LIMITED:
        todo = ["run the dlmm-scan forensics step (full holder list, funding-time cohort detector and the Bubblemaps map step)"]
        if not coverage.get("holder_scan_complete", True):
            todo.append("raise --max-pages so the holder scan completes")
        if coverage.get("examined_noninfra_share", 0.0) < COVERAGE_MIN_SUPPLY_SHARE:
            todo.append("raise --funding-top to check more wallets")
        todo.append("or supply Bubblemaps/GMGN rows with --external-artifact")
        return "Unverified, so do not rely on the missing flag: " + "; ".join(todo) + "."
    return "Re-run before acting if the token is young: provider data ages quickly. This is not proof of independent holders."


PROVIDER_PROSE = {"bubblemaps": "Bubblemaps", "gmgn": "GMGN", "jupiter": "Jupiter", "okx": "OKX", "insightx": "InsightX", "cabalspy": "CabalSpy", "solscanner": "SolScanner", "helius": "Helius"}


def provider_prose(name: str) -> str:
    """Readable provider name for prose (raw ids stay in JSON)."""
    return PROVIDER_PROSE.get(name) or _text(name) or "unnamed provider"


def flag_for(verdict: dict[str, Any], findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Presentation mapping of the underlying level; it never changes a gating or disagreement rule.

    UNRESOLVED stays CAUTION unless a cluster-grade provider finding (largest cluster, clusters together or bundle share
    at or over its alarm bar) exists: clear large clusters mean a dangerous token, and a calm reading from a source with
    known blind spots does not cancel them. The flag then names the disagreement. Hints alone stay CAUTION."""
    level = verdict["level"]
    label = {VERDICT_HIGH: FLAG_DANGER, VERDICT_UNRESOLVED: FLAG_CAUTION}.get(level, FLAG_NONE)
    if level == VERDICT_UNRESOLVED and any(finding_alarms(f) for f in findings or []):
        calm = (verdict.get("disagreement") or {}).get("disagreeing") or []
        label = FLAG_DANGER + (f" (clear large cluster; sources disagree: {', '.join(provider_prose(n) + ' reads calm' if n != 'own detectors' else 'own detectors read calm' for n in calm)})" if calm else " (clear large cluster)")
    why = list(verdict.get("reasons", []))[:3] if level in (VERDICT_HIGH, VERDICT_UNRESOLVED) else []
    caveat = None
    if level == VERDICT_LIMITED:
        caveat = "coverage is limited: " + (verdict.get("reasons") or ["too little was checked"])[0]
    elif level == VERDICT_NO_ALARM:
        caveat = "every required check ran and none alarmed; that is still not proof of independent holders"
    return {"label": label, "level": level, "why": why, "caveat": caveat}
