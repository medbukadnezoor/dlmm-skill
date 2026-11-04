"""Cross-provider disagreement rule fed from --external-artifact rows (offline)."""

import json
import os

from ha import crosscheck as cc
from ha import gating, report
from test_analysis import NOW, FakeHelius, W1, W2, run
from test_gating import STRONG, cov, core, sig


def f(provider, cluster=None, bundle=None, age=1.0, status="ok", hint=None):
    return {"provider": provider, "status": status, "largest_cluster_pct": cluster, "bundle_pct": bundle, "data_age_min": age, "alarm_hint": hint}


def test_bars_are_inclusive_and_only_ok_alarms():
    assert gating.apply_disagreement([f("a", gating.CLUSTER_ALARM_PCT)], gating.VERDICT_LIMITED)["level"] == gating.VERDICT_HIGH
    assert gating.apply_disagreement([f("a", None, gating.BUNDLE_ALARM_PCT)], gating.VERDICT_LIMITED)["level"] == gating.VERDICT_HIGH
    assert gating.apply_disagreement([f("a", 14.9, 29.9)], gating.VERDICT_LIMITED)["level"] is None
    for status in ("empty", "unavailable", "skipped"):
        assert gating.apply_disagreement([f("a", 90.0, 90.0, status=status)], gating.VERDICT_LIMITED)["level"] is None


def test_alarm_against_quiet_provider_is_unresolved_naming_both():
    out = gating.apply_disagreement([f("bubblemaps", 25.45), f("gmgn", None, 0.76)], gating.VERDICT_LIMITED)
    assert out["level"] == gating.VERDICT_UNRESOLVED and out["alarming"] == ["bubblemaps"] and "gmgn" in out["disagreeing"]
    assert gating.apply_disagreement([f("bubblemaps", 25.45)], gating.VERDICT_LIMITED)["level"] == gating.VERDICT_HIGH


def test_alarm_hint_raises_unresolved_despite_low_label():
    out = gating.apply_disagreement([f("okx", 2.0, hint="same fund source 0.947")], gating.VERDICT_NO_ALARM)
    assert out["level"] == gating.VERDICT_UNRESOLVED and "okx" in out["reasons"][0]
    assert not gating.all_clear_counts(f("okx", 2.0, hint="x"), 100.0)


def test_normalize_finding_statuses_and_bad_values():
    for status in gating.PROVIDER_STATUSES:
        assert gating.normalize_finding({"provider": "p", "status": status, "largest_cluster_pct": 1.0 if status == "ok" else None})["status"] == status
    n = gating.normalize_finding({"provider": "x<b>", "status": "?"})
    assert n["status"] == "unavailable" and "<" not in n["provider"]
    assert gating.normalize_finding(None) is None


def test_stale_all_clear_on_young_token_does_not_count_but_alarm_does():
    kw = dict(coverage=cov(), cohort_ran=True)
    stale = cc.overall(core(), STRONG, [], findings=[f("bubblemaps", 2.0, age=gating.STALE_ALL_CLEAR_MIN + 1)], token_age_h=0.75, **kw)
    assert stale["verdict"]["level"] == gating.VERDICT_LIMITED
    fresh = cc.overall(core(), STRONG, [], findings=[f("bubblemaps", 2.0, age=gating.STALE_ALL_CLEAR_MIN)], token_age_h=0.75, **kw)
    assert fresh["verdict"]["level"] == gating.VERDICT_NO_ALARM
    old_token = cc.overall(core(), STRONG, [], findings=[f("bubblemaps", 2.0, age=500.0)], token_age_h=gating.YOUNG_TOKEN_MAX_AGE_H + 1, **kw)
    assert old_token["verdict"]["level"] == gating.VERDICT_NO_ALARM
    unknown_age = cc.overall(core(), STRONG, [], findings=[f("bubblemaps", 2.0, age=None)], token_age_h=None, **kw)
    assert unknown_age["verdict"]["level"] == gating.VERDICT_LIMITED
    stale_alarm = cc.overall(core(), STRONG, [], findings=[f("bubblemaps", 44.0, age=900.0)], token_age_h=0.75, coverage=cov(), cohort_ran=False)
    assert stale_alarm["holder_risk"] == "high"


def test_provider_alarm_overrides_quiet_signals_never_no_alarm():
    out = cc.overall(core(), STRONG, [], coverage=cov(1.0), cohort_ran=True, findings=[f("bubblemaps", 25.45), f("gmgn", None, 0.76)])
    assert out["verdict"]["level"] == gating.VERDICT_UNRESOLVED and out["holder_risk"] == "unresolved"
    out = cc.overall(core(), STRONG, [], coverage=cov(1.0), findings=[f("bubblemaps", 25.45)])
    assert out["verdict"]["level"] == gating.VERDICT_HIGH and out["holder_risk"] == "high"
    out = cc.overall(core() + [sig("fail")], STRONG, [], coverage=cov(1.0), cohort_ran=True, findings=[f("a", 1.0), f("b", 1.0)])
    assert out["holder_risk"] == "high"


def cape_artifact(largest=0.2545, bundles=0.44, status="ok", age_s=22.0):
    return {
        "providers": {
            "bubblemaps": {"status": status, "reason": None, "clusters": {"largest_cluster_share": largest}, "supply_stats": {"bundles": bundles}, "freshness": {"age_seconds": age_s}},
            "gmgn": {"holders": [{"address": W1, "share_total_supply": 0.0076, "tags": ["bundler"]}, {"address": W2, "share_total_supply": 0.2, "tags": []}]},
        }
    }


def test_artifact_findings_map_bubblemaps_and_gmgn():
    rows = {r["provider"]: r for r in gating.artifact_findings(cape_artifact(), extra_age_min=2.0)}
    assert rows["bubblemaps"]["largest_cluster_pct"] == 25.45 and rows["bubblemaps"]["bundle_pct"] == 44.0
    assert abs(rows["bubblemaps"]["data_age_min"] - (22 / 60 + 2.0)) < 1e-6
    assert rows["gmgn"]["largest_cluster_pct"] is None and abs(rows["gmgn"]["bundle_pct"] - 0.76) < 1e-9
    unknown = {r["provider"]: r for r in gating.artifact_findings({"providers": {"bubblemaps": {"status": "unknown", "reason": "clusters_empty_or_invalid"}}})}
    assert unknown["bubblemaps"]["status"] == "empty"
    failed = gating.artifact_findings({"providers": {"bubblemaps": {"status": "failed"}}})
    assert failed[0]["status"] == "unavailable"
    assert gating.artifact_findings({"providers": {"gmgn": {"holders": []}}})[0]["status"] == "empty"
    passthrough = gating.artifact_findings({"provider_findings": [{"provider": "okx", "status": "ok", "largest_cluster_pct": 1, "unit": "percent", "alarm_hint": "sub metric"}]})
    assert passthrough[0]["alarm_hint"] == "sub metric"


def test_cape_like_external_artifact_ends_high_or_unresolved_never_no_alarm(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(cape_artifact()))
    art = run(helius=FakeHelius(complete=False), external_artifact=path)
    level = art["overall"]["verdict"]["level"]
    assert level in (gating.VERDICT_HIGH, gating.VERDICT_UNRESOLVED)
    assert any("bubblemaps" in r for r in art["overall"]["verdict"]["reasons"])
    text = report.render(art)
    assert "provider bubblemaps: ran" in text and "provider gmgn: ran" in text


def test_empty_bubblemaps_artifact_is_limited_and_reported_empty(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps({"providers": {"bubblemaps": {"status": "unknown", "reason": "clusters_missing"}}}))
    art = run(external_artifact=path)
    assert art["overall"]["verdict"]["level"] != gating.VERDICT_NO_ALARM
    assert "EMPTY" in report.render(art)


def test_artifact_file_age_adds_to_data_age(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(cape_artifact(largest=0.02, bundles=0.01)))
    old = NOW.timestamp() - 3 * 3600
    os.utime(path, (old, old))
    art = run(external_artifact=path)
    row = next(r for r in art["coverage"]["findings"] if r["provider"] == "bubblemaps")
    assert 179 < row["data_age_min"] < 182
