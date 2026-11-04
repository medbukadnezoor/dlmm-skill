"""holder-analysis mirror of the NO_ALARM gate hardening."""

from ha import gating
from test_gating import STRONG, core, cov, src
from ha import crosscheck as cc


def test_incomplete_scan_blocks_no_alarm():
    c = cov()
    ok = cc.overall(core(), STRONG, [], coverage=c, findings=[src()], cohort_ran=True)
    assert ok["verdict"]["level"] == gating.VERDICT_NO_ALARM
    c["holder_scan_complete"] = False
    out = cc.overall(core(), STRONG, [], coverage=c, findings=[src()], cohort_ran=True)
    assert out["verdict"]["level"] == gating.VERDICT_LIMITED
    assert any("scan was incomplete" in r for r in out["verdict"]["reasons"])


def test_fraction_unit_is_converted_and_ambiguity_is_unavailable_not_percent():
    f = gating.normalize_finding({"provider": "p", "status": "ok", "largest_cluster_pct": 0.25, "unit": "fraction"})
    assert f["largest_cluster_pct"] == 25.0
    rows = gating.normalize_findings_list([{"provider": "p", "status": "ok", "largest_cluster_pct": 0.3}])
    assert rows[0]["status"] == "unavailable" and "ambiguous" in rows[0]["detail"]
    assert gating.normalize_findings_list([{"provider": "p", "status": "ok", "largest_cluster_pct": 0.3}], "percent")[0]["largest_cluster_pct"] == 0.3
    assert gating.normalize_findings_list([{"provider": "p", "status": "ok", "largest_cluster_pct": 12.0}])[0]["largest_cluster_pct"] == 12.0


def test_aggregate_cluster_sum_alarms():
    f = gating.normalize_finding({"provider": "bubblemaps", "status": "ok", "largest_cluster_pct": 10, "cluster_sum_pct": 30, "unit": "percent"})
    assert gating.finding_alarms(f)
    assert gating.apply_disagreement([f], gating.VERDICT_LIMITED)["level"] == gating.VERDICT_HIGH
    quiet = gating.normalize_finding({"provider": "bubblemaps", "status": "ok", "largest_cluster_pct": 10, "cluster_sum_pct": 29.9, "unit": "percent"})
    assert gating.finding_alarms(quiet) == []


def test_artifact_bubblemaps_top10_sum_feeds_the_aggregate_alarm():
    art = {"providers": {"bubblemaps": {"status": "ok", "clusters": {"largest_cluster_share": 0.10, "top_10_cluster_share_sum": 0.35}, "supply_stats": {}, "freshness": {"age_seconds": 30}}}}
    row = gating.artifact_findings(art)[0]
    assert row["cluster_sum_pct"] == 35.0 and gating.finding_alarms(row)


def test_next_step_and_plain_wording_in_the_report():
    from ha import report
    from test_analysis import run

    text = report.render(run())
    assert "What to do next" in text
    assert "non-infrastructure" not in text and " bar" not in text
    assert "Unverified, so do not rely on the missing flag" in gating.next_step({"level": gating.VERDICT_LIMITED}, {"holder_scan_complete": False, "examined_noninfra_share": 0.1})
    assert "raise --max-pages" in gating.next_step({"level": gating.VERDICT_LIMITED}, {"holder_scan_complete": False})
    assert "Do not enter" in gating.next_step({"level": gating.VERDICT_HIGH}, {})
    assert "bubblemaps" in gating.next_step({"level": gating.VERDICT_UNRESOLVED, "disagreement": {"alarming": ["bubblemaps"], "disagreeing": ["gmgn"]}}, {})
    assert "not proof" in gating.next_step({"level": gating.VERDICT_NO_ALARM}, {})


def test_mixed_units_inside_one_finding_or_file_are_unavailable():
    mixed = gating.normalize_findings_list([{"provider": "p", "status": "ok", "largest_cluster_pct": 25.0, "bundle_pct": 0.5}])
    assert mixed[0]["status"] == "unavailable" and "ambiguous" in mixed[0]["detail"]
    rows = gating.normalize_findings_list([{"provider": "a", "status": "ok", "largest_cluster_pct": 25.0}, {"provider": "b", "status": "ok", "bundle_pct": 0.5}])
    assert [r["status"] for r in rows] == ["ok", "unavailable"]
    assert gating.normalize_findings_list([{"provider": "a", "status": "ok", "largest_cluster_pct": 25.0, "bundle_pct": 0.5, "unit": "percent"}])[0]["bundle_pct"] == 0.5
    assert gating.normalize_findings_list([{"provider": "z", "status": "empty", "largest_cluster_pct": 0.0}])[0]["status"] == "empty"


def test_duplicate_provider_names_are_kept_and_reported_not_dropped(tmp_path):
    import json

    from test_analysis import run

    path = tmp_path / "evidence.json"
    path.write_text(json.dumps({"provider_findings": [
        {"provider": "okx", "status": "ok", "largest_cluster_pct": 40, "unit": "percent"},
        {"provider": "OKX", "status": "ok", "largest_cluster_pct": 1, "unit": "percent"},
    ]}))
    art = run(external_artifact=path)
    assert art["providers"]["external_artifact.duplicate_providers"]["names"] == ["okx"]
    assert art["overall"]["verdict"]["level"] == gating.VERDICT_HIGH or art["overall"]["verdict"]["level"] == gating.VERDICT_UNRESOLVED  # the 40% alarm survives
    assert len(art["coverage"]["findings"]) == 2


def test_report_ends_with_a_glossary():
    from ha import report
    from test_analysis import run

    last = report.render(run()).strip().splitlines()[-1]
    assert last.startswith("Glossary:") and "cohort" in last and "Bubblemaps map" in last


def test_unreadable_or_out_of_range_fields_make_the_finding_unavailable():
    bad = [
        {"unit": "fraction", "largest_cluster_pct": 0.01, "cluster_sum_pct": 45},
        {"unit": "fraction", "largest_cluster_pct": 0.01, "bundle_pct": 45},
        {"unit": "percent", "largest_cluster_pct": 10, "cluster_sum_pct": "45"},
        {"unit": "percent", "largest_cluster_pct": 10, "cluster_sum_pct": 450},
        {"unit": "percent", "largest_cluster_pct": 10, "cluster_sum_pct": -45},
        {"unit": "percent", "largest_cluster_pct": 1, "cluster_sum_pct": 0.45},
        {"unit": "percent", "largest_cluster_pct": 10, "data_age_min": "5"},
    ]
    for extra in bad:
        f = gating.normalize_finding({"provider": "p", "status": "ok", **extra})
        assert f["status"] == "unavailable" and f["unreadable"] and f["largest_cluster_pct"] is None, extra
        assert gating.finding_alarms(f) == []
        out = cc.overall(core(), STRONG, [], coverage=cov(), findings=[f, src()], cohort_ran=True)
        assert "p" not in out["verdict"]["sources_counted"]


def test_ok_finding_with_no_readable_value_is_not_a_source_and_is_visible():
    f = gating.normalize_finding({"provider": "mystery", "status": "ok"})
    assert f["status"] == "unavailable" and f["unreadable"]
    assert gating.normalize_finding({"provider": "okx", "status": "ok", "alarm_hint": "same fund 0.9"})["status"] == "ok"
    from ha import report
    from test_analysis import run
    import json

    art = run()
    art["coverage"]["findings"] = [f]
    assert "provider mystery: ANSWERED BUT UNREADABLE" in report.render(art)
