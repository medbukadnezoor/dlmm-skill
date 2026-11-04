"""Verdict gating for holder-analysis: unknown is not safe, and no report reads as an all-clear on thin evidence."""

import re

from ha import crosscheck as cc
from ha import gating, report
from test_analysis import FakeHelius, FakeJupiter, run

REASSURING = re.compile(r"\b(clean|low)\b", re.I)


def sig(level, name="n"):
    return {"name": name, "level": level}


def core(level="ok"):
    return [sig(level, n) for n in sorted(cc.CORE_SIGNALS)]


def cov(share=0.8):
    return {"examined_noninfra_share": share, "examined_supply_share": share, "infra_share": 0.0, "holder_scan_complete": True}


def src(provider="bubblemaps", pct=2.0, status="ok"):
    return {"provider": provider, "status": status, "largest_cluster_pct": pct, "data_age_min": 1.0}


STRONG = {"status": "strong"}


def test_no_alarm_requires_cohort_coverage_and_two_sources():
    out = cc.overall(core(), STRONG, [], coverage=cov(), findings=[src()], cohort_ran=True)
    assert out["holder_risk"] == "no_alarm" and out["verdict"]["level"] == gating.VERDICT_NO_ALARM
    assert len(out["verdict"]["sources_counted"]) == 2


def test_default_cohort_detector_flag_keeps_holder_analysis_at_limited():
    assert gating.OWN_COHORT_DETECTOR_AVAILABLE is False
    out = cc.overall(core(), STRONG, [], coverage=cov(), findings=[src("bubblemaps"), src("insightx")])
    assert out["holder_risk"] == "limited" and out["verdict"]["level"] == gating.VERDICT_LIMITED
    assert any("cohort detector" in r for r in out["verdict"]["reasons"])


def test_coverage_under_bar_is_limited_and_bar_is_inclusive():
    bar = gating.COVERAGE_MIN_SUPPLY_SHARE
    low = cc.overall(core(), STRONG, [], coverage=cov(bar - 0.01), findings=[src()], cohort_ran=True)
    assert low["holder_risk"] == "limited"
    edge = cc.overall(core(), STRONG, [], coverage=cov(bar), findings=[src()], cohort_ran=True)
    assert edge["holder_risk"] == "no_alarm"


def test_one_source_empty_unavailable_and_non_cluster_rows_do_not_count():
    for findings in (
        [],
        [src(status="empty")],
        [src(status="unavailable")],
        [{"provider": "gmgn", "status": "ok", "largest_cluster_pct": None, "bundle_pct": 0.5}],
    ):
        out = cc.overall(core(), STRONG, [], coverage=cov(), findings=findings, cohort_ran=True)
        assert out["verdict"]["level"] == gating.VERDICT_LIMITED, findings


def test_a_fail_is_never_softened_by_great_coverage():
    out = cc.overall(core() + [sig("fail")], STRONG, [], coverage=cov(1.0), findings=[src(), src("x")], cohort_ran=True)
    assert out["holder_risk"] == "high" and out["verdict"]["level"] == gating.VERDICT_HIGH


def test_warn_is_elevated_and_unresolved_not_all_clear():
    out = cc.overall(core() + [sig("warn")], STRONG, [], coverage=cov(1.0), findings=[src(), src("x")], cohort_ran=True)
    assert out["holder_risk"] == "elevated" and out["verdict"]["level"] == gating.VERDICT_UNRESOLVED


def test_unmeasured_core_signal_stays_unknown_and_limited():
    out = cc.overall(core("unknown"), STRONG, [], coverage=cov(1.0), findings=[src(), src("x")], cohort_ran=True)
    assert out["holder_risk"] == "unknown"


def test_missing_coverage_argument_is_limited():
    assert cc.overall(core(), STRONG, [])["verdict"]["level"] == gating.VERDICT_LIMITED


def test_run_artifact_carries_coverage_block_and_detectors():
    art = run()
    coverage = art["coverage"]
    assert coverage["wallets_checked"] == 2 and coverage["wallets_with_funding_data"] == 2
    assert coverage["examined_supply_share"] == 0.5  # W1 + W2 of 1,000,000 supply
    states = {d["name"]: d["state"] for d in coverage["detectors"]}
    assert states["funding-time cohort (full holder list)"] == "not_run"
    assert states["acquisition-time check"] == "not_run"
    assert states["shared-funder clustering"] == "ran"


def test_coverage_with_no_helius_is_zero_and_unavailable():
    art = run(helius=None)
    assert art["coverage"]["examined_supply_share"] == 0.0
    assert art["overall"]["verdict"]["level"] in (gating.VERDICT_HIGH, gating.VERDICT_LIMITED)
    assert {d["name"]: d["state"] for d in art["coverage"]["detectors"]}["shared-funder clustering"] == "not_run"


def test_rendered_report_prints_coverage_and_never_reassures():
    for art in (run(), run(helius=None), run(jupiter=None)):
        text = report.render(art)
        assert "Verdict and coverage" in text and "NOT RUN" in text and "Detectors:" in text
        assert not REASSURING.search(text), REASSURING.search(text).group(0)


def test_all_quiet_run_prints_limited_not_low():
    class Quiet(FakeJupiter):
        def token(self, mint):
            tok = super().token(mint)
            tok["audit"]["bundlerStats"]["holdingPct"] = 0.0
            return tok

        def holders(self, mint, limit=100):
            data = super().holders(mint, limit)
            for row in data["holders"]:
                row["tags"], row["funder"] = [], None
            return data

    class QuietHelius(FakeHelius):
        def funded_by(self, wallet):
            self._hit("funded_by")
            return {"funder": wallet + "F", "name": None, "type": None, "amount": 4.0, "timestamp": 1}

        def largest_accounts(self, mint):
            self._hit("largest")
            return [{"token_account": "t1", "amount_raw": 30_000}, {"token_account": "t2", "amount_raw": 20_000}]

    art = run(helius=QuietHelius(), jupiter=Quiet())
    assert art["overall"]["holder_risk"] in ("limited", "unknown", "elevated", "high")
    assert art["overall"]["holder_risk"] != "low"
