import json
from datetime import datetime, timezone

import pytest

from ha import analysis, report
from ha.helius import BudgetExhausted
from ha.transport import TransportError

MINT = "Hg5Ja55T5wESq4vyFoiVCMeHXtGyVA69X2UHq8hgpump"
W1 = "8bDutiwy7JgL9fmjdz6LNsVZ9P91fw58SqSicy5rt2v8"
W2 = "4y2T1ghykCTq4EddoXjptZamk4qAsqcZw6eKxS8jdvE1"
PDA = "CR2wd49zdgdstjNjxNgz6ddZ5Nr87nJHpsAwhZJLiL4j"
NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)
LAUNCH = "2026-10-01T00:00:00Z"


class FakeHelius:
    def __init__(self, *, complete=True, fail=None, budget_after=None):
        self.calls, self.fail, self.complete, self.budget_after = {}, fail or {}, complete, budget_after
        self.max_calls = 100

    @property
    def total_calls(self):
        return sum(self.calls.values())

    def _hit(self, name):
        self.calls[name] = self.calls.get(name, 0) + 1
        if name in self.fail:
            raise self.fail[name]
        if self.budget_after is not None and name in ("funded_by", "first_activity") and self.calls[name] > self.budget_after:
            raise BudgetExhausted("cap")

    def token_supply(self, mint):
        self._hit("supply")
        return {"raw": 1_000_000, "decimals": 0}

    def mint_info(self, mint):
        self._hit("mint")
        return {"token_program": "T", "mint_authority": None, "freeze_authority": None, "extensions": []}

    def largest_accounts(self, mint):
        self._hit("largest")
        return [{"token_account": "t1", "amount_raw": 300_000}, {"token_account": "t2", "amount_raw": 200_000}]

    def token_account_owners(self, accounts):
        self._hit("owners")
        return {"t1": W1, "t2": W2}

    def all_holders(self, mint, *, max_pages):
        self._hit("scan")
        return {"owners": {W1: {"amount_raw": 300_000, "accounts": 1}, W2: {"amount_raw": 200_000, "accounts": 1}, PDA: {"amount_raw": 100_000, "accounts": 1}}, "complete": self.complete, "pages": 1}

    def owner_kinds(self, owners):
        self._hit("kinds")
        return {o: "wallet" for o in owners}

    def identities(self, owners):
        self._hit("identities")
        return {}

    def funded_by(self, wallet):
        self._hit("funded_by")
        return {"funder": "SHARED", "name": None, "type": None, "amount": 4.0, "timestamp": 1}

    def first_activity(self, wallet):
        self._hit("first_activity")
        return 1_790_000_000


class FakeJupiter:
    def __init__(self, *, holders_error=None):
        self.calls, self.holders_error = 0, holders_error

    def token(self, mint):
        self.calls += 1
        return {"symbol": "baton", "holderCount": 3, "totalSupply": 1_000_000.0, "firstPool": {"createdAt": LAUNCH}, "audit": {"mintAuthorityDisabled": True, "freezeAuthorityDisabled": True, "botHoldersPercentage": 1.0, "bundlerStats": {"holdingPct": 0.5}}}

    def holders(self, mint, limit=100):
        self.calls += 1
        if self.holders_error:
            raise self.holders_error
        rows = [{"owner": W1, "amount": 300_000.0, "tags": ["bundler"], "funder": "SHARED2", "funding_amount": 4.0}, {"owner": W2, "amount": 200_000.0, "tags": [], "funder": "SHARED2", "funding_amount": 4.0}]
        return {"count": 3, "holders": rows}

    def pools(self, mint):
        self.calls += 1
        return []


def run(**kw):
    kw.setdefault("helius", FakeHelius())
    kw.setdefault("jupiter", FakeJupiter())
    return analysis.run(MINT, now=NOW, **kw)


def test_full_run_builds_consistent_artifact():
    art = run()
    assert art["schema"] == "holder-analysis/1" and art["mint"] == MINT
    assert art["holder_scan"] == {"complete": True, "owners": 3, "basis": "full DAS scan"}
    assert [h["owner"] for h in art["top_holders"]][:2] == [W1, W2]
    assert art["top_holders"][0]["share"] == 0.3
    assert art["crosscheck"]["holders_vs_jupiter"]["status"] in ("strong", "partial")
    clusters = art["clusters"]["clusters"]
    assert len(clusters) == 1 and clusters[0]["supply_share"] == 0.5  # W1+W2 share a funder across providers
    signals = {s["name"]: s for s in art["signals"]}
    assert signals["largest_cluster"]["level"] == "fail"
    assert signals["tagged_bundler_share"]["value"] == 0.3
    assert art["budget"]["helius_total"] > 0 and art["budget"]["jupiter_calls"] == 3
    json.dumps(art)  # serialisable
    assert "SHARED" in report.render(art)


def test_partial_scan_falls_back_to_top_accounts():
    art = run(helius=FakeHelius(complete=False))
    assert art["holder_scan"]["complete"] is False
    assert art["holder_scan"]["basis"].startswith("top token accounts")
    assert [h["owner"] for h in art["top_holders"]] == [W1, W2]  # PDA only appears in the full scan


def test_provider_failure_is_unavailable_not_zero():
    art = run(jupiter=FakeJupiter(holders_error=TransportError("rate_limited", 429)))
    assert art["providers"]["jupiter.holders"] == {"status": "unavailable", "reason": "rate_limited", "http_status": 429}
    assert art["crosscheck"]["holders_vs_jupiter"]["status"] == "unknown"
    signals = {s["name"]: s for s in art["signals"]}
    assert signals["tagged_bundler_share"]["level"] == "unknown" and signals["tagged_bundler_share"]["value"] is None


def test_helius_failure_leaves_explicit_unknowns():
    art = run(helius=FakeHelius(fail={"supply": TransportError("auth_failed", 401)}))
    assert art["providers"]["helius.supply"]["reason"] == "auth_failed"
    assert art["top_holders"] == [] and art["concentration"] is None
    assert art["providers"]["helius.mint"]["status"] == "ok"  # other Helius calls still run and are recorded
    assert {s["name"]: s for s in art["signals"]}["top1_ex_infra"]["level"] == "unknown"
    # the Jupiter bundler tag (30% of supply) still drives the risk; the missing Helius evidence is listed, never read as safe
    assert art["overall"]["holder_risk"] == "high"
    assert "top1_ex_infra" in art["overall"]["unknown_signals"] and "top10_ex_infra" in art["overall"]["unknown_signals"]
    assert art["holder_scan"]["complete"] is False


def test_budget_exhaustion_marks_forensics_partial():
    art = run(helius=FakeHelius(budget_after=1))
    assert art["providers"]["helius.wallet_forensics"]["status"] == "partial"
    assert art["providers"]["helius.wallet_forensics"]["reason"] == "budget_exhausted"


def test_jupiter_only_and_helius_only_runs_do_not_crash():
    jup_only = run(helius=None)
    assert jup_only["top_holders"] == [] and jup_only["budget"]["helius_total"] == 0
    assert jup_only["overall"]["holder_risk"] != "low" and "top1_ex_infra" in jup_only["overall"]["unknown_signals"]
    # Jupiter's own total supply is enough to size the bundler-tagged share without Helius
    assert {s["name"]: s for s in jup_only["signals"]}["tagged_bundler_share"]["value"] == 0.3
    helius_only = run(jupiter=None)
    assert helius_only["crosscheck"]["holders_vs_jupiter"]["status"] == "unknown"
    assert helius_only["top_holders"]


def test_pool_removed_from_top1_without_shortening_the_window():
    class PoolJupiter(FakeJupiter):
        def pools(self, mint):
            return [{"id": W1, "dex": "x", "type": "x", "liquidity": 1, "volume24h": 1}]

    art = run(top=1, jupiter=PoolJupiter())
    conc = art["concentration"]
    assert [h["owner"] for h in art["top_holders"]] == [W1] and art["top_holders"][0]["kind"] == "liquidity_pool"
    assert conc["top1_ex_infra"] == 0.2  # the next real holder, not 0 because the displayed slice was all infra
    assert conc["largest_non_infra"]["owner"] == W2


def test_missing_funding_and_wallet_age_read_unknown_not_ok():
    class NoData(FakeHelius):
        def funded_by(self, wallet):
            self._hit("funded_by")
            return None

        def first_activity(self, wallet):
            self._hit("first_activity")
            return None

    class NoFunderJupiter(FakeJupiter):
        def holders(self, mint, limit=100):
            self.calls += 1
            return {"count": 3, "holders": [{"owner": W1, "amount": 300_000.0, "tags": [], "funder": None}, {"owner": W2, "amount": 200_000.0, "tags": [], "funder": None}]}

    art = run(helius=NoData(), jupiter=NoFunderJupiter())
    levels = {s["name"]: s["level"] for s in art["signals"]}
    assert levels["largest_cluster"] == "unknown" and levels["fresh_wallet_share"] == "unknown"
    assert art["overall"]["holder_risk"] == "high"  # the 30% holder still fails; unknowns never soften a fail
    assert {"largest_cluster", "fresh_wallet_share"} <= set(art["overall"]["core_unknown_signals"])
    assert "Not measured" in report.render(art)


def test_absent_jupiter_tag_fields_make_bundler_share_unknown():
    class NoTags(FakeJupiter):
        def holders(self, mint, limit=100):
            self.calls += 1
            return {"count": 3, "holders": [{"owner": W1, "amount": 300_000.0, "tags": None, "funder": None}]}

    art = run(jupiter=NoTags())
    bundler = {s["name"]: s for s in art["signals"]}["tagged_bundler_share"]
    assert bundler["level"] == "unknown" and bundler["value"] is None


def test_live_mint_authority_drives_risk_and_non_mint_is_unknown():
    class LiveMint(FakeHelius):
        def mint_info(self, mint):
            self._hit("mint")
            return {"token_program": "T", "mint_authority": "SomeKey", "freeze_authority": None, "extensions": []}

    art = run(helius=LiveMint())
    assert {s["name"]: s for s in art["signals"]}["mint_authority_active"]["level"] == "fail"
    assert art["overall"]["holder_risk"] == "high"
    assert "mint_authority_disabled" in {c["check"] for c in art["crosscheck"]["scalars"]}
    assert any(c["agree"] is False for c in art["crosscheck"]["scalars"])

    class NotAMint(FakeHelius):
        def mint_info(self, mint):
            self._hit("mint")
            raise TransportError("not_a_mint")

    art = run(helius=NotAMint())
    assert art["providers"]["helius.mint"]["reason"] == "not_a_mint"
    assert {s["name"]: s for s in art["signals"]}["mint_authority_active"]["level"] == "unknown"
    assert art["token"]["mint_authority"] == "unknown"


def test_unresolved_token_accounts_and_incomplete_scan_are_recorded():
    class Unresolved(FakeHelius):
        def token_account_owners(self, accounts):
            self._hit("owners")
            return {"t1": W1}  # t2 does not resolve

    art = run(helius=Unresolved(complete=False))
    assert art["providers"]["helius.largest_owners"] == {"status": "partial", "reason": "unresolved_token_accounts", "count": 1}
    assert art["providers"]["helius.holder_scan"]["status"] == "partial"


def test_external_artifact_without_rows_or_with_bad_bytes_is_recorded(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"providers": {}}))
    assert run(external_artifact=empty)["providers"]["external_artifact"]["reason"] == "no_gmgn_or_bubblemaps_rows"
    binary = tmp_path / "bin.json"
    binary.write_bytes(b"\xff\xfe\x00bad")
    assert run(external_artifact=binary)["providers"]["external_artifact"]["reason"] == "unreadable"


def test_invalid_mint_rejected():
    with pytest.raises(ValueError):
        analysis.run("not-a-mint", helius=None, jupiter=None)


def test_external_artifact_is_cross_checked(tmp_path):
    artifact = tmp_path / "evidence.json"
    artifact.write_text(json.dumps({"providers": {"gmgn": {"holders": [{"address": W1, "share_total_supply": 0.3}, {"address": W2, "share_total_supply": 0.2}]}}}))
    art = run(helius=FakeHelius(complete=False), external_artifact=artifact)  # two Helius rows, both in the provider list
    assert art["crosscheck"]["external"]["gmgn"]["status"] == "strong"
    full = run(external_artifact=artifact)  # third holder (a PDA) absent from the provider list -> only partial overlap
    assert full["crosscheck"]["external"]["gmgn"]["status"] == "partial"
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert run(external_artifact=bad)["providers"]["external_artifact"]["reason"] == "unreadable"
