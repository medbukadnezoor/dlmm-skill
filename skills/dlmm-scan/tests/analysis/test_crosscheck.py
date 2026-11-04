from ha import crosscheck as cc

WALLET = "8bDutiwy7JgL9fmjdz6LNsVZ9P91fw58SqSicy5rt2v8"  # on-curve
PDA = "CR2wd49zdgdstjNjxNgz6ddZ5Nr87nJHpsAwhZJLiL4j"  # off-curve
BURN = "1nc1nerator11111111111111111111111111111111"


def classify(owner, **kw):
    kw.setdefault("owner_kind", None)
    kw.setdefault("identity", None)
    kw.setdefault("pool_ids", set())
    return cc.classify_owner(owner, **kw)


def test_classify_kinds():
    assert classify(BURN) == "burn"
    assert classify(PDA, pool_ids={PDA}) == "liquidity_pool"
    assert classify(WALLET, identity={"category": "Exchange", "name": "MEXC Exchange", "tags": []}) == "exchange"
    assert classify(PDA, identity={"name": "Raydium Authority", "tags": []}) == "liquidity_pool"
    assert classify(PDA, identity={"name": "Jupiter Team Cold Multisig", "tags": []}) == "controlled_vault"
    assert classify(PDA) == "program_account"
    assert classify(WALLET, owner_kind="program:LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo") == "program_account"
    assert classify(WALLET) == "wallet"


def row(owner, share, amount=None):
    return {"owner": owner, "share": share, "amount": amount if amount is not None else share * 1000, "token_accounts": 1}


def test_concentration_keeps_multisigs_but_drops_pools():
    rows = [row("vault", 0.30), row("pool", 0.20), row("w1", 0.10), row("w2", 0.05)]
    kinds = {"vault": "controlled_vault", "pool": "liquidity_pool", "w1": "wallet", "w2": "wallet"}
    out = cc.concentration(rows, kinds, 1000)
    assert out["infra_share"] == 0.2
    assert out["top1_ex_infra"] == 0.3 and out["top1_wallets_only"] == 0.1 and out["top1_all"] == 0.3
    assert out["top5_ex_infra"] == 0.45
    assert out["controlled_vault_share"] == 0.3
    assert out["largest_non_infra"] == {"owner": "vault", "share": 0.3, "kind": "controlled_vault"}


def test_helius_row_math_and_largest_fold():
    rows = cc.helius_rows({"a": {"amount_raw": 600, "accounts": 1}, "b": {"amount_raw": 400, "accounts": 2}}, 2, 1000)
    assert [r["owner"] for r in rows] == ["a", "b"] and rows[0]["amount"] == 6.0 and rows[0]["share"] == 0.6
    folded = cc.largest_account_rows(
        [{"token_account": "t1", "amount_raw": 300}, {"token_account": "t2", "amount_raw": 200}, {"token_account": "t3", "amount_raw": 100}],
        {"t1": "o1", "t2": "o1", "t3": "o2"},
        0,
        1000,
    )
    assert folded[0]["owner"] == "o1" and folded[0]["share"] == 0.5


def holders(*pairs):
    return [row(o, s, a) for o, s, a in pairs]


def test_compare_holders_strong_partial_poor_unknown():
    helius = holders(("a", 0.4, 400), ("b", 0.3, 300), ("c", 0.2, 200), ("d", 0.1, 100))
    jup = [{"owner": o, "amount": a} for o, _, a in [("a", 0.4, 400), ("b", 0.3, 300), ("c", 0.2, 200), ("d", 0.1, 100)]]
    assert cc.compare_holders(helius, jup, top_n=4)["status"] == "strong"
    skew = [dict(j) for j in jup]
    skew[0]["amount"] = 480  # +20%
    result = cc.compare_holders(helius, skew, top_n=4)
    assert result["status"] == "partial" and len(result["balance_mismatches"]) == 1
    missing = cc.compare_holders(helius, jup[:3], top_n=4)
    assert missing["status"] == "partial" and missing["helius_top_missing_from_jupiter"][0]["owner"] == "d"
    assert cc.compare_holders(helius, [{"owner": "zz", "amount": 1}], top_n=4)["status"] == "poor"
    assert cc.compare_holders([], jup)["status"] == "unknown"


def test_compare_holders_flags_jupiter_only_when_scan_complete():
    helius = holders(("a", 0.5, 500), ("b", 0.5, 500))
    jup = [{"owner": "a", "amount": 500}, {"owner": "ghost", "amount": 400}]
    full = cc.compare_holders(helius, jup, top_n=2, helius_complete=True)
    assert full["jupiter_top_unknown_to_helius"] == ["ghost"]
    assert cc.compare_holders(helius, jup, top_n=2, helius_complete=False)["jupiter_top_unknown_to_helius"] == []


def test_compare_scalars_agreements_and_non_conclusive_holder_count():
    token = {"audit": {"mintAuthorityDisabled": True, "freezeAuthorityDisabled": True, "topHoldersPercentage": 17.0}, "totalSupply": 1000.0, "holderCount": 500}
    mint = {"mint_authority": "SomeAuthority", "freeze_authority": None}
    checks = {c["check"]: c for c in cc.compare_scalars(jupiter_token=token, mint=mint, supply_ui=1000.0, helius_total_owners=300, helius_complete=False, conc={"top10_all": 0.2})}
    assert checks["mint_authority_disabled"]["agree"] is False  # on-chain authority still set
    assert checks["freeze_authority_disabled"]["agree"] is True
    assert checks["total_supply"]["agree"] is True
    assert checks["holder_count"]["agree"] is None  # incomplete scan => not conclusive
    assert checks["top_holders_percentage"]["agree"] is None  # definition undocumented
    complete = {c["check"]: c for c in cc.compare_scalars(jupiter_token=token, mint=mint, supply_ui=1000.0, helius_total_owners=300, helius_complete=True, conc=None)}
    assert complete["holder_count"]["agree"] is False


def test_service_funder_rules():
    assert cc.is_service_funder({"funder": "f", "name": "Coinbase", "type": None, "amount": 50})
    assert cc.is_service_funder({"funder": "f", "name": None, "type": "Exchange", "amount": 50})
    assert cc.is_service_funder({"funder": "f", "name": None, "type": None, "amount": 0.00203928})
    assert not cc.is_service_funder({"funder": "f", "name": None, "type": None, "amount": 5.0})
    assert not cc.is_service_funder(None)


def test_compare_funding_separates_expected_from_substantive_disagreement():
    helius = {
        "same": {"funder": "X", "name": None, "type": None, "amount": 5.0},
        "rent_first": {"funder": "FOMO", "name": "FOMO Co-signer", "type": "Authority", "amount": 0.00203928},
        "diff": {"funder": "H", "name": None, "type": None, "amount": 5.8},
        "no_jup": {"funder": "Q", "name": None, "type": None, "amount": 1.0},
    }
    jup = [
        {"owner": "same", "funder": "X", "funding_amount": 5.0},
        {"owner": "rent_first", "funder": "REAL", "funding_amount": 95.0},
        {"owner": "diff", "funder": "J", "funding_amount": 5.9},
    ]
    out = cc.compare_funding(helius, jup)
    assert (out["compared"], out["agree"], out["helius_first_funding_is_service_level"], out["different_substantive_funders"]) == (3, 1, 1, 1)
    assert out["disagreements"][0]["wallet"] == "diff"


def test_clusters_link_across_providers_and_ignore_service_funders():
    rows = [row("w1", 0.10), row("w2", 0.05), row("w3", 0.04), row("w4", 0.03), row("w5", 0.02)]
    kinds = {r["owner"]: "wallet" for r in rows}
    funding = {
        "w1": {"funder": "FOMO", "name": "FOMO Co-signer", "type": "Authority", "amount": 0.00203928},  # rent top-up first
        "w2": {"funder": "X", "name": None, "type": None, "amount": 4.0},
        "w3": {"funder": "Y", "name": None, "type": None, "amount": 4.0},
        "w4": {"funder": "FOMO", "name": "FOMO Co-signer", "type": "Authority", "amount": 0.00203928},
        "w5": None,
    }
    jup = [{"owner": "w1", "funder": "X", "funding_amount": 4.0}, {"owner": "w4", "funder": "Z", "funding_amount": 3.0}]
    out = cc.clusters(rows, funding, jup, kinds)
    assert len(out["clusters"]) == 1
    cluster = out["clusters"][0]
    assert sorted(cluster["wallets"]) == ["w1", "w2"] and cluster["supply_share"] == 0.15
    assert cluster["shared_funders"] == {"X": ["helius", "jupiter"]}  # w1 via Jupiter, w2 via Helius
    assert out["service_funder_wallets"]["FOMO"] == 2  # a shared service funder never clusters w1 with w4


def test_clusters_skip_non_wallet_kinds():
    rows = [row("v1", 0.1), row("v2", 0.1)]
    kinds = {"v1": "controlled_vault", "v2": "controlled_vault"}
    funding = {"v1": {"funder": "X", "name": None, "type": None, "amount": 9.0}, "v2": {"funder": "X", "name": None, "type": None, "amount": 9.0}}
    assert cc.clusters(rows, funding, [], kinds)["clusters"] == []


def test_freshness_classes():
    launch = 10_000_000
    rows = [row("after", 0.1), row("recent", 0.1), row("old", 0.1), row("none", 0.1)]
    first = {"after": launch + 5, "recent": launch - 3 * 86400, "old": launch - 400 * 86400, "none": None}
    out = cc.freshness(rows, first, launch)
    assert out["counts"] == {"born_after_launch": 1, "fresh_pre_launch": 1, "established": 1, "unknown": 1}
    assert out["fresh_supply_share"] == 0.2
    assert cc.freshness(rows, first, None)["status"] == "unknown"


def test_signal_boundaries_and_unknown_is_not_zero():
    warn, fail = cc.THRESHOLDS["top1_ex_infra"]
    assert cc.signal("top1_ex_infra", warn - 0.001, "")["level"] == "ok"
    assert cc.signal("top1_ex_infra", warn, "")["level"] == "warn"
    assert cc.signal("top1_ex_infra", fail, "")["level"] == "fail"
    assert cc.signal("top1_ex_infra", None, "")["level"] == "unknown"


def sig(level, name="n"):
    return {"name": name, "level": level}


def core(level="ok"):
    return [sig(level, n) for n in sorted(cc.CORE_SIGNALS)]


def test_overall_levels_and_quality():
    ok_agreement = {"status": "strong"}
    assert cc.overall(core(), ok_agreement, [])["holder_risk"] == "limited"  # nothing alarmed, but no coverage/cohort evidence: never "low"
    assert cc.overall(core() + [sig("warn")], ok_agreement, [])["holder_risk"] == "elevated"
    assert cc.overall(core() + [sig("fail"), sig("unknown")], ok_agreement, [])["holder_risk"] == "high"
    assert cc.overall(core("unknown"), ok_agreement, [])["holder_risk"] == "unknown"
    assert cc.overall(core(), ok_agreement, [{"check": "mint_authority_disabled", "agree": False}])["data_quality"] == "conflicting"
    assert cc.overall(core(), {"status": "unknown"}, [])["data_quality"] == "limited"


def test_a_single_unknown_core_signal_blocks_low():
    signals = [sig("ok", n) for n in sorted(cc.CORE_SIGNALS)]
    signals[0] = sig("unknown", sorted(cc.CORE_SIGNALS)[0])
    out = cc.overall(signals, {"status": "strong"}, [])
    assert out["holder_risk"] == "unknown" and out["core_unknown_signals"] == [sorted(cc.CORE_SIGNALS)[0]]


def test_external_provider_status_feeds_data_quality():
    base = (core(), {"status": "strong"}, [])
    assert cc.overall(*base, {"gmgn": {"status": "poor"}})["data_quality"] == "conflicting"
    assert cc.overall(*base, {"gmgn": {"status": "partial"}})["data_quality"] == "limited"
    assert cc.overall(*base, {"gmgn": {"status": "strong"}})["data_quality"] == "ok"


def test_mint_and_freeze_authority_are_signals():
    def by_name(mint_info):
        return {s["name"]: s for s in cc.build_signals(conc=None, cluster_info=None, fresh=None, jupiter_token=None, tagged_bundler_share=None, mint_info=mint_info)}

    live = by_name({"mint_authority": "SomeKey", "freeze_authority": "OtherKey"})
    assert live["mint_authority_active"]["level"] == "fail" and live["freeze_authority_active"]["level"] == "warn"
    clean = by_name({"mint_authority": None, "freeze_authority": None})
    assert clean["mint_authority_active"]["level"] == "ok" and clean["mint_authority_active"]["value"] == "disabled"
    assert by_name(None)["mint_authority_active"]["level"] == "unknown"


def test_wallet_signals_unknown_when_coverage_is_low_or_absent():
    no_funding = {"clusters": [], "coverage": 0.0, "wallets_with_funding_data": 0, "wallets_total": 10}
    some = {"clusters": [], "coverage": 0.6, "wallets_with_funding_data": 6, "wallets_total": 10}
    mk = lambda c, f: {s["name"]: s for s in cc.build_signals(conc=None, cluster_info=c, fresh=f, jupiter_token=None, tagged_bundler_share=None)}  # noqa: E731
    assert mk(no_funding, None)["largest_cluster"]["level"] == "unknown"
    assert mk(some, None)["largest_cluster"]["level"] == "ok" and "6/10" in mk(some, None)["largest_cluster"]["basis"]
    assert mk(None, {"status": "partial", "coverage": 0.2, "fresh_supply_share": 0.0})["fresh_wallet_share"]["level"] == "unknown"
    assert mk(None, {"status": "partial", "coverage": 0.8, "fresh_supply_share": 0.4})["fresh_wallet_share"]["level"] == "fail"


def test_freshness_reports_coverage_and_never_zero_when_all_unknown():
    rows = [row("a", 0.1), row("b", 0.1)]
    all_unknown = cc.freshness(rows, {"a": None, "b": None}, 1_000_000)
    assert all_unknown["status"] == "unknown"
    partial = cc.freshness(rows, {"a": 2_000_000, "b": None}, 1_000_000)
    assert partial["status"] == "partial" and partial["coverage"] == 0.5 and partial["fresh_supply_share"] == 0.1


def test_clusters_report_funding_coverage():
    rows = [row("w1", 0.1), row("w2", 0.1)]
    kinds = {"w1": "wallet", "w2": "wallet"}
    out = cc.clusters(rows, {"w1": None, "w2": None}, [], kinds)
    assert out["coverage"] == 0.0 and out["wallets_with_funding_data"] == 0 and out["clusters"] == []


def test_classify_treasury_with_pool_word_and_labelled_wallet():
    assert classify(PDA, identity={"name": "Orca Foundation Treasury", "tags": []}) == "controlled_vault"
    assert classify(PDA, identity={"name": "Phoenix DAO multisig", "tags": []}) == "controlled_vault"
    assert classify(WALLET, identity={"name": "Pool party whale", "tags": []}) == "wallet"  # a keypair is never a pool


def test_jupiter_funder_that_helius_labels_a_service_is_not_an_insider_cluster():
    rows = [row("w1", 0.1), row("w2", 0.1), row("w3", 0.1)]
    kinds = {r["owner"]: "wallet" for r in rows}
    cex = {"funder": "CEXHOT", "name": "Binance Hot", "type": "Exchange", "amount": 30.0}
    funding = {"w1": cex, "w2": None, "w3": None}
    jup = [{"owner": "w2", "funder": "CEXHOT", "funding_amount": 12.0}, {"owner": "w3", "funder": "CEXHOT", "funding_amount": 9.0}]
    out = cc.clusters(rows, funding, jup, kinds)
    assert out["clusters"] == [] and out["service_funder_wallets"]["CEXHOT"] == 3


def test_compare_holders_poor_when_most_balances_disagree():
    helius = holders(("a", 0.4, 400), ("b", 0.3, 300), ("c", 0.2, 200), ("d", 0.1, 100))
    jup = [{"owner": o, "amount": a * 2} for o, _, a in [("a", 0.4, 400), ("b", 0.3, 300), ("c", 0.2, 200), ("d", 0.1, 100)]]
    assert cc.compare_holders(helius, jup, top_n=4)["status"] == "poor"
    ext = [{"owner": "a", "share": 0.1}, {"owner": "b", "share": 0.1}, {"owner": "c", "share": 0.1}, {"owner": "d", "share": 0.1}]
    assert cc.compare_external(helius, ext, top_n=4)["status"] == "poor"


def test_concentration_top10_uses_ten_non_infra_holders_when_infra_is_in_the_window():
    rows = [row(f"infra{i}", 0.05) for i in range(5)] + [row(f"w{i}", 0.02) for i in range(10)]
    kinds = {r["owner"]: ("liquidity_pool" if r["owner"].startswith("infra") else "wallet") for r in rows}
    out = cc.concentration(rows, kinds, 1000)
    assert out["top10_ex_infra"] == 0.2 and out["non_infra_rows"] == 10 and out["top20_limited_by_rows"] is True


def test_build_signals_uses_unknown_when_evidence_missing():
    signals = {s["name"]: s for s in cc.build_signals(conc=None, cluster_info=None, fresh=None, jupiter_token=None, tagged_bundler_share=None)}
    assert all(s["level"] == "unknown" and s["value"] is None for s in signals.values())


def test_external_rows_and_comparison():
    artifact = {"providers": {"gmgn": {"holders": [{"address": "a", "share_total_supply": 0.4}, {"address": "b", "share": 0.2}]}, "bubblemaps": {"nodes": {"top_holders": [{"address": "a", "share": 0.4}, {"address": "b", "share": 0.3}]}}}}
    ext = cc.external_rows(artifact)
    assert set(ext) == {"gmgn", "bubblemaps"} and ext["gmgn"][1]["share"] == 0.2
    helius = [row("a", 0.4), row("b", 0.2)]
    assert cc.compare_external(helius, ext["gmgn"], top_n=2)["status"] == "strong"
    bad = cc.compare_external(helius, ext["bubblemaps"], top_n=2)
    assert len(bad["share_mismatches"]) == 1 and bad["share_mismatches"][0]["owner"] == "b"
    assert cc.compare_external([], ext["gmgn"])["status"] == "unknown"
    assert cc.external_rows({"nothing": 1}) == {} and cc.external_rows(None) == {}
