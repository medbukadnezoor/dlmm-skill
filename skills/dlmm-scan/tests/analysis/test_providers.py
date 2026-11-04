import json

import pytest

from ha.helius import BudgetExhausted, HeliusClient
from ha.jupiter import JupiterClient, normalize_holder
from ha.transport import TransportError

from test_foundation import FakeOpener, FakeResponse, http_error

MINT = "Hg5Ja55T5wESq4vyFoiVCMeHXtGyVA69X2UHq8hgpump"
KEY = "super-secret-helius-key"


def rpc_ok(result):
    return FakeResponse(json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode())


def test_helius_sends_key_as_header_never_in_url():
    opener = FakeOpener(rpc_ok({"value": {"amount": "1000000", "decimals": 6}}))
    client = HeliusClient(KEY, opener=opener)
    assert client.token_supply(MINT) == {"raw": 1000000, "decimals": 6}
    request = opener.requests[0]
    assert KEY not in request.full_url
    assert request.get_header("X-api-key") == KEY


def test_helius_blocks_unlisted_rpc_methods():
    client = HeliusClient(KEY, opener=FakeOpener())
    for method in ("sendTransaction", "requestAirdrop", "getProgramAccounts"):
        with pytest.raises(TransportError):
            client.rpc(method, [])
    assert client.total_calls == 0


def test_helius_budget_is_enforced():
    opener = FakeOpener(rpc_ok({"value": {"amount": "1", "decimals": 0}}), rpc_ok({"value": {"amount": "1", "decimals": 0}}))
    client = HeliusClient(KEY, max_calls=2, opener=opener)
    client.token_supply(MINT)
    client.token_supply(MINT)
    with pytest.raises(BudgetExhausted):
        client.token_supply(MINT)
    assert client.calls == {"getTokenSupply": 2}


def test_helius_rpc_error_payload_is_an_error():
    opener = FakeOpener(FakeResponse(b'{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x"}}'))
    with pytest.raises(TransportError) as exc:
        HeliusClient(KEY, opener=opener).token_supply(MINT)
    assert exc.value.reason == "rpc_error"


def test_helius_all_holders_pages_and_aggregates_by_owner():
    page1 = {"token_accounts": [{"owner": "A", "amount": 5}, {"owner": "B", "amount": 3}, {"owner": "A", "amount": 2}, {"owner": "Z", "amount": 0}], "cursor": "c1"}
    page2 = {"token_accounts": [{"owner": "B", "amount": 4}], "cursor": None}
    client = HeliusClient(KEY, opener=FakeOpener(rpc_ok(page1), rpc_ok(page2)))
    scan = client.all_holders(MINT, max_pages=5)
    assert scan["complete"] is True and scan["pages"] == 2
    assert scan["owners"] == {"A": {"amount_raw": 7, "accounts": 2}, "B": {"amount_raw": 7, "accounts": 2}}


def test_helius_all_holders_marks_incomplete_when_page_cap_hit():
    page = {"token_accounts": [{"owner": "A", "amount": 1}], "cursor": "more"}
    client = HeliusClient(KEY, opener=FakeOpener(rpc_ok(page), rpc_ok(page)))
    scan = client.all_holders(MINT, max_pages=2)
    assert scan["complete"] is False and scan["pages"] == 2


def test_helius_owner_kinds_and_authorities():
    client = HeliusClient(KEY, opener=FakeOpener(
        rpc_ok({"value": [None, {"owner": "11111111111111111111111111111111"}, {"owner": "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo"}]}),
        rpc_ok({"value": {"owner": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "data": {"parsed": {"type": "mint", "info": {"mintAuthority": None, "freezeAuthority": "F", "extensions": [{"extension": "metadataPointer"}]}}}}}),
    ))
    kinds = client.owner_kinds(["a", "b", "c"])
    assert kinds == {"a": "wallet", "b": "wallet", "c": "program:LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo"}
    info = client.mint_info(MINT)
    assert info["mint_authority"] is None and info["freeze_authority"] == "F" and info["extensions"] == ["metadataPointer"]


def test_helius_funded_by_not_found_is_none_not_error():
    client = HeliusClient(KEY, opener=FakeOpener(http_error(404)))
    assert client.funded_by("W") is None


def test_helius_funded_by_parses_and_auth_is_header():
    body = {"funder": "F", "funderName": "FOMO Co-signer", "funderType": "Authority", "amount": 0.002, "timestamp": 1}
    opener = FakeOpener(FakeResponse(json.dumps(body).encode()))
    got = HeliusClient(KEY, opener=opener).funded_by("W")
    assert got == {"funder": "F", "name": "FOMO Co-signer", "type": "Authority", "amount": 0.002, "timestamp": 1}
    assert KEY not in opener.requests[0].full_url


def test_helius_first_activity_and_identities():
    client = HeliusClient(KEY, opener=FakeOpener(
        rpc_ok({"data": [{"blockTime": 1786387774}], "paginationToken": "x"}),
        FakeResponse(json.dumps([{"address": "W", "name": "MEXC Exchange", "category": "Exchange", "type": "wallet", "tags": ["Exchange"]}]).encode()),
    ))
    assert client.first_activity("W") == 1786387774
    assert client.identities(["W", "Q"])["W"]["category"] == "Exchange"


def test_jupiter_token_holders_pools():
    token = [{"id": "other"}, {"id": MINT, "symbol": "baton", "holderCount": 5}]
    holders = {"count": 5, "holders": [{"address": "A", "amount": 10.5, "solBalanceDisplay": 1.0, "holderTags": ["bundler"], "walletCategories": ["Influencer"], "usernames": {"pump": {"username": "x"}}, "addressInfo": {"fundingAddress": "F", "fundingAmount": 3.0, "fundingBlockTime": "t"}}]}
    pools = {"pools": [{"id": "P", "dex": "Meteora", "type": "meteora-dlmm", "liquidity": 9, "volume24h": 2}]}
    opener = FakeOpener(*[FakeResponse(json.dumps(p).encode()) for p in (token, holders, pools)])
    client = JupiterClient(opener=opener)
    assert client.token(MINT)["symbol"] == "baton"
    got = client.holders(MINT)
    assert got["holders"][0]["tags"] == ["bundler", "influencer"] and got["holders"][0]["funder"] == "F"
    assert client.pools(MINT)[0]["id"] == "P"
    assert client.calls == 3


def test_jupiter_token_missing_and_bad_shape():
    client = JupiterClient(opener=FakeOpener(FakeResponse(b"[]"), FakeResponse(b'{"nope": 1}')))
    assert client.token(MINT) is None
    with pytest.raises(TransportError):
        client.holders(MINT)


def test_normalize_holder_tolerates_missing_fields():
    row = normalize_holder({"address": "A"})
    assert row["owner"] == "A" and row["amount"] is None and row["funder"] is None
    assert row["tags"] is None  # no tag field at all is unknown, distinct from an empty list
    assert normalize_holder({"address": "A", "holderTags": []})["tags"] == []


# ---- regressions from the independent review ---------------------------------
@pytest.mark.parametrize("payload", [{"value": {}}, {"value": None}, {"value": {"amount": "0", "decimals": 6}}, {"value": {"amount": "abc", "decimals": 6}}, {"value": {"amount": "5"}}])
def test_helius_supply_missing_or_zero_is_an_error_not_zero(payload):
    with pytest.raises(TransportError) as exc:
        HeliusClient(KEY, opener=FakeOpener(rpc_ok(payload))).token_supply(MINT)
    assert exc.value.reason == "supply_missing_or_zero"


@pytest.mark.parametrize("value", [None, {"owner": "11111111111111111111111111111111", "data": ["", "base64"]}, {"data": {"parsed": {"type": "account", "info": {}}}}])
def test_helius_mint_info_rejects_non_mints(value):
    with pytest.raises(TransportError) as exc:
        HeliusClient(KEY, opener=FakeOpener(rpc_ok({"value": value}))).mint_info(MINT)
    assert exc.value.reason == "not_a_mint"


def test_helius_scan_not_complete_when_truncated_empty_or_malformed():
    truncated = HeliusClient(KEY, opener=FakeOpener(rpc_ok({"token_accounts": [{"owner": "A", "amount": 5}], "cursor": "c"}), rpc_ok({"token_accounts": [], "cursor": "c"})))
    assert truncated.all_holders(MINT, max_pages=5)["complete"] is False
    empty = HeliusClient(KEY, opener=FakeOpener(rpc_ok({"token_accounts": [], "cursor": None}))).all_holders(MINT)
    assert empty["complete"] is False and empty["owners"] == {}
    bad = HeliusClient(KEY, opener=FakeOpener(rpc_ok({"token_accounts": [{"owner": "A", "amount": 5}, {"owner": "B", "amount": "x"}, {"amount": 3}], "cursor": None}))).all_holders(MINT)
    assert bad["complete"] is False and bad["malformed_rows"] == 2
    with pytest.raises(TransportError):
        HeliusClient(KEY, opener=FakeOpener(rpc_ok({"nope": 1}))).all_holders(MINT)
