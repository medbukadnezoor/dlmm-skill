"""HS-GRAPH-T1: the shared HeliusClient allows getTransfersByAddress (the transfer-graph lane reuses the client instead of
copying the transport), and takes an optional pace for that lane; the analysis engine's own pace is unchanged."""

import json

import pytest

import helius_forensics as hf
from ha import helius as ha_helius
from ha.helius import ALLOWED_METHODS, ANALYSIS_RATE_CAP_PER_S, HeliusClient
from ha.transport import TransportError

from test_foundation import FakeOpener, FakeResponse

KEY = "super-secret-helius-key"
WALLET = "86xCnPeV69n6t3DnyGvkKobf9FdN2H9oiVDdaMpo2MMY"


def rpc_ok(result):
    return FakeResponse(json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode())


def test_get_transfers_by_address_is_allowlisted_and_sent_as_documented():
    assert "getTransfersByAddress" in ALLOWED_METHODS
    rows = [{"signature": "x", "type": "transfer", "amount": "2500000", "decimals": 6}]
    opener = FakeOpener(rpc_ok({"data": rows, "paginationToken": None}))
    client = HeliusClient(KEY, opener=opener)
    params = [WALLET, {"mint": "So11111111111111111111111111111111111111111", "limit": 100, "sortOrder": "asc"}]
    assert client.rpc("getTransfersByAddress", params) == {"data": rows, "paginationToken": None}
    request = opener.requests[0]
    assert request.full_url == "https://mainnet.helius-rpc.com/"
    assert json.loads(request.data) == {"jsonrpc": "2.0", "id": 1, "method": "getTransfersByAddress", "params": params}
    assert request.get_header("X-api-key") == KEY and KEY not in request.full_url
    assert client.calls == {"getTransfersByAddress": 1}


def test_the_allowlist_grew_by_exactly_this_one_read_only_method():
    assert ALLOWED_METHODS == {"getTokenSupply", "getTokenLargestAccounts", "getMultipleAccounts", "getAccountInfo", "getTokenAccounts",
                               "getTransactionsForAddress", "getTransfersByAddress"}
    client = HeliusClient(KEY, opener=FakeOpener())
    for method in ("sendTransaction", "requestAirdrop", "getProgramAccounts", "getTransfersByAddresses"):
        with pytest.raises(TransportError):
            client.rpc(method, [])
    assert client.total_calls == 0


def test_the_pace_stays_two_per_second_unless_the_caller_passes_its_own():
    assert ANALYSIS_RATE_CAP_PER_S == 2 and ha_helius.COMBINED_RATE_CAP_PER_S == 8
    default = HeliusClient(KEY)
    lane = HeliusClient(KEY, rate_cap_per_s=6)
    assert isinstance(default.gate, hf.RateGate) and isinstance(lane.gate, hf.RateGate)
    assert default.gate._per_s == 2
    assert lane.gate._per_s == 6
