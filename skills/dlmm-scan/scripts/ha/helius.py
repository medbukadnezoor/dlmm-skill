"""Helius client (paid key) for on-chain ground truth.

Auth is sent as the x-api-key header so the key never appears in a URL, a
log line, or an exception. Only read-only methods are allowlisted. Every call is
counted against a per-run budget because Helius credits are metered and the
per-method credit price depends on the account plan (not verified here).

HS-POOL-T1: the wallet checks run in a bounded pool (ha/analysis.py), so the call budget is checked and spent under
one lock, and every request this client starts passes one shared pace (the forensics engine's RateGate, reused).
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable
from urllib.parse import quote

from helius_forensics import KEY_RE, RateGate

from .transport import TransportError, request_json

# Shared pace of this engine (HS-POOL-T1). Every Helius request the analysis engine starts, every attempt and retry
# included, from every worker thread, waits for one RateGate: at most ANALYSIS_RATE_CAP_PER_S starts in any 1 s window,
# and an HTTP 429 pauses all of them. Reason for 2/s: the HELIUS_API_KEY is the same key, and the same credit pool,
# as the stop-loss bots; on the Developer plan the DAS & Enhanced / Wallet API group allows 10 requests/s (provider-docs
# cache current/helius.md, "Rate Limits"); and the forensics collector runs at the same time in wave 1 at up to
# helius_forensics.REQUEST_RATE_CAP_PER_S (6/s). Together the two engines stay within COMBINED_RATE_CAP_PER_S (6 + 2),
# which leaves 2/s of the 10/s for the bots and anything else on the key (tests/analysis/test_pool.py pins the sum).
# Every call of this engine is paced, not only the Wallet/DAS ones, so the bound holds however Helius groups a method.
ANALYSIS_RATE_CAP_PER_S = 2
COMBINED_RATE_CAP_PER_S = 8

RPC_HOST = "mainnet.helius-rpc.com"
API_HOST = "api.helius.xyz"
RPC_URL = f"https://{RPC_HOST}/"
ALLOWED_METHODS = {
    "getTokenSupply",
    "getTokenLargestAccounts",
    "getMultipleAccounts",
    "getAccountInfo",
    "getTokenAccounts",
    "getTransactionsForAddress",
    "getTransfersByAddress",  # HS-GRAPH-T1: the transfer-graph lane (10 credits per call, provider-docs current/helius.md)
}
SYSTEM_PROGRAM = "11111111111111111111111111111111"
MAX_ACCOUNTS_PER_CALL = 100


class BudgetExhausted(Exception):
    pass


class HeliusClient:
    def __init__(
        self,
        key: str,
        *,
        max_calls: int = 150,
        opener: Any | None = None,
        timeout: int = 30,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        rate_cap_per_s: int = ANALYSIS_RATE_CAP_PER_S,
    ) -> None:
        """`rate_cap_per_s` (HS-GRAPH-T1): the shared pace of this client. The analysis engine keeps the default; the
        transfer-graph lane passes its own cap, because it runs alone on the key in the follow-up wave, after both engines
        have finished."""
        if not key:
            raise TransportError("helius_key_missing")
        if not KEY_RE.fullmatch(key):  # one token of allowed characters (the forensics rule); urllib would echo a bad header value
            raise TransportError("helius_key_unexpected_format")
        self._key = key
        self._opener = opener
        self._timeout = timeout
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self.gate = RateGate(rate_cap_per_s, clock, sleep)
        self.max_calls = max_calls
        self.calls: dict[str, int] = {}

    @property
    def total_calls(self) -> int:
        with self._lock:
            return sum(self.calls.values())

    def _spend(self, label: str) -> None:
        """Check and count one call before it is sent, under one lock, so parallel workers can never push the total past
        max_calls. A refused call is never sent."""
        with self._lock:
            if sum(self.calls.values()) >= self.max_calls:
                raise BudgetExhausted(f"helius call budget of {self.max_calls} reached")
            self.calls[label] = self.calls.get(label, 0) + 1

    def _headers(self) -> dict[str, str]:
        return {"x-api-key": self._key}

    def rpc(self, method: str, params: Any) -> Any:
        if method not in ALLOWED_METHODS:
            raise TransportError("method_not_allowlisted")
        self._spend(method)
        payload = request_json(
            "POST",
            RPC_URL,
            allowed_hosts={RPC_HOST},
            headers=self._headers(),
            body={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            opener=self._opener,
            timeout=self._timeout,
            secrets=(self._key,),
            retries=1,
            sleep=self._sleep,
            clock=self._clock,
            gate=self.gate,
        )
        if not isinstance(payload, dict) or payload.get("error") is not None or "result" not in payload:
            raise TransportError("rpc_error")
        return payload["result"]

    def _api_get(self, label: str, path: str, *, not_found_ok: bool = False) -> Any:
        self._spend(label)
        try:
            return request_json(
                "GET",
                f"https://{API_HOST}{path}",
                allowed_hosts={API_HOST},
                headers=self._headers(),
                opener=self._opener,
                timeout=self._timeout,
                secrets=(self._key,),
                sleep=self._sleep,
                clock=self._clock,
                gate=self.gate,
            )
        except TransportError as exc:
            if not_found_ok and exc.reason == "not_found":
                return None
            raise

    # ---- token level -------------------------------------------------
    def token_supply(self, mint: str) -> dict[str, Any]:
        value = (self.rpc("getTokenSupply", [mint]) or {}).get("value")
        amount = value.get("amount") if isinstance(value, dict) else None
        if not isinstance(amount, str) or not amount.isdigit() or int(amount) == 0 or not isinstance(value.get("decimals"), int):
            raise TransportError("supply_missing_or_zero")  # never fabricate a zero supply
        return {"raw": int(amount), "decimals": value["decimals"]}

    def mint_info(self, mint: str) -> dict[str, Any]:
        value = (self.rpc("getAccountInfo", [mint, {"encoding": "jsonParsed"}]) or {}).get("value")
        data = value.get("data") if isinstance(value, dict) and isinstance(value.get("data"), dict) else {}
        parsed = data.get("parsed") if isinstance(data.get("parsed"), dict) else {}
        if parsed.get("type") != "mint":
            raise TransportError("not_a_mint")  # a wallet or missing account must not read as "authorities disabled"
        info = parsed.get("info") or {}
        extensions = info.get("extensions") if isinstance(info.get("extensions"), list) else []
        return {
            "token_program": value.get("owner"),
            "mint_authority": info.get("mintAuthority"),
            "freeze_authority": info.get("freezeAuthority"),
            "extensions": sorted({str(e.get("extension")) for e in extensions if isinstance(e, dict) and e.get("extension")}),
        }

    def largest_accounts(self, mint: str) -> list[dict[str, Any]]:
        rows = self.rpc("getTokenLargestAccounts", [mint]).get("value") or []
        return [
            {"token_account": r["address"], "amount_raw": int(r["amount"])}
            for r in rows
            if isinstance(r, dict) and r.get("address") and str(r.get("amount", "")).isdigit()
        ]

    def token_account_owners(self, token_accounts: list[str]) -> dict[str, str]:
        owners: dict[str, str] = {}
        for start in range(0, len(token_accounts), MAX_ACCOUNTS_PER_CALL):
            chunk = token_accounts[start : start + MAX_ACCOUNTS_PER_CALL]
            values = self.rpc("getMultipleAccounts", [chunk, {"encoding": "jsonParsed"}]).get("value") or []
            for address, value in zip(chunk, values):
                data = (value or {}).get("data")
                parsed = data.get("parsed") if isinstance(data, dict) else None
                owner = ((parsed or {}).get("info") or {}).get("owner")
                if owner:
                    owners[address] = owner
        return owners

    def owner_kinds(self, owners: list[str]) -> dict[str, str]:
        """'wallet' = system-owned or not on chain; otherwise 'program:<id>' (PDA/vault)."""
        kinds: dict[str, str] = {}
        for start in range(0, len(owners), MAX_ACCOUNTS_PER_CALL):
            chunk = owners[start : start + MAX_ACCOUNTS_PER_CALL]
            values = self.rpc("getMultipleAccounts", [chunk, {"encoding": "base64", "dataSlice": {"offset": 0, "length": 0}}]).get("value") or []
            for address, value in zip(chunk, values):
                program = (value or {}).get("owner")
                kinds[address] = "wallet" if value is None or program == SYSTEM_PROGRAM else f"program:{program}"
        return kinds

    def all_holders(self, mint: str, *, max_pages: int = 10, page_limit: int = 1000) -> dict[str, Any]:
        """Page DAS getTokenAccounts and aggregate balances by owner wallet."""
        owners: dict[str, dict[str, int]] = {}
        cursor: str | None = None
        pages = 0
        complete = False
        malformed = 0
        while pages < max_pages:
            params: dict[str, Any] = {"mint": mint, "limit": page_limit, "options": {"showZeroBalance": False}}
            if cursor:
                params["cursor"] = cursor
            result = self.rpc("getTokenAccounts", params)
            pages += 1
            accounts = result.get("token_accounts") if isinstance(result, dict) else None
            if not isinstance(accounts, list):
                raise TransportError("unexpected_shape")
            for account in accounts:
                owner, amount = account.get("owner"), account.get("amount")
                if not owner or not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
                    malformed += 1
                    continue
                if amount == 0:
                    continue
                slot = owners.setdefault(owner, {"amount_raw": 0, "accounts": 0})
                slot["amount_raw"] += amount
                slot["accounts"] += 1
            cursor = result.get("cursor")
            if not cursor:
                complete = True
                break
            if not accounts:
                break  # empty page with a cursor still set: truncated, not finished
        # complete only when the scan ended by exhausting the cursor, saw holders, and skipped nothing
        complete = complete and bool(owners) and malformed == 0
        return {"owners": owners, "complete": complete, "pages": pages, "malformed_rows": malformed}

    # ---- wallet level ------------------------------------------------
    def funded_by(self, wallet: str) -> dict[str, Any] | None:
        data = self._api_get("wallet_funded_by", f"/v1/wallet/{quote(wallet, safe='')}/funded-by", not_found_ok=True)
        if not isinstance(data, dict) or not data.get("funder"):
            return None
        return {
            "funder": data.get("funder"),
            "name": data.get("funderName"),
            "type": data.get("funderType"),
            "amount": data.get("amount"),
            "timestamp": data.get("timestamp"),
        }

    def first_activity(self, wallet: str) -> int | None:
        result = self.rpc("getTransactionsForAddress", [wallet, {"limit": 1, "sortOrder": "asc"}])
        rows = result.get("data") if isinstance(result, dict) else None
        if rows and isinstance(rows[0], dict) and isinstance(rows[0].get("blockTime"), int):
            return rows[0]["blockTime"]
        return None

    def identities(self, wallets: list[str]) -> dict[str, dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}
        for start in range(0, len(wallets), MAX_ACCOUNTS_PER_CALL):
            chunk = wallets[start : start + MAX_ACCOUNTS_PER_CALL]
            self._spend("wallet_batch_identity")
            data = request_json(
                "POST",
                f"https://{API_HOST}/v1/wallet/batch-identity",
                allowed_hosts={API_HOST},
                headers=self._headers(),
                body={"addresses": chunk},
                opener=self._opener,
                timeout=self._timeout,
                secrets=(self._key,),
                sleep=self._sleep,
                clock=self._clock,
                gate=self.gate,
            )
            for row in data if isinstance(data, list) else []:
                if isinstance(row, dict) and row.get("address"):
                    found[row["address"]] = {
                        "name": row.get("name"),
                        "category": row.get("category"),
                        "type": row.get("type"),
                        "tags": [str(t) for t in row.get("tags") or []],
                    }
        return found
