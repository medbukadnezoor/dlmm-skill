"""Jupiter datapi client (free, no key, UNDOCUMENTED frontend API).

datapi.jup.ag is not in Jupiter's published docs (those cover api.jup.ag/tokens/v2
with an API key). Endpoints here were verified live on 2026-10-14 and can change
or be rate-limited without notice, so every caller must treat failure as
"unavailable", never as zero.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlencode

from .transport import TransportError, request_json

HOST = "datapi.jup.ag"
BASE = f"https://{HOST}/v1"


class JupiterClient:
    def __init__(self, *, opener: Any | None = None, timeout: int = 30) -> None:
        self._opener = opener
        self._timeout = timeout
        self.calls = 0

    def _get(self, path: str, query: dict[str, Any] | None = None) -> Any:
        url = BASE + path + (("?" + urlencode(query)) if query else "")
        self.calls += 1
        return request_json("GET", url, allowed_hosts={HOST}, opener=self._opener, timeout=self._timeout)

    def token(self, mint: str) -> dict[str, Any] | None:
        rows = self._get("/assets/search", {"query": mint})
        if not isinstance(rows, list):
            raise TransportError("unexpected_shape")
        for row in rows:
            if isinstance(row, dict) and row.get("id") == mint:
                return row
        return None

    def holders(self, mint: str, limit: int = 100) -> dict[str, Any]:
        payload = self._get(f"/holders/{quote(mint, safe='')}", {"limit": limit})
        rows = payload.get("holders") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            raise TransportError("unexpected_shape")
        return {"count": payload.get("count"), "holders": [normalize_holder(r) for r in rows if isinstance(r, dict)]}

    def pools(self, mint: str) -> list[dict[str, Any]]:
        payload = self._get("/pools", {"assetIds": mint})
        rows = payload.get("pools") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            raise TransportError("unexpected_shape")
        return [
            {
                "id": r.get("id"),
                "dex": r.get("dex"),
                "type": r.get("type"),
                "liquidity": r.get("liquidity"),
                "volume24h": r.get("volume24h"),
            }
            for r in rows
            if isinstance(r, dict)
        ]


def _tags(row: dict[str, Any]) -> list[str] | None:
    """Sorted lowercase tags, or None when the row carries no tag field at all.

    None (schema absent) must stay distinct from [] (present and empty) so a
    renamed field in this undocumented API reads as unknown, not "no bundlers".
    """
    tags: set[str] = set()
    present = False
    for field in ("holderTags", "walletCategories", "tags"):
        value = row.get(field)
        if isinstance(value, list):
            present = True
            tags.update(str(item).strip().lower() for item in value if isinstance(item, str) and item.strip())
    return sorted(tags) if present else None


def normalize_holder(row: dict[str, Any]) -> dict[str, Any]:
    info = row.get("addressInfo") if isinstance(row.get("addressInfo"), dict) else {}
    names = row.get("usernames") if isinstance(row.get("usernames"), dict) else {}
    handles = sorted(
        {str(v.get("username")) for v in names.values() if isinstance(v, dict) and v.get("username")}
    )
    amount = row.get("amount")
    return {
        "owner": row.get("address"),
        "amount": float(amount) if isinstance(amount, (int, float)) and not isinstance(amount, bool) else None,
        "sol_balance": row.get("solBalanceDisplay") if isinstance(row.get("solBalanceDisplay"), (int, float)) else None,
        "tags": _tags(row),
        "handles": handles,
        "funder": info.get("fundingAddress"),
        "funding_amount": info.get("fundingAmount") if isinstance(info.get("fundingAmount"), (int, float)) else None,
        "funded_at": info.get("fundingBlockTime"),
        "last_active": row.get("lastActiveTime"),
    }
