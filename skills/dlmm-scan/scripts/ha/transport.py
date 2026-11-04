"""Allowlisted HTTPS JSON transport.

Every request is pinned to an explicit host allowlist, never follows redirects,
caps the response size, retries only transient failures, and redacts secrets
from every error it raises.
"""

from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.request
from collections.abc import Collection
from typing import Any
from urllib.parse import urlparse

MAX_BYTES = 8 * 1024 * 1024
RETRY_STATUS = {429, 500, 502, 503, 504}


class TransportError(Exception):
    def __init__(self, reason: str, http_status: int | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def redact(text: Any, secrets: Collection[str]) -> str:
    out = str(text)
    for secret in secrets:
        if secret:
            out = out.replace(secret, "<redacted>")
    return out


def request_json(
    method: str,
    url: str,
    *,
    allowed_hosts: Collection[str],
    headers: dict[str, str] | None = None,
    body: Any = None,
    timeout: int = 30,
    max_bytes: int = MAX_BYTES,
    retries: int = 2,
    secrets: Collection[str] = (),
    opener: Any | None = None,
    sleep: Any = time.sleep,
    deadline_s: float = 90.0,
    clock: Any = time.monotonic,
    gate: Any = None,
) -> Any:
    """`gate` (optional, HS-POOL-T1): a pace shared by every thread of one engine (helius_forensics.RateGate). Every
    attempt, retries included, waits for `gate.wait_turn()`, and an HTTP 429 calls `gate.pause(...)` with the same backoff
    this thread waits before its retry, so no thread of that engine starts a request meanwhile. Without a gate nothing
    changes; with one the retry count and the backoff sleeps stay the same."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise TransportError("scheme_not_https")
    if parsed.hostname not in set(allowed_hosts) or parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise TransportError("host_not_allowlisted")
    data = None
    send_headers = {"Accept": "application/json", "User-Agent": "holder-analysis/1.0"}
    send_headers.update(headers or {})
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        send_headers["Content-Type"] = "application/json"
    used_opener = opener or urllib.request.build_opener(_NoRedirect)
    attempt = 0
    started = clock()
    while True:
        if clock() - started > deadline_s:
            raise TransportError("deadline_exceeded")
        if gate is not None:
            gate.wait_turn()
        request =urllib.request.Request(url, data=data, method=method, headers=send_headers)
        try:
            with used_opener.open(request, timeout=timeout) as response:
                status = int(getattr(response, "status", 200) or 200)
                if 300 <= status < 400:
                    raise TransportError("redirect_disallowed", http_status=status)
                raw = response.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise TransportError("response_too_large")
            try:
                return json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise TransportError("invalid_json") from exc
        except TransportError:
            raise
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            exc.close()
            if 300 <= status < 400:
                raise TransportError("redirect_disallowed", http_status=status) from None
            if status == 429 and gate is not None:
                gate.pause(0.5 * (2 ** (attempt + 1)))  # the backoff below; after the last attempt it still holds the others back
            if status in RETRY_STATUS and attempt < retries:
                attempt += 1
                sleep(0.5 * (2**attempt))
                continue
            raise TransportError(
                {401: "auth_failed", 403: "access_denied", 404: "not_found", 429: "rate_limited"}.get(status, "http_error"),
                http_status=status,
            ) from None
        except (TimeoutError, urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            if attempt < retries:
                attempt += 1
                sleep(0.5 * (2**attempt))
                continue
            reason = "timeout" if isinstance(exc, TimeoutError) else "network_error"
            raise TransportError(reason) from None
