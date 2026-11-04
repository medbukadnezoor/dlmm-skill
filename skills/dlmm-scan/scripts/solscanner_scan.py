"""SolScanner public scan reader for dlmm-scan (one bounded, unauthenticated SSE observation).

SELF-CONTAINED COPY. This module is a deliberate duplicate of
skills/lp-research-companion/scripts/lp_research/solscanner.py (collect_solscanner and solscanner_finding, merged
and reviewed there), with its two helpers (the no-redirect handler and timestamp parsing) inlined so dlmm-scan
imports nothing from the sibling skill (an older, conflicting copy of that package can exist in a local checkout).
Only the User-Agent differs, plus a small command line at the end of this file (`main`: one call of collect_solscanner,
result saved as JSON) that the dlmm-scan `solscanner` collector runs. The two copies are kept in sync by tests/forensics/test_solscanner_report.py, which feeds both
parsers the same fixtures when the sibling skill is present in the checkout and compares their output (skipped when it
is not). Change both together.

Only normalized allowlisted facts leave this module. The public endpoint is
observed behavior without a cached API specification, so unknown shapes fail
closed and no response body or event is retained in an artifact.

Observed stream shapes (2026-10): a cached scan sends ``event: cache_hit``
(scannedAt, isStale, history) and then one ``event: complete`` whose JSON holds
``bundleGroups`` (groupId, riskScore, bundleType, confidence, wallets). The
older shape, a separate ``event: bundle_groups`` with key ``groups``, is still
accepted. Stale or expired scans keep their groups (status stays "unknown" with
the reason) so a caller can still use them as an alarm; ``scan_age_min`` reports
the age at fetch time.

CORROBORATION ONLY. SolScanner groups are broad: on real tokens a calm-looking
one (Space Inu, 41.6% group, risk 61) and a heavily flagged one (CAPE, 44%,
risk 96) both get large groups, and its risk score does not separate CAPE from
Altai the Tiger. ``solscanner_finding`` therefore never sets
largest_cluster_pct, cluster_sum_pct or bundle_pct: a SolScanner result can
raise an ``alarm_hint`` (status ok) but can never produce HIGH alone and never
counts as a calm / all-clear source. Finding contract (PR #105 schema)::

    {provider: "solscanner", status: ok|empty|unavailable, unit: "percent",
     data_age_min: float|None, alarm_hint: str|None, note: str}

    unusable result (no groups and a failure reason)  -> unavailable + reason
    zero groups from a usable scan                    -> empty
    groups, none meeting the hint rule                -> empty + note
    a group with risk >= MIN_RISK, confidence high and
    share >= MIN_SHARE_PCT                            -> ok + alarm_hint
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import queue
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect (the handler returns None, so urllib raises the 3xx as an HTTPError)."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def parse_update_time(value: Any) -> dt.datetime | None:
    number = _finite_number(value)
    if number is not None and number >= 0:
        try:
            return dt.datetime.fromtimestamp(number, tz=dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)

BASE_URL = "https://api.solscanner.app/contracts"
MAX_BYTES = 1024 * 1024
DEADLINE_SECONDS = 10.0
MAX_GROUPS = 64
MAX_OCCURRENCES = 1000

# PROVISIONAL constants: chosen from three observed tokens (CAPE, Space Inu,
# Altai the Tiger), not calibrated. Re-tune only with more labelled evidence.
SCAN_FRESH_SECONDS = 600  # a non-stale scan older than this is "expired_scan"
SOLSCANNER_HINT_MIN_RISK = 90  # group riskScore needed for an alarm_hint
SOLSCANNER_HINT_MIN_SHARE_PCT = 15.0  # group share of supply needed for an alarm_hint
SOLSCANNER_HINT_MAX_CHARS = 32  # downstream safe_label truncates labels to 32 chars

# Plain words only: downstream safe_label strips punctuation and cuts at 32 chars.
SOLSCANNER_DETAIL = "corroboration only not all clear"

_CONFIDENCE = frozenset({"low", "medium", "high"})
_LABEL = re.compile(r"[A-Za-z0-9_\-]{1,32}")
_BASE58 = frozenset("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")


class _ShapeError(Exception):
    pass


class _IdentityError(Exception):
    pass


def _stamp(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        if len(value) > 40:
            return None
        try:
            parsed_string = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed_string.tzinfo is None or parsed_string.utcoffset() != dt.timedelta(0):
            return None
        return value
    if isinstance(value, (int, float)) and value > 100_000_000_000:
        value /= 1000
    parsed = parse_update_time(value)
    if parsed is None:
        return None
    return parsed.isoformat().replace("+00:00", "Z")


def _empty(mint: str, fetched_at: str, reason: str) -> dict[str, Any]:
    return {
        "provider": "SolScanner", "chain": "sol", "mint": mint,
        "status": "unknown", "reason": reason, "fetched_at": fetched_at,
        "scanned_at": None, "is_stale": None, "scan_age_min": None, "scan_complete": None, "coverage": "unknown",
        "denominator": "total_supply", "groups": [],
    }


_IDENTITY_KEYS = ("contractAddress", "contract_address", "tokenAddress", "token_address", "mint")


def _identity(payload: dict[str, Any], mint: str) -> None:
    for key in _IDENTITY_KEYS:
        if key in payload and payload[key] != mint:
            raise _IdentityError


def _scan_facts(payload: dict[str, Any], mint: str, facts: dict[str, Any]) -> None:
    _identity(payload, mint)
    for key in ("scannedAt", "scanned_at"):
        if key in payload:
            stamp = _stamp(payload[key])
            if payload[key] is not None and stamp is None:
                raise _ShapeError
            if facts["scanned_at"] is not None and stamp != facts["scanned_at"]:
                raise _ShapeError
            facts["scanned_at"] = stamp
    for key in ("isStale", "is_stale"):
        if key in payload:
            value = payload[key]
            if value is not None and type(value) is not bool:
                raise _ShapeError
            if value is not None and facts["is_stale"] is not None and value != facts["is_stale"]:
                raise _ShapeError
            if value is not None:
                facts["is_stale"] = value


def _group_rows(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list) or len(rows) > MAX_GROUPS:
        raise _ShapeError
    normalized = []
    occurrences = 0
    for group in rows:
        if not isinstance(group, dict) or not isinstance(group.get("wallets"), list):
            raise _ShapeError
        wallets = group["wallets"]
        occurrences += len(wallets)
        if occurrences > MAX_OCCURRENCES:
            raise _ShapeError
        clean_wallets = []
        for row in wallets:
            if not isinstance(row, dict):
                raise _ShapeError
            address = row.get("address") or row.get("wallet")
            share = row.get("percentageOfSupply")
            if not isinstance(address, str) or not 32 <= len(address) <= 44 or any(c not in _BASE58 for c in address):
                raise _ShapeError
            if isinstance(share, bool) or not isinstance(share, (int, float)) or not math.isfinite(share) or not 0 <= share <= 100:
                raise _ShapeError
            clean_wallets.append({"address": address, "share_pct": float(share)})
        risk = group.get("riskScore")
        if risk is not None:
            if isinstance(risk, float) and risk.is_integer():
                risk = int(risk)
            if type(risk) is not int or not 0 <= risk <= 100:
                raise _ShapeError
        confidence = group.get("confidence")
        if confidence is not None and (not isinstance(confidence, str) or confidence not in _CONFIDENCE):
            raise _ShapeError
        bundle_type = group.get("bundleType")
        if bundle_type is not None:
            if not isinstance(bundle_type, str):
                raise _ShapeError
            bundle_type = bundle_type if _LABEL.fullmatch(bundle_type) else None
        normalized.append({"wallets": clean_wallets, "risk_score": risk,
                           "confidence": confidence, "bundle_type": bundle_type})
    return normalized


def _groups(payload: dict[str, Any], mint: str, key: str, *, require_identity: bool) -> list[dict[str, Any]]:
    _identity(payload, mint)
    if require_identity and not any(k in payload for k in _IDENTITY_KEYS):
        raise _IdentityError
    return _group_rows(payload.get(key))


def _response_socket(response: Any) -> Any | None:
    # urllib's HTTPSResponse socket; fakes need no socket and are checked after reads.
    fp = getattr(response, "fp", None)
    for candidate in (fp, getattr(fp, "fp", None)):
        sock = getattr(getattr(candidate, "raw", None), "_sock", None)
        if sock is not None:
            return sock
    return None


def _bounded_call(function: Any, timeout: float) -> Any:
    """Run a possibly blocking transport operation with a hard wall bound.

    urllib DNS/TLS and test transports can ignore socket timeouts. A daemon
    worker makes the bound apply equally to main and worker callers. The
    abandoned operation cannot perform a retry or publish any result.
    """
    if timeout <= 0:
        raise TimeoutError
    result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

    def invoke() -> None:
        try:
            result.put((True, function()))
        except BaseException as exc:  # propagate to the bounded caller
            result.put((False, exc))

    worker = threading.Thread(target=invoke, name="solscanner-transport", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise TimeoutError
    succeeded, value = result.get_nowait()
    if not succeeded:
        if isinstance(value, Exception):
            raise value
        raise OSError
    return value


class _BoundedResponse:
    def __init__(self, response: Any, remaining: Any) -> None:
        self._response = response
        self._remaining = remaining

    def __getattr__(self, name: str) -> Any:
        return getattr(self._response, name)

    def __enter__(self) -> "_BoundedResponse":
        self._response = _bounded_call(self._response.__enter__, self._remaining())
        return self

    def __exit__(self, *args: Any) -> bool:
        remaining = self._remaining()
        if remaining <= 0:
            return False
        try:
            return bool(_bounded_call(lambda: self._response.__exit__(*args), remaining))
        except Exception:
            # Cleanup cannot delay the caller past the overall deadline.
            return False

    def read(self, size: int = -1) -> bytes:
        return _bounded_call(lambda: self._response.read(size), self._remaining())


def collect_solscanner(mint: str, *, opener: Any | None = None,
                       clock: Any = time.monotonic, now: Any = utc_now) -> dict[str, Any]:
    """Attempt the exact public URL once; return a bounded observation or reason."""
    fetched_at = now().isoformat().replace("+00:00", "Z")
    result = _empty(mint, fetched_at, "not_attempted")
    if not isinstance(mint, str) or not 32 <= len(mint) <= 44 or any(c not in _BASE58 for c in mint):
        result["reason"] = "invalid_mint"
        return result
    started = clock()
    deadline = started + DEADLINE_SECONDS
    request = urllib.request.Request(
        f"{BASE_URL}/{mint}/scan/stream",
        headers={"Accept": "text/event-stream", "User-Agent": "holder-forensics/1.0"},
        method="GET",
    )
    # No environment proxy credentials, redirects, cookies, bearer tokens or retries.
    transport = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
    facts: dict[str, Any] = {"scanned_at": None, "is_stale": None, "groups": None, "scan_complete": None}
    data_lines: list[str] = []
    event_name: str | None = None
    buffer = b""
    total = 0
    saw_sse = False

    def dispatch() -> None:
        nonlocal data_lines, event_name
        if event_name in {"cache_hit", "bundle_groups", "token_metadata", "complete"} and data_lines:
            try:
                payload = json.loads("\n".join(data_lines))
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise _ShapeError from exc
            if not isinstance(payload, dict):
                raise _ShapeError
            _scan_facts(payload, mint, facts)
            if event_name in {"bundle_groups", "complete"}:
                key = "groups" if event_name == "bundle_groups" else "bundleGroups"
                if event_name == "complete":
                    complete = payload.get("scanComplete")
                    if complete is not None and type(complete) is not bool:
                        raise _ShapeError
                    if complete is not None:
                        facts["scan_complete"] = complete
                if key in payload:
                    if facts["groups"] is not None:
                        raise _ShapeError
                    # The real complete event carries the mint, so require it there.
                    facts["groups"] = _groups(payload, mint, key, require_identity=event_name == "complete")
        data_lines = []
        event_name = None

    try:
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError
        opened = _bounded_call(lambda: transport.open(request, timeout=remaining), remaining)
        with _BoundedResponse(opened, lambda: deadline - clock()) as response:
            status = int(getattr(response, "status", 200) or 200)
            if 300 <= status < 400:
                result["reason"] = "redirect_disallowed"
                return result
            if status != 200:
                result["reason"] = "http_error"
                return result
            content_type = response.headers.get("Content-Type", "") if getattr(response, "headers", None) else ""
            if content_type.split(";", 1)[0].strip().lower() != "text/event-stream":
                result["reason"] = "non_sse_response"
                return result
            while True:
                remaining = deadline - clock()
                if remaining <= 0:
                    raise TimeoutError
                sock = _response_socket(response)
                if sock is not None:
                    sock.settimeout(remaining)
                chunk = response.read(min(4096, MAX_BYTES + 1 - total))
                if clock() > deadline:
                    raise TimeoutError
                if not isinstance(chunk, bytes):
                    raise _ShapeError
                total += len(chunk)
                if total > MAX_BYTES:
                    result["reason"] = "response_too_large"
                    return result
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    raw, buffer = buffer.split(b"\n", 1)
                    try:
                        line = raw.removesuffix(b"\r").decode("utf-8")
                    except UnicodeError as exc:
                        raise _ShapeError from exc
                    if not line:
                        dispatch()
                    elif line.startswith(":"):
                        saw_sse = True
                    elif line.startswith("event:"):
                        saw_sse = True
                        event_name = line[6:].strip()
                    elif line.startswith("data:"):
                        saw_sse = True
                        data_lines.append(line[5:].lstrip(" "))
                if len(buffer) > MAX_BYTES:
                    raise _ShapeError
            if buffer:
                try:
                    line = buffer.removesuffix(b"\r").decode("utf-8")
                except UnicodeError as exc:
                    raise _ShapeError from exc
                if line.startswith("data:"):
                    data_lines.append(line[5:].lstrip(" "))
                elif line.startswith("event:"):
                    event_name = line[6:].strip()
            dispatch()
    except urllib.error.HTTPError as exc:
        result["reason"] = "redirect_disallowed" if 300 <= exc.code < 400 else "http_error"
        # Error-body cleanup is untrusted transport code too; it cannot extend
        # the absolute deadline or expose a raw body after the caller returns.
        try:
            _bounded_call(exc.close, max(0.0, deadline - clock()))
        except Exception:
            pass
        return result
    except (TimeoutError, socket.timeout):
        result["reason"] = "timeout"
        return result
    except _IdentityError:
        result["reason"] = "identity_mismatch"
        return result
    except _ShapeError:
        result["reason"] = "malformed_sse"
        return result
    except urllib.error.URLError as exc:
        result["reason"] = "timeout" if isinstance(exc.reason, TimeoutError) else "network_error"
        return result
    except OSError:
        result["reason"] = "network_error"
        return result
    except Exception:
        # Never allow a transport exception string (possibly containing a body)
        # to escape into an outer CLI traceback or durable evidence.
        result["reason"] = "network_error"
        return result
    if not saw_sse or facts["groups"] is None:
        result["reason"] = "missing_bundle_groups"
        return result
    scan_time = facts["scanned_at"]
    stale = facts["is_stale"]
    result.update({"scanned_at": scan_time, "is_stale": stale, "scan_complete": facts["scan_complete"],
                   "coverage": "observed_capped", "groups": facts["groups"]})
    for group in result["groups"]:
        for wallet in group["wallets"]:
            wallet["observed_at"] = scan_time
    scan_dt = parse_update_time(scan_time) if scan_time else None
    fetch_dt = parse_update_time(fetched_at)
    if scan_dt is not None and fetch_dt is not None and scan_dt <= fetch_dt:
        result["scan_age_min"] = round((fetch_dt - scan_dt).total_seconds() / 60, 2)
    if scan_time is None:
        result["reason"] = "missing_scan_time"
    elif stale is None:
        result["reason"] = "missing_stale_status"
    elif stale:
        result["reason"] = "provider_stale"
    elif facts["scan_complete"] is False:
        result["reason"] = "scan_incomplete"
    elif scan_dt is None or fetch_dt is None or scan_dt > fetch_dt:
        result["reason"] = "invalid_scan_time"
    elif (fetch_dt - scan_dt).total_seconds() > SCAN_FRESH_SECONDS:
        result["reason"] = "expired_scan"
    else:
        result["status"] = "ok"
        result["reason"] = None
    return result


# Reasons that still carry usable groups: the scan itself was read fine.
_GROUPS_USABLE_REASONS = frozenset({
    None, "provider_stale", "expired_scan", "missing_scan_time",
    "missing_stale_status", "invalid_scan_time", "scan_incomplete",
})


def _age_text(age_min: float | None) -> str:
    if age_min is None:
        return "age na"
    if age_min < 60:
        return f"{age_min:.0f}m"
    if age_min < 48 * 60:
        return f"{age_min / 60:.1f}h"
    return f"{age_min / 1440:.1f}d"


def solscanner_finding(result: Any, now: dt.datetime | None = None) -> dict[str, Any]:
    """Turn a collect_solscanner result into a corroboration-only provider finding.

    Never sets largest_cluster_pct, cluster_sum_pct or bundle_pct, so the
    finding can raise an alarm_hint but can never alarm alone or count as calm.
    alarm_hint is kept to SOLSCANNER_HINT_MAX_CHARS using only characters that
    survive the downstream label sanitizer.
    """
    finding: dict[str, Any] = {"provider": "solscanner", "status": "unavailable", "unit": "percent",
                               "data_age_min": None, "alarm_hint": None, "note": "",
                               "detail": SOLSCANNER_DETAIL}

    def unavailable(reason: Any) -> dict[str, Any]:
        text = reason if isinstance(reason, str) and re.fullmatch(r"[a-z_]{1,40}", reason) else "malformed_result"
        finding["note"] = f"SolScanner unavailable: {text}; not an all-clear"
        return finding

    if not isinstance(result, dict) or not isinstance(result.get("groups"), list):
        return unavailable(None)
    groups = result["groups"]
    reason = result.get("reason")
    if not groups and reason not in _GROUPS_USABLE_REASONS:
        return unavailable(reason)
    when = now or utc_now()
    scan_dt = parse_update_time(result.get("scanned_at")) if isinstance(result.get("scanned_at"), str) else None
    age = None
    future = False
    if scan_dt is not None:
        delta = (when - scan_dt).total_seconds()
        if delta < 0 or reason == "invalid_scan_time":
            future = True  # never present a future-dated scan as fresh
        else:
            age = round(delta / 60, 2)
    finding["data_age_min"] = age
    age_text = _age_text(age)
    # (long, short) flag shown inside the hint; first match wins.
    flags = None
    if future:
        flags = ("futuredated", "future")
    elif reason == "scan_incomplete":
        flags = ("incomplete", "part")
    elif result.get("is_stale") is True or reason == "provider_stale":
        flags = ("stale", "stale")
    elif reason == "expired_scan":
        flags = ("expired", "exp")
    if future:
        scan_txt = "scan is future dated"
    else:
        scan_txt = f"scan {age_text} old" + (f" ({flags[0]})" if flags else "")

    scored = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("wallets"), list):
            return unavailable(None)
        shares: dict[str, float] = {}
        for wallet in group["wallets"]:
            share = wallet.get("share_pct") if isinstance(wallet, dict) else None
            address = wallet.get("address") if isinstance(wallet, dict) else None
            if not isinstance(address, str) or isinstance(share, bool) or not isinstance(share, (int, float)) \
                    or not math.isfinite(share):
                return unavailable(None)
            shares[address] = float(share)
        scored.append((min(100.0, sum(shares.values())), len(shares), group.get("risk_score"), group.get("confidence")))
    if not scored:
        finding["status"] = "empty"
        finding["note"] = f"no bundle groups listed, {scan_txt}; not an all-clear"
        return finding

    hinting = [g for g in scored
               if type(g[2]) is int and g[2] >= SOLSCANNER_HINT_MIN_RISK and g[3] == "high"
               and g[0] >= SOLSCANNER_HINT_MIN_SHARE_PCT]
    if hinting:
        share, size, risk, _ = max(hinting, key=lambda g: g[0])
        base = f"{size}w r{risk} {share:.0f}pct"
        if flags is None:
            candidates = [f"corrob only {base} {age_text}", f"corrob only {base}"]
        else:
            candidates = [f"corrob only {base} {age_text} {flags[0]}", f"corrob only {base} {flags[0]}",
                          f"corrob {base} {flags[0]}", f"corrob {base} {flags[1]}"]
        hint = next((c for c in candidates if len(c) <= SOLSCANNER_HINT_MAX_CHARS), candidates[-1])
        finding["status"] = "ok"
        finding["alarm_hint"] = hint[:SOLSCANNER_HINT_MAX_CHARS]
        finding["note"] = (f"SolScanner corroboration only: bundle group of {size} wallets, risk {risk} (high confidence), "
                           f"{share:.1f}% of supply, {scan_txt}; groups are broad and the risk score is noisy")
        return finding
    share, size, risk, _ = max(scored, key=lambda g: g[0])
    finding["status"] = "empty"
    finding["note"] = (f"{len(scored)} bundle groups, largest {share:.1f}% (risk {risk if risk is not None else 'n/a'}); "
                       f"{scan_txt}; not an all-clear")
    return finding


# Command line (dlmm-scan collector `solscanner`; not part of the sibling copy kept in sync above). It only calls
# collect_solscanner once and saves its result as JSON, the file `helius_forensics.py assess --solscanner-json` (and
# `report --solscanner-json`) reads and revalidates. No key, no credits, no retries.


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read the public SolScanner scan for a Solana mint once (bounded: 1 MiB, 10 s, no redirects, no env proxy, "
                                                 "no key, no credits) and save the result for helius_forensics.py assess --solscanner-json. Corroboration only.")
    parser.add_argument("mint")
    parser.add_argument("--out", required=True, metavar="PATH", help="file to save the result JSON into (for example <RUN>/solscanner.json)")
    args = parser.parse_args(argv)
    mint = args.mint
    if not 32 <= len(mint) <= 44 or any(c not in _BASE58 for c in mint):
        print("error: mint is not a valid base58 Solana address", file=sys.stderr)
        return 2
    try:
        result = collect_solscanner(mint)
    except Exception:  # noqa: BLE001 - collect_solscanner already reduces failures to a reason; never print a traceback
        result = _empty(mint, utc_now().isoformat().replace("+00:00", "Z"), "network_error")
    try:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=1), encoding="utf-8")
    except OSError:
        print("error: --out is not a writable file path", file=sys.stderr)
        return 2
    groups, reason = result.get("groups") or [], result.get("reason")
    if groups or reason in _GROUPS_USABLE_REASONS:
        print(f"ok ({len(groups)} bundle group{'' if len(groups) == 1 else 's'}; {reason or 'fresh scan'}; corroboration only)")
    else:
        print(f"unavailable ({reason}; the result file records it)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
