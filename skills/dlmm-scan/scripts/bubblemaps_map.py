#!/usr/bin/env python3
"""Read the FREE Bubblemaps web map for a Solana token with Camoufox, refreshing stale maps.

Owner rule (2026-10-14): if the map's age pill ("18m ago") is >= 15 minutes, try to refresh it
before reading. The pill is a refresh control only when it is enabled. When it is disabled the script
does not click and reports the age as-is with refresh_error=pill_disabled. The likely reasons
(logged-out page state, a cooldown, a rate limit) are NOT confirmed, and one earlier run did refresh
this same public page successfully (18m -> just now), so refresh is best-effort. Trust a refresh only
when refresh_effective is true; otherwise state in the report that the clusters may be stale by
age_min_after minutes. A stale map on CHILL still showed a 22% cluster after the token had been
drained to a 99% pool-held state.

Cluster members (HS-BM-MEMBERS-T1, owner decision 2026-10-20): after the cluster sizes are read (exactly as
before: the same page state, the same text), the script expands every cluster in the map's Address List and
records each member row: rank, the shown short address (or a short inert label), the share as displayed and
the kind (holder, linking wallet that holds none, or hidden row). Facts the reader relies on (measured on the
live page, 2026-10-20):
- The Address List is virtualised (only rows near the visible part exist in the page) and sorted by share,
  with each cluster header placed by its total share. The member read therefore makes one top-down pass with
  a tall window, expands each cluster header once with its expand toggle (the chevron; never the eye button,
  a link, a form or any other control) and keeps every row by its list index.
- The size read sees only the rows rendered in the default window, so the list read can find smaller clusters
  further down; they are reported in clusters_list_only (display only, never counted).
- A header's wallet count = holder rows + linking rows (+ hidden rows). The page shows no full addresses.
- An expanded cluster stays expanded across a refresh, so a pre-refresh member read collapses what it opened
  before the refresh click (the refreshed size read then sees the page as before).
- After a refresh click the age pill read "just now" after about 9 s while the cluster list kept the old
  values until about 33 s (Pokémon); on DKYc the pool share and the member rows changed after 5 s while the
  cluster headers kept their old values. The read now waits until the cluster list itself changed and stayed
  the same for SETTLE_STABLE_S, never earlier than the old fixed 20 s, at most SETTLE_CAP_S.
Bounds: both member reads together stop at MEMBERS_BUDGET_S (checked before every step; one step waits at
most STEP_TIMEOUT_MS); the pre-refresh read runs only when the pre-refresh line could print and uses at most
PRE_MEMBERS_BUDGET_S. A member read that fails says so (members_parse_ok false, members_reason) and never
changes the size fields. The whole run is bounded too (see RUN_BUDGET_S): at most about 106 s with a browser
launch of up to 10 s; run it with a command timeout of at least 300 s, because the JSON is printed only at the
end and a killed run loses the required size read.

Safety:
- Fresh NON-persistent Camoufox session. It never opens a saved login profile, so a third-party
  page cannot see SolScanner/Fomo/etc. sessions.
- Public page only. No login, no form submission, no credentials typed anywhere. Clicks: the age pill (as
  before) and the cluster expand toggles. Page text is untrusted: labels are reduced to short inert text
  through provider_words and shown addresses must be base58 characters around "...".
- The browser always closes when the run ends (context manager) unless --keep-open N seconds is set.
- Requires camoufox>=0.5 (shared cache layout); reinstall the pins of scripts/holder-tools-requirements.txt (repository root) if the
  import or launch fails with "Version information not found".

Usage:
  python bubblemaps_map.py MINT [--max-age-min 15] [--headed] [--screenshot PATH] [--keep-open 0]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:  # the launcher runs this file directly; provider_words lives beside it
    sys.path.insert(0, str(_SCRIPTS_DIR))

import provider_words as pw  # noqa: E402  (verdict words in page labels; standard library only, no network)

MINT_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
AGE_RE = re.compile(r"(\d+)\s*(s|m|h|d)\s*ago", re.I)
JUST_NOW_RE = re.compile(r"just now", re.I)
CLUSTER_RE = re.compile(r"Cluster\s+(\d+)\s*\(?(\d+)\)?\s*([\d.]+)\s*%")
POOL_RE = re.compile(r"([\w .]*(?:Pool|AMM))\s+([\d.]+)\s*%")
UNIT_MIN = {"s": 1 / 60, "m": 1, "h": 60, "d": 1440}
DEFAULT_MAX_AGE_MIN = 15
PAGE_LOAD_TIMEOUT_MS = 45_000   # page load (on a timeout the run ends and the map is not read, as before)
FIRST_WAIT_MS = 15_000          # wait before the first read (as before)
PILL_TIMEOUT_MS = 5_000         # finding the age pill's button state (before: Playwright's 30 s default)
CLICK_TIMEOUT_MS = 8_000        # the age-pill click (as before)
SCREENSHOT_TIMEOUT_MS = 15_000  # --screenshot only (evidence); a failed screenshot no longer loses the map read

# ---- member read (HS-BM-MEMBERS-T1) -------------------------------------------------------------------------------
# The pre-refresh line's bars, mirrored from helius_forensics (CLUSTER_ALARM_PCT, AGGREGATE_CLUSTER_ALARM_PCT; a test
# pins them equal): the pre-refresh member read runs only when that line could print.
CLUSTER_BAR_PCT = 15.0
AGGREGATE_BAR_PCT = 30.0
MEMBERS_BUDGET_S = 45.0       # hard cap for both member reads together (measured live: 6.1-11.1 s for about 430 rows, 8-10 clusters)
PRE_MEMBERS_BUDGET_S = 15.0   # the pre-refresh read's part of it: reading stops at 10 s, collapsing at 15 s
PRE_READ_S = 10.0
STEP_TIMEOUT_MS = 3_000       # one expand or scroll waits at most this long for the list to re-render
POLL_MS = 50
SETTLE_MIN_S = 20.0           # the old fixed wait after the refresh click: the refreshed read is never earlier
SETTLE_STABLE_S = 5.0         # the cluster list must stay the same this long after it changed
SETTLE_CAP_S = 50.0           # stop waiting this long after the click, changed or not
SETTLE_POLL_MS = 1_000
# Worst-case wall time of one run (the registered command: no --screenshot, --keep-open 0), with a browser launch of L s
# (measured 2.3-9.5 s on 2026-10-20; this script cannot cap it):
#   fixed part:  L + 45 (page load timeout) + 15 (first wait) + 5 (pill state) + 8 (pill click) + 20 (settle minimum)
#                = L + 93 s, plus page reads (about 1 s);
#   optional:    the pre-refresh member read, the settle wait beyond its minimum and the final member read only use what is
#                left of RUN_BUDGET_S after the start (counted before the launch), each at most one step (about 4 s) late;
#   close:       about 1-2 s.
# So the run ends by max(L + 94, RUN_BUDGET_S + 4) + 2 s: about 106 s for L up to 10 s (typical measured: 26-47 s).
RUN_BUDGET_S = 100.0
REFRESH_RESERVE_S = CLICK_TIMEOUT_MS / 1000 + SETTLE_MIN_S  # kept for the click and the settle minimum before a pre-refresh read starts
FINAL_RESERVE_S = 15.0          # the settle wait beyond its minimum leaves this much of the run budget to the final member read
TALL_VIEWPORT = {"width": 1600, "height": 4000}  # set only after the last size read (the default window cannot be restored)
SCROLL_FRACTION = 0.8

HEADER_RE = re.compile(r"^Cluster\s+(\d+)\s*\(\s*(\d+)\s*\)\s*(<\s*)?(\d{1,3}(?:\.\d+)?)\s*%")
RANK_RE = re.compile(r"^\s*#(\d{1,6})\b")
SHARE_RE = re.compile(r"^(<\s*)?(\d{1,3}(?:\.\d+)?)\s*%$")
SHOWN_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{3,10}\.\.\.[1-9A-HJ-NP-Za-km-z]{3,10}$")  # the map's short address form
MAP_LABEL_STRIP = re.compile(r"[^\w .,:@&'\"()\-]")  # characters a map label may keep (helius_forensics holds the same rule)
LABEL_CAP = 40
MEMBER_KINDS = ("holder", "linking", "hidden")

# Read-only snapshot of the rendered Address List rows. Row markers observed 2026-10-20: a cluster header carries the
# chevron (path d "M7.41 8.59...") and starts with "Cluster N"; a member row starts with a colour-bar box (top-level rows
# start with the role=button item); linking rows carry the wand (path d "M4.16667 18.225") or, on dated pool rows, the
# clock (path d "M11.99 2C6.47"); hidden rows show the eye-slash (path d containing "3.42 2.45") on their eye button.
ROWS_JS = r"""() => {
  const sc = document.querySelector('#right-panel [data-testid=virtuoso-scroller]');
  if (!sc) return {error: 'address_list_not_found'};
  const items = [];
  for (const d of sc.querySelectorAll('[data-index]')) {
    const idx = Number(d.getAttribute('data-index'));
    const li = d.querySelector('li');
    if (!li) { items.push({idx, kind: 'other', text: (d.innerText || '').trim().slice(0, 80)}); continue; }
    const text = (li.innerText || '').trim().slice(0, 200);
    const header = !!li.querySelector('path[d^="M7.41 8.59"]') && /^Cluster\s+\d+/.test(text);
    const first = li.firstElementChild;
    const member = !header && !!first && !first.matches('[role=button]');
    const eye = li.querySelector('button svg path');
    let name = null;
    for (const p of li.querySelectorAll('p[aria-label]')) {
      const a = p.getAttribute('aria-label') || '';
      if (!a.startsWith('Share of')) { name = (p.innerText || a).trim().slice(0, 120); break; }
    }
    const share = li.querySelector('p[aria-label^="Share of"]');
    items.push({idx, kind: header ? 'header' : (member ? 'member' : 'top'), text, name,
                share: share ? (share.innerText || '').trim().slice(0, 20) : null,
                hidden: !!eye && (eye.getAttribute('d') || '').includes('3.42 2.45'),
                wand: !!li.querySelector('path[d^="M4.16667 18.225"]'),
                clock: !!li.querySelector('path[d^="M11.99 2C6.47"]')});
  }
  return {items, top: sc.scrollTop, height: sc.scrollHeight, view: sc.clientHeight};
}"""

# The one click of the member read: a cluster header's own expand toggle (the chevron), checked to be the header of the
# expected cluster number; never the eye (visibility) button.
CLICK_JS = r"""([idx, n]) => {
  const sc = document.querySelector('#right-panel [data-testid=virtuoso-scroller]');
  const row = sc && sc.querySelector('[data-index="' + Number(idx) + '"] li');
  if (!row) return false;
  const m = /^Cluster\s+(\d+)/.exec((row.innerText || '').trim());
  if (!m || Number(m[1]) !== Number(n)) return false;
  const path = row.querySelector('path[d^="M7.41 8.59"]');
  const svg = path && path.closest('svg');
  if (!svg || svg.closest('button')) return false;
  svg.dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true}));
  return true;
}"""

SCROLL_JS = r"""(top) => {
  const sc = document.querySelector('#right-panel [data-testid=virtuoso-scroller]');
  if (!sc) return false;
  sc.scrollTop = Number(top);
  return true;
}"""


def parse_age_minutes(text: str) -> tuple[float | None, str | None]:
    """Return (age in minutes, the matched label) from the map header text, or (None, None)."""
    if JUST_NOW_RE.search(text):
        return 0.0, "just now"
    match = AGE_RE.search(text)
    if not match:
        return None, None
    return int(match.group(1)) * UNIT_MIN[match.group(2).lower()], match.group(0)


def needs_refresh(age_min: float | None, max_age_min: float = DEFAULT_MAX_AGE_MIN) -> bool:
    """Refresh when the map is old enough. Unknown age is treated as stale (fail toward fresh data)."""
    return age_min is None or age_min >= max_age_min


def is_refresh_effective(refreshed: bool, age_before: float | None, age_after: float | None) -> bool:
    """A refresh only counts when the age pill is readable afterwards and actually dropped."""
    return bool(refreshed and age_after is not None and (age_before is None or age_after < age_before))


def parse_clusters(text: str, limit: int = 12) -> list[dict[str, float | int]]:
    return [
        {"cluster": int(n), "wallets": int(w), "supply_pct": float(p)}
        for n, w, p in CLUSTER_RE.findall(text)[:limit]
    ]


def parse_pool_share(text: str) -> float | None:
    """Largest 'Pool' share shown in the address list (99% means everyone sold into the pool)."""
    shares = [float(p) for _, p in POOL_RE.findall(text)]
    return max(shares) if shares else None


# ---- member read: pure parsing ------------------------------------------------------------------------------------


def parse_share(text: Any) -> tuple[float | None, bool, str | None]:
    """A displayed share: ("2.60%") -> (2.6, False, "2.60%"); ("< 0.01%") -> (0.01, True, "< 0.01%"), an upper bound.
    Anything else is (None, False, None)."""
    if not isinstance(text, str):
        return None, False, None
    shown = " ".join(text.split())
    m = SHARE_RE.match(shown)
    if not m or float(m.group(2)) > 100:
        return None, False, None
    return float(m.group(2)), bool(m.group(1)), shown


def parse_header(text: Any) -> dict[str, Any] | None:
    """'Cluster 1 (10) 11.45%' as the list header shows it, or None when it does not read that way."""
    m = HEADER_RE.match(" ".join(str(text).split())) if isinstance(text, str) else None
    if not m or float(m.group(4)) > 100:
        return None
    out: dict[str, Any] = {"cluster": int(m.group(1)), "wallets": int(m.group(2)), "supply_pct": float(m.group(4))}
    if m.group(3):
        out["supply_lt"] = True
    return out


def shown_address(name: Any) -> str | None:
    """The map's short address ("DuARUp...c6s6", base58 characters around "..."), or None."""
    if not isinstance(name, str):
        return None
    text = " ".join(name.replace("…", "...").split())
    return text if SHOWN_RE.match(text) else None


def map_label(name: Any) -> str | None:
    """A map label as short inert text (provider text: verdict words replaced by provider_words)."""
    return pw.label(name, MAP_LABEL_STRIP, LABEL_CAP) if isinstance(name, str) else None


def member_row(item: dict[str, Any]) -> dict[str, Any]:
    """One member row: rank, shown short address or label, share as displayed, kind (holder / linking / hidden)."""
    text = item.get("text") if isinstance(item.get("text"), str) else ""
    m = RANK_RE.match(text)
    rank = int(m.group(1)) if m else None
    shown = shown_address(item.get("name"))
    label = None if shown else map_label(item.get("name"))
    share, below, share_shown = parse_share(item.get("share"))
    wand, clock = item.get("wand") is True, item.get("clock") is True
    if wand or clock or (rank is None and share is None):
        kind = "linking"
    elif item.get("hidden") is True:
        kind = "hidden"
    else:
        kind = "holder"
    row: dict[str, Any] = {"rank": rank, "shown": shown, "label": label, "share_pct": share, "kind": kind}
    if share_shown:
        row["share_shown"] = share_shown
    if below:
        row["share_lt"] = True  # displayed as "< x%": share_pct is an upper bound
    if kind == "linking":
        row["linking_icon"] = "wand" if wand else "clock" if clock else None
    return row


def _valid_items(items: Any) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for it in items if isinstance(items, list) else []:
        if isinstance(it, dict) and isinstance(it.get("idx"), int) and not isinstance(it.get("idx"), bool) and it.get("kind") in ("header", "member", "top", "other"):
            out[it["idx"]] = it
    return out


def _count_kinds(members: list[dict[str, Any]]) -> dict[str, int]:
    return {k: sum(1 for r in members if r["kind"] == k) for k in MEMBER_KINDS}


def parse_list(items: dict[int, dict[str, Any]], at_end: bool) -> dict[str, Any]:
    """Clusters and their member rows from the rows of one list read (list index -> row). A cluster's rows are the member
    rows right after its header. members_complete is true only when the rows read equal the header's wallet count, no
    list index is missing inside the cluster, and the row after it (or the list end) was seen."""
    clusters: list[dict[str, Any]] = []
    problems: list[str] = []
    cur: dict[str, Any] | None = None

    def close(c: dict[str, Any], end_seen: bool) -> None:
        c["_end_seen"] = end_seen

    for i in sorted(items):
        it = items[i]
        if it["kind"] == "header":
            if cur is not None:
                close(cur, i == cur["_last"] + 1)
            head = parse_header(it.get("text"))
            if head is None:
                problems.append(f"list row {i} looks like a cluster header but does not read as 'Cluster N (wallets) share%'")
                cur = None
                continue
            cur = {**head, "members": [], "_last": i, "_gap": False}
            clusters.append(cur)
        elif it["kind"] == "member":
            if cur is None:
                problems.append(f"list row {i} is a member row outside any cluster")
                continue
            if i != cur["_last"] + 1:
                cur["_gap"] = True
            cur["members"].append(member_row(it))
            cur["_last"] = i
        else:
            if cur is not None:
                close(cur, i == cur["_last"] + 1)
                cur = None
    if cur is not None:
        close(cur, at_end)
    out = []
    for c in clusters:
        kinds = _count_kinds(c["members"])
        notes = []
        if c["_gap"]:
            notes.append("list rows are missing inside this cluster")
        if not c["_end_seen"]:
            notes.append("the read stopped before the end of this cluster")
        if len(c["members"]) != c["wallets"]:
            notes.append(f"read {len(c['members'])} rows ({kinds['holder']} holder, {kinds['linking']} linking, {kinds['hidden']} hidden), the header says {c['wallets']} wallets")
        entry = {k: v for k, v in c.items() if not k.startswith("_")}
        entry["members_complete"] = not notes
        if notes:
            entry["members_note"] = "; ".join(notes)
        out.append(entry)
    return {"clusters": out, "problems": problems}


def attach_members(size_clusters: list[dict[str, Any]], listed: list[dict[str, Any]], only: set[int] | None = None) -> list[dict[str, Any]]:
    """Copy each listed cluster's members onto the size-read cluster with the same number (in place; the size fields are
    never changed). Returns the listed clusters the size read does not have (display only). `only` limits the size-read
    clusters that are expected to have members (the pre-refresh read expands only some)."""
    by_n = {c["cluster"]: c for c in listed}
    for c in size_clusters:
        if only is not None and c.get("cluster") not in only:
            continue
        lc = by_n.pop(c.get("cluster"), None)
        if lc is None:
            c.update(members=None, members_complete=False, members_note="this cluster was not found in the list read")
            continue
        notes = [lc["members_note"]] if lc.get("members_note") else []
        if (lc["wallets"], lc["supply_pct"]) != (c.get("wallets"), c.get("supply_pct")):
            notes.append(f"the list header read {lc['wallets']} wallets, {lc['supply_pct']}% at member-read time (size read: {c.get('wallets')} wallets, {c.get('supply_pct')}%)")
        c.update(members=lc["members"], members_complete=lc["members_complete"])
        if notes:
            c["members_note"] = "; ".join(notes)
    return [c for n, c in sorted(by_n.items())] if only is None else []


def pre_refresh_targets(clusters_before: list[dict[str, Any]]) -> list[int]:
    """Clusters whose members the pre-refresh read takes: every cluster at or over the largest-cluster bar, else the largest
    one when the clusters together reach the aggregate bar; [] when the pre-refresh line cannot print."""
    shares = [(c["supply_pct"], c["cluster"]) for c in clusters_before if isinstance(c.get("supply_pct"), (int, float))]
    big = [n for s, n in shares if s >= CLUSTER_BAR_PCT]
    if big:
        return big
    if shares and sum(s for s, _ in shares) >= AGGREGATE_BAR_PCT:
        return [max(shares)[1]]
    return []


def settle_done(elapsed_s: float, changed_at_s: float | None, quiet_s: float, cap_s: float = SETTLE_CAP_S) -> str | None:
    """When the refreshed read may happen: 'stable' once the list changed and stayed the same SETTLE_STABLE_S (never before
    SETTLE_MIN_S), 'cap' at `cap_s` (SETTLE_CAP_S, or less when the run budget is short; never under SETTLE_MIN_S), else
    None (keep waiting)."""
    if elapsed_s >= SETTLE_MIN_S and changed_at_s is not None and quiet_s >= SETTLE_STABLE_S:
        return "stable"
    if elapsed_s >= max(SETTLE_MIN_S, cap_s):
        return "cap"
    return None


def _list_key(body: str) -> tuple:
    """The cluster list as the size read sees it. Only the clusters: on 2026-10-20 (DKYc) the pool share and the holder rows
    changed 5 s after a refresh click while the cluster headers kept their pre-refresh values (the member rows under them
    were already new), so a change elsewhere on the page does not mean the clusters were refreshed."""
    return tuple((c["cluster"], c["wallets"], c["supply_pct"]) for c in parse_clusters(body))


# ---- member read: browser steps (page = Playwright page, or a fake page in the tests) -------------------------------


def _snapshot(page: Any) -> dict[str, Any]:
    snap = page.evaluate(ROWS_JS)
    if not isinstance(snap, dict):
        return {"error": "address_list_unreadable"}
    if snap.get("error"):
        return {"error": str(snap["error"])[:40]}
    if not isinstance(snap.get("items"), list) or not all(isinstance(snap.get(k), (int, float)) for k in ("top", "height", "view")):
        return {"error": "address_list_unreadable"}
    return snap


def _at_end(snap: dict[str, Any]) -> bool:
    return snap["top"] + snap["view"] >= snap["height"] - 2


def _open_after(items: dict[int, dict[str, Any]], idx: int) -> bool | None:
    """True when the row after a header is a member row (the cluster is open), False when it is another row, None when it
    is not rendered."""
    nxt = items.get(idx + 1)
    return None if nxt is None else nxt["kind"] == "member"


def _wait(page: Any, check: Callable[[], bool], clock: Callable[[], float]) -> bool:
    start = clock()
    while clock() - start < STEP_TIMEOUT_MS / 1000:
        if check():
            return True
        page.wait_for_timeout(POLL_MS)
    return check()


def read_list(page: Any, deadline: float, *, targets: set[int] | None = None, clock: Callable[[], float] = time.monotonic) -> dict[str, Any]:
    """One top-down pass over the Address List: expands each collapsed cluster header once (only `targets` when given) and
    keeps every rendered row by its list index, scrolling until the list end (or, with `targets`, until each target
    cluster's last row was read). Stops at `deadline`."""
    out: dict[str, Any] = {"items": {}, "opened": [], "notes": [], "at_end": False, "error": None, "budget_hit": False}
    tried: set[int] = set()
    page.evaluate(SCROLL_JS, 0)
    page.wait_for_timeout(300)
    while True:
        if clock() >= deadline:
            out["budget_hit"] = True
            break
        snap = _snapshot(page)
        if snap.get("error"):
            out["error"] = snap["error"]
            break
        items = _valid_items(snap["items"])
        if not items:
            out["error"] = "address_list_empty"
            break
        pending = []
        for i, it in sorted(items.items()):
            head = parse_header(it.get("text")) if it["kind"] == "header" else None
            if head and head["cluster"] not in tried and (targets is None or head["cluster"] in targets):
                pending.append((i, head["cluster"]))
        if pending:
            i, n = pending[0]
            state = _open_after(items, i)
            if state is None and not _at_end(snap):  # the header is the last rendered row: bring the rows after it in
                page.evaluate(SCROLL_JS, snap["top"] + snap["view"] / 2)
                page.wait_for_timeout(POLL_MS * 4)
                continue
            tried.add(n)
            if state:
                out["opened"].append(n)
                out["notes"].append(f"Cluster {n} was already open")
                continue
            if not page.evaluate(CLICK_JS, [i, n]):
                out["notes"].append(f"Cluster {n}: its expand toggle was not found")
                continue
            if _wait(page, lambda: _open_after(_valid_items(_snapshot(page).get("items")), i) is True, clock):
                out["opened"].append(n)
            else:
                out["notes"].append(f"Cluster {n}: no member rows appeared after the expand toggle")
            continue
        out["items"].update(items)
        if targets is not None and _targets_read(out["items"], targets):
            break
        if _at_end(snap):
            out["at_end"] = True
            break
        last = max(items)
        page.evaluate(SCROLL_JS, snap["top"] + snap["view"] * SCROLL_FRACTION)
        _wait(page, lambda: max(_valid_items(_snapshot(page).get("items")) or [last]) > last, clock)
    return out


def _targets_read(items: dict[int, dict[str, Any]], targets: set[int]) -> bool:
    """Every target cluster's header and the row after its last member row were read."""
    found = {}
    for i, it in items.items():
        head = parse_header(it.get("text")) if it["kind"] == "header" else None
        if head and head["cluster"] in targets:
            found[head["cluster"]] = i
    if set(found) != set(targets):
        return False
    for i in found.values():
        j = i + 1
        while j in items and items[j]["kind"] == "member":
            j += 1
        if j not in items:
            return False
    return True


def collapse(page: Any, opened: list[int], deadline: float, *, clock: Callable[[], float] = time.monotonic) -> list[int]:
    """Close the clusters a read opened (top-down, with the same expand toggle). Returns the ones still open."""
    left = list(opened)
    page.evaluate(SCROLL_JS, 0)
    page.wait_for_timeout(300)
    while left and clock() < deadline:
        snap = _snapshot(page)
        if snap.get("error"):
            break
        items = _valid_items(snap["items"])
        acted = False
        for i, it in sorted(items.items()):
            head = parse_header(it.get("text")) if it["kind"] == "header" else None
            if not head or head["cluster"] not in left:
                continue
            state = _open_after(items, i)
            if state is False:
                left.remove(head["cluster"])
            elif state is True:
                if page.evaluate(CLICK_JS, [i, head["cluster"]]) and _wait(page, lambda: _open_after(_valid_items(_snapshot(page).get("items")), i) is not True, clock):
                    left.remove(head["cluster"])
                acted = True
                break
        if acted:
            continue
        if not items or _at_end(snap):
            break
        last = max(items)
        page.evaluate(SCROLL_JS, snap["top"] + snap["view"] * SCROLL_FRACTION)
        _wait(page, lambda: max(_valid_items(_snapshot(page).get("items")) or [last]) > last, clock)
    page.evaluate(SCROLL_JS, 0)
    page.wait_for_timeout(300)
    return left


def wait_for_settle(page: Any, before_body: str, *, clock: Callable[[], float] = time.monotonic, cap_s: float = SETTLE_CAP_S) -> tuple[str, dict[str, Any]]:
    """After the refresh click: poll the page text until the cluster list changed and stayed the same (settle_done).
    Returns (the page text to read, the settle facts)."""
    start = clock()
    before = _list_key(before_body)
    prev, changed_at, last_change = before, None, start
    while True:
        body = page.inner_text("body")
        now = clock()
        key = _list_key(body)
        if key != prev:
            prev, last_change = key, now
        if changed_at is None and key != before:
            changed_at = now - start
        done = settle_done(now - start, changed_at, now - last_change, cap_s)
        if done:
            cap = max(SETTLE_MIN_S, cap_s)
            info: dict[str, Any] = {"settle_s": round(now - start, 1), "settle_list_changed_s": None if changed_at is None else round(changed_at, 1), "settle_note": None,
                                    "settle_cap_s": round(cap, 1)}
            if done == "cap" and changed_at is None:
                info["settle_note"] = (f"the cluster list did not change within {cap:.0f} s after the refresh: the refreshed map may have the same "
                                       "clusters, or the page had not updated yet (the clusters may still be the pre-refresh ones)")
            elif done == "cap":
                info["settle_note"] = f"the cluster list was still changing {cap:.0f} s after the refresh; read at that point"
            return body, info
        page.wait_for_timeout(SETTLE_POLL_MS)


def _members_failure(result: dict[str, Any], reason: str) -> None:
    result.update(members_parse_ok=False, members_reason=reason)
    for c in result.get("clusters") or []:
        c.update(members=None, members_complete=False)


def read_pre_refresh_members(page: Any, result: dict[str, Any], *, clock: Callable[[], float] = time.monotonic, deadline: float | None = None) -> None:
    """Members of the pre-refresh clusters the pre-refresh line would name, read before the refresh click at the default
    window, then collapsed again so the refreshed size read sees the page as before. It starts only when the run budget
    (`deadline`) still holds its own time plus the refresh's fixed part; clusters it could not close are listed in
    `members_before_not_closed` (the refreshed size read may then list fewer clusters)."""
    targets = pre_refresh_targets(result.get("clusters_before") or [])
    if not targets:
        result.update(members_before_read=False, members_before_reason=(
            f"not needed: no pre-refresh cluster at or over {CLUSTER_BAR_PCT:g}% and clusters together under {AGGREGATE_BAR_PCT:g}% (the pre-refresh line cannot print)"))
        return
    t0 = clock()
    if deadline is not None and deadline - t0 < PRE_MEMBERS_BUDGET_S + REFRESH_RESERVE_S:
        result.update(members_before_read=False, members_before_clusters=targets, members_before_reason=(
            f"skipped: {max(0.0, deadline - t0):.0f} s left of the {RUN_BUDGET_S:g} s run budget, under the "
            f"{PRE_MEMBERS_BUDGET_S + REFRESH_RESERVE_S:g} s this read and the refresh need"))
        return
    reasons: list[str] = []
    opened: list[int] = []
    try:
        read = read_list(page, t0 + PRE_READ_S, targets=set(targets), clock=clock)
        opened = read["opened"]
        if read["error"]:
            reasons.append(f"the list could not be read ({read['error']})")
        else:
            parsed = parse_list(read["items"], read["at_end"])
            attach_members(result["clusters_before"], parsed["clusters"], only=set(targets))
            reasons += parsed["problems"]
        if read["budget_hit"]:
            reasons.append(f"time budget reached ({PRE_READ_S:g} s for the pre-refresh read)")
        reasons += read["notes"]
    except Exception as err:  # noqa: BLE001 - the member read never stops the map read
        reasons.append(f"browser step failed ({type(err).__name__})")
    try:
        still_open = collapse(page, opened, t0 + PRE_MEMBERS_BUDGET_S, clock=clock)
    except Exception as err:  # noqa: BLE001
        still_open = opened
        reasons.append(f"collapse failed ({type(err).__name__})")
    if still_open:  # a field of its own, so the display can always show it (HS-BM-MEMBERS-T1 repair R1)
        result["members_before_not_closed"] = list(still_open)
    ok = not any(r.startswith(("the list could not", "browser step", "list row")) for r in reasons)
    result.update(members_before_read=ok, members_before_reason="; ".join(reasons) or None,
                  members_before_seconds=round(clock() - t0, 1), members_before_clusters=targets)


def read_final_members(page: Any, result: dict[str, Any], *, clock: Callable[[], float] = time.monotonic, deadline: float | None = None) -> None:
    """Members of every cluster, read after the last size read in a tall window (more rows per step). Its budget is what
    the pre-refresh read left of MEMBERS_BUDGET_S (the settle wait in between does not count), and never past the run
    budget's `deadline`."""
    t0 = clock()
    budget = MEMBERS_BUDGET_S - float(result.get("members_before_seconds") or 0.0)
    if deadline is not None:
        budget = min(budget, deadline - t0)
    if budget < 1.0:
        _members_failure(result, f"not read: no time left in the {RUN_BUDGET_S:g} s run budget; the cluster sizes above were read as before")
        result["members_seconds"] = 0.0
        return
    try:
        page.set_viewport_size(TALL_VIEWPORT)
        page.wait_for_timeout(400)
        read = read_list(page, t0 + budget, clock=clock)
    except Exception as err:  # noqa: BLE001 - the member read never stops the map read
        _members_failure(result, f"browser step failed ({type(err).__name__}); the cluster sizes above were read as before")
        result["members_seconds"] = round(clock() - t0, 1)
        return
    result["members_seconds"] = round(clock() - t0, 1)
    if read["error"]:
        _members_failure(result, f"the Address List could not be read ({read['error']}); the page layout may have changed; the cluster sizes were read as before")
        return
    parsed = parse_list(read["items"], read["at_end"])
    sizes = result.get("clusters") or []
    if sizes and not parsed["clusters"] and not parsed["problems"] and read["budget_hit"]:
        _members_failure(result, f"not read: the time budget ({budget:.0f} s for this read) ran out before the first cluster's rows were read; the cluster sizes above were read as before")
        return
    if parsed["problems"] or (sizes and not parsed["clusters"]):
        why = parsed["problems"][:3] or [f"the list read found no cluster rows while the size read found {len(sizes)}"]
        _members_failure(result, "member rows could not be read: " + "; ".join(why) + " (the page layout may have changed; the cluster sizes were read as before)")
        return
    result["clusters_list_only"] = attach_members(sizes, parsed["clusters"])
    reasons = list(read["notes"])
    if read["budget_hit"]:
        reasons.append(f"time budget reached ({budget:.0f} s for this read: {MEMBERS_BUDGET_S:g} s for both member reads, and the {RUN_BUDGET_S:g} s run budget); clusters further down were not read")
    result.update(members_parse_ok=True, members_reason="; ".join(reasons) or None, members_list_clusters=len(parsed["clusters"]))


def read_map(mint: str, *, max_age_min: float, headed: bool, screenshot: Path | None, keep_open: int, clock: Callable[[], float] = time.monotonic) -> dict:
    from camoufox.sync_api import Camoufox  # lazy: unit tests do not need a browser

    started = clock()  # the run budget counts from here, before the browser launch
    run_deadline = started + RUN_BUDGET_S
    result: dict = {"mint": mint, "refreshed": False}
    with Camoufox(headless=not headed, humanize=True, block_webrtc=True) as browser:
        page = browser.new_page()
        page.goto(f"https://app.bubblemaps.io/sol/token/{mint}", wait_until="domcontentloaded", timeout=PAGE_LOAD_TIMEOUT_MS)
        page.wait_for_timeout(FIRST_WAIT_MS)
        body = page.inner_text("body")
        age, label = parse_age_minutes(body)
        result.update(age_label_before=label, age_min_before=age, clusters_before=parse_clusters(body))
        if needs_refresh(age, max_age_min):
            try:
                # Prefer the header button that carries the age pill; fall back to any text match.
                pill = page.get_by_role("button").filter(has_text=AGE_RE)
                target = pill.first if pill.count() else page.get_by_text(AGE_RE).first
                # The pill's button can be Mui-disabled (cause unproven: logged-out state, cooldown or rate limit).
                # Do not force-click a disabled element; report it without asserting why.
                disabled = target.evaluate("e => { const b = e.closest('button'); return !!b && b.disabled; }", timeout=PILL_TIMEOUT_MS)
                if disabled:
                    result["refresh_error"] = "pill_disabled"
                    result.update(members_before_read=False, members_before_reason="not needed: no refresh was tried (pill disabled)")
                else:
                    read_pre_refresh_members(page, result, clock=clock, deadline=run_deadline)
                    before_body = body
                    target.click(timeout=CLICK_TIMEOUT_MS)
                    result["refreshed"] = True
                    # the settle wait beyond its minimum leaves FINAL_RESERVE_S of the run budget to the final member read
                    cap = min(SETTLE_CAP_S, max(SETTLE_MIN_S, run_deadline - clock() - FINAL_RESERVE_S))
                    body, settle = wait_for_settle(page, before_body, clock=clock, cap_s=cap)
                    result.update(settle)
            except Exception as err:  # noqa: BLE001 - report, do not crash the analysis
                result["refresh_error"] = type(err).__name__
            result.setdefault("members_before_read", False)
            result.setdefault("members_before_reason", f"not read (the refresh step failed: {result.get('refresh_error')})")
        else:
            result.update(members_before_read=False, members_before_reason="not needed: no refresh was tried (map fresh enough)")
        age_after, label_after = parse_age_minutes(body)
        clusters = parse_clusters(body)
        pool_share = parse_pool_share(body)
        result.update(
            age_label_after=label_after,
            age_min_after=age_after,
            clusters=clusters,
            largest_pool_share_pct=pool_share,
            # A refresh is only trusted when the age pill actually dropped; a changed UI must not look like "no clusters".
            refresh_effective=is_refresh_effective(result["refreshed"], age, age_after),
            parse_ok=bool(clusters or pool_share is not None),
        )
        read_final_members(page, result, clock=clock, deadline=run_deadline)  # after every size field above is set; never changes them
        result["members_budget_s"] = MEMBERS_BUDGET_S
        result["run_budget_s"] = RUN_BUDGET_S
        result["run_seconds"] = round(clock() - started, 1)  # launch to here (the browser close comes after)
        if screenshot:
            try:  # evidence only: a failed screenshot never loses the map read
                page.evaluate(SCROLL_JS, 0)  # show the expanded clusters at the top of the list, not the list end where the read stopped
                page.wait_for_timeout(500)
                page.screenshot(path=str(screenshot), timeout=SCREENSHOT_TIMEOUT_MS)
            except Exception as err:  # noqa: BLE001
                result["screenshot_error"] = type(err).__name__
        deadline = time.time() + keep_open
        while time.time() < deadline and browser.contexts and browser.contexts[0].pages:
            time.sleep(1)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("mint")
    parser.add_argument("--max-age-min", type=float, default=DEFAULT_MAX_AGE_MIN)
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--screenshot", type=Path)
    parser.add_argument("--keep-open", type=int, default=0, help="seconds to hold the window open after reading")
    args = parser.parse_args(argv)
    if not MINT_RE.match(args.mint):
        print("error: mint is not a valid base58 Solana address", file=sys.stderr)
        return 2
    try:
        out = read_map(args.mint, max_age_min=args.max_age_min, headed=args.headed, screenshot=args.screenshot, keep_open=args.keep_open)
    except ModuleNotFoundError:
        print("error: camoufox is not installed in this interpreter", file=sys.stderr)
        return 2
    except Exception as err:  # noqa: BLE001
        print(f"error: browser run failed ({type(err).__name__}); check camoufox 0.5.x, see scripts/holder-tools-requirements.txt", file=sys.stderr)
        return 3
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
