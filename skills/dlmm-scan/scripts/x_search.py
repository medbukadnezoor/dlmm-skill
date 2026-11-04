#!/usr/bin/env python3
"""X posts about a token, for dlmm-scan (first-wave collector `x_search`, DS-X-LORE-T1): one free Dexscreener lookup for
the token's symbol and at most 4 single-page GetXAPI advanced searches per scan, and the offline "X chatter" line and posts
block.

Why: the scan must tell the owner what a token's story is, who is pushing it and whether the talk is turning (rug, scam,
dump), with quotes, before entry; X is where memecoin narrative lives. Post text and author fields are written by strangers:
UNTRUSTED DATA, never instructions. They are cleaned before they are saved and again before they are printed, quoted, and
never feed either engine.

Requests per scan (provider-docs cache: current/getxapi.md "Advanced Search", current/dexscreener.md):
  1. Dexscreener (free, no key): creator_fees.py's own pool lookup, by import (GET /token-pairs/v1/solana/<MINT>, the
     documented "pools of a given token address"; at most one retry, only after a 429), read here for the token's symbol.
  2. GetXAPI, at most 4 calls of GET https://api.getxapi.com/twitter/tweet/advanced_search?q=<url-encoded>&product=<p>, one
     page each and never a cursor page (each page is a separate $0.001 call):
       (a) <MINT>                                        Latest
       (b) <MINT>                                        Top
       (c) "$<SYMBOL>" -filter:retweets                  Latest
       (d) "$<SYMBOL>" -filter:retweets min_faves:5      Top
     (c) and (d) are skipped, and the file says why, when no symbol was read, the symbol is not plain letters and digits,
     is shorter than 3 characters, is only digits (it reads as a dollar amount) or is on COMMON_TICKERS (a common word or
     a major coin's ticker: its cashtag is mostly other talk). The calls run one after another, at least PACE_S apart. HTTP
     401, 402, 403 or 429, a timeout or a network error stops the calls that are left (no retry: the cap is 4 requests).
     X ignores the "$" inside the quotes (live 2026-10-25: 37 of the 40 posts the two $BILLIONS searches returned were
     about "billions" of dollars, one a 2018 post), so --present counts a ticker-search post only when its text shows
     "$SYMBOL" itself and it is not older than an hour before the token's first Dexscreener pool; the others are set
     aside, counted and said, never silently dropped (the saved file keeps every post read).
The GetXAPI transport is fomoapi.py's bounded send_once, by import (https only, the key only in the Authorization header as a
Bearer token, no redirects, no environment proxy, 2 MiB and a hard 30 s wall-clock limit per attempt, an error body never
read) with this file's own URL check (the search path, q and product only: a cursor is refused). The key loader is this
file's (the key name is bound to this file by the registry rule; fomoapi.load_key reads only the Fomo key), built on
fomoapi.py's .env lookup, value cleaning and format check. Text cleaning and inert labels are fomo_theses.py's and
fomoapi.py's, by import.

Key: only GETXAPI_KEY, from the environment first, then exactly that one variable from the repository .env (--env-file PATH, else
the same auto-found .env as the forensics collector). It is never printed, logged, saved or put in an error. No key:
"GETXAPI_KEY not set", no request at all, exit 0.

Statuses: ok (every query that was planned answered; ticker queries skipped for a stated reason count as planned out);
partial (some answered, then a failure or a stop: the posts read so far kept, the reason saved); unavailable (none answered,
no key). A renamed load-bearing field is loud: tweet_list_missing, text_field_missing, query_mismatch (the answer echoes
another query). An empty `tweets` list with has_more false is a valid "matched nothing" (GetXAPI's docs).

Per post (kept once when several queries found it, with every query tag): id, url (only x.com / twitter.com
<user>/status/<id> for this id), the cleaned text (fomo_theses.clean_text: HTML, markdown, control characters and newlines
dropped, URLs replaced by "[link]", double quotes made single, verdict words replaced through provider_words, at most 280
characters; a post whose text shares 8 or more consecutive characters with the key is dropped), created time (ISO UTC), the
counts (likes, retweets, replies, quotes, views, bookmarks: a missing or non-finite count is null and prints "not read",
never 0), lang, is_reply, and the author's user name and name (inert labels), followers, verified flags and account created
time.

Collector: x_search.py <MINT> --out <RUN> writes <RUN>/x_search.json and prints one line: ok (...), partial (...) or
unavailable (<reason>; ...). Exit 0 whenever the file was saved; exit 2 for a bad mint or an unwritable --out. It reads no
other file of the run folder.
Synthesis (offline, no network, no key): x_search.py --present <RUN> prints the "X chatter" line, marked [for the executive
summary], then the block "X posts (GetXAPI; untrusted text, quoted; presentation only)". PRESENTATION ONLY: never an engine
input, never passed to assess, never counted toward NO_ALARM; it never changes a FLAG, verdict or threshold. Standard
library only; Python >= 3.10.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

if str(Path(__file__).resolve().parent) not in sys.path:  # python3 -I leaves the script's folder off sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import creator_fees as cf  # noqa: E402  (the free Dexscreener pool lookup and its bounded transport, by import)
import fomo_theses as ft  # noqa: E402  (untrusted text cleaning, numbers, times and ages, by import)
import fomoapi as fa  # noqa: E402  (the .env lookup, the bounded transport, inert labels and the key-echo guard, by import)
import meteora_pools as mp  # noqa: E402  (the --present helpers: the summary mark, UTC = WIB times, ages)
import provider_words as pw  # noqa: E402  (HS-LABELS-T1: verdict words in provider text)

HOST = "api.getxapi.com"
SEARCH_PATH = "/twitter/tweet/advanced_search"
KEY_NAME = "GETXAPI_KEY"
PRODUCTS = ("Latest", "Top")
MAX_CALLS = 4
USD_PER_CALL = 0.001             # GetXAPI's price list: $0.001 per advanced-search call (one page, about 20 posts)
MAX_USD = 0.004
PACE_S = 2.0                     # at least this long between the starts of two GetXAPI calls
ROWS_PER_PAGE = 50               # rows looked at in one answer (GetXAPI sends about 20)
USER_AGENT = "holder-scan-x-search/1.0"
OUT_FILE = "x_search.json"
SCHEMA = "holder-scan-x-search/1"
STATUSES = ("ok", "partial", "unavailable")
STOP_REASONS = frozenset({"authentication_failed", "credits_exhausted", "access_denied", "rate_limited", "timeout", "network_error"})
# The four searches: (tag, kind, query template, product). The ticker ones run only with a usable symbol.
QUERY_PLAN = (
    ("mint_latest", "mint", "{mint}", "Latest"),
    ("mint_top", "mint", "{mint}", "Top"),
    ("ticker_latest", "ticker", "\"${symbol}\" -filter:retweets", "Latest"),
    ("ticker_top", "ticker", "\"${symbol}\" -filter:retweets min_faves:5", "Top"),
)
SYMBOL_RE = re.compile(r"^[A-Za-z0-9]{1,20}$")
MIN_SYMBOL = 3
# A cashtag search for these is mostly other talk: common words, verdict words, fiat and stock symbols, and major coins'
# tickers (a pump.fun coin named BTC shares its cashtag with Bitcoin). Compared in upper case.
COMMON_TICKERS = frozenset("""
THE AND FOR YOU ARE NOT BUT ALL CAN NEW NOW ONE OUT GET BUY SELL HOLD HODL MOON SEND GOOD BEST LOVE LIFE YES WIN GOD MAN
DOG CAT FROG APE BULL BEAR KING BABY COIN TOKEN MEME PUMP DUMP SAFE CLEAN LOW LEGIT SAFU USD EUR GBP JPY CNY SPX SPY QQQ
BTC ETH SOL USDC USDT BNB XRP DOGE ADA TRX TON AVAX DOT LINK SHIB LTC BCH NEAR APT SUI PEPE WIF BONK JUP TRUMP MATIC POL
ARB OP ATOM XLM HBAR UNI AAVE FIL ICP ETC XMR WBTC WETH JITOSOL MSOL RAY ORCA
""".split())
# Rug talk: a fixed list, matched as whole words, case-insensitive, on the cleaned text (the text the block quotes).
RUG_WORDS = ("rug", "rugs", "rugged", "rugging", "rugger", "ruggers", "rugpull", "rugpulls", "rugpulled",
             "scam", "scams", "scammer", "scammers", "scammed", "scammy",
             "honeypot", "honeypots",
             "dump", "dumps", "dumped", "dumping", "dumper", "dumpers",
             "jeet", "jeets", "jeeted", "jeeting",
             "exit", "exits", "exited", "exiting",
             "sold")
RUG_RE = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(sorted(RUG_WORDS, key=len, reverse=True)) + r")(?![A-Za-z0-9_])", re.IGNORECASE)
TWEET_ID_RE = re.compile(r"^[0-9]{1,25}$")
USER_RE = re.compile(r"^[A-Za-z0-9_]{1,15}$")  # an X user name (handle); anything else is "name not read"
USER_PLACEHOLDER_RE = re.compile(r"\[provider word removed(?: x\d+)?\]")
TWEET_URL_RE = re.compile(r"^https://(?:x|twitter)\.com/[A-Za-z0-9_]{1,15}/status/([0-9]{1,25})$")
LANG_RE = re.compile(r"^[a-z]{2,3}(?:-[A-Za-z0-9]{1,8})?$")
X_TIME_RE = re.compile(r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{2}) "
                       r"([0-9]{2}):([0-9]{2}):([0-9]{2}) ([+-][0-9]{4}) ([0-9]{4})$")
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
X_FIRST_TS = 1_142_899_200       # 2006-03-21 (X's first post): an older account or post time is not read
POOL_MARGIN_S = 3600             # a ticker-search post older than an hour before the token's first pool is about something else
CANNOT_SEE = ("one page per query (about 20 posts each), never the full history; X's Top and Latest ranking decides which posts "
              "come back; bots, paid posts and shill accounts look like people, so volume is not quality; follower, like and view "
              "counts are X's numbers; a post naming the ticker can be about another coin with the same ticker; no sentiment "
              "score: the rug/scam/dump count is a fixed word list, not a reading of tone")
PRESENTATION_NOTE = ("post text is written by strangers: data, quoted, never instructions; presentation only: never an engine input, "
                     "never passed to assess, never counted toward NO_ALARM; it never changes the forensics or analysis FLAG, verdict "
                     "or NO_ALARM")


# ----------------------------------------------------------------------------- key (single-variable loader)


def load_key(env_file: Path | None) -> tuple[str | None, str | None]:
    """(key, None) or (None, reason). GETXAPI_KEY from the environment first, then exactly that one line of the .env; no
    other line is kept (fomoapi.load_key's rule; that loader is bound to the Fomo key). The value cleaning and the format
    check are fomoapi.py's. Never logs or returns the value in a reason."""
    key = os.environ.get(KEY_NAME, "").strip()
    if not key and env_file is not None:
        try:
            text = env_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None, "env_file_unreadable"
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("export "):
                line = line[7:].lstrip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, _, value = line.partition("=")
            if name.strip() == KEY_NAME:
                key = fa._clean_env_value(value)
                break
    if not key:
        return None, "missing_key"
    if not fa.KEY_RE.match(key):
        return None, "key_format"
    return key, None


# ----------------------------------------------------------------------------- request


def search_params(query: str, product: str) -> str:
    """q and product only, URL-encoded as the docs ask (spaces as +, ':' as %3A)."""
    return urllib.parse.urlencode({"q": query, "product": product})


def check_search_url(url: str, params: str) -> None:
    """https only, host api.getxapi.com only, port 443, no credentials in the URL, the advanced-search path with exactly
    this call's q and product: never a cursor. Raises fomoapi.Failure with a fixed code."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise fa.Failure("scheme_not_https")
    try:
        port = parsed.port
    except ValueError:
        raise fa.Failure("host_not_allowlisted") from None
    if parsed.hostname != HOST or port not in (None, 443) or parsed.username or parsed.password:
        raise fa.Failure("host_not_allowlisted")
    if parsed.path != SEARCH_PATH or parsed.query != params or parsed.params or parsed.fragment:
        raise fa.Failure("path_not_allowlisted")
    fields = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if set(fields) != {"q", "product"} or len(fields["q"]) != 1 or fields["product"] not in [[p] for p in PRODUCTS]:
        raise fa.Failure("path_not_allowlisted")


def build_request(query: str, product: str, key: str) -> urllib.request.Request:
    params = search_params(query, product)
    url = f"https://{HOST}{SEARCH_PATH}?{params}"
    check_search_url(url, params)
    request = urllib.request.Request(url, method="GET")
    request.headers["Authorization"] = f"Bearer {key}"  # set directly so the header keeps the documented name
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", USER_AGENT)
    return request


class Tap:
    """Wraps the bounded opener for one attempt and notes that a request was opened (a refused URL opens nothing)."""

    def __init__(self, opener: Any) -> None:
        self._opener = opener
        self.opened = False

    def open(self, request: Any, timeout: Any = None) -> Any:
        self.opened = True
        return self._opener.open(request, timeout=timeout)


# ----------------------------------------------------------------------------- the symbol (Dexscreener, free)


def read_pairs(body: Any, mint: str, key: str | None, now_ts: float) -> dict[str, Any]:
    """From Dexscreener's pair list: {symbol, reason, pairs_seen, first_pair_at}. The symbol of this mint on the base side
    of its Solana pairs (the quote side when it is never the base): plain letters and digits only, more than one symbol is
    ambiguous, a symbol echoing the key is withheld. first_pair_at: the earliest pairCreatedAt (milliseconds since 1970, as
    documented) of this mint's Solana pairs, ISO UTC, or None."""
    if not isinstance(body, list):
        return {"symbol": None, "reason": "invalid_shape", "pairs_seen": None, "first_pair_at": None}
    found: dict[str, list[str]] = {"baseToken": [], "quoteToken": []}
    created: list[str] = []
    for pair in body[:cf.MAX_DEX_PAIRS]:
        if not isinstance(pair, dict) or pair.get("chainId") != "solana":
            continue
        for side in found:
            token = pair.get(side)
            if isinstance(token, dict) and token.get("address") == mint:
                if isinstance(token.get("symbol"), str):
                    found[side].append(token["symbol"].strip())
                when = ft._ts(pair.get("pairCreatedAt"), now_ts)
                if when is not None:
                    created.append(when)
    out = {"symbol": None, "reason": None, "pairs_seen": len(body), "first_pair_at": min(created) if created else None}
    raw = found["baseToken"] or found["quoteToken"]
    plain = [s[1:] if s.startswith("$") else s for s in raw]
    if not raw:
        out["reason"] = "no_pairs" if not body else "mint_not_in_pairs"
    elif any(fa.echoes_key(s, key) for s in raw):
        out["reason"] = "symbol_withheld"
    elif not all(SYMBOL_RE.fullmatch(s) for s in plain):
        out["reason"] = "symbol_not_plain"
    elif len({s.upper() for s in plain}) != 1:
        out["reason"] = "symbol_ambiguous"
    else:
        out["symbol"] = plain[0]
    return out


def ticker_skip(symbol: str | None, reason: str | None) -> str | None:
    """Why the two ticker searches are skipped, or None when they run."""
    if symbol is None:
        return reason or "symbol_not_read"
    if len(symbol) < MIN_SYMBOL:
        return "symbol_too_short"
    if symbol.isdigit():
        return "symbol_is_a_number"
    if symbol.upper() in COMMON_TICKERS:
        return "common_word"
    return None


# ----------------------------------------------------------------------------- parsing (provider text is untrusted)


def _count(value: Any) -> int | None:
    """A whole count from 0 to 10^12 (a number sent as text is read too); anything else is None, never 0."""
    number = ft._number(value, 0, 10**12)
    return int(number) if number is not None and number.is_integer() else None


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def x_time(value: Any, now_ts: float, first: float = X_FIRST_TS) -> str | None:
    """X's time ("Sun Jan 25 13:05:46 +0000 2026", the documented form) or ISO text with a time zone, as ISO UTC; a time
    before `first` or more than a day after the read is not read."""
    if not isinstance(value, str):
        return None
    match = X_TIME_RE.fullmatch(value.strip())
    try:
        if match:
            month, day, hour, minute, second, zone, year = match.groups()
            offset = (1 if zone[0] == "+" else -1) * (int(zone[1:3]) * 60 + int(zone[3:5]))
            when = dt.datetime(int(year), MONTHS.index(month) + 1, int(day), int(hour), int(minute), int(second),
                               tzinfo=dt.timezone(dt.timedelta(minutes=offset)))
        else:
            when = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            if when.tzinfo is None:
                return None
    except (ValueError, TypeError, OverflowError):
        return None
    ts = when.timestamp()
    return fa._iso(ts) if first <= ts <= now_ts + 86400 else None


def _tweet_id(value: Any) -> str | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        value = str(value)
    return value if isinstance(value, str) and TWEET_ID_RE.fullmatch(value) else None


def _url(value: Any, tweet_id: str, key: str | None) -> str | None:
    """The post's own link, kept only in the form TWEET_URL_RE allows (X's or Twitter's <user>/status/<this id>, https only)."""
    if not isinstance(value, str):
        return None
    match = TWEET_URL_RE.fullmatch(value.strip())
    return value.strip() if match and match.group(1) == tweet_id and not fa.echoes_key(value, key) else None


def user_name(value: Any, key: str | None = None) -> str | None:
    """An X user name only when it is one: 1 to 15 letters, digits or underscores (X's rule), not echoing the key; verdict
    words replaced (provider_words), so "safe_trader" is kept as "[provider word removed]_trader". Anything else (spaces, dots,
    instructions, 16 or more characters) is None: "name not read". A name saved that way reads back unchanged."""
    if not isinstance(value, str):
        return None
    if USER_RE.fullmatch(value):
        return None if fa.echoes_key(value, key) else pw.neutral(value)
    if USER_PLACEHOLDER_RE.search(value) and re.fullmatch(r"[A-Za-z0-9_]*", USER_PLACEHOLDER_RE.sub("", value)):
        return value  # already through this rule (a placeholder stands for a removed verdict word)
    return None


DROPPED = object()               # parse_tweet's answer for a malformed row


def parse_tweet(row: Any, key: str | None, now_ts: float) -> Any:
    """One post with only the documented fields kept, validated; DROPPED for a row without a readable id, ft.DROP for a post
    whose text echoes the key."""
    if not isinstance(row, dict):
        return DROPPED
    tweet_id = _tweet_id(row.get("id"))
    if tweet_id is None:
        return DROPPED
    text = ft.clean_text(row.get("text"), key)
    if text is ft.DROP:
        return ft.DROP
    author = row.get("author") if isinstance(row.get("author"), dict) else {}
    lang = row.get("lang") if isinstance(row.get("lang"), str) and LANG_RE.fullmatch(row["lang"]) else None
    return {
        "id": tweet_id, "url": _url(row.get("url"), tweet_id, key), "text": text, "created_at": x_time(row.get("createdAt"), now_ts),
        "likes": _count(row.get("likeCount")), "retweets": _count(row.get("retweetCount")), "replies": _count(row.get("replyCount")),
        "quotes": _count(row.get("quoteCount")), "views": _count(row.get("viewCount")), "bookmarks": _count(row.get("bookmarkCount")),
        "lang": lang, "is_reply": _bool(row.get("isReply")),
        "author": {"user_name": user_name(author.get("userName"), key), "name": fa.safe_label(author.get("name"), key),
                   "followers": _count(author.get("followers")), "blue_verified": _bool(author.get("isBlueVerified")),
                   "verified": _bool(author.get("isVerified")), "created_at": x_time(author.get("createdAt"), now_ts)},
        "queries": [],
    }


def parse_search(payload: Any, query: str, key: str | None, now_ts: float) -> dict[str, Any]:
    """One advanced-search answer, field names as in the cached docs: {query, tweet_count, has_more, next_cursor, tweets:
    [{id, url, text, retweetCount, replyCount, likeCount, quoteCount, viewCount, bookmarkCount, createdAt, lang, isReply,
    author: {userName, name, followers, isBlueVerified, isVerified, createdAt}, ...}]}. next_cursor is never kept or used.
    Loud guards: not an object (invalid_shape), no tweet list (tweet_list_missing), rows of which none has a text field
    (text_field_missing), an answer echoing another query (query_mismatch)."""
    if not isinstance(payload, dict):
        return {"status": "failed", "reason": "invalid_shape"}
    if isinstance(payload.get("query"), str) and payload["query"] != query:
        return {"status": "failed", "reason": "query_mismatch"}
    rows = payload.get("tweets")
    if not isinstance(rows, list):
        return {"status": "failed", "reason": "tweet_list_missing"}
    if rows and not any(isinstance(r, dict) and "text" in r for r in rows[:ROWS_PER_PAGE]):
        return {"status": "failed", "reason": "text_field_missing"}
    kept, dropped, echoed = [], max(0, len(rows) - ROWS_PER_PAGE), 0
    for row in rows[:ROWS_PER_PAGE]:
        post = parse_tweet(row, key, now_ts)
        if post is DROPPED:
            dropped += 1
        elif post is ft.DROP:
            echoed += 1
        else:
            kept.append(post)
    return {"status": "ok", "reason": None, "tweet_count": _count(payload.get("tweet_count")),
            "has_more": _bool(payload.get("has_more")), "posts": kept, "rows_dropped": dropped, "rows_dropped_key_echo": echoed}


# ----------------------------------------------------------------------------- collect


def _base(mint: str, fetched_at: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "collector": "x_search", "provider": "GetXAPI", "mint": mint, "status": "unavailable", "reason": None,
        "fetched_at": fetched_at,
        "request": {"method": "GET", "host": HOST, "path": SEARCH_PATH, "params": "q and product (Latest or Top) only; never a cursor",
                    "auth_header_names": list(fa.AUTH_HEADER_NAMES), "auth_scheme": "Bearer", "max_calls": MAX_CALLS, "pages_per_query": 1,
                    "usd_per_call": USD_PER_CALL, "max_usd": MAX_USD, "pace_s": PACE_S, "calls_sent": 0},
        "docs": "provider-docs current/getxapi.md (Advanced Search: GET /twitter/tweet/advanced_search); current/dexscreener.md (pools of a token)",
        "dexscreener": {"host": cf.DEX_HOST, "path": f"{cf.DEX_PATH_PREFIX}<MINT>", "cost": "free", "status": "not_sent", "reason": None,
                        "http_status": None, "requests_sent": 0, "pairs_seen": None, "first_pair_at": None},
        "symbol": None, "symbol_source": None, "ticker_skip_reason": None,
        "calls": [], "getxapi_calls": 0, "spend_usd": 0.0,
        "queries": [], "posts": [], "rows_dropped": 0, "rows_dropped_key_echo": 0, "rug_words": list(RUG_WORDS),
        "untrusted_text": True, "presentation_only": True, "note": PRESENTATION_NOTE, "cannot_see": CANNOT_SEE,
    }


def collect_x_search(
    mint: str,
    key: str | None,
    *,
    key_reason: str | None = None,
    opener: Any | None = None,
    now: Callable[[], float] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """One Dexscreener lookup, then at most 4 GetXAPI searches (one page each). Returns the x_search.json result; never
    raises for provider or transport failures; without a key it sends nothing. Reads no file of the run folder."""
    now, monotonic, sleep = now or time.time, monotonic or time.monotonic, sleep or time.sleep
    result = _base(mint, fa._iso(now()))
    if not key:
        result["reason"] = f"{KEY_NAME} not set" if key_reason in (None, "missing_key") else key_reason
        return result
    opener = opener or fa.default_opener()
    dex = cf.fetch_json(lambda: cf.dex_request(mint), opener, monotonic=monotonic, sleep=sleep)
    result["dexscreener"].update(requests_sent=dex["attempts"], http_status=dex["http_status"])
    if dex["reason"] is not None:
        result["dexscreener"].update(status="unavailable", reason=dex["reason"])
        symbol, why = None, "symbol_not_read"
    else:
        pairs = read_pairs(dex["body"], mint, key, now())
        symbol, why = pairs["symbol"], pairs["reason"]
        result["dexscreener"].update(status="ok", pairs_seen=pairs["pairs_seen"], first_pair_at=pairs["first_pair_at"], reason=why)
        why = None if symbol else ("symbol_not_read" if why in ("no_pairs", "mint_not_in_pairs", "invalid_shape") else why)
    skip = ticker_skip(symbol, why)
    result.update(symbol=symbol, symbol_source="dexscreener" if symbol else None, ticker_skip_reason=skip)
    posts: dict[str, dict[str, Any]] = {}
    stop: str | None = None
    started: float | None = None
    for tag, kind, template, product in QUERY_PLAN:
        query = template.format(mint=mint, symbol=symbol or "")
        entry: dict[str, Any] = {"tag": tag, "kind": kind, "q": query if kind == "mint" or not skip else None, "product": product,
                                 "status": None, "reason": None, "tweet_count": None, "has_more": None, "posts_read": 0}
        result["queries"].append(entry)
        if kind == "ticker" and skip:
            entry.update(status="skipped", reason=skip)
            continue
        if stop is not None or len(result["calls"]) >= MAX_CALLS:
            entry.update(status="not_sent", reason=stop or "call_cap")
            continue
        if started is not None:
            wait = PACE_S - (monotonic() - started)
            if wait > 0:
                sleep(wait)
        tap, at = Tap(opener), now()
        started = monotonic()
        body, reason, status_code = None, None, None
        try:
            body = fa.send_once(build_request(query, product, key), tap, mint, monotonic=monotonic,
                                check=lambda url, p=search_params(query, product): check_search_url(url, p))
            status_code = 200
        except fa.Failure as exc:
            reason, status_code = exc.reason, exc.http_status
        except Exception:  # noqa: BLE001 - defensive: no exception text leaves this function
            reason = "request_failed"
        got: dict[str, Any] = {"status": "failed", "reason": reason}
        if reason is None:
            payload = fa._decode(body)
            try:
                got = parse_search(payload, query, key, now()) if payload is not None else {"status": "failed", "reason": "invalid_json"}
            except Exception:  # noqa: BLE001 - a malformed answer the guards did not foresee: a fixed code, the call still counted
                got = {"status": "failed", "reason": "parse_error"}
        if tap.opened:
            result["calls"].append({"tag": tag, "q": query, "product": product, "at": fa._iso(at), "http_status": status_code,
                                    "status": "ok" if got["status"] == "ok" else got["reason"], "tweets_returned": len(got.get("posts") or [])})
        entry.update(status=got["status"], reason=got["reason"], tweet_count=got.get("tweet_count"), has_more=got.get("has_more"),
                     posts_read=len(got.get("posts") or []))
        result["rows_dropped"] += got.get("rows_dropped", 0)
        result["rows_dropped_key_echo"] += got.get("rows_dropped_key_echo", 0)
        for post in got.get("posts") or []:
            kept = posts.setdefault(post["id"], post)
            if tag not in kept["queries"]:
                kept["queries"].append(tag)
        if got["status"] != "ok" and got["reason"] in STOP_REASONS:
            stop = got["reason"]
    sent = len(result["calls"])
    answered = [q for q in result["queries"] if q["status"] == "ok"]
    failed = [q for q in result["queries"] if q["status"] in ("failed", "not_sent")]
    result["request"]["calls_sent"] = sent
    result.update(fetched_at=fa._iso(now()), getxapi_calls=sent, spend_usd=round(sent * USD_PER_CALL, 3), posts=list(posts.values()))
    if not answered:
        result.update(status="unavailable", reason=failed[0]["reason"] if failed else "no_query_answered")
    elif failed:
        result.update(status="partial", reason=failed[0]["reason"])
    else:
        result.update(status="ok", reason=None)
    return result


def _spend(result: dict[str, Any]) -> str:
    sent = result["getxapi_calls"]
    return f"{sent} GetXAPI call{'s' if sent != 1 else ''}, ${result['spend_usd']:.3f}" if sent else "no GetXAPI call sent"


def status_line(result: dict[str, Any]) -> str:
    symbol = f"; symbol ${result['symbol']}" if result.get("symbol") else ""
    if result["status"] in ("ok", "partial"):
        reason = f"{result['reason']}; " if result["status"] == "partial" else ""
        answered = sum(1 for q in result["queries"] if q["status"] == "ok")
        return (f"{result['status']} ({reason}{len(result['posts'])} posts from {answered} "
                f"quer{'y' if answered == 1 else 'ies'}; {_spend(result)}{pw.neutral(symbol)})")
    return f"{result['status']} ({result['reason']}; {_spend(result)})"


# ----------------------------------------------------------------------------- presentation (synthesis, offline)


SUMMARY_MARK = mp.SUMMARY_MARK   # "[for the executive summary] ", the same text as meteora_pools, exit_overhang, fomo_theses
LINE_HEAD = "X chatter (presentation only)"
NOT_READ_HEAD = "X chatter"
TITLE = "X posts (GetXAPI; untrusted text, quoted; presentation only)"
TOP_POSTS = 5
TOP_TICKER = 2                   # ticker-only posts listed after the posts naming the contract address, labelled (ticker post)
SYMBOL_STRIP = re.compile(r"[^A-Za-z0-9]")
REASON_WORDS = {
    "credits_exhausted": "credits_exhausted: GetXAPI credit balance exhausted, HTTP 402",
    "authentication_failed": "authentication_failed: GetXAPI refused the key, HTTP 401",
    "rate_limited": "rate_limited: HTTP 429, not retried (at most 4 calls a scan)",
}
SKIP_WORDS = {
    "symbol_not_read": "symbol not read",
    "symbol_not_plain": "the symbol is not plain letters and digits",
    "symbol_ambiguous": "Dexscreener lists more than one symbol",
    "symbol_withheld": "symbol withheld",
    "symbol_too_short": "shorter than 3 characters",
    "symbol_is_a_number": "only digits: reads as a dollar amount",
    "common_word": "a common word or a major coin's ticker",
}
LABELS = {"mint_latest": "mint (Latest)", "mint_top": "mint (Top)", "ticker_latest": "{sym} (Latest, no retweets)",
          "ticker_top": "{sym} (Top, no retweets, 5+ likes)"}


def _reason(value: Any) -> str:
    return ft._reason(value)


def _symbol(data: dict[str, Any]) -> str | None:
    """The saved symbol as "$SYMBOL", plain letters and digits only, verdict words replaced; None when not read."""
    value = data.get("symbol")
    if not isinstance(value, str) or not SYMBOL_RE.fullmatch(value):
        return None
    return "$" + pw.label(value, SYMBOL_STRIP, 20)


def _load(run: Path) -> dict[str, Any]:
    path = run / OUT_FILE
    if not path.exists():
        raise ft.NotRead(f"{OUT_FILE} missing; the x_search collector did not run")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        raise ft.NotRead(f"{OUT_FILE} unreadable") from None
    if not (isinstance(data, dict) and data.get("schema") == SCHEMA and data.get("status") in STATUSES and data.get("presentation_only") is True
            and isinstance(data.get("mint"), str) and fa.SOLANA_ADDRESS_RE.fullmatch(data["mint"]) and mp._parse_time(data.get("fetched_at")) is not None
            and isinstance(data.get("request"), dict) and isinstance(data.get("posts"), list) and isinstance(data.get("queries"), list)):
        raise ft.NotRead(f"{OUT_FILE} unreadable")
    return data


def _posts(data: dict[str, Any]) -> list[dict[str, Any]]:
    """The saved posts, every value validated and the text and labels cleaned again (a damaged row is skipped, a damaged
    value is None)."""
    rows = []
    for p in data["posts"]:
        if not isinstance(p, dict):
            continue
        text = ft.clean_text(p.get("text"))
        author = p.get("author") if isinstance(p.get("author"), dict) else {}
        tweet_id = _tweet_id(p.get("id"))
        rows.append({"id": tweet_id, "url": _url(p.get("url"), tweet_id, None) if tweet_id else None, "text": text if isinstance(text, str) else None,
                     "ts": mp._parse_time(p.get("created_at")), "likes": _count(p.get("likes")), "retweets": _count(p.get("retweets")),
                     "replies": _count(p.get("replies")), "views": _count(p.get("views")),
                     "user": user_name(author.get("user_name")),
                     "followers": _count(author.get("followers")), "blue": author.get("blue_verified") is True, "verified": author.get("verified") is True,
                     "queries": [q for q in p.get("queries") or [] if q in LABELS] if isinstance(p.get("queries"), list) else []})
    return rows


def names_mint(r: dict[str, Any], mint: str) -> bool:
    """A post naming the contract address: one the mint searches found (X matched the address), or one whose text shows it."""
    return any(q.startswith("mint") for q in r["queries"]) or (isinstance(r["text"], str) and mint in r["text"])


def on_topic(data: dict[str, Any], rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int, int]:
    """(posts counted, ticker-search posts set aside because the text does not show "$SYMBOL", set aside because they are
    older than an hour before the token's first Dexscreener pool). A post the mint searches found always counts: it names
    the mint. X ignores the "$" inside the quoted ticker search, so a ticker-search post counts only when its text shows
    the cashtag itself (any case, a whole word) and it is not older than the token's first pool (when both times are read)."""
    symbol = data.get("symbol") if isinstance(data.get("symbol"), str) and SYMBOL_RE.fullmatch(data["symbol"]) else None
    cashtag = re.compile(r"(?<![A-Za-z0-9$])\$" + re.escape(symbol) + r"(?![A-Za-z0-9])", re.IGNORECASE) if symbol else None
    first = mp._parse_time(ft._dict(data.get("dexscreener")).get("first_pair_at"))
    kept, no_tag, old = [], 0, 0
    for r in rows:
        if any(q.startswith("mint") for q in r["queries"]):
            kept.append(r)
        elif not (cashtag and r["text"] and cashtag.search(r["text"])):
            no_tag += 1
        elif first is not None and r["ts"] is not None and r["ts"] < first - POOL_MARGIN_S:
            old += 1
        else:
            kept.append(r)
    return kept, no_tag, old


def rug_words(text: str | None) -> list[str]:
    """The fixed-list rug words in a cleaned text, lower case, in list order (each once)."""
    if not text:
        return []
    found = {m.group(1).lower() for m in RUG_RE.finditer(text)}
    return [w for w in RUG_WORDS if w in found]


def _n(value: int | None, one: str, many: str) -> str:
    return f"{value:,} {one if value == 1 else many}" if value is not None else f"{many} not read"


def _who(r: dict[str, Any]) -> str:
    marks = [m for m, on in (("verified", r["verified"]), ("blue check", r["blue"])) if on]
    counts = f" ({', '.join([_n(r['followers'], 'follower', 'followers'), *marks])})"
    return (f"@{r['user']}" if r["user"] else "name not read") + counts + (" (ticker post)" if r.get("ticker_only") else "")


def _link(r: dict[str, Any]) -> str:
    """The post's link outside the quotes; a user name with a verdict word in it is left out of the link (X's
    /i/web/status/<id> form opens the same post)."""
    if not r["url"]:
        return "link not read"
    _, replaced = pw.neutralize(r["url"])
    return re.sub(r"/[A-Za-z0-9_]{1,15}/status/", "/i/web/status/", r["url"]) if replaced else r["url"]


def _post_line(r: dict[str, Any], scan: float, extra: str = "") -> str:
    quoted = f"\"{r['text']}\"" if r["text"] else "(no readable text)"
    counts = ", ".join([_n(r["likes"], "like", "likes"), _n(r["retweets"], "retweet", "retweets"), _n(r["replies"], "reply", "replies"),
                        _n(r["views"], "view", "views"), ft._age(r["ts"], scan)])
    return f"{_who(r)} — {counts}{extra} — {quoted} — {_link(r)}"


def _total(values: list[int], n: int, what: str) -> str:
    """A total of X's counts: exact when every post's count was read, "at least" when only some were, "not read" when none."""
    if not values:
        return f"{what} not read"
    return f"{'at least ' if len(values) < n else ''}{sum(values):,} {what}"


def _per_account(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each account's most-liked post (it stands for the account in the biggest-accounts list); a post without a readable
    name stands alone."""
    seen: dict[str, dict[str, Any]] = {}
    for i, r in enumerate(rows):
        best = seen.get(_account(r, i))
        if best is None or (r["likes"] if r["likes"] is not None else -1) > (best["likes"] if best["likes"] is not None else -1):
            seen[_account(r, i)] = r
    return list(seen.values())


def _account(r: dict[str, Any], i: int) -> str:
    return r["user"].lower() if r["user"] else f"#{i}"


def _by(rows: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    """Largest first (an unread value last); ties keep the saved order."""
    return sorted(rows, key=lambda r: -(r[field] if r[field] is not None else -1))


def _scope(data: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    """"mint <m>, $SYMBOL <s>": posts found by the mint and by the ticker searches, or why one was not read."""
    queries = {q.get("tag"): q for q in data["queries"] if isinstance(q, dict)}
    parts = []
    for kind, head in (("mint", "mint"), ("ticker", _symbol(data))):
        tags = [t for t in LABELS if t.startswith(kind)]
        states = [queries.get(t, {}).get("status") for t in tags]
        if "ok" in states:
            parts.append(f"{head or 'ticker'} {sum(1 for r in rows if set(r['queries']) & set(tags))}")
        elif kind == "ticker" and "skipped" in states:
            why = SKIP_WORDS.get(queries[tags[0]].get("reason"), "not searched")
            parts.append(f"{head} not searched ({why})" if head else f"ticker not searched ({why})")
        else:
            parts.append(f"{head or 'ticker'} not read")
    return ", ".join(parts)


def _biggest(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    known = [r for r in rows if r["followers"] is not None]
    return _by(known, "followers")[0] if known else None


def _account_text(r: dict[str, Any]) -> str:
    return f"@{r['user']} ({r['followers']:,} followers)" if r["user"] else f"name not read ({r['followers']:,} followers)"


def biggest_text(rows: list[dict[str, Any]]) -> str:
    """The line's biggest account, taken ONLY from posts naming the contract address (AMENDMENT A2): a ticker-only post may
    be about something else. Without such a post the line says so and may name the biggest ticker-post account, labelled."""
    mint_rows = [r for r in rows if not r.get("ticker_only")]
    if mint_rows:
        top = _biggest(mint_rows)
        if top is None:
            return "biggest account not read"
        return f"biggest account {_account_text(top)}" if top["user"] else f"biggest account: {_account_text(top)}"
    top = _biggest(rows)
    return ("biggest account: none among posts naming the contract address"
            + (f"; biggest ticker-post account {_account_text(top)} (ticker post; may be about something else)" if top else ""))


def summary_line(data: dict[str, Any], rows: list[dict[str, Any]], scan: float) -> str:
    """"first seen", like the biggest account, comes ONLY from posts naming the contract address (DS-X-FIRSTSEEN-T1): an
    older ticker-only post may be about something else. Without such a post the line says so and may give the first
    ticker post's age, labelled."""
    flag = f"partial: {_reason(data.get('reason'))}; " if data["status"] == "partial" else ""
    scope = _scope(data, rows)
    if not rows:
        return f"{LINE_HEAD}: 0 posts found ({flag}{scope}; a search window, not proof nobody is talking)."
    accounts = len({_account(r, i) for i, r in enumerate(rows)})
    mint_rows = [r for r in rows if not r.get("ticker_only")]
    times = [r["ts"] for r in (mint_rows or rows) if r["ts"] is not None]
    if mint_rows:
        first = f"first seen {ft._age(min(times), scan)}" if times else "first seen: time not read"
    else:
        first = ("first seen: none among posts naming the contract address"
                 + (f"; first ticker post {ft._age(min(times), scan)} (ticker post; may be about something else)" if times else ""))
    big = biggest_text(rows)
    rug = sum(1 for r in rows if rug_words(r["text"]))
    return (f"{LINE_HEAD}: {ft._plural(len(rows), 'post', 'posts')} from {ft._plural(accounts, 'account', 'accounts')} in the read window "
            f"({flag}{scope}); {first}; {big}; rug/scam/dump words in {ft._plural(rug, 'post', 'posts')}.")


def _queries_line(data: dict[str, Any], scan: float) -> str:
    sym = _symbol(data) or "ticker"
    parts = []
    for q in data["queries"]:
        if not isinstance(q, dict) or q.get("tag") not in LABELS:
            continue
        label = LABELS[q["tag"]].format(sym=sym)
        if q.get("status") == "ok":
            n = ft._int(q.get("posts_read"))
            parts.append(f"{label}: {ft._plural(n, 'post', 'posts') if n is not None else 'posts not read'}" + (", X has more" if q.get("has_more") is True else ""))
        elif q.get("status") == "skipped":
            parts.append(f"{label}: not searched ({SKIP_WORDS.get(q.get('reason'), 'not searched')})")
        elif q.get("status") == "not_sent":
            parts.append(f"{label}: not sent ({_reason(q.get('reason'))})")
        else:
            parts.append(f"{label}: not read ({_reason(q.get('reason'))})")
    return f"  queries (one page each, never a second page; read {mp._when(scan)}): " + "; ".join(parts)


def _spend_line(data: dict[str, Any]) -> str:
    sent = ft._int(data.get("getxapi_calls"))
    usd = ft._num(data.get("spend_usd"), 0.0, 1.0)
    if sent == 0:
        spend = "no GetXAPI call sent ($0)"
    elif sent is not None and usd is not None:
        spend = f"{ft._plural(sent, 'GetXAPI call', 'GetXAPI calls')} = ${usd:.3f}"
    else:
        spend = "GetXAPI calls not read"
    dex = ft._dict(data.get("dexscreener"))
    dex_calls = ft._int(dex.get("requests_sent"))
    sym = _symbol(data)
    if sym:
        source = f"symbol {sym} read from Dexscreener's pair list"
    elif dex.get("status") == "not_sent":
        source = "symbol not looked up"
    else:
        source = f"symbol not read ({SKIP_WORDS.get(data.get('ticker_skip_reason'), 'not read')}; Dexscreener: {_reason(dex.get('reason') or dex.get('status'))})"
    calls = f" ({ft._plural(dex_calls, 'free call', 'free calls')})" if dex_calls else ""
    return f"  spend: {spend} (cap {MAX_CALLS} calls = ${MAX_USD:.3f} a scan; ${USD_PER_CALL:.3f} a call, GetXAPI's price list); {source}{calls}"


def measure_and_print(run: Path) -> list[str]:
    try:
        data = _load(run)
    except ft.NotRead as why:
        return [f"{SUMMARY_MARK}{NOT_READ_HEAD}: not read ({why})", f"{TITLE}: not read ({why})"]
    scan = mp._parse_time(data["fetched_at"])
    if data["status"] == "unavailable":
        reason = data.get("reason")
        why = REASON_WORDS.get(reason) or _reason(reason)
        return [f"{SUMMARY_MARK}{NOT_READ_HEAD}: not read ({why})", f"{TITLE}: not read ({why})", _spend_line(data)]
    rows, no_tag, old = on_topic(data, _posts(data))
    for r in rows:
        r["ticker_only"] = not names_mint(r, data["mint"])
    lines = [f"{SUMMARY_MARK}{summary_line(data, rows, scan)}", TITLE, _queries_line(data, scan), _spend_line(data)]
    if no_tag or old:
        first = mp._parse_time(ft._dict(data.get("dexscreener")).get("first_pair_at"))
        why = [f"{no_tag} without {_symbol(data) or 'the cashtag'} in the text (X matched the word alone)" if no_tag else "",
               f"{old} older than an hour before the token's first Dexscreener pool ({mp._when(first)})" if old and first is not None else ""]
        lines.append(f"  set aside: {ft._plural(no_tag + old, 'ticker-search post', 'ticker-search posts')} not about this token: "
                     + "; ".join(w for w in why if w) + "; not counted and not shown below (the saved file keeps them)")
    if data["status"] == "partial":
        lines.append(f"  partial: {REASON_WORDS.get(data.get('reason')) or _reason(data.get('reason'))}; the posts below are what the answered searches gave")
    dropped = (ft._int(data.get("rows_dropped")) or 0) + (ft._int(data.get("rows_dropped_key_echo")) or 0)
    if dropped:
        lines.append(f"  {ft._plural(dropped, 'post', 'posts')} not shown (malformed, or text sharing a piece of the key)")
    if not rows:
        lines.append("  posts: none found (a search window, not proof nobody is talking)")
    else:
        accounts = len({_account(r, i) for i, r in enumerate(rows)})
        likes, views = [r["likes"] for r in rows if r["likes"] is not None], [r["views"] for r in rows if r["views"] is not None]
        times = [r["ts"] for r in rows if r["ts"] is not None]
        unread = sum(1 for r in rows if r["likes"] is None or r["views"] is None)
        lines.append(f"  counts: {ft._plural(len(rows), 'post', 'posts')} (a post found by several searches counted once), "
                     f"{ft._plural(accounts, 'account', 'accounts')}; {_total(likes, len(rows), 'likes')} and {_total(views, len(rows), 'views')} in total (X's numbers"
                     + (f"; likes or views not read on {ft._plural(unread, 'post', 'posts')}" if unread else "") + "); "
                     + (f"oldest post {mp._when(min(times))}, newest {mp._when(max(times))}" if times else "post times not read"))
        mint_rows, ticker_rows = [r for r in rows if not r["ticker_only"]], [r for r in rows if r["ticker_only"]]
        big_mint, big_ticker = _by(_per_account(mint_rows), "followers"), _by(_per_account(ticker_rows), "followers")
        big_mint, big_ticker = [r for r in big_mint if r["followers"] is not None], [r for r in big_ticker if r["followers"] is not None]
        lines.append(f"  biggest accounts (X's numbers; each with its most-liked post read): the top {min(TOP_POSTS, len(big_mint))} by followers among posts "
                     f"naming the contract address" + (f", then the top {min(TOP_TICKER, len(big_ticker))} ticker posts (may be about something else)" if big_ticker else "") + ":")
        lines += [f"    {_post_line(r, scan)}" for r in big_mint[:TOP_POSTS] + big_ticker[:TOP_TICKER]] or ["    followers not read"]
        liked_mint, liked_ticker = _by(mint_rows, "likes")[:TOP_POSTS], _by(ticker_rows, "likes")[:TOP_TICKER]
        lines.append(f"  most liked: the top {len(liked_mint)} among posts naming the contract address"
                     + (f", then the top {len(liked_ticker)} ticker posts (may be about something else)" if liked_ticker else "") + ":")
        lines += [f"    {_post_line(r, scan)}" for r in liked_mint + liked_ticker]
        rug = [r for r in rows if rug_words(r["text"])]
        lines.append(f"  rug/scam/dump words (a fixed list: rug, scam, honeypot, dump, jeet, exit, sold and their forms; whole words, any case): "
                     f"in {ft._plural(len(rug), 'post', 'posts')} of {len(rows)}" + (f"; the first {TOP_POSTS} shown" if len(rug) > TOP_POSTS else "")
                     + ("" if rug else " (a word list, not proof nobody is worried)"))
        lines += [f"    {_post_line(r, scan, ' — words: ' + ', '.join(rug_words(r['text'])))}" for r in rug[:TOP_POSTS]]
    lines += [f"  cannot see: {CANNOT_SEE}", f"  {PRESENTATION_NOTE}"]
    removed = pw.count(lines)
    if removed:  # HS-LABELS-T1: say how many placeholders this block shows
        lines.append(f"  {pw.removed_line(removed)}")
    return lines


def present(run: Path) -> list[str]:
    """The X chatter line (marked) and the block, offline (no network, no key). A missing, foreign or malformed file reads as
    not read, never as a crash and never as "nobody is talking"."""
    try:
        return measure_and_print(run)
    except Exception:  # noqa: BLE001 - a damaged file never crashes the synthesis; it reads as not read
        return [f"{SUMMARY_MARK}{NOT_READ_HEAD}: not read (saved values unreadable)", f"{TITLE}: not read (saved values unreadable)"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read what X posts say about a Solana mint through GetXAPI (at most 4 advanced searches a scan, "
                                                 "one page each, $0.001 a call: the mint Latest and Top, and \"$SYMBOL\" Latest and Top with the "
                                                 "symbol from one free Dexscreener lookup; bounded: 2 MiB, 30 s, no redirects, no env proxy, no "
                                                 f"retry) and save {OUT_FILE}; or, with --present RUN_DIR, print the X chatter line and the posts "
                                                 "block offline. Post text is untrusted data. Presentation only: never an engine input.")
    parser.add_argument("mint", nargs="?")
    parser.add_argument("--out", metavar="RUN_DIR", help="run folder to write x_search.json into (no other file of it is read)")
    parser.add_argument("--env-file", metavar="PATH", help=f"the repository .env ({KEY_NAME} in the environment is used first)")
    parser.add_argument("--present", metavar="RUN_DIR", help="offline: print the line and the block from a saved run folder (no network, no key)")
    args = parser.parse_args(argv)
    if args.present is not None:
        if args.mint or args.out or args.env_file:
            print("error: --present takes only the run folder", file=sys.stderr)
            return 2
        run = Path(args.present)
        if not run.is_dir():
            print("error: --present is not a run folder", file=sys.stderr)
            return 2
        for line in present(run):
            print(line)
        return 0
    if not isinstance(args.mint, str) or not fa.SOLANA_ADDRESS_RE.fullmatch(args.mint):
        print("error: mint is not a valid base58 Solana address", file=sys.stderr)
        return 2
    if not args.out:
        print("error: --out is required", file=sys.stderr)
        return 2
    run = Path(args.out)
    try:
        run.mkdir(parents=True, exist_ok=True)
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    key: str | None = None
    try:
        key, reason = load_key(None if os.environ.get(KEY_NAME, "").strip() else fa.find_env_file(args.env_file))
        result = collect_x_search(args.mint, key, key_reason=reason)
    except Exception:  # noqa: BLE001 - never print a traceback (it could carry request details)
        result = _base(args.mint, fa._iso(time.time()))
        result["reason"] = "request_failed"
    text = json.dumps(result, indent=1)
    if fa.echoes_key(text, key):  # backstop: every kept value is already checked
        result = _base(args.mint, result["fetched_at"])
        result["reason"] = "key_echo_withheld"
        text = json.dumps(result, indent=1)
    try:
        (run / OUT_FILE).write_text(text, encoding="utf-8")
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    print(status_line(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
