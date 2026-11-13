import asyncio
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx
import whois
from rapidfuzz.distance import Levenshtein

from ml.features import is_ip_host, split_host

from .brands import BRANDS, is_official

logging.getLogger("whois").setLevel(logging.CRITICAL)

WHOIS_TIMEOUT = 2.5
SAFE_BROWSING_TIMEOUT = 3.0
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
WHOIS_CACHE_TTL = 3600

_whois_cache = {}
_RAW_CREATED_RE = re.compile(
    r"(?:domain created|creation date|created on|registered on|created)[ .]*:\s*(\d{4}-\d{2}-\d{2})",
    re.IGNORECASE,
)
_LEET =str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


@dataclass
class ReputationResult:
    score: float = 0.0
    reasons: list = field(default_factory=list)
    safe_browsing: bool = False
    timings: dict = field(default_factory=dict)


def _whois_enabled():
    return os.getenv("WHOIS_ENABLED", "1").strip().lower() not in ("0", "false", "no")


def _safe_browsing_key():
    return os.getenv("GOOGLE_SAFE_BROWSING_KEY", "").strip()


def _typo_limit(name):
    return 2 if len(name) >= 6 else 1


def brand_similarity(host):
    sub, sld, suffix = split_host(host)
    if not sld:
        return 0.0, None
    registered = f"{sld}.{suffix}" if suffix else sld
    if is_official(registered):
        return 0.0, None
    name_part = f"{sub}.{sld}" if sub else sld
    for brand in BRANDS:
        for kw in brand.keywords:
            if kw in name_part:
                return 0.9, f"Домен похож на {brand.official[0]}: содержит «{kw}»"
            if kw in name_part.translate(_LEET):
                return 0.9, f"Домен похож на {brand.official[0]} (цифры вместо букв)"
    tokens = [t for t in re.split(r"[-.\d]+", sld.translate(_LEET)) if len(t) >= 4]
    for brand in BRANDS:
        for target in brand.keywords:
            if len(target) < 5:
                continue
            limit = _typo_limit(target)
            for token in tokens:
                if len(target) < 6 and token[0] != target[0]:
                    continue
                if 0 < Levenshtein.distance(token, target) <= limit:
                    return 0.9, f"Домен похож на {brand.official[0]} (возможная подмена букв)"
    return 0.0, None


def _creation_date(data):
    if not hasattr(data, "get"):
        return None
    value = data.get("creation_date")
    if isinstance(value, list):
        value = [v for v in value if isinstance(v, datetime)]
        value = min(value) if value else None
    if not isinstance(value, datetime):
        match = _RAW_CREATED_RE.search(data.get("raw") or "")
        if not match:
            return None
        value = datetime.strptime(match.group(1), "%Y-%m-%d")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def _age_score(days):
    if days < 30:
        return 1.0, f"Домен зарегистрирован {days} дн. назад"
    if days < 180:
        return 0.5, f"Домен зарегистрирован недавно: {days} дн. назад"
    return 0.0, None


async def domain_age(registered):
    now = time.time()
    cached = _whois_cache.get(registered)
    if cached and cached[0] > now:
        created = cached[1]
    else:
        try:
            data = await asyncio.wait_for(
                asyncio.to_thread(whois.whois, registered, quiet=True, timeout=2, inc_raw=True),
                timeout=WHOIS_TIMEOUT,
            )
            created = _creation_date(data)
        except Exception:
            created = None
        if created is not None:
            _whois_cache[registered] = (now + WHOIS_CACHE_TTL, created)
    if created is None:
        return 0.3, "Не удалось получить WHOIS"
    days = max(0, (datetime.now(timezone.utc) - created).days)
    return _age_score(days)


async def safe_browsing(url, key):
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=SAFE_BROWSING_TIMEOUT) as client:
            response = await client.post(SAFE_BROWSING_URL, params={"key": key}, json=payload)
            response.raise_for_status()
            if response.json().get("matches"):
                return 1.0, "Есть в базе Google Safe Browsing"
    except Exception:
        pass
    return 0.0, None


async def _timed(name, coro, timings):
    start = time.perf_counter()
    try:
        return await coro
    finally:
        timings[name] = round((time.perf_counter() - start) * 1000, 1)


async def check(host, clean_url):
    result = ReputationResult()
    checks = []

    if is_ip_host(host):
        checks.append((0.8, "Сайт открыт по IP-адресу, а не по доменному имени"))
    else:
        start = time.perf_counter()
        checks.append(brand_similarity(host))
        result.timings["brands"] = round((time.perf_counter() - start) * 1000, 1)

    tasks = {}
    _, sld, suffix = split_host(host)
    if _whois_enabled() and sld and suffix:
        tasks["whois"] = _timed("whois", domain_age(f"{sld}.{suffix}"), result.timings)
    key = _safe_browsing_key()
    if key:
        tasks["safe_browsing"] = _timed("safe_browsing", safe_browsing(clean_url, key), result.timings)

    if tasks:
        outcomes = await asyncio.gather(*tasks.values())
        for name, outcome in zip(tasks, outcomes):
            checks.append(outcome)
            if name == "safe_browsing" and outcome[0] >= 1.0:
                result.safe_browsing = True

    result.score = max((s for s, _ in checks), default=0.0)
    result.reasons = sorted(((s, r) for s, r in checks if r), key=lambda x: x[0], reverse=True)
    return result
