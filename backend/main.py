import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ml.features import parse_url, registered_domain

from . import content, ml_model, reputation, scorer
from .whitelist import is_whitelisted

CACHE_TTL = 3600
CACHE_MAX = 10000

logger = logging.getLogger("phishguard")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False

_cache = {}


class PageInfo(BaseModel):
    has_password_field: bool = False
    form_action_external: bool = False
    brand_in_title: Optional[str] = Field(default=None, max_length=100)
    title: Optional[str] = Field(default=None, max_length=500)


class CheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=8192)
    page: Optional[PageInfo] = None


class Scores(BaseModel):
    ml: float
    reputation: float
    content: Optional[float]


class CheckResponse(BaseModel):
    url: str
    domain: str
    risk: int
    verdict: str
    scores: Scores
    reasons: list[str]
    cached: bool
    elapsed_ms: int


@asynccontextmanager
async def lifespan(app):
    ml_model.load()
    logger.info("модель загружена")
    yield


app = FastAPI(title="PhishGuard", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(chrome-extension://[a-z]+|https?://(localhost|127\.0\.0\.1)(:\d+)?)$",
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


def _cache_get(key):
    entry = _cache.get(key)
    if entry and entry[0] > time.time():
        return entry[1]
    _cache.pop(key, None)
    return None


def _cache_put(key, value):
    if len(_cache) >= CACHE_MAX:
        now = time.time()
        for k in [k for k, v in _cache.items() if v[0] <= now]:
            del _cache[k]
        while len(_cache) >= CACHE_MAX:
            _cache.pop(next(iter(_cache)))
    _cache[key] = (time.time() + CACHE_TTL, value)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/check", response_model=CheckResponse)
async def check(request: CheckRequest):
    start = time.perf_counter()
    parts, host, _ = parse_url(request.url)
    if parts.scheme.lower() not in ("http", "https") or not host:
        raise HTTPException(status_code=400, detail="Некорректный URL")

    clean_url = f"{parts.scheme.lower()}://{host}{parts.path or '/'}"
    registered = registered_domain(host)
    is_https = parts.scheme.lower() == "https"
    timings = {}

    analysis = _cache_get(clean_url)
    cached = analysis is not None
    if not cached:
        t = time.perf_counter()
        ml_score = ml_model.predict(request.url)
        ml_reasons = ml_model.reasons(request.url)
        timings["ml"] = round((time.perf_counter() - t) * 1000, 1)

        whitelisted = is_whitelisted(host, registered)
        if whitelisted:
            rep = reputation.ReputationResult()
        else:
            t = time.perf_counter()
            rep = await reputation.check(host, clean_url)
            timings["reputation"] = round((time.perf_counter() - t) * 1000, 1)
            timings.update({f"rep.{k}": v for k, v in rep.timings.items()})
        analysis = (ml_score, ml_reasons, rep, whitelisted)
        _cache_put(clean_url, analysis)

    ml_score, ml_reasons, rep, whitelisted = analysis

    page_result = None
    if request.page is not None and not whitelisted:
        t = time.perf_counter()
        page_result = content.score(request.page.model_dump(), registered, is_https)
        timings["content"] = round((time.perf_counter() - t) * 1000, 1)

    assessment = scorer.combine(ml_score, ml_reasons, rep, page_result, whitelisted)
    elapsed = int(round((time.perf_counter() - start) * 1000))

    logger.info(
        "check %s risk=%d verdict=%s cached=%s total=%dms %s",
        clean_url,
        assessment.risk,
        assessment.verdict,
        cached,
        elapsed,
        " ".join(f"{k}={v}ms" for k, v in timings.items()),
    )

    return CheckResponse(
        url=request.url,
        domain=host,
        risk=assessment.risk,
        verdict=assessment.verdict,
        scores=Scores(
            ml=round(ml_score, 2),
            reputation=round(rep.score, 2),
            content=round(page_result.score, 2) if page_result is not None else None,
        ),
        reasons=assessment.reasons,
        cached=cached,
        elapsed_ms=elapsed,
    )
