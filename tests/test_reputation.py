import asyncio

import pytest
from fastapi.testclient import TestClient

from backend import content, reputation, scorer
from backend.brands import find_brand_in_text, is_official
from backend.main import app
from backend.whitelist import is_whitelisted


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setenv("WHOIS_ENABLED", "0")
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "")


@pytest.mark.parametrize(
    "host",
    ["kaspi-verify.xyz", "kaspi.com", "login.kaspi.kz.secure-auth.ru", "paypal-support.top", "my-halyk.online"],
)
def test_brand_in_domain(host):
    score, reason = reputation.brand_similarity(host)
    assert score == 0.9
    assert "похож" in reason


@pytest.mark.parametrize("host", ["kaspl.kz", "kaspii.kz", "paypa1.com", "gooogle.com", "micros0ft-login.com", "telegrarn.org"])
def test_typosquatting(host):
    score, _ = reputation.brand_similarity(host)
    assert score == 0.9


@pytest.mark.parametrize(
    "host",
    ["kaspi.kz", "shop.kaspi.kz", "halykbank.kz", "accounts.google.com", "paypal.com", "life.com", "github.com", "enu.kz"],
)
def test_no_false_brand(host):
    assert reputation.brand_similarity(host) == (0.0, None)


def test_age_score():
    assert reputation._age_score(3)[0] == 1.0
    assert "3 дн." in reputation._age_score(3)[1]
    assert reputation._age_score(100)[0] == 0.5
    assert reputation._age_score(1000) == (0.0, None)


def test_whois_raw_kz_date():
    raw = "Domain Name............: kaspi.kz\nDomain created.........: 2007-12-28 09:47:49 (GMT+0:00)\n"
    created = reputation._creation_date({"creation_date": None, "raw": raw})
    assert (created.year, created.month, created.day) == (2007, 12, 28)
    assert reputation._creation_date({"creation_date": None, "raw": "no data"}) is None


def test_check_offline_ip():
    result = asyncio.run(reputation.check("192.168.1.1", "http://192.168.1.1/"))
    assert result.score == 0.8
    assert not result.safe_browsing


def test_check_offline_brand():
    result = asyncio.run(reputation.check("kaspi-login.xyz", "https://kaspi-login.xyz/"))
    assert result.score == 0.9
    assert "whois" not in result.timings


def test_brands_and_whitelist():
    assert is_official("kaspi.kz")
    assert not is_official("kaspi-verify.xyz")
    assert find_brand_in_text("Kaspi.kz — вход").name == "Kaspi"
    assert is_whitelisted("kaspi.kz", "kaspi.kz")
    assert is_whitelisted("mail.google.com", "google.com")
    assert not is_whitelisted("kaspi-verify.xyz", "kaspi-verify.xyz")


def test_content_score():
    page = {"has_password_field": True, "form_action_external": True, "brand_in_title": "kaspi", "title": "Kaspi.kz — вход"}
    result = content.score(page, "kaspi-verify.xyz", is_https=False)
    assert result.score == 1.0
    assert len(result.reasons) == 3
    official = content.score(page, "kaspi.kz", is_https=True)
    assert official.score == pytest.approx(0.4)


def test_scorer_rules():
    rep = reputation.ReputationResult(score=1.0, reasons=[(1.0, "Есть в базе Google Safe Browsing")], safe_browsing=True)
    a = scorer.combine(0.1, [], rep)
    assert a.risk >= 90 and a.verdict == "phishing"
    assert scorer.combine(0.99, [], rep, whitelisted=True).risk == 0
    assert scorer.verdict_for(39) == "safe"
    assert scorer.verdict_for(40) == "suspicious"
    assert scorer.verdict_for(70) == "phishing"


def test_api():
    with TestClient(app) as client:
        assert client.get("/health").json() == {"status": "ok"}

        r = client.post("/check", json={"url": "https://kaspi.kz"}).json()
        assert r["verdict"] == "safe" and r["risk"] == 0

        r = client.post("/check", json={"url": "http://192.168.1.1/login@verify"}).json()
        assert r["risk"] >= 60

        r = client.post("/check", json={"url": "kaspi-login.xyz"}).json()
        assert r["verdict"] == "phishing"
        assert any("kaspi.kz" in reason for reason in r["reasons"])
        assert r["scores"]["content"] is None

        r2 = client.post("/check", json={"url": "kaspi-login.xyz?token=secret"}).json()
        assert r2["cached"] is True

        r = client.post(
            "/check",
            json={"url": "https://kaspi-verify.xyz/login", "page": {"has_password_field": True, "form_action_external": True, "brand_in_title": "kaspi", "title": "Kaspi.kz — вход"}},
        ).json()
        assert r["verdict"] == "phishing" and r["scores"]["content"] == 0.9
        assert len(r["reasons"]) <= 5

        assert client.post("/check", json={"url": "chrome://settings"}).status_code == 400
