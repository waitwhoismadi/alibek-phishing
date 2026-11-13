from ml.features import (
    FEATURE_NAMES,
    URL_FEATURE_NAMES,
    extract_features,
    extract_features_df,
    normalize_host,
    url_features,
)


def test_feature_order():
    assert list(extract_features("kaspi.kz").keys()) == FEATURE_NAMES
    assert list(url_features("kaspi.kz").keys()) == URL_FEATURE_NAMES


def test_ip_host():
    url = "http://192.168.1.1/login@verify"
    f = extract_features(url)
    assert f["has_ip"] == 1
    assert f["num_subdomains"] == 0
    assert f["sld_length"] == 0
    assert url_features(url)["at_in_url"] == 1


def test_ipv6_and_numeric_ip():
    assert extract_features("http://[2001:db8::1]/a")["has_ip"] == 1
    assert extract_features("http://3232235777/")["has_ip"] == 1


def test_at_in_authority():
    url = "http://kaspi.kz@evil-site.xyz/login"
    f = extract_features(url)
    assert normalize_host(url) == "evil-site.xyz"
    assert f["has_at"] == 1
    assert f["suspicious_tld"] == 1


def test_no_scheme_equals_normalized():
    assert normalize_host("kaspi.kz/login") == "kaspi.kz"
    assert extract_features("kaspi.kz") == extract_features("https://www.kaspi.kz/")
    assert extract_features("WWW.Kaspi.KZ.") == extract_features("http://kaspi.kz")


def test_punycode():
    f = extract_features("http://аpple.com/")
    assert f["is_punycode"] == 1
    assert normalize_host("http://аpple.com/").startswith("xn--")
    assert extract_features("https://xn--80ak6aa92e.com")["is_punycode"] == 1


def test_very_long_url():
    url = "https://example.com/" + "a" * 10000 + "?x=1&y=2"
    f = extract_features(url)
    assert f["domain_length"] == len("example.com")
    u = url_features(url)
    assert u["url_length"] > 10000
    assert u["num_query_params"] == 2


def test_port():
    assert extract_features("http://example.com:8080/")["has_port"] == 1
    assert extract_features("https://example.com:443/")["has_port"] == 0
    assert extract_features("http://example.com:99999/")["has_port"] == 1


def test_suspicious_host():
    f = extract_features("https://secure-login.paypal.account-verify.xyz/")
    assert f["suspicious_words"] >= 4
    assert f["brand_in_subdomain"] == 1
    assert f["suspicious_tld"] == 1
    assert f["num_subdomains"] == 2


def test_official_brand_not_flagged():
    f = extract_features("https://www.paypal.com/signin")
    assert f["brand_in_subdomain"] == 0
    assert f["suspicious_words"] == 0


def test_shortener():
    assert extract_features("bit.ly/abc")["is_shortener"] == 1
    assert extract_features("https://google.com")["is_shortener"] == 0


def test_garbage_does_not_raise():
    for url in ["", "   ", "http://[broken", "::::", None]:
        f = extract_features(url)
        assert set(f) == set(FEATURE_NAMES)


def test_batch():
    df = extract_features_df(["a.com", "https://b.org/x"])
    assert df.shape == (2, len(FEATURE_NAMES))
    assert list(df.columns) == FEATURE_NAMES
    df2 = extract_features_df(["a.com"], include_url_features=True)
    assert list(df2.columns) == FEATURE_NAMES + URL_FEATURE_NAMES
