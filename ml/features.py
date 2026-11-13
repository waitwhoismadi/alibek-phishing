import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

import pandas as pd
import tldextract

SUSPICIOUS_WORDS = (
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "bank",
    "signin",
    "confirm",
    "password",
    "wallet",
    "support",
)

SUSPICIOUS_TLDS = frozenset(
    {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "link", "work", "rest", "icu"}
)

SHORTENERS = frozenset({"bit.ly", "tinyurl.com", "goo.gl", "t.co", "cutt.ly", "is.gd"})

BRAND_KEYWORDS = (
    "kaspi",
    "halyk",
    "egov",
    "freedombank",
    "jusan",
    "kazpost",
    "google",
    "paypal",
    "apple",
    "microsoft",
    "facebook",
    "instagram",
    "telegram",
)

FEATURE_NAMES = [
    "domain_length",
    "sld_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "digit_ratio",
    "domain_entropy",
    "num_subdomains",
    "longest_label",
    "has_ip",
    "has_at",
    "has_port",
    "is_punycode",
    "suspicious_words",
    "suspicious_tld",
    "is_shortener",
    "brand_in_subdomain",
]

URL_FEATURE_NAMES = [
    "url_length",
    "path_length",
    "num_query_params",
    "is_https",
    "has_double_slash_in_path",
    "url_entropy",
    "num_special",
    "at_in_url",
    "path_suspicious_words",
]

_extract = tldextract.TLDExtract(suffix_list_urls=())
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_NUMERIC_HOST_RE = re.compile(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}")


def _split(url):
    url = (url or "").strip()
    if not _SCHEME_RE.match(url):
        url = "http://" + url
    try:
        return urlsplit(url)
    except ValueError:
        return urlsplit("http://")


def _to_ascii(host):
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def parse_url(url):
    parts = _split(url)
    host = _to_ascii((parts.hostname or "").rstrip(".").lower())
    if host.startswith("www."):
        host = host[4:]
    try:
        port = parts.port
    except ValueError:
        port = -1
    return parts, host, port


def normalize_host(url):
    return parse_url(url)[1]


def _entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _is_ip(host):
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_NUMERIC_HOST_RE.fullmatch(host))


def is_ip_host(host):
    return _is_ip(host)


def split_host(host):
    if _is_ip(host):
        return "", "", ""
    ext = _extract(host)
    return ext.subdomain, ext.domain, ext.suffix


def registered_domain(host):
    _, sld, suffix = split_host(host)
    return f"{sld}.{suffix}" if sld and suffix else sld


def extract_features(url):
    parts, host, port = parse_url(url)
    is_ip = _is_ip(host)
    sub, sld, suffix = split_host(host)
    tld = suffix.rsplit(".", 1)[-1]
    registered = f"{sld}.{suffix}" if sld and suffix else sld
    sub_labels = [p for p in sub.split(".") if p]
    num_digits = sum(ch.isdigit() for ch in host)
    return {
        "domain_length": len(host),
        "sld_length": len(sld),
        "num_dots": host.count("."),
        "num_hyphens": host.count("-"),
        "num_digits": num_digits,
        "digit_ratio": num_digits / len(host) if host else 0.0,
        "domain_entropy": _entropy(host),
        "num_subdomains": len(sub_labels),
        "longest_label": max((len(p) for p in host.split(".")), default=0),
        "has_ip": int(is_ip),
        "has_at": int("@" in parts.netloc),
        "has_port": int(port is not None and port not in (80, 443)),
        "is_punycode": int("xn--" in host),
        "suspicious_words": sum(w in host for w in SUSPICIOUS_WORDS),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "is_shortener": int(registered in SHORTENERS or host in SHORTENERS),
        "brand_in_subdomain": int(any(b in sub and b not in sld for b in BRAND_KEYWORDS)),
    }


def url_features(url):
    parts, _, _ = parse_url(url)
    raw = (url or "").strip()
    tail = (parts.path + "?" + parts.query).lower()
    return {
        "url_length": len(raw),
        "path_length": len(parts.path),
        "num_query_params": len([p for p in parts.query.split("&") if p]),
        "is_https": int(parts.scheme.lower() == "https"),
        "has_double_slash_in_path": int("//" in parts.path),
        "url_entropy": _entropy(raw),
        "num_special": sum(raw.count(c) for c in "@?=&%_~+"),
        "at_in_url": int("@" in raw),
        "path_suspicious_words": sum(w in tail for w in SUSPICIOUS_WORDS),
    }


def extract_features_df(urls, include_url_features=False):
    urls = list(urls)
    df = pd.DataFrame([extract_features(u) for u in urls], columns=FEATURE_NAMES)
    if include_url_features:
        extra = pd.DataFrame([url_features(u) for u in urls], columns=URL_FEATURE_NAMES)
        df = pd.concat([df, extra], axis=1)
    return df
