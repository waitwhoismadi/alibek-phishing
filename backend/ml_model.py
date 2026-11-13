import json
from pathlib import Path

import pandas as pd
from xgboost import XGBClassifier

from ml.features import (
    FEATURE_NAMES,
    SUSPICIOUS_WORDS,
    extract_features,
    parse_url,
    split_host,
    url_features,
)

ML_DIR = Path(__file__).resolve().parent.parent / "ml"

_model = None


def load():
    global _model
    if _model is not None:
        return _model
    names = json.loads((ML_DIR / "feature_names.json").read_text(encoding="utf-8"))
    if names != FEATURE_NAMES:
        raise RuntimeError("feature_names.json не совпадает с ml.features.FEATURE_NAMES")
    model = XGBClassifier()
    model.load_model(ML_DIR / "model.json")
    _model = model
    return _model


def predict(url):
    features = extract_features(url)
    frame = pd.DataFrame([features], columns=FEATURE_NAMES)
    return float(load().predict_proba(frame)[0, 1])


def reasons(url):
    f = extract_features(url)
    u = url_features(url)
    parts, host, _ = parse_url(url)
    _, _, suffix = split_host(host)
    found = []
    if f["has_at"] or u["at_in_url"]:
        found.append((0.7, "Символ @ в адресе страницы"))
    if f["is_punycode"]:
        found.append((0.7, "Домен в punycode: возможна подмена символов"))
    if f["brand_in_subdomain"]:
        found.append((0.7, "Название бренда в поддомене чужого сайта"))
    if f["suspicious_tld"]:
        found.append((0.6, f"Подозрительная доменная зона .{suffix.rsplit('.', 1)[-1]}"))
    text = (host + parts.path).lower()
    words = [w for w in SUSPICIOUS_WORDS if w in text]
    if words:
        found.append((0.55, "Подозрительные слова в URL: " + ", ".join(words[:4])))
    if f["num_subdomains"] >= 3:
        found.append((0.5, f"Много поддоменов: {f['num_subdomains']}"))
    if f["is_shortener"]:
        found.append((0.5, "Сокращённая ссылка скрывает настоящий адрес"))
    if f["has_port"]:
        found.append((0.45, "Нестандартный порт в адресе"))
    if not u["is_https"]:
        found.append((0.4, "Соединение без HTTPS"))
    if f["num_digits"] >= 5:
        found.append((0.35, "Много цифр в имени домена"))
    return sorted(found, key=lambda r: r[0], reverse=True)[:3]
