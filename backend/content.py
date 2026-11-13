from dataclasses import dataclass, field

from .brands import BRANDS, find_brand_in_text, is_official


@dataclass
class ContentResult:
    score: float = 0.0
    reasons: list = field(default_factory=list)


def _brand_from_page(page):
    keyword = (page.get("brand_in_title") or "").strip().lower()
    if keyword:
        for brand in BRANDS:
            if keyword in brand.keywords or keyword == brand.name.lower():
                return brand
        brand = find_brand_in_text(keyword)
        if brand:
            return brand
    return find_brand_in_text(page.get("title"))


def score(page, registered, is_https):
    result = ContentResult()
    total = 0.0
    if page.get("has_password_field") and not is_https:
        total += 0.4
        result.reasons.append((0.8, "Поле пароля на странице без HTTPS"))
    if page.get("form_action_external"):
        total += 0.4
        result.reasons.append((0.85, "Форма отправляет данные на чужой домен"))
    brand = _brand_from_page(page)
    if brand and not is_official(registered, brand):
        total += 0.5
        result.reasons.append(
            (0.85, f"Заголовок страницы упоминает {brand.name}, но домен не официальный")
        )
    result.score = min(total, 1.0)
    return result
