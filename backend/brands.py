from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    name: str
    keywords: tuple
    official: tuple


BRANDS = (
    Brand("Kaspi", ("kaspi", "каспи"), ("kaspi.kz",)),
    Brand("Halyk Bank", ("halykbank", "halyk", "халык"), ("halykbank.kz",)),
    Brand("eGov", ("egov",), ("egov.kz",)),
    Brand("Freedom Bank", ("freedombank", "фридом"), ("freedombank.kz",)),
    Brand("Jusan", ("jusan", "жусан"), ("jusan.kz",)),
    Brand("Kazpost", ("kazpost", "казпочта"), ("kazpost.kz",)),
    Brand("Google", ("google",), ("google.com", "google.kz")),
    Brand("PayPal", ("paypal",), ("paypal.com",)),
    Brand("Apple", ("apple", "icloud"), ("apple.com", "icloud.com")),
    Brand(
        "Microsoft",
        ("microsoft",),
        ("microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com"),
    ),
    Brand("Facebook", ("facebook",), ("facebook.com", "fb.com")),
    Brand("Instagram", ("instagram",), ("instagram.com",)),
    Brand("Telegram", ("telegram",), ("telegram.org", "t.me")),
)

OFFICIAL_DOMAINS = frozenset(d for b in BRANDS for d in b.official)


def is_official(registered, brand=None):
    domains = brand.official if brand else OFFICIAL_DOMAINS
    return registered in domains


def find_brand_in_text(text):
    text = (text or "").lower()
    if not text:
        return None
    for brand in BRANDS:
        if any(kw in text for kw in brand.keywords) or brand.name.lower() in text:
            return brand
    return None
