from dataclasses import dataclass

MAX_REASONS = 5
SAFE_BROWSING_FLOOR = 90


@dataclass
class Assessment:
    risk: int
    verdict: str
    reasons: list


def verdict_for(risk):
    if risk >= 70:
        return "phishing"
    if risk >= 40:
        return "suspicious"
    return "safe"


def combine(ml_score, ml_reasons, reputation, content=None, whitelisted=False):
    if whitelisted:
        return Assessment(0, "safe", ["Домен в белом списке известных сайтов"])

    if content is None:
        raw = 0.6 * ml_score + 0.4 * reputation.score
    else:
        raw = 0.5 * ml_score + 0.3 * reputation.score + 0.2 * content.score
    risk = int(round(100 * raw))
    if reputation.safe_browsing:
        risk = max(risk, SAFE_BROWSING_FLOOR)
    risk = max(0, min(100, risk))

    weighted = list(reputation.reasons)
    if content is not None:
        weighted += content.reasons
    if ml_score >= 0.5 or risk >= 40:
        weighted += [(w * max(ml_score, 0.5), r) for w, r in ml_reasons]

    reasons = []
    for _, text in sorted(weighted, key=lambda x: x[0], reverse=True):
        if text not in reasons:
            reasons.append(text)
        if len(reasons) == MAX_REASONS:
            break
    return Assessment(risk, verdict_for(risk), reasons)
