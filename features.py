import re
import numpy as np
from urllib.parse import urlparse

URL_RE = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', re.IGNORECASE)
EMAIL_DOMAIN_RE = re.compile(r'@([A-Za-z0-9\.\-]+\.[A-Za-z]{2,})')

HTML_TAG_RE = re.compile(r"<[^>]+>")

# English + a few common Nepal-ish spellings/phrases (extend later)
URGENT_WORDS = [
    "urgent", "immediately", "act now", "action required", "verify now",
    "suspended", "locked", "final notice", "last chance", "within 24 hours"
]

SENSITIVE_WORDS = [
    "password", "otp", "verification code", "one-time password", "pin",
    "credit card", "cvv", "ssn", "social security", "bank password", "mpin"
]

PHISH_ACTION_WORDS = [
    "login", "sign in", "verify", "confirm", "update", "reset", "validate"
]

UNSUB_WORDS = [
    "unsubscribe", "manage preferences", "email preferences", "opt out"
]

# Nepali-ish cues (light; keep minimal to avoid bias)
NEPALI_SENSITIVE = [
    "otp", "पासवर्ड", "पिन", "mpin", "verification", "verify"
]


def extract_domain(sender_email: str) -> str:
    if not sender_email:
        return ""
    m = EMAIL_DOMAIN_RE.search(sender_email)
    return m.group(1).lower() if m else ""


def contains_any(text: str, words) -> int:
    t = (text or "").lower()
    return int(any(w in t for w in words))


def normalize_text(s: str) -> str:
    if not s:
        return ""
    s = s.replace("\r", " ").replace("\n", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def url_features(urls):
    """
    Extract strong URL-based signals without overfitting.
    """
    domains = []
    has_ip_url = 0
    has_at_symbol = 0
    has_url_shortener = 0
    insecure_http = 0
    long_url = 0

    shorteners = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "rebrand.ly", "cutt.ly")

    for u in urls:
        uu = u
        if uu.lower().startswith("www."):
            uu = "http://" + uu

        if "@" in uu:
            has_at_symbol = 1

        try:
            p = urlparse(uu)
            host = (p.hostname or "").lower()
            domains.append(host)

            if host in shorteners:
                has_url_shortener = 1

            if p.scheme == "http":
                insecure_http = 1

            # crude IP-in-host detection
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or ""):
                has_ip_url = 1

            if len(uu) >= 80:
                long_url = 1
        except Exception:
            continue

    uniq_domains = sorted(set([d for d in domains if d]))
    return {
        "url_unique_domains": len(uniq_domains),
        "has_ip_url": has_ip_url,
        "has_at_symbol_url": has_at_symbol,
        "has_url_shortener": has_url_shortener,
        "has_insecure_http": insecure_http,
        "has_long_url": long_url,
    }


def extract_features(payload: dict) -> dict:
    subject = normalize_text(payload.get("subject") or "")
    body = payload.get("body") or ""
    sender_email = normalize_text(payload.get("sender_email") or payload.get("from") or "")

    # strip HTML tags lightly if HTML sneaks in
    if "<html" in body.lower() or "<body" in body.lower():
        body = HTML_TAG_RE.sub(" ", body)
    body = normalize_text(body)

    domain = extract_domain(sender_email)

    urls = URL_RE.findall(body)
    links_count = len(urls)
    links_count_log = float(np.log1p(min(links_count, 60)))
    link_density_log = float(np.log1p(links_count / (len(body) + 1)))

    text_all = f"{subject} {body}".lower()

    uf = url_features(urls)

    feats = {
        # for allowlist/explainability
        "subject": subject,
        "body": body,
        "sender_email": sender_email,
        "sender_domain": domain,

        # minimal numeric signals (avoid newsletter bias)
        "links_count_log": links_count_log,
        "link_density_log": link_density_log,

        # strong phishing cues
        "requests_sensitive_info": contains_any(text_all, SENSITIVE_WORDS) or contains_any(text_all, NEPALI_SENSITIVE),
        "has_urgency_language": contains_any(text_all, URGENT_WORDS),
        "has_phish_action": contains_any(text_all, PHISH_ACTION_WORDS),

        # domain structure risk
        "domain_length": len(domain),
        "digit_count": sum(c.isdigit() for c in domain),
        "hyphen_count": domain.count("-"),

        # legit marker (weak positive)
        "has_unsubscribe": contains_any(body, UNSUB_WORDS),

        # url signals
        "url_unique_domains": uf["url_unique_domains"],
        "has_ip_url": uf["has_ip_url"],
        "has_at_symbol_url": uf["has_at_symbol_url"],
        "has_url_shortener": uf["has_url_shortener"],
        "has_insecure_http": uf["has_insecure_http"],
        "has_long_url": uf["has_long_url"],
    }
    return feats


