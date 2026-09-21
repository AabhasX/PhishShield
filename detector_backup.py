import ipaddress
import re
from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"
}

SUSPICIOUS_WORDS = {
    "login", "signin", "verify", "verification", "account",
    "update", "secure", "security", "password", "confirm",
    "bank", "wallet", "billing", "payment", "recover",
    "unlock", "authenticate"
}

def is_ip_address(host):
    if not host:
        return False
    try:
        ipaddress.ip_address(host.split(":")[0])
        return True
    except ValueError:
        return False

def analyze_url(raw_url):
    original = raw_url.strip()
    normalized = original
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", normalized):
        normalized = "http://" + normalized

    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    path_query = f"{parsed.path} {parsed.query}".lower()
    reasons = []
    score = 0

    if parsed.scheme not in {"http", "https"}:
        reasons.append("Unsupported or unusual URL scheme")
        score += 20

    if is_ip_address(host):
        reasons.append("IP address is used instead of a normal domain name")
        score += 25

    if len(original) > 100:
        reasons.append("URL is unusually long")
        score += 10
    elif len(original) > 75:
        reasons.append("URL is longer than typical")
        score += 5

    if "@" in original:
        reasons.append("URL contains '@', which can obscure the real destination")
        score += 20

    if host.startswith("xn--") or ".xn--" in host:
        reasons.append("Punycode/IDN pattern detected in the domain")
        score += 10

    if host.count(".") >= 4:
        reasons.append("Domain contains many subdomain levels")
        score += 10
    elif host.count(".") == 3:
        score += 5

    if host.count("-") >= 3:
        reasons.append("Domain contains many hyphens")
        score += 8

    if len(host) > 40:
        reasons.append("Domain name is unusually long")
        score += 8

    if host in SHORTENERS:
        reasons.append("URL shortening service detected")
        score += 12

    hits = sorted({
        word for word in SUSPICIOUS_WORDS
        if re.search(rf"\b{re.escape(word)}\b", path_query + " " + host)
    })
    if hits:
        reasons.append(
            "Security-sensitive keywords detected: " + ", ".join(hits[:5])
        )
        score += min(25, 8 + len(hits) * 4)

    if len(hits) >= 2 and host.count("-") >= 2:
        reasons.append("Multiple hyphens combined with security-sensitive terms")
        score += 12

    if parsed.scheme == "http":
        reasons.append("Connection uses HTTP instead of HTTPS")
        score += 8
        if hits:
            score += 5

    if "//" in parsed.path:
        reasons.append("Multiple '//' sequences appear inside the URL path")
        score += 8

    if re.search(r"%[0-9a-fA-F]{2}", original):
        reasons.append("Encoded characters are present in the URL")
        score += 4

    score = max(0, min(100, score))

    if score >= 61:
        status = "HIGH RISK"
    elif score >= 31:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"

    if not reasons:
        reasons.append("No major risk indicators were detected by the current rules")

    return {
        "url": original,
        "host": host or "Unable to parse domain",
        "score": score,
        "status": status,
        "reasons": reasons
    }
