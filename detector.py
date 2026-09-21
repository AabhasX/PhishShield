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
    "unlock", "authenticate", "reset"
}

BRAND_DOMAINS = {
    "paypal": {"paypal.com", "www.paypal.com"},
    "google": {"google.com", "www.google.com"},
    "microsoft": {"microsoft.com", "www.microsoft.com"},
    "apple": {"apple.com", "www.apple.com"},
    "amazon": {"amazon.com", "www.amazon.com"},
    "facebook": {"facebook.com", "www.facebook.com"},
    "instagram": {"instagram.com", "www.instagram.com"},
    "netflix": {"netflix.com", "www.netflix.com"}
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

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        normalized
    ):
        normalized = "http://" + normalized

    try:
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return {
            "url": original,
            "host": "Unable to parse domain",
            "score": 80,
            "status": "HIGH RISK",
            "reasons": ["Malformed or invalid URL structure"]
        }

    path_query = f"{parsed.path} {parsed.query}".lower()

    reasons = []
    score = 0

    def add_reason(message, points):
        nonlocal score

        if message not in reasons:
            reasons.append(message)
            score += points

    if parsed.scheme not in {"http", "https"}:
        add_reason(
            "Unsupported or unusual URL scheme",
            20
        )

    if not host:
        add_reason(
            "Unable to identify a valid domain name",
            25
        )

    if is_ip_address(host):
        add_reason(
            "IP address is used instead of a normal domain name",
            25
        )

    if len(original) > 120:
        add_reason(
            "URL is unusually long",
            12
        )
    elif len(original) > 75:
        add_reason(
            "URL is longer than typical",
            5
        )

    if "@" in original:
        add_reason(
            "URL contains '@', which can obscure the real destination",
            20
        )

    if parsed.username or parsed.password:
        add_reason(
            "Username or password information is embedded in the URL",
            15
        )

    try:
        port = parsed.port
    except ValueError:
        port = None
        add_reason(
            "Invalid network port detected",
            10
        )

    if port is not None and port not in {80, 443}:
        add_reason(
            "Unusual network port detected",
            10
        )

    if host.startswith("xn--") or ".xn--" in host:
        add_reason(
            "Punycode/IDN pattern detected in the domain",
            10
        )

    labels = [part for part in host.split(".") if part]

    if len(labels) >= 5:
        add_reason(
            "Domain contains many subdomain levels",
            12
        )
    elif len(labels) == 4:
        add_reason(
            "Domain contains multiple subdomain levels",
            5
        )

    if host.count("-") >= 3:
        add_reason(
            "Domain contains many hyphens",
            8
        )

    if len(host) > 40:
        add_reason(
            "Domain name is unusually long",
            8
        )

    if host in SHORTENERS:
        add_reason(
            "URL shortening service detected",
            12
        )

    hits = sorted({
        word
        for word in SUSPICIOUS_WORDS
        if re.search(
            rf"\b{re.escape(word)}\b",
            path_query + " " + host
        )
    })

    if hits:
        keyword_score = min(25, 8 + len(hits) * 4)

        if len(hits) == 1:
            add_reason(
                "Security-sensitive keyword detected: " + hits[0],
                keyword_score
            )
        else:
            add_reason(
                "Security-sensitive keywords detected: "
                + ", ".join(hits[:6]),
                keyword_score
            )

    if len(hits) >= 2 and host.count("-") >= 2:
        add_reason(
            "Multiple hyphens combined with security-sensitive terms",
            12
        )

    if parsed.scheme == "http":
        http_score = 8

        if hits:
            http_score += 5

        add_reason(
            "Connection uses HTTP instead of HTTPS",
            http_score
        )

    if "//" in parsed.path:
        add_reason(
            "Multiple '//' sequences appear inside the URL path",
            8
        )

    if re.search(r"%[0-9a-fA-F]{2}", original):
        add_reason(
            "Encoded characters are present in the URL",
            4
        )

    if parsed.query:
        query_parts = [
            part for part in parsed.query.split("&")
            if part
        ]

        if len(query_parts) >= 5:
            add_reason(
                "URL contains many query parameters",
                8
            )

    if host:
        digit_count = sum(char.isdigit() for char in host)
        letter_count = sum(char.isalpha() for char in host)

        if digit_count >= 4 and digit_count > letter_count:
            add_reason(
                "Domain contains an unusually high number of digits",
                8
            )

    # Detect possible use of a well-known brand in an unrelated domain.
    for brand, official_domains in BRAND_DOMAINS.items():
        if brand in host:
            is_official = any(
                host == domain or host.endswith("." + domain)
                for domain in official_domains
            )

            if not is_official:
                add_reason(
                    f"Possible {brand} brand impersonation detected in domain",
                    15
                )

    score = max(0, min(100, score))

    if score >= 61:
        status = "HIGH RISK"
    elif score >= 31:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"

    if not reasons:
        reasons.append(
            "No major risk indicators were detected by the current rules"
        )

    return {
        "url": original,
        "host": host or "Unable to parse domain",
        "score": score,
        "status": status,
        "reasons": reasons
    }