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

BRANDS = [
    "netflix", "paypal", "google", "apple", "microsoft",
    "amazon", "facebook", "instagram", "whatsapp",
    "binance", "coinbase", "sbi", "icici"
]

BRAND_DOMAINS = {
    "netflix": {"netflix.com", "www.netflix.com"},
    "paypal": {"paypal.com", "www.paypal.com"},
    "google": {"google.com", "www.google.com"},
    "apple": {"apple.com", "www.apple.com", "icloud.com", "www.icloud.com"},
    "microsoft": {"microsoft.com", "www.microsoft.com", "live.com", "outlook.com"},
    "amazon": {"amazon.com", "www.amazon.com", "aws.amazon.com"},
    "facebook": {"facebook.com", "www.facebook.com", "fb.com"},
    "instagram": {"instagram.com", "www.instagram.com"},
    "whatsapp": {"whatsapp.com", "www.whatsapp.com"},
    "binance": {"binance.com", "www.binance.com"},
    "coinbase": {"coinbase.com", "www.coinbase.com"},
    "sbi": {"sbi.co.in", "www.sbi.co.in", "onlinesbi.sbi", "www.onlinesbi.sbi", "statebankofindia.com"},
    "icici": {"icicibank.com", "www.icicibank.com", "icici.com", "www.icici.com"}
}


def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def is_official_domain(host, brand):
    official_domains = BRAND_DOMAINS.get(brand, {f"{brand}.com", f"www.{brand}.com"})
    return any(host == domain or host.endswith("." + domain) for domain in official_domains)


def detect_brand_impersonation(host, path_query=""):
    """
    Detects typosquatting, character substitutions (leetspeak), Levenshtein edit distance,
    or brand names combined with hyphens or deceptive keywords.
    Returns a list of impersonated brand names.
    """
    if not host:
        return []

    host_lower = host.lower()
    matched = []

    # Extract domain labels and sub-tokens
    labels = [p for p in host_lower.split(".") if p]
    domain_labels = labels[:-1] if len(labels) > 1 else labels

    tokens = set()
    for lab in domain_labels:
        tokens.add(lab)
        for sub in re.split(r"[-_]", lab):
            if sub:
                tokens.add(sub)

    for brand in BRANDS:
        if is_official_domain(host_lower, brand):
            continue

        brand_detected = False

        # 1. Exact brand appears in an unofficial domain (mixed with hyphens, deceptive keywords, or subdomains)
        if brand in host_lower:
            has_hyphen = "-" in host_lower or "_" in host_lower
            has_deceptive = any(word in (host_lower + " " + path_query) for word in SUSPICIOUS_WORDS)
            is_unrelated = not is_official_domain(host_lower, brand)
            if has_hyphen or has_deceptive or is_unrelated:
                brand_detected = True

        # 2. Check tokens for visual leetspeak substitutions & Levenshtein edit distance
        if not brand_detected:
            for tok in tokens:
                if tok == brand or tok in SUSPICIOUS_WORDS:
                    continue

                # Common visual leetspeak / character substitutions:
                # '1' or 'i' replacing 'l' (e.g. 'netfiix' or 'paypa1')
                # '0' replacing 'o' (e.g. 'g00gle')
                # 'vv' replacing 'w'
                sub_tok = tok.replace("0", "o").replace("1", "l").replace("vv", "w")
                if sub_tok == brand:
                    brand_detected = True
                    break

                # Direct pairwise character substitution check (e.g. 'i' replacing 'l')
                if len(tok) == len(brand):
                    diffs = [(t_c, b_c) for t_c, b_c in zip(tok, brand) if t_c != b_c]
                    if diffs and all(
                        (t_c in ("1", "i") and b_c == "l") or
                        (t_c == "l" and b_c == "i") or
                        (t_c == "0" and b_c == "o") or
                        (t_c == "5" and b_c == "s") or
                        (t_c == "v" and b_c == "u")
                        for t_c, b_c in diffs
                    ):
                        brand_detected = True
                        break

                # Levenshtein distance check (edit distance 1 or 2)
                if len(brand) >= 4 and abs(len(tok) - len(brand)) <= 2:
                    dist = levenshtein_distance(tok, brand)
                    if dist in (1, 2):
                        brand_detected = True
                        break
                elif len(brand) <= 3 and len(tok) == len(brand):
                    dist = levenshtein_distance(tok, brand)
                    if dist == 1 and any(c.isdigit() or c in ("i", "l", "o") for c in tok):
                        brand_detected = True
                        break

        # 3. Whole domain core visual substitution check
        if not brand_detected and domain_labels:
            domain_core = "".join(re.split(r"[-_]", "-".join(domain_labels)))
            sub_core = domain_core.replace("0", "o").replace("1", "l").replace("vv", "w")
            if sub_core == brand or (len(brand) >= 4 and abs(len(domain_core) - len(brand)) <= 2 and levenshtein_distance(domain_core, brand) in (1, 2)):
                brand_detected = True

        if brand_detected:
            matched.append(brand)

    return matched


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

    # Brand Impersonation & Typosquatting Detection
    impersonated_brands = detect_brand_impersonation(host, path_query)
    for brand in impersonated_brands:
        add_reason(
            f"Brand Impersonation / Typosquatting Detected: Domain mimics '{brand}' using character substitution or deceptive spelling (+40).",
            40
        )

    score = max(0, min(100, score))

    if score > 60:
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