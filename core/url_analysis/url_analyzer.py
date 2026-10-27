"""Offline URL feature extraction for defensive phishing analysis.

This module never opens URLs, performs DNS lookups, or sends network
requests. Results are heuristic indicators, not a verdict on safety.
"""

import ipaddress
import re
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048

SUSPICIOUS_PATH_WORDS = {
    "account", "login", "password", "signin", "verify",
}

WEIGHTS = {
    "URL_CONTAINS_USERINFO": 35,
    "URL_USES_IP_ADDRESS": 25,
    "URL_HAS_PUNYCODE_HOST": 20,
    "URL_EXCESSIVE_LENGTH": 10,
    "URL_MANY_SUBDOMAINS": 10,
    "URL_SUSPICIOUS_PATH_WORD": 5,
    "URL_NON_HTTPS": 5,
}


def analyze_url(url: str) -> dict:
    """Return explainable URL indicators and a heuristic risk score."""
    if not isinstance(url, str):
        raise TypeError("url must be a string")

    url = url.strip()
    if not url:
        return {
            "url": url,
            "valid_syntax": False,
            "hostname": None,
            "indicators": [],
            "risk_score": 0,
            "risk_level": "unknown",
            "note": "Empty URL; no safety conclusion can be made.",
        }

    if len(url) > MAX_URL_LENGTH:
        return {
            "url": url[:MAX_URL_LENGTH],
            "valid_syntax": False,
            "hostname": None,
            "indicators": [{
                "code": "URL_EXCESSIVE_LENGTH",
                "severity": "low",
                "evidence": f"URL exceeds {MAX_URL_LENGTH} characters",
                "weight": WEIGHTS["URL_EXCESSIVE_LENGTH"],
            }],
            "risk_score": WEIGHTS["URL_EXCESSIVE_LENGTH"],
            "risk_level": "low",
            "note": "URL exceeded the analysis limit; parsing was skipped.",
        }

    indicators = []

    def add(code: str, severity: str, evidence: str) -> None:
        indicators.append({
            "code": code,
            "severity": severity,
            "evidence": evidence,
            "weight": WEIGHTS[code],
        })

    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()

        if scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Expected an absolute HTTP or HTTPS URL")

        # Accessing hostname and port can itself raise ValueError for
        # malformed bracketed IPv6 addresses or invalid ports.
        hostname = parsed.hostname
        _ = parsed.port

        if not hostname:
            raise ValueError("Missing hostname")

        hostname = hostname.rstrip(".").lower()

    except (ValueError, UnicodeError):
        return {
            "url": url,
            "valid_syntax": False,
            "hostname": None,
            "indicators": [],
            "risk_score": 0,
            "risk_level": "unknown",
            "note": "Malformed or unsupported URL; inspect manually.",
        }

    if parsed.username is not None or parsed.password is not None:
        add(
            "URL_CONTAINS_USERINFO",
            "high",
            "URL contains user-information before the hostname",
        )

    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        add(
            "URL_USES_IP_ADDRESS",
            "medium",
            f"Hostname is an IP address: {hostname}",
        )

    labels = hostname.split(".")
    if any(label.startswith("xn--") for label in labels):
        add(
            "URL_HAS_PUNYCODE_HOST",
            "medium",
            "Hostname contains an IDN punycode label",
        )

    if len(url) > 120:
        add(
            "URL_EXCESSIVE_LENGTH",
            "low",
            f"URL contains {len(url)} characters",
        )

    # Count hostname labels beyond a typical registrable-domain shape.
    # This is only a structural heuristic, not public-suffix validation.
    if not is_ip and len(labels) >= 5:
        add(
            "URL_MANY_SUBDOMAINS",
            "low",
            f"Hostname contains {len(labels)} labels",
        )

    path_and_query = f"{parsed.path} {parsed.query}".lower()
    matched_words = sorted(
        word for word in SUSPICIOUS_PATH_WORDS
        if re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])",
                     path_and_query)
    )
    if matched_words:
        add(
            "URL_SUSPICIOUS_PATH_WORD",
            "low",
            "Path/query contains: " + ", ".join(matched_words),
        )

    if scheme != "https":
        add(
            "URL_NON_HTTPS",
            "low",
            f"URL uses {scheme.upper()} rather than HTTPS",
        )

    score = min(100, sum(item["weight"] for item in indicators))

    if score == 0:
        level = "low"
    elif score < 25:
        level = "low"
    elif score < 50:
        level = "medium"
    elif score < 75:
        level = "high"
    else:
        level = "critical"

    return {
        "url": url,
        "valid_syntax": True,
        "scheme": scheme,
        "hostname": hostname,
        "indicators": indicators,
        "risk_score": score,
        "risk_level": level,
        "note": (
            "Heuristic score only; indicators do not prove maliciousness. "
            "No network request or DNS lookup was performed."
        ),
    }
