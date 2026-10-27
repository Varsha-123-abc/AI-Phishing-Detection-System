
"""Extract explainable phishing indicators for analyst review."""

import re
from email.utils import parseaddr

from core.url_analysis.url_analyzer import analyze_url

URGENT_PHRASES = (
    "verify your account",
    "account will be suspended",
    "urgent action required",
    "password expires",
    "confirm your password",
    "click here immediately",
    "unusual sign-in",
    "payment failed",
)

AUTH_FAILURE_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*fail\b", re.IGNORECASE
)

AUTH_STATUS_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*"
    r"(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)

RECEIVED_SPF_FAILURE_PATTERN = re.compile(
    r"^\s*fail\b", re.IGNORECASE
)

RECEIVED_SPF_STATUS_PATTERN = re.compile(
    r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)

EMAIL_ADDRESS_PATTERN = re.compile(r"^[^@\s<>]+@[^@\s<>]+$")


def extract_indicators(parsed_email: dict) -> list[dict]:
    """Return explainable email and URL indicators without network access."""
    indicators = []
    headers = parsed_email.get("headers", {})
    body = parsed_email.get("body", "")

    sender = headers.get("from")
    reply_to = headers.get("reply_to")
    return_path = headers.get("return_path")

    sender_address = parseaddr(sender or "")[1].strip().lower()
    sender_is_valid = bool(
        sender_address and EMAIL_ADDRESS_PATTERN.fullmatch(sender_address)
    )

    if sender and not sender_is_valid:
        indicators.append({
            "code": "MALFORMED_FROM_ADDRESS",
            "severity": "low",
            "evidence": (
                "The supplied From header does not contain a usable "
                "email address."
            ),
        })

    if sender_is_valid and reply_to:
        reply_address = parseaddr(reply_to)[1].strip().lower()

        if EMAIL_ADDRESS_PATTERN.fullmatch(reply_address):
            sender_domain = sender_address.rsplit("@", 1)[-1]
            reply_domain = reply_address.rsplit("@", 1)[-1]

            if sender_domain != reply_domain:
                indicators.append({
                    "code": "REPLY_TO_DOMAIN_MISMATCH",
                    "severity": "medium",
                    "evidence": (
                        f"From domain: {sender_domain}; "
                        f"Reply-To domain: {reply_domain}"
                    ),
                })

    # A mismatch is a review signal, not proof of spoofing.
    if sender_is_valid and return_path:
        return_address = parseaddr(return_path)[1].strip().lower()

        if EMAIL_ADDRESS_PATTERN.fullmatch(return_address):
            sender_domain = sender_address.rsplit("@", 1)[-1]
            return_domain = return_address.rsplit("@", 1)[-1]

            if sender_domain != return_domain:
                indicators.append({
                    "code": "FROM_RETURN_PATH_DOMAIN_MISMATCH",
                    "severity": "low",
                    "evidence": (
                        f"From domain: {sender_domain}; "
                        f"Return-Path domain: {return_domain}. "
                        "This difference can be legitimate."
                    ),
                })

    auth_results = headers.get("authentication_results") or ""
    received_spf = headers.get("received_spf") or ""

    # These headers are unverified claims; identify contradictory pass/fail.
    auth_statuses = {}

    for match in AUTH_STATUS_PATTERN.finditer(auth_results):
        mechanism = match.group(1).lower()
        status = match.group(2).lower()
        auth_statuses.setdefault(mechanism, set()).add(status)

    received_spf_status = RECEIVED_SPF_STATUS_PATTERN.match(received_spf)
    if received_spf_status:
        auth_statuses.setdefault("spf", set()).add(
            received_spf_status.group(1).lower()
        )

    conflicting_mechanisms = sorted(
        mechanism
        for mechanism, statuses in auth_statuses.items()
        if "pass" in statuses and "fail" in statuses
    )

    if conflicting_mechanisms:
        indicators.append({
            "code": "CONFLICTING_AUTHENTICATION_RESULTS",
            "severity": "low",
            "evidence": (
                "Contradictory pass/fail claims (unverified) for: "
                + ", ".join(conflicting_mechanisms)
            ),
        })

    # Keep one reported failure per mechanism across both headers.
    seen_auth_failures = set()

    for match in AUTH_FAILURE_PATTERN.finditer(auth_results):
        mechanism = match.group(1).lower()

        if mechanism in seen_auth_failures:
            continue

        seen_auth_failures.add(mechanism)
        indicators.append({
            "code": "AUTHENTICATION_FAILURE_REPORTED",
            "severity": "medium",
            "evidence": (
                "Reported in message headers (unverified): "
                f"{match.group(0)}"
            ),
        })

    received_spf_match = RECEIVED_SPF_FAILURE_PATTERN.match(received_spf)

    if received_spf_match and "spf" not in seen_auth_failures:
        seen_auth_failures.add("spf")
        indicators.append({
            "code": "AUTHENTICATION_FAILURE_REPORTED",
            "severity": "medium",
            "evidence": (
                "Received-SPF reported failure (unverified): "
                f"{received_spf_match.group(0).strip()}"
            ),
        })

    lower_body = body.lower()

    for phrase in URGENT_PHRASES:
        if phrase in lower_body:
            indicators.append({
                "code": "SUSPICIOUS_URGENCY_LANGUAGE",
                "severity": "low",
                "evidence": phrase,
            })

    # Analyze extracted URLs locally. Never open or resolve them.
    for item in parsed_email.get("urls", []):
        url = item.get("url", "")
        if not url:
            continue

        url_result = analyze_url(url)

        for finding in url_result["indicators"]:
            indicators.append({
                "code": finding["code"],
                "severity": finding["severity"],
                "evidence": finding["evidence"],
                "url": url,
                "weight": finding["weight"],
                "source": "url_analysis",
            })

    return indicators
