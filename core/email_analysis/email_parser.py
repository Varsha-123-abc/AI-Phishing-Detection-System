"""Offline, non-executing parser for raw email messages."""

from email import policy
from email.parser import Parser
from urllib.parse import urlsplit
import re

MAX_EMAIL_CHARS = 1_000_000

URL_PATTERN = re.compile(r"""https?://[^\s<>"']+""", re.IGNORECASE)


def parse_email(raw_email: str) -> dict:
    """Parse an email string and return headers, text, and URL evidence.

    Attachments are never executed or saved. Only text/plain body parts
    are inspected. Authentication headers are reported as supplied;
    they are not independently verified by this function.
    """
    if not isinstance(raw_email, str):
        raise TypeError("raw_email must be a string")

    if len(raw_email) > MAX_EMAIL_CHARS:
        raise ValueError("Email exceeds the 1,000,000-character safety limit")

    message = Parser(policy=policy.default).parsestr(raw_email)

    header_names = (
        "From", "To", "Cc", "Subject", "Date", "Reply-To",
        "Return-Path", "Message-ID", "Authentication-Results", "Received-SPF",
    )
    headers = {name.lower().replace("-", "_"): message.get(name)
               for name in header_names}

    body_parts = []
    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                continue
            if part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() != "text/plain":
                continue
            try:
                content = part.get_content()
                if isinstance(content, str):
                    body_parts.append(content)
            except (LookupError, UnicodeError, ValueError):
                body_parts.append("[Text body could not be decoded]")
    elif message.get_content_type() == "text/plain":
        try:
            content = message.get_content()
            if isinstance(content, str):
                body_parts.append(content)
        except (LookupError, UnicodeError, ValueError):
            body_parts.append("[Text body could not be decoded]")

    body = "\n".join(body_parts)
    urls = []
    seen = set()

    for match in URL_PATTERN.findall(body):
        # Remove common punctuation attached to a URL in prose.
        url = match.rstrip(".,;:!?)\u005d}")
        if url not in seen:
            seen.add(url)
            parsed = urlsplit(url)
            urls.append({
                "url": url,
                "scheme": parsed.scheme.lower(),
                "hostname": parsed.hostname,
                "has_username": parsed.username is not None,
                "has_password": parsed.password is not None,
            })

    return {
        "headers": headers,
        "body": body,
        "urls": urls,
        "is_multipart": message.is_multipart(),
        "attachment_count": sum(
            1 for part in message.walk()
            if not part.is_multipart()
            and part.get_content_disposition() == "attachment"
        ),
        "notes": [
            "Authentication headers are unverified claims from the message.",
            "URL extraction does not visit or validate the linked websites.",
        ],
    }
