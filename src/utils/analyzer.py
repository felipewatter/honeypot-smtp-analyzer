"""Bounded, offline SMTP message analysis; no network access to embedded URLs."""

import hashlib
import ipaddress
import re
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlsplit

URL_PATTERN = re.compile(r"""https?://[^\s<>"'()]{1,2048}""", re.IGNORECASE)
CREDENTIAL_TERMS = re.compile(r"login|signin|sign-in|password|verify|account|bank|wallet|reset|credential", re.I)


def _sender_domain(value):
    address = parseaddr(str(value))[1]
    if "@" not in address:
        return None
    candidate = address.rsplit("@", 1)[-1].lower().strip(".")
    return candidate if candidate and len(candidate) <= 253 and not any(ord(c) < 33 for c in candidate) else None


def analyze_message(raw):
    """Extract bounded indicators only; never return cleartext subjects or full URLs."""
    if isinstance(raw, bytes):
        message = BytesParser(policy=policy.default).parsebytes(raw)
        original = raw
    elif isinstance(raw, Message):
        message = raw
        original = raw.as_bytes()
    else:
        raise TypeError("Expected SMTP bytes or email.Message")

    found = []
    remaining = 250000
    for part in message.walk():
        if remaining <= 0 or len(found) >= 40:
            break
        if part.is_multipart() or part.get_content_type() not in ("text/plain", "text/html"):
            continue
        if part.get_content_disposition() == "attachment":
            continue
        try:
            content = part.get_content()
        except (UnicodeError, LookupError, ValueError, TypeError):
            continue
        if not isinstance(content, str):
            continue
        chunk = content[:remaining]
        remaining -= len(chunk)
        found.extend(match.group(0).rstrip(".,;!?:]") for match in URL_PATTERN.finditer(chunk))
        found = found[:40]

    domains = set()
    indicators = set()
    for address in found:
        try:
            parsed = urlsplit(address)
            host = parsed.hostname
            if not host or len(host) > 253:
                continue
            host = host.lower().strip(".")
            if not host or any(ord(ch) < 33 for ch in host):
                continue
            domains.add(host)
            if CREDENTIAL_TERMS.search(address):
                indicators.add("credential_themed_url")
            if host.startswith("xn--") or ".xn--" in host:
                indicators.add("punycode_hostname")
            try:
                ipaddress.ip_address(host)
                indicators.add("ip_address_url")
            except ValueError:
                pass
            if parsed.username or parsed.password:
                indicators.add("url_userinfo")
        except ValueError:
            continue
    if len(found) >= 10:
        indicators.add("many_urls")
    score = min(100, sum((
        40 if "credential_themed_url" in indicators else 0,
        25 if "ip_address_url" in indicators else 0,
        25 if "url_userinfo" in indicators else 0,
        20 if "punycode_hostname" in indicators else 0,
        15 if "many_urls" in indicators else 0,
    )))
    subject = str(message.get("Subject", ""))
    return {
        "message_sha256": hashlib.sha256(original).hexdigest(),
        "subject_sha256": hashlib.sha256(subject.encode("utf-8")).hexdigest(),
        "sender_domain": _sender_domain(message.get("From", "")),
        "size_bytes": len(original),
        "url_count": len(found),
        "url_domains": sorted(domains)[:15],
        "indicators": sorted(indicators),
        "risk_score": score,
        "risk_level": "high" if score >= 65 else "medium" if score >= 40 else "low",
    }
