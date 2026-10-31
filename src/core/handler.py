"""aiosmtpd DATA hook. The honeypot never delivers or relays messages."""

import logging
from pathlib import Path
from utils.analyzer import analyze_message
from utils.logger import DEFAULT_LOG_FILE, log_attempt

LOG = logging.getLogger(__name__)


def envelope_domain(address):
    if "@" not in address:
        return None
    value = address.rsplit("@", 1)[1].lower().strip().strip(">")
    return value if value and len(value) <= 253 and not any(ord(c) < 33 for c in value) else None


class HoneypotHandler:
    def __init__(self, log_file=DEFAULT_LOG_FILE, max_message_bytes=262144):
        self.log_file = Path(log_file)
        self.max_message_bytes = max_message_bytes

    async def handle_DATA(self, server, session, envelope):
        raw = envelope.original_content
        if not isinstance(raw, bytes):
            return "451 4.3.0 Message unavailable"
        if len(raw) > self.max_message_bytes:
            return "552 5.3.4 Message exceeds size limit"
        try:
            details = analyze_message(raw)
            peer = getattr(session, "peer", None)
            client_ip = peer[0] if isinstance(peer, tuple) and peer else None
            sender = str(getattr(envelope, "mail_from", "") or "")
            recipients = getattr(envelope, "rcpt_tos", []) or []
            recipient_domains = sorted({
                domain for address in recipients
                if (domain := envelope_domain(str(address))) is not None
            })[:15]
            log_attempt({
                "client_ip": client_ip,
                "envelope_sender_domain": envelope_domain(sender),
                "recipient_domains": recipient_domains,
                **details,
            }, self.log_file)
        except Exception:
            LOG.exception("Failed to capture SMTP event; returning transient error")
            return "451 4.3.0 Temporary local error"
        return "250 2.0.0 Message accepted for analysis"
