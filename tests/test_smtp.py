import json
import smtplib
import socket
import tempfile
import unittest
from pathlib import Path

from aiosmtpd.controller import Controller
from core.handler import HoneypotHandler
from main import is_loopback, main, make_parser


def unused_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return server.getsockname()[1]


class RealSMTPIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "capture" / "events.jsonl"
        self.port = unused_port()
        self.controller = Controller(
            HoneypotHandler(self.path, max_message_bytes=4096),
            hostname="127.0.0.1", port=self.port,
            data_size_limit=4096, command_call_limit=100,
            timeout=10,
        )
        self.controller.start()

    def tearDown(self):
        self.controller.stop()
        self.tmp.cleanup()

    def test_live_smtp_transaction_writes_jsonl(self):
        with smtplib.SMTP("127.0.0.1", self.port, timeout=5) as client:
            client.sendmail(
                "sender@sample.test", ["rcpt@honeypot.test"],
                "From: sender@sample.test\r\nSubject: Integration\r\n\r\nVisit https://example.test/verify",
            )
        events = [json.loads(row) for row in self.path.read_text().splitlines()]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["recipient_domains"], ["honeypot.test"])
        self.assertEqual(events[0]["url_domains"], ["example.test"])
        self.assertEqual(events[0]["risk_level"], "medium")

    def test_mail_is_accepted_but_never_forwarded(self):
        with smtplib.SMTP("127.0.0.1", self.port, timeout=5) as client:
            client.ehlo()
            status, message = client.noop()
            self.assertEqual(status, 250)
            self.assertNotIn("AUTH", client.ehlo_resp.decode("ascii", errors="ignore").upper())
            client.sendmail("source@sample.test", ["not-real@sample.test"], "Subject: test\r\n\r\nNo real delivery.")
        self.assertEqual(len(self.path.read_text().splitlines()), 1)


class CLITests(unittest.TestCase):
    def test_safe_defaults(self):
        args = make_parser().parse_args([])
        self.assertEqual(args.host, "127.0.0.1")
        self.assertEqual(args.port, 2525)
        self.assertFalse(args.allow_public_bind)

    def test_public_bind_requires_opt_in(self):
        with self.assertRaises(SystemExit):
            main(["--host", "0.0.0.0"])

    def test_rejects_invalid_limits(self):
        with self.assertRaises(SystemExit):
            main(["--port", "0"])
        with self.assertRaises(SystemExit):
            main(["--max-message-bytes", "1000000000"])

    def test_loopback_detection(self):
        self.assertTrue(is_loopback("127.0.0.1"))
        self.assertTrue(is_loopback("::1"))
        self.assertFalse(is_loopback("0.0.0.0"))
        self.assertFalse(is_loopback("198.51.100.1"))
