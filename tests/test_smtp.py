import asyncio
import json
import smtplib
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from core.handler import HoneypotHandler
from main import is_loopback, main, make_parser, make_smtp_protocol


def unused_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return server.getsockname()[1]


class RealSMTPIntegrationTests(unittest.TestCase):
    """Test the real aiosmtpd protocol without Controller's unreliable readiness trigger."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "capture" / "events.jsonl"
        self.port = unused_port()
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.start_error = None
        self.thread = threading.Thread(target=self._server_thread, daemon=True)
        self.thread.start()
        self.addCleanup(self._shutdown)
        self.assertTrue(self.ready.wait(10), "SMTP server did not bind")
        if self.start_error:
            raise self.start_error

    def _server_thread(self):
        asyncio.set_event_loop(self.loop)
        try:
            handler = HoneypotHandler(self.path, max_message_bytes=4096)
            self.server = self.loop.run_until_complete(
                self.loop.create_server(
                    lambda: make_smtp_protocol(handler, 4096),
                    host="127.0.0.1",
                    port=self.port,
                )
            )
        except BaseException as error:
            self.start_error = error
            self.ready.set()
            self.loop.close()
            return
        self.ready.set()
        try:
            self.loop.run_forever()
        finally:
            self.server.close()
            self.loop.run_until_complete(self.server.wait_closed())
            pending = asyncio.all_tasks(self.loop)
            for task in pending:
                task.cancel()
            if pending:
                self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self.loop.close()

    def _shutdown(self):
        if self.thread.is_alive():
            if self.loop.is_running():
                self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(timeout=10)
            self.assertFalse(self.thread.is_alive(), "SMTP server thread did not stop")

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
            code, message = client.ehlo()
            self.assertEqual(code, 250)
            self.assertNotIn("AUTH", message.decode("ascii", errors="ignore").upper())
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
