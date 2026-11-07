import asyncio
import json
import smtplib
import tempfile
import unittest
from pathlib import Path

from core.handler import HoneypotHandler
from main import is_loopback, main, make_parser, make_smtp_protocol


class RealSMTPIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Use the production asyncio protocol on the test's main event loop.

    The blocking smtplib client runs in a worker thread; the SMTP server does
    not. This avoids macOS kqueue event-loop thread-affinity/race problems and
    verifies an actual TCP 220 greeting, SMTP commands, and the captured log.
    """

    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "capture" / "events.jsonl"
        handler = HoneypotHandler(self.path, max_message_bytes=4096)
        self.server = await asyncio.get_running_loop().create_server(
            lambda: make_smtp_protocol(handler, 4096),
            host="127.0.0.1",
            port=0,  # Bind the OS-selected port: no unused_port() race.
        )
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()

    async def _send(self, action):
        # Never block the event loop responsible for generating the SMTP 220
        # greeting. Enforce finite client and outer integration timeouts.
        return await asyncio.wait_for(asyncio.to_thread(action), timeout=20)

    async def test_live_smtp_transaction_writes_jsonl(self):
        def send():
            with smtplib.SMTP("127.0.0.1", self.port, timeout=10) as client:
                client.sendmail(
                    "sender@sample.test", ["rcpt@honeypot.test"],
                    "From: sender@sample.test\r\nSubject: Integration\r\n\r\nVisit https://example.test/verify",
                )

        await self._send(send)
        events = [json.loads(row) for row in self.path.read_text().splitlines()]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["recipient_domains"], ["honeypot.test"])
        self.assertEqual(events[0]["url_domains"], ["example.test"])
        self.assertEqual(events[0]["risk_level"], "medium")

    async def test_mail_is_accepted_but_never_forwarded(self):
        def send():
            with smtplib.SMTP("127.0.0.1", self.port, timeout=10) as client:
                code, message = client.ehlo()
                self.assertEqual(code, 250)
                self.assertNotIn("AUTH", message.decode("ascii", errors="ignore").upper())
                client.sendmail(
                    "source@sample.test", ["not-real@sample.test"],
                    "Subject: test\r\n\r\nNo real delivery.",
                )

        await self._send(send)
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
