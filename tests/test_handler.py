import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from core.handler import HoneypotHandler


class HandlerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "capture" / "audit.jsonl"
        self.handler = HoneypotHandler(self.path, 4096)
        self.session = SimpleNamespace(peer=("192.0.2.4", 54321))

    def process(self, data):
        envelope = SimpleNamespace(
            original_content=data, mail_from="sender@sample.test",
            rcpt_tos=["one@example.test", "two@example.test"],
        )
        return asyncio.run(self.handler.handle_DATA(None, self.session, envelope))

    def test_capture_returns_250_and_logs_metadata(self):
        data = b"Subject: private secret\r\nFrom: sender@sample.test\r\n\r\nhttps://example.test/login?token=secret123"
        self.assertTrue(self.process(data).startswith("250"))
        records = [json.loads(x) for x in self.path.read_text().splitlines()]
        self.assertEqual(len(records), 1)
        event = records[0]
        self.assertEqual(event["client_ip"], "192.0.2.4")
        self.assertEqual(event["envelope_sender_domain"], "sample.test")
        self.assertEqual(event["recipient_domains"], ["example.test"])
        self.assertIn("credential_themed_url", event["indicators"])
        self.assertNotIn("private secret", self.path.read_text())
        self.assertNotIn("secret123", self.path.read_text())

    def test_excessive_message_rejected(self):
        result = self.process(b"x" * 4097)
        self.assertTrue(result.startswith("552"))
        self.assertFalse(self.path.exists())

    def test_missing_content_returns_transient_error(self):
        self.assertTrue(self.process(None).startswith("451"))
        self.assertFalse(self.path.exists())

    def test_io_failure_returns_transient_error(self):
        self.path.parent.mkdir()
        self.path.mkdir()
        self.assertTrue(self.process(b"Subject: hello\n\nbody").startswith("451"))
