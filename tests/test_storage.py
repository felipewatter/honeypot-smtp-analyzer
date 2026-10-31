import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from utils.logger import log_attempt


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "private" / "events.jsonl"

    def test_creates_private_jsonl_with_valid_timestamp(self):
        log_attempt({"ip": "127.0.0.1", "message_sha256": "a" * 64}, self.path)
        log_attempt({"ip": "192.0.2.1"}, self.path)
        entries = [json.loads(line) for line in self.path.read_text().splitlines()]
        self.assertEqual(len(entries), 2)
        self.assertTrue(entries[0]["timestamp"].endswith("+00:00"))
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)

    def test_symlink_file_rejected(self):
        target = Path(self.tmp.name) / "real.jsonl"
        target.write_text("")
        alias = self.path
        alias.parent.mkdir()
        try:
            alias.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink not available")
        with self.assertRaises(OSError):
            log_attempt({"event": "test"}, alias)
        self.assertEqual(target.read_text(), "")

    def test_symlink_directory_rejected(self):
        target = Path(self.tmp.name) / "real"
        target.mkdir()
        try:
            self.path.parent.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink not available")
        with self.assertRaises(OSError):
            log_attempt({"event": "test"}, self.path)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_excessive_existing_file_permissions_rejected(self):
        self.path.parent.mkdir()
        self.path.touch()
        self.path.chmod(0o644)
        with self.assertRaises(PermissionError):
            log_attempt({"secret": "should-not-appear"}, self.path)
        self.assertEqual(self.path.read_text(), "")
