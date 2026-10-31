import email
import unittest
from email.message import EmailMessage
from utils.analyzer import analyze_message


class AnalyzerTests(unittest.TestCase):
    def test_simple_credential_link(self):
        result = analyze_message(b"From: Agent <agent@sample.test>\r\nSubject: Action required\r\n\r\nOpen https://auth.example.test/login")
        self.assertEqual(result["sender_domain"], "sample.test")
        self.assertEqual(result["url_domains"], ["auth.example.test"])
        self.assertEqual(result["risk_level"], "medium")
        self.assertIn("credential_themed_url", result["indicators"])
        self.assertNotIn("Action required", str(result))
        self.assertNotIn("https://", str(result))

    def test_normal_message_is_low_risk(self):
        result = analyze_message(b"Subject: hello\r\n\r\nOrdinary email without links")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["url_count"], 0)
        self.assertEqual(result["risk_level"], "low")

    def test_multipart_html_without_inspecting_attachments(self):
        msg = EmailMessage()
        msg["From"] = "Analyst <person@example.test>"
        msg["Subject"] = "Test"
        msg.set_content("Plain text only.")
        msg.add_alternative('<a href="https://safe.example.test/login">open</a>', subtype="html")
        msg.add_attachment(b"https://bad.example.test/account", maintype="application", subtype="octet-stream", filename="attachment.bin")
        result = analyze_message(msg.as_bytes())
        self.assertEqual(result["url_domains"], ["safe.example.test"])
        self.assertEqual(result["url_count"], 1)

    def test_ip_hostname_and_userinfo_detected(self):
        result = analyze_message(b"Subject: IP\r\n\r\nhttps://username:password@192.0.2.1/secure")
        self.assertIn("ip_address_url", result["indicators"])
        self.assertIn("url_userinfo", result["indicators"])
        self.assertEqual(result["risk_level"], "high")

    def test_bounded_url_scanning(self):
        data = b"Subject: Example\r\n\r\n" + (b"https://portal.example.test/login " * 100)
        result = analyze_message(data)
        self.assertEqual(result["url_count"], 40)
        self.assertIn("many_urls", result["indicators"])

    def test_email_message_object_compatibility(self):
        message = email.message_from_bytes(b"Subject: OK\n\nhttps://example.test/path")
        self.assertEqual(analyze_message(message)["url_domains"], ["example.test"])

    def test_type_check(self):
        with self.assertRaises(TypeError):
            analyze_message("string is not an email")
