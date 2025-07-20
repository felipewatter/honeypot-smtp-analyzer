import re

def analyze_message(message):
    subject = message.get("Subject", "")
    sender = message.get("From", "")
    links = re.findall(r'https?://\S+', message.get_payload())
    phishing = any("login" in link or "bank" in link for link in links)
    return {
        "sender": sender,
        "subject": subject,
        "links": links,
        "is_phishing": phishing
    }