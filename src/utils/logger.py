import json
from datetime import datetime
from pathlib import Path

LOG_FILE = Path("src/logs/attempts.jsonl")

def log_attempt(message):
    data = {
        "timestamp": datetime.utcnow().isoformat(),
        "from": message.get("From"),
        "subject": message.get("Subject"),
        "payload": message.get_payload()
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")