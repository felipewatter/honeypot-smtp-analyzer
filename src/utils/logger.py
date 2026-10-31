"""Private append-only JSONL event logging (not cryptographically tamper-evident)."""

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LOG_FILE = Path("logs/attempts.jsonl")


def log_attempt(event, file_path=DEFAULT_LOG_FILE):
    """Persist sanitized metadata; no raw message body, subject or full URLs."""
    path = Path(file_path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir() or path.is_symlink():
        raise OSError("Log path must not be a symlink")
    record = {"timestamp": datetime.now(timezone.utc).isoformat(), **event}
    data = (json.dumps(record, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("Ledger destination must be a regular file")
        if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
            raise PermissionError("Existing log file is accessible to group/others")
        if os.write(fd, data) != len(data):
            raise OSError("Incomplete JSONL write")
        os.fsync(fd)
    finally:
        os.close(fd)
