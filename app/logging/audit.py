import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from app.core.config import Settings

SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{12,}\b"),
    re.compile(r"(?i)\b(password|token|secret|api[_ -]?key)\s*[:=]\s*\S+"),
)


class AuditLogger:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def log(self, payload: dict, raw_text: str | None = None) -> str:
        event_id = f"evt_{uuid4().hex}"
        event = {
            "event_id": event_id,
            "timestamp": datetime.now(UTC).isoformat(),
            **payload,
        }
        if raw_text is not None:
            event["input_hash"] = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
            event["redacted_input"] = redact(raw_text)

        line = json.dumps(event, sort_keys=True)
        if self.settings.audit_log_sink == "stdout":
            print(line, file=sys.stdout)
        else:
            path = Path(self.settings.audit_log_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        return event_id


def redact(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted
