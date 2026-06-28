import hashlib
import json
import re
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.config import Settings

SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{12,}\b"),
    re.compile(r"(?i)\b(password|token|secret|api[_ -]?key)\s*[:=]\s*\S+"),
)

_POSTGRES_POOLS: dict[str, Any] = {}


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
            if self.settings.audit_include_redacted_input:
                event["redacted_input"] = redact(raw_text)

        self._write(event)
        return event_id

    def ensure_schema(self) -> None:
        if self.settings.audit_log_sink != "postgres":
            return
        with self._postgres_connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS prompt_sentry_audit_events (
                    event_id TEXT PRIMARY KEY,
                    occurred_at TIMESTAMPTZ NOT NULL,
                    event JSONB NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS prompt_sentry_audit_events_occurred_at_idx
                ON prompt_sentry_audit_events (occurred_at DESC)
                """
            )

    def read_events(self, limit: int) -> list[dict]:
        if self.settings.audit_log_sink == "postgres":
            with self._postgres_connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT event FROM prompt_sentry_audit_events
                    ORDER BY occurred_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cursor.fetchall()
            return [dict(row[0]) for row in reversed(rows)]
        if self.settings.audit_log_sink == "stdout":
            return []
        return _read_file_events(Path(self.settings.audit_log_path), limit)

    def is_ready(self) -> bool:
        if self.settings.audit_log_sink != "postgres":
            return True
        try:
            with self._postgres_connection() as connection, connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                return cursor.fetchone() == (1,)
        except Exception:
            return False

    def _write(self, event: Mapping) -> None:
        line = json.dumps(event, sort_keys=True)
        if self.settings.audit_log_sink == "stdout":
            print(line, file=sys.stdout, flush=True)
            return
        if self.settings.audit_log_sink == "postgres":
            with self._postgres_connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO prompt_sentry_audit_events (event_id, occurred_at, event)
                    VALUES (%s, %s, %s::jsonb)
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    (event["event_id"], event["timestamp"], line),
                )
            return
        path = Path(self.settings.audit_log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def _postgres_connection(self):
        if not self.settings.database_url:
            raise RuntimeError("DATABASE_URL is required for PostgreSQL audit logging")
        pool = _POSTGRES_POOLS.get(self.settings.database_url)
        if pool is None:
            try:
                from psycopg_pool import ConnectionPool
            except ImportError as exc:  # pragma: no cover - configuration error
                raise RuntimeError("Install the 'production' extra to use PostgreSQL") from exc
            pool = ConnectionPool(
                conninfo=self.settings.database_url,
                min_size=1,
                max_size=10,
                open=True,
                kwargs={"autocommit": True},
            )
            _POSTGRES_POOLS[self.settings.database_url] = pool
        return pool.connection()


def close_postgres_pools() -> None:
    for pool in _POSTGRES_POOLS.values():
        pool.close()
    _POSTGRES_POOLS.clear()


def redact(text: str) -> str:
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def _read_file_events(path: Path, limit: int) -> list[dict]:
    if not path.exists():
        return []
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records[-limit:]
