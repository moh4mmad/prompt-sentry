CREATE TABLE IF NOT EXISTS prompt_sentry_audit_events (
    event_id TEXT PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    event JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS prompt_sentry_audit_events_occurred_at_idx
ON prompt_sentry_audit_events (occurred_at DESC);
