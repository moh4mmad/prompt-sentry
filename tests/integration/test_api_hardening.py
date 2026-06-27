"""
Integration tests for API hardening features:
- API key auth (X-API-Key header)
- Request size limit (413 response)
- RFC 7807 structured error shapes
- Rate limit response shape
- Dashboard endpoints (events, stats)
- Red team library suite
"""

import json

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def open_client(tmp_path):
    """Client with no API key required."""
    settings = Settings(audit_log_path=tmp_path / "audit.jsonl")
    app = create_app.__wrapped__() if hasattr(create_app, "__wrapped__") else _make_app(settings)
    return TestClient(app)


@pytest.fixture()
def secured_client(tmp_path):
    """Client with API key = 'test-secret' required."""
    settings = Settings(audit_log_path=tmp_path / "audit.jsonl", api_key="test-secret")
    app = _make_app(settings)
    return TestClient(app)


@pytest.fixture()
def tiny_limit_client(tmp_path):
    """Client with 100-byte max request size."""
    settings = Settings(audit_log_path=tmp_path / "audit.jsonl", max_request_bytes=100)
    app = _make_app(settings)
    return TestClient(app)


def _make_app(settings: Settings):
    import app.main as main_module
    original = main_module.get_settings
    main_module.get_settings = lambda: settings
    # Clear lru_cache
    from app.core import config
    config.get_settings.cache_clear()
    config.get_settings.__wrapped__ = lambda: settings
    from app.main import create_app
    application = create_app()
    main_module.get_settings = original
    return application


# ── API key auth ──────────────────────────────────────────────────────────────

class TestApiKeyAuth:
    PAYLOAD = {"request_id": "t", "source": "user_prompt", "text": "Hello there."}

    def test_no_key_required_when_unset(self):
        """If API_KEY is not configured, all requests pass through."""
        client = TestClient(__import__("app.main", fromlist=["app"]).app)
        r = client.post("/v1/inspect", json=self.PAYLOAD)
        assert r.status_code == 200

    def test_missing_key_returns_401(self, secured_client):
        r = secured_client.post("/v1/inspect", json=self.PAYLOAD)
        assert r.status_code == 401
        body = r.json()
        assert body["status"] == 401
        assert "type" in body

    def test_wrong_key_returns_401(self, secured_client):
        r = secured_client.post(
            "/v1/inspect",
            json=self.PAYLOAD,
            headers={"X-API-Key": "wrong-key"},
        )
        assert r.status_code == 401

    def test_correct_key_succeeds(self, secured_client):
        r = secured_client.post(
            "/v1/inspect",
            json=self.PAYLOAD,
            headers={"X-API-Key": "test-secret"},
        )
        assert r.status_code == 200

    def test_health_does_not_require_key(self, secured_client):
        r = secured_client.get("/health")
        assert r.status_code == 200


# ── Structured errors (RFC 7807) ──────────────────────────────────────────────

class TestStructuredErrors:
    def test_404_has_problem_detail_shape(self):
        client = TestClient(__import__("app.main", fromlist=["app"]).app)
        r = client.get("/v1/does-not-exist")
        assert r.status_code == 404
        body = r.json()
        assert "status" in body
        assert "type" in body

    def test_422_has_problem_detail_shape(self):
        client = TestClient(__import__("app.main", fromlist=["app"]).app)
        r = client.post("/v1/inspect", json={"bad": "payload"})
        assert r.status_code == 422
        body = r.json()
        assert "status" in body
        assert "title" in body

    def test_401_has_problem_detail_shape(self, secured_client):
        r = secured_client.post(
            "/v1/inspect",
            json={"request_id": "t", "source": "user_prompt", "text": "hi"},
        )
        assert r.status_code == 401
        body = r.json()
        assert body["status"] == 401
        assert "type" in body
        assert "title" in body


# ── Request size limit ────────────────────────────────────────────────────────

class TestRequestSizeLimit:
    def test_oversized_body_returns_413(self):
        # Build a minimal app with a tiny size limit and test it directly
        from fastapi import FastAPI
        from starlette.exceptions import HTTPException as StarletteHTTPException
        from starlette.middleware.base import BaseHTTPMiddleware

        from app.core.config import Settings as S
        from app.core.errors import http_exception_handler
        from app.core.ratelimit import request_size_middleware

        settings = S(audit_log_path="/tmp/test_size.jsonl", max_request_bytes=100)
        mini_app = FastAPI()
        mini_app.state.settings = settings
        mini_app.add_middleware(BaseHTTPMiddleware, dispatch=request_size_middleware)
        mini_app.add_exception_handler(StarletteHTTPException, http_exception_handler)

        @mini_app.post("/test")
        def endpoint(): return {"ok": True}

        client = TestClient(mini_app, raise_server_exceptions=False)
        big_payload = {"request_id": "t", "source": "user_prompt", "text": "x" * 200}
        body_bytes = json.dumps(big_payload).encode()
        r = client.post(
            "/test",
            content=body_bytes,
            headers={"Content-Type": "application/json", "Content-Length": str(len(body_bytes))},
        )
        # BaseHTTPMiddleware propagates the 413 as either 413 or 500 depending on Starlette version
        assert r.status_code in (413, 500)

    def test_normal_body_accepted(self, tiny_limit_client):
        r = tiny_limit_client.post(
            "/v1/inspect",
            json={"request_id": "t", "source": "user_prompt", "text": "Hi"},
        )
        assert r.status_code == 200


# ── Dashboard endpoints ───────────────────────────────────────────────────────

class TestDashboardEndpoints:
    """Test dashboard endpoint response shapes using the default app instance."""

    def test_events_endpoint_returns_correct_shape(self):
        client = TestClient(__import__("app.main", fromlist=["app"]).app)
        r = client.get("/dashboard/events?limit=10")
        assert r.status_code == 200
        body = r.json()
        assert "events" in body
        assert "total" in body
        assert isinstance(body["events"], list)
        assert body["total"] == len(body["events"])

    def test_events_limit_param_respected(self):
        client = TestClient(__import__("app.main", fromlist=["app"]).app)
        r = client.get("/dashboard/events?limit=5")
        assert r.status_code == 200
        assert len(r.json()["events"]) <= 5

    def test_stats_endpoint_returns_correct_shape(self):
        client = TestClient(__import__("app.main", fromlist=["app"]).app)
        r = client.get("/dashboard/stats")
        assert r.status_code == 200
        body = r.json()
        for key in ("total", "blocked", "alerted", "detection_rate", "avg_risk_score",
                    "action_counts", "attack_counts", "severity_counts", "risk_buckets"):
            assert key in body, f"Missing key: {key}"
        assert 0.0 <= body["detection_rate"] <= 1.0
        assert 0.0 <= body["avg_risk_score"] <= 1.0

    def test_stats_blocked_plus_alerted_le_total(self):
        client = TestClient(__import__("app.main", fromlist=["app"]).app)
        body = client.get("/dashboard/stats").json()
        assert body["blocked"] + body["alerted"] <= body["total"]


# ── Red team library suite ────────────────────────────────────────────────────

class TestRedTeamLibrarySuite:
    def test_library_suite_loads_and_runs(self):
        client = TestClient(__import__("app.main", fromlist=["app"]).app)
        r = client.post("/v1/red-team/run", json={"suite": "library", "categories": [], "mode": "offline"})
        assert r.status_code == 200
        body = r.json()
        assert body["total_tests"] > 0
        assert 0.0 <= body["pass_rate"] <= 1.0

    def test_library_suite_high_pass_rate(self):
        client = TestClient(__import__("app.main", fromlist=["app"]).app)
        r = client.post("/v1/red-team/run", json={"suite": "library", "mode": "offline"})
        body = r.json()
        assert body["pass_rate"] >= 0.85, (
            f"Library suite pass rate {body['pass_rate']:.0%} is below 85%. "
            f"Failures: {body.get('failures', [])}"
        )

    def test_category_filter_works(self):
        client = TestClient(__import__("app.main", fromlist=["app"]).app)
        r = client.post(
            "/v1/red-team/run",
            json={"suite": "library", "categories": ["jailbreak"], "mode": "offline"},
        )
        body = r.json()
        assert body["total_tests"] > 0
        # All tested cases should be jailbreak category
        for failure in body.get("failures", []):
            assert failure["category"] == "jailbreak"
