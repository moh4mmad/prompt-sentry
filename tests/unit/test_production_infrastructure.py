from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.core.ratelimit import _untrusted_forwarded_address
from app.logging.audit import AuditLogger


def make_app(settings: Settings):
    import app.main as main_module

    original = main_module.get_settings
    main_module.get_settings = lambda: settings
    try:
        return main_module.create_app()
    finally:
        main_module.get_settings = original


def test_production_rejects_single_instance_backends() -> None:
    with pytest.raises(ValidationError, match="Unsafe production configuration"):
        Settings(app_environment="production", api_key="api", dashboard_api_key="dashboard")


def test_thresholds_must_be_ordered() -> None:
    with pytest.raises(ValidationError, match="Risk thresholds must be ordered"):
        Settings(
            app_environment="production",
            api_key="api",
            dashboard_api_key="dashboard",
            audit_log_sink="postgres",
            database_url="postgresql://example",
            rate_limit_backend="redis",
            redis_url="redis://example",
            docs_enabled=False,
            enable_hsts=True,
            risk_monitor_threshold=0.8,
            risk_block_threshold=0.7,
        )


def test_classifier_weights_must_sum_to_one() -> None:
    with pytest.raises(ValidationError, match="Classifier weights must sum to 1.0"):
        Settings(rule_classifier_weight=0.9, llm_classifier_weight=0.9)


def test_dashboard_endpoints_require_separate_key(tmp_path: Path) -> None:
    settings = Settings(audit_log_path=tmp_path / "audit.jsonl", dashboard_api_key="dashboard-secret")
    with TestClient(make_app(settings)) as client:
        assert client.get("/dashboard/events").status_code == 401
        response = client.get("/dashboard/events", headers={"X-Dashboard-Key": "dashboard-secret"})
        assert response.status_code == 200


def test_audit_can_omit_redacted_prompt_content(tmp_path: Path) -> None:
    settings = Settings(
        audit_log_path=tmp_path / "audit.jsonl",
        audit_include_redacted_input=False,
    )
    logger = AuditLogger(settings)
    logger.log({"action": "block"}, raw_text="private customer prompt")
    event = logger.read_events(1)[0]
    assert "input_hash" in event
    assert "redacted_input" not in event


def test_readiness_for_local_backends() -> None:
    settings = Settings()
    with TestClient(make_app(settings)) as client:
        response = client.get("/ready")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"


def test_chunked_or_declared_oversized_body_is_rejected() -> None:
    settings = Settings(max_request_bytes=64)
    with TestClient(make_app(settings)) as client:
        response = client.post(
            "/v1/inspect",
            content=b"x" * 65,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413
        assert response.json()["status"] == 413


def test_forwarded_chain_ignores_spoofed_leftmost_address() -> None:
    address = _untrusted_forwarded_address(
        "203.0.113.99, 198.51.100.8, 10.0.0.9",
        "10.0.0.0/8",
    )
    assert address == "198.51.100.8"
