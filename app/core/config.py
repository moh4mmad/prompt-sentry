from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "PromptSentry"
    app_version: str = "0.1.0"
    app_environment: Literal["development", "test", "production"] = "development"
    docs_enabled: bool = True
    enable_hsts: bool = False
    prompt_sentry_mode: Literal["monitor", "protect", "red_team"] = "protect"

    risk_monitor_threshold: float = Field(default=0.25, ge=0.0, le=1.0)
    risk_sanitize_threshold: float = Field(default=0.50, ge=0.0, le=1.0)
    risk_block_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    risk_alert_threshold: float = Field(default=0.90, ge=0.0, le=1.0)

    audit_log_sink: Literal["file", "stdout", "postgres"] = "file"
    audit_log_path: Path = Path("logs/audit.jsonl")
    database_url: str | None = None
    audit_include_redacted_input: bool = True

    # API hardening
    api_key: str | None = None  # if set, all requests must supply X-API-Key header
    rate_limit_per_minute: int = Field(default=60, ge=1)
    rate_limit_backend: Literal["memory", "redis"] = "memory"
    redis_url: str | None = None
    rate_limit_fail_open: bool = False
    max_request_bytes: int = Field(default=1_048_576, ge=1)  # 1 MiB
    trusted_proxy_cidrs: str = ""
    cors_allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3100,http://127.0.0.1:3100"
    dashboard_api_key: str | None = None

    # LLM classifier (opt-in)
    llm_classifier_enabled: bool = False
    llm_classifier_provider: Literal["anthropic", "openai", "bedrock"] = "anthropic"
    llm_classifier_model: str = "claude-haiku-4-5-20251001"
    llm_classifier_api_key: str | None = None  # Anthropic or OpenAI key; Bedrock uses IAM
    llm_classifier_weight: float = Field(default=0.6, ge=0.0, le=1.0)
    rule_classifier_weight: float = Field(default=0.4, ge=0.0, le=1.0)

    # Bedrock-specific
    llm_classifier_aws_region: str = "us-east-1"
    # OpenAI-compatible base URL override (e.g. Azure OpenAI, local Ollama)
    llm_classifier_openai_base_url: str | None = None

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        thresholds = (
            self.risk_monitor_threshold,
            self.risk_sanitize_threshold,
            self.risk_block_threshold,
            self.risk_alert_threshold,
        )
        if abs((self.rule_classifier_weight + self.llm_classifier_weight) - 1.0) > 0.0001:
            raise ValueError("Classifier weights must sum to 1.0")
        if self.audit_log_sink == "postgres" and not self.database_url:
            raise ValueError("DATABASE_URL is required when AUDIT_LOG_SINK=postgres")
        if self.rate_limit_backend == "redis" and not self.redis_url:
            raise ValueError("REDIS_URL is required when RATE_LIMIT_BACKEND=redis")
        if self.app_environment == "production":
            if thresholds != tuple(sorted(thresholds)):
                raise ValueError("Risk thresholds must be ordered monitor <= sanitize <= block <= alert")
            missing = []
            if not self.api_key:
                missing.append("API_KEY")
            if not self.dashboard_api_key:
                missing.append("DASHBOARD_API_KEY")
            if self.audit_log_sink != "postgres":
                missing.append("AUDIT_LOG_SINK=postgres")
            if self.rate_limit_backend != "redis":
                missing.append("RATE_LIMIT_BACKEND=redis")
            if self.docs_enabled:
                missing.append("DOCS_ENABLED=false")
            if not self.enable_hsts:
                missing.append("ENABLE_HSTS=true")
            if missing:
                raise ValueError("Unsafe production configuration: " + ", ".join(missing))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
