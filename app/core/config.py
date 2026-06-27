from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "PromptSentry"
    app_version: str = "0.1.0"
    prompt_sentry_mode: Literal["monitor", "protect", "red_team"] = "protect"

    risk_monitor_threshold: float = Field(default=0.25, ge=0.0, le=1.0)
    risk_sanitize_threshold: float = Field(default=0.50, ge=0.0, le=1.0)
    risk_block_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    risk_alert_threshold: float = Field(default=0.90, ge=0.0, le=1.0)

    audit_log_sink: Literal["file", "stdout"] = "file"
    audit_log_path: Path = Path("logs/audit.jsonl")

    # API hardening
    api_key: str | None = None  # if set, all requests must supply X-API-Key header
    rate_limit_per_minute: int = Field(default=60, ge=1)
    max_request_bytes: int = Field(default=1_048_576, ge=1)  # 1 MiB

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


@lru_cache
def get_settings() -> Settings:
    return Settings()
