from __future__ import annotations

from typing import Any


class PromptSentryError(RuntimeError):
    """Base error for the PromptSentry SDK."""


class PromptSentryUnavailable(PromptSentryError):
    """The policy service could not return a decision."""


class PromptSentryBlocked(PromptSentryError):
    def __init__(
        self,
        *,
        action: str,
        risk_score: float,
        attack_types: tuple[str, ...] = (),
        reason: str | None = None,
        request_id: str | None = None,
    ) -> None:
        self.action = action
        self.risk_score = risk_score
        self.attack_types = attack_types
        self.reason = reason
        self.request_id = request_id
        detail = reason or ", ".join(attack_types) or "security policy"
        super().__init__(f"PromptSentry denied the operation ({action}, score={risk_score:.2f}): {detail}")


def safe_tool_error(reason: str, *, code: str = "promptsentry_denied") -> str:
    import json

    return json.dumps({"ok": False, "error": {"code": code, "message": reason}}, sort_keys=True)


def json_safe(value: Any) -> str:
    import json

    if isinstance(value, str):
        return value
    return json.dumps(value, default=str, sort_keys=True, separators=(",", ":"))
