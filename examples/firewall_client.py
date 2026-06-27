"""
Drop-in PromptSentry client.

Usage:
    from firewall_client import firewall, FirewallBlocked

    safe_text = firewall(user_input, source="user_prompt")
    # safe_text is either the original text (allowed) or sanitized text
    # raises FirewallBlocked if the input is blocked/alerted
"""

import os
import uuid

import httpx

FIREWALL_URL = os.getenv("FIREWALL_URL", "http://localhost:8100")
FIREWALL_API_KEY = os.getenv("FIREWALL_API_KEY")  # optional


class FirewallBlocked(Exception):
    """Raised when the firewall blocks or alerts on a request."""

    def __init__(self, action: str, risk_score: float, attack_types: list[str]):
        self.action = action
        self.risk_score = risk_score
        self.attack_types = attack_types
        super().__init__(
            f"Request blocked by PromptSentry "
            f"(action={action}, score={risk_score:.2f}, attacks={attack_types})"
        )


def firewall(
    text: str,
    *,
    source: str = "user_prompt",
    tenant_id: str | None = None,
    user_id: str | None = None,
    session_id: str | None = None,
    raise_on_block: bool = True,
) -> str:
    """
    Inspect text through the PromptSentry.

    Returns the text safe to send to the LLM:
    - If allowed:   returns original text
    - If sanitized: returns cleaned text
    - If blocked:   raises FirewallBlocked (or returns "" if raise_on_block=False)
    """
    headers = {"Content-Type": "application/json"}
    if FIREWALL_API_KEY:
        headers["X-API-Key"] = FIREWALL_API_KEY

    payload = {
        "request_id": f"req_{uuid.uuid4().hex[:12]}",
        "source": source,
        "text": text,
    }
    if tenant_id:
        payload["tenant_id"] = tenant_id
    if user_id:
        payload["user_id"] = user_id
    if session_id:
        payload["session_id"] = session_id

    response = httpx.post(
        f"{FIREWALL_URL}/v1/inspect",
        json=payload,
        headers=headers,
        timeout=5.0,
    )
    response.raise_for_status()
    result = response.json()

    action = result["action"]

    if action in ("block", "alert"):
        attack_types = [f["attack_type"] for f in result.get("findings", [])]
        if raise_on_block:
            raise FirewallBlocked(action, result["risk_score"], attack_types)
        return ""

    # sanitize returns cleaned text; allow/monitor return original
    return result.get("sanitized_text") or text
