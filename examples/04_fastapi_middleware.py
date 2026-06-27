"""
Example 4 — FastAPI app with firewall as a dependency.

If your app is already FastAPI, you can add firewall inspection as a
reusable dependency that runs before any endpoint that calls an LLM.

Run:
    pip install fastapi uvicorn anthropic httpx
    uvicorn 04_fastapi_middleware:app --reload --port 8001
"""

import uuid

import anthropic
import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel

FIREWALL_URL = "http://localhost:8100"

app = FastAPI(title="My AI App")


# ── Firewall dependency ───────────────────────────────────────────────────────

async def require_clean_prompt(request: Request) -> str:
    """
    FastAPI dependency — inspects the request body text before the handler runs.
    Returns the safe text (original or sanitized).
    Raises 400 if blocked.
    """
    body = await request.json()
    text = body.get("message", "")
    if not text:
        return text

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{FIREWALL_URL}/v1/inspect",
            json={
                "request_id": f"req_{uuid.uuid4().hex[:12]}",
                "source": "user_prompt",
                "text": text,
                "user_id": body.get("user_id"),
            },
            timeout=5.0,
        )

    result = resp.json()
    action = result["action"]

    if action in ("block", "alert"):
        attack_types = [f["attack_type"] for f in result.get("findings", [])]
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Request blocked by security policy",
                "attack_types": attack_types,
            },
        )

    # Return sanitized text if action was "sanitize", otherwise original
    return result.get("sanitized_text") or text


# ── Endpoints ─────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str
    user_id: str | None = None


class ChatResponse(BaseModel):
    reply: str
    request_id: str


@app.post("/chat", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    safe_text: str = Depends(require_clean_prompt),
):
    """Chat endpoint — firewall runs before the LLM call."""
    client = anthropic.Anthropic()
    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=1024,
        system="You are a helpful assistant.",
        messages=[{"role": "user", "content": safe_text}],
    )

    return ChatResponse(
        reply=message.content[0].text,
        request_id=f"req_{uuid.uuid4().hex[:8]}",
    )


@app.get("/health")
def health():
    return {"status": "ok"}
