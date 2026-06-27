"""
Example 3 — Tool-calling agent with firewall on every tool call.

Agents that call tools (search, code execution, DB queries) are the highest-
risk LLM applications. A single injected instruction can make the agent delete
files, exfiltrate data, or send emails.

Shows:
  - Inspect user input
  - Review each tool call before executing it
  - Inspect tool output before feeding it back to the model
"""

import json
import uuid

import anthropic
import httpx

FIREWALL_URL = "http://localhost:8100"


def review_tool_call(tool_name: str, arguments: dict, allowed_tools: list[str]) -> bool:
    """
    Returns True if the tool call is safe to execute.
    """
    response = httpx.post(
        f"{FIREWALL_URL}/v1/review-tool-call",
        json={
            "request_id": f"tool_{uuid.uuid4().hex[:8]}",
            "tool_name": tool_name,
            "arguments": arguments,
            "metadata": {
                "allowed_tools": allowed_tools,
                "user_role": "user",
            },
        },
        timeout=5.0,
    )
    result = response.json()
    return result["action"] not in ("block", "alert")


def inspect_tool_output(output: str) -> str:
    """Inspect tool output before feeding it back to the model."""
    response = httpx.post(
        f"{FIREWALL_URL}/v1/inspect",
        json={
            "request_id": f"out_{uuid.uuid4().hex[:8]}",
            "source": "tool_output",
            "text": output,
        },
        timeout=5.0,
    )
    result = response.json()
    if result["action"] in ("block", "alert"):
        return "[Tool output blocked by security policy]"
    return result.get("sanitized_text") or output


# ── Fake tools ────────────────────────────────────────────────────────────────

def search_web(query: str) -> str:
    return f"Search results for '{query}': Paris is the capital of France."


def get_weather(city: str) -> str:
    return f"Weather in {city}: 22°C, sunny."


TOOL_REGISTRY = {
    "search_web": search_web,
    "get_weather": get_weather,
}

TOOLS = [
    {
        "name": "search_web",
        "description": "Search the web for information",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "get_weather",
        "description": "Get weather for a city",
        "input_schema": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
    },
]

ALLOWED_TOOLS = ["search_web", "get_weather"]


# ── Agent loop ────────────────────────────────────────────────────────────────

def run_agent(user_input: str) -> str:
    client = anthropic.Anthropic()
    messages = [{"role": "user", "content": user_input}]

    while True:
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            tools=TOOLS,
            messages=messages,
        )

        if response.stop_reason == "end_turn":
            # Extract final text response
            for block in response.content:
                if hasattr(block, "text"):
                    return block.text
            return ""

        if response.stop_reason != "tool_use":
            break

        # Process tool calls
        messages.append({"role": "assistant", "content": response.content})
        tool_results = []

        for block in response.content:
            if block.type != "tool_use":
                continue

            tool_name = block.name
            tool_args = block.input

            print(f"[AGENT] Tool call: {tool_name}({json.dumps(tool_args)})")

            # Firewall: review the tool call before executing
            if not review_tool_call(tool_name, tool_args, ALLOWED_TOOLS):
                print(f"[FIREWALL] Blocked tool call: {tool_name}")
                result_text = f"Tool call '{tool_name}' was blocked by security policy."
            elif tool_name not in TOOL_REGISTRY:
                result_text = f"Unknown tool: {tool_name}"
            else:
                # Execute the tool
                raw_output = TOOL_REGISTRY[tool_name](**tool_args)

                # Firewall: inspect the tool output before feeding back
                result_text = inspect_tool_output(raw_output)

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result_text,
            })

        messages.append({"role": "user", "content": tool_results})

    return "Agent loop ended unexpectedly."


if __name__ == "__main__":
    print(run_agent("What's the weather in Paris?"))
    print()
    print(run_agent("Search for information about the Eiffel Tower"))
