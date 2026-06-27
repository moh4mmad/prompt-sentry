"""
Example 2 — RAG pipeline with firewall on both sides.

The most important integration pattern. Indirect injection (malicious
instructions hidden in documents) is the biggest real-world threat to RAG
apps. You need to inspect retrieved content before it goes into the prompt.

Shows:
  - Inspect user question (source=user_prompt)
  - Inspect each retrieved chunk (source=retrieved_document)
  - Inspect model output before returning to user (source=model_output)
"""

import anthropic
from firewall_client import FirewallBlocked, firewall


def retrieve_documents(query: str) -> list[dict]:
    """Stub — replace with your actual vector DB call."""
    return [
        {"id": "doc_1", "text": "Paris is the capital of France. Population 2.1M."},
        {"id": "doc_2", "text": "The Eiffel Tower was built in 1889."},
        # In real life, one of these might contain injected instructions
    ]


def rag_query(user_question: str, user_id: str = "anon") -> str:
    # Step 1: check the user's question
    try:
        safe_question = firewall(
            user_question,
            source="user_prompt",
            user_id=user_id,
        )
    except FirewallBlocked:
        return "I can't process that request."

    # Step 2: retrieve documents
    docs = retrieve_documents(safe_question)

    # Step 3: inspect each retrieved chunk before injecting into the prompt
    safe_chunks = []
    for doc in docs:
        try:
            safe_text = firewall(
                doc["text"],
                source="retrieved_document",
                user_id=user_id,
            )
            safe_chunks.append(safe_text)
        except FirewallBlocked as e:
            # Log the suspicious document and skip it
            print(f"[FIREWALL] Blocked document {doc['id']}: {e}")
            # Don't include it in the prompt at all

    if not safe_chunks:
        return "No safe documents found to answer your question."

    context = "\n\n".join(safe_chunks)

    # Step 4: call the LLM with clean context
    client = anthropic.Anthropic()
    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=1024,
        system="Answer questions using only the provided context.",
        messages=[
            {
                "role": "user",
                "content": f"Context:\n{context}\n\nQuestion: {safe_question}",
            }
        ],
    )
    response_text = message.content[0].text

    # Step 5: verify the output doesn't leak secrets
    try:
        return firewall(response_text, source="model_output", user_id=user_id)
    except FirewallBlocked:
        return "The response was blocked for containing sensitive data."


if __name__ == "__main__":
    print(rag_query("What is the capital of France?"))
    print()

    # This would be blocked if a doc contained injection instructions
    print(rag_query("Tell me about Paris"))
