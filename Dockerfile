FROM python:3.12-slim AS runtime

WORKDIR /app

# Install dependencies first (layer cache)
# .[llm] includes Anthropic SDK. For other providers:
#   OpenAI/Azure/Ollama → change to ".[llm,llm-openai]"
#   AWS Bedrock         → change to ".[llm,llm-bedrock]"
#   All providers       → change to ".[all]"
COPY app/ ./app/
COPY attack_library/ ./attack_library/
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir ".[production,llm]"

RUN addgroup --system prompt-sentry \
    && adduser --system --ingroup prompt-sentry --home /app prompt-sentry \
    && mkdir -p logs \
    && chown -R prompt-sentry:prompt-sentry /app

USER prompt-sentry

EXPOSE 8100

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8100", "--workers", "2", "--no-access-log"]
