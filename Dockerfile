FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (layer cache)
# .[llm] includes Anthropic SDK. For other providers:
#   OpenAI/Azure/Ollama → change to ".[llm,llm-openai]"
#   AWS Bedrock         → change to ".[llm,llm-bedrock]"
#   All providers       → change to ".[all]"
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[llm]"

# Copy source
COPY app/ ./app/
COPY attack_library/ ./attack_library/

RUN mkdir -p logs

EXPOSE 8100

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8100"]
