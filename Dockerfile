FROM python:3.11-slim-bookworm

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git patch nodejs npm \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
ENV PIP_DEFAULT_TIMEOUT=300
ENV PIP_RETRIES=10
RUN python -m pip install --upgrade pip
RUN python -m pip install --no-cache-dir --default-timeout=600 --retries=20 \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    -r requirements.txt

COPY blue_agent/ /app/blue_agent/
COPY red_agent/ /app/red_agent/
COPY target_platform/ /app/target_platform/
COPY targets/ /app/targets/
COPY target_gateway/ /app/target_gateway/
COPY models/ /app/models/
COPY rules/ /app/rules/
COPY target_app/requirements.txt /app/target_app/requirements.txt
RUN python -m pip install --default-timeout=300 --retries=10 -r /app/target_app/requirements.txt
RUN python -m pip install --no-cache-dir pip-audit semgrep

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Pre-download the embedding model so it doesn't block the healthcheck on startup
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

EXPOSE 8000

CMD ["uvicorn", "blue_agent.api.routes:app", "--host", "0.0.0.0", "--port", "8000"]
