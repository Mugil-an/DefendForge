# Technology Stack

- Language/runtime: Python `>=3.10`; Docker Blue Agent image uses Python 3.11 slim.
- Target framework: Flask `>=3.0`, Gunicorn `>=22.0`.
- Blue API: FastAPI `>=0.110,<1.0`, Uvicorn, Pydantic 2.
- HTTP clients: HTTPX; flow forwarding uses Requests.
- Persistence: bundled target uses SQLite; Blue Agent is configured for PostgreSQL via SQLAlchemy, asyncpg, and psycopg.
- Detection/ML: PyTorch, scikit-learn, pandas, NumPy, joblib, Stable-Baselines3, Gymnasium.
- LLM/RAG: OpenAI client, Sentence Transformers, FAISS, tiktoken.
- Security tooling: optional Semgrep and Bandit CLI integration.
- Runtime services in Compose: PostgreSQL/pgvector, MinIO, Elasticsearch, Kibana, target Flask app, Blue Agent, Red Agent, and flow sniffer.

Target integration constraints visible in the current stack are HTTP/HTTPS health checks, local filesystem scanning, pytest-based validation, and Docker-network service naming.
