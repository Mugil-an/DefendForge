"""
Central configuration for the Blue Agent.

All settings are loaded from environment variables with sensible
defaults.  Import ``settings`` anywhere in the codebase:

    from blue_agent.config import settings
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


def _env_int(key: str, default: int = 0) -> int:
    return int(os.getenv(key, str(default)))


def _env_float(key: str, default: float = 0.0) -> float:
    return float(os.getenv(key, str(default)))


def _env_bool(key: str, default: bool = False) -> bool:
    return os.getenv(key, str(default)).lower() in ("1", "true", "yes")


def _env_list(key: str, default: str = "") -> List[str]:
    raw = os.getenv(key, default)
    return [item.strip() for item in raw.split(",") if item.strip()] if raw else []


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BLUE_AGENT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
PATCHES_DIR = PROJECT_ROOT / "patches"
LOGS_DIR = PROJECT_ROOT / "logs"


@dataclass
class DatabaseSettings:
    host: str = _env("POSTGRES_HOST", "localhost")
    port: int = _env_int("POSTGRES_PORT", 5432)
    user: str = _env("POSTGRES_USER", "blue_agent")
    password: str = _env("POSTGRES_PASSWORD", "blue_agent_secret")
    database: str = _env("POSTGRES_DB", "blue_memory")

    @property
    def url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.database}"
        )

    @property
    def sync_url(self) -> str:
        return (
            f"postgresql://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.database}"
        )


@dataclass
class LLMSettings:
    """Configurable LLM provider (openai / deepseek / ollama)."""
    provider: str = _env("LLM_PROVIDER", "openai")          # openai | deepseek | ollama
    api_key: str = _env("LLM_API_KEY", "")
    base_url: str = _env("LLM_BASE_URL", "")                # override for deepseek / ollama
    model: str = _env("LLM_MODEL", "gpt-4o")
    temperature: float = _env_float("LLM_TEMPERATURE", 0.2)
    max_tokens: int = _env_int("LLM_MAX_TOKENS", 4096)
    timeout: int = _env_int("LLM_TIMEOUT", 60)

    @property
    def effective_base_url(self) -> str:
        if self.base_url:
            return self.base_url
        if self.provider == "deepseek":
            return "https://api.deepseek.com/v1"
        if self.provider == "ollama":
            return "http://localhost:11434/v1"
        return "https://api.openai.com/v1"


@dataclass
class RAGSettings:
    embedding_model: str = _env("RAG_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    vector_store: str = _env("RAG_VECTOR_STORE", "faiss")   # faiss | pgvector | pinecone
    faiss_index_path: str = _env(
        "RAG_FAISS_INDEX_PATH",
        str(DATA_DIR / "faiss_index"),
    )
    top_k: int = _env_int("RAG_TOP_K", 5)
    similarity_threshold: float = _env_float("RAG_SIMILARITY_THRESHOLD", 0.45)


@dataclass
class DetectionSettings:
    backend: str = _env("DETECTION_BACKEND", "isolation_forest")  # isolation_forest | autoencoder
    model_path: str = _env(
        "DETECTION_MODEL_PATH",
        str(MODELS_DIR / "isolation_forest.joblib"),
    )
    anomaly_threshold: float = _env_float("DETECTION_ANOMALY_THRESHOLD", 0.5)
    sliding_window_seconds: int = _env_int("DETECTION_WINDOW_SECONDS", 60)
    min_events_for_alert: int = _env_int("DETECTION_MIN_EVENTS", 3)


@dataclass
class PPOSettings:
    model_path: str = _env("PPO_MODEL_PATH", str(MODELS_DIR / "ppo_policy"))
    confidence_threshold: float = _env_float("PPO_CONFIDENCE_THRESHOLD", 0.80)
    learning_rate: float = _env_float("PPO_LEARNING_RATE", 3e-4)
    gamma: float = _env_float("PPO_GAMMA", 0.99)
    n_steps: int = _env_int("PPO_N_STEPS", 2048)
    batch_size: int = _env_int("PPO_BATCH_SIZE", 64)
    n_epochs: int = _env_int("PPO_N_EPOCHS", 10)
    total_timesteps: int = _env_int("PPO_TOTAL_TIMESTEPS", 100_000)


@dataclass
class AuditSettings:
    target_app_path: str = _env("TARGET_APP_PATH", str(PROJECT_ROOT / "target_app"))
    target_app_url: str = _env("TARGET_APP_URL", "http://target-app:5000")
    semgrep_rules: str = _env("SEMGREP_RULES", "p/python")
    bandit_config: str = _env("BANDIT_CONFIG", "")
    dependency_check_path: str = _env(
        "DEPENDENCY_CHECK_PATH", "/usr/local/bin/dependency-check"
    )


@dataclass
class ValidationSettings:
    test_dir: str = _env("VALIDATION_TEST_DIR", str(PROJECT_ROOT / "tests"))
    timeout_seconds: int = _env_int("VALIDATION_TIMEOUT", 300)
    health_check_url: str = _env(
        "VALIDATION_HEALTH_URL", "http://target-app:5000/health"
    )
    health_check_retries: int = _env_int("VALIDATION_HEALTH_RETRIES", 5)
    health_check_interval: int = _env_int("VALIDATION_HEALTH_INTERVAL", 3)


@dataclass
class MonitoringSettings:
    log_level: str = _env("LOG_LEVEL", "INFO")
    log_file: str = _env("LOG_FILE", str(LOGS_DIR / "blue_agent.log"))
    metrics_export_interval: int = _env_int("METRICS_EXPORT_INTERVAL", 30)


@dataclass
class SecuritySettings:
    """Hard-coded safety constraints — do NOT override lightly."""
    max_patch_size_kb: int = 256
    max_rollback_depth: int = 10
    tool_allowlist: List[str] = field(default_factory=lambda: [
        "inspect_file",
        "inspect_logs",
        "inspect_process",
        "inspect_dependencies",
        "run_semgrep",
        "run_bandit",
        "run_dependency_check",
        "block_ip",
        "rate_limit",
        "update_security_rule",
        "apply_patch",
        "run_tests",
        "rollback_patch",
        "restart_service",
    ])


@dataclass
class RedAgentSettings:
    """Configuration for the simulated Red Agent adversary."""
    target_url: str = _env("RED_AGENT_TARGET_URL", "http://target-app:5000")
    attack_intensity: str = _env("RED_AGENT_INTENSITY", "medium")  # low | medium | high
    benign_ratio: float = _env_float("RED_AGENT_BENIGN_RATIO", 0.3)
    scenario_duration: int = _env_int("RED_AGENT_SCENARIO_DURATION", 60)
    enabled_attacks: List[str] = field(default_factory=lambda: [
        "sql_injection", "xss", "path_traversal", "command_injection",
        "ssrf", "reconnaissance", "brute_force",
    ])


@dataclass
class Settings:
    """Aggregate of every sub-configuration."""
    db: DatabaseSettings = field(default_factory=DatabaseSettings)
    llm: LLMSettings = field(default_factory=LLMSettings)
    rag: RAGSettings = field(default_factory=RAGSettings)
    detection: DetectionSettings = field(default_factory=DetectionSettings)
    ppo: PPOSettings = field(default_factory=PPOSettings)
    audit: AuditSettings = field(default_factory=AuditSettings)
    validation: ValidationSettings = field(default_factory=ValidationSettings)
    monitoring: MonitoringSettings = field(default_factory=MonitoringSettings)
    security: SecuritySettings = field(default_factory=SecuritySettings)
    red: RedAgentSettings = field(default_factory=RedAgentSettings)

    # ---- global knobs ----
    round_number: int = _env_int("ROUND_NUMBER", 0)
    environment: str = _env("ENVIRONMENT", "development")
    debug: bool = _env_bool("DEBUG", False)

    @property
    def database_url(self) -> str:
        """Backward-compatible alias for db.sync_url."""
        return self.db.sync_url


# Singleton
settings = Settings()
