"""
PPO Policy — Proximal Policy Optimization for the Blue Agent's
fast-path decision making.

Uses Stable-Baselines3's PPO with a custom Gymnasium environment
that represents the Blue Agent's defensive state.

The observation space encodes:
  - anomaly score, detection confidence
  - attack type encoding, severity
  - endpoint hash
  - application health state
  - previous action history
  - Blue Memory signals

The action space maps to ``DefensiveAction`` (10 discrete actions).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import gymnasium as gym
import numpy as np
from gymnasium import spaces

from blue_agent.config import settings
from blue_agent.decision.action_space import ActionSpace, DefensiveAction
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import AttackEvent, PPODecision, Severity

log = get_logger("decision.ppo_policy")

# ---------------------------------------------------------------------------
# Attack-type encoding (known categories → integers)
# ---------------------------------------------------------------------------
_ATTACK_TYPE_MAP: Dict[str, int] = {
    "": 0,
    "unknown": 0,
    "sql_injection": 1,
    "SQL Injection": 1,
    "cross-site scripting": 2,
    "Cross-Site Scripting": 2,
    "xss": 2,
    "path_traversal": 3,
    "Path Traversal": 3,
    "command_injection": 4,
    "Command Injection": 4,
    "ssrf": 5,
    "SSRF": 5,
    "insecure_deserialization": 6,
    "brute_force": 7,
    "Reconnaissance Scan": 8,
    "reconnaissance": 8,
    "dos": 9,
    "privilege_escalation": 10,
}

_SEVERITY_MAP: Dict[Severity, float] = {
    Severity.UNKNOWN: 0.0,
    Severity.LOW: 0.25,
    Severity.MEDIUM: 0.5,
    Severity.HIGH: 0.75,
    Severity.CRITICAL: 1.0,
}

# ---------------------------------------------------------------------------
# Observation dimensions
# ---------------------------------------------------------------------------
# [anomaly_score, detection_confidence, attack_type_enc, severity_enc,
#  endpoint_hash, app_health, prev_action, prev_action_success,
#  failed_remediations, memory_similarity_score]
OBS_DIM = 10


def _endpoint_hash(endpoint: str) -> float:
    """Deterministic [0,1] hash of an endpoint string."""
    h = int(hashlib.md5(endpoint.encode()).hexdigest()[:8], 16)
    return h / 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Gymnasium Environment
# ---------------------------------------------------------------------------
class BlueAgentEnv(gym.Env):
    """
    Custom Gymnasium environment for the Blue Agent PPO policy.

    This environment is used both for:
      1. Training (with simulated attack/response loops)
      2. Inference (single-step: feed observation → get action)
    """

    metadata = {"render_modes": []}

    def __init__(self, action_space_def: Optional[ActionSpace] = None):
        super().__init__()
        self._action_space_def = action_space_def or ActionSpace()
        self.action_space = spaces.Discrete(self._action_space_def.n_actions)
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(OBS_DIM,), dtype=np.float32
        )
        # State for episodic training
        self._current_obs = np.zeros(OBS_DIM, dtype=np.float32)
        self._step_count = 0
        self._max_steps = 50

    def reset(
        self,
        *,
        seed: Optional[int] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        super().reset(seed=seed)
        self._current_obs = self.observation_space.sample()
        self._step_count = 0
        return self._current_obs.copy(), {}

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict[str, Any]]:
        self._step_count += 1
        reward = self._compute_reward(action, self._current_obs)

        # Simulate state transition
        self._current_obs = self.observation_space.sample()
        terminated = self._step_count >= self._max_steps
        truncated = False

        return self._current_obs.copy(), reward, terminated, truncated, {"action": action}

    def _compute_reward(self, action: int, obs: np.ndarray) -> float:
        """
        Reward function for training.

        Rewards correct responses:
        - High reward for blocking high-severity attacks
        - Penalty for no-action on severe attacks
        - Small penalty for unnecessary escalation
        - Reward for appropriate escalation when confidence is low
        """
        anomaly_score = obs[0]
        severity = obs[3]
        confidence = obs[1]

        reward = 0.0

        if action == DefensiveAction.NO_ACTION:
            if anomaly_score > 0.7:
                reward = -1.0 * severity  # Penalty for ignoring severe attacks
            else:
                reward = 0.1  # Small reward for correctly monitoring
        elif action == DefensiveAction.ESCALATE_TO_LLM:
            if confidence < 0.5:
                reward = 0.3  # Good: escalated when unsure
            else:
                reward = -0.2  # Wasted: could have handled it
        elif action in (
            DefensiveAction.BLOCK_SOURCE_IP,
            DefensiveAction.RATE_LIMIT_SOURCE,
            DefensiveAction.BLOCK_ENDPOINT,
        ):
            if anomaly_score > 0.5:
                reward = 0.5 + severity * 0.5  # Good blocking decision
            else:
                reward = -0.3  # False positive
        elif action == DefensiveAction.APPLY_KNOWN_PATCH:
            if severity > 0.5:
                reward = 0.8  # Patching high-severity vuln
            else:
                reward = 0.2
        elif action == DefensiveAction.ROLLBACK_PREVIOUS:
            reward = -0.1  # Mild penalty — rollback means a previous mistake

        return reward

    def set_observation(self, obs: np.ndarray) -> None:
        """Directly set observation for single-step inference."""
        self._current_obs = obs.copy()


# ---------------------------------------------------------------------------
# PPO Policy wrapper
# ---------------------------------------------------------------------------
class PPOPolicy:
    """
    Wraps Stable-Baselines3 PPO for defensive decision-making.

    Training
    --------
    ::
        policy = PPOPolicy()
        policy.train(total_timesteps=100_000)
        policy.save("models/ppo_policy")

    Inference
    ---------
    ::
        policy = PPOPolicy()
        policy.load("models/ppo_policy")
        decision = policy.decide(attack_event)
    """

    def __init__(self, action_space_def: Optional[ActionSpace] = None):
        self._action_space_def = action_space_def or ActionSpace()
        self._env = BlueAgentEnv(self._action_space_def)
        self._model = None
        self._loaded = False

    def train(self, total_timesteps: Optional[int] = None, **kwargs) -> None:
        """Train the PPO policy from scratch."""
        from stable_baselines3 import PPO as SB3_PPO

        timesteps = total_timesteps or settings.ppo.total_timesteps
        log.info("ppo_training_start", timesteps=timesteps)

        self._model = SB3_PPO(
            "MlpPolicy",
            self._env,
            learning_rate=settings.ppo.learning_rate,
            gamma=settings.ppo.gamma,
            n_steps=settings.ppo.n_steps,
            batch_size=settings.ppo.batch_size,
            n_epochs=settings.ppo.n_epochs,
            verbose=0,
            **kwargs,
        )
        self._model.learn(total_timesteps=timesteps)
        self._loaded = True
        log.info("ppo_training_complete")

    def save(self, path: Optional[str] = None) -> None:
        if self._model is None:
            raise RuntimeError("No model to save — train or load first")
        save_path = path or settings.ppo.model_path
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        self._model.save(save_path)
        log.info("ppo_model_saved", path=save_path)

    def load(self, path: Optional[str] = None) -> None:
        from stable_baselines3 import PPO as SB3_PPO

        load_path = path or settings.ppo.model_path
        self._model = SB3_PPO.load(load_path, env=self._env)
        self._loaded = True
        log.info("ppo_model_loaded", path=load_path)

    def decide(self, attack_event: AttackEvent, context: Optional[Dict[str, Any]] = None) -> PPODecision:
        """
        Make a defensive decision for a given attack event.

        Returns a ``PPODecision`` with the action, confidence,
        and reasoning.
        """
        obs = self._build_observation(attack_event, context or {})

        if self._model is not None and self._loaded:
            # SB3 predict returns (action, state)
            action_array, _states = self._model.predict(obs, deterministic=False)
            action = int(action_array)

            # Get action probabilities for confidence
            import torch
            obs_tensor = torch.tensor(obs.reshape(1, -1), dtype=torch.float32)
            with torch.no_grad():
                dist = self._model.policy.get_distribution(obs_tensor)
                probs = dist.distribution.probs.numpy().flatten()
            confidence = float(probs[action])
        else:
            # Fallback rule-based policy (before training)
            action, confidence = self._rule_based_fallback(attack_event, obs)

        action_meta = self._action_space_def.get(action)
        decision = PPODecision(
            action=action,
            action_name=action_meta.name,
            confidence=round(confidence, 4),
            reason=self._build_reason(action_meta.name, attack_event, confidence),
            state={"observation": obs.tolist()},
        )

        log.info(
            "ppo_decision",
            action=action_meta.name,
            confidence=round(confidence, 4),
            attack_type=attack_event.attack_type,
        )
        return decision

    def _build_observation(self, event: AttackEvent, context: Dict[str, Any]) -> np.ndarray:
        """Convert an attack event + context into the observation vector."""
        obs = np.zeros(OBS_DIM, dtype=np.float32)

        obs[0] = np.clip(event.anomaly_score, 0.0, 1.0)
        obs[1] = np.clip(event.detection_confidence, 0.0, 1.0)
        obs[2] = _ATTACK_TYPE_MAP.get(event.attack_type, 0) / max(len(_ATTACK_TYPE_MAP), 1)
        obs[3] = _SEVERITY_MAP.get(event.severity, 0.0)
        obs[4] = _endpoint_hash(event.endpoint)
        obs[5] = context.get("app_health", 1.0)
        obs[6] = context.get("prev_action", 0) / 9.0
        obs[7] = float(context.get("prev_action_success", True))
        obs[8] = min(1.0, context.get("failed_remediations", 0) / 5.0)
        obs[9] = context.get("memory_similarity", 0.0)

        return obs

    def _rule_based_fallback(self, event: AttackEvent, obs: np.ndarray) -> Tuple[int, float]:
        """
        Deterministic rule-based fallback when no trained model exists.

        Returns (action_id, confidence).
        """
        score = event.anomaly_score
        attack = event.attack_type.lower()

        # Known attack types with high confidence → direct action
        if attack in ("sql injection", "sql_injection") and score > 0.6:
            return DefensiveAction.APPLY_KNOWN_PATCH, 0.85
        if attack in ("cross-site scripting", "xss") and score > 0.6:
            return DefensiveAction.APPLY_KNOWN_PATCH, 0.80
        if attack in ("command injection", "command_injection") and score > 0.6:
            return DefensiveAction.DISABLE_ENDPOINT, 0.82
        if attack in ("path traversal", "path_traversal") and score > 0.6:
            return DefensiveAction.BLOCK_ENDPOINT, 0.78
        if attack in ("reconnaissance scan", "reconnaissance") and score > 0.5:
            return DefensiveAction.RATE_LIMIT_SOURCE, 0.75
        if attack in ("brute_force",) and score > 0.5:
            return DefensiveAction.BLOCK_SOURCE_IP, 0.80

        # High anomaly but unknown type → escalate
        if score > 0.7:
            return DefensiveAction.ESCALATE_TO_LLM, 0.45

        # Moderate anomaly → rate limit
        if score > 0.5:
            return DefensiveAction.RATE_LIMIT_SOURCE, 0.55

        # Low anomaly → monitor
        return DefensiveAction.NO_ACTION, 0.70

    def _build_reason(self, action_name: str, event: AttackEvent, confidence: float) -> str:
        parts = []
        if event.attack_type:
            parts.append(f"Detected {event.attack_type}")
        parts.append(f"anomaly_score={event.anomaly_score:.2f}")
        parts.append(f"confidence={confidence:.2f}")
        parts.append(f"→ {action_name}")
        return " | ".join(parts)

    @property
    def is_loaded(self) -> bool:
        return self._loaded
