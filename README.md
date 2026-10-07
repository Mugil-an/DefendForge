# DefendForge

![Build Status](https://img.shields.io/badge/build-passing-brightgreen) ![License](https://img.shields.io/badge/license-MIT-blue) ![Python](https://img.shields.io/badge/python-3.10%2B-blue)

**DefendForge** is a Collaborative Multi-Agent Cybersecurity Hardening system. It features an autonomous Blue Agent (defender) that actively monitors, detects, and remediates vulnerabilities in a deliberately vulnerable Flask application, while a Red Agent (simulated adversary) generates synthetic attack traffic.

## Architecture Overview

The system operates as a continuous loop between the Red Agent and the Blue Agent, acting on the Target Application.

```text
+-------------------+       Attack Traffic        +-------------------+
|                   | --------------------------> |                   |
|    Red Agent      |                             |   Target App      |
|  (Simulated Att.) | <-------------------------- | (Vulnerable App)  |
|                   |        Responses            |                   |
+-------------------+                             +-------------------+
                                                            |
                                                            | Logs / Metrics / Traffic
                                                            v
                                                  +-------------------+
                                                  |                   |
                                                  |    Blue Agent     |
                                                  |   (Autonomous     |
                                                  |     Defender)     |
                                                  |                   |
                                                  +-------------------+
```

The Blue Agent analyzes logs and traffic, makes decisions using a PPO (Proximal Policy Optimization) RL agent, and falls back to an LLM for complex reasoning. It dynamically retrieves remediation strategies using RAG (Retrieval-Augmented Generation) and applies patches or hardens the application.

### Current build scope

The implemented dashboard covers the complete Phase 1 loop: isolated target traffic,
Red/Green activity, Blue detection, confidence-gated fast/slow routing, remediation
validation, rollback visibility, hardening, memory, and multi-round metrics. Phase 2
(self-evolving moving-target defense and its held-out comparison) is intentionally
excluded from this build.

Open the dashboard to see the actual event stream and the attack path
`RECON -> DETECT -> ROUTE -> REMEDIATE -> VALIDATE -> HARDEN`. Ground truth is shown
separately from the defender result, so missed detections are not presented as
successful blocks. The Research novelty panel is backed by `/api/research/novelty`
and maps implemented integrations to the supplied papers. It deliberately does not
claim that DefendForge originated those research ideas. The self-evolving moving
target defense work is displayed as a Phase 2 reference only and is not implemented.

## Features

- **Detection**: Real-time traffic analysis and anomaly detection.
- **Decision Engine (PPO RL)**: Reinforcement Learning model to decide on mitigation actions.
- **LLM Reasoning**: Escalation to Large Language Models for complex, unseen attacks.
- **RAG (Knowledge Ingestion)**: Dynamically fetches mitigation strategies from a built-in cybersecurity knowledge base.
- **Remediation & Hardening**: Automated code patching, WAF rule generation, and IP blocklisting.
- **Memory**: Tracks past attacks and successful mitigations to avoid repeated mistakes.
- **Metrics**: Real-time tracking of Time-to-Detect (TTD), Time-to-Remediate (TTR), precision, and recall.
- **Safety Broker**: Validates all automated code changes to ensure they do not break application functionality.
- **API**: REST API for monitoring metrics, triggering actions, and viewing agent status.
- **Red Agent**: Automated attack simulation suite generating SQLi, XSS, SSRF, and other common exploits.
- **Autonomous Red Campaigns**: Bounded, simulation-only campaigns that use local attack knowledge, adapt to campaign history, and stream decisions to the dashboard.

## Quick Start

### Prerequisites
- Python 3.10+
- pip and virtualenv

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/DefendForge.git
   cd DefendForge
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

### Run Demo / Simulation

1. Start the Target Application:
   ```bash
   python -m target_app.app
   ```

2. Start the Blue Agent:
   ```bash
   python -m blue_agent.main
   ```

3. Launch the Red Agent:
   ```bash
   python -m red_agent.simulate
   ```

### Run an Autonomous Red Campaign

The autonomous Red Agent uses real HTTP requests against the bundled target by
default. It is deliberately restricted to `localhost`, loopback, and the
`target_app` Docker service; external hosts are rejected. Each campaign is bounded
by a maximum number of rounds and events, selects the next attack type from local
structured knowledge, and sends the resulting traffic through the Blue Agent.
Set `RED_SIMULATION_ONLY=true` only for deterministic generated traffic.

Start the dashboard API:

```bash
python -m uvicorn blue_agent.api.routes:app --host 127.0.0.1 --port 8000
```

Then open `http://127.0.0.1:8000/` and choose **Start Autonomous**.

The same operation is available through the API:

```bash
curl -X POST http://127.0.0.1:8000/api/red/campaign/start \
  -H "Content-Type: application/json" \
  -d "{\"rounds\":5,\"max_events\":25}"
```

Campaign status is available at `/api/red/campaign`, and campaign decisions and
attack results are streamed over the dashboard WebSocket as `campaign` and
`attack` events.

## Project Structure

```
DefendForge/
├── blue_agent/             # Autonomous defender modules
│   ├── audit/              # Log and configuration auditing
│   ├── detection/          # Anomaly and threat detection
│   ├── decision/           # PPO RL models and decision logic
│   ├── llm_reasoning/      # LLM integration for complex scenarios
│   ├── rag/                # Knowledge ingestion and retrieval
│   ├── remediation/        # Automated patching and mitigation
│   ├── hardening/          # Proactive security hardening
│   ├── memory/             # State and history tracking
│   ├── metrics/            # Performance and accuracy metrics
│   └── safety_broker/      # Code validation and safety checks
├── red_agent/              # Simulated adversary suite
├── target_app/             # Deliberately vulnerable Flask app
├── rules/                  # WAF rules and IP blocklists (JSON)
├── tests/                  # Unit and integration tests
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```

## Configuration

The system is configured via environment variables. Key variables include:

| Environment Variable       | Description                                      | Default                     |
|----------------------------|--------------------------------------------------|-----------------------------|
| `OPENAI_API_KEY`           | API key for LLM reasoning features               | `""`                        |
| `TARGET_APP_URL`           | URL of the target vulnerable application         | `http://localhost:5000`     |
| `BLUE_AGENT_PORT`          | Port for the Blue Agent API                      | `8000`                      |
| `LOG_LEVEL`                | Logging verbosity (DEBUG, INFO, WARNING, ERROR)  | `INFO`                      |
| `MAX_ESCALATIONS`          | Max allowed LLM escalations per round            | `5`                         |
| `RED_SIMULATION_ONLY`   | Use generated traffic instead of live local HTTP | `false`                      |
| `RED_TARGET_URL`        | Bundled target URL; must remain local           | `http://localhost:5000`      |
| `RED_REQUEST_TIMEOUT`   | Timeout for each live request in seconds        | `5`                          |
| `RED_MAX_CAMPAIGN_ROUNDS` | Default autonomous campaign round limit       | `5`                         |
| `RED_MAX_CAMPAIGN_EVENTS` | Default autonomous campaign event limit       | `25`                        |

*(Configuration is managed via dataclasses in `blue_agent/config.py`)*

## API Endpoints

The Blue Agent exposes a REST API for monitoring:

| Endpoint                  | Method | Description                              |
|---------------------------|--------|------------------------------------------|
| `/api/status`             | GET    | Get the current operational status       |
| `/api/metrics`            | GET    | Retrieve real-time metrics and stats     |
| `/api/metrics/reset`      | POST   | Reset all running metrics                |
| `/api/rules/waf`          | GET    | List active WAF rules                    |
| `/api/rules/blocklist`    | GET    | List actively blocked IPs                |

## Testing

Run the test suite using pytest:

```bash
pytest tests/
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
