# DefendForge

![Build Status](https://img.shields.io/badge/build-passing-brightgreen) ![License](https://img.shields.io/badge/license-MIT-blue) ![Python](https://img.shields.io/badge/python-3.10%2B-blue)

**DefendForge** is a Collaborative Multi-Agent Cybersecurity Hardening system for registered, locally running containerized applications. The Red Agent performs bounded reconnaissance, dependency/static analysis, and live attacks; the Blue Agent observes gateway traffic, distinguishes Red provenance from legitimate user traffic, detects attacks, remediates vulnerabilities, validates changes, and stores correlated outcomes for future rounds.

## Architecture Overview

The system operates as a continuous loop between the Red Agent and the Blue Agent, acting on the Target Application.

```text
+-------------------+       +-------------------+       +-------------------+
| Legitimate users  | ----> |                   | ----> |                   |
| (Green traffic)   |       | Target Gateway    |       |   Target App      |
+-------------------+       |                   |       | (container)       |
                            |                   |       +-------------------+
+-------------------+       |                   |
| Red Agent         | ----> |                   | ----> Blue Agent events
| audit + attacks   |       +-------------------+       (detection/remediation)
+-------------------+
```

The Blue Agent analyzes logs and traffic, makes decisions using a PPO (Proximal Policy Optimization) RL agent, and falls back to an LLM for complex reasoning. It dynamically retrieves remediation strategies using RAG (Retrieval-Augmented Generation) and applies patches or hardens the application.

### System Components (Docker Stack)

The full system is containerized and orchestrated via Docker Compose, including the following services:
- **target_app**: The vulnerable application (Flask) under test.
- **target_gateway**: A proxy that routes traffic to the `target_app`, enforcing Red Agent signature validation and capturing gateway events.
- **blue_agent**: The autonomous defender API. It uses PPO RL for decision making and escalates to an LLM (default: Ollama with Llama3).
- **red_agent**: Runs bounded autonomous campaigns, signing requests to the gateway and conducting security audits.
- **flow_sniffer**: Captures raw network flows in the target's network namespace and reports them to the Blue Agent.
- **db (PostgreSQL + pgvector)**: Stores the Blue Agent's "memory" (historical events, attack patterns, and successful mitigations) and enables vector search for RAG.
- **minio**: S3-compatible object storage for artifacts, model checkpoints, or knowledge bases.
- **elasticsearch & kibana**: For durable indexing, search, and visualization of security events, metrics, and traffic anomalies.

### Current build scope

The implemented dashboard covers the complete Phase 1 loop: isolated target traffic,
Red/Green activity, Blue detection, confidence-gated fast/slow routing, remediation
validation, rollback visibility, hardening, durable security events, memory, and
multi-round metrics. Phase 2
(self-evolving moving-target defense and its held-out comparison) is intentionally
excluded from this build.

Open the dashboard to see the actual event stream and the attack path
`RECON -> DETECT -> ROUTE -> REMEDIATE -> VALIDATE -> HARDEN`. Ground truth is shown
separately from the defender result, so missed detections are not presented as
successful blocks. The Research novelty panel is backed by `/api/research/novelty`
and maps implemented integrations to the supplied papers. It deliberately does not
claim that DefendForge originated those research ideas. The self-evolving moving
target defense work is displayed as a Phase 2 reference only and is not implemented.

## Workflow

The DefendForge system operates continuously through a multi-stage attack and defense lifecycle, typically following this sequence:

1. **Reconnaissance (RECON)**: The Red Agent discovers available endpoints on the Target Application and performs audits (e.g., `pip-audit`, `npm audit`, `semgrep`) against a read-only workspace to formulate its campaign.
2. **Traffic Generation**: Both legitimate (Green) and attack (Red) requests are routed through the `target_gateway`. Red requests are cryptographically signed to maintain ground-truth provenance for evaluation.
3. **Detection (DETECT)**: The Blue Agent monitors the normalized gateway events alongside raw network traffic captured by the `flow_sniffer`, using anomaly detection models to identify threats.
4. **Decision & Routing (ROUTE)**: Identified threats are routed to the Blue Agent's decision engine, which uses a PPO Reinforcement Learning model to pick a strategy, escalating to an LLM (e.g., Llama3) for novel or complex attack vectors.
5. **Remediation (REMEDIATE)**: Leveraging RAG (Retrieval-Augmented Generation) backed by pgvector, the system constructs a defense. This may involve generating WAF rules, blocklisting IPs, or generating automated code patches.
6. **Validation (VALIDATE)**: The Safety Broker runs target-specific tests (e.g., containerized test suites) against any proposed code changes. If validation fails or times out, the system automatically rolls back to prevent application downtime.
7. **Hardening (HARDEN)**: Validated defenses are finalized, and the Blue Agent's memory (PostgreSQL + pgvector) is updated. This persistent state tracks successful mitigations and past failures, ensuring the system adapts and learns over time.

### Startup & Knowledge Acquisition Flow

To understand how the system goes from a fresh start to an intelligent defender:

1. **System Initialization**: Running `docker-compose up` boots the vulnerable `target_app`, the storage engines (PostgreSQL/pgvector, Elasticsearch, Minio), and the `target_gateway` which shields the app.
2. **Blue Agent Readiness**: The Blue Agent loads its baseline PPO Reinforcement Learning policy, connects to the LLM (e.g., Llama3), and initializes its RAG knowledge base. At first, its specific memory of this app's vulnerabilities is a clean slate.
3. **Red Agent Engagement**: An autonomous campaign is triggered via the API or dashboard. The Red Agent maps the `target_app`'s attack surface and launches live exploits (e.g., SQLi, XSS, Path Traversal).
4. **Knowledge Generation**: As the Blue Agent detects these zero-day or unpatched attacks, it queries pgvector for similar known threats. If it lacks a known defense, it escalates the event to the LLM to dynamically generate a remediation strategy (such as a WAF rule or a Python code patch).
5. **Continuous Learning**: When the Safety Broker validates that a newly generated patch successfully stops the attack without breaking the app, the Blue Agent converts this scenario into vector embeddings. It stores the attack pattern and the successful mitigation in its pgvector memory. During future rounds, if the Red Agent attempts a similar attack, the Blue Agent instantly retrieves this acquired knowledge via RAG and mitigates the threat autonomously, bypassing the slower LLM escalation.

## Features

- **Detection**: Real-time traffic analysis and anomaly detection (aided by `flow_sniffer`).
- **Decision Engine (PPO RL)**: Reinforcement Learning model to decide on mitigation actions.
- **LLM Reasoning**: Escalation to Large Language Models (e.g., Llama3 via Ollama) for complex, unseen attacks.
- **RAG (Knowledge Ingestion)**: Dynamically fetches mitigation strategies from a built-in cybersecurity knowledge base using pgvector.
- **Remediation & Hardening**: Automated code patching, WAF rule generation, and IP blocklisting.
- **Memory**: Tracks past attacks and successful mitigations to avoid repeated mistakes, stored in PostgreSQL with pgvector.
- **Data Persistence & Analytics**: Comprehensive logging and event visualization backed by Elasticsearch and Kibana, with S3-compatible artifact storage via Minio.
- **Metrics**: Real-time tracking of Time-to-Detect (TTD), Time-to-Remediate (TTR), precision, and recall.
- **Safety Broker**: Validates all automated code changes to ensure they do not break application functionality.
- **API**: REST API for monitoring metrics, triggering actions, and viewing agent status.
- **Red Agent**: Bounded dynamic campaigns driven by target discovery, audit findings, and local attack knowledge.
- **Red audits**: Manifest-controlled `pip-audit`, `npm audit`, and Semgrep execution against a read-only target workspace.
- **Autonomous Red Campaigns**: Signed live campaigns through the gateway, with campaign/request correlation and adaptive round planning.
- **Durable events**: Normalized gateway events retain Red/user provenance separately from Blue model predictions.
- **Container validation**: Target-manifest commands run with argv-only execution, workspace confinement, timeout limits, and rollback on failure.

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

2. *(Optional)* Local Python Setup (for development):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

### Run Demo / Simulation

The recommended way to run the full system with all dependencies (PostgreSQL, Elasticsearch, Minio, etc.) is via Docker Compose:

```bash
docker-compose up --build
```

Wait for the services to initialize. The Blue Agent API will be available at `http://localhost:8000`, the Target Gateway at `http://localhost:8080`, and Kibana at `http://localhost:5601`.

*(Alternatively, for local script testing without the full infrastructure, you can run individual components like `python -m target_app.app`, `python -m blue_agent.main`, and `python -m red_agent.simulate`.)*

### Registering a target

Create `targets/<name>.json`:

```json
{
  "name": "my-app",
  "service": "my_app",
  "base_url": "http://my_app:8080",
  "discovery": {
    "openapi_path": "/openapi.json",
    "crawl_enabled": true,
    "max_depth": 2
  },
  "audit": {
    "source_path": "/target",
    "tools": ["pip-audit", "npm-audit", "semgrep"],
    "timeout_seconds": 300
  },
  "validation": {
    "command": ["npm", "test"],
    "working_dir": "/target",
    "timeout_seconds": 300
  }
}
```

Targets must resolve to localhost, a private address, or a declared Docker service. Red requests must use the gateway; direct remote targets are rejected.

### Run an Autonomous Red Campaign

The autonomous Red Agent uses real HTTP requests against the registered target
gateway. Each campaign is bounded by a maximum number of rounds and events,
discovers endpoints, considers audit findings, selects applicable attack types,
and signs each request with a campaign ID and request ID. External hosts are
rejected.
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

Campaign status is available at `/api/red/campaign`, durable normalized events
are available at `/api/security-events`, and campaign decisions and attack
results are streamed over the dashboard WebSocket as `campaign` and `attack`
events.

### Traffic and remediation model

```text
Green/user request -> gateway -> target
Red signed request  -> gateway -> target
                         |
                         v
                 Blue normalized event
                         |
       detect -> decide -> patch -> validate
                         |
                 accept or rollback
```

The gateway redacts credentials and cookies. Red provenance is retained as
evaluation ground truth, while Blue's anomaly/model result is stored separately
so precision, recall, false positives, and false negatives remain measurable.

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
├── target_gateway/         # Reverse proxy enforcing signatures and logging events
├── flow_sniffer/           # Raw network traffic capture service
├── rules/                  # WAF rules and IP blocklists (JSON)
├── tests/                  # Unit and integration tests
├── docker-compose.yml      # Full system Docker orchestration
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
