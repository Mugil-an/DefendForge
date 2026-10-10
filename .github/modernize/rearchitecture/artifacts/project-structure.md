# Project Structure

DefendForge is a Python full-stack cyber-range application composed of cooperating services:

- `target_app/`: bundled Flask ToDo application and SQLite persistence.
- `blue_agent/`: FastAPI dashboard/API, audit, detection, decision, LLM/RAG, remediation, hardening, memory, metrics, and safety modules.
- `red_agent/`: bounded simulated/live attack campaigns, payload catalog, recon, and guardrails.
- `green_agent/`: legitimate traffic generator.
- `flow_sniffer/`: CICFlowMeter wrapper forwarding netflow to Blue Agent.
- `rules/` and `models/`: JSON rules and ML model artifacts.
- `tests/`: unit/integration tests for Blue, Red, and target behavior.

Layers are service/API, agent orchestration, detection/decision, remediation/hardening, persistence/configuration, and dashboard/static assets. Docker Compose defines the runtime boundary and connects agents to the bundled `target_app` service.

Project type: full-stack, multi-service Python application with a deliberately vulnerable local HTTP target.
