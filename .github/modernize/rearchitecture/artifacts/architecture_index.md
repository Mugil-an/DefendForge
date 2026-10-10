# Architecture Index

This index is not the full contract. Do not implement from this file alone; follow the artifact paths below.

## Implementation Guide

### Global artifacts
- `unit_graph.yaml` — entrypoints, dependencies, source anchors, and shared references.
- `wire_contracts.yaml` — HTTP, REST, and netflow contracts; filter by `unit`.
- `shared_modules.yaml` — shared configuration and event structures; filter by `used_by_units`.
- `cross_unit_state.yaml` — configured target URL/path and event flow between agents.
- `project-structure.md` — module and layer map.
- `tech-stack.md` — existing frameworks, runtimes, and dependencies.
- `data-model.md` — bundled target application's persisted schema.

### Unit: target-app-http
- external trigger: HTTP requests to the bundled Flask application.
- must read: `units/target-app-http/behavior.yaml`, `units/target-app-http/bindings.yaml`, `units/target-app-http/unit_decomposition.yaml`.
- relevant global rows: `wire_contracts.yaml` rows with `unit: target-app-http`.
- before DONE report: preserved routes, request/response/error contracts, and target test evidence.

### Unit: blue-agent-api
- external trigger: REST/WebSocket requests to the FastAPI dashboard.
- must read: `units/blue-agent-api/behavior.yaml`, `units/blue-agent-api/bindings.yaml`, `units/blue-agent-api/unit_decomposition.yaml`.
- relevant global rows: `wire_contracts.yaml` rows with `unit: blue-agent-api`; shared rows used by `blue-agent-api`.
- before DONE report: preserved API routes, event schema, and health/traffic verification.

### Unit: red-live-campaign
- external trigger: campaign start API or Red Agent campaign runner.
- must read: `units/red-live-campaign/behavior.yaml`, `units/red-live-campaign/bindings.yaml`, `units/red-live-campaign/unit_decomposition.yaml`.
- relevant global rows: `wire_contracts.yaml` rows with `unit: red-live-campaign`; target safety flows.
- before DONE report: target allowlist, bounded execution, payload mapping, and local-only verification.

### Unit: green-live-traffic
- external trigger: Green Agent live traffic runner.
- must read: `units/green-live-traffic/behavior.yaml`, `units/green-live-traffic/bindings.yaml`, `units/green-live-traffic/unit_decomposition.yaml`.
- relevant global rows: `wire_contracts.yaml` rows with `unit: green-live-traffic`.
- before DONE report: generated traffic shape and endpoint assumptions.

### Unit: flow-sniffer
- external trigger: CICFlowMeter network flow stream.
- must read: `units/flow-sniffer/behavior.yaml`, `units/flow-sniffer/bindings.yaml`, `units/flow-sniffer/unit_decomposition.yaml`.
- relevant global rows: `wire_contracts.yaml` rows with `unit: flow-sniffer`.
- before DONE report: flow-to-Blue-Agent forwarding evidence.
