# ThreatLens

ThreatLens is a security intelligence ingestion platform. This repository contains service stubs, infrastructure definitions, and initial CI tooling.

## Structure

- `services/` — Python services for collectors, processing, API, and agents
- `infra/` — Docker Compose and runtime infrastructure
- `docs/` — architecture and query showcase documentation
- `tests/` — integration and automation tests

## Getting Started

1. Copy `.env.example` to `.env`
2. Run `make build && make up`

