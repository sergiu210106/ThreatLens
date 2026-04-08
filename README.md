# ThreatLens

ThreatLens is a security intelligence ingestion platform. This repository contains service stubs, infrastructure definitions, and initial CI tooling.

## Structure

- `services/` — Python services for collectors, processing, API, and agents
- `infra/` — Docker Compose and runtime infrastructure
- `docs/` — architecture and query showcase documentation
- `tests/` — integration and automation tests

## Prerequisites

- Docker and Docker Compose
- Python 3.12+ (for local testing and `make test-integration`)
- `make`

## Getting Started

1. Copy `.env.example` to `infra/.env`
2. Run `make build`
3. Run `make up`

This starts the core infrastructure services defined in `infra/docker-compose.yml`, including:

- `zookeeper`
- `kafka`
- `postgres`
- `chromadb`
- `api`
- `prometheus`
- `grafana`

## Kafka setup

The Kafka stack is configured to use Zookeeper and to auto-create the ingest topics on startup:

- `raw-cves` — 3 partitions, 7-day retention
- `raw-reports` — 3 partitions, 7-day retention
- `raw-pastes` — 2 partitions, 3-day retention

Topic creation is handled by the `kafka-init` service and the accompanying init script.

## Running tests

- Run unit tests: `make test`
- Run integration tests: `make test-integration`

The `test-integration` target starts Kafka and Zookeeper, then validates topic creation and produces/consumes a test message.

## Docker permissions

If you encounter a Docker socket permission error, either run the command with `sudo` or add your user to the Docker group:

```bash
sudo usermod -aG docker $USER
```

Then log out and log back in before retrying.

## Troubleshooting

- If `make test-integration` fails because Kafka topics are missing, make sure Kafka has fully started and the `kafka-init` script completed.
- If `docker compose up` fails due to image pull errors, check the image tags in `infra/docker-compose.yml` and verify access to Docker Hub.
- If `kafka-topics` commands fail inside the Kafka container, confirm that `kafka` is reachable at `kafka:9092` on the Docker network.
- If the integration test reports `python: No such file or directory`, use `python3` or install the Python 3 interpreter.
- If containers fail to start because ports are already in use, stop the conflicting services or change the port mappings in `infra/docker-compose.yml`.

