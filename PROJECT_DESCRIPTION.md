# ThreatLens Project Description

ThreatLens is a security threat intelligence pipeline built around Kafka, Python collectors, and downstream processing.

## Core components

- `services/collector-cve`
  - Python service that polls the NVD API (`https://services.nvd.nist.gov/rest/json/cves/2.0`).
  - Normalizes CVE data into a standard schema.
  - Produces JSON messages to the Kafka topic `raw-cves` using `confluent-kafka`.
  - Supports backfill mode with `--backfill --since YYYY-MM-DD`.
  - Handles HTTP errors with exponential backoff and logs each poll cycle.

- `infra/docker-compose.yml`
  - Defines the Kafka, Zookeeper, Postgres, ChromaDB, and supporting infrastructure services.
  - Uses Kafka topic initialization via `kafka-init`.

- `tests/unit`
  - Contains unit tests for the CVE normalization and extraction logic.

- `tests/integration`
  - Verifies Kafka topic creation and end-to-end producer/consumer connectivity.

## How it works

1. The collector service polls NVD in 15-minute intervals by default.
2. Each returned CVE is converted to a normalized event schema.
3. Events are published to Kafka as JSON strings.
4. Backfill mode can load historical CVE events from a specified start date.

## Testing commands

Use the local Python virtual environment in `.venv` to avoid installing dependencies globally.

### Setup and install dependencies

```bash
cd /home/sergiu/projects/threatlens
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r services/collector-cve/requirements.txt
```

### Validate Python syntax

```bash
. .venv/bin/activate
python -m py_compile services/collector-cve/main.py tests/unit/test_collector_cve.py
```

### Run unit tests

```bash
. .venv/bin/activate
python -m pytest -q tests/unit/test_collector_cve.py
```

### Run integration tests

```bash
cd /home/sergiu/projects/threatlens
docker compose -f infra/docker-compose.yml up -d zookeeper kafka
docker compose -f infra/docker-compose.yml run --rm kafka-init
. .venv/bin/activate
python -m pytest -q tests/integration/test_kafka_topics.py
```

### Run the collector service manually

```bash
. .venv/bin/activate
export KAFKA_BROKER=kafka:9092
export KAFKA_TOPIC_RAW_CVES=raw-cves
python services/collector-cve/main.py --backfill --since 2024-01-01
```
