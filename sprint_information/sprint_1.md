# ThreatLens — Sprint 1: Infrastructure & ingestion

**Duration:** Week 1  
**Focus:** DevOps foundation, Kafka setup, data collectors  
**Goal:** Messages flowing from 3 sources into Kafka topics, all containerized

---

## Tasks

### 1.1 Initialize repo with monorepo structure

Create the project skeleton that will house all services.

```
threatlens/
├── services/
│   ├── collector-cve/
│   ├── collector-reports/
│   ├── collector-pastes/
│   ├── spark-processing/
│   ├── agent/
│   └── api/
├── infra/
│   ├── docker-compose.yml
│   ├── docker-compose.dev.yml
│   ├── kafka/
│   └── prometheus/
├── docs/
│   ├── architecture.md
│   └── queries-showcase.md
├── tests/
│   └── integration/
├── .github/
│   └── workflows/
├── Makefile
├── .gitignore
├── .env.example
└── README.md
```

**Acceptance criteria:**
- Repo initialized with proper `.gitignore` (Python, Docker, IDE files)
- Each service has its own `Dockerfile`, `requirements.txt`, and `__init__.py`
- Makefile with targets: `build`, `up`, `down`, `test`, `lint`
- `.env.example` documents all required environment variables

---

### 1.2 Write base docker-compose.yml

Define all services, even if most are stubs initially. This establishes the network topology early.

**Services to define:**
- `zookeeper` — Kafka dependency (or skip if using KRaft mode)
- `kafka` — message broker, 3 topics
- `spark-master` — PySpark driver
- `spark-worker` — PySpark executor (1 worker for dev)
- `postgres` — structured storage
- `chromadb` — vector storage
- `api` — FastAPI server (stub)
- `prometheus` — metrics (stub)
- `grafana` — dashboards (stub)

**Acceptance criteria:**
- `docker compose up` brings up kafka + zookeeper + postgres + chromadb with healthchecks
- All services on a shared `threatlens` Docker network
- Volumes for persistent data (postgres, kafka logs)
- Environment variables externalized to `.env`

---

### 1.3 Configure Kafka with Zookeeper

Set up the message broker with proper topic design.

**Topics:**
| Topic | Partitions | Retention | Purpose |
|-------|-----------|-----------|---------|
| `raw-cves` | 3 | 7 days | NVD/MITRE vulnerability data |
| `raw-reports` | 3 | 7 days | OSINT threat reports and advisories |
| `raw-pastes` | 2 | 3 days | Paste site and GitHub leak data |

**Acceptance criteria:**
- Kafka accessible on `kafka:9092` within Docker network
- Topics auto-created on startup via init script or `KAFKA_CREATE_TOPICS`
- Can produce and consume test messages with `kafka-console-producer/consumer`
- Consider KRaft mode (Kafka 3.3+) to eliminate Zookeeper dependency

---

### 1.4 Build CVE feed collector service

The first and most important data source. The NVD API is well-documented and free.

**Implementation details:**
- Python service using `confluent-kafka` producer
- Poll NVD API (`https://services.nvd.nist.gov/rest/json/cves/2.0`) every 15 minutes
- Parse CVE JSON into a normalized message schema
- Produce to `raw-cves` Kafka topic
- Backfill mode: CLI flag `--backfill --since 2024-01-01` to load historical CVEs
- Rate limiting: NVD allows 5 requests/30s without API key, 50 requests/30s with key

**Message schema:**
```json
{
  "source": "nvd",
  "source_id": "CVE-2024-1234",
  "title": "...",
  "description": "...",
  "severity": "CRITICAL",
  "cvss_score": 9.8,
  "affected_software": ["apache/httpd:2.4.51"],
  "published_at": "2024-01-15T10:00:00Z",
  "collected_at": "2024-01-15T10:15:00Z",
  "raw_data": {}
}
```

**Acceptance criteria:**
- Service starts, polls NVD, produces messages to Kafka
- Messages are valid JSON matching the schema above
- Handles API errors gracefully (retry with exponential backoff)
- Logs every poll cycle with count of new CVEs found
- Backfill mode tested with at least 100 historical CVEs

---

### 1.5 Build threat report scraper service

Scrape publicly available security advisories and threat intelligence blogs.

**Sources to scrape:**
- CISA Known Exploited Vulnerabilities catalog (`https://www.cisa.gov/known-exploited-vulnerabilities-catalog`)
- Vendor security blogs (Microsoft MSRC, Google Project Zero RSS)
- Security advisories from GitHub Advisory Database API

**Implementation details:**
- Python service using `httpx` + `BeautifulSoup` / `feedparser` for RSS
- Produce to `raw-reports` Kafka topic
- Respect `robots.txt` and rate limits (1 request/second per domain)
- Store last-seen timestamps to avoid duplicate scraping

**Acceptance criteria:**
- Scrapes at least 2 sources successfully
- Produces normalized messages to `raw-reports` topic
- Deduplication by source URL
- Graceful handling of unreachable sources

---

### 1.6 Build paste monitor service

Monitor for leaked credentials, exposed secrets, and security-relevant pastes.

**Sources:**
- GitHub Security Advisories API (`https://api.github.com/advisories`)
- GitHub Code Search API for common leak patterns (API keys, tokens)
- Public paste aggregation APIs (where legally accessible)

**Implementation details:**
- Python service using GitHub REST API with authentication
- Produce to `raw-pastes` Kafka topic
- Filter for security-relevant content using keyword matching
- Respect GitHub API rate limits (5000 requests/hour with token)

**Acceptance criteria:**
- Produces messages to `raw-pastes` topic
- Filters out irrelevant content before producing
- Handles rate limiting gracefully

---

### 1.7 Set up GitHub Actions CI

Automated quality checks on every push.

**Workflow steps:**
1. Lint all Python code with `ruff`
2. Type-check with `mypy` (strict mode)
3. Run unit tests with `pytest`
4. Build all Docker images (verify they compile)
5. Run on push to `main` and on all pull requests

**Acceptance criteria:**
- CI passes on current codebase
- Failed lint or tests block merging
- Badge in README shows CI status

---

### 1.8 Write integration test for ingestion

End-to-end test that verifies the full ingestion pipeline.

**Test flow:**
1. `docker compose up -d kafka zookeeper` (wait for healthcheck)
2. Start collector services
3. Wait 60 seconds for at least one poll cycle
4. Consume from all 3 Kafka topics, assert messages exist
5. Validate message schema
6. `docker compose down -v`

**Acceptance criteria:**
- Test runs in CI via `make test-integration`
- Passes with clean Kafka (no pre-existing messages)
- Timeout after 120 seconds if no messages appear
- Cleans up all containers after test

---

## Sprint 1 definition of done

- [ ] `docker compose up` starts Kafka + Zookeeper + Postgres + ChromaDB
- [ ] CVE collector produces messages to `raw-cves` topic
- [ ] Report scraper produces messages to `raw-reports` topic
- [ ] Paste monitor produces messages to `raw-pastes` topic
- [ ] CI pipeline runs lint + tests on every push
- [ ] Integration test verifies end-to-end ingestion
- [ ] All services have Dockerfiles and healthchecks