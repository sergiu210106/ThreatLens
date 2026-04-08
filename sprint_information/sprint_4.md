# ThreatLens — Sprint 4: DevOps polish & demo

**Duration:** Week 4  
**Focus:** Observability, frontend, documentation, security  
**Goal:** Production-ready project with monitoring, a demo-able UI, and a polished GitHub presence

---

## Tasks

### 4.1 Set up Prometheus + Grafana stack

Full observability for the entire pipeline.

**Implementation details:**
- Add `prometheus` and `grafana` services to docker-compose
- Prometheus scrapes all services + Pushgateway on 15s interval
- Grafana pre-provisioned with datasource and dashboards (no manual setup needed)
- Use Grafana provisioning via config files mounted as volumes

**Prometheus targets:**
```yaml
scrape_configs:
  - job_name: 'api'
    static_configs:
      - targets: ['api:8000']
  - job_name: 'pushgateway'
    static_configs:
      - targets: ['pushgateway:9091']
  - job_name: 'kafka'
    static_configs:
      - targets: ['kafka-exporter:9308']
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']
```

**Grafana dashboards to build:**

**Dashboard 1 — Ingestion overview:**
- Messages per topic per minute (time series)
- Kafka consumer lag per topic (gauge)
- Collector uptime and error rate (stat panels)
- Last successful poll timestamp per collector

**Dashboard 2 — Processing pipeline:**
- Events processed per minute (time series)
- Processing latency P50/P95/P99 (histogram)
- Failed events count (stat panel with alert threshold)
- Spark job status (running/completed/failed)

**Dashboard 3 — Agent performance:**
- Query latency distribution (histogram)
- Queries per routing path (pie chart: semantic/structured/hybrid/general)
- Tool usage breakdown (bar chart)
- Active sessions count (gauge)

**Acceptance criteria:**
- `docker compose up` auto-provisions all 3 dashboards
- Grafana accessible at `localhost:3000` with no manual config
- Dashboards populate with real data after 5 minutes of pipeline activity
- At least one alert rule configured (e.g., processing error rate > 5%)

---

### 4.2 Add structured logging with Loki

Centralized log aggregation across all services.

**Implementation details:**
- Add Grafana Loki + Promtail to docker-compose
- All Python services log in JSON format using `structlog`
- Correlation IDs: generate a `trace_id` at ingestion, propagate through Kafka message headers, include in all downstream logs
- Promtail collects Docker container logs and ships to Loki
- Grafana datasource for Loki (query logs alongside metrics)

**Structured log format:**
```json
{
  "timestamp": "2024-01-15T10:15:30Z",
  "level": "info",
  "service": "collector-cve",
  "trace_id": "abc-123-def",
  "message": "Polled NVD API",
  "details": {
    "new_cves": 12,
    "duration_ms": 340,
    "api_status": 200
  }
}
```

**Python logging setup:**
```python
import structlog

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)

log = structlog.get_logger()
log.info("polled_nvd", new_cves=12, duration_ms=340)
```

**Acceptance criteria:**
- All services produce JSON logs
- Logs queryable in Grafana via Loki datasource
- Correlation IDs traceable across services (follow a single event from ingestion to agent response)
- Log retention: 7 days
- No sensitive data in logs (API keys, raw credentials)

---

### 4.3 Build Streamlit chat frontend

A simple but effective demo UI for the agent.

**Implementation details:**
- Streamlit app with chat interface (`st.chat_message`, `st.chat_input`)
- Streams responses from FastAPI `/chat` endpoint via SSE
- Sidebar with:
  - Pipeline stats (total events, last update time)
  - Severity filter (dropdown: All, Critical, High, Medium, Low)
  - Date range selector (last 7/14/30 days)
  - Example queries (clickable buttons)
- Source citations displayed as expandable sections below each response
- Confidence indicator (color-coded badge)

**Example queries to showcase:**
```python
EXAMPLE_QUERIES = [
    "What are the most critical threats this week?",
    "How many CVEs affect Python packages?",
    "Summarize recent supply chain vulnerabilities",
    "What P1 threats should I prioritize?",
    "Compare Apache vs Nginx vulnerability trends",
]
```

**Acceptance criteria:**
- Chat interface streams responses in real-time
- Example queries work out of the box with seeded data
- Sidebar filters actually modify agent queries
- Source citations link to original CVE/advisory pages
- Responsive layout (works on laptop screens)

---

### 4.4 Write Docker Compose profiles

Separate configurations for different use cases.

**Profiles:**

**dev** (`docker compose --profile dev up`):
- Hot reload on all Python services (volume mounts + `watchfiles`)
- Debug ports exposed (5678 for debugpy)
- Verbose logging (DEBUG level)
- Single Spark worker
- Grafana anonymous access enabled

**test** (`docker compose --profile test up`):
- Ephemeral containers (no persistent volumes)
- Seed data loaded on startup
- Auto-teardown after test suite completes
- Minimal resource allocation

**prod** (`docker compose --profile prod up`):
- Resource limits on all containers (CPU + memory)
- Restart policies (`unless-stopped`)
- No debug ports exposed
- Log level: WARNING
- Health check intervals tightened (10s)
- Read-only filesystem where possible

**docker-compose.override.yml for dev:**
```yaml
services:
  api:
    volumes:
      - ./services/api:/app
    environment:
      - LOG_LEVEL=DEBUG
      - RELOAD=true
    ports:
      - "5678:5678"  # debugpy
  
  collector-cve:
    volumes:
      - ./services/collector-cve:/app
    environment:
      - LOG_LEVEL=DEBUG
      - POLL_INTERVAL=60  # faster for dev
```

**Acceptance criteria:**
- Each profile starts with the correct configuration
- Dev profile: code changes reflect without rebuilding
- Test profile: starts, runs tests, exits with code 0 or 1
- Prod profile: respects resource limits, no debug access
- `make dev`, `make test`, `make prod` shortcuts in Makefile

---

### 4.5 Create architecture diagram in README

The first thing recruiters and engineers see on your GitHub repo.

**README structure:**
```markdown
# ThreatLens

AI-powered threat intelligence pipeline that ingests CVEs and 
security advisories, processes them at scale with PySpark, and 
provides an intelligent agent for querying and analyzing threats.

## Architecture
[Mermaid or image diagram here]

## Tech stack
- **Ingestion:** Python collectors → Kafka
- **Processing:** PySpark (normalize, enrich, score, embed)
- **Storage:** PostgreSQL + ChromaDB
- **Agent:** LangGraph (RAG + SQL tools + reasoning)
- **API:** FastAPI (streaming SSE)
- **Frontend:** Streamlit
- **Observability:** Prometheus + Grafana + Loki
- **Infrastructure:** Docker Compose, GitHub Actions CI

## Quick start
docker compose up
# Visit http://localhost:8501 for the chat UI
# Visit http://localhost:3000 for Grafana dashboards

## Example queries
[Show 5 example queries with screenshots]

## Project structure
[Tree diagram of the monorepo]

## Development
[How to run locally, how to add a new collector, how to modify the agent]
```

**Acceptance criteria:**
- README renders well on GitHub (no broken images or links)
- Architecture diagram accurately reflects the final system
- Quick start works: clone → docker compose up → working system
- At least 3 example query screenshots included

---

### 4.6 Write example queries showcase

Document compelling demonstrations of the agent's capabilities.

**10 example queries with expected outputs:**

| # | Query | Tests |
|---|-------|-------|
| 1 | "What are the most critical threats this week?" | Semantic retrieval + severity filter |
| 2 | "How many CVEs were published in the last 30 days by severity?" | SQL aggregation + grouping |
| 3 | "Tell me about supply chain attacks affecting npm packages" | Semantic search + software filter |
| 4 | "What's the trend in critical CVE publications over the last 3 months?" | SQL time series + trend analysis |
| 5 | "Which software vendors have the most vulnerabilities?" | SQL aggregation + ranking |
| 6 | "Summarize the top 5 P1 threats I should address today" | Hybrid: retrieval + SQL + synthesis |
| 7 | "Are there any CVEs with known exploits affecting our Python/Django stack?" | Semantic + exploit filter |
| 8 | "Compare the vulnerability landscape of Apache vs Microsoft products" | Hybrid comparison query |
| 9 | "Generate a weekly threat briefing for our DevOps team" | Full report generation |
| 10 | "What CVEs should I patch first based on severity and exploitability?" | Composite scoring + prioritization |

**Acceptance criteria:**
- All 10 queries documented with actual agent responses
- Each query demonstrates a different capability
- Responses include source citations
- Document stored in `docs/queries-showcase.md`

---

### 4.7 Record demo video

A 2-minute video that tells the story of ThreatLens.

**Script outline:**
1. **0:00-0:15** — Title card, one-sentence pitch
2. **0:15-0:30** — `docker compose up`, show services starting (terminal)
3. **0:30-0:50** — Open Streamlit, ask "What are the most critical threats this week?"
4. **0:50-1:10** — Show streaming response with citations, click through to original CVE
5. **1:10-1:30** — Ask a follow-up: "Which of these affect Python?" (demonstrates memory)
6. **1:30-1:50** — Switch to Grafana, show pipeline dashboard with live metrics
7. **1:50-2:00** — Quick architecture overview, link to repo

**Recording tips:**
- Use a clean terminal theme (dark background, readable font)
- Pre-seed data so results are impressive immediately
- Record with OBS or native screen recording
- Upload to YouTube (unlisted) and embed in README

**Acceptance criteria:**
- Video is under 3 minutes
- Shows: starting the system, querying the agent, viewing metrics
- Audio narration or text overlay explains what's happening
- Linked in README and in GitHub repo description

---

### 4.8 Security hardening

Make the project actually secure, not just about security.

**Tasks:**
- Scan all Docker images with Trivy (`trivy image threatlens/api:latest`)
- Pin all Python dependencies to exact versions in `requirements.txt`
- Pin all Docker base images to specific SHA digests
- Add `.env.example` with all required env vars (no actual secrets)
- Document API key setup for NVD, GitHub, and LLM provider
- SQL injection test: verify the agent rejects malicious queries
- Network isolation: only `api` and `frontend` expose ports to host
- Secrets management: document how to use Docker secrets or a `.env` file
- Add `SECURITY.md` with responsible disclosure policy

**Trivy integration in CI:**
```yaml
- name: Scan Docker images
  run: |
    for service in api collector-cve collector-reports spark-processing; do
      trivy image --severity HIGH,CRITICAL threatlens/$service:latest
    done
```

**Acceptance criteria:**
- No HIGH or CRITICAL vulnerabilities in Docker images
- All dependencies pinned
- `.env.example` covers every required variable
- Internal services not accessible from host network
- `SECURITY.md` exists in repo root

---

## Sprint 4 definition of done

- [ ] Prometheus + Grafana running with 3 pre-provisioned dashboards
- [ ] Structured JSON logging with correlation IDs across all services
- [ ] Streamlit chat frontend streams agent responses
- [ ] Docker Compose profiles for dev, test, and prod
- [ ] README with architecture diagram, quick start, and screenshots
- [ ] 10 example queries documented with actual responses
- [ ] Demo video recorded and linked in README
- [ ] Security scan passes with no HIGH/CRITICAL findings

---

## Project complete checklist

- [ ] `git clone` → `docker compose up` → working system in under 5 minutes
- [ ] Agent answers threat intelligence questions accurately with citations
- [ ] Pipeline processes real CVE data end-to-end
- [ ] Monitoring dashboards show system health
- [ ] CI/CD pipeline passes on every push
- [ ] Documentation is comprehensive and accurate
- [ ] Demo video showcases the full system
- [ ] Code is clean, typed, and tested