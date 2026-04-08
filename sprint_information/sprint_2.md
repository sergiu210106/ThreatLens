# ThreatLens — Sprint 2: PySpark processing pipeline

**Duration:** Week 2  
**Focus:** Spark cluster, data transformation, storage  
**Goal:** Raw Kafka messages transformed, enriched, scored, and stored in Postgres + ChromaDB

---

## Tasks

### 2.1 Set up PySpark cluster in Docker

Configure Spark to run as a standalone cluster inside Docker Compose.

**Implementation details:**
- `spark-master` container running Spark master process
- `spark-worker` container (1 worker for dev, configurable replicas for load testing)
- Shared volume for Spark JARs and job scripts
- Include `spark-sql-kafka-0-10` connector JAR for Kafka integration
- Include `postgresql` JDBC driver JAR for Postgres writes
- Memory: master 512MB, worker 1GB (configurable via `.env`)

**Spark configuration:**
```properties
spark.master=spark://spark-master:7077
spark.sql.streaming.kafka.bootstrap.servers=kafka:9092
spark.jars.packages=org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0,org.postgresql:postgresql:42.7.1
```

**Acceptance criteria:**
- Spark UI accessible on `localhost:8080`
- Worker registers with master automatically
- Can submit a test job that reads from Kafka and prints to console
- Healthchecks for both master and worker

---

### 2.2 Build schema normalization job

Unify the three different source formats into a single `ThreatEvent` schema.

**ThreatEvent unified schema:**
```python
@dataclass
class ThreatEvent:
    event_id: str           # UUID generated at processing time
    source: str             # "nvd", "cisa", "github_advisory", etc.
    source_id: str          # Original ID (CVE-2024-1234, GHSA-xxx)
    title: str
    description: str
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    cvss_score: float | None
    affected_software: list[str]  # ["vendor/product:version"]
    attack_vector: str | None     # NETWORK, LOCAL, PHYSICAL, etc.
    exploit_available: bool
    published_at: datetime
    collected_at: datetime
    processed_at: datetime
    raw_data: dict          # Original payload for debugging
```

**Implementation details:**
- Spark Structured Streaming job consuming from all 3 Kafka topics
- Source-specific parsing functions that map to the unified schema
- Handle missing fields gracefully (default to `None` or `UNKNOWN`)
- Output: write normalized events to an intermediate Kafka topic `normalized-events` or directly chain to enrichment

**Acceptance criteria:**
- Consumes from `raw-cves`, `raw-reports`, `raw-pastes`
- Produces valid `ThreatEvent` objects regardless of source format
- Handles malformed messages without crashing (dead-letter logging)
- Processes backlog of 1000+ messages within 60 seconds

---

### 2.3 Build NLP enrichment job

Extract structured intelligence from unstructured threat descriptions.

**Enrichment tasks:**
- Named Entity Recognition (NER) for software names, versions, vendors
- Attack vector classification (network, local, physical)
- Affected platform extraction (Linux, Windows, macOS, cloud)
- Key phrase extraction for searchability
- Language detection and normalization (ensure English or translate)

**Implementation details:**
- Use `spacy` with `en_core_web_sm` model for NER (lightweight, runs in Spark UDFs)
- Custom entity patterns for CVE IDs, version numbers, package names
- Register as Spark UDF: `@udf(returnType=ArrayType(StringType()))`
- Batch processing: collect descriptions, run NLP, redistribute results

**Spark UDF pattern:**
```python
import spacy

nlp = spacy.load("en_core_web_sm")

@udf(returnType=ArrayType(StringType()))
def extract_software_entities(text):
    doc = nlp(text)
    return [ent.text for ent in doc.ents if ent.label_ in ("ORG", "PRODUCT")]
```

**Acceptance criteria:**
- Extracts at least software names and version numbers from CVE descriptions
- Enriched fields added to the ThreatEvent: `extracted_entities`, `platforms`, `key_phrases`
- UDF handles None/empty descriptions without error
- Processing adds less than 2 seconds per batch of 100 events

---

### 2.4 Build severity scoring job

Compute a composite threat score that goes beyond raw CVSS.

**Scoring formula:**
```
composite_score = (
    0.4 * normalized_cvss +          # Base vulnerability severity
    0.25 * exploit_availability +      # 1.0 if known exploit, 0.0 if not
    0.2 * recency_factor +            # Decays over 30 days
    0.15 * affected_software_breadth   # More affected products = higher risk
)
```

**Implementation details:**
- PySpark transformation job reading from enriched events
- Each factor normalized to 0.0 - 1.0 range
- `recency_factor`: 1.0 for today, linearly decaying to 0.0 at 30 days old
- `affected_software_breadth`: `min(len(affected_software) / 10, 1.0)`
- Final score bucketed into priority tiers: P1 (>0.8), P2 (>0.6), P3 (>0.4), P4 (<=0.4)
- Write scored events to Postgres

**Acceptance criteria:**
- Every event gets a `composite_score` (float) and `priority_tier` (string)
- Scores are deterministic (same input = same output)
- Batch of 1000 events scored in under 10 seconds
- Score distribution is reasonable (not all P1 or all P4)

---

### 2.5 Build embedding generation job

Generate vector embeddings for semantic search (RAG retrieval).

**Implementation details:**
- Use `sentence-transformers` with `all-MiniLM-L6-v2` model (fast, 384 dimensions)
- Embed concatenation of: `title + " " + description + " " + " ".join(affected_software)`
- Batch generation: collect texts, generate embeddings on driver, distribute
- Write embeddings to ChromaDB with metadata (event_id, source, severity, date)

**ChromaDB collection schema:**
```python
collection.add(
    ids=[event.event_id],
    documents=[event.description],
    embeddings=[embedding.tolist()],
    metadatas=[{
        "source": event.source,
        "severity": event.severity,
        "cvss_score": event.cvss_score,
        "priority_tier": event.priority_tier,
        "published_at": event.published_at.isoformat(),
        "affected_software": ",".join(event.affected_software)
    }]
)
```

**Acceptance criteria:**
- Embeddings generated for all processed events
- ChromaDB queryable: semantic search returns relevant results
- Metadata filters work (e.g., filter by severity + date range)
- Embedding generation handles batches of 500+ events

---

### 2.6 Set up Postgres schema and migrations

Design the relational schema for structured threat data.

**Tables:**
```sql
-- Core event table
CREATE TABLE threat_events (
    event_id UUID PRIMARY KEY,
    source VARCHAR(50) NOT NULL,
    source_id VARCHAR(200) NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity VARCHAR(20),
    cvss_score DECIMAL(3,1),
    composite_score DECIMAL(4,3),
    priority_tier VARCHAR(5),
    attack_vector VARCHAR(50),
    exploit_available BOOLEAN DEFAULT FALSE,
    published_at TIMESTAMPTZ,
    collected_at TIMESTAMPTZ,
    processed_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(source, source_id)
);

-- Many-to-many: events <-> software
CREATE TABLE affected_software (
    id SERIAL PRIMARY KEY,
    event_id UUID REFERENCES threat_events(event_id),
    vendor VARCHAR(200),
    product VARCHAR(200),
    version VARCHAR(100)
);

-- Extracted entities for search
CREATE TABLE extracted_entities (
    id SERIAL PRIMARY KEY,
    event_id UUID REFERENCES threat_events(event_id),
    entity_type VARCHAR(50),
    entity_value VARCHAR(500)
);

-- Chat history for agent memory
CREATE TABLE chat_history (
    id SERIAL PRIMARY KEY,
    session_id UUID,
    role VARCHAR(20),
    content TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_events_severity ON threat_events(severity);
CREATE INDEX idx_events_published ON threat_events(published_at DESC);
CREATE INDEX idx_events_priority ON threat_events(priority_tier);
CREATE INDEX idx_software_product ON affected_software(product);
CREATE INDEX idx_entities_value ON extracted_entities(entity_value);
```

**Implementation details:**
- Use Alembic for migration management
- Initial migration creates all tables
- Seed script loads sample data for development
- Connection pooling via `asyncpg` or `psycopg2` pool

**Acceptance criteria:**
- `alembic upgrade head` creates all tables from scratch
- `alembic downgrade base` drops everything cleanly
- Indexes exist for all commonly queried columns
- Sample data seed loads 50+ test events

---

### 2.7 Write Spark job tests

Test each transformation independently before running the full pipeline.

**Unit tests:**
- Normalization: feed sample messages from each source, assert unified schema
- NLP enrichment: feed known descriptions, assert expected entities extracted
- Scoring: feed events with known CVSS/exploitability, assert expected scores
- Embedding: verify embedding dimensions and ChromaDB insertion

**Integration test:**
- Produce 100 test messages to Kafka
- Run full pipeline (normalize → enrich → score → store)
- Assert: 100 rows in Postgres, 100 embeddings in ChromaDB
- Assert: no dead-letter messages (all processed successfully)

**Acceptance criteria:**
- `make test-spark` runs all Spark job tests
- Unit tests run without Docker (mock Kafka/Postgres/ChromaDB)
- Integration test runs with Docker Compose
- All tests pass in CI

---

### 2.8 Add pipeline monitoring metrics

Instrument the Spark jobs so Sprint 4's Grafana dashboards have data.

**Metrics to expose:**
| Metric | Type | Description |
|--------|------|-------------|
| `threatlens_events_ingested_total` | Counter | Total raw messages consumed from Kafka |
| `threatlens_events_processed_total` | Counter | Events successfully through full pipeline |
| `threatlens_events_failed_total` | Counter | Events that failed processing |
| `threatlens_processing_latency_seconds` | Histogram | Time from Kafka consume to Postgres write |
| `threatlens_batch_size` | Gauge | Current micro-batch size |
| `threatlens_kafka_lag` | Gauge | Consumer group lag per topic |

**Implementation details:**
- Use Prometheus Pushgateway (Spark jobs are batch, can't serve /metrics)
- Push metrics at end of each micro-batch
- Add Pushgateway to docker-compose.yml
- Prometheus scrapes Pushgateway on 15s interval

**Acceptance criteria:**
- Metrics visible in Prometheus at `localhost:9090`
- At least 4 of the 6 metrics above are being pushed
- No metrics loss during normal operation

---

## Sprint 2 definition of done

- [ ] PySpark cluster runs in Docker with Kafka connector
- [ ] Raw messages from all 3 topics are normalized to unified schema
- [ ] NLP enrichment extracts software entities and attack vectors
- [ ] Composite severity scores computed and bucketed into priority tiers
- [ ] Embeddings generated and stored in ChromaDB
- [ ] Postgres schema created with migrations (Alembic)
- [ ] Unit and integration tests pass for all Spark jobs
- [ ] Pipeline metrics flowing to Prometheus