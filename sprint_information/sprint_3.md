# ThreatLens — Sprint 3: LangGraph agent

**Duration:** Week 3  
**Focus:** Agentic RAG, tool use, API layer  
**Goal:** A conversational agent that reasons over threat data using retrieval + SQL + synthesis

---

## Tasks

### 3.1 Design LangGraph state graph

Plan the full agent architecture before writing code. This is the brain of ThreatLens.

**State schema:**
```python
from typing import TypedDict, Annotated
from langgraph.graph import MessagesState

class ThreatAgentState(TypedDict):
    messages: list                    # Chat history
    query: str                        # Current user query
    query_type: str                   # "semantic", "structured", "hybrid", "general"
    retrieved_docs: list[dict]        # Results from ChromaDB
    sql_results: list[dict]           # Results from Postgres
    analysis: str                     # Reasoner's synthesized analysis
    sources: list[str]               # Source citations
    confidence: float                 # Agent's confidence in answer (0-1)
    tool_calls_made: list[str]       # Audit trail of tools used
```

**Graph topology:**
```
START → Router → [Retriever | SQL Tool | Both] → Reasoner → END
                                                    ↑
                                          (needs more context? loop back to Router)
```

**Routing logic:**
| Query type | Route | Example |
|------------|-------|---------|
| Semantic | Retriever → Reasoner | "What threats target Python web apps?" |
| Structured | SQL Tool → Reasoner | "How many critical CVEs this week?" |
| Hybrid | Retriever + SQL → Reasoner | "Summarize critical CVEs affecting our Django stack" |
| General | Reasoner only | "What is a zero-day vulnerability?" |

**Acceptance criteria:**
- State schema defined as a TypedDict
- Graph drawn with LangGraph's `StateGraph` builder
- Routing logic documented with example queries for each path
- Graph visualizable with `graph.get_graph().draw_mermaid()`

---

### 3.2 Build retriever node

Semantic search over ChromaDB to find relevant threat intelligence.

**Implementation details:**
- Query ChromaDB with the user's question (embed query → cosine similarity)
- Return top-k results (default k=5, configurable)
- Apply metadata filters based on query analysis:
  - Date range: "this week" → `published_at >= 7 days ago`
  - Severity: "critical" → `severity == "CRITICAL"`
  - Software: "affecting Python" → `affected_software contains "python"`
- Re-rank results by composite_score after retrieval
- Format results as structured context for the reasoner

**Node implementation:**
```python
def retriever_node(state: ThreatAgentState) -> dict:
    query = state["query"]
    
    # Build metadata filter from query analysis
    filters = build_metadata_filter(query)
    
    # Semantic search
    results = chroma_collection.query(
        query_texts=[query],
        n_results=5,
        where=filters
    )
    
    # Format for downstream nodes
    docs = format_retrieved_docs(results)
    
    return {
        "retrieved_docs": docs,
        "tool_calls_made": state["tool_calls_made"] + ["retriever"]
    }
```

**Acceptance criteria:**
- Returns relevant documents for semantic queries
- Metadata filters correctly narrow results
- Handles empty results gracefully (returns empty list, not error)
- Results include source citations (CVE IDs, URLs)
- Retrieval latency under 500ms for typical queries

---

### 3.3 Build SQL query tool node

Translate natural language questions into SQL queries against Postgres.

**Implementation details:**
- Use LLM to generate SQL from natural language (text-to-SQL)
- Restrict to SELECT queries only (no mutations)
- Provide the LLM with the database schema as context
- Validate generated SQL before execution (basic injection prevention)
- Execute against Postgres and return structured results
- Limit results to 50 rows maximum

**Supported query patterns:**
```sql
-- Counts and aggregations
"How many critical CVEs this month?"
→ SELECT COUNT(*) FROM threat_events 
  WHERE severity = 'CRITICAL' AND published_at >= NOW() - INTERVAL '30 days';

-- Top-N queries
"Top 10 most severe threats this week?"
→ SELECT title, cvss_score, composite_score FROM threat_events 
  WHERE published_at >= NOW() - INTERVAL '7 days'
  ORDER BY composite_score DESC LIMIT 10;

-- Filtering
"CVEs affecting Apache products"
→ SELECT te.title, te.severity, as.product 
  FROM threat_events te
  JOIN affected_software as ON te.event_id = as.event_id
  WHERE as.vendor ILIKE '%apache%';

-- Trend analysis
"CVE count by severity over last 4 weeks"
→ SELECT severity, DATE_TRUNC('week', published_at) as week, COUNT(*)
  FROM threat_events 
  WHERE published_at >= NOW() - INTERVAL '28 days'
  GROUP BY severity, week ORDER BY week;
```

**Safety guardrails:**
- Only SELECT statements allowed (regex check + parameterized queries)
- Query timeout: 5 seconds max
- Row limit: 50 rows returned
- Schema exposure: only share table names and column types with the LLM, not actual data

**Acceptance criteria:**
- Generates valid SQL for the supported query patterns above
- Rejects non-SELECT queries
- Returns structured results (list of dicts)
- Handles SQL errors gracefully (returns error message, not stack trace)
- Latency under 2 seconds for typical queries

---

### 3.4 Build reasoner node

The synthesis layer that turns raw data into actionable intelligence.

**Implementation details:**
- Takes retrieved docs + SQL results + chat history as context
- Produces a structured threat briefing with:
  - Summary (2-3 sentences answering the question)
  - Key findings (bullet points of critical data)
  - Affected systems (list of impacted software/platforms)
  - Recommended actions (prioritized response steps)
  - Confidence level (how well the data answers the question)
  - Source citations (CVE IDs, advisory URLs)

**Prompt template:**
```python
REASONER_PROMPT = """You are a cybersecurity threat analyst. 
Based on the following threat intelligence data, provide a concise briefing.

## Retrieved threat intelligence:
{retrieved_docs}

## Structured query results:
{sql_results}

## User question:
{query}

Respond with:
1. A direct answer to the question
2. Key findings from the data
3. Affected systems and software
4. Recommended actions (prioritized)
5. Confidence level (high/medium/low) with explanation

Always cite specific CVE IDs and sources."""
```

**Acceptance criteria:**
- Produces coherent, actionable threat briefings
- Always includes source citations when data is available
- Handles "no relevant data found" gracefully
- Confidence level reflects actual data coverage
- Response generated in under 5 seconds

---

### 3.5 Implement conditional routing

The router node that decides which tools the agent needs.

**Implementation details:**
- LLM-based classification of the user query into: semantic, structured, hybrid, general
- Conditional edges in LangGraph based on query_type
- Re-routing logic: if reasoner determines it needs more context, loop back to router with a refined query
- Maximum 2 re-routing loops to prevent infinite cycles

**Router implementation:**
```python
from langgraph.graph import StateGraph, END

def router_node(state: ThreatAgentState) -> dict:
    query = state["query"]
    # LLM classifies the query type
    query_type = classify_query(query)
    return {"query_type": query_type}

def route_by_type(state: ThreatAgentState) -> str:
    qt = state["query_type"]
    if qt == "semantic":
        return "retriever"
    elif qt == "structured":
        return "sql_tool"
    elif qt == "hybrid":
        return "retriever"  # retriever first, then SQL
    else:
        return "reasoner"   # general knowledge, skip tools

# Graph construction
graph = StateGraph(ThreatAgentState)
graph.add_node("router", router_node)
graph.add_node("retriever", retriever_node)
graph.add_node("sql_tool", sql_tool_node)
graph.add_node("reasoner", reasoner_node)

graph.set_entry_point("router")
graph.add_conditional_edges("router", route_by_type)
graph.add_edge("retriever", "sql_tool")   # For hybrid: chain
graph.add_edge("sql_tool", "reasoner")
graph.add_edge("reasoner", END)
```

**Acceptance criteria:**
- Correctly classifies at least 80% of test queries
- Hybrid queries use both retriever and SQL tool
- General questions skip tools entirely (faster response)
- No infinite loops (max 2 re-routes enforced)
- Full graph visualizable with LangGraph's built-in tools

---

### 3.6 Build FastAPI endpoints

The HTTP interface to the agent.

**Endpoints:**
| Method | Path | Description |
|--------|------|-------------|
| POST | `/chat` | Send a message, receive streaming response |
| POST | `/report` | Generate a threat briefing report (JSON) |
| GET | `/health` | Service healthcheck |
| GET | `/stats` | Pipeline stats (events count, last update) |

**Implementation details:**
```python
from fastapi import FastAPI
from fastapi.responses import StreamingResponse

app = FastAPI(title="ThreatLens API", version="0.1.0")

@app.post("/chat")
async def chat(request: ChatRequest) -> StreamingResponse:
    """Stream agent response token by token."""
    async def generate():
        async for chunk in agent.astream(request.message, request.session_id):
            yield f"data: {json.dumps(chunk)}\n\n"
    return StreamingResponse(generate(), media_type="text/event-stream")

@app.post("/report")
async def report(request: ReportRequest) -> ReportResponse:
    """Generate a structured threat briefing."""
    result = await agent.ainvoke(request.query)
    return ReportResponse(
        summary=result["analysis"],
        sources=result["sources"],
        confidence=result["confidence"],
        generated_at=datetime.utcnow()
    )
```

**Request/response models (Pydantic):**
```python
class ChatRequest(BaseModel):
    message: str
    session_id: str = Field(default_factory=lambda: str(uuid4()))

class ReportRequest(BaseModel):
    query: str
    severity_filter: str | None = None
    date_range_days: int = 7

class ReportResponse(BaseModel):
    summary: str
    sources: list[str]
    confidence: float
    generated_at: datetime
```

**Acceptance criteria:**
- `/chat` streams Server-Sent Events (SSE) correctly
- `/report` returns a complete JSON response
- `/health` returns 200 when all dependencies (Postgres, ChromaDB) are reachable
- Request validation catches malformed inputs with clear error messages
- CORS configured for frontend access

---

### 3.7 Add conversation memory

Persist chat history so the agent understands follow-up questions.

**Implementation details:**
- Store messages in `chat_history` Postgres table
- Group by `session_id` (UUID per conversation)
- Load last N messages (default 10) as context for each new query
- Trim old sessions after 24 hours (background cleanup task)

**Memory integration with LangGraph:**
```python
from langgraph.checkpoint.postgres import PostgresSaver

checkpointer = PostgresSaver(conn_string=POSTGRES_URL)

# Compile graph with memory
agent = graph.compile(checkpointer=checkpointer)

# Invoke with thread_id for session persistence
result = await agent.ainvoke(
    {"messages": [HumanMessage(content=query)]},
    config={"configurable": {"thread_id": session_id}}
)
```

**Acceptance criteria:**
- Follow-up questions work: "What about Apache?" after "Show me critical CVEs"
- Session isolation: different session_ids don't leak context
- Old sessions cleaned up automatically
- Memory doesn't grow unbounded (max 10 messages per session in context)

---

### 3.8 Write agent evaluation tests

Systematic testing of the agent's reasoning quality.

**Test suite (15+ queries across all routing paths):**

**Semantic queries:**
1. "What are the most dangerous threats targeting web applications?"
2. "Tell me about recent supply chain attacks"
3. "What vulnerabilities affect container orchestration tools?"

**Structured queries:**
4. "How many critical CVEs were published this week?"
5. "What's the average CVSS score by severity level?"
6. "Top 5 most affected software products"

**Hybrid queries:**
7. "Summarize critical CVEs affecting Python packages this month"
8. "Compare the severity of Apache vs Nginx vulnerabilities"
9. "What P1 threats should I prioritize for our Django stack?"

**Follow-up queries (test memory):**
10. "What about the last 30 days?" (after query 4)
11. "Can you go deeper on the top one?" (after query 6)

**Edge cases:**
12. "Hello, what can you do?" (general, no tools needed)
13. "" (empty query)
14. "asdfghjkl" (gibberish)
15. "DROP TABLE threat_events;" (SQL injection attempt)

**Evaluation criteria per query:**
- Correct routing (did it use the right tools?)
- Factual grounding (are claims backed by retrieved data?)
- Source citations present (CVE IDs referenced?)
- Response quality (coherent, actionable, appropriate length?)
- Latency (under 10 seconds for full response?)

**Acceptance criteria:**
- All 15 queries execute without errors
- Correct routing for at least 12/15 queries
- SQL injection attempt is safely rejected
- Empty/gibberish queries return helpful error messages
- Test results logged in a structured format for comparison across changes

---

## Sprint 3 definition of done

- [ ] LangGraph state graph designed and implemented
- [ ] Retriever node performs semantic search with metadata filtering
- [ ] SQL tool node translates natural language to safe SQL queries
- [ ] Reasoner node synthesizes data into actionable briefings
- [ ] Router correctly classifies and routes queries
- [ ] FastAPI serves `/chat` (streaming) and `/report` endpoints
- [ ] Conversation memory persists across messages in a session
- [ ] 15+ evaluation queries pass with acceptable quality