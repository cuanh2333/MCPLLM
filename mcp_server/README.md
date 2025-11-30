# MCP Servers

This directory contains MCP (Model Context Protocol) servers for the V3 Log Analyzer.

## Servers

### 1. log_server.py
**Purpose**: Log retrieval and threat intelligence

**Tools**:
- `load_log_file`: Load logs from local files
- `splunk_search`: Retrieve logs from Splunk
- `cron_splunk_query`: Scheduled Splunk queries
- `abuseipdb_check`: Check IP reputation (AbuseIPDB)
- `virustotal_ip`: Check IP reputation (VirusTotal)

**Usage**:
```bash
python run_mcp_server.py
```

### 2. rag_server.py
**Purpose**: Knowledge base query (OWASP/MITRE/Sigma)

**Tools**:
- `query_rag`: Query security knowledge base with hybrid search (BM25 + Dense)

**Parameters**:
- `question` (str): User's security question
- `category` (str, optional): Filter by category
  - `"asset"`: Search only in Asset.md
  - `"sigma"`: Search only in Sigma rules
  - `None`: Full hybrid search

**Usage**:
```bash
python run_rag_server.py
# or
python mcp_server/rag_server.py
```

**Test**:
```bash
python test_mcp_rag_connection.py
```

## Architecture

```
Backend (FastAPI)
    ↓
┌─────────────────────────────────────┐
│  MCP Clients (via stdio)            │
│  - AnalysisOrchestrator             │
│  - QueryRAGAgent                    │
└─────────────────────────────────────┘
    ↓                    ↓
┌──────────────┐   ┌──────────────┐
│ log_server.py│   │ rag_server.py│
│              │   │              │
│ Tools:       │   │ Tools:       │
│ - load_log   │   │ - query_rag  │
│ - splunk     │   │              │
│ - abuseipdb  │   │ ChromaDB:    │
│ - virustotal │   │ - Vector DB  │
└──────────────┘   │ - BM25 Index │
                   └──────────────┘
```

## Configuration

### log_server.py
Environment variables:
- `SPLUNK_HOST`: Splunk server hostname
- `SPLUNK_PORT`: Splunk server port (default: 8089)
- `SPLUNK_USERNAME`: Splunk username
- `SPLUNK_PASSWORD`: Splunk password
- `ABUSEIPDB_API_KEY`: AbuseIPDB API key
- `VIRUSTOTAL_API_KEY`: VirusTotal API key

### rag_server.py
Configuration in file:
- `VECTOR_STORE_PATH`: Path to ChromaDB (default: `D:\MCPLLM\test\chroma_sec_db`)
- `MY_COLLECTION_NAME`: Collection name (default: `security_knowledge_base`)
- Embedding model: `all-MiniLM-L6-v2`
- Hybrid search alpha: 0.55 (dense weight)

## Development

### Adding a New Tool to log_server.py
```python
@mcp.tool()
def my_new_tool(param1: str, param2: int) -> str:
    """
    Tool description.
    
    Args:
        param1: Description
        param2: Description
    
    Returns:
        Result description
    """
    # Implementation
    return result
```

### Adding a New Tool to rag_server.py
```python
@mcp.tool(name="my_tool")
def My_Tool(param: str) -> str:
    """Tool description."""
    # Implementation
    return json.dumps(result, ensure_ascii=False)
```

## Troubleshooting

### log_server.py Issues

**"Splunk connection failed"**:
- Check `SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_USERNAME`, `SPLUNK_PASSWORD`
- Verify Splunk server is accessible
- Check firewall rules

**"AbuseIPDB/VirusTotal API error"**:
- Check API keys are valid
- Check rate limits (free tier)
- Verify internet connection

### rag_server.py Issues

**"ChromaDB not found"**:
- Check `VECTOR_STORE_PATH` exists
- Verify ChromaDB is initialized
- Run: `python check_metadata.py`

**"No results from query_rag"**:
- Check collection has documents
- Verify embedding model is loaded
- Check query keywords

**"Category filter not working"**:
- Verify documents have correct metadata
- Run: `python main.py` to update categories
- Check category values: "asset", "sigma_rule"

## Testing

### Test log_server.py
```bash
# Test file loading
python -c "from mcp_server.log_server import load_log_file; print(load_log_file('web_attack_logs.txt')[:5])"

# Test Splunk (if configured)
python test_splunk_query.py
```

### Test rag_server.py
```bash
# Test MCP connection
python test_mcp_rag_connection.py

# Test standalone
python mcp_server/rag_server.py --test
```

## Performance

### log_server.py
- File loading: < 1 second (1000 lines)
- Splunk query: 2-5 seconds (depends on time range)
- AbuseIPDB: 1-2 seconds per IP
- VirusTotal: 1-2 seconds per IP

### rag_server.py
- Hybrid search: 1-2 seconds (1000 documents)
- Dense only: 0.5-1 second
- BM25 only: 0.3-0.5 second
- Category filter: 0.5-1 second (faster than full search)

---

**Version**: 3.0.0  
**Last Updated**: November 17, 2025
