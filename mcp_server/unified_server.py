"""
Unified MCP Server - Combines Log Server + RAG Server
Provides both log retrieval and knowledge base functionality via HTTP
"""

import os
import sys
import json
import asyncio
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

import uvicorn
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Unified MCP Server",
    description="Combined Log Server + RAG Server for MCPLLM",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# REQUEST/RESPONSE MODELS
# ============================================================================

class LogFileRequest(BaseModel):
    filepath: str
    max_lines: Optional[int] = None

class SplunkQueryRequest(BaseModel):
    index: str = "main"
    sourcetype: str = "access_combined"
    earliest_time: str = "-5m"
    latest_time: str = "now"
    search_query: Optional[str] = None



class RAGQueryRequest(BaseModel):
    query: str
    top_k: int = 5
    alpha: float = 0.55
    category: Optional[str] = None

class TICheckRequest(BaseModel):
    ip_address: str

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    services: Dict[str, str]

# ============================================================================
# LOG SERVER FUNCTIONS (from original log_server.py)
# ============================================================================

def load_log_file(filepath: str, max_lines: Optional[int] = None) -> List[str]:
    """Load logs from a local file."""
    try:
        log_path = Path(filepath)
        
        if not log_path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        if not log_path.is_file():
            raise IOError(f"Path is not a file: {filepath}")
        
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()
        
        # Strip newlines and filter empty lines
        lines = [line.strip() for line in lines if line.strip()]
        
        # Apply max_lines limit if specified
        if max_lines and max_lines > 0:
            lines = lines[-max_lines:]  # Return most recent lines
        
        logger.info(f"Successfully loaded {len(lines)} lines from {filepath}")
        return lines
        
    except Exception as e:
        logger.error(f"Error loading log file {filepath}: {e}")
        raise

def splunk_query(
    index: str = "main",
    sourcetype: str = "access_combined", 
    earliest_time: str = "-5m",
    latest_time: str = "now",
    search_query: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Query Splunk for logs."""
    try:
        import splunklib.client as client
        
        # Get Splunk credentials from environment
        splunk_host = os.getenv("SPLUNK_HOST", "localhost")
        splunk_port = int(os.getenv("SPLUNK_PORT", "8089"))
        splunk_username = os.getenv("SPLUNK_USERNAME", "admin")
        splunk_password = os.getenv("SPLUNK_PASSWORD", "")
        
        if not splunk_password:
            raise ValueError("SPLUNK_PASSWORD environment variable is required")
        
        # Connect to Splunk
        service = client.connect(
            host=splunk_host,
            port=splunk_port,
            username=splunk_username,
            password=splunk_password,
            scheme="https"
        )
        
        # Build search query
        if search_query:
            query = f'search index="{index}" sourcetype="{sourcetype}" {search_query}'
        else:
            query = f'search index="{index}" sourcetype="{sourcetype}"'
        
        # Execute search
        search_kwargs = {
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "output_mode": "json"
        }
        
        job = service.jobs.create(query, **search_kwargs)
        
        # Wait for job completion
        while not job.is_done():
            asyncio.sleep(0.1)
        
        # Get results
        results = []
        for result in job.results():
            results.append(dict(result))
        
        logger.info(f"Splunk query returned {len(results)} results")
        return results
        
    except Exception as e:
        logger.error(f"Splunk query error: {e}")
        raise

# ============================================================================
# THREAT INTELLIGENCE FUNCTIONS
# ============================================================================

async def abuseipdb_check(ip_address: str) -> Dict[str, Any]:
    """Check IP reputation via AbuseIPDB API."""
    abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
    if not abuseipdb_key:
        raise ValueError("ABUSEIPDB_API_KEY not configured")
    
    try:
        headers = {
            'Key': abuseipdb_key,
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': ''
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params
            )
            response.raise_for_status()
            
            data = response.json()
            if data.get('data'):
                result = data['data']
                return {
                    'ip_address': result.get('ipAddress'),
                    'abuse_confidence_score': result.get('abuseConfidencePercentage', 0),
                    'total_reports': result.get('totalReports', 0),
                    'country_code': result.get('countryCode'),
                    'usage_type': result.get('usageType'),
                    'isp': result.get('isp'),
                    'is_public': result.get('isPublic', True),
                    'is_whitelisted': result.get('isWhitelisted', False),
                    'last_reported_at': result.get('lastReportedAt')
                }
            
            return {"error": "No data found"}
            
    except Exception as e:
        logger.error(f"AbuseIPDB API error for {ip_address}: {e}")
        raise

async def virustotal_ip(ip_address: str) -> Dict[str, Any]:
    """Check IP reputation via VirusTotal API."""
    virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not virustotal_key:
        raise ValueError("VIRUSTOTAL_API_KEY not configured")
    
    try:
        headers = {
            'x-apikey': virustotal_key
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f'https://www.virustotal.com/vtapi/v2/ip-address/report',
                headers=headers,
                params={'ip': ip_address}
            )
            response.raise_for_status()
            
            data = response.json()
            if data.get('response_code') == 1:
                return {
                    'ip_address': ip_address,
                    'detected_urls': data.get('detected_urls', []),
                    'detected_samples': data.get('detected_samples', []),
                    'resolutions': data.get('resolutions', []),
                    'country': data.get('country'),
                    'as_owner': data.get('as_owner'),
                    'asn': data.get('asn')
                }
            
            return {"error": "No data found"}
            
    except Exception as e:
        logger.error(f"VirusTotal API error for {ip_address}: {e}")
        raise

# ============================================================================
# RAG SERVER FUNCTIONS (Hybrid Retrieval - BM25 + Vector Search)
# ============================================================================

import hashlib
import re
from rank_bm25 import BM25Okapi
from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

# Global variables for RAG
rag_initialized = False
vectorstore = None
all_docs = None
bm25 = None
doc_keys = None
embeddings_model = None

# Config
VECTOR_STORE_PATH = "./chroma_db"
MY_COLLECTION_NAME = "security_knowledge_base"

# Helper functions for hybrid retrieval
def doc_key(d):
    """Generate unique key for document."""
    meta = d.metadata or {}
    src = meta.get("source_url") or meta.get("source") or ""
    title = meta.get("title") or meta.get("cheatsheet_name") or meta.get("id") or ""
    aux = meta.get("yaml_path") or meta.get("technique_id") or meta.get("technique_name") or ""
    head = (d.page_content or "")[:256]
    h = hashlib.md5(head.encode("utf-8", "ignore")).hexdigest()[:8]
    return f"{src}|{title}|{aux}|{h}"

def payload_tokenize(text: str):
    """Tokenize text for BM25."""
    text = (text or "").lower()
    return [t for t in re.findall(
        r"[a-z0-9_]+|[\$\{\}\|\&\;\=\.\:/\\'\"][\$\{\}\|\&\;\=\.\:/\\'\"0-9a-z_]*",
        text,
    ) if len(t) > 1 or t in ("'", '"', "/", "=", ".")]

def bm25_build_corpus(docs):
    """Build BM25 corpus from documents."""
    corpus = []
    keys = []
    for d in docs:
        meta_bits = []
        for k in ("title", "tags", "yaml_path", "technique_id", "technique_name", "cheatsheet_name"):
            v = d.metadata.get(k)
            if v is None:
                continue
            if isinstance(v, list):
                v = " ".join(map(str, v))
            elif isinstance(v, dict):
                v = " ".join(f"{ik}:{iv}" for ik, iv in v.items())
            meta_bits.append(str(v))
        
        blob = " \n ".join([d.page_content or ""] + meta_bits)
        corpus.append(blob)
        keys.append(doc_key(d))
    return corpus, keys

def _minmax(d):
    """Normalize scores to 0-1 range."""
    if not d:
        return {}
    vals = list(d.values())
    lo, hi = min(vals), max(vals)
    if hi == lo:
        return {k: 1.0 for k in d}
    return {k: (v - lo) / (hi - lo) for k, v in d.items()}

def initialize_rag():
    """Initialize RAG components with hybrid retrieval."""
    global rag_initialized, vectorstore, all_docs, bm25, doc_keys, embeddings_model
    
    if rag_initialized:
        return
    
    try:
        logger.info("Loading ChromaDB and embedding model...")
        start_time = datetime.now()
        
        # Load embedding model
        embeddings_model = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            model_kwargs={"device": "cpu"}
        )
        
        # Load vectorstore
        vectorstore = Chroma(
            collection_name=MY_COLLECTION_NAME,
            embedding_function=embeddings_model,
            persist_directory=VECTOR_STORE_PATH
        )
        
        # Load all docs for BM25
        all_docs_data = vectorstore.get()
        all_docs = [
            Document(page_content=content, metadata=meta)
            for content, meta in zip(all_docs_data["documents"], all_docs_data["metadatas"])
        ]
        
        load_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"Loaded {len(all_docs)} documents in {load_time:.2f}s")
        
        # Build BM25 index
        logger.info("Building BM25 index...")
        corpus_texts, doc_keys = bm25_build_corpus(all_docs)
        tokenized_corpus = [payload_tokenize(text) for text in corpus_texts]
        bm25 = BM25Okapi(tokenized_corpus)
        logger.info(f"BM25 index built with {len(corpus_texts)} documents")
        
        rag_initialized = True
        logger.info("RAG components initialized successfully with hybrid retrieval")
        
    except Exception as e:
        logger.error(f"Failed to initialize RAG: {e}")
        raise



def hybrid_search(
    query: str,
    k_dense: int = 10,
    k_sparse: int = 80,
    alpha: float = 0.55,
    category_filter: Optional[str] = None,
):
    """Hybrid search combining dense (vector) and sparse (BM25) retrieval."""
    # Check if query contains IP address - do exact match first
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_matches = re.findall(ip_pattern, query)
    
    if ip_matches and category_filter == "asset":
        # Exact IP match for asset queries
        ip_to_find = ip_matches[0]  # Use first IP found
        exact_matches = []
        docs_to_search = [d for d in all_docs if d.metadata.get("category") == "asset"]
        
        for doc in docs_to_search:
            if ip_to_find in doc.page_content:
                # Extract the specific section containing this IP
                lines = doc.page_content.split('\n')
                ip_section = []
                found_ip = False
                
                for i, line in enumerate(lines):
                    if ip_to_find in line:
                        # Found the IP, now extract the entire section
                        section_start = i
                        for j in range(i - 1, -1, -1):
                            if lines[j].startswith('##'):
                                section_start = j
                                break
                        
                        section_end = len(lines)
                        for j in range(i + 1, len(lines)):
                            if lines[j].startswith('##'):
                                section_end = j
                                break
                        
                        ip_section = lines[section_start:section_end]
                        found_ip = True
                        break
                
                if found_ip and ip_section:
                    section_content = '\n'.join(ip_section).strip()
                    section_doc = Document(
                        page_content=section_content,
                        metadata=doc.metadata
                    )
                    exact_matches.append((section_doc, 0.99))
                else:
                    exact_matches.append((doc, 0.99))
        
        if exact_matches:
            return exact_matches
    
    # Filter docs by category if specified
    if category_filter:
        # Handle different filter types
        if category_filter == "sigma_rule":
            filtered_docs = [d for d in all_docs if d.metadata.get("source_type") == "sigma_rule"]
        elif category_filter == "mitre_attack":
            filtered_docs = [d for d in all_docs if d.metadata.get("source_type") == "mitre_attack"]
        elif category_filter == "owasp_cheatsheet":
            filtered_docs = [d for d in all_docs if d.metadata.get("source_type") == "owasp_cheatsheet"]
        else:
            # For other categories, use the category field
            filtered_docs = [d for d in all_docs if d.metadata.get("category") == category_filter]
        
        if not filtered_docs:
            return []
        
        # Rebuild BM25 for filtered docs
        corpus_texts_filtered, doc_keys_filtered = bm25_build_corpus(filtered_docs)
        tokenized_corpus_filtered = [payload_tokenize(text) for text in corpus_texts_filtered]
        bm25_filtered = BM25Okapi(tokenized_corpus_filtered)
        
        # Dense search on filtered
        dense_results = vectorstore.similarity_search_with_score(query, k=min(k_dense, len(filtered_docs)))
        
        # Filter dense results based on category type
        if category_filter in ["sigma_rule", "mitre_attack", "owasp_cheatsheet"]:
            dense_results = [(doc, score) for doc, score in dense_results 
                            if doc.metadata.get("source_type") == category_filter]
        else:
            dense_results = [(doc, score) for doc, score in dense_results 
                            if doc.metadata.get("category") == category_filter]
        
        # BM25 on filtered
        query_tokens = payload_tokenize(query)
        bm25_scores = bm25_filtered.get_scores(query_tokens)
        bm25_results = sorted(zip(filtered_docs, bm25_scores), key=lambda x: x[1], reverse=True)[:k_sparse]
    else:
        # Dense search (vector similarity)
        dense_results = vectorstore.similarity_search_with_score(query, k=k_dense)
        
        # BM25 search (keyword matching)
        query_tokens = payload_tokenize(query)
        bm25_scores = bm25.get_scores(query_tokens)
        bm25_results = sorted(zip(all_docs, bm25_scores), key=lambda x: x[1], reverse=True)[:k_sparse]
    
    # Normalize scores
    dense_dict = {doc_key(doc): 1.0 - score for doc, score in dense_results}
    bm25_dict = {doc_key(doc): score for doc, score in bm25_results}
    
    dense_norm = _minmax(dense_dict)
    bm25_norm = _minmax(bm25_dict)
    
    # Combine scores
    all_keys = set(dense_norm.keys()) | set(bm25_norm.keys())
    hybrid_scores = {}
    for k in all_keys:
        d_score = dense_norm.get(k, 0.0)
        b_score = bm25_norm.get(k, 0.0)
        hybrid_scores[k] = alpha * d_score + (1 - alpha) * b_score
    
    # Map back to documents
    key_to_doc = {}
    for doc in (all_docs if not category_filter else filtered_docs):
        key_to_doc[doc_key(doc)] = doc
    
    # Sort by hybrid score
    ranked = sorted(hybrid_scores.items(), key=lambda x: x[1], reverse=True)
    results = [(key_to_doc[k], score) for k, score in ranked if k in key_to_doc]
    
    return results

def query_rag(query: str, top_k: int = 5, alpha: float = 0.55, category: Optional[str] = None) -> Dict[str, Any]:
    """Query the RAG system using hybrid retrieval."""
    try:
        # Initialize RAG if needed
        if not rag_initialized:
            logger.info("Initializing RAG system...")
            initialize_rag()
        
        logger.info(f"RAG hybrid query: {query}")
        
        # Use hybrid search
        results = hybrid_search(
            query=query,
            k_dense=10,
            k_sparse=80,
            alpha=alpha,
            category_filter=category,
        )
        
        top_k_results = results[:top_k]
        
        formatted_results = []
        for doc, score in top_k_results:
            # For Sigma rules, return FULL content (not truncated)
            if category == "sigma_rule":
                content = doc.page_content  # Full content
            else:
                # For other categories, truncate to 300 chars
                content = doc.page_content[:300] + ("..." if len(doc.page_content) > 300 else "")
            
            formatted_results.append({
                "metadata": doc.metadata,
                "content_snippet": content,
                "hybrid_score": round(score, 4),
            })
        
        logger.info(f"RAG returned {len(formatted_results)} results")
        
        return {
            "query": query,
            "results": formatted_results,
            "total_results": len(formatted_results),
            "parameters": {
                "top_k": top_k,
                "alpha": alpha,
                "category": category
            }
        }
        
    except Exception as e:
        logger.error(f"RAG query error: {e}")
        return {
            "query": query,
            "results": [],
            "total_results": 0,
            "message": f"RAG system error: {str(e)}"
        }

# ============================================================================
# HTTP ENDPOINTS
# ============================================================================

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        services={
            "log_server": "active",
            "rag_server": "active" if rag_initialized else "initializing",
            "splunk": "configured" if os.getenv("SPLUNK_PASSWORD") else "not_configured"
        }
    )

@app.post("/load_log_file")
async def load_log_file_endpoint(request: LogFileRequest):
    """Load logs from a local file."""
    try:
        lines = load_log_file(request.filepath, request.max_lines)
        return {
            "success": True,
            "filepath": request.filepath,
            "lines_count": len(lines),
            "lines": lines
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/splunk_query")
async def splunk_query_endpoint(request: SplunkQueryRequest):
    """Query Splunk for logs."""
    try:
        results = splunk_query(
            index=request.index,
            sourcetype=request.sourcetype,
            earliest_time=request.earliest_time,
            latest_time=request.latest_time,
            search_query=request.search_query
        )
        return {
            "success": True,
            "results_count": len(results),
            "results": results,
            "query_params": {
                "index": request.index,
                "sourcetype": request.sourcetype,
                "earliest_time": request.earliest_time,
                "latest_time": request.latest_time
            }
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))



@app.post("/query_rag")
async def query_rag_endpoint(request: RAGQueryRequest):
    """Query the RAG knowledge base with hybrid retrieval."""
    try:
        results = query_rag(request.query, request.top_k, request.alpha, request.category)
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/abuseipdb_check")
async def abuseipdb_check_endpoint(request: TICheckRequest):
    """Check IP reputation via AbuseIPDB."""
    try:
        result = await abuseipdb_check(request.ip_address)
        return {
            "success": True,
            "ip_address": request.ip_address,
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/virustotal_ip")
async def virustotal_ip_endpoint(request: TICheckRequest):
    """Check IP reputation via VirusTotal."""
    try:
        result = await virustotal_ip(request.ip_address)
        return {
            "success": True,
            "ip_address": request.ip_address,
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/")
async def root():
    """Root endpoint with server info."""
    return {
        "name": "Unified MCP Server",
        "version": "1.0.0",
        "description": "Combined Log Server + RAG Server for MCPLLM",
        "endpoints": {
            "health": "/health",
            "load_log_file": "/load_log_file",
            "splunk_query": "/splunk_query",
            "query_rag": "/query_rag",
            "abuseipdb_check": "/abuseipdb_check",
            "virustotal_ip": "/virustotal_ip"
        },
        "status": "running"
    }

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Starting Unified MCP Server")
    print("=" * 60)
    print("📋 Services:")
    print("   • Log Server (file + Splunk)")
    print("   • RAG Server (knowledge base)")
    print("🌐 Endpoints:")
    print("   • Health: http://127.0.0.1:8001/health")
    print("   • Docs: http://127.0.0.1:8001/docs")
    print("=" * 60)
    
    # Initialize RAG components at startup
    print("🔄 Initializing RAG components...")
    try:
        initialize_rag()
        print("✅ RAG system ready with hybrid retrieval!")
        print(f"   • Loaded {len(all_docs)} documents")
        print(f"   • BM25 + Vector search enabled")
    except Exception as e:
        print(f"❌ RAG initialization failed: {e}")
        print("   Server will start but RAG queries will fail")
    
    print("=" * 60 + "\n")
    
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info")