"""
RAG Server - HTTP Transport Version

Chạy như một HTTP server để tránh phải reload ChromaDB mỗi lần query.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import json
import hashlib
import re
from rank_bm25 import BM25Okapi
from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
import logging
import uvicorn

# Tắt logs
logging.basicConfig(level=logging.ERROR)
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
logging.getLogger("posthog").setLevel(logging.ERROR)
logging.getLogger("chromadb").setLevel(logging.ERROR)

# Config
VECTOR_STORE_PATH = r"D:\MCPLLM\KB\chroma_db"
MY_COLLECTION_NAME = "security_knowledge_base"

# Initialize FastAPI
app = FastAPI(title="RAG Server", version="1.0.0")

# Global variables (load once at startup)
vectorstore = None
all_docs = None
bm25 = None
doc_keys = None

print("Loading ChromaDB and embedding model...")
start_time = __import__('time').time()

# Load embedding model
embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    model_kwargs={"device": "cpu"}
)

# Load vectorstore
vectorstore = Chroma(
    collection_name=MY_COLLECTION_NAME,
    embedding_function=embeddings,
    persist_directory=VECTOR_STORE_PATH
)

# Load all docs for BM25
all_docs = vectorstore.get()
all_docs = [
    Document(page_content=content, metadata=meta)
    for content, meta in zip(all_docs["documents"], all_docs["metadatas"])
]

print(f"Loaded {len(all_docs)} documents in {__import__('time').time() - start_time:.2f}s")

# Helper functions
def doc_key(d):
    meta = d.metadata or {}
    src = meta.get("source_url") or meta.get("source") or ""
    title = meta.get("title") or meta.get("cheatsheet_name") or meta.get("id") or ""
    aux = meta.get("yaml_path") or meta.get("technique_id") or meta.get("technique_name") or ""
    head = (d.page_content or "")[:256]
    h = hashlib.md5(head.encode("utf-8", "ignore")).hexdigest()[:8]
    return f"{src}|{title}|{aux}|{h}"


def payload_tokenize(text: str):
    text = (text or "").lower()
    return [
        t
        for t in re.findall(
            r"[a-z0-9_]+|[\$\{\}\|\&\;\=\.\:/\\'\"][\$\{\}\|\&\;\=\.\:/\\'\"0-9a-z_]*",
            text,
        )
        if len(t) > 1 or t in ("'", '"', "/", "=", ".")
    ]


def bm25_build_corpus(docs):
    corpus = []
    keys = []
    for d in docs:
        meta_bits = []
        for k in (
            "title",
            "tags",
            "yaml_path",
            "technique_id",
            "technique_name",
            "cheatsheet_name",
        ):
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
    if not d:
        return {}
    vals = list(d.values())
    lo, hi = min(vals), max(vals)
    if hi == lo:
        return {k: 1.0 for k in d}
    return {k: (v - lo) / (hi - lo) for k, v in d.items()}


# Build BM25 index at startup
print("Building BM25 index...")
corpus_texts, doc_keys = bm25_build_corpus(all_docs)
tokenized_corpus = [payload_tokenize(text) for text in corpus_texts]
bm25 = BM25Okapi(tokenized_corpus)
print(f"BM25 index built with {len(corpus_texts)} documents")


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
                # Asset.md format: Each asset is a ## section with multiple lines
                lines = doc.page_content.split('\n')
                ip_section = []
                found_ip = False
                
                for i, line in enumerate(lines):
                    if ip_to_find in line:
                        # Found the IP, now extract the entire section
                        # Go backwards to find the ## header
                        section_start = i
                        for j in range(i - 1, -1, -1):
                            if lines[j].startswith('##'):
                                section_start = j
                                break
                        
                        # Go forwards to find the next ## or end of doc
                        section_end = len(lines)
                        for j in range(i + 1, len(lines)):
                            if lines[j].startswith('##'):
                                section_end = j
                                break
                        
                        # Extract the complete section
                        ip_section = lines[section_start:section_end]
                        found_ip = True
                        break
                
                if found_ip and ip_section:
                    # Create a new document with just the relevant section
                    section_content = '\n'.join(ip_section).strip()
                    section_doc = Document(
                        page_content=section_content,
                        metadata=doc.metadata
                    )
                    exact_matches.append((section_doc, 0.99))
                else:
                    # Fallback to original doc
                    exact_matches.append((doc, 0.99))
        
        if exact_matches:
            # Return exact matches with high priority
            return exact_matches
    
    # Filter docs by category if specified
    if category_filter:
        filtered_docs = [
            d for d in all_docs if d.metadata.get("category") == category_filter
        ]
        if not filtered_docs:
            return []
        
        # Rebuild BM25 for filtered docs
        corpus_texts_filtered, doc_keys_filtered = bm25_build_corpus(filtered_docs)
        tokenized_corpus_filtered = [payload_tokenize(text) for text in corpus_texts_filtered]
        bm25_filtered = BM25Okapi(tokenized_corpus_filtered)
        
        # Dense search on filtered
        dense_results = vectorstore.similarity_search_with_score(
            query, k=min(k_dense, len(filtered_docs))
        )
        dense_results = [
            (doc, score)
            for doc, score in dense_results
            if doc.metadata.get("category") == category_filter
        ]
        
        # BM25 on filtered
        query_tokens = payload_tokenize(query)
        bm25_scores = bm25_filtered.get_scores(query_tokens)
        bm25_results = sorted(
            zip(filtered_docs, bm25_scores), key=lambda x: x[1], reverse=True
        )[:k_sparse]
        
    else:
        # Dense search (vector similarity)
        dense_results = vectorstore.similarity_search_with_score(query, k=k_dense)
        
        # BM25 search (keyword matching)
        query_tokens = payload_tokenize(query)
        bm25_scores = bm25.get_scores(query_tokens)
        bm25_results = sorted(
            zip(all_docs, bm25_scores), key=lambda x: x[1], reverse=True
        )[:k_sparse]
    
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


# API Models
class QueryRequest(BaseModel):
    question: str
    category: Optional[str] = None
    top_k: int = 5


class QueryResponse(BaseModel):
    results: list


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "documents_loaded": len(all_docs),
        "vectorstore": "ready",
        "bm25": "ready"
    }


@app.post("/query_rag", response_model=QueryResponse)
async def query_rag(request: QueryRequest):
    """Query RAG knowledge base."""
    try:
        results = hybrid_search(
            query=request.question,
            k_dense=10,
            k_sparse=80,
            alpha=0.55,
            category_filter=request.category,
        )
        
        top_k_results = results[: request.top_k]
        
        formatted_results = []
        for doc, score in top_k_results:
            # For Sigma rules, return FULL content (not truncated)
            # GenRuleAgent needs complete YAML rules
            if request.category == "sigma_rule":
                content = doc.page_content  # Full content
            else:
                # For other categories, truncate to 300 chars
                content = doc.page_content[:300] + ("..." if len(doc.page_content) > 300 else "")
            
            formatted_results.append({
                "metadata": doc.metadata,
                "content_snippet": content,
                "hybrid_score": round(score, 4),
            })
        
        return QueryResponse(results=formatted_results)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Query failed: {str(e)}")


if __name__ == "__main__":
    print("\n" + "="*60)
    print("RAG Server Ready!")
    print("="*60)
    print("Listening on: http://127.0.0.1:8001")
    print("Health check: http://127.0.0.1:8001/health")
    print("Query endpoint: POST http://127.0.0.1:8001/query_rag")
    print("="*60 + "\n")
    
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="error")
