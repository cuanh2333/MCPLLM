# rag_server.py
import json
import hashlib
import re
from rank_bm25 import BM25Okapi
from mcp.server.fastmcp import FastMCP  # <-- Dùng FastMCP
# from langchain_core.tools import tool # <-- Xóa dòng này
from langchain_core.documents import Document
from langchain_chroma import Chroma

# --- 1. SỬA LỖI CẢNH BÁO DEPRECATION ---
# from langchain_community.embeddings import HuggingFaceEmbeddings # <-- Dòng cũ
from langchain_huggingface import HuggingFaceEmbeddings # <-- Dòng mới
import logging  # <-- 1. THÊM IMPORT
import sys      # <-- 2. THÊM IMPORT

# --- 3. THÊM KHỐI CODE NÀY ĐỂ "IM LẶNG" SERVER ---
# Tắt tất cả log (INFO, WARNING) của các thư viện
logging.basicConfig(level=logging.ERROR)
# Ghi đè log của các thư viện "ồn ào"
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
logging.getLogger("posthog").setLevel(logging.ERROR)
logging.getLogger("chromadb").setLevel(logging.ERROR)
# --- KẾT THÚC KHỐI "IM LẶNG" ---
# --- Cấu hình ---
VECTOR_STORE_PATH = r"D:\MCPLLM\KB\chroma_db" # <-- Thêm 'r'
MY_COLLECTION_NAME = "security_knowledge_base" 

# --- 2. KHỞI TẠO FASTMCP ---
mcp = FastMCP("rag_server")
# mcp = FastMCP("rag_server",
#     host="0.0.0.0",  # <-- Chuyển host lên đây
#     port=8000) # <-- Khởi tạo server mcp

# --- (Các hàm helper: doc_key, payload_tokenize, bm25_build_corpus, _minmax) ---
# (Giữ nguyên các hàm này, tôi ẩn đi cho ngắn gọn)
def doc_key(d):
    meta = d.metadata or {}
    src = meta.get("source_url") or meta.get("source") or ""
    title = meta.get("title") or meta.get("cheatsheet_name") or meta.get("id") or ""
    aux = meta.get("yaml_path") or meta.get("technique_id") or meta.get("technique_name") or ""
    head = (d.page_content or "")[:256]
    h = hashlib.md5(head.encode("utf-8","ignore")).hexdigest()[:8]
    return f"{src}|{title}|{aux}|{h}"

def payload_tokenize(text: str):
    text = (text or "").lower()
    return [t for t in re.findall(r"[a-z0-9_]+|[\$\{\}\|\&\;\=\.\:/\\'\"][\$\{\}\|\&\;\=\.\:/\\'\"0-9a-z_]*", text)
            if len(t) > 1 or t in ("'", '"', "/", "=", ".")]

def bm25_build_corpus(docs):
    corpus = []
    keys = []
    for d in docs:
        meta_bits = []
        for k in ("title","tags","yaml_path","technique_id","technique_name","cheatsheet_name"):
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
    if not d: return {}
    vals = list(d.values()); lo, hi = min(vals), max(vals)
    if hi == lo: return {k: 1.0 for k in d}
    return {k: (v - lo) / (hi - lo) for k, v in d.items()}


# --- THAY THẾ TOÀN BỘ HÀM NÀY ---
# (Trong rag_server.py)

# --- THAY THẾ TOÀN BỘ HÀM NÀY ---
def hybrid_search(query: str, k_dense=10, k_sparse=80, alpha=0.60, category_filter: str = None):
    
    search_filter = None
    
    # 1. "Dịch" category thành bộ lọc ChromaDB
    if category_filter == "asset":
        search_filter = {"source": "Asset.md"}
    elif category_filter == "sigma":
        # SỬA LỖI: Dùng category đã được cập nhật
        search_filter = {"category": "sigma_rule"}

    # KỊCH BẢN 2: CÓ LỌC (category="asset" hoặc category="sigma")
    if search_filter:
        # Khi có lọc, chúng ta chỉ chạy Dense Search (Chroma)
        # vì BM25 index của bạn không được lọc.
        
        # print(f"--- Đang chạy Filtered Dense Search (filter: {search_filter}) ---")
        dense_hits = vectorstore.similarity_search_with_score(
            query, 
            k=k_dense,
            filter=search_filter
        )
        
        results = []
        for d, s in dense_hits:
            results.append((d, 1.0 - float(s))) 
        
        return results

    # KỊCH BẢN 1: KHÔNG LỌC (category=None)
    # -> Chạy Hybrid Search (BM25 + Dense) trên 1000 file NHƯ CŨ
    else:
        # print("--- Đang chạy Full Hybrid Search (không lọc) ---")
        # 1. Dense (Giữ nguyên code cũ)
        dense_hits = vectorstore.similarity_search_with_score(query, k=k_dense)
        dense_scores = {}
        for d, s in dense_hits:
            k = doc_key(d)
            dense_scores[k] = 1.0 - float(s)

        # 2. Sparse (Giữ nguyên code cũ)
        qtok = payload_tokenize(query)
        sparse_arr = bm25_model.get_scores(qtok) 
        all_sparse_scores = [(i, sc) for i, sc in enumerate(sparse_arr) if sc > 0]
        top_k_sparse_indices = sorted(all_sparse_scores, key=lambda x: x[1], reverse=True)[:k_sparse]
        sparse_scores = { bm25_keys[i]: float(sc) for i, sc in top_k_sparse_indices }

        # 3. Trộn (Giữ nguyên code cũ)
        dn, sn = _minmax(dense_scores), _minmax(sparse_scores)
        keys = set(dn) | set(sn)
        combo = {k: alpha*dn.get(k,0.0) + (1-alpha)*sn.get(k,0.0) for k in keys}

        # 4. Trả kết quả (Giữ nguyên code cũ)
        results = []
        for k, sc in sorted(combo.items(), key=lambda x: x[1], reverse=True):
            d = key2doc_map.get(k)
            if d:
                results.append((d, sc))
        return results

# --- Khởi tạo (Giữ nguyên) ---
# print("RAG Server: Đang tải mô hình Embedding...")
embedding_model = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    model_kwargs={'device': 'cpu'},
    encode_kwargs={'normalize_embeddings': True}
)

# print("RAG Server: Đang kết nối tới Vector Store (Chroma)...")
vectorstore = Chroma(
    persist_directory=VECTOR_STORE_PATH,
    embedding_function=embedding_model,
    collection_name=MY_COLLECTION_NAME 
)

# print("RAG Server: Đang tải toàn bộ tài liệu từ Chroma để xây dựng BM25...")
all_docs_data = vectorstore.get(include=["metadatas", "documents"])
docs_for_bm25 = []
for i, doc_content in enumerate(all_docs_data['documents']):
    doc = Document(
        page_content=doc_content, 
        metadata=all_docs_data['metadatas'][i]
    )
    docs_for_bm25.append(doc)

# print(f"RAG Server: Đã tải {len(docs_for_bm25)} tài liệu. Bắt đầu xây dựng BM25 index...")
corpus_texts, bm25_keys = bm25_build_corpus(docs_for_bm25)
bm25_model = BM25Okapi([payload_tokenize(t) for t in corpus_texts])
key2doc_map = { doc_key(d): d for d in docs_for_bm25 }

# --- 4. SỬA LẠI DECORATOR CỦA TOOL ---
# (Trong rag_server.py)
# --- THAY THẾ TOÀN BỘ HÀM TOOL NÀY ---
@mcp.tool(name="query_rag")
def Query_RAG(question: str, category: str = None) -> str: # <-- (1) Dùng `category: str = None`
    """
    Truy vấn KB.
    (MỚI) Nếu 'category' là 'asset', chỉ tìm trong Asset.md.
    (MỚI) Nếu 'category' là 'sigma', chỉ tìm trong các file Sigma.
    Nếu 'category' để trống, tìm tất cả.
    """
    
    try:
        # (2) TRUYỀN `category` VÀO `category_filter`
        results = hybrid_search(
            query=question, 
            k_dense=10, 
            k_sparse=80, 
            alpha=0.55, 
            category_filter=category 
        )
        
        top_k_results = results[:5]
        
        # (Phần còn lại của hàm giữ nguyên)
        formatted_results = []
        for doc, score in top_k_results:
            formatted_results.append({
                "metadata": doc.metadata,
                "content_snippet": doc.page_content[:300] + "...",
                "hybrid_score": round(score, 4)
            })
        
        return json.dumps(formatted_results, indent=2, ensure_ascii=False)

    except Exception as e:
        return json.dumps({"error": f"Lỗi: không thể xử lý truy vấn RAG. {e}"})
# --- 5. SỬA LẠI CÁCH CHẠY SERVER ---
# Chạy server
import sys  # <-- 1. THÊM IMPORT SYS
import textwrap # <-- 2. THÊM IMPORT (ĐỂ IN ĐẸP)
def show_results(title, results, top_k=5):
    """Hàm helper để in kết quả test cho đẹp."""
    print(f"\n--- {title} (Top {top_k}) ---")
    if not results:
        print("KHÔNG TÌM THẤY KẾT QUẢ.")
        print("-" * 30)
        return
    
    for i, (doc, score) in enumerate(results[:top_k], 1):
        print(f"[{i}] Score: {score:.4f}")
        print(f"    Source:   {doc.metadata.get('source')}")
        print(f"    Category: {doc.metadata.get('category')}") # In category để kiểm tra
        snippet = (doc.page_content or "").replace("\n", " ")
        print(f"    Snippet:  {textwrap.shorten(snippet, width=120)}")
    print("-" * 30)

def run_tests():
    """Chạy các kịch bản test."""
    print("========= BẮT ĐẦU TEST HYBRID SEARCH =========")
    
    # --- Test Case 1: Không lọc (Full Hybrid Search) ---
    query1 = "What are SQL injection detection rules?"
    print(f"Query 1: '{query1}' (Không lọc)")
    results1 = hybrid_search(query1, category_filter=None)
    show_results("Test 1: Full Hybrid Search", results1)

    # --- Test Case 2: Lọc theo "sigma" ---
    # (Giả sử bạn đã chạy script update_categories.py)
    query2 = "f5 bigip bash vulnerability" # Query liên quan đến sigma
    print(f"Query 2: '{query2}' (Lọc: category='sigma')")
    results2 = hybrid_search(query2, category_filter="sigma")
    show_results("Test 2: Filtered Search (Chỉ Sigma)", results2)

    # --- Test Case 3: Lọc theo "asset" ---
    # (Giả sử bạn có source là "Asset.md")
    query3 = "my server ip address" # Query liên quan đến asset
    print(f"Query 3: '{query3}' (Lọc: category='asset')")
    results3 = hybrid_search(query3, category_filter="asset")
    show_results("Test 3: Filtered Search (Chỉ Asset)", results3)
    
    print("========= TEST HOÀN TẤT =========")

if __name__ == "__main__":
    # print("Starting RAG server with tool: [Query_RAG]")
    # Dùng mcp.run() như bạn đã định nghĩa ở trên
    
    # mcp.run(transport="stdio")
    mcp.run(transport="stdio")
    # if "--test" in sys.argv:
    #     # Nếu có, chạy test
    #     run_tests()
    # else:
    #     # Nếu không, chạy server stdio (cho mcpclient)
    #     # (Đã xóa print để "im lặng")
    #     mcp.run(transport="stdio")