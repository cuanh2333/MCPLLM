# ===================================================================
# 📚 UNIVERSAL DOCUMENT LOADER + SPLITTER + CHROMA BUILDER
# Cho KB của SOC (MITRE, Sigma, Playbook, CVE, CSV event, v.v.)
# ===================================================================
import os
import shutil
from pathlib import Path

# -----------------------------
# 1️⃣ LOADERS (Document Loaders)
# -----------------------------
try:
    from langchain_community.document_loaders import (
        PyMuPDFLoader,                # PDF
        TextLoader,                   # Markdown (không cần 'unstructured')
        CSVLoader                     # CSV
    )
except ImportError:
    os.system("pip install -q langchain-community pymupdf")
    from langchain_community.document_loaders import (
        PyMuPDFLoader,
        TextLoader,
        CSVLoader
    )

# -----------------------------
# 2️⃣ SPLITTERS (Text Splitters)
# -----------------------------
try:
    from langchain_text_splitters import (
        RecursiveCharacterTextSplitter,  # Cho PDF, text
        MarkdownHeaderTextSplitter       # Cho playbook .md
    )
except ImportError:
    os.system("pip install -q langchain-text-splitters")
    from langchain_text_splitters import (
        RecursiveCharacterTextSplitter,
        MarkdownHeaderTextSplitter
    )

# -----------------------------
# 3️⃣ VECTOR STORE + EMBEDDING
# -----------------------------
try:
    from langchain_chroma import Chroma
    from langchain_huggingface import HuggingFaceEmbeddings
except ImportError:
    os.system("pip install -q langchain-chroma chromadb langchain-huggingface sentence-transformers")
    from langchain_chroma import Chroma
    from langchain_huggingface import HuggingFaceEmbeddings

from langchain_core.documents import Document
# -----------------------------
# 4️⃣ EMBEDDING MODEL
# -----------------------------
embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    encode_kwargs={"normalize_embeddings": True}
)

# ===================================================================
# ⚙️ FUNCTION: LOAD + SPLIT + STORE
# ===================================================================
# ===================================================================
# 📚 (Các import của bạn giữ nguyên ở đây)
# ...
# from langchain_core.documents import Document
# embeddings = HuggingFaceEmbeddings(...)
# ===================================================================

# ===================================================================
# 📚 UNIVERSAL DOCUMENT LOADER + SPLITTER + CHROMA BUILDER
# ===================================================================

import os
import shutil
from pathlib import Path

# -----------------------------
# 1️⃣ (Import Loaders)
# -----------------------------
try:
    from langchain_community.document_loaders import (
        PyMuPDFLoader, TextLoader, CSVLoader
    )
except ImportError:
    # (Code cài đặt của bạn)
    pass 

# -----------------------------
# 2️⃣ (Import Splitters)
# -----------------------------
try:
    from langchain_text_splitters import (
        RecursiveCharacterTextSplitter, MarkdownHeaderTextSplitter
    )
except ImportError:
    # (Code cài đặt của bạn)
    pass

# -----------------------------
# 3️⃣ (Import Vector Store)
# -----------------------------
try:
    from langchain_chroma import Chroma
    from langchain_huggingface import HuggingFaceEmbeddings
except ImportError:
    # (Code cài đặt của bạn)
    pass
    
from langchain_core.documents import Document

# -----------------------------
# 4️⃣ EMBEDDING MODEL (Định nghĩa 1 lần)
# -----------------------------
embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    encode_kwargs={"normalize_embeddings": True}
)

# ===================================================================
# ⚙️ HÀM PHỤ 1: XỬ LÝ FILES (Tách ra từ hàm build)
# (Hàm này giữ nguyên cấu trúc, nhưng thay Markdown loader sang TextLoader)
# ===================================================================
def process_files_into_chunks(
    file_paths: list[Path], 
    chunk_size: int = 1000, 
    chunk_overlap: int = 150
) -> list[Document]:
    """
    Nhận một DANH SÁCH các đường dẫn file và chạy Load + Split
    trên chúng, trả về một danh sách các chunks.
    """
    docs_all = []
    
    pdf_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size, chunk_overlap=chunk_overlap
    )
    md_splitter = MarkdownHeaderTextSplitter(headers_to_split_on=[
        ("#", "Header 1"), ("##", "Header 2"), ("###", "Header 3")
    ])

    for file in file_paths:
        ext = file.suffix.lower()
        split_docs = []
        try:
            if ext == ".pdf":
                loader = PyMuPDFLoader(str(file))
                docs = loader.load()
                split_docs = pdf_splitter.split_documents(docs)
                
            elif ext in (".md", ".markdown"):
                # ✅ Dùng TextLoader thay cho UnstructuredMarkdownLoader
                loader = TextLoader(str(file), encoding="utf-8")
                docs = loader.load()
                # MarkdownHeaderTextSplitter cần CHUỖI markdown để tách theo header
                merged_markdown = "\n".join([d.page_content for d in docs])
                split_docs = md_splitter.split_text(merged_markdown)  # trả về List[Document]

                # Đảm bảo metadata có 'source'
                for d in split_docs:
                    d.metadata = {**(d.metadata or {}), "source": file.name, "ext": ext}

            elif ext == ".csv":
                loader = CSVLoader(str(file))
                docs = loader.load()
                split_docs = docs  # CSV thường coi mỗi hàng là 1 Document
            
            else:
                print(f"⚠️ Bỏ qua file không hỗ trợ: {file.name}")
                continue

            # Gắn metadata 'source' nếu thiếu
            for doc in split_docs:
                doc.metadata = {**(doc.metadata or {}), "source": doc.metadata.get("source", file.name)}
                
            docs_all.extend(split_docs)
            print(f"✅ Đã xử lý {file.name} thành {len(split_docs)} chunks.")

        except Exception as e:
            print(f"❌ Lỗi khi xử lý {file.name}: {e}")
            
    return docs_all

# ===================================================================
# ⚙️ HÀM PHỤ 2: BUILD DB (Tạo mới)
# (Hàm này giữ nguyên, đã đúng – chỉ đang dùng Chroma từ langchain_chroma)
# ===================================================================
def build_chroma_vectorstore(
    source_dir: str,
    persist_dir: str,
    collection_name: str, # <-- Đảm bảo dùng tên này
    chunk_size: int = 1000,
    chunk_overlap: int = 150
):
    """
    XÓA DB CŨ (nếu có) và BUILD MỚI HOÀN TOÀN.
    """
    source_path = Path(source_dir)
    if not source_path.exists():
        print(f"❌ Không tìm thấy thư mục nguồn: {source_dir}")
        return None
        
    if Path(persist_dir).exists():
        print(f"🧹 Dọn thư mục cũ: {persist_dir}")
        shutil.rmtree(persist_dir)
        
    all_files = [file for file in source_path.glob("*") if file.suffix.lower() in [".pdf", ".md", ".csv"]]
    all_chunks = process_files_into_chunks(all_files, chunk_size, chunk_overlap)
    
    if not all_chunks:
        print("⚠️ Không có tài liệu hợp lệ để embed.")
        return None

    print(f"\n💾 Đang embed {len(all_chunks)} chunks vào Chroma (Tạo mới)...")
    vectorstore = Chroma.from_documents(
        documents=all_chunks,
        embedding=embeddings,
        persist_directory=persist_dir,
        collection_name=collection_name # <-- Dùng tên collection
    )
    
    count = vectorstore._collection.count()
    print(f"✅ Hoàn tất! Đã lưu vào: {persist_dir}")
    print(f"📊 Tổng số tài liệu (chunks) trong collection '{collection_name}': {count}")
    
    return vectorstore

# ===================================================================
# ⚙️ HÀM PHỤ 3: THÊM VÀO DB (*** giữ cấu trúc, chỉ sửa import/collection ***)
# ===================================================================
def add_to_existing_db(
    new_chunks: list[Document], 
    db_directory: str, 
    embedding_model,
    collection_name: str  # <-- *** Đảm bảo truyền tham số này ***
):
    """ Tải DB hiện có và thêm chunks mới vào ĐÚNG collection. """
    if not new_chunks:
        print("Không có tài liệu mới nào để thêm. Bỏ qua.")
        return
    
    print(f"\n--- 🔄 Đang tải DB hiện có từ: {db_directory} (Collection: {collection_name}) ---")
    vectorstore = Chroma(
        persist_directory=db_directory,
        embedding_function=embedding_model,
        collection_name=collection_name # <-- *** Chỉ định collection ***
    )
    
    count_before = vectorstore._collection.count()
    print(f"Số lượng tài liệu trước khi thêm: {count_before}")
    
    print(f"--- ➕ Đang thêm {len(new_chunks)} tài liệu mới vào DB... ---")
    vectorstore.add_documents(new_chunks)
    # Note: persist() không còn cần thiết trong version mới của Chroma
    # Data được tự động persist khi add_documents()
    
    count_after = vectorstore._collection.count()
    print(f"Số lượng tài liệu sau khi thêm: {count_after}")
    print("--- Thêm tài liệu thành công! ---")
    return vectorstore

# ===================================================================
# 🚀 HÀM ĐỒNG BỘ (SYNC) CHÍNH (*** giữ cấu trúc, chỉnh loader/collection ***)
# ===================================================================
def sync_kb_directory(
    source_dir: str, 
    persist_dir: str, 
    embedding_model,
    collection_name: str # <-- *** Truyền tên này ***
):
    """
    Kiểm tra file nào trong source_dir đã có trong DB,
    và chỉ nạp (ingest) những file MỚI vào ĐÚNG collection.
    """
    db_path = Path(persist_dir)
    source_path = Path(source_dir)
    
    # 1. KIỂM TRA BUILD LẦN ĐẦU
    if not db_path.exists():
        print(f"⚠️ Không tìm thấy DB tại {persist_dir}.")
        print("Bắt đầu BUILD DB MỚI...")
        build_chroma_vectorstore(
            source_dir=source_dir, 
            persist_dir=persist_dir,
            collection_name=collection_name # <-- *** Truyền tên ***
        )
        return

    # 2. DB ĐÃ TỒN TẠI -> TẢI VÀ KIỂM TRA
    print(f"✅ Đã tìm thấy DB. Đang tải (Collection: {collection_name})...")
    vectorstore = Chroma(
        persist_directory=persist_dir,
        embedding_function=embedding_model,
        collection_name=collection_name # <-- *** Chỉ định collection ***
    )
    
    current_doc_count = vectorstore._collection.count()
    print(f"📊 Số tài liệu (chunks) hiện có trong collection '{collection_name}': {current_doc_count}")
    
    all_docs_in_db = vectorstore.get(include=["metadatas"])
    processed_files = set()
    if all_docs_in_db and all_docs_in_db['metadatas']:
        for meta in all_docs_in_db['metadatas']:
            if 'source' in meta:
                processed_files.add(meta['source'])
                
    print(f"🔍 Đã tìm thấy {len(processed_files)} file đã được xử lý trong DB.")

    # 3. QUÉT THƯ MỤC NGUỒN
    print(f"📂 Đang quét thư mục nguồn: {source_dir}")
    files_on_disk = [
        file for file in source_path.glob("*") 
        if file.suffix.lower() in [".pdf", ".md", ".csv"]
    ]
    
    # 4. TÌM FILE MỚI
    new_files_to_process = []
    for file in files_on_disk:
        if file.name not in processed_files:
            new_files_to_process.append(file)
            
    if not new_files_to_process:
        print("\n--- ✅ KB ĐÃ ĐƯỢC ĐỒNG BỘ. Không có file mới. ---")
        return

    print(f"\n--- 📣 Phát hiện {len(new_files_to_process)} file MỚI cần nạp ---")
    for f in new_files_to_process:
        print(f"  -> {f.name}")

    # 5. XỬ LÝ VÀ THÊM FILE MỚI
    new_chunks = process_files_into_chunks(new_files_to_process)
    
    add_to_existing_db(
        new_chunks=new_chunks,
        db_directory=persist_dir,
        embedding_model=embedding_model,
        collection_name=collection_name # <-- *** Truyền tên ***
    )
    
    print("\n--- ✅ Đồng bộ KB hoàn tất! ---")

# ===================================================================
# 📦 HÀM MAIN (ĐỂ CHẠY) (*** giữ cấu trúc, đồng bộ import sửa ***)
# ===================================================================
if __name__ == "__main__":
    
    # --- 1. Định nghĩa các đường dẫn VÀ TÊN ---
    SRC_DIR = r"D:\MCPLLM\KB\Security" 
    CHROMA_DIR = r"D:\MCPLLM\KB\chroma_db"
    # *** Tên collection 1 lần duy nhất ***
    MY_COLLECTION_NAME = "security_knowledge_base"
    
    # --- 2. Chạy hàm đồng bộ (SYNC) ---
    sync_kb_directory(
        source_dir=SRC_DIR,
        persist_dir=CHROMA_DIR,
        embedding_model=embeddings,
        collection_name=MY_COLLECTION_NAME
    )

    # --- 3. Query thử (Tùy chọn) ---
    print("\n--- KIỂM TRA: Tải DB và query thử ---")
    try:
        final_db = Chroma(
            persist_directory=CHROMA_DIR,
            embedding_function=embeddings,
            collection_name=MY_COLLECTION_NAME
        )
        total = final_db._collection.count()
        print(f"📦 DB hiện có {total} chunks.")
        final_count = final_db._collection.count()
        print(f"📊 Tổng số tài liệu cuối cùng trong collection '{MY_COLLECTION_NAME}': {final_count}")
        try:
            all_docs = final_db.get(include=["metadatas"])
        except Exception:
            all_docs = final_db._collection.get(include=["metadatas"])  # fallback

        # In danh sách các file nguồn
        sources = set()
        if all_docs and all_docs.get("metadatas"):
            for meta in all_docs["metadatas"]:
                if isinstance(meta, dict) and "source" in meta:
                    sources.add(meta["source"])

        print(f"📦 Tổng số source khác nhau: {len(sources)}")
        for s in sorted(sources):
            print(f" - {s}")
        print()
    #     query = "IP: 192.168.1.100"
    #     print(f"\nĐang tìm kiếm: '{query}'")
    #     results = final_db.similarity_search(query, k=5)
        
    #     if results:
    #         print(f"Tìm thấy {len(results)} kết quả:")
    #         for doc in results:
    #              print(f"-> {doc.page_content[:300]}... (Nguồn: {doc.metadata.get('source','?')})")
    #     else:
    #         print("Không tìm thấy kết quả.")
    except Exception as e:
        print(f"❌ Lỗi khi query: {e}")
