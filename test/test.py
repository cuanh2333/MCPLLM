from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_community.vectorstores.utils import filter_complex_metadata
try:
    from langchain_huggingface import HuggingFaceEmbeddings
except ImportError:
    from langchain_community.embeddings import HuggingFaceEmbeddings
import os
import yaml
import json

def parse_chroma_metadata(doc: Document) -> dict:
    """
    Parse metadata từ ChromaDB, convert JSON strings về lại list/dict
    """
    metadata = doc.metadata.copy()
    json_fields = ['tags', 'references', 'detection', 'logsource', 'detection_keywords', 'falsepositives']
    
    for field in json_fields:
        if field in metadata and isinstance(metadata[field], str):
            try:
                metadata[field] = json.loads(metadata[field])
            except (json.JSONDecodeError, TypeError):
                pass  # Giữ nguyên nếu không parse được
    
    return metadata

def format_doc_for_llm(doc: Document, include_full_rule: bool = False) -> str:
    """
    Format document với metadata để LLM dễ đọc
    """
    metadata = parse_chroma_metadata(doc)
    
    output = []
    output.append(f"Title: {metadata.get('title', 'N/A')}")
    output.append(f"ID: {metadata.get('id', 'N/A')}")
    output.append(f"Status: {metadata.get('status', 'N/A')}")
    output.append(f"Level: {metadata.get('level', 'N/A')}")
    output.append(f"Description: {metadata.get('description', 'N/A')}")
    
    if metadata.get('author'):
        output.append(f"Author: {metadata.get('author')}")
    
    if metadata.get('tags'):
        tags = metadata['tags'] if isinstance(metadata['tags'], list) else []
        output.append(f"Tags: {', '.join(str(t) for t in tags)}")
    
    if metadata.get('logsource'):
        logsource = metadata['logsource'] if isinstance(metadata['logsource'], dict) else {}
        output.append(f"Log Source: {json.dumps(logsource, ensure_ascii=False)}")
    
    if metadata.get('detection'):
        detection = metadata['detection'] if isinstance(metadata['detection'], dict) else {}
        if 'keywords' in detection and detection['keywords']:
            keywords = detection['keywords']
            keywords_preview = keywords[:5] if len(keywords) > 5 else keywords
            output.append(f"Detection Keywords: {', '.join(str(k) for k in keywords_preview)}")
            if len(keywords) > 5:
                output.append(f"  (+ {len(keywords)-5} more keywords)")
        if 'condition' in detection:
            output.append(f"Detection Condition: {detection['condition']}")
    
    if metadata.get('references'):
        refs = metadata['references'] if isinstance(metadata['references'], list) else []
        if refs:
            output.append(f"References: {len(refs)} reference(s)")
            for ref in refs[:3]:
                output.append(f"  - {ref}")
            if len(refs) > 3:
                output.append(f"  ... và {len(refs)-3} reference(s) khác")
    
    output.append(f"\nContent:\n{doc.page_content}")
    
    if include_full_rule and metadata.get('full_rule'):
        output.append(f"\nFull Rule YAML:\n{metadata['full_rule']}")
    
    return "\n".join(output)

# Đường dẫn tương đối từ file test.py
sigma_path = os.path.join(os.path.dirname(__file__), "sigma", "rules", "web", "webserver_generic")

# Kiểm tra thư mục có tồn tại không
if not os.path.exists(sigma_path):
    print(f"Error: Thư mục không tồn tại: {sigma_path}")
    print(f"Đường dẫn tuyệt đối: {os.path.abspath(sigma_path)}")
    sigma_raw_docs = []
else:
    try:
        sigma_loader = DirectoryLoader(
            path=sigma_path,
            glob="**/*.yml",
            loader_cls=TextLoader,
            loader_kwargs={'encoding': 'utf-8'}
        )
        sigma_raw_docs = sigma_loader.load()
        print(f"Đã load {len(sigma_raw_docs)} file(s)")
        # In thông tin một vài file đầu tiên
        for i, doc in enumerate(sigma_raw_docs[:3]):
            print(f"\nFile {i+1}: {doc.metadata.get('source', 'N/A')}")
            print(f"Độ dài nội dung: {len(doc.page_content)} ký tự")
    except Exception as e:
        print(f"Lỗi khi load: {e}")
        sigma_raw_docs = []

# Xử lý YAML và tạo processed docs
if sigma_raw_docs:
    print("\n" + "="*50)
    print("Xử lý và parse YAML...")
    print("="*50)
    
    sigma_docs_processed = []
    for doc in sigma_raw_docs:
        try:
            parsed_yaml = yaml.safe_load(doc.page_content)
            
            if parsed_yaml:
                # Tạo summary content chi tiết hơn
                title = parsed_yaml.get('title', 'N/A')
                description = parsed_yaml.get('description', 'N/A')
                level = parsed_yaml.get('level', 'N/A')
                status = parsed_yaml.get('status', 'N/A')
                
                summary_content = f"Sigma Rule: {title}\nStatus: {status} | Level: {level}\nDescription: {description}"
                
                # Extract detection keywords nếu có
                detection = parsed_yaml.get('detection', {})
                keywords = detection.get('keywords', []) if isinstance(detection, dict) else []
                if keywords:
                    keywords_preview = keywords[:3] if len(keywords) > 3 else keywords
                    summary_content += f"\nKeywords: {', '.join(str(k) for k in keywords_preview)}"
                    if len(keywords) > 3:
                        summary_content += f" (+{len(keywords)-3} more)"
                
                new_doc = Document(
                    page_content=summary_content,
                    metadata={
                        "source": doc.metadata.get('source'),
                        "full_rule": doc.page_content,
                        # Thông tin cơ bản
                        "title": parsed_yaml.get('title'),
                        "id": parsed_yaml.get('id'),
                        "status": parsed_yaml.get('status'),
                        "level": parsed_yaml.get('level'),
                        "description": parsed_yaml.get('description'),
                        # Thông tin tác giả và ngày tháng
                        "author": parsed_yaml.get('author'),
                        "date": str(parsed_yaml.get('date', '')),
                        "modified": str(parsed_yaml.get('modified', '')),
                        # Tags và categories
                        "tags": parsed_yaml.get('tags', []),
                        # Logsource
                        "logsource": parsed_yaml.get('logsource', {}),
                        # Detection rules
                        "detection": parsed_yaml.get('detection', {}),
                        "detection_keywords": keywords,
                        "detection_keywords_count": len(keywords),
                        # References và false positives
                        "references": parsed_yaml.get('references', []),
                        "falsepositives": parsed_yaml.get('falsepositives', []),
                    }
                )
                sigma_docs_processed.append(new_doc)
            else:
                print(f"Warning: Không parse được YAML từ {doc.metadata.get('source')}")
        except Exception as e:
            print(f"Lỗi khi parse YAML từ {doc.metadata.get('source')}: {e}")
    
    print(f"\nĐã xử lý {len(sigma_docs_processed)} document(s)")
    
    # In ra một số docs đã processed
    print("\n" + "="*50)
    print("Một số docs đã xử lý (hiển thị 5 docs đầu tiên):")
    print("="*50)
    for i, doc in enumerate(sigma_docs_processed[:5]):
        print(f"\n{'='*60}")
        print(f"--- Doc {i+1} ---")
        print(f"{'='*60}")
        print(f"\n📄 CONTENT:")
        print(f"   {doc.page_content}")
        
        print(f"\n📋 METADATA (chi tiết):")
        print(f"   {'─'*58}")
        
        # Hiển thị các trường quan trọng trước
        important_fields = ['title', 'id', 'status', 'level', 'description', 'author', 'date', 'modified']
        for key in important_fields:
            if key in doc.metadata and doc.metadata[key]:
                value = doc.metadata[key]
                if isinstance(value, list):
                    print(f"   {key:20s}: {', '.join(str(v) for v in value[:5])}")
                    if len(value) > 5:
                        print(f"   {'':20s}  ... và {len(value)-5} mục khác")
                else:
                    print(f"   {key:20s}: {value}")
        
        # Tags
        if 'tags' in doc.metadata and doc.metadata['tags']:
            tags = doc.metadata['tags']
            print(f"   {'tags':20s}: {len(tags)} tag(s)")
            for tag in tags[:10]:
                print(f"   {'':20s}  - {tag}")
            if len(tags) > 10:
                print(f"   {'':20s}  ... và {len(tags)-10} tag(s) khác")
        
        # Logsource
        if 'logsource' in doc.metadata and doc.metadata['logsource']:
            logsource = doc.metadata['logsource']
            print(f"   {'logsource':20s}:")
            print(f"   {json.dumps(logsource, indent=8, ensure_ascii=False)}")
        
        # Detection
        if 'detection' in doc.metadata and doc.metadata['detection']:
            detection = doc.metadata['detection']
            keywords_count = doc.metadata.get('detection_keywords_count', 0)
            print(f"   {'detection':20s}: {keywords_count} keyword(s)")
            if 'keywords' in detection and detection['keywords']:
                keywords = detection['keywords']
                print(f"   {'':20s}  Keywords (first 5):")
                for kw in keywords[:5]:
                    print(f"   {'':20s}    - {str(kw)[:80]}")
                if len(keywords) > 5:
                    print(f"   {'':20s}  ... và {len(keywords)-5} keyword(s) khác")
            if 'condition' in detection:
                print(f"   {'':20s}  Condition: {detection['condition']}")
        
        # References
        if 'references' in doc.metadata and doc.metadata['references']:
            refs = doc.metadata['references']
            print(f"   {'references':20s}: {len(refs)} reference(s)")
            for ref in refs[:3]:
                print(f"   {'':20s}  - {ref}")
            if len(refs) > 3:
                print(f"   {'':20s}  ... và {len(refs)-3} reference(s) khác")
        
        # False positives
        if 'falsepositives' in doc.metadata and doc.metadata['falsepositives']:
            fps = doc.metadata['falsepositives']
            print(f"   {'falsepositives':20s}: {', '.join(str(fp) for fp in fps)}")
        
        # Full rule (preview only)
        if 'full_rule' in doc.metadata:
            full_rule = doc.metadata['full_rule']
            print(f"   {'full_rule':20s}: [Full rule - {len(str(full_rule))} ký tự]")
            preview = str(full_rule)[:200] if len(str(full_rule)) > 200 else str(full_rule)
            print(f"   {'':20s}  Preview: {preview}...")
        
        # Các trường khác
        other_fields = {k: v for k, v in doc.metadata.items() 
                       if k not in important_fields + ['tags', 'logsource', 'detection', 'references', 'falsepositives', 'full_rule', 'detection_keywords', 'detection_keywords_count']}
        if other_fields:
            print(f"\n   {'Các trường khác:':20s}")
            for key, value in other_fields.items():
                if isinstance(value, (list, dict)):
                    print(f"   {key:20s}: {type(value).__name__} với {len(value) if hasattr(value, '__len__') else 'N/A'} mục")
                else:
                    print(f"   {key:20s}: {value}")
        
        print(f"\n📊 METADATA (JSON format):")
        # Tạo bản copy metadata không có full_rule để dễ đọc
        metadata_clean = {k: v for k, v in doc.metadata.items() if k != 'full_rule'}
        print(json.dumps(metadata_clean, indent=2, ensure_ascii=False))
        print()
    
    # In tổng hợp metadata của tất cả docs
    print("\n" + "="*60)
    print("📊 TỔNG HỢP METADATA TẤT CẢ DOCS")
    print("="*60)
    print(f"\nTổng số docs: {len(sigma_docs_processed)}")
    
    # Thống kê các trường metadata
    all_metadata_keys = set()
    for doc in sigma_docs_processed:
        all_metadata_keys.update(doc.metadata.keys())
    
    print(f"\nCác trường metadata có trong docs:")
    for key in sorted(all_metadata_keys):
        count = sum(1 for doc in sigma_docs_processed if key in doc.metadata)
        print(f"  - {key}: có trong {count}/{len(sigma_docs_processed)} docs")
    
    # In metadata của tất cả docs dạng bảng
    print(f"\n{'='*60}")
    print("DANH SÁCH METADATA TẤT CẢ DOCS:")
    print(f"{'='*60}")
    for i, doc in enumerate(sigma_docs_processed):
        print(f"\n[{i+1}] {doc.metadata.get('source', 'N/A')}")
        metadata_summary = {k: v for k, v in doc.metadata.items() if k != 'full_rule'}
        print(json.dumps(metadata_summary, indent=4, ensure_ascii=False))
else:
    print("\nKhông có documents nào để xử lý.")

# Embedding và ChromaDB
if sigma_docs_processed:
    print("\n" + "="*60)
    print("🔮 EMBEDDING VÀ LƯU VÀO CHROMADB")
    print("="*60)
    
    try:
        # Khởi tạo embedding model (dùng HuggingFace local)
        print("\n📥 Đang tải embedding model...")
        embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            model_kwargs={'device': 'cpu'},
            encode_kwargs={'normalize_embeddings': True}
        )
        print("✅ Embedding model đã sẵn sàng")
        
        # Tạo đường dẫn lưu ChromaDB
        persist_directory = os.path.join(os.path.dirname(__file__), "chroma_db")
        os.makedirs(persist_directory, exist_ok=True)
        
        # Chuẩn bị documents với metadata tương thích ChromaDB
        print(f"\n💾 Đang tạo/load ChromaDB tại: {persist_directory}")
        
        # Convert list/dict trong metadata thành string cho ChromaDB
        docs_for_chroma = []
        for doc in sigma_docs_processed:
            new_metadata = {}
            for key, value in doc.metadata.items():
                if isinstance(value, (list, dict)):
                    # Convert list/dict thành JSON string
                    new_metadata[key] = json.dumps(value, ensure_ascii=False)
                elif value is None:
                    continue  # Skip None values
                else:
                    new_metadata[key] = value
            
            # Tạo document mới với metadata đã xử lý
            new_doc = Document(
                page_content=doc.page_content,
                metadata=new_metadata
            )
            docs_for_chroma.append(new_doc)
        
        # Filter complex metadata một lần nữa để chắc chắn
        docs_for_chroma = filter_complex_metadata(docs_for_chroma)
        
        # Tạo ChromaDB vector store
        vectorstore = Chroma.from_documents(
            documents=docs_for_chroma,
            embedding=embeddings,
            persist_directory=persist_directory,
            collection_name="sigma_rules"
        )
        print(f"✅ Đã lưu {len(sigma_docs_processed)} documents vào ChromaDB")
        
        # Ví dụ queries
        print("\n" + "="*60)
        print("🔍 VÍ DỤ QUERY TỪ CHROMADB")
        print("="*60)
        
        test_queries = [
            "Java payload attack",
            "SQL injection detection",
            "web server vulnerability",
            "remote code execution",
            "Path Travelsal",
            "Pattern SQL injection",
            "1 Or 1 = 1"
        ]
        
        for query in test_queries:
            print(f"\n{'─'*60}")
            print(f"🔎 Query: '{query}'")
            print(f"{'─'*60}")
            
            # Search với similarity
            results = vectorstore.similarity_search_with_score(query, k=3)
            
            for i, (doc, score) in enumerate(results, 1):
                print(f"\n  [{i}] Score: {score:.4f}")
                print(f"      Title: {doc.metadata.get('title', 'N/A')}")
                print(f"      Level: {doc.metadata.get('level', 'N/A')}")
                print(f"      Description: {doc.metadata.get('description', 'N/A')[:100]}...")
                print(f"      Source: {doc.metadata.get('source', 'N/A')}")
                
                # Parse metadata và hiển thị cho LLM
                parsed_meta = parse_chroma_metadata(doc)
                if parsed_meta.get('tags'):
                    tags = parsed_meta['tags'] if isinstance(parsed_meta['tags'], list) else []
                    print(f"      Tags: {', '.join(str(t) for t in tags[:5])}")
        
        # Ví dụ format document cho LLM
        print(f"\n{'='*60}")
        print("📝 VÍ DỤ FORMAT DOCUMENT CHO LLM")
        print("="*60)
        
        sample_query = "Java payload attack"
        sample_results = vectorstore.similarity_search(sample_query, k=2)
        
        for i, doc in enumerate(sample_results, 1):
            print(f"\n{'─'*60}")
            print(f"Document {i} - Formatted for LLM:")
            print(f"{'─'*60}")
            formatted = format_doc_for_llm(doc, include_full_rule=False)
            print(formatted)
        
        # Metadata filtering example
        print(f"\n{'='*60}")
        print("🔍 QUERY VỚI METADATA FILTERING")
        print("="*60)
        
        # Tìm các rules có level HIGH
        print(f"\n📊 Tìm rules có level='high':")
        high_level_docs = vectorstore.similarity_search(
            query="security detection",
            k=5,
            filter={"level": "high"}
        )
        print(f"  Tìm thấy {len(high_level_docs)} rules với level=high")
        for doc in high_level_docs[:3]:
            print(f"    - {doc.metadata.get('title', 'N/A')} (Level: {doc.metadata.get('level', 'N/A')})")
        
        # Tìm theo tags (parse JSON string trước)
        print(f"\n📊 Tìm rules có tag chứa 'attack':")
        attack_docs = vectorstore.similarity_search(
            query="attack detection",
            k=5
        )
        attack_docs_filtered = []
        for doc in attack_docs:
            parsed_meta = parse_chroma_metadata(doc)
            tags = parsed_meta.get('tags', [])
            if isinstance(tags, list) and any('attack' in str(tag).lower() for tag in tags):
                attack_docs_filtered.append((doc, parsed_meta))
        
        print(f"  Tìm thấy {len(attack_docs_filtered)} rules liên quan đến attack")
        for doc, parsed_meta in attack_docs_filtered[:3]:
            tags = parsed_meta.get('tags', []) if isinstance(parsed_meta.get('tags'), list) else []
            tags_str = ', '.join([str(t) for t in tags[:3]])
            print(f"    - {parsed_meta.get('title', 'N/A')}")
            print(f"      Tags: {tags_str}")
        
        # Ví dụ sử dụng formatted document cho LLM
        print(f"\n{'='*60}")
        print("💡 CÁCH SỬ DỤNG CHO LLM")
        print("="*60)
        print("\nKhi query và nhận được documents, bạn có thể:")
        print("1. Parse metadata: metadata = parse_chroma_metadata(doc)")
        print("2. Format cho LLM: formatted_text = format_doc_for_llm(doc)")
        print("3. Truyền formatted_text vào LLM prompt")
        print("\nVí dụ:")
        if attack_docs_filtered:
            example_doc, _ = attack_docs_filtered[0]
            example_formatted = format_doc_for_llm(example_doc)
            print(f"\n{example_formatted[:500]}...")
        
        print(f"\n✅ ChromaDB đã sẵn sàng để query!")
        print(f"   Đường dẫn: {persist_directory}")
        
    except Exception as e:
        print(f"\n❌ Lỗi khi embedding hoặc lưu vào ChromaDB: {e}")
        import traceback
        traceback.print_exc()