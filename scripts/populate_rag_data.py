"""
Populate RAG Data Script

Simple script to populate ChromaDB with sample security knowledge.
Avoids complex dependencies from notebook.
"""

import os
import sys
import json
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def create_sample_security_docs():
    """Create sample security documents for RAG."""
    
    sample_docs = [
        {
            "content": "XSS (Cross-Site Scripting) có 3 loại chính:\n1. Reflected XSS: Mã độc được phản chiếu từ server\n2. Stored XSS: Mã độc được lưu trữ trên server\n3. DOM-based XSS: Mã độc thực thi trong DOM của browser",
            "metadata": {
                "source_type": "security_knowledge",
                "title": "XSS Attack Types",
                "category": "web_security"
            }
        },
        {
            "content": "SQL Injection có các loại:\n1. In-band SQLi: Dữ liệu được trích xuất qua cùng kênh\n2. Inferential SQLi: Blind SQL injection\n3. Out-of-band SQLi: Dữ liệu được trích xuất qua kênh khác",
            "metadata": {
                "source_type": "security_knowledge", 
                "title": "SQL Injection Types",
                "category": "web_security"
            }
        },
        {
            "content": "CSRF (Cross-Site Request Forgery) là tấn công buộc người dùng thực hiện hành động không mong muốn trên ứng dụng web mà họ đã xác thực.",
            "metadata": {
                "source_type": "security_knowledge",
                "title": "CSRF Attack",
                "category": "web_security"
            }
        },
        {
            "content": "OWASP Top 10 2021:\n1. Broken Access Control\n2. Cryptographic Failures\n3. Injection\n4. Insecure Design\n5. Security Misconfiguration\n6. Vulnerable Components\n7. Authentication Failures\n8. Software Integrity Failures\n9. Logging Failures\n10. SSRF",
            "metadata": {
                "source_type": "security_knowledge",
                "title": "OWASP Top 10 2021",
                "category": "security_standards"
            }
        },
        {
            "content": "Sigma Rule for SQL Injection detection:\ntitle: SQL Injection Strings\ndetection:\n  keywords:\n    - 'union select'\n    - 'or 1=1'\n    - 'drop table'\ncondition: keywords",
            "metadata": {
                "source_type": "sigma_rule",
                "title": "SQL Injection Detection",
                "category": "detection_rules"
            }
        }
    ]
    
    return sample_docs

def populate_chromadb():
    """Populate ChromaDB with sample data."""
    try:
        import chromadb
        from langchain_core.documents import Document
        
        print("🔄 Initializing ChromaDB...")
        
        # Initialize ChromaDB
        chroma_path = "./chroma_db"
        os.makedirs(chroma_path, exist_ok=True)
        
        client = chromadb.PersistentClient(path=chroma_path)
        
        # Delete existing collection if exists
        try:
            client.delete_collection("security_knowledge")
            print("🗑️  Deleted existing collection")
        except:
            pass
        
        # Create new collection
        collection = client.create_collection(
            name="security_knowledge",
            metadata={"hnsw:space": "cosine"}
        )
        
        # Create sample documents
        sample_docs = create_sample_security_docs()
        
        print(f"📝 Adding {len(sample_docs)} documents...")
        
        # Add documents to collection
        documents = []
        metadatas = []
        ids = []
        
        for i, doc_data in enumerate(sample_docs):
            documents.append(doc_data["content"])
            metadatas.append(doc_data["metadata"])
            ids.append(f"doc_{i}")
        
        collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        
        print(f"✅ Successfully added {len(sample_docs)} documents to ChromaDB")
        print(f"📊 Collection count: {collection.count()}")
        
        # Test query
        print("\n🔍 Testing query...")
        results = collection.query(
            query_texts=["XSS types"],
            n_results=2
        )
        
        if results['documents'] and results['documents'][0]:
            print(f"✅ Query test successful: {len(results['documents'][0])} results")
            print(f"   First result: {results['documents'][0][0][:100]}...")
        else:
            print("⚠️  Query test returned no results")
        
        return True
        
    except Exception as e:
        print(f"❌ Error populating ChromaDB: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 60)
    print("📚 RAG Data Populator")
    print("=" * 60)
    
    success = populate_chromadb()
    
    if success:
        print("\n" + "=" * 60)
        print("✅ RAG data populated successfully!")
        print("🚀 You can now test knowledge queries:")
        print("   - 'XSS có mấy loại?'")
        print("   - 'SQL injection types'")
        print("   - 'OWASP Top 10'")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("❌ Failed to populate RAG data!")
        print("=" * 60)

if __name__ == "__main__":
    main()