# Chi Tiết Các Agent trong Hệ Thống

## Tổng Quan

Hệ thống của bạn có **10 Agent** chuyên biệt, mỗi agent đảm nhận một nhiệm vụ cụ thể trong quy trình phân tích bảo mật.

---

## 1. SupervisorAgent 🎯
**File:** `backend/agents/supervisor_agent.py`

### Chức năng chính:
- **Phân loại công việc** (Job Classification) bằng LLM
- **Quyết định workflow** - Agent nào cần chạy
- **Parse time range** từ câu hỏi người dùng

### Job Types:
1. **log_analysis** - Phân tích log tấn công
2. **asset_query** - Truy vấn thông tin tài sản nội bộ
3. **ip_reputation** - Kiểm tra IP độc hại (external)
4. **knowledge_query** - Trả lời câu hỏi bảo mật
5. **generic_rule** - Tạo detection rule

### Workflow Flags:
```python
{
  "need_analyze": bool,      # Cần phân tích log?
  "need_ti": bool,           # Cần threat intelligence?
  "need_genrule": bool,      # Cần tạo rule?
  "need_recommend": bool,    # Cần khuyến nghị?
  "need_report": bool,       # Cần báo cáo?
  "need_queryrag": bool,     # Cần query KB?
  "need_asset": bool         # Cần query asset?
}
```

### Ví dụ:
- **Input:** "Phân tích log tấn công SQL injection"
- **Output:** `job_type="log_analysis"`, `need_analyze=True`, `need_ti=True`

---

## 2. AnalyzeAgent 🔍
**File:** `backend/agents/analyze_agent.py`

### Chức năng chính:
- **Phân loại tấn công** bằng LLM (Groq/Google)
- **Chunking** - Chia log thành chunks 50 events
- **Parallel processing** - Xử lý nhiều chunks đồng thời

### Attack Types Detected:
- `sqli` - SQL Injection
- `xss` - Cross-Site Scripting
- `lfi` - Local File Inclusion
- `rfi` - Remote File Inclusion
- `rce` - Remote Code Execution
- `xxe` - XML External Entity
- `path_traversal` - Directory Traversal
- `command_injection` - OS Command Injection
- `benign` - Legitimate traffic

### Output Format (EventLabel):
```python
{
  "is_attack": bool,
  "attack_type": str,
  "short_note": str,
  "mitre_technique": str,  # T1190, T1059, etc.
  "confidence": float      # 0.0 - 1.0
}
```

### Đặc điểm:
- **CHUNK_SIZE = 50** events per LLM call
- Xử lý **file upload** detection (shell.php, backdoor.jsp)
- Map sang **MITRE ATT&CK** techniques

---

## 3. TIAgent 🛡️
**File:** `backend/agents/ti_agent.py`

### Chức năng chính:
- **Kiểm tra IP reputation** qua AbuseIPDB & VirusTotal
- **Filter business IPs** - Loại bỏ IP nội bộ
- **Risk scoring** - Phân loại mức độ nguy hiểm

### Risk Levels:
- **critical**: Abuse score ≥ 80 HOẶC VT detections > 5
- **high**: Abuse score 50-79 HOẶC VT detections 3-5
- **medium**: Abuse score 20-49 HOẶC VT detections 1-2
- **low**: Abuse score < 20 và không có VT detections

### Output (TISummary):
```python
{
  "iocs": [
    {
      "ip": "103.232.122.33",
      "risk": "critical",
      "abuse_score": 100,
      "vt_detections": 0,
      "notes": "IP độc hại cao..."
    }
  ],
  "ti_overall": {
    "max_risk": "critical",
    "high_risk_iocs": ["103.232.122.33"],
    "notes": "Phát hiện 1 IP nguy hiểm..."
  }
}
```

### Tính năng:
- **Caching** - Cache TI data 24h để tránh query lại
- **Business IP filtering** - Không check IP nội bộ
- **Batch processing** - Limit 10 IPs per analysis

---

## 4. RecommendAgent 💡
**File:** `backend/agents/recommend_agent.py`

### Chức năng chính:
- **Tạo khuyến nghị bảo mật** dựa trên findings + TI
- **3 nhóm hành động**: Immediate / Short-term / Long-term
- **Tiếng Việt** - Tất cả khuyến nghị bằng tiếng Việt

### Output (RecommendSummary):
```python
{
  "severity_overall": "high",
  "immediate_actions": [
    "Chặn các IP: 1.2.3.4, 5.6.7.8 tại firewall",
    "Kiểm tra và ngắt các session đáng ngờ"
  ],
  "short_term_actions": [
    "Cập nhật WAF rules để chặn SQL injection",
    "Vá lỗ hổng ứng dụng web"
  ],
  "long_term_actions": [
    "Triển khai input validation framework",
    "Thực hiện security code review"
  ],
  "notes": "Sự cố mức độ cao cần xử lý ngay..."
}
```

### Đặc điểm:
- **Context-aware** - Khuyến nghị dựa trên loại tấn công cụ thể
- **Actionable** - Bao gồm IP, URI, pattern cụ thể
- **Prioritized** - Ưu tiên theo severity và số lượng

---

## 5. ReportAgent 📄
**File:** `backend/agents/report_agent.py`

### Chức năng chính:
- **Tạo báo cáo Markdown** chi tiết
- **Export PDF** với font tiếng Việt
- **Comprehensive** - Tổng hợp tất cả findings

### Report Structure:
```markdown
# Báo Cáo Phân Tích Bảo Mật

## Tóm Tắt Điều Hành
## Chi Tiết Sự Cố
## Phân Tích Tấn Công
### Các Loại Tấn Công Phát Hiện
### MITRE ATT&CK Mapping
### Phân Tích Nguồn
## Threat Intelligence
### Phân Tích IOC
### Đánh Giá Rủi Ro
## Khuyến Nghị
### Hành Động Ngay Lập Tức
### Hành Động Ngắn Hạn
### Hành Động Dài Hạn
## Phụ Lục
```

### Tính năng:
- **PDF generation** - Sử dụng PDFGenerator với font tiếng Việt
- **Timestamp tracking** - Ghi rõ thời gian phân tích
- **Fallback report** - Tạo báo cáo cơ bản nếu LLM fail

---

## 6. GenRuleAgent 🔧
**File:** `backend/agents/genrule_agent.py`

### Chức năng chính:
- **Tạo detection rules** từ attack analysis
- **Multi-format** - Sigma YAML + Splunk SPL
- **RAG-enhanced** - Query Sigma rules từ KB

### Output (GenRuleSummary):
```python
{
  "main_attack_type": "sql_injection",
  "sigma_rule": "title: SQL Injection Detection\n...",
  "splunk_spl": "index=web | eval is_sqli=...",
  "notes": "**False Positives:**\n- Security scanners..."
}
```

### Workflow:
1. Query RAG cho Sigma rules mẫu
2. Extract patterns từ real log samples
3. Generate Sigma YAML (complete với metadata)
4. Generate Splunk SPL (với risk scoring)
5. Generate deployment notes (tiếng Việt)

### Đặc điểm:
- **Production-ready** - Rules có thể deploy ngay
- **5-10 detection patterns** per attack type
- **Risk scoring** - Tính điểm rủi ro trong SPL
- **False positive guidance** - Hướng dẫn xử lý FP

---

## 7. QueryRAGAgent 🧠
**File:** `backend/agents/queryrag_agent.py`

### Chức năng chính:
- **Trả lời câu hỏi bảo mật** bằng RAG
- **Query ChromaDB** qua HTTP (rag_server_http.py)
- **Multilingual** - Hỗ trợ tiếng Việt + English

### Query Categories:
- **asset** - Thông tin tài sản (IP, server)
- **sigma_rule** - Detection rules
- **owasp** - OWASP Top 10
- **mitre** - MITRE ATT&CK
- **None** - Full hybrid search

### Intent Detection:
```python
{
  "definition": "Giải thích khái niệm",
  "prevention": "Cách phòng chống",
  "detection": "Cách phát hiện",
  "example": "Ví dụ cụ thể",
  "comparison": "So sánh",
  "general": "Tổng quan"
}
```

### Workflow:
1. **Detect category** - Auto-detect asset/sigma/general
2. **Enhance query** - Thêm English keywords
3. **Query RAG** - HTTP call to rag_server
4. **Analyze intent** - Phân tích ý định câu hỏi
5. **Synthesize answer** - LLM tổng hợp câu trả lời

### Đặc điểm:
- **Hybrid search** - Vector + BM25
- **IP detection** - Auto-detect IP trong query → asset category
- **Context-aware** - Trả lời đúng trọng tâm câu hỏi

---

## 8. AssetAgent 🏢
**File:** `backend/agents/asset_agent.py`

### Chức năng chính:
- **Query asset database** (asset_ip_mapping.csv)
- **Enrich asset info** - IP, hostname, owner, location
- **Filter by type** - PENTEST / SERVER / COLLECTOR

### Asset Types:
- **PENTEST** - IP pentest (authorized attackers)
- **SERVER** - Protected servers
- **COLLECTOR** - Log collectors

### Output Format:
```markdown
🖥️ **DVWA-Server** (192.168.1.100)
   - Loại: SERVER
   - Nhãn: Web Application Server
   - Mô tả: Damn Vulnerable Web Application
   - Chủ sở hữu: Security Team
   - Vị trí: DMZ
```

### Đặc điểm:
- **Direct CSV read** - Không cần LLM
- **Fast lookup** - Instant response
- **Structured output** - Format rõ ràng

---

## 9. QueryAgent (Legacy)
**File:** `backend/agents/query_agent.py`

### Chức năng:
- Legacy agent, được thay thế bởi **QueryRAGAgent**
- Giữ lại để backward compatibility

---

## 10. Supervisor (Static Methods)
**File:** `backend/supervisor.py`

### Chức năng:
- **Pre-Supervisor** - Classify job type
- **Post-Supervisor** - Update need_* flags based on severity
- **Static methods** - Không cần instance

---

## Workflow Tổng Thể

```
User Query
    ↓
SupervisorAgent (classify job_type)
    ↓
┌─────────────────────────────────────┐
│ IF job_type = "log_analysis"       │
│   1. Fetch logs (MCP)               │
│   2. Normalize events               │
│   3. AnalyzeAgent (chunk + classify)│
│   4. TIAgent (check IPs)            │
│   5. RecommendAgent (generate recs) │
│   6. GenRuleAgent (create rules)    │
│   7. ReportAgent (markdown + PDF)   │
│   8. Telegram notification          │
└─────────────────────────────────────┘
┌─────────────────────────────────────┐
│ IF job_type = "knowledge_query"    │
│   1. QueryRAGAgent (query KB)       │
│   2. Return answer                  │
└─────────────────────────────────────┘
┌─────────────────────────────────────┐
│ IF job_type = "asset_query"        │
│   1. AssetAgent (query CSV)         │
│   2. Return asset info              │
└─────────────────────────────────────┘
┌─────────────────────────────────────┐
│ IF job_type = "ip_reputation"      │
│   1. TIAgent (check external IPs)   │
│   2. Return reputation report       │
└─────────────────────────────────────┘
```

---

## Agent Dependencies

```
SupervisorAgent
    ↓
    ├─→ AnalyzeAgent
    │       ↓
    │   TIAgent
    │       ↓
    │   RecommendAgent
    │       ↓
    │   GenRuleAgent (uses QueryRAGAgent)
    │       ↓
    │   ReportAgent
    │
    ├─→ QueryRAGAgent (standalone)
    │
    ├─→ AssetAgent (standalone)
    │
    └─→ TIAgent (standalone for IP reputation)
```

---

## LLM Configuration

Mỗi agent có thể config riêng model và temperature:

```python
# settings.py
analyze_agent_model = "llama-3.3-70b-versatile"
analyze_agent_temperature = 0.0

ti_agent_model = "llama-3.1-8b-instant"
ti_agent_temperature = 0.1

recommend_agent_model = "llama-3.3-70b-versatile"
recommend_agent_temperature = 0.2

report_agent_model = "llama-3.3-70b-versatile"
report_agent_temperature = 0.3

genrule_agent_model = "llama-3.3-70b-versatile"
genrule_agent_temperature = 0.1

queryrag_agent_model = "llama-3.3-70b-versatile"
queryrag_agent_temperature = 0.3

supervisor_agent_model = "llama-3.1-8b-instant"
supervisor_agent_temperature = 0.1
```

---

## Performance Metrics

| Agent | Avg Time | Token Usage | Chunking |
|-------|----------|-------------|----------|
| SupervisorAgent | 1-2s | ~500 | No |
| AnalyzeAgent | 5-30s | ~2000/chunk | Yes (50) |
| TIAgent | 10-20s | ~1000 | No |
| RecommendAgent | 3-5s | ~1500 | No |
| ReportAgent | 5-10s | ~2000 | No |
| GenRuleAgent | 10-15s | ~3000 | No |
| QueryRAGAgent | 3-8s | ~1500 | No |
| AssetAgent | <1s | 0 (no LLM) | No |

---

## Tóm Tắt

Hệ thống của bạn có **10 Agent chuyên biệt**, mỗi agent đảm nhận một nhiệm vụ cụ thể:

1. **SupervisorAgent** - Điều phối workflow
2. **AnalyzeAgent** - Phân loại tấn công (chunking)
3. **TIAgent** - Threat intelligence
4. **RecommendAgent** - Khuyến nghị bảo mật
5. **ReportAgent** - Báo cáo Markdown + PDF
6. **GenRuleAgent** - Tạo detection rules
7. **QueryRAGAgent** - Trả lời câu hỏi bảo mật
8. **AssetAgent** - Quản lý thông tin tài sản
9. **QueryAgent** - Legacy (deprecated)
10. **Supervisor** - Static helper methods

Kiến trúc này cho phép **modular**, **scalable**, và **maintainable** - mỗi agent có thể được update độc lập mà không ảnh hưởng đến các agent khác.
