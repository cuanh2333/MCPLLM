# 🔐 MCPLLM - Security Analysis System

Hệ thống phân tích log bảo mật tự động sử dụng AI/LLM với khả năng phát hiện tấn công, threat intelligence, và tạo detection rules.

## 🚀 Quick Start

### Chạy Local (Development)
```bash
# 1. Test setup
python scripts/test_local_setup.py

# 2. Chạy full stack
python run_fullstack.py

# 3. Truy cập
# Frontend: http://localhost:3000
# Backend: http://localhost:8888
# MCP Server: http://localhost:8001
```

### Deploy Production

**📖 Xem hướng dẫn deployment chi tiết tại: [DEPLOYMENT.md](DEPLOYMENT.md)**

```bash
# Quick production setup:
cd scripts
./setup_production.sh YOUR_SERVER_IP

# Hoặc manual setup:
./setup_services.sh      # Systemd services
./setup_nginx.sh         # Nginx reverse proxy
./start_all.sh          # Start all services
./test_mcp.sh           # Test deployment
```

## 📋 Mục Lục

1. [Tính Năng](#tính-năng)
2. [Yêu Cầu Hệ Thống](#yêu-cầu-hệ-thống)
3. [Kiến Trúc](#kiến-trúc)
4. [API Documentation](#api-documentation)

---

## 🎯 Tính Năng

### Core Features
- ✅ **Phân tích log tự động** - Phát hiện tấn công từ web logs (IIS, Apache, Nginx)
- ✅ **Threat Intelligence** - Kiểm tra IP độc hại qua AbuseIPDB & VirusTotal
- ✅ **Detection Rules** - Tạo Sigma/SPL rules tự động
- ✅ **Multi-source** - Hỗ trợ file upload, Splunk, và real-time analysis
- ✅ **RAG Knowledge Base** - Query Sigma rules, MITRE ATT&CK, security docs
- ✅ **Cron Scheduling** - Tự động phân tích định kỳ
- ✅ **Telegram Alerts** - Thông báo tấn công qua Telegram
- ✅ **PDF Reports** - Xuất báo cáo PDF với font tiếng Việt

### AI Agents
- **SupervisorAgent** - Phân loại job và routing thông minh
- **AnalyzeAgent** - Phát hiện tấn công từ logs
- **TIAgent** - Threat intelligence với caching
- **RecommendAgent** - Khuyến nghị bảo mật
- **GenRuleAgent** - Tạo detection rules
- **ReportAgent** - Tạo báo cáo chi tiết
- **QueryRAGAgent** - Truy vấn knowledge base

---

## 💻 Yêu Cầu Hệ Thống

### Phần Mềm
- Python 3.10+
- Node.js 18+
- Git

### API Keys (Bắt buộc)
- **Groq API** - LLM inference (miễn phí): https://console.groq.com
- **Google AI** - Gemini models (miễn phí): https://aistudio.google.com
- **AbuseIPDB** - Threat intelligence (miễn phí): https://www.abuseipdb.com/account/api

### API Keys (Tùy chọn)
- **VirusTotal** - Threat intelligence: https://www.virustotal.com/gui/my-apikey
- **Telegram Bot** - Notifications: https://t.me/BotFather
- **Splunk** - Log source: Splunk Enterprise/Cloud

---

## 📦 Cài Đặt

### 1. Clone Repository
```bash
git clone <repository-url>
cd MCPLLM
```

### 2. Cài Đặt Backend
```bash
# Tạo virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (Linux/Mac)
source .venv/bin/activate

# Cài đặt dependencies
pip install -r requirements.txt
```

### 3. Cài Đặt Frontend
```bash
cd frontend
npm install
cd ..
```

### 4. Tải Font (Cho PDF tiếng Việt)
```bash
# Tạo thư mục fonts
mkdir fonts

# Download DejaVu Sans fonts
# Windows: Copy từ C:\Windows\Fonts\
# Linux: sudo apt-get install fonts-dejavu
# Mac: brew install --cask font-dejavu

# Copy các file sau vào thư mục fonts/:
# - DejaVuSans.ttf
# - DejaVuSans-Bold.ttf
# - DejaVuSans-Oblique.ttf
# - DejaVuSans-BoldOblique.ttf
```

---

## ⚙️ Cấu Hình

### 1. Tạo File .env
```bash
cp .env.example .env
```

### 2. Cấu Hình API Keys
Mở file `.env` và điền các thông tin:

```env
# LLM Configuration (BẮT BUỘC)
GROQ_API_KEY=your_groq_api_key_here
GOOGLE_API_KEY=your_google_api_key_here

# Threat Intelligence (BẮT BUỘC cho TI features)
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here

# Telegram (TÙY CHỌN)
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Splunk (TÙY CHỌN)
SPLUNK_HOST=192.168.1.100
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=password
SPLUNK_INDEX=web_logs
SPLUNK_SOURCETYPE=access_combined
```

### 3. Cấu Hình Asset Mapping (Tùy chọn)
Chỉnh sửa `backend/asset_ip_mapping.csv` để map IP với tên asset:

```csv
ip,asset_name,description,is_protected,is_authorized_attacker
192.168.1.100,WEB-SERVER-01,Production Web Server,true,false
192.168.1.200,PENTEST-01,Penetration Testing Machine,false,true
```

---

## 🚀 Chạy Ứng Dụng

### Chạy Full Stack (Khuyến nghị)
```bash
python run_fullstack.py
```

Services sẽ chạy trên:
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8888
- **Unified MCP Server**: http://localhost:8001
- **API Docs**: http://localhost:8888/docs

### Chạy Riêng Lẻ

#### MCP Server
```bash
python run_mcp_server.py
```

#### Backend API
```bash
python run_backend.py
```

#### Frontend
```bash
cd frontend
npm run dev
```

---

## 📖 Sử Dụng

### 1. Giao Diện Web

#### Phân Tích File Log
1. Mở http://localhost:3000
2. Click icon 📎 để upload file log
3. Gõ câu hỏi hoặc để trống
4. Click Send
5. Xem kết quả phân tích

#### Query Thông Minh
Gõ các câu hỏi tự nhiên:
- "Phân tích logs trong 24h qua"
- "Check IP 103.232.122.33"
- "Tạo rule phát hiện SQL Injection"
- "Tôi bị tấn công gì trong 48h qua?"

#### Xem Statistics
1. Click tab "Thống Kê"
2. Xem tổng quan tấn công
3. Filter theo source (file/cron/all)
4. Click vào report để xem chi tiết

#### Cron Monitoring
1. Click tab "Giám Sát"
2. Tạo cron job mới
3. Xem lịch sử chạy
4. Monitor real-time status

### 2. API Usage

#### Phân Tích File
```bash
curl -X POST http://127.0.0.1:8888/analyze-file \
  -F "file=@access.log" \
  -F "query=Phân tích file này"
```

#### Smart Query
```bash
curl -X POST http://127.0.0.1:8888/smart-analyze \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Phân tích logs trong 24h qua",
    "send_telegram": false
  }'
```

#### Check IP Reputation
```bash
curl -X POST http://127.0.0.1:8888/smart-analyze \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Check IP 103.232.122.33"
  }'
```

### 3. Cron Job

#### Tạo Cron (Windows)
```bash
python setup_cron_windows.py
```

#### Chạy Thủ Công
```bash
python cron_log_analyzer.py
```

---

## 🏗️ Kiến Trúc

### Project Structure
```
mcpllm/
├── 📁 backend/              # FastAPI Backend
│   ├── agents/              # AI Agents
│   ├── services/            # Business Services  
│   ├── nodes/               # LangGraph Nodes
│   ├── utils/               # Utilities
│   ├── main.py              # FastAPI App
│   └── config.py            # Configuration
├── 📁 frontend/             # React Frontend
│   ├── src/                 # Source code
│   └── package.json         # Dependencies
├── 📁 mcp_server/           # MCP Server
│   └── unified_server.py    # Log + RAG Server
├── 📁 scripts/              # Deployment Scripts
│   ├── test_local_setup.py  # Setup validation
│   ├── setup_production.sh  # Production setup
│   ├── setup_services.sh    # Service setup
│   ├── start_all.sh         # Start all services
│   └── test_mcp.sh          # Test deployment
├── run_fullstack.py         # Local development
├── run_backend.py           # Backend only
├── run_mcp_server.py        # MCP server only
├── 📁 output/               # Analysis results
├── 📁 KB/                   # Knowledge base
├── 📁 fonts/                # PDF fonts
├── .env.example             # Environment template
├── requirements.txt         # Python deps
└── README.md                # This file
```

### Workflow
```
User Query
    ↓
SupervisorAgent (classify job type)
    ↓
┌─────────────┬──────────────┬─────────────┐
│ log_analysis│ ip_reputation│ generic_rule│
└─────────────┴──────────────┴─────────────┘
    ↓              ↓              ↓
Fetch Logs     TI Agent      QueryRAG
    ↓              ↓              ↓
Analyze        Asset Info    GenRule
    ↓              ↓              ↓
TI + Recommend     ↓              ↓
    ↓              ↓              ↓
Report         Response      Response
    ↓
Telegram (optional)
```

---

## 📚 API Documentation

### Endpoints

#### POST /analyze-file
Upload và phân tích file log.

**Request:**
- `file`: File log (multipart/form-data)
- `query`: Câu hỏi (optional)
- `send_telegram`: Boolean (optional)

**Response:**
```json
{
  "job_type": "log_analysis",
  "findings_summary": {...},
  "ti_summary": {...},
  "recommend_summary": {...},
  "attack_events_ref": {...}
}
```

#### POST /smart-analyze
Phân tích thông minh với query tự nhiên.

**Request:**
```json
{
  "query": "Phân tích logs trong 24h qua",
  "send_telegram": false
}
```

#### GET /statistics
Lấy thống kê từ report.

**Query Params:**
- `report`: Tên file CSV
- `source`: file/cron/all

#### GET /cron/status
Xem trạng thái cron jobs.

#### POST /cron/run-now
Chạy cron job ngay lập tức.

---

## 🔧 Troubleshooting

### Lỗi Thường Gặp

#### 1. Import Error
```bash
# Fix imports
python fix_remaining_imports.py
```

#### 2. API Key Invalid
- Kiểm tra `.env` file
- Verify API keys tại console của provider
- Restart backend

#### 3. Font Missing (PDF)
```bash
# Download DejaVu fonts
# Copy vào thư mục fonts/
```

#### 4. Splunk Connection Failed
- Kiểm tra SPLUNK_HOST, PORT
- Verify credentials
- Test connection: `curl -k https://SPLUNK_HOST:8089`

#### 5. Port Already in Use
```bash
# Kill process on port 8000
python kill_port_8000.py
```

---

## 📝 Notes

### Performance
- TI caching: 24h TTL
- RAG index: 3562 documents
- Recommended: 8GB RAM, 4 CPU cores

### Security
- API keys trong `.env` (không commit)
- HTTPS cho production
- Rate limiting enabled
- Input validation

### Limitations
- Max file size: 50MB
- Max events per analysis: 10,000
- Groq rate limit: 30 req/min
- AbuseIPDB: 1000 req/day (free tier)

---

## 🤝 Support

Nếu gặp vấn đề:
1. Kiểm tra logs trong terminal
2. Xem API docs: http://127.0.0.1:8888/docs
3. Review `.env` configuration
4. Check system requirements

## 🚀 Production Deployment

### Yêu cầu Server
- **OS**: Ubuntu 20.04+ / CentOS 7+
- **RAM**: 8GB+ (16GB recommended)
- **CPU**: 4+ cores
- **Storage**: 50GB+ free space
- **Network**: Internet connection

### Cài đặt Production

**📖 Xem hướng dẫn chi tiết tại: [DEPLOYMENT.md](DEPLOYMENT.md)**

#### Option 1: Automated Setup
```bash
# Clone và setup tự động
git clone <repository-url>
cd MCPLLM
bash scripts/setup_production.sh
```

#### Option 2: Manual Setup
```bash
# 1. Setup environment
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit .env với API keys

# 3. Build frontend
cd frontend && npm install && npm run build && cd ..

# 4. Setup services
sudo bash scripts/setup_services.sh
sudo bash scripts/setup_nginx.sh

# 5. Start services
sudo systemctl start mcpllm-backend mcpllm-mcp
sudo systemctl enable mcpllm-backend mcpllm-mcp
```

#### Monitoring
```bash
# Check services
sudo systemctl status mcpllm-backend
sudo systemctl status mcpllm-mcp

# View logs
sudo journalctl -u mcpllm-backend -f
sudo journalctl -u mcpllm-mcp -f

# Health checks
curl http://localhost:8888/health
curl http://localhost:8001/health
```

### URLs sau khi deploy
- **Frontend**: http://your-server-ip
- **Backend API**: http://your-server-ip:8888
- **MCP Server**: http://your-server-ip:8001
- **API Docs**: http://your-server-ip:8888/docs

---

## 📄 License

Proprietary - All rights reserved

---

**Version**: 4.0  
**Last Updated**: 2025-11-21
