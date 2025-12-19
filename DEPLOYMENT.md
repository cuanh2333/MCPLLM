# 🚀 MCPLLM Deployment Guide

Hướng dẫn chi tiết để deploy MCPLLM system lên server production.

## 📋 Yêu cầu hệ thống

### Minimum Requirements:
- **OS**: Ubuntu 20.04+ / CentOS 7+ / Windows Server 2019+
- **RAM**: 8GB (16GB recommended)
- **CPU**: 4 cores (8 cores recommended)
- **Storage**: 50GB free space
- **Network**: Internet connection để download models

### Software Requirements:
- **Python**: 3.9+
- **Node.js**: 18+
- **Nginx**: 1.18+ (optional, for production)
- **Git**: Latest version

## 🔧 Cài đặt từng bước

### Bước 1: Clone Repository

```bash
# Clone project
git clone https://github.com/your-username/MCPLLM.git
cd MCPLLM

# Kiểm tra branch
git branch -a
git checkout main  # hoặc branch bạn muốn deploy
```

### Bước 2: Setup Python Environment

```bash
# Tạo virtual environment
python3 -m venv .venv

# Activate environment
# Linux/Mac:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt
```

### Bước 3: Cấu hình Environment

```bash
# Copy file cấu hình mẫu
cp .env.example .env

# Chỉnh sửa cấu hình
nano .env  # hoặc vim .env
```

**Cấu hình quan trọng trong `.env`:**

```bash
# LLM Configuration - REQUIRED
GROQ_API_KEY=your_groq_api_key_here
LLM_MODEL=llama-3.3-70b-versatile
LLM_TEMPERATURE=0

# Splunk Configuration - REQUIRED nếu dùng Splunk
SPLUNK_HOST=your_splunk_server_ip
SPLUNK_PORT=8089
SPLUNK_USERNAME=your_username
SPLUNK_PASSWORD=your_password
SPLUNK_INDEX=your_index
SPLUNK_SOURCETYPE=your_sourcetype

# Threat Intelligence APIs - OPTIONAL
ABUSEIPDB_API_KEY=your_abuseipdb_key
VIRUSTOTAL_API_KEY=your_virustotal_key

# Telegram Notifications - OPTIONAL
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Google API - OPTIONAL
GOOGLE_API_KEY=your_google_api_key
```

### Bước 4: Setup Frontend

```bash
# Chuyển vào thư mục frontend
cd frontend

# Install Node.js dependencies
npm install

# Build production version
npm run build

# Quay lại thư mục gốc
cd ..
```

### Bước 5: Khởi tạo RAG Database

```bash
# Download và setup RAG model (chỉ cần chạy 1 lần)
python scripts/download_rag_model.py

# Populate RAG database với security knowledge
python scripts/populate_rag_data.py
```

### Bước 6: Test Local Setup

```bash
# Test cấu hình cơ bản
python scripts/test_local_setup.py

# Test MCP server
bash scripts/test_mcp.sh
```

## 🌐 Deployment Options

### Option 1: Quick Start (Development)

Chạy tất cả services cùng lúc:

```bash
python run_fullstack.py
```

**Services sẽ chạy trên:**
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8888
- **Unified MCP Server**: http://localhost:8001
- **API Docs**: http://localhost:8888/docs

### Option 2: Production Deployment

#### A. Manual Setup

**Terminal 1 - Backend API:**
```bash
source .venv/bin/activate
python run_backend.py
```

**Terminal 2 - MCP Server:**
```bash
source .venv/bin/activate
python run_mcp_server.py
```

**Terminal 3 - Frontend:**
```bash
cd frontend
npm run preview  # hoặc serve build folder
```

#### B. Automated Production Setup

```bash
# Chạy script setup tự động
bash scripts/setup_production.sh

# Hoặc setup từng phần:
bash scripts/setup_services.sh    # Setup systemd services
bash scripts/setup_nginx.sh       # Setup Nginx reverse proxy
```

## 🔧 Production Configuration

### Systemd Services

Sau khi chạy `setup_services.sh`, các services sẽ được tạo:

```bash
# Kiểm tra status
sudo systemctl status mcpllm-backend
sudo systemctl status mcpllm-mcp

# Start/Stop services
sudo systemctl start mcpllm-backend
sudo systemctl stop mcpllm-backend

# Enable auto-start
sudo systemctl enable mcpllm-backend
sudo systemctl enable mcpllm-mcp

# Xem logs
sudo journalctl -u mcpllm-backend -f
sudo journalctl -u mcpllm-mcp -f
```

### Nginx Configuration

Sau khi chạy `setup_nginx.sh`:

```bash
# Test Nginx config
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx

# Kiểm tra status
sudo systemctl status nginx
```

**URLs sau khi setup Nginx:**
- **Frontend**: http://your-server-ip
- **Backend API**: http://your-server-ip:8888
- **MCP Server**: http://your-server-ip:8001

## 🔍 Troubleshooting

### 1. Backend không start được

```bash
# Kiểm tra logs
python run_backend.py

# Kiểm tra port có bị chiếm không
netstat -tulpn | grep 8888

# Kiểm tra Python dependencies
pip list | grep -E "(fastapi|uvicorn|langchain)"
```

### 2. MCP Server lỗi

```bash
# Kiểm tra RAG database
ls -la chroma_db/

# Test MCP server riêng
python mcp_server/unified_server.py

# Kiểm tra model download
ls -la ~/.cache/huggingface/
```

### 3. Frontend không load được

```bash
# Rebuild frontend
cd frontend
npm run build

# Kiểm tra build output
ls -la dist/

# Test local serve
npm run preview
```

### 4. Splunk connection lỗi

```bash
# Test Splunk connection
curl -k -u username:password https://splunk-server:8089/services/auth/login

# Kiểm tra .env config
grep SPLUNK .env

# Test với Python
python -c "
import os
from dotenv import load_dotenv
load_dotenv()
print('SPLUNK_HOST:', os.getenv('SPLUNK_HOST'))
print('SPLUNK_USERNAME:', os.getenv('SPLUNK_USERNAME'))
"
```

### 5. Memory issues

```bash
# Kiểm tra RAM usage
free -h

# Kiểm tra Python processes
ps aux | grep python

# Restart services nếu cần
sudo systemctl restart mcpllm-backend
sudo systemctl restart mcpllm-mcp
```

## 📊 Monitoring & Maintenance

### Health Checks

```bash
# Backend health
curl http://localhost:8888/health

# MCP server health  
curl http://localhost:8001/health

# Frontend (nếu dùng Nginx)
curl http://localhost/
```

### Log Monitoring

```bash
# Backend logs
tail -f logs/backend.log

# MCP server logs
tail -f logs/mcp_server.log

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# System logs
sudo journalctl -u mcpllm-backend -f
sudo journalctl -u mcpllm-mcp -f
```

### Database Maintenance

```bash
# Backup RAG database
tar -czf chroma_db_backup_$(date +%Y%m%d).tar.gz chroma_db/

# Check database size
du -sh chroma_db/

# Rebuild RAG database nếu cần
rm -rf chroma_db/
python scripts/populate_rag_data.py
```

## 🔐 Security Considerations

### 1. API Keys Protection

```bash
# Đảm bảo .env không public
echo ".env" >> .gitignore

# Set proper permissions
chmod 600 .env

# Sử dụng environment variables thay vì hardcode
export GROQ_API_KEY="your_key_here"
```

### 2. Firewall Configuration

```bash
# Mở ports cần thiết
sudo ufw allow 22      # SSH
sudo ufw allow 80      # HTTP
sudo ufw allow 443     # HTTPS
sudo ufw allow 8888    # Backend API
sudo ufw allow 8001    # MCP Server

# Enable firewall
sudo ufw enable
```

### 3. SSL/HTTPS Setup

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## 📈 Performance Optimization

### 1. Python Optimization

```bash
# Use production WSGI server
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker backend.main:app --bind 0.0.0.0:8888
```

### 2. Database Optimization

```bash
# Optimize ChromaDB
# Trong Python code, sử dụng:
# - Batch operations
# - Proper indexing
# - Memory-mapped files
```

### 3. Caching

```bash
# Setup Redis (optional)
sudo apt install redis-server
sudo systemctl enable redis-server

# Configure caching trong code
pip install redis
```

## 🆘 Support & Contact

Nếu gặp vấn đề:

1. **Kiểm tra logs** trước tiên
2. **Search issues** trên GitHub repository
3. **Tạo issue mới** với đầy đủ thông tin:
   - OS version
   - Python version
   - Error logs
   - Steps to reproduce

## 📚 Additional Resources

- [API Documentation](http://localhost:8888/docs)
- [MCP Server Docs](http://localhost:8001/docs)
- [Frontend Guide](frontend/README.md)
- [Architecture Overview](docs/ARCHITECTURE.md)

---

**🎉 Chúc bạn deploy thành công!**

Nếu cần hỗ trợ thêm, hãy tạo issue trên GitHub repository.