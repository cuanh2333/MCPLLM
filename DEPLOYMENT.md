# 🚀 MCPLLM Deployment Guide

Hướng dẫn chi tiết để deploy MCPLLM system lên server production.

## 📋 Yêu cầu hệ thống

### Minimum Requirements:
- **OS**: Ubuntu 20.04+ / CentOS 7+ / Windows Server 2019+
- **RAM**: 8GB (16GB recommended)
- **CPU**: 4 cores (8 cores recommended)
- **Storage**: 10GB free space
- **Network**: Internet connection để download models

### Software Requirements:
- **Python**: 3.9+
- **Node.js**: 18+
- **Nginx**: 1.18+ (optional, for production)
- **Git**: Latest version

## 🌐 Deploy lên Server (VPS/Cloud)

### Bước 0: Chuẩn bị Server

**Kết nối vào server:**
```bash
# SSH vào server (thay your-server-ip bằng IP thật)
ssh root@your-server-ip
# hoặc
ssh username@your-server-ip
```

**Update system:**
```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade -y

# CentOS/RHEL
sudo yum update -y
```

**Cài đặt các công cụ cần thiết:**
```bash
# Ubuntu/Debian
sudo apt install -y git curl wget build-essential

# CentOS/RHEL
sudo yum install -y git curl wget gcc gcc-c++ make
```

**Cài đặt Python 3.10+:**
```bash
# Ubuntu 22.04+ đã có Python 3.10
python3 --version

# Nếu chưa có, cài đặt:
sudo apt install -y python3.10 python3.10-venv python3-pip

# Hoặc dùng pyenv để cài nhiều version:
curl https://pyenv.run | bash
pyenv install 3.10.12
pyenv global 3.10.12
```

**Cài đặt Node.js 18+:**
```bash
# Dùng NodeSource repository
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Kiểm tra version
node --version
npm --version
```

**Cài đặt Nginx (optional, cho production):**
```bash
# Ubuntu/Debian
sudo apt install -y nginx

# CentOS/RHEL
sudo yum install -y nginx

# Start và enable Nginx
sudo systemctl start nginx
sudo systemctl enable nginx
```

**Tạo user riêng cho app (recommended):**
```bash
# Tạo user mcpllm
sudo adduser mcpllm

# Add vào sudo group (nếu cần)
sudo usermod -aG sudo mcpllm

# Switch sang user mcpllm
su - mcpllm
```

## 🔧 Cài đặt từng bước

### Bước 1: Clone Repository

```bash
# Clone project vào server
cd ~
git clone https://github.com/cuanh2333/MCPLLM.git
cd MCPLLM

# Kiểm tra branch
git branch -a
git checkout main
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
# Nếu bạn đã có chroma_db từ local, upload lên server:
# Trên máy local:
tar -czf chroma_db.tar.gz chroma_db/
scp chroma_db.tar.gz username@your-server-ip:~/MCPLLM/

# Trên server:
cd ~/MCPLLM
tar -xzf chroma_db.tar.gz
rm chroma_db.tar.gz

# Hoặc populate lại từ đầu (mất thời gian):
python scripts/populate_rag_data.py
```

### Bước 6: Test Setup

```bash
# Test cấu hình cơ bản
python scripts/test_local_setup.py

# Test MCP server
bash scripts/test_mcp.sh
```

### Bước 7: Setup Systemd Services (Production)

**Tạo service cho Backend:**
```bash
sudo nano /etc/systemd/system/mcpllm-backend.service
```

Nội dung file:
```ini
[Unit]
Description=MCPLLM Backend API
After=network.target

[Service]
Type=simple
User=mcpllm
WorkingDirectory=/home/mcpllm/MCPLLM
Environment="PATH=/home/mcpllm/MCPLLM/.venv/bin"
ExecStart=/home/mcpllm/MCPLLM/.venv/bin/python run_backend.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Tạo service cho MCP Server:**
```bash
sudo nano /etc/systemd/system/mcpllm-mcp.service
```

Nội dung file:
```ini
[Unit]
Description=MCPLLM MCP Server
After=network.target

[Service]
Type=simple
User=mcpllm
WorkingDirectory=/home/mcpllm/MCPLLM
Environment="PATH=/home/mcpllm/MCPLLM/.venv/bin"
ExecStart=/home/mcpllm/MCPLLM/.venv/bin/python run_mcp_server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable và start services:**
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable services (auto-start on boot)
sudo systemctl enable mcpllm-backend
sudo systemctl enable mcpllm-mcp

# Start services
sudo systemctl start mcpllm-backend
sudo systemctl start mcpllm-mcp

# Kiểm tra status
sudo systemctl status mcpllm-backend
sudo systemctl status mcpllm-mcp
```

### Bước 8: Setup Nginx Reverse Proxy

**Tạo Nginx config:**
```bash
sudo nano /etc/nginx/sites-available/mcpllm
```

Nội dung file:
```nginx
# Frontend
server {
    listen 80;
    server_name your-domain.com;  # Thay bằng domain hoặc IP của bạn

    # Frontend static files
    location / {
        root /home/mcpllm/MCPLLM/frontend/dist;
        try_files $uri $uri/ /index.html;
        
        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }

    # Backend API proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8888/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeout settings
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }

    # MCP Server proxy
    location /mcp/ {
        proxy_pass http://127.0.0.1:8001/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    # Logs
    access_log /var/log/nginx/mcpllm_access.log;
    error_log /var/log/nginx/mcpllm_error.log;
}
```

**Enable site và restart Nginx:**
```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/mcpllm /etc/nginx/sites-enabled/

# Test config
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
```

### Bước 9: Setup Firewall

```bash
# Cho phép SSH, HTTP, HTTPS
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Nếu muốn truy cập trực tiếp backend/mcp (không khuyến nghị)
# sudo ufw allow 8888/tcp
# sudo ufw allow 8001/tcp

# Enable firewall
sudo ufw enable

# Kiểm tra status
sudo ufw status
```

### Bước 10: Setup SSL/HTTPS (Optional nhưng khuyến nghị)

```bash
# Cài đặt Certbot
sudo apt install -y certbot python3-certbot-nginx

# Lấy SSL certificate (thay your-domain.com)
sudo certbot --nginx -d your-domain.com

# Test auto-renewal
sudo certbot renew --dry-run

# Certbot sẽ tự động renew, nhưng có thể thêm cron job:
sudo crontab -e
# Thêm dòng:
0 12 * * * /usr/bin/certbot renew --quiet
```

## 🎯 Kiểm tra Deployment

### Kiểm tra Services

```bash
# Kiểm tra backend
curl http://localhost:8888/health

# Kiểm tra MCP server
curl http://localhost:8001/health

# Kiểm tra qua Nginx (từ máy khác)
curl http://your-server-ip/api/health
curl http://your-server-ip/mcp/health
```

### Kiểm tra Frontend

Mở trình duyệt và truy cập:
- **HTTP**: http://your-server-ip
- **HTTPS**: https://your-domain.com (nếu đã setup SSL)

### Xem Logs

```bash
# Backend logs
sudo journalctl -u mcpllm-backend -f

# MCP server logs
sudo journalctl -u mcpllm-mcp -f

# Nginx logs
sudo tail -f /var/log/nginx/mcpllm_access.log
sudo tail -f /var/log/nginx/mcpllm_error.log
```

## 🔄 Update và Maintenance

### Update Code từ GitHub

```bash
# SSH vào server
ssh username@your-server-ip

# Chuyển vào thư mục project
cd ~/MCPLLM

# Pull code mới
git pull origin main

# Update dependencies (nếu có thay đổi)
source .venv/bin/activate
pip install -r requirements.txt

# Rebuild frontend (nếu có thay đổi)
cd frontend
npm install
npm run build
cd ..

# Restart services
sudo systemctl restart mcpllm-backend
sudo systemctl restart mcpllm-mcp
sudo systemctl reload nginx
```

### Backup Database

```bash
# Tạo backup script
nano ~/backup_mcpllm.sh
```

Nội dung:
```bash
#!/bin/bash
BACKUP_DIR="/home/mcpllm/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Tạo thư mục backup
mkdir -p $BACKUP_DIR

# Backup chroma_db
cd /home/mcpllm/MCPLLM
tar -czf $BACKUP_DIR/chroma_db_$DATE.tar.gz chroma_db/

# Backup .env
cp .env $BACKUP_DIR/.env_$DATE

# Xóa backup cũ hơn 7 ngày
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete

echo "Backup completed: $DATE"
```

```bash
# Cho phép execute
chmod +x ~/backup_mcpllm.sh

# Test backup
~/backup_mcpllm.sh

# Setup cron job để backup tự động
crontab -e
# Thêm dòng (backup mỗi ngày lúc 2h sáng):
0 2 * * * /home/mcpllm/backup_mcpllm.sh >> /home/mcpllm/backup.log 2>&1
```

## 🌐 Deployment Options (Alternative)

### Option 1: Quick Start (Development/Testing)

Chạy tất cả services cùng lúc (không dùng cho production):

```bash
python run_fullstack.py
```

**Services sẽ chạy trên:**
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8888
- **Unified MCP Server**: http://localhost:8001
- **API Docs**: http://localhost:8888/docs

### Option 2: Production với Docker (Coming Soon)

```bash
# Build và run với Docker Compose
docker-compose up -d

# Xem logs
docker-compose logs -f

# Stop services
docker-compose down
```

## � Choecklist Deploy lên Server

### Pre-deployment
- [ ] Có server VPS/Cloud (Ubuntu 20.04+, 8GB RAM, 4 CPU cores)
- [ ] Có domain name (optional, có thể dùng IP)
- [ ] Có API keys: Groq, Google AI, AbuseIPDB
- [ ] Đã test code trên local

### Deployment Steps
- [ ] SSH vào server
- [ ] Update system và cài đặt dependencies
- [ ] Clone repository từ GitHub
- [ ] Setup Python virtual environment
- [ ] Cấu hình .env với API keys
- [ ] Build frontend
- [ ] Upload hoặc populate RAG database
- [ ] Test local setup
- [ ] Tạo systemd services
- [ ] Setup Nginx reverse proxy
- [ ] Cấu hình firewall
- [ ] Setup SSL/HTTPS (optional)
- [ ] Test deployment
- [ ] Setup backup cron job

### Post-deployment
- [ ] Monitor logs
- [ ] Test tất cả features
- [ ] Setup monitoring/alerting
- [ ] Document server credentials
- [ ] Tạo backup đầu tiên

## 🔧 Quản lý Services

### Systemd Commands

```bash
# Kiểm tra status
sudo systemctl status mcpllm-backend
sudo systemctl status mcpllm-mcp

# Start/Stop/Restart services
sudo systemctl start mcpllm-backend
sudo systemctl stop mcpllm-backend
sudo systemctl restart mcpllm-backend

# Enable/Disable auto-start
sudo systemctl enable mcpllm-backend
sudo systemctl disable mcpllm-backend

# Xem logs real-time
sudo journalctl -u mcpllm-backend -f
sudo journalctl -u mcpllm-mcp -f

# Xem logs với filter
sudo journalctl -u mcpllm-backend --since "1 hour ago"
sudo journalctl -u mcpllm-backend --since "2024-12-19 10:00:00"
```

### Nginx Commands

```bash
# Test config
sudo nginx -t

# Reload config (không downtime)
sudo systemctl reload nginx

# Restart Nginx
sudo systemctl restart nginx

# Kiểm tra status
sudo systemctl status nginx

# Xem logs
sudo tail -f /var/log/nginx/mcpllm_access.log
sudo tail -f /var/log/nginx/mcpllm_error.log
```

**URLs sau khi deploy:**
- **Frontend**: http://your-server-ip hoặc https://your-domain.com
- **Backend API**: http://your-server-ip/api/
- **MCP Server**: http://your-server-ip/mcp/
- **API Docs**: http://your-server-ip/api/docs

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