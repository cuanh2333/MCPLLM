#!/bin/bash
# Script tự động setup production

echo "🔧 Setting up production configuration..."

# 1. Tạo thư mục cần thiết
sudo mkdir -p /var/www/mcpllm
sudo mkdir -p /var/log/mcpllm
sudo chown -R deploy:deploy /var/www/mcpllm
sudo chown -R deploy:deploy /var/log/mcpllm

# 2. Copy code vào thư mục production
cp -r ~/mcpllm/* /var/www/mcpllm/
cd /var/www/mcpllm

# 3. Tạo .env production
cat > .env << 'EOF'
# Production Environment
GROQ_API_KEY=your_groq_api_key_here
GOOGLE_API_KEY=your_google_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here

# Telegram
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Splunk (cập nhật IP server thật)
SPLUNK_HOST=192.168.1.100
SPLUNK_PORT=8000
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=password

# Production settings
DEBUG=false
LOG_LEVEL=INFO
OUTPUT_DIR=/var/www/mcpllm/output
FONTS_DIR=/var/www/mcpllm/fonts
EOF

# 4. Tạo thư mục output và fonts
mkdir -p output fonts logs

# 5. Setup Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

echo "✅ Production setup completed!"
echo "📝 Next: Edit .env file with your real API keys"
echo "📝 Then: Run setup_services.sh"