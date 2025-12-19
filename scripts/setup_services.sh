#!/bin/bash
# Script setup backend systemd service

echo "🚀 Setting up backend service..."

# Tạo backend service
sudo tee /etc/systemd/system/mcpllm-backend.service > /dev/null << 'EOF'
[Unit]
Description=MCPLLM Backend API
After=network.target mcpllm-unified-server.service

[Service]
Type=simple
User=deploy
Group=deploy
WorkingDirectory=/var/www/mcpllm
Environment=PATH=/var/www/mcpllm/.venv/bin
Environment=PYTHONPATH=/var/www/mcpllm
ExecStart=/var/www/mcpllm/.venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8888
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd và enable service
sudo systemctl daemon-reload
sudo systemctl enable mcpllm-backend

echo "✅ Backend service created and enabled"
echo "📝 Next: Run setup_nginx.sh"