#!/bin/bash
# Script setup Nginx

echo "🌐 Setting up Nginx..."

SERVER_IP="$1"
if [ -z "$SERVER_IP" ]; then
    echo "Usage: ./setup_nginx.sh YOUR_SERVER_IP"
    echo "Example: ./setup_nginx.sh 192.168.1.100"
    exit 1
fi

# Tạo Nginx config
sudo tee /etc/nginx/sites-available/mcpllm > /dev/null << EOF
# MCPLLM Frontend + Backend
server {
    listen 80;
    server_name ${SERVER_IP};
    
    # Frontend static files
    location / {
        root /var/www/mcpllm/frontend/dist;
        try_files \$uri \$uri/ /index.html;
        
        # CORS headers
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
        add_header Access-Control-Allow-Headers "Content-Type, Authorization";
    }
    
    # Backend API
    location /api/ {
        proxy_pass http://127.0.0.1:8888/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # CORS headers
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
        add_header Access-Control-Allow-Headers "Content-Type, Authorization";
        
        # Handle preflight requests
        if (\$request_method = 'OPTIONS') {
            add_header Access-Control-Allow-Origin *;
            add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
            add_header Access-Control-Allow-Headers "Content-Type, Authorization";
            return 204;
        }
    }
    
    # Direct backend access (for development)
    location /backend/ {
        proxy_pass http://127.0.0.1:8888/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # MCP RAG Server (HTTP)
    location /rag/ {
        proxy_pass http://127.0.0.1:8001/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # CORS headers for MCP
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
        add_header Access-Control-Allow-Headers "Content-Type, Authorization";
    }
}

# Direct RAG Server access on port 8001
server {
    listen 8001;
    server_name ${SERVER_IP};
    
    location / {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # CORS headers
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
        add_header Access-Control-Allow-Headers "Content-Type, Authorization";
    }
}

# Direct backend access on port 8888
server {
    listen 8888;
    server_name ${SERVER_IP};
    
    location / {
        proxy_pass http://127.0.0.1:8888;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # CORS headers
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
        add_header Access-Control-Allow-Headers "Content-Type, Authorization";
    }
}
EOF

# Enable site
sudo ln -sf /etc/nginx/sites-available/mcpllm /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test nginx config
sudo nginx -t

if [ $? -eq 0 ]; then
    echo "✅ Nginx configuration is valid"
    sudo systemctl restart nginx
    echo "✅ Nginx restarted"
else
    echo "❌ Nginx configuration error"
    exit 1
fi

echo "🌐 Nginx setup completed!"
echo "📝 Frontend will be available at: http://${SERVER_IP}"
echo "📝 Backend API will be available at: http://${SERVER_IP}:8888"