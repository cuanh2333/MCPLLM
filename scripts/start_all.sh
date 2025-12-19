#!/bin/bash
# Script khởi động tất cả services

echo "🚀 Starting all MCPLLM services..."

# 1. Start Unified MCP Server
echo "Starting Unified MCP Server (Log + RAG)..."
sudo systemctl start mcpllm-unified-server
sleep 3

# 2. Start backend
echo "Starting backend..."
sudo systemctl start mcpllm-backend
sleep 3

# 4. Restart nginx
echo "Restarting Nginx..."
sudo systemctl restart nginx

# 5. Check status
echo ""
echo "📊 Service Status:"
echo "=================="

echo "Unified MCP Server:"
sudo systemctl is-active mcpllm-unified-server
sudo systemctl status mcpllm-unified-server --no-pager -l

echo ""
echo "Backend:"
sudo systemctl is-active mcpllm-backend
sudo systemctl status mcpllm-backend --no-pager -l

echo ""
echo "Nginx:"
sudo systemctl is-active nginx
sudo systemctl status nginx --no-pager -l

echo ""
echo "🌐 Access URLs:"
echo "==============="
echo "Frontend: http://$(hostname -I | awk '{print $1}')"
echo "Backend API: http://$(hostname -I | awk '{print $1}'):8888"
echo "API Docs: http://$(hostname -I | awk '{print $1}'):8888/docs"

echo ""
echo "📝 Useful commands:"
echo "==================="
echo "View backend logs: sudo journalctl -u mcpllm-backend -f"
echo "View RAG logs: sudo journalctl -u mcpllm-rag -f"
echo "View nginx logs: sudo tail -f /var/log/nginx/access.log"
echo "Stop all: sudo systemctl stop mcpllm-backend mcpllm-rag nginx"