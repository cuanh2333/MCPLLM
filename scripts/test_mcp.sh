#!/bin/bash
# Script test MCP servers

echo "🧪 Testing MCP servers..."

SERVER_IP="$1"
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="127.0.0.1"
fi

echo "Testing on server: $SERVER_IP"

# Test Unified MCP Server
echo ""
echo "1. Testing Unified MCP Server..."
echo "================================"

# Test health endpoint
echo "Health check:"
curl -s "http://${SERVER_IP}:8001/health" | jq . 2>/dev/null || curl -s "http://${SERVER_IP}:8001/health"

# Test RAG query
echo ""
echo "RAG query test:"
curl -s -X POST "http://${SERVER_IP}:8001/query_rag" \
  -H "Content-Type: application/json" \
  -d '{"query": "What is SQL injection?", "top_k": 3}' | jq . 2>/dev/null || echo "RAG query test completed"

# Test log file loading
echo ""
echo "Log file test:"
curl -s -X POST "http://${SERVER_IP}:8001/load_log_file" \
  -H "Content-Type: application/json" \
  -d '{"filepath": "./access.log", "max_lines": 5}' | jq . 2>/dev/null || echo "Log file test completed"

# Test Splunk connection (if configured)
echo ""
echo "Testing Splunk connection:"
curl -s -X POST "http://${SERVER_IP}:8001/splunk_query" \
  -H "Content-Type: application/json" \
  -d '{"index": "main", "earliest_time": "-1h", "latest_time": "now"}' | jq . 2>/dev/null || echo "Splunk test completed (may fail if not configured)"

# Test Backend API
echo ""
echo "2. Testing Backend API..."
echo "========================="

# Test health
echo "Backend health:"
curl -s "http://${SERVER_IP}:8888/health" | jq . 2>/dev/null || curl -s "http://${SERVER_IP}:8888/health"

# Test docs
echo ""
echo "API docs available at: http://${SERVER_IP}:8888/docs"

# Check service status
echo ""
echo "3. Service Status..."
echo "==================="

services=("mcpllm-unified-server" "mcpllm-backend" "nginx")

for service in "${services[@]}"; do
    status=$(sudo systemctl is-active $service 2>/dev/null)
    if [ "$status" = "active" ]; then
        echo "✅ $service: $status"
    else
        echo "❌ $service: $status"
    fi
done

echo ""
echo "📝 Access URLs:"
echo "==============="
echo "Frontend: http://${SERVER_IP}"
echo "Backend API: http://${SERVER_IP}:8888"
echo "Unified MCP Server: http://${SERVER_IP}:8001"
echo "Backend API Docs: http://${SERVER_IP}:8888/docs"
echo "MCP Server Docs: http://${SERVER_IP}:8001/docs"

echo ""
echo "📝 Logs commands:"
echo "=================="
echo "Unified MCP Server: sudo journalctl -u mcpllm-unified-server -f"
echo "Backend: sudo journalctl -u mcpllm-backend -f"
echo "Nginx: sudo tail -f /var/log/nginx/access.log"