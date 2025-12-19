"""
Run Unified MCP Server

Starts the unified MCP server (Log + RAG combined) for local development.
"""

import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

print("✓ Loaded environment variables from .env file")

def main():
    """Run the unified MCP server."""
    print("\nStarting Unified MCP Server...")
    print("Services: Log Server + RAG Server")
    print("Port: 8001")
    print("Health Check: http://127.0.0.1:8001/health")
    print("API Docs: http://127.0.0.1:8001/docs")
    print()
    
    # Import and run
    from mcp_server.unified_server import app
    import uvicorn
    
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8001,
        log_level="info",
        access_log=True
    )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✓ MCP server stopped")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Error starting MCP server: {e}")
        sys.exit(1)