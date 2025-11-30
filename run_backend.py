"""
Run Backend API Server

Starts the FastAPI backend server with uvicorn.
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

# Import and run
import uvicorn
from backend.config import settings

def main():
    """Run the backend API server."""
    host = "127.0.0.1"
    port = 8000
    
    print("\nStarting V1 Log Analyzer Backend...")
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"Reload: False")
    print(f"Log Level: info")
    print(f"API Documentation: http://{host}:{port}/docs")
    print(f"Health Check: http://{host}:{port}/health")
    print()
    
    # Run uvicorn server
    uvicorn.run(
        "backend.main:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
        access_log=True
    )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✓ Backend server stopped")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Error starting backend: {e}")
        sys.exit(1)
