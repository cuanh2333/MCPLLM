"""
Run full stack: MCP Server + Backend + Frontend
"""
import subprocess
import sys
import time
import os
import httpx
from pathlib import Path

def wait_for_service(url: str, service_name: str, timeout: int = 60):
    """Wait for a service to be ready"""
    print(f"⏳ Waiting for {service_name} to be ready...")
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            response = httpx.get(url, timeout=2.0)
            if response.status_code == 200:
                print(f"✅ {service_name} is ready!")
                return True
        except:
            pass
        time.sleep(1)
    
    print(f"⚠️  {service_name} did not start within {timeout}s")
    return False

def run_mcp_server():
    """Start Unified MCP Server"""
    print("🚀 Starting Unified MCP Server...")
    mcp_process = subprocess.Popen(
        [sys.executable, "mcp_server/unified_server.py"],
        text=True
    )
    return mcp_process

def run_backend():
    """Start FastAPI backend"""
    print("🚀 Starting backend server...")
    backend_process = subprocess.Popen(
        [sys.executable, "run_backend.py"],
        text=True
    )
    return backend_process

def run_frontend():
    """Start Vite frontend"""
    print("🚀 Starting frontend server...")
    frontend_dir = Path(__file__).parent / "frontend"
    
    # Check if node_modules exists
    if not (frontend_dir / "node_modules").exists():
        print("📦 Installing frontend dependencies...")
        subprocess.run(["npm", "install"], cwd=frontend_dir, shell=True)
    
    frontend_process = subprocess.Popen(
        ["npm", "run", "dev"],
        cwd=frontend_dir,
        text=True,
        shell=True
    )
    return frontend_process

def main():
    print("=" * 60)
    print("🔥 MCPLLM - Full Stack Local Development")
    print("=" * 60)
    
    processes = []
    
    try:
        # Start MCP server first
        mcp_server = run_mcp_server()
        processes.append(("MCP Server", mcp_server))
        
        # Wait for MCP server to be ready
        if not wait_for_service("http://127.0.0.1:8001/health", "MCP Server", timeout=60):
            raise RuntimeError("MCP Server failed to start")
        
        # Start backend
        backend = run_backend()
        processes.append(("Backend", backend))
        
        # Wait for backend to be ready
        if not wait_for_service("http://127.0.0.1:8888/health", "Backend", timeout=30):
            raise RuntimeError("Backend failed to start")
        
        # Start frontend
        frontend = run_frontend()
        processes.append(("Frontend", frontend))
        time.sleep(3)
        
        print("\n" + "=" * 60)
        print("✅ All servers started successfully!")
        print("=" * 60)
        print("🔧 Unified MCP Server: http://localhost:8001")
        print("📡 Backend API: http://localhost:8888")
        print("🌐 Frontend UI: http://localhost:3000")
        print("📚 API Docs: http://localhost:8888/docs")
        print("🩺 MCP Health: http://localhost:8001/health")
        print("=" * 60)
        print("\n⌨️  Press Ctrl+C to stop all servers\n")
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping all servers...")
        for name, process in processes:
            print(f"   Stopping {name}...")
            process.terminate()
        
        # Wait a bit for graceful shutdown
        time.sleep(2)
        
        # Force kill if still running
        for name, process in processes:
            if process.poll() is None:
                print(f"   Force killing {name}...")
                process.kill()
        
        print("✅ All servers stopped")

if __name__ == "__main__":
    main()