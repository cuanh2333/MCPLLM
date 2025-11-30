"""
Run both frontend and backend servers
"""
import subprocess
import sys
import time
import os
from pathlib import Path

def run_backend():
    """Start FastAPI backend"""
    print("🚀 Starting backend server...")
    backend_process = subprocess.Popen(
        [sys.executable, "run_backend.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
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
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=True
    )
    return frontend_process

def main():
    print("=" * 60)
    print("🔥 Security Analysis Chat - Full Stack")
    print("=" * 60)
    
    # Start backend
    backend = run_backend()
    time.sleep(3)  # Wait for backend to start
    
    # Start frontend
    frontend = run_frontend()
    time.sleep(2)
    
    print("\n" + "=" * 60)
    print("✅ Servers started successfully!")
    print("=" * 60)
    print("📡 Backend API: http://localhost:8000")
    print("🌐 Frontend UI: http://localhost:3000")
    print("📚 API Docs: http://localhost:8000/docs")
    print("=" * 60)
    print("\n⌨️  Press Ctrl+C to stop all servers\n")
    
    try:
        # Keep running and show logs
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping servers...")
        backend.terminate()
        frontend.terminate()
        print("✅ All servers stopped")

if __name__ == "__main__":
    main()
