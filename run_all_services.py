"""
Start All Services Script

Khởi động tất cả services cần thiết:
1. RAG Server (MCP) - Port 8001
2. Log Server (MCP) - Stdio (không cần port)
3. Backend API - Port 8000
4. Frontend (Vite) - Port 3000

Tất cả chạy trong background, có thể dừng bằng Ctrl+C
"""

import subprocess
import sys
import time
import os
import signal
from pathlib import Path

# Colors for terminal output
class Colors:
    GREEN = '\033[0;32m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color


class ServiceManager:
    """Quản lý các services."""
    
    def __init__(self):
        self.processes = []
        self.base_dir = Path(__file__).parent
        
    def start_service(self, name, command, cwd=None, wait_time=2, show_output=False):
        """Khởi động một service."""
        print(f"{Colors.CYAN}[{name}]{Colors.NC} Starting...")
        
        try:
            # Start process
            if show_output:
                # Show output in real-time
                process = subprocess.Popen(
                    command,
                    cwd=cwd or self.base_dir,
                    shell=True,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
                )
            else:
                # Capture output
                process = subprocess.Popen(
                    command,
                    cwd=cwd or self.base_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == 'win32' else 0
                )
            
            self.processes.append({
                'name': name,
                'process': process,
                'command': command,
                'show_output': show_output
            })
            
            # Wait a bit for service to start
            time.sleep(wait_time)
            
            # Check if still running
            if process.poll() is None:
                print(f"{Colors.GREEN}[{name}]{Colors.NC} ✓ Started (PID: {process.pid})")
                if show_output:
                    print(f"  Output: Showing in real-time")
                return True
            else:
                if not show_output:
                    stdout, stderr = process.communicate()
                    print(f"{Colors.RED}[{name}]{Colors.NC} ✗ Failed to start")
                    if stderr:
                        print(f"  Error: {stderr.decode('utf-8', errors='ignore')[:200]}")
                else:
                    print(f"{Colors.RED}[{name}]{Colors.NC} ✗ Failed to start")
                return False
                
        except Exception as e:
            print(f"{Colors.RED}[{name}]{Colors.NC} ✗ Exception: {e}")
            return False
    
    def stop_all(self):
        """Dừng tất cả services."""
        print(f"\n{Colors.YELLOW}Stopping all services...{Colors.NC}")
        
        for service in self.processes:
            name = service['name']
            process = service['process']
            
            if process.poll() is None:  # Still running
                print(f"{Colors.CYAN}[{name}]{Colors.NC} Stopping...")
                
                try:
                    if sys.platform == 'win32':
                        # Windows: Send CTRL_BREAK_EVENT
                        process.send_signal(signal.CTRL_BREAK_EVENT)
                    else:
                        # Unix: Send SIGTERM
                        process.terminate()
                    
                    # Wait for graceful shutdown
                    try:
                        process.wait(timeout=5)
                        print(f"{Colors.GREEN}[{name}]{Colors.NC} ✓ Stopped")
                    except subprocess.TimeoutExpired:
                        # Force kill if not stopped
                        process.kill()
                        print(f"{Colors.YELLOW}[{name}]{Colors.NC} ✓ Force killed")
                        
                except Exception as e:
                    print(f"{Colors.RED}[{name}]{Colors.NC} Error stopping: {e}")
    
    def monitor(self):
        """Monitor services và restart nếu crash."""
        print(f"\n{Colors.GREEN}All services running!{Colors.NC}")
        print(f"{Colors.CYAN}Press Ctrl+C to stop all services{Colors.NC}\n")
        
        try:
            while True:
                time.sleep(5)
                
                # Check if any service crashed
                for service in self.processes:
                    name = service['name']
                    process = service['process']
                    
                    if process.poll() is not None:  # Process died
                        print(f"{Colors.RED}[{name}]{Colors.NC} ✗ Crashed! Exit code: {process.returncode}")
                        
                        # Get error output
                        stdout, stderr = process.communicate()
                        if stderr:
                            print(f"  Error: {stderr.decode('utf-8', errors='ignore')[:500]}")
                        
                        # Don't auto-restart, just notify
                        print(f"{Colors.YELLOW}Please restart manually or fix the issue{Colors.NC}")
                        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Received Ctrl+C{Colors.NC}")


def main():
    """Main function."""
    print(f"{Colors.BLUE}{'='*60}{Colors.NC}")
    print(f"{Colors.BLUE}Starting All Services{Colors.NC}")
    print(f"{Colors.BLUE}{'='*60}{Colors.NC}\n")
    
    manager = ServiceManager()
    
    # Check if .env exists
    if not Path('.env').exists():
        print(f"{Colors.RED}✗ .env file not found!{Colors.NC}")
        print(f"  Please create .env file with required API keys")
        sys.exit(1)
    
    # Load .env
    try:
        from dotenv import load_dotenv
        load_dotenv()
        print(f"{Colors.GREEN}✓ Loaded .env file{Colors.NC}\n")
    except ImportError:
        print(f"{Colors.YELLOW}⚠ python-dotenv not installed{Colors.NC}\n")
    
    # Start services in order
    services_started = 0
    
    # 1. RAG Server (HTTP) - Chạy trước để load ChromaDB
    print(f"{Colors.CYAN}[1/3] RAG Server (HTTP){Colors.NC}")
    if manager.start_service(
        name="RAG Server",
        command="python mcp_server/rag_server_http.py",
        wait_time=10,  # Wait longer for ChromaDB to load (first time ~40s)
        show_output=True  # Show RAG server logs
    ):
        services_started += 1
    
    # 2. Log Server (MCP) - Không cần port, chỉ cần process sẵn sàng
    # Note: Log server dùng stdio nên không cần chạy persistent
    # Nó sẽ được spawn khi cần bởi backend
    print(f"\n{Colors.CYAN}[2/3] Log Server (MCP){Colors.NC}")
    print(f"{Colors.GREEN}[Log Server]{Colors.NC} ✓ Will be spawned on-demand (stdio)")
    
    # 3. Backend API
    print(f"\n{Colors.CYAN}[3/4] Backend API{Colors.NC}")
    if manager.start_service(
        name="Backend API",
        command="python run_backend.py",
        wait_time=3,
        show_output=True  # Show backend logs
    ):
        services_started += 1
    
    # 4. Frontend (Vite)
    print(f"\n{Colors.CYAN}[4/4] Frontend (Vite){Colors.NC}")
    frontend_dir = Path(__file__).parent / "frontend"
    if frontend_dir.exists():
        if manager.start_service(
            name="Frontend",
            command="npm run dev",
            cwd=frontend_dir,
            wait_time=5,
            show_output=True  # Show frontend logs
        ):
            services_started += 1
    else:
        print(f"{Colors.YELLOW}[Frontend]{Colors.NC} ⚠ Directory not found, skipping")
    
    # Summary
    print(f"\n{Colors.BLUE}{'='*60}{Colors.NC}")
    print(f"{Colors.GREEN}Services Started: {services_started}/3{Colors.NC}")
    print(f"{Colors.BLUE}{'='*60}{Colors.NC}")
    
    if services_started < 2:
        print(f"\n{Colors.RED}Some services failed to start!{Colors.NC}")
        print(f"Please check the errors above and fix them.")
        manager.stop_all()
        sys.exit(1)
    
    # Show service URLs
    print(f"\n{Colors.CYAN}Service URLs:{Colors.NC}")
    print(f"  Frontend UI:  http://localhost:3000")
    print(f"  Backend API:  http://127.0.0.1:8000")
    print(f"  API Docs:     http://127.0.0.1:8000/docs")
    print(f"  Health Check: http://127.0.0.1:8000/health")
    print(f"  RAG Server:   Running in background (MCP)")
    print(f"  Log Server:   On-demand (stdio)")
    
    # Monitor services
    try:
        manager.monitor()
    except Exception as e:
        print(f"\n{Colors.RED}Monitor error: {e}{Colors.NC}")
    finally:
        manager.stop_all()
        print(f"\n{Colors.GREEN}All services stopped. Goodbye!{Colors.NC}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted by user{Colors.NC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Fatal error: {e}{Colors.NC}")
        sys.exit(1)
