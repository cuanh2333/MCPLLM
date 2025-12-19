#!/usr/bin/env python3
"""
Test Local Setup

Kiểm tra xem hệ thống có thể chạy local không.
"""

import os
import sys
import requests
import time
import subprocess
from pathlib import Path

def check_python_version():
    """Kiểm tra Python version."""
    print("🐍 Checking Python version...")
    version = sys.version_info
    if version.major == 3 and version.minor >= 10:
        print(f"   ✅ Python {version.major}.{version.minor}.{version.micro} (OK)")
        return True
    else:
        print(f"   ❌ Python {version.major}.{version.minor}.{version.micro} (Need >= 3.10)")
        return False

def check_node_version():
    """Kiểm tra Node.js version."""
    print("📦 Checking Node.js version...")
    try:
        result = subprocess.run(["node", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            version = result.stdout.strip()
            major_version = int(version.replace('v', '').split('.')[0])
            if major_version >= 18:
                print(f"   ✅ Node.js {version} (OK)")
                return True
            else:
                print(f"   ❌ Node.js {version} (Need >= 18)")
                return False
        else:
            print("   ❌ Node.js not found")
            return False
    except Exception as e:
        print(f"   ❌ Error checking Node.js: {e}")
        return False

def check_dependencies():
    """Kiểm tra Python dependencies."""
    print("📚 Checking Python dependencies...")
    required_packages = [
        "fastapi", "uvicorn", "pydantic", "langchain", 
        "langchain-groq", "httpx", "python-dotenv"
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
            print(f"   ✅ {package}")
        except ImportError:
            print(f"   ❌ {package} (missing)")
            missing.append(package)
    
    if missing:
        print(f"\n   Install missing packages: pip install {' '.join(missing)}")
        return False
    return True

def check_env_file():
    """Kiểm tra .env file."""
    print("⚙️  Checking .env configuration...")
    
    if not os.path.exists("../.env"):
        print("   ❌ .env file not found")
        print("   Create .env file: cp .env.example .env")
        return False
    
    print("   ✅ .env file exists")
    
    # Load and check basic config
    from dotenv import load_dotenv
    load_dotenv("../.env")
    
    groq_key = os.getenv("GROQ_API_KEY")
    if groq_key and groq_key != "your_groq_api_key_here":
        print("   ✅ GROQ_API_KEY configured")
    else:
        print("   ⚠️  GROQ_API_KEY not configured (optional for testing)")
    
    return True

def check_directories():
    """Kiểm tra thư mục cần thiết."""
    print("📁 Checking required directories...")
    
    required_dirs = ["../backend", "../frontend", "../mcp_server", "../output", "../KB"]
    for dir_name in required_dirs:
        if os.path.exists(dir_name):
            print(f"   ✅ {dir_name}/")
        else:
            print(f"   ❌ {dir_name}/ (missing)")
            return False
    
    return True

def test_import_modules():
    """Test import các module chính."""
    print("🔍 Testing module imports...")
    
    try:
        # Add project root to path
        project_root = Path(__file__).parent.parent
        sys.path.insert(0, str(project_root))
        
        # Test backend imports
        from backend.config import settings
        print("   ✅ backend.config")
        
        from backend.main import app
        print("   ✅ backend.main")
        
        # Test MCP server import
        from mcp_server.unified_server import app as mcp_app
        print("   ✅ mcp_server.unified_server")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Import error: {e}")
        return False

def test_services_start():
    """Test khởi động services."""
    print("🚀 Testing service startup...")
    
    # Test MCP server
    print("   Testing MCP server import...")
    try:
        from mcp_server.unified_server import app
        print("   ✅ MCP server can be imported")
    except Exception as e:
        print(f"   ❌ MCP server import failed: {e}")
        return False
    
    # Test backend
    print("   Testing backend import...")
    try:
        from backend.main import app
        print("   ✅ Backend can be imported")
    except Exception as e:
        print(f"   ❌ Backend import failed: {e}")
        return False
    
    return True

def main():
    """Chạy tất cả tests."""
    print("=" * 60)
    print("🧪 MCPLLM Local Setup Test")
    print("=" * 60)
    
    tests = [
        ("Python Version", check_python_version),
        ("Node.js Version", check_node_version),
        ("Python Dependencies", check_dependencies),
        ("Environment File", check_env_file),
        ("Directory Structure", check_directories),
        ("Module Imports", test_import_modules),
        ("Service Startup", test_services_start),
    ]
    
    results = []
    for test_name, test_func in tests:
        print()
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"   ❌ Test failed with error: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Results Summary")
    print("=" * 60)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
        if result:
            passed += 1
    
    print(f"\nPassed: {passed}/{len(results)} tests")
    
    if passed == len(results):
        print("\n🎉 All tests passed! You can run the system with:")
        print("   python scripts/run_fullstack.py")
    else:
        print(f"\n⚠️  {len(results) - passed} tests failed. Please fix the issues above.")
        print("\n📖 See README.md for detailed instructions.")
    
    return passed == len(results)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)