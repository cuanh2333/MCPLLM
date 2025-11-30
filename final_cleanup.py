"""Final cleanup - Remove all unnecessary files, keep only README.md"""
import os
import glob
import shutil

print("🧹 Final Cleanup - Removing unnecessary files...\n")

# Files to delete
files_to_delete = [
    # All test files
    'test_*.py',
    'check_*.py',
    '*_test.py',
    
    # Cleanup scripts
    'cleanup_*.py',
    'reorganize_*.py',
    'update_imports_*.py',
    'fix_*.py',
    'rollback_*.py',
    'add_*.py',
    
    # Sample data
    'sample_*.txt',
    'access.log',
    
    # All MD files EXCEPT README.md
    'V4_*.md',
    'START_HERE.md',
    'HOW_IT_REALLY_WORKS.md',
    'INSTALLATION.md',
    'QUICK_START_UI.md',
    'HUONG_DAN_GIAO_DIEN.md',
    'README_V4.md',
    'SESSION_*.md',
    'FINAL_*.md',
    'COMPLETE_*.md',
    'TRULY_*.md',
    'AGENTS_*.md',
    'QUICK_START_*.md',
    'RUN_*.md',
    'TEST_*.md',
    'TESTING_*.md',
    'RESTART_*.md',
    'FRONTEND_*.md',
    'PDF_*.md',
    'SPLUNK_*.md',
    'CODE_*.md',
    'MCP_*.md',
    'test_monitoring_view.md',
    
    # Other scripts
    'generate_*.py',
    'migrate_*.py',
    'setup_*.py',
    'create_sample_*.py',
    'find_*.py',
    'show_*.py',
    'restart_*.py',
    'quick_*.py',
    'kill_*.py',
    'install_frontend.py',
    'run_v4_tests.py',
    'run_all_test_cases.py',
    'run_all_test_cases.sh',
    'clean_test_data.py',
    
    # Config files
    'pytest.ini',
    'requirements-test.txt',
]

# Directories to delete
dirs_to_delete = [
    'test',
    'tests',
    '.kiro',
]

deleted_count = 0

# Delete files
for pattern in files_to_delete:
    matches = glob.glob(pattern, recursive=False)
    for file_path in matches:
        if os.path.exists(file_path) and file_path != 'README.md':
            try:
                os.remove(file_path)
                deleted_count += 1
                print(f"  ✓ Deleted: {file_path}")
            except Exception as e:
                print(f"  ✗ Failed: {file_path} - {e}")

# Delete directories
for dir_path in dirs_to_delete:
    if os.path.exists(dir_path):
        try:
            shutil.rmtree(dir_path)
            deleted_count += 1
            print(f"  ✓ Deleted directory: {dir_path}")
        except Exception as e:
            print(f"  ✗ Failed: {dir_path} - {e}")

print(f"\n{'='*60}")
print(f"✅ Final Cleanup Complete!")
print(f"{'='*60}")
print(f"Deleted {deleted_count} items")

print("\n📦 Project Structure:")
print("""
MCPLLM/
├── README.md                    ← DOCUMENTATION DUY NHẤT
├── .env                         ← Configuration
├── requirements.txt
├── run_all_services.py          ← START HERE
├── run_fullstack.py
├── run_backend.py
├── cron_log_analyzer.py
├── backend/
│   ├── agents/                  ← 7 AI agents
│   ├── nodes/                   ← 4 LangGraph nodes
│   ├── utils/                   ← 5 utilities
│   ├── services/                ← 7 services
│   ├── main.py
│   ├── analyzer.py
│   ├── graph_builder.py
│   ├── routing.py
│   ├── models.py
│   └── config.py
├── frontend/
│   ├── src/
│   ├── package.json
│   └── vite.config.js
├── mcp_server/
│   ├── log_server.py
│   └── rag_server_http.py
├── KB/                          ← Knowledge base
├── fonts/                       ← PDF fonts
└── output/                      ← Analysis results
""")

print("\n🎯 Ready for deployment!")
print("\nTo start:")
print("  1. Configure .env file")
print("  2. python run_all_services.py")
print("  3. Open http://localhost:3000")
