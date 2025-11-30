"""
MCP Log Retrieval Server

Provides tools for retrieving logs from various sources:
- load_log_file: Read logs from local files
- splunk_search: Retrieve logs from Splunk (stub for V1)
"""

from mcp.server.fastmcp import FastMCP
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize FastMCP server
mcp = FastMCP("log-retrieval-server")


@mcp.tool()
def load_log_file(filepath: str, max_lines: Optional[int] = None) -> list[str]:
    """
    Load logs from a local file.
    
    Args:
        filepath: Path to the log file to read
        max_lines: Optional maximum number of lines to return (returns most recent lines)
    
    Returns:
        List of log lines as strings
    
    Raises:
        FileNotFoundError: If the specified file does not exist
        PermissionError: If the file cannot be read due to permissions
        IOError: If there's an error reading the file
    """
    try:
        # Convert to Path object for better path handling
        log_path = Path(filepath)
        
        # Check if file exists
        if not log_path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        # Check if it's a file (not a directory)
        if not log_path.is_file():
            raise IOError(f"Path is not a file: {filepath}")
        
        # Read the file
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
        
        # Strip newlines from each line
        lines = [line.rstrip('\n\r') for line in lines]
        
        # Apply max_lines limit if specified
        if max_lines is not None and max_lines > 0:
            # Return the most recent lines (last N lines)
            lines = lines[-max_lines:]
        
        return lines
    
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Failed to load log file: {e}")
    except PermissionError as e:
        raise PermissionError(f"Permission denied reading log file: {filepath}")
    except Exception as e:
        raise IOError(f"Error reading log file {filepath}: {e}")


@mcp.tool()
def splunk_search(
    index: str,
    sourcetype: str,
    earliest_time: str,
    latest_time: str,
    search_filter: str = ""
) -> list[str]:
    """
    Retrieve logs from Splunk using splunklib SDK.
    
    Args:
        index: Splunk index to search (e.g., "main", "web_iis")
        sourcetype: Sourcetype to filter (e.g., "modsec:dvwa")
        earliest_time: Start time for search (e.g., "-7h5m", "-1h")
        latest_time: End time for search (e.g., "-7h", "now")
        search_filter: Optional additional search filter (e.g., "status=500")
    
    Returns:
        List of log lines as strings
    
    Raises:
        ConnectionError: If cannot connect to Splunk server
        Exception: If search fails
    """
    import os
    import splunklib.client as client
    import splunklib.results as results
    
    # Get Splunk credentials from environment
    splunk_host = os.getenv("SPLUNK_HOST", "localhost")
    splunk_port = int(os.getenv("SPLUNK_PORT", "8089"))
    splunk_username = os.getenv("SPLUNK_USERNAME", "admin")
    splunk_password = os.getenv("SPLUNK_PASSWORD", "")
    
    if not splunk_password:
        raise ValueError("SPLUNK_PASSWORD not set in environment")
    
    try:
        # Connect to Splunk
        service = client.connect(
            host=splunk_host,
            port=splunk_port,
            username=splunk_username,
            password=splunk_password,
            autologin=True
        )
        
        # Build search query
        search_query = f'search index={index} sourcetype={sourcetype}'
        if search_filter:
            search_query += f' {search_filter}'
        
        # Create search job
        job = service.jobs.create(
            search_query,
            earliest_time=earliest_time,
            latest_time=latest_time,
            exec_mode="blocking"  # Wait for results
        )
        
        # Get results (count=0 means get all results, not just first 100)
        log_lines = []
        for result in results.ResultsReader(job.results(count=0)):
            if isinstance(result, dict):
                # Extract _raw field (the actual log line)
                raw_log = result.get('_raw', '')
                if raw_log:
                    log_lines.append(raw_log)
        
        return log_lines
    
    except Exception as e:
        # Log error and raise exception so caller can see what went wrong
        import traceback
        error_msg = f"Splunk search error: {e}\n{traceback.format_exc()}"
        print(error_msg)
        # Return error as a log line so we can see it
        return [f"ERROR: {error_msg}"]


@mcp.tool()
def abuseipdb_check(ip_address: str) -> str:
    """
    Check IP reputation using AbuseIPDB API.
    
    Args:
        ip_address: IP address to check
    
    Returns:
        JSON string with IP reputation data
    """
    import os
    import requests
    
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    
    if not api_key:
        return '{"error": "ABUSEIPDB_API_KEY not set in environment"}'
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        # Extract key information
        if "data" in data:
            ip_data = data["data"]
            result = {
                "ip": ip_address,
                "abuse_confidence_score": ip_data.get("abuseConfidenceScore", 0),
                "country_code": ip_data.get("countryCode", "N/A"),
                "usage_type": ip_data.get("usageType", "N/A"),
                "isp": ip_data.get("isp", "N/A"),
                "total_reports": ip_data.get("totalReports", 0),
                "is_whitelisted": ip_data.get("isWhitelisted", False),
                "last_reported_at": ip_data.get("lastReportedAt", "N/A")
            }
            return str(result)
        else:
            return str(data)
    
    except requests.exceptions.RequestException as e:
        return f'{{"error": "AbuseIPDB API request failed: {str(e)}"}}'
    except Exception as e:
        return f'{{"error": "AbuseIPDB check failed: {str(e)}"}}'


@mcp.tool()
def virustotal_ip(ip_address: str) -> str:
    """
    Check IP reputation using VirusTotal API.
    
    Args:
        ip_address: IP address to check
    
    Returns:
        JSON string with IP reputation data
    """
    import os
    import requests
    
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    
    if not api_key:
        return '{"error": "VIRUSTOTAL_API_KEY not set in environment"}'
    
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {
            "x-apikey": api_key
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        # Extract key information
        if "data" in data:
            ip_data = data["data"]
            attributes = ip_data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            result = {
                "ip": ip_address,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "country": attributes.get("country", "N/A"),
                "as_owner": attributes.get("as_owner", "N/A"),
                "reputation": attributes.get("reputation", 0)
            }
            return str(result)
        else:
            return str(data)
    
    except requests.exceptions.RequestException as e:
        return f'{{"error": "VirusTotal API request failed: {str(e)}"}}'
    except Exception as e:
        return f'{{"error": "VirusTotal check failed: {str(e)}"}}'


@mcp.tool()
def cron_splunk_query(earliest_time: str = "-7h-5m", latest_time: str = "-7h") -> list[str]:
    """
    Retrieve logs from Splunk for scheduled cron analysis.
    
    This is a convenience tool specifically for cron jobs that automatically
    queries the configured Splunk index with predefined parameters:
    - index: web_iis
    - sourcetype: modsec:dvwa
    - earliest_time: configurable (default: -7h-5m for sliding window)
    - latest_time: configurable (default: -7h for sliding window)
    
    Args:
        earliest_time: Splunk earliest time (e.g., "-7h-5m", "-1h")
        latest_time: Splunk latest time (e.g., "-7h", "now")
    
    Returns:
        List of log lines as strings from the specified time range
    """
    import os
    
    # Get config from environment or use defaults
    index = os.getenv("SPLUNK_INDEX", "web_iis")
    sourcetype = os.getenv("SPLUNK_SOURCETYPE", "modsec:dvwa")
    
    # Use splunk_search with provided or default cron parameters
    return splunk_search(
        index=index,
        sourcetype=sourcetype,
        earliest_time=earliest_time,
        latest_time=latest_time,
        search_filter=""
    )


@mcp.tool()
def rag_query(question: str, top_k: int = 5) -> str:
    """
    V3: Query OWASP/MITRE/Sigma knowledge base using RAG.
    
    Args:
        question: User's security question
        top_k: Number of top relevant snippets to return (default: 5)
    
    Returns:
        JSON string with list of relevant knowledge base snippets:
        [
            {
                "source": "OWASP Top 10",
                "title": "A03:2021 – Injection",
                "content": "...",
                "relevance": 0.95
            },
            ...
        ]
    """
    import json
    
    # TODO: Implement actual RAG with vector DB (ChromaDB/FAISS)
    # For now, return mock data based on keywords
    
    question_lower = question.lower()
    snippets = []
    
    # SQL Injection knowledge
    if "sql" in question_lower or "sqli" in question_lower:
        snippets.append({
            "source": "OWASP Top 10 2021",
            "title": "A03:2021 – Injection",
            "content": """SQL Injection là một lỗ hổng bảo mật cho phép kẻ tấn công can thiệp vào các truy vấn SQL mà ứng dụng thực hiện với cơ sở dữ liệu. 

**Cơ chế tấn công:**
- Chèn mã SQL độc hại vào input của ứng dụng
- Bypass authentication: ' OR '1'='1
- Extract data: UNION SELECT
- Modify/delete data: DROP TABLE

**Phòng chống:**
1. Sử dụng Prepared Statements (Parameterized Queries)
2. Stored Procedures
3. Input validation và sanitization
4. Principle of Least Privilege cho database accounts
5. WAF (Web Application Firewall)""",
            "relevance": 0.95
        })
        
        snippets.append({
            "source": "MITRE ATT&CK",
            "title": "T1190 - Exploit Public-Facing Application",
            "content": """SQL Injection thường được phân loại dưới technique T1190 trong MITRE ATT&CK framework.

**Tactics:** Initial Access
**Technique ID:** T1190
**Description:** Adversaries may attempt to exploit weaknesses in Internet-facing applications to gain initial access to systems.""",
            "relevance": 0.88
        })
    
    # XSS knowledge
    elif "xss" in question_lower or "cross-site scripting" in question_lower:
        snippets.append({
            "source": "OWASP Top 10 2021",
            "title": "A03:2021 – Injection (XSS)",
            "content": """Cross-Site Scripting (XSS) cho phép kẻ tấn công chèn JavaScript độc hại vào trang web.

**Các loại XSS:**
1. Reflected XSS: Script được phản chiếu từ request
2. Stored XSS: Script được lưu trữ trong database
3. DOM-based XSS: Script thực thi trong DOM

**Phòng chống:**
1. Output encoding/escaping
2. Content Security Policy (CSP)
3. Input validation
4. HTTPOnly và Secure flags cho cookies
5. X-XSS-Protection header""",
            "relevance": 0.93
        })
    
    # Generic security knowledge
    else:
        snippets.append({
            "source": "OWASP Top 10 2021",
            "title": "Overview",
            "content": """OWASP Top 10 là danh sách 10 rủi ro bảo mật web nghiêm trọng nhất:

A01:2021 – Broken Access Control
A02:2021 – Cryptographic Failures
A03:2021 – Injection
A04:2021 – Insecure Design
A05:2021 – Security Misconfiguration
A06:2021 – Vulnerable and Outdated Components
A07:2021 – Identification and Authentication Failures
A08:2021 – Software and Data Integrity Failures
A09:2021 – Security Logging and Monitoring Failures
A10:2021 – Server-Side Request Forgery (SSRF)""",
            "relevance": 0.70
        })
    
    # Limit to top_k
    snippets = snippets[:top_k]
    
    return json.dumps(snippets, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    # Run the MCP server
    mcp.run()
