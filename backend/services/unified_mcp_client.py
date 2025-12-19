"""
Unified MCP Client - HTTP client for unified MCP server
Replaces MCP stdio calls with HTTP requests
"""

import httpx
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class UnifiedMCPClient:
    """HTTP client for unified MCP server."""
    
    def __init__(self, base_url: str = "http://127.0.0.1:8001"):
        self.base_url = base_url
        self.timeout = 30.0
    
    async def load_log_file(self, filepath: str, max_lines: Optional[int] = None) -> List[str]:
        """Load logs from a local file via HTTP."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/load_log_file",
                    json={
                        "filepath": filepath,
                        "max_lines": max_lines
                    }
                )
                response.raise_for_status()
                data = response.json()
                return data["lines"]
                
        except Exception as e:
            logger.error(f"Failed to load log file via HTTP: {e}")
            raise
    
    async def splunk_query(
        self,
        index: str = "main",
        sourcetype: str = "access_combined",
        earliest_time: str = "-5m", 
        latest_time: str = "now",
        search_query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Query Splunk via HTTP."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/splunk_query",
                    json={
                        "index": index,
                        "sourcetype": sourcetype,
                        "earliest_time": earliest_time,
                        "latest_time": latest_time,
                        "search_query": search_query
                    }
                )
                response.raise_for_status()
                data = response.json()
                return data["results"]
                
        except Exception as e:
            logger.error(f"Failed to query Splunk via HTTP: {e}")
            raise
    


    async def query_rag(self, query: str, top_k: int = 5, alpha: float = 0.55) -> Dict[str, Any]:
        """Query RAG knowledge base via HTTP."""
        try:
            # Use longer timeout for RAG queries (may need to initialize)
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{self.base_url}/query_rag",
                    json={
                        "query": query,
                        "top_k": top_k,
                        "alpha": alpha
                    }
                )
                response.raise_for_status()
                return response.json()
                
        except Exception as e:
            logger.error(f"Failed to query RAG via HTTP: {e}")
            raise
    
    async def abuseipdb_check(self, ip_address: str) -> Dict[str, Any]:
        """Check IP reputation via AbuseIPDB."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/abuseipdb_check",
                    json={"ip_address": ip_address}
                )
                response.raise_for_status()
                data = response.json()
                return data["result"]
                
        except Exception as e:
            logger.error(f"Failed to check AbuseIPDB via HTTP: {e}")
            raise
    
    async def virustotal_ip(self, ip_address: str) -> Dict[str, Any]:
        """Check IP reputation via VirusTotal."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/virustotal_ip",
                    json={"ip_address": ip_address}
                )
                response.raise_for_status()
                data = response.json()
                return data["result"]
                
        except Exception as e:
            logger.error(f"Failed to check VirusTotal via HTTP: {e}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Check server health."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.base_url}/health")
                response.raise_for_status()
                return response.json()
                
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            raise

# Global client instance
_unified_client = None

def get_unified_client() -> UnifiedMCPClient:
    """Get global unified MCP client instance."""
    global _unified_client
    if _unified_client is None:
        _unified_client = UnifiedMCPClient()
    return _unified_client