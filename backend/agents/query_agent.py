"""
Query Agent for V1 Log Analyzer
Parses user natural language queries and determines log source parameters
"""
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import logging

from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage

logger = logging.getLogger(__name__)


class QueryAgent:
    """
    Agent that understands user queries and determines appropriate log source.
    
    Examples:
    - "1 giờ qua có tấn công không?" → Splunk query with earliest=-1h
    - "Phân tích file access.log" → File source
    - "Hôm nay có SQL injection không?" → Splunk query with earliest=@d
    """
    
    def __init__(self, llm: ChatGroq):
        self.llm = llm
    
    async def parse_query(self, user_query: str, default_source: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Parse user query to determine log source and parameters.
        
        Args:
            user_query: Natural language query from user
            default_source: Default log source if query doesn't specify
        
        Returns:
            Dictionary with:
            - source_type: "splunk" or "file" or "knowledge"
            - log_source: Configuration for the source (None for knowledge queries)
            - parsed_intent: Extracted intent from query
            - enable_genrule: True if user wants detection rules (NEW)
        """
        logger.info(f"Parsing user query: {user_query}")
        
        # FIRST: Check if this is IP reputation query
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', user_query)
        if ip_match and any(kw in user_query.lower() for kw in ["kiểm tra", "check", "độc hại", "malicious", "reputation", "abuse"]):
            # Extract all IPs from query
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', user_query)
            logger.info(f"Detected IP reputation query for {len(ips)} IPs")
            return {
                "source_type": "ip_reputation",
                "log_source": None,
                "parsed_intent": {
                    "source": "ip_reputation",
                    "query_type": "ip_reputation",
                    "ips": ips
                },
                "enable_genrule": False
            }
        
        # SECOND: Check if this is a knowledge query (no log analysis needed)
        if self._is_knowledge_query(user_query):
            logger.info("Detected knowledge query (no log source needed)")
            return {
                "source_type": "knowledge",
                "log_source": None,  # No log source for knowledge queries
                "parsed_intent": {
                    "source": "knowledge",
                    "query_type": "knowledge"
                },
                "enable_genrule": False  # No rules for knowledge queries
            }
        
        # SECOND: Check if user wants detection rules
        wants_genrule = self._wants_detection_rules(user_query)
        wants_generic_rule = self._wants_generic_rule(user_query)
        
        if wants_genrule:
            logger.info("User wants detection rules (enable_genrule=True)")
        if wants_generic_rule:
            logger.info("User wants GENERIC rule (no specific log needed)")
        
        # Check if query mentions a file
        file_match = self._extract_file_path(user_query)
        if file_match:
            logger.info(f"Detected file source: {file_match}")
            return {
                "source_type": "file",
                "log_source": {
                    "type": "file",
                    "path": file_match
                },
                "parsed_intent": {
                    "source": "file",
                    "filepath": file_match
                },
                "enable_genrule": wants_genrule  # Auto-detect from query
            }
        
        # Check for time-based queries (Splunk)
        time_intent = self._extract_time_intent(user_query)
        if time_intent:
            logger.info(f"Detected time-based query: {time_intent}")
            
            # Use LLM to extract more details
            splunk_params = await self._build_splunk_query(user_query, time_intent)
            
            return {
                "source_type": "splunk",
                "log_source": splunk_params,
                "parsed_intent": time_intent,
                "enable_genrule": wants_genrule  # Auto-detect from query
            }
        
        # Default: use provided default_source or assume file
        if default_source:
            logger.info("Using default source")
            return {
                "source_type": default_source.get("type", "file"),
                "log_source": default_source,
                "parsed_intent": {"source": "default"},
                "enable_genrule": wants_genrule  # Auto-detect from query
            }
        
        # Special case: User wants GENERIC rule without specific log
        if wants_generic_rule:
            logger.info("User wants generic rule → treating as knowledge query with rule generation")
            return {
                "source_type": "generic_rule",  # Special type
                "log_source": None,
                "parsed_intent": {
                    "source": "generic_rule",
                    "query_type": "generic_rule_generation"
                },
                "enable_genrule": True  # Enable rule generation
            }
        
        # Fallback: ask LLM to determine
        logger.info("Using LLM to determine source")
        result = await self._llm_parse_query(user_query)
        result["enable_genrule"] = wants_genrule  # Auto-detect from query
        return result
    
    def _is_knowledge_query(self, query: str) -> bool:
        """
        Check if query is asking for knowledge/information rather than log analysis.
        
        Knowledge queries typically ask "what is X?" or "how to prevent Y?"
        without mentioning specific logs or time ranges.
        """
        query_lower = query.lower()
        
        # IP reputation query indicators
        ip_reputation_indicators = [
            "ip", "kiểm tra ip", "check ip", "reputation",
            "độc hại", "malicious", "abuse", "threat",
            "có độc hại không", "is malicious"
        ]
        
        # Check if asking about IP reputation
        has_ip_query = any(ind in query_lower for ind in ip_reputation_indicators)
        has_ip_address = bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', query))
        
        if has_ip_query and has_ip_address:
            # This is IP reputation query, not knowledge query
            return False
        
        # Knowledge query indicators (questions about concepts)
        knowledge_indicators = [
            "là gì", "what is", "explain", "giải thích",
            "hướng dẫn", "guide", "tutorial", "cách thức",
            "các bước", "quy trình", "process", "procedure",
            "xử lý", "ứng phó", "respond", "handle", "incident response",
            "cách phòng chống", "làm thế nào để phòng chống", "làm sao để phòng chống",
            "how to prevent", "how to defend", "how to mitigate",
            "phòng thủ", "defense", "mitigation", "giảm thiểu",
            "best practice", "khuyến nghị", "recommend",
            "tell me about", "cho tôi biết về",
            "technique", "mitre", "owasp",
            # Asset-related queries
            "ip nghiệp vụ", "business ip", "danh sách server", "server list",
            "máy chủ", "database server", "web server", "production server",
            "infrastructure", "cơ sở hạ tầng", "tài sản", "asset",
            "ip pentest", "ip máy pentest", "pentest ip", "ip tấn công",
            "ip của tôi", "ip của hệ thống", "bên hệ thống", "trong hệ thống",
            "thông tin về", "information about", "cho biết", "liệt kê"
        ]
        
        # Log analysis indicators (mentions of logs or time)
        log_indicators = [
            "phân tích", "analyze", "check log", "kiểm tra log",
            "có tấn công", "có attack", "detect attack", "phát hiện tấn công",
            "giờ qua", "ngày qua", "hôm nay", "hôm qua",
            "last hour", "today", "yesterday",
            ".log", ".txt", "file", "trong log"
        ]
        
        has_knowledge_indicator = any(ind in query_lower for ind in knowledge_indicators)
        has_log_indicator = any(ind in query_lower for ind in log_indicators)
        
        # If has knowledge indicators but NO log indicators → knowledge query
        if has_knowledge_indicator and not has_log_indicator:
            return True
        
        return False
    
    def _wants_detection_rules(self, query: str) -> bool:
        """
        Check if user wants detection rules generated.
        
        Detects keywords like "tạo rule", "generate rule", "detection rule", etc.
        """
        query_lower = query.lower()
        
        # Detection rule keywords (Vietnamese + English)
        rule_keywords = [
            # Vietnamese
            "tạo rule", "tạo rules", "tạo detection rule",
            "viết rule", "viết rules",
            "generate rule", "sinh rule",
            "detection rule", "detection rules",
            
            # English
            "create rule", "create rules",
            "write rule", "write rules", 
            "generate rule", "generate rules",
            "sigma rule", "splunk rule", "spl rule",
            "detection logic", "detection query",
            
            # Specific formats
            "sigma", "spl", "aql",
            "qradar rule", "siem rule"
        ]
        
        # Check if any keyword is in query
        for keyword in rule_keywords:
            if keyword in query_lower:
                return True
        
        return False
    
    def _wants_generic_rule(self, query: str) -> bool:
        """
        Check if user wants GENERIC rule (without specific log analysis).
        
        Examples:
        - "Tạo Sigma rule cho SQL injection"
        - "Generate detection rule for XSS"
        - "Write Splunk rule for command injection"
        
        These queries want rules based on attack TYPE, not specific logs.
        """
        query_lower = query.lower()
        
        # Must have rule keyword
        if not self._wants_detection_rules(query_lower):
            return False
        
        # Must mention attack type
        attack_types = [
            "sql injection", "sqli", "sql inject",
            "xss", "cross-site scripting",
            "lfi", "local file inclusion",
            "rfi", "remote file inclusion", 
            "rce", "remote code execution",
            "command injection", "cmd injection",
            "xxe", "xml external entity",
            "path traversal", "directory traversal",
            "csrf", "cross-site request forgery",
            "ssrf", "server-side request forgery"
        ]
        
        has_attack_type = any(attack in query_lower for attack in attack_types)
        
        # Must NOT mention specific log source
        log_indicators = [
            ".log", ".txt", "file", "access.log", "error.log",
            "phân tích", "analyze", "check log",
            "giờ qua", "ngày qua", "hôm nay",
            "last hour", "today", "yesterday"
        ]
        
        has_log_source = any(indicator in query_lower for indicator in log_indicators)
        
        # Generic rule = wants rule + has attack type + NO log source
        return has_attack_type and not has_log_source
    
    def _extract_file_path(self, query: str) -> Optional[str]:
        """Extract file path from query"""
        # Look for common file patterns
        patterns = [
            r'file\s+([^\s]+\.(?:log|txt))',
            r'([^\s]+\.(?:log|txt))',
            r'phân tích\s+file\s+([^\s]+)',  # "phân tích file access.log"
            r'phân tích\s+([^\s]+\.(?:log|txt))',  # "phân tích access.log"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, query, re.IGNORECASE)
            if match:
                filepath = match.group(1)
                # If matched "log file" without extension, default to access.log
                if filepath == "log" or filepath == "file":
                    return "access.log"
                return filepath
        
        # REMOVED: Don't fallback to access.log if query has time indicators
        # Let _extract_time_intent() handle time-based queries
        
        return None
    
    def _extract_time_intent(self, query: str) -> Optional[Dict[str, Any]]:
        """Extract time-based intent from query"""
        query_lower = query.lower()
        
        # Time patterns
        time_patterns = {
            # Vietnamese
            r'(\d+)\s*giờ\s*qua': lambda m: {'hours': int(m.group(1))},
            r'(\d+)\s*phút\s*qua': lambda m: {'minutes': int(m.group(1))},
            r'(\d+)\s*ngày\s*qua': lambda m: {'days': int(m.group(1))},
            r'hôm\s*nay': lambda m: {'today': True},
            r'hôm\s*qua': lambda m: {'yesterday': True},
            r'tuần\s*này': lambda m: {'this_week': True},
            
            # English
            r'last\s+(\d+)\s+hours?': lambda m: {'hours': int(m.group(1))},
            r'last\s+(\d+)\s+minutes?': lambda m: {'minutes': int(m.group(1))},
            r'last\s+(\d+)\s+days?': lambda m: {'days': int(m.group(1))},
            r'today': lambda m: {'today': True},
            r'yesterday': lambda m: {'yesterday': True},
            r'this\s+week': lambda m: {'this_week': True},
        }
        
        for pattern, extractor in time_patterns.items():
            match = re.search(pattern, query_lower)
            if match:
                return extractor(match)
        
        return None
    
    async def _build_splunk_query(self, user_query: str, time_intent: Dict) -> Dict[str, Any]:
        """Build Splunk query parameters from time intent"""
        
        # Calculate time range
        now = datetime.now()
        
        if 'hours' in time_intent:
            earliest = now - timedelta(hours=time_intent['hours'])
            earliest_str = f"-{time_intent['hours']}h"
        elif 'minutes' in time_intent:
            earliest = now - timedelta(minutes=time_intent['minutes'])
            earliest_str = f"-{time_intent['minutes']}m"
        elif 'days' in time_intent:
            earliest = now - timedelta(days=time_intent['days'])
            earliest_str = f"-{time_intent['days']}d"
        elif time_intent.get('today'):
            earliest_str = "@d"  # Start of today
        elif time_intent.get('yesterday'):
            earliest_str = "-1d@d"  # Start of yesterday
        elif time_intent.get('this_week'):
            earliest_str = "@w1"  # Start of week (Monday)
        else:
            earliest_str = "-1h"  # Default: last hour
        
        # Use LLM to extract attack type focus
        attack_focus = await self._extract_attack_focus(user_query)
        
        # Build Splunk query
        splunk_query = {
            "type": "splunk",
            "index": "web_iis",  # Default index
            "sourcetype": "modsec:dvwa",  # Default sourcetype
            "earliest_time": earliest_str,
            "latest_time": "now",
            "search_filter": attack_focus.get("search_filter", "")
        }
        
        logger.info(f"Built Splunk query: {splunk_query}")
        return splunk_query
    
    async def _extract_attack_focus(self, user_query: str) -> Dict[str, str]:
        """Use LLM to extract attack type focus from query"""
        
        prompt = f"""Analyze this security question and extract the attack type focus.

Question: "{user_query}"

If the question asks about specific attack types, return a Splunk search filter.
Otherwise, return empty string.

Attack type keywords:
- SQL injection: "UNION" OR "SELECT" OR "INSERT" OR "DROP"
- XSS: "<script>" OR "onerror=" OR "onload="
- File upload: "upload" OR "filename="
- Command injection: "cmd=" OR "exec" OR "system"

Return ONLY JSON:
{{"search_filter": "keyword1 OR keyword2", "attack_types": ["sqli", "xss"]}}

If no specific attack type mentioned, return:
{{"search_filter": "", "attack_types": []}}
"""
        
        try:
            response = await self.llm.ainvoke([HumanMessage(content=prompt)])
            content = response.content.strip()
            
            # Remove markdown
            if content.startswith('```json'):
                content = content[7:]
            elif content.startswith('```'):
                content = content[3:]
            if content.endswith('```'):
                content = content[:-3]
            
            import json
            result = json.loads(content.strip())
            return result
        
        except Exception as e:
            logger.warning(f"Failed to extract attack focus: {e}")
            return {"search_filter": "", "attack_types": []}
    
    async def _llm_parse_query(self, user_query: str) -> Dict[str, Any]:
        """Use LLM to parse query when pattern matching fails"""
        
        # Get default index and sourcetype from environment
        import os
        default_index = os.getenv("SPLUNK_INDEX", "hf")
        default_sourcetype = os.getenv("SPLUNK_SOURCETYPE", "win_log")
        
        prompt = f"""Parse this user query and determine the log source.

Query: "{user_query}"

Determine:
1. Is this asking about a specific file? (file path mentioned)
2. Is this asking about recent events? (time-based: "1 hour ago", "today", etc.)
3. What time range? (if time-based)

IMPORTANT: 
- For Splunk queries, ALWAYS use these exact values:
  - index: "{default_index}"
  - sourcetype: "{default_sourcetype}"
- DO NOT change index or sourcetype based on query content
- Only extract time range from the query

Return ONLY JSON:
{{
  "source_type": "file" or "splunk",
  "log_source": {{
    "type": "file",
    "path": "filename.log"
  }} or {{
    "type": "splunk",
    "index": "{default_index}",
    "sourcetype": "{default_sourcetype}",
    "earliest_time": "-1h",
    "latest_time": "now"
  }}
}}
"""
        
        try:
            response = await self.llm.ainvoke([HumanMessage(content=prompt)])
            content = response.content.strip()
            
            # Remove markdown
            if content.startswith('```json'):
                content = content[7:]
            elif content.startswith('```'):
                content = content[3:]
            if content.endswith('```'):
                content = content[:-3]
            
            import json
            result = json.loads(content.strip())
            return {
                "source_type": result["source_type"],
                "log_source": result["log_source"],
                "parsed_intent": {"source": "llm_parsed"}
            }
        
        except Exception as e:
            logger.error(f"Failed to parse query with LLM: {e}")
            # Fallback to file source
            return {
                "source_type": "file",
                "log_source": {"type": "file", "path": "access.log"},
                "parsed_intent": {"source": "fallback"}
            }
