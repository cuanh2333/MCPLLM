"""
SupervisorAgent - LLM-based Job Classification

This agent uses LLM to intelligently classify jobs and set workflow flags.
"""

import logging
import json
from typing import Dict, Any, Optional

from langchain_groq import ChatGroq
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage

from backend.config import settings

logger = logging.getLogger(__name__)


class SupervisorAgent:
    """LLM-based supervisor for intelligent workflow decisions."""
    
    def __init__(self, llm=None):
        """Initialize SupervisorAgent.
        
        Args:
            llm: Optional LLM instance. If None, creates default LLM.
        """
        if llm is None:
            # Create default LLM for SupervisorAgent - read from settings
            model = settings.supervisor_agent_model or "llama-3.1-8b-instant"
            temperature = settings.supervisor_agent_temperature or 0.1
            
            self.llm = ChatGroq(
                api_key=settings.groq_api_key,
                model=model,
                temperature=temperature
            )
            logger.info(f"[SupervisorAgent] Initialized with Groq {model}")
        else:
            self.llm = llm
            logger.info("[SupervisorAgent] Initialized with provided LLM")
    
    async def classify_job(
        self,
        user_query: str,
        has_log_source: bool,
        log_source_type: Optional[str]
    ) -> Dict[str, Any]:
        """Classify job type and set initial flags.
        
        Args:
            user_query: User's request
            has_log_source: Whether log source is provided
            log_source_type: Type of log source (file|splunk|cron)
            
        Returns:
            Classification result with job_type and flags
        """
        logger.info("[SupervisorAgent] Classifying job...")
        logger.info(f"  User query: {user_query}")
        logger.info(f"  Has log source: {has_log_source}")
        logger.info(f"  Log source type: {log_source_type}")
        
        try:
            # Build prompt
            prompt = self._build_classify_prompt(user_query, has_log_source, log_source_type)
            
            # Call LLM
            messages = [
                SystemMessage(content="You are a security analysis workflow supervisor. Respond with JSON only."),
                HumanMessage(content=prompt)
            ]
            
            response = await self.llm.ainvoke(messages)
            response_text = response.content.strip()
            
            # Parse JSON response
            # Remove markdown code blocks if present
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            response_text = response_text.strip()
            
            result = json.loads(response_text)
            
            # Validate result
            required_fields = ["job_type", "reasoning", "need_analyze", "need_ti", 
                             "need_genrule", "need_recommend", "need_report", 
                             "need_queryrag", "need_asset"]
            
            for field in required_fields:
                if field not in result:
                    raise ValueError(f"Missing required field: {field}")
            
            logger.info(f"[SupervisorAgent] Classification complete:")
            logger.info(f"  Job type: {result['job_type']}")
            logger.info(f"  Reasoning: {result['reasoning']}")
            
            return result
        
        except Exception as e:
            logger.error(f"[SupervisorAgent] Classification failed: {e}", exc_info=True)
            logger.warning("[SupervisorAgent] Falling back to rule-based classification")
            
            # Fallback to rule-based classification
            return self._rule_based_classification(user_query, has_log_source, log_source_type)
    
    def parse_time_range(self, user_query: str) -> Optional[Dict[str, str]]:
        """Parse time range from user query.
        
        Detects patterns like:
        - "1 giờ qua", "2 giờ trước" → -1h, -2h
        - "24 giờ qua", "1 ngày qua" → -24h, -1d
        - "30 phút qua" → -30m
        - "1 tuần qua" → -7d
        
        Args:
            user_query: User's request
            
        Returns:
            Dict with earliest_time and latest_time, or None if no time range detected
        """
        import re
        
        query_lower = user_query.lower()
        
        # Pattern: "X giờ qua/trước"
        hour_match = re.search(r'(\d+)\s*(giờ|hour|h)\s*(qua|trước|ago|past)', query_lower)
        if hour_match:
            hours = int(hour_match.group(1))
            return {
                "earliest_time": f"-{hours}h",
                "latest_time": "now"
            }
        
        # Pattern: "X phút qua/trước"
        minute_match = re.search(r'(\d+)\s*(phút|minute|min|m)\s*(qua|trước|ago|past)', query_lower)
        if minute_match:
            minutes = int(minute_match.group(1))
            return {
                "earliest_time": f"-{minutes}m",
                "latest_time": "now"
            }
        
        # Pattern: "X ngày qua/trước"
        day_match = re.search(r'(\d+)\s*(ngày|day|d)\s*(qua|trước|ago|past)', query_lower)
        if day_match:
            days = int(day_match.group(1))
            return {
                "earliest_time": f"-{days}d",
                "latest_time": "now"
            }
        
        # Pattern: "X tuần qua/trước"
        week_match = re.search(r'(\d+)\s*(tuần|week|w)\s*(qua|trước|ago|past)', query_lower)
        if week_match:
            weeks = int(week_match.group(1))
            days = weeks * 7
            return {
                "earliest_time": f"-{days}d",
                "latest_time": "now"
            }
        
        # Special case: "hôm nay" (today)
        if "hôm nay" in query_lower or "today" in query_lower:
            return {
                "earliest_time": "@d",  # Start of today
                "latest_time": "now"
            }
        
        # Special case: "hôm qua" (yesterday)
        if "hôm qua" in query_lower or "yesterday" in query_lower:
            return {
                "earliest_time": "-1d@d",  # Start of yesterday
                "latest_time": "@d"  # Start of today
            }
        
        logger.info("[SupervisorAgent] No time range detected in query")
        return None
    
    def _build_classify_prompt(
        self,
        user_query: str,
        has_log_source: bool,
        log_source_type: Optional[str]
    ) -> str:
        """Build prompt for job classification.
        
        Args:
            user_query: User's request
            has_log_source: Whether log source is provided
            log_source_type: Type of log source
            
        Returns:
            Prompt string
        """
        return f"""You are a security analysis workflow supervisor.

**User Request:**
- Query: "{user_query}"
- Has log source: {has_log_source}
- Log source type: {log_source_type or "None"}

**Task:**
Classify the job type and set initial workflow flags.

**Job Types (in priority order):**
1. **generic_rule**: User wants to create detection rules (keywords: "tạo rule", "tao rule", "create rule", "Sigma", "SPL", "detection rule", "detect", "phát hiện") - HIGHEST PRIORITY
2. **log_analysis**: User wants to analyze logs (has log_source)
3. **asset_query**: User asks about internal assets/infrastructure (keywords: "IP pentest", "IP máy chủ", "server", "máy chủ", "thiết bị", "tài sản", "asset", "hệ thống", "infrastructure", "nghiệp vụ")
4. **ip_reputation**: User wants to check EXTERNAL IP reputation/threat intelligence (keywords: "check IP", "kiểm tra IP", "độc hại", "malicious", "reputation", "abuse") - ONLY if asking about external/unknown IPs
5. **knowledge_query**: User asks security questions (no log_source, knowledge keywords)

**Output Format (JSON):**
{{
  "job_type": "log_analysis|ip_reputation|knowledge_query|asset_query|generic_rule",
  "reasoning": "Brief explanation of why this classification",
  "need_analyze": true/false,
  "need_ti": true/false,
  "need_genrule": false,
  "need_recommend": true/false,
  "need_report": true/false,
  "need_queryrag": true/false,
  "need_asset": true/false
}}

**Rules:**
- need_genrule is ALWAYS false initially (only enabled by user or post-supervisor)
- log_analysis: need_analyze=true, need_ti=true, need_recommend=true, need_report=true
- asset_query: need_asset=true, all others=false (query internal asset database directly)
- ip_reputation: need_ti=true, all others=false (check external IP reputation)
- knowledge_query: need_queryrag=true, all others=false
- generic_rule: need_queryrag=true, need_genrule=true

**Important:**
- If query asks about "IP pentest", "IP máy chủ", "server của tôi", "hệ thống" → asset_query (internal assets)
- If query asks to "check IP X.X.X.X" for malicious/reputation → ip_reputation (external threat intel)

**Examples:**

Example 1:
Query: "Phân tích log tấn công SQL injection"
Has log source: true
→ job_type: "log_analysis", need_analyze=true, need_ti=true, need_recommend=true, need_report=true

Example 2:
Query: "IP pentest của hệ thống là gì?"
Has log source: false
→ job_type: "asset_query", need_asset=true (query internal asset database)

Example 3:
Query: "Check IP 14.138.31.1 có độc hại không"
Has log source: false
→ job_type: "ip_reputation", need_ti=true (check external threat intelligence)

Example 4:
Query: "SQL injection là gì?"
Has log source: false
→ job_type: "knowledge_query", need_queryrag=true

Example 5:
Query: "Thông tin về server 192.168.1.100"
Has log source: false
→ job_type: "asset_query", need_asset=true

Example 6:
Query: "Tạo Sigma rule cho SQL injection"
Has log source: false
→ job_type: "generic_rule", need_queryrag=true, need_genrule=true

Example 7:
Query: "tạo cho tôi rule detect SQL injection"
Has log source: true (but user wants RULE, not analysis)
→ job_type: "generic_rule", need_queryrag=true, need_genrule=true

**CRITICAL DECISION RULES (CHECK IN ORDER):**

1. **Does query contain rule generation keywords?**
   - Vietnamese: "tạo rule", "tạo cho tôi rule", "viết rule", "sinh rule", "detect", "phát hiện"
   - English: "create rule", "generate rule", "write rule", "detection rule", "Sigma", "SPL"
   - If YES → job_type = "generic_rule" (STOP HERE, ignore has_log_source)

2. **Does query ask about internal assets/infrastructure?**
   - Keywords: "IP pentest", "IP máy chủ", "server", "thiết bị", "tài sản", "hệ thống"
   - If YES → job_type = "asset_query"

3. **Does query ask to check external IP reputation?**
   - Keywords: "check IP", "kiểm tra IP", "độc hại", "malicious", "reputation"
   - If YES → job_type = "ip_reputation"

4. **Does has_log_source = true?**
   - If YES → job_type = "log_analysis"

5. **Otherwise:**
   - job_type = "knowledge_query"

**EXAMPLES OF TRICKY CASES:**

❌ WRONG:
Query: "tạo cho tôi rule detect SQL injection"
has_log_source: true
→ job_type: "log_analysis" (WRONG! User wants RULE, not analysis)

✅ CORRECT:
Query: "tạo cho tôi rule detect SQL injection"
has_log_source: true
→ job_type: "generic_rule" (User explicitly asks for RULE)

**Response (JSON only, no explanation):**"""
    
    def _rule_based_classification(
        self,
        user_query: str,
        has_log_source: bool,
        log_source_type: Optional[str]
    ) -> Dict[str, Any]:
        """Fallback rule-based classification.
        
        Args:
            user_query: User's request
            has_log_source: Whether log source is provided
            log_source_type: Type of log source
            
        Returns:
            Classification result
        """
        logger.info("[SupervisorAgent] Using rule-based classification (fallback)")
        
        if has_log_source:
            # Has log source → log_analysis
            return {
                "job_type": "log_analysis",
                "reasoning": "Has log source → log_analysis (rule-based fallback)",
                "need_analyze": True,
                "need_ti": True,
                "need_genrule": False,
                "need_recommend": True,
                "need_report": True,
                "need_queryrag": False,
                "need_asset": False
            }
        
        # No log source → check query keywords
        query_lower = user_query.lower()
        
        # Check for IP reputation query (PRIORITY)
        import re
        has_ip = bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', query_lower))
        ip_reputation_keywords = ["kiểm tra", "check", "độc hại", "malicious", "reputation", "abuse", "threat"]
        if has_ip and any(kw in query_lower for kw in ip_reputation_keywords):
            return {
                "job_type": "ip_reputation",
                "reasoning": "IP reputation query detected (rule-based fallback)",
                "need_analyze": False,
                "need_ti": True,
                "need_genrule": False,
                "need_recommend": False,
                "need_report": False,
                "need_queryrag": False,
                "need_asset": False
            }
        
        # Check for asset query
        asset_keywords = ["asset", "server", "máy chủ", "ip address", "hostname", "thiết bị", "device"]
        if any(kw in query_lower for kw in asset_keywords):
            return {
                "job_type": "asset_query",
                "reasoning": "Asset keywords detected (rule-based fallback)",
                "need_analyze": False,
                "need_ti": False,
                "need_genrule": False,
                "need_recommend": False,
                "need_report": False,
                "need_queryrag": True,
                "need_asset": True
            }
        
        # Check for generic rule query
        rule_keywords = [
            "tạo rule", "tao rule", "create rule", "generate rule", "viết rule", "viet rule",
            "sigma", "splunk", "spl", "qradar", "aql",
            "detection rule", "rule phát hiện", "rule phat hien", "phát hiện",
            "detect", "detection", "phát hiện tấn công", "phat hien tan cong",
            "sql injection", "xss", "lfi", "rfi", "rce", "xxe",
            "tạo cho tôi", "tao cho toi"  # Vietnamese: "create for me"
        ]
        # Check if query contains rule keywords AND attack type
        has_rule_keyword = any(kw in query_lower for kw in rule_keywords)
        attack_types = ["sql injection", "sqli", "xss", "lfi", "rfi", "rce", "xxe", "command injection"]
        has_attack_type = any(attack in query_lower for attack in attack_types)
        
        if has_rule_keyword or (has_attack_type and "detect" in query_lower):
            return {
                "job_type": "generic_rule",
                "reasoning": "Rule generation keywords detected (rule-based fallback)",
                "need_analyze": False,
                "need_ti": False,
                "need_genrule": True,
                "need_recommend": False,
                "need_report": False,
                "need_queryrag": True,
                "need_asset": False
            }
        
        # Default → knowledge_query
        return {
            "job_type": "knowledge_query",
            "reasoning": "No specific keywords, default to knowledge query (rule-based fallback)",
            "need_analyze": False,
            "need_ti": False,
            "need_genrule": False,
            "need_recommend": False,
            "need_report": False,
            "need_queryrag": True,
            "need_asset": False
        }
