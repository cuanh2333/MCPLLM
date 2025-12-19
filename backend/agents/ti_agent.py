"""
V2: Threat Intelligence Agent

Analyzes IOCs (IP addresses, domains) using external threat intelligence sources
like AbuseIPDB and VirusTotal via MCP tools.
"""

import json
import logging
from typing import Optional

from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage

from backend.models import TISummary, Event, EventLabel
from backend.services.unified_mcp_client import get_unified_client


logger = logging.getLogger(__name__)


class TIAgent:
    """
    Threat Intelligence Agent for IOC analysis.
    
    Fetches threat intelligence data from AbuseIPDB and VirusTotal,
    then uses LLM to analyze and summarize the findings.
    """
    
    def __init__(self, llm: ChatGroq, mcp_server_path: str = None):
        """
        Initialize TIAgent.
        
        Args:
            llm: ChatGroq LLM instance
            mcp_server_path: Path to MCP server script (deprecated, using unified client)
        """
        self.llm = llm
        self.mcp_client = get_unified_client()
        logger.info("TIAgent initialized with unified MCP client")
    
    async def analyze(
        self,
        events: list[Event],
        labels: dict[str, EventLabel]
    ) -> TISummary:
        """
        Analyze IOCs from attack events.
        
        Args:
            events: List of all events
            labels: Event labels with attack classifications
        
        Returns:
            TISummary with IOC analysis and overall assessment
        """
        logger.info("Starting TI analysis")
        
        # Extract attack IPs
        attack_ips = self._extract_attack_ips(events, labels)
        logger.info(f"Extracted {len(attack_ips)} unique attack IPs")
        
        if not attack_ips:
            logger.info("No attack IPs to analyze")
            return TISummary(
                iocs=[],
                ti_overall={
                    "max_risk": "low",
                    "high_risk_iocs": [],
                    "notes": "No attack IPs detected"
                }
            )
        
        # Load asset info and filter business IPs
        from backend.services.asset_manager import get_asset_manager
        asset_manager = get_asset_manager()
        # AssetManager loads on init, no need to call load_assets()
        
        # Separate business IPs from external IPs
        # Check if method exists, otherwise use empty list
        if hasattr(asset_manager, 'is_business_ip'):
            business_ips = [ip for ip in attack_ips if asset_manager.is_business_ip(ip)]
        else:
            business_ips = []
        
        if hasattr(asset_manager, 'filter_external_ips'):
            external_ips = asset_manager.filter_external_ips(attack_ips)
        else:
            external_ips = attack_ips  # All IPs are external if no filter
        
        if business_ips:
            logger.info(f"Found {len(business_ips)} business IPs (likely simulated attacks)")
            for ip in business_ips:
                asset_info = asset_manager.get_asset_info(ip)
                logger.info(f"  - {ip}: {asset_info.get('description', 'Unknown')}")
        
        if not external_ips:
            logger.info("All attack IPs are business IPs (simulated attacks)")
            return TISummary(
                iocs=[],
                ti_overall={
                    "max_risk": "low",
                    "high_risk_iocs": [],
                    "notes": f"All {len(business_ips)} attack IPs are internal business IPs (simulated attacks)"
                }
            )
        
        logger.info(f"Analyzing {len(external_ips)} external IPs (real threats)")
        
        # Fetch TI data from MCP (only for external IPs)
        ti_raw = await self._fetch_ti_data(external_ips)
        logger.info(f"Fetched TI data for {len(ti_raw)} external IPs")
        
        # Analyze with LLM
        ti_summary = await self._analyze_with_llm(ti_raw)
        logger.info("TI analysis complete")
        
        return ti_summary
    
    async def analyze_ips(self, ips: list[str]) -> TISummary:
        """
        Analyze IP addresses directly (for IP reputation queries).
        
        This is a simplified version that doesn't require events/labels.
        Used for standalone IP reputation checks.
        
        Args:
            ips: List of IP addresses to analyze
            
        Returns:
            TISummary with IOC analysis
        """
        logger.info(f"[TIAgent] Analyzing {len(ips)} IPs directly")
        
        if not ips:
            return TISummary(
                iocs=[],
                ti_overall={
                    "max_risk": "low",
                    "high_risk_iocs": [],
                    "notes": "No IPs provided"
                }
            )
        
        # Fetch TI data from MCP
        ti_raw = await self._fetch_ti_data(ips)
        logger.info(f"[TIAgent] Fetched TI data for {len(ti_raw)} IPs")
        
        # Analyze with LLM
        ti_summary = await self._analyze_with_llm(ti_raw)
        logger.info("[TIAgent] IP analysis complete")
        
        return ti_summary
    
    def _extract_attack_ips(
        self,
        events: list[Event],
        labels: dict[str, EventLabel]
    ) -> list[str]:
        """Extract unique IP addresses from attack events."""
        attack_ips = set()
        
        for event in events:
            event_id = event['event_id']
            if event_id in labels and labels[event_id]['is_attack']:
                if event['src_ip']:
                    attack_ips.add(event['src_ip'])
        
        return list(attack_ips)
    
    async def _fetch_ti_data(self, ips: list[str]) -> list[dict]:
        """
        Fetch threat intelligence data from MCP tools with caching.
        
        Args:
            ips: List of IP addresses to check
        
        Returns:
            List of TI data for each IP
        """
        from backend.utils.ti_cache import get_ti_cache
        
        ti_cache = get_ti_cache(ttl_hours=24)
        ti_data = []
        ips_to_fetch = []
        
        # Check cache first
        for ip in ips[:10]:  # Limit to 10 IPs
            cached = ti_cache.get(ip)
            if cached:
                logger.info(f"Using cached TI data for {ip}")
                ti_data.append(cached)
            else:
                ips_to_fetch.append(ip)
        
        # If all IPs are cached, return early
        if not ips_to_fetch:
            logger.info(f"All {len(ips[:10])} IPs found in cache")
            return ti_data
        
        logger.info(f"Fetching TI data for {len(ips_to_fetch)} new IPs (cached: {len(ti_data)})")
        
        try:
            # Check each IP that's not in cache using unified MCP client
            for ip in ips_to_fetch:
                logger.info(f"Checking IP: {ip}")
                
                ip_data = {
                    "ip": ip,
                    "abuseipdb": None,
                    "virustotal": None
                }
                
                # Try AbuseIPDB
                try:
                    abuseipdb_result = await self.mcp_client.abuseipdb_check(ip)
                    if abuseipdb_result:
                        ip_data["abuseipdb"] = str(abuseipdb_result)
                except Exception as e:
                    logger.warning(f"AbuseIPDB check failed for {ip}: {e}")
                
                # Try VirusTotal
                try:
                    vt_result = await self.mcp_client.virustotal_ip(ip)
                    if vt_result:
                        ip_data["virustotal"] = str(vt_result)
                except Exception as e:
                    logger.warning(f"VirusTotal check failed for {ip}: {e}")
                
                # Cache the result
                ti_cache.set(ip, ip_data)
                ti_data.append(ip_data)
        
        except Exception as e:
            logger.error(f"Failed to fetch TI data: {e}")
            # Return empty data on failure for IPs not yet fetched
            for ip in ips_to_fetch:
                ti_data.append({
                    "ip": ip,
                    "abuseipdb": None,
                    "virustotal": None,
                    "error": str(e)
                })
        
        logger.info(f"[TIAgent] Fetched TI data for {len(ti_data)} IPs")
        return ti_data
    
    async def _analyze_with_llm(self, ti_raw: list[dict]) -> TISummary:
        """
        Analyze TI data with LLM.
        
        Args:
            ti_raw: Raw TI data from MCP tools
        
        Returns:
            TISummary with analysis results
        """
        prompt = self._create_prompt(ti_raw)
        
        try:
            response = await self.llm.ainvoke([HumanMessage(content=prompt)])
            ti_summary = self._parse_response(response.content)
            return ti_summary
        
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            # Return default summary on failure
            return TISummary(
                iocs=[{"ip": item["ip"], "risk": "unknown"} for item in ti_raw],
                ti_overall={
                    "max_risk": "medium",
                    "high_risk_iocs": [],
                    "notes": f"TI analysis failed: {str(e)}"
                }
            )
    
    def _create_prompt(self, ti_raw: list[dict]) -> str:
        """Create analysis prompt for LLM in Vietnamese."""
        prompt = """Bạn là chuyên gia phân tích threat intelligence. Phân tích dữ liệu IOC từ AbuseIPDB và VirusTotal.

Đánh giá mức độ rủi ro cho mỗi IP dựa trên:
- AbuseIPDB abuse confidence score (0-100)
- VirusTotal detection ratio
- Hoạt động độc hại đã báo cáo
- Thông tin quốc gia/ISP

Phân loại rủi ro (QUAN TRỌNG - tuân thủ chính xác):
- critical: Abuse score >= 80 HOẶC VT detections > 5
- high: Abuse score 50-79 HOẶC VT detections 3-5
- medium: Abuse score 20-49 HOẶC VT detections 1-2
- low: Abuse score < 20 và không có VT detections

ĐỊNH DẠNG OUTPUT:
QUAN TRỌNG: Trả về CHÍNH XÁC pure JSON, KHÔNG có markdown, KHÔNG có code blocks, KHÔNG có giải thích.
Bắt đầu trực tiếp bằng { và kết thúc bằng }
TẤT CẢ các trường "notes" PHẢI viết bằng TIẾNG VIỆT.

Ví dụ (với notes tiếng Việt):
{
  "iocs": [
    {
      "ip": "103.232.122.33",
      "risk": "critical",
      "abuse_score": 100,
      "vt_detections": 0,
      "notes": "IP độc hại cao, được báo cáo 712 lần cho hoạt động Data Center/Web Hosting/Transit từ VHOST CO., LTD tại Việt Nam"
    }
  ],
  "ti_overall": {
    "max_risk": "critical",
    "high_risk_iocs": ["103.232.122.33"],
    "notes": "Phát hiện 1 IP có mức độ nguy hiểm cao (critical). Khuyến nghị chặn ngay lập tức."
  }
}

DO NOT wrap in markdown code blocks. Return pure JSON only.

IOC Data:
"""
        
        for item in ti_raw:
            prompt += f"\n\nIP: {item['ip']}"
            if item.get('abuseipdb'):
                prompt += f"\nAbuseIPDB: {item['abuseipdb']}"
            if item.get('virustotal'):
                prompt += f"\nVirusTotal: {item['virustotal']}"
            if item.get('error'):
                prompt += f"\nError: {item['error']}"
        
        return prompt
    
    def _parse_response(self, response_content: str) -> TISummary:
        """Parse LLM response into TISummary."""
        content = response_content.strip()
        
        # Handle markdown code blocks with various formats
        if '```json' in content:
            # Extract content between ```json and ```
            start = content.find('```json') + 7
            end = content.find('```', start)
            if end != -1:
                content = content[start:end]
        elif content.startswith('```'):
            content = content[3:]
            if content.endswith('```'):
                content = content[:-3]
        elif content.endswith('```'):
            content = content[:-3]
        
        content = content.strip()
        
        try:
            data = json.loads(content)
            return TISummary(
                iocs=data.get('iocs', []),
                ti_overall=data.get('ti_overall', {
                    "max_risk": "medium",
                    "high_risk_iocs": [],
                    "notes": "Analysis completed"
                })
            )
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse TI response: {e}")
            return TISummary(
                iocs=[],
                ti_overall={
                    "max_risk": "medium",
                    "high_risk_iocs": [],
                    "notes": f"Parse error: {str(e)}"
                }
            )
