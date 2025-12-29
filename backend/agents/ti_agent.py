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
                logger.info(f"✅ Using cached TI data for {ip}")
                logger.debug(f"   Cached data: {str(cached)[:200]}...")
                ti_data.append(cached)
            else:
                ips_to_fetch.append(ip)
        
        # If all IPs are cached, return early
        if not ips_to_fetch:
            logger.info(f"All {len(ips[:10])} IPs found in cache")
            return ti_data
        
        logger.info(f"🔍 Fetching TI data for {len(ips_to_fetch)} new IPs (cached: {len(ti_data)})")
        
        try:
            # Check each IP that's not in cache using unified MCP client
            for ip in ips_to_fetch:
                logger.info(f"🌐 Checking IP: {ip}")
                
                ip_data = {
                    "ip": ip,
                    "abuseipdb": None,
                    "virustotal": None
                }
                
                # Try AbuseIPDB
                try:
                    logger.info(f"   → Calling AbuseIPDB for {ip}...")
                    abuseipdb_result = await self.mcp_client.abuseipdb_check(ip)
                    if abuseipdb_result:
                        logger.info(f"   ✅ AbuseIPDB response: {str(abuseipdb_result)[:200]}...")
                        ip_data["abuseipdb"] = str(abuseipdb_result)
                    else:
                        logger.warning(f"   ⚠️ AbuseIPDB returned None for {ip}")
                except Exception as e:
                    logger.error(f"   ❌ AbuseIPDB check failed for {ip}: {e}", exc_info=True)
                
                # Skip VirusTotal (not needed + API issues)
                # VirusTotal often returns 403 errors and is not essential for IP reputation
                
                # Cache the result
                logger.info(f"💾 Caching TI data for {ip}")
                ti_cache.set(ip, ip_data)
                ti_data.append(ip_data)
        
        except Exception as e:
            logger.error(f"Failed to fetch TI data: {e}", exc_info=True)
            # Return empty data on failure for IPs not yet fetched
            for ip in ips_to_fetch:
                ti_data.append({
                    "ip": ip,
                    "abuseipdb": None,
                    "virustotal": None,
                    "error": str(e)
                })
        
        logger.info(f"[TIAgent] Fetched TI data for {len(ti_data)} IPs total")
        return ti_data
    
    async def _analyze_with_llm(self, ti_raw: list[dict]) -> TISummary:
        """
        Analyze TI data with LLM.
        
        Args:
            ti_raw: Raw TI data from MCP tools
        
        Returns:
            TISummary with analysis results
        """
        # Log raw TI data
        logger.info("=" * 80)
        logger.info("📊 RAW TI DATA TO ANALYZE:")
        for item in ti_raw:
            logger.info(f"  IP: {item.get('ip')}")
            logger.info(f"    AbuseIPDB: {str(item.get('abuseipdb'))[:300] if item.get('abuseipdb') else 'None'}")
            logger.info(f"    VirusTotal: {str(item.get('virustotal'))[:300] if item.get('virustotal') else 'None'}")
        logger.info("=" * 80)
        
        prompt = self._create_prompt(ti_raw)
        
        # Log prompt
        logger.info("📝 LLM PROMPT:")
        logger.info(prompt)
        logger.info("=" * 80)
        
        try:
            logger.info("🤖 Calling LLM for TI analysis...")
            response = await self.llm.ainvoke([HumanMessage(content=prompt)])
            
            # Log full response
            logger.info("📨 LLM RESPONSE:")
            logger.info(f"Response type: {type(response.content)}")
            logger.info(f"Response length: {len(response.content)} chars")
            logger.info(f"Response content:\n{response.content}")
            logger.info("=" * 80)
            
            ti_summary = self._parse_response(response.content)
            
            # Log parsed result
            logger.info("✅ PARSED TI SUMMARY:")
            logger.info(f"  IOCs count: {len(ti_summary.get('iocs', []))}")
            logger.info(f"  Max risk: {ti_summary.get('ti_overall', {}).get('max_risk')}")
            logger.info("=" * 80)
            
            # If parsing succeeded but returned empty iocs, create fallback
            if not ti_summary.get('iocs') and ti_raw:
                logger.warning("⚠️ LLM returned empty iocs, creating fallback from raw data")
                ti_summary = self._create_fallback_summary(ti_raw)
            
            return ti_summary
        
        except Exception as e:
            logger.error(f"❌ LLM analysis failed: {e}", exc_info=True)
            # Return fallback summary with raw data
            return self._create_fallback_summary(ti_raw)
    
    def _create_fallback_summary(self, ti_raw: list[dict]) -> TISummary:
        """
        Create fallback summary from raw TI data when LLM fails.
        
        Args:
            ti_raw: Raw TI data from MCP tools
            
        Returns:
            TISummary with basic analysis
        """
        logger.info("[TIAgent] Creating fallback summary from raw TI data")
        
        iocs = []
        high_risk_ips = []
        max_risk = "low"
        
        for item in ti_raw:
            ip = item.get('ip')
            abuse_score = 0
            total_reports = 0
            risk = "unknown"
            notes = []
            
            # Parse AbuseIPDB data
            abuseipdb_data = item.get('abuseipdb')
            if abuseipdb_data and isinstance(abuseipdb_data, str):
                # Try to extract abuse score and total reports from string
                import re
                score_match = re.search(r'abuse_confidence_score["\s:]+(\d+)', abuseipdb_data)
                if score_match:
                    abuse_score = int(score_match.group(1))
                
                reports_match = re.search(r'total_reports["\s:]+(\d+)', abuseipdb_data)
                if reports_match:
                    total_reports = int(reports_match.group(1))
                
                # Extract country/ISP info
                country_match = re.search(r'country_code["\s:]+["\']([A-Z]{2})["\']', abuseipdb_data)
                isp_match = re.search(r'isp["\s:]+["\']([^"\']+)["\']', abuseipdb_data)
                
                if country_match or isp_match:
                    country = country_match.group(1) if country_match else "Unknown"
                    isp = isp_match.group(1) if isp_match else "Unknown"
                    notes.append(f"Quốc gia: {country}, ISP: {isp}")
            
            # Determine risk level based on abuse_score AND total_reports
            if abuse_score >= 80 or total_reports > 1000:
                risk = "critical"
                max_risk = "critical"
                high_risk_ips.append(ip)
            elif abuse_score >= 50 or total_reports >= 500:
                risk = "high"
                if max_risk not in ["critical"]:
                    max_risk = "high"
                high_risk_ips.append(ip)
            elif abuse_score >= 20 or total_reports >= 100:
                risk = "medium"
                if max_risk not in ["critical", "high"]:
                    max_risk = "medium"
            else:
                risk = "low"
            
            # Build notes
            if abuse_score > 0:
                notes.append(f"AbuseIPDB Score: {abuse_score}/100")
            if total_reports > 0:
                notes.append(f"Tổng báo cáo: {total_reports}")
            if not notes:
                notes.append("Không có dữ liệu threat intelligence")
            
            iocs.append({
                'ip': ip,
                'risk': risk,
                'abuse_score': abuse_score,
                'total_reports': total_reports,
                'notes': " | ".join(notes)
            })
        
        return TISummary(
            iocs=iocs,
            ti_overall={
                "max_risk": max_risk,
                "high_risk_iocs": high_risk_ips,
                "notes": f"Phân tích {len(iocs)} IP (fallback mode - LLM parse failed)"
            }
        )
    
    def _create_prompt(self, ti_raw: list[dict]) -> str:
        """Create analysis prompt for LLM in Vietnamese."""
        prompt = """Bạn là chuyên gia phân tích threat intelligence. Phân tích dữ liệu IOC từ AbuseIPDB.

Đánh giá mức độ rủi ro cho mỗi IP dựa trên:
- AbuseIPDB abuse confidence score (0-100) - mức độ tin cậy IP độc hại
- AbuseIPDB total_reports - số lần bị báo cáo (QUAN TRỌNG!)
- Thông tin quốc gia/ISP
- Usage type (Data Center/Hosting thường đáng ngờ)
- Thời gian báo cáo gần nhất (last_reported_at)

Phân loại rủi ro (QUAN TRỌNG - tuân thủ chính xác):
- critical: Abuse score >= 80 HOẶC total_reports > 1000
- high: Abuse score 50-79 HOẶC total_reports 500-1000
- medium: Abuse score 20-49 HOẶC total_reports 100-499
- low: Abuse score < 20 và total_reports < 100

LƯU Ý QUAN TRỌNG:
- total_reports > 100 → KHÔNG THỂ là "low" risk
- total_reports > 500 → tối thiểu là "high" risk
- Data Center/Web Hosting/Transit → thường là proxy/VPN/botnet
- last_reported_at trong vài ngày gần đây → tăng mức độ nguy hiểm
- Nếu abuse_score = 0 nhưng total_reports cao → vẫn đáng ngờ!

ĐỊNH DẠNG OUTPUT:
QUAN TRỌNG: Trả về CHÍNH XÁC pure JSON, KHÔNG có markdown, KHÔNG có code blocks, KHÔNG có giải thích.
Bắt đầu trực tiếp bằng { và kết thúc bằng }
TẤT CẢ các trường "notes" PHẢI viết bằng TIẾNG VIỆT.

Ví dụ:
{
  "iocs": [
    {
      "ip": "185.241.208.170",
      "risk": "high",
      "abuse_score": 0,
      "total_reports": 563,
      "notes": "IP đáng ngờ với 563 báo cáo từ AbuseIPDB (mặc dù confidence score = 0). Từ Data Center/Web Hosting tại Ba Lan (1337 Services GmbH). Báo cáo gần nhất: 2025-12-20. Khuyến nghị theo dõi và cân nhắc chặn."
    }
  ],
  "ti_overall": {
    "max_risk": "high",
    "high_risk_iocs": ["185.241.208.170"],
    "notes": "Phát hiện 1 IP có mức độ nguy hiểm cao với 563 báo cáo từ AbuseIPDB."
  }
}

DO NOT wrap in markdown code blocks. Return pure JSON only.

IOC Data:
"""
        
        for item in ti_raw:
            prompt += f"\n\nIP: {item['ip']}"
            if item.get('abuseipdb'):
                prompt += f"\nAbuseIPDB: {item['abuseipdb']}"
            if item.get('error'):
                prompt += f"\nError: {item['error']}"
        
        return prompt
    
    def _parse_response(self, response_content: str) -> TISummary:
        """Parse LLM response into TISummary."""
        content = response_content.strip()
        
        logger.info("🔍 PARSING LLM RESPONSE:")
        logger.info(f"  Original length: {len(response_content)} chars")
        logger.info(f"  After strip: {len(content)} chars")
        logger.info(f"  First 100 chars: {content[:100]}")
        
        # Handle markdown code blocks with various formats
        if '```json' in content:
            # Extract content between ```json and ```
            start = content.find('```json') + 7
            end = content.find('```', start)
            if end != -1:
                content = content[start:end]
                logger.info(f"  Extracted from ```json block: {len(content)} chars")
        elif content.startswith('```'):
            content = content[3:]
            if content.endswith('```'):
                content = content[:-3]
            logger.info(f"  Removed ``` markers: {len(content)} chars")
        elif content.endswith('```'):
            content = content[:-3]
            logger.info(f"  Removed trailing ```: {len(content)} chars")
        
        content = content.strip()
        
        # Check if content is empty
        if not content:
            logger.error("❌ LLM returned EMPTY response after processing")
            logger.error(f"   Original response_content: '{response_content}'")
            return TISummary(
                iocs=[],
                ti_overall={
                    "max_risk": "medium",
                    "high_risk_iocs": [],
                    "notes": "LLM returned empty response"
                }
            )
        
        logger.info(f"  Final content to parse ({len(content)} chars):")
        logger.info(f"  {content[:500]}")
        
        try:
            data = json.loads(content)
            logger.info(f"✅ JSON parsed successfully: {len(data.get('iocs', []))} IOCs")
            return TISummary(
                iocs=data.get('iocs', []),
                ti_overall=data.get('ti_overall', {
                    "max_risk": "medium",
                    "high_risk_iocs": [],
                    "notes": "Analysis completed"
                })
            )
        except json.JSONDecodeError as e:
            logger.error(f"❌ JSON PARSE ERROR: {e}")
            logger.error(f"   Error at line {e.lineno}, column {e.colno}")
            logger.error(f"   Content that failed (first 1000 chars):\n{content[:1000]}")
            return TISummary(
                iocs=[],
                ti_overall={
                    "max_risk": "medium",
                    "high_risk_iocs": [],
                    "notes": f"Parse error: {str(e)}"
                }
            )
