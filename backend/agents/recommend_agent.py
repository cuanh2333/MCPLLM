"""
V2: Recommendation Agent

Generates actionable security recommendations based on findings and TI analysis.
"""

import json
import logging

from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage

from backend.models import RecommendSummary, FindingsSummary, TISummary
from backend.agents.queryrag_agent import get_queryrag_agent


logger = logging.getLogger(__name__)


class RecommendAgent:
    """
    Recommendation Agent for security playbook generation.
    
    Analyzes findings and TI data to generate immediate, short-term,
    and long-term security recommendations.
    """
    
    def __init__(self, llm: ChatGroq):
        """
        Initialize RecommendAgent.
        
        Args:
            llm: ChatGroq LLM instance
        """
        self.llm = llm
        logger.info("RecommendAgent initialized")
    
    async def generate(
        self,
        findings_summary: FindingsSummary,
        ti_summary: TISummary
    ) -> RecommendSummary:
        """
        Generate security recommendations using RAG knowledge base.
        
        Args:
            findings_summary: Analysis findings summary
            ti_summary: Threat intelligence summary
        
        Returns:
            RecommendSummary with actionable recommendations from RAG
        """
        logger.info("Generating recommendations using RAG knowledge base")
        
        # Query RAG for incident response playbook
        rag_recommendations = await self._query_rag_for_recommendations(findings_summary, ti_summary)
        
        prompt = self._create_prompt(findings_summary, ti_summary, rag_recommendations)
        
        try:
            response = await self.llm.ainvoke([HumanMessage(content=prompt)])
            recommend_summary = self._parse_response(response.content)
            
            logger.info("Recommendations generated successfully with RAG knowledge")
            return recommend_summary
        
        except Exception as e:
            logger.error(f"Failed to generate recommendations: {e}")
            # Return default recommendations on failure (Vietnamese)
            return RecommendSummary(
                severity_overall=findings_summary['severity_level'],
                immediate_actions=[
                    "Chặn các IP tấn công tại firewall",
                    "Rà soát các sự kiện tấn công trong file CSV đã xuất",
                    "Giám sát các hệ thống bị ảnh hưởng để phát hiện hoạt động đáng ngờ"
                ],
                short_term_actions=[
                    "Cập nhật WAF rules để chặn các pattern tấn công đã phát hiện",
                    "Vá lỗi các hệ thống có lỗ hổng",
                    "Thực hiện incident response theo playbook"
                ],
                long_term_actions=[
                    "Triển khai chương trình đào tạo nhận thức bảo mật",
                    "Rà soát và cập nhật các chính sách bảo mật",
                    "Nâng cấp hệ thống monitoring và detection"
                ],
                notes=f"Không thể tạo khuyến nghị tự động: {str(e)}"
            )
    
    async def _query_rag_for_recommendations(
        self,
        findings_summary: FindingsSummary,
        ti_summary: TISummary
    ) -> str:
        """
        Query RAG knowledge base for incident response recommendations.
        Query each attack type separately for better RAG understanding.
        
        Args:
            findings_summary: Analysis findings summary
            ti_summary: Threat intelligence summary
        
        Returns:
            RAG recommendations text (combined from multiple queries)
        """
        try:
            attack_breakdown = findings_summary.get('attack_breakdown', [])
            severity = findings_summary.get('severity_level', 'medium')
            
            if not attack_breakdown:
                # No specific attacks, use general query
                query = f"General incident response playbook for {severity} severity security incidents. IP blocking and mitigation steps."
                logger.info(f"Querying RAG (general): {query}")
                
                queryrag_agent = get_queryrag_agent()
                rag_result = await queryrag_agent.query_knowledge(
                    user_query=query,
                    category="incident_response"
                )
                
                if rag_result and rag_result.get('answer'):
                    return rag_result['answer']
                else:
                    return "Không có khuyến nghị từ knowledge base"
            
            # Query each attack type separately for better RAG understanding
            all_recommendations = []
            queryrag_agent = get_queryrag_agent()
            
            for attack_info in attack_breakdown:
                attack_type = attack_info['attack_type']
                count = attack_info['count']
                percentage = attack_info['percentage']
                
                # Create focused query for single attack type
                query = f"How to respond to {attack_type} attack? Incident response steps, IP blocking, WAF rules, and mitigation for {attack_type}."
                
                logger.info(f"Querying RAG for {attack_type}: {query}")
                
                try:
                    rag_result = await queryrag_agent.query_knowledge(
                        user_query=query,
                        category="incident_response"
                    )
                    
                    if rag_result and rag_result.get('answer'):
                        # Add context about this specific attack
                        recommendation = f"\n=== {attack_type.upper()} ATTACK ({count} events, {percentage:.1f}%) ===\n"
                        recommendation += rag_result['answer']
                        all_recommendations.append(recommendation)
                        logger.info(f"RAG returned recommendations for {attack_type}")
                    else:
                        logger.warning(f"RAG returned no recommendations for {attack_type}")
                        
                except Exception as e:
                    logger.error(f"Failed to query RAG for {attack_type}: {e}")
                    continue
            
            if all_recommendations:
                combined_recommendations = "\n\n".join(all_recommendations)
                logger.info(f"Combined recommendations from {len(all_recommendations)} attack types")
                return combined_recommendations
            else:
                logger.warning("No RAG recommendations returned for any attack type")
                return "Không có khuyến nghị từ knowledge base"
                
        except Exception as e:
            logger.error(f"Failed to query RAG for recommendations: {e}")
            return "Lỗi khi truy vấn knowledge base"
    
    def _create_prompt(
        self,
        findings_summary: FindingsSummary,
        ti_summary: TISummary,
        rag_recommendations: str
    ) -> str:
        """Create recommendation prompt for LLM in Vietnamese."""
        prompt = """Bạn là chuyên gia ứng phó sự cố bảo mật. Dựa trên phân tích tấn công và threat intelligence, hãy đưa ra các khuyến nghị bảo mật CỤ THỂ, THỰC TẾ BẰNG TIẾNG VIỆT.

TÓM TẮT PHÂN TÍCH:
"""
        prompt += f"- Tổng Sự Kiện: {findings_summary['total_events']}\n"
        prompt += f"- Sự Kiện Tấn Công: {findings_summary['total_attack_events']}\n"
        prompt += f"- Mức Độ: {findings_summary['severity_level']}\n"
        
        # Chi tiết từng loại tấn công
        prompt += "\nCHI TIẾT CÁC LOẠI TẤN CÔNG:\n"
        for ab in findings_summary['attack_breakdown']:
            prompt += f"- {ab['attack_type'].upper()}: {ab['count']} lần ({ab['percentage']:.1f}%)\n"
            prompt += f"  Từ các IP: {', '.join(ab['source_ips'][:5])}"
            if len(ab['source_ips']) > 5:
                prompt += f" và {len(ab['source_ips']) - 5} IP khác"
            prompt += "\n"
        
        if findings_summary.get('mitre_techniques'):
            prompt += f"\nMITRE ATT&CK Techniques: {', '.join(findings_summary['mitre_techniques'])}\n"
        
        # Sample events để hiểu context cụ thể
        if findings_summary.get('sample_events'):
            prompt += "\nMẪU CÁC CUỘC TẤN CÔNG (để hiểu pattern):\n"
            for i, sample in enumerate(findings_summary['sample_events'][:5], 1):
                prompt += f"{i}. {sample.get('attack_type', 'unknown').upper()}: "
                prompt += f"{sample.get('method', 'GET')} {sample.get('uri', '/')[:100]}\n"
                prompt += f"   Từ IP: {sample.get('src_ip', 'unknown')}\n"
        
        prompt += f"\nTóm Tắt: {findings_summary['summary_text']}\n"
        
        # TI summary với chi tiết IOCs
        if ti_summary and isinstance(ti_summary, dict):
            if ti_summary.get('iocs'):
                prompt += "\n\nTHREAT INTELLIGENCE - CÁC IP ĐỘC HẠI:\n"
                for ioc in ti_summary['iocs'][:10]:  # Top 10 IOCs
                    prompt += f"- {ioc.get('ip')}: "
                    prompt += f"Abuse Score {ioc.get('abuse_score', 0)}/100, "
                    prompt += f"Risk: {ioc.get('risk', 'unknown')}\n"
            
            if ti_summary.get('ti_overall'):
                prompt += f"\nTổng Quan TI:\n"
                prompt += f"- Mức Rủi Ro Cao Nhất: {ti_summary['ti_overall'].get('max_risk', 'unknown')}\n"
                prompt += f"- Số IOC Rủi Ro Cao: {len(ti_summary['ti_overall'].get('high_risk_iocs', []))}\n"
        else:
            prompt += "\n\nTHREAT INTELLIGENCE: Không có dữ liệu\n"
        
        # Add RAG recommendations
        prompt += f"\n\nKHUYẾN NGHỊ TỪ KNOWLEDGE BASE:\n{rag_recommendations}\n"
        
        # Asset context nếu có
        if findings_summary.get('asset_context'):
            asset_ctx = findings_summary['asset_context']
            if asset_ctx.get('is_simulated_attack'):
                prompt += "\n⚠️ LƯU Ý QUAN TRỌNG: "
                prompt += f"Phát hiện {len(asset_ctx.get('pentest_ips', []))} IP PENTEST. "
                prompt += "Đây là hoạt động NGHIỆP VỤ, không phải tấn công thật!\n"
                prompt += "Khuyến nghị cần tập trung vào cải thiện phòng thủ, không cần ứng phó khẩn cấp.\n"
        
        prompt += """

Dựa trên phân tích trên, tạo khuyến nghị CỤ THỂ, THỰC TẾ theo 3 nhóm (BẰNG TIẾNG VIỆT):

YÊU CẦU:
- Khuyến nghị phải CỤ THỂ với loại tấn công đã phát hiện
- Bao gồm các IP, URI, pattern cụ thể từ phân tích
- Phân biệt rõ: tấn công thật vs pentest
- Ưu tiên dựa trên severity và số lượng tấn công

1. HÀNH ĐỘNG NGAY LẬP TỨC (trong 1 giờ):
   - Chặn các IP độc hại CỤ THỂ (liệt kê IP)
   - Chặn các URI/pattern tấn công CỤ THỂ
   - Cô lập hệ thống bị xâm nhập (nếu có)
   - Vô hiệu hóa các tài khoản bị compromise (nếu có)
   - Reset session/token bị đánh cắp

2. HÀNH ĐỘNG NGẮN HẠN (trong 1 tuần):
   - Cập nhật WAF rules để chặn pattern CỤ THỂ (ví dụ: UNION SELECT, <script>, ../)
   - Vá lỗ hổng CỤ THỂ (SQLi, XSS, LFI, RCE - tùy loại tấn công)
   - Rà soát logs tìm pattern tương tự
   - Kiểm tra và vá các endpoint bị tấn công
   - Cập nhật input validation cho các parameter bị exploit

3. HÀNH ĐỘNG DÀI HẠN (trong 1 tháng):
   - Triển khai prepared statements (nếu có SQLi)
   - Implement CSP header (nếu có XSS)
   - Hardening file permissions (nếu có LFI/RFI)
   - Disable dangerous functions (nếu có RCE)
   - Đào tạo dev team về secure coding
   - Penetration testing định kỳ
   - Nâng cấp monitoring/alerting

ĐỊNH DẠNG OUTPUT:
QUAN TRỌNG: Chỉ trả về JSON thuần túy, KHÔNG có markdown, KHÔNG có code blocks, KHÔNG có giải thích.
Bắt đầu trực tiếp bằng { và kết thúc bằng }

VÍ DỤ:
{
  "severity_overall": "high",
  "immediate_actions": [
    "Chặn các IP: 1.2.3.4, 5.6.7.8 tại firewall",
    "Kiểm tra và ngắt các session đáng ngờ"
  ],
  "short_term_actions": [
    "Cập nhật WAF rules để chặn SQL injection",
    "Vá lỗ hổng ứng dụng web"
  ],
  "long_term_actions": [
    "Triển khai input validation framework",
    "Thực hiện security code review"
  ],
  "notes": "Sự cố mức độ cao cần xử lý ngay. Phát hiện nhiều vector tấn công."
}

KHÔNG được wrap trong markdown code blocks. Chỉ trả về JSON thuần túy.

Tạo khuyến nghị BẰNG TIẾNG VIỆT ngay bây giờ:
"""
        return prompt
    
    def _parse_response(self, response_content: str) -> RecommendSummary:
        """Parse LLM response into RecommendSummary."""
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
            return RecommendSummary(
                severity_overall=data.get('severity_overall', 'medium'),
                immediate_actions=data.get('immediate_actions', []),
                short_term_actions=data.get('short_term_actions', []),
                long_term_actions=data.get('long_term_actions', []),
                notes=data.get('notes', '')
            )
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse recommendation response: {e}")
            raise ValueError(f"Invalid JSON response: {e}")
    

