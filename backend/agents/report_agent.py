"""
V2: Report Agent

Generates comprehensive markdown reports from analysis results.
V2.2: Added PDF export with Vietnamese font support.
"""

import logging
from datetime import datetime
from typing import Optional
from pathlib import Path

from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage

from backend.models import (
    FindingsSummary,
    TISummary,
    RecommendSummary,
    AttackEventsRef,
    AttackStatistics
)


logger = logging.getLogger(__name__)


class ReportAgent:
    """
    Report Agent for markdown report generation.
    
    Creates comprehensive security analysis reports in markdown format.
    """
    
    def __init__(self, llm: ChatGroq, enable_pdf: bool = True):
        """
        Initialize ReportAgent.
        
        Args:
            llm: ChatGroq LLM instance
            enable_pdf: Enable PDF generation (default: True)
        """
        self.llm = llm
        self.enable_pdf = enable_pdf
        self.pdf_generator = None
        
        if enable_pdf:
            try:
                from backend.utils.pdf_generator import PDFGenerator
                self.pdf_generator = PDFGenerator()
                logger.info("ReportAgent initialized with PDF support")
            except Exception as e:
                logger.warning(f"PDF support disabled: {e}")
                self.enable_pdf = False
        else:
            logger.info("ReportAgent initialized (PDF disabled)")
    
    async def generate(
        self,
        findings_summary: FindingsSummary,
        ti_summary: TISummary,
        recommend_summary: RecommendSummary,
        attack_events_ref: AttackEventsRef,
        export_pdf: bool = False,
        output_dir: str = "./output"
    ) -> tuple[str, Optional[str]]:
        """
        Generate markdown report and optionally export to PDF.
        
        Args:
            findings_summary: Analysis findings
            ti_summary: Threat intelligence summary
            recommend_summary: Recommendations
            attack_events_ref: Attack events reference
            export_pdf: Export to PDF (default: False)
            output_dir: Output directory for PDF (default: ./output)
        
        Returns:
            Tuple of (markdown_report, pdf_path)
            pdf_path is None if export_pdf=False or PDF generation fails
        """
        logger.info("Generating markdown report")
        
        prompt = self._create_prompt(
            findings_summary,
            ti_summary,
            recommend_summary,
            attack_events_ref
        )
        
        try:
            response = await self.llm.ainvoke([HumanMessage(content=prompt)])
            report_markdown = response.content.strip()
            logger.info("Report generated successfully")
        
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            # Return basic report on failure
            report_markdown = self._generate_fallback_report(
                findings_summary,
                ti_summary,
                recommend_summary,
                attack_events_ref,
                error=str(e)
            )
        
        # Export to PDF if requested
        pdf_path = None
        if export_pdf and self.enable_pdf and self.pdf_generator:
            try:
                pdf_path = self._export_to_pdf(
                    report_markdown,
                    attack_events_ref['report_id'],
                    output_dir
                )
            except Exception as e:
                logger.error(f"Failed to export PDF: {e}")
        
        return report_markdown, pdf_path
    
    def _create_prompt(
        self,
        findings_summary: FindingsSummary,
        ti_summary: TISummary,
        recommend_summary: RecommendSummary,
        attack_events_ref: AttackEventsRef
    ) -> str:
        """Create report generation prompt for LLM in Vietnamese."""
        
        # Get current timestamp
        from datetime import datetime
        current_time = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        
        # Extract time range from report_id if available
        # Format: report_YYYYMMDD_HHMMSS
        report_id = attack_events_ref['report_id']
        time_range = "N/A"
        if report_id.startswith('report_'):
            try:
                date_part = report_id.split('_')[1]  # YYYYMMDD
                time_part = report_id.split('_')[2]  # HHMMSS
                year = date_part[:4]
                month = date_part[4:6]
                day = date_part[6:8]
                hour = time_part[:2]
                minute = time_part[2:4]
                second = time_part[4:6]
                analysis_time = f"{day}/{month}/{year} {hour}:{minute}:{second}"
                time_range = f"Phân tích vào: {analysis_time}"
            except:
                time_range = f"Phân tích vào: {current_time}"
        
        prompt = f"""Bạn là chuyên gia phân tích bảo mật đang viết báo cáo sự cố chi tiết. Hãy tạo báo cáo markdown chuyên nghiệp BẰNG TIẾNG VIỆT dựa trên dữ liệu sau.

DỮ LIỆU BÁO CÁO:

PHÁT HIỆN:
"""
        prompt += f"- Mã Báo Cáo: {attack_events_ref['report_id']}\n"
        prompt += f"- Thời Gian: {time_range}\n"
        prompt += f"- Tổng Sự Kiện: {findings_summary['total_events']}\n"
        prompt += f"- Sự Kiện Tấn Công: {findings_summary['total_attack_events']}\n"
        prompt += f"- Mức Độ: {findings_summary['severity_level']}\n"
        prompt += f"- File CSV: {attack_events_ref['csv_path']}\n\n"
        
        prompt += "Phân Loại Tấn Công:\n"
        for ab in findings_summary['attack_breakdown']:
            prompt += f"  - {ab['attack_type']}: {ab['count']} sự kiện ({ab['percentage']:.1f}%)\n"
            prompt += f"    IP Nguồn: {', '.join(ab['source_ips'][:5])}\n"
        
        if findings_summary.get('mitre_techniques'):
            prompt += f"\nMITRE Techniques: {', '.join(findings_summary['mitre_techniques'])}\n"
        
        prompt += f"\nTóm Tắt: {findings_summary['summary_text']}\n"
        
        # TI summary (handle None)
        if ti_summary and isinstance(ti_summary, dict) and ti_summary.get('ti_overall'):
            prompt += "\n\nTHREAT INTELLIGENCE:\n"
            prompt += f"- Mức Rủi Ro Cao Nhất: {ti_summary['ti_overall'].get('max_risk', 'unknown')}\n"
            prompt += f"- IOC Rủi Ro Cao: {ti_summary['ti_overall'].get('high_risk_iocs', [])}\n"
            prompt += f"- Ghi Chú: {ti_summary['ti_overall'].get('notes', 'N/A')}\n"
            
            if ti_summary.get('iocs'):
                prompt += "\nChi Tiết IOC:\n"
                for ioc in ti_summary['iocs'][:10]:
                    prompt += f"  - {ioc.get('ip', 'N/A')}: mức rủi ro {ioc.get('risk', 'unknown')}\n"
        else:
            prompt += "\n\nTHREAT INTELLIGENCE: Not available\n"
        
        prompt += "\n\nKHUYẾN NGHỊ:\n"
        prompt += f"- Mức Độ Tổng Thể: {recommend_summary['severity_overall']}\n"
        prompt += f"- Ghi Chú: {recommend_summary['notes']}\n\n"
        
        prompt += "Hành Động Ngay:\n"
        for action in recommend_summary['immediate_actions']:
            prompt += f"  - {action}\n"
        
        prompt += "\nHành Động Ngắn Hạn:\n"
        for action in recommend_summary['short_term_actions']:
            prompt += f"  - {action}\n"
        
        prompt += "\nHành Động Dài Hạn:\n"
        for action in recommend_summary['long_term_actions']:
            prompt += f"  - {action}\n"
        
        # Generate attack statistics for report
        attack_statistics = self._generate_attack_statistics(findings_summary, ti_summary)
        
        # Add simple attack statistics to prompt
        if attack_statistics:
            prompt += "\n\nBẢNG THỐNG KÊ ĐƠN GIẢN:\n"
            
            # IP Details (like Statistics page)
            if attack_statistics.get('ip_details'):
                prompt += "\nDữ Liệu Chi Tiết IP:\n"
                for ip_detail in attack_statistics['ip_details'][:10]:
                    prompt += f"  - {ip_detail['ip']}: {ip_detail['attack_type']} ({ip_detail['count']} lần) - {ip_detail['status_text']}\n"
            
            # URI Details
            if attack_statistics.get('uri_details'):
                prompt += "\nURI Bị Tấn Công Nhiều Nhất:\n"
                for uri_detail in attack_statistics['uri_details'][:5]:
                    prompt += f"  - {uri_detail['uri']}: {uri_detail['count']} lần ({uri_detail['method']})\n"
            
            # Summary
            if attack_statistics.get('summary'):
                summary = attack_statistics['summary']
                prompt += f"\nTóm Tắt: {summary['total_ips']} IP, {summary['total_uris']} URI, {summary['high_risk_ips']} IP rủi ro cao\n"
        
        prompt += """

Tạo báo cáo markdown chuyên nghiệp BẰNG TIẾNG VIỆT với cấu trúc sau:

# Báo Cáo Phân Tích Bảo Mật

## Tóm Tắt Điều Hành
Tổng quan ngắn gọn về sự cố (2-3 đoạn văn)

## Chi Tiết Sự Cố
- Mã Báo Cáo: {attack_events_ref['report_id']}
- Ngày Phân Tích: {time_range}
- Tổng Số Sự Kiện Phân Tích: {findings_summary['total_events']}
- Sự Kiện Tấn Công Phát Hiện: {findings_summary['total_attack_events']}
- Mức Độ Nghiêm Trọng: {findings_summary['severity_level'].upper()}

## Phân Tích Tấn Công
### Các Loại Tấn Công Phát Hiện
Danh sách các loại tấn công với số lượng và phần trăm

### MITRE ATT&CK Mapping
Danh sách các techniques phát hiện

### Phân Tích Nguồn
Top IP tấn công và đặc điểm

## Dữ Liệu Chi Tiết IP
Tạo bảng markdown với các cột: Địa Chỉ IP | Kỹ Thuật Tấn Công | Số Lần | Trạng Thái (AbuseIPDB) | Mức Độ

## URI Bị Tấn Công Nhiều Nhất
Tạo bảng markdown với các cột: URI | Số Lần Tấn Công | Phương Thức

## Threat Intelligence
### Phân Tích IOC
Tóm tắt kết quả threat intelligence

### Đánh Giá Rủi Ro
Mức độ rủi ro tổng thể và các IOC rủi ro cao

## Khuyến Nghị
QUAN TRỌNG: Phần Khuyến Nghị này chỉ dùng TEXT và BULLET POINTS, KHÔNG tạo bảng

### Hành Động Ngay Lập Tức (< 1 giờ)
Liệt kê dạng bullet points với mô tả chi tiết (KHÔNG dùng bảng)

### Hành Động Ngắn Hạn (< 1 tuần)
Liệt kê dạng bullet points với mô tả chi tiết (KHÔNG dùng bảng)

### Hành Động Dài Hạn (< 1 tháng)
Liệt kê dạng bullet points với mô tả chi tiết (KHÔNG dùng bảng)

## Phụ Lục
- Vị Trí File CSV
- Ghi Chú Bổ Sung

---
Báo cáo được tạo vào {current_time}

QUAN TRỌNG: 
- Sử dụng thời gian cụ thể: {time_range}
- Thời gian tạo báo cáo: {current_time}
- Đảm bảo tất cả timestamp hiển thị đầy đủ ngày/tháng/năm và giờ:phút:giây
- Tạo BẢNG MARKDOWN cho phần "Dữ Liệu Chi Tiết IP" và "URI Bị Tấn Công Nhiều Nhất"
- Phần KHUYẾN NGHỊ chỉ dùng bullet points, KHÔNG tạo bảng

Generate the report now (markdown only, no code blocks):
"""
        return prompt
    
    def _generate_fallback_report(
        self,
        findings_summary: FindingsSummary,
        ti_summary: TISummary,
        recommend_summary: RecommendSummary,
        attack_events_ref: AttackEventsRef,
        error: str
    ) -> str:
        """Generate basic fallback report if LLM fails."""
        current_time = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        
        # Extract analysis time from report_id
        report_id = attack_events_ref['report_id']
        analysis_time = current_time
        if report_id.startswith('report_'):
            try:
                date_part = report_id.split('_')[1]
                time_part = report_id.split('_')[2]
                year = date_part[:4]
                month = date_part[4:6]
                day = date_part[6:8]
                hour = time_part[:2]
                minute = time_part[2:4]
                second = time_part[4:6]
                analysis_time = f"{day}/{month}/{year} {hour}:{minute}:{second}"
            except:
                pass
        
        report = f"""# Báo Cáo Phân Tích Bảo Mật

## Tóm Tắt Điều Hành

Báo cáo này tóm tắt kết quả phân tích bảo mật được thực hiện vào {analysis_time}.

**Mã Báo Cáo**: {attack_events_ref['report_id']}  
**Ngày Phân Tích**: {analysis_time}  
**Tổng Sự Kiện**: {findings_summary['total_events']}  
**Sự Kiện Tấn Công**: {findings_summary['total_attack_events']}  
**Mức Độ**: {findings_summary['severity_level'].upper()}

{findings_summary['summary_text']}

## Attack Analysis

### Attack Types Detected

"""
        for ab in findings_summary['attack_breakdown']:
            report += f"- **{ab['attack_type']}**: {ab['count']} events ({ab['percentage']:.1f}%)\n"
            report += f"  - Source IPs: {', '.join(ab['source_ips'][:5])}\n"
        
        if findings_summary.get('mitre_techniques'):
            report += "\n### MITRE ATT&CK Techniques\n\n"
            for tech in findings_summary['mitre_techniques']:
                report += f"- {tech}\n"
        
        # TI section (handle None)
        if ti_summary and isinstance(ti_summary, dict) and ti_summary.get('ti_overall'):
            report += f"""

## Threat Intelligence

**Max Risk Level**: {ti_summary['ti_overall'].get('max_risk', 'unknown')}  
**High Risk IOCs**: {len(ti_summary['ti_overall'].get('high_risk_iocs', []))}

{ti_summary['ti_overall'].get('notes', 'N/A')}

"""
        else:
            report += "\n## Threat Intelligence\n\nNot available\n\n"
        
        report += f"""
## Recommendations

**Overall Severity**: {recommend_summary['severity_overall'].upper()}

### Immediate Actions (< 1 hour)

"""
        for action in recommend_summary['immediate_actions']:
            report += f"- {action}\n"
        
        report += "\n### Short-term Actions (< 1 week)\n\n"
        for action in recommend_summary['short_term_actions']:
            report += f"- {action}\n"
        
        report += "\n### Long-term Actions (< 1 month)\n\n"
        for action in recommend_summary['long_term_actions']:
            report += f"- {action}\n"
        
        report += f"""

## Appendix

**CSV Export**: {attack_events_ref['csv_path'] or 'N/A'}

**Notes**: {recommend_summary['notes']}

---

*Báo cáo được tạo vào {current_time}*

*Lưu ý: Không thể tạo báo cáo tự động do lỗi: {error}. Đây là báo cáo dự phòng.*
"""
        return report
    
    def _export_to_pdf(
        self,
        markdown_text: str,
        report_id: str,
        output_dir: str
    ) -> str:
        """
        Export markdown report to PDF.
        
        Args:
            markdown_text: Markdown report content
            report_id: Report ID for filename
            output_dir: Output directory
        
        Returns:
            Path to generated PDF file
        """
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Generate PDF filename
        pdf_filename = f"{report_id}_report.pdf"
        pdf_path = str(Path(output_dir) / pdf_filename)
        
        # Convert to PDF
        logger.info(f"Exporting report to PDF: {pdf_path}")
        self.pdf_generator.markdown_to_pdf(
            markdown_text,
            pdf_path,
            title=f"Security Analysis Report - {report_id}"
        )
        
        logger.info(f"PDF exported successfully: {pdf_path}")
        return pdf_path
    def _generate_attack_statistics(
        self,
        findings_summary: FindingsSummary,
        ti_summary: TISummary
    ) -> AttackStatistics:
        """
        Generate simple attack statistics for report (like Statistics page).
        
        Args:
            findings_summary: Analysis findings summary
            ti_summary: Threat intelligence summary
        
        Returns:
            AttackStatistics with simple IP and URI details
        """
        logger.info("Generating attack statistics for report")
        
        ip_details = []
        uri_details = []
        
        # Process attack breakdown to create IP details (similar to Statistics page)
        for attack_breakdown in findings_summary.get('attack_breakdown', []):
            attack_type = attack_breakdown.get('attack_type', 'unknown')
            count = attack_breakdown.get('count', 0)
            
            for src_ip in attack_breakdown.get('source_ips', []):
                # Estimate count per IP
                estimated_count = count // len(attack_breakdown.get('source_ips', [1]))
                
                # Get TI status if available
                status = 'unknown'
                status_text = 'Chưa kiểm tra'
                severity = '0.0'
                
                if ti_summary and isinstance(ti_summary, dict) and ti_summary.get('iocs'):
                    for ioc in ti_summary['iocs']:
                        if ioc.get('ip') == src_ip:
                            risk = ioc.get('risk', 'unknown')
                            abuse_score = ioc.get('abuse_score', 0)
                            
                            if risk == 'high':
                                status = 'high'
                                status_text = f'Rủi ro cao ({abuse_score}/100)'
                                severity = str(min(10.0, abuse_score / 10))
                            elif risk == 'medium':
                                status = 'medium'
                                status_text = f'Rủi ro trung bình ({abuse_score}/100)'
                                severity = str(min(7.0, abuse_score / 15))
                            else:
                                status = 'low'
                                status_text = f'Rủi ro thấp ({abuse_score}/100)'
                                severity = str(min(5.0, abuse_score / 20))
                            break
                
                ip_details.append({
                    'ip': src_ip,
                    'attack_type': attack_type.upper(),
                    'count': estimated_count,
                    'status': status,
                    'status_text': status_text,
                    'severity': severity
                })
        
        # Process sample events to create URI details
        uri_counter = {}
        if findings_summary.get('sample_events'):
            for event in findings_summary['sample_events']:
                uri = event.get('uri', '/')
                method = event.get('method', 'GET')
                
                if uri not in uri_counter:
                    uri_counter[uri] = {
                        'count': 0,
                        'method': method
                    }
                uri_counter[uri]['count'] += 1
        
        # Convert to sorted list (top 10)
        uri_details = [
            {
                'uri': uri,
                'count': data['count'],
                'method': data['method']
            }
            for uri, data in sorted(uri_counter.items(), key=lambda x: x[1]['count'], reverse=True)[:10]
        ]
        
        # Create summary
        summary = {
            'total_ips': len(ip_details),
            'total_uris': len(uri_details),
            'high_risk_ips': len([ip for ip in ip_details if ip['status'] == 'high'])
        }
        
        return AttackStatistics(
            ip_details=ip_details,
            uri_details=uri_details,
            summary=summary
        )