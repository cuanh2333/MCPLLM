"""
PDF Report Generator - Vietnamese Version
Tạo báo cáo PDF chuyên nghiệp với tiếng Việt
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
import os

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, Frame, PageTemplate
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from backend.models import FindingsSummary, TISummary, RecommendSummary, AttackEventsRef


logger = logging.getLogger(__name__)


class VietnamesePDFGenerator:
    """Tạo báo cáo PDF tiếng Việt chuyên nghiệp."""
    
    def __init__(self):
        """Khởi tạo generator với font tiếng Việt."""
        self._register_vietnamese_fonts()
        self._setup_styles()
    
    def _register_vietnamese_fonts(self):
        """Đăng ký font tiếng Việt."""
        try:
            # Thử đăng ký DejaVu Sans (hỗ trợ tiếng Việt tốt)
            font_paths = [
                'DejaVuSans.ttf',
                'DejaVuSans-Bold.ttf',
                '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
                '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
                'C:\\Windows\\Fonts\\DejaVuSans.ttf',
                'C:\\Windows\\Fonts\\DejaVuSans-Bold.ttf',
            ]
            
            # Tìm font
            dejavu_regular = None
            dejavu_bold = None
            
            for path in font_paths:
                if os.path.exists(path):
                    if 'Bold' in path:
                        dejavu_bold = path
                    else:
                        dejavu_regular = path
            
            if dejavu_regular:
                pdfmetrics.registerFont(TTFont('DejaVuSans', dejavu_regular))
                self.font_regular = 'DejaVuSans'
                logger.info(f"Đã đăng ký font: {dejavu_regular}")
            else:
                self.font_regular = 'Helvetica'
                logger.warning("Không tìm thấy DejaVuSans.ttf, dùng Helvetica")
            
            if dejavu_bold:
                pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', dejavu_bold))
                self.font_bold = 'DejaVuSans-Bold'
                logger.info(f"Đã đăng ký font bold: {dejavu_bold}")
            else:
                self.font_bold = 'Helvetica-Bold'
                logger.warning("Không tìm thấy DejaVuSans-Bold.ttf, dùng Helvetica-Bold")
                
        except Exception as e:
            logger.error(f"Lỗi đăng ký font: {e}")
            self.font_regular = 'Helvetica'
            self.font_bold = 'Helvetica-Bold'
    
    def _setup_styles(self):
        """Thiết lập các style cho văn bản."""
        from reportlab.lib.styles import StyleSheet1
        self.styles = StyleSheet1()
        
        # Tiêu đề chính
        self.styles.add(ParagraphStyle(
            name='Title',
            fontName=self.font_bold,
            fontSize=20,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=20,
            alignment=TA_CENTER,
            leading=24
        ))
        
        # Tiêu đề phần
        self.styles.add(ParagraphStyle(
            name='Heading1',
            fontName=self.font_bold,
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=20,
            leading=20
        ))
        
        # Tiêu đề phụ
        self.styles.add(ParagraphStyle(
            name='Heading2',
            fontName=self.font_bold,
            fontSize=14,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=10,
            spaceBefore=15,
            leading=18
        ))
        
        # Văn bản thường
        self.styles.add(ParagraphStyle(
            name='Normal',
            fontName=self.font_regular,
            fontSize=11,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=10,
            leading=16,
            alignment=TA_JUSTIFY
        ))
        
        # Bullet point
        self.styles.add(ParagraphStyle(
            name='Bullet',
            fontName=self.font_regular,
            fontSize=11,
            textColor=colors.HexColor('#2c3e50'),
            leftIndent=20,
            spaceAfter=6,
            leading=16
        ))
    
    def generate_pdf(
        self,
        findings_summary: FindingsSummary,
        ti_summary: TISummary,
        recommend_summary: RecommendSummary,
        attack_events_ref: AttackEventsRef,
        output_path: str
    ) -> str:
        """
        Tạo báo cáo PDF tiếng Việt.
        """
        logger.info(f"Đang tạo báo cáo PDF tiếng Việt: {output_path}")
        
        # Tạo document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=40*mm,
            leftMargin=40*mm,
            topMargin=20*mm,
            bottomMargin=20*mm
        )
        
        # Xây dựng nội dung
        story = []
        
        # Trang bìa
        story.extend(self._build_cover_page(attack_events_ref, findings_summary))
        story.append(PageBreak())
        
        # Tóm tắt điều hành
        story.extend(self._build_executive_summary(findings_summary))
        story.append(Spacer(1, 10*mm))
        
        # Thông tin sự cố
        story.extend(self._build_incident_info(findings_summary, attack_events_ref))
        story.append(PageBreak())
        
        # Phân tích tấn công
        story.extend(self._build_attack_analysis(findings_summary))
        story.append(Spacer(1, 10*mm))
        
        # Tình báo mối đe dọa
        story.extend(self._build_threat_intelligence(ti_summary))
        story.append(PageBreak())
        
        # Khuyến nghị
        story.extend(self._build_recommendations(recommend_summary))
        story.append(Spacer(1, 10*mm))
        
        # Phụ lục
        story.extend(self._build_appendix(attack_events_ref, findings_summary))
        
        # Tạo PDF
        doc.build(story, onFirstPage=self._add_page_decoration, onLaterPages=self._add_page_decoration)
        
        logger.info(f"Đã tạo báo cáo PDF: {output_path}")
        return output_path
    
    def _build_cover_page(self, attack_ref: AttackEventsRef, findings: FindingsSummary) -> list:
        """Tạo trang bìa."""
        elements = []
        
        elements.append(Spacer(1, 60*mm))
        
        title = Paragraph("BÁO CÁO PHÂN TÍCH BẢO MẬT", self.styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 5*mm))
        
        subtitle = Paragraph("Hệ Thống Phân Tích Log Đa Tác Nhân V2", self.styles['Normal'])
        elements.append(KeepTogether([subtitle]))
        elements.append(Spacer(1, 20*mm))
        
        info_data = [
            ['Mã báo cáo:', attack_ref['report_id']],
            ['Ngày tạo:', datetime.now().strftime('%d/%m/%Y %H:%M:%S')],
            ['Mức độ nghiêm trọng:', self._get_severity_vietnamese(findings['severity_level'])],
            ['Tổng sự kiện:', str(findings['total_events'])],
            ['Sự kiện tấn công:', str(findings['total_attack_events'])]
        ]
        
        table = Table(info_data, colWidths=[60*mm, 80*mm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
            ('BOX', (0, 0), (-1, -1), 2, colors.HexColor('#2c3e50')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('FONTNAME', (0, 0), (0, -1), self.font_bold),
            ('FONTNAME', (1, 0), (1, -1), self.font_regular),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]))
        
        elements.append(table)
        return elements
    
    def _build_executive_summary(self, findings: FindingsSummary) -> list:
        """Tạo phần tóm tắt điều hành."""
        elements = []
        
        elements.append(Paragraph("1. TÓM TẮT ĐIỀU HÀNH", self.styles['Heading1']))
        elements.append(Spacer(1, 5*mm))
        
        summary_text = findings['summary_text']
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        
        return elements
    
    def _build_incident_info(self, findings: FindingsSummary, attack_ref: AttackEventsRef) -> list:
        """Tạo phần thông tin sự cố."""
        elements = []
        
        elements.append(Paragraph("2. THÔNG TIN SỰ CỐ", self.styles['Heading1']))
        elements.append(Spacer(1, 5*mm))
        
        severity_vi = self._get_severity_vietnamese(findings['severity_level'])
        severity_color = self._get_severity_color(findings['severity_level'])
        
        attack_rate = (findings['total_attack_events'] / findings['total_events'] * 100) if findings['total_events'] > 0 else 0
        
        info_data = [
            ['Chỉ số', 'Giá trị'],
            ['Mã báo cáo', attack_ref['report_id']],
            ['Thời gian phân tích', datetime.now().strftime('%d/%m/%Y %H:%M:%S')],
            ['Tổng số sự kiện', f"{findings['total_events']:,}"],
            ['Sự kiện tấn công', f"{findings['total_attack_events']:,}"],
            ['Tỷ lệ tấn công', f"{attack_rate:.1f}%"],
            ['Mức độ nghiêm trọng', severity_vi],
        ]
        
        table = Table(info_data, colWidths=[70*mm, 70*mm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), self.font_bold),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
            ('FONTNAME', (0, 1), (0, -1), self.font_bold),
            ('FONTNAME', (1, 1), (1, -1), self.font_regular),
            ('FONTSIZE', (0, 1), (-1, -1), 11),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (1, -1), (1, -1), severity_color),
            ('FONTNAME', (1, -1), (1, -1), self.font_bold),
        ]))
        
        elements.append(table)
        return elements

    
    def _build_attack_analysis(self, findings: FindingsSummary) -> list:
        """Tạo phần phân tích tấn công."""
        elements = []
        
        elements.append(Paragraph("3. PHÂN TÍCH TẤN CÔNG", self.styles['Heading1']))
        elements.append(Spacer(1, 5*mm))
        
        elements.append(Paragraph("3.1. Các Loại Tấn Công Phát Hiện", self.styles['Heading2']))
        elements.append(Spacer(1, 3*mm))
        
        if findings['attack_breakdown']:
            attack_data = [['Loại tấn công', 'Số lượng', 'Tỷ lệ (%)', 'IP nguồn']]
            
            for ab in findings['attack_breakdown']:
                attack_type_vi = self._get_attack_type_vietnamese(ab['attack_type'])
                
                ips = ab['source_ips']
                if len(ips) <= 3:
                    ip_str = ', '.join(ips)
                else:
                    ip_str = ', '.join(ips[:3]) + f' +{len(ips)-3}'
                
                attack_data.append([
                    attack_type_vi,
                    str(ab['count']),
                    f"{ab['percentage']:.1f}%",
                    ip_str
                ])
            
            table = Table(attack_data, colWidths=[40*mm, 25*mm, 25*mm, 50*mm])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), self.font_bold),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (1, 0), (2, -1), 'CENTER'),
                ('ALIGN', (3, 0), (3, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
                ('FONTNAME', (0, 1), (-1, -1), self.font_regular),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ]))
            
            elements.append(table)
        else:
            elements.append(Paragraph("Không phát hiện tấn công.", self.styles['Normal']))
        
        if findings.get('mitre_techniques'):
            elements.append(Spacer(1, 5*mm))
            elements.append(Paragraph("3.2. Kỹ Thuật MITRE ATT&CK", self.styles['Heading2']))
            elements.append(Spacer(1, 3*mm))
            
            for technique in findings['mitre_techniques']:
                technique_desc = self._get_mitre_description(technique)
                elements.append(Paragraph(f"• <b>{technique}</b>: {technique_desc}", self.styles['Bullet']))
        
        return elements
    
    def _build_threat_intelligence(self, ti_summary: TISummary) -> list:
        """Tạo phần tình báo mối đe dọa."""
        elements = []
        
        elements.append(Paragraph("4. TÌNH BÁO MỐI ĐE DỌA", self.styles['Heading1']))
        elements.append(Spacer(1, 5*mm))
        
        elements.append(Paragraph("4.1. Đánh Giá Tổng Quan", self.styles['Heading2']))
        elements.append(Spacer(1, 3*mm))
        
        ti_overall = ti_summary['ti_overall']
        max_risk = ti_overall.get('max_risk', 'unknown')
        max_risk_vi = self._get_risk_vietnamese(max_risk)
        risk_color = self._get_risk_color(max_risk)
        
        high_risk_count = len(ti_overall.get('high_risk_iocs', []))
        
        risk_data = [
            ['Mức độ rủi ro cao nhất', max_risk_vi],
            ['Số IOC rủi ro cao', str(high_risk_count)],
        ]
        
        table = Table(risk_data, colWidths=[70*mm, 70*mm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
            ('FONTNAME', (0, 0), (0, -1), self.font_bold),
            ('FONTNAME', (1, 0), (1, -1), self.font_regular),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (1, 0), (1, 0), risk_color),
            ('FONTNAME', (1, 0), (1, 0), self.font_bold),
        ]))
        
        elements.append(table)
        elements.append(Spacer(1, 3*mm))
        
        notes = ti_overall.get('notes', 'Không có thông tin')
        elements.append(Paragraph(f"<b>Nhận xét:</b> {notes}", self.styles['Normal']))
        
        if ti_summary['iocs']:
            elements.append(Spacer(1, 5*mm))
            elements.append(Paragraph("4.2. Chi Tiết IOC (Top 10)", self.styles['Heading2']))
            elements.append(Spacer(1, 3*mm))
            
            ioc_data = [['Địa chỉ IP', 'Mức rủi ro', 'Ghi chú']]
            
            for ioc in ti_summary['iocs'][:10]:
                ip = ioc.get('ip', 'N/A')
                risk = self._get_risk_vietnamese(ioc.get('risk', 'unknown'))
                notes = ioc.get('notes', 'N/A')
                
                if len(notes) > 50:
                    notes = notes[:47] + '...'
                
                ioc_data.append([ip, risk, notes])
            
            table = Table(ioc_data, colWidths=[35*mm, 30*mm, 75*mm])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), self.font_bold),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
                ('FONTNAME', (0, 1), (-1, -1), self.font_regular),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ]))
            
            elements.append(table)
        
        return elements
    
    def _build_recommendations(self, recommend: RecommendSummary) -> list:
        """Tạo phần khuyến nghị."""
        elements = []
        
        elements.append(Paragraph("5. KHUYẾN NGHỊ BẢO MẬT", self.styles['Heading1']))
        elements.append(Spacer(1, 5*mm))
        
        severity_vi = self._get_severity_vietnamese(recommend['severity_overall'])
        elements.append(Paragraph(f"<b>Mức độ nghiêm trọng:</b> {severity_vi}", self.styles['Normal']))
        elements.append(Spacer(1, 5*mm))
        
        elements.append(Paragraph("5.1. Hành Động Khẩn Cấp (< 1 giờ)", self.styles['Heading2']))
        elements.append(Spacer(1, 3*mm))
        
        if recommend['immediate_actions']:
            for i, action in enumerate(recommend['immediate_actions'], 1):
                elements.append(Paragraph(f"{i}. {action}", self.styles['Bullet']))
        else:
            elements.append(Paragraph("Không có hành động khẩn cấp.", self.styles['Normal']))
        
        elements.append(Spacer(1, 5*mm))
        elements.append(Paragraph("5.2. Hành Động Ngắn Hạn (< 1 tuần)", self.styles['Heading2']))
        elements.append(Spacer(1, 3*mm))
        
        if recommend['short_term_actions']:
            for i, action in enumerate(recommend['short_term_actions'], 1):
                elements.append(Paragraph(f"{i}. {action}", self.styles['Bullet']))
        else:
            elements.append(Paragraph("Không có hành động ngắn hạn.", self.styles['Normal']))
        
        elements.append(Spacer(1, 5*mm))
        elements.append(Paragraph("5.3. Hành Động Dài Hạn (< 1 tháng)", self.styles['Heading2']))
        elements.append(Spacer(1, 3*mm))
        
        if recommend['long_term_actions']:
            for i, action in enumerate(recommend['long_term_actions'], 1):
                elements.append(Paragraph(f"{i}. {action}", self.styles['Bullet']))
        else:
            elements.append(Paragraph("Không có hành động dài hạn.", self.styles['Normal']))
        
        if recommend['notes']:
            elements.append(Spacer(1, 5*mm))
            elements.append(Paragraph(f"<b>Ghi chú bổ sung:</b> {recommend['notes']}", self.styles['Normal']))
        
        return elements
    
    def _build_appendix(self, attack_ref: AttackEventsRef, findings: FindingsSummary) -> list:
        """Tạo phần phụ lục."""
        elements = []
        
        elements.append(Paragraph("6. PHỤ LỤC", self.styles['Heading1']))
        elements.append(Spacer(1, 5*mm))
        
        elements.append(Paragraph("6.1. Xuất Dữ Liệu", self.styles['Heading2']))
        elements.append(Spacer(1, 3*mm))
        
        elements.append(Paragraph(
            "Dữ liệu chi tiết về các sự kiện tấn công đã được xuất ra định dạng CSV để phân tích sâu hơn.",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 3*mm))
        
        csv_data = [
            ['Thông tin', 'Giá trị'],
            ['File CSV', attack_ref['csv_path'] or 'Không có'],
            ['Tổng sự kiện tấn công', str(attack_ref['total_attack_events'])],
            ['Mã báo cáo', attack_ref['report_id']]
        ]
        
        table = Table(csv_data, colWidths=[60*mm, 80*mm])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), self.font_bold),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
            ('FONTNAME', (0, 1), (0, -1), self.font_bold),
            ('FONTNAME', (1, 1), (1, -1), self.font_regular),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ]))
        
        elements.append(table)
        
        if findings.get('sample_events'):
            elements.append(Spacer(1, 5*mm))
            elements.append(Paragraph("6.2. Mẫu Sự Kiện Tấn Công", self.styles['Heading2']))
            elements.append(Spacer(1, 3*mm))
            
            for i, event in enumerate(findings['sample_events'][:5], 1):
                event_text = f"<b>Sự kiện {i}:</b> {event.get('timestamp', 'N/A')} - "
                event_text += f"{event.get('src_ip', 'N/A')} - "
                event_text += f"{event.get('method', 'N/A')} {event.get('uri', 'N/A')[:50]}"
                elements.append(Paragraph(event_text, self.styles['Normal']))
        
        return elements
    
    def _add_page_decoration(self, canvas, doc):
        """Thêm header và footer cho mỗi trang."""
        canvas.saveState()
        
        footer_text = f"Hệ Thống Phân Tích Log Đa Tác Nhân V2 | {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
        canvas.setFont(self.font_regular, 8)
        canvas.setFillColor(colors.grey)
        canvas.drawCentredString(A4[0] / 2, 15*mm, footer_text)
        
        page_num = canvas.getPageNumber()
        canvas.drawRightString(A4[0] - 40*mm, 15*mm, f"Trang {page_num}")
        
        canvas.setStrokeColor(colors.HexColor('#2c3e50'))
        canvas.setLineWidth(2)
        canvas.line(40*mm, A4[1] - 15*mm, A4[0] - 40*mm, A4[1] - 15*mm)
        
        canvas.restoreState()
    
    def _get_severity_vietnamese(self, severity: str) -> str:
        """Chuyển đổi mức độ nghiêm trọng sang tiếng Việt."""
        mapping = {
            'low': 'Thấp',
            'medium': 'Trung bình',
            'high': 'Cao',
            'critical': 'Nghiêm trọng'
        }
        return mapping.get(severity.lower(), severity.upper())
    
    def _get_severity_color(self, severity: str) -> colors.Color:
        """Lấy màu cho mức độ nghiêm trọng."""
        mapping = {
            'low': colors.green,
            'medium': colors.orange,
            'high': colors.red,
            'critical': colors.darkred
        }
        return mapping.get(severity.lower(), colors.grey)
    
    def _get_risk_vietnamese(self, risk: str) -> str:
        """Chuyển đổi mức độ rủi ro sang tiếng Việt."""
        mapping = {
            'low': 'Thấp',
            'medium': 'Trung bình',
            'high': 'Cao',
            'critical': 'Nghiêm trọng',
            'unknown': 'Không xác định'
        }
        return mapping.get(risk.lower(), risk.upper())
    
    def _get_risk_color(self, risk: str) -> colors.Color:
        """Lấy màu cho mức độ rủi ro."""
        mapping = {
            'low': colors.green,
            'medium': colors.orange,
            'high': colors.red,
            'critical': colors.darkred,
            'unknown': colors.grey
        }
        return mapping.get(risk.lower(), colors.grey)
    
    def _get_attack_type_vietnamese(self, attack_type: str) -> str:
        """Chuyển đổi loại tấn công sang tiếng Việt."""
        mapping = {
            'sqli': 'SQL Injection',
            'xss': 'Cross-Site Scripting (XSS)',
            'lfi': 'Local File Inclusion',
            'rfi': 'Remote File Inclusion',
            'rce': 'Remote Code Execution',
            'xxe': 'XML External Entity',
            'path_traversal': 'Path Traversal',
            'command_injection': 'Command Injection',
            'benign': 'Lành tính'
        }
        return mapping.get(attack_type.lower(), attack_type.upper())
    
    def _get_mitre_description(self, technique: str) -> str:
        """Lấy mô tả kỹ thuật MITRE ATT&CK."""
        mapping = {
            'T1190': 'Khai thác ứng dụng công khai',
            'T1059': 'Command and Scripting Interpreter',
            'T1083': 'File and Directory Discovery',
            'T1071': 'Application Layer Protocol'
        }
        return mapping.get(technique, 'Kỹ thuật tấn công')
