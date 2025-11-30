"""
V2.2: PDF Generator with Vietnamese Font Support

Converts markdown reports to PDF with proper Vietnamese font rendering
and auto-expanding table rows.
"""

import logging
import os
from datetime import datetime
from typing import Optional
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, Image
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import markdown2

logger = logging.getLogger(__name__)


class PDFGenerator:
    """
    PDF Generator with Vietnamese font support.
    
    Features:
    - Vietnamese font rendering (DejaVu Sans)
    - Auto-expanding table rows
    - Markdown to PDF conversion
    - Professional formatting
    """
    
    def __init__(self, font_dir: Optional[str] = None):
        """
        Initialize PDF Generator.
        
        Args:
            font_dir: Directory containing font files (optional)
        """
        self.font_dir = font_dir or "./fonts"
        self._register_fonts()
        logger.info("PDFGenerator initialized")
    
    def _register_fonts(self):
        """Register Vietnamese-compatible fonts."""
        try:
            # Try to register DejaVu Sans fonts
            font_paths = {
                'DejaVuSans': 'DejaVuSans.ttf',
                'DejaVuSans-Bold': 'DejaVuSans-Bold.ttf',
                'DejaVuSans-Italic': 'DejaVuSans-Oblique.ttf',
                'DejaVuSans-BoldItalic': 'DejaVuSans-BoldOblique.ttf'
            }
            
            for font_name, font_file in font_paths.items():
                font_path = os.path.join(self.font_dir, font_file)
                if os.path.exists(font_path):
                    pdfmetrics.registerFont(TTFont(font_name, font_path))
                    logger.info(f"Registered font: {font_name}")
                else:
                    logger.warning(f"Font file not found: {font_path}")
            
            # Set default font
            self.default_font = 'DejaVuSans'
            self.bold_font = 'DejaVuSans-Bold'
            self.italic_font = 'DejaVuSans-Italic'
            
        except Exception as e:
            logger.error(f"Failed to register fonts: {e}")
            # Fallback to Helvetica (limited Vietnamese support)
            self.default_font = 'Helvetica'
            self.bold_font = 'Helvetica-Bold'
            self.italic_font = 'Helvetica-Oblique'
    
    def _create_styles(self):
        """Create custom paragraph styles with Vietnamese font."""
        styles = getSampleStyleSheet()
        
        # Title style
        styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=styles['Heading1'],
            fontName=self.bold_font,
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        # Heading 1
        styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=styles['Heading1'],
            fontName=self.bold_font,
            fontSize=18,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
            borderWidth=0,
            borderColor=colors.HexColor('#3498db'),
            borderPadding=5
        ))
        
        # Heading 2
        styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=styles['Heading2'],
            fontName=self.bold_font,
            fontSize=14,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=10,
            spaceBefore=10
        ))
        
        # Heading 3
        styles.add(ParagraphStyle(
            name='CustomHeading3',
            parent=styles['Heading3'],
            fontName=self.bold_font,
            fontSize=12,
            textColor=colors.HexColor('#7f8c8d'),
            spaceAfter=8,
            spaceBefore=8
        ))
        
        # Body text
        styles.add(ParagraphStyle(
            name='CustomBody',
            parent=styles['BodyText'],
            fontName=self.default_font,
            fontSize=10,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=6,
            alignment=TA_JUSTIFY,
            leading=14
        ))
        
        # Bullet list
        styles.add(ParagraphStyle(
            name='CustomBullet',
            parent=styles['BodyText'],
            fontName=self.default_font,
            fontSize=10,
            textColor=colors.HexColor('#2c3e50'),
            leftIndent=20,
            spaceAfter=4,
            leading=14
        ))
        
        # Code/Monospace
        styles.add(ParagraphStyle(
            name='CustomCode',
            parent=styles['Code'],
            fontName=self.default_font,
            fontSize=9,
            textColor=colors.HexColor('#c0392b'),
            backColor=colors.HexColor('#ecf0f1'),
            leftIndent=10,
            rightIndent=10,
            spaceAfter=6
        ))
        
        return styles
    
    def markdown_to_pdf(
        self,
        markdown_text: str,
        output_path: str,
        title: Optional[str] = None
    ) -> str:
        """
        Convert markdown report to PDF.
        
        Args:
            markdown_text: Markdown content
            output_path: Output PDF file path
            title: Document title (optional)
        
        Returns:
            Path to generated PDF file
        """
        logger.info(f"Converting markdown to PDF: {output_path}")
        
        # Create PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm,
            title=title or "Security Analysis Report"
        )
        
        # Get styles
        styles = self._create_styles()
        
        # Build story (content)
        story = []
        
        # Parse markdown
        lines = markdown_text.split('\n')
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            
            # Skip empty lines
            if not line:
                story.append(Spacer(1, 0.2*cm))
                i += 1
                continue
            
            # Heading 1
            if line.startswith('# '):
                text = self._safe_format(line[2:].strip())
                story.append(Paragraph(text, styles['CustomTitle']))
                story.append(Spacer(1, 0.3*cm))
            
            # Heading 2
            elif line.startswith('## '):
                text = self._safe_format(line[3:].strip())
                story.append(Spacer(1, 0.4*cm))
                story.append(Paragraph(text, styles['CustomHeading1']))
            
            # Heading 3
            elif line.startswith('### '):
                text = self._safe_format(line[4:].strip())
                story.append(Paragraph(text, styles['CustomHeading2']))
            
            # Heading 4
            elif line.startswith('#### '):
                text = self._safe_format(line[5:].strip())
                story.append(Paragraph(text, styles['CustomHeading3']))
            
            # Horizontal rule
            elif line.startswith('---') or line.startswith('***'):
                story.append(Spacer(1, 0.3*cm))
                story.append(Table(
                    [['']], 
                    colWidths=[doc.width],
                    style=TableStyle([
                        ('LINEABOVE', (0, 0), (-1, 0), 1, colors.grey)
                    ])
                ))
                story.append(Spacer(1, 0.3*cm))
            
            # Bullet list
            elif line.startswith('- ') or line.startswith('* '):
                text = '• ' + self._safe_format(line[2:].strip())
                story.append(Paragraph(text, styles['CustomBullet']))
            
            # Numbered list
            elif line and line[0].isdigit() and '. ' in line:
                text = self._safe_format(line.strip())
                story.append(Paragraph(text, styles['CustomBullet']))
            
            # Table detection (simple)
            elif '|' in line and i + 1 < len(lines) and '|' in lines[i + 1]:
                table_lines = [line]
                i += 1
                while i < len(lines) and '|' in lines[i]:
                    table_lines.append(lines[i])
                    i += 1
                i -= 1
                
                # Parse and create table
                table_element = self._create_table(table_lines, doc.width)
                if table_element:
                    story.append(Spacer(1, 0.2*cm))
                    story.append(table_element)
                    story.append(Spacer(1, 0.2*cm))
            
            # Bold text
            elif line.startswith('**') and line.endswith('**'):
                import html
                text = f"<b>{html.escape(line[2:-2])}</b>"
                story.append(Paragraph(text, styles['CustomBody']))
            
            # Regular paragraph
            else:
                # Handle inline formatting
                try:
                    text = self._format_inline(line)
                    story.append(Paragraph(text, styles['CustomBody']))
                except Exception as e:
                    # If formatting fails, use plain text
                    logger.warning(f"Failed to format line, using plain text: {e}")
                    import html
                    safe_text = html.escape(line)
                    story.append(Paragraph(safe_text, styles['CustomBody']))
            
            i += 1
        
        # Build PDF
        try:
            doc.build(story)
            logger.info(f"PDF generated successfully: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to generate PDF: {e}")
            raise
    
    def _safe_format(self, text: str) -> str:
        """Safely format text with basic HTML escaping."""
        import html
        # Just escape HTML, no markdown formatting for headings/bullets
        return html.escape(text)
    
    def _format_inline(self, text: str) -> str:
        """Format inline markdown elements safely."""
        import re
        import html
        
        # Escape HTML special characters first
        text = html.escape(text)
        
        # Bold (convert escaped ** back)
        text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
        text = re.sub(r'__(.+?)__', r'<b>\1</b>', text)
        
        # Italic (be careful not to match ** inside bold)
        text = re.sub(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)', r'<i>\1</i>', text)
        text = re.sub(r'(?<!_)_(?!_)(.+?)(?<!_)_(?!_)', r'<i>\1</i>', text)
        
        # Code
        text = re.sub(r'`(.+?)`', r'<font color="#c0392b" face="Courier">\1</font>', text)
        
        return text
    
    def _create_table(self, table_lines: list[str], max_width: float) -> Optional[Table]:
        """
        Create table with auto-expanding rows.
        
        Args:
            table_lines: List of table lines from markdown
            max_width: Maximum table width
        
        Returns:
            Table element or None if parsing fails
        """
        try:
            # Parse table
            rows = []
            for line in table_lines:
                # Skip separator line
                if set(line.replace('|', '').replace('-', '').replace(':', '').strip()) == set():
                    continue
                
                # Split by |
                cells = [cell.strip() for cell in line.split('|')]
                # Remove empty first/last cells
                if cells and not cells[0]:
                    cells = cells[1:]
                if cells and not cells[-1]:
                    cells = cells[:-1]
                
                if cells:
                    rows.append(cells)
            
            if not rows:
                return None
            
            # Calculate column widths (equal distribution)
            num_cols = len(rows[0])
            col_width = max_width / num_cols
            col_widths = [col_width] * num_cols
            
            # Convert cells to Paragraphs for auto-wrapping
            styles = self._create_styles()
            table_data = []
            
            for row_idx, row in enumerate(rows):
                table_row = []
                for cell in row:
                    # Format cell content safely
                    try:
                        cell_text = self._format_inline(cell)
                    except Exception as e:
                        logger.warning(f"Failed to format table cell, using plain text: {e}")
                        import html
                        cell_text = html.escape(cell)
                    
                    # Use smaller font for tables
                    try:
                        para = Paragraph(cell_text, ParagraphStyle(
                            name='TableCell',
                            parent=styles['CustomBody'],
                            fontSize=9,
                            leading=12
                        ))
                        table_row.append(para)
                    except Exception as e:
                        # If Paragraph fails, use plain text
                        logger.warning(f"Failed to create paragraph for cell, using plain text: {e}")
                        import html
                        safe_text = html.escape(cell)
                        para = Paragraph(safe_text, ParagraphStyle(
                            name='TableCell',
                            parent=styles['CustomBody'],
                            fontSize=9,
                            leading=12
                        ))
                        table_row.append(para)
                table_data.append(table_row)
            
            # Create table
            table = Table(table_data, colWidths=col_widths, repeatRows=1)
            
            # Style table
            table_style = TableStyle([
                # Header row (first row)
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), self.bold_font),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                
                # Body rows
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#2c3e50')),
                ('FONTNAME', (0, 1), (-1, -1), self.default_font),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                
                # Grid
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#2c3e50')),
                
                # Padding
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                
                # Alternating row colors
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#ecf0f1')])
            ])
            
            table.setStyle(table_style)
            
            return table
        
        except Exception as e:
            logger.error(f"Failed to create table: {e}")
            return None

