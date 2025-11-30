"""
Telegram Bot Notifier for V2 Multi-Agent System

Sends analysis reports and alerts via Telegram.
"""

import logging
from typing import Optional
import requests
from backend.models import FindingsSummary, TISummary, RecommendSummary, AttackEventsRef
from backend.config import settings


logger = logging.getLogger(__name__)


class TelegramNotifier:
    """Send notifications via Telegram Bot."""
    
    def __init__(self):
        self.bot_token = settings.telegram_bot_token
        self.chat_id = settings.telegram_chat_id
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"
    
    @staticmethod
    def _escape_markdown(text: str) -> str:
        """Escape special characters for Telegram MarkdownV2."""
        # For Markdown (not MarkdownV2), we need to escape: _ * [ ] ( ) ~ ` > # + - = | { } . !
        # But for basic Markdown, just escape the most problematic ones
        special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
        for char in special_chars:
            text = text.replace(char, f'\\{char}')
        return text
    
    def is_configured(self) -> bool:
        """Check if Telegram is configured."""
        return bool(self.bot_token and self.chat_id)
    
    def send_message(self, text: str, parse_mode: str = "Markdown") -> bool:
        """
        Send text message to Telegram.
        
        Args:
            text: Message text
            parse_mode: "Markdown" or "HTML"
        
        Returns:
            True if successful, False otherwise
        """
        if not self.is_configured():
            logger.warning("Telegram not configured, skipping notification")
            return False
        
        try:
            # Telegram message limit is 4096 characters
            max_length = 4000  # Leave some margin
            if len(text) > max_length:
                logger.warning(f"Message too long ({len(text)} chars), truncating to {max_length}")
                text = text[:max_length] + "\n\n... (đã cắt bớt)"
            
            url = f"{self.base_url}/sendMessage"
            payload = {
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": parse_mode
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            # Log response for debugging
            if response.status_code != 200:
                logger.error(f"Telegram API error: {response.status_code}")
                logger.error(f"Response: {response.text}")
            
            response.raise_for_status()
            
            logger.info("Telegram message sent successfully")
            return True
        
        except requests.exceptions.HTTPError as e:
            logger.error(f"Failed to send Telegram message: {e}")
            logger.error(f"Response: {e.response.text if hasattr(e, 'response') else 'N/A'}")
            
            # Try sending without parse_mode if markdown fails
            if parse_mode == "Markdown":
                logger.info("Retrying without Markdown formatting...")
                try:
                    # Remove markdown formatting
                    plain_text = text.replace('*', '').replace('_', '').replace('`', '')
                    payload = {
                        "chat_id": self.chat_id,
                        "text": plain_text[:max_length]
                    }
                    response = requests.post(url, json=payload, timeout=10)
                    response.raise_for_status()
                    logger.info("Telegram message sent (plain text)")
                    return True
                except Exception as retry_error:
                    logger.error(f"Retry also failed: {retry_error}")
            
            return False
        
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Failed to connect to Telegram API: {e}")
            logger.warning("Telegram may be blocked by firewall/proxy or network is down")
            return False
        
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")
            return False
    
    def send_document(self, file_path: str, caption: str = "") -> bool:
        """
        Send document (PDF, CSV) to Telegram.
        
        Args:
            file_path: Path to file
            caption: Optional caption
        
        Returns:
            True if successful, False otherwise
        """
        if not self.is_configured():
            logger.warning("Telegram not configured, skipping notification")
            return False
        
        try:
            # Normalize path to handle mixed slashes
            import os
            file_path = os.path.normpath(file_path)
            
            # Check if file exists
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return False
            
            url = f"{self.base_url}/sendDocument"
            
            with open(file_path, 'rb') as file:
                files = {'document': file}
                data = {
                    'chat_id': self.chat_id,
                    'caption': caption
                }
                
                response = requests.post(url, data=data, files=files, timeout=30)
                response.raise_for_status()
            
            logger.info(f"Telegram document sent: {file_path}")
            return True
        
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Failed to connect to Telegram API: {e}")
            logger.warning("Telegram may be blocked by firewall/proxy or network is down")
            return False
        
        except FileNotFoundError as e:
            logger.error(f"File not found: {e}")
            return False
        
        except Exception as e:
            logger.error(f"Failed to send Telegram document: {e}")
            return False
    
    def send_analysis_alert(
        self,
        findings: FindingsSummary,
        ti_summary: TISummary,
        recommend: RecommendSummary,
        attack_ref: AttackEventsRef
    ) -> bool:
        """
        Send analysis alert with summary.
        
        Args:
            findings: Analysis findings
            ti_summary: Threat intelligence summary
            recommend: Recommendations
            attack_ref: Attack events reference
        
        Returns:
            True if successful, False otherwise
        """
        if not self.is_configured():
            return False
        
        # Build alert message
        message = self._build_alert_message(findings, ti_summary, recommend, attack_ref)
        
        # Debug log
        logger.debug(f"Alert message length: {len(message)} characters")
        logger.debug(f"Alert message preview: {message[:200]}...")
        
        # Use HTML parse mode instead of Markdown
        return self.send_message(message, parse_mode="HTML")
    
    def send_report_with_pdf(
        self,
        pdf_path: str,
        findings: FindingsSummary,
        attack_ref: AttackEventsRef
    ) -> bool:
        """
        Send PDF report with summary caption.
        
        Args:
            pdf_path: Path to PDF file
            findings: Analysis findings
            attack_ref: Attack events reference
        
        Returns:
            True if successful, False otherwise
        """
        if not self.is_configured():
            return False
        
        # Build caption
        caption = self._build_pdf_caption(findings, attack_ref)
        
        return self.send_document(pdf_path, caption)
    
    def _build_alert_message(
        self,
        findings: FindingsSummary,
        ti_summary: TISummary,
        recommend: RecommendSummary,
        attack_ref: AttackEventsRef
    ) -> str:
        """Build alert message text in Vietnamese."""
        severity_emoji = {
            'low': '🟢',
            'medium': '🟡',
            'high': '🔴',
            'critical': '🚨'
        }
        
        severity_vn = {
            'low': 'Thấp',
            'medium': 'Trung Bình',
            'high': 'Cao',
            'critical': 'Nghiêm Trọng'
        }
        
        emoji = severity_emoji.get(findings['severity_level'], '⚪')
        severity_text = severity_vn.get(findings['severity_level'], findings['severity_level'].upper())
        
        # Use HTML instead of Markdown to avoid parsing issues
        message = f"""
{emoji} <b>Cảnh Báo Phân Tích Bảo Mật</b>

<b>Mã Báo Cáo:</b> <code>{attack_ref['report_id']}</code>
<b>Mức Độ:</b> <b>{severity_text}</b>

📊 <b>Tóm Tắt Phân Tích:</b>
• Tổng Sự Kiện: {findings['total_events']}
• Sự Kiện Tấn Công: {findings['total_attack_events']}
• Tỷ Lệ Tấn Công: {findings['total_attack_events']/findings['total_events']*100:.1f}%

"""
        
        # Attack breakdown (top 3 only to keep message short)
        if findings['attack_breakdown']:
            message += "🎯 <b>Các Loại Tấn Công:</b>\n"
            for ab in findings['attack_breakdown'][:3]:  # Top 3
                message += f"• {ab['attack_type'].upper()}: {ab['count']} ({ab['percentage']:.1f}%)\n"
            if len(findings['attack_breakdown']) > 3:
                message += f"• ... và {len(findings['attack_breakdown']) - 3} loại khác\n"
            message += "\n"
        
        # MITRE techniques
        if findings.get('mitre_techniques'):
            message += "🔍 <b>MITRE ATT&CK Techniques:</b>\n"
            for tech in findings['mitre_techniques'][:5]:
                message += f"• {tech}\n"
            message += "\n"
        
        # TI summary (handle None)
        if ti_summary and isinstance(ti_summary, dict) and ti_summary.get('ti_overall'):
            ti_overall = ti_summary['ti_overall']
            max_risk = ti_overall.get('max_risk', 'unknown')
            risk_vn = {
                'low': 'Thấp',
                'medium': 'Trung Bình',
                'high': 'Cao',
                'critical': 'Nghiêm Trọng',
                'unknown': 'Chưa Xác Định'
            }
            risk_text = risk_vn.get(max_risk, max_risk.upper())
            
            message += f"🔒 <b>Threat Intelligence:</b>\n"
            message += f"• Mức Rủi Ro Cao Nhất: {risk_text}\n"
            message += f"• Số IOC Rủi Ro Cao: {len(ti_overall.get('high_risk_iocs', []))}\n\n"
        else:
            message += f"🔒 <b>Threat Intelligence:</b> Không khả dụng\n\n"
        
        # Recommendations (top 2 only)
        message += f"💡 <b>Hành Động Ngay ({len(recommend['immediate_actions'])}):</b>\n"
        for action in recommend['immediate_actions'][:2]:  # Top 2
            # Truncate long actions and escape HTML
            action_text = action if len(action) < 80 else action[:77] + '...'
            # Escape HTML special chars
            action_text = action_text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            message += f"• {action_text}\n"
        
        if len(recommend['immediate_actions']) > 2:
            message += f"• ... và {len(recommend['immediate_actions']) - 2} hành động khác\n"
        
        message += f"\n📄 <b>Báo cáo đầy đủ và CSV đang được gửi...</b>"
        
        return message
    
    def _build_pdf_caption(
        self,
        findings: FindingsSummary,
        attack_ref: AttackEventsRef
    ) -> str:
        """Build PDF caption in Vietnamese."""
        severity_emoji = {
            'low': '🟢',
            'medium': '🟡',
            'high': '🔴',
            'critical': '🚨'
        }
        
        severity_vn = {
            'low': 'Thấp',
            'medium': 'Trung Bình',
            'high': 'Cao',
            'critical': 'Nghiêm Trọng'
        }
        
        emoji = severity_emoji.get(findings['severity_level'], '⚪')
        severity_text = severity_vn.get(findings['severity_level'], findings['severity_level'].upper())
        
        caption = f"""📄 Báo Cáo Phân Tích Bảo Mật {emoji}

Mã Báo Cáo: {attack_ref['report_id']}
Mức Độ: {severity_text}
Tấn Công: {findings['total_attack_events']}/{findings['total_events']} sự kiện

Báo cáo PDF đầy đủ đính kèm."""
        
        return caption
    
    def send_complete_report(
        self,
        findings: FindingsSummary,
        ti_summary: TISummary,
        recommend: RecommendSummary,
        attack_ref: AttackEventsRef,
        pdf_path: Optional[str] = None,
        csv_path: Optional[str] = None
    ) -> bool:
        """
        Send complete report with alert, PDF, and CSV.
        
        Args:
            findings: Analysis findings
            ti_summary: Threat intelligence summary
            recommend: Recommendations
            attack_ref: Attack events reference
            pdf_path: Path to PDF file (optional)
            csv_path: Path to CSV file (optional)
        
        Returns:
            True if all messages sent successfully
        """
        if not self.is_configured():
            logger.warning("Telegram not configured, skipping notification")
            return False
        
        success = True
        
        # 1. Send alert message
        logger.info("Sending Telegram alert message...")
        alert_sent = self.send_analysis_alert(findings, ti_summary, recommend, attack_ref)
        if alert_sent:
            logger.info("✅ Alert message sent successfully")
        else:
            logger.error("❌ Failed to send alert message")
            success = False
        
        # Small delay between messages
        import time
        time.sleep(1)
        
        # 2. Send PDF if available
        if pdf_path:
            logger.info(f"Sending PDF report: {pdf_path}")
            time.sleep(1)  # Delay between messages
            caption = self._build_pdf_caption(findings, attack_ref)
            pdf_sent = self.send_document(pdf_path, caption)
            if pdf_sent:
                logger.info("✅ PDF report sent successfully")
            else:
                logger.error("❌ Failed to send PDF report")
                success = False
        
        # 3. Send CSV if available
        if csv_path:
            logger.info(f"Sending CSV export: {csv_path}")
            time.sleep(1)  # Delay between messages
            csv_caption = f"""📊 Dữ Liệu Sự Kiện Tấn Công (CSV)

Mã Báo Cáo: {attack_ref['report_id']}
Số Sự Kiện: {attack_ref['total_attack_events']}

File CSV chứa chi tiết tất cả sự kiện tấn công."""
            csv_sent = self.send_document(csv_path, csv_caption)
            if csv_sent:
                logger.info("✅ CSV export sent successfully")
            else:
                logger.error("❌ Failed to send CSV export")
                success = False
        
        if success:
            logger.info("✅ All Telegram notifications sent successfully")
        else:
            logger.warning("⚠️ Some Telegram notifications failed")
        
        return success
      