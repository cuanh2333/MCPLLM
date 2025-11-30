"""
Cron Job: Tự động phân tích log từ Splunk mỗi 5 phút

Chạy: python cron_log_analyzer.py
Hoặc setup cron: */5 * * * * python /path/to/cron_log_analyzer.py
"""

import asyncio
import logging
import sys
from datetime import datetime, timedelta
import httpx

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cron_analyzer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Config
BACKEND_URL = "http://127.0.0.1:8000"
ANALYSIS_INTERVAL_MINUTES = 5  # Phân tích log của 5 phút gần nhất
AUTO_SEND_TELEGRAM = True  # Tự động gửi Telegram cho cron job


async def analyze_recent_logs():
    """
    Phân tích log với sliding window.
    
    Sliding window logic:
    - Chạy mỗi 5 phút
    - Phân tích 5 phút cách đây 7 giờ
    - earliest=-7h-5m, latest=-7h
    
    Ví dụ: Nếu chạy lúc 17:00
    - Phân tích logs từ 10:00-10:05 (7 giờ trước)
    """
    try:
        logger.info("="*60)
        logger.info(f"Starting automated log analysis at {datetime.now()}")
        logger.info("="*60)
        
        # Sliding window: phân tích 5 phút cách đây 7 giờ
        # earliest=-7h-5m (7 giờ 5 phút trước)
        # latest=-7h (7 giờ trước)
        earliest = "-7h-5m"
        latest = "-7h"
        
        logger.info(f"Sliding window: earliest={earliest}, latest={latest}")
        logger.info(f"This analyzes logs from 7h5m ago to 7h ago")
        
        # Query cho cronjob - phân tích log từ Splunk
        query = "Phân tích log từ Splunk có tấn công không?"
        
        # Gọi backend API với custom time range (sliding window)
        payload = {
            "query": query,
            "send_telegram": AUTO_SEND_TELEGRAM,  # Tự động gửi Telegram
            "source_label": "cron",  # Đánh dấu đây là cron job
            "earliest_time": earliest,  # Override với sliding window
            "latest_time": latest
        }
        
        async with httpx.AsyncClient(timeout=300.0) as client:
            logger.info("Sending request to backend...")
            response = await client.post(
                f"{BACKEND_URL}/smart-analyze",
                json=payload
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info("✅ Analysis completed successfully")
                logger.info(f"Job type: {result.get('job_type')}")
                
                # Log summary
                findings = result.get('findings_summary', {})
                if findings:
                    logger.info(f"Has attack: {findings.get('has_attack')}")
                    logger.info(f"Total events: {findings.get('total_events')}")
                    logger.info(f"Attack events: {findings.get('total_attack_events')}")
                
                if AUTO_SEND_TELEGRAM:
                    logger.info("📱 Telegram notification sent automatically")
                
                return result
            else:
                logger.error(f"❌ Backend returned {response.status_code}: {response.text}")
                return None
                
    except Exception as e:
        logger.error(f"❌ Cron job failed: {e}", exc_info=True)
        return None


async def main():
    """Main entry point."""
    result = await analyze_recent_logs()
    
    if result:
        logger.info("="*60)
        logger.info("Cron job completed successfully")
        logger.info("="*60)
    else:
        logger.error("="*60)
        logger.error("Cron job failed")
        logger.error("="*60)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
