"""
Background Cron Scheduler for automated log analysis.

Provides API to start/stop scheduled analysis jobs.
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional
import httpx

logger = logging.getLogger(__name__)


class CronScheduler:
    """
    Background scheduler for automated log analysis.
    
    Features:
    - Start/stop scheduling via API
    - Configurable interval (default: 5 minutes)
    - Real-time monitoring (earliest=-5m, latest=now)
    - Automatic Telegram notifications
    """
    
    def __init__(self, backend_url: str = "http://127.0.0.1:8888"):
        self.backend_url = backend_url
        self.is_running = False
        self.task: Optional[asyncio.Task] = None
        self.interval_minutes = 5
        self.earliest_time = "-5m"
        self.latest_time = "now"
        
    async def start(self):
        """Start the cron scheduler."""
        if self.is_running:
            logger.warning("Cron scheduler already running")
            return False
        
        self.is_running = True
        self.task = asyncio.create_task(self._run_loop())
        logger.info(f"✅ Cron scheduler started (interval: {self.interval_minutes} minutes)")
        return True
    
    async def stop(self):
        """Stop the cron scheduler."""
        if not self.is_running:
            logger.warning("Cron scheduler not running")
            return False
        
        self.is_running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        
        logger.info("✅ Cron scheduler stopped")
        return True
    
    def get_status(self) -> dict:
        """Get current scheduler status."""
        return {
            "is_running": self.is_running,
            "interval_minutes": self.interval_minutes,
            "earliest_time": self.earliest_time,
            "latest_time": self.latest_time,
            "next_run": None  # TODO: track next run time
        }
    
    def reload_config(self):
        """Reload configuration from environment variables."""
        import os
        self.earliest_time = os.getenv("SPLUNK_EARLIEST_TIME", "-5m")
        self.latest_time = os.getenv("SPLUNK_LATEST_TIME", "now")
        logger.info(f"✅ Reloaded config: {self.earliest_time} to {self.latest_time}")
        return True
    
    async def _run_loop(self):
        """Main scheduler loop."""
        logger.info("Cron scheduler loop started")
        
        while self.is_running:
            try:
                # Run analysis
                await self._run_analysis()
                
                # Wait for next interval
                await asyncio.sleep(self.interval_minutes * 60)
                
            except asyncio.CancelledError:
                logger.info("Cron scheduler loop cancelled")
                break
            except Exception as e:
                logger.error(f"Error in cron scheduler loop: {e}", exc_info=True)
                # Continue running even if one iteration fails
                await asyncio.sleep(60)  # Wait 1 minute before retry
    
    async def _run_analysis(self):
        """Run a single analysis iteration."""
        try:
            logger.info("="*60)
            logger.info(f"Cron job triggered at {datetime.now()}")
            logger.info(f"Sliding window: {self.earliest_time} to {self.latest_time}")
            logger.info("="*60)
            
            # Prepare request
            # Note: send_telegram will be conditional based on attack detection
            # Note: No need to pass earliest_time/latest_time - cron_splunk_query uses default -5m to now
            payload = {
                "query": "Phân tích log từ Splunk có tấn công không?",
                "send_telegram": False,  # Will check and send only if has attack
                "source_label": "cron"
            }
            
            # Call backend API
            async with httpx.AsyncClient(timeout=300.0) as client:
                response = await client.post(
                    f"{self.backend_url}/smart-analyze",
                    json=payload
                )
                
                if response.status_code == 200:
                    result = response.json()
                    logger.info("✅ Cron analysis completed")
                    
                    findings = result.get('findings_summary', {})
                    if findings:
                        has_attack = findings.get('has_attack', False)
                        total_events = findings.get('total_events', 0)
                        attack_events = findings.get('total_attack_events', 0)
                        
                        logger.info(f"Has attack: {has_attack}")
                        logger.info(f"Total events: {total_events}")
                        logger.info(f"Attack events: {attack_events}")
                        
                        # Save cron run metadata even if no attacks
                        await self._save_cron_metadata(result)
                        
                        # Note: Telegram is already sent by workflow if attack detected
                        if has_attack and attack_events > 0:
                            logger.info("🚨 Attack detected! Telegram notification already sent by workflow")
                        else:
                            logger.info("✅ No attacks detected, no Telegram notification needed")
                else:
                    logger.error(f"❌ Cron analysis failed: {response.status_code}")
                    
        except Exception as e:
            logger.error(f"❌ Cron analysis error: {e}", exc_info=True)
    
    async def _save_cron_metadata(self, analysis_result: dict):
        """Save cron run metadata for tracking (even if no attacks)."""
        try:
            import json
            import os
            from datetime import datetime
            
            # Use the same metadata file as query runs
            metadata_file = "./output/analysis_runs_metadata.json"
            metadata = {}
            
            if os.path.exists(metadata_file):
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)
            
            # Add this run
            run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            findings = analysis_result.get('findings_summary', {})
            
            metadata[run_id] = {
                'source_type': 'cron',
                'timestamp': datetime.now().isoformat(),
                'query': f"Cron sliding window: {self.earliest_time} to {self.latest_time}",
                'log_source_type': 'splunk',
                'total_events': findings.get('total_events', 0),
                'total_attack_events': findings.get('total_attack_events', 0),
                'has_attack': findings.get('has_attack', False),
                'csv_path': analysis_result.get('attack_events_ref', {}).get('csv_path') if findings.get('has_attack') else None
            }
            
            # Keep only last 100 runs
            if len(metadata) > 100:
                sorted_keys = sorted(metadata.keys())
                for old_key in sorted_keys[:-100]:
                    del metadata[old_key]
            
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, ensure_ascii=False, indent=2)
            
            logger.info(f"✅ Saved cron run metadata: {run_id}")
            
        except Exception as e:
            logger.error(f"❌ Failed to save cron metadata: {e}", exc_info=True)
    



# Global scheduler instance
_scheduler: Optional[CronScheduler] = None


def get_scheduler() -> CronScheduler:
    """Get or create global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = CronScheduler()
    return _scheduler
