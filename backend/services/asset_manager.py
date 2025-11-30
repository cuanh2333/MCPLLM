"""
Asset Manager - Fast in-memory asset lookup

Load asset DB once at startup, O(1) lookup for IP enrichment.
"""
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class AssetManager:
    """Quản lý thông tin asset (IP, domain) trong memory."""
    
    def __init__(self, asset_db_path: str = "backend/asset_db.json"):
        self.asset_db_path = Path(asset_db_path)
        self.assets = {}
        self.domains = {}
        self._load_asset_db()
    
    def _load_asset_db(self):
        """Load asset DB từ JSON file."""
        try:
            if not self.asset_db_path.exists():
                logger.warning(f"Asset DB not found: {self.asset_db_path}")
                return
            
            with open(self.asset_db_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.assets = data.get("assets", {})
            self.domains = data.get("domains", {})
            
            logger.info(f"Loaded {len(self.assets)} assets and {len(self.domains)} domains")
            
        except Exception as e:
            logger.error(f"Failed to load asset DB: {e}")
    
    def get_asset_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Lookup asset info by IP (O(1)).
        
        Returns:
            {
                "type": "SERVER" | "PENTEST" | "COLLECTOR",
                "label": "PROTECTED_ASSET" | "AUTHORIZED_ATTACKER" | ...,
                "description": "...",
                "severity_if_target": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
                "severity_if_source": "..."
            }
        """
        return self.assets.get(ip)
    
    def get_domain_info(self, domain: str) -> Optional[Dict[str, Any]]:
        """Lookup domain info."""
        return self.domains.get(domain.lower())
    
    def is_protected_asset(self, ip: str) -> bool:
        """Check if IP is a protected asset."""
        asset = self.get_asset_info(ip)
        return asset and asset.get("label") == "PROTECTED_ASSET"
    
    def is_pentest_ip(self, ip: str) -> bool:
        """Check if IP is authorized pentest."""
        asset = self.get_asset_info(ip)
        return asset and asset.get("type") == "PENTEST"
    
    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich event với asset information.
        
        Thêm fields:
        - source_asset_info
        - target_asset_info
        - is_protected_asset_attacked
        - adjusted_severity
        """
        enriched = event.copy()
        
        # Source IP enrichment
        source_ip = event.get("source_ip")
        if source_ip:
            source_info = self.get_asset_info(source_ip)
            if source_info:
                enriched["source_asset_info"] = source_info
        
        # Target IP enrichment
        target_ip = event.get("target_ip") or event.get("dest_ip")
        if target_ip:
            target_info = self.get_asset_info(target_ip)
            if target_info:
                enriched["target_asset_info"] = target_info
                
                # Adjust severity if protected asset is attacked
                if target_info.get("label") == "PROTECTED_ASSET":
                    enriched["is_protected_asset_attacked"] = True
                    enriched["adjusted_severity"] = target_info.get("severity_if_target", "HIGH")
        
        # Check if this is pentest activity
        if source_ip and self.is_pentest_ip(source_ip):
            enriched["is_pentest_activity"] = True
            enriched["pentest_note"] = "⚠️ Đây là IP Pentest/Nghiệp vụ - Hoạt động được phép"
            # Vẫn giữ severity gốc để cảnh báo, nhưng thêm context
            # Không tự động hạ xuống INFO
        
        return enriched
    
    def batch_enrich(self, events: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
        """Enrich multiple events at once."""
        return [self.enrich_event(event) for event in events]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get asset DB summary."""
        protected_assets = [ip for ip, info in self.assets.items() 
                           if info.get("label") == "PROTECTED_ASSET"]
        pentest_ips = [ip for ip, info in self.assets.items() 
                      if info.get("type") == "PENTEST"]
        
        return {
            "total_assets": len(self.assets),
            "total_domains": len(self.domains),
            "protected_assets": protected_assets,
            "pentest_ips": pentest_ips
        }


# Singleton instance
_asset_manager = None


def get_asset_manager() -> AssetManager:
    """Get or create AssetManager singleton."""
    global _asset_manager
    if _asset_manager is None:
        _asset_manager = AssetManager()
    return _asset_manager
