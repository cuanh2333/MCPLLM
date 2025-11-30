"""
Asset IP Lookup Module

Provides IP to Asset mapping functionality using CSV database.
"""

import pandas as pd
import logging
from typing import Optional, Dict, Any, List
from pathlib import Path

logger = logging.getLogger(__name__)


class AssetIPLookup:
    """Lookup asset information by IP address."""
    
    def __init__(self, csv_path: str = "backend/asset_ip_mapping.csv"):
        """Initialize asset lookup.
        
        Args:
            csv_path: Path to asset CSV file
        """
        self.csv_path = csv_path
        self.df = None
        self._load_csv()
    
    def _load_csv(self):
        """Load asset CSV into DataFrame."""
        try:
            if Path(self.csv_path).exists():
                self.df = pd.read_csv(self.csv_path)
                logger.info(f"[AssetIPLookup] Loaded {len(self.df)} assets from {self.csv_path}")
            else:
                logger.warning(f"[AssetIPLookup] CSV not found: {self.csv_path}")
                self.df = pd.DataFrame()
        except Exception as e:
            logger.error(f"[AssetIPLookup] Failed to load CSV: {e}")
            self.df = pd.DataFrame()
    
    def lookup_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Lookup asset info by IP address.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            Asset info dict or None if not found
        """
        if self.df is None or self.df.empty:
            return None
        
        # Find matching IP
        matches = self.df[self.df['ip_address'] == ip]
        
        if matches.empty:
            return None
        
        # Return first match as dict
        asset = matches.iloc[0].to_dict()
        
        # Clean up NaN values
        asset = {k: (v if pd.notna(v) else None) for k, v in asset.items()}
        
        logger.info(f"[AssetIPLookup] Found asset for {ip}: {asset.get('hostname')}")
        return asset
    
    def lookup_multiple_ips(self, ips: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
        """Lookup multiple IPs at once.
        
        Args:
            ips: List of IP addresses
            
        Returns:
            Dict mapping IP to asset info (or None if not found)
        """
        results = {}
        for ip in ips:
            results[ip] = self.lookup_ip(ip)
        return results
    
    def is_protected_asset(self, ip: str) -> bool:
        """Check if IP is a protected asset.
        
        Args:
            ip: IP address
            
        Returns:
            True if IP is a protected asset
        """
        asset = self.lookup_ip(ip)
        if not asset:
            return False
        
        return asset.get('label') == 'PROTECTED_ASSET'
    
    def is_authorized_attacker(self, ip: str) -> bool:
        """Check if IP is an authorized attacker (pentest).
        
        Args:
            ip: IP address
            
        Returns:
            True if IP is authorized attacker
        """
        asset = self.lookup_ip(ip)
        if not asset:
            return False
        
        return asset.get('label') == 'AUTHORIZED_ATTACKER'
    
    def get_severity_for_ip(self, ip: str, role: str = 'source') -> str:
        """Get severity level for IP based on role.
        
        Args:
            ip: IP address
            role: 'source' or 'target'
            
        Returns:
            Severity level (critical/high/medium/low/informational)
        """
        asset = self.lookup_ip(ip)
        if not asset:
            return 'medium'  # Default for unknown IPs
        
        if role == 'target':
            return asset.get('severity_if_target', 'medium')
        else:
            return asset.get('severity_if_source', 'low')
    
    def enrich_ip_info(self, ip: str, external_ti: Optional[Dict] = None) -> Dict[str, Any]:
        """Enrich IP with both asset DB and external TI info.
        
        Args:
            ip: IP address
            external_ti: External threat intelligence (e.g., from AbuseIPDB)
            
        Returns:
            Enriched IP info combining asset DB and TI
        """
        result = {
            'ip': ip,
            'asset_info': None,
            'ti_info': external_ti,
            'is_internal': False,
            'is_protected': False,
            'is_authorized_attacker': False,
            'recommended_severity': 'medium'
        }
        
        # Check asset DB
        asset = self.lookup_ip(ip)
        if asset:
            result['asset_info'] = asset
            result['is_internal'] = True
            result['is_protected'] = asset.get('label') == 'PROTECTED_ASSET'
            result['is_authorized_attacker'] = asset.get('label') == 'AUTHORIZED_ATTACKER'
            
            # Determine severity
            if result['is_authorized_attacker']:
                result['recommended_severity'] = 'informational'
            elif result['is_protected'] and external_ti:
                # Protected asset being attacked
                result['recommended_severity'] = 'critical'
            elif asset.get('severity_if_target'):
                result['recommended_severity'] = asset['severity_if_target']
        
        return result


# Global instance
_asset_lookup = None


def get_asset_lookup() -> AssetIPLookup:
    """Get global AssetIPLookup instance.
    
    Returns:
        AssetIPLookup instance
    """
    global _asset_lookup
    if _asset_lookup is None:
        _asset_lookup = AssetIPLookup()
    return _asset_lookup
