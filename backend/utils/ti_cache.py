"""
TI Cache Manager

Caches threat intelligence results to avoid redundant API calls.
"""

import json
import logging
import time
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class TICache:
    """
    Thread-safe TI cache with TTL (Time To Live).
    
    Features:
    - Persistent cache (saved to disk)
    - TTL-based expiration (default: 24 hours)
    - Automatic cleanup of expired entries
    """
    
    def __init__(self, cache_file: str = "./output/ti_cache.json", ttl_hours: int = 24):
        """
        Initialize TI cache.
        
        Args:
            cache_file: Path to cache file
            ttl_hours: Time to live in hours (default: 24)
        """
        self.cache_file = Path(cache_file)
        self.ttl_seconds = ttl_hours * 3600
        self.cache: Dict[str, Dict[str, Any]] = {}
        self._load_cache()
        logger.info(f"TICache initialized (TTL: {ttl_hours}h, file: {cache_file})")
    
    def _load_cache(self):
        """Load cache from disk."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.cache = json.load(f)
                
                # Clean expired entries on load
                self._cleanup_expired()
                logger.info(f"Loaded {len(self.cache)} cached IPs")
            else:
                logger.info("No existing cache file, starting fresh")
        except Exception as e:
            logger.error(f"Failed to load cache: {e}")
            self.cache = {}
    
    def _save_cache(self):
        """Save cache to disk."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")
    
    def _cleanup_expired(self):
        """Remove expired entries from cache."""
        current_time = time.time()
        expired_keys = []
        
        for ip, data in self.cache.items():
            if current_time - data.get('timestamp', 0) > self.ttl_seconds:
                expired_keys.append(ip)
        
        for key in expired_keys:
            del self.cache[key]
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def get(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Get cached TI data for an IP.
        
        Args:
            ip: IP address
        
        Returns:
            Cached data or None if not found/expired
        """
        if ip not in self.cache:
            return None
        
        data = self.cache[ip]
        current_time = time.time()
        
        # Check if expired
        if current_time - data.get('timestamp', 0) > self.ttl_seconds:
            logger.debug(f"Cache expired for {ip}")
            del self.cache[ip]
            return None
        
        logger.debug(f"Cache hit for {ip}")
        return data.get('ti_data')
    
    def set(self, ip: str, ti_data: Dict[str, Any]):
        """
        Cache TI data for an IP.
        
        Args:
            ip: IP address
            ti_data: TI data to cache
        """
        self.cache[ip] = {
            'timestamp': time.time(),
            'ti_data': ti_data
        }
        self._save_cache()
        logger.debug(f"Cached TI data for {ip}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        current_time = time.time()
        valid_entries = sum(
            1 for data in self.cache.values()
            if current_time - data.get('timestamp', 0) <= self.ttl_seconds
        )
        
        return {
            'total_entries': len(self.cache),
            'valid_entries': valid_entries,
            'ttl_hours': self.ttl_seconds / 3600
        }
    
    def clear(self):
        """Clear all cache entries."""
        self.cache = {}
        self._save_cache()
        logger.info("Cache cleared")


# Global cache instance
_ti_cache: Optional[TICache] = None


def get_ti_cache(ttl_hours: int = 24) -> TICache:
    """
    Get global TI cache instance (singleton).
    
    Args:
        ttl_hours: Time to live in hours
    
    Returns:
        TICache instance
    """
    global _ti_cache
    if _ti_cache is None:
        _ti_cache = TICache(ttl_hours=ttl_hours)
    return _ti_cache
