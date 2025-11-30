"""
AssetAgent - Asset Enrichment

This agent enriches asset information by reading directly from asset_ip_mapping.csv.
"""

import logging
from typing import Dict, Any, List, Optional
import csv
import os

logger = logging.getLogger(__name__)


class AssetAgent:
    """Agent for enriching asset information."""
    
    def __init__(self, csv_path: str = "backend/asset_ip_mapping.csv"):
        """Initialize AssetAgent.
        
        Args:
            csv_path: Path to asset IP mapping CSV file
        """
        self.csv_path = csv_path
        self.assets = []
        self._load_assets()
        logger.info(f"[AssetAgent] Initialized with {len(self.assets)} assets")
    
    def _load_assets(self):
        """Load assets from CSV file."""
        try:
            if not os.path.exists(self.csv_path):
                logger.warning(f"[AssetAgent] CSV file not found: {self.csv_path}")
                return
            
            with open(self.csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                self.assets = list(reader)
            
            logger.info(f"[AssetAgent] Loaded {len(self.assets)} assets from CSV")
        except Exception as e:
            logger.error(f"[AssetAgent] Failed to load CSV: {e}")
            self.assets = []
    
    async def enrich_assets(
        self,
        query: str,
        context: Optional[str] = None
    ) -> Dict[str, Any]:
        """Enrich asset information based on user query.
        
        Args:
            query: User query about assets (e.g., "IP máy chủ của tôi là gì")
            context: Optional context from user query
            
        Returns:
            Asset summary with enriched information
        """
        logger.info(f"[AssetAgent] Enriching assets for query: {query}")
        
        try:
            query_lower = query.lower()
            
            # Determine what user is asking for
            if any(kw in query_lower for kw in ["pentest", "tấn công", "attacker", "authorized"]):
                # Looking for pentest IPs
                filtered = [a for a in self.assets if a.get('asset_type') == 'PENTEST']
                title = "**IP Pentest (Authorized Attackers):**\n"
            elif any(kw in query_lower for kw in ["server", "máy chủ", "protected", "bảo vệ"]):
                # Looking for servers
                filtered = [a for a in self.assets if a.get('asset_type') == 'SERVER']
                title = "**IP Máy chủ (Protected Assets):**\n"
            elif any(kw in query_lower for kw in ["collector", "thu thập", "log"]):
                # Looking for collectors
                filtered = [a for a in self.assets if a.get('asset_type') == 'COLLECTOR']
                title = "**IP Thu thập log (Collectors):**\n"
            else:
                # Show all assets
                filtered = self.assets
                title = "**Tất cả tài sản trong hệ thống:**\n"
            
            if not filtered:
                return {
                    "answer": "Không tìm thấy tài sản phù hợp với yêu cầu."
                }
            
            # Format answer
            answer_lines = [title]
            for asset in filtered:
                ip = asset.get('ip_address', 'N/A')
                hostname = asset.get('hostname', 'Unknown')
                asset_type = asset.get('asset_type', 'Unknown')
                label = asset.get('label', 'Unknown')
                description = asset.get('description', '')
                owner = asset.get('owner', '')
                location = asset.get('location', '')
                
                answer_lines.append(f"\n🖥️ **{hostname}** ({ip})")
                answer_lines.append(f"   - Loại: {asset_type}")
                answer_lines.append(f"   - Nhãn: {label}")
                if description:
                    answer_lines.append(f"   - Mô tả: {description}")
                if owner:
                    answer_lines.append(f"   - Chủ sở hữu: {owner}")
                if location:
                    answer_lines.append(f"   - Vị trí: {location}")
            
            answer = "\n".join(answer_lines)
            
            logger.info(f"[AssetAgent] Found {len(filtered)} matching assets")
            return {
                "answer": answer
            }
            
        except Exception as e:
            logger.error(f"[AssetAgent] Enrichment failed: {e}", exc_info=True)
            return {
                "answer": f"Lỗi khi truy vấn thông tin tài sản: {str(e)}"
            }
    

