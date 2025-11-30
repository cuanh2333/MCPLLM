"""
Asset Enrichment Module

Enriches analysis results with asset context (pentest IPs, protected assets, etc.)
"""

import logging
from typing import Dict, Any, List
from backend.services.asset_ip_lookup import get_asset_lookup
from backend.models import Event, EventLabel, FindingsSummary

logger = logging.getLogger(__name__)


def enrich_findings_with_assets(
    findings: FindingsSummary,
    events: List[Event],
    labels: Dict[str, EventLabel]
) -> FindingsSummary:
    """
    Enrich findings summary with asset context.
    
    Adds information about:
    - Pentest/authorized attacker IPs
    - Protected asset targets
    - Business context for severity adjustment
    
    Args:
        findings: Original findings summary
        events: List of events
        labels: Event labels
        
    Returns:
        Enriched findings summary with asset context
    """
    logger.info("[AssetEnrichment] Enriching findings with asset context...")
    
    try:
        asset_lookup = get_asset_lookup()
        
        # Analyze source IPs
        pentest_ips = set()
        protected_targets = set()
        all_source_ips = set()
        
        for event in events:
            event_id = event['event_id']
            if event_id not in labels:
                continue
            
            label = labels[event_id]
            if not label.get('is_attack'):
                continue
            
            src_ip = event.get('src_ip')
            if src_ip:
                all_source_ips.add(src_ip)
                
                # Check if source is authorized attacker
                if asset_lookup.is_authorized_attacker(src_ip):
                    pentest_ips.add(src_ip)
                    logger.info(f"[AssetEnrichment] Found pentest IP: {src_ip}")
        
        # Add asset context to findings
        findings['asset_context'] = {
            'pentest_ips': list(pentest_ips),
            'pentest_attack_count': len([e for e in events if e.get('src_ip') in pentest_ips and labels.get(e['event_id'], {}).get('is_attack')]),
            'is_simulated_attack': len(pentest_ips) > 0,
            'protected_targets': list(protected_targets)
        }
        
        # Adjust severity if all attacks are from pentest IPs
        if pentest_ips and all_source_ips == pentest_ips:
            logger.info("[AssetEnrichment] All attacks from pentest IPs → severity: informational")
            findings['original_severity'] = findings['severity_level']
            findings['severity_level'] = 'low'  # Downgrade severity
            findings['severity_note'] = '⚠️ Tất cả tấn công đến từ IP pentest - đây là hoạt động NGHIỆP VỤ'
        elif pentest_ips:
            findings['severity_note'] = f'⚠️ Phát hiện {len(pentest_ips)} IP pentest trong {len(all_source_ips)} IP tấn công'
        
        # Update summary text
        if findings.get('asset_context', {}).get('is_simulated_attack'):
            original_summary = findings.get('summary_text', '')
            findings['summary_text'] = (
                f"⚠️ **HOẠT ĐỘNG PENTEST PHÁT HIỆN**\n\n"
                f"Phát hiện {len(pentest_ips)} IP pentest: {', '.join(pentest_ips)}\n"
                f"Đây là hoạt động NGHIỆP VỤ - không phải tấn công thật.\n\n"
                f"---\n\n{original_summary}"
            )
        
        logger.info(f"[AssetEnrichment] Enrichment complete: {len(pentest_ips)} pentest IPs found")
        return findings
        
    except Exception as e:
        logger.error(f"[AssetEnrichment] Failed: {e}", exc_info=True)
        return findings  # Return original if enrichment fails


def get_asset_context_for_report(findings: FindingsSummary) -> str:
    """
    Generate asset context section for report.
    
    Args:
        findings: Findings summary with asset context
        
    Returns:
        Markdown text for asset context section
    """
    asset_context = findings.get('asset_context', {})
    
    if not asset_context:
        return ""
    
    sections = []
    
    # Pentest IPs section
    if asset_context.get('pentest_ips'):
        pentest_ips = asset_context['pentest_ips']
        sections.append(
            f"### ⚠️ Hoạt Động Pentest\n\n"
            f"**Phát hiện {len(pentest_ips)} IP pentest:**\n"
        )
        for ip in pentest_ips:
            sections.append(f"- `{ip}` - IP pentest được ủy quyền\n")
        
        sections.append(
            f"\n**Tổng số tấn công từ IP pentest:** {asset_context.get('pentest_attack_count', 0)}\n\n"
            f"⚠️ **LƯU Ý:** Đây là hoạt động NGHIỆP VỤ (pentest/red team), "
            f"không phải tấn công thật từ bên ngoài.\n\n"
        )
    
    # Protected targets section
    if asset_context.get('protected_targets'):
        sections.append(
            f"### 🛡️ Tài Sản Được Bảo Vệ\n\n"
            f"Các tài sản quan trọng bị tấn công:\n"
        )
        for target in asset_context['protected_targets']:
            sections.append(f"- `{target}`\n")
        sections.append("\n")
    
    return "".join(sections)
