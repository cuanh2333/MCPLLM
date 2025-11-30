"""
Rule Exporter - Export generated rules to files

Tự động lưu Sigma và SPL rules ra files
"""
import os
import logging
from datetime import datetime
from typing import Optional
from backend.models import GenRuleSummary

logger = logging.getLogger(__name__)


def export_rules(genrule_summary: GenRuleSummary, output_dir: str = "./output") -> dict:
    """
    Export generated rules to files.
    
    Args:
        genrule_summary: Generated rules
        output_dir: Output directory
        
    Returns:
        Dictionary with file paths
    """
    try:
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        attack_type = genrule_summary['main_attack_type']
        
        # File paths
        sigma_file = os.path.join(output_dir, f"sigma_rule_{attack_type}_{timestamp}.yml")
        spl_file = os.path.join(output_dir, f"splunk_spl_{attack_type}_{timestamp}.txt")
        notes_file = os.path.join(output_dir, f"rule_notes_{attack_type}_{timestamp}.txt")
        
        # Export Sigma rule
        if genrule_summary['sigma_rule']:
            with open(sigma_file, 'w', encoding='utf-8') as f:
                f.write(genrule_summary['sigma_rule'])
            logger.info(f"Exported Sigma rule to {sigma_file}")
        
        # Export SPL query
        if genrule_summary['splunk_spl']:
            with open(spl_file, 'w', encoding='utf-8') as f:
                f.write(genrule_summary['splunk_spl'])
            logger.info(f"Exported Splunk SPL to {spl_file}")
        
        # Export notes
        if genrule_summary['notes']:
            with open(notes_file, 'w', encoding='utf-8') as f:
                f.write(f"Detection Rules Notes\n")
                f.write(f"{'='*80}\n\n")
                f.write(f"Attack Type: {attack_type}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"{'='*80}\n")
                f.write(f"NOTES:\n")
                f.write(f"{'='*80}\n\n")
                f.write(genrule_summary['notes'])
            logger.info(f"Exported notes to {notes_file}")
        
        return {
            'sigma_file': sigma_file,
            'spl_file': spl_file,
            'notes_file': notes_file
        }
    
    except Exception as e:
        logger.error(f"Failed to export rules: {e}")
        return {}
