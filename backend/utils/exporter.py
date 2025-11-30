"""
CSV export module for V1 Log Analyzer System.

This module handles exporting attack events to CSV files for detailed investigation
and reporting. Only non-benign events are exported.
"""

import os
import logging
from datetime import datetime
from typing import Optional
import pandas as pd

from backend.models import Event, EventLabel
from backend.config import settings

# Configure logging
logger = logging.getLogger(__name__)


def export_attack_events_csv(
    events: list[Event],
    labels: dict[str, EventLabel]
) -> Optional[str]:
    """
    Export attack events to a timestamped CSV file (V2 extended).
    
    Filters events to only include non-benign attacks and exports them to a CSV
    file in the configured output directory. The filename includes a timestamp
    for uniqueness.
    
    Args:
        events: List of normalized Event objects
        labels: Dictionary mapping event_id to EventLabel (V2)
    
    Returns:
        Path to the exported CSV file, or None if no attack events found or export fails
    
    Requirements:
        - 5.1: Export all attack events (non-benign) to CSV
        - 5.2: CSV contains specified columns in correct order
        - 5.3: Filename includes timestamp
        - 5.4: Create output directory if needed
        - 8.4: Handle export errors gracefully
        - V2: Include additional fields (short_note, mitre_technique, confidence)
    """
    try:
        # Filter events to only include non-benign attacks
        attack_events = []
        for event in events:
            event_id = event['event_id']
            label = labels.get(event_id)
            
            # Skip if no label or not an attack
            if not label or not label['is_attack']:
                continue
            
            # Add attack classification to event data for CSV export (V2 extended)
            attack_event = {
                'event_id': event['event_id'],
                'timestamp': event['timestamp'],
                'src_ip': event['src_ip'],
                'method': event['method'],
                'uri': event['uri'],
                'status': event['status'],
                'attack_type': label['attack_type'],
                'confidence': label['confidence'],
                'mitre_technique': label['mitre_technique'] or '',
                'short_note': label['short_note'],
                'user_agent': event['user_agent'],
                'raw_log': event['raw_log']
            }
            attack_events.append(attack_event)
        
        # Return None if no attack events found
        if not attack_events:
            logger.info("No attack events to export")
            return None
        
        # Create output directory if it doesn't exist
        output_dir = settings.output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate timestamped filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"attack_events_{timestamp}.csv"
        csv_path = os.path.join(output_dir, filename)
        
        # Create DataFrame and export to CSV
        df = pd.DataFrame(attack_events)
        
        # Ensure column order matches requirements (V2: include new fields)
        column_order = [
            'attack_type', 'confidence', 'mitre_technique', 'event_id', 'timestamp',
            'src_ip', 'method', 'uri', 'status', 'short_note', 'user_agent', 'raw_log'
        ]
        df = df[column_order]
        
        # Export to CSV with UTF-8 BOM encoding (for Excel compatibility)
        df.to_csv(csv_path, index=False, encoding='utf-8-sig')
        
        logger.info(f"Exported {len(attack_events)} attack events to {csv_path}")
        return csv_path
    
    except Exception as e:
        # Log error but don't fail the entire analysis
        logger.error(f"Failed to export CSV: {e}")
        return None
