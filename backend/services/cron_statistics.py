"""
Cron-specific statistics aggregation.
Reads from analysis_runs_metadata.json and aggregates cron runs.
"""
import json
import os
from collections import defaultdict
from typing import Dict, List


def get_cron_statistics() -> Dict:
    """
    Get aggregated statistics from all cron runs.
    
    Returns:
        Dictionary with aggregated cron statistics
    """
    metadata_file = "./output/analysis_runs_metadata.json"
    
    if not os.path.exists(metadata_file):
        return {
            "total_events": 0,
            "total_attack_events": 0,
            "total_runs": 0,
            "runs_with_attacks": 0,
            "ip_details": [],
            "recent_runs": []
        }
    
    with open(metadata_file, 'r', encoding='utf-8') as f:
        all_runs = json.load(f)
    
    # Filter only cron runs
    cron_runs = {k: v for k, v in all_runs.items() if v.get('source_type') == 'cron'}
    
    if not cron_runs:
        return {
            "total_events": 0,
            "total_attack_events": 0,
            "total_runs": 0,
            "runs_with_attacks": 0,
            "ip_details": [],
            "recent_runs": []
        }
    
    # Aggregate statistics
    total_events = sum(run.get('total_events', 0) for run in cron_runs.values())
    total_attack_events = sum(run.get('total_attack_events', 0) for run in cron_runs.values())
    runs_with_attacks = sum(1 for run in cron_runs.values() if run.get('has_attack', False))
    
    # Get recent runs (last 10)
    sorted_runs = sorted(cron_runs.items(), key=lambda x: x[0], reverse=True)[:10]
    recent_runs = [
        {
            'run_id': run_id,
            'timestamp': run_data.get('timestamp'),
            'total_events': run_data.get('total_events', 0),
            'attack_events': run_data.get('total_attack_events', 0),
            'has_attack': run_data.get('has_attack', False)
        }
        for run_id, run_data in sorted_runs
    ]
    
    # Aggregate IP details from CSV files (if available)
    ip_details = []
    if total_attack_events > 0:
        # Read from latest CSV with attacks
        for run_id, run_data in sorted_runs:
            # Only read CSV if this specific run has attacks
            if run_data.get('has_attack', False):
                csv_path = run_data.get('csv_path')
                if csv_path and os.path.exists(csv_path):
                    ip_details = _read_ip_details_from_csv(csv_path)
                    break
    
    return {
        "total_events": total_events,
        "total_attack_events": total_attack_events,
        "total_runs": len(cron_runs),
        "runs_with_attacks": runs_with_attacks,
        "ip_details": ip_details,
        "recent_runs": recent_runs
    }


def _read_ip_details_from_csv(csv_path: str) -> List[Dict]:
    """Read IP details from CSV file."""
    import csv
    from collections import defaultdict
    
    ip_attacks = defaultdict(lambda: {"count": 0, "types": set()})
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                src_ip = row.get('src_ip', 'Unknown')
                attack_type = row.get('attack_type', 'Unknown')
                
                ip_attacks[src_ip]["count"] += 1
                ip_attacks[src_ip]["types"].add(attack_type)
        
        # Convert to list
        ip_details = []
        for ip, data in sorted(ip_attacks.items(), key=lambda x: x[1]["count"], reverse=True)[:10]:
            ip_details.append({
                "ip": ip,
                "count": data["count"],
                "attack_types": ", ".join(sorted(data["types"])),
                "status": "unknown",
                "status_text": "Chưa kiểm tra"
            })
        
        return ip_details
        
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return []
