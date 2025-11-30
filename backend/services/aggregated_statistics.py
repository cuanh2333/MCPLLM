"""
Aggregated statistics from analysis_runs_metadata.json.
Shows statistics for all runs (cron, query, file) combined or filtered by source.
"""
import json
import os
from typing import Dict, List, Optional


def get_aggregated_statistics(source_filter: Optional[str] = None) -> Dict:
    """
    Get aggregated statistics from all analysis runs.
    
    Args:
        source_filter: Filter by source type ('cron', 'query', 'file', or None for all)
    
    Returns:
        Dictionary with aggregated statistics
    """
    metadata_file = "./output/analysis_runs_metadata.json"
    
    if not os.path.exists(metadata_file):
        return _empty_stats()
    
    with open(metadata_file, 'r', encoding='utf-8') as f:
        all_runs = json.load(f)
    
    # Filter by source if specified
    if source_filter and source_filter != 'all':
        filtered_runs = {k: v for k, v in all_runs.items() 
                        if v.get('source_type') == source_filter}
    else:
        filtered_runs = all_runs
    
    if not filtered_runs:
        return _empty_stats()
    
    # Aggregate statistics
    total_events = sum(run.get('total_events', 0) for run in filtered_runs.values())
    total_attack_events = sum(run.get('total_attack_events', 0) for run in filtered_runs.values())
    total_runs = len(filtered_runs)
    runs_with_attacks = sum(1 for run in filtered_runs.values() if run.get('has_attack', False))
    
    # Get breakdown by source type
    source_breakdown = _get_source_breakdown(filtered_runs)
    
    # Get recent runs (last 10)
    recent_runs = _get_recent_runs(filtered_runs, limit=10)
    
    # Get IP details from latest CSV with attacks
    ip_details = _get_aggregated_ip_details(filtered_runs)
    
    return {
        "total_events": total_events,
        "total_attack_events": total_attack_events,
        "total_runs": total_runs,
        "runs_with_attacks": runs_with_attacks,
        "source_breakdown": source_breakdown,
        "recent_runs": recent_runs,
        "ip_details": ip_details,
        "trend_data": [],  # Could be calculated from recent_runs
        "attack_trend": []  # Could be calculated from recent_runs
    }


def _empty_stats() -> Dict:
    """Return empty statistics structure."""
    return {
        "total_events": 0,
        "total_attack_events": 0,
        "total_runs": 0,
        "runs_with_attacks": 0,
        "source_breakdown": [],
        "recent_runs": [],
        "ip_details": [],
        "trend_data": [],
        "attack_trend": []
    }


def _get_source_breakdown(runs: Dict) -> List[Dict]:
    """Get breakdown by source type."""
    from collections import defaultdict
    
    breakdown = defaultdict(lambda: {
        'total_events': 0,
        'attack_events': 0,
        'runs': 0,
        'runs_with_attacks': 0
    })
    
    for run_data in runs.values():
        source = run_data.get('source_type', 'unknown')
        breakdown[source]['total_events'] += run_data.get('total_events', 0)
        breakdown[source]['attack_events'] += run_data.get('total_attack_events', 0)
        breakdown[source]['runs'] += 1
        if run_data.get('has_attack', False):
            breakdown[source]['runs_with_attacks'] += 1
    
    return [
        {
            'source_type': source,
            'total_events': data['total_events'],
            'attack_events': data['attack_events'],
            'runs': data['runs'],
            'runs_with_attacks': data['runs_with_attacks']
        }
        for source, data in breakdown.items()
    ]


def _get_recent_runs(runs: Dict, limit: int = 10) -> List[Dict]:
    """Get recent runs sorted by timestamp."""
    sorted_runs = sorted(runs.items(), key=lambda x: x[0], reverse=True)[:limit]
    
    return [
        {
            'run_id': run_id,
            'timestamp': run_data.get('timestamp'),
            'source_type': run_data.get('source_type'),
            'query': run_data.get('query', 'N/A'),
            'total_events': run_data.get('total_events', 0),
            'attack_events': run_data.get('total_attack_events', 0),
            'has_attack': run_data.get('has_attack', False)
        }
        for run_id, run_data in sorted_runs
    ]


def _get_aggregated_ip_details(runs: Dict) -> List[Dict]:
    """Get aggregated IP details from all CSV files with attacks."""
    import csv
    from collections import defaultdict
    import glob
    
    ip_attacks = defaultdict(lambda: {"count": 0, "types": set()})
    
    # Strategy 1: Get CSV paths from metadata
    runs_with_attacks = [
        (run_id, run_data) 
        for run_id, run_data in sorted(runs.items(), key=lambda x: x[0], reverse=True)
        if run_data.get('has_attack', False) and run_data.get('csv_path')
    ]
    
    csv_files_to_read = []
    
    # Read from metadata CSV paths
    for run_id, run_data in runs_with_attacks:
        csv_path = run_data.get('csv_path')
        if csv_path and os.path.exists(csv_path):
            csv_files_to_read.append(csv_path)
    
    # Strategy 2: If no CSV from metadata, scan output directory for all CSV files
    if not csv_files_to_read:
        csv_pattern = "./output/attack_events_*.csv"
        csv_files_to_read = glob.glob(csv_pattern)
        print(f"No CSV in metadata, found {len(csv_files_to_read)} CSV files in output directory")
    
    # Read all CSV files
    for csv_path in csv_files_to_read:
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    src_ip = row.get('src_ip', 'Unknown')
                    attack_type = row.get('attack_type', 'Unknown')
                    
                    ip_attacks[src_ip]["count"] += 1
                    ip_attacks[src_ip]["types"].add(attack_type)
        except Exception as e:
            print(f"Error reading CSV {csv_path}: {e}")
            continue
    
    # Convert to list and sort by count
    ip_details = []
    for ip, data in sorted(ip_attacks.items(), key=lambda x: x[1]["count"], reverse=True)[:20]:
        ip_details.append({
            "ip": ip,
            "count": data["count"],
            "attack_type": ", ".join(sorted(data["types"])),
            "status": "unknown",
            "status_text": "Chưa kiểm tra",
            "severity": "5.0"
        })
    
    return ip_details
