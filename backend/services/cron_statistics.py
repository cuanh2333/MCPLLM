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
    """Read IP details from CSV file with Asset DB and TI cache integration."""
    import csv
    import ast
    from collections import defaultdict
    
    ip_attacks = defaultdict(lambda: {"count": 0, "types": set()})
    
    try:
        # Fix BOM issue
        with open(csv_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                src_ip = row.get('src_ip', 'Unknown')
                attack_type = row.get('attack_type', 'Unknown')
                
                ip_attacks[src_ip]["count"] += 1
                ip_attacks[src_ip]["types"].add(attack_type)
        
        # Load TI cache for IP reputation data
        ti_cache = {}
        ti_cache_path = "./output/ti_cache.json"
        if os.path.exists(ti_cache_path):
            try:
                with open(ti_cache_path, 'r', encoding='utf-8') as f:
                    ti_cache = json.load(f)
            except Exception as e:
                print(f"Error reading TI cache: {e}")
        
        # Convert to list with Asset DB and TI integration
        ip_details = []
        for ip, data in sorted(ip_attacks.items(), key=lambda x: x[1]["count"], reverse=True)[:10]:
            # Get IP reputation data - Priority order: Asset DB > TI cache > IP range
            status = "unknown"
            status_text = "Chưa kiểm tra"
            severity = "5.0"
            
            # Priority 1: Check Asset DB first
            try:
                asset_db_path = "./backend/asset_db.json"
                asset_info = None
                if os.path.exists(asset_db_path):
                    with open(asset_db_path, 'r', encoding='utf-8') as f:
                        asset_db = json.load(f)
                        asset_info = asset_db.get('assets', {}).get(ip)
                
                if asset_info:
                    asset_type = asset_info.get('type', '')
                    asset_label = asset_info.get('label', '')
                    asset_description = asset_info.get('description', '')
                    
                    if asset_type == 'PENTEST' or asset_label == 'AUTHORIZED_ATTACKER':
                        status = "safe"
                        status_text = f"IP Pentest được ủy quyền ({asset_description})"
                        severity = "2.0"
                    elif asset_label == 'PROTECTED_ASSET':
                        status = "safe"
                        status_text = f"Tài sản được bảo vệ ({asset_description})"
                        severity = "1.0"
                    elif asset_type == 'SERVER':
                        status = "safe"
                        status_text = f"Máy chủ nội bộ ({asset_description})"
                        severity = "1.0"
                    elif asset_type == 'COLLECTOR':
                        status = "safe"
                        status_text = f"Log Collector ({asset_description})"
                        severity = "1.0"
                    else:
                        status = "safe"
                        status_text = f"Tài sản nội bộ ({asset_type})"
                        severity = "1.0"
            except Exception as e:
                asset_info = None
            
            # Priority 2: Check TI cache if not in Asset DB
            if not asset_info and ip in ti_cache:
                ti_data = ti_cache[ip].get('ti_data', {})
                abuseipdb_str = ti_data.get('abuseipdb', '')
                
                if abuseipdb_str and abuseipdb_str != 'None':
                    try:
                        abuseipdb_data = ast.literal_eval(abuseipdb_str)
                        confidence_score = abuseipdb_data.get('abuse_confidence_score', 0)
                        total_reports = abuseipdb_data.get('total_reports', 0)
                        usage_type = abuseipdb_data.get('usage_type', '')
                        
                        if usage_type == 'Reserved':
                            status = "safe"
                            status_text = "IP nội bộ"
                            severity = "1.0"
                        elif confidence_score == 0 and total_reports == 0:
                            status = "safe"
                            status_text = "Không có báo cáo độc hại"
                            severity = "2.0"
                        elif confidence_score > 0:
                            if confidence_score >= 75:
                                status = "malicious"
                                status_text = f"Độc hại cao ({confidence_score}% confidence)"
                                severity = "9.0"
                            elif confidence_score >= 25:
                                status = "suspicious"
                                status_text = f"Khả nghi ({confidence_score}% confidence)"
                                severity = "7.0"
                            else:
                                status = "low_risk"
                                status_text = f"Rủi ro thấp ({confidence_score}% confidence)"
                                severity = "4.0"
                        else:
                            status = "unknown"
                            status_text = "Dữ liệu không đầy đủ"
                            severity = "5.0"
                    except Exception as e:
                        status = "unknown"
                        status_text = "Lỗi phân tích dữ liệu"
                        severity = "5.0"
                else:
                    status = "unknown"
                    status_text = "Không có dữ liệu AbuseIPDB"
                    severity = "5.0"
            elif not asset_info:
                # Priority 3: Not in Asset DB and not in TI cache
                if ip.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                                 '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                                 '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
                                 '127.', 'localhost')):
                    status = "safe"
                    status_text = "IP nội bộ (chưa kiểm tra AbuseIPDB)"
                    severity = "3.0"
                else:
                    status = "unknown"
                    status_text = "IP ngoại vi chưa kiểm tra AbuseIPDB"
                    severity = "5.0"
            
            ip_details.append({
                "ip": ip,
                "count": data["count"],
                "attack_types": ", ".join(sorted(data["types"])),
                "status": status,
                "status_text": status_text,
                "severity": severity
            })
        
        return ip_details
        
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return []
