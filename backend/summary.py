"""
Findings summary generation module for V1 Log Analyzer System.

This module provides functions to generate high-level summaries of attack detection
results, including severity calculation, attack breakdowns, and Vietnamese summaries.
"""

from typing import Literal, Union
from backend.models import Event, EventLabel, AttackBreakdown, FindingsSummary


def calculate_severity(
    total_attack_events: int,
    attack_types: list[str]
) -> Literal['low', 'medium', 'high', 'critical']:
    """
    Calculate severity level based on attack volume and types (V2 extended).
    
    Severity rules:
    - CRITICAL: total_attack_events >= 200 OR (>= 50 AND contains rce/xxe)
    - HIGH: total_attack_events >= 100 OR contains rce/xxe/sqli
    - MEDIUM: total_attack_events >= 10 OR contains xss/lfi/command_injection
    - LOW: all other cases
    
    Args:
        total_attack_events: Total number of attack events detected
        attack_types: List of unique attack type strings
    
    Returns:
        Severity level: 'low', 'medium', 'high', or 'critical'
    
    Requirements: 4.3, 4.4, 4.5, V2
    """
    critical_attacks = ['rce', 'xxe']
    high_risk_attacks = ['rce', 'xxe', 'sqli']
    medium_risk_attacks = ['xss', 'lfi', 'command_injection']
    
    # Check for critical severity
    if total_attack_events >= 200:
        return 'critical'
    
    if total_attack_events >= 50:
        for attack_type in attack_types:
            if attack_type in critical_attacks:
                return 'critical'
    
    # Check for high severity
    if total_attack_events >= 100:
        return 'high'
    
    for attack_type in attack_types:
        if attack_type in high_risk_attacks:
            return 'high'
    
    # Check for medium severity
    if total_attack_events >= 10:
        return 'medium'
    
    for attack_type in attack_types:
        if attack_type in medium_risk_attacks:
            return 'medium'
    
    # Default to low severity
    return 'low'


def generate_findings_summary(
    events: list[Event],
    labels: Union[dict[str, str], dict[str, EventLabel]]
) -> FindingsSummary:
    """
    Generate comprehensive findings summary from analyzed events (V2 extended).
    
    Processes events and their attack classifications to produce:
    - Attack detection status
    - Event counts (total and attacks)
    - Detailed breakdown by attack type with counts, percentages, and source IPs
    - MITRE ATT&CK techniques (V2)
    - Severity level assessment
    - Vietnamese summary text
    - Sample events (V2)
    
    Args:
        events: List of normalized Event objects
        labels: Dictionary mapping event_id to attack_type (V1) or EventLabel (V2)
    
    Returns:
        FindingsSummary with complete analysis results
    
    Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 8.2, V2-R1
    """
    # Only count events that have labels (Requirement 8.2)
    labeled_events = [e for e in events if e['event_id'] in labels]
    total_events = len(labeled_events)
    
    # Build attack statistics and collect MITRE techniques
    attack_stats: dict[str, dict] = {}
    mitre_techniques = set()
    sample_events = []
    
    for event in labeled_events:
        event_id = event['event_id']
        label = labels.get(event_id)
        
        # Handle both V1 (str) and V2 (EventLabel) formats
        if isinstance(label, str):
            attack_type = label
            is_attack = (attack_type != 'benign')
            mitre_tech = None
        else:
            attack_type = label['attack_type']
            is_attack = label['is_attack']
            mitre_tech = label.get('mitre_technique')
        
        # Skip benign events
        if not is_attack or attack_type == 'benign':
            continue
        
        # Collect MITRE technique
        if mitre_tech:
            mitre_techniques.add(mitre_tech)
        
        # Initialize attack type entry if not exists
        if attack_type not in attack_stats:
            attack_stats[attack_type] = {
                'count': 0,
                'source_ips': set()
            }
        
        # Update statistics
        attack_stats[attack_type]['count'] += 1
        
        # Add source IP if available
        if event['src_ip']:
            attack_stats[attack_type]['source_ips'].add(event['src_ip'])
        
        # Collect sample events (max 10)
        if len(sample_events) < 10:
            sample_events.append({
                'event_id': event_id,
                'attack_type': attack_type,
                'src_ip': event['src_ip'],
                'uri': event['uri'],
                'method': event['method']
            })
    
    # Calculate total attack events
    total_attack_events = sum(stats['count'] for stats in attack_stats.values())
    has_attack = total_attack_events > 0
    
    # Build attack breakdown list
    attack_breakdown: list[AttackBreakdown] = []
    
    for attack_type, stats in attack_stats.items():
        count = stats['count']
        
        # Zero-division check for percentage calculation (Requirement 8.2)
        percentage = (count / total_attack_events * 100) if total_attack_events > 0 else 0.0
        
        attack_breakdown.append(AttackBreakdown(
            attack_type=attack_type,
            count=count,
            percentage=round(percentage, 2),
            source_ips=sorted(list(stats['source_ips']))
        ))
    
    # Sort by count descending
    attack_breakdown.sort(key=lambda x: x['count'], reverse=True)
    
    # Calculate severity level
    attack_types = list(attack_stats.keys())
    severity_level = calculate_severity(total_attack_events, attack_types)
    
    # Generate Vietnamese summary text
    summary_text = _generate_vietnamese_summary(
        has_attack=has_attack,
        total_events=total_events,
        total_attack_events=total_attack_events,
        attack_breakdown=attack_breakdown,
        severity_level=severity_level
    )
    
    return FindingsSummary(
        has_attack=has_attack,
        total_events=total_events,
        total_attack_events=total_attack_events,
        attack_breakdown=attack_breakdown,
        mitre_techniques=sorted(list(mitre_techniques)),
        severity_level=severity_level,
        summary_text=summary_text,
        sample_events=sample_events
    )


def _generate_vietnamese_summary(
    has_attack: bool,
    total_events: int,
    total_attack_events: int,
    attack_breakdown: list[AttackBreakdown],
    severity_level: str
) -> str:
    """
    Generate human-readable summary in Vietnamese.
    
    Args:
        has_attack: Whether any attacks were detected
        total_events: Total number of events analyzed
        total_attack_events: Number of attack events
        attack_breakdown: List of attack breakdowns
        severity_level: Severity level (low/medium/high)
    
    Returns:
        Vietnamese summary text
    
    Requirements: 4.5
    """
    if not has_attack:
        return (
            f"Phân tích hoàn tất {total_events} sự kiện. "
            f"Không phát hiện hoạt động tấn công đáng ngờ. "
            f"Tất cả các yêu cầu được đánh giá là lưu lượng hợp lệ."
        )
    
    # Severity level in Vietnamese
    severity_vn = {
        'low': 'Thấp',
        'medium': 'Trung bình',
        'high': 'Cao',
        'critical': 'Nghiêm trọng'
    }
    
    # Build attack type summary
    attack_summary_parts = []
    for breakdown in attack_breakdown[:3]:  # Top 3 attack types
        attack_type = breakdown['attack_type']
        count = breakdown['count']
        percentage = breakdown['percentage']
        
        # Translate attack types to Vietnamese
        attack_type_vn = {
            'sqli': 'SQL Injection',
            'xss': 'Cross-Site Scripting (XSS)',
            'lfi': 'Local File Inclusion',
            'rfi': 'Remote File Inclusion',
            'rce': 'Remote Code Execution',
            'xxe': 'XML External Entity',
            'path_traversal': 'Path Traversal',
            'command_injection': 'Command Injection'
        }.get(attack_type, attack_type.upper())
        
        attack_summary_parts.append(
            f"{attack_type_vn} ({count} sự kiện, {percentage}%)"
        )
    
    attack_list = ", ".join(attack_summary_parts)
    
    summary = (
        f"Phân tích hoàn tất {total_events} sự kiện. "
        f"Phát hiện {total_attack_events} sự kiện tấn công "
        f"({round(total_attack_events / total_events * 100, 1)}% tổng số). "
        f"Mức độ nghiêm trọng: {severity_vn[severity_level]}. "
        f"Các loại tấn công chính: {attack_list}."
    )
    
    # Add recommendation based on severity
    if severity_level == 'critical':
        summary += " Khuyến nghị: KHẨN CẤP - Cần xử lý ngay lập tức và kích hoạt quy trình ứng phó sự cố."
    elif severity_level == 'high':
        summary += " Khuyến nghị: Cần xử lý khẩn cấp và điều tra ngay lập tức."
    elif severity_level == 'medium':
        summary += " Khuyến nghị: Cần xem xét và xử lý trong thời gian sớm nhất."
    else:
        summary += " Khuyến nghị: Theo dõi và xem xét định kỳ."
    
    return summary
