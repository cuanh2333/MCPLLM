"""
Time Parser - Parse natural language time expressions to Splunk queries

Examples:
- "log 2h qua" → earliest=-2h
- "log trong 5 phút gần nhất" → earliest=-5m
- "log hôm nay" → earliest=@d
- "log từ 14:00 đến 15:00" → earliest="14:00:00" latest="15:00:00"

Timezone Handling:
- If TIMEZONE_OFFSET_HOURS is set, automatically adjusts time for Splunk UTC logs
- Example: Local UTC+7, Splunk UTC+0 → offset=7 → "2h qua" becomes "9h qua" in Splunk
"""

import re
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)

# Get timezone offset from environment
TIMEZONE_OFFSET_HOURS = int(os.getenv("TIMEZONE_OFFSET_HOURS", "0"))


class TimeParser:
    """Parse natural language time expressions."""
    
    @staticmethod
    def apply_timezone_offset(earliest: str, latest: str = "now") -> tuple[str, str]:
        """
        Apply timezone offset to time expressions.
        
        If Splunk logs are in UTC+0 but local time is UTC+7,
        we need to subtract 7 hours from the query time.
        
        Example:
        - User asks "2h qua" at 15:00 local (UTC+7)
        - In UTC+0, it's 08:00
        - To get logs from 13:00-15:00 local (06:00-08:00 UTC),
          we need to query "9h qua" (2h + 7h offset)
        
        Args:
            earliest: Earliest time (e.g., "-2h", "@d")
            latest: Latest time (default: "now")
            
        Returns:
            Adjusted (earliest, latest) tuple
        """
        if TIMEZONE_OFFSET_HOURS == 0:
            return earliest, latest
        
        # Handle relative time expressions like "-2h", "-30m"
        if earliest.startswith("-") and not earliest.startswith("-@"):
            # Extract number and unit
            match = re.match(r'-(\d+)([hmd])', earliest)
            if match:
                value = int(match.group(1))
                unit = match.group(2)
                
                if unit == 'h':
                    # Add offset hours
                    adjusted_value = value + TIMEZONE_OFFSET_HOURS
                    adjusted_earliest = f"-{adjusted_value}h"
                    logger.info(f"Timezone adjustment: {earliest} → {adjusted_earliest} (offset: +{TIMEZONE_OFFSET_HOURS}h)")
                    return adjusted_earliest, latest
                elif unit == 'm':
                    # Convert to hours if needed
                    total_minutes = value + (TIMEZONE_OFFSET_HOURS * 60)
                    if total_minutes >= 60:
                        hours = total_minutes // 60
                        remaining_minutes = total_minutes % 60
                        if remaining_minutes == 0:
                            adjusted_earliest = f"-{hours}h"
                        else:
                            adjusted_earliest = f"-{hours}h-{remaining_minutes}m"
                    else:
                        adjusted_earliest = f"-{total_minutes}m"
                    logger.info(f"Timezone adjustment: {earliest} → {adjusted_earliest} (offset: +{TIMEZONE_OFFSET_HOURS}h)")
                    return adjusted_earliest, latest
                elif unit == 'd':
                    # Days don't need adjustment for same-day queries
                    return earliest, latest
        
        # Handle snap-to-time expressions like "@d", "@w0"
        # These are already in the correct timezone context
        if "@" in earliest:
            return earliest, latest
        
        # Handle absolute time expressions
        # These need to be converted to UTC
        if re.match(r'\d{4}-\d{2}-\d{2}', earliest):
            try:
                dt = datetime.fromisoformat(earliest)
                # Subtract offset to convert local to UTC
                utc_dt = dt - timedelta(hours=TIMEZONE_OFFSET_HOURS)
                adjusted_earliest = utc_dt.strftime('%Y-%m-%d %H:%M:%S')
                logger.info(f"Timezone adjustment: {earliest} → {adjusted_earliest} (UTC conversion)")
                
                # Also adjust latest if it's absolute time
                adjusted_latest = latest
                if latest != "now" and re.match(r'\d{4}-\d{2}-\d{2}', latest):
                    dt_latest = datetime.fromisoformat(latest)
                    utc_dt_latest = dt_latest - timedelta(hours=TIMEZONE_OFFSET_HOURS)
                    adjusted_latest = utc_dt_latest.strftime('%Y-%m-%d %H:%M:%S')
                
                return adjusted_earliest, adjusted_latest
            except Exception as e:
                logger.warning(f"Failed to parse absolute time: {e}")
                return earliest, latest
        
        return earliest, latest
    
    @staticmethod
    def parse_time_expression(query: str) -> Optional[Dict[str, Any]]:
        """
        Parse time expression from user query.
        
        Args:
            query: User query containing time expression
            
        Returns:
            {
                "earliest": "-2h" or "2024-01-01 14:00:00",
                "latest": "now" or "2024-01-01 15:00:00",
                "time_range_text": "2 giờ qua"
            }
            or None if no time expression found
        """
        query_lower = query.lower()
        
        # Pattern 1: "X giờ qua" / "X hours ago"
        pattern_hours = r'(\d+)\s*(giờ|h|hour|hours)\s*(qua|gần nhất|ago|past)'
        match = re.search(pattern_hours, query_lower)
        if match:
            hours = int(match.group(1))
            earliest = f"-{hours}h"
            latest = "now"
            
            # Apply timezone offset
            earliest, latest = TimeParser.apply_timezone_offset(earliest, latest)
            
            return {
                "earliest": earliest,
                "latest": latest,
                "time_range_text": f"{hours} giờ qua",
                "minutes": hours * 60
            }
        
        # Pattern 2: "X phút qua" / "X minutes ago"
        pattern_minutes = r'(\d+)\s*(phút|m|min|minute|minutes)\s*(qua|gần nhất|ago|past)'
        match = re.search(pattern_minutes, query_lower)
        if match:
            minutes = int(match.group(1))
            earliest = f"-{minutes}m"
            latest = "now"
            
            # Apply timezone offset
            earliest, latest = TimeParser.apply_timezone_offset(earliest, latest)
            
            return {
                "earliest": earliest,
                "latest": latest,
                "time_range_text": f"{minutes} phút qua",
                "minutes": minutes
            }
        
        # Pattern 3: "X ngày qua" / "X days ago"
        pattern_days = r'(\d+)\s*(ngày|day|days)\s*(qua|gần nhất|ago|past)'
        match = re.search(pattern_days, query_lower)
        if match:
            days = int(match.group(1))
            return {
                "earliest": f"-{days}d",
                "latest": "now",
                "time_range_text": f"{days} ngày qua",
                "minutes": days * 24 * 60
            }
        
        # Pattern 4: "hôm nay" / "today"
        if any(kw in query_lower for kw in ['hôm nay', 'today', 'ngày hôm nay']):
            return {
                "earliest": "@d",
                "latest": "now",
                "time_range_text": "hôm nay",
                "minutes": None
            }
        
        # Pattern 5: "hôm qua" / "yesterday"
        if any(kw in query_lower for kw in ['hôm qua', 'yesterday']):
            return {
                "earliest": "-1d@d",
                "latest": "@d",
                "time_range_text": "hôm qua",
                "minutes": None
            }
        
        # Pattern 6: "tuần này" / "this week"
        if any(kw in query_lower for kw in ['tuần này', 'this week']):
            return {
                "earliest": "@w0",
                "latest": "now",
                "time_range_text": "tuần này",
                "minutes": None
            }
        
        # Pattern 7: Specific time range "từ HH:MM đến HH:MM"
        pattern_time_range = r'từ\s+(\d{1,2}):(\d{2})\s+đến\s+(\d{1,2}):(\d{2})'
        match = re.search(pattern_time_range, query_lower)
        if match:
            start_hour, start_min = match.group(1), match.group(2)
            end_hour, end_min = match.group(3), match.group(4)
            
            today = datetime.now().strftime('%Y-%m-%d')
            return {
                "earliest": f"{today} {start_hour}:{start_min}:00",
                "latest": f"{today} {end_hour}:{end_min}:00",
                "time_range_text": f"từ {start_hour}:{start_min} đến {end_hour}:{end_min}",
                "minutes": None
            }
        
        # Default: No time expression found
        return None
    
    @staticmethod
    def build_splunk_query(base_query: str, time_info: Dict[str, Any]) -> str:
        """
        Build Splunk query with time range.
        
        Args:
            base_query: Base Splunk query (e.g., "index=*")
            time_info: Time info from parse_time_expression()
            
        Returns:
            Complete Splunk query with time range
        """
        if not time_info:
            return base_query
        
        earliest = time_info.get("earliest")
        latest = time_info.get("latest", "now")
        
        # Add time range to query
        query = f"{base_query} earliest={earliest}"
        if latest and latest != "now":
            query += f" latest={latest}"
        
        return query
    
    @staticmethod
    def parse_and_build_query(user_query: str, default_index: str = "index=*") -> Dict[str, Any]:
        """
        Parse user query and build complete Splunk query.
        
        Args:
            user_query: User's natural language query
            default_index: Default Splunk index
            
        Returns:
            {
                "splunk_query": "index=* earliest=-2h",
                "time_range_text": "2 giờ qua",
                "has_time_expression": True
            }
        """
        time_info = TimeParser.parse_time_expression(user_query)
        
        if time_info:
            splunk_query = TimeParser.build_splunk_query(default_index, time_info)
            return {
                "splunk_query": splunk_query,
                "time_range_text": time_info.get("time_range_text"),
                "time_info": time_info,
                "has_time_expression": True
            }
        else:
            # No time expression, use default (last 5 minutes)
            return {
                "splunk_query": f"{default_index} earliest=-5m",
                "time_range_text": "5 phút gần nhất (mặc định)",
                "time_info": {
                    "earliest": "-5m",
                    "latest": "now",
                    "minutes": 5
                },
                "has_time_expression": False
            }


# Singleton instance
_time_parser = TimeParser()


def parse_time_from_query(query: str) -> Optional[Dict[str, Any]]:
    """Parse time expression from query."""
    return _time_parser.parse_time_expression(query)


def build_splunk_query_from_query(query: str, default_index: str = "index=*") -> Dict[str, Any]:
    """Parse query and build Splunk query."""
    return _time_parser.parse_and_build_query(query, default_index)
