"""
Log normalization module for V1 Log Analyzer System.

This module provides functionality to parse raw log entries from various formats
(Apache, Nginx, IIS, JSON) into standardized Event structures for analysis.
"""

import re
import json
from typing import Optional
from urllib.parse import unquote_plus
from backend.models import Event


def normalize_log_entry(raw_log: str, event_id: str) -> Event:
    """
    Parse a raw log line into a normalized Event structure.
    
    Supports multiple log formats with intelligent fallback:
    1. JSON format: Nginx JSON logs with request_headers, response_headers, etc.
    2. Apache/Nginx combined: IP - - [timestamp] "METHOD /uri HTTP/x.x" status size "referer" "user-agent"
    3. IIS W3C: timestamp IP method URI query port - IP user-agent referer status substatus win32status time-taken
    4. Generic format: Extracts IP, method, URI, status from any format
    
    Args:
        raw_log: Raw log line string to parse
        event_id: Unique identifier to assign to this event
    
    Returns:
        Event object with parsed fields. Uses intelligent fallback to extract
        as much information as possible even from unknown formats.
    
    Examples:
        >>> log = '192.168.1.100 - - [15/Nov/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        >>> event = normalize_log_entry(log, "20251115_001")
        >>> event['src_ip']
        '192.168.1.100'
    """
    # Try JSON format first (Nginx JSON logs)
    json_event = _parse_json_format(raw_log, event_id)
    if json_event:
        return json_event
    
    # Try Apache/Nginx format
    apache_event = _parse_apache_format(raw_log, event_id)
    if apache_event:
        return apache_event
    
    # Try IIS format
    iis_event = _parse_iis_format(raw_log, event_id)
    if iis_event:
        return iis_event
    
    # Fallback: Try generic parsing to extract what we can
    generic_event = _parse_generic_format(raw_log, event_id)
    if generic_event:
        return generic_event
    
    # Last resort: return Event with null fields except event_id and raw_log
    return Event(
        event_id=event_id,
        timestamp=None,
        src_ip=None,
        method=None,
        uri=None,
        status=None,
        user_agent=None,
        raw_log=raw_log
    )


def _parse_json_format(raw_log: str, event_id: str) -> Optional[Event]:
    """
    Parse JSON log format (Nginx JSON logs).
    
    Expected fields:
    - remote_addr: Source IP address
    - time_local: Timestamp
    - request: Full HTTP request line (e.g., "GET /path HTTP/1.1")
    - status: HTTP status code
    - request_headers.user-agent: User agent string
    - request_body: Request body (optional)
    
    Example:
        {"remote_addr":"192.168.195.1","time_local":"15/Nov/2025:21:37:55 +0700",
         "request":"GET /icons/folder.gif HTTP/1.1","status":200,...}
    """
    try:
        log_data = json.loads(raw_log)
        
        # Extract source IP
        src_ip = log_data.get('remote_addr')
        
        # Extract timestamp
        timestamp = log_data.get('time_local')
        
        # Extract method and URI from request field
        request = log_data.get('request', '')
        method = None
        uri = None
        
        if request:
            # Parse "METHOD /uri HTTP/x.x" format
            request_parts = request.split(' ', 2)
            if len(request_parts) >= 2:
                method = request_parts[0]
                uri = request_parts[1]
        
        # Extract status code
        status = log_data.get('status')
        if status is not None:
            status = int(status)
        
        # Extract user agent from request_headers
        user_agent = None
        request_headers = log_data.get('request_headers', {})
        if isinstance(request_headers, dict):
            user_agent = request_headers.get('user-agent') or request_headers.get('User-Agent')
        
        # Include request body in URI if present (for POST attack detection)
        request_body = log_data.get('request_body', '')
        if request_body and request_body != '-' and uri:
            # Extract filename from multipart/form-data if present
            filename = None
            if 'filename=' in request_body:
                import re
                filename_match = re.search(r'filename="([^"]+)"', request_body)
                if filename_match:
                    filename = filename_match.group(1)
            
            # Add filename to URI if found
            if filename:
                uri += f" [File: {filename}]"
            
            # Add body content (limit length)
            uri += f" [Body: {request_body[:200]}]"
        
        return Event(
            event_id=event_id,
            timestamp=timestamp,
            src_ip=src_ip,
            method=method,
            uri=uri,
            status=status,
            user_agent=user_agent,
            raw_log=raw_log
        )
    
    except (json.JSONDecodeError, ValueError, KeyError):
        # Not a valid JSON log
        return None


def _parse_iis_format(raw_log: str, event_id: str) -> Optional[Event]:
    """
    Parse IIS W3C log format.
    Format: timestamp IP method URI query port - IP user-agent referer status substatus win32status time-taken
    
    More flexible parsing that handles various IIS log formats.
    """
    parts = raw_log.split()
    
    # IIS logs need at least: date time IP method URI
    if len(parts) < 5:
        return None
    
    # Check if first part looks like a date (YYYY-MM-DD)
    if not re.match(r'\d{4}-\d{2}-\d{2}', parts[0]):
        return None
    
    try:
        timestamp = f"{parts[0]} {parts[1]}"
        src_ip = parts[2]
        method = parts[3]
        uri_path = parts[4]
        
        # Query string (field 5)
        query = parts[5] if len(parts) > 5 and parts[5] != '-' else ''
        
        # Port (field 6) - skip
        # Dash (field 7) - skip  
        # Client IP duplicate (field 8) - skip
        
        # User agent (field 9)
        user_agent = None
        if len(parts) > 9 and parts[9] != '-':
            try:
                user_agent = unquote_plus(parts[9])
            except:
                user_agent = parts[9]
        
        # Referer (field 10)
        referer = None
        if len(parts) > 10 and parts[10] != '-':
            try:
                referer = unquote_plus(parts[10])
            except:
                referer = parts[10]
        
        # Status (field 11)
        status = None
        if len(parts) > 11 and parts[11].isdigit():
            status = int(parts[11])
        
        # Combine URI with query and referer for full context
        full_uri = uri_path
        if query and query != '-':
            full_uri += f"?{query}"
        if referer and referer != '-':
            # Include referer in URI for attack detection
            full_uri += f" [Referer: {referer}]"
        
        return Event(
            event_id=event_id,
            timestamp=timestamp,
            src_ip=src_ip,
            method=method,
            uri=full_uri,
            status=status,
            user_agent=user_agent,
            raw_log=raw_log
        )
    except (ValueError, IndexError) as e:
        # Failed to parse as IIS
        return None


def _parse_apache_format(raw_log: str, event_id: str) -> Optional[Event]:
    """
    Parse Apache/Nginx combined log format.
    Format: IP - - [timestamp] "METHOD /uri HTTP/x.x" status size "referer" "user-agent" ["request_body"]
    """
    # Try with optional request body at the end
    pattern_with_body = r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]+) [^"]+" (\d+) \d+ "[^"]*" "([^"]+)" "([^"]*)"'
    match = re.match(pattern_with_body, raw_log)
    
    if match:
        src_ip, timestamp, method, uri, status, user_agent, request_body = match.groups()
        
        # Append request body to URI if present
        if request_body and request_body != '-':
            uri += f" [Body: {request_body}]"
        
        return Event(
            event_id=event_id,
            timestamp=timestamp,
            src_ip=src_ip,
            method=method,
            uri=uri,
            status=int(status),
            user_agent=user_agent,
            raw_log=raw_log
        )
    
    # Try standard format without request body
    pattern = r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]+) [^"]+" (\d+) \d+ "[^"]*" "([^"]+)"'
    match = re.match(pattern, raw_log)
    
    if not match:
        return None
    
    src_ip, timestamp, method, uri, status, user_agent = match.groups()
    
    return Event(
        event_id=event_id,
        timestamp=timestamp,
        src_ip=src_ip,
        method=method,
        uri=uri,
        status=int(status),
        user_agent=user_agent,
        raw_log=raw_log
    )


def _parse_generic_format(raw_log: str, event_id: str) -> Optional[Event]:
    """
    Generic parser that extracts fields from any log format using pattern matching.
    
    Attempts to extract:
    - IP address (IPv4 pattern)
    - HTTP method (GET, POST, PUT, DELETE, etc.)
    - URI/path (anything that looks like a URL path)
    - Status code (3-digit number)
    - Timestamp (various formats)
    """
    # Extract IP address (IPv4)
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    ip_match = re.search(ip_pattern, raw_log)
    src_ip = ip_match.group(1) if ip_match else None
    
    # Extract HTTP method
    method_pattern = r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\b'
    method_match = re.search(method_pattern, raw_log, re.IGNORECASE)
    method = method_match.group(1).upper() if method_match else None
    
    # Extract URI/path (look for paths starting with /)
    uri_pattern = r'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)'
    uri_match = re.search(uri_pattern, raw_log, re.IGNORECASE)
    uri = uri_match.group(1) if uri_match else None
    
    # If no URI found with method, try to find any path-like string
    if not uri:
        path_pattern = r'(/[^\s]*)'
        path_match = re.search(path_pattern, raw_log)
        uri = path_match.group(1) if path_match else None
    
    # Extract status code (3-digit number, typically 200-599)
    status_pattern = r'\b([1-5]\d{2})\b'
    status_match = re.search(status_pattern, raw_log)
    status = int(status_match.group(1)) if status_match else None
    
    # Extract timestamp (try various formats)
    timestamp = None
    
    # Try ISO format: YYYY-MM-DD HH:MM:SS
    iso_pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
    iso_match = re.search(iso_pattern, raw_log)
    if iso_match:
        timestamp = iso_match.group(1)
    else:
        # Try Apache format: [DD/Mon/YYYY:HH:MM:SS +ZZZZ]
        apache_ts_pattern = r'\[([^\]]+)\]'
        apache_ts_match = re.search(apache_ts_pattern, raw_log)
        if apache_ts_match:
            timestamp = apache_ts_match.group(1)
    
    # Extract user agent (look for Mozilla, curl, etc.)
    ua_pattern = r'(Mozilla[^"]*|curl[^\s]*|python-requests[^\s]*)'
    ua_match = re.search(ua_pattern, raw_log, re.IGNORECASE)
    user_agent = ua_match.group(1) if ua_match else None
    
    # Only return event if we extracted at least IP or method+URI
    if src_ip or (method and uri):
        return Event(
            event_id=event_id,
            timestamp=timestamp,
            src_ip=src_ip,
            method=method,
            uri=uri,
            status=status,
            user_agent=user_agent,
            raw_log=raw_log
        )
    
    return None
