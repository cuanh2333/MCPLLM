"""
IO Nodes for V4 LangGraph Workflow

This module contains nodes that handle input/output operations
such as fetching logs, exporting data, and sending notifications.
"""

import logging
from typing import Dict, Any
from datetime import datetime
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from backend.normalizer import normalize_log_entry
from backend.utils.exporter import export_attack_events_csv
from backend.services.telegram_notifier import TelegramNotifier
from backend.config import settings

logger = logging.getLogger(__name__)


async def fetch_logs_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Fetch logs from source (file/splunk/cron).
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with raw_logs
    """
    logger.info("[fetch_logs] Fetching logs...")
    
    try:
        log_source = state.get("log_source")
        if not log_source:
            logger.warning("[fetch_logs] No log_source provided, skipping")
            state["raw_logs"] = []
            workflow_path = state.get("workflow_path", [])
            workflow_path.append("fetch_logs_skipped")
            state["workflow_path"] = workflow_path
            return state
        
        # Fetch logs using MCP
        raw_logs = await _fetch_logs_from_mcp(log_source)
        
        logger.info(f"[fetch_logs] Fetched {len(raw_logs)} logs")
        logger.info(f"[fetch_logs] Setting raw_logs in state (type: {type(raw_logs)}, len: {len(raw_logs)})")
        
        # Update state and return
        state["raw_logs"] = raw_logs
        workflow_path = state.get("workflow_path", [])
        workflow_path.append("fetch_logs")
        state["workflow_path"] = workflow_path
        
        return state
    
    except Exception as e:
        logger.error(f"[fetch_logs] Failed: {e}", exc_info=True)
        state["raw_logs"] = []
        workflow_path = state.get("workflow_path", [])
        workflow_path.append("fetch_logs_failed")
        state["workflow_path"] = workflow_path
        return state


async def normalize_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize logs to Event objects.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with events
    """
    logger.info("[normalize] Normalizing logs...")
    
    try:
        raw_logs = state.get("raw_logs", [])
        if not raw_logs:
            logger.warning("[normalize] No raw_logs to normalize")
            state["events"] = []
            state["workflow_path"].append("normalize_skipped")
            return state
        
        # Normalize using existing normalizer
        events = []
        timestamp_prefix = datetime.now().strftime("%Y%m%d")
        
        for i, raw_log in enumerate(raw_logs, 1):
            event_id = f"evt_{timestamp_prefix}_{i:05d}"
            try:
                event = normalize_log_entry(raw_log, event_id)
                events.append(event)
            except Exception as e:
                logger.warning(f"[normalize] Failed to normalize event {event_id}: {e}")
                # Create minimal event
                from backend.models import Event
                event = Event(
                    event_id=event_id,
                    timestamp=None,
                    src_ip=None,
                    method=None,
                    uri=None,
                    status=None,
                    user_agent=None,
                    raw_log=raw_log
                )
                events.append(event)
        
        state["events"] = events
        state["workflow_path"].append("normalize")
        
        logger.info(f"[normalize] Normalized {len(events)} events")
        return state
    
    except Exception as e:
        logger.error(f"[normalize] Failed: {e}", exc_info=True)
        state["events"] = []
        state["workflow_path"].append("normalize_failed")
        return state


async def export_csv_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Export attack events to CSV.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with attack_events_ref
    """
    logger.info("[export_csv] Exporting attack events...")
    
    try:
        events = state.get("events", [])
        labels = state.get("labels", {})
        
        if not events or not labels:
            logger.warning("[export_csv] No events or labels to export")
            state["workflow_path"].append("export_csv_skipped")
            return state
        
        # Export using existing exporter
        csv_path = export_attack_events_csv(events, labels)
        
        # Create attack_events_ref
        report_id = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        total_attack_events = sum(1 for label in labels.values() if label.get('is_attack'))
        
        from backend.models import AttackEventsRef
        state["attack_events_ref"] = AttackEventsRef(
            report_id=report_id,
            total_attack_events=total_attack_events,
            csv_path=csv_path
        )
        
        state["workflow_path"].append("export_csv")
        
        logger.info(f"[export_csv] Exported {total_attack_events} attacks to {csv_path}")
        return state
    
    except Exception as e:
        logger.error(f"[export_csv] Failed: {e}", exc_info=True)
        state["workflow_path"].append("export_csv_failed")
        return state


async def send_telegram_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Send Telegram alerts.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state
    """
    logger.info("[send_telegram] Sending Telegram alert...")
    
    try:
        telegram = TelegramNotifier()
        if not telegram.is_configured():
            logger.info("[send_telegram] Telegram not configured, skipping")
            state["workflow_path"].append("send_telegram_skipped")
            return state
        
        # Send complete report
        telegram.send_complete_report(
            findings=state.get("findings_summary"),
            ti_summary=state.get("ti_summary"),
            recommend=state.get("recommend_summary"),
            attack_ref=state.get("attack_events_ref"),
            pdf_path=state.get("pdf_path"),
            csv_path=state.get("attack_events_ref", {}).get("csv_path")
        )
        
        state["workflow_path"].append("send_telegram")
        
        logger.info("[send_telegram] Telegram notification sent")
        return state
    
    except Exception as e:
        logger.error(f"[send_telegram] Failed: {e}", exc_info=True)
        state["workflow_path"].append("send_telegram_failed")
        return state





async def _fetch_logs_from_mcp(log_source: dict) -> list[str]:
    """Fetch logs from MCP server.
    
    Args:
        log_source: Log source configuration
        
    Returns:
        List of raw log lines
    """
    source_type = log_source.get('type')
    
    if not source_type:
        raise ValueError("log_source must contain 'type' field")
    
    logger.info(f"Connecting to MCP server: {settings.mcp_server_path}")
    
    try:
        import os
        server_params = StdioServerParameters(
            command="python",
            args=[settings.mcp_server_path],
            env=dict(os.environ)
        )
        
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                logger.info("MCP session initialized")
                
                if source_type == "file":
                    filepath = log_source.get('path')
                    max_lines = log_source.get('max_lines')
                    
                    if not filepath:
                        raise ValueError("log_source with type 'file' must contain 'path' field")
                    
                    logger.info(f"Calling load_log_file tool: path={filepath}, max_lines={max_lines}")
                    
                    result = await session.call_tool(
                        "load_log_file",
                        arguments={
                            "filepath": filepath,
                            "max_lines": max_lines
                        }
                    )
                    
                    if result.content:
                        logs = [content.text for content in result.content]
                        logger.info(f"MCP returned {len(result.content)} content items")
                        logger.info(f"First item type: {type(logs[0]) if logs else 'N/A'}")
                        logger.info(f"First item length: {len(logs[0]) if logs else 0}")
                        
                        # If MCP returns one big string, split by newlines
                        if len(logs) == 1 and '\n' in logs[0]:
                            logger.info("Splitting single string into lines")
                            logs = logs[0].strip().split('\n')
                    else:
                        logs = []
                    
                    logger.info(f"Retrieved {len(logs)} logs from file")
                    return logs
                
                elif source_type == "splunk":
                    index = log_source.get('index')
                    sourcetype = log_source.get('sourcetype')
                    earliest_time = log_source.get('earliest_time', '-1h')
                    latest_time = log_source.get('latest_time', 'now')
                    search_filter = log_source.get('search_filter', '')
                    
                    if not index or not sourcetype:
                        raise ValueError("log_source with type 'splunk' must contain 'index' and 'sourcetype' fields")
                    
                    logger.info(f"Calling splunk_search tool: index={index}, sourcetype={sourcetype}")
                    
                    result = await session.call_tool(
                        "splunk_search",
                        arguments={
                            "index": index,
                            "sourcetype": sourcetype,
                            "earliest_time": earliest_time,
                            "latest_time": latest_time,
                            "search_filter": search_filter
                        }
                    )
                    
                    if result.content:
                        logs = [content.text for content in result.content]
                    else:
                        logs = []
                    
                    logger.info(f"Retrieved {len(logs)} logs from Splunk")
                    return logs
                
                elif source_type == "cron_splunk":
                    logger.info("Calling cron_splunk_query tool (default: -7h-5m to -7h)")
                    
                    result = await session.call_tool(
                        "cron_splunk_query",
                        arguments={}
                    )
                    
                    if result.content:
                        logs = [content.text for content in result.content]
                    else:
                        logs = []
                    
                    logger.info(f"Retrieved {len(logs)} logs from cron Splunk query")
                    return logs
                
                else:
                    raise ValueError(f"Unsupported log_source type: {source_type}")
    
    except Exception as e:
        logger.error(f"Failed to fetch logs from MCP server: {e}")
        raise Exception(f"MCP log retrieval failed: {e}")
