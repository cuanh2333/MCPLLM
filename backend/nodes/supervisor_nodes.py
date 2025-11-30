"""
Supervisor Nodes for V4 LangGraph Workflow

This module contains supervisor nodes that handle job classification
and workflow flag management.
"""

import logging
import time
from typing import Dict, Any

from backend.config import settings

logger = logging.getLogger(__name__)


async def supervisor_pre_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Pre-supervisor: Classify job and set initial flags.
    
    This node determines the job type and sets initial workflow flags.
    It can use either LLM-based SupervisorAgent or rule-based logic.
    
    NEW: Auto-detects time range from user query and creates Splunk log_source automatically.
    NEW: Extracts IPs from query for IP reputation checks.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with job_type and need_* flags
    """
    logger.info("[supervisor_pre] Starting job classification...")
    
    try:
        user_query = state.get("user_query", "")
        
        # FIRST: Check if this is IP reputation query and extract IPs
        import re
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', user_query)
        ip_keywords = ["kiểm tra", "check", "độc hại", "malicious", "reputation", "abuse", "threat"]
        
        if ip_match and any(kw in user_query.lower() for kw in ip_keywords):
            # Extract all IPs from query
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', user_query)
            logger.info(f"  Detected IP reputation query for {len(ips)} IPs: {ips}")
            
            # Set parsed_intent with extracted IPs
            state["parsed_intent"] = {
                "source": "ip_reputation",
                "query_type": "ip_reputation",
                "ips": ips
            }
            
            # Set job_type and flags for IP reputation
            state["job_type"] = "ip_reputation"
            state["need_analyze"] = False
            state["need_ti"] = True
            state["need_genrule"] = False
            state["need_recommend"] = False
            state["need_report"] = False
            state["need_queryrag"] = False
            state["need_asset"] = False
            state["supervisor_reasoning"] = f"IP reputation query detected for {len(ips)} IPs"
            
            # Initialize workflow tracking
            state["workflow_path"] = ["supervisor_pre"]
            state["graph_metadata"] = {
                "start_time": time.time(),
                "supervisor_type": "ip_reputation_detector"
            }
            
            logger.info(f"[supervisor_pre] Job type: ip_reputation (extracted {len(ips)} IPs)")
            return state
        
        # Check if SupervisorAgent is enabled
        use_supervisor_agent = getattr(settings, 'use_supervisor_agent', True)
        
        # NEW: Auto-detect time range and create log_source if needed
        if not state.get("log_source"):
            from backend.agents.supervisor_agent import SupervisorAgent
            supervisor = SupervisorAgent()
            
            time_range = supervisor.parse_time_range(user_query)
            
            if time_range:
                # User mentioned time range → auto-create Splunk log_source
                logger.info(f"  Auto-detected time range: {time_range['earliest_time']} to {time_range['latest_time']}")
                
                # Get Splunk config from environment or use defaults
                import os
                splunk_index = os.getenv("SPLUNK_INDEX", "web_iis")
                splunk_sourcetype = os.getenv("SPLUNK_SOURCETYPE", "modsec:dvwa")
                
                state["log_source"] = {
                    "type": "splunk",
                    "index": splunk_index,
                    "sourcetype": splunk_sourcetype,
                    "earliest_time": time_range["earliest_time"],
                    "latest_time": time_range["latest_time"],
                    "search_filter": ""
                }
                
                logger.info(f"  Auto-created Splunk log_source: index={splunk_index}, sourcetype={splunk_sourcetype}")
                logger.info(f"  Time range: {time_range['earliest_time']} to {time_range['latest_time']}")
        
        if use_supervisor_agent:
            # Use LLM-based SupervisorAgent
            logger.info("  Using LLM-based SupervisorAgent")
            
            from backend.agents.supervisor_agent import SupervisorAgent
            supervisor = SupervisorAgent()
            
            result = await supervisor.classify_job(
                user_query=state.get("user_query", ""),
                has_log_source=state.get("log_source") is not None,
                log_source_type=state.get("log_source", {}).get("type") if state.get("log_source") else None
            )
            
            # Update state with LLM decisions
            state["job_type"] = result["job_type"]
            state["need_analyze"] = result["need_analyze"]
            state["need_ti"] = result["need_ti"]
            state["need_genrule"] = result["need_genrule"]
            state["need_recommend"] = result["need_recommend"]
            state["need_report"] = result["need_report"]
            state["need_queryrag"] = result["need_queryrag"]
            state["need_asset"] = result["need_asset"]
            state["supervisor_reasoning"] = result["reasoning"]
            
            logger.info(f"  Job type: {result['job_type']}")
            logger.info(f"  Reasoning: {result['reasoning']}")
            
            supervisor_type = "llm"
        else:
            # Fallback to rule-based logic (V3 style)
            logger.info("  Using rule-based supervisor (config disabled)")
            state = _rule_based_classification(state)
            supervisor_type = "rule"
        
        # Initialize workflow tracking
        state["workflow_path"] = ["supervisor_pre"]
        
        # Initialize graph metadata
        state["graph_metadata"] = {
            "start_time": time.time(),
            "supervisor_type": supervisor_type
        }
        
        logger.info(f"[supervisor_pre] Job type: {state['job_type']}")
        logger.info("[supervisor_pre] Completed successfully")
        return state
    
    except Exception as e:
        logger.error(f"[supervisor_pre] Failed: {e}, using fallback", exc_info=True)
        
        # Fallback to rule-based
        state = _rule_based_classification(state)
        state["workflow_path"] = ["supervisor_pre_fallback"]
        state["graph_metadata"] = {
            "start_time": time.time(),
            "supervisor_type": "rule_fallback"
        }
        
        return state


async def supervisor_post_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Post-supervisor: Update flags based on findings.
    
    This node updates workflow flags based on analysis results.
    It respects user preferences (especially enable_genrule).
    
    Args:
        state: Current analysis state with findings
        
    Returns:
        Updated state with adjusted need_* flags
    """
    logger.info("[supervisor_post] Updating workflow flags...")
    
    findings = state.get("findings_summary")
    
    if not findings or not findings.get("has_attack"):
        # No attacks → disable all
        logger.info("  No attacks detected → disabling all agents")
        state["need_ti"] = False
        state["need_genrule"] = False
        state["need_recommend"] = False
        state["need_report"] = False
    
    elif findings.get("severity_level") in ["high", "critical"]:
        # High severity → enable TI
        logger.info(f"  High severity ({findings['severity_level']}) → enabling TI")
        state["need_ti"] = True
        state["need_recommend"] = True
        state["need_report"] = True
    
    else:
        # Low/medium → disable TI
        logger.info(f"  Low/medium severity ({findings['severity_level']}) → disabling TI")
        state["need_ti"] = False
        state["need_recommend"] = True
        state["need_report"] = True
    
    # CRITICAL: Respect user's explicit genrule preference
    if state.get("enable_genrule"):
        state["need_genrule"] = True
        logger.info("  User enabled genrule → keeping enabled")
    
    state["workflow_path"].append("supervisor_post")
    
    logger.info("[supervisor_post] Completed successfully")
    return state


def _rule_based_classification(state: Dict[str, Any]) -> Dict[str, Any]:
    """Fallback rule-based classification (V3 logic).
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with job_type and flags
    """
    if state.get("log_source"):
        # Has log source → log_analysis
        state["job_type"] = "log_analysis"
        state["need_analyze"] = True
        state["need_ti"] = True
        state["need_genrule"] = False  # Always false initially
        state["need_recommend"] = True
        state["need_report"] = True
        state["need_queryrag"] = False
        state["need_asset"] = False
    
    elif _is_knowledge_query(state.get("user_query", "")):
        # Knowledge keywords → knowledge_query
        state["job_type"] = "knowledge_query"
        state["need_analyze"] = False
        state["need_ti"] = False
        state["need_genrule"] = False
        state["need_recommend"] = False
        state["need_report"] = False
        state["need_queryrag"] = True
        state["need_asset"] = False
    
    elif _is_asset_query(state.get("user_query", "")):
        # Asset keywords → asset_query
        state["job_type"] = "asset_query"
        state["need_analyze"] = False
        state["need_ti"] = False
        state["need_genrule"] = False
        state["need_recommend"] = False
        state["need_report"] = False
        state["need_queryrag"] = True
        state["need_asset"] = True
    
    elif _is_generic_rule_query(state.get("user_query", "")):
        # Rule keywords → generic_rule
        state["job_type"] = "generic_rule"
        state["need_analyze"] = False
        state["need_ti"] = False
        state["need_genrule"] = True
        state["need_recommend"] = False
        state["need_report"] = False
        state["need_queryrag"] = True
        state["need_asset"] = False
    
    else:
        # Default → knowledge_query
        state["job_type"] = "knowledge_query"
        state["need_queryrag"] = True
    
    return state


def _is_knowledge_query(query: str) -> bool:
    """Check if query is a knowledge question."""
    knowledge_keywords = [
        "là gì", "what is", "explain", "giải thích",
        "how to", "làm thế nào", "tại sao", "why"
    ]
    query_lower = query.lower()
    return any(kw in query_lower for kw in knowledge_keywords)


def _is_asset_query(query: str) -> bool:
    """Check if query is about assets."""
    asset_keywords = [
        "asset", "server", "máy chủ", "ip address",
        "hostname", "thiết bị", "device"
    ]
    query_lower = query.lower()
    return any(kw in query_lower for kw in asset_keywords)


def _is_generic_rule_query(query: str) -> bool:
    """Check if query is about creating rules."""
    rule_keywords = [
        "tạo rule", "create rule", "sigma", "splunk spl",
        "qradar aql", "detection rule", "rule phát hiện"
    ]
    query_lower = query.lower()
    return any(kw in query_lower for kw in rule_keywords)
