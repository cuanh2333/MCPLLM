"""
V4 Routing Functions

This module contains routing functions for conditional edges in the LangGraph workflow.
"""

import logging
from backend.models import AnalysisState

logger = logging.getLogger(__name__)


def route_by_job_type(state: AnalysisState) -> str:
    """Route based on job_type from supervisor_pre.
    
    Args:
        state: Current analysis state
        
    Returns:
        Next node name
    """
    job_type = state.get("job_type", "log_analysis")
    logger.info(f"[routing] Job type: {job_type}")
    return job_type


def route_post_supervisor(state: AnalysisState) -> str:
    """Route after post-supervisor based on need_* flags.
    
    Args:
        state: Current analysis state
        
    Returns:
        Next node name
    """
    if state.get("need_ti"):
        return "ti"
    elif state.get("need_genrule"):
        return "genrule"
    elif state.get("need_recommend"):
        return "recommend"
    elif state.get("need_report"):
        return "report"
    else:
        return "end"


def route_after_ti(state: AnalysisState) -> str:
    """Route after TI node.
    
    Args:
        state: Current analysis state
        
    Returns:
        Next node name
    """
    job_type = state.get("job_type")
    
    # IP reputation query: TI already has asset info, skip asset node
    if job_type == "ip_reputation":
        logger.info("[routing] IP reputation query - TI has asset info, skipping asset node")
        return "end"
    
    # For other job types, check if asset enrichment is needed
    # Skip asset if TI already enriched asset info
    ti_summary = state.get("ti_summary")
    if ti_summary and ti_summary.get("iocs"):
        has_asset_info = any(ioc.get("asset_info") for ioc in ti_summary["iocs"])
        if has_asset_info:
            logger.info("[routing] TI already has asset info, skipping asset node")
            # Continue to next step
            if state.get("need_genrule"):
                return "genrule"
            elif state.get("need_recommend"):
                return "recommend"
            elif state.get("need_report"):
                return "report"
            else:
                return _check_telegram(state)
    
    # Otherwise check if asset node is needed
    if state.get("need_asset"):
        return "asset"
    elif state.get("need_genrule"):
        return "genrule"
    elif state.get("need_recommend"):
        return "recommend"
    elif state.get("need_report"):
        return "report"
    else:
        # Check if we should send telegram (cron or user request only)
        return _check_telegram(state)


def route_after_queryrag(state: AnalysisState) -> str:
    """Route after QueryRAG node.
    
    Args:
        state: Current analysis state
        
    Returns:
        Next node name
    """
    job_type = state.get("job_type")
    
    if job_type == "generic_rule":
        return "genrule"
    elif state.get("need_recommend"):
        return "recommend"
    else:
        return "end"


def route_check_recommend(state: AnalysisState) -> str:
    """Check if recommend is needed after genrule.
    
    Args:
        state: Current analysis state
        
    Returns:
        Next node name
    """
    job_type = state.get("job_type")
    
    # Generic rule job should end after genrule, no recommend needed
    if job_type == "generic_rule":
        return "end"
    
    if state.get("need_recommend"):
        return "recommend"
    elif state.get("need_report"):
        return "report"
    else:
        # Check if we should send telegram (cron or user request only)
        return _check_telegram(state)


def route_check_report(state: AnalysisState) -> str:
    """Check if report is needed after recommend.
    
    Args:
        state: Current analysis state
        
    Returns:
        Next node name
    """
    if state.get("need_report"):
        return "report"
    else:
        # Check if we should send telegram (cron or user request only)
        return _check_telegram(state)


def route_check_telegram(state: AnalysisState) -> str:
    """Check if telegram notification is needed after report.
    
    Telegram is sent only when:
    1. Cron job (log_source.type == "cron_splunk")
    2. User explicitly requests (send_telegram == True)
    
    Args:
        state: Current analysis state
        
    Returns:
        Next node name
    """
    # Check if user explicitly requested telegram
    if state.get("send_telegram"):
        logger.info("[routing] User requested Telegram → sending")
        return "telegram"
    
    # Check if this is a cron job
    log_source = state.get("log_source", {})
    if log_source.get("type") == "cron_splunk":
        logger.info("[routing] Cron job detected → sending Telegram")
        return "telegram"
    
    # Otherwise, end workflow
    logger.info("[routing] No Telegram needed → END")
    return "end"


def _check_telegram(state: AnalysisState) -> str:
    """Helper to check if telegram is needed.
    
    Telegram is sent only when:
    1. Cron job (log_source.type == "cron_splunk")
    2. User explicitly requests (send_telegram == True)
    
    Args:
        state: Current analysis state
        
    Returns:
        Next node name
    """
    # Check if user explicitly requested telegram
    if state.get("send_telegram"):
        logger.info("[routing] User requested Telegram → sending")
        return "telegram"
    
    # Check if this is a cron job
    log_source = state.get("log_source")
    if log_source and log_source.get("type") == "cron_splunk":
        logger.info("[routing] Cron job detected → sending Telegram")
        return "telegram"
    
    # Otherwise, end workflow
    return "end"


def route_asset_query(state: AnalysisState) -> str:
    """Route after asset node based on job_type.
    
    Asset node is used in two flows:
    1. log_analysis: TI → asset → genrule/recommend/report/telegram/thehive/END
    2. asset_query: supervisor_pre → asset → queryrag/END
    
    Args:
        state: Current analysis state
        
    Returns:
        Next node name
    """
    job_type = state.get("job_type")
    
    if job_type == "asset_query":
        # Asset query flow: check if we need to enrich with RAG
        if state.get("need_queryrag"):
            return "queryrag"
        else:
            return "end"
    else:
        # Log analysis flow: continue to next agent or end
        if state.get("need_genrule"):
            return "genrule"
        elif state.get("need_recommend"):
            return "recommend"
        elif state.get("need_report"):
            return "report"
        else:
            # Check if we should send telegram (cron or user request only)
            return _check_telegram(state)
