"""
Processing Nodes for V4 LangGraph Workflow

This module contains nodes that handle data processing operations
such as chunking, merging, and summarizing.
"""

import logging
from typing import Dict, Any

from backend.summary import generate_findings_summary
from backend.config import settings

logger = logging.getLogger(__name__)


async def chunk_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Split events into chunks if >100 events.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with event_chunks
    """
    logger.info("[chunk] Chunking events...")
    
    try:
        events = state.get("events", [])
        
        if not events:
            logger.warning("[chunk] No events to chunk")
            state["event_chunks"] = []
            state["workflow_path"].append("chunk_skipped")
            return state
        
        # Chunk events if > chunk_size (default 50)
        chunk_size = settings.chunk_size
        
        if len(events) <= chunk_size:
            # No chunking needed
            logger.info(f"[chunk] {len(events)} events <= {chunk_size}, no chunking needed")
            state["event_chunks"] = [events]
        else:
            # Split into chunks
            chunks = []
            for i in range(0, len(events), chunk_size):
                chunk = events[i:i + chunk_size]
                chunks.append(chunk)
            
            state["event_chunks"] = chunks
            logger.info(f"[chunk] Split {len(events)} events into {len(chunks)} chunks")
        
        state["workflow_path"].append("chunk")
        return state
    
    except Exception as e:
        logger.error(f"[chunk] Failed: {e}", exc_info=True)
        state["event_chunks"] = [state.get("events", [])]
        state["workflow_path"].append("chunk_failed")
        return state


async def merge_analyze_results_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Merge analysis results from chunks.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with merged labels
    """
    logger.info("[merge_results] Merging analysis results...")
    
    try:
        # Labels should already be merged by analyze_node
        # This node is a placeholder for future enhancements
        
        labels = state.get("labels", {})
        
        if not labels:
            logger.warning("[merge_results] No labels to merge")
            state["workflow_path"].append("merge_results_skipped")
            return state
        
        logger.info(f"[merge_results] Merged {len(labels)} labels")
        state["workflow_path"].append("merge_results")
        return state
    
    except Exception as e:
        logger.error(f"[merge_results] Failed: {e}", exc_info=True)
        state["workflow_path"].append("merge_results_failed")
        return state


async def summary_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Generate findings summary.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with findings_summary
    """
    logger.info("[summary] Generating findings summary...")
    
    try:
        events = state.get("events", [])
        labels = state.get("labels", {})
        
        if not events or not labels:
            logger.warning("[summary] No events or labels for summary")
            state["findings_summary"] = {
                'has_attack': False,
                'total_events': 0,
                'total_attack_events': 0,
                'attack_breakdown': [],
                'mitre_techniques': [],
                'severity_level': 'low',
                'summary_text': 'No events analyzed',
                'sample_events': []
            }
            state["workflow_path"].append("summary_skipped")
            return state
        
        # Generate summary using existing summary module
        findings_summary = generate_findings_summary(events, labels)
        
        # Enrich with asset context
        try:
            from backend.services.asset_enrichment import enrich_findings_with_assets
            findings_summary = enrich_findings_with_assets(findings_summary, events, labels)
            logger.info("[summary] Enriched findings with asset context")
        except Exception as e:
            logger.warning(f"[summary] Failed to enrich with assets: {e}")
        
        state["findings_summary"] = findings_summary
        
        state["workflow_path"].append("summary")
        
        logger.info(f"[summary] Generated summary: {findings_summary['total_attack_events']} attacks, "
                   f"severity: {findings_summary['severity_level']}")
        return state
    
    except Exception as e:
        logger.error(f"[summary] Failed: {e}", exc_info=True)
        state["findings_summary"] = {
            'has_attack': False,
            'total_events': 0,
            'total_attack_events': 0,
            'attack_breakdown': [],
            'mitre_techniques': [],
            'severity_level': 'low',
            'summary_text': 'Summary generation failed',
            'sample_events': []
        }
        state["workflow_path"].append("summary_failed")
        return state
