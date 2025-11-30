"""
V4 LangGraph Builder

This module builds and compiles the LangGraph workflow for V4.
"""

import logging
from langgraph.graph import StateGraph, END
from backend.models import AnalysisState

logger = logging.getLogger(__name__)


def build_analysis_graph() -> StateGraph:
    """Build and compile LangGraph workflow.
    
    Returns:
        Compiled StateGraph ready for execution
    """
    logger.info("[graph_builder] Building LangGraph workflow...")
    
    from backend.nodes import (
        supervisor_pre_node,
        supervisor_post_node,
        fetch_logs_node,
        normalize_node,
        chunk_node,
        analyze_node,
        merge_analyze_results_node,
        summary_node,
        export_csv_node,
        ti_node,
        asset_node,
        genrule_node,
        recommend_node,
        report_node,
        queryrag_node,
        send_telegram_node,
    )
    from backend.routing import (
        route_by_job_type,
        route_post_supervisor,
        route_after_ti,
        route_after_queryrag,
        route_check_recommend,
        route_check_report,
        route_check_telegram,
        route_asset_query,
    )
    
    # Initialize graph with proper state type
    graph = StateGraph(AnalysisState)
    
    # Add all nodes
    _add_nodes(graph)
    
    # Set entry point
    graph.set_entry_point("supervisor_pre")
    
    # Add edges
    _add_edges(graph)
    
    # Compile graph
    compiled_graph = graph.compile()
    
    logger.info("[graph_builder] LangGraph workflow compiled successfully")
    return compiled_graph


def _add_nodes(graph: StateGraph):
    """Add all nodes to graph."""
    from backend.nodes import (
        supervisor_pre_node,
        supervisor_post_node,
        fetch_logs_node,
        normalize_node,
        chunk_node,
        analyze_node,
        merge_analyze_results_node,
        summary_node,
        export_csv_node,
        ti_node,
        asset_node,
        genrule_node,
        recommend_node,
        report_node,
        queryrag_node,
        send_telegram_node,
    )
    
    # Supervisor nodes
    graph.add_node("supervisor_pre", supervisor_pre_node)
    graph.add_node("supervisor_post", supervisor_post_node)
    
    # IO nodes
    graph.add_node("fetch_logs", fetch_logs_node)
    graph.add_node("normalize", normalize_node)
    graph.add_node("export_csv", export_csv_node)
    graph.add_node("send_telegram", send_telegram_node)
    
    # Processing nodes
    graph.add_node("chunk", chunk_node)
    graph.add_node("merge_results", merge_analyze_results_node)
    graph.add_node("summary", summary_node)
    
    # Agent nodes
    graph.add_node("analyze", analyze_node)
    graph.add_node("ti", ti_node)
    graph.add_node("asset", asset_node)
    graph.add_node("genrule", genrule_node)
    graph.add_node("recommend", recommend_node)
    graph.add_node("report", report_node)
    graph.add_node("queryrag", queryrag_node)
    
    logger.info("[graph_builder] Added 17 nodes to graph (16 physical nodes + SupervisorAgent embedded in supervisor_pre/post)")


def _add_edges(graph: StateGraph):
    """Add all edges to graph."""
    from backend.routing import (
        route_by_job_type,
        route_post_supervisor,
        route_after_ti,
        route_after_queryrag,
        route_check_recommend,
        route_check_report,
        route_check_telegram,
        route_asset_query,
    )
    
    # ========================================
    # Entry: supervisor_pre routes by job_type
    # ========================================
    graph.add_conditional_edges(
        "supervisor_pre",
        route_by_job_type,
        {
            "log_analysis": "fetch_logs",
            "knowledge_query": "queryrag",
            "asset_query": "asset",
            "generic_rule": "queryrag",
            "ip_reputation": "ti"  # IP reputation goes directly to TI
        }
    )
    
    # ========================================
    # Log Analysis Flow (Sequential)
    # ========================================
    graph.add_edge("fetch_logs", "normalize")
    graph.add_edge("normalize", "chunk")
    graph.add_edge("chunk", "analyze")
    graph.add_edge("analyze", "merge_results")
    graph.add_edge("merge_results", "summary")
    graph.add_edge("summary", "export_csv")
    graph.add_edge("export_csv", "supervisor_post")
    
    # ========================================
    # Post-Supervisor Routing
    # ========================================
    graph.add_conditional_edges(
        "supervisor_post",
        route_post_supervisor,
        {
            "ti": "ti",
            "genrule": "genrule",
            "recommend": "recommend",
            "report": "report",
            "telegram": "send_telegram",
            "end": END
        }
    )
    
    # ========================================
    # TI → Asset (optional) or GenRule check
    # ========================================
    graph.add_conditional_edges(
        "ti",
        route_after_ti,
        {
            "asset": "asset",
            "genrule": "genrule",
            "recommend": "recommend",
            "report": "report",
            "telegram": "send_telegram",
            "end": END
        }
    )
    
    # ========================================
    # Asset → Dynamic routing based on job_type
    # ========================================
    # Asset node is used in two flows:
    # 1. log_analysis: TI → asset → genrule/recommend/report/telegram/END
    # 2. asset_query: supervisor_pre → asset → queryrag/END
    graph.add_conditional_edges(
        "asset",
        route_asset_query,
        {
            "queryrag": "queryrag",
            "genrule": "genrule",
            "recommend": "recommend",
            "report": "report",
            "telegram": "send_telegram",
            "end": END
        }
    )
    
    # ========================================
    # GenRule → Recommend/Report/Telegram/END
    # ========================================
    graph.add_conditional_edges(
        "genrule",
        route_check_recommend,
        {
            "recommend": "recommend",
            "report": "report",
            "telegram": "send_telegram",
            "end": END
        }
    )
    
    # ========================================
    # Recommend → Report/Telegram/END
    # ========================================
    graph.add_conditional_edges(
        "recommend",
        route_check_report,
        {
            "report": "report",
            "telegram": "send_telegram",
            "end": END
        }
    )
    
    # ========================================
    # Report → Telegram/END
    # ========================================
    graph.add_conditional_edges(
        "report",
        route_check_telegram,
        {
            "telegram": "send_telegram",
            "end": END
        }
    )
    
    # ========================================
    # Telegram → END
    # ========================================
    graph.add_edge("send_telegram", END)
    
    # ========================================
    # Knowledge Query Flow
    # ========================================
    graph.add_conditional_edges(
        "queryrag",
        route_after_queryrag,
        {
            "genrule": "genrule",  # For generic_rule job
            "recommend": "recommend",  # For knowledge_query job
            "end": END
        }
    )
    
    logger.info("[graph_builder] Added all edges to graph")
