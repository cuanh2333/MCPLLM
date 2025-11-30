"""
V4 Graph Visualizer

This module provides visualization capabilities for the LangGraph workflow.
"""

import logging
from typing import Dict, Any, Optional
from langgraph.graph import StateGraph

logger = logging.getLogger(__name__)


def visualize_graph(graph: StateGraph, output_path: str = "./graph.png") -> str:
    """Generate visual representation of graph.
    
    Args:
        graph: Compiled StateGraph
        output_path: Path to save visualization
        
    Returns:
        Path to generated visualization
    """
    logger.info("[visualizer] Generating graph visualization...")
    
    try:
        # Generate Mermaid diagram
        mermaid_code = graph.get_graph().draw_mermaid()
        
        # Save to file
        mermaid_path = output_path.replace('.png', '.mmd')
        with open(mermaid_path, 'w') as f:
            f.write(mermaid_code)
        
        logger.info(f"[visualizer] Mermaid diagram saved to {mermaid_path}")
        
        # TODO: Convert to PNG (requires mermaid-cli)
        # import subprocess
        # subprocess.run(["mmdc", "-i", mermaid_path, "-o", output_path])
        
        return mermaid_path
    
    except Exception as e:
        logger.error(f"[visualizer] Failed to generate visualization: {e}")
        return ""


def visualize_execution(
    state: Dict[str, Any],
    output_path: str = "./execution.png"
) -> str:
    """Visualize actual execution path.
    
    Args:
        state: Analysis state with workflow_path
        output_path: Path to save visualization
        
    Returns:
        Path to generated visualization
    """
    logger.info("[visualizer] Generating execution visualization...")
    
    workflow_path = state.get("workflow_path", [])
    
    # Generate Mermaid with highlighted path
    mermaid_code = _generate_execution_diagram(workflow_path)
    
    # Save to file
    mermaid_path = output_path.replace('.png', '.mmd')
    with open(mermaid_path, 'w') as f:
        f.write(mermaid_code)
    
    logger.info(f"[visualizer] Execution diagram saved to {mermaid_path}")
    return mermaid_path


def _generate_execution_diagram(workflow_path: list) -> str:
    """Generate Mermaid diagram with highlighted execution path.
    
    Args:
        workflow_path: List of nodes visited
        
    Returns:
        Mermaid diagram code
    """
    mermaid = "graph TD\n"
    
    for i, node in enumerate(workflow_path):
        if i < len(workflow_path) - 1:
            next_node = workflow_path[i + 1]
            mermaid += f"    {node}[{node}] --> {next_node}[{next_node}]\n"
        else:
            mermaid += f"    {node}[{node}]\n"
    
    # Highlight visited nodes
    for node in workflow_path:
        mermaid += f"    style {node} fill:#90EE90\n"
    
    return mermaid
