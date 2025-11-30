"""
V4 Agents Module

This module contains LLM-based agents for V4:
- SupervisorAgent: Intelligent job classification
- AssetAgent: Asset enrichment
"""

from backend.agents.supervisor_agent import SupervisorAgent
from backend.agents.asset_agent import AssetAgent

__all__ = [
    "SupervisorAgent",
    "AssetAgent",
]
