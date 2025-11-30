"""
V3 Supervisor: Job classification and orchestration logic.

This module provides Pre-Supervisor and Post-Supervisor logic for V3:
- Pre-Supervisor: Classify job type and set initial need_* flags
- Post-Supervisor: Update need_* flags based on analysis results
"""

import logging
from typing import Optional
from backend.models import AnalysisState, FindingsSummary

logger = logging.getLogger(__name__)


class Supervisor:
    """
    V3 Supervisor for job classification and orchestration.
    """
    
    # Knowledge query keywords
    KNOWLEDGE_KEYWORDS = [
        "là gì", "what is", "explain", "giải thích",
        "cách phòng chống", "how to prevent", "how to defend",
        "tấn công", "attack", "vulnerability", "lỗ hổng",
        "OWASP", "MITRE", "CVE", "Sigma",
        "phòng thủ", "defense", "mitigation", "giảm thiểu"
    ]
    
    @staticmethod
    def pre_supervisor(state: AnalysisState) -> AnalysisState:
        """
        Pre-Supervisor: Classify job type and set initial need_* flags.
        
        Args:
            state: AnalysisState with user_query and log_source
            
        Returns:
            Updated state with job_type and need_* flags
        """
        logger.info("Pre-Supervisor: Classifying job type...")
        
        # Check if log_source is provided (None means knowledge query from QueryAgent)
        log_source = state.get('log_source')
        has_log_source = log_source is not None and (
            isinstance(log_source, dict) and log_source.get('type') is not None
        )
        
        # Check if query contains knowledge keywords
        user_query = state.get('user_query', '').lower()
        is_knowledge = any(kw in user_query for kw in Supervisor.KNOWLEDGE_KEYWORDS)
        
        # NOTE: enable_genrule is ONLY used in generic_rule workflow
        # It is IGNORED in log_analysis workflow
        
        # Classify job type
        # Priority 0: Check if this is generic rule generation (special case)
        source_type = state.get('source_type')
        if source_type == 'generic_rule':
            state['job_type'] = 'generic_rule'
            state['need_analyze'] = False  # No log analysis
            state['need_ti'] = False
            state['need_genrule'] = True  # Generate GENERIC rule
            state['need_recommend'] = True  # General recommendations
            state['need_report'] = False
            state['need_queryrag'] = True  # Query KB for attack info
            state['need_asset'] = False
            logger.info("Job type: generic_rule (rule generation without specific logs)")
        
        # Priority 1: If source_type is ip_reputation → ip_reputation_check
        elif state.get('source_type') == 'ip_reputation':
            state['job_type'] = 'ip_reputation_check'
            state['need_analyze'] = False
            state['need_ti'] = True  # Use TI agent to check IPs
            state['need_genrule'] = False
            state['need_recommend'] = False
            state['need_report'] = False
            state['need_queryrag'] = False
            state['need_asset'] = True  # Check if IP is in asset DB
            logger.info("Job type: ip_reputation_check")
        
        # Priority 2: If log_source is None or empty dict → knowledge_query
        elif log_source is None or (isinstance(log_source, dict) and not log_source):
            state['job_type'] = 'knowledge_query'
            state['need_analyze'] = False
            state['need_ti'] = False
            state['need_genrule'] = False  # No rules for pure knowledge queries
            state['need_recommend'] = False
            state['need_report'] = False
            state['need_queryrag'] = True
            state['need_asset'] = False
            logger.info("Job type: knowledge_query (no log source)")
            
        # Priority 2: Has log source → log_analysis
        elif has_log_source:
            state['job_type'] = 'log_analysis'
            state['need_analyze'] = True
            state['need_ti'] = True
            state['need_genrule'] = False  # LUÔN False cho log_analysis!
            state['need_recommend'] = True
            state['need_report'] = True
            state['need_queryrag'] = False
            state['need_asset'] = False
            logger.info("Job type: log_analysis")
            logger.info("NOTE: enable_genrule is IGNORED in log_analysis workflow!")
            
        # Priority 3: No log source + knowledge keywords → knowledge_query
        elif is_knowledge:
            state['job_type'] = 'knowledge_query'
            state['need_analyze'] = False
            state['need_ti'] = False
            state['need_genrule'] = False  # No rules for knowledge queries
            state['need_recommend'] = False
            state['need_report'] = False
            state['need_queryrag'] = True
            state['need_asset'] = False
            logger.info("Job type: knowledge_query")
            
        # Priority 4: Default to log_analysis if unclear
        else:
            state['job_type'] = 'log_analysis'
            state['need_analyze'] = True
            state['need_ti'] = False
            state['need_genrule'] = False  # LUÔN False cho log_analysis!
            state['need_recommend'] = True
            state['need_report'] = False
            state['need_queryrag'] = False
            state['need_asset'] = False
            logger.info("Job type: log_analysis (default)")
            logger.info("NOTE: enable_genrule is IGNORED in log_analysis workflow!")
        
        logger.info(f"Need flags: analyze={state['need_analyze']}, ti={state['need_ti']}, "
                   f"genrule={state['need_genrule']}, recommend={state['need_recommend']}, "
                   f"report={state['need_report']}, queryrag={state['need_queryrag']}")
        
        return state
    
    @staticmethod
    def post_supervisor(state: AnalysisState) -> AnalysisState:
        """
        Post-Supervisor: Update need_* flags based on analysis results.
        
        Called after Analyze phase to dynamically adjust workflow based on:
        - has_attack: Whether attacks were detected
        - severity_level: Severity of detected attacks
        
        NOTE: need_genrule is ALWAYS False in log_analysis workflow!
        Log Analysis NEVER generates rules. Use generic_rule workflow instead.
        
        Args:
            state: AnalysisState with findings_summary populated
            
        Returns:
            Updated state with adjusted need_* flags
        """
        logger.info("Post-Supervisor: Updating need_* flags based on findings...")
        
        findings = state.get('findings_summary')
        if not findings:
            logger.warning("No findings_summary available, skipping Post-Supervisor")
            return state
        
        has_attack = findings.get('has_attack', False)
        severity = findings.get('severity_level', 'low')
        
        if not has_attack:
            # No attack detected → disable all features (including GenRule)
            logger.info("No attacks detected → disabling TI/GenRule/Recommend/Report")
            state['need_ti'] = False
            state['need_genrule'] = False  # Override: no attacks = no rules
            state['need_recommend'] = False
            state['need_report'] = False
            
        elif severity in ['low', 'medium']:
            # Low/medium severity → disable TI
            logger.info(f"Severity: {severity} → disabling TI")
            state['need_ti'] = False
            state['need_genrule'] = False  # Keep False
            state['need_recommend'] = True
            state['need_report'] = True
            
        elif severity in ['high', 'critical']:
            # High/critical severity → enable TI
            logger.info(f"Severity: {severity} → enabling TI")
            state['need_ti'] = True
            state['need_genrule'] = False  # Keep False (log_analysis NEVER generates rules!)
            state['need_recommend'] = True
            state['need_report'] = True
        
        logger.info(f"Updated need flags: ti={state['need_ti']}, genrule={state['need_genrule']} (ALWAYS False in log_analysis!), "
                   f"recommend={state['need_recommend']}, report={state['need_report']}")
        
        return state
