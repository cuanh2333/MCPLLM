"""
Data models for V1 Log Analyzer System.

This module defines the core data structures used throughout the analysis workflow,
including event normalization, attack classification, and findings reporting.
"""

from typing import TypedDict, Optional, Literal, Any


class Event(TypedDict):
    """
    Normalized log event structure.
    
    Represents a single log entry parsed into standardized fields for analysis.
    All fields except event_id and raw_log may be None if parsing fails.
    
    Attributes:
        event_id: Unique identifier for the event (format: timestamp_sequential)
        timestamp: Timestamp from the log entry
        src_ip: Source IP address of the request
        method: HTTP method (GET, POST, etc.)
        uri: Request URI/path
        status: HTTP response status code
        user_agent: User-Agent header from the request
        raw_log: Original unparsed log line
    """
    event_id: str
    timestamp: Optional[str]
    src_ip: Optional[str]
    method: Optional[str]
    uri: Optional[str]
    status: Optional[int]
    user_agent: Optional[str]
    raw_log: str


class EventLabel(TypedDict):
    """
    V2: Extended label for analyzed event.
    
    Attributes:
        is_attack: True if event is classified as attack
        attack_type: Type of attack (sqli, xss, lfi, etc.) or "benign"
        short_note: Brief explanation of the classification
        mitre_technique: MITRE ATT&CK technique ID (e.g., "T1190") or None
        confidence: Confidence score (0.0 to 1.0)
    """
    is_attack: bool
    attack_type: str
    short_note: str
    mitre_technique: Optional[str]
    confidence: float


class AttackBreakdown(TypedDict):
    """
    Statistical breakdown for a specific attack type.
    
    Provides count, percentage, and source IPs for each detected attack category.
    
    Attributes:
        attack_type: Type of attack (sqli, xss, lfi, rfi, rce, xxe, path_traversal, command_injection)
        count: Number of events classified as this attack type
        percentage: Percentage of total attack events (0-100)
        source_ips: List of unique source IP addresses for this attack type
    """
    attack_type: str
    count: int
    percentage: float
    source_ips: list[str]


class FindingsSummary(TypedDict):
    """
    High-level summary of analysis findings.
    
    Aggregates attack detection results with severity assessment and summary text.
    
    Attributes:
        has_attack: True if any attack events were detected
        total_events: Total number of events analyzed (only events with labels)
        total_attack_events: Number of events classified as attacks (non-benign)
        attack_breakdown: List of AttackBreakdown for each detected attack type
        mitre_techniques: List of MITRE ATT&CK techniques detected (V2)
        severity_level: Overall severity (low/medium/high/critical) based on attack types and volume
        summary_text: Human-readable summary in Vietnamese
        sample_events: Sample attack events for reference (V2)
    """
    has_attack: bool
    total_events: int
    total_attack_events: int
    attack_breakdown: list[AttackBreakdown]
    mitre_techniques: list[str]
    severity_level: Literal['low', 'medium', 'high', 'critical']
    summary_text: str
    sample_events: list[dict]


class AttackEventsRef(TypedDict):
    """
    Reference to exported attack events data.
    
    Provides metadata about the CSV export containing detailed attack event data.
    
    Attributes:
        report_id: Unique identifier for this analysis report (timestamp-based)
        total_attack_events: Number of attack events exported to CSV
        csv_path: File path to the exported CSV file, or None if no attacks detected
    """
    report_id: str
    total_attack_events: int
    csv_path: Optional[str]


class TISummary(TypedDict):
    """
    V2: Threat Intelligence summary.
    
    Attributes:
        iocs: List of IOC analysis results
        ti_overall: Overall TI assessment with max_risk and notes
    """
    iocs: list[dict]
    ti_overall: dict


class AttackStatistics(TypedDict):
    """
    Simple attack statistics for recommendation report - similar to Statistics page.
    
    Attributes:
        ip_details: List of IP attack details (like current Statistics page)
        uri_details: List of most attacked URIs
        summary: Basic summary stats
    """
    ip_details: list[dict[str, Any]]  # [{"ip": "1.2.3.4", "attack_type": "sqli", "count": 50, "status": "high"}]
    uri_details: list[dict[str, Any]]  # [{"uri": "/admin", "count": 30, "method": "POST"}]
    summary: dict[str, Any]           # {"total_ips": 10, "total_uris": 5}


class RecommendSummary(TypedDict):
    """
    V2: Recommendation summary.
    
    Attributes:
        severity_overall: Overall severity assessment
        immediate_actions: List of immediate actions to take
        short_term_actions: List of short-term actions
        long_term_actions: List of long-term actions
        notes: Additional notes
    """
    severity_overall: Literal['low', 'medium', 'high', 'critical']
    immediate_actions: list[str]
    short_term_actions: list[str]
    long_term_actions: list[str]
    notes: str


class GenRuleSummary(TypedDict):
    """
    V3: Generated detection rules summary.
    
    Attributes:
        main_attack_type: Primary attack type for rule generation
        sigma_rule: Sigma detection rule in YAML format
        splunk_spl: Splunk SPL query
        qradar_aql: QRadar AQL query (deprecated, kept for backward compatibility)
        notes: Notes on rule tuning and false positives
    """
    main_attack_type: str
    sigma_rule: str
    splunk_spl: str
    qradar_aql: str  # Deprecated but kept for compatibility
    notes: str


class AnalysisState(TypedDict):
    """
    Complete state of an analysis workflow (V3 extended).
    
    Tracks input parameters, processing state, and output results throughout
    the analysis lifecycle. Updated incrementally as each workflow step completes.
    
    Input fields (set at initialization):
        source_type: Type of log source (splunk/file/cron)
        user_query: User's natural language query describing the analysis
        log_source: Source-specific configuration dict (e.g., {type: "file", path: "..."})
    
    Processing fields (populated during workflow):
        events: List of normalized Event objects after log parsing
        labels: V2 extended labels with EventLabel structure
    
    Output fields (populated after analysis):
        findings_summary: High-level findings summary, or None if not yet analyzed
        attack_events_ref: Reference to exported attack data, or None if not yet exported
        analyzed: True when analysis workflow completes successfully
        
    V2 fields:
        ti_summary: Threat intelligence summary
        ti_done: True when TI analysis completes
        recommend_summary: Recommendation summary
        recommend_done: True when recommendation generation completes
        report_markdown: Full markdown report
        report_done: True when report generation completes
        pdf_path: PDF report path
        
    V3 fields:
        job_type: Type of job (log_analysis/knowledge_query/asset_query/mixed)
        need_analyze: Flag to run analyze phase
        need_ti: Flag to run TI analysis
        need_genrule: Flag to run rule generation
        need_recommend: Flag to run recommendations
        need_report: Flag to run report generation
        need_queryrag: Flag to run RAG query
        need_asset: Flag to run asset management (V4)
        genrule_summary: Generated detection rules
        genrule_done: True when rule generation completes
        rag_answer: RAG answer from knowledge base
    """
    # Input parameters
    source_type: Literal['splunk', 'file', 'cron']
    user_query: str
    log_source: dict
    
    # Processing state
    raw_logs: list[str]  # Raw log lines from fetch_logs
    events: list[Event]
    labels: Optional[dict[str, EventLabel]]
    
    # Output results (V1)
    findings_summary: Optional[FindingsSummary]
    attack_events_ref: Optional[AttackEventsRef]
    analyzed: bool
    
    # V2 fields
    ti_summary: Optional[TISummary]
    ti_done: bool
    recommend_summary: Optional[RecommendSummary]
    recommend_done: bool
    report_markdown: Optional[str]
    report_done: bool
    pdf_path: Optional[str]
    
    # V3 fields
    job_type: Literal['log_analysis', 'knowledge_query', 'asset_query', 'mixed', 'generic_rule', 'ip_reputation']
    need_analyze: bool
    need_ti: bool
    need_genrule: bool
    need_recommend: bool
    need_report: bool
    need_queryrag: bool
    need_asset: bool
    genrule_summary: Optional[GenRuleSummary]
    genrule_done: bool
    rag_answer: Optional[str]
    rag_sources: Optional[list[dict]]  # RAG source citations with metadata
    parsed_intent: Optional[dict]  # Parsed intent from QueryAgent (e.g., IPs for ip_reputation)
    
    # V4 fields (LangGraph + SupervisorAgent)
    asset_summary: Optional[dict]  # AssetAgent output
    supervisor_reasoning: Optional[str]  # SupervisorAgent reasoning
    workflow_path: list[str]  # Track nodes visited
    graph_metadata: Optional[dict]  # Graph execution metadata
    enable_genrule: bool  # User preference for genrule generation
    send_telegram: bool  # User preference for Telegram notification (default: False, auto True for cron)
