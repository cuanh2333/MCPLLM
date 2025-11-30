"""
Analysis orchestrator for V1 Log Analyzer System.

This module provides the AnalysisOrchestrator class that coordinates the complete
analysis workflow: fetch logs → normalize → analyze → summarize → export.
"""

import logging
import os
from datetime import datetime
from typing import Optional

from langchain_groq import ChatGroq
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from backend.models import AnalysisState, Event, AttackEventsRef, EventLabel
from backend.config import settings
from backend.normalizer import normalize_log_entry
from backend.agents.analyze_agent import LLMAnalyzer
from backend.summary import generate_findings_summary
from backend.utils.exporter import export_attack_events_csv
from backend.agents.ti_agent import TIAgent
from backend.agents.recommend_agent import RecommendAgent
from backend.agents.report_agent import ReportAgent
from backend.utils.llm_factory import (
    create_analyze_agent_llm,
    create_ti_agent_llm,
    create_recommend_agent_llm,
    create_report_agent_llm
)
# PDF generator is now integrated in ReportAgent
# from backend.utils.pdf_generator import PDFGenerator
from backend.services.telegram_notifier import TelegramNotifier
# V3 imports
from backend.supervisor import Supervisor
from backend.agents.genrule_agent import get_genrule_agent
from backend.agents.queryrag_agent import get_queryrag_agent


# Configure logging
logger = logging.getLogger(__name__)


class AnalysisOrchestrator:
    """
    Main orchestrator for log analysis workflow.
    
    Coordinates the complete analysis pipeline:
    1. Fetch logs from MCP server (Splunk or file)
    2. Normalize raw logs into Event structures
    3. Analyze events with LLM for attack classification
    4. Generate findings summary with severity assessment
    5. Export attack events to CSV
    
    Attributes:
        llm: ChatGroq LLM instance for analysis
        mcp_server_path: Path to MCP server script
    
    Requirements: 7.1, 7.2
    """
    
    def __init__(self):
        """
        Initialize AnalysisOrchestrator with LLM and MCP configuration.
        
        Loads configuration from settings and initializes the LLM
        instance for attack classification using configured provider.
        
        Requirements: 7.1, V2, V4
        """
        # Initialize LLM for AnalyzeAgent with agent-specific config
        self.llm = create_analyze_agent_llm()
        
        # Store MCP server path
        self.mcp_server_path = settings.mcp_server_path
        
        # V4: Compile LangGraph workflow if enabled
        self.graph = None
        if settings.use_langgraph:
            try:
                from backend.graph_builder import build_analysis_graph
                self.graph = build_analysis_graph()
                logger.info("V4 LangGraph workflow compiled successfully")
            except Exception as e:
                logger.error(f"Failed to compile LangGraph workflow: {e}")
                logger.warning("V4 disabled, will use V3 workflow")
                self.graph = None
        
        logger.info(f"AnalysisOrchestrator initialized")
        logger.info(f"  AnalyzeAgent provider: {settings.get_analyze_agent_provider()}")
        logger.info(f"  AnalyzeAgent model: {settings.get_analyze_agent_model()}")
        logger.info(f"  AnalyzeAgent temperature: {settings.get_analyze_agent_temperature()}")
        logger.info(f"  V4 LangGraph: {'enabled' if self.graph else 'disabled'}")
    
    async def analyze(self, state: AnalysisState, enable_v2: bool = True) -> AnalysisState:
        """
        Execute complete analysis workflow (V2 extended).
        
        Coordinates all analysis steps and updates the state object with results
        at each stage. The workflow is:
        1. Fetch logs from source
        2. Normalize logs to Event objects
        3. Analyze events with LLM (V2: returns EventLabel)
        4. Generate findings summary
        5. Export attack events to CSV
        6. [V2] TI analysis (if attacks detected)
        7. [V2] Generate recommendations
        8. [V2] Generate report
        
        Args:
            state: AnalysisState initialized with input parameters
                   (source_type, user_query, log_source)
            enable_v2: Enable V2 features (TI, Recommend, Report)
        
        Returns:
            Updated AnalysisState with analysis results populated:
            - events: List of normalized Event objects
            - labels: Event labels with full classification (V2)
            - findings_summary: High-level findings summary
            - attack_events_ref: Reference to exported CSV
            - analyzed: Set to True on successful completion
            - [V2] ti_summary, recommend_summary, report_markdown
        
        Raises:
            Exception: If any step of the analysis fails
        
        Requirements: 7.2, V2-R5
        """
        logger.info(f"Starting analysis for source_type: {state['source_type']}")
        logger.info(f"User query: {state['user_query']}")
        logger.info(f"V2 features enabled: {enable_v2}")
        
        try:
            # Step 1: Fetch logs from MCP server
            logger.info("Step 1: Fetching logs...")
            raw_logs = await self.fetch_logs(state['log_source'])
            logger.info(f"Fetched {len(raw_logs)} raw log entries")
            
            # Step 2: Normalize events
            logger.info("Step 2: Normalizing events...")
            state['events'] = self.normalize_events(raw_logs)
            logger.info(f"Normalized {len(state['events'])} events")
            
            # Step 3: Analyze with LLM (V2: returns EventLabel)
            logger.info("Step 3: Analyzing events with LLM...")
            labels = await self.analyze_with_llm(state['events'], state['user_query'])
            state['labels'] = labels
            logger.info(f"Analyzed {len(labels)} events")
            
            # Step 4: Generate summary
            logger.info("Step 4: Generating findings summary...")
            state['findings_summary'] = self.generate_summary(state['events'], labels)
            logger.info(f"Summary generated: {state['findings_summary']['total_attack_events']} attacks detected")
            
            # Step 5: Export CSV
            logger.info("Step 5: Exporting attack events to CSV...")
            state['attack_events_ref'] = self.export_csv(state['events'], labels)
            logger.info(f"CSV export complete: {state['attack_events_ref']['csv_path']}")
            
            # Mark V1 analysis as complete
            state['analyzed'] = True
            logger.info("V1 analysis workflow completed successfully")
            
            # V2: Early exit if no attacks detected
            if enable_v2 and not state['findings_summary']['has_attack']:
                logger.info("No attacks detected, skipping V2 analysis")
                state['ti_done'] = True
                state['recommend_done'] = True
                state['report_done'] = True
                return state
            
            # V2: Step 6 - TI Analysis
            if enable_v2:
                logger.info("Step 6 (V2): Running TI analysis...")
                # Create TIAgent with agent-specific LLM config
                ti_llm = create_ti_agent_llm()
                ti_agent = TIAgent(ti_llm, self.mcp_server_path)
                logger.info(f"  TIAgent provider: {settings.get_ti_agent_provider()}")
                logger.info(f"  TIAgent model: {settings.get_ti_agent_model()}")
                state['ti_summary'] = await ti_agent.analyze(state['events'], labels)
                state['ti_done'] = True
                logger.info("TI analysis complete")
                
                # Update CSV with AbuseIPDB data
                if state.get('attack_events_ref') and state['attack_events_ref'].get('csv_path'):
                    try:
                        csv_path = state['attack_events_ref']['csv_path']
                        logger.info(f"Updating CSV with TI data: {csv_path}")
                        
                        import pandas as pd
                        
                        # Read existing CSV
                        df = pd.read_csv(csv_path, encoding='utf-8')
                        
                        # Create IP to TI data mapping
                        ti_map = {}
                        for ioc in state['ti_summary'].get('iocs', []):
                            ip = ioc.get('ip')
                            if ip:
                                ti_map[ip] = {
                                    'abuse_score': ioc.get('abuse_score', 0),
                                    'abuse_risk': ioc.get('risk', 'unknown'),
                                    'abuse_status': ioc.get('notes', '')
                                }
                        
                        # Add TI columns
                        df['abuse_score'] = df['src_ip'].map(lambda ip: ti_map.get(ip, {}).get('abuse_score', 0))
                        df['abuse_risk'] = df['src_ip'].map(lambda ip: ti_map.get(ip, {}).get('abuse_risk', 'unknown'))
                        df['abuse_status'] = df['src_ip'].map(lambda ip: ti_map.get(ip, {}).get('abuse_status', 'Chưa kiểm tra'))
                        
                        # Save updated CSV
                        df.to_csv(csv_path, index=False, encoding='utf-8')
                        logger.info(f"Updated CSV with TI data for {len(ti_map)} IPs")
                        
                    except Exception as e:
                        logger.warning(f"Failed to update CSV with TI data: {e}")
                
                # Step 7: Generate recommendations
                logger.info("Step 7 (V2): Generating recommendations...")
                # Create RecommendAgent with agent-specific LLM config
                recommend_llm = create_recommend_agent_llm()
                recommend_agent = RecommendAgent(recommend_llm)
                logger.info(f"  RecommendAgent provider: {settings.get_recommend_agent_provider()}")
                logger.info(f"  RecommendAgent model: {settings.get_recommend_agent_model()}")
                state['recommend_summary'] = await recommend_agent.generate(
                    state['findings_summary'],
                    state['ti_summary']
                )
                state['recommend_done'] = True
                logger.info("Recommendations generated")
                
                # Step 8: Generate report (markdown + PDF)
                logger.info("Step 8 (V2): Generating markdown report and PDF...")
                # Create ReportAgent with agent-specific LLM config
                report_llm = create_report_agent_llm()
                report_agent = ReportAgent(report_llm, enable_pdf=True)
                logger.info(f"  ReportAgent provider: {settings.get_report_agent_provider()}")
                logger.info(f"  ReportAgent model: {settings.get_report_agent_model()}")
                
                # Generate markdown and PDF
                report_markdown, pdf_path = await report_agent.generate(
                    state['findings_summary'],
                    state['ti_summary'],
                    state['recommend_summary'],
                    state['attack_events_ref'],
                    export_pdf=True,
                    output_dir="./output"
                )
                
                state['report_markdown'] = report_markdown
                state['report_done'] = True
                
                if pdf_path:
                    state['pdf_path'] = pdf_path
                    logger.info(f"Report generated (markdown + PDF): {pdf_path}")
                else:
                    logger.info("Report generated (markdown only)")
                
                # Step 10: Send Telegram notification (alert + PDF + CSV)
                logger.info("Step 10 (V2): Sending Telegram notification...")
                try:
                    telegram = TelegramNotifier()
                    if telegram.is_configured():
                        # Send complete report (alert + PDF + CSV)
                        telegram.send_complete_report(
                            findings=state['findings_summary'],
                            ti_summary=state['ti_summary'],
                            recommend=state['recommend_summary'],
                            attack_ref=state['attack_events_ref'],
                            pdf_path=state.get('pdf_path'),
                            csv_path=state['attack_events_ref'].get('csv_path')
                        )
                        logger.info("Telegram notification sent (alert + PDF + CSV)")
                    else:
                        logger.info("Telegram not configured, skipping notification")
                except Exception as e:
                    logger.error(f"Failed to send Telegram notification: {e}")
                
                logger.info("V2 analysis workflow completed successfully")
            
            return state
        
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            raise
    
    async def fetch_logs(self, log_source: dict) -> list[str]:
        """
        Fetch logs from MCP server based on log source configuration.
        
        Connects to the MCP server and calls the appropriate tool based on
        the log_source.type field. Supports:
        - "file": Load logs from local file using load_log_file tool
        - "splunk": Retrieve logs from Splunk using splunk_search tool
        
        Args:
            log_source: Dictionary containing source configuration:
                - type: "file" or "splunk"
                - For file: {type: "file", path: "/path/to/log.txt", max_lines: 1000}
                - For splunk: {type: "splunk", index: "main", sourcetype: "...", ...}
        
        Returns:
            List of raw log lines as strings
        
        Raises:
            ValueError: If log_source.type is not supported
            Exception: If MCP connection or tool execution fails
        
        Requirements: 1.1, 1.2, 1.3, 8.1
        """
        source_type = log_source.get('type')
        
        if not source_type:
            raise ValueError("log_source must contain 'type' field")
        
        logger.info(f"Connecting to MCP server: {self.mcp_server_path}")
        
        try:
            # Set up MCP server parameters
            # Pass environment variables to MCP server subprocess
            import os
            server_params = StdioServerParameters(
                command="python",
                args=[self.mcp_server_path],
                env=dict(os.environ)  # Pass all environment variables
            )
            
            # Connect to MCP server and call appropriate tool
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    # Initialize session
                    await session.initialize()
                    logger.info("MCP session initialized")
                    
                    # Call appropriate tool based on source type
                    if source_type == "file":
                        # Load logs from file
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
                        
                        # Extract log lines from result
                        # MCP returns list of TextContent objects, each containing one log line
                        if result.content:
                            logs = [content.text for content in result.content]
                        else:
                            logs = []
                        
                        logger.info(f"Retrieved {len(logs)} logs from file")
                        return logs
                    
                    elif source_type == "splunk":
                        # Retrieve logs from Splunk
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
                        
                        # Extract log lines from result
                        # MCP returns list of TextContent objects, each containing one log line
                        if result.content:
                            logs = [content.text for content in result.content]
                        else:
                            logs = []
                        
                        logger.info(f"Retrieved {len(logs)} logs from Splunk")
                        return logs
                    
                    elif source_type == "cron_splunk":
                        # Retrieve logs using cron-specific Splunk query (default: -7h-5m to -7h)
                        logger.info("Calling cron_splunk_query tool (default: -7h-5m to -7h)")
                        
                        result = await session.call_tool(
                            "cron_splunk_query",
                            arguments={}
                        )
                        
                        # Extract log lines from result
                        # MCP returns list of TextContent objects, each containing one log line
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
    
    def normalize_events(self, raw_logs: list[str]) -> list[Event]:
        """
        Normalize raw log entries into Event structures.
        
        Parses each raw log line using the normalizer module and generates
        sequential event IDs with timestamp prefix. Handles parsing failures
        gracefully by creating Event objects with null fields.
        
        Args:
            raw_logs: List of raw log line strings
        
        Returns:
            List of normalized Event objects with unique event_ids
        
        Requirements: 2.1, 2.2, 2.3, 2.4
        """
        events = []
        timestamp_prefix = datetime.now().strftime("%Y%m%d")
        
        logger.info(f"Normalizing {len(raw_logs)} raw log entries")
        
        for i, raw_log in enumerate(raw_logs, 1):
            # Generate sequential event_id with timestamp prefix
            event_id = f"evt_{timestamp_prefix}_{i:05d}"
            
            try:
                # Normalize log entry
                event = normalize_log_entry(raw_log, event_id)
                events.append(event)
            
            except Exception as e:
                # Log parsing error but continue processing
                logger.warning(f"Failed to normalize log entry {event_id}: {e}")
                
                # Create minimal event with null fields
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
        
        logger.info(f"Successfully normalized {len(events)} events")
        return events
    
    async def analyze_with_llm(self, events: list[Event], user_query: str = "") -> dict[str, EventLabel]:
        """
        Analyze events with LLM for attack classification (V2 extended).
        
        Creates an LLMAnalyzer instance and processes events in chunks to
        classify each event as an attack type or benign traffic.
        
        Args:
            events: List of normalized Event objects to analyze
            user_query: User's question/focus area for analysis
        
        Returns:
            Dictionary mapping event_id to EventLabel with full classification.
            Attack types: sqli, xss, lfi, rfi, rce, xxe, path_traversal,
                         command_injection, or benign
        
        Requirements: 3.1, 3.2, 3.3, V2-R1
        """
        logger.info(f"Analyzing {len(events)} events with LLM")
        logger.info(f"User query: {user_query}")
        
        # Create LLMAnalyzer instance with configured LLM
        analyzer = LLMAnalyzer(self.llm)
        
        # Analyze events and get classifications
        labels = await analyzer.analyze_events(events, user_query)
        
        # Log statistics
        attack_count = sum(1 for label in labels.values() if label['is_attack'])
        logger.info(f"LLM analysis complete: {attack_count}/{len(labels)} attacks detected")
        
        return labels
    
    def generate_summary(self, events: list[Event], labels: dict[str, EventLabel]):
        """
        Generate findings summary from analyzed events (V2 extended).
        
        Calls the summary module to generate a comprehensive findings summary
        including attack breakdown, severity assessment, and Vietnamese summary text.
        
        Args:
            events: List of normalized Event objects
            labels: Dictionary mapping event_id to EventLabel
        
        Returns:
            FindingsSummary with complete analysis results including:
            - has_attack: Whether any attacks were detected
            - total_events: Total number of events analyzed
            - total_attack_events: Number of attack events
            - attack_breakdown: Detailed breakdown by attack type
            - mitre_techniques: List of MITRE techniques (V2)
            - severity_level: Overall severity (low/medium/high/critical)
            - summary_text: Vietnamese summary text
            - sample_events: Sample attack events (V2)
        
        Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, V2-R1
        """
        logger.info("Generating findings summary")
        
        # Generate summary using summary module
        findings_summary = generate_findings_summary(events, labels)
        
        logger.info(f"Summary generated: {findings_summary['total_attack_events']} attacks, "
                   f"severity: {findings_summary['severity_level']}")
        
        return findings_summary
    
    def export_csv(self, events: list[Event], labels: dict[str, EventLabel]) -> AttackEventsRef:
        """
        Export attack events to CSV and create reference (V2 compatible).
        
        Calls the exporter module to write attack events to a timestamped CSV file
        and creates an AttackEventsRef with report metadata.
        
        Args:
            events: List of normalized Event objects
            labels: Dictionary mapping event_id to EventLabel
        
        Returns:
            AttackEventsRef containing:
            - report_id: Unique timestamp-based report identifier
            - total_attack_events: Number of attack events exported
            - csv_path: Path to exported CSV file, or None if no attacks
        
        Requirements: 5.1, 5.2, 5.3, 7.3, 7.4, 7.5, V2
        """
        logger.info("Exporting attack events to CSV")
        
        # Generate report_id using timestamp
        report_id = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Export attack events to CSV
        csv_path = export_attack_events_csv(events, labels)
        
        # Count total attack events
        total_attack_events = sum(
            1 for event_id, label in labels.items() 
            if label['is_attack']
        )
        
        # Create AttackEventsRef
        attack_events_ref = AttackEventsRef(
            report_id=report_id,
            total_attack_events=total_attack_events,
            csv_path=csv_path
        )
        
        if csv_path:
            logger.info(f"Exported {total_attack_events} attack events to {csv_path}")
        else:
            logger.info("No attack events to export")
        
        return attack_events_ref

    async def analyze_v3(self, state: AnalysisState, enable_v3: bool = True) -> AnalysisState:
        """
        Execute complete analysis workflow (V3 extended).
        
        V3 adds:
        - Pre-Supervisor: Job classification (log_analysis vs knowledge_query)
        - Post-Supervisor: Dynamic need_* flag updates based on severity
        - GenRuleAgent: Generate Sigma/SPL/AQL rules for high/critical attacks
        - QueryRAGAgent: Answer knowledge queries using OWASP/MITRE/Sigma KB
        
        Workflow:
        1. Pre-Supervisor: Classify job_type and set need_* flags
        2. [IF job_type = "log_analysis"]
           a. Fetch logs → Normalize → Analyze → Summary → CSV
           b. Post-Supervisor: Update need_* flags based on severity
           c. [IF need_ti] TI Analysis
           d. [IF need_genrule] Generate Rules
           e. [IF need_recommend] Recommendations
           f. [IF need_report] Report + PDF
        3. [IF job_type = "knowledge_query"]
           a. [IF need_queryrag] Query KB and synthesize answer
           b. [IF need_recommend] General recommendations
        
        Args:
            state: AnalysisState initialized with input parameters
            enable_v3: Enable V3 features (GenRule, QueryRAG, Supervisor)
        
        Returns:
            Updated AnalysisState with V3 results
        """
        logger.info("=" * 60)
        logger.info("Starting V3 Analysis Workflow")
        logger.info("=" * 60)
        logger.info(f"User query: {state['user_query']}")
        logger.info(f"V3 features enabled: {enable_v3}")
        
        try:
            # Initialize V3 state fields
            state['genrule_done'] = False
            state['rag_answer'] = None
            state['rag_sources'] = None
            
            # Step 1: Pre-Supervisor - Classify job type
            if enable_v3:
                logger.info("\n[Pre-Supervisor] Classifying job type...")
                state = Supervisor.pre_supervisor(state)
            else:
                # V2 fallback: default to log_analysis
                state['job_type'] = 'log_analysis'
                state['need_analyze'] = True
                state['need_ti'] = True
                state['need_genrule'] = False
                state['need_recommend'] = True
                state['need_report'] = True
                state['need_queryrag'] = False
                state['need_asset'] = False
            
            job_type = state['job_type']
            logger.info(f"Job Type: {job_type}")
            
            # Branch based on job type
            if job_type == 'log_analysis':
                await self._execute_log_analysis_flow(state, enable_v3)
            
            elif job_type == 'knowledge_query':
                await self._execute_knowledge_query_flow(state, enable_v3)
            
            elif job_type == 'ip_reputation_check':
                await self._execute_ip_reputation_flow(state)
            
            elif job_type == 'generic_rule':
                await self._execute_generic_rule_flow(state, enable_v3)
            
            else:
                logger.warning(f"Unknown job_type: {job_type}, defaulting to log_analysis")
                await self._execute_log_analysis_flow(state, enable_v3)
            
            logger.info("=" * 60)
            logger.info("V3 Analysis Workflow Completed Successfully")
            logger.info("=" * 60)
            
            return state
        
        except Exception as e:
            logger.error(f"V3 Analysis failed: {e}")
            raise
    
    async def _execute_log_analysis_flow(self, state: AnalysisState, enable_v3: bool):
        """Execute log_analysis workflow."""
        logger.info("\n[Log Analysis Flow] Starting...")
        
        # Step 1: Fetch logs
        if state['need_analyze']:
            logger.info("\n[Step 1] Fetching logs...")
            raw_logs = await self.fetch_logs(state['log_source'])
            logger.info(f"Fetched {len(raw_logs)} raw log entries")
            
            # Step 2: Normalize
            logger.info("\n[Step 2] Normalizing events...")
            state['events'] = self.normalize_events(raw_logs)
            logger.info(f"Normalized {len(state['events'])} events")
            
            # Step 3: Analyze with LLM
            logger.info("\n[Step 3] Analyzing events with LLM...")
            labels = await self.analyze_with_llm(state['events'], state['user_query'])
            state['labels'] = labels
            logger.info(f"Analyzed {len(labels)} events")
            
            # Step 4: Generate summary
            logger.info("\n[Step 4] Generating findings summary...")
            state['findings_summary'] = self.generate_summary(state['events'], labels)
            logger.info(f"Summary: {state['findings_summary']['total_attack_events']} attacks, "
                       f"severity: {state['findings_summary']['severity_level']}")
            
            # Step 5: Export CSV
            logger.info("\n[Step 5] Exporting attack events to CSV...")
            state['attack_events_ref'] = self.export_csv(state['events'], labels)
            logger.info(f"CSV: {state['attack_events_ref']['csv_path']}")
            
            state['analyzed'] = True
            
            # Post-Supervisor: Update need_* flags based on findings
            if enable_v3:
                logger.info("\n[Post-Supervisor] Updating need_* flags...")
                state = Supervisor.post_supervisor(state)
        
        # Step 6: TI Analysis
        if state.get('need_ti', False):
            logger.info("\n[Step 6] Running TI analysis...")
            ti_llm = create_ti_agent_llm()
            ti_agent = TIAgent(ti_llm, self.mcp_server_path)
            state['ti_summary'] = await ti_agent.analyze(state['events'], state['labels'])
            state['ti_done'] = True
            logger.info("TI analysis complete")
        else:
            logger.info("\n[Step 6] Skipping TI analysis (need_ti=False)")
            state['ti_done'] = True
        
        # Step 7: GenRule (V3 New)
        if enable_v3 and state.get('need_genrule', False):
            logger.info("\n[Step 7] Generating detection rules (V3)...")
            genrule_agent = get_genrule_agent()
            genrule_summary, genrule_sources = await genrule_agent.generate_rules(
                state['findings_summary'],
                state.get('ti_summary')
            )
            state['genrule_summary'] = genrule_summary
            state['genrule_done'] = True
            
            # Merge genrule sources with existing rag_sources
            if genrule_sources:
                existing_sources = state.get('rag_sources') or []
                state['rag_sources'] = existing_sources + genrule_sources
                logger.info(f"Added {len(genrule_sources)} RAG sources from GenRule")
            
            logger.info(f"Rules generated for: {state['genrule_summary']['main_attack_type']}")
            
            # Export rules to files
            from backend.rule_exporter import export_rules
            rule_files = export_rules(state['genrule_summary'], output_dir="./output")
            if rule_files:
                logger.info(f"Rules exported to:")
                logger.info(f"  - Sigma: {rule_files.get('sigma_file')}")
                logger.info(f"  - SPL: {rule_files.get('spl_file')}")
                logger.info(f"  - Notes: {rule_files.get('notes_file')}")
                state['rule_files'] = rule_files
        else:
            logger.info("\n[Step 7] Skipping rule generation (need_genrule=False or V3 disabled)")
            state['genrule_done'] = True
        
        # Step 8: Recommendations
        if state.get('need_recommend', False):
            logger.info("\n[Step 8] Generating recommendations...")
            recommend_llm = create_recommend_agent_llm()
            recommend_agent = RecommendAgent(recommend_llm)
            state['recommend_summary'] = await recommend_agent.generate(
                state['findings_summary'],
                state.get('ti_summary')
            )
            state['recommend_done'] = True
            logger.info("Recommendations generated")
        else:
            logger.info("\n[Step 8] Skipping recommendations (need_recommend=False)")
            state['recommend_done'] = True
        
        # Step 9: Report + PDF
        if state.get('need_report', False):
            logger.info("\n[Step 9] Generating report (markdown + PDF)...")
            report_llm = create_report_agent_llm()
            report_agent = ReportAgent(report_llm, enable_pdf=True)
            
            report_markdown, pdf_path = await report_agent.generate(
                state['findings_summary'],
                state.get('ti_summary'),
                state.get('recommend_summary'),
                state['attack_events_ref'],
                export_pdf=True,
                output_dir="./output"
            )
            
            state['report_markdown'] = report_markdown
            state['report_done'] = True
            
            if pdf_path:
                state['pdf_path'] = pdf_path
                logger.info(f"Report generated: {pdf_path}")
            else:
                logger.info("Report generated (markdown only)")
            
            # Step 10: Telegram notification
            logger.info("\n[Step 10] Sending Telegram notification...")
            try:
                telegram = TelegramNotifier()
                if telegram.is_configured():
                    telegram.send_complete_report(
                        findings=state['findings_summary'],
                        ti_summary=state.get('ti_summary'),
                        recommend=state.get('recommend_summary'),
                        attack_ref=state['attack_events_ref'],
                        pdf_path=state.get('pdf_path'),
                        csv_path=state['attack_events_ref'].get('csv_path')
                    )
                    logger.info("Telegram notification sent")
                else:
                    logger.info("Telegram not configured, skipping")
            except Exception as e:
                logger.error(f"Telegram notification failed: {e}")
        else:
            logger.info("\n[Step 9] Skipping report generation (need_report=False)")
            state['report_done'] = True
    
    async def _execute_ip_reputation_flow(self, state: AnalysisState):
        """Execute IP reputation check workflow."""
        logger.info("\n[IP Reputation Check Flow] Starting...")
        
        # Extract IPs from parsed_intent
        parsed_intent = state.get('parsed_intent', {})
        ips = parsed_intent.get('ips', [])
        
        if not ips:
            logger.warning("No IPs found in query")
            state['ti_summary'] = {"error": "No IPs found in query"}
            return
        
        logger.info(f"Checking reputation for {len(ips)} IPs: {ips}")
        
        # Check asset DB first
        from backend.services.asset_manager import get_asset_manager
        asset_mgr = get_asset_manager()
        
        ip_results = []
        for ip in ips:
            logger.info(f"\n[IP: {ip}] Checking...")
            
            # Check asset DB
            asset_info = asset_mgr.get_asset_info(ip)
            if asset_info:
                logger.info(f"  Found in Asset DB: {asset_info.get('label')}")
            
            # Check AbuseIPDB
            from backend.agents.ti_agent import TIAgent
            from backend.utils.llm_factory import create_ti_agent_llm
            from backend.config import settings
            
            ti_llm = create_ti_agent_llm()
            ti_agent = TIAgent(ti_llm, settings.mcp_server_path)
            
            # Use analyze_ips for single IP
            ti_summary = await ti_agent.analyze_ips([ip])
            
            # Extract results
            abuse_result = None
            vt_result = None
            if ti_summary and ti_summary.get('iocs'):
                ioc = ti_summary['iocs'][0]
                abuse_result = {
                    "abuse_score": ioc.get('abuse_score', 0),
                    "risk": ioc.get('risk', 'unknown'),
                    "country": ioc.get('country'),
                    "notes": ioc.get('notes')
                }
                vt_result = {}  # Placeholder
            
            ip_results.append({
                "ip": ip,
                "asset_info": asset_info,
                "abuseipdb": abuse_result,
                "virustotal": vt_result
            })
        
        # Store results
        state['ti_summary'] = {
            "query_type": "ip_reputation_check",
            "ips_checked": len(ips),
            "results": ip_results
        }
        state['ti_done'] = True
        
        logger.info(f"IP reputation check completed for {len(ips)} IPs")
    
    async def _execute_knowledge_query_flow(self, state: AnalysisState, enable_v3: bool):
        """Execute knowledge_query workflow."""
        logger.info("\n[Knowledge Query Flow] Starting...")
        
        # Step 1: Query RAG
        if enable_v3 and state.get('need_queryrag', False):
            logger.info("\n[Step 1] Querying knowledge base (V3)...")
            
            # Detect category from query
            user_query_lower = state['user_query'].lower()
            category = None
            
            if "asset" in user_query_lower or "server" in user_query_lower or "ip address" in user_query_lower:
                category = "asset"
                logger.info("  Detected category: asset")
            elif "sigma" in user_query_lower or "detection rule" in user_query_lower or "siem" in user_query_lower:
                category = "sigma"
                logger.info("  Detected category: sigma")
            else:
                logger.info("  No category filter (full hybrid search)")
            
            # Use QueryRAGAgent with category
            queryrag_agent = get_queryrag_agent()
            state['rag_answer'] = await queryrag_agent.query_knowledge(
                user_query=state['user_query'],
                category=category
            )
            logger.info("RAG answer generated")
        else:
            logger.info("\n[Step 1] Skipping RAG query (need_queryrag=False or V3 disabled)")
            state['rag_answer'] = "RAG query disabled or not available."
        
        # Step 2: General recommendations (optional)
        if state.get('need_recommend', False):
            logger.info("\n[Step 2] Generating general recommendations...")
            # For knowledge queries, we can provide general playbook recommendations
            # without specific log analysis
            state['recommend_summary'] = {
                'severity_overall': 'info',
                'immediate_actions': [],
                'short_term_actions': [
                    'Review security best practices for the queried topic',
                    'Implement recommended controls'
                ],
                'long_term_actions': [
                    'Security awareness training',
                    'Regular security assessments'
                ],
                'notes': 'General recommendations for knowledge query'
            }
            state['recommend_done'] = True
            logger.info("General recommendations provided")
        else:
            logger.info("\n[Step 2] Skipping recommendations (need_recommend=False)")
            state['recommend_done'] = True
    
    async def _execute_generic_rule_flow(self, state: AnalysisState, enable_v3: bool):
        """
        Execute generic_rule workflow.
        
        This flow generates detection rules based on attack TYPE (from knowledge base)
        WITHOUT analyzing specific logs.
        
        Example: "Tạo Sigma rule cho SQL injection"
        → Query KB for SQL injection info
        → Generate generic Sigma/SPL/AQL rules
        """
        logger.info("\n[Generic Rule Generation Flow] Starting...")
        
        # Step 1: Query RAG for attack information
        if enable_v3 and state.get('need_queryrag', False):
            logger.info("\n[Step 1] Querying knowledge base for attack info...")
            
            queryrag_agent = get_queryrag_agent()
            state['rag_answer'] = await queryrag_agent.query_knowledge(
                user_query=state['user_query'],
                category="sigma"  # Focus on detection rules
            )
            logger.info("Attack information retrieved from KB")
        else:
            logger.info("\n[Step 1] Skipping RAG query")
            state['rag_answer'] = None
            state['rag_sources'] = None
        
        # Step 2: Generate GENERIC detection rules
        if enable_v3 and state.get('need_genrule', False):
            logger.info("\n[Step 2] Generating generic detection rules...")
            
            # Create a synthetic findings_summary for generic rule generation
            user_query = state['user_query'].lower()
            
            # Extract attack type from query
            attack_type = "unknown"
            if "sql injection" in user_query or "sqli" in user_query:
                attack_type = "sql_injection"
            elif "xss" in user_query or "cross-site scripting" in user_query:
                attack_type = "xss"
            elif "lfi" in user_query or "local file inclusion" in user_query:
                attack_type = "lfi"
            elif "rfi" in user_query or "remote file inclusion" in user_query:
                attack_type = "rfi"
            elif "rce" in user_query or "remote code execution" in user_query:
                attack_type = "rce"
            elif "command injection" in user_query:
                attack_type = "command_injection"
            
            # Create synthetic findings for GenRuleAgent
            synthetic_findings = {
                'has_attack': True,
                'total_events': 0,  # No actual events
                'total_attack_events': 0,
                'attack_breakdown': [
                    {
                        'attack_type': attack_type,
                        'count': 0,
                        'percentage': 100.0,
                        'source_ips': []
                    }
                ],
                'mitre_techniques': [],
                'severity_level': 'info',  # Generic rule, not from real attack
                'summary_text': f'Generic detection rule for {attack_type}',
                'sample_events': []
            }
            
            # Generate rules using GenRuleAgent
            genrule_agent = get_genrule_agent()
            genrule_summary, genrule_sources = await genrule_agent.generate_rules(
                synthetic_findings,
                ti_summary=None  # No TI for generic rules
            )
            state['genrule_summary'] = genrule_summary
            state['genrule_done'] = True
            
            # Save RAG sources from GenRule
            if genrule_sources:
                state['rag_sources'] = genrule_sources
                logger.info(f"Saved {len(genrule_sources)} RAG sources from GenRule")
            
            logger.info(f"Generic rules generated for: {attack_type}")
        else:
            logger.info("\n[Step 2] Skipping rule generation")
            state['genrule_done'] = True
        
        # Step 3: General recommendations
        if state.get('need_recommend', False):
            logger.info("\n[Step 3] Generating general recommendations...")
            state['recommend_summary'] = {
                'severity_overall': 'info',
                'immediate_actions': [
                    'Deploy generated detection rules to SIEM',
                    'Test rules with sample data'
                ],
                'short_term_actions': [
                    'Tune rules to reduce false positives',
                    'Monitor rule effectiveness'
                ],
                'long_term_actions': [
                    'Regular rule updates based on threat intelligence',
                    'Integrate with incident response playbooks'
                ],
                'notes': 'Generic recommendations for detection rule deployment'
            }
            state['recommend_done'] = True
            logger.info("General recommendations provided")
        else:
            logger.info("\n[Step 2] Skipping recommendations (need_recommend=False)")
            state['recommend_done'] = True
        
        # Mark as analyzed (even though no log analysis was done)
        state['analyzed'] = True
    
    async def analyze_v4(self, state: AnalysisState) -> AnalysisState:
        """
        Execute complete analysis workflow using V4 LangGraph.
        
        V4 uses LangGraph for workflow orchestration with:
        - SupervisorAgent for intelligent job classification
        - Dynamic routing based on runtime state
        - Modular nodes for each processing step
        - Built-in workflow tracking and observability
        
        Args:
            state: AnalysisState initialized with input parameters
        
        Returns:
            Updated AnalysisState with V4 results
        
        Raises:
            Exception: If graph is not compiled or execution fails
        """
        logger.info("=" * 60)
        logger.info("Starting V4 Analysis Workflow (LangGraph)")
        logger.info("=" * 60)
        logger.info(f"User query: {state.get('user_query', '')}")
        
        if not self.graph:
            raise Exception("V4 LangGraph workflow not compiled. Set USE_LANGGRAPH=true in config.")
        
        try:
            # Initialize V4 state fields if not present
            if "workflow_path" not in state:
                state["workflow_path"] = []
            if "graph_metadata" not in state:
                state["graph_metadata"] = {}
            
            # Execute LangGraph workflow
            logger.info("Invoking LangGraph workflow...")
            result = await self.graph.ainvoke(state)
            
            # Log workflow completion
            logger.info("=" * 60)
            logger.info("V4 Analysis Workflow Completed Successfully")
            logger.info("=" * 60)
            logger.info(f"Job type: {result.get('job_type')}")
            logger.info(f"Workflow path: {' → '.join(result.get('workflow_path', []))}")
            if result.get('supervisor_reasoning'):
                logger.info(f"Supervisor reasoning: {result.get('supervisor_reasoning')}")
            
            return result
        
        except Exception as e:
            logger.error(f"V4 Analysis failed: {e}", exc_info=True)
            raise
    
    async def analyze_smart(self, state: AnalysisState) -> AnalysisState:
        """
        Smart analysis with automatic V4/V3 fallback.
        
        Tries V4 first, falls back to V3 if V4 fails or is disabled.
        
        Args:
            state: AnalysisState initialized with input parameters
        
        Returns:
            Updated AnalysisState with analysis results
        """
        # Try V4 first if enabled
        if settings.use_langgraph and self.graph:
            try:
                logger.info("Using V4 LangGraph workflow")
                return await self.analyze_v4(state)
            except Exception as e:
                logger.error(f"V4 failed: {e}, falling back to V3")
                logger.warning("Falling back to V3 workflow")
        
        # Fallback to V3
        logger.info("Using V3 sequential workflow")
        return await self.analyze_v3(state, enable_v3=True)
    

