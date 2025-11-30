"""
Agent Nodes for V4 LangGraph Workflow

This module contains nodes that call LLM agents for analysis,
threat intelligence, rule generation, recommendations, and reporting.
"""

import logging
from typing import Dict, Any

from backend.agents.analyze_agent import LLMAnalyzer
from backend.agents.ti_agent import TIAgent
from backend.agents.recommend_agent import RecommendAgent
from backend.agents.report_agent import ReportAgent
from backend.agents.genrule_agent import get_genrule_agent
from backend.agents.queryrag_agent import get_queryrag_agent
from backend.utils.llm_factory import (
    create_analyze_agent_llm,
    create_ti_agent_llm,
    create_recommend_agent_llm,
    create_report_agent_llm
)
from backend.config import settings

logger = logging.getLogger(__name__)


async def analyze_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze events with AnalyzeAgent.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with labels
    """
    logger.info("[analyze] Analyzing events...")
    
    try:
        events = state.get("events", [])
        user_query = state.get("user_query", "")
        
        if not events:
            logger.warning("[analyze] No events to analyze")
            state["labels"] = {}
            state["analyzed"] = True
            state["workflow_path"].append("analyze_skipped")
            return state
        
        # Create LLM and analyzer
        llm = create_analyze_agent_llm()
        analyzer = LLMAnalyzer(llm)
        
        # Analyze events
        labels = await analyzer.analyze_events(events, user_query)
        state["labels"] = labels
        state["analyzed"] = True
        
        state["workflow_path"].append("analyze")
        
        attack_count = sum(1 for label in labels.values() if label.get('is_attack'))
        logger.info(f"[analyze] Analyzed {len(labels)} events, {attack_count} attacks detected")
        return state
    
    except Exception as e:
        logger.error(f"[analyze] Failed: {e}", exc_info=True)
        state["labels"] = {}
        state["analyzed"] = False
        state["workflow_path"].append("analyze_failed")
        raise  # Critical node, re-raise


async def ti_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Run TI analysis with TIAgent.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with ti_summary
    """
    logger.info("[ti] Running threat intelligence analysis...")
    
    try:
        job_type = state.get("job_type")
        
        # For IP reputation query, get IPs from parsed_intent
        if job_type == "ip_reputation":
            parsed_intent = state.get("parsed_intent", {})
            ips = parsed_intent.get("ips", [])
            
            logger.info(f"[ti] IP reputation query - parsed_intent: {parsed_intent}")
            logger.info(f"[ti] Extracted IPs: {ips}")
            
            if not ips:
                logger.warning("[ti] No IPs found in parsed_intent")
                logger.warning(f"[ti] Full state keys: {list(state.keys())}")
                logger.warning(f"[ti] parsed_intent content: {parsed_intent}")
                state["ti_summary"] = None
                state["ti_done"] = True
                state["workflow_path"].append("ti_skipped")
                return state
            
            logger.info(f"[ti] IP reputation query for {len(ips)} IPs")
            
            # Create TI agent
            ti_llm = create_ti_agent_llm()
            ti_agent = TIAgent(ti_llm, settings.mcp_server_path)
            
            # Run TI analysis directly on IPs (no need for fake events!)
            ti_summary = await ti_agent.analyze_ips(ips)
            
            # Enrich with asset info if available
            try:
                from backend.services.asset_ip_lookup import get_asset_lookup
                asset_lookup = get_asset_lookup()
                
                # Enrich each IOC with asset info
                for ioc in ti_summary.get('iocs', []):
                    ip = ioc.get('ip')
                    if ip:
                        enriched = asset_lookup.enrich_ip_info(ip, ioc)
                        ioc['asset_info'] = enriched.get('asset_info')
                        ioc['is_internal'] = enriched.get('is_internal')
                        ioc['is_protected'] = enriched.get('is_protected')
                        ioc['is_authorized_attacker'] = enriched.get('is_authorized_attacker')
                        
                        # Add asset context to notes
                        if enriched.get('asset_info'):
                            asset = enriched['asset_info']
                            asset_note = f"\n🏢 Internal Asset: {asset.get('hostname')} ({asset.get('label')})"
                            if asset.get('description'):
                                asset_note += f"\n📝 {asset['description']}"
                            ioc['notes'] = (ioc.get('notes', '') + asset_note).strip()
                
                logger.info(f"[ti] Enriched {len(ti_summary.get('iocs', []))} IPs with asset info")
            except Exception as e:
                logger.warning(f"[ti] Failed to enrich with asset info: {e}")
            
            state["ti_summary"] = ti_summary
            state["ti_done"] = True
            state["workflow_path"].append("ti")
            return state
        
        # Normal log analysis flow
        events = state.get("events", [])
        labels = state.get("labels", {})
        
        if not events or not labels:
            logger.warning("[ti] No events or labels for TI analysis")
            state["ti_summary"] = None
            state["ti_done"] = True
            state["workflow_path"].append("ti_skipped")
            return state
        
        # Create TI agent
        ti_llm = create_ti_agent_llm()
        ti_agent = TIAgent(ti_llm, settings.mcp_server_path)
        
        # Run TI analysis
        ti_summary = await ti_agent.analyze(events, labels)
        state["ti_summary"] = ti_summary
        state["ti_done"] = True
        
        # Update CSV with AbuseIPDB data
        if state.get('attack_events_ref') and state['attack_events_ref'].get('csv_path'):
            try:
                csv_path = state['attack_events_ref']['csv_path']
                logger.info(f"[ti] Updating CSV with TI data: {csv_path}")
                
                import pandas as pd
                
                # Read existing CSV
                df = pd.read_csv(csv_path, encoding='utf-8')
                
                # Create IP to TI data mapping
                ti_map = {}
                for ioc in ti_summary.get('iocs', []):
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
                logger.info(f"[ti] Updated CSV with TI data for {len(ti_map)} IPs")
                
            except Exception as e:
                logger.warning(f"[ti] Failed to update CSV with TI data: {e}")
        
        state["workflow_path"].append("ti")
        
        logger.info(f"[ti] TI analysis complete, analyzed {len(ti_summary.get('iocs', []))} IOCs")
        return state
    
    except Exception as e:
        logger.error(f"[ti] Failed: {e}", exc_info=True)
        state["ti_summary"] = None
        state["ti_done"] = True
        state["workflow_path"].append("ti_failed")
        return state  # Non-critical, continue


async def asset_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich asset information with AssetAgent.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with asset_summary
    """
    logger.info("[asset] Enriching asset information...")
    
    try:
        # Check if TI Agent already enriched asset info
        ti_summary = state.get("ti_summary")
        if ti_summary and ti_summary.get("iocs"):
            logger.info("[asset] Reusing asset info from TI Agent")
            
            # Extract asset information from TI summary
            assets_found = []
            for ioc in ti_summary["iocs"]:
                if ioc.get("asset_info"):
                    asset = ioc["asset_info"]
                    assets_found.append({
                        "ip": ioc.get("value"),
                        "hostname": asset.get("hostname"),
                        "type": asset.get("type"),
                        "label": asset.get("label"),
                        "description": asset.get("description"),
                        "owner": asset.get("owner"),
                        "location": asset.get("location")
                    })
            
            if assets_found:
                # Format as readable answer
                answer_lines = ["**Thông tin tài sản từ hệ thống:**\n"]
                for asset in assets_found:
                    hostname = asset.get('hostname') or 'Unknown'
                    ip = asset.get('ip') or 'N/A'
                    asset_type = asset.get('type') or 'Unknown'
                    label = asset.get('label') or 'Unknown'
                    description = asset.get('description') or 'Không có mô tả'
                    
                    answer_lines.append(f"🖥️ **{hostname}** ({ip})")
                    answer_lines.append(f"   - Loại: {asset_type}")
                    answer_lines.append(f"   - Nhãn: {label}")
                    answer_lines.append(f"   - Mô tả: {description}")
                    if asset.get('owner'):
                        answer_lines.append(f"   - Chủ sở hữu: {asset['owner']}")
                    if asset.get('location'):
                        answer_lines.append(f"   - Vị trí: {asset['location']}")
                    answer_lines.append("")
                
                state["asset_summary"] = {
                    "answer": "\n".join(answer_lines)
                    # No sources - info comes from TI Agent
                }
                state["workflow_path"].append("asset")
                logger.info(f"[asset] Found {len(assets_found)} assets from TI Agent")
                return state
        
        # Fallback: Query RAG if no TI info available
        from backend.agents.asset_agent import AssetAgent
        
        user_query = state.get("user_query", "")
        if not user_query:
            logger.warning("[asset] No user query provided")
            state["asset_summary"] = None
            state["workflow_path"].append("asset_skipped")
            return state
        
        logger.info("[asset] Querying RAG for asset information")
        asset_agent = AssetAgent()
        asset_summary = await asset_agent.enrich_assets(
            query=user_query,
            context=None
        )
        
        state["asset_summary"] = asset_summary
        state["workflow_path"].append("asset")
        logger.info(f"[asset] Asset enrichment completed via RAG")
        return state
    
    except Exception as e:
        logger.error(f"[asset] Failed: {e}", exc_info=True)
        state["asset_summary"] = None
        state["workflow_path"].append("asset_failed")
        return state  # Non-critical, continue


async def genrule_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Generate detection rules with GenRuleAgent.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with genrule_summary
    """
    logger.info("[genrule] Generating detection rules...")
    
    try:
        findings_summary = state.get("findings_summary")
        ti_summary = state.get("ti_summary")
        job_type = state.get("job_type")
        
        # For generic_rule job, create minimal findings from user_query
        if job_type == "generic_rule" and not findings_summary:
            logger.info("[genrule] Generic rule job - creating minimal findings from query")
            user_query = state.get("user_query", "")
            
            # Extract attack type from query - comprehensive mapping
            attack_type = "unknown"
            query_lower = user_query.lower()
            
            # SQL Injection
            if "sql" in query_lower or "sqli" in query_lower:
                attack_type = "sql_injection"
            # XSS
            elif "xss" in query_lower or "cross site scripting" in query_lower or "cross-site scripting" in query_lower:
                attack_type = "xss"
            # Path/Directory Traversal
            elif "path traversal" in query_lower or "directory traversal" in query_lower or "path-traversal" in query_lower:
                attack_type = "path_traversal"
            # LFI
            elif "lfi" in query_lower or "local file inclusion" in query_lower:
                attack_type = "lfi"
            # RFI
            elif "rfi" in query_lower or "remote file inclusion" in query_lower:
                attack_type = "rfi"
            # RCE
            elif "rce" in query_lower or "remote code execution" in query_lower:
                attack_type = "rce"
            # Command Injection
            elif "command injection" in query_lower or "cmd injection" in query_lower:
                attack_type = "command_injection"
            # XXE
            elif "xxe" in query_lower or "xml external entity" in query_lower:
                attack_type = "xxe"
            # SSTI
            elif "ssti" in query_lower or "server side template injection" in query_lower or "template injection" in query_lower:
                attack_type = "ssti"
            # CSRF
            elif "csrf" in query_lower or "cross site request forgery" in query_lower:
                attack_type = "csrf"
            # SSRF
            elif "ssrf" in query_lower or "server side request forgery" in query_lower:
                attack_type = "ssrf"
            # Webshell
            elif "webshell" in query_lower or "web shell" in query_lower:
                attack_type = "webshell"
            # Suspicious User-Agent
            elif "user agent" in query_lower or "user-agent" in query_lower or "suspicious agent" in query_lower:
                attack_type = "suspicious_useragent"
            # File Upload
            elif "file upload" in query_lower or "upload" in query_lower:
                attack_type = "file_upload"
            # Authentication Bypass
            elif "auth bypass" in query_lower or "authentication bypass" in query_lower:
                attack_type = "authentication_bypass"
            # IDOR
            elif "idor" in query_lower or "insecure direct object" in query_lower:
                attack_type = "idor"
            # Source Code Enumeration
            elif "source code" in query_lower or "code enumeration" in query_lower:
                attack_type = "source_code_enumeration"
            
            # Create minimal findings for rule generation
            findings_summary = {
                "has_attack": True,
                "total_events": 0,
                "total_attack_events": 0,
                "attack_breakdown": [{"attack_type": attack_type, "count": 1, "percentage": 100.0, "source_ips": []}],
                "mitre_techniques": [],
                "severity_level": "medium",
                "summary_text": f"Generic rule generation for {attack_type}",
                "sample_events": []
            }
        
        if not findings_summary:
            logger.warning("[genrule] No findings_summary for rule generation")
            state["genrule_summary"] = None
            state["genrule_done"] = True
            state["workflow_path"].append("genrule_skipped")
            return state
        
        # Get GenRule agent
        genrule_agent = get_genrule_agent()
        
        # Generate rules (returns tuple of summary and sources)
        genrule_summary, genrule_sources = await genrule_agent.generate_rules(findings_summary, ti_summary)
        state["genrule_summary"] = genrule_summary
        state["genrule_done"] = True
        
        # Merge genrule sources with existing rag_sources
        if genrule_sources:
            existing_sources = state.get("rag_sources") or []
            state["rag_sources"] = existing_sources + genrule_sources
            logger.info(f"[genrule] Added {len(genrule_sources)} RAG sources (total: {len(state['rag_sources'])})")
        
        state["workflow_path"].append("genrule")
        
        logger.info(f"[genrule] Rules generated for: {genrule_summary.get('main_attack_type')}")
        return state
    
    except Exception as e:
        logger.error(f"[genrule] Failed: {e}", exc_info=True)
        state["genrule_summary"] = None
        state["genrule_done"] = True
        state["workflow_path"].append("genrule_failed")
        return state  # Non-critical, continue


async def recommend_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Generate recommendations with RecommendAgent.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with recommend_summary
    """
    logger.info("[recommend] Generating recommendations...")
    
    try:
        findings_summary = state.get("findings_summary")
        ti_summary = state.get("ti_summary")
        
        if not findings_summary:
            logger.warning("[recommend] No findings_summary for recommendations")
            state["recommend_summary"] = None
            state["recommend_done"] = True
            state["workflow_path"].append("recommend_skipped")
            return state
        
        # Create Recommend agent
        recommend_llm = create_recommend_agent_llm()
        recommend_agent = RecommendAgent(recommend_llm)
        
        # Generate recommendations
        recommend_summary = await recommend_agent.generate(findings_summary, ti_summary)
        state["recommend_summary"] = recommend_summary
        state["recommend_done"] = True
        
        state["workflow_path"].append("recommend")
        
        logger.info(f"[recommend] Recommendations generated, severity: {recommend_summary.get('severity_overall')}")
        return state
    
    except Exception as e:
        logger.error(f"[recommend] Failed: {e}", exc_info=True)
        state["recommend_summary"] = None
        state["recommend_done"] = True
        state["workflow_path"].append("recommend_failed")
        return state  # Non-critical, continue


async def report_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Generate PDF report with ReportAgent.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with report_markdown and pdf_path
    """
    logger.info("[report] Generating PDF report...")
    
    try:
        findings_summary = state.get("findings_summary")
        ti_summary = state.get("ti_summary")
        recommend_summary = state.get("recommend_summary")
        attack_events_ref = state.get("attack_events_ref")
        
        if not findings_summary:
            logger.warning("[report] No findings_summary for report")
            state["report_markdown"] = None
            state["pdf_path"] = None
            state["report_done"] = True
            state["workflow_path"].append("report_skipped")
            return state
        
        # Create Report agent
        report_llm = create_report_agent_llm()
        report_agent = ReportAgent(report_llm, enable_pdf=True)
        
        # Generate report
        report_markdown, pdf_path = await report_agent.generate(
            findings_summary,
            ti_summary,
            recommend_summary,
            attack_events_ref,
            export_pdf=True,
            output_dir="./output"
        )
        
        state["report_markdown"] = report_markdown
        state["pdf_path"] = pdf_path
        state["report_done"] = True
        
        state["workflow_path"].append("report")
        
        logger.info(f"[report] Report generated: {pdf_path}")
        return state
    
    except Exception as e:
        logger.error(f"[report] Failed: {e}", exc_info=True)
        state["report_markdown"] = None
        state["pdf_path"] = None
        state["report_done"] = True
        state["workflow_path"].append("report_failed")
        return state  # Non-critical, continue


async def queryrag_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Query knowledge base with QueryRAGAgent.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with rag_answer
    """
    logger.info("[queryrag] Querying knowledge base...")
    
    try:
        user_query = state.get("user_query", "")
        job_type = state.get("job_type", "")
        
        if not user_query:
            logger.warning("[queryrag] No user_query for RAG")
            state["rag_answer"] = None
            state["workflow_path"].append("queryrag_skipped")
            return state
        
        # Map job_type to RAG category
        # Let QueryRAG agent auto-detect if no explicit job_type
        category = None
        
        if job_type == "asset_query":
            category = "asset"
            logger.info("  Category from job_type: asset")
        elif job_type == "sigma_query":
            category = "sigma"
            logger.info("  Category from job_type: sigma")
        else:
            # Let QueryRAG agent auto-detect category from query
            logger.info("  No explicit category, QueryRAG will auto-detect")
        
        # Get QueryRAG agent
        queryrag_agent = get_queryrag_agent()
        
        # Query knowledge base
        rag_result = await queryrag_agent.query_knowledge(
            user_query=user_query,
            category=category
        )
        
        # Handle both dict (with sources) and string (fallback) responses
        if isinstance(rag_result, dict):
            state["rag_answer"] = rag_result.get("answer", "")
            state["rag_sources"] = rag_result.get("sources", [])
            logger.info(f"[queryrag] RAG answer generated with {len(state['rag_sources'])} sources")
        else:
            # Fallback: old string format
            state["rag_answer"] = rag_result
            state["rag_sources"] = []
            logger.info(f"[queryrag] RAG answer generated (no sources)")
        
        state["workflow_path"].append("queryrag")
        
        logger.info(f"[queryrag] Answer length: {len(state['rag_answer'])} chars")
        return state
    
    except Exception as e:
        logger.error(f"[queryrag] Failed: {e}", exc_info=True)
        state["rag_answer"] = None
        state["workflow_path"].append("queryrag_failed")
        return state  # Non-critical, continue



async def summary_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Generate user-facing summary with SummaryAgent.
    
    Tổng hợp kết quả từ các agents và trả lời câu hỏi của user.
    
    Args:
        state: Current analysis state
        
    Returns:
        Updated state with user_summary
    """
    logger.info("[summary] Generating user-facing summary...")
    
    try:
        from backend.summary_agent import SummaryAgent
        from backend.utils.llm_factory import create_llm
        
        user_query = state.get("query", "")
        findings_summary = state.get("findings_summary")
        ti_summary = state.get("ti_summary")
        recommend_summary = state.get("recommend_summary")
        job_type = state.get("job_type", "unknown")
        
        # Create Summary agent
        summary_llm = create_llm(
            model=settings.RECOMMEND_AGENT_MODEL,
            temperature=0.3,
            provider=settings.RECOMMEND_AGENT_PROVIDER
        )
        summary_agent = SummaryAgent(summary_llm)
        
        # Generate summary
        user_summary = await summary_agent.summarize(
            user_query,
            findings_summary,
            ti_summary,
            recommend_summary,
            job_type
        )
        
        state["user_summary"] = user_summary
        state["workflow_path"].append("summary")
        
        logger.info("[summary] User summary generated successfully")
        return state
    
    except Exception as e:
        logger.error(f"[summary] Failed: {e}", exc_info=True)
        state["user_summary"] = None
        state["workflow_path"].append("summary_failed")
        return state  # Non-critical, continue
