"""
V3 GenRuleAgent: Generate detection rules (Sigma/SPL/AQL) for detected attacks.

This agent generates detection rules in multiple formats based on attack analysis.
"""

import json
import logging
from typing import Optional
from backend.models import FindingsSummary, TISummary, GenRuleSummary
from backend.utils.llm_factory import create_llm
from backend.config import settings

logger = logging.getLogger(__name__)


class GenRuleAgent:
    """
    Agent for generating detection rules from attack analysis.
    
    Generates rules in:
    - Sigma format (YAML) - Universal detection rule format
    - Splunk SPL - Splunk Search Processing Language
    """
    
    def __init__(self):
        # Get model and temperature from settings
        model = settings.genrule_agent_model or settings.llm_model
        temperature = settings.genrule_agent_temperature or 0.1
        provider = settings.llm_provider
        
        self.llm = create_llm(
            provider=provider,
            model=model,
            temperature=temperature
        )
    
    async def generate_rules(
        self,
        findings_summary: FindingsSummary,
        ti_summary: Optional[TISummary] = None
    ) -> tuple[GenRuleSummary, list]:
        """
        Generate detection rules based on attack analysis.
        
        Enhanced with RAG:
        - Query Sigma rules from knowledge base
        - Query OWASP best practices
        - Generate rules for ALL attack types
        
        Args:
            findings_summary: Attack analysis findings
            ti_summary: Optional threat intelligence data
            
        Returns:
            Tuple of (GenRuleSummary, rag_sources)
            - GenRuleSummary: Generated rules
            - rag_sources: List of RAG sources used for rule generation
        """
        try:
            logger.info("GenRuleAgent: Generating detection rules...")
            
            # Get all attack types
            attack_breakdown = findings_summary.get('attack_breakdown', [])
            if not attack_breakdown:
                logger.warning("No attacks found, using fallback")
                return self._get_fallback_rules(findings_summary), []
            
            # Query RAG for each attack type to get Sigma rules and OWASP guidance
            rag_context, rag_sources = await self._query_rag_for_attacks(attack_breakdown)
            
            # Build prompt with RAG context
            prompt = self._build_prompt_with_rag(findings_summary, ti_summary, rag_context)
            
            # Call LLM using LangChain interface
            from langchain_core.messages import SystemMessage, HumanMessage
            
            system_prompt = """You are a Security Detection Engineer. Generate ONLY detection rules in JSON format.

CRITICAL: Your response MUST be valid JSON with these exact fields:
{
  "main_attack_type": "attack_name",
  "sigma_rule": "complete YAML rule",
  "splunk_spl": "complete SPL query", 
  "notes": "deployment notes"
}

Rules must be:
- Production-ready (deployable immediately)
- Extract REAL patterns from provided log samples
- Include 5-10 detection patterns per attack type
- Complete with metadata, scoring, aggregation

DO NOT write explanations or markdown. ONLY output the JSON."""

            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=prompt)
            ]
            
            response = await self.llm.ainvoke(messages)
            
            # Parse response
            content = response.content
            genrule_summary = self._parse_response(content, findings_summary)
            
            logger.info(f"GenRuleAgent: Generated rules for {genrule_summary['main_attack_type']} with {len(rag_sources)} sources")
            return genrule_summary, rag_sources
            
        except Exception as e:
            logger.error(f"GenRuleAgent failed: {e}")
            return self._get_fallback_rules(findings_summary), []
    
    def _extract_best_sigma_rule(self, rag_context: str, attack_type: str, sources: list) -> str:
        """
        Extract the MOST RELEVANT Sigma rule from RAG context.
        
        RAG may return multiple Sigma rules. We need to:
        1. Split by rule boundaries (title: ...)
        2. Score each rule by relevance to attack_type
        3. Return the best matching rule
        
        Args:
            rag_context: Full RAG response (may contain multiple rules)
            attack_type: Target attack type (sqli, xss, etc.)
            sources: RAG sources for metadata
            
        Returns:
            Single best Sigma rule (YAML format)
        """
        import re
        
        # If context is short (< 500 chars), it's likely a single rule
        if len(rag_context) < 500:
            return rag_context
        
        # Split by Sigma rule boundaries
        # Sigma rules start with "title:" at the beginning of a line
        rule_pattern = r'(?:^|\n)title:\s*(.+?)(?=\ntitle:|\Z)'
        matches = list(re.finditer(rule_pattern, rag_context, re.MULTILINE | re.DOTALL))
        
        if not matches:
            # No clear rule boundaries, return first 2000 chars
            logger.warning(f"Could not split Sigma rules, returning first 2000 chars")
            return rag_context[:2000]
        
        logger.info(f"Found {len(matches)} Sigma rules in RAG context")
        
        # Score each rule by relevance
        best_rule = None
        best_score = 0
        
        # Attack type keywords for scoring
        attack_keywords = {
            'sqli': ['sql', 'injection', 'union', 'select', 'database'],
            'sql_injection': ['sql', 'injection', 'union', 'select', 'database'],
            'xss': ['xss', 'cross-site', 'script', 'javascript', 'html'],
            'lfi': ['lfi', 'local', 'file', 'inclusion', 'path', 'traversal'],
            'rfi': ['rfi', 'remote', 'file', 'inclusion', 'url'],
            'rce': ['rce', 'remote', 'code', 'execution', 'command', 'shell'],
            'command_injection': ['command', 'injection', 'shell', 'exec', 'system'],
            'xxe': ['xxe', 'xml', 'external', 'entity'],
            'path_traversal': ['path', 'traversal', 'directory', 'dot', 'slash']
        }
        
        keywords = attack_keywords.get(attack_type, [attack_type])
        
        for match in matches:
            rule_text = match.group(0)
            rule_title = match.group(1).lower()
            rule_lower = rule_text.lower()
            
            # Score by keyword matches in title and content
            score = 0
            
            # 1. Title match (very important)
            title_matches = 0
            for keyword in keywords:
                if keyword in rule_title:
                    score += 15  # Title match is VERY important
                    title_matches += 1
            
            # 2. Content match (less important)
            content_matches = 0
            for keyword in keywords:
                if keyword in rule_lower:
                    score += 1
                    content_matches += 1
            
            # 3. PENALTY for multi-attack rules (contains other attack types)
            # We want FOCUSED rules, not generic "catch-all" rules
            other_attack_indicators = [
                'ssti', 'webshell', 'source code', 'enumeration',
                'directory listing', 'file upload', 'csrf', 'ssrf',
                'xxe', 'xml', 'ldap', 'nosql'
            ]
            
            # Remove current attack type from penalty list
            penalty_keywords = [kw for kw in other_attack_indicators 
                              if kw not in keywords]
            
            multi_attack_penalty = 0
            for penalty_kw in penalty_keywords:
                if penalty_kw in rule_lower:
                    multi_attack_penalty += 5  # Heavy penalty for each extra attack type
            
            score -= multi_attack_penalty
            
            # 4. Prefer shorter rules (more focused)
            if len(rule_text) < 1000:
                score += 3
            elif len(rule_text) < 1500:
                score += 1
            
            # 5. Bonus for "pure" attack type (title contains ONLY target attack)
            if title_matches > 0 and multi_attack_penalty == 0:
                score += 10  # Big bonus for focused rules
            
            logger.info(f"  Rule '{match.group(1)[:60]}...' scored {score} (title:{title_matches}, content:{content_matches}, penalty:{multi_attack_penalty})")
            
            if score > best_score:
                best_score = score
                best_rule = rule_text
        
        if best_rule:
            logger.info(f"Selected best rule with score {best_score}")
            return best_rule.strip()
        else:
            # Fallback: return first rule
            logger.warning(f"No good match, returning first rule")
            return matches[0].group(0).strip()
    
    async def _query_rag_for_attacks(self, attack_breakdown: list) -> tuple[dict, list]:
        """
        Query RAG for Sigma rules and OWASP guidance for each attack type.
        
        Optimized queries:
        - Use category="sigma_rule" to filter Sigma rules
        - Use specific attack keywords for better matching
        
        Returns:
            Tuple of (rag_context dict, all_sources list)
            - rag_context: Dictionary with attack_type -> RAG context text
            - all_sources: List of all RAG sources for citation
        """
        rag_context = {}
        all_sources = []
        
        try:
            from backend.agents.queryrag_agent import get_queryrag_agent
            queryrag_agent = get_queryrag_agent()
            
            # Map attack types to English keywords for RAG query
            # RAG KB (Sigma, OWASP) is in English, so we need English keywords
            # This mapping handles both English and Vietnamese attack type names
            attack_keywords = {
                # SQL Injection variants
                'sql_injection': 'SQL injection SQLi database query UNION SELECT INSERT',
                'sqli': 'SQL injection SQLi database query UNION SELECT INSERT',
                'sql': 'SQL injection SQLi database query',
                
                # XSS variants
                'xss': 'cross-site scripting XSS script injection javascript',
                'cross_site_scripting': 'cross-site scripting XSS script injection',
                
                # File Inclusion
                'lfi': 'local file inclusion LFI path traversal file read',
                'local_file_inclusion': 'local file inclusion LFI path traversal',
                'rfi': 'remote file inclusion RFI remote file',
                'remote_file_inclusion': 'remote file inclusion RFI',
                
                # Code Execution
                'rce': 'remote code execution RCE command injection shell',
                'remote_code_execution': 'remote code execution RCE command',
                'command_injection': 'command injection OS command execution shell',
                
                # XML attacks
                'xxe': 'XML external entity XXE XML injection',
                
                # Path/Directory
                'path_traversal': 'path traversal directory traversal dot dot slash',
                'directory_traversal': 'directory traversal path traversal',
                
                # File Upload
                'file_upload': 'malicious file upload unrestricted file upload',
                
                # Other common attacks
                'csrf': 'cross-site request forgery CSRF',
                'ssrf': 'server-side request forgery SSRF',
                'idor': 'insecure direct object reference IDOR',
                'authentication_bypass': 'authentication bypass auth bypass'
            }
            
            # Query ONLY for the MAIN attack type (top 1)
            if attack_breakdown:
                main_attack = attack_breakdown[0]
                attack_type = main_attack['attack_type']
                
                # Get optimized English keywords for RAG query
                keywords = attack_keywords.get(attack_type, attack_type)
                
                # Query Sigma rules with FOCUSED query (avoid multi-attack rules)
                # Add "ONLY" to emphasize we want focused rules
                query_sigma = f"{keywords} detection ONLY (not combined with other attacks)"
                logger.info(f"Querying Sigma rule for: {attack_type} (focused query)")
                
                sigma_result = await queryrag_agent.query_knowledge(
                    user_query=query_sigma,
                    category="sigma_rule"
                )
                
                # Extract FULL Sigma rule content
                if isinstance(sigma_result, dict):
                    sigma_context = sigma_result.get('answer', '')
                    sigma_sources = sigma_result.get('sources', [])
                    all_sources.extend(sigma_sources)
                else:
                    sigma_context = sigma_result
                    sigma_sources = []
                
                # Extract ONLY the MOST RELEVANT Sigma rule (not all rules)
                # RAG may return multiple rules, we need to pick the best one
                best_rule = self._extract_best_sigma_rule(sigma_context, attack_type, sigma_sources)
                
                rag_context[attack_type] = best_rule
                
                logger.info(f"Retrieved Sigma rule for {attack_type}: {len(best_rule)} chars, {len(sigma_sources)} sources")
        
        except Exception as e:
            logger.warning(f"Failed to query RAG: {e}")
            # Continue without RAG context
        
        return rag_context, all_sources
    
    def _build_prompt_with_rag(
        self,
        findings_summary: FindingsSummary,
        ti_summary: Optional[TISummary],
        rag_context: dict
    ) -> str:
        """Build detailed but focused prompt with RAG context."""
        # Get all attack types
        attack_breakdown = findings_summary.get("attack_breakdown", [])
        
        # Build attack summary
        attack_summary = []
        for attack in attack_breakdown[:3]:  # Top 3
            attack_summary.append(
                f"- {attack['attack_type']}: {attack['count']} events ({attack['percentage']:.1f}%)"
            )
        
        # Get sample events
        sample_events = findings_summary.get("sample_events", [])[:3]
        
        # Get IOCs
        iocs = []
        if ti_summary:
            iocs = [ioc["ip"] for ioc in ti_summary.get("iocs", [])[:5] if ioc.get("risk") in ["high", "critical"]]
        
        # Build RAG context section - Keep FULL Sigma rule
        rag_section = ""
        if rag_context:
            rag_section = "\n📚 REFERENCE SIGMA RULE (copy ALL detection patterns from this):\n"
            for attack_type, context in rag_context.items():
                rag_section += f"\n{attack_type.upper()} SIGMA RULE:\n{context}\n"  # Full rule, no truncation
        
        prompt = f"""Create production-ready detection rules for web application attacks.

📊 ATTACK DATA:
Total: {findings_summary["total_attack_events"]} | Severity: {findings_summary["severity_level"].upper()} | MITRE: {", ".join(findings_summary.get("mitre_techniques", [])) or "T1190"}

Attack Types:
{chr(10).join(attack_summary)}

Real Log Samples:
```json
{json.dumps(sample_events, indent=2, ensure_ascii=False)}
```

Malicious IPs: {", ".join(iocs[:5]) if iocs else "None"}

{rag_section}

═══════════════════════════════════════════════════════════════
TASK: CREATE PRODUCTION-READY DETECTION RULES

CRITICAL REQUIREMENTS:
✓ Rules must be FOCUSED on the main attack type ONLY
✓ Extract REAL patterns from log samples (not generic)
✓ Include 5-10 specific detection patterns
✓ Add proper filters to reduce false positives
✓ Use correct field names from log samples

═══════════════════════════════════════════════════════════════

1. SIGMA RULE (Complete YAML):

   STRUCTURE (follow this EXACTLY):
   ```yaml
   title: [Attack Type] Detection - [Specific Variant]
   id: [UUID v4]
   status: stable|experimental
   description: |
     Detects [attack type] attacks via [method].
     Patterns include: [list 3-5 key patterns]
   references:
     - https://attack.mitre.org/techniques/[MITRE ID]/
     - https://owasp.org/www-community/attacks/[Attack]
   author: Security Detection System
   date: 2025/11/27
   tags:
     - attack.initial_access
     - attack.t1190
     - web.[attack_type]
   logsource:
     category: webserver
     product: apache|nginx|iis
   detection:
     selection_[variant1]:
       cs-uri-query|contains:
         - 'pattern1'
         - 'pattern2'
         - 'pattern3'
     selection_[variant2]:
       cs-uri-query|contains:
         - 'pattern4'
         - 'pattern5'
     filter_legitimate:
       sc-status: 404|403
     filter_scanner:
       cs-useragent|contains:
         - 'Mozilla/'
         - 'Chrome/'
     condition: (selection_variant1 or selection_variant2) and not (filter_legitimate or filter_scanner)
   falsepositives:
     - Security scanners
     - Penetration testing
     - Development environments
   level: high|critical
   ```

   INSTRUCTIONS:
   - Use REAL patterns from log samples (cs-uri-query, cs-method, etc.)
   - Create 2-3 selection blocks for different attack variants
   - Add filters to exclude legitimate traffic
   - Condition: (selection1 OR selection2) AND NOT (filter1 OR filter2)
   - Level: critical (if successful), high (if attempted)

2. SPLUNK SPL (Complete Query):

   STRUCTURE (follow this EXACTLY):
   ```spl
   index=web sourcetype=* earliest=-1h
   
   | eval attack_indicators=0
   
   | eval attack_indicators=attack_indicators + 
       if(like(lower(cs_uri_query), "%pattern1%") OR 
          like(lower(cs_uri_query), "%pattern2%"), 1, 0)
   
   | eval attack_indicators=attack_indicators + 
       if(like(lower(cs_uri_query), "%pattern3%") OR 
          like(lower(cs_uri_query), "%pattern4%"), 1, 0)
   
   | eval attack_indicators=attack_indicators + 
       if(sc_status>=200 AND sc_status<300, 1, 0)
   
   | eval risk_score=attack_indicators*20
   
   | eval severity=case(
       risk_score>=80, "CRITICAL",
       risk_score>=60, "HIGH",
       risk_score>=40, "MEDIUM",
       1=1, "LOW"
   )
   
   | where attack_indicators>=2
   
   | stats 
       count as total_attempts,
       dc(c_ip) as unique_ips,
       values(cs_uri_query) as attack_payloads,
       values(sc_status) as response_codes,
       earliest(_time) as first_seen,
       latest(_time) as last_seen,
       max(risk_score) as max_risk
       by c_ip, severity
   
   | eval duration=tostring(last_seen-first_seen, "duration")
   
   | where total_attempts>=3 OR max_risk>=70
   
   | sort - max_risk, - total_attempts
   
   | table _time, c_ip, severity, max_risk, total_attempts, unique_ips, attack_payloads, duration
   
   | head 100
   ```

   INSTRUCTIONS:
   - Extract patterns from log samples (use REAL field names)
   - Create 3-5 indicator checks (each adds to attack_indicators)
   - Risk score = indicators * 20 (max 100)
   - Threshold: >=2 indicators OR risk>=70
   - Stats by c_ip and severity
   - Sort by risk_score DESC

3. DEPLOYMENT NOTES (TIẾNG VIỆT):

   STRUCTURE:
   ```
   **False Positives:**
   1. [Tình huống 1]: [Cách khắc phục]
   2. [Tình huống 2]: [Cách khắc phục]
   3. [Tình huống 3]: [Cách khắc phục]

   **Tuning:**
   - Threshold hiện tại: [giá trị]
   - Điều chỉnh: [hướng dẫn cụ thể]
   - Field names: [danh sách fields cần verify]

   **Testing:**
   1. [Bước 1]
   2. [Bước 2]
   3. [Bước 3]
   4. [Bước 4]

   **Maintenance:**
   - Review: [tần suất]
   - Update: [khi nào]
   - Archive: [điều kiện]
   ```

EXAMPLE OUTPUT (follow this format EXACTLY):
{{
  "main_attack_type": "sql_injection",
  "sigma_rule": "title: SQL Injection Detection\\nid: 12345678-1234-4abc-8def-123456789abc\\nstatus: experimental\\ndescription: Detects SQL injection attacks\\nlogsource:\\n  category: webserver\\ndetection:\\n  selection:\\n    cs-uri-query|contains:\\n      - 'union select'\\n      - \\\"' or '1'='1\\\"\\n  condition: selection\\nlevel: high",
  "splunk_spl": "index=web earliest=-1h | eval is_sqli=if(like(lower(cs_uri_query), \\\"%union%select%\\\") OR like(lower(cs_uri_query), \\\"%' or '1'='1%\\\"), 1, 0) | where is_sqli=1 | stats count by c_ip | where count>=3",
  "notes": "**False Positives:**\\n- Security scanners (Nessus, Qualys): Thêm whitelist IP\\n- Penetration testing: Loại trừ IP tester\\n- Môi trường dev/staging: Exclude staging servers\\n\\n**Tuning:**\\n- Threshold hiện tại: >= 3 attempts\\n- Điều chỉnh: >= 2 (nhạy hơn) hoặc >= 5 (ít noise hơn)\\n\\n**Testing:**\\n1. Chạy query với dữ liệu 7 ngày gần nhất\\n2. Review kết quả, xác định false positives\\n3. Điều chỉnh threshold và filters\\n4. Deploy vào production\\n\\n**Maintenance:**\\n- Review hàng tuần trong tháng đầu\\n- Sau đó review hàng tháng\\n- Update khi có attack pattern mới"
}}

OUTPUT ONLY VALID JSON. NO explanations, NO markdown, NO extra text."""
        
        return prompt
    
    def _build_prompt(
        self,
        findings_summary: FindingsSummary,
        ti_summary: Optional[TISummary]
    ) -> str:
        """Build LLM prompt for rule generation."""
        # Get main attack type
        main_attack = findings_summary["attack_breakdown"][0]["attack_type"] if findings_summary["attack_breakdown"] else "unknown"
        
        # Get sample events
        sample_events = findings_summary.get("sample_events", [])[:3]
        
        # Get MITRE techniques
        mitre_techniques = findings_summary.get("mitre_techniques", [])
        
        # Get IOCs if available
        iocs = []
        if ti_summary:
            iocs = [ioc["ip"] for ioc in ti_summary.get("iocs", []) if ioc.get("risk") in ["high", "critical"]]
        
        prompt = f"""Based on the following security incident analysis, generate detection rules in three formats:

**Incident Summary:**
- Main Attack Type: {main_attack}
- Severity: {findings_summary["severity_level"]}
- Total Attack Events: {findings_summary["total_attack_events"]}
- MITRE ATT&CK Techniques: {", ".join(mitre_techniques) if mitre_techniques else "None"}

**Sample Attack Events:**
```json
{json.dumps(sample_events, indent=2, ensure_ascii=False)}
```

**High-Risk IOCs:**
{", ".join(iocs) if iocs else "None detected"}

**Task:**
Generate detection rules in the following formats:

1. **Sigma Rule** (YAML format):
   - Include title, description, logsource, detection logic
   - Use appropriate field names (uri, status, method, src_ip, etc.)
   - Add condition logic for detection
   - Follow Sigma rule specification
   - Include level (low/medium/high/critical)

2. **Splunk SPL Query**:
   - Assume index=web for web logs
   - Use appropriate search operators
   - Include time range considerations
   - Add stats/table for better visualization
   - Include threshold logic if applicable

3. **Notes**:
   - Mention potential false positives
   - Suggest tuning parameters
   - Recommend testing approach
   - Deployment considerations

**Output Format (JSON):**
```json
{{
  "main_attack_type": "{main_attack}",
  "sigma_rule": "title: ...",
  "splunk_spl": "index=web ...",
  "notes": "..."
}}
```

**QUAN TRỌNG: Viết TẤT CẢ nội dung trong trường "notes" bằng TIẾNG VIỆT.**
- Hướng dẫn triển khai: Tiếng Việt
- False Positives: Tiếng Việt  
- Tuning Recommendations: Tiếng Việt
- Testing Procedure: Tiếng Việt
- Deployment Checklist: Tiếng Việt
- Next Steps: Tiếng Việt

Generate the rules now (notes in Vietnamese):"""
        
        return prompt
    
    def _parse_response(self, content: str, findings_summary: FindingsSummary) -> GenRuleSummary:
        """Parse LLM response into GenRuleSummary."""
        try:
            # Try to extract JSON from response
            if "```json" in content:
                json_start = content.find("```json") + 7
                json_end = content.find("```", json_start)
                json_str = content[json_start:json_end].strip()
            elif "```" in content:
                json_start = content.find("```") + 3
                json_end = content.find("```", json_start)
                json_str = content[json_start:json_end].strip()
            else:
                json_str = content.strip()
            
            # Clean control characters and fix escape sequences
            import re
            # Remove control characters except newline, tab, carriage return
            json_str = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]', '', json_str)
            
            # Try to parse JSON with strict=False to be more lenient
            try:
                data = json.loads(json_str, strict=False)
            except json.JSONDecodeError as e:
                logger.warning(f"JSON parse error: {e}, trying to fix...")
                # If still fails, try to extract fields manually
                # This is a fallback for malformed JSON
                import ast
                # Try to find the fields in the text
                main_attack = findings_summary["attack_breakdown"][0]["attack_type"] if findings_summary["attack_breakdown"] else "unknown"
                
                # Extract sigma_rule (between quotes after "sigma_rule":)
                sigma_match = re.search(r'"sigma_rule"\s*:\s*"((?:[^"\\]|\\.)*)"', json_str, re.DOTALL)
                sigma_rule = sigma_match.group(1) if sigma_match else ""
                
                # Extract splunk_spl
                spl_match = re.search(r'"splunk_spl"\s*:\s*"((?:[^"\\]|\\.)*)"', json_str, re.DOTALL)
                splunk_spl = spl_match.group(1) if spl_match else ""
                
                # Extract notes
                notes_match = re.search(r'"notes"\s*:\s*"((?:[^"\\]|\\.)*)"', json_str, re.DOTALL)
                notes = notes_match.group(1) if notes_match else ""
                
                # Unescape strings
                if sigma_rule:
                    sigma_rule = sigma_rule.encode().decode('unicode_escape')
                if splunk_spl:
                    splunk_spl = splunk_spl.encode().decode('unicode_escape')
                if notes:
                    notes = notes.encode().decode('unicode_escape')
                
                data = {
                    "main_attack_type": main_attack,
                    "sigma_rule": sigma_rule,
                    "splunk_spl": splunk_spl,
                    "notes": notes
                }
            
            return GenRuleSummary(
                main_attack_type=data.get("main_attack_type", "unknown"),
                sigma_rule=data.get("sigma_rule", ""),
                splunk_spl=data.get("splunk_spl", ""),
                qradar_aql="",  # Not generated anymore
                notes=data.get("notes", "")
            )
        except Exception as e:
            logger.warning(f"Failed to parse GenRule response: {e}")
            return self._get_fallback_rules(findings_summary)
    
    def _get_fallback_rules(self, findings_summary: FindingsSummary) -> GenRuleSummary:
        """Return comprehensive fallback rules if LLM fails."""
        main_attack = findings_summary["attack_breakdown"][0]["attack_type"] if findings_summary["attack_breakdown"] else "unknown"
        total_attacks = findings_summary.get("total_attack_events", 0)
        severity = findings_summary.get("severity_level", "medium")
        
        # Get attack patterns from breakdown
        attack_types = [a["attack_type"] for a in findings_summary.get("attack_breakdown", [])]
        
        sigma_rule = f"""title: Web Application Attack Detection - {main_attack.upper()}
id: auto-generated-{main_attack}
status: experimental
description: |
  Detects potential {main_attack} attacks against web applications.
  This rule was auto-generated based on {total_attacks} detected attack events.
  
  Attack types covered: {", ".join(attack_types)}
  
  IMPORTANT: This is a fallback rule. Please review and customize based on your environment.
references:
  - https://owasp.org/www-community/attacks/
  - https://attack.mitre.org/
author: Auto-Generated Detection System
date: 2025/11/21
tags:
  - attack.initial_access
  - attack.t1190
logsource:
  category: webserver
  product: apache
detection:
  selection:
    cs-uri-query|contains:
      - '../'
      - '..%2f'
      - 'union select'
      - '<script'
      - 'eval('
      - 'exec('
      - '/etc/passwd'
      - 'cmd.exe'
  filter:
    sc-status: 404
  condition: selection and not filter
falsepositives:
  - Legitimate application functionality
  - Security scanners
  - Penetration testing
level: {severity}
"""
        
        splunk_spl = f"""index=web sourcetype=* 
    [Search for {main_attack} attacks]

| eval attack_indicators=0

| eval attack_indicators=attack_indicators + 
    if(like(cs_uri_query, "%../%") OR like(cs_uri_query, "%..%2f%"), 1, 0)
    
| eval attack_indicators=attack_indicators + 
    if(like(cs_uri_query, "%union%select%") OR like(cs_uri_query, "%'%or%'1'='1%"), 1, 0)
    
| eval attack_indicators=attack_indicators + 
    if(like(cs_uri_query, "%<script%") OR like(cs_uri_query, "%javascript:%"), 1, 0)
    
| eval attack_indicators=attack_indicators + 
    if(like(cs_uri_query, "%eval(%") OR like(cs_uri_query, "%exec(%"), 1, 0)

| where attack_indicators > 0

| eval severity=case(
    attack_indicators >= 3, "CRITICAL",
    attack_indicators >= 2, "HIGH",
    attack_indicators >= 1, "MEDIUM",
    1=1, "LOW"
)

| stats 
    count as total_attempts,
    dc(c_ip) as unique_ips,
    values(cs_uri_query) as payloads,
    earliest(_time) as first_seen,
    latest(_time) as last_seen
    by c_ip, cs_method, severity

| eval duration=tostring(last_seen-first_seen, "duration")

| where total_attempts > 3

| sort - total_attempts

| table _time, c_ip, severity, total_attempts, unique_ips, payloads, duration

| head 50"""
        
        notes = f"""⚠️ FALLBACK RULE NOTICE ⚠️
This rule was auto-generated because the AI detection engine encountered an error.

**Detected Attack Summary:**
- Main Attack Type: {main_attack}
- Total Attack Events: {total_attacks}
- Severity Level: {severity.upper()}
- Attack Types: {", ".join(attack_types)}

**False Positives:**
- Security scanning tools (Nessus, Qualys, Burp Suite)
- Legitimate penetration testing activities
- Web application firewalls testing
- Development/staging environments

**Tuning Recommendations:**
1. Adjust threshold in SPL query (currently > 3 attempts)
2. Add whitelist for known scanner IPs
3. Customize field names to match your log source
4. Add time-based correlation (e.g., 10 attempts in 5 minutes)

**Testing Procedure:**
1. Run SPL query in Splunk with last 24 hours
2. Review results for false positives
3. Adjust thresholds and filters
4. Test Sigma rule in your SIEM
5. Validate against known attack samples

**Deployment Checklist:**
- [ ] Verify field names (cs-uri-query, c-ip, sc-status, etc.)
- [ ] Test in non-production environment
- [ ] Add environment-specific whitelists
- [ ] Configure alert routing
- [ ] Document exceptions
- [ ] Schedule weekly review

**Next Steps:**
1. Review sample attack events in findings
2. Customize detection patterns based on actual payloads
3. Add specific IOCs if available
4. Map to MITRE ATT&CK techniques
5. Integrate with threat intelligence feeds

**Performance Notes:**
- Expected load: Low to Medium
- Recommended search window: 1-24 hours
- Index impact: Minimal
- Query execution: < 30 seconds for 1M events

**Maintenance:**
- Review weekly for first month
- Adjust to monthly after stabilization
- Update patterns when new attack variants detected
- Archive rule if no longer relevant

For better detection rules, ensure the AI engine has:
- Valid API credentials
- Sufficient context about attack patterns
- Access to threat intelligence feeds
- Updated knowledge base"""
        
        return GenRuleSummary(
            main_attack_type=main_attack,
            sigma_rule=sigma_rule,
            splunk_spl=splunk_spl,
            qradar_aql="",  # Not generated
            notes=notes
        )


# Singleton instance
_genrule_agent = None


def get_genrule_agent() -> GenRuleAgent:
    """Get or create GenRuleAgent singleton."""
    global _genrule_agent
    if _genrule_agent is None:
        _genrule_agent = GenRuleAgent()
    return _genrule_agent
