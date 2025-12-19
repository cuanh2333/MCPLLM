"""
V3 QueryRAGAgent: Answer security knowledge queries using RAG.

This agent queries OWASP/MITRE/Sigma knowledge base via unified MCP server.
"""

import json
import logging
from typing import Optional
from backend.utils.llm_factory import create_llm
from backend.config import settings
from backend.services.unified_mcp_client import get_unified_client

logger = logging.getLogger(__name__)


class QueryRAGAgent:
    """
    Agent for answering security knowledge queries using RAG.
    
    Integrates with rag_server.py via MCP to query ChromaDB knowledge base.
    """
    
    def __init__(self):
        # Get model and temperature from settings
        model = settings.queryrag_agent_model or settings.llm_model
        temperature = settings.queryrag_agent_temperature or 0.3
        provider = settings.llm_provider
        
        self.llm = create_llm(
            provider=provider,
            model=model,
            temperature=temperature
        )
        self.mcp_client = get_unified_client()
    
    async def query_knowledge(
        self,
        user_query: str,
        category: Optional[str] = None
    ) -> str:
        """
        Answer knowledge query using RAG.
        
        Handles multilingual queries:
        - Detects Vietnamese queries
        - Extracts English keywords for RAG search
        - Returns answer in user's language
        
        Args:
            user_query: User's question (Vietnamese or English)
            category: Filter by category (optional)
                - "asset": Search only in Asset.md
                - "sigma": Search only in Sigma rules
                - None: Full hybrid search
            
        Returns:
            Markdown formatted answer
        """
        try:
            import time
            start_time = time.time()
            
            logger.info(f"QueryRAGAgent: Answering query: {user_query}")
            
            # Auto-detect category if not provided
            if category is None:
                detected_category = self._detect_query_category(user_query)
                if detected_category:
                    category = detected_category
                    logger.info(f"  Auto-detected category: {category}")
            
            if category:
                logger.info(f"  Category filter: {category}")
            
            # Enhance query with English keywords if needed
            t1 = time.time()
            enhanced_query = await self._enhance_query_with_keywords(user_query)
            logger.info(f"  Enhanced query: {enhanced_query} (took {time.time()-t1:.2f}s)")
            
            # Call MCP query_rag tool to get KB snippets
            t2 = time.time()
            rag_results = await self._call_mcp_query_rag(enhanced_query, category)
            logger.info(f"  MCP query_rag took {time.time()-t2:.2f}s")
            
            if not rag_results:
                logger.warning("No RAG results found")
            
            # SPECIAL CASE: For sigma_rule category, return RAW content without LLM synthesis
            # GenRuleAgent needs the actual YAML rules, not a summarized answer
            if category == "sigma_rule":
                logger.info("  Sigma rule query → returning RAW content (no LLM synthesis)")
                
                # Concatenate all RAG snippets (they contain actual Sigma YAML)
                # Try to get full content first, fallback to snippet
                raw_content = ""
                for i, result in enumerate(rag_results, 1):
                    # Try full content first (if available)
                    content = result.get('content', result.get('content_snippet', ''))
                    
                    if content:
                        # Add separator between rules
                        if i > 1:
                            raw_content += "\n" + "="*80 + "\n\n"
                        raw_content += content
                        logger.info(f"    Rule {i}: {len(content)} chars")
                
                total_time = time.time() - start_time
                logger.info(f"QueryRAGAgent: Returned {len(raw_content)} chars of RAW Sigma rules from {len(rag_results)} sources (total: {total_time:.2f}s)")
                
                return {
                    'answer': raw_content.strip(),
                    'sources': rag_results
                }
            
            # For other categories, use LLM to synthesize answer
            # Build prompt with RAG context
            prompt = self._build_prompt(user_query, rag_results, category)
            
            # Call LLM to synthesize answer (LangChain style)
            from langchain_core.messages import SystemMessage, HumanMessage
            
            messages = [
                SystemMessage(content="You are a cybersecurity expert. Answer questions clearly and comprehensively based on provided knowledge base references."),
                HumanMessage(content=prompt)
            ]
            
            t3 = time.time()
            response = await self.llm.ainvoke(messages)
            logger.info(f"  LLM synthesis took {time.time()-t3:.2f}s")
            
            # Get answer (LangChain response format)
            answer = response.content
            
            total_time = time.time() - start_time
            logger.info(f"QueryRAGAgent: Answer generated successfully (total: {total_time:.2f}s)")
            
            # Return both answer and sources
            return {
                'answer': answer,
                'sources': rag_results  # Include RAG sources for citation
            }
            
        except Exception as e:
            logger.error(f"QueryRAGAgent failed: {e}")
            return self._get_fallback_answer(user_query)
    
    def _detect_query_category(self, user_query: str) -> Optional[str]:
        """
        Detect if query is about assets or sigma rules.
        
        Returns:
            "asset" - Query about system assets (IPs, servers)
            "sigma" - Query about detection rules
            None - General query
        """
        import re
        query_lower = user_query.lower()
        
        # Check if query contains IP address pattern (highest priority)
        # Matches: 192.168.1.1, 10.0.0.1, etc.
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        if re.search(ip_pattern, user_query):
            logger.info(f"  Detected IP address in query → category: asset")
            return "asset"
        
        # Asset-related keywords
        asset_keywords = [
            'ip nghiệp vụ', 'ip business', 'business ip',
            'server', 'máy chủ', 'hệ thống',
            'tài sản', 'asset',
            'infrastructure', 'cơ sở hạ tầng',
            'production server', 'staging server',
            'database server', 'web server',
            'internal ip', 'ip nội bộ',
            'hostname', 'domain'
        ]
        
        # Sigma/Detection rule keywords
        sigma_keywords = [
            'sigma rule', 'detection rule',
            'phát hiện', 'detection',
            'rule', 'quy tắc',
            'tạo rule', 'create rule', 'generate rule',
            'viết rule', 'write rule',
            'siem', 'splunk', 'qradar'
        ]
        
        # Check asset keywords
        if any(keyword in query_lower for keyword in asset_keywords):
            return "asset"
        
        # Check sigma keywords
        if any(keyword in query_lower for keyword in sigma_keywords):
            return "sigma_rule"  # Match with actual category in database
        
        return None
    
    async def _enhance_query_with_keywords(self, user_query: str) -> str:
        """
        Enhance query with English keywords for better RAG matching.
        
        RAG KB is in English, so we extract/translate key terms.
        
        Examples:
        - "SQL injection là gì?" → "SQL injection SQLi what is definition"
        - "Làm thế nào để phòng chống XSS" → "XSS cross-site scripting prevention mitigation defense how to prevent"
        - "IP nghiệp vụ là gì?" → "business IP asset infrastructure"
        """
        query_lower = user_query.lower()
        
        # Vietnamese to English keyword mapping
        vn_to_en = {
            'là gì': 'what is definition',
            'cách phòng chống': 'prevention mitigation defense how to prevent',
            'làm thế nào để phòng chống': 'prevention mitigation defense how to prevent secure',
            'làm sao để phòng chống': 'prevention mitigation defense how to prevent',
            'phòng thủ': 'defense mitigation protection',
            'tấn công': 'attack exploitation',
            'lỗ hổng': 'vulnerability weakness',
            'bảo mật': 'security secure',
            'phát hiện': 'detection identify',
            'giải thích': 'explain description',
            'ví dụ': 'example sample',
            # Asset-related
            'ip nghiệp vụ': 'business IP asset',
            'máy chủ': 'server',
            'hệ thống': 'system infrastructure',
            'tài sản': 'asset',
            'cơ sở hạ tầng': 'infrastructure',
        }
        
        # Attack type keywords with expanded terms (NO prevention by default)
        attack_keywords = {
            'sql injection': 'SQL injection SQLi database attack',
            'xss': 'XSS cross-site scripting',
            'lfi': 'LFI local file inclusion',
            'rfi': 'RFI remote file inclusion',
            'rce': 'RCE remote code execution',
            'command injection': 'command injection OS command',
            'xxe': 'XXE XML external entity',
        }
        
        # Start with original query
        enhanced_parts = [user_query]
        
        # Add English translations for Vietnamese phrases
        for vn, en in vn_to_en.items():
            if vn in query_lower:
                enhanced_parts.append(en)
        
        # Add attack-specific keywords
        for attack, keywords in attack_keywords.items():
            if attack in query_lower:
                enhanced_parts.append(keywords)
                break
        
        # Join all parts
        enhanced = ' '.join(enhanced_parts)
        
        return enhanced
    
    async def _call_mcp_query_rag(
        self,
        question: str,
        category: Optional[str] = None
    ) -> list[dict]:
        """
        Call RAG server via HTTP to retrieve KB snippets.
        
        Args:
            question: User's question
            category: Filter by category (asset/sigma/None)
            
        Returns:
            List of dicts with metadata, content_snippet, hybrid_score
        """
        try:
            import httpx
            
            logger.info(f"Calling RAG server HTTP: question='{question}', category={category}")
            
            # Build request payload
            payload = {
                "query": question,
                "top_k": 5
            }
            if category:
                payload["category"] = category
            
            # Call HTTP endpoint
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    "http://127.0.0.1:8001/query_rag",
                    json=payload
                )
                
                if response.status_code == 200:
                    data = response.json()
                    results = data.get("results", [])
                    logger.info(f"Retrieved {len(results)} results from RAG")
                    return results
                else:
                    logger.error(f"RAG server returned {response.status_code}: {response.text}")
                    return []
        
        except Exception as e:
            logger.error(f"Failed to call RAG server: {e}")
            return []
    
    def _analyze_query_intent(self, user_query: str, category: Optional[str] = None) -> dict:
        """
        Phân tích ý định của câu hỏi để trả lời đúng trọng tâm.
        
        Args:
            user_query: User's question
            category: Query category (asset/sigma/None)
        
        Returns:
            {
                "intent_type": "definition" | "prevention" | "detection" | "example" | "comparison" | "general",
                "focus_areas": ["prevention", "mitigation", ...],
                "answer_structure": "Cấu trúc câu trả lời phù hợp"
            }
        """
        query_lower = user_query.lower()
        
        # Phát hiện intent
        intent_type = "general"
        focus_areas = []
        
        # Prevention/Mitigation intent
        prevention_keywords = [
            "phòng chống", "phòng thủ", "giảm thiểu", "bảo vệ",
            "làm thế nào để", "làm sao để", "cách nào để",
            "prevent", "mitigate", "defend", "protect", "secure",
            "how to", "how can", "ways to"
        ]
        
        # Definition intent
        definition_keywords = [
            "là gì", "định nghĩa", "giải thích", "thông tin",
            "what is", "define", "explain", "meaning", "information about"
        ]
        
        # Detection intent
        detection_keywords = [
            "phát hiện", "nhận biết", "xác định", "dấu hiệu",
            "detect", "identify", "recognize", "signs", "indicators"
        ]
        
        # Example intent
        example_keywords = [
            "ví dụ", "mẫu", "case study",
            "example", "sample", "demonstration"
        ]
        
        # Comparison intent
        comparison_keywords = [
            "khác nhau", "so sánh", "phân biệt",
            "difference", "compare", "versus", "vs"
        ]
        
        # Determine primary intent
        if any(kw in query_lower for kw in prevention_keywords):
            intent_type = "prevention"
            focus_areas = ["prevention", "mitigation", "best_practices", "implementation"]
        elif any(kw in query_lower for kw in detection_keywords):
            intent_type = "detection"
            focus_areas = ["detection", "indicators", "monitoring", "tools"]
        elif any(kw in query_lower for kw in definition_keywords):
            intent_type = "definition"
            # For asset queries, focus ONLY on asset information
            if category == "asset":
                focus_areas = ["asset_info", "description", "purpose", "details"]
            else:
                focus_areas = ["definition", "mechanism", "impact"]
        elif any(kw in query_lower for kw in example_keywords):
            intent_type = "example"
            focus_areas = ["examples", "case_studies", "demonstrations"]
        elif any(kw in query_lower for kw in comparison_keywords):
            intent_type = "comparison"
            focus_areas = ["comparison", "differences", "similarities"]
        
        # Determine answer structure based on category
        if category == "asset":
            structure_map = {
                "prevention": "Focus on asset protection and security measures",
                "detection": "Focus on asset monitoring and detection methods",
                "definition": "Focus 100% on asset information: IP, hostname, purpose, owner, criticality. DO NOT mention prevention or security unless explicitly asked.",
                "example": "Focus on concrete asset examples",
                "comparison": "Focus on comparing assets",
                "general": "Provide asset information: IP, hostname, purpose, owner, criticality"
            }
        else:
            structure_map = {
                "prevention": "Focus 80% on prevention/mitigation techniques, 20% on brief definition",
                "detection": "Focus 80% on detection methods and indicators, 20% on brief definition",
                "definition": "Focus 60% on definition and mechanism, 40% on prevention overview",
                "example": "Focus 80% on concrete examples and case studies",
                "comparison": "Focus on comparing and contrasting the concepts",
                "general": "Balanced coverage: definition, mechanism, prevention, examples"
            }
        
        return {
            "intent_type": intent_type,
            "focus_areas": focus_areas,
            "answer_structure": structure_map.get(intent_type, structure_map["general"])
        }
    
    def _build_prompt(
        self,
        user_query: str,
        rag_results: list[dict],
        category: Optional[str] = None
    ) -> str:
        """
        Build LLM prompt with RAG context.
        
        Args:
            user_query: User's question
            rag_results: Results from query_rag tool
                [{"metadata": {...}, "content_snippet": "...", "hybrid_score": 0.85}]
            category: Query category (asset/sigma/None)
        """
        # Analyze query intent
        intent_analysis = self._analyze_query_intent(user_query, category)
        
        prompt = f"""**User Question:**
{user_query}

**Query Intent Analysis:**
- Intent Type: {intent_analysis['intent_type']}
- Focus Areas: {', '.join(intent_analysis['focus_areas'])}
- Answer Structure: {intent_analysis['answer_structure']}

"""
        
        if rag_results and len(rag_results) > 0:
            prompt += "**Knowledge Base References:**\n\n"
            for i, result in enumerate(rag_results, 1):
                metadata = result.get("metadata", {})
                content = result.get("content_snippet", "")
                score = result.get("hybrid_score", 0.0)
                
                source = metadata.get("source", "Unknown")
                category = metadata.get("category", "")
                title = metadata.get("title", "")
                
                prompt += f"**Reference {i}** (Source: {source}, Score: {score:.4f})\n"
                if category:
                    prompt += f"Category: {category}\n"
                if title:
                    prompt += f"Title: {title}\n"
                prompt += f"Content:\n{content}\n\n"
        else:
            prompt += "**Note:** No specific knowledge base references found. Please provide a general answer based on your cybersecurity expertise.\n\n"
        
        # Add category-specific instructions
        if category == "asset":
            prompt += """**Task:**
Extract and present ONLY the information about the specific asset from the references above.

**CRITICAL RULES - MUST FOLLOW:**
1. **ONLY show information from the reference** - DO NOT add any extra information
2. **DO NOT explain what the fields mean** - just show the data
3. **DO NOT add security recommendations** unless explicitly asked
4. **DO NOT discuss attacks or vulnerabilities** unless explicitly asked
5. **Format exactly as shown in the reference** - preserve the structure
6. If multiple assets found, show only the one matching the IP in the question
7. If asset not found, say "Không tìm thấy thông tin về IP này trong cơ sở dữ liệu"

**Answer Format (Vietnamese):**
```
🖥️ **Thông tin Asset**

* IP: [IP address]
* **Nghiệp vụ (Label):** [Label]
* **Logic (Rule):** [Rule description from reference]
```

**DO NOT add:**
- Explanations about what each field means
- Security recommendations
- Attack scenarios
- Prevention measures
- Any information not in the reference

**Answer:**"""
        else:
            prompt += """**Task:**
Based on the query intent analysis and references above, provide a comprehensive answer that **directly addresses what the user is asking for**.

**Critical Instructions:**
1. **Follow the Answer Structure** specified in the intent analysis
2. **Prioritize the Focus Areas** - spend most of your answer on what the user wants to know
3. If user asks "how to prevent" → 80% prevention techniques, 20% brief context
4. If user asks "what is" (security topic) → 60% definition/mechanism, 40% prevention overview
5. If user asks "how to detect" → 80% detection methods, 20% brief context
6. If user asks for "examples" → 80% concrete examples and case studies

**Answer Format:**
- Use markdown formatting with clear sections
- Be clear, actionable, and practical
- Use Vietnamese if the question is in Vietnamese, otherwise use English
- Cite sources when using specific information from references
- For technical questions, provide specific, implementable steps

**Answer:**"""
        
        return prompt
    
    def _get_fallback_answer(self, user_query: str) -> dict:
        """Return fallback answer if MCP or LLM fails."""
        answer = f"""# Trả Lời Câu Hỏi

**Câu hỏi:** {user_query}

**Lỗi:** Không thể truy vấn cơ sở kiến thức hoặc tạo câu trả lời. Vui lòng thử lại sau.

**Gợi ý:**
- Kiểm tra rag_server.py đang chạy: `python mcp_server/rag_server.py --test`
- Kiểm tra ChromaDB accessible tại: D:\\MCPLLM\\test\\chroma_sec_db
- Kiểm tra MCP connection: `python test_mcp_rag_connection.py`
- Kiểm tra API key và cấu hình

Để được hỗ trợ, vui lòng liên hệ quản trị viên hệ thống.
"""
        return {
            'answer': answer,
            'sources': []
        }


# Singleton instance
_queryrag_agent = None


def get_queryrag_agent() -> QueryRAGAgent:
    """Get or create QueryRAGAgent singleton."""
    global _queryrag_agent
    if _queryrag_agent is None:
        _queryrag_agent = QueryRAGAgent()
    return _queryrag_agent