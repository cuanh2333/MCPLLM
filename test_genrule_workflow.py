"""
Test complete GenRule workflow:
1. Query RAG for Sigma rules
2. Extract best rule
3. Generate detection rules

Run this AFTER restarting RAG server!
"""
import asyncio
import sys
import os
import re

sys.path.insert(0, os.path.dirname(__file__))

from backend.agents.queryrag_agent import QueryRAGAgent
from backend.agents.genrule_agent import GenRuleAgent


async def test_genrule_workflow():
    """Test complete workflow"""
    
    print("=" * 80)
    print("Testing GenRule Workflow")
    print("=" * 80)
    
    # Step 1: Query RAG for SQL injection Sigma rules
    print("\nStep 1: Query RAG for Sigma rules")
    print("-" * 80)
    
    queryrag = QueryRAGAgent()
    
    query = "SQL injection SQLi database query UNION SELECT INSERT detection ONLY"
    result = await queryrag.query_knowledge(query, category="sigma_rule")
    
    if isinstance(result, dict):
        answer = result.get('answer', '')
        sources = result.get('sources', [])
        
        print(f"✓ Retrieved {len(sources)} sources")
        print(f"✓ Answer length: {len(answer)} chars")
        
        # Check YAML completeness
        has_title = 'title:' in answer
        has_detection = 'detection:' in answer
        has_logsource = 'logsource:' in answer
        has_condition = 'condition:' in answer
        
        print(f"\nYAML Completeness:")
        print(f"  Has title: {has_title}")
        print(f"  Has logsource: {has_logsource}")
        print(f"  Has detection: {has_detection}")
        print(f"  Has condition: {has_condition}")
        
        if not (has_title and has_detection and has_logsource and has_condition):
            print("\n✗ FAIL: Incomplete Sigma YAML")
            print("\nFirst 1000 chars:")
            print(answer[:1000])
            print("\n⚠️  Please restart RAG server to apply changes!")
            return False
        
        print("\n✓ PASS: Full Sigma YAML retrieved")
        
        # Step 2: Extract best rule
        print("\nStep 2: Extract best Sigma rule")
        print("-" * 80)
        
        genrule = GenRuleAgent()
        best_rule = genrule._extract_best_sigma_rule(answer, "sqli", sources)
        
        print(f"✓ Extracted rule length: {len(best_rule)} chars")
        
        # Extract title
        title_match = re.search(r'title:\s*(.+)', best_rule)
        if title_match:
            title = title_match.group(1)
            print(f"✓ Rule title: {title}")
            
            # Check if focused (not multi-attack)
            multi_indicators = ['ssti', 'webshell', 'source code', 'enumeration']
            is_multi = any(ind in title.lower() for ind in multi_indicators)
            
            if is_multi:
                print(f"✗ WARNING: Multi-attack rule detected")
            else:
                print(f"✓ Focused SQL injection rule")
        
        # Check rule has detection section
        if 'detection:' in best_rule and 'condition:' in best_rule:
            print(f"✓ Rule has complete detection logic")
        else:
            print(f"✗ FAIL: Rule missing detection logic")
            return False
        
        print("\n✓ PASS: Best rule extracted successfully")
        
        # Step 3: Show what GenRuleAgent will use
        print("\nStep 3: GenRuleAgent will use this rule")
        print("-" * 80)
        print(best_rule[:500])
        print("...")
        
        print("\n" + "=" * 80)
        print("✓ ALL TESTS PASSED!")
        print("=" * 80)
        print("\nGenRuleAgent is ready to generate detection rules.")
        print("It will:")
        print("  1. Use the focused Sigma rule as reference")
        print("  2. Extract patterns from real log samples")
        print("  3. Generate Sigma YAML + Splunk SPL")
        print("  4. Add deployment notes in Vietnamese")
        
        return True
    
    else:
        print(f"\n✗ FAIL: Unexpected result type")
        return False


if __name__ == "__main__":
    print("\n⚠️  IMPORTANT: Make sure RAG server is running!")
    print("   If you just modified rag_server_http.py, restart it first.\n")
    
    success = asyncio.run(test_genrule_workflow())
    sys.exit(0 if success else 1)
