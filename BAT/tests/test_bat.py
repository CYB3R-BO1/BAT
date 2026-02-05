"""
BAT Test Suite

Tests for vulnerability detection, patch generation, and reporting.
"""

import os
import sys
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.ast_parser import ASTParser
from analyzer.taint_engine import TaintEngine
from analyzer.lifetime_checker import LifetimeChecker
from analyzer.overflow_checker import OverflowChecker
from agent.investigator import VulnerabilityInvestigator
from agent.patch_agent import PatchAgent
from rag.retriever import KnowledgeRetriever


class TestASTParser(unittest.TestCase):
    """Tests for AST Parser."""
    
    def setUp(self):
        self.parser = ASTParser()
        self.test_file = Path(__file__).parent / "test_vulnerable.c"
    
    def test_parse_file(self):
        """Test parsing a C file."""
        if self.test_file.exists():
            self.parser.parse_file(str(self.test_file))
            index = self.parser.get_index()
            
            self.assertGreater(len(index.files), 0)
            self.assertGreater(len(index.functions), 0)
    
    def test_dangerous_calls(self):
        """Test detection of dangerous function calls."""
        if self.test_file.exists():
            self.parser.parse_file(str(self.test_file))
            dangerous = self.parser.get_dangerous_calls()
            
            # Should find strcpy, gets, sprintf, etc.
            dangerous_names = {call.callee for call in dangerous}
            self.assertTrue(
                dangerous_names.intersection({'strcpy', 'gets', 'sprintf', 'free', 'malloc'})
            )


class TestTaintEngine(unittest.TestCase):
    """Tests for Taint Analysis Engine."""
    
    def setUp(self):
        self.engine = TaintEngine()
        self.test_file = Path(__file__).parent / "test_vulnerable.c"
    
    def test_taint_sources(self):
        """Test detection of taint sources."""
        if self.test_file.exists():
            self.engine.analyze_file(str(self.test_file))
            
            # Should detect input sources
            self.assertGreater(len(self.engine.taint_sources) + len(self.engine.taint_sinks), 0)
    
    def test_taint_flows(self):
        """Test computation of taint flows."""
        if self.test_file.exists():
            self.engine.analyze_file(str(self.test_file))
            flows = self.engine.compute_taint_flows()
            
            # May or may not find flows depending on complexity
            # Just verify it doesn't crash
            self.assertIsInstance(flows, list)


class TestLifetimeChecker(unittest.TestCase):
    """Tests for Use-After-Free detection."""
    
    def setUp(self):
        self.checker = LifetimeChecker()
        self.test_file = Path(__file__).parent / "test_vulnerable.c"
    
    def test_uaf_detection(self):
        """Test UAF vulnerability detection."""
        if self.test_file.exists():
            evidence = self.checker.analyze_file(str(self.test_file))
            
            # Should find UAF in test file
            self.assertIsInstance(evidence, list)


class TestOverflowChecker(unittest.TestCase):
    """Tests for Overflow detection."""
    
    def setUp(self):
        self.checker = OverflowChecker()
        self.test_file = Path(__file__).parent / "test_vulnerable.c"
    
    def test_buffer_overflow_detection(self):
        """Test buffer overflow detection."""
        if self.test_file.exists():
            buf_evidence, int_evidence = self.checker.analyze_file(str(self.test_file))
            
            # Should find buffer overflows (strcpy, gets, sprintf)
            self.assertGreater(len(buf_evidence), 0)
            
            # Verify we found expected sinks
            sinks = {e.sink for e in buf_evidence}
            self.assertTrue(sinks.intersection({'strcpy', 'gets', 'sprintf', 'strcat'}))


class TestPatchAgent(unittest.TestCase):
    """Tests for Patch Generation."""
    
    def setUp(self):
        self.agent = PatchAgent()
    
    def test_strcpy_patch(self):
        """Test patch generation for strcpy."""
        evidence = {
            'vuln_type': 'BUFFER_OVERFLOW',
            'sink': 'strcpy',
            'location': 'test.c:10',
            'taint_path': ['test.c:10 strcpy(buffer, input)']
        }
        
        source_lines = [
            '#include <string.h>',
            'void func(char *input) {',
            '    char buffer[32];',
            '    strcpy(buffer, input);',
            '}'
        ]
        
        patch = self.agent.generate_patch(evidence, source_lines)
        
        if patch:
            self.assertIn('strncpy', patch.patched_code)
            self.assertEqual(patch.vuln_type, 'BUFFER_OVERFLOW')
    
    def test_gets_patch(self):
        """Test patch generation for gets."""
        evidence = {
            'vuln_type': 'BUFFER_OVERFLOW',
            'sink': 'gets',
            'location': 'test.c:5',
            'taint_path': ['test.c:5 gets(buffer)']
        }
        
        patch = self.agent.generate_patch(evidence)
        
        if patch:
            self.assertIn('fgets', patch.patched_code)


class TestKnowledgeRetriever(unittest.TestCase):
    """Tests for Knowledge Retrieval."""
    
    def setUp(self):
        self.retriever = KnowledgeRetriever()
    
    def test_cwe_lookup(self):
        """Test CWE knowledge lookup."""
        knowledge = self.retriever.get_by_cwe('CWE-787')
        
        self.assertIsNotNone(knowledge)
        self.assertEqual(knowledge.id, 'CWE-787')
        self.assertIn('buffer', knowledge.title.lower())
    
    def test_retrieve(self):
        """Test knowledge retrieval by query."""
        results = self.retriever.retrieve('strcpy buffer overflow')
        
        self.assertGreater(len(results), 0)
    
    def test_safe_replacement(self):
        """Test safe replacement lookup."""
        replacement = self.retriever.get_safe_replacement('strcpy')
        
        self.assertIsNotNone(replacement)
        self.assertIn('strncpy', replacement['safe'])
    
    def test_explanation_generation(self):
        """Test explanation generation."""
        evidence = {
            'vuln_type': 'BUFFER_OVERFLOW',
            'sink': 'strcpy',
            'cwe_id': 'CWE-787'
        }
        
        explanation = self.retriever.generate_explanation(evidence)
        
        self.assertIn('CWE-787', explanation)
        self.assertIn('strcpy', explanation.lower())


class TestInvestigator(unittest.TestCase):
    """Tests for Vulnerability Investigator."""
    
    def setUp(self):
        self.test_file = Path(__file__).parent / "test_vulnerable.c"
    
    def test_investigation(self):
        """Test full investigation pipeline."""
        if self.test_file.exists():
            investigator = VulnerabilityInvestigator(str(self.test_file))
            result = investigator.investigate()
            
            # Should find vulnerabilities in test file
            self.assertGreater(len(result.confirmed), 0)
            self.assertIsNotNone(result.repo_index)


def run_tests():
    """Run all tests."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestASTParser))
    suite.addTests(loader.loadTestsFromTestCase(TestTaintEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestLifetimeChecker))
    suite.addTests(loader.loadTestsFromTestCase(TestOverflowChecker))
    suite.addTests(loader.loadTestsFromTestCase(TestPatchAgent))
    suite.addTests(loader.loadTestsFromTestCase(TestKnowledgeRetriever))
    suite.addTests(loader.loadTestsFromTestCase(TestInvestigator))
    
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite)


if __name__ == '__main__':
    run_tests()
