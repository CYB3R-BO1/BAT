"""
Vulnerability Investigator Module

The main autonomous agent that orchestrates vulnerability detection:
1. Scans codebase
2. Generates hypotheses
3. Extracts evidence
4. Classifies vulnerabilities
5. Generates reports
"""

import os
import sys
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path

# Handle both module and standalone imports
try:
    from BAT.analyzer.ast_parser import ASTParser, RepoIndex
    from BAT.analyzer.taint_engine import TaintEngine
    from BAT.analyzer.lifetime_checker import LifetimeChecker
    from BAT.analyzer.overflow_checker import OverflowChecker
except ImportError:
    # Add parent to path for standalone execution
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from analyzer.ast_parser import ASTParser, RepoIndex
    from analyzer.taint_engine import TaintEngine
    from analyzer.lifetime_checker import LifetimeChecker
    from analyzer.overflow_checker import OverflowChecker


@dataclass
class VulnerabilityCandidate:
    """A potential vulnerability candidate."""
    vuln_type: str
    sink: str
    file: str
    line: int
    confidence: float = 0.0
    priority: str = "MEDIUM"
    evidence: Dict = field(default_factory=dict)


@dataclass
class InvestigationResult:
    """Result of a vulnerability investigation."""
    candidates: List[VulnerabilityCandidate] = field(default_factory=list)
    confirmed: List[Dict] = field(default_factory=list)
    discarded: List[Dict] = field(default_factory=list)
    repo_index: Optional[RepoIndex] = None
    summary: Dict = field(default_factory=dict)


class VulnerabilityInvestigator:
    """
    Autonomous Vulnerability Investigation Agent
    
    Orchestrates the vulnerability detection pipeline:
    1. Codebase reconnaissance
    2. Hypothesis generation
    3. Evidence extraction
    4. Vulnerability classification
    """

    # Vulnerability types supported
    VULN_TYPES = {
        'BUFFER_OVERFLOW': {
            'cwe_ids': ['CWE-787', 'CWE-120'],
            'severity': 'HIGH',
            'description': 'Out-of-bounds write to memory buffer'
        },
        'USE_AFTER_FREE': {
            'cwe_ids': ['CWE-416'],
            'severity': 'HIGH',
            'description': 'Use of memory after it has been freed'
        },
        'INTEGER_OVERFLOW': {
            'cwe_ids': ['CWE-190'],
            'severity': 'MEDIUM',
            'description': 'Integer overflow leading to memory corruption'
        }
    }

    def __init__(self, project_path: str, config: Dict = None):
        """
        Initialize the vulnerability investigator.
        
        Args:
            project_path: Path to the C project
            config: Optional configuration dictionary
        """
        self.project_path = Path(project_path)
        self.config = config or {}
        
        # Initialize analyzers
        self.ast_parser = ASTParser()
        self.taint_engine = TaintEngine()
        self.lifetime_checker = LifetimeChecker()
        self.overflow_checker = OverflowChecker()
        
        # Investigation state
        self.result = InvestigationResult()
        self.candidates: List[VulnerabilityCandidate] = []
        self.evidence_store: List[Dict] = []

    def investigate(self) -> InvestigationResult:
        """
        Run the complete vulnerability investigation pipeline.
        
        Returns:
            InvestigationResult containing all findings
        """
        print(f"[BAT] Starting investigation of {self.project_path}")
        
        # Step 1: Codebase Reconnaissance
        print("[BAT] Phase 1: Codebase Reconnaissance")
        self._reconnaissance()
        
        # Step 2: Generate Hypotheses
        print("[BAT] Phase 2: Hypothesis Generation")
        self._generate_hypotheses()
        
        # Step 3: Extract Evidence
        print("[BAT] Phase 3: Evidence Extraction")
        self._extract_evidence()
        
        # Step 4: Classify Vulnerabilities
        print("[BAT] Phase 4: Vulnerability Classification")
        self._classify_vulnerabilities()
        
        # Step 5: Build Summary
        print("[BAT] Phase 5: Building Summary")
        self._build_summary()
        
        print(f"[BAT] Investigation complete. Found {len(self.result.confirmed)} vulnerabilities.")
        
        return self.result

    def _reconnaissance(self) -> None:
        """Phase 1: Build understanding of the codebase structure."""
        if self.project_path.is_file():
            self.ast_parser.parse_file(str(self.project_path))
        else:
            self.ast_parser.parse_directory(str(self.project_path))
        
        self.result.repo_index = self.ast_parser.get_index()
        
        # Log reconnaissance results
        num_files = len(self.result.repo_index.files)
        num_functions = len(self.result.repo_index.functions)
        num_calls = len(self.result.repo_index.calls)
        
        print(f"[BAT]   - Parsed {num_files} files")
        print(f"[BAT]   - Found {num_functions} functions")
        print(f"[BAT]   - Found {num_calls} function calls")

    def _generate_hypotheses(self) -> None:
        """Phase 2: Generate vulnerability hypotheses based on dangerous sinks."""
        dangerous_calls = self.ast_parser.get_dangerous_calls()
        
        for call in dangerous_calls:
            candidate = VulnerabilityCandidate(
                vuln_type=self._infer_vuln_type(call.callee),
                sink=call.callee,
                file=call.file,
                line=call.line,
                priority=self._get_priority(call.callee)
            )
            self.candidates.append(candidate)
        
        print(f"[BAT]   - Generated {len(self.candidates)} hypotheses")

    def _infer_vuln_type(self, sink: str) -> str:
        """Infer vulnerability type from sink function."""
        overflow_sinks = {'strcpy', 'strcat', 'gets', 'sprintf', 'vsprintf', 
                         'memcpy', 'memmove', 'scanf', 'fscanf', 'sscanf'}
        uaf_sinks = {'free'}
        malloc_sinks = {'malloc', 'calloc', 'realloc'}
        
        if sink in overflow_sinks:
            return 'BUFFER_OVERFLOW'
        elif sink in uaf_sinks:
            return 'USE_AFTER_FREE'
        elif sink in malloc_sinks:
            return 'INTEGER_OVERFLOW'
        
        return 'UNKNOWN'

    def _get_priority(self, sink: str) -> str:
        """Get priority based on sink function."""
        critical_sinks = {'gets'}
        high_sinks = {'strcpy', 'strcat', 'sprintf', 'free'}
        
        if sink in critical_sinks:
            return 'CRITICAL'
        elif sink in high_sinks:
            return 'HIGH'
        return 'MEDIUM'

    def _extract_evidence(self) -> None:
        """Phase 3: Extract evidence for each hypothesis."""
        c_files = self._get_c_files()
        
        # Run specialized analyzers
        for filepath in c_files:
            try:
                # Taint analysis for buffer overflow
                self.taint_engine.analyze_file(filepath)
                
                # Lifetime analysis for UAF
                self.lifetime_checker.analyze_file(filepath)
                
                # Overflow analysis
                self.overflow_checker.analyze_file(filepath)
            except Exception as e:
                print(f"[BAT]   Warning: Error analyzing {filepath}: {e}")
        
        # Compute taint flows
        taint_flows = self.taint_engine.compute_taint_flows()
        
        # Collect evidence
        for flow in taint_flows:
            evidence = self.taint_engine.get_evidence_for_flow(flow)
            self.evidence_store.append(evidence)
        
        # Collect UAF evidence
        uaf_evidence = self.lifetime_checker.get_all_evidence()
        self.evidence_store.extend(uaf_evidence)
        
        # Collect overflow evidence
        overflow_evidence = self.overflow_checker.get_all_evidence()
        self.evidence_store.extend(overflow_evidence)
        
        print(f"[BAT]   - Extracted {len(self.evidence_store)} evidence objects")

    def _get_c_files(self) -> List[str]:
        """Get all C source files in the project."""
        if self.project_path.is_file():
            return [str(self.project_path)]
        
        c_files = []
        for ext in ['*.c', '*.h']:
            c_files.extend(self.project_path.glob(f'**/{ext}'))
        
        return [str(f) for f in c_files]

    def _classify_vulnerabilities(self) -> None:
        """Phase 4: Classify and confirm vulnerabilities."""
        confidence_threshold = self.config.get('confidence_threshold', 0.6)
        
        for evidence in self.evidence_store:
            confidence = evidence.get('confidence', 0.5)
            vuln_type = evidence.get('vuln_type', 'UNKNOWN')
            
            if confidence >= confidence_threshold:
                # Enrich evidence with classification data
                classified = self._enrich_evidence(evidence)
                self.result.confirmed.append(classified)
            else:
                self.result.discarded.append({
                    'evidence': evidence,
                    'reason': f'Low confidence ({confidence:.2f} < {confidence_threshold})'
                })
        
        print(f"[BAT]   - Confirmed {len(self.result.confirmed)} vulnerabilities")
        print(f"[BAT]   - Discarded {len(self.result.discarded)} candidates")

    def _enrich_evidence(self, evidence: Dict) -> Dict:
        """Enrich evidence with additional classification data."""
        vuln_type = evidence.get('vuln_type', 'UNKNOWN')
        vuln_info = self.VULN_TYPES.get(vuln_type, {})
        
        enriched = evidence.copy()
        enriched['cwe_ids'] = vuln_info.get('cwe_ids', [])
        enriched['severity'] = self._calculate_severity(evidence)
        enriched['description'] = vuln_info.get('description', 'Unknown vulnerability')
        
        return enriched

    def _calculate_severity(self, evidence: Dict) -> str:
        """Calculate severity based on evidence."""
        confidence = evidence.get('confidence', 0.5)
        vuln_type = evidence.get('vuln_type', 'UNKNOWN')
        
        # Base severity from vulnerability type
        base_severity = self.VULN_TYPES.get(vuln_type, {}).get('severity', 'MEDIUM')
        
        # Adjust based on specific indicators
        if evidence.get('input_source') == 'stdin' or 'argv' in str(evidence.get('input_source', '')):
            return 'CRITICAL' if base_severity == 'HIGH' else 'HIGH'
        
        if evidence.get('bounds_check', True) == False:
            if base_severity == 'MEDIUM':
                return 'HIGH'
        
        return base_severity

    def _build_summary(self) -> None:
        """Build investigation summary."""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        type_counts = {}
        
        for vuln in self.result.confirmed:
            severity = vuln.get('severity', 'MEDIUM')
            vuln_type = vuln.get('vuln_type', 'UNKNOWN')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        self.result.summary = {
            'total_vulnerabilities': len(self.result.confirmed),
            'severity_distribution': severity_counts,
            'type_distribution': type_counts,
            'files_analyzed': len(self.result.repo_index.files) if self.result.repo_index else 0,
            'functions_analyzed': len(self.result.repo_index.functions) if self.result.repo_index else 0
        }

    def get_findings_json(self) -> str:
        """Get all findings as JSON string."""
        return json.dumps({
            'summary': self.result.summary,
            'vulnerabilities': self.result.confirmed,
            'discarded': self.result.discarded
        }, indent=2)

    def save_findings(self, output_path: str) -> None:
        """Save findings to file."""
        with open(output_path, 'w') as f:
            f.write(self.get_findings_json())

    def get_candidates_for_type(self, vuln_type: str) -> List[Dict]:
        """Get all confirmed findings of a specific type."""
        return [v for v in self.result.confirmed if v.get('vuln_type') == vuln_type]
