"""
Report Generator Module

Generates comprehensive security reports in multiple formats:
- JSON (machine-readable)
- Markdown (human-readable)
- HTML (optional)
"""

import sys
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path

# Handle both module and standalone imports
try:
    from BAT.rag.retriever import KnowledgeRetriever
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from rag.retriever import KnowledgeRetriever


@dataclass
class VulnerabilityFinding:
    """A single vulnerability finding."""
    id: int
    vuln_type: str
    severity: str
    location: str
    sink: str
    evidence: Dict
    explanation: str
    patch: Optional[Dict] = None
    validation: Optional[Dict] = None
    cwe_ids: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityReport:
    """Complete vulnerability report."""
    title: str
    project: str
    scan_date: str
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)


class ReportGenerator:
    """
    Generator for vulnerability reports.
    
    Produces detailed reports in JSON and Markdown formats.
    """

    def __init__(self, knowledge_retriever: KnowledgeRetriever = None):
        """
        Initialize the report generator.
        
        Args:
            knowledge_retriever: Optional KnowledgeRetriever for explanations
        """
        self.retriever = knowledge_retriever or KnowledgeRetriever()
        self.report: Optional[VulnerabilityReport] = None

    def generate_report(self, 
                        vulnerabilities: List[Dict],
                        patches: List[Dict] = None,
                        validations: List[Dict] = None,
                        project_name: str = "Unknown",
                        summary: Dict = None) -> VulnerabilityReport:
        """
        Generate a complete vulnerability report.
        
        Args:
            vulnerabilities: List of vulnerability evidence dicts
            patches: Optional list of patch suggestions
            validations: Optional list of validation results
            project_name: Name of the analyzed project
            summary: Optional summary statistics
            
        Returns:
            VulnerabilityReport object
        """
        patches = patches or []
        validations = validations or []
        
        # Create patch lookup
        patch_lookup = {}
        for patch in patches:
            key = f"{patch.get('file', '')}:{patch.get('line', 0)}"
            patch_lookup[key] = patch
        
        # Create validation lookup
        validation_lookup = {}
        for val in validations:
            patch_info = val.get('patch', {})
            key = f"{patch_info.get('file', '')}:{patch_info.get('line', 0)}"
            validation_lookup[key] = val
        
        # Build findings
        findings = []
        for i, vuln in enumerate(vulnerabilities, 1):
            location = vuln.get('location', '')
            
            # Get associated patch and validation
            patch = patch_lookup.get(location)
            validation = validation_lookup.get(location)
            
            # Generate explanation
            explanation = self.retriever.generate_explanation(vuln)
            
            finding = VulnerabilityFinding(
                id=i,
                vuln_type=vuln.get('vuln_type', 'UNKNOWN'),
                severity=vuln.get('severity', 'MEDIUM'),
                location=location,
                sink=vuln.get('sink', ''),
                evidence=vuln,
                explanation=explanation,
                patch=patch,
                validation=validation,
                cwe_ids=vuln.get('cwe_ids', [vuln.get('cwe_id', '')] if vuln.get('cwe_id') else [])
            )
            findings.append(finding)
        
        # Generate summary if not provided
        if not summary:
            summary = self._generate_summary(findings)
        
        self.report = VulnerabilityReport(
            title="BAT Security Report",
            project=project_name,
            scan_date=datetime.now().isoformat(),
            findings=findings,
            summary=summary,
            metadata={
                'bat_version': '1.0.0',
                'report_format': 'v1'
            }
        )
        
        return self.report

    def _generate_summary(self, findings: List[VulnerabilityFinding]) -> Dict:
        """Generate summary statistics."""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        type_counts = {}
        patched = 0
        fixed = 0
        
        for finding in findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            vuln_type = finding.vuln_type
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
            
            if finding.patch:
                patched += 1
            if finding.validation and finding.validation.get('vulnerability_fixed'):
                fixed += 1
        
        return {
            'total_vulnerabilities': len(findings),
            'severity_distribution': severity_counts,
            'type_distribution': type_counts,
            'patches_generated': patched,
            'patches_validated': fixed
        }

    def to_json(self, indent: int = 2) -> str:
        """
        Export report to JSON format.
        
        Returns:
            JSON string representation
        """
        if not self.report:
            return "{}"
        
        return json.dumps(self._report_to_dict(), indent=indent)

    def _report_to_dict(self) -> Dict:
        """Convert report to dictionary."""
        return {
            'title': self.report.title,
            'project': self.report.project,
            'scan_date': self.report.scan_date,
            'summary': self.report.summary,
            'findings': [
                {
                    'id': f.id,
                    'vuln_type': f.vuln_type,
                    'severity': f.severity,
                    'location': f.location,
                    'sink': f.sink,
                    'cwe_ids': f.cwe_ids,
                    'evidence': f.evidence,
                    'explanation': f.explanation,
                    'patch': f.patch,
                    'validation': f.validation
                }
                for f in self.report.findings
            ],
            'metadata': self.report.metadata
        }

    def to_markdown(self) -> str:
        """
        Export report to Markdown format.
        
        Returns:
            Markdown string representation
        """
        if not self.report:
            return ""
        
        lines = []
        
        # Header
        lines.append(f"# {self.report.title}")
        lines.append("")
        lines.append(f"**Project:** {self.report.project}")
        lines.append(f"**Scan Date:** {self.report.scan_date}")
        lines.append("")
        
        # Summary
        lines.append("## Summary")
        lines.append("")
        summary = self.report.summary
        lines.append(f"- **Total vulnerabilities found:** {summary.get('total_vulnerabilities', 0)}")
        
        severity_dist = summary.get('severity_distribution', {})
        lines.append(f"- **Critical:** {severity_dist.get('CRITICAL', 0)}")
        lines.append(f"- **High:** {severity_dist.get('HIGH', 0)}")
        lines.append(f"- **Medium:** {severity_dist.get('MEDIUM', 0)}")
        lines.append(f"- **Low:** {severity_dist.get('LOW', 0)}")
        
        lines.append(f"- **Patches generated:** {summary.get('patches_generated', 0)}")
        lines.append(f"- **Patches validated:** {summary.get('patches_validated', 0)}")
        lines.append("")
        
        # Findings
        lines.append("---")
        lines.append("")
        lines.append("## Findings")
        lines.append("")
        
        for finding in self.report.findings:
            lines.extend(self._finding_to_markdown(finding))
            lines.append("")
            lines.append("---")
            lines.append("")
        
        return '\n'.join(lines)

    def _finding_to_markdown(self, finding: VulnerabilityFinding) -> List[str]:
        """Convert a single finding to Markdown."""
        lines = []
        
        # Header with severity badge
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        emoji = severity_emoji.get(finding.severity, '⚪')
        
        cwe_str = ', '.join(finding.cwe_ids) if finding.cwe_ids else 'Unknown'
        lines.append(f"### Finding {finding.id}: {finding.vuln_type} ({cwe_str})")
        lines.append("")
        lines.append(f"**Severity:** {emoji} {finding.severity}")
        lines.append(f"**Location:** `{finding.location}`")
        if finding.sink:
            lines.append(f"**Sink:** `{finding.sink}`")
        lines.append("")
        
        # Evidence
        lines.append("#### Evidence")
        lines.append("")
        evidence = finding.evidence
        
        if 'taint_path' in evidence:
            lines.append("**Taint Path:**")
            for step in evidence['taint_path']:
                lines.append(f"- `{step}`")
            lines.append("")
        
        if 'buffer' in evidence:
            lines.append(f"**Buffer:** `{evidence['buffer']}`")
        if 'input_source' in evidence:
            lines.append(f"**Input Source:** `{evidence['input_source']}`")
        if 'bounds_check' in evidence:
            lines.append(f"**Bounds Check:** {'Yes' if evidence['bounds_check'] else 'No'}")
        if 'confidence' in evidence:
            lines.append(f"**Confidence:** {evidence['confidence']:.2f}")
        lines.append("")
        
        # Explanation
        lines.append("#### Explanation")
        lines.append("")
        lines.append(finding.explanation)
        lines.append("")
        
        # Exploit Scenario
        exploit_scenario = self.retriever.get_exploit_scenario(evidence)
        lines.append("#### Potential Exploit Scenario")
        lines.append("")
        lines.append(exploit_scenario)
        lines.append("")
        
        # Patch
        if finding.patch:
            lines.append("#### Suggested Patch")
            lines.append("")
            lines.append(f"**Explanation:** {finding.patch.get('explanation', 'N/A')}")
            lines.append("")
            
            # Show diff
            if finding.patch.get('diff'):
                lines.append("```diff")
                lines.append(finding.patch['diff'])
                lines.append("```")
            else:
                # Show before/after
                lines.append("**Before:**")
                lines.append("```c")
                lines.append(finding.patch.get('original_code', ''))
                lines.append("```")
                lines.append("")
                lines.append("**After:**")
                lines.append("```c")
                lines.append(finding.patch.get('patched_code', ''))
                lines.append("```")
            lines.append("")
        
        # Validation
        if finding.validation:
            lines.append("#### Patch Validation")
            lines.append("")
            val = finding.validation
            lines.append(f"- **Patch Applied:** {'✅ Yes' if val.get('patch_applied') else '❌ No'}")
            lines.append(f"- **Compilation:** {val.get('compilation', 'N/A')}")
            lines.append(f"- **Vulnerability Fixed:** {'✅ Yes' if val.get('vulnerability_fixed') else '❌ No'}")
            if val.get('errors'):
                lines.append(f"- **Errors:** {', '.join(val['errors'])}")
            lines.append("")
        
        return lines

    def save_json(self, output_path: str) -> None:
        """Save report as JSON file."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(self.to_json())

    def save_markdown(self, output_path: str) -> None:
        """Save report as Markdown file."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(self.to_markdown())

    def save(self, output_dir: str, base_name: str = "report") -> Dict[str, str]:
        """
        Save report in multiple formats.
        
        Args:
            output_dir: Directory to save reports
            base_name: Base filename (without extension)
            
        Returns:
            Dict mapping format to file path
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        paths = {}
        
        # Save JSON
        json_path = output_path / f"{base_name}.json"
        self.save_json(str(json_path))
        paths['json'] = str(json_path)
        
        # Save Markdown
        md_path = output_path / f"{base_name}.md"
        self.save_markdown(str(md_path))
        paths['markdown'] = str(md_path)
        
        return paths
