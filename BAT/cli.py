#!/usr/bin/env python3
"""
BAT - Autonomous Vulnerability Investigation CLI

Usage:
    bat scan ./project
    bat scan file.c
    bat scan ./project --output ./reports
    bat scan ./project --format json,md
"""

import argparse
import sys
import os
from pathlib import Path
from typing import List, Dict

# Add package directory to path for imports
_pkg_dir = Path(__file__).parent
sys.path.insert(0, str(_pkg_dir))
sys.path.insert(0, str(_pkg_dir.parent))

# Try relative imports first (when run as module), fall back to absolute
try:
    from BAT.agent.investigator import VulnerabilityInvestigator
    from BAT.agent.patch_agent import PatchAgent
    from BAT.agent.validator import PatchValidator
    from BAT.rag.retriever import KnowledgeRetriever
    from BAT.report.report_generator import ReportGenerator
except ImportError:
    from agent.investigator import VulnerabilityInvestigator
    from agent.patch_agent import PatchAgent
    from agent.validator import PatchValidator
    from rag.retriever import KnowledgeRetriever
    from report.report_generator import ReportGenerator


def print_banner():
    """Print BAT banner."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║   ____    _  _____   __     ___                              ║
║  | __ )  / \\|_   _| /  \\   / _ \\                            ║
║  |  _ \\ / _ \\ | |  / /\\ \\ | | | |                           ║
║  | |_) / ___ \\| | / ____ \\| |_| |                           ║
║  |____/_/   \\_\\_|/_/    \\_\\\\___/                            ║
║                                                              ║
║  Autonomous Vulnerability Investigation for C Memory Bugs    ║
║  Version 1.0.0                                               ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def scan_project(args) -> int:
    """
    Scan a project for vulnerabilities.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        Exit code (0 for success)
    """
    project_path = args.path
    
    # Validate path
    if not os.path.exists(project_path):
        print(f"Error: Path does not exist: {project_path}")
        return 1
    
    # Configuration
    config = {
        'confidence_threshold': args.confidence,
        'compiler': args.compiler,
        'run_tests': args.run_tests
    }
    
    # Phase 1: Investigation
    print("\n[Phase 1] Vulnerability Investigation")
    print("=" * 50)
    
    investigator = VulnerabilityInvestigator(project_path, config)
    result = investigator.investigate()
    
    if not result.confirmed:
        print("\n✅ No vulnerabilities found!")
        return 0
    
    print(f"\n⚠️  Found {len(result.confirmed)} potential vulnerabilities")
    
    # Phase 2: Patch Generation
    print("\n[Phase 2] Patch Generation")
    print("=" * 50)
    
    # Load file contents for patching
    file_contents = {}
    for vuln in result.confirmed:
        location = vuln.get('location', '')
        if ':' in location:
            filename = location.rsplit(':', 1)[0]
            if filename not in file_contents:
                filepath = os.path.join(project_path, filename) if os.path.isdir(project_path) else project_path
                if os.path.exists(filepath):
                    try:
                        with open(filepath, 'r') as f:
                            file_contents[filename] = f.readlines()
                    except:
                        pass
    
    patch_agent = PatchAgent(config)
    patches = patch_agent.generate_patches_for_findings(result.confirmed, 
                                                         {k: v for k, v in file_contents.items()})
    
    print(f"Generated {len(patches)} patches")
    
    # Phase 3: Patch Validation
    validations = []
    if args.validate and patches:
        print("\n[Phase 3] Patch Validation")
        print("=" * 50)
        
        validator = PatchValidator(project_path, config)
        
        for patch in patches:
            content = ''.join(file_contents.get(patch.file, []))
            val_result = validator.validate_patch(patch, content)
            
            # Store the validation result
            result_json = {
                'patch_applied': val_result.patch_applied,
                'compilation_success': val_result.compilation_success,
                'vulnerability_fixed': val_result.vulnerability_fixed,
                'tests_passed': val_result.tests_passed,
                'errors': val_result.errors
            }
            validations.append(result_json)
            
            status = "✅" if val_result.vulnerability_fixed else "❌"
            print(f"  {status} {patch.file}:{patch.line} - {patch.vuln_type}")
        
        summary = validator.get_validation_summary()
        print(f"\nValidation Summary: {summary['vulnerabilities_fixed']}/{summary['total_patches']} patches successful")
    
    # Phase 4: Report Generation
    print("\n[Phase 4] Report Generation")
    print("=" * 50)
    
    retriever = KnowledgeRetriever()
    generator = ReportGenerator(retriever)
    
    project_name = os.path.basename(os.path.abspath(project_path))
    report = generator.generate_report(
        vulnerabilities=result.confirmed,
        patches=patch_agent.get_all_patches_json(),
        validations=validations,
        project_name=project_name,
        summary=result.summary
    )
    
    # Save reports
    output_dir = args.output or os.path.join(os.getcwd(), 'bat_reports')
    os.makedirs(output_dir, exist_ok=True)
    
    formats = args.format.split(',') if args.format else ['json', 'md']
    
    paths = {}
    if 'json' in formats:
        json_path = os.path.join(output_dir, 'report.json')
        generator.save_json(json_path)
        paths['json'] = json_path
        print(f"  📄 JSON report: {json_path}")
    
    if 'md' in formats or 'markdown' in formats:
        md_path = os.path.join(output_dir, 'report.md')
        generator.save_markdown(md_path)
        paths['markdown'] = md_path
        print(f"  📄 Markdown report: {md_path}")
    
    # Print summary
    print("\n" + "=" * 50)
    print("SCAN SUMMARY")
    print("=" * 50)
    
    summary = result.summary
    print(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
    print("\nBy Severity:")
    for sev, count in summary.get('severity_distribution', {}).items():
        if count > 0:
            print(f"  - {sev}: {count}")
    
    print("\nBy Type:")
    for vuln_type, count in summary.get('type_distribution', {}).items():
        print(f"  - {vuln_type}: {count}")
    
    print(f"\nFiles Analyzed: {summary.get('files_analyzed', 0)}")
    print(f"Functions Analyzed: {summary.get('functions_analyzed', 0)}")
    
    return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog='bat',
        description='BAT - Autonomous Vulnerability Investigation for C Memory Bugs'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a C project for vulnerabilities')
    scan_parser.add_argument('path', help='Path to C project or file')
    scan_parser.add_argument('-o', '--output', help='Output directory for reports')
    scan_parser.add_argument('-f', '--format', default='json,md',
                           help='Output formats (json, md). Comma-separated.')
    scan_parser.add_argument('--confidence', type=float, default=0.6,
                           help='Confidence threshold (0.0-1.0)')
    scan_parser.add_argument('--compiler', default='gcc',
                           help='C compiler for validation')
    scan_parser.add_argument('--validate', action='store_true', default=True,
                           help='Validate generated patches')
    scan_parser.add_argument('--no-validate', action='store_false', dest='validate',
                           help='Skip patch validation')
    scan_parser.add_argument('--run-tests', action='store_true',
                           help='Run test suite after patching')
    scan_parser.add_argument('-v', '--verbose', action='store_true',
                           help='Verbose output')
    scan_parser.add_argument('-q', '--quiet', action='store_true',
                           help='Quiet mode (minimal output)')
    
    # Version
    parser.add_argument('--version', action='version', version='BAT 1.0.0')
    
    args = parser.parse_args()
    
    if not args.quiet:
        print_banner()
    
    if args.command == 'scan':
        return scan_project(args)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
