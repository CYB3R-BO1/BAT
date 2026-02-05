"""
BAT Report Module

Contains components for:
- Report generation (JSON, Markdown)
- Report templates
"""

from .report_generator import ReportGenerator, VulnerabilityReport

__all__ = ['ReportGenerator', 'VulnerabilityReport']
