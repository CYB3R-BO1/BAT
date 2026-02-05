"""
BAT Agent Module

Contains components for:
- Autonomous vulnerability investigation
- Patch generation
- Patch validation
"""

from .investigator import VulnerabilityInvestigator
from .patch_agent import PatchAgent, PatchSuggestion
from .validator import PatchValidator, ValidationResult

__all__ = [
    'VulnerabilityInvestigator',
    'PatchAgent', 'PatchSuggestion',
    'PatchValidator', 'ValidationResult'
]
