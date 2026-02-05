"""
Patch Agent Module

Generates patches for detected vulnerabilities using:
- Rule-based transformations
- Knowledge base of safe replacements
- LLM-assisted patch generation (optional)
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from difflib import unified_diff


@dataclass
class PatchSuggestion:
    """A suggested patch for a vulnerability."""
    vuln_type: str
    file: str
    line: int
    original_code: str
    patched_code: str
    explanation: str
    diff: str = ""
    confidence: float = 0.0
    cwe_reference: str = ""


class PatchAgent:
    """
    Agent for generating patches for detected vulnerabilities.
    
    Uses rule-based transformations and safe replacement patterns.
    """

    # Safe replacement patterns
    SAFE_REPLACEMENTS = {
        'strcpy': {
            'pattern': r'strcpy\s*\(\s*(\w+)\s*,\s*([^)]+)\s*\)',
            'replacement': 'strncpy({dest}, {src}, sizeof({dest}) - 1); {dest}[sizeof({dest}) - 1] = \'\\0\'',
            'explanation': 'Replace unbounded strcpy with strncpy and explicit null termination'
        },
        'strcat': {
            'pattern': r'strcat\s*\(\s*(\w+)\s*,\s*([^)]+)\s*\)',
            'replacement': 'strncat({dest}, {src}, sizeof({dest}) - strlen({dest}) - 1)',
            'explanation': 'Replace unbounded strcat with strncat with proper bounds'
        },
        'gets': {
            'pattern': r'gets\s*\(\s*(\w+)\s*\)',
            'replacement': 'fgets({dest}, sizeof({dest}), stdin)',
            'explanation': 'Replace dangerous gets with bounded fgets'
        },
        'sprintf': {
            'pattern': r'sprintf\s*\(\s*(\w+)\s*,\s*([^)]+)\s*\)',
            'replacement': 'snprintf({dest}, sizeof({dest}), {format_and_args})',
            'explanation': 'Replace sprintf with bounded snprintf'
        },
        'vsprintf': {
            'pattern': r'vsprintf\s*\(\s*(\w+)\s*,\s*([^,]+)\s*,\s*([^)]+)\s*\)',
            'replacement': 'vsnprintf({dest}, sizeof({dest}), {format}, {args})',
            'explanation': 'Replace vsprintf with bounded vsnprintf'
        },
        'scanf': {
            'pattern': r'scanf\s*\(\s*"([^"]*)"\s*,\s*([^)]+)\s*\)',
            'replacement': 'scanf("{format_safe}", {args})',
            'explanation': 'Add width specifiers to scanf format string'
        }
    }

    # UAF fix patterns
    UAF_FIXES = {
        'null_after_free': {
            'explanation': 'Set pointer to NULL after free to prevent reuse',
            'template': '{free_stmt}\n    {ptr} = NULL;'
        },
        'check_before_use': {
            'explanation': 'Add NULL check before pointer use',
            'template': 'if ({ptr} != NULL) {{\n        {use_stmt}\n    }}'
        }
    }

    # Integer overflow fixes
    INT_OVERFLOW_FIXES = {
        'safe_multiply': {
            'explanation': 'Use safe multiplication with overflow check',
            'template': '''if ({op1} != 0 && {op2} > SIZE_MAX / {op1}) {{
        // Handle overflow error
        return NULL;
    }}
    {original}'''
        },
        'use_safe_math': {
            'explanation': 'Use compiler builtin for overflow-safe arithmetic',
            'template': '''size_t result;
    if (__builtin_mul_overflow({op1}, {op2}, &result)) {{
        // Handle overflow
        return NULL;
    }}
    {alloc_func}(result)'''
        }
    }

    def __init__(self, config: Dict = None):
        """
        Initialize the patch agent.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.patches: List[PatchSuggestion] = []

    def generate_patch(self, evidence: Dict, source_lines: List[str] = None) -> Optional[PatchSuggestion]:
        """
        Generate a patch for a vulnerability.
        
        Args:
            evidence: Vulnerability evidence dictionary
            source_lines: Optional source code lines for context
            
        Returns:
            PatchSuggestion if successful, None otherwise
        """
        vuln_type = evidence.get('vuln_type', '')
        
        if vuln_type == 'BUFFER_OVERFLOW':
            return self._generate_buffer_overflow_patch(evidence, source_lines)
        elif vuln_type == 'USE_AFTER_FREE':
            return self._generate_uaf_patch(evidence, source_lines)
        elif vuln_type == 'INTEGER_OVERFLOW':
            return self._generate_integer_overflow_patch(evidence, source_lines)
        
        return None

    def _generate_buffer_overflow_patch(self, evidence: Dict, 
                                         source_lines: List[str] = None) -> Optional[PatchSuggestion]:
        """Generate patch for buffer overflow vulnerability."""
        sink = evidence.get('sink', '')
        location = evidence.get('location', '')
        
        if ':' in location:
            file, line = location.rsplit(':', 1)
            line = int(line)
        else:
            return None
        
        # Get original code
        original_code = ""
        if source_lines and line <= len(source_lines):
            original_code = source_lines[line - 1]
        else:
            # Try to reconstruct from taint path
            taint_path = evidence.get('taint_path', [])
            if taint_path:
                original_code = taint_path[-1].split(' ', 2)[-1] if len(taint_path[-1].split(' ')) > 2 else ""
        
        # Generate patched code
        patched_code, explanation = self._apply_safe_replacement(sink, original_code, evidence)
        
        if not patched_code:
            return None
        
        # Generate diff
        diff = self._generate_diff(original_code, patched_code, file, line)
        
        return PatchSuggestion(
            vuln_type='BUFFER_OVERFLOW',
            file=file,
            line=line,
            original_code=original_code.strip(),
            patched_code=patched_code.strip(),
            explanation=explanation,
            diff=diff,
            confidence=0.85,
            cwe_reference=evidence.get('cwe_id', 'CWE-787')
        )

    def _apply_safe_replacement(self, sink: str, original_code: str, 
                                 evidence: Dict) -> Tuple[str, str]:
        """Apply safe replacement pattern for a sink."""
        if sink not in self.SAFE_REPLACEMENTS:
            return "", ""
        
        replacement_info = self.SAFE_REPLACEMENTS[sink]
        pattern = replacement_info['pattern']
        template = replacement_info['replacement']
        explanation = replacement_info['explanation']
        
        match = re.search(pattern, original_code)
        if not match:
            return "", ""
        
        # Extract captured groups
        groups = match.groups()
        
        if sink == 'strcpy':
            dest = groups[0]
            src = groups[1].strip()
            patched = template.format(dest=dest, src=src)
        elif sink == 'strcat':
            dest = groups[0]
            src = groups[1].strip()
            patched = template.format(dest=dest, src=src)
        elif sink == 'gets':
            dest = groups[0]
            patched = template.format(dest=dest)
        elif sink == 'sprintf':
            dest = groups[0]
            format_and_args = groups[1].strip()
            patched = template.format(dest=dest, format_and_args=format_and_args)
        elif sink == 'vsprintf':
            dest = groups[0]
            fmt = groups[1].strip()
            args = groups[2].strip()
            patched = template.format(dest=dest, format=fmt, args=args)
        elif sink == 'scanf':
            fmt = groups[0]
            args = groups[1].strip()
            # Add width specifiers to %s
            safe_fmt = re.sub(r'%s', '%255s', fmt)
            patched = template.format(format_safe=safe_fmt, args=args)
        else:
            return "", ""
        
        # Preserve indentation
        indent = len(original_code) - len(original_code.lstrip())
        patched = ' ' * indent + patched
        
        return patched, explanation

    def _generate_uaf_patch(self, evidence: Dict, 
                            source_lines: List[str] = None) -> Optional[PatchSuggestion]:
        """Generate patch for use-after-free vulnerability."""
        pointer = evidence.get('pointer', '')
        free_site = evidence.get('free_site', '')
        use_site = evidence.get('use_site', '')
        
        if not free_site or not use_site:
            return None
        
        # Parse locations
        free_parts = free_site.split(':')
        if len(free_parts) >= 2:
            file = free_parts[0]
            free_line = int(free_parts[1].split()[0])
        else:
            return None
        
        # Generate patch: add NULL assignment after free
        original_code = f"free({pointer});"
        patched_code = f"free({pointer});\n    {pointer} = NULL;"
        
        explanation = self.UAF_FIXES['null_after_free']['explanation']
        diff = self._generate_diff(original_code, patched_code, file, free_line)
        
        return PatchSuggestion(
            vuln_type='USE_AFTER_FREE',
            file=file,
            line=free_line,
            original_code=original_code,
            patched_code=patched_code,
            explanation=explanation,
            diff=diff,
            confidence=0.80,
            cwe_reference='CWE-416'
        )

    def _generate_integer_overflow_patch(self, evidence: Dict,
                                          source_lines: List[str] = None) -> Optional[PatchSuggestion]:
        """Generate patch for integer overflow vulnerability."""
        expression = evidence.get('expression', '')
        location = evidence.get('location', '')
        used_in = evidence.get('used_in', '')
        
        if ':' in location:
            file, line = location.rsplit(':', 1)
            line = int(line)
        else:
            return None
        
        # Parse the multiplication expression (handle sizeof and other function calls)
        if '*' in expression:
            # Find multiplication not inside parentheses
            op1, op2 = self._split_multiplication(expression)
            if op1 and op2:
                original_code = used_in
                
                # Generate safe multiplication check
                fix_template = self.INT_OVERFLOW_FIXES['safe_multiply']
                patched_code = fix_template['template'].format(
                    op1=op1, op2=op2, original=original_code
                )
                
                explanation = fix_template['explanation']
                diff = self._generate_diff(original_code, patched_code, file, line)
                
                return PatchSuggestion(
                    vuln_type='INTEGER_OVERFLOW',
                    file=file,
                    line=line,
                    original_code=original_code,
                    patched_code=patched_code,
                    explanation=explanation,
                    diff=diff,
                    confidence=0.75,
                    cwe_reference='CWE-190'
                )
        
        return None

    def _split_multiplication(self, expr: str) -> tuple:
        """Split multiplication expression at top-level * operator."""
        depth = 0
        for i, char in enumerate(expr):
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            elif char == '*' and depth == 0:
                op1 = expr[:i].strip()
                op2 = expr[i+1:].strip()
                return (op1, op2)
        return (None, None)

    def _generate_diff(self, original: str, patched: str, filename: str, line: int) -> str:
        """Generate unified diff format."""
        original_lines = [original + '\n'] if original else []
        patched_lines = [patched + '\n'] if patched else []
        
        diff_lines = list(unified_diff(
            original_lines,
            patched_lines,
            fromfile=f'a/{filename}',
            tofile=f'b/{filename}',
            lineterm=''
        ))
        
        return '\n'.join(diff_lines)

    def generate_patches_for_findings(self, findings: List[Dict], 
                                       file_contents: Dict[str, List[str]] = None) -> List[PatchSuggestion]:
        """
        Generate patches for a list of vulnerability findings.
        
        Args:
            findings: List of vulnerability evidence dictionaries
            file_contents: Optional dict mapping filenames to source lines
            
        Returns:
            List of patch suggestions
        """
        self.patches = []
        file_contents = file_contents or {}
        
        for finding in findings:
            location = finding.get('location', '')
            if ':' in location:
                file = location.rsplit(':', 1)[0]
            else:
                file = finding.get('file', '')
            
            source_lines = file_contents.get(file, None)
            
            patch = self.generate_patch(finding, source_lines)
            if patch:
                self.patches.append(patch)
        
        return self.patches

    def get_patch_diff(self, patch: PatchSuggestion) -> str:
        """Get the diff string for a patch."""
        return patch.diff

    def apply_patch_to_content(self, content: str, patch: PatchSuggestion) -> str:
        """
        Apply a patch to file content.
        
        Args:
            content: Original file content
            patch: Patch to apply
            
        Returns:
            Patched file content
        """
        lines = content.split('\n')
        
        if patch.line <= len(lines):
            # Replace the line
            lines[patch.line - 1] = patch.patched_code
        
        return '\n'.join(lines)

    def get_all_patches_json(self) -> List[Dict]:
        """Get all patches as JSON-serializable dicts."""
        return [
            {
                'vuln_type': p.vuln_type,
                'file': p.file,
                'line': p.line,
                'original_code': p.original_code,
                'patched_code': p.patched_code,
                'explanation': p.explanation,
                'diff': p.diff,
                'confidence': p.confidence,
                'cwe_reference': p.cwe_reference
            }
            for p in self.patches
        ]
