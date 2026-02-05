"""
Overflow Checker Module

Detects buffer overflow and integer overflow vulnerabilities:
- Buffer overflows: strcpy, gets, sprintf without bounds checking
- Integer overflows: arithmetic operations that may overflow, especially in size calculations
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum


class OverflowType(Enum):
    """Types of overflow vulnerabilities."""
    BUFFER_OVERFLOW = "buffer_overflow"
    INTEGER_OVERFLOW = "integer_overflow"
    HEAP_OVERFLOW = "heap_overflow"
    STACK_OVERFLOW = "stack_overflow"


@dataclass
class BufferInfo:
    """Information about a buffer."""
    name: str
    size: Optional[int]
    element_type: str
    file: str
    line: int
    is_stack: bool = True
    is_heap: bool = False


@dataclass
class BufferOverflowEvidence:
    """Evidence for a buffer overflow vulnerability."""
    vuln_type: str = "BUFFER_OVERFLOW"
    sink: str = ""
    location: str = ""
    buffer: str = ""
    buffer_size: Optional[int] = None
    input_source: str = ""
    bounds_check: bool = False
    taint_path: List[str] = field(default_factory=list)
    confidence: float = 0.0
    cwe_id: str = "CWE-787"


@dataclass
class IntegerOverflowEvidence:
    """Evidence for an integer overflow vulnerability."""
    vuln_type: str = "INTEGER_OVERFLOW"
    expression: str = ""
    location: str = ""
    used_in: str = ""
    overflow_check: bool = False
    operand_types: List[str] = field(default_factory=list)
    confidence: float = 0.0
    cwe_id: str = "CWE-190"


class OverflowChecker:
    """
    Checker for buffer overflow and integer overflow vulnerabilities.
    """

    # Dangerous functions for buffer overflow
    BUFFER_OVERFLOW_SINKS = {
        'strcpy': {'dest_arg': 0, 'src_arg': 1, 'severity': 'HIGH'},
        'strcat': {'dest_arg': 0, 'src_arg': 1, 'severity': 'HIGH'},
        'gets': {'dest_arg': 0, 'severity': 'CRITICAL'},
        'sprintf': {'dest_arg': 0, 'severity': 'HIGH'},
        'vsprintf': {'dest_arg': 0, 'severity': 'HIGH'},
        'memcpy': {'dest_arg': 0, 'src_arg': 1, 'size_arg': 2, 'severity': 'MEDIUM'},
        'memmove': {'dest_arg': 0, 'src_arg': 1, 'size_arg': 2, 'severity': 'MEDIUM'},
        'scanf': {'severity': 'HIGH'},
        'fscanf': {'severity': 'HIGH'},
        'sscanf': {'severity': 'HIGH'},
    }

    # Safer alternatives
    SAFE_ALTERNATIVES = {
        'strcpy': 'strncpy or strlcpy',
        'strcat': 'strncat or strlcat',
        'gets': 'fgets',
        'sprintf': 'snprintf',
        'vsprintf': 'vsnprintf',
        'scanf': 'fgets + sscanf with width specifiers',
    }

    # Integer operations that may overflow
    INTEGER_OVERFLOW_OPS = {
        '*': 'multiplication',
        '+': 'addition',
        '<<': 'left shift',
    }

    def __init__(self):
        """Initialize the overflow checker."""
        self.buffers: Dict[str, BufferInfo] = {}
        self.buffer_overflow_evidence: List[BufferOverflowEvidence] = []
        self.integer_overflow_evidence: List[IntegerOverflowEvidence] = []
        self.current_function = ""
        self.dangerous_size_vars: Dict[str, Tuple[str, int]] = {}  # var -> (file, line)

    def analyze_file(self, filepath: str) -> Tuple[List[BufferOverflowEvidence], List[IntegerOverflowEvidence]]:
        """
        Analyze a C file for overflow vulnerabilities.
        
        Args:
            filepath: Path to C source file
            
        Returns:
            Tuple of (buffer overflow evidence, integer overflow evidence)
        """
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')

        filename = filepath.split('/')[-1].split('\\')[-1]
        
        # First pass: collect buffer declarations
        self._collect_buffers(lines, filename)
        
        # Second pass: find vulnerabilities
        self._find_vulnerabilities(lines, filename)
        
        return self.buffer_overflow_evidence, self.integer_overflow_evidence

    def _collect_buffers(self, lines: List[str], filename: str) -> None:
        """Collect buffer declarations from source."""
        for line_num, line in enumerate(lines, 1):
            # Stack-allocated arrays: char buf[SIZE], int arr[N]
            array_pattern = r'(\w+)\s+(\w+)\s*\[\s*(\d+)\s*\]'
            match = re.search(array_pattern, line)
            if match:
                elem_type = match.group(1)
                name = match.group(2)
                size = int(match.group(3))
                
                self.buffers[name] = BufferInfo(
                    name=name,
                    size=size,
                    element_type=elem_type,
                    file=filename,
                    line=line_num,
                    is_stack=True
                )
            
            # Heap-allocated buffers: ptr = malloc(SIZE)
            malloc_pattern = r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\d+|\w+(?:\s*\*\s*\w+)?)\s*\)'
            match = re.search(malloc_pattern, line)
            if match:
                name = match.group(1)
                size_expr = match.group(2)
                
                # Try to extract numeric size
                size = None
                if size_expr.isdigit():
                    size = int(size_expr)
                
                self.buffers[name] = BufferInfo(
                    name=name,
                    size=size,
                    element_type='void',
                    file=filename,
                    line=line_num,
                    is_stack=False,
                    is_heap=True
                )

    def _find_vulnerabilities(self, lines: List[str], filename: str) -> None:
        """Find buffer and integer overflow vulnerabilities."""
        for line_num, line in enumerate(lines, 1):
            # Track current function
            func_match = re.match(r'^\s*\w+(?:\s*\*)*\s+(\w+)\s*\([^)]*\)\s*{?', line)
            if func_match:
                self.current_function = func_match.group(1)

            # Check for buffer overflow sinks
            self._check_buffer_overflow_sinks(line, filename, line_num)
            
            # Check for integer overflows
            self._check_integer_overflow(line, filename, line_num)

    def _check_buffer_overflow_sinks(self, line: str, filename: str, line_num: int) -> None:
        """Check for dangerous buffer operations."""
        for sink_name, sink_info in self.BUFFER_OVERFLOW_SINKS.items():
            pattern = rf'\b{sink_name}\s*\(([^)]*)\)'
            match = re.search(pattern, line)
            if match:
                args_str = match.group(1)
                args = self._parse_arguments(args_str)
                
                evidence = self._analyze_sink_call(sink_name, sink_info, args, filename, line_num, line)
                if evidence:
                    self.buffer_overflow_evidence.append(evidence)

    def _analyze_sink_call(self, sink_name: str, sink_info: Dict, args: List[str],
                           filename: str, line_num: int, line: str) -> Optional[BufferOverflowEvidence]:
        """Analyze a sink function call for vulnerabilities."""
        # Special handling for gets - always vulnerable
        if sink_name == 'gets':
            dest = args[0] if args else "unknown"
            buffer_info = self.buffers.get(dest)
            return BufferOverflowEvidence(
                sink=sink_name,
                location=f"{filename}:{line_num}",
                buffer=f"char {dest}[{buffer_info.size if buffer_info else '?'}]",
                buffer_size=buffer_info.size if buffer_info else None,
                input_source="stdin",
                bounds_check=False,
                taint_path=[f"{filename}:{line_num} {sink_name}({dest})"],
                confidence=0.98,
                cwe_id="CWE-120"
            )

        # For strcpy, strcat - check if destination buffer is known
        if sink_name in ['strcpy', 'strcat']:
            if len(args) >= 2:
                dest = args[sink_info['dest_arg']].strip()
                src = args[sink_info['src_arg']].strip()
                
                buffer_info = self.buffers.get(dest)
                
                # Check for bounds checking before this call (simple heuristic)
                has_bounds_check = self._check_for_bounds_check(src, line)
                
                return BufferOverflowEvidence(
                    sink=sink_name,
                    location=f"{filename}:{line_num}",
                    buffer=f"char {dest}[{buffer_info.size if buffer_info else '?'}]",
                    buffer_size=buffer_info.size if buffer_info else None,
                    input_source=src,
                    bounds_check=has_bounds_check,
                    taint_path=[f"{filename}:{line_num} {sink_name}({dest}, {src})"],
                    confidence=0.85 if not has_bounds_check else 0.3
                )

        # For sprintf - always potentially dangerous without snprintf
        if sink_name in ['sprintf', 'vsprintf']:
            if args:
                dest = args[0].strip()
                buffer_info = self.buffers.get(dest)
                
                return BufferOverflowEvidence(
                    sink=sink_name,
                    location=f"{filename}:{line_num}",
                    buffer=f"char {dest}[{buffer_info.size if buffer_info else '?'}]",
                    buffer_size=buffer_info.size if buffer_info else None,
                    input_source="format string",
                    bounds_check=False,
                    taint_path=[f"{filename}:{line_num} {line.strip()}"],
                    confidence=0.80
                )

        # For memcpy - check if size is validated
        if sink_name in ['memcpy', 'memmove']:
            if len(args) >= 3:
                dest = args[0].strip()
                src = args[1].strip()
                size = args[2].strip()
                
                buffer_info = self.buffers.get(dest)
                
                # Check if size is a constant or potentially dangerous
                is_size_safe = self._is_size_safe(size, buffer_info)
                
                if not is_size_safe:
                    return BufferOverflowEvidence(
                        sink=sink_name,
                        location=f"{filename}:{line_num}",
                        buffer=f"{dest}[{buffer_info.size if buffer_info else '?'}]",
                        buffer_size=buffer_info.size if buffer_info else None,
                        input_source=src,
                        bounds_check=False,
                        taint_path=[f"{filename}:{line_num} {sink_name}({dest}, {src}, {size})"],
                        confidence=0.70
                    )

        return None

    def _extract_balanced_parens(self, text: str, start_func: str) -> Optional[str]:
        """Extract content within balanced parentheses after a function name."""
        pattern = rf'{start_func}\s*\('
        match = re.search(pattern, text)
        if not match:
            return None
        
        start_idx = match.end()
        depth = 1
        idx = start_idx
        
        while idx < len(text) and depth > 0:
            if text[idx] == '(':
                depth += 1
            elif text[idx] == ')':
                depth -= 1
            idx += 1
        
        if depth == 0:
            return text[start_idx:idx-1]
        return None

    def _check_integer_overflow(self, line: str, filename: str, line_num: int) -> None:
        """Check for integer overflow vulnerabilities."""
        # Extract malloc argument with balanced parentheses
        size_expr = self._extract_balanced_parens(line, 'malloc')
        if size_expr:
            
            # Check for multiplication in size expression
            if '*' in size_expr:
                parts = size_expr.split('*')
                if len(parts) >= 2:
                    # Check if there's overflow checking before
                    has_overflow_check = self._check_for_overflow_check(size_expr, line)
                    
                    if not has_overflow_check:
                        evidence = IntegerOverflowEvidence(
                            expression=size_expr.strip(),
                            location=f"{filename}:{line_num}",
                            used_in=f"malloc({size_expr.strip()})",
                            overflow_check=False,
                            operand_types=['int', 'int'],  # Simplified
                            confidence=0.75
                        )
                        self.integer_overflow_evidence.append(evidence)
            
            # Check for addition that might overflow
            if '+' in size_expr and not '*' in size_expr:
                has_overflow_check = self._check_for_overflow_check(size_expr, line)
                
                if not has_overflow_check:
                    evidence = IntegerOverflowEvidence(
                        expression=size_expr.strip(),
                        location=f"{filename}:{line_num}",
                        used_in=f"malloc({size_expr.strip()})",
                        overflow_check=False,
                        confidence=0.65
                    )
                    self.integer_overflow_evidence.append(evidence)

        # Check for size calculations stored in variables
        # Match: var = expression (where expression contains *)
        calc_pattern = r'(\w+)\s*=\s*([^;]+\*[^;]+);'
        match = re.search(calc_pattern, line)
        if match:
            result_var = match.group(1)
            full_expr = match.group(2).strip()
            
            # Use balanced split to handle sizeof(type) properly
            op1, op2 = self._split_multiplication_expr(full_expr)
            
            if op1 and op2:
                # Track this as a potentially dangerous size variable
                self.dangerous_size_vars[result_var] = (filename, line_num)
                
                # Check if used in memory allocation context
                if 'size' in result_var.lower() or 'len' in result_var.lower():
                    has_overflow_check = self._check_for_overflow_check(f"{op1} * {op2}", line)
                    
                    if not has_overflow_check:
                        evidence = IntegerOverflowEvidence(
                            expression=f"{op1} * {op2}",
                            location=f"{filename}:{line_num}",
                            used_in=f"{result_var} = {op1} * {op2}",
                            overflow_check=False,
                            confidence=0.60
                        )
                        self.integer_overflow_evidence.append(evidence)
    
    def _split_multiplication_expr(self, expr: str) -> tuple:
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

    def _parse_arguments(self, args_str: str) -> List[str]:
        """Parse function arguments handling nested parentheses."""
        args = []
        depth = 0
        current = ""
        
        for char in args_str:
            if char == '(':
                depth += 1
                current += char
            elif char == ')':
                depth -= 1
                current += char
            elif char == ',' and depth == 0:
                args.append(current.strip())
                current = ""
            else:
                current += char
        
        if current.strip():
            args.append(current.strip())
        
        return args

    def _check_for_bounds_check(self, var: str, line: str) -> bool:
        """Check if there's a bounds check for the variable."""
        # Simple heuristic: look for strlen, sizeof in the line
        bounds_indicators = ['strlen', 'sizeof', 'min(', 'MIN(', '< ', '<= ']
        return any(indicator in line for indicator in bounds_indicators)

    def _check_for_overflow_check(self, expr: str, line: str) -> bool:
        """Check if there's overflow checking for the expression."""
        # Look for common overflow check patterns
        overflow_check_patterns = [
            r'if\s*\([^)]*>\s*SIZE_MAX',
            r'if\s*\([^)]*overflow',
            r'__builtin_mul_overflow',
            r'safe_mult',
            r'checked_mult',
        ]
        return any(re.search(p, line, re.IGNORECASE) for p in overflow_check_patterns)

    def _is_size_safe(self, size: str, buffer_info: Optional[BufferInfo]) -> bool:
        """Check if a size parameter is safe."""
        # If size is sizeof(buffer), it's safe
        if buffer_info and f'sizeof({buffer_info.name})' in size:
            return True
        
        # If size is a small constant, it might be safe
        if size.isdigit() and buffer_info and buffer_info.size:
            if int(size) <= buffer_info.size:
                return True
        
        return False

    def get_buffer_overflow_evidence_json(self, evidence: BufferOverflowEvidence) -> Dict:
        """Convert buffer overflow evidence to JSON-serializable dict."""
        return {
            "vuln_type": evidence.vuln_type,
            "sink": evidence.sink,
            "location": evidence.location,
            "buffer": evidence.buffer,
            "buffer_size": evidence.buffer_size,
            "input_source": evidence.input_source,
            "bounds_check": evidence.bounds_check,
            "taint_path": evidence.taint_path,
            "confidence": evidence.confidence,
            "cwe_id": evidence.cwe_id,
            "safe_alternative": self.SAFE_ALTERNATIVES.get(evidence.sink, "manual bounds checking")
        }

    def get_integer_overflow_evidence_json(self, evidence: IntegerOverflowEvidence) -> Dict:
        """Convert integer overflow evidence to JSON-serializable dict."""
        return {
            "vuln_type": evidence.vuln_type,
            "expression": evidence.expression,
            "location": evidence.location,
            "used_in": evidence.used_in,
            "overflow_check": evidence.overflow_check,
            "operand_types": evidence.operand_types,
            "confidence": evidence.confidence,
            "cwe_id": evidence.cwe_id
        }

    def get_all_evidence(self) -> List[Dict]:
        """Get all overflow evidence as JSON-serializable dicts."""
        evidence = []
        
        for e in self.buffer_overflow_evidence:
            evidence.append(self.get_buffer_overflow_evidence_json(e))
        
        for e in self.integer_overflow_evidence:
            evidence.append(self.get_integer_overflow_evidence_json(e))
        
        return evidence

    def reset(self) -> None:
        """Reset the checker state."""
        self.buffers.clear()
        self.buffer_overflow_evidence.clear()
        self.integer_overflow_evidence.clear()  
        self.current_function = ""
        self.dangerous_size_vars.clear()
