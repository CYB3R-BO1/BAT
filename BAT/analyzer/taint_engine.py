"""
Taint Analysis Engine

Performs taint tracking to identify data flows from untrusted sources
to dangerous sinks. Used primarily for buffer overflow detection.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from enum import Enum


class TaintType(Enum):
    """Types of taint sources."""
    USER_INPUT = "user_input"
    FILE_INPUT = "file_input"
    NETWORK_INPUT = "network_input"
    ENVIRONMENT = "environment"
    UNKNOWN = "unknown"


@dataclass
class TaintSource:
    """Represents a source of tainted data."""
    name: str
    source_type: TaintType
    file: str
    line: int
    function: str = ""
    description: str = ""


@dataclass
class TaintSink:
    """Represents a dangerous sink."""
    name: str
    file: str
    line: int
    function: str
    sink_type: str
    arguments: List[str] = field(default_factory=list)
    vulnerable_arg_indices: List[int] = field(default_factory=list)


@dataclass
class TaintFlow:
    """Represents a flow of tainted data from source to sink."""
    source: TaintSource
    sink: TaintSink
    path: List[Tuple[str, int, str]] = field(default_factory=list)  # (file, line, description)
    variables: List[str] = field(default_factory=list)


class TaintEngine:
    """
    Engine for performing taint analysis on C code.
    
    Tracks data flow from sources (user input, files, network)
    to sinks (dangerous functions like strcpy, sprintf, etc.)
    """

    # Known taint sources
    TAINT_SOURCES = {
        # User input functions
        'argv': TaintType.USER_INPUT,
        'gets': TaintType.USER_INPUT,
        'fgets': TaintType.FILE_INPUT,
        'scanf': TaintType.USER_INPUT,
        'fscanf': TaintType.FILE_INPUT,
        'sscanf': TaintType.USER_INPUT,
        'read': TaintType.FILE_INPUT,
        'fread': TaintType.FILE_INPUT,
        'getc': TaintType.FILE_INPUT,
        'fgetc': TaintType.FILE_INPUT,
        'getchar': TaintType.USER_INPUT,
        'getenv': TaintType.ENVIRONMENT,
        'recv': TaintType.NETWORK_INPUT,
        'recvfrom': TaintType.NETWORK_INPUT,
    }

    # Dangerous sinks and their vulnerable argument positions
    DANGEROUS_SINKS = {
        'strcpy': {'type': 'buffer_overflow', 'vuln_args': [1]},  # src is arg 1
        'strncpy': {'type': 'buffer_overflow', 'vuln_args': [1]},
        'strcat': {'type': 'buffer_overflow', 'vuln_args': [1]},
        'strncat': {'type': 'buffer_overflow', 'vuln_args': [1]},
        'sprintf': {'type': 'buffer_overflow', 'vuln_args': [1, 2, 3, 4]},
        'vsprintf': {'type': 'buffer_overflow', 'vuln_args': [1, 2, 3, 4]},
        'gets': {'type': 'buffer_overflow', 'vuln_args': [0]},
        'memcpy': {'type': 'buffer_overflow', 'vuln_args': [1]},
        'memmove': {'type': 'buffer_overflow', 'vuln_args': [1]},
        'scanf': {'type': 'buffer_overflow', 'vuln_args': [1, 2, 3, 4]},
        'fscanf': {'type': 'buffer_overflow', 'vuln_args': [2, 3, 4, 5]},
        'sscanf': {'type': 'buffer_overflow', 'vuln_args': [2, 3, 4, 5]},
    }

    def __init__(self):
        """Initialize the taint engine."""
        self.taint_sources: List[TaintSource] = []
        self.taint_sinks: List[TaintSink] = []
        self.tainted_variables: Dict[str, TaintSource] = {}  # var_name -> source
        self.taint_flows: List[TaintFlow] = []
        self.variable_assignments: Dict[str, List[Tuple[str, int, str]]] = {}  # var -> [(file, line, from_var)]

    def analyze_file(self, filepath: str) -> None:
        """
        Analyze a C file for taint sources and sinks.
        
        Args:
            filepath: Path to C source file
        """
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')

        filename = filepath.split('/')[-1].split('\\')[-1]
        current_function = ""

        for line_num, line in enumerate(lines, 1):
            # Track current function
            func_match = re.match(r'^\s*\w+(?:\s*\*)*\s+(\w+)\s*\([^)]*\)\s*{', line)
            if func_match:
                current_function = func_match.group(1)

            # Check for main function with argv
            if 'main' in line and 'argv' in line:
                self._add_taint_source('argv', TaintType.USER_INPUT, filename, line_num, 'main')

            # Find taint sources
            for source_name, source_type in self.TAINT_SOURCES.items():
                if source_name in line and source_name != 'argv':
                    self._add_taint_source(source_name, source_type, filename, line_num, current_function)
                    self._extract_tainted_variable(line, source_name, filename, line_num)

            # Find dangerous sinks
            for sink_name, sink_info in self.DANGEROUS_SINKS.items():
                if re.search(rf'\b{sink_name}\s*\(', line):
                    args = self._extract_call_arguments(line, sink_name)
                    sink = TaintSink(
                        name=sink_name,
                        file=filename,
                        line=line_num,
                        function=current_function,
                        sink_type=sink_info['type'],
                        arguments=args,
                        vulnerable_arg_indices=sink_info['vuln_args']
                    )
                    self.taint_sinks.append(sink)

            # Track variable assignments
            self._track_assignments(line, filename, line_num)

    def _add_taint_source(self, name: str, source_type: TaintType, file: str, 
                          line: int, function: str) -> None:
        """Add a taint source."""
        source = TaintSource(
            name=name,
            source_type=source_type,
            file=file,
            line=line,
            function=function
        )
        self.taint_sources.append(source)

    def _extract_tainted_variable(self, line: str, source_name: str, 
                                   file: str, line_num: int) -> None:
        """Extract the variable that receives tainted data."""
        # Pattern for assignment: var = source(...)
        assign_pattern = rf'(\w+)\s*=\s*{source_name}\s*\('
        match = re.search(assign_pattern, line)
        if match:
            var_name = match.group(1)
            self.tainted_variables[var_name] = self.taint_sources[-1]

        # Pattern for scanf-like: source(..., &var)
        scanf_pattern = rf'{source_name}\s*\([^)]*&(\w+)'
        match = re.search(scanf_pattern, line)
        if match:
            var_name = match.group(1)
            self.tainted_variables[var_name] = self.taint_sources[-1]

        # Pattern for fgets: source(var, ...)
        fgets_pattern = rf'{source_name}\s*\((\w+)'
        if source_name in ['fgets', 'gets', 'read', 'fread', 'recv']:
            match = re.search(fgets_pattern, line)
            if match:
                var_name = match.group(1)
                self.tainted_variables[var_name] = self.taint_sources[-1]

    def _extract_call_arguments(self, line: str, func_name: str) -> List[str]:
        """Extract arguments from a function call."""
        pattern = rf'{func_name}\s*\(([^)]*)\)'
        match = re.search(pattern, line)
        if match:
            args_str = match.group(1)
            # Simple splitting, doesn't handle nested calls perfectly
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
        return []

    def _track_assignments(self, line: str, file: str, line_num: int) -> None:
        """Track variable assignments for taint propagation."""
        # Pattern: var = other_var or var = func(other_var)
        assign_pattern = r'(\w+)\s*=\s*(.+);'
        match = re.search(assign_pattern, line)
        if match:
            target_var = match.group(1)
            rhs = match.group(2)
            
            # Check if RHS contains any tainted variable
            # Create a copy of keys to avoid modifying dict during iteration
            for tainted_var in list(self.tainted_variables.keys()):
                if re.search(rf'\b{tainted_var}\b', rhs):
                    if target_var not in self.variable_assignments:
                        self.variable_assignments[target_var] = []
                    self.variable_assignments[target_var].append((file, line_num, tainted_var))
                    # Propagate taint
                    self.tainted_variables[target_var] = self.tainted_variables[tainted_var]

    def compute_taint_flows(self) -> List[TaintFlow]:
        """
        Compute all taint flows from sources to sinks.
        
        Returns:
            List of TaintFlow objects representing source-to-sink paths
        """
        self.taint_flows = []

        for sink in self.taint_sinks:
            # Check each argument of the sink
            for i, arg in enumerate(sink.arguments):
                if i in sink.vulnerable_arg_indices or not sink.vulnerable_arg_indices:
                    # Extract variable names from argument
                    var_names = re.findall(r'\b(\w+)\b', arg)
                    
                    for var_name in var_names:
                        if var_name in self.tainted_variables:
                            source = self.tainted_variables[var_name]
                            path = self._build_taint_path(source, sink, var_name)
                            
                            flow = TaintFlow(
                                source=source,
                                sink=sink,
                                path=path,
                                variables=[var_name]
                            )
                            self.taint_flows.append(flow)

        return self.taint_flows

    def _build_taint_path(self, source: TaintSource, sink: TaintSink, 
                          var_name: str) -> List[Tuple[str, int, str]]:
        """Build the path from source to sink."""
        path = [(source.file, source.line, f"Source: {source.name}")]
        
        # Add intermediate assignments
        if var_name in self.variable_assignments:
            for file, line, from_var in self.variable_assignments[var_name]:
                path.append((file, line, f"Assignment from {from_var}"))
        
        path.append((sink.file, sink.line, f"Sink: {sink.name}({', '.join(sink.arguments)})"))
        
        return path

    def get_flows_to_sink(self, sink_name: str) -> List[TaintFlow]:
        """Get all taint flows to a specific sink function."""
        return [flow for flow in self.taint_flows if flow.sink.name == sink_name]

    def is_variable_tainted(self, var_name: str) -> bool:
        """Check if a variable is tainted."""
        return var_name in self.tainted_variables

    def get_taint_source(self, var_name: str) -> Optional[TaintSource]:
        """Get the taint source for a variable."""
        return self.tainted_variables.get(var_name)

    def analyze_argv_propagation(self, lines: List[str], filename: str) -> None:
        """
        Special handling for argv propagation in main function.
        
        Args:
            lines: Source code lines
            filename: Name of the file
        """
        in_main = False
        for line_num, line in enumerate(lines, 1):
            if 'int main' in line:
                in_main = True
                # Mark argv as tainted
                if 'argv' in line:
                    source = TaintSource(
                        name='argv',
                        source_type=TaintType.USER_INPUT,
                        file=filename,
                        line=line_num,
                        function='main'
                    )
                    self.taint_sources.append(source)
                    self.tainted_variables['argv'] = source
                continue
            
            if in_main:
                # Track argv[n] assignments
                argv_pattern = r'(\w+)\s*=\s*argv\[(\d+)\]'
                match = re.search(argv_pattern, line)
                if match:
                    var_name = match.group(1)
                    self.tainted_variables[var_name] = self.tainted_variables.get('argv')
                    if var_name not in self.variable_assignments:
                        self.variable_assignments[var_name] = []
                    self.variable_assignments[var_name].append((filename, line_num, 'argv'))

    def get_evidence_for_flow(self, flow: TaintFlow) -> Dict:
        """
        Generate evidence object for a taint flow.
        
        Args:
            flow: TaintFlow to generate evidence for
            
        Returns:
            Evidence dictionary
        """
        return {
            "vuln_type": "BUFFER_OVERFLOW",
            "sink": flow.sink.name,
            "location": f"{flow.sink.file}:{flow.sink.line}",
            "input_source": flow.source.name,
            "source_type": flow.source.source_type.value,
            "bounds_check": False,  # Would need more analysis
            "taint_path": [
                f"{file}:{line} {desc}" for file, line, desc in flow.path
            ],
            "confidence": self._calculate_confidence(flow)
        }

    def _calculate_confidence(self, flow: TaintFlow) -> float:
        """Calculate confidence score for a taint flow."""
        confidence = 0.7  # Base confidence
        
        # Higher confidence for known dangerous patterns
        if flow.source.source_type == TaintType.USER_INPUT:
            confidence += 0.15
        
        # Higher confidence for direct flows (shorter path)
        if len(flow.path) <= 3:
            confidence += 0.1
        
        # Higher confidence for certain sinks
        dangerous_sinks = {'strcpy', 'gets', 'sprintf'}
        if flow.sink.name in dangerous_sinks:
            confidence += 0.05
        
        return min(confidence, 1.0)
