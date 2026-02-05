"""
AST Parser Module

Parses C source code using libclang to extract:
- Function definitions and declarations
- Call graphs
- Variable declarations and usages
- Control flow information
"""

import os
import json
import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set, Tuple
from pathlib import Path

try:
    from clang.cindex import Index, CursorKind, TypeKind, Config
    CLANG_AVAILABLE = True
except ImportError:
    CLANG_AVAILABLE = False


@dataclass
class VariableInfo:
    """Information about a variable declaration."""
    name: str
    var_type: str
    file: str
    line: int
    is_pointer: bool = False
    is_array: bool = False
    array_size: Optional[int] = None
    is_parameter: bool = False


@dataclass
class FunctionInfo:
    """Information about a function."""
    name: str
    file: str
    line: int
    return_type: str
    parameters: List[VariableInfo] = field(default_factory=list)
    local_variables: List[VariableInfo] = field(default_factory=list)
    is_definition: bool = True


@dataclass
class CallInfo:
    """Information about a function call."""
    caller: str
    callee: str
    file: str
    line: int
    arguments: List[str] = field(default_factory=list)


@dataclass
class RepoIndex:
    """Index of a C codebase."""
    files: List[str] = field(default_factory=list)
    functions: List[FunctionInfo] = field(default_factory=list)
    calls: List[CallInfo] = field(default_factory=list)
    variables: List[VariableInfo] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "files": self.files,
            "functions": [
                {
                    "name": f.name,
                    "file": f.file,
                    "line": f.line,
                    "return_type": f.return_type,
                    "parameters": [asdict(p) for p in f.parameters],
                    "is_definition": f.is_definition
                }
                for f in self.functions
            ],
            "calls": [
                {
                    "caller": c.caller,
                    "callee": c.callee,
                    "file": c.file,
                    "line": c.line,
                    "arguments": c.arguments
                }
                for c in self.calls
            ]
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class ASTParser:
    """
    Parser for C source code using libclang or regex fallback.
    
    Extracts structural information including:
    - Function definitions and declarations
    - Call graphs
    - Variable declarations
    - Buffer allocations
    """

    # Dangerous sinks to track
    DANGEROUS_SINKS = {
        'strcpy', 'strcat', 'gets', 'sprintf', 'vsprintf',
        'memcpy', 'memmove', 'strncpy', 'strncat',
        'scanf', 'fscanf', 'sscanf',
        'malloc', 'calloc', 'realloc', 'free'
    }

    def __init__(self, clang_lib_path: Optional[str] = None):
        """
        Initialize the AST parser.
        
        Args:
            clang_lib_path: Optional path to libclang library
        """
        self.use_clang = CLANG_AVAILABLE
        self.index = None
        
        if CLANG_AVAILABLE:
            if clang_lib_path:
                Config.set_library_file(clang_lib_path)
            try:
                self.index = Index.create()
            except Exception as e:
                print(f"Warning: Could not initialize clang: {e}")
                self.use_clang = False
        
        self.current_function: Optional[str] = None
        self.repo_index = RepoIndex()

    def parse_file(self, filepath: str) -> None:
        """
        Parse a single C source file.
        
        Args:
            filepath: Path to the C source file
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        rel_path = os.path.basename(filepath)
        if rel_path not in self.repo_index.files:
            self.repo_index.files.append(rel_path)

        if self.use_clang and self.index:
            self._parse_with_clang(filepath)
        else:
            self._parse_with_regex(filepath)

    def _parse_with_clang(self, filepath: str) -> None:
        """Parse using libclang."""
        try:
            tu = self.index.parse(filepath, args=['-std=c11'])
            self._visit_clang_node(tu.cursor, filepath)
        except Exception as e:
            print(f"Clang parsing failed, falling back to regex: {e}")
            self._parse_with_regex(filepath)

    def _visit_clang_node(self, node, filepath: str, current_func: str = None) -> None:
        """Recursively visit clang AST nodes."""
        if node.location.file and str(node.location.file) != filepath:
            return

        if node.kind == CursorKind.FUNCTION_DECL:
            func_info = FunctionInfo(
                name=node.spelling,
                file=os.path.basename(filepath),
                line=node.location.line,
                return_type=node.result_type.spelling,
                is_definition=node.is_definition()
            )
            
            for arg in node.get_arguments():
                var_info = VariableInfo(
                    name=arg.spelling,
                    var_type=arg.type.spelling,
                    file=os.path.basename(filepath),
                    line=arg.location.line,
                    is_pointer='*' in arg.type.spelling,
                    is_array=arg.type.kind == TypeKind.CONSTANTARRAY,
                    is_parameter=True
                )
                func_info.parameters.append(var_info)
            
            self.repo_index.functions.append(func_info)
            current_func = node.spelling

        elif node.kind == CursorKind.CALL_EXPR:
            if current_func:
                call_info = CallInfo(
                    caller=current_func,
                    callee=node.spelling,
                    file=os.path.basename(filepath),
                    line=node.location.line,
                    arguments=[arg.spelling for arg in node.get_arguments()]
                )
                self.repo_index.calls.append(call_info)

        elif node.kind == CursorKind.VAR_DECL:
            var_info = VariableInfo(
                name=node.spelling,
                var_type=node.type.spelling,
                file=os.path.basename(filepath),
                line=node.location.line,
                is_pointer='*' in node.type.spelling,
                is_array=node.type.kind == TypeKind.CONSTANTARRAY
            )
            if var_info.is_array:
                var_info.array_size = node.type.get_array_size()
            self.repo_index.variables.append(var_info)

        for child in node.get_children():
            self._visit_clang_node(child, filepath, current_func)

    def _parse_with_regex(self, filepath: str) -> None:
        """Fallback parsing using regex patterns."""
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')

        rel_path = os.path.basename(filepath)
        
        # Parse functions
        func_pattern = r'^\s*(\w+(?:\s*\*)*)\s+(\w+)\s*\(([^)]*)\)\s*{'
        for i, line in enumerate(lines, 1):
            match = re.match(func_pattern, line)
            if match:
                return_type = match.group(1).strip()
                func_name = match.group(2)
                params_str = match.group(3)
                
                func_info = FunctionInfo(
                    name=func_name,
                    file=rel_path,
                    line=i,
                    return_type=return_type
                )
                
                # Parse parameters
                if params_str.strip() and params_str.strip() != 'void':
                    for param in params_str.split(','):
                        param = param.strip()
                        if param:
                            parts = param.rsplit(' ', 1)
                            if len(parts) == 2:
                                ptype, pname = parts
                                pname = pname.strip('*').strip()
                                func_info.parameters.append(VariableInfo(
                                    name=pname,
                                    var_type=ptype,
                                    file=rel_path,
                                    line=i,
                                    is_pointer='*' in param,
                                    is_parameter=True
                                ))
                
                self.repo_index.functions.append(func_info)
                self.current_function = func_name

        # Parse function calls
        call_pattern = r'(\w+)\s*\(([^)]*)\)'
        current_func = None
        
        for i, line in enumerate(lines, 1):
            # Track current function
            func_match = re.match(func_pattern, line)
            if func_match:
                current_func = func_match.group(2)
            
            # Find function calls
            for match in re.finditer(call_pattern, line):
                callee = match.group(1)
                args_str = match.group(2)
                
                # Skip keywords and type casts
                if callee in ['if', 'while', 'for', 'switch', 'return', 'sizeof']:
                    continue
                
                if current_func and current_func != callee:
                    args = [a.strip() for a in args_str.split(',') if a.strip()]
                    call_info = CallInfo(
                        caller=current_func,
                        callee=callee,
                        file=rel_path,
                        line=i,
                        arguments=args
                    )
                    self.repo_index.calls.append(call_info)

        # Parse variable declarations
        var_pattern = r'^\s*(\w+(?:\s*\*)*)\s+(\w+)(?:\[(\d+)\])?\s*[;=]'
        for i, line in enumerate(lines, 1):
            match = re.match(var_pattern, line)
            if match:
                var_type = match.group(1).strip()
                var_name = match.group(2)
                array_size = match.group(3)
                
                var_info = VariableInfo(
                    name=var_name,
                    var_type=var_type,
                    file=rel_path,
                    line=i,
                    is_pointer='*' in var_type,
                    is_array=array_size is not None,
                    array_size=int(array_size) if array_size else None
                )
                self.repo_index.variables.append(var_info)

    def parse_directory(self, dirpath: str, recursive: bool = True) -> None:
        """
        Parse all C files in a directory.
        
        Args:
            dirpath: Path to directory
            recursive: Whether to search recursively
        """
        if not os.path.isdir(dirpath):
            raise NotADirectoryError(f"Not a directory: {dirpath}")

        c_extensions = {'.c', '.h'}
        
        if recursive:
            for root, _, files in os.walk(dirpath):
                for file in files:
                    if Path(file).suffix in c_extensions:
                        filepath = os.path.join(root, file)
                        try:
                            self.parse_file(filepath)
                        except Exception as e:
                            print(f"Error parsing {filepath}: {e}")
        else:
            for file in os.listdir(dirpath):
                if Path(file).suffix in c_extensions:
                    filepath = os.path.join(dirpath, file)
                    try:
                        self.parse_file(filepath)
                    except Exception as e:
                        print(f"Error parsing {filepath}: {e}")

    def get_dangerous_calls(self) -> List[CallInfo]:
        """Get all calls to dangerous sink functions."""
        return [
            call for call in self.repo_index.calls
            if call.callee in self.DANGEROUS_SINKS
        ]

    def get_function_by_name(self, name: str) -> Optional[FunctionInfo]:
        """Get function info by name."""
        for func in self.repo_index.functions:
            if func.name == name:
                return func
        return None

    def get_call_graph(self) -> Dict[str, Set[str]]:
        """Build a call graph from parsed data."""
        graph = {}
        for call in self.repo_index.calls:
            if call.caller not in graph:
                graph[call.caller] = set()
            graph[call.caller].add(call.callee)
        return graph

    def get_callers(self, function_name: str) -> List[str]:
        """Get all functions that call the given function."""
        return list(set(
            call.caller for call in self.repo_index.calls
            if call.callee == function_name
        ))

    def save_index(self, output_path: str) -> None:
        """Save the repo index to a JSON file."""
        with open(output_path, 'w') as f:
            f.write(self.repo_index.to_json())

    def get_index(self) -> RepoIndex:
        """Get the current repo index."""
        return self.repo_index
