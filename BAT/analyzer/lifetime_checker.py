"""
Lifetime Checker Module

Detects Use-After-Free (UAF) vulnerabilities by tracking pointer lifetimes:
- Allocation sites
- Free sites
- Dereference after free
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from enum import Enum


class PointerState(Enum):
    """State of a pointer."""
    UNINITIALIZED = "uninitialized"
    ALLOCATED = "allocated"
    FREED = "freed"
    REASSIGNED = "reassigned"


@dataclass
class LifetimeEvent:
    """An event in the lifetime of a pointer."""
    event_type: str  # 'alloc', 'free', 'use', 'assign'
    pointer: str
    file: str
    line: int
    function: str
    expression: str = ""


@dataclass
class PointerInfo:
    """Information about a tracked pointer."""
    name: str
    state: PointerState
    alloc_site: Optional[Tuple[str, int]] = None  # (file, line)
    free_site: Optional[Tuple[str, int]] = None
    events: List[LifetimeEvent] = field(default_factory=list)
    aliases: Set[str] = field(default_factory=set)


@dataclass
class UAFEvidence:
    """Evidence for a Use-After-Free vulnerability."""
    pointer: str
    alloc_site: str
    free_site: str
    use_site: str
    function: str
    lifetime_violation: bool
    events: List[Dict] = field(default_factory=list)
    confidence: float = 0.0


class LifetimeChecker:
    """
    Checker for Use-After-Free vulnerabilities.
    
    Tracks pointer lifetimes through:
    - malloc/calloc/realloc allocations
    - free calls
    - Dereferences and uses
    """

    ALLOC_FUNCTIONS = {'malloc', 'calloc', 'realloc', 'strdup', 'strndup'}
    FREE_FUNCTIONS = {'free'}
    
    def __init__(self):
        """Initialize the lifetime checker."""
        self.pointers: Dict[str, PointerInfo] = {}
        self.events: List[LifetimeEvent] = []
        self.uaf_candidates: List[UAFEvidence] = []
        self.current_function = ""
        self.function_scopes: Dict[str, Set[str]] = {}  # function -> local pointers

    def analyze_file(self, filepath: str) -> List[UAFEvidence]:
        """
        Analyze a C file for Use-After-Free vulnerabilities.
        
        Args:
            filepath: Path to C source file
            
        Returns:
            List of UAF evidence objects
        """
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')

        filename = filepath.split('/')[-1].split('\\')[-1]
        self._analyze_lines(lines, filename)
        
        return self.detect_uaf()

    def _analyze_lines(self, lines: List[str], filename: str) -> None:
        """Analyze source lines for lifetime events."""
        brace_depth = 0
        
        for line_num, line in enumerate(lines, 1):
            # Track function scope
            func_match = re.match(r'^\s*\w+(?:\s*\*)*\s+(\w+)\s*\([^)]*\)\s*{?', line)
            if func_match and '{' in line:
                self.current_function = func_match.group(1)
                self.function_scopes[self.current_function] = set()
                brace_depth = 1
                continue
            
            # Track brace depth for scope
            brace_depth += line.count('{') - line.count('}')
            if brace_depth <= 0 and self.current_function:
                self.current_function = ""

            # Check for allocations
            self._check_allocation(line, filename, line_num)
            
            # Check for frees
            self._check_free(line, filename, line_num)
            
            # Check for uses/dereferences
            self._check_use(line, filename, line_num)
            
            # Check for pointer assignments (aliasing)
            self._check_assignment(line, filename, line_num)

    def _check_allocation(self, line: str, file: str, line_num: int) -> None:
        """Check for pointer allocation."""
        for alloc_func in self.ALLOC_FUNCTIONS:
            # Pattern: ptr = malloc(...) or type *ptr = malloc(...)
            pattern = rf'(\w+)\s*=\s*(?:\([^)]*\)\s*)?{alloc_func}\s*\('
            match = re.search(pattern, line)
            if match:
                ptr_name = match.group(1)
                
                # Also check for declaration: type *ptr = malloc
                decl_pattern = rf'\*\s*(\w+)\s*=\s*(?:\([^)]*\)\s*)?{alloc_func}\s*\('
                decl_match = re.search(decl_pattern, line)
                if decl_match:
                    ptr_name = decl_match.group(1)
                
                event = LifetimeEvent(
                    event_type='alloc',
                    pointer=ptr_name,
                    file=file,
                    line=line_num,
                    function=self.current_function,
                    expression=line.strip()
                )
                self.events.append(event)
                
                # Update pointer info
                if ptr_name not in self.pointers:
                    self.pointers[ptr_name] = PointerInfo(
                        name=ptr_name,
                        state=PointerState.ALLOCATED
                    )
                else:
                    self.pointers[ptr_name].state = PointerState.ALLOCATED
                
                self.pointers[ptr_name].alloc_site = (file, line_num)
                self.pointers[ptr_name].events.append(event)
                self.pointers[ptr_name].free_site = None  # Reset free site on reallocation
                
                if self.current_function:
                    self.function_scopes.setdefault(self.current_function, set()).add(ptr_name)

    def _check_free(self, line: str, file: str, line_num: int) -> None:
        """Check for pointer free."""
        for free_func in self.FREE_FUNCTIONS:
            pattern = rf'{free_func}\s*\(\s*(\w+)\s*\)'
            match = re.search(pattern, line)
            if match:
                ptr_name = match.group(1)
                
                event = LifetimeEvent(
                    event_type='free',
                    pointer=ptr_name,
                    file=file,
                    line=line_num,
                    function=self.current_function,
                    expression=line.strip()
                )
                self.events.append(event)
                
                if ptr_name in self.pointers:
                    self.pointers[ptr_name].state = PointerState.FREED
                    self.pointers[ptr_name].free_site = (file, line_num)
                    self.pointers[ptr_name].events.append(event)
                    
                    # Mark aliases as freed too
                    for alias in self.pointers[ptr_name].aliases:
                        if alias in self.pointers:
                            self.pointers[alias].state = PointerState.FREED
                            self.pointers[alias].free_site = (file, line_num)
                else:
                    # First time seeing this pointer, record the free
                    self.pointers[ptr_name] = PointerInfo(
                        name=ptr_name,
                        state=PointerState.FREED,
                        free_site=(file, line_num),
                        events=[event]
                    )

    def _check_use(self, line: str, file: str, line_num: int) -> None:
        """Check for pointer dereference/use."""
        for ptr_name, ptr_info in self.pointers.items():
            # Skip if we're on an alloc or free line for this pointer
            if f'malloc' in line or f'free({ptr_name})' in line:
                continue
            if f'{ptr_name} =' in line and 'malloc' in line:
                continue
            
            # Check for dereference: *ptr, ptr->member, ptr[index]
            deref_patterns = [
                rf'\*\s*{ptr_name}\b',           # *ptr
                rf'{ptr_name}\s*->',              # ptr->
                rf'{ptr_name}\s*\[',              # ptr[
                rf'\({ptr_name}\)',               # (ptr) as argument, might be use
            ]
            
            for pattern in deref_patterns:
                if re.search(pattern, line):
                    # Make sure it's not in a malloc/free context
                    if not re.search(rf'free\s*\(\s*{ptr_name}', line):
                        event = LifetimeEvent(
                            event_type='use',
                            pointer=ptr_name,
                            file=file,
                            line=line_num,
                            function=self.current_function,
                            expression=line.strip()
                        )
                        self.events.append(event)
                        ptr_info.events.append(event)
                        break

    def _check_assignment(self, line: str, file: str, line_num: int) -> None:
        """Check for pointer assignments (aliasing)."""
        # Pattern: ptr1 = ptr2 (not malloc/function call)
        pattern = r'(\w+)\s*=\s*(\w+)\s*;'
        match = re.search(pattern, line)
        if match:
            target = match.group(1)
            source = match.group(2)
            
            if source in self.pointers:
                event = LifetimeEvent(
                    event_type='assign',
                    pointer=target,
                    file=file,
                    line=line_num,
                    function=self.current_function,
                    expression=line.strip()
                )
                self.events.append(event)
                
                # Create alias relationship
                if target not in self.pointers:
                    self.pointers[target] = PointerInfo(
                        name=target,
                        state=self.pointers[source].state,
                        alloc_site=self.pointers[source].alloc_site,
                        free_site=self.pointers[source].free_site,
                        events=[event]
                    )
                
                self.pointers[source].aliases.add(target)
                self.pointers[target].aliases.add(source)

    def detect_uaf(self) -> List[UAFEvidence]:
        """
        Detect Use-After-Free vulnerabilities from collected events.
        
        Returns:
            List of UAF evidence objects
        """
        self.uaf_candidates = []
        
        for ptr_name, ptr_info in self.pointers.items():
            if ptr_info.state != PointerState.FREED:
                continue
            if ptr_info.free_site is None:
                continue
            
            free_file, free_line = ptr_info.free_site
            
            # Look for uses after free
            for event in ptr_info.events:
                if event.event_type == 'use':
                    # Check if use is after free (simplistic: line number comparison)
                    if event.file == free_file and event.line > free_line:
                        evidence = self._build_uaf_evidence(ptr_info, event)
                        self.uaf_candidates.append(evidence)
                    elif event.file != free_file:
                        # Cross-file UAF - harder to determine, flag it
                        evidence = self._build_uaf_evidence(ptr_info, event)
                        evidence.confidence = 0.6  # Lower confidence for cross-file
                        self.uaf_candidates.append(evidence)
        
        return self.uaf_candidates

    def _build_uaf_evidence(self, ptr_info: PointerInfo, use_event: LifetimeEvent) -> UAFEvidence:
        """Build UAF evidence object."""
        alloc_site = "unknown"
        if ptr_info.alloc_site:
            alloc_site = f"{ptr_info.alloc_site[0]}:{ptr_info.alloc_site[1]} malloc"
        
        free_site = "unknown"
        if ptr_info.free_site:
            free_site = f"{ptr_info.free_site[0]}:{ptr_info.free_site[1]} free({ptr_info.name})"
        
        use_site = f"{use_event.file}:{use_event.line} {ptr_info.name}"
        
        events_list = []
        for event in ptr_info.events:
            events_list.append({
                "type": event.event_type,
                "location": f"{event.file}:{event.line}",
                "expression": event.expression
            })
        
        return UAFEvidence(
            pointer=ptr_info.name,
            alloc_site=alloc_site,
            free_site=free_site,
            use_site=use_site,
            function=use_event.function,
            lifetime_violation=True,
            events=events_list,
            confidence=self._calculate_confidence(ptr_info, use_event)
        )

    def _calculate_confidence(self, ptr_info: PointerInfo, use_event: LifetimeEvent) -> float:
        """Calculate confidence score for UAF detection."""
        confidence = 0.75
        
        # Higher confidence if we have clear allocation site
        if ptr_info.alloc_site:
            confidence += 0.1
        
        # Higher confidence if free and use are in same function
        free_event = next((e for e in ptr_info.events if e.event_type == 'free'), None)
        if free_event and free_event.function == use_event.function:
            confidence += 0.1
        
        # Lower confidence for aliased pointers
        if ptr_info.aliases:
            confidence -= 0.1
        
        return min(max(confidence, 0.0), 1.0)

    def get_evidence_json(self, evidence: UAFEvidence) -> Dict:
        """Convert UAF evidence to JSON-serializable dict."""
        # Extract location from use_site (format: "file:line pointer_name")
        location = ""
        if evidence.use_site:
            parts = evidence.use_site.split()
            if parts:
                location = parts[0]  # Get "file:line" part
        
        return {
            "vuln_type": "USE_AFTER_FREE",
            "pointer": evidence.pointer,
            "location": location,
            "alloc_site": evidence.alloc_site,
            "free_site": evidence.free_site,
            "use_site": evidence.use_site,
            "function": evidence.function,
            "lifetime_violation": evidence.lifetime_violation,
            "events": evidence.events,
            "confidence": evidence.confidence
        }

    def get_all_evidence(self) -> List[Dict]:
        """Get all UAF evidence as JSON-serializable dicts."""
        return [self.get_evidence_json(e) for e in self.uaf_candidates]

    def reset(self) -> None:
        """Reset the checker state."""
        self.pointers.clear()
        self.events.clear()
        self.uaf_candidates.clear()
        self.current_function = ""
        self.function_scopes.clear()
