"""
Knowledge Retriever Module

Retrieves security knowledge from:
- CWE database
- CERT C Secure Coding guidelines
- Common vulnerability patterns and fixes
"""

import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path


@dataclass
class SecurityKnowledge:
    """A piece of security knowledge."""
    id: str
    title: str
    description: str
    category: str
    severity: str = "MEDIUM"
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    code_examples: Dict[str, str] = field(default_factory=dict)  # bad/good examples
    keywords: List[str] = field(default_factory=list)


class KnowledgeRetriever:
    """
    Retriever for security knowledge based on CWE and CERT C.
    
    Provides grounded explanations and fix suggestions.
    """

    # Built-in CWE knowledge base
    CWE_KNOWLEDGE = {
        'CWE-787': SecurityKnowledge(
            id='CWE-787',
            title='Out-of-bounds Write',
            description='The software writes data past the end, or before the beginning, '
                       'of the intended buffer. This typically occurs when a pointer or '
                       'its index is incremented to a position beyond the bounds of the buffer.',
            category='Memory Safety',
            severity='HIGH',
            remediation='Use bounded string functions (strncpy, snprintf) and always validate '
                       'buffer sizes before writing. Use sizeof() to determine buffer size '
                       'and ensure write operations respect these limits.',
            references=[
                'https://cwe.mitre.org/data/definitions/787.html',
                'CERT C: ARR30-C, STR31-C'
            ],
            code_examples={
                'bad': 'char buf[10];\nstrcpy(buf, user_input);  // No bounds checking',
                'good': 'char buf[10];\nstrncpy(buf, user_input, sizeof(buf) - 1);\nbuf[sizeof(buf) - 1] = \'\\0\';'
            },
            keywords=['buffer overflow', 'out-of-bounds', 'strcpy', 'strcat', 'memcpy', 'write']
        ),
        'CWE-120': SecurityKnowledge(
            id='CWE-120',
            title='Buffer Copy without Checking Size of Input',
            description='The program copies an input buffer to an output buffer without '
                       'verifying that the size of the input buffer is less than the size '
                       'of the output buffer, leading to a buffer overflow.',
            category='Memory Safety',
            severity='HIGH',
            remediation='Always check input size before copying. Use strncpy, snprintf, '
                       'or memcpy with proper size limits. Consider using safer alternatives '
                       'like strlcpy where available.',
            references=[
                'https://cwe.mitre.org/data/definitions/120.html',
                'CERT C: STR31-C'
            ],
            code_examples={
                'bad': 'void copy(char *src) {\n    char dst[256];\n    strcpy(dst, src);\n}',
                'good': 'void copy(char *src) {\n    char dst[256];\n    strncpy(dst, src, sizeof(dst) - 1);\n    dst[sizeof(dst) - 1] = \'\\0\';\n}'
            },
            keywords=['buffer copy', 'strcpy', 'input validation', 'size check']
        ),
        'CWE-416': SecurityKnowledge(
            id='CWE-416',
            title='Use After Free',
            description='Referencing memory after it has been freed can cause a program '
                       'to crash, use unexpected values, or execute code. The use of '
                       'previously freed memory can have any number of adverse consequences.',
            category='Memory Safety',
            severity='HIGH',
            remediation='Set pointers to NULL immediately after freeing. Check for NULL '
                       'before any pointer dereference. Use smart pointers in C++ or '
                       'implement reference counting. Consider using static analysis tools.',
            references=[
                'https://cwe.mitre.org/data/definitions/416.html',
                'CERT C: MEM30-C'
            ],
            code_examples={
                'bad': 'free(ptr);\nptr->data = 0;  // Use after free!',
                'good': 'free(ptr);\nptr = NULL;\n// Any use now will fail-fast with NULL deref'
            },
            keywords=['use after free', 'UAF', 'dangling pointer', 'free', 'memory']
        ),
        'CWE-190': SecurityKnowledge(
            id='CWE-190',
            title='Integer Overflow or Wraparound',
            description='The software performs a calculation that can produce an integer '
                       'overflow or wraparound, when the logic assumes that the resulting '
                       'value will always be larger than the original value.',
            category='Numeric Errors',
            severity='MEDIUM',
            remediation='Check for potential overflow before arithmetic operations. '
                       'Use compiler builtins like __builtin_mul_overflow. Validate '
                       'that integer values are within expected ranges before use in '
                       'memory allocation or array indexing.',
            references=[
                'https://cwe.mitre.org/data/definitions/190.html',
                'CERT C: INT30-C, INT32-C'
            ],
            code_examples={
                'bad': 'size_t size = count * sizeof(int);\nint *arr = malloc(size);  // May overflow!',
                'good': 'if (count > SIZE_MAX / sizeof(int)) {\n    return NULL;  // Overflow would occur\n}\nsize_t size = count * sizeof(int);\nint *arr = malloc(size);'
            },
            keywords=['integer overflow', 'wraparound', 'multiplication', 'allocation', 'size']
        ),
        'CWE-122': SecurityKnowledge(
            id='CWE-122',
            title='Heap-based Buffer Overflow',
            description='A heap overflow condition is a buffer overflow, where the buffer '
                       'that can be overwritten is allocated in the heap portion of memory.',
            category='Memory Safety',
            severity='HIGH',
            remediation='Validate all input sizes before copying to heap buffers. '
                       'Use bounded copy functions. Consider using memory-safe languages '
                       'or allocators with bounds checking.',
            references=[
                'https://cwe.mitre.org/data/definitions/122.html',
                'CERT C: MEM35-C'
            ],
            code_examples={
                'bad': 'char *buf = malloc(100);\nstrcpy(buf, user_input);',
                'good': 'char *buf = malloc(100);\nstrncpy(buf, user_input, 99);\nbuf[99] = \'\\0\';'
            },
            keywords=['heap overflow', 'malloc', 'dynamic allocation', 'buffer overflow']
        ),
        'CWE-125': SecurityKnowledge(
            id='CWE-125',
            title='Out-of-bounds Read',
            description='The software reads data past the end, or before the beginning, '
                       'of the intended buffer.',
            category='Memory Safety',
            severity='MEDIUM',
            remediation='Always validate array indices before use. Use bounded read '
                       'functions. Implement proper length checking on input data.',
            references=[
                'https://cwe.mitre.org/data/definitions/125.html',
                'CERT C: ARR30-C'
            ],
            code_examples={
                'bad': 'int arr[10];\nint val = arr[user_index];  // No bounds check',
                'good': 'int arr[10];\nif (user_index >= 0 && user_index < 10) {\n    int val = arr[user_index];\n}'
            },
            keywords=['out-of-bounds read', 'buffer overread', 'array index']
        )
    }

    # CERT C Secure Coding Rules
    CERT_RULES = {
        'STR31-C': SecurityKnowledge(
            id='STR31-C',
            title='Guarantee that storage for strings has sufficient space for character data and the null terminator',
            description='Copying data to a buffer that is not large enough to hold that data '
                       'results in a buffer overflow. To prevent such errors, either limit '
                       'copies to the size of the destination buffer or ensure the destination '
                       'is large enough to hold the source data.',
            category='Strings (STR)',
            severity='HIGH',
            remediation='Always account for the null terminator when sizing buffers. '
                       'Use strncpy, snprintf, or similar bounded functions. Verify source '
                       'string length before copying.',
            references=[
                'https://wiki.sei.cmu.edu/confluence/display/c/STR31-C'
            ],
            code_examples={
                'bad': 'char buf[BUFSIZE];\nstrcpy(buf, src);',
                'good': 'char buf[BUFSIZE];\nstrncpy(buf, src, BUFSIZE - 1);\nbuf[BUFSIZE - 1] = \'\\0\';'
            },
            keywords=['string', 'buffer', 'null terminator', 'strcpy', 'strncpy']
        ),
        'MEM30-C': SecurityKnowledge(
            id='MEM30-C',
            title='Do not access freed memory',
            description='Evaluating a pointer that has been freed (including passing it to '
                       'a function) is undefined behavior. The program may appear to function '
                       'normally, produce strange results, or crash.',
            category='Memory Management (MEM)',
            severity='HIGH',
            remediation='Set freed pointers to NULL immediately. Use a memory management '
                       'strategy that tracks allocation state. Consider using smart pointers or RAII.',
            references=[
                'https://wiki.sei.cmu.edu/confluence/display/c/MEM30-C'
            ],
            code_examples={
                'bad': 'free(p);\nuse(p);  // Undefined behavior',
                'good': 'free(p);\np = NULL;\nif (p != NULL) use(p);'
            },
            keywords=['free', 'memory', 'use after free', 'dangling pointer']
        ),
        'INT30-C': SecurityKnowledge(
            id='INT30-C',
            title='Ensure that unsigned integer operations do not wrap',
            description='Unsigned integer operations in C can wrap around, leading to '
                       'unexpected values. This can cause security vulnerabilities when '
                       'the result is used in memory allocation or as an array index.',
            category='Integers (INT)',
            severity='MEDIUM',
            remediation='Check for potential wraparound before operations. Use compiler '
                       'builtins for safe arithmetic. Validate input ranges.',
            references=[
                'https://wiki.sei.cmu.edu/confluence/display/c/INT30-C'
            ],
            code_examples={
                'bad': 'unsigned int total = a * b;  // May wrap',
                'good': 'if (b != 0 && a > UINT_MAX / b) error();\nunsigned int total = a * b;'
            },
            keywords=['unsigned', 'integer', 'wrap', 'overflow', 'multiplication']
        ),
        'ARR30-C': SecurityKnowledge(
            id='ARR30-C',
            title='Do not form or use out-of-bounds pointers or array subscripts',
            description='Forming or using a pointer or array subscript that is out of bounds '
                       'results in undefined behavior. Such code can crash, produce wrong results, '
                       'or allow attackers to corrupt memory.',
            category='Arrays (ARR)',
            severity='HIGH',
            remediation='Always validate array indices before use. Ensure pointer arithmetic '
                       'stays within allocated bounds. Use sizeof for array bounds.',
            references=[
                'https://wiki.sei.cmu.edu/confluence/display/c/ARR30-C'
            ],
            code_examples={
                'bad': 'int arr[10];\narr[i] = val;  // i may be out of bounds',
                'good': 'int arr[10];\nif (i >= 0 && i < 10) arr[i] = val;'
            },
            keywords=['array', 'bounds', 'index', 'pointer arithmetic']
        )
    }

    # Common unsafe -> safe function replacements
    SAFE_REPLACEMENTS = {
        'strcpy': {
            'safe': ['strncpy', 'strlcpy', 'strcpy_s'],
            'note': 'Use strncpy with explicit null termination, or strlcpy where available'
        },
        'strcat': {
            'safe': ['strncat', 'strlcat', 'strcat_s'],
            'note': 'Calculate remaining buffer space before concatenation'
        },
        'gets': {
            'safe': ['fgets'],
            'note': 'Always specify maximum buffer size with fgets'
        },
        'sprintf': {
            'safe': ['snprintf', 'sprintf_s'],
            'note': 'Always specify buffer size with snprintf'
        },
        'vsprintf': {
            'safe': ['vsnprintf', 'vsprintf_s'],
            'note': 'Always specify buffer size with vsnprintf'
        },
        'scanf': {
            'safe': ['fgets + sscanf', 'scanf with width specifiers'],
            'note': 'Use width specifiers in format strings or fgets + strtok/sscanf'
        }
    }

    def __init__(self, knowledge_base_path: str = None):
        """
        Initialize the knowledge retriever.
        
        Args:
            knowledge_base_path: Optional path to custom knowledge base
        """
        self.knowledge_base_path = knowledge_base_path
        self.knowledge: Dict[str, SecurityKnowledge] = {}
        self._load_knowledge()

    def _load_knowledge(self) -> None:
        """Load knowledge from built-in and custom sources."""
        # Load built-in CWE knowledge
        self.knowledge.update(self.CWE_KNOWLEDGE)
        
        # Load CERT rules
        self.knowledge.update(self.CERT_RULES)
        
        # Load custom knowledge base if provided
        if self.knowledge_base_path:
            self._load_custom_knowledge(self.knowledge_base_path)

    def _load_custom_knowledge(self, path: str) -> None:
        """Load custom knowledge from directory."""
        kb_path = Path(path)
        if not kb_path.exists():
            return
        
        # Load JSON files
        for json_file in kb_path.glob('*.json'):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    for item in data:
                        knowledge = SecurityKnowledge(**item)
                        self.knowledge[knowledge.id] = knowledge
            except Exception as e:
                print(f"Error loading {json_file}: {e}")

    def retrieve(self, query: str, vuln_type: str = None, 
                 top_k: int = 3) -> List[SecurityKnowledge]:
        """
        Retrieve relevant security knowledge.
        
        Args:
            query: Search query (e.g., "strcpy buffer overflow")
            vuln_type: Optional specific vulnerability type
            top_k: Number of results to return
            
        Returns:
            List of relevant SecurityKnowledge items
        """
        results = []
        query_lower = query.lower()
        query_terms = set(query_lower.split())
        
        for id, knowledge in self.knowledge.items():
            score = self._calculate_relevance(knowledge, query_terms, vuln_type)
            if score > 0:
                results.append((score, knowledge))
        
        # Sort by relevance score
        results.sort(key=lambda x: x[0], reverse=True)
        
        return [k for _, k in results[:top_k]]

    def _calculate_relevance(self, knowledge: SecurityKnowledge, 
                            query_terms: set, vuln_type: str = None) -> float:
        """Calculate relevance score for a knowledge item."""
        score = 0.0
        
        # Check keywords
        knowledge_keywords = set(k.lower() for k in knowledge.keywords)
        keyword_matches = query_terms.intersection(knowledge_keywords)
        score += len(keyword_matches) * 2.0
        
        # Check title
        title_lower = knowledge.title.lower()
        for term in query_terms:
            if term in title_lower:
                score += 1.5
        
        # Check description
        desc_lower = knowledge.description.lower()
        for term in query_terms:
            if term in desc_lower:
                score += 0.5
        
        # Boost if CWE ID matches
        for term in query_terms:
            if term.upper() in knowledge.id.upper():
                score += 5.0
        
        # Boost for matching vulnerability type
        if vuln_type:
            if vuln_type.lower() in knowledge.title.lower():
                score += 3.0
            if vuln_type.lower() in knowledge.category.lower():
                score += 2.0
        
        return score

    def get_by_cwe(self, cwe_id: str) -> Optional[SecurityKnowledge]:
        """Get knowledge by CWE ID."""
        # Normalize ID
        if not cwe_id.upper().startswith('CWE-'):
            cwe_id = f'CWE-{cwe_id}'
        
        return self.knowledge.get(cwe_id.upper())

    def get_by_cert_rule(self, rule_id: str) -> Optional[SecurityKnowledge]:
        """Get knowledge by CERT rule ID."""
        return self.knowledge.get(rule_id.upper())

    def get_safe_replacement(self, unsafe_func: str) -> Optional[Dict]:
        """Get safe replacement suggestion for an unsafe function."""
        return self.SAFE_REPLACEMENTS.get(unsafe_func.lower())

    def generate_explanation(self, evidence: Dict) -> str:
        """
        Generate a grounded explanation for a vulnerability.
        
        Args:
            evidence: Vulnerability evidence dictionary
            
        Returns:
            Explanation text with references
        """
        vuln_type = evidence.get('vuln_type', 'UNKNOWN')
        cwe_id = evidence.get('cwe_id', '')
        sink = evidence.get('sink', '')
        
        # Start with basic explanation
        explanation_parts = []
        
        # Get CWE knowledge
        cwe_knowledge = self.get_by_cwe(cwe_id) if cwe_id else None
        if cwe_knowledge:
            explanation_parts.append(f"**{cwe_knowledge.title}** ({cwe_knowledge.id})")
            explanation_parts.append(f"\n{cwe_knowledge.description}")
        
        # Add vulnerability-specific explanation
        if vuln_type == 'BUFFER_OVERFLOW':
            explanation_parts.append(
                f"\n\nThe use of `{sink}` without proper bounds checking can allow "
                f"an attacker to write data beyond the allocated buffer, potentially "
                f"leading to code execution or denial of service."
            )
        elif vuln_type == 'USE_AFTER_FREE':
            explanation_parts.append(
                "\n\nAccessing memory after it has been freed leads to undefined behavior. "
                "An attacker may be able to control the contents of the freed memory, "
                "potentially leading to arbitrary code execution."
            )
        elif vuln_type == 'INTEGER_OVERFLOW':
            explanation_parts.append(
                "\n\nInteger overflow in size calculations can result in smaller-than-expected "
                "allocations. When the program then writes to this buffer assuming the original "
                "size, a heap buffer overflow occurs."
            )
        
        # Add remediation
        if cwe_knowledge:
            explanation_parts.append(f"\n\n**Remediation:** {cwe_knowledge.remediation}")
        
        # Add safe replacement if applicable
        if sink:
            replacement = self.get_safe_replacement(sink)
            if replacement:
                explanation_parts.append(
                    f"\n\n**Safe Alternative:** Replace `{sink}` with "
                    f"`{replacement['safe'][0]}`. {replacement['note']}"
                )
        
        # Add references
        if cwe_knowledge and cwe_knowledge.references:
            explanation_parts.append("\n\n**References:**")
            for ref in cwe_knowledge.references:
                explanation_parts.append(f"\n- {ref}")
        
        return ''.join(explanation_parts)

    def get_exploit_scenario(self, evidence: Dict) -> str:
        """
        Generate a potential exploit scenario.
        
        Args:
            evidence: Vulnerability evidence
            
        Returns:
            Exploit scenario description
        """
        vuln_type = evidence.get('vuln_type', 'UNKNOWN')
        sink = evidence.get('sink', '')
        input_source = evidence.get('input_source', 'user input')
        
        if vuln_type == 'BUFFER_OVERFLOW':
            return (
                f"An attacker could provide a maliciously crafted {input_source} that exceeds "
                f"the expected buffer size. When this input reaches `{sink}`, it overflows "
                f"the destination buffer. Depending on the memory layout, this could:\n"
                f"1. Overwrite adjacent variables, corrupting program state\n"
                f"2. Overwrite return addresses on the stack, redirecting execution\n"
                f"3. Overwrite function pointers or vtables for code execution"
            )
        elif vuln_type == 'USE_AFTER_FREE':
            return (
                "An attacker could trigger the following sequence:\n"
                "1. Cause the vulnerable pointer to be freed\n"
                "2. Allocate new memory that occupies the freed region\n"
                "3. Control the contents of this new allocation\n"
                "4. Trigger the use-after-free, causing the program to use attacker-controlled data"
            )
        elif vuln_type == 'INTEGER_OVERFLOW':
            return (
                "An attacker could provide size values that cause integer overflow:\n"
                "1. Supply large values for multiplied operands\n"
                "2. The multiplication wraps around to a small value\n"
                "3. A small buffer is allocated\n"
                "4. Subsequent operations write based on original (large) size\n"
                "5. Heap buffer overflow occurs"
            )
        
        return "Exploit scenario not available for this vulnerability type."
