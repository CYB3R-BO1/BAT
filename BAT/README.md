# BAT: Autonomous Vulnerability Investigation for C Memory Bugs

**BAT** (Bug Analysis Tool) is an autonomous vulnerability investigation system for C codebases that detects memory-safety vulnerabilities with evidence-backed findings.

## Features

✅ **Evidence-Based Detection** - Produces valid evidence with source→sink reachability and lifetime traces  
✅ **Multi-Bug Support** - Detects Buffer Overflows (CWE-787), Use-After-Free (CWE-416), and Integer Overflows (CWE-190)  
✅ **Automatic Patch Generation** - Suggests secure code replacements  
✅ **Patch Validation** - Validates patches via compilation  
✅ **Grounded Explanations** - References CWE and CERT C secure coding guidelines  
✅ **Comprehensive Reports** - JSON and Markdown report formats

## Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/BAT.git
cd BAT

# Install dependencies
pip install -r requirements.txt

# Optional: Install libclang for enhanced AST parsing
pip install clang
```

## Quick Start

```bash
# Scan a C project
python -m BAT.cli scan ./vulnerable_project

# Scan a single file
python -m BAT.cli scan vulnerable.c

# Specify output directory
python -m BAT.cli scan ./project --output ./reports

# Skip patch validation
python -m BAT.cli scan ./project --no-validate
```

## Usage

### Basic Scan

```bash
bat scan ./path/to/c/project
```

### Options

| Option          | Description                                 |
| --------------- | ------------------------------------------- |
| `-o, --output`  | Output directory for reports                |
| `-f, --format`  | Output formats: json, md (default: json,md) |
| `--confidence`  | Confidence threshold 0.0-1.0 (default: 0.6) |
| `--compiler`    | C compiler for validation (default: gcc)    |
| `--validate`    | Enable patch validation (default)           |
| `--no-validate` | Skip patch validation                       |
| `-v, --verbose` | Verbose output                              |
| `-q, --quiet`   | Quiet mode                                  |

### Example Output

```
[BAT] Starting investigation of ./vulnerable_project
[BAT] Phase 1: Codebase Reconnaissance
[BAT]   - Parsed 5 files
[BAT]   - Found 12 functions
[BAT]   - Found 45 function calls
[BAT] Phase 2: Hypothesis Generation
[BAT]   - Generated 8 hypotheses
[BAT] Phase 3: Evidence Extraction
[BAT]   - Extracted 5 evidence objects
[BAT] Phase 4: Vulnerability Classification
[BAT]   - Confirmed 3 vulnerabilities
[BAT]   - Discarded 2 candidates
[BAT] Investigation complete. Found 3 vulnerabilities.
```

## Supported Vulnerability Types

### 1. Buffer Overflow (CWE-787, CWE-120)

Detects unsafe function usage:

- `strcpy`, `strcat` - Unbounded string copies
- `gets` - Always unsafe
- `sprintf`, `vsprintf` - Format string without bounds
- `memcpy` - Without size validation

**Evidence includes:**

- Destination buffer size
- Source input controllability
- Missing bounds check
- Taint path from source to sink

### 2. Use-After-Free (CWE-416)

Detects memory lifetime violations:

- `free()` followed by dereference
- Pointer reuse after deallocation

**Evidence includes:**

- Allocation site
- Free site
- Use-after-free site
- Lifetime event trace

### 3. Integer Overflow (CWE-190)

Detects overflow in size calculations:

- `size * n` overflow passed to `malloc`
- Arithmetic operations without overflow checks

**Evidence includes:**

- Overflow expression
- Usage context
- Missing overflow check

## Report Format

### JSON Report

```json
{
  "title": "BAT Security Report",
  "project": "vulnerable_project",
  "scan_date": "2024-01-15T10:30:00",
  "summary": {
    "total_vulnerabilities": 3,
    "severity_distribution": {
      "CRITICAL": 0,
      "HIGH": 2,
      "MEDIUM": 1
    }
  },
  "findings": [
    {
      "id": 1,
      "vuln_type": "BUFFER_OVERFLOW",
      "severity": "HIGH",
      "location": "utils.c:42",
      "evidence": {
        "sink": "strcpy",
        "buffer": "char buf[32]",
        "input_source": "argv[1]",
        "taint_path": ["main.c:12 argv[1]", "utils.c:42 strcpy(buf,input)"]
      }
    }
  ]
}
```

### Markdown Report

````markdown
# BAT Security Report

## Summary

- Total vulnerabilities found: 3
- High severity: 2
- Patched successfully: 2

## Finding 1: Buffer Overflow (CWE-787)

**Location:** utils.c:42
**Sink:** strcpy
**Confidence:** 0.92

### Evidence Path

main.c:12 → utils.c:40 → utils.c:42

### Explanation

Unbounded input reaches strcpy into fixed buffer...

### Suggested Patch

```diff
- strcpy(buf, user_input);
+ strncpy(buf, user_input, sizeof(buf)-1);
+ buf[sizeof(buf)-1] = '\0';
```
````

```

## Architecture

```

BAT/
├── analyzer/ # Static analysis components
│ ├── ast_parser.py # Clang/regex-based AST parsing
│ ├── taint_engine.py # Taint flow analysis
│ ├── lifetime_checker.py # UAF detection
│ └── overflow_checker.py # Buffer/integer overflow
├── agent/ # Autonomous agents
│ ├── investigator.py # Main investigation orchestrator
│ ├── patch_agent.py # Patch generation
│ └── validator.py # Patch validation
├── rag/ # Knowledge retrieval
│ └── retriever.py # CWE/CERT knowledge base
├── report/ # Report generation
│ └── report_generator.py
└── cli.py # Command-line interface

````

## API Usage

```python
from BAT.agent.investigator import VulnerabilityInvestigator
from BAT.agent.patch_agent import PatchAgent
from BAT.report.report_generator import ReportGenerator

# Investigate vulnerabilities
investigator = VulnerabilityInvestigator('./project')
result = investigator.investigate()

# Generate patches
patch_agent = PatchAgent()
patches = patch_agent.generate_patches_for_findings(result.confirmed)

# Generate report
generator = ReportGenerator()
report = generator.generate_report(
    vulnerabilities=result.confirmed,
    patches=patch_agent.get_all_patches_json()
)

# Save reports
generator.save('./output', 'report')
````

## Testing with Vulnerable Code

BAT can be tested with known vulnerable codebases:

- [Juliet Test Suite](https://samate.nist.gov/SARD/test-suites/112)
- [SARD Test Cases](https://samate.nist.gov/SARD/)

## Requirements

- Python 3.8+
- Optional: libclang for enhanced parsing
- Optional: GCC/Clang for patch validation

## License

MIT License

## References

- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [CERT C Secure Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c)
