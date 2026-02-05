"""
Patch Validator Module

Validates generated patches by:
1. Applying patch to temporary copy
2. Compiling the patched code
3. Re-running analysis to confirm fix
4. Optionally running tests
"""

import os
import sys
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path

# Handle both module and standalone imports
try:
    from BAT.agent.patch_agent import PatchSuggestion
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from agent.patch_agent import PatchSuggestion


@dataclass
class ValidationResult:
    """Result of patch validation."""
    patch: PatchSuggestion
    patch_applied: bool = False
    compilation_success: bool = False
    compilation_output: str = ""
    vulnerability_fixed: bool = False
    tests_passed: Optional[bool] = None
    test_output: str = ""
    errors: List[str] = field(default_factory=list)


class PatchValidator:
    """
    Validator for generated patches.
    
    Validates patches by:
    1. Creating a temporary copy of the project
    2. Applying the patch
    3. Compiling to check for syntax errors
    4. Re-running vulnerability analysis
    5. Optionally running test suite
    """

    def __init__(self, project_path: str, config: Dict = None):
        """
        Initialize the patch validator.
        
        Args:
            project_path: Path to the C project
            config: Optional configuration dictionary
        """
        self.project_path = Path(project_path)
        self.config = config or {}
        self.temp_dir: Optional[Path] = None
        self.validation_results: List[ValidationResult] = []
        
        # Compiler settings
        self.compiler = config.get('compiler', 'gcc')
        self.compile_flags = config.get('compile_flags', ['-Wall', '-Wextra', '-c'])

    def validate_patch(self, patch: PatchSuggestion, 
                       file_content: str = None) -> ValidationResult:
        """
        Validate a single patch.
        
        Args:
            patch: The patch to validate
            file_content: Optional original file content
            
        Returns:
            ValidationResult with validation details
        """
        result = ValidationResult(patch=patch)
        
        try:
            # Step 1: Create temporary directory
            self.temp_dir = Path(tempfile.mkdtemp(prefix='bat_validate_'))
            
            # Step 2: Copy project or file
            if self.project_path.is_file():
                temp_file = self.temp_dir / self.project_path.name
                if file_content:
                    temp_file.write_text(file_content)
                else:
                    shutil.copy2(self.project_path, temp_file)
            else:
                shutil.copytree(self.project_path, self.temp_dir / 'project')
                temp_file = self.temp_dir / 'project' / patch.file
            
            # Step 3: Apply patch
            result.patch_applied = self._apply_patch(temp_file, patch)
            
            if not result.patch_applied:
                result.errors.append("Failed to apply patch")
                return result
            
            # Step 4: Compile
            result.compilation_success, result.compilation_output = self._compile(temp_file)
            
            if not result.compilation_success:
                result.errors.append("Compilation failed after patch")
                return result
            
            # Step 5: Re-analyze (simplified check)
            result.vulnerability_fixed = self._check_vulnerability_fixed(temp_file, patch)
            
            # Step 6: Run tests if available
            if self.config.get('run_tests', False):
                result.tests_passed, result.test_output = self._run_tests()
            
        except Exception as e:
            result.errors.append(str(e))
        finally:
            # Cleanup
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        self.validation_results.append(result)
        return result

    def _apply_patch(self, file_path: Path, patch: PatchSuggestion) -> bool:
        """Apply patch to file."""
        try:
            content = file_path.read_text()
            lines = content.split('\n')
            
            # Find and replace the vulnerable line
            if patch.line <= len(lines):
                # Simple replacement - find original and replace
                original_stripped = patch.original_code.strip()
                
                for i, line in enumerate(lines):
                    if original_stripped in line.strip() or (
                        patch.line - 1 == i and original_stripped in line
                    ):
                        # Preserve indentation
                        indent = len(line) - len(line.lstrip())
                        patched_lines = patch.patched_code.split('\n')
                        patched_with_indent = '\n'.join(
                            ' ' * indent + pl.strip() if pl.strip() else ''
                            for pl in patched_lines
                        )
                        lines[i] = patched_with_indent
                        break
                
                file_path.write_text('\n'.join(lines))
                return True
            
            return False
        except Exception as e:
            print(f"Error applying patch: {e}")
            return False

    def _compile(self, file_path: Path) -> Tuple[bool, str]:
        """Compile the file and check for errors."""
        try:
            # Build compile command
            cmd = [self.compiler] + self.compile_flags + [str(file_path)]
            
            # Run compiler
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(file_path.parent)
            )
            
            output = result.stdout + result.stderr
            
            # Check for success
            if result.returncode == 0:
                return True, output
            else:
                return False, output
                
        except subprocess.TimeoutExpired:
            return False, "Compilation timed out"
        except FileNotFoundError:
            # Try alternative compilers
            for alt_compiler in ['clang', 'cc']:
                try:
                    cmd = [alt_compiler] + self.compile_flags + [str(file_path)]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        return True, result.stdout + result.stderr
                except:
                    continue
            return False, f"Compiler '{self.compiler}' not found"
        except Exception as e:
            return False, str(e)

    def _check_vulnerability_fixed(self, file_path: Path, patch: PatchSuggestion) -> bool:
        """
        Check if the vulnerability was fixed by re-analyzing.
        
        Simplified check: look for the dangerous pattern in patched code.
        """
        try:
            content = file_path.read_text()
            
            # Check if dangerous sink is still present without bounds
            vuln_type = patch.vuln_type
            
            if vuln_type == 'BUFFER_OVERFLOW':
                # For buffer overflow, check if unsafe function is replaced
                dangerous_patterns = {
                    'strcpy': r'\bstrcpy\s*\([^)]*\)',
                    'gets': r'\bgets\s*\([^)]*\)',
                    'sprintf': r'\bsprintf\s*\([^)]*\)',
                }
                
                import re
                for sink, pattern in dangerous_patterns.items():
                    if sink in patch.original_code.lower():
                        # Check if the dangerous pattern still exists at the same location
                        matches = list(re.finditer(pattern, content))
                        # If we removed it or replaced it, vulnerability is fixed
                        if not matches or patch.patched_code not in content:
                            return True
                
                # Check for safe alternatives
                safe_patterns = ['strncpy', 'snprintf', 'fgets', 'strlcpy']
                for safe in safe_patterns:
                    if safe in content and safe in patch.patched_code:
                        return True
            
            elif vuln_type == 'USE_AFTER_FREE':
                # Check if NULL assignment is present after free
                if '= NULL' in patch.patched_code and '= NULL' in content:
                    return True
            
            elif vuln_type == 'INTEGER_OVERFLOW':
                # Check if overflow check is present
                if 'SIZE_MAX' in patch.patched_code or '__builtin_mul_overflow' in patch.patched_code:
                    if 'SIZE_MAX' in content or '__builtin_mul_overflow' in content:
                        return True
            
            return False
            
        except Exception as e:
            print(f"Error checking vulnerability fix: {e}")
            return False

    def _run_tests(self) -> Tuple[bool, str]:
        """Run test suite if available."""
        test_cmd = self.config.get('test_command', None)
        
        if not test_cmd:
            return None, "No test command configured"
        
        try:
            result = subprocess.run(
                test_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(self.temp_dir)
            )
            
            output = result.stdout + result.stderr
            return result.returncode == 0, output
            
        except subprocess.TimeoutExpired:
            return False, "Tests timed out"
        except Exception as e:
            return False, str(e)

    def validate_all_patches(self, patches: List[PatchSuggestion],
                             file_contents: Dict[str, str] = None) -> List[ValidationResult]:
        """
        Validate multiple patches.
        
        Args:
            patches: List of patches to validate
            file_contents: Optional dict mapping filenames to content
            
        Returns:
            List of validation results
        """
        file_contents = file_contents or {}
        results = []
        
        for patch in patches:
            content = file_contents.get(patch.file, None)
            result = self.validate_patch(patch, content)
            results.append(result)
        
        return results

    def get_validation_summary(self) -> Dict:
        """Get summary of all validations."""
        total = len(self.validation_results)
        applied = sum(1 for r in self.validation_results if r.patch_applied)
        compiled = sum(1 for r in self.validation_results if r.compilation_success)
        fixed = sum(1 for r in self.validation_results if r.vulnerability_fixed)
        
        return {
            'total_patches': total,
            'patches_applied': applied,
            'compilation_success': compiled,
            'vulnerabilities_fixed': fixed,
            'success_rate': fixed / total if total > 0 else 0.0
        }

    def get_results_json(self) -> List[Dict]:
        """Get all validation results as JSON-serializable dicts."""
        return [
            {
                'patch': {
                    'vuln_type': r.patch.vuln_type,
                    'file': r.patch.file,
                    'line': r.patch.line,
                    'original_code': r.patch.original_code,
                    'patched_code': r.patch.patched_code
                },
                'patch_applied': r.patch_applied,
                'compilation': 'SUCCESS' if r.compilation_success else 'FAILED',
                'compilation_output': r.compilation_output[:500] if r.compilation_output else '',
                'vulnerability_fixed': r.vulnerability_fixed,
                'tests_passed': r.tests_passed,
                'errors': r.errors
            }
            for r in self.validation_results
        ]
