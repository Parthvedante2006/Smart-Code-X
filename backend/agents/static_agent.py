import ast
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Tuple
from collections import defaultdict
import hashlib

from static_agent_files.collect_python_files import collect_python_files

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class StaticCodeAnalyzer:
    """
    Comprehensive static code analyzer for Python files.
    Performs AST-based analysis, pylint, bandit, and radon checks.
    """
    
    def __init__(self, temp_folder: str = "temp", session_id: str = None, results_base_folder: str = "results"):
        """
        Initialize the static code analyzer.
        
        Args:
            temp_folder: Path to folder containing Python files to analyze
            session_id: Unique session identifier for this analysis run
            results_base_folder: Base folder for storing results (default: "results")
        """
        self.temp_folder = Path(temp_folder)
        self.session_id = session_id
        self.results_base_folder = Path(results_base_folder)
        self.all_issues = []
        self.file_stats = {}
        
    def analyze_all_files(self) -> Dict[str, Any]:
        """
        Analyze all Python files in the temp folder and save results.
        
        Returns:
            JSON-serializable dictionary with analysis results
        """
        if not self.temp_folder.exists():
            logger.error(f"Temp folder does not exist: {self.temp_folder}")
            return self._build_summary()
        
        # Get all Python files
        python_files = list(self.temp_folder.rglob("*.py"))
        
        if not python_files:
            logger.warning("No Python files found in temp folder")
            return self._build_summary()
        
        logger.info(f"Found {len(python_files)} Python files to analyze")
        
        # Analyze each file
        for file_path in python_files:
            logger.info(f"Analyzing: {file_path}")
            self._analyze_single_file(file_path)
        
        # Normalize, deduplicate, and build summary
        self._normalize_issues()
        self._deduplicate_issues()
        summary = self._build_summary()
        
        # Save results to structured folder
        self._save_results(summary)
        
        return summary
    
    def _analyze_single_file(self, file_path: Path) -> None:
        """
        Analyze a single Python file with all tools.
        
        Args:
            file_path: Path to the Python file
        """
        file_str = str(file_path)
        
        # Initialize file stats
        self.file_stats[file_str] = {
            'syntax_error': False,
            'ast_issues': 0,
            'pylint_issues': 0,
            'bandit_issues': 0,
            'radon_metrics': {}
        }
        
        # Step 1: Read file safely
        try:
            content = self._read_file_safely(file_path)
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            self._add_issue(file_str, 'read_error', str(e), 1, 'error')
            return

        # Step 2: Text-based scan for TODO/FIXME (comments are not visible in AST)
        self._scan_todo_fixme(file_str, content)

        # Step 3: Parse AST
        try:
            tree = ast.parse(content, filename=file_str)
        except SyntaxError as e:
            logger.warning(f"Syntax error in {file_path}: {e}")
            self._add_issue(file_str, 'syntax_error', str(e), e.lineno or 1, 'error')
            self.file_stats[file_str]['syntax_error'] = True
            return  # Skip file if syntax error

        # Step 4: Run AST-based rules
        self._run_ast_rules(file_str, tree, content)

        # Step 5: Run pylint
        self._run_pylint(file_path)

        # Step 6: Run bandit
        self._run_bandit(file_path)

        # Step 7: Run radon
        self._run_radon(file_path)

    def _scan_todo_fixme(self, file_path: str, content: str) -> None:
        """
        Scan raw text for TODO/FIXME markers.

        Comments are not represented in the AST, so we scan the raw file content
        line-by-line before parsing.
        """
        for idx, line in enumerate(content.splitlines(), start=1):
            if 'TODO' in line or 'FIXME' in line:
                snippet = line.strip()
                self._add_issue(
                    file_path,
                    'todo_comment',
                    f'TODO/FIXME found: {snippet[:80]}',
                    idx,
                    'info'
                )
                self.file_stats[file_path]['ast_issues'] += 1
    
    def _read_file_safely(self, file_path: Path) -> str:
        """
        Safely read a file with encoding error handling.
        
        Args:
            file_path: Path to file
            
        Returns:
            File content as string
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            logger.warning(f"Encoding issue in {file_path}, reading with errors='ignore'")
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
    
    def _run_ast_rules(self, file_path: str, tree: ast.AST, content: str) -> None:
        """
        Run AST-based analysis rules.
        
        Args:
            file_path: Path to file
            tree: AST tree
            content: File content
        """
        # Build parent map to allow checking whether nodes are inside functions
        parent_map: Dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parent_map[child] = parent

        def _is_inside_function(node: ast.AST) -> bool:
            """Return True if node is nested inside a function definition."""
            current = parent_map.get(node)
            while current is not None:
                if isinstance(current, ast.FunctionDef):
                    return True
                current = parent_map.get(current)
            return False

        # Rule 1: Check for bare except clauses and empty handlers
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                # Bare except: catches all exceptions -> Medium
                if node.type is None:
                    self._add_issue(
                        file_path,
                        'bare_except',
                        'Bare except clause found (catches all exceptions)',
                        node.lineno,
                        'warning'
                    )
                    self.file_stats[file_path]['ast_issues'] += 1

                # Empty except body (no handling or only pass) -> High
                if not node.body or all(isinstance(stmt, ast.Pass) for stmt in node.body):
                    self._add_issue(
                        file_path,
                        'empty_except_body',
                        'Except block has an empty body or only pass; exception is effectively ignored',
                        node.lineno,
                        'error'
                    )
                    self.file_stats[file_path]['ast_issues'] += 1

            # Rule 2: Check for print statements (should use logging) only inside functions
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == 'print':
                    if _is_inside_function(node):
                        self._add_issue(
                            file_path,
                            'print_statement',
                            'Use logging instead of print statements in library code',
                            node.lineno,
                            'info'
                        )
                        self.file_stats[file_path]['ast_issues'] += 1

                # Rule 3: Dangerous use of eval/exec -> High
                if isinstance(node.func, ast.Name) and node.func.id in {'eval', 'exec'}:
                    self._add_issue(
                        file_path,
                        'dangerous_eval_exec',
                        f'Use of {node.func.id} detected; this can lead to code injection vulnerabilities',
                        node.lineno,
                        'error'
                    )
                    self.file_stats[file_path]['ast_issues'] += 1

                # Rule 4: Insecure hash functions (md5/sha1) -> High
                if isinstance(node.func, ast.Attribute) and node.func.attr in {'md5', 'sha1'}:
                    self._add_issue(
                        file_path,
                        'insecure_hash_function',
                        f'Use of insecure hash function ({node.func.attr}); prefer SHA-256 or better',
                        node.lineno,
                        'error'
                    )
                    self.file_stats[file_path]['ast_issues'] += 1

                # Rule 5: subprocess.Popen with shell=True -> High
                if (
                    (isinstance(node.func, ast.Name) and node.func.id == 'Popen')
                    or (isinstance(node.func, ast.Attribute) and node.func.attr == 'Popen')
                ):
                    for kw in node.keywords:
                        if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            self._add_issue(
                                file_path,
                                'subprocess_popen_shell_true',
                                'subprocess.Popen with shell=True can be dangerous; avoid shell=True or sanitize inputs',
                                node.lineno,
                                'error'
                            )
                            self.file_stats[file_path]['ast_issues'] += 1
                            break

            # Rule 6: Check for long functions (>80 lines)
            if isinstance(node, ast.FunctionDef):
                start = getattr(node, 'lineno', None)
                end = getattr(node, 'end_lineno', None)
                if start is None or end is None:
                    continue
                func_length = end - start
                if func_length > 80:
                    self._add_issue(
                        file_path,
                        'long_function',
                        f'Function "{node.name}" is too long ({func_length} lines)',
                        node.lineno,
                        'warning'
                    )
                    self.file_stats[file_path]['ast_issues'] += 1
    
    def _run_pylint(self, file_path: Path) -> None:
        """
        Run pylint on a file and collect issues.
        
        Args:
            file_path: Path to file
        """
        try:
            result = subprocess.run(
                ['pylint', '--output-format=json', str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.stdout:
                try:
                    pylint_issues = json.loads(result.stdout)
                    for issue in pylint_issues:
                        symbol = issue.get('symbol', 'unknown')
                        issue_type = f"pylint_{symbol}"
                        severity = self._map_pylint_severity(issue.get('type', 'info'))

                        # Downgrade import errors to environment/info level
                        if symbol == 'import-error':
                            severity = 'info'
                            issue_type = 'environment_import_error'

                        self._add_issue(
                            str(file_path),
                            issue_type,
                            issue.get('message', 'Unknown issue'),
                            issue.get('line', 1),
                            severity
                        )
                        self.file_stats[str(file_path)]['pylint_issues'] += 1
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse pylint output for {file_path}")
        
        except subprocess.TimeoutExpired:
            logger.warning(f"Pylint timeout for {file_path}")
        except FileNotFoundError:
            logger.warning("Pylint not found, skipping pylint analysis")
        except Exception as e:
            logger.warning(f"Pylint error for {file_path}: {e}")
    
    def _run_bandit(self, file_path: Path) -> None:
        """
        Run bandit security scanner on a file.
        
        Args:
            file_path: Path to file
        """
        try:
            result = subprocess.run(
                ['bandit', '-f', 'json', str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.stdout:
                try:
                    bandit_output = json.loads(result.stdout)
                    for issue in bandit_output.get('results', []):
                        severity = issue.get('issue_severity', 'LOW').lower()
                        if severity == 'high':
                            severity = 'error'
                        elif severity == 'medium':
                            severity = 'warning'
                        else:
                            severity = 'info'
                        
                        self._add_issue(
                            str(file_path),
                            f"bandit_{issue.get('test_id', 'unknown')}",
                            issue.get('issue_text', 'Security issue'),
                            issue.get('line_number', 1),
                            severity
                        )
                        self.file_stats[str(file_path)]['bandit_issues'] += 1
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse bandit output for {file_path}")
        
        except subprocess.TimeoutExpired:
            logger.warning(f"Bandit timeout for {file_path}")
        except FileNotFoundError:
            logger.warning("Bandit not found, skipping security analysis")
        except Exception as e:
            logger.warning(f"Bandit error for {file_path}: {e}")
    
    def _run_radon(self, file_path: Path) -> None:
        """
        Run radon complexity analyzer on a file.
        
        Args:
            file_path: Path to file
        """
        try:
            # Cyclomatic complexity
            result_cc = subprocess.run(
                ['radon', 'cc', '-j', str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result_cc.stdout:
                try:
                    cc_data = json.loads(result_cc.stdout)
                    file_cc = cc_data.get(str(file_path), [])
                    
                    for item in file_cc:
                        complexity = item.get('complexity', 0)
                        if complexity > 10:  # High complexity threshold
                            self._add_issue(
                                str(file_path),
                                'high_complexity',
                                f"{item.get('type', 'Function')} '{item.get('name', 'unknown')}' has high complexity ({complexity})",
                                item.get('lineno', 1),
                                'warning'
                            )
                    
                    # Store metrics
                    self.file_stats[str(file_path)]['radon_metrics']['complexity'] = file_cc
                
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse radon output for {file_path}")
            
            # Maintainability index
            result_mi = subprocess.run(
                ['radon', 'mi', '-j', str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result_mi.stdout:
                try:
                    mi_data = json.loads(result_mi.stdout)
                    self.file_stats[str(file_path)]['radon_metrics']['maintainability'] = mi_data
                except json.JSONDecodeError:
                    pass
        
        except subprocess.TimeoutExpired:
            logger.warning(f"Radon timeout for {file_path}")
        except FileNotFoundError:
            logger.warning("Radon not found, skipping complexity analysis")
        except Exception as e:
            logger.warning(f"Radon error for {file_path}: {e}")
    
    def _add_issue(self, file_path: str, issue_type: str, message: str, line: int, severity: str) -> None:
        """
        Add an issue to the collection.
        
        Args:
            file_path: Path to file
            issue_type: Type of issue
            message: Issue message
            line: Line number
            severity: Severity level (error, warning, info)
        """
        self.all_issues.append({
            'file': file_path,
            'type': issue_type,
            'message': message,
            'line': line,
            # Keep raw/internal severity and normalize later
            'raw_severity': severity,
            'severity': severity,
        })
    
    def _normalize_issues(self) -> None:
        """
        Normalize all collected issues (ensure consistent format).
        """
        for issue in self.all_issues:
            # Normalize file paths (use relative paths)
            if self.temp_folder:
                try:
                    issue['file'] = str(Path(issue['file']).relative_to(self.temp_folder))
                except ValueError:
                    pass  # Keep absolute path if can't make relative

            # Normalize severity to High / Medium / Low for output
            raw = (issue.get('raw_severity') or issue.get('severity') or '').lower()
            if raw in {'error', 'high'}:
                norm = 'High'
            elif raw in {'warning', 'medium'}:
                norm = 'Medium'
            else:
                norm = 'Low'
            issue['severity'] = norm
            
            # Ensure line is an integer
            try:
                issue['line'] = int(issue['line'])
            except (ValueError, TypeError):
                issue['line'] = 1
    
    def _deduplicate_issues(self) -> None:
        """
        Remove duplicate issues based on normalized (file, line, type) and
        keep the highest-severity instance. Also suppress certain noisy
        overlaps (e.g., pylint timeout vs Bandit B113).
        """
        # Detect Bandit timeout issues (B113) so we can suppress overlapping pylint ones
        bandit_timeout_locations = {
            (issue['file'], issue['line'])
            for issue in self.all_issues
            if issue.get('type') == 'bandit_B113'
        }

        def severity_rank(sev: str) -> int:
            sev = (sev or '').lower()
            if sev == 'high':
                return 3
            if sev == 'medium':
                return 2
            if sev == 'low':
                return 1
            return 0

        merged: Dict[Tuple[str, int, str], Dict[str, Any]] = {}

        for issue in self.all_issues:
            key = (issue['file'], issue['line'], issue['type'])

            # Suppress pylint timeout if Bandit B113 already reported on same location
            if (
                issue['type'].startswith('pylint_')
                and 'timeout' in issue['type']
                and (issue['file'], issue['line']) in bandit_timeout_locations
            ):
                continue

            existing = merged.get(key)
            if existing is None:
                merged[key] = issue
            else:
                # Keep the one with higher severity
                if severity_rank(issue.get('severity')) > severity_rank(existing.get('severity')):
                    merged[key] = issue

        removed_count = len(self.all_issues) - len(merged)
        if removed_count > 0:
            logger.info(f"Removed {removed_count} duplicate issues")

        self.all_issues = list(merged.values())
    
    def _build_summary(self) -> Dict[str, Any]:
        """
        Build a comprehensive summary of all analysis results.
        
        Returns:
            JSON-serializable summary dictionary
        """
        # Count issues by severity
        severity_counts = defaultdict(int)
        for issue in self.all_issues:
            severity_counts[issue['severity']] += 1
        
        # Count issues by type
        type_counts = defaultdict(int)
        for issue in self.all_issues:
            type_counts[issue['type']] += 1
        
        # Count issues by file
        file_counts = defaultdict(int)
        for issue in self.all_issues:
            file_counts[issue['file']] += 1

        # Normalize file_stats paths in the same way as issues
        normalized_file_stats: Dict[str, Any] = {}
        for path_str, stats in self.file_stats.items():
            new_key = path_str
            if self.temp_folder:
                try:
                    new_key = str(Path(path_str).relative_to(self.temp_folder))
                except ValueError:
                    pass
            normalized_file_stats[new_key] = stats

        summary = {
            'agent_name': 'static_agent',
            'session_id': self.session_id,
            'total_files_analyzed': len(self.file_stats),
            'total_issues': len(self.all_issues),
            'severity_breakdown': dict(severity_counts),
            'type_breakdown': dict(type_counts),
            'file_breakdown': dict(file_counts),
            'issues': self.all_issues,
            'file_stats': normalized_file_stats
        }
        
        return summary
    
    def _save_results(self, summary: Dict[str, Any]) -> None:
        """
        Save analysis results to structured folder.
        
        Args:
            summary: Analysis summary dictionary
        """
        if not self.session_id:
            logger.warning("No session ID provided, skipping structured save")
            return
        
        # Create results folder structure: results/<session_id>/
        results_folder = self.results_base_folder / self.session_id
        try:
            results_folder.mkdir(parents=True, exist_ok=True)
            
            # Save as static_agent.json
            output_file = results_folder / "static_agent.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2)
            
            logger.info(f"\n{'='*50}")
            logger.info(f"Results saved to: {output_file.absolute()}")
            logger.info(f"{'='*50}\n")
            
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
    
    @staticmethod
    def _map_pylint_severity(pylint_type: str) -> str:
        """
        Map pylint message type to severity level.
        
        Args:
            pylint_type: Pylint message type
            
        Returns:
            Severity level (error, warning, info)
        """
        mapping = {
            'error': 'error',
            'fatal': 'error',
            'warning': 'warning',
            'convention': 'info',
            'refactor': 'info',
            'information': 'info'
        }
        return mapping.get(pylint_type.lower(), 'info')


def analyze_temp_folder(temp_folder: str = "temp", session_id: str = None, results_base_folder: str = "results") -> Dict[str, Any]:
    """
    Main entry point for analyzing all Python files in temp folder.
    
    Args:
        temp_folder: Path to temp folder containing Python files
        session_id: Unique session identifier for this analysis run
        results_base_folder: Base folder for storing results (default: "results")
        
    Returns:
        JSON-serializable analysis results
    """
    analyzer = StaticCodeAnalyzer(temp_folder, session_id, results_base_folder)
    results = analyzer.analyze_all_files()
    return results


def analyze_directory_with_collection(
    directory_path: str,
    base_temp_folder: str = "temp",
    results_base_folder: str = "results",
) -> Dict[str, Any]:
    """
    High-level helper that:
    1) Uses collect_python_files() to copy all .py files from directory_path
       into temp/<session_id>/ while preserving relative structure.
    2) Runs StaticCodeAnalyzer on that specific session folder.

    Args:
        directory_path: Root directory to scan for Python files.
        base_temp_folder: Base temp folder where session subfolder is created.
        results_base_folder: Base folder for structured analyzer results.

    Returns:
        Static analyzer summary dict, augmented with collection stats and session_id.
    """
    collected_files, collection_stats, session_id = collect_python_files(
        directory_path, base_temp_folder=base_temp_folder
    )

    # Point analyzer at the concrete session folder just created by the collector
    session_temp_folder = str(Path(base_temp_folder) / session_id)

    analyzer = StaticCodeAnalyzer(
        temp_folder=session_temp_folder,
        session_id=session_id,
        results_base_folder=results_base_folder,
    )
    analysis_summary = analyzer.analyze_all_files()

    # Attach collection metadata for downstream consumers
    analysis_summary.setdefault("meta", {})
    analysis_summary["meta"]["collection_stats"] = collection_stats
    analysis_summary["meta"]["collected_files"] = collected_files
    analysis_summary["meta"]["session_id"] = session_id

    return analysis_summary


if __name__ == "__main__":
    print("=" * 60)
    print("Static Code Analyzer (with file collection)")
    print("=" * 60)

    # Get root directory from user
    directory = input("\nEnter the directory path to scan (project root): ").strip()
    if not directory:
        directory = "."

    print(f"\nCollecting and analyzing Python files from: {directory}")
    print("-" * 60)

    # Run end-to-end: collect → analyze
    results = analyze_directory_with_collection(directory)

    # Display high-level results
    session_id = results.get("meta", {}).get("session_id", results.get("session_id", "N/A"))
    print(f"\n{'=' * 60}")
    print("ANALYSIS RESULTS")
    print(f"{'=' * 60}")
    print(f"\nSession ID: {session_id}")
    print(f"Agent: {results.get('agent_name', 'N/A')}")
    print(f"Total Files Analyzed: {results.get('total_files_analyzed', 0)}")
    print(f"Total Issues Found: {results.get('total_issues', 0)}")

    if results.get("severity_breakdown"):
        print("\nSeverity Breakdown:")
        for severity, count in results["severity_breakdown"].items():
            print(f"  {severity}: {count}")

    if results.get("type_breakdown"):
        print("\nTop Issue Types:")
        sorted_types = sorted(results["type_breakdown"].items(), key=lambda x: x[1], reverse=True)
        for issue_type, count in sorted_types[:10]:
            print(f"  {issue_type}: {count}")

    print(f"\n{'=' * 60}")
