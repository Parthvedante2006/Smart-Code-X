"""
Semantic Agent (SCAA) - Semantic Code Analysis Agent

Analyzes Python code to check if code implementation matches its declared intent.
Uses AST parsing and semantic embeddings to compare function names/docstrings with actual logic.

Key Principles:
- Does NOT execute code
- Does NOT modify code
- Does NOT guess runtime behavior
- Uses AST to extract meaningful tokens
- Compares intent (name/docstring) with behavior (logic tokens)
"""

import ast
import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional, Set
import sys

# Add static_agent_files to path to import collect_python_files
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'static_agent_files'))
from collect_python_files import collect_python_files

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Similarity thresholds
EMBEDDINGS_AVAILABLE = True
SIMILARITY_THRESHOLD_LOW = 0.40
SIMILARITY_THRESHOLD_MEDIUM = 0.65

# Security-related keywords (triggers for stricter analysis)
SECURITY_KEYWORDS = {
    'encrypt', 'decrypt', 'encryption', 'decryption',
    'hash', 'hashing', 'secure', 'security', 'authenticate',
    'password', 'token', 'secret', 'key', 'auth', 'authorize'
}

# Insecure methods (flag if used with security keywords)
INSECURE_METHODS = {
    'base64', 'md5', 'sha1', 'eval', 'exec', 'pickle', 'marshal'
}

# Generic function names (skip analysis)
GENERIC_NAMES = {
    'get', 'set', 'do', 'run', 'main', 'init', 'process', 'handle',
    'helper', 'util', 'util_func', 'temp', 'test', 'check'
}

# Test file indicators
TEST_FILE_INDICATORS = {'test_', '_test.py', 'tests/', 'test.py'}


class SemanticAnalyzer:
    """
    Semantic Code Analysis Agent that compares function intent with implementation.
    """
    
    def __init__(self):
        """Initialize the semantic analyzer. Model is loaded lazily."""
        self.model = None

    def _load_model_if_needed(self):
        """Lazy load the model only when analysis is requested."""
        if self.model is None and EMBEDDINGS_AVAILABLE:
            try:
                logger.info("Lazy loading sentence-transformers model...")
                from sentence_transformers import SentenceTransformer
                self.model = SentenceTransformer('all-MiniLM-L6-v2')
                logger.info("Model loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load embedding model: {e}")
                self.model = None

    
    def should_skip_file(self, file_path: str) -> bool:
        """
        Determine if a file should be skipped.
        
        Skip:
        - Test files
        - Generated code (optional heuristic)
        """
        file_str = str(file_path).lower()
        for indicator in TEST_FILE_INDICATORS:
            if indicator in file_str:
                return True
        return False
    
    def read_file_safely(self, file_path: Path) -> Optional[str]:
        """
        Read a Python file safely, handling encoding issues.
        
        Returns:
            File content as string, or None if file cannot be read.
        """
        try:
            # Try UTF-8 first
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            # Try with error handling
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    logger.warning(f"Read {file_path} with encoding errors ignored")
                    return content
            except Exception as e:
                logger.warning(f"Failed to read {file_path}: {e}")
                return None
        except Exception as e:
            logger.warning(f"Failed to read {file_path}: {e}")
            return None
    
    def parse_ast_safely(self, content: str, file_path: str) -> Optional[ast.AST]:
        """
        Parse Python code into AST safely.
        
        Returns:
            AST node, or None if parsing fails.
        """
        try:
            return ast.parse(content, filename=file_path)
        except SyntaxError as e:
            logger.debug(f"Syntax error in {file_path}: {e}. Skipping (Static Agent handles this).")
            return None
        except Exception as e:
            logger.warning(f"Failed to parse AST for {file_path}: {e}")
            return None
    
    def is_trivial_function(self, func_node: ast.FunctionDef) -> bool:
        """
        Check if a function is trivial (one-liner or empty).
        
        Skip trivial functions to avoid noise.
        """
        if not func_node.body:
            return True
        
        # Check if function is just a pass or return statement
        if len(func_node.body) == 1:
            first_stmt = func_node.body[0]
            if isinstance(first_stmt, ast.Pass):
                return True
            if isinstance(first_stmt, ast.Return) and first_stmt.value is None:
                return True
        
        # Check if it's a one-liner utility
        if len(func_node.body) <= 1:
            return True
        
        return False
    
    def extract_imports(self, tree: ast.AST) -> Set[str]:
        """
        Extract all imported module names from AST.
        """
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split('.')[0])  # Get base module name
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split('.')[0])
        return imports
    
    def extract_function_calls(self, node: ast.AST) -> Set[str]:
        """
        Recursively extract all function call names from AST node.
        """
        calls = set()
        
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    calls.add(child.func.id)
                elif isinstance(child.func, ast.Attribute):
                    # Get attribute name (e.g., obj.method -> method)
                    calls.add(child.func.attr)
                    # Also get the base object if it's a name
                    if isinstance(child.func.value, ast.Name):
                        calls.add(child.func.value.id)
        
        return calls
    
    def extract_attributes(self, node: ast.AST) -> Set[str]:
        """
        Extract attribute accesses from AST.
        """
        attributes = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                attributes.add(child.attr)
        return attributes
    
    def extract_variables(self, node: ast.AST) -> Set[str]:
        """
        Extract variable names from AST (assignments and usage).
        """
        variables = set()
        
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Load)):
                variables.add(child.id)
        
        return variables
    
    def extract_string_literals(self, node: ast.AST, min_length: int = 3) -> Set[str]:
        """
        Extract meaningful string literals from AST.
        Skip very short strings (likely format strings or single chars).
        """
        strings = set()
        for child in ast.walk(node):
            # Python 3.8+ uses ast.Constant for string literals
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if len(child.value) >= min_length:
                    strings.add(child.value)
        return strings
    
    def extract_function_intent(self, func_node: ast.FunctionDef) -> Dict[str, Any]:
        """
        Extract intent signals from function:
        1. Function name
        2. Docstring (if exists)
        3. Parameter names
        """
        intent = {
            'name': func_node.name,
            'docstring': None,
            'params': []
        }
        
        # Extract docstring (first expression string in body)
        if func_node.body:
            first_expr = func_node.body[0]
            if isinstance(first_expr, ast.Expr):
                # Python 3.8+ uses ast.Constant for string literals
                if isinstance(first_expr.value, ast.Constant) and isinstance(first_expr.value.value, str):
                    intent['docstring'] = first_expr.value.value
        
        # Extract parameter names
        for arg in func_node.args.args:
            intent['params'].append(arg.arg)
        
        return intent
    
    def extract_function_behavior(self, func_node: ast.FunctionDef, imports: Set[str]) -> Dict[str, Set[str]]:
        """
        Extract behavioral tokens from function body:
        - Function calls
        - Attributes
        - Variable names
        - Imported modules used
        - String literals (meaningful)
        """
        behavior = {
            'function_calls': self.extract_function_calls(func_node),
            'attributes': self.extract_attributes(func_node),
            'variables': self.extract_variables(func_node),
            'imports_used': set(),
            'string_literals': self.extract_string_literals(func_node)
        }
        
        # Find which imports are actually used
        all_tokens = (behavior['function_calls'] | 
                     behavior['attributes'] | 
                     behavior['variables'])
        
        for imp in imports:
            if imp in all_tokens:
                behavior['imports_used'].add(imp)
        
        return behavior
    
    def build_intent_text(self, intent: Dict[str, Any]) -> str:
        """
        Build intent text from function intent signals.
        Priority order: docstring > function name > parameter names
        """
        parts = []
        
        # Priority 1: Docstring
        if intent['docstring']:
            parts.append(intent['docstring'])
        
        # Priority 2: Function name
        parts.append(intent['name'])
        
        # Priority 3: Parameter names
        if intent['params']:
            parts.append(' '.join(intent['params']))
        
        return ' '.join(parts)
    
    def build_behavior_text(self, behavior: Dict[str, Set[str]]) -> str:
        """
        Build behavior text from logic tokens.
        """
        parts = []
        
        # Function calls (most important)
        if behavior['function_calls']:
            parts.extend(sorted(behavior['function_calls']))
        
        # Attributes
        if behavior['attributes']:
            parts.extend(sorted(behavior['attributes']))
        
        # Variables
        if behavior['variables']:
            parts.extend(sorted(behavior['variables']))
        
        # Imports used
        if behavior['imports_used']:
            parts.extend(sorted(behavior['imports_used']))
        # String literals (only meaningful ones)
        if behavior['string_literals']:
            # Take first few meaningful strings
            meaningful_strings = [s for s in sorted(behavior['string_literals']) 
                                if len(s) > 3 and not s.isdigit()][:5]
            parts.extend(meaningful_strings)
        
        return ' '.join(parts)
    
    def check_security_heuristic(self, intent_text: str, behavior_text: str) -> Tuple[bool, Optional[str]]:
        """
        Check for security-related mismatches.
        E.g., function claims encryption but uses base64.
        
        Returns:
            (should_flag, reason)
        """
        intent_lower = intent_text.lower()
        behavior_lower = behavior_text.lower()
        
        # Check if intent mentions security
        has_security_intent = any(keyword in intent_lower for keyword in SECURITY_KEYWORDS)
        
        if has_security_intent:
            # Check if behavior uses insecure methods
            uses_insecure = any(method in behavior_lower for method in INSECURE_METHODS)
            
            if uses_insecure:
                insecure_found = [m for m in INSECURE_METHODS if m in behavior_lower]
                reason = f"Function name/docstring implies security (encryption/hashing) but implementation uses insecure methods ({', '.join(insecure_found)})"
                return True, reason
        
        return False, None
    
    def compute_similarity(self, intent_text: str, behavior_text: str) -> float:
        """
        Compute semantic similarity between intent and behavior using embeddings.
        
        Returns:
            Similarity score (0-1), or 0.5 if embeddings unavailable.
        """
        if not intent_text or not behavior_text:
            return 0.5
        
        # Fallback: basic keyword matching if model unavailable
        if not self.model:
            intent_words = set(intent_text.lower().split())
            behavior_words = set(behavior_text.lower().split())
            if not intent_words or not behavior_words:
                return 0.5
            
            intersection = intent_words & behavior_words
            union = intent_words | behavior_words
            return len(intersection) / len(union) if union else 0.5
        
        # Try to load model if available
        self._load_model_if_needed()

        try:
            # Get embeddings
            if self.model:
                intent_embedding = self.model.encode(intent_text, convert_to_tensor=False)
                behavior_embedding = self.model.encode(behavior_text, convert_to_tensor=False)
            else:
                raise ImportError("Model not available")
            
            # Compute cosine similarity
            try:
                import numpy as np
                similarity = np.dot(intent_embedding, behavior_embedding) / (
                    np.linalg.norm(intent_embedding) * np.linalg.norm(behavior_embedding)
                )
                return float(similarity)
            except ImportError:
                # Fallback if numpy not available (shouldn't happen with sentence-transformers)
                # Manual cosine similarity computation
                dot_product = sum(a * b for a, b in zip(intent_embedding, behavior_embedding))
                norm_intent = sum(a * a for a in intent_embedding) ** 0.5
                norm_behavior = sum(b * b for b in behavior_embedding) ** 0.5
                if norm_intent == 0 or norm_behavior == 0:
                    return 0.5
                similarity = dot_product / (norm_intent * norm_behavior)
                return float(similarity)
            
        except Exception as e:
            logger.warning(f"Error computing similarity: {e}")
            # Fallback to keyword matching
            intent_words = set(intent_text.lower().split())
            behavior_words = set(behavior_text.lower().split())
            if not intent_words or not behavior_words:
                return 0.5
            intersection = intent_words & behavior_words
            union = intent_words | behavior_words
            return len(intersection) / len(union) if union else 0.5
    
    def determine_severity(self, similarity: float, security_issue: bool) -> str:
        """
        Determine issue severity based on similarity score and security flags.
        """
        if security_issue:
            return "High"
        
        if similarity < SIMILARITY_THRESHOLD_LOW:
            return "High"
        elif similarity < SIMILARITY_THRESHOLD_MEDIUM:
            return "Medium"
        else:
            return "Low"
    
    def should_report_issue(self, func_name: str, intent_text: str, behavior_text: str, 
                          similarity: float, security_issue: bool) -> Tuple[bool, Optional[str]]:
        """
        Decide whether to report an issue for this function.
        
        Returns:
            (should_report, reason)
        """
        # Skip if name is too generic
        if func_name.lower() in GENERIC_NAMES or func_name.lower().startswith('test_'):
            return False, None
        
        # Skip if behavior is empty
        if not behavior_text or len(behavior_text.strip()) < 3:
            return False, None
        
        # Always report security issues
        if security_issue:
            return True, "Security heuristic triggered"
        
        # Report if similarity is below threshold
        if similarity < SIMILARITY_THRESHOLD_MEDIUM:
            if similarity < SIMILARITY_THRESHOLD_LOW:
                return True, f"Strong mismatch between intent and implementation (similarity: {similarity:.2f})"
            else:
                return True, f"Partial mismatch between intent and implementation (similarity: {similarity:.2f})"
        
        return False, None
    
    def analyze_function(self, func_node: ast.FunctionDef, file_path: str, 
                        imports: Set[str], source_lines: List[str]) -> Optional[Dict[str, Any]]:
        """
        Analyze a single function for semantic mismatches.
        
        Returns:
            Issue dict if found, None otherwise.
        """
        # Skip trivial functions
        if self.is_trivial_function(func_node):
            return None
        
        # Extract intent and behavior
        intent = self.extract_function_intent(func_node)
        behavior = self.extract_function_behavior(func_node, imports)
        
        # Build comparison texts
        intent_text = self.build_intent_text(intent)
        behavior_text = self.build_behavior_text(behavior)
        
        # Skip if no meaningful intent or behavior
        if not intent_text or not behavior_text:
            return None
        
        # Check security heuristics
        security_issue, security_reason = self.check_security_heuristic(intent_text, behavior_text)
        
        # Compute similarity
        similarity = self.compute_similarity(intent_text, behavior_text)
        
        # Decide if we should report
        should_report, reason = self.should_report_issue(
            intent['name'], intent_text, behavior_text, similarity, security_issue
        )
        
        if not should_report:
            return None
        
        # Build issue object
        issue = {
            'file': file_path,
            'function': intent['name'],
            'line_number': func_node.lineno,
            'severity': self.determine_severity(similarity, security_issue),
            'similarity': round(similarity, 3),
            'issue': reason or security_reason or f"Mismatch between function intent and implementation",
            'evidence': {
                'intent_text': intent_text[:200],  # Truncate for display
                'behavior_tokens': {
                    'function_calls': list(behavior['function_calls'])[:10],
                    'attributes': list(behavior['attributes'])[:10],
                    'imports_used': list(behavior['imports_used'])[:10]
                }
            }
        }
        
        # Add code snippet (first few lines of function)
        try:
            end_line = func_node.end_lineno if hasattr(func_node, 'end_lineno') else func_node.lineno + 5
            snippet_lines = source_lines[func_node.lineno - 1:min(end_line, func_node.lineno + 10)]
            issue['evidence']['code_snippet'] = '\n'.join(snippet_lines[:15])
        except:
            pass
        
        return issue
    
    def analyze_file(self, file_path: Path, relative_path: str = None) -> List[Dict[str, Any]]:
        """
        Analyze a single Python file for semantic issues.
        
        Returns:
            List of issues found.
        """
        issues = []
        
        # Skip test files
        if self.should_skip_file(str(file_path)):
            return issues

        # Skip non-Python files
        if not str(file_path).endswith('.py'):
            return issues
        
        # Read file safely
        content = self.read_file_safely(file_path)
        if not content:
            return issues
        
        # Parse AST
        tree = self.parse_ast_safely(content, str(file_path))
        if not tree:
            return issues
        
        # Get source lines for snippets
        source_lines = content.splitlines()
        
        # Extract imports at file level
        imports = self.extract_imports(tree)
        
        # Extract all function definitions
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                issue = self.analyze_function(node, str(file_path), imports, source_lines)
                if issue:
                    issues.append(issue)
        
        return issues
    
    def analyze_repository_with_session(
        self, 
        temp_folder: str, 
        session_id: str, 
        results_base_folder: str
    ) -> Dict[str, Any]:
        """
        Analyze repository using existing temp folder and session_id.
        
        Args:
            temp_folder: Path to temp folder with collected files
            session_id: Session ID for this analysis
            results_base_folder: Base folder for results
            
        Returns:
            Dictionary with issues and summary
        """
        logger.info(f"Starting semantic analysis for session: {session_id}")
        
        temp_folder_path = Path(temp_folder)
        if not temp_folder_path.exists():
            logger.warning(f"Temp folder does not exist: {temp_folder}")
            return {
                "agent": "SCAA",
                "session_id": session_id,
                "issues": [],
                "summary": {
                    "total_files": 0,
                    "files_analyzed": 0,
                    "functions_analyzed": 0,
                    "issues_found": 0,
                    "average_similarity": 0.0
                }
            }
        
        # Get all Python files from temp folder
        collected_files = [str(f.relative_to(temp_folder_path)) 
                          for f in temp_folder_path.rglob("*.py")]
        
        if not collected_files:
            logger.warning("No Python files found in temp folder")
            return {
                "agent": "SCAA",
                "session_id": session_id,
                "issues": [],
                "summary": {
                    "total_files": 0,
                    "files_analyzed": 0,
                    "functions_analyzed": 0,
                    "issues_found": 0,
                    "average_similarity": 0.0
                }
            }
        
        logger.info(f"Found {len(collected_files)} Python files")
        
        # Analyze each file
        all_issues = []
        total_functions = 0
        similarity_scores = []
        files_analyzed_count = 0
        
        for relative_file in collected_files:
            file_path = temp_folder_path / relative_file
            if not file_path.exists():
                continue
            
            try:
                file_issues = self.analyze_file(file_path, relative_path=str(relative_file))
                all_issues.extend(file_issues)
                files_analyzed_count += 1
                
                # Count functions
                content = self.read_file_safely(file_path)
                if content:
                    tree = self.parse_ast_safely(content, str(file_path))
                    if tree:
                        functions_in_file = sum(1 for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
                        total_functions += functions_in_file
                
                # Collect similarity scores
                for issue in file_issues:
                    if 'similarity' in issue:
                        similarity_scores.append(issue['similarity'])
                
                logger.info(f"Analyzed {relative_file}: {len(file_issues)} issues found")
            except Exception as e:
                logger.warning(f"Error analyzing {relative_file}: {e}")
                continue
        
        # Build summary
        avg_similarity = sum(similarity_scores) / len(similarity_scores) if similarity_scores else 0.0
        
        summary = {
            "total_files": len(collected_files),
            "files_analyzed": files_analyzed_count,
            "functions_analyzed": total_functions,
            "issues_found": len(all_issues),
            "average_similarity": round(avg_similarity, 3)
        }
        
        logger.info(f"Semantic analysis complete: {len(all_issues)} issues found")
        
        result = {
            "agent": "SCAA",
            "session_id": session_id,
            "issues": all_issues,
            "summary": summary
        }
        
        # Save results to JSON file
        self._save_results(result, session_id, results_base_folder)
        
        return result
    
    def analyze_repository(self, repo_path: str) -> Dict[str, Any]:
        """
        Analyze an entire repository for semantic issues.
        
        Args:
            repo_path: Path to repository directory
            
        Returns:
            Dictionary with issues and summary
        """
        logger.info(f"Starting semantic analysis of repository: {repo_path}")
        
        # Collect Python files
        logger.info("Collecting Python files...")
        base_temp_folder = os.path.join(os.path.dirname(__file__), "temp")
        collected_files, stats, session_id = collect_python_files(repo_path, base_temp_folder)
        
        if not collected_files:
            logger.warning("No Python files found to analyze")
            return {
                "agent": "SCAA",
                "issues": [],
                "summary": {
                    "total_files": 0,
                    "files_analyzed": 0,
                    "functions_analyzed": 0,
                    "issues_found": 0,
                    "average_similarity": 0.0
                }
            }
        
        logger.info(f"Found {len(collected_files)} Python files")
        
        # Analyze each file
        all_issues = []
        total_functions = 0
        similarity_scores = []
        files_analyzed_count = 0
        
        temp_folder = Path(base_temp_folder) / session_id
        
        for relative_file in collected_files:
            file_path = temp_folder / relative_file
            if not file_path.exists():
                continue
            
            try:
                file_issues = self.analyze_file(file_path)
                all_issues.extend(file_issues)
                files_analyzed_count += 1
                
                # Count functions (approximate)
                content = self.read_file_safely(file_path)
                if content:
                    tree = self.parse_ast_safely(content, str(file_path))
                    if tree:
                        functions_in_file = sum(1 for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
                        total_functions += functions_in_file
                
                # Collect similarity scores
                for issue in file_issues:
                    if 'similarity' in issue:
                        similarity_scores.append(issue['similarity'])
                
                logger.info(f"Analyzed {relative_file}: {len(file_issues)} issues found")
            except Exception as e:
                logger.warning(f"Error analyzing {relative_file}: {e}")
                continue
        
        # Build summary
        avg_similarity = sum(similarity_scores) / len(similarity_scores) if similarity_scores else 0.0
        
        summary = {
            "total_files": len(collected_files),
            "files_analyzed": files_analyzed_count,
            "functions_analyzed": total_functions,
            "issues_found": len(all_issues),
            "average_similarity": round(avg_similarity, 3)
        }
        
        logger.info(f"Semantic analysis complete: {len(all_issues)} issues found")
        
        result = {
            "agent": "SCAA",
            "session_id": session_id,
            "issues": all_issues,
            "summary": summary
        }
        
        # Save results to JSON file
        self._save_results(result, session_id)
        
        return result
    
    def _save_results(self, results: Dict[str, Any], session_id: str, results_base_folder: str = None) -> None:
        """Save analysis results to JSON file in results folder."""
        try:
            if results_base_folder is None:
                results_base_folder = os.path.join(os.path.dirname(__file__), "results")
            results_folder = Path(results_base_folder) / session_id
            results_folder.mkdir(parents=True, exist_ok=True)
            
            output_file = results_folder / "semantic_agent.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Semantic agent results saved to: {output_file}")
        except Exception as e:
            logger.warning(f"Failed to save semantic agent results: {e}")


def analyze_semantic(repo_path: str) -> Dict[str, Any]:
    """
    Main entry point for semantic analysis.
    
    This function is called by the orchestrator.
    
    Args:
        repo_path: Path to repository directory
        
    Returns:
        Dictionary with SCAA analysis results
    """
    analyzer = SemanticAnalyzer()
    return analyzer.analyze_repository(repo_path)


# For testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python semantic_agent.py <repo_path>")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    results = analyze_semantic(repo_path)
    
    import json
    print(json.dumps(results, indent=2, ensure_ascii=False))

