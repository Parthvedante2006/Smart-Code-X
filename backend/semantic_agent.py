"""
Semantic & Contextual Analysis Agent (SCAA)

Analyzes code to detect mismatches between function intent (name, docstring)
and actual implementation by comparing semantic embeddings.
"""

import os
import ast
import re
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
import logging

try:
    from sentence_transformers import SentenceTransformer, util
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logging.warning("sentence-transformers not available. SCAA will use fallback mode.")


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SemanticAnalyzer:
    """Semantic & Contextual Analysis Agent implementation."""
    
    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        similarity_thresholds: Optional[Dict[str, float]] = None,
        batch_size: int = 32,
        skip_dirs: Optional[List[str]] = None,
        skip_test_files: bool = True
    ):
        """
        Initialize the Semantic Analyzer.
        
        Args:
            model_name: Name of the sentence transformer model to use
            similarity_thresholds: Dict with 'high', 'medium', 'low' thresholds
            batch_size: Batch size for embedding computation
            skip_dirs: Directories to skip (e.g., ['node_modules', '.git'])
            skip_test_files: Whether to skip test files
        """
        self.model_name = model_name
        self.batch_size = batch_size
        self.skip_dirs = skip_dirs or ['.git', '__pycache__', 'node_modules', '.venv', 'venv', 'env']
        self.skip_test_files = skip_test_files
        
        # Default similarity thresholds
        self.thresholds = similarity_thresholds or {
            'high': 0.4,      # Below this = High severity
            'medium': 0.65,   # Between high and medium = Medium severity
            # Above medium = OK (not flagged)
        }
        
        # Initialize model if available
        self.model = None
        if TRANSFORMERS_AVAILABLE:
            try:
                logger.info(f"Loading embedding model: {model_name}")
                self.model = SentenceTransformer(model_name)
                logger.info("Model loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load model: {e}")
                self.model = None
        else:
            logger.warning("Running in fallback mode without embeddings")
    
    def _normalize_function_name(self, name: str) -> str:
        """
        Normalize function name by splitting camelCase and snake_case.
        
        Example: 'calculateAverage' -> 'calculate average'
                 'get_user_data' -> 'get user data'
        """
        # Split camelCase
        name = re.sub(r'(?<!^)(?=[A-Z])', ' ', name)
        # Split snake_case and underscores
        name = name.replace('_', ' ').replace('-', ' ')
        # Normalize whitespace
        name = ' '.join(name.split())
        return name.lower()
    
    def _extract_tokens_from_ast(self, node: ast.AST) -> List[str]:
        """
        Extract meaningful tokens from AST node (function body).
        
        Extracts:
        - Variable names (ast.Name)
        - Attribute names (ast.Attribute)
        - Function call names (ast.Call)
        - Imported modules (ast.Import, ast.ImportFrom)
        - String literals that look meaningful
        - Keywords
        """
        tokens = []
        
        for child in ast.walk(node):
            # Variable and function names
            if isinstance(child, ast.Name):
                # Skip single-letter variables and common placeholders
                if len(child.id) > 1 and child.id not in ['i', 'j', 'k', 'x', 'y', 'z', 'self', 'cls']:
                    tokens.append(child.id)
            
            # Attribute access (e.g., obj.method, module.function)
            elif isinstance(child, ast.Attribute):
                if child.attr and len(child.attr) > 1:
                    tokens.append(child.attr)
            
            # Function calls
            elif isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if child.func.id and len(child.func.id) > 1:
                        tokens.append(child.func.id)
                elif isinstance(child.func, ast.Attribute):
                    if child.func.attr and len(child.func.attr) > 1:
                        tokens.append(child.func.attr)
            
            # String literals (docstrings, meaningful strings)
            elif isinstance(child, ast.Constant) and isinstance(child.value, str):
                # Only include strings that look meaningful (not too short, not just whitespace)
                s = child.value.strip()
                if len(s) > 3 and not s.startswith('http'):
                    # Take first few words
                    words = s.split()[:5]
                    tokens.extend([w.lower() for w in words if len(w) > 2])
            
            # Import statements
            elif isinstance(child, ast.Import):
                for alias in child.names:
                    if alias.name:
                        # Extract module name parts
                        parts = alias.name.split('.')
                        tokens.extend([p for p in parts if len(p) > 1])
            
            elif isinstance(child, ast.ImportFrom):
                if child.module:
                    parts = child.module.split('.')
                    tokens.extend([p for p in parts if len(p) > 1])
                for alias in child.names:
                    if alias.name and len(alias.name) > 1:
                        tokens.append(alias.name)
        
        # Remove duplicates, filter out common Python keywords
        python_keywords = {
            'def', 'if', 'else', 'elif', 'for', 'while', 'return', 'import',
            'from', 'as', 'try', 'except', 'finally', 'with', 'pass', 'break',
            'continue', 'class', 'is', 'in', 'and', 'or', 'not', 'True', 'False',
            'None', 'print', 'len', 'str', 'int', 'float', 'list', 'dict', 'set'
        }
        
        tokens = [t.lower() for t in tokens if t.lower() not in python_keywords]
        return list(set(tokens))
    
    def _normalize_docstring(self, docstring: Optional[str]) -> Optional[str]:
        """
        Normalize docstring by extracting first sentence and cleaning.
        
        Removes common boilerplate and takes the first meaningful sentence.
        """
        if not docstring:
            return None
        
        # Remove leading/trailing whitespace
        doc = docstring.strip()
        
        # Remove common docstring markers
        doc = re.sub(r'^"""\s*', '', doc)
        doc = re.sub(r'\s*"""$', '', doc)
        doc = re.sub(r"^'''\s*", '', doc)
        doc = re.sub(r"\s*'''$", '', doc)
        
        # Extract first sentence (up to first period, exclamation, or question mark)
        first_sentence = re.split(r'[.!?]\s+', doc)[0]
        first_sentence = first_sentence.strip()
        
        # Limit length
        if len(first_sentence) > 200:
            first_sentence = first_sentence[:200]
        
        return first_sentence if first_sentence else None
    
    def _build_logic_text(self, tokens: List[str], max_tokens: int = 50) -> str:
        """
        Build a text representation from extracted tokens.
        
        Joins tokens into a space-separated string, limiting the number.
        """
        # Take most relevant tokens (limit to avoid noise)
        tokens = tokens[:max_tokens]
        return ' '.join(tokens)
    
    def _compute_similarity(self, text1: str, text2: str) -> float:
        """
        Compute cosine similarity between two texts using embeddings.
        
        Returns similarity score between 0 and 1.
        """
        if not self.model:
            # Fallback: simple word overlap
            words1 = set(text1.lower().split())
            words2 = set(text2.lower().split())
            if not words1 or not words2:
                return 0.0
            intersection = words1.intersection(words2)
            union = words1.union(words2)
            return len(intersection) / len(union) if union else 0.0
        
        try:
            embeddings = self.model.encode([text1, text2], convert_to_tensor=True)
            similarity = util.cos_sim(embeddings[0], embeddings[1]).item()
            return float(similarity)
        except Exception as e:
            logger.error(f"Error computing similarity: {e}")
            return 0.0
    
    def _batch_compute_similarities(
        self, 
        text_pairs: List[Tuple[str, str]]
    ) -> List[float]:
        """
        Compute similarities for multiple text pairs in batches.
        
        More efficient than computing one-by-one.
        """
        if not self.model:
            return [self._compute_similarity(t1, t2) for t1, t2 in text_pairs]
        
        similarities = []
        for i in range(0, len(text_pairs), self.batch_size):
            batch = text_pairs[i:i + self.batch_size]
            texts1 = [t1 for t1, _ in batch]
            texts2 = [t2 for _, t2 in batch]
            
            try:
                embeddings1 = self.model.encode(texts1, convert_to_tensor=True)
                embeddings2 = self.model.encode(texts2, convert_to_tensor=True)
                batch_similarities = util.cos_sim(embeddings1, embeddings2)
                
                # Extract diagonal (pairwise similarities)
                for j in range(len(batch)):
                    similarities.append(batch_similarities[j][j].item())
            except Exception as e:
                logger.error(f"Error in batch similarity computation: {e}")
                # Fallback to individual computation
                for t1, t2 in batch:
                    similarities.append(self._compute_similarity(t1, t2))
        
        return similarities
    
    def _determine_severity(
        self, 
        similarity: float, 
        function_name: str,
        doc_text: Optional[str],
        logic_text: str
    ) -> Tuple[str, str]:
        """
        Determine severity and issue message based on similarity and heuristics.
        
        Returns: (severity, issue_message)
        """
        # Security-related heuristics
        security_keywords = ['encrypt', 'hash', 'sign', 'decrypt', 'crypto', 'secure', 'password', 'token', 'auth']
        name_lower = function_name.lower()
        logic_lower = logic_text.lower()
        
        # Check for security-related function names
        has_security_name = any(kw in name_lower for kw in security_keywords)
        has_security_doc = doc_text and any(kw in doc_text.lower() for kw in security_keywords) if doc_text else False
        
        # Check if logic uses insecure methods
        insecure_patterns = ['base64', 'b64encode', 'b64decode', 'md5', 'sha1']
        uses_insecure = any(pattern in logic_lower for pattern in insecure_patterns)
        
        if (has_security_name or has_security_doc) and uses_insecure:
            return (
                "High",
                "Function name/docstring implies security (encryption/hashing) but implementation uses insecure methods (base64/MD5/SHA1)"
            )
        
        # Similarity-based severity
        if similarity < self.thresholds['high']:
            if not doc_text:
                return (
                    "High",
                    "Function name does not match implementation logic (missing docstring)"
                )
            return (
                "High",
                "Docstring and implementation logic show significant mismatch"
            )
        elif similarity < self.thresholds['medium']:
            if not doc_text:
                return (
                    "Medium",
                    "Function name partially matches implementation logic (missing docstring)"
                )
            return (
                "Medium",
                "Docstring and implementation logic show moderate mismatch"
            )
        else:
            # Similarity is OK, but check for other issues
            if not doc_text:
                return (
                    "Low",
                    "Missing docstring (function name matches logic)"
                )
            return None, None  # No issue
    
    def _extract_function_info(self, node: ast.FunctionDef, file_path: str, source_lines: List[str]) -> Dict[str, Any]:
        """
        Extract all relevant information from a function AST node.
        
        Returns dict with function metadata.
        """
        func_name = node.name
        docstring = ast.get_docstring(node)
        
        # Extract tokens from function body
        tokens = self._extract_tokens_from_ast(node)
        logic_text = self._build_logic_text(tokens)
        
        # Normalize texts
        name_text = self._normalize_function_name(func_name)
        doc_text = self._normalize_docstring(docstring)
        
        # Extract code snippet for evidence (first few lines of body)
        code_snippet = None
        if hasattr(node, 'lineno') and node.lineno:
            try:
                start_line = node.lineno - 1  # 0-indexed
                end_line = min(start_line + 5, len(source_lines))
                code_snippet = '\n'.join(source_lines[start_line:end_line])
            except Exception:
                pass
        
        return {
            'name': func_name,
            'name_text': name_text,
            'docstring': docstring,
            'doc_text': doc_text,
            'tokens': tokens,
            'logic_text': logic_text,
            'code_snippet': code_snippet,
            'file_path': file_path,
            'line_number': node.lineno if hasattr(node, 'lineno') else None
        }
    
    def _should_skip_file(self, file_path: str) -> bool:
        """Determine if a file should be skipped."""
        # Skip test files if configured
        if self.skip_test_files:
            test_patterns = ['test_', '_test.py', 'tests/', '/test/']
            if any(pattern in file_path for pattern in test_patterns):
                return True
        
        # Skip files in excluded directories
        path_parts = file_path.replace('\\', '/').split('/')
        for part in path_parts:
            if part in self.skip_dirs:
                return True
        
        return False
    
    def _walk_repository(self, repo_path: str) -> List[str]:
        """
        Walk repository and collect Python file paths.
        
        Returns list of file paths to analyze.
        """
        file_paths = []
        
        if not os.path.exists(repo_path):
            logger.error(f"Repository path does not exist: {repo_path}")
            return file_paths
        
        for root, dirs, files in os.walk(repo_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.skip_dirs]
            
            for filename in files:
                if filename.endswith('.py'):
                    file_path = os.path.join(root, filename)
                    if not self._should_skip_file(file_path):
                        file_paths.append(file_path)
        
        logger.info(f"Found {len(file_paths)} Python files to analyze")
        return file_paths
    
    def _parse_file(self, file_path: str) -> Tuple[Optional[ast.AST], List[str]]:
        """
        Parse a Python file and return AST and source lines.
        
        Returns: (ast_tree, source_lines) or (None, []) on error
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
                source_lines = source.splitlines()
            
            tree = ast.parse(source, filename=file_path)
            return tree, source_lines
        except SyntaxError as e:
            logger.warning(f"Syntax error in {file_path}: {e}")
            return None, []
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            return None, []
    
    def analyze_repository(self, repo_path: str) -> Dict[str, Any]:
        """
        Main analysis function - analyzes entire repository.
        
        Args:
            repo_path: Root path to the repository
            
        Returns:
            Structured report with issues and summary
        """
        logger.info(f"Starting semantic analysis of repository: {repo_path}")
        
        # Walk repository
        file_paths = self._walk_repository(repo_path)
        
        if not file_paths:
            return {
                "agent": "SCAA",
                "issues": [],
                "summary": {
                    "total_functions": 0,
                    "flagged_count": 0,
                    "avg_similarity": 0.0,
                    "files_analyzed": 0
                }
            }
        
        # Collect all functions
        all_functions = []
        
        for file_path in file_paths:
            tree, source_lines = self._parse_file(file_path)
            if not tree:
                continue
            
            # Extract functions from AST
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Skip private/internal functions if desired (optional)
                    # if node.name.startswith('_') and not node.name.startswith('__'):
                    #     continue
                    
                    func_info = self._extract_function_info(node, file_path, source_lines)
                    all_functions.append(func_info)
        
        logger.info(f"Extracted {len(all_functions)} functions")
        
        if not all_functions:
            return {
                "agent": "SCAA",
                "issues": [],
                "summary": {
                    "total_functions": 0,
                    "flagged_count": 0,
                    "avg_similarity": 0.0,
                    "files_analyzed": len(set(f['file_path'] for f in all_functions))
                }
            }
        
        # Compute similarities and identify issues
        issues = []
        similarities = []
        
        # Prepare text pairs for batch processing
        text_pairs = []
        function_metadata = []
        
        for func_info in all_functions:
            doc_text = func_info['doc_text']
            name_text = func_info['name_text']
            logic_text = func_info['logic_text']
            
            if doc_text:
                # Primary: compare docstring vs logic
                text_pairs.append((doc_text, logic_text))
                function_metadata.append({
                    'func_info': func_info,
                    'comparison_type': 'doc_logic',
                    'fallback': False
                })
            else:
                # Fallback: compare name vs logic
                text_pairs.append((name_text, logic_text))
                function_metadata.append({
                    'func_info': func_info,
                    'comparison_type': 'name_logic',
                    'fallback': True
                })
        
        # Batch compute similarities
        logger.info("Computing semantic similarities...")
        similarity_scores = self._batch_compute_similarities(text_pairs)
        
        # Process results and form issues
        for i, (func_meta, similarity) in enumerate(zip(function_metadata, similarity_scores)):
            func_info = func_meta['func_info']
            similarities.append(similarity)
            
            # Determine severity and issue message
            severity, issue_msg = self._determine_severity(
                similarity,
                func_info['name'],
                func_info['doc_text'],
                func_info['logic_text']
            )
            
            if severity:  # Issue detected
                # Build evidence
                evidence = {
                    'function_name': func_info['name'],
                    'similarity_score': round(similarity, 3),
                    'docstring': func_info['docstring'],
                    'logic_tokens': func_info['tokens'][:20],  # First 20 tokens
                    'code_snippet': func_info['code_snippet']
                }
                
                issues.append({
                    'file': func_info['file_path'],
                    'function': func_info['name'],
                    'issue': issue_msg,
                    'severity': severity,
                    'similarity': round(similarity, 3),
                    'evidence': evidence,
                    'line_number': func_info['line_number']
                })
        
        # Build summary
        avg_similarity = sum(similarities) / len(similarities) if similarities else 0.0
        unique_files = len(set(f['file_path'] for f in all_functions))
        
        summary = {
            'total_functions': len(all_functions),
            'flagged_count': len(issues),
            'avg_similarity': round(avg_similarity, 3),
            'files_analyzed': unique_files
        }
        
        logger.info(f"Analysis complete: {len(issues)} issues found in {len(all_functions)} functions")
        
        return {
            "agent": "SCAA",
            "issues": issues,
            "summary": summary
        }


def analyze_semantic(repo_path: str, **kwargs) -> Dict[str, Any]:
    """
    Public API function for semantic analysis.
    
    Args:
        repo_path: Root path to the repository
        **kwargs: Optional configuration (model_name, thresholds, etc.)
    
    Returns:
        Structured report with issues and summary
    """
    analyzer = SemanticAnalyzer(**kwargs)
    return analyzer.analyze_repository(repo_path)


# For testing/standalone execution
if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) > 1:
        repo_path = sys.argv[1]
    else:
        repo_path = os.getcwd()
    
    logger.info(f"Analyzing repository: {repo_path}")
    result = analyze_semantic(repo_path)
    
    # Output as JSON
    print(json.dumps(result, indent=2, ensure_ascii=False))

