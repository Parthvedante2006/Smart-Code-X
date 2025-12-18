"""
Hallucination Detection and Validation Agent (HDVA)

Detects references to symbols that cannot be resolved logically.
Answers: "Is the code talking about things that don't exist?"

Key Principles:
- Does NOT execute code
- Does NOT import user modules
- Does NOT analyze semantics/style/security
- Only detects unresolvable symbol references
- Uses AST to build symbol table and check usages
"""

import ast
import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional, Set
from collections import defaultdict

# Add static_agent_files to path to import collect_python_files
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'static_agent_files'))
from collect_python_files import collect_python_files

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Test file indicators
TEST_FILE_INDICATORS = {'test_', '_test.py', 'tests/', 'test.py'}

# Python standard library modules (base list - Python 3.8+)
# Using sys.stdlib_module_names if available, otherwise fallback list
try:
    STANDARD_LIBRARY = set(sys.stdlib_module_names)
except AttributeError:
    # Fallback for older Python versions
    STANDARD_LIBRARY = {
        'abc', 'argparse', 'array', 'ast', 'asyncio', 'atexit', 'base64',
        'binascii', 'bisect', 'builtins', 'bz2', 'calendar', 'cgi', 'cgitb',
        'cmath', 'cmd', 'code', 'codecs', 'codeop', 'collections', 'colorsys',
        'compileall', 'concurrent', 'configparser', 'contextlib', 'contextvars',
        'copy', 'copyreg', 'csv', 'ctypes', 'dataclasses', 'datetime', 'dbm',
        'decimal', 'difflib', 'dis', 'doctest', 'email', 'encodings', 'enum',
        'errno', 'faulthandler', 'fcntl', 'filecmp', 'fileinput', 'fnmatch',
        'fractions', 'ftplib', 'functools', 'gc', 'getopt', 'getpass',
        'gettext', 'glob', 'graphlib', 'grp', 'gzip', 'hashlib', 'heapq',
        'hmac', 'html', 'http', 'imaplib', 'imghdr', 'importlib', 'inspect',
        'io', 'ipaddress', 'itertools', 'json', 'keyword', 'lib2to3',
        'linecache', 'locale', 'logging', 'lzma', 'mailbox', 'mailcap',
        'marshal', 'math', 'mimetypes', 'mmap', 'modulefinder', 'multiprocessing',
        'netrc', 'nntplib', 'numbers', 'opcode', 'operator', 'optparse',
        'os', 'pathlib', 'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil',
        'platform', 'plistlib', 'poplib', 'posixpath', 'pprint', 'profile',
        'pstats', 'pty', 'py_compile', 'pyclbr', 'pydoc', 'queue', 'quopri',
        'random', 're', 'readline', 'reprlib', 'resource', 'rlcompleter',
        'runpy', 'sched', 'secrets', 'select', 'selectors', 'shelve', 'shlex',
        'shutil', 'signal', 'site', 'smtplib', 'sndhdr', 'socket', 'socketserver',
        'sre_compile', 'sre_constants', 'sre_parse', 'ssl', 'stat', 'statistics',
        'string', 'stringprep', 'struct', 'subprocess', 'sunau', 'symtable',
        'sys', 'sysconfig', 'syslog', 'tarfile', 'telnetlib', 'tempfile',
        'termios', 'test', 'textwrap', 'threading', 'time', 'timeit', 'tkinter',
        'token', 'tokenize', 'trace', 'traceback', 'tracemalloc', 'tty', 'turtle',
        'turtledemo', 'types', 'typing', 'unicodedata', 'unittest', 'urllib',
        'uu', 'uuid', 'venv', 'warnings', 'wave', 'weakref', 'webbrowser',
        'winreg', 'winsound', 'wsgiref', 'xdrlib', 'xml', 'xmlrpc', 'zipfile',
        'zipapp', 'zlib'
    }

# Built-in functions and classes (always available)
BUILTIN_FUNCTIONS = {
    'abs', 'all', 'any', 'ascii', 'bin', 'bool', 'bytearray', 'bytes',
    'callable', 'chr', 'classmethod', 'compile', 'complex', 'delattr',
    'dict', 'dir', 'divmod', 'enumerate', 'eval', 'exec', 'filter',
    'float', 'format', 'frozenset', 'getattr', 'globals', 'hasattr',
    'hash', 'help', 'hex', 'id', 'input', 'int', 'isinstance', 'issubclass',
    'iter', 'len', 'list', 'locals', 'map', 'max', 'min', 'next', 'object',
    'oct', 'open', 'ord', 'pow', 'print', 'property', 'range', 'repr',
    'reversed', 'round', 'set', 'setattr', 'slice', 'sorted', 'staticmethod',
    'str', 'sum', 'super', 'tuple', 'type', 'vars', 'zip', '__import__'
}

# Built-in exceptions (always available)
BUILTIN_EXCEPTIONS = {
    'BaseException', 'Exception', 'ArithmeticError', 'AssertionError',
    'AttributeError', 'BufferError', 'BytesWarning', 'DeprecationWarning',
    'EOFError', 'EnvironmentError', 'FloatingPointError', 'FutureWarning',
    'GeneratorExit', 'IOError', 'ImportError', 'ImportWarning',
    'IndentationError', 'IndexError', 'KeyError', 'KeyboardInterrupt',
    'LookupError', 'MemoryError', 'NameError', 'NotImplementedError',
    'OSError', 'OverflowError', 'PendingDeprecationWarning', 'ReferenceError',
    'ResourceWarning', 'RuntimeError', 'RuntimeWarning', 'StopIteration',
    'SyntaxError', 'SyntaxWarning', 'SystemError', 'SystemExit',
    'TabError', 'TypeError', 'UnboundLocalError', 'UnicodeDecodeError',
    'UnicodeEncodeError', 'UnicodeError', 'UnicodeTranslateError',
    'UnicodeWarning', 'UserWarning', 'ValueError', 'Warning',
    'ZeroDivisionError', 'BlockingIOError', 'ChildProcessError',
    'ConnectionError', 'BrokenPipeError', 'ConnectionAbortedError',
    'ConnectionRefusedError', 'ConnectionResetError', 'FileExistsError',
    'FileNotFoundError', 'InterruptedError', 'IsADirectoryError',
    'NotADirectoryError', 'PermissionError', 'ProcessLookupError',
    'TimeoutError', 'StopAsyncIteration', 'ModuleNotFoundError',
    'RecursionError', 'EncodingWarning'
}

# All built-ins (functions + exceptions + constants)
ALL_BUILTINS = BUILTIN_FUNCTIONS | BUILTIN_EXCEPTIONS | {
    'True', 'False', 'None', 'Ellipsis', 'NotImplemented', 'self', 'cls'
}

# Known libraries (well-known, don't flag as hallucination)
# If module is imported from this list, trust all its symbols
KNOWN_LIBS = {
    'tkinter',  # GUI library - wildcard imports common
    'numpy', 'pandas', 'matplotlib', 'scipy', 'sklearn', 'requests',
    'django', 'flask', 'fastapi', 'sqlalchemy', 'pytest', 'unittest',
    'pydantic', 'pyyaml', 'pillow', 'pygame', 'tensorflow', 'torch',
    'PIL', 'bs4', 'beautifulsoup4', 'pathlib', 'io', 'validators',
    'selenium', 'scrapy', 'pytest', 'nose', 'mock'
}


class SymbolTable:
    """
    Symbol table to track defined symbols in a file/module.
    """
    
    def __init__(self):
        self.functions: Set[str] = set()
        self.classes: Set[str] = set()
        self.variables: Set[str] = set()
        self.imports: Dict[str, str] = {}  # local_name -> source_module
        self.imported_modules: Set[str] = set()
        self.wildcard_imports: Set[str] = set()  # Modules with "from X import *"
        self.class_attributes: Dict[str, Set[str]] = defaultdict(set)
        self.class_methods: Dict[str, Set[str]] = defaultdict(set)
        
        # Scoped variables (tracked per scope)
        self.scoped_variables: Dict[ast.AST, Set[str]] = {}  # node -> {variable_names}
        self.all_scoped_variables: Set[str] = set()  # All variables from any scope
    
    def add_function(self, name: str):
        self.functions.add(name)
    
    def add_class(self, name: str):
        self.classes.add(name)
    
    def add_variable(self, name: str):
        self.variables.add(name)
        self.all_scoped_variables.add(name)
    
    def add_scoped_variable(self, name: str, scope_node: Optional[ast.AST] = None):
        """Add a scoped variable (loop var, comprehension var, function arg, etc.)"""
        self.all_scoped_variables.add(name)
        if scope_node:
            if scope_node not in self.scoped_variables:
                self.scoped_variables[scope_node] = set()
            self.scoped_variables[scope_node].add(name)
    
    def add_import(self, local_name: str, source_module: str):
        """Add an import: local_name is how it's used, source_module is where it comes from."""
        self.imports[local_name] = source_module
        self.imported_modules.add(source_module.split('.')[0])
        self.all_scoped_variables.add(local_name)  # Imported names are available
    
    def add_wildcard_import(self, module: str):
        """Add a wildcard import - assume ALL public symbols from this module are available."""
        self.wildcard_imports.add(module.split('.')[0])  # Track base module
    
    def is_defined(self, name: str) -> bool:
        """Check if a symbol is defined locally."""
        return (name in self.functions or 
                name in self.classes or 
                name in self.variables or 
                name in self.imports or
                name in self.all_scoped_variables)
    
    def get_imported_module(self, name: str) -> Optional[str]:
        """Get the source module for an imported symbol."""
        return self.imports.get(name)
    
    def has_wildcard_import(self, module_base: str) -> bool:
        """Check if there's a wildcard import from this module."""
        return module_base in self.wildcard_imports


class HallucinationDetector:
    """
    Detects hallucinated (unresolvable) symbol references in Python code.
    """
    
    def __init__(self):
        self.symbol_tables: Dict[str, SymbolTable] = {}  # file_path -> SymbolTable
    
    def should_skip_file(self, file_path: str) -> bool:
        """Skip test files."""
        file_str = str(file_path).lower()
        for indicator in TEST_FILE_INDICATORS:
            if indicator in file_str:
                return True
        return False
    
    def read_file_safely(self, file_path: Path) -> Optional[str]:
        """Read a Python file safely, handling encoding issues."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
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
        """Parse Python code into AST safely."""
        try:
            return ast.parse(content, filename=file_path)
        except SyntaxError as e:
            logger.debug(f"Syntax error in {file_path}: {e}. Skipping (Static Agent handles this).")
            return None
        except Exception as e:
            logger.warning(f"Failed to parse AST for {file_path}: {e}")
            return None
    
    def is_dynamic_access(self, node: ast.AST) -> bool:
        """
        Check if node uses dynamic attribute access (getattr, setattr, hasattr).
        These are impossible to resolve statically - skip them.
        """
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if child.func.id in ('getattr', 'setattr', 'hasattr', '__import__'):
                        return True
        return False
    
    def is_dynamic_import(self, node: ast.AST) -> bool:
        """Check if node contains dynamic import (__import__ call)."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name) and child.func.id == '__import__':
                    return True
        return False
    
    def build_symbol_table(self, tree: ast.AST, file_path: str) -> SymbolTable:
        """Build symbol table from AST, tracking all scoped variables."""
        symbol_table = SymbolTable()
        
        # First pass: collect definitions (functions, classes, imports)
        for node in ast.walk(tree):
            # Collect function definitions
            if isinstance(node, ast.FunctionDef):
                symbol_table.add_function(node.name)
                # Track function arguments
                for arg in node.args.args:
                    symbol_table.add_scoped_variable(arg.arg, node)
                # Track *args and **kwargs if present
                if node.args.vararg:
                    symbol_table.add_scoped_variable(node.args.vararg.arg, node)
                if node.args.kwarg:
                    symbol_table.add_scoped_variable(node.args.kwarg.arg, node)
            
            # Collect class definitions
            if isinstance(node, ast.ClassDef):
                symbol_table.add_class(node.name)
                # Collect class methods
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        symbol_table.class_methods[node.name].add(item.name)
            
            # Collect variable assignments (all levels)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    self._extract_assignment_targets(target, symbol_table, node)
            
            # Collect imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname if alias.asname else alias.name.split('.')[0]
                    symbol_table.add_import(local_name, alias.name)
            
            if isinstance(node, ast.ImportFrom):
                if node.module:
                    # Check for wildcard import
                    for alias in node.names:
                        if alias.name == '*':
                            # Wildcard import - track the module
                            symbol_table.add_wildcard_import(node.module)
                        else:
                            # Named import
                            local_name = alias.asname if alias.asname else alias.name
                            symbol_table.add_import(local_name, node.module)
        
        # Second pass: collect scoped variables (loops, comprehensions, exception handlers)
        for node in ast.walk(tree):
            # Loop variables (for x in ...)
            if isinstance(node, ast.For):
                if isinstance(node.target, ast.Name):
                    symbol_table.add_scoped_variable(node.target.id, node)
                elif isinstance(node.target, ast.Tuple):
                    for elt in node.target.elts:
                        if isinstance(elt, ast.Name):
                            symbol_table.add_scoped_variable(elt.id, node)
            
            # Comprehension variables ([x for x in ...])
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                for generator in node.generators:
                    if isinstance(generator.target, ast.Name):
                        symbol_table.add_scoped_variable(generator.target.id, node)
                    elif isinstance(generator.target, ast.Tuple):
                        for elt in generator.target.elts:
                            if isinstance(elt, ast.Name):
                                symbol_table.add_scoped_variable(elt.id, node)
            
            # Exception handler aliases (except Exception as e:)
            if isinstance(node, ast.ExceptHandler):
                if node.name:
                    symbol_table.add_scoped_variable(node.name, node)
        
        return symbol_table
    
    def _extract_assignment_targets(self, target: ast.AST, symbol_table: SymbolTable, assignment_node: ast.AST):
        """Recursively extract variable names from assignment targets."""
        if isinstance(target, ast.Name):
            symbol_table.add_scoped_variable(target.id, assignment_node)
        elif isinstance(target, ast.Tuple):
            for elt in target.elts:
                self._extract_assignment_targets(elt, symbol_table, assignment_node)
        elif isinstance(target, ast.List):
            for elt in target.elts:
                self._extract_assignment_targets(elt, symbol_table, assignment_node)
    
    def is_standard_library(self, module_name: str) -> bool:
        """Check if module is from Python standard library."""
        base_module = module_name.split('.')[0]
        return base_module in STANDARD_LIBRARY
    
    def is_known_library(self, module_name: str) -> bool:
        """Check if module is a known library (don't flag)."""
        base_module = module_name.split('.')[0]
        return base_module in KNOWN_LIBS
    
    def is_builtin(self, name: str) -> bool:
        """Check if name is a built-in (function, exception, or constant)."""
        return name in ALL_BUILTINS
    
    def resolve_attribute_chain(self, node: ast.Attribute, symbol_table: SymbolTable) -> Tuple[Optional[str], Optional[str]]:
        """
        Resolve an attribute chain (e.g., obj.method).
        Returns (base_object_name, attribute_name) or (None, None) if cannot resolve.
        """
        # Walk up the attribute chain
        parts = []
        current = node
        
        while isinstance(current, ast.Attribute):
            parts.insert(0, current.attr)
            current = current.value
        
        if not parts:
            return None, None
        
        attribute_name = parts[-1]
        
        # Get base object
        if isinstance(current, ast.Name):
            base_name = current.id
            return base_name, attribute_name
        
        return None, None
    
    def check_symbol_resolution(self, name: str, symbol_table: SymbolTable) -> Tuple[bool, Optional[str]]:
        """
        Check if a symbol can be resolved.
        Returns (is_resolved, reason_if_unresolved)
        
        IMPORTANT: Only flag if symbol is truly unresolvable.
        """
        # 1. Check built-ins first (always available)
        if self.is_builtin(name):
            return True, None
        
        # 2. Check local definitions (functions, classes, variables, imports)
        if symbol_table.is_defined(name):
            return True, None
        
        # 3. Check if it's from a specific import
        imported_module = symbol_table.get_imported_module(name)
        if imported_module:
            base_module = imported_module.split('.')[0]
            # Trust standard library and known libraries
            if self.is_standard_library(imported_module) or self.is_known_library(imported_module):
                return True, None
        
        # 4. Check wildcard imports - trust symbols from wildcard imports of known/standard libraries
        # We can't statically determine which symbols come from wildcard imports,
        # but we trust wildcard imports from known/standard libraries
        for wildcard_module in symbol_table.wildcard_imports:
            if self.is_known_library(wildcard_module) or self.is_standard_library(wildcard_module):
                # Trust that ANY symbol might come from this wildcard import
                # This prevents false positives with "from tkinter import *" etc.
                return True, None
        
        # 5. Check if it's a module name that was imported
        if name in symbol_table.imported_modules:
            if self.is_standard_library(name) or self.is_known_library(name):
                return True, None
        
        # 6. If we reach here, symbol cannot be resolved
        # But be conservative - only flag if it's clearly a problem
        return False, f"Symbol '{name}' is not defined and cannot be resolved"
    
    def check_method_call(self, base_name: str, method_name: str, 
                         symbol_table: SymbolTable) -> Tuple[Optional[bool], Optional[str]]:
        """
        Check if a method call is valid.
        Returns (is_valid, reason_if_invalid)
        - (True, None): Valid
        - (False, reason): Invalid (flag it)
        - (None, None): Ambiguous (skip, don't flag)
        """
        # If base is builtin, assume valid
        if self.is_builtin(base_name):
            return True, None
        
        # If base is imported from standard/known library, assume valid
        # We can't verify all methods without importing, so we trust them
        if base_name in symbol_table.imported_modules:
            base_module = base_name.split('.')[0] if '.' in base_name else base_name
            if self.is_standard_library(base_name) or self.is_known_library(base_name):
                return True, None
        
        # Check wildcard imports
        for wildcard_module in symbol_table.wildcard_imports:
            if base_name in symbol_table.imported_modules or self.is_known_library(wildcard_module):
                return True, None
        
        # If base is a class we defined, check if method exists
        if base_name in symbol_table.classes:
            if method_name in symbol_table.class_methods[base_name]:
                return True, None
            # Only flag if we're CERTAIN the class doesn't have the method
            # (This is conservative - we skip if uncertain)
            return None, None  # Skip - might be a valid method we haven't seen
        
        # Unknown base - skip (too ambiguous, could be user-defined)
        return None, None
    
    def extract_usages(self, tree: ast.AST, symbol_table: SymbolTable, 
                      file_path: str) -> List[Dict[str, Any]]:
        """
        Extract symbol usages and check for hallucinations.
        Only flags symbols that are USED (Load context), not assigned (Store context).
        Returns list of hallucination issues.
        """
        issues = []
        
        for node in ast.walk(tree):
            # Skip dynamic access patterns
            if self.is_dynamic_access(node):
                continue
            
            # Check Name nodes - ONLY in Load context (usage, not assignment)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                name = node.id
                
                # Skip if it's an assignment target (Store context)
                # We already handle assignments separately
                
                # Check if symbol can be resolved
                is_resolved, reason = self.check_symbol_resolution(name, symbol_table)
                
                if not is_resolved and reason:
                    # Only flag if we're certain it's a problem
                    # Don't flag ambiguous cases
                    issues.append({
                        'file': file_path,
                        'line': node.lineno,
                        'symbol': name,
                        'issue': reason,
                        'type': 'undefined_symbol',
                        'severity': 'High'
                    })
            
            # Check Attribute nodes (method/attribute access) - only in Load context
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                base_name, attr_name = self.resolve_attribute_chain(node, symbol_table)
                
                if base_name and attr_name:
                    # Check if method call is valid
                    is_valid, reason = self.check_method_call(base_name, attr_name, symbol_table)
                    
                    # Only flag if explicitly False (invalid), skip if None (ambiguous)
                    if is_valid is False and reason:
                        issues.append({
                            'file': file_path,
                            'line': node.lineno,
                            'symbol': f"{base_name}.{attr_name}",
                            'issue': reason,
                            'type': 'undefined_method',
                            'severity': 'Medium'
                        })
        
        return issues
    
    def analyze_file(self, file_path: Path, relative_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Analyze a single Python file for hallucinations."""
        issues = []
        
        # Use relative path if provided, otherwise use file_path as string
        file_path_str = relative_path if relative_path else str(file_path)
        
        # Skip test files
        if self.should_skip_file(file_path_str):
            return issues
        
        # Read file
        content = self.read_file_safely(file_path)
        if not content:
            return issues
        
        # Parse AST
        tree = self.parse_ast_safely(content, str(file_path))
        if not tree:
            return issues
        
        # Build symbol table
        symbol_table = self.build_symbol_table(tree, file_path_str)
        self.symbol_tables[file_path_str] = symbol_table
        
        # Extract and check usages
        file_issues = self.extract_usages(tree, symbol_table, file_path_str)
        
        # Deduplicate issues (same symbol on same line)
        seen = set()
        for issue in file_issues:
            key = (issue['file'], issue['line'], issue['symbol'])
            if key not in seen:
                seen.add(key)
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
        logger.info(f"Starting hallucination detection for session: {session_id}")
        
        temp_folder_path = Path(temp_folder)
        if not temp_folder_path.exists():
            logger.warning(f"Temp folder does not exist: {temp_folder}")
            return {
                "agent": "HDVA",
                "session_id": session_id,
                "issues": [],
                "summary": {
                    "total_files": 0,
                    "files_analyzed": 0,
                    "hallucinations_found": 0
                }
            }
        
        # Get all Python files from temp folder
        collected_files = [str(f.relative_to(temp_folder_path)) 
                          for f in temp_folder_path.rglob("*.py")]
        
        if not collected_files:
            logger.warning("No Python files found in temp folder")
            return {
                "agent": "HDVA",
                "session_id": session_id,
                "issues": [],
                "summary": {
                    "total_files": 0,
                    "files_analyzed": 0,
                    "hallucinations_found": 0
                }
            }
        
        logger.info(f"Found {len(collected_files)} Python files")
        
        # Analyze each file
        all_issues = []
        files_analyzed_count = 0
        
        for relative_file in collected_files:
            file_path = temp_folder_path / relative_file
            if not file_path.exists():
                continue
            
            try:
                file_issues = self.analyze_file(file_path, relative_path=str(relative_file))
                all_issues.extend(file_issues)
                files_analyzed_count += 1
                
                logger.info(f"Analyzed {relative_file}: {len(file_issues)} hallucinations found")
            except Exception as e:
                logger.warning(f"Error analyzing {relative_file}: {e}")
                continue
        
        # Format issues for output
        formatted_issues = []
        for issue in all_issues:
            function_name = None
            try:
                issue_file_path = temp_folder_path / issue['file']
                if issue_file_path.exists():
                    content = self.read_file_safely(issue_file_path)
                    if content:
                        tree = self.parse_ast_safely(content, str(issue_file_path))
                        if tree:
                            for node in ast.walk(tree):
                                if isinstance(node, ast.FunctionDef):
                                    if node.lineno <= issue['line']:
                                        if hasattr(node, 'end_lineno') and node.end_lineno:
                                            if issue['line'] <= node.end_lineno:
                                                function_name = node.name
                                                break
                                        else:
                                            function_name = node.name
            except:
                pass
            
            formatted_issues.append({
                'file': issue['file'],
                'function': function_name,
                'line': issue['line'],
                'issue': issue['issue'],
                'severity': issue['severity'],
                'probability': 0.85 if issue['severity'] == 'High' else 0.70,
                'symbol': issue.get('symbol', ''),
                'type': issue.get('type', 'unknown')
            })
        
        summary = {
            "total_files": len(collected_files),
            "files_analyzed": files_analyzed_count,
            "hallucinations_found": len(formatted_issues)
        }
        
        logger.info(f"Hallucination detection complete: {len(formatted_issues)} issues found")
        
        result = {
            "agent": "HDVA",
            "session_id": session_id,
            "issues": formatted_issues,
            "summary": summary
        }
        
        # Save results to JSON file
        self._save_results(result, session_id, results_base_folder)
        
        return result
    
    def analyze_repository(self, repo_path: str) -> Dict[str, Any]:
        """
        Analyze an entire repository for hallucinated symbols.
        
        Args:
            repo_path: Path to repository directory
            
        Returns:
            Dictionary with issues and summary
        """
        logger.info(f"Starting hallucination detection for repository: {repo_path}")
        
        # Collect Python files
        logger.info("Collecting Python files...")
        base_temp_folder = os.path.join(os.path.dirname(__file__), "temp")
        collected_files, stats, session_id = collect_python_files(repo_path, base_temp_folder)
        
        if not collected_files:
            logger.warning("No Python files found to analyze")
            return {
                "agent": "HDVA",
                "issues": [],
                "summary": {
                    "total_files": 0,
                    "files_analyzed": 0,
                    "hallucinations_found": 0
                }
            }
        
        logger.info(f"Found {len(collected_files)} Python files")
        
        # Analyze each file
        all_issues = []
        files_analyzed_count = 0
        temp_folder = Path(base_temp_folder) / session_id
        
        for relative_file in collected_files:
            file_path = temp_folder / relative_file
            if not file_path.exists():
                continue
            
            try:
                # Pass relative file path for consistent issue reporting
                file_issues = self.analyze_file(file_path, relative_path=str(relative_file))
                all_issues.extend(file_issues)
                files_analyzed_count += 1
                
                logger.info(f"Analyzed {relative_file}: {len(file_issues)} hallucinations found")
            except Exception as e:
                logger.warning(f"Error analyzing {relative_file}: {e}")
                continue
        
        # Format issues for output (match expected format)
        formatted_issues = []
        for issue in all_issues:
            # Get function name if available (find containing function)
            function_name = None
            try:
                # Find the actual file path
                issue_file_path = temp_folder / issue['file']
                if issue_file_path.exists():
                    content = self.read_file_safely(issue_file_path)
                    if content:
                        tree = self.parse_ast_safely(content, str(issue_file_path))
                        if tree:
                            # Find function containing this line
                            for node in ast.walk(tree):
                                if isinstance(node, ast.FunctionDef):
                                    if node.lineno <= issue['line']:
                                        if hasattr(node, 'end_lineno') and node.end_lineno:
                                            if issue['line'] <= node.end_lineno:
                                                function_name = node.name
                                                break
                                        else:
                                            # Estimate end line - use last function found
                                            function_name = node.name
            except:
                pass
            
            formatted_issues.append({
                'file': issue['file'],
                'function': function_name,
                'line': issue['line'],
                'issue': issue['issue'],
                'severity': issue['severity'],
                'probability': 0.85 if issue['severity'] == 'High' else 0.70,  # Confidence score
                'symbol': issue.get('symbol', ''),
                'type': issue.get('type', 'unknown')
            })
        
        # Build summary
        summary = {
            "total_files": len(collected_files),
            "files_analyzed": files_analyzed_count,
            "hallucinations_found": len(formatted_issues)
        }
        
        logger.info(f"Hallucination detection complete: {len(formatted_issues)} issues found")
        
        result = {
            "agent": "HDVA",
            "session_id": session_id,
            "issues": formatted_issues,
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
            
            output_file = results_folder / "hallucination_agent.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Hallucination agent results saved to: {output_file}")
        except Exception as e:
            logger.warning(f"Failed to save hallucination agent results: {e}")


def analyze_hdva(repo_path: str) -> Dict[str, Any]:
    """
    Main entry point for hallucination detection.
    
    This function is called by the orchestrator.
    
    Args:
        repo_path: Path to repository directory
        
    Returns:
        Dictionary with HDVA analysis results
    """
    detector = HallucinationDetector()
    return detector.analyze_repository(repo_path)


# For testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python hallucination_agent.py <repo_path>")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    results = analyze_hdva(repo_path)
    
    import json
    print(json.dumps(results, indent=2, ensure_ascii=False))

