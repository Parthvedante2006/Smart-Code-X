"""
IERA - Intelligent Enhancement Recommendation Agent

Primary Role: Recommender Agent (not analyzer, not enforcer)

Answers: "Given what we already know about this code, what improvements would 
meaningfully increase quality, safety, clarity, or maintainability?"

Key Principles:
- Never judges correctness
- Never blocks builds
- Never modifies code
- Never duplicates other agents
- Never assumes intent
- Advisory only - helps developers, not police them
"""

import ast
import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Test file indicators
TEST_FILE_INDICATORS = {'test_', '_test.py', 'tests/', 'test.py'}

# Recommendation strength levels
RECOMMENDATION_STRENGTHS = {
    'Info': 1,           # Nice-to-have
    'Suggestion': 2,     # Useful improvement
    'Strong Suggestion': 3  # High impact, still optional
}

# Recommendation categories
RECOMMENDATION_CATEGORIES = {
    'intent_clarity': 'Intent Clarity',
    'security_hygiene': 'Security Hygiene',
    'maintainability': 'Maintainability',
    'api_design': 'API Design & Usability',
    'error_handling': 'Error Handling',
    'consistency_style': 'Consistency & Style'
}


class RecommendationGenerator:
    """
    Generates actionable recommendations based on outputs from other agents.
    Does NOT re-analyze code - only uses structured outputs from SAA, SCAA, HDVA.
    """
    
    def __init__(self):
        self.recommendations: List[Dict[str, Any]] = []
        self.files_to_skip: Set[str] = set()
    
    def should_skip_file(self, file_path: str) -> bool:
        """Skip test files and generated code."""
        file_str = str(file_path).lower()
        for indicator in TEST_FILE_INDICATORS:
            if indicator in file_str:
                return True
        return False
    
    def collect_context_by_file(
        self, 
        saa_output: Any, 
        scaa_output: Dict[str, Any], 
        hdva_output: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Organize issues by file for easier processing.
        
        Returns:
            Dictionary mapping file_path -> {saa_issues, scaa_issues, hdva_issues}
        """
        context_by_file: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'saa_issues': [],
            'scaa_issues': [],
            'hdva_issues': [],
            'file_stats': {}
        })
        
        # Collect SAA issues - handle both dict and list formats
        if isinstance(saa_output, dict):
            # Static agent returns dict with 'issues' key
            for issue in saa_output.get('issues', []):
                file_path = issue.get('file', 'unknown')
                context_by_file[file_path]['saa_issues'].append(issue)
            
            # Collect file stats from SAA
            if 'file_stats' in saa_output:
                for file_path, stats in saa_output['file_stats'].items():
                    context_by_file[file_path]['file_stats'] = stats
        elif isinstance(saa_output, list):
            # Legacy format - list of issues
            for issue in saa_output:
                file_path = issue.get('file', 'unknown')
                context_by_file[file_path]['saa_issues'].append(issue)
        
        # Collect SCAA issues
        if isinstance(scaa_output, dict):
            for issue in scaa_output.get('issues', []):
                file_path = issue.get('file', 'unknown')
                context_by_file[file_path]['scaa_issues'].append(issue)
        
        # Collect HDVA issues
        if isinstance(hdva_output, dict):
            for issue in hdva_output.get('issues', []):
                file_path = issue.get('file', 'unknown')
                context_by_file[file_path]['hdva_issues'].append(issue)
        
        return dict(context_by_file)
    
    def should_generate_recommendation(
        self, 
        file_path: str, 
        function_name: Optional[str] = None,
        context: Dict[str, Any] = None
    ) -> bool:
        """
        Decide if a recommendation is worth generating.
        
        Skip if:
        - File is trivial/test/generated
        - Function is trivial
        - No relevant signals
        """
        # Skip test files
        if self.should_skip_file(file_path):
            return False
        
        # Skip if no relevant context
        if not context:
            return False
        
        # If there are issues from any agent, worth recommending
        if (context.get('saa_issues') or 
            context.get('scaa_issues') or 
            context.get('hdva_issues')):
            return True
        
        # Even if no issues, might have structural signals worth recommending
        file_stats = context.get('file_stats', {})
        if file_stats:
            return True
        
        return False
    
    def generate_intent_clarity_recommendations(
        self, 
        file_path: str, 
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate recommendations for intent clarity."""
        recommendations = []
        
        # Check SCAA issues (semantic mismatches)
        for issue in context.get('scaa_issues', []):
            similarity = issue.get('similarity', 1.0)
            function_name = issue.get('function', 'unknown')
            
            if similarity < 0.65:  # Low similarity indicates mismatch
                if similarity < 0.40:
                    strength = 'Strong Suggestion'
                else:
                    strength = 'Suggestion'
                
                recommendations.append({
                    'file': file_path,
                    'function': function_name,
                    'line': issue.get('line_number'),
                    'category': 'intent_clarity',
                    'strength': strength,
                    'title': 'Align function name with implementation',
                    'explanation': (
                        f"Function '{function_name}' has a similarity score of {similarity:.2f} "
                        f"between its declared intent and actual implementation. "
                        f"Consider renaming the function to better match what it does, "
                        f"or refactoring the implementation to match its name."
                    ),
                    'suggestions': [
                        'Review the function implementation and update the function name accordingly',
                        'Or refactor the code to match the current function name\'s intent',
                        'Consider adding or updating the docstring to clarify the function\'s purpose'
                    ],
                    'evidence': {
                        'similarity_score': similarity,
                        'intent_text': issue.get('evidence', {}).get('intent_text', ''),
                        'source': 'SCAA'
                    }
                })
        
        # Check for missing docstrings (from SAA or general analysis)
        for issue in context.get('saa_issues', []):
            if 'docstring' in issue.get('message', '').lower() or 'docstring' in issue.get('type', '').lower():
                function_name = issue.get('function') or issue.get('symbol', 'unknown')
                recommendations.append({
                    'file': file_path,
                    'function': function_name,
                    'line': issue.get('line'),
                    'category': 'intent_clarity',
                    'strength': 'Suggestion',
                    'title': 'Add function docstring',
                    'explanation': (
                        f"Function '{function_name}' lacks a docstring. "
                        f"Adding a clear docstring improves code readability and helps other "
                        f"developers understand the function's purpose, parameters, and return value."
                    ),
                    'suggestions': [
                        'Add a docstring describing what the function does',
                        'Document parameters and their types',
                        'Document the return value and its type'
                    ],
                    'evidence': {
                        'source': 'SAA'
                    }
                })
        
        return recommendations
    
    def generate_security_hygiene_recommendations(
        self, 
        file_path: str, 
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate recommendations for security hygiene."""
        recommendations = []
        
        # Check SCAA security issues
        for issue in context.get('scaa_issues', []):
            if issue.get('severity') == 'High' and 'security' in issue.get('issue', '').lower():
                function_name = issue.get('function', 'unknown')
                
                recommendations.append({
                    'file': file_path,
                    'function': function_name,
                    'line': issue.get('line_number'),
                    'category': 'security_hygiene',
                    'strength': 'Strong Suggestion',
                    'title': 'Review security implementation',
                    'explanation': (
                        f"Function '{function_name}' uses security-related terms but may be "
                        f"using weak or inappropriate security primitives. "
                        f"Review the implementation to ensure it meets security best practices."
                    ),
                    'suggestions': [
                        'Use strong encryption algorithms (e.g., AES, Fernet) instead of base64 encoding',
                        'Use secure hashing (e.g., SHA-256, bcrypt) instead of MD5 or SHA1',
                        'Consider using established security libraries for cryptographic operations',
                        'Add clear documentation about security assumptions and limitations'
                    ],
                    'evidence': {
                        'issue_description': issue.get('issue', ''),
                        'source': 'SCAA'
                    }
                })
        
        return recommendations
    
    def generate_maintainability_recommendations(
        self, 
        file_path: str, 
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate recommendations for maintainability."""
        recommendations = []
        
        file_stats = context.get('file_stats', {})
        
        # Check complexity metrics
        radon_metrics = file_stats.get('radon_metrics', {})
        if isinstance(radon_metrics, dict):
            complexity_data = radon_metrics.get('complexity', 0)
            # Handle complexity - it can be a list of functions or a number
            if isinstance(complexity_data, list):
                # Get max complexity from list of functions
                max_complexity = max((item.get('complexity', 0) for item in complexity_data if isinstance(item, dict)), default=0)
                if max_complexity > 10:
                    complexity = max_complexity
                else:
                    complexity = None
            elif isinstance(complexity_data, (int, float)):
                complexity = complexity_data
            else:
                complexity = None
            
            if complexity and complexity > 10:
                recommendations.append({
                    'file': file_path,
                    'function': None,
                    'line': None,
                    'category': 'maintainability',
                    'strength': 'Suggestion',
                    'title': 'Reduce cyclomatic complexity',
                    'explanation': (
                        f"This file has a cyclomatic complexity of {complexity}, which is relatively high. "
                        f"High complexity makes code harder to understand and maintain."
                    ),
                    'suggestions': [
                        'Break down complex functions into smaller, single-purpose functions',
                        'Extract helper functions for complex logic',
                        'Consider using early returns to reduce nesting',
                        'Simplify conditional logic where possible'
                    ],
                    'evidence': {
                        'complexity_score': complexity,
                        'source': 'SAA'
                    }
                })
        
        # Check for large functions (from SAA issues)
        for issue in context.get('saa_issues', []):
            if 'too many' in issue.get('message', '').lower() or 'large' in issue.get('message', '').lower():
                function_name = issue.get('function') or issue.get('symbol', 'unknown')
                recommendations.append({
                    'file': file_path,
                    'function': function_name,
                    'line': issue.get('line'),
                    'category': 'maintainability',
                    'strength': 'Suggestion',
                    'title': 'Consider splitting large function',
                    'explanation': (
                        f"Function '{function_name}' appears to be doing too much. "
                        f"Breaking it into smaller functions improves readability and maintainability."
                    ),
                    'suggestions': [
                        'Extract related functionality into separate helper functions',
                        'Identify distinct responsibilities and separate them',
                        'Consider using a class if the function manages state'
                    ],
                    'evidence': {
                        'source': 'SAA'
                    }
                })
        
        return recommendations
    
    def generate_api_design_recommendations(
        self, 
        file_path: str, 
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate recommendations for API design and usability."""
        recommendations = []
        
        # Check for too many parameters (from SAA)
        for issue in context.get('saa_issues', []):
            message = issue.get('message', '').lower()
            if 'too many' in message and 'parameter' in message:
                function_name = issue.get('function') or issue.get('symbol', 'unknown')
                recommendations.append({
                    'file': file_path,
                    'function': function_name,
                    'line': issue.get('line'),
                    'category': 'api_design',
                    'strength': 'Suggestion',
                    'title': 'Consider using configuration object',
                    'explanation': (
                        f"Function '{function_name}' has many parameters, which can make it "
                        f"difficult to use and maintain. Consider grouping related parameters."
                    ),
                    'suggestions': [
                        'Group related parameters into a configuration object or dataclass',
                        'Use keyword-only arguments for better API clarity',
                        'Consider using default values for optional parameters',
                        'Document all parameters clearly'
                    ],
                    'evidence': {
                        'source': 'SAA'
                    }
                })
        
        return recommendations
    
    def generate_error_handling_recommendations(
        self, 
        file_path: str, 
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate recommendations for error handling."""
        recommendations = []
        
        # Check for broad exception handling (from SAA)
        for issue in context.get('saa_issues', []):
            message = issue.get('message', '').lower()
            if 'bare except' in message or 'too broad' in message:
                function_name = issue.get('function') or issue.get('symbol', 'unknown')
                recommendations.append({
                    'file': file_path,
                    'function': function_name,
                    'line': issue.get('line'),
                    'category': 'error_handling',
                    'strength': 'Suggestion',
                    'title': 'Use specific exception handling',
                    'explanation': (
                        f"Function '{function_name}' uses broad exception handling. "
                        f"Specific exception types make error handling more robust and debuggable."
                    ),
                    'suggestions': [
                        'Catch specific exception types instead of bare except',
                        'Handle different error cases appropriately',
                        'Consider logging exceptions for debugging',
                        'Document expected exceptions in docstring'
                    ],
                    'evidence': {
                        'source': 'SAA'
                    }
                })
        
        return recommendations
    
    def generate_consistency_recommendations(
        self, 
        file_path: str, 
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate recommendations for consistency and style."""
        recommendations = []
        
        # Check for naming inconsistencies (from SAA)
        for issue in context.get('saa_issues', []):
            message = issue.get('message', '').lower()
            if 'naming' in message or 'convention' in message:
                function_name = issue.get('function') or issue.get('symbol', 'unknown')
                recommendations.append({
                    'file': file_path,
                    'function': function_name,
                    'line': issue.get('line'),
                    'category': 'consistency_style',
                    'strength': 'Info',
                    'title': 'Follow naming conventions',
                    'explanation': (
                        f"Function '{function_name}' doesn't follow Python naming conventions. "
                        f"Consistent naming improves code readability."
                    ),
                    'suggestions': [
                        'Use snake_case for function and variable names',
                        'Use PascalCase for class names',
                        'Use UPPER_CASE for constants',
                        'Follow PEP 8 naming conventions'
                    ],
                    'evidence': {
                        'source': 'SAA'
                    }
                })
        
        return recommendations
    
    def generate_recommendations_for_file(
        self, 
        file_path: str, 
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate all recommendations for a single file."""
        if not self.should_generate_recommendation(file_path, context=context):
            return []
        
        recommendations = []
        
        # Generate recommendations by category
        recommendations.extend(self.generate_intent_clarity_recommendations(file_path, context))
        recommendations.extend(self.generate_security_hygiene_recommendations(file_path, context))
        recommendations.extend(self.generate_maintainability_recommendations(file_path, context))
        recommendations.extend(self.generate_api_design_recommendations(file_path, context))
        recommendations.extend(self.generate_error_handling_recommendations(file_path, context))
        recommendations.extend(self.generate_consistency_recommendations(file_path, context))
        
        return recommendations
    
    def deduplicate_recommendations(self, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate or very similar recommendations."""
        seen = set()
        unique_recommendations = []
        
        for rec in recommendations:
            # Create a key based on file, function, category, and title
            key = (
                rec.get('file'),
                rec.get('function'),
                rec.get('category'),
                rec.get('title')
            )
            
            if key not in seen:
                seen.add(key)
                unique_recommendations.append(rec)
        
        return unique_recommendations
    
    def generate_all_recommendations(
        self,
        saa_output: List[Dict[str, Any]],
        scaa_output: Dict[str, Any],
        hdva_output: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate all recommendations from agent outputs."""
        # Collect context by file
        context_by_file = self.collect_context_by_file(saa_output, scaa_output, hdva_output)
        
        # Generate recommendations for each file
        all_recommendations = []
        for file_path, context in context_by_file.items():
            file_recommendations = self.generate_recommendations_for_file(file_path, context)
            all_recommendations.extend(file_recommendations)
        
        # Deduplicate
        all_recommendations = self.deduplicate_recommendations(all_recommendations)
        
        # Sort by strength (higher first) and then by category
        all_recommendations.sort(
            key=lambda r: (
                -RECOMMENDATION_STRENGTHS.get(r.get('strength', 'Info'), 1),
                r.get('category', '')
            )
        )
        
        return all_recommendations
    
    def build_summary(self, recommendations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build summary statistics for recommendations."""
        total = len(recommendations)
        
        # Count by category
        category_counts = defaultdict(int)
        for rec in recommendations:
            category_counts[rec.get('category', 'unknown')] += 1
        
        # Count by strength
        strength_counts = defaultdict(int)
        for rec in recommendations:
            strength_counts[rec.get('strength', 'Info')] += 1
        
        # Count by file
        file_counts = defaultdict(int)
        for rec in recommendations:
            file_counts[rec.get('file', 'unknown')] += 1
        
        # Top categories
        top_categories = sorted(
            category_counts.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:5]
        
        return {
            'total_recommendations': total,
            'category_breakdown': dict(category_counts),
            'strength_breakdown': dict(strength_counts),
            'files_affected': len(file_counts),
            'top_categories': [{'category': cat, 'count': count} for cat, count in top_categories],
            'high_impact_count': strength_counts.get('Strong Suggestion', 0)
        }


def generate_recommendations(
    session_id: str,
    results_base_folder: str = "results"
) -> Dict[str, Any]:
    """
    Main entry point for IERA recommendation generation.
    
    Reads stored JSON results from other agents and generates recommendations.
    
    Args:
        session_id: Session ID to identify which results to read
        results_base_folder: Base folder where results are stored (default: "results")
        
    Returns:
        Dictionary with recommendations and summary
    """
    logger.info(f"Starting IERA recommendation generation for session: {session_id}")
    
    # Read stored results from JSON files
    results_folder = Path(results_base_folder) / session_id
    
    # Load Static Agent results
    saa_output = _load_agent_results(results_folder / "static_agent.json")
    
    # Load Semantic Agent results
    scaa_output = _load_agent_results(results_folder / "semantic_agent.json")
    
    # Load Hallucination Agent results
    hdva_output = _load_agent_results(results_folder / "hallucination_agent.json")
    
    # Handle None/empty inputs gracefully
    saa_output = saa_output or {}
    scaa_output = scaa_output or {}
    hdva_output = hdva_output or {}
    
    # Initialize generator
    generator = RecommendationGenerator()
    
    # Generate all recommendations
    recommendations = generator.generate_all_recommendations(
        saa_output, scaa_output, hdva_output
    )
    
    # Build summary
    summary = generator.build_summary(recommendations)
    
    logger.info(f"IERA generated {len(recommendations)} recommendations")
    
    result = {
        "agent": "IERA",
        "recommendations": recommendations,
        "summary": summary
    }
    
    # Save IERA results to JSON file
    _save_iera_results(result, session_id, results_base_folder)
    
    return result


def _load_agent_results(json_file: Path) -> Optional[Dict[str, Any]]:
    """Load agent results from JSON file."""
    try:
        if json_file.exists():
            with open(json_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            logger.warning(f"Agent results file not found: {json_file}")
            return None
    except Exception as e:
        logger.warning(f"Failed to load agent results from {json_file}: {e}")
        return None


def _save_iera_results(results: Dict[str, Any], session_id: str, results_base_folder: str) -> None:
    """Save IERA results to JSON file."""
    try:
        results_folder = Path(results_base_folder) / session_id
        results_folder.mkdir(parents=True, exist_ok=True)
        
        output_file = results_folder / "recommender_agent.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"IERA results saved to: {output_file}")
    except Exception as e:
        logger.warning(f"Failed to save IERA results: {e}")


# For testing
if __name__ == "__main__":
    # Example usage with dummy data
    dummy_saa = [
        {
            "file": "example.py",
            "line": 10,
            "message": "Missing docstring",
            "type": "docstring",
            "severity": "info"
        }
    ]
    
    dummy_scaa = {
        "agent": "SCAA",
        "issues": [
            {
                "file": "example.py",
                "function": "encrypt_data",
                "line_number": 20,
                "similarity": 0.35,
                "severity": "High",
                "issue": "Security semantic mismatch",
                "evidence": {
                    "intent_text": "encrypt data securely"
                }
            }
        ]
    }
    
    dummy_hdva = {
        "agent": "HDVA",
        "issues": []
    }
    
    result = generate_recommendations(dummy_saa, dummy_scaa, dummy_hdva)
    
    import json
    print(json.dumps(result, indent=2, ensure_ascii=False))

