import subprocess
import json
from statistics import mean

class StaticAnalysisAgent:
    def __init__(self):
        # Stores all issues found by different tools
        self.results = []

    # --- Run Pylint (Style & Syntax Checking) ---
    def run_pylint(self, file_path):
        try:
            # Command to run pylint in JSON output mode
            cmd = ["pylint", file_path, "-f", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True)

            # Only process output if pylint returned valid JSON
            if result.stdout.strip():
                data = json.loads(result.stdout)
                # Loop through all detected issues
                for issue in data:
                    self.results.append({
                        "tool": "Pylint",
                        "file": issue.get("path"),
                        "line": issue.get("line"),
                        "type": "Style",  # Category of issue
                        "message": issue.get("message"),
                        "symbol": issue.get("symbol"),  # Short pylint code
                        "severity": "Medium" if issue.get("type") == "warning" else "Low"
                    })
        except Exception as e:
            print("Error running Pylint:", e)

    # --- Run Bandit (Security Vulnerability Scanner) ---
    def run_bandit(self, file_path):
        try:
            # Command to run Bandit recursively with JSON output
            cmd = ["bandit", "-r", file_path, "-f", "json", "-q"]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.stdout.strip():
                data = json.loads(result.stdout)
                for issue in data.get("results", []):
                    self.results.append({
                        "tool": "Bandit",
                        "file": issue.get("filename"),
                        "line": issue.get("line_number"),
                        "type": "Security",
                        "message": issue.get("issue_text"),
                        "severity": issue.get("issue_severity")  # LOW, MEDIUM, or HIGH
                    })
        except Exception as e:
            print("Error running Bandit:", e)

    # --- Run Radon (Cyclomatic Complexity Analysis) ---
    def run_radon(self, file_path):
        try:
            # Command to calculate code complexity using Radon
            cmd = ["radon", "cc", file_path, "-j"]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.stdout.strip():
                data = json.loads(result.stdout)
                # Radon returns a dict of file -> code block details
                for fname, blocks in data.items():
                    for block in blocks:
                        self.results.append({
                            "tool": "Radon",
                            "file": fname,
                            "line": block.get("lineno"),
                            "type": "Complexity",
                            "message": f"Cyclomatic complexity {block.get('complexity')}",
                            # High complexity (>10) = harder to maintain
                            "severity": "High" if block.get("complexity") > 10 else "Low"
                        })
        except Exception as e:
            print("Error running Radon:", e)

    # --- Run Maintainability Index Calculation ---
    def run_maintainability(self, file_path):
        try:
            # Command to compute maintainability index via Radon
            cmd = ["radon", "mi", file_path, "-j"]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.stdout.strip():
                data = json.loads(result.stdout)
                # Extract MI (maintainability index) for all blocks
                mi_scores = [item["mi"] for item in data.values()]
                avg_mi = mean(mi_scores) if mi_scores else 100

                # Append average MI result with severity interpretation
                self.results.append({
                    "tool": "Radon",
                    "file": file_path,
                    "type": "Maintainability",
                    "message": f"Average Maintainability Index: {round(avg_mi, 2)}",
                    "severity": (
                        "Low" if avg_mi > 70 else
                        "Medium" if avg_mi > 50 else
                        "High"
                    )
                })
        except Exception as e:
            print("Error computing maintainability:", e)

    # --- Run All Checks Together ---
    def analyze(self, file_path):
        """
        Runs all static analysis tools in sequence
        and aggregates their results into a single list.
        """
        self.results = []  # Reset previous results

        # Run all analysis tools sequentially
        self.run_pylint(file_path)
        self.run_bandit(file_path)
        self.run_radon(file_path)
        self.run_maintainability(file_path)

        # Return combined analysis report
        return self.results
