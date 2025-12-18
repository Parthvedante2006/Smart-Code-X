"""
orchestrator.py

Central controller that runs all agents on a given repository:

- SAA  (StaticAnalysisAgent)         -> static_agent.py
- SCAA (SemanticAnalyzer)            -> semantic_agent.py
- HDVA (Hallucination Detection)     -> hdva_agent.py   (you will expose analyze_hdva())
- IERA (Intelligent Recommender)     -> recommender_agent.py

Usage (for testing):
    python orchestrator.py /path/to/repo
"""

import os
import sys
import json
import logging
from typing import Dict, Any
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# ---- Import your agents ----
from agents.static_agent import StaticAnalysisAgent
from agents.semantic_agent import analyze_semantic
from agents.recommender_agent import generate_recommendations

# HDVA (Hallucination Detection and Validation Agent)
try:
    from agents.hallucination_agent import analyze_hdva
except ImportError:
    analyze_hdva = None  # fallback, we will handle below

# Import file collector to collect files once
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'agents', 'static_agent_files'))
from collect_python_files import collect_python_files


# ---------- Helpers to run each agent safely ----------

def run_saa(repo_path: str):
    """
    Run StaticAnalysisAgent on the repository.
    For now, we call it once with repo_path so tools like bandit/radon
    can run recursively.
    """
    try:
        saa = StaticAnalysisAgent()
        saa_output = saa.analyze(repo_path)   # your analyze() already exists
        return saa_output, None
    except Exception as e:
        return [], f"SAA error: {e}"


def run_saa_with_session(repo_path: str, temp_folder: str, session_id: str, results_folder: str):
    """Run Static Analysis Agent with existing session."""
    try:
        from agents.static_agent import analyze_temp_folder
        saa_output = analyze_temp_folder(
            temp_folder=temp_folder,
            session_id=session_id,
            results_base_folder=results_folder
        )
        return saa_output, None
    except Exception as e:
        return {}, f"SAA error: {e}"


def run_scaa_with_session(temp_folder: str, session_id: str, results_folder: str):
    """Run Semantic Analysis Agent with existing session."""
    try:
        from agents.semantic_agent import SemanticAnalyzer
        analyzer = SemanticAnalyzer()
        scaa_output = analyzer.analyze_repository_with_session(temp_folder, session_id, results_folder)
        return scaa_output, None
    except Exception as e:
        return {"agent": "SCAA", "issues": [], "summary": {}}, f"SCAA error: {e}"


def run_hdva_with_session(temp_folder: str, session_id: str, results_folder: str):
    """Run Hallucination Detection Agent with existing session."""
    if analyze_hdva is None:
        return {"agent": "HDVA", "issues": [], "summary": {}}, "HDVA analyze_hdva() not implemented/importable"
    
    try:
        from agents.hallucination_agent import HallucinationDetector
        detector = HallucinationDetector()
        hdva_output = detector.analyze_repository_with_session(temp_folder, session_id, results_folder)
        return hdva_output, None
    except Exception as e:
        return {"agent": "HDVA", "issues": [], "summary": {}}, f"HDVA error: {e}"


def run_scaa(repo_path: str):
    """
    Run Semantic & Contextual Analysis Agent (SCAA).
    """
    try:
        scaa_output = analyze_semantic(repo_path)
        return scaa_output, None
    except Exception as e:
        return {"agent": "SCAA", "issues": [], "summary": {}}, f"SCAA error: {e}"


def run_hdva(repo_path: str):
    """
    Run Hallucination Detection & Validation Agent (HDVA).

    You need to implement an `analyze_hdva(repo_path)` function
    inside your hdva_agent.py that:

    - walks through repo_path
    - finds .py files
    - runs your trained model on each file
    - returns a dict:
        {
          "agent": "HDVA",
          "issues": [
             {
               "file": "...",
               "function": "...",    # optional
               "line": 10,           # optional
               "issue": "Function appears hallucinated",
               "severity": "High",
               "probability": 0.87
             }
          ],
          "summary": {...}
        }
    """
    if analyze_hdva is None:
        # HDVA not wired yet
        return {"agent": "HDVA", "issues": [], "summary": {}}, "HDVA analyze_hdva() not implemented/importable"

    try:
        hdva_output = analyze_hdva(repo_path)
        return hdva_output, None
    except Exception as e:
        return {"agent": "HDVA", "issues": [], "summary": {}}, f"HDVA error: {e}"


# ---------- Main Orchestrator Function ----------

def run_all_agents(repo_path: str) -> Dict[str, Any]:
    """
    High-level function that:
    - Collects files once and creates ONE session_id folder
    - Runs SAA, SCAA, HDVA on the same session
    - Passes their outputs into IERA
    - Returns final combined JSON
    """

    if not os.path.exists(repo_path):
        return {
            "status": "error",
            "message": f"Repository path does not exist: {repo_path}"
        }

    # 0) Collect files ONCE - this creates ONE session_id for all agents
    base_temp_folder = os.path.join("agents", "temp")
    base_results_folder = os.path.join("agents", "results")
    
    logger.info(f"Collecting Python files from: {repo_path}")
    collected_files, collection_stats, session_id = collect_python_files(
        repo_path, 
        base_temp_folder=base_temp_folder
    )
    
    logger.info(f"Session ID: {session_id}")
    logger.info(f"Collected {len(collected_files)} Python files")
    logger.info(f"Files stored in: {base_temp_folder}/{session_id}/")
    
    if not collected_files:
        return {
            "status": "error",
            "message": "No Python files found in the repository"
        }
    
    # 1) Run all analysis agents with the SAME session_id
    temp_folder_path = str(Path(base_temp_folder) / session_id)
    saa_output, saa_err = run_saa_with_session(repo_path, temp_folder_path, session_id, base_results_folder)
    scaa_output, scaa_err = run_scaa_with_session(temp_folder_path, session_id, base_results_folder)
    hdva_output, hdva_err = run_hdva_with_session(temp_folder_path, session_id, base_results_folder)

    # 2) Run IERA - it reads from stored JSON files
    iera_output = generate_recommendations(session_id=session_id, results_base_folder=base_results_folder)

    # 3) Collect errors (if any)
    errors = []
    if saa_err:
        errors.append(saa_err)
    if scaa_err:
        errors.append(scaa_err)
    if hdva_err:
        errors.append(hdva_err)

    # 4) Final combined structure
    result: Dict[str, Any] = {
        "status": "success" if not errors else "partial_success",
        "agents": {
            "SAA": saa_output,
            "SCAA": scaa_output,
            "HDVA": hdva_output,
            "IERA": iera_output
        }
    }

    if errors:
        result["errors"] = errors

    return result


# ---------- CLI for local testing ----------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python orchestrator.py /path/to/repo")
        sys.exit(1)

    repo_path = sys.argv[1]
    output = run_all_agents(repo_path)
    print(json.dumps(output, indent=2, ensure_ascii=False))
