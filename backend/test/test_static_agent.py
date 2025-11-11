import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from agents.static_agent import StaticAnalysisAgent

saa = StaticAnalysisAgent()
results = saa.analyze("sample_code.py")

for r in results:
    print(f"[{r['tool']}] {r['type']} → {r['message']} (Severity: {r['severity']})")
