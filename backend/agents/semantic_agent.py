import os
import ast
from sentence_transformers import SentenceTransformer, util

repo_path=os.path.dirname(os.path.abspath(r"D:\PARTH\OneDrive\EDI\testing"))

def analyze_repository(repo_path):
    all_functions = []  # store info about every function in all files

    # 1️⃣ Walk through the given repo path
    for root, dirs, files in os.walk(repo_path):
        for filename in files:
            # 2️⃣ Filter Python files only
            if filename.endswith(".py"):
                file_path = os.path.join(root, filename)

                try:
                    # 3️⃣ Read the content of the file
                    with open(file_path, "r", encoding="utf-8") as f:
                        code = f.read()

                    # 4️⃣ Parse the file content using AST
                    tree = ast.parse(code)

                    # 5️⃣ Extract all function definitions
                    for node in ast.walk(tree):
                        if isinstance(node, ast.FunctionDef):
                            func_name = node.name
                            docstring = ast.get_docstring(node)
                            # Optional: Extract variable names or called functions
                            body_keywords = [n.id for n in ast.walk(node) if isinstance(n, ast.Name)]

                            # 6️⃣ Store the data for this function
                            all_functions.append({
                                "file": filename,
                                "function": func_name,
                                "docstring": docstring,
                                "keywords": list(set(body_keywords))
                            })
                
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
                    continue

    # 7️⃣ Return combined report
    return {"agent": "SCAA", "functions": all_functions}


def analyze_semantic(repo_path):
    results = analyze_repository(repo_path)  # your existing function
    issues = []

    for func in results["functions"]:
        doc = func["docstring"]
        logic = " ".join(func["keywords"])
        name = func["function"]

        # If docstring exists, compare docstring ↔ logic
        if doc:
            sim = util.cos_sim(model.encode(doc), model.encode(logic)).item()
            if sim < 0.5:
                issues.append({
                    "file": func["file"],
                    "function": name,
                    "issue": "Docstring and code logic mismatch",
                    "severity": "Medium"
                })
        else:
            # No docstring — fallback: compare function name ↔ logic
            sim = util.cos_sim(model.encode(name), model.encode(logic)).item()
            if sim < 0.5:
                issues.append({
                    "file": func["file"],
                    "function": name,
                    "issue": "Function name doesn't match logic",
                    "severity": "Medium"
                })

    return {"agent": "SCAA", "issues": issues}

result=analyze_semantic(repo_path)
print(result)