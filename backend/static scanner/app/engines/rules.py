import ast
from app.models import Finding

class PythonRuleVisitor(ast.NodeVisitor):
    def __init__(self, file_path, source):
        self.file_path = file_path
        self.source_lines = source.splitlines()
        self.findings = []
        self.dynamic_query_vars = set()

    def emit(self, node, title, kind, severity, cwe, evidence, explanation, remediation, confidence=0.7):
        self.findings.append(Finding(
            finding_id=f"PY-{kind}-{node.lineno}", title=title, vulnerability_type=kind,
            severity=severity, file_path=self.file_path, line_number=node.lineno, cwe=cwe,
            evidence=evidence[:500], explanation=explanation, remediation=remediation,
            confidence=confidence, validation_status="Needs review", detection_engine="Python AST rules"
        ))

    def visit_Call(self, node):
        name = node.func.id if isinstance(node.func, ast.Name) else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
        line = self.source_lines[node.lineno-1].strip() if node.lineno <= len(self.source_lines) else ""
        if name in {"execute", "executemany"}:
            dynamic_arg = bool(node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)))
            if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in self.dynamic_query_vars:
                dynamic_arg = True
            if dynamic_arg:
                self.emit(node, "Potential SQL Injection", "SQL_INJECTION", "HIGH", "CWE-89", line,
                          "SQL passed to execution API appears to be assembled dynamically. Confirm whether untrusted data is incorporated.",
                          "Use parameterized queries; avoid string interpolation or concatenation for SQL values.", 0.82)
        if name in {"system", "popen"}:
            self.emit(node, "Potential Command Injection", "COMMAND_INJECTION", "HIGH", "CWE-78", line,
                      "Shell-related function is used. Review whether any argument contains untrusted data.",
                      "Avoid shell execution. Prefer APIs that accept argument lists and validate inputs.", 0.65)
        if name == "Popen" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if any(x in first.value for x in ("$", ";", "&&", "|")):
                    self.emit(node, "Potential Unsafe Process Execution", "COMMAND_INJECTION", "MEDIUM", "CWE-78", line,
                              "Process invocation contains shell-like syntax; verify shell usage and input handling.",
                              "Use shell=False and pass a fixed argument list; validate dynamic arguments.", 0.55)
        if name in {"eval", "exec"}:
            self.emit(node, "Dynamic Code Execution", "DYNAMIC_EXECUTION", "HIGH", "CWE-95", line,
                      f"Use of {name}() can execute dynamically supplied code.",
                      "Avoid eval/exec on untrusted or dynamic input; replace with explicit parsing or dispatch.", 0.9)
        if name in {"pickle.loads", "loads"} or (isinstance(node.func, ast.Attribute) and node.func.attr in {"load", "loads"} and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle"):
            self.emit(node, "Potential Unsafe Deserialization", "UNSAFE_DESERIALIZATION", "HIGH", "CWE-502", line,
                      "Pickle deserialization can execute code when processing untrusted data.",
                      "Do not deserialize untrusted pickle data; use a safe serialization format.", 0.85)
        if name in {"open", "Path"} and node.args and isinstance(node.args[0], ast.BinOp):
            self.emit(node, "Potential Path Traversal", "PATH_TRAVERSAL", "MEDIUM", "CWE-22", line,
                      "File path appears to be dynamically constructed. Check for user-controlled path segments.",
                      "Resolve paths against a fixed base directory and verify the resolved path remains inside it.", 0.6)
        self.generic_visit(node)

    def visit_Assign(self, node):
        rhs = node.value
        if isinstance(rhs, (ast.BinOp, ast.JoinedStr)):
            # Heuristic: mark variables containing dynamically constructed SQL strings.
            rendered = ast.unparse(rhs).lower() if hasattr(ast, "unparse") else ""
            if "select " in rendered or "insert " in rendered or "update " in rendered or "delete " in rendered:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.dynamic_query_vars.add(target.id)
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            if alias.name == "pickle":
                line = self.source_lines[node.lineno-1].strip()
                self.emit(node, "Pickle imported", "UNSAFE_DESERIALIZATION", "INFO", "CWE-502", line,
                          "Pickle can be unsafe when used to deserialize untrusted data; import alone is not a vulnerability.",
                          "Review pickle usage and avoid deserializing untrusted content.", 0.35)
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and len(node.value) > 24:
            # Secret patterns are primarily handled by the regex engine.
            pass


def scan_python(file_path, source):
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [], f"Python parse error: {e.msg} (line {e.lineno})"
    visitor = PythonRuleVisitor(file_path, source)
    visitor.visit(tree)
    return visitor.findings, None
