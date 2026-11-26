import re
from app.models import Finding

PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "HIGH", "CWE-798"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA) PRIVATE KEY-----"), "CRITICAL", "CWE-798"),
    ("Generic credential assignment", re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]"), "MEDIUM", "CWE-798"),
]

def scan_secrets(path, text):
    findings=[]
    for line_no, line in enumerate(text.splitlines(), 1):
        for label, pattern, severity, cwe in PATTERNS:
            match=pattern.search(line)
            if match:
                # Avoid exposing the credential itself in evidence.
                evidence = line[:120]
                findings.append(Finding(f"SECRET-{line_no}-{label.replace(' ','_')}", f"Possible {label}", "SECRET_EXPOSURE", severity,
                    path, line_no, cwe, evidence, "A line matches a credential or private-key pattern; confirm whether it is a real secret.",
                    "Remove the secret from source, rotate it if exposed, and use a secret manager or environment-based configuration.",
                    0.72, "Needs review", "Secret pattern scanner", ["https://owasp.org/www-project-top-ten/" ]))
                break
    return findings
