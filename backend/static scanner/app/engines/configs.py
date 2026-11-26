from app.models import Finding

def scan_config(path, text):
    findings=[]
    checks=[("DEBUG=True", "DEBUG\\s*[:=]\\s*(True|true)", "MEDIUM", "CWE-489", "Debug mode may expose sensitive details.", "Disable debug mode in production."),
            ("Permissive CORS", "(?i)allow_origins\\s*[:=].*\\*", "MEDIUM", "CWE-942", "Wildcard CORS configuration can be risky when paired with sensitive APIs.", "Restrict allowed origins to trusted domains."),
            ("TLS verification disabled", "(?i)(verify\\s*=\\s*False|ssl_verify\\s*[:=]\\s*false)", "HIGH", "CWE-295", "TLS certificate verification appears disabled.", "Enable certificate verification and configure trusted certificates.")]
    import re
    for line_no,line in enumerate(text.splitlines(),1):
        for title,pattern,severity,cwe,explanation,fix in checks:
            if re.search(pattern,line):
                findings.append(Finding(
            finding_id=f"CONFIG-{line_no}-{title.replace(' ','_')}",
            title=title,
            vulnerability_type="INSECURE_CONFIGURATION",
            severity=severity,
            file_path=path,
            line_number=line_no,
            cwe=cwe,
            evidence=line.strip()[:300],
            explanation=explanation,
            remediation=fix,
            confidence=0.65,
            validation_status="Needs review",
            detection_engine="Configuration scanner",
            references=[],
            risk_score=0.0
        ))
    return findings
