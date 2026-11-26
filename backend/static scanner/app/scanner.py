from pathlib import Path
import hashlib
from app.models import Finding
from app.engines.rules import scan_python
from app.engines.secrets import scan_secrets
from app.engines.configs import scan_config
from app.engines.dependencies import scan_dependency_file
from app.engines.ai import analyze_with_ai
from app.config import OSV_ENABLED


def risk_score(f):
    sev={"CRITICAL":10,"HIGH":8,"MEDIUM":5,"LOW":2,"INFO":1}.get(f.severity,5)
    return round(sev * (0.55 + 0.45 * f.confidence),2)

def deduplicate(findings):
    seen=set(); output=[]
    for f in findings:
        key=(f.vulnerability_type,f.file_path,f.line_number,f.title)
        if key in seen: continue
        seen.add(key); f.risk_score=risk_score(f); output.append(f)
    return output

def scan_files(files, scan_id):
    findings=[]; warnings=[]; count=0
    for path,text in files.items():
        count+=1
        if path.endswith(".py"):
            fs,error=scan_python(path,text); findings.extend(fs)
            if error: warnings.append(f"{path}: {error}")
        findings.extend(scan_secrets(path,text))
        findings.extend(scan_config(path,text))
        if Path(path).name in {"requirements.txt","package.json"}:
            fs,error=scan_dependency_file(Path(path).name,text,OSV_ENABLED); findings.extend(fs)
            if error: warnings.append(error)
    ai_fs,ai_warning=analyze_with_ai(files,findings); findings.extend(ai_fs)
    if ai_warning: warnings.append(ai_warning)
    findings=deduplicate(findings)
    summary={s:sum(1 for f in findings if f.severity==s) for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
    return {"scan_id":scan_id,"files_scanned":count,"findings_count":len(findings),"summary":summary,"findings":[f.model_dump() for f in sorted(findings,key=lambda x:x.risk_score,reverse=True)],"warnings":warnings}
