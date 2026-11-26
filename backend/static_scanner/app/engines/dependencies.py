import json, re
import urllib.request, urllib.error
from app.models import Finding


def extract_dependencies(filename, text):
    deps=[]
    if filename.endswith("requirements.txt"):
        for line in text.splitlines():
            line=line.strip()
            if not line or line.startswith("#") or line.startswith("-"): continue
            m=re.match(r"([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|>|<)\s*([A-Za-z0-9_.+-]+)",line)
            if m: deps.append({"name":m.group(1),"version":m.group(2)})
    elif filename.endswith("package.json"):
        try:
            obj=json.loads(text)
            for section in ("dependencies","devDependencies","optionalDependencies"):
                for name,version in obj.get(section,{}).items():
                    deps.append({"name":name,"version":str(version).lstrip("^~>=<")})
        except Exception: pass
    return deps


def osv_query(dep, ecosystem):
    payload=json.dumps({"package":{"name":dep["name"],"ecosystem":ecosystem},"version":dep["version"]}).encode()
    req=urllib.request.Request("https://api.osv.dev/v1/query",data=payload,headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=5) as response: return json.loads(response.read().decode()).get("vulns",[])
    except Exception: return None


def scan_dependency_file(filename, text, enabled=True):
    findings=[]; deps=extract_dependencies(filename,text)
    if not enabled or not deps: return findings, ("Dependency checks disabled" if not enabled else None)
    ecosystem="PyPI" if filename.endswith("requirements.txt") else "npm"
    for dep in deps[:80]:
        advisories=osv_query(dep,ecosystem)
        if advisories is None: continue
        for advisory in advisories[:5]:
            ids=advisory.get("id", "OSV advisory")
            summary=advisory.get("summary", "Known package vulnerability")
            findings.append(Finding(
                finding_id=f"OSV-{dep['name']}-{ids}",
                title=f"{dep['name']} {dep['version']}: {summary[:100]}",
                vulnerability_type="VULNERABLE_DEPENDENCY",
                severity="HIGH",
                file_path=filename,
                line_number=None,
                cwe="CWE-1104",
                evidence=f"Package {dep['name']} version {dep['version']} matched advisory {ids}",
                explanation=summary,
                remediation="Upgrade to a version not listed as affected in the advisory.",
                confidence=0.95,
                validation_status="Advisory match",
                detection_engine="OSV database",
                references=[f"https://osv.dev/vulnerability/{ids}"]
            ))
    return findings, None
