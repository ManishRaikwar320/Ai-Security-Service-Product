from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from pathlib import Path
import zipfile, io, uuid, json
from app.config import MAX_UPLOAD_MB, MAX_FILES, MAX_FILE_BYTES, IGNORED_DIRS, SUPPORTED_EXTENSIONS, DEPENDENCY_FILES
from app.scanner import scan_files

app=FastAPI(title="AI Code Vulnerability Scanner",version="0.1.0",description="Defensive source-code analysis MVP. Uploaded code is never executed.")

@app.get("/health")
def health(): return {"status":"ok"}

@app.get("/")
def root(): return {"name":"AI Code Vulnerability Scanner","version":"0.1.0","docs":"/docs","health":"/health"}


def accepted_file(name):
    p=Path(name)
    return p.name in DEPENDENCY_FILES or p.suffix.lower() in SUPPORTED_EXTENSIONS

def safe_name(name):
    # Keep only a normalized relative path; reject absolute and traversal paths.
    p=Path(name.replace("\\","/"))
    if p.is_absolute() or ".." in p.parts: return None
    return str(p)

@app.post("/scan")
async def scan_zip(file: UploadFile=File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400,"Upload a ZIP file containing source code.")
    data=await file.read(MAX_UPLOAD_MB*1024*1024+1)
    if len(data)>MAX_UPLOAD_MB*1024*1024: raise HTTPException(413,"Upload exceeds size limit.")
    try: archive=zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile: raise HTTPException(400,"Invalid ZIP file.")
    files={}; warnings=[]
    for info in archive.infolist():
        if info.is_dir(): continue
        name=safe_name(info.filename)
        if not name: warnings.append("Skipped unsafe path entry."); continue
        if any(part in IGNORED_DIRS for part in Path(name).parts): continue
        if not accepted_file(name): continue
        if info.file_size>MAX_FILE_BYTES: warnings.append(f"Skipped oversized file: {name}"); continue
        if len(files)>=MAX_FILES: warnings.append("File count limit reached."); break
        try:
            raw=archive.read(info)
            text=raw.decode("utf-8",errors="replace")
        except Exception: continue
        files[name]=text
    if not files: raise HTTPException(400,"No supported text source or dependency files found.")
    scan_id=str(uuid.uuid4())
    report=scan_files(files,scan_id)
    report["warnings"].extend(warnings)
    return JSONResponse(report)

@app.post("/scan/text")
async def scan_text(payload: dict):
    name=payload.get("filename","snippet.py")
    code=payload.get("code")
    if not isinstance(code,str) or not code: raise HTTPException(400,"Provide code as a non-empty string.")
    if len(code.encode())>MAX_FILE_BYTES: raise HTTPException(413,"Code snippet exceeds size limit.")
    if not accepted_file(name): raise HTTPException(400,"Unsupported file type.")
    report=scan_files({name:code},str(uuid.uuid4()))
    return JSONResponse(report)
