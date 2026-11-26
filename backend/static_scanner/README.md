# AI Code Vulnerability Scanner (MVP)

Defensive code-scanning API. Uploaded code is parsed/read but **never executed**.

## Engines
- Python AST heuristic rules (SQL injection, shell calls, eval/exec, pickle, dynamic paths)
- Secret-pattern scanning (evidence is truncated; review before sharing reports)
- Basic configuration checks (debug, wildcard CORS, disabled TLS verification)
- OSV package advisory lookup for `requirements.txt` and `package.json` (network-dependent)
- Optional AI semantic review through an OpenAI-compatible API (disabled by default)
- Deduplication, confidence-based risk prioritization, JSON report

> This is an MVP, not a replacement for professional testing. Heuristic detections may miss vulnerabilities or produce false positives. Scan only code you own or have permission to review. ZIP contents are not executed. AI mode sends selected source snippets to the configured API; enable it only after reviewing privacy implications.

## Run locally (Windows PowerShell)
```powershell
cd ai_code_scanner
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000/docs

## Run using Docker
```bash
docker compose up --build
```

## API
- `GET /health`
- `GET /`
- `POST /scan` — upload a ZIP (`multipart/form-data`, field `file`)
- `POST /scan/text` — JSON `{ "filename": "snippet.py", "code": "..." }`

## AI mode (optional)
Set environment variables before running:
```text
AI_ENABLED=true
AI_BASE_URL=https://api.openai.com/v1
AI_MODEL=your-model-name
AI_API_KEY=your-key
```
Use a compatible endpoint and model. Do not upload confidential code unless your provider's data terms are suitable. AI output is unverified and is labeled `Needs review`.

## Limitations / next steps
- Python AST checks are heuristics, not full taint analysis.
- Dependency scanning supports simple `requirements.txt` pins and `package.json`; lockfile support is planned.
- OSV requests are made for extracted package/version pairs and require network access.
- Add auth, quotas, isolated workers, persistent scan storage, CI integration, tests, and broader language rules before production use.
