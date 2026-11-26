from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
SCAN_DIR = Path(os.getenv("SCAN_DIR", BASE_DIR / "scan_tmp")).resolve()
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "25"))
MAX_FILES = int(os.getenv("MAX_FILES", "1500"))
MAX_FILE_BYTES = int(os.getenv("MAX_FILE_BYTES", "500000"))
AI_ENABLED = os.getenv("AI_ENABLED", "false").lower() == "true"
AI_BASE_URL = os.getenv("AI_BASE_URL", "https://api.openai.com/v1")
AI_MODEL = os.getenv("AI_MODEL", "")
AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_MAX_FILES = int(os.getenv("AI_MAX_FILES", "12"))
AI_MAX_CHARS_PER_FILE = int(os.getenv("AI_MAX_CHARS_PER_FILE", "6000"))
OSV_ENABLED = os.getenv("OSV_ENABLED", "true").lower() == "true"

IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor", "coverage", ".next"}
SUPPORTED_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".go", ".rb", ".sql", ".yaml", ".yml", ".json", ".toml", ".ini", ".sh", ".html", ".xml", ".tf"}
DEPENDENCY_FILES = {"requirements.txt", "package-lock.json", "npm-shrinkwrap.json", "package.json", "Pipfile.lock", "poetry.lock", "pyproject.toml", "go.sum", "Cargo.lock"}
