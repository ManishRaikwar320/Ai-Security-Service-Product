import os
from dotenv import load_dotenv

load_dotenv()

ZAP_API_KEY = os.getenv("ZAP_API_KEY")
ZAP_PROXY = os.getenv("ZAP_PROXY", "http://127.0.0.1:8080")

TARGET_URL = os.getenv(
    "TARGET_URL",
    "http://127.0.0.1:8000"
)

# Active scanning is disabled by default.
ENABLE_ACTIVE_SCAN = (
    os.getenv("ENABLE_ACTIVE_SCAN", "false").lower() == "true"
)

REPORT_DIR = "reports"