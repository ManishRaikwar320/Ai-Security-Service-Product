
import os
import json
from datetime import datetime, timezone
from collections import Counter


def generate_report(scan_data):

    findings = scan_data["findings"]

    severity_counts = Counter(
        item["severity"] for item in findings
    )

    sql_findings = [
        item for item in findings
        if item["is_sql_injection"]
    ]

    report = {
        "scan_id": datetime.now(timezone.utc).strftime(
            "%Y%m%d%H%M%S"
        ),

        "scan_time": datetime.now(
            timezone.utc
        ).isoformat(),

        "target": scan_data["target"],

        "files_or_urls_discovered": len(
            scan_data["discovered_urls"]
        ),

        "findings_count": len(findings),

        "summary": {
            "CRITICAL": severity_counts.get("CRITICAL", 0),
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
            "INFORMATIONAL": severity_counts.get(
                "INFORMATIONAL", 0
            )
        },

        "sql_injection_alerts": len(sql_findings),

        "discovered_urls": scan_data["discovered_urls"],

        "findings": findings
    }

    os.makedirs("reports", exist_ok=True)

    file_path = "reports/scan_report.json"

    with open(file_path, "w", encoding="utf-8") as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    print("\nReport generated:", file_path)

    return report
