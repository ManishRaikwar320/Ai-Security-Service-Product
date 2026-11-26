from zap_engine import ZAPScanner
from report_generator import generate_report

from config import TARGET_URL


def main():

    print("=" * 50)
    print(" AI POWERED AUTOMATED DAST SCANNER")
    print("=" * 50)

    try:

        scanner = ZAPScanner()

        scan_data = scanner.scan(TARGET_URL)

        report = generate_report(scan_data)

        print("\n========== SCAN SUMMARY ==========")

        print("Target:", report["target"])

        print(
            "Discovered URLs:",
            report["files_or_urls_discovered"]
        )

        print(
            "Total Findings:",
            report["findings_count"]
        )

        print(
            "SQL Injection Alerts:",
            report["sql_injection_alerts"]
        )

        print("\nSeverity Summary:")

        for severity, count in report["summary"].items():

            print(f"{severity}: {count}")

        print("\nScan completed successfully.")

    except Exception as error:

        print("\nScan failed:", str(error))


if __name__ == "__main__":
    main()
