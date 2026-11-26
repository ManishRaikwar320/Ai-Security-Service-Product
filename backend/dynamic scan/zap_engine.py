
import re
import time
from urllib.parse import urlparse

from zapv2 import ZAPv2

from config import (
    ZAP_API_KEY,
    ZAP_PROXY,
    ENABLE_ACTIVE_SCAN
)


class ZAPScanner:

    def __init__(self):

        self.zap = ZAPv2(
            apikey=ZAP_API_KEY,
            proxies={
                "http": ZAP_PROXY,
                "https": ZAP_PROXY
            }
        )

    def validate_target(self, target):

        parsed = urlparse(target)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only HTTP/HTTPS targets allowed")

        if not parsed.hostname:
            raise ValueError("Invalid target URL")

        if parsed.username or parsed.password:
            raise ValueError("Credentials in URL are not allowed")

        return target.rstrip("/")

    def is_local_target(self, target):

        host = urlparse(target).hostname

        return host in ("localhost", "127.0.0.1", "::1")

    def run_spider(self, target):

        print("\n[1] Starting Spider...")

        scan_id = self.zap.spider.scan(target)

        while True:

            progress = int(
                self.zap.spider.status(scan_id)
            )

            print(f"Spider: {progress}%")

            if progress >= 100:
                break

            time.sleep(2)

        return self.zap.spider.results(scan_id)

    def wait_for_passive_scan(self):

        print("\n[2] Waiting for Passive Scan...")

        while True:

            remaining = int(
                self.zap.pscan.records_to_scan
            )

            print("Records remaining:", remaining)

            if remaining <= 0:
                break

            time.sleep(2)

    def run_active_scan(self, target):

        if not ENABLE_ACTIVE_SCAN:
            print("\n[3] Active Scan disabled.")
            return None

        if not self.is_local_target(target):
            raise ValueError(
                "Active scan is restricted to localhost "
                "in this starter configuration."
            )

        print("\n[3] Starting Active Scan...")

        scan_id = self.zap.ascan.scan(target)

        while True:

            progress = int(
                self.zap.ascan.status(scan_id)
            )

            print(f"Active Scan: {progress}%")

            if progress >= 100:
                break

            time.sleep(3)

        return scan_id

    def get_alerts(self, target):

        print("\n[4] Collecting Alerts...")

        return self.zap.core.alerts(
            baseurl=target,
            start=0,
            count=5000
        )

    def normalize_alerts(self, alerts):

        unique = {}

        for alert in alerts:

            name = alert.get("alert", "Unknown")
            url = alert.get("url", "")
            param = alert.get("param", "")
            evidence = alert.get("evidence", "")

            key = (
                name,
                url,
                param,
                evidence
            )

            if key in unique:
                continue

            risk = alert.get("risk", "Informational")

            sql_injection = bool(
                re.search(
                    r"sql injection|cwe.?89",
                    name + " " + alert.get("cweid", ""),
                    re.IGNORECASE
                )
            )

            unique[key] = {
                "title": name,
                "url": url,
                "parameter": param,
                "severity": risk.upper(),
                "confidence": alert.get("confidence"),
                "cwe": alert.get("cweid"),
                "evidence": evidence,
                "description": alert.get("description"),
                "solution": alert.get("solution"),
                "reference": alert.get("reference"),
                "is_sql_injection": sql_injection
            }

        return list(unique.values())

    def scan(self, target):

        target = self.validate_target(target)

        print("Target:", target)

        # Verify that ZAP API is reachable.
        print("ZAP Version:", self.zap.core.version)

        urls = self.run_spider(target)

        self.wait_for_passive_scan()

        self.run_active_scan(target)

        alerts = self.get_alerts(target)

        findings = self.normalize_alerts(alerts)

        return {
            "target": target,
            "discovered_urls": urls,
            "findings": findings
        }
