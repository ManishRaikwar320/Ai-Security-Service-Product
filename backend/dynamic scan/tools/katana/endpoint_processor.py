
import json
from pathlib import Path
from urllib.parse import urlparse, parse_qs


INPUT_FILE = Path("endpoints.jsonl")
OUTPUT_FILE = Path("endpoints_clean.json")


def process_endpoints():

    unique = {}

    with INPUT_FILE.open("r", encoding="utf-8") as file:

        for line in file:

            try:
                data = json.loads(line)

                request = data.get("request", {})
                response = data.get("response", {})

                url = request.get("endpoint")

                if not url:
                    continue

                parsed = urlparse(url)

                method = request.get("method", "GET").upper()
                params = list(parse_qs(parsed.query).keys())

                # Deduplicate by method + URL
                key = (method, url)

                unique[key] = {
                    "url": url,
                    "method": method,
                    "path": parsed.path,
                    "parameters": params,
                    "status_code": response.get("status_code"),
                    "category": (
                        "API" if "/api/" in parsed.path
                        else "WEB"
                    )
                }

            except (json.JSONDecodeError, ValueError):
                continue

    results = list(unique.values())

    OUTPUT_FILE.write_text(
        json.dumps(results, indent=4),
        encoding="utf-8"
    )

    print("Total unique endpoints:", len(results))
    print("Saved:", OUTPUT_FILE)

    return results


if __name__ == "__main__":
    process_endpoints()
