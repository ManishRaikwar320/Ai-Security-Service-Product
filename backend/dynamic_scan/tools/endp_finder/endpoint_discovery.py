
import subprocess
import json
from pathlib import Path


def discover_endpoints(target_url):

    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)

    output_file = output_dir / "endpoints.jsonl"

    command = [
        "katana",
        "-u", target_url,
        "-d", "3",
        "-jc",
        "-jsonl",
        "-silent",
        "-rl", "2",
        "-c", "2",
        "-mdp", "100",
        "-o", str(output_file)
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=False
        )

        if result.returncode != 0:
            return {
                "status": "error",
                "error": result.stderr
            }

        endpoints = []

        if output_file.exists():
            with output_file.open(
                "r",
                encoding="utf-8"
            ) as file:

                for line in file:
                    try:
                        data = json.loads(line)

                        request = data.get("request", {})

                        endpoint = request.get("endpoint")

                        if endpoint:
                            endpoints.append({
                                "url": endpoint,
                                "method": request.get(
                                    "method", "GET"
                                ),
                                "source": data.get("source")
                            })

                    except json.JSONDecodeError:
                        continue

        return {
            "status": "success",
            "total_endpoints": len(endpoints),
            "endpoints": endpoints
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "error": "Katana executable not found"
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": "Crawling timeout"
        }


if __name__ == "__main__":

    result = discover_endpoints(
        "https://itinero.company"
    )

    print(json.dumps(result, indent=4))
