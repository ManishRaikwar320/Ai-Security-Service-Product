
import os
import sys
import json
import zipfile
import urllib.request
from pathlib import Path


# Installation directory
INSTALL_DIR = Path("./")
ZIP_PATH = INSTALL_DIR / "katana.zip"
EXE_PATH = INSTALL_DIR / "katana.exe"

# Official GitHub API
API_URL = (
    "https://api.github.com/repos/"
    "projectdiscovery/katana/releases/latest"
)


def install_katana():

    print("\n=== Katana Installer ===\n")

    INSTALL_DIR.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Get latest release information
        print("[1/4] Checking latest Katana release...")

        request = urllib.request.Request(
            API_URL,
            headers={"User-Agent": "Python-Katana-Installer"}
        )

        with urllib.request.urlopen(request, timeout=30) as response:
            release = json.loads(response.read())

        version = release["tag_name"]
        print(f"Latest version: {version}")

        # 2. Find Windows AMD64 ZIP
        asset = next(
            (
                item for item in release["assets"]
                if item["name"].endswith(
                    "windows_amd64.zip"
                )
            ),
            None
        )

        if not asset:
            raise RuntimeError(
                "Windows AMD64 ZIP not found in release"
            )

        download_url = asset["browser_download_url"]

        # 3. Download ZIP
        print("\n[2/4] Downloading Katana...")

        urllib.request.urlretrieve(
            download_url,
            ZIP_PATH
        )

        print("Download completed.")

        # 4. Extract executable safely
        print("\n[3/4] Extracting files...")

        with zipfile.ZipFile(ZIP_PATH, "r") as archive:

            exe_member = next(
                (
                    name for name in archive.namelist()
                    if Path(name).name.lower() == "katana.exe"
                ),
                None
            )

            if not exe_member:
                raise RuntimeError(
                    "katana.exe not found inside ZIP"
                )

            with archive.open(exe_member) as source:
                with EXE_PATH.open("wb") as destination:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        destination.write(chunk)

        ZIP_PATH.unlink(missing_ok=True)

        # 5. Verify installation
        print("\n[4/4] Verifying installation...")

        import subprocess

        result = subprocess.run(
            [str(EXE_PATH), "-version"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr or "Version check failed"
            )

        print("\nKatana installed successfully!")
        print("Version:", result.stdout.strip())
        print("Location:", EXE_PATH)

        print("\nRun Katana using:")
        print(f'"{EXE_PATH}" -u http://127.0.0.1:8000')

    except Exception as error:
        ZIP_PATH.unlink(missing_ok=True)
        print("\nInstallation failed:", error)
        sys.exit(1)


if __name__ == "__main__":
    install_katana()
