
import os
import sys
import json
import platform
import subprocess
import urllib.request
import zipfile

from pathlib import Path


API_URL = (
    "https://api.github.com/repos/"
    "projectdiscovery/katana/releases/latest"
)


def detect_environment():

    system = platform.system().lower()
    machine = platform.machine().lower()

    if machine in ("amd64", "x86_64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    elif machine in ("i386", "i686", "x86"):
        arch = "386"
    else:
        raise RuntimeError(f"Unsupported architecture: {machine}")

    if system == "windows":
        os_name = "windows"
        exe_name = "katana.exe"

    elif system == "linux":
        os_name = "linux"
        exe_name = "katana"

    elif system == "darwin":
        os_name = "macOS"
        exe_name = "katana"

    else:
        raise RuntimeError(f"Unsupported OS: {system}")

    # Kaggle-specific installation directory
    if os.path.exists("/kaggle/working"):
        install_dir = Path("/kaggle/working/katana")
    elif system == "windows":
        install_dir = Path("./dynamic_scan/tools/endp_finder/katana")
    else:
        install_dir = Path.home() / ".local" / "bin"

    return os_name, arch, exe_name, install_dir


def install_katana():

    print("\n=== Universal Katana Installer ===\n")

    zip_path = None

    try:

        # 1. Detect OS and architecture
        print("[1/5] Detecting environment...")

        os_name, arch, exe_name, install_dir = (
            detect_environment()
        )

        print("OS:", os_name)
        print("Architecture:", arch)
        print("Install directory:", install_dir)

        install_dir.mkdir(parents=True, exist_ok=True)

        # 2. Get latest release
        print("\n[2/5] Checking latest release...")

        request = urllib.request.Request(
            API_URL,
            headers={
                "User-Agent": "Universal-Katana-Installer"
            }
        )

        with urllib.request.urlopen(
            request, timeout=30
        ) as response:

            release = json.loads(response.read())

        version = release["tag_name"]

        print("Latest version:", version)

        # 3. Find matching binary
        suffix = f"_{os_name}_{arch}.zip"

        asset = next(
            (
                item for item in release["assets"]
                if item["name"].endswith(suffix)
            ),
            None
        )

        if not asset:
            raise RuntimeError(
                f"No binary found for {os_name}/{arch}"
            )

        zip_path = install_dir / asset["name"]

        # 4. Download
        print("\n[3/5] Downloading Katana...")

        urllib.request.urlretrieve(
            asset["browser_download_url"],
            zip_path
        )

        print("Download completed.")

        # 5. Extract executable
        print("\n[4/5] Extracting binary...")

        exe_path = install_dir / exe_name

        with zipfile.ZipFile(zip_path, "r") as archive:

            member = next(
                (
                    name for name in archive.namelist()
                    if Path(name).name == exe_name
                ),
                None
            )

            if not member:
                raise RuntimeError(
                    f"{exe_name} not found in archive"
                )

            with archive.open(member) as source:
                with exe_path.open("wb") as destination:

                    while True:
                        chunk = source.read(1024 * 1024)

                        if not chunk:
                            break

                        destination.write(chunk)

        # Linux/macOS executable permission
        if os_name != "windows":
            exe_path.chmod(0o755)

        zip_path.unlink(missing_ok=True)

        # 6. Verify
        print("\n[5/5] Verifying installation...")

        result = subprocess.run(
            [str(exe_path), "-version"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr or "Version check failed"
            )

        print("\nInstallation successful!")
        print("Version:", result.stdout.strip() or result.stderr.strip())
        print("Executable:", exe_path)

        print("\nExample usage:")

        if os_name == "windows":
            print(
                f'"{exe_path}" -u '
                'http://127.0.0.1:8000'
            )
        else:
            print(
                f'{exe_path} -u '
                'http://127.0.0.1:8000'
            )

        return str(exe_path)

    except Exception as error:

        if zip_path and zip_path.exists():
            zip_path.unlink(missing_ok=True)

        print("\nInstallation failed:", error)
        return None


if __name__ == "__main__":
    install_katana()
