"""
katana_gau_recon.py
Automatic setup + endpoint discovery using Katana and GAU.

Usage:
    python katana_gau_recon.py https://example.com
    python katana_gau_recon.py https://example.com --depth 5 --timeout 900
    python katana_gau_recon.py https://www.example.com --scope-domain example.com
    python katana_gau_recon.py https://example.com --skip-gau
    python katana_gau_recon.py https://example.com --skip-katana
    python katana_gau_recon.py https://example.com --persist-path
    python katana_gau_recon.py https://example.com --probe-rate 5 --max-probe 2000
    python katana_gau_recon.py https://example.com --no-probe
    python katana_gau_recon.py https://example.com --keep-soft404

Use only on domains you own or are explicitly authorized to test.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import platform
import re
import shutil
import subprocess
import ssl
import tarfile
import tempfile
import threading
import time
import uuid
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import parse_qs, quote, urljoin, urlparse, urlunparse

USER_AGENT = "Katana-GAU-Recon-Installer"

TOOLS = {
    "katana": {
        "repo": "projectdiscovery/katana",
        "exe": "katana.exe" if os.name == "nt" else "katana",
        "version_flag": "-version",
        "go_package": "github.com/projectdiscovery/katana/cmd/katana@latest",
    },
    "gau": {
        "repo": "lc/gau",
        "exe": "gau.exe" if os.name == "nt" else "gau",
        "version_flag": "--version",
        "go_package": "github.com/lc/gau/v2/cmd/gau@latest",
    },
}


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
@dataclass
class Paths:
    report_dir: Path
    raw_dir: Path
    katana_raw: Path
    gau_raw: Path
    json_report: Path
    txt_report: Path
    active_json: Path
    active_txt: Path
    inactive_txt: Path
    gau_active_json: Path
    gau_active_txt: Path
    errors_txt: Path
    soft404_txt: Path
    summary_report: Path

    @classmethod
    def from_dir(cls, report_dir="reports") -> "Paths":
        report = Path(report_dir).resolve()
        raw = report / "raw"
        return cls(
            report_dir=report,
            raw_dir=raw,
            katana_raw=raw / "katana.jsonl",
            gau_raw=raw / "gau.txt",
            json_report=report / "endpoints_clean.json",
            txt_report=report / "endpoints_clean.txt",
            active_json=report / "endpoints_active.json",
            active_txt=report / "endpoints_active.txt",
            inactive_txt=report / "endpoints_inactive.txt",
            gau_active_json=report / "gau_active.json",
            gau_active_txt=report / "gau_active.txt",
            errors_txt=report / "endpoints_errors.txt",
            soft404_txt=report / "endpoints_soft404_suspect.txt",
            summary_report=report / "endpoints_summary.json",
        )

    def prepare(self):
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.katana_raw.unlink(missing_ok=True)
        self.gau_raw.unlink(missing_ok=True)


# --------------------------------------------------------------------------
# Platform / install helpers
# --------------------------------------------------------------------------
def detect_platform():
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {"windows": "windows", "linux": "linux", "darwin": "macos"}
    arch_map = {
        "amd64": "amd64", "x86_64": "amd64",
        "arm64": "arm64", "aarch64": "arm64",
        "i386": "386", "i686": "386", "x86": "386",
    }

    if system not in os_map:
        raise RuntimeError(f"Unsupported operating system: {system}")
    if machine not in arch_map:
        raise RuntimeError(f"Unsupported architecture: {machine}")

    kaggle = Path("/kaggle/working").exists()
    if kaggle:
        base_dir = Path("/kaggle/working") / "recon-tools"
    elif system == "windows":
        base_dir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "ReconTools"
    else:
        base_dir = Path.home() / ".local" / "bin"

    return os_map[system], arch_map[machine], base_dir, kaggle


def _github_request(url, token_ok=True):
    headers = {"User-Agent": USER_AGENT}
    token = os.environ.get("GITHUB_TOKEN")
    if token and token_ok:
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(url, headers=headers)


def github_json(url):
    try:
        with urllib.request.urlopen(_github_request(url), timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429):
            raise RuntimeError(
                "GitHub API rate limit hit. Set the GITHUB_TOKEN environment "
                "variable or try again later."
            ) from exc
        raise RuntimeError(f"GitHub API error {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Network error while contacting GitHub: {exc.reason}") from exc


def go_bin_dirs():
    """Possible Go binary directories (honours GOBIN / GOPATH)."""
    dirs = []
    go = shutil.which("go")
    if go:
        for var, suffix in (("GOBIN", ""), ("GOPATH", "bin")):
            try:
                out = subprocess.run(
                    [go, "env", var], capture_output=True, text=True, timeout=15
                ).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                out = ""
            if out:
                # GOPATH can contain several entries
                for part in out.split(os.pathsep):
                    dirs.append(Path(part) / suffix if suffix else Path(part))
    dirs.append(Path.home() / "go" / "bin")
    return dirs


def find_tool(name):
    exe = TOOLS[name]["exe"]
    found = shutil.which(name)
    if found:
        return str(Path(found).resolve())

    _, _, base_dir, _ = detect_platform()
    candidates = [
        base_dir / name / exe,  # where install_tool() puts the binary
        base_dir / exe,
        Path.home() / ".local" / "bin" / exe,
        *[d / exe for d in go_bin_dirs()],
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.resolve())
    return None


_PATH_LOCK = threading.Lock()


def add_directory_to_path(directory: Path, persist=False):
    with _PATH_LOCK:
        _add_directory_to_path(directory, persist)


def _add_directory_to_path(directory: Path, persist=False):
    directory = directory.resolve()
    current = os.environ.get("PATH", "")
    parts = current.split(os.pathsep) if current else []
    if str(directory) not in parts:
        os.environ["PATH"] = str(directory) + os.pathsep + current

    if not persist:
        return

    _, _, _, kaggle = detect_platform()
    if kaggle:
        print(f"  PATH set for this session: {directory}")
        return

    try:
        if platform.system().lower() == "windows":
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, "Environment", 0,
                winreg.KEY_READ | winreg.KEY_SET_VALUE,
            ) as key:
                try:
                    old, _ = winreg.QueryValueEx(key, "Path")
                except FileNotFoundError:
                    old = ""
                values = [p for p in old.split(";") if p]
                if str(directory).lower() not in [p.lower() for p in values]:
                    values.append(str(directory))
                    winreg.SetValueEx(
                        key, "Path", 0, winreg.REG_EXPAND_SZ, ";".join(values)
                    )
            print(f"  Permanent user PATH updated: {directory}")
            print("  Open a new terminal for the change to apply.")
        else:
            shell_files = [Path.home() / ".profile", Path.home() / ".bashrc"]
            zshrc = Path.home() / ".zshrc"
            if zshrc.exists() or platform.system().lower() == "darwin":
                shell_files.append(zshrc)
            line = f'export PATH="{directory}:$PATH"'
            for rc_file in shell_files:
                try:
                    old = rc_file.read_text(encoding="utf-8") if rc_file.exists() else ""
                    if str(directory) not in old:
                        with rc_file.open("a", encoding="utf-8") as handle:
                            handle.write("\n# Added by katana_gau_recon\n" + line + "\n")
                except OSError as exc:
                    print(f"  Could not update {rc_file}: {exc}")
            print(f"  PATH configured in shell profile: {directory}")
    except Exception as exc:  # noqa: BLE001
        print(f"  PATH is set for this process; permanent update skipped: {exc}")


def asset_matches(asset_name, os_name, arch, tool=None):
    name = asset_name.lower()
    os_token = os_name.lower()
    # GAU publishes macOS builds as "darwin", Katana as "macOS"
    if tool == "gau" and os_token == "macos":
        os_token = "darwin"
    if f"_{os_token}_" not in name or f"_{arch.lower()}" not in name:
        return False
    return name.endswith((".zip", ".tar.gz", ".tgz"))


def sha256_of(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_checksum(archive_path: Path, assets):
    """Verify the archive against the release's checksums file when published."""
    checksum_asset = next(
        (a for a in assets
         if "checksum" in a.get("name", "").lower()
         and a.get("name", "").lower().endswith(".txt")),
        None,
    )
    if not checksum_asset:
        print("  Warning: no checksums file in release; skipping verification.")
        return

    with urllib.request.urlopen(
        _github_request(checksum_asset["browser_download_url"], token_ok=False),
        timeout=30,
    ) as response:
        text = response.read().decode("utf-8", errors="replace")

    expected = None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == archive_path.name:
            expected = parts[0].lower()
            break

    if not expected:
        print("  Warning: archive not listed in checksums file; skipping verification.")
        return

    actual = sha256_of(archive_path)
    if actual != expected:
        archive_path.unlink(missing_ok=True)
        raise RuntimeError(
            f"Checksum mismatch for {archive_path.name}: expected {expected}, got {actual}"
        )
    print("  SHA-256 checksum verified.")


def extract_binary(archive_path: Path, exe_name: str, destination: Path):
    destination.mkdir(parents=True, exist_ok=True)
    temp_dir = destination / "_extract_tmp"
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir(parents=True)

    member_found = False
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.namelist():
                if Path(member).name.lower() == exe_name.lower():
                    with archive.open(member) as src, (temp_dir / exe_name).open("wb") as dst:
                        shutil.copyfileobj(src, dst)
                    member_found = True
                    break
    elif tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path, "r:*") as archive:
            member = next(
                (m for m in archive.getmembers()
                 if Path(m.name).name.lower() == exe_name.lower() and m.isfile()),
                None,
            )
            if member:
                source = archive.extractfile(member)
                if source:
                    with source, (temp_dir / exe_name).open("wb") as dst:
                        shutil.copyfileobj(source, dst)
                    member_found = True

    if not member_found:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise RuntimeError(f"{exe_name} was not found inside {archive_path.name}")

    final_path = destination / exe_name
    if final_path.exists():
        final_path.unlink()
    shutil.move(str(temp_dir / exe_name), final_path)
    shutil.rmtree(temp_dir, ignore_errors=True)
    if os.name != "nt":
        final_path.chmod(0o755)
    archive_path.unlink(missing_ok=True)
    return final_path


def install_with_go(name):
    go = shutil.which("go")
    if not go:
        return None
    subprocess.run([go, "install", TOOLS[name]["go_package"]], check=True, timeout=900)
    exe_name = TOOLS[name]["exe"]
    for directory in go_bin_dirs():
        candidate = directory / exe_name
        if candidate.is_file():
            return str(candidate.resolve())
    return None


def install_tool(name):
    print(f"\n=== Installing {name} ===")
    os_name, arch, base_dir, _ = detect_platform()
    exe_name = TOOLS[name]["exe"]
    install_dir = base_dir / name
    install_dir.mkdir(parents=True, exist_ok=True)

    repo = TOOLS[name]["repo"]
    release = github_json(f"https://api.github.com/repos/{repo}/releases/latest")
    assets = release.get("assets", [])
    asset = next(
        (item for item in assets
         if asset_matches(item.get("name", ""), os_name, arch, name)),
        None,
    )

    if not asset:
        go_path = install_with_go(name)
        if go_path:
            return go_path
        raise RuntimeError(
            f"No downloadable {os_name}/{arch} release asset found for {name}. "
            "Install Go and retry, or install the tool manually."
        )

    archive_path = install_dir / asset["name"]
    print(f"Downloading {asset['name']} ({release.get('tag_name', 'latest')})...")
    try:
        with urllib.request.urlopen(
            _github_request(asset["browser_download_url"], token_ok=False), timeout=120
        ) as response, archive_path.open("wb") as out:
            shutil.copyfileobj(response, out)
    except urllib.error.URLError as exc:
        archive_path.unlink(missing_ok=True)
        raise RuntimeError(f"Download failed: {exc}") from exc

    verify_checksum(archive_path, assets)
    executable = extract_binary(archive_path, exe_name, install_dir)
    return str(executable.resolve())


def make_executable(path):
    """chmod +x when the binary lacks the execute bit (e.g. Kaggle/Colab unzip)."""
    if os.name == "nt":
        return path
    target = Path(path)
    if not os.access(target, os.X_OK):
        try:
            target.chmod(target.stat().st_mode | 0o755)
            print(f"chmod +x applied: {target}")
        except OSError as exc:
            print(f"Could not chmod +x {target}: {exc}")
    return path


def copy_to_exec_dir(name, path):
    """Fallback for noexec mounts (e.g. /kaggle/working): run from a temp dir."""
    exec_dir = Path(tempfile.gettempdir()) / "recon-bin"
    exec_dir.mkdir(parents=True, exist_ok=True)
    destination = exec_dir / Path(path).name
    shutil.copy2(path, destination)
    destination.chmod(0o755)
    print(f"{name}: original location is not executable; using copy at {destination}")
    return str(destination)


def _print_version(name, path):
    check = subprocess.run(
        [path, TOOLS[name]["version_flag"]],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=30,
    )
    version_text = (check.stdout or check.stderr).strip()
    if check.returncode == 0 and version_text:
        print(f"{name} version: {version_text.splitlines()[0]}")
    else:
        print(f"{name} executable found; version flag not confirmed.")


def ensure_tool(name, persist_path=False):
    path = find_tool(name)
    if path:
        print(f"{name} found: {path}")
    else:
        print(f"{name} not found. Installing...")
        path = install_tool(name)

    path = make_executable(path)

    try:
        _print_version(name, path)
    except PermissionError:
        # chmod did not help -> the filesystem is probably mounted noexec.
        path = copy_to_exec_dir(name, path)
        try:
            _print_version(name, path)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"{name} cannot be executed: {exc}") from exc
    except (OSError, subprocess.SubprocessError):
        print(f"{name} executable found; version check failed.")

    add_directory_to_path(Path(path).parent, persist=persist_path)
    return path


# --------------------------------------------------------------------------
# Target / scope
# --------------------------------------------------------------------------
def normalize_target(target):
    parsed = urlparse(target if "://" in target else "https://" + target)
    if not parsed.hostname:
        raise ValueError("Please provide a valid target URL/domain.")
    scheme = parsed.scheme if parsed.scheme in ("http", "https") else "https"
    return urlunparse((scheme, parsed.netloc, parsed.path or "/", "", "", ""))


def default_scope_domain(target_host):
    """Strip a leading 'www.' so sibling subdomains (api.example.com) stay in scope."""
    host = target_host.lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def in_scope(url, scope_domain):
    try:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
        scope = scope_domain.lower().rstrip(".")
        return host == scope or host.endswith("." + scope)
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------
# Tool runners
# --------------------------------------------------------------------------
def _run(command, label, timeout):
    print(f"\nRunning {label}...")
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"{label} timed out after {timeout}s"}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}

    if result.returncode != 0:
        return {"ok": False, "error": result.stderr.strip() or f"{label} failed"}
    return {"ok": True, "stderr": result.stderr.strip()}


def run_katana(path, target, depth, timeout, output_file,
               rate_limit=10, concurrency=5):
    command = [
        path, "-u", target, "-d", str(depth), "-jc", "-xhr",
        "-kf", "all", "-jsonl", "-silent", "-duc",
        "-rl", str(rate_limit), "-c", str(concurrency),
        # Graceful stop: Katana ends the crawl itself and keeps its output.
        "-ct", f"{timeout}s",
        "-o", str(output_file),
    ]
    # Hard kill only as a safety net, slightly after the crawl-duration limit.
    return _run(command, "Katana", timeout + 60)


def run_gau(path, domain, timeout, output_file, include_subdomains=True,
            threads=10, providers=None, skip_static=True):
    command = [path, domain, "--threads", str(threads)]
    if include_subdomains:
        command.append("--subs")
    if providers:
        command.extend(["--providers", providers])
    if skip_static:
        # Don't even fetch images/css/fonts: fewer URLs to process and probe.
        command.extend(["--blacklist",
                        ",".join(sorted(e.lstrip(".") for e in STATIC_EXTENSIONS))])
    command.extend(["--o", str(output_file)])
    return _run(command, "GAU", timeout)


# --------------------------------------------------------------------------
# Processing
# --------------------------------------------------------------------------
def classify_endpoint(parsed):
    path = parsed.path.lower()
    if "graphql" in path:
        return "GRAPHQL"
    if re.search(r"(^|/)(api|v[0-9]+)(/|$)", path):
        return "API"
    return "WEB"


def get_header(headers, wanted):
    """Case-insensitive header lookup (also tolerates '_' instead of '-')."""
    if not isinstance(headers, dict):
        return None
    wanted = wanted.lower().replace("_", "-")
    for key, value in headers.items():
        if str(key).lower().replace("_", "-") == wanted:
            return value
    return None


def is_active_status(code):
    """An endpoint counts as active if it answers with < 400, or 401/403/405
    (it exists but is protected / method-restricted)."""
    if code is None:
        return False
    return code < 400 or code in ACTIVE_EXTRA_STATUS


def endpoint_record(url, method="GET", source=None, status_code=None,
                    content_type=None):
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    return {
        "url": url,
        "method": method.upper(),
        "host": parsed.netloc.lower(),
        "path": parsed.path or "/",
        "parameters": sorted(query.keys()),
        "parameter_count": len(query),
        "query_values": query,
        "extension": Path(parsed.path).suffix.lower(),
        "status_code": status_code,
        "content_type": content_type,
        "content_length": None,
        "final_url": None,
        "alive": is_active_status(status_code) if status_code is not None else None,
        "probed": False,
        "probe_error": None,
        "probe_inferred": False,
        "soft_404_suspect": False,
        "state": "unverified",
        "sources": [source] if source else [],
        "category": classify_endpoint(parsed),
    }


# --------------------------------------------------------------------------
# Liveness probing (used for GAU's historical URLs)
# --------------------------------------------------------------------------
STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".webm", ".avi", ".map",
}
ACTIVE_EXTRA_STATUS = {401, 403, 405}
# GET requests to these could change state on badly designed apps; never probe them.
UNSAFE_PATH_RE = re.compile(
    r"(log[-_]?out|sign[-_]?out|delete|remove|unsubscribe|deactivate|destroy|revoke)",
    re.IGNORECASE,
)
PROBE_USER_AGENT = "Mozilla/5.0 (compatible; katana-gau-recon/1.0)"
_PROBE_FIELDS = ("status_code", "content_type", "content_length", "final_url",
                 "alive", "probe_error", "probed", "probe_inferred")


@dataclass
class ProbeConfig:
    enabled: bool = True
    threads: int = 30
    timeout: int = 8
    rate: float = 40.0          # requests per second (global)
    max_probe: int = 5000
    include_static: bool = False
    insecure: bool = False      # skip TLS certificate verification
    soft404_check: bool = True  # detect catch-all hosts (random-path baseline)
    keep_soft404: bool = False  # keep soft-404 suspects in the active list
    dedupe: bool = True         # probe one URL per (host, path, param names)


class RateLimiter:
    """Global requests-per-second limiter shared by all probe threads."""

    def __init__(self, rate):
        self.interval = 1.0 / max(rate, 0.1)
        self.lock = threading.Lock()
        self.next_time = time.monotonic()

    def wait(self):
        with self.lock:
            now = time.monotonic()
            if self.next_time < now:
                self.next_time = now
            delay = self.next_time - now
            self.next_time += self.interval
        if delay > 0:
            time.sleep(delay)


def make_ssl_context(insecure=False):
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


# Keep-alive connections, one set per worker thread (no TLS handshake per URL).
# Redirects are never followed by the library; probe_url does it manually so
# every hop can be scope-checked.
_tls = threading.local()
_QUOTE_SAFE = "/?&=%:@!$'()*+,;~-._#[]"
_STALE_ERRORS = (
    http.client.RemoteDisconnected, http.client.CannotSendRequest,
    http.client.ResponseNotReady, ConnectionResetError, BrokenPipeError,
)


def _request_once(ctx, url, method, timeout, limiter):
    limiter.wait()
    parsed = urlparse(url)
    target = quote(
        (parsed.path or "/") + ("?" + parsed.query if parsed.query else ""),
        safe=_QUOTE_SAFE,
    )
    headers = {"User-Agent": PROBE_USER_AGENT, "Accept": "*/*"}
    if method == "GET":
        headers["Range"] = "bytes=0-0"  # ask for a single byte; body is never read

    conns = _tls.__dict__.setdefault("conns", {})
    key = (parsed.scheme, parsed.netloc)
    for attempt in range(2):
        conn = conns.get(key)
        fresh = conn is None
        if fresh:
            if parsed.scheme == "https":
                conn = http.client.HTTPSConnection(parsed.netloc, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(parsed.netloc, timeout=timeout)
            conns[key] = conn
        try:
            conn.request(method, target, headers=headers)
            response = conn.getresponse()
            status, hdrs = response.status, response.msg
            if method == "HEAD":
                response.read()  # empty; frees the connection for reuse
            if method != "HEAD" or response.will_close:
                conn.close()
                conns.pop(key, None)
            return status, hdrs
        except _STALE_ERRORS:
            conn.close()
            conns.pop(key, None)
            if fresh or attempt == 1:
                raise
        except Exception:
            conn.close()
            conns.pop(key, None)
            raise


def probe_url(url, scope_domain, ctx, timeout, limiter, max_redirects=3):
    """Safe liveness check: HEAD (single-byte GET only if HEAD is unsupported),
    redirects followed only while they stay in scope. Never raises."""
    result = {
        "alive": False, "status_code": None, "final_url": None,
        "content_type": None, "content_length": None, "error": None,
    }
    current = url
    try:
        status, headers = None, None
        for _ in range(max_redirects + 1):
            status, headers = _request_once(ctx, current, "HEAD", timeout, limiter)
            if status in (400, 405, 501):
                status, headers = _request_once(ctx, current, "GET", timeout, limiter)

            location = headers.get("Location") if headers else None
            if 300 <= status < 400 and location:
                nxt = urljoin(current, location)
                if nxt.startswith(("http://", "https://")) and in_scope(nxt, scope_domain):
                    current = nxt
                    continue
            break

        result["status_code"] = status
        result["alive"] = is_active_status(status)
        result["final_url"] = current if current != url else None
        if headers:
            result["content_type"] = headers.get("Content-Type")
            length = headers.get("Content-Length")
            result["content_length"] = int(length) if length and length.isdigit() else None
    except Exception as exc:  # noqa: BLE001 - network errors, bad URLs, TLS, timeouts
        result["error"] = f"{type(exc).__name__}: {exc}"[:200]
    return result


def _ctype(value):
    return (value or "").split(";")[0].strip().lower()


def _signature(item):
    """Works for probe results (error key) and records alike."""
    return (item["status_code"], _ctype(item["content_type"]),
            item["content_length"], item["final_url"])


def _dedupe_key(record):
    parsed = urlparse(record["url"])
    return (parsed.scheme, parsed.netloc.lower(), parsed.path or "/",
            tuple(record["parameters"]))


def _copy_probe(src, dst):
    for field in _PROBE_FIELDS:
        dst[field] = src[field]


def probe_endpoints(records, scope_domain, cfg: ProbeConfig, ctx, limiter):
    """Probe unverified GET records in place and return statistics."""
    stats = {
        "enabled": True, "candidates": 0, "probed": 0, "inferred": 0, "deduped": 0,
        "skipped_static": 0, "skipped_unsafe": 0, "skipped_over_limit": 0,
        "active": 0, "inactive": 0, "errors": 0,
        "soft_404_suspects": 0, "catch_all_hosts": [],
    }

    candidates = []
    for record in records.values():
        if record["status_code"] is not None or record["method"] != "GET" or record["probed"]:
            continue  # already observed or already probed
        stats["candidates"] += 1
        if not cfg.include_static and record["extension"] in STATIC_EXTENSIONS:
            stats["skipped_static"] += 1
            continue
        if UNSAFE_PATH_RE.search(record["path"]):
            stats["skipped_unsafe"] += 1
            continue
        candidates.append(record)

    # API/GraphQL and parameterised URLs first, in case the cap cuts the list.
    candidates.sort(key=lambda r: (r["category"] == "WEB", r["parameter_count"] == 0, r["url"]))

    # One request per (host, path, parameter names); the rest inherit the result.
    groups = {}
    if cfg.dedupe:
        for rec in candidates:
            groups.setdefault(_dedupe_key(rec), []).append(rec)
        reps = [members[0] for members in groups.values()]
        stats["deduped"] = len(candidates) - len(reps)
    else:
        reps = candidates

    if len(reps) > cfg.max_probe:
        stats["skipped_over_limit"] = len(reps) - cfg.max_probe
        reps = reps[: cfg.max_probe]

    if not reps:
        return stats

    print(f"\nProbing {len(reps)} historical URLs "
          f"({stats['deduped']} duplicates inferred; {cfg.threads} threads, "
          f"{cfg.rate:g} req/s)...")

    pool = ThreadPoolExecutor(max_workers=cfg.threads)
    futures = {
        pool.submit(probe_url, rec["url"], scope_domain, ctx, cfg.timeout, limiter): rec
        for rec in reps
    }
    done = 0
    try:
        for future in as_completed(futures):
            record = futures[future]
            res = future.result()
            record["probed"] = True
            record["status_code"] = res["status_code"]
            record["content_type"] = res["content_type"]
            record["content_length"] = res["content_length"]
            record["final_url"] = res["final_url"]
            # Network errors/timeouts say nothing about the endpoint -> keep unknown.
            record["alive"] = None if res["error"] else res["alive"]
            record["probe_error"] = res["error"]

            done += 1
            stats["probed"] += 1
            if res["error"]:
                stats["errors"] += 1
            elif res["alive"]:
                stats["active"] += 1
            else:
                stats["inactive"] += 1
            if done % 200 == 0 or done == len(reps):
                print(f"  probed {done}/{len(reps)}  active so far: {stats['active']}")
        pool.shutdown(wait=True)
    except KeyboardInterrupt:
        print("\nProbing interrupted; saving results collected so far.")
        pool.shutdown(wait=False, cancel_futures=True)
        # Records that were never probed stay alive=None (unverified).

    if cfg.dedupe:
        for rep in reps:
            if not rep["probed"]:
                continue
            for member in groups[_dedupe_key(rep)][1:]:
                _copy_probe(rep, member)
                member["probe_inferred"] = True
                stats["inferred"] += 1
    return stats


def run_soft404(records, scope_domain, cfg, ctx, limiter, stats):
    """Request one random, non-existent path per scheme+host. If the host still
    answers 'active', it is a catch-all (SPA / wildcard redirect); probed URLs
    whose response matches that baseline are flagged as soft-404 suspects."""
    groups = {}
    for rec in records.values():
        if rec["probed"] and rec["alive"] is True:
            parsed = urlparse(rec["url"])
            groups.setdefault((parsed.scheme, parsed.netloc), []).append(rec)
    if not groups:
        return

    print("\nChecking for soft-404 / catch-all hosts...")

    def baseline(key):
        scheme, netloc = key
        url = f"{scheme}://{netloc}/zz-{uuid.uuid4().hex[:12]}"
        return key, probe_url(url, scope_domain, ctx, cfg.timeout, limiter)

    flagged, catch_all = 0, []
    with ThreadPoolExecutor(max_workers=cfg.threads) as pool:
        for key, res in pool.map(baseline, list(groups)):
            if not res["alive"]:
                continue  # random path is dead -> host answers honestly
            catch_all.append(f"{key[0]}://{key[1]}")
            sig = _signature(res)
            for rec in groups[key]:
                if _signature(rec) == sig:
                    rec["soft_404_suspect"] = True
                    flagged += 1
    stats["soft_404_suspects"] = flagged
    stats["catch_all_hosts"] = sorted(catch_all)
    print(f"  catch-all hosts: {len(catch_all)}, soft-404 suspects: {flagged}")


def merge_probe_stats(pre, final):
    out = dict(final)
    for key in ("probed", "active", "inactive", "errors", "inferred", "deduped"):
        out[key] = pre.get(key, 0) + final.get(key, 0)
    out["candidates"] = max(pre.get("candidates", 0), final.get("candidates", 0))
    return out


# --------------------------------------------------------------------------
# Output processing
# --------------------------------------------------------------------------
def build_records(paths: Paths, scope_domain):
    """Merge Katana + GAU raw output into one record per (method, url)."""
    records = {}

    if paths.katana_raw.exists():
        with paths.katana_raw.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue

                request = item.get("request") or {}
                response = item.get("response") or {}
                url = request.get("endpoint") or item.get("endpoint") or item.get("url")
                if not url or not in_scope(url, scope_domain):
                    continue

                method = (request.get("method") or item.get("method") or "GET").upper()
                key = (method, url)
                if key in records:
                    continue
                records[key] = endpoint_record(
                    url, method, "katana",
                    response.get("status_code"),
                    get_header(response.get("headers"), "content-type"),
                )

    # GAU URLs are historical; liveness is established later by probing.
    if paths.gau_raw.exists():
        with paths.gau_raw.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                url = line.strip()
                if not url.startswith(("http://", "https://")):
                    continue
                if not in_scope(url, scope_domain):
                    continue

                key = ("GET", url)
                if key in records:
                    if "gau" not in records[key]["sources"]:
                        records[key]["sources"].append("gau")
                else:
                    records[key] = endpoint_record(url, "GET", "gau")

    return records


def gau_only_records(paths: Paths, scope_domain):
    """Records for GAU's URLs alone (used to start probing before Katana ends)."""
    records = {}
    if paths.gau_raw.exists():
        with paths.gau_raw.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                url = line.strip()
                if url.startswith(("http://", "https://")) and in_scope(url, scope_domain):
                    records.setdefault(("GET", url), endpoint_record(url, "GET", "gau"))
    return records


def _write_lines(path: Path, items):
    text = "\n".join(f'{i["method"]} {i["url"]}' for i in items)
    path.write_text(text + ("\n" if text else ""), encoding="utf-8")


def record_state(record, keep_soft404=False):
    """active | inactive | error | soft_404_suspect | unverified"""
    if record["probe_error"]:
        return "error"
    if record["alive"] is True:
        if record["soft_404_suspect"] and not keep_soft404:
            return "soft_404_suspect"
        return "active"
    if record["alive"] is False:
        return "inactive"
    return "unverified"


def process_outputs(paths: Paths, target_host, scope_domain, failures=None,
                    probe: ProbeConfig | None = None, probe_cache=None,
                    pre_stats=None):
    records = build_records(paths, scope_domain)

    # Results already obtained while Katana was still crawling.
    if probe_cache:
        for rec in records.values():
            if rec["status_code"] is None and rec["method"] == "GET" and not rec["probed"]:
                fields = probe_cache.get(rec["url"])
                if fields:
                    rec.update(fields)

    probe_stats = {"enabled": False}
    if probe and probe.enabled:
        ctx = make_ssl_context(probe.insecure)
        limiter = RateLimiter(probe.rate)
        budget = probe.max_probe - (pre_stats or {}).get("probed", 0)
        if budget > 0:
            probe_stats = probe_endpoints(
                records, scope_domain, replace(probe, max_probe=budget), ctx, limiter
            )
        else:
            probe_stats = {"enabled": True, "candidates": 0, "probed": 0, "inferred": 0,
                           "deduped": 0, "skipped_static": 0, "skipped_unsafe": 0,
                           "skipped_over_limit": 0, "active": 0, "inactive": 0,
                           "errors": 0, "soft_404_suspects": 0, "catch_all_hosts": []}
        if pre_stats:
            probe_stats = merge_probe_stats(pre_stats, probe_stats)
        if probe.soft404_check:
            run_soft404(records, scope_domain, probe, ctx, limiter, probe_stats)

    results = sorted(
        records.values(),
        key=lambda item: (item["host"], item["path"], item["method"], item["url"]),
    )
    keep_soft404 = bool(probe and probe.keep_soft404)
    for r in results:
        r["state"] = record_state(r, keep_soft404)
    active = [r for r in results if r["state"] == "active"]
    inactive = [r for r in results if r["state"] == "inactive"]
    errors = [r for r in results if r["state"] == "error"]
    soft404 = [r for r in results if r["state"] == "soft_404_suspect"]
    unverified = [r for r in results if r["state"] == "unverified"]
    # Historical (GAU) URLs that are confirmed still alive.
    gau_active = [r for r in active if "gau" in r["sources"]]

    paths.report_dir.mkdir(parents=True, exist_ok=True)
    paths.json_report.write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _write_lines(paths.txt_report, results)
    # Active endpoints: Katana-observed (status < 400 or 401/403/405) + probed-alive GAU URLs.
    paths.active_json.write_text(
        json.dumps(active, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _write_lines(paths.active_txt, active)
    _write_lines(paths.inactive_txt, inactive)
    _write_lines(paths.errors_txt, errors)
    _write_lines(paths.soft404_txt, soft404)
    paths.gau_active_json.write_text(
        json.dumps(gau_active, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _write_lines(paths.gau_active_txt, gau_active)

    summary = {
        "target_host": target_host,
        "scope_domain": scope_domain,
        "total_unique_endpoints": len(results),
        "active_endpoints": len(active),
        "inactive_endpoints": len(inactive),
        "unverified_endpoints": len(unverified),
        "error_endpoints": len(errors),
        "soft_404_suspects": len(soft404),
        "gau_active_endpoints": len(gau_active),
        "active_status_codes": dict(
            sorted(Counter(r["status_code"] for r in active).items())
        ),
        "sources": {
            "katana": sum("katana" in item["sources"] for item in results),
            "gau": sum("gau" in item["sources"] for item in results),
            "both": sum(set(item["sources"]) == {"katana", "gau"} for item in results),
        },
        "categories": {
            category: sum(item["category"] == category for item in results)
            for category in ("API", "GRAPHQL", "WEB")
        },
        "active_categories": {
            category: sum(item["category"] == category for item in active)
            for category in ("API", "GRAPHQL", "WEB")
        },
        "methods": {
            method: sum(item["method"] == method for item in results)
            for method in sorted({item["method"] for item in results})
        },
        "probe": probe_stats,
        "failures": failures or [],
        "report_directory": str(paths.report_dir),
        "note": (
            "Active = HTTP status < 400, or 401/403/405. GAU URLs are verified with "
            "safe HEAD requests (GET only if HEAD is unsupported). Network errors/timeouts "
            "are listed separately (endpoints_errors.txt), not as inactive. Hosts that "
            "answer a random non-existent path are treated as catch-all and matching "
            "responses go to endpoints_soft404_suspect.txt (--keep-soft404 keeps them "
            "in the active list)."
        ),
    }
    paths.summary_report.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return results, summary


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def discover_endpoints(
    target,
    depth=3,
    timeout=300,
    use_katana=True,
    use_gau=True,
    include_subdomains=True,
    report_dir="reports",
    scope_domain=None,
    rate_limit=50,
    concurrency=10,
    persist_path=False,
    probe=True,
    probe_threads=30,
    probe_timeout=8,
    probe_rate=40.0,
    max_probe=5000,
    include_static=False,
    insecure=False,
    soft404_check=True,
    keep_soft404=False,
    dedupe=True,
    gau_threads=10,
    gau_providers=None,
):
    """
    Import-friendly endpoint discovery.
    Checks/installs tools, runs discovery, probes GAU's historical URLs for
    liveness, merges results and returns (endpoints, summary).
    """
    if not use_katana and not use_gau:
        raise ValueError("Enable at least one tool: Katana or GAU.")
    if depth < 1 or timeout < 1:
        raise ValueError("depth and timeout must be positive.")
    if rate_limit < 1 or concurrency < 1:
        raise ValueError("rate_limit and concurrency must be positive.")
    if gau_threads < 1:
        raise ValueError("gau_threads must be positive.")
    if probe_threads < 1 or probe_timeout < 1 or probe_rate <= 0 or max_probe < 1:
        raise ValueError("probe_threads, probe_timeout, probe_rate and max_probe must be positive.")

    paths = Paths.from_dir(report_dir)
    paths.prepare()

    target = normalize_target(target)
    target_host = urlparse(target).hostname.lower()
    scope_domain = (scope_domain or default_scope_domain(target_host)).lower()

    failures = []
    started = time.monotonic()

    probe_cfg = ProbeConfig(
        enabled=probe and use_gau,
        threads=probe_threads,
        timeout=probe_timeout,
        rate=probe_rate,
        max_probe=max_probe,
        include_static=include_static,
        insecure=insecure,
        soft404_check=soft404_check,
        keep_soft404=keep_soft404,
        dedupe=dedupe,
    )

    def katana_job():
        try:
            katana_path = ensure_tool("katana", persist_path)
            result = run_katana(
                katana_path, target, depth, timeout, paths.katana_raw,
                rate_limit, concurrency,
            )
            return [] if result["ok"] else ["Katana: " + result["error"]]
        except Exception as exc:  # noqa: BLE001
            return ["Katana setup: " + str(exc)]

    def gau_job():
        """Run GAU, then probe its URLs right away - Katana may still be crawling."""
        fails, cache, stats = [], None, None
        try:
            gau_path = ensure_tool("gau", persist_path)
            result = run_gau(
                gau_path, scope_domain, timeout, paths.gau_raw, include_subdomains,
                threads=gau_threads, providers=gau_providers,
                skip_static=not include_static,
            )
            if not result["ok"]:
                fails.append("GAU: " + result["error"])
        except Exception as exc:  # noqa: BLE001
            fails.append("GAU setup: " + str(exc))

        if probe_cfg.enabled and paths.gau_raw.exists():
            try:
                pre = gau_only_records(paths, scope_domain)
                stats = probe_endpoints(
                    pre, scope_domain, probe_cfg,
                    make_ssl_context(insecure), RateLimiter(probe_rate),
                )
                cache = {
                    rec["url"]: {f: rec[f] for f in _PROBE_FIELDS}
                    for rec in pre.values() if rec["probed"]
                }
            except Exception as exc:  # noqa: BLE001
                fails.append("GAU probe: " + str(exc))
        return fails, cache, stats

    # Katana and GAU (install + run + GAU probing) all run in parallel.
    gau_cache, gau_stats = None, None
    with ThreadPoolExecutor(max_workers=2) as pool:
        katana_future = pool.submit(katana_job) if use_katana else None
        gau_future = pool.submit(gau_job) if use_gau else None
        if katana_future:
            failures.extend(katana_future.result())
        if gau_future:
            gau_failures, gau_cache, gau_stats = gau_future.result()
            failures.extend(gau_failures)

    endpoints, summary = process_outputs(
        paths, target_host, scope_domain, failures, probe_cfg,
        probe_cache=gau_cache, pre_stats=gau_stats,
    )
    elapsed = time.monotonic() - started

    # Cleanup: keep only endpoints_active.json and endpoints_summary.json

    keep_files = {
        "endpoints_active.json",
        "endpoints_summary.json",
    }

    for item in paths.report_dir.iterdir():
        if item.name in keep_files:
            continue

        try:
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
        except Exception as e:
            print(f"[!] Cleanup failed: {item.name} - {e}")

    print("[+] Cleanup complete. Only endpoints_active.json and endpoints_summary.json retained.")


    print("\n========== DISCOVERY COMPLETE ==========")
    print("Total time:        ", f"{elapsed:.0f}s")
    print("Target:            ", target)
    print("Scope domain:      ", scope_domain)
    print("Total endpoints:   ", summary["total_unique_endpoints"])
    print("Active endpoints:  ", summary["active_endpoints"])
    print("Inactive endpoints:", summary["inactive_endpoints"])
    print("Unverified:        ", summary["unverified_endpoints"])
    print("Probe errors:      ", summary["error_endpoints"])
    print("Soft-404 suspects: ", summary["soft_404_suspects"])
    print("GAU active:        ", summary["gau_active_endpoints"])
    print("All (JSON):        ", paths.json_report)
    print("Active (JSON):     ", paths.active_json)
    print("Active (TXT):      ", paths.active_txt)
    print("GAU active (TXT):  ", paths.gau_active_txt)
    print("Summary:           ", paths.summary_report)
    if failures:
        print("\nSome steps failed:")
        for failure in failures:
            print(f"  - {failure}")
    if not endpoints:
        print("No in-scope endpoints were collected.")

    return endpoints, summary


def main():
    parser = argparse.ArgumentParser(
        description="Install/check Katana + GAU, discover endpoints, and verify "
                    "which historical (GAU) URLs are still active."
    )
    parser.add_argument("target", help="Authorized target URL/domain")
    parser.add_argument("--depth", type=int, default=3, help="Katana crawl depth")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Max seconds per tool (Katana stops gracefully)")
    parser.add_argument("--skip-katana", action="store_true", help="Skip Katana")
    parser.add_argument("--skip-gau", action="store_true", help="Skip GAU")
    parser.add_argument("--no-subs", action="store_true", help="Do not include GAU subdomains")
    parser.add_argument("--scope-domain",
                        help="Domain used for scope filtering and GAU "
                             "(default: target host without 'www.')")
    parser.add_argument("--rate-limit", type=int, default=50,
                        help="Katana requests per second (default: 50)")
    parser.add_argument("--concurrency", type=int, default=10,
                        help="Katana concurrency (default: 10)")
    parser.add_argument("--gau-threads", type=int, default=10,
                        help="GAU threads (default: 10)")
    parser.add_argument("--gau-providers",
                        help="GAU providers, e.g. wayback,commoncrawl,otx,urlscan "
                             "(fewer providers = faster)")
    parser.add_argument("--report-dir", default="reports", help="Output directory")
    parser.add_argument("--persist-path", action="store_true",
                        help="Permanently add the tool install directory to PATH")

    probe_group = parser.add_argument_group("GAU liveness probing")
    probe_group.add_argument("--no-probe", action="store_true",
                             help="Do not verify GAU URLs (they stay 'unverified')")
    probe_group.add_argument("--probe-threads", type=int, default=30,
                             help="Probe worker threads (default: 30)")
    probe_group.add_argument("--probe-timeout", type=int, default=8,
                             help="Per-request timeout in seconds (default: 8)")
    probe_group.add_argument("--probe-rate", type=float, default=40.0,
                             help="Max probe requests per second, total (default: 40)")
    probe_group.add_argument("--max-probe", type=int, default=5000,
                             help="Max GAU URLs to probe (default: 5000)")
    probe_group.add_argument("--include-static", action="store_true",
                             help="Also probe static files (images, css, fonts...)")
    probe_group.add_argument("--insecure", action="store_true",
                             help="Skip TLS certificate verification while probing")
    probe_group.add_argument("--no-dedupe", action="store_true",
                             help="Probe every URL instead of one per (host, path, params)")
    probe_group.add_argument("--no-soft404-check", action="store_true",
                             help="Skip catch-all / soft-404 detection")
    probe_group.add_argument("--keep-soft404", action="store_true",
                             help="Keep soft-404 suspects in the active list")
    args = parser.parse_args()

    if args.gau_threads < 1:
        parser.error("--gau-threads must be positive")
    if args.depth < 1 or args.timeout < 1:
        parser.error("--depth and --timeout must be positive integers")
    if args.rate_limit < 1 or args.concurrency < 1:
        parser.error("--rate-limit and --concurrency must be positive integers")

    try:
        _, summary = discover_endpoints(
            args.target,
            depth=args.depth,
            timeout=args.timeout,
            use_katana=not args.skip_katana,
            use_gau=not args.skip_gau,
            include_subdomains=not args.no_subs,
            report_dir=args.report_dir,
            scope_domain=args.scope_domain,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            persist_path=args.persist_path,
            probe=not args.no_probe,
            probe_threads=args.probe_threads,
            probe_timeout=args.probe_timeout,
            probe_rate=args.probe_rate,
            max_probe=args.max_probe,
            include_static=args.include_static,
            insecure=args.insecure,
            soft404_check=not args.no_soft404_check,
            keep_soft404=args.keep_soft404,
            dedupe=not args.no_dedupe,
            gau_threads=args.gau_threads,
            gau_providers=args.gau_providers,
        )
    except ValueError as exc:
        parser.error(str(exc))

    return 1 if summary["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())