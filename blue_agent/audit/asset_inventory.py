"""
Asset Inventory — discovers what the target application exposes.

Collects:
- source files
- running services / open ports
- configuration files
- dependency manifests
"""

from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger

log = get_logger("audit.asset_inventory")


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------
_SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php",
    ".html", ".css", ".sql", ".sh", ".yml", ".yaml", ".json",
    ".toml", ".cfg", ".ini", ".env", ".xml",
}

_CONFIG_NAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env", ".env.example", "nginx.conf", "gunicorn.conf.py",
    "uwsgi.ini", "supervisord.conf", "settings.py", "config.py",
    "config.yaml", "config.json", "alembic.ini",
}

_DEPENDENCY_NAMES = {
    "requirements.txt", "Pipfile", "Pipfile.lock",
    "pyproject.toml", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock",
    "go.mod", "Gemfile", "Gemfile.lock", "pom.xml",
    "build.gradle", "composer.json",
}


def discover_source_files(root: Path) -> List[Dict[str, Any]]:
    """Return a list of source-code files with size information."""
    results: List[Dict[str, Any]] = []
    for p in root.rglob("*"):
        if p.is_file() and p.suffix in _SOURCE_EXTENSIONS:
            # Skip virtual envs and hidden dirs
            parts_lower = [part.lower() for part in p.parts]
            if any(
                part.startswith(".") or part in ("node_modules", "__pycache__", ".venv", "venv")
                for part in parts_lower
            ):
                continue
            results.append({
                "path": str(p.relative_to(root)),
                "extension": p.suffix,
                "size_bytes": p.stat().st_size,
            })
    log.info("source_files_discovered", count=len(results))
    return results


def discover_config_files(root: Path) -> List[Dict[str, Any]]:
    """Return configuration files found under *root*."""
    results: List[Dict[str, Any]] = []
    for p in root.rglob("*"):
        if p.is_file() and p.name in _CONFIG_NAMES:
            results.append({
                "path": str(p.relative_to(root)),
                "name": p.name,
                "size_bytes": p.stat().st_size,
            })
    log.info("config_files_discovered", count=len(results))
    return results


def discover_dependency_manifests(root: Path) -> List[Dict[str, Any]]:
    """Return dependency manifest files."""
    results: List[Dict[str, Any]] = []
    for p in root.rglob("*"):
        if p.is_file() and p.name in _DEPENDENCY_NAMES:
            results.append({
                "path": str(p.relative_to(root)),
                "name": p.name,
                "size_bytes": p.stat().st_size,
            })
    log.info("dependency_manifests_discovered", count=len(results))
    return results


# ---------------------------------------------------------------------------
# Port scanning (lightweight)
# ---------------------------------------------------------------------------
def scan_ports(
    host: str = "127.0.0.1",
    ports: Optional[List[int]] = None,
    timeout: float = 0.5,
) -> List[Dict[str, Any]]:
    """
    Attempt TCP connections to *ports* on *host*.

    Default port list covers common web-app ports.
    """
    if ports is None:
        ports = [22, 80, 443, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 9200, 27017]

    open_ports: List[Dict[str, Any]] = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append({"host": host, "port": port, "state": "open"})
        except OSError:
            pass
        finally:
            sock.close()

    log.info("port_scan_complete", host=host, open_ports=len(open_ports))
    return open_ports


# ---------------------------------------------------------------------------
# Dependency parsing
# ---------------------------------------------------------------------------
def parse_requirements_txt(path: Path) -> List[Dict[str, str]]:
    """Parse a ``requirements.txt`` into package / version-constraint pairs."""
    deps: List[Dict[str, str]] = []
    if not path.is_file():
        return deps
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle: package>=1.0,<2.0
        for sep in (">=", "<=", "==", "~=", "!=", ">", "<"):
            if sep in line:
                name, version = line.split(sep, 1)
                deps.append({"name": name.strip(), "version_spec": f"{sep}{version.strip()}"})
                break
        else:
            deps.append({"name": line, "version_spec": ""})
    return deps


def parse_package_json(path: Path) -> List[Dict[str, str]]:
    """Parse a ``package.json`` into combined dependency entries."""
    deps: List[Dict[str, str]] = []
    if not path.is_file():
        return deps
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return deps

    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            deps.append({"name": name, "version_spec": version})
    return deps


def collect_dependencies(root: Path) -> List[Dict[str, str]]:
    """Aggregate dependencies from all known manifest formats."""
    all_deps: List[Dict[str, str]] = []
    for p in root.rglob("requirements*.txt"):
        all_deps.extend(parse_requirements_txt(p))
    for p in root.rglob("package.json"):
        all_deps.extend(parse_package_json(p))
    log.info("dependencies_collected", count=len(all_deps))
    return all_deps


# ---------------------------------------------------------------------------
# Full inventory
# ---------------------------------------------------------------------------
def collect_inventory(
    target_path: Optional[str] = None,
    scan_host: str = "127.0.0.1",
) -> Dict[str, Any]:
    """
    Run a full asset inventory on the target application.

    Returns a dict suitable for inclusion in ``AuditReport.assets``.
    """
    root = Path(target_path or settings.audit.target_app_path)
    if not root.exists():
        log.warning("target_path_missing", path=str(root))
        return {"error": f"Target path {root} does not exist"}

    inventory: Dict[str, Any] = {
        "target_path": str(root),
        "source_files": discover_source_files(root),
        "config_files": discover_config_files(root),
        "dependency_manifests": discover_dependency_manifests(root),
        "dependencies": collect_dependencies(root),
        "open_ports": scan_ports(host=scan_host),
    }

    log.info(
        "asset_inventory_complete",
        source_files=len(inventory["source_files"]),
        config_files=len(inventory["config_files"]),
        dependencies=len(inventory["dependencies"]),
        open_ports=len(inventory["open_ports"]),
    )
    return inventory
