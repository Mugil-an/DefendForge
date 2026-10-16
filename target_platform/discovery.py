"""
Target Surface Discovery Engine.

Discovers the real attack and defense surface of any target application through:
1. Static source code AST analysis (FastAPI, Flask, Django, Starlette, Express, etc.)
2. Live network OpenAPI / Swagger schema discovery
3. Live HTTP endpoint probing and technology fingerprinting

Provides unified endpoint inventories and classifies attack suitability for Red Agent
and benign traffic profiles for Green Agent.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

import httpx

from blue_agent.logging_cfg import get_logger

log = get_logger("target.discovery")


@dataclass
class DiscoveredEndpoint:
    """A discovered endpoint in the target application."""
    path: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    source_file: str = ""
    line_number: int = 0
    source_type: str = "probe"  # static_ast | openapi | probe
    attack_suitability: List[str] = field(default_factory=list)
    is_benign_safe: bool = True
    content_type: str = ""
    status_code: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "parameters": self.parameters,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "source_type": self.source_type,
            "attack_suitability": self.attack_suitability,
            "is_benign_safe": self.is_benign_safe,
            "content_type": self.content_type,
            "status_code": self.status_code,
        }


@dataclass
class TargetSurface:
    """The synthesized attack and defense surface of the target application."""
    target_url: str
    target_path: str = ""
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    server_info: str = ""
    has_openapi: bool = False

    @property
    def total_routes(self) -> int:
        return len(self.endpoints)

    def get_endpoints_for_attack(self, attack_type: str) -> List[DiscoveredEndpoint]:
        """Return endpoints suited for a specific attack category."""
        matched = [ep for ep in self.endpoints if attack_type in ep.attack_suitability]
        if matched:
            return matched
        # Fallback to any endpoint if specific match isn't tagged
        if attack_type == "reconnaissance":
            return [ep for ep in self.endpoints if ep.method == "GET"] or self.endpoints
        # For data-carrying attacks, prefer endpoints with params or POST/PUT
        param_eps = [ep for ep in self.endpoints if ep.parameters or ep.method in ("POST", "PUT")]
        return param_eps or self.endpoints

    def get_benign_endpoints(self) -> List[DiscoveredEndpoint]:
        """Return endpoints safe for legitimate Green Agent traffic."""
        safe = [ep for ep in self.endpoints if ep.is_benign_safe and ep.method in ("GET", "HEAD")]
        if safe:
            return safe
        return [ep for ep in self.endpoints if ep.method == "GET"] or self.endpoints

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "target_path": self.target_path,
            "total_routes": self.total_routes,
            "technologies": self.technologies,
            "server_info": self.server_info,
            "has_openapi": self.has_openapi,
            "endpoints": [ep.to_dict() for ep in self.endpoints],
        }


class TargetSurfaceDiscovery:
    """
    Analyzes target application source code and live network endpoints to construct
    an accurate TargetSurface.
    """

    def __init__(self, target_url: str, target_path: Optional[str] = None):
        self.target_url = target_url.rstrip("/")
        resolved_path = ""
        if target_path and os.path.exists(target_path):
            resolved_path = str(Path(target_path).resolve())
        elif os.path.exists("/target") and os.path.isdir("/target"):
            resolved_path = "/target"
        elif os.path.exists("/app/target_app") and os.path.isdir("/app/target_app"):
            resolved_path = "/app/target_app"
        elif os.path.exists("./target_app") and os.path.isdir("./target_app"):
            resolved_path = str(Path("./target_app").resolve())
        self.target_path = resolved_path

    def discover(self) -> TargetSurface:
        """Run full static and dynamic discovery."""
        log.info("starting_surface_discovery", target_url=self.target_url, target_path=self.target_path)
        surface = TargetSurface(target_url=self.target_url, target_path=self.target_path)

        # 1. Static AST analysis if source code path exists
        static_endpoints: List[DiscoveredEndpoint] = []
        if self.target_path and os.path.isdir(self.target_path):
            static_endpoints = self._analyze_source_ast(self.target_path)
            if static_endpoints:
                surface.technologies.append("Python Web Framework")
                log.info("ast_routes_discovered", count=len(static_endpoints))

        # 2. Dynamic live OpenAPI discovery
        openapi_endpoints, openapi_found = self._probe_openapi()
        if openapi_found:
            surface.has_openapi = True
            surface.technologies.append("OpenAPI / Swagger REST API")
            log.info("openapi_routes_discovered", count=len(openapi_endpoints))

        # 3. Dynamic live endpoint probing
        probed_endpoints, server_techs = self._probe_common_routes()
        surface.technologies.extend([t for t in server_techs if t not in surface.technologies])

        # 4. Synthesize and unify all endpoints
        merged_map: Dict[str, DiscoveredEndpoint] = {}

        # Prioritize static AST (rich param info and source file locations)
        for ep in static_endpoints:
            key = f"{ep.method}:{ep.path}"
            merged_map[key] = ep

        # Merge OpenAPI
        for ep in openapi_endpoints:
            key = f"{ep.method}:{ep.path}"
            if key in merged_map:
                existing = merged_map[key]
                # Merge params
                combined_params = list(dict.fromkeys(existing.parameters + ep.parameters))
                existing.parameters = combined_params
                existing.attack_suitability = list(dict.fromkeys(existing.attack_suitability + ep.attack_suitability))
            else:
                merged_map[key] = ep

        # Merge live probed
        for ep in probed_endpoints:
            key = f"{ep.method}:{ep.path}"
            if key in merged_map:
                merged_map[key].status_code = ep.status_code
                merged_map[key].content_type = ep.content_type
            else:
                merged_map[key] = ep

        # Fallback if nothing could be discovered
        if not merged_map:
            merged_map["GET:/"] = DiscoveredEndpoint(
                path="/",
                method="GET",
                source_type="fallback",
                attack_suitability=["reconnaissance"],
                is_benign_safe=True,
            )

        surface.endpoints = list(merged_map.values())
        log.info("surface_discovery_complete", total_routes=surface.total_routes, technologies=surface.technologies)
        return surface

    def _analyze_source_ast(self, root_dir: str) -> List[DiscoveredEndpoint]:
        """Perform recursive Python AST static analysis to find all routes and parameters."""
        endpoints: List[DiscoveredEndpoint] = []
        skip_dirs = {".venv", "venv", "__pycache__", ".git", ".idea", ".vscode", "node_modules", "dist", "build"}

        for dirpath, dirnames, filenames in os.walk(root_dir):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for f in filenames:
                if not f.endswith(".py"):
                    continue
                fpath = os.path.join(dirpath, f)
                rel_file = os.path.relpath(fpath, root_dir).replace("\\", "/")

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as src:
                        tree = ast.parse(src.read(), filename=fpath)
                except Exception:
                    continue

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        for dec in node.decorator_list:
                            ep = self._extract_route_from_decorator(dec, node, rel_file)
                            if ep:
                                endpoints.append(ep)

        return endpoints

    def _extract_route_from_decorator(
        self,
        dec: ast.expr,
        fn_node: ast.FunctionDef,
        rel_file: str,
    ) -> Optional[DiscoveredEndpoint]:
        """Extract endpoint details from FastAPI/Flask route decorators."""
        if not isinstance(dec, ast.Call):
            return None

        method = "GET"
        path = ""
        is_route = False

        if isinstance(dec.func, ast.Attribute):
            attr_name = dec.func.attr.lower()
            if attr_name in ("get", "post", "put", "delete", "patch", "options", "head"):
                method = attr_name.upper()
                is_route = True
            elif attr_name == "route":
                is_route = True
                # Check methods keyword arg in Flask
                for kw in dec.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        methods = [elt.value for elt in kw.value.elts if isinstance(elt, ast.Constant)]
                        if methods:
                            method = str(methods[0]).upper()
        elif isinstance(dec.func, ast.Name):
            name = dec.func.id.lower()
            if name in ("get", "post", "put", "delete", "patch"):
                method = name.upper()
                is_route = True

        if not is_route:
            return None

        # Extract path argument
        if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
            path = dec.args[0].value
        elif dec.keywords:
            for kw in dec.keywords:
                if kw.arg in ("rule", "path") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    path = kw.value.value
                    break

        if not path:
            path = "/"
        if not path.startswith("/"):
            path = "/" + path

        # Extract parameter names from function definition
        params: List[str] = []
        ignored_args = {"self", "cls", "request", "db", "session", "background_tasks", "response"}
        for arg in fn_node.args.args:
            if arg.arg.lower() not in ignored_args:
                params.append(arg.arg)

        # Also extract parameters from path template (e.g. /{user_id} or /<account_id>)
        path_params = re.findall(r"[{<]([a-zA-Z0-9_]+)[}>]", path)
        for pp in path_params:
            if pp not in params:
                params.append(pp)

        # Classify attack suitabilities
        suitabilities = self._classify_suitabilities(path, method, params, fn_node.name)
        is_benign_safe = method in ("GET", "HEAD") and not any(p in path.lower() for p in ("delete", "admin", "drop"))

        return DiscoveredEndpoint(
            path=path,
            method=method,
            parameters=params,
            source_file=rel_file,
            line_number=fn_node.lineno,
            source_type="static_ast",
            attack_suitability=suitabilities,
            is_benign_safe=is_benign_safe,
        )

    def _classify_suitabilities(
        self,
        path: str,
        method: str,
        params: List[str],
        fn_name: str,
    ) -> List[str]:
        """Classify which attacks are best suited for an endpoint based on path and params."""
        suits: List[str] = []
        combined_text = f"{path} {' '.join(params)} {fn_name}".lower()

        # SQL Injection
        if any(term in combined_text for term in ("id", "user", "name", "search", "query", "q", "filter", "login", "account", "status", "priority")):
            suits.append("sql_injection")

        # Command Injection
        if any(term in combined_text for term in ("ping", "exec", "run", "cmd", "system", "sync", "host", "job", "scheduler")):
            suits.append("command_injection")

        # Cross-Site Scripting (XSS)
        if any(term in combined_text for term in ("greet", "comment", "message", "query", "search", "title", "text", "body", "email", "preferences", "notes")):
            suits.append("xss")

        # Path Traversal
        if any(term in combined_text for term in ("file", "download", "upload", "path", "doc", "read", "account_id", "dir", "export")):
            suits.append("path_traversal")

        # SSRF
        if any(term in combined_text for term in ("url", "fetch", "link", "webhook", "proxy", "oauth", "callback", "redirect", "connect")):
            suits.append("ssrf")

        # Brute Force / Auth Bypass
        if any(term in combined_text for term in ("login", "auth", "token", "key", "secret", "admin", "oauth", "signup", "credential", "session")):
            suits.append("brute_force")

        # Reconnaissance
        suits.append("reconnaissance")
        return suits

    def _is_target_online(self) -> bool:
        """Quick 0.5s check to see if target host and port are listening."""
        try:
            with httpx.Client(timeout=0.5, verify=False) as client:
                client.get(self.target_url)
                return True
        except (httpx.ConnectError, httpx.TimeoutException):
            return False
        except Exception:
            # If server returned HTTP error or redirect, it's alive!
            return True

    def _probe_openapi(self) -> tuple[List[DiscoveredEndpoint], bool]:
        """Probe the target URL for OpenAPI / Swagger specifications."""
        endpoints: List[DiscoveredEndpoint] = []
        if not self._is_target_online():
            return endpoints, False

        openapi_paths = ["/openapi.json", "/api/openapi.json", "/swagger.json", "/api/swagger.json"]

        try:
            with httpx.Client(timeout=3.0, verify=False) as client:
                for o_path in openapi_paths:
                    url = urljoin(self.target_url + "/", o_path.lstrip("/"))
                    try:
                        resp = client.get(url)
                        if resp.status_code == 200 and "application/json" in resp.headers.get("content-type", ""):
                            doc = resp.json()
                            paths = doc.get("paths", {})
                            for route_path, operations in paths.items():
                                for method_name, op in operations.items():
                                    method = method_name.upper()
                                    if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                                        continue
                                    params: List[str] = []
                                    for p in op.get("parameters", []):
                                        if isinstance(p, dict) and p.get("name"):
                                            params.append(p["name"])

                                    # Extract body schema properties if present
                                    req_body = op.get("requestBody", {}).get("content", {}).get("application/json", {})
                                    body_schema = req_body.get("schema", {})
                                    if "$ref" in body_schema:
                                        ref_name = body_schema["$ref"].split("/")[-1]
                                        components = doc.get("components", {}).get("schemas", {})
                                        schema_obj = components.get(ref_name, {})
                                        params.extend(list(schema_obj.get("properties", {}).keys()))

                                    suits = self._classify_suitabilities(route_path, method, params, op.get("operationId", ""))
                                    endpoints.append(DiscoveredEndpoint(
                                        path=route_path,
                                        method=method,
                                        parameters=params,
                                        source_type="openapi",
                                        attack_suitability=suits,
                                        is_benign_safe=method in ("GET", "HEAD"),
                                    ))
                            return endpoints, True
                    except Exception:
                        continue
        except Exception:
            pass

        return endpoints, False

    def _probe_common_routes(self) -> tuple[List[DiscoveredEndpoint], List[str]]:
        """Live HTTP probe of common routes to check status codes and identify server."""
        endpoints: List[DiscoveredEndpoint] = []
        techs: List[str] = []
        if not self._is_target_online():
            return endpoints, techs

        common_probes = ["/", "/health", "/api/config", "/api/health", "/status", "/robots.txt"]

        try:
            with httpx.Client(timeout=2.0, verify=False) as client:
                for probe in common_probes:
                    url = urljoin(self.target_url + "/", probe.lstrip("/"))
                    try:
                        resp = client.get(url)
                        if resp.status_code != 404:
                            server = resp.headers.get("server")
                            if server and server not in techs:
                                techs.append(server)
                            ct = resp.headers.get("content-type", "")
                            if "json" in ct and "REST / JSON API" not in techs:
                                techs.append("REST / JSON API")

                            endpoints.append(DiscoveredEndpoint(
                                path=probe,
                                method="GET",
                                status_code=resp.status_code,
                                content_type=ct,
                                source_type="probe",
                                attack_suitability=["reconnaissance"],
                                is_benign_safe=True,
                            ))
                    except Exception:
                        continue
        except Exception:
            pass

        return endpoints, techs
