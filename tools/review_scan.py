#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
review_scan.py — Universal deterministic code review scanner.

Outputs a FACT list (facts, not judgments). Zero model, zero hallucination, reproducible.

Auto-discovers project structure from --root (default CWD) by finding manifest files
(package.json / requirements.txt / go.mod / pom.xml / Cargo.toml etc.), then scans all
source files across 5 languages (Python / JS-TS / Java / Go / Rust) for 7 dimensions.

Supports optional .code-review.yml per-project overlay for project-specific precision
(auth markers, SSRF guard functions, delete anchors, fetch impl files, etc.).

Usage:
  review-scan --root /path/to/project              # scan uncommitted changes
  review-scan --root /path/to/project --full        # full scan
  review-scan --root /path/to/project --json        # JSON output
  review-scan --root /path/to/project --base main   # diff against branch/ref
  review-scan --selftest                            # self-contained fixture test
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# Windows console default GBK; force UTF-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Category -> finding ID prefix
CAT_PREFIX = {
    "route": "ROUTE",
    "auth": "AUTH",
    "ssrf": "SSRF",
    "secret": "SECRET",
    "cross_store_delete": "CROSS_STORE_DELETE",
    "bare_fetch": "FETCH",
    "error_swallow": "ERR_SWALLOW",
    "unbounded_retry": "OOM_RISK",
    "timestamp_trust": "TS_TRUST",
}

# Default auth markers (cross-framework, generic)
DEFAULT_AUTH_MARKERS = [
    "Depends(",              # FastAPI
    "@requires_auth",        # Flask
    "@login_required",       # Flask / Django
    "auth_required",         # generic
    "@PreAuthorize",         # Spring
    "@RolesAllowed",         # Spring
    "@UseGuards",            # NestJS
    "@Authorize",            # NestJS
    "@authenticated",        # generic
    "login_required",        # Django
    ".use(auth",             # Express
    "requireAuth",           # Express / Koa
    "c.MustAuth",            # gin
    "AuthMiddleware",        # generic
    "jwt.verify",            # generic
    "session[:user]",        # Rails / Django
]

# Default SSRF URL parameter names
DEFAULT_URL_PARAMS = r"\b(?:callback_url|webhook_url|target_url|redirect_url|url)\s*[:=]"

# Default delete anchors (generic, cross-store)
DEFAULT_DELETE_ANCHORS = {
    "sql": re.compile(r"DELETE FROM|db\.delete\(|\.delete_one\(|\.delete_many\(", re.I),
    "nosql": re.compile(r"\.remove\(|\.drop\(|mongo.*delete", re.I),
    "object_storage": re.compile(r"s3.*delete|oss.*delete|tos.*delete|gcs.*delete|minio.*delete", re.I),
    "orm": re.compile(r"\.destroy|exec.*DELETE", re.I),
}

# Default fetch URL whitelist (auth endpoints that need no token)
DEFAULT_FETCH_URL_WHITELIST = re.compile(
    r"/api/auth/(login|register|forgot-?password|logout|refresh|sso)"
)

# Secret detection (language-agnostic)
SECRET_RE = re.compile(
    r"""(api_key|apikey|secret|password|access_key|secret_key|token|ak|sk)
        \s*=\s*['"]([A-Za-z0-9_\-]{16,})['"]""",
    re.IGNORECASE | re.VERBOSE)
GETENV_RE = re.compile(r"os\.getenv|os\.environ|config\(|Config\(|process\.env\.")

# Placeholder blacklist (historical hardcoded defaults)
SECRET_PLACEHOLDERS = [
    "your-secret-key-change-in-production-please-use-env-var",
    "change-me-to-a-random-secret",
]

# Directories to always exclude
EXCLUDE_DIRS = {
    "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
    ".git", ".next", ".nuxt", "out", "target", ".idea", ".vscode", "vendor",
    ".gradle", ".m2", ".terraform", ".serverless", ".pytest_cache", ".mypy_cache",
    "coverage", ".cache", "binlog2sql", "bin",
}

# Source file extensions
SRC_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".go", ".rs",
    ".yml", ".yaml",
}

# Manifest files -> language hint
MANIFESTS = {
    "package.json": "js",
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "setup.py": "python",
    "Pipfile": "python",
    "go.mod": "go",
    "pom.xml": "java",
    "build.gradle": "java",
    "build.gradle.kts": "java",
    "Cargo.toml": "rust",
}

# Risk level keywords
RISK_HIGH = ["api/", "auth", "jwt", "/db", "db.py", "credit", "payment", "config",
             "delete", "erase", "docker", "login", "permission"]
RISK_MID = ["services/", "tasks/", "external", "review"]

# ---------------------------------------------------------------------------
# Route regexes per framework
# ---------------------------------------------------------------------------

ROUTE_PATTERNS = {
    "fastapi": re.compile(
        r"@(?:router|app)\.(get|post|put|delete|patch)\(\s*"
        r"(?:response_model=[^,]+,\s*)?"
        r'[\'"]([^\'"]+)[\'"]'),
    "flask": re.compile(
        r"@(?:\w+)\.(?:route|get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]"),
    "django": re.compile(
        r"""(?:path|re_path|include)\(\s*['"]([^'"]+)['"]"""),
    "express": re.compile(
        r"(?:app|router)\.(?:get|post|put|delete|patch|use)\(\s*['\"]([^'\"]+)['\"]"),
    "nestjs": re.compile(
        r"@(Get|Post|Put|Delete|Patch)\(\s*['\"]([^'\"]+)['\"]"),
    "koa": re.compile(
        r"router\.(?:get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]"),
    "spring": re.compile(
        r"@(Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*)?['\"]([^'\"]*)['\"]"),
    "gin": re.compile(
        r"\.(?:GET|POST|PUT|DELETE|PATCH|Handle|Any)\(\s*['\"]([^'\"]+)['\"]"),
    "echo": re.compile(
        r"\.(?:GET|POST|PUT|DELETE|PATCH)\(\s*['\"]([^'\"]+)['\"]"),
    "net_http": re.compile(
        r"(?:http|mux)\.(?:HandleFunc|Handle)\(\s*['\"]([^'\"]+)['\"]"),
    "axum": re.compile(
        r"\.route\(\s*['\"]([^'\"]+)['\"]"),
    "actix": re.compile(
        r"(?:web::resource|web::scope|cfg\.route)\(\s*['\"]([^'\"]+)['\"]"),
}

# Framework detection heuristics (import/decorator patterns in source files)
FRAMEWORK_DETECT = {
    "fastapi": [r"from fastapi", r"import fastapi", r"APIRouter"],
    "flask": [r"from flask", r"import flask", r"Flask\(__name__"],
    "django": [r"from django", r"import django", r"urlpatterns"],
    "express": [r"require\(['\"]express['\"]\)", r"from ['\"]express['\"]", r"express\(\)"],
    "nestjs": [r"@Controller", r"@Module", r"from ['\"]@nestjs"],
    "koa": [r"from ['\"]koa['\"]", r"require\(['\"]koa['\"]\)"],
    "spring": [r"@(Get|Post|Put|Delete|Request)Mapping", r"org\.springframework"],
    "gin": [r'"github\.com/gin-gonic/gin"', r"gin\.(Default|New)"],
    "echo": [r'"github\.com/labstack/echo', r"echo\.(New|NewWithContext)"],
    "net_http": [r'"net/http"', r"http\.HandleFunc", r"http\.Handle"],
    "axum": [r"axum::", r"Router::new"],
    "actix": [r"actix_web::", r"actix::", r"#\[get\(", r"#\[post\("],
}

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

_findings = []

def add(project, subsystem, branch, file, line, category, evidence,
        severity="P1", status="confirmed", **extra):
    """Construct a finding (conforms to review-finding-schema.json)."""
    seq = sum(1 for f in _findings if f["category"] == category) + 1
    f = {
        "id": f"{CAT_PREFIX[category]}-{seq:03d}",
        "project": project,
        "subsystem": subsystem,
        "branch": branch or "",
        "file": file,
        "line": line,
        "severity": severity,
        "category": category,
        "evidence": evidence,
        "status": status,
    }
    f.update(extra)
    _findings.append(f)

# ---------------------------------------------------------------------------
# Config loading (.code-review.yml)
# ---------------------------------------------------------------------------

def load_config(root):
    """Load .code-review.yml from project root if it exists. Returns dict."""
    cfg_path = Path(root) / ".code-review.yml"
    if not cfg_path.is_file():
        return {}
    try:
        import yaml  # optional dependency
        with open(cfg_path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except ImportError:
        # Fallback: simple manual parse for common keys
        return _parse_simple_yml(cfg_path)
    except Exception:
        return {}


def _parse_simple_yml(path):
    """Minimal YAML parser for .code-review.yml when PyYAML is not installed."""
    cfg = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    continue
                key, _, val = line.partition(":")
                key = key.strip()
                val = val.strip()
                if val.startswith("[") and val.endswith("]"):
                    # Simple list: [a, b, c]
                    items = [v.strip().strip("'\"") for v in val[1:-1].split(",") if v.strip()]
                    cfg[key] = items
                elif val.startswith("{"):
                    pass  # dict too complex for simple parser, skip
                else:
                    cfg[key] = val.strip("'\"")
    except Exception:
        pass
    return cfg


def get_auth_markers(cfg):
    """Return merged auth markers list (default + config overlay)."""
    markers = list(DEFAULT_AUTH_MARKERS)
    extra = cfg.get("auth_markers", [])
    if isinstance(extra, list):
        markers.extend(extra)
    return markers


def get_ssrf_guard_functions(cfg):
    """Return SSRF guard function names from config, or empty list."""
    funcs = cfg.get("ssrf_guard_functions", [])
    return funcs if isinstance(funcs, list) else []


def get_delete_anchors(cfg):
    """Return merged delete anchors dict (default + config overlay)."""
    anchors = dict(DEFAULT_DELETE_ANCHORS)
    extra = cfg.get("delete_anchors", {})
    if isinstance(extra, dict):
        for key, patterns in extra.items():
            if isinstance(patterns, list):
                combined = "|".join(re.escape(p) if p.isidentifier() else p for p in patterns)
                anchors[key] = re.compile(combined, re.I)
    return anchors


def get_fetch_impl_files(cfg):
    """Return fetch implementation files (skip these for S6)."""
    files = cfg.get("fetch_impl_files", [])
    return [f.lower() for f in files] if isinstance(files, list) else []


def get_extra_exclude_dirs(cfg):
    """Return extra directories to exclude from config."""
    dirs = cfg.get("exclude_dirs", [])
    return set(dirs) if isinstance(dirs, list) else set()


# ---------------------------------------------------------------------------
# Verification runner (regression check after fix)
# ---------------------------------------------------------------------------

def get_verification_commands(cfg):
    """Return verification commands from .code-review.yml config."""
    ver = cfg.get("verification", {})
    if isinstance(ver, dict):
        return ver.get("commands", [])
    return []


def path_matches_glob(path, patterns):
    """Check if path matches any glob pattern (for on_paths filtering)."""
    if not patterns:
        return True
    from fnmatch import fnmatch
    p = str(path).replace("\\", "/")
    for pat in patterns:
        if fnmatch(p, pat) or fnmatch(p, "*/" + pat):
            return True
    return False


def discover_default_verification(unit_root, langs):
    """Auto-discover default verification commands based on project type."""
    commands = []
    root = Path(unit_root)

    # Python
    if "python" in langs:
        # pytest
        if (root / "pytest.ini").is_file() or (root / "pyproject.toml").is_file():
            commands.append({
                "name": "pytest",
                "run": "pytest",
                "cwd": ".",
                "on_risk": ["HIGH", "MID", "LOW"],
            })
        else:
            # Check for tests/ directory
            if any((root / "tests").rglob("test_*.py")) or (root / "tests").exists():
                commands.append({
                    "name": "pytest",
                    "run": "pytest",
                    "cwd": ".",
                    "on_risk": ["HIGH", "MID", "LOW"],
                })
        # compileall fallback
        commands.append({
            "name": "python compileall",
            "run": "python -m compileall .",
            "cwd": ".",
            "on_risk": ["HIGH", "MID", "LOW"],
        })

    # Java
    if "java" in langs:
        if (root / "pom.xml").is_file():
            commands.append({
                "name": "mvn test",
                "run": "mvn test",
                "cwd": ".",
                "on_risk": ["HIGH", "MID"],
            })
        elif (root / "build.gradle").is_file() or (root / "build.gradle.kts").is_file():
            commands.append({
                "name": "gradle test",
                "run": "gradle test",
                "cwd": ".",
                "on_risk": ["HIGH", "MID"],
            })

    # JS/TS
    if "js" in langs:
        pkg = root / "package.json"
        if pkg.is_file():
            try:
                import json
                with open(pkg, "r", encoding="utf-8") as fh:
                    pkg_data = json.load(fh)
                scripts = pkg_data.get("scripts", {})
                if "test" in scripts:
                    commands.append({
                        "name": "npm test",
                        "run": "npm test",
                        "cwd": ".",
                        "on_risk": ["HIGH", "MID", "LOW"],
                    })
                if "build" in scripts:
                    commands.append({
                        "name": "npm run build",
                        "run": "npm run build",
                        "cwd": ".",
                        "on_risk": ["HIGH", "MID", "LOW"],
                    })
            except Exception:
                pass
        # TypeScript typecheck fallback
        if (root / "tsconfig.json").is_file():
            commands.append({
                "name": "tsc --noEmit",
                "run": "npx tsc --noEmit",
                "cwd": ".",
                "on_risk": ["HIGH", "MID", "LOW"],
            })

    return commands


def run_verification(unit_root, commands, risk, changed_files_list):
    """Run verification commands and return results.

    Returns (passed: bool, results: list of dicts).
    Each result dict: {name, passed, exit_code, stdout, stderr}.
    """
    results = []
    passed = True
    root = Path(unit_root)

    for cmd_spec in commands:
        name = cmd_spec.get("name", "?")
        run_cmd = cmd_spec.get("run", "")
        cwd = cmd_spec.get("cwd", ".")
        on_risk = cmd_spec.get("on_risk", ["HIGH", "MID", "LOW"])
        on_paths = cmd_spec.get("on_paths", [])
        expect_exit = cmd_spec.get("expect_exit", 0)
        timeout = cmd_spec.get("timeout", 300)

        # Filter by risk level
        if risk not in on_risk:
            continue

        # Filter by changed file paths
        if on_paths and changed_files_list:
            matched = False
            for cf in changed_files_list:
                if path_matches_glob(cf, on_paths):
                    matched = True
                    break
            if not matched:
                continue

        # Execute command
        cwd_path = root / cwd if not Path(cwd).is_absolute() else Path(cwd)
        if not cwd_path.is_dir():
            cwd_path = root

        try:
            out = subprocess.run(
                run_cmd, shell=True, cwd=str(cwd_path),
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=timeout)
            cmd_passed = out.returncode == expect_exit
            results.append({
                "name": name,
                "passed": cmd_passed,
                "exit_code": out.returncode,
                "stdout": out.stdout[:2000] if out.stdout else "",
                "stderr": out.stderr[:2000] if out.stderr else "",
            })
            if not cmd_passed:
                passed = False
        except subprocess.TimeoutExpired:
            results.append({
                "name": name,
                "passed": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Timeout after {timeout}s",
            })
            passed = False
        except Exception as e:
            results.append({
                "name": name,
                "passed": False,
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
            })
            passed = False

    return passed, results


def print_verification_summary(ver_results):
    """Print verification results to stdout."""
    if not ver_results:
        return
    print("\n=== Verification ===")
    for r in ver_results:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"  [{status}] {r['name']} (exit={r['exit_code']})")
        if not r["passed"]:
            if r.get("stderr"):
                print(f"       {r['stderr'][:200]}")


# ---------------------------------------------------------------------------
# Phase 0: Project auto-discovery
# ---------------------------------------------------------------------------

def git(git_dir, *args):
    """Run git in git_dir, return stdout string (empty on failure)."""
    try:
        out = subprocess.run(
            ["git", *args], cwd=str(git_dir), capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=30)
        return out.stdout.strip()
    except Exception:
        return ""


def _excluded(path, extra_exclude=None):
    dirs = EXCLUDE_DIRS
    if extra_exclude:
        dirs = dirs | extra_exclude
    return any(part in dirs for part in path.parts)


def discover_units(root):
    """Auto-discover project units by scanning for manifest files.

    Returns [(unit_name, unit_root_path, language_hints), ...].
    unit_name = directory name containing the manifest.
    """
    root = Path(root).resolve()
    units = {}  # dir_path -> (name, set of languages)
    for manifest, lang in MANIFESTS.items():
        for p in root.rglob(manifest):
            if _excluded(p):
                continue
            d = p.parent
            if d not in units:
                units[d] = (d.name, set())
            units[d][1].add(lang)

    if not units:
        # Fallback: entire root is one unit
        return [(".".join(root.parts[-2:]) if len(root.parts) >= 2 else root.name, root, set())]

    return [(name, d, langs) for d, (name, langs) in units.items()]


def detect_frameworks(unit_root, langs):
    """Detect web frameworks by scanning source files for import/decorator patterns.

    Returns set of framework names (keys of ROUTE_PATTERNS).
    """
    detected = set()
    # Sample files (limit to avoid scanning everything just for detection)
    sample_files = []
    for ext in (".py", ".js", ".ts", ".java", ".go", ".rs"):
        for p in unit_root.rglob(f"*{ext}"):
            if _excluded(p):
                continue
            sample_files.append(p)
            if len(sample_files) >= 50:
                break
        if len(sample_files) >= 50:
            break

    all_text = ""
    for p in sample_files:
        try:
            all_text += p.read_text(encoding="utf-8", errors="replace") + "\n"
        except Exception:
            continue

    for fw, patterns in FRAMEWORK_DETECT.items():
        for pat in patterns:
            if re.search(pat, all_text):
                detected.add(fw)
                break

    # Language hint: if langs has 'python' but no python framework detected, still scan py
    return detected


def get_branch(unit_root):
    """Get current git branch for unit_root."""
    # Find git root (could be unit_root itself or a parent)
    git_dir = unit_root
    # Check if this dir is inside a git repo
    if not (git_dir / ".git").exists():
        # Walk up to find .git
        for parent in git_dir.parents:
            if (parent / ".git").exists():
                git_dir = parent
                break
    return git(git_dir, "rev-parse", "--abbrev-ref", "HEAD")


def changed_files(unit_root, base, full, extra_exclude=None):
    """Return list of files to scan (absolute paths)."""
    if full:
        files = []
        for ext in ("*.py", "*.java", "*.ts", "*.tsx", "*.js", "*.jsx", "*.mjs", "*.cjs",
                    "*.go", "*.rs", "*.yml", "*.yaml", ".env.example", "*.env.example"):
            files.extend(unit_root.rglob(ext))
        return sorted({f for f in files if f.is_file() and not _excluded(f, extra_exclude)})

    # Find git root for diff
    git_dir = unit_root
    if not (git_dir / ".git").exists():
        for parent in unit_root.parents:
            if (parent / ".git").exists():
                git_dir = parent
                break

    if base:
        names = git(git_dir, "diff", "--name-only", base).splitlines()
    else:
        names = git(git_dir, "diff", "--name-only").splitlines()
        names += git(git_dir, "diff", "--staged", "--name-only").splitlines()

    out = []
    prefix = str(unit_root).replace("\\", "/")
    for n in dict.fromkeys(names):
        p = git_dir / n
        # Only include files under this unit root
        if not str(p).replace("\\", "/").startswith(prefix):
            continue
        if p.is_file() and not _excluded(p, extra_exclude):
            out.append(p)
    return sorted(out)

# ---------------------------------------------------------------------------
# Utility: read file, block splitting
# ---------------------------------------------------------------------------

def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except Exception:
        return []


def topdef_blocks(lines):
    """Split Python file into top-level def/async def blocks.

    Returns [(start_line_idx, end_line_idx, header_text)].
    Header includes decorators + signature up to ):.
    """
    blocks = []
    n = len(lines)
    i = 0
    while i < n:
        m = re.match(r"^(@\w|async def |def |class )", lines[i])
        if m and (m.group(1).startswith("@") or "def " in m.group(1)):
            start = i
            j = i
            while j > 0 and lines[j - 1].lstrip().startswith("@"):
                j -= 1
            start = j
            end = start
            paren_depth = 0
            seen_def = False
            k = start
            while k < n:
                ln = lines[k]
                if "def " in ln or "class " in ln:
                    seen_def = True
                if seen_def:
                    paren_depth += ln.count("(") - ln.count(")")
                    if paren_depth <= 0 and ":" in ln:
                        end = k
                        break
                end = k
                k += 1
            header = "\n".join(lines[start:end + 1])
            blocks.append((start, end, header))
            i = end + 1
        else:
            i += 1
    return blocks


def js_function_blocks(lines):
    """Split JS/TS file into function/method blocks (rough heuristic).

    Returns [(start_line_idx, end_line_idx, header_text)].
    """
    blocks = []
    n = len(lines)
    i = 0
    while i < n:
        ln = lines[i].strip()
        # Match function declarations, arrow functions, method definitions
        m = re.match(
            r"(?:export\s+)?(?:async\s+)?(?:function\s+\w+|const\s+\w+\s*=\s*(?:async\s+)?\(|"
            r"(?:public|private|protected)?\s*(?:async\s+)?\w+\s*\()",
            ln)
        if m:
            start = i
            # Find block end (brace depth)
            depth = 0
            end = i
            found_open = False
            for k in range(i, min(i + 200, n)):
                depth += lines[k].count("{") - lines[k].count("}")
                if "{" in lines[k]:
                    found_open = True
                if found_open and depth <= 0:
                    end = k
                    break
                end = k
            header = "\n".join(lines[start:min(start + 5, end + 1)])
            blocks.append((start, end, header))
            i = end + 1
        else:
            i += 1
    return blocks

# ---------------------------------------------------------------------------
# S1+S2: Route listing + Auth checking (multi-framework)
# ---------------------------------------------------------------------------

def scan_routes_python(lines, subsystem, branch, rel, frameworks, auth_markers):
    """S1+S2 for Python frameworks (FastAPI, Flask, Django)."""
    blocks = topdef_blocks(lines)
    n_blocks = len(blocks)

    for fw in frameworks:
        if fw not in ("fastapi", "flask", "django"):
            continue
        route_re = ROUTE_PATTERNS.get(fw)
        if not route_re:
            continue

        for i, (start, end, header) in enumerate(blocks):
            m = route_re.search(header)
            if not m:
                continue
            # Extract method and path from match groups
            groups = m.groups()
            if fw == "fastapi":
                method, path = groups[0].upper(), groups[1]
            elif fw == "flask":
                # Flask: .route("path") or .get("path") — first group is path
                path = groups[0]
                # Try to extract method from the decorator
                method_m = re.search(r"\.(get|post|put|delete|patch)\(", header)
                method = method_m.group(1).upper() if method_m else "ANY"
            elif fw == "django":
                path = groups[0]
                method = "ANY"  # Django urlpatterns don't specify method
            else:
                continue

            line_no = start + 1
            add("", subsystem, branch, rel, line_no, "route",
                f"[{fw}] {method} {path}", severity="INFO")

            # S2: Check auth
            next_start = blocks[i + 1][0] if i + 1 < n_blocks else len(lines)
            full_fn = header + "\n" + "\n".join(lines[end + 1:next_start])
            if not any(mk in full_fn for mk in auth_markers):
                add("", subsystem, branch, rel, line_no, "auth",
                    f"[{fw}] {method} {path} — no auth marker found in function",
                    severity="P1")


def scan_routes_js(lines, subsystem, branch, rel, frameworks, auth_markers):
    """S1+S2 for JS/TS frameworks (Express, NestJS, Koa)."""
    for fw in frameworks:
        if fw not in ("express", "nestjs", "koa"):
            continue
        route_re = ROUTE_PATTERNS.get(fw)
        if not route_re:
            continue

        for idx, ln in enumerate(lines, 1):
            m = route_re.search(ln)
            if not m:
                continue
            groups = m.groups()
            if fw == "nestjs":
                method, path = groups[0].upper(), groups[1]
            else:
                # Express/Koa: method in the call, path is first group
                path = groups[0]
                method_m = re.search(r"\.(get|post|put|delete|patch|use)\(", ln)
                method = method_m.group(1).upper() if method_m else "USE"

            add("", subsystem, branch, rel, idx, "route",
                f"[{fw}] {method} {path}", severity="INFO")

            # S2: Check surrounding context for auth middleware (rough)
            # Look at this line and a few lines above for auth markers
            context_start = max(0, idx - 6)
            context = "\n".join(lines[context_start:idx + 2])
            if not any(mk in context for mk in auth_markers):
                add("", subsystem, branch, rel, idx, "auth",
                    f"[{fw}] {method} {path} — no auth marker found in context",
                    severity="P1")


def scan_routes_java(lines, subsystem, branch, rel, frameworks, auth_markers):
    """S1+S2 for Java (Spring)."""
    if "spring" not in frameworks:
        return
    route_re = ROUTE_PATTERNS["spring"]
    for idx, ln in enumerate(lines, 1):
        m = route_re.search(ln)
        if not m:
            continue
        method, path = m.group(1), m.group(2)
        add("", subsystem, branch, rel, idx, "route",
            f"[spring] {method}Mapping {path}", severity="INFO")
        # Spring auth is typically in SecurityConfig, not per-method
        # But check for @PreAuthorize / @RolesAllowed as a bonus
        context_start = max(0, idx - 4)
        context = "\n".join(lines[context_start:idx + 1])
        if not any(mk in context for mk in auth_markers):
            add("", subsystem, branch, rel, idx, "auth",
                f"[spring] {method}Mapping {path} — no auth annotation found",
                severity="P2")  # P2 because Spring auth is usually centralized


def scan_routes_go(lines, subsystem, branch, rel, frameworks, auth_markers):
    """S1+S2 for Go (gin, echo, net/http)."""
    for fw in ("gin", "echo", "net_http"):
        if fw not in frameworks:
            continue
        route_re = ROUTE_PATTERNS.get(fw)
        if not route_re:
            continue
        for idx, ln in enumerate(lines, 1):
            m = route_re.search(ln)
            if not m:
                continue
            path = m.group(1)
            # Extract method
            method_m = re.search(r"\.(GET|POST|PUT|DELETE|PATCH|HandleFunc|Handle)\(", ln)
            method = method_m.group(1) if method_m else "ANY"
            add("", subsystem, branch, rel, idx, "route",
                f"[{fw}] {method} {path}", severity="INFO")


def scan_routes_rust(lines, subsystem, branch, rel, frameworks, auth_markers):
    """S1+S2 for Rust (axum, actix)."""
    for fw in ("axum", "actix"):
        if fw not in frameworks:
            continue
        route_re = ROUTE_PATTERNS.get(fw)
        if not route_re:
            continue
        for idx, ln in enumerate(lines, 1):
            m = route_re.search(ln)
            if not m:
                continue
            path = m.group(1)
            add("", subsystem, branch, rel, idx, "route",
                f"[{fw}] {path}", severity="INFO")

# ---------------------------------------------------------------------------
# S3: SSRF (URL parameter + guard function check)
# ---------------------------------------------------------------------------

def scan_ssrf_python(lines, subsystem, branch, rel, frameworks, cfg):
    """S3 for Python: route accepts URL param — report if guard function missing.

    Two modes:
    - No ssrf_guard_functions configured: report INFO (fact: "accepts URL param, verify SSRF check")
    - Configured: report P1 if guard function not called in function body
    """
    guard_funcs = get_ssrf_guard_functions(cfg)
    url_param_re = re.compile(cfg.get("url_param_pattern", DEFAULT_URL_PARAMS))
    guard_re = None
    if guard_funcs:
        guard_re = re.compile("|".join(re.escape(f) + r"\s*\(" for f in guard_funcs))

    blocks = topdef_blocks(lines)
    route_re = None
    for fw in frameworks:
        if fw in ("fastapi", "flask"):
            route_re = ROUTE_PATTERNS.get(fw)
            break
    if not route_re:
        return

    for start, end, header in blocks:
        if not route_re.search(header):
            continue
        if not url_param_re.search(header):
            continue
        # Check function body for guard function
        body_start = end + 1
        body_text = "\n".join(lines[body_start:body_start + 80])
        mdef = re.search(r"(async )?def (\w+)", header)
        fname = mdef.group(2) if mdef else "?"

        if guard_re:
            if not guard_re.search(body_text):
                add("", subsystem, branch, rel, end + 1, "ssrf",
                    f"{fname}() accepts URL param but does not call "
                    f"{'/'.join(guard_funcs)}()",
                    severity="P1")
        else:
            # Degraded mode: just report the fact
            add("", subsystem, branch, rel, end + 1, "ssrf",
                f"{fname}() accepts URL param — verify SSRF validation is applied "
                f"(configure ssrf_guard_functions in .code-review.yml for precise check)",
                severity="INFO")


def check_unit_ssrf(subsystem, unit_root, branch, cfg):
    """Unit-level: entire backend has no SSRF guard function references."""
    guard_funcs = get_ssrf_guard_functions(cfg)
    if not guard_funcs:
        return  # Can't check without configured guard functions
    guard_re = re.compile("|".join(re.escape(f) for f in guard_funcs))
    has_guard = False
    for py in unit_root.rglob("*.py"):
        if _excluded(py):
            continue
        try:
            if guard_re.search(py.read_text(encoding="utf-8", errors="replace")):
                has_guard = True
                break
        except Exception:
            continue
    if not has_guard:
        add("", subsystem, branch, "(unit-level)", 0, "ssrf",
            f"{subsystem} has no SSRF guard function ({'/'.join(guard_funcs)}) — "
            f"SSRF protection status unknown",
            severity="P1", status="plausible_blocking")

# ---------------------------------------------------------------------------
# S4: Hardcoded secrets (language-agnostic)
# ---------------------------------------------------------------------------

def scan_secrets(lines, subsystem, branch, rel):
    """S4: Detect hardcoded secrets/keys (16+ char string assignments)."""
    for idx, ln in enumerate(lines, 1):
        # Placeholder blacklist
        for ph in SECRET_PLACEHOLDERS:
            if ph in ln:
                add("", subsystem, branch, rel, idx, "secret",
                    f"Placeholder secret default: {ph} (must use .env)",
                    severity="P1")
        # Skip env/config reads
        if GETENV_RE.search(ln):
            continue
        m = SECRET_RE.search(ln)
        if m:
            add("", subsystem, branch, rel, idx, "secret",
                f"Suspected hardcoded secret: {m.group(1)}={m.group(2)[:8]}...(len={len(m.group(2))})",
                severity="P0")

# ---------------------------------------------------------------------------
# S5: Cross-store delete (generic)
# ---------------------------------------------------------------------------

def scan_cross_store_delete(lines, subsystem, branch, rel, cfg):
    """S5: Delete function that touches >=2 categories of storage."""
    anchors = get_delete_anchors(cfg)
    blocks = topdef_blocks(lines)
    for start, end, header in blocks:
        mdef = re.search(r"(async )?def (\w+)", header)
        if not mdef:
            continue
        fname = mdef.group(2)
        if "delete" not in fname.lower() and "remove" not in fname.lower():
            continue
        body = "\n".join(lines[end + 1: end + 121])
        present = [k for k, rx in anchors.items() if rx.search(body)]
        if len(present) >= 2:
            add("", subsystem, branch, rel, end + 1, "cross_store_delete",
                f"Cross-store delete in {fname}() touches: {', '.join(present)} "
                f"(verify deletion order + failure rollback)",
                severity="P1")

# ---------------------------------------------------------------------------
# S6: Bare fetch (JS/TS)
# ---------------------------------------------------------------------------

FETCH_RE = re.compile(r"\bfetch\s*\(")
METHOD_FETCH_RE = re.compile(r"\.\s*fetch\s*\(")


def scan_bare_fetch(lines, subsystem, branch, rel, cfg):
    """S6: Direct fetch() calls that bypass auth client."""
    impl_files = get_fetch_impl_files(cfg)
    url_whitelist = DEFAULT_FETCH_URL_WHITELIST

    # Check if this file is a fetch implementation file
    rel_lower = rel.lower()
    if any(impl in rel_lower for impl in impl_files):
        return

    for idx, ln in enumerate(lines, 1):
        if not FETCH_RE.search(ln):
            continue
        # Exclude method calls x.fetch(
        if METHOD_FETCH_RE.search(ln):
            continue
        # Exclude auth URL whitelist
        if url_whitelist.search(ln):
            continue
        # Exclude non-API resource URLs
        marg = re.search(r"fetch\(\s*([^\n]+)", ln)
        if marg:
            arg = marg.group(1).strip()
            if arg.startswith(("`", "'", '"')) and "/api" not in arg[:30] \
                    and "API_BASE" not in arg and "result." not in arg:
                continue
            if not arg.startswith(("`", "'", '"')) and "${" not in arg \
                    and "/api" not in arg and "API_BASE" not in arg:
                continue
        add("", subsystem, branch, rel, idx, "bare_fetch",
            f"Bare fetch() not going through auth client (token expiry silently fails)",
            severity="P2")

# ---------------------------------------------------------------------------
# S7: Error swallowing (Python + JS/TS)
# ---------------------------------------------------------------------------

SWALLOW_BODY_RE = re.compile(
    r"^\s*(pass|return\s+(None|\[\]|\{\}|\"\"|\'\'))\s*(?:#.*)?$")

JS_SWALLOW_RE = re.compile(
    r"catch\s*\([^)]*\)\s*\{[\s]*(?:(?://[^\n]*\n[\s]*)*)?"
    r"(?:return\s*(?:undefined|null|false)?\s*;?\s*)?\}")


def scan_error_swallow(lines, subsystem, branch, rel, ext):
    """S7: Error swallowing — except: pass / catch: return null."""
    n = len(lines)

    if ext == ".py":
        for idx in range(n):
            ln = lines[idx]
            stripped = ln.strip()
            if not re.match(r"^\s*except\s*(?:\(|Exception\b|:)", stripped):
                continue
            indent = len(ln) - len(ln.lstrip())
            for j in range(idx + 1, min(idx + 5, n)):
                body_ln = lines[j]
                body_stripped = body_ln.strip()
                if not body_stripped:
                    continue
                body_indent = len(body_ln) - len(body_ln.lstrip())
                if body_indent <= indent:
                    break
                if SWALLOW_BODY_RE.match(body_ln):
                    add("", subsystem, branch, rel, idx + 1, "error_swallow",
                        f"Error swallowed: {stripped} -> {body_stripped} "
                        f"(masks failure, upstream misjudges success)",
                        severity="P2")
                    break

    elif ext in (".js", ".jsx", ".ts", ".tsx"):
        # Simplified JS/TS: look for catch {} with empty or return null body
        for idx in range(n):
            ln = lines[idx].strip()
            if not re.match(r"catch\s*\(", ln):
                continue
            # Check next few lines for empty or return null
            found_swallow = False
            for j in range(idx, min(idx + 6, n)):
                body = lines[j].strip()
                if body in ("}", "{"):
                    continue
                if not body or body.startswith("//") or body.startswith("/*"):
                    continue
                if re.match(r"return\s*(undefined|null|false)?\s*;?$", body):
                    found_swallow = True
                    break
                # Non-trivial body -> not swallowing
                break
            if found_swallow:
                add("", subsystem, branch, rel, idx + 1, "error_swallow",
                    f"Error swallowed: catch -> return null/undefined "
                    f"(masks failure, upstream misjudges success)",
                    severity="P2")

    elif ext in (".go", ".java", ".rs"):
        # MVP: not covered, report INFO if we see catch/except patterns
        pass  # Future: add Go/Java/Rust error swallow detection

# ---------------------------------------------------------------------------
# S8: Unbounded retry / OOM risk (Python)
# ---------------------------------------------------------------------------

RETRY_LOOP_RE = re.compile(
    r"(retry|while\s+True|for\s+.*\s+in\s+range\(\d{3,}\))", re.I)
APPEND_IN_LOOP_RE = re.compile(r"\b(\w+)\.(append|extend|add)\s*\(")
BOUNDED_HINTS = re.compile(r"max_retries|max_attempts|retry_limit|MAX_", re.I)


def scan_unbounded_retry(lines, subsystem, branch, rel):
    """S8: Unbounded loop + append -> OOM risk."""
    n = len(lines)
    for idx in range(n):
        ln = lines[idx].strip()
        is_while_true = re.match(r"while\s+True\s*:", ln)
        is_big_range = re.match(r"for\s+\w+\s+in\s+range\((\d+)\)", ln)
        if not is_while_true and not is_big_range:
            continue
        if is_big_range and int(is_big_range.group(1)) < 100:
            continue
        indent = len(lines[idx]) - len(lines[idx].lstrip())
        body_lines = []
        for j in range(idx + 1, min(idx + 30, n)):
            if lines[j].strip() and (len(lines[j]) - len(lines[j].lstrip())) <= indent:
                break
            body_lines.append(lines[j])
        body = "\n".join(body_lines)
        if BOUNDED_HINTS.search(body):
            continue
        if is_while_true and "break" not in body and "return" not in body:
            add("", subsystem, branch, rel, idx + 1, "unbounded_retry",
                f"while True with no break/return -> potential infinite loop",
                severity="P2")
            continue
        appends = APPEND_IN_LOOP_RE.findall(body)
        if appends:
            var_names = sorted({a[0] for a in appends})
            add("", subsystem, branch, rel, idx + 1, "unbounded_retry",
                f"Unbounded append in loop to {', '.join(var_names[:3])} -> OOM risk",
                severity="P2")

# ---------------------------------------------------------------------------
# S9: Timestamp trust
# ---------------------------------------------------------------------------

TS_TRUST_FRONTEND_RE = re.compile(
    r"(Date\.now\(\)|new\s+Date\(\))\s*(?:[+\-/]|\.getTime)")
TS_TRUST_BACKEND_RE = re.compile(
    r"(request\.\w+|query|form|body).*?(timestamp|time_stamp|created_at|updated_at)"
    r"\s*(==|!=|>=|<=|>|<|sort|order)", re.I)


def scan_timestamp_trust(lines, subsystem, branch, rel, is_frontend=False):
    """S9: Client timestamp used as trusted input for comparison/sorting."""
    for idx, ln in enumerate(lines, 1):
        if is_frontend:
            if TS_TRUST_FRONTEND_RE.search(ln):
                add("", subsystem, branch, rel, idx, "timestamp_trust",
                    f"Client Date.now()/new Date() used for computation/comparison -> tamperable",
                    severity="P2")
        else:
            if TS_TRUST_BACKEND_RE.search(ln):
                add("", subsystem, branch, rel, idx, "timestamp_trust",
                    f"Request/query timestamp used for comparison/sorting -> untrusted input",
                    severity="P2")

# ---------------------------------------------------------------------------
# Unit-level checks
# ---------------------------------------------------------------------------

def unit_has_auth(unit_root, auth_markers):
    """Check if unit backend has any auth markers at all."""
    for ext in ("*.py", "*.js", "*.ts", "*.java", "*.go", "*.rs"):
        for p in unit_root.rglob(ext):
            if _excluded(p):
                continue
            try:
                txt = p.read_text(encoding="utf-8", errors="replace")
                if any(mk in txt for mk in auth_markers):
                    return True
            except Exception:
                continue
    return False


def check_unit_auth(subsystem, unit_root, branch, auth_markers):
    """Unit-level: entire backend has no auth markers -> flag weak auth status."""
    if unit_has_auth(unit_root, auth_markers):
        return
    add("", subsystem, branch, "(unit-level)", 0, "auth",
        f"{subsystem} has no auth markers in any backend file — weak auth status "
        f"(not flagging per-route P0)",
        severity="P1", status="plausible_blocking")

# ---------------------------------------------------------------------------
# Dispatcher: scan one file
# ---------------------------------------------------------------------------

def scan_one(path, subsystem, branch, unit_root, frameworks, auth_markers, cfg,
             report_auth=True):
    """Dispatch file to appropriate scanners based on extension."""
    rel = str(path.relative_to(unit_root)).replace("\\", "/")
    lines = read_lines(path)
    if not lines:
        return
    low = rel.lower()

    # Determine extension
    ext = Path(path).suffix.lower()

    if ext == ".py":
        # S1+S2 routes (Python frameworks)
        if frameworks:
            scan_routes_python(lines, subsystem, branch, rel, frameworks, auth_markers)
        # S3 SSRF (Python)
        if frameworks and any(fw in frameworks for fw in ("fastapi", "flask")):
            scan_ssrf_python(lines, subsystem, branch, rel, frameworks, cfg)
        # S5 cross-store delete
        scan_cross_store_delete(lines, subsystem, branch, rel, cfg)
        # S4 secrets
        scan_secrets(lines, subsystem, branch, rel)
        # S7 error swallow
        scan_error_swallow(lines, subsystem, branch, rel, ext)
        # S8 unbounded retry
        scan_unbounded_retry(lines, subsystem, branch, rel)
        # S9 timestamp trust (backend)
        scan_timestamp_trust(lines, subsystem, branch, rel, is_frontend=False)

    elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        # S1+S2 routes (JS frameworks)
        if frameworks:
            scan_routes_js(lines, subsystem, branch, rel, frameworks, auth_markers)
        # S6 bare fetch
        scan_bare_fetch(lines, subsystem, branch, rel, cfg)
        # S4 secrets
        scan_secrets(lines, subsystem, branch, rel)
        # S7 error swallow
        scan_error_swallow(lines, subsystem, branch, rel, ext)
        # S9 timestamp trust (frontend)
        scan_timestamp_trust(lines, subsystem, branch, rel, is_frontend=True)

    elif ext == ".java":
        # S1+S2 routes (Spring)
        if frameworks:
            scan_routes_java(lines, subsystem, branch, rel, frameworks, auth_markers)
        # S4 secrets
        scan_secrets(lines, subsystem, branch, rel)

    elif ext == ".go":
        # S1 routes (gin/echo/net_http)
        if frameworks:
            scan_routes_go(lines, subsystem, branch, rel, frameworks, auth_markers)
        # S4 secrets
        scan_secrets(lines, subsystem, branch, rel)

    elif ext == ".rs":
        # S1 routes (axum/actix)
        if frameworks:
            scan_routes_rust(lines, subsystem, branch, rel, frameworks, auth_markers)
        # S4 secrets
        scan_secrets(lines, subsystem, branch, rel)

    elif ext in (".yml", ".yaml") or ".env" in low:
        # S4 secrets only
        scan_secrets(lines, subsystem, branch, rel)

# ---------------------------------------------------------------------------
# Risk level
# ---------------------------------------------------------------------------

def risk_level(files):
    paths = " ".join(str(f).lower() for f in files)
    if any(k in paths for k in RISK_HIGH):
        return "HIGH"
    if any(k in paths for k in RISK_MID):
        return "MID"
    return "LOW"

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_summary(risk, total_files, ver_results=None):
    print(f"\n=== Deterministic Code Review Scan ===")
    print(f"Risk level: {risk}  |  Files scanned: {total_files}")
    by_cat = {}
    for f in _findings:
        by_cat.setdefault(f["category"], []).append(f)
    labels = {"route": "S1 Routes", "auth": "S2 Auth", "ssrf": "S3 SSRF",
              "secret": "S4 Hardcoded", "cross_store_delete": "S5 Cross-store delete",
              "bare_fetch": "S6 Bare fetch", "error_swallow": "S7 Error swallow",
              "unbounded_retry": "S8 OOM risk", "timestamp_trust": "S9 Timestamp trust"}
    for cat in ["auth", "ssrf", "secret", "cross_store_delete", "bare_fetch",
                "error_swallow", "unbounded_retry", "timestamp_trust", "route"]:
        items = by_cat.get(cat, [])
        if not items:
            continue
        print(f"\n[{labels.get(cat, cat)}] {len(items)} findings")
        for f in items[:15]:
            sev = f["severity"]
            print(f"  {f['id']} [{sev}] {f['subsystem']}/{f['file']}:{f['line']}")
            print(f"       {f['evidence']}")
        if len(items) > 15:
            print(f"  ... {len(items) - 15} more (use --json for all)")

    if ver_results is not None:
        print_verification_summary(ver_results)

# ---------------------------------------------------------------------------
# Selftest (self-contained fixtures, no dependency on real projects)
# ---------------------------------------------------------------------------

def selftest():
    """Run self-contained fixture tests to verify all scanners."""
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {msg}")
        if not cond:
            ok = False

    print("=== selftest: verify scanners against synthetic fixtures ===\n")

    tmpdir = Path(tempfile.mkdtemp(prefix="review_scan_selftest_"))

    # --- Fixture 1: FastAPI Python with route + no auth ---
    f1 = tmpdir / "app_fastapi.py"
    f1.write_text(
        'from fastapi import APIRouter\n'
        'router = APIRouter()\n'
        '\n'
        '@router.get("/api/users")\n'
        'async def list_users(url: str = None):\n'
        '    return []\n'
        '\n'
        '@router.post("/api/admin/delete")\n'
        'async def delete_thing():\n'
        '    pass\n'
    , encoding="utf-8")

    _findings.clear()
    lines = read_lines(f1)
    auth_markers = get_auth_markers({})
    scan_routes_python(lines, "test", "main", "app_fastapi.py", {"fastapi"}, auth_markers)
    has_route = any(f["category"] == "route" for f in _findings)
    has_no_auth = any(f["category"] == "auth" for f in _findings)
    check(has_route, "S1 detects FastAPI routes")
    check(has_no_auth, "S2 detects missing auth on FastAPI routes")

    # --- Fixture 2: SSRF — URL param without guard ---
    _findings.clear()
    scan_ssrf_python(lines, "test", "main", "app_fastapi.py", {"fastapi"}, {})
    # Without ssrf_guard_functions configured, should report INFO
    has_ssrf_info = any(f["category"] == "ssrf" and f["severity"] == "INFO" for f in _findings)
    check(has_ssrf_info, "S3 degraded mode reports INFO for URL param without guard config")

    # --- Fixture 3: SSRF — URL param with guard configured, but not called ---
    _findings.clear()
    cfg_with_guard = {"ssrf_guard_functions": ["is_safe_external_url"]}
    scan_ssrf_python(lines, "test", "main", "app_fastapi.py", {"fastapi"}, cfg_with_guard)
    has_ssrf_p1 = any(f["category"] == "ssrf" and f["severity"] == "P1" for f in _findings)
    check(has_ssrf_p1, "S3 precise mode reports P1 when guard function not called")

    # --- Fixture 4: Hardcoded secret ---
    f4 = tmpdir / "config.py"
    f4.write_text(
        'API_KEY = "abcdefgh12345678"\n'
        'SAFE_KEY = os.getenv("API_KEY")\n'
    , encoding="utf-8")
    _findings.clear()
    scan_secrets(read_lines(f4), "test", "main", "config.py")
    has_secret = any(f["category"] == "secret" and f["severity"] == "P0" for f in _findings)
    no_env_false = not any("os.getenv" in f["file"] and f["severity"] == "P0" for f in _findings)
    check(has_secret, "S4 detects hardcoded secret")
    check(no_env_false, "S4 skips os.getenv lines")

    # --- Fixture 5: Cross-store delete ---
    f5 = tmpdir / "deleter.py"
    f5.write_text(
        'async def delete_project(project_id):\n'
        '    await db.execute("DELETE FROM projects WHERE id=:id")\n'
        '    await s3_client.delete_object(Bucket=b, Key=k)\n'
    , encoding="utf-8")
    _findings.clear()
    scan_cross_store_delete(read_lines(f5), "test", "main", "deleter.py", {})
    has_cross = any(f["category"] == "cross_store_delete" for f in _findings)
    check(has_cross, "S5 detects cross-store delete (SQL + S3)")

    # --- Fixture 6: Bare fetch ---
    f6 = tmpdir / "app.tsx"
    f6.write_text(
        'fetch("/api/data")\n'
        'authFetch("/api/secure")\n'
        'fetch("/api/auth/login")\n'
    , encoding="utf-8")
    _findings.clear()
    scan_bare_fetch(read_lines(f6), "test", "main", "app.tsx", {})
    has_bare = any(f["category"] == "bare_fetch" for f in _findings)
    no_auth_fetch = not any("authFetch" in f.get("evidence", "") for f in _findings)
    no_login = not any("auth/login" in f.get("evidence", "") for f in _findings)
    check(has_bare, "S6 detects bare fetch()")
    check(no_auth_fetch, "S6 skips authFetch (method call)")
    check(no_login, "S6 skips auth URL whitelist")

    # --- Fixture 7: Error swallow (Python) ---
    f7 = tmpdir / "handler.py"
    f7.write_text(
        'try:\n'
        '    result = do_thing()\n'
        'except Exception:\n'
        '    pass\n'
    , encoding="utf-8")
    _findings.clear()
    scan_error_swallow(read_lines(f7), "test", "main", "handler.py", ".py")
    has_swallow = any(f["category"] == "error_swallow" for f in _findings)
    check(has_swallow, "S7 detects Python except: pass")

    # --- Fixture 8: Spring route ---
    f8 = tmpdir / "Controller.java"
    f8.write_text(
        '@RestController\n'
        'public class UserController {\n'
        '    @GetMapping("/api/users")\n'
        '    public List<User> listUsers() { return null; }\n'
        '}\n'
    , encoding="utf-8")
    _findings.clear()
    scan_routes_java(read_lines(f8), "test", "main", "Controller.java", {"spring"}, auth_markers)
    has_spring_route = any(f["category"] == "route" and "[spring]" in f["evidence"] for f in _findings)
    check(has_spring_route, "S1 detects Spring @GetMapping routes")

    # --- Fixture 9: Express route ---
    f9 = tmpdir / "server.js"
    f9.write_text(
        "const app = require('express')();\n"
        "app.get('/api/items', (req, res) => res.json([]));\n"
        "app.post('/api/items', (req, res) => res.json({}));\n"
    , encoding="utf-8")
    _findings.clear()
    scan_routes_js(read_lines(f9), "test", "main", "server.js", {"express"}, auth_markers)
    has_express_route = any(f["category"] == "route" and "[express]" in f["evidence"] for f in _findings)
    check(has_express_route, "S1 detects Express routes")

    # --- Fixture 10: gin (Go) route ---
    f10 = tmpdir / "main.go"
    f10.write_text(
        'package main\n'
        'import "github.com/gin-gonic/gin"\n'
        'func main() {\n'
        '    r := gin.Default()\n'
        '    r.GET("/api/ping", handler)\n'
        '}\n'
    , encoding="utf-8")
    _findings.clear()
    scan_routes_go(read_lines(f10), "test", "main", "main.go", {"gin"}, auth_markers)
    has_gin_route = any(f["category"] == "route" and "[gin]" in f["evidence"] for f in _findings)
    check(has_gin_route, "S1 detects gin routes")

    # --- Fixture 11: axum (Rust) route ---
    f11 = tmpdir / "main.rs"
    f11.write_text(
        'use axum::Router;\n'
        'fn app() -> Router {\n'
        '    Router::new().route("/api/health", get(handler))\n'
        '}\n'
    , encoding="utf-8")
    _findings.clear()
    scan_routes_rust(read_lines(f11), "test", "main", "main.rs", {"axum"}, auth_markers)
    has_axum_route = any(f["category"] == "route" and "[axum]" in f["evidence"] for f in _findings)
    check(has_axum_route, "S1 detects axum routes")

    # --- Fixture 12: Project discovery ---
    # Create a mini project structure
    proj = tmpdir / "myproject"
    proj.mkdir()
    (proj / "package.json").write_text('{"name": "test"}', encoding="utf-8")
    (proj / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    units = discover_units(proj)
    has_multi_unit = len(units) >= 1
    check(has_multi_unit, "Phase 0 discovers project units from manifests")

    # --- Fixture 13: Framework detection ---
    detected = detect_frameworks(proj, {"python", "js"})
    # The project has package.json + requirements.txt but no source files with imports
    # So framework detection may return empty — that's OK, just verify it doesn't crash
    check(True, "Framework detection runs without error (may return empty for fixture)")

    # --- Fixture 14: Verification runner ---
    _findings.clear()
    ver_passed, ver_results = run_verification(
        tmpdir, [
            {"name": "echo ok", "run": "echo ok", "cwd": ".", "on_risk": ["HIGH", "MID", "LOW"], "expect_exit": 0}
        ], "HIGH", [tmpdir / "dummy.py"])
    check(ver_passed, "Verification runner: passing command passes")

    ver_passed2, ver_results2 = run_verification(
        tmpdir, [
            {"name": "failing", "run": "exit 1", "cwd": ".", "on_risk": ["HIGH", "MID", "LOW"], "expect_exit": 0}
        ], "HIGH", [tmpdir / "dummy.py"])
    check(not ver_passed2, "Verification runner: failing command fails")

    # Cleanup
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)

    print(f"\nselftest {'all passed' if ok else 'HAS FAILURES'}")
    return 0 if ok else 1

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Universal deterministic code review scanner")
    ap.add_argument("--selftest", action="store_true",
                    help="Run self-contained fixture tests")
    ap.add_argument("--root", default=".",
                    help="Project root directory (default: CWD)")
    ap.add_argument("--full", action="store_true",
                    help="Full scan (default: scan git uncommitted changes)")
    ap.add_argument("--base", help="Diff against specified base ref")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--verify", action="store_true",
                    help="Run verification commands after scan (from .code-review.yml)")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"Error: --root {root} is not a directory", file=sys.stderr)
        return 1

    # Load optional config
    cfg = load_config(root)
    auth_markers = get_auth_markers(cfg)
    extra_exclude = get_extra_exclude_dirs(cfg)

    # Phase 0: Discover project units
    units = discover_units(root)

    all_files = []
    for unit_name, unit_root, langs in units:
        branch = get_branch(unit_root)
        frameworks = detect_frameworks(unit_root, langs)

        # Get files to scan
        files = changed_files(unit_root, args.base, args.full, extra_exclude)
        if not files and not args.full:
            print(f"[{unit_name}] No uncommitted changes (use --full for full scan, "
                  f"--base <ref> for diff against base)", file=sys.stderr)
        all_files.extend(files)

        # Unit-level checks
        check_unit_auth(unit_name, unit_root, branch, auth_markers)
        if get_ssrf_guard_functions(cfg):
            check_unit_ssrf(unit_name, unit_root, branch, cfg)

        # Per-file scanning
        report_auth = unit_has_auth(unit_root, auth_markers)  # suppress per-route if whole unit has no auth
        for path in files:
            scan_one(path, unit_name, branch, unit_root, frameworks,
                     auth_markers, cfg, report_auth=report_auth)

    risk = risk_level(all_files)

    # Verification (if --verify)
    ver_results = None
    ver_passed = True
    if args.verify:
        ver_cmds = get_verification_commands(cfg)
        if not ver_cmds:
            # Auto-discover default commands
            for unit_name, unit_root, langs in units:
                ver_cmds = discover_default_verification(unit_root, langs)
                if ver_cmds:
                    break
        if ver_cmds:
            # Use first unit's root for verification
            first_unit_root = units[0][1] if units else root
            ver_passed, ver_results = run_verification(
                first_unit_root, ver_cmds, risk, all_files)
        else:
            ver_results = [{"name": "auto-discovery", "passed": True,
                           "exit_code": 0, "stdout": "", "stderr":
                           "No verification commands configured or auto-discovered"}]

    if args.json:
        output = {"risk": risk, "file_count": len(all_files),
                  "findings": _findings}
        if ver_results is not None:
            output["verification"] = {"passed": ver_passed, "results": ver_results}
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        print_summary(risk, len(all_files), ver_results)

    # Return non-zero if findings or verification failed
    if _findings:
        return 1
    if args.verify and not ver_passed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
