"""
Bell Governance Protocol — 22 Governed Capabilities

The model forms the proposal. The law evaluates it. The executor is deterministic.
The model cannot select constraints, cannot execute, cannot verify.

Architecture:
  natural language
    → LLM (proposal formation only)
    → Proposal object
    → ConstraintRegistry.match() → applicable constraints
    → StateManager.derive()     → expected state + derived fields
    → check_constraints()       → APPROVED / BLOCKED / CLARIFY
    → DeterministicExecutor     → real operations
    → verify()                  → actual state == expected state
    → output

Capabilities (22):
  File system  : file_read, file_write, file_list, file_delete, file_copy,
                 file_move, file_search, dir_create, dir_delete
  HTTP         : http_get, http_post
  Data         : json_read, json_write, csv_read, csv_write
  Git          : git_status, git_diff, git_log  (read-only)
  Compute      : math_eval, hash_compute, template_render, env_read
"""

import ast
import copy
import csv
import hashlib
import io
import json
import operator as op_module
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APPROVED       = "APPROVED"
BLOCKED        = "BLOCKED"
CONFIRM        = "CONFIRM"
CLARIFY        = "CLARIFY"
STALE          = "STALE"
ROLLBACK       = "ROLLBACK"
INTERNAL_ERROR = "INTERNAL_ERROR"

ALL_ACTION_TYPES = [
    "file_read", "file_write", "file_list", "file_delete",
    "file_copy", "file_move", "file_search",
    "dir_create", "dir_delete",
    "http_get", "http_post",
    "json_read", "json_write", "csv_read", "csv_write",
    "shell_run",
    "git_status", "git_diff", "git_log",
    "math_eval", "hash_compute", "template_render", "env_read",
    "govern",
]

SHELL_INJECTION = re.compile(r'[;&|`$<>()\n\r]')

# Safe math operators for math_eval
SAFE_OPS = {
    ast.Add:  op_module.add,
    ast.Sub:  op_module.sub,
    ast.Mult: op_module.mul,
    ast.Div:  op_module.truediv,
    ast.Pow:  op_module.pow,
    ast.Mod:  op_module.mod,
    ast.FloorDiv: op_module.floordiv,
    ast.USub: op_module.neg,
    ast.UAdd: op_module.pos,
}


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config(path: str = None) -> Dict:
    default = Path(__file__).parent / "config.json"
    target  = Path(path) if path else default
    if target.exists():
        return json.loads(target.read_text())
    return {
        "allowed_write_dirs":          ["./workspace"],
        "allowed_read_dirs":           ["./workspace"],
        "allowed_commands":            ["echo", "ls"],
        "allowed_domains":             [],
        "allowed_env_vars":            ["HOME", "PATH", "USER", "PYTHONPATH"],
        "allowed_git_dirs":            ["."],
        "max_file_size_bytes":         1048576,
        "max_command_timeout_seconds": 30,
        "max_http_response_bytes":     524288,
        "ollama_url":                  "http://127.0.0.1:11434",
        "ollama_model":                "llama3.2",
    }


def load_constraints(config_dir: str = None) -> List[Dict]:
    base = Path(config_dir) if config_dir else Path(__file__).parent / "constraints"
    all_c = []
    if base.exists():
        for f in sorted(base.glob("*.json")):
            all_c.extend(json.loads(f.read_text()))
    return all_c


# ---------------------------------------------------------------------------
# Proposal
# ---------------------------------------------------------------------------

@dataclass
class Proposal:
    proposal_id:            str
    created_at:             float
    source_channel:         str
    raw_input:              str
    action_type:            str
    parameters:             Dict[str, Any]
    state_snapshot_version: str
    parameters_complete:    bool = True


# ---------------------------------------------------------------------------
# Constraint + Registry
# ---------------------------------------------------------------------------

@dataclass
class Constraint:
    constraint_id: str
    scope:         str
    field:         str
    operator:      str
    value:         Any
    severity:      str
    on_fail:       str
    description:   str = ""


@dataclass
class Binding:
    binding_id:     str
    match_actions:  List[str]
    constraint_ids: List[str]
    priority:       int
    enabled:        bool = True


class ConstraintRegistry:
    def __init__(self):
        self._constraints: Dict[str, Constraint] = {}
        self._bindings:    List[Binding] = []

    def load_constraints(self, raw: List[Dict]):
        for c in raw:
            fields = {k: c[k] for k in Constraint.__dataclass_fields__ if k in c}
            self._constraints[c["constraint_id"]] = Constraint(**fields)

    def add_binding(self, b: Binding):
        self._bindings.append(b)

    def match(self, proposal: Proposal) -> List["Constraint"]:
        seen: Dict[str, Constraint] = {}
        for b in sorted(self._bindings, key=lambda x: x.priority, reverse=True):
            if not b.enabled:
                continue
            if not b.match_actions or proposal.action_type in b.match_actions:
                for cid in b.constraint_ids:
                    if cid in self._constraints:
                        seen[cid] = self._constraints[cid]
        return list(seen.values())

    @classmethod
    def build(cls, constraint_defs: List[Dict], cfg: Dict) -> "ConstraintRegistry":
        r = cls()
        r.load_constraints(constraint_defs)

        # Inject runtime constraints not in JSON files
        r._constraints["action_type_known"] = Constraint(
            constraint_id="action_type_known", scope="proposal",
            field="proposal.action_type", operator="in",
            value=ALL_ACTION_TYPES, severity="critical", on_fail="block",
            description="Action type must be in the registered capability list",
        )
        r._constraints["http_domain_allowed"] = Constraint(
            constraint_id="http_domain_allowed", scope="derived",
            field="derived.domain_allowed", operator="eq",
            value=True, severity="critical", on_fail="block",
            description="HTTP target domain must be in allowed_domains",
        )
        r._constraints["env_var_allowed"] = Constraint(
            constraint_id="env_var_allowed", scope="derived",
            field="derived.env_var_allowed", operator="eq",
            value=True, severity="critical", on_fail="block",
            description="Environment variable must be in allowed_env_vars",
        )
        r._constraints["math_expression_safe"] = Constraint(
            constraint_id="math_expression_safe", scope="derived",
            field="derived.math_safe", operator="eq",
            value=True, severity="critical", on_fail="block",
            description="Math expression must contain only safe numeric operations",
        )
        r._constraints["git_dir_allowed"] = Constraint(
            constraint_id="git_dir_allowed", scope="derived",
            field="derived.git_dir_allowed", operator="eq",
            value=True, severity="critical", on_fail="block",
            description="Git operation must target an allowed repository",
        )
        r._constraints["csv_path_allowed"] = Constraint(
            constraint_id="csv_path_allowed", scope="derived",
            field="derived.path_in_read_allowlist", operator="eq",
            value=True, severity="critical", on_fail="block",
            description="CSV path must be in allowed read directories",
        )

        # Global
        r.add_binding(Binding("global", [], [
            "state_version_current", "action_type_known", "parameters_present",
        ], 1000))

        # File ops
        r.add_binding(Binding("file_write",  ["file_write"],
            ["write_path_allowed", "file_size_within_limit", "no_path_traversal"], 100))
        r.add_binding(Binding("file_read",   ["file_read", "file_list", "file_search"],
            ["read_path_allowed", "no_path_traversal"], 100))
        r.add_binding(Binding("file_delete", ["file_delete", "file_move"],
            ["write_path_allowed", "no_path_traversal"], 100))
        r.add_binding(Binding("file_copy",   ["file_copy"],
            ["write_path_allowed", "read_path_allowed", "no_path_traversal"], 100))
        r.add_binding(Binding("dir_ops",     ["dir_create", "dir_delete"],
            ["write_path_allowed", "no_path_traversal"], 100))

        # Data
        r.add_binding(Binding("json_write",  ["json_write"],
            ["write_path_allowed", "file_size_within_limit", "no_path_traversal"], 100))
        r.add_binding(Binding("json_read",   ["json_read"],
            ["read_path_allowed", "no_path_traversal"], 100))
        r.add_binding(Binding("csv_read",    ["csv_read"],
            ["csv_path_allowed", "no_path_traversal"], 100))
        r.add_binding(Binding("csv_write",   ["csv_write"],
            ["write_path_allowed", "file_size_within_limit", "no_path_traversal"], 100))

        # Shell
        r.add_binding(Binding("shell", ["shell_run"],
            ["command_whitelisted", "no_shell_injection", "timeout_within_limit"], 100))

        # HTTP
        r.add_binding(Binding("http", ["http_get", "http_post"],
            ["http_domain_allowed"], 100))

        # Git
        r.add_binding(Binding("git", ["git_status", "git_diff", "git_log"],
            ["git_dir_allowed"], 100))

        # Compute
        r.add_binding(Binding("math",   ["math_eval"],   ["math_expression_safe"], 100))
        r.add_binding(Binding("env",    ["env_read"],    ["env_var_allowed"], 100))

        return r


# ---------------------------------------------------------------------------
# State Manager
# ---------------------------------------------------------------------------

class StateManager:
    def __init__(self, workspace_root: str, cfg: Dict):
        self._root = Path(workspace_root).resolve()
        self._cfg  = cfg
        self.version = str(uuid.uuid4())
        self._history: List[Dict] = []
        self._committed_keys: set = set()
        for d in cfg.get("allowed_write_dirs", []):
            (self._root / d.lstrip("./")).mkdir(parents=True, exist_ok=True)

    def snapshot(self) -> Tuple[str, Dict]:
        return self.version, self._read_fs()

    def _read_fs(self) -> Dict:
        files = {}
        dirs  = set(self._cfg.get("allowed_read_dirs", []) +
                    self._cfg.get("allowed_write_dirs", []))
        for d in dirs:
            p = self._root / d.lstrip("./")
            if p.exists():
                for f in p.rglob("*"):
                    if f.is_file():
                        rel = str(f.relative_to(self._root))
                        try:
                            files[rel] = hashlib.sha256(f.read_bytes()).hexdigest()
                        except Exception:
                            pass
        return {"files": files, "version": self.version}

    def _in_write(self, path: str) -> bool:
        return self._in_list(path, self._cfg.get("allowed_write_dirs", []))

    def _in_read(self, path: str) -> bool:
        return self._in_list(path, self._cfg.get("allowed_read_dirs", []) +
                                    self._cfg.get("allowed_write_dirs", []))

    def _in_list(self, path: str, lst: List[str]) -> bool:
        if not path:
            return False
        norm = path.replace("\\", "/").lstrip("/")
        for a in lst:
            prefix = a.lstrip("./").rstrip("/")
            if norm.startswith(prefix + "/") or norm == prefix:
                return True
        return False

    def derive(self, proposal: Proposal, pre_state: Dict, cfg: Dict) -> Tuple[Dict, Dict]:
        """Pure derivation — no side effects."""
        expected = copy.deepcopy(pre_state)
        derived:  Dict[str, Any] = {
            "path_in_write_allowlist": True,
            "path_in_read_allowlist":  True,
            "path_traversal_detected": False,
            "content_size_bytes":      0,
            "command_in_whitelist":    True,
            "shell_injection_detected": False,
            "timeout_within_limit":    True,
            "domain_allowed":          True,
            "env_var_allowed":         True,
            "math_safe":               True,
            "git_dir_allowed":         True,
        }

        a = proposal.action_type
        p = proposal.parameters

        def path_checks(path, write=False):
            derived["path_traversal_detected"] = ".." in (path or "")
            if write:
                derived["path_in_write_allowlist"] = self._in_write(path or "")
            derived["path_in_read_allowlist"] = self._in_read(path or "")

        if a == "file_write":
            path_checks(p.get("path", ""), write=True)
            content = p.get("content", "")
            derived["content_size_bytes"] = len(content.encode())
            if derived["path_in_write_allowlist"] and not derived["path_traversal_detected"]:
                expected["files"][p["path"]] = hashlib.sha256(content.encode()).hexdigest()

        elif a in ("file_read", "file_list", "file_search"):
            path_checks(p.get("path", ""))

        elif a == "file_delete":
            path_checks(p.get("path", ""), write=True)
            if derived["path_in_write_allowlist"] and not derived["path_traversal_detected"]:
                expected["files"].pop(p.get("path", ""), None)

        elif a == "file_copy":
            src = p.get("src", "")
            dst = p.get("dst", "")
            derived["path_traversal_detected"] = ".." in src or ".." in dst
            derived["path_in_read_allowlist"]  = self._in_read(src)
            derived["path_in_write_allowlist"] = self._in_write(dst)

        elif a == "file_move":
            src = p.get("src", "")
            dst = p.get("dst", "")
            derived["path_traversal_detected"] = ".." in src or ".." in dst
            derived["path_in_write_allowlist"] = self._in_write(src) and self._in_write(dst)

        elif a in ("dir_create", "dir_delete"):
            path_checks(p.get("path", ""), write=True)

        elif a == "json_write":
            path_checks(p.get("path", ""), write=True)
            content = json.dumps(p.get("data", {}))
            derived["content_size_bytes"] = len(content.encode())

        elif a in ("json_read", "csv_read"):
            path_checks(p.get("path", ""))

        elif a == "csv_write":
            path_checks(p.get("path", ""), write=True)
            rows = p.get("rows", [])
            derived["content_size_bytes"] = sum(
                len(",".join(str(v) for v in r).encode()) for r in rows)

        elif a == "shell_run":
            cmd = p.get("command", "")
            args = p.get("args", [])
            timeout = p.get("timeout", cfg.get("max_command_timeout_seconds", 30))
            derived["command_in_whitelist"]     = cmd in cfg.get("allowed_commands", [])
            derived["shell_injection_detected"] = bool(
                SHELL_INJECTION.search(" ".join(str(x) for x in args)))
            derived["timeout_within_limit"]     = int(timeout) <= cfg.get("max_command_timeout_seconds", 30)

        elif a in ("http_get", "http_post"):
            url = p.get("url", "")
            try:
                domain = urllib.parse.urlparse(url).netloc
                allowed = cfg.get("allowed_domains", [])
                derived["domain_allowed"] = (not allowed) or any(
                    domain == d or domain.endswith("." + d) for d in allowed)
            except Exception:
                derived["domain_allowed"] = False

        elif a in ("git_status", "git_diff", "git_log"):
            path = p.get("repo_path", ".")
            allowed_git = cfg.get("allowed_git_dirs", ["."])
            derived["git_dir_allowed"] = path in allowed_git

        elif a == "math_eval":
            expr = p.get("expression", "")
            derived["math_safe"] = _is_safe_math(expr)

        elif a == "env_read":
            var = p.get("var", "")
            derived["env_var_allowed"] = var in cfg.get("allowed_env_vars",
                ["HOME", "PATH", "USER", "PYTHONPATH"])

        return expected, derived

    def commit_version(self) -> str:
        self.version = str(uuid.uuid4())
        return self.version

    def record(self, execution_id, proposal_id, pre_ver, post_ver, idempotency_key):
        self._history.append({
            "execution_id": execution_id, "proposal_id": proposal_id,
            "pre_state_version": pre_ver, "post_state_version": post_ver,
            "idempotency_key": idempotency_key, "timestamp": time.time(),
        })
        self._committed_keys.add(idempotency_key)

    def already_committed(self, key: str) -> bool:
        return key in self._committed_keys


# ---------------------------------------------------------------------------
# Safe math evaluator (no exec, no eval)
# ---------------------------------------------------------------------------

def _is_safe_math(expr: str) -> bool:
    try:
        tree = ast.parse(expr, mode="eval")
        for node in ast.walk(tree):
            if not isinstance(node, (
                ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant,
                ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow, ast.Mod,
                ast.FloorDiv, ast.USub, ast.UAdd,
            )):
                return False
        return True
    except Exception:
        return False


def _eval_math(expr: str) -> Any:
    def _eval(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.BinOp):
            return SAFE_OPS[type(node.op)](_eval(node.left), _eval(node.right))
        if isinstance(node, ast.UnaryOp):
            return SAFE_OPS[type(node.op)](_eval(node.operand))
        raise ValueError(f"Unsafe node: {node}")
    return _eval(ast.parse(expr, mode="eval").body)


# ---------------------------------------------------------------------------
# Predicate evaluation
# ---------------------------------------------------------------------------

def _resolve(field_path: str, proposal: Proposal, state: Dict, derived: Dict) -> Any:
    if field_path.startswith("derived."):
        return derived.get(field_path[8:])
    if field_path.startswith("proposal."):
        attr = field_path[9:]
        return getattr(proposal, attr, proposal.parameters.get(attr))
    return None


def _apply(op: str, left: Any, right: Any) -> bool:
    try:
        if op == "eq":         return left == right
        if op == "neq":        return left != right
        if op == "gte":        return left is not None and left >= right
        if op == "lte":        return left is not None and left <= right
        if op == "gt":         return left is not None and left >  right
        if op == "lt":         return left is not None and left <  right
        if op == "in":         return left in (right or [])
        if op == "not_in":     return left not in (right or [])
        if op == "exists":     return left is not None
        if op == "not_exists": return left is None
    except TypeError:
        return False
    return False


def check_constraints(
    constraints: List[Constraint],
    proposal:    Proposal,
    state:       Dict,
    derived:     Dict,
) -> Tuple[str, List[Constraint]]:
    failures = [c for c in constraints
                if not _apply(c.operator, _resolve(c.field, proposal, state, derived), c.value)]
    if not failures:
        return APPROVED, []
    for f in failures:
        if f.on_fail == "block":
            return BLOCKED, failures
    for f in failures:
        if f.on_fail == "confirm":
            return CONFIRM, failures
    return CLARIFY, failures


# ---------------------------------------------------------------------------
# Deterministic Executor — 22 capabilities
# ---------------------------------------------------------------------------

class DeterministicExecutor:
    def __init__(self, workspace_root: str, cfg: Dict):
        self._root = Path(workspace_root).resolve()
        self._cfg  = cfg

    def execute(self, proposal: Proposal) -> Dict[str, Any]:
        a = proposal.action_type
        p = proposal.parameters
        try:
            if a == "file_read":      return self._file_read(p)
            if a == "file_write":     return self._file_write(p)
            if a == "file_list":      return self._file_list(p)
            if a == "file_delete":    return self._file_delete(p)
            if a == "file_copy":      return self._file_copy(p)
            if a == "file_move":      return self._file_move(p)
            if a == "file_search":    return self._file_search(p)
            if a == "dir_create":     return self._dir_create(p)
            if a == "dir_delete":     return self._dir_delete(p)
            if a == "json_read":      return self._json_read(p)
            if a == "json_write":     return self._json_write(p)
            if a == "csv_read":       return self._csv_read(p)
            if a == "csv_write":      return self._csv_write(p)
            if a == "shell_run":      return self._shell_run(p)
            if a == "http_get":       return self._http_get(p)
            if a == "http_post":      return self._http_post(p)
            if a == "git_status":     return self._git(["status", "--short"], p)
            if a == "git_diff":       return self._git(["diff"], p)
            if a == "git_log":        return self._git(["log", "--oneline",
                                          f"-{p.get('limit', 10)}"], p)
            if a == "math_eval":      return self._math_eval(p)
            if a == "hash_compute":   return self._hash_compute(p)
            if a == "template_render": return self._template_render(p)
            if a == "env_read":       return self._env_read(p)
            return {"ok": False, "error": f"Unknown action: {a}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # --- helpers ---

    def _rp(self, path: str) -> Path:
        p = (self._root / path.lstrip("/")).resolve()
        p.relative_to(self._root)   # raises if outside root
        return p

    # --- file ops ---

    def _file_read(self, p):
        path = self._rp(p["path"])
        return {"ok": True, "path": p["path"], "content": path.read_text(encoding="utf-8")}

    def _file_write(self, p):
        path = self._rp(p["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        content = p.get("content", "")
        path.write_text(content, encoding="utf-8")
        return {"ok": True, "path": p["path"], "bytes": len(content.encode())}

    def _file_list(self, p):
        path = self._rp(p.get("path", "."))
        entries = [
            {"name": f.name, "type": "dir" if f.is_dir() else "file",
             "size": f.stat().st_size if f.is_file() else 0}
            for f in sorted(path.iterdir())
        ]
        return {"ok": True, "entries": entries, "count": len(entries)}

    def _file_delete(self, p):
        self._rp(p["path"]).unlink()
        return {"ok": True, "deleted": p["path"]}

    def _file_copy(self, p):
        src = self._rp(p["src"])
        dst = self._rp(p["dst"])
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return {"ok": True, "src": p["src"], "dst": p["dst"]}

    def _file_move(self, p):
        src = self._rp(p["src"])
        dst = self._rp(p["dst"])
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        return {"ok": True, "src": p["src"], "dst": p["dst"]}

    def _file_search(self, p):
        path    = self._rp(p.get("path", "."))
        pattern = re.compile(p.get("pattern", ""), re.IGNORECASE if p.get("ignore_case") else 0)
        results = []
        for f in path.rglob("*"):
            if f.is_file():
                try:
                    for i, line in enumerate(f.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                        if pattern.search(line):
                            results.append({"file": str(f.relative_to(self._root)),
                                            "line": i, "text": line.strip()})
                except Exception:
                    pass
        return {"ok": True, "matches": results, "count": len(results)}

    def _dir_create(self, p):
        self._rp(p["path"]).mkdir(parents=True, exist_ok=True)
        return {"ok": True, "created": p["path"]}

    def _dir_delete(self, p):
        shutil.rmtree(self._rp(p["path"]))
        return {"ok": True, "deleted": p["path"]}

    # --- data ops ---

    def _json_read(self, p):
        data = json.loads(self._rp(p["path"]).read_text(encoding="utf-8"))
        return {"ok": True, "path": p["path"], "data": data}

    def _json_write(self, p):
        path = self._rp(p["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(p.get("data", {}), indent=2)
        path.write_text(content, encoding="utf-8")
        return {"ok": True, "path": p["path"], "bytes": len(content.encode())}

    def _csv_read(self, p):
        text    = self._rp(p["path"]).read_text(encoding="utf-8")
        reader  = csv.DictReader(io.StringIO(text))
        rows    = list(reader)
        return {"ok": True, "path": p["path"], "rows": rows, "count": len(rows)}

    def _csv_write(self, p):
        path = self._rp(p["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        rows    = p.get("rows", [])
        headers = p.get("headers", list(rows[0].keys()) if rows and isinstance(rows[0], dict) else [])
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
        path.write_text(out.getvalue(), encoding="utf-8")
        return {"ok": True, "path": p["path"], "rows": len(rows)}

    # --- shell ---

    def _shell_run(self, p):
        timeout = min(int(p.get("timeout", 10)), self._cfg.get("max_command_timeout_seconds", 30))
        result  = subprocess.run(
            [p["command"]] + [str(a) for a in p.get("args", [])],
            capture_output=True, text=True, timeout=timeout, cwd=str(self._root),
        )
        return {"ok": result.returncode == 0, "exit_code": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr}

    # --- http ---

    def _http_get(self, p):
        req     = urllib.request.Request(p["url"], headers=p.get("headers", {}))
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read(self._cfg.get("max_http_response_bytes", 524288))
        return {"ok": True, "status": resp.status,
                "body": body.decode("utf-8", errors="replace")}

    def _http_post(self, p):
        data    = json.dumps(p.get("body", {})).encode()
        headers = {"Content-Type": "application/json", **p.get("headers", {})}
        req     = urllib.request.Request(p["url"], data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read(self._cfg.get("max_http_response_bytes", 524288))
        return {"ok": True, "status": resp.status,
                "body": body.decode("utf-8", errors="replace")}

    # --- git (read-only) ---

    def _git(self, subcmd: List[str], p: Dict):
        repo = p.get("repo_path", ".")
        result = subprocess.run(
            ["git"] + subcmd,
            capture_output=True, text=True, timeout=10,
            cwd=str((self._root / repo).resolve()),
        )
        return {"ok": result.returncode == 0, "output": result.stdout, "stderr": result.stderr}

    # --- compute ---

    def _math_eval(self, p):
        result = _eval_math(p["expression"])
        return {"ok": True, "expression": p["expression"], "result": result}

    def _hash_compute(self, p):
        algo    = p.get("algorithm", "sha256")
        content = p.get("content", "").encode()
        h       = hashlib.new(algo, content).hexdigest()
        return {"ok": True, "algorithm": algo, "hash": h}

    def _template_render(self, p):
        template  = p.get("template", "")
        variables = p.get("variables", {})
        result    = re.sub(
            r'\{\{(\w+)\}\}',
            lambda m: str(variables.get(m.group(1), m.group(0))),
            template,
        )
        return {"ok": True, "output": result}

    def _env_read(self, p):
        var = p.get("var", "")
        return {"ok": True, "var": var, "value": os.environ.get(var)}


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify(proposal: Proposal, expected: Dict, actual: Dict, exec_result: Dict) -> Tuple[bool, str]:
    a = proposal.action_type

    if not exec_result.get("ok"):
        return False, exec_result.get("error", exec_result.get("stderr", "execution failed"))

    if a == "file_write":
        path = proposal.parameters.get("path", "")
        if expected["files"].get(path) != actual["files"].get(path):
            return False, f"file hash mismatch for {path}"

    if a == "file_delete":
        path = proposal.parameters.get("path", "")
        if path in actual["files"]:
            return False, f"file still exists: {path}"

    return True, "ok"


# ---------------------------------------------------------------------------
# Proposal formation — LLM sits here and only here
# ---------------------------------------------------------------------------

def _call_ollama(raw: str, cfg: Dict) -> Optional[Dict]:
    system = f"""Extract a structured command from natural language.

Return ONLY valid JSON, no explanation, no markdown fences.

Schema:
{{
  "action_type": "one of: {', '.join(ALL_ACTION_TYPES)}",
  "parameters": {{
    "path": "file/dir path if applicable",
    "src": "source path for copy/move",
    "dst": "destination path for copy/move",
    "content": "text content if writing",
    "data": {{}},
    "rows": [],
    "headers": [],
    "command": "command name for shell_run",
    "args": [],
    "url": "full URL for http ops",
    "body": {{}},
    "pattern": "regex pattern for file_search",
    "expression": "math expression for math_eval",
    "algorithm": "sha256 for hash_compute",
    "template": "template string with {{{{var}}}} placeholders",
    "variables": {{}},
    "var": "env var name for env_read",
    "repo_path": ".",
    "limit": 10
  }},
  "parameters_complete": true
}}

Only include parameters that are actually needed for the action.
If unclear or missing info, set parameters_complete to false."""

    try:
        body = json.dumps({
            "model":  cfg.get("ollama_model", "llama3.2"),
            "prompt": f"{system}\n\nInput: {raw}",
            "stream": False,
        }).encode()
        req = urllib.request.Request(
            f"{cfg.get('ollama_url', 'http://127.0.0.1:11434')}/api/generate",
            data=body, headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            text = json.loads(resp.read()).get("response", "")
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if m:
            return json.loads(m.group())
    except Exception:
        pass
    return None


def build_proposal(raw: str, version: str, cfg: Dict) -> Proposal:
    parsed = _call_ollama(raw, cfg)
    if not parsed:
        try:
            parsed = json.loads(raw)
        except Exception:
            pass

    if parsed and "action_type" in parsed:
        return Proposal(
            proposal_id=str(uuid.uuid4()), created_at=time.time(),
            source_channel="cli", raw_input=raw,
            action_type=parsed.get("action_type", "unknown"),
            parameters=parsed.get("parameters", {}),
            state_snapshot_version=version,
            parameters_complete=parsed.get("parameters_complete", True),
        )
    return Proposal(
        proposal_id=str(uuid.uuid4()), created_at=time.time(),
        source_channel="cli", raw_input=raw,
        action_type="unknown", parameters={},
        state_snapshot_version=version,
        parameters_complete=False,
    )


# ---------------------------------------------------------------------------
# Governance loop
# ---------------------------------------------------------------------------

def run_cycle(raw: str, registry: ConstraintRegistry,
              state: StateManager, executor: DeterministicExecutor,
              cfg: Dict) -> Dict[str, Any]:

    pre_ver, pre_state = state.snapshot()
    proposal           = build_proposal(raw, pre_ver, cfg)
    expected, derived  = state.derive(proposal, pre_state, cfg)
    constraints        = registry.match(proposal)
    decision, failures = check_constraints(constraints, proposal, pre_state, derived)

    if decision != APPROVED:
        return {"status": decision,
                "reasons": [f"{f.constraint_id}: {f.description}" for f in failures],
                "proposal": proposal.proposal_id}

    ikey = hashlib.sha256(
        f"{proposal.action_type}:{json.dumps(proposal.parameters, sort_keys=True)}".encode()
    ).hexdigest()

    if state.already_committed(ikey):
        return {"status": "IDEMPOTENT", "proposal": proposal.proposal_id}

    cur_ver, _ = state.snapshot()
    if cur_ver != pre_ver:
        return {"status": STALE, "proposal": proposal.proposal_id}

    exec_result         = executor.execute(proposal)
    post_ver, act_state = state.snapshot()
    passed, reason      = verify(proposal, expected, act_state, exec_result)

    if not passed:
        return {"status": ROLLBACK, "reason": reason, "proposal": proposal.proposal_id}

    new_ver = state.commit_version()
    state.record(str(uuid.uuid4()), proposal.proposal_id, pre_ver, new_ver, ikey)

    return {"status": "COMMITTED", "proposal": proposal.proposal_id,
            "result": exec_result, "version": new_ver}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_result(result: Dict):
    status = result["status"]
    r      = result.get("result", {})

    if status == "COMMITTED":
        print(f"  ✓ COMMITTED [{result.get('version','')[:8]}]")
        if "content" in r:
            preview = r["content"][:400]
            print(f"    {preview}")
        elif "entries" in r:
            for e in r["entries"]:
                t = "d" if e["type"] == "dir" else "f"
                print(f"    {t}  {e['name']}  ({e.get('size',0)} B)")
        elif "matches" in r:
            for m in r["matches"][:20]:
                print(f"    {m['file']}:{m['line']}  {m['text']}")
        elif "rows" in r:
            rows = r["rows"]
            if rows:
                print(f"    {list(rows[0].keys())}")
                for row in rows[:5]:
                    print(f"    {list(row.values())}")
        elif "data" in r:
            print(f"    {json.dumps(r['data'], indent=2)[:300]}")
        elif "result" in r:
            print(f"    {r['result']}")
        elif "output" in r:
            print(f"    {r['output'][:400]}")
        elif "stdout" in r and r["stdout"].strip():
            print(f"    {r['stdout'].strip()[:300]}")
        elif "value" in r:
            print(f"    {r['var']} = {r['value']}")
        elif "hash" in r:
            print(f"    {r['algorithm']}: {r['hash']}")
    elif status == "BLOCKED":
        print(f"  ✗ BLOCKED")
        for reason in result.get("reasons", []):
            print(f"    {reason}")
    elif status == "CLARIFY":
        print(f"  ? CLARIFY")
        for reason in result.get("reasons", []):
            print(f"    {reason}")
    else:
        print(f"  ! {status}: {result.get('reason', result.get('reasons', ''))}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Bell Governance Protocol")
    parser.add_argument("--workspace", default="./workspace")
    parser.add_argument("--config",    default=None)
    args = parser.parse_args()

    cfg      = load_config(args.config)
    raw_c    = load_constraints()
    registry = ConstraintRegistry.build(raw_c, cfg)
    state    = StateManager(args.workspace, cfg)
    executor = DeterministicExecutor(args.workspace, cfg)

    Path(args.workspace).mkdir(parents=True, exist_ok=True)

    print("Bell Governance Protocol  —  22 capabilities")
    print(f"  Workspace : {Path(args.workspace).resolve()}")
    print(f"  LLM       : {'Ollama @ ' + cfg.get('ollama_url') if cfg.get('ollama_url') else 'JSON mode'}")
    print()
    print("  file_read  file_write  file_list  file_delete  file_copy  file_move")
    print("  file_search  dir_create  dir_delete")
    print("  json_read  json_write  csv_read  csv_write")
    print("  http_get  http_post")
    print("  git_status  git_diff  git_log")
    print("  math_eval  hash_compute  template_render  env_read")
    print()
    print("Input: natural language (Ollama) or raw JSON. 'exit' to quit.\n")

    while True:
        try:
            raw = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break
        if not raw or raw.lower() in ("exit", "quit"):
            break
        _print_result(run_cycle(raw, registry, state, executor, cfg))
        print()


if __name__ == "__main__":
    main()
