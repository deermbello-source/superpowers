"""
Bell Governance Protocol — Correct Implementation

The model forms the proposal. The law evaluates it. The executor is deterministic.
The model cannot select constraints, cannot execute, cannot verify.

Architecture:
  natural language
    → LLM (proposal formation only)
    → Proposal object
    → ConstraintRegistry.match() → applicable constraints
    → StateManager.derive()     → expected state + derived fields
    → check_constraints()       → APPROVED / BLOCKED / CLARIFY
    → ExecutionContract         → exact allowed mutations
    → DeterministicExecutor     → real file / shell operations
    → verify()                  → actual state == expected state
    → output
"""

import copy
import hashlib
import json
import os
import re
import shlex
import subprocess
import time
import uuid
from dataclasses import dataclass, field
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

SHELL_INJECTION_CHARS = re.compile(r'[;&|`$<>()\n\r]')


# ---------------------------------------------------------------------------
# Config loader
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
        "max_file_size_bytes":         1048576,
        "max_command_timeout_seconds": 30,
        "ollama_url":                  "http://127.0.0.1:11434",
        "ollama_model":                "llama3.2",
    }


def load_constraints(config_dir: str = None) -> List[Dict]:
    base = Path(config_dir) if config_dir else Path(__file__).parent / "constraints"
    all_constraints = []
    if base.exists():
        for f in sorted(base.glob("*.json")):
            all_constraints.extend(json.loads(f.read_text()))
    return all_constraints


# ---------------------------------------------------------------------------
# Proposal
# ---------------------------------------------------------------------------

@dataclass
class Proposal:
    proposal_id:           str
    created_at:            float
    source_channel:        str
    raw_input:             str
    action_type:           str        # file_read | file_write | file_list | file_delete | shell_run | govern
    parameters:            Dict[str, Any]
    state_snapshot_version: str
    parameters_complete:   bool = True


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
    match_actions:  List[str]   # empty = global (matches all)
    constraint_ids: List[str]
    priority:       int
    enabled:        bool = True


class ConstraintRegistry:
    def __init__(self):
        self._constraints: Dict[str, Constraint] = {}
        self._bindings: List[Binding] = []

    def load_constraints(self, raw: List[Dict]):
        for c in raw:
            obj = Constraint(**{k: c[k] for k in Constraint.__dataclass_fields__ if k in c})
            self._constraints[obj.constraint_id] = obj

    def add_binding(self, binding: Binding):
        self._bindings.append(binding)

    def match(self, proposal: Proposal) -> List[Constraint]:
        """Deterministic: union of all applicable constraint sets, deduped."""
        result: Dict[str, Constraint] = {}
        for b in sorted(self._bindings, key=lambda x: x.priority, reverse=True):
            if not b.enabled:
                continue
            if not b.match_actions or proposal.action_type in b.match_actions:
                for cid in b.constraint_ids:
                    if cid in self._constraints:
                        result[cid] = self._constraints[cid]
        return list(result.values())

    @classmethod
    def build(cls, constraint_defs: List[Dict], cfg: Dict) -> "ConstraintRegistry":
        registry = cls()
        registry.load_constraints(constraint_defs)

        # global bindings — apply to every proposal
        registry.add_binding(Binding(
            binding_id="global",
            match_actions=[],
            constraint_ids=["state_version_current", "action_type_known", "parameters_present"],
            priority=1000,
        ))

        # file write bindings
        registry.add_binding(Binding(
            binding_id="file_write",
            match_actions=["file_write"],
            constraint_ids=["write_path_allowed", "file_size_within_limit", "no_path_traversal"],
            priority=100,
        ))

        # file read bindings
        registry.add_binding(Binding(
            binding_id="file_read",
            match_actions=["file_read", "file_list"],
            constraint_ids=["read_path_allowed", "no_path_traversal"],
            priority=100,
        ))

        # file delete — write allowlist applies (stricter)
        registry.add_binding(Binding(
            binding_id="file_delete",
            match_actions=["file_delete"],
            constraint_ids=["write_path_allowed", "no_path_traversal"],
            priority=100,
        ))

        # shell bindings
        registry.add_binding(Binding(
            binding_id="shell",
            match_actions=["shell_run"],
            constraint_ids=["command_whitelisted", "no_shell_injection", "timeout_within_limit"],
            priority=100,
        ))

        return registry


# ---------------------------------------------------------------------------
# State Manager
# ---------------------------------------------------------------------------

class StateManager:
    """
    Truth surface. Versioned. Immutable snapshots. Pure derivation.

    State tree:
      files/  → {relative_path: content_hash}   (we don't store full content in state tree)
      procs/  → {execution_id: exit_code}
    """

    def __init__(self, workspace_root: str, cfg: Dict):
        self._root    = Path(workspace_root).resolve()
        self._cfg     = cfg
        self.version  = self._make_version()
        self._history: List[Dict] = []
        self._committed_keys: set = set()

        # ensure workspace dirs exist
        for d in cfg.get("allowed_write_dirs", []):
            (self._root / d.lstrip("./")).mkdir(parents=True, exist_ok=True)

    def _make_version(self) -> str:
        return str(uuid.uuid4())

    def snapshot(self) -> Tuple[str, Dict]:
        """Return (version, state snapshot). Snapshot = hash of real filesystem."""
        state = self._read_fs_state()
        return self.version, state

    def _read_fs_state(self) -> Dict:
        """Read actual filesystem state within allowed dirs."""
        files = {}
        for d in self._cfg.get("allowed_read_dirs", []) + self._cfg.get("allowed_write_dirs", []):
            dir_path = self._root / d.lstrip("./")
            if dir_path.exists():
                for f in dir_path.rglob("*"):
                    if f.is_file():
                        rel = str(f.relative_to(self._root))
                        try:
                            files[rel] = hashlib.sha256(f.read_bytes()).hexdigest()
                        except Exception:
                            pass
        return {"files": files, "version": self.version}

    def derive(self, proposal: Proposal, pre_state: Dict, cfg: Dict) -> Tuple[Dict, Dict]:
        """
        Pure derivation: compute expected state and derived fields.
        No side effects. The executor will do the same operations later.
        """
        expected = copy.deepcopy(pre_state)
        derived:  Dict[str, Any] = {}

        action = proposal.action_type
        params = proposal.parameters

        if action == "file_write":
            path    = params.get("path", "")
            content = params.get("content", "")
            derived["path_in_write_allowlist"] = self._in_allowlist(
                path, cfg.get("allowed_write_dirs", []))
            derived["path_in_read_allowlist"]  = derived["path_in_write_allowlist"]
            derived["path_traversal_detected"] = ".." in path
            derived["content_size_bytes"]      = len(content.encode())
            if derived["path_in_write_allowlist"] and not derived["path_traversal_detected"]:
                content_hash = hashlib.sha256(content.encode()).hexdigest()
                expected["files"][path] = content_hash

        elif action in ("file_read", "file_list"):
            path = params.get("path", "")
            derived["path_in_read_allowlist"]  = self._in_allowlist(
                path, cfg.get("allowed_read_dirs", []))
            derived["path_in_write_allowlist"] = derived["path_in_read_allowlist"]
            derived["path_traversal_detected"] = ".." in path
            derived["content_size_bytes"]      = 0

        elif action == "file_delete":
            path = params.get("path", "")
            derived["path_in_write_allowlist"] = self._in_allowlist(
                path, cfg.get("allowed_write_dirs", []))
            derived["path_traversal_detected"] = ".." in path
            derived["content_size_bytes"]      = 0
            if derived["path_in_write_allowlist"] and not derived["path_traversal_detected"]:
                expected["files"].pop(path, None)

        elif action == "shell_run":
            cmd     = params.get("command", "")
            args    = params.get("args", [])
            timeout = params.get("timeout", cfg.get("max_command_timeout_seconds", 30))
            derived["command_in_whitelist"]    = cmd in cfg.get("allowed_commands", [])
            derived["shell_injection_detected"] = bool(SHELL_INJECTION_CHARS.search(
                " ".join(str(a) for a in args)))
            derived["timeout_within_limit"]    = timeout <= cfg.get("max_command_timeout_seconds", 30)

        # universal derived fields
        derived["path_in_write_allowlist"] = derived.get("path_in_write_allowlist", True)
        derived["path_in_read_allowlist"]  = derived.get("path_in_read_allowlist",  True)
        derived["path_traversal_detected"] = derived.get("path_traversal_detected", False)
        derived["content_size_bytes"]      = derived.get("content_size_bytes", 0)

        return expected, derived

    def _in_allowlist(self, path: str, allowlist: List[str]) -> bool:
        if not path:
            return False
        normalized = path.replace("\\", "/").lstrip("/")
        for allowed in allowlist:
            prefix = allowed.lstrip("./").rstrip("/")
            if normalized.startswith(prefix + "/") or normalized == prefix:
                return True
        return False

    def commit_version(self, new_files_written: List[str] = None) -> str:
        """Advance version after execution."""
        self.version = self._make_version()
        return self.version

    def record(self, execution_id: str, proposal_id: str, pre_ver: str,
               post_ver: str, idempotency_key: str):
        self._history.append({
            "execution_id":      execution_id,
            "proposal_id":       proposal_id,
            "pre_state_version": pre_ver,
            "post_state_version": post_ver,
            "idempotency_key":   idempotency_key,
            "timestamp":         time.time(),
        })
        self._committed_keys.add(idempotency_key)

    def already_committed(self, key: str) -> bool:
        return key in self._committed_keys


# ---------------------------------------------------------------------------
# Predicate evaluation
# ---------------------------------------------------------------------------

def _resolve(field_path: str, proposal: Proposal, state: Dict, derived: Dict) -> Any:
    if field_path.startswith("derived."):
        return derived.get(field_path[8:])
    if field_path.startswith("proposal."):
        attr = field_path[9:]
        if attr == "action_type":
            return proposal.action_type
        if attr == "state_snapshot_version":
            return proposal.state_snapshot_version
        if attr == "parameters_complete":
            return proposal.parameters_complete
        return proposal.parameters.get(attr)
    return None


def _apply(op: str, left: Any, right: Any) -> bool:
    try:
        if op == "eq":        return left == right
        if op == "neq":       return left != right
        if op == "gte":       return left is not None and left >= right
        if op == "lte":       return left is not None and left <= right
        if op == "gt":        return left is not None and left >  right
        if op == "lt":        return left is not None and left <  right
        if op == "in":        return left in (right or [])
        if op == "not_in":    return left not in (right or [])
        if op == "exists":    return left is not None
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
    """Return (classification, failed_constraints)."""
    failures: List[Constraint] = []
    for c in constraints:
        left = _resolve(c.field, proposal, state, derived)
        if not _apply(c.operator, left, c.value):
            failures.append(c)

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
# Deterministic Executor
# ---------------------------------------------------------------------------

class DeterministicExecutor:
    """
    Executes ONLY what the approved contract specifies.
    No inference. No helpfulness. No optimization.
    Maps action_type to a closed set of real operations.
    """

    def __init__(self, workspace_root: str, cfg: Dict):
        self._root = Path(workspace_root).resolve()
        self._cfg  = cfg

    def execute(self, proposal: Proposal) -> Dict[str, Any]:
        action = proposal.action_type
        params = proposal.parameters

        if action == "file_write":
            return self._file_write(params)
        if action == "file_read":
            return self._file_read(params)
        if action == "file_list":
            return self._file_list(params)
        if action == "file_delete":
            return self._file_delete(params)
        if action == "shell_run":
            return self._shell_run(params)

        return {"ok": False, "error": f"Unknown action: {action}"}

    def _resolve_path(self, path: str) -> Path:
        """Resolve a relative path within the workspace root."""
        p = (self._root / path.lstrip("/")).resolve()
        # safety: ensure it stays inside root
        p.relative_to(self._root)
        return p

    def _file_write(self, params: Dict) -> Dict:
        try:
            p = self._resolve_path(params["path"])
            p.parent.mkdir(parents=True, exist_ok=True)
            content = params.get("content", "")
            p.write_text(content, encoding="utf-8")
            return {
                "ok":      True,
                "path":    str(p.relative_to(self._root)),
                "size":    len(content.encode()),
                "hash":    hashlib.sha256(content.encode()).hexdigest(),
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _file_read(self, params: Dict) -> Dict:
        try:
            p = self._resolve_path(params["path"])
            content = p.read_text(encoding="utf-8")
            return {"ok": True, "path": params["path"], "content": content}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _file_list(self, params: Dict) -> Dict:
        try:
            p = self._resolve_path(params.get("path", "."))
            entries = []
            for item in sorted(p.iterdir()):
                rel = str(item.relative_to(self._root))
                entries.append({"name": item.name, "type": "dir" if item.is_dir() else "file",
                                 "path": rel})
            return {"ok": True, "entries": entries}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _file_delete(self, params: Dict) -> Dict:
        try:
            p = self._resolve_path(params["path"])
            p.unlink()
            return {"ok": True, "path": params["path"]}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def _shell_run(self, params: Dict) -> Dict:
        cmd     = params.get("command", "")
        args    = params.get("args", [])
        timeout = min(
            int(params.get("timeout", 10)),
            self._cfg.get("max_command_timeout_seconds", 30)
        )
        try:
            result = subprocess.run(
                [cmd] + [str(a) for a in args],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self._root),
            )
            return {
                "ok":       result.returncode == 0,
                "exit_code": result.returncode,
                "stdout":    result.stdout,
                "stderr":    result.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "timeout"}
        except Exception as e:
            return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify(
    proposal:       Proposal,
    expected_state: Dict,
    actual_state:   Dict,
    exec_result:    Dict,
) -> Tuple[bool, str]:
    """
    Check that actual state matches expected state for the fields the proposal touched.
    For shell ops: check exit_code == 0 (we can't predict stdout).
    Returns (passed, reason).
    """
    action = proposal.action_type

    if action == "file_write":
        path = proposal.parameters.get("path", "")
        expected_hash = expected_state["files"].get(path)
        actual_hash   = actual_state["files"].get(path)
        if expected_hash != actual_hash:
            return False, f"file hash mismatch: expected {expected_hash}, got {actual_hash}"
        return True, "ok"

    if action == "file_delete":
        path = proposal.parameters.get("path", "")
        if path in actual_state["files"]:
            return False, f"file still exists after delete: {path}"
        return True, "ok"

    if action in ("file_read", "file_list"):
        return exec_result.get("ok", False), exec_result.get("error", "ok")

    if action == "shell_run":
        if not exec_result.get("ok"):
            return False, f"command failed: {exec_result.get('error', exec_result.get('stderr', ''))}"
        return True, "ok"

    return True, "ok"


# ---------------------------------------------------------------------------
# Proposal formation — LLM sits HERE and only here
# ---------------------------------------------------------------------------

def parse_with_llm(raw_input: str, cfg: Dict) -> Optional[Dict]:
    """
    Call Ollama to extract a structured proposal from natural language.
    Returns None if Ollama is unavailable or output is unparseable.
    The model fills action_type and parameters only.
    It cannot select constraints. It cannot choose the executor.
    """
    try:
        import urllib.request, urllib.error
        system_prompt = """You extract structured commands from natural language.

Return ONLY valid JSON with this exact structure (no explanation, no markdown):
{
  "action_type": "file_read|file_write|file_list|file_delete|shell_run",
  "parameters": {
    "path": "relative path if file op",
    "content": "file content if writing",
    "command": "command name if shell op",
    "args": ["arg1", "arg2"]
  },
  "parameters_complete": true
}

If the input is unclear or missing required info, set parameters_complete to false.
Only use action types from the exact list above."""

        body = json.dumps({
            "model":  cfg.get("ollama_model", "llama3.2"),
            "prompt": f"{system_prompt}\n\nInput: {raw_input}",
            "stream": False,
        }).encode()

        req = urllib.request.Request(
            f"{cfg.get('ollama_url', 'http://127.0.0.1:11434')}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            text = data.get("response", "").strip()
            # extract JSON from response
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                return json.loads(match.group())
    except Exception:
        pass
    return None


def build_proposal(raw_input: str, state_version: str, cfg: Dict) -> Proposal:
    """
    Build a Proposal from raw input.
    First try LLM. If unavailable, try JSON parse. If neither, return incomplete proposal.
    """
    parsed = parse_with_llm(raw_input, cfg)

    # fallback: try parsing as raw JSON
    if not parsed:
        try:
            parsed = json.loads(raw_input)
        except Exception:
            pass

    if parsed and "action_type" in parsed:
        return Proposal(
            proposal_id=str(uuid.uuid4()),
            created_at=time.time(),
            source_channel="cli",
            raw_input=raw_input,
            action_type=parsed.get("action_type", "unknown"),
            parameters=parsed.get("parameters", {}),
            state_snapshot_version=state_version,
            parameters_complete=parsed.get("parameters_complete", True),
        )

    # cannot parse — return incomplete
    return Proposal(
        proposal_id=str(uuid.uuid4()),
        created_at=time.time(),
        source_channel="cli",
        raw_input=raw_input,
        action_type="unknown",
        parameters={},
        state_snapshot_version=state_version,
        parameters_complete=False,
    )


# ---------------------------------------------------------------------------
# Main governance loop
# ---------------------------------------------------------------------------

def run_cycle(
    raw_input:  str,
    registry:   ConstraintRegistry,
    state_mgr:  StateManager,
    executor:   DeterministicExecutor,
    cfg:        Dict,
) -> Dict[str, Any]:

    # 1. Proposal formation (LLM or JSON parse)
    pre_version, pre_state = state_mgr.snapshot()
    proposal = build_proposal(raw_input, pre_version, cfg)

    # 2. Derive expected state + derived fields (pure, no side effects)
    expected_state, derived = state_mgr.derive(proposal, pre_state, cfg)

    # 3. Select applicable constraints from registry (deterministic)
    constraints = registry.match(proposal)

    # 4. Evaluate constraints
    decision, failures = check_constraints(constraints, proposal, pre_state, derived)

    if decision != APPROVED:
        reasons = [f"{f.constraint_id}: {f.description}" for f in failures]
        return {
            "status":   decision,
            "reasons":  reasons,
            "proposal": proposal.proposal_id,
        }

    # 5. Execute (deterministic only — no LLM, no inference)
    idempotency_key = hashlib.sha256(
        f"{proposal.action_type}:{json.dumps(proposal.parameters, sort_keys=True)}".encode()
    ).hexdigest()

    if state_mgr.already_committed(idempotency_key):
        return {"status": "IDEMPOTENT", "proposal": proposal.proposal_id}

    # verify state hasn't changed since proposal was formed
    current_version, _ = state_mgr.snapshot()
    if current_version != pre_version:
        return {"status": STALE, "proposal": proposal.proposal_id}

    exec_result = executor.execute(proposal)

    # 6. Verify: actual state == expected state
    post_version, actual_state = state_mgr.snapshot()
    passed, reason = verify(proposal, expected_state, actual_state, exec_result)

    if not passed:
        return {
            "status":  ROLLBACK,
            "reason":  reason,
            "proposal": proposal.proposal_id,
        }

    # 7. Record and advance version
    new_version = state_mgr.commit_version()
    state_mgr.record(
        execution_id=str(uuid.uuid4()),
        proposal_id=proposal.proposal_id,
        pre_ver=pre_version,
        post_ver=new_version,
        idempotency_key=idempotency_key,
    )

    return {
        "status":   "COMMITTED",
        "proposal": proposal.proposal_id,
        "result":   exec_result,
        "version":  new_version,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Bell Governance Protocol")
    parser.add_argument("--workspace", default="./workspace",
                        help="Root directory for file operations")
    parser.add_argument("--config", default=None, help="Path to config.json")
    args = parser.parse_args()

    cfg      = load_config(args.config)
    raw_constraints = load_constraints()
    registry = ConstraintRegistry.build(raw_constraints, cfg)
    state    = StateManager(args.workspace, cfg)
    executor = DeterministicExecutor(args.workspace, cfg)

    # ensure workspace exists
    Path(args.workspace).mkdir(parents=True, exist_ok=True)

    print("Bell Governance Protocol")
    print(f"  Workspace:   {Path(args.workspace).resolve()}")
    print(f"  Constraints: {len(raw_constraints)} loaded")
    print(f"  Allowed ops: file_read, file_write, file_list, file_delete, shell_run")
    print(f"  LLM:         {'Ollama at ' + cfg.get('ollama_url') if cfg.get('ollama_url') else 'none (JSON mode)'}")
    print()
    print("Input: natural language (if Ollama running) or raw JSON proposal.")
    print("Type 'exit' to quit.\n")

    while True:
        try:
            raw = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not raw or raw.lower() in ("exit", "quit"):
            break

        result = run_cycle(raw, registry, state, executor, cfg)
        status = result["status"]

        if status == "COMMITTED":
            r = result.get("result", {})
            print(f"  ✓ COMMITTED  [{result['version'][:8]}]")
            if "content" in r:
                print(f"    {r['content'][:200]}")
            elif "entries" in r:
                for e in r["entries"]:
                    print(f"    {'d' if e['type'] == 'dir' else 'f'}  {e['path']}")
            elif "stdout" in r and r["stdout"].strip():
                print(f"    {r['stdout'].strip()[:300]}")
        elif status == "BLOCKED":
            print(f"  ✗ BLOCKED")
            for reason in result.get("reasons", []):
                print(f"    {reason}")
        elif status == "CLARIFY":
            print(f"  ? CLARIFY — missing information:")
            for reason in result.get("reasons", []):
                print(f"    {reason}")
        else:
            print(f"  ! {status}: {result.get('reason', result.get('reasons', ''))}")
        print()


if __name__ == "__main__":
    main()
