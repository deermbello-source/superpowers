"""
Clarient — Intent Stabilization Membrane

Runs before proposal formation. Prevents premature collapse of unclear,
contradictory, or structurally invalid intent.

If the outcome is CLARIFY or BLOCK:
  - no proposal is formed
  - no traversal record is created
  - no canonical mutation occurs

Clarient is deterministic. No LLM inference.
"""

import re
from typing import Any, Dict, List, Optional

from .source_loop import SourceLoop


CLEAR    = "CLEAR"
CLARIFY  = "CLARIFY"
BLOCK    = "BLOCK"
CONFIRM  = "CONFIRM"
REDIRECT = "REDIRECT"


BLOCKED_PATTERNS = [
    (re.compile(r'\bbypass\b.*\bgovernance\b', re.I),   "Governance bypass is not permitted"),
    (re.compile(r'\boverride\b.*\blaw\b',       re.I),   "Law override is not permitted"),
    (re.compile(r'\bdisable\b.*\bconstraint\b', re.I),   "Constraint disable is not permitted"),
    (re.compile(r'\bdelete\b.*\bcanonical\b',   re.I),   "Canonical deletion is not permitted"),
    (re.compile(r'\bgrant\b.*\bauthority\b',    re.I),   "Authority self-grant is not permitted"),
    (re.compile(r'\bself.authoriz',             re.I),   "Self-authorization is not permitted"),
    (re.compile(r'rm\s+-rf\s+/',               re.I),   "Destructive root operation is not permitted"),
    (re.compile(r'\bformat\b.*\bdisk\b',        re.I),   "Disk format is not permitted"),
]

CONTRADICTION_PATTERNS = [
    (re.compile(r'\bbuild\b.*\bdelete\b',         re.I), "Request contains conflicting build/delete intent"),
    (re.compile(r'\bcreate\b.*\bdestroy\b',        re.I), "Request contains conflicting create/destroy intent"),
    (re.compile(r'\badd\b.*\bremove\b.*\bsame\b',  re.I), "Request may contain contradictory add/remove"),
]

MIN_TOKENS = 2

ACTION_KEYWORDS = {
    "file_write":      ["write", "create", "save", "generate", "produce", "make a file", "new file", "store"],
    "file_read":       ["read", "show", "display", "cat", "open", "get contents"],
    "file_list":       ["list", "ls", "what files", "directory contents"],
    "file_delete":     ["delete file", "remove file"],
    "file_copy":       ["copy"],
    "file_move":       ["move", "rename"],
    "file_search":     ["search", "find", "grep", "look for"],
    "dir_create":      ["mkdir", "new folder", "create directory", "make dir"],
    "dir_delete":      ["rmdir", "delete folder", "remove directory"],
    "shell_run":       ["run", "execute", "bash", "shell", "command", "python", "script"],
    "json_write":      ["write json", "save json", "json file"],
    "json_read":       ["read json", "load json", "parse json"],
    "csv_write":       ["write csv", "save csv"],
    "csv_read":        ["read csv", "load csv"],
    "http_get":        ["get request", "fetch", "http get", "curl"],
    "http_post":       ["post request", "http post", "submit"],
    "git_status":      ["git status", "what changed"],
    "git_diff":        ["git diff", "show diff", "what's different"],
    "git_log":         ["git log", "commit history"],
    "math_eval":       ["calculate", "compute", "math", "evaluate", "what is", "+", "-", "*", "/", "**"],
    "hash_compute":    ["hash", "sha", "md5", "checksum"],
    "template_render": ["render", "template", "fill in"],
    "env_read":        ["environment variable", "env var", "getenv"],
}


def _infer_action_type(text: str) -> Optional[str]:
    lower = text.lower()
    for action, keywords in ACTION_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return action
    return None


class Clarient(SourceLoop):

    def read(self, input_data: Any) -> Dict:
        if isinstance(input_data, str):
            text, context = input_data.strip(), {}
        elif isinstance(input_data, dict):
            text    = input_data.get("text", "").strip()
            context = input_data.get("context", {})
        else:
            text, context = str(input_data).strip(), {}

        return {
            "text":    text,
            "tokens":  text.split(),
            "lower":   text.lower(),
            "context": context,
        }

    def frame(self, body: Dict) -> Dict:
        text   = body["text"]
        tokens = body["tokens"]

        blocked      = None
        contradiction = None

        for pattern, reason in BLOCKED_PATTERNS:
            if pattern.search(text):
                blocked = reason
                break

        if not blocked:
            for pattern, reason in CONTRADICTION_PATTERNS:
                if pattern.search(text):
                    contradiction = reason
                    break

        return {
            **body,
            "is_empty":       len(text) == 0,
            "too_sparse":     len(tokens) < MIN_TOKENS,
            "blocked":        blocked,
            "contradiction":  contradiction,
            "inferred_action": _infer_action_type(text),
            "is_json":        text.strip().startswith("{"),
        }

    def decide(self, framed: Dict) -> str:
        if framed["blocked"]:
            return BLOCK
        if framed["is_empty"] or framed["too_sparse"]:
            return CLARIFY
        if framed["contradiction"]:
            return CONFIRM
        if framed["is_json"]:
            return CLEAR
        if framed["inferred_action"] is None:
            return CLARIFY
        return CLEAR

    def emit(self, decision: str, framed: Dict) -> Dict:
        out: Dict[str, Any] = {
            "decision":        decision,
            "inferred_action": framed.get("inferred_action"),
        }

        if decision == BLOCK:
            out["reason"] = framed.get("blocked", "Forbidden intent pattern")
        elif decision in (CLARIFY, CONFIRM):
            if framed["is_empty"]:
                out["question"] = "What would you like to do?"
            elif framed["too_sparse"]:
                out["question"] = "Can you be more specific? (e.g., write a file, run a command, search for something)"
            elif framed["contradiction"]:
                out["question"] = (
                    f"This request contains potentially conflicting intent: "
                    f"{framed['contradiction']}. Confirm to proceed."
                )
            else:
                out["question"] = (
                    "I can't determine what kind of action this is. "
                    "Try: write/read/list/search/run/calculate/hash/render"
                )

        return out

    def invariant(self, output: Any) -> bool:
        return (
            isinstance(output, dict)
            and "decision" in output
            and output["decision"] in (CLEAR, CLARIFY, BLOCK, CONFIRM, REDIRECT)
        )

    def drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict):
            return "output_not_dict"
        if output.get("decision") not in (CLEAR, CLARIFY, BLOCK, CONFIRM, REDIRECT):
            return "unknown_decision"
        return None


_clarient = Clarient()


def evaluate(intent: str, context: dict = None) -> Dict:
    """
    Evaluate intent stability. Returns the full result dict.
    result["status"] is one of: CLEAR, CLARIFY, BLOCK, CONFIRM, REDIRECT, DRIFT
    result["output"]["question"] is set when clarification is needed.
    result["output"]["reason"] is set when blocked.
    """
    return _clarient.run({"text": intent, "context": context or {}})
