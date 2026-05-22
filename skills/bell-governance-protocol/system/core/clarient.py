"""
Clarient Protocol — Intent Stabilization Membrane

Runs BEFORE proposal formation. Prevents premature collapse of
unclear, contradictory, or structurally invalid intent.

If Clarient returns CLARIFY or BLOCK:
  - no proposal is formed
  - no traversal record is created
  - no canonical mutation occurs
  - no downstream process treats the request as stabilized

Clarient does not use LLM inference. It applies deterministic rules.
It is the membrane between raw language and governed process.
"""

import re
from typing import Any, Dict, List, Optional

from .source_loop import SourceLoop


# ---------------------------------------------------------------------------
# Clarient outcomes
# ---------------------------------------------------------------------------

CLEAR    = "CLEAR"       # intent is stable; proceed to proposal formation
CLARIFY  = "CLARIFY"     # intent is ambiguous; return question to user
BLOCK    = "BLOCK"       # intent is forbidden or structurally invalid
CONFIRM  = "CONFIRM"     # intent is coherent but high-risk; require confirmation
REDIRECT = "REDIRECT"    # intent belongs to a different operational mode


# ---------------------------------------------------------------------------
# Forbidden patterns — BLOCK without LLM
# ---------------------------------------------------------------------------

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

# Patterns that suggest contradictory frames
CONTRADICTION_PATTERNS = [
    (re.compile(r'\bbuild\b.*\bdelete\b',       re.I),  "Request contains conflicting build/delete intent"),
    (re.compile(r'\bcreate\b.*\bdestroy\b',     re.I),  "Request contains conflicting create/destroy intent"),
    (re.compile(r'\badd\b.*\bremove\b.*\bsame\b', re.I), "Request may contain contradictory add/remove"),
]

# Minimum signal — requests this sparse cannot form a valid proposal
MIN_TOKENS = 2

# Action type keywords — used to infer if an action type is identifiable
ACTION_KEYWORDS = {
    "file_write":     ["write", "create", "save", "generate", "produce", "make a file",
                       "new file", "store"],
    "file_read":      ["read", "show", "display", "cat", "open", "get contents"],
    "file_list":      ["list", "ls", "what files", "directory contents"],
    "file_delete":    ["delete file", "remove file"],
    "file_copy":      ["copy"],
    "file_move":      ["move", "rename"],
    "file_search":    ["search", "find", "grep", "look for"],
    "dir_create":     ["mkdir", "new folder", "create directory", "make dir"],
    "dir_delete":     ["rmdir", "delete folder", "remove directory"],
    "shell_run":      ["run", "execute", "bash", "shell", "command", "python",
                       "script"],
    "json_write":     ["write json", "save json", "json file"],
    "json_read":      ["read json", "load json", "parse json"],
    "csv_write":      ["write csv", "save csv"],
    "csv_read":       ["read csv", "load csv"],
    "http_get":       ["get request", "fetch", "http get", "curl"],
    "http_post":      ["post request", "http post", "submit"],
    "git_status":     ["git status", "what changed"],
    "git_diff":       ["git diff", "show diff", "what's different"],
    "git_log":        ["git log", "commit history"],
    "math_eval":      ["calculate", "compute", "math", "evaluate", "what is",
                       "+", "-", "*", "/", "**"],
    "hash_compute":   ["hash", "sha", "md5", "checksum"],
    "template_render": ["render", "template", "fill in"],
    "env_read":       ["environment variable", "env var", "getenv"],
}


def _infer_action_type(text: str) -> Optional[str]:
    lower = text.lower()
    for action, keywords in ACTION_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return action
    return None


# ---------------------------------------------------------------------------
# Clarient subsystem
# ---------------------------------------------------------------------------

class Clarient(SourceLoop):
    """
    Intent stabilization membrane.
    Runs before proposal formation in the agent loop.
    Inherits SourceLoop — the protocol itself runs N→B→F→C→R→I→D→N.
    """

    def read_body(self, input_data: Any) -> Dict:
        """B: Read the raw intent and context."""
        if isinstance(input_data, str):
            text    = input_data.strip()
            context = {}
        elif isinstance(input_data, dict):
            text    = input_data.get("text", "").strip()
            context = input_data.get("context", {})
        else:
            text    = str(input_data).strip()
            context = {}

        return {
            "text":       text,
            "tokens":     text.split(),
            "lower":      text.lower(),
            "context":    context,
            "char_count": len(text),
        }

    def apply_frame(self, body: Dict) -> Dict:
        """F: Apply intent-stabilization frame."""
        text   = body["text"]
        lower  = body["lower"]
        tokens = body["tokens"]

        frame = {
            "body":              body,
            "is_empty":          len(text) == 0,
            "too_sparse":        len(tokens) < MIN_TOKENS,
            "blocked_pattern":   None,
            "contradiction":     None,
            "inferred_action":   _infer_action_type(text),
            "has_json":          text.strip().startswith("{"),
        }

        # Check forbidden patterns
        for pattern, reason in BLOCKED_PATTERNS:
            if pattern.search(text):
                frame["blocked_pattern"] = reason
                break

        # Check contradictions (only if not already blocked)
        if not frame["blocked_pattern"]:
            for pattern, reason in CONTRADICTION_PATTERNS:
                if pattern.search(text):
                    frame["contradiction"] = reason
                    break

        return frame

    def collapse(self, framed: Dict) -> str:
        """C: Collapse to CLEAR / CLARIFY / BLOCK / CONFIRM."""
        if framed["blocked_pattern"]:
            return BLOCK

        if framed["is_empty"] or framed["too_sparse"]:
            return CLARIFY

        if framed["contradiction"]:
            return CONFIRM

        # If it's raw JSON, action_type is explicit — always clear
        if framed["has_json"]:
            return CLEAR

        # Natural language: must be able to infer action type
        if framed["inferred_action"] is None:
            return CLARIFY

        return CLEAR

    def return_output(self, decision: str, framed: Dict) -> Dict:
        """R: Produce the stabilized result."""
        output: Dict[str, Any] = {
            "decision":       decision,
            "inferred_action": framed.get("inferred_action"),
        }

        if decision == BLOCK:
            output["reason"] = framed.get("blocked_pattern", "Forbidden intent pattern")

        elif decision == CLARIFY:
            if framed["is_empty"]:
                output["question"] = "What would you like to do?"
            elif framed["too_sparse"]:
                output["question"] = f"Can you be more specific? (e.g., write a file, run a command, search for something)"
            else:
                output["question"] = (
                    f"I can't determine what kind of action this is. "
                    f"Try: write/read/list/search/run/calculate/hash/render"
                )

        elif decision == CONFIRM:
            output["question"] = (
                f"This request contains potentially conflicting intent: "
                f"{framed.get('contradiction')}. Confirm to proceed."
            )

        elif decision == CLEAR:
            output["inferred_action"] = framed.get("inferred_action")

        return output

    def verify_invariant(self, output: Any) -> bool:
        """I: Clarient must always produce a decision."""
        return (
            isinstance(output, dict)
            and "decision" in output
            and output["decision"] in (CLEAR, CLARIFY, BLOCK, CONFIRM, REDIRECT)
        )

    def detect_drift(self, output: Any) -> Optional[str]:
        """D: Clarient drift = decision is missing or unknown."""
        if not isinstance(output, dict):
            return "output_not_dict"
        if output.get("decision") not in (CLEAR, CLARIFY, BLOCK, CONFIRM, REDIRECT):
            return "unknown_decision"
        return None


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

_clarient = Clarient()


def evaluate(intent: str, context: dict = None) -> Dict:
    """
    Evaluate intent stability. Returns the full SourceLoop result dict.
    result["status"] is one of: CLEAR, CLARIFY, BLOCK, CONFIRM, REDIRECT, DRIFT
    result["output"]["question"] is set when clarification is needed.
    result["output"]["reason"] is set when blocked.
    """
    return _clarient.run({"text": intent, "context": context or {}})
