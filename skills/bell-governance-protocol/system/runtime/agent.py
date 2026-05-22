"""
BRCM Agent Loop — Governed generative agent

Outer loop that ties all layers together:

  user intent
    → Clarient.evaluate()          [CLEAR / CLARIFY / BLOCK]
    → LLM / JSON: build_plan()     [decompose intent into ordered steps]
    → for each step:
        run_cycle(step, ...)        [BGP: proposal → constraints → execute]
        if COMMITTED: canonical.record_receipt()
        if BLOCKED/CLARIFY: surface to user, stop build
    → output verified build result

The agent can build:
  - Software systems (file_write + shell_run + git ops)
  - New agent definitions (write capability spec → assimilation)
  - New constraint definitions (GOVERN proposals)
  - Composed multi-step workflows (each step individually governed)

The LLM sits only in build_plan(). Everything below it is deterministic.
"""

import hashlib
import json
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional

# BGP engine (existing)
sys.path.insert(0, str(Path(__file__).parent.parent))
import bgp as bgp_module

try:
    from ..core.clarient import evaluate as clarient_evaluate, CLEAR, CLARIFY, BLOCK, CONFIRM
    from ..core.canonical import CanonicalState
except ImportError:
    from core.clarient import evaluate as clarient_evaluate, CLEAR, CLARIFY, BLOCK, CONFIRM
    from core.canonical import CanonicalState


# ---------------------------------------------------------------------------
# Agent configuration
# ---------------------------------------------------------------------------

DEFAULT_AGENT_CONFIG = {
    "workspace":               "./workspace",
    "canonical_db":            "./canonical.db",
    "ollama_url":              "http://127.0.0.1:11434",
    "ollama_model":            "llama3.2",
    "max_steps":               20,
    "stop_on_block":           True,
    "stop_on_clarify":         True,
}

PLAN_SYSTEM_PROMPT = """You are a governed build planner. Your ONLY output is a JSON array of steps.

Each step is:
{"action_type": "<type>", "parameters": {...}, "parameters_complete": true}

Supported action types:
file_read, file_write, file_list, file_delete, file_copy, file_move, file_search,
dir_create, dir_delete, json_read, json_write, csv_read, csv_write,
shell_run, http_get, http_post,
git_status, git_diff, git_log,
math_eval, hash_compute, template_render, env_read

Rules:
- Output ONLY the JSON array. No prose, no explanation.
- Every step must have parameters_complete: true.
- shell_run steps require: {"command": "<cmd>", "args": []}
- file_write requires: {"path": "<path>", "content": "<content>"}
- Do not invent action types not in the list above.
- Maximum 20 steps per plan.
"""


# ---------------------------------------------------------------------------
# LLM plan builder
# ---------------------------------------------------------------------------

def _call_ollama(prompt: str, system: str, url: str, model: str) -> str:
    payload = json.dumps({
        "model":  model,
        "prompt": prompt,
        "system": system,
        "stream": False,
    }).encode()
    req = urllib.request.Request(
        f"{url}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())["response"]
    except Exception as e:
        return f"ERROR:{e}"


def build_plan(intent: str, cfg: Dict) -> List[Dict]:
    """
    Decompose intent into an ordered list of BGP-compatible steps.
    Uses LLM if available; accepts raw JSON array input otherwise.
    """
    # If intent is already a JSON array, parse it directly
    stripped = intent.strip()
    if stripped.startswith("["):
        try:
            steps = json.loads(stripped)
            if isinstance(steps, list):
                return steps
        except json.JSONDecodeError:
            pass

    # If it's a single JSON object, wrap it
    if stripped.startswith("{"):
        try:
            step = json.loads(stripped)
            if isinstance(step, dict):
                return [step]
        except json.JSONDecodeError:
            pass

    # Try LLM
    ollama_url   = cfg.get("ollama_url",   DEFAULT_AGENT_CONFIG["ollama_url"])
    ollama_model = cfg.get("ollama_model", DEFAULT_AGENT_CONFIG["ollama_model"])

    response = _call_ollama(
        prompt=f"Build plan for: {intent}",
        system=PLAN_SYSTEM_PROMPT,
        url=ollama_url,
        model=ollama_model,
    )

    if response.startswith("ERROR:"):
        return []

    # Extract JSON from response
    for start_char in ("[", "{"):
        idx = response.find(start_char)
        if idx != -1:
            fragment = response[idx:]
            end_char = "]" if start_char == "[" else "}"
            end_idx  = fragment.rfind(end_char)
            if end_idx != -1:
                fragment = fragment[:end_idx + 1]
                try:
                    parsed = json.loads(fragment)
                    if isinstance(parsed, list):
                        return parsed
                    if isinstance(parsed, dict):
                        return [parsed]
                except json.JSONDecodeError:
                    pass

    return []


# ---------------------------------------------------------------------------
# BRCM Agent
# ---------------------------------------------------------------------------

class BRCMAgent:
    """
    Bell Recursive Constitutional Metabolism — governed generative agent.

    Every build step is a BGP proposal: governed, verified, and canonically recorded
    if committed. The agent cannot bypass any layer.
    """

    def __init__(self, config: Dict = None):
        self.cfg       = {**DEFAULT_AGENT_CONFIG, **(config or {})}
        self.canonical = CanonicalState(db_path=self.cfg["canonical_db"])

        # Boot BGP subsystems
        bgp_cfg          = bgp_module.load_config(self.cfg.get("bgp_config"))
        constraint_defs  = bgp_module.load_constraints()
        workspace        = self.cfg["workspace"]
        self.reg         = bgp_module.ConstraintRegistry.build(constraint_defs, bgp_cfg)
        self.state       = bgp_module.StateManager(workspace, bgp_cfg)
        self.exec        = bgp_module.DeterministicExecutor(workspace, bgp_cfg)
        self._bgp_cfg    = bgp_cfg

    def run(self, intent: str) -> Dict:
        """
        Run the full BRCM agent loop for a single intent.
        Returns the build result.
        """
        # 1. Clarient — intent stabilization
        clarient_result = clarient_evaluate(intent)
        clarient_status = clarient_result.get("status")
        clarient_out    = clarient_result.get("output", {})

        if clarient_status == BLOCK:
            return {
                "status":  "BLOCKED",
                "layer":   "clarient",
                "reason":  clarient_out.get("reason", "Forbidden intent"),
                "steps":   [],
            }

        if clarient_status in (CLARIFY, CONFIRM):
            return {
                "status":   "CLARIFY",
                "layer":    "clarient",
                "question": clarient_out.get("question", "Please clarify your intent."),
                "steps":    [],
            }

        # 2. Build plan — LLM decomposes intent into steps
        steps = build_plan(intent, self.cfg)

        if not steps:
            return {
                "status":  "CLARIFY",
                "layer":   "plan",
                "question": "I couldn't form a build plan. Try providing a JSON step directly.",
                "steps":   [],
            }

        if len(steps) > self.cfg["max_steps"]:
            steps = steps[:self.cfg["max_steps"]]

        # 3. Execute each step through BGP
        build_log    = []
        committed    = []
        blocked      = []
        max_steps    = self.cfg["max_steps"]

        for i, step in enumerate(steps[:max_steps]):
            action_type = step.get("action_type", "")
            parameters  = step.get("parameters", {})

            # Capture pre-version before run_cycle mutates state
            pre_version, _ = self.state.snapshot()

            # run_cycle expects a raw string (JSON or natural language)
            raw_step    = json.dumps(step)
            step_result = bgp_module.run_cycle(
                raw=raw_step,
                registry=self.reg,
                state=self.state,
                executor=self.exec,
                cfg=self._bgp_cfg,
            )

            build_log.append({
                "step":        i + 1,
                "action_type": action_type,
                "status":      step_result.get("status"),
                "result":      step_result,
            })

            status = step_result.get("status")

            if status == "COMMITTED":
                # Compute idempotency key (same formula as bgp.run_cycle)
                ikey = hashlib.sha256(
                    f"{action_type}:{json.dumps(parameters, sort_keys=True)}".encode()
                ).hexdigest()

                receipt = self.canonical.record_receipt(
                    bgp_result=step_result,
                    action_type=action_type,
                    parameters=parameters,
                    idempotency_key=ikey,
                    pre_version=pre_version,
                )
                committed.append({
                    "step":    i + 1,
                    "action":  action_type,
                    "receipt": receipt,
                })

            elif status == "BLOCKED":
                blocked.append({
                    "step":   i + 1,
                    "action": action_type,
                    "reason": step_result.get("reason", ""),
                })
                if self.cfg["stop_on_block"]:
                    return {
                        "status":    "BLOCKED",
                        "layer":     "bgp",
                        "blocked_at": i + 1,
                        "reason":    step_result.get("reason", ""),
                        "committed": committed,
                        "blocked":   blocked,
                        "build_log": build_log,
                    }

            elif status in ("CLARIFY", "DRIFT"):
                if self.cfg["stop_on_clarify"]:
                    return {
                        "status":    status,
                        "layer":     "bgp",
                        "stopped_at": i + 1,
                        "output":    step_result.get("output"),
                        "committed": committed,
                        "build_log": build_log,
                    }

        return {
            "status":    "COMPLETE",
            "steps_run": len(build_log),
            "committed": committed,
            "blocked":   blocked,
            "build_log": build_log,
            "canonical": self.canonical.stats(),
        }

    def status(self) -> Dict:
        return {
            "canonical": self.canonical.stats(),
            "state": {
                "version":   self.state.version,
                "committed": len(self.state._committed_keys),
            },
        }
