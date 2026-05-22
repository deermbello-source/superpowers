"""
Assimilation Topology — Governed capability intake pipeline

External capabilities (tools, repos, models) cannot enter the system
by being claimed. They must traverse 8 stages, each governed by SourceLoop.

Stages:
  1. Discover  — record existence, possible utility, possible threat
  2. Classify  — dependency geometry, authority surface, execution behavior
  3. Constrain — define sandbox boundaries, allowed operations
  4. Rename    — assign governed identity (external name archived)
  5. Wrap      — generate BGP-compatible capability definition
  6. Admit     — run through BGP: APPROVED / BLOCKED / CLARIFY
  7. Verify    — post-admission: does behavior match classification?
  8. Compose   — add to registry as new action_type

A capability that exits with stage < 8 is NOT operational.
Only Compose transitions a capability from "known" to "admitted".
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from ..core.source_loop import SourceLoop
except ImportError:
    from core.source_loop import SourceLoop


# ---------------------------------------------------------------------------
# Stage outcome constants
# ---------------------------------------------------------------------------

STAGE_PASS    = "PASS"
STAGE_BLOCK   = "BLOCK"
STAGE_CLARIFY = "CLARIFY"
STAGE_DEFER   = "DEFER"


# ---------------------------------------------------------------------------
# Known threat signals
# ---------------------------------------------------------------------------

THREAT_PATTERNS = [
    ("network_exfil",  ["telemetry", "beacon", "phone home", "upload", "post credentials"]),
    ("privilege_esc",  ["sudo", "setuid", "chmod 777", "escalate", "root access"]),
    ("supply_chain",   ["postinstall", "preinstall", "install hook", "setup.py exec"]),
    ("crypto_mining",  ["mine", "hash rate", "gpu util", "worker thread", "pool"]),
    ("lateral_move",   ["scan network", "enumerate hosts", "ping sweep", "nmap"]),
]


def _detect_threats(text: str) -> List[str]:
    lower = text.lower()
    found = []
    for name, signals in THREAT_PATTERNS:
        if any(s in lower for s in signals):
            found.append(name)
    return found


# ---------------------------------------------------------------------------
# Dependency geometry
# ---------------------------------------------------------------------------

def _classify_deps(manifest: Dict) -> Dict:
    """Extract dependency surface from a capability manifest."""
    deps = manifest.get("dependencies", [])
    return {
        "count":        len(deps),
        "has_network":  any("http" in d or "request" in d for d in deps),
        "has_crypto":   any("crypt" in d or "ssl" in d for d in deps),
        "has_exec":     any("subprocess" in d or "os" in d or "exec" in d for d in deps),
        "names":        deps,
    }


# ---------------------------------------------------------------------------
# Stage implementations — each inherits SourceLoop
# ---------------------------------------------------------------------------

class DiscoverStage(SourceLoop):
    """Stage 1: Record existence, utility, and threat surface."""

    def read_body(self, input_data: Any) -> Dict:
        manifest = input_data if isinstance(input_data, dict) else {"raw": str(input_data)}
        return {
            "manifest":    manifest,
            "name":        manifest.get("name", "unknown"),
            "source":      manifest.get("source", ""),
            "description": manifest.get("description", ""),
            "raw_text":    json.dumps(manifest),
        }

    def apply_frame(self, body: Dict) -> Dict:
        threats = _detect_threats(body["raw_text"])
        return {
            **body,
            "threats":        threats,
            "has_threats":    len(threats) > 0,
            "has_name":       body["name"] != "unknown",
            "has_description": len(body["description"]) > 0,
        }

    def collapse(self, framed: Dict) -> str:
        if framed["has_threats"]:
            return STAGE_BLOCK
        if not framed["has_name"]:
            return STAGE_CLARIFY
        return STAGE_PASS

    def return_output(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":       "discover",
            "decision":    decision,
            "name":        framed["name"],
            "threats":     framed["threats"],
            "source":      framed["source"],
            "description": framed["description"],
            "timestamp":   time.time(),
        }

    def verify_invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "stage" in output and "decision" in output

    def detect_drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict):
            return "output_not_dict"
        if output.get("stage") != "discover":
            return "wrong_stage"
        return None


class ClassifyStage(SourceLoop):
    """Stage 2: Classify dependency geometry, authority surface, execution behavior."""

    def read_body(self, input_data: Any) -> Dict:
        return {"discover": input_data, "manifest": input_data.get("manifest", {})}

    def apply_frame(self, body: Dict) -> Dict:
        manifest = body["manifest"]
        deps     = _classify_deps(manifest)
        exec_ops = manifest.get("execution_ops", [])
        return {
            **body,
            "deps":          deps,
            "exec_ops":      exec_ops,
            "writes_files":  "file_write" in exec_ops or "file_delete" in exec_ops,
            "runs_shell":    "shell_run" in exec_ops or deps["has_exec"],
            "uses_network":  "http_get" in exec_ops or "http_post" in exec_ops or deps["has_network"],
            "authority_surface": (
                "high"   if ("shell_run" in exec_ops and "http_post" in exec_ops)
                else "medium" if ("shell_run" in exec_ops or deps["has_exec"])
                else "low"
            ),
        }

    def collapse(self, framed: Dict) -> str:
        if framed["authority_surface"] == "high":
            return STAGE_CLARIFY
        return STAGE_PASS

    def return_output(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":            "classify",
            "decision":         decision,
            "deps":             framed["deps"],
            "exec_ops":         framed["exec_ops"],
            "writes_files":     framed["writes_files"],
            "runs_shell":       framed["runs_shell"],
            "uses_network":     framed["uses_network"],
            "authority_surface": framed["authority_surface"],
        }

    def verify_invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "authority_surface" in output

    def detect_drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict):
            return "output_not_dict"
        if output.get("authority_surface") not in ("low", "medium", "high"):
            return "unknown_authority_surface"
        return None


class ConstrainStage(SourceLoop):
    """Stage 3: Define sandbox boundaries and allowed operations."""

    def read_body(self, input_data: Any) -> Dict:
        return {
            "classify": input_data,
            "exec_ops": input_data.get("exec_ops", []),
            "authority_surface": input_data.get("authority_surface", "low"),
        }

    def apply_frame(self, body: Dict) -> Dict:
        surface = body["authority_surface"]
        ops     = body["exec_ops"]

        # Derive sandbox limits by authority surface
        if surface == "low":
            allowed_ops  = ops
            read_scope   = "workspace"
            write_scope  = "workspace"
            shell_scope  = []
            network_scope = []
        elif surface == "medium":
            allowed_ops  = [op for op in ops if op != "shell_run"]
            read_scope   = "workspace"
            write_scope  = "workspace/output"
            shell_scope  = []
            network_scope = []
        else:
            allowed_ops  = [op for op in ops if op in ("file_read", "file_list", "math_eval")]
            read_scope   = "workspace"
            write_scope  = ""
            shell_scope  = []
            network_scope = []

        return {
            **body,
            "allowed_ops":  allowed_ops,
            "read_scope":   read_scope,
            "write_scope":  write_scope,
            "shell_scope":  shell_scope,
            "network_scope": network_scope,
            "has_ops":      len(allowed_ops) > 0,
        }

    def collapse(self, framed: Dict) -> str:
        if not framed["has_ops"]:
            return STAGE_CLARIFY
        return STAGE_PASS

    def return_output(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":         "constrain",
            "decision":      decision,
            "allowed_ops":   framed["allowed_ops"],
            "read_scope":    framed["read_scope"],
            "write_scope":   framed["write_scope"],
            "shell_scope":   framed["shell_scope"],
            "network_scope": framed["network_scope"],
        }

    def verify_invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "allowed_ops" in output

    def detect_drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict):
            return "output_not_dict"
        return None


class RenameStage(SourceLoop):
    """Stage 4: Assign internal governed identity. External name is archived."""

    def read_body(self, input_data: Any) -> Dict:
        return {
            "constrain": input_data,
            "external_name": input_data.get("discover", {}).get("name", "unknown"),
        }

    def apply_frame(self, body: Dict) -> Dict:
        ext = body["external_name"].lower().replace("-", "_").replace(" ", "_")
        governed_id = f"ext_{ext}"
        canon_hash  = hashlib.sha256(ext.encode()).hexdigest()[:8]
        return {
            **body,
            "governed_id":   governed_id,
            "canon_hash":    canon_hash,
            "external_name_archived": body["external_name"],
        }

    def collapse(self, framed: Dict) -> str:
        return STAGE_PASS

    def return_output(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":          "rename",
            "decision":       decision,
            "governed_id":    framed["governed_id"],
            "canon_hash":     framed["canon_hash"],
            "external_name":  framed["external_name_archived"],
        }

    def verify_invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "governed_id" in output

    def detect_drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict):
            return "output_not_dict"
        if not output.get("governed_id", "").startswith("ext_"):
            return "governed_id_malformed"
        return None


class WrapStage(SourceLoop):
    """Stage 5: Generate a BGP-compatible capability definition."""

    def read_body(self, input_data: Any) -> Dict:
        return {
            "rename":     input_data,
            "constrain":  input_data.get("constrain", {}),
        }

    def apply_frame(self, body: Dict) -> Dict:
        governed_id = body["rename"].get("governed_id", "ext_unknown")
        allowed_ops = body["constrain"].get("allowed_ops", [])
        return {
            **body,
            "governed_id": governed_id,
            "allowed_ops": allowed_ops,
            "capability_def": {
                "action_type":  governed_id,
                "parameters":   {
                    "op":      {"type": "str",  "required": True, "allowed": allowed_ops},
                    "args":    {"type": "dict", "required": False},
                },
                "derived": {
                    "op_allowed": f"parameters.op in {allowed_ops!r}",
                },
                "constraints": [
                    {
                        "constraint_id": f"{governed_id}_op_allowed",
                        "scope":         "derived",
                        "field":         "derived.op_allowed",
                        "operator":      "eq",
                        "value":         True,
                        "severity":      "critical",
                        "on_fail":       "block",
                        "description":   f"Operation must be in admitted op set for {governed_id}",
                    }
                ],
            },
        }

    def collapse(self, framed: Dict) -> str:
        if not framed["allowed_ops"]:
            return STAGE_BLOCK
        return STAGE_PASS

    def return_output(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":          "wrap",
            "decision":       decision,
            "governed_id":    framed["governed_id"],
            "capability_def": framed["capability_def"],
        }

    def verify_invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "capability_def" in output

    def detect_drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict):
            return "output_not_dict"
        cap = output.get("capability_def", {})
        if "action_type" not in cap:
            return "capability_def_missing_action_type"
        return None


class AdmitStage(SourceLoop):
    """
    Stage 6: Run admission decision.
    In a live system this calls run_cycle() in bgp.py. Here it applies the
    capability_def constraints deterministically — no LLM at this layer.
    """

    def read_body(self, input_data: Any) -> Dict:
        return {
            "wrap":           input_data,
            "capability_def": input_data.get("capability_def", {}),
        }

    def apply_frame(self, body: Dict) -> Dict:
        cap = body["capability_def"]
        params = cap.get("parameters", {})
        constraints = cap.get("constraints", [])
        return {
            **body,
            "has_action_type": bool(cap.get("action_type")),
            "has_params":      len(params) > 0,
            "has_constraints": len(constraints) > 0,
            "constraint_count": len(constraints),
        }

    def collapse(self, framed: Dict) -> str:
        if not framed["has_action_type"] or not framed["has_params"]:
            return STAGE_BLOCK
        if not framed["has_constraints"]:
            return STAGE_CLARIFY
        return STAGE_PASS

    def return_output(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":       "admit",
            "decision":    decision,
            "governed_id": framed["capability_def"].get("action_type"),
            "admitted":    decision == STAGE_PASS,
        }

    def verify_invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "admitted" in output

    def detect_drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict):
            return "output_not_dict"
        if not isinstance(output.get("admitted"), bool):
            return "admitted_not_bool"
        return None


class VerifyStage(SourceLoop):
    """Stage 7: Post-admission behavioral verification."""

    def read_body(self, input_data: Any) -> Dict:
        return {
            "admit":      input_data,
            "governed_id": input_data.get("governed_id"),
            "admitted":   input_data.get("admitted", False),
        }

    def apply_frame(self, body: Dict) -> Dict:
        # Behavioral verification: we check structural coherence.
        # A live system would run a dry-run with canary parameters.
        governed_id = body["governed_id"] or ""
        return {
            **body,
            "id_well_formed":   governed_id.startswith("ext_") and len(governed_id) > 4,
            "was_admitted":     body["admitted"],
        }

    def collapse(self, framed: Dict) -> str:
        if not framed["was_admitted"]:
            return STAGE_BLOCK
        if not framed["id_well_formed"]:
            return STAGE_BLOCK
        return STAGE_PASS

    def return_output(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":       "verify",
            "decision":    decision,
            "governed_id": framed["governed_id"],
            "verified":    decision == STAGE_PASS,
        }

    def verify_invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "verified" in output

    def detect_drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict):
            return "output_not_dict"
        if not isinstance(output.get("verified"), bool):
            return "verified_not_bool"
        return None


class ComposeStage(SourceLoop):
    """Stage 8: Add to registry. Capability becomes operational."""

    def read_body(self, input_data: Any) -> Dict:
        return {
            "verify":         input_data,
            "governed_id":    input_data.get("governed_id"),
            "verified":       input_data.get("verified", False),
            "capability_def": input_data.get("capability_def", {}),
        }

    def apply_frame(self, body: Dict) -> Dict:
        return {
            **body,
            "ready": body["verified"] and bool(body["governed_id"]),
        }

    def collapse(self, framed: Dict) -> str:
        return STAGE_PASS if framed["ready"] else STAGE_BLOCK

    def return_output(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":          "compose",
            "decision":       decision,
            "governed_id":    framed["governed_id"],
            "operational":    decision == STAGE_PASS,
            "capability_def": framed["capability_def"],
            "composed_at":    time.time() if decision == STAGE_PASS else None,
        }

    def verify_invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "operational" in output

    def detect_drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict):
            return "output_not_dict"
        if output.get("operational") and not output.get("governed_id"):
            return "operational_without_governed_id"
        return None


# ---------------------------------------------------------------------------
# Assimilation Topology — orchestrates all 8 stages
# ---------------------------------------------------------------------------

STAGES = [
    ("discover",  DiscoverStage),
    ("classify",  ClassifyStage),
    ("constrain", ConstrainStage),
    ("rename",    RenameStage),
    ("wrap",      WrapStage),
    ("admit",     AdmitStage),
    ("verify",    VerifyStage),
    ("compose",   ComposeStage),
]


class AssimilationTopology:
    """
    Governs how external capabilities enter the system.

    assimilate(manifest) → runs all 8 stages in sequence.
    Each stage must return PASS to proceed to the next.
    Any BLOCK or CLARIFY at any stage halts the topology.

    A capability is operational only when all 8 stages complete with PASS.
    """

    def __init__(self):
        self._registry: Dict[str, Dict] = {}
        self._stage_instances = {name: cls() for name, cls in STAGES}

    def assimilate(self, manifest: Dict) -> Dict:
        """
        Run a capability manifest through all 8 stages.
        Returns the full traversal record.
        """
        traversal = {
            "manifest":  manifest,
            "stages":    {},
            "halted_at": None,
            "operational": False,
            "governed_id": None,
        }

        # Wrap manifest so all stages can access it as input_data["manifest"]
        # and also directly as input_data["name"], etc.
        current_input = {"manifest": manifest, **manifest}

        for stage_name, _ in STAGES:
            stage    = self._stage_instances[stage_name]
            result   = stage.run(current_input)
            stage_out = result.get("output", {})
            decision  = stage_out.get("decision") if stage_out else result.get("status")

            traversal["stages"][stage_name] = {
                "result":   result,
                "decision": decision,
            }

            if decision != STAGE_PASS or result.get("status") == "DRIFT":
                traversal["halted_at"] = stage_name
                traversal["halt_reason"] = (
                    result.get("drift") or
                    f"stage={stage_name} decision={decision}"
                )
                return traversal

            # Thread through: each stage output feeds the next,
            # but we keep the cumulative context available.
            current_input = {**current_input, **stage_out, stage_name: stage_out}

        # All 8 stages passed
        governed_id     = current_input.get("governed_id")
        capability_def  = current_input.get("capability_def", {})
        traversal["operational"]   = True
        traversal["governed_id"]   = governed_id
        traversal["capability_def"] = capability_def

        if governed_id:
            self._registry[governed_id] = {
                "capability_def": capability_def,
                "admitted_at":    time.time(),
                "manifest":       manifest,
            }

        return traversal

    def get_admitted(self, governed_id: str) -> Optional[Dict]:
        return self._registry.get(governed_id)

    def list_admitted(self) -> List[str]:
        return list(self._registry.keys())

    def is_operational(self, governed_id: str) -> bool:
        return governed_id in self._registry


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_topology = AssimilationTopology()


def assimilate(manifest: Dict) -> Dict:
    """
    Assimilate an external capability through the full 8-stage topology.
    Returns the traversal record. Check result["operational"] to confirm admission.
    """
    return _topology.assimilate(manifest)


def is_operational(governed_id: str) -> bool:
    return _topology.is_operational(governed_id)


def list_admitted() -> List[str]:
    return _topology.list_admitted()
