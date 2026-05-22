"""
Assimilation Topology — governed capability intake

External capabilities cannot enter the system by being claimed.
They traverse 8 stages. Every stage is a closed loop.
A capability that exits with stage < 8 is not operational.

Stages: Discover → Classify → Constrain → Rename → Wrap → Admit → Verify → Compose
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


PASS    = "PASS"
BLOCK   = "BLOCK"
CLARIFY = "CLARIFY"
DEFER   = "DEFER"

THREAT_PATTERNS = [
    ("network_exfil", ["telemetry", "beacon", "phone home", "upload", "post credentials"]),
    ("privilege_esc", ["sudo", "setuid", "chmod 777", "escalate", "root access"]),
    ("supply_chain",  ["postinstall", "preinstall", "install hook", "setup.py exec"]),
    ("crypto_mining", ["mine", "hash rate", "gpu util", "worker thread", "pool"]),
    ("lateral_move",  ["scan network", "enumerate hosts", "ping sweep", "nmap"]),
]


def _detect_threats(text: str) -> List[str]:
    lower = text.lower()
    return [name for name, signals in THREAT_PATTERNS if any(s in lower for s in signals)]


def _classify_deps(manifest: Dict) -> Dict:
    deps = manifest.get("dependencies", [])
    return {
        "count":      len(deps),
        "has_network": any("http" in d or "request" in d for d in deps),
        "has_crypto":  any("crypt" in d or "ssl" in d for d in deps),
        "has_exec":    any("subprocess" in d or "os" in d or "exec" in d for d in deps),
        "names":       deps,
    }


# ---------------------------------------------------------------------------
# Stage 1 — Discover
# ---------------------------------------------------------------------------

class DiscoverStage(SourceLoop):

    def read(self, input_data: Any) -> Dict:
        m = input_data if isinstance(input_data, dict) else {"raw": str(input_data)}
        return {
            "manifest":    m,
            "name":        m.get("name", "unknown"),
            "source":      m.get("source", ""),
            "description": m.get("description", ""),
            "raw_text":    json.dumps(m),
        }

    def frame(self, body: Dict) -> Dict:
        threats = _detect_threats(body["raw_text"])
        return {
            **body,
            "threats":         threats,
            "has_threats":     len(threats) > 0,
            "has_name":        body["name"] != "unknown",
            "has_description": len(body["description"]) > 0,
        }

    def decide(self, framed: Dict) -> str:
        if framed["has_threats"]:  return BLOCK
        if not framed["has_name"]: return CLARIFY
        return PASS

    def emit(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":       "discover",
            "decision":    decision,
            "name":        framed["name"],
            "threats":     framed["threats"],
            "source":      framed["source"],
            "description": framed["description"],
            "timestamp":   time.time(),
        }

    def invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "stage" in output and "decision" in output

    def drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict): return "output_not_dict"
        if output.get("stage") != "discover": return "wrong_stage"
        return None


# ---------------------------------------------------------------------------
# Stage 2 — Classify
# ---------------------------------------------------------------------------

class ClassifyStage(SourceLoop):

    def read(self, input_data: Any) -> Dict:
        return {"discover": input_data, "manifest": input_data.get("manifest", {})}

    def frame(self, body: Dict) -> Dict:
        manifest = body["manifest"]
        deps     = _classify_deps(manifest)
        exec_ops = manifest.get("execution_ops", [])
        high     = "shell_run" in exec_ops and ("http_post" in exec_ops or deps["has_network"])
        medium   = "shell_run" in exec_ops or deps["has_exec"]
        return {
            **body,
            "deps":             deps,
            "exec_ops":         exec_ops,
            "writes_files":     "file_write" in exec_ops or "file_delete" in exec_ops,
            "runs_shell":       "shell_run" in exec_ops or deps["has_exec"],
            "uses_network":     "http_get" in exec_ops or "http_post" in exec_ops or deps["has_network"],
            "authority_surface": "high" if high else "medium" if medium else "low",
        }

    def decide(self, framed: Dict) -> str:
        return CLARIFY if framed["authority_surface"] == "high" else PASS

    def emit(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":             "classify",
            "decision":          decision,
            "deps":              framed["deps"],
            "exec_ops":          framed["exec_ops"],
            "writes_files":      framed["writes_files"],
            "runs_shell":        framed["runs_shell"],
            "uses_network":      framed["uses_network"],
            "authority_surface": framed["authority_surface"],
        }

    def invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "authority_surface" in output

    def drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict): return "output_not_dict"
        if output.get("authority_surface") not in ("low", "medium", "high"):
            return "unknown_authority_surface"
        return None


# ---------------------------------------------------------------------------
# Stage 3 — Constrain
# ---------------------------------------------------------------------------

class ConstrainStage(SourceLoop):

    def read(self, input_data: Any) -> Dict:
        return {
            "classify":          input_data,
            "exec_ops":          input_data.get("exec_ops", []),
            "authority_surface": input_data.get("authority_surface", "low"),
        }

    def frame(self, body: Dict) -> Dict:
        surface = body["authority_surface"]
        ops     = body["exec_ops"]

        if surface == "low":
            allowed_ops, write_scope = ops, "workspace"
        elif surface == "medium":
            allowed_ops, write_scope = [op for op in ops if op != "shell_run"], "workspace/output"
        else:
            allowed_ops, write_scope = [op for op in ops if op in ("file_read", "file_list", "math_eval")], ""

        return {
            **body,
            "allowed_ops": allowed_ops,
            "read_scope":  "workspace",
            "write_scope": write_scope,
            "has_ops":     len(allowed_ops) > 0,
        }

    def decide(self, framed: Dict) -> str:
        return PASS if framed["has_ops"] else CLARIFY

    def emit(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":       "constrain",
            "decision":    decision,
            "allowed_ops": framed["allowed_ops"],
            "read_scope":  framed["read_scope"],
            "write_scope": framed["write_scope"],
        }

    def invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "allowed_ops" in output

    def drift(self, output: Any) -> Optional[str]:
        return None if isinstance(output, dict) else "output_not_dict"


# ---------------------------------------------------------------------------
# Stage 4 — Rename
# ---------------------------------------------------------------------------

class RenameStage(SourceLoop):

    def read(self, input_data: Any) -> Dict:
        return {
            "constrain":     input_data,
            "external_name": input_data.get("discover", {}).get("name", "unknown"),
        }

    def frame(self, body: Dict) -> Dict:
        ext = body["external_name"].lower().replace("-", "_").replace(" ", "_")
        return {
            **body,
            "governed_id":  f"ext_{ext}",
            "canon_hash":   hashlib.sha256(ext.encode()).hexdigest()[:8],
            "external_name_archived": body["external_name"],
        }

    def decide(self, framed: Dict) -> str:
        return PASS

    def emit(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":         "rename",
            "decision":      decision,
            "governed_id":   framed["governed_id"],
            "canon_hash":    framed["canon_hash"],
            "external_name": framed["external_name_archived"],
        }

    def invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "governed_id" in output

    def drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict): return "output_not_dict"
        if not output.get("governed_id", "").startswith("ext_"):
            return "governed_id_malformed"
        return None


# ---------------------------------------------------------------------------
# Stage 5 — Wrap
# ---------------------------------------------------------------------------

class WrapStage(SourceLoop):

    def read(self, input_data: Any) -> Dict:
        return {
            "rename":    input_data,
            "constrain": input_data.get("constrain", {}),
        }

    def frame(self, body: Dict) -> Dict:
        governed_id = body["rename"].get("governed_id", "ext_unknown")
        allowed_ops = body["constrain"].get("allowed_ops", [])
        return {
            **body,
            "governed_id": governed_id,
            "allowed_ops": allowed_ops,
            "capability_def": {
                "action_type": governed_id,
                "parameters": {
                    "op":   {"type": "str",  "required": True,  "allowed": allowed_ops},
                    "args": {"type": "dict", "required": False},
                },
                "derived": {
                    "op_allowed": f"parameters.op in {allowed_ops!r}",
                },
                "constraints": [{
                    "constraint_id": f"{governed_id}_op_allowed",
                    "scope":         "derived",
                    "field":         "derived.op_allowed",
                    "operator":      "eq",
                    "value":         True,
                    "severity":      "critical",
                    "on_fail":       "block",
                    "description":   f"Operation must be in admitted op set for {governed_id}",
                }],
            },
        }

    def decide(self, framed: Dict) -> str:
        return BLOCK if not framed["allowed_ops"] else PASS

    def emit(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":          "wrap",
            "decision":       decision,
            "governed_id":    framed["governed_id"],
            "capability_def": framed["capability_def"],
        }

    def invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "capability_def" in output

    def drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict): return "output_not_dict"
        if "action_type" not in output.get("capability_def", {}):
            return "capability_def_missing_action_type"
        return None


# ---------------------------------------------------------------------------
# Stage 6 — Admit
# ---------------------------------------------------------------------------

class AdmitStage(SourceLoop):

    def read(self, input_data: Any) -> Dict:
        return {
            "wrap":           input_data,
            "capability_def": input_data.get("capability_def", {}),
        }

    def frame(self, body: Dict) -> Dict:
        cap = body["capability_def"]
        return {
            **body,
            "has_action_type": bool(cap.get("action_type")),
            "has_params":      len(cap.get("parameters", {})) > 0,
            "has_constraints": len(cap.get("constraints", [])) > 0,
        }

    def decide(self, framed: Dict) -> str:
        if not framed["has_action_type"] or not framed["has_params"]: return BLOCK
        if not framed["has_constraints"]: return CLARIFY
        return PASS

    def emit(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":       "admit",
            "decision":    decision,
            "governed_id": framed["capability_def"].get("action_type"),
            "admitted":    decision == PASS,
        }

    def invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "admitted" in output

    def drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict): return "output_not_dict"
        if not isinstance(output.get("admitted"), bool): return "admitted_not_bool"
        return None


# ---------------------------------------------------------------------------
# Stage 7 — Verify
# ---------------------------------------------------------------------------

class VerifyStage(SourceLoop):

    def read(self, input_data: Any) -> Dict:
        return {
            "admit":       input_data,
            "governed_id": input_data.get("governed_id"),
            "admitted":    input_data.get("admitted", False),
        }

    def frame(self, body: Dict) -> Dict:
        gid = body["governed_id"] or ""
        return {
            **body,
            "id_well_formed": gid.startswith("ext_") and len(gid) > 4,
            "was_admitted":   body["admitted"],
        }

    def decide(self, framed: Dict) -> str:
        return PASS if (framed["was_admitted"] and framed["id_well_formed"]) else BLOCK

    def emit(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":       "verify",
            "decision":    decision,
            "governed_id": framed["governed_id"],
            "verified":    decision == PASS,
        }

    def invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "verified" in output

    def drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict): return "output_not_dict"
        if not isinstance(output.get("verified"), bool): return "verified_not_bool"
        return None


# ---------------------------------------------------------------------------
# Stage 8 — Compose
# ---------------------------------------------------------------------------

class ComposeStage(SourceLoop):

    def read(self, input_data: Any) -> Dict:
        return {
            "verify":         input_data,
            "governed_id":    input_data.get("governed_id"),
            "verified":       input_data.get("verified", False),
            "capability_def": input_data.get("capability_def", {}),
        }

    def frame(self, body: Dict) -> Dict:
        return {**body, "ready": body["verified"] and bool(body["governed_id"])}

    def decide(self, framed: Dict) -> str:
        return PASS if framed["ready"] else BLOCK

    def emit(self, decision: str, framed: Dict) -> Dict:
        return {
            "stage":          "compose",
            "decision":       decision,
            "governed_id":    framed["governed_id"],
            "operational":    decision == PASS,
            "capability_def": framed["capability_def"],
            "composed_at":    time.time() if decision == PASS else None,
        }

    def invariant(self, output: Any) -> bool:
        return isinstance(output, dict) and "operational" in output

    def drift(self, output: Any) -> Optional[str]:
        if not isinstance(output, dict): return "output_not_dict"
        if output.get("operational") and not output.get("governed_id"):
            return "operational_without_governed_id"
        return None


# ---------------------------------------------------------------------------
# Topology orchestrator
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
    Run a capability manifest through all 8 stages.
    A capability is operational only when all stages complete with PASS.
    """

    def __init__(self):
        self._registry: Dict[str, Dict] = {}
        self._stages = {name: cls() for name, cls in STAGES}

    def assimilate(self, manifest: Dict) -> Dict:
        traversal = {
            "manifest":     manifest,
            "stages":       {},
            "halted_at":    None,
            "operational":  False,
            "governed_id":  None,
        }

        current = {"manifest": manifest, **manifest}

        for stage_name, _ in STAGES:
            result    = self._stages[stage_name].run(current)
            stage_out = result.get("output", {})
            decision  = stage_out.get("decision") if stage_out else result.get("status")

            traversal["stages"][stage_name] = {"result": result, "decision": decision}

            if decision != PASS or result.get("status") == "DRIFT":
                traversal["halted_at"]   = stage_name
                traversal["halt_reason"] = (
                    result.get("drift") or f"stage={stage_name} decision={decision}"
                )
                return traversal

            current = {**current, **stage_out, stage_name: stage_out}

        governed_id    = current.get("governed_id")
        capability_def = current.get("capability_def", {})

        traversal["operational"]    = True
        traversal["governed_id"]    = governed_id
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


_topology = AssimilationTopology()


def assimilate(manifest: Dict) -> Dict:
    """Assimilate an external capability. Check result['operational'] to confirm admission."""
    return _topology.assimilate(manifest)


def is_operational(governed_id: str) -> bool:
    return _topology.is_operational(governed_id)


def list_admitted() -> List[str]:
    return _topology.list_admitted()
