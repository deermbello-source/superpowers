"""
Bell Governance Protocol — Reference Implementation

This is an identity-preserving minimal implementation of the full governance loop.
It is not optimized. Every function corresponds directly to a named layer in SKILL.md.

Layers:
  1. Proposal Formation   — build_proposal_from_model()
  2. Registry Match       — ConstraintRegistry.match()
  3. State Derivation     — StateManager.derive()
  4. Predicate Evaluation — check_constraints()
  5. Decision             — implied by check_constraints() return value
  6. Execution Contract   — prepare_contract(), execute()
  7. Verification         — verify()
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import copy
import hashlib
import json
import time
import uuid


# ---------------------------------------------------------------------------
# Classification constants
# ---------------------------------------------------------------------------

APPROVED = "APPROVED"
BLOCKED  = "BLOCKED"
CONFIRM  = "CONFIRM"
CLARIFY  = "CLARIFY"
STALE    = "STALE"
ROLLBACK = "ROLLBACK"
INTERNAL_ERROR = "INTERNAL_ERROR"


# ---------------------------------------------------------------------------
# 1. Core types
# ---------------------------------------------------------------------------

@dataclass
class Proposal:
    proposal_id: str
    created_at: float
    source_channel: str
    raw_input: Any

    intent: Dict[str, Any]
    action: Dict[str, Any]
    target: Dict[str, Any]
    parameters: Dict[str, Any]
    constraints: Dict[str, Any]

    state_snapshot_version: str
    risk: Dict[str, Any]

    output_contract: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Constraint:
    constraint_id: str
    scope: str           # proposal | state | derived | global
    field: str           # dotted path: derived.balance_after, state.balance, etc.
    operator: str        # gte | lte | eq | neq | gt | lt | in | not_in | exists | not_exists
    value: Any
    severity: str        # info | warning | critical
    on_fail: str         # clarify | confirm | block


@dataclass
class Binding:
    binding_id: str
    match: Dict[str, List[str]]
    constraint_ids: List[str]
    priority: int
    enabled: bool = True


@dataclass
class ExecutionContract:
    execution_id: str
    proposal_id: str
    pre_state_version: str
    expected_state_version: Optional[str]
    allowed_mutations: List[Dict[str, Any]]
    forbidden_effects: List[str]
    expiry: Optional[float]        # unix timestamp or None
    idempotency_key: str


@dataclass
class VerificationReceipt:
    verification_id: str
    proposal_id: str
    execution_id: str
    pre_state_version: str
    actual_state_version: str
    expected_hash: str
    actual_hash: str
    verified_fields: List[str]
    result: str                    # pass | fail
    failure_reasons: List[str]


# ---------------------------------------------------------------------------
# 2. Constraint Registry
# ---------------------------------------------------------------------------

class ConstraintRegistry:
    """
    Maps proposal features to constraint sets.
    Matching is deterministic: either a binding matches or it does not.
    Priority resolves conflicts; it does not control inclusion.
    """

    def __init__(self):
        self.bindings: List[Binding] = []
        self.constraints: Dict[str, Constraint] = {}

    def add_constraint(self, constraint: Constraint):
        self.constraints[constraint.constraint_id] = constraint

    def add_binding(self, binding: Binding):
        self.bindings.append(binding)

    def match(self, proposal: Proposal) -> List[Constraint]:
        """Return the deduplicated union of all constraints from all matching bindings."""
        matched_ids: Dict[str, Constraint] = {}

        for binding in sorted(self.bindings, key=lambda b: b.priority, reverse=True):
            if not binding.enabled:
                continue
            if self._matches(binding.match, proposal):
                for cid in binding.constraint_ids:
                    if cid in self.constraints:
                        matched_ids[cid] = self.constraints[cid]

        return list(matched_ids.values())

    def _matches(self, spec: Dict[str, List[str]], proposal: Proposal) -> bool:
        """Deterministic match. Absent key = wildcard."""
        if "action_type" in spec:
            if proposal.action.get("type") not in spec["action_type"]:
                return False
        if "target_domain" in spec:
            if proposal.target.get("domain") not in spec["target_domain"]:
                return False
        if "target_scope" in spec:
            if proposal.target.get("scope") not in spec["target_scope"]:
                return False
        if "policy_scope" in spec:
            proposal_scopes = proposal.constraints.get("policy_scope", [])
            if not set(proposal_scopes).intersection(spec["policy_scope"]):
                return False
        if "source_channel" in spec:
            if proposal.source_channel not in spec["source_channel"]:
                return False
        if "risk_level" in spec:
            if proposal.risk.get("level") not in spec["risk_level"]:
                return False
        return True


# ---------------------------------------------------------------------------
# 3. State Manager + Derived Field Engine
# ---------------------------------------------------------------------------

class StateManager:
    """
    The canonical truth surface of the architecture.

    derive() is a pure function. It does not modify state.
    No derived field may require side effects to compute.
    The same derive() is used in validation and in execution.
    """

    def __init__(self, initial_state: Optional[Dict] = None):
        self.state: Dict[str, Any] = initial_state or {}
        self.version: str = self._new_version_id()
        self.history: List[Dict] = []
        self._committed_idempotency_keys: set = set()

    def _new_version_id(self) -> str:
        return str(uuid.uuid4())

    def snapshot(self) -> Tuple[str, Dict]:
        """Return (version, deep copy of current state)."""
        return self.version, copy.deepcopy(self.state)

    def state_hash(self, state: Optional[Dict] = None) -> str:
        """Deterministic content hash of a state dict."""
        target = state if state is not None else self.state
        serialized = json.dumps(target, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(serialized.encode()).hexdigest()

    def derive(self, proposal: Proposal, pre_state: Dict) -> Tuple[Dict, Dict]:
        """
        Pure derivation: compute expected new state and derived fields.
        No side effects. Same result for same inputs.

        Returns (expected_new_state, derived_fields).
        """
        new_state  = copy.deepcopy(pre_state)
        derived: Dict[str, Any] = {}

        action_type = proposal.action.get("type")

        if action_type == "allocate":
            amount = proposal.parameters.get("amount", 0)
            src    = proposal.parameters.get("from")
            dst    = proposal.parameters.get("to")

            if src and src in new_state:
                new_state[src] -= amount
                derived["balance_after_src"] = new_state[src]

            if dst and dst in new_state:
                new_state[dst] += amount
                derived["balance_after_dst"] = new_state[dst]

        elif action_type == "set":
            target_ref = proposal.parameters.get("target_ref")
            value      = proposal.parameters.get("value")
            if target_ref:
                new_state[target_ref] = value
                derived["value_after"] = value

        elif action_type == "modify":
            target_ref = proposal.parameters.get("target_ref")
            delta      = proposal.parameters.get("delta", 0)
            if target_ref and target_ref in new_state:
                new_state[target_ref] += delta
                derived["value_after"] = new_state[target_ref]

        return new_state, derived

    def commit(self, expected_state: Dict, proposal_id: str, execution_id: str,
               idempotency_key: str) -> str:
        """
        Atomic commit of expected state.
        Records history entry. Returns new version.
        """
        pre_version = self.version
        self.state  = copy.deepcopy(expected_state)
        self.version = self._new_version_id()
        self._committed_idempotency_keys.add(idempotency_key)
        self.history.append({
            "execution_id":       execution_id,
            "proposal_id":        proposal_id,
            "pre_state_version":  pre_version,
            "post_state_version": self.version,
            "idempotency_key":    idempotency_key,
            "timestamp":          time.time(),
        })
        return self.version

    def rollback_to(self, version: str, state_snapshot: Dict):
        """Restore state to the given snapshot. Records rollback in history."""
        self.state   = copy.deepcopy(state_snapshot)
        self.version = version
        self.history.append({
            "execution_id":      "ROLLBACK",
            "proposal_id":       None,
            "pre_state_version": "DIVERGED",
            "post_state_version": version,
            "idempotency_key":   None,
            "timestamp":          time.time(),
        })

    def idempotency_key_committed(self, key: str) -> bool:
        return key in self._committed_idempotency_keys


# ---------------------------------------------------------------------------
# 4. Predicate Evaluation Engine
# ---------------------------------------------------------------------------

def _resolve_field(field: str, proposal: Proposal, state: Dict, derived: Dict) -> Any:
    """Resolve a dotted field path against proposal, state, or derived fields."""
    if field.startswith("derived."):
        return derived.get(field[len("derived."):])
    if field.startswith("state."):
        return state.get(field[len("state."):])
    if field.startswith("proposal.parameters."):
        return proposal.parameters.get(field[len("proposal.parameters."):])
    if field.startswith("proposal."):
        parts = field[len("proposal."):].split(".")
        obj = proposal
        for part in parts:
            if isinstance(obj, dict):
                obj = obj.get(part)
            else:
                obj = getattr(obj, part, None)
        return obj
    return None


def _apply_operator(operator: str, left: Any, right: Any) -> bool:
    """Closed set of operators. No custom operators at runtime."""
    if operator == "gte":       return left is not None and left >= right
    if operator == "lte":       return left is not None and left <= right
    if operator == "eq":        return left == right
    if operator == "neq":       return left != right
    if operator == "gt":        return left is not None and left > right
    if operator == "lt":        return left is not None and left < right
    if operator == "in":        return left in right
    if operator == "not_in":    return left not in right
    if operator == "exists":    return left is not None
    if operator == "not_exists": return left is None
    raise ValueError(f"Unknown operator: {operator}")


def check_constraints(
    constraints: List[Constraint],
    proposal: Proposal,
    pre_state: Dict,
    derived: Dict,
) -> str:
    """
    Evaluate all constraints. Return classification.
    block > confirm > clarify
    """
    failures: List[Constraint] = []

    for c in constraints:
        left = _resolve_field(c.field, proposal, pre_state, derived)
        try:
            passed = _apply_operator(c.operator, left, c.value)
        except (TypeError, ValueError):
            passed = False

        if not passed:
            failures.append(c)

    if not failures:
        return APPROVED

    for f in failures:
        if f.on_fail == "block":
            return BLOCKED

    for f in failures:
        if f.on_fail == "confirm":
            return CONFIRM

    return CLARIFY


# ---------------------------------------------------------------------------
# 5. Execution Contract + Engine
# ---------------------------------------------------------------------------

def prepare_contract(
    proposal: Proposal,
    pre_state_version: str,
    expected_state: Dict,
    state_manager: StateManager,
) -> ExecutionContract:
    """
    Instantiate the execution contract from the approved proposal.
    Enumerates allowed mutations from the expected state delta.
    """
    return ExecutionContract(
        execution_id=str(uuid.uuid4()),
        proposal_id=proposal.proposal_id,
        pre_state_version=pre_state_version,
        expected_state_version=None,   # set after commit
        allowed_mutations=[],          # in production: diff(pre_state, expected_state)
        forbidden_effects=[
            "out_of_scope_mutation",
            "implicit_resource_creation",
            "visibility_escalation",
            "unapproved_side_effect",
        ],
        expiry=None,                   # None = no expiry in this reference impl
        idempotency_key=str(uuid.uuid4()),
    )


def execute(
    contract: ExecutionContract,
    expected_state: Dict,
    state_manager: StateManager,
    proposal: Proposal,
) -> Tuple[str, str]:
    """
    Commit the approved delta atomically.
    Returns (new_state_version, status).
    """
    # Check expiry
    if contract.expiry and time.time() > contract.expiry:
        return "", "EXPIRED"

    # Check idempotency
    if state_manager.idempotency_key_committed(contract.idempotency_key):
        return state_manager.version, "IDEMPOTENT"

    # Check state freshness (version lock)
    if state_manager.version != contract.pre_state_version:
        return "", STALE

    # Atomic commit
    new_version = state_manager.commit(
        expected_state,
        proposal_id=contract.proposal_id,
        execution_id=contract.execution_id,
        idempotency_key=contract.idempotency_key,
    )
    return new_version, APPROVED


# ---------------------------------------------------------------------------
# 6. Verification
# ---------------------------------------------------------------------------

def verify(
    contract: ExecutionContract,
    pre_state_version: str,
    expected_state: Dict,
    actual_state: Dict,
    state_manager: StateManager,
    pre_state_snapshot: Dict,
) -> VerificationReceipt:
    """
    Proof of equivalence between validated and realized state.
    Divergence triggers rollback; never silent acceptance.
    """
    expected_hash = hashlib.sha256(
        json.dumps(expected_state, sort_keys=True).encode()
    ).hexdigest()
    actual_hash = hashlib.sha256(
        json.dumps(actual_state, sort_keys=True).encode()
    ).hexdigest()

    passed  = expected_hash == actual_hash
    reasons = [] if passed else ["state_hash_mismatch"]

    if not passed:
        state_manager.rollback_to(pre_state_version, pre_state_snapshot)

    return VerificationReceipt(
        verification_id=str(uuid.uuid4()),
        proposal_id=contract.proposal_id,
        execution_id=contract.execution_id,
        pre_state_version=pre_state_version,
        actual_state_version=state_manager.version,
        expected_hash=expected_hash,
        actual_hash=actual_hash,
        verified_fields=[],
        result="pass" if passed else "fail",
        failure_reasons=reasons,
    )


# ---------------------------------------------------------------------------
# 7. Model Front-End (Proposal Formation)
# ---------------------------------------------------------------------------

def model_parse(raw_input: str) -> Dict[str, Any]:
    """
    Model shapes the proposal fields. It does not select constraints.
    It does not execute. It does not access state directly.

    In production: replace with an LLM call that returns structured JSON.
    This stub parses simple command strings for demonstration.
    """
    tokens = raw_input.lower().split()

    if "allocate" in tokens or "transfer" in tokens or "move" in tokens:
        try:
            amount = float([t for t in tokens if t.replace(".", "").isdigit()][0])
        except IndexError:
            amount = 0.0

        from_acc = None
        to_acc   = None
        if "from" in tokens:
            idx = tokens.index("from")
            if idx + 1 < len(tokens):
                from_acc = tokens[idx + 1]
        if "to" in tokens:
            idx = tokens.index("to")
            if idx + 1 < len(tokens):
                to_acc = tokens[idx + 1]

        return {
            "intent":     {"summary": "transfer funds", "goal_type": "allocate", "confidence": 0.85},
            "action":     {"type": "allocate", "subtype": None},
            "target":     {"domain": "finance", "object_id": None, "scope": "account"},
            "parameters": {"amount": amount, "from": from_acc, "to": to_acc},
        }

    return {
        "intent":     {"summary": "unknown", "goal_type": "other", "confidence": 0.1},
        "action":     {"type": "noop", "subtype": None},
        "target":     {"domain": "unknown", "object_id": None, "scope": None},
        "parameters": {},
    }


def build_proposal_from_model(raw_input: str, state_manager: StateManager) -> Proposal:
    """Build a complete Proposal from model-parsed fields + system context."""
    parsed = model_parse(raw_input)
    return Proposal(
        proposal_id=str(uuid.uuid4()),
        created_at=time.time(),
        source_channel="text",
        raw_input=raw_input,
        intent=parsed["intent"],
        action=parsed["action"],
        target=parsed["target"],
        parameters=parsed["parameters"],
        constraints={
            "explicit":     [],
            "inherited":    [],
            "policy_scope": ["default_finance"],
        },
        state_snapshot_version=state_manager.version,
        risk={"level": "medium"},
    )


# ---------------------------------------------------------------------------
# 8. Loop Runner
# ---------------------------------------------------------------------------

def run_cycle(
    raw_input: str,
    registry: ConstraintRegistry,
    state_manager: StateManager,
) -> Dict[str, Any]:
    """
    The complete governance loop. No layer is skipped. No layer overrides another.
    """
    # --- Layer 1: Proposal Formation ---
    proposal = build_proposal_from_model(raw_input, state_manager)

    # --- Layer 3: State Snapshot ---
    pre_version, pre_state = state_manager.snapshot()
    proposal.state_snapshot_version = pre_version

    # --- Layer 3: Derivation (pure) ---
    expected_state, derived = state_manager.derive(proposal, pre_state)

    # --- Layer 2: Registry Match ---
    constraints = registry.match(proposal)

    # --- Layer 4: Predicate Evaluation ---
    decision = check_constraints(constraints, proposal, pre_state, derived)

    if decision != APPROVED:
        return {"status": decision, "proposal_id": proposal.proposal_id}

    # --- Layer 6: Execution Contract ---
    contract = prepare_contract(proposal, pre_version, expected_state, state_manager)
    new_version, exec_status = execute(contract, expected_state, state_manager, proposal)

    if exec_status != APPROVED:
        return {"status": exec_status, "proposal_id": proposal.proposal_id}

    # --- Layer 7: Verification ---
    actual_state = copy.deepcopy(state_manager.state)
    receipt = verify(
        contract,
        pre_state_version=pre_version,
        expected_state=expected_state,
        actual_state=actual_state,
        state_manager=state_manager,
        pre_state_snapshot=pre_state,
    )

    if receipt.result == "fail":
        return {
            "status":        ROLLBACK,
            "proposal_id":   proposal.proposal_id,
            "receipt":        receipt,
        }

    # --- Output (verified transformation only) ---
    return {
        "status":        "COMMITTED",
        "proposal_id":   proposal.proposal_id,
        "new_version":   new_version,
        "state":          state_manager.state,
        "receipt":        receipt,
    }


# ---------------------------------------------------------------------------
# 9. Example: Financial Governance
# ---------------------------------------------------------------------------

def build_finance_registry() -> ConstraintRegistry:
    """Minimal finance registry with a minimum-balance constraint."""
    registry = ConstraintRegistry()

    # Constraint: source account must remain above minimum after transfer
    registry.add_constraint(Constraint(
        constraint_id="min_balance_src",
        scope="derived",
        field="derived.balance_after_src",
        operator="gte",
        value=100,
        severity="critical",
        on_fail="block",
    ))

    # Constraint: amount must be positive
    registry.add_constraint(Constraint(
        constraint_id="positive_amount",
        scope="proposal",
        field="proposal.parameters.amount",
        operator="gt",
        value=0,
        severity="critical",
        on_fail="block",
    ))

    # Global binding: applies to all allocations in finance domain
    registry.add_binding(Binding(
        binding_id="finance_alloc_global",
        match={
            "action_type":   ["allocate"],
            "target_domain": ["finance"],
        },
        constraint_ids=["min_balance_src", "positive_amount"],
        priority=100,
    ))

    return registry


if __name__ == "__main__":
    # Initial state: two accounts
    sm = StateManager(initial_state={"main": 1000, "savings": 200})
    registry = build_finance_registry()

    print("=== Test 1: Transfer 800 from main to savings (should COMMIT) ===")
    result = run_cycle("move 800 from main to savings", registry, sm)
    print(f"  Status:  {result['status']}")
    print(f"  State:   {result.get('state')}")
    print()

    print("=== Test 2: Transfer 950 from main to savings (main < 100 after; should BLOCK) ===")
    # main is now 200 after Test 1. 200 - 950 = -750 < 100
    result = run_cycle("move 950 from main to savings", registry, sm)
    print(f"  Status:  {result['status']}")
    print(f"  State:   {sm.state}  (unchanged)")
    print()

    print("=== Test 3: Transfer 50 from main to savings (main = 200; 200-50=150 >= 100; should COMMIT) ===")
    result = run_cycle("move 50 from main to savings", registry, sm)
    print(f"  Status:  {result['status']}")
    print(f"  State:   {result.get('state')}")
