---
name: bell-governance-protocol
description: Use when designing or implementing a governance layer for AI model actions—where proposals must be validated against formal constraints before execution, execution must be atomic and verifiable, and drift through constraint omission, execution divergence, or informal state access must be architecturally impossible.
---

# Bell Governance Protocol

## Overview

A closed, drift-free architecture for governing AI model actions. The model proposes. The law validates. Execution commits only what validation authorized. Verification proves it.

**Core principle:** No layer can override another. No layer can "help." No layer can drift.

**Announce at start:** "I'm using the bell-governance-protocol skill to implement this governance layer."

## The Seven Layers

```
Raw Input
  → [1] Proposal Formation      structured object; model fills intent/action/target/parameters
  → [2] Registry Match          applicable constraint set selected deterministically
  → [3] State Derivation        derived fields + expected state computed (pure, no side effects)
  → [4] Predicate Evaluation    constraint predicates evaluated over proposal + state + derived
  → [5] Decision                APPROVED / BLOCKED / CONFIRM / CLARIFY
  → [6] Execution Contract      atomic delta committed; no mutation outside the contract
  → [7] Verification            actual state hash == expected state hash, or rollback
  → Output                      verified transformation only; no representation of unverified action
```

Each layer is a prerequisite for the next. None may be skipped, reordered, or bypassed.

## Layer Responsibilities

| Layer | Input | Output | Invariant |
|---|---|---|---|
| Proposal Formation | Raw signal | Proposal object | Model shapes only; cannot select constraints |
| Registry Match | Proposal features | Constraint ID set | Deterministic; no heuristics |
| State Derivation | Proposal + pre-state | Derived fields + expected state | Pure function; no side effects |
| Predicate Evaluation | Constraints + derived fields | Pass/fail per constraint | Closed operator set only |
| Decision | Eval results + risk | Classification | block > confirm > clarify |
| Execution Contract | Approved proposal + expected state | Atomic delta | No mutation outside allowed_mutations |
| Verification | Actual state vs expected state | Pass or rollback | Divergence triggers rollback; never silent acceptance |

## Drift Vectors and Closures

| Drift Vector | Closure |
|---|---|
| Constraint omission | Registry: binding rule selects full applicable set; omission is a registry problem |
| Registry manipulation | Registry changes are GOVERN proposals; pass same validation pipeline |
| Stale state | Execution checks live state version == pre_state_version before commit |
| Execution divergence | Verification compares actual hash vs expected hash; mismatch triggers rollback |
| Helpful side effects | Execution contract lists allowed_mutations explicitly; anything else is forbidden |
| Replay/duplication | idempotency_key on execution contract; same key cannot commit twice |
| Informal derivation | Derived fields computed by a closed set of pure functions; no runtime inference |

## Constraint Registry

The registry maps proposal features to constraint sets. A binding activates when all specified match conditions are satisfied by the proposal.

Match conditions (each optional; absent = wildcard):
- `action_type` — must be in list
- `target_domain` — must be in list
- `target_scope` — must be in list
- `policy_scope` — must intersect
- `source_channel` — must be in list
- `risk_level` — must be in list

Three binding levels:
- **Global** — empty or broad match; applies to every proposal (state-version coherence, target resolution, representation safety)
- **Domain** — matches on `target_domain`, `action_type`, `policy_scope`
- **Local** — matches on specific scopes or resource classes

Priority resolves conflicts only. Both constraints still exist and are both evaluated.

Severity precedence: `block > confirm > clarify`. Higher severity dominates when two constraints conflict on `on_fail`.

## State Manager Contract

```
StateManager:
  current_version: VersionID
  get_snapshot(version)   → StateTree
  derive(proposal, pre_state) → (expected_new_state, derived_fields)  # pure
  commit(expected_state)  → new_version
  rollback_to(version)
  quarantine(version)
```

`derive` is a pure function. It does not modify state. No derived field may require side effects to compute. The same `derive` is called during validation (to compute expected state) and during verification (to confirm the executed state matches).

## Decision Table

| Constraint Results | Classification |
|---|---|
| All pass | APPROVED |
| Any `on_fail: block` | BLOCKED |
| Any `on_fail: confirm` (no blocks) | CONFIRM |
| Any `on_fail: clarify` (no blocks, no confirms) | CLARIFY |

Only APPROVED proceeds to execution.

## Execution Contract

The contract narrows legality into realizability. It enumerates exactly what may change and forbids everything else.

Required fields: `execution_id`, `proposal_id`, `pre_state_version`, `expected_state_version`, `allowed_mutations[]`, `forbidden_effects[]`, `expiry`, `idempotency_key`.

Execution sequence:
1. Check expiry
2. Check idempotency key not already committed
3. Check live state version == `pre_state_version`
4. Stage allowed mutations
5. Commit atomically (transaction, journal, or CAS; mechanism varies; invariant does not)
6. Record new state version
7. Pass to verification

## Verification

Verification is proof of equivalence, not a second decision.

```
verify(pre_state, expected_state, actual_state):
    expected_hash = hash(expected_state)
    actual_hash   = hash(actual_state)
    if expected_hash != actual_hash:
        rollback_to(pre_state)
        record execution_mismatch
        return FAIL
    return PASS
```

If FAIL: rollback or quarantine. No divergent manifested state may remain authoritative. No failed execution may be represented as successful in output.

## Governance of the Registry Itself

Registry changes are not administrative exceptions. They are proposals of type `govern` with `target.scope = constraint_registry`. They pass through the same pipeline. The law governs changes to its own applicability surface. No side-channel edits.

## Runtime Sequence (Pseudocode)

See `reference-implementation.py` for the complete runnable form.

```python
def run_cycle(raw_input, registry, state_manager):
    proposal  = build_proposal_from_model(raw_input, state_manager)
    pre_ver, pre_state = state_manager.snapshot()
    expected_state, derived = state_manager.derive(proposal, pre_state)
    constraints = registry.match(proposal)
    decision = check_constraints(constraints, proposal, pre_state, derived)
    if decision != APPROVED:
        return route(decision)
    contract = prepare_contract(proposal, pre_ver, expected_state)
    if not preconditions_met(contract, state_manager):
        return route(CLARIFY)
    new_ver = state_manager.commit(expected_state)
    if not verify(pre_state, expected_state, state_manager.state):
        state_manager.rollback_to(pre_ver)
        return route(INTERNAL_ERROR)
    return format_output(new_ver, proposal.output_contract)
```

## Schemas

See `schemas.md` for canonical JSON schemas for:
- Proposal object
- Constraint object
- Registry binding
- Execution contract
- Verification receipt
- State version metadata

## Common Mistakes

**Letting the model select constraints**
- Model fills intent, action, target, parameters. Registry selects constraints. These are different layers. If the model touches constraint selection, the boundary is broken.

**Treating priority as inclusion control**
- Priority resolves conflicts between bindings. It does not suppress lower-priority bindings. All matching bindings are evaluated; their constraint sets are unioned.

**Skipping verification because "commit succeeded"**
- A successful commit proves the database accepted a write. It does not prove the written state equals the validated state. Verification is required.

**Informal derived fields**
- `balance_after` does not exist in stored state. It must be computed by `derive` before validation and the same `derive` must be used during execution. If derivation is inline or ad hoc, the two computations may diverge. Use the state manager's `derive` function everywhere.

**Allowing the output layer to run before verification**
- Output represents a verified transformation. If output runs before verification, the observer may receive a success representation that rollback later contradicts.

## Integration Points

This skill produces a governed execution loop. It is compatible with any state backend that supports:
- Versioned snapshots (content hash or Merkle root)
- Atomic commit (transaction, journal, or compare-and-swap)
- Rollback to a prior version

The model front-end may be any language model. It fills proposal fields only. It cannot select constraints, modify state directly, or bypass the execution contract.
