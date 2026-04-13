# Bell Governance Protocol — Canonical Schemas

All schemas are canonical. Changes require a GOVERN proposal.

---

## Proposal Object

```json
{
  "proposal_id": "string (UUID)",
  "created_at": "ISO-8601 timestamp",
  "source_channel": "text | api | internal",
  "raw_input": "any",

  "intent": {
    "summary": "string",
    "goal_type": "allocate | modify | query | govern | other",
    "confidence": "float 0–1"
  },

  "action": {
    "type": "string (must exist in capability registry)",
    "subtype": "string | null"
  },

  "target": {
    "domain": "string",
    "object_id": "string | null",
    "scope": "string"
  },

  "parameters": {
    "...": "domain-specific; evaluated against derived fields during validation"
  },

  "constraints": {
    "explicit": ["constraint_id"],
    "inherited": ["constraint_id"],
    "policy_scope": ["policy_id"]
  },

  "state_snapshot": {
    "version": "string (references a specific StateVersion)"
  },

  "risk": {
    "level": "low | medium | high | critical"
  },

  "output_contract": {
    "format": "string",
    "representation_constraints": []
  }
}
```

---

## Constraint Object

```json
{
  "constraint_id": "string",
  "scope": "proposal | state | derived | global",
  "field": "string (dotted path: derived.balance_after, state.balance, proposal.parameters.amount)",
  "operator": "gte | lte | eq | neq | gt | lt | in | not_in | exists | not_exists",
  "value": "any",
  "severity": "info | warning | critical",
  "on_fail": "clarify | confirm | block"
}
```

Operator semantics are closed. No custom operators at runtime.

---

## Registry Binding

```json
{
  "binding_id": "string",
  "match": {
    "action_type":    ["string"],
    "target_domain":  ["string"],
    "target_scope":   ["string"],
    "policy_scope":   ["string"],
    "source_channel": ["string"],
    "risk_level":     ["low", "medium", "high", "critical"]
  },
  "constraint_ids": ["string"],
  "priority": 100,
  "enabled": true
}
```

`match` keys are each optional. Absent key = wildcard (matches all values).
`priority` resolves conflicts; it does not control inclusion.
`enabled: false` deactivates the binding without deleting it (preserves audit history).

---

## Capability

```json
{
  "capability_id": "string",
  "name": "string",
  "domain": "string",
  "allowed_target_types": ["string"],
  "default_risk": "low | medium | high | critical",
  "requires_confirmation": false,
  "enabled": true
}
```

Stored at `system.capabilities` in the state tree. Changes require a GOVERN proposal.

---

## Execution Contract

```json
{
  "execution_id": "string (UUID)",
  "proposal_id": "string",
  "pre_state_version": "string",
  "expected_state_version": "string | null",
  "allowed_mutations": [
    {
      "target_ref": "string (dot-path into state tree)",
      "operator": "set | increment | decrement | append | remove | create | delete",
      "value": "any"
    }
  ],
  "forbidden_effects": [
    "out_of_scope_mutation",
    "implicit_resource_creation",
    "visibility_escalation",
    "unapproved_side_effect"
  ],
  "expiry": "ISO-8601 timestamp | null",
  "idempotency_key": "string"
}
```

`allowed_mutations` is exhaustive. Any mutation not listed is a contract violation.

---

## State Version Metadata

```json
{
  "state_version": "string",
  "state_hash": "string (SHA-256 of deterministic serialization)",
  "timestamp": "ISO-8601",
  "parent_version": "string | null"
}
```

Genesis version has `parent_version: null`. Every commit produces a new version.

---

## Verification Receipt

```json
{
  "verification_id": "string (UUID)",
  "proposal_id": "string",
  "execution_id": "string",
  "pre_state_version": "string",
  "actual_state_version": "string",
  "expected_hash": "string",
  "actual_hash": "string",
  "verified_fields": ["dot-path"],
  "result": "pass | fail",
  "failure_reasons": ["string"]
}
```

`result: fail` triggers rollback or quarantine. Receipt is recorded regardless.

---

## Execution History Entry

```json
{
  "execution_id": "string",
  "proposal_id": "string",
  "pre_state_version": "string",
  "post_state_version": "string",
  "idempotency_key": "string",
  "timestamp": "ISO-8601",
  "verification_result": "pass | fail"
}
```

Stored in `state_manager.history`. Never deleted. Provides trace continuity across cycles.

---

## State Tree Structure

```
state/
  <domain>/
    <resource_type>/
      <resource_id>/
        <field>: value
  system/
    capabilities/
      <capability_id>/: Capability
    constraints/
      <constraint_id>/: Constraint
    registry/
      <binding_id>/: Binding
```

Paths are `/`-delimited. Each node is a JSON object. State is versioned at the root.

---

## Derived Field Contract

Derived fields are computed by `state_manager.derive(proposal, pre_state)` before validation. They are ephemeral — not stored in the state tree. They are available to constraint predicates via the `derived.` prefix.

Standard derived fields:

| Field | Computation | Example |
|---|---|---|
| `balance_after` | `pre_state.balance + proposal.parameters.delta` | Financial transfer |
| `visibility_after` | `merge(pre_state.visibility, proposal.parameters.visibility_change)` | Permissions update |
| `effective_scope` | `intersect(policy_scope, target_scope)` | Scope resolution |
| `quota_remaining` | `pre_state.quota_limit - pre_state.quota_used` | Rate limiting |

New derived fields require a GOVERN proposal (same validation pipeline).
