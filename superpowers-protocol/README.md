# Superpowers Closed Workflow Protocol

A strict execution protocol layer that constrains how Superpowers operates on repositories. This is not an app, not a chatbot, and not an autonomous agent. It is a specification that enforces state discipline on every workflow.

## The Core Invariant

> Superpowers cannot be governed from the inside. Therefore every input it receives must already be shaped like a bounded execution packet.

Not: *Do the work.*

Instead: *Consume this artifact. Act inside this boundary. Produce this artifact. Validate this way. Route failure here. Write the receipt. Stop.*

---

## Directory Layout

```
superpowers-protocol/
├── README.md                    ← this file
├── protocol.yaml                ← root index; all paths discovered from here
├── states/
│   ├── state_machine.yaml       ← canonical FSM; all skills reference these state names
│   └── failure_routing.yaml    ← failure class → blocked state → required action
├── schemas/                     ← JSON Schema Draft-07; all artifacts validated here
│   ├── goal.schema.json
│   ├── context_lock.schema.json
│   ├── capability_evidence.schema.json
│   ├── execution_contract.schema.json
│   ├── task_queue.schema.json
│   ├── validation_rules.schema.json
│   ├── execution_result.schema.json
│   ├── validation_report.schema.json
│   ├── repair_task.schema.json
│   ├── receipt.schema.json
│   ├── promotion_record.schema.json
│   ├── lock.schema.json
│   └── handoff_check.schema.json
├── skills/                      ← YAML skill cards (not SKILL.md format)
│   ├── 00_goal_intake.yaml
│   ├── 01_repo_discovery.yaml
│   ├── 02_capability_evidence.yaml
│   ├── 03_contract_builder.yaml
│   ├── 04_task_queue_builder.yaml
│   ├── 05_validation_rule_builder.yaml
│   ├── 06_controlled_execution.yaml
│   ├── 07_validation_runner.yaml
│   ├── 08_repair_planner.yaml
│   ├── 09_receipt_writer.yaml
│   ├── 10_promotion_gate.yaml
│   └── 11_handoff_checker.yaml
├── workflows/
│   ├── repo_assimilation.workflow.yaml
│   ├── feature_build.workflow.yaml
│   ├── bug_fix.workflow.yaml
│   ├── schema_change.workflow.yaml
│   ├── dependency_change.workflow.yaml
│   ├── documentation.workflow.yaml
│   ├── uv_texture_asset.workflow.yaml
│   └── reference_to_blender.workflow.yaml
├── job_packets/                 ← runtime; job packet folders created here
└── receipts/                    ← runtime; append-only receipt files written here
```

---

## The Seven Protocol Laws

1. **State gate.** A skill cannot run unless `current_state` matches `state_gate.required_current_state` in `states/state_machine.yaml`.

2. **No trust by default.** Every repo starts as `read_only`. Trust is only elevated after repo assimilation produces a validated `trust_profile`.

3. **Evidence required.** No capability is usable unless evidence exists: `file_exists | readme | package_script | exported_function | cli_command | test_file | schema | config | folder_pattern`.

4. **Three-phase write gate.** No write workflow executes directly. Every write must pass: `plan_only → validate_plan → live_write`. Skill `06_controlled_execution` enforces this.

5. **No silent fallbacks.** If the selected method fails and no approved fallback is listed in the execution contract, the workflow routes to `BLOCKED_EXECUTION`. The agent does not switch approaches on its own.

6. **Deterministic artifact naming.** Every artifact must be named: `{job_id}_{step_number}_{artifact_type}_v{version}.{ext}`. The regex is enforced in `schemas/receipt.schema.json`.

7. **Receipts are append-only.** A finalized receipt cannot be edited. Corrections require an amendment receipt with a new `receipt_sequence_number`.

---

## State Machine Summary

```
DRAFT → INTAKE_LOCKED → CAPABILITY_MAPPED → CONTRACT_READY → TASK_READY
      → EXECUTING → VALIDATING → REPAIR_REQUIRED → REPAIRING
      → VALIDATED → PROMOTED → RECEIPTED

Blocked exits (terminal without human intervention):
  DRAFT              → BLOCKED_INTAKE
  CAPABILITY_MAPPED  → BLOCKED_CAPABILITY
  CONTRACT_READY     → BLOCKED_CONTRACT
  EXECUTING          → BLOCKED_EXECUTION
  VALIDATING         → BLOCKED_VALIDATION
  REPAIRING          → BLOCKED_REPAIR
  (any state)        → HUMAN_REVIEW
```

Full transition table: `states/state_machine.yaml`
Failure routing table: `states/failure_routing.yaml`

---

## Running a Workflow

1. Create a job packet directory: `job_packets/{job_id}/`
2. Write `{job_id}_00_goal_v1.json` conforming to `schemas/goal.schema.json`
3. Select a workflow from `workflows/` matching the `goal.workflow_type`
4. Execute skills in `skill_sequence[]` order, starting with `00_goal_intake`
5. Between skills where `handoff_validations[]` requires it, run `11_handoff_checker`
6. After each state transition listed in `receipt_required_at[]`, run `09_receipt_writer`
7. After `VALIDATED`, run `10_promotion_gate` — human approval required before `PROMOTED`

---

## Artifact Naming Examples

```
job_0001_00_goal_v1.json
job_0001_01_context_lock_v1.json
job_0001_02_capability_evidence_v1.json
job_0001_03_execution_contract_v1.json
job_0001_04_task_queue_v1.json
job_0001_05_validation_rules_v1.json
job_0001_06_execution_result_task01_v1.json
job_0001_07_validation_report_v1.json
job_0001_receipt_v1.json
job_0001_receipt_amendment_v1.json
```

Repair increments the patch version. Feature extension increments minor. Breaking schema change increments major.

---

## Definition of Done Per Layer

**Goal done:** Artifact exists. Target output is testable. Unknowns listed. Non-goals listed. Assumptions locked.

**Capability done:** Evidence exists. Safe use defined. Required inputs known. Expected outputs known. Trust profile assigned.

**Contract done:** Authorized repos listed. Write paths listed. Forbidden paths listed. Commands listed. Failure routing listed. Success definition listed.

**Task done:** Preconditions listed. Action is atomic. Expected output listed. Validation linked. Routing defined.

**Execution done:** Expected output produced. No forbidden path touched. Commands logged. Assumptions logged. Result artifact produced.

**Validation done:** All checks run. Failures classified. Repair/block/pass route selected. No ambiguous status.

**Receipt done:** Final status stated. Outputs listed. Constraints preserved/broken listed. Drift listed. Next action stated.
