---
name: bell-governance-protocol
description: Use when you need a deterministic governance layer between an LLM and real system operations—where the model proposes, constraints validate, and a deterministic executor commits only what was approved.
---

# Bell Governance Protocol

## Overview

The model proposes. The law validates. A deterministic executor commits. The model cannot select constraints, cannot execute, cannot verify.

**The core insight:** Code can govern code when the governed thing is deterministic. An LLM cannot be governed at generation — only its output can be filtered. So the LLM is placed at the proposal formation layer only. Everything below it is deterministic and real.

This is the same architecture as BlackRock's Aladdin: portfolio manager (or model) proposes a trade → constraints from the mandate evaluate it → approved trades go to the execution layer → post-trade verification.

**Announce at start:** "I'm using the bell-governance-protocol skill."

## What Belongs at Each Layer

| Layer | Who/What | What it cannot do |
|---|---|---|
| Proposal formation | LLM | Select constraints, execute, modify state |
| Constraint registry | Closed config | Be modified without a GOVERN proposal |
| Predicate evaluation | Deterministic engine | Infer, guess, approximate |
| Executor | Real file/shell/API ops | Execute unapproved mutations |
| Verification | Hash comparison | Accept divergent state |

## Running the System

```bash
# From the skill directory
python3 system/bgp.py --workspace ./workspace

# With custom config
python3 system/bgp.py --workspace ./workspace --config ./system/config.json
```

Input is natural language (if Ollama is running) or raw JSON:

```json
{"action_type": "file_write", "parameters": {"path": "workspace/notes.txt", "content": "hello"}, "parameters_complete": true}
```

## Supported Action Types

| Action | Required Parameters |
|---|---|
| `file_read` | `path` |
| `file_write` | `path`, `content` |
| `file_list` | `path` |
| `file_delete` | `path` |
| `shell_run` | `command`, `args[]` |
| `govern` | (modify config/constraints via proposal) |

## Configuration (`config.json`)

```json
{
  "allowed_write_dirs":          ["./workspace"],
  "allowed_read_dirs":           ["./workspace"],
  "allowed_commands":            ["echo", "ls", "python", "git"],
  "max_file_size_bytes":         1048576,
  "max_command_timeout_seconds": 30,
  "ollama_url":                  "http://127.0.0.1:11434",
  "ollama_model":                "llama3.2"
}
```

The constraint layer reads these values. Changing them changes what is legally permitted. The model never reads this config directly.

## Adding Constraints

Drop a JSON file in `system/constraints/`. Format:

```json
[
  {
    "constraint_id": "my_constraint",
    "scope": "derived",
    "field": "derived.my_derived_field",
    "operator": "eq",
    "value": true,
    "severity": "critical",
    "on_fail": "block",
    "description": "Human-readable reason shown on block"
  }
]
```

Operators: `eq`, `neq`, `gte`, `lte`, `gt`, `lt`, `in`, `not_in`, `exists`, `not_exists`.

Add a binding in `ConstraintRegistry.build()` to attach the constraint to specific action types.

## What the Model Is Not Allowed to Do

The LLM sits in `build_proposal()`. It receives natural language and returns:

```json
{"action_type": "...", "parameters": {...}, "parameters_complete": true}
```

That is everything it touches. The model cannot:
- Read or modify `config.json`
- Choose which constraints apply
- Call the executor directly
- Mark its own output as approved
- Skip verification

## Why This Works Where Llama3.2 + 478 "Capabilities" Did Not

The previous approach registered 478 capability names and asked the model to pretend it could invoke them. The model cooperated — until it didn't. Cooperation is not constraint.

This system doesn't ask the model to cooperate. The model produces a structured JSON blob. If the blob passes constraints, a real Python function runs. If not, it is blocked. The model's willingness is irrelevant.

**Governance of deterministic operations is real governance.**
Governance of a generative model's outputs is filtering, not governance.

## Files

```
system/
  bgp.py              complete implementation (all seven layers)
  config.json         allowed dirs, commands, timeouts
  constraints/
    global.json       universal constraints (action_type, state_version, completeness)
    file_ops.json     path allowlist, traversal detection, size limits
    shell_ops.json    command whitelist, injection detection, timeout
  workspace/          default working directory for file operations
```
