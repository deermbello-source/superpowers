"""
BRCM CLI — Entry point for the governed generative agent

Usage:
  python3 runtime/cli.py [--workspace ./workspace] [--config ./system/config.json]

Input: natural language (if Ollama running) or raw JSON step(s).

Special commands:
  /status   — show canonical state stats and agent state
  /history  — show recent canonical receipts
  /help     — show this message
  /quit     — exit
"""

import argparse
import json
import sys
from pathlib import Path

# Ensure system/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from runtime.agent import BRCMAgent, DEFAULT_AGENT_CONFIG


HELP_TEXT = """
Bell Recursive Constitutional Metabolism — Governed Generative Agent

Input types:
  Natural language    : "write a python script that prints hello world"
  Single JSON step    : {"action_type": "file_write", "parameters": {...}, "parameters_complete": true}
  JSON step array     : [{"action_type": "..."}, ...]

Commands:
  /status             — canonical state stats
  /history [n]        — last n canonical receipts (default 10)
  /help               — this message
  /quit               — exit

Supported action_types:
  file_read, file_write, file_list, file_delete, file_copy, file_move, file_search
  dir_create, dir_delete
  json_read, json_write, csv_read, csv_write
  shell_run, http_get, http_post
  git_status, git_diff, git_log
  math_eval, hash_compute, template_render, env_read
""".strip()


def _fmt_result(result: dict) -> str:
    status = result.get("status", "?")

    if status == "BLOCKED":
        layer  = result.get("layer", "")
        reason = result.get("reason", "")
        at     = result.get("blocked_at", "")
        lines  = [f"BLOCKED [{layer}]"]
        if at:
            lines.append(f"  at step {at}")
        if reason:
            lines.append(f"  reason: {reason}")
        committed = result.get("committed", [])
        if committed:
            lines.append(f"  {len(committed)} step(s) committed before block")
        return "\n".join(lines)

    if status == "CLARIFY":
        layer    = result.get("layer", "")
        question = result.get("question", "")
        return f"CLARIFY [{layer}]\n  {question}"

    if status == "COMPLETE":
        steps     = result.get("steps_run", 0)
        committed = result.get("committed", [])
        blocked   = result.get("blocked", [])
        canon     = result.get("canonical", {})
        lines     = [f"COMPLETE — {steps} step(s) run"]
        lines.append(f"  committed : {len(committed)}")
        if blocked:
            lines.append(f"  blocked   : {len(blocked)}")
        if canon:
            lines.append(f"  canonical : {canon.get('total_receipts', 0)} total receipts")
        for c in committed:
            lines.append(f"    step {c['step']}: {c['action']} ✓")
        return "\n".join(lines)

    if status == "DRIFT":
        return f"DRIFT — {result.get('output', '')}"

    return json.dumps(result, indent=2)


def run_cli(workspace: str, bgp_config: str = None):
    cfg = {
        **DEFAULT_AGENT_CONFIG,
        "workspace":    workspace,
        "canonical_db": str(Path(workspace).parent / "canonical.db"),
    }
    if bgp_config:
        cfg["bgp_config"] = bgp_config

    print("Bell Recursive Constitutional Metabolism")
    print(f"workspace : {workspace}")
    print(f"canonical : {cfg['canonical_db']}")
    print("Type /help for commands. Ctrl-C or /quit to exit.\n")

    try:
        agent = BRCMAgent(config=cfg)
    except Exception as e:
        print(f"ERROR: Failed to boot agent: {e}")
        sys.exit(1)

    while True:
        try:
            line = input("brcm> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not line:
            continue

        if line == "/quit":
            print("Exiting.")
            break

        if line == "/help":
            print(HELP_TEXT)
            continue

        if line == "/status":
            s = agent.status()
            print(json.dumps(s, indent=2))
            continue

        if line.startswith("/history"):
            parts = line.split()
            n     = int(parts[1]) if len(parts) > 1 else 10
            rows  = agent.canonical.get_history(limit=n)
            if not rows:
                print("No canonical receipts yet.")
            else:
                for r in rows:
                    ok = "✓" if r["result_ok"] else "✗"
                    print(f"  {ok} {r['action_type']:20s}  {r['proposal_id'][:12]}  v={r['post_version'][:8]}")
            continue

        # Run the agent loop
        try:
            result = agent.run(line)
            print(_fmt_result(result))
        except Exception as e:
            print(f"ERROR: {e}")
            import traceback
            traceback.print_exc()

        print()


def main():
    parser = argparse.ArgumentParser(
        description="BRCM — Bell Recursive Constitutional Metabolism",
    )
    parser.add_argument(
        "--workspace", default="./workspace",
        help="Working directory for file operations (default: ./workspace)",
    )
    parser.add_argument(
        "--config", default=None,
        help="Path to BGP config.json (default: system/config.json)",
    )
    args = parser.parse_args()

    workspace = Path(args.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    run_cli(workspace=str(workspace), bgp_config=args.config)


if __name__ == "__main__":
    main()
