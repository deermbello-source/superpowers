"""
Canonical State — SQLite-backed, append-only

Only results that have passed BGP validation and verification are recorded here.
Canonical state is the architecture's authoritative truth surface.
It is never written to directly — only through record_receipt().

Tables:
  receipts        — every COMMITTED execution
  canonical_files — file content hashes for committed writes
  governance_log  — GOVERN proposals and outcomes
"""

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .source_loop import SourceLoop


class CanonicalState(SourceLoop):

    def __init__(self, db_path: str = "./canonical.db"):
        super().__init__()
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS receipts (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    proposal_id       TEXT NOT NULL,
                    action_type       TEXT NOT NULL,
                    parameters_hash   TEXT NOT NULL,
                    idempotency_key   TEXT NOT NULL UNIQUE,
                    pre_version       TEXT NOT NULL,
                    post_version      TEXT NOT NULL,
                    result_ok         INTEGER NOT NULL,
                    result_summary    TEXT,
                    recorded_at       REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS canonical_files (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    path         TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    version      TEXT NOT NULL,
                    recorded_at  REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS governance_log (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    proposal_id  TEXT NOT NULL,
                    action_type  TEXT NOT NULL,
                    outcome      TEXT NOT NULL,
                    detail       TEXT,
                    recorded_at  REAL NOT NULL
                );
            """)

    # ------------------------------------------------------------------
    # Governed write path
    # ------------------------------------------------------------------

    def read(self, input_data: Any) -> Dict:
        return {"result": input_data}

    def frame(self, body: Dict) -> Dict:
        result = body["result"]
        valid  = (
            isinstance(result, dict)
            and result.get("status") == "COMMITTED"
            and "proposal" in result
            and "version" in result
        )
        return {
            "result":   result,
            "is_valid": valid,
            "reason":   None if valid else (
                f"Non-committed result blocked: "
                f"status={result.get('status') if isinstance(result, dict) else 'unknown'}"
            ),
        }

    def decide(self, framed: Dict) -> str:
        return "WRITE" if framed["is_valid"] else "REJECT"

    def emit(self, decision: str, framed: Dict) -> Optional[Dict]:
        if decision != "WRITE":
            return None

        result   = framed["result"]
        exec_res = result.get("result", {})
        action   = result.get("_action_type", "unknown")
        params   = result.get("_parameters", {})
        ikey     = result.get("_idempotency_key", "")
        pre_ver  = result.get("_pre_version", "")
        summary  = self._summarize(exec_res)

        with self._connect() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO receipts
                (proposal_id, action_type, parameters_hash, idempotency_key,
                 pre_version, post_version, result_ok, result_summary, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result["proposal"],
                action,
                hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest(),
                ikey,
                pre_ver,
                result["version"],
                1 if exec_res.get("ok") else 0,
                summary,
                time.time(),
            ))

            if action == "file_write" and exec_res.get("ok"):
                path         = params.get("path", "")
                content      = params.get("content", "")
                content_hash = hashlib.sha256(content.encode()).hexdigest()
                conn.execute("""
                    INSERT INTO canonical_files (path, content_hash, version, recorded_at)
                    VALUES (?, ?, ?, ?)
                """, (path, content_hash, result["version"], time.time()))

        return {"recorded": True, "proposal_id": result["proposal"], "version": result["version"]}

    def invariant(self, output: Any) -> bool:
        return output is None or isinstance(output, dict)

    def drift(self, output: Any) -> Optional[str]:
        return None

    # ------------------------------------------------------------------
    # Query interface
    # ------------------------------------------------------------------

    def record_receipt(self, bgp_result: Dict, action_type: str,
                       parameters: Dict, idempotency_key: str,
                       pre_version: str) -> Dict:
        """The only path by which results enter canonical truth."""
        enriched = {
            **bgp_result,
            "_action_type":     action_type,
            "_parameters":      parameters,
            "_idempotency_key": idempotency_key,
            "_pre_version":     pre_version,
        }
        return self.run(enriched)

    def get_history(self, action_type: str = None, limit: int = 20) -> List[Dict]:
        with self._connect() as conn:
            if action_type:
                rows = conn.execute(
                    "SELECT * FROM receipts WHERE action_type=? ORDER BY recorded_at DESC LIMIT ?",
                    (action_type, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM receipts ORDER BY recorded_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_canonical_file(self, path: str) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM canonical_files WHERE path=? ORDER BY recorded_at DESC LIMIT 1",
                (path,),
            ).fetchone()
        return dict(row) if row else None

    def is_committed(self, idempotency_key: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM receipts WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
        return row is not None

    def log_governance(self, proposal_id: str, action_type: str,
                       outcome: str, detail: str = None):
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO governance_log (proposal_id, action_type, outcome, detail, recorded_at)
                VALUES (?, ?, ?, ?, ?)
            """, (proposal_id, action_type, outcome, detail, time.time()))

    def stats(self) -> Dict:
        with self._connect() as conn:
            total     = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
            committed = conn.execute("SELECT COUNT(*) FROM receipts WHERE result_ok=1").fetchone()[0]
            files     = conn.execute("SELECT COUNT(*) FROM canonical_files").fetchone()[0]
            gov       = conn.execute("SELECT COUNT(*) FROM governance_log").fetchone()[0]
        return {
            "total_receipts":  total,
            "committed":       committed,
            "canonical_files": files,
            "governance_log":  gov,
            "db_path":         str(self._db_path),
        }

    def _summarize(self, exec_result: Dict) -> str:
        if not exec_result:
            return ""
        if "content"  in exec_result: return f"read:{len(exec_result['content'])}b"
        if "entries"  in exec_result: return f"listed:{len(exec_result['entries'])}entries"
        if "stdout"   in exec_result: return exec_result["stdout"].strip()[:100]
        if "result"   in exec_result: return str(exec_result["result"])[:100]
        if "hash"     in exec_result: return f"hash:{exec_result['hash'][:16]}"
        return "ok"
