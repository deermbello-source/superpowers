"""
Metabolic closure — every governed subsystem runs this sequence.
No handoff until the loop is closed. Unclosed process = downstream drift.
"""

from typing import Any, Dict, Optional


class SourceLoop:
    """
    Base for every BRCM subsystem. Override read / frame / decide / emit.
    run() enforces the full closure before returning. Partial exits are blocked.
    """

    def read(self, input_data: Any) -> Dict:
        return {"input": input_data}

    def frame(self, body: Dict) -> Dict:
        return body

    def decide(self, framed: Dict) -> str:
        return "PASS"

    def emit(self, decision: str, framed: Dict) -> Any:
        return framed

    def invariant(self, output: Any) -> bool:
        return output is not None

    def drift(self, output: Any) -> Optional[str]:
        return None

    def run(self, input_data: Any) -> Dict:
        self._open = False

        body     = self.read(input_data)
        framed   = self.frame(body)
        decision = self.decide(framed)
        output   = self.emit(decision, framed)
        ok       = self.invariant(output)
        d        = self.drift(output)

        self._open = True

        if not ok or d:
            return {
                "status":   "DRIFT",
                "drift":    d or "invariant_violation",
                "output":   None,
                "decision": decision,
            }

        return {
            "status": decision,
            "output": output,
            "drift":  None,
            "closed": True,
        }

    @property
    def is_closed(self) -> bool:
        return getattr(self, "_open", True)
