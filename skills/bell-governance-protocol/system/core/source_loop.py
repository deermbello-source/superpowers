"""
Source Loop — N → B → F → C → R → I → D → N

The universal metabolic closure law.
Every subsystem inherits this. No handoff without loop closure.
Unclosed process = unresolved debt = downstream drift.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class SourceLoop(ABC):
    """
    Base class for every BRCM subsystem.
    Enforces: enter_null → read_body → apply_frame → collapse →
              return_output → verify_invariant → detect_drift → reset

    Subclasses implement the phase methods.
    run() enforces the full sequence and blocks partial handoff.
    """

    def __init__(self):
        self._phase  = "NULL"
        self._closed = True

    # ------------------------------------------------------------------
    # Phase methods — override in subclasses
    # ------------------------------------------------------------------

    def enter_null(self, input_data: Any) -> None:
        """N: Enter unresolved potential. Wait for lawful trigger."""
        pass

    @abstractmethod
    def read_body(self, input_data: Any) -> Dict:
        """B: Read bounded local state necessary for this operation."""
        ...

    @abstractmethod
    def apply_frame(self, body: Dict) -> Dict:
        """F: Apply constraint frame — what matters, what is forbidden."""
        ...

    @abstractmethod
    def collapse(self, framed: Dict) -> str:
        """C: Collapse to one lawful decision: APPROVED/BLOCKED/CLARIFY/etc."""
        ...

    @abstractmethod
    def return_output(self, decision: str, framed: Dict) -> Any:
        """R: Produce the concrete return value for the decision."""
        ...

    def verify_invariant(self, output: Any) -> bool:
        """I: Verify that the subsystem's structure was preserved."""
        return output is not None

    def detect_drift(self, output: Any) -> Optional[str]:
        """D: Detect mismatch. Return drift description or None."""
        return None

    def reset(self) -> None:
        """N: Return to lawful stillness."""
        self._phase = "NULL"

    # ------------------------------------------------------------------
    # run() — enforces full loop closure
    # ------------------------------------------------------------------

    def run(self, input_data: Any) -> Dict:
        """
        Execute the full N→B→F→C→R→I→D→N cycle.
        No partial return. No short-circuit exit.
        Only closed loops may hand off.
        """
        self._closed = False

        # N — enter null
        self._phase = "NULL"
        self.enter_null(input_data)

        # B — read body
        self._phase = "BODY"
        body = self.read_body(input_data)

        # F — apply frame
        self._phase = "FRAME"
        framed = self.apply_frame(body)

        # C — collapse
        self._phase = "COLLAPSE"
        decision = self.collapse(framed)

        # R — return output
        self._phase = "RETURN"
        output = self.return_output(decision, framed)

        # I — verify invariant
        self._phase = "INVARIANT"
        invariant_holds = self.verify_invariant(output)

        # D — detect drift
        self._phase = "DRIFT"
        drift = self.detect_drift(output)

        # N — reset
        self._phase = "NULL"
        self.reset()
        self._closed = True

        if not invariant_holds or drift:
            return {
                "status":   "DRIFT",
                "phase":    self._phase,
                "drift":    drift or "invariant_violation",
                "output":   None,
                "decision": decision,
            }

        return {
            "status":   decision,
            "output":   output,
            "drift":    None,
            "closed":   True,
        }

    @property
    def is_closed(self) -> bool:
        return self._closed
