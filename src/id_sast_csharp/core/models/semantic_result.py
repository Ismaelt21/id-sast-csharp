from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional


@dataclass(slots=True)
class SemanticAnalysisResult:
    vulnerability_detected: bool
    classification: str
    confidence: float
    reasoning: str
    mitigation_detected: bool = False
    mitigation_type: Optional[str] = None
    metadata: Dict[str, Any] | None = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

