from dataclasses import dataclass, asdict
from typing import Any, Dict


@dataclass(slots=True)
class GeneratedRule:
    rule_id: str
    vulnerability_type: str
    confidence: float
    pattern_name: str
    metadata: Dict[str, Any] | None = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

