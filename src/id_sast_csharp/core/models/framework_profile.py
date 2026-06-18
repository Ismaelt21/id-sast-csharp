from dataclasses import dataclass, asdict
from typing import Any, Dict


@dataclass(slots=True)
class FrameworkProfile:
    name: str
    confidence: float = 0.0
    metadata: Dict[str, Any] | None = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

