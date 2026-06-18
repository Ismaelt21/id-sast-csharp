from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass(slots=True)
class RoslynAnalysisRequest:
    project_path: str
    files: List[str] | None = None


class RoslynBridgeClient:
    """
    Adapter placeholder for the Roslyn bridge.

    The current scaffold keeps the legacy analysis path alive.
    Later we can replace this adapter with a direct HTTP client
    to the bridge service or a local process manager.
    """

    def analyze_project(self, request: RoslynAnalysisRequest) -> Dict[str, Any]:
        return {
            "project_path": request.project_path,
            "files": request.files or [],
            "status": "not_implemented",
        }

