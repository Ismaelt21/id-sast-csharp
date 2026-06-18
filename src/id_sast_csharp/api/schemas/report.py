from typing import Any, Dict, List

from pydantic import BaseModel


class ReportResponse(BaseModel):
    metadata: Dict[str, Any]
    project: Dict[str, Any]
    statistics: Dict[str, Any]
    findings: List[Dict[str, Any]]

