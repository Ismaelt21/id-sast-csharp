from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass(slots=True)
class ScanResult:
    scan_id: str
    status: str
    project_name: str
    files_scanned: int
    findings_count: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    framework: Optional[str] = None
    reports: Dict[str, str] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    ai: Dict[str, Any] = field(default_factory=dict)
    database: Dict[str, Any] = field(default_factory=dict)
    report: Dict[str, Any] = field(default_factory=dict)
    report_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
