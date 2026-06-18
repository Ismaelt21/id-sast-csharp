from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ScanRequestSchema(BaseModel):
    project_path: str = Field(..., description="Path to the C# project to analyze")
    use_ai: bool = True
    persist: bool = True
    json_only: bool = False
    html_only: bool = False
    sarif_only: bool = False
    verbose: bool = False
    output_directory: Optional[str] = None


class ScanResponseSchema(BaseModel):
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
    reports: Dict[str, str] = Field(default_factory=dict)
    findings: list[Dict[str, Any]] = Field(default_factory=list)
    ai: Dict[str, Any] = Field(default_factory=dict)
    database: Dict[str, Any] = Field(default_factory=dict)
    report: Dict[str, Any] = Field(default_factory=dict)
    report_path: Optional[str] = None
