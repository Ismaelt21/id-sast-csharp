from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class ScanRequest:
    project_path: str
    use_ai: bool = True
    persist: bool = True
    json_only: bool = False
    html_only: bool = False
    sarif_only: bool = False
    verbose: bool = False
    output_directory: str | None = None

    def resolved_project_path(self) -> Path:
        return Path(self.project_path).resolve()

