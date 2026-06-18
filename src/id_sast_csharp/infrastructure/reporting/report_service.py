from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from id_sast_csharp.infrastructure.config.settings import Settings


class ReportService:
    def __init__(self, output_dir: str | None = None):
        self.output_dir = Path(output_dir) if output_dir else Settings.REPORTS_DIR

    def ensure_output_dir(self) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        return self.output_dir

    def summarize(self, report: Dict[str, Any]) -> Dict[str, Any]:
        self.ensure_output_dir()
        return {
            "json": report.get("json_path"),
            "html": report.get("html_path"),
            "sarif": report.get("sarif_path"),
        }

    def find_report_path(self, scan_id: str) -> Path | None:
        self.ensure_output_dir()

        scan_id = scan_id.strip()
        if not scan_id:
            return None

        short_id = scan_id[:8]
        patterns = [
            f"*_{short_id}.json",
            f"*{short_id}*.json",
        ]

        for pattern in patterns:
            for path in sorted(self.output_dir.rglob(pattern)):
                loaded = self._load_json(path)
                if loaded.get("scan_id") == scan_id:
                    return path

        for path in sorted(self.output_dir.rglob("*.json")):
            loaded = self._load_json(path)
            if loaded.get("scan_id") == scan_id:
                return path

        return None

    def load_report(self, scan_id: str) -> tuple[Dict[str, Any], Path] | None:
        report_path = self.find_report_path(scan_id)
        if not report_path:
            return None
        return self._load_json(report_path), report_path

    def _load_json(self, path: Path) -> Dict[str, Any]:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
