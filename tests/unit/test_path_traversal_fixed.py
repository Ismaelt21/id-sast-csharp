from __future__ import annotations

import shutil
from pathlib import Path

from fastapi.testclient import TestClient

from id_sast_csharp.api.app import app


def test_fixed_path_traversal_sample_does_not_report_path_traversal(tmp_path: Path) -> None:
    client = TestClient(app)
    root = Path(__file__).resolve().parents[2]

    sample_dir = tmp_path / "fixed_path_sample"
    sample_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / "tests" / "samples" / "path_traversal" / "FixedFileController.cs", sample_dir)

    response = client.post(
        "/scan",
        json={
            "project_path": str(sample_dir),
            "use_ai": False,
            "persist": False,
            "json_only": True,
            "html_only": False,
            "sarif_only": False,
            "verbose": False,
            "output_directory": str(tmp_path / "reports"),
        },
    )

    assert response.status_code == 200, response.text

    payload = response.json()
    vulnerability_kinds = {finding["vulnerability"] for finding in payload["findings"]}

    assert "PATH_TRAVERSAL" not in vulnerability_kinds
    assert "CSRF" in vulnerability_kinds
