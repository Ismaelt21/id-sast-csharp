from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from id_sast_csharp.api.app import app


def test_scan_endpoint_detects_path_traversal_sample(tmp_path: Path) -> None:
    client = TestClient(app)
    root = Path(__file__).resolve().parents[2]
    sample_project = root / "tests" / "samples" / "path_traversal"

    response = client.post(
        "/scan",
        json={
            "project_path": str(sample_project),
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

    assert "PATH_TRAVERSAL" in vulnerability_kinds
    assert payload["findings_count"] >= 1
