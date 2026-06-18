from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from id_sast_csharp.api.app import app


def test_scan_endpoint_returns_real_results(tmp_path: Path) -> None:
    client = TestClient(app)
    root = Path(__file__).resolve().parents[2]
    sample_project = root / "tests" / "samples" / "demo"

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
    assert payload["status"] == "completed"
    assert payload["project_name"] == "demo"
    assert payload["files_scanned"] == 2
    assert payload["findings_count"] == 7
    assert payload["critical"] == 1
    assert payload["high"] == 3
    assert payload["medium"] == 2
    assert payload["low"] == 1
    assert payload["framework"] == "aspnetcore"
    assert payload["reports"]["json"]
    assert len(payload["findings"]) == 7
    assert payload["findings"][0]["id"]
    assert payload["findings"][0]["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
