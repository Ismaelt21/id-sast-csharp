from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from id_sast_csharp.api.app import app


def test_scan_get_endpoint_returns_persisted_result() -> None:
    client = TestClient(app)
    root = Path(__file__).resolve().parents[2]
    sample_project = root / "tests" / "samples" / "demo"

    post_response = client.post(
        "/scan",
        json={
            "project_path": str(sample_project),
            "use_ai": False,
            "persist": False,
            "json_only": True,
            "html_only": False,
            "sarif_only": False,
            "verbose": False,
        },
    )

    assert post_response.status_code == 200, post_response.text
    scan_id = post_response.json()["scan_id"]

    get_response = client.get(f"/scan/{scan_id}")
    assert get_response.status_code == 200, get_response.text

    payload = get_response.json()
    assert payload["scan_id"] == scan_id
    assert payload["project_name"] == "demo"
    assert payload["findings_count"] == 7
    assert payload["report"]["scan_id"] == scan_id
    assert payload["report"]["summary"]["total_vulnerabilities"] == 7
    assert len(payload["report"]["vulnerabilities"]) == 7
