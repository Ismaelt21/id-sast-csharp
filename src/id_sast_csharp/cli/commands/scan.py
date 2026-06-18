from id_sast_csharp.core.models.scan_request import ScanRequest
from id_sast_csharp.core.services.csharp_sast_service import CSharpSastService


def run_scan(
    project_path: str,
    use_ai: bool = True,
    verbose: bool = False,
    persist: bool = True,
    json_only: bool = False,
    html_only: bool = False,
    sarif_only: bool = False,
    output_directory: str | None = None,
) -> dict:
    service = CSharpSastService()
    result = service.scan(
        ScanRequest(
            project_path=project_path,
            use_ai=use_ai,
            verbose=verbose,
            persist=persist,
            json_only=json_only,
            html_only=html_only,
            sarif_only=sarif_only,
            output_directory=output_directory,
        )
    )
    return result.to_dict()
