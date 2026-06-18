from fastapi import APIRouter, HTTPException

from id_sast_csharp.api.schemas.scan import ScanRequestSchema, ScanResponseSchema
from id_sast_csharp.core.models.scan_request import ScanRequest
from id_sast_csharp.core.pipeline.analysis_pipeline import AnalysisPipeline
from id_sast_csharp.core.services.csharp_sast_service import CSharpSastService

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("", response_model=ScanResponseSchema)
def scan(payload: ScanRequestSchema) -> ScanResponseSchema:
    service = CSharpSastService()

    try:
        result = service.scan(
            ScanRequest(
                project_path=payload.project_path,
                use_ai=payload.use_ai,
                persist=payload.persist,
                json_only=payload.json_only,
                html_only=payload.html_only,
                sarif_only=payload.sarif_only,
                verbose=payload.verbose,
                output_directory=payload.output_directory,
            )
    )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return ScanResponseSchema(**result.to_dict())


@router.get("/{scan_id}", response_model=ScanResponseSchema)
def get_scan(scan_id: str) -> ScanResponseSchema:
    pipeline = AnalysisPipeline()

    try:
        result = pipeline.load_scan(scan_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return ScanResponseSchema(**result.to_dict())
