from __future__ import annotations

from id_sast_csharp.core.models.scan_request import ScanRequest
from id_sast_csharp.core.models.scan_result import ScanResult
from id_sast_csharp.core.pipeline.analysis_pipeline import AnalysisPipeline


class CSharpSastService:
    """
    Facade used by API and CLI.
    """

    def __init__(self, pipeline: AnalysisPipeline | None = None):
        self._pipeline = pipeline or AnalysisPipeline()

    def scan(self, request: ScanRequest) -> ScanResult:
        return self._pipeline.run(request)

