from fastapi import APIRouter

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.get("/stats")
def stats() -> dict:
    return {"total_scans": 0, "total_vulnerabilities": 0}

