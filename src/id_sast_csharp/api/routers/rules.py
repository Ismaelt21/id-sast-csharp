from fastapi import APIRouter

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("")
def list_rules() -> dict:
    return {"items": [], "total": 0}


@router.get("/stats")
def stats() -> dict:
    return {"total_rules": 0, "validated_rules": 0, "unvalidated_rules": 0}

