"""Global search router."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.services.search_service import global_search

router = APIRouter()


@router.get("/search")
def search(q: str = Query(..., min_length=1, max_length=200), db: Session = Depends(get_db)):
    hits = global_search(db, q)
    return {"query": q, "total": len(hits), "items": hits}
