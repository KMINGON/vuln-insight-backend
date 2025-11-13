from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.db import get_session
from api.repositories.cve_repo import CVERepository
from api.services.cve_service import CVEService

router = APIRouter(prefix="/api/v1/cve", tags=["CVE"])

@router.get("/recent")
async def recent(limit: int = 20, session: AsyncSession = Depends(get_session)):
    rows = await CVERepository.fetch_recent(session, limit)
    return CVEService.convert_rows(rows)

@router.get("/by-date")
async def by_date(start: str, end: str, session: AsyncSession = Depends(get_session)):
    rows = await CVERepository.fetch_by_date(session, start, end)
    return CVEService.convert_rows(rows)

@router.get("/summary")
async def summary(session: AsyncSession = Depends(get_session)):
    raw = await CVERepository.summary(session)
    return CVEService.convert_summary(raw)
