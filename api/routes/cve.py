from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.db import get_session
from api.schemas import CVEDetailResponse, CVEListResponse, CVESummaryResponse
from api.services.cve_service import CVEService

router = APIRouter(prefix="/api/v1/cve", tags=["CVE"])


@router.get(
    "/recent",
    response_model=CVEListResponse,
    summary="최신 CVE 목록 조회",
)
async def recent(
    limit: int = Query(20, ge=1, le=200, description="반환할 최대 건수"),
    offset: int = Query(0, ge=0, description="페이지네이션 오프셋"),
    session: AsyncSession = Depends(get_session),
):
    return await CVEService.get_recent(session=session, limit=limit, offset=offset)


@router.get(
    "/summary",
    response_model=CVESummaryResponse,
    summary="CVE 집계 요약",
)
async def summary(session: AsyncSession = Depends(get_session)):
    return await CVEService.get_summary(session=session)


@router.get(
    "/{cve_id}",
    response_model=CVEDetailResponse,
    summary="CVE 상세 정보",
)
async def detail(cve_id: str, session: AsyncSession = Depends(get_session)):
    return await CVEService.get_detail(session=session, cve_id=cve_id)
