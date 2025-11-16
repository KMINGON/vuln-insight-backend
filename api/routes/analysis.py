from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.db import get_session
from api.schemas import (
    AnalysisCpeResponse,
    AnalysisCveCpeResponse,
    AnalysisCveCweResponse,
    AnalysisCveTableResponse,
    AnalysisCweResponse,
)
from api.services.analysis_service import AnalysisService

router = APIRouter(prefix="/api/v1/analysis", tags=["Analysis"])


def _build_filters(
    date_from: Optional[datetime],
    date_to: Optional[datetime],
    vendor: Optional[str],
    product: Optional[str],
    cwe_id: Optional[int],
    min_score: Optional[float],
    max_score: Optional[float],
    cvss_version: Optional[str],
    severity: Optional[str],
):
    return AnalysisService.build_filters(
        date_from=date_from,
        date_to=date_to,
        vendor=vendor,
        product=product,
        cwe_id=cwe_id,
        min_score=min_score,
        max_score=max_score,
        cvss_version=cvss_version,
        severity=severity,
    )


@router.get(
    "/cve-table",
    response_model=AnalysisCveTableResponse,
    summary="CVE 메인 분석 테이블",
)
async def cve_table(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    date_from: Optional[datetime] = Query(None, alias="from"),
    date_to: Optional[datetime] = Query(None, alias="to"),
    vendor: Optional[str] = Query(None),
    product: Optional[str] = Query(None),
    cwe_id: Optional[int] = Query(None),
    min_score: Optional[float] = Query(None),
    max_score: Optional[float] = Query(None),
    cvss_version: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    session: AsyncSession = Depends(get_session),
):
    filters = _build_filters(
        date_from, date_to, vendor, product, cwe_id, min_score, max_score, cvss_version, severity
    )
    return await AnalysisService.get_cve_table(session, filters, limit, offset)


@router.get(
    "/cve-cwe",
    response_model=AnalysisCveCweResponse,
    summary="CVE × CWE 관계 테이블",
)
async def cve_cwe(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    date_from: Optional[datetime] = Query(None, alias="from"),
    date_to: Optional[datetime] = Query(None, alias="to"),
    vendor: Optional[str] = Query(None),
    product: Optional[str] = Query(None),
    cwe_id: Optional[int] = Query(None),
    min_score: Optional[float] = Query(None),
    max_score: Optional[float] = Query(None),
    cvss_version: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    session: AsyncSession = Depends(get_session),
):
    filters = _build_filters(
        date_from, date_to, vendor, product, cwe_id, min_score, max_score, cvss_version, severity
    )
    return await AnalysisService.get_cve_cwe(session, filters, limit, offset)


@router.get(
    "/cve-cpe",
    response_model=AnalysisCveCpeResponse,
    summary="CVE × CPE 관계 테이블",
)
async def cve_cpe(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    date_from: Optional[datetime] = Query(None, alias="from"),
    date_to: Optional[datetime] = Query(None, alias="to"),
    vendor: Optional[str] = Query(None),
    product: Optional[str] = Query(None),
    cwe_id: Optional[int] = Query(None),
    min_score: Optional[float] = Query(None),
    max_score: Optional[float] = Query(None),
    cvss_version: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    session: AsyncSession = Depends(get_session),
):
    filters = _build_filters(
        date_from, date_to, vendor, product, cwe_id, min_score, max_score, cvss_version, severity
    )
    return await AnalysisService.get_cve_cpe(session, filters, limit, offset)


@router.get(
    "/cpe-table",
    response_model=AnalysisCpeResponse,
    summary="CPE 메타데이터 테이블",
)
async def cpe_table(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    vendor: Optional[str] = Query(None),
    product: Optional[str] = Query(None),
    deprecated: Optional[bool] = Query(None),
    target_sw: Optional[str] = Query(None),
    target_hw: Optional[str] = Query(None),
    session: AsyncSession = Depends(get_session),
):
    filters = AnalysisService.build_cpe_filters(
        vendor=vendor,
        product=product,
        deprecated=deprecated,
        target_sw=target_sw,
        target_hw=target_hw,
    )
    return await AnalysisService.get_cpe_table(session, filters, limit, offset)


@router.get(
    "/cwe-table",
    response_model=AnalysisCweResponse,
    summary="CWE 메타데이터 테이블",
)
async def cwe_table(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    abstraction: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    likelihood_of_exploit: Optional[str] = Query(None),
    session: AsyncSession = Depends(get_session),
):
    filters = AnalysisService.build_cwe_filters(
        abstraction=abstraction,
        status=status,
        likelihood_of_exploit=likelihood_of_exploit,
    )
    return await AnalysisService.get_cwe_table(session, filters, limit, offset)
