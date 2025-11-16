from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from api.repositories.analysis_repo import AnalysisRepository


class AnalysisService:
    @staticmethod
    def build_filters(
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        cwe_id: Optional[int] = None,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        cvss_version: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> Dict:
        filters: Dict = {}
        if date_from:
            filters["date_from"] = date_from
        if date_to:
            filters["date_to"] = date_to
        if vendor:
            filters["vendor"] = vendor
        if product:
            filters["product"] = product
        if cwe_id:
            filters["cwe_id"] = cwe_id
        if min_score is not None:
            filters["min_score"] = min_score
        if max_score is not None:
            filters["max_score"] = max_score
        if cvss_version:
            filters["cvss_version"] = cvss_version
        if severity:
            filters["severity"] = severity
        return filters

    @staticmethod
    def build_cpe_filters(
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        deprecated: Optional[bool] = None,
        target_sw: Optional[str] = None,
        target_hw: Optional[str] = None,
    ) -> Dict:
        filters: Dict = {}
        if vendor:
            filters["vendor"] = vendor
        if product:
            filters["product"] = product
        if deprecated is not None:
            filters["deprecated"] = deprecated
        if target_sw:
            filters["target_sw"] = target_sw
        if target_hw:
            filters["target_hw"] = target_hw
        return filters

    @staticmethod
    def build_cwe_filters(
        abstraction: Optional[str] = None,
        status: Optional[str] = None,
        likelihood_of_exploit: Optional[str] = None,
    ) -> Dict:
        filters: Dict = {}
        if abstraction:
            filters["abstraction"] = abstraction
        if status:
            filters["status"] = status
        if likelihood_of_exploit:
            filters["likelihood_of_exploit"] = likelihood_of_exploit
        return filters

    @classmethod
    async def get_cve_table(
        cls,
        session: AsyncSession,
        filters: Dict,
        limit: int,
        offset: int,
    ):
        rows, total = await AnalysisRepository.fetch_cve_table(session, filters, limit, offset)
        data = [cls._normalize_row(row) for row in rows]
        return {
            "data": data,
            "meta": cls._build_meta(limit, offset, total),
        }

    @classmethod
    async def get_cve_cwe(
        cls,
        session: AsyncSession,
        filters: Dict,
        limit: int,
        offset: int,
    ):
        rows, total = await AnalysisRepository.fetch_cve_cwe(session, filters, limit, offset)
        data = [dict(row) for row in rows]
        return {
            "data": data,
            "meta": cls._build_meta(limit, offset, total),
        }

    @classmethod
    async def get_cve_cpe(
        cls,
        session: AsyncSession,
        filters: Dict,
        limit: int,
        offset: int,
    ):
        rows, total = await AnalysisRepository.fetch_cve_cpe(session, filters, limit, offset)
        data = [dict(row) for row in rows]
        return {
            "data": data,
            "meta": cls._build_meta(limit, offset, total),
        }

    @classmethod
    async def get_cpe_table(
        cls,
        session: AsyncSession,
        filters: Dict,
        limit: int,
        offset: int,
    ):
        rows, total = await AnalysisRepository.fetch_cpe_table(session, filters, limit, offset)
        data = [dict(row) for row in rows]
        return {
            "data": data,
            "meta": cls._build_meta(limit, offset, total),
        }

    @classmethod
    async def get_cwe_table(
        cls,
        session: AsyncSession,
        filters: Dict,
        limit: int,
        offset: int,
    ):
        rows, total = await AnalysisRepository.fetch_cwe_table(session, filters, limit, offset)
        data = [dict(row) for row in rows]
        return {
            "data": data,
            "meta": cls._build_meta(limit, offset, total),
        }

    @staticmethod
    def _normalize_row(row: Dict) -> Dict:
        normalized = dict(row)
        normalized["has_cpe"] = bool(row.get("has_cpe"))
        normalized["has_cvss_v3"] = bool(row.get("has_cvss_v3"))
        normalized["has_cvss_v2"] = bool(row.get("has_cvss_v2"))
        return normalized

    @staticmethod
    def _build_meta(limit: Optional[int], offset: Optional[int], total: Optional[int]):
        return {
            "limit": limit,
            "offset": offset,
            "total": total,
            "generated_at": datetime.now(timezone.utc),
        }
