from __future__ import annotations

from typing import Dict, Tuple

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


class AnalysisRepository:
    METRIC_CTE = """
WITH metric AS (
    SELECT DISTINCT ON (cve_id)
        cve_id,
        cvss_version,
        source,
        metric_type,
        vector_string,
        base_score,
        base_severity,
        exploitability_score,
        impact_score,
        raw_json
    FROM cve_metric
    ORDER BY cve_id,
        CASE
            WHEN cvss_version = '4.0' THEN 1
            WHEN cvss_version = '3.1' THEN 2
            WHEN cvss_version = '3.0' THEN 3
            WHEN cvss_version = '2.0' THEN 4
            ELSE 5
        END,
        id DESC
)
"""

    @classmethod
    async def fetch_cve_table(
        cls,
        session: AsyncSession,
        filters: Dict,
        limit: int,
        offset: int,
    ):
        where_clause, params = cls._build_cve_where_clause(filters)
        params.update({"limit": limit, "offset": offset})
        query = text(
            f"""
{cls.METRIC_CTE}
SELECT
    cc.cve_id,
    cc.source_identifier,
    cc.vuln_status,
    cc.published_ts,
    cc.last_modified_ts,
    EXTRACT(YEAR FROM cc.published_ts)::INT AS year,
    EXTRACT(MONTH FROM cc.published_ts)::INT AS month,
    cm.cvss_version,
    cm.base_score,
    cm.base_severity,
    cm.exploitability_score,
    cm.impact_score,
    cwe.primary_cwe_id,
    cwe.primary_cwe_code,
    rep.vendor,
    rep.product,
    rep.part,
    COALESCE(rep.has_cpe, FALSE) AS has_cpe,
    COALESCE(flags.has_cvss_v3, FALSE) AS has_cvss_v3,
    COALESCE(flags.has_cvss_v2, FALSE) AS has_cvss_v2
FROM cve_core cc
LEFT JOIN metric cm ON cm.cve_id = cc.cve_id
LEFT JOIN LATERAL (
    SELECT cwe_id AS primary_cwe_id, cwe_code AS primary_cwe_code
    FROM cve_weakness
    WHERE cve_id = cc.cve_id
    ORDER BY CASE WHEN weakness_type = 'Primary' THEN 0 ELSE 1 END, id
    LIMIT 1
) cwe ON TRUE
LEFT JOIN LATERAL (
    SELECT
        NULLIF(split_part(criteria_cpe_uri, ':', 3), '') AS part,
        NULLIF(split_part(criteria_cpe_uri, ':', 4), '') AS vendor,
        NULLIF(split_part(criteria_cpe_uri, ':', 5), '') AS product,
        TRUE AS has_cpe
    FROM cve_cpe_match
    WHERE cve_id = cc.cve_id
    ORDER BY id
    LIMIT 1
) rep ON TRUE
LEFT JOIN LATERAL (
    SELECT
        BOOL_OR(cvss_version LIKE '3%') AS has_cvss_v3,
        BOOL_OR(cvss_version LIKE '2%') AS has_cvss_v2
    FROM cve_metric
    WHERE cve_id = cc.cve_id
) flags ON TRUE
WHERE {where_clause}
ORDER BY cc.published_ts DESC NULLS LAST, cc.cve_id
LIMIT :limit OFFSET :offset
            """
        )
        rows = await session.execute(query, params)
        total = await cls._count_cves(session, filters)
        return rows.mappings().all(), total

    @classmethod
    async def fetch_cve_cwe(
        cls,
        session: AsyncSession,
        filters: Dict,
        limit: int,
        offset: int,
    ):
        where_clause, params = cls._build_cve_where_clause(filters)
        params.update({"limit": limit, "offset": offset})
        query = text(
            f"""
{cls.METRIC_CTE}
SELECT
    cw.cve_id,
    cw.cwe_id,
    cw.cwe_code,
    cwe.name AS cwe_name,
    cw.source AS weakness_source,
    cw.weakness_type
FROM cve_weakness cw
JOIN cve_core cc ON cc.cve_id = cw.cve_id
LEFT JOIN metric cm ON cm.cve_id = cc.cve_id
LEFT JOIN cwe_core cwe ON cwe.cwe_id = cw.cwe_id
WHERE {where_clause}
ORDER BY cw.cve_id DESC, cw.id
LIMIT :limit OFFSET :offset
            """
        )
        rows = await session.execute(query, params)
        total = await cls._count_cve_cwe(session, filters)
        return rows.mappings().all(), total

    @classmethod
    async def fetch_cve_cpe(
        cls,
        session: AsyncSession,
        filters: Dict,
        limit: int,
        offset: int,
    ):
        where_clause, params = cls._build_cve_where_clause(filters)
        row_filters = []
        if "vendor_like" in params:
            row_filters.append("NULLIF(split_part(ccm.criteria_cpe_uri, ':', 4), '') ILIKE :vendor_like")
        if "product_like" in params:
            row_filters.append("NULLIF(split_part(ccm.criteria_cpe_uri, ':', 5), '') ILIKE :product_like")
        row_clause = " AND ".join(row_filters) if row_filters else "TRUE"
        params = dict(params)
        params.update({"limit": limit, "offset": offset})
        query = text(
            f"""
{cls.METRIC_CTE}
SELECT
    ccm.cve_id,
    ccm.criteria_cpe_uri,
    ccm.vulnerable,
    NULLIF(split_part(ccm.criteria_cpe_uri, ':', 3), '') AS part,
    NULLIF(split_part(ccm.criteria_cpe_uri, ':', 4), '') AS vendor,
    NULLIF(split_part(ccm.criteria_cpe_uri, ':', 5), '') AS product,
    NULLIF(split_part(ccm.criteria_cpe_uri, ':', 6), '') AS cpe_version,
    NULLIF(split_part(ccm.criteria_cpe_uri, ':', 7), '') AS cpe_update,
    NULLIF(split_part(ccm.criteria_cpe_uri, ':', 11), '') AS target_sw,
    NULLIF(split_part(ccm.criteria_cpe_uri, ':', 12), '') AS target_hw,
    cms.status
FROM cve_cpe_match ccm
JOIN cve_core cc ON cc.cve_id = ccm.cve_id
LEFT JOIN metric cm ON cm.cve_id = cc.cve_id
LEFT JOIN cpe_match_string cms ON cms.criteria_cpe_uri = ccm.criteria_cpe_uri
WHERE {where_clause}
  AND {row_clause}
ORDER BY ccm.cve_id DESC, ccm.id
LIMIT :limit OFFSET :offset
            """
        )
        rows = await session.execute(query, params)
        total = await cls._count_cve_cpe(session, filters, row_clause)
        return rows.mappings().all(), total

    @classmethod
    async def fetch_cpe_table(
        cls,
        session: AsyncSession,
        filters: Dict,
        limit: int,
        offset: int,
    ):
        where_clause, params = cls._build_cpe_where_clause(filters)
        params.update({"limit": limit, "offset": offset})
        query = text(
            f"""
SELECT
    c.cpe_name_id,
    c.cpe_uri,
    c.vendor,
    c.product,
    c.part,
    c.cpe_version,
    c.cpe_update,
    c.target_sw,
    c.target_hw,
    c.deprecated,
    c.created_ts,
    c.last_modified_ts,
    title.title_en
FROM cpe c
LEFT JOIN LATERAL (
    SELECT title AS title_en
    FROM cpe_title
    WHERE cpe_name_id = c.cpe_name_id
    ORDER BY CASE WHEN lang = 'en' THEN 0 ELSE 1 END
    LIMIT 1
) title ON TRUE
WHERE {where_clause}
ORDER BY c.last_modified_ts DESC NULLS LAST, c.cpe_name_id
LIMIT :limit OFFSET :offset
            """
        )
        rows = await session.execute(query, params)
        total = await cls._count_cpe(session, filters)
        return rows.mappings().all(), total

    @classmethod
    async def fetch_cwe_table(
        cls,
        session: AsyncSession,
        filters: Dict,
        limit: int,
        offset: int,
    ):
        where_clause, params = cls._build_cwe_where_clause(filters)
        params.update({"limit": limit, "offset": offset})
        query = text(
            f"""
SELECT
    cwe_id,
    name,
    abstraction,
    status,
    likelihood_of_exploit,
    description
FROM cwe_core
WHERE {where_clause}
ORDER BY cwe_id
LIMIT :limit OFFSET :offset
            """
        )
        rows = await session.execute(query, params)
        total = await cls._count_cwe(session, filters)
        return rows.mappings().all(), total

    @classmethod
    def _build_cve_where_clause(
        cls,
        filters: Dict,
        core_alias: str = "cc",
        metric_alias: str = "cm",
    ) -> Tuple[str, Dict]:
        clauses = []
        params: Dict = {}
        date_from = filters.get("date_from")
        date_to = filters.get("date_to")
        vendor = filters.get("vendor")
        product = filters.get("product")
        cwe_id = filters.get("cwe_id")
        min_score = filters.get("min_score")
        max_score = filters.get("max_score")
        cvss_version = filters.get("cvss_version")
        severity = filters.get("severity")

        if date_from:
            clauses.append(f"{core_alias}.published_ts >= :date_from")
            params["date_from"] = date_from
        if date_to:
            clauses.append(f"{core_alias}.published_ts <= :date_to")
            params["date_to"] = date_to
        if vendor:
            clauses.append(
                f"""
                EXISTS (
                    SELECT 1
                    FROM cve_cpe_match ccm_filter
                    WHERE ccm_filter.cve_id = {core_alias}.cve_id
                      AND NULLIF(split_part(ccm_filter.criteria_cpe_uri, ':', 4), '') ILIKE :vendor_like
                )
                """
            )
            params["vendor_like"] = f"%{vendor}%"
        if product:
            clauses.append(
                f"""
                EXISTS (
                    SELECT 1
                    FROM cve_cpe_match ccm_filter_prod
                    WHERE ccm_filter_prod.cve_id = {core_alias}.cve_id
                      AND NULLIF(split_part(ccm_filter_prod.criteria_cpe_uri, ':', 5), '') ILIKE :product_like
                )
                """
            )
            params["product_like"] = f"%{product}%"
        if cwe_id:
            clauses.append(
                f"""
                EXISTS (
                    SELECT 1
                    FROM cve_weakness cw_filter
                    WHERE cw_filter.cve_id = {core_alias}.cve_id
                      AND cw_filter.cwe_id = :filter_cwe_id
                )
                """
            )
            params["filter_cwe_id"] = cwe_id
        if min_score is not None:
            clauses.append(f"{metric_alias}.base_score >= :min_score")
            params["min_score"] = min_score
        if max_score is not None:
            clauses.append(f"{metric_alias}.base_score <= :max_score")
            params["max_score"] = max_score
        if cvss_version:
            clauses.append(f"{metric_alias}.cvss_version = :cvss_version")
            params["cvss_version"] = cvss_version
        if severity:
            clauses.append(f"{metric_alias}.base_severity ILIKE :severity_like")
            params["severity_like"] = severity

        where_clause = " AND ".join(clauses) if clauses else "TRUE"
        return where_clause, params

    @classmethod
    def _build_cpe_where_clause(cls, filters: Dict) -> Tuple[str, Dict]:
        clauses = []
        params: Dict = {}
        vendor = filters.get("vendor")
        product = filters.get("product")
        deprecated = filters.get("deprecated")
        target_sw = filters.get("target_sw")
        target_hw = filters.get("target_hw")

        if vendor:
            clauses.append("vendor ILIKE :vendor_like")
            params["vendor_like"] = f"%{vendor}%"
        if product:
            clauses.append("product ILIKE :product_like")
            params["product_like"] = f"%{product}%"
        if deprecated is not None:
            clauses.append("deprecated = :deprecated")
            params["deprecated"] = deprecated
        if target_sw:
            clauses.append("target_sw ILIKE :target_sw_like")
            params["target_sw_like"] = f"%{target_sw}%"
        if target_hw:
            clauses.append("target_hw ILIKE :target_hw_like")
            params["target_hw_like"] = f"%{target_hw}%"

        where_clause = " AND ".join(clauses) if clauses else "TRUE"
        return where_clause, params

    @classmethod
    def _build_cwe_where_clause(cls, filters: Dict) -> Tuple[str, Dict]:
        clauses = []
        params: Dict = {}
        abstraction = filters.get("abstraction")
        status = filters.get("status")
        likelihood = filters.get("likelihood_of_exploit")

        if abstraction:
            clauses.append("abstraction ILIKE :abstraction_like")
            params["abstraction_like"] = f"%{abstraction}%"
        if status:
            clauses.append("status ILIKE :status_like")
            params["status_like"] = f"%{status}%"
        if likelihood:
            clauses.append("likelihood_of_exploit ILIKE :likelihood_like")
            params["likelihood_like"] = f"%{likelihood}%"

        where_clause = " AND ".join(clauses) if clauses else "TRUE"
        return where_clause, params

    @classmethod
    async def _count_cves(cls, session: AsyncSession, filters: Dict) -> int:
        where_clause, params = cls._build_cve_where_clause(filters)
        count_query = text(
            f"""
{cls.METRIC_CTE}
SELECT COUNT(*)
FROM cve_core cc
LEFT JOIN metric cm ON cm.cve_id = cc.cve_id
WHERE {where_clause}
            """
        )
        result = await session.execute(count_query, params)
        return result.scalar_one() or 0

    @classmethod
    async def _count_cve_cwe(cls, session: AsyncSession, filters: Dict) -> int:
        where_clause, params = cls._build_cve_where_clause(filters)
        count_query = text(
            f"""
{cls.METRIC_CTE}
SELECT COUNT(*)
FROM cve_weakness cw
JOIN cve_core cc ON cc.cve_id = cw.cve_id
LEFT JOIN metric cm ON cm.cve_id = cc.cve_id
WHERE {where_clause}
            """
        )
        result = await session.execute(count_query, params)
        return result.scalar_one() or 0

    @classmethod
    async def _count_cve_cpe(
        cls,
        session: AsyncSession,
        filters: Dict,
        row_clause: str,
    ) -> int:
        where_clause, params = cls._build_cve_where_clause(filters)
        count_query = text(
            f"""
{cls.METRIC_CTE}
SELECT COUNT(*)
FROM cve_cpe_match ccm
JOIN cve_core cc ON cc.cve_id = ccm.cve_id
LEFT JOIN metric cm ON cm.cve_id = cc.cve_id
WHERE {where_clause}
  AND {row_clause}
            """
        )
        result = await session.execute(count_query, params)
        return result.scalar_one() or 0

    @classmethod
    async def _count_cpe(cls, session: AsyncSession, filters: Dict) -> int:
        where_clause, params = cls._build_cpe_where_clause(filters)
        count_query = text(
            f"""
SELECT COUNT(*)
FROM cpe
WHERE {where_clause}
            """
        )
        result = await session.execute(count_query, params)
        return result.scalar_one() or 0

    @classmethod
    async def _count_cwe(cls, session: AsyncSession, filters: Dict) -> int:
        where_clause, params = cls._build_cwe_where_clause(filters)
        count_query = text(
            f"""
SELECT COUNT(*)
FROM cwe_core
WHERE {where_clause}
            """
        )
        result = await session.execute(count_query, params)
        return result.scalar_one() or 0
