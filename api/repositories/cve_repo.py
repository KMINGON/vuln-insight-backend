from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

class CVERepository:
    
    @staticmethod
    async def fetch_recent(session: AsyncSession, limit: int = 20, offset: int = 0):
        data_query = text("""
            SELECT cve_id, source_identifier, published, last_modified, vuln_status, raw_json
            FROM cve
            ORDER BY published::timestamptz DESC
            LIMIT :limit OFFSET :offset
        """)
        rows = await session.execute(data_query, {"limit": limit, "offset": offset})
        total_query = text("SELECT COUNT(*) FROM cve")
        total = (await session.execute(total_query)).scalar() or 0
        return rows.mappings().all(), total

    @staticmethod
    async def summary(session: AsyncSession):
        q_total = text("SELECT COUNT(*) AS total FROM cve")
        q_24h = text("""
            SELECT COUNT(*) AS last24
            FROM cve
            WHERE published::timestamptz >= NOW() - INTERVAL '24 hours'
        """)
        q_top_sources = text("""
            SELECT source_identifier, COUNT(*) AS cnt
            FROM cve
            GROUP BY source_identifier
            ORDER BY cnt DESC
            LIMIT 5
        """)

        total = (await session.execute(q_total)).scalar()
        last24 = (await session.execute(q_24h)).scalar()
        top_sources = (await session.execute(q_top_sources)).mappings().all()

        return {
            "total": total or 0,
            "last24": last24 or 0,
            "top_sources": top_sources
        }

    @staticmethod
    async def fetch_core(session: AsyncSession, cve_id: str):
        query = text("""
            SELECT cve_id, source_identifier, vuln_status, published_ts, last_modified_ts
            FROM cve_core
            WHERE cve_id = :cve_id
        """)
        row = await session.execute(query, {"cve_id": cve_id})
        return row.mappings().first()

    @staticmethod
    async def fetch_descriptions(session: AsyncSession, cve_id: str):
        query = text("""
            SELECT lang, value
            FROM cve_description
            WHERE cve_id = :cve_id
            ORDER BY lang
        """)
        rows = await session.execute(query, {"cve_id": cve_id})
        return rows.mappings().all()

    @staticmethod
    async def fetch_references(session: AsyncSession, cve_id: str):
        query = text("""
            SELECT url, source, tags
            FROM cve_reference
            WHERE cve_id = :cve_id
        """)
        rows = await session.execute(query, {"cve_id": cve_id})
        return rows.mappings().all()

    @staticmethod
    async def fetch_metrics(session: AsyncSession, cve_id: str):
        query = text("""
            SELECT cvss_version, source, metric_type, vector_string,
                   base_score, base_severity, exploitability_score,
                   impact_score, raw_json
            FROM cve_metric
            WHERE cve_id = :cve_id
            ORDER BY cvss_version DESC, id
        """)
        rows = await session.execute(query, {"cve_id": cve_id})
        return rows.mappings().all()

    @staticmethod
    async def fetch_weaknesses(session: AsyncSession, cve_id: str):
        query = text("""
            SELECT cwe_code, cwe_id, source, weakness_type
            FROM cve_weakness
            WHERE cve_id = :cve_id
        """)
        rows = await session.execute(query, {"cve_id": cve_id})
        return rows.mappings().all()

    @staticmethod
    async def fetch_cpes(session: AsyncSession, cve_id: str):
        query = text("""
            SELECT match_criteria_id, criteria_cpe_uri, vulnerable,
                   version_start_incl, version_start_excl,
                   version_end_incl, version_end_excl
            FROM cve_cpe_match
            WHERE cve_id = :cve_id
        """)
        rows = await session.execute(query, {"cve_id": cve_id})
        return rows.mappings().all()
