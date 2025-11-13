from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

class CVERepository:
    
    @staticmethod
    async def fetch_recent(session: AsyncSession, limit: int = 20):
        q = text("""
            SELECT cve_id, source_identifier, published, last_modified, vuln_status, raw_json
            FROM cve
            ORDER BY published::timestamptz DESC
            LIMIT :limit
        """)
        rows = await session.execute(q, {"limit": limit})
        return rows.mappings().all()

    @staticmethod
    async def fetch_by_date(session: AsyncSession, start: str, end: str):
        q = text("""
            SELECT cve_id, source_identifier, published, vuln_status, raw_json
            FROM cve
            WHERE published::timestamptz BETWEEN :start::timestamptz AND :end::timestamptz
            ORDER BY published::timestamptz ASC
        """)
        rows = await session.execute(q, {"start": start, "end": end})
        return rows.mappings().all()

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
            "total": total,
            "last24": last24,
            "top_sources": top_sources
        }
