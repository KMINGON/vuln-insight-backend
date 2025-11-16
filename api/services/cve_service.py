from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, List

from sqlalchemy.ext.asyncio import AsyncSession

from api.repositories.cve_repo import CVERepository

class CVEService:

    @classmethod
    async def get_recent(cls, session: AsyncSession, limit: int, offset: int):
        rows, total = await CVERepository.fetch_recent(session, limit=limit, offset=offset)
        return {
            "data": cls.convert_rows(rows),
            "meta": cls.build_meta(limit=limit, offset=offset, total=total),
        }

    @classmethod
    async def get_summary(cls, session: AsyncSession):
        raw = await CVERepository.summary(session)
        return {
            "data": cls.convert_summary(raw),
            "meta": cls.build_meta(),
        }

    @classmethod
    async def get_detail(cls, session: AsyncSession, cve_id: str):
        core = await CVERepository.fetch_core(session, cve_id)
        if not core:
            return {
                "data": None,
                "meta": cls.build_meta(),
            }
        descriptions, references, metrics, weaknesses, cpes = await cls._fetch_detail_related(
            session, cve_id
        )
        data = {
            "cve_id": core["cve_id"],
            "source_identifier": core.get("source_identifier"),
            "vuln_status": core.get("vuln_status"),
            "published_ts": core.get("published_ts"),
            "last_modified_ts": core.get("last_modified_ts"),
            "descriptions": descriptions,
            "references": references,
            "metrics": metrics,
            "weaknesses": weaknesses,
            "cpes": cpes,
        }
        return {
            "data": data,
            "meta": cls.build_meta(),
        }

    @classmethod
    def convert_rows(cls, rows: List[Dict]) -> List[Dict]:
        data = []
        for r in rows:
            item = dict(r)
            raw_json = item.get("raw_json")
            item["raw_json"] = cls.safe_json_load(raw_json)
            data.append(item)
        return data

    @staticmethod
    def convert_summary(raw: dict) -> Dict:
        top_sources = []
        for item in raw.get("top_sources", []):
            top_sources.append(
                {
                    "source_identifier": item.get("source_identifier"),
                    "count": item.get("cnt", 0),
                }
            )
        return {
            "total_cve": raw.get("total", 0),
            "last_24_hours": raw.get("last24", 0),
            "top_sources": top_sources,
        }

    @staticmethod
    def build_meta(limit: int | None = None, offset: int | None = None, total: int | None = None) -> Dict:
        return {
            "limit": limit,
            "offset": offset,
            "total": total,
            "generated_at": datetime.now(timezone.utc),
        }

    @staticmethod
    def safe_json_load(raw_value):
        if isinstance(raw_value, str):
            try:
                return json.loads(raw_value)
            except json.JSONDecodeError:
                return None
        return raw_value

    @classmethod
    async def _fetch_detail_related(cls, session: AsyncSession, cve_id: str):
        descriptions_raw = await CVERepository.fetch_descriptions(session, cve_id)
        references_raw = await CVERepository.fetch_references(session, cve_id)
        metrics_raw = await CVERepository.fetch_metrics(session, cve_id)
        weaknesses_raw = await CVERepository.fetch_weaknesses(session, cve_id)
        cpes_raw = await CVERepository.fetch_cpes(session, cve_id)
        return (
            cls._convert_descriptions(descriptions_raw),
            cls._convert_references(references_raw),
            cls._convert_metrics(metrics_raw),
            cls._convert_weaknesses(weaknesses_raw),
            cls._convert_cpes(cpes_raw),
        )

    @staticmethod
    def _convert_descriptions(rows: List[Dict]) -> List[Dict]:
        return [
            {
                "lang": row.get("lang"),
                "value": row.get("value"),
            }
            for row in rows
        ]

    @staticmethod
    def _convert_references(rows: List[Dict]) -> List[Dict]:
        return [
            {
                "url": row.get("url"),
                "source": row.get("source"),
                "tags": row.get("tags"),
            }
            for row in rows
        ]

    @classmethod
    def _convert_metrics(cls, rows: List[Dict]) -> List[Dict]:
        normalized = []
        for row in rows:
            entry = dict(row)
            entry["raw_json"] = cls.safe_json_load(row.get("raw_json"))
            normalized.append(entry)
        return normalized

    @staticmethod
    def _convert_weaknesses(rows: List[Dict]) -> List[Dict]:
        return [
            {
                "cwe_code": row.get("cwe_code"),
                "cwe_id": row.get("cwe_id"),
                "source": row.get("source"),
                "weakness_type": row.get("weakness_type"),
            }
            for row in rows
        ]

    @staticmethod
    def _convert_cpes(rows: List[Dict]) -> List[Dict]:
        return [
            {
                "criteria_cpe_uri": row.get("criteria_cpe_uri"),
                "vulnerable": row.get("vulnerable"),
                "match_criteria_id": row.get("match_criteria_id"),
                "version_start_incl": row.get("version_start_incl"),
                "version_start_excl": row.get("version_start_excl"),
                "version_end_incl": row.get("version_end_incl"),
                "version_end_excl": row.get("version_end_excl"),
            }
            for row in rows
        ]
