from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class ResponseMeta(BaseModel):
    limit: Optional[int] = None
    offset: Optional[int] = None
    total: Optional[int] = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CVERecord(BaseModel):
    cve_id: str
    source_identifier: Optional[str] = None
    published: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    vuln_status: Optional[str] = None
    raw_json: Optional[dict[str, Any]] = None


class CVEListResponse(BaseModel):
    data: list[CVERecord]
    meta: ResponseMeta


class TopSource(BaseModel):
    source_identifier: str
    count: int


class CVESummaryData(BaseModel):
    total_cve: int
    last_24_hours: int
    top_sources: list[TopSource]


class CVESummaryResponse(BaseModel):
    data: CVESummaryData
    meta: ResponseMeta


class CVEDescription(BaseModel):
    lang: str
    value: str


class CVEReference(BaseModel):
    url: str
    source: Optional[str] = None
    tags: Optional[list[str]] = None


class CVEMetric(BaseModel):
    cvss_version: str
    source: Optional[str] = None
    metric_type: Optional[str] = None
    vector_string: Optional[str] = None
    base_score: Optional[float] = None
    base_severity: Optional[str] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    raw_json: Optional[dict[str, Any]] = None


class CVEWeakness(BaseModel):
    cwe_code: Optional[str] = None
    cwe_id: Optional[int] = None
    source: Optional[str] = None
    weakness_type: Optional[str] = None


class CVECpeMatch(BaseModel):
    criteria_cpe_uri: str
    vulnerable: Optional[bool] = None
    match_criteria_id: Optional[str] = None
    version_start_incl: Optional[str] = None
    version_start_excl: Optional[str] = None
    version_end_incl: Optional[str] = None
    version_end_excl: Optional[str] = None


class CVEDetailData(BaseModel):
    cve_id: str
    source_identifier: Optional[str] = None
    vuln_status: Optional[str] = None
    published_ts: Optional[datetime] = None
    last_modified_ts: Optional[datetime] = None
    descriptions: list[CVEDescription] = Field(default_factory=list)
    references: list[CVEReference] = Field(default_factory=list)
    metrics: list[CVEMetric] = Field(default_factory=list)
    weaknesses: list[CVEWeakness] = Field(default_factory=list)
    cpes: list[CVECpeMatch] = Field(default_factory=list)


class CVEDetailResponse(BaseModel):
    data: Optional[CVEDetailData] = None
    meta: ResponseMeta
