from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from .cve import ResponseMeta


class AnalysisCveTableRow(BaseModel):
    cve_id: str
    source_identifier: Optional[str] = None
    vuln_status: Optional[str] = None
    published_ts: Optional[datetime] = None
    last_modified_ts: Optional[datetime] = None
    year: Optional[int] = None
    month: Optional[int] = None
    cvss_version: Optional[str] = None
    base_score: Optional[float] = None
    base_severity: Optional[str] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    primary_cwe_id: Optional[int] = None
    primary_cwe_code: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    part: Optional[str] = None
    has_cpe: bool = False
    has_cvss_v3: bool = False
    has_cvss_v2: bool = False


class AnalysisCveTableResponse(BaseModel):
    data: list[AnalysisCveTableRow]
    meta: ResponseMeta


class AnalysisCveCweRow(BaseModel):
    cve_id: str
    cwe_id: Optional[int] = None
    cwe_code: Optional[str] = None
    cwe_name: Optional[str] = None
    weakness_source: Optional[str] = None
    weakness_type: Optional[str] = None


class AnalysisCveCweResponse(BaseModel):
    data: list[AnalysisCveCweRow]
    meta: ResponseMeta


class AnalysisCveCpeRow(BaseModel):
    cve_id: str
    criteria_cpe_uri: str
    vulnerable: Optional[bool] = None
    part: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    cpe_version: Optional[str] = None
    cpe_update: Optional[str] = None
    target_sw: Optional[str] = None
    target_hw: Optional[str] = None
    status: Optional[str] = None


class AnalysisCveCpeResponse(BaseModel):
    data: list[AnalysisCveCpeRow]
    meta: ResponseMeta


class AnalysisCpeRow(BaseModel):
    cpe_name_id: str
    cpe_uri: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    part: Optional[str] = None
    cpe_version: Optional[str] = None
    cpe_update: Optional[str] = None
    target_sw: Optional[str] = None
    target_hw: Optional[str] = None
    deprecated: Optional[bool] = None
    created_ts: Optional[datetime] = None
    last_modified_ts: Optional[datetime] = None
    title_en: Optional[str] = None


class AnalysisCpeResponse(BaseModel):
    data: list[AnalysisCpeRow]
    meta: ResponseMeta


class AnalysisCweRow(BaseModel):
    cwe_id: int
    name: Optional[str] = None
    abstraction: Optional[str] = None
    status: Optional[str] = None
    likelihood_of_exploit: Optional[str] = None
    description: Optional[str] = None


class AnalysisCweResponse(BaseModel):
    data: list[AnalysisCweRow]
    meta: ResponseMeta
