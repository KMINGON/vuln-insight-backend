# API 구조 가이드

FastAPI 기반 NVD 백엔드가 어떤 계층, 데이터 스키마, 엔드포인트 규칙으로 동작해야 하는지를 정의한다. `docs/API_STRUCTURE_RECOMEND.md`의 분석/통계 요구사항과 `docs/DataSechma.md`의 NVD 스키마를 반영했으며, 변경 시 본 문서를 우선 갱신한다.

## 1. 목표와 범위
- Stage2에서 정규화한 CVE/CPE/CWE 데이터를 `/api/v1/**`로 노출한다.
- 운영용 API(헬스·요약·최근 목록) + 분석용 wide-table API + 사전 집계 통계 API를 한 리포지토리에서 제공한다.
- 프런트엔드나 RAG는 별도 문서에서 정의하되, 백엔드 인터페이스는 본 문서를 기준으로 검증한다.

## 2. 핵심 데이터 소스
- **CVE**: NVD `cve_item` 스키마 준수(`cve_id`, `sourceIdentifier`, `vulnStatus`, `published`, `metrics`, `weaknesses`, `configurations`). JSON 원문은 `cve.raw_json`으로 저장하되 서비스 계층에서 필요한 필드만 해석한다.
- **CPE**: `cpe`, `cpe_match_string`, `cpe_title` 테이블에서 vendor/product/버전 메타데이터를 추출한다.
- **CWE**: `cwe_core`, `cve_weakness` 조합으로 primary/secondary 관계를 유지한다.
- 정규화 뷰 예시: `cve_core`, `cve_metric`, `cve_weakness`, `cve_cpe_match`. 분석 API는 이 뷰를 조인해 “1 CVE 1행 또는 (CVE, 관계) 행”을 반환한다.

## 3. 계층 구조와 디렉터리 매핑
| 계층 | 디렉터리/파일 | 책임 |
| --- | --- | --- |
| Core | `api/core/config.py`, `api/core/db.py` | 환경 변수/DB 세션, 공통 의존성 |
| Router | `api/routes/` | 엔드포인트 선언, 쿼리 파라미터, response_model |
| Service | `api/services/` | 비즈니스 규칙, JSON 파싱, 필드 필터링 |
| Repository | `api/repositories/` | SQLAlchemy/Raw SQL, 조인/집계 |
| Schema | `api/schemas/` | Pydantic DTO (`ResponseMeta`, `CVERecord`, 통계 응답 등) |

규칙: Router → Service → Repository 단방향 의존, Raw JSON은 Service에서만 역직렬화, Repository는 `AsyncSession`과 파라미터화된 SQL만 사용한다.

## 4. 공통 요청/응답 규약
- 헤더: `Content-Type: application/json; charset=UTF-8`. 인증은 내부망 기준 미적용(추후 `x-api-key` 헤더 추가 가능).
- 쿼리 파라미터
  - 페이지네이션: `limit`(기본 20, 최대 200), `offset`(기본 0).
  - 날짜: `from`, `to` (`YYYY-MM-DD` 또는 ISO8601).
  - 필터: `vendor`, `product`, `cwe_id`, `cpe_part`, `min_score`, `max_score`, `cvss_version`, `severity`.
- 응답 래퍼:
  ```json
  {
    "data": [...],
    "meta": {
      "limit": 20,
      "offset": 0,
      "total": 523,
      "generated_at": "2024-04-10T00:00:00Z"
    }
  }
  ```
- 에러 포맷:
  ```json
  {
    "error": {
      "code": "BAD_REQUEST",
      "message": "limit must be <= 200",
      "details": null
    }
  }
  ```

## 5. 운영 API (Operational)
| Method | Path | 설명 | 비고 |
| --- | --- | --- | --- |
| GET | `/api/v1/health` | 앱/DB 상태, 버전 정보 | 최소 헬스 체크 |
| GET | `/api/v1/cve/recent` | 최신 CVE 목록 | `limit`,`offset` 적용, `raw_json`은 dict |
| GET | `/api/v1/cve/summary` | 전체 건수, 최근 24시간 건수, 상위 소스 | 추후 Severity 요약 필드 추가 |
| GET | `/api/v1/cve/{cve_id}` | CVE 상세 + 설명/참조/CVSS/CWE/CPE | `routes.cve.detail` |

운영 API 응답 모델은 `api/schemas/cve.py`를 사용하고, OpenAPI 문서에 sample을 포함한다.

## 6. 분석 API (Analysis Wide Tables)
모두 `GET /api/v1/analysis/...` 프리픽스를 사용하며 공통 필터(`from`,`to`,`vendor`,`product`,`cwe_id`,`min_score`,`max_score`,`cvss_version`,`limit`,`offset`)를 허용한다.

1. `GET /api/v1/analysis/cve-table`
   - 데이터: `cve_core` + 대표 `cve_metric` + `cve_weakness` + `cve_cpe_match`.
   - 컬럼: `cve_id`, `source_identifier`, `published_ts`, `base_score`, `base_severity`, `primary_cwe_id`, `vendor`, `product`, `has_cvss_v3`, `year`, `month` 등.
   - 용도: 연/월별 추세, vendor별 분포, severity별 비율, CVSS 버전 사용 분석.

2. `GET /api/v1/analysis/cve-cwe`
   - 데이터: `cve_weakness` + `cwe_core`.
   - 컬럼: `cve_id`, `cwe_id`, `cwe_code`, `cwe_name`, `weakness_source`, `weakness_type`.
   - 용도: CWE 코오커런스, 히트맵, 상위 CWE 분석.

3. `GET /api/v1/analysis/cve-cpe`
   - 데이터: `cve_cpe_match` + `cpe_match_string` + `cpe`.
   - 컬럼: `(cve_id, criteria_cpe_uri, vendor, product, part, version, target_sw, status, vulnerable)`.
   - 용도: 제품/버전별 취약점 분포, 플랫폼별 위험도.

4. `GET /api/v1/analysis/cpe-table`
   - 데이터: `cpe` + `cpe_title` + `cpe_ref`.
   - 컬럼: `cpe_name_id`, `cpe_uri`, `vendor`, `product`, `deprecated`, `created_ts`, `last_modified_ts`, `title_en`.
   - 용도: 제품 메타데이터 현황, deprecated 비율.

5. `GET /api/v1/analysis/cwe-table`
   - 데이터: `cwe_core`.
   - 컬럼: `cwe_id`, `name`, `abstraction`, `status`, `likelihood_of_exploit`, `description`.
   - 용도: CWE 사전, 분류별 개수 집계.

각 API는 CSV friendly JSON 배열을 반환하며, 프런트가 추가 조인 없이 시각화를 바로 수행할 수 있도록 wide-column 구조를 유지한다.

## 7. 통계 API (Stats & Aggregations)
프리픽스 `GET /api/v1/stats/...`. 서버가 무거운 집계를 선계산하여 tidy 형태로 전달한다.

| Path | 설명 | 주요 파라미터 | 반환 예시 |
| --- | --- | --- | --- |
| `/stats/cve/time-series` | 월/년별 CVE 추세 및 severity 단위 카운트 | `interval=month|year`, 공통 필터 | `{ "period": "2024-01-01", "total_cve": 123, "critical": 10, ... }` |
| `/stats/cve/cvss-distribution` | CVSS 점수 히스토그램 | `cvss_version`, `bins`, 공통 필터 | bin label + count |
| `/stats/cwe/top` | 상위 CWE (개수·평균/최대 점수) | `limit`, `from`, `to`, `vendor`, `product` | `{ "cwe_id": "89", "cve_count": 5300, ... }` |
| `/stats/vendor/top` / `/stats/product/top` | 벤더/제품 TOP N 통계 | `limit`, `min_score`, `severity` | `{ "vendor": "apache", "cve_count": 400, ... }` |
| `/stats/cwe/severity-matrix` | CWE × Severity 히트맵 데이터 | `limit_cwe`, 공통 필터 | severity별 카운트 컬럼 |
| `/stats/cvss/version-usage` | CVSS 버전 사용량 | `from`, `to` | `{ "cvss_version": "3.1", "cve_count": 60000 }` |
| `/stats/overview` | KPI 카드용 요약 | `from`, `to` | 전체/신규 CVE 수, 평균·중앙 점수 등 |

모든 통계 API 역시 `{data: [...], meta: {...}}` 래퍼를 따르며, `data` 배열은 시각화 라이브러리(Plotly, Streamlit)에서 그대로 사용할 수 있도록 tidy 형태를 유지한다.

## 8. 서비스·리포지토리 계약
- Repository는 입력 파라미터 검증을 신뢰하지 말고 `text()` 바인딩을 이용해 SQL 인젝션을 방지한다.
- Service는 DataSechma에 명시된 필수 필드를 검증해 누락 시 기본값을 채움.
- 공통 유틸:
  - `build_meta(limit, offset, total)` : UTC `generated_at` 포함.
  - `paginate(query, limit, offset)` : Repository에서 재사용 가능한 패턴.
  - 통계 API는 Pandas 사용 대신 SQL에서 Group By/Window 함수로 집계한다.

## 9. 테스트·문서화·변경 관리
- `pytest` + `httpx.AsyncClient`로 Router 테스트, Repository는 DB sandbox를 통한 통합 테스트.
- `docs/API_SPEC.md` (본 작업에서 생성)와 동기화되도록 OpenAPI description을 최신으로 유지한다.
- 구조 변경 시
  1. `docs/API_STRUCTURE.md` 업데이트
  2. `api/schemas/` 수정 및 버전 태그
  3. `docs/API_SPEC.md` 예시/파라미터 갱신
  4. PR 템플릿에 “API 변경 체크리스트”를 추가해 리뷰 시 검증.

이 가이드를 따르면 운영/분석/통계 API가 동일한 규약을 따르게 되어, 데이터 소비자가 추가 변환 없이 분석과 시각화를 수행할 수 있다.
