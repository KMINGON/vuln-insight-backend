# API Specification

이 문서는 `/api/v1` 아래에서 제공되는 운영형·분석형·통계형 REST 엔드포인트의 사용 방법을 정의한다. 모든 응답은 `application/json; charset=UTF-8` 포맷이며 `{ "data": ..., "meta": ... }` 래퍼를 따른다. 예시 JSON은 `docs/DataSechma.md`에 제시된 NVD 스키마를 기반으로 구성됐으며, 각 API만으로 어떤 분석이 가능한지 바로 파악할 수 있도록 필드 설명을 함께 제공한다.

## 1. 공통 사항
- **Base URL**: `http://localhost:8000/api/v1`
- **인증**: 내부망 기준 미적용 (추후 `x-api-key` 추가 가능)
- **공통 쿼리 파라미터**: `limit`(기본 20, 최대 200), `offset`(기본 0), `from`, `to`, `vendor`, `product`, `cwe_id`, `min_score`, `max_score`, `cvss_version`, `severity`
- **에러 포맷**
  ```json
  {
    "error": {
      "code": "BAD_REQUEST",
      "message": "limit must be <= 200",
      "details": null
    }
  }
  ```

## 2. 운영 API

| Method | Path | 설명 |
| --- | --- | --- |
| GET | `/health` | 앱/DB 상태 및 버전 정보 |
| GET | `/cve/recent` | 최신 CVE 목록 |
| GET | `/cve/summary` | 전체 건수, 최근 24시간 건수, 상위 소스 |
| GET | `/cve/{cve_id}` | 단일 CVE 상세 (설명/참조/CVSS/CWE/CPE) |

### 2.1 GET `/cve/recent`
- **정보**: 최신 CVE 행과 Raw JSON(`cve_item` 스키마)를 함께 반환해 UI·추가 파서에서 바로 활용 가능.
- **Query**: `limit`, `offset`
- **Response**
  ```json
  {
    "data": [
      {
        "cve_id": "CVE-2024-0001",
        "source_identifier": "cve@mitre.org",
        "published": "2024-04-09T12:00:00Z",
        "last_modified": "2024-04-10T02:10:00Z",
        "vuln_status": "Analyzed",
        "raw_json": {
          "cve": {
            "id": "CVE-2024-0001",
            "metrics": {
              "cvssMetricV31": [
                {
                  "cvssData": {
                    "version": "3.1",
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                  },
                  "exploitabilityScore": 3.9,
                  "impactScore": 5.9
                }
              ]
            },
            "weaknesses": [
              {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "description": [
                  { "lang": "en", "value": "CWE-89" }
                ]
              }
            ]
          }
        }
      }
    ],
    "meta": {
      "limit": 10,
      "offset": 0,
      "total": 523,
      "generated_at": "2024-04-10T02:10:05Z"
    }
  }
  ```
  *분석 활용*: 신규 CVE를 바로 확인하거나 Raw JSON을 변환해 추가 파생 지표를 계산.

### 2.2 GET `/cve/summary`
- **정보**: 전체 CVE 규모, 최근 24시간 발생량, 주요 신고 주체 Top-N을 KPI 카드로 표시 가능.
- **Response**
  ```json
  {
    "data": {
      "total_cve": 129382,
      "last_24_hours": 182,
      "top_sources": [
        { "source_identifier": "nvd@nist.gov", "count": 532 },
        { "source_identifier": "cna@oracle.com", "count": 120 },
        { "source_identifier": "cna@microsoft.com", "count": 98 }
      ]
    },
    "meta": {
      "generated_at": "2024-04-10T02:12:00Z"
    }
  }
  ```

### 2.3 GET `/cve/{cve_id}`
- **정보**: 정규화된 `cve_core`, 설명, 참조, CVSS metrics, CWE, CPE 매핑을 한 번에 내려 사용자 상세 페이지나 분석용 카드에 사용.
- **Response**
  ```json
  {
    "data": {
      "cve_id": "CVE-2024-0001",
      "source_identifier": "cve@mitre.org",
      "vuln_status": "Analyzed",
      "published_ts": "2024-04-09T12:00:00Z",
      "last_modified_ts": "2024-04-10T02:10:00Z",
      "descriptions": [
        { "lang": "en", "value": "Buffer overflow in ..." },
        { "lang": "ko", "value": "버퍼 오버플로 취약점 ..." }
      ],
      "references": [
        {
          "url": "https://httpd.apache.org/security/vulnerabilities_24.html",
          "source": "apache",
          "tags": ["Vendor Advisory"]
        }
      ],
      "metrics": [
        {
          "cvss_version": "3.1",
          "metric_type": "Primary",
          "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "base_score": 9.8,
          "base_severity": "CRITICAL",
          "exploitability_score": 3.9,
          "impact_score": 5.9,
          "raw_json": {
            "cvssData": { "attackVector": "NETWORK", "privilegesRequired": "NONE" }
          }
        }
      ],
      "weaknesses": [
        { "cwe_code": "CWE-89", "cwe_id": 89, "source": "nvd@nist.gov", "weakness_type": "Primary" }
      ],
      "cpes": [
        {
          "criteria_cpe_uri": "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*",
          "vulnerable": true,
          "match_criteria_id": "1234-5678",
          "version_start_incl": null,
          "version_start_excl": null,
          "version_end_incl": null,
          "version_end_excl": null
        }
      ]
    },
    "meta": {
      "generated_at": "2024-04-10T02:18:00Z"
    }
  }
  ```
  *분석 활용*: 상세 페이지, CVSS/CWE/CPE 관계 시각화, 레퍼런스 링크 제공.

## 3. 분석 API (`/analysis`)

| Method | Path | 목적 |
| --- | --- | --- |
| GET | `/analysis/cve-table` | CVE 중심 wide table |
| GET | `/analysis/cve-cwe` | CVE×CWE 관계 |
| GET | `/analysis/cve-cpe` | CVE×CPE 관계 |
| GET | `/analysis/cpe-table` | CPE 메타데이터 |
| GET | `/analysis/cwe-table` | CWE 메타데이터 |

### 3.1 GET `/analysis/cve-table`
- **정보**: `cve_core` + 대표 CVSS + 대표 CWE + 대표 CPE를 조인한 1행 1 CVE 데이터프레임. 연/월 추세, vendor·product 분포, severity 비율 즉시 분석 가능.
- **Response**
  ```json
  {
    "data": [
      {
        "cve_id": "CVE-2024-0001",
        "published_ts": "2024-04-09T12:00:00Z",
        "last_modified_ts": "2024-04-10T02:10:00Z",
        "year": 2024,
        "month": 4,
        "cvss_version": "3.1",
        "base_score": 9.8,
        "base_severity": "CRITICAL",
        "exploitability_score": 3.9,
        "impact_score": 5.9,
        "primary_cwe_id": "89",
        "primary_cwe_code": "CWE-89",
        "vendor": "apache",
        "product": "http_server",
        "part": "a",
        "has_cpe": true,
        "has_cvss_v3": true,
        "has_cvss_v2": false
      }
    ],
    "meta": {
      "limit": 100,
      "offset": 0,
      "total": 3400,
      "generated_at": "2024-04-10T02:20:00Z"
    }
  }
  ```
  *분석 활용*: Streamlit/BI에서 groupby(`year`,`vendor`), 평균 점수 산출, severity 스택 차트 작성.

### 3.2 GET `/analysis/cve-cwe`
- **정보**: CVE별 다중 CWE 관계를 그대로 반환해 CWE 상관관계, 네트워크 그래프, 히트맵 분석에 활용.
- **Response**
  ```json
  {
    "data": [
      {
        "cve_id": "CVE-2024-0001",
        "cwe_id": "79",
        "cwe_code": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation",
        "weakness_source": "nvd@nist.gov",
        "weakness_type": "Primary"
      },
      {
        "cve_id": "CVE-2024-0001",
        "cwe_id": "80",
        "cwe_code": "CWE-80",
        "cwe_name": "CWE placeholder",
        "weakness_source": "cna@vendor.com",
        "weakness_type": "Secondary"
      }
    ],
    "meta": {
      "limit": 200,
      "offset": 0,
      "total": 6200,
      "generated_at": "2024-04-10T02:25:00Z"
    }
  }
  ```
  *분석 활용*: `pivot_table(cwe_code, cve_id)`로 코오커런스 매트릭스를 구성하거나, CWE별 CVE 수·평균 점수를 계산.

### 3.3 GET `/analysis/cve-cpe`
- **정보**: (CVE, CPE) 조합으로 제품/버전/플랫폼 기준 분석 가능. 벤더별 취약점 수, 버전 히트맵, target_sw 분포를 바로 산출.
- **Response**
  ```json
  {
    "data": [
      {
        "cve_id": "CVE-2024-0001",
        "criteria_cpe_uri": "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*",
        "vulnerable": true,
        "vendor": "apache",
        "product": "http_server",
        "part": "a",
        "cpe_version": "2.4.53",
        "cpe_update": "*",
        "target_sw": "linux",
        "target_hw": null,
        "status": "Active"
      }
    ],
    "meta": {
      "limit": 100,
      "offset": 0,
      "total": 9800,
      "generated_at": "2024-04-10T02:27:00Z"
    }
  }
  ```

### 3.4 GET `/analysis/cpe-table`
- **정보**: CPE 사전(제품 메타데이터, deprecated 여부, 생성/수정일)로 벤더별 제품 수나 deprecated 추이를 분석.
- **Response**
  ```json
  {
    "data": [
      {
        "cpe_name_id": "CPE-12345",
        "cpe_uri": "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*",
        "vendor": "apache",
        "product": "http_server",
        "part": "a",
        "cpe_version": "2.4.53",
        "cpe_update": "*",
        "target_sw": "linux",
        "target_hw": null,
        "deprecated": false,
        "created_ts": "2014-02-01T00:00:00Z",
        "last_modified_ts": "2022-05-01T00:00:00Z",
        "title_en": "Apache HTTP Server 2.4.53"
      }
    ],
    "meta": {
      "limit": 100,
      "offset": 0,
      "total": 25000,
      "generated_at": "2024-04-10T02:28:00Z"
    }
  }
  ```

### 3.5 GET `/analysis/cwe-table`
- **정보**: CWE 사전(추상화 수준, 상태, exploit 가능성)으로 CWE 분류별 위험도와 규모를 분석.
- **Response**
  ```json
  {
    "data": [
      {
        "cwe_id": "89",
        "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "abstraction": "Class",
        "status": "Stable",
        "likelihood_of_exploit": "High",
        "description": "The software constructs all or part of an SQL command using externally influenced input..."
      }
    ],
    "meta": {
      "limit": 100,
      "offset": 0,
      "total": 1200,
      "generated_at": "2024-04-10T02:29:00Z"
    }
  }
  ```

## 4. 통계 API (`/stats`)

| Method | Path | 설명 |
| --- | --- | --- |
| GET | `/stats/cve/time-series` | 연/월별 추세와 severity 분포 |
| GET | `/stats/cve/cvss-distribution` | CVSS 히스토그램 |
| GET | `/stats/cwe/top` | 상위 CWE |
| GET | `/stats/vendor/top` | 상위 벤더 |
| GET | `/stats/product/top` | 상위 제품 |
| GET | `/stats/cwe/severity-matrix` | CWE×Severity 히트맵 |
| GET | `/stats/cvss/version-usage` | CVSS 버전 사용량 |
| GET | `/stats/overview` | KPI 카드용 요약 |

### 4.1 GET `/stats/cve/time-series`
- **정보**: 기간별 CVE 수와 severity 분포를 제공해 라인/스택 에어리어 차트를 즉시 생성.
- **Response**
  ```json
  {
    "data": [
      {
        "period": "2024-01-01",
        "total_cve": 1200,
        "critical": 80,
        "high": 400,
        "medium": 560,
        "low": 120,
        "none": 40
      },
      {
        "period": "2024-02-01",
        "total_cve": 980,
        "critical": 60,
        "high": 350,
        "medium": 430,
        "low": 110,
        "none": 30
      }
    ],
    "meta": { "generated_at": "2024-04-10T02:30:00Z" }
  }
  ```

### 4.2 GET `/stats/cve/cvss-distribution`
- **정보**: CVSS 점수 구간별 카운트로 히스토그램/누적 분포 작성.
- **Response**
  ```json
  {
    "data": [
      { "bin_label": "[0.0,1.0)", "score_min": 0.0, "score_max": 1.0, "count": 12 },
      { "bin_label": "[1.0,2.0)", "score_min": 1.0, "score_max": 2.0, "count": 25 },
      { "bin_label": "[9.0,10.0]", "score_min": 9.0, "score_max": 10.0, "count": 210 }
    ],
    "meta": { "generated_at": "2024-04-10T02:32:00Z" }
  }
  ```

### 4.3 GET `/stats/cwe/top`
- **정보**: CWE별 CVE 수, 평균/최대 점수, exploit 가능성을 제공해 TopN 막대그래프를 구성.
- **Response**
  ```json
  {
    "data": [
      {
        "cwe_id": "89",
        "cwe_code": "CWE-89",
        "cwe_name": "SQL Injection",
        "cve_count": 5300,
        "avg_score": 8.7,
        "max_score": 10.0,
        "likelihood_of_exploit": "High"
      },
      {
        "cwe_id": "79",
        "cwe_code": "CWE-79",
        "cwe_name": "Cross-site Scripting (XSS)",
        "cve_count": 4200,
        "avg_score": 7.2,
        "max_score": 9.8,
        "likelihood_of_exploit": "Medium"
      }
    ],
    "meta": { "generated_at": "2024-04-10T02:33:00Z" }
  }
  ```

### 4.4 GET `/stats/vendor/top` 및 `/stats/product/top`
- **정보**: 벤더/제품별 CVE 수와 severity 비율을 제공해 TopN 차트와 드릴다운에 활용.
- **Response**
  ```json
  {
    "data": [
      {
        "vendor": "apache",
        "cve_count": 540,
        "avg_score": 7.8,
        "critical_ratio": 0.22,
        "high_ratio": 0.41,
        "medium_ratio": 0.30
      },
      {
        "vendor": "microsoft",
        "cve_count": 610,
        "avg_score": 7.0,
        "critical_ratio": 0.18,
        "high_ratio": 0.45,
        "medium_ratio": 0.32
      }
    ],
    "meta": { "generated_at": "2024-04-10T02:34:00Z" }
  }
  ```

### 4.5 GET `/stats/cwe/severity-matrix`
- **정보**: CWE별 severity 카운트를 피벗 형태로 제공해 히트맵을 즉시 생성.
- **Response**
  ```json
  {
    "data": [
      {
        "cwe_id": "89",
        "cwe_code": "CWE-89",
        "cwe_name": "SQL Injection",
        "critical": 3000,
        "high": 1800,
        "medium": 400,
        "low": 50
      },
      {
        "cwe_id": "79",
        "cwe_code": "CWE-79",
        "cwe_name": "Cross-site Scripting (XSS)",
        "critical": 900,
        "high": 1900,
        "medium": 1100,
        "low": 300
      }
    ],
    "meta": { "generated_at": "2024-04-10T02:35:00Z" }
  }
  ```

### 4.6 GET `/stats/cvss/version-usage`
- **정보**: CVSS 버전별 사용량(2.0/3.0/3.1/4.0)을 집계해 파이/스택 차트를 작성.
- **Response**
  ```json
  {
    "data": [
      { "cvss_version": "2.0", "cve_count": 20000 },
      { "cvss_version": "3.0", "cve_count": 5000 },
      { "cvss_version": "3.1", "cve_count": 60000 },
      { "cvss_version": "4.0", "cve_count": 1000 }
    ],
    "meta": { "generated_at": "2024-04-10T02:36:00Z" }
  }
  ```

### 4.7 GET `/stats/overview`
- **정보**: 전체 CVE 수, 신규 건수, 평균/중앙 점수, severity 비율, 대표 CWE·벤더를 한 번에 제공해 KPI 카드로 활용.
- **Response**
  ```json
  {
    "data": {
      "total_cve": 129382,
      "new_cve": 182,
      "avg_score": 7.3,
      "median_score": 7.1,
      "critical_ratio": 0.18,
      "top_cwe": { "cwe_code": "CWE-89", "cve_count": 5300 },
      "top_vendor": { "vendor": "microsoft", "cve_count": 610 }
    },
    "meta": { "generated_at": "2024-04-10T02:37:00Z" }
  }
  ```

## 5. 예시 워크플로
1. `/analysis/cve-table`과 동일한 필터로 `/stats/cve/time-series`를 호출해 연/월 추세·severity 분포 차트를 구성.
2. `/analysis/cve-cpe` 결과를 vendor/product별 groupby로 집계하고, `/stats/vendor/top`과 비교해 상위 벤더 상세 분석.
3. `/stats/overview`와 `/cve/summary`를 주기적으로 호출해 KPI 카드 갱신.

향후 엔드포인트가 추가되면 본 명세서에 새로운 필드 설명과 JSON 예시를 반드시 기록한다.
