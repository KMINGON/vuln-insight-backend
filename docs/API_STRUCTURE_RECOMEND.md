## 1. 분석용 데이터 전달 API 설계

공통 원칙

- 전부 `GET /api/v1/analysis/...`
- 공통 필터: `from`, `to`(날짜), `vendor`, `product`, `cwe_id`, `min_score`, `max_score`, `cvss_version`, `limit`, `offset` 등
- **역할**: 정규화된 여러 테이블을 **한 번의 조인으로 “분석 친화적 wide table”**로 만들어 프론트로 전달

### 1-1. CVE 중심 분석 테이블

### `GET /api/v1/analysis/cve-table`

- 목적: 대부분의 시각화가 이 한 테이블만으로 가능하도록 만드는 “메인 분석용 데이터프레임”
- 백엔드에서 하는 일:
    - `cve_core`
    - 
        - (대표 metric: Primary & 최신 CVSS 3.x or 4.0) `cve_metric`
    - 
        - (대표 weakness: Primary / 가장 자주 나오는 CWE) `cve_weakness`
    - 
        - (대표 CPE: vendor/product 추출) `cve_cpe_match` + `cpe` or `cpe_match_string`
    - 를 조인해서 1 CVE당 1행(or 소수 행)으로 정규화
- 주요 컬럼(예시):

```
cve_id
source_identifier
vuln_status
published_ts
last_modified_ts
year, month               # 편의용 파생 컬럼

cvss_version              # 2.0/3.0/3.1/4.0
base_score
base_severity
exploitability_score
impact_score

primary_cwe_id            # 89
primary_cwe_code          # 'CWE-89'
primary_cwe_name          # (cwe_core.name 조인 옵션)

vendor                    # from CPE (e.g. 'apache')
product                   # from CPE (e.g. 'http_server')
part                      # 'a'/'o'/'h'
cpe_uri_example           # 대표 cpe:2.3:... 하나(또는 첫 번째)

has_cpe                   # bool
has_cvss_v3               # bool
has_cvss_v2               # bool

```

- 프론트에서 할 수 있는 시각화:
    - 연도/월별 CVE 수, 평균 점수
    - vendor/product별 취약점 분포
    - severity 별 비율, CVSS 버전별 사용 추이
    - CWE별 평균 점수, 분포, 박스플롯 등

---

### 1-2. CVE × CWE 관계 테이블

### `GET /api/v1/analysis/cve-cwe`

- 목적: 한 CVE에 여러 CWE가 붙는 구조를 그대로 가져와서 **CWE 분석, 네트워크/코오커런스 분석, 히트맵** 등에 사용
- 백엔드에서 하는 일:
    - `cve_weakness` + `cwe_core`(선택) 조인
- 주요 컬럼:

```
cve_id
cwe_id
cwe_code            # 'CWE-89'
cwe_name
weakness_source     # 'nvd@nist.gov' / 'cna@...'
weakness_type       # Primary/Secondary 등

```

- 프론트:
    - CWE별 CVE 수, 평균 CVSS score (cve-table과 merge)
    - CWE 상위 랭킹, 막대그래프
    - “다른 CWE와 함께 나타나는 CWE” 코오커런스 매트릭스 (pivot_table)

---

### 1-3. CVE × CPE (제품/버전 매핑) 테이블

### `GET /api/v1/analysis/cve-cpe`

- 목적: **제품/버전/플랫폼 기준 분석** (어디에서 취약점이 많이 나오나)
- 백엔드:
    - `cve_cpe_match`
    - 
        - `cpe_match_string` (criteria_cpe_uri 기준)
    - 
        - `cpe` (있다면)
    - 를 조인해 row-per-(CVE, CPE) 구조 생성
- 주요 컬럼:

```
cve_id
criteria_cpe_uri          # cpe:2.3:...
vulnerable                # bool

part, vendor, product
cpe_version, cpe_update
target_sw, target_hw
status                    # Active/Inactive from cpe_match_string.status

```

- 프론트:
    - vendor/product별 취약점 수 (groupby)
    - 버전별 취약점 분포 (heatmap: version vs year)
    - target_sw(OS, 플랫폼) 별 CVE 수

---

### 1-4. CPE Dictionary 테이블

### `GET /api/v1/analysis/cpe-table`

- 목적: CPE 자체만 가지고 **제품/버전 메타데이터 분석** (취약점이 없는 제품도 포함 가능)
- 백엔드:
    - `cpe` + `cpe_title` + `cpe_ref` 일부 조인
- 주요 컬럼:

```
cpe_name_id
cpe_uri
part, vendor, product
cpe_version, cpe_update, target_sw, target_hw
deprecated
created_ts, last_modified_ts
title_en (있으면)

```

- 프론트:
    - 벤더별 제품 개수
    - deprecated 제품 비율
    - 기술 스택/플랫폼 분포

---

### 1-5. CWE Dictionary 테이블

### `GET /api/v1/analysis/cwe-table`

- 목적: CWE 메타정보와 결합해서 “취약점의 질적 특성” 시각화
- 백엔드: `cwe_core`
- 주요 컬럼:

```
cwe_id
name
abstraction           # Pillar/Class/Base/Variant/Compound
status                # Draft/Usable/Stable...
likelihood_of_exploit
description           # short 텍스트

```

- 프론트:
    - abstraction 별 빈도 (CVE와 조인해도 좋고, 단독 통계도 가능)
    - likelihood_of_exploit 분포
    - status별 CWE 개수

---

## 2. 꼭 미리 집계해서 주는 통계 API 설계

공통 원칙

- `GET /api/v1/stats/...`
- 프론트에서 자주 재사용되는, 비교적 무거운 집계를 서버에서 수행
- 반환 데이터는 **이미 시각화에 바로 쓸 수 있는 형태**(tidy 또는 pivot-ready)

---

### 2-1. CVE 시간 추세 (연/월별)

### `GET /api/v1/stats/cve/time-series`

- 파라미터:
    - `interval=month|year` (default month)
    - `from`, `to`
    - `vendor`, `product`, `cwe_id`, `min_score`, `max_score`, `cvss_version`, `severity`
- 결과 예:

```
period        total_cve  critical  high  medium  low  none
2020-01-01    123        10        40    50      20   3
2020-02-01    ...
...

```

- 프론트:
    - 라인차트/스택드 에어리어: 전체 CVE 추세 + severity별 추세
    - 특정 vendor/product 필터 후 추세 비교

---

### 2-2. CVSS 점수 분포 / 히스토그램

### `GET /api/v1/stats/cve/cvss-distribution`

- 파라미터:
    - `cvss_version=3.1|3.0|2.0|4.0|any`
    - `bins=10` (서버에서 cut/qcut)
    - `from`, `to`, `vendor`, `product`, `cwe_id`
- 결과 예:

```
bin_label       score_min  score_max  count
"[0.0, 1.0)"    0.0        1.0        12
"[1.0, 2.0)"    ...
...

```

- 프론트:
    - 히스토그램/막대그래프 (pandas로도 할 수 있지만, 전체 데이터에서 반복 사용되므로 서버 집계로 이득)

---

### 2-3. 상위 CWE 통계

### `GET /api/v1/stats/cwe/top`

- 파라미터:
    - `limit=20`
    - `from`, `to`, `vendor`, `product`
- 서버 집계:
    - `cve_weakness` + `cve_metric` + `cwe_core` 조인
    - CWE별 CVE 수, 평균 점수, 최대/최소, 평균 exploitability 등 계산
- 결과 예:

```
cwe_id  cwe_code  cwe_name                     cve_count  avg_score  max_score  likelihood_of_exploit
89      CWE-89    SQL Injection                5300       8.7        10.0       High
79      CWE-79    Cross-site Scripting (XSS)   ...
...

```

- 프론트:
    - 탑 N 막대그래프
    - 점수 기준 정렬, 필터링

---

### 2-4. 상위 Vendor / Product 통계

### `GET /api/v1/stats/vendor/top`

- 파라미터:
    - `limit=20`, `from`, `to`, `min_score`, `severity`
- 서버 집계:
    - `cve_cpe_match` + `cpe` + `cve_metric`
    - vendor별 CVE 수, 평균 점수, 심각도 분포

### `GET /api/v1/stats/product/top`

- 유사 구조, product 기준
- 결과 예:

```
vendor   cve_count  avg_score  critical_ratio  high_ratio  medium_ratio
apache   ...
microsoft ...
...

```

- 프론트:
    - 벤더/제품 TopN 테이블 + 바 차트
    - 특정 벤더 선택 시 제품별 상세 그래프

---

### 2-5. CWE × Severity 매트릭스 (히트맵용)

### `GET /api/v1/stats/cwe/severity-matrix`

- 파라미터:
    - `limit_cwe=20` (상위 CWE만)
    - `from`, `to`, `vendor`, `product`
- 서버 집계:
    - CWE별 + severity별 카운트 pivot
- 결과 예:

```
cwe_id  cwe_code  cwe_name         critical  high  medium  low
89      CWE-89    SQL Injection    3000      1000  200     10
79      CWE-79    XSS              ...
...

```

- 프론트:
    - 히트맵/annotated heatmap
    - CWE별 심각도 패턴 비교

---

### 2-6. CVSS 버전 사용 현황

### `GET /api/v1/stats/cvss/version-usage`

- 파라미터:
    - `from`, `to`
- 서버 집계:
    - CVE별 존재하는 metric 버전(v2, v3.0, v3.1, v4.0)을 카운트
- 결과 예:

```
cvss_version  cve_count
2.0           20000
3.0           5000
3.1           60000
4.0           1000

```

- 프론트:
    - 파이차트, 바차트
    - 시계열 버전 사용 추세는 `/stats/cve/time-series`에 `groupby cvss_version`을 추가하거나 별도 `/stats/cvss/version-time-series`로 확장 가능

---

### 2-7. 전체 요약 지표(Overview 카드용)

### `GET /api/v1/stats/overview`

- 파라미터: `from`, `to`
- 서버에서 계산:
    - 전체 CVE 수
    - 기간 내 신규 CVE 수
    - 평균 CVSS 점수, 중앙값
    - Critical/High 비율
    - 상위 CWE / Vendor 한 줄씩
- 프론트:
    - Streamlit 상단 KPI 카드로 배치

---

## 3. 요약

- **분석용 API**
    - `GET /analysis/cve-table` ← 메인 wide 테이블
    - `GET /analysis/cve-cwe` ← CVE×CWE 관계
    - `GET /analysis/cve-cpe` ← CVE×CPE(제품/버전) 관계
    - `GET /analysis/cpe-table` ← CPE 메타데이터
    - `GET /analysis/cwe-table` ← CWE 메타데이터
- **집계(stats) API**
    - `GET /stats/cve/time-series`
    - `GET /stats/cve/cvss-distribution`
    - `GET /stats/cwe/top`
    - `GET /stats/vendor/top`, `GET /stats/product/top`
    - `GET /stats/cwe/severity-matrix`
    - `GET /stats/cvss/version-usage`