# Analysis API 테스트 요청 모음

분석용 엔드포인트(`/api/v1/analysis/...`)를 빠르게 검증할 수 있는 curl 명령 예시를 모았습니다. 각 요청은 README/AGENTS/API_SPEC에서 설명한 필드를 실제로 반환하는지 확인할 때 사용하세요. 필요에 따라 필터 값을 수정하거나 조합하면 됩니다.

## 1. CVE 메인 테이블 (`/analysis/cve-table`)
```bash
curl -G "http://localhost:8000/api/v1/analysis/cve-table" \
  --data-urlencode "limit=5" \
  --data-urlencode "from=2024-01-01" \
  --data-urlencode "to=2024-03-31" \
  --data-urlencode "vendor=apache" \
  --data-urlencode "min_score=7" \
  --data-urlencode "cvss_version=3.1"
```
- 연/월, CVSS 점수, 대표 CWE, 대표 CPE 필드가 채워지는지 확인합니다.

## 2. CVE × CWE 관계 (`/analysis/cve-cwe`)
```bash
curl -G "http://localhost:8000/api/v1/analysis/cve-cwe" \
  --data-urlencode "limit=10" \
  --data-urlencode "from=2024-01-01" \
  --data-urlencode "to=2024-03-31" \
  --data-urlencode "cwe_id=79"
```
- `cwe_name`, `weakness_source`, `weakness_type`가 올바르게 조인되는지 확인합니다.

## 3. CVE × CPE 관계 (`/analysis/cve-cpe`)
```bash
curl -G "http://localhost:8000/api/v1/analysis/cve-cpe" \
  --data-urlencode "limit=10" \
  --data-urlencode "from=2024-01-01" \
  --data-urlencode "to=2024-03-31" \
  --data-urlencode "vendor=apache" \
  --data-urlencode "product=http_server"
```
- `criteria_cpe_uri`, `part`, `vendor`, `product`, `target_sw`, `status`가 명세대로 오는지 확인합니다.

## 4. CPE 메타 테이블 (`/analysis/cpe-table`)
```bash
curl -G "http://localhost:8000/api/v1/analysis/cpe-table" \
  --data-urlencode "limit=5" \
  --data-urlencode "vendor=apache" \
  --data-urlencode "deprecated=false"
```
- `title_en`, `deprecated`, `created_ts`, `last_modified_ts` 등 메타 필드 확인.

## 5. CWE 메타 테이블 (`/analysis/cwe-table`)
```bash
curl -G "http://localhost:8000/api/v1/analysis/cwe-table" \
  --data-urlencode "limit=5" \
  --data-urlencode "abstraction=Class" \
  --data-urlencode "status=Stable"
```
- `likelihood_of_exploit`, `description` 등 CWE 메타데이터가 노출되는지 확인합니다.

요청 실행 전에는 PostgreSQL과 ETL 작업이 완료되어 Stage2 테이블이 채워져 있어야 하며, `uvicorn api.main:app --reload`를 통해 API 서버를 기동해야 합니다.
