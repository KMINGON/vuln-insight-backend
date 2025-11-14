# 프로젝트 전체 가이드 (경량 백엔드 버전)

현재 프로젝트는 **NVD/MITRE 데이터를 자동 수집·정규화하여 FastAPI 기반 REST API로 제공**하는 데에 집중한다. 이후 단계에서 동일 인프라 위에 RAG 검색 기능을 가장 효율적인 방식으로 붙일 수 있도록 가이드를 포함한다. 데이터 분석, 대시보드, 프론트엔드는 별도 리포지토리나 후속 프로젝트로 분리한다.

## 1. 비전과 범위
- **목표**: 최신 NVD 데이터를 안정적으로 적재하고, 정제된 정보를 REST API로 노출하는 백엔드 서비스를 제공한다.
- **범위**: 데이터 파이프라인(다운로드 → RAW 적재 → 정규화)과 FastAPI 서버. 그 외 기능은 도입하지 않는다.
- **원칙**
    1. 자동화된 파이프라인: 동일한 스크립트/도커 명령으로 언제든 재실행 가능해야 한다.
    2. 단일 의존성: 기존 스택(Python, PostgreSQL, FastAPI) 이외의 도구 도입을 최소화한다.
    3. 명확한 문서화: 설정, 실행 방법, API 스펙이 README와 docs/에 정리되어야 한다.

## 2. 아키텍처 개요
| 계층 | 구성 요소 | 설명 |
| --- | --- | --- |
| 수집 & ETL | `etl/download_data.py`, `etl/etl_load.py`, `etl/etl_stage2.py` | NVD JSON 다운로드 → RAW 적재 → Stage 스키마 구성 |
| 저장소 | PostgreSQL 15 (docker-compose) | RAW/정규화 테이블, 뷰, 인덱스 관리 |
| API 백엔드 | FastAPI, SQLAlchemy, 서비스/리포지토리 계층 | 정규화 데이터를 조회하는 REST API |
| 관측·운영 | Docker Compose 로그, 기본 헬스체크 API | 추가 모니터링 스택 없이 컨테이너 로그와 헬스 엔드포인트로 감시 |

> 필요한 경우에만 선택적으로 Alembic, pytest 등 경량 도구를 추가할 수 있으나, 큐/캐시/빅데이터 도구는 도입하지 않는다.

## 3. 단계별 계획

### Phase 0 – 환경/기초
- 작업: `.env` 관리, Docker Compose 및 스크립트 정리, README 업데이트.
- 완료 기준: `docker compose up` 한 번으로 DB + ETL + API가 정상 동작.

### Phase 1 – 데이터 파이프라인 안정화
- 작업: 다운로드 증분 로직, RAW/Stage 검증, 실패 시 재시도/로그 보강.
- 완료 기준: 동일 데이터를 두 번 이상 연속 실행해도 일관된 결과가 나오는지 검증.

### Phase 2 – API 제공
- 작업: 라우터/서비스/리포지토리 구조 확립, 핵심 엔드포인트(CVE 리스트/상세/통계) 구현, 기본 테스트/문서화.
- 완료 기준: `/api/v1/cves`와 `/api/v1/cves/{cve_id}`가 실제 데이터와 함께 응답하고, OpenAPI 문서가 정상 노출된다.

### Phase 3 – RAG 확장 (선택)
- 작업: Stage2 결과를 텍스트로 정규화 → 임베딩 생성 → 벡터 스토어 적재 → 질의 API 노출.
- 권장 흐름:
    1. `etl/rag_embeddings.py`(신규)에서 CVE 요약/패치정보를 문단 단위로 생성.
    2. sentence-transformers(E5/LLaMA) 기반 임베딩을 수행하고 PostgreSQL PGVector 확장(또는 Qdrant) 테이블에 저장.
    3. FastAPI에 `rag/` 모듈을 추가하여 질의 요청을 받아 상위 K 문단을 반환.
- 완료 기준: `/api/v1/rag/query`가 유사 질의에 대해 관련 CVE 문단을 응답하고, 임베딩 인덱스가 ETL과 동일 주기로 갱신된다.

### (참고) Out-of-scope
- 분석 대시보드, 시각화, 프론트엔드, 고급 모니터링은 본 프로젝트 계획에 포함하지 않는다. 필요 시 별도 이슈/리포지토리에서 다룬다.

## 4. 기술 스택
| 영역 | 스택 | 비고 |
| --- | --- | --- |
| 언어/런타임 | Python 3.11 | 기존 스크립트와 호환 |
| 웹 프레임워크 | FastAPI | ASGI 기반, 자동 문서 제공 |
| ORM/DB Layer | SQLAlchemy Core/ORM | 복잡한 조인 구성에 활용 |
| 데이터베이스 | PostgreSQL 15 | RAW/Stage 테이블 저장 및 인덱스 |
| 데이터 처리 | 표준 라이브러리 + Pandas/Polars (필요 시) | JSON 파싱, 변환 |
| DevOps | Docker, docker-compose | 로컬 및 배포 환경 통일 |
| 테스트/품질 | Pytest, Ruff/Black (선택) | 선택적 경량 도구 |

## 5. 협업 및 문서화 지침
- 빠른 온보딩: `README.md` + `docs/TODO.md` + `docs/API_STRUCTURE.md`.
- 변경 기록: 주요 의사결정은 `docs/decisions/ADR-XXX.md` (필요 시)로 관리.
- 브랜치/CI: 간단한 GitHub Actions 워크플로(포맷·테스트)를 마련하되, 외부 서비스 의존은 최소화.

## 6. 향후 참고 사항
- API 상세 구조는 `docs/API_STRUCTURE.md`에 정리한다.
- RAG 확장을 진행할 때는 아래 7장을 참고한다.
- 모든 스크립트/명령은 Docker Compose 혹은 `scripts/` 내에서 재현 가능해야 한다.

## 7. RAG 통합 가이드 (효율적 구성)
1. **배치 위치**: 백엔드 리포지토리 안에 `rag/` 디렉터리를 두고, FastAPI 앱의 서브라우터로 노출한다. 프론트엔드는 REST API만 소비한다.
2. **DB 선택**: 기존 PostgreSQL 인스턴스에 PGVector 확장을 설치해 동일 데이터베이스에서 벡터 테이블(`rag_chunks`)을 운영한다. 필요 시 S3/MinIO에 원문을 보관하고, 대규모 확장이 필요하면 별도 Qdrant/Weaviate를 추가한다.
3. **파이프라인**:
    - Stage2 완료 후 `rag_embeddings.py`를 실행해 문단 단위 텍스트와 메타데이터를 생성.
    - sentence-transformers(E5-Large 등)로 임베딩을 만들고 PGVector 테이블에 `INSERT ... ON CONFLICT`로 업서트.
    - 벡터 테이블 스키마 예시: `(id UUID, cve_id TEXT, chunk TEXT, embedding vector(768), published_ts TIMESTAMP)`.
4. **쿼리 API**:
    - `/api/v1/rag/query`에서 입력 질문을 같은 모델로 임베딩해 `ORDER BY embedding <=> :query LIMIT K`로 검색.
    - 응답은 관련 CVE ID, chunk, score, 추가로 기존 REST API 링크를 포함.
5. **운영**:
    - 임베딩 스크립트는 Docker Compose의 선택적 서비스나 `scripts/run_rag_index.sh`로 실행.
    - 모델 파일은 Hugging Face에서 수동 다운로드 후 `models/`에 두거나, 사내 아티팩트로 캐싱해 네트워크 의존을 줄인다.
    - 보안 상 API 키/모델 키는 `.env`에 저장하고, RAG API에는 레이트 리밋이나 토큰 검증을 추후 추가한다.

이 과정을 따르면 새로운 인프라나 대규모 의존성 추가 없이, 기존 백엔드 구조를 재활용하며 RAG 기능을 확장할 수 있다.
