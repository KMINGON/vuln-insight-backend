# 프로젝트 추천 사항

> 요구된 범위 외에, 코드베이스를 검토하며 더 효율적인 운영/개발을 위해 고려할 만한 도구와 절차를 정리했습니다. 바로 적용하지 않아도 되며, 필요 시 우선순위를 조정하세요.

## 1. 데이터 파이프라인
- **Polars 도입 검토**: `etl/etl_load.py`와 `etl_stage2.py`에서 대량 JSON 처리 시 Pandas보다 빠르고 메모리 효율적인 Polars를 실험해볼 가치가 있습니다.
- **Prefect 미니 플로우**: Airflow 대신 가벼운 Prefect Flow를 작성하면 현재 Docker Compose 환경에서도 스케줄/재시도/로그 UI를 확보할 수 있습니다.
- **데이터 검증**: Great Expectations와 같은 경량 데이터 검증 도구를 사용하거나, 최소한 SQL 기반 체크리스트를 `tests/data_quality/`에 작성해 자동화하면 품질 확보가 쉽습니다.

## 2. 데이터베이스/마이그레이션
- **Alembic 도입**: 현재 SQL 스크립트만 존재하므로, Schema 변경 이력을 Alembic으로 관리하면 배포 자동화 시 안정성이 높아집니다.
- **PGVector 준비**: RAG 통합을 염두에 두고 `CREATE EXTENSION IF NOT EXISTS vector;`를 초기 스키마에 포함해 두면 추후 추가 작업이 줄어듭니다.

## 3. 백엔드 구조
- **Pydantic 스키마 분리**: `api/schemas/` 디렉터리를 만들어 요청/응답 모델을 중앙 관리하면 라우터/서비스 코드가 간결해집니다.
- **공통 응답/에러 미들웨어**: FastAPI `@app.middleware` 또는 exception handler를 구현해 API 응답 형태를 통일하고, 로깅/트레이싱을 쉽게 추적할 수 있습니다.
- **Makefile 또는 Task Runner**: `make etl`, `make api` 같은 명령을 제공하면 Docker를 쓰지 않는 경우에도 반복 작업을 단순화할 수 있습니다.

## 4. 테스트/품질
- **Pytest + FactoryBoy**: 샘플 데이터를 손쉽게 만들 수 있으므로 Repository/Service 단위 테스트 작성이 수월합니다.
- **Static Analysis**: Ruff(린트)와 MyPy(타입체크)를 CI에 추가해 버그를 조기 차단할 수 있습니다. 두 도구 모두 빠르고 설정이 간단합니다.

## 5. 배포/운영
- **Docker 이미지 경량화**: 멀티 스테이지 빌드 + `pip install --no-cache-dir`를 적용하면 배포 속도와 저장공간을 줄일 수 있습니다.
- **로그 집계**: 단일 서버 운영 시에도 Loki(or Vector) + Grafana 조합으로 로그를 중앙화하면 장애 조사 시간이 단축됩니다.
- **헬스체크/메트릭**: `/health` 외에 `/metrics`(Prometheus 형식)를 쉽게 추가할 수 있으므로, 추후 모니터링 시스템 연동이 수월합니다.

## 6. 문서화/협업
- **ADR 템플릿**: `docs/decisions/ADR-000-template.md`를 만들어 구조화된 의사결정 기록을 남기면, 향후 팀원이 합류했을 때 배경 설명이 쉬워집니다.
- **Sample Data Pack**: `data/sample/` 디렉터리에 소형 JSON/SQL 덤프를 제공하면 테스트나 데모가 빠르게 재현됩니다.

이 항목들은 필수는 아니지만, 프로젝트를 장기적으로 운영하거나 인원을 확장할 때 도움이 될 만한 개선 포인트입니다.
