# Repository Guidelines

## Project Structure & Module Organization
데이터 수집과 적재 코드는 `etl/` (`download_data.py`, `etl_load.py`, `etl_stage2.py`)에, FastAPI 레이어는 `api/core`, `api/routes`, `api/services`, `api/repositories` 구조에 맞춰 배치한다. 데이터베이스 스키마는 `sql/create_nvd_schema.sql` 및 리셋 스크립트에 정의하며, 장문의 문서는 `docs/`, 실험용 스크립트는 `playground/`에 둔다. 대용량 원본 JSON은 `data/`에 저장하되 Git에 올리지 않는다. 테스트 모듈은 실제 코드 트리와 동일한 구조를 따라 `tests/` 아래에 생성한다.

## Build, Test, and Development Commands
- `docker compose up` — PostgreSQL, ETL 서비스, FastAPI 백엔드를 한 번에 기동한다. 중지 시 `docker compose stop`.
- `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt` — 로컬 개발용 가상환경을 구성한다.
- `psql -h localhost -U nvduser -d nvddb -f sql/create_nvd_schema.sql` — 새로운 데이터 세트를 적재하기 전에 스키마를 초기화한다.
- `python etl/download_data.py && python etl/etl_load.py && python etl/etl_stage2.py` — 전체 파이프라인을 순서대로 실행한다.
- `uvicorn api.main:app --reload` — http://localhost:8000/docs 에서 즉시 API를 검증한다.
- `pytest -q` 및 `pytest --cov=api --cov=etl` — 자동 테스트와 커버리지를 실행하고, 필요 시 `docker compose logs backend`로 로그를 확인한다.

## Coding Style & Naming Conventions
Python 3.11, 4칸 들여쓰기, 타입 힌트를 기본으로 사용한다. `routes`는 의존성 주입만 담당하고, `services`는 도메인 규칙, `repositories`는 SQLAlchemy 쿼리를 처리하도록 책임을 분리한다. 함수·변수는 `snake_case`, 클래스는 `UpperCamelCase`, 모듈은 도메인 명을 활용한다. Black(88자 폭)으로 포맷팅하고 Ruff로 린트 후 커밋하며, README와 docs의 JSON 예시는 실제 API 응답과 동일하게 유지한다.

## Testing Guidelines
pytest를 기본 테스트 프레임워크로 사용하고 파일 이름은 `test_<module>.py` 패턴을 따른다. 서비스 계층 테스트에서는 비동기 SQLAlchemy 세션을 목킹하고, 통합 테스트는 SQL 스크립트를 이용해 경량 샘플 데이터를 적재한다. 새로운 API 엔드포인트마다 최소 한 개의 요청·응답 검증을 추가하며(`client.get("/api/v1/cve/recent")` 등), ETL 테스트에서는 단계별 행 수와 대표 CVE ID를 비교하고 `pytest --cov`로 커버리지를 기록한다.

## Commit & Pull Request Guidelines
`feat: ...`, `refactor: ...`와 같은 `<type>: summary` 규칙을 git log와 동일하게 유지하고, 영어 명령형 문장으로 72자 이내에 작성한다. 관련 이슈가 있다면 `(#42)` 형태로 덧붙인다. PR에는 변경 동기, 실행 커맨드, 스키마나 설정 변경 여부, API 변화 시 샘플 curl 또는 Swagger 캡처를 포함한다. 수정한 문서(`README.md`, `docs/*`, `AGENTS.md` 등)를 항목으로 명시하고, 후속 작업이 필요하면 체크리스트로 남긴다.

## Security & Configuration Tips
민감한 값은 `.env`에만 저장하고 필요한 키 목록은 README에 설명한다. `data/`와 DB 덤프는 외부 공유 전에 익명 처리한다. `sql/create_nvd_schema.sql`과 `sql/reset_nvd_schema.sql` 변경 시 항상 동기화하고, Python 코드에 임시 DDL을 작성하기보다는 SQL 파일이나 마이그레이션 스크립트를 갱신한다. FastAPI 라우터에서는 모든 입력 파라미터를 검증하고, 가공되지 않은 NVD JSON을 그대로 노출하지 않는다.
