

## 프로젝트 개요
이 프로젝트는 **NVD(National Vulnerability Database), MITRE**에서 제공하는
CVE, CPE Match, CPE Dictionary, CWE 데이터 전체를 자동으로 다운로드·적재·정규화하고,
정제된 데이터를 데이터 분석 및 서비스에서 활용할 수 있도록 API 형태로 제공하는 백엔드 시스템이다.

전체 파이프라인은 다음과 같이 구성된다.

- **데이터 수집 (download_data.py)**
    -  NVD의 최신 CVE, CPE Match, CPE Dictionary, CWE JSON 파일을 자동 다운로드
    - 기존 파일과 비교해 업데이트 여부를 판단하여 최신 데이터 유지

- **RAW 적재 (etl_load.py)**
    - 다운로드한 모든 JSON 데이터를 PostgreSQL의 RAW 테이블에 저장
    - 각 데이터 유형(CVE / CPE Match / CPE Dictionary / CWE)에 맞는 스키마로 정리

- **정규화 및 후처리 (etl_stage2.py)**
    - RAW 테이블을 분석용/조회용 구조로 정규화
    - CVE 상세 정보, 영향도, CPE 매핑, CWE 연관 정보 등을 분리·정리하여 다수의 목적 기반 테이블에 저장

- **API Backend (FastAPI)**

    - 정규화된 데이터를 조회하기 위한 REST API 제공
    - 서비스 계층, 리포지토리 계층으로 분리된 구조
    - 복잡한 조인/매핑을 내부적으로 처리한 후 API로 최종 데이터 반환

- **PostgreSQL DB**

    - docker-compose 기반으로 실행
    - 스키마 생성/삭제/재생성은 sql/*.sql로 관리
    - 로컬 실행 스크립트(local_run.sh)
    Docker 없이도 로컬 개발환경에서 전체 파이프라인(ETL → API 실행)을 한 번에 재현 가능

이 구조는 **NVD 전체 데이터셋을 최신 상태**로 유지하면서,
다른 분석 시스템이나 프론트엔드에서 바로 활용할 수 있도록 **표준화된 API 인터페이스**를 제공한다.

## 실행 방법
### Docker 이용
```bash
-- 세팅
docker compose up
-- 끄기
docker compose stop
-- 켜기
docker compose start
```
FastAPI 실행 후 API는 다음에서 확인할 수 있습니다.  
http://localhost:8000/docs

> **Tip**: 최초 한 번 `etl` 서비스가 실행되어 데이터를 다운로드·정규화하면 PostgreSQL 볼륨에 데이터가 유지됩니다. 이후에는 ETL이 다시 돌 필요가 없으므로 `docker compose up backend` (필요 시 `db`)만 실행해 API 서버만 구동할 수 있습니다.

### 로컬에서 실행
`.env` 생성 및 사용할 DB 정보 입력 (그대로 둬도 됨)
```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

sudo service postgresql start
sudo -u postgres psql

-- DB 유저 생성 (env 정보 직접 지정했을 시 일치하도록 user 생성)
CREATE USER nvduser WITH PASSWORD '2828';

-- DB 생성
CREATE DATABASE nvddb OWNER nvduser;

-- 권한 부여
GRANT ALL PRIVILEGES ON DATABASE nvddb TO nvduser;
\q
-- DB 스키마 초기화
psql -h localhost -U nvduser -d nvddb -f sql/create_nvd_schema.sql

-- 최신 데이터 다운로드
python etl/download_data.py

-- Raw Date DB 적재
python etl/etl_load.py

-- 정규화 테이블 적재
python etl/etl_stage2.py

-- FastAPI 서버 실행
uvicorn api.main:app --reload
```

> 로컬 DB에 데이터가 이미 채워져 있다면, 위의 다운로드/ETL 단계는 생략하고 `uvicorn`만 재실행하면 됩니다.


## 디렉토리 구조
```plain
.
├── api/
│   ├── core/                # 핵심 설정 및 공통 컴포넌트
│   │   ├── config.py        # 환경 설정 로딩
│   │   └── db.py            # DB 연결/세션 관리
│   ├── repositories/        # DB 접근 레이어 (CRUD)
│   │   └── cve_repo.py
│   ├── routes/              # FastAPI 라우터 정의
│   │   └── cve.py
│   ├── services/            # 비즈니스 로직
│   │   └── cve_service.py
│   └── main.py              # FastAPI 엔트리포인트
│
├── data/                    # 다운로드된 NVD 원본 데이터 저장 디렉터리
│
├── etl/                     # 데이터 수집 및 ETL 파이프라인
│   ├── download_data.py     # NVD 데이터 다운로드
│   ├── etl_load.py          # DB 적재(정규화 1단계)
│   └── etl_stage2.py        # 추가 정규화/가공 2단계
│
├── scripts/
│   └── local_run.sh         # 로컬 실행용 통합 스크립트
│
├── playground/              # 실험용 코드 및 테스트 스크립트
│   └── db_connect_test.py
│
├── sql/                     # DB 스키마 관리 SQL 파일들
│   ├── create_nvd_schema.sql
│   ├── drop_nvd_schema.sql
│   └── reset_nvd_schema.sql
│
├── .env                     # 환경변수 설정 파일
├── Dockerfile               # Backend/ETL 빌드용 Dockerfile
├── docker-compose.yml       # Backend + PostgreSQL + ETL 일괄 실행 구성
├── requirements.txt         # Python 패키지 의존성 목록
├── requirements.txt         # 정상 작동 버전 고정 requirements
└── README.md
```

## 참고사항
- DB 스키마 정리 : [Notion](https://www.notion.so/DB-2aab11334add802b92e0e2713ad8d97a?source=copy_link)
- 초기 Data Download 및 테이블 정규화가 오래걸리니 가능하다면 로컬에서 미리 download_data.py 실행 후 Docker 실행 (로컬 data 공유)
- 데이터 정규화 작업이 오래 걸릴 수 있으니 docker 실행 시 `nvd-etl exited with code 0` 로그 확인 후 API 요청 전송
