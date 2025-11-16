# api/core/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):   # 환경변수기반 설정을 관리하는 Pydantic BaseSettings 상속 클래스
    # 환경변수 키 정의
    DB_HOST: str
    DB_PORT: int
    DB_USER: str
    DB_PASS: str
    DB_NAME: str

    @property
    def SYNC_DATABASE_URL(self) -> str:   # 동기식 데이터베이스 URL 생성
        return (
            f"postgresql+psycopg2://{self.DB_USER}:{self.DB_PASS}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )

    @property
    def ASYNC_DATABASE_URL(self) -> str:   # 비동기식 데이터베이스 URL 생성
        return (
            f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASS}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )   # .env 파일에서 환경변수를 자동으로 로드하도록 설정


settings = Settings() # Settings 객체를 실제로 생성, 다른 모듈에서 settings.DB_USER 등으로 접근 가능
