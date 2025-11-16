# api/core/db.py
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from .config import settings

engine = create_async_engine(
    settings.ASYNC_DATABASE_URL,
    future=True,
    echo=False,
) # SQLAlchemy 비동기 엔진 생성

AsyncSessionLocal = sessionmaker(
    engine, expire_on_commit=False, class_=AsyncSession
)   # 비동기 DB 세션을 생성하는 세션 팩토리(sessionmaker) 생성

async def get_session():    # FastAPI에서 의존성 주입(Depends)에 사용할 비동기 세션 제공 함수
    async with AsyncSessionLocal() as session:
        yield session
