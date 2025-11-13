# api/core/db.py
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from .config import settings

engine = create_async_engine(
    settings.ASYNC_DATABASE_URL,
    future=True,
    echo=False,
)

AsyncSessionLocal = sessionmaker(
    engine, expire_on_commit=False, class_=AsyncSession
)

async def get_session():
    async with AsyncSessionLocal() as session:
        yield session
