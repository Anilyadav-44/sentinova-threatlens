from typing import AsyncGenerator, Generator

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings


# ---------------------------------------------------------
# Base Model Definition
# ---------------------------------------------------------
class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------
# Async Engine & Session Manager (Primary SQLAlchemy 2.0 AsyncIO)
# ---------------------------------------------------------
async_connect_args = {}
if settings.async_database_url.startswith("sqlite"):
    async_connect_args["check_same_thread"] = False

async_engine = create_async_engine(
    settings.async_database_url,
    connect_args=async_connect_args,
    pool_pre_ping=True,
    echo=False,
    future=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)

async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that yields an asynchronous database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ---------------------------------------------------------
# Sync Engine & Session Manager (For sync tasks, migrations, & compatibility)
# ---------------------------------------------------------
sync_connect_args = {}
if settings.sync_database_url.startswith("sqlite"):
    sync_connect_args["check_same_thread"] = False

engine = create_engine(
    settings.sync_database_url,
    connect_args=sync_connect_args,
    pool_pre_ping=True,
    echo=False,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

def get_db() -> Generator:
    """Dependency that yields a synchronous database session."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


async def init_async_db() -> None:
    """Creates database tables asynchronously."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
