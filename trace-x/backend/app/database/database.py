"""Database setup. SQLite by default; PostgreSQL-ready via TRACE_X_DB_URL."""
import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# Repo root: backend/app/database -> up 3 levels
REPO_ROOT = Path(__file__).resolve().parents[3]

DATABASE_URL = os.environ.get("TRACE_X_DB_URL", f"sqlite:///{REPO_ROOT / 'data' / 'tracex.db'}")

_is_sqlite = DATABASE_URL.startswith("sqlite")

if _is_sqlite and ":///:memory:" not in DATABASE_URL:
    # Ensure the sqlite file directory exists
    db_path = Path(DATABASE_URL.replace("sqlite:///", "", 1))
    db_path.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(bind=engine)
