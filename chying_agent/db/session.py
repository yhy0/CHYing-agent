"""
Database session management for CHYing Agent.

Provides SQLite database connection and session management.
"""

import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from .models import Base

# Database path - relative to project root
_PROJECT_ROOT = Path(__file__).parent.parent.parent
DB_PATH = _PROJECT_ROOT / "data" / "chying.db"

# Ensure data directory exists
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DB_PATH}"

# Create engine with SQLite-specific settings
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite with threads
    echo=os.getenv("DB_ECHO", "false").lower() == "true",
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Initialize database tables.

    Creates all tables defined in models if they don't exist.
    Runs lightweight migrations for new columns on existing tables.
    Safe to call multiple times.
    """
    Base.metadata.create_all(bind=engine)
    _migrate_add_columns()


def get_db_session() -> Session:
    """Get a new database session.

    Caller is responsible for closing the session.
    Prefer using get_db() context manager instead.

    Returns:
        Session: A new SQLAlchemy session
    """
    return SessionLocal()


@contextmanager
def get_db() -> Generator[Session, None, None]:
    """Get database session as context manager.

    Automatically handles commit on success and rollback on error.

    Usage:
        with get_db() as db:
            db.add(some_object)
            # Auto-commits on exit

    Yields:
        Session: SQLAlchemy session
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_db_dependency() -> Generator[Session, None, None]:
    """FastAPI dependency for database session.

    Usage in FastAPI:
        @app.get("/items")
        def get_items(db: Session = Depends(get_db_dependency)):
            return db.query(Item).all()

    Yields:
        Session: SQLAlchemy session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


_logger = logging.getLogger(__name__)


def _migrate_add_columns() -> None:
    """Add missing columns to existing tables (idempotent).

    SQLAlchemy create_all only creates missing tables, not missing columns.
    This function inspects existing tables and adds any new columns defined
    in models but absent from the DB schema.
    """
    _new_columns = {
        "executions": {
            "total_cost_usd": "REAL",
            "input_tokens": "INTEGER",
            "output_tokens": "INTEGER",
        },
    }

    insp = inspect(engine)
    with engine.begin() as conn:
        for table_name, columns in _new_columns.items():
            if not insp.has_table(table_name):
                continue
            existing = {col["name"] for col in insp.get_columns(table_name)}
            for col_name, col_type in columns.items():
                if col_name not in existing:
                    conn.execute(text(
                        f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}"
                    ))
                    _logger.info(f"[DB Migration] Added column {table_name}.{col_name}")
