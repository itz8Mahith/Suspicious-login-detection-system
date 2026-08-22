"""
AuthSentinel - Database Configuration and Session Management
Uses SQLite with SQLAlchemy. Automatically supports local directories and cloud serverless (/tmp on Vercel).
"""

import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Detect Vercel / serverless read-only container environments
if os.environ.get("VERCEL") or not os.access(".", os.W_OK):
    DB_DIR = Path("/tmp")
else:
    DB_DIR = Path("./data")
    try:
        DB_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        DB_DIR = Path("/tmp")

DB_PATH = DB_DIR / "sentinel.db"
DATABASE_URL = f"sqlite:///{DB_PATH.as_posix()}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """Dependency for obtaining a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Create all database tables on application startup."""
    import app.models.user
    import app.models.login_log
    import app.models.alert
    Base.metadata.create_all(bind=engine)
