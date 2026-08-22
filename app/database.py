"""
AuthSentinel - Database Configuration and Session Management
Uses SQLite with SQLAlchemy for zero-configuration, reliable persistence.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./data/sentinel.db"

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
