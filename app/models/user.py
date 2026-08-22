"""
AuthSentinel - User & Behavioral Baseline Database Models
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    full_name = Column(String(128), nullable=False)
    role = Column(String(32), default="Employee")
    is_locked = Column(Boolean, default=False)
    failed_attempt_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    baseline = relationship("UserBaseline", back_populates="user", uselist=False)
    logs = relationship("LoginLog", back_populates="user")
    alerts = relationship("SecurityAlert", back_populates="user")

class UserBaseline(Base):
    __tablename__ = "user_baselines"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)

    # Historical profiles stored as JSON strings
    typical_hours_json = Column(Text, default="[9, 10, 11, 12, 13, 14, 15, 16, 17]") # Typical active hours (9 AM - 5 PM)
    known_devices_json = Column(Text, default="[]")  # List of known device fingerprints / User-Agents
    known_countries_json = Column(Text, default="[\"India\"]")  # List of primary home/work countries
    known_ips_json = Column(Text, default="[]")

    # Last observed successful login state for velocity calculation
    last_login_at = Column(DateTime, nullable=True)
    last_ip = Column(String(45), nullable=True)
    last_city = Column(String(64), nullable=True)
    last_country = Column(String(64), nullable=True)
    last_latitude = Column(Float, nullable=True)
    last_longitude = Column(Float, nullable=True)
    last_device_fingerprint = Column(String(128), nullable=True)

    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    user = relationship("User", back_populates="baseline")
