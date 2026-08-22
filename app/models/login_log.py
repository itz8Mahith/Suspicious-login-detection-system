"""
AuthSentinel - Login Audit Log Database Model
Stores every authentication event with rich geolocation, client fingerprints, and risk analytics.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

class LoginLog(Base):
    __tablename__ = "login_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String(64), index=True, nullable=False)

    # Network & Geolocation Metadata
    ip_address = Column(String(45), nullable=False)
    city = Column(String(64), nullable=True)
    country = Column(String(64), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)

    # Client Environment & Fingerprint
    user_agent = Column(Text, nullable=False)
    device_fingerprint = Column(String(128), nullable=True)
    device_type = Column(String(32), default="Desktop")
    os_name = Column(String(32), default="Windows")
    browser = Column(String(32), default="Chrome")

    # Authentication Outcome & Risk Analytics
    is_success = Column(Boolean, default=True)
    failure_reason = Column(String(128), nullable=True)
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(16), default="LOW")
    action_taken = Column(String(32), default="ALLOW")
    triggered_rules_json = Column(Text, default="[]")

    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    user = relationship("User", back_populates="logs")
    alerts = relationship("SecurityAlert", back_populates="login_log")
