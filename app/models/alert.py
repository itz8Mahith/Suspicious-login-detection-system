"""
AuthSentinel - Security Alert Database Model
Tracks detected anomalies, severity levels, forensic evidence, and SOC status.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String(64), index=True, nullable=False)
    login_log_id = Column(Integer, ForeignKey("login_logs.id"), nullable=True)

    alert_type = Column(String(64), nullable=False, index=True) # IMPOSSIBLE_TRAVEL, BRUTE_FORCE, NEW_DEVICE, etc.
    severity = Column(String(16), nullable=False, index=True)   # LOW, MEDIUM, HIGH, CRITICAL
    title = Column(String(128), nullable=False)
    description = Column(Text, nullable=False)
    evidence_json = Column(Text, default="{}")

    # MITRE ATT&CK Context
    mitre_technique_id = Column(String(32), nullable=True)
    mitre_technique_name = Column(String(128), nullable=True)

    status = Column(String(32), default="OPEN") # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    user = relationship("User", back_populates="alerts")
    login_log = relationship("LoginLog", back_populates="alerts")
