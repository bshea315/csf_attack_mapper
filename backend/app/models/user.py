"""User and authentication models."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.models.database import Base


class User(Base):
    """User model for authentication and authorization."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="viewer")  # admin|editor|viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    audit_logs = relationship("AuditLog", back_populates="user")
    detection_versions = relationship("DetectionVersion", back_populates="created_by_user")
    detection_mappings = relationship("DetectionMitreMapping", back_populates="created_by_user")
    ingest_batches = relationship("IngestBatch", back_populates="created_by_user")

    def __repr__(self):
        return f"<User(id={self.id}, username={self.username}, role={self.role})>"


class AuditLog(Base):
    """Audit log for tracking changes."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(50), nullable=False)  # create|update|delete|login|logout
    entity_type = Column(String(50), nullable=False)  # detection|mapping|user|etc.
    entity_id = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)  # JSON string with before/after
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    user = relationship("User", back_populates="audit_logs")

    def __repr__(self):
        return f"<AuditLog(id={self.id}, action={self.action}, entity={self.entity_type})>"
