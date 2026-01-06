"""Playbook model for SOAR integration."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Float
from sqlalchemy.orm import relationship
from app.models.database import Base


class Playbook(Base):
    """
    SOAR Playbook reference.

    Stores playbook metadata extracted from SOAR execution logs.
    Playbooks can be linked to detections for response automation tracking.
    """
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(String(100), unique=True, nullable=False, index=True)  # External ID from SOAR
    name = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    category = Column(String(100), nullable=True)  # e.g., "Enrichment", "Response", "Containment"

    # Time savings metrics
    time_saved_minutes = Column(Float, default=0)  # Estimated time saved per successful run
    avg_manual_time_minutes = Column(Float, nullable=True)  # Avg time if done manually (for ROI)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    runs = relationship("PlaybookRun", back_populates="playbook", cascade="all, delete-orphan")
    detection_links = relationship("DetectionPlaybookLink", back_populates="playbook", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Playbook(id={self.id}, playbook_id='{self.playbook_id}', name='{self.name}')>"
