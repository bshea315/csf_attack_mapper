"""SOAR execution models for playbook runs, action runs, and detection links."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, Text, ForeignKey, Index
from sqlalchemy.orm import relationship
from app.models.database import Base


class PlaybookRun(Base):
    """
    Record of a single playbook execution.

    Extracted from Splunk phantom_playbook_run index.
    """
    __tablename__ = "playbook_runs"

    id = Column(Integer, primary_key=True, index=True)
    playbook_run_id = Column(String(100), unique=True, nullable=False, index=True)  # External run ID
    playbook_id = Column(Integer, ForeignKey("playbooks.id"), nullable=True, index=True)

    # Execution details
    status = Column(String(50), nullable=False, index=True)  # success|failure|running|cancelled
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    container_id = Column(String(100), nullable=True)  # SOAR container/case ID

    # Splunk event metadata
    event_time = Column(DateTime, nullable=True)  # _time from Splunk
    index_time = Column(DateTime, nullable=True)  # _indextime from Splunk

    # Raw data for debugging/audit
    raw_event = Column(Text, nullable=True)  # JSON blob of full Splunk event

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    playbook = relationship("Playbook", back_populates="runs")
    action_runs = relationship("ActionRun", back_populates="playbook_run", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_playbook_runs_event_time', 'event_time'),
        Index('idx_playbook_runs_status_time', 'status', 'event_time'),
    )

    def __repr__(self):
        return f"<PlaybookRun(id={self.id}, run_id='{self.playbook_run_id}', status='{self.status}')>"


class ActionRun(Base):
    """
    Record of a single action execution within a playbook run.

    Extracted from Splunk phantom_action_run index.
    """
    __tablename__ = "action_runs"

    id = Column(Integer, primary_key=True, index=True)
    action_run_id = Column(String(100), unique=True, nullable=False, index=True)  # External action run ID
    playbook_run_id = Column(Integer, ForeignKey("playbook_runs.id"), nullable=True, index=True)

    # Action details
    action_name = Column(String(200), nullable=False, index=True)
    app_name = Column(String(200), nullable=True)
    status = Column(String(50), nullable=False, index=True)  # success|failure
    duration_seconds = Column(Float, nullable=True)
    error_message = Column(Text, nullable=True)

    # Splunk event metadata
    event_time = Column(DateTime, nullable=True)
    index_time = Column(DateTime, nullable=True)

    # Raw data
    raw_event = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    playbook_run = relationship("PlaybookRun", back_populates="action_runs")

    __table_args__ = (
        Index('idx_action_runs_action_status', 'action_name', 'status'),
    )

    def __repr__(self):
        return f"<ActionRun(id={self.id}, action='{self.action_name}', status='{self.status}')>"


class DetectionPlaybookLink(Base):
    """
    Links a detection to a playbook for response automation tracking.

    Can be created manually or via auto-linking heuristics.
    """
    __tablename__ = "detection_playbook_links"

    id = Column(Integer, primary_key=True, index=True)
    detection_id = Column(Integer, ForeignKey("detections.id", ondelete="CASCADE"), nullable=False, index=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False, index=True)

    # Link metadata
    link_type = Column(String(20), default="manual")  # manual|auto
    link_evidence = Column(Text, nullable=True)  # JSON: why auto-linked
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    detection = relationship("Detection", back_populates="playbook_links")
    playbook = relationship("Playbook", back_populates="detection_links")

    __table_args__ = (
        Index('idx_detection_playbook_unique', 'detection_id', 'playbook_id', unique=True),
    )

    def __repr__(self):
        return f"<DetectionPlaybookLink(detection_id={self.detection_id}, playbook_id={self.playbook_id})>"
