"""Detection and ingest batch models."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.models.database import Base


class Detection(Base):
    """SPL detection/correlation search model."""
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    detection_id = Column(String(255), unique=True, nullable=False, index=True)  # External ID
    name = Column(String(500), nullable=False, index=True)
    description = Column(Text, nullable=True)
    spl = Column(Text, nullable=False)
    severity = Column(String(20), nullable=True)  # low|medium|high|critical
    status = Column(String(20), default="enabled")  # enabled|disabled
    owner_team = Column(String(100), nullable=True)
    original_mitre_tags = Column(Text, nullable=True)  # JSON array from source
    data_source_notes = Column(Text, nullable=True)
    ingest_batch_id = Column(Integer, ForeignKey("ingest_batches.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    ingest_batch = relationship("IngestBatch", back_populates="detections")
    versions = relationship("DetectionVersion", back_populates="detection", order_by="DetectionVersion.version_number.desc()")
    spl_artifacts = relationship("SplParseArtifact", back_populates="detection", uselist=False)
    mitre_mappings = relationship("DetectionMitreMapping", back_populates="detection", cascade="all, delete-orphan")
    csf_impacts = relationship("DetectionCsfImpact", back_populates="detection", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Detection(id={self.id}, name={self.name[:50]})>"


class DetectionVersion(Base):
    """Version history for detection changes."""
    __tablename__ = "detection_versions"

    id = Column(Integer, primary_key=True, index=True)
    detection_id = Column(Integer, ForeignKey("detections.id"), nullable=False)
    version_number = Column(Integer, nullable=False)
    spl = Column(Text, nullable=False)
    changed_fields = Column(Text, nullable=True)  # JSON of what changed
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    detection = relationship("Detection", back_populates="versions")
    created_by_user = relationship("User", back_populates="detection_versions")

    def __repr__(self):
        return f"<DetectionVersion(detection_id={self.detection_id}, v={self.version_number})>"


class IngestBatch(Base):
    """Track ingest job batches."""
    __tablename__ = "ingest_batches"

    id = Column(Integer, primary_key=True, index=True)
    source_type = Column(String(20), nullable=False)  # csv|yaml|paste
    source_filename = Column(String(500), nullable=True)
    total_records = Column(Integer, nullable=True)
    successful = Column(Integer, default=0)
    failed = Column(Integer, default=0)
    warnings = Column(Text, nullable=True)  # JSON array
    status = Column(String(20), default="pending")  # pending|processing|completed|failed
    error_message = Column(Text, nullable=True)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    created_by_user = relationship("User", back_populates="ingest_batches")
    detections = relationship("Detection", back_populates="ingest_batch")

    def __repr__(self):
        return f"<IngestBatch(id={self.id}, type={self.source_type}, status={self.status})>"
