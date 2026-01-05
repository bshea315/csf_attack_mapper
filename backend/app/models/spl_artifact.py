"""SPL parsing artifacts model."""
from datetime import datetime
from sqlalchemy import Column, Integer, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.models.database import Base


class SplParseArtifact(Base):
    """Extracted artifacts from SPL parsing."""
    __tablename__ = "spl_parse_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    detection_id = Column(Integer, ForeignKey("detections.id"), unique=True, nullable=False)

    # Data sources
    indexes = Column(Text, nullable=True)  # JSON array
    sourcetypes = Column(Text, nullable=True)  # JSON array
    datamodels = Column(Text, nullable=True)  # JSON array

    # SPL elements
    macros = Column(Text, nullable=True)  # JSON array
    fields_referenced = Column(Text, nullable=True)  # JSON array
    commands_used = Column(Text, nullable=True)  # JSON array

    # Time and aggregation
    time_constraints = Column(Text, nullable=True)  # JSON object
    aggregations = Column(Text, nullable=True)  # JSON object
    thresholds = Column(Text, nullable=True)  # JSON array

    # Complexity analysis
    complexity_score = Column(Integer, nullable=True)
    complexity_signals = Column(Text, nullable=True)  # JSON object

    # Raw output
    raw_parse_output = Column(Text, nullable=True)  # Full parse tree

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    detection = relationship("Detection", back_populates="spl_artifacts")

    def __repr__(self):
        return f"<SplParseArtifact(detection_id={self.detection_id}, complexity={self.complexity_score})>"
