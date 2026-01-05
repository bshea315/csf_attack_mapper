"""MITRE ATT&CK models."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.models.database import Base


class MitreTechnique(Base):
    """MITRE ATT&CK technique reference."""
    __tablename__ = "mitre_techniques"

    id = Column(String(20), primary_key=True)  # T1110, T1110.001, etc.
    name = Column(String(500), nullable=False, index=True)
    description = Column(Text, nullable=True)
    tactics = Column(Text, nullable=False)  # JSON array of tactics
    platforms = Column(Text, nullable=True)  # JSON array
    data_sources = Column(Text, nullable=True)  # JSON array
    is_subtechnique = Column(Boolean, default=False)
    parent_technique_id = Column(String(20), ForeignKey("mitre_techniques.id"), nullable=True)
    external_references = Column(Text, nullable=True)  # JSON
    url = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    parent_technique = relationship("MitreTechnique", remote_side=[id], backref="subtechniques")
    detection_mappings = relationship("DetectionMitreMapping", back_populates="technique")
    csf_mappings = relationship("MitreToCsfMapping", back_populates="technique")

    def __repr__(self):
        return f"<MitreTechnique(id={self.id}, name={self.name[:50]})>"


class DetectionMitreMapping(Base):
    """Mapping between detections and MITRE techniques."""
    __tablename__ = "detection_mitre_mappings"

    id = Column(Integer, primary_key=True, index=True)
    detection_id = Column(Integer, ForeignKey("detections.id"), nullable=False)
    technique_id = Column(String(20), ForeignKey("mitre_techniques.id"), nullable=False)
    confidence = Column(Float, nullable=False)  # 0.0 to 1.0
    method = Column(String(20), nullable=False)  # rule|manual
    rule_id = Column(String(100), nullable=True)  # Which rule matched
    rationale = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)  # JSON: matched tokens
    is_accepted = Column(Boolean, default=True)  # User can reject
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    detection = relationship("Detection", back_populates="mitre_mappings")
    technique = relationship("MitreTechnique", back_populates="detection_mappings")
    created_by_user = relationship("User", back_populates="detection_mappings")

    def __repr__(self):
        return f"<DetectionMitreMapping(detection={self.detection_id}, technique={self.technique_id})>"

    class Config:
        # Unique constraint on detection_id + technique_id
        __table_args__ = (
            {"sqlite_autoincrement": True},
        )
