"""NIST CSF 2.0 models."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.models.database import Base


class CsfCategory(Base):
    """NIST CSF 2.0 category/subcategory reference."""
    __tablename__ = "csf_categories"

    id = Column(String(20), primary_key=True)  # GV.RM-1, DE.CM-1, etc.
    function = Column(String(20), nullable=False, index=True)  # GOVERN|IDENTIFY|PROTECT|DETECT|RESPOND|RECOVER
    category = Column(String(20), nullable=False, index=True)  # GV.RM, DE.CM, etc.
    subcategory = Column(String(20), nullable=True)  # The full subcategory ID
    name = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    mitre_mappings = relationship("MitreToCsfMapping", back_populates="csf_category")
    detection_impacts = relationship("DetectionCsfImpact", back_populates="csf_category")

    def __repr__(self):
        return f"<CsfCategory(id={self.id}, function={self.function})>"


class MitreToCsfMapping(Base):
    """Curated mapping from MITRE techniques to CSF categories."""
    __tablename__ = "mitre_to_csf_mappings"

    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String(20), ForeignKey("mitre_techniques.id"), nullable=False)
    csf_id = Column(String(20), ForeignKey("csf_categories.id"), nullable=False)
    weight = Column(Float, nullable=False, default=0.5)  # Impact weight 0-1
    rationale = Column(Text, nullable=True)
    source = Column(String(20), default="curated")  # curated|manual
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    technique = relationship("MitreTechnique", back_populates="csf_mappings")
    csf_category = relationship("CsfCategory", back_populates="mitre_mappings")

    def __repr__(self):
        return f"<MitreToCsfMapping(technique={self.technique_id}, csf={self.csf_id})>"


class DetectionCsfImpact(Base):
    """Computed detection impact on CSF categories."""
    __tablename__ = "detection_csf_impact"

    id = Column(Integer, primary_key=True, index=True)
    detection_id = Column(Integer, ForeignKey("detections.id"), nullable=False)
    csf_id = Column(String(20), ForeignKey("csf_categories.id"), nullable=False)
    impact_score = Column(Float, nullable=False)  # Computed weighted score
    contributing_techniques = Column(Text, nullable=True)  # JSON array of technique IDs
    computed_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    detection = relationship("Detection", back_populates="csf_impacts")
    csf_category = relationship("CsfCategory", back_populates="detection_impacts")

    def __repr__(self):
        return f"<DetectionCsfImpact(detection={self.detection_id}, csf={self.csf_id})>"
