"""Mapping schemas for MITRE and CSF."""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class MitreTechniqueResponse(BaseModel):
    """Schema for MITRE technique."""
    id: str
    name: str
    description: Optional[str]
    tactics: List[str]
    platforms: List[str] = []
    data_sources: List[str] = []
    is_subtechnique: bool
    parent_technique_id: Optional[str]
    url: Optional[str]
    detection_count: int = 0

    class Config:
        from_attributes = True


class DetectionMitreMappingCreate(BaseModel):
    """Schema for creating a MITRE mapping."""
    technique_id: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    rationale: str = Field(..., min_length=1)
    method: str = Field(default="manual", pattern="^(rule|manual)$")


class DetectionMitreMappingUpdate(BaseModel):
    """Schema for updating a MITRE mapping."""
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    rationale: Optional[str] = None
    is_accepted: Optional[bool] = None


class DetectionMitreMappingResponse(BaseModel):
    """Schema for MITRE mapping response."""
    id: int
    detection_id: int
    technique_id: str
    technique_name: str
    technique_tactics: List[str]
    confidence: float
    method: str
    rule_id: Optional[str]
    rationale: str
    evidence: Optional[Dict[str, Any]]
    is_accepted: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CsfCategoryResponse(BaseModel):
    """Schema for CSF category."""
    id: str
    function: str
    category: str
    subcategory: Optional[str]
    name: str
    description: Optional[str]
    detection_count: int = 0
    coverage_score: float = 0.0

    class Config:
        from_attributes = True


class MitreToCsfMappingCreate(BaseModel):
    """Schema for creating MITRE to CSF mapping."""
    technique_id: str
    csf_id: str
    weight: float = Field(..., ge=0.0, le=1.0)
    rationale: Optional[str] = None


class MitreToCsfMappingUpdate(BaseModel):
    """Schema for updating MITRE to CSF mapping."""
    weight: Optional[float] = Field(None, ge=0.0, le=1.0)
    rationale: Optional[str] = None


class MitreToCsfMappingResponse(BaseModel):
    """Schema for MITRE to CSF mapping response."""
    id: int
    technique_id: str
    technique_name: str
    csf_id: str
    csf_function: str
    csf_name: str
    weight: float
    rationale: Optional[str]
    source: str
    created_at: datetime

    class Config:
        from_attributes = True


class DetectionCsfImpactResponse(BaseModel):
    """Schema for detection CSF impact."""
    csf_id: str
    csf_function: str
    csf_category: str
    csf_name: str
    impact_score: float
    contributing_techniques: List[str]
    computed_at: datetime

    class Config:
        from_attributes = True
