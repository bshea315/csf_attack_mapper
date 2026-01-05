"""Detection and ingest schemas."""
from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field


class SplArtifactResponse(BaseModel):
    """Schema for SPL parse artifacts."""
    indexes: List[str] = []
    sourcetypes: List[str] = []
    datamodels: List[str] = []
    macros: List[str] = []
    fields_referenced: List[str] = []
    commands_used: List[str] = []
    time_constraints: Optional[Dict[str, Any]] = None
    aggregations: Optional[Dict[str, Any]] = None
    thresholds: List[Dict[str, Any]] = []
    complexity_score: Optional[int] = None
    complexity_signals: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class DetectionCreate(BaseModel):
    """Schema for creating a detection."""
    detection_id: str = Field(..., min_length=1, max_length=255)
    name: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    spl: str = Field(..., min_length=1)
    severity: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    status: str = Field(default="enabled", pattern="^(enabled|disabled)$")
    owner_team: Optional[str] = None
    original_mitre_tags: Optional[List[str]] = None
    data_source_notes: Optional[str] = None


class DetectionUpdate(BaseModel):
    """Schema for updating a detection."""
    name: Optional[str] = Field(None, max_length=500)
    description: Optional[str] = None
    spl: Optional[str] = None
    severity: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    status: Optional[str] = Field(None, pattern="^(enabled|disabled)$")
    owner_team: Optional[str] = None
    data_source_notes: Optional[str] = None


class MitreMappingSummary(BaseModel):
    """Summary of a MITRE mapping for detection response."""
    technique_id: str
    technique_name: str
    confidence: float
    method: str
    is_accepted: bool


class CsfImpactSummary(BaseModel):
    """Summary of CSF impact for detection response."""
    csf_id: str
    function: str
    impact_score: float


class DetectionResponse(BaseModel):
    """Schema for detection response."""
    id: int
    detection_id: str
    name: str
    description: Optional[str]
    spl: str
    severity: Optional[str]
    status: str
    owner_team: Optional[str]
    original_mitre_tags: Optional[List[str]]
    data_source_notes: Optional[str]
    created_at: datetime
    updated_at: datetime
    spl_artifacts: Optional[SplArtifactResponse] = None
    mitre_mappings: List[MitreMappingSummary] = []
    csf_impacts: List[CsfImpactSummary] = []

    class Config:
        from_attributes = True


class DetectionListResponse(BaseModel):
    """Schema for paginated detection list."""
    items: List[DetectionResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class DetectionVersionResponse(BaseModel):
    """Schema for detection version history."""
    id: int
    version_number: int
    spl: str
    changed_fields: Optional[Dict[str, Any]]
    created_by: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class IngestBatchResponse(BaseModel):
    """Schema for ingest batch status."""
    id: int
    source_type: str
    source_filename: Optional[str]
    total_records: Optional[int]
    successful: int
    failed: int
    warnings: List[str] = []
    status: str
    error_message: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class IngestPasteRequest(BaseModel):
    """Schema for paste ingest request."""
    content: str = Field(..., min_length=1)


class IngestPreviewResponse(BaseModel):
    """Schema for ingest preview."""
    detected_format: str
    record_count: int
    sample_records: List[Dict[str, Any]]
    validation_warnings: List[str] = []
