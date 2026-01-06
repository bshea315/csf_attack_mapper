"""Analytics and reporting schemas."""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class OverviewStats(BaseModel):
    """Dashboard overview statistics."""
    total_detections: int
    enabled_detections: int
    disabled_detections: int
    enabled_percentage: float
    techniques_covered: int
    total_techniques: int
    technique_coverage_percentage: float
    csf_functions_covered: int
    average_csf_coverage: float
    last_ingest_at: Optional[datetime]
    recent_ingests: List[Dict[str, Any]] = []


class TechniqueCoverage(BaseModel):
    """Coverage data for a single technique."""
    technique_id: str
    technique_name: str
    tactics: List[str]
    detection_count: int
    weighted_coverage: float
    is_subtechnique: bool = False
    parent_technique_id: Optional[str] = None
    url: Optional[str] = None
    detections: List[Dict[str, Any]] = []


class AttackCoverageResponse(BaseModel):
    """ATT&CK matrix coverage data."""
    tactics: List[str]
    techniques_by_tactic: Dict[str, List[TechniqueCoverage]]
    total_techniques: int
    covered_techniques: int
    coverage_percentage: float
    top_covered: List[TechniqueCoverage]
    uncovered: List[Dict[str, str]]


class CsfFunctionCoverage(BaseModel):
    """Coverage data for a CSF function."""
    function: str
    categories: List[Dict[str, Any]]
    total_subcategories: int
    covered_subcategories: int
    average_score: float
    detection_count: int


class CsfCoverageResponse(BaseModel):
    """CSF posture coverage data."""
    functions: List[CsfFunctionCoverage]
    overall_score: float
    govern_score: float
    identify_score: float
    protect_score: float
    detect_score: float
    respond_score: float
    recover_score: float


class GapItem(BaseModel):
    """Single gap item."""
    type: str  # technique_gap|csf_gap|quality_issue
    id: str
    name: str
    severity: str  # high|medium|low
    description: str
    recommendation: str
    impact_estimate: float


class GapAnalysisResponse(BaseModel):
    """Gap analysis results."""
    technique_gaps: List[GapItem]
    csf_gaps: List[GapItem]
    quality_issues: List[GapItem]
    total_gaps: int
    critical_gaps: int
    high_priority_items: List[GapItem]


class RecommendationItem(BaseModel):
    """Single recommendation."""
    id: str
    type: str  # add_detection|tune_detection|enable_detection|reduce_complexity
    priority: int  # 1-10
    title: str
    description: str
    evidence: List[str]
    impact_estimate: float
    affected_techniques: List[str] = []
    affected_csf: List[str] = []
    detection_id: Optional[int] = None


class RecommendationResponse(BaseModel):
    """Recommendations for improving coverage."""
    recommendations: List[RecommendationItem]
    total_count: int
    by_type: Dict[str, int]


class CrosswalkItem(BaseModel):
    """Single crosswalk relationship."""
    technique_id: str
    technique_name: str
    csf_id: str
    csf_function: str
    csf_name: str
    weight: float
    detection_count: int
    detections: List[Dict[str, Any]] = []


class CrosswalkResponse(BaseModel):
    """Crosswalk view data."""
    items: List[CrosswalkItem]
    techniques_with_csf: int
    csf_with_techniques: int
    total_mappings: int
