"""Pydantic schemas for Playbook and SOAR execution data."""
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field


# ============================================================================
# Playbook Schemas
# ============================================================================

class PlaybookBase(BaseModel):
    """Base playbook schema."""
    playbook_id: str = Field(..., description="External ID from SOAR system")
    name: str = Field(..., max_length=500)
    description: Optional[str] = None
    is_active: bool = True
    category: Optional[str] = None
    time_saved_minutes: float = Field(default=0, description="Estimated time saved per successful run (minutes)")
    avg_manual_time_minutes: Optional[float] = Field(default=None, description="Avg time if done manually (minutes)")


class PlaybookCreate(PlaybookBase):
    """Schema for creating a playbook."""
    pass


class PlaybookUpdate(BaseModel):
    """Schema for updating a playbook."""
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    category: Optional[str] = None
    time_saved_minutes: Optional[float] = Field(default=None, description="Estimated time saved per successful run")
    avg_manual_time_minutes: Optional[float] = None


class PlaybookResponse(BaseModel):
    """Schema for playbook response."""
    id: int
    playbook_id: str
    name: str
    description: Optional[str] = None
    is_active: bool = True
    category: Optional[str] = None
    time_saved_minutes: float = 0
    avg_manual_time_minutes: Optional[float] = None
    created_at: datetime
    updated_at: datetime
    run_count: int = 0
    success_rate: Optional[float] = None
    linked_detection_count: int = 0
    total_time_saved_hours: float = 0  # Calculated: time_saved_minutes * successful_runs / 60

    class Config:
        from_attributes = True


class PlaybookListResponse(BaseModel):
    """Paginated list of playbooks."""
    items: List[PlaybookResponse]
    total: int
    page: int
    page_size: int
    pages: int


# ============================================================================
# Playbook Run Schemas
# ============================================================================

class PlaybookRunBase(BaseModel):
    """Base playbook run schema."""
    playbook_run_id: str = Field(..., description="External run ID from SOAR")
    status: str = Field(..., description="success|failure|running|cancelled")
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    container_id: Optional[str] = None


class PlaybookRunCreate(PlaybookRunBase):
    """Schema for creating a playbook run."""
    playbook_id: Optional[int] = None
    event_time: Optional[datetime] = None
    index_time: Optional[datetime] = None
    raw_event: Optional[str] = None


class PlaybookRunResponse(PlaybookRunBase):
    """Schema for playbook run response."""
    id: int
    playbook_id: Optional[int] = None
    playbook_name: Optional[str] = None
    event_time: Optional[datetime] = None
    action_count: int = 0
    successful_actions: int = 0
    failed_actions: int = 0
    created_at: datetime

    class Config:
        from_attributes = True


class PlaybookRunListResponse(BaseModel):
    """Paginated list of playbook runs."""
    items: List[PlaybookRunResponse]
    total: int
    page: int
    page_size: int
    pages: int


# ============================================================================
# Action Run Schemas
# ============================================================================

class ActionRunBase(BaseModel):
    """Base action run schema."""
    action_run_id: str = Field(..., description="External action run ID")
    action_name: str
    app_name: Optional[str] = None
    status: str = Field(..., description="success|failure")
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None


class ActionRunCreate(ActionRunBase):
    """Schema for creating an action run."""
    playbook_run_id: Optional[int] = None
    event_time: Optional[datetime] = None
    index_time: Optional[datetime] = None
    raw_event: Optional[str] = None


class ActionRunResponse(ActionRunBase):
    """Schema for action run response."""
    id: int
    playbook_run_id: Optional[int] = None
    event_time: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ActionRunListResponse(BaseModel):
    """Paginated list of action runs."""
    items: List[ActionRunResponse]
    total: int
    page: int
    page_size: int
    pages: int


# ============================================================================
# Detection-Playbook Link Schemas
# ============================================================================

class DetectionPlaybookLinkBase(BaseModel):
    """Base detection-playbook link schema."""
    detection_id: int
    playbook_id: int
    link_type: str = Field(default="manual", pattern="^(manual|auto)$")
    link_evidence: Optional[str] = None


class DetectionPlaybookLinkCreate(BaseModel):
    """Schema for creating a detection-playbook link."""
    detection_id: int
    link_type: str = Field(default="manual")


class DetectionPlaybookLinkResponse(DetectionPlaybookLinkBase):
    """Schema for detection-playbook link response."""
    id: int
    detection_name: Optional[str] = None
    playbook_name: Optional[str] = None
    created_by: Optional[int] = None
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================================
# SOAR Metrics Schemas
# ============================================================================

class PlaybookTimeSaved(BaseModel):
    """Time saved breakdown for a single playbook."""
    playbook_id: int
    playbook_name: str
    category: Optional[str] = None
    successful_runs: int
    time_saved_per_run_minutes: float
    total_time_saved_minutes: float
    total_time_saved_hours: float


class PlaybookMetrics(BaseModel):
    """Metrics for a single playbook."""
    playbook_id: int
    playbook_name: str
    category: Optional[str] = None
    total_runs: int
    successful_runs: int
    failed_runs: int
    success_rate: float
    avg_duration_seconds: Optional[float] = None
    p50_duration_seconds: Optional[float] = None
    p95_duration_seconds: Optional[float] = None
    last_run_at: Optional[datetime] = None
    linked_detections: int = 0
    time_saved_per_run_minutes: float = 0
    total_time_saved_hours: float = 0


class ActionMetrics(BaseModel):
    """Metrics for a single action type."""
    action_name: str
    app_name: Optional[str] = None
    total_runs: int
    successful_runs: int
    failed_runs: int
    success_rate: float
    avg_duration_seconds: Optional[float] = None
    common_errors: List[str] = []


class AppMetrics(BaseModel):
    """Metrics for a SOAR app/integration."""
    app_name: str
    total_actions: int
    successful_actions: int
    failed_actions: int
    success_rate: float
    unique_action_types: int
    avg_action_duration: Optional[float] = None


class SOAROverviewMetrics(BaseModel):
    """Overall SOAR metrics."""
    # Playbook metrics
    total_playbooks: int
    active_playbooks: int
    playbooks_with_time_config: int  # Playbooks that have time_saved_minutes configured

    # Run metrics
    total_runs: int
    successful_runs: int
    failed_runs: int
    cancelled_runs: int = 0
    overall_success_rate: float

    # Action metrics
    total_actions: int
    avg_actions_per_run: float
    unique_action_types: int = 0
    unique_apps: int = 0

    # Performance metrics
    avg_run_duration_seconds: Optional[float] = None
    median_run_duration_seconds: Optional[float] = None

    # Time-based run counts
    runs_last_24h: int = 0
    runs_last_7d: int = 0
    runs_last_30d: int = 0

    # Time savings metrics (KEY FEATURE)
    total_time_saved_minutes: float = 0
    total_time_saved_hours: float = 0
    estimated_cost_savings: float = 0  # Based on avg analyst hourly rate

    # Detection linkage
    linked_detections: int = 0
    unlinked_detections: int = 0
    automation_coverage_percent: float = 0  # % of detections with playbooks

    # Efficiency metrics
    mttr_minutes: Optional[float] = None  # Mean Time to Respond (based on playbook duration)
    automation_rate: float = 0  # % of runs that completed automatically (success + failure vs cancelled)


class SOARDashboardResponse(BaseModel):
    """Full SOAR dashboard data."""
    overview: SOAROverviewMetrics
    time_saved_by_playbook: List[PlaybookTimeSaved]  # NEW: Time breakdown
    top_playbooks: List[PlaybookMetrics]
    top_actions: List[ActionMetrics]
    top_apps: List[AppMetrics]  # NEW: App metrics
    recent_failures: List[PlaybookRunResponse]
    time_series: List[dict]  # For charting runs over time
    category_breakdown: List[dict]  # NEW: Runs by playbook category


class PlaybookStatsResponse(BaseModel):
    """Statistics for a specific playbook."""
    playbook: PlaybookResponse
    metrics: PlaybookMetrics
    action_breakdown: List[ActionMetrics]
    recent_runs: List[PlaybookRunResponse]
    linked_detections: List[dict]  # Simplified detection info
