"""Pydantic schemas for Splunk configuration."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class SplunkConfigBase(BaseModel):
    """Base Splunk configuration schema."""
    name: str = Field(default="default", max_length=100)
    base_url: str = Field(..., description="Splunk REST API base URL (e.g., https://splunk-sh.company.com:8089)")
    auth_type: str = Field(default="token", pattern="^(token|basic)$")
    verify_tls: bool = True
    es_app_namespace: str = Field(default="SplunkEnterpriseSecuritySuite")
    es_owner: str = Field(default="nobody")
    soar_playbook_run_index: str = Field(default="phantom_playbook_run")
    soar_action_run_index: str = Field(default="phantom_action_run")
    soar_time_window_days: int = Field(default=30, ge=1, le=365)

    @field_validator('base_url')
    @classmethod
    def validate_base_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('base_url must start with http:// or https://')
        return v.rstrip('/')


class SplunkConfigCreate(SplunkConfigBase):
    """Schema for creating Splunk config."""
    auth_token: Optional[str] = Field(default=None, description="Bearer token for authentication")
    auth_username: Optional[str] = Field(default=None, description="Username for basic auth")
    auth_password: Optional[str] = Field(default=None, description="Password for basic auth")

    @field_validator('auth_token', 'auth_password')
    @classmethod
    def validate_secrets(cls, v):
        if v and len(v) < 8:
            raise ValueError('Secret must be at least 8 characters')
        return v


class SplunkConfigUpdate(BaseModel):
    """Schema for updating Splunk config."""
    name: Optional[str] = None
    base_url: Optional[str] = None
    auth_type: Optional[str] = None
    auth_token: Optional[str] = None  # Will be encrypted
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None  # Will be encrypted
    verify_tls: Optional[bool] = None
    es_app_namespace: Optional[str] = None
    es_owner: Optional[str] = None
    soar_playbook_run_index: Optional[str] = None
    soar_action_run_index: Optional[str] = None
    soar_time_window_days: Optional[int] = None


class SplunkConfigResponse(SplunkConfigBase):
    """Schema for Splunk config response (masks secrets)."""
    id: int
    has_token: bool = False
    has_password: bool = False
    is_active: bool
    last_es_sync_at: Optional[datetime] = None
    last_soar_sync_at: Optional[datetime] = None
    es_detection_count: int = 0
    soar_playbook_count: int = 0
    soar_run_count: int = 0
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SplunkConnectionTestRequest(BaseModel):
    """Request for testing Splunk connection."""
    pass  # Uses stored config


class SplunkConnectionTestResponse(BaseModel):
    """Response from Splunk connection test."""
    success: bool
    message: str
    server_info: Optional[dict] = None
    error: Optional[str] = None


class ESSyncRequest(BaseModel):
    """Request for ES detection sync."""
    pass  # Uses stored config


class ESSyncResponse(BaseModel):
    """Response from ES detection sync."""
    success: bool
    total_found: int = 0
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    failed: int = 0
    errors: list[str] = []
    duration_seconds: float = 0.0


class SOARSyncRequest(BaseModel):
    """Request for SOAR log sync."""
    days: int = Field(default=30, ge=1, le=365)


class SOARSyncResponse(BaseModel):
    """Response from SOAR log sync."""
    success: bool
    playbook_runs_found: int = 0
    playbook_runs_created: int = 0
    action_runs_found: int = 0
    action_runs_created: int = 0
    playbooks_discovered: int = 0
    errors: list[str] = []
    duration_seconds: float = 0.0
