"""Pydantic schemas package."""
from app.schemas.user import (
    UserCreate,
    UserUpdate,
    UserResponse,
    Token,
    TokenData,
    LoginRequest,
)
from app.schemas.detection import (
    DetectionCreate,
    DetectionUpdate,
    DetectionResponse,
    DetectionListResponse,
    DetectionVersionResponse,
    IngestBatchResponse,
    SplArtifactResponse,
)
from app.schemas.mapping import (
    MitreTechniqueResponse,
    DetectionMitreMappingCreate,
    DetectionMitreMappingUpdate,
    DetectionMitreMappingResponse,
    CsfCategoryResponse,
    MitreToCsfMappingResponse,
    DetectionCsfImpactResponse,
)
from app.schemas.analytics import (
    OverviewStats,
    AttackCoverageResponse,
    CsfCoverageResponse,
    GapAnalysisResponse,
    RecommendationResponse,
    CrosswalkResponse,
)

__all__ = [
    # User schemas
    "UserCreate",
    "UserUpdate",
    "UserResponse",
    "Token",
    "TokenData",
    "LoginRequest",
    # Detection schemas
    "DetectionCreate",
    "DetectionUpdate",
    "DetectionResponse",
    "DetectionListResponse",
    "DetectionVersionResponse",
    "IngestBatchResponse",
    "SplArtifactResponse",
    # Mapping schemas
    "MitreTechniqueResponse",
    "DetectionMitreMappingCreate",
    "DetectionMitreMappingUpdate",
    "DetectionMitreMappingResponse",
    "CsfCategoryResponse",
    "MitreToCsfMappingResponse",
    "DetectionCsfImpactResponse",
    # Analytics schemas
    "OverviewStats",
    "AttackCoverageResponse",
    "CsfCoverageResponse",
    "GapAnalysisResponse",
    "RecommendationResponse",
    "CrosswalkResponse",
]
