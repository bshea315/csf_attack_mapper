"""Tests for API endpoints."""
import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient
import asyncio
from unittest.mock import patch, MagicMock

# We'll use a test configuration
import sys
import os

# Add the backend app to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def mock_settings():
    """Mock settings for testing."""
    with patch('app.config.settings') as mock:
        mock.DATABASE_URL = "sqlite+aiosqlite:///:memory:"
        mock.SECRET_KEY = "test-secret-key"
        mock.ALGORITHM = "HS256"
        mock.ACCESS_TOKEN_EXPIRE_MINUTES = 30
        mock.DEFAULT_ADMIN_USERNAME = "admin"
        mock.DEFAULT_ADMIN_PASSWORD = "changeme123"
        yield mock


class TestAuthEndpoints:
    """Tests for authentication endpoints."""

    def test_login_request_structure(self):
        """Test login request structure."""
        # Verify the expected structure
        from app.schemas.user import LoginRequest

        request = LoginRequest(username="test", password="password")
        assert request.username == "test"
        assert request.password == "password"

    def test_user_response_structure(self):
        """Test user response structure."""
        from app.schemas.user import UserResponse

        response = UserResponse(
            id=1,
            username="admin",
            email="admin@test.com",
            role="admin",
            is_active=True,
        )
        assert response.id == 1
        assert response.role == "admin"


class TestDetectionSchemas:
    """Tests for detection schemas."""

    def test_detection_response_structure(self):
        """Test detection response structure."""
        from app.schemas.detection import DetectionResponse

        # Test that the schema can be instantiated with required fields
        response = DetectionResponse(
            id=1,
            detection_id="DET-001",
            name="Test Detection",
            spl="index=main | stats count",
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
        )
        assert response.id == 1
        assert response.detection_id == "DET-001"

    def test_spl_artifact_response(self):
        """Test SPL artifact response structure."""
        from app.schemas.detection import SplArtifactResponse

        response = SplArtifactResponse(
            indexes=["main", "security"],
            sourcetypes=["syslog"],
            datamodels=[],
            macros=[],
            fields_referenced=["user", "src_ip"],
            commands_used=["stats", "where"],
            time_constraints={},
            aggregations={},
            thresholds=[],
            complexity_score=25,
        )
        assert "main" in response.indexes
        assert response.complexity_score == 25


class TestMappingSchemas:
    """Tests for mapping schemas."""

    def test_mitre_technique_response(self):
        """Test MITRE technique response structure."""
        from app.schemas.mapping import MitreTechniqueResponse

        response = MitreTechniqueResponse(
            id="T1110",
            name="Brute Force",
            tactic=["Credential Access"],
            is_subtechnique=False,
        )
        assert response.id == "T1110"
        assert "Credential Access" in response.tactic

    def test_csf_category_response(self):
        """Test CSF category response structure."""
        from app.schemas.mapping import CsfCategoryResponse

        response = CsfCategoryResponse(
            id="DE.CM-1",
            function="DETECT",
            category="DE.CM",
            name="Networks are monitored",
        )
        assert response.function == "DETECT"
        assert response.id == "DE.CM-1"

    def test_detection_mitre_mapping(self):
        """Test detection MITRE mapping structure."""
        from app.schemas.mapping import DetectionMitreMappingResponse

        response = DetectionMitreMappingResponse(
            id=1,
            technique_id="T1110",
            technique_name="Brute Force",
            confidence=0.85,
            method="rule",
            rationale="Matched brute force rule",
            is_accepted=True,
        )
        assert response.confidence == 0.85
        assert response.method == "rule"


class TestAnalyticsSchemas:
    """Tests for analytics schemas."""

    def test_overview_stats(self):
        """Test overview stats structure."""
        from app.schemas.analytics import OverviewStats

        stats = OverviewStats(
            total_detections=100,
            enabled_detections=85,
            enabled_percentage=85.0,
            total_techniques=200,
            techniques_covered=50,
            technique_coverage_percentage=25.0,
            total_csf_categories=23,
            csf_categories_covered=15,
            recent_ingest_count=5,
        )
        assert stats.total_detections == 100
        assert stats.technique_coverage_percentage == 25.0

    def test_gap_analysis_response(self):
        """Test gap analysis response structure."""
        from app.schemas.analytics import GapAnalysisResponse

        response = GapAnalysisResponse(
            total_gaps=10,
            critical_gaps=3,
            uncovered_technique_count=50,
            low_csf_coverage_count=5,
        )
        assert response.total_gaps == 10
        assert response.critical_gaps == 3


class TestIngestSchemas:
    """Tests for ingest schemas."""

    def test_ingest_batch_response(self):
        """Test ingest batch response structure."""
        from app.schemas.detection import IngestBatchResponse

        response = IngestBatchResponse(
            id=1,
            source_type="csv",
            source_filename="detections.csv",
            total_records=20,
            successful=18,
            failed=2,
            status="completed",
            created_at="2024-01-01T00:00:00",
        )
        assert response.total_records == 20
        assert response.status == "completed"


class TestDatabaseModels:
    """Tests for database models."""

    def test_detection_model(self):
        """Test Detection model structure."""
        from app.models.detection import Detection

        # Check model has expected attributes
        assert hasattr(Detection, 'id')
        assert hasattr(Detection, 'detection_id')
        assert hasattr(Detection, 'name')
        assert hasattr(Detection, 'spl')
        assert hasattr(Detection, 'severity')
        assert hasattr(Detection, 'status')

    def test_user_model(self):
        """Test User model structure."""
        from app.models.user import User

        assert hasattr(User, 'id')
        assert hasattr(User, 'username')
        assert hasattr(User, 'email')
        assert hasattr(User, 'password_hash')
        assert hasattr(User, 'role')

    def test_mitre_technique_model(self):
        """Test MitreTechnique model structure."""
        from app.models.mitre import MitreTechnique

        assert hasattr(MitreTechnique, 'id')
        assert hasattr(MitreTechnique, 'name')
        assert hasattr(MitreTechnique, 'tactic')
        assert hasattr(MitreTechnique, 'is_subtechnique')

    def test_csf_category_model(self):
        """Test CsfCategory model structure."""
        from app.models.csf import CsfCategory

        assert hasattr(CsfCategory, 'id')
        assert hasattr(CsfCategory, 'function')
        assert hasattr(CsfCategory, 'category')
        assert hasattr(CsfCategory, 'name')


class TestRouteStructure:
    """Tests for route module structure."""

    def test_auth_routes_exist(self):
        """Test auth routes module exists."""
        from app.api.routes import auth
        assert hasattr(auth, 'router')

    def test_detection_routes_exist(self):
        """Test detection routes module exists."""
        from app.api.routes import detections
        assert hasattr(detections, 'router')

    def test_analytics_routes_exist(self):
        """Test analytics routes module exists."""
        from app.api.routes import analytics
        assert hasattr(analytics, 'router')

    def test_ingest_routes_exist(self):
        """Test ingest routes module exists."""
        from app.api.routes import ingest
        assert hasattr(ingest, 'router')

    def test_exports_routes_exist(self):
        """Test exports routes module exists."""
        from app.api.routes import exports
        assert hasattr(exports, 'router')


class TestServiceIntegration:
    """Integration tests for services."""

    def test_spl_parser_service(self):
        """Test SPL parser service integration."""
        from app.services.spl_parser import SPLParser

        parser = SPLParser()
        result = parser.parse("index=main | stats count by user")

        assert result.indexes == ['main']
        assert 'stats' in result.commands_used
        assert 'user' in result.fields_referenced

    def test_csf_calculator_service(self):
        """Test CSF calculator service initialization."""
        from app.services.csf_calculator import CSFCalculator

        calc = CSFCalculator()
        assert hasattr(calc, 'crosswalk')


class TestPasswordHashing:
    """Tests for password security."""

    def test_password_hash_verify(self):
        """Test password hashing and verification."""
        from app.core.security import hash_password, verify_password

        password = "test_password_123"
        hashed = hash_password(password)

        # Hash should be different from original
        assert hashed != password

        # Should verify correctly
        assert verify_password(password, hashed) is True

        # Wrong password should fail
        assert verify_password("wrong_password", hashed) is False

    def test_jwt_creation(self):
        """Test JWT token creation."""
        from app.core.security import create_access_token
        from datetime import timedelta

        data = {"sub": "testuser", "role": "admin"}
        token = create_access_token(data, expires_delta=timedelta(hours=1))

        assert isinstance(token, str)
        assert len(token) > 0


class TestConfigSettings:
    """Tests for configuration settings."""

    def test_settings_exist(self):
        """Test settings module exists."""
        from app.config import Settings

        settings = Settings()
        assert hasattr(settings, 'SECRET_KEY')
        assert hasattr(settings, 'DATABASE_URL')
        assert hasattr(settings, 'ALGORITHM')


class TestPaginatedResponse:
    """Tests for paginated responses."""

    def test_paginated_detection_response(self):
        """Test paginated detection response."""
        from app.schemas.detection import DetectionListResponse, DetectionSummary
        from datetime import datetime

        # Create sample detection summaries
        items = [
            DetectionSummary(
                id=1,
                detection_id="DET-001",
                name="Test Detection",
                severity="high",
                status="enabled",
                mitre_mappings=[],
                updated_at=datetime.now(),
            )
        ]

        response = DetectionListResponse(
            items=items,
            total=1,
            page=1,
            page_size=20,
            total_pages=1,
        )

        assert response.total == 1
        assert response.page == 1
        assert len(response.items) == 1
