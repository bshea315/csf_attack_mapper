"""Analytics and coverage routes."""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user_required
from app.models.user import User
from app.services.coverage_analyzer import CoverageAnalyzer
from app.schemas.analytics import (
    OverviewStats,
    AttackCoverageResponse,
    CsfCoverageResponse,
    GapAnalysisResponse,
    RecommendationResponse,
    CrosswalkResponse,
)


router = APIRouter()


@router.get("/overview", response_model=OverviewStats)
async def get_overview(
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Get dashboard overview statistics."""
    analyzer = CoverageAnalyzer(db)
    stats = await analyzer.get_overview_stats()
    return OverviewStats(**stats)


@router.get("/attack-coverage", response_model=AttackCoverageResponse)
async def get_attack_coverage(
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Get MITRE ATT&CK coverage data for heatmap."""
    analyzer = CoverageAnalyzer(db)
    coverage = await analyzer.get_attack_coverage()
    return AttackCoverageResponse(**coverage)


@router.get("/csf-coverage", response_model=CsfCoverageResponse)
async def get_csf_coverage(
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Get NIST CSF 2.0 coverage data."""
    analyzer = CoverageAnalyzer(db)
    coverage = await analyzer.get_csf_coverage()
    return CsfCoverageResponse(**coverage)


@router.get("/gaps", response_model=GapAnalysisResponse)
async def get_gaps(
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Get gap analysis data."""
    analyzer = CoverageAnalyzer(db)
    gaps = await analyzer.get_gaps()
    return GapAnalysisResponse(**gaps)


@router.get("/recommendations", response_model=RecommendationResponse)
async def get_recommendations(
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Get improvement recommendations."""
    analyzer = CoverageAnalyzer(db)
    recommendations = await analyzer.get_recommendations()
    return RecommendationResponse(**recommendations)


@router.get("/crosswalk", response_model=CrosswalkResponse)
async def get_crosswalk(
    technique_id: Optional[str] = Query(None),
    csf_id: Optional[str] = Query(None),
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Get crosswalk data between MITRE and CSF."""
    analyzer = CoverageAnalyzer(db)
    crosswalk = await analyzer.get_crosswalk(technique_id=technique_id, csf_id=csf_id)
    return CrosswalkResponse(**crosswalk)
