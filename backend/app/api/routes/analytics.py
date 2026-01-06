"""Analytics and coverage routes."""
import json
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.deps import get_db, get_current_user_required
from app.models.user import User
from app.models.mitre import MitreTechnique, DetectionMitreMapping
from app.models.detection import Detection
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


@router.get("/technique/{technique_id}")
async def get_technique_details(
    technique_id: str,
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Get details for a specific technique including mapped detections."""
    # Get the technique
    stmt = select(MitreTechnique).where(MitreTechnique.id == technique_id)
    result = await db.execute(stmt)
    technique = result.scalar_one_or_none()

    if not technique:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Technique not found"
        )

    tactics = json.loads(technique.tactics) if technique.tactics else []

    # Get all detections mapped to this technique
    mapping_stmt = select(DetectionMitreMapping, Detection).join(
        Detection, DetectionMitreMapping.detection_id == Detection.id
    ).where(
        DetectionMitreMapping.technique_id == technique_id,
        DetectionMitreMapping.is_accepted == True
    )

    mapping_result = await db.execute(mapping_stmt)
    mappings = mapping_result.all()

    detections = [
        {
            "id": m[1].id,
            "detection_id": m[1].detection_id,
            "name": m[1].name,
            "severity": m[1].severity,
            "status": m[1].status,
            "confidence": m[0].confidence,
            "method": m[0].method,
            "rationale": m[0].rationale,
        }
        for m in mappings
    ]

    # Get sub-techniques if this is a parent technique
    subtechniques = []
    if not technique.is_subtechnique:
        sub_stmt = select(MitreTechnique).where(
            MitreTechnique.parent_technique_id == technique_id
        )
        sub_result = await db.execute(sub_stmt)
        subs = sub_result.scalars().all()

        for sub in subs:
            # Get detection count for sub-technique
            sub_count_stmt = select(DetectionMitreMapping).where(
                DetectionMitreMapping.technique_id == sub.id,
                DetectionMitreMapping.is_accepted == True
            )
            sub_count_result = await db.execute(sub_count_stmt)
            sub_count = len(sub_count_result.all())

            subtechniques.append({
                "technique_id": sub.id,
                "technique_name": sub.name,
                "detection_count": sub_count,
                "url": sub.url or f"https://attack.mitre.org/techniques/{sub.id.replace('.', '/')}",
            })

    return {
        "technique_id": technique.id,
        "technique_name": technique.name,
        "description": technique.description,
        "tactics": tactics,
        "is_subtechnique": technique.is_subtechnique,
        "parent_technique_id": technique.parent_technique_id,
        "url": technique.url or f"https://attack.mitre.org/techniques/{technique.id.replace('.', '/')}",
        "detection_count": len(detections),
        "detections": detections,
        "subtechniques": subtechniques,
    }
