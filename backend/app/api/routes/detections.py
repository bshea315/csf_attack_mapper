"""Detection management routes."""
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_

from app.api.deps import get_db, get_current_user_required, get_editor_user
from app.models.user import User
from app.models.detection import Detection, DetectionVersion
from app.models.spl_artifact import SplParseArtifact
from app.models.mitre import DetectionMitreMapping, MitreTechnique
from app.models.csf import DetectionCsfImpact, CsfCategory
from app.services.ingest_pipeline import IngestPipeline
from app.schemas.detection import (
    DetectionResponse,
    DetectionListResponse,
    DetectionUpdate,
    DetectionVersionResponse,
    SplArtifactResponse,
    MitreMappingSummary,
    CsfImpactSummary,
)


router = APIRouter()


@router.get("", response_model=DetectionListResponse)
async def list_detections(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    severity: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    has_mitre: Optional[bool] = None,
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """List detections with filtering and pagination."""
    # Build query
    stmt = select(Detection)

    # Apply filters
    if search:
        stmt = stmt.where(
            or_(
                Detection.name.ilike(f"%{search}%"),
                Detection.description.ilike(f"%{search}%"),
                Detection.detection_id.ilike(f"%{search}%"),
            )
        )
    if severity:
        stmt = stmt.where(Detection.severity == severity)
    if status_filter:
        stmt = stmt.where(Detection.status == status_filter)

    # Count total
    count_stmt = select(func.count()).select_from(stmt.subquery())
    count_result = await db.execute(count_stmt)
    total = count_result.scalar() or 0

    # Apply pagination and ordering
    stmt = stmt.order_by(Detection.updated_at.desc())
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(stmt)
    detections = result.scalars().all()

    # Build response items
    items = []
    for detection in detections:
        # Get MITRE mappings for this detection
        mapping_stmt = select(DetectionMitreMapping, MitreTechnique).join(
            MitreTechnique, DetectionMitreMapping.technique_id == MitreTechnique.id
        ).where(
            DetectionMitreMapping.detection_id == detection.id,
            DetectionMitreMapping.is_accepted == True
        )
        mapping_result = await db.execute(mapping_stmt)
        mappings = mapping_result.all()

        mitre_mappings = [
            MitreMappingSummary(
                technique_id=m[0].technique_id,
                technique_name=m[1].name,
                confidence=m[0].confidence,
                method=m[0].method,
                is_accepted=m[0].is_accepted,
            )
            for m in mappings
        ]

        # Filter by has_mitre if specified
        if has_mitre is not None:
            if has_mitre and len(mitre_mappings) == 0:
                continue
            if not has_mitre and len(mitre_mappings) > 0:
                continue

        items.append(DetectionResponse(
            id=detection.id,
            detection_id=detection.detection_id,
            name=detection.name,
            description=detection.description,
            spl=detection.spl,
            severity=detection.severity,
            status=detection.status,
            owner_team=detection.owner_team,
            original_mitre_tags=json.loads(detection.original_mitre_tags) if detection.original_mitre_tags else None,
            data_source_notes=detection.data_source_notes,
            created_at=detection.created_at,
            updated_at=detection.updated_at,
            mitre_mappings=mitre_mappings,
            csf_impacts=[],
        ))

    total_pages = (total + page_size - 1) // page_size

    return DetectionListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{detection_id}", response_model=DetectionResponse)
async def get_detection(
    detection_id: int,
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Get detection details including mappings."""
    stmt = select(Detection).where(Detection.id == detection_id)
    result = await db.execute(stmt)
    detection = result.scalar_one_or_none()

    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found",
        )

    # Get SPL artifacts
    artifact_stmt = select(SplParseArtifact).where(SplParseArtifact.detection_id == detection.id)
    artifact_result = await db.execute(artifact_stmt)
    artifact = artifact_result.scalar_one_or_none()

    spl_artifacts = None
    if artifact:
        spl_artifacts = SplArtifactResponse(
            indexes=json.loads(artifact.indexes) if artifact.indexes else [],
            sourcetypes=json.loads(artifact.sourcetypes) if artifact.sourcetypes else [],
            datamodels=json.loads(artifact.datamodels) if artifact.datamodels else [],
            macros=json.loads(artifact.macros) if artifact.macros else [],
            fields_referenced=json.loads(artifact.fields_referenced) if artifact.fields_referenced else [],
            commands_used=json.loads(artifact.commands_used) if artifact.commands_used else [],
            time_constraints=json.loads(artifact.time_constraints) if artifact.time_constraints else None,
            aggregations=json.loads(artifact.aggregations) if artifact.aggregations else None,
            thresholds=json.loads(artifact.thresholds) if artifact.thresholds else [],
            complexity_score=artifact.complexity_score,
            complexity_signals=json.loads(artifact.complexity_signals) if artifact.complexity_signals else None,
        )

    # Get MITRE mappings
    mapping_stmt = select(DetectionMitreMapping, MitreTechnique).join(
        MitreTechnique, DetectionMitreMapping.technique_id == MitreTechnique.id
    ).where(DetectionMitreMapping.detection_id == detection.id)

    mapping_result = await db.execute(mapping_stmt)
    mappings = mapping_result.all()

    mitre_mappings = [
        MitreMappingSummary(
            technique_id=m[0].technique_id,
            technique_name=m[1].name,
            confidence=m[0].confidence,
            method=m[0].method,
            is_accepted=m[0].is_accepted,
        )
        for m in mappings
    ]

    # Get CSF impacts
    impact_stmt = select(DetectionCsfImpact, CsfCategory).join(
        CsfCategory, DetectionCsfImpact.csf_id == CsfCategory.id
    ).where(DetectionCsfImpact.detection_id == detection.id)

    impact_result = await db.execute(impact_stmt)
    impacts = impact_result.all()

    csf_impacts = [
        CsfImpactSummary(
            csf_id=i[0].csf_id,
            function=i[1].function,
            impact_score=i[0].impact_score,
        )
        for i in impacts
    ]

    return DetectionResponse(
        id=detection.id,
        detection_id=detection.detection_id,
        name=detection.name,
        description=detection.description,
        spl=detection.spl,
        severity=detection.severity,
        status=detection.status,
        owner_team=detection.owner_team,
        original_mitre_tags=json.loads(detection.original_mitre_tags) if detection.original_mitre_tags else None,
        data_source_notes=detection.data_source_notes,
        created_at=detection.created_at,
        updated_at=detection.updated_at,
        spl_artifacts=spl_artifacts,
        mitre_mappings=mitre_mappings,
        csf_impacts=csf_impacts,
    )


@router.put("/{detection_id}", response_model=DetectionResponse)
async def update_detection(
    detection_id: int,
    update_data: DetectionUpdate,
    user: User = Depends(get_editor_user),
    db: AsyncSession = Depends(get_db),
):
    """Update detection metadata."""
    stmt = select(Detection).where(Detection.id == detection_id)
    result = await db.execute(stmt)
    detection = result.scalar_one_or_none()

    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found",
        )

    if update_data.name is not None:
        detection.name = update_data.name
    if update_data.description is not None:
        detection.description = update_data.description
    if update_data.severity is not None:
        detection.severity = update_data.severity
    if update_data.status is not None:
        detection.status = update_data.status
    if update_data.owner_team is not None:
        detection.owner_team = update_data.owner_team
    if update_data.data_source_notes is not None:
        detection.data_source_notes = update_data.data_source_notes

    await db.commit()
    await db.refresh(detection)

    # Return updated detection
    return await get_detection(detection_id, user, db)


@router.get("/{detection_id}/versions", response_model=List[DetectionVersionResponse])
async def get_detection_versions(
    detection_id: int,
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Get version history for a detection."""
    stmt = select(Detection).where(Detection.id == detection_id)
    result = await db.execute(stmt)
    detection = result.scalar_one_or_none()

    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found",
        )

    version_stmt = select(DetectionVersion, User).outerjoin(
        User, DetectionVersion.created_by_id == User.id
    ).where(
        DetectionVersion.detection_id == detection_id
    ).order_by(DetectionVersion.version_number.desc())

    version_result = await db.execute(version_stmt)
    versions = version_result.all()

    return [
        DetectionVersionResponse(
            id=v[0].id,
            version_number=v[0].version_number,
            spl=v[0].spl,
            changed_fields=json.loads(v[0].changed_fields) if v[0].changed_fields else None,
            created_by=v[1].username if v[1] else None,
            created_at=v[0].created_at,
        )
        for v in versions
    ]


@router.post("/{detection_id}/recompute", response_model=DetectionResponse)
async def recompute_mappings(
    detection_id: int,
    user: User = Depends(get_editor_user),
    db: AsyncSession = Depends(get_db),
):
    """Recompute MITRE and CSF mappings for a detection."""
    stmt = select(Detection).where(Detection.id == detection_id)
    result = await db.execute(stmt)
    detection = result.scalar_one_or_none()

    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found",
        )

    pipeline = IngestPipeline(db)

    # Clear existing mappings
    await pipeline._clear_mappings(detection.id)

    # Re-parse and re-map
    await pipeline._parse_spl(detection)
    await pipeline._map_to_mitre(detection, user.id)
    await pipeline._calculate_csf_impact(detection)

    await db.commit()

    return await get_detection(detection_id, user, db)


@router.delete("/{detection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_detection(
    detection_id: int,
    user: User = Depends(get_editor_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a detection."""
    stmt = select(Detection).where(Detection.id == detection_id)
    result = await db.execute(stmt)
    detection = result.scalar_one_or_none()

    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found",
        )

    await db.delete(detection)
    await db.commit()
