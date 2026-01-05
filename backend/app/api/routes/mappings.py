"""Mapping management routes for MITRE and CSF."""
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.api.deps import get_db, get_current_user_required, get_editor_user
from app.models.user import User
from app.models.detection import Detection
from app.models.mitre import MitreTechnique, DetectionMitreMapping
from app.models.csf import CsfCategory, MitreToCsfMapping, DetectionCsfImpact
from app.schemas.mapping import (
    MitreTechniqueResponse,
    DetectionMitreMappingCreate,
    DetectionMitreMappingUpdate,
    DetectionMitreMappingResponse,
    CsfCategoryResponse,
    MitreToCsfMappingResponse,
    MitreToCsfMappingUpdate,
)


router = APIRouter()


# MITRE Techniques endpoints
@router.get("/mitre/techniques", response_model=List[MitreTechniqueResponse])
async def list_mitre_techniques(
    tactic: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """List MITRE ATT&CK techniques."""
    stmt = select(
        MitreTechnique,
        func.count(DetectionMitreMapping.id).label('detection_count')
    ).outerjoin(
        DetectionMitreMapping,
        (MitreTechnique.id == DetectionMitreMapping.technique_id) &
        (DetectionMitreMapping.is_accepted == True)
    ).group_by(MitreTechnique.id)

    if search:
        stmt = stmt.where(
            (MitreTechnique.id.ilike(f"%{search}%")) |
            (MitreTechnique.name.ilike(f"%{search}%"))
        )

    stmt = stmt.order_by(MitreTechnique.id).limit(limit)

    result = await db.execute(stmt)
    rows = result.all()

    techniques = []
    for row in rows:
        tech = row[0]
        detection_count = row[1] or 0

        tactics = json.loads(tech.tactics) if tech.tactics else []

        # Filter by tactic if specified
        if tactic and tactic.lower() not in [t.lower() for t in tactics]:
            continue

        techniques.append(MitreTechniqueResponse(
            id=tech.id,
            name=tech.name,
            description=tech.description,
            tactics=tactics,
            platforms=json.loads(tech.platforms) if tech.platforms else [],
            data_sources=json.loads(tech.data_sources) if tech.data_sources else [],
            is_subtechnique=tech.is_subtechnique,
            parent_technique_id=tech.parent_technique_id,
            url=tech.url,
            detection_count=detection_count,
        ))

    return techniques


@router.get("/mitre/techniques/{technique_id}", response_model=MitreTechniqueResponse)
async def get_mitre_technique(
    technique_id: str,
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific MITRE technique."""
    stmt = select(MitreTechnique).where(MitreTechnique.id == technique_id)
    result = await db.execute(stmt)
    tech = result.scalar_one_or_none()

    if tech is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Technique not found",
        )

    # Count detections
    count_stmt = select(func.count(DetectionMitreMapping.id)).where(
        DetectionMitreMapping.technique_id == technique_id,
        DetectionMitreMapping.is_accepted == True
    )
    count_result = await db.execute(count_stmt)
    detection_count = count_result.scalar() or 0

    return MitreTechniqueResponse(
        id=tech.id,
        name=tech.name,
        description=tech.description,
        tactics=json.loads(tech.tactics) if tech.tactics else [],
        platforms=json.loads(tech.platforms) if tech.platforms else [],
        data_sources=json.loads(tech.data_sources) if tech.data_sources else [],
        is_subtechnique=tech.is_subtechnique,
        parent_technique_id=tech.parent_technique_id,
        url=tech.url,
        detection_count=detection_count,
    )


# Detection MITRE Mappings endpoints
@router.get("/detections/{detection_id}/mitre", response_model=List[DetectionMitreMappingResponse])
async def get_detection_mitre_mappings(
    detection_id: int,
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Get MITRE mappings for a detection."""
    stmt = select(DetectionMitreMapping, MitreTechnique).join(
        MitreTechnique, DetectionMitreMapping.technique_id == MitreTechnique.id
    ).where(DetectionMitreMapping.detection_id == detection_id)

    result = await db.execute(stmt)
    rows = result.all()

    return [
        DetectionMitreMappingResponse(
            id=row[0].id,
            detection_id=row[0].detection_id,
            technique_id=row[0].technique_id,
            technique_name=row[1].name,
            technique_tactics=json.loads(row[1].tactics) if row[1].tactics else [],
            confidence=row[0].confidence,
            method=row[0].method,
            rule_id=row[0].rule_id,
            rationale=row[0].rationale,
            evidence=json.loads(row[0].evidence) if row[0].evidence else None,
            is_accepted=row[0].is_accepted,
            created_at=row[0].created_at,
            updated_at=row[0].updated_at,
        )
        for row in rows
    ]


@router.post("/detections/{detection_id}/mitre", response_model=DetectionMitreMappingResponse, status_code=status.HTTP_201_CREATED)
async def add_detection_mitre_mapping(
    detection_id: int,
    mapping_data: DetectionMitreMappingCreate,
    user: User = Depends(get_editor_user),
    db: AsyncSession = Depends(get_db),
):
    """Add a manual MITRE mapping to a detection."""
    # Verify detection exists
    stmt = select(Detection).where(Detection.id == detection_id)
    result = await db.execute(stmt)
    detection = result.scalar_one_or_none()

    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found",
        )

    # Verify technique exists
    tech_stmt = select(MitreTechnique).where(MitreTechnique.id == mapping_data.technique_id)
    tech_result = await db.execute(tech_stmt)
    technique = tech_result.scalar_one_or_none()

    if technique is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Technique not found",
        )

    # Check for existing mapping
    existing_stmt = select(DetectionMitreMapping).where(
        DetectionMitreMapping.detection_id == detection_id,
        DetectionMitreMapping.technique_id == mapping_data.technique_id,
    )
    existing_result = await db.execute(existing_stmt)
    existing = existing_result.scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mapping already exists for this technique",
        )

    mapping = DetectionMitreMapping(
        detection_id=detection_id,
        technique_id=mapping_data.technique_id,
        confidence=mapping_data.confidence,
        method="manual",
        rationale=mapping_data.rationale,
        is_accepted=True,
        created_by_id=user.id,
    )
    db.add(mapping)
    await db.commit()
    await db.refresh(mapping)

    return DetectionMitreMappingResponse(
        id=mapping.id,
        detection_id=mapping.detection_id,
        technique_id=mapping.technique_id,
        technique_name=technique.name,
        technique_tactics=json.loads(technique.tactics) if technique.tactics else [],
        confidence=mapping.confidence,
        method=mapping.method,
        rule_id=mapping.rule_id,
        rationale=mapping.rationale,
        evidence=None,
        is_accepted=mapping.is_accepted,
        created_at=mapping.created_at,
        updated_at=mapping.updated_at,
    )


@router.put("/detections/{detection_id}/mitre/{mapping_id}", response_model=DetectionMitreMappingResponse)
async def update_detection_mitre_mapping(
    detection_id: int,
    mapping_id: int,
    update_data: DetectionMitreMappingUpdate,
    user: User = Depends(get_editor_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a MITRE mapping."""
    stmt = select(DetectionMitreMapping, MitreTechnique).join(
        MitreTechnique, DetectionMitreMapping.technique_id == MitreTechnique.id
    ).where(
        DetectionMitreMapping.id == mapping_id,
        DetectionMitreMapping.detection_id == detection_id,
    )
    result = await db.execute(stmt)
    row = result.one_or_none()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mapping not found",
        )

    mapping, technique = row

    if update_data.confidence is not None:
        mapping.confidence = update_data.confidence
    if update_data.rationale is not None:
        mapping.rationale = update_data.rationale
    if update_data.is_accepted is not None:
        mapping.is_accepted = update_data.is_accepted

    await db.commit()
    await db.refresh(mapping)

    return DetectionMitreMappingResponse(
        id=mapping.id,
        detection_id=mapping.detection_id,
        technique_id=mapping.technique_id,
        technique_name=technique.name,
        technique_tactics=json.loads(technique.tactics) if technique.tactics else [],
        confidence=mapping.confidence,
        method=mapping.method,
        rule_id=mapping.rule_id,
        rationale=mapping.rationale,
        evidence=json.loads(mapping.evidence) if mapping.evidence else None,
        is_accepted=mapping.is_accepted,
        created_at=mapping.created_at,
        updated_at=mapping.updated_at,
    )


@router.delete("/detections/{detection_id}/mitre/{mapping_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_detection_mitre_mapping(
    detection_id: int,
    mapping_id: int,
    user: User = Depends(get_editor_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a MITRE mapping."""
    stmt = select(DetectionMitreMapping).where(
        DetectionMitreMapping.id == mapping_id,
        DetectionMitreMapping.detection_id == detection_id,
    )
    result = await db.execute(stmt)
    mapping = result.scalar_one_or_none()

    if mapping is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mapping not found",
        )

    await db.delete(mapping)
    await db.commit()


# CSF Categories endpoints
@router.get("/csf/categories", response_model=List[CsfCategoryResponse])
async def list_csf_categories(
    function: Optional[str] = None,
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """List CSF 2.0 categories."""
    stmt = select(
        CsfCategory,
        func.count(func.distinct(DetectionCsfImpact.detection_id)).label('detection_count'),
        func.avg(DetectionCsfImpact.impact_score).label('avg_score')
    ).outerjoin(
        DetectionCsfImpact
    ).group_by(CsfCategory.id)

    if function:
        stmt = stmt.where(CsfCategory.function == function.upper())

    stmt = stmt.order_by(CsfCategory.function, CsfCategory.category, CsfCategory.id)

    result = await db.execute(stmt)
    rows = result.all()

    return [
        CsfCategoryResponse(
            id=row[0].id,
            function=row[0].function,
            category=row[0].category,
            subcategory=row[0].subcategory,
            name=row[0].name,
            description=row[0].description,
            detection_count=row[1] or 0,
            coverage_score=row[2] or 0.0,
        )
        for row in rows
    ]


# MITRE to CSF Crosswalk endpoints
@router.get("/mitre-to-csf", response_model=List[MitreToCsfMappingResponse])
async def list_mitre_to_csf_mappings(
    technique_id: Optional[str] = None,
    csf_id: Optional[str] = None,
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """List MITRE to CSF crosswalk mappings."""
    stmt = select(MitreToCsfMapping, MitreTechnique, CsfCategory).join(
        MitreTechnique, MitreToCsfMapping.technique_id == MitreTechnique.id
    ).join(
        CsfCategory, MitreToCsfMapping.csf_id == CsfCategory.id
    )

    if technique_id:
        stmt = stmt.where(MitreToCsfMapping.technique_id == technique_id)
    if csf_id:
        stmt = stmt.where(MitreToCsfMapping.csf_id == csf_id)

    result = await db.execute(stmt)
    rows = result.all()

    return [
        MitreToCsfMappingResponse(
            id=row[0].id,
            technique_id=row[0].technique_id,
            technique_name=row[1].name,
            csf_id=row[0].csf_id,
            csf_function=row[2].function,
            csf_name=row[2].name,
            weight=row[0].weight,
            rationale=row[0].rationale,
            source=row[0].source,
            created_at=row[0].created_at,
        )
        for row in rows
    ]


@router.put("/mitre-to-csf/{mapping_id}", response_model=MitreToCsfMappingResponse)
async def update_mitre_to_csf_mapping(
    mapping_id: int,
    update_data: MitreToCsfMappingUpdate,
    user: User = Depends(get_editor_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a MITRE to CSF crosswalk mapping."""
    stmt = select(MitreToCsfMapping, MitreTechnique, CsfCategory).join(
        MitreTechnique, MitreToCsfMapping.technique_id == MitreTechnique.id
    ).join(
        CsfCategory, MitreToCsfMapping.csf_id == CsfCategory.id
    ).where(MitreToCsfMapping.id == mapping_id)

    result = await db.execute(stmt)
    row = result.one_or_none()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mapping not found",
        )

    mapping, technique, csf = row

    if update_data.weight is not None:
        mapping.weight = update_data.weight
    if update_data.rationale is not None:
        mapping.rationale = update_data.rationale

    mapping.source = "manual"  # Mark as manually edited

    await db.commit()
    await db.refresh(mapping)

    return MitreToCsfMappingResponse(
        id=mapping.id,
        technique_id=mapping.technique_id,
        technique_name=technique.name,
        csf_id=mapping.csf_id,
        csf_function=csf.function,
        csf_name=csf.name,
        weight=mapping.weight,
        rationale=mapping.rationale,
        source=mapping.source,
        created_at=mapping.created_at,
    )
