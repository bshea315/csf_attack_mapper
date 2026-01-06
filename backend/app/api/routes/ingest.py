"""Ingest routes for uploading detections."""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from app.api.deps import get_db, get_current_user_required, get_editor_user, get_admin_user
from app.models.user import User
from app.models.detection import IngestBatch
from app.services.ingest_pipeline import IngestPipeline
from app.schemas.detection import IngestBatchResponse, IngestPasteRequest


class ReprocessRequest(BaseModel):
    """Request body for reprocessing mappings."""
    use_enhanced_mapper: bool = True
    confirmation: str  # Must be "REPROCESS" to confirm


class ReprocessResponse(BaseModel):
    """Response for reprocessing operation."""
    total_detections: int
    successful: int
    failed: int
    errors: List[str]
    mapper_type: str


router = APIRouter()


@router.post("/csv", response_model=IngestBatchResponse)
async def ingest_csv(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    user: User = Depends(get_editor_user),
    db: AsyncSession = Depends(get_db),
):
    """Upload CSV file containing detections."""
    if not file.filename.endswith('.csv'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a CSV file",
        )

    content = await file.read()
    try:
        content_str = content.decode('utf-8')
    except UnicodeDecodeError:
        content_str = content.decode('latin-1')

    pipeline = IngestPipeline(db)
    result = await pipeline.ingest_csv(
        content=content_str,
        filename=file.filename,
        user_id=user.id,
    )

    # Get batch for response
    stmt = select(IngestBatch).where(IngestBatch.id == result.batch_id)
    batch_result = await db.execute(stmt)
    batch = batch_result.scalar_one()

    return IngestBatchResponse(
        id=batch.id,
        source_type=batch.source_type,
        source_filename=batch.source_filename,
        total_records=batch.total_records,
        successful=batch.successful,
        failed=batch.failed,
        warnings=result.warnings,
        status=batch.status,
        error_message=batch.error_message,
        created_at=batch.created_at,
        completed_at=batch.completed_at,
    )


@router.post("/yaml", response_model=IngestBatchResponse)
async def ingest_yaml(
    file: UploadFile = File(...),
    user: User = Depends(get_editor_user),
    db: AsyncSession = Depends(get_db),
):
    """Upload YAML file containing detections."""
    if not file.filename.endswith(('.yml', '.yaml')):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a YAML file",
        )

    content = await file.read()
    try:
        content_str = content.decode('utf-8')
    except UnicodeDecodeError:
        content_str = content.decode('latin-1')

    pipeline = IngestPipeline(db)
    result = await pipeline.ingest_yaml(
        content=content_str,
        filename=file.filename,
        user_id=user.id,
    )

    stmt = select(IngestBatch).where(IngestBatch.id == result.batch_id)
    batch_result = await db.execute(stmt)
    batch = batch_result.scalar_one()

    return IngestBatchResponse(
        id=batch.id,
        source_type=batch.source_type,
        source_filename=batch.source_filename,
        total_records=batch.total_records,
        successful=batch.successful,
        failed=batch.failed,
        warnings=result.warnings,
        status=batch.status,
        error_message=batch.error_message,
        created_at=batch.created_at,
        completed_at=batch.completed_at,
    )


@router.post("/paste", response_model=IngestBatchResponse)
async def ingest_paste(
    request: IngestPasteRequest,
    user: User = Depends(get_editor_user),
    db: AsyncSession = Depends(get_db),
):
    """Ingest detections from pasted text content."""
    pipeline = IngestPipeline(db)
    result = await pipeline.ingest_paste(
        content=request.content,
        user_id=user.id,
    )

    stmt = select(IngestBatch).where(IngestBatch.id == result.batch_id)
    batch_result = await db.execute(stmt)
    batch = batch_result.scalar_one()

    return IngestBatchResponse(
        id=batch.id,
        source_type=batch.source_type,
        source_filename=batch.source_filename,
        total_records=batch.total_records,
        successful=batch.successful,
        failed=batch.failed,
        warnings=result.warnings,
        status=batch.status,
        error_message=batch.error_message,
        created_at=batch.created_at,
        completed_at=batch.completed_at,
    )


@router.get("/batches", response_model=List[IngestBatchResponse])
async def list_batches(
    limit: int = 20,
    offset: int = 0,
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """List recent ingest batches."""
    stmt = select(IngestBatch).order_by(IngestBatch.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(stmt)
    batches = result.scalars().all()

    return [
        IngestBatchResponse(
            id=b.id,
            source_type=b.source_type,
            source_filename=b.source_filename,
            total_records=b.total_records,
            successful=b.successful,
            failed=b.failed,
            warnings=[],
            status=b.status,
            error_message=b.error_message,
            created_at=b.created_at,
            completed_at=b.completed_at,
        )
        for b in batches
    ]


@router.get("/batches/{batch_id}", response_model=IngestBatchResponse)
async def get_batch(
    batch_id: int,
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Get ingest batch details."""
    stmt = select(IngestBatch).where(IngestBatch.id == batch_id)
    result = await db.execute(stmt)
    batch = result.scalar_one_or_none()

    if batch is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Batch not found",
        )

    import json
    warnings = json.loads(batch.warnings) if batch.warnings else []

    return IngestBatchResponse(
        id=batch.id,
        source_type=batch.source_type,
        source_filename=batch.source_filename,
        total_records=batch.total_records,
        successful=batch.successful,
        failed=batch.failed,
        warnings=warnings,
        status=batch.status,
        error_message=batch.error_message,
        created_at=batch.created_at,
        completed_at=batch.completed_at,
    )


@router.post("/reprocess", response_model=ReprocessResponse)
async def reprocess_all_mappings(
    request: ReprocessRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Re-process MITRE mappings for all detections.

    This is a destructive operation that clears all existing MITRE mappings
    and CSF impacts, then re-runs the mapper on all detections.

    Requires:
    - Admin role
    - Confirmation string must be exactly "REPROCESS"

    Use cases:
    - Switching from legacy to enhanced mapper
    - After updating technique indicators
    - Fixing mapping issues across all detections
    """
    # Verify confirmation
    if request.confirmation != "REPROCESS":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirmation must be exactly 'REPROCESS' to proceed",
        )

    pipeline = IngestPipeline(db, use_enhanced_mapper=request.use_enhanced_mapper)
    result = await pipeline.reprocess_all_mappings(user_id=user.id)

    return ReprocessResponse(
        total_detections=result['total_detections'],
        successful=result['successful'],
        failed=result['failed'],
        errors=result['errors'],
        mapper_type=result['mapper_type'],
    )
