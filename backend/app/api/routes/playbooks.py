"""
Playbook and SOAR dashboard API routes.

Provides endpoints for:
- Listing playbooks and runs
- Managing detection-playbook links
- SOAR metrics and dashboard data
"""
import json
from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc, case
from sqlalchemy.orm import selectinload

from app.models.database import get_db
from app.models.user import User
from app.models.playbook import Playbook
from app.models.soar import PlaybookRun, ActionRun, DetectionPlaybookLink
from app.models.detection import Detection
from app.api.deps import get_current_user, get_admin_user
from app.schemas.playbook import (
    PlaybookResponse,
    PlaybookListResponse,
    PlaybookUpdate,
    PlaybookRunResponse,
    PlaybookRunListResponse,
    DetectionPlaybookLinkCreate,
    DetectionPlaybookLinkResponse,
    PlaybookMetrics,
    PlaybookTimeSaved,
    ActionMetrics,
    AppMetrics,
    SOAROverviewMetrics,
    SOARDashboardResponse,
    PlaybookStatsResponse,
)

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


# ============================================================================
# Playbook List/Detail Endpoints
# ============================================================================

@router.get("", response_model=PlaybookListResponse)
async def list_playbooks(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    is_active: Optional[bool] = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List playbooks with pagination and filtering.
    """
    # Base query
    stmt = select(Playbook)

    # Apply filters
    if search:
        stmt = stmt.where(Playbook.name.ilike(f"%{search}%"))
    if is_active is not None:
        stmt = stmt.where(Playbook.is_active == is_active)

    # Get total count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Apply pagination
    stmt = stmt.order_by(desc(Playbook.updated_at))
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(stmt)
    playbooks = result.scalars().all()

    # Enrich with stats
    items = []
    for pb in playbooks:
        stats = await _get_playbook_stats(db, pb.id)
        # Calculate total time saved
        successful_runs = stats.get("successful_runs", 0)
        time_saved_per_run = getattr(pb, 'time_saved_minutes', 0) or 0
        total_time_saved_hours = (successful_runs * time_saved_per_run) / 60.0

        items.append(PlaybookResponse(
            id=pb.id,
            playbook_id=pb.playbook_id,
            name=pb.name,
            description=pb.description,
            is_active=pb.is_active,
            category=getattr(pb, 'category', None),
            time_saved_minutes=time_saved_per_run,
            avg_manual_time_minutes=getattr(pb, 'avg_manual_time_minutes', None),
            created_at=pb.created_at,
            updated_at=pb.updated_at,
            run_count=stats["run_count"],
            success_rate=stats["success_rate"],
            linked_detection_count=stats["linked_detection_count"],
            total_time_saved_hours=total_time_saved_hours,
        ))

    return PlaybookListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/{playbook_id}", response_model=PlaybookStatsResponse)
async def get_playbook_detail(
    playbook_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get playbook details with metrics and recent runs.
    """
    stmt = select(Playbook).where(Playbook.id == playbook_id)
    result = await db.execute(stmt)
    playbook = result.scalar_one_or_none()

    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    # Get full metrics
    metrics = await _compute_playbook_metrics(db, playbook)

    # Get action breakdown
    action_breakdown = await _get_action_metrics_for_playbook(db, playbook_id)

    # Get recent runs
    runs_stmt = (
        select(PlaybookRun)
        .where(PlaybookRun.playbook_id == playbook_id)
        .order_by(desc(PlaybookRun.event_time))
        .limit(10)
    )
    runs_result = await db.execute(runs_stmt)
    recent_runs = [_run_to_response(r, playbook.name) for r in runs_result.scalars().all()]

    # Get linked detections
    links_stmt = (
        select(DetectionPlaybookLink, Detection)
        .join(Detection)
        .where(DetectionPlaybookLink.playbook_id == playbook_id)
    )
    links_result = await db.execute(links_stmt)
    linked_detections = [
        {"id": det.id, "name": det.name, "severity": det.severity, "link_type": link.link_type}
        for link, det in links_result.all()
    ]

    stats = await _get_playbook_stats(db, playbook.id)
    successful_runs = stats.get("successful_runs", 0)
    time_saved_per_run = getattr(playbook, 'time_saved_minutes', 0) or 0
    total_time_saved_hours = (successful_runs * time_saved_per_run) / 60.0

    playbook_response = PlaybookResponse(
        id=playbook.id,
        playbook_id=playbook.playbook_id,
        name=playbook.name,
        description=playbook.description,
        is_active=playbook.is_active,
        category=getattr(playbook, 'category', None),
        time_saved_minutes=time_saved_per_run,
        avg_manual_time_minutes=getattr(playbook, 'avg_manual_time_minutes', None),
        created_at=playbook.created_at,
        updated_at=playbook.updated_at,
        run_count=stats["run_count"],
        success_rate=stats["success_rate"],
        linked_detection_count=stats["linked_detection_count"],
        total_time_saved_hours=total_time_saved_hours,
    )

    return PlaybookStatsResponse(
        playbook=playbook_response,
        metrics=metrics,
        action_breakdown=action_breakdown,
        recent_runs=recent_runs,
        linked_detections=linked_detections,
    )


@router.put("/{playbook_id}", response_model=PlaybookResponse)
async def update_playbook(
    playbook_id: int,
    update_data: PlaybookUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Update playbook settings including time saved metrics.
    """
    stmt = select(Playbook).where(Playbook.id == playbook_id)
    result = await db.execute(stmt)
    playbook = result.scalar_one_or_none()

    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    # Update fields if provided
    update_dict = update_data.model_dump(exclude_unset=True)
    for field, value in update_dict.items():
        if hasattr(playbook, field):
            setattr(playbook, field, value)

    await db.commit()
    await db.refresh(playbook)

    stats = await _get_playbook_stats(db, playbook.id)
    successful_runs = stats.get("successful_runs", 0)
    time_saved_per_run = getattr(playbook, 'time_saved_minutes', 0) or 0
    total_time_saved_hours = (successful_runs * time_saved_per_run) / 60.0

    return PlaybookResponse(
        id=playbook.id,
        playbook_id=playbook.playbook_id,
        name=playbook.name,
        description=playbook.description,
        is_active=playbook.is_active,
        category=getattr(playbook, 'category', None),
        time_saved_minutes=time_saved_per_run,
        avg_manual_time_minutes=getattr(playbook, 'avg_manual_time_minutes', None),
        created_at=playbook.created_at,
        updated_at=playbook.updated_at,
        run_count=stats["run_count"],
        success_rate=stats["success_rate"],
        linked_detection_count=stats["linked_detection_count"],
        total_time_saved_hours=total_time_saved_hours,
    )


# ============================================================================
# Playbook Runs Endpoints
# ============================================================================

@router.get("/{playbook_id}/runs", response_model=PlaybookRunListResponse)
async def list_playbook_runs(
    playbook_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List runs for a specific playbook.
    """
    # Verify playbook exists
    pb_stmt = select(Playbook).where(Playbook.id == playbook_id)
    pb_result = await db.execute(pb_stmt)
    playbook = pb_result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    # Build query
    stmt = select(PlaybookRun).where(PlaybookRun.playbook_id == playbook_id)

    if status:
        stmt = stmt.where(PlaybookRun.status == status)

    # Count
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Paginate
    stmt = stmt.order_by(desc(PlaybookRun.event_time))
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(stmt)
    runs = result.scalars().all()

    items = [_run_to_response(r, playbook.name) for r in runs]

    return PlaybookRunListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


# ============================================================================
# Detection-Playbook Link Endpoints
# ============================================================================

@router.post("/{playbook_id}/link-detection", response_model=DetectionPlaybookLinkResponse)
async def link_detection_to_playbook(
    playbook_id: int,
    link_data: DetectionPlaybookLinkCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Manually link a detection to a playbook.
    """
    # Verify playbook exists
    pb_stmt = select(Playbook).where(Playbook.id == playbook_id)
    pb_result = await db.execute(pb_stmt)
    playbook = pb_result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    # Verify detection exists
    det_stmt = select(Detection).where(Detection.id == link_data.detection_id)
    det_result = await db.execute(det_stmt)
    detection = det_result.scalar_one_or_none()
    if not detection:
        raise HTTPException(status_code=404, detail="Detection not found")

    # Check for existing link
    existing_stmt = select(DetectionPlaybookLink).where(
        DetectionPlaybookLink.detection_id == link_data.detection_id,
        DetectionPlaybookLink.playbook_id == playbook_id,
    )
    existing = (await db.execute(existing_stmt)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="Link already exists")

    # Create link
    link = DetectionPlaybookLink(
        detection_id=link_data.detection_id,
        playbook_id=playbook_id,
        link_type="manual",
        created_by=user.id,
    )
    db.add(link)
    await db.commit()
    await db.refresh(link)

    return DetectionPlaybookLinkResponse(
        id=link.id,
        detection_id=link.detection_id,
        playbook_id=link.playbook_id,
        link_type=link.link_type,
        link_evidence=link.link_evidence,
        detection_name=detection.name,
        playbook_name=playbook.name,
        created_by=link.created_by,
        created_at=link.created_at,
    )


@router.delete("/{playbook_id}/link-detection/{detection_id}")
async def unlink_detection_from_playbook(
    playbook_id: int,
    detection_id: int,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Remove link between detection and playbook.
    """
    stmt = select(DetectionPlaybookLink).where(
        DetectionPlaybookLink.detection_id == detection_id,
        DetectionPlaybookLink.playbook_id == playbook_id,
    )
    link = (await db.execute(stmt)).scalar_one_or_none()

    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    await db.delete(link)
    await db.commit()

    return {"message": "Link removed"}


# ============================================================================
# SOAR Dashboard Endpoints
# ============================================================================

@router.get("/dashboard/overview", response_model=SOARDashboardResponse)
async def get_soar_dashboard(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get SOAR dashboard overview with metrics and recent data.
    """
    overview = await _compute_overview_metrics(db)
    time_saved_by_playbook = await _get_time_saved_by_playbook(db)
    top_playbooks = await _get_top_playbooks(db, limit=10)
    top_actions = await _get_top_actions(db, limit=10)
    top_apps = await _get_top_apps(db, limit=10)
    recent_failures = await _get_recent_failures(db, limit=5)
    time_series = await _get_runs_time_series(db, days=30)
    category_breakdown = await _get_category_breakdown(db)

    return SOARDashboardResponse(
        overview=overview,
        time_saved_by_playbook=time_saved_by_playbook,
        top_playbooks=top_playbooks,
        top_actions=top_actions,
        top_apps=top_apps,
        recent_failures=recent_failures,
        time_series=time_series,
        category_breakdown=category_breakdown,
    )


# ============================================================================
# Helper Functions
# ============================================================================

async def _get_playbook_stats(db: AsyncSession, playbook_id: int) -> dict:
    """Get basic stats for a playbook."""
    # Run count
    run_count_stmt = select(func.count(PlaybookRun.id)).where(
        PlaybookRun.playbook_id == playbook_id
    )
    run_count = (await db.execute(run_count_stmt)).scalar() or 0

    # Success count
    success_count_stmt = select(func.count(PlaybookRun.id)).where(
        PlaybookRun.playbook_id == playbook_id,
        PlaybookRun.status == "success",
    )
    success_count = (await db.execute(success_count_stmt)).scalar() or 0

    # Success rate
    success_rate = (success_count / run_count * 100) if run_count > 0 else None

    # Linked detections
    link_count_stmt = select(func.count(DetectionPlaybookLink.id)).where(
        DetectionPlaybookLink.playbook_id == playbook_id
    )
    linked_detection_count = (await db.execute(link_count_stmt)).scalar() or 0

    return {
        "run_count": run_count,
        "successful_runs": success_count,
        "success_rate": success_rate,
        "linked_detection_count": linked_detection_count,
    }


async def _compute_playbook_metrics(db: AsyncSession, playbook: Playbook) -> PlaybookMetrics:
    """Compute full metrics for a playbook."""
    stats = await _get_playbook_stats(db, playbook.id)

    # Get success/failure counts
    success_stmt = select(func.count(PlaybookRun.id)).where(
        PlaybookRun.playbook_id == playbook.id,
        PlaybookRun.status == "success",
    )
    successful_runs = (await db.execute(success_stmt)).scalar() or 0

    failure_stmt = select(func.count(PlaybookRun.id)).where(
        PlaybookRun.playbook_id == playbook.id,
        PlaybookRun.status == "failure",
    )
    failed_runs = (await db.execute(failure_stmt)).scalar() or 0

    # Get duration stats
    duration_stmt = select(
        func.avg(PlaybookRun.duration_seconds),
    ).where(
        PlaybookRun.playbook_id == playbook.id,
        PlaybookRun.duration_seconds.isnot(None),
    )
    avg_duration = (await db.execute(duration_stmt)).scalar()

    # Last run
    last_run_stmt = (
        select(PlaybookRun.event_time)
        .where(PlaybookRun.playbook_id == playbook.id)
        .order_by(desc(PlaybookRun.event_time))
        .limit(1)
    )
    last_run_at = (await db.execute(last_run_stmt)).scalar()

    # Time saved calculation
    time_saved_per_run = getattr(playbook, 'time_saved_minutes', 0) or 0
    total_time_saved_hours = (successful_runs * time_saved_per_run) / 60.0

    return PlaybookMetrics(
        playbook_id=playbook.id,
        playbook_name=playbook.name,
        category=getattr(playbook, 'category', None),
        total_runs=stats["run_count"],
        successful_runs=successful_runs,
        failed_runs=failed_runs,
        success_rate=stats["success_rate"] or 0.0,
        avg_duration_seconds=avg_duration,
        last_run_at=last_run_at,
        linked_detections=stats["linked_detection_count"],
        time_saved_per_run_minutes=time_saved_per_run,
        total_time_saved_hours=total_time_saved_hours,
    )


async def _get_action_metrics_for_playbook(db: AsyncSession, playbook_id: int) -> List[ActionMetrics]:
    """Get action metrics for runs of a specific playbook."""
    stmt = (
        select(
            ActionRun.action_name,
            ActionRun.app_name,
            func.count(ActionRun.id).label("total"),
            func.sum(case((ActionRun.status == "success", 1), else_=0)).label("success"),
            func.avg(ActionRun.duration_seconds).label("avg_duration"),
        )
        .join(PlaybookRun)
        .where(PlaybookRun.playbook_id == playbook_id)
        .group_by(ActionRun.action_name, ActionRun.app_name)
        .order_by(desc("total"))
        .limit(20)
    )

    result = await db.execute(stmt)
    metrics = []
    for row in result.all():
        total = row.total or 0
        success = row.success or 0
        metrics.append(ActionMetrics(
            action_name=row.action_name,
            app_name=row.app_name,
            total_runs=total,
            successful_runs=success,
            failed_runs=total - success,
            success_rate=(success / total * 100) if total > 0 else 0.0,
            avg_duration_seconds=row.avg_duration,
        ))

    return metrics


async def _compute_overview_metrics(db: AsyncSession) -> SOAROverviewMetrics:
    """Compute overall SOAR metrics including time savings."""
    # Playbook counts
    total_playbooks = (await db.execute(select(func.count(Playbook.id)))).scalar() or 0
    active_playbooks = (await db.execute(
        select(func.count(Playbook.id)).where(Playbook.is_active == True)
    )).scalar() or 0

    # Count playbooks with time_saved_minutes configured
    playbooks_with_time_config = (await db.execute(
        select(func.count(Playbook.id)).where(
            Playbook.time_saved_minutes > 0
        )
    )).scalar() or 0

    # Run counts
    total_runs = (await db.execute(select(func.count(PlaybookRun.id)))).scalar() or 0
    successful_runs = (await db.execute(
        select(func.count(PlaybookRun.id)).where(PlaybookRun.status == "success")
    )).scalar() or 0
    failed_runs = (await db.execute(
        select(func.count(PlaybookRun.id)).where(PlaybookRun.status == "failure")
    )).scalar() or 0
    cancelled_runs = (await db.execute(
        select(func.count(PlaybookRun.id)).where(PlaybookRun.status == "cancelled")
    )).scalar() or 0

    # Action counts
    total_actions = (await db.execute(select(func.count(ActionRun.id)))).scalar() or 0

    # Unique action types and apps
    unique_action_types = (await db.execute(
        select(func.count(func.distinct(ActionRun.action_name)))
    )).scalar() or 0
    unique_apps = (await db.execute(
        select(func.count(func.distinct(ActionRun.app_name))).where(ActionRun.app_name.isnot(None))
    )).scalar() or 0

    # Time-based run counts
    now = datetime.utcnow()
    runs_24h = (await db.execute(
        select(func.count(PlaybookRun.id)).where(
            PlaybookRun.event_time >= now - timedelta(hours=24)
        )
    )).scalar() or 0

    runs_7d = (await db.execute(
        select(func.count(PlaybookRun.id)).where(
            PlaybookRun.event_time >= now - timedelta(days=7)
        )
    )).scalar() or 0

    runs_30d = (await db.execute(
        select(func.count(PlaybookRun.id)).where(
            PlaybookRun.event_time >= now - timedelta(days=30)
        )
    )).scalar() or 0

    # Duration stats (average and median approximation)
    avg_duration = (await db.execute(
        select(func.avg(PlaybookRun.duration_seconds)).where(
            PlaybookRun.duration_seconds.isnot(None)
        )
    )).scalar()

    # For SQLite, we'll use a simple approach for median
    median_duration = None
    if total_runs > 0:
        median_stmt = (
            select(PlaybookRun.duration_seconds)
            .where(PlaybookRun.duration_seconds.isnot(None))
            .order_by(PlaybookRun.duration_seconds)
            .offset(total_runs // 2)
            .limit(1)
        )
        median_result = (await db.execute(median_stmt)).scalar()
        median_duration = median_result

    # Detection link counts
    linked_detections = (await db.execute(
        select(func.count(func.distinct(DetectionPlaybookLink.detection_id)))
    )).scalar() or 0

    total_detections = (await db.execute(select(func.count(Detection.id)))).scalar() or 0
    unlinked_detections = total_detections - linked_detections

    # Automation coverage percent
    automation_coverage = (linked_detections / total_detections * 100) if total_detections > 0 else 0.0

    # Calculate total time saved across all playbooks
    # Sum of (successful_runs * time_saved_minutes) for each playbook
    time_saved_stmt = (
        select(
            func.sum(Playbook.time_saved_minutes * func.count(PlaybookRun.id))
        )
        .join(PlaybookRun, PlaybookRun.playbook_id == Playbook.id)
        .where(PlaybookRun.status == "success")
        .group_by(Playbook.id)
    )
    # Actually, let's compute it differently for accuracy
    playbooks_result = await db.execute(select(Playbook))
    playbooks = playbooks_result.scalars().all()

    total_time_saved_minutes = 0.0
    for pb in playbooks:
        success_count_stmt = select(func.count(PlaybookRun.id)).where(
            PlaybookRun.playbook_id == pb.id,
            PlaybookRun.status == "success"
        )
        pb_success_runs = (await db.execute(success_count_stmt)).scalar() or 0
        time_per_run = getattr(pb, 'time_saved_minutes', 0) or 0
        total_time_saved_minutes += pb_success_runs * time_per_run

    total_time_saved_hours = total_time_saved_minutes / 60.0

    # Estimated cost savings (assuming $75/hr for analyst time)
    ANALYST_HOURLY_RATE = 75.0
    estimated_cost_savings = total_time_saved_hours * ANALYST_HOURLY_RATE

    # MTTR (Mean Time to Respond) - based on average playbook duration
    mttr_minutes = (avg_duration / 60.0) if avg_duration else None

    # Automation rate: % of runs that completed automatically (success + failure vs cancelled)
    completed_runs = successful_runs + failed_runs
    automation_rate = (completed_runs / total_runs * 100) if total_runs > 0 else 0.0

    return SOAROverviewMetrics(
        total_playbooks=total_playbooks,
        active_playbooks=active_playbooks,
        playbooks_with_time_config=playbooks_with_time_config,
        total_runs=total_runs,
        successful_runs=successful_runs,
        failed_runs=failed_runs,
        cancelled_runs=cancelled_runs,
        overall_success_rate=(successful_runs / total_runs * 100) if total_runs > 0 else 0.0,
        total_actions=total_actions,
        avg_actions_per_run=(total_actions / total_runs) if total_runs > 0 else 0.0,
        unique_action_types=unique_action_types,
        unique_apps=unique_apps,
        avg_run_duration_seconds=avg_duration,
        median_run_duration_seconds=median_duration,
        runs_last_24h=runs_24h,
        runs_last_7d=runs_7d,
        runs_last_30d=runs_30d,
        total_time_saved_minutes=total_time_saved_minutes,
        total_time_saved_hours=total_time_saved_hours,
        estimated_cost_savings=estimated_cost_savings,
        linked_detections=linked_detections,
        unlinked_detections=unlinked_detections,
        automation_coverage_percent=automation_coverage,
        mttr_minutes=mttr_minutes,
        automation_rate=automation_rate,
    )


async def _get_top_playbooks(db: AsyncSession, limit: int = 10) -> List[PlaybookMetrics]:
    """Get top playbooks by run count."""
    stmt = (
        select(Playbook)
        .join(PlaybookRun, isouter=True)
        .group_by(Playbook.id)
        .order_by(desc(func.count(PlaybookRun.id)))
        .limit(limit)
    )

    result = await db.execute(stmt)
    playbooks = result.scalars().all()

    return [await _compute_playbook_metrics(db, pb) for pb in playbooks]


async def _get_top_actions(db: AsyncSession, limit: int = 10) -> List[ActionMetrics]:
    """Get top actions by run count."""
    stmt = (
        select(
            ActionRun.action_name,
            ActionRun.app_name,
            func.count(ActionRun.id).label("total"),
            func.sum(case((ActionRun.status == "success", 1), else_=0)).label("success"),
            func.avg(ActionRun.duration_seconds).label("avg_duration"),
        )
        .group_by(ActionRun.action_name, ActionRun.app_name)
        .order_by(desc("total"))
        .limit(limit)
    )

    result = await db.execute(stmt)
    metrics = []
    for row in result.all():
        total = row.total or 0
        success = row.success or 0
        metrics.append(ActionMetrics(
            action_name=row.action_name,
            app_name=row.app_name,
            total_runs=total,
            successful_runs=success,
            failed_runs=total - success,
            success_rate=(success / total * 100) if total > 0 else 0.0,
            avg_duration_seconds=row.avg_duration,
        ))

    return metrics


async def _get_recent_failures(db: AsyncSession, limit: int = 5) -> List[PlaybookRunResponse]:
    """Get most recent failed playbook runs."""
    stmt = (
        select(PlaybookRun, Playbook.name)
        .join(Playbook, isouter=True)
        .where(PlaybookRun.status == "failure")
        .order_by(desc(PlaybookRun.event_time))
        .limit(limit)
    )

    result = await db.execute(stmt)
    return [_run_to_response(run, name) for run, name in result.all()]


async def _get_runs_time_series(db: AsyncSession, days: int = 30) -> List[dict]:
    """Get daily run counts for time series chart."""
    cutoff = datetime.utcnow() - timedelta(days=days)

    # This is SQLite-specific date formatting
    stmt = (
        select(
            func.date(PlaybookRun.event_time).label("date"),
            func.count(PlaybookRun.id).label("total"),
            func.sum(case((PlaybookRun.status == "success", 1), else_=0)).label("success"),
            func.sum(case((PlaybookRun.status == "failure", 1), else_=0)).label("failure"),
        )
        .where(PlaybookRun.event_time >= cutoff)
        .group_by(func.date(PlaybookRun.event_time))
        .order_by("date")
    )

    result = await db.execute(stmt)
    return [
        {
            "date": row.date,
            "total": row.total or 0,
            "success": row.success or 0,
            "failure": row.failure or 0,
        }
        for row in result.all()
    ]


def _run_to_response(run: PlaybookRun, playbook_name: Optional[str] = None) -> PlaybookRunResponse:
    """Convert PlaybookRun model to response schema."""
    return PlaybookRunResponse(
        id=run.id,
        playbook_run_id=run.playbook_run_id,
        playbook_id=run.playbook_id,
        playbook_name=playbook_name,
        status=run.status,
        start_time=run.start_time,
        end_time=run.end_time,
        duration_seconds=run.duration_seconds,
        container_id=run.container_id,
        event_time=run.event_time,
        action_count=0,  # Could be computed if needed
        successful_actions=0,
        failed_actions=0,
        created_at=run.created_at,
    )


async def _get_time_saved_by_playbook(db: AsyncSession) -> List[PlaybookTimeSaved]:
    """Get time saved breakdown for each playbook."""
    playbooks_result = await db.execute(
        select(Playbook).where(Playbook.time_saved_minutes > 0)
    )
    playbooks = playbooks_result.scalars().all()

    time_saved_list = []
    for pb in playbooks:
        # Get successful runs count
        success_count_stmt = select(func.count(PlaybookRun.id)).where(
            PlaybookRun.playbook_id == pb.id,
            PlaybookRun.status == "success"
        )
        successful_runs = (await db.execute(success_count_stmt)).scalar() or 0

        if successful_runs > 0:
            time_per_run = getattr(pb, 'time_saved_minutes', 0) or 0
            total_minutes = successful_runs * time_per_run
            total_hours = total_minutes / 60.0

            time_saved_list.append(PlaybookTimeSaved(
                playbook_id=pb.id,
                playbook_name=pb.name,
                category=getattr(pb, 'category', None),
                successful_runs=successful_runs,
                time_saved_per_run_minutes=time_per_run,
                total_time_saved_minutes=total_minutes,
                total_time_saved_hours=total_hours,
            ))

    # Sort by total time saved descending
    time_saved_list.sort(key=lambda x: x.total_time_saved_hours, reverse=True)
    return time_saved_list


async def _get_top_apps(db: AsyncSession, limit: int = 10) -> List[AppMetrics]:
    """Get top apps/integrations by action count."""
    stmt = (
        select(
            ActionRun.app_name,
            func.count(ActionRun.id).label("total"),
            func.sum(case((ActionRun.status == "success", 1), else_=0)).label("success"),
            func.count(func.distinct(ActionRun.action_name)).label("unique_actions"),
            func.avg(ActionRun.duration_seconds).label("avg_duration"),
        )
        .where(ActionRun.app_name.isnot(None))
        .group_by(ActionRun.app_name)
        .order_by(desc("total"))
        .limit(limit)
    )

    result = await db.execute(stmt)
    metrics = []
    for row in result.all():
        total = row.total or 0
        success = row.success or 0
        metrics.append(AppMetrics(
            app_name=row.app_name,
            total_actions=total,
            successful_actions=success,
            failed_actions=total - success,
            success_rate=(success / total * 100) if total > 0 else 0.0,
            unique_action_types=row.unique_actions or 0,
            avg_action_duration=row.avg_duration,
        ))

    return metrics


async def _get_category_breakdown(db: AsyncSession) -> List[dict]:
    """Get playbook run breakdown by category."""
    stmt = (
        select(
            Playbook.category,
            func.count(PlaybookRun.id).label("total_runs"),
            func.sum(case((PlaybookRun.status == "success", 1), else_=0)).label("success"),
            func.sum(case((PlaybookRun.status == "failure", 1), else_=0)).label("failure"),
        )
        .join(PlaybookRun, PlaybookRun.playbook_id == Playbook.id)
        .group_by(Playbook.category)
        .order_by(desc("total_runs"))
    )

    result = await db.execute(stmt)
    return [
        {
            "category": row.category or "Uncategorized",
            "total_runs": row.total_runs or 0,
            "successful_runs": row.success or 0,
            "failed_runs": row.failure or 0,
            "success_rate": (row.success / row.total_runs * 100) if row.total_runs > 0 else 0.0,
        }
        for row in result.all()
    ]
