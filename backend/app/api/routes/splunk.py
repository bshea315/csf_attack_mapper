"""
Splunk configuration and sync API routes.

Provides endpoints for:
- Managing Splunk connection configuration
- Testing Splunk connectivity
- Syncing ES correlation searches
- Syncing SOAR playbook/action runs
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.models.database import get_db
from app.models.user import User
from app.models.splunk_config import SplunkConfig
from app.api.deps import get_current_user, get_admin_user
from app.schemas.splunk import (
    SplunkConfigCreate,
    SplunkConfigUpdate,
    SplunkConfigResponse,
    SplunkConnectionTestResponse,
    ESSyncResponse,
    SOARSyncRequest,
    SOARSyncResponse,
)
from app.core.encryption import encrypt_secret
from app.services.splunk_connector import (
    SplunkConnector,
    SplunkConnectorError,
    SplunkAuthError,
    SplunkConnectionError,
)
from app.services.splunk_sync import SplunkSyncService

router = APIRouter(prefix="/splunk", tags=["splunk"])


# ============================================================================
# Configuration Endpoints
# ============================================================================

@router.get("/config", response_model=Optional[SplunkConfigResponse])
async def get_splunk_config(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get current Splunk configuration.

    Returns the active configuration with secrets masked.
    """
    stmt = select(SplunkConfig).where(SplunkConfig.is_active == True)
    result = await db.execute(stmt)
    config = result.scalar_one_or_none()

    if not config:
        return None

    return _config_to_response(config)


@router.post("/config", response_model=SplunkConfigResponse)
async def create_splunk_config(
    config_data: SplunkConfigCreate,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create new Splunk configuration.

    Requires admin role. Deactivates any existing configurations.
    """
    # Deactivate existing configs
    stmt = update(SplunkConfig).values(is_active=False)
    await db.execute(stmt)

    # Encrypt secrets
    auth_token_encrypted = None
    auth_password_encrypted = None

    if config_data.auth_type == "token" and config_data.auth_token:
        auth_token_encrypted = encrypt_secret(config_data.auth_token)
    elif config_data.auth_type == "basic" and config_data.auth_password:
        auth_password_encrypted = encrypt_secret(config_data.auth_password)

    # Create new config
    config = SplunkConfig(
        name=config_data.name,
        base_url=config_data.base_url,
        auth_type=config_data.auth_type,
        auth_token_encrypted=auth_token_encrypted,
        auth_username=config_data.auth_username,
        auth_password_encrypted=auth_password_encrypted,
        verify_tls=config_data.verify_tls,
        es_app_namespace=config_data.es_app_namespace,
        es_owner=config_data.es_owner,
        soar_playbook_run_index=config_data.soar_playbook_run_index,
        soar_action_run_index=config_data.soar_action_run_index,
        soar_time_window_days=config_data.soar_time_window_days,
        is_active=True,
    )
    db.add(config)
    await db.commit()
    await db.refresh(config)

    return _config_to_response(config)


@router.put("/config", response_model=SplunkConfigResponse)
async def update_splunk_config(
    config_data: SplunkConfigUpdate,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Update existing Splunk configuration.

    Only updates fields that are provided. Requires admin role.
    """
    stmt = select(SplunkConfig).where(SplunkConfig.is_active == True)
    result = await db.execute(stmt)
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="No Splunk configuration found")

    # Update provided fields
    update_data = config_data.model_dump(exclude_unset=True)

    # Handle secret encryption
    if "auth_token" in update_data and update_data["auth_token"]:
        config.auth_token_encrypted = encrypt_secret(update_data.pop("auth_token"))
    elif "auth_token" in update_data:
        update_data.pop("auth_token")

    if "auth_password" in update_data and update_data["auth_password"]:
        config.auth_password_encrypted = encrypt_secret(update_data.pop("auth_password"))
    elif "auth_password" in update_data:
        update_data.pop("auth_password")

    # Apply other updates
    for key, value in update_data.items():
        if hasattr(config, key):
            setattr(config, key, value)

    await db.commit()
    await db.refresh(config)

    return _config_to_response(config)


@router.delete("/config")
async def delete_splunk_config(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Delete active Splunk configuration.

    Requires admin role.
    """
    stmt = select(SplunkConfig).where(SplunkConfig.is_active == True)
    result = await db.execute(stmt)
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="No Splunk configuration found")

    await db.delete(config)
    await db.commit()

    return {"message": "Configuration deleted"}


# ============================================================================
# Connection Test Endpoint
# ============================================================================

@router.post("/test-connection", response_model=SplunkConnectionTestResponse)
async def test_splunk_connection(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Test connection to configured Splunk server.

    Uses stored configuration to attempt connection and retrieve server info.
    """
    try:
        connector = await SplunkConnector.from_config(db)
        server_info = await connector.test_connection()

        return SplunkConnectionTestResponse(
            success=True,
            message="Successfully connected to Splunk",
            server_info=server_info,
        )

    except SplunkAuthError as e:
        return SplunkConnectionTestResponse(
            success=False,
            message="Authentication failed",
            error=str(e),
        )

    except SplunkConnectionError as e:
        return SplunkConnectionTestResponse(
            success=False,
            message="Connection failed",
            error=str(e),
        )

    except SplunkConnectorError as e:
        return SplunkConnectionTestResponse(
            success=False,
            message="Splunk API error",
            error=str(e),
        )


# ============================================================================
# ES Sync Endpoints
# ============================================================================

@router.post("/sync/es", response_model=ESSyncResponse)
async def sync_es_correlation_searches(
    background_tasks: BackgroundTasks,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Sync ES correlation searches from Splunk.

    Fetches all correlation searches from Splunk ES and creates/updates
    corresponding detections in the local database.

    Requires admin role.
    """
    sync_service = SplunkSyncService(db)
    result = await sync_service.sync_es_correlation_searches()

    return ESSyncResponse(
        success=result.success,
        total_found=result.total_found,
        created=result.created,
        updated=result.updated,
        unchanged=result.unchanged,
        failed=result.failed,
        errors=result.errors,
        duration_seconds=result.duration_seconds,
    )


# ============================================================================
# SOAR Sync Endpoints
# ============================================================================

@router.post("/sync/soar", response_model=SOARSyncResponse)
async def sync_soar_logs(
    request: SOARSyncRequest,
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Sync SOAR playbook and action runs from Splunk.

    Fetches playbook execution logs from configured Splunk indexes
    and stores them for metrics and linkage analysis.

    Requires admin role.
    """
    sync_service = SplunkSyncService(db)
    result = await sync_service.sync_soar_logs(days=request.days)

    return SOARSyncResponse(
        success=result.success,
        playbook_runs_found=result.playbook_runs_found,
        playbook_runs_created=result.playbook_runs_created,
        action_runs_found=result.action_runs_found,
        action_runs_created=result.action_runs_created,
        playbooks_discovered=result.playbooks_discovered,
        errors=result.errors,
        duration_seconds=result.duration_seconds,
    )


@router.post("/sync/auto-link")
async def auto_link_detections_to_playbooks(
    user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Automatically link detections to playbooks using heuristics.

    Creates auto-type links between detections and playbooks based on:
    - Name matching
    - Keyword similarity

    Requires admin role.
    """
    sync_service = SplunkSyncService(db)
    stats = await sync_service.auto_link_detections()

    return {
        "success": True,
        "links_created": stats["links_created"],
        "links_skipped": stats["links_skipped"],
        "errors": stats["errors"],
    }


# ============================================================================
# Helper Functions
# ============================================================================

def _config_to_response(config: SplunkConfig) -> SplunkConfigResponse:
    """Convert config model to response schema with masked secrets."""
    return SplunkConfigResponse(
        id=config.id,
        name=config.name,
        base_url=config.base_url,
        auth_type=config.auth_type,
        verify_tls=config.verify_tls,
        es_app_namespace=config.es_app_namespace,
        es_owner=config.es_owner,
        soar_playbook_run_index=config.soar_playbook_run_index,
        soar_action_run_index=config.soar_action_run_index,
        soar_time_window_days=config.soar_time_window_days,
        has_token=bool(config.auth_token_encrypted),
        has_password=bool(config.auth_password_encrypted),
        is_active=config.is_active,
        last_es_sync_at=config.last_es_sync_at,
        last_soar_sync_at=config.last_soar_sync_at,
        es_detection_count=config.es_detection_count,
        soar_playbook_count=config.soar_playbook_count,
        soar_run_count=config.soar_run_count,
        created_at=config.created_at,
        updated_at=config.updated_at,
    )
