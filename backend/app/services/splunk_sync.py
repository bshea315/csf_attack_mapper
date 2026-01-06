"""
Splunk ES and SOAR synchronization service.

Handles:
- Syncing ES correlation searches as detections
- Syncing SOAR playbook/action runs
- Auto-linking detections to playbooks
"""
import json
import logging
import time
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func

from app.models.detection import Detection
from app.models.playbook import Playbook
from app.models.soar import PlaybookRun, ActionRun, DetectionPlaybookLink
from app.models.splunk_config import SplunkConfig
from app.services.splunk_connector import SplunkConnector, SplunkConnectorError

logger = logging.getLogger(__name__)


class ESSyncResult:
    """Result of ES correlation search sync."""

    def __init__(self):
        self.success = False
        self.total_found = 0
        self.created = 0
        self.updated = 0
        self.unchanged = 0
        self.failed = 0
        self.errors: List[str] = []
        self.duration_seconds = 0.0


class SOARSyncResult:
    """Result of SOAR log sync."""

    def __init__(self):
        self.success = False
        self.playbook_runs_found = 0
        self.playbook_runs_created = 0
        self.action_runs_found = 0
        self.action_runs_created = 0
        self.playbooks_discovered = 0
        self.errors: List[str] = []
        self.duration_seconds = 0.0


class SplunkSyncService:
    """
    Service for syncing Splunk ES and SOAR data.
    """

    def __init__(self, db: AsyncSession, connector: Optional[SplunkConnector] = None):
        """
        Initialize sync service.

        Args:
            db: Database session
            connector: Optional pre-configured connector (will create from config if None)
        """
        self.db = db
        self._connector = connector

    async def _get_connector(self) -> SplunkConnector:
        """Get or create Splunk connector."""
        if self._connector is None:
            self._connector = await SplunkConnector.from_config(self.db)
        return self._connector

    async def sync_es_correlation_searches(self) -> ESSyncResult:
        """
        Sync ES correlation searches from Splunk to local detections.

        Creates new detections for new searches, updates existing ones.

        Returns:
            ESSyncResult with statistics
        """
        result = ESSyncResult()
        start_time = time.time()

        try:
            connector = await self._get_connector()
            searches = await connector.get_es_correlation_searches()
            result.total_found = len(searches)

            for search in searches:
                try:
                    created, updated = await self._upsert_detection_from_es(search)
                    if created:
                        result.created += 1
                    elif updated:
                        result.updated += 1
                    else:
                        result.unchanged += 1
                except Exception as e:
                    result.failed += 1
                    result.errors.append(f"Error processing {search.get('name', 'unknown')}: {e}")
                    logger.exception(f"Failed to process ES search: {search}")

            # Update sync timestamp on config
            await self._update_es_sync_timestamp()
            await self.db.commit()

            result.success = True

        except SplunkConnectorError as e:
            result.errors.append(f"Splunk connection error: {e}")
            logger.error(f"ES sync failed: {e}")
        except Exception as e:
            result.errors.append(f"Unexpected error: {e}")
            logger.exception("ES sync failed unexpectedly")

        result.duration_seconds = time.time() - start_time
        return result

    async def _upsert_detection_from_es(self, search: Dict[str, Any]) -> Tuple[bool, bool]:
        """
        Create or update detection from ES correlation search.

        Returns:
            Tuple of (created, updated) booleans
        """
        savedsearch_id = search.get("savedsearch_id")
        if not savedsearch_id:
            raise ValueError("Missing savedsearch_id")

        # Check for existing detection by Splunk ID
        stmt = select(Detection).where(
            Detection.splunk_savedsearch_id == savedsearch_id
        )
        existing = (await self.db.execute(stmt)).scalar_one_or_none()

        # Also check by detection_id (name-based fallback)
        detection_id = f"es_{savedsearch_id}"
        if not existing:
            stmt = select(Detection).where(Detection.detection_id == detection_id)
            existing = (await self.db.execute(stmt)).scalar_one_or_none()

        spl = search.get("spl", "")
        name = search.get("name", savedsearch_id)
        description = search.get("description", "")
        severity = search.get("severity", "medium")
        status = "enabled" if search.get("enabled", True) else "disabled"
        mitre_tags = search.get("mitre_tags", [])
        raw_payload = search.get("raw_payload", {})

        if existing:
            # Check if anything changed
            changes = []
            if existing.spl != spl:
                changes.append("spl")
            if existing.name != name:
                changes.append("name")
            if existing.description != description:
                changes.append("description")
            if existing.severity != severity:
                changes.append("severity")
            if existing.status != status:
                changes.append("status")

            if not changes:
                return (False, False)

            # Update existing
            existing.spl = spl
            existing.name = name
            existing.description = description
            existing.severity = severity
            existing.status = status
            existing.original_mitre_tags = json.dumps(mitre_tags) if mitre_tags else None
            existing.splunk_app = search.get("app")
            existing.raw_savedsearch_payload = json.dumps(raw_payload)
            existing.updated_at = datetime.utcnow()

            return (False, True)

        else:
            # Create new detection
            detection = Detection(
                detection_id=detection_id,
                name=name,
                description=description,
                spl=spl,
                severity=severity,
                status=status,
                source_type="splunk_es",
                splunk_savedsearch_id=savedsearch_id,
                splunk_app=search.get("app"),
                original_mitre_tags=json.dumps(mitre_tags) if mitre_tags else None,
                raw_savedsearch_payload=json.dumps(raw_payload),
            )
            self.db.add(detection)

            return (True, False)

    async def _update_es_sync_timestamp(self):
        """Update last ES sync timestamp on active config."""
        stmt = (
            update(SplunkConfig)
            .where(SplunkConfig.is_active == True)
            .values(last_es_sync_at=datetime.utcnow())
        )
        await self.db.execute(stmt)

    async def sync_soar_logs(self, days: int = 30) -> SOARSyncResult:
        """
        Sync SOAR playbook and action runs from Splunk.

        Args:
            days: Number of days of history to sync

        Returns:
            SOARSyncResult with statistics
        """
        result = SOARSyncResult()
        start_time = time.time()

        try:
            connector = await self._get_connector()

            # Get config for index names
            config = await self._get_active_config()
            if not config:
                result.errors.append("No active Splunk configuration")
                return result

            # Sync playbook runs
            playbook_runs = await connector.get_soar_playbook_runs(
                index=config.soar_playbook_run_index,
                days=days,
            )
            result.playbook_runs_found = len(playbook_runs)

            for run in playbook_runs:
                try:
                    created = await self._upsert_playbook_run(run)
                    if created:
                        result.playbook_runs_created += 1
                except Exception as e:
                    result.errors.append(f"Error processing playbook run: {e}")

            # Sync action runs
            action_runs = await connector.get_soar_action_runs(
                index=config.soar_action_run_index,
                days=days,
            )
            result.action_runs_found = len(action_runs)

            for action in action_runs:
                try:
                    created = await self._upsert_action_run(action)
                    if created:
                        result.action_runs_created += 1
                except Exception as e:
                    result.errors.append(f"Error processing action run: {e}")

            # Count discovered playbooks
            stmt = select(func.count(Playbook.id))
            count_result = await self.db.execute(stmt)
            result.playbooks_discovered = count_result.scalar() or 0

            # Update sync timestamp
            await self._update_soar_sync_timestamp()
            await self.db.commit()

            result.success = True

        except SplunkConnectorError as e:
            result.errors.append(f"Splunk connection error: {e}")
            logger.error(f"SOAR sync failed: {e}")
        except Exception as e:
            result.errors.append(f"Unexpected error: {e}")
            logger.exception("SOAR sync failed unexpectedly")

        result.duration_seconds = time.time() - start_time
        return result

    async def _upsert_playbook_run(self, run: Dict[str, Any]) -> bool:
        """
        Create playbook run if not exists. Also creates/updates playbook reference.

        Returns:
            True if created, False if already exists
        """
        run_id = run.get("playbook_run_id")
        if not run_id:
            return False

        # Check for existing
        stmt = select(PlaybookRun).where(PlaybookRun.playbook_run_id == run_id)
        existing = (await self.db.execute(stmt)).scalar_one_or_none()
        if existing:
            return False

        # Ensure playbook exists
        playbook_id = await self._ensure_playbook(
            playbook_external_id=run.get("playbook_id"),
            playbook_name=run.get("playbook_name"),
        )

        # Create run
        playbook_run = PlaybookRun(
            playbook_run_id=run_id,
            playbook_id=playbook_id,
            status=run.get("status", "unknown"),
            start_time=run.get("start_time"),
            end_time=run.get("end_time"),
            duration_seconds=run.get("duration_seconds"),
            container_id=run.get("container_id"),
            event_time=run.get("event_time"),
            index_time=run.get("index_time"),
            raw_event=run.get("raw_event"),
        )
        self.db.add(playbook_run)

        return True

    async def _ensure_playbook(
        self,
        playbook_external_id: Optional[str],
        playbook_name: Optional[str],
    ) -> Optional[int]:
        """
        Ensure playbook exists in database, creating if necessary.

        Returns:
            Playbook internal ID, or None if no identifier provided
        """
        if not playbook_external_id and not playbook_name:
            return None

        external_id = playbook_external_id or playbook_name

        stmt = select(Playbook).where(Playbook.playbook_id == external_id)
        existing = (await self.db.execute(stmt)).scalar_one_or_none()

        if existing:
            return existing.id

        # Create new playbook
        playbook = Playbook(
            playbook_id=external_id,
            name=playbook_name or external_id,
            is_active=True,
        )
        self.db.add(playbook)
        await self.db.flush()

        return playbook.id

    async def _upsert_action_run(self, action: Dict[str, Any]) -> bool:
        """
        Create action run if not exists.

        Returns:
            True if created, False if already exists
        """
        action_run_id = action.get("action_run_id")
        if not action_run_id:
            return False

        # Check for existing
        stmt = select(ActionRun).where(ActionRun.action_run_id == action_run_id)
        existing = (await self.db.execute(stmt)).scalar_one_or_none()
        if existing:
            return False

        # Find linked playbook run
        playbook_run_id = None
        ext_pb_run_id = action.get("playbook_run_id")
        if ext_pb_run_id:
            stmt = select(PlaybookRun.id).where(
                PlaybookRun.playbook_run_id == ext_pb_run_id
            )
            result = await self.db.execute(stmt)
            row = result.first()
            if row:
                playbook_run_id = row[0]

        # Create action run
        action_run = ActionRun(
            action_run_id=action_run_id,
            playbook_run_id=playbook_run_id,
            action_name=action.get("action_name", "unknown"),
            app_name=action.get("app_name"),
            status=action.get("status", "unknown"),
            duration_seconds=action.get("duration_seconds"),
            error_message=action.get("error_message"),
            event_time=action.get("event_time"),
            index_time=action.get("index_time"),
            raw_event=action.get("raw_event"),
        )
        self.db.add(action_run)

        return True

    async def _update_soar_sync_timestamp(self):
        """Update last SOAR sync timestamp on active config."""
        stmt = (
            update(SplunkConfig)
            .where(SplunkConfig.is_active == True)
            .values(last_soar_sync_at=datetime.utcnow())
        )
        await self.db.execute(stmt)

    async def _get_active_config(self) -> Optional[SplunkConfig]:
        """Get active Splunk configuration."""
        stmt = select(SplunkConfig).where(SplunkConfig.is_active == True)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def auto_link_detections(self) -> Dict[str, Any]:
        """
        Automatically link detections to playbooks based on heuristics.

        Heuristics:
        - Name matching (detection name contains playbook name or vice versa)
        - MITRE technique matching (if both have same techniques)

        Returns:
            Statistics about links created
        """
        stats = {
            "links_created": 0,
            "links_skipped": 0,
            "errors": [],
        }

        # Get all detections
        det_stmt = select(Detection)
        det_result = await self.db.execute(det_stmt)
        detections = det_result.scalars().all()

        # Get all playbooks
        pb_stmt = select(Playbook)
        pb_result = await self.db.execute(pb_stmt)
        playbooks = pb_result.scalars().all()

        for detection in detections:
            for playbook in playbooks:
                # Check if link already exists
                link_stmt = select(DetectionPlaybookLink).where(
                    DetectionPlaybookLink.detection_id == detection.id,
                    DetectionPlaybookLink.playbook_id == playbook.id,
                )
                existing = (await self.db.execute(link_stmt)).scalar_one_or_none()
                if existing:
                    continue

                # Check for name match
                evidence = self._check_link_heuristics(detection, playbook)
                if evidence:
                    link = DetectionPlaybookLink(
                        detection_id=detection.id,
                        playbook_id=playbook.id,
                        link_type="auto",
                        link_evidence=json.dumps(evidence),
                    )
                    self.db.add(link)
                    stats["links_created"] += 1

        await self.db.commit()
        return stats

    def _check_link_heuristics(
        self,
        detection: Detection,
        playbook: Playbook,
    ) -> Optional[Dict[str, Any]]:
        """
        Check if detection and playbook should be linked.

        Returns:
            Evidence dict if should link, None otherwise
        """
        evidence = {}
        det_name = detection.name.lower()
        pb_name = playbook.name.lower()

        # Name substring match
        if pb_name in det_name or det_name in pb_name:
            evidence["name_match"] = True

        # Common keyword matching
        det_keywords = set(det_name.replace("-", " ").replace("_", " ").split())
        pb_keywords = set(pb_name.replace("-", " ").replace("_", " ").split())

        # Remove common words
        stop_words = {"the", "a", "an", "and", "or", "for", "to", "in", "on", "with"}
        det_keywords -= stop_words
        pb_keywords -= stop_words

        common = det_keywords & pb_keywords
        if len(common) >= 2:
            evidence["keyword_match"] = list(common)

        return evidence if evidence else None
