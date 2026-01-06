#!/usr/bin/env python3
"""
Seed database with sample SOAR fixture data for development.

Creates sample:
- Playbooks
- Playbook runs
- Action runs
- Detection-playbook links
"""
import asyncio
import json
import random
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from sqlalchemy import select
from app.models.database import async_session
from app.models.playbook import Playbook
from app.models.soar import PlaybookRun, ActionRun, DetectionPlaybookLink
from app.models.detection import Detection


# Sample playbook definitions with time savings and categories
SAMPLE_PLAYBOOKS = [
    {
        "playbook_id": "investigate_malware",
        "name": "Investigate Malware Alert",
        "description": "Automated investigation of malware detection alerts",
        "category": "Investigation",
        "time_saved_minutes": 45,  # Manual investigation typically takes 45+ min
        "avg_manual_time_minutes": 60,
    },
    {
        "playbook_id": "block_ip_firewall",
        "name": "Block IP on Firewall",
        "description": "Block malicious IP addresses on perimeter firewall",
        "category": "Containment",
        "time_saved_minutes": 15,  # Quick action but requires multiple systems
        "avg_manual_time_minutes": 20,
    },
    {
        "playbook_id": "isolate_endpoint",
        "name": "Isolate Compromised Endpoint",
        "description": "Network isolation of potentially compromised endpoints",
        "category": "Containment",
        "time_saved_minutes": 20,  # Critical time-sensitive action
        "avg_manual_time_minutes": 30,
    },
    {
        "playbook_id": "phishing_response",
        "name": "Phishing Email Response",
        "description": "Automated response to phishing email reports",
        "category": "Response",
        "time_saved_minutes": 30,  # Email analysis, IOC extraction, blocking
        "avg_manual_time_minutes": 45,
    },
    {
        "playbook_id": "credential_compromise",
        "name": "Credential Compromise Response",
        "description": "Response workflow for compromised credentials",
        "category": "Response",
        "time_saved_minutes": 25,  # Password reset, session invalidation
        "avg_manual_time_minutes": 35,
    },
    {
        "playbook_id": "enrichment_workflow",
        "name": "Threat Intelligence Enrichment",
        "description": "Enrich alerts with threat intelligence data",
        "category": "Enrichment",
        "time_saved_minutes": 10,  # Quick lookups but multiple sources
        "avg_manual_time_minutes": 15,
    },
    {
        "playbook_id": "brute_force_response",
        "name": "Brute Force Attack Response",
        "description": "Automated response to brute force authentication attempts",
        "category": "Response",
        "time_saved_minutes": 20,  # Account lockout, IP blocking
        "avg_manual_time_minutes": 30,
    },
    {
        "playbook_id": "data_exfil_response",
        "name": "Data Exfiltration Response",
        "description": "Response to potential data exfiltration events",
        "category": "Investigation",
        "time_saved_minutes": 60,  # Complex analysis, multiple data sources
        "avg_manual_time_minutes": 90,
    },
]

# Sample actions that playbooks might contain
SAMPLE_ACTIONS = [
    ("get_file_reputation", "VirusTotal"),
    ("lookup_domain", "DomainTools"),
    ("get_user_info", "Active Directory"),
    ("block_ip", "Palo Alto NGFW"),
    ("quarantine_endpoint", "CrowdStrike"),
    ("disable_user", "Active Directory"),
    ("send_email", "SMTP"),
    ("create_ticket", "ServiceNow"),
    ("run_query", "Splunk"),
    ("enrich_artifact", "ThreatConnect"),
    ("get_process_info", "Carbon Black"),
    ("reset_password", "Active Directory"),
]


async def create_playbooks() -> list:
    """Create sample playbooks with time savings and categories."""
    async with async_session() as session:
        playbooks = []
        for pb_data in SAMPLE_PLAYBOOKS:
            # Check if exists
            stmt = select(Playbook).where(Playbook.playbook_id == pb_data["playbook_id"])
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                # Update existing playbook with new fields if they're not set
                if not existing.category and pb_data.get("category"):
                    existing.category = pb_data["category"]
                if not existing.time_saved_minutes and pb_data.get("time_saved_minutes"):
                    existing.time_saved_minutes = pb_data["time_saved_minutes"]
                if not existing.avg_manual_time_minutes and pb_data.get("avg_manual_time_minutes"):
                    existing.avg_manual_time_minutes = pb_data["avg_manual_time_minutes"]
                playbooks.append(existing)
                continue

            playbook = Playbook(
                playbook_id=pb_data["playbook_id"],
                name=pb_data["name"],
                description=pb_data["description"],
                is_active=True,
                category=pb_data.get("category"),
                time_saved_minutes=pb_data.get("time_saved_minutes", 0),
                avg_manual_time_minutes=pb_data.get("avg_manual_time_minutes"),
            )
            session.add(playbook)
            playbooks.append(playbook)

        await session.commit()

        # Refresh to get IDs
        for pb in playbooks:
            await session.refresh(pb)

        return playbooks


async def create_playbook_runs(playbooks: list, num_days: int = 30) -> list:
    """Create sample playbook runs over the past N days."""
    async with async_session() as session:
        runs = []
        now = datetime.utcnow()

        for _ in range(200):  # Create 200 runs
            playbook = random.choice(playbooks)

            # Random time in the past num_days
            event_time = now - timedelta(
                days=random.randint(0, num_days),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
            )

            # Random status (80% success, 15% failure, 5% cancelled)
            rand = random.random()
            if rand < 0.80:
                status = "success"
            elif rand < 0.95:
                status = "failure"
            else:
                status = "cancelled"

            # Random duration (5-300 seconds)
            duration = random.uniform(5, 300) if status != "cancelled" else None

            run_id = f"run_{playbook.playbook_id}_{event_time.strftime('%Y%m%d%H%M%S')}_{random.randint(1000, 9999)}"

            # Check if exists
            stmt = select(PlaybookRun).where(PlaybookRun.playbook_run_id == run_id)
            result = await session.execute(stmt)
            if result.scalar_one_or_none():
                continue

            run = PlaybookRun(
                playbook_run_id=run_id,
                playbook_id=playbook.id,
                status=status,
                start_time=event_time,
                end_time=event_time + timedelta(seconds=duration) if duration else None,
                duration_seconds=duration,
                container_id=f"container_{random.randint(10000, 99999)}",
                event_time=event_time,
                index_time=event_time + timedelta(seconds=random.randint(1, 60)),
            )
            session.add(run)
            runs.append(run)

        await session.commit()

        for run in runs:
            await session.refresh(run)

        return runs


async def create_action_runs(playbook_runs: list) -> list:
    """Create sample action runs for playbook runs."""
    async with async_session() as session:
        actions = []

        for run in playbook_runs:
            # Each playbook run has 3-8 actions
            num_actions = random.randint(3, 8)

            for i in range(num_actions):
                action_name, app_name = random.choice(SAMPLE_ACTIONS)

                # Action success rate depends on playbook run status
                if run.status == "success":
                    action_status = "success"
                elif run.status == "failure" and i == num_actions - 1:
                    # Last action failed
                    action_status = "failure"
                else:
                    action_status = "success" if random.random() < 0.9 else "failure"

                action_duration = random.uniform(0.5, 30)
                action_time = run.start_time + timedelta(seconds=i * 10 + random.uniform(0, 5)) if run.start_time else None

                action_run_id = f"action_{run.playbook_run_id}_{i}_{random.randint(1000, 9999)}"

                # Check if exists
                stmt = select(ActionRun).where(ActionRun.action_run_id == action_run_id)
                result = await session.execute(stmt)
                if result.scalar_one_or_none():
                    continue

                action = ActionRun(
                    action_run_id=action_run_id,
                    playbook_run_id=run.id,
                    action_name=action_name,
                    app_name=app_name,
                    status=action_status,
                    duration_seconds=action_duration,
                    error_message="Action timed out" if action_status == "failure" else None,
                    event_time=action_time,
                    index_time=action_time + timedelta(seconds=random.randint(1, 10)) if action_time else None,
                )
                session.add(action)
                actions.append(action)

        await session.commit()
        return actions


async def create_detection_links(playbooks: list) -> int:
    """Link playbooks to existing detections based on keywords."""
    async with async_session() as session:
        # Get all detections
        stmt = select(Detection)
        result = await session.execute(stmt)
        detections = result.scalars().all()

        if not detections:
            print("No detections found to link.")
            return 0

        links_created = 0

        # Simple keyword matching
        keyword_map = {
            "malware": ["investigate_malware"],
            "brute": ["brute_force_response", "credential_compromise"],
            "phishing": ["phishing_response"],
            "credential": ["credential_compromise"],
            "exfil": ["data_exfil_response"],
            "firewall": ["block_ip_firewall"],
            "endpoint": ["isolate_endpoint"],
        }

        for detection in detections:
            det_name_lower = detection.name.lower()

            # Find matching playbooks
            matching_pb_ids = set()
            for keyword, pb_ids in keyword_map.items():
                if keyword in det_name_lower:
                    matching_pb_ids.update(pb_ids)

            # Also randomly link some playbooks
            if random.random() < 0.3:
                random_pb = random.choice(playbooks)
                matching_pb_ids.add(random_pb.playbook_id)

            for pb_id in matching_pb_ids:
                # Find playbook
                pb_stmt = select(Playbook).where(Playbook.playbook_id == pb_id)
                pb_result = await session.execute(pb_stmt)
                playbook = pb_result.scalar_one_or_none()

                if not playbook:
                    continue

                # Check if link exists
                link_stmt = select(DetectionPlaybookLink).where(
                    DetectionPlaybookLink.detection_id == detection.id,
                    DetectionPlaybookLink.playbook_id == playbook.id,
                )
                link_result = await session.execute(link_stmt)
                if link_result.scalar_one_or_none():
                    continue

                link = DetectionPlaybookLink(
                    detection_id=detection.id,
                    playbook_id=playbook.id,
                    link_type="auto",
                    link_evidence=json.dumps({"matched_keyword": True}),
                )
                session.add(link)
                links_created += 1

        await session.commit()
        return links_created


async def main():
    """Seed the database with SOAR fixture data."""
    print("=" * 60)
    print("SOAR Fixture Data Seeder")
    print("=" * 60)

    print("\n1. Creating playbooks...")
    playbooks = await create_playbooks()
    print(f"   Created/found {len(playbooks)} playbooks")

    print("\n2. Creating playbook runs...")
    runs = await create_playbook_runs(playbooks)
    print(f"   Created {len(runs)} playbook runs")

    print("\n3. Creating action runs...")
    actions = await create_action_runs(runs)
    print(f"   Created {len(actions)} action runs")

    print("\n4. Creating detection-playbook links...")
    links = await create_detection_links(playbooks)
    print(f"   Created {links} detection-playbook links")

    print("\n" + "=" * 60)
    print("Seeding complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
