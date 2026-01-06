#!/usr/bin/env python3
"""
Add Splunk ES and SOAR integration tables to existing database.

This script adds the new tables without affecting existing data:
- splunk_config
- playbooks
- playbook_runs
- action_runs
- detection_playbook_links

It also adds new columns to the detections table if they don't exist.
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from sqlalchemy import text, inspect
from sqlalchemy.ext.asyncio import AsyncConnection
from app.models.database import engine, Base
# Import all models to register them with Base
from app.models import (
    SplunkConfig,
    Playbook,
    PlaybookRun,
    ActionRun,
    DetectionPlaybookLink,
    Detection,
)


async def table_exists(conn: AsyncConnection, table_name: str) -> bool:
    """Check if a table exists in the database."""
    result = await conn.execute(
        text(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
    )
    return result.fetchone() is not None


async def column_exists(conn: AsyncConnection, table_name: str, column_name: str) -> bool:
    """Check if a column exists in a table."""
    result = await conn.execute(text(f"PRAGMA table_info({table_name})"))
    columns = [row[1] for row in result.fetchall()]
    return column_name in columns


async def add_detection_columns(conn: AsyncConnection):
    """Add new columns to detections table for Splunk ES integration."""
    columns_to_add = [
        ("source_type", "VARCHAR(20) DEFAULT 'manual'"),
        ("splunk_savedsearch_id", "VARCHAR(255)"),
        ("splunk_app", "VARCHAR(100)"),
        ("raw_savedsearch_payload", "TEXT"),
    ]

    for col_name, col_def in columns_to_add:
        if not await column_exists(conn, "detections", col_name):
            print(f"  Adding column: detections.{col_name}")
            await conn.execute(text(f"ALTER TABLE detections ADD COLUMN {col_name} {col_def}"))
        else:
            print(f"  Column already exists: detections.{col_name}")


async def add_playbook_columns(conn: AsyncConnection):
    """Add new columns to playbooks table for time savings metrics."""
    columns_to_add = [
        ("category", "VARCHAR(100)"),
        ("time_saved_minutes", "FLOAT DEFAULT 0"),
        ("avg_manual_time_minutes", "FLOAT"),
    ]

    for col_name, col_def in columns_to_add:
        if not await column_exists(conn, "playbooks", col_name):
            print(f"  Adding column: playbooks.{col_name}")
            await conn.execute(text(f"ALTER TABLE playbooks ADD COLUMN {col_name} {col_def}"))
        else:
            print(f"  Column already exists: playbooks.{col_name}")


async def create_new_tables(conn: AsyncConnection):
    """Create new tables for Splunk/SOAR integration."""
    new_tables = [
        "splunk_config",
        "playbooks",
        "playbook_runs",
        "action_runs",
        "detection_playbook_links",
    ]

    for table_name in new_tables:
        if await table_exists(conn, table_name):
            print(f"  Table already exists: {table_name}")
        else:
            print(f"  Creating table: {table_name}")

    # Create all tables (will skip existing ones)
    await conn.run_sync(Base.metadata.create_all)


async def main():
    """Run the migration."""
    print("=" * 60)
    print("Splunk ES + SOAR Integration - Database Migration")
    print("=" * 60)

    async with engine.begin() as conn:
        # Check if detections table exists (basic sanity check)
        if not await table_exists(conn, "detections"):
            print("ERROR: 'detections' table not found. Run init_db.py first.")
            return

        print("\n1. Adding new columns to detections table...")
        await add_detection_columns(conn)

        print("\n2. Creating new tables...")
        await create_new_tables(conn)

        print("\n3. Adding new columns to playbooks table...")
        if await table_exists(conn, "playbooks"):
            await add_playbook_columns(conn)
        else:
            print("  Playbooks table not found (will be created with columns)")

        await conn.commit()

    print("\n" + "=" * 60)
    print("Migration complete!")
    print("=" * 60)
    print("\nNew capabilities added:")
    print("  - Splunk configuration storage (with encrypted secrets)")
    print("  - SOAR playbook tracking")
    print("  - Playbook run history")
    print("  - Action run details")
    print("  - Detection ↔ Playbook linking")


if __name__ == "__main__":
    asyncio.run(main())
