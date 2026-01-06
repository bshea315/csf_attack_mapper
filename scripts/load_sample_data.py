#!/usr/bin/env python3
"""
Load sample detection data from CSV file.

This script loads sample_detections.csv through the ingest pipeline,
which automatically:
- Parses SPL queries
- Maps to MITRE ATT&CK techniques
- Calculates CSF impact scores
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.models.database import async_session
from app.services.ingest_pipeline import IngestPipeline


async def load_sample_detections():
    """Load sample detections from CSV file."""
    sample_file = Path(__file__).parent.parent / "sample_data" / "sample_detections.csv"

    if not sample_file.exists():
        print(f"Error: Sample file not found at {sample_file}")
        return False

    print(f"Loading sample detections from {sample_file}...")

    with open(sample_file, 'r') as f:
        csv_content = f.read()

    async with async_session() as db:
        pipeline = IngestPipeline(db, use_enhanced_mapper=True)
        result = await pipeline.ingest_csv(
            content=csv_content,
            filename="sample_detections.csv",
            user_id=1,  # Admin user
        )

    print(f"\nResults:")
    print(f"  Total records:  {result.total}")
    print(f"  Successful:     {result.successful}")
    print(f"  Failed:         {result.failed}")

    if result.warnings:
        print(f"\nWarnings:")
        for warning in result.warnings:
            print(f"  - {warning}")

    if result.errors:
        print(f"\nErrors:")
        for error in result.errors:
            print(f"  - {error}")

    return result.failed == 0


async def main():
    """Run sample data loading."""
    print("=" * 60)
    print("Loading Sample Detection Data")
    print("=" * 60)

    success = await load_sample_detections()

    print("\n" + "=" * 60)
    if success:
        print("Sample data loaded successfully!")
    else:
        print("Sample data loading completed with errors.")
    print("=" * 60)

    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
