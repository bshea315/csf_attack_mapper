#!/usr/bin/env python3
"""Recompute CSF impacts for all detections based on their MITRE mappings."""
import asyncio
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from sqlalchemy import select, delete, func
from sqlalchemy.orm import selectinload
from app.models.database import async_session
from app.models.detection import Detection
from app.models.mitre import DetectionMitreMapping
from app.models.csf import DetectionCsfImpact, MitreToCsfMapping
from app.services.csf_calculator import CSFCalculator


async def recompute_all_csf_impacts():
    """Recompute CSF impacts for all detections."""
    print("=" * 60)
    print("CSF Impact Recomputation")
    print("=" * 60)

    csf_calculator = CSFCalculator()
    summary = csf_calculator.get_crosswalk_summary()
    print(f"\nCrosswalk loaded:")
    print(f"  Techniques in crosswalk: {summary['total_techniques']}")
    print(f"  CSF categories: {summary['total_csf_categories']}")
    print(f"  Functions covered: {', '.join(summary['functions_covered'])}")
    print(f"  Total mappings: {summary['total_mappings']}")

    async with async_session() as session:
        # Clear existing CSF impacts
        print("\nClearing existing CSF impacts...")
        await session.execute(delete(DetectionCsfImpact))
        await session.commit()

        # Get all detections with their MITRE mappings
        print("Loading detections and MITRE mappings...")
        stmt = select(Detection).options(
            selectinload(Detection.mitre_mappings)
        )
        result = await session.execute(stmt)
        detections = result.scalars().all()

        print(f"Found {len(detections)} detections")

        # Process each detection
        total_impacts = 0
        detections_with_impacts = 0

        for detection in detections:
            # Get accepted MITRE mappings
            accepted_mappings = [
                m for m in detection.mitre_mappings
                if m.is_accepted
            ]

            if not accepted_mappings:
                continue

            # Build technique mapping list for CSF calculator
            technique_mappings = [
                {'technique_id': m.technique_id, 'confidence': m.confidence}
                for m in accepted_mappings
            ]

            # Calculate CSF impacts
            csf_result = csf_calculator.calculate_impacts(technique_mappings)

            if csf_result.impacts:
                detections_with_impacts += 1
                for impact in csf_result.impacts:
                    csf_impact = DetectionCsfImpact(
                        detection_id=detection.id,
                        csf_id=impact.csf_id,
                        impact_score=impact.impact_score,
                        contributing_techniques=json.dumps(impact.contributing_techniques),
                    )
                    session.add(csf_impact)
                    total_impacts += 1

        await session.commit()

        print(f"\n=== Results ===")
        print(f"  Detections processed: {len(detections)}")
        print(f"  Detections with CSF impacts: {detections_with_impacts}")
        print(f"  Total CSF impacts created: {total_impacts}")

        # Verify with query
        count_stmt = select(func.count(DetectionCsfImpact.id))
        count_result = await session.execute(count_stmt)
        final_count = count_result.scalar_one()
        print(f"  Final CSF impacts in DB: {final_count}")

        # Show function coverage
        print("\n=== CSF Function Coverage ===")
        function_stmt = select(
            DetectionCsfImpact.csf_id,
            func.count(DetectionCsfImpact.id).label('count'),
            func.avg(DetectionCsfImpact.impact_score).label('avg_score')
        ).group_by(DetectionCsfImpact.csf_id)
        function_result = await session.execute(function_stmt)

        for row in function_result.all():
            print(f"  {row.csf_id}: {row.count} impacts, avg score: {row.avg_score:.3f}")


async def main():
    """Main entry point."""
    await recompute_all_csf_impacts()
    print("\n" + "=" * 60)
    print("Done! CSF impacts have been recomputed.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
