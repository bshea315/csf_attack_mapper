#!/usr/bin/env python3
"""Recompute CSF impacts for all detections based on their MITRE mappings.

This script uses the mitre_to_csf_mappings table in the database (not the YAML file)
to compute CSF impacts for all detections.
"""
import asyncio
import json
import sys
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from sqlalchemy import select, delete, func
from sqlalchemy.orm import selectinload
from app.models.database import async_session
from app.models.detection import Detection
from app.models.mitre import DetectionMitreMapping, MitreTechnique
from app.models.csf import DetectionCsfImpact, MitreToCsfMapping


# CSF 2.0 Functions
CSF_FUNCTIONS = ['GOVERN', 'IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER']

# Map CSF category prefix to function
CSF_CATEGORY_TO_FUNCTION = {
    'GV': 'GOVERN',
    'ID': 'IDENTIFY',
    'PR': 'PROTECT',
    'DE': 'DETECT',
    'RS': 'RESPOND',
    'RC': 'RECOVER',
}


def get_function_from_category(category: str) -> str:
    """Get CSF function from category prefix."""
    prefix = category.split('.')[0] if '.' in category else category[:2]
    return CSF_CATEGORY_TO_FUNCTION.get(prefix, 'DETECT')


@dataclass
class CSFImpact:
    """CSF impact for a category."""
    csf_id: str
    function: str
    impact_score: float = 0.0
    contributing_techniques: List[str] = field(default_factory=list)


async def load_csf_crosswalk(session) -> Dict[str, List[Dict]]:
    """Load all MITRE-to-CSF mappings from database."""
    stmt = select(MitreToCsfMapping)
    result = await session.execute(stmt)
    mappings = result.scalars().all()

    crosswalk = defaultdict(list)
    for m in mappings:
        crosswalk[m.technique_id].append({
            'csf_id': m.csf_id,
            'weight': m.weight,
            'rationale': m.rationale or '',
        })

    return dict(crosswalk)


def calculate_csf_impacts(
    technique_mappings: List[Dict],
    crosswalk: Dict[str, List[Dict]],
) -> List[CSFImpact]:
    """Calculate CSF impacts from technique mappings."""
    csf_impacts: Dict[str, CSFImpact] = {}

    for mapping in technique_mappings:
        technique_id = mapping['technique_id']
        confidence = mapping['confidence']

        # Get CSF mappings for this technique
        csf_mappings = crosswalk.get(technique_id, [])

        # Also check parent technique if sub-technique
        if '.' in technique_id:
            parent_id = technique_id.split('.')[0]
            csf_mappings = csf_mappings + crosswalk.get(parent_id, [])

        for csf_mapping in csf_mappings:
            csf_id = csf_mapping['csf_id']
            weight = csf_mapping['weight']

            # Calculate impact: confidence * weight
            impact = confidence * weight

            if csf_id not in csf_impacts:
                function = get_function_from_category(csf_id)
                csf_impacts[csf_id] = CSFImpact(
                    csf_id=csf_id,
                    function=function,
                )

            # Only count each technique once per CSF category
            if technique_id not in csf_impacts[csf_id].contributing_techniques:
                csf_impacts[csf_id].impact_score += impact
                csf_impacts[csf_id].contributing_techniques.append(technique_id)

    # Cap impact scores at 1.0
    for csf_id, impact in csf_impacts.items():
        impact.impact_score = min(1.0, impact.impact_score)

    return list(csf_impacts.values())


async def recompute_all_csf_impacts():
    """Recompute CSF impacts for all detections."""
    print("=" * 60)
    print("CSF Impact Recomputation (using database mappings)")
    print("=" * 60)

    async with async_session() as session:
        # Load crosswalk from database
        print("\nLoading MITRE-to-CSF crosswalk from database...")
        crosswalk = await load_csf_crosswalk(session)
        print(f"  Techniques in crosswalk: {len(crosswalk)}")
        print(f"  Total mappings: {sum(len(m) for m in crosswalk.values())}")

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
        function_stats = defaultdict(int)

        for detection in detections:
            # Get accepted MITRE mappings
            accepted_mappings = [
                {'technique_id': m.technique_id, 'confidence': m.confidence}
                for m in detection.mitre_mappings
                if m.is_accepted
            ]

            if not accepted_mappings:
                continue

            # Calculate CSF impacts
            impacts = calculate_csf_impacts(accepted_mappings, crosswalk)

            if impacts:
                detections_with_impacts += 1
                for impact in impacts:
                    csf_impact = DetectionCsfImpact(
                        detection_id=detection.id,
                        csf_id=impact.csf_id,
                        impact_score=impact.impact_score,
                        contributing_techniques=json.dumps(impact.contributing_techniques),
                    )
                    session.add(csf_impact)
                    total_impacts += 1
                    function_stats[impact.function] += 1

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
        for func_name in CSF_FUNCTIONS:
            count = function_stats.get(func_name, 0)
            print(f"  {func_name}: {count} impacts")

        # Show category breakdown
        print("\n=== CSF Category Coverage ===")
        cat_stmt = select(
            DetectionCsfImpact.csf_id,
            func.count(DetectionCsfImpact.id).label('count'),
            func.avg(DetectionCsfImpact.impact_score).label('avg_score')
        ).group_by(DetectionCsfImpact.csf_id)
        cat_result = await session.execute(cat_stmt)

        for row in cat_result.all():
            print(f"  {row.csf_id}: {row.count} detections, avg score: {row.avg_score:.3f}")


async def main():
    """Main entry point."""
    await recompute_all_csf_impacts()
    print("\n" + "=" * 60)
    print("Done! CSF impacts have been recomputed.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
