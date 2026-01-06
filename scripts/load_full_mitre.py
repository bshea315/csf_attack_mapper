#!/usr/bin/env python3
"""Load full MITRE ATT&CK Enterprise techniques from STIX data."""
import asyncio
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from sqlalchemy import select, delete
from app.models.database import engine, async_session, Base
from app.models.mitre import MitreTechnique


def parse_stix_data(stix_path: Path):
    """Parse STIX bundle and extract techniques."""
    print(f"Loading STIX data from {stix_path}...")
    with open(stix_path, 'r') as f:
        data = json.load(f)

    objects = data.get('objects', [])

    # Extract techniques (attack-pattern type)
    techniques_raw = [o for o in objects if o.get('type') == 'attack-pattern']

    # Extract relationships for parent-child mapping
    relationships = [o for o in objects if o.get('type') == 'relationship']
    subtechnique_rels = [r for r in relationships if r.get('relationship_type') == 'subtechnique-of']

    # Build STIX ID -> technique ID mapping
    stix_to_tech_id = {}
    for t in techniques_raw:
        stix_id = t.get('id')
        ext_refs = t.get('external_references', [])
        for ref in ext_refs:
            if ref.get('source_name') == 'mitre-attack':
                tech_id = ref.get('external_id')
                stix_to_tech_id[stix_id] = tech_id
                break

    # Build parent mapping from relationships
    # sub_stix_id -> parent_tech_id
    parent_map = {}
    for rel in subtechnique_rels:
        source_stix = rel.get('source_ref')  # sub-technique
        target_stix = rel.get('target_ref')  # parent technique
        if source_stix and target_stix:
            parent_tech_id = stix_to_tech_id.get(target_stix)
            if parent_tech_id:
                parent_map[source_stix] = parent_tech_id

    # Parse techniques
    techniques = []
    skipped = 0

    for t in techniques_raw:
        # Skip deprecated techniques
        if t.get('x_mitre_deprecated', False):
            skipped += 1
            continue

        # Skip revoked techniques
        if t.get('revoked', False):
            skipped += 1
            continue

        stix_id = t.get('id')

        # Get technique ID from external_references
        ext_refs = t.get('external_references', [])
        tech_id = None
        url = None
        for ref in ext_refs:
            if ref.get('source_name') == 'mitre-attack':
                tech_id = ref.get('external_id')
                url = ref.get('url')
                break

        if not tech_id:
            skipped += 1
            continue

        # Get tactics from kill_chain_phases
        tactics = [p.get('phase_name') for p in t.get('kill_chain_phases', [])]

        # Determine if sub-technique and get parent
        is_subtechnique = t.get('x_mitre_is_subtechnique', False)
        parent_technique_id = parent_map.get(stix_id) if is_subtechnique else None

        # If it's a sub-technique but we couldn't find parent via relationship,
        # try to parse from the ID (e.g., T1059.001 -> T1059)
        if is_subtechnique and not parent_technique_id and '.' in tech_id:
            parent_technique_id = tech_id.split('.')[0]

        # Get platforms
        platforms = t.get('x_mitre_platforms', [])

        # Get data sources from x_mitre_data_sources (legacy) or will need to look at relationships
        data_sources = t.get('x_mitre_data_sources', [])

        techniques.append({
            'id': tech_id,
            'name': t.get('name'),
            'description': t.get('description', '')[:5000] if t.get('description') else None,  # Truncate long descriptions
            'tactics': tactics,
            'platforms': platforms,
            'data_sources': data_sources,
            'is_subtechnique': is_subtechnique,
            'parent_technique_id': parent_technique_id,
            'url': url,
        })

    # Sort by technique ID for cleaner output
    techniques.sort(key=lambda x: x['id'])

    print(f"Parsed {len(techniques)} techniques (skipped {skipped} deprecated/revoked)")

    # Count by type
    parents = [t for t in techniques if not t['is_subtechnique']]
    subs = [t for t in techniques if t['is_subtechnique']]
    print(f"  Parent techniques: {len(parents)}")
    print(f"  Sub-techniques: {len(subs)}")

    return techniques


async def load_techniques_to_db(techniques: list):
    """Load techniques into database, replacing existing data."""
    print("\nLoading techniques into database...")

    async with async_session() as session:
        # Count existing
        count_stmt = select(MitreTechnique)
        count_result = await session.execute(count_stmt)
        existing_count = len(count_result.scalars().all())
        print(f"Existing techniques in DB: {existing_count}")

        # Delete existing techniques (to replace with fresh data)
        print("Clearing existing techniques...")
        await session.execute(delete(MitreTechnique))
        await session.commit()

        # Insert new techniques in batches
        print("Inserting new techniques...")
        batch_size = 100
        inserted = 0

        for i in range(0, len(techniques), batch_size):
            batch = techniques[i:i + batch_size]

            for tech in batch:
                technique = MitreTechnique(
                    id=tech['id'],
                    name=tech['name'],
                    description=tech['description'],
                    tactics=json.dumps(tech['tactics']),
                    platforms=json.dumps(tech['platforms']),
                    data_sources=json.dumps(tech['data_sources']),
                    is_subtechnique=tech['is_subtechnique'],
                    parent_technique_id=tech['parent_technique_id'],
                    url=tech['url'],
                )
                session.add(technique)

            await session.commit()
            inserted += len(batch)
            print(f"  Inserted {inserted}/{len(techniques)} techniques...")

        print(f"\nSuccessfully loaded {inserted} techniques into database!")

        # Verify counts
        verify_stmt = select(MitreTechnique)
        verify_result = await session.execute(verify_stmt)
        final_count = len(verify_result.scalars().all())
        print(f"Final technique count in DB: {final_count}")


async def main():
    """Main entry point."""
    print("=" * 60)
    print("MITRE ATT&CK Enterprise Data Loader")
    print("=" * 60)

    # Path to STIX data
    stix_path = Path(__file__).parent.parent / "data" / "enterprise-attack.json"

    if not stix_path.exists():
        print(f"ERROR: STIX file not found at {stix_path}")
        print("Download it first using:")
        print('  curl -L -o data/enterprise-attack.json "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"')
        sys.exit(1)

    # Parse STIX data
    techniques = parse_stix_data(stix_path)

    # Load into database
    await load_techniques_to_db(techniques)

    print("=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
