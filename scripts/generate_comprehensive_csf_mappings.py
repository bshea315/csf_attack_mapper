#!/usr/bin/env python3
"""
Generate comprehensive MITRE ATT&CK to NIST CSF 2.0 mappings.

This script creates mappings for ALL techniques based on:
1. Tactic-based default mappings (industry best practice alignment)
2. Technique-specific overrides for higher accuracy

The mapping logic follows the relationship between:
- MITRE ATT&CK Tactics (adversary behavior phases)
- NIST CSF 2.0 Functions (security program functions)

Mapping Rationale:
- GOVERN: Risk management, organizational context, supply chain
- IDENTIFY: Asset management, risk assessment, understanding environment
- PROTECT: Access control, awareness training, data security, platform security
- DETECT: Continuous monitoring, anomaly detection, adverse event analysis
- RESPOND: Incident response, analysis, mitigation, communications
- RECOVER: Recovery planning, improvements, communications
"""
import asyncio
import json
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from sqlalchemy import select, delete, func
from app.models.database import async_session
from app.models.mitre import MitreTechnique
from app.models.csf import MitreToCsfMapping, CsfCategory

# =============================================================================
# TACTIC TO CSF FUNCTION MAPPINGS
# =============================================================================
# Based on industry best practices and the relationship between adversary
# behaviors and defensive security functions.

TACTIC_TO_CSF = {
    # Pre-Attack Tactics - Focus on governance and identification
    'reconnaissance': [
        {'function': 'IDENTIFY', 'category': 'ID.RA', 'weight': 0.5,
         'rationale': 'Reconnaissance awareness relates to risk assessment and threat identification.'},
        {'function': 'DETECT', 'category': 'DE.CM', 'weight': 0.4,
         'rationale': 'External reconnaissance attempts may be detected through monitoring.'},
    ],
    'resource-development': [
        {'function': 'GOVERN', 'category': 'GV.SC', 'weight': 0.5,
         'rationale': 'Supply chain and third-party risk governance.'},
        {'function': 'IDENTIFY', 'category': 'ID.RA', 'weight': 0.4,
         'rationale': 'Understanding threat landscape and attacker capabilities.'},
    ],

    # Initial Compromise - Protection and Detection focus
    'initial-access': [
        {'function': 'PROTECT', 'category': 'PR.AA', 'weight': 0.6,
         'rationale': 'Access control and authentication prevent unauthorized entry.'},
        {'function': 'DETECT', 'category': 'DE.CM', 'weight': 0.5,
         'rationale': 'Continuous monitoring detects initial compromise attempts.'},
        {'function': 'PROTECT', 'category': 'PR.AT', 'weight': 0.4,
         'rationale': 'Security awareness training helps prevent social engineering.'},
    ],

    # Execution - Detection and Protection
    'execution': [
        {'function': 'DETECT', 'category': 'DE.CM', 'weight': 0.7,
         'rationale': 'Endpoint and process monitoring detects malicious execution.'},
        {'function': 'PROTECT', 'category': 'PR.PS', 'weight': 0.5,
         'rationale': 'Platform security controls can prevent unauthorized execution.'},
    ],

    # Persistence - Detection focused
    'persistence': [
        {'function': 'DETECT', 'category': 'DE.CM', 'weight': 0.7,
         'rationale': 'Continuous monitoring detects persistence mechanisms.'},
        {'function': 'PROTECT', 'category': 'PR.PS', 'weight': 0.5,
         'rationale': 'Configuration management prevents unauthorized changes.'},
        {'function': 'DETECT', 'category': 'DE.AE', 'weight': 0.4,
         'rationale': 'Anomaly detection identifies new persistence artifacts.'},
    ],

    # Privilege Escalation - Protection and Detection
    'privilege-escalation': [
        {'function': 'DETECT', 'category': 'DE.CM', 'weight': 0.7,
         'rationale': 'Monitoring detects privilege escalation attempts.'},
        {'function': 'PROTECT', 'category': 'PR.AA', 'weight': 0.6,
         'rationale': 'Least privilege and access controls prevent escalation.'},
        {'function': 'PROTECT', 'category': 'PR.PS', 'weight': 0.4,
         'rationale': 'Platform hardening reduces escalation paths.'},
    ],

    # Defense Evasion - Primarily Detection
    'defense-evasion': [
        {'function': 'DETECT', 'category': 'DE.CM', 'weight': 0.7,
         'rationale': 'Defense evasion detection requires robust monitoring.'},
        {'function': 'DETECT', 'category': 'DE.AE', 'weight': 0.6,
         'rationale': 'Anomaly detection identifies evasion techniques.'},
        {'function': 'PROTECT', 'category': 'PR.DS', 'weight': 0.4,
         'rationale': 'Data integrity protections detect tampering.'},
    ],

    # Credential Access - Protection and Detection
    'credential-access': [
        {'function': 'DETECT', 'category': 'DE.CM', 'weight': 0.7,
         'rationale': 'Credential theft attempts require continuous monitoring.'},
        {'function': 'PROTECT', 'category': 'PR.AA', 'weight': 0.6,
         'rationale': 'Strong authentication and credential protection.'},
        {'function': 'PROTECT', 'category': 'PR.DS', 'weight': 0.5,
         'rationale': 'Data security protects stored credentials.'},
    ],

    # Discovery - Detection focused
    'discovery': [
        {'function': 'DETECT', 'category': 'DE.CM', 'weight': 0.6,
         'rationale': 'Monitoring detects internal reconnaissance.'},
        {'function': 'DETECT', 'category': 'DE.AE', 'weight': 0.5,
         'rationale': 'Anomaly detection for unusual enumeration activity.'},
    ],

    # Lateral Movement - Detection and Protection
    'lateral-movement': [
        {'function': 'DETECT', 'category': 'DE.CM', 'weight': 0.7,
         'rationale': 'Network and endpoint monitoring for lateral movement.'},
        {'function': 'PROTECT', 'category': 'PR.AA', 'weight': 0.6,
         'rationale': 'Network segmentation and access controls limit movement.'},
        {'function': 'PROTECT', 'category': 'PR.IR', 'weight': 0.4,
         'rationale': 'Network infrastructure security.'},
    ],

    # Collection - Detection and Protection
    'collection': [
        {'function': 'DETECT', 'category': 'DE.CM', 'weight': 0.6,
         'rationale': 'Monitoring for data collection activities.'},
        {'function': 'PROTECT', 'category': 'PR.DS', 'weight': 0.6,
         'rationale': 'Data loss prevention and access controls.'},
    ],

    # Command and Control - Detection focused
    'command-and-control': [
        {'function': 'DETECT', 'category': 'DE.CM', 'weight': 0.7,
         'rationale': 'Network monitoring for C2 communications.'},
        {'function': 'DETECT', 'category': 'DE.AE', 'weight': 0.6,
         'rationale': 'Anomaly detection for beaconing and C2 traffic.'},
        {'function': 'PROTECT', 'category': 'PR.IR', 'weight': 0.4,
         'rationale': 'Network controls can block C2 channels.'},
    ],

    # Exfiltration - Detection and Protection
    'exfiltration': [
        {'function': 'DETECT', 'category': 'DE.CM', 'weight': 0.7,
         'rationale': 'DLP and network monitoring for data exfiltration.'},
        {'function': 'PROTECT', 'category': 'PR.DS', 'weight': 0.6,
         'rationale': 'Data protection and DLP controls.'},
        {'function': 'PROTECT', 'category': 'PR.IR', 'weight': 0.4,
         'rationale': 'Network controls limit exfiltration paths.'},
    ],

    # Impact - Response and Recovery focus
    'impact': [
        {'function': 'DETECT', 'category': 'DE.CM', 'weight': 0.6,
         'rationale': 'Detect destructive or disruptive activities.'},
        {'function': 'RESPOND', 'category': 'RS.AN', 'weight': 0.6,
         'rationale': 'Incident analysis and response to impact events.'},
        {'function': 'RECOVER', 'category': 'RC.RP', 'weight': 0.6,
         'rationale': 'Recovery planning for impact events.'},
        {'function': 'PROTECT', 'category': 'PR.DS', 'weight': 0.5,
         'rationale': 'Backups and integrity protections.'},
    ],
}

# CSF 2.0 Subcategory definitions for mapping
CSF_SUBCATEGORIES = {
    # GOVERN
    'GV.OC': 'Organizational Context',
    'GV.RM': 'Risk Management Strategy',
    'GV.RR': 'Roles, Responsibilities, and Authorities',
    'GV.PO': 'Policy',
    'GV.OV': 'Oversight',
    'GV.SC': 'Cybersecurity Supply Chain Risk Management',

    # IDENTIFY
    'ID.AM': 'Asset Management',
    'ID.RA': 'Risk Assessment',
    'ID.IM': 'Improvement',

    # PROTECT
    'PR.AA': 'Identity Management, Authentication, and Access Control',
    'PR.AT': 'Awareness and Training',
    'PR.DS': 'Data Security',
    'PR.PS': 'Platform Security',
    'PR.IR': 'Technology Infrastructure Resilience',

    # DETECT
    'DE.CM': 'Continuous Monitoring',
    'DE.AE': 'Adverse Event Analysis',

    # RESPOND
    'RS.MA': 'Incident Management',
    'RS.AN': 'Incident Analysis',
    'RS.CO': 'Incident Response Reporting and Communication',
    'RS.MI': 'Incident Mitigation',

    # RECOVER
    'RC.RP': 'Incident Recovery Plan Execution',
    'RC.CO': 'Incident Recovery Communication',
}


def normalize_tactic(tactic: str) -> str:
    """Normalize tactic name to match our mapping keys."""
    return tactic.lower().replace(' ', '-').replace('_', '-')


async def generate_mappings():
    """Generate comprehensive MITRE to CSF mappings for all techniques."""
    print("=" * 70)
    print("Comprehensive MITRE ATT&CK to NIST CSF 2.0 Mapping Generator")
    print("=" * 70)

    async with async_session() as session:
        # Get all techniques
        stmt = select(MitreTechnique)
        result = await session.execute(stmt)
        techniques = result.scalars().all()

        print(f"\nTotal techniques in database: {len(techniques)}")

        # Analyze tactic coverage
        tactic_counts = defaultdict(int)
        techniques_by_tactic = defaultdict(list)

        for tech in techniques:
            tactics = json.loads(tech.tactics) if tech.tactics else []
            for tactic in tactics:
                norm_tactic = normalize_tactic(tactic)
                tactic_counts[norm_tactic] += 1
                techniques_by_tactic[norm_tactic].append(tech)

        print("\nTechniques per tactic:")
        for tactic in sorted(tactic_counts.keys()):
            mapped = "✓" if tactic in TACTIC_TO_CSF else "✗"
            print(f"  {mapped} {tactic}: {tactic_counts[tactic]}")

        # Generate mappings
        print("\nGenerating CSF mappings...")

        mappings = []
        techniques_mapped = 0
        techniques_without_tactic = 0

        for tech in techniques:
            tactics = json.loads(tech.tactics) if tech.tactics else []

            if not tactics:
                techniques_without_tactic += 1
                continue

            # Generate mappings for each tactic the technique belongs to
            tech_csf_mappings = {}

            for tactic in tactics:
                norm_tactic = normalize_tactic(tactic)
                csf_mappings = TACTIC_TO_CSF.get(norm_tactic, [])

                for csf in csf_mappings:
                    csf_key = csf['category']
                    # Use highest weight if multiple tactics map to same CSF
                    if csf_key not in tech_csf_mappings or csf['weight'] > tech_csf_mappings[csf_key]['weight']:
                        tech_csf_mappings[csf_key] = {
                            'technique_id': tech.id,
                            'csf_id': csf_key,
                            'function': csf['function'],
                            'weight': csf['weight'],
                            'rationale': csf['rationale'],
                            'source_tactic': norm_tactic,
                        }

            if tech_csf_mappings:
                techniques_mapped += 1
                mappings.extend(tech_csf_mappings.values())

        print(f"\nMapping Statistics:")
        print(f"  Techniques mapped: {techniques_mapped}")
        print(f"  Techniques without tactics: {techniques_without_tactic}")
        print(f"  Total CSF mappings generated: {len(mappings)}")

        # Aggregate by CSF category
        csf_category_counts = defaultdict(int)
        csf_function_counts = defaultdict(int)
        for m in mappings:
            csf_category_counts[m['csf_id']] += 1
            csf_function_counts[m['function']] += 1

        print("\nMappings by CSF Function:")
        for func in ['GOVERN', 'IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER']:
            print(f"  {func}: {csf_function_counts.get(func, 0)}")

        print("\nMappings by CSF Category (top 15):")
        for cat, count in sorted(csf_category_counts.items(), key=lambda x: -x[1])[:15]:
            name = CSF_SUBCATEGORIES.get(cat, 'Unknown')
            print(f"  {cat} ({name}): {count}")

        return mappings, techniques


async def save_to_database(mappings: List[Dict]):
    """Save mappings to the database."""
    print("\n" + "=" * 70)
    print("Saving mappings to database...")

    async with async_session() as session:
        # Clear existing mappings
        print("Clearing existing MITRE-to-CSF mappings...")
        await session.execute(delete(MitreToCsfMapping))
        await session.commit()

        # Insert new mappings in batches
        print("Inserting new mappings...")
        batch_size = 100
        inserted = 0

        for i in range(0, len(mappings), batch_size):
            batch = mappings[i:i + batch_size]
            for m in batch:
                mapping = MitreToCsfMapping(
                    technique_id=m['technique_id'],
                    csf_id=m['csf_id'],
                    weight=m['weight'],
                    rationale=m['rationale'],
                    source='tactic-based-auto',
                )
                session.add(mapping)

            await session.commit()
            inserted += len(batch)
            print(f"  Inserted {inserted}/{len(mappings)} mappings...")

        # Verify
        count_stmt = select(func.count(MitreToCsfMapping.id))
        count_result = await session.execute(count_stmt)
        final_count = count_result.scalar()
        print(f"\nFinal mapping count in database: {final_count}")


def save_to_yaml(mappings: List[Dict], output_path: Path):
    """Save mappings to YAML file for reference."""
    print(f"\nSaving to YAML: {output_path}")

    yaml_data = {
        'version': 2,
        'description': 'Comprehensive MITRE ATT&CK to NIST CSF 2.0 mappings (auto-generated from tactics)',
        'generation_method': 'tactic-based',
        'mappings': [
            {
                'technique_id': m['technique_id'],
                'csf': {
                    'function': m['function'],
                    'category': m['csf_id'],
                },
                'weight': m['weight'],
                'rationale': m['rationale'],
                'source_tactic': m.get('source_tactic', 'unknown'),
            }
            for m in mappings
        ]
    }

    with open(output_path, 'w') as f:
        yaml.dump(yaml_data, f, default_flow_style=False, sort_keys=False)

    print(f"Saved {len(mappings)} mappings to YAML")


async def main():
    """Main entry point."""
    # Generate mappings
    mappings, techniques = await generate_mappings()

    # Save to database
    await save_to_database(mappings)

    # Save to YAML for reference
    yaml_path = Path(__file__).parent.parent / "mappings" / "mitre_to_csf_comprehensive.yml"
    save_to_yaml(mappings, yaml_path)

    print("\n" + "=" * 70)
    print("Comprehensive CSF mappings generation complete!")
    print(f"  Techniques covered: {len(set(m['technique_id'] for m in mappings))}")
    print(f"  Total mappings: {len(mappings)}")
    print("=" * 70)

    # Now recompute CSF impacts for detections
    print("\nRecomputing CSF impacts for all detections...")
    import subprocess
    result = subprocess.run(
        ['python', str(Path(__file__).parent / 'recompute_csf_impacts.py')],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).parent.parent)
    )
    print(result.stdout)
    if result.returncode != 0:
        print("Error recomputing CSF impacts:")
        print(result.stderr)


if __name__ == "__main__":
    asyncio.run(main())
