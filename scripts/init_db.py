#!/usr/bin/env python3
"""Initialize database with reference data and default admin user."""
import asyncio
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from sqlalchemy import select
from app.models.database import engine, async_session, Base
from app.models.user import User
from app.models.mitre import MitreTechnique
from app.models.csf import CsfCategory, MitreToCsfMapping
from app.core.security import get_password_hash
from app.config import settings
import yaml


async def create_tables():
    """Create all database tables."""
    print("Creating database tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Tables created successfully.")


async def create_default_admin():
    """Create default admin user if it doesn't exist."""
    async with async_session() as session:
        stmt = select(User).where(User.username == settings.DEFAULT_ADMIN_USERNAME)
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            print(f"Admin user '{settings.DEFAULT_ADMIN_USERNAME}' already exists.")
            return

        admin = User(
            username=settings.DEFAULT_ADMIN_USERNAME,
            email=settings.DEFAULT_ADMIN_EMAIL,
            password_hash=get_password_hash(settings.DEFAULT_ADMIN_PASSWORD),
            role="admin",
            is_active=True,
        )
        session.add(admin)
        await session.commit()
        print(f"Created admin user: {settings.DEFAULT_ADMIN_USERNAME}")
        print(f"Default password: {settings.DEFAULT_ADMIN_PASSWORD}")
        print("IMPORTANT: Change this password after first login!")


async def load_mitre_techniques():
    """Load MITRE ATT&CK techniques from embedded data."""
    async with async_session() as session:
        # Check if already loaded
        stmt = select(MitreTechnique).limit(1)
        result = await session.execute(stmt)
        if result.scalar_one_or_none():
            print("MITRE techniques already loaded.")
            return

        print("Loading MITRE ATT&CK techniques...")

        # Embedded subset of common techniques (in production, would load from STIX)
        techniques = [
            # Credential Access
            {"id": "T1110", "name": "Brute Force", "tactics": ["credential-access"], "is_subtechnique": False},
            {"id": "T1110.001", "name": "Password Guessing", "tactics": ["credential-access"], "is_subtechnique": True, "parent": "T1110"},
            {"id": "T1110.003", "name": "Password Spraying", "tactics": ["credential-access"], "is_subtechnique": True, "parent": "T1110"},
            {"id": "T1003", "name": "OS Credential Dumping", "tactics": ["credential-access"], "is_subtechnique": False},
            {"id": "T1003.001", "name": "LSASS Memory", "tactics": ["credential-access"], "is_subtechnique": True, "parent": "T1003"},
            {"id": "T1003.002", "name": "Security Account Manager", "tactics": ["credential-access"], "is_subtechnique": True, "parent": "T1003"},
            {"id": "T1558", "name": "Steal or Forge Kerberos Tickets", "tactics": ["credential-access"], "is_subtechnique": False},
            {"id": "T1558.003", "name": "Kerberoasting", "tactics": ["credential-access"], "is_subtechnique": True, "parent": "T1558"},

            # Initial Access
            {"id": "T1566", "name": "Phishing", "tactics": ["initial-access"], "is_subtechnique": False},
            {"id": "T1566.001", "name": "Spearphishing Attachment", "tactics": ["initial-access"], "is_subtechnique": True, "parent": "T1566"},
            {"id": "T1078", "name": "Valid Accounts", "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"], "is_subtechnique": False},
            {"id": "T1078.004", "name": "Cloud Accounts", "tactics": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"], "is_subtechnique": True, "parent": "T1078"},

            # Execution
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"], "is_subtechnique": False},
            {"id": "T1059.001", "name": "PowerShell", "tactics": ["execution"], "is_subtechnique": True, "parent": "T1059"},
            {"id": "T1059.003", "name": "Windows Command Shell", "tactics": ["execution"], "is_subtechnique": True, "parent": "T1059"},
            {"id": "T1047", "name": "Windows Management Instrumentation", "tactics": ["execution"], "is_subtechnique": False},
            {"id": "T1053", "name": "Scheduled Task/Job", "tactics": ["execution", "persistence", "privilege-escalation"], "is_subtechnique": False},
            {"id": "T1053.005", "name": "Scheduled Task", "tactics": ["execution", "persistence", "privilege-escalation"], "is_subtechnique": True, "parent": "T1053"},
            {"id": "T1218", "name": "System Binary Proxy Execution", "tactics": ["defense-evasion"], "is_subtechnique": False},
            {"id": "T1218.005", "name": "Mshta", "tactics": ["defense-evasion"], "is_subtechnique": True, "parent": "T1218"},
            {"id": "T1218.011", "name": "Rundll32", "tactics": ["defense-evasion"], "is_subtechnique": True, "parent": "T1218"},

            # Persistence
            {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactics": ["persistence", "privilege-escalation"], "is_subtechnique": False},
            {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder", "tactics": ["persistence", "privilege-escalation"], "is_subtechnique": True, "parent": "T1547"},
            {"id": "T1543", "name": "Create or Modify System Process", "tactics": ["persistence", "privilege-escalation"], "is_subtechnique": False},
            {"id": "T1543.003", "name": "Windows Service", "tactics": ["persistence", "privilege-escalation"], "is_subtechnique": True, "parent": "T1543"},

            # Privilege Escalation
            {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactics": ["privilege-escalation", "defense-evasion"], "is_subtechnique": False},
            {"id": "T1548.002", "name": "Bypass User Account Control", "tactics": ["privilege-escalation", "defense-evasion"], "is_subtechnique": True, "parent": "T1548"},

            # Defense Evasion
            {"id": "T1070", "name": "Indicator Removal", "tactics": ["defense-evasion"], "is_subtechnique": False},
            {"id": "T1070.001", "name": "Clear Windows Event Logs", "tactics": ["defense-evasion"], "is_subtechnique": True, "parent": "T1070"},
            {"id": "T1562", "name": "Impair Defenses", "tactics": ["defense-evasion"], "is_subtechnique": False},
            {"id": "T1562.001", "name": "Disable or Modify Tools", "tactics": ["defense-evasion"], "is_subtechnique": True, "parent": "T1562"},
            {"id": "T1562.007", "name": "Disable or Modify Cloud Firewall", "tactics": ["defense-evasion"], "is_subtechnique": True, "parent": "T1562"},
            {"id": "T1055", "name": "Process Injection", "tactics": ["defense-evasion", "privilege-escalation"], "is_subtechnique": False},
            {"id": "T1027", "name": "Obfuscated Files or Information", "tactics": ["defense-evasion"], "is_subtechnique": False},
            {"id": "T1556", "name": "Modify Authentication Process", "tactics": ["credential-access", "defense-evasion", "persistence"], "is_subtechnique": False},

            # Discovery
            {"id": "T1482", "name": "Domain Trust Discovery", "tactics": ["discovery"], "is_subtechnique": False},
            {"id": "T1135", "name": "Network Share Discovery", "tactics": ["discovery"], "is_subtechnique": False},
            {"id": "T1087", "name": "Account Discovery", "tactics": ["discovery"], "is_subtechnique": False},

            # Lateral Movement
            {"id": "T1021", "name": "Remote Services", "tactics": ["lateral-movement"], "is_subtechnique": False},
            {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactics": ["lateral-movement"], "is_subtechnique": True, "parent": "T1021"},
            {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactics": ["lateral-movement"], "is_subtechnique": True, "parent": "T1021"},
            {"id": "T1021.003", "name": "Distributed Component Object Model", "tactics": ["lateral-movement"], "is_subtechnique": True, "parent": "T1021"},
            {"id": "T1550", "name": "Use Alternate Authentication Material", "tactics": ["defense-evasion", "lateral-movement"], "is_subtechnique": False},
            {"id": "T1550.001", "name": "Application Access Token", "tactics": ["defense-evasion", "lateral-movement"], "is_subtechnique": True, "parent": "T1550"},

            # Collection
            {"id": "T1114", "name": "Email Collection", "tactics": ["collection"], "is_subtechnique": False},
            {"id": "T1114.003", "name": "Email Forwarding Rule", "tactics": ["collection"], "is_subtechnique": True, "parent": "T1114"},

            # Command and Control
            {"id": "T1071", "name": "Application Layer Protocol", "tactics": ["command-and-control"], "is_subtechnique": False},
            {"id": "T1071.004", "name": "DNS", "tactics": ["command-and-control"], "is_subtechnique": True, "parent": "T1071"},

            # Account Manipulation
            {"id": "T1098", "name": "Account Manipulation", "tactics": ["persistence", "privilege-escalation"], "is_subtechnique": False},
            {"id": "T1098.001", "name": "Additional Cloud Credentials", "tactics": ["persistence", "privilege-escalation"], "is_subtechnique": True, "parent": "T1098"},
            {"id": "T1098.003", "name": "Additional Cloud Roles", "tactics": ["persistence", "privilege-escalation"], "is_subtechnique": True, "parent": "T1098"},
        ]

        for tech in techniques:
            technique = MitreTechnique(
                id=tech["id"],
                name=tech["name"],
                tactics=json.dumps(tech["tactics"]),
                is_subtechnique=tech.get("is_subtechnique", False),
                parent_technique_id=tech.get("parent"),
                url=f"https://attack.mitre.org/techniques/{tech['id'].replace('.', '/')}",
            )
            session.add(technique)

        await session.commit()
        print(f"Loaded {len(techniques)} MITRE techniques.")


async def load_csf_categories():
    """Load NIST CSF 2.0 categories."""
    async with async_session() as session:
        # Check if already loaded
        stmt = select(CsfCategory).limit(1)
        result = await session.execute(stmt)
        if result.scalar_one_or_none():
            print("CSF categories already loaded.")
            return

        print("Loading NIST CSF 2.0 categories...")

        # CSF 2.0 categories
        categories = [
            # GOVERN
            {"id": "GV.OC-1", "function": "GOVERN", "category": "GV.OC", "name": "Organizational Context", "description": "The circumstances of the organization are understood and inform cybersecurity risk management."},
            {"id": "GV.RM-1", "function": "GOVERN", "category": "GV.RM", "name": "Risk Management Strategy", "description": "Cybersecurity risk management objectives are established and communicated."},
            {"id": "GV.RM-2", "function": "GOVERN", "category": "GV.RM", "name": "Risk Management Strategy", "description": "Risk appetite and risk tolerance statements are established."},
            {"id": "GV.RM-3", "function": "GOVERN", "category": "GV.RM", "name": "Risk Management Strategy", "description": "Cybersecurity risk management activities are integrated into enterprise risk management."},
            {"id": "GV.SC-3", "function": "GOVERN", "category": "GV.SC", "name": "Supply Chain Risk Management", "description": "Supply chain risks are identified, assessed, and managed."},

            # IDENTIFY
            {"id": "ID.AM-1", "function": "IDENTIFY", "category": "ID.AM", "name": "Asset Management", "description": "Inventories of hardware and software are maintained."},
            {"id": "ID.RA-1", "function": "IDENTIFY", "category": "ID.RA", "name": "Risk Assessment", "description": "Vulnerabilities in assets are identified, validated, and recorded."},

            # PROTECT
            {"id": "PR.AA-1", "function": "PROTECT", "category": "PR.AA", "name": "Identity Management and Access Control", "description": "Identities and credentials for users and devices are managed."},
            {"id": "PR.AA-3", "function": "PROTECT", "category": "PR.AA", "name": "Identity Management and Access Control", "description": "Access permissions and authorizations are managed."},
            {"id": "PR.AA-5", "function": "PROTECT", "category": "PR.AA", "name": "Identity Management and Access Control", "description": "Network integrity is protected using network segregation."},
            {"id": "PR.AT-1", "function": "PROTECT", "category": "PR.AT", "name": "Awareness and Training", "description": "All users are informed and trained."},
            {"id": "PR.DS-1", "function": "PROTECT", "category": "PR.DS", "name": "Data Security", "description": "Data-at-rest is protected."},
            {"id": "PR.DS-6", "function": "PROTECT", "category": "PR.DS", "name": "Data Security", "description": "Integrity checking mechanisms are used to verify software, firmware, and information integrity."},
            {"id": "PR.PS-1", "function": "PROTECT", "category": "PR.PS", "name": "Platform Security", "description": "Configuration management practices are established."},
            {"id": "PR.PS-2", "function": "PROTECT", "category": "PR.PS", "name": "Platform Security", "description": "Software is maintained, replaced, and removed commensurate with risk."},

            # DETECT
            {"id": "DE.AE-2", "function": "DETECT", "category": "DE.AE", "name": "Adverse Event Analysis", "description": "Potentially adverse events are analyzed to characterize impacts and support response."},
            {"id": "DE.AE-4", "function": "DETECT", "category": "DE.AE", "name": "Adverse Event Analysis", "description": "Information on adverse events is correlated from multiple sources."},
            {"id": "DE.CM-1", "function": "DETECT", "category": "DE.CM", "name": "Continuous Monitoring", "description": "Networks and network services are monitored."},
            {"id": "DE.CM-3", "function": "DETECT", "category": "DE.CM", "name": "Continuous Monitoring", "description": "Computing hardware and software are monitored."},
            {"id": "DE.CM-6", "function": "DETECT", "category": "DE.CM", "name": "Continuous Monitoring", "description": "External service provider activities and services are monitored."},

            # RESPOND
            {"id": "RS.AN-1", "function": "RESPOND", "category": "RS.AN", "name": "Incident Analysis", "description": "Investigations are conducted to support incident response."},
            {"id": "RS.MA-1", "function": "RESPOND", "category": "RS.MA", "name": "Incident Management", "description": "Incidents are managed."},

            # RECOVER
            {"id": "RC.RP-1", "function": "RECOVER", "category": "RC.RP", "name": "Incident Recovery Plan Execution", "description": "Recovery activities are performed."},
        ]

        for cat in categories:
            category = CsfCategory(
                id=cat["id"],
                function=cat["function"],
                category=cat["category"],
                subcategory=cat["id"],
                name=cat["name"],
                description=cat["description"],
            )
            session.add(category)

        await session.commit()
        print(f"Loaded {len(categories)} CSF categories.")


async def load_mitre_to_csf_mappings():
    """Load MITRE to CSF crosswalk from YAML file."""
    async with async_session() as session:
        # Check if already loaded
        stmt = select(MitreToCsfMapping).limit(1)
        result = await session.execute(stmt)
        if result.scalar_one_or_none():
            print("MITRE to CSF mappings already loaded.")
            return

        crosswalk_path = settings.MAPPINGS_DIR / "mitre_to_csf_starter.yml"
        if not crosswalk_path.exists():
            print(f"Warning: Crosswalk file not found at {crosswalk_path}")
            return

        print("Loading MITRE to CSF crosswalk mappings...")

        with open(crosswalk_path, 'r') as f:
            data = yaml.safe_load(f)

        if not data or 'mappings' not in data:
            print("No mappings found in crosswalk file.")
            return

        count = 0
        for mapping in data['mappings']:
            technique_id = mapping.get('technique_id')
            csf = mapping.get('csf', {})
            csf_id = csf.get('subcategory') or csf.get('category')

            if not technique_id or not csf_id:
                continue

            # Verify technique exists
            tech_stmt = select(MitreTechnique).where(MitreTechnique.id == technique_id)
            tech_result = await session.execute(tech_stmt)
            if not tech_result.scalar_one_or_none():
                continue

            # Verify CSF category exists
            csf_stmt = select(CsfCategory).where(CsfCategory.id == csf_id)
            csf_result = await session.execute(csf_stmt)
            if not csf_result.scalar_one_or_none():
                continue

            mitre_csf = MitreToCsfMapping(
                technique_id=technique_id,
                csf_id=csf_id,
                weight=mapping.get('weight', 0.5),
                rationale=mapping.get('rationale', ''),
                source='curated',
            )
            session.add(mitre_csf)
            count += 1

        await session.commit()
        print(f"Loaded {count} MITRE to CSF mappings.")


async def main():
    """Run all initialization steps."""
    print("=" * 60)
    print("CSF×ATT&CK Mapper - Database Initialization")
    print("=" * 60)

    await create_tables()
    await create_default_admin()
    await load_mitre_techniques()
    await load_csf_categories()
    await load_mitre_to_csf_mappings()

    print("=" * 60)
    print("Initialization complete!")
    print("=" * 60)
    print(f"\nDefault admin credentials:")
    print(f"  Username: {settings.DEFAULT_ADMIN_USERNAME}")
    print(f"  Password: {settings.DEFAULT_ADMIN_PASSWORD}")
    print("\nStart the server with:")
    print("  cd backend && uvicorn app.main:app --reload --port 8000")


if __name__ == "__main__":
    asyncio.run(main())
