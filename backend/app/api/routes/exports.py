"""Export routes for CSV/JSON downloads."""
import csv
import io
import json
from datetime import datetime
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.deps import get_db, get_current_user_required
from app.models.user import User
from app.models.detection import Detection
from app.models.spl_artifact import SplParseArtifact
from app.models.mitre import DetectionMitreMapping, MitreTechnique
from app.models.csf import DetectionCsfImpact, CsfCategory
from app.services.coverage_analyzer import CoverageAnalyzer


router = APIRouter()


@router.get("/detections.csv")
async def export_detections_csv(
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Export all detections with mappings as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        'detection_id', 'name', 'description', 'severity', 'status',
        'owner_team', 'mitre_techniques', 'mitre_confidence_avg',
        'csf_functions', 'csf_score_avg', 'complexity_score',
        'indexes', 'sourcetypes', 'created_at', 'updated_at'
    ])

    # Get all detections with mappings
    stmt = select(Detection).order_by(Detection.name)
    result = await db.execute(stmt)
    detections = result.scalars().all()

    for detection in detections:
        # Get MITRE mappings
        mitre_stmt = select(DetectionMitreMapping).where(
            DetectionMitreMapping.detection_id == detection.id,
            DetectionMitreMapping.is_accepted == True
        )
        mitre_result = await db.execute(mitre_stmt)
        mitre_mappings = mitre_result.scalars().all()

        mitre_techniques = ','.join([m.technique_id for m in mitre_mappings])
        mitre_confidence_avg = sum(m.confidence for m in mitre_mappings) / len(mitre_mappings) if mitre_mappings else 0

        # Get CSF impacts
        csf_stmt = select(DetectionCsfImpact, CsfCategory).join(
            CsfCategory, DetectionCsfImpact.csf_id == CsfCategory.id
        ).where(DetectionCsfImpact.detection_id == detection.id)
        csf_result = await db.execute(csf_stmt)
        csf_impacts = csf_result.all()

        csf_functions = ','.join(set(i[1].function for i in csf_impacts))
        csf_score_avg = sum(i[0].impact_score for i in csf_impacts) / len(csf_impacts) if csf_impacts else 0

        # Get artifacts
        artifact_stmt = select(SplParseArtifact).where(SplParseArtifact.detection_id == detection.id)
        artifact_result = await db.execute(artifact_stmt)
        artifact = artifact_result.scalar_one_or_none()

        complexity = artifact.complexity_score if artifact else None
        indexes = ','.join(json.loads(artifact.indexes)) if artifact and artifact.indexes else ''
        sourcetypes = ','.join(json.loads(artifact.sourcetypes)) if artifact and artifact.sourcetypes else ''

        writer.writerow([
            detection.detection_id,
            detection.name,
            detection.description or '',
            detection.severity or '',
            detection.status,
            detection.owner_team or '',
            mitre_techniques,
            round(mitre_confidence_avg, 3),
            csf_functions,
            round(csf_score_avg, 3),
            complexity,
            indexes,
            sourcetypes,
            detection.created_at.isoformat(),
            detection.updated_at.isoformat(),
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=detections_{datetime.now().strftime('%Y%m%d')}.csv"}
    )


@router.get("/attack-coverage.csv")
async def export_attack_coverage_csv(
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Export ATT&CK coverage as CSV."""
    analyzer = CoverageAnalyzer(db)
    coverage = await analyzer.get_attack_coverage()

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        'technique_id', 'technique_name', 'tactics', 'detection_count',
        'weighted_coverage', 'is_subtechnique'
    ])

    # Flatten techniques from all tactics
    seen = set()
    for tactic, techniques in coverage['techniques_by_tactic'].items():
        for tech in techniques:
            if tech['technique_id'] not in seen:
                seen.add(tech['technique_id'])
                writer.writerow([
                    tech['technique_id'],
                    tech['technique_name'],
                    ','.join(tech['tactics']),
                    tech['detection_count'],
                    round(tech['weighted_coverage'], 3),
                    tech['is_subtechnique'],
                ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=attack_coverage_{datetime.now().strftime('%Y%m%d')}.csv"}
    )


@router.get("/csf-posture.csv")
async def export_csf_posture_csv(
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Export CSF posture as CSV."""
    analyzer = CoverageAnalyzer(db)
    coverage = await analyzer.get_csf_coverage()

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        'function', 'category_id', 'category_name', 'detection_count', 'score'
    ])

    for func_data in coverage['functions']:
        for cat in func_data['categories']:
            writer.writerow([
                func_data['function'],
                cat['id'],
                cat['name'],
                cat['detection_count'],
                round(cat['score'], 3),
            ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=csf_posture_{datetime.now().strftime('%Y%m%d')}.csv"}
    )


@router.get("/full-report.json")
async def export_full_report_json(
    user: User = Depends(get_current_user_required),
    db: AsyncSession = Depends(get_db),
):
    """Export full report as JSON."""
    analyzer = CoverageAnalyzer(db)

    overview = await analyzer.get_overview_stats()
    attack_coverage = await analyzer.get_attack_coverage()
    csf_coverage = await analyzer.get_csf_coverage()
    gaps = await analyzer.get_gaps()
    recommendations = await analyzer.get_recommendations()

    report = {
        'generated_at': datetime.utcnow().isoformat(),
        'overview': overview,
        'attack_coverage': {
            'total_techniques': attack_coverage['total_techniques'],
            'covered_techniques': attack_coverage['covered_techniques'],
            'coverage_percentage': attack_coverage['coverage_percentage'],
            'top_covered': attack_coverage['top_covered'][:10],
        },
        'csf_coverage': {
            'overall_score': csf_coverage['overall_score'],
            'function_scores': {
                'govern': csf_coverage['govern_score'],
                'identify': csf_coverage['identify_score'],
                'protect': csf_coverage['protect_score'],
                'detect': csf_coverage['detect_score'],
                'respond': csf_coverage['respond_score'],
                'recover': csf_coverage['recover_score'],
            }
        },
        'gaps': {
            'total': gaps['total_gaps'],
            'critical': gaps['critical_gaps'],
            'technique_gaps': len(gaps['technique_gaps']),
            'csf_gaps': len(gaps['csf_gaps']),
            'quality_issues': len(gaps['quality_issues']),
        },
        'recommendations': recommendations['recommendations'][:10],
    }

    return StreamingResponse(
        iter([json.dumps(report, indent=2)]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=csf_attack_report_{datetime.now().strftime('%Y%m%d')}.json"}
    )
