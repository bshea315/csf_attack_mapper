"""Coverage analysis and recommendations service."""
import json
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from app.models.detection import Detection, IngestBatch
from app.models.spl_artifact import SplParseArtifact
from app.models.mitre import MitreTechnique, DetectionMitreMapping
from app.models.csf import CsfCategory, MitreToCsfMapping, DetectionCsfImpact
from app.services.recommendation_engine import RecommendationEngine


class CoverageAnalyzer:
    """Analyzer for coverage gaps and recommendations."""

    # MITRE Tactics in order
    TACTICS = [
        'reconnaissance', 'resource-development', 'initial-access',
        'execution', 'persistence', 'privilege-escalation',
        'defense-evasion', 'credential-access', 'discovery',
        'lateral-movement', 'collection', 'command-and-control',
        'exfiltration', 'impact'
    ]

    CSF_FUNCTIONS = ['GOVERN', 'IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER']

    def __init__(self, db: AsyncSession):
        """Initialize analyzer with database session."""
        self.db = db

    async def get_overview_stats(self) -> Dict[str, Any]:
        """Get overview statistics for dashboard."""
        # Count detections
        total_stmt = select(func.count(Detection.id))
        total_result = await self.db.execute(total_stmt)
        total_detections = total_result.scalar() or 0

        enabled_stmt = select(func.count(Detection.id)).where(Detection.status == 'enabled')
        enabled_result = await self.db.execute(enabled_stmt)
        enabled_detections = enabled_result.scalar() or 0

        # Count techniques covered
        covered_stmt = select(func.count(func.distinct(DetectionMitreMapping.technique_id))).where(
            DetectionMitreMapping.is_accepted == True
        )
        covered_result = await self.db.execute(covered_stmt)
        techniques_covered = covered_result.scalar() or 0

        total_techniques_stmt = select(func.count(MitreTechnique.id))
        total_techniques_result = await self.db.execute(total_techniques_stmt)
        total_techniques = total_techniques_result.scalar() or 0

        # CSF coverage
        csf_covered_stmt = select(func.count(func.distinct(DetectionCsfImpact.csf_id)))
        csf_covered_result = await self.db.execute(csf_covered_stmt)
        csf_covered = csf_covered_result.scalar() or 0

        # Average CSF score
        avg_score_stmt = select(func.avg(DetectionCsfImpact.impact_score))
        avg_score_result = await self.db.execute(avg_score_stmt)
        avg_csf_score = avg_score_result.scalar() or 0.0

        # Get last ingest and recent ingests
        last_ingest_stmt = select(IngestBatch).order_by(desc(IngestBatch.completed_at)).limit(1)
        last_ingest_result = await self.db.execute(last_ingest_stmt)
        last_ingest = last_ingest_result.scalar_one_or_none()

        recent_ingests_stmt = select(IngestBatch).order_by(desc(IngestBatch.created_at)).limit(5)
        recent_ingests_result = await self.db.execute(recent_ingests_stmt)
        recent_ingests_list = recent_ingests_result.scalars().all()

        recent_ingests = [
            {
                'id': batch.id,
                'source_type': batch.source_type,
                'source_filename': batch.source_filename,
                'total_records': batch.total_records,
                'successful': batch.successful,
                'failed': batch.failed,
                'status': batch.status,
                'created_at': batch.created_at.isoformat() if batch.created_at else None,
                'completed_at': batch.completed_at.isoformat() if batch.completed_at else None,
            }
            for batch in recent_ingests_list
        ]

        return {
            'total_detections': total_detections,
            'enabled_detections': enabled_detections,
            'disabled_detections': total_detections - enabled_detections,
            'enabled_percentage': (enabled_detections / total_detections * 100) if total_detections > 0 else 0,
            'techniques_covered': techniques_covered,
            'total_techniques': total_techniques,
            'technique_coverage_percentage': (techniques_covered / total_techniques * 100) if total_techniques > 0 else 0,
            'csf_functions_covered': csf_covered,
            'average_csf_coverage': round(avg_csf_score, 3),
            'last_ingest_at': last_ingest.completed_at if last_ingest else None,
            'recent_ingests': recent_ingests,
        }

    async def get_attack_coverage(self) -> Dict[str, Any]:
        """Get MITRE ATT&CK coverage data."""
        # Get all techniques with detection counts
        stmt = select(
            MitreTechnique,
            func.count(DetectionMitreMapping.id).label('detection_count'),
            func.avg(DetectionMitreMapping.confidence).label('avg_confidence')
        ).outerjoin(
            DetectionMitreMapping,
            (MitreTechnique.id == DetectionMitreMapping.technique_id) &
            (DetectionMitreMapping.is_accepted == True)
        ).group_by(MitreTechnique.id)

        result = await self.db.execute(stmt)
        rows = result.all()

        techniques_by_tactic: Dict[str, List[Dict]] = {tactic: [] for tactic in self.TACTICS}
        total_techniques = 0
        covered_techniques = 0

        for row in rows:
            technique = row[0]
            detection_count = row[1] or 0
            avg_confidence = row[2] or 0.0

            total_techniques += 1
            if detection_count > 0:
                covered_techniques += 1

            tactics = json.loads(technique.tactics) if technique.tactics else []

            tech_data = {
                'technique_id': technique.id,
                'technique_name': technique.name,
                'tactics': tactics,
                'detection_count': detection_count,
                'weighted_coverage': avg_confidence * min(detection_count, 5) / 5,  # Cap at 5 detections
                'is_subtechnique': technique.is_subtechnique,
                'parent_technique_id': technique.parent_technique_id,
                'url': technique.url or f"https://attack.mitre.org/techniques/{technique.id.replace('.', '/')}",
            }

            for tactic in tactics:
                tactic_lower = tactic.lower().replace(' ', '-')
                if tactic_lower in techniques_by_tactic:
                    techniques_by_tactic[tactic_lower].append(tech_data)

        # Get top covered techniques
        all_techniques = [t for tactics in techniques_by_tactic.values() for t in tactics]
        top_covered = sorted(all_techniques, key=lambda x: x['detection_count'], reverse=True)[:10]

        # Get uncovered techniques
        uncovered = [
            {'technique_id': t['technique_id'], 'technique_name': t['technique_name']}
            for t in all_techniques if t['detection_count'] == 0
        ][:20]

        return {
            'tactics': self.TACTICS,
            'techniques_by_tactic': techniques_by_tactic,
            'total_techniques': total_techniques,
            'covered_techniques': covered_techniques,
            'coverage_percentage': (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0,
            'top_covered': top_covered,
            'uncovered': uncovered,
        }

    async def get_csf_coverage(self) -> Dict[str, Any]:
        """Get NIST CSF 2.0 coverage data."""
        # Get impact data from detection_csf_impact joined with csf_categories
        # detection_csf_impact.csf_id stores subcategory IDs like "DE.CM-1", "PR.AA-1"
        # We need to aggregate by the parent category (DE.CM, PR.AA)
        impact_stmt = select(
            CsfCategory.category,  # Parent category like "DE.CM"
            CsfCategory.function,
            func.count(func.distinct(DetectionCsfImpact.detection_id)).label('detection_count'),
            func.avg(DetectionCsfImpact.impact_score).label('avg_score')
        ).select_from(DetectionCsfImpact).join(
            CsfCategory, DetectionCsfImpact.csf_id == CsfCategory.id
        ).group_by(CsfCategory.category, CsfCategory.function)

        impact_result = await self.db.execute(impact_stmt)
        impact_by_category = {
            row[0]: {'function': row[1], 'detection_count': row[2] or 0, 'avg_score': row[3] or 0.0}
            for row in impact_result.all()
        }

        # Get all CSF categories (subcategories) grouped by category
        cat_stmt = select(CsfCategory)
        cat_result = await self.db.execute(cat_stmt)
        all_categories = cat_result.scalars().all()

        # Build unique categories by function
        # csf_categories table has subcategories (DE.CM-1) with category field (DE.CM)
        category_map: Dict[str, Dict] = {}  # category -> {function, name, subcategories}

        for csf in all_categories:
            cat_code = csf.category  # e.g., "DE.CM"
            if cat_code not in category_map:
                category_map[cat_code] = {
                    'category': cat_code,
                    'function': csf.function,
                    'name': csf.name,
                    'subcategory_ids': [],
                }
            category_map[cat_code]['subcategory_ids'].append(csf.id)

        # Organize by function
        functions_data: Dict[str, Dict] = {}
        for func_name in self.CSF_FUNCTIONS:
            functions_data[func_name] = {
                'function': func_name,
                'categories': [],
                'total_categories': 0,
                'covered_categories': 0,
                'total_subcategories': 0,
                'covered_subcategories': 0,
                'total_score': 0.0,
                'detection_count': 0,
            }

        for cat_code, cat_info in category_map.items():
            func_name = cat_info['function']
            # Now impact_by_category is keyed by parent category (DE.CM), not subcategory (DE.CM-1)
            impact_data = impact_by_category.get(cat_code, {'detection_count': 0, 'avg_score': 0.0})
            detection_count = impact_data['detection_count']
            avg_score = impact_data['avg_score']
            num_subcategories = len(cat_info['subcategory_ids'])

            if func_name in functions_data:
                functions_data[func_name]['categories'].append({
                    'id': cat_code,
                    'name': cat_info['name'],
                    'category': cat_code,
                    'detection_count': detection_count,
                    'score': round(avg_score, 3),
                    'subcategory_count': num_subcategories,
                })
                functions_data[func_name]['total_categories'] += 1
                functions_data[func_name]['total_subcategories'] += num_subcategories
                if detection_count > 0:
                    functions_data[func_name]['covered_categories'] += 1
                    functions_data[func_name]['covered_subcategories'] += num_subcategories
                    functions_data[func_name]['total_score'] += avg_score
                    functions_data[func_name]['detection_count'] += detection_count

        # Calculate averages
        for func_name, data in functions_data.items():
            if data['covered_categories'] > 0:
                data['average_score'] = data['total_score'] / data['covered_categories']
            else:
                data['average_score'] = 0.0

        # Calculate overall and per-function scores
        total_covered = sum(f['covered_categories'] for f in functions_data.values())
        total_score = sum(f['total_score'] for f in functions_data.values())
        overall_score = total_score / total_covered if total_covered > 0 else 0.0

        return {
            'functions': list(functions_data.values()),
            'overall_score': round(overall_score, 3),
            'govern_score': round(functions_data.get('GOVERN', {}).get('average_score', 0), 3),
            'identify_score': round(functions_data.get('IDENTIFY', {}).get('average_score', 0), 3),
            'protect_score': round(functions_data.get('PROTECT', {}).get('average_score', 0), 3),
            'detect_score': round(functions_data.get('DETECT', {}).get('average_score', 0), 3),
            'respond_score': round(functions_data.get('RESPOND', {}).get('average_score', 0), 3),
            'recover_score': round(functions_data.get('RECOVER', {}).get('average_score', 0), 3),
        }

    async def get_gaps(self) -> Dict[str, Any]:
        """Get gap analysis data."""
        gaps = {
            'technique_gaps': [],
            'csf_gaps': [],
            'quality_issues': [],
        }

        # Find techniques with no detections
        stmt = select(MitreTechnique).outerjoin(
            DetectionMitreMapping,
            (MitreTechnique.id == DetectionMitreMapping.technique_id) &
            (DetectionMitreMapping.is_accepted == True)
        ).where(DetectionMitreMapping.id == None)

        result = await self.db.execute(stmt)
        uncovered_techniques = result.scalars().all()

        for tech in uncovered_techniques[:20]:  # Limit to 20
            tactics = json.loads(tech.tactics) if tech.tactics else []
            gaps['technique_gaps'].append({
                'type': 'technique_gap',
                'id': tech.id,
                'name': tech.name,
                'severity': 'high' if 'initial-access' in [t.lower() for t in tactics] else 'medium',
                'description': f"No detections mapped to {tech.name}",
                'recommendation': f"Create detection for {tech.name} ({tech.id})",
                'impact_estimate': 0.1,
            })

        # Find CSF categories with low coverage
        stmt = select(
            CsfCategory,
            func.avg(DetectionCsfImpact.impact_score).label('avg_score')
        ).outerjoin(
            DetectionCsfImpact
        ).group_by(CsfCategory.id).having(
            (func.avg(DetectionCsfImpact.impact_score) < 0.3) |
            (func.avg(DetectionCsfImpact.impact_score) == None)
        )

        result = await self.db.execute(stmt)
        low_csf = result.all()

        for row in low_csf[:10]:
            csf = row[0]
            score = row[1] or 0
            gaps['csf_gaps'].append({
                'type': 'csf_gap',
                'id': csf.id,
                'name': csf.name,
                'severity': 'high' if csf.function == 'GOVERN' else 'medium',
                'description': f"Low coverage for {csf.function}/{csf.category}: {csf.name}",
                'recommendation': f"Add detections that map to techniques covering {csf.id}",
                'impact_estimate': 0.15,
            })

        # Find quality issues in detections
        stmt = select(Detection, SplParseArtifact).join(
            SplParseArtifact, Detection.id == SplParseArtifact.detection_id
        )

        result = await self.db.execute(stmt)
        rows = result.all()

        for row in rows:
            detection = row[0]
            artifact = row[1]

            issues = []
            complexity = artifact.complexity_score or 0
            signals = json.loads(artifact.complexity_signals) if artifact.complexity_signals else {}
            thresholds = json.loads(artifact.thresholds) if artifact.thresholds else []
            indexes = json.loads(artifact.indexes) if artifact.indexes else []

            # High complexity
            if complexity > 60:
                issues.append('high_complexity')

            # Uses transaction or join
            if signals.get('transaction_count', 0) > 0:
                issues.append('uses_transaction')
            if signals.get('join_count', 0) > 0:
                issues.append('uses_join')

            # No thresholds
            if len(thresholds) == 0:
                issues.append('no_thresholds')

            # No data source specified
            if len(indexes) == 0:
                issues.append('no_index')

            # Detection disabled
            if detection.status == 'disabled':
                issues.append('disabled')

            if issues:
                severity = 'high' if 'disabled' in issues or 'high_complexity' in issues else 'low'
                gaps['quality_issues'].append({
                    'type': 'quality_issue',
                    'id': str(detection.id),
                    'name': detection.name,
                    'severity': severity,
                    'description': f"Quality issues: {', '.join(issues)}",
                    'recommendation': self._get_quality_recommendation(issues),
                    'impact_estimate': 0.05,
                    'detection_id': detection.id,
                })

        gaps['total_gaps'] = (
            len(gaps['technique_gaps']) +
            len(gaps['csf_gaps']) +
            len(gaps['quality_issues'])
        )
        gaps['critical_gaps'] = sum(
            1 for g in gaps['technique_gaps'] + gaps['csf_gaps'] + gaps['quality_issues']
            if g['severity'] == 'high'
        )
        gaps['high_priority_items'] = sorted(
            gaps['technique_gaps'] + gaps['csf_gaps'] + gaps['quality_issues'],
            key=lambda x: (0 if x['severity'] == 'high' else 1, -x['impact_estimate'])
        )[:10]

        return gaps

    def _get_quality_recommendation(self, issues: List[str]) -> str:
        """Get recommendation text for quality issues."""
        recommendations = []
        if 'high_complexity' in issues:
            recommendations.append("Consider simplifying the SPL query")
        if 'uses_transaction' in issues:
            recommendations.append("Consider alternatives to transaction command")
        if 'uses_join' in issues:
            recommendations.append("Review join usage for performance")
        if 'no_thresholds' in issues:
            recommendations.append("Add threshold conditions to reduce false positives")
        if 'no_index' in issues:
            recommendations.append("Specify index to improve search performance")
        if 'disabled' in issues:
            recommendations.append("Consider enabling this detection")

        return "; ".join(recommendations) if recommendations else "Review detection quality"

    async def get_recommendations(
        self,
        limit: int = 20,
        include_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Get improvement recommendations using sophisticated multi-dimensional scoring.

        This method uses the RecommendationEngine for deterministic, consistent
        prioritization based on coverage gaps, impact, effort, and risk.

        Args:
            limit: Maximum number of recommendations to return
            include_types: Filter to specific recommendation types

        Returns:
            Dict with recommendations list, counts, and scoring metadata
        """
        engine = RecommendationEngine(self.db)
        return await engine.generate_recommendations(
            limit=limit,
            include_types=include_types,
        )

    async def get_crosswalk(
        self,
        technique_id: Optional[str] = None,
        csf_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get crosswalk data between MITRE and CSF."""
        items = []

        if technique_id:
            # Get CSF categories for specific technique
            stmt = select(
                MitreToCsfMapping,
                MitreTechnique,
                CsfCategory,
            ).join(
                MitreTechnique, MitreToCsfMapping.technique_id == MitreTechnique.id
            ).join(
                CsfCategory, MitreToCsfMapping.csf_id == CsfCategory.id
            ).where(MitreToCsfMapping.technique_id == technique_id)

        elif csf_id:
            # Get techniques for specific CSF category
            stmt = select(
                MitreToCsfMapping,
                MitreTechnique,
                CsfCategory,
            ).join(
                MitreTechnique, MitreToCsfMapping.technique_id == MitreTechnique.id
            ).join(
                CsfCategory, MitreToCsfMapping.csf_id == CsfCategory.id
            ).where(MitreToCsfMapping.csf_id == csf_id)

        else:
            # Get all crosswalk mappings
            stmt = select(
                MitreToCsfMapping,
                MitreTechnique,
                CsfCategory,
            ).join(
                MitreTechnique, MitreToCsfMapping.technique_id == MitreTechnique.id
            ).join(
                CsfCategory, MitreToCsfMapping.csf_id == CsfCategory.id
            )

        result = await self.db.execute(stmt)
        rows = result.all()

        for row in rows:
            mapping = row[0]
            technique = row[1]
            csf = row[2]

            # Count detections for this technique
            count_stmt = select(func.count(DetectionMitreMapping.id)).where(
                DetectionMitreMapping.technique_id == technique.id,
                DetectionMitreMapping.is_accepted == True
            )
            count_result = await self.db.execute(count_stmt)
            detection_count = count_result.scalar() or 0

            items.append({
                'technique_id': technique.id,
                'technique_name': technique.name,
                'csf_id': csf.id,
                'csf_function': csf.function,
                'csf_name': csf.name,
                'weight': mapping.weight,
                'detection_count': detection_count,
            })

        techniques_with_csf = len(set(i['technique_id'] for i in items))
        csf_with_techniques = len(set(i['csf_id'] for i in items))

        return {
            'items': items,
            'techniques_with_csf': techniques_with_csf,
            'csf_with_techniques': csf_with_techniques,
            'total_mappings': len(items),
        }
