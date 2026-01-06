"""
Sophisticated Recommendation Engine with multi-dimensional scoring.

This engine produces consistent, deterministic recommendations based on:
- Coverage Gap Score (0.30) - How critical is this gap?
- Impact Score (0.25) - What's the benefit of addressing?
- Effort Score (0.15) - How hard to implement? (inverted: easier = higher priority)
- Risk Score (0.30) - What's the risk of NOT addressing?

Same inputs always produce same outputs - no randomness or ML inference.
"""
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.detection import Detection
from app.models.spl_artifact import SplParseArtifact
from app.models.mitre import MitreTechnique, DetectionMitreMapping
from app.models.csf import CsfCategory, MitreToCsfMapping, DetectionCsfImpact


# Scoring weights - deterministic configuration
PRIORITY_WEIGHTS = {
    'coverage_gap': 0.30,
    'impact': 0.25,
    'effort': 0.15,  # Inverted: (1 - effort) used
    'risk': 0.30,
}

# Tactic criticality for risk scoring
TACTIC_CRITICALITY = {
    'initial-access': 1.0,
    'execution': 0.95,
    'persistence': 0.90,
    'privilege-escalation': 0.90,
    'defense-evasion': 0.85,
    'credential-access': 0.85,
    'lateral-movement': 0.80,
    'collection': 0.70,
    'command-and-control': 0.75,
    'exfiltration': 0.80,
    'impact': 0.75,
    'discovery': 0.50,
    'reconnaissance': 0.60,
    'resource-development': 0.40,
}

# CSF Function criticality for risk scoring
CSF_FUNCTION_CRITICALITY = {
    'GOVERN': 0.85,
    'IDENTIFY': 0.75,
    'PROTECT': 0.90,
    'DETECT': 1.0,
    'RESPOND': 0.95,
    'RECOVER': 0.70,
}

# Recommendation type base impacts
RECOMMENDATION_TYPE_IMPACT = {
    'add_detection': 0.15,
    'enhance_detection': 0.10,
    'enable_detection': 0.12,
    'tune_detection': 0.08,
    'add_data_source': 0.20,
    'reduce_redundancy': 0.05,
}

# Effort estimates by recommendation type
RECOMMENDATION_TYPE_EFFORT = {
    'add_detection': 0.70,       # High effort - need to write new SPL
    'enhance_detection': 0.50,   # Medium effort - modify existing
    'enable_detection': 0.10,    # Low effort - just enable
    'tune_detection': 0.40,      # Medium effort - adjust thresholds
    'add_data_source': 0.80,     # High effort - infrastructure change
    'reduce_redundancy': 0.30,   # Lower effort - consolidation
}


class RecommendationType(str, Enum):
    ADD_DETECTION = 'add_detection'
    ENHANCE_DETECTION = 'enhance_detection'
    ENABLE_DETECTION = 'enable_detection'
    TUNE_DETECTION = 'tune_detection'
    ADD_DATA_SOURCE = 'add_data_source'
    REDUCE_REDUNDANCY = 'reduce_redundancy'


@dataclass
class ScoreBreakdown:
    """Detailed breakdown of priority score components."""
    coverage_gap: float = 0.0
    impact: float = 0.0
    effort: float = 0.0
    risk: float = 0.0

    def to_dict(self) -> Dict[str, float]:
        return {
            'coverage_gap': round(self.coverage_gap, 3),
            'impact': round(self.impact, 3),
            'effort': round(self.effort, 3),
            'risk': round(self.risk, 3),
        }


@dataclass
class ScoredRecommendation:
    """A recommendation with full scoring details."""
    id: str
    type: str
    priority_score: float
    priority_rank: int = 0  # Set after sorting
    title: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    score_breakdown: ScoreBreakdown = field(default_factory=ScoreBreakdown)
    affected_techniques: List[str] = field(default_factory=list)
    affected_csf: List[str] = field(default_factory=list)
    detection_id: Optional[int] = None
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'type': self.type,
            'priority': self.priority_rank,
            'priority_score': round(self.priority_score, 3),
            'title': self.title,
            'description': self.description,
            'evidence': self.evidence,
            'score_breakdown': self.score_breakdown.to_dict(),
            'impact_estimate': RECOMMENDATION_TYPE_IMPACT.get(self.type, 0.1),
            'affected_techniques': self.affected_techniques,
            'affected_csf': self.affected_csf,
            'detection_id': self.detection_id,
            'rationale': self.rationale,
        }


class RecommendationEngine:
    """
    Sophisticated recommendation engine with multi-dimensional scoring.

    This engine is deterministic - same inputs always produce same outputs.
    """

    def __init__(self, db: AsyncSession):
        """Initialize engine with database session."""
        self.db = db
        self._technique_cache: Dict[str, MitreTechnique] = {}
        self._csf_cache: Dict[str, CsfCategory] = {}
        self._detection_count_cache: Dict[str, int] = {}

    async def generate_recommendations(
        self,
        limit: int = 20,
        include_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate prioritized recommendations.

        Args:
            limit: Maximum number of recommendations to return
            include_types: Filter to specific recommendation types

        Returns:
            Dict with recommendations list and metadata
        """
        await self._warm_caches()

        all_recommendations: List[ScoredRecommendation] = []

        # Generate recommendations from different sources
        technique_recs = await self._generate_technique_gap_recommendations()
        all_recommendations.extend(technique_recs)

        csf_recs = await self._generate_csf_gap_recommendations()
        all_recommendations.extend(csf_recs)

        quality_recs = await self._generate_quality_recommendations()
        all_recommendations.extend(quality_recs)

        enable_recs = await self._generate_enable_recommendations()
        all_recommendations.extend(enable_recs)

        enhance_recs = await self._generate_enhancement_recommendations()
        all_recommendations.extend(enhance_recs)

        # Filter by type if requested
        if include_types:
            all_recommendations = [
                r for r in all_recommendations
                if r.type in include_types
            ]

        # Sort by priority score (descending) - deterministic
        all_recommendations.sort(key=lambda r: (-r.priority_score, r.id))

        # Assign priority ranks
        for i, rec in enumerate(all_recommendations):
            rec.priority_rank = i + 1

        # Limit results
        recommendations = all_recommendations[:limit]

        # Build type counts
        by_type: Dict[str, int] = {}
        for rec in all_recommendations:
            by_type[rec.type] = by_type.get(rec.type, 0) + 1

        return {
            'recommendations': [r.to_dict() for r in recommendations],
            'total_count': len(all_recommendations),
            'returned_count': len(recommendations),
            'by_type': by_type,
            'scoring_weights': PRIORITY_WEIGHTS,
        }

    async def _warm_caches(self):
        """Load data into caches for efficient scoring."""
        # Cache techniques
        stmt = select(MitreTechnique)
        result = await self.db.execute(stmt)
        for tech in result.scalars().all():
            self._technique_cache[tech.id] = tech

        # Cache CSF categories
        stmt = select(CsfCategory)
        result = await self.db.execute(stmt)
        for csf in result.scalars().all():
            self._csf_cache[csf.id] = csf

        # Cache detection counts per technique
        stmt = select(
            DetectionMitreMapping.technique_id,
            func.count(DetectionMitreMapping.id)
        ).where(
            DetectionMitreMapping.is_accepted == True
        ).group_by(DetectionMitreMapping.technique_id)

        result = await self.db.execute(stmt)
        for row in result.all():
            self._detection_count_cache[row[0]] = row[1]

    async def _generate_technique_gap_recommendations(self) -> List[ScoredRecommendation]:
        """Generate recommendations for uncovered techniques."""
        recommendations = []

        # Find techniques with no detections
        covered_techniques = set(self._detection_count_cache.keys())

        for tech_id, technique in self._technique_cache.items():
            if tech_id in covered_techniques:
                continue

            # Calculate scores
            scores = self._calculate_technique_gap_scores(technique)
            priority_score = self._calculate_priority_score(scores)

            tactics = json.loads(technique.tactics) if technique.tactics else []
            tactic_str = ', '.join(tactics[:2]) if tactics else 'unknown'

            rec = ScoredRecommendation(
                id=f"add_tech_{tech_id}",
                type=RecommendationType.ADD_DETECTION.value,
                priority_score=priority_score,
                title=f"Add detection for {technique.name}",
                description=f"Create a new detection rule to cover {technique.name} ({tech_id}) in the {tactic_str} tactic(s).",
                evidence=self._build_technique_gap_evidence(technique, scores),
                score_breakdown=scores,
                affected_techniques=[tech_id],
                affected_csf=await self._get_csf_for_technique(tech_id),
                rationale=self._build_technique_gap_rationale(technique, scores),
            )
            recommendations.append(rec)

        return recommendations

    def _calculate_technique_gap_scores(self, technique: MitreTechnique) -> ScoreBreakdown:
        """Calculate score breakdown for a technique gap."""
        scores = ScoreBreakdown()
        tactics = json.loads(technique.tactics) if technique.tactics else []

        # Coverage Gap Score: Based on technique importance
        # Sub-techniques slightly less critical than parent
        if technique.is_subtechnique:
            scores.coverage_gap = 0.7
        else:
            scores.coverage_gap = 1.0

        # Impact Score: Based on how many CSF categories would be affected
        scores.impact = self._estimate_technique_impact(technique.id)

        # Effort Score: Estimate based on technique complexity
        scores.effort = self._estimate_detection_effort(technique)

        # Risk Score: Based on tactic criticality
        if tactics:
            max_criticality = max(
                TACTIC_CRITICALITY.get(t.lower().replace(' ', '-'), 0.5)
                for t in tactics
            )
            scores.risk = max_criticality
        else:
            scores.risk = 0.5

        return scores

    def _estimate_technique_impact(self, technique_id: str) -> float:
        """Estimate the impact of covering a technique."""
        # Check how many CSF categories this technique maps to
        # More CSF coverage = higher impact
        base_impact = RECOMMENDATION_TYPE_IMPACT['add_detection']

        # In a full implementation, we'd look up MitreToCsfMapping
        # For now, estimate based on technique type
        if technique_id.startswith('T1'):
            if '.' in technique_id:
                return base_impact * 0.8  # Sub-technique
            return base_impact * 1.0  # Parent technique

        return base_impact

    def _estimate_detection_effort(self, technique: MitreTechnique) -> float:
        """Estimate effort to create detection for technique."""
        # Base effort
        effort = RECOMMENDATION_TYPE_EFFORT['add_detection']

        # Adjust based on data sources
        data_sources = json.loads(technique.data_sources) if technique.data_sources else []

        if not data_sources:
            effort += 0.1  # Harder if no documented data sources
        elif len(data_sources) > 3:
            effort -= 0.1  # Easier with multiple data source options

        # Sub-techniques often more specific and easier to detect
        if technique.is_subtechnique:
            effort -= 0.1

        return min(max(effort, 0.1), 1.0)

    def _build_technique_gap_evidence(
        self,
        technique: MitreTechnique,
        scores: ScoreBreakdown
    ) -> List[str]:
        """Build evidence list for technique gap recommendation."""
        evidence = [f"Technique {technique.id} ({technique.name}) has no mapped detections"]

        tactics = json.loads(technique.tactics) if technique.tactics else []
        if tactics:
            tactic_str = ', '.join(tactics)
            evidence.append(f"Belongs to tactic(s): {tactic_str}")

        if scores.risk >= 0.8:
            evidence.append("High-criticality tactic - prioritize coverage")

        data_sources = json.loads(technique.data_sources) if technique.data_sources else []
        if data_sources:
            evidence.append(f"Data sources available: {', '.join(data_sources[:3])}")

        return evidence

    def _build_technique_gap_rationale(
        self,
        technique: MitreTechnique,
        scores: ScoreBreakdown
    ) -> str:
        """Build human-readable rationale for the recommendation."""
        parts = []

        if scores.risk >= 0.9:
            parts.append("Critical tactic requiring immediate attention")
        elif scores.risk >= 0.7:
            parts.append("High-priority tactic")

        if scores.coverage_gap >= 0.9:
            parts.append("No existing coverage")

        if scores.effort <= 0.5:
            parts.append("Relatively low implementation effort")

        return "; ".join(parts) if parts else "Standard priority recommendation"

    async def _generate_csf_gap_recommendations(self) -> List[ScoredRecommendation]:
        """Generate recommendations for CSF coverage gaps."""
        recommendations = []

        # Get CSF categories with low coverage
        stmt = select(
            CsfCategory,
            func.avg(DetectionCsfImpact.impact_score).label('avg_score'),
            func.count(DetectionCsfImpact.id).label('detection_count')
        ).outerjoin(
            DetectionCsfImpact, CsfCategory.id == DetectionCsfImpact.csf_id
        ).group_by(CsfCategory.id)

        result = await self.db.execute(stmt)
        rows = result.all()

        for row in rows:
            csf = row[0]
            avg_score = row[1] or 0.0
            detection_count = row[2] or 0

            # Only recommend for low coverage
            if avg_score >= 0.5 and detection_count >= 2:
                continue

            scores = self._calculate_csf_gap_scores(csf, avg_score, detection_count)
            priority_score = self._calculate_priority_score(scores)

            # Skip very low priority
            if priority_score < 0.2:
                continue

            rec = ScoredRecommendation(
                id=f"csf_{csf.id.replace('.', '_')}",
                type=RecommendationType.ADD_DETECTION.value,
                priority_score=priority_score,
                title=f"Improve coverage for {csf.function}/{csf.category}",
                description=f"Add detections that map to techniques covering {csf.id}: {csf.name}",
                evidence=self._build_csf_gap_evidence(csf, avg_score, detection_count),
                score_breakdown=scores,
                affected_techniques=[],
                affected_csf=[csf.id],
                rationale=self._build_csf_gap_rationale(csf, scores),
            )
            recommendations.append(rec)

        return recommendations

    def _calculate_csf_gap_scores(
        self,
        csf: CsfCategory,
        avg_score: float,
        detection_count: int
    ) -> ScoreBreakdown:
        """Calculate score breakdown for CSF gap."""
        scores = ScoreBreakdown()

        # Coverage Gap: Inverse of current coverage
        scores.coverage_gap = 1.0 - min(avg_score, 1.0)

        # Impact: Based on CSF function importance
        function_criticality = CSF_FUNCTION_CRITICALITY.get(csf.function, 0.5)
        scores.impact = function_criticality * 0.15

        # Effort: Lower if we have some detections already
        if detection_count > 0:
            scores.effort = 0.5  # Some work already done
        else:
            scores.effort = 0.7  # Need to start from scratch

        # Risk: Based on function criticality
        scores.risk = function_criticality

        return scores

    def _build_csf_gap_evidence(
        self,
        csf: CsfCategory,
        avg_score: float,
        detection_count: int
    ) -> List[str]:
        """Build evidence for CSF gap recommendation."""
        evidence = []

        if detection_count == 0:
            evidence.append(f"No detections currently map to {csf.id}")
        else:
            evidence.append(f"Only {detection_count} detection(s) with average score {avg_score:.2f}")

        evidence.append(f"CSF Function: {csf.function}")

        if csf.function == 'GOVERN':
            evidence.append("GOVERN is new in CSF 2.0 - often overlooked")
        elif csf.function == 'DETECT':
            evidence.append("DETECT function is core to security monitoring")

        return evidence

    def _build_csf_gap_rationale(
        self,
        csf: CsfCategory,
        scores: ScoreBreakdown
    ) -> str:
        """Build rationale for CSF gap recommendation."""
        parts = []

        if scores.risk >= 0.9:
            parts.append(f"{csf.function} is a critical security function")

        if scores.coverage_gap >= 0.8:
            parts.append("Significant coverage gap exists")

        return "; ".join(parts) if parts else "Improve compliance coverage"

    async def _generate_quality_recommendations(self) -> List[ScoredRecommendation]:
        """Generate recommendations for detection quality issues."""
        recommendations = []

        stmt = select(Detection, SplParseArtifact).join(
            SplParseArtifact, Detection.id == SplParseArtifact.detection_id
        ).where(Detection.status == 'enabled')

        result = await self.db.execute(stmt)
        rows = result.all()

        for row in rows:
            detection = row[0]
            artifact = row[1]

            issues = self._analyze_quality_issues(detection, artifact)
            if not issues:
                continue

            scores = self._calculate_quality_scores(detection, artifact, issues)
            priority_score = self._calculate_priority_score(scores)

            # Skip low priority
            if priority_score < 0.15:
                continue

            rec = ScoredRecommendation(
                id=f"quality_{detection.id}",
                type=RecommendationType.TUNE_DETECTION.value,
                priority_score=priority_score,
                title=f"Tune detection: {detection.name[:50]}",
                description=self._build_quality_description(issues),
                evidence=issues,
                score_breakdown=scores,
                affected_techniques=await self._get_techniques_for_detection(detection.id),
                affected_csf=[],
                detection_id=detection.id,
                rationale=self._build_quality_rationale(issues),
            )
            recommendations.append(rec)

        return recommendations

    def _analyze_quality_issues(
        self,
        detection: Detection,
        artifact: SplParseArtifact
    ) -> List[str]:
        """Analyze a detection for quality issues."""
        issues = []

        complexity = artifact.complexity_score or 0
        signals = json.loads(artifact.complexity_signals) if artifact.complexity_signals else {}
        thresholds = json.loads(artifact.thresholds) if artifact.thresholds else []
        indexes = json.loads(artifact.indexes) if artifact.indexes else []

        if complexity > 70:
            issues.append(f"High complexity score ({complexity}) may impact performance")
        elif complexity > 50:
            issues.append(f"Moderate complexity ({complexity}) - consider simplification")

        if signals.get('transaction_count', 0) > 0:
            issues.append("Uses transaction command - high resource usage")

        if signals.get('join_count', 0) > 0:
            issues.append("Uses join command - may have performance implications")

        if len(thresholds) == 0:
            issues.append("No thresholds defined - may generate excessive alerts")

        if len(indexes) == 0:
            issues.append("No index specified - search performance may be poor")

        subsearches = signals.get('subsearch_count', 0)
        if subsearches > 2:
            issues.append(f"Multiple subsearches ({subsearches}) - consider restructuring")

        return issues

    def _calculate_quality_scores(
        self,
        detection: Detection,
        artifact: SplParseArtifact,
        issues: List[str]
    ) -> ScoreBreakdown:
        """Calculate scores for quality recommendation."""
        scores = ScoreBreakdown()

        # Coverage Gap: Based on number of issues
        scores.coverage_gap = min(len(issues) * 0.2, 1.0)

        # Impact: Quality improvements have moderate impact
        scores.impact = RECOMMENDATION_TYPE_IMPACT['tune_detection']

        # Effort: Usually moderate for tuning
        scores.effort = RECOMMENDATION_TYPE_EFFORT['tune_detection']

        # Risk: Based on detection severity
        severity_risk = {
            'critical': 0.9,
            'high': 0.7,
            'medium': 0.5,
            'low': 0.3,
        }
        scores.risk = severity_risk.get(detection.severity, 0.5)

        return scores

    def _build_quality_description(self, issues: List[str]) -> str:
        """Build description for quality recommendation."""
        if len(issues) == 1:
            return issues[0]
        return f"Address {len(issues)} quality issues to improve detection effectiveness"

    def _build_quality_rationale(self, issues: List[str]) -> str:
        """Build rationale for quality recommendation."""
        if any('performance' in i.lower() for i in issues):
            return "Performance improvements needed"
        if any('threshold' in i.lower() for i in issues):
            return "Alert quality improvements needed"
        return "General quality improvements"

    async def _generate_enable_recommendations(self) -> List[ScoredRecommendation]:
        """Generate recommendations for disabled detections worth enabling."""
        recommendations = []

        # Find disabled detections that have MITRE mappings
        stmt = select(Detection).where(
            Detection.status == 'disabled'
        )

        result = await self.db.execute(stmt)
        detections = result.scalars().all()

        for detection in detections:
            techniques = await self._get_techniques_for_detection(detection.id)
            if not techniques:
                continue  # Skip if no MITRE mappings

            scores = self._calculate_enable_scores(detection, techniques)
            priority_score = self._calculate_priority_score(scores)

            rec = ScoredRecommendation(
                id=f"enable_{detection.id}",
                type=RecommendationType.ENABLE_DETECTION.value,
                priority_score=priority_score,
                title=f"Enable detection: {detection.name[:50]}",
                description=f"This detection covers {len(techniques)} technique(s) and is currently disabled",
                evidence=[
                    f"Detection is disabled but mapped to: {', '.join(techniques[:3])}",
                    "Enabling would immediately improve coverage",
                ],
                score_breakdown=scores,
                affected_techniques=techniques,
                affected_csf=[],
                detection_id=detection.id,
                rationale="Quick win - enable for immediate coverage improvement",
            )
            recommendations.append(rec)

        return recommendations

    def _calculate_enable_scores(
        self,
        detection: Detection,
        techniques: List[str]
    ) -> ScoreBreakdown:
        """Calculate scores for enable recommendation."""
        scores = ScoreBreakdown()

        # Coverage Gap: Higher if techniques have low coverage elsewhere
        uncovered_count = sum(
            1 for t in techniques
            if self._detection_count_cache.get(t, 0) <= 1
        )
        scores.coverage_gap = min(uncovered_count * 0.3, 1.0)

        # Impact: Based on number of techniques covered
        scores.impact = min(len(techniques) * 0.05, 0.2)

        # Effort: Very low - just enabling
        scores.effort = RECOMMENDATION_TYPE_EFFORT['enable_detection']

        # Risk: Based on detection severity
        severity_risk = {
            'critical': 0.9,
            'high': 0.7,
            'medium': 0.5,
            'low': 0.3,
        }
        scores.risk = severity_risk.get(detection.severity, 0.5)

        return scores

    async def _generate_enhancement_recommendations(self) -> List[ScoredRecommendation]:
        """Generate recommendations for enhancing existing detections."""
        recommendations = []

        # Find detections with low-confidence mappings
        stmt = select(
            Detection,
            DetectionMitreMapping
        ).join(
            DetectionMitreMapping, Detection.id == DetectionMitreMapping.detection_id
        ).where(
            DetectionMitreMapping.is_accepted == True,
            DetectionMitreMapping.confidence < 0.5
        )

        result = await self.db.execute(stmt)
        rows = result.all()

        # Group by detection
        detection_low_confidence: Dict[int, List[Tuple[Detection, DetectionMitreMapping]]] = {}
        for row in rows:
            detection = row[0]
            mapping = row[1]
            if detection.id not in detection_low_confidence:
                detection_low_confidence[detection.id] = []
            detection_low_confidence[detection.id].append((detection, mapping))

        for detection_id, mappings in detection_low_confidence.items():
            detection = mappings[0][0]
            low_conf_techs = [m[1].technique_id for m in mappings]

            scores = self._calculate_enhance_scores(detection, mappings)
            priority_score = self._calculate_priority_score(scores)

            # Skip low priority
            if priority_score < 0.2:
                continue

            rec = ScoredRecommendation(
                id=f"enhance_{detection_id}",
                type=RecommendationType.ENHANCE_DETECTION.value,
                priority_score=priority_score,
                title=f"Enhance mapping: {detection.name[:50]}",
                description=f"Improve SPL or add tags to increase mapping confidence for {len(low_conf_techs)} technique(s)",
                evidence=[
                    f"Low confidence mappings: {', '.join(low_conf_techs[:3])}",
                    "Enhancing SPL specificity would improve mapping accuracy",
                ],
                score_breakdown=scores,
                affected_techniques=low_conf_techs,
                affected_csf=[],
                detection_id=detection_id,
                rationale="Improve detection specificity for better technique attribution",
            )
            recommendations.append(rec)

        return recommendations

    def _calculate_enhance_scores(
        self,
        detection: Detection,
        mappings: List[Tuple[Detection, DetectionMitreMapping]]
    ) -> ScoreBreakdown:
        """Calculate scores for enhancement recommendation."""
        scores = ScoreBreakdown()

        # Coverage Gap: Based on average confidence gap
        avg_confidence = sum(m[1].confidence for m in mappings) / len(mappings)
        scores.coverage_gap = 1.0 - avg_confidence

        # Impact: Moderate - improving existing coverage
        scores.impact = RECOMMENDATION_TYPE_IMPACT['enhance_detection']

        # Effort: Medium
        scores.effort = RECOMMENDATION_TYPE_EFFORT['enhance_detection']

        # Risk: Based on detection severity
        severity_risk = {
            'critical': 0.9,
            'high': 0.7,
            'medium': 0.5,
            'low': 0.3,
        }
        scores.risk = severity_risk.get(detection.severity, 0.5)

        return scores

    def _calculate_priority_score(self, scores: ScoreBreakdown) -> float:
        """
        Calculate final priority score from breakdown.

        Formula:
        priority = coverage_gap * 0.30 + impact * 0.25 + (1 - effort) * 0.15 + risk * 0.30
        """
        return (
            scores.coverage_gap * PRIORITY_WEIGHTS['coverage_gap'] +
            scores.impact * PRIORITY_WEIGHTS['impact'] +
            (1 - scores.effort) * PRIORITY_WEIGHTS['effort'] +
            scores.risk * PRIORITY_WEIGHTS['risk']
        )

    async def _get_csf_for_technique(self, technique_id: str) -> List[str]:
        """Get CSF categories mapped to a technique."""
        stmt = select(MitreToCsfMapping.csf_id).where(
            MitreToCsfMapping.technique_id == technique_id
        )
        result = await self.db.execute(stmt)
        return [row[0] for row in result.all()]

    async def _get_techniques_for_detection(self, detection_id: int) -> List[str]:
        """Get techniques mapped to a detection."""
        stmt = select(DetectionMitreMapping.technique_id).where(
            DetectionMitreMapping.detection_id == detection_id,
            DetectionMitreMapping.is_accepted == True
        )
        result = await self.db.execute(stmt)
        return [row[0] for row in result.all()]
