"""
Enhanced MITRE ATT&CK mapping service using deterministic multi-signal scoring.

This mapper provides consistent, reproducible mappings by scoring SPL detections
against a comprehensive indicator database. The same input always produces
the same output.

Signal Weights:
    - Data Sources: 0.25 (indexes, sourcetypes, datamodels)
    - Field Indicators: 0.30 (fields referenced in SPL)
    - Behavioral Patterns: 0.35 (regex patterns in SPL)
    - Tag Confirmation: 0.10 (original MITRE tags from detection)
"""
import re
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from app.config import settings


# Signal weights - these determine the final score composition
SIGNAL_WEIGHTS = {
    'data_source': 0.25,
    'field_indicator': 0.30,
    'behavioral': 0.35,
    'tag_confirmation': 0.10,
}

# Confidence thresholds for mapping acceptance
CONFIDENCE_THRESHOLDS = {
    'high': 0.70,      # Auto-accept
    'medium': 0.45,    # Accept with review flag
    'low': 0.25,       # Suggest for review
}


@dataclass
class SignalScores:
    """Breakdown of scores by signal type."""
    data_source: float = 0.0
    field_indicator: float = 0.0
    behavioral: float = 0.0
    tag_confirmation: float = 0.0

    def to_dict(self) -> Dict[str, float]:
        return {
            'data_source': round(self.data_source, 3),
            'field_indicator': round(self.field_indicator, 3),
            'behavioral': round(self.behavioral, 3),
            'tag_confirmation': round(self.tag_confirmation, 3),
        }


@dataclass
class EnhancedMappingMatch:
    """Result of enhanced technique matching."""
    technique_id: str
    technique_name: str
    final_score: float
    confidence_level: str  # 'high', 'medium', 'low'
    signal_scores: SignalScores
    evidence: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'technique_id': self.technique_id,
            'technique_name': self.technique_name,
            'final_score': round(self.final_score, 3),
            'confidence_level': self.confidence_level,
            'signal_scores': self.signal_scores.to_dict(),
            'evidence': self.evidence,
            'rationale': self.rationale,
        }


@dataclass
class EnhancedMappingResult:
    """Full enhanced mapping result for a detection."""
    matches: List[EnhancedMappingMatch] = field(default_factory=list)
    techniques_evaluated: int = 0
    mapping_method: str = "enhanced_multi_signal"

    def get_accepted_mappings(self, min_confidence: str = 'low') -> List[EnhancedMappingMatch]:
        """Get mappings meeting minimum confidence threshold."""
        threshold = CONFIDENCE_THRESHOLDS.get(min_confidence, 0.25)
        return [m for m in self.matches if m.final_score >= threshold]


class EnhancedMitreMapper:
    """
    Enhanced MITRE ATT&CK mapper using deterministic multi-signal scoring.

    This mapper is completely deterministic - the same inputs will always
    produce identical outputs. No randomness, no ML inference.
    """

    def __init__(self, indicators_path: Optional[Path] = None):
        """Initialize mapper with technique indicators database."""
        self.indicators_path = indicators_path or settings.MAPPINGS_DIR / "technique_indicators.yml"
        self.indicators: Dict[str, Dict[str, Any]] = {}
        self.tactic_criticality: Dict[str, float] = {}
        self.thresholds: Dict[str, float] = CONFIDENCE_THRESHOLDS.copy()
        self._load_indicators()

    def _load_indicators(self):
        """Load technique indicators from YAML file."""
        if not self.indicators_path.exists():
            return

        with open(self.indicators_path, 'r') as f:
            data = yaml.safe_load(f)

        if data:
            self.indicators = data.get('indicators', {})
            self.tactic_criticality = data.get('tactic_criticality', {})
            if 'thresholds' in data:
                self.thresholds.update(data['thresholds'])

    def reload_indicators(self):
        """Reload indicators from file."""
        self.indicators = {}
        self._load_indicators()

    def map_detection(
        self,
        name: str,
        description: str,
        spl: str,
        sourcetypes: Optional[List[str]] = None,
        fields: Optional[List[str]] = None,
        indexes: Optional[List[str]] = None,
        datamodels: Optional[List[str]] = None,
        original_mitre_tags: Optional[List[str]] = None,
    ) -> EnhancedMappingResult:
        """
        Map a detection to MITRE techniques using multi-signal scoring.

        Args:
            name: Detection name
            description: Detection description
            spl: The SPL query
            sourcetypes: Extracted sourcetypes from SPL
            fields: Extracted fields from SPL
            indexes: Extracted indexes from SPL
            datamodels: Extracted datamodels from SPL
            original_mitre_tags: MITRE technique IDs from original detection tags

        Returns:
            EnhancedMappingResult with all matches
        """
        result = EnhancedMappingResult(techniques_evaluated=len(self.indicators))

        # Normalize inputs for consistent matching
        all_text = f"{name} {description} {spl}".lower()
        spl_lower = spl.lower()
        sourcetypes_set = {st.lower() for st in (sourcetypes or [])}
        fields_set = {f.lower() for f in (fields or [])}
        indexes_set = {idx.lower() for idx in (indexes or [])}
        datamodels_set = {dm.lower() for dm in (datamodels or [])}
        mitre_tags_set = {t.upper() for t in (original_mitre_tags or [])}

        # Evaluate each technique
        for technique_id, indicators in self.indicators.items():
            match = self._evaluate_technique(
                technique_id=technique_id,
                indicators=indicators,
                all_text=all_text,
                spl=spl_lower,
                sourcetypes=sourcetypes_set,
                fields=fields_set,
                indexes=indexes_set,
                datamodels=datamodels_set,
                mitre_tags=mitre_tags_set,
            )
            if match and match.final_score >= self.thresholds.get('low', 0.25):
                result.matches.append(match)

        # Sort by score descending
        result.matches.sort(key=lambda m: m.final_score, reverse=True)

        return result

    def _evaluate_technique(
        self,
        technique_id: str,
        indicators: Dict[str, Any],
        all_text: str,
        spl: str,
        sourcetypes: Set[str],
        fields: Set[str],
        indexes: Set[str],
        datamodels: Set[str],
        mitre_tags: Set[str],
    ) -> Optional[EnhancedMappingMatch]:
        """Evaluate a single technique against detection data."""
        scores = SignalScores()
        evidence = {
            'data_sources': {},
            'fields': {},
            'patterns': [],
            'tag_match': False,
        }

        # 1. Data Source Score (0.25 weight)
        ds_score, ds_evidence = self._score_data_sources(
            indicators.get('data_sources', {}),
            sourcetypes, indexes, datamodels
        )
        scores.data_source = ds_score
        evidence['data_sources'] = ds_evidence

        # 2. Field Indicator Score (0.30 weight)
        field_score, field_evidence = self._score_field_indicators(
            indicators.get('field_indicators', {}),
            fields
        )
        scores.field_indicator = field_score
        evidence['fields'] = field_evidence

        # 3. Behavioral Pattern Score (0.35 weight)
        pattern_score, pattern_evidence = self._score_behavioral_patterns(
            indicators.get('behavioral_patterns', []),
            spl, all_text
        )
        scores.behavioral = pattern_score
        evidence['patterns'] = pattern_evidence

        # 4. Tag Confirmation Score (0.10 weight)
        tag_score = self._score_tag_confirmation(technique_id, mitre_tags)
        scores.tag_confirmation = tag_score
        evidence['tag_match'] = tag_score > 0

        # Calculate final weighted score
        final_score = (
            scores.data_source * SIGNAL_WEIGHTS['data_source'] +
            scores.field_indicator * SIGNAL_WEIGHTS['field_indicator'] +
            scores.behavioral * SIGNAL_WEIGHTS['behavioral'] +
            scores.tag_confirmation * SIGNAL_WEIGHTS['tag_confirmation']
        )

        # Determine confidence level
        confidence_level = self._get_confidence_level(final_score)

        # Build rationale
        rationale = self._build_rationale(
            technique_id, indicators.get('name', technique_id),
            scores, evidence
        )

        return EnhancedMappingMatch(
            technique_id=technique_id,
            technique_name=indicators.get('name', technique_id),
            final_score=final_score,
            confidence_level=confidence_level,
            signal_scores=scores,
            evidence=evidence,
            rationale=rationale,
        )

    def _score_data_sources(
        self,
        ds_config: Dict[str, Any],
        sourcetypes: Set[str],
        indexes: Set[str],
        datamodels: Set[str],
    ) -> Tuple[float, Dict[str, List[str]]]:
        """
        Score based on data source matching.

        Returns score (0-1) and evidence of matches.
        """
        evidence = {'matched_sourcetypes': [], 'matched_indexes': [], 'matched_datamodels': []}

        if not ds_config:
            return 0.0, evidence

        max_score = 0.0

        # Check strong matches (weight: 1.0)
        strong = ds_config.get('strong', {})
        if strong:
            strong_score, strong_evidence = self._check_ds_match(
                strong, sourcetypes, indexes, datamodels, 1.0
            )
            if strong_score > max_score:
                max_score = strong_score
                evidence = strong_evidence

        # Check moderate matches (weight: 0.6)
        moderate = ds_config.get('moderate', {})
        if moderate:
            mod_score, mod_evidence = self._check_ds_match(
                moderate, sourcetypes, indexes, datamodels, 0.6
            )
            if mod_score > max_score:
                max_score = mod_score
                evidence = mod_evidence

        return max_score, evidence

    def _check_ds_match(
        self,
        config: Dict[str, Any],
        sourcetypes: Set[str],
        indexes: Set[str],
        datamodels: Set[str],
        weight: float,
    ) -> Tuple[float, Dict[str, List[str]]]:
        """Check data source matches with given weight."""
        evidence = {'matched_sourcetypes': [], 'matched_indexes': [], 'matched_datamodels': []}
        matches = 0
        total_checks = 0

        # Check sourcetypes
        expected_st = config.get('sourcetypes', [])
        if expected_st:
            total_checks += 1
            for st in expected_st:
                st_lower = st.lower()
                for actual_st in sourcetypes:
                    if st_lower in actual_st or actual_st in st_lower:
                        evidence['matched_sourcetypes'].append(actual_st)
                        matches += 1
                        break

        # Check indexes
        expected_idx = config.get('indexes', [])
        if expected_idx:
            total_checks += 1
            for idx in expected_idx:
                idx_lower = idx.lower()
                for actual_idx in indexes:
                    if idx_lower in actual_idx or actual_idx in idx_lower:
                        evidence['matched_indexes'].append(actual_idx)
                        matches += 1
                        break

        # Check datamodels
        expected_dm = config.get('datamodels', [])
        if expected_dm:
            total_checks += 1
            for dm in expected_dm:
                dm_lower = dm.lower()
                for actual_dm in datamodels:
                    if dm_lower in actual_dm or actual_dm in dm_lower:
                        evidence['matched_datamodels'].append(actual_dm)
                        matches += 1
                        break

        if total_checks == 0:
            return 0.0, evidence

        score = (matches / total_checks) * weight
        return score, evidence

    def _score_field_indicators(
        self,
        field_config: Dict[str, Any],
        fields: Set[str],
    ) -> Tuple[float, Dict[str, List[str]]]:
        """
        Score based on field indicator matching.

        Returns score (0-1) and evidence of matches.
        """
        evidence = {'matched_strong': [], 'matched_moderate': []}

        if not field_config or not fields:
            return 0.0, evidence

        max_score = 0.0

        # Check strong field indicators (weight: 1.0)
        strong_fields = field_config.get('strong', [])
        if strong_fields:
            strong_matched = []
            for expected in strong_fields:
                expected_lower = expected.lower()
                for actual in fields:
                    if expected_lower == actual or expected_lower in actual:
                        strong_matched.append(actual)
                        break

            if strong_matched:
                score = min(len(strong_matched) / len(strong_fields), 1.0)
                if score > max_score:
                    max_score = score
                    evidence['matched_strong'] = strong_matched

        # Check moderate field indicators (weight: 0.6)
        moderate_fields = field_config.get('moderate', [])
        if moderate_fields:
            mod_matched = []
            for expected in moderate_fields:
                expected_lower = expected.lower()
                for actual in fields:
                    if expected_lower == actual or expected_lower in actual:
                        mod_matched.append(actual)
                        break

            if mod_matched:
                score = min(len(mod_matched) / len(moderate_fields), 1.0) * 0.6
                if score > max_score:
                    max_score = score
                    evidence['matched_moderate'] = mod_matched

        return max_score, evidence

    def _score_behavioral_patterns(
        self,
        patterns: List[Dict[str, Any]],
        spl: str,
        all_text: str,
    ) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Score based on behavioral pattern matching.

        Returns the highest matching pattern score (0-1) and evidence.
        """
        evidence = []

        if not patterns:
            return 0.0, evidence

        max_score = 0.0

        for pattern_config in patterns:
            pattern = pattern_config.get('pattern', '')
            weight = pattern_config.get('weight', 0.5)
            description = pattern_config.get('description', '')

            try:
                # Check against SPL first (more specific)
                if re.search(pattern, spl, re.IGNORECASE):
                    evidence.append({
                        'pattern': pattern,
                        'weight': weight,
                        'description': description,
                        'matched_in': 'spl',
                    })
                    if weight > max_score:
                        max_score = weight
                # Also check against all text (name, description)
                elif re.search(pattern, all_text, re.IGNORECASE):
                    evidence.append({
                        'pattern': pattern,
                        'weight': weight * 0.8,  # Slight penalty for non-SPL match
                        'description': description,
                        'matched_in': 'text',
                    })
                    adjusted_weight = weight * 0.8
                    if adjusted_weight > max_score:
                        max_score = adjusted_weight
            except re.error:
                # Invalid regex, skip
                continue

        return max_score, evidence

    def _score_tag_confirmation(
        self,
        technique_id: str,
        mitre_tags: Set[str],
    ) -> float:
        """
        Score based on original MITRE tag confirmation.

        Returns 1.0 if technique or parent matches, 0.0 otherwise.
        """
        if not mitre_tags:
            return 0.0

        technique_upper = technique_id.upper()

        # Direct match
        if technique_upper in mitre_tags:
            return 1.0

        # Check for technique variants (T1059 matches T1059.001)
        for tag in mitre_tags:
            if technique_upper.startswith(tag) or tag.startswith(technique_upper):
                return 0.8

        # Check parent technique
        if '.' in technique_id:
            parent_id = technique_id.split('.')[0].upper()
            if parent_id in mitre_tags:
                return 0.7

        return 0.0

    def _get_confidence_level(self, score: float) -> str:
        """Get confidence level string from score."""
        if score >= self.thresholds['high']:
            return 'high'
        elif score >= self.thresholds['medium']:
            return 'medium'
        elif score >= self.thresholds['low']:
            return 'low'
        return 'none'

    def _build_rationale(
        self,
        technique_id: str,
        technique_name: str,
        scores: SignalScores,
        evidence: Dict[str, Any],
    ) -> str:
        """Build human-readable rationale for the mapping."""
        parts = []

        # Data source rationale
        ds_evidence = evidence.get('data_sources', {})
        ds_matched = (
            ds_evidence.get('matched_sourcetypes', []) +
            ds_evidence.get('matched_indexes', []) +
            ds_evidence.get('matched_datamodels', [])
        )
        if ds_matched:
            parts.append(f"Data sources ({', '.join(ds_matched[:3])}) align with {technique_id}")

        # Field rationale
        field_evidence = evidence.get('fields', {})
        fields_matched = (
            field_evidence.get('matched_strong', []) +
            field_evidence.get('matched_moderate', [])
        )
        if fields_matched:
            parts.append(f"Fields ({', '.join(fields_matched[:3])}) indicate {technique_name}")

        # Pattern rationale
        patterns = evidence.get('patterns', [])
        if patterns:
            best_pattern = max(patterns, key=lambda p: p.get('weight', 0))
            parts.append(f"Pattern match: {best_pattern.get('description', 'behavioral indicator')}")

        # Tag rationale
        if evidence.get('tag_match'):
            parts.append(f"Original MITRE tags confirm {technique_id}")

        if not parts:
            return f"Low confidence match to {technique_name} ({technique_id})"

        return "; ".join(parts)

    def get_tactic_criticality(self, tactic: str) -> float:
        """Get criticality weight for a tactic (for recommendations)."""
        return self.tactic_criticality.get(tactic.lower(), 0.5)

    def get_indicators_summary(self) -> Dict[str, Any]:
        """Get summary of loaded indicators."""
        techniques_by_tactic: Dict[str, List[str]] = {}

        for tech_id, indicators in self.indicators.items():
            tactic = indicators.get('tactic', 'unknown')
            if tactic not in techniques_by_tactic:
                techniques_by_tactic[tactic] = []
            techniques_by_tactic[tactic].append(tech_id)

        return {
            'total_techniques': len(self.indicators),
            'techniques_by_tactic': techniques_by_tactic,
            'tactic_count': len(techniques_by_tactic),
            'thresholds': self.thresholds,
        }


# Factory function to get the appropriate mapper
def get_mapper(enhanced: bool = True) -> Any:
    """
    Get the appropriate MITRE mapper.

    Args:
        enhanced: If True, use enhanced multi-signal mapper. Otherwise, use rule-based.

    Returns:
        Mapper instance
    """
    if enhanced:
        return EnhancedMitreMapper()
    else:
        from app.services.mitre_mapper import MitreMapper
        return MitreMapper()
