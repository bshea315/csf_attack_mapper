"""CSF 2.0 impact calculator service."""
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from app.config import settings


@dataclass
class CSFImpact:
    """CSF impact score for a single category."""
    csf_id: str
    function: str
    category: str
    impact_score: float
    contributing_techniques: List[str] = field(default_factory=list)
    contributing_weights: List[float] = field(default_factory=list)


@dataclass
class CSFCalculationResult:
    """Full CSF calculation result."""
    impacts: List[CSFImpact] = field(default_factory=list)
    function_scores: Dict[str, float] = field(default_factory=dict)
    overall_score: float = 0.0


class CSFCalculator:
    """Calculator for CSF 2.0 impact scores from MITRE mappings."""

    # CSF 2.0 Functions
    CSF_FUNCTIONS = ['GOVERN', 'IDENTIFY', 'PROTECT', 'DETECT', 'RESPOND', 'RECOVER']

    def __init__(self, crosswalk_path: Optional[Path] = None):
        """Initialize calculator with crosswalk mapping."""
        self.crosswalk_path = crosswalk_path or settings.MAPPINGS_DIR / "mitre_to_csf_starter.yml"
        self.crosswalk: Dict[str, List[Dict[str, Any]]] = {}  # technique_id -> list of CSF mappings
        self._load_crosswalk()

    def _load_crosswalk(self):
        """Load MITRE to CSF crosswalk from YAML file."""
        if not self.crosswalk_path.exists():
            return

        with open(self.crosswalk_path, 'r') as f:
            data = yaml.safe_load(f)

        if data and 'mappings' in data:
            for mapping in data['mappings']:
                technique_id = mapping.get('technique_id')
                if technique_id:
                    if technique_id not in self.crosswalk:
                        self.crosswalk[technique_id] = []
                    self.crosswalk[technique_id].append({
                        'csf_id': mapping.get('csf', {}).get('subcategory') or mapping.get('csf', {}).get('category'),
                        'function': mapping.get('csf', {}).get('function'),
                        'category': mapping.get('csf', {}).get('category'),
                        'weight': mapping.get('weight', 0.5),
                        'rationale': mapping.get('rationale', ''),
                    })

    def reload_crosswalk(self):
        """Reload crosswalk from file."""
        self.crosswalk = {}
        self._load_crosswalk()

    def calculate_impacts(
        self,
        technique_mappings: List[Dict[str, Any]],
    ) -> CSFCalculationResult:
        """
        Calculate CSF impacts from MITRE technique mappings.

        Args:
            technique_mappings: List of dicts with 'technique_id' and 'confidence'

        Returns:
            CSFCalculationResult with all impact scores
        """
        result = CSFCalculationResult()

        # Aggregate impacts by CSF category
        csf_impacts: Dict[str, CSFImpact] = {}

        for mapping in technique_mappings:
            technique_id = mapping.get('technique_id')
            confidence = mapping.get('confidence', 1.0)

            # Get CSF mappings for this technique
            csf_mappings = self.crosswalk.get(technique_id, [])

            # Also check parent technique if this is a sub-technique
            if '.' in technique_id:
                parent_id = technique_id.split('.')[0]
                csf_mappings.extend(self.crosswalk.get(parent_id, []))

            for csf_mapping in csf_mappings:
                csf_id = csf_mapping['csf_id']
                weight = csf_mapping['weight']
                function = csf_mapping['function']
                category = csf_mapping['category']

                # Calculate impact score: technique confidence * crosswalk weight
                impact = confidence * weight

                if csf_id not in csf_impacts:
                    csf_impacts[csf_id] = CSFImpact(
                        csf_id=csf_id,
                        function=function,
                        category=category,
                        impact_score=0.0,
                    )

                # Aggregate impact (use max for same technique, sum across techniques)
                if technique_id not in csf_impacts[csf_id].contributing_techniques:
                    csf_impacts[csf_id].impact_score += impact
                    csf_impacts[csf_id].contributing_techniques.append(technique_id)
                    csf_impacts[csf_id].contributing_weights.append(weight)

        # Normalize scores (cap at 1.0)
        for csf_id, impact in csf_impacts.items():
            impact.impact_score = min(1.0, impact.impact_score)

        result.impacts = list(csf_impacts.values())

        # Calculate function-level scores
        function_impacts: Dict[str, List[float]] = {f: [] for f in self.CSF_FUNCTIONS}
        for impact in result.impacts:
            if impact.function in function_impacts:
                function_impacts[impact.function].append(impact.impact_score)

        for function, scores in function_impacts.items():
            if scores:
                result.function_scores[function] = sum(scores) / len(scores)
            else:
                result.function_scores[function] = 0.0

        # Calculate overall score (average of function scores)
        if result.function_scores:
            result.overall_score = sum(result.function_scores.values()) / len(result.function_scores)

        return result

    def get_csf_for_technique(self, technique_id: str) -> List[Dict[str, Any]]:
        """Get CSF categories mapped to a specific technique."""
        mappings = self.crosswalk.get(technique_id, [])

        # Also check parent technique
        if '.' in technique_id:
            parent_id = technique_id.split('.')[0]
            mappings.extend(self.crosswalk.get(parent_id, []))

        return mappings

    def get_techniques_for_csf(self, csf_id: str) -> List[Dict[str, Any]]:
        """Get techniques mapped to a specific CSF category."""
        techniques = []
        for technique_id, mappings in self.crosswalk.items():
            for mapping in mappings:
                if mapping['csf_id'] == csf_id or mapping['category'] == csf_id:
                    techniques.append({
                        'technique_id': technique_id,
                        'weight': mapping['weight'],
                        'rationale': mapping['rationale'],
                    })
        return techniques

    def get_crosswalk_summary(self) -> Dict[str, Any]:
        """Get summary of loaded crosswalk."""
        techniques = set()
        csf_categories = set()
        functions_covered = set()

        for technique_id, mappings in self.crosswalk.items():
            techniques.add(technique_id)
            for mapping in mappings:
                csf_categories.add(mapping['csf_id'])
                functions_covered.add(mapping['function'])

        return {
            'total_techniques': len(techniques),
            'total_csf_categories': len(csf_categories),
            'functions_covered': sorted(list(functions_covered)),
            'total_mappings': sum(len(m) for m in self.crosswalk.values()),
        }
