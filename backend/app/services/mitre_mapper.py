"""MITRE ATT&CK mapping service using rule-based matching."""
import re
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from app.config import settings


@dataclass
class MappingMatch:
    """Result of a single mapping rule match."""
    technique_id: str
    confidence: float
    rule_id: str
    rule_name: str
    rationale: str
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MappingResult:
    """Full mapping result for a detection."""
    matches: List[MappingMatch] = field(default_factory=list)
    total_rules_checked: int = 0


class MitreMapper:
    """Rule-based MITRE ATT&CK technique mapper."""

    def __init__(self, rules_path: Optional[Path] = None):
        """Initialize mapper with rules from YAML file."""
        self.rules_path = rules_path or settings.MAPPINGS_DIR / "mitre_rules_starter.yml"
        self.rules: List[Dict[str, Any]] = []
        self._load_rules()

    def _load_rules(self):
        """Load mapping rules from YAML file."""
        if not self.rules_path.exists():
            return

        with open(self.rules_path, 'r') as f:
            data = yaml.safe_load(f)

        if data and 'rules' in data:
            self.rules = data['rules']

    def reload_rules(self):
        """Reload rules from file."""
        self._load_rules()

    def map_detection(
        self,
        name: str,
        description: str,
        spl: str,
        sourcetypes: List[str] = None,
        fields: List[str] = None,
        indexes: List[str] = None,
        datamodels: List[str] = None,
    ) -> MappingResult:
        """
        Map a detection to MITRE techniques using rules.

        Args:
            name: Detection name
            description: Detection description
            spl: The SPL query
            sourcetypes: Extracted sourcetypes from SPL
            fields: Extracted fields from SPL
            indexes: Extracted indexes from SPL
            datamodels: Extracted datamodels from SPL

        Returns:
            MappingResult with all matches
        """
        result = MappingResult(total_rules_checked=len(self.rules))

        # Combine all text for keyword matching
        all_text = f"{name} {description} {spl}".lower()
        sourcetypes = [st.lower() for st in (sourcetypes or [])]
        fields = [f.lower() for f in (fields or [])]
        indexes = [idx.lower() for idx in (indexes or [])]
        datamodels = [dm.lower() for dm in (datamodels or [])]

        for rule in self.rules:
            match = self._evaluate_rule(
                rule=rule,
                all_text=all_text,
                sourcetypes=sourcetypes,
                fields=fields,
                indexes=indexes,
                datamodels=datamodels,
                spl=spl.lower(),
            )
            if match:
                result.matches.append(match)

        # Sort by confidence descending
        result.matches.sort(key=lambda m: m.confidence, reverse=True)

        return result

    def _evaluate_rule(
        self,
        rule: Dict[str, Any],
        all_text: str,
        sourcetypes: List[str],
        fields: List[str],
        indexes: List[str],
        datamodels: List[str],
        spl: str,
    ) -> Optional[MappingMatch]:
        """Evaluate a single rule against detection data."""
        match_config = rule.get('match', {})
        evidence = {}
        match_score = 0
        total_criteria = 0

        # Check any_keywords
        if 'any_keywords' in match_config:
            total_criteria += 1
            keywords = match_config['any_keywords']
            matched_keywords = [kw for kw in keywords if kw.lower() in all_text]
            if matched_keywords:
                match_score += 1
                evidence['matched_keywords'] = matched_keywords

        # Check all_keywords (all must match)
        if 'all_keywords' in match_config:
            total_criteria += 1
            keywords = match_config['all_keywords']
            all_matched = all(kw.lower() in all_text for kw in keywords)
            if all_matched:
                match_score += 1
                evidence['matched_all_keywords'] = keywords

        # Check any_sourcetypes
        if 'any_sourcetypes' in match_config:
            total_criteria += 1
            rule_sourcetypes = [st.lower() for st in match_config['any_sourcetypes']]
            matched_st = [st for st in sourcetypes if st in rule_sourcetypes]
            if matched_st:
                match_score += 1
                evidence['matched_sourcetypes'] = matched_st

        # Check any_fields
        if 'any_fields' in match_config:
            total_criteria += 1
            rule_fields = [f.lower() for f in match_config['any_fields']]
            matched_fields = [f for f in fields if f in rule_fields]
            if matched_fields:
                match_score += 1
                evidence['matched_fields'] = matched_fields

        # Check any_indexes
        if 'any_indexes' in match_config:
            total_criteria += 1
            rule_indexes = [idx.lower() for idx in match_config['any_indexes']]
            matched_idx = [idx for idx in indexes if idx in rule_indexes]
            if matched_idx:
                match_score += 1
                evidence['matched_indexes'] = matched_idx

        # Check any_datamodels
        if 'any_datamodels' in match_config:
            total_criteria += 1
            rule_datamodels = [dm.lower() for dm in match_config['any_datamodels']]
            matched_dm = [dm for dm in datamodels if dm in rule_datamodels]
            if matched_dm:
                match_score += 1
                evidence['matched_datamodels'] = matched_dm

        # Check any_regex
        if 'any_regex' in match_config:
            total_criteria += 1
            matched_regex = []
            for pattern in match_config['any_regex']:
                try:
                    if re.search(pattern, spl, re.IGNORECASE):
                        matched_regex.append(pattern)
                except re.error:
                    continue
            if matched_regex:
                match_score += 1
                evidence['matched_regex'] = matched_regex

        # Check any_event_ids
        if 'any_event_ids' in match_config:
            total_criteria += 1
            event_ids = match_config['any_event_ids']
            matched_events = []
            for eid in event_ids:
                # Look for EventCode=X, EventID=X, event_id=X patterns
                patterns = [
                    rf'EventCode\s*=\s*{eid}\b',
                    rf'EventID\s*=\s*{eid}\b',
                    rf'event_id\s*=\s*{eid}\b',
                    rf'signature_id\s*=\s*{eid}\b',
                ]
                for pattern in patterns:
                    if re.search(pattern, spl, re.IGNORECASE):
                        matched_events.append(str(eid))
                        break
            if matched_events:
                match_score += 1
                evidence['matched_event_ids'] = matched_events

        # Determine if rule matched
        if match_score == 0 or total_criteria == 0:
            return None

        # Calculate effective confidence
        # Base confidence from rule, adjusted by match coverage
        base_confidence = rule.get('confidence', 0.5)
        coverage_factor = match_score / total_criteria
        effective_confidence = base_confidence * (0.7 + 0.3 * coverage_factor)

        return MappingMatch(
            technique_id=rule['technique_id'],
            confidence=round(effective_confidence, 3),
            rule_id=rule.get('id', 'unknown'),
            rule_name=rule.get('name', 'Unknown Rule'),
            rationale=rule.get('rationale', 'Matched rule criteria'),
            evidence=evidence,
        )

    def get_rules_summary(self) -> Dict[str, Any]:
        """Get summary of loaded rules."""
        techniques = set()
        for rule in self.rules:
            techniques.add(rule.get('technique_id', ''))

        return {
            'total_rules': len(self.rules),
            'unique_techniques': len(techniques),
            'techniques': sorted(list(techniques)),
        }
