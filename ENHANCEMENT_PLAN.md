# CSF×ATT&CK Mapper Enhancement Plan

## Executive Summary

This plan addresses two major enhancements:
1. **Enhanced MITRE Mapping** - A deterministic multi-signal scoring system for SPL analysis
2. **Sophisticated Recommendation Engine** - Consistent, weighted recommendations based on risk/impact

---

## Part 1: Enhanced MITRE Technique Mapping

### Current State Analysis

The current `MitreMapper` uses rule-based matching with:
- Keyword matching (any_keywords, all_keywords)
- Sourcetype/field/index matching
- Regex patterns
- Event ID matching

**Limitations:**
1. Only ~40 rules covering ~30 techniques (out of 200+ techniques)
2. No semantic understanding of what SPL is detecting
3. Limited data source correlation
4. No behavioral pattern library

### Proposed: Multi-Signal Scoring System

A **deterministic** scoring system that produces identical results for identical inputs:

```
Final Technique Score = Σ(Signal_Weight × Signal_Match_Score)
```

#### Signal Categories and Weights

| Signal Type | Weight | Description |
|------------|--------|-------------|
| Data Source Match | 0.25 | SPL data sources align with technique's required data sources |
| Field Indicator Match | 0.30 | Referenced fields suggest technique behavior |
| Behavioral Pattern Match | 0.35 | SPL contains technique-specific detection patterns |
| Tag Confirmation | 0.10 | Original MITRE tags from detection confirm technique |

#### Implementation: Technique Indicator Database

Create a comprehensive indicator database in YAML:

```yaml
# technique_indicators.yml
indicators:
  T1059.001:  # PowerShell
    name: "PowerShell"
    tactic: "execution"

    data_sources:
      strong:  # Weight: 1.0
        - index: ["wineventlog", "windows"]
        - sourcetype: ["powershell", "xmlwineventlog:microsoft-windows-powershell"]
        - datamodel: ["Endpoint"]
      moderate:  # Weight: 0.6
        - sourcetype: ["sysmon"]

    field_indicators:
      strong:  # Weight: 1.0
        - ["process_name", "powershell"]
        - ["commandline", "parent_process"]
      moderate:  # Weight: 0.6
        - ["user", "dest"]

    behavioral_patterns:
      # High-confidence patterns (Weight: 0.8-1.0)
      - pattern: "(?i)powershell.*-enc"
        weight: 0.95
        description: "Encoded command execution"
      - pattern: "(?i)powershell.*-nop.*-w.*hidden"
        weight: 0.9
        description: "Hidden execution with no profile"
      - pattern: "(?i)downloadstring|invoke-webrequest"
        weight: 0.85
        description: "Remote content download"

      # Medium-confidence patterns (Weight: 0.5-0.7)
      - pattern: "(?i)invoke-expression|iex\\s*\\("
        weight: 0.7
        description: "Dynamic code execution"
      - pattern: "(?i)powershell"
        weight: 0.4
        description: "Basic PowerShell reference"

    event_ids:
      strong:  # Weight: 1.0
        - 4103  # Module logging
        - 4104  # Script block logging
      moderate:  # Weight: 0.6
        - 4688  # Process creation
```

#### Scoring Algorithm

```python
def calculate_technique_score(detection, technique_indicators):
    """
    Deterministic technique scoring.

    Returns: float between 0.0 and 1.0
    """
    scores = {
        'data_source': 0.0,
        'field_indicator': 0.0,
        'behavioral': 0.0,
        'tag_confirmation': 0.0
    }

    # 1. Data Source Score (0.25 weight)
    ds_matches = match_data_sources(detection.artifacts, technique_indicators['data_sources'])
    scores['data_source'] = ds_matches['score']  # 0.0 to 1.0

    # 2. Field Indicator Score (0.30 weight)
    field_matches = match_fields(detection.artifacts, technique_indicators['field_indicators'])
    scores['field_indicator'] = field_matches['score']  # 0.0 to 1.0

    # 3. Behavioral Pattern Score (0.35 weight)
    pattern_matches = match_patterns(detection.spl, technique_indicators['behavioral_patterns'])
    scores['behavioral'] = pattern_matches['best_score']  # Highest matching pattern

    # 4. Tag Confirmation Score (0.10 weight)
    if technique_id in detection.original_mitre_tags:
        scores['tag_confirmation'] = 1.0

    # Calculate final weighted score
    final_score = (
        scores['data_source'] * 0.25 +
        scores['field_indicator'] * 0.30 +
        scores['behavioral'] * 0.35 +
        scores['tag_confirmation'] * 0.10
    )

    return final_score, scores  # Return both for evidence
```

#### Confidence Thresholds

| Score Range | Confidence Level | Action |
|------------|------------------|--------|
| ≥ 0.70 | High | Auto-accept mapping |
| 0.45 - 0.69 | Medium | Accept with review flag |
| 0.25 - 0.44 | Low | Suggest for review |
| < 0.25 | None | Don't map |

### Determinism Guarantee

The system is deterministic because:
1. All inputs are from the database (SPL, artifacts, tags)
2. All pattern matching uses fixed regex (no fuzzy matching)
3. All weights are configuration constants
4. No randomness or ML inference
5. **Same detection → Same extracted features → Same scores → Same mappings**

---

## Part 2: Sophisticated Recommendation Engine

### Current State Analysis

Current recommendations are:
- Sequentially prioritized (1, 2, 3...)
- Static impact estimates (15%, 12%, 8%)
- Simple severity logic (initial-access = high)

### Proposed: Multi-Dimensional Scoring

#### Scoring Dimensions

1. **Coverage Gap Score (0-1)** - How critical is this gap?
   - Technique prevalence in threat landscape
   - Kill chain position importance
   - Number of related techniques affected

2. **Impact Score (0-1)** - What's the benefit of addressing?
   - CSF functions affected
   - Number of techniques that would be covered
   - Alignment with organizational priorities

3. **Effort Score (0-1)** - How hard to implement?
   - Data sources available in environment
   - Similar detections already exist
   - Complexity of technique to detect

4. **Risk Score (0-1)** - What's the risk of NOT addressing?
   - Tactic criticality (initial-access > discovery)
   - Technique severity
   - Dwell time implications

#### Final Priority Formula

```python
def calculate_priority(gap):
    """
    Deterministic priority calculation.

    Higher score = Higher priority
    """
    coverage_gap = calculate_coverage_gap_score(gap)
    impact = calculate_impact_score(gap)
    effort = calculate_effort_score(gap)
    risk = calculate_risk_score(gap)

    # Weighted combination
    priority_score = (
        coverage_gap * 0.30 +
        impact * 0.25 +
        (1 - effort) * 0.15 +  # Lower effort = higher priority
        risk * 0.30
    )

    return priority_score
```

#### Tactic Criticality Weights (Risk Score Component)

```python
TACTIC_CRITICALITY = {
    'initial-access': 1.0,      # Entry point - critical
    'execution': 0.95,          # Running malicious code
    'persistence': 0.90,        # Maintaining access
    'privilege-escalation': 0.90,
    'defense-evasion': 0.85,
    'credential-access': 0.85,
    'lateral-movement': 0.80,
    'collection': 0.70,
    'command-and-control': 0.75,
    'exfiltration': 0.80,
    'impact': 0.75,
    'discovery': 0.50,          # Often noisy, less critical
    'reconnaissance': 0.60,
    'resource-development': 0.40,
}
```

#### Recommendation Types

| Type | Description | Base Impact |
|------|-------------|-------------|
| `add_detection` | Create new detection for uncovered technique | 0.15 |
| `enhance_detection` | Improve low-confidence mapping | 0.10 |
| `enable_detection` | Enable disabled but valuable detection | 0.12 |
| `tune_detection` | Fix quality issues (complexity, thresholds) | 0.08 |
| `add_data_source` | Enable new coverage area | 0.20 |
| `reduce_redundancy` | Consolidate overlapping detections | 0.05 |

#### Determinism Guarantee

Same as mapping - all inputs are static database values with fixed weights.

---

## Implementation Plan

### Phase 1: Enhanced MITRE Mapping (Files to Create/Modify)

1. **Create**: `mappings/technique_indicators.yml`
   - Comprehensive indicator database for 50+ high-priority techniques
   - Focus on: Execution, Credential Access, Persistence, Defense Evasion

2. **Modify**: `backend/app/services/mitre_mapper.py`
   - Add `EnhancedMitreMapper` class
   - Implement multi-signal scoring
   - Generate detailed evidence for each mapping

3. **Modify**: `backend/app/services/ingest_pipeline.py`
   - Use enhanced mapper
   - Store scoring details in evidence field

### Phase 2: Sophisticated Recommendations (Files to Create/Modify)

1. **Create**: `backend/app/services/recommendation_engine.py`
   - New class with multi-dimensional scoring
   - Configurable weights
   - Detailed rationale generation

2. **Modify**: `backend/app/services/coverage_analyzer.py`
   - Use new recommendation engine
   - Add more gap detection logic

3. **Modify**: Frontend `Recommendations.tsx`
   - Display scoring breakdown
   - Show improvement path

### Phase 3: Configuration & Testing

1. **Create**: `backend/app/config/scoring_weights.py`
   - Centralized weight configuration
   - Easy tuning without code changes

2. **Create**: Unit tests for determinism verification
   - Same input → Same output tests
   - Regression tests for scoring

---

## Priority Technique Coverage

### Tier 1 (Immediate - 20 Techniques)

| ID | Name | Tactic | Priority |
|----|------|--------|----------|
| T1059.001 | PowerShell | Execution | Critical |
| T1059.003 | Windows Command Shell | Execution | Critical |
| T1003.001 | LSASS Memory | Credential Access | Critical |
| T1110 | Brute Force | Credential Access | High |
| T1547.001 | Registry Run Keys | Persistence | High |
| T1053.005 | Scheduled Task | Persistence | High |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | High |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | High |
| T1070.001 | Clear Windows Event Logs | Defense Evasion | High |
| T1055 | Process Injection | Defense Evasion | High |
| T1566.001 | Spearphishing Attachment | Initial Access | Critical |
| T1078 | Valid Accounts | Defense Evasion | High |
| T1047 | Windows Management Instrumentation | Execution | High |
| T1218.005 | Mshta | Defense Evasion | Medium |
| T1218.011 | Rundll32 | Defense Evasion | Medium |
| T1548.002 | Bypass User Account Control | Privilege Escalation | High |
| T1562.001 | Disable or Modify Tools | Defense Evasion | High |
| T1071.004 | DNS Tunneling | Command and Control | Medium |
| T1027 | Obfuscated Files or Information | Defense Evasion | Medium |
| T1482 | Domain Trust Discovery | Discovery | Medium |

### Tier 2 (Short-term - 30 Additional Techniques)

Cloud-focused: T1078.004, T1098.001, T1098.003, T1550.001
Lateral Movement: T1021.003, T1021.006
Collection: T1114, T1114.003
Additional Discovery: T1087, T1135

---

## Success Metrics

1. **Mapping Coverage**: Increase auto-mapped techniques from ~30 to 50+
2. **Mapping Accuracy**: >85% acceptance rate on auto-mappings
3. **Recommendation Relevance**: Consistent priority ordering
4. **Determinism**: 100% reproducible results

---

## Execution Order

1. Create technique indicators YAML (Tier 1 techniques)
2. Implement enhanced mapper with multi-signal scoring
3. Update ingest pipeline to use enhanced mapper
4. Create recommendation engine with weighted scoring
5. Update coverage analyzer to use new engine
6. Update frontend to display enhanced data
7. Test determinism and accuracy
8. Expand to Tier 2 techniques
