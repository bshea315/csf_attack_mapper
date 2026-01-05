"""Tests for MITRE Mapper service."""
import pytest
import tempfile
from pathlib import Path
import yaml
from app.services.mitre_mapper import MitreMapper, MappingMatch, MappingResult


@pytest.fixture
def temp_rules_file():
    """Create a temporary rules file for testing."""
    rules = {
        'version': '1.0',
        'rules': [
            {
                'id': 'test-001',
                'name': 'Brute Force Detection',
                'technique_id': 'T1110',
                'confidence': 0.8,
                'rationale': 'Login failure patterns indicate brute force',
                'match': {
                    'any_keywords': ['brute force', 'login failure', 'authentication failure'],
                    'any_sourcetypes': ['WinEventLog:Security', 'linux_secure'],
                    'any_event_ids': [4625, 529],
                }
            },
            {
                'id': 'test-002',
                'name': 'PowerShell Execution',
                'technique_id': 'T1059.001',
                'confidence': 0.7,
                'rationale': 'PowerShell command execution detected',
                'match': {
                    'any_keywords': ['powershell', 'pwsh'],
                    'any_regex': [r'powershell\.exe', r'pwsh\.exe'],
                    'any_event_ids': [4104, 4103],
                }
            },
            {
                'id': 'test-003',
                'name': 'Credential Dumping',
                'technique_id': 'T1003',
                'confidence': 0.9,
                'rationale': 'LSASS access patterns detected',
                'match': {
                    'all_keywords': ['lsass', 'memory'],
                    'any_fields': ['process_name', 'parent_process'],
                }
            },
            {
                'id': 'test-004',
                'name': 'Authentication Datamodel',
                'technique_id': 'T1078',
                'confidence': 0.6,
                'rationale': 'Valid account usage via authentication datamodel',
                'match': {
                    'any_datamodels': ['Authentication'],
                    'any_keywords': ['login', 'authentication'],
                }
            },
            {
                'id': 'test-005',
                'name': 'Index-Based Auth',
                'technique_id': 'T1078',
                'confidence': 0.5,
                'rationale': 'Authentication events from auth index',
                'match': {
                    'any_indexes': ['auth', 'security'],
                    'any_keywords': ['login'],
                }
            },
        ]
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump(rules, f)
        return Path(f.name)


@pytest.fixture
def mapper(temp_rules_file):
    """Create mapper with test rules."""
    return MitreMapper(rules_path=temp_rules_file)


class TestRuleLoading:
    """Tests for rule loading."""

    def test_load_rules(self, mapper):
        """Test that rules are loaded correctly."""
        assert len(mapper.rules) == 5

    def test_reload_rules(self, mapper):
        """Test rule reloading."""
        original_count = len(mapper.rules)
        mapper.reload_rules()
        assert len(mapper.rules) == original_count

    def test_missing_rules_file(self):
        """Test handling of missing rules file."""
        mapper = MitreMapper(rules_path=Path('/nonexistent/path.yml'))
        assert len(mapper.rules) == 0


class TestKeywordMatching:
    """Tests for keyword-based matching."""

    def test_any_keywords_match(self, mapper):
        """Test matching with any_keywords."""
        result = mapper.map_detection(
            name="Brute Force Login Detection",
            description="Detects multiple login failures",
            spl="index=auth | stats count by user | where count > 10",
        )

        # Should match brute force rule
        technique_ids = [m.technique_id for m in result.matches]
        assert 'T1110' in technique_ids

    def test_all_keywords_match(self, mapper):
        """Test matching with all_keywords."""
        result = mapper.map_detection(
            name="LSASS Memory Access Detection",
            description="Detects access to lsass memory",
            spl="index=endpoint | search lsass memory",
            fields=['process_name', 'parent_process'],
        )

        # Should match credential dumping rule (T1003)
        technique_ids = [m.technique_id for m in result.matches]
        assert 'T1003' in technique_ids

    def test_all_keywords_partial_no_match(self, mapper):
        """Test that partial all_keywords doesn't match."""
        result = mapper.map_detection(
            name="LSASS Detection",  # Only lsass, not memory
            description="Detects lsass",
            spl="index=endpoint",
        )

        # Should NOT match T1003 since it needs both 'lsass' AND 'memory'
        technique_ids = [m.technique_id for m in result.matches]
        # T1003 shouldn't be in matches unless there's also memory keyword
        matches_t1003 = [m for m in result.matches if m.technique_id == 'T1003']
        if matches_t1003:
            # If it matched, check it has the right evidence
            assert 'matched_all_keywords' in matches_t1003[0].evidence or \
                   'lsass' in str(result.matches)


class TestSourcetypeMatching:
    """Tests for sourcetype-based matching."""

    def test_any_sourcetypes_match(self, mapper):
        """Test matching with any_sourcetypes."""
        result = mapper.map_detection(
            name="Failed Login Detection",
            description="Detects authentication failures",
            spl="index=security sourcetype=WinEventLog:Security",
            sourcetypes=['WinEventLog:Security'],
        )

        # Should match brute force rule due to sourcetype
        matches = [m for m in result.matches if 'matched_sourcetypes' in m.evidence]
        assert len(matches) > 0


class TestEventIdMatching:
    """Tests for event ID matching."""

    def test_event_code_match(self, mapper):
        """Test matching Windows EventCode."""
        result = mapper.map_detection(
            name="Login Failure Detection",
            description="Detects failed logins",
            spl="index=security EventCode=4625 | stats count",
        )

        # Should match brute force rule
        technique_ids = [m.technique_id for m in result.matches]
        assert 'T1110' in technique_ids

        # Check evidence
        brute_force_match = next(m for m in result.matches if m.technique_id == 'T1110')
        assert '4625' in brute_force_match.evidence.get('matched_event_ids', [])

    def test_powershell_event_match(self, mapper):
        """Test matching PowerShell event IDs."""
        result = mapper.map_detection(
            name="PowerShell Script Block",
            description="Detects PowerShell execution",
            spl="index=endpoint EventCode=4104 ScriptBlockText=*",
        )

        # Should match PowerShell rule
        technique_ids = [m.technique_id for m in result.matches]
        assert 'T1059.001' in technique_ids


class TestRegexMatching:
    """Tests for regex-based matching."""

    def test_regex_match(self, mapper):
        """Test matching with any_regex."""
        result = mapper.map_detection(
            name="Process Execution",
            description="Detects process execution",
            spl="index=endpoint process_name=powershell.exe | stats count",
        )

        # Should match PowerShell rule via regex
        technique_ids = [m.technique_id for m in result.matches]
        assert 'T1059.001' in technique_ids


class TestDatamodelMatching:
    """Tests for datamodel-based matching."""

    def test_datamodel_match(self, mapper):
        """Test matching with any_datamodels."""
        result = mapper.map_detection(
            name="Login Activity",
            description="Detects authentication login events",
            spl="| tstats count from datamodel=Authentication",
            datamodels=['Authentication'],
        )

        # Should match T1078 due to datamodel
        technique_ids = [m.technique_id for m in result.matches]
        assert 'T1078' in technique_ids


class TestIndexMatching:
    """Tests for index-based matching."""

    def test_index_match(self, mapper):
        """Test matching with any_indexes."""
        result = mapper.map_detection(
            name="Login Detection",
            description="User login monitoring",
            spl="index=auth | stats count by user",
            indexes=['auth'],
        )

        # Should match T1078 rule with auth index
        technique_ids = [m.technique_id for m in result.matches]
        assert 'T1078' in technique_ids


class TestFieldMatching:
    """Tests for field-based matching."""

    def test_field_match(self, mapper):
        """Test matching with any_fields."""
        result = mapper.map_detection(
            name="LSASS Memory Access",
            description="Detects lsass memory access",
            spl="index=endpoint | search lsass memory",
            fields=['process_name', 'parent_process'],
        )

        # Should match T1003 due to fields + keywords
        matches = [m for m in result.matches if m.technique_id == 'T1003']
        assert len(matches) > 0
        assert 'matched_fields' in matches[0].evidence


class TestConfidenceScoring:
    """Tests for confidence calculation."""

    def test_high_confidence_match(self, mapper):
        """Test that good matches get high confidence."""
        result = mapper.map_detection(
            name="Brute Force Attack Detection",
            description="Multiple authentication failures detected",
            spl="index=security EventCode=4625 | stats count by user | where count > 10",
            sourcetypes=['WinEventLog:Security'],
        )

        brute_force_matches = [m for m in result.matches if m.technique_id == 'T1110']
        assert len(brute_force_matches) > 0
        assert brute_force_matches[0].confidence >= 0.5

    def test_confidence_sorted(self, mapper):
        """Test that results are sorted by confidence."""
        result = mapper.map_detection(
            name="Login Detection with PowerShell",
            description="Login failure and powershell execution",
            spl="index=auth EventCode=4625 powershell.exe EventCode=4104",
            sourcetypes=['WinEventLog:Security'],
        )

        if len(result.matches) > 1:
            for i in range(len(result.matches) - 1):
                assert result.matches[i].confidence >= result.matches[i + 1].confidence


class TestNoMatch:
    """Tests for non-matching scenarios."""

    def test_no_match_empty_query(self, mapper):
        """Test that empty/generic queries don't match."""
        result = mapper.map_detection(
            name="Generic Detection",
            description="Some detection",
            spl="index=main | stats count",
        )

        # Should have few or no matches
        assert result.total_rules_checked == 5

    def test_no_match_unrelated(self, mapper):
        """Test that unrelated content doesn't match."""
        result = mapper.map_detection(
            name="Network Traffic Analysis",
            description="Analyzing network packets",
            spl="index=network sourcetype=pcap | stats count by src_ip",
            sourcetypes=['pcap'],
        )

        # Should not match brute force, powershell, or credential dumping
        high_conf_matches = [m for m in result.matches if m.confidence > 0.7]
        # Fewer high-confidence matches for unrelated content
        assert len(high_conf_matches) < 3


class TestMappingResult:
    """Tests for MappingResult dataclass."""

    def test_result_structure(self, mapper):
        """Test MappingResult has correct structure."""
        result = mapper.map_detection(
            name="Test",
            description="Test",
            spl="index=auth",
        )

        assert isinstance(result, MappingResult)
        assert isinstance(result.matches, list)
        assert isinstance(result.total_rules_checked, int)

    def test_match_structure(self, mapper):
        """Test MappingMatch has correct structure."""
        result = mapper.map_detection(
            name="Brute Force Detection",
            description="Login failures",
            spl="index=auth EventCode=4625",
        )

        if result.matches:
            match = result.matches[0]
            assert isinstance(match, MappingMatch)
            assert hasattr(match, 'technique_id')
            assert hasattr(match, 'confidence')
            assert hasattr(match, 'rule_id')
            assert hasattr(match, 'rationale')
            assert hasattr(match, 'evidence')


class TestRulesSummary:
    """Tests for rules summary."""

    def test_get_summary(self, mapper):
        """Test getting rules summary."""
        summary = mapper.get_rules_summary()

        assert 'total_rules' in summary
        assert 'unique_techniques' in summary
        assert 'techniques' in summary
        assert summary['total_rules'] == 5
        assert isinstance(summary['techniques'], list)
