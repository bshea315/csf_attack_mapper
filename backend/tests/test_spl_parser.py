"""Tests for SPL Parser service."""
import pytest
from app.services.spl_parser import SPLParser, SPLParseResult


@pytest.fixture
def parser():
    """Create SPL parser instance."""
    return SPLParser()


class TestIndexExtraction:
    """Tests for index extraction."""

    def test_simple_index(self, parser):
        """Test extracting simple index."""
        spl = 'index=main | stats count'
        result = parser.parse(spl)
        assert result.indexes == ['main']

    def test_quoted_index(self, parser):
        """Test extracting quoted index."""
        spl = 'index="security_logs" | stats count'
        result = parser.parse(spl)
        assert result.indexes == ['security_logs']

    def test_multiple_indexes(self, parser):
        """Test extracting multiple indexes."""
        spl = 'index=main OR index=security | stats count'
        result = parser.parse(spl)
        assert sorted(result.indexes) == ['main', 'security']

    def test_index_in_clause(self, parser):
        """Test extracting indexes from IN clause."""
        spl = 'index IN (main, security, auth) | stats count'
        result = parser.parse(spl)
        assert sorted(result.indexes) == ['auth', 'main', 'security']


class TestSourcetypeExtraction:
    """Tests for sourcetype extraction."""

    def test_simple_sourcetype(self, parser):
        """Test extracting simple sourcetype."""
        spl = 'index=main sourcetype=syslog | stats count'
        result = parser.parse(spl)
        assert result.sourcetypes == ['syslog']

    def test_multiple_sourcetypes(self, parser):
        """Test extracting multiple sourcetypes."""
        spl = 'sourcetype=WinEventLog OR sourcetype=xmlwineventlog | stats count'
        result = parser.parse(spl)
        assert sorted(result.sourcetypes) == ['WinEventLog', 'xmlwineventlog']


class TestDatamodelExtraction:
    """Tests for datamodel extraction."""

    def test_tstats_datamodel(self, parser):
        """Test extracting datamodel from tstats."""
        spl = '| tstats count from datamodel=Authentication | where count > 10'
        result = parser.parse(spl)
        assert 'Authentication' in result.datamodels

    def test_multiple_datamodels(self, parser):
        """Test extracting multiple datamodels."""
        spl = '| tstats count from datamodel=Authentication | append [| tstats count from datamodel=Endpoint]'
        result = parser.parse(spl)
        assert 'Authentication' in result.datamodels
        assert 'Endpoint' in result.datamodels


class TestMacroExtraction:
    """Tests for macro extraction."""

    def test_simple_macro(self, parser):
        """Test extracting simple macro."""
        spl = '`security_content_ctime(firstTime)` | stats count'
        result = parser.parse(spl)
        assert 'security_content_ctime' in result.macros

    def test_multiple_macros(self, parser):
        """Test extracting multiple macros."""
        spl = '`my_index` `my_sourcetype` | `my_filter` | stats count'
        result = parser.parse(spl)
        assert len(result.macros) >= 2


class TestCommandExtraction:
    """Tests for command extraction."""

    def test_basic_commands(self, parser):
        """Test extracting basic commands."""
        spl = 'index=main | stats count by user | where count > 10 | table user count'
        result = parser.parse(spl)
        assert 'stats' in result.commands_used
        assert 'where' in result.commands_used
        assert 'table' in result.commands_used

    def test_tstats_command(self, parser):
        """Test detecting tstats command."""
        spl = '| tstats count from datamodel=Authentication by user'
        result = parser.parse(spl)
        assert 'tstats' in result.commands_used

    def test_join_command(self, parser):
        """Test detecting join command."""
        spl = 'index=main | join user [search index=users | table user role]'
        result = parser.parse(spl)
        assert 'join' in result.commands_used

    def test_transaction_command(self, parser):
        """Test detecting transaction command."""
        spl = 'index=auth | transaction session_id maxspan=30m | stats count'
        result = parser.parse(spl)
        assert 'transaction' in result.commands_used


class TestTimeConstraintExtraction:
    """Tests for time constraint extraction."""

    def test_earliest_latest(self, parser):
        """Test extracting earliest/latest."""
        spl = 'index=main earliest=-24h latest=now | stats count'
        result = parser.parse(spl)
        assert result.time_constraints.get('earliest') == '-24h'
        assert result.time_constraints.get('latest') == 'now'

    def test_span(self, parser):
        """Test extracting span."""
        spl = 'index=main | timechart span=1h count'
        result = parser.parse(spl)
        assert result.time_constraints.get('span') == '1h'


class TestThresholdExtraction:
    """Tests for threshold extraction."""

    def test_simple_threshold(self, parser):
        """Test extracting simple threshold."""
        spl = 'index=auth | stats count by user | where count > 10'
        result = parser.parse(spl)
        assert len(result.thresholds) == 1
        assert result.thresholds[0]['field'] == 'count'
        assert result.thresholds[0]['operator'] == '>'
        assert result.thresholds[0]['value'] == 10.0

    def test_multiple_thresholds(self, parser):
        """Test extracting multiple thresholds."""
        spl = 'index=auth | stats count dc(src) as unique_src by user | where count > 10 AND unique_src > 5'
        result = parser.parse(spl)
        assert len(result.thresholds) >= 1

    def test_function_threshold(self, parser):
        """Test extracting threshold with function."""
        spl = 'index=auth | stats dc(src) by user | where dc(src) > 50'
        result = parser.parse(spl)
        assert len(result.thresholds) >= 1


class TestAggregationExtraction:
    """Tests for aggregation extraction."""

    def test_stats_aggregations(self, parser):
        """Test extracting stats aggregations."""
        spl = 'index=main | stats count sum(bytes) avg(duration) by user'
        result = parser.parse(spl)
        assert 'count' in result.aggregations['functions']
        assert 'sum' in result.aggregations['functions']
        assert 'avg' in result.aggregations['functions']

    def test_group_by_fields(self, parser):
        """Test extracting group by fields."""
        spl = 'index=main | stats count by user, src_ip, dest_ip'
        result = parser.parse(spl)
        assert 'user' in result.aggregations['group_by']
        assert 'src_ip' in result.aggregations['group_by']


class TestComplexityScoring:
    """Tests for complexity scoring."""

    def test_simple_query_low_complexity(self, parser):
        """Test that simple queries have low complexity."""
        spl = 'index=main | stats count'
        result = parser.parse(spl)
        assert result.complexity_score < 30

    def test_complex_query_high_complexity(self, parser):
        """Test that complex queries have higher complexity."""
        spl = '''
        index=main
        | join user [search index=users | table user role]
        | transaction session_id maxspan=30m
        | eval risk = if(count > 10, "high", "low")
        | lookup user_info.csv user OUTPUT department
        | stats count by user department
        | where count > 5
        '''
        result = parser.parse(spl)
        assert result.complexity_score > 40

    def test_tstats_reduces_complexity(self, parser):
        """Test that tstats usage is considered efficient."""
        spl_regular = 'index=main | stats count by user'
        spl_tstats = '| tstats count from datamodel=Authentication by user'

        result_regular = parser.parse(spl_regular)
        result_tstats = parser.parse(spl_tstats)

        # tstats should have lower complexity for similar functionality
        assert result_tstats.complexity_signals['uses_tstats'] is True

    def test_subsearch_increases_complexity(self, parser):
        """Test that subsearches increase complexity."""
        spl_simple = 'index=main | stats count'
        spl_subsearch = 'index=main [search index=users | table user] | stats count'

        result_simple = parser.parse(spl_simple)
        result_subsearch = parser.parse(spl_subsearch)

        assert result_subsearch.complexity_signals['subsearch_count'] > 0
        assert result_subsearch.complexity_score > result_simple.complexity_score


class TestFieldExtraction:
    """Tests for field extraction."""

    def test_by_clause_fields(self, parser):
        """Test extracting fields from by clause."""
        spl = 'index=main | stats count by user, src_ip'
        result = parser.parse(spl)
        assert 'user' in result.fields_referenced

    def test_function_argument_fields(self, parser):
        """Test extracting fields from function arguments."""
        spl = 'index=main | stats dc(src_ip) sum(bytes) by user'
        result = parser.parse(spl)
        assert 'src_ip' in result.fields_referenced
        assert 'bytes' in result.fields_referenced


class TestRealWorldQueries:
    """Tests with real-world query patterns."""

    def test_brute_force_detection(self, parser):
        """Test parsing brute force detection query."""
        spl = '''
        index=auth action=failure
        | stats count by user, src_ip
        | where count > 10
        '''
        result = parser.parse(spl)
        assert result.indexes == ['auth']
        assert 'stats' in result.commands_used
        assert 'where' in result.commands_used
        assert len(result.thresholds) == 1

    def test_powershell_detection(self, parser):
        """Test parsing PowerShell detection query."""
        spl = '''
        index=endpoint sourcetype=WinEventLog EventCode=4104
        | rex field=ScriptBlockText "(?i)(Invoke-Mimikatz|Invoke-Empire)"
        | stats count by host, user
        '''
        result = parser.parse(spl)
        assert result.indexes == ['endpoint']
        assert 'WinEventLog' in result.sourcetypes
        assert 'rex' in result.commands_used

    def test_authentication_datamodel(self, parser):
        """Test parsing authentication datamodel query."""
        spl = '''
        | tstats `security_content_summariesonly`
        count min(_time) as firstTime max(_time) as lastTime
        from datamodel=Authentication where Authentication.action=failure
        by Authentication.user Authentication.src
        | `drop_dm_object_name("Authentication")`
        | where count > 5
        '''
        result = parser.parse(spl)
        assert 'Authentication' in result.datamodels
        assert 'tstats' in result.commands_used
        assert len(result.macros) >= 1


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_query(self, parser):
        """Test parsing empty query."""
        result = parser.parse('')
        assert result.indexes == []
        assert result.complexity_score >= 0

    def test_multiline_query(self, parser):
        """Test parsing multiline query."""
        spl = '''index=main
        | stats count
        | where count > 10'''
        result = parser.parse(spl)
        assert result.indexes == ['main']
        assert 'stats' in result.commands_used

    def test_special_characters(self, parser):
        """Test handling special characters."""
        spl = 'index=main user="admin@domain.com" | stats count'
        result = parser.parse(spl)
        assert result.indexes == ['main']


class TestSPLParseResult:
    """Tests for SPLParseResult dataclass."""

    def test_to_dict(self, parser):
        """Test converting result to dictionary."""
        spl = 'index=main | stats count'
        result = parser.parse(spl)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert 'indexes' in d
        assert 'complexity_score' in d

    def test_to_json(self, parser):
        """Test converting result to JSON."""
        spl = 'index=main | stats count'
        result = parser.parse(spl)
        json_str = result.to_json()
        assert isinstance(json_str, str)
        assert 'main' in json_str
