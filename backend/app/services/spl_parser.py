"""SPL (Splunk Processing Language) parser service."""
import re
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class SPLParseResult:
    """Result of SPL parsing."""
    indexes: List[str] = field(default_factory=list)
    sourcetypes: List[str] = field(default_factory=list)
    datamodels: List[str] = field(default_factory=list)
    macros: List[str] = field(default_factory=list)
    fields_referenced: List[str] = field(default_factory=list)
    commands_used: List[str] = field(default_factory=list)
    time_constraints: Dict[str, Any] = field(default_factory=dict)
    aggregations: Dict[str, Any] = field(default_factory=dict)
    thresholds: List[Dict[str, Any]] = field(default_factory=list)
    complexity_score: int = 0
    complexity_signals: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


class SPLParser:
    """Parser for Splunk Processing Language queries."""

    # Common SPL commands
    SPL_COMMANDS = [
        "search", "where", "stats", "eventstats", "streamstats", "tstats",
        "eval", "rex", "regex", "table", "fields", "rename", "sort",
        "dedup", "head", "tail", "top", "rare", "timechart", "chart",
        "transaction", "join", "lookup", "inputlookup", "outputlookup",
        "append", "appendpipe", "map", "foreach", "mvexpand", "makemv",
        "convert", "fillnull", "replace", "bin", "bucket", "span",
        "collect", "sendemail", "outputcsv", "return", "format"
    ]

    # Aggregation functions
    AGG_FUNCTIONS = [
        "count", "dc", "distinct_count", "sum", "avg", "mean", "min", "max",
        "stdev", "var", "range", "first", "last", "list", "values",
        "earliest", "latest", "rate", "per_second", "per_minute", "per_hour"
    ]

    def __init__(self):
        """Initialize SPL parser."""
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for parsing."""
        # Index pattern: index=value or index="value" or index IN (...)
        self.index_pattern = re.compile(
            r'index\s*=\s*["\']?([^"\'\s\|]+)["\']?|'
            r'index\s+IN\s*\(([^)]+)\)',
            re.IGNORECASE
        )

        # Sourcetype pattern
        self.sourcetype_pattern = re.compile(
            r'sourcetype\s*=\s*["\']?([^"\'\s\|]+)["\']?|'
            r'sourcetype\s+IN\s*\(([^)]+)\)',
            re.IGNORECASE
        )

        # Datamodel pattern (tstats usage or datamodel command)
        self.datamodel_pattern = re.compile(
            r'from\s+datamodel\s*=\s*["\']?([^"\'\s\|\.]+)|'
            r'\|\s*datamodel\s+([^\s\|]+)|'
            r'datamodel\s*=\s*["\']?([^"\'\s\|]+)',
            re.IGNORECASE
        )

        # Macro pattern: `macro_name` or `macro_name(args)`
        self.macro_pattern = re.compile(r'`([^`]+)`')

        # Time constraint patterns
        self.time_patterns = {
            'earliest': re.compile(r'earliest\s*=\s*([^\s\|]+)', re.IGNORECASE),
            'latest': re.compile(r'latest\s*=\s*([^\s\|]+)', re.IGNORECASE),
            'span': re.compile(r'span\s*=\s*([^\s\|]+)', re.IGNORECASE),
            'bin_span': re.compile(r'bin\s+[^|]*span\s*=\s*([^\s\|]+)', re.IGNORECASE),
        }

        # Threshold patterns: where count > N, where dc(x) > N, etc.
        self.threshold_pattern = re.compile(
            r'where\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\([^)]*\))?)\s*([><=!]+)\s*(\d+(?:\.\d+)?)',
            re.IGNORECASE
        )

        # Field reference patterns (simplified)
        self.field_pattern = re.compile(
            r'(?:by|over|groupby)\s+([a-zA-Z_][a-zA-Z0-9_,\s]+)|'
            r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=|'
            r'values?\(([a-zA-Z_][a-zA-Z0-9_]*)\)|'
            r'dc\(([a-zA-Z_][a-zA-Z0-9_]*)\)|'
            r'count\(([a-zA-Z_][a-zA-Z0-9_]*)\)',
            re.IGNORECASE
        )

        # Aggregation pattern
        self.agg_pattern = re.compile(
            r'\b(' + '|'.join(self.AGG_FUNCTIONS) + r')\s*\(',
            re.IGNORECASE
        )

    def parse(self, spl: str) -> SPLParseResult:
        """Parse SPL query and extract artifacts."""
        result = SPLParseResult()

        # Normalize SPL (handle multiline)
        spl_normalized = ' '.join(spl.split())

        # Extract indexes
        result.indexes = self._extract_indexes(spl_normalized)

        # Extract sourcetypes
        result.sourcetypes = self._extract_sourcetypes(spl_normalized)

        # Extract datamodels
        result.datamodels = self._extract_datamodels(spl_normalized)

        # Extract macros
        result.macros = self._extract_macros(spl_normalized)

        # Extract commands used
        result.commands_used = self._extract_commands(spl_normalized)

        # Extract time constraints
        result.time_constraints = self._extract_time_constraints(spl_normalized)

        # Extract aggregations
        result.aggregations = self._extract_aggregations(spl_normalized)

        # Extract thresholds
        result.thresholds = self._extract_thresholds(spl_normalized)

        # Extract field references
        result.fields_referenced = self._extract_fields(spl_normalized)

        # Calculate complexity
        result.complexity_score, result.complexity_signals = self._calculate_complexity(
            spl_normalized, result
        )

        return result

    def _extract_indexes(self, spl: str) -> List[str]:
        """Extract index values from SPL."""
        indexes = set()
        for match in self.index_pattern.finditer(spl):
            if match.group(1):
                indexes.add(match.group(1).strip('"\''))
            if match.group(2):
                # Handle IN clause
                for idx in match.group(2).split(','):
                    indexes.add(idx.strip().strip('"\''))
        return sorted(list(indexes))

    def _extract_sourcetypes(self, spl: str) -> List[str]:
        """Extract sourcetype values from SPL."""
        sourcetypes = set()
        for match in self.sourcetype_pattern.finditer(spl):
            if match.group(1):
                sourcetypes.add(match.group(1).strip('"\''))
            if match.group(2):
                for st in match.group(2).split(','):
                    sourcetypes.add(st.strip().strip('"\''))
        return sorted(list(sourcetypes))

    def _extract_datamodels(self, spl: str) -> List[str]:
        """Extract datamodel references from SPL."""
        datamodels = set()
        for match in self.datamodel_pattern.finditer(spl):
            for group in match.groups():
                if group:
                    datamodels.add(group.strip('"\''))
        return sorted(list(datamodels))

    def _extract_macros(self, spl: str) -> List[str]:
        """Extract macro references from SPL."""
        macros = []
        for match in self.macro_pattern.finditer(spl):
            macro_name = match.group(1)
            # Extract just the macro name (before any arguments)
            if '(' in macro_name:
                macro_name = macro_name.split('(')[0]
            macros.append(macro_name)
        return sorted(list(set(macros)))

    def _extract_commands(self, spl: str) -> List[str]:
        """Extract SPL commands used."""
        commands = set()
        spl_lower = spl.lower()

        for cmd in self.SPL_COMMANDS:
            # Match command at start, after pipe, or after whitespace
            pattern = rf'(?:^|\|)\s*{cmd}\b'
            if re.search(pattern, spl_lower):
                commands.add(cmd)

        return sorted(list(commands))

    def _extract_time_constraints(self, spl: str) -> Dict[str, Any]:
        """Extract time-related constraints."""
        constraints = {}

        for name, pattern in self.time_patterns.items():
            match = pattern.search(spl)
            if match:
                constraints[name] = match.group(1)

        return constraints

    def _extract_aggregations(self, spl: str) -> Dict[str, Any]:
        """Extract aggregation functions and their usage."""
        aggregations = {
            'functions': [],
            'group_by': [],
        }

        # Find aggregation functions
        for match in self.agg_pattern.finditer(spl):
            aggregations['functions'].append(match.group(1).lower())

        # Find group by fields
        by_pattern = re.compile(r'\bby\s+([a-zA-Z_][a-zA-Z0-9_,\s]+?)(?:\||$)', re.IGNORECASE)
        for match in by_pattern.finditer(spl):
            fields = [f.strip() for f in match.group(1).split(',')]
            aggregations['group_by'].extend(fields)

        aggregations['functions'] = sorted(list(set(aggregations['functions'])))
        aggregations['group_by'] = sorted(list(set(aggregations['group_by'])))

        return aggregations

    def _extract_thresholds(self, spl: str) -> List[Dict[str, Any]]:
        """Extract threshold conditions."""
        thresholds = []

        for match in self.threshold_pattern.finditer(spl):
            thresholds.append({
                'field': match.group(1),
                'operator': match.group(2),
                'value': float(match.group(3)),
            })

        return thresholds

    def _extract_fields(self, spl: str) -> List[str]:
        """Extract field references from SPL."""
        fields = set()

        # Common field patterns
        patterns = [
            r'by\s+([a-zA-Z_][a-zA-Z0-9_]+)',
            r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=(?!=)',
            r'values?\(([a-zA-Z_][a-zA-Z0-9_]*)\)',
            r'dc\(([a-zA-Z_][a-zA-Z0-9_]*)\)',
            r'count\(([a-zA-Z_][a-zA-Z0-9_]*)\)',
            r'sum\(([a-zA-Z_][a-zA-Z0-9_]*)\)',
            r'avg\(([a-zA-Z_][a-zA-Z0-9_]*)\)',
            r'\|\s*table\s+([a-zA-Z_][a-zA-Z0-9_,\s]+)',
            r'\|\s*fields\s+[+-]?([a-zA-Z_][a-zA-Z0-9_,\s]+)',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, spl, re.IGNORECASE):
                field_str = match.group(1)
                # Split on comma and clean
                for f in field_str.split(','):
                    clean = f.strip().strip('"\'')
                    if clean and not clean.startswith('_') and clean.lower() not in ['as', 'by', 'over']:
                        fields.add(clean)

        # Filter out SPL keywords and common non-fields
        keywords = {'search', 'where', 'stats', 'eval', 'table', 'fields', 'as', 'by', 'over', 'and', 'or', 'not'}
        fields = {f for f in fields if f.lower() not in keywords}

        return sorted(list(fields))

    def _calculate_complexity(self, spl: str, result: SPLParseResult) -> tuple:
        """Calculate complexity score and signals."""
        signals = {
            'pipe_count': spl.count('|'),
            'subsearch_count': spl.count('['),
            'join_count': result.commands_used.count('join'),
            'transaction_count': result.commands_used.count('transaction'),
            'lookup_count': result.commands_used.count('lookup') + result.commands_used.count('inputlookup'),
            'macro_count': len(result.macros),
            'uses_tstats': 'tstats' in result.commands_used,
            'data_source_count': len(result.indexes) + len(result.sourcetypes) + len(result.datamodels),
            'has_thresholds': len(result.thresholds) > 0,
            'aggregation_count': len(result.aggregations.get('functions', [])),
        }

        # Calculate score (0-100)
        score = 10  # Base score

        # Add points for complexity indicators
        score += signals['pipe_count'] * 3
        score += signals['subsearch_count'] * 10
        score += signals['join_count'] * 15
        score += signals['transaction_count'] * 12
        score += signals['lookup_count'] * 5
        score += signals['macro_count'] * 3
        score += signals['aggregation_count'] * 2

        # Reduce score if using efficient patterns
        if signals['uses_tstats']:
            score = max(0, score - 10)

        # Cap at 100
        score = min(100, score)

        return score, signals
