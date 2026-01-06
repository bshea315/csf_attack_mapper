"""Ingest pipeline for processing detection uploads."""
import csv
import io
import json
import re
import yaml
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.models.detection import Detection, DetectionVersion, IngestBatch
from app.models.spl_artifact import SplParseArtifact
from app.models.mitre import DetectionMitreMapping
from app.models.csf import DetectionCsfImpact
from app.services.spl_parser import SPLParser
from app.services.mitre_mapper import MitreMapper
from app.services.enhanced_mitre_mapper import EnhancedMitreMapper, get_mapper
from app.services.csf_calculator import CSFCalculator
from app.config import settings


@dataclass
class IngestRecord:
    """Single detection record from ingest."""
    detection_id: str
    name: str
    spl: str
    description: str = ""
    severity: str = ""
    status: str = "enabled"
    owner_team: str = ""
    mitre_tags: List[str] = field(default_factory=list)
    data_source_notes: str = ""


@dataclass
class IngestResult:
    """Result of ingest operation."""
    batch_id: int
    total: int
    successful: int
    failed: int
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    processed_ids: List[int] = field(default_factory=list)


class IngestPipeline:
    """Pipeline for ingesting and processing detections."""

    def __init__(self, db: AsyncSession, use_enhanced_mapper: bool = True):
        """
        Initialize pipeline with database session.

        Args:
            db: Database session
            use_enhanced_mapper: If True, use the multi-signal enhanced mapper.
                                If False, use the legacy rule-based mapper.
        """
        self.db = db
        self.spl_parser = SPLParser()
        self.use_enhanced_mapper = use_enhanced_mapper

        # Initialize the appropriate mapper
        if use_enhanced_mapper:
            self.enhanced_mapper = EnhancedMitreMapper()
            self.mitre_mapper = None
        else:
            self.mitre_mapper = MitreMapper()
            self.enhanced_mapper = None

        self.csf_calculator = CSFCalculator()

    async def ingest_csv(
        self,
        content: str,
        filename: str = "",
        user_id: Optional[int] = None,
    ) -> IngestResult:
        """
        Ingest detections from CSV content.

        Expected columns: detection_id, name, spl, description, severity, status, owner_team, mitre_tags, data_source_notes
        """
        # Create batch record
        batch = IngestBatch(
            source_type="csv",
            source_filename=filename,
            status="processing",
            created_by_id=user_id,
        )
        self.db.add(batch)
        await self.db.flush()

        records = []
        warnings = []
        errors = []

        try:
            reader = csv.DictReader(io.StringIO(content))

            for row_num, row in enumerate(reader, start=2):
                try:
                    record = self._parse_csv_row(row)
                    if record:
                        records.append(record)
                except Exception as e:
                    warnings.append(f"Row {row_num}: {str(e)}")

        except Exception as e:
            errors.append(f"CSV parse error: {str(e)}")

        batch.total_records = len(records)

        # Process records
        result = await self._process_records(records, batch, user_id)
        result.warnings.extend(warnings)
        result.errors.extend(errors)

        return result

    async def ingest_yaml(
        self,
        content: str,
        filename: str = "",
        user_id: Optional[int] = None,
    ) -> IngestResult:
        """Ingest detections from YAML content."""
        batch = IngestBatch(
            source_type="yaml",
            source_filename=filename,
            status="processing",
            created_by_id=user_id,
        )
        self.db.add(batch)
        await self.db.flush()

        records = []
        warnings = []
        errors = []

        try:
            # Handle multiple YAML documents
            docs = list(yaml.safe_load_all(content))
            for doc_num, doc in enumerate(docs, start=1):
                if doc:
                    try:
                        record = self._parse_yaml_doc(doc, doc_num)
                        if record:
                            records.append(record)
                    except Exception as e:
                        warnings.append(f"Document {doc_num}: {str(e)}")

        except Exception as e:
            errors.append(f"YAML parse error: {str(e)}")

        batch.total_records = len(records)

        result = await self._process_records(records, batch, user_id)
        result.warnings.extend(warnings)
        result.errors.extend(errors)

        return result

    async def ingest_paste(
        self,
        content: str,
        user_id: Optional[int] = None,
    ) -> IngestResult:
        """
        Ingest detections from pasted text with delimiter format.

        Format:
        === DETECTION ===
        name: ...
        id: ...
        spl: |
          <SPL here>
        description: ...
        === DETECTION ===
        """
        batch = IngestBatch(
            source_type="paste",
            status="processing",
            created_by_id=user_id,
        )
        self.db.add(batch)
        await self.db.flush()

        records = []
        warnings = []
        errors = []

        try:
            # Split by delimiter
            detection_blocks = re.split(r'===\s*DETECTION\s*===', content, flags=re.IGNORECASE)

            for block_num, block in enumerate(detection_blocks, start=1):
                block = block.strip()
                if not block:
                    continue

                try:
                    record = self._parse_paste_block(block, block_num)
                    if record:
                        records.append(record)
                except Exception as e:
                    warnings.append(f"Block {block_num}: {str(e)}")

        except Exception as e:
            errors.append(f"Parse error: {str(e)}")

        batch.total_records = len(records)

        result = await self._process_records(records, batch, user_id)
        result.warnings.extend(warnings)
        result.errors.extend(errors)

        return result

    def _parse_csv_row(self, row: Dict[str, str]) -> Optional[IngestRecord]:
        """Parse a CSV row into an IngestRecord."""
        detection_id = row.get('detection_id', '').strip()
        name = row.get('name', '').strip()
        spl = row.get('spl', '').strip()

        if not detection_id or not name or not spl:
            raise ValueError("Missing required field (detection_id, name, or spl)")

        mitre_tags = []
        tags_str = row.get('mitre_tags', '')
        if tags_str:
            mitre_tags = [t.strip() for t in tags_str.split(',') if t.strip()]

        return IngestRecord(
            detection_id=detection_id,
            name=name,
            spl=spl,
            description=row.get('description', ''),
            severity=row.get('severity', '').lower(),
            status=row.get('status', 'enabled').lower(),
            owner_team=row.get('owner_team', ''),
            mitre_tags=mitre_tags,
            data_source_notes=row.get('data_source_notes', ''),
        )

    def _parse_yaml_doc(self, doc: Dict[str, Any], doc_num: int) -> Optional[IngestRecord]:
        """Parse a YAML document into an IngestRecord."""
        # Handle various YAML formats
        detection_id = doc.get('id') or doc.get('detection_id') or f"yaml_{doc_num}"
        name = doc.get('name', '')
        spl = doc.get('spl') or doc.get('search', '')

        if not name or not spl:
            raise ValueError("Missing required field (name or spl/search)")

        mitre_tags = []
        tags = doc.get('tags', [])
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, str) and tag.startswith('attack.'):
                    mitre_tags.append(tag.replace('attack.', ''))
                elif isinstance(tag, dict) and 'mitre_attack_id' in tag:
                    mitre_tags.append(tag['mitre_attack_id'])

        return IngestRecord(
            detection_id=str(detection_id),
            name=name,
            spl=spl,
            description=doc.get('description', ''),
            severity=str(doc.get('severity', '')).lower(),
            status=doc.get('status', 'enabled'),
            owner_team=doc.get('owner_team', '') or doc.get('author', ''),
            mitre_tags=mitre_tags,
            data_source_notes=doc.get('data_source_notes', ''),
        )

    def _parse_paste_block(self, block: str, block_num: int) -> Optional[IngestRecord]:
        """Parse a pasted detection block."""
        lines = block.strip().split('\n')
        data = {}
        current_key = None
        current_value = []

        for line in lines:
            # Check for key: value pattern
            match = re.match(r'^([a-zA-Z_]+):\s*(.*)$', line)
            if match:
                # Save previous key
                if current_key:
                    data[current_key] = '\n'.join(current_value).strip()

                current_key = match.group(1).lower()
                value = match.group(2)

                if value == '|':
                    current_value = []
                else:
                    current_value = [value]
            elif current_key:
                current_value.append(line)

        # Save last key
        if current_key:
            data[current_key] = '\n'.join(current_value).strip()

        detection_id = data.get('id') or data.get('detection_id') or f"paste_{block_num}"
        name = data.get('name', '')
        spl = data.get('spl', '')

        if not name or not spl:
            raise ValueError("Missing required field (name or spl)")

        return IngestRecord(
            detection_id=str(detection_id),
            name=name,
            spl=spl,
            description=data.get('description', ''),
            severity=data.get('severity', '').lower(),
            status=data.get('status', 'enabled').lower(),
            owner_team=data.get('owner_team', ''),
            data_source_notes=data.get('data_source_notes', ''),
        )

    async def _process_records(
        self,
        records: List[IngestRecord],
        batch: IngestBatch,
        user_id: Optional[int],
    ) -> IngestResult:
        """Process parsed records through the full pipeline."""
        result = IngestResult(
            batch_id=batch.id,
            total=len(records),
            successful=0,
            failed=0,
        )

        for record in records:
            try:
                detection_id = await self._process_single_record(record, batch.id, user_id)
                result.processed_ids.append(detection_id)
                result.successful += 1
            except Exception as e:
                result.failed += 1
                result.errors.append(f"{record.detection_id}: {str(e)}")

        # Update batch status
        batch.successful = result.successful
        batch.failed = result.failed
        batch.warnings = json.dumps(result.warnings)
        batch.status = "completed" if result.failed == 0 else "completed_with_errors"
        batch.completed_at = datetime.utcnow()

        await self.db.commit()

        return result

    async def _process_single_record(
        self,
        record: IngestRecord,
        batch_id: int,
        user_id: Optional[int],
    ) -> int:
        """Process a single detection record through the full pipeline."""
        # Check if detection already exists
        stmt = select(Detection).where(Detection.detection_id == record.detection_id)
        result = await self.db.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            # Update existing detection
            detection = existing
            old_spl = detection.spl

            detection.name = record.name
            detection.description = record.description
            detection.spl = record.spl
            detection.severity = record.severity if record.severity else detection.severity
            detection.status = record.status
            detection.owner_team = record.owner_team
            detection.original_mitre_tags = json.dumps(record.mitre_tags) if record.mitre_tags else None
            detection.data_source_notes = record.data_source_notes
            detection.updated_at = datetime.utcnow()

            # Create version if SPL changed
            if old_spl != record.spl:
                stmt = select(DetectionVersion).where(
                    DetectionVersion.detection_id == detection.id
                ).order_by(DetectionVersion.version_number.desc())
                result = await self.db.execute(stmt)
                last_version = result.scalar_one_or_none()
                new_version_num = (last_version.version_number if last_version else 0) + 1

                version = DetectionVersion(
                    detection_id=detection.id,
                    version_number=new_version_num,
                    spl=record.spl,
                    changed_fields=json.dumps(['spl']),
                    created_by_id=user_id,
                )
                self.db.add(version)

                # Re-process mappings since SPL changed
                await self._clear_mappings(detection.id)
        else:
            # Create new detection
            detection = Detection(
                detection_id=record.detection_id,
                name=record.name,
                description=record.description,
                spl=record.spl,
                severity=record.severity if record.severity else None,
                status=record.status,
                owner_team=record.owner_team,
                original_mitre_tags=json.dumps(record.mitre_tags) if record.mitre_tags else None,
                data_source_notes=record.data_source_notes,
                ingest_batch_id=batch_id,
            )
            self.db.add(detection)
            await self.db.flush()

            # Create initial version
            version = DetectionVersion(
                detection_id=detection.id,
                version_number=1,
                spl=record.spl,
                changed_fields=json.dumps(['initial']),
                created_by_id=user_id,
            )
            self.db.add(version)

        await self.db.flush()

        # Parse SPL
        await self._parse_spl(detection)

        # Map to MITRE
        await self._map_to_mitre(detection, user_id)

        # Calculate CSF impact
        await self._calculate_csf_impact(detection)

        return detection.id

    async def _clear_mappings(self, detection_id: int, preserve_manual: bool = True):
        """
        Clear existing mappings for a detection.

        Args:
            detection_id: Detection to clear mappings for
            preserve_manual: If True, keep manually-added mappings (default: True)
        """
        # Delete MITRE mappings (optionally preserving manual ones)
        stmt = select(DetectionMitreMapping).where(DetectionMitreMapping.detection_id == detection_id)
        if preserve_manual:
            stmt = stmt.where(DetectionMitreMapping.method != 'manual')
        result = await self.db.execute(stmt)
        for mapping in result.scalars():
            await self.db.delete(mapping)

        # Delete CSF impacts
        stmt = select(DetectionCsfImpact).where(DetectionCsfImpact.detection_id == detection_id)
        result = await self.db.execute(stmt)
        for impact in result.scalars():
            await self.db.delete(impact)

        # Delete SPL artifacts
        stmt = select(SplParseArtifact).where(SplParseArtifact.detection_id == detection_id)
        result = await self.db.execute(stmt)
        for artifact in result.scalars():
            await self.db.delete(artifact)

    async def _parse_spl(self, detection: Detection):
        """Parse SPL and store artifacts."""
        parse_result = self.spl_parser.parse(detection.spl)

        # Check for existing artifact
        stmt = select(SplParseArtifact).where(SplParseArtifact.detection_id == detection.id)
        result = await self.db.execute(stmt)
        artifact = result.scalar_one_or_none()

        if artifact:
            artifact.indexes = json.dumps(parse_result.indexes)
            artifact.sourcetypes = json.dumps(parse_result.sourcetypes)
            artifact.datamodels = json.dumps(parse_result.datamodels)
            artifact.macros = json.dumps(parse_result.macros)
            artifact.fields_referenced = json.dumps(parse_result.fields_referenced)
            artifact.commands_used = json.dumps(parse_result.commands_used)
            artifact.time_constraints = json.dumps(parse_result.time_constraints)
            artifact.aggregations = json.dumps(parse_result.aggregations)
            artifact.thresholds = json.dumps(parse_result.thresholds)
            artifact.complexity_score = parse_result.complexity_score
            artifact.complexity_signals = json.dumps(parse_result.complexity_signals)
            artifact.raw_parse_output = parse_result.to_json()
            artifact.updated_at = datetime.utcnow()
        else:
            artifact = SplParseArtifact(
                detection_id=detection.id,
                indexes=json.dumps(parse_result.indexes),
                sourcetypes=json.dumps(parse_result.sourcetypes),
                datamodels=json.dumps(parse_result.datamodels),
                macros=json.dumps(parse_result.macros),
                fields_referenced=json.dumps(parse_result.fields_referenced),
                commands_used=json.dumps(parse_result.commands_used),
                time_constraints=json.dumps(parse_result.time_constraints),
                aggregations=json.dumps(parse_result.aggregations),
                thresholds=json.dumps(parse_result.thresholds),
                complexity_score=parse_result.complexity_score,
                complexity_signals=json.dumps(parse_result.complexity_signals),
                raw_parse_output=parse_result.to_json(),
            )
            self.db.add(artifact)

    async def _map_to_mitre(self, detection: Detection, user_id: Optional[int]):
        """Map detection to MITRE techniques using rules or enhanced multi-signal scoring."""
        # Get SPL artifacts for mapping
        stmt = select(SplParseArtifact).where(SplParseArtifact.detection_id == detection.id)
        result = await self.db.execute(stmt)
        artifact = result.scalar_one_or_none()

        sourcetypes = json.loads(artifact.sourcetypes) if artifact and artifact.sourcetypes else []
        fields = json.loads(artifact.fields_referenced) if artifact and artifact.fields_referenced else []
        indexes = json.loads(artifact.indexes) if artifact and artifact.indexes else []
        datamodels = json.loads(artifact.datamodels) if artifact and artifact.datamodels else []

        # Get original MITRE tags if present
        original_mitre_tags = []
        if detection.original_mitre_tags:
            try:
                original_mitre_tags = json.loads(detection.original_mitre_tags)
            except (json.JSONDecodeError, TypeError):
                pass

        # Get existing manual mappings to avoid duplicates
        stmt = select(DetectionMitreMapping.technique_id).where(
            DetectionMitreMapping.detection_id == detection.id,
            DetectionMitreMapping.method == 'manual'
        )
        result = await self.db.execute(stmt)
        manual_technique_ids = {row[0] for row in result.all()}

        if self.use_enhanced_mapper and self.enhanced_mapper:
            # Use enhanced multi-signal mapper
            mapping_result = self.enhanced_mapper.map_detection(
                name=detection.name,
                description=detection.description or '',
                spl=detection.spl,
                sourcetypes=sourcetypes,
                fields=fields,
                indexes=indexes,
                datamodels=datamodels,
                original_mitre_tags=original_mitre_tags,
            )

            # Get accepted mappings based on confidence threshold
            accepted = mapping_result.get_accepted_mappings(min_confidence='low')

            for match in accepted:
                # Skip if technique already has a manual mapping (manual takes priority)
                if match.technique_id in manual_technique_ids:
                    continue

                mapping = DetectionMitreMapping(
                    detection_id=detection.id,
                    technique_id=match.technique_id,
                    confidence=match.final_score,
                    method='enhanced_multi_signal',
                    rule_id=None,
                    rationale=match.rationale,
                    evidence=json.dumps({
                        'signal_scores': match.signal_scores.to_dict(),
                        'confidence_level': match.confidence_level,
                        'evidence_details': match.evidence,
                    }),
                    is_accepted=True,
                    created_by_id=user_id,
                )
                self.db.add(mapping)
        else:
            # Use legacy rule-based mapper
            mapping_result = self.mitre_mapper.map_detection(
                name=detection.name,
                description=detection.description or '',
                spl=detection.spl,
                sourcetypes=sourcetypes,
                fields=fields,
                indexes=indexes,
                datamodels=datamodels,
            )

            for match in mapping_result.matches:
                # Skip if technique already has a manual mapping (manual takes priority)
                if match.technique_id in manual_technique_ids:
                    continue

                mapping = DetectionMitreMapping(
                    detection_id=detection.id,
                    technique_id=match.technique_id,
                    confidence=match.confidence,
                    method='rule',
                    rule_id=match.rule_id,
                    rationale=match.rationale,
                    evidence=json.dumps(match.evidence),
                    is_accepted=True,
                    created_by_id=user_id,
                )
                self.db.add(mapping)

    async def _calculate_csf_impact(self, detection: Detection):
        """Calculate CSF impact scores for detection."""
        # Get MITRE mappings
        stmt = select(DetectionMitreMapping).where(
            DetectionMitreMapping.detection_id == detection.id,
            DetectionMitreMapping.is_accepted == True
        )
        result = await self.db.execute(stmt)
        mitre_mappings = result.scalars().all()

        technique_mappings = [
            {'technique_id': m.technique_id, 'confidence': m.confidence}
            for m in mitre_mappings
        ]

        csf_result = self.csf_calculator.calculate_impacts(technique_mappings)

        for impact in csf_result.impacts:
            csf_impact = DetectionCsfImpact(
                detection_id=detection.id,
                csf_id=impact.csf_id,
                impact_score=impact.impact_score,
                contributing_techniques=json.dumps(impact.contributing_techniques),
            )
            self.db.add(csf_impact)

    async def reprocess_all_mappings(
        self,
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Re-process MITRE mappings and CSF impacts for all detections.

        This clears existing mappings and re-runs the mapper (enhanced or legacy)
        on all detections. Useful when:
        - Switching to enhanced mapper
        - Updating technique indicators
        - Fixing mapping issues

        Args:
            user_id: User ID for audit trail

        Returns:
            Summary of re-processing results
        """
        result = {
            'total_detections': 0,
            'successful': 0,
            'failed': 0,
            'errors': [],
            'mapper_type': 'enhanced_multi_signal' if self.use_enhanced_mapper else 'rule_based',
        }

        # Get all detections
        stmt = select(Detection)
        db_result = await self.db.execute(stmt)
        detections = db_result.scalars().all()

        result['total_detections'] = len(detections)

        for detection in detections:
            try:
                # Clear existing mappings
                await self._clear_mappings(detection.id)

                # Re-map to MITRE
                await self._map_to_mitre(detection, user_id)

                # Re-calculate CSF impact
                await self._calculate_csf_impact(detection)

                result['successful'] += 1
            except Exception as e:
                result['failed'] += 1
                result['errors'].append(f"{detection.detection_id}: {str(e)}")

        await self.db.commit()

        return result

    async def reprocess_single_detection(
        self,
        detection_id: int,
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Re-process MITRE mappings and CSF impacts for a single detection.

        Args:
            detection_id: Database ID of the detection
            user_id: User ID for audit trail

        Returns:
            Summary of re-processing results
        """
        # Get detection
        stmt = select(Detection).where(Detection.id == detection_id)
        db_result = await self.db.execute(stmt)
        detection = db_result.scalar_one_or_none()

        if not detection:
            raise ValueError(f"Detection not found: {detection_id}")

        # Clear existing mappings
        await self._clear_mappings(detection.id)

        # Re-map to MITRE
        await self._map_to_mitre(detection, user_id)

        # Re-calculate CSF impact
        await self._calculate_csf_impact(detection)

        await self.db.commit()

        # Get new mapping count
        stmt = select(func.count(DetectionMitreMapping.id)).where(
            DetectionMitreMapping.detection_id == detection_id
        )
        count_result = await self.db.execute(stmt)
        mapping_count = count_result.scalar() or 0

        return {
            'detection_id': detection_id,
            'detection_name': detection.name,
            'mappings_created': mapping_count,
            'mapper_type': 'enhanced_multi_signal' if self.use_enhanced_mapper else 'rule_based',
        }
