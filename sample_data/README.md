# Sample Detection Data

This directory contains sample SPL detection data for testing the CSF×ATT&CK Mapper.

## Files

### sample_detections.csv
Contains 20 sample detection rules covering:
- Windows Security (brute force, credential dumping, service creation)
- Azure AD / Entra ID (impossible travel, app consent)
- AWS CloudTrail (IAM changes, security groups)
- Office 365 (mailbox forwarding)
- Network (DNS tunneling)

## Import Instructions

### Via Web UI
1. Start the application (see main README)
2. Log in with admin credentials
3. Navigate to **Ingest** page
4. Select **CSV Upload** tab
5. Upload `sample_detections.csv`
6. Review the import results

### Via API
```bash
curl -X POST "http://localhost:8000/api/ingest/csv" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@sample_detections.csv"
```

## CSV Format

| Column | Required | Description |
|--------|----------|-------------|
| detection_id | Yes | Unique identifier for the detection |
| name | Yes | Human-readable detection name |
| description | No | Detailed description |
| spl | Yes | The Splunk SPL query |
| severity | No | low, medium, high, or critical |
| status | No | enabled or disabled (default: enabled) |
| owner_team | No | Team responsible for the detection |
| mitre_tags | No | Comma-separated MITRE technique IDs |
| data_source_notes | No | Notes about data sources |

## What Happens During Import

1. **Parsing**: CSV is validated and parsed
2. **SPL Analysis**: Each SPL query is analyzed to extract:
   - Indexes and sourcetypes
   - Commands used (stats, tstats, join, etc.)
   - Time constraints
   - Thresholds and aggregations
   - Complexity score

3. **MITRE Mapping**: Rule engine maps detections to MITRE ATT&CK techniques based on:
   - Keywords in name/description/SPL
   - Sourcetypes and data models
   - Event IDs
   - Regex patterns

4. **CSF Impact**: MITRE mappings are crosswalked to NIST CSF 2.0 categories

5. **Dashboard Update**: Coverage metrics are recalculated
