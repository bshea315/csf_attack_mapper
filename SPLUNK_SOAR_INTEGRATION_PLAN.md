# Splunk ES + SOAR Integration Plan

## Executive Summary

This plan adds Splunk Enterprise Security (ES) correlation search sync and SOAR playbook execution evidence to the CSF×ATT&CK Mapper. The integration enables:
- Automatic ingestion of ES correlation searches via Splunk REST API
- SOAR execution metrics from Splunk phantom logs
- Response automation coverage overlays on ATT&CK/CSF dashboards

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          React Frontend                              │
│   ┌──────────┬───────────┬───────────┬──────────┬────────────────┐  │
│   │ Admin    │ Playbooks │ SOAR      │ ATT&CK   │ CSF            │  │
│   │ Config   │ List      │ Dashboard │ Coverage │ Posture        │  │
│   └──────────┴───────────┴───────────┴──────────┴────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                │ REST API
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         FastAPI Backend                              │
│   ┌──────────────┬───────────────┬────────────────┬───────────────┐ │
│   │ Admin API    │ Sync API      │ Playbook API   │ SOAR Metrics  │ │
│   └──────────────┴───────────────┴────────────────┴───────────────┘ │
│   ┌──────────────┬───────────────┬────────────────────────────────┐ │
│   │ Splunk ES    │ SOAR Log      │ Detection-Playbook             │ │
│   │ Connector    │ Ingestor      │ Linker                         │ │
│   └──────────────┴───────────────┴────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
          ┌─────────────────┐    ┌─────────────────┐
          │   SQLite DB     │    │  Splunk REST    │
          │   (local)       │    │  API (external) │
          └─────────────────┘    └─────────────────┘
```

---

## Database Schema Additions

### 1. Splunk Configuration (Encrypted)

```sql
CREATE TABLE splunk_config (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL DEFAULT 'default',
    base_url TEXT NOT NULL,               -- https://splunk-sh.company.com:8089
    auth_type TEXT NOT NULL,              -- 'token' or 'basic'
    auth_token_encrypted TEXT,            -- Encrypted bearer token
    auth_username TEXT,                   -- For basic auth
    auth_password_encrypted TEXT,         -- Encrypted password
    verify_tls BOOLEAN DEFAULT TRUE,
    es_app_namespace TEXT DEFAULT 'SplunkEnterpriseSecuritySuite',
    es_owner TEXT DEFAULT 'nobody',
    soar_playbook_run_index TEXT DEFAULT 'phantom_playbook_run',
    soar_action_run_index TEXT DEFAULT 'phantom_action_run',
    soar_time_window_days INTEGER DEFAULT 30,
    is_active BOOLEAN DEFAULT TRUE,
    last_es_sync_at TIMESTAMP,
    last_soar_sync_at TIMESTAMP,
    es_detection_count INTEGER DEFAULT 0,
    soar_playbook_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 2. Playbooks

```sql
CREATE TABLE playbooks (
    id INTEGER PRIMARY KEY,
    playbook_id TEXT UNIQUE NOT NULL,     -- External ID from SOAR
    name TEXT NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 3. Playbook Runs

```sql
CREATE TABLE playbook_runs (
    id INTEGER PRIMARY KEY,
    playbook_run_id TEXT UNIQUE NOT NULL, -- External run ID
    playbook_id INTEGER REFERENCES playbooks(id),
    status TEXT NOT NULL,                 -- success|failure|running|cancelled
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    duration_seconds REAL,
    container_id TEXT,                    -- SOAR container/case ID
    event_time TIMESTAMP,                 -- _time from Splunk
    index_time TIMESTAMP,                 -- _indextime from Splunk
    raw_event JSONB,                      -- Full Splunk event
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_playbook_runs_playbook ON playbook_runs(playbook_id);
CREATE INDEX idx_playbook_runs_status ON playbook_runs(status);
CREATE INDEX idx_playbook_runs_event_time ON playbook_runs(event_time);
```

### 4. Action Runs

```sql
CREATE TABLE action_runs (
    id INTEGER PRIMARY KEY,
    action_run_id TEXT UNIQUE NOT NULL,   -- External action run ID
    playbook_run_id INTEGER REFERENCES playbook_runs(id),
    action_name TEXT NOT NULL,
    app_name TEXT,
    status TEXT NOT NULL,                 -- success|failure
    duration_seconds REAL,
    error_message TEXT,
    event_time TIMESTAMP,
    index_time TIMESTAMP,
    raw_event JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_action_runs_playbook_run ON action_runs(playbook_run_id);
CREATE INDEX idx_action_runs_action_name ON action_runs(action_name);
CREATE INDEX idx_action_runs_status ON action_runs(status);
```

### 5. Detection-Playbook Links

```sql
CREATE TABLE detection_playbook_links (
    id INTEGER PRIMARY KEY,
    detection_id INTEGER REFERENCES detections(id) ON DELETE CASCADE,
    playbook_id INTEGER REFERENCES playbooks(id) ON DELETE CASCADE,
    link_type TEXT DEFAULT 'manual',      -- manual|auto
    link_evidence TEXT,                   -- JSON: why auto-linked
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(detection_id, playbook_id)
);
```

### 6. Detection Table Updates

Add columns to existing `detections` table:

```sql
ALTER TABLE detections ADD COLUMN source_type TEXT DEFAULT 'manual';
    -- manual|csv|yaml|splunk_es
ALTER TABLE detections ADD COLUMN splunk_savedsearch_id TEXT;
ALTER TABLE detections ADD COLUMN splunk_app TEXT;
ALTER TABLE detections ADD COLUMN raw_savedsearch_payload JSONB;
```

---

## API Endpoints

### Admin Configuration

```
GET  /api/admin/splunk-config           - Get current config (masks secrets)
PUT  /api/admin/splunk-config           - Update config
POST /api/admin/splunk-config/test      - Test Splunk connection
DELETE /api/admin/splunk-config         - Remove config
```

### Sync Operations

```
POST /api/sync/es-detections            - Sync ES correlation searches
GET  /api/sync/es-detections/status     - Get last sync status
POST /api/sync/soar-logs                - Sync SOAR logs from Splunk
GET  /api/sync/soar-logs/status         - Get last sync status
```

### Playbooks

```
GET  /api/playbooks                     - List playbooks with metrics
GET  /api/playbooks/{id}                - Get playbook details
GET  /api/playbooks/{id}/runs           - Get playbook run history
POST /api/playbooks/{id}/link/{detection_id}   - Link to detection
DELETE /api/playbooks/{id}/link/{detection_id} - Unlink from detection
```

### SOAR Metrics

```
GET  /api/soar/metrics                  - Overall SOAR metrics
GET  /api/soar/metrics/playbooks        - Per-playbook metrics
GET  /api/soar/metrics/actions          - Action-level metrics
GET  /api/soar/metrics/coverage         - Detection/technique coverage
```

---

## Services

### 1. SplunkConnector Service

```python
class SplunkConnector:
    """Handles all Splunk REST API communication."""

    async def test_connection(self) -> Dict[str, Any]
    async def get_server_info(self) -> Dict[str, Any]
    async def get_correlation_searches(self) -> List[Dict]
    async def run_search(self, spl: str, earliest: str, latest: str) -> List[Dict]
```

### 2. ESDetectionSync Service

```python
class ESDetectionSync:
    """Syncs ES correlation searches to local database."""

    async def sync_all(self) -> SyncResult
    async def upsert_detection(self, saved_search: Dict) -> Detection
    async def detect_changes(self, saved_search: Dict, existing: Detection) -> List[str]
```

### 3. SOARLogIngestor Service

```python
class SOARLogIngestor:
    """Ingests SOAR execution logs from Splunk indexes."""

    async def sync_playbook_runs(self, days: int = 30) -> SyncResult
    async def sync_action_runs(self, days: int = 30) -> SyncResult
    async def correlate_runs(self) -> int  # Links actions to playbook runs
    async def auto_link_detections(self) -> int  # Heuristic detection linking
```

### 4. SOARMetricsCalculator Service

```python
class SOARMetricsCalculator:
    """Calculates SOAR metrics from ingested data."""

    async def get_overall_metrics(self, days: int = 30) -> Dict
    async def get_playbook_metrics(self, playbook_id: int) -> Dict
    async def get_action_metrics(self) -> Dict
    async def get_coverage_metrics(self) -> Dict
```

---

## Frontend Pages

### 1. Admin Page (`/admin`)

**Sections:**
- Splunk Configuration form
- Connection test button with status
- Sync buttons: "Sync ES Detections", "Sync SOAR Logs"
- Last sync timestamps and counts
- User management (existing)

### 2. Playbooks Page (`/playbooks`)

**Features:**
- Searchable/filterable list
- Columns: Name, Runs (30d), Success Rate, P95 Duration, Last Run, Top Failing Action
- Click to view details
- Link/unlink detections

### 3. SOAR Dashboard (`/soar`)

**Metrics Cards:**
- Total Runs (30d)
- Success Rate
- Failure Count
- P95 Duration
- Indexing Lag P95

**Charts:**
- Runs per day (line chart)
- Success/Failure breakdown (pie)
- Top failing playbooks (bar)
- Top failing actions (bar)

### 4. Enhanced ATT&CK Coverage

**Additions:**
- Response evidence badge on techniques
- Filter: "Has SOAR response"
- Overlay: Playbook coverage count

### 5. Enhanced CSF Posture

**Additions:**
- Response evidence column
- Filter: "Has response automation"

---

## Security Considerations

### Secrets Management
- Encrypt Splunk tokens/passwords using Fernet (symmetric encryption)
- Derive key from SECRET_KEY
- Never log or return decrypted secrets in API responses

### RBAC
- Admin-only: Splunk config, sync operations
- Editor: Link/unlink playbooks to detections
- Viewer: Read-only access to all dashboards

### Audit Trail
- Log all sync operations
- Log config changes
- Log manual playbook links

---

## Implementation Phases

### Phase 1: Database & Models (Day 1)
1. Create Alembic migration for new tables
2. Create SQLAlchemy models
3. Add encryption utilities for secrets

### Phase 2: Splunk Connector (Day 2)
1. Create SplunkConnector service
2. Implement connection test
3. Implement ES correlation search fetch

### Phase 3: ES Detection Sync (Day 3)
1. Create ESDetectionSync service
2. Create sync API endpoints
3. Handle upsert logic with version tracking

### Phase 4: SOAR Log Ingest (Day 4)
1. Create SOARLogIngestor service
2. Parse playbook_run events
3. Parse action_run events
4. Implement correlation logic

### Phase 5: SOAR Metrics (Day 5)
1. Create SOARMetricsCalculator service
2. Implement all metric calculations
3. Create metrics API endpoints

### Phase 6: Frontend - Admin (Day 6)
1. Create Admin page with Splunk config form
2. Add connection test UI
3. Add sync buttons with progress

### Phase 7: Frontend - Playbooks & SOAR Dashboard (Day 7)
1. Create Playbooks list page
2. Create SOAR Dashboard page
3. Add detection-playbook linking UI

### Phase 8: Dashboard Enhancements (Day 8)
1. Add response evidence to ATT&CK coverage
2. Add response evidence to CSF posture
3. Update recommendations with SOAR gaps

### Phase 9: Fixtures & Testing (Day 9)
1. Create seed data for development
2. Write unit tests
3. Integration testing

---

## Metric Formulas

### Reliability Metrics
```python
success_rate = successful_runs / total_runs * 100
failure_rate = failed_runs / total_runs * 100
median_duration = percentile(durations, 50)
p95_duration = percentile(durations, 95)
```

### Coverage Metrics
```python
detection_coverage = detections_with_playbooks / total_detections * 100
technique_coverage = techniques_with_soar_evidence / total_mapped_techniques * 100
csf_coverage = csf_categories_with_response / total_csf_categories * 100
```

### Timeliness Metrics
```python
indexing_lag = index_time - event_time
p50_lag = percentile(lags, 50)
p95_lag = percentile(lags, 95)
```

---

## SPL Templates

### Fetch Playbook Runs
```spl
index=$PHANTOM_PLAYBOOK_RUN_INDEX$ earliest=-${DAYS}d@d latest=now
| fields _time _indextime playbook playbook_run status duration container_id
| rename playbook as playbook_id, playbook_run as playbook_run_id
```

### Fetch Action Runs
```spl
index=$PHANTOM_ACTION_RUN_INDEX$ earliest=-${DAYS}d@d latest=now
| fields _time _indextime playbook playbook_run action app status duration error
| rename playbook as playbook_id, playbook_run as playbook_run_id, action as action_name, app as app_name, error as error_message
```

---

## File Structure (New Files)

```
backend/app/
├── models/
│   ├── splunk_config.py      # NEW
│   ├── playbook.py           # NEW
│   └── soar.py               # NEW (runs, action_runs, links)
├── services/
│   ├── splunk_connector.py   # NEW
│   ├── es_sync.py            # NEW
│   ├── soar_ingestor.py      # NEW
│   └── soar_metrics.py       # NEW
├── api/routes/
│   ├── admin.py              # NEW
│   ├── sync.py               # NEW
│   ├── playbooks.py          # NEW
│   └── soar.py               # NEW
├── schemas/
│   ├── splunk.py             # NEW
│   ├── playbook.py           # NEW
│   └── soar.py               # NEW
└── core/
    └── encryption.py         # NEW

frontend/src/
├── pages/
│   ├── Admin.tsx             # NEW
│   ├── Playbooks.tsx         # NEW
│   └── SoarDashboard.tsx     # NEW
└── types/
    └── index.ts              # UPDATE with new types
```

---

## Success Criteria

1. **ES Sync**: Successfully fetch and store ES correlation searches
2. **SOAR Ingest**: Parse and store playbook/action runs from Splunk logs
3. **Metrics Accuracy**: All metrics match manual calculation
4. **UI Completeness**: All specified pages functional
5. **Security**: Secrets encrypted, RBAC enforced
6. **Determinism**: Same sync produces same results
