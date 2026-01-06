# CSF×ATT&CK Mapper

A security tool that ingests Splunk SPL detection rules, maps them to MITRE ATT&CK techniques, and crosswalks to NIST CSF 2.0 for coverage analysis and compliance reporting.

## Features

### Core Functionality
- **SPL Ingestion**: Import detections via CSV, YAML, or direct paste
- **SPL Parsing**: Automatic extraction of indexes, sourcetypes, datamodels, macros, commands, and thresholds
- **MITRE ATT&CK Mapping**: Rule-based mapping with confidence scoring and evidence tracking
- **NIST CSF 2.0 Crosswalk**: Automatic mapping of ATT&CK techniques to CSF categories including GOVERN function
- **Coverage Analytics**: Visualize ATT&CK matrix coverage and CSF posture
- **Gap Analysis**: Identify uncovered techniques and low-coverage CSF categories
- **Recommendations**: Prioritized improvement suggestions based on coverage gaps
- **Export**: CSV and JSON exports for reporting

### Splunk Integration
- **Splunk ES Sync**: Direct synchronization of correlation searches from Splunk Enterprise Security
- **Splunk SOAR Integration**: Import playbook execution logs and action metrics
- **SOAR Dashboard**: Visualize automation metrics, time savings, and playbook performance
- **Playbook Management**: Track playbooks, configure time savings estimates, view run history
- **Detection-Playbook Linking**: Associate detections with response playbooks for automation tracking

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        React Frontend                            │
│   Dashboard │ Detections │ ATT&CK │ CSF │ Recommendations │ Ingest│
└─────────────────────────────────────────────────────────────────┘
                              │ REST API
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        FastAPI Backend                           │
│   SPL Parser │ MITRE Mapper │ CSF Calculator │ Coverage Analyzer │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │     SQLite      │
                    └─────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+
- npm or yarn

### One-Click Setup (Recommended)

The easiest way to get started is with the automated setup script. This script:
- Creates Python virtual environment and installs dependencies
- Initializes the database with MITRE ATT&CK and CSF 2.0 reference data
- Loads 20 sample SPL detections with automatic MITRE mapping
- Creates 8 SOAR playbooks with 200 sample execution runs
- Establishes detection-to-playbook links for automation tracking
- Installs frontend dependencies

```bash
# Clone the repository
git clone <repository-url>
cd csf_attack_mapper

# Run the setup script
./setup.sh
```

After setup completes, you'll have a fully populated demo environment ready to explore.

**Start the servers:**

```bash
# Terminal 1: Backend
cd backend
source venv/bin/activate
uvicorn app.main:app --reload --port 8000

# Terminal 2: Frontend
cd frontend
npm run dev
```

### Manual Setup (Alternative)

If you prefer manual setup or need to customize the process:

#### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database and load reference data
python ../scripts/init_db.py

# (Optional) Load sample detections
python ../scripts/load_sample_data.py

# (Optional) Load SOAR playbook data
python ../scripts/seed_soar_fixtures.py

# Start the backend server
uvicorn app.main:app --reload --port 8000
```

#### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

### Access the Application

- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

### Default Credentials

```
Username: admin
Password: changeme123
```

## Splunk Integration Setup

To sync detections directly from Splunk Enterprise Security and import SOAR playbook metrics:

1. Navigate to **Admin** page in the application
2. Configure your Splunk connection:
   - **Base URL**: Your Splunk management URL (e.g., `https://splunk.example.com:8089`)
   - **Authentication**: Token (recommended) or Basic auth
   - **ES App Namespace**: Usually `SplunkEnterpriseSecuritySuite`
   - **SOAR Indexes**: Configure indexes where SOAR logs playbook runs

3. Test the connection to verify credentials

4. Use **Sync ES Detections** to import correlation searches

5. Use **Sync SOAR Logs** to import playbook execution data

### SOAR Dashboard Metrics

The SOAR Dashboard displays:
- **Total Time Saved**: Calculated from successful playbook runs × configured time savings
- **Time Saved by Playbook**: Breakdown of automation ROI per playbook
- **Automation Rate**: Percentage of runs completing successfully
- **Mean Time to Respond (MTTR)**: Average playbook execution time
- **Category Breakdown**: Runs grouped by playbook category (Investigation, Containment, etc.)

Configure time savings for each playbook on the Playbook Detail page to enable ROI calculations.

## Importing Detections

### CSV Format

```csv
detection_id,name,spl,severity,status,mitre_tags
DET-001,Brute Force Login,index=auth | stats count by user | where count > 10,high,enabled,"T1110,T1078"
```

### YAML Format

```yaml
detections:
  - detection_id: DET-001
    name: Brute Force Login Detection
    search: |
      index=auth
      | stats count by user
      | where count > 10
    severity: high
    status: enabled
    mitre_tags:
      - T1110
      - T1078
```

### Paste Format

```
detection_id|||name|||spl|||severity|||status
DET-001|||Brute Force Login|||index=auth | stats count by user | where count > 10|||high|||enabled
```

## Sample Data

The setup script automatically loads sample data to demonstrate all features:

### Sample Detections (`sample_data/sample_detections.csv`)

20 SPL detection rules covering common attack techniques:
- Windows authentication monitoring (brute force, Kerberoasting)
- Credential dumping detection (LSASS access)
- PowerShell and command-line monitoring
- Persistence mechanisms (scheduled tasks, services, registry)
- Lateral movement (RDP, PsExec, WMI)
- Cloud security (Azure AD, AWS, O365)

Each detection is automatically:
- Parsed to extract SPL artifacts (indexes, sourcetypes, fields)
- Mapped to MITRE ATT&CK techniques with confidence scores
- Cross-walked to NIST CSF 2.0 categories

### Sample Playbooks

8 SOAR playbooks demonstrating automation workflows:

| Playbook | Category | Time Saved |
|----------|----------|------------|
| Investigate Malware Alert | Investigation | 45 min |
| Block IP on Firewall | Containment | 15 min |
| Isolate Compromised Endpoint | Containment | 20 min |
| Phishing Email Response | Response | 30 min |
| Credential Compromise Response | Response | 25 min |
| Threat Intelligence Enrichment | Enrichment | 10 min |
| Brute Force Attack Response | Response | 20 min |
| Data Exfiltration Response | Investigation | 60 min |

Each playbook includes:
- 200 simulated execution runs over 30 days
- Action-level metrics with success/failure tracking
- Links to relevant detections for automation tracking

You can also import detections manually through the Ingest page or using the API.

## Project Structure

```
csf_attack_mapper/
├── setup.sh                   # One-click setup script
├── backend/
│   ├── app/
│   │   ├── api/routes/        # API endpoints
│   │   │   ├── auth.py            # Authentication
│   │   │   ├── detections.py      # Detection CRUD
│   │   │   ├── ingest.py          # File upload/paste
│   │   │   ├── analytics.py       # Coverage analytics
│   │   │   ├── playbooks.py       # SOAR playbooks
│   │   │   └── splunk.py          # Splunk integration
│   │   ├── models/            # SQLAlchemy models
│   │   ├── schemas/           # Pydantic schemas
│   │   ├── services/          # Business logic
│   │   │   ├── spl_parser.py      # SPL parsing
│   │   │   ├── mitre_mapper.py    # MITRE mapping rules
│   │   │   ├── csf_calculator.py  # CSF calculation
│   │   │   ├── coverage_analyzer.py
│   │   │   └── splunk_client.py   # Splunk REST client
│   │   └── core/              # Security utilities
│   └── tests/                 # Unit tests
├── scripts/                   # Setup and data loading
│   ├── init_db.py                 # Initialize database
│   ├── load_sample_data.py        # Load sample detections
│   └── seed_soar_fixtures.py      # Load SOAR playbooks
├── frontend/
│   ├── src/
│   │   ├── api/               # API client
│   │   ├── components/        # React components
│   │   ├── pages/             # Page components
│   │   │   ├── Dashboard.tsx      # Overview stats
│   │   │   ├── Detections.tsx     # Detection list
│   │   │   ├── DetectionDetail.tsx
│   │   │   ├── AttackCoverage.tsx # ATT&CK matrix
│   │   │   ├── CsfPosture.tsx     # CSF heatmap
│   │   │   ├── Playbooks.tsx      # SOAR playbooks
│   │   │   ├── PlaybookDetail.tsx
│   │   │   ├── SOARDashboard.tsx  # SOAR metrics
│   │   │   └── Admin.tsx          # Splunk config
│   │   └── types/             # TypeScript types
│   └── package.json
├── mappings/
│   ├── mitre_rules_starter.yml     # MITRE mapping rules
│   └── mitre_to_csf_starter.yml    # ATT&CK→CSF crosswalk
├── data/
│   └── csf_attack_mapper.db        # SQLite database
└── sample_data/
    └── sample_detections.csv       # Sample detections
```

## API Endpoints

### Authentication
- `POST /api/auth/login` - Login and get JWT token
- `GET /api/auth/me` - Get current user info

### Detections
- `GET /api/detections` - List detections (paginated)
- `GET /api/detections/{id}` - Get detection details
- `PUT /api/detections/{id}` - Update detection
- `POST /api/detections/{id}/recompute` - Re-run mapping

### Ingest
- `POST /api/ingest/csv` - Upload CSV file
- `POST /api/ingest/yaml` - Upload YAML file
- `POST /api/ingest/paste` - Paste content directly

### Analytics
- `GET /api/analytics/overview` - Dashboard statistics
- `GET /api/analytics/attack-coverage` - ATT&CK matrix data
- `GET /api/analytics/csf-coverage` - CSF coverage data
- `GET /api/analytics/gaps` - Gap analysis
- `GET /api/analytics/recommendations` - Improvement recommendations

### Exports
- `GET /api/exports/detections.csv` - Export detections
- `GET /api/exports/attack-coverage.csv` - Export ATT&CK coverage
- `GET /api/exports/csf-posture.csv` - Export CSF posture

### Splunk Integration
- `GET /api/splunk/config` - Get Splunk configuration
- `POST /api/splunk/config` - Create Splunk configuration
- `PUT /api/splunk/config` - Update Splunk configuration
- `POST /api/splunk/test-connection` - Test Splunk connectivity
- `POST /api/splunk/sync/es` - Sync detections from Splunk ES
- `POST /api/splunk/sync/soar` - Sync playbook runs from SOAR logs

### Playbooks (SOAR)
- `GET /api/playbooks` - List playbooks (paginated)
- `GET /api/playbooks/{id}` - Get playbook details with metrics
- `PUT /api/playbooks/{id}` - Update playbook (time savings config)
- `POST /api/playbooks/{id}/link-detection` - Link detection to playbook
- `DELETE /api/playbooks/{id}/link-detection/{detection_id}` - Unlink detection
- `GET /api/playbooks/dashboard/overview` - SOAR dashboard metrics

## MITRE Mapping Rules

Mapping rules are defined in `mappings/mitre_rules_starter.yml`. Each rule can match on:

- **Keywords**: Match text in detection name, description, or SPL
- **Sourcetypes**: Match specific Splunk sourcetypes
- **Event IDs**: Match Windows EventCode or other event identifiers
- **Regex patterns**: Match patterns in SPL queries
- **Fields**: Match specific field references
- **Datamodels**: Match Splunk CIM datamodel usage

Example rule:

```yaml
rules:
  - id: brute-force-001
    name: Brute Force - Login Failures
    technique_id: T1110
    confidence: 0.8
    rationale: Multiple login failures indicate brute force attempt
    match:
      any_keywords:
        - brute force
        - login failure
        - authentication failure
      any_sourcetypes:
        - WinEventLog:Security
        - linux_secure
      any_event_ids:
        - 4625
        - 529
```

## CSF 2.0 Crosswalk

The MITRE→CSF crosswalk is defined in `mappings/mitre_to_csf_starter.yml`. It maps ATT&CK techniques to CSF categories with weighted impact scores.

CSF Functions:
- **GOVERN (GV)** - New in CSF 2.0, governance activities
- **IDENTIFY (ID)** - Asset and risk management
- **PROTECT (PR)** - Safeguards
- **DETECT (DE)** - Detection activities
- **RESPOND (RS)** - Response activities
- **RECOVER (RC)** - Recovery activities

## Running Tests

```bash
cd backend
pytest
```

## Technology Stack

- **Backend**: FastAPI, SQLAlchemy 2.0, Alembic, Python 3.10+
- **Frontend**: React 18, TypeScript, Vite, TailwindCSS
- **Database**: SQLite (local development)
- **Auth**: JWT with bcrypt password hashing

## Security Notes

- JWT tokens expire after 24 hours by default
- Passwords are hashed using bcrypt
- Role-based access: admin, editor, viewer
- API endpoints are protected by authentication
- CORS is configured for localhost development

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest`
5. Submit a pull request

## License

MIT License
