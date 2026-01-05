# CSF×ATT&CK Mapper

A security tool that ingests Splunk SPL detection rules, maps them to MITRE ATT&CK techniques, and crosswalks to NIST CSF 2.0 for coverage analysis and compliance reporting.

## Features

- **SPL Ingestion**: Import detections via CSV, YAML, or direct paste
- **SPL Parsing**: Automatic extraction of indexes, sourcetypes, datamodels, macros, commands, and thresholds
- **MITRE ATT&CK Mapping**: Rule-based mapping with confidence scoring and evidence tracking
- **NIST CSF 2.0 Crosswalk**: Automatic mapping of ATT&CK techniques to CSF categories including GOVERN function
- **Coverage Analytics**: Visualize ATT&CK matrix coverage and CSF posture
- **Gap Analysis**: Identify uncovered techniques and low-coverage CSF categories
- **Recommendations**: Prioritized improvement suggestions based on coverage gaps
- **Export**: CSV and JSON exports for reporting

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

### Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database and load reference data
python scripts/init_db.py

# Start the backend server
uvicorn app.main:app --reload --port 8000
```

### Frontend Setup

```bash
# Navigate to frontend directory (in a new terminal)
cd frontend

# Install dependencies
npm install

# Start the development server
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

Sample detections are provided in `sample_data/sample_detections.csv`. Import them through the Ingest page or using the API.

## Project Structure

```
csf_attack_mapper/
├── backend/
│   ├── app/
│   │   ├── api/routes/        # API endpoints
│   │   ├── models/            # SQLAlchemy models
│   │   ├── schemas/           # Pydantic schemas
│   │   ├── services/          # Business logic
│   │   │   ├── spl_parser.py      # SPL parsing
│   │   │   ├── mitre_mapper.py    # MITRE mapping rules
│   │   │   ├── csf_calculator.py  # CSF calculation
│   │   │   └── coverage_analyzer.py
│   │   └── core/              # Security utilities
│   ├── scripts/               # Init scripts
│   └── tests/                 # Unit tests
├── frontend/
│   ├── src/
│   │   ├── api/               # API client
│   │   ├── components/        # React components
│   │   ├── pages/             # Page components
│   │   └── types/             # TypeScript types
│   └── package.json
├── mappings/
│   ├── mitre_rules_starter.yml     # MITRE mapping rules
│   └── mitre_to_csf_starter.yml    # ATT&CK→CSF crosswalk
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

- JWT tokens expire after 30 minutes by default
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
