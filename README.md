# CodeShield v2.1 — Enterprise Security Scanner

Production-grade, locally-running Python application that performs multi-dimensional security scanning on uploaded ZIP codebases.

## Features

- **7 Scanner Plugins**: SAST, SCA, Secrets Detection, License Compliance, Supply Chain Security, API Security, Code Quality Analysis
- **Multi-source Vulnerability Database**: OSV.dev, NVD API v2.0, GitHub Advisory Database, OSS Index
- **SBOM Generation**: CycloneDX 1.4 format
- **Rich Report Generation**: Excel (.xlsx) with charts + PDF (.pdf) with severity-grouped sections
- **Enterprise Dashboard**: Dark/light theme, OWASP heatmap, trend analysis, risk score, real-time SSE progress
- **Security Enrichment**: CWE, OWASP Top 10, MITRE ATT&CK, PCI-DSS, HIPAA mapping per finding
- **Trend Analysis**: New vs recurring findings across scans

## Quick Start

```bash
# Clone the repository
git clone https://github.com/your-org/codeshield.git
cd codeshield

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate
# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the server
python run.py
```

Open http://127.0.0.1:5000 in your browser. Upload a ZIP file to scan.

## Configuration

Configuration is loaded from `config.toml` with environment variable overrides:

```bash
# Optional: NVD API key for faster sync (50 req/30s vs 5 req/30s)
export CODESHIELD_NVD_API_KEY=your-key-here

# Optional: GitHub token for advisory sync
export GITHUB_TOKEN=ghp_your-token-here

# Optional: Custom database path
export CODESHIELD_DB_PATH=/custom/path/codeshield.db
```

See `config.toml` for all available options.

## Architecture

```
codeshield/
├── app.py              # Flask application factory
├── config.py           # Multi-source config (env + TOML)
├── engine.py           # Scan orchestrator (zero detection logic)
├── context.py          # File tree & scan context builder
├── mappings.py         # Central CWE/OWASP/MITRE/compliance mappings
├── database/           # SQLite with WAL mode, auto-migration
├── plugins/            # Auto-discovered scanner plugins
│   ├── sast_plugin.py
│   ├── sca_plugin.py
│   ├── secrets_plugin.py
│   ├── license_plugin.py
│   ├── supplychain_plugin.py
│   ├── apisecurity_plugin.py
│   └── codequality_plugin.py
├── reports/            # Excel + PDF report generators
├── structures/         # Aho-Corasick, Interval Tree, Bloom Filter, DAG
├── sync/               # Multi-source vulnerability data sync
│   ├── osv.py          # OSV.dev API
│   ├── nvd.py          # NVD REST API v2.0
│   ├── github_advisory.py  # GitHub Advisory GraphQL
│   ├── ossindex.py     # Sonatype OSS Index
│   ├── spdx.py         # SPDX license list
│   └── engine.py       # Sync orchestrator (bg + primary)
├── web/                # Flask routes + SSE
├── templates/          # Jinja2 templates
└── static/             # CSS + JS dashboard
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard UI |
| POST | `/api/upload` | Upload ZIP for scanning |
| GET | `/api/scan/<id>/results` | Get scan results |
| GET | `/api/scan/<id>/events` | SSE progress stream |
| GET | `/api/scan/<id>/report/excel` | Download Excel report |
| GET | `/api/scan/<id>/report/pdf` | Download PDF report |
| GET | `/api/scan/<id>/risk-score` | Get computed risk score |
| GET | `/api/scan/<id>/trends` | Get trend analysis |
| GET | `/api/scans` | Scan history |
| GET | `/api/health` | Health check |
| POST | `/api/finding/<id>/false-positive` | Toggle false positive |

## Security

- ZIP bomb defense (file count, size, nesting depth limits)
- Path traversal prevention (symlink + `..` rejection)
- Parameterized SQL everywhere (no string interpolation)
- Jinja2 autoescape + JS DOM text content for XSS prevention
- Secret redaction in findings
- `secure_filename()` for upload sanitization
- UUID validation on all scan endpoints

## License

MIT
