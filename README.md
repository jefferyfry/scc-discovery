# Google Cloud SCC Discovery & Security Posture Assessment Tool

An enterprise-grade Python discovery and audit tool that queries Google Cloud Security Command Center (SCC) and related GCP security APIs using read-only permissions to audit your existing security architecture and generate an executive-ready PDF report.

Supports auditing **Organizations**, **Folders**, or **Standalone Projects** (projects without an Organization node), directly from **Google Cloud Shell** or your **Local Terminal**.

---

## Key Features

- **Project & Organization Scope Support**: Audits standalone GCP Projects, Folder hierarchies, or full Google Cloud Organizations.
- **SCC Tier & Setup Audit**: Identifies active SCC tier (Standard / Premium / Enterprise), asset discovery modes, and service agents.
- **Security Posture Discovery**: Discovers security postures, revisions, policy sets, and posture deployments (Enterprise tier).
- **Sensitive Data Protection (Cloud DLP)**: Audits automated profiling discovery configs, inspect templates, de-identify rules, and job triggers.
- **Integrated & Built-in Services**: Inspects SHA, ETD, CTD, VMTD, RVD, WSS, SDP, Anomaly Detection, plus custom SHA/ETD detection modules.
- **Continuous Exports & Mute Rules**: Catalogs Pub/Sub notification topics, BigQuery streaming datasets, and active CEL finding mute rules.
- **Multi-Cloud & Connectors**: Discovers AWS/Azure multi-cloud connectors, Jira/ServiceNow ticketing integrations, and SIEM pipelines.
- **Findings Aggregation**: Performs server-side `group_findings` queries across detector sources, top issue categories, severities, and finding classes.
- **Compliance Benchmarks**: Evaluates active compliance frameworks (CIS GCP Foundations v2.0, NIST 800-53, PCI-DSS, ISO 27001, SOC 2, HIPAA).
- **Asset Inventory Breakdown**: Catalogs cloud assets across Compute, Storage, Databases, IAM, Networking, and Cryptography.
- **Hierarchy & Scope Coverage**: Maps Project, Folder, and Organization resources to evaluate security coverage.
- **Architecture Migration Blueprint**: Calculates an overall Migration Readiness Score (0-100), provides an architectural mapping matrix, and outlines a 4-phase transition roadmap.
- **Executive PDF Report Generator**: Generates an 8-page, publication-quality PDF report using ReportLab with dynamic `Page X of Y` numbering, stat cards, and clean typography.
- **Demo / Offline Mode**: Includes a realistic synthetic enterprise dataset for dry-runs and offline report generation without live GCP access.

---

## 1. Clone the Repository

Clone the repository to your Google Cloud Shell or local machine using either `git` or the `gh` (GitHub CLI):

### Option A: Using `git`
```bash
# HTTPS
git clone https://github.com/<YOUR-GITHUB-ORG-OR-ACCOUNT>/scc-discovery.git

# Or SSH
git clone git@github.com:<YOUR-GITHUB-ORG-OR-ACCOUNT>/scc-discovery.git

# Navigate into the project folder
cd scc-discovery
```

### Option B: Using GitHub CLI (`gh`)
```bash
gh repo clone <YOUR-GITHUB-ORG-OR-ACCOUNT>/scc-discovery
cd scc-discovery
```

> **Note**: Replace `<YOUR-GITHUB-ORG-OR-ACCOUNT>` with the GitHub organization or username where the repository is hosted.

---

## 2. Quickstart

### Option 1: Running in Google Cloud Shell (Recommended - Zero Setup)
```bash
# 1. Authorize gcloud for Application Default Credentials
gcloud auth application-default login

# 2. Setup Virtual Environment and install packages
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3A. Run Discovery against a Standalone Project (No Organization needed):
python scc_discovery.py --project-id YOUR_PROJECT_ID --output-pdf scc_discovery_report.pdf

# 3B. Or Run Discovery against an entire Organization:
python scc_discovery.py --org-id YOUR_ORGANIZATION_ID --output-pdf scc_discovery_report.pdf

# 4. Download PDF to your computer
cloudshell download scc_discovery_report.pdf
```

### Option 2: Running in Local Terminal (macOS / Linux / Windows WSL)
```bash
# 1. Setup Virtual Environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Authenticate to Google Cloud
gcloud auth login
gcloud auth application-default login

# 3. Run Discovery against a Project or Organization
python scc_discovery.py --project-id YOUR_PROJECT_ID --output-pdf scc_discovery_report.pdf
```

### Option 3: Offline Demo Mode (No GCP Account Needed)
```bash
# Offline demo run for a Project or Organization:
python scc_discovery.py --mock-data --output-pdf scc_demo_report.pdf
```

### Option 4: Running the End-to-End Test Suite
```bash
python test_e2e.py
```

---

## Repository Structure

```
.
├── scc_discovery.py             # Main CLI entrypoint (Supports --project-id, --org-id, --folder-id)
├── test_e2e.py                  # End-to-end automated test suite
├── requirements.txt             # Required Python dependencies
├── .gitignore                   # Git ignore patterns for Python, outputs & credentials
├── README.md                    # Project overview & quickstart
├── INSTRUCTIONS.md              # Detailed authentication, IAM setup & execution guide
├── discovery/                   # Read-only GCP API Collector Modules
│   ├── __init__.py
│   ├── auth.py                  # GCP authentication (ADC handling)
│   ├── scc_core.py              # SCC tier, scope settings, built-in services & custom rules
│   ├── postures.py              # Security Posture Management & deployments
│   ├── dlp_sdp.py               # Sensitive Data Protection (DLP) discovery & inspect templates
│   ├── exports_mutes.py         # Continuous exports (Pub/Sub & BigQuery) and Mute rules
│   ├── connectors.py            # Multi-cloud, ticketing, and SIEM connectors
│   ├── findings.py              # Findings aggregation (by source, category, severity, class)
│   ├── compliance.py            # Compliance benchmarks and control tracking
│   ├── assets.py                # Asset inventory breakdown by resource type
│   ├── hierarchy.py             # Organization, folder, project hierarchy and coverage
│   └── mock_data.py             # High-fidelity synthetic dataset for demo/offline runs
└── report/                      # Reporting & Migration Mapping Modules
    ├── __init__.py
    ├── migration_mapping.py     # Cloud security migration taxonomy, readiness scoring & roadmap
    └── pdf_generator.py         # ReportLab PDF engine (executive styling & NumberedCanvas)
```

---

## Documentation

For full step-by-step instructions on IAM permissions setup at the Project or Organization level, granting roles via `gcloud`, command-line arguments, and how to download and review the generated outputs, see [INSTRUCTIONS.md](file:///Users/jeff.fry/git/scc-discovery/INSTRUCTIONS.md).
