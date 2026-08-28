# Google Cloud SCC Discovery & Security Posture Assessment Tool
## Setup, IAM Permissions, Authentication & Execution Guide

This document provides step-by-step instructions for cloning the repository, configuring **read-only Google Cloud IAM permissions**, authenticating, and running the discovery tool in **Google Cloud Shell** or your **Local Terminal** to audit **Security Command Center (SCC)** across **Standalone Projects** (projects with no Organization node), **Folders**, or full **Organizations**, and generate an executive **Security Posture Assessment Report (PDF & JSON)**.

---

## Table of Contents
1. [Cloning the Repository](#1-cloning-the-repository)
   - [Option A: Clone with `git` (HTTPS or SSH)](#option-a-clone-with-git-https-or-ssh)
   - [Option B: Clone with GitHub CLI (`gh`)](#option-b-clone-with-github-cli-gh)
2. [Execution Environments & System Requirements](#2-execution-environments--system-requirements)
   - [Environment A: Google Cloud Shell (Recommended - Zero Setup)](#environment-a-google-cloud-shell-recommended---zero-setup)
   - [Environment B: Local Terminal (macOS / Linux / Windows WSL)](#environment-b-local-terminal-macos--linux--windows-wsl)
3. [Required Read-Only IAM Permissions & Roles](#3-required-read-only-iam-permissions--roles)
   - [Predefined Read-Only Roles](#predefined-read-only-roles)
   - [Granular API Permissions Breakdown](#granular-api-permissions-breakdown)
   - [Optional: Custom Least-Privilege IAM Role (YAML)](#optional-custom-least-privilege-iam-role-yaml)
4. [Granting IAM Permissions via `gcloud`](#4-granting-iam-permissions-via-gcloud)
   - [Case 1: Standalone Project (No Organization Node)](#case-1-standalone-project-no-organization-node)
   - [Case 2: Organization-Wide Discovery](#case-2-organization-wide-discovery)
5. [Enabling Required Google Cloud APIs](#5-enabling-required-google-cloud-apis)
6. [Authentication Walkthrough](#6-authentication-walkthrough)
   - [Running in Google Cloud Shell](#running-in-google-cloud-shell)
   - [Running in Local Terminal (Application Default Credentials)](#running-in-local-terminal-application-default-credentials)
7. [Running the Discovery Script](#7-running-the-discovery-script)
   - [Standalone Project Audit (No Organization Needed)](#standalone-project-audit-no-organization-needed)
   - [Organization-Wide Audit](#organization-wide-audit)
   - [Folder-Scoped Audit](#folder-scoped-audit)
   - [Offline / Demo Mode (No GCP Connection Needed)](#offline--demo-mode-no-gcp-connection-needed)
   - [Downloading the PDF from Cloud Shell](#downloading-the-pdf-from-cloud-shell)
   - [CLI Arguments Reference](#cli-arguments-reference)
8. [Reviewing the Generated Outputs](#8-reviewing-the-generated-outputs)
9. [Automated End-to-End (E2E) Testing](#9-automated-end-to-end-e2e-testing)
10. [Troubleshooting & FAQ](#10-troubleshooting--faq)

---

## 1. Cloning the Repository

First, clone the repository to your environment (Google Cloud Shell or your local machine):

### Option A: Clone with `git` (HTTPS or SSH)

```bash
# Clone using HTTPS:
git clone https://github.com/<YOUR-GITHUB-ORG-OR-ACCOUNT>/scc-discovery.git

# Or clone using SSH:
git clone git@github.com:<YOUR-GITHUB-ORG-OR-ACCOUNT>/scc-discovery.git

# Enter the repository directory:
cd scc-discovery
```

### Option B: Clone with GitHub CLI (`gh`)

If you use the [GitHub CLI](https://cli.github.com/):

```bash
# Authenticate GitHub CLI (if not already authenticated)
gh auth login

# Clone the repository:
gh repo clone <YOUR-GITHUB-ORG-OR-ACCOUNT>/scc-discovery

# Enter the repository directory:
cd scc-discovery
```

> **Note**: Replace `<YOUR-GITHUB-ORG-OR-ACCOUNT>` with the organization or user account where the repository is hosted.

---

## 2. Execution Environments & System Requirements

This tool is designed to be executed directly by security engineers and administrators in either **Google Cloud Shell** or a **Local Terminal**.

### Environment A: Google Cloud Shell (Recommended - Zero Setup)
Google Cloud Shell runs directly in your browser with `gcloud`, `git`, and `python3` pre-installed and automatically authenticated with your Google account.
- **Access**: Open [https://shell.cloud.google.com](https://shell.cloud.google.com) or click the **Activate Cloud Shell** icon in the Google Cloud Console header.

### Environment B: Local Terminal (macOS / Linux / Windows WSL)
- **Git**: `git` or GitHub CLI `gh` installed.
- **Python**: Version `3.9` or higher (`python3 --version`).
- **Google Cloud SDK**: `gcloud` CLI installed and initialized (`gcloud init`).

---

## 3. Required Read-Only IAM Permissions & Roles

All operations performed by this tool are **100% read-only**. The tool issues only `GET`, `LIST`, and `POST (group/search)` API queries. It does not modify, create, mute, or delete any resources or findings.

### Predefined Read-Only Roles

Depending on whether you are auditing an **Organization** or a **Standalone Project**, grant the following read-only roles:

| Predefined Role Name | Role ID | Purpose & Data Gathered |
| :--- | :--- | :--- |
| **Security Center Admin Viewer** | `roles/securitycenter.adminViewer` | Queries SCC tier, settings, registered sources, custom detection rules (SHA & ETD), continuous exports (Pub/Sub & BigQuery), mute rules, and server-side finding counts. |
| **Security Postures Viewer** | `roles/securityposture.viewer` | Discovers security postures, policy sets, posture deployments (Enterprise tier). |
| **DLP Reader / Viewer** | `roles/dlp.reader` | Inspects Sensitive Data Protection (Cloud DLP) discovery configs (profiling), inspect templates, de-identify rules, and job triggers. |
| **Cloud Asset Viewer** | `roles/cloudasset.viewer` | Catalogs cloud asset inventory and groups assets across resource types. |
| **Resource Manager Viewer** | `roles/resourcemanager.viewer` | Discovers project metadata and parent hierarchy. |

---

### Granular API Permissions Breakdown

If your security policy enforces custom granular roles, the following read permissions are required:

```
# Security Command Center (SCC)
securitycenter.organizationsettings.get  (for Org scope)
securitycenter.sources.list
securitycenter.sources.get
securitycenter.findings.list
securitycenter.findings.group
securitycenter.muteconfigs.list
securitycenter.muteconfigs.get
securitycenter.notificationconfig.list
securitycenter.notificationconfig.get
securitycenter.bigqueryexports.list
securitycenter.bigqueryexports.get
securitycenter.securityhealthanalyticscustommodules.list
securitycenter.eventthreatdetectioncustommodules.list

# Sensitive Data Protection (Cloud DLP)
dlp.discoveryConfigs.list
dlp.discoveryConfigs.get
dlp.inspectTemplates.list
dlp.inspectTemplates.get
dlp.deidentifyTemplates.list
dlp.deidentifyTemplates.get
dlp.jobTriggers.list
dlp.jobTriggers.get

# Cloud Asset Inventory & Resource Manager
cloudasset.assets.searchAllResources
resourcemanager.projects.get
resourcemanager.organizations.get (for Org scope)
resourcemanager.folders.list (for Org/Folder scope)
```

---

### Optional: Custom Least-Privilege IAM Role (YAML)

To create a single custom role with only the required read permissions:

1. Save the following YAML definition as `scc_discovery_role.yaml`:
```yaml
title: "SCC Read-Only Discovery Auditor"
description: "Minimal read-only permissions to audit SCC configuration and asset posture."
stage: "GA"
includedPermissions:
  - securitycenter.sources.list
  - securitycenter.sources.get
  - securitycenter.findings.list
  - securitycenter.findings.group
  - securitycenter.muteconfigs.list
  - securitycenter.muteconfigs.get
  - securitycenter.notificationconfig.list
  - securitycenter.notificationconfig.get
  - securitycenter.bigqueryexports.list
  - securitycenter.bigqueryexports.get
  - dlp.discoveryConfigs.list
  - dlp.discoveryConfigs.get
  - dlp.inspectTemplates.list
  - dlp.inspectTemplates.get
  - dlp.deidentifyTemplates.list
  - dlp.jobTriggers.list
  - cloudasset.assets.searchAllResources
  - resourcemanager.projects.get
```

2. Create the role at the Project or Organization level:
```bash
# At Project Level:
PROJECT_ID="YOUR_PROJECT_ID"
gcloud iam roles create sccDiscoveryAuditor --project=$PROJECT_ID --file=scc_discovery_role.yaml

# Or at Organization Level:
ORG_ID="YOUR_ORGANIZATION_ID"
gcloud iam roles create sccDiscoveryAuditor --organization=$ORG_ID --file=scc_discovery_role.yaml
```

---

## 4. Granting IAM Permissions via `gcloud`

### Case 1: Standalone Project (No Organization Node)
If your project is standalone (or you only have permissions on a specific project):

```bash
PROJECT_ID="YOUR_PROJECT_ID"          # Replace with your project ID (e.g. secops-prod)
USER_EMAIL="your-email@company.com"   # Replace with your Google user account email

for ROLE in \
    roles/securitycenter.adminViewer \
    roles/dlp.reader \
    roles/cloudasset.viewer \
    roles/resourcemanager.viewer; do
    gcloud projects add-iam-policy-binding $PROJECT_ID \
        --member="user:$USER_EMAIL" \
        --role="$ROLE"
done
```

---

### Case 2: Organization-Wide Discovery
If auditing an entire Organization:

```bash
ORG_ID="YOUR_ORGANIZATION_ID"        # Replace with your numeric Org ID (e.g. 123456789012)
USER_EMAIL="your-email@company.com"   # Replace with your Google user account email

for ROLE in \
    roles/securitycenter.adminViewer \
    roles/securityposture.viewer \
    roles/dlp.reader \
    roles/cloudasset.viewer \
    roles/resourcemanager.organizationViewer; do
    gcloud organizations add-iam-policy-binding $ORG_ID \
        --member="user:$USER_EMAIL" \
        --role="$ROLE"
done
```

---

## 5. Enabling Required Google Cloud APIs

Ensure the following Google Cloud security APIs are active on your project:

```bash
gcloud services enable \
    securitycenter.googleapis.com \
    dlp.googleapis.com \
    cloudasset.googleapis.com \
    cloudresourcemanager.googleapis.com
```

---

## 6. Authentication Walkthrough

### Running in Google Cloud Shell
Google Cloud Shell already has your user session active:

```bash
# 1. Authorize gcloud to generate Application Default Credentials
gcloud auth application-default login

# 2. Setup virtual environment and install packages
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

### Running in Local Terminal (Application Default Credentials)
If executing from your local macOS / Linux terminal:

```bash
# 1. Login with your Google account
gcloud auth login

# 2. Generate Application Default Credentials (ADC)
gcloud auth application-default login

# 3. Setup virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 7. Running the Discovery Script

### Standalone Project Audit (No Organization Needed)
To audit a project-level SCC instance:

```bash
python scc_discovery.py \
    --project-id YOUR_PROJECT_ID \
    --output-pdf scc_discovery_report.pdf \
    --output-json scc_discovery_raw.json
```

### Organization-Wide Audit
To audit an entire Google Cloud Organization:

```bash
python scc_discovery.py \
    --org-id 108429384721 \
    --output-pdf scc_discovery_report.pdf \
    --output-json scc_discovery_raw.json
```

### Folder-Scoped Audit
```bash
python scc_discovery.py \
    --folder-id 948201948271 \
    --output-pdf prod_folder_scc_report.pdf
```

### Offline / Demo Mode (No GCP Connection Needed)
To preview report generation without GCP credentials:
```bash
python scc_discovery.py \
    --mock-data \
    --output-pdf scc_demo_report.pdf \
    --output-json scc_demo_raw.json
```

### Downloading the PDF from Cloud Shell
If you ran the script in **Google Cloud Shell**, download the generated PDF to your local machine:

```bash
cloudshell download scc_discovery_report.pdf
```
*(Or click the three dots icon `⋮` in the Cloud Shell top bar and select **Download File** -> enter `scc_discovery_report.pdf`)*.

---

### CLI Arguments Reference

| Argument | Description | Default |
| :--- | :--- | :--- |
| `--project-id` | GCP Project ID to audit a standalone or project-scoped SCC instance. | `None` |
| `--org-id` | GCP Organization ID (numeric string or `organizations/123`). | `None` |
| `--folder-id` | Optional GCP Folder ID to scope hierarchy discovery. | `None` |
| `--location` | Regional or global endpoint location. | `global` |
| `--output-pdf` | Path for the generated PDF assessment report. | `scc_discovery_report.pdf` |
| `--output-json` | Optional path to export the complete discovery dataset as JSON. | `None` |
| `--mock-data`, `--demo` | Runs discovery using a synthetic dataset for offline demos. | `False` |
| `-v`, `--verbose` | Enables detailed debug logging in console. | `False` |

---

## 8. Reviewing the Generated Outputs

### Terminal Summary
Upon completion, the tool prints an executive summary table to the console detailing scope, tier, asset volume, findings breakdown, and architecture readiness score.

### Executive PDF Report (`scc_discovery_report.pdf`)
The generated PDF is an 8-page, publication-quality document containing:
1. **Cover Page & Metadata**: Scope target (Project/Org), ID, auditor identity, and assessment date.
2. **Section 1 - Executive Summary & Scorecard**: 6 visual metric stat cards and readiness breakdown score (0-100).
3. **Section 2 - SCC Tier & Built-in Services**: Tier classification, asset discovery status, service agents, and status of SHA, ETD, CTD, VMTD, RVD, WSS, SDP, and custom detection rules.
4. **Section 3 - Security Postures & Sensitive Data (DLP)**: Postures, deployments, templates, discovery configs, and inspect templates.
5. **Section 4 - Continuous Exports, Mute Rules & Connectors**: Pub/Sub topics, BigQuery tables, CEL suppression mute rules, and multi-cloud/ticketing connectors (AWS, Azure, Jira, ServiceNow, Chronicle).
6. **Section 5 - Findings Deep-Dive & Compliance**: Server-side finding counts by source detector, top categories, severities, and active compliance standards (CIS GCP Foundations, NIST 800-53, PCI-DSS, ISO 27001, SOC 2, HIPAA).
7. **Section 6 - Asset Inventory & Hierarchy Coverage**: Resource counts across Compute, Storage, Databases, IAM, and Networking, plus complete folder/project hierarchy.
8. **Section 7 - Cloud Security Migration Blueprint**: Architectural translation matrix and 4-phase turnkey migration execution roadmap.

### Raw JSON Dataset (`scc_discovery_raw.json`)
Contains the full machine-readable JSON structure for programmatic analysis or import.

---

## 9. Automated End-to-End (E2E) Testing

A dedicated test suite [`test_e2e.py`](file:///Users/jeff.fry/git/scc-discovery/test_e2e.py) is included to validate the entire discovery, JSON serialization, PDF rendering, and CLI execution pipeline across both Project and Organization scopes.

### Running the Test Suite
```bash
# Run via python directly
python test_e2e.py

# Or run with verbose unittest discovery
python3 -m unittest test_e2e.py -v
```

---

## 10. Troubleshooting & FAQ

### Q: I have an SCC instance on a project with no organization. How do I run the tool?
**Solution**: Run `python scc_discovery.py --project-id YOUR_PROJECT_ID`. The tool will automatically scope all SCC, DLP, Asset, and Findings API queries to your project without requiring an Organization resource.

### Q: I received `403 Forbidden` / `PERMISSION_DENIED` on Organization Settings or Postures.
**Solution**: Ensure your user identity has `roles/securitycenter.adminViewer` granted on the project (`gcloud projects add-iam-policy-binding`) or organization (`gcloud organizations add-iam-policy-binding`).

### Q: `securityposture.googleapis.com` or `dlp.googleapis.com` returned `404 Not Found`.
**Solution**: On project-scoped or Standard tier instances, Organization Postures are not active. The script automatically catches this, records the feature as `NOT_APPLICABLE (Project Scope)`, and continues discovering all other resources without failing.
