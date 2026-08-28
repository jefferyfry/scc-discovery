# Google Cloud SCC Discovery & Security Posture Assessment Tool
## Setup, IAM Permissions, Authentication & Execution Guide

This document provides step-by-step instructions for cloning the repository, configuring **read-only Google Cloud IAM permissions**, authenticating, and running the discovery tool in **Google Cloud Shell** or your **Local Terminal** to audit **Security Command Center (SCC)** and generate an executive **Security Posture Assessment Report (PDF & JSON)**.

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
5. [Enabling Required Google Cloud APIs](#5-enabling-required-google-cloud-apis)
6. [Authentication Walkthrough](#6-authentication-walkthrough)
   - [Running in Google Cloud Shell](#running-in-google-cloud-shell)
   - [Running in Local Terminal (Application Default Credentials)](#running-in-local-terminal-application-default-credentials)
7. [Locating Your Google Cloud Organization ID](#7-locating-your-google-cloud-organization-id)
8. [Running the Discovery Script](#8-running-the-discovery-script)
   - [Full Organization Audit (Generates PDF & JSON)](#full-organization-audit-generates-pdf--json)
   - [Folder-Scoped Audit](#folder-scoped-audit)
   - [Project-Scoped Audit](#project-scoped-audit)
   - [Offline / Demo Mode (No GCP Connection Needed)](#offline--demo-mode-no-gcp-connection-needed)
   - [Downloading the PDF from Cloud Shell](#downloading-the-pdf-from-cloud-shell)
   - [CLI Arguments Reference](#cli-arguments-reference)
9. [Reviewing the Generated Outputs](#9-reviewing-the-generated-outputs)
10. [Automated End-to-End (E2E) Testing](#10-automated-end-to-end-e2e-testing)
11. [Troubleshooting & FAQ](#11-troubleshooting--faq)

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

To audit an organization, your user account requires the following predefined read-only roles at the **Organization level** (or Folder level if scoped):

| Predefined Role Name | Role ID | Purpose & Data Gathered |
| :--- | :--- | :--- |
| **Security Center Admin Viewer** | `roles/securitycenter.adminViewer` | Queries SCC tier, organization settings, registered sources, custom detection rules (SHA & ETD), continuous exports (Pub/Sub & BigQuery), mute rules, and server-side finding counts. |
| **Security Postures Viewer** | `roles/securityposture.viewer` | Discovers security postures, policy sets, posture deployments, and posture templates. |
| **DLP Reader / Viewer** | `roles/dlp.reader` | Inspects Sensitive Data Protection (Cloud DLP) discovery configs (profiling), inspect templates, de-identify rules, and job triggers. |
| **Cloud Asset Viewer** | `roles/cloudasset.viewer` | Catalogs cloud asset inventory and groups assets across resource types. |
| **Resource Manager Organization Viewer** | `roles/resourcemanager.organizationViewer` | Discovers organization hierarchy, folders tree, and project inventory for coverage analysis. |

---

### Granular API Permissions Breakdown

If your security policy enforces custom granular roles, the following read permissions are required:

```
# Security Command Center (SCC)
securitycenter.organizationsettings.get
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

# Security Posture Management (SCC Enterprise)
securityposture.postures.list
securityposture.postures.get
securityposture.postureDeployments.list
securityposture.postureDeployments.get
securityposture.postureTemplates.list
securityposture.postureTemplates.get

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
resourcemanager.organizations.get
resourcemanager.folders.list
resourcemanager.folders.get
resourcemanager.projects.list
resourcemanager.projects.get
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
  - securitycenter.organizationsettings.get
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
  - securityposture.postures.list
  - securityposture.postures.get
  - securityposture.postureDeployments.list
  - securityposture.postureDeployments.get
  - securityposture.postureTemplates.list
  - dlp.discoveryConfigs.list
  - dlp.discoveryConfigs.get
  - dlp.inspectTemplates.list
  - dlp.inspectTemplates.get
  - dlp.deidentifyTemplates.list
  - dlp.jobTriggers.list
  - cloudasset.assets.searchAllResources
  - resourcemanager.organizations.get
  - resourcemanager.folders.list
  - resourcemanager.projects.list
```

2. Create the role at the organization level:
```bash
ORG_ID="YOUR_ORGANIZATION_ID"
gcloud iam roles create sccDiscoveryAuditor \
    --organization=$ORG_ID \
    --file=scc_discovery_role.yaml
```

---

## 4. Granting IAM Permissions via `gcloud`

Run the following commands in Cloud Shell or Terminal (executed by an Organization Administrator):

```bash
ORG_ID="YOUR_ORGANIZATION_ID"        # Replace with your numeric Org ID (e.g. 123456789012)
USER_EMAIL="your-email@company.com"   # Replace with your Google user account email

# Grant required read-only roles at Organization level
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

Ensure the following Google Cloud security APIs are active:

```bash
gcloud services enable \
    securitycenter.googleapis.com \
    securityposture.googleapis.com \
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
# 1. Login with your Google Workspace / Cloud Identity account
gcloud auth login

# 2. Generate Application Default Credentials (ADC)
gcloud auth application-default login

# 3. Setup virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 7. Locating Your Google Cloud Organization ID

To find your Organization ID:

```bash
gcloud organizations list
```

Example Output:
```
DISPLAY_NAME          ID            DIRECTORY_CUSTOMER_ID
enterprise-corp.com   108429384721  C01ab2c3d
```
Use the numeric value `108429384721` as the argument to `--org-id`.

---

## 8. Running the Discovery Script

### Full Organization Audit (Generates PDF & JSON)
```bash
python scc_discovery.py \
    --org-id 108429384721 \
    --output-pdf scc_discovery_report.pdf \
    --output-json scc_discovery_raw.json
```

### Folder-Scoped Audit
```bash
python scc_discovery.py \
    --org-id 108429384721 \
    --folder-id 948201948271 \
    --output-pdf prod_folder_scc_report.pdf
```

### Project-Scoped Audit
```bash
python scc_discovery.py \
    --org-id 108429384721 \
    --project-id ecommerce-frontend-prod \
    --output-pdf project_scc_report.pdf
```

### Offline / Demo Mode (No GCP Connection Needed)
To preview report generation and inspect sample outputs without GCP credentials:
```bash
python scc_discovery.py \
    --mock-data \
    --output-pdf scc_demo_report.pdf \
    --output-json scc_demo_raw.json
```

### Downloading the PDF from Cloud Shell
If you ran the script in **Google Cloud Shell**, download the generated PDF to your local machine using the built-in command:

```bash
cloudshell download scc_discovery_report.pdf
```
*(Or click the three dots icon `⋮` in the Cloud Shell top bar and select **Download File** -> enter `scc_discovery_report.pdf`)*.

---

### CLI Arguments Reference

| Argument | Description | Default |
| :--- | :--- | :--- |
| `--org-id` | GCP Organization ID (numeric string or `organizations/123`). | `None` (Required for live runs) |
| `--folder-id` | Optional GCP Folder ID to scope hierarchy discovery. | `None` |
| `--project-id` | Optional GCP Project ID to scope discovery to a single project. | `None` |
| `--location` | Regional or global endpoint location. | `global` |
| `--output-pdf` | Path for the generated PDF assessment report. | `scc_discovery_report.pdf` |
| `--output-json` | Optional path to export the complete discovery dataset as JSON. | `None` |
| `--mock-data`, `--demo` | Runs discovery using a synthetic enterprise dataset for offline demos. | `False` |
| `-v`, `--verbose` | Enables detailed debug logging in console. | `False` |

---

## 9. Reviewing the Generated Outputs

### Terminal Summary
Upon completion, the tool prints an executive summary table to the console detailing tier, asset volume, findings breakdown, and architecture readiness score.

### Executive PDF Report (`scc_discovery_report.pdf`)
The generated PDF is an 8-page, publication-quality document containing:
1. **Cover Page & Metadata**: Organization ID, scope, auditor identity, and assessment date.
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

## 10. Automated End-to-End (E2E) Testing

A dedicated test suite [`test_e2e.py`](file:///Users/jeff.fry/git/scc-discovery/test_e2e.py) is included to validate the entire discovery, JSON serialization, PDF rendering, and CLI execution pipeline without requiring live GCP credentials.

### Running the Test Suite
```bash
# Run via python directly
python test_e2e.py

# Or run with verbose unittest discovery
python3 -m unittest test_e2e.py -v
```

### What the E2E Test Suite Validates:
1. **Mock Dataset & Schema Integrity**: Verifies that synthetic enterprise data contains all required keys and correct types across all 13 domains.
2. **Migration Readiness & Roadmap**: Validates scoring algorithms, rating thresholds, and 4-phase milestone deliverables.
3. **JSON Serialization**: Ensures the data structure serializes to valid JSON and reloads losslessly.
4. **ReportLab PDF Generation & Magic Bytes**: Verifies that `%PDF` header magic bytes are valid, minimum page count is met (>= 7 pages), and `NumberedCanvas` renders cleanly without layout overflows.
5. **Error Resilience (Mocked 403 & 404)**: Injects mocked HTTP 403 Forbidden and 404 Not Found errors to verify graceful degradation.
6. **Subprocess CLI Execution**: Executes `scc_discovery.py` as a real OS subprocess with `--mock-data`, `--output-pdf`, and `--output-json` to assert exit code `0`.

---

## 11. Troubleshooting & FAQ

### Q: I received `403 Forbidden` / `PERMISSION_DENIED` on Organization Settings or Postures.
**Solution**: Ensure your user identity has `roles/securitycenter.adminViewer` and `roles/securityposture.viewer` granted at the **Organization** level (`gcloud organizations add-iam-policy-binding`).

### Q: `securityposture.googleapis.com` or `dlp.googleapis.com` returned `404 Not Found`.
**Solution**: If running on SCC Standard tier, the Security Postures API is disabled. The script automatically catches this, records the feature as `UNAVAILABLE (Standard Tier)`, and continues discovering all other resources without failing.

### Q: How do I test the PDF formatting without live GCP credentials?
**Solution**: Run `python scc_discovery.py --mock-data --output-pdf preview.pdf` to generate a full report using synthetic enterprise data.
