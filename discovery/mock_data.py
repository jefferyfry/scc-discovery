"""
discovery/mock_data.py - High-Fidelity Synthetic GCP/SCC Enterprise Discovery Dataset

This module provides a complete, realistic dataset for offline testing, demos, and dry-runs
without requiring active GCP credentials or live API access.

It models an enterprise-grade Google Cloud environment running SCC Enterprise with:
- Multi-cloud connectors (AWS, Azure)
- Security Postures & Deployments
- Sensitive Data Protection (DLP) Automated Discovery & Inspection
- Threat Detection (ETD, CTD, VMTD, RVD)
- Custom SHA & ETD detection modules
- Continuous Exports (Pub/Sub & BigQuery)
- Mute Rules / Exceptions
- Findings aggregated across sources, categories, severities, and classes
- Compliance benchmark adherence (CIS, NIST, PCI-DSS, ISO, SOC 2, HIPAA)
- Asset inventory breakdown across 3,400+ resources
- Full Organization, Folder, and Project hierarchy coverage
"""

from typing import Dict, Any, Optional
from discovery.scc_core import normalize_resource


def get_mock_discovery_data(resource_id: Optional[str] = None, org_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate a full synthetic discovery dictionary.

    Args:
        resource_id: Mock organization ID, project ID, or folder ID.
        org_id: Backward-compatible alias for resource_id.

    Returns:
        Dict matching the schema produced by live GCP discovery collectors.
    """
    target = resource_id or org_id or "819203948571"
    parent_name, raw_id, scope_type = normalize_resource(target)
    is_org = (scope_type == "ORGANIZATION")
    org_name = parent_name if is_org else f"projects/{raw_id}"

    return {
        "metadata": {
            "mode": "DEMO / SYNTHETIC DATASET",
            "organization_id": raw_id,
            "organization_name": parent_name,
            "domain": "enterprise-corp.com" if is_org else f"{raw_id}.cloud",
            "caller_identity": "secops-architect@enterprise-corp.com (Cloud Security Architect)",
            "discovery_timestamp": "2026-08-27T16:30:00Z",
            "primary_location": "global",
            "scope_type": scope_type,
        },
        "scc_core": {
            "tier_info": {
                "tier_name": "Enterprise Tier" if is_org else "Standard Tier (Project Scope)",
                "tier_code": "ENTERPRISE" if is_org else "STANDARD",
                "description": "Full Multi-Cloud Security Posture, Advanced Threat Detection (ETD/CTD/VMTD), Posture Management, and Governance." if is_org else "Project-Scoped Security Command Center & Security Health Analytics.",
                "is_enterprise": is_org,
                "posture_api_status": "ACTIVE" if is_org else "NOT_CONFIGURED",
                "scope": f"{scope_type.capitalize()}-level ({parent_name})",
                "org_name": parent_name,
                "location": "global",
            },
            "organization_settings": {
                "status": "SUCCESS" if is_org else f"NOT_APPLICABLE ({scope_type.capitalize()} Scope)",
                "name": f"{parent_name}/organizationSettings" if is_org else parent_name,
                "enable_asset_discovery": True,
                "asset_discovery_mode": "AUTOMATIC",
                "asset_discovery_config": {
                    "inclusionMode": "INCLUDE_ALL_PROJECTS"
                }
            },
            "services_status": [
                {
                    "service_id": "sha",
                    "display_name": "Security Health Analytics (SHA)",
                    "category": "Cloud Security Posture Management (CSPM)",
                    "description": "Scans GCP resources for security misconfigurations and compliance violations.",
                    "enabled": True,
                    "status": "ENABLED",
                    "tier_requirement": "Standard (Basic) / Premium / Enterprise (Full + Custom Rules)",
                    "custom_rules_count": 6,
                    "target_capability_mapping": "Cloud Security Posture Management (CSPM) & Custom Configuration Rules",
                },
                {
                    "service_id": "wss",
                    "display_name": "Web Security Scanner (WSS)",
                    "category": "Application Security (DAST)",
                    "description": "Crawls and analyzes public App Engine, GKE, and Compute Engine web endpoints for OWASP flaws.",
                    "enabled": True,
                    "status": "ENABLED",
                    "tier_requirement": "Premium / Enterprise",
                    "custom_rules_count": 0,
                    "target_capability_mapping": "Dynamic Application Security Testing (DAST) & Inventory",
                },
                {
                    "service_id": "etd",
                    "display_name": "Event Threat Detection (ETD)",
                    "category": "Cloud Detection and Response (CDR)",
                    "description": "Analyzes Cloud Audit logs, VPC Flow logs, and DNS queries for malicious behavior.",
                    "enabled": True,
                    "status": "ENABLED",
                    "tier_requirement": "Premium / Enterprise",
                    "custom_rules_count": 3,
                    "target_capability_mapping": "Cloud Detection & Response (CDR) & Cloud Events Analysis",
                },
                {
                    "service_id": "ctd",
                    "display_name": "Container Threat Detection (CTD)",
                    "category": "Cloud Workload Protection (CWPP)",
                    "description": "Detects runtime container execution anomalies, suspicious binaries, and reverse shells in GKE.",
                    "enabled": True,
                    "status": "ENABLED",
                    "tier_requirement": "Premium / Enterprise",
                    "custom_rules_count": 0,
                    "target_capability_mapping": "Runtime Workload Sensor & K8s Admission Control",
                },
                {
                    "service_id": "vmtd",
                    "display_name": "Virtual Machine Threat Detection (VMTD)",
                    "category": "Cloud Workload Protection (CWPP)",
                    "description": "Agentless hypervisor-level memory scanning for kernel rootkits and crypto-mining on VMs.",
                    "enabled": is_org,
                    "status": "ENABLED" if is_org else "DISABLED",
                    "tier_requirement": "Premium / Enterprise",
                    "custom_rules_count": 0,
                    "target_capability_mapping": "Agentless VM Scanning & Runtime Behavioral Detection",
                },
                {
                    "service_id": "cloud_run_td",
                    "display_name": "Cloud Run Threat Detection",
                    "category": "Serverless Workload Protection",
                    "description": "Monitors runtime executions in Cloud Run serverless container instances for suspicious activity.",
                    "enabled": False,
                    "status": "DISABLED",
                    "tier_requirement": "Premium / Enterprise",
                    "custom_rules_count": 0,
                    "target_capability_mapping": "Serverless Container Runtime Defense",
                },
                {
                    "service_id": "rvd",
                    "display_name": "Vulnerability Assessment & Rapid Vulnerability Detection",
                    "category": "Vulnerability Management",
                    "description": "Scans public-facing workloads for zero-day vulnerabilities and critical remote code execution (RCE) flaws.",
                    "enabled": True,
                    "status": "ENABLED",
                    "tier_requirement": "Premium / Enterprise",
                    "custom_rules_count": 0,
                    "target_capability_mapping": "Vulnerability Management & Attack Surface Analysis",
                },
                {
                    "service_id": "notebook_scanner",
                    "display_name": "Notebook Security Scanner",
                    "category": "AI / ML Workspace Security",
                    "description": "Detects security vulnerabilities and credential exposures across Vertex AI Workbench notebooks.",
                    "enabled": False,
                    "status": "DISABLED",
                    "tier_requirement": "Premium / Enterprise",
                    "custom_rules_count": 0,
                    "target_capability_mapping": "Data Science & AI Workspace Posture",
                },
                {
                    "service_id": "artifact_guard",
                    "display_name": "Artifact Guard / Container Analysis",
                    "category": "Software Supply Chain Security",
                    "description": "Scans container images stored in Artifact Registry / Container Registry for OS vulnerabilities.",
                    "enabled": False,
                    "status": "DISABLED",
                    "tier_requirement": "Standard / Premium / Enterprise",
                    "custom_rules_count": 0,
                    "target_capability_mapping": "Container Registry & CI/CD Vulnerability Scanning",
                },
                {
                    "service_id": "compliance_manager",
                    "display_name": "Compliance Manager / Evaluation Service",
                    "category": "Regulatory Compliance",
                    "description": "Continuously audits workloads against CIS, NIST 800-53, PCI-DSS, ISO 27001, and SOC 2.",
                    "enabled": is_org,
                    "status": "ENABLED" if is_org else "DISABLED",
                    "tier_requirement": "Enterprise Tier",
                    "custom_rules_count": 0,
                    "target_capability_mapping": "Automated Multi-Standard Compliance Auditing",
                },
                {
                    "service_id": "ai_protection",
                    "display_name": "AI Protection & Model Armor",
                    "category": "Generative AI Security",
                    "description": "Provides runtime guardrails and prompt injection defenses for LLMs and AI workloads.",
                    "enabled": False,
                    "status": "DISABLED",
                    "tier_requirement": "Enterprise Tier",
                    "custom_rules_count": 0,
                    "target_capability_mapping": "Generative AI & LLM Runtime Guardrails",
                },
                {
                    "service_id": "external_exposure",
                    "display_name": "External Exposure & Attack Surface Management",
                    "category": "External Attack Surface (EASM)",
                    "description": "Discovers publicly exposed cloud assets, dangling DNS records, and shadow cloud resources.",
                    "enabled": False,
                    "status": "DISABLED",
                    "tier_requirement": "Enterprise Tier",
                    "custom_rules_count": 0,
                    "target_capability_mapping": "External Attack Surface Management (EASM)",
                },
                {
                    "service_id": "sdp",
                    "display_name": "Sensitive Data Protection (SDP / Cloud DLP)",
                    "category": "Data Security Posture Management (DSPM)",
                    "description": "Automated discovery and classification of sensitive data in GCS, BigQuery, and Cloud SQL.",
                    "enabled": is_org,
                    "status": "ENABLED" if is_org else "DISABLED",
                    "tier_requirement": "Premium / Enterprise (Integrated)",
                    "custom_rules_count": 0,
                    "target_capability_mapping": "Data Security Posture Management (DSPM) & Classification",
                },
                {
                    "service_id": "anomaly",
                    "display_name": "Cloud Anomaly Detection",
                    "category": "Behavioral Analytics",
                    "description": "Detects anomalous account activities, abnormal resource spikes, and compromised IAM identities.",
                    "enabled": False,
                    "status": "DISABLED",
                    "tier_requirement": "Standard / Premium / Enterprise",
                    "custom_rules_count": 0,
                    "target_capability_mapping": "Identity Threat Detection & Behavioral Profiling",
                }
            ],
            "sha_custom_modules": [
                {
                    "name": f"{org_name}/securityHealthAnalyticsCustomModules/custom_deny_public_gcs",
                    "display_name": "Enforce Private GCS Buckets (No AllUsers / AllAuth)",
                    "enablement_state": "ENABLED",
                    "severity": "CRITICAL",
                    "description": "Flags any Cloud Storage bucket configured with public IAM read or write grants.",
                },
                {
                    "name": f"{org_name}/securityHealthAnalyticsCustomModules/custom_enforce_cmek_bigquery",
                    "display_name": "Mandate Customer-Managed Encryption (CMEK) for BigQuery",
                    "enablement_state": "ENABLED",
                    "severity": "HIGH",
                    "description": "Ensures all BigQuery datasets are encrypted using organization KMS keys.",
                },
                {
                    "name": f"{org_name}/securityHealthAnalyticsCustomModules/custom_disallow_default_sa",
                    "display_name": "Block Compute Engine Default Service Account Usage",
                    "enablement_state": "ENABLED",
                    "severity": "HIGH",
                    "description": "Detects VMs running with default Compute Service Account with Editor permissions.",
                },
                {
                    "name": f"{org_name}/securityHealthAnalyticsCustomModules/custom_require_shielded_vm",
                    "display_name": "Require Shielded VM & Secure Boot on all Compute Instances",
                    "enablement_state": "ENABLED",
                    "severity": "MEDIUM",
                    "description": "Enforces Secure Boot, vTPM, and Integrity Monitoring on GCE instances.",
                },
                {
                    "name": f"{org_name}/securityHealthAnalyticsCustomModules/custom_deny_egress_all",
                    "display_name": "Flag Unrestricted 0.0.0.0/0 Egress Firewall Rules",
                    "enablement_state": "ENABLED",
                    "severity": "MEDIUM",
                    "description": "Alerts on custom VPC firewall rules allowing unrestricted outbound traffic on high-risk ports.",
                },
                {
                    "name": f"{org_name}/securityHealthAnalyticsCustomModules/custom_require_binary_authorization",
                    "display_name": "Require Binary Authorization on Production GKE Clusters",
                    "enablement_state": "ENABLED",
                    "severity": "HIGH",
                    "description": "Validates container signature verification is enforced before pod scheduling in GKE.",
                }
            ],
            "etd_custom_modules": [
                {
                    "name": f"{org_name}/eventThreatDetectionCustomModules/etd_high_priv_role_grant",
                    "display_name": "Anomalous Organization Admin Role Grant",
                    "enablement_state": "ENABLED",
                    "type": "CUSTOM_IAM_RULE",
                    "description": "Alerts in real-time when roles/owner or roles/resourcemanager.organizationAdmin is granted to an external identity."
                },
                {
                    "name": f"{org_name}/eventThreatDetectionCustomModules/etd_mass_data_egress",
                    "display_name": "Mass Cloud Storage Exfiltration to External IP",
                    "enablement_state": "ENABLED",
                    "type": "CUSTOM_NETWORK_RULE",
                    "description": "Monitors VPC Flow Logs for multi-gigabyte egress flows from private buckets to untrusted external ASNs."
                },
                {
                    "name": f"{org_name}/eventThreatDetectionCustomModules/etd_crypto_pool_dns",
                    "display_name": "Cryptomining Stratum Mining Pool DNS Query",
                    "enablement_state": "ENABLED",
                    "type": "CUSTOM_DNS_RULE",
                    "description": "Detects internal VM DNS queries resolving known Monero/Bitcoin mining pool endpoints."
                }
            ],
            "integrated_sources": [
                {"name": f"{org_name}/sources/1001", "source_id": "1001", "display_name": "Security Health Analytics", "description": "GCP Configuration Misconfiguration Detector", "is_builtin": True, "type": "BUILTIN"},
                {"name": f"{org_name}/sources/1002", "source_id": "1002", "display_name": "Event Threat Detection", "description": "Cloud Audit & VPC Log Threat Intelligence", "is_builtin": True, "type": "BUILTIN"},
                {"name": f"{org_name}/sources/1003", "source_id": "1003", "display_name": "Container Threat Detection", "description": "GKE Runtime Behavioral Security", "is_builtin": True, "type": "BUILTIN"},
                {"name": f"{org_name}/sources/1004", "source_id": "1004", "display_name": "Virtual Machine Threat Detection", "description": "Agentless Hypervisor Memory Inspection", "is_builtin": True, "type": "BUILTIN"},
                {"name": f"{org_name}/sources/1005", "source_id": "1005", "display_name": "Sensitive Data Protection", "description": "Cloud DLP Sensitive Data Discovery", "is_builtin": True, "type": "BUILTIN"},
                {"name": f"{org_name}/sources/1006", "source_id": "1006", "display_name": "Rapid Vulnerability Detection", "description": "Zero-day Attack Surface Scanner", "is_builtin": True, "type": "BUILTIN"},
                {"name": f"{org_name}/sources/1007", "source_id": "1007", "display_name": "Web Security Scanner", "description": "Application Security & OWASP Top 10", "is_builtin": True, "type": "BUILTIN"},
                {"name": f"{org_name}/sources/2001", "source_id": "2001", "display_name": "Tenable.io Vulnerability Bridge", "description": "Host Vulnerability Management Integration", "is_builtin": False, "type": "INTEGRATED_VENDOR"},
                {"name": f"{org_name}/sources/2002", "source_id": "2002", "display_name": "Palo Alto Prisma Cloud Feed", "description": "Legacy CSPM Finding Importer", "is_builtin": False, "type": "INTEGRATED_VENDOR"},
                {"name": f"{org_name}/sources/2003", "source_id": "2003", "display_name": "Custom SecOps Egress Sensor", "description": "Internal Custom Python Security Tool Findings", "is_builtin": False, "type": "INTEGRATED_VENDOR"}
            ],
            "setup_details": {
                "organization_id": raw_id,
                "organization_name": parent_name,
                "scope_type": scope_type,
                "primary_location": "global",
                "scc_service_agent": f"service-org-{raw_id}@security-center-api.iam.gserviceaccount.com" if is_org else f"service-{raw_id}@gcp-sa-scc.iam.gserviceaccount.com",
                "dlp_service_agent": f"service-org-{raw_id}@gcp-sa-dlp.iam.gserviceaccount.com" if is_org else f"service-{raw_id}@gcp-sa-dlp.iam.gserviceaccount.com",
                "asset_discovery_status": "AUTOMATIC" if is_org else "PROJECT_MANAGED",
                "api_endpoints_active": [
                    "securitycenter.googleapis.com (v1/v2)",
                    "securityposture.googleapis.com (v1)",
                    "dlp.googleapis.com (v2)",
                    "cloudasset.googleapis.com (v1)",
                    "cloudresourcemanager.googleapis.com (v3)"
                ]
            }
        },
        "postures": {
            "postures": [
                {
                    "name": f"{org_name}/locations/global/postures/gcp-enterprise-baseline",
                    "posture_id": "gcp-enterprise-baseline",
                    "state": "ACTIVE",
                    "revision_id": "v3.2",
                    "description": "Enterprise-wide mandatory security guardrails and CIS Foundations benchmark policies.",
                    "policy_sets_count": 4,
                    "total_rules_count": 52,
                    "policy_sets": [
                        {"policy_set_id": "iam-governance", "description": "Enforce MFA, deny external users, service account limits", "rules_count": 14},
                        {"policy_set_id": "network-perimeter", "description": "VPC Service Controls, firewall restrictions, private Google access", "rules_count": 16},
                        {"policy_set_id": "data-protection", "description": "CMEK enforcement, public bucket prevention, data retention", "rules_count": 12},
                        {"policy_set_id": "logging-auditing", "description": "Audit log sinks, retention lock, admin activity tracking", "rules_count": 10},
                    ],
                    "create_time": "2024-03-15T10:00:00Z",
                    "update_time": "2026-06-20T14:30:00Z",
                },
                {
                    "name": f"{org_name}/locations/global/postures/prod-workload-hardening",
                    "posture_id": "prod-workload-hardening",
                    "state": "ACTIVE",
                    "revision_id": "v2.0",
                    "description": "Strict workload protection posture deployed to all production Kubernetes (GKE) and VM folders.",
                    "policy_sets_count": 3,
                    "total_rules_count": 38,
                    "policy_sets": [
                        {"policy_set_id": "gke-hardening", "description": "Private clusters, Binary Auth, non-root containers, Network Policies", "rules_count": 18},
                        {"policy_set_id": "compute-hardening", "description": "Shielded VMs, OS Login, confidential computing, internal IP only", "rules_count": 12},
                        {"policy_set_id": "database-hardening", "description": "Cloud SQL SSL enforce, private IP, automated backups", "rules_count": 8},
                    ],
                    "create_time": "2024-08-10T12:00:00Z",
                    "update_time": "2026-07-12T09:15:00Z",
                },
                {
                    "name": f"{org_name}/locations/global/postures/multicloud-aws-posture",
                    "posture_id": "multicloud-aws-posture",
                    "state": "ACTIVE",
                    "revision_id": "v1.1",
                    "description": "Multi-cloud AWS posture assessment mapping AWS accounts to SCC Enterprise dashboard.",
                    "policy_sets_count": 2,
                    "total_rules_count": 24,
                    "policy_sets": [
                        {"policy_set_id": "aws-s3-guardrails", "description": "Block public S3 access, enforce SSE-KMS", "rules_count": 10},
                        {"policy_set_id": "aws-iam-guardrails", "description": "Deny root account access, MFA on console logins", "rules_count": 14},
                    ],
                    "create_time": "2025-01-20T16:00:00Z",
                    "update_time": "2026-05-18T11:45:00Z",
                }
            ],
            "posture_count": 3,
            "posture_deployments": [
                {
                    "name": f"{org_name}/locations/global/postureDeployments/dep-org-baseline",
                    "deployment_id": "dep-org-baseline",
                    "target_resource": org_name,
                    "posture_id": "gcp-enterprise-baseline",
                    "posture_revision_id": "v3.2",
                    "state": "ACTIVE",
                    "description": "Org-wide deployment of baseline posture covering all 22 projects.",
                    "failure_message": "",
                    "create_time": "2024-03-16T11:00:00Z",
                    "update_time": "2026-06-20T14:35:00Z"
                },
                {
                    "name": f"{org_name}/locations/global/postureDeployments/dep-prod-folder",
                    "deployment_id": "dep-prod-folder",
                    "target_resource": "folders/948201948271",
                    "posture_id": "prod-workload-hardening",
                    "posture_revision_id": "v2.0",
                    "state": "ACTIVE",
                    "description": "Production Folder deployment covering 10 mission-critical projects.",
                    "failure_message": "",
                    "create_time": "2024-08-11T13:00:00Z",
                    "update_time": "2026-07-12T09:20:00Z"
                },
                {
                    "name": f"{org_name}/locations/global/postureDeployments/dep-data-analytics-folder",
                    "deployment_id": "dep-data-analytics-folder",
                    "target_resource": "folders/948201948272",
                    "posture_id": "prod-workload-hardening",
                    "posture_revision_id": "v2.0",
                    "state": "ACTIVE",
                    "description": "Data Analytics folder deployment enforcing strict data and database posture.",
                    "failure_message": "",
                    "create_time": "2024-08-15T09:00:00Z",
                    "update_time": "2026-07-12T09:25:00Z"
                },
                {
                    "name": f"{org_name}/locations/global/postureDeployments/dep-aws-multicloud",
                    "deployment_id": "dep-aws-multicloud",
                    "target_resource": "aws:organizations/o-8a9d7f6b4e",
                    "posture_id": "multicloud-aws-posture",
                    "posture_revision_id": "v1.1",
                    "state": "ACTIVE",
                    "description": "Multi-cloud AWS connector deployment covering 14 AWS accounts.",
                    "failure_message": "",
                    "create_time": "2025-01-22T10:00:00Z",
                    "update_time": "2026-05-18T11:50:00Z"
                }
            ],
            "deployment_count": 4,
            "posture_templates": [
                {"template_id": "cis-gcp-foundations-v2.0", "name": "CIS GCP Foundations v2.0 Template", "description": "Pre-built Google Cloud posture aligning with CIS benchmark", "policy_sets_count": 5, "revision_id": "1"},
                {"template_id": "nist-sp-800-53-rev5", "name": "NIST SP 800-53 Rev 5 Template", "description": "Pre-built federal security and privacy controls", "policy_sets_count": 8, "revision_id": "1"},
                {"template_id": "aws-foundation-benchmark", "name": "AWS Security Foundations Template", "description": "Pre-built baseline for multi-cloud AWS posture assessment", "policy_sets_count": 4, "revision_id": "1"},
            ],
            "template_count": 3,
            "posture_feature_enabled": True
        },
        "dlp_sdp": {
            "discovery_configs": [
                {
                    "name": f"{org_name}/locations/global/discoveryConfigs/bq-analytics-profiler",
                    "config_id": "bq-analytics-profiler",
                    "display_name": "Continuous BigQuery Data Profiler",
                    "status": "RUNNING",
                    "targets": ["BigQuery (Tables & Datasets)"],
                    "inspect_template": f"{org_name}/locations/global/inspectTemplates/customer-pii-template",
                    "create_time": "2024-04-10T10:00:00Z",
                    "update_time": "2026-08-01T12:00:00Z"
                },
                {
                    "name": f"{org_name}/locations/global/discoveryConfigs/gcs-datalake-profiler",
                    "config_id": "gcs-datalake-profiler",
                    "display_name": "Enterprise GCS Data Lake Scanner",
                    "status": "RUNNING",
                    "targets": ["Cloud Storage (Buckets)", "Cloud SQL (Databases)"],
                    "inspect_template": f"{org_name}/locations/global/inspectTemplates/financial-credentials-template",
                    "create_time": "2024-05-18T14:00:00Z",
                    "update_time": "2026-08-05T09:30:00Z"
                }
            ],
            "discovery_config_count": 2,
            "inspect_templates": [
                {
                    "name": f"{org_name}/locations/global/inspectTemplates/customer-pii-template",
                    "template_id": "customer-pii-template",
                    "display_name": "Global Customer PII & Identification Template",
                    "description": "Detects SSNs, Passport Numbers, Driver Licenses, Phone Numbers, and Email Addresses.",
                    "min_likelihood": "LIKELY",
                    "info_types_count": 14,
                    "custom_info_types_count": 2,
                    "sample_info_types": ["US_SOCIAL_SECURITY_NUMBER", "PASSPORT", "EMAIL_ADDRESS", "PHONE_NUMBER", "DRIVERS_LICENSE_NUMBER"],
                    "create_time": "2024-04-01T08:00:00Z",
                    "update_time": "2026-06-15T11:00:00Z"
                },
                {
                    "name": f"{org_name}/locations/global/inspectTemplates/financial-credentials-template",
                    "template_id": "financial-credentials-template",
                    "display_name": "Payment Cards & Secrets / API Keys Detector",
                    "description": "Detects Credit Card PANs, IBANs, GCP Service Account Private Keys, JWT Tokens, and AWS Access Keys.",
                    "min_likelihood": "VERY_LIKELY",
                    "info_types_count": 18,
                    "custom_info_types_count": 4,
                    "sample_info_types": ["CREDIT_CARD_NUMBER", "IBAN_CODE", "GCP_CREDENTIALS", "AUTH_TOKEN", "ENCRYPTION_KEY"],
                    "create_time": "2024-04-05T09:30:00Z",
                    "update_time": "2026-07-20T15:00:00Z"
                },
                {
                    "name": f"{org_name}/locations/global/inspectTemplates/healthcare-phi-template",
                    "template_id": "healthcare-phi-template",
                    "display_name": "Healthcare PHI & Medical Records Template",
                    "description": "Detects US Medical Record Numbers (MRN), Healthcare Provider IDs, and prescription data.",
                    "min_likelihood": "POSSIBLE",
                    "info_types_count": 8,
                    "custom_info_types_count": 1,
                    "sample_info_types": ["US_HEALTHCARE_NPI", "US_MEDICARE_BENEFICIARY_ID", "MEDICAL_TERM"],
                    "create_time": "2024-09-12T14:00:00Z",
                    "update_time": "2026-05-10T10:00:00Z"
                }
            ],
            "inspect_template_count": 3,
            "deidentify_templates": [
                {
                    "name": f"{org_name}/locations/global/deidentifyTemplates/mask-pii-for-dev",
                    "template_id": "mask-pii-for-dev",
                    "display_name": "Mask PII for Non-Prod / Dev Environments",
                    "description": "Replaces SSN and Credit Card digits with asterisks (*), preserving last 4 digits.",
                    "create_time": "2024-05-01T10:00:00Z",
                    "update_time": "2026-04-12T14:00:00Z"
                },
                {
                    "name": f"{org_name}/locations/global/deidentifyTemplates/crypto-hash-user-id",
                    "template_id": "crypto-hash-user-id",
                    "display_name": "Pseudonymize Customer IDs via HMAC-SHA256",
                    "description": "Cryptographically hashes customer primary keys before loading into analytics datasets.",
                    "create_time": "2024-06-10T11:00:00Z",
                    "update_time": "2026-06-18T16:30:00Z"
                }
            ],
            "deidentify_template_count": 2,
            "job_triggers": [
                {
                    "name": f"{org_name}/locations/global/jobTriggers/nightly-analytics-dlp-scan",
                    "trigger_id": "nightly-analytics-dlp-scan",
                    "display_name": "Nightly Sensitive Data Profile Refresh (BigQuery)",
                    "description": "Scheduled inspection of newly loaded BigQuery partition tables.",
                    "status": "HEALTHY",
                    "last_run_time": "2026-08-27T02:00:00Z",
                    "inspect_job": {"target": "BigQuery Analytics Data Warehouse"}
                },
                {
                    "name": f"{org_name}/locations/global/jobTriggers/weekly-gcs-bucket-audit",
                    "trigger_id": "weekly-gcs-bucket-audit",
                    "display_name": "Weekly Cloud Storage Bucket Deep Scan",
                    "description": "Scans all objects in staging and raw ingestion GCS buckets.",
                    "status": "HEALTHY",
                    "last_run_time": "2026-08-24T04:00:00Z",
                    "inspect_job": {"target": "All GCS Buckets in Production"}
                }
            ],
            "job_trigger_count": 2,
            "sdp_active": True
        },
        "exports_mutes": {
            "pubsub_notification_configs": [
                {
                    "name": f"{org_name}/notificationConfigs/critical-threats-pubsub",
                    "config_id": "critical-threats-pubsub",
                    "pubsub_topic": "projects/secops-central-hub/topics/scc-critical-findings",
                    "topic_short": "scc-critical-findings",
                    "filter": 'state = "ACTIVE" AND severity = "CRITICAL"',
                    "description": "Streams critical active threats immediately to incident response pipeline.",
                    "service_account": f"service-org-{raw_id}@security-center-api.iam.gserviceaccount.com" if is_org else f"service-{raw_id}@gcp-sa-scc.iam.gserviceaccount.com"
                },
                {
                    "name": f"{org_name}/notificationConfigs/jira-ticket-bridge",
                    "config_id": "jira-ticket-bridge",
                    "pubsub_topic": "projects/secops-central-hub/topics/scc-jira-autoticketing",
                    "topic_short": "scc-jira-autoticketing",
                    "filter": 'state = "ACTIVE" AND (severity = "HIGH" OR severity = "CRITICAL") AND finding_class = "VULNERABILITY"',
                    "description": "Triggers automated Jira ticket creation for software vulnerabilities.",
                    "service_account": f"service-org-{raw_id}@security-center-api.iam.gserviceaccount.com" if is_org else f"service-{raw_id}@gcp-sa-scc.iam.gserviceaccount.com"
                },
                {
                    "name": f"{org_name}/notificationConfigs/chronicle-siem-feed",
                    "config_id": "chronicle-siem-feed",
                    "pubsub_topic": "projects/secops-central-hub/topics/scc-all-events-siem",
                    "topic_short": "scc-all-events-siem",
                    "filter": 'state = "ACTIVE"',
                    "description": "Complete real-time stream of all SCC findings forwarded to Google SecOps / Chronicle SIEM.",
                    "service_account": f"service-org-{raw_id}@security-center-api.iam.gserviceaccount.com" if is_org else f"service-{raw_id}@gcp-sa-scc.iam.gserviceaccount.com"
                }
            ],
            "pubsub_export_count": 3,
            "bigquery_exports": [
                {
                    "name": f"{org_name}/bigQueryExports/scc_findings_daily_lake",
                    "export_id": "scc_findings_daily_lake",
                    "dataset": "projects/secops-central-hub/datasets/scc_security_analytics",
                    "dataset_short": "scc_security_analytics",
                    "filter": 'state = "ACTIVE" OR state = "RESOLVED"',
                    "description": "Continuous streaming export of all finding states for audit & reporting.",
                    "principal": f"service-org-{raw_id}@security-center-api.iam.gserviceaccount.com" if is_org else f"service-{raw_id}@gcp-sa-scc.iam.gserviceaccount.com",
                    "create_time": "2024-02-10T10:00:00Z",
                    "update_time": "2026-01-15T12:00:00Z"
                },
                {
                    "name": f"{org_name}/bigQueryExports/scc_compliance_archive",
                    "export_id": "scc_compliance_archive",
                    "dataset": "projects/compliance-auditing-prod/datasets/scc_compliance_snapshots",
                    "dataset_short": "scc_compliance_snapshots",
                    "filter": 'finding_class = "MISCONFIGURATION"',
                    "description": "Dedicated dataset for historical compliance evidence and quarterly auditor reports.",
                    "principal": f"service-org-{raw_id}@security-center-api.iam.gserviceaccount.com" if is_org else f"service-{raw_id}@gcp-sa-scc.iam.gserviceaccount.com",
                    "create_time": "2024-05-20T08:00:00Z",
                    "update_time": "2026-03-10T14:30:00Z"
                }
            ],
            "bigquery_export_count": 2,
            "mute_rules": [
                {
                    "name": f"{org_name}/muteConfigs/mute-sandbox-test-vpc-ports",
                    "mute_id": "mute-sandbox-test-vpc-ports",
                    "display_name": "Mute Test VPC Open Ports in Sandbox Projects",
                    "description": "Suppresses OPEN_FIREWALL findings in sandbox/scratch projects with automated TTLs.",
                    "filter": 'resource.project_display_name : "sandbox-" AND category = "OPEN_FIREWALL"',
                    "most_recent_editor": "devops-lead@enterprise-corp.com",
                    "create_time": "2024-06-12T11:00:00Z",
                    "update_time": "2026-04-10T09:00:00Z"
                },
                {
                    "name": f"{org_name}/muteConfigs/mute-public-doc-gcs-bucket",
                    "mute_id": "mute-public-doc-gcs-bucket",
                    "display_name": "Approved Public CDN Documentation Buckets",
                    "description": "Exceptions for static asset CDN buckets intentionally configured with public read.",
                    "filter": 'resource.name = "//storage.googleapis.com/enterprise-corp-public-docs" AND category = "PUBLIC_BUCKET_ACL"',
                    "most_recent_editor": "ciso-office@enterprise-corp.com",
                    "create_time": "2024-07-01T15:30:00Z",
                    "update_time": "2026-01-20T10:15:00Z"
                },
                {
                    "name": f"{org_name}/muteConfigs/mute-internal-scanners-etd",
                    "mute_id": "mute-internal-scanners-etd",
                    "display_name": "Mute Authorized Vulnerability Scanner IP Addresses in ETD",
                    "description": "Prevents ETD alerts when authorized Qualys/Tenable internal scanners perform port probes.",
                    "filter": 'source.display_name = "Event Threat Detection" AND indicator.ip_addresses : "10.240.10.50"',
                    "most_recent_editor": "secops-architect@enterprise-corp.com",
                    "create_time": "2025-02-14T16:00:00Z",
                    "update_time": "2026-05-12T14:45:00Z"
                },
                {
                    "name": f"{org_name}/muteConfigs/mute-legacy-service-account-key-rotation",
                    "mute_id": "mute-legacy-service-account-key-rotation",
                    "display_name": "Legacy SA Key Rotation Waiver (Expiring Q4 2026)",
                    "description": "Approved risk waiver for legacy on-prem mainframe integration service account key rotation.",
                    "filter": 'category = "KEY_NOT_ROTATED" AND resource.name : "sa-mainframe-sync"',
                    "most_recent_editor": "ciso-risk-committee@enterprise-corp.com",
                    "create_time": "2025-08-01T10:00:00Z",
                    "update_time": "2026-08-01T08:00:00Z"
                },
                {
                    "name": f"{org_name}/muteConfigs/mute-gke-node-cos-deprecated-cve",
                    "mute_id": "mute-gke-node-cos-deprecated-cve",
                    "display_name": "Mute Non-Exploitable Kernel CVEs on Ephemeral Node Pools",
                    "description": "Mutes CVE-2023-XXXX on batch worker node pools scheduled for 24h recycling.",
                    "filter": 'category = "VULNERABILITY" AND vulnerability.cve.id = "CVE-2023-4911" AND resource.name : "batch-worker"',
                    "most_recent_editor": "k8s-platform-eng@enterprise-corp.com",
                    "create_time": "2025-11-10T14:00:00Z",
                    "update_time": "2026-03-25T11:30:00Z"
                }
            ],
            "mute_rule_count": 5
        },
        "connectors": {
            "multicloud_connectors": [
                {
                    "type": "AWS Cloud Connector",
                    "name": "AWS Production & Data Master Account Connector",
                    "target_id": "aws:organizations/o-8a9d7f6b4e (14 Accounts)",
                    "status": "ACTIVE",
                    "description": "AWS Multi-cloud posture assessment & inventory connection.",
                    "target_connector_mapping": "Cloud Account Connector (Role-based / Multi-cloud)"
                },
                {
                    "type": "Azure Cloud Connector",
                    "name": "Azure Enterprise Tenant Connector",
                    "target_id": "azure:tenants/7f8a9b0c-1d2e-3f4a-5b6c-7d8e9f0a1b2c (5 Subscriptions)",
                    "status": "ACTIVE",
                    "description": "Azure Multi-cloud posture assessment & subscription discovery.",
                    "target_connector_mapping": "Subscription Connector (App Registration / Multi-cloud)"
                }
            ],
            "multicloud_count": 2,
            "ticketing_connectors": [
                {
                    "type": "Jira Ticketing Connector",
                    "name": "Jira Cloud SecOps Project Bridge",
                    "topic": "projects/secops-central-hub/topics/scc-jira-autoticketing",
                    "status": "ACTIVE",
                    "description": "Automated ticket creation in Jira (Project: SEC) for high/critical security findings.",
                    "target_connector_mapping": "Jira Cloud / Server Integration & Automation Rules"
                },
                {
                    "type": "ServiceNow ITSM Connector",
                    "name": "ServiceNow Security Incident Response (SIR)",
                    "topic": "projects/secops-central-hub/topics/scc-critical-findings",
                    "status": "ACTIVE",
                    "description": "ServiceNow Incident & Vulnerability Response integration.",
                    "target_connector_mapping": "ServiceNow Incident & Security Operations Integration"
                },
                {
                    "type": "Chronicle / Google SecOps SIEM",
                    "name": "Chronicle SIEM Real-time Security Ingestion",
                    "topic": "projects/secops-central-hub/topics/scc-all-events-siem",
                    "status": "ACTIVE",
                    "description": "Real-time SIEM ingestion for security event correlation.",
                    "target_connector_mapping": "SIEM Streaming Forwarder & Webhook Integration"
                }
            ],
            "ticketing_count": 3,
            "vendor_sources": [
                {"name": f"{org_name}/sources/2001", "display_name": "Tenable.io Host Vulnerabilities", "description": "Agent-based vulnerability scans on VMs", "source_id": "2001", "type": "3rd-Party Security Vendor Source"},
                {"name": f"{org_name}/sources/2002", "display_name": "Palo Alto Prisma Cloud CSPM", "description": "Legacy multi-cloud configuration findings", "source_id": "2002", "type": "3rd-Party Security Vendor Source"},
                {"name": f"{org_name}/sources/2003", "display_name": "Custom SecOps Egress Sensor", "description": "Internal network anomaly detection engine", "source_id": "2003", "type": "3rd-Party Security Vendor Source"}
            ],
            "vendor_source_count": 3,
            "total_connectors": 8
        },
        "findings": {
            "total_active_findings": 1482,
            "severity_breakdown": {
                "CRITICAL": 34,
                "HIGH": 218,
                "MEDIUM": 690,
                "LOW": 540
            },
            "class_breakdown": {
                "MISCONFIGURATION": 894,
                "VULNERABILITY": 382,
                "THREAT": 142,
                "OBSERVATION": 64
            },
            "findings_by_source": [
                {"source_id": "1001", "source_name": "Security Health Analytics (SHA)", "category_type": "CSPM / Misconfiguration", "count": 862, "percentage": 58.2},
                {"source_id": "2001", "source_name": "Tenable.io Vulnerability Bridge", "category_type": "Vulnerability Management", "count": 284, "percentage": 19.2},
                {"source_id": "1002", "source_name": "Event Threat Detection (ETD)", "category_type": "CDR / Threat Detection", "count": 96, "percentage": 6.5},
                {"source_id": "1006", "source_name": "Rapid Vulnerability Detection (RVD)", "category_type": "Vulnerability Management", "count": 82, "percentage": 5.5},
                {"source_id": "1005", "source_name": "Sensitive Data Protection (SDP)", "category_type": "DSPM / Sensitive Data", "count": 58, "percentage": 3.9},
                {"source_id": "1003", "source_name": "Container Threat Detection (CTD)", "category_type": "CWPP / Container Runtime", "count": 42, "percentage": 2.8},
                {"source_id": "1007", "source_name": "Web Security Scanner (WSS)", "category_type": "DAST / Web Application", "count": 38, "percentage": 2.6},
                {"source_id": "1004", "source_name": "Virtual Machine Threat Detection (VMTD)", "category_type": "CWPP / VM Memory Inspection", "count": 20, "percentage": 1.3}
            ],
            "findings_by_category": [
                {"key": "OPEN_FIREWALL", "count": 142, "class": "MISCONFIGURATION", "severity": "HIGH"},
                {"key": "PUBLIC_BUCKET_ACL", "count": 118, "class": "MISCONFIGURATION", "severity": "CRITICAL"},
                {"key": "NON_PRIVILEGED_SERVICE_ACCOUNT_ADMIN", "count": 94, "class": "MISCONFIGURATION", "severity": "HIGH"},
                {"key": "PACKAGE_VULNERABILITY", "count": 88, "class": "VULNERABILITY", "severity": "HIGH"},
                {"key": "KMS_KEY_NOT_ROTATED", "count": 76, "class": "MISCONFIGURATION", "severity": "MEDIUM"},
                {"key": "SUSPICIOUS_SCRIPT_EXECUTION", "count": 64, "class": "THREAT", "severity": "CRITICAL"},
                {"key": "OUTDATED_OS_IMAGE", "count": 58, "class": "VULNERABILITY", "severity": "MEDIUM"},
                {"key": "EXPOSED_SERVICE_ACCOUNT_KEY", "count": 52, "class": "MISCONFIGURATION", "severity": "CRITICAL"},
                {"key": "UNRESTRICTED_SQL_INSTANCE", "count": 48, "class": "MISCONFIGURATION", "severity": "HIGH"},
                {"key": "SENSITIVE_DATA_PII_EXPOSED", "count": 46, "class": "OBSERVATION", "severity": "HIGH"},
                {"key": "CONTAINER_ROOT_EXECUTION", "count": 44, "class": "MISCONFIGURATION", "severity": "MEDIUM"},
                {"key": "ANOMALOUS_IAM_GRANT", "count": 38, "class": "THREAT", "severity": "CRITICAL"},
                {"key": "UNENCRYPTED_BIGQUERY_TABLE", "count": 36, "class": "MISCONFIGURATION", "severity": "MEDIUM"},
                {"key": "GKE_LEGACY_AUTH_ENABLED", "count": 34, "class": "MISCONFIGURATION", "severity": "HIGH"},
                {"key": "SUSPICIOUS_BINARY_EXECUTION", "count": 32, "class": "THREAT", "severity": "HIGH"},
                {"key": "DEFAULT_COMPUTE_SA_USED", "count": 30, "class": "MISCONFIGURATION", "severity": "HIGH"},
                {"key": "SQL_INJECTION_VULNERABILITY", "count": 28, "class": "VULNERABILITY", "severity": "CRITICAL"},
                {"key": "XSS_VULNERABILITY", "count": 26, "class": "VULNERABILITY", "severity": "MEDIUM"},
                {"key": "PUBLIC_IP_ON_GKE_NODE", "count": 24, "class": "MISCONFIGURATION", "severity": "MEDIUM"},
                {"key": "CRYPTO_MINING_BEHAVIOR", "count": 18, "class": "THREAT", "severity": "CRITICAL"}
            ],
            "top_categories": [
                {"key": "OPEN_FIREWALL", "count": 142},
                {"key": "PUBLIC_BUCKET_ACL", "count": 118},
                {"key": "NON_PRIVILEGED_SERVICE_ACCOUNT_ADMIN", "count": 94},
                {"key": "PACKAGE_VULNERABILITY", "count": 88},
                {"key": "KMS_KEY_NOT_ROTATED", "count": 76},
                {"key": "SUSPICIOUS_SCRIPT_EXECUTION", "count": 64},
                {"key": "OUTDATED_OS_IMAGE", "count": 58},
                {"key": "EXPOSED_SERVICE_ACCOUNT_KEY", "count": 52},
                {"key": "UNRESTRICTED_SQL_INSTANCE", "count": 48},
                {"key": "SENSITIVE_DATA_PII_EXPOSED", "count": 46}
            ]
        },
        "compliance": {
            "total_frameworks_tracked": 6,
            "enabled_frameworks_count": 6,
            "compliance_frameworks": [
                {
                    "framework_id": "cis-gcp",
                    "name": "CIS Google Cloud Computing Foundations",
                    "category": "Regulatory & Best Practices",
                    "description": "Center for Internet Security prescriptive guidance for Google Cloud Platform.",
                    "enabled": True,
                    "status": "ACTIVE / MONITORED",
                    "evaluated_controls_count": 92,
                    "failing_controls_count": 15,
                    "passing_percentage": 83.7,
                    "standard_framework_name": "CIS Google Cloud Platform Foundation Benchmark v2.0",
                },
                {
                    "framework_id": "nist-800-53",
                    "name": "NIST SP 800-53 Rev 5",
                    "category": "Federal / Government",
                    "description": "National Institute of Standards and Technology security & privacy catalog.",
                    "enabled": True,
                    "status": "ACTIVE / MONITORED",
                    "evaluated_controls_count": 134,
                    "failing_controls_count": 28,
                    "passing_percentage": 79.1,
                    "standard_framework_name": "NIST 800-53 Rev. 5",
                },
                {
                    "framework_id": "pci-dss",
                    "name": "PCI-DSS v4.0",
                    "category": "Payment Card Industry",
                    "description": "Global standard for cardholder data environments and financial workloads.",
                    "enabled": True,
                    "status": "ACTIVE / MONITORED",
                    "evaluated_controls_count": 78,
                    "failing_controls_count": 7,
                    "passing_percentage": 91.0,
                    "standard_framework_name": "PCI DSS v4.0",
                },
                {
                    "framework_id": "iso-27001",
                    "name": "ISO/IEC 27001:2022",
                    "category": "International Standard",
                    "description": "Information security management system (ISMS) controls.",
                    "enabled": True,
                    "status": "ACTIVE / MONITORED",
                    "evaluated_controls_count": 88,
                    "failing_controls_count": 11,
                    "passing_percentage": 87.5,
                    "standard_framework_name": "ISO/IEC 27001:2022",
                },
                {
                    "framework_id": "soc-2",
                    "name": "SOC 2 Type II",
                    "category": "Service Organization Controls",
                    "description": "AICPA Trust Services Criteria (Security, Confidentiality, Availability).",
                    "enabled": True,
                    "status": "ACTIVE / MONITORED",
                    "evaluated_controls_count": 72,
                    "failing_controls_count": 10,
                    "passing_percentage": 86.1,
                    "standard_framework_name": "SOC 2 Type II",
                },
                {
                    "framework_id": "hipaa",
                    "name": "HIPAA Security Rule",
                    "category": "Healthcare / Privacy",
                    "description": "Standards to safeguard electronic Protected Health Information (ePHI).",
                    "enabled": True,
                    "status": "ACTIVE / MONITORED",
                    "evaluated_controls_count": 64,
                    "failing_controls_count": 5,
                    "passing_percentage": 92.2,
                    "standard_framework_name": "HIPAA Security",
                }
            ]
        },
        "assets": {
            "total_assets": 3420,
            "asset_types_count": 28,
            "top_asset_types": [
                {"resource_type": "compute.googleapis.com/Instance", "short_type": "Compute Instance (VM)", "service": "compute", "count": 520},
                {"resource_type": "storage.googleapis.com/Bucket", "short_type": "Cloud Storage Bucket", "service": "storage", "count": 320},
                {"resource_type": "iam.googleapis.com/ServiceAccount", "short_type": "IAM Service Account", "service": "iam", "count": 240},
                {"resource_type": "compute.googleapis.com/Firewall", "short_type": "VPC Firewall Rule", "service": "compute", "count": 180},
                {"resource_type": "compute.googleapis.com/Disk", "short_type": "Persistent Disk Volume", "service": "compute", "count": 680},
                {"resource_type": "bigquery.googleapis.com/Dataset", "short_type": "BigQuery Dataset", "service": "bigquery", "count": 115},
                {"resource_type": "bigquery.googleapis.com/Table", "short_type": "BigQuery Table", "service": "bigquery", "count": 480},
                {"resource_type": "container.googleapis.com/Cluster", "short_type": "GKE Kubernetes Cluster", "service": "container", "count": 84},
                {"resource_type": "container.googleapis.com/NodePool", "short_type": "GKE Node Pool", "service": "container", "count": 164},
                {"resource_type": "sqladmin.googleapis.com/Instance", "short_type": "Cloud SQL Database Instance", "service": "sqladmin", "count": 72},
                {"resource_type": "cloudkms.googleapis.com/CryptoKey", "short_type": "Cloud KMS CryptoKey", "service": "cloudkms", "count": 96},
                {"resource_type": "compute.googleapis.com/ForwardingRule", "short_type": "Cloud Load Balancer", "service": "compute", "count": 45},
                {"resource_type": "cloudfunctions.googleapis.com/CloudFunction", "short_type": "Cloud Function", "service": "cloudfunctions", "count": 140},
                {"resource_type": "pubsub.googleapis.com/Topic", "short_type": "Pub/Sub Topic", "service": "pubsub", "count": 150},
                {"resource_type": "secretmanager.googleapis.com/Secret", "short_type": "Secret Manager Secret", "service": "secretmanager", "count": 134}
            ],
            "domain_categories": {
                "Compute & Workloads (VMs, Containers, Functions)": 1588,
                "Storage & Data Lakes (GCS, BigQuery, Filestore)": 915,
                "Databases (Cloud SQL, Spanner, Firestore, Bigtable)": 124,
                "Identity & Access Management (Roles, Service Accounts, Keys)": 380,
                "Networking & Connectivity (VPC, Subnets, Firewalls, Load Balancers)": 285,
                "Security & Cryptography (KMS, Secrets, Certificates)": 230,
                "Other Cloud Services": 198
            }
        },
        "hierarchy": {
            "organization": {
                "name": org_name,
                "display_name": "Enterprise Corp Global",
                "directory_customer_id": "C01ab2c3d",
                "state": "ACTIVE",
                "create_time": "2021-01-15T08:00:00Z"
            },
            "folders": [
                {"name": "folders/948201948270", "folder_id": "948201948270", "display_name": "Core-Infrastructure-Shared", "state": "ACTIVE", "parent": org_name},
                {"name": "folders/948201948271", "folder_id": "948201948271", "display_name": "Production-Workloads-Ecosystem", "state": "ACTIVE", "parent": org_name},
                {"name": "folders/948201948272", "folder_id": "948201948272", "display_name": "Data-Analytics-AI-Platform", "state": "ACTIVE", "parent": org_name},
                {"name": "folders/948201948273", "folder_id": "948201948273", "display_name": "Non-Production-Dev-Sandbox", "state": "ACTIVE", "parent": org_name}
            ],
            "folder_count": 4,
            "project_count": 22,
            "active_project_count": 22,
            "coverage_scope": "Organization-Wide (100% Inherited)",
            "coverage_percentage": 100.0,
            "projects_summary": [
                {"project_id": "core-hub-network-prod", "display_name": "Core Hub & Transit VPC", "state": "ACTIVE", "parent": "folders/948201948270"},
                {"project_id": "secops-central-hub", "display_name": "SecOps Central Security Hub", "state": "ACTIVE", "parent": "folders/948201948270"},
                {"project_id": "iam-identity-governance", "display_name": "IAM & Directory Sync", "state": "ACTIVE", "parent": "folders/948201948270"},
                {"project_id": "ecommerce-frontend-prod", "display_name": "E-Commerce Web & APIs", "state": "ACTIVE", "parent": "folders/948201948271"},
                {"project_id": "payments-backend-pci-prod", "display_name": "PCI Payment Processing", "state": "ACTIVE", "parent": "folders/948201948271"},
                {"project_id": "orders-fulfillment-prod", "display_name": "Orders & Inventory Service", "state": "ACTIVE", "parent": "folders/948201948271"},
                {"project_id": "customer-data-lake-prod", "display_name": "Customer BigQuery Lake", "state": "ACTIVE", "parent": "folders/948201948272"},
                {"project_id": "ml-training-vertex-ai", "display_name": "Vertex AI ML Training", "state": "ACTIVE", "parent": "folders/948201948272"},
                {"project_id": "dev-engineering-sandbox-01", "display_name": "Dev Engineering Sandbox", "state": "ACTIVE", "parent": "folders/948201948273"},
                {"project_id": "qa-integration-testing", "display_name": "QA Automation Test Bed", "state": "ACTIVE", "parent": "folders/948201948273"}
            ]
        }
    }
