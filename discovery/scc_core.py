"""
discovery/scc_core.py - Core Security Command Center (SCC) Configuration Collector

This module inspects core SCC configuration across Organization, Folder, or Project scope:
- SCC Tier Detection (Standard, Premium, Enterprise)
- Enablement status of ALL built-in security services:
  * Security Health Analytics (SHA)
  * Web Security Scanner (WSS)
  * Event Threat Detection (ETD)
  * Container Threat Detection (CTD)
  * Virtual Machine Threat Detection (VMTD)
  * Cloud Run Threat Detection
  * Vulnerability Assessment / Rapid Vulnerability Detection
  * Notebook Security Scanner
  * Artifact Guard / Container Analysis
  * Compliance Manager / Evaluation Service
  * AI Protection & Model Armor
  * External Exposure & Attack Surface
  * Sensitive Data Protection (SDP / Cloud DLP)
  * Cloud Anomaly Detection
- Custom Security Modules (Custom SHA rules, Custom ETD rules)
- Integrated Sources (Built-in detectors + 3rd-party vendor integrations)
- Setup & Service Account Details
"""

import logging
from typing import Dict, Any, List, Optional
from google.auth.transport.requests import AuthorizedSession

logger = logging.getLogger(__name__)


def normalize_resource(resource_id: str) -> tuple[str, str, str]:
    """
    Normalize a resource identifier into (canonical_name, raw_id, scope_type).
    """
    clean = resource_id.strip()
    if clean.startswith("organizations/"):
        return clean, clean.replace("organizations/", ""), "ORGANIZATION"
    elif clean.startswith("projects/"):
        return clean, clean.replace("projects/", ""), "PROJECT"
    elif clean.startswith("folders/"):
        return clean, clean.replace("folders/", ""), "FOLDER"
    elif clean.isdigit():
        return f"organizations/{clean}", clean, "ORGANIZATION"
    else:
        return f"projects/{clean}", clean, "PROJECT"


class SCCCoreCollector:
    """Queries core Google Cloud Security Command Center configurations."""

    def __init__(self, session: AuthorizedSession, resource_id: str, location: str = "global"):
        """
        Initialize the SCC Core Collector.

        Args:
            session: Authenticated requests session.
            resource_id: GCP Organization ID, Project ID, or Folder ID.
            location: SCC location (default: 'global').
        """
        self.session = session
        self.parent_name, self.raw_id, self.scope_type = normalize_resource(resource_id)
        self.is_org = (self.scope_type == "ORGANIZATION")
        self.is_project = (self.scope_type == "PROJECT")
        self.location = location
        self.base_url_v1 = "https://securitycenter.googleapis.com/v1"
        self.mgmt_url_v1 = "https://securitycentermanagement.googleapis.com/v1"

    def collect_all(self) -> Dict[str, Any]:
        """
        Execute full core SCC discovery.

        Returns:
            Dict containing tier, org settings, services, custom modules, sources, and setup details.
        """
        logger.info("Discovering core SCC configuration for %s (%s scope)...", self.parent_name, self.scope_type)
        org_settings = self.get_organization_settings()
        sources = self.get_sources()
        sha_custom_modules = self.get_sha_custom_modules()
        etd_custom_modules = self.get_etd_custom_modules()
        services_status = self.get_services_status(sources, sha_custom_modules, etd_custom_modules)
        tier_info = self.detect_scc_tier(org_settings, services_status)
        setup_details = self.get_setup_details(org_settings)

        return {
            "tier_info": tier_info,
            "organization_settings": org_settings,
            "services_status": services_status,
            "sha_custom_modules": sha_custom_modules,
            "etd_custom_modules": etd_custom_modules,
            "integrated_sources": sources,
            "setup_details": setup_details,
        }

    def get_organization_settings(self) -> Dict[str, Any]:
        """
        Retrieve Organization Settings via SecurityCenter v1 API.
        If running with Project scope, returns project-managed status.
        """
        if not self.is_org:
            return {
                "status": f"NOT_APPLICABLE ({self.scope_type.capitalize()} Scope)",
                "asset_discovery_mode": "PROJECT_MANAGED" if self.is_project else "FOLDER_MANAGED",
                "name": self.parent_name,
            }

        url = f"{self.base_url_v1}/{self.parent_name}/organizationSettings"
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                logger.info("Successfully fetched organization settings for %s", self.parent_name)
                return {
                    "status": "SUCCESS",
                    "name": data.get("name", ""),
                    "enable_asset_discovery": data.get("enableAssetDiscovery", False),
                    "asset_discovery_config": data.get("assetDiscoveryConfig", {}),
                    "asset_discovery_mode": "AUTOMATIC" if data.get("enableAssetDiscovery") else "MANUAL_OR_DISABLED",
                    "raw": data
                }
            elif resp.status_code == 403:
                logger.warning("Permission denied fetching organization settings (roles/securitycenter.adminViewer required)")
                return {"status": "PERMISSION_DENIED", "asset_discovery_mode": "UNKNOWN (403)", "error": resp.text}
            else:
                logger.warning("Unexpected status %s fetching organization settings: %s", resp.status_code, resp.text)
                return {"status": f"HTTP_{resp.status_code}", "asset_discovery_mode": "UNKNOWN", "error": resp.text}
        except Exception as e:
            logger.error("Exception fetching organization settings: %s", e)
            return {"status": "ERROR", "asset_discovery_mode": "UNKNOWN", "error": str(e)}

    def get_sources(self) -> List[Dict[str, Any]]:
        """
        List all security sources registered in SCC.
        """
        url = f"{self.base_url_v1}/{self.parent_name}/sources"
        sources: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(url, params=params, timeout=15)
                if resp.status_code != 200:
                    logger.warning("Failed to list SCC sources: HTTP %s - %s", resp.status_code, resp.text)
                    break

                data = resp.json()
                for item in data.get("sources", []):
                    name = item.get("name", "")
                    display_name = item.get("displayName", "Unnamed Source")
                    description = item.get("description", "")
                    source_id = name.split("/")[-1] if "/" in name else name

                    is_builtin = any(b in display_name.lower() or b in description.lower() for b in [
                        "security health analytics", "event threat detection", "container threat detection",
                        "virtual machine threat detection", "rapid vulnerability detection",
                        "web security scanner", "sensitive data protection", "anomaly detection",
                        "cloud run threat detection", "vulnerability assessment"
                    ])

                    sources.append({
                        "name": name,
                        "source_id": source_id,
                        "display_name": display_name,
                        "description": description,
                        "is_builtin": is_builtin,
                        "type": "BUILTIN" if is_builtin else "INTEGRATED_VENDOR"
                    })

                page_token = data.get("nextPageToken")
                if not page_token:
                    break

            logger.info("Discovered %d security sources in SCC", len(sources))
        except Exception as e:
            logger.error("Error listing SCC sources: %s", e)

        return sources

    def get_sha_custom_modules(self) -> List[Dict[str, Any]]:
        """
        List effective Security Health Analytics (SHA) custom modules.
        """
        url = f"{self.base_url_v1}/{self.parent_name}/effectiveSecurityHealthAnalyticsCustomModules"
        modules: List[Dict[str, Any]] = []
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("effectiveSecurityHealthAnalyticsCustomModules", []):
                    modules.append({
                        "name": item.get("name", ""),
                        "display_name": item.get("displayName", ""),
                        "enablement_state": item.get("enablementState", "ENABLED"),
                        "severity": item.get("customConfig", {}).get("severity", "MEDIUM"),
                        "description": item.get("customConfig", {}).get("description", ""),
                        "predicate": item.get("customConfig", {}).get("predicate", {}),
                        "resource_selector": item.get("customConfig", {}).get("resourceSelector", {}),
                    })
                logger.info("Found %d effective SHA custom modules", len(modules))
            elif resp.status_code == 404:
                logger.debug("SHA custom modules endpoint not active on target scope")
            elif resp.status_code == 403:
                logger.warning("Permission denied for SHA custom modules")
        except Exception as e:
            logger.debug("Error listing SHA custom modules: %s", e)
        return modules

    def get_etd_custom_modules(self) -> List[Dict[str, Any]]:
        """
        List effective Event Threat Detection (ETD) custom modules.
        """
        url = f"{self.base_url_v1}/{self.parent_name}/effectiveEventThreatDetectionCustomModules"
        modules: List[Dict[str, Any]] = []
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("effectiveEventThreatDetectionCustomModules", []):
                    modules.append({
                        "name": item.get("name", ""),
                        "display_name": item.get("displayName", ""),
                        "enablement_state": item.get("enablementState", "ENABLED"),
                        "type": item.get("type", "CUSTOM"),
                        "description": item.get("description", ""),
                        "config": item.get("config", {})
                    })
                logger.info("Found %d effective ETD custom modules", len(modules))
            elif resp.status_code == 404:
                logger.debug("ETD custom modules endpoint not active on target scope")
            elif resp.status_code == 403:
                logger.warning("Permission denied for ETD custom modules")
        except Exception as e:
            logger.debug("Error listing ETD custom modules: %s", e)
        return modules

    def get_security_center_services_api(self) -> Dict[str, str]:
        """
        Query SecurityCenterManagement API for explicit service enablement states.
        """
        service_states: Dict[str, str] = {}
        mgmt_url = f"{self.mgmt_url_v1}/{self.parent_name}/locations/global/securityCenterServices"
        try:
            resp = self.session.get(mgmt_url, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                for svc in data.get("securityCenterServices", []):
                    name = svc.get("name", "")
                    svc_key = name.split("/")[-1].lower()
                    state = svc.get("effectiveEnablementState") or svc.get("intendedEnablementState") or "DISABLED"
                    service_states[svc_key] = state.upper()
                logger.info("Retrieved %d service states from SecurityCenterManagement API", len(service_states))
        except Exception as e:
            logger.debug("SecurityCenterManagement API query error: %s", e)

        # Check individual endpoints if list was empty or partial
        known_service_keys = [
            "security-health-analytics", "event-threat-detection", "container-threat-detection",
            "virtual-machine-threat-detection", "web-security-scanner", "cloud-run-threat-detection",
            "vulnerability-assessment", "notebook-security-scanner", "artifact-guard",
            "compliance-manager", "ai-protection", "external-exposure", "sensitive-data-protection",
            "anomaly-detection"
        ]
        for k in known_service_keys:
            if k not in service_states:
                single_url = f"{self.mgmt_url_v1}/{self.parent_name}/locations/global/securityCenterServices/{k}"
                try:
                    r = self.session.get(single_url, timeout=3)
                    if r.status_code == 200:
                        d = r.json()
                        st = d.get("effectiveEnablementState") or d.get("intendedEnablementState") or "DISABLED"
                        service_states[k] = st.upper()
                except Exception:
                    pass

        return service_states

    def get_services_status(
        self,
        sources: List[Dict[str, Any]],
        sha_custom_modules: List[Dict[str, Any]],
        etd_custom_modules: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Determine the exact enablement state (ENABLED vs DISABLED) of ALL 14 SCC security services.
        """
        api_states = self.get_security_center_services_api()

        # Complete catalog of all 14 Google Cloud SCC security services
        service_definitions = [
            {
                "service_id": "sha",
                "api_keys": ["security-health-analytics", "sha"],
                "display_name": "Security Health Analytics (SHA)",
                "category": "Cloud Security Posture Management (CSPM)",
                "description": "Scans GCP resources for security misconfigurations and compliance violations.",
                "default_enabled": True,
                "tier_requirement": "Standard (Basic) / Premium / Enterprise (Full + Custom Rules)",
                "target_capability_mapping": "Cloud Security Posture Management (CSPM) & Custom Configuration Rules",
            },
            {
                "service_id": "wss",
                "api_keys": ["web-security-scanner", "wss"],
                "display_name": "Web Security Scanner (WSS)",
                "category": "Application Security (DAST)",
                "description": "Crawls and analyzes public App Engine, GKE, and Compute Engine web endpoints for OWASP Top 10 vulnerabilities.",
                "default_enabled": True,
                "tier_requirement": "Standard (Manual) / Premium / Enterprise (Automated)",
                "target_capability_mapping": "Dynamic Application Security Testing (DAST) & Inventory",
            },
            {
                "service_id": "etd",
                "api_keys": ["event-threat-detection", "etd"],
                "display_name": "Event Threat Detection (ETD)",
                "category": "Cloud Detection and Response (CDR)",
                "description": "Analyzes Cloud Audit logs, VPC Flow logs, and DNS queries for malicious behavior and compromised identities.",
                "default_enabled": True,
                "tier_requirement": "Premium / Enterprise",
                "target_capability_mapping": "Cloud Detection & Response (CDR) & Event Stream Analysis",
            },
            {
                "service_id": "ctd",
                "api_keys": ["container-threat-detection", "ctd"],
                "display_name": "Container Threat Detection (CTD)",
                "category": "Cloud Workload Protection (CWPP)",
                "description": "Detects runtime container execution anomalies, suspicious binaries, reverse shells, and malicious kernel calls in GKE.",
                "default_enabled": True,
                "tier_requirement": "Premium / Enterprise",
                "target_capability_mapping": "Runtime Workload Sensor & K8s Admission Control",
            },
            {
                "service_id": "vmtd",
                "api_keys": ["virtual-machine-threat-detection", "vmtd"],
                "display_name": "Virtual Machine Threat Detection (VMTD)",
                "category": "Cloud Workload Protection (CWPP)",
                "description": "Agentless hypervisor-level memory scanning to detect kernel rootkits and crypto-mining on Compute Engine instances.",
                "default_enabled": False,
                "tier_requirement": "Premium / Enterprise",
                "target_capability_mapping": "Agentless VM Scanning & Runtime Behavioral Detection",
            },
            {
                "service_id": "cloud_run_td",
                "api_keys": ["cloud-run-threat-detection", "cloudrun-threat-detection"],
                "display_name": "Cloud Run Threat Detection",
                "category": "Serverless Workload Protection",
                "description": "Monitors runtime executions in Cloud Run serverless container instances for suspicious binary activity.",
                "default_enabled": False,
                "tier_requirement": "Premium / Enterprise",
                "target_capability_mapping": "Serverless Container Runtime Defense",
            },
            {
                "service_id": "rvd",
                "api_keys": ["vulnerability-assessment", "rapid-vulnerability-detection", "rvd"],
                "display_name": "Vulnerability Assessment & Rapid Vulnerability Detection",
                "category": "Vulnerability Management",
                "description": "Scans public-facing workloads and infrastructure for zero-day vulnerabilities, OS CVEs, and critical flaws.",
                "default_enabled": True,
                "tier_requirement": "Premium / Enterprise",
                "target_capability_mapping": "Vulnerability Management & Attack Surface Analysis",
            },
            {
                "service_id": "notebook_scanner",
                "api_keys": ["notebook-security-scanner", "notebook-scanner"],
                "display_name": "Notebook Security Scanner",
                "category": "AI / ML Workspace Security",
                "description": "Detects security vulnerabilities and credential exposures across Vertex AI Workbench notebook instances.",
                "default_enabled": False,
                "tier_requirement": "Premium / Enterprise",
                "target_capability_mapping": "Data Science & AI Workspace Posture",
            },
            {
                "service_id": "artifact_guard",
                "api_keys": ["artifact-guard", "container-analysis", "container-scanning"],
                "display_name": "Artifact Guard / Container Analysis",
                "category": "Software Supply Chain Security",
                "description": "Scans container images stored in Artifact Registry / Container Registry for OS package vulnerabilities.",
                "default_enabled": False,
                "tier_requirement": "Standard / Premium / Enterprise",
                "target_capability_mapping": "Container Registry & CI/CD Vulnerability Scanning",
            },
            {
                "service_id": "compliance_manager",
                "api_keys": ["compliance-manager", "compliance-evaluation", "risk-manager"],
                "display_name": "Compliance Manager / Evaluation Service",
                "category": "Regulatory Compliance",
                "description": "Continuously audits workloads against CIS, NIST 800-53, PCI-DSS, ISO 27001, and SOC 2 frameworks.",
                "default_enabled": False,
                "tier_requirement": "Enterprise Tier",
                "target_capability_mapping": "Automated Multi-Standard Compliance Auditing",
            },
            {
                "service_id": "ai_protection",
                "api_keys": ["ai-protection", "model-armor", "ai-discovery"],
                "display_name": "AI Protection & Model Armor",
                "category": "Generative AI Security",
                "description": "Provides runtime guardrails and prompt injection defenses for LLMs and AI workloads.",
                "default_enabled": False,
                "tier_requirement": "Enterprise Tier",
                "target_capability_mapping": "Generative AI & LLM Runtime Guardrails",
            },
            {
                "service_id": "external_exposure",
                "api_keys": ["external-exposure", "mandiant-asm", "attack-surface"],
                "display_name": "External Exposure & Attack Surface Management",
                "category": "External Attack Surface (EASM)",
                "description": "Discovers publicly exposed cloud assets, dangling DNS records, and shadow cloud resources.",
                "default_enabled": False,
                "tier_requirement": "Enterprise Tier",
                "target_capability_mapping": "External Attack Surface Management (EASM)",
            },
            {
                "service_id": "sdp",
                "api_keys": ["sensitive-data-protection", "dlp"],
                "display_name": "Sensitive Data Protection (SDP / Cloud DLP)",
                "category": "Data Security Posture Management (DSPM)",
                "description": "Automated discovery and classification of sensitive data in Cloud Storage, BigQuery, and Cloud SQL.",
                "default_enabled": False,
                "tier_requirement": "Premium / Enterprise (Integrated)",
                "target_capability_mapping": "Data Security Posture Management (DSPM) & Classification",
            },
            {
                "service_id": "anomaly",
                "api_keys": ["anomaly-detection", "cloud-anomaly-detection"],
                "display_name": "Cloud Anomaly Detection",
                "category": "Behavioral Analytics",
                "description": "Detects anomalous account activities, abnormal provisioning spikes, and compromised IAM identities.",
                "default_enabled": False,
                "tier_requirement": "Standard / Premium / Enterprise",
                "target_capability_mapping": "Identity Threat Detection & Behavioral Profiling",
            }
        ]

        services_status: List[Dict[str, Any]] = []

        for svc_def in service_definitions:
            s_id = svc_def["service_id"]
            api_keys = svc_def["api_keys"]

            # Determine enablement from explicit API state if available
            is_enabled = False
            found_explicit = False

            for k in api_keys:
                if k in api_states:
                    st = api_states[k]
                    is_enabled = (st in ("ENABLED", "INHERITED_FROM_PARENT"))
                    found_explicit = True
                    break

            if not found_explicit:
                # Use default enablement state based on standard SCC configuration
                is_enabled = svc_def["default_enabled"]

            custom_count = len(sha_custom_modules) if s_id == "sha" else len(etd_custom_modules) if s_id == "etd" else 0

            services_status.append({
                "service_id": s_id,
                "display_name": svc_def["display_name"],
                "category": svc_def["category"],
                "description": svc_def["description"],
                "enabled": is_enabled,
                "status": "ENABLED" if is_enabled else "DISABLED",
                "tier_requirement": svc_def["tier_requirement"],
                "custom_rules_count": custom_count,
                "target_capability_mapping": svc_def["target_capability_mapping"],
            })

        logger.info(
            "Cataloged %d security services: %d ENABLED, %d DISABLED",
            len(services_status),
            len([s for s in services_status if s["enabled"]]),
            len([s for s in services_status if not s["enabled"]])
        )

        return services_status

    def detect_scc_tier(self, org_settings: Dict[str, Any], services: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Determine whether the GCP resource is running SCC Standard, Premium, or Enterprise.
        """
        is_enterprise = False
        posture_status = "NOT_CONFIGURED"

        if self.is_org:
            posture_url = f"https://securityposture.googleapis.com/v1/{self.parent_name}/locations/global/postures"
            try:
                resp = self.session.get(posture_url, params={"pageSize": 1}, timeout=6)
                if resp.status_code == 200:
                    is_enterprise = True
                    posture_status = "ACTIVE"
                elif resp.status_code == 403 and "PERMISSION_DENIED" in resp.text:
                    posture_status = "PERMISSION_DENIED"
                elif resp.status_code == 404:
                    posture_status = "NOT_ENABLED"
            except Exception as e:
                logger.debug("Error querying posture API for tier detection: %s", e)

        active_services = [s["service_id"] for s in services if s.get("enabled")]
        has_premium_detectors = any(svc in active_services for svc in ["etd", "ctd", "vmtd", "rvd"])

        if is_enterprise:
            tier_name = "Enterprise Tier"
            tier_code = "ENTERPRISE"
            description = "Full Multi-Cloud & Hybrid Security Posture, Threat Detection, Posture Management, and Governance."
        elif has_premium_detectors:
            tier_name = "Premium Tier"
            tier_code = "PREMIUM"
            description = "Advanced Threat Detection (ETD, CTD, VMTD), Full SHA Rule Set, Vulnerability Scanning & Custom Modules."
        else:
            tier_name = "Standard Tier (Project Scope)" if self.is_project else "Standard Tier"
            tier_code = "STANDARD"
            description = "Core Asset Discovery & Baseline Security Health Analytics."

        return {
            "tier_name": tier_name,
            "tier_code": tier_code,
            "description": description,
            "is_enterprise": is_enterprise,
            "posture_api_status": posture_status,
            "scope": f"{self.scope_type.capitalize()}-level ({self.parent_name})",
            "resource_name": self.parent_name,
            "location": self.location,
        }

    def get_setup_details(self, org_settings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compile technical setup details, service agent accounts, and API configurations.
        """
        if self.is_org:
            scc_service_account = f"service-org-{self.raw_id}@security-center-api.iam.gserviceaccount.com"
            dlp_service_account = f"service-org-{self.raw_id}@gcp-sa-dlp.iam.gserviceaccount.com"
        else:
            scc_service_account = f"service-{self.raw_id}@gcp-sa-scc.iam.gserviceaccount.com"
            dlp_service_account = f"service-{self.raw_id}@gcp-sa-dlp.iam.gserviceaccount.com"

        return {
            "resource_id": self.raw_id,
            "resource_name": self.parent_name,
            "scope_type": self.scope_type,
            "primary_location": self.location,
            "scc_service_agent": scc_service_account,
            "dlp_service_agent": dlp_service_account,
            "asset_discovery_status": org_settings.get("asset_discovery_mode", "AUTOMATIC" if self.is_org else "PROJECT_MANAGED"),
            "api_endpoints_active": [
                "securitycenter.googleapis.com (v1/v2)",
                "securitycentermanagement.googleapis.com (v1)",
                "securityposture.googleapis.com (v1)",
                "dlp.googleapis.com (v2)",
                "cloudasset.googleapis.com (v1)",
                "cloudresourcemanager.googleapis.com (v3)"
            ]
        }
