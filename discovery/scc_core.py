"""
discovery/scc_core.py - Core Security Command Center (SCC) Configuration Collector

This module inspects core SCC configuration across Organization, Folder, or Project scope:
- SCC Tier Detection (Standard, Premium, Enterprise)
- Organization / Scope Settings (Asset discovery mode, configuration state)
- Built-in Security Services status (SHA, ETD, CTD, VMTD, RVD, WSS, SDP, Anomaly Detection)
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
        self.base_url_v2 = "https://securitycenter.googleapis.com/v2"

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
                        "web security scanner", "sensitive data protection", "anomaly detection"
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

    def get_services_status(
        self,
        sources: List[Dict[str, Any]],
        sha_custom_modules: List[Dict[str, Any]],
        etd_custom_modules: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Determine the enablement state and capability details of all SCC built-in security services.
        """
        source_names_lower = [s.get("display_name", "").lower() for s in sources]

        services = [
            {
                "service_id": "sha",
                "display_name": "Security Health Analytics (SHA)",
                "category": "Cloud Security Posture Management (CSPM)",
                "description": "Scans GCP resources for security misconfigurations and compliance violations.",
                "enabled": any("health analytics" in s for s in source_names_lower) or len(sha_custom_modules) > 0 or self.is_project,
                "tier_requirement": "Standard (Basic) / Premium / Enterprise (Full + Custom Rules)",
                "custom_rules_count": len(sha_custom_modules),
                "target_capability_mapping": "Cloud Security Posture Management (CSPM) & Custom Configuration Rules",
            },
            {
                "service_id": "etd",
                "display_name": "Event Threat Detection (ETD)",
                "category": "Cloud Detection and Response (CDR)",
                "description": "Analyzes Cloud Audit logs, VPC Flow logs, and DNS queries for malicious behavior and compromised identities.",
                "enabled": any("event threat" in s for s in source_names_lower) or len(etd_custom_modules) > 0,
                "tier_requirement": "Premium / Enterprise",
                "custom_rules_count": len(etd_custom_modules),
                "target_capability_mapping": "Cloud Detection & Response (CDR) & Event Stream Analysis",
            },
            {
                "service_id": "ctd",
                "display_name": "Container Threat Detection (CTD)",
                "category": "Cloud Workload Protection (CWPP)",
                "description": "Detects runtime container execution anomalies, suspicious binaries, reverse shells, and malicious kernel calls in GKE.",
                "enabled": any("container threat" in s for s in source_names_lower),
                "tier_requirement": "Premium / Enterprise",
                "custom_rules_count": 0,
                "target_capability_mapping": "Runtime Workload Sensor & K8s Admission Control",
            },
            {
                "service_id": "vmtd",
                "display_name": "Virtual Machine Threat Detection (VMTD)",
                "category": "Cloud Workload Protection (CWPP)",
                "description": "Agentless hypervisor-level memory scanning to detect kernel rootkits and crypto-mining on Compute Engine instances.",
                "enabled": any("virtual machine threat" in s or "vmtd" in s for s in source_names_lower),
                "tier_requirement": "Premium / Enterprise",
                "custom_rules_count": 0,
                "target_capability_mapping": "Agentless VM Scanning & Runtime Behavioral Detection",
            },
            {
                "service_id": "rvd",
                "display_name": "Rapid Vulnerability Detection (RVD)",
                "category": "Vulnerability Management",
                "description": "Scans public-facing GCP workloads for zero-day vulnerabilities and critical remote code execution (RCE) flaws.",
                "enabled": any("rapid vulnerability" in s for s in source_names_lower),
                "tier_requirement": "Premium / Enterprise",
                "custom_rules_count": 0,
                "target_capability_mapping": "Vulnerability Management & Attack Surface Analysis",
            },
            {
                "service_id": "wss",
                "display_name": "Web Security Scanner (WSS)",
                "category": "Application Security (DAST)",
                "description": "Crawls and analyzes public App Engine, GKE, and Compute Engine web endpoints for OWASP Top 10 vulnerabilities.",
                "enabled": any("web security" in s for s in source_names_lower),
                "tier_requirement": "Standard (Manual) / Premium / Enterprise (Automated)",
                "custom_rules_count": 0,
                "target_capability_mapping": "Dynamic Application Security Testing (DAST) & Inventory",
            },
            {
                "service_id": "sdp",
                "display_name": "Sensitive Data Protection (SDP / Cloud DLP)",
                "category": "Data Security Posture Management (DSPM)",
                "description": "Automated discovery and classification of sensitive data (PII, PCI, secrets, financial records) in GCS, BigQuery, and Cloud SQL.",
                "enabled": any("sensitive data" in s or "dlp" in s for s in source_names_lower),
                "tier_requirement": "Premium / Enterprise (Integrated) / Standalone DLP",
                "custom_rules_count": 0,
                "target_capability_mapping": "Data Security Posture Management (DSPM) & Classification",
            },
            {
                "service_id": "anomaly",
                "display_name": "Anomaly Detection",
                "category": "Behavioral Analytics",
                "description": "Detects anomalous account activities, abnormal resource provisioning spikes, and anomalous service account usage.",
                "enabled": any("anomaly" in s for s in source_names_lower),
                "tier_requirement": "Standard / Premium / Enterprise",
                "custom_rules_count": 0,
                "target_capability_mapping": "Identity Threat Detection & Behavioral Profiling",
            }
        ]

        return services

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
                "securityposture.googleapis.com (v1)",
                "dlp.googleapis.com (v2)",
                "cloudasset.googleapis.com (v1)",
                "cloudresourcemanager.googleapis.com (v3)"
            ]
        }
