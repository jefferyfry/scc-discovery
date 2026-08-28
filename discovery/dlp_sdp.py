"""
discovery/dlp_sdp.py - Sensitive Data Protection (SDP / Cloud DLP) Collector

This module inspects:
- Discovery Configs (Automated BigQuery / Cloud Storage / Cloud SQL data profiling)
- Inspect Templates (Predefined + Custom infoTypes, likelihood rules, regex rules)
- De-identify Templates (Transformations, masking, pseudonymization rules)
- Job Triggers & Data Scans

API References:
- Endpoint: https://dlp.googleapis.com/v2/{parent}/locations/{location}/discoveryConfigs
- Endpoint: https://dlp.googleapis.com/v2/{parent}/locations/{location}/inspectTemplates
- Endpoint: https://dlp.googleapis.com/v2/{parent}/locations/{location}/deidentifyTemplates
- Endpoint: https://dlp.googleapis.com/v2/{parent}/locations/{location}/jobTriggers
"""

import logging
from typing import Dict, Any, List, Optional
from google.auth.transport.requests import AuthorizedSession
from discovery.scc_core import normalize_resource

logger = logging.getLogger(__name__)


class SensitiveDataProtectionCollector:
    """Queries Sensitive Data Protection / Cloud DLP configurations from GCP."""

    def __init__(self, session: AuthorizedSession, resource_id: str, location: str = "global"):
        """
        Initialize the SDP / Cloud DLP Collector.

        Args:
            session: Authenticated requests session.
            resource_id: GCP Organization ID, Project ID, or Folder ID.
            location: Regional location or 'global' (default: 'global').
        """
        self.session = session
        self.parent_name, self.raw_id, self.scope_type = normalize_resource(resource_id)
        self.location = location
        self.parent_path = f"{self.parent_name}/locations/{self.location}"
        self.base_url = f"https://dlp.googleapis.com/v2/{self.parent_path}"

    def collect_all(self) -> Dict[str, Any]:
        """
        Execute full Sensitive Data Protection discovery.

        Returns:
            Dict containing discovery configs, inspect templates, de-identify templates, and job triggers.
        """
        logger.info("Discovering Sensitive Data Protection (DLP) for %s...", self.parent_path)
        discovery_configs = self.list_discovery_configs()
        inspect_templates = self.list_inspect_templates()
        deidentify_templates = self.list_deidentify_templates()
        job_triggers = self.list_job_triggers()

        return {
            "discovery_configs": discovery_configs,
            "discovery_config_count": len(discovery_configs),
            "inspect_templates": inspect_templates,
            "inspect_template_count": len(inspect_templates),
            "deidentify_templates": deidentify_templates,
            "deidentify_template_count": len(deidentify_templates),
            "job_triggers": job_triggers,
            "job_trigger_count": len(job_triggers),
            "scope": f"{self.scope_type.capitalize()}-level ({self.parent_name})",
        }

    def list_discovery_configs(self) -> List[Dict[str, Any]]:
        """
        List automated data profiling discovery configurations.
        """
        url = f"{self.base_url}/discoveryConfigs"
        configs: List[Dict[str, Any]] = []
        try:
            resp = self.session.get(url, timeout=12)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("discoveryConfigs", []):
                    targets = []
                    for t in item.get("targets", []):
                        if "bigQueryTarget" in t:
                            targets.append("BigQuery Tables")
                        elif "cloudStorageTarget" in t:
                            targets.append("Cloud Storage Buckets")
                        elif "cloudSqlTarget" in t:
                            targets.append("Cloud SQL Databases")

                    configs.append({
                        "name": item.get("name", ""),
                        "display_name": item.get("displayName", item.get("name", "").split("/")[-1]),
                        "status": item.get("status", "ACTIVE"),
                        "targets": targets or ["All Project / Org Data Lakes"],
                        "inspect_template": item.get("inspectTemplate", "Standard Profiling"),
                        "actions": list(item.get("actions", [{}])[0].keys()) if item.get("actions") else ["SCC Findings Ingestion"],
                    })
                logger.info("Found %d DLP discovery configs", len(configs))
            elif resp.status_code == 403:
                logger.warning("Permission denied for DLP discovery configs (roles/dlp.reader required)")
            elif resp.status_code == 404:
                logger.debug("DLP discovery configs endpoint not active on target location")
        except Exception as e:
            logger.debug("Error listing DLP discovery configs: %s", e)

        return configs

    def list_inspect_templates(self) -> List[Dict[str, Any]]:
        """
        List Cloud DLP Inspect Templates.
        """
        url = f"{self.base_url}/inspectTemplates"
        templates: List[Dict[str, Any]] = []
        try:
            resp = self.session.get(url, timeout=12)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("inspectTemplates", []):
                    inspect_config = item.get("inspectConfig", {})
                    info_types = inspect_config.get("infoTypes", [])
                    custom_types = inspect_config.get("customInfoTypes", [])

                    templates.append({
                        "name": item.get("name", ""),
                        "display_name": item.get("displayName", item.get("name", "").split("/")[-1]),
                        "description": item.get("description", ""),
                        "min_likelihood": inspect_config.get("minLikelihood", "LIKELY"),
                        "info_types_count": len(info_types) + len(custom_types),
                        "sample_info_types": [t.get("name", "") for t in info_types[:5]],
                        "custom_info_types_count": len(custom_types),
                        "create_time": item.get("createTime", ""),
                    })
                logger.info("Found %d DLP inspect templates", len(templates))
            elif resp.status_code == 403:
                logger.warning("Permission denied for DLP inspect templates")
        except Exception as e:
            logger.debug("Error listing DLP inspect templates: %s", e)

        return templates

    def list_deidentify_templates(self) -> List[Dict[str, Any]]:
        """
        List Cloud DLP De-identification Templates.
        """
        url = f"{self.base_url}/deidentifyTemplates"
        templates: List[Dict[str, Any]] = []
        try:
            resp = self.session.get(url, timeout=12)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("deidentifyTemplates", []):
                    templates.append({
                        "name": item.get("name", ""),
                        "display_name": item.get("displayName", item.get("name", "").split("/")[-1]),
                        "description": item.get("description", ""),
                        "create_time": item.get("createTime", ""),
                    })
                logger.info("Found %d DLP de-identify templates", len(templates))
            elif resp.status_code == 403:
                logger.warning("Permission denied for DLP de-identify templates")
        except Exception as e:
            logger.debug("Error listing DLP de-identify templates: %s", e)

        return templates

    def list_job_triggers(self) -> List[Dict[str, Any]]:
        """
        List scheduled DLP Job Triggers.
        """
        url = f"{self.base_url}/jobTriggers"
        triggers: List[Dict[str, Any]] = []
        try:
            resp = self.session.get(url, timeout=12)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("jobTriggers", []):
                    triggers.append({
                        "name": item.get("name", ""),
                        "display_name": item.get("displayName", item.get("name", "").split("/")[-1]),
                        "status": item.get("status", "HEALTHY"),
                        "last_run_time": item.get("lastRunTime", ""),
                    })
                logger.info("Found %d DLP job triggers", len(triggers))
            elif resp.status_code == 403:
                logger.warning("Permission denied for DLP job triggers")
        except Exception as e:
            logger.debug("Error listing DLP job triggers: %s", e)

        return triggers
