"""
discovery/dlp_sdp.py - Sensitive Data Protection (SDP) & Cloud DLP Configuration Collector

This module inspects Google Cloud Sensitive Data Protection (Cloud DLP):
- Discovery Configs (Automated continuous sensitive data profiling for BigQuery, GCS, Cloud SQL)
- Inspect Templates (InfoType detectors, regexes, custom dictionaries, likelihood thresholds)
- De-identify Templates (Masking, pseudonymization, cryptographic hashing, bucketing rules)
- Job Triggers (Scheduled inspection scan jobs and targets)
- Integration with SCC (Publishing data risk findings to SCC)

API References:
- Service: dlp.googleapis.com (v2)
- Endpoint: https://dlp.googleapis.com/v2/organizations/{org_id}/locations/{location}/discoveryConfigs
- Endpoint: https://dlp.googleapis.com/v2/organizations/{org_id}/locations/{location}/inspectTemplates
- Endpoint: https://dlp.googleapis.com/v2/organizations/{org_id}/locations/{location}/deidentifyTemplates
- Endpoint: https://dlp.googleapis.com/v2/organizations/{org_id}/locations/{location}/jobTriggers
"""

import logging
from typing import Dict, Any, List, Optional
from google.auth.transport.requests import AuthorizedSession

logger = logging.getLogger(__name__)


class SensitiveDataProtectionCollector:
    """Queries Sensitive Data Protection / Cloud DLP configurations from GCP."""

    def __init__(self, session: AuthorizedSession, org_id: str, location: str = "global"):
        """
        Initialize the SDP / Cloud DLP Collector.

        Args:
            session: Authenticated requests session.
            org_id: GCP Organization ID (numeric string or 'organizations/123').
            location: Regional location or 'global' (default: 'global').
        """
        self.session = session
        self.raw_org_id = org_id.replace("organizations/", "")
        self.org_name = f"organizations/{self.raw_org_id}"
        self.location = location
        self.parent_path = f"{self.org_name}/locations/{self.location}"
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
            "sdp_active": len(discovery_configs) > 0 or len(inspect_templates) > 0 or len(job_triggers) > 0,
        }

    def list_discovery_configs(self) -> List[Dict[str, Any]]:
        """
        List Sensitive Data Protection Discovery Configs (Automated Data Profiling).

        API Endpoint: GET https://dlp.googleapis.com/v2/organizations/{org_id}/locations/{location}/discoveryConfigs
        Required Permission: dlp.discoveryConfigs.list
        """
        url = f"{self.base_url}/discoveryConfigs"
        configs: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(url, params=params, timeout=12)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("discoveryConfigs", []):
                        name = item.get("name", "")
                        cfg_id = name.split("/")[-1] if "/" in name else name
                        status = item.get("status", "STATUS_UNSPECIFIED")
                        targets = []
                        for target in item.get("targets", []):
                            if "bigQueryTarget" in target:
                                targets.append("BigQuery (Tables & Datasets)")
                            if "cloudStorageTarget" in target:
                                targets.append("Cloud Storage (Buckets)")
                            if "cloudSqlTarget" in target:
                                targets.append("Cloud SQL (Databases)")

                        configs.append({
                            "name": name,
                            "config_id": cfg_id,
                            "display_name": item.get("displayName", cfg_id),
                            "status": status,
                            "targets": targets or ["Unspecified Data Target"],
                            "inspect_template": item.get("inspectTemplate", "Default Built-in Profiles"),
                            "create_time": item.get("createTime", ""),
                            "update_time": item.get("updateTime", ""),
                        })

                    page_token = data.get("nextPageToken")
                    if not page_token:
                        break
                elif resp.status_code in (404, 403):
                    break
                else:
                    logger.warning("Unexpected status %s listing discovery configs: %s", resp.status_code, resp.text)
                    break

            logger.info("Found %d SDP Discovery Configs", len(configs))
        except Exception as e:
            logger.debug("Error listing discovery configs: %s", e)

        return configs

    def list_inspect_templates(self) -> List[Dict[str, Any]]:
        """
        List Cloud DLP Inspect Templates (custom infoTypes, regexes, dictionaries, sensitivity rules).

        API Endpoint: GET https://dlp.googleapis.com/v2/organizations/{org_id}/locations/{location}/inspectTemplates
        Required Permission: dlp.inspectTemplates.list
        """
        url = f"{self.base_url}/inspectTemplates"
        templates: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(url, params=params, timeout=12)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("inspectTemplates", []):
                        name = item.get("name", "")
                        tmpl_id = name.split("/")[-1] if "/" in name else name
                        inspect_config = item.get("inspectConfig", {})
                        info_types = [it.get("name", "") for it in inspect_config.get("infoTypes", [])]
                        custom_info_types = [cit.get("infoType", {}).get("name", "") for cit in inspect_config.get("customInfoTypes", [])]
                        min_likelihood = inspect_config.get("minLikelihood", "LIKELY")

                        templates.append({
                            "name": name,
                            "template_id": tmpl_id,
                            "display_name": item.get("displayName", tmpl_id),
                            "description": item.get("description", ""),
                            "min_likelihood": min_likelihood,
                            "info_types_count": len(info_types),
                            "custom_info_types_count": len(custom_info_types),
                            "sample_info_types": (info_types + custom_info_types)[:5],
                            "create_time": item.get("createTime", ""),
                            "update_time": item.get("updateTime", ""),
                        })

                    page_token = data.get("nextPageToken")
                    if not page_token:
                        break
                elif resp.status_code in (404, 403):
                    break
                else:
                    break

            logger.info("Found %d DLP Inspect Templates", len(templates))
        except Exception as e:
            logger.debug("Error listing inspect templates: %s", e)

        return templates

    def list_deidentify_templates(self) -> List[Dict[str, Any]]:
        """
        List Cloud DLP De-identification Templates (masking, pseudonymization, hashing).

        API Endpoint: GET https://dlp.googleapis.com/v2/organizations/{org_id}/locations/{location}/deidentifyTemplates
        """
        url = f"{self.base_url}/deidentifyTemplates"
        templates: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(url, params=params, timeout=12)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("deidentifyTemplates", []):
                        name = item.get("name", "")
                        tmpl_id = name.split("/")[-1] if "/" in name else name
                        templates.append({
                            "name": name,
                            "template_id": tmpl_id,
                            "display_name": item.get("displayName", tmpl_id),
                            "description": item.get("description", ""),
                            "create_time": item.get("createTime", ""),
                            "update_time": item.get("updateTime", ""),
                        })

                    page_token = data.get("nextPageToken")
                    if not page_token:
                        break
                elif resp.status_code in (404, 403):
                    break
                else:
                    break

            logger.info("Found %d DLP De-identify Templates", len(templates))
        except Exception as e:
            logger.debug("Error listing deidentify templates: %s", e)

        return templates

    def list_job_triggers(self) -> List[Dict[str, Any]]:
        """
        List DLP Job Triggers (Scheduled inspection and profiling jobs).

        API Endpoint: GET https://dlp.googleapis.com/v2/organizations/{org_id}/locations/{location}/jobTriggers
        """
        url = f"{self.base_url}/jobTriggers"
        triggers: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(url, params=params, timeout=12)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("jobTriggers", []):
                        name = item.get("name", "")
                        trig_id = name.split("/")[-1] if "/" in name else name
                        status = item.get("status", "STATUS_UNSPECIFIED")
                        triggers.append({
                            "name": name,
                            "trigger_id": trig_id,
                            "display_name": item.get("displayName", trig_id),
                            "description": item.get("description", ""),
                            "status": status,
                            "last_run_time": item.get("lastRunTime", ""),
                            "inspect_job": item.get("inspectJob", {}),
                        })

                    page_token = data.get("nextPageToken")
                    if not page_token:
                        break
                elif resp.status_code in (404, 403):
                    break
                else:
                    break

            logger.info("Found %d DLP Job Triggers", len(triggers))
        except Exception as e:
            logger.debug("Error listing job triggers: %s", e)

        return triggers
