"""
discovery/exports_mutes.py - Continuous Exports & Mute Rules Collector

This module inspects:
- Continuous Pub/Sub Exports (Notification Configs for SIEM, Slack, PagerDuty, Webhooks)
- Continuous BigQuery Exports (Streaming findings tables to BigQuery for analytics)
- Finding Mute Rules (Finding suppression filters & exception management)

API References:
- Notification Configs: https://securitycenter.googleapis.com/v1/organizations/{org_id}/notificationConfigs
- BigQuery Exports: https://securitycenter.googleapis.com/v1/organizations/{org_id}/bigQueryExports
- Mute Configs: https://securitycenter.googleapis.com/v1/organizations/{org_id}/muteConfigs
"""

import logging
from typing import Dict, Any, List, Optional
from google.auth.transport.requests import AuthorizedSession

logger = logging.getLogger(__name__)


class ExportsAndMutesCollector:
    """Queries Continuous Exports (Pub/Sub & BigQuery) and Mute Rules from SCC."""

    def __init__(self, session: AuthorizedSession, org_id: str, location: str = "global"):
        """
        Initialize the Exports and Mutes Collector.

        Args:
            session: Authenticated requests session.
            org_id: GCP Organization ID (numeric string or 'organizations/123').
            location: SCC location (default: 'global').
        """
        self.session = session
        self.raw_org_id = org_id.replace("organizations/", "")
        self.org_name = f"organizations/{self.raw_org_id}"
        self.location = location
        self.base_url = "https://securitycenter.googleapis.com/v1"

    def collect_all(self) -> Dict[str, Any]:
        """
        Execute full exports and mute rules discovery.

        Returns:
            Dict containing notification configs, bigquery exports, and mute configs.
        """
        logger.info("Discovering Continuous Exports & Mute Rules for %s...", self.org_name)
        pubsub_exports = self.list_notification_configs()
        bq_exports = self.list_bigquery_exports()
        mute_rules = self.list_mute_configs()

        return {
            "pubsub_notification_configs": pubsub_exports,
            "pubsub_export_count": len(pubsub_exports),
            "bigquery_exports": bq_exports,
            "bigquery_export_count": len(bq_exports),
            "mute_rules": mute_rules,
            "mute_rule_count": len(mute_rules),
        }

    def list_notification_configs(self) -> List[Dict[str, Any]]:
        """
        List all Pub/Sub continuous finding notification exports.

        API Endpoint: GET https://securitycenter.googleapis.com/v1/organizations/{org_id}/notificationConfigs
        Required Permission: securitycenter.notificationconfig.list
        """
        url = f"{self.base_url}/{self.org_name}/notificationConfigs"
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
                    for item in data.get("notificationConfigs", []):
                        name = item.get("name", "")
                        cfg_id = name.split("/")[-1] if "/" in name else name
                        topic = item.get("pubsubTopic", "")
                        streaming_filter = item.get("streamingConfig", {}).get("filter", "state = \"ACTIVE\"")
                        description = item.get("description", "No description provided")

                        configs.append({
                            "name": name,
                            "config_id": cfg_id,
                            "pubsub_topic": topic,
                            "topic_short": topic.split("/")[-1] if "/" in topic else topic,
                            "filter": streaming_filter,
                            "description": description,
                            "service_account": item.get("serviceAccount", ""),
                        })

                    page_token = data.get("nextPageToken")
                    if not page_token:
                        break
                elif resp.status_code == 403:
                    logger.warning("Permission denied listing notification configs")
                    break
                else:
                    break

            logger.info("Found %d Pub/Sub Continuous Notification Exports", len(configs))
        except Exception as e:
            logger.debug("Error listing notification configs: %s", e)

        return configs

    def list_bigquery_exports(self) -> List[Dict[str, Any]]:
        """
        List all BigQuery continuous finding export configurations.

        API Endpoint: GET https://securitycenter.googleapis.com/v1/organizations/{org_id}/bigQueryExports
        Required Permission: securitycenter.bigqueryexports.list
        """
        url = f"{self.base_url}/{self.org_name}/bigQueryExports"
        exports: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(url, params=params, timeout=12)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("bigQueryExports", []):
                        name = item.get("name", "")
                        export_id = name.split("/")[-1] if "/" in name else name
                        dataset = item.get("dataset", "")
                        filter_expr = item.get("filter", "All Findings")
                        description = item.get("description", "")

                        exports.append({
                            "name": name,
                            "export_id": export_id,
                            "dataset": dataset,
                            "dataset_short": dataset.split("/")[-1] if "/" in dataset else dataset,
                            "filter": filter_expr,
                            "description": description,
                            "principal": item.get("principal", ""),
                            "create_time": item.get("createTime", ""),
                            "update_time": item.get("updateTime", ""),
                        })

                    page_token = data.get("nextPageToken")
                    if not page_token:
                        break
                elif resp.status_code == 403:
                    logger.warning("Permission denied listing BigQuery exports")
                    break
                else:
                    break

            logger.info("Found %d BigQuery Continuous Exports", len(exports))
        except Exception as e:
            logger.debug("Error listing BigQuery exports: %s", e)

        return exports

    def list_mute_configs(self) -> List[Dict[str, Any]]:
        """
        List all Finding Mute Rules (Mute Configs) in the organization.

        API Endpoint: GET https://securitycenter.googleapis.com/v1/organizations/{org_id}/muteConfigs
        Required Permission: securitycenter.muteconfigs.list
        """
        url = f"{self.base_url}/{self.org_name}/muteConfigs"
        mutes: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(url, params=params, timeout=12)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("muteConfigs", []):
                        name = item.get("name", "")
                        mute_id = name.split("/")[-1] if "/" in name else name
                        display_name = item.get("displayName", mute_id)
                        description = item.get("description", "No description provided")
                        filter_expr = item.get("filter", "")

                        mutes.append({
                            "name": name,
                            "mute_id": mute_id,
                            "display_name": display_name,
                            "description": description,
                            "filter": filter_expr,
                            "most_recent_editor": item.get("mostRecentEditor", "Automated / Unknown"),
                            "create_time": item.get("createTime", ""),
                            "update_time": item.get("updateTime", ""),
                        })

                    page_token = data.get("nextPageToken")
                    if not page_token:
                        break
                elif resp.status_code == 403:
                    logger.warning("Permission denied listing mute configs")
                    break
                else:
                    break

            logger.info("Found %d Finding Mute Rules", len(mutes))
        except Exception as e:
            logger.debug("Error listing mute configs: %s", e)

        return mutes
