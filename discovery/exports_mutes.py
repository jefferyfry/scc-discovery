"""
discovery/exports_mutes.py - Continuous Exports & Mute Rules Collector

This module inspects:
- Continuous Pub/Sub Exports (Notification Configs for SIEM, Slack, PagerDuty, Webhooks)
- Continuous BigQuery Exports (Streaming findings tables to BigQuery for analytics)
- Finding Mute Rules (Finding suppression filters & exception management)

API References:
- Notification Configs: https://securitycenter.googleapis.com/v1/{parent}/notificationConfigs
- BigQuery Exports: https://securitycenter.googleapis.com/v1/{parent}/bigQueryExports
- Mute Configs: https://securitycenter.googleapis.com/v1/{parent}/muteConfigs
"""

import logging
from typing import Dict, Any, List, Optional
from google.auth.transport.requests import AuthorizedSession
from discovery.scc_core import normalize_resource

logger = logging.getLogger(__name__)


class ExportsAndMutesCollector:
    """Queries Continuous Exports (Pub/Sub & BigQuery) and Mute Rules from SCC."""

    def __init__(self, session: AuthorizedSession, resource_id: str, location: str = "global"):
        """
        Initialize the Exports and Mutes Collector.

        Args:
            session: Authenticated requests session.
            resource_id: GCP Organization ID, Project ID, or Folder ID.
            location: SCC location (default: 'global').
        """
        self.session = session
        self.parent_name, self.raw_id, self.scope_type = normalize_resource(resource_id)
        self.location = location
        self.base_url = "https://securitycenter.googleapis.com/v1"

    def collect_all(self) -> Dict[str, Any]:
        """
        Execute full exports and mute rules discovery.

        Returns:
            Dict containing notification configs, bigquery exports, and mute configs.
        """
        logger.info("Discovering Continuous Exports & Mute Rules for %s (%s scope)...", self.parent_name, self.scope_type)
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
            "scope": f"{self.scope_type.capitalize()}-level ({self.parent_name})",
        }

    def list_notification_configs(self) -> List[Dict[str, Any]]:
        """
        List continuous Pub/Sub export notification configurations.
        """
        url = f"{self.base_url}/{self.parent_name}/notificationConfigs"
        configs: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(url, params=params, timeout=15)
                if resp.status_code != 200:
                    break

                data = resp.json()
                for item in data.get("notificationConfigs", []):
                    name = item.get("name", "")
                    topic = item.get("pubsubTopic", "")
                    configs.append({
                        "name": name,
                        "config_id": name.split("/")[-1],
                        "description": item.get("description", ""),
                        "pubsub_topic": topic,
                        "topic_short": topic.split("/")[-1] if "/" in topic else topic,
                        "filter": item.get("streamingConfig", {}).get("filter", "ALL_FINDINGS"),
                    })

                page_token = data.get("nextPageToken")
                if not page_token:
                    break

            logger.info("Found %d continuous Pub/Sub exports", len(configs))
        except Exception as e:
            logger.debug("Error listing notification configs: %s", e)

        return configs

    def list_bigquery_exports(self) -> List[Dict[str, Any]]:
        """
        List continuous BigQuery export configurations.
        """
        url = f"{self.base_url}/{self.parent_name}/bigQueryExports"
        exports: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(url, params=params, timeout=15)
                if resp.status_code != 200:
                    break

                data = resp.json()
                for item in data.get("bigQueryExports", []):
                    name = item.get("name", "")
                    dataset = item.get("dataset", "")
                    exports.append({
                        "name": name,
                        "export_id": name.split("/")[-1],
                        "description": item.get("description", ""),
                        "dataset": dataset,
                        "dataset_short": dataset.split("/")[-1] if "/" in dataset else dataset,
                        "filter": item.get("filter", "ALL_FINDINGS"),
                        "create_time": item.get("createTime", ""),
                        "most_recent_editor": item.get("mostRecentEditor", ""),
                    })

                page_token = data.get("nextPageToken")
                if not page_token:
                    break

            logger.info("Found %d continuous BigQuery exports", len(exports))
        except Exception as e:
            logger.debug("Error listing BigQuery exports: %s", e)

        return exports

    def list_mute_configs(self) -> List[Dict[str, Any]]:
        """
        List finding mute configurations / suppression rules.
        """
        url = f"{self.base_url}/{self.parent_name}/muteConfigs"
        mutes: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(url, params=params, timeout=15)
                if resp.status_code != 200:
                    break

                data = resp.json()
                for item in data.get("muteConfigs", []):
                    name = item.get("name", "")
                    mutes.append({
                        "name": name,
                        "mute_config_id": name.split("/")[-1],
                        "display_name": item.get("displayName", name.split("/")[-1]),
                        "description": item.get("description", ""),
                        "filter": item.get("filter", ""),
                        "create_time": item.get("createTime", ""),
                        "update_time": item.get("updateTime", ""),
                        "most_recent_editor": item.get("mostRecentEditor", "Unknown"),
                    })

                page_token = data.get("nextPageToken")
                if not page_token:
                    break

            logger.info("Found %d finding mute rules", len(mutes))
        except Exception as e:
            logger.debug("Error listing mute configs: %s", e)

        return mutes
