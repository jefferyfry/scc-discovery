"""
discovery/assets.py - Cloud Asset Inventory & Resource Type Breakdown Collector

This module aggregates cloud asset inventory across Organization, Folder, or Project:
- Total asset count
- Asset counts grouped by Resource Type (Compute Instances, Buckets, GKE, BigQuery, IAM, SQL, etc.)
- Publicly accessible or external asset indicators

API References:
- SCC GroupAssets: POST https://securitycenter.googleapis.com/v1/{parent}/assets:group
- Cloud Asset Inventory: GET https://cloudasset.googleapis.com/v1/{parent}:searchAllResources
"""

import logging
from typing import Dict, Any, List, Optional
from google.auth.transport.requests import AuthorizedSession
from discovery.scc_core import normalize_resource

logger = logging.getLogger(__name__)


class AssetInventoryCollector:
    """Queries Cloud Asset Inventory and SCC Asset discovery."""

    def __init__(self, session: AuthorizedSession, resource_id: str):
        """
        Initialize the Asset Inventory Collector.

        Args:
            session: Authenticated requests session.
            resource_id: GCP Organization ID, Project ID, or Folder ID.
        """
        self.session = session
        self.parent_name, self.raw_id, self.scope_type = normalize_resource(resource_id)
        self.scc_group_assets_url = f"https://securitycenter.googleapis.com/v1/{self.parent_name}/assets:group"
        self.asset_search_url = f"https://cloudasset.googleapis.com/v1/{self.parent_name}:searchAllResources"

    def collect_all(self) -> Dict[str, Any]:
        """
        Execute full asset inventory discovery.

        Returns:
            Dict containing total assets, breakdown by resource type, and category summaries.
        """
        logger.info("Discovering asset inventory and resource counts for %s (%s scope)...", self.parent_name, self.scope_type)
        asset_counts = self.group_assets_by_type()

        # If SCC GroupAssets returned empty or failed, fallback to Cloud Asset Search
        if not asset_counts:
            logger.info("Falling back to Cloud Asset Inventory SearchAllResources...")
            asset_counts = self.search_cloud_assets()

        total_assets = sum(item["count"] for item in asset_counts)
        categorized_assets = self.categorize_assets(asset_counts)

        return {
            "total_assets": total_assets,
            "asset_types_count": len(asset_counts),
            "asset_counts_by_type": asset_counts,
            "top_asset_types": asset_counts[:12],
            "domain_categories": categorized_assets,
            "scope": f"{self.scope_type.capitalize()}-level ({self.parent_name})",
        }

    def group_assets_by_type(self) -> List[Dict[str, Any]]:
        """
        Query SCC assets:group endpoint to aggregate asset inventory by resourceType.
        """
        payload = {
            "groupBy": "securityCenterProperties.resourceType",
            "pageSize": 100
        }
        results = []
        try:
            resp = self.session.post(self.scc_group_assets_url, json=payload, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("groupByResults", []):
                    res_type = item.get("properties", {}).get("securityCenterProperties.resourceType", "UNKNOWN")
                    count = int(item.get("count", 0))
                    results.append({
                        "resource_type": res_type,
                        "display_name": self._format_resource_type(res_type),
                        "count": count
                    })
                results.sort(key=lambda x: x["count"], reverse=True)
                logger.info("Discovered %d resource types via SCC assets:group", len(results))
            elif resp.status_code == 403:
                logger.warning("Permission denied querying SCC assets:group")
        except Exception as e:
            logger.debug("Error querying SCC assets:group: %s", e)

        return results

    def search_cloud_assets(self) -> List[Dict[str, Any]]:
        """
        Fallback: Query Cloud Asset Inventory searchAllResources API.
        """
        counts: Dict[str, int] = {}
        page_token = None
        try:
            while True:
                params = {"pageSize": 500}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(self.asset_search_url, params=params, timeout=20)
                if resp.status_code != 200:
                    break

                data = resp.json()
                for res in data.get("results", []):
                    asset_type = res.get("assetType", "UNKNOWN")
                    counts[asset_type] = counts.get(asset_type, 0) + 1

                page_token = data.get("nextPageToken")
                if not page_token or len(counts) > 200:
                    break

            results = [
                {
                    "resource_type": k,
                    "display_name": self._format_resource_type(k),
                    "count": v
                }
                for k, v in counts.items()
            ]
            results.sort(key=lambda x: x["count"], reverse=True)
            logger.info("Discovered %d resource types via Cloud Asset Inventory", len(results))
            return results
        except Exception as e:
            logger.debug("Error querying Cloud Asset Inventory: %s", e)

        return []

    def categorize_assets(self, asset_counts: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Group fine-grained resource types into high-level architecture domains.
        """
        domains: Dict[str, int] = {
            "Compute & Workloads (VMs, Containers, Functions)": 0,
            "Storage & Data Lakes (GCS, Filestore)": 0,
            "Databases & Analytics (BigQuery, Cloud SQL, Spanner)": 0,
            "Identity & Access Management (Service Accounts, Keys)": 0,
            "Networking & Connectivity (VPCs, Firewalls, Load Balancers)": 0,
            "Security & Cryptography (KMS Keys, Secrets)": 0,
            "Other Cloud Services": 0
        }

        for item in asset_counts:
            r_type = item["resource_type"].lower()
            cnt = item["count"]

            if any(k in r_type for k in ["instance", "container", "cluster", "function", "run.googleapis"]):
                domains["Compute & Workloads (VMs, Containers, Functions)"] += cnt
            elif any(k in r_type for k in ["bucket", "storage", "filestore"]):
                domains["Storage & Data Lakes (GCS, Filestore)"] += cnt
            elif any(k in r_type for k in ["sql", "bigquery", "spanner", "bigtable", "firestore"]):
                domains["Databases & Analytics (BigQuery, Cloud SQL, Spanner)"] += cnt
            elif any(k in r_type for k in ["serviceaccount", "iam", "key", "role"]):
                domains["Identity & Access Management (Service Accounts, Keys)"] += cnt
            elif any(k in r_type for k in ["network", "firewall", "forwardingrule", "router", "subnet"]):
                domains["Networking & Connectivity (VPCs, Firewalls, Load Balancers)"] += cnt
            elif any(k in r_type for k in ["kms", "cryptokey", "secretmanager"]):
                domains["Security & Cryptography (KMS Keys, Secrets)"] += cnt
            else:
                domains["Other Cloud Services"] += cnt

        return {k: v for k, v in domains.items() if v > 0}

    def _format_resource_type(self, res_type: str) -> str:
        """Helper to convert full GCP resource type URL to clean display name."""
        if "/" in res_type:
            parts = res_type.split("/")
            return parts[-1] if len(parts) > 1 else res_type
        if "." in res_type:
            return res_type.split(".")[-1]
        return res_type
