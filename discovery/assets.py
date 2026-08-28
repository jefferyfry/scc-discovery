"""
discovery/assets.py - Cloud Asset Inventory & Resource Type Breakdown Collector

This module aggregates the organization's cloud asset inventory:
- Total asset count
- Asset counts grouped by Resource Type (Compute Instances, Buckets, GKE, BigQuery, IAM, SQL, etc.)
- Publicly accessible or external asset indicators

API References:
- SCC GroupAssets: POST https://securitycenter.googleapis.com/v1/organizations/{org_id}/assets:group
- Cloud Asset Inventory: GET https://cloudasset.googleapis.com/v1/organizations/{org_id}:searchAllResources
"""

import logging
from typing import Dict, Any, List, Optional
from google.auth.transport.requests import AuthorizedSession

logger = logging.getLogger(__name__)


class AssetInventoryCollector:
    """Queries Cloud Asset Inventory and SCC Asset discovery."""

    def __init__(self, session: AuthorizedSession, org_id: str):
        """
        Initialize the Asset Inventory Collector.

        Args:
            session: Authenticated requests session.
            org_id: GCP Organization ID (numeric string or 'organizations/123').
        """
        self.session = session
        self.raw_org_id = org_id.replace("organizations/", "")
        self.org_name = f"organizations/{self.raw_org_id}"
        self.scc_group_assets_url = f"https://securitycenter.googleapis.com/v1/{self.org_name}/assets:group"
        self.asset_search_url = f"https://cloudasset.googleapis.com/v1/{self.org_name}:searchAllResources"

    def collect_all(self) -> Dict[str, Any]:
        """
        Execute full asset inventory discovery.

        Returns:
            Dict containing total assets, breakdown by resource type, and category summaries.
        """
        logger.info("Discovering asset inventory and resource counts for %s...", self.org_name)
        asset_counts = self.group_assets_by_type()

        # If SCC GroupAssets returned empty or failed, fallback to Cloud Asset Search
        if not asset_counts:
            logger.info("Falling back to Cloud Asset Inventory SearchAllResources...")
            asset_counts = self.search_cloud_assets()

        total_assets = sum(item["count"] for item in asset_counts)

        # Categorize into high-level service domains
        categorized_assets = self.categorize_assets(asset_counts)

        return {
            "total_assets": total_assets,
            "asset_types_count": len(asset_counts),
            "asset_types_breakdown": asset_counts,
            "top_asset_types": asset_counts[:15],
            "domain_categories": categorized_assets,
        }

    def group_assets_by_type(self) -> List[Dict[str, Any]]:
        """
        Query SCC GroupAssets API to aggregate assets by resource type.
        """
        results: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                body: Dict[str, Any] = {
                    "groupBy": "securityCenterProperties.resourceType",
                    "pageSize": 1000
                }
                if page_token:
                    body["pageToken"] = page_token

                resp = self.session.post(self.scc_group_assets_url, json=body, timeout=20)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("groupByResults", []):
                        props = item.get("properties", {})
                        r_type = props.get("securityCenterProperties.resourceType", "UNKNOWN")
                        count = int(item.get("count", 0))
                        results.append({
                            "resource_type": r_type,
                            "short_type": r_type.split("/")[-1] if "/" in r_type else r_type,
                            "service": r_type.split(".")[0] if "." in r_type else "other",
                            "count": count,
                        })

                    page_token = data.get("nextPageToken")
                    if not page_token:
                        break
                elif resp.status_code in (403, 404):
                    logger.debug("SCC GroupAssets returned %s; will use Cloud Asset API fallback", resp.status_code)
                    break
                else:
                    logger.warning("SCC GroupAssets HTTP %s: %s", resp.status_code, resp.text)
                    break
        except Exception as e:
            logger.debug("Error during SCC GroupAssets: %s", e)

        results.sort(key=lambda x: x["count"], reverse=True)
        return results

    def search_cloud_assets(self) -> List[Dict[str, Any]]:
        """
        Fallback using Cloud Asset Inventory SearchAllResources.
        """
        type_counts: Dict[str, int] = {}
        page_token = None

        try:
            while True:
                params: Dict[str, Any] = {"pageSize": 500}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(self.asset_search_url, params=params, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    for resource in data.get("results", []):
                        asset_type = resource.get("assetType", "UNKNOWN")
                        type_counts[asset_type] = type_counts.get(asset_type, 0) + 1

                    page_token = data.get("nextPageToken")
                    if not page_token:
                        break
                else:
                    break
        except Exception as e:
            logger.debug("Error during Cloud Asset search: %s", e)

        results = [
            {
                "resource_type": k,
                "short_type": k.split("/")[-1] if "/" in k else k,
                "service": k.split(".")[0] if "." in k else "other",
                "count": v
            }
            for k, v in type_counts.items()
        ]
        results.sort(key=lambda x: x["count"], reverse=True)
        return results

    def categorize_assets(self, asset_counts: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Group fine-grained resource types into executive cloud architecture domains.
        """
        domains: Dict[str, int] = {
            "Compute & Workloads (VMs, Containers, Functions)": 0,
            "Storage & Data Lakes (GCS, BigQuery, Filestore)": 0,
            "Databases (Cloud SQL, Spanner, Firestore, Bigtable)": 0,
            "Identity & Access Management (Roles, Service Accounts, Keys)": 0,
            "Networking & Connectivity (VPC, Subnets, Firewalls, Load Balancers)": 0,
            "Security & Cryptography (KMS, Secrets, Certificates)": 0,
            "Other Cloud Services": 0
        }

        for item in asset_counts:
            rt = item["resource_type"].lower()
            count = item["count"]

            if any(k in rt for k in ["instance", "cluster", "nodepool", "pod", "function", "run.googleapis.com"]):
                domains["Compute & Workloads (VMs, Containers, Functions)"] += count
            elif any(k in rt for k in ["bucket", "storage.googleapis.com", "bigquery.googleapis.com/dataset", "bigquery.googleapis.com/table"]):
                domains["Storage & Data Lakes (GCS, BigQuery, Filestore)"] += count
            elif any(k in rt for k in ["sqladmin", "spanner", "firestore", "bigtable"]):
                domains["Databases (Cloud SQL, Spanner, Firestore, Bigtable)"] += count
            elif any(k in rt for k in ["iam.googleapis.com", "serviceaccount", "role", "key"]):
                domains["Identity & Access Management (Roles, Service Accounts, Keys)"] += count
            elif any(k in rt for k in ["compute.googleapis.com/network", "compute.googleapis.com/subnetwork", "firewall", "forwardingrule", "router", "vpn"]):
                domains["Networking & Connectivity (VPC, Subnets, Firewalls, Load Balancers)"] += count
            elif any(k in rt for k in ["kms", "cryptokey", "secretmanager", "certificate"]):
                domains["Security & Cryptography (KMS, Secrets, Certificates)"] += count
            else:
                domains["Other Cloud Services"] += count

        return domains
