"""
discovery/findings.py - Security Findings & Issues Metrics Collector

This module aggregates findings across the organization:
- Total active findings
- Number of findings by source (SHA, ETD, CTD, VMTD, SDP, WSS, RVD, 3rd-party)
- Number of issues/findings by category (Top 25 categories, misconfigurations, threats, vulnerabilities)
- Breakdown by Severity (CRITICAL, HIGH, MEDIUM, LOW)
- Breakdown by Class (MISCONFIGURATION, THREAT, VULNERABILITY, OBSERVATION)

API References:
- Service: securitycenter.googleapis.com (v1)
- Method: SecurityCenter.GroupFindings
- Endpoint: POST https://securitycenter.googleapis.com/v1/organizations/{org_id}/sources/-/findings:group
- Required Permission: securitycenter.findings.group / securitycenter.findings.list
"""

import logging
from typing import Dict, Any, List, Optional
from google.auth.transport.requests import AuthorizedSession

logger = logging.getLogger(__name__)


class FindingsCollector:
    """Aggregates findings and security issues using SCC GroupFindings API."""

    def __init__(self, session: AuthorizedSession, org_id: str):
        """
        Initialize the Findings Collector.

        Args:
            session: Authenticated requests session.
            org_id: GCP Organization ID (numeric string or 'organizations/123').
        """
        self.session = session
        self.raw_org_id = org_id.replace("organizations/", "")
        self.org_name = f"organizations/{self.raw_org_id}"
        self.group_endpoint = f"https://securitycenter.googleapis.com/v1/{self.org_name}/sources/-/findings:group"

    def collect_all(self, source_lookup: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Execute full findings aggregation and metrics collection.

        Args:
            source_lookup: Optional dictionary mapping source_id to display name.

        Returns:
            Dict containing findings by source, category, severity, and class.
        """
        logger.info("Aggregating SCC findings and issues for %s...", self.org_name)
        source_lookup = source_lookup or {}

        severity_counts = self.group_by_field("severity", filter_expr='state="ACTIVE"')
        class_counts = self.group_by_field("finding_class", filter_expr='state="ACTIVE"')
        category_counts = self.group_by_field("category", filter_expr='state="ACTIVE"')
        source_counts_raw = self.group_by_field("source_id", filter_expr='state="ACTIVE"')

        # Enrich source counts with human-readable names
        findings_by_source: List[Dict[str, Any]] = []
        total_active_findings = sum(item["count"] for item in severity_counts)

        for sc in source_counts_raw:
            s_id = sc.get("key", "unknown")
            display_name = source_lookup.get(s_id, f"Source-{s_id}")
            # Map standard known source IDs
            if "health" in display_name.lower():
                category_type = "CSPM / Misconfiguration"
            elif "event" in display_name.lower():
                category_type = "CDR / Threat Detection"
            elif "container" in display_name.lower():
                category_type = "CWPP / Container Runtime"
            elif "virtual machine" in display_name.lower() or "vmtd" in display_name.lower():
                category_type = "CWPP / VM Memory Inspection"
            elif "sensitive data" in display_name.lower() or "dlp" in display_name.lower():
                category_type = "DSPM / Sensitive Data"
            elif "vulnerability" in display_name.lower():
                category_type = "Vulnerability Management"
            elif "web security" in display_name.lower():
                category_type = "DAST / Web Application"
            else:
                category_type = "Integrated / Custom"

            findings_by_source.append({
                "source_id": s_id,
                "source_name": display_name,
                "category_type": category_type,
                "count": sc.get("count", 0),
                "percentage": round((sc.get("count", 0) / total_active_findings * 100), 1) if total_active_findings else 0
            })

        # Sort sources and categories by count descending
        findings_by_source.sort(key=lambda x: x["count"], reverse=True)
        category_counts.sort(key=lambda x: x["count"], reverse=True)

        return {
            "total_active_findings": total_active_findings,
            "severity_breakdown": {s["key"]: s["count"] for s in severity_counts},
            "class_breakdown": {c["key"]: c["count"] for c in class_counts},
            "findings_by_source": findings_by_source,
            "findings_by_category": category_counts,
            "top_categories": category_counts[:20],
        }

    def group_by_field(self, group_by_field: str, filter_expr: str = 'state="ACTIVE"') -> List[Dict[str, Any]]:
        """
        Query SCC GroupFindings API to aggregate findings by a specific field server-side.

        API Request Body:
        {
          "groupBy": "category",
          "filter": "state = \"ACTIVE\""
        }
        """
        results: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                body: Dict[str, Any] = {
                    "groupBy": group_by_field,
                    "filter": filter_expr,
                    "pageSize": 1000
                }
                if page_token:
                    body["pageToken"] = page_token

                resp = self.session.post(self.group_endpoint, json=body, timeout=20)
                if resp.status_code == 200:
                    data = resp.json()
                    for group_result in data.get("groupByResults", []):
                        props = group_result.get("properties", {})
                        count_val = int(group_result.get("count", 0))
                        key_val = props.get(group_by_field, "UNKNOWN")
                        results.append({
                            "key": str(key_val),
                            "count": count_val
                        })

                    page_token = data.get("nextPageToken")
                    if not page_token:
                        break
                elif resp.status_code == 403:
                    logger.warning("Permission denied grouping findings by %s", group_by_field)
                    break
                else:
                    logger.warning("HTTP %s grouping findings by %s: %s", resp.status_code, group_by_field, resp.text)
                    break
        except Exception as e:
            logger.debug("Error during GroupFindings for %s: %s", group_by_field, e)

        return results
