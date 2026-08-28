"""
discovery/findings.py - Security Findings & Issues Metrics Collector

This module aggregates findings across Organization, Folder, or Project scope:
- Total active findings
- Number of findings by source (SHA, ETD, CTD, VMTD, SDP, WSS, RVD, 3rd-party)
- Number of issues/findings by category (Top 25 categories, misconfigurations, threats, vulnerabilities)
- Breakdown by Severity (CRITICAL, HIGH, MEDIUM, LOW)
- Breakdown by Class (MISCONFIGURATION, THREAT, VULNERABILITY, OBSERVATION)

API References:
- Service: securitycenter.googleapis.com (v1)
- Method: SecurityCenter.GroupFindings
- Endpoint: POST https://securitycenter.googleapis.com/v1/{parent}/sources/-/findings:group
- Required Permission: securitycenter.findings.group / securitycenter.findings.list
"""

import logging
from typing import Dict, Any, List, Optional
from google.auth.transport.requests import AuthorizedSession
from discovery.scc_core import normalize_resource

logger = logging.getLogger(__name__)


class FindingsCollector:
    """Aggregates findings and security issues using SCC GroupFindings API."""

    def __init__(self, session: AuthorizedSession, resource_id: str):
        """
        Initialize the Findings Collector.

        Args:
            session: Authenticated requests session.
            resource_id: GCP Organization ID, Project ID, or Folder ID.
        """
        self.session = session
        self.parent_name, self.raw_id, self.scope_type = normalize_resource(resource_id)
        self.group_endpoint = f"https://securitycenter.googleapis.com/v1/{self.parent_name}/sources/-/findings:group"

    def collect_all(self, source_lookup: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Execute full findings aggregation and metrics collection.

        Args:
            source_lookup: Optional dictionary mapping source_id to display name.

        Returns:
            Dict containing findings by source, category, severity, and class.
        """
        logger.info("Aggregating SCC findings and issues for %s (%s scope)...", self.parent_name, self.scope_type)
        source_lookup = source_lookup or {}

        severity_counts = self.group_by_field("severity", filter_expr='state="ACTIVE"')
        class_counts = self.group_by_field("finding_class", filter_expr='state="ACTIVE"')
        category_counts = self.group_by_field("category", filter_expr='state="ACTIVE"')

        # In SCC v1 GroupFindings, the property is 'source' or 'source_id'
        source_counts_raw = self.group_by_field("source", filter_expr='state="ACTIVE"')
        if not source_counts_raw:
            source_counts_raw = self.group_by_field("source_id", filter_expr='state="ACTIVE"')

        total_findings = sum(severity_counts.values()) if severity_counts else 0

        # Enrich source counts with human-readable names
        findings_by_source: List[Dict[str, Any]] = []

        if source_counts_raw:
            for item in source_counts_raw:
                raw_key = item.get("key", "Unknown")
                count = item.get("count", 0)
                s_id = raw_key.split("/")[-1] if "/" in raw_key else raw_key
                disp_name = source_lookup.get(s_id) or source_lookup.get(raw_key) or self._infer_source_name(s_id)
                cat_type = self._classify_source_category(disp_name)
                share_pct = round((count / total_findings * 100), 1) if total_findings > 0 else 0.0

                findings_by_source.append({
                    "source_id": s_id,
                    "source_name": disp_name,
                    "category_type": cat_type,
                    "count": count,
                    "percentage": share_pct,
                })
        elif category_counts and total_findings > 0:
            # Fallback: Infer source distribution from category prefixes
            inferred_sources: Dict[str, int] = {}
            for item in category_counts:
                cat_name = item.get("key", "")
                cnt = item.get("count", 0)
                src = self._infer_source_from_category(cat_name)
                inferred_sources[src] = inferred_sources.get(src, 0) + cnt

            for src_name, cnt in inferred_sources.items():
                share_pct = round((cnt / total_findings * 100), 1)
                findings_by_source.append({
                    "source_id": src_name.lower().replace(" ", "_"),
                    "source_name": src_name,
                    "category_type": self._classify_source_category(src_name),
                    "count": cnt,
                    "percentage": share_pct,
                })

        # Sort sources by count descending
        findings_by_source.sort(key=lambda x: x["count"], reverse=True)

        # Enrich top categories
        findings_by_category: List[Dict[str, Any]] = []
        for item in category_counts:
            cat_name = item.get("key", "")
            findings_by_category.append({
                "key": cat_name,
                "count": item.get("count", 0),
                "class": self._infer_category_class(cat_name),
                "severity": self._infer_category_severity(cat_name),
            })
        findings_by_category.sort(key=lambda x: x["count"], reverse=True)

        return {
            "total_active_findings": total_findings,
            "severity_breakdown": {
                "CRITICAL": severity_counts.get("CRITICAL", 0),
                "HIGH": severity_counts.get("HIGH", 0),
                "MEDIUM": severity_counts.get("MEDIUM", 0),
                "LOW": severity_counts.get("LOW", 0),
            },
            "class_breakdown": {
                "MISCONFIGURATION": class_counts.get("MISCONFIGURATION", 0),
                "VULNERABILITY": class_counts.get("VULNERABILITY", 0),
                "THREAT": class_counts.get("THREAT", 0),
                "OBSERVATION": class_counts.get("OBSERVATION", 0),
            },
            "findings_by_source": findings_by_source,
            "findings_by_category": findings_by_category,
            "top_categories": findings_by_category[:12],
        }

    def group_by_field(self, group_by_column: str, filter_expr: str = "") -> Any:
        """
        Execute server-side GroupFindings query.
        """
        payload = {
            "groupBy": group_by_column,
            "pageSize": 100
        }
        if filter_expr:
            payload["filter"] = filter_expr

        try:
            resp = self.session.post(self.group_endpoint, json=payload, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for item in data.get("groupByResults", []):
                    properties = item.get("properties", {})
                    # SCC returns the property with exact name or nested
                    key = properties.get(group_by_column) or properties.get("source") or properties.get("key") or "UNKNOWN"
                    count = int(item.get("count", 0))
                    results.append({"key": str(key), "count": count})

                if group_by_column in ("severity", "finding_class"):
                    return {r["key"]: r["count"] for r in results}
                return results
            elif resp.status_code == 403:
                logger.warning("Permission denied grouping findings by %s", group_by_column)
            elif resp.status_code == 404:
                logger.debug("GroupFindings endpoint not active for %s", self.parent_name)
        except Exception as e:
            logger.debug("Error executing GroupFindings for %s: %s", group_by_column, e)

        return {} if group_by_column in ("severity", "finding_class") else []

    def _infer_source_from_category(self, cat: str) -> str:
        c_upper = cat.upper()
        if any(prefix in c_upper for prefix in ["PERSISTENCE:", "EXECUTION:", "EXFILTRATION:", "PRIVILEGE ESCALATION:", "INITIAL ACCESS:", "DEFENSE EVASION:"]):
            return "Event Threat Detection (ETD)"
        elif any(w in c_upper for w in ["VULNERABILITY", "CVE", "PACKAGE", "OUTDATED"]):
            return "Vulnerability Assessment"
        elif any(w in c_upper for w in ["CONTAINER", "K8S", "GKE"]):
            return "Container Threat Detection (CTD)"
        elif any(w in c_upper for w in ["VM_", "VMTD", "MINING"]):
            return "Virtual Machine Threat Detection (VMTD)"
        elif any(w in c_upper for w in ["WEB_", "XSS", "SQL_INJECTION", "WSS"]):
            return "Web Security Scanner (WSS)"
        elif any(w in c_upper for w in ["PII", "DLP", "SENSITIVE"]):
            return "Sensitive Data Protection (SDP)"
        return "Security Health Analytics (SHA)"

    def _infer_source_name(self, source_id: str) -> str:
        common_sources = {
            "1001": "Security Health Analytics (SHA)",
            "1002": "Event Threat Detection (ETD)",
            "1003": "Container Threat Detection (CTD)",
            "1004": "Virtual Machine Threat Detection (VMTD)",
            "1005": "Sensitive Data Protection (SDP)",
            "1006": "Rapid Vulnerability Detection (RVD)",
            "1007": "Web Security Scanner (WSS)",
            "1008": "Anomaly Detection",
        }
        return common_sources.get(source_id, f"Security Source ({source_id})")

    def _classify_source_category(self, display_name: str) -> str:
        name_l = display_name.lower()
        if "health analytics" in name_l or "sha" in name_l:
            return "CSPM / Misconfiguration"
        elif "event threat" in name_l or "etd" in name_l:
            return "CDR / Threat Detection"
        elif "container threat" in name_l or "ctd" in name_l:
            return "CWPP / Container Runtime"
        elif "virtual machine" in name_l or "vmtd" in name_l:
            return "CWPP / VM Memory Inspection"
        elif "sensitive data" in name_l or "dlp" in name_l:
            return "DSPM / Sensitive Data"
        elif "vulnerability" in name_l or "rvd" in name_l:
            return "Vulnerability Management"
        elif "web security" in name_l or "wss" in name_l:
            return "DAST / Web Application"
        elif "run threat" in name_l:
            return "Serverless Threat Detection"
        return "Third-Party / Vendor Finding"

    def _infer_category_class(self, cat: str) -> str:
        c_upper = cat.upper()
        if any(w in c_upper for w in ["VULNERABILITY", "CVE", "OUTDATED", "PATCH", "EXPLOIT"]):
            return "VULNERABILITY"
        elif any(w in c_upper for w in ["PERSISTENCE", "EXECUTION", "EXFILTRATION", "ANOMALOUS", "MINING", "REVERSE_SHELL", "THREAT", "SUSPICIOUS"]):
            return "THREAT"
        elif any(w in c_upper for w in ["PII", "SENSITIVE_DATA", "EXPOSED_DATA"]):
            return "OBSERVATION"
        return "MISCONFIGURATION"

    def _infer_category_severity(self, cat: str) -> str:
        c_upper = cat.upper()
        if any(w in c_upper for w in ["PUBLIC_BUCKET", "EXPOSED_KEY", "ADMIN_PRIVILEGE", "MINING", "SQL_INJECTION", "CRITICAL"]):
            return "CRITICAL"
        elif any(w in c_upper for w in ["FIREWALL", "NON_PRIVILEGED", "DEFAULT_SA", "PACKAGE_VULNERABILITY", "HIGH"]):
            return "HIGH"
        elif any(w in c_upper for w in ["UNENCRYPTED", "KMS", "LOGGING", "ROTATED", "MEDIUM"]):
            return "MEDIUM"
        return "LOW"
