"""
discovery/connectors.py - Connectors & Third-Party Integrations Collector

This module inspects:
- Multi-cloud Connectors (AWS & Azure accounts connected to SCC Enterprise)
- Ticketing & IT Service Management Connectors (Jira, ServiceNow, PagerDuty)
- SIEM / SOAR Connectors (Chronicle SOAR, Google SecOps, Splunk, Cortex XSOAR)
- Third-party Security Vendor Sources registered in SCC

API References:
- Multi-cloud Connectors / Postures: https://securityposture.googleapis.com/v1/organizations/{org_id}/locations/{location}/...
- SCC Sources: https://securitycenter.googleapis.com/v1/organizations/{org_id}/sources
"""

import logging
from typing import Dict, Any, List, Optional
from google.auth.transport.requests import AuthorizedSession

logger = logging.getLogger(__name__)


class ConnectorsCollector:
    """Queries Connectors, multi-cloud integrations, and ticketing pipelines."""

    def __init__(self, session: AuthorizedSession, org_id: str, location: str = "global"):
        """
        Initialize the Connectors Collector.

        Args:
            session: Authenticated requests session.
            org_id: GCP Organization ID (numeric string or 'organizations/123').
            location: SCC location (default: 'global').
        """
        self.session = session
        self.raw_org_id = org_id.replace("organizations/", "")
        self.org_name = f"organizations/{self.raw_org_id}"
        self.location = location
        self.base_url_v1 = "https://securitycenter.googleapis.com/v1"

    def collect_all(self, registered_sources: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Execute full connectors discovery.

        Returns:
            Dict containing multi-cloud connectors, ticketing integrations, SIEM pipelines, and vendor sources.
        """
        logger.info("Discovering Connectors and Integrations for %s...", self.org_name)
        multicloud_connectors = self.discover_multicloud_connectors()
        ticketing_connectors = self.discover_ticketing_connectors()
        vendor_sources = self.filter_vendor_sources(registered_sources or [])

        return {
            "multicloud_connectors": multicloud_connectors,
            "multicloud_count": len(multicloud_connectors),
            "ticketing_connectors": ticketing_connectors,
            "ticketing_count": len(ticketing_connectors),
            "vendor_sources": vendor_sources,
            "vendor_source_count": len(vendor_sources),
            "total_connectors": len(multicloud_connectors) + len(ticketing_connectors) + len(vendor_sources)
        }

    def discover_multicloud_connectors(self) -> List[Dict[str, Any]]:
        """
        Query connected AWS accounts and Azure subscriptions managed under SCC Enterprise.
        """
        connectors: List[Dict[str, Any]] = []
        # Query posture deployments targeting AWS/Azure or check registered multi-cloud resources
        url = f"https://securityposture.googleapis.com/v1/{self.org_name}/locations/{self.location}/postureDeployments"
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for dep in data.get("postureDeployments", []):
                    target = dep.get("targetResource", "")
                    if "aws" in target.lower():
                        connectors.append({
                            "type": "AWS Cloud Connector",
                            "name": dep.get("name", ""),
                            "target_id": target,
                            "status": dep.get("state", "ACTIVE"),
                            "description": "AWS Multi-cloud posture assessment & inventory connection",
                            "target_connector_mapping": "Cloud Account Connector (Role-based / Multi-cloud)",
                        })
                    elif "azure" in target.lower():
                        connectors.append({
                            "type": "Azure Cloud Connector",
                            "name": dep.get("name", ""),
                            "target_id": target,
                            "status": dep.get("state", "ACTIVE"),
                            "description": "Azure Multi-cloud posture assessment & inventory connection",
                            "target_connector_mapping": "Subscription Connector (App Registration / Multi-cloud)",
                        })
        except Exception as e:
            logger.debug("Error checking multi-cloud connectors: %s", e)

        return connectors

    def discover_ticketing_connectors(self) -> List[Dict[str, Any]]:
        """
        Inspect Pub/Sub continuous export topics to identify connected ticketing/ITSM systems (Jira, ServiceNow, PagerDuty).
        """
        connectors: List[Dict[str, Any]] = []
        url = f"{self.base_url_v1}/{self.org_name}/notificationConfigs"
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("notificationConfigs", []):
                    name = item.get("name", "")
                    topic = item.get("pubsubTopic", "").lower()
                    desc = item.get("description", "").lower()

                    if "jira" in topic or "jira" in desc:
                        connectors.append({
                            "type": "Jira Ticketing Connector",
                            "name": name,
                            "topic": item.get("pubsubTopic", ""),
                            "status": "ACTIVE",
                            "description": "Automated ticket creation in Jira for high/critical security findings",
                            "target_connector_mapping": "Jira Cloud / Server Integration & Automation Actions",
                        })
                    elif "servicenow" in topic or "snow" in topic or "servicenow" in desc:
                        connectors.append({
                            "type": "ServiceNow ITSM Connector",
                            "name": name,
                            "topic": item.get("pubsubTopic", ""),
                            "status": "ACTIVE",
                            "description": "ServiceNow Incident & Vulnerability Response integration",
                            "target_connector_mapping": "ServiceNow Incident & Security Operations Integration",
                        })
                    elif "pagerduty" in topic or "pagerduty" in desc:
                        connectors.append({
                            "type": "PagerDuty Incident Connector",
                            "name": name,
                            "topic": item.get("pubsubTopic", ""),
                            "status": "ACTIVE",
                            "description": "On-call paging pipeline for critical threat detections",
                            "target_connector_mapping": "PagerDuty Incident Alerting Integration",
                        })
                    elif "chronicle" in topic or "siem" in topic or "secops" in topic:
                        connectors.append({
                            "type": "Chronicle / Google SecOps SIEM",
                            "name": name,
                            "topic": item.get("pubsubTopic", ""),
                            "status": "ACTIVE",
                            "description": "Real-time SIEM ingestion for security event correlation",
                            "target_connector_mapping": "SIEM Streaming Forwarder & Webhook Integration",
                        })
        except Exception as e:
            logger.debug("Error detecting ticketing connectors: %s", e)

        return connectors

    def filter_vendor_sources(self, sources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter integrated third-party security vendors registered in SCC.
        """
        vendor_sources: List[Dict[str, Any]] = []
        for src in sources:
            if not src.get("is_builtin", False):
                vendor_sources.append({
                    "name": src.get("name", ""),
                    "display_name": src.get("display_name", ""),
                    "description": src.get("description", ""),
                    "source_id": src.get("source_id", ""),
                    "type": "3rd-Party Security Vendor Source"
                })
        return vendor_sources
