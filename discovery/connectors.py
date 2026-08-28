"""
discovery/connectors.py - Connectors, Multi-Cloud & Ticketing Integrations Collector

This module inspects:
- Multi-cloud Connectors (AWS, Azure multi-cloud connections in SCC Enterprise)
- Ticketing & SIEM Connectors (Jira, ServiceNow, Chronicle, PagerDuty, Slack, Webhooks)
- 3rd-Party Security Vendor Integrations (Tenable, Qualys, Palo Alto, CrowdStrike, etc.)
"""

import logging
from typing import Dict, Any, List, Optional
from google.auth.transport.requests import AuthorizedSession
from discovery.scc_core import normalize_resource

logger = logging.getLogger(__name__)


class ConnectorsCollector:
    """Discovers Multi-cloud connectors, Ticketing/ITSM bridges, and SIEM pipelines."""

    def __init__(self, session: AuthorizedSession, resource_id: str, location: str = "global"):
        """
        Initialize the Connectors Collector.

        Args:
            session: Authenticated requests session.
            resource_id: GCP Organization ID, Project ID, or Folder ID.
            location: SCC location (default: 'global').
        """
        self.session = session
        self.parent_name, self.raw_id, self.scope_type = normalize_resource(resource_id)
        self.location = location
        self.base_url_v1 = "https://securitycenter.googleapis.com/v1"

    def collect_all(self, registered_sources: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Execute full connectors discovery.

        Returns:
            Dict containing multi-cloud connectors, ticketing integrations, SIEM pipelines, and vendor sources.
        """
        logger.info("Discovering Connectors and Integrations for %s...", self.parent_name)
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
            "total_connectors": len(multicloud_connectors) + len(ticketing_connectors) + len(vendor_sources),
            "scope": f"{self.scope_type.capitalize()}-level ({self.parent_name})",
        }

    def discover_multicloud_connectors(self) -> List[Dict[str, Any]]:
        """
        Check for active multi-cloud connections (AWS / Azure posture deployments).
        """
        connectors: List[Dict[str, Any]] = []
        if self.scope_type != "ORGANIZATION":
            return connectors

        posture_dep_url = f"https://securityposture.googleapis.com/v1/{self.parent_name}/locations/{self.location}/postureDeployments"
        try:
            resp = self.session.get(posture_dep_url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for dep in data.get("postureDeployments", []):
                    target = dep.get("targetResource", "")
                    if "aws" in target.lower() or "amazon" in target.lower():
                        connectors.append({
                            "type": "AWS Cloud Connector",
                            "name": dep.get("name", "").split("/")[-1],
                            "target_id": target,
                            "status": dep.get("state", "ACTIVE"),
                            "description": dep.get("description", "AWS Multi-cloud posture assessment connection."),
                            "target_connector_mapping": "Cloud Account Connector (Role-based / Multi-cloud)"
                        })
                    elif "azure" in target.lower() or "tenant" in target.lower():
                        connectors.append({
                            "type": "Azure Cloud Connector",
                            "name": dep.get("name", "").split("/")[-1],
                            "target_id": target,
                            "status": dep.get("state", "ACTIVE"),
                            "description": dep.get("description", "Azure Multi-cloud posture assessment connection."),
                            "target_connector_mapping": "Subscription Connector (App Registration / Multi-cloud)"
                        })
        except Exception as e:
            logger.debug("Error checking multi-cloud connectors: %s", e)

        return connectors

    def discover_ticketing_connectors(self) -> List[Dict[str, Any]]:
        """
        Discover continuous export notification topics configured for ticketing (Jira/ServiceNow) or SIEM.
        """
        connectors: List[Dict[str, Any]] = []
        url = f"{self.base_url_v1}/{self.parent_name}/notificationConfigs"

        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("notificationConfigs", []):
                    name = item.get("name", "")
                    topic = item.get("pubsubTopic", "")
                    desc = item.get("description", "").lower()
                    t_lower = topic.lower()

                    if "jira" in t_lower or "jira" in desc:
                        connectors.append({
                            "type": "Jira Ticketing Connector",
                            "name": name.split("/")[-1],
                            "topic": topic,
                            "status": "ACTIVE",
                            "description": item.get("description", "Automated Jira issue creation bridge for security findings."),
                            "target_connector_mapping": "Jira Cloud / Server Integration & Automation Rules"
                        })
                    elif "servicenow" in t_lower or "snow" in t_lower or "servicenow" in desc:
                        connectors.append({
                            "type": "ServiceNow ITSM Connector",
                            "name": name.split("/")[-1],
                            "topic": topic,
                            "status": "ACTIVE",
                            "description": item.get("description", "ServiceNow Incident & Vulnerability Response integration."),
                            "target_connector_mapping": "ServiceNow Incident & Security Operations Integration"
                        })
                    elif any(s in t_lower or s in desc for s in ["siem", "chronicle", "splunk", "sentinel"]):
                        connectors.append({
                            "type": "SIEM / Chronicle Forwarder",
                            "name": name.split("/")[-1],
                            "topic": topic,
                            "status": "ACTIVE",
                            "description": item.get("description", "Real-time SIEM streaming pipeline for event correlation."),
                            "target_connector_mapping": "SIEM Streaming Forwarder & Webhook Integration"
                        })
        except Exception as e:
            logger.debug("Error checking ticketing connectors: %s", e)

        return connectors

    def filter_vendor_sources(self, registered_sources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter 3rd-party vendor and partner security sources integrated with SCC.
        """
        vendor_sources: List[Dict[str, Any]] = []
        for s in registered_sources:
            if not s.get("is_builtin"):
                vendor_sources.append({
                    "name": s.get("name", ""),
                    "display_name": s.get("display_name", "Vendor Source"),
                    "description": s.get("description", ""),
                    "source_id": s.get("source_id", ""),
                    "type": "3rd-Party Security Vendor Source"
                })
        return vendor_sources
