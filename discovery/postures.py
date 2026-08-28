"""
discovery/postures.py - Security Posture Management & Deployments Collector

This module inspects Security Posture Management (SCC Enterprise feature):
- Security Postures (Custom & predefined baseline postures, CIS, NIST, ISO)
- Policy Sets & Policy Rules
- Posture Deployments (Active deployments to organizations, folders, projects)
- Posture Templates

API References:
- Endpoint: https://securityposture.googleapis.com/v1/{parent}/locations/{location}/postures
- Endpoint: https://securityposture.googleapis.com/v1/{parent}/locations/{location}/postureDeployments
- Endpoint: https://securityposture.googleapis.com/v1/{parent}/locations/{location}/postureTemplates
"""

import logging
from typing import Dict, Any, List, Optional
from google.auth.transport.requests import AuthorizedSession
from discovery.scc_core import normalize_resource

logger = logging.getLogger(__name__)


class SecurityPostureCollector:
    """Queries Security Posture configurations and deployments from GCP."""

    def __init__(self, session: AuthorizedSession, resource_id: str, location: str = "global"):
        """
        Initialize the Security Posture Collector.

        Args:
            session: Authenticated requests session.
            resource_id: GCP Organization ID, Project ID, or Folder ID.
            location: Regional location or 'global' (default: 'global').
        """
        self.session = session
        self.parent_name, self.raw_id, self.scope_type = normalize_resource(resource_id)
        self.is_org = (self.scope_type == "ORGANIZATION")
        self.location = location
        self.parent_path = f"{self.parent_name}/locations/{self.location}"
        self.base_url = f"https://securityposture.googleapis.com/v1/{self.parent_path}"

    def collect_all(self) -> Dict[str, Any]:
        """
        Execute full Security Posture discovery.

        Returns:
            Dict containing postures, deployments, templates, and summary metrics.
        """
        logger.info("Discovering Security Postures for %s (%s scope)...", self.parent_path, self.scope_type)
        if not self.is_org:
            logger.info("Security Posture deployments are primarily managed at the Organization level. Setting project scope.")
            return {
                "postures": [],
                "posture_count": 0,
                "posture_deployments": [],
                "deployment_count": 0,
                "posture_templates": [],
                "template_count": 0,
                "scope": f"{self.scope_type.capitalize()}-level ({self.parent_name})",
                "status": f"NOT_APPLICABLE ({self.scope_type.capitalize()} Scope - Requires Organization Node)"
            }

        postures = self.list_postures()
        deployments = self.list_posture_deployments()
        templates = self.list_posture_templates()

        return {
            "postures": postures,
            "posture_count": len(postures),
            "posture_deployments": deployments,
            "deployment_count": len(deployments),
            "posture_templates": templates,
            "template_count": len(templates),
            "scope": f"{self.scope_type.capitalize()}-level ({self.parent_name})",
        }

    def list_postures(self) -> List[Dict[str, Any]]:
        """
        List all security postures.
        """
        url = f"{self.base_url}/postures"
        postures: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(url, params=params, timeout=12)
                if resp.status_code == 404:
                    logger.debug("Security Posture API not active on target resource")
                    break
                elif resp.status_code == 403:
                    logger.warning("Permission denied querying Security Postures (roles/securityposture.viewer required)")
                    break
                elif resp.status_code != 200:
                    break

                data = resp.json()
                for item in data.get("postures", []):
                    policy_sets = item.get("policySets", [])
                    total_rules = sum(len(ps.get("policies", [])) for ps in policy_sets)
                    postures.append({
                        "name": item.get("name", ""),
                        "posture_id": item.get("name", "").split("/")[-1],
                        "revision_id": item.get("revisionId", ""),
                        "state": item.get("state", "ACTIVE"),
                        "description": item.get("description", ""),
                        "policy_sets_count": len(policy_sets),
                        "total_rules_count": total_rules,
                        "create_time": item.get("createTime", ""),
                        "update_time": item.get("updateTime", ""),
                    })

                page_token = data.get("nextPageToken")
                if not page_token:
                    break

            logger.info("Found %d security postures", len(postures))
        except Exception as e:
            logger.debug("Error listing security postures: %s", e)

        return postures

    def list_posture_deployments(self) -> List[Dict[str, Any]]:
        """
        List all active posture deployments.
        """
        url = f"{self.base_url}/postureDeployments"
        deployments: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(url, params=params, timeout=12)
                if resp.status_code in (403, 404) or resp.status_code != 200:
                    break

                data = resp.json()
                for item in data.get("postureDeployments", []):
                    deployments.append({
                        "name": item.get("name", ""),
                        "deployment_id": item.get("name", "").split("/")[-1],
                        "target_resource": item.get("targetResource", ""),
                        "posture_id": item.get("postureId", ""),
                        "posture_revision_id": item.get("postureRevisionId", ""),
                        "state": item.get("state", "ACTIVE"),
                        "description": item.get("description", ""),
                        "create_time": item.get("createTime", ""),
                    })

                page_token = data.get("nextPageToken")
                if not page_token:
                    break

            logger.info("Found %d posture deployments", len(deployments))
        except Exception as e:
            logger.debug("Error listing posture deployments: %s", e)

        return deployments

    def list_posture_templates(self) -> List[Dict[str, Any]]:
        """
        List built-in posture templates (CIS, NIST, etc.).
        """
        url = f"{self.base_url}/postureTemplates"
        templates: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                params = {"pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(url, params=params, timeout=12)
                if resp.status_code in (403, 404) or resp.status_code != 200:
                    break

                data = resp.json()
                for item in data.get("postureTemplates", []):
                    templates.append({
                        "name": item.get("name", ""),
                        "template_id": item.get("name", "").split("/")[-1],
                        "description": item.get("description", ""),
                        "revision_id": item.get("revisionId", ""),
                        "state": item.get("state", "ACTIVE"),
                    })

                page_token = data.get("nextPageToken")
                if not page_token:
                    break

            logger.info("Found %d posture templates", len(templates))
        except Exception as e:
            logger.debug("Error listing posture templates: %s", e)

        return templates
