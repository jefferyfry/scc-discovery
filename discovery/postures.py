"""
discovery/postures.py - Security Posture Management & Policy Deployment Collector

This module inspects Google Cloud Security Posture Management (available in SCC Enterprise):
- Security Postures (Defined postures, policy sets, and posture controls)
- Posture Deployments (Target bindings across Organization, Folders, and Projects)
- Posture Templates (Pre-built compliance & security posture baselines)

API References:
- Service: securityposture.googleapis.com
- Endpoint: https://securityposture.googleapis.com/v1/organizations/{org_id}/locations/{location}/postures
- Endpoint: https://securityposture.googleapis.com/v1/organizations/{org_id}/locations/{location}/postureDeployments
- Endpoint: https://securityposture.googleapis.com/v1/organizations/{org_id}/locations/{location}/postureTemplates
"""

import logging
from typing import Dict, Any, List, Optional
from google.auth.transport.requests import AuthorizedSession

logger = logging.getLogger(__name__)


class SecurityPostureCollector:
    """Queries Security Posture configurations and deployments from GCP."""

    def __init__(self, session: AuthorizedSession, org_id: str, location: str = "global"):
        """
        Initialize the Security Posture Collector.

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
        self.base_url = f"https://securityposture.googleapis.com/v1/{self.parent_path}"

    def collect_all(self) -> Dict[str, Any]:
        """
        Execute full Security Posture discovery.

        Returns:
            Dict containing postures, deployments, templates, and summary metrics.
        """
        logger.info("Discovering Security Postures for %s...", self.parent_path)
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
            "posture_feature_enabled": len(postures) > 0 or len(deployments) > 0 or len(templates) > 0,
        }

    def list_postures(self) -> List[Dict[str, Any]]:
        """
        List all custom and configured security postures in the organization.

        API Endpoint: GET https://securityposture.googleapis.com/v1/organizations/{org_id}/locations/{location}/postures
        Required Permission: securityposture.postures.list
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
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("postures", []):
                        name = item.get("name", "")
                        posture_id = name.split("/")[-1] if "/" in name else name
                        state = item.get("state", "STATE_UNSPECIFIED")
                        description = item.get("description", "No description provided")
                        revision_id = item.get("revisionId", "1")
                        policy_sets = item.get("policySets", [])

                        # Calculate total policy controls across all policy sets
                        total_rules = 0
                        policy_set_summaries = []
                        for ps in policy_sets:
                            ps_id = ps.get("policySetId", "unknown")
                            ps_desc = ps.get("description", "")
                            policies = ps.get("policies", [])
                            total_rules += len(policies)
                            policy_set_summaries.append({
                                "policy_set_id": ps_id,
                                "description": ps_desc,
                                "rules_count": len(policies),
                            })

                        postures.append({
                            "name": name,
                            "posture_id": posture_id,
                            "state": state,
                            "revision_id": revision_id,
                            "description": description,
                            "policy_sets_count": len(policy_sets),
                            "total_rules_count": total_rules,
                            "policy_sets": policy_set_summaries,
                            "create_time": item.get("createTime", ""),
                            "update_time": item.get("updateTime", ""),
                        })

                    page_token = data.get("nextPageToken")
                    if not page_token:
                        break
                elif resp.status_code == 404:
                    logger.debug("Security Posture API not enabled or no postures found (404)")
                    break
                elif resp.status_code == 403:
                    logger.warning("Permission denied querying Security Postures (roles/securityposture.viewer required)")
                    break
                else:
                    logger.warning("Unexpected status %s listing postures: %s", resp.status_code, resp.text)
                    break

            logger.info("Found %d Security Postures", len(postures))
        except Exception as e:
            logger.debug("Error listing postures: %s", e)

        return postures

    def list_posture_deployments(self) -> List[Dict[str, Any]]:
        """
        List all active and pending Security Posture Deployments.

        API Endpoint: GET https://securityposture.googleapis.com/v1/organizations/{org_id}/locations/{location}/postureDeployments
        Required Permission: securityposture.postureDeployments.list
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
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("postureDeployments", []):
                        name = item.get("name", "")
                        dep_id = name.split("/")[-1] if "/" in name else name
                        target_resource = item.get("targetResource", "")
                        posture_id = item.get("postureId", "")
                        posture_revision_id = item.get("postureRevisionId", "")
                        state = item.get("state", "STATE_UNSPECIFIED")
                        description = item.get("description", "")

                        deployments.append({
                            "name": name,
                            "deployment_id": dep_id,
                            "target_resource": target_resource,
                            "posture_id": posture_id,
                            "posture_revision_id": posture_revision_id,
                            "state": state,
                            "description": description,
                            "failure_message": item.get("failureMessage", ""),
                            "create_time": item.get("createTime", ""),
                            "update_time": item.get("updateTime", ""),
                        })

                    page_token = data.get("nextPageToken")
                    if not page_token:
                        break
                elif resp.status_code in (404, 403):
                    break
                else:
                    logger.warning("Unexpected status %s listing posture deployments: %s", resp.status_code, resp.text)
                    break

            logger.info("Found %d Posture Deployments", len(deployments))
        except Exception as e:
            logger.debug("Error listing posture deployments: %s", e)

        return deployments

    def list_posture_templates(self) -> List[Dict[str, Any]]:
        """
        List Google Cloud pre-defined posture templates (e.g. CIS Foundations, NIST, PCI-DSS).

        API Endpoint: GET https://securityposture.googleapis.com/v1/organizations/{org_id}/locations/{location}/postureTemplates
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
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("postureTemplates", []):
                        name = item.get("name", "")
                        tmpl_id = name.split("/")[-1] if "/" in name else name
                        description = item.get("description", "")
                        policy_sets = item.get("policySets", [])

                        templates.append({
                            "template_id": tmpl_id,
                            "name": name,
                            "description": description,
                            "policy_sets_count": len(policy_sets),
                            "revision_id": item.get("revisionId", "1"),
                        })

                    page_token = data.get("nextPageToken")
                    if not page_token:
                        break
                elif resp.status_code in (404, 403):
                    break
                else:
                    break
        except Exception as e:
            logger.debug("Error listing posture templates: %s", e)

        return templates
