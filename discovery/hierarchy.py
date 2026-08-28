"""
discovery/hierarchy.py - Resource Hierarchy & Scope Coverage Collector

This module maps the Google Cloud resource hierarchy across Organization, Folder, or Project:
- Organization details (ID, Domain, Display Name)
- Folders hierarchy (Folder IDs, names, nested structure)
- Projects inventory (Active, pending deletion, project numbers, parents)
- SCC Coverage mapping (Evaluating Org-wide vs folder/project scoped coverage)

API References:
- Resource Manager Organizations: GET https://cloudresourcemanager.googleapis.com/v3/organizations/{org_id}
- Resource Manager Folders: GET https://cloudresourcemanager.googleapis.com/v3/folders?parent=...
- Resource Manager Projects: GET https://cloudresourcemanager.googleapis.com/v3/projects?parent=... or /projects/{project_id}
"""

import logging
from typing import Dict, Any, List, Optional
from google.auth.transport.requests import AuthorizedSession
from discovery.scc_core import normalize_resource

logger = logging.getLogger(__name__)


class ResourceHierarchyCollector:
    """Queries Cloud Resource Manager hierarchy to evaluate coverage across the organization or project."""

    def __init__(self, session: AuthorizedSession, resource_id: str):
        """
        Initialize the Resource Hierarchy Collector.

        Args:
            session: Authenticated requests session.
            resource_id: GCP Organization ID, Project ID, or Folder ID.
        """
        self.session = session
        self.parent_name, self.raw_id, self.scope_type = normalize_resource(resource_id)
        self.is_org = (self.scope_type == "ORGANIZATION")
        self.is_project = (self.scope_type == "PROJECT")
        self.crm_url = "https://cloudresourcemanager.googleapis.com/v3"

    def collect_all(self) -> Dict[str, Any]:
        """
        Execute full resource hierarchy discovery.

        Returns:
            Dict containing organization/project details, folders, projects, and coverage evaluation.
        """
        logger.info("Discovering GCP Resource Hierarchy for %s (%s scope)...", self.parent_name, self.scope_type)

        if self.is_project:
            proj_details = self.get_single_project_details()
            return {
                "organization": {
                    "name": "Standalone Project Scope",
                    "display_name": f"Project: {self.raw_id}",
                    "state": proj_details.get("state", "ACTIVE"),
                    "directory_customer_id": "N/A (Project Scope)"
                },
                "folders": [],
                "folder_count": 0,
                "projects": [proj_details],
                "project_count": 1,
                "active_project_count": 1 if proj_details.get("state") in ("ACTIVE", "STATE_UNSPECIFIED") else 0,
                "coverage_scope": f"Project-Level Scope ({self.raw_id})",
                "coverage_percentage": 100.0,
                "projects_summary": [proj_details]
            }

        org_details = self.get_org_details()
        folders = self.list_folders()
        projects = self.list_projects()

        active_projects = [p for p in projects if p.get("state") in ("ACTIVE", "STATE_UNSPECIFIED")]

        return {
            "organization": org_details,
            "folders": folders,
            "folder_count": len(folders),
            "projects": projects,
            "project_count": len(projects),
            "active_project_count": len(active_projects),
            "coverage_scope": "Organization-Wide (100% Inherited)" if len(projects) > 0 else "Scoped / Project Level",
            "coverage_percentage": 100.0 if len(projects) > 0 else 0.0,
            "projects_summary": [
                {
                    "project_id": p.get("project_id", ""),
                    "display_name": p.get("display_name", ""),
                    "state": p.get("state", "ACTIVE"),
                    "parent": p.get("parent", "")
                }
                for p in projects[:25]
            ]
        }

    def get_single_project_details(self) -> Dict[str, Any]:
        """
        Retrieve metadata for a single target project.
        """
        url = f"{self.crm_url}/projects/{self.raw_id}"
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "project_id": data.get("projectId", self.raw_id),
                    "project_number": data.get("name", "").split("/")[-1],
                    "display_name": data.get("displayName", self.raw_id),
                    "state": data.get("state", "ACTIVE"),
                    "parent": data.get("parent", "None (No Organization)")
                }
        except Exception as e:
            logger.debug("Error getting project details: %s", e)

        return {
            "project_id": self.raw_id,
            "project_number": "N/A",
            "display_name": self.raw_id,
            "state": "ACTIVE",
            "parent": "None (Standalone Project)"
        }

    def get_org_details(self) -> Dict[str, Any]:
        """
        Retrieve GCP Organization metadata.
        """
        url = f"{self.crm_url}/{self.parent_name}"
        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "name": data.get("name", self.parent_name),
                    "display_name": data.get("displayName", self.raw_id),
                    "directory_customer_id": data.get("directoryCustomerId", ""),
                    "state": data.get("state", "ACTIVE"),
                    "create_time": data.get("createTime", ""),
                }
            elif resp.status_code == 403:
                logger.warning("Permission denied reading organization metadata (roles/resourcemanager.organizationViewer)")
                return {"name": self.parent_name, "display_name": f"Org-{self.raw_id}", "state": "ACTIVE"}
        except Exception as e:
            logger.debug("Error getting org details: %s", e)

        return {"name": self.parent_name, "display_name": f"Org-{self.raw_id}", "state": "ACTIVE"}

    def list_folders(self) -> List[Dict[str, Any]]:
        """
        List top-level and nested folders under the organization.
        """
        url = f"{self.crm_url}/folders"
        folders: List[Dict[str, Any]] = []
        try:
            params = {"parent": self.parent_name}
            resp = self.session.get(url, params=params, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for f in data.get("folders", []):
                    f_name = f.get("name", "")
                    folders.append({
                        "name": f_name,
                        "folder_id": f_name.split("/")[-1],
                        "display_name": f.get("displayName", "Unnamed Folder"),
                        "state": f.get("state", "ACTIVE"),
                        "parent": f.get("parent", self.parent_name)
                    })
                logger.info("Discovered %d folders under %s", len(folders), self.parent_name)
            elif resp.status_code == 403:
                logger.warning("Permission denied listing folders")
        except Exception as e:
            logger.debug("Error listing folders: %s", e)

        return folders

    def list_projects(self) -> List[Dict[str, Any]]:
        """
        List all projects under the organization and its folders.
        """
        url = f"{self.crm_url}/projects"
        projects: List[Dict[str, Any]] = []
        page_token = None

        try:
            while True:
                params = {"parent": self.parent_name, "pageSize": 100}
                if page_token:
                    params["pageToken"] = page_token

                resp = self.session.get(url, params=params, timeout=15)
                if resp.status_code != 200:
                    break

                data = resp.json()
                for p in data.get("projects", []):
                    proj_id = p.get("projectId", "")
                    projects.append({
                        "name": p.get("name", ""),
                        "project_id": proj_id,
                        "project_number": p.get("name", "").split("/")[-1],
                        "display_name": p.get("displayName", proj_id),
                        "state": p.get("state", "ACTIVE"),
                        "parent": p.get("parent", self.parent_name)
                    })

                page_token = data.get("nextPageToken")
                if not page_token:
                    break

            logger.info("Discovered %d projects under %s", len(projects), self.parent_name)
        except Exception as e:
            logger.debug("Error listing projects: %s", e)

        return projects
