"""
discovery/auth.py - Google Cloud Authentication & Session Management

This module manages authentication to Google Cloud APIs for read-only discovery of:
- Security Command Center (SCC)
- Cloud Security Posture Management
- Sensitive Data Protection (Cloud DLP)
- Cloud Asset Inventory
- Cloud Resource Manager (Hierarchy)

Authentication Methods Supported:
1. Application Default Credentials (ADC): Automatically discovered when running
   under `gcloud auth application-default login` or on GCP compute environments (GCE, Cloud Run, GKE).
2. Service Account Key File: Explicit path passed via `--credentials` / `--service-account-key`.

Required Read-Only IAM Roles:
- roles/securitycenter.adminViewer (or roles/securitycenter.viewer)
- roles/securityposture.viewer
- roles/dlp.reader
- roles/cloudasset.viewer
- roles/resourcemanager.organizationViewer (or roles/resourcemanager.viewer)
"""

import os
import logging
from typing import Optional, Tuple, Dict, Any

import google.auth
from google.auth.credentials import Credentials
from google.oauth2 import service_account
from google.auth.transport.requests import AuthorizedSession

logger = logging.getLogger(__name__)

# Standard cloud platform scope required for all GCP REST and gRPC API interactions
GCP_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class GCPAuthManager:
    """Manages GCP credentials and authorized HTTP sessions for discovery queries."""

    def __init__(self, key_file_path: Optional[str] = None):
        """
        Initialize the GCP Authentication Manager.

        Args:
            key_file_path: Optional path to a service account JSON credentials key file.
                           If None, Application Default Credentials (ADC) will be used.
        """
        self.key_file_path = key_file_path
        self._credentials: Optional[Credentials] = None
        self._project_id: Optional[str] = None
        self._session: Optional[AuthorizedSession] = None
        self._identity_info: Dict[str, Any] = {}

    def get_credentials(self) -> Credentials:
        """
        Retrieve valid Google Cloud credentials (ADC or Service Account file).

        Returns:
            google.auth.credentials.Credentials object with cloud-platform scope.

        Raises:
            google.auth.exceptions.DefaultCredentialsError if credentials cannot be resolved.
        """
        if self._credentials is not None:
            return self._credentials

        if self.key_file_path and os.path.exists(self.key_file_path):
            logger.info("Authenticating using Service Account key file: %s", self.key_file_path)
            self._credentials = service_account.Credentials.from_service_account_file(
                self.key_file_path,
                scopes=GCP_SCOPES
            )
            # Try to read the service account email
            try:
                self._identity_info["service_account_email"] = self._credentials.service_account_email
                self._identity_info["auth_type"] = "Service Account Key"
            except Exception:
                pass
        else:
            logger.info("Authenticating using Google Application Default Credentials (ADC)...")
            self._credentials, self._project_id = google.auth.default(scopes=GCP_SCOPES)
            self._identity_info["auth_type"] = "Application Default Credentials (ADC)"
            if self._project_id:
                self._identity_info["default_project"] = self._project_id

        return self._credentials

    def get_authorized_session(self) -> AuthorizedSession:
        """
        Get an authenticated requests.Session for executing direct Google Cloud REST API calls.

        Direct REST sessions provide reliable, granular control over endpoints,
        error codes (e.g. 403 Forbidden vs 404 Not Found), and pagination across
        all GCP security APIs.

        Returns:
            AuthorizedSession configured with active credentials.
        """
        if self._session is not None:
            return self._session

        creds = self.get_credentials()
        self._session = AuthorizedSession(creds)
        return self._session

    def get_caller_identity(self) -> Dict[str, Any]:
        """
        Inspect the authenticated identity (User or Service Account) to include in discovery metadata.

        Returns:
            Dict containing caller identity details (email, type, project).
        """
        if self._identity_info.get("email"):
            return self._identity_info

        try:
            session = self.get_authorized_session()
            # Query Google OAuth2 TokenInfo endpoint to discover caller email
            resp = session.get("https://www.googleapis.com/oauth2/v1/userinfo", timeout=5)
            if resp.status_code == 200:
                user_info = resp.json()
                self._identity_info["email"] = user_info.get("email", "Unknown")
                self._identity_info["verified_email"] = user_info.get("verified_email", False)
        except Exception as e:
            logger.debug("Could not query userinfo endpoint: %s", e)
            if "service_account_email" in self._identity_info:
                self._identity_info["email"] = self._identity_info["service_account_email"]
            else:
                self._identity_info["email"] = "ADC Authenticated Principal"

        return self._identity_info
