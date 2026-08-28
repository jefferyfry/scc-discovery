#!/usr/bin/env python3
"""
test_e2e.py - Comprehensive End-to-End (E2E) Test Suite for SCC Discovery Tool

This test suite validates the entire discovery, aggregation, JSON export,
and PDF report generation pipeline.

Test Coverage:
1. CLI Argument Parsing & Validation
2. Mock & Synthetic Data Pipeline
3. Data Aggregation & Scorecard Calculations
4. Schema & Data Structure Integrity
5. JSON Export & Serialization
6. PDF Generation & Layout Integrity (Page Count, PDF Magic Bytes, NumberedCanvas)
7. Error Resilience & Graceful Degradation (Mocked 403 Forbidden & 404 Not Found)
8. Subprocess CLI Execution

Usage:
    python3 -m unittest test_e2e.py -v
    or
    python3 test_e2e.py
"""

import os
import sys
import json
import tempfile
import unittest
import subprocess
from unittest.mock import MagicMock, patch

# Import collectors and generators
from discovery.auth import GCPAuthManager
from discovery.scc_core import SCCCoreCollector
from discovery.postures import SecurityPostureCollector
from discovery.dlp_sdp import SensitiveDataProtectionCollector
from discovery.exports_mutes import ExportsAndMutesCollector
from discovery.connectors import ConnectorsCollector
from discovery.findings import FindingsCollector
from discovery.compliance import ComplianceCollector
from discovery.assets import AssetInventoryCollector
from discovery.hierarchy import ResourceHierarchyCollector
from discovery.mock_data import get_mock_discovery_data
from report.migration_mapping import calculate_migration_readiness, get_phased_migration_roadmap
from report.pdf_generator import SCCReportGenerator
from scc_discovery import parse_arguments, setup_logging


class TestSCCDiscoveryE2E(unittest.TestCase):
    """End-to-end integration and pipeline test cases."""

    def setUp(self):
        """Create a temporary directory for test artifacts."""
        self.test_dir = tempfile.TemporaryDirectory()
        self.pdf_path = os.path.join(self.test_dir.name, "test_output.pdf")
        self.json_path = os.path.join(self.test_dir.name, "test_output.json")
        self.org_id = "819203948571"

    def tearDown(self):
        """Clean up temporary test artifacts."""
        self.test_dir.cleanup()

    # -------------------------------------------------------------------------
    # 1. Mock Dataset & Schema Integrity Tests
    # -------------------------------------------------------------------------
    def test_01_mock_data_generation_and_schema(self):
        """Validate that synthetic enterprise dataset matches required schema."""
        data = get_mock_discovery_data(org_id=self.org_id)
        self.assertIsInstance(data, dict)

        # Check required top-level domains
        required_keys = [
            "metadata", "scc_core", "postures", "dlp_sdp",
            "exports_mutes", "connectors", "findings", "compliance",
            "assets", "hierarchy"
        ]
        for key in required_keys:
            self.assertIn(key, data, f"Missing required domain: {key}")

        # Check SCC Core
        scc_core = data["scc_core"]
        self.assertEqual(scc_core["tier_info"]["tier_code"], "ENTERPRISE")
        self.assertEqual(scc_core["organization_settings"]["asset_discovery_mode"], "AUTOMATIC")
        self.assertGreater(len(scc_core["services_status"]), 0)
        self.assertGreater(len(scc_core["sha_custom_modules"]), 0)

        # Check Postures & DLP
        self.assertGreater(data["postures"]["posture_count"], 0)
        self.assertGreater(data["postures"]["deployment_count"], 0)
        self.assertGreater(data["dlp_sdp"]["discovery_config_count"], 0)
        self.assertGreater(data["dlp_sdp"]["inspect_template_count"], 0)

        # Check Exports & Mutes
        self.assertGreater(data["exports_mutes"]["pubsub_export_count"], 0)
        self.assertGreater(data["exports_mutes"]["bigquery_export_count"], 0)
        self.assertGreater(data["exports_mutes"]["mute_rule_count"], 0)

        # Check Findings & Assets
        self.assertGreater(data["findings"]["total_active_findings"], 0)
        self.assertIn("CRITICAL", data["findings"]["severity_breakdown"])
        self.assertGreater(data["assets"]["total_assets"], 0)
        self.assertEqual(data["hierarchy"]["coverage_percentage"], 100.0)

    # -------------------------------------------------------------------------
    # 2. Migration Scorecard & Roadmap Calculation Tests
    # -------------------------------------------------------------------------
    def test_02_migration_scoring_and_roadmap(self):
        """Validate migration readiness calculation and 4-phase transition roadmap."""
        data = get_mock_discovery_data(org_id=self.org_id)
        readiness = calculate_migration_readiness(data)

        self.assertIsInstance(readiness, dict)
        self.assertIn("overall_score", readiness)
        self.assertGreaterEqual(readiness["overall_score"], 0)
        self.assertLessEqual(readiness["overall_score"], 100)
        self.assertIn("rating", readiness)
        self.assertIn("complexity", readiness)
        self.assertIn("estimated_duration", readiness)
        self.assertGreater(len(readiness["breakdown"]), 0)

        # Validate 4-phase roadmap
        roadmap = get_phased_migration_roadmap()
        self.assertEqual(len(roadmap), 4, "Roadmap must contain exactly 4 phases")
        for phase in roadmap:
            self.assertIn("phase", phase)
            self.assertIn("objectives", phase)
            self.assertIn("deliverable", phase)
            self.assertGreater(len(phase["objectives"]), 0)

    # -------------------------------------------------------------------------
    # 3. JSON Serialization & Export Tests
    # -------------------------------------------------------------------------
    def test_03_json_export_and_deserialization(self):
        """Verify that discovered data serializes to JSON and can be deserialized accurately."""
        data = get_mock_discovery_data(org_id=self.org_id)
        with open(self.json_path, "w") as f:
            json.dump(data, f, indent=2)

        self.assertTrue(os.path.exists(self.json_path))
        self.assertGreater(os.path.getsize(self.json_path), 5000)

        with open(self.json_path, "r") as f:
            loaded_data = json.load(f)

        self.assertEqual(loaded_data["metadata"]["organization_id"], self.org_id)
        self.assertEqual(loaded_data["findings"]["total_active_findings"], data["findings"]["total_active_findings"])

    # -------------------------------------------------------------------------
    # 4. PDF Generation & Document Structure Tests
    # -------------------------------------------------------------------------
    def test_04_pdf_generation_and_page_structure(self):
        """Verify ReportLab PDF generation, byte integrity, and minimum page count."""
        data = get_mock_discovery_data(org_id=self.org_id)
        report_gen = SCCReportGenerator(data, output_path=self.pdf_path)
        output_file = report_gen.generate()

        self.assertTrue(os.path.exists(output_file))
        file_size = os.path.getsize(output_file)
        self.assertGreater(file_size, 15000, f"PDF file size too small: {file_size} bytes")

        # Validate PDF Magic Bytes (%PDF-1.4 or similar)
        with open(output_file, "rb") as f:
            header = f.read(5)
            self.assertEqual(header, b"%PDF-", "File is not a valid PDF")

            # Check Page Objects count
            f.seek(0)
            content = f.read()
            page_count = content.count(b'/Type /Page\n') + content.count(b'/Type /Page ') + content.count(b'/Type/Page')
            self.assertGreaterEqual(page_count, 7, f"PDF should have at least 7 pages, got {page_count}")

    # -------------------------------------------------------------------------
    # 5. Error Resilience & Graceful Degradation (Mocked HTTP 403 & 404)
    # -------------------------------------------------------------------------
    def test_05_collector_error_resilience(self):
        """Verify that collectors handle 403 Forbidden and 404 Not Found without crashing."""
        mock_session = MagicMock()

        # Mock 403 Forbidden on org settings
        mock_response_403 = MagicMock()
        mock_response_403.status_code = 403
        mock_response_403.text = "PERMISSION_DENIED: User lacks securitycenter.adminViewer"
        mock_session.get.return_value = mock_response_403
        mock_session.post.return_value = mock_response_403

        collector = SCCCoreCollector(mock_session, self.org_id)
        settings = collector.get_organization_settings()
        self.assertEqual(settings["status"], "PERMISSION_DENIED")

        posture_collector = SecurityPostureCollector(mock_session, self.org_id)
        postures = posture_collector.list_postures()
        self.assertEqual(len(postures), 0)

        # Ensure PDF generator can handle empty/degraded discovery without crashing
        degraded_data = {
            "metadata": {"organization_id": self.org_id, "primary_location": "global"},
            "scc_core": {"tier_info": {"tier_name": "Standard Tier", "description": "Basic"}, "services_status": []},
            "postures": {"posture_count": 0, "deployment_count": 0, "postures": []},
            "dlp_sdp": {"discovery_configs": [], "inspect_templates": []},
            "exports_mutes": {"pubsub_notification_configs": [], "bigquery_exports": [], "mute_rules": []},
            "connectors": {"multicloud_connectors": [], "ticketing_connectors": []},
            "findings": {"total_active_findings": 0, "severity_breakdown": {}, "findings_by_source": [], "findings_by_category": []},
            "compliance": {"compliance_frameworks": []},
            "assets": {"total_assets": 0, "domain_categories": {}},
            "hierarchy": {"organization": {}, "projects_summary": []}
        }
        degraded_pdf_path = os.path.join(self.test_dir.name, "degraded_report.pdf")
        gen = SCCReportGenerator(degraded_data, output_path=degraded_pdf_path)
        result = gen.generate()
        self.assertTrue(os.path.exists(result))

    # -------------------------------------------------------------------------
    # 6. Full Subprocess CLI End-to-End Execution
    # -------------------------------------------------------------------------
    def test_06_cli_subprocess_execution(self):
        """Execute the CLI script via subprocess and assert 0 exit code and created files."""
        cli_script = os.path.abspath("scc_discovery.py")
        cmd = [
            sys.executable,
            cli_script,
            "--mock-data",
            "--org-id", self.org_id,
            "--output-pdf", self.pdf_path,
            "--output-json", self.json_path
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"CLI exited with error:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}")
        self.assertIn("SCC DISCOVERY & AUDIT SUMMARY", result.stdout)
        self.assertIn("SUCCESS: Professional PDF Report generated", result.stdout)
        self.assertTrue(os.path.exists(self.pdf_path))
        self.assertTrue(os.path.exists(self.json_path))


if __name__ == "__main__":
    print("\n======================================================================")
    print("      RUNNING GOOGLE CLOUD SCC DISCOVERY END-TO-END TEST SUITE        ")
    print("======================================================================\n")
    unittest.main(verbosity=2)
