#!/usr/bin/env python3
"""
========================================================================================
Google Cloud Security Command Center (SCC) Discovery & Security Posture Assessor
========================================================================================

Description:
    This tool performs a comprehensive, read-only discovery audit of an existing Google
    Cloud Security Command Center (SCC) deployment. It extracts configuration metadata,
    security postures, data loss prevention (DLP) profiles, continuous exports, mute rules,
    connectors, active findings, compliance frameworks, and asset counts across Organization,
    Folder, or standalone Project scope.

    The discovered data is organized and exported into:
    1. An executive-ready, multi-page PDF report for cloud security assessment.
    2. An optional raw JSON dataset for programmatic integration or pipeline analysis.

Usage Examples:
    # 1. Run live discovery against a standalone Project (No Organization needed):
    python scc_discovery.py --project-id my-project-id --output-pdf project_report.pdf

    # 2. Run live discovery against a GCP Organization using Application Default Credentials:
    python scc_discovery.py --org-id 123456789012 --output-pdf scc_report.pdf

    # 3. Run with raw JSON export:
    python scc_discovery.py --project-id my-project-id --output-pdf scc_report.pdf --output-json scc_data.json

    # 4. Run in Demo / Offline mode (generates full report using realistic enterprise mock data):
    python scc_discovery.py --mock-data --output-pdf scc_demo_report.pdf

Prerequisites:
    Python 3.9+ with libraries installed from requirements.txt:
    pip install -r requirements.txt

Required Read-Only GCP IAM Roles (Assigned at Organization or Project level):
    - roles/securitycenter.adminViewer (or roles/securitycenter.viewer)
    - roles/securityposture.viewer (if evaluating Enterprise postures)
    - roles/dlp.reader
    - roles/cloudasset.viewer
    - roles/resourcemanager.organizationViewer (or roles/resourcemanager.viewer)

Author: Cloud Security Architecture Team
========================================================================================
"""

import os
import sys
import json
import argparse
import logging
from datetime import datetime
from typing import Dict, Any, Optional

# Discovery Collector Modules
from discovery.auth import GCPAuthManager
from discovery.scc_core import SCCCoreCollector, normalize_resource
from discovery.postures import SecurityPostureCollector
from discovery.dlp_sdp import SensitiveDataProtectionCollector
from discovery.exports_mutes import ExportsAndMutesCollector
from discovery.connectors import ConnectorsCollector
from discovery.findings import FindingsCollector
from discovery.compliance import ComplianceCollector
from discovery.assets import AssetInventoryCollector
from discovery.hierarchy import ResourceHierarchyCollector
from discovery.mock_data import get_mock_discovery_data

# Reporting Modules
from report.migration_mapping import calculate_migration_readiness
from report.pdf_generator import SCCReportGenerator


def setup_logging(verbose: bool = False) -> None:
    """Configure terminal logging formatting."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )


def print_banner() -> None:
    """Print CLI header banner."""
    banner = """
====================================================================================
  Google Cloud SCC Discovery & Security Posture Assessment Tool
====================================================================================
"""
    print(banner)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Audit Google Cloud SCC configuration and produce a Security Posture & Architecture PDF report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standalone Project Audit (No Organization node required):
  python scc_discovery.py --project-id my-project-id --output-pdf project_report.pdf

  # Organization-Wide Audit:
  python scc_discovery.py --org-id 123456789012 --output-pdf org_report.pdf

  # Offline Demo Mode:
  python scc_discovery.py --mock-data --output-pdf demo_report.pdf --output-json demo_data.json
        """
    )

    parser.add_argument(
        "--project-id",
        type=str,
        default=None,
        help="GCP Project ID to audit a standalone or project-level SCC instance (e.g. 'my-security-project')."
    )
    parser.add_argument(
        "--org-id",
        type=str,
        default=None,
        help="GCP Organization ID for organization-wide discovery (e.g. '123456789012' or 'organizations/123456789012')."
    )
    parser.add_argument(
        "--folder-id",
        type=str,
        default=None,
        help="Optional GCP Folder ID to scope discovery to a specific folder hierarchy (e.g. '9876543210')."
    )
    parser.add_argument(
        "--location",
        type=str,
        default="global",
        help="SCC / Posture / DLP location endpoint (default: 'global')."
    )
    parser.add_argument(
        "--credentials", "--service-account-key",
        dest="credentials",
        type=str,
        default=None,
        help="Path to optional GCP Service Account JSON credentials key file."
    )
    parser.add_argument(
        "--output-pdf",
        type=str,
        default="scc_discovery_report.pdf",
        help="Path for generated PDF report (default: 'scc_discovery_report.pdf')."
    )
    parser.add_argument(
        "--output-json",
        type=str,
        default=None,
        help="Optional path to export raw discovery dataset as a JSON file."
    )
    parser.add_argument(
        "--mock-data", "--demo",
        dest="mock_data",
        action="store_true",
        help="Run discovery in demo mode using a comprehensive synthetic enterprise dataset."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging."
    )

    return parser.parse_args()


def resolve_target_resource(args: argparse.Namespace) -> str:
    """Determine the canonical resource target from CLI arguments."""
    if args.project_id:
        return f"projects/{args.project_id.replace('projects/', '')}"
    elif args.folder_id:
        return f"folders/{args.folder_id.replace('folders/', '')}"
    elif args.org_id:
        return f"organizations/{args.org_id.replace('organizations/', '')}"
    return "organizations/819203948571"


def run_live_discovery(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Execute live GCP read-only API discovery across all SCC and security domains.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Consolidated dictionary of all discovered security configurations.
    """
    logger = logging.getLogger(__name__)

    if not (args.org_id or args.project_id or args.folder_id):
        print("[!] ERROR: You must specify a target scope using --project-id, --org-id, or --folder-id (or use --mock-data for demo mode).")
        print("\n    Examples:")
        print("      python scc_discovery.py --project-id my-project-id --output-pdf project_report.pdf")
        print("      python scc_discovery.py --org-id 123456789012 --output-pdf scc_report.pdf")
        print("      python scc_discovery.py --folder-id 9876543210 --output-pdf folder_report.pdf")
        sys.exit(1)

    target_resource = resolve_target_resource(args)
    parent_name, raw_id, scope_type = normalize_resource(target_resource)

    print(f"[*] Initializing GCP Authentication for {scope_type.capitalize()} Scope: {parent_name}...")
    auth_mgr = GCPAuthManager(key_file_path=args.credentials)
    session = auth_mgr.get_authorized_session()
    caller_info = auth_mgr.get_caller_identity()
    print(f"    Authenticated as: {caller_info.get('email', 'GCP Identity')}")

    discovery_data: Dict[str, Any] = {
        "metadata": {
            "mode": f"LIVE GCP DISCOVERY ({scope_type.capitalize()} Scope)",
            "organization_id": raw_id,
            "organization_name": parent_name,
            "scope_type": scope_type,
            "caller_identity": caller_info.get("email", "Unknown"),
            "discovery_timestamp": datetime.utcnow().isoformat() + "Z",
            "primary_location": args.location,
        }
    }

    # 1. Core SCC Configuration & Tier
    print(f"[*] 1/8 Querying SCC Core Settings, Tier & Built-in Services ({scope_type.capitalize()} Scope)...")
    scc_collector = SCCCoreCollector(session, parent_name, location=args.location)
    discovery_data["scc_core"] = scc_collector.collect_all()
    source_lookup = {
        s["source_id"]: s["display_name"]
        for s in discovery_data["scc_core"].get("integrated_sources", [])
    }

    # 2. Security Posture Management & Deployments
    print("[*] 2/8 Querying Security Postures, Deployments & Templates...")
    posture_collector = SecurityPostureCollector(session, parent_name, location=args.location)
    discovery_data["postures"] = posture_collector.collect_all()

    # 3. Sensitive Data Protection (DLP)
    print("[*] 3/8 Querying Sensitive Data Protection (Cloud DLP) Configs...")
    dlp_collector = SensitiveDataProtectionCollector(session, parent_name, location=args.location)
    discovery_data["dlp_sdp"] = dlp_collector.collect_all()

    # 4. Continuous Exports & Mute Rules
    print("[*] 4/8 Querying Continuous Exports (Pub/Sub, BigQuery) & Mute Rules...")
    exp_collector = ExportsAndMutesCollector(session, parent_name, location=args.location)
    discovery_data["exports_mutes"] = exp_collector.collect_all()

    # 5. Connectors & Integrations
    print("[*] 5/8 Discovering Connectors (Multi-Cloud, Ticketing, SIEM)...")
    conn_collector = ConnectorsCollector(session, parent_name, location=args.location)
    discovery_data["connectors"] = conn_collector.collect_all(
        registered_sources=discovery_data["scc_core"].get("integrated_sources", [])
    )

    # 6. Active Findings Aggregation
    print("[*] 6/8 Aggregating Active Findings by Source, Category & Severity...")
    findings_collector = FindingsCollector(session, parent_name)
    discovery_data["findings"] = findings_collector.collect_all(source_lookup=source_lookup)

    # 7. Compliance Frameworks & Benchmarks
    print("[*] 7/8 Evaluating Enabled Compliance Frameworks (CIS, NIST, PCI, ISO)...")
    comp_collector = ComplianceCollector(session, parent_name)
    discovery_data["compliance"] = comp_collector.collect_all(postures_data=discovery_data["postures"])

    # 8. Asset Inventory & Hierarchy Coverage
    print("[*] 8/8 Inspecting Cloud Asset Inventory & Resource Hierarchy...")
    asset_collector = AssetInventoryCollector(session, parent_name)
    discovery_data["assets"] = asset_collector.collect_all()

    hier_collector = ResourceHierarchyCollector(session, parent_name)
    discovery_data["hierarchy"] = hier_collector.collect_all()

    print("[+] Discovery data successfully gathered from all Google Cloud endpoints.")
    return discovery_data


def print_summary_table(discovery_data: Dict[str, Any]) -> None:
    """Print terminal summary table after discovery completion."""
    scc_core = discovery_data.get("scc_core", {})
    tier_info = scc_core.get("tier_info", {})
    postures = discovery_data.get("postures", {})
    dlp_data = discovery_data.get("dlp_sdp", {})
    exports = discovery_data.get("exports_mutes", {})
    connectors = discovery_data.get("connectors", {})
    findings = discovery_data.get("findings", {})
    compliance = discovery_data.get("compliance", {})
    assets = discovery_data.get("assets", {})
    hierarchy = discovery_data.get("hierarchy", {})

    readiness = calculate_migration_readiness(discovery_data)

    print("\n" + "=" * 84)
    print("                      SCC DISCOVERY & AUDIT SUMMARY")
    print("=" * 84)
    print(f"  Target Resource:         {discovery_data.get('metadata', {}).get('organization_name', 'Unknown')}")
    print(f"  SCC Version / Tier:      {tier_info.get('tier_name', 'Enterprise Tier')}")
    print(f"  Asset Discovery Mode:    {scc_core.get('organization_settings', {}).get('asset_discovery_mode', 'AUTOMATIC')}")
    print(f"  Hierarchy Scope:         {hierarchy.get('project_count', 0)} Project(s) across {hierarchy.get('folder_count', 0)} Folder(s)")
    print(f"  Total Cloud Assets:      {assets.get('total_assets', 0):,} assets ({assets.get('asset_types_count', 0)} resource types)")
    print(f"  Active Findings:         {findings.get('total_active_findings', 0):,} ({findings.get('severity_breakdown', {}).get('CRITICAL', 0)} Critical, {findings.get('severity_breakdown', {}).get('HIGH', 0)} High)")
    print(f"  Security Postures:       {postures.get('posture_count', 0)} Active ({postures.get('deployment_count', 0)} Deployments)")
    print(f"  Sensitive Data (DLP):    {dlp_data.get('discovery_config_count', 0)} Profiling Configs, {dlp_data.get('inspect_template_count', 0)} Inspect Templates")
    print(f"  Continuous Exports:      {exports.get('pubsub_export_count', 0)} Pub/Sub Topics, {exports.get('bigquery_export_count', 0)} BigQuery Streams")
    print(f"  Finding Mute Rules:      {exports.get('mute_rule_count', 0)} Active Suppression Rules")
    print(f"  Connectors:              {connectors.get('multicloud_count', 0)} Multi-Cloud, {connectors.get('ticketing_count', 0)} Ticketing / SIEM")
    print(f"  Compliance Frameworks:   {compliance.get('enabled_frameworks_count', 0)} Active (CIS GCP, NIST 800-53, PCI-DSS, ISO 27001)")
    print("-" * 84)
    print(f"  Migration Readiness:     {readiness.get('overall_score')}/100 - {readiness.get('rating')}")
    print(f"  Estimated Transition:    {readiness.get('estimated_duration')} ({readiness.get('complexity')} Complexity)")
    print("=" * 84 + "\n")


def main() -> None:
    """Main CLI execution routine."""
    print_banner()
    args = parse_arguments()
    setup_logging(args.verbose)

    # 1. Gather Discovery Data
    if args.mock_data:
        print("[*] Running in DEMO / MOCK DATA mode (High-fidelity enterprise dataset)...")
        target_resource = resolve_target_resource(args)
        discovery_data = get_mock_discovery_data(resource_id=target_resource)
    else:
        discovery_data = run_live_discovery(args)

    # 2. Print Terminal Summary
    print_summary_table(discovery_data)

    # 3. Export Raw JSON (if requested)
    if args.output_json:
        print(f"[*] Exporting raw discovery JSON to: {args.output_json}...")
        try:
            with open(args.output_json, "w") as f:
                json.dump(discovery_data, f, indent=2)
            print(f"[+] Raw discovery JSON written to: {os.path.abspath(args.output_json)}")
        except Exception as e:
            print(f"[!] Error writing JSON output: {e}")

    # 4. Generate PDF Report
    print(f"[*] Generating PDF Assessment Report at: {args.output_pdf}...")
    try:
        report_gen = SCCReportGenerator(discovery_data, output_path=args.output_pdf)
        pdf_path = report_gen.generate()
        print(f"\n[+] SUCCESS: Professional PDF Report generated at:")
        print(f"    {pdf_path}\n")
    except Exception as e:
        logging.exception("Error during PDF report generation")
        print(f"[!] ERROR generating PDF report: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
