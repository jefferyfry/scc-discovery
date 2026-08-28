"""
report/migration_mapping.py - Cloud Security Platform Migration Taxonomy & Capability Assessment

This module provides:
1. Direct feature-by-feature translation matrix from SCC to modern Cloud Security capabilities (CSPM, CWPP, CDR, DSPM, CIEM).
2. Architecture mapping for Cloud Detection & Response (CDR), Workload Protection, Posture Management, and Data Security.
3. Translation guides for Mute Rules -> Exception Policies and Continuous Exports -> Event Stream Forwarders.
4. Security Migration Readiness Scoring algorithm.
5. Step-by-step phased transition roadmap for cloud security platform migration.
"""

from typing import Dict, Any, List


# Comprehensive feature mapping matrix
MAPPING_TAXONOMY = [
    {
        "domain": "Cloud Detection & Response (CDR)",
        "scc_feature": "Event Threat Detection (ETD)",
        "scc_details": "Analyzes Cloud Audit, VPC Flow, and DNS logs via streaming analytics.",
        "target_component": "Cloud Events Ingestion & Behavioral CDR",
        "target_capability": "Real-time threat detection analyzing cloud audit trails, IAM anomalies, and network traffic correlated against the security graph.",
        "migration_action": "Enable Cloud Events log streams on GCP Organization; configure CDR alert rules and threat policies."
    },
    {
        "domain": "Cloud Workload Protection (CWPP)",
        "scc_feature": "Container Threat Detection (CTD)",
        "scc_details": "Monitors GKE container execution anomalies, reverse shells, and malicious binaries.",
        "target_component": "Runtime Security Sensor & K8s Admission Control",
        "target_capability": "eBPF-powered real-time container runtime security, process monitoring, file integrity monitoring, and K8s admission control.",
        "migration_action": "Deploy runtime DaemonSet onto GKE clusters using Helm / Terraform."
    },
    {
        "domain": "Cloud Workload Protection (CWPP)",
        "scc_feature": "VM Threat Detection (VMTD)",
        "scc_details": "Hypervisor-level memory scanning for crypto-miners and kernel rootkits on GCE.",
        "target_component": "Agentless VM Disk Scanning & Runtime Behavioral Sensor",
        "target_capability": "Zero-impact agentless VM snapshot scanning paired with lightweight runtime sensor for live behavioral detection.",
        "migration_action": "Grant Agentless Disk Snapshot permissions and deploy runtime sensors to high-criticality VMs."
    },
    {
        "domain": "Cloud Security Posture (CSPM)",
        "scc_feature": "Security Health Analytics (SHA)",
        "scc_details": "Scans GCP resource configurations for CIS benchmarks and security violations.",
        "target_component": "Cloud Security Posture Management & Security Graph",
        "target_capability": "Agentless cloud configuration analysis, deep toxic combination path analysis, and graph-based misconfiguration hunting.",
        "migration_action": "Connect GCP Organization via read-only service account; map SHA custom rules to custom posture controls."
    },
    {
        "domain": "Data Security Posture (DSPM)",
        "scc_feature": "Sensitive Data Protection (Cloud DLP)",
        "scc_details": "Continuous data profiling and inspect templates for BigQuery, GCS, and Cloud SQL.",
        "target_component": "Data Security Posture Management (DSPM) & Classifiers",
        "target_capability": "Automated discovery of sensitive data (PII, PCI, secrets, PHI) across buckets, databases, and disks correlated with exposure paths.",
        "migration_action": "Enable DSPM profiling on GCS buckets and BigQuery datasets; convert custom DLP infoTypes to data classifiers."
    },
    {
        "domain": "Vulnerability Management",
        "scc_feature": "Rapid Vulnerability Detection & WSS",
        "scc_details": "Scans public endpoints for zero-days and crawls web apps for OWASP vulnerabilities.",
        "target_component": "Vulnerability Management & External Attack Surface",
        "target_capability": "Agentless OS, package, and container image vulnerability assessment correlated with network reachability and exploit availability.",
        "migration_action": "Automatically inventory and prioritize CVEs across all GCP workloads without active scanning probes."
    },
    {
        "domain": "Governance & Compliance",
        "scc_feature": "Security Posture Management & Frameworks",
        "scc_details": "Posture definitions, policy deployments, and CIS/NIST/PCI compliance benchmarks.",
        "target_component": "Compliance Frameworks & Security Graph Policies",
        "target_capability": "Support for regulatory frameworks (CIS, NIST, PCI-DSS, ISO 27001, SOC 2, HIPAA, FedRAMP) with 1-click audit reports.",
        "migration_action": "Enable matching compliance frameworks; assign scope to GCP Projects and multi-cloud accounts."
    },
    {
        "domain": "Exception Management",
        "scc_feature": "Finding Mute Rules",
        "scc_details": "CEL expression-based suppression rules to silence acceptable findings.",
        "target_component": "Exception Rules & Business Waivers",
        "target_capability": "Context-aware exception management with expiration dates, business justification tracking, and ticket cross-referencing.",
        "migration_action": "Export SCC mute rules; recreate as scoped exception rules with owner attribution and review dates."
    },
    {
        "domain": "Alerting & Integrations",
        "scc_feature": "Continuous Exports (Pub/Sub & BigQuery)",
        "scc_details": "Streams findings to Pub/Sub topics for Jira, ServiceNow, and SIEM.",
        "target_component": "Integrations, Automation Actions & SIEM Forwarder",
        "target_capability": "Native bi-directional Jira/ServiceNow integrations, Webhook triggers, and streaming export to Splunk, Chronicle, Sentinel, and S3/GCS.",
        "migration_action": "Configure native integrations for Jira, ServiceNow, and SIEM using API tokens and webhooks."
    }
]


def calculate_migration_readiness(discovery_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate an overall cloud security migration readiness score and complexity assessment.

    Scoring Factors:
    - Organization Coverage (Max 25 pts): 100% org-wide coverage simplifies cloud connector setup.
    - Posture & Compliance Complexity (Max 20 pts): Standard frameworks are directly supported.
    - Custom Detection Rules (Max 15 pts): Volume of custom SHA/ETD modules to translate.
    - Data Protection (DSPM) Setup (Max 15 pts): DLP templates ready for data classifier mapping.
    - Integrations & Pipelines (Max 15 pts): Pub/Sub & BigQuery exports mapped to automation triggers.
    - Mute Rules Clarity (Max 10 pts): Mute rule volume and condition complexity.
    """
    score = 0
    breakdown = []

    # 1. Organization Coverage
    hierarchy = discovery_data.get("hierarchy", {})
    coverage_pct = hierarchy.get("coverage_percentage", 100.0)
    cov_score = int((coverage_pct / 100.0) * 25)
    score += cov_score
    breakdown.append({
        "category": "Organization Hierarchy & Coverage",
        "score": cov_score,
        "max_score": 25,
        "status": "EXCELLENT" if cov_score >= 20 else "GOOD",
        "details": f"{coverage_pct}% hierarchy coverage across {hierarchy.get('project_count', 0)} projects."
    })

    # 2. Compliance Frameworks
    compliance = discovery_data.get("compliance", {})
    fw_count = compliance.get("enabled_frameworks_count", 0)
    fw_score = 20 if fw_count > 0 else 10
    score += fw_score
    breakdown.append({
        "category": "Compliance & Benchmark Alignment",
        "score": fw_score,
        "max_score": 20,
        "status": "EXCELLENT",
        "details": f"{fw_count} standard frameworks (CIS, NIST, PCI, ISO) have 100% native coverage in target platform."
    })

    # 3. Custom Modules Translation
    scc_core = discovery_data.get("scc_core", {})
    sha_custom = len(scc_core.get("sha_custom_modules", []))
    etd_custom = len(scc_core.get("etd_custom_modules", []))
    total_custom = sha_custom + etd_custom
    custom_score = 15 if total_custom <= 10 else 10
    score += custom_score
    breakdown.append({
        "category": "Custom Detection Rules Translation",
        "score": custom_score,
        "max_score": 15,
        "status": "LOW COMPLEXITY" if total_custom <= 10 else "MODERATE COMPLEXITY",
        "details": f"{total_custom} custom rules ({sha_custom} SHA, {etd_custom} ETD) identified for conversion to custom controls."
    })

    # 4. Sensitive Data Protection (DSPM)
    dlp_data = discovery_data.get("dlp_sdp", {})
    inspect_count = dlp_data.get("inspect_template_count", 0)
    dlp_score = 15 if inspect_count > 0 else 12
    score += dlp_score
    breakdown.append({
        "category": "Data Security Posture (DSPM)",
        "score": dlp_score,
        "max_score": 15,
        "status": "READY",
        "details": f"{inspect_count} DLP inspection templates and {dlp_data.get('discovery_config_count', 0)} profiling configs mapped to DSPM."
    })

    # 5. Alerting & Connectors
    exports = discovery_data.get("exports_mutes", {})
    conn_data = discovery_data.get("connectors", {})
    pubsub_cnt = exports.get("pubsub_export_count", 0)
    ticket_cnt = conn_data.get("ticketing_count", 0)
    int_score = 15 if (pubsub_cnt > 0 or ticket_cnt > 0) else 10
    score += int_score
    breakdown.append({
        "category": "Alerting & Ticketing Automation",
        "score": int_score,
        "max_score": 15,
        "status": "READY",
        "details": f"{pubsub_cnt} continuous export pipelines and {ticket_cnt} ticketing systems directly supported via native integrations."
    })

    # 6. Mute Rules Migration
    mute_count = exports.get("mute_rule_count", 0)
    mute_score = 10 if mute_count <= 10 else 7
    score += mute_score
    breakdown.append({
        "category": "Mute Rules & Exception Policy Porting",
        "score": mute_score,
        "max_score": 10,
        "status": "READY",
        "details": f"{mute_count} mute rules documented and ready for migration to target exception rules."
    })

    # Overall classification
    if score >= 85:
        rating = "HIGH READINESS (Rapid Turnkey Migration)"
        complexity = "LOW TO MODERATE"
        est_weeks = "2 - 4 Weeks"
    elif score >= 70:
        rating = "MODERATE READINESS"
        complexity = "MODERATE"
        est_weeks = "4 - 6 Weeks"
    else:
        rating = "COMPLEX MIGRATION"
        complexity = "HIGH"
        est_weeks = "6 - 8 Weeks"

    return {
        "overall_score": score,
        "rating": rating,
        "complexity": complexity,
        "estimated_duration": est_weeks,
        "breakdown": breakdown
    }


def get_phased_migration_roadmap() -> List[Dict[str, Any]]:
    """
    Return the standard 4-phase migration execution plan for cloud security platform migration.
    """
    return [
        {
            "phase": "Phase 1: Foundation & Cloud Connector Setup (Week 1)",
            "objectives": [
                "Establish target cloud security platform tenant and configure SSO / SAML integration.",
                "Deploy GCP Organization Connector using Terraform / gcloud (read-only IAM role).",
                "Validate full GCP resource inventory discovery against SCC asset counts.",
                "Enable Cloud Events log stream ingestion for GCP Audit & VPC Flow logs (CDR)."
            ],
            "deliverable": "Complete asset visibility in cloud security graph with zero disruption to active workloads."
        },
        {
            "phase": "Phase 2: Baseline Parity & Workload Protection Deployment (Weeks 2-3)",
            "objectives": [
                "Deploy Runtime Security Sensors onto GKE clusters via Helm.",
                "Enable Agentless Disk Scanning across GCP Compute Engine VMs.",
                "Activate core compliance frameworks (CIS GCP Foundations v2.0, NIST 800-53, PCI-DSS).",
                "Recreate custom SHA/ETD detection modules as custom security posture controls.",
                "Port documented SCC Mute Rules into exception policies with business owners and TTLs.",
                "Enable DSPM data classification on critical BigQuery datasets and GCS buckets."
            ],
            "deliverable": "Target security platform actively monitoring runtime workloads and posture in parallel with SCC."
        },
        {
            "phase": "Phase 3: Operational Cutover & Automation Integration (Weeks 3-4)",
            "objectives": [
                "Configure native integrations for Jira, ServiceNow, and SIEM / SecOps tools.",
                "Establish automated alert routing actions to send Critical/High alerts to SecOps on-call.",
                "Conduct dual-run verification comparing SCC findings with correlated target security alerts.",
                "Train SOC analysts and cloud engineering teams on alert triage and investigation workflows."
            ],
            "deliverable": "SecOps team actively triaging and remediating alerts through target cloud security platform."
        },
        {
            "phase": "Phase 4: SCC Decommissioning & Optimization (Week 4+)",
            "objectives": [
                "Disable legacy continuous export Pub/Sub topics and BigQuery streaming sinks.",
                "Downgrade or disable SCC Enterprise/Premium tier licenses in Google Cloud Console.",
                "Review correlated risk paths and establish automated remediation workflows.",
                "Generate executive compliance and security posture reports directly from target platform."
            ],
            "deliverable": "Streamlined single-pane-of-glass security operations with reduced GCP licensing overhead."
        }
    ]
