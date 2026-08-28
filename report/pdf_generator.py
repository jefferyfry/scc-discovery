"""
report/pdf_generator.py - Multi-Page Executive PDF Report Generator

This module transforms the raw SCC discovery and security posture dataset into an
executive-ready, multi-page PDF assessment report.

Design Specifications:
- 8 Distinct Pages / Sections
- Professional Enterprise Color Palette (Navy #0F172A, Slate #334155, Cyan #0284C7, Emerald #16A34A, Amber #D97706, Crimson #DC2626)
- Dynamic Header / Footer with Two-Pass Page X of Y Numbering (NumberedCanvas)
- Metric Stat Cards, Badges, Scope Summary, and Responsive Tables
- Empty-state handlers for unconfigured or permission-restricted features
"""

import os
import logging
from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable, KeepTogether
)
from reportlab.pdfgen import canvas

from report.migration_mapping import calculate_migration_readiness, get_phased_migration_roadmap

logger = logging.getLogger(__name__)

# Enterprise Color Palette
NAVY_PRIMARY = colors.HexColor("#0F172A")     # Dark Slate/Navy
SLATE_SECONDARY = colors.HexColor("#334155")  # Deep Slate
CYAN_ACCENT = colors.HexColor("#0284C7")      # Vibrant Cyan
EMERALD_SUCCESS = colors.HexColor("#16A34A")  # Soft Green
AMBER_WARNING = colors.HexColor("#D97706")    # Amber Orange
CRIMSON_DANGER = colors.HexColor("#DC2626")   # Alert Red
BG_LIGHT = colors.HexColor("#F8FAFC")         # Ultra Light Gray/Blue
BG_ALT = colors.HexColor("#F1F5F9")           # Light Table Row Alternate
BORDER_COLOR = colors.HexColor("#CBD5E1")     # Clean Subtle Border
TEXT_DARK = colors.HexColor("#1E293B")
TEXT_MUTED = colors.HexColor("#64748B")


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to compute and render total page count dynamically.
    Renders top running header and bottom footer with 'Page X of Y'.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 7.5)
        self.setFillColor(TEXT_MUTED)

        # Draw Running Header (Pages 2+)
        if self._pageNumber > 1:
            self.drawString(36, 792 - 28, "Google Cloud SCC Discovery & Security Posture Assessment Report")
            self.setStrokeColor(BORDER_COLOR)
            self.setLineWidth(0.5)
            self.line(36, 792 - 32, 612 - 36, 792 - 32)

        # Draw Footer (All pages)
        self.setStrokeColor(BORDER_COLOR)
        self.setLineWidth(0.5)
        self.line(36, 38, 612 - 36, 38)
        self.drawString(36, 26, "CONFIDENTIAL - Cloud Security Discovery & Architecture Audit")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 36, 26, page_str)

        self.restoreState()


class SCCReportGenerator:
    """Builds and compiles the full PDF Discovery and Architecture Audit Report."""

    def __init__(self, discovery_data: Dict[str, Any], output_path: str = "scc_discovery_report.pdf"):
        """
        Initialize the Report Generator.

        Args:
            discovery_data: Dictionary produced by the SCC Discovery collectors.
            output_path: Target path for the output PDF file.
        """
        self.data = discovery_data
        self.output_path = output_path
        self.readiness = calculate_migration_readiness(discovery_data)
        self.styles = getSampleStyleSheet()
        self._init_custom_styles()

    def _init_custom_styles(self):
        """Register custom typography styles for headers, tables, callouts, and body."""
        self.styles.add(ParagraphStyle(
            'CoverTitle',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=24,
            leading=28,
            textColor=NAVY_PRIMARY,
            alignment=0,
            spaceAfter=8
        ))
        self.styles.add(ParagraphStyle(
            'CoverSubtitle',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=13,
            leading=17,
            textColor=CYAN_ACCENT,
            alignment=0,
            spaceAfter=15
        ))
        self.styles.add(ParagraphStyle(
            'SectionHeading',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=15,
            leading=19,
            textColor=NAVY_PRIMARY,
            spaceBefore=14,
            spaceAfter=6,
            keepWithNext=True
        ))
        self.styles.add(ParagraphStyle(
            'SubSectionHeading',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=10.5,
            leading=14,
            textColor=SLATE_SECONDARY,
            spaceBefore=8,
            spaceAfter=4,
            keepWithNext=True
        ))
        self.styles.add(ParagraphStyle(
            'BodyCustom',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=8.5,
            leading=12,
            textColor=TEXT_DARK,
            spaceAfter=4
        ))
        self.styles.add(ParagraphStyle(
            'BodyMuted',
            parent=self.styles['Normal'],
            fontName='Helvetica-Oblique',
            fontSize=8,
            leading=11,
            textColor=TEXT_MUTED
        ))
        self.styles.add(ParagraphStyle(
            'TableCell',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=7.5,
            leading=10,
            textColor=TEXT_DARK
        ))
        self.styles.add(ParagraphStyle(
            'TableCellBold',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7.5,
            leading=10,
            textColor=NAVY_PRIMARY
        ))
        self.styles.add(ParagraphStyle(
            'TableHead',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7.5,
            leading=10,
            textColor=colors.white
        ))
        self.styles.add(ParagraphStyle(
            'BadgeSuccess',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7.5,
            leading=9,
            textColor=EMERALD_SUCCESS
        ))
        self.styles.add(ParagraphStyle(
            'BadgeWarning',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7.5,
            leading=9,
            textColor=AMBER_WARNING
        ))
        self.styles.add(ParagraphStyle(
            'BadgeDanger',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7.5,
            leading=9,
            textColor=CRIMSON_DANGER
        ))
        self.styles.add(ParagraphStyle(
            'StatCardValue',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=15,
            leading=18,
            textColor=NAVY_PRIMARY,
            alignment=1
        ))
        self.styles.add(ParagraphStyle(
            'StatCardLabel',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=7.5,
            leading=9,
            textColor=TEXT_MUTED,
            alignment=1
        ))

    def generate(self) -> str:
        """
        Compile and write the PDF report to disk.

        Returns:
            Absolute path of generated PDF file.
        """
        logger.info("Generating PDF discovery report at: %s", self.output_path)
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=46,
            bottomMargin=46
        )

        story = []

        # 1. Cover Page & Executive Summary
        story.extend(self._build_cover_page())
        story.append(PageBreak())

        # 2. Executive Summary & Readiness Scorecard
        story.extend(self._build_executive_summary_section())
        story.append(PageBreak())

        # 3. SCC Tier, Setup Details & Built-in Services
        story.extend(self._build_scc_core_section())
        story.append(PageBreak())

        # 4. Security Postures & Sensitive Data Protection (DLP)
        story.extend(self._build_postures_and_dlp_section())
        story.append(PageBreak())

        # 5. Continuous Exports, Mute Rules & Connectors
        story.extend(self._build_exports_mutes_connectors_section())
        story.append(PageBreak())

        # 6. Findings Analysis & Compliance Frameworks
        story.extend(self._build_findings_and_compliance_section())
        story.append(PageBreak())

        # 7. Asset Inventory & Organization Coverage Hierarchy
        story.extend(self._build_assets_and_hierarchy_section())
        story.append(PageBreak())

        # 8. Migration Blueprint & Transition Roadmap
        story.extend(self._build_migration_blueprint_section())

        # Build document with custom canvas
        doc.build(story, canvasmaker=NumberedCanvas)
        logger.info("PDF Report successfully compiled: %s", self.output_path)
        return os.path.abspath(self.output_path)

    # -------------------------------------------------------------------------
    # Section Builders
    # -------------------------------------------------------------------------

    def _build_cover_page(self) -> List[Any]:
        """Construct the cover page with title, metadata box, and executive overview."""
        elements = []
        meta = self.data.get("metadata", {})
        scc_core = self.data.get("scc_core", {})
        tier_info = scc_core.get("tier_info", {})
        services = scc_core.get("services_status", [])
        sha_custom = scc_core.get("sha_custom_modules", [])
        etd_custom = scc_core.get("etd_custom_modules", [])
        postures = self.data.get("postures", {})
        dlp_data = self.data.get("dlp_sdp", {})
        exports = self.data.get("exports_mutes", {})
        findings = self.data.get("findings", {})
        compliance = self.data.get("compliance", {})
        assets = self.data.get("assets", {})
        hierarchy = self.data.get("hierarchy", {})
        org_details = hierarchy.get("organization", {})

        enabled_svc_count = len([s for s in services if s.get("enabled")])
        total_svc_count = len(services)
        custom_rules_total = len(sha_custom) + len(etd_custom)
        total_exports = exports.get('pubsub_export_count', 0) + exports.get('bigquery_export_count', 0)

        elements.append(Spacer(1, 20))
        elements.append(Paragraph("GOOGLE CLOUD SECURITY COMMAND CENTER (SCC)", self.styles['CoverSubtitle']))
        elements.append(Paragraph("Configuration Audit & Security Platform Assessment Report", self.styles['CoverTitle']))
        elements.append(HRFlowable(width="100%", thickness=3, color=CYAN_ACCENT, spaceBefore=4, spaceAfter=15))

        elements.append(Paragraph(
            "This discovery report provides a comprehensive, read-only audit of the Google Cloud Security Command Center (SCC) "
            "deployment across the environment. It captures version tiers, security postures, sensitive data protection (DLP) "
            "configurations, built-in/integrated services, continuous export pipelines, finding mute rules, connectors, active security "
            "findings, compliance frameworks, and asset inventory to formulate a seamless cloud security architecture and transition roadmap.",
            self.styles['BodyCustom']
        ))
        elements.append(Spacer(1, 15))

        # Metadata Table
        meta_table_data = [
            [
                Paragraph("<b>Target Resource:</b>", self.styles['TableCellBold']),
                Paragraph(str(meta.get("organization_name", meta.get("organization_id", "Unknown"))), self.styles['TableCell']),
                Paragraph("<b>Assessment Date:</b>", self.styles['TableCellBold']),
                Paragraph(datetime.now().strftime("%B %d, %Y"), self.styles['TableCell']),
            ],
            [
                Paragraph("<b>Scope Type:</b>", self.styles['TableCellBold']),
                Paragraph(str(meta.get("scope_type", "PROJECT")).capitalize() + " Scope", self.styles['TableCell']),
                Paragraph("<b>Auditor / Principal:</b>", self.styles['TableCellBold']),
                Paragraph(str(meta.get("caller_identity", "Security Administrator")), self.styles['TableCell']),
            ],
            [
                Paragraph("<b>SCC Version Tier:</b>", self.styles['TableCellBold']),
                Paragraph(f"<font color='#0284C7'><b>{tier_info.get('tier_name', 'Enterprise Tier')}</b></font>", self.styles['TableCell']),
                Paragraph("<b>Hierarchy Scope:</b>", self.styles['TableCellBold']),
                Paragraph(f"{hierarchy.get('project_count', 0)} Project(s) in {hierarchy.get('folder_count', 0)} Folder(s)", self.styles['TableCell']),
            ],
            [
                Paragraph("<b>Primary Location:</b>", self.styles['TableCellBold']),
                Paragraph(str(meta.get("primary_location", "global")), self.styles['TableCell']),
                Paragraph("<b>Migration Readiness:</b>", self.styles['TableCellBold']),
                Paragraph(f"<font color='#16A34A'><b>{self.readiness.get('overall_score')}/100 - {self.readiness.get('rating').split(' ')[0]}</b></font>", self.styles['TableCell']),
            ],
        ]

        t = Table(meta_table_data, colWidths=[1.4 * inch, 2.3 * inch, 1.4 * inch, 2.3 * inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 20))

        # Dynamic Scope Summary Box
        elements.append(Paragraph("Discovery Scope Summary", self.styles['SubSectionHeading']))
        scope_text = (
            f"• <b>Version & Scope:</b> Evaluated {tier_info.get('tier_name', 'SCC')}, {postures.get('posture_count', 0)} active postures, and {postures.get('deployment_count', 0)} posture deployments.<br/>"
            f"• <b>Security Services:</b> Evaluated {total_svc_count} built-in & integrated services ({enabled_svc_count} ENABLED, {total_svc_count - enabled_svc_count} DISABLED) and {custom_rules_total} custom detection rules.<br/>"
            f"• <b>Sensitive Data (DLP):</b> Audited {dlp_data.get('discovery_config_count', 0)} automated data profiling configs and {dlp_data.get('inspect_template_count', 0)} inspection templates.<br/>"
            f"• <b>Alerting & Exceptions:</b> Discovered {total_exports} continuous exports (BigQuery/PubSub) and {exports.get('mute_rule_count', 0)} active mute rules.<br/>"
            f"• <b>Findings & Assets:</b> Cataloged {findings.get('total_active_findings', 0):,} active findings, {compliance.get('enabled_frameworks_count', 0)} compliance frameworks, and {assets.get('total_assets', 0):,} cloud assets."
        )
        t_scope = Table([[Paragraph(scope_text, self.styles['BodyCustom'])]], colWidths=[7.4 * inch])
        t_scope.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), BG_ALT),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(t_scope)

        return elements

    def _build_executive_summary_section(self) -> List[Any]:
        """Build Executive Summary & Migration Readiness Scorecard."""
        elements = []
        elements.append(Paragraph("1. Executive Summary & Security Migration Scorecard", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=10))

        # 6 Stat Cards in a 2x3 Grid
        findings = self.data.get("findings", {})
        assets = self.data.get("assets", {})
        scc_core = self.data.get("scc_core", {})
        tier_info = scc_core.get("tier_info", {})
        postures = self.data.get("postures", {})
        sev = findings.get("severity_breakdown", {})

        stat_cards = [
            [
                self._create_stat_card("SCC VERSION TIER", tier_info.get("tier_name", "Enterprise Tier")),
                self._create_stat_card("TOTAL CLOUD ASSETS", f"{assets.get('total_assets', 0):,}"),
                self._create_stat_card("ACTIVE FINDINGS", f"{findings.get('total_active_findings', 0):,}"),
            ],
            [
                self._create_stat_card("CRITICAL / HIGH ISSUES", f"{sev.get('CRITICAL', 0) + sev.get('HIGH', 0):,}", color=CRIMSON_DANGER),
                self._create_stat_card("SECURITY POSTURES", f"{postures.get('posture_count', 0)} Active ({postures.get('deployment_count', 0)} Deployed)"),
                self._create_stat_card("MIGRATION READINESS", f"{self.readiness.get('overall_score')}/100", color=EMERALD_SUCCESS),
            ]
        ]
        t_cards = Table(stat_cards, colWidths=[2.46 * inch, 2.46 * inch, 2.46 * inch])
        t_cards.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_cards)
        elements.append(Spacer(1, 12))

        # Readiness Assessment Breakdown Table
        elements.append(Paragraph("Security Platform Migration Readiness Breakdown", self.styles['SubSectionHeading']))
        readiness_rows = [
            [
                Paragraph("Assessment Dimension", self.styles['TableHead']),
                Paragraph("Score", self.styles['TableHead']),
                Paragraph("Readiness State", self.styles['TableHead']),
                Paragraph("Technical Assessment Details", self.styles['TableHead']),
            ]
        ]

        for item in self.readiness.get("breakdown", []):
            status_style = self.styles['BadgeSuccess'] if "EXCELLENT" in item["status"] or "READY" in item["status"] else self.styles['BadgeWarning']
            readiness_rows.append([
                Paragraph(f"<b>{item['category']}</b>", self.styles['TableCellBold']),
                Paragraph(f"{item['score']} / {item['max_score']}", self.styles['TableCell']),
                Paragraph(item['status'], status_style),
                Paragraph(item['details'], self.styles['TableCell']),
            ])

        t_ready = Table(readiness_rows, colWidths=[1.8 * inch, 0.8 * inch, 1.4 * inch, 3.4 * inch])
        t_ready.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(t_ready)
        elements.append(Spacer(1, 10))

        # Executive Recommendation Callout
        rec_text = (
            f"<b>Executive Summary & Recommendation:</b> The target GCP environment achieves a "
            f"<b>{self.readiness.get('overall_score')}/100 ({self.readiness.get('rating')})</b> score for cloud security platform migration. "
            f"Estimated transition timeline is <b>{self.readiness.get('estimated_duration')}</b> with <b>{self.readiness.get('complexity')}</b> complexity. "
            f"Connecting the GCP environment provides 100% visibility into misconfigurations, sensitive data, "
            f"and runtime container/VM threats across the cloud architecture."
        )
        t_rec = Table([[Paragraph(rec_text, self.styles['BodyCustom'])]], colWidths=[7.4 * inch])
        t_rec.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), BG_ALT),
            ('BOX', (0, 0), (-1, -1), 1, CYAN_ACCENT),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(t_rec)

        return elements

    def _create_stat_card(self, label: str, value: str, color: colors.Color = NAVY_PRIMARY) -> Table:
        """Helper to create a visually clean metric card."""
        val_style = ParagraphStyle('CardVal', parent=self.styles['StatCardValue'], textColor=color)
        t = Table(
            [
                [Paragraph(value, val_style)],
                [Paragraph(label, self.styles['StatCardLabel'])],
            ],
            colWidths=[2.38 * inch]
        )
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ]))
        return t

    def _build_scc_core_section(self) -> List[Any]:
        """Build SCC Tier, Setup Details, and Built-in Services Section."""
        elements = []
        scc_core = self.data.get("scc_core", {})
        tier_info = scc_core.get("tier_info", {})
        setup = scc_core.get("setup_details", {})
        services = scc_core.get("services_status", [])
        sha_custom = scc_core.get("sha_custom_modules", [])
        etd_custom = scc_core.get("etd_custom_modules", [])

        enabled_count = len([s for s in services if s.get("enabled")])
        total_count = len(services)

        elements.append(Paragraph("2. SCC Version Tier, Setup & Security Services Status", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=8))

        # Setup Details Table
        setup_data = [
            [
                Paragraph("<b>Enabled SCC Tier:</b>", self.styles['TableCellBold']),
                Paragraph(f"<b>{tier_info.get('tier_name')}</b> ({tier_info.get('description')})", self.styles['TableCell']),
            ],
            [
                Paragraph("<b>Asset Discovery Mode:</b>", self.styles['TableCellBold']),
                Paragraph(str(setup.get("asset_discovery_status", "AUTOMATIC")), self.styles['TableCell']),
            ],
            [
                Paragraph("<b>SCC Service Agent:</b>", self.styles['TableCellBold']),
                Paragraph(f"<code>{setup.get('scc_service_agent')}</code>", self.styles['TableCell']),
            ],
            [
                Paragraph("<b>DLP Service Agent:</b>", self.styles['TableCellBold']),
                Paragraph(f"<code>{setup.get('dlp_service_agent')}</code>", self.styles['TableCell']),
            ],
        ]
        t_setup = Table(setup_data, colWidths=[1.8 * inch, 5.6 * inch])
        t_setup.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_setup)
        elements.append(Spacer(1, 8))

        # Built-in & Integrated Services Table (All 14 services listed with Enabled/Disabled status)
        elements.append(Paragraph(f"Built-in & Integrated Security Services ({enabled_count} of {total_count} Enabled)", self.styles['SubSectionHeading']))
        svc_rows = [
            [
                Paragraph("Service Name", self.styles['TableHead']),
                Paragraph("Domain Category", self.styles['TableHead']),
                Paragraph("Status", self.styles['TableHead']),
                Paragraph("Custom Rules", self.styles['TableHead']),
                Paragraph("Target Architecture Capability", self.styles['TableHead']),
            ]
        ]
        for s in services:
            enabled_badge = Paragraph("ENABLED", self.styles['BadgeSuccess']) if s["enabled"] else Paragraph("DISABLED", self.styles['BadgeWarning'])
            svc_rows.append([
                Paragraph(f"<b>{s['display_name']}</b>", self.styles['TableCellBold']),
                Paragraph(s['category'], self.styles['TableCell']),
                enabled_badge,
                Paragraph(str(s.get("custom_rules_count", 0)), self.styles['TableCell']),
                Paragraph(s.get('target_capability_mapping', s['category']), self.styles['TableCell']),
            ])

        t_svc = Table(svc_rows, colWidths=[2.2 * inch, 1.4 * inch, 0.7 * inch, 0.7 * inch, 2.4 * inch])
        t_svc.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('PADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(t_svc)
        elements.append(Spacer(1, 8))

        # Custom Detection Modules Table (SHA & ETD)
        all_custom = [("SHA", m) for m in sha_custom] + [("ETD", m) for m in etd_custom]
        if all_custom:
            elements.append(Paragraph(f"Custom Security Detection Modules ({len(all_custom)} Total)", self.styles['SubSectionHeading']))
            custom_rows = [
                [
                    Paragraph("Type", self.styles['TableHead']),
                    Paragraph("Custom Rule Name", self.styles['TableHead']),
                    Paragraph("Severity", self.styles['TableHead']),
                    Paragraph("Rule Logic / Description", self.styles['TableHead']),
                ]
            ]
            for c_type, m in all_custom[:8]:  # Show top 8
                sev_style = self.styles['BadgeDanger'] if m.get("severity") in ("CRITICAL", "HIGH") else self.styles['TableCell']
                custom_rows.append([
                    Paragraph(f"<b>{c_type}</b>", self.styles['TableCellBold']),
                    Paragraph(m.get("display_name", ""), self.styles['TableCell']),
                    Paragraph(m.get("severity", "HIGH"), sev_style),
                    Paragraph(m.get("description", ""), self.styles['TableCell']),
                ])
            t_custom = Table(custom_rows, colWidths=[0.6 * inch, 2.2 * inch, 0.9 * inch, 3.7 * inch])
            t_custom.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
                ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
                ('PADDING', (0, 0), (-1, -1), 3),
            ]))
            elements.append(t_custom)

        return elements

    def _build_postures_and_dlp_section(self) -> List[Any]:
        """Build Security Postures and Sensitive Data Protection Section."""
        elements = []
        postures = self.data.get("postures", {})
        dlp_data = self.data.get("dlp_sdp", {})

        elements.append(Paragraph("3. Security Postures & Sensitive Data Protection (Cloud DLP)", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=8))

        # Security Postures & Deployments
        elements.append(Paragraph(f"Security Postures & Deployments ({postures.get('posture_count', 0)} Postures, {postures.get('deployment_count', 0)} Deployments)", self.styles['SubSectionHeading']))
        posture_rows = [
            [
                Paragraph("Posture ID", self.styles['TableHead']),
                Paragraph("Revision", self.styles['TableHead']),
                Paragraph("Policy Sets", self.styles['TableHead']),
                Paragraph("Rules Count", self.styles['TableHead']),
                Paragraph("Target Deployments / Scope", self.styles['TableHead']),
            ]
        ]
        deployments = postures.get("posture_deployments", [])
        posture_list = postures.get("postures", [])
        if posture_list:
            for p in posture_list:
                p_id = p.get("posture_id", "")
                p_deps = [d.get("target_resource", "") for d in deployments if p_id in d.get("posture_id", "")]
                target_str = ", ".join(p_deps) if p_deps else "All Organization Projects"
                posture_rows.append([
                    Paragraph(f"<b>{p_id}</b>", self.styles['TableCellBold']),
                    Paragraph(p.get("revision_id", "v1"), self.styles['TableCell']),
                    Paragraph(str(p.get("policy_sets_count", 1)), self.styles['TableCell']),
                    Paragraph(str(p.get("total_rules_count", 0)), self.styles['TableCell']),
                    Paragraph(target_str, self.styles['TableCell']),
                ])
        else:
            posture_rows.append([
                Paragraph("<i>0 security postures active (Security Postures are managed at the Organization level)</i>", self.styles['BodyMuted']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
            ])

        t_posture = Table(posture_rows, colWidths=[1.8 * inch, 0.7 * inch, 0.9 * inch, 0.8 * inch, 3.2 * inch])
        t_posture.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_posture)
        elements.append(Spacer(1, 10))

        # Sensitive Data Protection (DLP) Automated Discovery
        elements.append(Paragraph(f"Sensitive Data Protection (SDP) Discovery Configs & Profiling ({dlp_data.get('discovery_config_count', 0)} Active)", self.styles['SubSectionHeading']))
        dlp_disc_rows = [
            [
                Paragraph("Config Name", self.styles['TableHead']),
                Paragraph("Target Storage / Lake", self.styles['TableHead']),
                Paragraph("Status", self.styles['TableHead']),
                Paragraph("Inspection Template Attached", self.styles['TableHead']),
            ]
        ]
        configs = dlp_data.get("discovery_configs", [])
        if configs:
            for cfg in configs:
                dlp_disc_rows.append([
                    Paragraph(f"<b>{cfg.get('display_name')}</b>", self.styles['TableCellBold']),
                    Paragraph(", ".join(cfg.get("targets", [])), self.styles['TableCell']),
                    Paragraph(cfg.get("status", "ACTIVE"), self.styles['BadgeSuccess']),
                    Paragraph(cfg.get("inspect_template", "").split("/")[-1], self.styles['TableCell']),
                ])
        else:
            dlp_disc_rows.append([
                Paragraph("<i>0 automated data profiling discovery configs active in this scope</i>", self.styles['BodyMuted']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
            ])

        t_dlp_disc = Table(dlp_disc_rows, colWidths=[2.2 * inch, 2.2 * inch, 0.8 * inch, 2.2 * inch])
        t_dlp_disc.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_dlp_disc)
        elements.append(Spacer(1, 10))

        # DLP Inspect Templates Table
        elements.append(Paragraph(f"Cloud DLP Inspect & De-identify Templates ({dlp_data.get('inspect_template_count', 0)} Active)", self.styles['SubSectionHeading']))
        tmpl_rows = [
            [
                Paragraph("Template Name", self.styles['TableHead']),
                Paragraph("Min Likelihood", self.styles['TableHead']),
                Paragraph("InfoTypes", self.styles['TableHead']),
                Paragraph("Sample Sensitive InfoTypes Detected", self.styles['TableHead']),
                Paragraph("Target DSPM Mapping", self.styles['TableHead']),
            ]
        ]
        templates = dlp_data.get("inspect_templates", [])
        if templates:
            for t_item in templates:
                samples = ", ".join(t_item.get("sample_info_types", []))
                tmpl_rows.append([
                    Paragraph(f"<b>{t_item.get('display_name')}</b>", self.styles['TableCellBold']),
                    Paragraph(t_item.get("min_likelihood", "LIKELY"), self.styles['TableCell']),
                    Paragraph(str(t_item.get("info_types_count", 0)), self.styles['TableCell']),
                    Paragraph(samples, self.styles['TableCell']),
                    Paragraph("Data Security Classifiers", self.styles['TableCell']),
                ])
        else:
            tmpl_rows.append([
                Paragraph("<i>0 Cloud DLP inspect templates discovered</i>", self.styles['BodyMuted']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
            ])

        t_tmpl = Table(tmpl_rows, colWidths=[1.8 * inch, 1.0 * inch, 0.7 * inch, 2.3 * inch, 1.6 * inch])
        t_tmpl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_tmpl)

        return elements

    def _build_exports_mutes_connectors_section(self) -> List[Any]:
        """Build Continuous Exports, Mute Rules, and Connectors Section."""
        elements = []
        exports = self.data.get("exports_mutes", {})
        connectors = self.data.get("connectors", {})

        elements.append(Paragraph("4. Continuous Exports, Mute Rules & Connectors", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=8))

        # Continuous Exports Table (PubSub & BigQuery)
        elements.append(Paragraph(f"Continuous Exports ({exports.get('pubsub_export_count', 0)} Pub/Sub, {exports.get('bigquery_export_count', 0)} BigQuery)", self.styles['SubSectionHeading']))
        exp_rows = [
            [
                Paragraph("Export Type", self.styles['TableHead']),
                Paragraph("Export ID / Destination", self.styles['TableHead']),
                Paragraph("CEL Filter Condition", self.styles['TableHead']),
                Paragraph("Target Integration Pipeline", self.styles['TableHead']),
            ]
        ]
        has_exports = False
        for ps in exports.get("pubsub_notification_configs", []):
            has_exports = True
            exp_rows.append([
                Paragraph("<b>Pub/Sub Stream</b>", self.styles['TableCellBold']),
                Paragraph(f"<code>{ps.get('topic_short')}</code>", self.styles['TableCell']),
                Paragraph(ps.get("filter", ""), self.styles['TableCell']),
                Paragraph("Webhooks / SIEM Forwarder", self.styles['TableCell']),
            ])
        for bq in exports.get("bigquery_exports", []):
            has_exports = True
            exp_rows.append([
                Paragraph("<b>BigQuery Table</b>", self.styles['TableCellBold']),
                Paragraph(f"<code>{bq.get('dataset_short')}</code>", self.styles['TableCell']),
                Paragraph(bq.get("filter", ""), self.styles['TableCell']),
                Paragraph("Data Exporter / Cloud Sinks", self.styles['TableCell']),
            ])
        if not has_exports:
            exp_rows.append([
                Paragraph("<i>0 continuous Pub/Sub or BigQuery exports configured</i>", self.styles['BodyMuted']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
            ])

        t_exp = Table(exp_rows, colWidths=[1.3 * inch, 2.0 * inch, 2.3 * inch, 1.8 * inch])
        t_exp.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_exp)
        elements.append(Spacer(1, 10))

        # Mute Rules Table
        mutes = exports.get("mute_rules", [])
        elements.append(Paragraph(f"Finding Mute Rules & Exceptions ({len(mutes)} Active Rules)", self.styles['SubSectionHeading']))
        mute_rows = [
            [
                Paragraph("Mute Rule Display Name", self.styles['TableHead']),
                Paragraph("CEL Suppression Filter", self.styles['TableHead']),
                Paragraph("Created By / Editor", self.styles['TableHead']),
                Paragraph("Target Exception Mapping", self.styles['TableHead']),
            ]
        ]
        if mutes:
            for m in mutes[:6]:
                mute_rows.append([
                    Paragraph(f"<b>{m.get('display_name')}</b>", self.styles['TableCellBold']),
                    Paragraph(f"<code>{m.get('filter')}</code>", self.styles['TableCell']),
                    Paragraph(m.get("most_recent_editor", "Unknown"), self.styles['TableCell']),
                    Paragraph("Exception Rule / Waiver", self.styles['TableCell']),
                ])
        else:
            mute_rows.append([
                Paragraph("<i>0 finding mute or exception rules active in this scope</i>", self.styles['BodyMuted']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
            ])

        t_mute = Table(mute_rows, colWidths=[2.1 * inch, 2.6 * inch, 1.4 * inch, 1.3 * inch])
        t_mute.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_mute)
        elements.append(Spacer(1, 10))

        # Connectors Table (Multi-Cloud, Ticketing, SIEM)
        elements.append(Paragraph(f"Connectors & Integrations ({connectors.get('total_connectors', 0)} Total)", self.styles['SubSectionHeading']))
        conn_rows = [
            [
                Paragraph("Connector Type", self.styles['TableHead']),
                Paragraph("Integration Name / Target", self.styles['TableHead']),
                Paragraph("Status", self.styles['TableHead']),
                Paragraph("Target Connector Equivalent", self.styles['TableHead']),
            ]
        ]
        has_conn = False
        for mc in connectors.get("multicloud_connectors", []):
            has_conn = True
            conn_rows.append([
                Paragraph(f"<b>{mc.get('type')}</b>", self.styles['TableCellBold']),
                Paragraph(mc.get("target_id", ""), self.styles['TableCell']),
                Paragraph(mc.get("status", "ACTIVE"), self.styles['BadgeSuccess']),
                Paragraph(mc.get("target_connector_mapping", "Cloud Account Connector"), self.styles['TableCell']),
            ])
        for tc in connectors.get("ticketing_connectors", []):
            has_conn = True
            conn_rows.append([
                Paragraph(f"<b>{tc.get('type')}</b>", self.styles['TableCellBold']),
                Paragraph(tc.get("name", ""), self.styles['TableCell']),
                Paragraph(tc.get("status", "ACTIVE"), self.styles['BadgeSuccess']),
                Paragraph(tc.get("target_connector_mapping", "ITSM / SIEM Connector"), self.styles['TableCell']),
            ])
        if not has_conn:
            conn_rows.append([
                Paragraph("<i>0 multi-cloud or ticketing connectors configured</i>", self.styles['BodyMuted']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
            ])

        t_conn = Table(conn_rows, colWidths=[1.8 * inch, 2.2 * inch, 0.8 * inch, 2.6 * inch])
        t_conn.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_conn)

        return elements

    def _build_findings_and_compliance_section(self) -> List[Any]:
        """Build Findings Breakdown (Source/Category) and Compliance Frameworks Section."""
        elements = []
        findings = self.data.get("findings", {})
        compliance = self.data.get("compliance", {})

        elements.append(Paragraph("5. Findings Deep-Dive & Compliance Frameworks", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=8))

        # Findings by Source Table
        elements.append(Paragraph(f"Active Findings by Source Detector ({findings.get('total_active_findings', 0):,} Total)", self.styles['SubSectionHeading']))
        src_rows = [
            [
                Paragraph("Detector Source", self.styles['TableHead']),
                Paragraph("Domain Category", self.styles['TableHead']),
                Paragraph("Active Findings", self.styles['TableHead']),
                Paragraph("Share %", self.styles['TableHead']),
                Paragraph("Target Security Domain", self.styles['TableHead']),
            ]
        ]
        src_list = findings.get("findings_by_source", [])
        if src_list:
            for src in src_list:
                src_rows.append([
                    Paragraph(f"<b>{src.get('source_name')}</b>", self.styles['TableCellBold']),
                    Paragraph(src.get("category_type", ""), self.styles['TableCell']),
                    Paragraph(f"{src.get('count', 0):,}", self.styles['TableCell']),
                    Paragraph(f"{src.get('percentage', 0)}%", self.styles['TableCell']),
                    Paragraph(src.get("category_type", "").split("/")[0], self.styles['TableCell']),
                ])
        else:
            src_rows.append([
                Paragraph("<i>0 active findings recorded across detectors in this scope</i>", self.styles['BodyMuted']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("0", self.styles['TableCell']),
                Paragraph("0.0%", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
            ])

        t_src = Table(src_rows, colWidths=[2.2 * inch, 1.8 * inch, 1.0 * inch, 0.7 * inch, 1.7 * inch])
        t_src.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_src)
        elements.append(Spacer(1, 10))

        # Top Finding Categories Table
        elements.append(Paragraph("Top Security Issue Categories & Classes", self.styles['SubSectionHeading']))
        cat_rows = [
            [
                Paragraph("Finding Category", self.styles['TableHead']),
                Paragraph("Finding Class", self.styles['TableHead']),
                Paragraph("Severity", self.styles['TableHead']),
                Paragraph("Count", self.styles['TableHead']),
            ]
        ]
        cat_list = findings.get("findings_by_category", [])
        if cat_list:
            for cat in cat_list[:10]:
                sev = cat.get("severity", "MEDIUM")
                sev_style = self.styles['BadgeDanger'] if sev in ("CRITICAL", "HIGH") else self.styles['BadgeWarning']
                cat_rows.append([
                    Paragraph(f"<b>{cat.get('key')}</b>", self.styles['TableCellBold']),
                    Paragraph(cat.get("class", "MISCONFIGURATION"), self.styles['TableCell']),
                    Paragraph(sev, sev_style),
                    Paragraph(str(cat.get("count", 0)), self.styles['TableCell']),
                ])
        else:
            cat_rows.append([
                Paragraph("<i>No active finding categories found</i>", self.styles['BodyMuted']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("0", self.styles['TableCell']),
            ])

        t_cat = Table(cat_rows, colWidths=[3.2 * inch, 1.8 * inch, 1.2 * inch, 1.2 * inch])
        t_cat.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_cat)
        elements.append(Spacer(1, 10))

        # Enabled Compliance Frameworks Table
        elements.append(Paragraph("Enabled Compliance Frameworks & Benchmark Violation Status", self.styles['SubSectionHeading']))
        fw_rows = [
            [
                Paragraph("Compliance Benchmark", self.styles['TableHead']),
                Paragraph("Evaluated Controls", self.styles['TableHead']),
                Paragraph("Failing Controls", self.styles['TableHead']),
                Paragraph("Passing Score %", self.styles['TableHead']),
                Paragraph("Standard Framework Benchmark", self.styles['TableHead']),
            ]
        ]
        for fw in compliance.get("compliance_frameworks", []):
            pct = fw.get("passing_percentage", 85.0)
            pct_style = self.styles['BadgeSuccess'] if pct >= 85 else self.styles['BadgeWarning']
            fw_rows.append([
                Paragraph(f"<b>{fw.get('name')}</b>", self.styles['TableCellBold']),
                Paragraph(str(fw.get("evaluated_controls_count", 0)), self.styles['TableCell']),
                Paragraph(str(fw.get("failing_controls_count", 0)), self.styles['TableCell']),
                Paragraph(f"{pct}%", pct_style),
                Paragraph(fw.get("standard_framework_name", fw.get("name")), self.styles['TableCell']),
            ])

        t_fw = Table(fw_rows, colWidths=[2.2 * inch, 1.1 * inch, 1.0 * inch, 1.0 * inch, 2.1 * inch])
        t_fw.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_fw)

        return elements

    def _build_assets_and_hierarchy_section(self) -> List[Any]:
        """Build Asset Inventory & Organization Hierarchy Section."""
        elements = []
        assets = self.data.get("assets", {})
        hierarchy = self.data.get("hierarchy", {})

        elements.append(Paragraph("6. Asset Inventory & Organization Hierarchy Coverage", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=8))

        # Asset Breakdown by Domain Table
        elements.append(Paragraph(f"Cloud Asset Inventory ({assets.get('total_assets', 0):,} Total Resources across {assets.get('asset_types_count', 0)} Types)", self.styles['SubSectionHeading']))
        domain_rows = [
            [
                Paragraph("Architecture Domain", self.styles['TableHead']),
                Paragraph("Resource Count", self.styles['TableHead']),
                Paragraph("Share %", self.styles['TableHead']),
                Paragraph("Security Graph Coverage", self.styles['TableHead']),
            ]
        ]
        total_assets = assets.get("total_assets", 1) or 1
        dom_cats = assets.get("domain_categories", {})
        if dom_cats:
            for dom, count in dom_cats.items():
                share_pct = round((count / total_assets * 100), 1)
                domain_rows.append([
                    Paragraph(f"<b>{dom}</b>", self.styles['TableCellBold']),
                    Paragraph(f"{count:,}", self.styles['TableCell']),
                    Paragraph(f"{share_pct}%", self.styles['TableCell']),
                    Paragraph("100% Agentless & Graph Ingested", self.styles['TableCell']),
                ])
        else:
            domain_rows.append([
                Paragraph("<i>0 cloud assets discovered in this scope</i>", self.styles['BodyMuted']),
                Paragraph("0", self.styles['TableCell']),
                Paragraph("0.0%", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
            ])

        t_dom = Table(domain_rows, colWidths=[2.8 * inch, 1.1 * inch, 0.9 * inch, 2.6 * inch])
        t_dom.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_dom)
        elements.append(Spacer(1, 10))

        # Hierarchy & Scope Table
        elements.append(Paragraph(f"Hierarchy & Scope Coverage ({hierarchy.get('project_count', 0)} Project(s) in {hierarchy.get('folder_count', 0)} Folder(s))", self.styles['SubSectionHeading']))
        hier_rows = [
            [
                Paragraph("Project ID", self.styles['TableHead']),
                Paragraph("Display Name", self.styles['TableHead']),
                Paragraph("Parent Folder / Org", self.styles['TableHead']),
                Paragraph("SCC Scope", self.styles['TableHead']),
            ]
        ]
        proj_list = hierarchy.get("projects_summary", [])
        if proj_list:
            for p in proj_list[:12]:
                hier_rows.append([
                    Paragraph(f"<b>{p.get('project_id')}</b>", self.styles['TableCellBold']),
                    Paragraph(p.get("display_name", ""), self.styles['TableCell']),
                    Paragraph(p.get("parent", "Direct Org Node"), self.styles['TableCell']),
                    Paragraph("Active Scope", self.styles['TableCell']),
                ])
        else:
            hier_rows.append([
                Paragraph("<i>Project details recorded in metadata</i>", self.styles['BodyMuted']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
                Paragraph("-", self.styles['TableCell']),
            ])

        t_hier = Table(hier_rows, colWidths=[2.2 * inch, 2.0 * inch, 1.8 * inch, 1.4 * inch])
        t_hier.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_hier)

        return elements

    def _build_migration_blueprint_section(self) -> List[Any]:
        """Build Cloud Security Architecture Mapping & 4-Phase Migration Roadmap Section."""
        elements = []
        elements.append(Paragraph("7. Cloud Security Platform Migration Blueprint & Transition Roadmap", self.styles['SectionHeading']))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=CYAN_ACCENT, spaceBefore=2, spaceAfter=8))

        # Architecture Translation Matrix Table
        elements.append(Paragraph("SCC to Target Cloud Security Architecture Translation Matrix", self.styles['SubSectionHeading']))
        matrix_rows = [
            [
                Paragraph("Security Domain", self.styles['TableHead']),
                Paragraph("SCC Feature", self.styles['TableHead']),
                Paragraph("Target Architecture Component", self.styles['TableHead']),
                Paragraph("Migration Action", self.styles['TableHead']),
            ],
            [
                Paragraph("<b>Cloud Detection & Response (CDR)</b>", self.styles['TableCellBold']),
                Paragraph("Event Threat Detection (ETD)", self.styles['TableCell']),
                Paragraph("Cloud Events Ingestion & Behavioral CDR", self.styles['TableCell']),
                Paragraph("Enable Cloud Events log streams on GCP Organization; configure CDR alert rules and threat policies.", self.styles['TableCell']),
            ],
            [
                Paragraph("<b>Cloud Workload Protection (CWPP)</b>", self.styles['TableCellBold']),
                Paragraph("Container Threat Detection (CTD)", self.styles['TableCell']),
                Paragraph("Runtime Security Sensor & K8s Admission Control", self.styles['TableCell']),
                Paragraph("Deploy runtime DaemonSet onto GKE clusters using Helm / Terraform.", self.styles['TableCell']),
            ],
            [
                Paragraph("<b>Cloud Workload Protection (CWPP)</b>", self.styles['TableCellBold']),
                Paragraph("VM Threat Detection (VMTD)", self.styles['TableCell']),
                Paragraph("Agentless VM Disk Scanning & Runtime Behavioral Sensor", self.styles['TableCell']),
                Paragraph("Grant Agentless Disk Snapshot permissions and deploy runtime sensors to high-criticality VMs.", self.styles['TableCell']),
            ],
            [
                Paragraph("<b>Cloud Security Posture (CSPM)</b>", self.styles['TableCellBold']),
                Paragraph("Security Health Analytics (SHA)", self.styles['TableCell']),
                Paragraph("Cloud Security Posture Management & Security Graph", self.styles['TableCell']),
                Paragraph("Connect GCP Organization via read-only service account; map SHA custom rules to custom posture controls.", self.styles['TableCell']),
            ],
            [
                Paragraph("<b>Data Security Posture (DSPM)</b>", self.styles['TableCellBold']),
                Paragraph("Sensitive Data Protection (Cloud DLP)", self.styles['TableCell']),
                Paragraph("Data Security Posture Management (DSPM) & Classifiers", self.styles['TableCell']),
                Paragraph("Enable DSPM profiling on GCS buckets and BigQuery datasets; convert custom DLP infoTypes to data classifiers.", self.styles['TableCell']),
            ],
            [
                Paragraph("<b>Vulnerability Management</b>", self.styles['TableCellBold']),
                Paragraph("Rapid Vulnerability Detection & WSS", self.styles['TableCell']),
                Paragraph("Vulnerability Management & External Attack Surface", self.styles['TableCell']),
                Paragraph("Automatically inventory and prioritize CVEs across all GCP workloads without active scanning probes.", self.styles['TableCell']),
            ],
        ]

        t_matrix = Table(matrix_rows, colWidths=[1.4 * inch, 1.4 * inch, 1.8 * inch, 2.8 * inch])
        t_matrix.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), NAVY_PRIMARY),
            ('BOX', (0, 0), (-1, -1), 1, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT]),
            ('PADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(t_matrix)
        elements.append(Spacer(1, 8))

        # 4-Phase Roadmap Box
        elements.append(Paragraph("4-Phase Turnkey Migration Execution Roadmap", self.styles['SubSectionHeading']))
        roadmap = get_phased_migration_roadmap()
        for p in roadmap:
            objs = "<br/>• ".join([""] + p["objectives"])
            box_html = (
                f"<b>{p['phase']}</b><br/>"
                f"{objs}<br/>"
                f"<b>Key Milestone Deliverable:</b> {p['deliverable']}"
            )
            t_box = Table([[Paragraph(box_html, self.styles['TableCell'])]], colWidths=[7.4 * inch])
            t_box.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), BG_ALT),
                ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(t_box)
            elements.append(Spacer(1, 4))

        return elements
