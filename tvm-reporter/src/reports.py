"""
Report generation module for TVM Reporter
"""

import pandas as pd
import logging
from typing import Optional, Dict, Any
from datetime import datetime
import os

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class ReportGenerator:
    """Generate CSV and PDF reports"""

    def __init__(
        self,
        config: Dict,
        owners_config: Dict,
        output_dir: str,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize ReportGenerator

        Args:
            config: Configuration dictionary
            owners_config: Owners configuration dictionary
            output_dir: Output directory for reports
            logger: Logger instance
        """
        self.config = config
        self.owners_config = owners_config
        self.output_dir = output_dir
        self.logger = logger or logging.getLogger(__name__)

        # Create dated report folder
        self.report_date = datetime.now().strftime("%Y-%m-%d")
        self.report_dir = f"{output_dir}/reports/{self.report_date}"
        os.makedirs(self.report_dir, exist_ok=True)

        self.logger.info(f"Report directory: {self.report_dir}")

    def resolve_owner(self, product: str, vendor: str) -> str:
        """
        Resolve owner based on product and vendor patterns

        Args:
            product: Product name
            vendor: Vendor name

        Returns:
            Owner name
        """
        patterns = self.owners_config.get('patterns', [])

        for pattern in patterns:
            if pattern.get('product_pattern', '').lower() in str(product).lower():
                return pattern.get('owner', 'Unassigned')
            if pattern.get('vendor_pattern', '').lower() in str(vendor).lower():
                return pattern.get('owner', 'Unassigned')

        return self.owners_config.get('default_owner', 'Unassigned')

    def generate_remediation_plan(
        self,
        vuln_fact: pd.DataFrame,
        metrics: Dict[str, Any]
    ) -> str:
        """
        Generate Remediation_Plan.csv

        Args:
            vuln_fact: VulnDevice fact table
            metrics: Computed metrics

        Returns:
            Path to generated CSV
        """
        self.logger.info("Generating Remediation Plan CSV")

        if vuln_fact.empty:
            self.logger.warning("No vulnerability data for remediation plan")
            return None

        # Filter to Critical and High severity
        remediation = vuln_fact[vuln_fact['severity'].isin(['Critical', 'High'])].copy()

        if remediation.empty:
            self.logger.warning("No Critical or High severity vulnerabilities")
            return None

        # Add owner assignment
        remediation['owner'] = remediation.apply(
            lambda row: self.resolve_owner(
                row.get('software_product', ''),
                row.get('software_vendor', '')
            ), axis=1
        )

        # Add SLA days based on severity
        sla_config = self.config.get('sla_days', {})
        remediation['sla_days'] = remediation['severity'].map({
            'Critical': sla_config.get('critical', 7),
            'High': sla_config.get('high', 30)
        })

        # Select and order columns
        output_cols = [
            'cve', 'severity', 'cvss', 'device_name', 'device_key',
            'software_product', 'software_vendor', 'software_version',
            'recommendation_id', 'recommendation_title', 'owner', 'sla_days'
        ]

        existing_cols = [col for col in output_cols if col in remediation.columns]
        remediation_out = remediation[existing_cols]

        # Sort by severity and CVSS
        remediation_out = remediation_out.sort_values(
            ['severity', 'cvss'],
            ascending=[True, False]
        )

        filepath = f"{self.report_dir}/Remediation_Plan.csv"
        remediation_out.to_csv(filepath, index=False)

        self.logger.info(f"Remediation Plan written to {filepath}")

        return filepath

    def generate_cve_by_device(self, vuln_fact: pd.DataFrame) -> str:
        """
        Generate CVE_By_Device.csv

        Args:
            vuln_fact: VulnDevice fact table

        Returns:
            Path to generated CSV
        """
        self.logger.info("Generating CVE by Device CSV")

        if vuln_fact.empty:
            return None

        # Group by device
        cve_by_device = vuln_fact.groupby(['device_key', 'device_name']).agg({
            'cve': lambda x: ', '.join(x.unique()),
            'severity': lambda x: list(x)
        }).reset_index()

        # Count severity levels
        cve_by_device['critical_count'] = cve_by_device['severity'].apply(
            lambda x: x.count('Critical')
        )
        cve_by_device['high_count'] = cve_by_device['severity'].apply(
            lambda x: x.count('High')
        )
        cve_by_device['total_cves'] = cve_by_device['severity'].apply(len)

        cve_by_device = cve_by_device.drop(columns=['severity'])

        filepath = f"{self.report_dir}/CVE_By_Device.csv"
        cve_by_device.to_csv(filepath, index=False)

        self.logger.info(f"CVE by Device written to {filepath}")

        return filepath

    def generate_device_by_cve(self, vuln_fact: pd.DataFrame) -> str:
        """
        Generate Device_By_CVE.csv

        Args:
            vuln_fact: VulnDevice fact table

        Returns:
            Path to generated CSV
        """
        self.logger.info("Generating Device by CVE CSV")

        if vuln_fact.empty:
            return None

        # Group by CVE
        device_by_cve = vuln_fact.groupby('cve').agg({
            'device_name': lambda x: ', '.join(x.unique()),
            'device_key': 'nunique',
            'severity': 'first',
            'cvss': 'first',
            'software_product': lambda x: ', '.join(x.dropna().unique()[:3])
        }).reset_index()

        device_by_cve.columns = [
            'cve', 'affected_devices', 'device_count',
            'severity', 'cvss', 'products'
        ]

        device_by_cve = device_by_cve.sort_values('device_count', ascending=False)

        filepath = f"{self.report_dir}/Device_By_CVE.csv"
        device_by_cve.to_csv(filepath, index=False)

        self.logger.info(f"Device by CVE written to {filepath}")

        return filepath

    def generate_software_risk_priorities(self, software_fact: pd.DataFrame) -> str:
        """
        Generate Software_Risk_Priorities.csv

        Args:
            software_fact: SoftwareDevice fact table

        Returns:
            Path to generated CSV
        """
        self.logger.info("Generating Software Risk Priorities CSV")

        if software_fact is None or software_fact.empty:
            return None

        # Aggregate by product
        risk_priorities = software_fact.groupby(['product', 'vendor']).agg({
            'device_key': 'nunique',
            'vuln_count': 'sum',
            'critical_vuln_count': 'sum',
            'eol_flag': 'max'
        }).reset_index()

        risk_priorities.columns = [
            'product', 'vendor', 'device_count',
            'total_vulnerabilities', 'critical_vulnerabilities', 'is_eol'
        ]

        # Calculate risk score
        risk_priorities['risk_score'] = (
            risk_priorities['critical_vulnerabilities'] * 10 +
            risk_priorities['total_vulnerabilities'] +
            risk_priorities['is_eol'].astype(int) * 50
        )

        risk_priorities = risk_priorities.sort_values('risk_score', ascending=False)

        filepath = f"{self.report_dir}/Software_Risk_Priorities.csv"
        risk_priorities.to_csv(filepath, index=False)

        self.logger.info(f"Software Risk Priorities written to {filepath}")

        return filepath

    def generate_datasets_profile(self, metrics: Dict[str, Any]) -> str:
        """
        Generate Datasets_Profile.csv

        Args:
            metrics: Computed metrics

        Returns:
            Path to generated CSV
        """
        self.logger.info("Generating Datasets Profile CSV")

        summary = metrics.get('summary', {})

        profile_data = [
            {'metric': 'Total CVEs', 'value': summary.get('total_cves', 0)},
            {'metric': 'Total Devices', 'value': summary.get('total_devices', 0)},
            {'metric': 'Total Products', 'value': summary.get('total_products', 0)},
            {'metric': 'Total Vendors', 'value': summary.get('total_vendors', 0)},
            {'metric': 'Total Vulnerabilities', 'value': summary.get('total_vulnerabilities', 0)},
            {'metric': 'Critical Vulnerabilities', 'value': summary.get('critical_count', 0)},
            {'metric': 'High Vulnerabilities', 'value': summary.get('high_count', 0)},
            {'metric': 'Medium Vulnerabilities', 'value': summary.get('medium_count', 0)},
            {'metric': 'Low Vulnerabilities', 'value': summary.get('low_count', 0)},
        ]

        profile_df = pd.DataFrame(profile_data)

        filepath = f"{self.report_dir}/Datasets_Profile.csv"
        profile_df.to_csv(filepath, index=False)

        self.logger.info(f"Datasets Profile written to {filepath}")

        return filepath

    def generate_pdf_summary(
        self,
        metrics: Dict[str, Any],
        model: Dict[str, pd.DataFrame]
    ) -> str:
        """
        Generate Executive Snapshot PDF

        Args:
            metrics: Computed metrics
            model: Data model

        Returns:
            Path to generated PDF
        """
        if not REPORTLAB_AVAILABLE:
            self.logger.warning("ReportLab not available. PDF generation skipped.")
            return None

        self.logger.info("Generating Executive Snapshot PDF")

        filepath = f"{self.report_dir}/Executive_Snapshot.pdf"

        doc = SimpleDocTemplate(filepath, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30
        )

        story.append(Paragraph("TVM Executive Snapshot", title_style))
        story.append(Paragraph(f"Report Date: {self.report_date}", styles['Normal']))
        story.append(Spacer(1, 0.3 * inch))

        # Summary Section
        story.append(Paragraph("Summary Metrics", styles['Heading2']))
        summary = metrics.get('summary', {})

        summary_data = [
            ['Metric', 'Value'],
            ['Total CVEs', str(summary.get('total_cves', 0))],
            ['Total Devices', str(summary.get('total_devices', 0))],
            ['Total Products', str(summary.get('total_products', 0))],
            ['Critical Vulnerabilities', str(summary.get('critical_count', 0))],
            ['High Vulnerabilities', str(summary.get('high_count', 0))],
            ['Medium Vulnerabilities', str(summary.get('medium_count', 0))],
            ['Low Vulnerabilities', str(summary.get('low_count', 0))],
        ]

        summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 0.3 * inch))

        # Top CVEs
        story.append(Paragraph("Top CVEs by Device Impact", styles['Heading2']))
        top_cves = metrics.get('top_cves')

        if top_cves is not None and not top_cves.empty:
            cve_data = [['CVE', 'Devices', 'Severity', 'CVSS']]
            for _, row in top_cves.head(10).iterrows():
                cve_data.append([
                    str(row['cve'])[:20],
                    str(row['device_count']),
                    str(row['severity']),
                    f"{row['cvss']:.1f}"
                ])

            cve_table = Table(cve_data, colWidths=[2 * inch, 1 * inch, 1.5 * inch, 1 * inch])
            cve_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(cve_table)
        else:
            story.append(Paragraph("No CVE data available", styles['Normal']))

        story.append(Spacer(1, 0.3 * inch))

        # Top Recommendations
        story.append(Paragraph("Top Recommendations", styles['Heading2']))
        top_recs = metrics.get('top_recommendations')

        if top_recs is not None and not top_recs.empty:
            rec_data = [['Recommendation', 'Affected Devices']]
            for _, row in top_recs.head(5).iterrows():
                rec_data.append([
                    str(row.get('recommendation_title', ''))[:50],
                    str(row.get('affected_devices', 0))
                ])

            rec_table = Table(rec_data, colWidths=[4 * inch, 1.5 * inch])
            rec_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(rec_table)
        else:
            story.append(Paragraph("No recommendation data available", styles['Normal']))

        story.append(PageBreak())

        # Device Hotlist
        story.append(Paragraph("Device Hotlist", styles['Heading2']))
        hotlist = metrics.get('device_hotlist')

        if hotlist is not None and not hotlist.empty:
            hotlist_data = [['Device', 'Critical CVEs', 'High Risk CVEs']]
            for _, row in hotlist.head(10).iterrows():
                hotlist_data.append([
                    str(row.get('device_name', ''))[:30],
                    str(row.get('critical_cve_count', 0)),
                    str(row.get('high_risk_cve_count', 0))
                ])

            hotlist_table = Table(hotlist_data, colWidths=[3 * inch, 1.5 * inch, 1.5 * inch])
            hotlist_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(hotlist_table)
        else:
            story.append(Paragraph("No device hotlist data available", styles['Normal']))

        story.append(Spacer(1, 0.3 * inch))

        # Exceptions
        story.append(Paragraph("Exceptions", styles['Heading2']))
        exceptions = metrics.get('exceptions', {})

        if exceptions:
            for exc_name, exc_df in exceptions.items():
                if exc_df is not None and not exc_df.empty:
                    story.append(Paragraph(
                        f"{exc_name.replace('_', ' ').title()}: {len(exc_df)} items",
                        styles['Normal']
                    ))
        else:
            story.append(Paragraph("No exceptions found", styles['Normal']))

        # Trends (if available)
        trends = metrics.get('trends')
        if trends is not None and not trends.empty:
            story.append(Spacer(1, 0.3 * inch))
            story.append(Paragraph("Daily Trends", styles['Heading2']))
            story.append(Paragraph(
                f"Trend data available for {len(trends)} days",
                styles['Normal']
            ))

        # Build PDF
        doc.build(story)

        self.logger.info(f"Executive Snapshot PDF written to {filepath}")

        return filepath

    def generate_all_reports(
        self,
        model: Dict[str, pd.DataFrame],
        metrics: Dict[str, Any]
    ) -> Dict[str, str]:
        """
        Generate all reports

        Args:
            model: Data model
            metrics: Computed metrics

        Returns:
            Dictionary of generated report paths
        """
        report_paths = {}

        vuln_fact = model.get('vuln_device_fact')
        software_fact = model.get('software_device_fact')

        # Generate CSV reports
        report_paths['remediation_plan'] = self.generate_remediation_plan(vuln_fact, metrics)
        report_paths['cve_by_device'] = self.generate_cve_by_device(vuln_fact)
        report_paths['device_by_cve'] = self.generate_device_by_cve(vuln_fact)
        report_paths['software_risk'] = self.generate_software_risk_priorities(software_fact)
        report_paths['datasets_profile'] = self.generate_datasets_profile(metrics)

        # Generate PDF
        report_paths['executive_pdf'] = self.generate_pdf_summary(metrics, model)

        self.logger.info("All reports generated successfully")

        return report_paths
