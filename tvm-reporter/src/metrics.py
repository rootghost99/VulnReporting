"""
Metrics computation module for TVM Reporter
"""

import pandas as pd
import logging
from typing import Optional, Dict, Any


class MetricsCalculator:
    """Calculate metrics from data model"""

    def __init__(self, config: Dict, logger: Optional[logging.Logger] = None):
        """
        Initialize MetricsCalculator

        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self.metrics = {}
        self.top_n = config.get('report', {}).get('top_n', 10)

    def compute_summary_metrics(self, vuln_fact: pd.DataFrame) -> Dict[str, Any]:
        """
        Compute summary metrics

        Args:
            vuln_fact: VulnDevice fact table

        Returns:
            Dictionary of summary metrics
        """
        self.logger.info("Computing summary metrics")

        summary = {
            'total_cves': vuln_fact['cve'].nunique() if not vuln_fact.empty else 0,
            'total_devices': vuln_fact['device_key'].nunique() if not vuln_fact.empty else 0,
            'total_products': vuln_fact['software_product'].nunique() if not vuln_fact.empty else 0,
            'total_vendors': vuln_fact['software_vendor'].nunique() if not vuln_fact.empty else 0,
            'total_vulnerabilities': len(vuln_fact)
        }

        # Counts by severity
        severity_counts = vuln_fact['severity'].value_counts().to_dict() if not vuln_fact.empty else {}
        summary['critical_count'] = severity_counts.get('Critical', 0)
        summary['high_count'] = severity_counts.get('High', 0)
        summary['medium_count'] = severity_counts.get('Medium', 0)
        summary['low_count'] = severity_counts.get('Low', 0)

        # Counts by exposure bucket
        if 'exposure_bucket' in vuln_fact.columns:
            exposure_counts = vuln_fact['exposure_bucket'].value_counts().to_dict()
            summary['very_high_exposure'] = exposure_counts.get('Very High', 0)
            summary['high_exposure'] = exposure_counts.get('High', 0)
            summary['medium_exposure'] = exposure_counts.get('Medium', 0)
            summary['low_exposure'] = exposure_counts.get('Low', 0)

        self.logger.info(f"Summary metrics: {summary}")

        return summary

    def compute_top_cves(self, vuln_fact: pd.DataFrame) -> pd.DataFrame:
        """
        Compute top CVEs by impacted devices

        Args:
            vuln_fact: VulnDevice fact table

        Returns:
            DataFrame of top CVEs
        """
        self.logger.info(f"Computing top {self.top_n} CVEs")

        if vuln_fact.empty:
            return pd.DataFrame()

        top_cves = vuln_fact.groupby('cve').agg({
            'device_key': 'nunique',
            'severity': 'first',
            'cvss': 'first',
            'software_product': lambda x: ', '.join(x.dropna().unique()[:3])
        }).reset_index()

        top_cves.columns = ['cve', 'device_count', 'severity', 'cvss', 'products']
        top_cves = top_cves.sort_values('device_count', ascending=False).head(self.top_n)

        self.logger.info(f"Top CVEs computed: {len(top_cves)} records")

        return top_cves

    def compute_top_products(self, vuln_fact: pd.DataFrame) -> pd.DataFrame:
        """
        Compute top products involved in Critical or High severity CVEs

        Args:
            vuln_fact: VulnDevice fact table

        Returns:
            DataFrame of top products
        """
        self.logger.info(f"Computing top {self.top_n} products")

        if vuln_fact.empty:
            return pd.DataFrame()

        # Filter to Critical and High severity
        high_risk = vuln_fact[vuln_fact['severity'].isin(['Critical', 'High'])]

        if high_risk.empty:
            return pd.DataFrame()

        top_products = high_risk.groupby('software_product').agg({
            'cve': 'nunique',
            'device_key': 'nunique',
            'software_vendor': 'first'
        }).reset_index()

        top_products.columns = ['product', 'cve_count', 'device_count', 'vendor']
        top_products = top_products.sort_values('cve_count', ascending=False).head(self.top_n)

        self.logger.info(f"Top products computed: {len(top_products)} records")

        return top_products

    def compute_top_recommendations(self, rec_dim: pd.DataFrame) -> pd.DataFrame:
        """
        Compute top recommendations by affected devices or exposure reduction

        Args:
            rec_dim: Recommendation dimension table

        Returns:
            DataFrame of top recommendations
        """
        self.logger.info(f"Computing top {self.top_n} recommendations")

        if rec_dim is None or rec_dim.empty:
            return pd.DataFrame()

        # Sort by affected_devices or exposure_reduction
        if 'affected_devices' in rec_dim.columns:
            sort_col = 'affected_devices'
        elif 'exposure_reduction' in rec_dim.columns:
            sort_col = 'exposure_reduction'
        else:
            return pd.DataFrame()

        top_recs = rec_dim.sort_values(sort_col, ascending=False).head(self.top_n)

        self.logger.info(f"Top recommendations computed: {len(top_recs)} records")

        return top_recs

    def compute_device_hotlist(self, vuln_fact: pd.DataFrame) -> pd.DataFrame:
        """
        Generate device hotlist with highest concentration of Critical/High CVEs

        Args:
            vuln_fact: VulnDevice fact table

        Returns:
            DataFrame of hotlist devices
        """
        self.logger.info("Computing device hotlist")

        if vuln_fact.empty:
            return pd.DataFrame()

        # Filter to Critical and High severity
        high_risk = vuln_fact[vuln_fact['severity'].isin(['Critical', 'High'])]

        if high_risk.empty:
            return pd.DataFrame()

        hotlist = high_risk.groupby(['device_key', 'device_name']).agg({
            'cve': 'nunique',
            'severity': lambda x: (x == 'Critical').sum()
        }).reset_index()

        hotlist.columns = ['device_key', 'device_name', 'high_risk_cve_count', 'critical_cve_count']
        hotlist = hotlist.sort_values('critical_cve_count', ascending=False).head(self.top_n)

        self.logger.info(f"Device hotlist computed: {len(hotlist)} records")

        return hotlist

    def compute_exceptions(
        self,
        vuln_fact: pd.DataFrame,
        software_fact: pd.DataFrame
    ) -> Dict[str, pd.DataFrame]:
        """
        Generate exception lists

        Args:
            vuln_fact: VulnDevice fact table
            software_fact: SoftwareDevice fact table

        Returns:
            Dictionary containing exception DataFrames
        """
        self.logger.info("Computing exception lists")

        exceptions = {}

        # CVEs without recommendations
        if not vuln_fact.empty:
            no_recs = vuln_fact[
                vuln_fact['recommendation_id'].isna() |
                (vuln_fact['recommendation_id'] == '')
            ]

            if not no_recs.empty:
                cves_no_recs = no_recs.groupby('cve').agg({
                    'device_key': 'nunique',
                    'severity': 'first',
                    'software_product': lambda x: ', '.join(x.dropna().unique()[:3])
                }).reset_index()
                cves_no_recs.columns = ['cve', 'device_count', 'severity', 'products']
                exceptions['cves_without_recommendations'] = cves_no_recs
                self.logger.info(f"CVEs without recommendations: {len(cves_no_recs)}")

        # EOL software with open CVEs
        if software_fact is not None and not software_fact.empty:
            eol_with_vulns = software_fact[
                (software_fact['eol_flag'] == True) &
                (software_fact['vuln_count'] > 0)
            ]

            if not eol_with_vulns.empty:
                eol_list = eol_with_vulns[
                    ['device_key', 'device_name', 'product', 'vendor', 'version',
                     'vuln_count', 'critical_vuln_count']
                ].sort_values('critical_vuln_count', ascending=False)
                exceptions['eol_software_with_vulnerabilities'] = eol_list
                self.logger.info(f"EOL software with vulnerabilities: {len(eol_list)}")

        return exceptions

    def compute_trends(self, events_linked: Optional[pd.DataFrame]) -> Optional[pd.DataFrame]:
        """
        Compute daily trend metrics from events

        Args:
            events_linked: Linked events DataFrame

        Returns:
            DataFrame of daily trends or None
        """
        if events_linked is None or events_linked.empty:
            self.logger.info("No events data available for trend analysis")
            return None

        self.logger.info("Computing daily trends")

        if 'event_time' not in events_linked.columns:
            return None

        # Group by date
        trends = events_linked.groupby('event_time').agg({
            'device_name': 'nunique',
            'cve': 'nunique'
        }).reset_index()

        trends.columns = ['date', 'devices_affected', 'unique_cves']
        trends = trends.sort_values('date')

        self.logger.info(f"Daily trends computed: {len(trends)} days")

        return trends

    def compute_all(
        self,
        model: Dict[str, Optional[pd.DataFrame]]
    ) -> Dict[str, Any]:
        """
        Compute all metrics

        Args:
            model: Data model dictionary

        Returns:
            Dictionary containing all computed metrics
        """
        vuln_fact = model.get('vuln_device_fact')
        software_fact = model.get('software_device_fact')
        rec_dim = model.get('rec_dimension')
        events_linked = model.get('events_linked')

        # Compute all metrics
        self.metrics['summary'] = self.compute_summary_metrics(vuln_fact)
        self.metrics['top_cves'] = self.compute_top_cves(vuln_fact)
        self.metrics['top_products'] = self.compute_top_products(vuln_fact)
        self.metrics['top_recommendations'] = self.compute_top_recommendations(rec_dim)
        self.metrics['device_hotlist'] = self.compute_device_hotlist(vuln_fact)
        self.metrics['exceptions'] = self.compute_exceptions(vuln_fact, software_fact)
        self.metrics['trends'] = self.compute_trends(events_linked)

        self.logger.info("Metrics computation complete")

        return self.metrics
