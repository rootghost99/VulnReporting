"""
Data model construction module for TVM Reporter
"""

import pandas as pd
import logging
from typing import Optional, Dict


class DataModel:
    """Build canonical data model with fact tables and dimension tables"""

    def __init__(self, config: Dict, logger: Optional[logging.Logger] = None):
        """
        Initialize DataModel

        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self.model = {}

    def build_vuln_device_fact(
        self,
        vulns: pd.DataFrame,
        software: pd.DataFrame,
        recs: pd.DataFrame
    ) -> pd.DataFrame:
        """
        Build VulnDevice fact table by joining vulnerabilities with software and recommendations

        Args:
            vulns: Vulnerabilities DataFrame
            software: Software inventory DataFrame
            recs: Recommendations DataFrame

        Returns:
            VulnDevice fact table
        """
        self.logger.info("Building VulnDevice fact table")

        # Start with vulnerabilities as base
        fact = vulns.copy()

        # Join with software on device_key and product match
        if software is not None and not software.empty:
            # Create simplified software lookup
            software_lookup = software[['device_key', 'software_key', 'product', 'vendor', 'eol_flag']].copy()

            # Try to join on device_key and product
            fact = fact.merge(
                software_lookup,
                on=['device_key', 'software_key'],
                how='left',
                suffixes=('', '_sw')
            )

            # Fill missing vendor from software
            if 'vendor_sw' in fact.columns:
                fact['software_vendor'] = fact['software_vendor'].fillna(fact['vendor_sw'])
                fact = fact.drop(columns=['vendor_sw'])

            self.logger.info(f"Joined with software inventory: {len(fact)} records")

        # Join with recommendations
        if recs is not None and not recs.empty:
            # First try to join on recommendation_id
            if 'recommendation_id' in fact.columns and 'recommendation_id' in recs.columns:
                fact = fact.merge(
                    recs[['recommendation_id', 'recommendation_title', 'category',
                          'exposure_reduction', 'reference_url']],
                    on='recommendation_id',
                    how='left',
                    suffixes=('', '_rec')
                )

            # Fallback: join on product/vendor match if recommendation_id join failed
            else:
                recs_lookup = recs[['product', 'vendor', 'recommendation_id',
                                   'recommendation_title', 'category']].copy()
                fact = fact.merge(
                    recs_lookup,
                    left_on=['software_product', 'software_vendor'],
                    right_on=['product', 'vendor'],
                    how='left',
                    suffixes=('', '_rec')
                )

            self.logger.info(f"Joined with recommendations: {len(fact)} records")

        self.logger.info(f"VulnDevice fact table created: {len(fact)} records")

        return fact

    def build_software_device_fact(
        self,
        software: pd.DataFrame,
        vulns: pd.DataFrame
    ) -> pd.DataFrame:
        """
        Build SoftwareDevice fact table

        Args:
            software: Software inventory DataFrame
            vulns: Vulnerabilities DataFrame

        Returns:
            SoftwareDevice fact table
        """
        self.logger.info("Building SoftwareDevice fact table")

        fact = software.copy()

        # Aggregate vulnerability counts per software installation
        if vulns is not None and not vulns.empty:
            vuln_counts = vulns.groupby(['device_key', 'software_key']).agg({
                'cve': 'count',
                'severity': lambda x: (x == 'Critical').sum()
            }).reset_index()
            vuln_counts.columns = ['device_key', 'software_key', 'vuln_count', 'critical_vuln_count']

            fact = fact.merge(
                vuln_counts,
                on=['device_key', 'software_key'],
                how='left'
            )

            fact['vuln_count'] = fact['vuln_count'].fillna(0).astype(int)
            fact['critical_vuln_count'] = fact['critical_vuln_count'].fillna(0).astype(int)

            self.logger.info(f"Added vulnerability counts to software inventory")

        self.logger.info(f"SoftwareDevice fact table created: {len(fact)} records")

        return fact

    def build_rec_dimension(self, recs: pd.DataFrame) -> pd.DataFrame:
        """
        Build Recommendation dimension table

        Args:
            recs: Recommendations DataFrame

        Returns:
            Recommendation dimension table
        """
        self.logger.info("Building Recommendation dimension table")

        # Recommendations are already in dimension format
        dim = recs.copy()

        self.logger.info(f"Recommendation dimension table created: {len(dim)} records")

        return dim

    def link_events(
        self,
        events: pd.DataFrame,
        vulns: pd.DataFrame
    ) -> Optional[pd.DataFrame]:
        """
        Link events with vulnerabilities for trend analysis

        Args:
            events: Events DataFrame
            vulns: Vulnerabilities DataFrame

        Returns:
            Linked events DataFrame or None
        """
        if events is None or events.empty:
            return None

        self.logger.info("Linking events with vulnerabilities")

        # Join events with vulnerabilities on CVE or recommendation_id
        linked = events.copy()

        if 'cve' in events.columns and 'cve' in vulns.columns:
            vuln_lookup = vulns[['cve', 'severity', 'cvss']].drop_duplicates()
            linked = linked.merge(
                vuln_lookup,
                on='cve',
                how='left',
                suffixes=('', '_vuln')
            )

        self.logger.info(f"Linked events: {len(linked)} records")

        return linked

    def build_model(
        self,
        data: Dict[str, Optional[pd.DataFrame]]
    ) -> Dict[str, Optional[pd.DataFrame]]:
        """
        Build complete data model

        Args:
            data: Dictionary of validated DataFrames

        Returns:
            Dictionary containing model tables
        """
        vulns = data.get('vulnerabilities')
        recs = data.get('recommendations')
        software = data.get('software')
        events = data.get('events')

        # Build fact tables
        self.model['vuln_device_fact'] = self.build_vuln_device_fact(
            vulns, software, recs
        )

        self.model['software_device_fact'] = self.build_software_device_fact(
            software, vulns
        )

        # Build dimension tables
        self.model['rec_dimension'] = self.build_rec_dimension(recs)

        # Link events if available
        self.model['events_linked'] = self.link_events(events, vulns)

        self.logger.info("Data model construction complete")

        return self.model
