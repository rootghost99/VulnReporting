"""
Schema normalization module for TVM Reporter
"""

import pandas as pd
import logging
from typing import Optional, Dict, List
from src.utils import (
    normalize_header, parse_date, derive_severity, derive_exposure,
    build_software_key, build_device_key, safe_str, safe_float
)


class SchemaNormalizer:
    """Normalize CSV schemas to canonical format"""

    # Canonical column definitions
    VULN_CANONICAL = [
        'device_id', 'device_name', 'cve', 'severity', 'cvss', 'exposure',
        'software_vendor', 'software_product', 'software_version',
        'published_date', 'detected_date', 'fix_available', 'recommendation_id'
    ]

    REC_CANONICAL = [
        'recommendation_id', 'recommendation_title', 'category', 'severity',
        'exposure_reduction', 'product', 'vendor', 'affected_devices',
        'justification', 'reference_url'
    ]

    SOFTWARE_CANONICAL = [
        'device_id', 'device_name', 'vendor', 'product', 'version',
        'install_date', 'eol_flag'
    ]

    EVENT_CANONICAL = [
        'event_time', 'device_name', 'severity', 'recommendation_id', 'cve'
    ]

    # Column alias mappings
    VULN_ALIASES = {
        'device_id': ['deviceid', 'machineid', 'machine_id', 'device_identifier'],
        'device_name': ['devicename', 'machinename', 'machine_name', 'hostname', 'host_name'],
        'cve': ['cveid', 'cve_id', 'vulnerability_id', 'vuln_id'],
        'severity': ['severity_level', 'risk_level'],
        'cvss': ['cvss_score', 'cvssscore', 'score'],
        'exposure': ['exposure_score', 'exposurescore'],
        'software_vendor': ['vendor', 'software_vendor_name', 'vendorname'],
        'software_product': ['product', 'product_name', 'productname', 'software_name'],
        'software_version': ['version', 'product_version', 'productversion'],
        'published_date': ['publisheddate', 'publish_date', 'released_date'],
        'detected_date': ['detecteddate', 'detect_date', 'discovered_date', 'first_seen'],
        'fix_available': ['fixavailable', 'fix_status', 'patch_available'],
        'recommendation_id': ['recommendationid', 'recommendation', 'rec_id']
    }

    REC_ALIASES = {
        'recommendation_id': ['recommendationid', 'recommendation', 'rec_id', 'id'],
        'recommendation_title': ['title', 'recommendationtitle', 'recommendation_name', 'name'],
        'category': ['recommendation_category', 'type', 'rec_category'],
        'severity': ['severity_level', 'risk_level'],
        'exposure_reduction': ['exposurereduction', 'exposure_impact', 'impact'],
        'product': ['product_name', 'productname', 'software'],
        'vendor': ['vendor_name', 'vendorname'],
        'affected_devices': ['affecteddevices', 'exposed_devices', 'device_count'],
        'justification': ['description', 'details', 'recommendation_details'],
        'reference_url': ['referenceurl', 'reference', 'url', 'link']
    }

    SOFTWARE_ALIASES = {
        'device_id': ['deviceid', 'machineid', 'machine_id', 'device_identifier'],
        'device_name': ['devicename', 'machinename', 'machine_name', 'hostname'],
        'vendor': ['vendor_name', 'vendorname', 'software_vendor'],
        'product': ['product_name', 'productname', 'software_name', 'software_product'],
        'version': ['product_version', 'productversion', 'software_version'],
        'install_date': ['installdate', 'installation_date', 'installed_date'],
        'eol_flag': ['eolflag', 'end_of_life', 'endoflife', 'is_eol']
    }

    EVENT_ALIASES = {
        'event_time': ['eventtime', 'timestamp', 'event_date', 'date'],
        'device_name': ['devicename', 'machinename', 'machine_name', 'hostname'],
        'severity': ['severity_level', 'risk_level'],
        'recommendation_id': ['recommendationid', 'recommendation', 'rec_id'],
        'cve': ['cveid', 'cve_id', 'vulnerability_id']
    }

    def __init__(self, config: Dict, logger: Optional[logging.Logger] = None):
        """
        Initialize SchemaNormalizer

        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)

        # Load any custom header mappings from config
        self.custom_mappings = config.get('header_mappings', {})

    def normalize_columns(self, df: pd.DataFrame, aliases: Dict[str, List[str]]) -> pd.DataFrame:
        """
        Normalize DataFrame column headers and map aliases

        Args:
            df: Input DataFrame
            aliases: Dictionary mapping canonical names to aliases

        Returns:
            DataFrame with normalized columns
        """
        if df is None:
            return None

        # First normalize all headers
        df.columns = [normalize_header(col) for col in df.columns]

        # Create mapping from normalized alias to canonical
        column_mapping = {}
        for canonical, alias_list in aliases.items():
            for alias in alias_list:
                normalized_alias = normalize_header(alias)
                if normalized_alias in df.columns and canonical not in df.columns:
                    column_mapping[normalized_alias] = canonical
                    break

        # Apply mapping
        if column_mapping:
            df = df.rename(columns=column_mapping)
            self.logger.info(f"Mapped columns: {column_mapping}")

        return df

    def normalize_vulnerabilities(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize vulnerabilities DataFrame

        Args:
            df: Raw vulnerabilities DataFrame

        Returns:
            Normalized vulnerabilities DataFrame
        """
        if df is None:
            return None

        self.logger.info("Normalizing vulnerabilities schema")

        # Normalize column headers
        df = self.normalize_columns(df, self.VULN_ALIASES)

        # Derive composite fields
        if 'device_key' not in df.columns:
            df['device_key'] = df.apply(
                lambda row: build_device_key(
                    row.get('device_id'), row.get('device_name')
                ), axis=1
            )

        if 'software_key' not in df.columns:
            df['software_key'] = df.apply(
                lambda row: build_software_key(
                    row.get('software_vendor', ''),
                    row.get('software_product', ''),
                    row.get('software_version', '')
                ), axis=1
            )

        if 'vuln_key' not in df.columns:
            df['vuln_key'] = df['cve'].fillna('').astype(str)

        # Derive severity if not present
        if 'severity' not in df.columns or df['severity'].isna().all():
            df['severity'] = df.apply(
                lambda row: derive_severity(
                    row.get('cvss'), row.get('severity')
                ), axis=1
            )

        # Derive exposure bucket
        if 'exposure_bucket' not in df.columns:
            df['exposure_bucket'] = df.apply(
                lambda row: derive_exposure(row.get('exposure')), axis=1
            )

        # Parse dates
        if 'published_date' in df.columns:
            df['published_date'] = df['published_date'].apply(
                lambda x: parse_date(x, self.logger)
            )

        if 'detected_date' in df.columns:
            df['detected_date'] = df['detected_date'].apply(
                lambda x: parse_date(x, self.logger)
            )

        # Ensure CVSS is numeric
        if 'cvss' in df.columns:
            df['cvss'] = df['cvss'].apply(lambda x: safe_float(x, 0.0))

        self.logger.info(f"Normalized vulnerabilities: {len(df)} rows")

        return df

    def normalize_recommendations(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize recommendations DataFrame

        Args:
            df: Raw recommendations DataFrame

        Returns:
            Normalized recommendations DataFrame
        """
        if df is None:
            return None

        self.logger.info("Normalizing recommendations schema")

        # Normalize column headers
        df = self.normalize_columns(df, self.REC_ALIASES)

        # Derive rec_key
        if 'rec_key' not in df.columns:
            df['rec_key'] = df['recommendation_id'].fillna('').astype(str)

        # Ensure affected_devices is numeric
        if 'affected_devices' in df.columns:
            df['affected_devices'] = df['affected_devices'].apply(
                lambda x: safe_float(x, 0.0)
            )

        # Ensure exposure_reduction is numeric
        if 'exposure_reduction' in df.columns:
            df['exposure_reduction'] = df['exposure_reduction'].apply(
                lambda x: safe_float(x, 0.0)
            )

        self.logger.info(f"Normalized recommendations: {len(df)} rows")

        return df

    def normalize_software(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize software inventory DataFrame

        Args:
            df: Raw software DataFrame

        Returns:
            Normalized software DataFrame
        """
        if df is None:
            return None

        self.logger.info("Normalizing software inventory schema")

        # Normalize column headers
        df = self.normalize_columns(df, self.SOFTWARE_ALIASES)

        # Derive composite fields
        if 'device_key' not in df.columns:
            df['device_key'] = df.apply(
                lambda row: build_device_key(
                    row.get('device_id'), row.get('device_name')
                ), axis=1
            )

        if 'software_key' not in df.columns:
            df['software_key'] = df.apply(
                lambda row: build_software_key(
                    row.get('vendor', ''),
                    row.get('product', ''),
                    row.get('version', '')
                ), axis=1
            )

        # Parse install date
        if 'install_date' in df.columns:
            df['install_date'] = df['install_date'].apply(
                lambda x: parse_date(x, self.logger)
            )

        # Normalize EOL flag to boolean
        if 'eol_flag' in df.columns:
            df['eol_flag'] = df['eol_flag'].apply(
                lambda x: str(x).lower() in ['true', '1', 'yes', 'y']
            )
        else:
            df['eol_flag'] = False

        self.logger.info(f"Normalized software inventory: {len(df)} rows")

        return df

    def normalize_events(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalize events DataFrame

        Args:
            df: Raw events DataFrame

        Returns:
            Normalized events DataFrame
        """
        if df is None:
            return None

        self.logger.info("Normalizing events schema")

        # Normalize column headers
        df = self.normalize_columns(df, self.EVENT_ALIASES)

        # Parse event time
        if 'event_time' in df.columns:
            df['event_time'] = df['event_time'].apply(
                lambda x: parse_date(x, self.logger)
            )

        # Derive device_key if needed
        if 'device_key' not in df.columns:
            df['device_key'] = df['device_name'].fillna('').astype(str)

        self.logger.info(f"Normalized events: {len(df)} rows")

        return df

    def normalize_all(self, data: Dict[str, Optional[pd.DataFrame]]) -> Dict[str, Optional[pd.DataFrame]]:
        """
        Normalize all datasets

        Args:
            data: Dictionary of raw DataFrames

        Returns:
            Dictionary of normalized DataFrames
        """
        normalized = {}

        normalized['vulnerabilities'] = self.normalize_vulnerabilities(
            data.get('vulnerabilities')
        )

        normalized['recommendations'] = self.normalize_recommendations(
            data.get('recommendations')
        )

        normalized['software'] = self.normalize_software(
            data.get('software')
        )

        normalized['events'] = self.normalize_events(
            data.get('events')
        )

        self.logger.info("Schema normalization complete")

        return normalized
