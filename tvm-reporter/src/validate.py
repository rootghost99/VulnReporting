"""
Data validation module for TVM Reporter
"""

import pandas as pd
import logging
import sys
from typing import Optional, Dict, List, Tuple
from datetime import datetime


class DataValidator:
    """Validate normalized datasets"""

    def __init__(
        self,
        config: Dict,
        log_dir: str,
        strict: bool = False,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initialize DataValidator

        Args:
            config: Configuration dictionary
            log_dir: Directory for validation logs
            strict: Enable strict mode (exit on validation failure)
            logger: Logger instance
        """
        self.config = config
        self.log_dir = log_dir
        self.strict = strict
        self.logger = logger or logging.getLogger(__name__)
        self.validation_results = []

    def check_required_columns(
        self,
        df: pd.DataFrame,
        required_columns: List[str],
        dataset_name: str
    ) -> Tuple[bool, List[str]]:
        """
        Check if required columns exist in DataFrame

        Args:
            df: DataFrame to validate
            required_columns: List of required column names
            dataset_name: Name of dataset for logging

        Returns:
            Tuple of (is_valid, missing_columns)
        """
        if df is None:
            self.logger.warning(f"{dataset_name} dataset is None")
            return False, required_columns

        missing = [col for col in required_columns if col not in df.columns]

        if missing:
            self.logger.warning(
                f"{dataset_name} missing required columns: {missing}"
            )
            self.validation_results.append({
                'dataset': dataset_name,
                'check': 'required_columns',
                'status': 'FAIL',
                'details': f"Missing: {missing}"
            })
            return False, missing
        else:
            self.logger.info(
                f"{dataset_name} has all required columns"
            )
            self.validation_results.append({
                'dataset': dataset_name,
                'check': 'required_columns',
                'status': 'PASS',
                'details': 'All required columns present'
            })
            return True, []

    def check_duplicates(
        self,
        df: pd.DataFrame,
        key_columns: List[str],
        dataset_name: str
    ) -> pd.DataFrame:
        """
        Check for and remove duplicate records

        Args:
            df: DataFrame to check
            key_columns: Columns that define uniqueness
            dataset_name: Name of dataset for logging

        Returns:
            DataFrame with duplicates removed
        """
        if df is None:
            return None

        # Check if key columns exist
        existing_keys = [col for col in key_columns if col in df.columns]

        if not existing_keys:
            self.logger.warning(
                f"{dataset_name}: No key columns found for duplicate check"
            )
            return df

        initial_count = len(df)
        df_deduped = df.drop_duplicates(subset=existing_keys, keep='first')
        final_count = len(df_deduped)
        duplicates_removed = initial_count - final_count

        if duplicates_removed > 0:
            self.logger.warning(
                f"{dataset_name}: Removed {duplicates_removed} duplicate records"
            )
            self.validation_results.append({
                'dataset': dataset_name,
                'check': 'duplicates',
                'status': 'WARN',
                'details': f"Removed {duplicates_removed} duplicates"
            })
        else:
            self.logger.info(f"{dataset_name}: No duplicates found")
            self.validation_results.append({
                'dataset': dataset_name,
                'check': 'duplicates',
                'status': 'PASS',
                'details': 'No duplicates found'
            })

        return df_deduped

    def check_data_quality(
        self,
        df: pd.DataFrame,
        critical_columns: List[str],
        dataset_name: str
    ) -> None:
        """
        Check data quality metrics

        Args:
            df: DataFrame to check
            critical_columns: Columns that should not be null
            dataset_name: Name of dataset for logging
        """
        if df is None:
            return

        for col in critical_columns:
            if col not in df.columns:
                continue

            null_count = df[col].isna().sum()
            null_pct = (null_count / len(df)) * 100 if len(df) > 0 else 0

            if null_pct > 0:
                self.logger.warning(
                    f"{dataset_name}.{col}: {null_count} ({null_pct:.1f}%) null values"
                )
                self.validation_results.append({
                    'dataset': dataset_name,
                    'check': f'null_check_{col}',
                    'status': 'WARN',
                    'details': f"{null_count} ({null_pct:.1f}%) null values"
                })

    def validate_vulnerabilities(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Validate vulnerabilities dataset

        Args:
            df: Vulnerabilities DataFrame

        Returns:
            Validated and cleaned DataFrame
        """
        self.logger.info("Validating vulnerabilities dataset")

        required = ['device_key', 'cve', 'severity']
        self.check_required_columns(df, required, 'vulnerabilities')

        critical = ['device_key', 'cve', 'software_product']
        self.check_data_quality(df, critical, 'vulnerabilities')

        df = self.check_duplicates(df, ['device_key', 'cve'], 'vulnerabilities')

        return df

    def validate_recommendations(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Validate recommendations dataset

        Args:
            df: Recommendations DataFrame

        Returns:
            Validated and cleaned DataFrame
        """
        self.logger.info("Validating recommendations dataset")

        required = ['recommendation_id', 'recommendation_title']
        self.check_required_columns(df, required, 'recommendations')

        critical = ['recommendation_id', 'product']
        self.check_data_quality(df, critical, 'recommendations')

        df = self.check_duplicates(df, ['recommendation_id'], 'recommendations')

        return df

    def validate_software(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Validate software inventory dataset

        Args:
            df: Software DataFrame

        Returns:
            Validated and cleaned DataFrame
        """
        self.logger.info("Validating software inventory dataset")

        required = ['device_key', 'product']
        self.check_required_columns(df, required, 'software')

        critical = ['device_key', 'product', 'vendor']
        self.check_data_quality(df, critical, 'software')

        df = self.check_duplicates(df, ['device_key', 'software_key'], 'software')

        return df

    def validate_events(self, df: pd.DataFrame) -> Optional[pd.DataFrame]:
        """
        Validate events dataset

        Args:
            df: Events DataFrame

        Returns:
            Validated and cleaned DataFrame
        """
        if df is None:
            return None

        self.logger.info("Validating events dataset")

        required = ['event_time', 'device_name']
        self.check_required_columns(df, required, 'events')

        critical = ['event_time', 'device_name']
        self.check_data_quality(df, critical, 'events')

        return df

    def validate_all(
        self,
        data: Dict[str, Optional[pd.DataFrame]]
    ) -> Dict[str, Optional[pd.DataFrame]]:
        """
        Validate all datasets

        Args:
            data: Dictionary of normalized DataFrames

        Returns:
            Dictionary of validated DataFrames
        """
        validated = {}

        validated['vulnerabilities'] = self.validate_vulnerabilities(
            data.get('vulnerabilities')
        )

        validated['recommendations'] = self.validate_recommendations(
            data.get('recommendations')
        )

        validated['software'] = self.validate_software(
            data.get('software')
        )

        validated['events'] = self.validate_events(
            data.get('events')
        )

        # Write validation log
        self.write_validation_log()

        # Check if strict mode should fail
        if self.strict:
            failures = [r for r in self.validation_results if r['status'] == 'FAIL']
            if failures:
                self.logger.error(
                    f"Validation failed in strict mode. {len(failures)} failures."
                )
                sys.exit(1)

        self.logger.info("Validation complete")

        return validated

    def write_validation_log(self) -> None:
        """Write validation results to log file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = f"{self.log_dir}/validation_{timestamp}.csv"

        df = pd.DataFrame(self.validation_results)

        if not df.empty:
            df.to_csv(log_path, index=False)
            self.logger.info(f"Validation log written to {log_path}")
