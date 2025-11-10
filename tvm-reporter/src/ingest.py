"""
CSV ingestion module for TVM Reporter
"""

import pandas as pd
import logging
from typing import Optional, Dict


class DataLoader:
    """Load and parse CSV files"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize DataLoader

        Args:
            logger: Logger instance for logging
        """
        self.logger = logger or logging.getLogger(__name__)

    def load_csv(self, filepath: str, required: bool = True) -> Optional[pd.DataFrame]:
        """
        Load CSV file into DataFrame

        Args:
            filepath: Path to CSV file
            required: Whether file is required (error if missing)

        Returns:
            DataFrame or None if file not found and not required
        """
        try:
            df = pd.read_csv(filepath, encoding='utf-8-sig', low_memory=False)
            self.logger.info(f"Loaded {len(df)} rows from {filepath}")
            return df
        except FileNotFoundError:
            if required:
                self.logger.error(f"Required file not found: {filepath}")
                raise
            else:
                self.logger.warning(f"Optional file not found: {filepath}")
                return None
        except Exception as e:
            self.logger.error(f"Error loading {filepath}: {str(e)}")
            raise

    def load_all(
        self,
        vulns_path: Optional[str] = None,
        recs_path: Optional[str] = None,
        software_path: Optional[str] = None,
        events_path: Optional[str] = None
    ) -> Dict[str, Optional[pd.DataFrame]]:
        """
        Load all input CSV files

        Args:
            vulns_path: Path to vulnerabilities CSV
            recs_path: Path to recommendations CSV
            software_path: Path to software inventory CSV
            events_path: Path to events CSV (optional)

        Returns:
            Dictionary containing loaded DataFrames
        """
        data = {}

        if vulns_path:
            data['vulnerabilities'] = self.load_csv(vulns_path, required=True)
        else:
            data['vulnerabilities'] = None

        if recs_path:
            data['recommendations'] = self.load_csv(recs_path, required=True)
        else:
            data['recommendations'] = None

        if software_path:
            data['software'] = self.load_csv(software_path, required=True)
        else:
            data['software'] = None

        if events_path:
            data['events'] = self.load_csv(events_path, required=False)
        else:
            data['events'] = None

        self.logger.info(f"Data loading complete. Loaded {sum(1 for v in data.values() if v is not None)} datasets")

        return data
