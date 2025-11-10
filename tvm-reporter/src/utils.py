"""
Utility functions for TVM Reporter
"""

import re
import logging
from datetime import datetime
from typing import Any, Optional


def setup_logging(log_dir: str, log_level: str = "INFO") -> logging.Logger:
    """
    Configure logging to file and console

    Args:
        log_dir: Directory for log files
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("tvm-reporter")
    logger.setLevel(getattr(logging, log_level.upper()))

    # File handler
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fh = logging.FileHandler(f"{log_dir}/tvm_reporter_{timestamp}.log")
    fh.setLevel(logging.DEBUG)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger


def normalize_header(header: str) -> str:
    """
    Normalize column header: lowercase, remove punctuation, collapse whitespace

    Args:
        header: Raw column header

    Returns:
        Normalized header string
    """
    # Convert to lowercase
    normalized = header.lower()
    # Remove punctuation except underscores
    normalized = re.sub(r'[^\w\s]', '', normalized)
    # Collapse multiple spaces to single underscore
    normalized = re.sub(r'\s+', '_', normalized)
    # Remove leading/trailing underscores
    normalized = normalized.strip('_')

    return normalized


def parse_date(date_str: Any, logger: Optional[logging.Logger] = None) -> Optional[str]:
    """
    Parse various date formats into ISO format (YYYY-MM-DD)

    Args:
        date_str: Date string in various formats
        logger: Logger for warnings

    Returns:
        ISO formatted date string or None if parsing fails
    """
    if not date_str or str(date_str).strip() == '' or str(date_str).lower() in ['nan', 'none', 'null']:
        return None

    date_str = str(date_str).strip()

    # Common date formats to try
    formats = [
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%m/%d/%Y",
        "%d/%m/%Y",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%fZ",
    ]

    for fmt in formats:
        try:
            parsed_date = datetime.strptime(date_str, fmt)
            return parsed_date.strftime("%Y-%m-%d")
        except ValueError:
            continue

    # Log warning if no format matched
    if logger:
        logger.warning(f"Unable to parse date: {date_str}")

    return None


def derive_severity(cvss: Any, severity_text: Any) -> str:
    """
    Derive severity bucket from CVSS score or severity text

    Args:
        cvss: CVSS score (numeric or string)
        severity_text: Severity text description

    Returns:
        Severity bucket: Critical, High, Medium, or Low
    """
    # Try to parse CVSS score
    try:
        cvss_score = float(cvss) if cvss else 0.0
        if cvss_score >= 9.0:
            return "Critical"
        elif cvss_score >= 7.0:
            return "High"
        elif cvss_score >= 4.0:
            return "Medium"
        else:
            return "Low"
    except (ValueError, TypeError):
        pass

    # Fallback to text-based severity
    if severity_text:
        severity_lower = str(severity_text).lower()
        if 'critical' in severity_lower:
            return "Critical"
        elif 'high' in severity_lower:
            return "High"
        elif 'medium' in severity_lower:
            return "Medium"
        elif 'low' in severity_lower:
            return "Low"

    return "Low"


def derive_exposure(exposure_value: Any) -> str:
    """
    Derive exposure bucket from exposure score

    Args:
        exposure_value: Exposure score (numeric or string)

    Returns:
        Exposure bucket: Very High, High, Medium, or Low
    """
    try:
        exposure = float(exposure_value) if exposure_value else 0.0
        if exposure >= 80:
            return "Very High"
        elif exposure >= 60:
            return "High"
        elif exposure >= 30:
            return "Medium"
        else:
            return "Low"
    except (ValueError, TypeError):
        return "Low"


def build_software_key(vendor: str, product: str, version: str) -> str:
    """
    Construct software key from vendor, product, and version

    Args:
        vendor: Software vendor
        product: Software product name
        version: Software version

    Returns:
        Composite software key
    """
    vendor = str(vendor).strip() if vendor else "unknown"
    product = str(product).strip() if product else "unknown"
    version = str(version).strip() if version else "unknown"

    return f"{vendor}|{product}|{version}"


def build_device_key(device_id: Any, device_name: Any) -> str:
    """
    Resolve device key using device_id or device_name

    Args:
        device_id: Device ID
        device_name: Device name

    Returns:
        Device key (preferring device_id)
    """
    if device_id and str(device_id).strip() and str(device_id).lower() not in ['nan', 'none', 'null', '']:
        return str(device_id).strip()
    elif device_name and str(device_name).strip() and str(device_name).lower() not in ['nan', 'none', 'null', '']:
        return str(device_name).strip()
    else:
        return "unknown"


def safe_str(value: Any, default: str = "") -> str:
    """
    Safely convert value to string, handling None and NaN

    Args:
        value: Any value to convert
        default: Default value if conversion fails

    Returns:
        String representation or default
    """
    if value is None or str(value).lower() in ['nan', 'none', 'null']:
        return default
    return str(value).strip()


def safe_float(value: Any, default: float = 0.0) -> float:
    """
    Safely convert value to float

    Args:
        value: Any value to convert
        default: Default value if conversion fails

    Returns:
        Float value or default
    """
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    """
    Safely convert value to integer

    Args:
        value: Any value to convert
        default: Default value if conversion fails

    Returns:
        Integer value or default
    """
    try:
        return int(float(value))
    except (ValueError, TypeError):
        return default
