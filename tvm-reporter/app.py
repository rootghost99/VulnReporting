#!/usr/bin/env python3
"""
TVM Reporter - Microsoft Defender for Endpoint TVM Export Processor

Main application entry point with CLI argument parsing.
"""

import argparse
import sys
import yaml
import os
from datetime import datetime

from src.utils import setup_logging
from src.ingest import DataLoader
from src.normalize import SchemaNormalizer
from src.validate import DataValidator
from src.model import DataModel
from src.metrics import MetricsCalculator
from src.reports import ReportGenerator


def load_config(config_path: str) -> dict:
    """
    Load YAML configuration file

    Args:
        config_path: Path to config file

    Returns:
        Configuration dictionary
    """
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        print(f"Error loading config from {config_path}: {str(e)}")
        sys.exit(1)


def parse_arguments():
    """
    Parse command line arguments

    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='TVM Reporter - Process Microsoft Defender TVM exports'
    )

    # Required input files
    parser.add_argument(
        '--vulns',
        required=True,
        help='Path to vulnerabilities CSV file'
    )

    parser.add_argument(
        '--recs',
        required=True,
        help='Path to recommendations CSV file'
    )

    parser.add_argument(
        '--software',
        required=True,
        help='Path to software inventory CSV file'
    )

    parser.add_argument(
        '--events',
        required=False,
        help='Path to events CSV file (optional)'
    )

    # Configuration files
    parser.add_argument(
        '--config',
        default='config/config.yaml',
        help='Path to configuration YAML file (default: config/config.yaml)'
    )

    parser.add_argument(
        '--owners',
        default='config/owners.yaml',
        help='Path to owners YAML file (default: config/owners.yaml)'
    )

    # Output directory
    parser.add_argument(
        '--out',
        default='output',
        help='Output directory for reports (default: output)'
    )

    # Optional flags
    parser.add_argument(
        '--profile',
        action='store_true',
        help='Enable profile mode (quick analysis with sampling)'
    )

    parser.add_argument(
        '--strict',
        action='store_true',
        help='Enable strict validation mode (exit on validation errors)'
    )

    parser.add_argument(
        '--since',
        help='Only include vulnerabilities detected since date (YYYY-MM-DD)'
    )

    return parser.parse_args()


def filter_by_date(data: dict, since_date: str, logger):
    """
    Filter vulnerabilities by detection date

    Args:
        data: Dictionary of DataFrames
        since_date: Date string in YYYY-MM-DD format
        logger: Logger instance

    Returns:
        Filtered data dictionary
    """
    if not since_date:
        return data

    try:
        since_dt = datetime.strptime(since_date, '%Y-%m-%d')
        logger.info(f"Filtering vulnerabilities detected since {since_date}")

        vulns = data.get('vulnerabilities')
        if vulns is not None and 'detected_date' in vulns.columns:
            original_count = len(vulns)
            vulns['detected_date_dt'] = vulns['detected_date'].apply(
                lambda x: datetime.strptime(x, '%Y-%m-%d') if x else None
            )
            vulns = vulns[vulns['detected_date_dt'] >= since_dt]
            data['vulnerabilities'] = vulns.drop(columns=['detected_date_dt'])
            logger.info(f"Filtered vulnerabilities: {original_count} -> {len(vulns)}")

    except Exception as e:
        logger.warning(f"Date filtering failed: {str(e)}")

    return data


def main():
    """Main application entry point"""

    # Parse command line arguments
    args = parse_arguments()

    # Create output directories
    os.makedirs(f"{args.out}/reports", exist_ok=True)
    os.makedirs(f"{args.out}/logs", exist_ok=True)

    # Setup logging
    logger = setup_logging(
        log_dir=f"{args.out}/logs",
        log_level="INFO"
    )

    logger.info("=" * 60)
    logger.info("TVM Reporter - Starting execution")
    logger.info("=" * 60)

    try:
        # Load configuration files
        logger.info("Loading configuration files")
        config = load_config(args.config)
        owners_config = load_config(args.owners)

        # Override config with CLI arguments
        if args.since:
            config['date_filters']['since_date'] = args.since
        if args.profile:
            config['profile']['enabled'] = True

        # Step 1: Ingest CSV files
        logger.info("Step 1: Ingesting CSV files")
        loader = DataLoader(logger)
        data = loader.load_all(
            vulns_path=args.vulns,
            recs_path=args.recs,
            software_path=args.software,
            events_path=args.events
        )

        # Apply profile mode sampling if enabled
        if config.get('profile', {}).get('enabled'):
            sample_size = config['profile'].get('sample_size', 1000)
            logger.info(f"Profile mode: sampling {sample_size} rows per dataset")
            for key, df in data.items():
                if df is not None and len(df) > sample_size:
                    data[key] = df.sample(n=sample_size, random_state=42)

        # Step 2: Normalize schemas
        logger.info("Step 2: Normalizing schemas")
        normalizer = SchemaNormalizer(config, logger)
        data = normalizer.normalize_all(data)

        # Apply date filtering if specified
        if args.since:
            data = filter_by_date(data, args.since, logger)

        # Step 3: Validate datasets
        logger.info("Step 3: Validating datasets")
        validator = DataValidator(
            config,
            log_dir=f"{args.out}/logs",
            strict=args.strict,
            logger=logger
        )
        data = validator.validate_all(data)

        # Step 4: Build data model
        logger.info("Step 4: Building data model")
        model_builder = DataModel(config, logger)
        model = model_builder.build_model(data)

        # Step 5: Compute metrics
        logger.info("Step 5: Computing metrics")
        metrics_calc = MetricsCalculator(config, logger)
        metrics = metrics_calc.compute_all(model)

        # Step 6: Generate reports
        logger.info("Step 6: Generating reports")
        report_gen = ReportGenerator(
            config,
            owners_config,
            output_dir=args.out,
            logger=logger
        )
        report_paths = report_gen.generate_all_reports(model, metrics)

        # Summary
        logger.info("=" * 60)
        logger.info("TVM Reporter - Execution completed successfully")
        logger.info("=" * 60)
        logger.info("Generated reports:")
        for report_name, report_path in report_paths.items():
            if report_path:
                logger.info(f"  - {report_name}: {report_path}")

        logger.info("=" * 60)

        # Print summary to console
        summary = metrics.get('summary', {})
        print("\n" + "=" * 60)
        print("TVM REPORTER - EXECUTION SUMMARY")
        print("=" * 60)
        print(f"Total CVEs:               {summary.get('total_cves', 0)}")
        print(f"Total Devices:            {summary.get('total_devices', 0)}")
        print(f"Total Products:           {summary.get('total_products', 0)}")
        print(f"Critical Vulnerabilities: {summary.get('critical_count', 0)}")
        print(f"High Vulnerabilities:     {summary.get('high_count', 0)}")
        print(f"Medium Vulnerabilities:   {summary.get('medium_count', 0)}")
        print(f"Low Vulnerabilities:      {summary.get('low_count', 0)}")
        print("=" * 60)
        print(f"\nReports written to: {report_gen.report_dir}")
        print("=" * 60 + "\n")

        return 0

    except Exception as e:
        logger.error(f"Fatal error: {str(e)}", exc_info=True)
        print(f"\nERROR: {str(e)}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
