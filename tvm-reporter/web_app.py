#!/usr/bin/env python3
"""
TVM Reporter - Web Interface
Streamlit-based web UI for processing TVM exports without command line
"""

import streamlit as st
import os
import sys
import yaml
import tempfile
import shutil
from datetime import datetime
from io import BytesIO
import zipfile

from src.utils import setup_logging
from src.ingest import DataLoader
from src.normalize import SchemaNormalizer
from src.validate import DataValidator
from src.model import DataModel
from src.metrics import MetricsCalculator
from src.reports import ReportGenerator


def load_config(config_path: str) -> dict:
    """Load YAML configuration file"""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        st.error(f"Error loading config from {config_path}: {str(e)}")
        return None


def save_uploaded_file(uploaded_file, temp_dir):
    """Save uploaded file to temporary directory"""
    if uploaded_file is not None:
        file_path = os.path.join(temp_dir, uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return file_path
    return None


def create_download_zip(report_dir):
    """Create a zip file of all generated reports"""
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(report_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, report_dir)
                zip_file.write(file_path, arcname)
    zip_buffer.seek(0)
    return zip_buffer


def run_tvm_reporter(vulns_file, recs_file, software_file, events_file,
                     config_path, owners_path, profile_mode, strict_mode,
                     since_date, temp_dir):
    """Run the TVM Reporter processing pipeline"""

    # Create output directories in temp
    output_dir = os.path.join(temp_dir, "output")
    os.makedirs(f"{output_dir}/reports", exist_ok=True)
    os.makedirs(f"{output_dir}/logs", exist_ok=True)

    # Setup logging
    logger = setup_logging(
        log_dir=f"{output_dir}/logs",
        log_level="INFO"
    )

    progress_bar = st.progress(0)
    status_text = st.empty()

    try:
        # Load configuration files
        status_text.text("Loading configuration files...")
        progress_bar.progress(10)
        config = load_config(config_path)
        owners_config = load_config(owners_path)

        if not config or not owners_config:
            return None, None

        # Override config with options
        if since_date:
            if 'date_filters' not in config:
                config['date_filters'] = {}
            config['date_filters']['since_date'] = since_date
        if profile_mode:
            if 'profile' not in config:
                config['profile'] = {}
            config['profile']['enabled'] = True

        # Step 1: Ingest CSV files
        status_text.text("Step 1/6: Loading CSV files...")
        progress_bar.progress(20)
        loader = DataLoader(logger)
        data = loader.load_all(
            vulns_path=vulns_file,
            recs_path=recs_file,
            software_path=software_file,
            events_path=events_file
        )

        # Apply profile mode sampling if enabled
        if config.get('profile', {}).get('enabled'):
            sample_size = config['profile'].get('sample_size', 1000)
            logger.info(f"Profile mode: sampling {sample_size} rows per dataset")
            for key, df in data.items():
                if df is not None and len(df) > sample_size:
                    data[key] = df.sample(n=sample_size, random_state=42)

        # Step 2: Normalize schemas
        status_text.text("Step 2/6: Normalizing data schemas...")
        progress_bar.progress(35)
        normalizer = SchemaNormalizer(config, logger)
        data = normalizer.normalize_all(data)

        # Apply date filtering if specified
        if since_date:
            from app import filter_by_date
            data = filter_by_date(data, since_date, logger)

        # Step 3: Validate datasets
        status_text.text("Step 3/6: Validating datasets...")
        progress_bar.progress(50)
        validator = DataValidator(
            config,
            log_dir=f"{output_dir}/logs",
            strict=strict_mode,
            logger=logger
        )
        data = validator.validate_all(data)

        # Step 4: Build data model
        status_text.text("Step 4/6: Building data model...")
        progress_bar.progress(65)
        model_builder = DataModel(config, logger)
        model = model_builder.build_model(data)

        # Step 5: Compute metrics
        status_text.text("Step 5/6: Computing metrics...")
        progress_bar.progress(80)
        metrics_calc = MetricsCalculator(config, logger)
        metrics = metrics_calc.compute_all(model)

        # Step 6: Generate reports
        status_text.text("Step 6/6: Generating reports...")
        progress_bar.progress(90)
        report_gen = ReportGenerator(
            config,
            owners_config,
            output_dir=output_dir,
            logger=logger
        )
        report_paths = report_gen.generate_all_reports(model, metrics)

        progress_bar.progress(100)
        status_text.text("Processing complete!")

        return metrics, report_gen.report_dir

    except Exception as e:
        logger.error(f"Fatal error: {str(e)}", exc_info=True)
        st.error(f"Processing failed: {str(e)}")
        return None, None


def main():
    """Main Streamlit application"""

    st.set_page_config(
        page_title="TVM Reporter",
        page_icon="🛡️",
        layout="wide"
    )

    st.title("🛡️ TVM Reporter - Web Interface")
    st.markdown("Process Microsoft Defender for Endpoint TVM exports without command line")

    st.markdown("---")

    # File upload section
    st.header("📁 Upload CSV Files")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Required Files")
        vulns_file = st.file_uploader(
            "Vulnerabilities CSV",
            type=['csv'],
            help="Upload your vulnerabilities export CSV file"
        )
        recs_file = st.file_uploader(
            "Recommendations CSV",
            type=['csv'],
            help="Upload your recommendations export CSV file"
        )
        software_file = st.file_uploader(
            "Software Inventory CSV",
            type=['csv'],
            help="Upload your software inventory export CSV file"
        )

    with col2:
        st.subheader("Optional Files")
        events_file = st.file_uploader(
            "Events CSV (Optional)",
            type=['csv'],
            help="Upload events CSV for trend analysis (optional)"
        )

        st.markdown("### Configuration Files")
        st.info("Using default config files from `config/` directory")

    # Options section
    st.markdown("---")
    st.header("⚙️ Processing Options")

    col1, col2, col3 = st.columns(3)

    with col1:
        profile_mode = st.checkbox(
            "Profile Mode",
            help="Enable quick analysis with data sampling (faster processing)"
        )

    with col2:
        strict_mode = st.checkbox(
            "Strict Validation",
            help="Exit on validation errors"
        )

    with col3:
        since_date = st.date_input(
            "Filter Since Date (Optional)",
            value=None,
            help="Only include vulnerabilities detected after this date"
        )

    # Process button
    st.markdown("---")

    if st.button("🚀 Process Reports", type="primary", use_container_width=True):

        # Validate required files
        if not vulns_file or not recs_file or not software_file:
            st.error("⚠️ Please upload all required CSV files (Vulnerabilities, Recommendations, Software Inventory)")
            return

        # Create temporary directory for processing
        temp_dir = tempfile.mkdtemp()

        try:
            with st.spinner("Processing your TVM exports..."):

                # Save uploaded files
                vulns_path = save_uploaded_file(vulns_file, temp_dir)
                recs_path = save_uploaded_file(recs_file, temp_dir)
                software_path = save_uploaded_file(software_file, temp_dir)
                events_path = save_uploaded_file(events_file, temp_dir) if events_file else None

                # Convert date to string if provided
                since_date_str = since_date.strftime('%Y-%m-%d') if since_date else None

                # Run the reporter
                metrics, report_dir = run_tvm_reporter(
                    vulns_path,
                    recs_path,
                    software_path,
                    events_path,
                    'config/config.yaml',
                    'config/owners.yaml',
                    profile_mode,
                    strict_mode,
                    since_date_str,
                    temp_dir
                )

                if metrics and report_dir:
                    # Display summary
                    st.success("✅ Processing completed successfully!")

                    st.markdown("---")
                    st.header("📊 Summary")

                    summary = metrics.get('summary', {})

                    col1, col2, col3, col4 = st.columns(4)

                    with col1:
                        st.metric("Total CVEs", summary.get('total_cves', 0))
                        st.metric("Total Devices", summary.get('total_devices', 0))

                    with col2:
                        st.metric("Critical", summary.get('critical_count', 0))
                        st.metric("High", summary.get('high_count', 0))

                    with col3:
                        st.metric("Medium", summary.get('medium_count', 0))
                        st.metric("Low", summary.get('low_count', 0))

                    with col4:
                        st.metric("Total Products", summary.get('total_products', 0))
                        st.metric("Total Recommendations", summary.get('total_recommendations', 0))

                    # Download section
                    st.markdown("---")
                    st.header("📥 Download Reports")

                    # Create zip of all reports
                    zip_buffer = create_download_zip(report_dir)

                    st.download_button(
                        label="⬇️ Download All Reports (ZIP)",
                        data=zip_buffer,
                        file_name=f"tvm_reports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                        mime="application/zip",
                        use_container_width=True,
                        type="primary"
                    )

                    # List individual reports
                    st.markdown("### Individual Reports")
                    for root, dirs, files in os.walk(report_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            with open(file_path, 'rb') as f:
                                file_data = f.read()

                            st.download_button(
                                label=f"📄 {file}",
                                data=file_data,
                                file_name=file,
                                mime="application/octet-stream",
                                key=file
                            )

        finally:
            # Cleanup temporary directory
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                st.warning(f"Could not cleanup temporary files: {e}")

    # Information section
    st.markdown("---")
    with st.expander("ℹ️ How to Use This Tool"):
        st.markdown("""
        ### Step-by-Step Guide

        1. **Upload Required CSV Files**
           - Export Vulnerabilities, Recommendations, and Software Inventory from Microsoft Defender for Endpoint TVM
           - Upload each file using the file upload buttons above

        2. **Optional: Upload Events CSV**
           - For trend analysis, upload the Events CSV file

        3. **Configure Options**
           - **Profile Mode**: Enable for faster processing with data sampling (recommended for large datasets)
           - **Strict Validation**: Enable to stop processing if validation errors occur
           - **Filter Since Date**: Only process vulnerabilities detected after this date

        4. **Process Reports**
           - Click the "Process Reports" button to start processing
           - Wait for the progress bar to complete

        5. **Download Results**
           - View the summary statistics
           - Download all reports as a ZIP file, or individual reports

        ### Generated Reports

        - **Remediation_Plan.csv**: Critical and High severity vulnerabilities with owner assignments
        - **CVE_By_Device.csv**: Devices grouped with their CVEs
        - **Device_By_CVE.csv**: CVEs grouped with affected devices
        - **Software_Risk_Priorities.csv**: Software risk scoring and EOL status
        - **Datasets_Profile.csv**: Summary statistics
        - **Executive_Snapshot.pdf**: Executive summary with top CVEs, products, and recommendations

        ### Need Help?

        - Check the [README.md](README.md) for detailed documentation
        - Review configuration files in `config/` directory
        - Contact Security Operations team for support
        """)


if __name__ == "__main__":
    main()
