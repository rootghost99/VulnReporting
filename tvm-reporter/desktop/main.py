#!/usr/bin/env python3
"""
TVM Reporter - Desktop Application
Eel-based desktop GUI for processing TVM exports
"""

import eel
import os
import sys
import yaml
import tempfile
import shutil
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils import setup_logging
from src.ingest import DataLoader
from src.normalize import SchemaNormalizer
from src.validate import DataValidator
from src.model import DataModel
from src.metrics import MetricsCalculator
from src.reports import ReportGenerator


# Global state for processing
processing_state = {
    'progress': 0,
    'status': '',
    'error': None,
    'complete': False
}


def get_base_path():
    """Get base path for resources (handles PyInstaller bundling)"""
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_config_path(filename):
    """Get path to config file"""
    base = get_base_path()
    return os.path.join(base, 'config', filename)


def load_config(config_path: str) -> dict:
    """Load YAML configuration file"""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        return None


@eel.expose
def select_output_folder():
    """Open folder selection dialog"""
    import tkinter as tk
    from tkinter import filedialog

    root = tk.Tk()
    root.withdraw()
    root.wm_attributes('-topmost', 1)

    folder = filedialog.askdirectory(title="Select Output Folder")
    root.destroy()

    return folder if folder else None


@eel.expose
def select_files():
    """Open file selection dialog for CSV files"""
    import tkinter as tk
    from tkinter import filedialog

    root = tk.Tk()
    root.withdraw()
    root.wm_attributes('-topmost', 1)

    files = filedialog.askopenfilenames(
        title="Select CSV Files",
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
    )
    root.destroy()

    return list(files) if files else []


@eel.expose
def get_processing_state():
    """Get current processing state"""
    return processing_state


@eel.expose
def process_reports(vulns_path, recs_path, software_path, events_path,
                    output_folder, profile_mode, strict_mode, since_date):
    """
    Main processing function - runs the TVM Reporter pipeline
    """
    global processing_state

    # Reset state
    processing_state = {
        'progress': 0,
        'status': 'Initializing...',
        'error': None,
        'complete': False
    }

    try:
        # Validate required files
        if not vulns_path or not os.path.exists(vulns_path):
            raise ValueError("Vulnerabilities CSV file is required")
        if not recs_path or not os.path.exists(recs_path):
            raise ValueError("Recommendations CSV file is required")
        if not software_path or not os.path.exists(software_path):
            raise ValueError("Software Inventory CSV file is required")

        # Setup output directory
        if not output_folder:
            output_folder = os.path.join(os.path.expanduser("~"), "TVM_Reports")

        date_str = datetime.now().strftime('%Y-%m-%d')
        output_dir = os.path.join(output_folder, f"reports_{date_str}")
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "logs"), exist_ok=True)

        # Setup logging
        processing_state['status'] = 'Setting up logging...'
        processing_state['progress'] = 5

        logger = setup_logging(
            log_dir=os.path.join(output_dir, "logs"),
            log_level="INFO"
        )

        # Load configuration
        processing_state['status'] = 'Loading configuration...'
        processing_state['progress'] = 10

        config_path = get_config_path('config.yaml')
        owners_path = get_config_path('owners.yaml')

        config = load_config(config_path)
        owners_config = load_config(owners_path)

        if not config:
            raise ValueError(f"Could not load config from {config_path}")
        if not owners_config:
            raise ValueError(f"Could not load owners config from {owners_path}")

        # Apply options
        if since_date:
            if 'date_filters' not in config:
                config['date_filters'] = {}
            config['date_filters']['since_date'] = since_date

        if profile_mode:
            if 'profile' not in config:
                config['profile'] = {}
            config['profile']['enabled'] = True

        # Step 1: Ingest CSV files
        processing_state['status'] = 'Step 1/6: Loading CSV files...'
        processing_state['progress'] = 20

        loader = DataLoader(logger)
        data = loader.load_all(
            vulns_path=vulns_path,
            recs_path=recs_path,
            software_path=software_path,
            events_path=events_path if events_path and os.path.exists(events_path) else None
        )

        # Apply profile mode sampling
        if config.get('profile', {}).get('enabled'):
            sample_size = config['profile'].get('sample_size', 1000)
            logger.info(f"Profile mode: sampling {sample_size} rows per dataset")
            for key, df in data.items():
                if df is not None and len(df) > sample_size:
                    data[key] = df.sample(n=sample_size, random_state=42)

        # Step 2: Normalize schemas
        processing_state['status'] = 'Step 2/6: Normalizing data schemas...'
        processing_state['progress'] = 35

        normalizer = SchemaNormalizer(config, logger)
        data = normalizer.normalize_all(data)

        # Apply date filtering
        if since_date:
            from app import filter_by_date
            data = filter_by_date(data, since_date, logger)

        # Step 3: Validate datasets
        processing_state['status'] = 'Step 3/6: Validating datasets...'
        processing_state['progress'] = 50

        validator = DataValidator(
            config,
            log_dir=os.path.join(output_dir, "logs"),
            strict=strict_mode,
            logger=logger
        )
        data = validator.validate_all(data)

        # Step 4: Build data model
        processing_state['status'] = 'Step 4/6: Building data model...'
        processing_state['progress'] = 65

        model_builder = DataModel(config, logger)
        model = model_builder.build_model(data)

        # Step 5: Compute metrics
        processing_state['status'] = 'Step 5/6: Computing metrics...'
        processing_state['progress'] = 80

        metrics_calc = MetricsCalculator(config, logger)
        metrics = metrics_calc.compute_all(model)

        # Step 6: Generate reports
        processing_state['status'] = 'Step 6/6: Generating reports...'
        processing_state['progress'] = 90

        report_gen = ReportGenerator(
            config,
            owners_config,
            output_dir=output_dir,
            logger=logger
        )
        report_paths = report_gen.generate_all_reports(model, metrics)

        # Complete
        processing_state['progress'] = 100
        processing_state['status'] = 'Processing complete!'
        processing_state['complete'] = True

        # Return summary
        summary = metrics.get('summary', {})
        return {
            'success': True,
            'output_dir': report_gen.report_dir,
            'summary': {
                'total_cves': summary.get('total_cves', 0),
                'total_devices': summary.get('total_devices', 0),
                'total_products': summary.get('total_products', 0),
                'critical_count': summary.get('critical_count', 0),
                'high_count': summary.get('high_count', 0),
                'medium_count': summary.get('medium_count', 0),
                'low_count': summary.get('low_count', 0),
            },
            'reports': [os.path.basename(p) for p in report_paths] if report_paths else []
        }

    except Exception as e:
        processing_state['error'] = str(e)
        processing_state['status'] = f'Error: {str(e)}'
        return {
            'success': False,
            'error': str(e)
        }


@eel.expose
def open_folder(folder_path):
    """Open folder in system file explorer"""
    import subprocess
    import platform

    if platform.system() == 'Windows':
        os.startfile(folder_path)
    elif platform.system() == 'Darwin':  # macOS
        subprocess.run(['open', folder_path])
    else:  # Linux
        subprocess.run(['xdg-open', folder_path])


@eel.expose
def get_app_info():
    """Get application information"""
    return {
        'name': 'TVM Reporter',
        'version': '1.0.0',
        'description': 'Microsoft Defender TVM Export Analyzer'
    }


def main():
    """Main entry point"""
    # Initialize Eel with web folder
    web_folder = os.path.join(os.path.dirname(__file__), 'web')
    eel.init(web_folder)

    # Start the application
    try:
        eel.start(
            'index.html',
            size=(1200, 800),
            position=(100, 100),
            port=0,  # Auto-select available port
            mode='chrome',  # Try Chrome first
            cmdline_args=['--disable-gpu']  # Helps with some systems
        )
    except EnvironmentError:
        # If Chrome not found, try default browser
        try:
            eel.start(
                'index.html',
                size=(1200, 800),
                position=(100, 100),
                port=0,
                mode='edge'  # Try Edge on Windows
            )
        except EnvironmentError:
            # Fall back to default browser
            eel.start(
                'index.html',
                size=(1200, 800),
                position=(100, 100),
                port=8080,
                mode=None,
                host='localhost'
            )


if __name__ == '__main__':
    main()
