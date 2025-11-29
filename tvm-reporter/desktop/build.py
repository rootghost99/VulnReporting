#!/usr/bin/env python3
"""
TVM Reporter - Build Script
Creates standalone executable using PyInstaller
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path


def get_project_root():
    """Get the project root directory"""
    return Path(__file__).parent.parent.absolute()


def clean_build():
    """Clean previous build artifacts"""
    project_root = get_project_root()
    desktop_dir = project_root / 'desktop'

    dirs_to_clean = [
        desktop_dir / 'build',
        desktop_dir / 'dist',
        project_root / 'build',
        project_root / 'dist',
    ]

    for dir_path in dirs_to_clean:
        if dir_path.exists():
            print(f"Cleaning {dir_path}...")
            shutil.rmtree(dir_path)

    # Clean spec files
    for spec_file in desktop_dir.glob('*.spec'):
        print(f"Removing {spec_file}...")
        spec_file.unlink()


def build_executable():
    """Build the executable using PyInstaller"""
    project_root = get_project_root()
    desktop_dir = project_root / 'desktop'
    src_dir = project_root / 'src'
    config_dir = project_root / 'config'
    web_dir = desktop_dir / 'web'

    # Change to desktop directory
    os.chdir(desktop_dir)

    # PyInstaller command
    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--name=TVM-Reporter',
        '--onefile',  # Single executable
        '--windowed',  # No console window
        '--icon=web/favicon.ico' if (web_dir / 'favicon.ico').exists() else '',

        # Add data files
        f'--add-data={web_dir}{os.pathsep}web',
        f'--add-data={config_dir}{os.pathsep}config',
        f'--add-data={src_dir}{os.pathsep}src',
        f'--add-data={project_root / "app.py"}{os.pathsep}.',

        # Hidden imports (dependencies that PyInstaller might miss)
        '--hidden-import=eel',
        '--hidden-import=bottle_websocket',
        '--hidden-import=pandas',
        '--hidden-import=yaml',
        '--hidden-import=reportlab',
        '--hidden-import=reportlab.lib',
        '--hidden-import=reportlab.lib.colors',
        '--hidden-import=reportlab.lib.pagesizes',
        '--hidden-import=reportlab.lib.styles',
        '--hidden-import=reportlab.lib.units',
        '--hidden-import=reportlab.platypus',
        '--hidden-import=reportlab.pdfgen',
        '--hidden-import=tkinter',
        '--hidden-import=tkinter.filedialog',

        # Collect all from eel
        '--collect-all=eel',

        # Entry point
        'main.py',
    ]

    # Remove empty arguments
    cmd = [c for c in cmd if c]

    print("Building executable...")
    print(f"Command: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=False)

    if result.returncode == 0:
        print("\n" + "=" * 50)
        print("BUILD SUCCESSFUL!")
        print("=" * 50)

        dist_dir = desktop_dir / 'dist'
        if sys.platform == 'win32':
            exe_path = dist_dir / 'TVM-Reporter.exe'
        else:
            exe_path = dist_dir / 'TVM-Reporter'

        if exe_path.exists():
            print(f"\nExecutable created at: {exe_path}")
            print(f"Size: {exe_path.stat().st_size / (1024*1024):.1f} MB")
        else:
            print(f"\nLooking for executable in: {dist_dir}")
            for f in dist_dir.iterdir():
                print(f"  - {f.name}")

        print("\nTo run the application:")
        if sys.platform == 'win32':
            print(f"  {exe_path}")
        else:
            print(f"  ./{exe_path.name}")

    else:
        print("\n" + "=" * 50)
        print("BUILD FAILED!")
        print("=" * 50)
        sys.exit(1)


def create_spec_file():
    """Create a PyInstaller spec file for more control"""
    project_root = get_project_root()
    desktop_dir = project_root / 'desktop'

    spec_content = f'''# -*- mode: python ; coding: utf-8 -*-

import os
import sys
from pathlib import Path

block_cipher = None

project_root = Path(r'{project_root}')
desktop_dir = project_root / 'desktop'

a = Analysis(
    ['main.py'],
    pathex=[str(project_root), str(desktop_dir)],
    binaries=[],
    datas=[
        (str(desktop_dir / 'web'), 'web'),
        (str(project_root / 'config'), 'config'),
        (str(project_root / 'src'), 'src'),
        (str(project_root / 'app.py'), '.'),
    ],
    hiddenimports=[
        'eel',
        'bottle_websocket',
        'pandas',
        'yaml',
        'reportlab',
        'reportlab.lib',
        'reportlab.lib.colors',
        'reportlab.lib.pagesizes',
        'reportlab.lib.styles',
        'reportlab.lib.units',
        'reportlab.platypus',
        'reportlab.pdfgen',
        'tkinter',
        'tkinter.filedialog',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Collect eel files
from PyInstaller.utils.hooks import collect_all
eel_datas, eel_binaries, eel_hiddenimports = collect_all('eel')
a.datas += eel_datas
a.binaries += eel_binaries
a.hiddenimports += eel_hiddenimports

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='TVM-Reporter',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Set to True for debugging
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
'''

    spec_path = desktop_dir / 'TVM-Reporter.spec'
    with open(spec_path, 'w') as f:
        f.write(spec_content)

    print(f"Created spec file: {spec_path}")
    return spec_path


def build_from_spec():
    """Build using the spec file"""
    project_root = get_project_root()
    desktop_dir = project_root / 'desktop'

    spec_path = create_spec_file()

    os.chdir(desktop_dir)

    cmd = [
        sys.executable, '-m', 'PyInstaller',
        '--clean',
        str(spec_path),
    ]

    print("Building from spec file...")
    result = subprocess.run(cmd, capture_output=False)

    return result.returncode == 0


def main():
    """Main build script entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Build TVM Reporter executable')
    parser.add_argument('--clean', action='store_true', help='Clean build artifacts only')
    parser.add_argument('--spec', action='store_true', help='Build using spec file (more control)')

    args = parser.parse_args()

    if args.clean:
        clean_build()
        print("Clean complete!")
        return

    # Clean first
    clean_build()

    # Build
    if args.spec:
        success = build_from_spec()
    else:
        build_executable()


if __name__ == '__main__':
    main()
