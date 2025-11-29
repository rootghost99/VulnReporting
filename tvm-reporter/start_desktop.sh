#!/bin/bash
# TVM Reporter Desktop Application Launcher

echo "=========================================="
echo "  TVM Reporter - Desktop Application"
echo "=========================================="
echo ""
echo "Starting desktop application..."
echo ""

cd "$(dirname "$0")"
python desktop/main.py
