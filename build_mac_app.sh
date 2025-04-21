#!/bin/bash

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install required packages
pip install -r requirements.txt
pip install pyinstaller

# Build the application
pyinstaller --clean network_security_tool.spec

# Create a DMG file
hdiutil create -volname "Network Security Tool" -srcfolder dist/Network\ Security\ Tool.app -ov -format UDZO dist/NetworkSecurityTool.dmg

echo "Build complete! The application is available in the dist folder."
echo "You can find the DMG file at: dist/NetworkSecurityTool.dmg" 