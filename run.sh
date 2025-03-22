#!/bin/bash

# NetScan launcher script
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
VENV_DIR="$SCRIPT_DIR/venv"

# Check if running as root (required for network scanning)
if [ "$EUID" -ne 0 ]; then
  echo -e "\e[31mThis application requires root privileges for network scanning.\e[0m"
  echo -e "\e[31mPlease run with: sudo $0\e[0m"
  exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
  echo -e "\e[32mSetting up virtual environment...\e[0m"
  python3 -m venv "$VENV_DIR"
  
  # Install dependencies
  "$VENV_DIR/bin/pip" install -r "$SCRIPT_DIR/requirements.txt"
fi

# Run the application using the python from virtual environment
echo -e "\e[32mLaunching NetScan...\e[0m"
"$VENV_DIR/bin/python" "$SCRIPT_DIR/main.py"
