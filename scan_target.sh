#!/bin/bash
# Script to run a targeted network scan on 10.42.1.0/24 subnet

# Activate virtual environment
source venv/bin/activate

# Run the scanner with target network and exit after scan
python3 -c "
import sys
import signal
from src.core.scanners.network_discovery import NetworkScanner
from src.ui.terminal_output import terminal, MSG_SUCCESS

# Set up interrupt handler
def handle_interrupt(sig, frame):
    terminal.warning('\\nScan interrupted by user!')
    scanner.continue_scan = False
    sys.exit(0)

# Register the signal handler
signal.signal(signal.SIGINT, handle_interrupt)

try:
    scanner = NetworkScanner()
    terminal.success('Starting intensive scan of 10.42.1.0/24 network...')
    devices = scanner.scan_specific_network('10.42.1.1')
    
    if devices:
        terminal.success(f'Found {len(devices)} devices on 10.42.1.0/24 network')
        
        for device in devices:
            ip = device.get('ip', 'Unknown')
            mac = device.get('mac', 'Unknown')
            hostname = device.get('hostname', 'Unknown')
            vendor = device.get('vendor', 'Unknown')
            
            terminal.info(f'IP: {ip:<15} | MAC: {mac:<17} | Hostname: {hostname:<20} | Vendor: {vendor}')
    else:
        terminal.warning('No devices found on 10.42.1.0/24 network')
        
    terminal.success('Scan complete!')
    
except KeyboardInterrupt:
    terminal.warning('\\nScan interrupted by user!')
    if hasattr(scanner, 'continue_scan'):
        scanner.continue_scan = False
except Exception as e:
    terminal.error(f'Error during scan: {str(e)}')
"
