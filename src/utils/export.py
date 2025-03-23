#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import csv
from datetime import datetime

# Import terminal output system
from src.ui.terminal_output import terminal

def export_to_file(devices, filename):
    """Export scan results to a file"""
    try:
        # Get file extension
        _, ext = os.path.splitext(filename)
        ext = ext.lower()
        
        # Create output directory if it doesn't exist
        output_dir = os.path.join(os.getcwd(), 'results')
        os.makedirs(output_dir, exist_ok=True)
        
        # Full path to the output file
        output_file = os.path.join(output_dir, filename)
        
        # Export based on file type
        if ext == '.json':
            return export_to_json(devices, output_file)
        elif ext == '.csv':
            return export_to_csv(devices, output_file)
        else:
            # Default to JSON
            if '.' not in filename:
                output_file += '.json'
            return export_to_json(devices, output_file)
            
    except Exception as e:
        terminal.error(f"Error exporting data: {e}")
        return False

def export_to_json(devices, output_file):
    """Export devices to JSON file"""
    try:
        with open(output_file, 'w') as f:
            # Add metadata
            data = {
                'scan_time': datetime.now().isoformat(),
                'device_count': len(devices),
                'devices': devices
            }
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        terminal.error(f"Error exporting to JSON: {e}")
        return False

def export_to_csv(devices, output_file):
    """Export devices to CSV file"""
    try:
        with open(output_file, 'w', newline='') as f:
            # Define CSV fields
            fieldnames = ['ip', 'hostname', 'mac', 'vendor', 'status']
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for device in devices:
                # Filter to only the fields we want
                filtered_device = {field: device.get(field, 'Unknown') for field in fieldnames}
                writer.writerow(filtered_device)
                
        return True
    except Exception as e:
        terminal.error(f"Error exporting to CSV: {e}")
        return False
