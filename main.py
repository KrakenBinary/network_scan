#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import threading
from src.ui.cyber_effects import CyberEffect
from src.ui.console_ui import NetScanConsole
from src.core.scanners.network_discovery import NetworkScanner

def check_root():
    """Check if the script is run with root/admin privileges"""
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:  # Unix/Linux/Mac
        return os.geteuid() == 0

def main():
    """Main entry point for the application"""
    # Initialize the cyber effects
    cyber_fx = CyberEffect()
    
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Display boot sequence
    cyber_fx.display_banner("NetScan", font="poison")
    cyber_fx.type_text("Initializing network scanner...", speed=0.01, color="\033[38;2;0;255;0m")
    time.sleep(0.5)
    
    # Check for root privileges
    if not check_root():
        cyber_fx.type_text("\nWARNING: This program requires root/admin privileges for full functionality.", 
                          color="\033[33m")
        cyber_fx.type_text("Some scanning features may not work correctly.", color="\033[33m")
        cyber_fx.type_text("Please restart with 'sudo python main.py'\n", color="\033[33m")
        
        # Ask if user wants to continue anyway
        cyber_fx.type_text("Continue anyway? (y/n)", color="\033[38;2;0;255;0m")
        response = input().strip().lower()
        
        if response != 'y' and response != 'yes':
            cyber_fx.type_text("Exiting program.", color="\033[38;2;0;255;0m")
            sys.exit(0)
    
    # Simulate boot sequence
    cyber_fx.type_text("Loading modules:", speed=0.01, color="\033[38;2;0;255;0m")
    modules = [
        "Network Interface Scanner", 
        "ARP Discovery Module", 
        "Port Scanner", 
        "Hostname Resolver",
        "MAC Vendor Database"
    ]
    
    for module in modules:
        cyber_fx.type_text(f"  - Loading {module}...", speed=0.005, color="\033[38;2;0;255;0m")
        time.sleep(0.3)
        cyber_fx.type_text("    [LOADED]", speed=0.001, color="\033[38;2;50;255;50m")
    
    # Brief matrix rain effect
    cyber_fx.matrix_rain(duration=1.5, density=0.3)
    
    # Initialize scanner and console
    try:
        scanner = NetworkScanner()
        console = NetScanConsole()
        
        # Inject scanner into console
        console.inject_scanner(scanner)
        
        # Start console
        console.start()
        
    except KeyboardInterrupt:
        cyber_fx.type_text("\nProgram terminated by user.", color="\033[38;2;0;255;0m")
    except Exception as e:
        cyber_fx.type_text(f"\nAn error occurred: {e}", color="\033[31m")
    finally:
        cyber_fx.type_text("Shutting down...", color="\033[38;2;0;255;0m")
        sys.exit(0)

if __name__ == "__main__":
    main()
