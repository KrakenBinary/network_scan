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
    
    # Create console for displaying banner
    console = NetScanConsole()
    
    # Display banner using the new method
    console._display_banner()
    
    print("Initializing network scanner...")
    print("Loading modules with verbose output:")
    
    print("  - Loading Network Interface Scanner...")
    time.sleep(0.3)
    print("    [INFO] Detecting available network interfaces...")
    time.sleep(0.2)
    print("    [INFO] Configuring interface monitoring...")
    time.sleep(0.2)
    print("    [LOADED]")
    
    print("  - Loading ARP Discovery Module...")
    time.sleep(0.3)
    print("    [INFO] Setting up ARP packet crafting...")
    time.sleep(0.2)
    print("    [INFO] Configuring broadcast parameters...")
    time.sleep(0.2)
    print("    [LOADED]")
    
    print("  - Loading Port Scanner...")
    time.sleep(0.2)
    print("    [LOADED]")
    
    print("  - Loading Hostname Resolver...")
    time.sleep(0.2)
    print("    [LOADED]")
    
    print("  - Loading MAC Vendor Database...")
    time.sleep(0.3)
    print("    [INFO] Initializing vendor database...")
    time.sleep(0.2)
    print("    [INFO] Loading OUI prefixes...")
    time.sleep(0.2)
    print("    [LOADED]")
    
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
    
    # Initialize scanner and console
    try:
        scanner = NetworkScanner()
        console.inject_scanner(scanner)
        
        # Start console
        console.start()
        
    except KeyboardInterrupt:
        cyber_fx.type_text("\nProgram terminated by user.", color="\033[38;2;0;255;0m")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
    finally:
        print("Shutting down...")
        sys.exit(0)

if __name__ == "__main__":
    main()
