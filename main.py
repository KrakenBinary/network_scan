#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import threading
import random
from rich.console import Console

from src.ui.terminal_output import terminal
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

def simulate_loading():
    """Create a hacker-style loading sequence"""
    # Start with glitch text for the main initialization
    terminal.glitch_text("[SYSTEM BOOT] Initializing NetScan v1.0", iterations=2)
    time.sleep(0.5)
    
    # Network interface module with typing effect
    terminal.type_text("  └─ Loading Network Interface Scanner", speed=0.01)
    time.sleep(0.3)
    terminal.info("     [INFO] Detecting available network interfaces...")
    time.sleep(0.2)
    terminal.info("     [INFO] Configuring interface monitoring...")
    time.sleep(0.4)
    terminal.success("     [LOADED]")
    
    # ARP module with more glitchy effect
    terminal.type_text("  └─ Loading ARP Discovery Module", speed=0.01)
    time.sleep(0.3)
    terminal.info("     [INFO] Setting up ARP packet crafting...")
    time.sleep(0.2)
    # Simulated packet hex dump for hacker feel
    packet_hex = "0x45000073000040004001 61C9C0A80A63C0A80A0C"
    terminal.type_text(f"     [DEBUG] Sample packet: {packet_hex}", speed=0.001)
    time.sleep(0.3)
    terminal.info("     [INFO] Configuring broadcast parameters...")
    time.sleep(0.3)
    terminal.success("     [LOADED]")
    
    # Port scanner with minimal output
    terminal.type_text("  └─ Loading Port Scanner", speed=0.01)
    time.sleep(0.5)
    terminal.success("     [LOADED]")
    
    # Hostname resolver with minimal output
    terminal.type_text("  └─ Loading Hostname Resolver", speed=0.01)
    time.sleep(0.4)
    terminal.success("     [LOADED]")
    
    # MAC vendor database with details
    terminal.type_text("  └─ Loading MAC Vendor Database", speed=0.01)
    time.sleep(0.3)
    terminal.info("     [INFO] Initializing vendor database...")
    time.sleep(0.2)
    terminal.info("     [INFO] Loading OUI prefixes...")
    time.sleep(0.4)
    terminal.success("     [LOADED]")
    
    # Final system initialization
    time.sleep(0.5)
    terminal.glitch_text("[SYSTEM READY] All modules loaded successfully", iterations=2)
    terminal.print("\n", msg_type="normal")

def main():
    """Main entry point for the application"""
    try:
        # Skip the loading sequence as requested
        # simulate_loading()
        
        # Initialize scanner
        terminal.info("[TRACE] Initializing scanner...")
        scanner = NetworkScanner()
        
        # Create console only after loading is complete 
        terminal.info("[TRACE] Creating console...")
        console = NetScanConsole()
        
        # Inject scanner into console
        terminal.info("[TRACE] Injecting scanner...")
        console.inject_scanner(scanner)
        
        # Start the console (this will display the banner)
        console.start()
        
    except KeyboardInterrupt:
        terminal.warning("\nInterrupted by user. Shutting down...")
        sys.exit(0)
    except Exception as e:
        terminal.error(f"An error occurred: {str(e)}")
        terminal.warning("Shutting down...")
        sys.exit(1)

if __name__ == "__main__":
    # Check for root privileges
    is_root = check_root()
    
    if not is_root:
        terminal.warning("[!] This tool requires root/admin privileges for full functionality.")
        terminal.warning("[!] Please run as root/administrator.")
        
        # Ask if user wants to continue anyway
        while True:
            response = input("[?] Continue anyway? (y/n): ")
            if response.lower() in ['y', 'yes']:
                break
            elif response.lower() in ['n', 'no']:
                sys.exit(0)
    
    # Start main program
    main()
