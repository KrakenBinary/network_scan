#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import threading
import datetime
import platform
import json
import importlib
import glob
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.box import DOUBLE, HEAVY

from .terminal_output import terminal, MSG_NORMAL, MSG_WARNING, MSG_INFO, MSG_ERROR

# Import terminal_output only - we no longer need CyberEffect
# Define available commands
AVAILABLE_COMMANDS = [
    'help', 'scan', 'devices', 'interfaces', 'scan_ports', 'info', 'target', 
    'export', 'clear', 'exit', 'about', 'subnets', 'scanall'
]

class NetScanConsole:
    """Interactive MUD-style console for the network scanner"""
    
    def __init__(self):
        """Initialize the console"""
        # Create rich console instance
        self.console = Console()
        
        # Set up console variables
        self.running = True
        self.target_network = None
        self.scanning_thread = None
        
        # Scanner will be injected later
        self.scanner = None
        
        # Initialize command history and prompt styling
        self.history = InMemoryHistory()
        self.session = PromptSession(
            history=self.history,
            auto_suggest=AutoSuggestFromHistory()
        )
        
        # Create prompt style
        self.prompt_style = Style.from_dict({
            # Styling for prompt
            'prompt': 'ansigreen bold',
            # Styling for user input
            'command': 'ansibrightgreen',
        })

    def inject_scanner(self, scanner):
        """Inject the scanner module"""
        self.scanner = scanner
    
    def display_welcome(self):
        """Display welcome message and banner"""
        terminal.show_banner()
        
        terminal.print("Welcome to NetScan Terminal", msg_type="info")
        terminal.print("Type 'help' to see available commands\n", msg_type="info")
        
    def start(self):
        """Start the interactive console"""
        try:
            # Display banner and welcome message
            self.display_welcome()
            
            # Main command loop
            while self.running:
                try:
                    # Prompt for command with retro styling
                    user_input = self.session.prompt(
                        [
                            ('class:prompt', '['),
                            ('class:prompt', 'NETSCAN'),
                            ('class:prompt', '] '),
                            ('class:prompt', '> '),
                        ],
                        style=self.prompt_style
                    ).strip()
                    
                    if not user_input:
                        continue
                        
                    # Process the command
                    self.execute_command(user_input)
                    
                except KeyboardInterrupt:
                    # Handle Ctrl+C gracefully
                    terminal.warning("\nInterrupted!")
                    self.running = False
                    
                except EOFError:
                    # Handle Ctrl+D (EOF)
                    terminal.warning("\nExiting...")
                    self.running = False
                    
        except Exception as e:
            terminal.error(f"Console error: {str(e)}")
            
        finally:
            terminal.info("Goodbye!")
            # Show exit message
            terminal.info("Disconnecting from the network...")
            time.sleep(0.5)
            terminal.warning("CONNECTION TERMINATED")
    
    def execute_command(self, cmd_line):
        """Execute a command"""
        # Allow empty commands
        if not cmd_line:
            return
            
        # Parse command and args
        parts = cmd_line.strip().split(' ')
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Dispatch to appropriate method
        if cmd == 'help':
            self._show_help()
        elif cmd == 'scan':
            if args:
                # Scan specific network
                target = args[0]
                self._scan_specific_network(target)
            else:
                # Scan all networks
                self._run_scan()
        elif cmd == 'scanall':
            self._scan_all_subnets()
        elif cmd == 'devices':
            self._show_devices()
        elif cmd == 'interfaces':
            self._show_interfaces()
        elif cmd == 'scan_ports':
            if len(args) >= 2:
                self._scan_ports(args[0], args[1])
            elif len(args) == 1:
                self._scan_ports(args[0])
            else:
                self._show_help()
        elif cmd == 'info':
            if args:
                self._show_device_info(args[0])
            else:
                self._show_help()
        elif cmd == 'target':
            if args:
                self._set_target(args[0])
            else:
                self._show_current_target()
        elif cmd == 'export':
            if args:
                self._export_data(args[0])
            else:
                self._export_data()
        elif cmd == 'clear':
            # Use separator instead of clearing screen
            terminal.clear_screen()
        elif cmd == 'exit':
            self.running = False
        elif cmd == 'about':
            self._show_about()
        elif cmd == 'subnets':
            self._show_subnets()
        else:
            terminal.warning(f"Command not found: {cmd}. Type 'help' for available commands")
    
    def _clear_screen(self):
        """Print a separator instead of clearing the screen"""
        print("\n" + "-" * 60 + "\n")
    
    def _show_help(self):
        """Display help information"""
        terminal.clear_screen()
        
        # Display header without animation for reliability
        terminal.success("NETSCAN COMMAND REFERENCE")
        print()
        
        # Create help content with sections
        commands = [
            ["scan", "Scan the local network for devices"],
            ["scanip <ip>", "Scan a specific IP address"],
            ["scannet <subnet>", "Scan a specific subnet (e.g., 192.168.1.0/24)"],
            ["scanall", "Discover and scan all accessible subnets"],
            ["subnets", "Show active subnets"],
            ["devices", "Show discovered devices"],
            ["interfaces", "Show network interfaces"],
            ["export <filename>", "Export scan results to JSON/CSV file"],
            ["about", "Show information about NetScan"],
            ["clear", "Clear the screen"],
            ["exit/quit", "Exit the application"],
            ["help", "Show this help message"]
        ]
        
        # Display command table with retro styling
        terminal.hacker_table("AVAILABLE COMMANDS", ["Command", "Description"], commands)
        
        # Show advanced usage tips
        terminal.info("\nADVANCED USAGE TIPS:")
        terminal.print(" • Run 'scanall' for comprehensive network discovery", msg_type="info")
        terminal.print(" • Use 'export results.json' to save your findings", msg_type="info")
        terminal.print(" • MAC addresses are displayed in xx-xx-xx-xx-xx-xx format", msg_type="info")
        
        terminal.info("\nPress any key to continue...")
        input()
        terminal.clear_screen()
    
    def _show_about(self):
        """Display information about the tool"""
        import platform
        
        # Clear screen and show retro header
        terminal.clear_screen()
        
        # Display title with consistent styling
        terminal.success("N E T S C A N - T E R M I N A L")
        time.sleep(0.5)
        
        # Display cool ASCII art
        print(f"""
    ┌───────────────────────────────────────────────┐
    │  █▓▒░  ADVANCED NETWORK RECONNAISSANCE  ░▒▓█  │
    └───────────────────────────────────────────────┘
        """)
        
        # Create data for the about info
        about_data = [
            ["Version", "1.0.0"],
            ["Codename", "TERMINAL GHOST"],
            ["Developer", "NetScan Division"],
            ["Features", "ARP scanning, port scanning, device discovery"],
            ["Platform", platform.platform()],
            ["Python", sys.version.split()[0]],
            ["Date", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Status", "OPERATIONAL"]
        ]
        
        # Display information as a retro table
        terminal.hacker_table("SYSTEM INFORMATION", ["Item", "Details"], about_data)
        
        # Show disclaimer with consistent styling
        time.sleep(0.3)
        terminal.info("\n[DISCLAIMER]")
        terminal.warning("This tool is for authorized network diagnostics and security assessment only.")
                          
        # Wait for user input to continue
        terminal.info("\nPress any key to return to main interface...")
        input()
        terminal.clear_screen()
    
    def _start_scan(self, target=None):
        """Start a network scan in a separate thread"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!")
            return
            
        # Start scan in a separate thread so we don't block the console
        if self.scanning_thread and self.scanning_thread.is_alive():
            terminal.info("A scan is already running...")
            return
        
        self.scanning_thread = threading.Thread(target=self._run_scan, args=(target,))
        self.scanning_thread.daemon = True
        self.scanning_thread.start()
    
    def _run_scan(self, target=None):
        """Run network scan in a separate thread"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!")
            return
            
        try:
            # Display scan header with cyber effect
            terminal.clear_screen()
            terminal.success("INITIATING NETWORK SCAN")
            
            # Show scan parameters
            if target:
                terminal.info(f"Target: {target}")
            else:
                terminal.info("Target: All available networks")
            
            # Display scanner ASCII art
            terminal.show_scanner_progress(text="INITIALIZING SCAN...", progress=10)
            time.sleep(0.5)
            
            # Run actual scan
            if target:
                # Parse target - could be IP or subnet
                if '/' in target:
                    # Subnet scan
                    terminal.info(f"Scanning subnet: {target}")
                    terminal.show_scanner_progress(text=f"SCANNING {target}...", progress=30)
                    devices = self.scanner.scan_specific_network(target)
                else:
                    # Single IP scan
                    terminal.info(f"Scanning device: {target}")
                    terminal.show_scanner_progress(text=f"SCANNING {target}...", progress=30)
                    devices = self.scanner.scan_single_ip(target)
            else:
                # Default scan - use auto-detection
                terminal.info("Starting network discovery...")
                terminal.show_scanner_progress(text="NETWORK DISCOVERY...", progress=50)
                devices = self.scanner.smart_scan()
                
            # Update scan progress
            terminal.show_scanner_progress(text="ANALYZING RESULTS...", progress=90)
            time.sleep(0.3)
            
            # Complete scan
            terminal.show_scanner_progress(text="SCAN COMPLETE", progress=100)
            time.sleep(0.5)
            
            if devices:
                terminal.success(f"Scan complete! Found {len(devices)} devices.")
                self.discovered_devices = devices
                self._show_devices()
            else:
                terminal.warning("Scan complete. No devices found.")
                
        except KeyboardInterrupt:
            terminal.warning("Scan interrupted by user!")
            
        except Exception as e:
            terminal.error(f"Error during scan: {str(e)}")
    
    def _scan_all_subnets(self):
        """Scan all active subnets"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!")
            return
            
        # Start scan in a separate thread so we don't block the console
        if self.scanning_thread and self.scanning_thread.is_alive():
            terminal.info("A scan is already running...")
            return
        
        self.scanning_thread = threading.Thread(target=self._run_scan_all_subnets)
        self.scanning_thread.daemon = True
        self.scanning_thread.start()
    
    def _run_scan_all_subnets(self):
        """Run network scan on all active subnets in a separate thread"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!")
            return
            
        try:
            # Display scan header with cyber effect
            terminal.clear_screen()
            terminal.success("INITIATING COMPREHENSIVE NETWORK SCAN")
            
            # Flag to track scanning status
            self.scanner.continue_scan = True
            
            # Discovery phase
            terminal.info("Starting intelligent subnet discovery...")
            terminal.info("This will automatically find and scan all likely networks...")
            
            # First use our new smart subnet discovery to identify all possible subnets
            subnets_list = self.scanner.smart_subnet_discovery()
            
            if not subnets_list:
                terminal.warning("No subnets discovered. Try running with elevated privileges.")
                return
                
            # Show discovered subnets in a table
            subnet_rows = []
            for i, subnet in enumerate(subnets_list):
                subnet_rows.append([
                    str(i+1),
                    subnet['network'],
                    subnet['source'],
                    subnet['type'].upper()
                ])
                
            terminal.hacker_table(
                "DISCOVERED SUBNETS", 
                ["#", "Network", "Source", "Type"], 
                subnet_rows
            )
            
            # Filter to only include discovered (not brute-forced) and common subnets
            scan_subnets = [s for s in subnets_list if s['type'] in ['local', 'route', 'gateway', 'arp', 'common']]
            
            terminal.info(f"Scanning {len(scan_subnets)} most likely subnets...")
            
            # Use our organized subnet scanning method to scan selected subnets
            self.discovered_devices = self.scanner.scan_selected_subnets(scan_subnets, max_concurrent=2)
            
            terminal.info("Scan analysis complete")
            
            if self.discovered_devices:
                terminal.success(f"Scan complete! Found {len(self.discovered_devices)} devices across all subnets.")
                
                # Show the skull for dramatic effect
                terminal.show_skull()
                terminal.success(f"IDENTIFIED {len(self.discovered_devices)} NETWORK NODES")
                
                # Display devices
                self._show_devices()
                
                # Automatically export the results
                timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
                export_filename = f"netscan_results_{timestamp}.json"
                export_path = self.scanner.export_data_to_json(export_filename)
                if export_path:
                    terminal.success(f"Results automatically exported to: {export_path}")
            else:
                terminal.warning("Scan complete. No devices found on any subnet.")
                
        except KeyboardInterrupt:
            # Handle user interruption
            terminal.warning("Scan interrupted by user!")
            if hasattr(self.scanner, 'continue_scan'):
                self.scanner.continue_scan = False
            
        except Exception as e:
            terminal.error(f"Error during scan: {str(e)}")
            if hasattr(self.scanner, 'continue_scan'):
                self.scanner.continue_scan = False

    def _show_subnets(self):
        """Show available subnets for scanning"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!")
            return
            
        # Use the new active subnet discovery method
        subnets = self.scanner.show_active_subnets()
        
        if not subnets:
            terminal.info("No active subnets found. Try running with elevated privileges (sudo).")
            return
            
        # Add instructions for using the subnets
        terminal.info("\nTo scan a specific subnet, use: scan <subnet>")
        terminal.info("Example: scan 10.42.1.0/24")
        terminal.info("To scan all subnets automatically, use: scanall")
    
    def _show_devices(self):
        """Display discovered devices"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!")
            return
            
        # Get devices from both the scanner's results and our multi-threaded scan results
        devices = self.scanner.get_scan_results()
        
        # If we have discovered devices from the multi-threaded scan, use those too
        if hasattr(self, 'discovered_devices') and self.discovered_devices:
            # Combine the results, avoiding duplicates by IP
            existing_ips = {d.get('ip') for d in devices}
            for device in self.discovered_devices:
                if device.get('ip') not in existing_ips:
                    devices.append(device)
                    existing_ips.add(device.get('ip'))
        
        if not devices:
            terminal.info("No devices found. Run 'scan' or 'scanall' first.")
            return
        
        # Show skull ASCII art and device count with glitch effect
        terminal.show_skull()
        terminal.success(f"FOUND {len(devices)} NETWORK NODES")
            
        # Create a table for displaying the devices
        column_titles = ["IP Address", "Hostname", "MAC Address", "Vendor"]
        rows = []
        
        # Add device rows
        for device in devices:
            rows.append([
                device.get('ip', 'Unknown'),
                device.get('hostname', 'Unknown'),
                device.get('mac', 'Unknown'),
                device.get('vendor', 'Unknown')
            ])
        
        # Display stylized table
        terminal.hacker_table("DISCOVERED DEVICES", column_titles, rows)
        
        # Show network ASCII art at the bottom
        terminal.show_network_art()
    
    def _show_interfaces(self):
        """Display network interfaces"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!")
            return
            
        interfaces = self.scanner.get_local_interfaces()
        
        if not interfaces:
            terminal.info("No network interfaces found.")
            return
            
        # Create a table for displaying the interfaces
        table = Table(title="Network Interfaces", box=HEAVY)
        table.add_column("Interface", style="cyan")
        table.add_column("IP Address", style="green")
        table.add_column("Netmask", style="yellow")
        table.add_column("MAC Address", style="magenta")
        
        # Add interface rows
        for iface in interfaces:
            table.add_row(
                iface.get('name', 'Unknown'),
                iface.get('ip', 'Unknown'),
                iface.get('netmask', 'Unknown'),
                iface.get('mac', 'Unknown')
            )
        
        self.console.print(table)
    
    def _scan_ports(self, ip, port_spec='1-1000'):
        """Scan ports on a device"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!")
            return
            
        # Validate port specification
        if not self._validate_port_spec(port_spec):
            terminal.warning("Invalid port specification. Use numbers, ranges (e.g. 1-1000), or comma-separated values.")
            return
            
        # Start scanning
        self.console.print(f"[cyan]Scanning ports on {ip}...[/cyan]")
        results = self.scanner.scan_ports(ip, port_spec)
        
        if not results:
            terminal.info(f"No open ports found on {ip}.")
            return
            
        # Display results
        table = Table(title=f"Open Ports on {ip}", box=HEAVY)
        table.add_column("Port", style="cyan", justify="right")
        table.add_column("Service", style="green")
        table.add_column("Version", style="yellow")
        table.add_column("State", style="magenta")
        
        for port_info in results:
            table.add_row(
                str(port_info.get('port', 'Unknown')),
                port_info.get('service', 'Unknown'),
                port_info.get('version', ''),
                port_info.get('state', 'Unknown')
            )
        
        self.console.print(table)
    
    def _show_device_info(self, ip):
        """Show detailed information about a device"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!")
            return
            
        # Find the device
        found = False
        for device in self.scanner.get_scan_results():
            if device.get('ip') == ip:
                found = True
                
                # Display detailed information
                table = Table(title=f"Device Information: {ip}", box=DOUBLE)
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="green")
                
                # Add device information
                for key, value in device.items():
                    table.add_row(key.capitalize(), str(value))
                
                self.console.print(table)
                
                # Also show port scan results if available
                self._show_port_results(ip)
                break
                
        if not found:
            terminal.warning(f"Device with IP {ip} not found. Run 'scan' first.")
    
    def _show_port_results(self, ip):
        """Show port scan results for a device if available"""
        if hasattr(self.scanner, 'port_scan_results') and ip in self.scanner.port_scan_results:
            ports = self.scanner.port_scan_results[ip]
            
            if ports:
                table = Table(title=f"Port Scan Results for {ip}", box=HEAVY)
                table.add_column("Port", style="cyan", justify="right")
                table.add_column("Service", style="green")
                table.add_column("Version", style="yellow")
                table.add_column("State", style="magenta")
                
                for port_info in ports:
                    table.add_row(
                        str(port_info.get('port', 'Unknown')),
                        port_info.get('service', 'Unknown'),
                        port_info.get('version', ''),
                        port_info.get('state', 'Unknown')
                    )
                
                self.console.print(table)
    
    def _validate_port_spec(self, port_spec):
        """Validate port specification"""
        # Check for comma-separated values
        if ',' in port_spec:
            parts = port_spec.split(',')
            return all(self._validate_port_spec(part) for part in parts)
            
        # Check for range (e.g., 1-1000)
        if '-' in port_spec:
            try:
                start, end = port_spec.split('-')
                start, end = int(start), int(end)
                return 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end
            except ValueError:
                return False
                
        # Check for single port
        try:
            port = int(port_spec)
            return 1 <= port <= 65535
        except ValueError:
            return False
    
    def _set_target(self, target):
        """Set the target network"""
        self.target_network = target
        terminal.success(f"Target network set to: {target}")
    
    def _show_current_target(self):
        """Show the current target network"""
        if self.target_network:
            terminal.info(f"Current target network: {self.target_network}")
        else:
            terminal.info("No target network set. Use 'target <network/CIDR>' to set one.")
    
    def _export_data(self, filename=None):
        """Export data to a file"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!")
            return
            
        # Generate default filename if not provided
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = f"netscan_results_{timestamp}.json"
            
        # Get absolute path for the file
        current_dir = os.getcwd()
        filepath = os.path.join(current_dir, filename)
            
        # Export data
        if self.scanner.export_data_to_json(filepath):
            terminal.success(f"Data exported to {filename}")
        else:
            terminal.error("Error exporting data. Check permissions and try again.")
    
    def inject_data(self, key, value):
        """Allow external components to inject data into the console"""
        if key == "target_network":
            self.target_network = value
    
    def _scan_specific_network(self, target):
        """Scan a specific network"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!")
            return
            
        # Start scan in a separate thread so we don't block the console
        if self.scanning_thread and self.scanning_thread.is_alive():
            terminal.info("A scan is already running...")
            return
        
        self.scanning_thread = threading.Thread(target=self._run_scan, args=(target,))
        self.scanning_thread.daemon = True
        self.scanning_thread.start()
