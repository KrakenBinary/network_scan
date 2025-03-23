#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import threading
import json
from datetime import datetime
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.table import Table
from rich.box import HEAVY, DOUBLE

# Import terminal_output only - we no longer need CyberEffect
from .terminal_output import terminal, NEON_GREEN, RESET, MSG_NORMAL, MSG_WARNING, MSG_INFO, MSG_ERROR

# Define available commands
AVAILABLE_COMMANDS = [
    'help', 'scan', 'devices', 'interfaces', 'scan_ports', 'info', 'target', 
    'export', 'clear', 'exit', 'about'
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
        
        # Setup prompt toolkit
        command_completer = WordCompleter(AVAILABLE_COMMANDS)
        self.history = InMemoryHistory()
        self.session = PromptSession(
            history=self.history,
            auto_suggest=AutoSuggestFromHistory(),
            completer=command_completer,
            style=Style.from_dict({
                'prompt': 'ansired bold',
            }),
            complete_in_thread=True
        )
    
    def inject_scanner(self, scanner):
        """Inject the scanner module"""
        self.scanner = scanner
    
    def display_welcome(self):
        """Display welcome message and banner"""
        self.console.print("\n")
        with open(os.path.join(os.path.dirname(__file__), 'banner.txt'), 'r') as f:
            banner = f.read()
            self.console.print(f"[bold green]{banner}[/bold green]")
        
        self.console.print("\n[bold cyan]NetScan - Advanced Network Reconnaissance Tool[/bold cyan]")
        self.console.print("[cyan]----------------------------------------[/cyan]")
        self.console.print("[cyan]Type 'help' for available commands[/cyan]")
        self.console.print("[cyan]Type 'exit' to quit[/cyan]")
        self.console.print("\n")
    
    def start(self):
        """Start the interactive console"""
        self.display_welcome()
        
        while self.running:
            try:
                # Get user input
                user_input = self.session.prompt('┌──[NetScan]─[~]\n└─$ ')
                print()  # Add newline after command
                
                # Execute command
                self.execute_command(user_input)
                
            except KeyboardInterrupt:
                self.running = False
            except EOFError:
                self.running = False
        
        # Show exit message
        print("\nDisconnecting from the network...")
        time.sleep(0.5)
        print("CONNECTION TERMINATED")
    
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
            self._start_scan(args[0] if args else None)
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
            os.system('clear')
        elif cmd == 'exit':
            self.running = False
        elif cmd == 'about':
            self._show_about()
        else:
            terminal.warning(f"Command not found: {cmd}. Type 'help' for available commands")
    
    def _clear_screen(self):
        """Print a separator instead of clearing the screen"""
        print("\n" + "-" * 60 + "\n")
    
    def _show_help(self):
        """Display help information"""
        help_table = Table(title="NetScan Commands", box=HEAVY)
        help_table.add_column("Command", style="cyan")
        help_table.add_column("Description", style="green")
        help_table.add_column("Usage", style="yellow")
        
        # Add command details
        help_table.add_row("help", "Display this help message", "help")
        help_table.add_row("scan", "Scan for devices on the network", "scan [network/CIDR]")
        help_table.add_row("devices", "List discovered devices", "devices")
        help_table.add_row("interfaces", "List network interfaces", "interfaces")
        help_table.add_row("scan_ports", "Scan ports on a device", "scan_ports <ip> [ports]")
        help_table.add_row("info", "Show detailed information about a device", "info <ip>")
        help_table.add_row("target", "Set or show the target network", "target [network/CIDR]")
        help_table.add_row("export", "Export data to a file", "export [filename]")
        help_table.add_row("clear", "Clear the screen", "clear")
        help_table.add_row("about", "Show information about NetScan", "about")
        help_table.add_row("exit", "Exit the program", "exit")
        
        self.console.print(help_table)
    
    def _show_about(self):
        """Display information about the tool"""
        about_table = Table(title="About NetScan", box=DOUBLE)
        about_table.add_column("Item", style="cyan")
        about_table.add_column("Details", style="green")
        
        about_table.add_row("Name", "NetScan")
        about_table.add_row("Version", "1.0")
        about_table.add_row("Author", "KrakenBinary")
        about_table.add_row("License", "MIT")
        about_table.add_row("Description", "Advanced network reconnaissance and scanning tool")
        about_table.add_row("Features", "ARP scanning, port scanning, device discovery")
        about_table.add_row("Platform", platform.platform())
        about_table.add_row("Python", sys.version)
        about_table.add_row("Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        self.console.print(about_table)
    
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
        """Run the network scan in a separate thread"""
        terminal.print("Initializing scan module...")
        time.sleep(0.5)
        
        if target:
            terminal.print(f"Scanning network: {target}")
            devices = self.scanner.scan_network(target)
        else:
            terminal.print("Scanning all local networks...")
            devices = self.scanner.scan_network()
            
        # Show summary when done
        device_count = len(devices)
        terminal.success(f"Scan complete. Discovered {device_count} devices.")
    
    def _show_devices(self):
        """Display discovered devices"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!")
            return
            
        devices = self.scanner.get_scan_results()
        
        if not devices:
            terminal.info("No devices found. Run 'scan' first.")
            return
            
        # Create a table for displaying the devices
        table = Table(title="Discovered Devices", box=HEAVY)
        table.add_column("IP Address", style="cyan")
        table.add_column("Hostname", style="green")
        table.add_column("MAC Address", style="yellow")
        table.add_column("Vendor", style="magenta")
        
        # Add device rows
        for device in devices:
            table.add_row(
                device.get('ip', 'Unknown'),
                device.get('hostname', 'Unknown'),
                device.get('mac', 'Unknown'),
                device.get('vendor', 'Unknown')
            )
        
        self.console.print(table)
    
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
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
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
