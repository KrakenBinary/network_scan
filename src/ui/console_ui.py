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

# Import CyberEffect with absolute import to avoid issues
from src.ui.cyber_effects import CyberEffect
from .terminal_output import terminal, NEON_GREEN, RESET, MSG_NORMAL, MSG_WARNING, MSG_INFO, MSG_ERROR

# Define available commands
AVAILABLE_COMMANDS = [
    'help', 'scan', 'devices', 'interfaces', 'scan_ports', 'info', 'target', 
    'export', 'clear', 'exit', 'about'
]

class NetScanConsole:
    """Interactive MUD-style console for the network scanner"""
    
    def __init__(self):
        self.cyber_fx = CyberEffect()
        self.console = Console()
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
    
    def start(self):
        """Start the interactive console"""
        # Display the welcome message (which includes the banner)
        self._show_welcome()
        
        # Main command loop
        while self.running:
            try:
                # Create the prompt
                prompt_text = ANSI('\033[1;31m┌──[\033[1;36mNetScan\033[1;31m]─[\033[1;33m~\033[1;31m]\n└─\033[1;37m$ \033[0m')
                
                # Get command from user
                cmd = self.session.prompt(prompt_text, refresh_interval=0.5)
                
                # Process the command
                self._process_command(cmd)
                
            except KeyboardInterrupt:
                terminal.warning("\nUse 'exit' to quit.")
            except EOFError:
                self.running = False
    
    def _process_command(self, command):
        """Process user commands"""
        if not command:
            return
            
        # Parse command and arguments
        parts = command.lower().split()
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        # Command processing
        if cmd == 'exit' or cmd == 'quit':
            self._exit_program()
        elif cmd == 'help':
            self._show_help()
        elif cmd == 'clear':
            self._clear_screen()
        elif cmd == 'scan':
            self._start_scan(args)
        elif cmd == 'devices':
            self._show_devices()
        elif cmd == 'interfaces':
            self._show_interfaces()
        elif cmd == 'scan_ports' and len(args) > 0:
            self._scan_ports(args[0], args[1:])
        elif cmd == 'info' and len(args) > 0:
            self._show_device_info(args[0])
        elif cmd == 'target':
            if len(args) > 0:
                self._set_target(args[0])
            else:
                self._show_current_target()
        elif cmd == 'export':
            self._export_data(args[0] if args else None)
        elif cmd == 'about':
            self._show_about()
        else:
            terminal.warning(f"Command not found: {cmd}. Type 'help' for available commands", msg_type=MSG_NORMAL)
    
    def _clear_screen(self):
        """Print a separator instead of clearing the screen"""
        terminal.separator(msg_type=MSG_NORMAL)
    
    def _show_welcome(self):
        """Display welcome message and banner"""
        self._display_banner()
        
        terminal.type_text("Welcome to the KrakenBinary NetScan", speed=0.01, msg_type=MSG_NORMAL)
        terminal.print("-" * 60, msg_type="normal")
        terminal.info("Type 'help' to see available commands")
        terminal.info("Type 'exit' to quit")
        terminal.print("")  # Add empty line for spacing
    
    def _show_help(self):
        """Display help information"""
        # Create rich table for help
        from rich.table import Table
        help_table = Table(title="NetScan Commands")
        
        # Add columns
        help_table.add_column("Command", style="cyan")
        help_table.add_column("Description", style="green")
        help_table.add_column("Example", style="yellow")
        
        # Add rows
        help_table.add_row("help", "Show this help menu", "help")
        help_table.add_row("scan [target]", "Scan for devices on network", "scan 192.168.1.0/24")
        help_table.add_row("ports [ip]", "Scan ports on a specific IP", "ports 192.168.1.1")
        help_table.add_row("show devices", "Show discovered devices", "show devices")
        help_table.add_row("show [ip]", "Show details about an IP", "show 192.168.1.1")
        help_table.add_row("set network [cidr]", "Set target network", "set network 192.168.1.0/24")
        help_table.add_row("export [filename]", "Export results to file", "export results.json")
        help_table.add_row("info", "Show system information", "info")
        help_table.add_row("clear", "Clear the screen", "clear")
        help_table.add_row("exit", "Exit the program", "exit")
        
        # Use terminal system instead of direct console.print
        terminal.table(help_table)
    
    def _exit_program(self):
        """Exit the program"""
        terminal.type_text("Disconnecting from the network...", speed=0.01, msg_type=MSG_NORMAL)
        time.sleep(0.5)
        terminal.glitch_text("CONNECTION TERMINATED")
        self.running = False
    
    def _start_scan(self, args):
        """Start a network scan"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!", msg_type=MSG_NORMAL)
            return
            
        target = None
        if args:
            target = args[0]
        elif self.target_network:
            target = self.target_network
            
        # Use a thread to prevent UI blocking
        if self.scanning_thread and self.scanning_thread.is_alive():
            terminal.type_text("A scan is already in progress!", msg_type=MSG_NORMAL)
            return
            
        self.scanning_thread = threading.Thread(
            target=self._run_scan,
            args=(target,)
        )
        self.scanning_thread.daemon = True
        self.scanning_thread.start()
    
    def _run_scan(self, target=None):
        """Run the network scan in a separate thread"""
        terminal.print("Initializing scan module...", msg_type=MSG_NORMAL)
        time.sleep(0.5)
        
        if target:
            self.cyber_fx.simulate_connection(target)
            devices = self.scanner.scan_network(target)
        else:
            terminal.print("Scanning all local networks...", msg_type=MSG_NORMAL)
            devices = self.scanner.scan_network()
            
        # Show summary when done
        device_count = len(devices)
        terminal.success(f"Scan complete. Discovered {device_count} devices.", msg_type=MSG_NORMAL)
    
    def _show_devices(self):
        """Display discovered devices"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!", msg_type=MSG_NORMAL)
            return
            
        devices = self.scanner.get_scan_results()
        
        if not devices:
            terminal.info("No devices found. Run 'scan' first.", msg_type=MSG_NORMAL)
            return
            
        table = Table(title="Discovered Devices", box=DOUBLE)
        
        table.add_column("IP Address", style="cyan")
        table.add_column("Hostname", style="green") 
        table.add_column("MAC Address", style="green")
        table.add_column("Vendor", style="green")
        
        for device in devices:
            table.add_row(
                device.get('ip', 'Unknown'),
                device.get('hostname', 'Unknown'),
                device.get('mac', 'Unknown'),
                device.get('vendor', 'Unknown')
            )
        
        # Use terminal system instead of direct console.print
        terminal.table(table)
    
    def _show_interfaces(self):
        """Display network interfaces"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!", msg_type=MSG_NORMAL)
            return
            
        interfaces = self.scanner.get_local_interfaces()
        
        if not interfaces:
            terminal.info("No network interfaces found.", msg_type=MSG_NORMAL)
            return
            
        table = Table(title="Network Interfaces", box=DOUBLE)
        
        table.add_column("Interface", style="cyan")
        table.add_column("IP Address", style="green")
        table.add_column("Netmask", style="green")
        table.add_column("MAC Address", style="green")
        
        for iface in interfaces:
            table.add_row(
                iface.get('name', 'Unknown'),
                iface.get('ip', 'Unknown'),
                iface.get('netmask', 'Unknown'),
                iface.get('mac', 'Unknown')
            )
        
        # Use terminal system instead of direct console.print
        terminal.table(table)
    
    def _scan_ports(self, ip, args):
        """Scan ports on a specific device"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!", msg_type=MSG_NORMAL)
            return
            
        # Parse port arguments
        ports = None
        if args:
            try:
                # Handle comma-separated list (e.g. "80,443,8080")
                if ',' in args[0]:
                    ports = [int(p) for p in args[0].split(',')]
                # Handle range (e.g. "1-1000")
                elif '-' in args[0]:
                    start, end = map(int, args[0].split('-'))
                    ports = range(start, end + 1)
                # Handle single port
                else:
                    ports = [int(p) for p in args]
            except ValueError:
                terminal.warning("Invalid port specification. Use numbers, ranges (e.g. 1-1000), or comma-separated values.", msg_type=MSG_NORMAL)
                return
        
        # Start spinner
        terminal.print(f"Scanning ports on {ip}...", msg_type=MSG_NORMAL)
        
        # Perform scan
        results = self.scanner.scan_ports(ip, ports)
        
        # Display results
        if not results:
            terminal.info(f"No open ports found on {ip}.", msg_type=MSG_NORMAL)
            return
            
        table = Table(title=f"Open Ports on {ip}", box=DOUBLE)
        
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="green")
        table.add_column("State", style="green")
        
        for port, info in results.items():
            table.add_row(
                f"{port}", 
                info.get('service', 'Unknown'),
                info.get('state', 'Unknown')
            )
        
        # Use terminal system instead of direct console.print
        terminal.table(table)
    
    def _show_device_info(self, ip):
        """Show detailed information about a device"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!", msg_type=MSG_NORMAL)
            return
            
        device = self.scanner.get_device_by_ip(ip)
        
        if not device:
            terminal.warning(f"Device with IP {ip} not found. Run 'scan' first.", msg_type=MSG_NORMAL)
            return
            
        # Display device info
        terminal.print(f"\n[ Device Information: {ip} ]", msg_type=MSG_NORMAL)
        terminal.print("=" * 60, msg_type=MSG_NORMAL)
        
        terminal.print(f"IP Address:    {device.get('ip', 'Unknown')}", msg_type=MSG_NORMAL)
        terminal.print(f"Hostname:      {device.get('hostname', 'Unknown')}", msg_type=MSG_NORMAL)
        terminal.print(f"MAC Address:   {device.get('mac', 'Unknown')}", msg_type=MSG_NORMAL)
        terminal.print(f"Vendor:        {device.get('vendor', 'Unknown')}", msg_type=MSG_NORMAL)
        
        # Display open ports if any
        ports = device.get('ports', {})
        if ports:
            terminal.print("\nOpen Ports:", msg_type=MSG_NORMAL)
            terminal.print("-" * 40, msg_type=MSG_NORMAL)
            
            for port, info in ports.items():
                terminal.print(f"  {port}/tcp   {info.get('service', 'Unknown')}", msg_type=MSG_NORMAL)
        
        print()
    
    def _set_target(self, target):
        """Set the target network"""
        self.target_network = target
        terminal.success(f"Target network set to: {target}", msg_type=MSG_NORMAL)
    
    def _show_current_target(self):
        """Show the current target network"""
        if self.target_network:
            terminal.print(f"Current target network: {self.target_network}", msg_type=MSG_NORMAL)
        else:
            terminal.info("No target network set. Use 'target <network/CIDR>' to set one.", msg_type=MSG_NORMAL)
    
    def _export_data(self, filename=None):
        """Export scan data to a JSON file"""
        if not self.scanner:
            terminal.warning("ERROR: Scanner module not initialized!", msg_type=MSG_NORMAL)
            return
        
        # Use provided filename or generate one with timestamp
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = f"netscan_results_{timestamp}.json"
        
        # Make sure it has .json extension
        if not filename.endswith('.json'):
            filename = f"{filename}.json"
        
        # Make sure path exists
        result_dir = os.path.join(os.getcwd(), "results")
        os.makedirs(result_dir, exist_ok=True)
        
        # Full path to the export file
        filepath = os.path.join(result_dir, filename)
            
        # Export data
        if self.scanner.export_data_to_json(filepath):
            terminal.success(f"Data exported to {filename}", msg_type=MSG_NORMAL)
        else:
            terminal.error("Error exporting data. Check permissions and try again.", msg_type=MSG_NORMAL)
    
    def _show_about(self):
        """Show information about the program"""
        terminal.print("")  # Empty line for spacing
        terminal.print("About NetScan", msg_type="success")
        terminal.print("=" * 60, msg_type="normal")
        terminal.print("NetScan - Network Discovery Tool", msg_type="normal")
        terminal.print("Version: 1.0.0", msg_type="normal")
        terminal.print("", msg_type="normal")  # Empty line
        terminal.print("A hacker-themed network mapping tool for MSP reconnaissance", msg_type="normal")
        terminal.print("", msg_type="normal")  # Empty line
        terminal.print("Features:", msg_type="normal")
        terminal.print("- Network device discovery using ARP", msg_type="normal")
        terminal.print("- Port scanning with service detection", msg_type="normal")
        terminal.print("- MAC address vendor lookup", msg_type="normal")
        terminal.print("- Export results to JSON or CSV", msg_type="normal")
        terminal.print("", msg_type="normal")  # Empty line
        
    def _display_banner(self):
        """Display application banner"""
        # More elaborate ASCII/ANSI art for NetScan
        netscan_logo = """
[bright_green]███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝[/bright_green]
                                                          
[bright_cyan]╔══════════════════════════════════════════════════════╗
║  [bright_green]Network Reconnaissance & Security Analysis Tool v1.0[/bright_green]  ║
╚══════════════════════════════════════════════════════╝[/bright_cyan]
"""
        # Use terminal system instead of direct console.print
        terminal.rich_print(netscan_logo)
    
    def inject_scanner(self, scanner):
        """Inject the network scanner instance"""
        self.scanner = scanner
