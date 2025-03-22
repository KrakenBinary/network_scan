#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import threading
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import ANSI
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich.panel import Panel
from rich.box import DOUBLE, HEAVY
from datetime import datetime

from .cyber_effects import CyberEffect, NEON_GREEN, CYAN_BLUE, RESET

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
        self._show_welcome()
        
        while self.running:
            try:
                # Create prompt with simpler style
                prompt_text = ANSI(f"{NEON_GREEN}>> {RESET}")
                command = self.session.prompt(prompt_text)
                
                # Process the command
                self._process_command(command.strip())
                
            except KeyboardInterrupt:
                self.cyber_fx.type_text("\nUse 'exit' to quit properly.", color=NEON_GREEN)
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
            self.cyber_fx.type_text(f"Command not found: {cmd}", color=NEON_GREEN)
            self.cyber_fx.type_text("Type 'help' for available commands", color=NEON_GREEN)
    
    def _clear_screen(self):
        """Print a separator instead of clearing the screen"""
        print(f"\n{NEON_GREEN}{'=' * 80}{RESET}\n")
    
    def _show_welcome(self):
        """Display welcome message and banner"""
        self._display_banner()
        
        welcome_text = """
╔═══════════════════════════════════════════════════════════════════════╗
║                   Welcome to the KrakenBinary NetScan                 ║
║                                                                       ║
║  A hacker-themed network discovery tool for MSP reconnaissance.       ║
║  Type 'help' for available commands, or 'exit' to quit.               ║
╚═══════════════════════════════════════════════════════════════════════╝
        """
        self.cyber_fx.type_text(welcome_text, speed=0.001)
        print()
    
    def _show_help(self):
        """Display help information"""
        help_table = Table(title="Available Commands", box=HEAVY)
        
        help_table.add_column("Command", style="cyan")
        help_table.add_column("Description", style="green")
        help_table.add_column("Usage", style="green")
        
        help_table.add_row("help", "Show this help information", "help")
        help_table.add_row("scan", "Scan the network for devices", "scan [network/CIDR]")
        help_table.add_row("interfaces", "List network interfaces", "interfaces")
        help_table.add_row("devices", "List discovered devices", "devices")
        help_table.add_row("target", "Set target network", "target 192.168.1.0/24")
        help_table.add_row("scan_ports", "Scan ports on a device", "scan_ports <IP> [ports]")
        help_table.add_row("info", "Show detailed info for a device", "info <IP>")
        help_table.add_row("export", "Export scan results", "export [filename]")
        help_table.add_row("clear", "Clear the screen", "clear")
        help_table.add_row("about", "Display about information", "about")
        help_table.add_row("exit", "Exit the program", "exit")
        
        self.console.print(help_table)
    
    def _exit_program(self):
        """Exit the program"""
        self.cyber_fx.type_text("Disconnecting from the network...", speed=0.01, color=NEON_GREEN)
        time.sleep(0.5)
        self.cyber_fx.glitch_text("CONNECTION TERMINATED")
        self.running = False
    
    def _start_scan(self, args):
        """Start a network scan"""
        if not self.scanner:
            self.cyber_fx.type_text("ERROR: Scanner module not initialized!", color="\033[31m")
            return
            
        target = None
        if args:
            target = args[0]
        elif self.target_network:
            target = self.target_network
            
        # Use a thread to prevent UI blocking
        if self.scanning_thread and self.scanning_thread.is_alive():
            self.cyber_fx.type_text("A scan is already in progress!", color=NEON_GREEN)
            return
            
        self.scanning_thread = threading.Thread(
            target=self._run_scan,
            args=(target,)
        )
        self.scanning_thread.daemon = True
        self.scanning_thread.start()
    
    def _run_scan(self, target=None):
        """Run the network scan in a separate thread"""
        print("Initializing scan module...")
        time.sleep(0.5)
        
        if target:
            self.cyber_fx.simulate_connection(target)
            devices = self.scanner.scan_network(target)
        else:
            print("Scanning all local networks...")
            devices = self.scanner.scan_network()
            
        # Show summary when done
        device_count = len(devices)
        self.cyber_fx.type_text(f"Scan complete. Discovered {device_count} devices.", color=NEON_GREEN)
    
    def _show_devices(self):
        """Display discovered devices"""
        if not self.scanner:
            self.cyber_fx.type_text("ERROR: Scanner module not initialized!", color="\033[31m")
            return
            
        devices = self.scanner.get_scan_results()
        
        if not devices:
            self.cyber_fx.type_text("No devices found. Run 'scan' first.", color=NEON_GREEN)
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
        
        self.console.print(table)
    
    def _show_interfaces(self):
        """Display network interfaces"""
        if not self.scanner:
            self.cyber_fx.type_text("ERROR: Scanner module not initialized!", color="\033[31m")
            return
            
        interfaces = self.scanner.get_local_interfaces()
        
        if not interfaces:
            self.cyber_fx.type_text("No network interfaces found.", color=NEON_GREEN)
            return
            
        table = Table(title="Network Interfaces", box=DOUBLE)
        
        table.add_column("Interface", style="cyan")
        table.add_column("IP Address", style="green")
        table.add_column("Netmask", style="green")
        table.add_column("Network", style="green")
        table.add_column("MAC Address", style="green")
        
        for iface in interfaces:
            table.add_row(
                iface.get('name', 'Unknown'),
                iface.get('ip', 'Unknown'),
                iface.get('netmask', 'Unknown'),
                iface.get('range', 'Unknown'),
                iface.get('mac', 'Unknown')
            )
        
        self.console.print(table)
    
    def _scan_ports(self, ip, args):
        """Scan ports on a specific device"""
        if not self.scanner:
            self.cyber_fx.type_text("ERROR: Scanner module not initialized!", color="\033[31m")
            return
            
        ports = args[0] if args else "22,80,443,445,3389,8080"
        
        self.cyber_fx.type_text(f"Scanning ports on {ip}...", color=NEON_GREEN)
        ports_info = self.scanner.port_scan(ip, ports, True)
        
        if not ports_info:
            self.cyber_fx.type_text(f"No open ports found on {ip}", color=NEON_GREEN)
            return
            
        table = Table(title=f"Open Ports on {ip}", box=DOUBLE)
        
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="green")
        table.add_column("Version", style="green")
        
        for port_info in ports_info:
            table.add_row(
                str(port_info.get('port', 'Unknown')),
                port_info.get('service', 'Unknown'),
                port_info.get('version', 'Unknown')
            )
        
        self.console.print(table)
    
    def _show_device_info(self, ip):
        """Show detailed information about a device"""
        if not self.scanner:
            self.cyber_fx.type_text("ERROR: Scanner module not initialized!", color="\033[31m")
            return
            
        devices = self.scanner.get_scan_results()
        device = next((d for d in devices if d.get('ip') == ip), None)
        
        if not device:
            self.cyber_fx.type_text(f"Device with IP {ip} not found. Run 'scan' first.", color=NEON_GREEN)
            return
            
        # Display basic info
        panel = Panel(
            f"IP Address: {device.get('ip', 'Unknown')}\n"
            f"Hostname: {device.get('hostname', 'Unknown')}\n"
            f"MAC Address: {device.get('mac', 'Unknown')}\n"
            f"Vendor: {device.get('vendor', 'Unknown')}\n"
            f"Status: {device.get('status', 'Unknown')}",
            title=f"Device Information: {ip}",
            border_style="green",
            box=HEAVY
        )
        
        self.console.print(panel)
        
        # Offer to scan ports
        self.cyber_fx.type_text(f"Would you like to scan ports on {ip}? (y/n)", color=NEON_GREEN)
        response = input().strip().lower()
        
        if response == 'y' or response == 'yes':
            self._scan_ports(ip, [])
    
    def _set_target(self, target):
        """Set the target network"""
        self.target_network = target
        self.cyber_fx.type_text(f"Target network set to: {target}", color=NEON_GREEN)
    
    def _show_current_target(self):
        """Show the current target network"""
        if self.target_network:
            self.cyber_fx.type_text(f"Current target network: {self.target_network}", color=NEON_GREEN)
        else:
            self.cyber_fx.type_text("No target network set. Use 'target <network/CIDR>' to set one.", 
                                   color=NEON_GREEN)
    
    def _export_data(self, filename=None):
        """Export scan data to a JSON file"""
        if not self.scanner:
            self.cyber_fx.type_text("ERROR: Scanner module not initialized!", color="\033[31m")
            return
            
        if not self.scanner.get_scan_results():
            self.cyber_fx.type_text("No scan data to export. Run 'scan' first.", color=NEON_GREEN)
            return
        
        self.cyber_fx.type_text("Exporting network data to JSON...", color=NEON_GREEN)
        
        # Call the export function
        saved_file = self.scanner.export_data_to_json(filename)
        
        if saved_file:
            # Create a panel to show the export result
            panel = Panel(
                f"✓ Scan data exported successfully\n"
                f"✓ File: {saved_file}\n"
                f"✓ Devices: {len(self.scanner.get_scan_results())}\n"
                f"✓ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                title="Export Complete",
                border_style="green",
                box=HEAVY
            )
            self.console.print(panel)
        else:
            self.cyber_fx.type_text("Error exporting data. Check permissions and try again.", color="\033[31m")
    
    def _show_about(self):
        """Show information about the program"""
        about_text = """
╔═══════════════════════════════════════════════════════════════════════╗
║                            About NetScan                              ║
║                                                                       ║
║  Version: 1.0.0                                                       ║
║  Author: KrakenBinary                                                 ║
║                                                                       ║
║  A hacker-themed network discovery tool designed for MSPs to gather   ║
║  comprehensive network information from new clients, including        ║
║  networks, subnets, device names, MAC addresses, and IP addresses.    ║
║                                                                       ║
║  Built with Python using scapy, nmap, rich, and other libraries.      ║
║  Features a cyberpunk aesthetic with interactive MUD-style console.   ║
╚═══════════════════════════════════════════════════════════════════════╝
        """
        self.cyber_fx.type_text(about_text, speed=0.001, color=NEON_GREEN)
        
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
        self.console.print(netscan_logo)
    
    def inject_scanner(self, scanner):
        """Inject the network scanner instance"""
        self.scanner = scanner
