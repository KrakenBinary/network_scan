#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ipaddress
import os
import time
import socket
import threading
import netifaces
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
import nmap
from mac_vendor_lookup import MacLookup
from netaddr import EUI, NotRegisteredError
import datetime
import json
import platform
from src.ui.terminal_output import terminal
import traceback
from rich.progress import Progress, TextColumn, BarColumn, SpinnerColumn, TimeElapsedColumn
import re
import subprocess
import sys
import concurrent.futures

class NetworkScanner:
    """Class for network discovery and scanning"""
    
    def __init__(self):
        """Initialize the scanner"""
        self.discovered_devices = []
        self.port_scan_results = {}
        self.local_interfaces = []
        self.continue_scan = True
        self._lock = threading.Lock()
        # Flag to enable/disable verbose output
        self.verbose = True
        # Callback for scan progress updates
        self.scan_callback = None

    def get_local_interfaces(self):
        """Get all available network interfaces"""
        interfaces = []
        try:
            # Get all interfaces
            all_ifaces = netifaces.interfaces()
            
            for iface in all_ifaces:
                # Skip loopback interfaces (127.x.x.x)
                if iface == 'lo' or iface.startswith('loop'):
                    terminal.info(f"Skipping loopback interface {iface}")
                    continue
                
                # Get interface addresses
                addrs = netifaces.ifaddresses(iface)
                
                # Skip interfaces without IPv4
                if netifaces.AF_INET not in addrs:
                    continue
                
                # Get IPv4 info
                ipv4_info = addrs[netifaces.AF_INET][0]
                ip = ipv4_info.get('addr', '')
                netmask = ipv4_info.get('netmask', '')
                
                # Skip loopback addresses (127.x.x.x)
                if ip.startswith('127.'):
                    terminal.info(f"Skipping loopback address {ip} on interface {iface}")
                    continue
                
                # Get MAC address if available
                mac = ''
                if netifaces.AF_LINK in addrs:
                    mac = addrs[netifaces.AF_LINK][0].get('addr', '')
                
                # Calculate CIDR notation
                cidr = self._netmask_to_cidr(netmask)
                network = f"{ip}/{cidr}"
                
                # Create interface info
                interface = {
                    'name': iface,
                    'ip': ip,
                    'netmask': netmask,
                    'mac': mac,
                    'network': network
                }
                
                interfaces.append(interface)
                
            self.local_interfaces = interfaces
            return interfaces
            
        except Exception as e:
            terminal.error(f"Error getting interfaces: {str(e)}")
            return interfaces
    
    def get_subnet_list(self):
        """Build a comprehensive list of detectable subnets based on local interfaces and common networks"""
        subnets = []
        
        # First get local subnets from interfaces
        interfaces = self.get_local_interfaces()
        for interface in interfaces:
            network = interface.get('network')
            if network:
                subnet = {
                    'network': network,
                    'source': f"Interface {interface.get('name')}",
                    'interface': interface.get('name'),
                    'type': 'local'
                }
                subnets.append(subnet)
        
        # Add common subnets that might be present but not directly attached
        common_networks = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16"
        ]
        
        # Check if we already have these networks from interfaces
        existing_networks = [s['network'].split('/')[0] for s in subnets]
        
        for network in common_networks:
            base_ip = network.split('/')[0]
            # Skip if we already have this network
            if any(ip.startswith(base_ip.rsplit('.', 1)[0]) for ip in existing_networks):
                continue
                
            # For large networks, add common subdivisions instead
            if network == "10.0.0.0/8":
                for i in range(0, 256, 32):
                    subnet = {
                        'network': f"10.{i}.0.0/16",
                        'source': "Common private range",
                        'interface': None,
                        'type': 'common'
                    }
                    subnets.append(subnet)
            elif network == "172.16.0.0/12":
                for i in range(16, 32, 4):
                    subnet = {
                        'network': f"172.{i}.0.0/16",
                        'source': "Common private range",
                        'interface': None,
                        'type': 'common'
                    }
                    subnets.append(subnet)
            elif network == "192.168.0.0/16":
                for i in range(0, 256, 16):
                    subnet = {
                        'network': f"192.168.{i}.0/24",
                        'source': "Common private range",
                        'interface': None,
                        'type': 'common'
                    }
                    subnets.append(subnet)
        
        # Add special networks that are commonly used
        special_networks = [
            {"network": "10.42.1.0/24", "source": "Special network"},
            {"network": "10.0.2.0/24", "source": "Common VM network"},
            {"network": "192.168.56.0/24", "source": "VirtualBox host-only"},
            {"network": "192.168.99.0/24", "source": "Docker/VM common"},
            {"network": "172.17.0.0/16", "source": "Docker default"}
        ]
        
        for network in special_networks:
            network_ip = network["network"].split('/')[0].rsplit('.', 1)[0]
            # Skip if we already have this network
            if any(ip.startswith(network_ip) for ip in existing_networks):
                continue
                
            subnet = {
                'network': network["network"],
                'source': network["source"],
                'interface': None,
                'type': 'special'
            }
            subnets.append(subnet)
        
        return subnets
    
    def show_subnet_list(self):
        """Get and display the list of subnets for scanning"""
        subnets = self.get_subnet_list()
        
        terminal.success(f"Found {len(subnets)} potential networks to scan:")
        
        for i, subnet in enumerate(subnets, 1):
            network = subnet['network']
            source = subnet['source']
            
            if subnet['type'] == 'local':
                terminal.success(f"{i}. {network} - {source}")
            elif subnet['type'] == 'special':
                terminal.warning(f"{i}. {network} - {source}")
            else:
                terminal.info(f"{i}. {network} - {source}")
        
        return subnets
    
    def arp_scan(self, target_range):
        """
        Perform ARP scan on a target network range
        target_range: IP range in CIDR notation (e.g., '192.168.1.0/24')
        """
        devices = []
        
        try:
            terminal.info(f"Starting ARP scan for {target_range}")
            
            # Parse the target range to get network information
            network = ipaddress.IPv4Network(target_range, strict=False)
            total_hosts = network.num_addresses
            
            # Skip for very large networks (e.g., /8, /16) as they're too big for ARP scanning
            if total_hosts > 256:
                terminal.warning(f"Network {target_range} is too large ({total_hosts} addresses). Limiting scan to first 256 addresses.")
                # Limit to first 256 addresses
                target_ips = [str(ip) for ip in list(network.hosts())[:256]]
            else:
                target_ips = [str(ip) for ip in network.hosts()]
            
            terminal.info(f"Scanning {len(target_ips)} IP addresses...")
            
            # Use multiprocessing to scan IPs in parallel
            # We'll split the IPs into chunks for batch processing
            chunk_size = 16  # Process 16 IPs at a time
            
            # Process IPs in chunks
            for i in range(0, len(target_ips), chunk_size):
                # Check if we should stop scanning (for interrupt handling)
                if not self.continue_scan:
                    terminal.warning("Scan interrupted. Stopping...")
                    break
                    
                # Get the current chunk of IPs
                chunk = target_ips[i:i+chunk_size]
                terminal.info(f"Scanning IP batch {i//chunk_size + 1}/{len(target_ips)//chunk_size + 1}: {chunk[0]}-{chunk[-1]}")
                
                # Create and send ARP requests for this chunk
                responses = self._scan_ip_chunk(chunk)
                
                # Process responses
                for ip_addr, mac_addr in responses:
                    # Check if device is already discovered to prevent duplicates
                    if not any(d['ip'] == ip_addr for d in devices):
                        # Double MAC address sanitization
                        mac_addr = self._sanitize_mac(mac_addr)
                        
                        # Get vendor and hostname
                        vendor = self.get_mac_vendor(mac_addr)
                        hostname = self.get_hostname(ip_addr)
                        
                        # Create device info
                        device = {
                            'ip': ip_addr,
                            'mac': mac_addr,
                            'vendor': vendor,
                            'hostname': hostname,
                            'status': 'up',
                            'subnet': target_range,
                            'last_seen': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                        
                        devices.append(device)
                        terminal.success(f"Found device: {ip_addr} ({hostname or 'Unknown'})")
            
            # Update the master list of discovered devices
            with self._lock:
                # Add new devices and update existing ones
                for device in devices:
                    # Check if device already exists in master list
                    existing = next((d for d in self.discovered_devices if d['ip'] == device['ip']), None)
                    if existing:
                        # Update existing device with new info
                        existing.update(device)
                    else:
                        # Add new device
                        self.discovered_devices.append(device)
            
            return devices
            
        except KeyboardInterrupt:
            terminal.warning("Scan interrupted by user. Stopping...")
            self.continue_scan = False
            return devices
        except Exception as e:
            terminal.error(f"ARP scan error: {str(e)}")
            return []            
    
    def _scan_ip_chunk(self, ip_chunk):
        """
        Scan a chunk of IP addresses in parallel
        Returns a list of (ip, mac) tuples for discovered devices
        """
        results = []
        
        try:
            # Create an ARP request packet for the entire chunk at once
            # This is more efficient than individual packets
            arp_request = ARP(pdst=ip_chunk)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp_request
            
            # Set a shorter timeout to allow for keyboard interrupts
            # We'll do multiple quick scans instead of one long one
            scan_result = srp(packet, timeout=1, verbose=0, retry=1)[0]
            
            # Process responses
            for sent, received in scan_result:
                ip_addr = received.psrc
                mac_addr = received.hwsrc
                
                results.append((ip_addr, mac_addr))
                
        except Exception as e:
            terminal.error(f"Chunk scan error: {str(e)}")
            
        return results
    
    def _sanitize_mac(self, mac_address):
        """
        Sanitize MAC address to ensure it's in the correct format.
        Removes any non-hexadecimal characters and formats with hyphens.
        """
        if not mac_address:
            return "Unknown"
            
        try:
            # Convert to string if it's not already
            mac_address = str(mac_address)
            
            # Special case - if we see the disc/CD emoji or other known invalid characters
            # These seem to be encoding errors that appear in some MAC addresses
            mac_address = mac_address.replace('💿', '')
            mac_address = mac_address.replace('�', '')
            
            # Check if it's already a well-formed MAC address with colons or hyphens
            if re.match(r'^([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}$', mac_address):
                # If it has colons, replace them with hyphens
                clean_mac = mac_address.replace(':', '-').lower()
                return clean_mac
                
            # First, remove all non-hex digits
            clean_mac = re.sub(r'[^0-9a-fA-F]', '', mac_address)
            
            # Make sure it's the right length (12 hex digits)
            if len(clean_mac) != 12:
                # If it's not 12 characters, it's malformed
                # Pad with zeros if too short, or truncate if too long
                clean_mac = clean_mac.ljust(12, '0')[:12]
                
            # Format as xx-xx-xx-xx-xx-xx (with hyphens instead of colons)
            formatted_mac = '-'.join(clean_mac[i:i+2] for i in range(0, 12, 2))
            return formatted_mac.lower()
            
        except Exception as e:
            terminal.warning(f"Error sanitizing MAC address {mac_address}: {str(e)}")
            return "00-00-00-00-00-00"  # Return a placeholder with hyphens
    
    def get_mac_vendor(self, mac_address):
        """Get vendor from MAC address"""
        try:
            # Use a synchronous approach instead of async
            vendor = MacLookup().lookup(mac_address)
            return vendor
        except Exception:
            return "Unknown"
    
    def get_hostname(self, ip_address):
        """Resolve hostname from IP address"""
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror):
            return "Unknown"
    
    def port_scan(self, ip_address, ports="22,80,443,445,3389", progress=None):
        """
        Scan for open ports on a specific IP address
        ports: comma-separated list of ports or ranges (e.g., "22-25,80,443")
        """
        try:
            nm = nmap.PortScanner()
            
            if progress:
                terminal.info(f"Scanning ports on {ip_address}...")
                result = nm.scan(ip_address, ports, arguments='-T4 -sV')
            else:
                result = nm.scan(ip_address, ports, arguments='-T4 -sV')
            
            if ip_address not in nm.all_hosts():
                return []
            
            open_ports = []
            for port in nm[ip_address]['tcp']:
                if nm[ip_address]['tcp'][port]['state'] == 'open':
                    service_info = {
                        'port': port,
                        'service': nm[ip_address]['tcp'][port]['name'],
                        'version': nm[ip_address]['tcp'][port]['product'] + ' ' + 
                                  nm[ip_address]['tcp'][port]['version'],
                        'state': 'open'
                    }
                    open_ports.append(service_info)
            
            self.port_scan_results[ip_address] = open_ports
            return open_ports
            
        except Exception as e:
            terminal.error(f"Error during port scan: {e}")
            return []
    
    def scan_network(self, target_range=None):
        """
        Scan a network range for devices
        If no target_range provided, scans all local networks
        """
        # If no target specified, use all local networks
        if not target_range:
            if not self.local_interfaces:
                self.get_local_interfaces()
            
            all_devices = []
            
            # Filter out interfaces without a range property
            valid_interfaces = [iface for iface in self.local_interfaces if 'range' in iface]
            
            if not valid_interfaces:
                terminal.warning("No valid network interfaces found for scanning")
                return []
            
            # Scan each interface
            terminal.info(f"Starting network scan across {len(valid_interfaces)} interfaces...")
            
            for i, interface in enumerate(valid_interfaces):
                # Only scan interfaces with valid network ranges
                if 'range' in interface:
                    try:
                        ip = interface['ip']
                        network_range = interface['range']
                        
                        terminal.info(f"Scanning network: {network_range} on {interface['name']} ({i+1}/{len(valid_interfaces)})")
                        
                        # Perform the ARP scan
                        devices = self.arp_scan(network_range)
                        all_devices.extend(devices)
                        
                        # Report results for this interface
                        if devices:
                            terminal.success(f"Found {len(devices)} devices on {interface['name']} ({ip})")
                        else:
                            terminal.warning(f"No devices found on {interface['name']} ({ip})")
                    except Exception as e:
                        terminal.error(f"Error scanning interface {interface['name']}: {str(e)}")
            
            self.discovered_devices = all_devices
            if all_devices:
                terminal.success(f"Scan complete! Discovered {len(all_devices)} devices total")
            else:
                terminal.warning("Scan complete. No devices found.")
            return all_devices
        else:
            # Scan specific target range
            terminal.info(f"Scanning target network: {target_range}")
            
            # Perform the scan
            devices = self.arp_scan(target_range)
            
            # Report results
            if devices:
                terminal.success(f"Found {len(devices)} devices on {target_range}")
            else:
                terminal.warning(f"No devices found on {target_range}")
            
            return devices
    
    def get_scan_results(self):
        """Return all discovered devices"""
        return self.discovered_devices

    def export_data_to_json(self, filename=None):
        """
        Export all collected data to a structured JSON file
        Returns the path to the saved file
        """
        try:
            # Generate filename if not provided
            if not filename:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"netscan_results_{timestamp}.json"
            
            # Create results directory if it doesn't exist
            output_dir = os.path.join(os.getcwd(), 'results')
            os.makedirs(output_dir, exist_ok=True)
            
            # Ensure the filename starts with the output directory
            if not filename.startswith(output_dir):
                filename = os.path.join(output_dir, os.path.basename(filename))
            
            # Create structured data
            data = {
                "scan_info": {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "total_devices": len(self.discovered_devices)
                },
                "devices": self.discovered_devices,
                "device_count": len(self.discovered_devices),
                "port_scan_results": self.port_scan_results
            }
            
            # Write to file
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
                
            terminal.success(f"Data exported to: {filename}")
            return filename
        
        except Exception as e:
            terminal.error(f"Error exporting data: {str(e)}")
            return None

    def scan_specific_network(self, target_ip):
        """
        Perform an intensive scan on a specific network, especially useful for 
        hard-to-detect networks like 10.42.1.0/24.
        """
        devices = []
        
        try:
            # Convert target to a network range if it's not already
            if '/' not in target_ip:
                # If it's a single IP, convert to a /24 network
                ip_parts = target_ip.split('.')
                network_prefix = '.'.join(ip_parts[0:3])
                target_network = f"{network_prefix}.0/24"
            else:
                # It's already a network range
                target_network = target_ip
            
            terminal.info(f"Starting intensive network scan on {target_network}")
            
            # First, try a regular ARP scan with our improved chunking method
            terminal.info("Phase 1: ARP broadcast scanning")
            devices = self.arp_scan(target_network)
            
            # If we found very few devices, try additional methods
            if len(devices) < 3:
                terminal.info("Phase 2: Individual IP probing")
                
                # Check if we should stop scanning (for interrupt handling)
                if not getattr(self, 'continue_scan', True):
                    terminal.warning("Scan interrupted. Stopping...")
                    return devices
                
                # Get network information
                network = ipaddress.IPv4Network(target_network, strict=False)
                
                # Try dedicated scan for certain IPs that are commonly used
                common_hosts = [1, 2, 3, 10, 20, 50, 100, 150, 200, 254]
                
                terminal.info("Probing common IP addresses...")
                for host in common_hosts:
                    # Check for interrupt
                    if not getattr(self, 'continue_scan', True):
                        break
                        
                    # Only check if we haven't already found this IP
                    target_ip = f"{network_prefix}.{host}"
                    if not any(d['ip'] == target_ip for d in devices):
                        # Try direct ping to this IP
                        if self._quick_ping(target_ip):
                            # Get MAC address through ARP cache
                            mac = self._get_mac_from_arp(target_ip)
                            if mac:
                                # Get hostname and vendor
                                hostname = self.get_hostname(target_ip)
                                vendor = self.get_mac_vendor(mac)
                                
                                # Add to discovered devices
                                device = {
                                    'ip': target_ip,
                                    'mac': mac,
                                    'vendor': vendor,
                                    'hostname': hostname,
                                    'status': 'up',
                                    'last_seen': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                }
                                
                                devices.append(device)
                                terminal.success(f"Found device through direct probe: {target_ip} ({hostname or 'Unknown'})")
            
            # Update the master list
            with self._lock:
                # Add new devices and update existing ones
                for device in devices:
                    existing = next((d for d in self.discovered_devices if d['ip'] == device['ip']), None)
                    if existing:
                        existing.update(device)
                    else:
                        self.discovered_devices.append(device)
            
            return devices
            
        except KeyboardInterrupt:
            terminal.warning("Scan interrupted by user. Stopping...")
            self.continue_scan = False
            return devices
        except Exception as e:
            terminal.error(f"Network scan error: {str(e)}")
            return devices

    def _quick_ping(self, ip):
        """Perform a quick ping to check if host is up"""
        try:
            # Using scapy to send a quick ICMP echo request with short timeout
            response = sr1(IP(dst=ip)/ICMP(), timeout=0.5, verbose=0)
            return response is not None
        except Exception:
            return False

    def _get_mac_from_arp(self, ip):
        """Get MAC address from system ARP cache"""
        try:
            if sys.platform.startswith('win'):
                # Windows command
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line:
                            # Extract MAC from ARP output
                            match = re.search(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', line)
                            if match:
                                return self._sanitize_mac(match.group(1))
            else:
                # Linux/Mac command
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line:
                            # Extract MAC from ARP output
                            match = re.search(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})', line)
                            if match:
                                return self._sanitize_mac(match.group(1))
        except Exception as e:
            pass
            
        return None

    def _netmask_to_cidr(self, netmask):
        """Convert netmask to CIDR notation"""
        return str(sum([bin(int(i)).count('1') for i in netmask.split('.')]))

    def discover_active_subnets(self):
        """
        Actively discover subnets by sending probes and analyzing network traffic.
        Returns a list of active subnets.
        """
        active_subnets = []
        
        # First get local interfaces
        terminal.info("Analyzing local interfaces...")
        interfaces = self.get_local_interfaces()
        
        # Step 1: Test local subnets first
        terminal.info("Probing local networks...")
        for interface in interfaces:
            network = interface.get('network')
            if not network:
                continue
                
            interface_name = interface.get('name')
            terminal.info(f"Checking activity on {network} (interface: {interface_name})...")
            
            # Send a few test packets to determine if the network is active
            if self._is_subnet_active(network):
                subnet = {
                    'network': network,
                    'source': f"Active local network ({interface_name})",
                    'interface': interface_name,
                    'type': 'active_local',
                    'priority': 1  # Highest priority
                }
                active_subnets.append(subnet)
                terminal.success(f"Found active subnet: {network}")
        
        # Step 2: Check gateway connectivity and determine adjacent networks
        terminal.info("Checking gateway and adjacent networks...")
        gateways = self._get_default_gateways()
        for gw in gateways:
            if gw:
                # Get gateway subnet
                gw_ip = gw.get('gateway')
                if gw_ip:
                    # Create subnet from gateway
                    ip_parts = gw_ip.split('.')
                    network_prefix = '.'.join(ip_parts[0:3])
                    network = f"{network_prefix}.0/24"
                    
                    if any(s['network'] == network for s in active_subnets):
                        continue
                    
                    terminal.info(f"Testing subnet via gateway {gw_ip}...")
                    if self._is_subnet_active(network):
                        subnet = {
                            'network': network,
                            'source': f"Via gateway {gw_ip}",
                            'interface': gw.get('interface'),
                            'type': 'active_gateway',
                            'priority': 2
                        }
                        active_subnets.append(subnet)
                        terminal.success(f"Found active subnet via gateway: {network}")
        
        # Step 3: Look for special subnets we know might be active
        # These are common network ranges used in various environments
        special_networks = [
            "10.42.1.0/24",  # Your specifically mentioned network
            "10.0.2.0/24",   # Common VM network
            "192.168.56.0/24" # VirtualBox
        ]
        
        terminal.info("Checking special networks...")
        for network in special_networks:
            if any(s['network'] == network for s in active_subnets):
                continue
                
            terminal.info(f"Testing special network {network}...")
            if self._is_subnet_active(network):
                subnet = {
                    'network': network,
                    'source': "Active special network",
                    'interface': None,
                    'type': 'active_special',
                    'priority': 3
                }
                active_subnets.append(subnet)
                terminal.success(f"Found active special subnet: {network}")
        
        # Step 4: Explore adjacent networks to those we've found
        if active_subnets:
            terminal.info("Checking for adjacent networks to discovered subnets...")
            adjacent_networks = self._get_adjacent_networks(active_subnets)
            
            for network in adjacent_networks:
                if any(s['network'] == network for s in active_subnets):
                    continue
                    
                terminal.info(f"Testing adjacent network {network}...")
                if self._is_subnet_active(network):
                    subnet = {
                        'network': network,
                        'source': "Adjacent active network",
                        'interface': None,
                        'type': 'active_adjacent',
                        'priority': 4
                    }
                    active_subnets.append(subnet)
                    terminal.success(f"Found active adjacent subnet: {network}")
        
        # Sort by priority
        active_subnets.sort(key=lambda x: x.get('priority', 999))
        
        terminal.success(f"Found {len(active_subnets)} active subnets.")
        return active_subnets
    
    def show_active_subnets(self):
        """Discover and display active subnets"""
        terminal.info("Discovering active subnets...")
        subnets = self.discover_active_subnets()
        
        if subnets:
            terminal.success(f"Found {len(subnets)} active subnets:")
            
            for i, subnet in enumerate(subnets, 1):
                network = subnet['network']
                source = subnet['source']
                
                # Different colors for different subnet types
                if subnet['type'] == 'active_local':
                    terminal.success(f"{i}. {network} - {source}")
                elif subnet['type'] == 'active_gateway':
                    terminal.warning(f"{i}. {network} - {source}")
                elif subnet['type'] == 'active_special':
                    terminal.warning(f"{i}. {network} - {source}")
                else:
                    terminal.info(f"{i}. {network} - {source}")
                    
            terminal.info("\nTo scan a specific subnet, use: scan <subnet>")
            terminal.info("Example: scan 10.42.1.0/24")
        else:
            terminal.warning("No active subnets found.")
            
        return subnets

    def discover_all_subnets_mt(self, max_threads=10):
        """
        Discover all available subnets using multi-threading.
        
        Args:
            max_threads: Maximum number of threads to use
            
        Returns:
            List of active subnet dictionaries
        """
        import multiprocessing
        from rich.progress import Progress, TextColumn, BarColumn, SpinnerColumn, TimeElapsedColumn
        
        # Get list of potential subnets to test
        terminal.info("Building list of potential subnets to scan...")
        
        # Start with subnets we know might be interesting
        potential_subnets = []
        
        # Step 1: Add all local interface networks
        local_interfaces = self.get_local_interfaces()
        for interface in local_interfaces:
            network = interface.get('network')
            if network:
                # Skip loopback
                if network.startswith('127.'):
                    continue
                    
                # Add direct network
                potential_subnets.append({
                    'network': network,
                    'source': f"Local interface ({interface.get('name')})",
                    'priority': 1
                })
                
                # Add expanded networks (e.g., if we have 192.168.1.0/24, also check 192.168.0.0/24)
                expanded = self._expand_network(network)
                for exp_net in expanded:
                    potential_subnets.append({
                        'network': exp_net,
                        'source': f"Adjacent to {network}",
                        'priority': 2
                    })
        
        # Step 2: Add gateway-based networks
        gateways = self._get_default_gateways()
        for gw in gateways:
            if gw:
                gw_ip = gw.get('gateway')
                if gw_ip:
                    # Create subnet from gateway
                    ip_parts = gw_ip.split('.')
                    network_prefix = '.'.join(ip_parts[0:3])
                    network = f"{network_prefix}.0/24"
                    
                    if not any(s['network'] == network for s in potential_subnets):
                        potential_subnets.append({
                            'network': network,
                            'source': f"Via gateway {gw_ip}",
                            'priority': 2
                        })
                    
                    # Also check networks near the gateway
                    expanded = self._expand_network(network)
                    for exp_net in expanded:
                        if not any(s['network'] == exp_net for s in potential_subnets):
                            potential_subnets.append({
                                'network': exp_net,
                                'source': f"Adjacent to gateway {gw_ip}",
                                'priority': 3
                            })
        
        # Step 3: Add special networks we care about
        special_networks = [
            "10.42.1.0/24",  # Specifically mentioned network
            "10.0.2.0/24",   # Common VM network
            "192.168.56.0/24", # VirtualBox host-only
            "172.17.0.0/16",  # Docker default
            "192.168.99.0/24"  # Docker Toolbox
        ]
        
        for network in special_networks:
            if not any(s['network'] == network for s in potential_subnets):
                potential_subnets.append({
                    'network': network,
                    'source': "Special network",
                    'priority': 3
                })
        
        # Step 4: Add common private networks
        common_networks = [
            "192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", 
            "10.0.0.0/24", "10.0.1.0/24", "10.1.1.0/24", 
            "172.16.0.0/24", "172.31.0.0/24"
        ]
        
        for network in common_networks:
            if not any(s['network'] == network for s in potential_subnets):
                potential_subnets.append({
                    'network': network,
                    'source': "Common private network",
                    'priority': 4
                })
        
        # Determine optimal thread count based on cores
        cpu_count = multiprocessing.cpu_count()
        optimal_threads = min(max_threads, cpu_count + 2)  # CPU count + 2 is a good rule of thumb
        
        terminal.info(f"Using {optimal_threads} threads to check {len(potential_subnets)} potential subnets...")
        
        # Set up thread pool and results list
        active_subnets = []
        active_subnets_lock = threading.Lock()
        
        # Create work queue and populate with networks
        work_queue = potential_subnets.copy()
        queue_lock = threading.Lock()
        
        # Track active threads
        threads = []
        
        # Shared flag for interruption
        self.continue_scan = True
        
        # Progress tracking
        total_to_scan = len(work_queue)
        completed = 0
        completed_lock = threading.Lock()
        
        # Track found subnets for display
        found_subnets_count = 0
        found_lock = threading.Lock()
        
        # Rich progress display
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TextColumn("[bold cyan]{task.completed}/{task.total}"),
            TextColumn("[bold green]{task.fields[found]} subnets found"),
            TimeElapsedColumn()
        ) as progress:
            # Create the main progress bar
            task = progress.add_task("[cyan]Scanning subnets...", total=total_to_scan, found=0)
            
            # Thread worker function
            def worker():
                nonlocal completed, found_subnets_count
                while self.continue_scan:
                    # Get network from queue
                    with queue_lock:
                        if not work_queue:
                            break
                        subnet_info = work_queue.pop(0)
                        
                        # Also update the total if we added new networks dynamically
                        if total_to_scan < len(potential_subnets):
                            progress.update(task, total=len(potential_subnets))
                    
                    subnet = subnet_info['network']
                    source = subnet_info['source']
                    
                    try:
                        # Check if subnet is active
                        is_active = self._is_subnet_active(subnet)
                        
                        # Update progress
                        with completed_lock:
                            completed += 1
                            progress.update(task, advance=1)
                        
                        if is_active:
                            # Add to results list with thread safety
                            with active_subnets_lock:
                                subnet_data = {
                                    'network': subnet,
                                    'source': source,
                                    'priority': subnet_info.get('priority', 999)
                                }
                                active_subnets.append(subnet_data)
                                
                                # Update found count
                                with found_lock:
                                    found_subnets_count += 1
                                    progress.update(task, found=found_subnets_count)
                                    
                            # If we find an active subnet, also add adjacent networks to queue
                            adjacent_networks = self._get_adjacent_networks([subnet_data])
                            with queue_lock:
                                for adj_net in adjacent_networks:
                                    if not any(s['network'] == adj_net for s in active_subnets) and \
                                       not any(s.get('network') == adj_net for s in work_queue):
                                        work_queue.append({
                                            'network': adj_net,
                                            'source': f"Adjacent to active subnet {subnet}",
                                            'priority': subnet_info.get('priority', 999) + 1
                                        })
                                        # Update potential subnets list
                                        potential_subnets.append({
                                            'network': adj_net,
                                            'source': f"Adjacent to active subnet {subnet}",
                                            'priority': subnet_info.get('priority', 999) + 1
                                        })
                                        
                    except KeyboardInterrupt:
                        self.continue_scan = False
                        return
                    except Exception as e:
                        # Update progress even on error
                        with completed_lock:
                            completed += 1
                            progress.update(task, advance=1)
                    
            # Start worker threads
            try:
                for i in range(optimal_threads):
                    thread = threading.Thread(target=worker)
                    thread.daemon = True
                    threads.append(thread)
                    thread.start()
                
                # Wait for all threads to complete or keyboard interrupt
                for thread in threads:
                    while thread.is_alive() and self.continue_scan:
                        thread.join(timeout=0.5)
                        
            except KeyboardInterrupt:
                terminal.warning("Scan interrupted by user. Processing results...")
                self.continue_scan = False
        
        # Sort active subnets by priority
        active_subnets.sort(key=lambda x: x.get('priority', 999))
        
        terminal.success(f"Found {len(active_subnets)} active subnets.")
        return active_subnets
    
    def _expand_network(self, network_cidr):
        """
        Expand a network to include adjacent networks.
        E.g., for 192.168.1.0/24, return [192.168.0.0/24, 192.168.2.0/24]
        """
        try:
            expanded = []
            network = ipaddress.IPv4Network(network_cidr, strict=False)
            
            # For /24 networks, check one level up and down
            prefix_len = network.prefixlen
            if prefix_len == 24:
                # Get the network as an integer
                network_int = int(network.network_address)
                network_bytes = network_int.to_bytes(4, byteorder='big')
                
                # Add networks with third octet +/- 1
                third_octet = network_bytes[2]
                
                for new_third in [third_octet - 1, third_octet + 1]:
                    if 0 <= new_third <= 255:
                        new_bytes = bytearray(network_bytes)
                        new_bytes[2] = new_third
                        new_int = int.from_bytes(new_bytes, byteorder='big')
                        new_addr = ipaddress.IPv4Address(new_int)
                        expanded.append(f"{new_addr}/24")
                        
            # Also try one prefix shorter (e.g., /24 -> /16)
            if prefix_len > 16:
                supernet = network.supernet(new_prefix=16)
                expanded.append(str(supernet))
                
            return expanded
            
        except Exception as e:
            terminal.error(f"Error expanding network {network_cidr}: {str(e)}")
            return []
            
    def scan_all_discovered_subnets(self):
        """
        Discover and scan all active subnets.
        This method uses multi-threading to find all subnets and then scans them.
        """
        terminal.info("Starting comprehensive subnet discovery and scanning...")
        
        # Discover all active subnets
        active_subnets = self.discover_all_subnets_mt()
        
        if not active_subnets:
            terminal.warning("No active subnets found.")
            return []
            
        # Show discovered subnets
        terminal.success(f"Found {len(active_subnets)} active subnets:")
        for i, subnet in enumerate(active_subnets, 1):
            network = subnet['network']
            source = subnet['source']
            terminal.info(f"{i}. {network} - {source}")
        
        # Now scan each discovered subnet with parallel scanning
        return self._scan_subnets_parallel(active_subnets)
        
    def _scan_subnets_parallel(self, subnets, max_parallel=4):
        """
        Scan multiple subnets in parallel for better performance
        
        Args:
            subnets: List of subnet dictionaries to scan
            max_parallel: Maximum number of parallel scans
            
        Returns:
            List of discovered devices across all subnets
        """
        import multiprocessing
        from queue import Queue
        
        # Get optimal parallel count
        cpu_count = multiprocessing.cpu_count()
        parallel_count = min(max_parallel, cpu_count)
        
        terminal.info(f"\nBeginning scan of {len(subnets)} subnets using {parallel_count} parallel scanners...")
        
        # Create thread-safe collections
        all_devices = []
        devices_lock = threading.Lock()
        
        # Create subnet queue
        subnet_queue = Queue()
        for subnet in subnets:
            subnet_queue.put(subnet)
            
        # Shared flag for interruption
        self.continue_scan = True
        
        # Progress tracking
        completed = 0
        completed_lock = threading.Lock()
        total_subnets = len(subnets)
        
        # Create progress display
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TextColumn("[bold cyan]{task.completed}/{task.total}"),
            TextColumn("[bold green]{task.fields[devices]} devices found"),
            TimeElapsedColumn()
        ) as progress:
            # Create the main progress bar
            task = progress.add_task("[cyan]Scanning networks...", total=total_subnets, devices=0)
            
            # Worker function for subnet scanning
            def scan_worker():
                nonlocal completed
                devices_found = 0
                
                while self.continue_scan:
                    # Get subnet from queue
                    try:
                        if subnet_queue.empty():
                            break
                        subnet_info = subnet_queue.get(block=False)
                        network = subnet_info['network']
                        
                        # Update progress description
                        progress.update(task, description=f"[cyan]Scanning {network}")
                        
                        try:
                            # Scan the subnet
                            subnet_devices = self.scan_specific_network(network)
                            
                            # Add devices to the global list with thread safety
                            if subnet_devices:
                                with devices_lock:
                                    all_devices.extend(subnet_devices)
                                    devices_found += len(subnet_devices)
                                    # Update the total devices found
                                    progress.update(task, devices=len(all_devices))
                        except Exception as e:
                            terminal.error(f"Error scanning subnet {network}: {str(e)}")
                        
                        # Mark as completed
                        with completed_lock:
                            completed += 1
                            progress.update(task, completed=completed)
                            
                        # Mark task as done in queue
                        subnet_queue.task_done()
                        
                    except Exception:
                        # Queue empty or other error
                        break
            
            # Start scanner threads
            threads = []
            try:
                for i in range(parallel_count):
                    thread = threading.Thread(target=scan_worker)
                    thread.daemon = True
                    threads.append(thread)
                    thread.start()
                
                # Wait for all threads to complete or for interrupt
                for thread in threads:
                    while thread.is_alive() and self.continue_scan:
                        thread.join(timeout=0.5)
                        
            except KeyboardInterrupt:
                terminal.warning("Scan interrupted by user.")
                self.continue_scan = False
        
        terminal.success(f"Completed scan of all subnets. Found {len(all_devices)} devices total.")
        return all_devices

    def _test_subnet_tcp(self, subnet):
        """Test subnet activity using TCP SYN to common ports on key hosts"""
        try:
            # Parse subnet
            network = ipaddress.IPv4Network(subnet, strict=False)
            
            # Only test a few key hosts (.1, .254, etc.)
            hosts_to_test = []
            
            # Gateway (.1) is often active
            network_int = int(network.network_address)
            gateway_ip = str(ipaddress.IPv4Address(network_int + 1))  # .1 address
            hosts_to_test.append(gateway_ip)
            
            # Test end of the range for network devices (.254)
            if network.num_addresses > 250:
                end_ip = str(ipaddress.IPv4Address(network_int + 254))  # .254 address
                hosts_to_test.append(end_ip)
            
            # Common ports to test
            ports = [80, 443, 22, 8080]
            
            for host in hosts_to_test:
                for port in ports:
                    try:
                        # Quick TCP socket test
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)  # Very short timeout
                        result = sock.connect_ex((host, port))
                        sock.close()
                        
                        if result == 0:  # Port is open
                            return True
                    except:
                        pass
            
            return False
            
        except Exception as e:
            terminal.error(f"Error in TCP subnet test for {subnet}: {str(e)}")
            return False

    def _is_subnet_active(self, subnet):
        """
        Test if a subnet is active by sending probes and analyzing responses.
        Uses multiple techniques to increase detection accuracy.
        Returns True if the subnet appears to be active
        """
        try:
            # Parse the subnet
            network = ipaddress.IPv4Network(subnet, strict=False)
            
            # Method 1: ICMP ping test for key hosts
            try:
                # For very small subnets, test specific IPs
                if network.num_addresses <= 256:
                    # Test the first few hosts in the subnet
                    hosts_to_test = list(network.hosts())[:3]  # First 3 hosts
                    
                    # Also test the gateway (.1) which is usually the first host in the network
                    network_addr_int = int(network.network_address)
                    gateway_ip = str(ipaddress.IPv4Address(network_addr_int + 1))  # .1 address
                    
                    if gateway_ip not in [str(host) for host in hosts_to_test]:
                        hosts_to_test.append(ipaddress.IPv4Address(gateway_ip))
                    
                    # Test these hosts with pings
                    for host in hosts_to_test:
                        host_ip = str(host)
                        if self._quick_ping(host_ip):
                            terminal.success(f"Subnet {subnet} is active (ICMP ping)")
                            return True
                else:
                    # For larger networks, just test the gateway
                    network_addr_int = int(network.network_address)
                    gateway_ip = str(ipaddress.IPv4Address(network_addr_int + 1))
                    if self._quick_ping(gateway_ip):
                        terminal.success(f"Subnet {subnet} is active (ICMP ping)")
                        return True
            except Exception as e:
                terminal.error(f"Error in ICMP test for {subnet}: {str(e)}")
            
            # Method 2: ARP probe
            try:
                if self._send_arp_probe(subnet):
                    terminal.success(f"Subnet {subnet} is active (ARP)")
                    return True
            except Exception as e:
                terminal.error(f"Error in ARP test for {subnet}: {str(e)}")
            
            # Method 3: TCP port scan
            try:
                if self._test_subnet_tcp(subnet):
                    terminal.success(f"Subnet {subnet} is active (TCP)")
                    return True
            except Exception as e:
                terminal.error(f"Error in TCP test for {subnet}: {str(e)}")
            
            # No methods detected activity
            return False
                
        except Exception as e:
            terminal.error(f"Error checking subnet {subnet}: {str(e)}")
            return False

    def _send_arp_probe(self, subnet):
        """Send ARP probe to check if a subnet is active"""
        try:
            # Create and send ARP broadcast
            arp_request = ARP(pdst=subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp_request
            
            # Short timeout to check for responses
            result = srp(packet, timeout=1, verbose=0)[0]
            
            # If we got any responses, the subnet is active
            return len(result) > 0
            
        except Exception:
            return False
    
    def _get_default_gateways(self):
        """Get default gateway information"""
        gateways = []
        
        try:
            # Get gateways from netifaces
            gw_info = netifaces.gateways()
            
            # Check for default gateway
            if 'default' in gw_info and netifaces.AF_INET in gw_info['default']:
                default_gw = gw_info['default'][netifaces.AF_INET]
                if default_gw:
                    gw_ip, interface = default_gw[0], default_gw[1]
                    gateways.append({
                        'gateway': gw_ip,
                        'interface': interface,
                        'type': 'default'
                    })
            
            # Also look at all gateways, not just default
            if 2 in gw_info:  # 2 is AF_INET
                for gw_entry in gw_info[2]:
                    if len(gw_entry) >= 2:
                        gw_ip, interface = gw_entry[0], gw_entry[1]
                        if not any(g['gateway'] == gw_ip for g in gateways):
                            gateways.append({
                                'gateway': gw_ip,
                                'interface': interface,
                                'type': 'non_default'
                            })
            
        except Exception as e:
            terminal.error(f"Error getting gateways: {str(e)}")
            
        return gateways
    
    def _get_adjacent_networks(self, active_subnets):
        """
        Get networks adjacent to the active ones we've found
        For example, if 192.168.1.0/24 is active, check 192.168.0.0/24 and 192.168.2.0/24
        """
        adjacent = []
        
        for subnet in active_subnets:
            network_str = subnet['network']
            try:
                # Parse the network
                network = ipaddress.IPv4Network(network_str, strict=False)
                
                # Get first octet
                network_int = int(network.network_address)
                network_bytes = network_int.to_bytes(4, byteorder='big')
                first_octet = network_bytes[0]
                
                # Only consider private network ranges
                if first_octet in [10, 172, 192]:  # Private network ranges
                    # Get the network prefix
                    prefix_len = network.prefixlen
                    
                    # Generate adjacent networks based on the CIDR
                    if prefix_len == 24:  # For /24 networks
                        # Get the octets
                        second_octet = network_bytes[1]
                        third_octet = network_bytes[2]
                        
                        # Check one network below and one above
                        for offset in [-1, 1]:
                            new_third = third_octet + offset
                            # Skip invalid octet values
                            if new_third < 0 or new_third > 255:
                                continue
                                
                            # Create the new network bytes
                            new_network_bytes = bytearray(network_bytes)
                            new_network_bytes[2] = new_third
                            
                            # Convert back to an IPv4 address
                            new_network_int = int.from_bytes(new_network_bytes, byteorder='big')
                            new_ip = ipaddress.IPv4Address(new_network_int)
                            
                            # Create the new network string
                            new_network = f"{new_ip}/24"
                            if new_network not in adjacent:
                                adjacent.append(new_network)
                                
                    elif prefix_len == 16:  # For /16 networks
                        # Get the second octet
                        second_octet = network_bytes[1]
                        
                        # Check one network below and one above
                        for offset in [-1, 1]:
                            new_second = second_octet + offset
                            # Skip invalid octet values
                            if new_second < 0 or new_second > 255:
                                continue
                                
                            # Create the new network bytes
                            new_network_bytes = bytearray(network_bytes)
                            new_network_bytes[1] = new_second
                            
                            # Convert back to an IPv4 address
                            new_network_int = int.from_bytes(new_network_bytes, byteorder='big')
                            new_ip = ipaddress.IPv4Address(new_network_int)
                            
                            # Create the new network string
                            new_network = f"{new_ip}/16"
                            if new_network not in adjacent:
                                adjacent.append(new_network)
            except Exception as e:
                # Skip problematic networks
                terminal.error(f"Error processing adjacent network for {network_str}: {str(e)}")
                pass
                
        return adjacent
            
    def discover_subnets_from_routes(self):
        """Discover subnets by analyzing the system's routing table"""
        subnets = []
        try:
            terminal.info("Analyzing routing table for subnets...")
            
            # Use 'ip route' command to get routing information (Linux)
            if os.name == 'posix':
                route_output = subprocess.check_output(['ip', 'route'], universal_newlines=True)
                
                # Parse the output to extract network information
                for line in route_output.splitlines():
                    if 'dev' in line and not line.startswith('default'):
                        parts = line.split()
                        if '/' in parts[0]:  # This is a subnet in CIDR notation
                            subnet = {
                                'network': parts[0],
                                'interface': parts[parts.index('dev') + 1],
                                'source': 'Routing table',
                                'type': 'route'
                            }
                            subnets.append(subnet)
            
            # For Windows systems
            elif os.name == 'nt':
                route_output = subprocess.check_output(['route', 'print'], universal_newlines=True)
                # Parse the windows route output (more complex)
                in_routes_section = False
                for line in route_output.splitlines():
                    if "Network Destination" in line:
                        in_routes_section = True
                        continue
                    
                    if in_routes_section and line.strip() and not "==" in line:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] != "0.0.0.0":
                            network = parts[0]
                            netmask = parts[1]
                            interface = parts[3]
                            
                            # Convert to CIDR notation
                            cidr = self._netmask_to_cidr(netmask)
                            network_cidr = f"{network}/{cidr}"
                            
                            subnet = {
                                'network': network_cidr,
                                'interface': interface,
                                'source': 'Routing table',
                                'type': 'route'
                            }
                            subnets.append(subnet)
            
            terminal.success(f"Found {len(subnets)} subnets from routing table")
            return subnets
            
        except Exception as e:
            terminal.error(f"Error analyzing route table: {str(e)}")
            return []
    
    def discover_subnets_from_arp(self):
        """Discover potential subnets by analyzing the ARP cache"""
        subnets = set()
        try:
            terminal.info("Analyzing ARP cache for recent devices...")
            
            # Get the ARP cache (Linux)
            if os.name == 'posix':
                try:
                    arp_output = subprocess.check_output(['arp', '-n'], universal_newlines=True)
                except FileNotFoundError:
                    # Try alternative command if arp is not available
                    try:
                        arp_output = subprocess.check_output(['ip', 'neigh', 'show'], universal_newlines=True)
                    except:
                        terminal.warning("ARP command not available, trying alternative methods")
                        return []
                
                # Analyze IP addresses to infer subnets
                for line in arp_output.splitlines():
                    parts = line.split()
                    # Look for IP addresses in the output
                    for part in parts:
                        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', part):
                            ip = part
                            if not ip.startswith('127.'):  # Skip loopback
                                # Try to infer a /24 subnet
                                subnet = ip.rsplit('.', 1)[0] + '.0/24'
                                subnets.add(subnet)
            
            # For Windows systems
            elif os.name == 'nt':
                arp_output = subprocess.check_output(['arp', '-a'], universal_newlines=True)
                
                for line in arp_output.splitlines():
                    if 'Internet Address' in line or 'dynamic' in line or 'static' in line:
                        parts = line.split()
                        for part in parts:
                            # Look for items that could be IP addresses
                            if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', part):
                                ip = part
                                if not ip.startswith('127.'):  # Skip loopback
                                    # Try to infer a /24 subnet
                                    subnet = ip.rsplit('.', 1)[0] + '.0/24'
                                    subnets.add(subnet)
            
            subnet_list = [{'network': s, 'source': 'ARP cache', 'type': 'arp'} for s in subnets]
            terminal.success(f"Found {len(subnet_list)} subnets from ARP cache")
            return subnet_list
            
        except Exception as e:
            terminal.error(f"Error analyzing ARP cache: {str(e)}")
            return []
    
    def discover_subnets_from_gateways(self):
        """Discover subnets by identifying and analyzing gateways"""
        subnets = []
        try:
            terminal.info("Analyzing gateways to identify connected networks...")
            
            # Get default gateway (Linux)
            if os.name == 'posix':
                try:
                    # Try the ip route method first
                    route_output = subprocess.check_output(['ip', 'route', 'show', 'default'], universal_newlines=True)
                    
                    for line in route_output.splitlines():
                        if 'via' in line:
                            parts = line.split()
                            gateway_index = parts.index('via') + 1
                            if gateway_index < len(parts):
                                gateway = parts[gateway_index]
                                
                                # The gateway is likely on a directly connected subnet
                                subnet = {
                                    'network': f"{gateway.rsplit('.', 1)[0]}.0/24",
                                    'source': f"Gateway inference ({gateway})",
                                    'type': 'gateway'
                                }
                                subnets.append(subnet)
                except:
                    # Fallback to parsing /proc/net/route
                    try:
                        with open('/proc/net/route', 'r') as f:
                            for line in f.readlines()[1:]:  # Skip header
                                parts = line.split()
                                if len(parts) >= 3 and parts[1] == '00000000':  # Default route
                                    # Convert hex gateway to IP
                                    gw = parts[2]
                                    gw_ip = '.'.join([
                                        str(int(gw[6:8], 16)),
                                        str(int(gw[4:6], 16)),
                                        str(int(gw[2:4], 16)),
                                        str(int(gw[0:2], 16))
                                    ])
                                    
                                    subnet = {
                                        'network': f"{gw_ip.rsplit('.', 1)[0]}.0/24",
                                        'source': f"Gateway inference ({gw_ip})",
                                        'type': 'gateway'
                                    }
                                    subnets.append(subnet)
                    except:
                        terminal.warning("Could not access route information")
            
            # For Windows systems
            elif os.name == 'nt':
                route_output = subprocess.check_output(['ipconfig'], universal_newlines=True)
                
                for line in route_output.splitlines():
                    if 'Default Gateway' in line and '.' in line:
                        gateway = line.split(':')[-1].strip()
                        
                        subnet = {
                            'network': f"{gateway.rsplit('.', 1)[0]}.0/24",
                            'source': f"Gateway inference ({gateway})",
                            'type': 'gateway'
                        }
                        subnets.append(subnet)
            
            terminal.success(f"Found {len(subnets)} subnets from gateway analysis")
            return subnets
            
        except Exception as e:
            terminal.error(f"Error analyzing gateways: {str(e)}")
            return []
    
    def is_subnet_reachable(self, subnet):
        """Test if a subnet is reachable by pinging its network address"""
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
            # Try pinging the gateway (usually .1) or another address
            test_ip = str(network.network_address + 1)  # Usually the gateway
            
            # Use ping with short timeout
            if os.name == 'posix':
                result = subprocess.call(['ping', '-c', '1', '-W', '1', test_ip], 
                                        stdout=subprocess.DEVNULL, 
                                        stderr=subprocess.DEVNULL)
            else:  # Windows
                result = subprocess.call(['ping', '-n', '1', '-w', '1000', test_ip], 
                                        stdout=subprocess.DEVNULL, 
                                        stderr=subprocess.DEVNULL)
                
            return result == 0
        except:
            return False
    
    def smart_subnet_discovery(self):
        """Discover subnets using multiple intelligent methods"""
        terminal.info("Starting smart subnet discovery...")
        
        # Initialize results list
        discovered_subnets = []
        
        # Track seen networks to avoid duplicates
        seen_networks = set()
        
        try:
            # Method 1: Local interfaces (direct networks)
            terminal.info("Analyzing local network interfaces...")
            interfaces = self.get_local_interfaces()
            for interface in interfaces:
                if interface.get('network') and not interface.get('network').startswith('127.'):
                    network = interface.get('network')
                    if network not in seen_networks:
                        discovered_subnets.append({
                            'network': network,
                            'source': f"Local interface: {interface.get('name')}",
                            'type': 'local'
                        })
                        seen_networks.add(network)
            
            # Method 2: Routes
            terminal.info("Analyzing routing table...")
            try:
                route_subnets = self.discover_subnets_from_routes()
                for subnet in route_subnets:
                    if subnet['network'] not in seen_networks:
                        subnet['type'] = 'route'
                        discovered_subnets.append(subnet)
                        seen_networks.add(subnet['network'])
            except Exception as e:
                terminal.warning(f"Error analyzing routes: {str(e)}")
            
            # Method 3: ARP Cache
            terminal.info("Analyzing ARP cache...")
            try:
                arp_subnets = self.discover_subnets_from_arp()
                for subnet in arp_subnets:
                    if subnet['network'] not in seen_networks:
                        subnet['type'] = 'arp'
                        discovered_subnets.append(subnet)
                        seen_networks.add(subnet['network'])
            except Exception as e:
                terminal.warning(f"Error analyzing ARP cache: {str(e)}")
            
            # Method 4: Gateways
            terminal.info("Analyzing gateway information...")
            try:
                gateway_subnets = self.discover_subnets_from_gateways()
                for subnet in gateway_subnets:
                    if subnet['network'] not in seen_networks:
                        subnet['type'] = 'gateway'
                        discovered_subnets.append(subnet)
                        seen_networks.add(subnet['network'])
            except Exception as e:
                terminal.warning(f"Error analyzing gateways: {str(e)}")
            
            # Method 5: Common Networks
            terminal.info("Adding common network ranges...")
            common_networks = [
                {"cidr": "192.168.0.0/24", "desc": "Common home network"},
                {"cidr": "192.168.1.0/24", "desc": "Common home network"},
                {"cidr": "192.168.2.0/24", "desc": "Common home network"},
                {"cidr": "10.0.0.0/24", "desc": "Common private range"},
                {"cidr": "10.0.1.0/24", "desc": "Common private range"},
                {"cidr": "10.1.1.0/24", "desc": "Common private range"},
                {"cidr": "10.10.10.0/24", "desc": "Common private range"},
                {"cidr": "172.16.0.0/24", "desc": "Common private range"}
            ]
            
            for network in common_networks:
                if network["cidr"] not in seen_networks:
                    discovered_subnets.append({
                        'network': network["cidr"],
                        'source': network["desc"],
                        'type': 'common'
                    })
                    seen_networks.add(network["cidr"])
            
            # Method 6: Special Networks
            special_networks = [
                {"cidr": "10.42.1.0/24", "desc": "Special network"},
                {"cidr": "10.0.2.0/24", "desc": "Common VM network"},
                {"cidr": "192.168.56.0/24", "desc": "VirtualBox host-only"},
                {"cidr": "172.17.0.0/16", "desc": "Docker default"}
            ]
            
            for network in special_networks:
                if network["cidr"] not in seen_networks:
                    discovered_subnets.append({
                        'network': network["cidr"],
                        'source': network["desc"],
                        'type': 'special'
                    })
                    seen_networks.add(network["cidr"])
            
            terminal.success(f"Smart discovery found {len(discovered_subnets)} potential subnets")
            return discovered_subnets
            
        except Exception as e:
            terminal.error(f"Error during smart subnet discovery: {str(e)}")
            return []
