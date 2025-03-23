#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ipaddress
import socket
import time
import threading
import netifaces
from scapy.all import ARP, Ether, srp
import nmap
from mac_vendor_lookup import MacLookup
from netaddr import EUI, NotRegisteredError
import datetime
import json
import platform
from src.ui.terminal_output import terminal

class NetworkScanner:
    """Class for network discovery and scanning"""
    
    def __init__(self):
        self.mac_lookup = MacLookup()
        self.discovered_devices = []
        self.local_interfaces = []
        self._lock = threading.Lock()
        self.port_scan_results = {}
    
    def get_local_interfaces(self):
        """Get all available network interfaces"""
        terminal.info("Analyzing network interfaces...")
        interfaces = []
        for iface in netifaces.interfaces():
            try:
                # Get interface details
                addrs = netifaces.ifaddresses(iface)
                
                # Skip interfaces with no IPv4 address
                if netifaces.AF_INET not in addrs:
                    continue
                
                # Get IP address and netmask
                ipv4_info = addrs[netifaces.AF_INET][0]
                ip = ipv4_info.get('addr', 'Unknown')
                netmask = ipv4_info.get('netmask', 'Unknown')
                
                # Get MAC address if available
                mac = "Unknown"
                if netifaces.AF_LINK in addrs:
                    mac = addrs[netifaces.AF_LINK][0].get('addr', 'Unknown')
                
                # Add to list of interfaces
                interfaces.append({
                    'name': iface,
                    'ip': ip,
                    'netmask': netmask,
                    'mac': mac
                })
            except Exception as e:
                terminal.error(f"Error getting info for interface {iface}: {str(e)}")
        
        self.local_interfaces = interfaces
        terminal.success(f"Found {len(interfaces)} network interfaces")
        return interfaces
    
    def arp_scan(self, target_range):
        """
        Perform ARP scan on a target network range
        target_range: IP range in CIDR notation (e.g., '192.168.1.0/24')
        """
        try:
            devices = []
            
            # Create ARP request packet
            arp = ARP(pdst=target_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and capture responses
            terminal.info(f"Sending ARP packets to {target_range}")
            result = srp(packet, timeout=3, verbose=0)[0]
            
            # Process the responses
            for sent, received in result:
                # Extract information from response
                mac_addr = received.hwsrc
                # Ensure MAC address is clean and properly formatted
                if len(mac_addr) > 17:  # Standard MAC is 17 chars with colons
                    mac_addr = ":".join([mac_addr[i:i+2] for i in range(0, 12, 2)])
                
                ip_addr = received.psrc
                
                # Get vendor and hostname
                vendor = self.get_mac_vendor(mac_addr)
                hostname = self.get_hostname(ip_addr)
                
                device = {
                    'ip': ip_addr,
                    'mac': mac_addr,
                    'vendor': vendor,
                    'hostname': hostname,
                    'status': 'up'
                }
                
                devices.append(device)
            
            return devices
            
        except Exception as e:
            terminal.error(f"ARP scan error: {str(e)}")
            return []
    
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
            
            # Scan each interface
            terminal.info("Starting network scan across all interfaces...")
            total_interfaces = len(self.local_interfaces)
            
            for i, interface in enumerate(self.local_interfaces):
                # Only scan interfaces with valid IP addresses
                if 'ip' in interface and interface['ip'] != 'Unknown':
                    # Calculate network CIDR if possible
                    try:
                        ip = interface['ip']
                        netmask = interface['netmask']
                        network = f"{ip}/{netmask}"
                        
                        terminal.info(f"Scanning network: {network} ({i+1}/{total_interfaces})")
                        
                        # Perform the ARP scan without progress bar
                        devices = self.arp_scan(network)
                        all_devices.extend(devices)
                        
                        # Report results for this interface
                        terminal.success(f"Found {len(devices)} devices on {interface['name']} ({ip})")
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
        if not filename:
            # Create filename with timestamp if not provided
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"netscan_results_{timestamp}.json"
            
        # Ensure the filename has .json extension
        if not filename.endswith('.json'):
            filename += '.json'
            
        # Create structured data dictionary
        export_data = {
            "scan_info": {
                "timestamp": datetime.datetime.now().isoformat(),
                "scanner_version": "1.0.0",
                "scan_duration": self.last_scan_duration if hasattr(self, 'last_scan_duration') else None,
            },
            "local_system": {
                "interfaces": self.local_interfaces,
                "hostname": socket.gethostname(),
                "platform": platform.platform(),
            },
            "network": {
                "devices": self.discovered_devices,
                "device_count": len(self.discovered_devices),
                "port_scan_results": self.port_scan_results if hasattr(self, 'port_scan_results') else {},
            }
        }
        
        # Add advanced metadata for each device
        for device in export_data["network"]["devices"]:
            # Add ports information if available
            ip = device.get('ip')
            if hasattr(self, 'port_scan_results') and ip in self.port_scan_results:
                device['ports'] = self.port_scan_results[ip]
                
            # Add timestamps
            device['first_seen'] = datetime.datetime.now().isoformat()
            device['last_seen'] = datetime.datetime.now().isoformat()
            
            # Add risk assessment (placeholder for future enhancement)
            device['risk_score'] = 0
            device['notable_services'] = []
        
        # Save to file
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=4)
            return filename
        except Exception as e:
            terminal.error(f"Error exporting data: {str(e)}")
            return None
