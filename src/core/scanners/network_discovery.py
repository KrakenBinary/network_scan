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

from ...ui.cyber_effects import CyberEffect

class NetworkScanner:
    """Class for network discovery and scanning"""
    
    def __init__(self):
        self.cyber_fx = CyberEffect()
        self.mac_lookup = MacLookup()
        self.discovered_devices = []
        self.local_interfaces = []
        self._lock = threading.Lock()
        self.port_scan_results = {}
    
    def get_local_interfaces(self):
        """Get all available network interfaces"""
        with self.cyber_fx.hacker_spinner("Analyzing network interfaces"):
            interfaces = []
            for iface in netifaces.interfaces():
                # Skip loopback interface
                if iface.startswith('lo'):
                    continue
                
                try:
                    # Get the addresses for this interface
                    addresses = netifaces.ifaddresses(iface)
                    
                    # Check if it has IPv4 address
                    if netifaces.AF_INET in addresses:
                        ipv4_info = addresses[netifaces.AF_INET][0]
                        
                        # Get MAC address if available
                        mac = None
                        if netifaces.AF_LINK in addresses:
                            mac = addresses[netifaces.AF_LINK][0].get('addr')
                        
                        iface_info = {
                            'name': iface,
                            'ip': ipv4_info.get('addr'),
                            'netmask': ipv4_info.get('netmask'),
                            'mac': mac
                        }
                        
                        # Calculate network range
                        if iface_info['ip'] and iface_info['netmask']:
                            try:
                                network = ipaddress.IPv4Network(
                                    f"{iface_info['ip']}/{iface_info['netmask']}", 
                                    strict=False
                                )
                                iface_info['network'] = str(network.network_address)
                                iface_info['cidr'] = network.prefixlen
                                iface_info['range'] = f"{network.network_address}/{network.prefixlen}"
                            except ValueError:
                                pass
                        
                        interfaces.append(iface_info)
                except (ValueError, KeyError):
                    continue
            
            self.local_interfaces = interfaces
            return interfaces
    
    def arp_scan(self, target_range, progress=None, task_id=None):
        """
        Perform ARP scan on a target network range
        target_range: IP range in CIDR notation (e.g., '192.168.1.0/24')
        """
        try:
            target_network = ipaddress.IPv4Network(target_range)
            devices = []
            
            # Don't create a new task if we already have one
            has_own_task = False
            if progress and task_id is None:
                task_id = progress.add_task(f"[bright_green]Scanning {target_range}", total=100)
                has_own_task = True
            
            # Create ARP request packet
            arp = ARP(pdst=target_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and capture responses
            result = srp(packet, timeout=3, verbose=0)[0]
            
            completed = 0
            for sent, received in result:
                # Extract information from response
                mac_addr = received.hwsrc
                # Ensure MAC address is clean and properly formatted
                if len(mac_addr) > 17:  # Standard MAC is 17 chars with colons
                    mac_addr = ":".join([mac_addr[i:i+2] for i in range(0, 12, 2)])
                
                device = {
                    'ip': received.psrc,
                    'mac': mac_addr,
                    'vendor': self.get_mac_vendor(mac_addr),
                    'hostname': self.get_hostname(received.psrc),
                    'status': 'up'
                }
                devices.append(device)
                
                # Update progress
                if progress and task_id is not None:
                    completed += 1
                    if has_own_task:
                        # If we created our own task, update based on completed devices
                        progress.update(task_id, advance=1, description=f"[bright_green]Found {completed} devices")
                    else:
                        # If using parent task, just advance parent task
                        progress.update(task_id, advance=1)
            
            # Complete the progress bar
            if progress and task_id is not None and has_own_task:
                progress.update(task_id, completed=100)
            
            with self._lock:
                self.discovered_devices.extend(devices)
            
            return devices
            
        except Exception as e:
            print(f"Error scanning network {target_range}: {str(e)}")
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
                with self.cyber_fx.hacker_spinner(f"Scanning ports on {ip_address}"):
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
            print(f"Error during port scan: {e}")
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
            
            # Use a single progress bar for all networks
            with self.cyber_fx.cyber_progress() as progress:
                total_interfaces = len([iface for iface in self.local_interfaces if 'range' in iface])
                main_task = progress.add_task("[bright_green]Scanning all networks", total=total_interfaces)
                
                for interface in self.local_interfaces:
                    if 'range' in interface:
                        # Don't use progress.add_task in arp_scan, just pass the main task
                        devices = self.arp_scan(interface['range'], progress, main_task)
                        all_devices.extend(devices)
            
            self.discovered_devices = all_devices
            return all_devices
        else:
            # Scan specific target range
            with self.cyber_fx.cyber_progress() as progress:
                task = progress.add_task(f"[bright_green]Scanning {target_range}", total=100)
                devices = self.arp_scan(target_range, progress, task)
            
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
            print(f"Error exporting data: {str(e)}")
            return None
