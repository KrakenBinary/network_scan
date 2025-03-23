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
import traceback

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
                
                # Skip loopback interfaces (127.0.0.0/8)
                if ip.startswith('127.'):
                    terminal.info(f"Skipping loopback interface {iface}")
                    continue
                
                # Get MAC address if available
                mac = "Unknown"
                if netifaces.AF_LINK in addrs:
                    mac = addrs[netifaces.AF_LINK][0].get('addr', 'Unknown')
                
                # Calculate network CIDR
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    cidr = network.prefixlen
                    network_addr = str(network.network_address)
                    
                    # Add to list of interfaces with network information
                    interfaces.append({
                        'name': iface,
                        'ip': ip,
                        'netmask': netmask,
                        'mac': mac,
                        'network': network_addr,
                        'cidr': cidr,
                        'range': f"{network_addr}/{cidr}"
                    })
                except (ValueError, Exception) as e:
                    # Add interface without network information
                    terminal.warning(f"Could not calculate network for {iface}: {str(e)}")
                    interfaces.append({
                        'name': iface,
                        'ip': ip,
                        'netmask': netmask,
                        'mac': mac
                    })
            except Exception as e:
                terminal.error(f"Error getting info for interface {iface}: {str(e)}")
        
        self.local_interfaces = interfaces
        terminal.success(f"Found {len(interfaces)} usable network interfaces")
        return interfaces
    
    def arp_scan(self, target_range):
        """
        Perform ARP scan on a target network range
        target_range: IP range in CIDR notation (e.g., '192.168.1.0/24')
        """
        try:
            terminal.info(f"Starting ARP scan for {target_range}")
            devices = []
            
            # Parse the target range to get network information
            network = ipaddress.IPv4Network(target_range, strict=False)
            total_hosts = network.num_addresses
            
            # Skip for very large networks (e.g., /8, /16) as they're too big for ARP scanning
            if total_hosts > 1024:
                terminal.warning(f"Network {target_range} is too large ({total_hosts} addresses). Limiting scan to first 256 addresses.")
                # Limit to first 256 addresses
                target_ips = [str(ip) for ip in list(network.hosts())[:256]]
            else:
                target_ips = [str(ip) for ip in network.hosts()]
            
            terminal.info(f"Scanning {len(target_ips)} IP addresses...")
            
            # Create ARP request packets for each IP
            # We'll use a more direct approach with individual packets for better results
            for i, ip in enumerate(target_ips):
                if i % 25 == 0:  # Show progress every 25 IPs
                    terminal.info(f"Scanning IP {i+1}/{len(target_ips)}: {ip}")
                
                try:
                    # Create and send ARP request
                    arp_request = ARP(pdst=ip)
                    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = ether/arp_request
                    
                    # Send packet with a longer timeout for better results
                    result = srp(packet, timeout=2, verbose=0, retry=2)[0]
                    
                    # Process responses
                    for sent, received in result:
                        # Extract information
                        ip_addr = received.psrc
                        mac_addr = received.hwsrc
                        
                        # Clean up MAC address if needed
                        if len(mac_addr) > 17:
                            mac_addr = ":".join([mac_addr[i:i+2] for i in range(0, 12, 2)])
                        
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
                            'last_seen': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                        
                        # Add to list, avoiding duplicates
                        if not any(d['ip'] == ip_addr for d in devices):
                            devices.append(device)
                            terminal.success(f"Found device: {ip_addr} ({hostname or 'Unknown'})")
                
                except Exception as e:
                    terminal.error(f"Error scanning {ip}: {str(e)}")
            
            # Try an alternative scan method if few or no devices were found
            if len(devices) < 2:
                terminal.info("Using alternative scan method for better device discovery...")
                # Send a broadcast packet to all addresses at once
                arp_request = ARP(pdst=target_range)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = broadcast/arp_request
                
                # Increase timeout for better results
                result = srp(packet, timeout=5, verbose=0, retry=3)[0]
                
                for sent, received in result:
                    ip_addr = received.psrc
                    mac_addr = received.hwsrc
                    
                    # Skip if already in our list
                    if any(d['ip'] == ip_addr for d in devices):
                        continue
                    
                    # Get device info
                    vendor = self.get_mac_vendor(mac_addr)
                    hostname = self.get_hostname(ip_addr)
                    
                    device = {
                        'ip': ip_addr,
                        'mac': mac_addr,
                        'vendor': vendor,
                        'hostname': hostname,
                        'status': 'up',
                        'last_seen': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    devices.append(device)
                    terminal.success(f"Found additional device: {ip_addr} ({hostname or 'Unknown'})")
            
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

    def scan_specific_network(self, target_ip):
        """
        Scan a specific network based on target IP
        This performs a more intensive scan on a specific network
        """
        try:
            # Determine CIDR notation (assuming a /24 subnet if not specified)
            if '/' not in target_ip:
                # Extract the network part and create a /24 CIDR
                ip_parts = target_ip.split('.')
                network_part = '.'.join(ip_parts[0:3])
                target_range = f"{network_part}.0/24"
            else:
                target_range = target_ip
            
            # For the 10.42.1.1 network specifically, we'll use a different approach
            is_target_network = target_ip.startswith("10.42.1.") or target_range.startswith("10.42.1.")
            if is_target_network:
                terminal.info("Detected 10.42.1.x network - using optimized scan approach...")
            
            terminal.info(f"Performing intensive scan on {target_range}...")
            
            # Set up ARP scanning
            devices = []
            
            # Send directed ARP requests to each IP in the subnet for better results
            if is_target_network:
                # For our target network, we'll generate and scan all possible IP addresses
                for i in range(1, 255):
                    ip = f"10.42.1.{i}"
                    
                    # Create ARP request for this specific IP
                    arp_request = ARP(pdst=ip)
                    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = ether/arp_request
                    
                    # Using longer timeout for the target network
                    result = srp(packet, timeout=3, verbose=0, retry=3)[0]
                    
                    for sent, received in result:
                        ip_addr = received.psrc
                        mac_addr = received.hwsrc
                        
                        if not any(d['ip'] == ip_addr for d in devices):
                            vendor = self.get_mac_vendor(mac_addr)
                            hostname = self.get_hostname(ip_addr)
                            
                            device = {
                                'ip': ip_addr,
                                'mac': mac_addr,
                                'vendor': vendor,
                                'hostname': hostname,
                                'status': 'up',
                                'last_seen': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
                            
                            devices.append(device)
                            terminal.success(f"Found device: {ip_addr} ({hostname or vendor or 'Unknown'})")
            
            # Direct scan with increased parameters
            arp_request = ARP(pdst=target_range)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast/arp_request
            
            # More aggressive scan parameters
            terminal.info("Sending broadcast ARP requests (attempt 1 of 3)...")
            
            # Multiple scan attempts with different timeouts
            for attempt in range(1, 4):
                # Increase timeout and retry for each attempt
                timeout = 3 + (attempt * 2)
                
                terminal.info(f"Scan attempt {attempt}/3 with {timeout}s timeout...")
                result = srp(packet, timeout=timeout, verbose=0, retry=3)[0]
                
                for sent, received in result:
                    ip_addr = received.psrc
                    mac_addr = received.hwsrc
                    
                    # Skip if already in our list
                    if any(d['ip'] == ip_addr for d in devices):
                        continue
                    
                    # Get device info
                    vendor = self.get_mac_vendor(mac_addr)
                    hostname = self.get_hostname(ip_addr)
                    
                    device = {
                        'ip': ip_addr,
                        'mac': mac_addr,
                        'vendor': vendor,
                        'hostname': hostname,
                        'status': 'up',
                        'last_seen': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    devices.append(device)
                    terminal.success(f"Found device: {ip_addr} ({hostname or vendor or 'Unknown'})")
            
            # Try an alternative approach with direct IP probing
            if len(devices) < 6 and is_target_network:
                terminal.info("Using alternative method specifically for 10.42.1.x network...")
                
                # Define gateway - likely to respond
                gateway = "10.42.1.1"
                
                # Check if gateway is in our list
                if not any(d['ip'] == gateway for d in devices):
                    # Try a more direct approach with rawsend
                    try:
                        # Send ping to gateway
                        ping_packet = IP(dst=gateway)/ICMP()
                        send(ping_packet, verbose=0)
                        
                        # Now try ARP again
                        arp_response = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gateway), 
                                           timeout=2, verbose=0)
                        
                        if arp_response:
                            ip_addr = arp_response.psrc
                            mac_addr = arp_response.hwsrc
                            
                            vendor = self.get_mac_vendor(mac_addr)
                            hostname = self.get_hostname(ip_addr)
                            
                            device = {
                                'ip': ip_addr,
                                'mac': mac_addr,
                                'vendor': vendor,
                                'hostname': hostname,
                                'status': 'up',
                                'last_seen': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
                            
                            if not any(d['ip'] == ip_addr for d in devices):
                                devices.append(device)
                                terminal.success(f"Found gateway device: {ip_addr}")
                    except Exception as e:
                        terminal.warning(f"Failed to detect gateway: {e}")
                
                # Try to find common host IPs on the target network
                common_hosts = [2, 3, 4, 5, 10, 15, 20, 25, 30, 50, 100, 150, 200, 250]
                for host in common_hosts:
                    ip = f"10.42.1.{host}"
                    
                    # Skip if already found
                    if any(d['ip'] == ip for d in devices):
                        continue
                    
                    try:
                        # Use more direct approach
                        terminal.info(f"Probing potential host at {ip}...")
                        
                        # First ping to wake up the host
                        ping_packet = IP(dst=ip)/ICMP()
                        send(ping_packet, verbose=0)
                        
                        # Then ARP
                        arp_response = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                                           timeout=2, verbose=0)
                        
                        if arp_response:
                            ip_addr = arp_response.psrc
                            mac_addr = arp_response.hwsrc
                            
                            vendor = self.get_mac_vendor(mac_addr)
                            hostname = self.get_hostname(ip_addr)
                            
                            device = {
                                'ip': ip_addr,
                                'mac': mac_addr,
                                'vendor': vendor,
                                'hostname': hostname,
                                'status': 'up',
                                'last_seen': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
                            
                            if not any(d['ip'] == ip_addr for d in devices):
                                devices.append(device)
                                terminal.success(f"Found additional host: {ip_addr}")
                    except Exception as e:
                        pass
            
            # Update the master list
            with self._lock:
                for device in devices:
                    existing = next((d for d in self.discovered_devices if d['ip'] == device['ip']), None)
                    if existing:
                        existing.update(device)
                    else:
                        self.discovered_devices.append(device)
            
            if devices:
                terminal.success(f"Intensive scan complete! Found {len(devices)} devices on {target_range}")
            else:
                terminal.warning(f"Intensive scan complete. No devices found on {target_range}")
            
            return devices
            
        except Exception as e:
            terminal.error(f"Error during intensive scan: {str(e)}")
            traceback.print_exc()
            return []
