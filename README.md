# NetScan - Cyberpunk Network Reconnaissance Tool

![NetScan](https://img.shields.io/badge/NetScan-v1.0.0-brightgreen)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A hacker-themed network scanning tool designed for MSPs to gather network information from new clients. NetScan features a retro cyberpunk aesthetic with neon green text and a MUD-style interactive console interface.

## Features

- **Network Discovery**: Scan local networks or specified target ranges
- **Device Enumeration**: Identify devices, hostnames, MAC addresses, and vendors
- **Port Scanning**: Detect open ports and running services
- **Interface Analysis**: View all network interfaces and their configurations
- **MUD-style Console**: Interactive terminal UI with command history
- **Cyberpunk Aesthetics**: Matrix-style effects, ASCII art, and neon green styling
- **Export Capabilities**: Save scan results as JSON or CSV

## Requirements

- Python 3.8+
- Root/Admin privileges (for ARP scanning)
- Linux, macOS, or Windows

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/krakenbinary/network_scan.git
   cd network_scan
   ```

2. Create and activate a virtual environment (optional but recommended):
   ```
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   # or
   venv\Scripts\activate  # Windows
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the tool with root/admin privileges for full functionality:

```
sudo python main.py
```

### Available Commands

- `help` - Show help information
- `scan [network/CIDR]` - Scan the network for devices
- `interfaces` - List network interfaces
- `devices` - List discovered devices
- `target <network/CIDR>` - Set target network
- `scan_ports <IP> [ports]` - Scan ports on a device
- `info <IP>` - Show detailed info for a device
- `export [filename]` - Export scan results
- `clear` - Clear the screen
- `matrix` - Display Matrix digital rain
- `about` - Display about information
- `exit` - Exit the program

## Screenshots

(Screenshots will be added after first execution)

## Security Considerations

- This tool is designed for legitimate network reconnaissance by authorized MSPs
- Always obtain proper authorization before scanning any network
- Some features require root/admin privileges to function correctly

## License

MIT License

## Author

KrakenBinary
