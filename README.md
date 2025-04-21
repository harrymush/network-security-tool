# Network Security Tool

A comprehensive network security toolkit built with Python and PyQt6, offering various network analysis and security testing features.

## Features

### Network Tools
- **Port Scanner**
  - Multiple scan types (TCP Connect, SYN, Stealth)
  - Custom port ranges and presets
  - Service detection and banner grabbing
  - Multi-threaded scanning
  - Support for multiple targets (IP/hostname)

- **DNS Tools**
  - DNS record lookup (A, AAAA, MX, NS, etc.)
  - WHOIS lookup
  - Comprehensive results display

### Packet Sniffer
- Real-time packet capture and analysis
- BPF filter support
- Network interface selection
- Detailed packet information display
- Traffic statistics tracking

### Vulnerability Scanner
- Target URL scanning
- Configurable scan options
- Severity-based results
- Progress tracking
- Detailed vulnerability reporting

### Password Tools
- **Password Generator**
  - Customizable password length
  - Character set selection
  - Copy to clipboard functionality
  - Password strength indicators

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/network-security-tool.git
cd network-security-tool
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the application:
```bash
python main.py
```

## Building

To create a standalone executable:
```bash
pyinstaller --clean network_security_tool.spec
```

The built application will be available in the `dist` directory.

## Requirements
- Python 3.x
- PyQt6
- Scapy
- nmap-python
- dnspython
- requests

## Note
Some features may require root/administrator privileges to function properly, particularly the packet sniffer and certain port scanning options.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer
This tool is for educational and testing purposes only. Users are responsible for complying with applicable laws and regulations when using this software. 