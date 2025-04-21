# Network Security Tool

A comprehensive network security toolkit built with Python and PyQt6, providing various network analysis and security testing features.

## Features

- **Network Tools**
  - Port Scanner (TCP/UDP scanning with service detection)
  - DNS Tools (DNS queries and WHOIS lookup)
  - Network Interface Information

- **Packet Sniffer**
  - Real-time packet capture
  - BPF filter support
  - Detailed packet analysis
  - Statistics tracking

- **Vulnerability Scanner**
  - Target URL scanning
  - Multiple scan types
  - Severity-based results
  - Progress tracking

- **Password Tools**
  - Password Generator (customizable options)
  - Password Strength Analyzer
  - Password Cracker (Note: Currently experiencing issues - for educational purposes only)

- **Web Security Tools**
  - Web Crawler
  - Basic vulnerability testing
  - SSL/TLS analysis

## Installation

### macOS

1. Download the latest release `Network Security Tool.dmg`
2. Mount the DMG file by double-clicking it
3. Drag the Network Security Tool application to your Applications folder
4. Eject the DMG
5. Launch the application from your Applications folder

Note: You may need to allow the application in System Preferences > Security & Privacy when first launching.

### From Source

1. Clone the repository:
```bash
git clone https://github.com/yourusername/network-security-tool.git
cd network-security-tool
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python -m network_security_tool
```

## Requirements

- Python 3.8+
- PyQt6
- Scapy
- nmap
- Additional dependencies listed in requirements.txt

## Known Issues

- The Password Cracker module is currently experiencing functionality issues. This feature is provided for educational purposes only and will be fixed in a future update.

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Users are responsible for ensuring they have permission to test target systems and comply with all applicable laws and regulations.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 