# Network Security Tool

A comprehensive network security and penetration testing tool built with Python and PyQt6. This application provides a suite of tools for network analysis, security testing, and password management.

## Features

### Network Tools
- Network Scanner: Discover active hosts on your network
- SSL/TLS Analyzer: Check SSL/TLS configurations and vulnerabilities
- DNS Tools: Perform DNS lookups, WHOIS queries, and more

### Port Scanner
- Multiple scan types (TCP Connect, SYN, Stealth)
- Customizable port ranges
- Service detection and banner grabbing
- Save scan results
- Multi-threaded scanning for improved performance

### Packet Sniffer
- Real-time packet capture and analysis
- BPF filter support
- Interface selection
- Packet statistics and detailed information
- Live traffic monitoring

### Vulnerability Scanner
- Web application vulnerability scanning
- Service vulnerability detection
- Customizable scan options
- Detailed vulnerability reports

### Password Tools
- Password Generator
  - Customizable character sets
  - Length options
  - Special character handling
- Passphrase Generator
  - Word-based secure passphrases
  - Customizable separator options
  - Capital/number/symbol inclusion
- Password Analyzer
  - Strength assessment
  - Common pattern detection
- Password Cracker
  - Dictionary attacks
  - Brute force capability
- Hash Converter
  - Multiple hash algorithm support
  - Quick hash generation and verification

### Web Cracker
- Web form authentication testing
- Multiple attack methods
- Custom pattern matching
- Multi-threaded operations

## Requirements
- Python 3.8+
- PyQt6
- Scapy
- nmap
- python-whois
- dnspython
- cryptography
- requests

## Installation

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
sudo python3 -m network_security_tool
```

Note: Root/Administrator privileges are required for certain features like packet sniffing and port scanning.

## Usage

The application provides a tabbed interface with different security tools:

1. Network Tools Tab
   - Use for basic network scanning and analysis
   - SSL/TLS configuration checking
   - DNS and WHOIS lookups

2. Port Scanner Tab
   - Select target(s) and port ranges
   - Choose scan type and options
   - View and save results

3. Packet Sniffer Tab
   - Select network interface
   - Apply BPF filters
   - Monitor network traffic in real-time

4. Vulnerability Scanner Tab
   - Configure scan targets and options
   - Run comprehensive vulnerability scans
   - View detailed reports

5. Password Tools Tab
   - Generate secure passwords
   - Create memorable passphrases
   - Analyze password strength
   - Convert and verify hashes

6. Web Cracker Tab
   - Test web authentication
   - Configure attack parameters
   - Monitor cracking progress

## Security Notice

This tool is intended for legitimate security testing and educational purposes only. Always ensure you have proper authorization before testing any systems or networks you don't own.

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool should only be used in compliance with all applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this program. 